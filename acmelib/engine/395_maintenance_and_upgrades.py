# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- maintenance and upgrades (1.0.37) -----------------------------------------------
def _upgrade_view(h):
    meta = None
    try:
        meta = json.loads(h.store.get_meta('upgrade:pkg') or 'null')
    except ValueError:
        meta = None
    nodes = []
    for n in ha_nodes(h.store):
        n = dict(n)
        n['maintenance'] = maintenance_row(h.store, n['name'])
        nodes.append(n)
    if not nodes:
        nodes = [{'name': node_name(), 'version': __version__, 'me': True, 'alive': True,
                  'maintenance': maintenance_row(h.store)}]
    ok, why = upgrade_checks(h.store, meta, pages=True)
    plan = upgrade_plan(h.store)
    # A finished one hidden by Hide this (1.0.123).
    if plan and plan.get('state') != 'running' and \
            h.store.get_meta('upgrade:seen') == str(plan.get('id') or plan.get('at')):
        plan = None
    return {'node': node_name(), 'version': __version__, 'nodes': nodes, 'package': meta,
            'plan': plan, 'ready': ok, 'not_ready': why,
            'downgrade_on': bool(CONFIG.get('upgrade_downgrade')),
            'mode': CONFIG.get('ha_mode') or '',
            'helper': UPGRADE_HELPER.exists(),
            'path_unit': Path('/etc/systemd/system/acme-upgrade.path').exists(),
            'log': upgrade_log_tail(120), 'web': online_view(h.store)}


@route('GET', '/api/upgrade')
def _upgrade(h):
    h.me('fulladmin')
    return _upgrade_view(h)


@route('POST', '/api/upgrade/package')
def _upgrade_package(h):
    s = h.me('fulladmin')
    UPGRADE_DIR.mkdir(mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='incoming-', suffix='.tar.gz', dir=str(UPGRADE_DIR))
    os.close(fd)
    tmp = Path(tmp)
    try:
        h.body_to_file(tmp, UPGRADE_MOST)
        try:
            info = upgrade_inspect(tmp)
        except ValueError as e:
            h.store.add_event('starting and stopping', '%s sent a package that was refused: %s'
                              % (s['name'], e), 'warn', who=s['name'])
            raise ApiError(400, str(e))
        if info.get('older'):
            raise ApiError(400, '%s is older than %s, which runs here: going back is done on '
                                'the command line' % (info['version'], info.get('installed')))
        plan = upgrade_plan(h.store)
        if plan and plan['state'] == 'running':
            raise ApiError(409, 'an upgrade is going on: wait for it, or stop it first')
        meta = upgrade_store_package(h.store, tmp, info, s['name'])
        h.store.add_event('starting and stopping', '%s sent acme %s (signed by %s), ready to '
                          'be put in' % (s['name'], meta['version'], meta.get('signed_by')),
                          'warn', who=s['name'])
        return dict(_upgrade_view(h), message='acme %s is checked and ready' % meta['version'])
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


@route('POST', '/api/upgrade')
def _upgrade_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = b.get('action')
    try:
        if act == 'start':
            upgrade_start(h.store, s['name'], pages=True)
            return dict(_upgrade_view(h), message='the upgrade has begun')
        if act == 'online_look':
            row = online_look(h.store, s['name'])
            if row.get('error'):
                raise ValueError('%s: %s' % (row.get('url'), row['error']))
            n = row.get('newest') or {}
            return dict(_upgrade_view(h), message=(
                'acme %s is there - newer than %s' % (n['version'], __version__) if row.get('newer')
                else ('nothing newer than %s' % __version__ if n else 'no acme package there')))
        if str(act or '').startswith('downgrade') and not CONFIG.get('upgrade_downgrade'):
            # Offered on the pages only when switched on (1.0.144).
            raise ValueError('going back to an older version is not offered on these pages: '
                             'switch it on in Settings → Upgrades')
        if act == 'downgrade_changelog':
            return {'changelog': downgrade_changelog(b.get('version'))}
        if act == 'downgrade_list':
            # Going back (1.0.143): the older versions there, and what stands
            # in the way of each.
            return {'downgrade': downgrade_list(h.store)}
        if act == 'downgrade_get':
            plan = upgrade_plan(h.store)
            if plan and plan['state'] == 'running':
                raise ValueError('an upgrade is going on: wait for it, or stop it first')
            meta = downgrade_fetch(h.store, str(b.get('version') or ''), s['name'])
            if b.get('start'):
                upgrade_start(h.store, s['name'], pages=True)
                return dict(_upgrade_view(h), message='acme %s fetched and checked; going back '
                            'to it has begun' % meta['version'])
            return dict(_upgrade_view(h), message='acme %s is fetched, checked for this database '
                        'and ready to go back to' % meta['version'])
        if act == 'online_get':
            plan = upgrade_plan(h.store)
            if plan and plan['state'] == 'running':
                raise ValueError('an upgrade is going on: wait for it, or stop it first')
            meta = online_fetch(h.store, str(b.get('version') or ''), s['name'])
            if b.get('start'):
                upgrade_start(h.store, s['name'], pages=True)
                return dict(_upgrade_view(h), message='acme %s fetched and checked; the upgrade '
                            'has begun' % meta['version'])
            return dict(_upgrade_view(h), message='acme %s is fetched, checked and ready'
                        % meta['version'])
        if act == 'hide':
            plan = upgrade_plan(h.store)
            if plan and plan.get('state') == 'running':
                raise ValueError('the upgrade is going on')
            if plan:
                h.store.set_meta('upgrade:seen', str(plan.get('id') or plan.get('at')))
            return _upgrade_view(h)
        if act == 'cancel':
            upgrade_cancel(h.store, s['name'])
            return dict(_upgrade_view(h), message='the upgrade is stopped')
        if act == 'maintenance':
            name = str(b.get('node') or node_name())
            if name not in [n['name'] for n in ha_nodes(h.store)] + [node_name()]:
                raise ValueError('there is no node %s' % name)
            on = bool(b.get('on'))
            maintenance_set(h.store, on, str(b.get('why') or 'by hand'), s['name'], name)
            return dict(_upgrade_view(h), message='%s: maintenance %s' % (
                name, 'on' if on else 'off'))
        if act == 'forget':
            plan = upgrade_plan(h.store)
            if plan and plan['state'] == 'running':
                raise ValueError('an upgrade is going on with it')
            h.store.db.run("DELETE FROM meta WHERE k LIKE 'upgrade:piece:%'")
            h.store.db.run("DELETE FROM meta WHERE k = 'upgrade:pkg'")
            return dict(_upgrade_view(h), message='the package is forgotten')
    except ValueError as e:
        raise ApiError(400, str(e))
    except (OSError, tarfile.TarError, subprocess.SubprocessError) as e:
        # The address not answering, a package cut off (1.0.146): said, not an
        # error 500 with its trace in the log.
        raise ApiError(502, 'the address could not be read: %s'
                       % (getattr(e, 'reason', None) or e))
    raise ApiError(400, 'no such thing to do')


