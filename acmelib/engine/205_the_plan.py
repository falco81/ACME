# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the plan ------------------------------------------------------------------------
def upgrade_nodes_now(store):
    """The nodes an upgrade goes over: every one heard from lately, or this
    one alone."""
    nodes = [n for n in ha_nodes(store) if n.get('alive')]
    if not nodes:
        nodes = [{'name': node_name(), 'version': __version__, 'me': True, 'alive': True}]
    return nodes


def upgrade_plan(store):
    plan = _meta_json(store, 'upgrade:plan')
    if not plan:
        return None
    plan['steps'] = []
    plan['drain_s'] = UPGRADE_DRAIN_S
    for name in plan.get('order') or []:
        row = _meta_obj(store, 'upgrade:node:' + name)
        if row.get('id') != plan.get('id'):
            row = {'state': 'waiting'}
        row['name'] = name
        plan['steps'].append(row)
    states = [s.get('state') for s in plan['steps']]
    if any(s == 'failed' for s in states):
        plan['state'] = 'failed'
    elif states and all(s == 'done' for s in states):
        plan['state'] = 'done'
    elif plan.get('cancelled'):
        plan['state'] = 'cancelled'
    else:
        plan['state'] = 'running'
    return plan


def upgrade_checks(store, meta, pages=False):
    """What must be so before an upgrade starts - (ok, [why not]). A package
    to go back to (1.0.143) is looked at again as it was when it was taken."""
    why = []
    if not meta:
        return False, ['no package has been sent yet']
    down = bool(meta.get('downgrade'))
    if down:
        why += downgrade_why_not(store, meta['version'])
        if pages and not CONFIG.get('upgrade_downgrade'):
            # Switched off since it was fetched (1.0.146): not started from the pages.
            why.append('going back to an older version is switched off (Settings → Upgrades)')
    nodes = upgrade_nodes_now(store)
    for n in ha_nodes(store):
        if not n.get('alive'):
            why.append('%s has not been heard from for %d s - bring it back, or forget it '
                       '(Settings - High availability)' % (n['name'], int(n.get('age') or 0)))
    for n in nodes:
        have = str(n.get('version') or '')
        try:
            if have and not down and tuple(int(x) for x in have.split('.')) > \
                    tuple(int(x) for x in meta['version'].split('.')):
                why.append('%s runs %s, newer than %s' % (n['name'], have, meta['version']))
        except ValueError:
            pass
    if CONFIG.get('ha_mode') == 'replicated':
        rep = ha_repl_state(store)
        if not rep.get('healthy'):
            why.append('the replication is not running both ways - see Settings - High '
                       'availability')
    plan = upgrade_plan(store)
    if plan and plan['state'] == 'running':
        why.append('an upgrade is going on already')
    # ...nor an update of the system or a restart (1.0.80): the other way round was refused,
    # this way the two went on over each other on one node
    try:
        if (osup_plan(store) or {}).get('state') == 'running':
            why.append('the system is being updated - wait for it to end')
        if power_busy(store):
            why.append('a restart or power-off is going on - wait for it to end')
    except NameError:
        pass
    return not why, why


def upgrade_start(store, by, pages=False):
    meta = _meta_json(store, 'upgrade:pkg')
    ok, why = upgrade_checks(store, meta, pages)
    if not ok:
        raise ValueError('; '.join(why))
    names = [n['name'] for n in upgrade_nodes_now(store)]
    me = node_name()
    # The others first and this node last: the pages it shows stay up the
    # longest, and the first node is the one somebody can look at while it
    # is done.
    order = sorted(n for n in names if n != me) + ([me] if me in names else [])
    ident = '%d-%s' % (int(time.time()), secrets.token_hex(4))
    for name in order:
        k = 'upgrade:node:' + name
        if store.get_meta(k) is None:
            # Made here, for every node, before anything else: from then on
            # each node only UPDATEs its own.
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)',
                         (k, json.dumps({'state': 'none'})))
    plan = {'id': ident, 'version': meta['version'], 'sha': meta['sha'], 'order': order,
            'by': by, 'at': time.time(), 'from': me, 'downgrade': bool(meta.get('downgrade'))}
    store.set_meta('upgrade:plan', json.dumps(plan))
    store.add_event('starting and stopping', '%s started %s %s: %s, one at a time' % (
        by, 'going back to' if plan['downgrade'] else 'the upgrade to', meta['version'],
        ', '.join(order)), 'warn', who=by)
    return upgrade_plan(store)


def upgrade_cancel(store, by):
    plan = _meta_json(store, 'upgrade:plan')
    if not plan:
        raise ValueError('no upgrade is going on')
    plan['cancelled'] = {'by': by, 'at': time.time()}
    store.set_meta('upgrade:plan', json.dumps(plan))
    _peer_update('upgrade:plan', json.dumps(plan))
    store.add_event('starting and stopping', '%s stopped the upgrade to %s: the nodes not '
                    'begun stay as they are' % (by, plan.get('version')), 'warn', who=by)


def _my_step(store, plan, **fields):
    k = 'upgrade:node:' + node_name()
    row = _meta_obj(store, k)
    if row.get('id') != plan['id']:
        row = {'id': plan['id']}
    row.update(fields)
    row['at'] = time.time()
    _row_write(store, k, row, mine=False)
    return row


def _helper_status():
    try:
        fd = os.open(str(UPGRADE_DIR / 'status.json'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            return json.loads(f.read(1 << 20).decode('utf-8'))
    except (OSError, ValueError):
        return {}


def upgrade_log_tail(lines=200):
    try:
        fd = os.open(str(UPGRADE_DIR / 'last.log'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as f:
            text = f.read(4 << 20).decode('utf-8', 'replace')
        return text.splitlines()[-lines:]
    except OSError:
        return []


def upgrade_tick(daemon):
    """This node's part of the plan, every few seconds."""
    store = daemon.store
    if HA_REBUILDING.is_set():
        return
    plan = upgrade_plan(store)
    # A cancelled plan is still finished where a node has begun (1.0.44):
    # one that drains goes back into service, one that installs is checked
    # and comes back - it never stays in maintenance for good.
    if plan and plan['state'] == 'failed':
        _back_after_marked(store, plan)
    if not plan or plan['state'] not in ('running', 'cancelled'):
        return
    me = node_name()
    if store.get_meta('upgrade:node:' + me) is None:
        return                          # its row has not come over from the other node yet
    steps = plan['steps']
    turn = next((s for s in steps if s.get('state') != 'done'), None)
    if turn and turn['name'] != me and turn.get('state') in ('draining', 'installing',
                                                             'checking'):
        # The node whose turn it is gone for longer than an upgrade takes
        # (1.0.59): marked failed from here, or the plan ran for ever and
        # stopped every new upload and start until somebody cancelled it.
        alive = any(n.get('name') == turn['name'] and n.get('alive')
                    for n in ha_nodes(store))
        if not alive and now_minus(turn.get('at')) > UPGRADE_TIMEOUT_S + 300 and \
                not _peer_still_at_it(turn):
            row = dict(turn)
            row.pop('name', None)
            row.update({'state': 'failed', 'at': time.time(), 'marked_by': me,
                        'said': 'not heard from for %d min while %s - marked failed by %s'
                                % (UPGRADE_TIMEOUT_S // 60 + 5, turn.get('state'), me)})
            try:
                _row_write(store, 'upgrade:node:' + turn['name'], row, mine=False)
                store.add_event('starting and stopping', 'the upgrade of %s to %s failed: '
                                'the node has not been heard from' % (turn['name'],
                                                                      plan['version']), 'bad')
            except Exception as e:                      # noqa: BLE001
                log('the upgrade of %s could not be marked failed: %s' % (turn['name'], e),
                    'warn')
        return
    if not turn or turn['name'] != me:
        return
    state = turn.get('state')
    now = time.time()
    if plan.get('cancelled') and state in ('waiting', 'none', None, 'cancelled'):
        return
    if plan.get('cancelled') and state == 'draining':
        if not turn.get('was_maint'):
            maintenance_set(store, False, by=plan.get('by') or '')
        _my_step(store, plan, state='cancelled', said='cancelled before it was installed; '
                 'back in service')
        return
    if state in ('waiting', 'none', None) and len(steps) > 1:
        # Never both out at once (1.0.44): the others have to be alive and
        # in service before this one leaves.
        for n in ha_nodes(store):
            if n['name'] == me or n['name'] not in [x['name'] for x in steps]:
                continue
            alive = n.get('alive') or _peer_alive_there(n['name'])
            # ...and not stepped aside either (1.0.48): for its clock, a split, a rebuild or a
            # restore it is out with its row saying nothing - its heartbeat says it.
            beat_out = beat_aside(n)
            if not alive or beat_out or maintenance_row(store, n['name']).get('on'):
                if turn.get('said') != 'waiting for %s to be in service' % n['name']:
                    _my_step(store, plan, state='waiting',
                             said='waiting for %s to be in service' % n['name'])
                return
    if state in ('waiting', 'none', None):
        was = maintenance_row(store)
        alone = len(steps) == 1
        maintenance_set(store, True, 'upgrade to %s' % plan['version'], plan.get('by') or '')
        _my_step(store, plan, state='draining', was_maint=bool(was.get('on')),
                 began=now, said='in maintenance; the balancer and the work go to the other '
                 'node' if not alone else 'in maintenance')
        if not alone:
            return
        state = 'draining'
        turn = _meta_json(store, 'upgrade:node:' + me)
    if state == 'draining':
        if len(steps) > 1 and now - float(turn.get('at') or 0) < UPGRADE_DRAIN_S:
            return
        meta = _meta_obj(store, 'upgrade:pkg')
        try:
            if meta.get('sha') != plan['sha']:
                raise ValueError('the package in the database is not the one this upgrade '
                                 'was started with')
            path = upgrade_package_file(store, meta)
            req = {'id': plan['id'], 'file': path.name, 'sha': plan['sha'],
                   'version': plan['version'], 'by': plan.get('by'), 'at': now,
                   'downgrade': bool(plan.get('downgrade'))}
            tmp = UPGRADE_DIR / 'request.part'
            try:
                tmp.unlink()
            except OSError:
                pass
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, 'w') as f:
                json.dump(req, f)
            os.replace(str(tmp), str(UPGRADE_DIR / 'request.json'))
        except Exception as e:                          # noqa: BLE001
            _upgrade_failed(store, plan, turn, 'the package could not be handed over: %s' % e)
            return
        _my_step(store, plan, state='installing', asked=now, from_version=__version__,
                 said='handed to root (acme-upgrade.service)')
        log('the upgrade to %s is handed to acme-upgrade.service' % plan['version'])
        return
    if state == 'installing':
        # Its own version tried again (1.0.52): restarted by install.sh's rescue after a
        # failure it ran the old code unchanged, and was taken for the new one broken - left in
        # maintenance. The helper's word first.
        hs = _helper_status() if __version__ == plan['version'] else {}
        if hs.get('id') == plan['id'] and hs.get('state') == 'failed':
            _upgrade_failed(store, plan, turn, hs.get('said') or
                            'install.sh ended with %s' % hs.get('rc'), tail=hs.get('tail'))
            return
        if __version__ == plan['version'] and float(daemon.started or 0) > \
                float(turn.get('asked') or 0):
            _my_step(store, plan, state='checking', said='restarted as %s' % __version__)
            state = 'checking'
            turn = _meta_json(store, 'upgrade:node:' + me)
        else:
            got = _helper_status()
            if got.get('id') == plan['id'] and got.get('state') == 'failed':
                _upgrade_failed(store, plan, turn, got.get('said') or
                                'install.sh ended with %s' % got.get('rc'),
                                tail=got.get('tail'))
                return
            if not (UPGRADE_DIR / 'request.json').exists() and \
                    not (UPGRADE_DIR / 'request.taken').exists() and \
                    got.get('id') != plan['id'] and now - float(turn.get('asked') or now) > 120:
                _upgrade_failed(store, plan, turn, 'acme-upgrade.service never took the request '
                                '- is acme-upgrade.path installed and running? (install.sh '
                                '--upgrade once on the command line puts it in)')
                return
            if now - float(turn.get('asked') or now) > UPGRADE_TIMEOUT_S:
                _upgrade_failed(store, plan, turn, 'it has not come back as %s in %d min'
                                % (plan['version'], UPGRADE_TIMEOUT_S // 60))
                return
            # How far install.sh is (1.0.67): its sections, "==> ...", for the
            # bar on the pages - written when one more has begun.
            if got.get('id') == plan['id'] and got.get('state') == 'running':
                parts = [x[4:].strip() for x in upgrade_log_tail(400) if x.startswith('==> ')]
                if parts and len(parts) != int(turn.get('part') or 0):
                    _my_step(store, plan, part=len(parts), part_words=parts[-1][:120],
                             asked=turn.get('asked'))
            return
    if state == 'checking':
        trouble = []
        try:
            store.db.value('SELECT 1')
        except Exception as e:                          # noqa: BLE001
            trouble.append('the database: %s' % e)
        if not getattr(getattr(daemon, 'api', None), 'httpd', None):
            trouble.append('the API is not listening')
        got = _helper_status()
        if got.get('id') == plan['id'] and got.get('state') == 'running':
            if now - float(turn.get('at') or now) < 600:
                return                  # install.sh is still finishing (the firewall, its checks)
            # Not done just because it took long (1.0.44).
            trouble.append('install.sh has not said it finished in 10 min (see '
                           'journalctl -u acme-upgrade)')
        if got.get('id') == plan['id'] and got.get('state') == 'failed':
            trouble.append(got.get('said') or 'install.sh ended with %s' % got.get('rc'))
        if CONFIG.get('ha_mode') == 'replicated':
            ha_refresh_tables(store)
        if trouble:
            _upgrade_failed(store, plan, turn, '; '.join(trouble), tail=got.get('tail'))
            return
        if not turn.get('was_maint'):
            maintenance_set(store, False, by=plan.get('by') or '')
        _my_step(store, plan, state='done', said='%s, checked, back in service' % __version__,
                 tail=(got.get('tail') or [])[-12:])
        store.add_event('starting and stopping', '%s is upgraded to %s' % (me, __version__))
        log('upgraded to %s and back in service' % __version__)
        if all((s.get('state') == 'done') or s['name'] == me for s in steps):
            store.add_event('starting and stopping', 'the upgrade to %s is done on every node'
                            % plan['version'])


PEER_THERE = {}                   # name: (when asked, alive)


def beat_aside(n):
    """A node stepped aside, by its heartbeat: `maintenance` is a bool there (1.0.51 - read as
    a dict, it never was, and a node out was taken for one in service)."""
    m = n.get('maintenance')
    return bool(m.get('on')) if isinstance(m, dict) else bool(m)


def _peer_alive_there(name):
    """Its heartbeat read in its own database (1.0.206): a node done with the new
    version writes nothing that comes over to this older one any more - its
    heartbeat looked stale here, and the last node waited for it for good.
    Asked every 15 s at most."""
    was = PEER_THERE.get(name)
    if was and time.monotonic() - was[0] < 15:
        return was[1]
    alive, vip = False, False
    try:
        far = ha_peer_db()
        try:
            beat = json.loads(far.value('SELECT v FROM meta WHERE k = ?', ('node:' + name,))
                              or '{}')
            # Its age by its own database's clock (1.0.44): by this machine's, two minutes of
            # skew made a live node dead here - and both nodes led.
            try:
                there = float(far.value('SELECT EXTRACT(EPOCH FROM clock_timestamp())') or 0)
            except Exception:                           # noqa: BLE001
                there = 0.0
            at = float(beat.get('at') or 0)
            alive = (there - at < 120) if there else now_minus(at) < 120
            vip = bool(alive and (beat.get('web') or {}).get('vip_here'))
        finally:
            far.close()
    except Exception:                                   # noqa: BLE001
        alive = False
    PEER_THERE[name] = (time.monotonic(), alive, vip)
    return alive


def peer_vip_there(name):
    """Whether the node said, in its own database when last asked, it holds the VIP."""
    was = PEER_THERE.get(name)
    return bool(was and len(was) > 2 and was[2])


def _peer_still_at_it(turn):
    """Its own row read in its own database (1.0.61): while it runs the new
    version, what it writes does not come over to this one - its heartbeat
    looks stale, and a node that was fine was marked failed."""
    try:
        far = ha_peer_db()
    except Exception:                                   # noqa: BLE001
        return False                    # not reachable either: gone indeed
    try:
        row = json.loads(far.value('SELECT v FROM meta WHERE k = ?',
                                   ('upgrade:node:' + turn['name'],)) or '{}')
        beat = json.loads(far.value('SELECT v FROM meta WHERE k = ?',
                                    ('node:' + turn['name'],)) or '{}')
        return row.get('state') == 'done' or now_minus(row.get('at')) < 600 or \
            now_minus(beat.get('at')) < 120
    except Exception:                                   # noqa: BLE001
        return False
    finally:
        try:
            far.close()
        except Exception:                               # noqa: BLE001
            pass


def _back_after_marked(store, plan):
    """A node the other one marked failed while it drained, come back on
    its old version (1.0.61): taken out of the maintenance the upgrade put
    it in, once - nothing else would."""
    me = node_name()
    row = _meta_obj(store, 'upgrade:node:' + me)
    if row.get('id') != plan.get('id') or row.get('state') != 'failed' or \
            not row.get('marked_by') or row.get('back') or __version__ == plan.get('version'):
        return
    if not row.get('was_maint'):
        try:
            maintenance_set(store, False, by=plan.get('by') or '')
        except Exception:                               # noqa: BLE001
            return
    row['back'] = True
    try:
        _row_write(store, 'upgrade:node:' + me, row, mine=False)
    except Exception:                                   # noqa: BLE001
        pass
    log('back in service: the upgrade had been marked failed by %s while this node waited'
        % row.get('marked_by'), 'warn')


def now_minus(at):
    try:
        return time.time() - float(at or time.time())
    except (TypeError, ValueError):
        return 0.0


def _upgrade_failed(store, plan, turn, said, tail=None):
    # Already running the new version and its checks failed (1.0.59): kept
    # in maintenance - it is the broken version that would be put in service.
    # Only once it has started again as that version (1.0.61): the same
    # version put in again, failing before anything was installed, left a
    # working node out.
    # ...and only where the tree changed (1.0.52): its own version put in again and failing, the
    # rescue's restart ran the same code - it was taken for the new one broken
    broken_new = __version__ == plan.get('version') and turn.get('state') == 'checking' and \
        turn.get('from_version') != plan.get('version')
    if broken_new:
        said = '%s - left in maintenance: it runs %s, which did not pass its checks' % (
            said, __version__)
    _my_step(store, plan, state='failed', said=str(said)[:500], tail=(tail or [])[-40:])
    # Back in service where it still runs as it did: a failed upgrade must
    # not leave a working node out.
    if not turn.get('was_maint') and not broken_new:
        try:
            maintenance_set(store, False, by=plan.get('by') or '')
        except Exception:                               # noqa: BLE001
            pass
    store.add_event('starting and stopping', 'the upgrade of %s to %s failed: %s'
                    % (node_name(), plan['version'], said), 'bad')
    log('the upgrade to %s failed: %s' % (plan['version'], said), 'error')


def ha_refresh_tables(store):
    """The list of tables taken from the other node read again, here and
    there: a version that adds a table needs it, and it costs nothing when
    none was added. Where the other node does not have the table yet (it
    is still the older version) its half fails, and it is done again when
    that node comes back upgraded."""
    try:
        ha_control(store, 'refresh', by='the upgrade')
    except Exception as e:                              # noqa: BLE001
        log('reading the tables of the other node again: %s' % e, 'warn')
    slot = int(CONFIG.get('ha_slot') or 1)
    try:
        far = ha_peer_db()
        try:
            far.run('ALTER SUBSCRIPTION %s REFRESH PUBLICATION WITH (copy_data = false)'
                    % ha_sub_here(far, slot))
        finally:
            far.close()
    except Exception as e:                              # noqa: BLE001
        log('the other node could not read this one\'s tables again yet: %s'
            % str(e).split('\n')[0][:200], 'info')
