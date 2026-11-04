# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- may this node hold the address? ---------------------------------------------------
def vip_health_check(daemon):
    """One look at everything the pages need, from outside the daemon: its
    own /healthz through nginx and PHP to the daemon and the database - and
    the API listening, and no maintenance, upgrade or rebuild. A node that is
    not healthy lets the address go to the other."""
    store = daemon.store
    why = ''
    if HA_REBUILDING.is_set():
        why = 'being rebuilt from the other node'
    elif maintenance_now(store).get('on'):
        why = 'in maintenance'
    elif not getattr(getattr(daemon, 'api', None), 'httpd', None):
        why = 'the API is not listening'
    elif VIP_HEALTH_URL == 'none':
        pass                            # a test bed whose nginx is another node's
    else:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(VIP_HEALTH_URL,
                                         headers={'User-Agent': 'acme-vip-check'})
            with url_open(req, timeout=4, context=ctx) as r:     # straight, never a proxy
                body = r.read(200).decode('utf-8', 'replace')
                if r.status != 200 or not body.startswith('ok'):
                    why = 'its pages say: %s' % body.strip()[:80]
        except urllib.error.HTTPError as e:
            try:
                why = 'its pages say %d: %s' % (e.code, e.read(200).decode('utf-8',
                                                                           'replace').strip()[:80])
            except Exception:                           # noqa: BLE001
                why = 'its pages say %d' % e.code
        except Exception as e:                          # noqa: BLE001
            why = 'its pages do not answer (%s)' % str(e)[:80]
    return why


def vip_watch(daemon):
    """Every three seconds: /run/acme/vip-state for keepalived."""
    while not daemon.stop_flag.wait(3):
        try:
            store = daemon.store
            v = vip_conf(store)
            if not v.get('on') or not CONFIG.get('ha_mode'):
                VIP_HEALTH['here'] = False
                try:
                    VIP_STATE.unlink()
                except OSError:
                    pass
                continue
            why = vip_health_check(daemon)
            if why:
                VIP_HEALTH['fails'] += 1
            else:
                VIP_HEALTH['fails'] = 0
            # Maintenance asked for (1.0.186): said at once, not after two looks -
            # the node stops its work, and the VIP address went silent for
            # seconds before keepalived moved it.
            m = maintenance_now(store)
            planned = m.get('on')
            if planned:
                VIP_HEALTH['fails'] = max(VIP_HEALTH['fails'], VIP_FAILS_BEFORE)
                if m.get('split') or m.get('clock'):
                    VIP_HEALTH.pop('drain_since', None)     # silent at once (otp 1.0.227)
                else:
                    VIP_HEALTH.setdefault('drain_since', time.time())
                why = why or 'in maintenance'
            else:
                VIP_HEALTH.pop('drain_since', None)
            VIP_HEALTH['here'] = vip_here(v.get('address'))
            ok = VIP_HEALTH['fails'] < VIP_FAILS_BEFORE
            if not why or not ok or VIP_HEALTH['ok'] is None:
                VIP_HEALTH.update(ok=ok, why=why if not ok else '')
            VIP_HEALTH['at'] = time.time()
            prefer = vip_prefer_me(store, v)
            line = ('ok prefer' if prefer else 'ok') if ok else 'fail ' + (why or '?')
            tmp = RUN_DIR / '.vip-state'
            tmp.write_text(line + '\n')
            os.chmod(str(tmp), 0o640)
            os.replace(str(tmp), str(VIP_STATE))
        except Exception as e:                          # noqa: BLE001
            log_sparing('vip-watch:' + str(e)[:80], 'the VIP address: %s' % e, 'warn', 600)
            if isinstance(e, DbError) and CONFIG.get('ha_mode') and VIP_STATE.exists():
                # Its database gone (otp 1.0.227): the pages here cannot answer, and the file
                # was left to go stale - the VIP address went unanswered 14 s before it moved.
                # Said at once.
                try:
                    VIP_HEALTH.update(ok=False, why='the database cannot be reached', at=time.time())
                    tmp = RUN_DIR / '.vip-state'
                    tmp.write_text('fail the database cannot be reached\n')
                    os.chmod(str(tmp), 0o640)
                    os.replace(str(tmp), str(VIP_STATE))
                except OSError:
                    pass
                daemon.stop_flag.wait(2)
                continue
            daemon.stop_flag.wait(10)


# ---- what the pages and the command line change ----------------------------------------
def vip_checked(b, store):
    try:
        net = plain_ip(b.get('address'), 'interface')
    except ValueError:
        raise ValueError('the VIP address is an address with its prefix, e.g. 192.0.2.10/24')
    if '/' not in str(b.get('address') or ''):
        raise ValueError('give the prefix with the address, e.g. 192.0.2.10/24')
    if net.ip.is_loopback or net.ip.is_multicast or net.ip.is_unspecified:
        raise ValueError('%s cannot be the VIP address' % net.ip)
    nodes = [n for n in ha_nodes(store)]
    for n in nodes:
        if str(n.get('address') or '') == str(net.ip):
            raise ValueError('%s is the address of %s: the VIP address is a third one'
                             % (net.ip, n['name']))
    fqdn = str(b.get('fqdn') or '').strip().lower().rstrip('.')
    if fqdn and not re.match(r'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
                             r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', fqdn):
        raise ValueError('%r is not a host name' % fqdn)
    try:
        vrid = int(b.get('vrid') or 51)
    except (TypeError, ValueError):
        raise ValueError('the VRRP id is a number')
    if not 1 <= vrid <= 255:
        raise ValueError('the VRRP id is 1 to 255 - one no other VRRP on that network uses')
    ifaces = {}
    for k, val in (b.get('ifaces') or {}).items():
        val = str(val or '').strip()
        if val and not re.match(r'^[A-Za-z0-9_.:-]{1,15}\Z', val):
            raise ValueError('%r is not the name of a network interface' % val)
        if val:
            ifaces[str(k)] = val
    a6 = str(b.get('address6') or '').strip()
    if a6:
        if '/' not in a6:
            raise ValueError('give the prefix with the IPv6 VIP address, e.g. 2001:db8::10/64')
        try:
            n6 = plain_ip(a6, 'interface')
        except ValueError:
            raise ValueError('the IPv6 VIP address is an address with its prefix, e.g. '
                             '2001:db8::10/64')
        if n6.version != 6 or n6.ip.is_link_local or n6.ip.is_loopback:
            raise ValueError('the IPv6 VIP address is a global IPv6 address')
        a6 = str(n6)
    return {'address': str(net), 'fqdn': fqdn, 'vrid': vrid, 'ifaces': ifaces, 'address6': a6}


def vip_set(store, by, **changes):
    v = vip_conf(store)
    v.update(changes)
    v['at'] = time.time()
    v['by'] = by
    store.set_meta('web:vip', json.dumps(v))
    return v


# ---- a node renamed (1.0.48) ---------------------------------------------------------
NODE_NAME_FILE = STATE_DIR / 'node-name'


def node_carry(store, old, new, by='the daemon'):
    """What belongs to a node by its name, carried to its new name: its own
    settings (key@node), its maintenance, its TLS, its place as the web
    address's preferred node and its interface - and the old name off the
    list of nodes. Nothing the new name has already is overwritten."""
    if not old or old == new:
        return []
    said = []
    for r in store.db.rows('SELECT k, v FROM settings'):
        k = str(r['k'])
        if k.endswith('@' + old):
            want = k[:-len(old)] + new
            if store.db.value('SELECT 1 FROM settings WHERE k = ?', (want,)) is None:
                store.db.run('UPDATE settings SET k = ? WHERE k = ?', (want, k))
                said.append('its own setting %s' % k.split('@')[0])
            else:
                store.db.run('DELETE FROM settings WHERE k = ?', (k,))
    old_maint = _json_meta(store, 'maint:' + old)
    if old_maint and old_maint.get('on') and not (maintenance_row(store, new) or {}).get('on'):
        maintenance_set(store, True, old_maint.get('why') or 'carried over from %s' % old,
                        old_maint.get('by') or '', name=new)
        said.append('its maintenance')
    prof = store.get_meta('web:tls:' + old)
    if prof and store.get_meta('web:tls:' + new) is None:
        store.set_meta('web:tls:' + new, prof)
        said.append('its certificate and TLS settings')
    v = vip_conf(store)
    changed = False
    if v.get('prefer') == old:
        v['prefer'] = new
        changed = True
    ifaces = v.get('ifaces') or {}
    if old in ifaces and new not in ifaces:
        ifaces[new] = ifaces.pop(old)
        v['ifaces'] = ifaces
        changed = True
    if changed:
        store.set_meta('web:vip', json.dumps(v))
        said.append('its place in the VIP address')
    # Its place as the preferred node when the two lose each other (1.0.19): left on the
    # old name, neither node was the preferred one - with "priority" both stepped aside
    # while apart, and nobody answered, renewed or changed anything.
    if str(store.settings_saved().get('split_prefer') or '') == old:
        store.save_setting('split_prefer', new, by)
        said.append('its place as the preferred node when the nodes lose each other')
    if str(CONFIG.get('split_prefer') or '') == old:
        CONFIG['split_prefer'] = new
    for k in ('node:', 'maint:', 'upgrade:node:', 'web:tls:', 'web:retry:', 'db_job:', 'fw:now:',
              'db_sizes:', 'hatls:node:', 'split:state:'):
        store.db.run('DELETE FROM meta WHERE k = ?', (k + old,))
    store.add_event('settings', 'the node %s is called %s now; carried over: %s' % (
        old, new, ', '.join(said) or 'nothing (it had nothing of its own)'), 'warn', who=by)
    dbguard_resign(store, 'the node %s is called %s now' % (old, new))      # 1.0.231
    return said


def node_name_check(store):
    """At the start: was this node called something else last time?"""
    me = node_name()
    try:
        before = NODE_NAME_FILE.read_text().strip()
    except OSError:
        before = ''
    if before and before != me:
        # The new name is another machine's, answering now (1.0.110): carried
        # over, this node's own settings would land on that one - and with the
        # name put back, that one's on this one. Nothing is carried.
        try:
            taken = [n for n in ha_nodes(store) if n['name'] == me and n.get('alive') and
                     n.get('mid') and n['mid'] != machine_id()]
        except Exception:                               # noqa: BLE001
            taken = []
        if taken:
            log('this node was %s and is called %s now - but %s (%s) is %s and answering: '
                'nothing carried over; give this node its own name (acme --set node_name=%s, '
                'then systemctl restart acme)' % (before, me, taken[0].get('address') or '?',
                                                 taken[0].get('host') or '?', me, before), 'error')
            return
        try:
            said = node_carry(store, before, me)
            log('this node was %s and is %s now; carried over: %s'
                % (before, me, ', '.join(said) or 'nothing'), 'warn')
        except Exception as e:                          # noqa: BLE001
            log('carrying %s over to %s: %s' % (before, me, e), 'warn')
            return
    if before != me:
        try:
            NODE_NAME_FILE.write_text(me + '\n')
        except OSError:
            pass


