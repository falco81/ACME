# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- a node's address changed: the cluster put right in place (1.0.106) ----------
# Replication remembers the other node's address in three places on each node:
# config.json (ha_peer, and ha_address - its own, as the other reaches it), its
# subscription's connection, and the line of pg_hba.conf that lets the other
# node in. Changing an address used to mean taking the pair apart and building
# it again. Now one node is told the new address(es) - on its pages or with
# acme --ha-readdress - and puts its three places right; then it tells the other
# node straight into that one's database, which does its part by itself.
#
# Which node to do it on: the one whose address did NOT change. Its own line
# in the other's pg_hba.conf still matches, so it can reach the other at the
# new address and tell it; the other cannot reach it yet. When both changed,
# do it on both (each says what it could not do).
READDRESS_LOCK = threading.Lock()
# A tell that failed after going back, tried again (1.0.56): when this
# process last tried it.
READDRESS_TELL_TRIED = {'at': 0.0}


def _addr_key(a):
    """An address in one form to compare (1.0.56): ip_address's canonical one,
    anything else (a host name) in lower case. Compared as text, 10.0.0.1 was
    "in" 10.0.0.12 and FD99::1 was not fd99::1."""
    a = str(a or '').strip()
    try:
        return str(ipaddress.ip_address(a.strip('[]')))
    except ValueError:
        return a.lower()


def _readdress_ip(text, what):
    text = str(text or '').strip()
    if not text:
        return ''
    try:
        return str(peer_address(text))
    except ValueError:
        raise ValueError('%s is one plain address (192.0.2.10), not %r' % (what, text[:60]))


def _readdress_hba(old_peer, new_peer, root_now, keep_old=False, drop_old=False):
    """This node's pg_hba.conf: the other node's line moved to its new
    address (host or hostssl kept), by the root helper."""
    ask_id = secrets.token_hex(8)
    data = {'id': ask_id, 'do': 'peer', 'port': int(CONFIG.get('db_port') or 5432),
            'db': str(CONFIG.get('db_name') or 'acme'), 'user': str(CONFIG.get('db_user') or 'acme'),
            'peer': new_peer, 'old_peer': old_peer, 'ca_file': str(HA_CA_FILE),
            # On trial (1.0.137): the old address let in beside the new one,
            # so the other node can still be told if it goes back; and taken
            # out once the new one is kept.
            'keep_old': bool(keep_old), 'drop_old': bool(drop_old)}
    pgtls_send(data)
    if root_now:
        # On the command line, as root: the helper run here and now.
        helper = Path(__file__).resolve().parent / 'acme_web.py'
        if not helper.exists():
            helper = Path('/usr/local/lib/acme/acme_web.py')
        subprocess.run(['/usr/bin/python3', '-I', str(helper)], capture_output=True,
                       timeout=120, env=dict(os.environ, ACME_STATE=str(STATE_DIR)))
    end = time.time() + 60
    while time.time() < end:
        try:
            got = json.loads((WEB_DIR / PGTLS_FILE).read_text())
        except (OSError, ValueError):
            got = None
        if isinstance(got, dict) and got.get('id') == ask_id:
            if not got.get('ok'):
                raise ValueError('pg_hba.conf: %s' % (got.get('said') or 'the root helper said no'))
            return got.get('said') or 'pg_hba.conf changed'
        time.sleep(0.5)
    raise ValueError('the root helper of this node did not answer in a minute - is acme-web.path '
                     'running?  systemctl status acme-web.path')


def ha_readdress(store, mine='', peer='', by='', root_now=False, tell=True, daemon=None,
                 keep_old=False):
    """This node told its own new address (`mine`, as the other node reaches
    it) and/or the other node's (`peer`). Returns what was done and what is
    left, in words."""
    if CONFIG.get('ha_mode') != 'replicated':
        raise ValueError('this node does not replicate')
    mine = _readdress_ip(mine, 'this node\'s address')
    peer = _readdress_ip(peer, 'the other node\'s address')
    had_mine = str(CONFIG.get('ha_address') or node_address() or '')
    had_peer = str(CONFIG.get('ha_peer') or '')
    if _addr_key(mine) == _addr_key(had_mine):
        mine = ''
    sub_again = False
    if _addr_key(peer) == _addr_key(had_peer):
        peer = ''
        # The subscription still on another address (a move that failed half
        # way before 1.0.209): put where ha_peer says.
        if had_peer and _sub_host(store) not in ('', had_peer):
            peer, sub_again = had_peer, True
    if not mine and not peer:
        return {'message': 'nothing to change: both addresses are as this node has them',
                'done': [], 'left': []}
    # One address compared with the other (1.0.56), not a substring of a
    # string: 10.0.0.1 beside 10.0.0.12 was refused.
    if peer and _addr_key(peer) == _addr_key(mine or had_mine):
        raise ValueError('the two nodes cannot have one address')
    done, left = [], []
    with READDRESS_LOCK:
        if peer:
            if not sub_again:
                done.append(_readdress_hba(had_peer, peer, root_now, keep_old=keep_old))
            sub = ha_sub_here(store.db, 3 - int(CONFIG.get('ha_slot') or 1))
            if store.db.value(SUB_HERE_SQL, (sub,)):
                conninfo = ha_conninfo(peer, int(CONFIG.get('ha_peer_port') or 5432),
                                       CONFIG.get('db_name'), CONFIG.get('db_user'),
                                       CONFIG.get('db_password'))
                try:
                    sub_connection_set(store, sub, conninfo)
                except ValueError as e:
                    raise ValueError('the subscription %s could not be pointed at %s: %s'
                                     % (sub, peer, str(e).split(': ', 1)[-1]))
                done.append('this node takes the other\'s rows from %s now' % peer)
            # Written once the subscription was moved (1.0.209): written first, a
            # move that failed left config.json on the new address and the
            # subscription on the old one - and asked again, "nothing to change".
            if not sub_again:
                write_file_settings({'ha_peer': peer})
                CONFIG['ha_peer'] = peer
                done.append('ha_peer = %s (was %s)' % (peer, had_peer))
            once_peer_forget()
        if mine:
            write_file_settings({'ha_address': mine})
            CONFIG['ha_address'] = mine
            done.append('ha_address = %s (was %s)' % (mine, had_mine))
        # The other node told, straight into its database: it is reached at
        # its address as this node now has it.
        if tell:
            d2, l2 = readdress_tell(peer or had_peer, mine or had_mine, by, keep_old)
            done += d2
            left += l2
            _readdress_tell_keep(store, peer or had_peer, mine or had_mine, by, keep_old,
                                 bool(l2))
    hatls_check_soon()
    store.add_event('settings', '%s: the addresses of the cluster changed on %s - %s%s' % (
        by or 'command line', node_name(), '; '.join(done),
        (' - left: ' + '; '.join(left)) if left else ''), 'warn', who=by or 'command line')
    log('the addresses of the cluster changed: %s' % '; '.join(done + left), 'warn')
    if daemon is not None:
        try:
            daemon.reload_all('the addresses of the cluster changed')
        except Exception:                               # noqa: BLE001
            pass
    return {'message': '; '.join(done + left), 'done': done, 'left': left}


def _sub_host(store):
    """The host this node's subscription reaches the other at ('' unknown)."""
    try:
        sub = ha_sub_here(store.db, 3 - int(CONFIG.get('ha_slot') or 1))
        conn = store.db.value('SELECT subconninfo FROM pg_subscription WHERE subname = ?', (sub,))
        got = re.search(r'(?:^|\s)host=(\S+)', str(conn or ''))
        return got.group(1).strip("'") if got else ''
    except Exception:                                   # noqa: BLE001
        return ''


def readdress_tell(peer, mine, by, keep_old=False):
    """The other node (at `peer`) told this node is at `mine`, straight into
    its database. (done, left) in words."""
    done, left = [], []
    ask = {'at': time.time(), 'by': by, 'from': node_name(), 'mine': peer, 'peer': mine,
           'keep_old': bool(keep_old)}
    told = False
    # As the link is set; where its certificate names the old address, by the
    # cluster's authority alone (1.0.139) - not unchecked, nor in the clear:
    # whoever stood between could have written this request themselves.
    mode, ca = ha_link_tls()
    tries = [None] + ([('verify-ca', ca)] if mode == 'verify-full' else [])
    for tls in tries:
        try:
            far = db_open(ha_peer_conf(timeout=5, tls=tls))
        except Exception:                               # noqa: BLE001
            continue
        try:
            far.run('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE '
                    'SET v = EXCLUDED.v', ('readdress:ask', json.dumps(ask)))
            # Signed there as the row is written there (1.0.231): the row is this node's
            # word, made only there.
            dbguard_sign(far, 'm', 'readdress:ask', json.dumps(ask))
            told = True
            break
        except Exception:                               # noqa: BLE001
            continue
        finally:
            far.close()
    if told:
        done.append('the other node was told and puts its side right by itself '
                    '(within seconds)')
    else:
        left.append('the other node could not be reached at %s to be told: do the same '
                    'there - its pages (Settings → High availability → The addresses of '
                    'the two nodes) or  acme --ha-readdress --ha-address %s --ha-peer %s  on it'
                    % (peer, peer, mine))
    return done, left


def _readdress_tell_keep(store, peer, mine, by, keep_old, failed):
    """A tell that failed while this node goes back to its old network (1.0.56,
    as otp 1.0.262 R3-5): kept in 'readdress:tell:NODE' and tried again by
    readdress_tick - it was tried once after the restart, and the other node
    went on pointing at the address given up. Told, the row goes."""
    k = 'readdress:tell:' + node_name()
    try:
        if not failed:
            if store.get_meta(k):
                store.db.run('DELETE FROM meta WHERE k = ?', (k,))
            return
        job = _meta_obj(store, 'net:job:' + node_name())
        if not job.get('rollback') or job.get('state') != 'running':
            return
        store.set_meta(k, json.dumps({'peer': peer, 'mine': mine, 'by': by,
                                      'keep_old': bool(keep_old), 'at': time.time()}))
    except Exception as e:                              # noqa: BLE001
        log('the other node to be told again later: %s' % e, 'warn')


def readdress_tell_again(store):
    """The kept tell (1.0.56) tried again: every minute while the other node's
    heartbeat is fresh, every 5 min otherwise, not while this node's network
    job is still under way; dropped once told, or once ha_address moved on."""
    k = 'readdress:tell:' + node_name()
    try:
        row = json.loads(store.get_meta(k) or 'null')
    except ValueError:
        row = None
    if not isinstance(row, dict):
        return
    if _addr_key(row.get('mine')) != _addr_key(CONFIG.get('ha_address') or node_address()):
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
        log('the other node is no longer told %s: ha_address moved on' % row.get('mine'), 'info')
        return
    if net_job_active(_meta_obj(store, 'net:job:' + node_name())):
        return
    alive = any(n.get('alive') for n in ha_nodes(store) if not n.get('me'))
    if time.time() - READDRESS_TELL_TRIED['at'] < (60 if alive else 300):
        return
    READDRESS_TELL_TRIED['at'] = time.time()
    done, left = readdress_tell(str(CONFIG.get('ha_peer') or row.get('peer') or ''),
                                row.get('mine') or '', row.get('by') or 'acme',
                                bool(row.get('keep_old')))
    if done and not left:
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))
        log('the other node told %s at last' % row.get('mine'), 'info')
        store.add_event('settings', 'the other node was told %s is at %s again' % (
            node_name(), row.get('mine')), 'info', who=row.get('by') or 'acme')


def readdress_tick(store, daemon=None):
    """A request the other node wrote into this database: this node's part."""
    # A tell that failed after going back, tried again (1.0.56).
    try:
        readdress_tell_again(store)
    except Exception as e:                              # noqa: BLE001
        log_sparing('readdress-tell-again', 'telling the other node again: %s' % e, 'warn',
                    every=600)
    raw = store.get_meta('readdress:ask')
    if not raw:
        return
    try:
        ask = json.loads(raw)
    except ValueError:
        return
    if not isinstance(ask, dict) or ask.get('from') == node_name() or ask.get('done'):
        return
    try:
        got = ha_readdress(store, ask.get('mine') or '', ask.get('peer') or '',
                           by='%s (told by %s)' % (ask.get('by') or 'acme', ask.get('from')),
                           tell=False, daemon=daemon, keep_old=bool(ask.get('keep_old')))
        ask.update(done=time.time(), said=got['message'])
    except Exception as e:                              # noqa: BLE001
        ask.update(done=time.time(), error=str(e)[:300])
        log('putting the addresses of the cluster right as %s asked: %s'
            % (ask.get('from'), e), 'warn')
        store.add_event('settings', 'the addresses of the cluster could not be put right on %s '
                        'as %s asked: %s' % (node_name(), ask.get('from'), e), 'bad')
    store.set_meta('readdress:ask', json.dumps(ask))


def readdress_view(store):
    """What the pages show: the addresses as this node has them, what it
    seems to have now, and whether the other node is reached there."""
    said = node_address()
    out = {'mine': str(CONFIG.get('ha_address') or ''), 'peer': str(CONFIG.get('ha_peer') or ''),
           'detected': said, 'addresses': readdress_addresses()}
    out['mine_here'] = not out['mine'] or out['mine'] in out['addresses'] or \
        out['mine'].startswith('127.') or out['mine'] == '::1' or not out['addresses']
    try:
        raw = json.loads(store.get_meta('readdress:ask') or 'null')
        if isinstance(raw, dict):
            out['last'] = raw
    except ValueError:
        pass
    return out


def readdress_addresses():
    """The addresses this machine has, without loopback and link-local - from
    local_addresses() (88w_web), never a second function of that name: one
    here (1.0.106) took its place everywhere, found no `ip` in the service's
    PATH, and the VIP address showed "on no node" though a node held it."""
    out = []
    for a in sorted(local_addresses()):
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            continue
        out.append(str(ip))
    return out
