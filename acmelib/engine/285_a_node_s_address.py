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
    if mine == had_mine:
        mine = ''
    sub_again = False
    if peer == had_peer:
        peer = ''
        # The subscription still on another address (a move that failed half
        # way before 1.0.209): put where ha_peer says.
        if had_peer and _sub_host(store) not in ('', had_peer):
            peer, sub_again = had_peer, True
    if not mine and not peer:
        return {'message': 'nothing to change: both addresses are as this node has them',
                'done': [], 'left': []}
    if peer and peer in (mine or had_mine):
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


def readdress_tick(store, daemon=None):
    """A request the other node wrote into this database: this node's part."""
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
