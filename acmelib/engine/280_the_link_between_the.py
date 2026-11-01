# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the link between the two databases: encrypted and checked (1.0.104) -----------
# One button on the High availability page does it on a running cluster,
# without stopping anything, on both nodes:
#   1. the cluster gets an authority of its own (kept in the database, its key
#      sealed), and each node a certificate from it for every name and address
#      the other node may reach its PostgreSQL by;
#   2. each node's root helper (acme_web.py) puts the certificate into its
#      PostgreSQL, the authority into /etc/pki/acme/ha-ca.pem (readable by
#      PostgreSQL's own workers), switches ssl on and reloads - no restart;
#   3. once both servers answer with them, each node tries the other with
#      verify-full and only then takes it for its own link (config.json:
#      ha_tls, ha_tls_ca) and moves its subscription over to it;
#   4. once both subscriptions are on it, each server takes the other node
#      only over TLS (pg_hba.conf: host -> hostssl for the other node).
# The local connection of the daemon to 127.0.0.1 is left as it is: Database
# → TLS is about a database on another machine.
# Certificates are renewed by each node by itself 45 days before they end; the
# authority is replaced two years before it ends, the old one trusted beside
# the new one until it runs out. The button also mends a link whose
# certificate has run out: the other node is then told over an encrypted but
# unchecked connection - only to start the same steps.
HA_CA_FILE = Path(os.environ.get('ACME_HA_CA', '/etc/pki/acme/ha-ca.pem'))
PGTLS_ASK = 'pgtls.ask'
PGTLS_FILE = 'pgtls.json'
HATLS_LOCK = threading.Lock()
HATLS_STEPS = ('names', 'server', 'link', 'hba', 'done')
HATLS_CERT_DAYS = 730
HATLS_RENEW_DAYS = 45
HATLS_CA_DAYS = 7300
HATLS_CA_ROLL_DAYS = 730


def hatls_version(v):
    out = []
    for x in re.split(r'[.-]', str(v or '')):
        try:
            out.append(int(x))
        except ValueError:
            out.append(0)
    return tuple(out)


def ha_link_tls(c=None):
    """(mode, authority file) of the link to the other node's PostgreSQL:
    its own when set, else the database's as before (1.0.33)."""
    c = CONFIG if c is None else c
    if c.get('ha_tls'):
        return str(c.get('ha_tls')), str(c.get('ha_tls_ca') or '')
    if str(c.get('db_tls_ca') or '') == str(HA_CA_FILE):
        # The daemon's own connection encrypted by Settings → The database
        # (1.0.172): that is this node's PostgreSQL on 127.0.0.1, not the other
        # node's - the link is not moved with it, nor stopped by it.
        return '', ''
    return str(c.get('db_tls') or ''), str(c.get('db_tls_ca') or '')


def ha_peer_conf(timeout=None, tls=None):
    c = {k: CONFIG.get(k) for k in DB_KEYS}
    c['db_host'] = CONFIG.get('ha_peer')
    c['db_port'] = CONFIG.get('ha_peer_port') or 5432
    c['db_tls'], c['db_tls_ca'] = tls if tls is not None else ha_link_tls()
    if timeout:
        c['db_timeout_s'] = timeout
    return c


def _cert_end(pem):
    out = _openssl(['x509', '-noout', '-enddate'], pem.encode(), what='the certificate')
    when = out.decode().strip().split('=', 1)[-1]
    return float(ssl.cert_time_to_seconds(when))


def hatls_ca(store):
    try:
        got = json.loads(store.get_meta('hatls:ca') or 'null')
    except ValueError:
        got = None
    return got if isinstance(got, dict) and got.get('cas') else {'cas': []}


def hatls_ca_make(store, by):
    """A new authority for the cluster, put in front of the ones it has; the
    old ones are trusted beside it until they run out."""
    key = new_key('ec')
    with tempfile.TemporaryDirectory(prefix='acme-ca-') as t:
        kf = os.path.join(t, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key)
        os.chmod(kf, 0o600)
        name = re.sub(r'[^A-Za-z0-9 .-]', '', str(CONFIG.get('site_name') or 'acme'))[:40] or 'acme'
        crt = _openssl(['req', '-new', '-x509', '-key', kf, '-days', str(HATLS_CA_DAYS),
                        '-subj', '/CN=%s cluster database authority %s'
                        % (name, datetime.now().strftime('%Y-%m-%d %H:%M')),
                        '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
                       what='the authority').decode()
    ca = hatls_ca(store)
    now = time.time()
    cas = [{'cert': crt, 'key': seal_secret(key, bind='hatls:ca'), 'end': _cert_end(crt),
            'at': now, 'by': by}]
    cas += [x for x in ca['cas'] if float(x.get('end') or 0) > now][:3]
    store.set_meta('hatls:ca', json.dumps({'cas': cas}))
    return cas[0]


def hatls_trust(ca):
    """Every authority still good, the newest first - one file."""
    now = time.time()
    return ''.join(x['cert'].strip() + '\n' for x in ca['cas'] if float(x.get('end') or 0) > now)


def hatls_names(peer_host=''):
    names = [node_name(), 'localhost', '127.0.0.1', '::1']
    for n in (CONFIG.get('ha_address'), node_address(), socket.gethostname(), socket.getfqdn(),
              peer_host):
        n = str(n or '').strip()
        if n and n not in names:
            names.append(n)
    ok = []
    for n in names:
        try:
            _san_ext([n])
            ok.append(n)
        except ValueError:
            pass
    return ok


def hatls_san(names):
    """subjectAltName with every address twice (1.0.105): as an address, for
    libpq 14 and later, and as a name, for libpq 13 - the one RHEL/Alma 9 has
    and the daemon uses - which reads names alone and refused 192.168.42.33."""
    out = []
    for n in names:
        one = _san_ext([n])
        out.append(one)
        if one.startswith('IP:'):
            out.append('DNS:' + n)
    return ','.join(out)


def hatls_needs(store):
    """The addresses the other node reaches this one by - each must be in this
    node's certificate both ways."""
    want = set()
    peer_name = hatls_peer_name(store)
    peer = hatls_state(store, peer_name) if peer_name else {}
    for n in (CONFIG.get('ha_address'), node_address(), peer.get('peer_host'),
              peer.get('peer_lacks')):
        n = str(n or '').strip()
        if n:
            want.add(n)
    for b in ha_nodes(store):
        if b['me'] and b.get('address'):
            want.add(str(b['address']))
    return sorted(want)


def hatls_issue(store, names, eku='serverAuth', days=None, cn=None):
    """A key and a certificate for this node's PostgreSQL, from the newest
    authority of the cluster - or (1.0.172) another use of acme's authority:
    isemon's server, a node's client certificate (eku clientAuth)."""
    ca = hatls_ca(store)
    if not ca['cas']:
        raise ValueError('the cluster has no authority yet')
    top = ca['cas'][0]
    ca_key = unseal_secret(top['key'], bind='hatls:ca')
    if not ca_key or not str(ca_key).startswith('-----BEGIN'):
        raise ValueError('the authority\'s key cannot be opened on this node (is its '
                         'secrets.key the cluster\'s?)')
    key = new_key('ec')
    cn = re.sub(r'[^A-Za-z0-9.-]', '', cn or node_name())[:64] or 'acme'
    with tempfile.TemporaryDirectory(prefix='acme-crt-') as t:
        for n, v in (('k.pem', key), ('ca.pem', top['cert']), ('cakey.pem', ca_key)):
            with open(os.path.join(t, n), 'w') as f:
                f.write(v)
            os.chmod(os.path.join(t, n), 0o600)
        with open(os.path.join(t, 'ext.cnf'), 'w') as f:
            f.write('[v3]\nbasicConstraints=critical,CA:FALSE\n'
                    'keyUsage=critical,digitalSignature,keyEncipherment\n'
                    'extendedKeyUsage=%s\n' % eku +
                    ('subjectAltName=%s\n' % hatls_san(names) if names else ''))
        csr = _openssl(['req', '-new', '-key', os.path.join(t, 'k.pem'), '-subj', '/CN=' + cn],
                       what='the request')
        crt = _openssl(['x509', '-req', '-CA', os.path.join(t, 'ca.pem'), '-CAkey',
                        os.path.join(t, 'cakey.pem'), '-set_serial',
                        str(int.from_bytes(secrets.token_bytes(12), 'big')), '-days',
                        str(int(days or HATLS_CERT_DAYS)), '-sha256', '-extfile',
                        os.path.join(t, 'ext.cnf'), '-extensions', 'v3'], csr,
                       what='the certificate').decode()
    return key, crt


def hatls_state(store, name=None):
    try:
        got = json.loads(store.get_meta('hatls:node:' + (name or node_name())) or 'null')
    except ValueError:
        got = None
    return got if isinstance(got, dict) else {}


def hatls_put(store, st):
    st['at'] = time.time()
    st['node'] = node_name()
    store.set_meta('hatls:node:' + node_name(), json.dumps(st))
    if st.get('step') in ('done', 'off_done'):
        DBTLS_WORK['at'] = 0.0          # the row of Encryption to the database anew (1.0.172)


def hatls_want(store):
    try:
        got = json.loads(store.get_meta('hatls:want') or 'null')
    except ValueError:
        got = None
    return got if isinstance(got, dict) else None


def hatls_peer_name(store):
    for n in ha_nodes(store):
        if not n['me']:
            return n['name']
    return ''


def hatls_view(store):
    mode, ca_file = ha_link_tls()
    ca = hatls_ca(store)
    nodes = []
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'hatls:node:%'"):
        try:
            one = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        one['name'] = r['k'][len('hatls:node:'):]
        one['me'] = one['name'] == node_name()
        one.pop('asked', None)
        nodes.append(one)
    nodes.sort(key=lambda x: (not x['me'], x['name']))
    w = hatls_want(store)
    return {'mode': mode, 'ca_file': ca_file, 'own': bool(CONFIG.get('ha_tls')),
            'want': w, 'nodes': nodes,
            'authority_end': [float(x.get('end') or 0) for x in ca['cas']],
            'off': bool(w and w.get('off')),
            'running': bool(w) and any(x.get('for') == w.get('at') and x.get('step') not in
                                       ('done', 'failed', 'off_done') for x in nodes)}


def hatls_start(store, by, here=True):
    """The button: both nodes, every step, from wherever they are."""
    if CONFIG.get('ha_mode') != 'replicated':
        raise ValueError('this node does not replicate')
    if store.db.engine != 'postgres':
        raise ValueError('the link is between two PostgreSQLs')
    peer = next((n for n in ha_nodes(store) if not n['me']), None)
    if peer and peer.get('alive') and hatls_version(peer.get('version')) < (1, 0, 104):
        raise ValueError('the other node runs acme %s: upgrade it to this version first'
                         % peer.get('version'))
    if not WEB_DIR.is_dir():
        raise ValueError('%s is not here: the root helper of this node is not installed '
                         '(install.sh --upgrade puts it in)' % WEB_DIR)
    with HATLS_LOCK:
        ca = hatls_ca(store)
        now = time.time()
        if not ca['cas'] or float(ca['cas'][0].get('end') or 0) - now < HATLS_CA_ROLL_DAYS * 86400:
            hatls_ca_make(store, by)
        w = {'at': now, 'by': by, 'from': node_name()}
        store.set_meta('hatls:want', json.dumps(w))
    said = 'both nodes are on their way'
    # The other node told straight into its own database too: with the link
    # stopped (a certificate run out) nothing would carry it over. Checked
    # first, unchecked when that is what does not work - only to say "start".
    told = False
    for tls in (None, ('require', ''), ('prefer', '')):
        try:
            far = db_open(ha_peer_conf(timeout=5, tls=tls))
        except Exception:                               # noqa: BLE001
            continue
        try:
            # The same values replication carries anyway, written in place -
            # never a delete, which would go over and take them away here.
            # Only over a row the other node has already (1.0.147): a row made
            # there and here at once is a duplicate key that stops replication
            # for good. A row new here goes over by replication.
            hits = 0
            for k, v in (('hatls:ca', store.get_meta('hatls:ca')), ('hatls:want', json.dumps(w))):
                hits += far.run('UPDATE meta SET v = ? WHERE k = ?', (v, k)) or 0
            told = hits > 0
            break
        except Exception:                               # noqa: BLE001
            continue
        finally:
            far.close()
    if not told:
        said = ('this node is on its way; the other node\'s database could not be reached '
                'just now - it starts when replication carries it over, or press the button '
                'there')
    store.add_event('settings', '%s: the link between the databases is being encrypted and '
                    'checked (verify-full) on both nodes' % by, who=by)
    if here:
        threading.Thread(target=hatls_tick, args=(store,), name='hatls', daemon=True).start()
    return {'message': said, 'link_tls': hatls_view(store)}


HATLS_OFF_STEPS = ('off_hba', 'off_link', 'off_server', 'off_done')


def hatls_off(store, by, here=True):
    """TLS between the databases switched off again (1.0.107), the steps the
    other way round so replication never stops on it: both databases let the
    other node in without TLS, then both links go back, then the cluster's
    certificates leave both PostgreSQLs (ssl as it was before acme)."""
    if CONFIG.get('ha_mode') != 'replicated':
        raise ValueError('this node does not replicate')
    now = time.time()
    w = {'at': now, 'by': by, 'from': node_name(), 'off': True}
    store.set_meta('hatls:want', json.dumps(w))
    told = False
    for tls in (None, ('require', ''), ('prefer', '')):
        try:
            far = db_open(ha_peer_conf(timeout=5, tls=tls))
        except Exception:                               # noqa: BLE001
            continue
        try:
            told = bool(far.run('UPDATE meta SET v = ? WHERE k = ?',
                                ('hatls:want', json.dumps(w))))   # see hatls_start
            break
        except Exception:                               # noqa: BLE001
            continue
        finally:
            far.close()
    store.add_event('settings', '%s: TLS between the databases is being switched off on both '
                    'nodes' % by, 'warn', who=by)
    if here:
        threading.Thread(target=hatls_tick, args=(store,), name='hatls', daemon=True).start()
    return {'message': 'both nodes are on their way' if told else
            'this node is on its way; the other node could not be reached just now - it starts '
            'when replication carries it over, or press the button there',
            'link_tls': hatls_view(store)}


def _hatls_off_tick(store, w, st):
    now = time.time()
    if st.get('for') != w.get('at'):
        st = {'for': w.get('at'), 'step': 'off_hba', 'began': now, 'off': True}
        hatls_put(store, st)
    if st.get('step') in ('off_done', 'failed'):
        return
    pn = hatls_peer_name(store)
    peer = hatls_state(store, pn) if pn else {}
    rank = {x: i for i, x in enumerate(HATLS_OFF_STEPS)}

    def peer_at(step):
        if not peer:
            return True                 # no other node known: nothing to wait for
        return peer.get('for') == st.get('for') and rank.get(peer.get('step'), -1) >= rank[step]

    def helper(what, then, said):
        if st.get('asked'):
            got = _hatls_answer(st)
            if got is None:
                if now - float(st.get('asked_at') or now) > 180:
                    _hatls_fail(store, st, 'the root helper of this node did not answer in 3 '
                                'minutes - is acme-web.path running?  systemctl status acme-web.path')
                return False
            if not got.get('ok'):
                _hatls_fail(store, st, got.get('said') or 'the root helper said no')
                return False
            st.update(step=then, asked=None, said=got.get('said') or '')
            hatls_put(store, st)
            return True
        _hatls_ask(st, what)
        st['said'] = said
        hatls_put(store, st)
        return False

    if st['step'] == 'off_hba':
        if not helper({'do': 'hba_off'}, 'off_link',
                      'this node\'s PostgreSQL lets the other node in without TLS too'):
            return
    if st['step'] == 'off_link':
        if not peer_at('off_link'):
            st['said'] = 'waiting for %s to let this node in without TLS' % (pn or 'the other node')
            hatls_put(store, st)
            return
        write_file_settings({'ha_tls': '', 'ha_tls_ca': ''})
        CONFIG['ha_tls'], CONFIG['ha_tls_ca'] = '', ''
        sub = ha_sub_here(store.db, 3 - int(CONFIG.get('ha_slot') or 1))
        if store.db.value(SUB_HERE_SQL, (sub,)):
            conninfo = ha_conninfo(CONFIG.get('ha_peer'), int(CONFIG.get('ha_peer_port') or 5432),
                                   CONFIG.get('db_name'), CONFIG.get('db_user'),
                                   CONFIG.get('db_password'))
            sub_connection_set(store, sub, conninfo)
        once_peer_forget()
        st.update(step='off_server', said='this node takes the other\'s rows as before (Database '
                  '→ TLS)')
        hatls_put(store, st)
    if st['step'] == 'off_server':
        if not peer_at('off_server'):
            st['said'] = 'waiting for %s to move its link back' % (pn or 'the other node')
            hatls_put(store, st)
            return
        if CONFIG.get('db_tls') and str(CONFIG.get('db_tls_ca') or '') == str(HA_CA_FILE):
            # The daemon's own connection checks PostgreSQL with this
            # certificate (1.0.172): it stays, and Settings → The database
            # renews it from now on - the link is off all the same.
            store.set_meta('dbtls:server:' + node_name(), json.dumps(
                {'cert_end': st.get('cert_end'), 'at': now, 'by': 'kept when the link\'s TLS '
                 'went off', 'names': hatls_names()}))
            st.update(step='off_done', said='the certificate stays in this node\'s PostgreSQL: '
                      'the daemon\'s own connection to it is encrypted with it (Settings → The '
                      'database)', asked=None)
        elif not helper({'do': 'server_off'}, 'off_done',
                        'the cluster\'s certificate leaves this node\'s PostgreSQL'):
            return
        else:
            # Nothing else keeps it: not renewed by Settings → The database either.
            store.db.run('DELETE FROM meta WHERE k = ?', ('dbtls:server:' + node_name(),))
        st.update(cert_end=None, done_at=now)
        hatls_put(store, st)
        store.add_event('ha', 'TLS between the databases is off on %s' % node_name(), 'warn')


PGTLS_LOCK = threading.Lock()


def pgtls_send(data):
    """A request into the root helper's pgtls.ask (1.0.139): one waiting there
    and not yet read is not written over - the change of the addresses and the
    link's TLS used the same file and the same temporary name, and one of
    them waited for an answer that never came."""
    with PGTLS_LOCK:
        end = time.time() + 30
        while (WEB_DIR / PGTLS_ASK).exists() and time.time() < end:
            time.sleep(0.5)
        tmp = WEB_DIR / ('.%s.%s' % (PGTLS_ASK, secrets.token_hex(6)))
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(json.dumps(data))
        os.replace(str(tmp), str(WEB_DIR / PGTLS_ASK))


def _hatls_ask(st, what):
    """A request to this node's root helper, as a file in the folder it reads."""
    ask_id = secrets.token_hex(8)
    data = dict(what, id=ask_id, port=int(CONFIG.get('db_port') or 5432),
                db=str(CONFIG.get('db_name') or 'acme'), user=str(CONFIG.get('db_user') or 'acme'),
                peer=str(CONFIG.get('ha_peer') or ''), ca_file=str(HA_CA_FILE))
    pgtls_send(data)
    st['asked'] = ask_id
    st['asked_at'] = time.time()


def _hatls_answer(st):
    """The helper's answer to the request this node made, or None yet."""
    try:
        got = json.loads((WEB_DIR / PGTLS_FILE).read_text())
    except (OSError, ValueError):
        return None
    if isinstance(got, dict) and got.get('id') == st.get('asked'):
        return got
    return None


def _hatls_fail(store, st, why):
    st.update(step='failed', failed_step=st.get('step'), error=str(why)[:400], asked=None)
    hatls_put(store, st)
    log('encrypting the link between the databases: %s' % why, 'warn')
    store.add_event('ha', 'the link between the databases on %s: %s' % (node_name(), why), 'warn')


# When this node next looks whether what it has is what the cluster wants:
# at start, after a database is put back, and every ten minutes.
HATLS_CHECK = {'next': 0.0}


def hatls_check_soon():
    HATLS_CHECK['next'] = 0.0


def hatls_own_cert(store):
    """The certificate this node's PostgreSQL answers with, checked against
    the cluster's authorities: its end in seconds, or ValueError."""
    trust = hatls_trust(hatls_ca(store))
    if not trust:
        raise ValueError('the cluster has no authority that is still good')
    ctx = ssl.create_default_context(cadata=trust)
    ctx.check_hostname = False
    s = socket.create_connection(('127.0.0.1', int(CONFIG.get('db_port') or 5432)), timeout=5)
    try:
        s.sendall(struct.pack('!II', 8, 80877103))           # SSLRequest
        if s.recv(1) != b'S':
            raise ValueError('this node\'s PostgreSQL does not speak TLS')
        try:
            t = ctx.wrap_socket(s)
        except ssl.SSLError as e:
            raise ValueError('this node\'s PostgreSQL answers with a certificate the cluster\'s '
                             'authority did not sign (%s)' % str(e)[:120])
        try:
            got = t.getpeercert() or {}
        finally:
            t.close()
    finally:
        try:
            s.close()
        except OSError:
            pass
    return float(ssl.cert_time_to_seconds(got['notAfter'])), got.get('subjectAltName') or ()


def hatls_check(store):
    """What is in place against what the cluster wants - after a database put
    back, a node reinstalled or joined again, a config.json written anew, a
    PostgreSQL set up again or a certificate run out. Anything not right
    starts this node's steps again by itself; each one is safe to repeat."""
    now = time.time()
    w = hatls_want(store)
    if (not w and not CONFIG.get('ha_tls')) or (w and w.get('off')):
        return                          # never set up, or switched off on purpose
    st = hatls_state(store)
    stuck = st.get('step') == 'link' and now - float(st.get('link_since') or now) > 120
    if st.get('step') not in (None, 'done', 'failed') and not stuck:
        return                          # on its way
    if st.get('step') == 'failed' and now - float(st.get('at') or 0) < 3600:
        # Tried again an hour later - or at once when the other node has put
        # its side right since (1.0.105), or this node's own certificate is
        # what is wrong (looked at below, as for one stuck on the link).
        pn = hatls_peer_name(store)
        peer = hatls_state(store, pn) if pn else {}
        if float(peer.get('at') or 0) > float(st.get('at') or 0) and \
                peer.get('step') in ('link', 'hba', 'done'):
            st2 = {'for': st.get('for') or now, 'step': 'names', 'renew': True, 'began': now,
                   'peer_host': str(CONFIG.get('ha_peer') or ''), 'cert_end': st.get('cert_end'),
                   'said': 'the other node put its side right: tried again'}
            hatls_put(store, st2)
            return
        stuck = True
    ca = hatls_ca(store)
    if not ca['cas'] or not hatls_trust(ca):
        # config.json says verify-full, the database knows no authority (put
        # back from before it): one node makes a new one, both take it.
        if claim_once(store, 'hatls:remake', str(int(time.time() // 600))):
            hatls_ca_make(store, 'acme (no authority in the database)')
            store.set_meta('hatls:want', json.dumps({'at': now, 'by': 'acme (repaired)',
                                                    'from': node_name()}))
            store.add_event('ha', 'the database has no authority for the link between the '
                            'databases (put back from before it?): a new one is made and both '
                            'nodes take it', 'warn')
        return
    wrong = []
    if not st:
        wrong.append('this node has not been through the steps')
    if (CONFIG.get('ha_tls') != 'verify-full' or
            str(CONFIG.get('ha_tls_ca') or '') != str(HA_CA_FILE)) and not stuck:
        wrong.append('its link to the other node is not set to verify-full')
    try:
        end, sans = hatls_own_cert(store)
        if end - now < HATLS_RENEW_DAYS * 86400:
            wrong.append('its database\'s certificate ends %s'
                         % datetime.fromtimestamp(end).strftime('%Y-%m-%d'))
        dns = set(str(v).lower() for k, v in sans if k == 'DNS')
        ips = set()
        for k, v in sans:
            if k == 'IP Address':
                try:
                    ips.add(str(ipaddress.ip_address(str(v).strip())))
                except ValueError:
                    pass
        for n in hatls_needs(store):
            try:
                a = str(ipaddress.ip_address(n))
                ok = a in ips and n.lower() in dns
            except ValueError:
                ok = n.lower() in dns
            if not ok:
                wrong.append('its certificate does not name %s the way every PostgreSQL client '
                             'reads it' % n)
    except Exception as e:                              # noqa: BLE001
        wrong.append(str(e)[:200])
    if stuck:
        # Waiting for the other node's database to pass: only what this node's
        # own certificate lacks is put right here (1.0.105).
        wrong = [x for x in wrong if 'certificate' in x]
    try:
        have = HA_CA_FILE.read_text()
        if ca['cas'][0]['cert'].strip() not in have:
            wrong.append('%s does not hold the newest authority' % HA_CA_FILE)
    except OSError:
        wrong.append('%s is not there' % HA_CA_FILE)
    if not wrong:
        if stuck:
            log('the link between the databases waits for the other node: this node\'s own '
                'certificate names %s - nothing to put right here' % ', '.join(hatls_needs(store)))
        return
    st = {'for': (w or {}).get('at') or now, 'step': 'names', 'renew': True, 'began': now,
          'peer_host': str(CONFIG.get('ha_peer') or ''), 'cert_end': st.get('cert_end'),
          'said': 'put right by itself: ' + '; '.join(wrong)}
    hatls_put(store, st)
    log('the link between the databases is put right on this node: %s' % '; '.join(wrong))
    store.add_event('ha', 'the link between the databases on %s is put right by itself: %s'
                    % (node_name(), '; '.join(wrong)), 'warn')


def hatls_tick(store):
    """One look at where this node is; every step is safe to take again."""
    if CONFIG.get('ha_mode') != 'replicated' or getattr(store.db, 'engine', '') != 'postgres':
        return
    if not HATLS_LOCK.acquire(False):
        return
    try:
        if time.time() >= HATLS_CHECK['next']:
            HATLS_CHECK['next'] = time.time() + 600
            try:
                hatls_check(store)
            except Exception as e:                      # noqa: BLE001
                log('looking at the link between the databases: %s' % e, 'warn')
        _hatls_tick(store)
    except Exception as e:                              # noqa: BLE001
        log('encrypting the link between the databases: %s' % e, 'warn')
    finally:
        HATLS_LOCK.release()


def _hatls_tick(store):
    now = time.time()
    w = hatls_want(store)
    st = hatls_state(store)
    if w and w.get('off'):
        _hatls_off_tick(store, w, st)
        return
    # The other node says this node's certificate lacks a name it reaches it
    # by (1.0.106): a new one at once, not at the next look ten minutes on.
    pn0 = hatls_peer_name(store)
    peer0 = hatls_state(store, pn0) if pn0 else {}
    lacks = str(peer0.get('peer_lacks') or '')
    if w and lacks and peer0.get('step') == 'link' and \
            st.get('step') in ('link', 'hba', 'done', 'failed') and \
            st.get('lack_fixed') != '%s@%s' % (lacks, peer0.get('link_since')):
        st = {'for': st.get('for') or w.get('at'), 'step': 'names', 'renew': True, 'began': now,
              'peer_host': str(CONFIG.get('ha_peer') or ''), 'cert_end': st.get('cert_end'),
              'lack_fixed': '%s@%s' % (lacks, peer0.get('link_since')),
              'said': '%s reaches this node as %s, which its certificate did not name: a new '
                      'one is made' % (pn0, lacks)}
        hatls_put(store, st)
        log('the link between the databases: %s reaches this node as %s - a new certificate'
            % (pn0, lacks))
    # Renewed by itself: the authority within two years of its end (one node
    # makes the new one, and every node's certificate from it), or a
    # certificate of this node ending within 45 days.
    # The authority is looked at whatever this node's certificate (1.0.187):
    # it was only when that ended soon, so the node that may make a new one
    # never did when only the other node's was ending - and that one, not
    # allowed to, renewed nothing at all until its certificate ran out. A
    # node not making it renews its own as ever; tried again the next day
    # if making it failed (not the next month).
    if not w or (st.get('for') == w.get('at') and st.get('step') == 'done'):
        ca = hatls_ca(store)
        if st.get('step') == 'done' and ca['cas'] and \
                float(ca['cas'][0].get('end') or 0) - now < HATLS_CA_ROLL_DAYS * 86400 and \
                claim_once(store, 'hatls:roll', datetime.now().strftime('%Y-%m-%d')):
            hatls_ca_make(store, 'acme (the authority ends soon)')
            w = {'at': now, 'by': 'acme (renewed)', 'from': node_name()}
            store.set_meta('hatls:want', json.dumps(w))
            st = {}
        elif st.get('step') == 'done' and float(st.get('cert_end') or 0) - now < \
                HATLS_RENEW_DAYS * 86400:
            ends = float(st.get('cert_end') or now)
            st = {'for': w.get('at') if w else now, 'step': 'names', 'renew': True,
                  'began': now, 'peer_host': str(CONFIG.get('ha_peer') or '')}
            hatls_put(store, st)
            store.add_event('ha', 'the certificate of %s\'s database ends %s: renewed'
                            % (node_name(), datetime.fromtimestamp(ends).strftime('%Y-%m-%d')))
        if not w or st.get('step') == 'done':
            return
    # A renewal of its own under way is let finish; one finished takes a want
    # come since (1.0.187) - the new authority's: it stayed on the old one's.
    if st.get('for') != w.get('at') and \
            (not st.get('renew') or st.get('step') in ('done', 'failed')):
        st = {'for': w.get('at'), 'step': 'names', 'began': now,
              'peer_host': str(CONFIG.get('ha_peer') or ''), 'cert_end': st.get('cert_end')}
        hatls_put(store, st)
    if st.get('step') in ('done', 'failed'):
        return
    peer_name = hatls_peer_name(store)
    peer = hatls_state(store, peer_name) if peer_name else {}
    peer_here = peer.get('for') == st.get('for') or peer.get('renew') or \
        peer.get('step') == 'done'
    rank = {s: i for i, s in enumerate(HATLS_STEPS)}

    def peer_at(step):
        return bool(peer) and (peer.get('step') == 'done' or
                               (peer_here and rank.get(peer.get('step'), -1) >= rank[step]))

    if st['step'] == 'names':
        # The names the other node reaches this one by come with its state;
        # a minute is waited for them, then this node goes on with its own.
        if not peer_here and now - float(st.get('began') or now) < 60 and not st.get('renew'):
            st['said'] = 'waiting for %s to start' % (peer_name or 'the other node')
            hatls_put(store, st)
            return
        st['names'] = hatls_names(peer.get('peer_host') if peer_here else '')
        for n in hatls_needs(store):
            if n not in st['names']:
                try:
                    _san_ext([n])
                    st['names'].append(n)
                except ValueError:
                    pass
        st['step'] = 'server'
        st['said'] = 'the certificate of this node\'s database is made'
        hatls_put(store, st)
    if st['step'] == 'server':
        if st.get('asked'):
            got = _hatls_answer(st)
            if got is None:
                if now - float(st.get('asked_at') or now) > 180:
                    _hatls_fail(store, st, 'the root helper of this node did not answer in 3 '
                                'minutes - is acme-web.path running?  systemctl status acme-web.path')
                return
            if not got.get('ok'):
                _hatls_fail(store, st, got.get('said') or 'the root helper said no')
                return
            st.update(step='link', asked=None, said=got.get('said') or '',
                      cert_end=got.get('cert_end') or st.get('cert_end'),
                      data_dir=got.get('data_dir') or '')
            hatls_put(store, st)
        else:
            if not hatls_ca(store)['cas']:
                # Gone meanwhile (a database put back from before it): one node
                # makes a new one; the other waits for it to come over.
                if claim_once(store, 'hatls:remake', str(int(time.time() // 600))):
                    hatls_ca_make(store, 'acme (no authority in the database)')
                else:
                    st['said'] = 'waiting for the cluster\'s authority to come over'
                    hatls_put(store, st)
                    return
            key, crt = hatls_issue(store, st.get('names') or hatls_names())
            st['cert_end'] = _cert_end(crt)
            _hatls_ask(st, {'do': 'server', 'cert': crt, 'key': key,
                            'trust': hatls_trust(hatls_ca(store))})
            st['said'] = 'this node\'s PostgreSQL is being given its certificate (root helper)'
            hatls_put(store, st)
            return
    if st['step'] == 'link':
        if not peer_at('link'):
            st['said'] = 'waiting for %s to give its database a certificate' % (
                peer_name or 'the other node')
            hatls_put(store, st)
            return
        if now < float(st.get('retry_at') or 0):
            return
        try:
            far = db_open(ha_peer_conf(timeout=5, tls=('verify-full', str(HA_CA_FILE))))
            try:
                far.value('SELECT 1')
            finally:
                far.close()
        except Exception as e:                          # noqa: BLE001
            why = scrub_secret(str(e).split('\n')[0])[:300]
            if now - float(st.get('link_since') or now) > 900:
                _hatls_fail(store, st, 'the other node\'s database does not pass verify-full: '
                            + why)
                return
            st.setdefault('link_since', now)
            # The other node's certificate lacks the name this node reaches it
            # by: said in this node's state, where the other node reads it and
            # makes itself a new one at once (1.0.106).
            m = re.search(r'does not match host name "([^"]+)"', why)
            if m:
                st['peer_lacks'] = m.group(1)
            st.update(retry_at=now + 20, said='the other node\'s database does not pass '
                      'verify-full yet: ' + why)
            hatls_put(store, st)
            return
        write_file_settings({'ha_tls': 'verify-full', 'ha_tls_ca': str(HA_CA_FILE)})
        CONFIG['ha_tls'], CONFIG['ha_tls_ca'] = 'verify-full', str(HA_CA_FILE)
        sub = ha_sub_here(store.db, 3 - int(CONFIG.get('ha_slot') or 1))
        if store.db.value(SUB_HERE_SQL, (sub,)):
            conninfo = ha_conninfo(CONFIG.get('ha_peer'), int(CONFIG.get('ha_peer_port') or 5432),
                                   CONFIG.get('db_name'), CONFIG.get('db_user'),
                                   CONFIG.get('db_password'))
            sub_connection_set(store, sub, conninfo)
        once_peer_forget()
        st.update(step='hba', said='this node takes the other\'s rows over TLS, its '
                  'certificate checked (verify-full)', retry_at=0, link_since=None,
                  peer_lacks=None)
        hatls_put(store, st)
    if st['step'] == 'hba':
        if st.get('asked'):
            got = _hatls_answer(st)
            if got is None:
                if now - float(st.get('asked_at') or now) > 180:
                    _hatls_fail(store, st, 'the root helper of this node did not answer in 3 '
                                'minutes - is acme-web.path running?  systemctl status acme-web.path')
                return
            if not got.get('ok'):
                _hatls_fail(store, st, got.get('said') or 'the root helper said no')
                return
            st.update(step='done', asked=None, said=got.get('said') or 'done', done_at=now,
                      error=None, renew=None)
            hatls_put(store, st)
            store.add_event('ha', 'the link between the databases is encrypted and checked on '
                            '%s (verify-full); its certificate ends %s' % (
                                node_name(), datetime.fromtimestamp(
                                    float(st.get('cert_end') or now)).strftime('%Y-%m-%d')))
            return
        if not peer_at('hba'):
            st['said'] = 'waiting for %s to move its link over' % (peer_name or 'the other node')
            hatls_put(store, st)
            return
        _hatls_ask(st, {'do': 'hba'})
        st['said'] = 'this node\'s PostgreSQL is told to take the other node over TLS only'
        hatls_put(store, st)


