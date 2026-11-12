# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- something asked of every node, each answering for itself (1.0.169) ----------------
# A test that only a node itself can make - Proxy → Try it, a test line to
# isemon or to the syslog servers - asked once on the pages and made on every
# node: the ask is kept in the database ('ask:want:KIND'), each node's loop
# sees it within seconds and writes its own answer ('ask:got:KIND:NODE'), the
# page shows every node's as they come. The node the page is on answers at
# once. Each answer is made in a thread of its own.
NODE_ASK = {'do': {}, 'done': set(), 'daemon': [None]}
NODE_ASK_FRESH = 120


def node_ask_kind(kind):
    """Registers what a kind of ask does: fn(daemon, args) -> dict."""
    def put(fn):
        NODE_ASK['do'][kind] = fn
        return fn
    return put


def _node_ask_run(daemon, kind, want):
    key = '%s:%s' % (kind, want.get('id'))
    if key in NODE_ASK['done'] or kind not in NODE_ASK['do']:
        return
    if len(NODE_ASK['done']) > 2000:
        # Kept to a size (1.0.209): one per test pressed, for good. Only an ask
        # fresh within NODE_ASK_FRESH is offered again, and done again it only
        # writes this node's answer over itself.
        NODE_ASK['done'].clear()
    args = want.get('args')
    only = (args if isinstance(args, dict) else {}).get('only')
    if only and only != node_name():
        NODE_ASK['done'].add(key)
        return
    NODE_ASK['done'].add(key)
    store = daemon.store

    def go():
        try:
            got = NODE_ASK['do'][kind](daemon, want.get('args') or {})
        except Exception as e:                          # noqa: BLE001
            got = {'ok': False, 'error': str(e)[:300]}
        got = dict(got or {}, id=want['id'], at=time.time(), node=node_name())
        store.set_meta('ask:got:%s:%s' % (kind, node_name()), json.dumps(got, default=str))
    threading.Thread(target=go, name='acme-ask-' + kind, daemon=True).start()


def node_ask(daemon, kind, args, by):
    only = (args or {}).get('only')
    if only and only != node_name() and only not in set(host_nodes(daemon.store)):
        # a node not heard of (1.0.78): said at once - it waited 90 s and said "no answer - is
        # acme running there?", as of a node down, for a name mistyped
        raise ValueError('there is no node %s (the nodes: %s)' % (
            only, ', '.join(sorted(set(host_nodes(daemon.store)) | {node_name()}))))
    want = {'id': secrets.token_hex(6), 'args': args or {}, 'at': time.time(), 'by': by}
    daemon.store.set_meta('ask:want:' + kind, json.dumps(want))
    # Asked from the command line (1.0.188), this node's daemon does it too, as
    # the other's: not in a process that ends when the command does.
    if getattr(daemon, 'serving', True):
        _node_ask_run(daemon, kind, want)
    nodes = [n for n, a in host_alive(daemon.store).items() if a] or [node_name()]
    nodes = sorted(set(nodes) | {node_name()})
    if (args or {}).get('only'):
        nodes = [args['only']]
    return {'id': want['id'], 'nodes': nodes}


def node_ask_tick(daemon):
    NODE_ASK['daemon'][0] = daemon
    for kind in list(NODE_ASK['do']):
        want = _meta_obj(daemon.store, 'ask:want:' + kind)
        if want.get('id') and time.time() - float(want.get('at') or 0) < NODE_ASK_FRESH:
            _node_ask_run(daemon, kind, want)


def node_ask_results(store, kind, ident):
    out = {}
    for n in host_nodes(store):
        got = _meta_obj(store, 'ask:got:%s:%s' % (kind, n))
        out[n] = got if got.get('id') == ident else None
    return out


@node_ask_kind('proxy')
def _ask_proxy(daemon, args):
    return proxy_try(args.get('url') or '')


@node_ask_kind('isemon')
def _ask_isemon(daemon, args):
    sh = getattr(daemon, 'shipper', None)
    if not sh:
        raise ValueError('nothing is sent from this process')
    if not CONFIG.get('isemon'):
        raise ValueError('sending to isemon is off')
    before = dict(sh.sent)
    # A line of the certificates', as isemon reads them (acme-certs), said to be
    # a test - to the receivers only, not into the files.
    who = str(args.get('as_user') or '').strip()
    if who:
        # A test sign-in under the name given, a success or a failure as chosen (1.0.77: the
        # pages' "Send a test sign-in" sent the certificates' test line, name and outcome
        # left out) - as a sign-in to these pages is said, the words saying it is a test.
        ok = args.get('ok', True) not in (False, 0, '0', 'false')
        words = ('%s signed in from %s (a test from acme, sent by %s)' if ok else
                 'a wrong password for %s from %s (a test from acme, sent by %s)') % (
            who, node_name(), args.get('by') or '?')
        sh.put('acme', 'daemon', event_kv(
            'sign-ins', words, 'info' if ok else 'warn', who, node_name(),
            {'action': 'sign-in', 'result': 'ok' if ok else 'failed', 'user': who, 'test': 1}))
    else:
        sh.put('acme-certs', 'daemon', event_kv(
            'certificates', 'a test from acme %s on %s, sent by %s - nothing happened to a '
            'certificate' % (__version__, node_name(), args.get('by') or '?'), 'info',
            str(args.get('by') or ''), node_name()))
    sh.flush(8)
    st = sh.state()
    went = [k for k, v in st.get('sent', {}).items() if v > before.get(k, 0)]
    return {'ok': bool(went) and not st.get('trouble'), 'went': went, 'state': st}


@node_ask_kind('siem')
def _ask_siem(daemon, args):
    si = getattr(daemon, 'siem', None)
    if not si:
        raise ValueError('nothing is sent from this process')
    got = si.test(args.get('by') or '?')
    return {'ok': all(v == 'sent' for v in got.values()), 'test': got, 'state': si.state()}


@node_ask_kind('dircheck')
def _ask_dircheck(daemon, args):
    ad = daemon.dirs.get(str(args.get('name') or '').lower())
    if not ad:
        raise ValueError('there is no directory called %s here' % args.get('name'))
    c = ad.check()
    ok = any(sv.get('ok') for sv in c.get('servers') or [])
    return {'ok': ok, 'check': c}


# ---- the daemon's own connection to its database: encrypted and checked (1.0.170) -------
# Settings → The database → Encryption to the database server, as a wizard, on
# the running installation - every node, nothing stopped:
#   replicated - each node's own PostgreSQL: the certificate the link between
#                the databases gave it (High availability) when that is on, or
#                one from the same authority given here when it is not - the
#                two are on and off each by itself (1.0.172): the link's TLS
#                switched off leaves the certificate where the connection uses
#                it, and this one switched off leaves it where the link does;
#   local      - PostgreSQL on this machine, no cluster: it is given a
#                certificate from acme's own authority (renewed by itself 45 days
#                before it ends, and made again when the machine's names or
#                addresses change), then the connection moves over;
#   remote     - a database server elsewhere (and the one of a shared cluster):
#                its administrator gave it a certificate; its authority is given
#                here, or the system's is used, or acme's own when that server is
#                another node's PostgreSQL given one by this wizard.
# The wizard goes in phases, each asked of every node and finished on all of
# them before the next: 'server' (the certificates of the PostgreSQLs on the
# nodes themselves), then 'connect' (every node's connection moved over). Off
# the other way round: 'connect' with no TLS on every node, then 'server_off'.
# Each move is made on the live database: the new connection is tried apart
# first, then config.json is written and the daemon's connections are made
# again with it - and put back at once to what they were if the first
# statement on the new one does not go.
# A connection that never leaves the machine (localhost) that stops working
# because of its TLS - the certificate gone, PostgreSQL set up again - is moved
# back to no TLS by itself, with an alert, unless high security forbids it:
# the renewals come first.
DBTLS_CA = STATE_DIR / 'db-ca.pem'
DBTLS_EVERY = 300
DBTLS_RENEW_DAYS = 45
DBTLS_LOCK = threading.Lock()
DBTLS_WORK = {'at': 0.0, 'rescue': 0.0, 'renew': None}
DBTLS_MODES = ('', 'require', 'verify-ca', 'verify-full')


def dbtls_kind(conf=None):
    c = CONFIG if conf is None else conf
    if c.get('db_engine') not in ('postgres', 'mariadb'):
        return 'sqlite'
    host = str(c.get('db_host') or '').strip()
    if not host or host.startswith('/'):
        return 'socket'                 # a Unix socket: nothing crosses a network
    local = host.strip('[]') in ('127.0.0.1', 'localhost', '::1')
    if c.get('db_engine') == 'postgres' and local:
        return 'replicated' if c.get('ha_mode') == 'replicated' else 'local'
    return 'remote'


def _dbtls_system_ca():
    """The system's authorities as one file: libpq has no 'the system' before
    PostgreSQL 16, and an empty sslrootcert with verify-ca looks in ~/.postgresql."""
    p = ssl.get_default_verify_paths()
    for f in (p.cafile, p.openssl_cafile, '/etc/pki/tls/certs/ca-bundle.crt',
              '/etc/ssl/certs/ca-certificates.crt'):
        if f and os.path.isfile(f):
            return str(f)
    return ''


def _dbtls_ssl(db):
    """What the server says of this very connection: (ssl, version, cipher)."""
    if db.engine == 'postgres':
        row = db.row('SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()')
        if not row:
            return False, '', ''
        return bool(row.get('ssl')), str(row.get('version') or ''), str(row.get('cipher') or '')
    if db.engine == 'mariadb':
        got = {r.get('Variable_name') or r.get('variable_name'): r.get('Value') or r.get('value')
               for r in db.rows("SHOW SESSION STATUS LIKE 'Ssl_%'")}
        cipher = str(got.get('Ssl_cipher') or '')
        return bool(cipher), str(got.get('Ssl_version') or ''), cipher
    return False, '', ''


def dbtls_probe(mode, ca):
    """A connection of its own with these settings: whether it opens, and
    whether it is encrypted. The daemon's own connections are not touched."""
    c = {k: CONFIG.get(k) for k in DB_KEYS}
    c.update(db_tls=mode, db_tls_ca=ca, db_timeout_s=8)
    began = time.time()
    out = {'mode': mode, 'ca': ca}
    try:
        db = db_open(c, statement_s=10)
    except Exception as e:                              # noqa: BLE001
        return dict(out, ok=False, said=scrub_secret(str(e).split('\n')[0])[:300],
                    ms=int((time.time() - began) * 1000))
    try:
        db.value('SELECT 1')
        ssl_on, ver, cipher = _dbtls_ssl(db)
    except Exception as e:                              # noqa: BLE001
        return dict(out, ok=False, said=scrub_secret(str(e).split('\n')[0])[:300],
                    ms=int((time.time() - began) * 1000))
    finally:
        try:
            db.close()
        except Exception:                               # noqa: BLE001
            pass
    out.update(ok=True, ssl=ssl_on, version=ver, cipher=cipher,
               ms=int((time.time() - began) * 1000))
    if mode and not ssl_on:
        out.update(ok=False, said='it opened, but not encrypted - the server does not speak TLS')
    return out


def _dbtls_dbs(daemon):
    """Every connection of this daemon to its database."""
    out = [daemon.store.db]
    r = getattr(daemon, '_reader', None)
    if r is not None and getattr(r, 'db', None) is not None and r.db is not daemon.store.db:
        out.append(r.db)
    return out


def _dbtls_reconnect(daemon, mode, ca):
    """Every connection of the daemon made again with (mode, ca) at its next
    statement - the waits after a failed try forgotten too, or a lane that
    failed with the old settings would say so for another minute."""
    for d in _dbtls_dbs(daemon):
        d.tls, d.tls_ca = mode, ca
        d.close()
        for lane in list(getattr(d, '_lanes', {}).values()):
            lane.failed_until = 0.0
            lane.down_until = 0.0


def _dbtls_hisec(mode, store):
    if mode in ('verify-ca', 'verify-full') or dbtls_kind() in ('sqlite', 'socket'):
        return
    if hisec_enforced('db:tls', store):
        raise ValueError('high security is on: the database is reached with TLS that checks its '
                         'certificate (verify-ca or verify-full) - or make db:tls an exception '
                         'there first')


def dbtls_switch(daemon, mode, ca, by):
    """This node's connection moved over to (mode, ca) - on the live database,
    put back as it was if the new one does not go."""
    if mode not in DBTLS_MODES:
        raise ValueError('the mode is require, verify-ca or verify-full')
    with DBTLS_LOCK:
        if mode and dbtls_kind() in ('sqlite', 'socket'):
            raise ValueError('the database is %s - nothing goes over a network to encrypt'
                             % ('a file on this machine' if dbtls_kind() == 'sqlite' else
                                'reached over a Unix socket'))
        _dbtls_hisec(mode, daemon.store)
        p = dbtls_probe(mode, ca)
        if not p['ok']:
            raise ValueError('a connection with %s did not go: %s' % (mode or 'no TLS', p['said']))
        old = (str(CONFIG.get('db_tls') or ''), str(CONFIG.get('db_tls_ca') or ''))
        if old == (mode, ca):
            dbtls_publish(daemon, force=True)
            return dict(p, changed=False)

        def use(m, c):
            write_file_settings({'db_tls': m, 'db_tls_ca': c})
            CONFIG['db_tls'], CONFIG['db_tls_ca'] = m, c
            _dbtls_reconnect(daemon, m, c)
        use(mode, ca)
        try:
            daemon.store.db.value('SELECT 1')
            ssl_on, ver, cipher = _dbtls_ssl(daemon.store.db)
            if mode and not ssl_on:
                raise ValueError('the new connection is not encrypted')
        except Exception as e:                          # noqa: BLE001
            use(*old)
            try:
                daemon.store.db.value('SELECT 1')
            except Exception:                           # noqa: BLE001
                pass
            raise ValueError('the daemon\'s connection did not go with it, so it is as it was: %s'
                             % scrub_secret(str(e).split('\n')[0])[:300])
        DBTLS_WORK.pop('rescued', None)
        try:
            daemon.store.db.run('DELETE FROM meta WHERE k = ?', ('dbtls:rescued:' + node_name(),))
        except Exception:                               # noqa: BLE001
            pass
        daemon.store.add_event('settings', '%s: the connection of %s to its database %s' % (
            by, node_name(), ('is encrypted (%s, %s)' % (mode, ver or 'TLS')) if mode else
            'is no longer encrypted'), 'warn' if not mode else 'info', who=by)
        log('the connection to the database: %s' % (('%s, %s' % (mode, ver)) if mode else
                                                    'no TLS'))
        dbtls_publish(daemon, force=True)
        return dict(p, changed=True, version=ver, cipher=cipher)


def _dbtls_helper(what, store, by, wait=120):
    """A request to this node's root helper about its PostgreSQL, and its answer."""
    st = {}
    _hatls_ask(st, what)
    end = time.time() + wait
    while time.time() < end:
        got = _hatls_answer(st)
        if got is not None:
            if not got.get('ok'):
                raise ValueError(got.get('said') or 'the root helper said no')
            return got
        time.sleep(0.5)
    raise ValueError('the root helper of this node did not answer in 2 minutes - is '
                     'acme-web.path running?  systemctl status acme-web.path')


def _dbtls_server_cert(store, by):
    """This machine's PostgreSQL given a certificate from acme's authority
    (kind local): for localhost, 127.0.0.1 and its names; ssl switched on with
    a reload, no restart."""
    hatls_ca_ensure(store, by)          # one node makes it (1.0.56, 1.0.62)
    names = hatls_names()
    key, crt = hatls_issue(store, names)
    got = _dbtls_helper({'do': 'server', 'cert': crt, 'key': key,
                         'trust': hatls_trust(hatls_ca(store))}, store, by)
    store.set_meta('dbtls:server:' + node_name(), json.dumps(
        {'cert_end': got.get('cert_end') or _cert_end(crt), 'at': time.time(), 'by': by,
         'names': names}))
    return got


def _dbtls_rows(store):
    return {n: _meta_obj(store, 'dbtls:node:' + n) for n in host_nodes(store)}


def _dbtls_ca_for(store, kind, mode, args):
    """The authority file this node checks the server with, for this mode."""
    if not mode or mode == 'require':
        return ''
    if kind in ('replicated', 'local'):
        return str(HA_CA_FILE)
    src = str(args.get('ca_source') or 'given')
    if src == 'system':
        return _dbtls_system_ca() if CONFIG.get('db_engine') == 'postgres' else ''
    if src == 'keep':
        return str(CONFIG.get('db_tls_ca') or '')
    if src == 'acme':
        pem = hatls_trust(hatls_ca(store))
        if not pem:
            raise ValueError('acme has no authority of its own yet - give the server\'s one')
    else:
        pem = str(args.get('ca_pem') or '').strip()
        if '-----BEGIN CERTIFICATE-----' not in pem:
            raise ValueError('the server\'s authority is a PEM certificate (-----BEGIN '
                             'CERTIFICATE-----)')
    tmp = str(DBTLS_CA) + '.new'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as f:
        f.write(pem.strip() + '\n')
    os.chmod(tmp, 0o644)        # read by pg_dump and mariadb-dump too; nothing secret
    if os.path.exists(str(DBTLS_CA)) and str(CONFIG.get('db_tls_ca') or '') == str(DBTLS_CA):
        # The file in use is not written over before the new one is known to go.
        alt = STATE_DIR / 'db-ca.next.pem'
        os.replace(tmp, str(alt))
        return str(alt)
    os.replace(tmp, str(DBTLS_CA))
    return str(DBTLS_CA)


def _dbtls_link_has(store):
    """Whether the link between the databases has this node's PostgreSQL
    certificate in place and renews it (High availability → Repair done)."""
    return CONFIG.get('ha_mode') == 'replicated' and \
        hatls_state(store).get('step') == 'done' and \
        CONFIG.get('ha_tls') == 'verify-full' and HA_CA_FILE.exists()


def _dbtls_has_server(store):
    """This node's PostgreSQL has a certificate from acme's authority."""
    return HA_CA_FILE.exists() and (_dbtls_link_has(store) or bool(
        _meta_json(store, 'dbtls:server:' + node_name())))


def dbtls_apply(daemon, args):
    """What every node does in one phase of the wizard."""
    store = daemon.store
    by = str(args.get('by') or '?')
    phase = str(args.get('phase') or '')
    kind = dbtls_kind()
    base = {'kind': kind, 'phase': phase}
    if phase == 'server':
        if kind == 'replicated' and _dbtls_link_has(store) and not args.get('renew'):
            return dict(base, ok=True, skip=True,
                        said='its PostgreSQL has the certificate of the link between the '
                             'databases, renewed with it')
        if kind not in ('local', 'replicated'):
            return dict(base, ok=True, skip=True, said={
                'remote': 'its database server is elsewhere',
                'sqlite': 'its database is a file on this machine',
                'socket': 'it reaches its database over a Unix socket'}.get(kind, ''))
        srv = _meta_obj(store, 'dbtls:server:' + node_name())
        if srv and not args.get('renew') and \
                float(srv.get('cert_end') or 0) - time.time() > DBTLS_RENEW_DAYS * 86400 and \
                set(srv.get('names') or []) == set(hatls_names()) and HA_CA_FILE.exists():
            p = dbtls_probe('verify-full', str(HA_CA_FILE))
            if p['ok']:
                return dict(base, ok=True, said='its PostgreSQL has its certificate already',
                            cert_end=srv.get('cert_end'))
        got = _dbtls_server_cert(store, by)
        store.add_event('settings', '%s: the PostgreSQL of %s was given a certificate from '
                        'acme\'s authority' % (by, node_name()), 'info', who=by)
        dbtls_publish(daemon, force=True)
        return dict(base, ok=True, said=got.get('said') or 'PostgreSQL answers over TLS',
                    cert_end=got.get('cert_end'))
    if phase == 'connect':
        mode = str(args.get('mode') or '')
        if mode not in DBTLS_MODES:
            raise ValueError('the mode is require, verify-ca or verify-full')
        if kind in ('sqlite', 'socket'):
            return dict(base, ok=True, skip=True, said='nothing of it goes over a network')
        if mode and kind in ('replicated', 'local'):
            if not _dbtls_has_server(store):
                raise ValueError('this node\'s PostgreSQL has no certificate from acme yet')
            mode = 'verify-full'
        ca = _dbtls_ca_for(store, kind, mode, args)
        # The cluster's wish, in its database (1.0.88): a node put back from a backup or joined
        # afresh had its connection without TLS - config.json is the machine's, not the backup's
        if not args.get('only'):
            store.set_meta('dbtls:want', json.dumps({'mode': mode, 'ca_source': str(
                args.get('ca_source') or ''), 'by': by, 'at': time.time()}))
        try:
            got = dbtls_switch(daemon, mode, ca, by)
        except Exception:
            if ca.endswith('db-ca.next.pem'):
                try:
                    os.unlink(ca)
                except OSError:
                    pass
            raise
        if ca.endswith('db-ca.next.pem'):
            # It went: the new authority takes the usual name, and the
            # connection is moved onto it - the same file, nothing to try again.
            os.replace(ca, str(DBTLS_CA))
            with DBTLS_LOCK:
                write_file_settings({'db_tls_ca': str(DBTLS_CA)})
                CONFIG['db_tls_ca'] = str(DBTLS_CA)
                for d in _dbtls_dbs(daemon):
                    d.tls_ca = str(DBTLS_CA)
        return dict(got, **dict(base, ok=True, said='it was so already' if
                                got.get('changed') is False else ''))
    if phase == 'server_off':
        if kind not in ('local', 'replicated') or \
                not (_meta_obj(store, 'dbtls:server:' + node_name())):
            return dict(base, ok=True, skip=True, said='nothing of acme\'s in its PostgreSQL')
        if CONFIG.get('db_tls'):
            raise ValueError('this node\'s connection still uses TLS - it moves back first')
        if kind == 'replicated' and (_dbtls_link_has(store) or
                                     hatls_state(store).get('step') not in (None, 'off_done',
                                                                            'failed')):
            # The link between the databases uses the certificate (1.0.172):
            # it stays, renewed by the link.
            store.db.run('DELETE FROM meta WHERE k = ?', ('dbtls:server:' + node_name(),))
            dbtls_publish(daemon, force=True)
            return dict(base, ok=True, said='the certificate stays: the link between the '
                        'databases uses it and renews it')
        others = [n for n, r in _dbtls_rows(store).items()
                  if n != node_name() and r.get('mode') and r.get('kind') == 'remote']
        if others:
            raise ValueError('%s still reach%s a database with TLS - perhaps this one: switch '
                             'them off first' % (', '.join(others), 'es' if len(others) == 1
                                                 else ''))
        got = _dbtls_helper({'do': 'server_off'}, store, by)
        store.db.run('DELETE FROM meta WHERE k = ?', ('dbtls:server:' + node_name(),))
        store.add_event('settings', '%s: acme\'s certificate left the PostgreSQL of %s'
                        % (by, node_name()), 'warn', who=by)
        dbtls_publish(daemon, force=True)
        return dict(base, ok=True, said=got.get('said') or '')
    raise ValueError('the phase is server, connect or server_off')


def dbtls_publish(daemon, force=False):
    """This node's connection as the server says it is, for the page."""
    now = time.time()
    if not force and now - DBTLS_WORK['at'] < DBTLS_EVERY:
        return
    DBTLS_WORK['at'] = now
    store = daemon.store
    row = {'at': now, 'kind': dbtls_kind(), 'mode': str(CONFIG.get('db_tls') or ''),
           'ca': str(CONFIG.get('db_tls_ca') or ''), 'engine': CONFIG.get('db_engine'),
           'host': str(CONFIG.get('db_host') or '')}
    if row['ca'] == str(HA_CA_FILE):
        row['ca_said'] = 'acme\'s own authority' if row['kind'] == 'local' else \
            'the cluster\'s authority'
    elif row['ca'] == str(DBTLS_CA):
        row['ca_said'] = 'the authority given in the wizard'
    elif row['ca'] and row['ca'] == _dbtls_system_ca():
        row['ca_said'] = 'the system\'s authorities'
    elif row['ca']:
        row['ca_said'] = row['ca']
    elif row['mode'] in ('verify-ca', 'verify-full'):
        row['ca_said'] = 'the system\'s authorities'
    try:
        row['ssl'], row['version'], row['cipher'] = _dbtls_ssl(store.db)
    except Exception as e:                              # noqa: BLE001
        row['said'] = scrub_secret(str(e))[:200]
    srv = _meta_obj(store, 'dbtls:server:' + node_name())
    link = row['kind'] == 'replicated' and _dbtls_link_has(store)
    if link:
        row['cert_end'] = hatls_state(store).get('cert_end')
        row['server_by'] = 'link'
    elif row['kind'] in ('local', 'replicated') and srv:
        row['cert_end'] = srv.get('cert_end')
        row['server'] = True
        row['server_by'] = 'here'
    resc = DBTLS_WORK.get('rescued') or _meta_obj(store, 'dbtls:rescued:' + node_name())
    if resc:
        row['rescued'] = {x: resc.get(x) for x in ('at', 'was', 'why')}   # after a restart too
    try:
        store.set_meta('dbtls:node:' + node_name(), json.dumps(row))
    except Exception:                                   # noqa: BLE001
        DBTLS_WORK['at'] = 0.0          # the database not there just now: again soon


def _dbtls_rescue(daemon):
    """A connection on this machine that stopped because of its TLS: back to
    no TLS (nothing of it leaves the machine), said loudly. Under high
    security it stays and is only said."""
    now = time.time()
    if now - DBTLS_WORK['rescue'] < 10:
        return
    DBTLS_WORK['rescue'] = now
    if dbtls_kind() not in ('local', 'replicated') or not CONFIG.get('db_tls'):
        return
    try:
        daemon.store.db.value('SELECT 1')
        return
    except Exception:                                   # noqa: BLE001
        pass
    mode, ca = str(CONFIG.get('db_tls') or ''), str(CONFIG.get('db_tls_ca') or '')
    p = dbtls_probe(mode, ca)
    if p['ok']:
        return                                          # it is back: a passing failure
    plain = dbtls_probe('', '')
    if not plain['ok']:
        return                                          # the database is down: not TLS's matter
    why = p.get('said') or '?'
    if hisec_enforced('db:tls', daemon.store):
        log_sparing('dbtls-rescue', 'the connection to the database on this machine does not go '
                    'with TLS (%s) and high security keeps it so' % why, 'error', every=600)
        return
    with DBTLS_LOCK:
        write_file_settings({'db_tls': '', 'db_tls_ca': ''})
        CONFIG['db_tls'], CONFIG['db_tls_ca'] = '', ''
        _dbtls_reconnect(daemon, '', '')
    DBTLS_WORK['rescued'] = {'at': now, 'was': mode, 'why': why[:200]}
    try:
        # Kept (1.0.57): what it was moved back from, so that it goes encrypted again by
        # itself once that works - it stayed without TLS for good, the link's certificate
        # renewed or not.
        daemon.store.set_meta('dbtls:rescued:' + node_name(), json.dumps(
            {'at': now, 'was': mode, 'ca': ca, 'why': why[:200]}))
    except Exception:                                   # noqa: BLE001
        pass
    log('the connection to the database on this machine stopped with TLS (%s): it goes without '
        'TLS now - it never leaves the machine. Settings → The database → Encryption to put it '
        'back' % why, 'error')
    try:
        daemon.store.add_event('settings', 'the connection of %s to its database on the same '
                               'machine stopped with TLS (%s) and was moved back to no TLS, so '
                               'acme goes on - encrypt it again in Settings → The database'
                               % (node_name(), why[:200]), 'bad')
    except Exception:                                   # noqa: BLE001
        pass
    dbtls_publish(daemon, force=True)


def dbtls_watch(daemon):
    """Its own thread, from the start: the daemon's loop waits for the
    database, and a connection broken by its TLS is what it would wait for."""
    while True:
        time.sleep(5)
        try:
            _dbtls_rescue(daemon)
        except Exception as e:                          # noqa: BLE001
            log_sparing('dbtls-rescue-x', 'the connection to the database: %s' % e, 'warn',
                        every=600)
        if not DBTLS_WORK['at']:
            try:
                dbtls_publish(daemon)   # one not written while the database was away
            except Exception as e:      # noqa: BLE001
                # The thread kept (1.0.206): the database away at its first look
                # ended it, and the rescue it is for never ran.
                log_sparing('dbtls-publish-x', 'the connection to the database: %s' % e,
                            'warn', every=600)


DBTLS_AGAIN_S = 600


def _dbtls_link_on(store):
    """The link between the databases is set to verify-full and not being switched off: it
    gives this node's PostgreSQL its certificate and renews it."""
    return CONFIG.get('ha_mode') == 'replicated' and CONFIG.get('ha_tls') == 'verify-full' and \
        not (hatls_want(store) or {}).get('off')


def _dbtls_again(daemon):
    """A connection moved back to no TLS by the rescue goes encrypted again by itself (1.0.57)
    once that works - every 10 minutes it is tried apart; the move itself is dbtls_switch's,
    put back as it was if it does not go."""
    store = daemon.store
    k = 'dbtls:rescued:' + node_name()
    r = _meta_obj(store, k)
    if not r:
        return
    if CONFIG.get('db_tls') or not r.get('was') or dbtls_kind() not in ('local', 'replicated'):
        store.db.run('DELETE FROM meta WHERE k = ?', (k,))     # set by hand since: as it is
        return
    now = time.time()
    last = float(r.get('tried') or r.get('at') or 0)
    if 0 <= now - last < DBTLS_AGAIN_S:       # a step of the clock back: tried now (1.0.62)
        return
    r['tried'] = now
    store.set_meta(k, json.dumps(r))
    if not dbtls_probe(r['was'], str(r.get('ca') or ''))['ok']:
        return
    try:
        dbtls_switch(daemon, r['was'], str(r.get('ca') or ''), 'acme (it works with TLS again)')
    except ValueError as e:
        log_sparing('dbtls-again', 'the connection to the database: going back to TLS did not '
                    'go: %s' % e, 'warn', every=3600)


def _dbtls_as_wanted(daemon):
    """This node's connection as the cluster asked (dbtls:want, 1.0.88) when it is not so: a
    node put back from a backup, or a new one joined, came up without TLS - tried every 10
    minutes, the move dbtls_switch's own (put back as it was if it does not go). Not while the
    rescue holds it back (dbtls:rescued:), nor before this node's PostgreSQL has a certificate."""
    store = daemon.store
    want = _meta_obj(store, 'dbtls:want')
    mode = str(want.get('mode') or '')
    if not mode or str(CONFIG.get('db_tls') or '') == mode or \
            _meta_obj(store, 'dbtls:rescued:' + node_name()):
        return
    if dbtls_kind() not in ('local', 'replicated') or not _dbtls_has_server(store):
        return
    now = time.time()
    if 0 <= now - DBTLS_WORK.get('wanted_at', 0) < DBTLS_AGAIN_S:
        return
    DBTLS_WORK['wanted_at'] = now
    try:
        ca = _dbtls_ca_for(store, dbtls_kind(), 'verify-full',
                           {'ca_source': want.get('ca_source') or 'acme'})
        if not dbtls_probe('verify-full', ca)['ok']:
            return
        dbtls_switch(daemon, 'verify-full', ca, 'acme (as the cluster asked: %s)'
                     % (want.get('by') or '?'))
        store.add_event('settings', 'the connection of %s to its database is encrypted again, as '
                        'the cluster asked (verify-full)' % node_name())
    except Exception as e:                              # noqa: BLE001
        log_sparing('dbtls-wanted', 'the connection to the database as the cluster asked: %s'
                    % e, 'warn', every=3600)


def dbtls_tick(daemon):
    """Every few minutes the row for the page; the own certificate
    (kind local) made again 45 days before it ends or when the machine's
    names change - in a thread, the connection keeps going."""
    dbtls_publish(daemon)
    if dbtls_kind() not in ('local', 'replicated'):
        return
    _dbtls_again(daemon)
    _dbtls_as_wanted(daemon)
    srv = _meta_obj(daemon.store, 'dbtls:server:' + node_name())
    if not srv or _dbtls_link_has(daemon.store) or _dbtls_link_on(daemon.store):
        # None of its own, or the link renews it - also while the link's own renewal is
        # under way (1.0.57): a row of its own kept from before the link took it renewed the
        # certificate at the same moment, from another list of names.
        return
    t = DBTLS_WORK.get('renew')
    if t is not None and t.is_alive():
        return
    old = float(srv.get('cert_end') or 0) - time.time() < DBTLS_RENEW_DAYS * 86400
    moved = set(srv.get('names') or []) != set(hatls_names())
    if not (old or moved) or time.time() - float(srv.get('tried') or 0) < 6 * 3600:
        return
    srv['tried'] = time.time()
    daemon.store.set_meta('dbtls:server:' + node_name(), json.dumps(srv))

    def go():
        try:
            _dbtls_server_cert(daemon.store, 'acme (renewed)')
            daemon.store.add_event('settings', 'the certificate of %s\'s PostgreSQL was made '
                                   'again (%s)' % (node_name(), 'it was to end soon' if old else
                                                   'the names of the machine changed'))
            dbtls_publish(daemon, force=True)
        except Exception as e:                          # noqa: BLE001
            daemon.store.add_event('settings', 'the certificate of %s\'s PostgreSQL could not be '
                                   'made again: %s' % (node_name(), e), 'bad')
    DBTLS_WORK['renew'] = threading.Thread(target=go, name='acme-dbtls-renew', daemon=True)
    DBTLS_WORK['renew'].start()


def dbtls_view(store):
    nodes = []
    alive = host_alive(store)
    for n in host_nodes(store):
        row = _meta_obj(store, 'dbtls:node:' + n)
        row.pop('ca', None)
        nodes.append(dict(row, name=n, me=n == node_name(), alive=bool(alive.get(n))))
    link_done = False
    if CONFIG.get('ha_mode') == 'replicated':
        hat = hatls_view(store)
        link_done = len(hat['nodes']) >= 2 and all(x.get('step') == 'done' for x in hat['nodes'])
    own_ca = bool(hatls_trust(hatls_ca(store))) if CONFIG.get('db_engine') == 'postgres' else False
    return {'kind': dbtls_kind(), 'engine': CONFIG.get('db_engine'), 'nodes': nodes,
            'mode': str(CONFIG.get('db_tls') or ''), 'ha_mode': CONFIG.get('ha_mode') or '',
            'host': str(CONFIG.get('db_host') or ''), 'link_done': link_done,
            'own_ca': own_ca, 'servers': [n for n in host_nodes(store)
                                          if _meta_json(store, 'dbtls:server:' + n)],
            'hisec': hisec_enforced('db:tls', store)}


@node_ask_kind('dbtls_probe')
def _ask_dbtls_probe(daemon, args):
    """What a mode would do on this node - nothing changed."""
    mode = str(args.get('mode') or '')
    kind = dbtls_kind()
    if kind in ('sqlite', 'socket'):
        return {'ok': True, 'kind': kind, 'skip': True}
    plain = dbtls_probe('require', '')
    out = {'kind': kind, 'server_tls': bool(plain.get('ok')),
           'server_said': plain.get('said') or ''}
    if kind in ('replicated', 'local') and mode:
        if not _dbtls_has_server(daemon.store):
            return dict(out, ok=True, needs_server=True,
                        said='its PostgreSQL is given a certificate from acme first')
        return dict(out, **{k: v for k, v in dbtls_probe('verify-full', str(HA_CA_FILE)).items()
                            if k != 'ca'})
    if not mode:
        return dict(out, **{k: v for k, v in dbtls_probe('', '').items() if k != 'ca'})
    tmp = None
    try:
        ca = ''
        src = str(args.get('ca_source') or 'given')
        if mode != 'require':
            if src == 'system':
                ca = _dbtls_system_ca() if CONFIG.get('db_engine') == 'postgres' else ''
            elif src == 'keep':
                ca = str(CONFIG.get('db_tls_ca') or '')
            else:
                pem = hatls_trust(hatls_ca(daemon.store)) if src == 'acme' else \
                    str(args.get('ca_pem') or '')
                if '-----BEGIN CERTIFICATE-----' not in pem:
                    raise ValueError('the server\'s authority is a PEM certificate')
                fd, tmp = tempfile.mkstemp(suffix='.pem', dir=str(STATE_DIR))
                with os.fdopen(fd, 'w') as f:
                    f.write(pem.strip() + '\n')
                ca = tmp
        return dict(out, **{k: v for k, v in dbtls_probe(mode, ca).items() if k != 'ca'})
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


@node_ask_kind('dbtls_apply')
def _ask_dbtls_apply(daemon, args):
    return dbtls_apply(daemon, args)


