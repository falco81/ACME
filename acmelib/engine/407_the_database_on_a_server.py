# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the database on a server of its own, looked after by acme-db-agent (1.0.110) ----------
# docs/external-database.md. Until now acme looked after a PostgreSQL (or MariaDB) only on its
# own machine, through the root helper (acme_web.py): the certificate of the database, its
# pg_hba.conf, its settings and restarts, the replication's TLS. With the database on a server
# of its own, a small agent there (deploy/acme_db_agent.py, installed with install.sh
# --db-server / --db-agent) does the same closed set of things for this node, over HTTPS with
# certificates from acme's own authority both ways and every request signed.
#
# Which one does it is this node's own choice, kept in a file of its own (never in config.json
# or the database, so nothing of it moves with a backup or to the other node):
#   /var/lib/acme/db-agent/agent.json   {"db_admin": "agent:HOST:PORT", ...}
# Without that file - every installation until now - db_admin is 'local': nothing here runs,
# nothing is asked, nothing is said; every path is the one it was.
DBAGENT_DIR = STATE_DIR / 'db-agent'
DBAGENT_FILE = DBAGENT_DIR / 'agent.json'
DBAGENT_CACHE = {'key': None, 'conf': None}
DBAGENT_EVERY = float(os.environ.get('ACME_DBAGENT_EVERY') or 30)
DBAGENT_DOWN_S = float(os.environ.get('ACME_DBAGENT_DOWN_S') or 90)
DBAGENT_RENEW_DAYS = 45
DBAGENT_CERT_DAYS = 730
DBAGENT_PROTO = 'acme-db-agent/1'
DBAGENT_LOCK = threading.Lock()
DBAGENT_PGTLS_LOCK = threading.Lock()
DBAGENT_STATE = {'ok': None, 'down_since': 0.0, 'fails': 0, 'facts': {}, 'at': 0.0,
                 'load': None, 'load_at': 0.0}


def db_agent():
    """This node's agent (its agent.json), or None: the database is looked after here."""
    try:
        st = os.stat(str(DBAGENT_FILE))
    except OSError:
        return None
    key = (st.st_mtime_ns, st.st_size)
    if DBAGENT_CACHE['key'] != key:
        try:
            conf = json.loads(DBAGENT_FILE.read_text())
        except (OSError, ValueError):
            conf = None
        if not isinstance(conf, dict) or not str(conf.get('db_admin') or '').startswith('agent:'):
            conf = None
        DBAGENT_CACHE.update(key=key, conf=conf)
    return DBAGENT_CACHE['conf']


def db_agent_on():
    return db_agent() is not None


def db_admin():
    """'local' (the root helper on this machine, as ever) or 'agent:HOST:PORT'."""
    a = db_agent()
    return str(a['db_admin']) if a else 'local'


def db_agent_db_host():
    a = db_agent() or {}
    return str(a.get('db_host') or a.get('host') or '')


def db_agent_put(changes):
    a = dict(db_agent() or {})
    a.update(changes)
    DBAGENT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_replacing(DBAGENT_FILE, json.dumps(a, indent=1, sort_keys=True) + '\n', 0o600)
    _db_agent_own(DBAGENT_FILE)
    DBAGENT_CACHE['key'] = None
    return a


def _db_agent_own(path, mode=0o600):
    try:
        chown_to_service(path, mode)
    except NameError:
        pass


# ---- the join code -------------------------------------------------------------------------
def db_agent_code(code):
    """ADBA1.<base64url JSON {h, p, s, f, e}>: the agent's address and port, the one-time
    secret, the fingerprint of the certificate it answers with, its engine."""
    code = str(code or '').strip()
    if not code.startswith('ADBA1.'):
        raise ValueError('that is not a join code of acme-db-agent (it starts with ADBA1.)')
    raw = code[6:]
    try:
        data = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode())
    except (ValueError, UnicodeDecodeError):
        raise ValueError('the join code is cut short or mistyped')
    if not isinstance(data, dict) or not re.fullmatch(r'[0-9a-f]{64}', str(data.get('f') or '')) \
            or not data.get('s') or not data.get('h'):
        raise ValueError('the join code is cut short or mistyped')
    try:
        data['p'] = int(data.get('p') or 9443)
    except (TypeError, ValueError):
        raise ValueError('the join code is cut short or mistyped')
    return data


# ---- talking to it ----------------------------------------------------------------------
def _db_agent_ctx(with_client=True, verify=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False          # pinned by fingerprint, and checked against acme's authority
    ca = DBAGENT_DIR / 'ca.pem'
    if verify and ca.exists():
        ctx.load_verify_locations(cafile=str(ca))
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE
    if with_client:
        ctx.load_cert_chain(str(DBAGENT_DIR / 'client.crt'), str(DBAGENT_DIR / 'client.key'))
    return ctx


def _db_agent_http(host, port, path, body, ctx, pins, headers=None, timeout=90):
    """One request, the agent's certificate pinned: (status, body bytes, headers)."""
    import http.client
    conn = http.client.HTTPSConnection(host, int(port), context=ctx, timeout=timeout)
    try:
        conn.connect()
        fp = hashlib.sha256(conn.sock.getpeercert(True) or b'').hexdigest()
        if fp not in pins:
            raise ValueError('the agent at %s:%s answers with a certificate acme did not pin (%s…) '
                             '- not the agent that joined, or somebody in between' % (
                                 host, port, fp[:16]))
        conn.request('POST' if body is not None else 'GET', path, body=body,
                     headers=dict(headers or {}, **{'Content-Type': 'application/json'}))
        r = conn.getresponse()
        return r.status, r.read(1 << 22), dict(r.getheaders())
    finally:
        conn.close()


def db_agent_sign_key(conf=None):
    """The key this node signs its requests with: a file of its own beside its client key
    (0600, the daemon's) - not sealed with secrets.key, which a join or a backup put back
    replaces."""
    try:
        key = (DBAGENT_DIR / 'sign.key').read_text().strip()
    except OSError:
        return None
    return key if re.fullmatch(r'[0-9a-f]{64}', key) else None


def db_agent_call(op, args=None, timeout=90, conf=None):
    """One of the agent's operations, signed; its answer (a dict) or ValueError."""
    a = conf or db_agent()
    if not a:
        raise ValueError('this node has no database agent (db_admin is local)')
    key = db_agent_sign_key(a)
    if not key:
        raise ValueError('the signing key of the database agent is not in %s - join the '
                         'agent again (acme --db-agent-join)' % DBAGENT_DIR)
    body = json.dumps({'op': op, 'args': args or {}}).encode()
    ts = '%.3f' % time.time()
    nonce = secrets.token_hex(16)
    node = str(a.get('node') or node_name())
    text = '\n'.join([DBAGENT_PROTO, 'POST', '/v1/op', node, ts, nonce,
                      hashlib.sha256(body).hexdigest()]).encode()
    sig = hmac.new(bytes.fromhex(key), text, 'sha256').hexdigest()
    last = None
    for attempt in (0, 1):
        try:
            st, got, hd = _db_agent_http(a['host'], a['port'], '/v1/op', body, _db_agent_ctx(),
                                         list(a.get('pins') or []),
                                         {'X-Acme-Node': node, 'X-Acme-Time': ts,
                                          'X-Acme-Nonce': nonce, 'X-Acme-Sign': sig}, timeout)
            break
        except Exception as e:                          # noqa: BLE001  (http.client's too)
            last = e
            # the agent starting its listening side again (a new certificate): once more
            if attempt == 0 and op in ('status', 'load') :
                time.sleep(1.5)
                ts = '%.3f' % time.time()
                nonce = secrets.token_hex(16)
                text = '\n'.join([DBAGENT_PROTO, 'POST', '/v1/op', node, ts, nonce,
                                  hashlib.sha256(body).hexdigest()]).encode()
                sig = hmac.new(bytes.fromhex(key), text, 'sha256').hexdigest()
                continue
            raise ValueError('the database agent at %s:%s does not answer: %s'
                             % (a['host'], a['port'], str(e)[:200]))
    else:
        raise ValueError('the database agent at %s:%s does not answer: %s'
                         % (a['host'], a['port'], str(last)[:200]))
    try:
        out = json.loads(got.decode() or '{}')
    except ValueError:
        raise ValueError('the database agent answered what is not JSON (HTTP %d)' % st)
    if st == 200:
        want = hmac.new(bytes.fromhex(key), ('reply\n%s\n' % nonce).encode() +
                        hashlib.sha256(got).digest(), 'sha256').hexdigest()
        if not hmac.compare_digest(want, str(hd.get('X-Acme-Sign') or '')):
            raise ValueError('the database agent\'s answer is not signed with this node\'s key')
    if st != 200 or not out.get('ok'):
        raise ValueError('the database agent said: %s' % (out.get('said') or 'HTTP %d' % st))
    out.pop('ok', None)
    if out.get('restart'):
        # Its listening side starts again with what it was given: waited for.
        time.sleep(0.8)
        end = time.time() + 30
        while True:
            try:
                db_agent_call('status', timeout=10, conf=conf)
                break
            except ValueError:
                if time.time() > end:
                    raise
                time.sleep(0.5)
    return out


# ---- joining an agent ------------------------------------------------------------------
def db_agent_sign(store, csr, names, eku='serverAuth', days=DBAGENT_CERT_DAYS, cn='acme-db-agent'):
    """A certificate for the key of a request (the agent's: its key never leaves its server),
    from the newest of acme's authorities - as hatls_issue does for a key made here."""
    ca = hatls_ca(store)
    if not ca['cas']:
        raise ValueError('acme has no authority yet')
    top = ca['cas'][0]
    ca_key = unseal_secret(top['key'], bind='hatls:ca')
    if not ca_key or not str(ca_key).startswith('-----BEGIN'):
        raise ValueError('the authority\'s key cannot be opened on this node')
    cn = re.sub(r'[^A-Za-z0-9.-]', '', cn)[:64] or 'acme-db-agent'
    ok_names = []
    for n in names:
        try:
            _san_ext([n])
            if n not in ok_names:
                ok_names.append(n)
        except ValueError:
            pass
    with tempfile.TemporaryDirectory(prefix='acme-dba-') as t:
        for n, v in (('csr.pem', csr), ('ca.pem', top['cert']), ('cakey.pem', ca_key)):
            with open(os.path.join(t, n), 'w') as f:
                f.write(v)
            os.chmod(os.path.join(t, n), 0o600)
        with open(os.path.join(t, 'ext.cnf'), 'w') as f:
            f.write('[v3]\nbasicConstraints=critical,CA:FALSE\n'
                    'keyUsage=critical,digitalSignature,keyEncipherment\n'
                    'extendedKeyUsage=%s\n' % eku +
                    ('subjectAltName=%s\n' % hatls_san(ok_names) if ok_names else ''))
        crt = _openssl(['x509', '-req', '-in', os.path.join(t, 'csr.pem'), '-CA',
                        os.path.join(t, 'ca.pem'), '-CAkey', os.path.join(t, 'cakey.pem'),
                        '-set_serial', str(int.from_bytes(secrets.token_bytes(12), 'big')),
                        '-days', str(int(days)), '-sha256', '-subj', '/CN=' + cn, '-extfile',
                        os.path.join(t, 'ext.cnf'), '-extensions', 'v3'],
                       what='the certificate').decode()
    return crt


def _db_agent_fp(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip() + '\n')).hexdigest()


def db_agent_join(store, code, addr='', db_host='', by='command line', say=None):
    """This node joins the agent of a code: the agent's certificate request signed by acme's
    authority, a client certificate of this node's own, a signing key - and from then on the
    database server is looked after through it (db_admin = agent:HOST:PORT)."""
    say = say or (lambda t: None)
    data = db_agent_code(code)
    host, port = data['h'], data['p']
    if addr:
        m = re.fullmatch(r'\[?([^\]]+?)\]?(?::(\d{1,5}))?', str(addr).strip())
        if not m:
            raise ValueError('the agent\'s address is HOST or HOST:PORT')
        host, port = m.group(1), int(m.group(2) or port)
    node = node_name()
    boot = [data['f']]

    def enroll(path, body):
        st, got, _ = _db_agent_http(host, port, path, json.dumps(body).encode(),
                                    _db_agent_ctx(with_client=False, verify=False), boot,
                                    timeout=60)
        try:
            out = json.loads(got.decode() or '{}')
        except ValueError:
            out = {}
        if st != 200 or not out.get('ok'):
            raise ValueError('the database agent said: %s' % (out.get('said') or 'HTTP %d' % st))
        return out
    try:
        began = enroll('/v1/enroll/begin', {'secret': data['s'], 'node': node})
    except (OSError, ssl.SSLError) as e:
        raise ValueError('the database agent at %s:%s cannot be reached: %s' % (host, port, e))
    say('the agent at %s:%s answers (acme-db-agent %s, %s) and is the one of the code'
        % (host, port, began.get('version'), began.get('engine')))
    hatls_ca_ensure(store, by)
    names = [host] + [str(x) for x in began.get('names') or []]
    if db_host and db_host not in names:
        names.insert(1, db_host)
    cert = db_agent_sign(store, began['csr'], names, 'serverAuth')
    ckey, ccrt = hatls_issue(store, [], eku='clientAuth', days=DBAGENT_CERT_DAYS,
                             cn='acme-' + node)
    trust = hatls_trust(hatls_ca(store))
    sign_key = secrets.token_hex(32)
    enroll('/v1/enroll/finish', {'secret': data['s'], 'node': node, 'cert': cert, 'ca': trust,
                                 'client_cert': ccrt, 'sign_key': sign_key})
    say('the agent has its certificate from acme\'s authority; this node its client certificate')
    DBAGENT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, text, mode in (('client.key', ckey, 0o600), ('client.crt', ccrt, 0o644),
                             ('ca.pem', trust, 0o644), ('sign.key', sign_key + '\n', 0o600)):
        write_replacing(DBAGENT_DIR / name, text, mode)
        _db_agent_own(DBAGENT_DIR / name, mode)
    _db_agent_own(DBAGENT_DIR, None)
    engine = 'mariadb' if began.get('engine') == 'mariadb' else 'postgres'
    a = db_agent_put({'db_admin': 'agent:%s:%d' % (host, port), 'host': host, 'port': port,
                      'node': node, 'pins': [_db_agent_fp(cert)],
                      'engine': engine, 'pg_port': int(began.get('pg_port') or 5432),
                      'my_port': int(began.get('my_port') or 3306),
                      'db_host': db_host or host, 'at': time.time(), 'by': by,
                      'agent_cert_end': _cert_end(cert), 'client_cert_end': _cert_end(ccrt)})
    # The agent starts its listening side again with the new certificate: waited for.
    end = time.time() + 20
    while True:
        try:
            got = db_agent_call('status', conf=a)
            break
        except ValueError:
            if time.time() > end:
                raise
            time.sleep(0.5)
    db_agent_ha_ca_local(trust)
    store.add_event('settings', '%s: %s looks after its database server %s through acme-db-agent '
                    '(%s:%d) from now on' % (by, node, db_host or host, host, port), 'warn', who=by)
    return {'host': host, 'port': port, 'facts': got.get('facts') or {},
            'agent': got.get('agent') or {}}


def db_agent_ha_ca_local(trust):
    """acme's authorities on this node too, at the path the database servers have them
    (/etc/pki/acme/ha-ca.pem): the daemon checks its database with it (verify-full), as
    the replication's workers check the other server with the agent's copy."""
    if not trust:
        return
    try:
        if os.geteuid() == 0:
            made = not HA_CA_FILE.parent.exists()
            HA_CA_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            ids = service_ids()
            if made and ids:
                # a folder made for it here: the daemon's own, so it can renew the file
                os.chown(str(HA_CA_FILE.parent), ids[0], ids[1])
            write_replacing(HA_CA_FILE, trust, 0o644)
            _db_agent_own(HA_CA_FILE, 0o644)
            return
        try:
            write_replacing(HA_CA_FILE, trust, 0o644)
        except PermissionError:
            # root's folder, the file the daemon's own (--db-agent-join): written in place
            fd = os.open(str(HA_CA_FILE), os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(fd, 'w') as f:
                f.write(trust)
    except OSError as e:
        log_sparing('dbagent-ca', 'acme\'s authorities could not be written to %s here: %s'
                    % (HA_CA_FILE, e), 'warn', every=3600)


def db_agent_forget(store=None, by='command line'):
    """Back to looking after a database on this machine (db_admin local). The agent keeps
    this node's certificate until it is told otherwise (acme_db_agent.py --forget NODE)."""
    a = db_agent()
    if not a:
        return False
    try:
        os.replace(str(DBAGENT_FILE), str(DBAGENT_FILE) + '.forgotten')
    except OSError:
        DBAGENT_FILE.unlink()
    DBAGENT_CACHE['key'] = None
    if store is not None:
        store.add_event('settings', '%s: %s no longer looks after its database server through '
                        'acme-db-agent (%s)' % (by, node_name(), a.get('db_admin')), 'warn', who=by)
    return True


# ---- what the root helper did, done by the agent ------------------------------------------
def db_agent_link_peers():
    """Who the link's pg_hba lines are for, on a database server of its own: the other
    database server (it subscribes from here) and the other acme node (it asks here)."""
    out = []
    a = db_agent() or {}
    for x in (CONFIG.get('ha_peer'), a.get('peer_node')):
        x = str(x or '').strip()
        try:
            x = str(plain_ip(x, 'address')) if x else ''
        except ValueError:
            x = ''
        if x and x not in out:
            out.append(x)
    return out


def db_agent_pgtls_send(data):
    """pgtls_send for a database on a server of its own: the same request, done by the agent
    in a thread, its answer written where the root helper's goes (pgtls.json) - every reader
    of it (the link's steps, Database -> TLS, a new address) as it was."""
    data = dict(data)

    def work():
        with DBAGENT_PGTLS_LOCK:
            out = {'at': time.time(), 'ok': False, 'id': str(data.get('id') or '')[:40]}
            try:
                req = dict(data)
                req.pop('port', None)
                if req.get('do') in ('hba', 'hba_off'):
                    req['peers'] = db_agent_link_peers() or ([req['peer']] if req.get('peer') else [])
                got = db_agent_call('pgtls', req, timeout=240)
                if req.get('do') == 'server' and req.get('trust'):
                    db_agent_ha_ca_local(req['trust'])
                out.update(got)
                out['ok'] = True
            except Exception as e:                      # noqa: BLE001
                out['said'] = str(e)[:400]
            try:
                WEB_DIR.mkdir(parents=True, exist_ok=True)
                write_replacing(WEB_DIR / PGTLS_FILE, json.dumps(out), 0o640)
            except OSError as e:
                log('the database agent\'s answer could not be written: %s' % e, 'error')
    threading.Thread(target=work, name='dbagent-pgtls', daemon=True).start()


def db_agent_pglog():
    try:
        got = db_agent_call('pglog', {}, timeout=30)
    except ValueError as e:
        return {'at': time.time(), 'entries': [], 'said': str(e)[:300]}
    got.setdefault('at', time.time())
    return got


def db_agent_prepare(peer, name, user, password, say, extra=()):
    """pg_prepare_local on the agent's server: the peers are the other database server, the
    other acme node, and this node (it opens its database from its own address)."""
    a = db_agent() or {}
    peers = []
    for x in [peer, a.get('peer_node'), node_address(), '127.0.0.1'] + list(extra):
        x = str(x or '').strip()
        try:
            x = str(plain_ip(x, 'address')) if x else ''
        except ValueError:
            x = ''
        if x and x not in peers:
            peers.append(x)
    got = db_agent_call('pg_prepare', {'db': name, 'user': user, 'password': password,
                                       'peers': peers}, timeout=120)
    for line in got.get('said') or []:
        say(line)
    return bool(got.get('restart')), int(got.get('major') or 16)


def db_agent_restart(say=None):
    got = db_agent_call('pg_restart' if (db_agent() or {}).get('engine') != 'mariadb'
                        else 'my_restart', {}, timeout=240)
    if say:
        say(got.get('said') or 'the database server started again')
    return got


def db_agent_publication(name):
    return db_agent_call('pg_publication', {'db': name})


def db_agent_fw(peers):
    return db_agent_call('fw_allow', {'peers': [p for p in peers if p]})


def db_agent_running():
    try:
        return bool((db_agent_call('status', timeout=20).get('facts') or {}).get('running'))
    except ValueError:
        return False


def db_agent_dbmake(c):
    """The database and its account made on the agent's server, let in from this node."""
    peers = [x for x in (node_address(), '127.0.0.1') if x]
    got = db_agent_call('dbmake', {'name': c['db_name'], 'user': c['db_user'],
                                   'password': c['db_password'], 'peers': peers}, timeout=120)
    return list(got.get('said') or [])


def db_agent_is_target(c):
    a = db_agent()
    if not a:
        return False
    host = str(c.get('db_host') or '').strip('[]').lower()
    return host in (str(a.get('db_host') or '').lower(), str(a.get('host') or '').lower())


# ---- MariaDB on a server of its own: its TLS (layout A) --------------------------------------
def db_agent_mariadb_tls(store, by):
    """MariaDB given a certificate from acme's authority through the agent (and renewed the
    same way); this node then reaches it with verify-full through Database -> TLS ('acme')."""
    a = db_agent()
    if not a or a.get('engine') != 'mariadb':
        raise ValueError('this node\'s database agent does not look after a MariaDB')
    hatls_ca_ensure(store, by)
    names = [x for x in (db_agent_db_host(), a.get('host')) if x]
    key, crt = hatls_issue(store, names, days=HATLS_CERT_DAYS, cn='mariadb')
    got = db_agent_call('my_tls', {'cert': crt, 'key': key,
                                   'trust': hatls_trust(hatls_ca(store))}, timeout=240)
    store.set_meta('dbtls:server:' + node_name(), json.dumps(
        {'cert_end': got.get('cert_end') or _cert_end(crt), 'at': time.time(), 'by': by,
         'names': names, 'engine': 'mariadb'}))
    store.add_event('settings', '%s: the MariaDB of %s was given a certificate from acme\'s '
                    'authority (acme-db-agent)' % (by, node_name()), 'info', who=by)
    return got


# ---- renewing the agent's certificate and this node's ---------------------------------------
def db_agent_renew(store, by='acme (renewed)', force=False):
    a = db_agent()
    if not a:
        return []
    now = time.time()
    done = []
    if force or float(a.get('agent_cert_end') or 0) - now < DBAGENT_RENEW_DAYS * 86400:
        got = db_agent_call('agent_csr', {})
        names = [a['host']] + [str(x) for x in got.get('names') or []]
        if a.get('db_host') and a['db_host'] not in names:
            names.insert(1, a['db_host'])
        cert = db_agent_sign(store, got['csr'], names)
        trust = hatls_trust(hatls_ca(store))
        fp = _db_agent_fp(cert)
        # The new one pinned beside the old before the agent takes it: never locked out.
        a = db_agent_put({'pins': [fp] + [x for x in a.get('pins') or [] if x != fp][:1]})
        have = (DBAGENT_DIR / 'ca.pem').read_text() if (DBAGENT_DIR / 'ca.pem').exists() else ''
        if trust.strip() not in have:
            write_replacing(DBAGENT_DIR / 'ca.pem', trust + have, 0o644)
        db_agent_call('agent_cert', {'cert': cert, 'ca': trust}, conf=a)
        a = db_agent_put({'pins': [fp], 'agent_cert_end': _cert_end(cert)})
        done.append('the agent\'s certificate (ends %s)'
                    % datetime.fromtimestamp(_cert_end(cert)).strftime('%Y-%m-%d'))
    if force or float(a.get('client_cert_end') or 0) - now < DBAGENT_RENEW_DAYS * 86400:
        ckey, ccrt = hatls_issue(store, [], eku='clientAuth', days=DBAGENT_CERT_DAYS,
                                 cn='acme-' + str(a.get('node') or node_name()))
        trust = hatls_trust(hatls_ca(store))
        old = (DBAGENT_DIR / 'ca.pem').read_text() if (DBAGENT_DIR / 'ca.pem').exists() else ''
        both = trust + ''.join(c for c in re.findall(
            r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----\s*', old)
            if c.strip() not in trust)
        db_agent_call('trust', {'ca': both, 'client_cert_new': ccrt})
        for name, text, mode in (('client.key', ckey, 0o600), ('client.crt', ccrt, 0o644)):
            write_replacing(DBAGENT_DIR / name, text, mode)
            _db_agent_own(DBAGENT_DIR / name, mode)
        db_agent_call('status')         # the new one used once: the agent forgets the old
        db_agent_put({'client_cert_end': _cert_end(ccrt)})
        done.append('this node\'s client certificate')
    if done:
        store.add_event('settings', '%s: renewed for acme-db-agent: %s' % (by, ', '.join(done)),
                        who=by)
    return done


# ---- watching it (only on a node that has an agent) ----------------------------------------
def db_agent_look(store):
    """One look: is the agent there, what is its server - written into this node's row
    ('dbagent:node:NODE') for every node's pages and alerts."""
    a = db_agent()
    if not a:
        return None
    now = time.time()
    row = {'at': now, 'node': node_name(), 'db_admin': a['db_admin'], 'host': a.get('host'),
           'port': a.get('port'), 'db_host': a.get('db_host'), 'engine': a.get('engine'),
           'agent_cert_end': a.get('agent_cert_end'), 'client_cert_end': a.get('client_cert_end')}
    try:
        got = db_agent_call('status', timeout=20)
        was_down = DBAGENT_STATE['ok'] is False
        DBAGENT_STATE.update(ok=True, fails=0, down_since=0.0, facts=got.get('facts') or {},
                             at=now)
        row.update(ok=True, facts=got.get('facts') or {}, agent=got.get('agent') or {})
        if was_down:
            store.add_event('ha', 'the database agent of %s (%s:%s) answers again'
                            % (node_name(), a.get('host'), a.get('port')))
    except ValueError as e:
        DBAGENT_STATE['fails'] += 1
        if not DBAGENT_STATE['down_since']:
            DBAGENT_STATE['down_since'] = now
        row.update(ok=False, said=str(e)[:300], down_since=DBAGENT_STATE['down_since'],
                   fails=DBAGENT_STATE['fails'])
        if DBAGENT_STATE['ok'] is not False and DBAGENT_STATE['fails'] >= 2:
            DBAGENT_STATE['ok'] = False
            store.add_event('ha', 'the database agent of %s (%s:%s) does not answer: %s'
                            % (node_name(), a.get('host'), a.get('port'), str(e)[:200]), 'warn')
        prev = _meta_obj(store, 'dbagent:node:' + node_name())
        if prev.get('facts'):
            row['facts'] = prev['facts']            # the last known, said as old
    store.set_meta('dbagent:node:' + node_name(), json.dumps(row, default=str))
    return row


def db_agent_watch(daemon):
    """The thread of a node with an agent: a look every 30 s, the certificates renewed 45 days
    before they end, the meter's reading of the database server while a page watches."""
    last_look = last_renew = 0.0
    while True:
        try:
            if not db_agent_on():
                time.sleep(10)
                continue
            now = time.time()
            if now - last_look >= DBAGENT_EVERY:
                last_look = now
                db_agent_look(daemon.store)
            if now - last_renew >= 3600:
                last_renew = now
                try:
                    db_agent_renew(daemon.store)
                except Exception as e:                  # noqa: BLE001
                    log_sparing('dbagent-renew', 'renewing the database agent\'s certificates: '
                                '%s' % e, 'warn', every=3600)
            if CONFIG.get('perf_meter') and CONFIG.get('ha_mode') and any(
                    float(v.get('until') or 0) > now for v in LOAD_WATCH['rows'].values()):
                db_agent_load_put(daemon.store)
        except Exception as e:                          # noqa: BLE001
            log_sparing('dbagent-watch', 'watching the database agent: %s' % e, 'warn', every=600)
        time.sleep(2)


@hook('daemon_start')
def _db_agent_start(daemon):
    if not db_agent_on():
        return                          # db_admin local: nothing of it runs
    log('the database server is looked after through acme-db-agent (%s)' % db_admin())
    threading.Thread(target=db_agent_watch, args=(daemon,), name='dbagent', daemon=True).start()


# ---- the meter in the header: the database servers beside the nodes ---------------------------
def db_agent_load(fresh=False):
    """This node's database server, in the shape of server_load() (and its database's own)."""
    now = time.time()
    if not fresh and DBAGENT_STATE['load'] and now - DBAGENT_STATE['load_at'] < 2.5:
        return DBAGENT_STATE['load']
    got = db_agent_call('load', {'db': CONFIG.get('db_name') or 'acme'}, timeout=10)
    got.pop('said', None)
    DBAGENT_STATE.update(load=got, load_at=now)
    return got


def db_agent_load_put(store):
    if time.time() - float(DBAGENT_STATE.get('put_at') or 0) < 4:
        return
    DBAGENT_STATE['put_at'] = time.time()
    try:
        v = dict(db_agent_load())
    except ValueError as e:
        v = {'at': time.time(), 'down': True, 'said': str(e)[:200]}
    v.update(kind='db', node=node_name(), host=db_agent_db_host())
    store.set_meta('load:db:' + node_name(), json.dumps(v, default=str))


def db_agent_load_rows(store):
    """The database servers for /api/load: this node's read now, the others' from their rows -
    each {kind: 'db', name: 'db of NODE', node, host, cpu, mem_used, ... , db: {...}}."""
    out = []
    me = node_name()
    if db_agent_on():
        try:
            v = dict(db_agent_load())
        except ValueError as e:
            v = {'at': time.time(), 'down': True, 'said': str(e)[:200]}
        v.update(kind='db', node=me, host=db_agent_db_host(), age=0.0)
        out.append(v)
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'load:db:%'"):
        n = str(r['k'])[len('load:db:'):]
        if n == me:
            continue
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        age = time.time() - float(v.get('at') or 0)
        if not isinstance(v, dict) or age > 3600:
            continue
        v.update(kind='db', node=n, age=round(age, 1))
        out.append(v)
    for v in out:
        v['name'] = 'db:%s' % v['node']
    out.sort(key=lambda x: x['node'])
    return out


# ---- what the pages and the cards are given ---------------------------------------------------
def db_agent_servers(store):
    """Every database server looked after by an agent, in the shape of a node of the cards'
    dots (name, me, alive) with kind 'db': [{kind, name, node, me, alive, host, db_host, port,
    engine, ok, said, down_since, at, facts{version, running, ssl, wal_level, connections,
    disk{total, free}, ram, cpus, load, uptime}, agent{version, cert_end, clients}, ...}]."""
    out = []
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'dbagent:node:%'")
    except Exception:                                   # noqa: BLE001
        rows = []
    now = time.time()
    for r in rows:
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if not isinstance(v, dict):
            continue
        n = str(r['k'])[len('dbagent:node:'):]
        fresh = now - float(v.get('at') or 0) < max(3 * DBAGENT_EVERY, 120)
        v.update(kind='db', name='db:%s' % n, node=n, me=n == node_name(),
                 alive=bool(v.get('ok')) and fresh, stale=not fresh)
        out.append(v)
    out.sort(key=lambda x: x['node'])
    return out


def db_agent_view(store):
    a = db_agent()
    view = {'db_admin': db_admin(), 'node': node_name(), 'servers': db_agent_servers(store)}
    if a:
        view.update(host=a.get('host'), port=a.get('port'), db_host=a.get('db_host'),
                    engine=a.get('engine'), joined_at=a.get('at'), joined_by=a.get('by'),
                    peer_node=a.get('peer_node') or '',
                    agent_cert_end=a.get('agent_cert_end'),
                    client_cert_end=a.get('client_cert_end'),
                    state={'ok': DBAGENT_STATE['ok'], 'down_since': DBAGENT_STATE['down_since'],
                           'fails': DBAGENT_STATE['fails'], 'at': DBAGENT_STATE['at']})
    # Which settings reach a database server too (their cards draw it beside the nodes).
    view['applies'] = DBAGENT_APPLIES
    return view


# The cards whose dots show the database servers too (docs/external-database.md, "The pages").
DBAGENT_APPLIES = {
    'dbtls': 'the database\'s certificate from acme\'s authority, ssl on, its renewal',
    'ha_link': 'the link between the databases: certificate, verify-full, pg_hba hostssl',
    'ha_replication': 'wal_level, listen_addresses, the account, the publication',
    'db_firewall': 'the database\'s port opened to the acme nodes and the other server',
    'db_tune': 'the database server\'s own settings and their restart',
    'db_errors': 'PostgreSQL\'s log of the replication',
    'perf_meter': 'how busy the database server is',
}


@route('GET', '/api/db-agent')
def _db_agent_get(h):
    h.me('readonly')
    return db_agent_view(h.store)


@route('POST', '/api/db-agent')
def _db_agent_post(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    by = s['name']
    try:
        if act == 'join':
            got = db_agent_join(h.store, str(b.get('code') or ''), str(b.get('address') or ''),
                                str(b.get('db_host') or ''), by=by)
            threading.Thread(target=db_agent_watch, args=(h.d,), name='dbagent',
                             daemon=True).start()
            return dict(got, view=db_agent_view(h.store))
        if act == 'look':
            return {'row': db_agent_look(h.store), 'view': db_agent_view(h.store)}
        if act == 'renew':
            return {'done': db_agent_renew(h.store, by, force=True), 'view': db_agent_view(h.store)}
        if act == 'restart':
            got = db_agent_restart()
            h.store.add_event('settings', '%s restarted the database server through its agent'
                              % by, 'warn', who=by)
            return {'message': got.get('said') or '', 'view': db_agent_view(h.store)}
        if act == 'mariadb_tls':
            return {'message': db_agent_mariadb_tls(h.store, by).get('said') or '',
                    'view': db_agent_view(h.store)}
        if act == 'forget':
            db_agent_forget(h.store, by)
            return {'view': db_agent_view(h.store)}
    except ValueError as e:
        raise ApiError(400, str(e))
    raise ApiError(400, 'the action is join, look, renew, restart, mariadb_tls or forget')


# ---- alerts, metrics, status (only with an agent) ---------------------------------------------
@hook('alerts')
def _db_agent_alerts(store):
    out = []
    if not db_agent_on() and not CONFIG.get('ha_mode'):
        return out
    now = time.time()
    for v in db_agent_servers(store) if db_agent_on() else []:
        if v.get('ok') is False and now - float(v.get('down_since') or now) >= DBAGENT_DOWN_S:
            out.append({'key': 'dbagent:' + v['node'], 'level': 'bad', 'node': v['node'],
                        'pane': 'db', 'title': 'The database agent of %s does not answer'
                        % v['node'],
                        'words': 'acme-db-agent at %s:%s has not answered since %s: %s - its '
                                 'database server can be neither renewed nor changed from acme' % (
                                     v.get('host'), v.get('port'),
                                     datetime.fromtimestamp(float(v['down_since'])).strftime(
                                         '%Y-%m-%d %H:%M'), v.get('said') or '?')})
        elif v.get('ok') and (v.get('facts') or {}).get('running') is False:
            out.append({'key': 'dbserver:' + v['node'], 'level': 'bad', 'node': v['node'],
                        'pane': 'db', 'title': 'The database server of %s is down' % v['node'],
                        'words': 'its agent answers, the database does not: %s'
                                 % ((v.get('facts') or {}).get('said') or '?')})
        elif v.get('ok') and float(v.get('agent_cert_end') or now + 1e9) - now < 14 * 86400:
            out.append({'key': 'dbagent:cert:' + v['node'], 'level': 'warn', 'node': v['node'],
                        'pane': 'db', 'title': 'The certificate of the database agent of %s '
                        'ends soon' % v['node'], 'words': 'it is renewed by itself 45 days '
                        'before - look at the agent (Settings -> The database)'})
    return out


@hook('metrics')
def _db_agent_metrics(store):
    if not db_agent_on():
        return []
    rows = db_agent_servers(store)
    return [('acme_db_agent_up', 'Whether the database agent of a node answers (1) or not (0)',
             'gauge', [({'node': v['node'], 'host': str(v.get('host') or '')},
                        1 if v.get('alive') else 0) for v in rows]),
            ('acme_db_server_up', 'Whether the database server behind the agent runs',
             'gauge', [({'node': v['node']}, 1 if (v.get('facts') or {}).get('running') else 0)
                       for v in rows])]


@hook('status')
def _db_agent_status_lines(store, pal):
    a = db_agent()
    if not a:
        return []
    row = _meta_obj(store, 'dbagent:node:' + node_name())
    f = row.get('facts') or {}
    ok = row.get('ok')
    words = '  database server: %s through acme-db-agent %s:%s - %s' % (
        a.get('db_host'), a.get('host'), a.get('port'),
        ('answers; %s %s' % (f.get('engine'), f.get('version') or '')) if ok else
        ('does NOT answer: %s' % (row.get('said') or '?')) if ok is False else 'not looked at yet')
    return [words]


# ---- the command line -------------------------------------------------------------------------
@hook('cli_args')
def _db_agent_cli_args(p):
    g = p.add_argument_group('THE DATABASE ON A SERVER OF ITS OWN (acme-db-agent)')
    g.add_argument('--db-agent-join', metavar='CODE', help='this node joins the database agent '
                   'of a code (acme_db_agent.py --new-code on the database server prints it); its '
                   'database server is looked after through it from then on (as root)')
    g.add_argument('--db-agent', metavar='HOST[:PORT]', help='--db-agent-join: the agent\'s '
                   'address as this node reaches it, when not the one in the code')
    g.add_argument('--db-agent-db-host', metavar='HOST', help='--db-agent-join: the database '
                   'server\'s address as this node reaches it (the agent\'s by default)')
    g.add_argument('--db-agent-status', action='store_true', help='this node\'s database agent '
                   'and its server: answering, versions, certificates (--json)')
    g.add_argument('--db-agent-renew', action='store_true', help='the agent\'s certificate and '
                   'this node\'s client certificate renewed now')
    g.add_argument('--db-agent-restart', action='store_true', help='the database server '
                   'started again through its agent')
    g.add_argument('--db-agent-mariadb-tls', action='store_true', help='MariaDB on the agent\'s '
                   'server given a certificate from acme\'s authority')
    g.add_argument('--db-agent-forget', action='store_true', help='back to looking after a '
                   'database on this machine (db_admin local) - with --yes')
    g.add_argument('--ha-peer-node', metavar='ADDRESS', help='--ha-setup with the databases on '
                   'servers of their own: the other acme node\'s address (its database server '
                   'is --ha-peer)')


@hook('cli_run')
def _db_agent_cli(args):
    if not any(getattr(args, k, None) for k in (
            'db_agent_join', 'db_agent_status', 'db_agent_renew', 'db_agent_restart',
            'db_agent_mariadb_tls', 'db_agent_forget')):
        return None
    ok_line = (lambda t: print('  ok   ' + t))
    os.environ['ACME_STAY_ROOT'] = '1'
    try:
        store = Storage(open_db())
    except DbError as e:
        raise SystemExit('acme: %s' % e)
    load_config(saved=store.settings_saved())
    HA_STORE['store'] = store
    if args.db_agent_join:
        if os.geteuid() != 0 and not os.environ.get('ACME_DBAGENT_ANY_USER'):
            raise SystemExit('acme: run this as root - it writes this node\'s keys')
        try:
            got = db_agent_join(store, args.db_agent_join, args.db_agent or '',
                                args.db_agent_db_host or '', say=ok_line)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        f = got.get('facts') or {}
        ok_line('the database server: %s %s, %s' % (f.get('engine'), f.get('version') or '',
                                                     'running' if f.get('running') else 'NOT running'))
        ok_line('db_admin = agent:%s:%s (%s)' % (got['host'], got['port'], DBAGENT_FILE))
        if not os.environ.get('ACME_HA_NO_RESTART') and os.geteuid() == 0:
            subprocess.run(['systemctl', 'restart', 'acme'], capture_output=True)
        return 0
    if args.db_agent_forget:
        if not args.yes:
            raise SystemExit('acme: the database server is then looked after as one on this '
                             'machine (the root helper) - again with --yes')
        print('acme: %s' % ('db_admin is local again' if db_agent_forget(store) else
                            'db_admin was local already'))
        return 0
    if not db_agent_on():
        raise SystemExit('acme: this node has no database agent (db_admin is local)')
    try:
        if args.db_agent_renew:
            for x in db_agent_renew(store, 'command line', force=True):
                ok_line('renewed: %s' % x)
            return 0
        if args.db_agent_restart:
            ok_line(db_agent_restart().get('said') or 'started again')
            return 0
        if args.db_agent_mariadb_tls:
            ok_line(db_agent_mariadb_tls(store, 'command line').get('said') or 'done')
            return 0
        row = db_agent_look(store)
    except ValueError as e:
        raise SystemExit('acme: %s' % e)
    if args.json:
        print(json.dumps(db_agent_view(store), indent=1, default=str))
        return 0 if row.get('ok') else 1
    f = row.get('facts') or {}
    ag = row.get('agent') or {}
    print('db_admin: %s' % db_admin())
    print('  agent:    %s' % ('answers, acme-db-agent %s, its certificate ends %s' % (
        ag.get('version'), datetime.fromtimestamp(float(ag['cert_end'])).strftime('%Y-%m-%d')
        if ag.get('cert_end') else '?') if row.get('ok') else 'does NOT answer: %s'
        % row.get('said')))
    if f:
        print('  server:   %s %s on %s - %s, TLS %s' % (
            f.get('engine'), f.get('version') or '', f.get('host'),
            'running' if f.get('running') else 'NOT running', 'on' if f.get('ssl') else 'off'))
        if f.get('disk'):
            print('  disk:     %s free of %s' % (bytes_words(f['disk'].get('free')),
                                                bytes_words(f['disk'].get('total'))))
    return 0 if row.get('ok') else 1
