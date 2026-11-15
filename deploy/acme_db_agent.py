#!/usr/bin/python3 -I
"""acme_db_agent.py - acme-db-agent: a database server of its own, looked after by acme (1.0.110).

acme looks after the database on its own machine through its root helper
(acme_web.py): a certificate for PostgreSQL, pg_hba.conf, a restart, the
replication's settings. When the database is on a server of its own, this
agent does the same there - and nothing else:

  * it answers HTTPS on a port of its own (9443), only to acme nodes that
    joined it: each shows a client certificate from acme's own authority
    (mutual TLS), its fingerprint one of those enrolled, and signs every
    request (HMAC-SHA256 with a key of its own, given at enrollment) with the
    time and a nonce - a request seen before, or older than two minutes, is
    refused;
  * it does a closed set of operations (acme_pg_ops.OPS: status, pgtls,
    pg_prepare, pg_allow, pg_publication, pg_restart, pg_reload, pglog,
    dbmake, my_tls, my_restart, fw_allow; agent_csr, agent_cert, trust,
    clients). Every value is checked against the one shape it may have; no
    shell, no file named by the request, SQL only as the postgres account;
  * the side that faces the network runs as an account of its own
    (acme-db-agent, or nobody): it terminates TLS, checks the certificate,
    the signature and the rate, and hands the request to the root side over a
    socket pair. The root side checks it all again (the signature, the
    nonce) before it does anything, and writes the audit log;
  * joining: `acme_db_agent.py --new-code` prints a one-time code (an hour)
    holding this server's address, a secret and the fingerprint of the
    certificate it answers with - acme pins it, so nobody in between can
    pose as the agent. `acme --db-agent-join CODE` on the acme node gets a
    certificate request from here, issues this server's certificate and its
    own client certificate from acme's authority, and sends them back with
    its signing key. The code is then used up.

  acme_db_agent.py [--config FILE]          serve (systemd: acme-db-agent.service)
  acme_db_agent.py --new-code [--minutes N] a one-time join code for an acme node
  acme_db_agent.py --status                 what is here (JSON)
  acme_db_agent.py --forget NODE            an acme node no longer let in

Its configuration: /etc/acme-db-agent/agent.json (root's, 0600) - see
docs/external-database.md. Standard library only; openssl for the keys.
"""
import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

VERSION = '1.0.110'
CONF_FILE = os.environ.get('ACME_DB_AGENT_CONFIG', '/etc/acme-db-agent/agent.json')
PROTO = 'acme-db-agent/1'
SKEW = 120                      # a request's time this far from ours at most (s)
CODE_MINUTES = 60
CODE_TRIES = 5
BODY_MOST = 262144
AGENT_OPS = ('agent_csr', 'agent_cert', 'trust', 'clients')
DEFAULTS = {'listen': '0.0.0.0', 'port': 9443, 'engine': 'postgres', 'pg_port': 5432,
            'my_port': 3306, 'user': 'acme-db-agent', 'state': '/var/lib/acme-db-agent',
            'log': '/var/log/acme-db-agent/audit.log', 'ha_ca': '/etc/pki/acme/ha-ca.pem',
            'advertise': '', 'names': [], 'rate': 20, 'burst': 60}


def conf_read(path=None):
    path = path or CONF_FILE
    c = dict(DEFAULTS)
    try:
        with open(path) as f:
            got = json.load(f)
        if isinstance(got, dict):
            c.update(got)
    except FileNotFoundError:
        pass
    c['dir'] = os.path.dirname(os.path.abspath(path))
    return c


def _p(c, name):
    return os.path.join(c['dir'], name)


def _write(path, text, mode=0o600):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.acme-', dir=d)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


def _json(path, default):
    try:
        got = json.loads(_read(path, '') or 'null')
    except ValueError:
        got = None
    return got if got is not None else default


def _openssl(args, data=None):
    got = subprocess.run(['openssl'] + args, input=data, capture_output=True, text=True)
    if got.returncode != 0:
        raise ValueError('openssl: %s' % (got.stderr or got.stdout).strip()[-200:])
    return got.stdout


def fp_of_pem(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip() + '\n')).hexdigest()


def cert_end(pem):
    out = _openssl(['x509', '-noout', '-enddate'], pem)
    return float(ssl.cert_time_to_seconds(out.strip().split('=', 1)[-1]))


def my_names(c):
    names = [x for x in (c.get('advertise'), socket.gethostname(), socket.getfqdn()) if x]
    names += [str(x) for x in c.get('names') or []]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.0.2.1', 9))
        names.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    out = []
    for n in names:
        if n and n not in out:
            out.append(n)
    return out


def boot_cert(c):
    """The certificate it answers with until an acme node issued it one: self-signed, made
    once; its fingerprint goes into the join code."""
    crt, key = _p(c, 'boot.crt'), _p(c, 'boot.key')
    if not (os.path.exists(crt) and os.path.exists(key)):
        with tempfile.TemporaryDirectory() as t:
            k = os.path.join(t, 'k.pem')
            _openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', k])
            pem = _openssl(['req', '-new', '-x509', '-key', k, '-days', '3650', '-subj',
                            '/CN=acme-db-agent %s' % socket.gethostname()[:40]])
            _write(key, open(k).read())
        _write(crt, pem, 0o644)
    return crt, key


def served_cert(c):
    if os.path.exists(_p(c, 'server.crt')) and os.path.exists(_p(c, 'server.key')):
        return _p(c, 'server.crt'), _p(c, 'server.key')
    return boot_cert(c)


def clients(c):
    got = _json(_p(c, 'clients.json'), [])
    return [x for x in got if isinstance(x, dict) and x.get('fp') and x.get('key')]


def audit(c, **kw):
    kw['ts'] = time.time()
    try:
        os.makedirs(os.path.dirname(c['log']), mode=0o750, exist_ok=True)
        fd = os.open(c['log'], os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(json.dumps(kw, sort_keys=True) + '\n')
    except OSError:
        pass


def sign_text(method, path, node, ts, nonce, body):
    return '\n'.join([PROTO, method, path, node, str(ts), nonce,
                      hashlib.sha256(body).hexdigest()]).encode()


def reply_sig(key, nonce, body):
    return hmac.new(key, ('reply\n%s\n' % nonce).encode() + hashlib.sha256(body).digest(),
                    'sha256').hexdigest()


# ---- the root side -------------------------------------------------------------------------
class Root(object):
    """What root does: checks a request once more and carries it out."""

    def __init__(self, c):
        self.c = c
        self.seen = {}                  # nonce -> time (replays)
        os.environ['ACME_HA_CA'] = c['ha_ca']
        if c.get('my_socket'):
            # MariaDB's socket where it is not the usual one: the clients root runs (the root
            # helper's dbmake too) read it from an option file of the agent's own.
            home = os.path.join(c['state'], 'home')
            os.makedirs(home, mode=0o700, exist_ok=True)
            _write(os.path.join(home, '.my.cnf'), '[client]\nsocket=%s\n' % c['my_socket'])
            os.environ['HOME'] = home
            os.environ['MYSQL_UNIX_PORT'] = str(c['my_socket'])
        sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
        import acme_pg_ops
        self.ops = acme_pg_ops

    def handle(self, msg):
        kind = msg.get('kind')
        try:
            if kind == 'op':
                return self.op(msg)
            if kind in ('enroll_begin', 'enroll_finish'):
                return self.enroll(msg)
            return {'ok': False, 'said': 'not a request this agent knows'}
        except self.ops.Refused as e:
            return {'ok': False, 'said': str(e)[:400]}
        except Exception as e:                          # noqa: BLE001
            return {'ok': False, 'said': 'it went wrong: %s' % str(e)[:300]}

    def _client(self, msg):
        """The enrolled acme node this is: its certificate, its signature, a fresh nonce."""
        fp = str(msg.get('fp') or '')
        node = str(msg.get('node') or '')
        cl = clients(self.c)
        one = next((x for x in cl if hmac.compare_digest(x['fp'], fp)), None)
        nxt = next((x for x in cl if hmac.compare_digest(str(x.get('fp_next') or ''), fp)), None)
        if nxt is not None and nxt.get('name') == node:
            # Its renewed certificate in use: the old one is no longer let in.
            nxt['fp'], nxt['fp_next'], one = fp, None, nxt
            _write(_p(self.c, 'clients.json'), json.dumps(cl, indent=1))
        if not one or one.get('name') != node:
            raise self.ops.Refused('this client certificate is not one enrolled here')
        body = base64.b64decode(msg.get('body') or '')
        try:
            ts = float(msg.get('ts'))
        except (TypeError, ValueError):
            raise self.ops.Refused('the request has no time')
        now = time.time()
        if abs(now - ts) > SKEW:
            raise self.ops.Refused('the request\'s time is %d s from this server\'s' % (now - ts))
        nonce = str(msg.get('nonce') or '')
        if not (16 <= len(nonce) <= 64) or nonce in self.seen:
            raise self.ops.Refused('the request was seen before')
        want = hmac.new(bytes.fromhex(one['key']), sign_text(msg.get('method', 'POST'),
                                                             msg.get('path', ''), node, msg['ts'],
                                                             nonce, body), 'sha256').hexdigest()
        if not hmac.compare_digest(want, str(msg.get('sig') or '')):
            raise self.ops.Refused('the request is not signed by %s' % node)
        self.seen = {k: v for k, v in self.seen.items() if v > now - 2 * SKEW}
        self.seen[nonce] = now
        return one, json.loads(body.decode() or '{}')

    def op(self, msg):
        one, req = self._client(msg)
        op, args = str(req.get('op') or ''), req.get('args') or {}
        if op in AGENT_OPS:
            out = getattr(self, 'a_' + op)(args, one)
        else:
            out = self.ops.run_op(op, args, self.c)
        if op == 'status':
            out.update(agent=self.agent_facts())
        said = out.get('said')
        audit(self.c, node=one['name'], ip=msg.get('ip'), op=op, ok=True,
              said=(said if isinstance(said, str) else '; '.join(map(str, said or [])))[:300],
              do=args.get('do') if isinstance(args, dict) else None)
        return dict(out, ok=True, key=one['key'])

    def agent_facts(self):
        crt, _ = served_cert(self.c)
        pem = _read(crt, '')
        return {'version': VERSION, 'port': self.c['port'], 'engine': self.c['engine'],
                'pg_port': self.c['pg_port'], 'cert_end': cert_end(pem) if pem else None,
                'cert_fp': fp_of_pem(pem) if pem else '', 'boot': crt.endswith('boot.crt'),
                'clients': [{'name': x['name'], 'addr': x.get('addr'), 'at': x.get('at'),
                             'cert_end': x.get('cert_end')} for x in clients(self.c)],
                'uid': os.geteuid()}

    # -- enrollment: a one-time code, then this server's certificate and the node's ---------
    def _code(self, secret):
        codes = _json(_p(self.c, 'join.json'), [])
        now = time.time()
        h = hashlib.sha256(str(secret or '').encode()).hexdigest()
        left = []
        hit = None
        for x in codes:
            if float(x.get('until') or 0) < now or int(x.get('tries') or 0) >= CODE_TRIES:
                continue
            if hmac.compare_digest(x['hash'], h):
                hit = x
            left.append(x)
        if hit is None:
            for x in left:              # every code living takes a wrong try
                x['tries'] = int(x.get('tries') or 0) + 1
            _write(_p(self.c, 'join.json'), json.dumps(left))
            raise self.ops.Refused('the join code is not one this agent gave, or it was used up '
                                   'or ran out: make a new one (acme_db_agent.py --new-code)')
        return hit, left

    def enroll(self, msg):
        req = json.loads(base64.b64decode(msg.get('body') or '').decode() or '{}')
        hit, left = self._code(req.get('secret'))
        node = str(req.get('node') or '')
        if not node or len(node) > 63 or not node.replace('-', '').replace('_', '').replace('.', '').isalnum():
            raise self.ops.Refused('the node\'s name is a plain name')
        if msg['kind'] == 'enroll_begin':
            csr = self.new_csr()
            audit(self.c, node=node, ip=msg.get('ip'), op='enroll_begin', ok=True)
            return {'ok': True, 'csr': csr, 'names': my_names(self.c), 'version': VERSION,
                    'engine': self.c['engine'], 'pg_port': self.c['pg_port'],
                    'my_port': self.c['my_port']}
        ca = str(req.get('ca') or '')
        client = str(req.get('client_cert') or '')
        key = str(req.get('sign_key') or '')
        if len(key) != 64 or any(ch not in '0123456789abcdef' for ch in key):
            raise self.ops.Refused('the signing key is 32 bytes in hex')
        self.check_issued(ca, client, 'sslclient')
        self.install_cert(str(req.get('cert') or ''), ca)
        now = time.time()
        cl = [x for x in clients(self.c) if x.get('name') != node]
        cl.append({'name': node, 'fp': fp_of_pem(client), 'key': key, 'at': now,
                   'addr': msg.get('ip'), 'cert_end': cert_end(client)})
        _write(_p(self.c, 'clients.json'), json.dumps(cl, indent=1))
        _write(_p(self.c, 'join.json'), json.dumps([x for x in left if x is not hit]))
        audit(self.c, node=node, ip=msg.get('ip'), op='enroll', ok=True,
              said='enrolled; the code is used up')
        return {'ok': True, 'restart': True, 'said': '%s joined this agent' % node,
                'facts': self.agent_facts()}

    def new_csr(self):
        with tempfile.TemporaryDirectory() as t:
            k = os.path.join(t, 'k.pem')
            _openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', k])
            csr = _openssl(['req', '-new', '-key', k, '-subj', '/CN=acme-db-agent'])
            _write(_p(self.c, 'pending.key'), open(k).read())
        return csr

    def check_issued(self, ca, pem, purpose):
        if '-----BEGIN CERTIFICATE-----' not in ca or '-----BEGIN CERTIFICATE-----' not in pem:
            raise self.ops.Refused('the authority and the certificate are PEM')
        with tempfile.TemporaryDirectory() as t:
            for n, v in (('ca.pem', ca), ('c.pem', pem)):
                with open(os.path.join(t, n), 'w') as f:
                    f.write(v.strip() + '\n')
            try:
                _openssl(['verify', '-purpose', purpose, '-CAfile', os.path.join(t, 'ca.pem'),
                          os.path.join(t, 'c.pem')])
            except ValueError as e:
                raise self.ops.Refused('the certificate is not from that authority: %s' % e)

    def install_cert(self, cert, ca):
        pending = _p(self.c, 'pending.key')
        if not os.path.exists(pending):
            raise self.ops.Refused('no certificate request is waiting here')
        self.check_issued(ca, cert, 'sslserver')
        a = _openssl(['x509', '-noout', '-pubkey'], cert)
        b = _openssl(['pkey', '-in', pending, '-pubout'])
        if a.strip() != b.strip():
            raise self.ops.Refused('the certificate is not for the key this agent asked with')
        trust = _read(_p(self.c, 'ca.pem'), '') or ''
        if ca.strip() not in trust:
            trust = ca.strip() + '\n' + trust
        _write(_p(self.c, 'ca.pem'), trust, 0o644)
        _write(_p(self.c, 'server.key'), _read(pending))
        _write(_p(self.c, 'server.crt'), cert.strip() + '\n', 0o644)
        os.unlink(pending)

    # -- what an enrolled node may ask of the agent itself --------------------------------
    def a_agent_csr(self, args, one):
        return {'csr': self.new_csr(), 'names': my_names(self.c)}

    def a_agent_cert(self, args, one):
        self.install_cert(str(args.get('cert') or ''), str(args.get('ca') or '').strip() or
                          _read(_p(self.c, 'ca.pem'), ''))
        return {'said': 'the agent answers with its new certificate', 'restart': True,
                'cert_end': cert_end(str(args.get('cert')))}

    def a_trust(self, args, one):
        """The authorities client certificates are checked against, replaced - refused when
        the asking node's own certificate would no longer pass (never locked out)."""
        ca = str(args.get('ca') or '').strip()
        mine = str(args.get('client_cert') or '')
        if mine:
            if fp_of_pem(mine) != one['fp']:
                raise self.ops.Refused('that is not the certificate this node asks with')
        cl = clients(self.c)
        if args.get('client_cert_new'):
            new = str(args['client_cert_new'])
            self.check_issued(ca, new, 'sslclient')
            for x in cl:
                if x['name'] == one['name']:
                    x['fp_next'] = fp_of_pem(new)
            _write(_p(self.c, 'clients.json'), json.dumps(cl, indent=1))
        _write(_p(self.c, 'ca.pem'), ca + '\n', 0o644)
        return {'said': 'the authorities are replaced', 'restart': True}

    def a_clients(self, args, one):
        drop = str(args.get('drop') or '')
        cl = clients(self.c)
        if drop:
            if drop == one['name']:
                raise self.ops.Refused('a node does not take itself away')
            cl = [x for x in cl if x['name'] != drop]
        _write(_p(self.c, 'clients.json'), json.dumps(cl, indent=1))
        return {'clients': [x['name'] for x in cl], 'restart': bool(drop)}


# ---- the side that faces the network ------------------------------------------------------
def _send(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack('!I', len(data)) + data)


def _recv(sock):
    head = b''
    while len(head) < 4:
        got = sock.recv(4 - len(head))
        if not got:
            raise EOFError
        head += got
    n = struct.unpack('!I', head)[0]
    data = b''
    while len(data) < n:
        got = sock.recv(min(65536, n - len(data)))
        if not got:
            raise EOFError
        data += got
    return json.loads(data.decode())


class Bucket(object):
    def __init__(self, rate, burst):
        self.rate, self.burst, self.b, self.lock = float(rate), float(burst), {}, threading.Lock()

    def take(self, key, n=1.0):
        now = time.monotonic()
        with self.lock:
            left, at = self.b.get(key, (self.burst, now))
            left = min(self.burst, left + (now - at) * self.rate)
            if left < n:
                self.b[key] = (left, now)
                return False
            self.b[key] = (left - n, now)
            return True


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'acme-db-agent'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def answer(self, code, obj, key=None, nonce=''):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if key:
            self.send_header('X-Acme-Sign', reply_sig(bytes.fromhex(key), nonce, body))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self):
        if self.path == '/v1/hello':
            # Nothing but that it is here and which version (for acme's join and probes).
            return self.answer(200, {'agent': 'acme-db-agent', 'version': VERSION})
        return self.answer(404, {'ok': False, 'said': 'not here'})

    def do_POST(self):
        srv = self.server
        ip = self.client_address[0]
        if not srv.bucket.take(ip) or not srv.fails.take(ip, 0):
            return self.answer(429, {'ok': False, 'said': 'too many requests - wait a moment'})
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= BODY_MOST:
            return self.answer(413, {'ok': False, 'said': 'the request is too big'})
        body = self.rfile.read(n)
        msg = {'ip': ip, 'path': self.path, 'method': 'POST',
               'body': base64.b64encode(body).decode()}
        der = self.connection.getpeercert(True)
        if self.path in ('/v1/enroll/begin', '/v1/enroll/finish'):
            msg['kind'] = 'enroll_begin' if self.path.endswith('begin') else 'enroll_finish'
        elif self.path == '/v1/op':
            if not der:
                srv.fails.take(ip, 5)
                return self.answer(401, {'ok': False, 'said': 'a client certificate from acme\'s '
                                                              'authority is needed'})
            msg.update(kind='op', fp=hashlib.sha256(der).hexdigest(),
                       node=self.headers.get('X-Acme-Node') or '',
                       ts=self.headers.get('X-Acme-Time') or '',
                       nonce=self.headers.get('X-Acme-Nonce') or '',
                       sig=self.headers.get('X-Acme-Sign') or '')
            if not any(hmac.compare_digest(x['fp'], msg['fp']) or
                       hmac.compare_digest(str(x.get('fp_next') or ''), msg['fp'])
                       for x in srv.clients):
                srv.fails.take(ip, 5)
                return self.answer(403, {'ok': False, 'said': 'this client certificate is not '
                                                              'one enrolled here'})
        else:
            return self.answer(404, {'ok': False, 'said': 'not here'})
        if getattr(srv, 'closing', False):
            return self.answer(503, {'ok': False, 'said': 'the agent is starting again'})
        with srv.root_lock:
            try:
                _send(srv.root, msg)
                got = _recv(srv.root)
            except (EOFError, OSError):
                # root is gone or starting this side again: this one ends
                threading.Thread(target=lambda: (time.sleep(0.3), os._exit(4)), daemon=True).start()
                return self.answer(503, {'ok': False, 'said': 'the agent is starting again'})
        key = got.pop('key', None)
        if not got.get('ok'):
            srv.fails.take(ip, 3)
        if got.get('restart'):
            srv.closing = True
        self.answer(200 if got.get('ok') else 400, got, key, msg.get('nonce', ''))
        if got.get('restart'):
            # Its new certificate or clients: this side started again by root with them.
            threading.Thread(target=lambda: (time.sleep(0.5), os._exit(3)), daemon=True).start()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        sock, addr = self.socket.accept()
        return sock, addr

    def finish_request(self, request, client_address):
        request.settimeout(30)
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            self.fails.take(client_address[0], 2)
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def handle_error(self, request, client_address):
        pass


def make_ctx(c):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    crt, key = served_cert(c)
    ctx.load_cert_chain(crt, key)
    ca = _read(_p(c, 'ca.pem'), '')
    if ca and '-----BEGIN CERTIFICATE-----' in ca:
        ctx.load_verify_locations(cadata=ca)
        ctx.verify_mode = ssl.CERT_OPTIONAL      # enrollment comes without one
    return ctx


def drop_to(c):
    """Root no more: the agent's own account (or nobody), no other groups."""
    if os.geteuid() != 0:
        return
    import pwd
    try:
        pw = pwd.getpwnam(str(c.get('user') or 'acme-db-agent'))
    except KeyError:
        pw = pwd.getpwnam('nobody')
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    if os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit('acme-db-agent: root could not be given up')
    try:
        import ctypes
        ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)        # PR_SET_NO_NEW_PRIVS
    except Exception:                                   # noqa: BLE001
        pass


def child(c, sock, cl):
    # Not root's handlers: this side ends at SIGTERM, and with root (PR_SET_PDEATHSIG).
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        import ctypes
        ctypes.CDLL(None).prctl(1, signal.SIGTERM, 0, 0, 0)
    except Exception:                                   # noqa: BLE001
        pass
    if os.getppid() == 1:
        os._exit(2)
    ctx = make_ctx(c)
    listener = Server((c['listen'], int(c['port'])), Handler, bind_and_activate=False)
    if ':' in c['listen']:
        listener.address_family = socket.AF_INET6
        listener.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    listener.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.server_bind()
    listener.server_activate()
    drop_to(c)
    listener.ctx = ctx
    listener.root = sock
    listener.root_lock = threading.Lock()
    listener.clients = cl
    listener.bucket = Bucket(c['rate'], c['burst'])
    listener.fails = Bucket(0.2, 20)
    listener.serve_forever()


def serve(c):
    os.makedirs(c['state'], mode=0o700, exist_ok=True)
    root = Root(c)
    stop = {'now': False}

    def bye(*_):
        stop['now'] = True
        pid = stop.get('pid')
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    audit(c, op='start', ok=True, said='acme-db-agent %s on %s:%s' % (VERSION, c['listen'],
                                                                       c['port']))
    while not stop['now']:
        mine, theirs = socket.socketpair()
        # The clients read as root, before giving it up: the file is root's alone.
        cl = clients(c)
        pid = os.fork()
        if pid == 0:
            mine.close()
            try:
                child(c, theirs, cl)
            finally:
                os._exit(2)
        theirs.close()
        stop['pid'] = pid
        began = time.monotonic()
        try:
            while True:
                try:
                    msg = _recv(mine)
                except (EOFError, OSError):
                    break
                try:
                    _send(mine, root.handle(msg))
                except OSError:
                    break               # that side went (it starts again with what is new)
        finally:
            mine.close()
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        if not stop['now'] and time.monotonic() - began < 2:
            time.sleep(2)               # one that dies at once is not started 100 times a second
    return 0


def new_code(c, minutes=CODE_MINUTES):
    crt, _ = served_cert(c)
    host = c.get('advertise') or (my_names(c) or ['127.0.0.1'])[-1]
    secret = secrets.token_urlsafe(18)
    codes = [x for x in _json(_p(c, 'join.json'), []) if float(x.get('until') or 0) > time.time()]
    codes.append({'hash': hashlib.sha256(secret.encode()).hexdigest(),
                  'until': time.time() + minutes * 60, 'tries': 0})
    _write(_p(c, 'join.json'), json.dumps(codes))
    data = {'h': host, 'p': int(c['port']), 's': secret, 'f': fp_of_pem(_read(crt)),
            'e': c['engine']}
    return 'ADBA1.' + base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':'))
                                               .encode()).decode().rstrip('=')


def main(argv):
    path = None
    if '--config' in argv:
        i = argv.index('--config')
        path = argv[i + 1]
        del argv[i:i + 2]
    c = conf_read(path)
    if argv[:1] == ['--new-code']:
        minutes = int(argv[argv.index('--minutes') + 1]) if '--minutes' in argv else CODE_MINUTES
        code = new_code(c, minutes)
        print(code)
        sys.stderr.write('acme-db-agent: give this code to the acme node within %d minutes:\n'
                         '  acme --db-agent-join %s\n' % (minutes, code))
        return 0
    if argv[:1] == ['--status']:
        crt, _ = served_cert(c)
        print(json.dumps({'version': VERSION, 'port': c['port'], 'engine': c['engine'],
                          'cert': crt, 'cert_fp': fp_of_pem(_read(crt)),
                          'clients': [x['name'] for x in clients(c)]}, indent=1))
        return 0
    if argv[:1] == ['--forget'] and len(argv) > 1:
        cl = [x for x in clients(c) if x['name'] != argv[1]]
        _write(_p(c, 'clients.json'), json.dumps(cl, indent=1))
        print('%s is no longer let in (restart acme-db-agent)' % argv[1])
        return 0
    if argv:
        print(__doc__)
        return 2
    return serve(c)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
