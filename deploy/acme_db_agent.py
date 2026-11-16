#!/usr/bin/python3 -I
"""acme_db_agent.py - acme-db-agent: a database server of its own, looked after by acme (1.0.113).

acme looks after the database on its own machine through its root helper
(acme_web.py): a certificate for PostgreSQL, pg_hba.conf, a restart, the
replication's settings. When the database is on a server of its own, this
agent does the same there - and nothing else:

  * it answers HTTPS on a port of its own (9443), only to acme nodes that
    joined it. It answers with a certificate it made itself (no authority:
    every node pins its fingerprint, from the join code on), the same for
    every node that joined - several nodes may join one agent. It renews it
    by itself: the next one is made 60 days before the end and announced to
    every node in the signed answer of `status`; it is put in use once every
    node joined took it in (7 days before the end at the latest).
  * each node shows a client certificate (mutual TLS) whose fingerprint is
    one enrolled - a list of fingerprints, each node's own (the authorities
    that issued them are only what TLS needs to ask for them; one node's
    never replaces another's) - and signs every request (HMAC-SHA256 with a
    key of its own, given at enrollment) with the time and a nonce: a request
    seen before (also before the agent last started), or older than two
    minutes, is refused;
  * it does a closed set of operations (acme_pg_ops.OPS: status, load, pgtls,
    pg_prepare, pg_allow, my_allow, pg_publication, pg_restart, pg_reload,
    pglog, dbmake, my_tls, my_restart, fw_allow; agent_renew, trust,
    clients). Every value is checked against the one shape it may have; no
    shell, no file named by the request, SQL only as the postgres account;
  * two processes. The side that faces the network is a program started
    afresh (never a copy of root's memory), runs as an account of its own
    (acme-db-agent - never nobody, never root): it terminates TLS and rate-
    limits, and hands the request as it came - method, path, headers, body
    and the client's certificate - to the root side over a socket pair. It
    holds no signing key. The root side works the fingerprint out of the
    certificate itself, checks it is enrolled, checks the signature, the
    time and the nonce, runs the operation, signs the answer, and writes the
    audit log - refusals too;
  * joining: `acme_db_agent.py --new-code` prints a one-time code (an hour)
    holding this server's address, a secret, the code's id and the
    fingerprint of the certificate it answers with - acme pins it, so nobody
    in between can pose as the agent. `acme --db-agent-join -` on the acme
    node (the code pasted on its standard input) begins (a token of its own
    for this node's finish), sends its client certificate, the authorities
    that issued it and its signing key. The code is then used up. Wrong codes
    are counted per address (and per code when the code's id is right).

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
import re
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

VERSION = '1.0.114'
CONF_FILE = os.environ.get('ACME_DB_AGENT_CONFIG', '/etc/acme-db-agent/agent.json')
PROTO = 'acme-db-agent/1'
SKEW = 120                      # a request's time this far from ours at most (s)
CODE_MINUTES = 60
CODE_TRIES = 5                  # wrong tries of one code (its id right) before it is void
ADDR_TRIES = 10                 # wrong codes from one address in an hour before it is refused
BODY_MOST = 262144
AGENT_CERT_DAYS = 825
AGENT_NEXT_DAYS = 60            # the next certificate made and announced this long before the end
AGENT_FORCE_DAYS = 7            # put in use then even if a node never took it in
AGENT_OPS = ('agent_renew', 'trust', 'clients')
DEFAULTS = {'listen': '0.0.0.0', 'port': 9443, 'engine': 'postgres', 'pg_port': 5432,
            'my_port': 3306, 'user': 'acme-db-agent', 'state': '/var/lib/acme-db-agent',
            'log': '/var/log/acme-db-agent/audit.log', 'ha_ca': '/etc/pki/acme/ha-ca.pem',
            'advertise': '', 'names': [], 'rate': 20, 'burst': 60,
            'fail_rate': 0.2, 'fail_burst': 20}
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----')


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
    c['path'] = os.path.abspath(path)
    c['dir'] = os.path.dirname(c['path'])
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


def _sha(text):
    return hashlib.sha256(str(text or '').encode()).hexdigest()


def fp_of_pem(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.strip() + '\n')).hexdigest()


def cert_end(pem):
    out = _openssl(['x509', '-noout', '-enddate'], pem)
    return float(ssl.cert_time_to_seconds(out.strip().split('=', 1)[-1]))


def pem_blocks(text):
    out = []
    for b in PEM_RE.findall(str(text or '')):
        b = b.strip() + '\n'
        if b not in out:
            out.append(b)
    return out


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


# ---- the agent's own certificate: made here, pinned by every node, renewed here -----------
def _make_cert(crt, key):
    with tempfile.TemporaryDirectory() as t:
        k = os.path.join(t, 'k.pem')
        _openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', k])
        pem = _openssl(['req', '-new', '-x509', '-key', k, '-days', str(AGENT_CERT_DAYS),
                        '-subj', '/CN=acme-db-agent %s' % socket.gethostname()[:40]])
        with open(k) as f:
            _write(key, f.read())
    _write(crt, pem, 0o644)


def agent_cert(c):
    """(crt, key) the agent answers with - to every node alike. Made here once (before 1.0.113
    was released it was boot.crt: taken over)."""
    crt, key = _p(c, 'agent.crt'), _p(c, 'agent.key')
    if not (os.path.exists(crt) and os.path.exists(key)):
        old_c, old_k = _p(c, 'boot.crt'), _p(c, 'boot.key')
        if os.path.exists(old_c) and os.path.exists(old_k):
            os.replace(old_k, key)
            os.replace(old_c, crt)
        else:
            _make_cert(crt, key)
    return crt, key


def next_cert(c):
    """(crt, key) of the next certificate when one is made and announced, else None."""
    crt, key = _p(c, 'agent-next.crt'), _p(c, 'agent-next.key')
    return (crt, key) if os.path.exists(crt) and os.path.exists(key) else None


def cert_facts(c):
    crt, _ = agent_cert(c)
    pem = _read(crt, '') or ''
    out = {'cert_fp': fp_of_pem(pem) if pem else '', 'cert_end': cert_end(pem) if pem else None,
           'cert_next_fp': '', 'cert_next_end': None}
    nxt = next_cert(c)
    if nxt:
        npem = _read(nxt[0], '') or ''
        if npem:
            out.update(cert_next_fp=fp_of_pem(npem), cert_next_end=cert_end(npem))
    return out


def clients(c):
    got = _json(_p(c, 'clients.json'), [])
    return [x for x in got if isinstance(x, dict) and x.get('fp') and x.get('key')]


def clients_put(c, cl):
    _write(_p(c, 'clients.json'), json.dumps(cl, indent=1))


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
    """What root does: every check of a request, the operation, the signed answer. Every key
    stays here."""

    def __init__(self, c):
        self.c = c
        self.code_fails = {}            # address -> [times of wrong codes]
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
        sys.dont_write_bytecode = True          # nothing written into the program's folder
        import acme_pg_ops
        self.ops = acme_pg_ops
        self.seen = self._nonces_load()

    # -- the nonces seen, kept across a restart (a request captured is never taken twice) ---
    def _nonces_path(self):
        return os.path.join(self.c['state'], 'nonces.json')

    def _nonces_load(self):
        got = _json(self._nonces_path(), {})
        now = time.time()
        if not isinstance(got, dict):
            return {}
        return {str(k): float(v) for k, v in got.items()
                if isinstance(v, (int, float)) and v > now - 2 * SKEW}

    def _nonce_keep(self, nonce, now):
        self.seen = {k: v for k, v in self.seen.items() if v > now - 2 * SKEW}
        self.seen[nonce] = now
        try:
            os.makedirs(self.c['state'], mode=0o700, exist_ok=True)
            _write(self._nonces_path(), json.dumps(self.seen))
        except OSError:
            pass

    # -- what the network side is given: no key, only what TLS and the first check need ----
    def for_network_side(self):
        cl = clients(self.c)
        fps, cas = [], []
        for x in cl:
            for f in (x.get('fp'), x.get('fp_next')):
                if f and f not in fps:
                    fps.append(f)
            for b in pem_blocks(x.get('ca')):
                if b not in cas:
                    cas.append(b)
        return {'kind': 'init', 'fps': fps, 'cas': ''.join(cas)}

    def handle(self, msg):
        kind = msg.get('kind')
        try:
            if kind == 'op':
                return self.op(msg)
            if kind in ('enroll_begin', 'enroll_finish'):
                return self.enroll(msg)
            if kind == 'refused':
                audit(self.c, ip=msg.get('ip'), op='refused', ok=False,
                      said=str(msg.get('why') or '')[:200])
                return {'code': 0}
            return self.reply(404, {'ok': False, 'said': 'not a request this agent knows'})
        except Exception as e:                          # noqa: BLE001
            audit(self.c, ip=msg.get('ip'), op=str(kind)[:20], ok=False,
                  said=('it went wrong: %s' % e)[:300])
            return self.reply(400, {'ok': False, 'said': 'it went wrong: %s' % str(e)[:300]},
                              penalty=1)

    @staticmethod
    def reply(code, obj, key=None, nonce='', restart=False, penalty=0):
        body = json.dumps(obj)
        return {'code': code, 'body': body,
                'sig': reply_sig(bytes.fromhex(key), nonce, body.encode()) if key else '',
                'restart': bool(restart), 'penalty': int(penalty)}

    def _refused(self, msg, code, said, node='', op='', penalty=3):
        audit(self.c, ip=msg.get('ip'), node=node or None, op=op or 'refused', ok=False,
              said=said[:300])
        return self.reply(code, {'ok': False, 'said': said}, penalty=penalty)

    def op(self, msg):
        h = msg.get('headers') if isinstance(msg.get('headers'), dict) else {}
        node = str(h.get('node') or '')[:64]
        try:
            der = base64.b64decode(msg.get('der') or '')
            body = base64.b64decode(msg.get('body') or '')
        except (ValueError, TypeError):
            return self._refused(msg, 400, 'the request is not one this agent reads', node)
        if not der:
            return self._refused(msg, 401, 'a client certificate is needed', node, penalty=5)
        # The fingerprint worked out here, from the certificate itself - not taken from the
        # network side.
        fp = hashlib.sha256(der).hexdigest()
        cl = clients(self.c)
        one = next((x for x in cl if x.get('name') == node and (
            hmac.compare_digest(x['fp'], fp) or hmac.compare_digest(str(x.get('fp_next') or ''), fp))),
            None)
        if one is None:
            return self._refused(msg, 403, 'this client certificate is not one enrolled here',
                                 node, penalty=5)
        try:
            ts = float(h.get('ts'))
        except (TypeError, ValueError):
            return self._refused(msg, 400, 'the request has no time', node)
        now = time.time()
        if abs(now - ts) > SKEW:
            return self._refused(msg, 400, 'the request\'s time is %d s from this server\'s'
                                 % (now - ts), node)
        nonce = str(h.get('nonce') or '')
        if not (16 <= len(nonce) <= 64) or not re.fullmatch(r'[0-9A-Za-z_-]+', nonce) or \
                nonce in self.seen:
            return self._refused(msg, 400, 'the request was seen before', node)
        want = hmac.new(bytes.fromhex(one['key']), sign_text(
            str(msg.get('method') or 'POST'), str(msg.get('path') or ''), node, h.get('ts'),
            nonce, body), 'sha256').hexdigest()
        if not hmac.compare_digest(want, str(h.get('sig') or '')):
            return self._refused(msg, 400, 'the request is not signed by %s' % node, node)
        self._nonce_keep(nonce, now)
        if one.get('fp_next') and hmac.compare_digest(str(one['fp_next']), fp):
            # Its renewed certificate in use: the old one is no longer let in.
            one['fp'], one['fp_next'] = fp, None
            clients_put(self.c, cl)
        key = one['key']
        try:
            req = json.loads(body.decode() or '{}')
            if not isinstance(req, dict):
                raise ValueError('not an object')
        except (ValueError, UnicodeDecodeError):
            return self._refused(msg, 400, 'the request is not JSON', node)
        op, args = str(req.get('op') or '')[:40], req.get('args') or {}
        restart = False
        try:
            if op in AGENT_OPS:
                out = getattr(self, 'a_' + op)(args if isinstance(args, dict) else {}, one, cl,
                                               der)
                restart = bool(out.pop('agent_restart', False))
            else:
                out = self.ops.run_op(op, args, self.c)
                out.pop('agent_restart', None)          # the agent's own word only
            if op == 'status':
                restart = self.pins_taken(one, cl, args) or restart
                out.update(agent=self.agent_facts())
        except self.ops.Refused as e:
            audit(self.c, node=node, ip=msg.get('ip'), op=op, ok=False, said=str(e)[:300])
            return self.reply(400, {'ok': False, 'said': str(e)[:400]}, key, nonce)
        said = out.get('said')
        audit(self.c, node=node, ip=msg.get('ip'), op=op, ok=True,
              said=(said if isinstance(said, str) else '; '.join(map(str, said or [])))[:300],
              do=args.get('do') if isinstance(args, dict) else None)
        if restart:
            out['agent_restart'] = True
        return self.reply(200, dict(out, ok=True), key, nonce, restart=restart)

    def agent_facts(self):
        f = cert_facts(self.c)
        return dict(f, version=VERSION, port=self.c['port'], engine=self.c['engine'],
                    pg_port=self.c['pg_port'],
                    clients=[{'name': x['name'], 'addr': x.get('addr'), 'at': x.get('at'),
                              'cert_end': x.get('cert_end'),
                              'next_taken': bool(f['cert_next_fp']) and
                              f['cert_next_fp'] in (x.get('pinned') or [])}
                             for x in clients(self.c)],
                    uid=os.geteuid())

    # -- the agent's certificate renewed here: the next one announced, then put in use -----
    def next_make(self, force=False):
        """The next certificate made when the one in use ends within 60 days (or asked)."""
        if next_cert(self.c):
            return False
        crt, _ = agent_cert(self.c)
        left = cert_end(_read(crt, '')) - time.time()
        if not force and left > AGENT_NEXT_DAYS * 86400:
            return False
        _make_cert(_p(self.c, 'agent-next.crt'), _p(self.c, 'agent-next.key'))
        audit(self.c, op='agent_next', ok=True, said='the next certificate of the agent: %s'
              % fp_of_pem(_read(_p(self.c, 'agent-next.crt'))))
        return True

    def pins_taken(self, one, cl, args):
        """A node's `status` says which of the agent's certificates it pins: kept, and once
        every node took the next one in (or the one in use ends within 7 days) it is put in
        use - True: the network side starts again with it."""
        self.next_make()
        pins = args.get('pins') if isinstance(args, dict) else None
        f = cert_facts(self.c)
        if isinstance(pins, list):
            mine = [p for p in pins if isinstance(p, str) and p in (f['cert_fp'], f['cert_next_fp'])
                    and p]
            if sorted(mine) != sorted(one.get('pinned') or []):
                one['pinned'] = mine
                clients_put(self.c, cl)
        nxt = f['cert_next_fp']
        if not nxt:
            return False
        everyone = all(nxt in (x.get('pinned') or []) for x in cl)
        late = (f['cert_end'] or 0) - time.time() < AGENT_FORCE_DAYS * 86400
        if not (everyone or late):
            return False
        crt, key = agent_cert(self.c)
        ncrt, nkey = next_cert(self.c)
        os.replace(nkey, key)
        os.replace(ncrt, crt)
        audit(self.c, op='agent_cert', ok=True, said='the agent answers with its next certificate '
              '%s%s' % (nxt, '' if everyone else ' (not every node took it in: it ends soon)'))
        return True

    # -- enrollment: a one-time code, a token per begin, then the node's certificate --------
    def _addr_ok(self, ip):
        now = time.time()
        got = [t for t in self.code_fails.get(ip, []) if t > now - 3600]
        self.code_fails[ip] = got
        if len(got) >= ADDR_TRIES:
            raise self.ops.Refused('too many wrong join codes from %s - wait an hour' % ip)

    def _code(self, req, ip):
        codes = _json(_p(self.c, 'join.json'), [])
        now = time.time()
        h = _sha(req.get('secret'))
        cid = str(req.get('code_id') or '')
        left, hit = [], None
        for x in codes:
            if not isinstance(x, dict) or float(x.get('until') or 0) < now or \
                    int(x.get('tries') or 0) >= CODE_TRIES:
                continue
            same_id = not cid or not x.get('id') or hmac.compare_digest(str(x['id']), cid)
            if hmac.compare_digest(str(x.get('hash') or ''), h) and same_id:
                hit = x
            left.append(x)
        if hit is None:
            # The address counts the wrong try - and the code only when its id was right: a
            # stranger guessing burns no code of somebody else's.
            self.code_fails.setdefault(ip, []).append(now)
            if cid:
                for x in left:
                    if x.get('id') and hmac.compare_digest(str(x['id']), cid):
                        x['tries'] = int(x.get('tries') or 0) + 1
            _write(_p(self.c, 'join.json'), json.dumps(left))
            raise self.ops.Refused('the join code is not one this agent gave, or it was used up '
                                   'or ran out: make a new one (acme_db_agent.py --new-code)')
        return hit, left

    def enroll(self, msg):
        ip = str(msg.get('ip') or '')
        what = msg['kind']
        try:
            req = json.loads(base64.b64decode(msg.get('body') or '').decode() or '{}')
            if not isinstance(req, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return self._refused(msg, 400, 'the request is not JSON', op=what)
        node = str(req.get('node') or '')[:80]
        try:
            self._addr_ok(ip)
            hit, left = self._code(req, ip)
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}', node):
                raise self.ops.Refused('the node\'s name is a plain name')
            if what == 'enroll_begin':
                token = secrets.token_urlsafe(18)
                now = time.time()
                hit['begun'] = [b for b in hit.get('begun') or [] if isinstance(b, dict) and
                                float(b.get('at') or 0) > now - 900][-4:] + [{'h': _sha(token),
                                                                               'at': now}]
                _write(_p(self.c, 'join.json'), json.dumps(left))
                audit(self.c, node=node, ip=ip, op='enroll_begin', ok=True)
                f = cert_facts(self.c)
                return self.reply(200, {'ok': True, 'token': token, 'names': my_names(self.c),
                                        'version': VERSION, 'engine': self.c['engine'],
                                        'pg_port': self.c['pg_port'], 'my_port': self.c['my_port'],
                                        'cert_fp': f['cert_fp'], 'cert_next_fp': f['cert_next_fp']})
            token = _sha(req.get('token'))
            if not any(hmac.compare_digest(str(b.get('h') or ''), token) for b in
                       hit.get('begun') or [] if isinstance(b, dict) and
                       float(b.get('at') or 0) > time.time() - 900):
                self.code_fails.setdefault(ip, []).append(time.time())
                raise self.ops.Refused('the join was not begun with this code from here (or more '
                                       'than 15 minutes ago) - join again')
            ca = str(req.get('ca') or '')
            client = str(req.get('client_cert') or '')
            key = str(req.get('sign_key') or '')
            if not HEX64.match(key):
                raise self.ops.Refused('the signing key is 32 bytes in hex')
            if not pem_blocks(ca):
                raise self.ops.Refused('the authorities of the node\'s certificate are missing')
            self.check_issued(ca, client, 'sslclient')
        except self.ops.Refused as e:
            return self._refused(msg, 400, str(e), node, what)
        now = time.time()
        cl = [x for x in clients(self.c) if x.get('name') != node]
        cl.append({'name': node, 'fp': fp_of_pem(client), 'key': key, 'at': now, 'addr': ip,
                   'ca': ''.join(pem_blocks(ca)), 'cert_end': cert_end(client), 'pinned': []})
        clients_put(self.c, cl)
        _write(_p(self.c, 'join.json'), json.dumps([x for x in left if x is not hit]))
        audit(self.c, node=node, ip=ip, op='enroll', ok=True, said='enrolled; the code is used up')
        return self.reply(200, {'ok': True, 'agent_restart': True,
                                'said': '%s joined this agent' % node,
                                'facts': self.agent_facts()}, restart=True)

    def check_issued(self, ca, pem, purpose):
        if not pem_blocks(ca) or not pem_blocks(pem):
            raise self.ops.Refused('the authority and the certificate are PEM')
        with tempfile.TemporaryDirectory() as t:
            for n, v in (('ca.pem', ''.join(pem_blocks(ca))), ('c.pem', pem_blocks(pem)[0])):
                with open(os.path.join(t, n), 'w') as f:
                    f.write(v)
            try:
                _openssl(['verify', '-purpose', purpose, '-CAfile', os.path.join(t, 'ca.pem'),
                          os.path.join(t, 'c.pem')])
            except ValueError as e:
                raise self.ops.Refused('the certificate is not from that authority: %s' % e)

    # -- what an enrolled node may ask of the agent itself --------------------------------
    def a_agent_renew(self, args, one, cl, der):
        """The agent's next certificate made now (it is announced to every node, and put in
        use once every node took it in)."""
        self.next_make(force=True)
        f = cert_facts(self.c)
        return {'said': 'the agent\'s next certificate is announced to every node joined',
                'cert_next_fp': f['cert_next_fp'], 'cert_next_end': f['cert_next_end']}

    def a_trust(self, args, one, cl, der):
        """The authorities that issue THIS node's client certificates (each node's own - one
        node never replaces another's), with its next certificate announced. Refused when
        empty, or when the certificate the node asks with now would not pass with them (never
        locked out)."""
        ca = ''.join(pem_blocks(args.get('ca')))
        if not ca:
            raise self.ops.Refused('no authority given: refused - this node would be locked out')
        self.check_issued(ca, ssl.DER_cert_to_PEM_cert(der), 'sslclient')
        new = str(args.get('client_cert_new') or '')
        if new:
            self.check_issued(ca, new, 'sslclient')
            one['fp_next'] = fp_of_pem(new)
        one['ca'] = ca
        clients_put(self.c, cl)
        return {'said': 'the authorities of %s are replaced' % one['name'], 'agent_restart': True}

    def a_clients(self, args, one, cl, der):
        drop = str(args.get('drop') or '')
        if drop:
            if drop == one['name']:
                raise self.ops.Refused('a node does not take itself away')
            cl = [x for x in cl if x['name'] != drop]
            clients_put(self.c, cl)
        return {'clients': [x['name'] for x in cl], 'agent_restart': bool(drop)}


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

    def _now(self, key, now):
        left, at = self.b.get(key, (self.burst, now))
        return min(self.burst, left + (now - at) * self.rate)

    def take(self, key, n=1.0):
        now = time.monotonic()
        with self.lock:
            left = self._now(key, now)
            if left < n:
                self.b[key] = (left, now)
                return False
            self.b[key] = (left - n, now)
            return True

    def charge(self, key, n):
        """A penalty: taken whatever is left (it may go below nothing, to wait it off)."""
        now = time.monotonic()
        with self.lock:
            self.b[key] = (max(-self.burst, self._now(key, now) - n), now)

    def ok(self, key, need=1.0):
        """Is there `need` left - nothing taken."""
        with self.lock:
            return self._now(key, time.monotonic()) >= need


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'acme-db-agent'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def answer_raw(self, code, body, sig=''):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if sig:
            self.send_header('X-Acme-Sign', sig)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def answer(self, code, obj):
        self.answer_raw(code, json.dumps(obj).encode())

    def ask_root(self, msg):
        srv = self.server
        with srv.root_lock:
            try:
                _send(srv.root, msg)
                return _recv(srv.root)
            except (EOFError, OSError):
                # root is gone or starting this side again: this one ends
                threading.Thread(target=lambda: (time.sleep(0.3), os._exit(4)), daemon=True).start()
                return None

    def do_GET(self):
        if self.path == '/v1/hello':
            # Nothing but that it is here and which version (for acme's join and probes).
            return self.answer(200, {'agent': 'acme-db-agent', 'version': VERSION})
        return self.answer(404, {'ok': False, 'said': 'not here'})

    def do_POST(self):
        srv = self.server
        ip = self.client_address[0]
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= BODY_MOST:
            return self.answer(413, {'ok': False, 'said': 'the request is too big'})
        body = self.rfile.read(n)       # read before any answer: unread, the close resets it
        if not srv.fails.ok(ip) or not srv.bucket.take(ip):
            return self.answer(429, {'ok': False, 'said': 'too many requests - wait a moment'})
        der = self.connection.getpeercert(True) or b''
        if self.path in ('/v1/enroll/begin', '/v1/enroll/finish'):
            kind = 'enroll_begin' if self.path.endswith('begin') else 'enroll_finish'
        elif self.path == '/v1/op':
            kind = 'op'
            why = '' if der else 'no client certificate'
            if der and hashlib.sha256(der).hexdigest() not in srv.fps:
                why = 'a client certificate not enrolled here'
            if why:
                srv.fails.charge(ip, 5)
                if self.ask_root({'kind': 'refused', 'ip': ip, 'why': why}) is None:
                    return self.answer(503, {'ok': False, 'said': 'the agent is starting again'})
                return self.answer(401 if not der else 403, {'ok': False, 'said': (
                    'a client certificate from acme\'s authority is needed' if not der else
                    'this client certificate is not one enrolled here')})
        else:
            return self.answer(404, {'ok': False, 'said': 'not here'})
        if getattr(srv, 'closing', False):
            return self.answer(503, {'ok': False, 'said': 'the agent is starting again'})
        # Handed over as it came: root works everything out of it itself.
        msg = {'kind': kind, 'ip': ip, 'path': self.path, 'method': 'POST',
               'headers': {'node': self.headers.get('X-Acme-Node') or '',
                           'ts': self.headers.get('X-Acme-Time') or '',
                           'nonce': self.headers.get('X-Acme-Nonce') or '',
                           'sig': self.headers.get('X-Acme-Sign') or ''},
               'body': base64.b64encode(body).decode(), 'der': base64.b64encode(der).decode()}
        got = self.ask_root(msg)
        if got is None:
            return self.answer(503, {'ok': False, 'said': 'the agent is starting again'})
        if got.get('penalty'):
            srv.fails.charge(ip, float(got['penalty']))
        if got.get('restart'):
            srv.closing = True
        self.answer_raw(int(got.get('code') or 500), str(got.get('body') or '').encode(),
                        str(got.get('sig') or ''))
        if got.get('restart'):
            # Its new certificate or clients: this side started again by root with them.
            threading.Thread(target=lambda: (time.sleep(0.5), os._exit(3)), daemon=True).start()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def finish_request(self, request, client_address):
        request.settimeout(30)
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            self.fails.charge(client_address[0], 2)
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


def make_ctx(c, cas):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    crt, key = agent_cert(c)
    ctx.load_cert_chain(crt, key)
    if cas:
        # Only what TLS needs to ask for the nodes' certificates: who is let in is the
        # fingerprint, checked by root.
        ctx.load_verify_locations(cadata=cas)
        ctx.verify_mode = ssl.CERT_OPTIONAL      # enrollment comes without one
    return ctx


def drop_to(c):
    """Root no more: the agent's own account - never root, never nobody - no other groups."""
    if os.geteuid() != 0:
        return
    import pwd
    name = str(c.get('user') or 'acme-db-agent')
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        raise SystemExit('acme-db-agent: the account %s is not there (install.sh --db-agent '
                         'makes it): the side that faces the network does not run as root' % name)
    if pw.pw_uid == 0 or name == 'nobody':
        raise SystemExit('acme-db-agent: the side that faces the network runs as an account of '
                         'its own, not %s' % name)
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


def network_side(c, fd):
    """The side that faces the network: a program of its own (started by root with the socket
    pair), not a copy of root's memory - no signing key was ever in it."""
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        import ctypes
        ctypes.CDLL(None).prctl(1, signal.SIGTERM, 0, 0, 0)    # PR_SET_PDEATHSIG: dies with root
    except Exception:                                   # noqa: BLE001
        pass
    if os.getppid() == 1:
        os._exit(2)
    sock = socket.socket(fileno=fd)
    init = _recv(sock)
    ctx = make_ctx(c, str(init.get('cas') or ''))
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
    listener.fps = set(str(x) for x in init.get('fps') or [])
    listener.bucket = Bucket(c['rate'], c['burst'])
    listener.fails = Bucket(c.get('fail_rate') or 0.2, c.get('fail_burst') or 20)
    listener.serve_forever()


def serve(c):
    os.makedirs(c['state'], mode=0o700, exist_ok=True)
    agent_cert(c)
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
    me = os.path.realpath(__file__)
    while not stop['now']:
        mine, theirs = socket.socketpair()
        proc = subprocess.Popen([sys.executable, '-I', me, '--config', c['path'],
                                 '--network-side', str(theirs.fileno())],
                                pass_fds=(theirs.fileno(),), close_fds=True, cwd='/')
        theirs.close()
        stop['pid'] = proc.pid
        began = time.monotonic()
        try:
            _send(mine, root.for_network_side())
            while True:
                try:
                    msg = _recv(mine)
                except (EOFError, OSError):
                    break
                try:
                    _send(mine, root.handle(msg))
                except OSError:
                    break               # that side went (it starts again with what is new)
        except OSError:
            pass
        finally:
            mine.close()
            try:
                proc.terminate()
            except OSError:
                pass
            try:
                proc.wait(20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        if not stop['now'] and time.monotonic() - began < 2:
            time.sleep(2)               # one that dies at once is not started 100 times a second
    return 0


def new_code(c, minutes=CODE_MINUTES):
    crt, _ = agent_cert(c)
    host = c.get('advertise') or (my_names(c) or ['127.0.0.1'])[-1]
    secret = secrets.token_urlsafe(18)
    cid = secrets.token_hex(4)
    codes = [x for x in _json(_p(c, 'join.json'), []) if isinstance(x, dict) and
             float(x.get('until') or 0) > time.time()]
    codes.append({'id': cid, 'hash': _sha(secret), 'until': time.time() + minutes * 60, 'tries': 0})
    _write(_p(c, 'join.json'), json.dumps(codes))
    data = {'h': host, 'p': int(c['port']), 's': secret, 'i': cid, 'f': fp_of_pem(_read(crt)),
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
    if argv[:1] == ['--network-side'] and len(argv) == 2:
        return network_side(c, int(argv[1]))
    if argv[:1] == ['--new-code']:
        minutes = int(argv[argv.index('--minutes') + 1]) if '--minutes' in argv else CODE_MINUTES
        code = new_code(c, minutes)
        print(code)
        sys.stderr.write('acme-db-agent: give this code to the acme node within %d minutes - as '
                         'root there:\n  acme --db-agent-join -\nand paste it (it is read from '
                         'standard input, never put on a command line)\n' % minutes)
        return 0
    if argv[:1] == ['--status']:
        crt, _ = agent_cert(c)
        f = cert_facts(c)
        print(json.dumps({'version': VERSION, 'port': c['port'], 'engine': c['engine'],
                          'cert': crt, 'cert_fp': f['cert_fp'], 'cert_next_fp': f['cert_next_fp'],
                          'clients': [x['name'] for x in clients(c)]}, indent=1))
        return 0
    if argv[:1] == ['--forget'] and len(argv) > 1:
        cl = [x for x in clients(c) if x['name'] != argv[1]]
        clients_put(c, cl)
        print('%s is no longer let in (restart acme-db-agent)' % argv[1])
        return 0
    if argv:
        print(__doc__)
        return 2
    return serve(c)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
