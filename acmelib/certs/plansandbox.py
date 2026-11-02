# -*- coding: utf-8 -*-
"""
The run plan's recording (acmelib/certs/runplan.py): a module's own code run
in a process of its own against a Context that answers everything and does
nothing - every call it would make written down instead.

    python3 -I -c '...plansandbox.main()'   < job JSON   > recordings JSON

Run by runplan.record() only, never inside the daemon. Before anything of
acmelib is imported the process is shut in (lockdown):

* the network: socket connect / sendto / create_connection / getaddrinfo and
  the rest raise - a call not caught below fails, it never goes out;
* programs: only openssl, and only its subcommands that read and write local
  files (genpkey, req, x509, pkcs12...) - never s_client, ocsp; everything
  else (ssh, scp, curl, a script) raises (or, inside a module's run, is
  written down and not run);
* files: written only under the process's own temporary folder; a write
  elsewhere inside a module's run is written down and not done (outside a
  run it raises); deleting, renaming, chmod, chown elsewhere the same;
* time: sleep() waits for nothing - it moves a clock of the process's own,
  so a module that waits for propagation is through its wait at once (the
  wait written down);
* every run has a few seconds (SIGALRM) - a module that loops is stopped.

The modules get no secret: the daemon hands each secret field as a stand-in
(PLANSECRET...), and the dummy certificate and key are made here, for this
run, never kept. What is written down is masked once more before it leaves
(keys, PEM, base64 blobs, auth headers) - runplan.py masks again.
"""
from __future__ import annotations

import builtins
import io
import json
import os
import re
import signal
import socket
import sys
import time
import traceback

SANDBOX = ['']                  # the process's own folder
RECORDING = [None]              # the list a module's run writes into, or None
SESSION = 'PLANSESSION0token'   # what a sign-in is answered with
TOKEN = 'PLAN-TOKEN-from-the-CA-0000000000'   # an ACME token (8+ of [A-Za-z0-9_-])
TXT = 'PLANTXTvalueComputedFromTheToken0000000000a'  # 43 characters, base64url
KEYAUTH = TOKEN + '.PLANthumbprintOfTheAccountKey00000000000000'
SAFE_OPENSSL = {'genpkey', 'req', 'x509', 'pkcs12', 'pkey', 'pkcs8', 'rsa', 'ec', 'ecparam',
                'genrsa', 'pkcs7', 'crl2pkcs7', 'dgst', 'asn1parse', 'base64', 'enc',
                'pkeyutl', 'version', 'list', 'rand', 'crl', 'verify', 'storeutl', 'kdf',
                'mac', 'sha256', 'sha1', 'md5'}
_real = {}


class Blocked(OSError):
    pass


def rec(ev):
    r = RECORDING[0]
    if r is not None and len(r) < 400:
        r.append(ev)


def _inside(path):
    try:
        p = os.path.realpath(os.fsdecode(path))
    except (TypeError, ValueError):
        return False
    root = SANDBOX[0]
    if p == os.devnull:
        return True
    return bool(root) and (p == root or p.startswith(root + os.sep))


# ---------------------------------------------------------------------------
# The lockdown
# ---------------------------------------------------------------------------
def _no_net(*_a, **_k):
    raise Blocked('the run plan contacts nothing')


class _Recorded(io.BytesIO):
    """A file a module writes outside the folder: kept in memory, written down on close."""
    def __init__(self, path, text, mode_bits=None):
        io.BytesIO.__init__(self)
        self._path, self._text = path, text

    def write(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return io.BytesIO.write(self, data)

    def close(self):
        if not self.closed:
            rec(dict({'kind': 'file', 'path': os.fsdecode(self._path)},
                     **blob_facts(self.getvalue())))
        io.BytesIO.close(self)


def _open(file, mode='r', *a, **k):
    if isinstance(file, int) or not any(c in str(mode) for c in 'wax+'):
        return _real['open'](file, mode, *a, **k)
    if _inside(file):
        return _real['open'](file, mode, *a, **k)
    if RECORDING[0] is not None:
        f = _Recorded(file, 'b' not in str(mode))
        if 'b' not in str(mode):
            return io.TextIOWrapper(f, encoding=k.get('encoding') or 'utf-8')
        return f
    raise Blocked('the run plan writes nothing outside its folder: %s' % file)


WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _os_open(path, flags, mode=0o777, *a, **k):
    if flags & WRITE_FLAGS and not _inside(path):
        raise Blocked('the run plan writes nothing outside its folder: %s' % path)
    return _real['os.open'](path, flags, mode, *a, **k)


def _guarded(name, kind):
    real = getattr(os, name)
    _real['os.' + name] = real

    def fn(path, *a, **k):
        if isinstance(path, int) or _inside(path):
            return real(path, *a, **k)
        if RECORDING[0] is not None:
            ev = {'kind': kind, 'path': os.fsdecode(path)}
            if kind == 'chmod' and a:
                ev['mode'] = '%o' % int(a[0])
            if kind == 'chown' and len(a) >= 2:
                ev['owner'] = '%s:%s' % (a[0], a[1])
            rec(ev)
            return None
        raise Blocked('the run plan changes nothing outside its folder: %s' % path)
    return fn


def _replace(src, dst, *a, **k):
    if _inside(src) and _inside(dst):
        return _real['os.replace'](src, dst, *a, **k)
    if RECORDING[0] is not None and _inside(src):
        try:
            with _real['open'](src, 'rb') as f:
                data = f.read()
            mode = '%o' % (os.stat(src).st_mode & 0o777)
            _real['os.unlink'](src)
        except OSError:
            data, mode = b'', None
        ev = dict({'kind': 'file', 'path': os.fsdecode(dst)}, **blob_facts(data))
        if mode:
            ev['mode'] = mode
        rec(ev)
        return None
    if RECORDING[0] is not None:
        rec({'kind': 'move', 'path': os.fsdecode(dst), 'from': os.fsdecode(src)})
        return None
    raise Blocked('the run plan moves nothing outside its folder')


def _popen_init(self, args, *a, **k):
    argv = [args] if isinstance(args, (str, bytes)) else list(args or [])
    exe = os.path.basename(os.fsdecode(argv[0])) if argv else ''
    sub = os.fsdecode(argv[1]) if len(argv) > 1 else ''
    if exe == 'openssl' and sub in SAFE_OPENSSL and not k.get('shell'):
        return _real['Popen.__init__'](self, args, *a, **k)
    rec({'kind': 'command', 'argv': [os.fsdecode(x) for x in argv][:60]})
    raise Blocked('the run plan runs no program: %s' % exe)


def _forbid(*_a, **_k):
    raise Blocked('the run plan runs no program')


def _mk_temp(real):
    def fn(*a, **k):
        d = k.get('dir')
        if d is None or not _inside(d):
            k['dir'] = SANDBOX[0]
        return real(*a, **k)
    return fn


CLOCK = [0.0]


def _sleep(s):
    try:
        s = max(0.0, float(s))
    except (TypeError, ValueError):
        s = 0.0
    CLOCK[0] += s
    r = RECORDING[0]
    if r is not None and s > 0:
        if r and r[-1].get('kind') == 'wait':
            r[-1]['seconds'] += s
            r[-1]['times'] += 1
        else:
            rec({'kind': 'wait', 'seconds': s, 'times': 1})


def lockdown(folder):
    import shutil
    import subprocess
    import tempfile
    SANDBOX[0] = os.path.realpath(folder)
    for n in ('connect', 'connect_ex', 'sendto', 'sendmsg', 'bind', 'listen'):
        setattr(socket.socket, n, _no_net)
    for n in ('create_connection', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex',
              'gethostbyaddr', 'create_server', 'socketpair', 'fromfd'):
        setattr(socket, n, _no_net)
    _real['open'] = builtins.open
    builtins.open = _open
    io.open = _open
    _real['os.open'] = os.open
    os.open = _os_open
    for name, kind in (('mkdir', 'mkdir'), ('makedirs', 'mkdir'), ('chmod', 'chmod'),
                       ('chown', 'chown'), ('lchown', 'chown'), ('remove', 'delete'),
                       ('unlink', 'delete'), ('rmdir', 'delete'), ('truncate', 'delete'),
                       ('utime', 'touch'), ('mkfifo', 'mkdir')):
        if hasattr(os, name):
            setattr(os, name, _guarded(name, kind))
    _real['os.replace'] = os.replace
    _real['os.unlink'] = _real.get('os.unlink') or os.unlink
    os.replace = _replace
    os.rename = _replace
    for n in ('link', 'symlink'):
        setattr(os, n, _forbid)
    for n in ('system', 'popen', 'fork', 'forkpty', 'execv', 'execve', 'execl', 'execle',
              'execlp', 'execvp', 'execvpe', 'spawnv', 'spawnve', 'spawnl', 'posix_spawn',
              'posix_spawnp', 'kill', 'killpg'):
        if hasattr(os, n):
            setattr(os, n, _forbid)
    _real['Popen.__init__'] = subprocess.Popen.__init__
    subprocess.Popen.__init__ = _popen_init
    shutil.rmtree = _guarded_rmtree(shutil.rmtree)
    tempfile.mkdtemp = _mk_temp(tempfile.mkdtemp)
    tempfile.mkstemp = _mk_temp(tempfile.mkstemp)
    tempfile.tempdir = SANDBOX[0]
    _real['time'] = time.time
    _real['monotonic'] = time.monotonic
    time.sleep = _sleep
    time.time = lambda: _real['time']() + CLOCK[0]
    time.monotonic = lambda: _real['monotonic']() + CLOCK[0]


def _guarded_rmtree(real):
    def fn(path, *a, **k):
        if _inside(path):
            return real(path, *a, **k)
        if RECORDING[0] is not None:
            rec({'kind': 'delete', 'path': os.fsdecode(path)})
            return None
        raise Blocked('the run plan deletes nothing outside its folder')
    return fn


# ---------------------------------------------------------------------------
# What is said of a piece of data
# ---------------------------------------------------------------------------
PEM_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----')


def blob_facts(data):
    """{'size', 'format', 'secret', 'body'?} of bytes written or sent."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = data or b''
    out = {'size': len(data)}
    try:
        t = data.decode('utf-8')
    except UnicodeDecodeError:
        t = None
    if t is None:
        out['format'] = 'binary (DER, PKCS#12 or a keystore)'
        out['secret'] = True
        return out
    labels = [m.group(1) for m in PEM_RE.finditer(t)]
    keys = [x for x in labels if 'PRIVATE KEY' in x]
    certs = [x for x in labels if x == 'CERTIFICATE']
    if keys and certs:
        out['format'] = 'private key and %d certificate(s) (PEM)' % len(certs)
        out['secret'] = True
    elif keys:
        out['format'] = 'private key (PEM)'
        out['secret'] = True
    elif certs:
        out['format'] = 'certificate (PEM)' if len(certs) == 1 else \
            '%d certificates (PEM)' % len(certs)
    elif labels:
        out['format'] = '%s (PEM)' % labels[0].lower()
    else:
        out['format'] = 'text'
        if len(t) <= 20000:
            out['body'] = t
    return out


B64_RUN = re.compile(r'[A-Za-z0-9+/_-]{120,}={0,2}')
SECRET_KEY = re.compile(r'(pass|secret|token|apikey|api_key|api-key|private|passphrase|'
                        r'credential|signature|hmac|session|cookie|auth)', re.I)
SECRET_HEADER = re.compile(r'(authorization|cookie|key|token|secret|auth|pass|session|'
                           r'signature|credential)', re.I)


def size_words(n):
    if n < 1024:
        return '%d B' % n
    return '%.1f kB' % (n / 1024.0)


def mask_text(t, marks):
    """Secrets out of a piece of text: the stand-ins, PEM keys, long base64."""
    t = str(t)
    for m, label in (marks or {}).items():
        if m and m in t:
            t = t.replace(m, '•••• (%s)' % label)
    t = t.replace(SESSION, '‹session›')

    def pem(m):
        lab = m.group(1)
        if 'PRIVATE KEY' in lab:
            return '•••• (private key, PEM, %s)' % size_words(len(m.group(0)))
        return '‹%s, PEM, %s›' % (lab.lower(), size_words(len(m.group(0))))
    t = PEM_RE.sub(pem, t)

    def b64(m):
        s = m.group(0)
        import base64
        try:
            raw = base64.b64decode(s + '=' * (-len(s) % 4), altchars=b'-_' if '-' in s or '_'
                                   in s else None)
        except Exception:                               # noqa: BLE001
            return s
        try:
            inner = raw.decode('utf-8')
        except UnicodeDecodeError:
            inner = None
        if inner and 'PRIVATE KEY' in inner:
            return '•••• (private key, PEM, base64, %s)' % size_words(len(raw))
        if inner and 'CERTIFICATE' in inner:
            return '‹certificate PEM, base64, %s›' % size_words(len(raw))
        if inner is None:
            return '•••• (binary, base64, %s)' % size_words(len(raw))
        return s
    return B64_RUN.sub(b64, t)


def mask_json(v, marks, key=''):
    if isinstance(v, dict):
        return {k: mask_json(x, marks, str(k)) for k, x in v.items()}
    if isinstance(v, list):
        return [mask_json(x, marks, key) for x in v]
    if isinstance(v, str):
        if key and SECRET_KEY.search(key) and v and not v.startswith('‹'):
            if v == SESSION:
                return '‹session›'
            return '••••'
        return mask_text(v, marks)
    return v


def mask_url(url, marks):
    import urllib.parse
    try:
        u = urllib.parse.urlsplit(str(url))
    except ValueError:
        return mask_text(url, marks)
    net = u.netloc
    if '@' in net:
        net = '••••@' + net.rsplit('@', 1)[1]
    q = '&'.join('%s=%s' % (k, '••••' if SECRET_KEY.search(
        urllib.parse.unquote(k)) and v else v) if eq else k
        for k, eq, v in (p.partition('=') for p in u.query.split('&') if p)) if u.query else ''
    return mask_text(urllib.parse.urlunsplit((u.scheme, net, u.path, q, u.fragment)), marks)


def mask_body(body, marks):
    """-> (shown, facts): a JSON body as JSON (masked), text masked, binary in words."""
    if body is None:
        return None, {}
    if isinstance(body, (dict, list)):
        return mask_json(body, marks), {'size': len(json.dumps(body))}
    if isinstance(body, str):
        body = body.encode('utf-8')
    facts = {'size': len(body)}
    try:
        t = body.decode('utf-8')
    except UnicodeDecodeError:
        return None, dict(facts, format='binary')
    if t[:1] in ('{', '['):
        try:
            return mask_json(json.loads(t), marks), facts
        except ValueError:
            pass
    if re.match(r'^[\w.%+-]+=[^&\s]*(&[\w.%+-]+=[^&\s]*)*$', t.strip()):
        import urllib.parse
        pairs = urllib.parse.parse_qsl(t.strip(), keep_blank_values=True)
        return mask_json(dict(pairs), marks), dict(facts, format='form')
    if len(t) > 12000:
        t = t[:12000] + '\n…'
    return mask_text(t, marks), facts


# ---------------------------------------------------------------------------
# The Context that does nothing
# ---------------------------------------------------------------------------
LOGIN_RE = re.compile(r'(login|logon|signin|sign-in|auth|token|session|oauth)', re.I)


class Answers(object):
    """What the recording answers an HTTP call: a module's hints first, else 200 and
    {} (a sign-in: a session in every shape a module may look for)."""
    def __init__(self, rules):
        self.rules = rules or []

    def __call__(self, method, url):
        for r in self.rules:
            if r.get('method') and r['method'] != method:
                continue
            if r.get('url') and not re.search(r['url'], url):
                continue
            body = r.get('body', {})
            if isinstance(body, (dict, list)):
                import urllib.parse
                tail = urllib.parse.unquote(url.split('?', 1)[0].rstrip('/').rsplit('/', 1)[-1])
                body = json.dumps(body).replace('{SESSION}', SESSION).replace(
                    '{TAIL}', tail.replace('"', ''))
            return int(r.get('status', 200)), dict(r.get('headers') or {}), \
                str(body).encode('utf-8')
        path = url.split('?', 1)[0]
        h = {'Content-Type': 'application/json',
             'Set-Cookie': 'NITRO_AUTH_TOKEN=%s; sessionid=%s; path=/' % (SESSION, SESSION),
             'X-Auth-Token': SESSION, 'X-Subject-Token': SESSION}
        if method == 'POST' and LOGIN_RE.search(path):
            body = {'sessionid': SESSION, 'token': SESSION, 'access_token': SESSION,
                    'session': SESSION, 'sid': SESSION, 'jwt': SESSION, 'success': True,
                    'data': {'token': SESSION, 'access_token': SESSION}}
            return 200, h, json.dumps(body).encode()
        return 200, h, b'{}'


class FakeSsh(object):
    def __init__(self, ctx, conn):
        self.ctx = ctx
        self.conn = dict(conn or {})
        self.host = str(self.conn.get('host') or '').strip('[]')
        self.port = int(self.conn.get('port') or 22)
        self.user = str(self.conn.get('user') or 'root')
        auth = 'key' if self.conn.get('key') else ('password' if self.conn.get('password')
                                                   else 'none')
        hk = str(self.conn.get('hostkey') or '').strip()
        prints = []
        if hk:
            try:
                from acmelib.certs import runtime
                prints = [runtime.hostkey_fingerprint(x) for x in runtime.hostkey_lines(hk)]
            except Exception:                           # noqa: BLE001
                prints = []
        rec({'kind': 'ssh-open', 'host': self.host, 'port': self.port, 'user': self.user,
             'auth': auth, 'hostkey': prints,
             'trust_first': bool(self.conn.get('trust_first'))})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def run(self, command, input=None, timeout=120, check=True):
        ev = {'kind': 'ssh-run', 'host': self.host, 'command': str(command)}
        if input:
            f = blob_facts(input)
            ev['input'] = {'size': f['size'], 'format': f.get('format'),
                           'secret': bool(f.get('secret')) or 'sudo -S' in str(command)}
        rec(ev)
        if 'http_code' in str(command):
            return 0, '{}\n200', ''
        return 0, '', ''

    def put(self, data, remote_path, mode=0o600, owner=None, via='shell'):
        ev = dict({'kind': 'ssh-put', 'host': self.host, 'path': str(remote_path),
                   'mode': '%o' % int(mode) if mode is not None else None,
                   'owner': owner or None, 'via': via}, **blob_facts(data))
        rec(ev)

    def get(self, remote_path):
        rec({'kind': 'ssh-get', 'host': self.host, 'path': str(remote_path)})
        return b''

    def close(self):
        pass


class PlanContext(object):
    """A Context (acmelib/plugins/base.py) that answers and does nothing."""
    def __init__(self, job, scope, answers):
        self.job = None
        self.store = None
        self.scope = scope
        self.node = job.get('node') or 'acme'
        self.settings = dict(job.get('settings') or {})
        self.answers = answers
        self.record_names, self.tokens, self.children = [], [], []
        self.deploy_id = job.get('deploy_id')
        self.target_name = job.get('target_name')
        self._kv = {}

    def step(self, words, level='info'):
        rec({'kind': 'say', 'words': str(words)[:600], 'level': level})

    def debug(self, words):
        pass

    def cancelled(self):
        return False

    def cancel(self):
        pass

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True,
             ca_pem=None, client_cert=None, proxy=True):
        from acmelib.plugins import base
        method = str(method or 'GET').upper()
        if not re.match(r'^https?://', str(url or '')):
            raise base.PluginError('%r is not an http(s) address' % url, retry=False)
        h = dict(headers or {})
        if isinstance(body, (dict, list)):
            h.setdefault('Content-Type', 'application/json')
        st, hd, raw = self.answers(method, str(url))
        rec({'kind': 'http', 'method': method, 'url': str(url), 'headers': h, 'body': body,
             'verify': bool(verify), 'ca': bool(ca_pem), 'client_cert': bool(client_cert),
             'proxy': bool(proxy), 'answer': st})
        return st, hd, raw

    def ssh(self, conn):
        return FakeSsh(self, conn)

    def openssl(self, args, data=None, timeout=60):
        from acmelib.certs import pki
        from acmelib.plugins import base
        try:
            return pki.openssl(list(args), data, timeout)
        except Exception as e:                          # noqa: BLE001
            raise base.PluginError('openssl: %s' % e, retry=False)

    def run_local(self, argv, timeout=120, env=None, cwd=None):
        rec({'kind': 'command', 'argv': [str(x) for x in argv][:60],
             'env': sorted(k for k in (env or {}) if k.startswith('ACME_')), 'cwd': cwd})
        return 0, b'', b''

    def kv_get(self, key, default=None):
        return self._kv.get(str(key), default)

    def kv_set(self, key, value, ttl_s=None):
        self._kv[str(key)] = value

    def seal(self, text, bind):
        return text

    def unseal(self, value, bind):
        return value

    def dns_put(self, name, type, value, ttl=60):
        rec({'kind': 'own-dns', 'name': str(name).rstrip('.').lower(),
             'type': str(type or 'TXT').upper(), 'value': str(value), 'ttl': ttl})

    def dns_drop(self, name, type, value=None):
        rec({'kind': 'own-dns-drop', 'name': str(name).rstrip('.').lower(),
             'type': str(type or 'TXT').upper()})

    def http_token_put(self, token, key_authorization):
        rec({'kind': 'own-http', 'token': str(token)})

    def http_token_drop(self, token):
        rec({'kind': 'own-http-drop', 'token': str(token)})

    def http_file_put(self, host, path, content, ttl_s=None):
        rec({'kind': 'own-file', 'host': str(host), 'path': str(path)})

    def http_file_drop(self, host, path):
        rec({'kind': 'own-file-drop', 'host': str(host), 'path': str(path)})

    def dns_server_info(self):
        return dict(self.settings.get('_dns_server') or {'on': False, 'zones': []})

    def own_addresses(self):
        return {'vip': None, 'nodes': []}

    def port_open(self, proto, port):
        return None

    def http_probe(self):
        return None

    def acme_sources(self, names=None):
        return []

    def validation(self, name):
        return None

    def tidy(self):
        pass

    def pages_where(self):
        return {'node': self.node, 'nodes': [self.node], 'cluster': False,
                'vip': {'on': False, 'fqdn': '', 'address': ''}}

    def pages_get(self, where):
        return None

    def pages_put(self, where, cert_pem, key_pem, chain_pems=None, how='', alt=None):
        rec({'kind': 'pages', 'where': str(where), 'alt': bool(alt)})
        return {'cn': '', 'not_after': None, 'fingerprint': '', 'verify': '', 'alt': bool(alt)}

    def push_identity(self):
        return {'seed': b'\0' * 32, 'public': 'PLAN', 'id': 'acme-plan', 'text': 'acme-plan'}

    def push_pin(self, url, pin=None):
        return None


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------
class Alarm(BaseException):
    pass


def _alarm(*_a):
    raise Alarm()


def dummy_bundle(cert):
    """A certificate of the same names and key type, made for this run (and its twin)."""
    from acmelib.certs import bundle as B
    from acmelib.certs import pki
    names = list(cert.get('names') or ['example.invalid'])

    def one(kt):
        key = pki.make_key(kt or 'ec-256')
        pem = pki.self_signed(key, names, days=90)
        chain = list(cert.get('chain') or [])
        if not chain:
            ckey = pki.make_key('ec-256')
            chain = [pki.self_signed(ckey, [], subject={'CN': 'Plan Intermediate CA'},
                                     days=365, is_ca=True)]
        b = B.CertBundle(cert.get('name') or names[0], pem, key, chain, names=names)
        for k in ('serial', 'not_before', 'not_after'):
            if cert.get(k):
                setattr(b, k, cert[k])
        b.version = int(cert.get('version') or 1)
        return b
    b = one(cert.get('key_type'))
    if cert.get('key_type_alt'):
        b.alt = one(cert['key_type_alt'])
        b.alt.variant_name = 'alt'
    return b


def module(family, kind):
    from acmelib.plugins import base
    return base.REGISTRY.get(family, kind)


def run_one(job, r, bundle_holder):
    events = []
    RECORDING[0] = events
    err = None
    said = None
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(int(r.get('seconds') or 8))
    try:
        cls = module(r['family'], r['kind'])
        ctx = PlanContext(dict(job, deploy_id=r.get('deploy_id'), target_name=r.get('name')),
                          '%s:%s' % (r['family'], r.get('name')), Answers(r.get('answers')))
        inst = cls(dict(r.get('config') or {}), ctx)
        op = r.get('op')
        if op == 'deploy':
            if bundle_holder[0] is None:
                RECORDING[0] = None
                bundle_holder[0] = dummy_bundle(job.get('cert') or {})
                RECORDING[0] = events
            b = bundle_holder[0]
            if b.alt is not None and not getattr(cls, 'dual', False):
                from acmelib.certs.deployer import pick_variant
                b = pick_variant(b, r.get('options') or {}, cls)
            opts = dict(r.get('options') or {})
            if callable(getattr(inst, 'preview', None)):
                RECORDING[0] = None
                try:
                    pv = inst.preview(b, dict(opts))
                    sc = pv.get('script') if isinstance(pv.get('script'), dict) else None
                    if sc and opts.get('script_body') and sc.get('mode') == 'inline':
                        sc = dict(sc, body=mask_text(str(opts.get('script_body'))[:20000],
                                                     r.get('marks')))
                    events.append({'kind': 'preview', 'files': [
                        {k: f.get(k) for k in ('path', 'full', 'format', 'title', 'mode',
                                               'owner', 'size', 'exact', 'key', 'variant')
                         if k in f}
                        for f in (pv.get('files') or [])][:40],
                        'env': sorted((pv.get('env') or {}).keys())[:60], 'script': sc})
                except Exception:                       # noqa: BLE001
                    pass
                RECORDING[0] = events
            said = inst.deploy(b, opts)
            rec({'kind': 'phase', 'what': 'verify'})
            try:
                inst.verify(b, opts)
            except Exception:                           # noqa: BLE001
                pass
        elif op == 'challenge':
            name = r.get('names', ['example.invalid'])[0]
            handle = inst.present(name, TOKEN, KEYAUTH, TXT)
            rec({'kind': 'phase', 'what': 'ready'})
            try:
                inst.ready(name, handle)
            except Exception as e:                      # noqa: BLE001
                rec({'kind': 'phase', 'what': 'ready-stopped', 'why': str(e)[:300]})
            rec({'kind': 'phase', 'what': 'cleanup'})
            inst.cleanup(name, handle)
        elif op == 'issue':
            from acmelib.certs import pki
            from acmelib.plugins import base
            cert = job.get('cert') or {}
            names = list(cert.get('names') or ['example.invalid'])
            RECORDING[0] = None
            key = pki.make_key(cert.get('key_type') or 'ec-256')
            csr_pem, csr_der = pki.make_csr(key, names)
            RECORDING[0] = events
            req = base.CertRequest(names=names, sans=names, key_type=cert.get('key_type'),
                                   key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                   subject={}, days=cert.get('days'), profile={},
                                   challenges={}, previous=None, cert_id=cert.get('id'))
            got = inst.issue(req)
            said = 'issued' if got else None
    except Alarm:
        err = 'it took too long (it was stopped after %s s)' % (r.get('seconds') or 8)
    except Exception as e:                              # noqa: BLE001
        err = '%s' % e if e.__class__.__name__ in ('PluginError', 'PkiError') or \
            isinstance(e, Blocked) else '%s: %s' % (type(e).__name__, e)
        if os.environ.get('ACME_PLAN_TRACE'):
            err += '\n' + traceback.format_exc()
    finally:
        signal.alarm(0)
        RECORDING[0] = None
    marks = r.get('marks') or {}
    return {'events': [clean(ev, marks) for ev in events], 'error': mask_text(err, marks)
            if err else None, 'said': mask_text(said, marks) if isinstance(said, str) else None}


def clean(ev, marks):
    """An event as it leaves: every secret masked."""
    ev = dict(ev)
    k = ev.get('kind')
    if k == 'http':
        ev['url'] = mask_url(ev['url'], marks)
        ev['headers'] = {hk: ('••••' if SECRET_HEADER.search(str(hk))
                              and str(hk).lower() not in ('content-type', 'accept')
                              else mask_text(hv, marks)) for hk, hv in ev['headers'].items()}
        body, facts = mask_body(ev.get('body'), marks)
        ev['body'] = body
        ev['body_facts'] = facts
    elif k in ('ssh-run',):
        ev['command'] = mask_text(ev['command'], marks)
    elif k in ('ssh-put', 'file'):
        if ev.get('body') is not None:
            ev['body'] = mask_text(ev['body'], marks)
    elif k == 'command':
        ev['argv'] = [mask_text(a, marks) for a in ev.get('argv') or []]
    elif k == 'say':
        ev['words'] = mask_text(ev['words'], marks)
    elif k in ('dns-ask', 'dns-update'):
        ev = mask_json(ev, marks)
    for key in ('path', 'host'):
        if isinstance(ev.get(key), str):
            ev[key] = mask_text(ev[key], marks)
    return ev


def _patch_modules(job):
    """What reaches out is written down: DNS questions, TLS handshakes, the resolvers."""
    from acmelib.plugins.challenges import _dns as D
    from acmelib.plugins.targets import _common as TC
    res = job.get('resolvers') or {}

    def exchange(server, wire, port=53, timeout=3.0, tcp=False):
        try:
            q = D.parse(wire)
            op = (q.flags >> 11) & 0xF
            if op == D.OP_UPDATE:
                rec({'kind': 'dns-update', 'server': '%s:%s' % (server, port),
                     'zone': D.norm(q.question[0][0]) if q.question else '',
                     'records': [{'name': D.norm(x.name), 'type': D.type_name(x.rtype),
                                  'value': x.text if x.rclass != D.CLASS_ANY else None,
                                  'delete': x.rclass in (D.CLASS_ANY, D.CLASS_NONE),
                                  'ttl': x.ttl} for x in q.authority],
                     'tsig': bool(q.additional and q.additional[-1].rtype == 250)})
            else:
                for n, t, _c in q.question:
                    rec({'kind': 'dns-ask', 'server': str(server), 'port': port,
                         'name': D.norm(n), 'qtype': D.type_name(t)})
        except Exception:                               # noqa: BLE001
            pass
        raise D.DnsError('the run plan asks no DNS server')
    D.exchange = exchange
    D.send_udp = _no_net
    D.send_tcp = _no_net

    def resolver(purpose, given=(), ctx=None):
        given = [str(x).strip() for x in (given or []) if str(x).strip()]
        return given or list(res.get(purpose) or res.get('validation') or ['127.0.0.1'])
    D.resolver = resolver
    D.system_resolvers = lambda: list(res.get('system') or ['127.0.0.1'])

    def served_der(host, port, sni=None, timeout=10, only=None):
        rec({'kind': 'check', 'host': str(host), 'port': int(port), 'sni': sni or '',
             'only': only or ''})
        raise OSError('the run plan makes no handshake')
    TC.served_der = served_der
    try:
        from acmelib.certs import dnssets
        dnssets.for_module = resolver
        dnssets.ssh_address = lambda ctx, host: str(host or '').strip('[]')
    except Exception:                                   # noqa: BLE001
        pass


def main():
    raw = sys.stdin.buffer.read()
    job = json.loads(raw.decode('utf-8'))
    folder = os.environ.get('TMPDIR') or job.get('folder')
    lockdown(folder)
    sys.path.insert(0, job['root'])
    from acmelib.plugins import base
    base.REGISTRY.dirs = base.REGISTRY.dirs[:1] + [d for d in job.get('plugin_dirs') or []]
    base.REGISTRY.reload()
    _patch_modules(job)
    out = {}
    holder = [None]
    for r in job.get('runs') or []:
        got = run_one(job, r, holder)
        if r.get('op') == 'deploy' and r.get('later_answers') is not None:
            later = dict(r, answers=r['later_answers'])
            got['later'] = run_one(job, later, holder)['events']
        out[r['id']] = got
    sys.stdout.write(json.dumps({'runs': out}, default=str))
    sys.stdout.flush()


if __name__ == '__main__':
    main()
