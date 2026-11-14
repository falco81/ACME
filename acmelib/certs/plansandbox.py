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
ANSWERS = [None]                # the run's Answers - what a call around ctx is answered too
SENT_NEW = [False]              # the run's certificate has been sent to the device (served_der)
SESSION = 'PLANSESSION0token'   # what a sign-in is answered with
TOKEN = 'PLAN-TOKEN-from-the-CA-0000000000'   # an ACME token (8+ of [A-Za-z0-9_-])
TXT = 'PLANTXTvalueComputedFromTheToken0000000000a'  # 43 characters, base64url
KEYAUTH = TOKEN + '.PLANthumbprintOfTheAccountKey00000000000000'
SAFE_OPENSSL = {'genpkey', 'req', 'x509', 'pkcs12', 'pkey', 'pkcs8', 'rsa', 'ec', 'ecparam',
                'genrsa', 'pkcs7', 'crl2pkcs7', 'dgst', 'asn1parse', 'base64', 'enc',
                'pkeyutl', 'version', 'list', 'rand', 'crl', 'verify', 'storeutl', 'kdf',
                'mac', 'sha256', 'sha1', 'md5', 'cms'}       # cms: files only (SCEP)
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
def note_sent(data):
    """Whether `data` (sent to the device: a body, an upload, an SSH input, a file) carries the
    certificate deployed - its DER, its base64 (PEM), or a binary bundle (PKCS#12, a keystore,
    DER) of some size: from then on the stand-in device serves the new certificate
    (served_der, 1.0.98)."""
    if SENT_NEW[0] or data is None:
        return
    ans = ANSWERS[0]
    b = getattr(ans, 'bundle', None)
    if b is None:
        return
    try:
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        if isinstance(data, str):
            data = data.encode('utf-8', 'replace')
        data = bytes(data)
        marks = getattr(ans, '_new_marks', None)
        if marks is None:
            import base64
            from acmelib.plugins.targets import _common as C
            marks = []
            for v in C.variants_of(b):
                der = C.pem_to_der(v.cert_pem)
                # within the first line of the PEM (64 characters): the same in a PEM (its
                # line ends written any way) and in the DER's base64 on one line
                marks += [der[40:80], base64.b64encode(der)[12:64]]
            ans._new_marks = marks
        if any(m and m in data for m in marks):
            SENT_NEW[0] = True
            return
        if len(data) >= 600:
            try:
                t = data.decode('utf-8')
            except UnicodeDecodeError:
                SENT_NEW[0] = True          # a PKCS#12, a keystore, DER: the certificate in it
                return
            import base64
            for m in re.finditer(r'[A-Za-z0-9+/]{800,}={0,2}', t):
                try:                        # ... or such a one in base64 (in JSON, XML)
                    base64.b64decode(m.group(0) + '=' * (-len(m.group(0)) % 4)).decode('utf-8')
                except UnicodeDecodeError:
                    SENT_NEW[0] = True
                    return
                except ValueError:
                    continue
    except Exception:                                   # noqa: BLE001
        pass


def bypass(how, what):
    """A module went around acme's connection layer (ctx.http, ctx.ssh, ctx.run_local...):
    written down as such - What happens shows it as an error step - and refused."""
    rec({'kind': 'bypass', 'how': str(how), 'what': str(what)[:600]})


def _no_net(*_a, **_k):
    raise Blocked('the run plan contacts nothing')


def _lookup_said(name):
    def fn(*a, **_k):
        if RECORDING[0] is not None:
            bypass('dns', '%s(%s)' % (name, ', '.join(repr(x) for x in a[:2])))
        raise Blocked('the run plan contacts nothing')
    return fn


def _net_said(how):
    """A connection a module opens itself (1.0.37) - not through the Context: where to is
    written down (and what it sends to an address, UDP: SNMP, syslog, its own DNS),
    then refused as any other."""
    def fn(*a, **k):
        addr = next((x for x in a if isinstance(x, tuple) and len(x) >= 2), None)
        data = next((x for x in a if isinstance(x, (bytes, bytearray))), None)
        if addr is not None:
            ev = {'kind': 'socket', 'how': how, 'host': str(addr[0]), 'port': int(addr[1] or 0)}
            if data is not None:
                ev['bytes'] = len(data)
                ev['hex'] = bytes(data[:512]).hex()
            rec(ev)
            bypass('udp' if how == 'udp' else 'socket', '%s %s:%s' % (
                'UDP' if how == 'udp' else 'TCP', addr[0], addr[1]))
        raise Blocked('the run plan contacts nothing')
    return fn


# ---- HTTP a module makes itself (http.client, urllib): written down as ctx.http is -----
class _FakeResponse(object):
    def __init__(self, status=200, body=b'{}', ctype='application/json'):
        import email.message
        self.status = self.code = status
        self.reason = 'OK'
        self.msg = self.headers = email.message.Message()
        self.headers['Content-Type'] = ctype
        self.headers['Content-Length'] = str(len(body))
        self._buf = io.BytesIO(body)
        self.will_close = True
        self.length = len(body)
        self.fp = self._buf
        self.url = ''
        self.closed = False

    def read(self, n=-1):
        return self._buf.read() if n is None or n < 0 else self._buf.read(n)

    def readline(self, *a):
        return self._buf.readline(*a)

    def readinto(self, b):
        return self._buf.readinto(b)

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def getheaders(self):
        return list(self.headers.items())

    def info(self):
        return self.headers

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status

    def close(self):
        self.closed = True

    def isclosed(self):
        return self.closed

    def __iter__(self):
        return iter(self._buf)

    def __enter__(self):
        return self

    def __exit__(self, *e):
        self.close()


def _patch_http_client():
    import http.client as HC
    import ssl as _ssl

    def request(self, method, url, body=None, headers=None, *, encode_chunked=False):
        tls = isinstance(self, HC.HTTPSConnection)
        dflt = 443 if tls else 80
        # through a proxy (CONNECT): the host it tunnels to is the one asked
        host, port = self.host, self.port
        proxied = bool(getattr(self, '_tunnel_host', None))
        if proxied:
            host, port = self._tunnel_host, self._tunnel_port or dflt
        full = url if re.match(r'^https?://', str(url)) else '%s://%s%s%s' % (
            'https' if tls else 'http', host, '' if port in (None, dflt) else
            ':%s' % port, url)
        ctx = getattr(self, '_context', None)
        verify = True
        if tls and ctx is not None:
            verify = ctx.verify_mode != _ssl.CERT_NONE
        b = body
        if isinstance(b, (bytes, bytearray)):
            b = bytes(b).decode('utf-8', 'replace')
        elif b is not None and not isinstance(b, str):
            b = '‹a stream›'
        bypass('http.client', '%s %s' % (str(method).upper(), full))
        ev = {'kind': 'http', 'method': str(method).upper(), 'url': full,
              'headers': {str(k): str(v) for k, v in dict(headers or {}).items()},
              'body': b, 'verify': verify, 'ca': False, 'client_cert': False,
              'proxy': proxied, 'proxy_own': proxied, 'own': True,
              'timeout': getattr(self, 'timeout', None)
              if isinstance(getattr(self, 'timeout', None), (int, float)) else None}
        # answered as ctx.http would be (the module's answers), a stand-in else
        ans = ANSWERS[0]
        if ans is not None:
            note_sent(body)
            st, hd, raw = ans(str(method).upper(), full, body)
            hd = dict(hd or {})
            r = _FakeResponse(st, raw, hd.get('Content-Type') or 'application/json')
            for hk, hv in hd.items():
                if hk.lower() not in ('content-type', 'content-length'):
                    r.headers[hk] = hv
            ev.update(answer=st, answer_headers=hd, answer_body=raw)
            if getattr(ans, 'fell', None):
                ev['fallback'] = ans.fell
        else:
            r = _FakeResponse()
            ev.update(answer=200, fallback='empty')
        rec(ev)
        self._acme_answer = r

    def getresponse(self):
        r = getattr(self, '_acme_answer', None) or _FakeResponse()
        self._acme_answer = None
        return r

    def connect(self):
        # putrequest/endheaders of its own (1.0.101): refused, but not written down as going
        # around acme's connection layer
        if RECORDING[0] is not None:
            tls = isinstance(self, HC.HTTPSConnection)
            host = getattr(self, '_tunnel_host', None) or self.host
            port = getattr(self, '_tunnel_port', None) or self.port or (443 if tls else 80)
            bypass('http.client', 'a connection to %s://%s:%s' % ('https' if tls else 'http',
                                                                  host, port))
        raise Blocked('the run plan contacts nothing')
    HC.HTTPConnection.request = request
    HC.HTTPConnection.getresponse = getresponse
    HC.HTTPConnection.connect = connect


# ---- FTP / FTPS a module speaks itself (ftplib): every command written down ----------
def _patch_ftplib():
    import ftplib as F

    def connect(self, host='', port=0, timeout=-999, source_address=None):
        self.host = host or getattr(self, 'host', '')
        self.port = port or 21
        rec({'kind': 'ftp-open', 'host': str(self.host), 'port': int(self.port),
             'tls': isinstance(self, F.FTP_TLS),
             'verify': (getattr(self, 'context', None) is None or
                        getattr(self.context, 'verify_mode', 2) != 0)})
        self.welcome = '220 ‹the server\'s greeting›'
        self.sock = None
        return self.welcome

    def sendcmd(self, cmd):
        shown = 'PASS ••••' if str(cmd).upper().startswith('PASS ') else str(cmd)
        rec({'kind': 'ftp-cmd', 'host': str(getattr(self, 'host', '')), 'cmd': shown})
        up = str(cmd).upper()
        if up.startswith('USER'):
            return '331 ‹password required›'
        if up.startswith('PASS'):
            return '230 ‹logged in›'
        if up.startswith('MKD'):
            return '257 "%s"' % str(cmd)[4:]
        if up.startswith('AUTH'):
            return '234 ‹AUTH TLS ok›'
        if up.startswith('QUIT'):
            return '221 ‹bye›'
        if up.startswith('PWD'):
            return '257 "/"'
        return '200 ‹ok›'

    def voidcmd(self, cmd):
        return sendcmd(self, cmd)

    def auth(self):
        resp = sendcmd(self, 'AUTH TLS')
        return resp

    def storbinary(self, cmd, fp, blocksize=8192, callback=None, rest=None):
        data = fp.read() if hasattr(fp, 'read') else b''
        note_sent(data)
        f = blob_facts(data or b'')
        rec({'kind': 'ftp-put', 'host': str(getattr(self, 'host', '')), 'cmd': str(cmd),
             'bytes': len(data or b''), 'format': f.get('format'), 'sha256': f.get('sha256'),
             'secret': bool(f.get('secret'))})
        return '226 ‹transfer complete›'

    def storlines(self, cmd, fp, callback=None):
        return storbinary(self, cmd, fp)

    def retrbinary(self, cmd, callback, blocksize=8192, rest=None):
        rec({'kind': 'ftp-cmd', 'host': str(getattr(self, 'host', '')), 'cmd': str(cmd)})
        return '226 ‹transfer complete›'

    def close(self):
        self.sock = None
    F.FTP.connect = connect
    F.FTP.sendcmd = sendcmd
    F.FTP.voidcmd = voidcmd
    F.FTP.storbinary = storbinary
    F.FTP.storlines = storlines
    F.FTP.retrbinary = retrbinary
    F.FTP.close = close
    F.FTP_TLS.auth = auth
    F.FTP_TLS.prot_p = lambda self: (sendcmd(self, 'PBSZ 0'), sendcmd(self, 'PROT P'))[1]


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
            note_sent(self.getvalue())
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
        note_sent(data)
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
    bypass('program', ' '.join(os.fsdecode(x) for x in argv[:60]))
    raise Blocked('the run plan runs no program: %s' % exe)


def _forbid(*_a, **_k):
    raise Blocked('the run plan runs no program')


def _forbid_said(name):
    def fn(*a, **_k):
        if RECORDING[0] is not None:
            bypass('program', '%s(%s)' % (name, ', '.join(repr(x)[:200] for x in a[:3])))
        raise Blocked('the run plan runs no program')
    return fn


def _mk_temp(real):
    def fn(*a, **k):
        d = k.get('dir')
        if d is None or not _inside(d):
            k['dir'] = SANDBOX[0]
        return real(*a, **k)
    return fn


CLOCK = [0.0]


# where a sleep is not the module's own wait: the standard library's polling (subprocess
# waiting for openssl making a PKCS#12, a thread joined) - slept for real, a moment, and
# neither recorded nor put on the clock
_STDLIB_SLEEPERS = ('subprocess', 'threading', 'selectors', 'multiprocessing', 'asyncio',
                    'concurrent', 'queue', 'socketserver')


def _sleep(s):
    try:
        s = max(0.0, float(s))
    except (TypeError, ValueError):
        s = 0.0
    try:
        caller = str(sys._getframe(1).f_globals.get('__name__') or '')
    except ValueError:
        caller = ''
    if caller.split('.', 1)[0] in _STDLIB_SLEEPERS:
        _real.get('sleep', lambda _s: None)(min(s, 0.05))
        return
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
    for n in ('bind', 'listen'):
        setattr(socket.socket, n, _no_net)
    socket.socket.connect = _net_said('tcp')
    socket.socket.connect_ex = _net_said('tcp')
    socket.socket.sendto = _net_said('udp')
    socket.socket.sendmsg = _net_said('udp')
    for n in ('getaddrinfo', 'gethostbyname', 'gethostbyname_ex',
              'gethostbyaddr', 'create_server', 'socketpair', 'fromfd'):
        setattr(socket, n, _lookup_said(n) if n.startswith(('get',)) else _no_net)
    socket.getfqdn = _lookup_said('getfqdn')
    socket.create_connection = _net_said('tcp')
    _patch_http_client()
    _patch_ftplib()
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
            setattr(os, n, _forbid_said('os.' + n))
    _real['Popen.__init__'] = subprocess.Popen.__init__
    subprocess.Popen.__init__ = _popen_init
    shutil.rmtree = _guarded_rmtree(shutil.rmtree)
    tempfile.mkdtemp = _mk_temp(tempfile.mkdtemp)
    tempfile.mkstemp = _mk_temp(tempfile.mkstemp)
    tempfile.tempdir = SANDBOX[0]
    _real['time'] = time.time
    _real['monotonic'] = time.monotonic
    _real['sleep'] = time.sleep
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
    import hashlib
    out = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
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
# a name whose value is a secret wherever it stands - a JSON key, a form field, a query
# parameter, a multipart part (1.0.98: one rule for all of them; runtime.SECRET_PARAM's
# words too: key, sig, code)
SECRET_NAME = re.compile(r'(pass|secret|token|apikey|api_key|api-key|private|passphrase|'
                         r'credential|signature|hmac|session|cookie|auth(?!or(?!i[sz]))|'
                         r'(^|[_.-])pin$|^pin([_.-]|$)|'
                         r'(^|[_.-])key$|^key(pem|data|file|_pem|_data)?$|privkey|'
                         r'^sid$|_sid$|^sig$|assertion$)', re.I)
NOT_SECRET_NAME = re.compile(r'^(public[_-]?key|authorizations|key[_-]?(type|size|usage|length|alg|algorithm|'
                             r'id|name|spec)|auth[_-]?(type|method|mode|scheme|source|login[_-]?domain|domain|provider)|'
                             r'token[_-]?(type|expires?|ttl)|session[_-]?(timeout|ttl|type))$', re.I)
HEADER_SCHEMES = re.compile(r'^(Basic|Bearer|Token|Negotiate|NTLM|Digest|SSWS|ApiKey|'
                            r'Key|Splunk|GenieKey|Bot|AWS4-HMAC-SHA256|SharedKey|PVEAPIToken)\b',
                            re.I)


# what a name says ABOUT a secret is no secret (1.0.98): its last word an algorithm, a type, a
# size, a usage, a format, a name, a time... (privateKeyAlgorithm, keyType, tokenExpires,
# passwordPolicy, sessionTimeout, signatureAlgorithm), its first a yes/no (hasPassword,
# enable_syno_token, isPrivate), a public key
NOT_SECRET_LAST = {'algorithm', 'algorithms', 'algo', 'alg', 'type', 'types', 'size', 'length',
                   'len', 'bits', 'usage', 'usages', 'format', 'fmt', 'name', 'names', 'count',
                   'expires', 'expiry', 'expiration', 'expire', 'ttl', 'timeout', 'lifetime',
                   'age', 'mode', 'method', 'methods', 'scheme', 'policy', 'status', 'state',
                   'enabled', 'disabled', 'required', 'version', 'strength', 'curve', 'hash',
                   'digest', 'label', 'path', 'file', 'filename', 'location', 'store',
                   'provider', 'source', 'kind', 'class', 'level', 'url', 'uri', 'endpoint',
                   'header', 'field', 'alias', 'min', 'max', 'changed', 'set', 'exists',
                   'present', 'domain', 'realm', 'server', 'host', 'port', 'protocol',
                   'complexity', 'history', 'reset', 'rotation', 'reuse', 'storage', 'spec',
                   'flag', 'flags', 'option', 'options', 'id_type', 'login'}
NOT_SECRET_FIRST = {'is', 'has', 'enable', 'enabled', 'use', 'allow', 'require', 'show', 'no',
                    'with', 'public', 'disable', 'need', 'needs', 'can', 'should'}


def _words(n):
    n = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', n)
    n = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', n)
    return [w.lower() for w in re.split(r'[\s_.\-@:/]+', n) if w]


def secret_name(name):
    n = str(name or '').strip()
    if not n or not SECRET_NAME.search(n) or NOT_SECRET_NAME.match(n):
        return False
    w = _words(n)
    if len(w) > 1 and (w[-1] in NOT_SECRET_LAST or w[0] in NOT_SECRET_FIRST):
        return False
    return True


def header_shown(name, value, marks=None):
    """A header as What happens shows it: an Authorization / Cookie / token header as
    dots - the scheme word kept (Basic, Bearer...); a Cookie's names kept."""
    n = str(name).lower()
    v = str(value)
    if n in ('content-type', 'accept', 'content-length', 'host', 'user-agent',
             'accept-encoding', 'connection', 'content-disposition', 'keep-alive'):
        return mask_text(v, marks)
    if n in ('cookie', 'set-cookie'):
        if n == 'set-cookie':
            first, sep, rest = v.partition(';')
            k, eq, _x = first.partition('=')
            return '%s=••••%s%s' % (k.strip(), sep, rest) if eq else '••••'
        return '; '.join('%s=••••' % p.partition('=')[0].strip() if '=' in p else '••••'
                         for p in v.split(';') if p.strip())
    if SECRET_HEADER.search(n):
        m = HEADER_SCHEMES.match(v.strip())
        return ('%s ••••' % m.group(1)) if m and v.strip() != m.group(1) else '••••'
    return mask_text(v, marks)


# a secret on a command line (1.0.98): -p 'x', --password=x, -Password 'x', pass:x,
# ConvertTo-SecureString 'x', PASSWORD=x - whatever the module made it (a PFX's password
# made for the one run is no stand-in the marks know)
CMD_SECRETS = [
    (re.compile(r"((?:^|\s)-(?:p|pw|pass)\s+)('[^']*'|\"[^\"]*\")"), True),
    (re.compile(r"((?:^|\s)--?(?:password|passwd|passphrase|pass|secret|token|api-?key|"
                r"key-?pass|keypass|storepass|keystore-?password|pin)(?:\s+|=))"
                r"('[^']*'|\"[^\"]*\"|[^\s;|&()'\"]+)", re.I), True),
    (re.compile(r"((?:^|\s)-(?:Password|PlainPassword|Pin|Secret|Token|ApiKey|Passphrase|"
                r"CertificatePassword|PfxPassword|KeyPassword)(?::|\s+))"
                r"('[^']*'|\"[^\"]*\"|[^\s;|&()'\"]+)", re.I), True),
    (re.compile(r"(ConvertTo-SecureString\s+(?:-String\s+)?)('[^']*'|\"[^\"]*\")", re.I), True),
    (re.compile(r"(\bpass:)('[^']*'|\"[^\"]*\"|[^\s'\"]+)"), False),
    (re.compile(r"(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|PASSPHRASE|API_KEY)[A-Z0-9_]*=)"
                r"('[^']*'|\"[^\"]*\"|[^\s;|&'\"]+)"), False),
]


def mask_command(t, marks=None):
    """A command line (SSH, PowerShell, a program here) with its secrets as dots."""
    t = mask_text(t, marks)
    for rx, quoted in CMD_SECRETS:
        t = rx.sub(lambda m, q=quoted: m.group(0) if '••••' in m.group(2) or
                   m.group(2).strip('\'"').startswith('$') else
                   m.group(1) + ("'••••'" if q else '••••'), t)
    return t


def size_words(n):
    if n < 1024:
        return '%d B' % n
    return '%.1f kB' % (n / 1024.0)


def encoded_script(command):
    """The script of `powershell ... -EncodedCommand <base64 of UTF-16LE>`, readable -
    or '' when the command has none."""
    import base64
    m = re.search(r'-(?:EncodedCommand|enc|e|ec)\s+([A-Za-z0-9+/=]{8,})', str(command or ''),
                  re.I)
    if not m:
        return ''
    try:
        text = base64.b64decode(m.group(1)).decode('utf-16-le').replace('\r\n', '\n')
    except (ValueError, UnicodeDecodeError):
        return ''
    # A password written into the script (a PFX's, made for the one run) shown as dots too.
    text = re.sub(r"(ConvertTo-SecureString\s+(?:-String\s+)?)'[^']*'", r"\1'••••'", text,
                  flags=re.I)
    return re.sub(r"(-(?:Password|PlainPassword|Pin)\s+)'[^']*'", r"\1'••••'", text, flags=re.I)


def _is_cert_der(raw):
    """A certificate in DER (no key with it): shown as one, not dots (1.0.98)."""
    try:
        from acmelib.certs import pki
        return bool(pki.cert_info(bytes(raw)).get('serial'))
    except Exception:                                   # noqa: BLE001
        return False


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
            if raw[:1] == b'\x30' and _is_cert_der(raw):
                return '‹certificate, DER, base64, %s›' % size_words(len(raw))
            return '•••• (binary, base64, %s)' % size_words(len(raw))
        return s
    t = B64_RUN.sub(b64, t)
    if '</' in t:
        # an XML element of a secret's name (1.0.98: <Password> of a Sophos upload, the
        # PKCS#12's password made for the one run, no stand-in the marks know)
        # (<key name=".."> - a filter's, Sophos - is no key)
        t = XML_SECRET.sub(lambda m: m.group(0) if not secret_name(m.group(1)) or
                           m.group(1).lower() == 'key' or
                           m.group(3).startswith(('••••', '‹')) else
                           '<%s%s>••••</%s>' % (m.group(1), m.group(2) or '', m.group(1)), t)
    return t


XML_SECRET = re.compile(r'<([A-Za-z][\w.:-]*)(\s[^<>]*)?>([^<]+)</\1>')


def mask_json(v, marks, key=''):
    if isinstance(v, dict):
        return {k: mask_json(x, marks, str(k)) for k, x in v.items()}
    if isinstance(v, list):
        return [mask_json(x, marks, key) for x in v]
    if isinstance(v, str):
        t = mask_text(v, marks)
        # a secret's name: dots - unless what mask_text made of it says what it was in
        # dots already (a private key's PEM: "•••• (private key, PEM, ...)"); a JWT whose
        # part mask_text took for a blob is dots whole (1.0.98)
        if key and secret_name(key) and v and not v.startswith('‹') and not \
                v.startswith('••••') and not t.startswith('••••') and not key_reference(key, v):
            return '••••'
        return t
    return v


PUBLIC_VALUE = re.compile(r'^(acme-push-ed25519|ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-[a-z0-9]+|'
                          r'sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-[a-z0-9@.]+) [A-Za-z0-9+/=]+'
                          r'( [^\n]*)?$|^-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE)-----')
KEYISH_NAME = re.compile(r'(^|[_.-])key$|^key(file|_file|path|_path)?$|privkey|private_?key',
                         re.I)
PATH_VALUE = re.compile(r'^(/|[A-Za-z]:[\\/]|~/|\./|\.\./)[^\s"\'<>|]{0,400}$|'
                        r'^[\w.@-]{1,200}\.(key|pem|crt|cer|pfx|p12|der|jks)$')


def key_reference(name, value):
    """A "key" field that names where a key is (F5's certKeyChain key: /Common/acme-x.key, a
    file name) - not key material: shown (1.0.98). Only a key's name, never a password's or a
    token's; a value with a PEM, a long base64 run or no path shape stays dots."""
    v = str(value or '')
    # a public key is never a secret (acme push's acme_key: "acme-push-ed25519 BASE64 ...",
    # an SSH public key, a PEM public key or certificate) - a private key always is
    if PUBLIC_VALUE.match(v.strip()) and 'PRIVATE' not in v:
        return True
    # a yes/no is never a secret, whatever its name (Synology's enable_syno_token: "yes")
    if v.strip().lower() in ('yes', 'no', 'true', 'false', 'on', 'off', 'none', 'null', '0',
                             '1', 'enabled', 'disabled'):
        return True
    if not PATH_VALUE.match(v) or '-----' in v or re.search(r'[A-Za-z0-9+/=_-]{60,}', v):
        return False
    if KEYISH_NAME.search(str(name or '')):
        return True
    # under another secret's name only a path of folders (/etc/x/y, C:\\a\\b) or a key or
    # certificate file's name - "/abc" may be a password
    return bool(re.match(r'^(/|[A-Za-z]:[\\/]|~/|\.\.?/)[^/\\]+[/\\]', v) or
                re.search(r'\.(key|pem|crt|cer|pfx|p12|der|jks)$', v))


def mask_url(url, marks):
    import urllib.parse
    try:
        u = urllib.parse.urlsplit(str(url))
    except ValueError:
        return mask_text(url, marks)
    net = u.netloc
    if '@' in net:
        net = '••••@' + net.rsplit('@', 1)[1]
    q = '&'.join('%s=%s' % (k, '••••' if secret_name(urllib.parse.unquote(k)) and v else v)
                 if eq else k
                 for k, eq, v in (p.partition('=') for p in u.query.split('&') if p)) \
        if u.query else ''
    return placeholders_readable(
        mask_text(urllib.parse.urlunsplit((u.scheme, net, u.path, q, u.fragment)), marks))


def placeholders_readable(t):
    """A stand-in ‹like this› (and dots) a module percent-encoded into a URL, readable again:
    %E2%80%B9zone%20id%E2%80%BA -> ‹zone id› (1.0.98)."""
    import urllib.parse
    t = re.sub(r'(?i)%E2%80%B9((?:(?!%E2%80%BA).){0,300})%E2%80%BA',
               lambda m: '‹%s›' % urllib.parse.unquote_plus(m.group(1)), str(t))
    return re.sub(r'(?i)(%E2%80%A2){4}', '••••', t)


def _sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def binary_words(data):
    return '‹binary data, %s, sha256 %s›' % (size_words(len(data)), _sha(data)[:16])


def _boundary(ctype):
    m = re.search(r'boundary="?([^";]+)"?', str(ctype or ''), re.I)
    return m.group(1) if m else ''


def multipart_parts(body, ctype):
    """[{name, filename, type, size, sha256, format, value?, secret?}] of a multipart body."""
    bnd = _boundary(ctype)
    if not bnd:
        m = re.match(rb'--([^\r\n]{4,200})\r?\n', body)
        bnd = m.group(1).decode('latin-1') if m else ''
    if not bnd:
        return None
    out = []
    for chunk in body.split(b'--' + bnd.encode('latin-1'))[1:]:
        if chunk.startswith(b'--'):
            break
        chunk = chunk[2:] if chunk.startswith(b'\r\n') else chunk.lstrip(b'\n')
        head, sep, data = chunk.partition(b'\r\n\r\n')
        if not sep:
            head, sep, data = chunk.partition(b'\n\n')
        if data.endswith(b'\r\n'):
            data = data[:-2]
        elif data.endswith(b'\n'):
            data = data[:-1]
        h = head.decode('utf-8', 'replace')
        name = re.search(r'\bname="([^"]*)"', h)
        fn = re.search(r'\bfilename="([^"]*)"', h)
        ct = re.search(r'(?im)^content-type:\s*(.+)$', h)
        part = {'name': name.group(1) if name else '', 'filename': fn.group(1) if fn else None,
                'type': ct.group(1).strip() if ct else None, 'size': len(data),
                'sha256': _sha(data)}
        f = blob_facts(data)
        part['format'] = f.get('format')
        if f.get('secret'):
            part['secret'] = True
        out.append((part, data))
    return out


def multipart_text(parts, marks):
    """The parts of a multipart body, readable: each its name, file name, type, size; a
    text field's value (a secret one as dots), a PEM as a placeholder, binary as its size
    and sha256."""
    lines = []
    for part, data in parts:
        head = ['part "%s"' % part['name']]
        if part.get('filename') is not None:
            head.append('file "%s"' % part['filename'])
        if part.get('type'):
            head.append(part['type'])
        head.append(size_words(part['size']))
        lines.append('── ' + ' · '.join(head))
        try:
            t = data.decode('utf-8')
        except UnicodeDecodeError:
            t = None
        if t is None:
            lines.append(('•••• (%s)' % part['format']) if part.get('secret') and
                         part['format'] != 'binary (DER, PKCS#12 or a keystore)' else
                         binary_words(data))
        elif secret_name(part['name']) and t and part.get('filename') is None and \
                '-----BEGIN' not in t:
            lines.append('••••')
        else:
            t = mask_text(t, marks)
            lines.append(t if len(t) <= 4000 else t[:4000] + '\n…')
    return '\n'.join(lines)


def mask_body(body, marks, ctype=None):
    """-> (shown, facts): a JSON body as JSON (masked), form fields as fields (masked), a
    multipart body its parts (file names, types, sizes), text masked, binary as its size
    and sha256."""
    if body is None:
        return None, {}
    if isinstance(body, (dict, list)):
        return mask_json(body, marks), {'size': len(json.dumps(body)), 'format': 'json'}
    if isinstance(body, str):
        body = body.encode('utf-8')
    body = bytes(body)
    facts = {'size': len(body)}
    if 'multipart/' in str(ctype or '').lower() or re.match(rb'--[^\r\n]{4,200}\r?\n'
                                                           rb'Content-Disposition', body):
        parts = multipart_parts(body, ctype)
        if parts is not None:
            return multipart_text(parts, marks), dict(
                facts, format='multipart', parts=[p for p, _d in parts])
    try:
        t = body.decode('utf-8')
    except UnicodeDecodeError:
        return binary_words(body), dict(facts, format='binary', sha256=_sha(body))
    if t[:1] in ('{', '['):
        try:
            return mask_json(json.loads(t), marks), dict(facts, format='json')
        except ValueError:
            pass
    if re.match(r'^[\w.%+\[\]-]+=[^&\s]*(&[\w.%+\[\]-]+=[^&\s]*)*$', t.strip()):
        import urllib.parse
        pairs = urllib.parse.parse_qsl(t.strip(), keep_blank_values=True)
        return mask_json(dict(pairs), marks), dict(facts, format='form')
    if len(t) > 12000:
        t = t[:12000] + '\n…'
    fmt = 'xml' if t.lstrip()[:1] == '<' else 'text'
    return mask_text(t, marks), dict(facts, format=fmt)


def _b64u_json(s):
    import base64
    s = str(s or '')
    if not s:
        return ''
    raw = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    return json.loads(raw.decode('utf-8'))


def _jws_parts(d):
    """A flattened JWS (protected, payload, signature) decoded -> dict, or None."""
    if not isinstance(d, dict) or not {'protected', 'payload', 'signature'} <= set(d):
        return None
    try:
        prot = _b64u_json(d['protected'])
        pay = _b64u_json(d['payload'])
    except Exception:                                   # noqa: BLE001
        return None
    if not isinstance(prot, dict):
        return None
    return {'protected': prot, 'payload': pay}


def jws_shown(body, marks):
    """An ACME request's JWS as people read it: the protected header (alg, nonce, url, kid
    or the account's public jwk) and the payload decoded - "" a POST-as-GET -, the CSR
    in words, an EAB inside decoded the same way; every signature dots. None: not a JWS."""
    try:
        d = json.loads(bytes(body).decode('utf-8') if isinstance(body, (bytes, bytearray))
                       else body) if not isinstance(body, dict) else body
    except Exception:                                   # noqa: BLE001
        return None
    got = _jws_parts(d)
    if got is None:
        return None

    def jwk(p):
        k = p.get('jwk') if isinstance(p, dict) else None
        if isinstance(k, dict) and isinstance(k.get('n'), str) and len(k['n']) > 40:
            # an RSA public key's modulus: public, long - its start and its size
            p['jwk'] = dict(k, n='%s… (RSA modulus, %d bits)' % (
                k['n'][:24], len(k['n'].rstrip('=')) * 6 // 8 * 8))
        return p
    prot = jwk(got['protected'])
    pay = got['payload']
    if isinstance(pay, dict):
        pay = dict(pay)
        if isinstance(pay.get('csr'), str):
            n = len(pay['csr']) * 3 // 4
            pay['csr'] = '‹the certificate request (CSR), DER, base64url, %s›' % size_words(n)
        eab = _jws_parts(pay.get('externalAccountBinding'))
        if eab is not None:
            pay['externalAccountBinding'] = {
                'protected': eab['protected'], 'payload': '‹the account\'s public key (jwk, '
                'as in the header)›', 'signature': '•••• (HMAC-SHA256 with the EAB key)'}
        if isinstance(pay.get('certificate'), str) and len(pay['certificate']) > 60:
            pay['certificate'] = '‹the certificate, DER, base64url›'
    out = {'protected': prot, 'payload': pay, 'signature': '•••• (signature)'}
    return mask_json(out, marks)


def jws_wire(body):
    """The JWS body as sent, an EAB's signature in its payload left out (re-encoded)."""
    import base64
    try:
        d = json.loads(bytes(body).decode('utf-8') if isinstance(body, (bytes, bytearray))
                       else body) if not isinstance(body, dict) else dict(body)
        pay = _b64u_json(d.get('payload'))
        if isinstance(pay, dict) and isinstance(pay.get('externalAccountBinding'), dict):
            pay['externalAccountBinding'] = dict(pay['externalAccountBinding'],
                                                 signature='••••')
            d['payload'] = base64.urlsafe_b64encode(json.dumps(
                pay, separators=(',', ':')).encode()).decode().rstrip('=')
        return json.dumps(d).encode('utf-8')
    except Exception:                                   # noqa: BLE001
        return body


def wire_body(body, marks, ctype=None):
    """The body as it goes on the wire, its secrets out: JSON as sent (compact), form
    fields url-encoded, a multipart body its parts, binary in words."""
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return json.dumps(mask_json(body, marks), ensure_ascii=False)
    shown, facts = mask_body(body, marks, ctype)
    f = facts.get('format')
    if f == 'json':
        raw = body.decode('utf-8', 'replace') if isinstance(body, (bytes, bytearray)) else body
        # as sent: its own spacing kept when nothing in it was masked
        if json.dumps(json.loads(raw)) == json.dumps(shown):
            return mask_text(raw, marks)
        return json.dumps(shown, ensure_ascii=False)
    if f == 'form':
        import urllib.parse
        return '&'.join('%s=%s' % (urllib.parse.quote_plus(str(k)), v if str(v).startswith(
            ('••••', '‹')) else urllib.parse.quote_plus(str(v))) for k, v in shown.items())
    return shown


# ---------------------------------------------------------------------------
# The Context that does nothing
# ---------------------------------------------------------------------------
LOGIN_RE = re.compile(r'(login|logon|signin|sign-in|auth|token|session|oauth)', re.I)


class Answers(object):
    """What the recording answers an HTTP call: a module's hints first, else 200 and
    {} (a sign-in: a session in every shape a module may look for).

    A rule: {method?, url? (a regex), sent? (a regex of the body sent - Answers.sent_text: one
    API address for every call, its command in the body), status?, headers?, body, times?};
    "times": n - the rule answers its first n matching calls, then the next matching rule
    does. In a body:
    {SESSION}, {TAIL} (the last part of the path) and {SENT:key} - the value of "key"
    (dotted for a nested one) in the JSON body the module sent last with it ('' before);
    {SEEN:regex} - its first group in this request ("METHOD url\nbody") or one before.
    SSH rules (ssh()): {command (a regex), input? (a regex), script? (a regex of the PowerShell
    script run - decoded or uploaded), seen_lines?, stdout?, stderr?, exit?,
    times?} - what a command matching them printed."""
    def __init__(self, rules, ssh_rules=None):
        self.rules = rules or []
        self.ssh_rules = ssh_rules or []
        self.used = {}
        self.sent = {}
        # a device asked for its key and CSR (Target.device_csr, "the device makes the key"):
        # the CSR it answers - a throwaway one for the names. {CSR} in a rule's body, and
        # what a call no rule answers gets (as CSRString, CSR and csr), an SSH command too.
        self.csr = ''
        # the certificate deployed and the deployment's options (run_one): {EARLIER}
        self.bundle, self.options = None, {}

    EARLIER_RE = re.compile(r'\{(EARLIER\d*|CURRENT|LABEL)(?::(\d+))?(?::(\d+))?(?::([^}\d]))?\}')

    def earlier(self, text):
        """{EARLIER} / {EARLIER2} (1.0.98) in an answer: the name acme gave (object_name:
        acme-<label>-<date>-<serial>) to an earlier certificate of this one - 3 (EARLIER2: 6,
        EARLIER3: 9, EARLIERn: 3n) months older, another serial - so a device answers with the certificate
        a renewal replaces; {EARLIER:n}: of a module whose names are at most n long (63);
        {EARLIER:n:s}: with a serial of s characters (8); {EARLIER:n:s:c}: each character
        but A-Z a-z 0-9 _ - written as c (TrueNAS: _). {CURRENT...} (same arguments): the
        name this certificate gets - listed back after it was put there; {LABEL[:n]}: its
        label (_common.label_of - "acme {LABEL}" of a module). The certificate's DNS
        names: {CERTNAME} (the first), {CERTNAMES} (all, by commas; "{CERTNAMES}" in a JSON
        body: a list of them) - a device listing the certificate it holds for them. {CACN},
        {CACN2}, {CACN_}: the CA certificates of its chain (below)."""
        if self.bundle is not None and '{CERTNAME' in text:
            dns = [str(n) for n in (getattr(self.bundle, 'names', None) or [])]
            text = text.replace('"{CERTNAMES}"', json.dumps(dns)).replace(
                '{CERTNAMES}', ','.join(dns)).replace('{CERTNAME}', dns[0] if dns else '')
        if self.bundle is not None and '{FP' in text:
            # {FP} / {FP1}: the SHA-256 / SHA-1 fingerprint (hex, lower case) of the certificate
            # deployed - a device listing it by its fingerprint after the import (group 3)
            import hashlib
            from acmelib.plugins.targets import _common as C
            try:
                der = C.pem_to_der(self.bundle.cert_pem)
                text = text.replace('{FP1}', hashlib.sha1(der).hexdigest()).replace(
                    '{FP}', hashlib.sha256(der).hexdigest())
            except Exception:                           # noqa: BLE001
                pass
        if self.bundle is not None and '{CACN' in text:
            # {CACN} / {CACN2}: the common name of the first (second) CA certificate of the
            # chain deployed, {CACN_}: with what is not A-Z a-z 0-9 . - _ written as _ (a
            # file named after it) - a device's trust store holding it at a renewal; a line
            # naming a CA the chain has not is left out
            from acmelib.certs import pki
            from acmelib.plugins.targets import _common as C
            cns = []
            for pem in C.chain_list(self.bundle):
                try:
                    cns.append(str((pki.cert_info(pem).get('subject') or {}).get('CN') or ''))
                except Exception:                       # noqa: BLE001
                    cns.append('')

            def ca(m):
                i = int(m.group(1) or 1) - 1
                v = cns[i] if i < len(cns) else ''
                return re.sub(r'[^A-Za-z0-9._-]', '_', v) if m.group(2) else v
            text = '\n'.join(re.sub(r'\{CACN(\d?)(_?)\}', ca, ln) for ln in text.split('\n')
                             if all(int(x or 1) <= len(cns)
                                    for x in re.findall(r'\{CACN(\d?)_?\}', ln)))
        if self.bundle is not None and '{CAID' in text:
            # {CAID} / {CAID2}: _common.chain_id of the first (second) CA certificate of the
            # chain - the "acme-ca-<id>" a module named it when it added it before, there at a
            # renewal (1.0.98); a line naming a CA the chain has not is left out
            from acmelib.plugins.targets import _common as C
            ids = []
            for pem in C.chain_list(self.bundle):
                try:
                    ids.append(C.chain_id(pem))
                except Exception:                       # noqa: BLE001
                    ids.append('')
            text = '\n'.join(re.sub(r'\{CAID(\d?)\}', lambda m: ids[int(m.group(1) or 1) - 1],
                                    ln) for ln in text.split('\n')
                             if all(int(x or 1) <= len(ids)
                                    for x in re.findall(r'\{CAID(\d?)\}', ln)))
        if '{EARLIER' not in text and '{CURRENT' not in text and '{LABEL' not in text:
            return text

        def one(m):
            from acmelib.plugins.targets import _common as C
            if m.group(1) == 'LABEL':
                try:
                    return C.label_of(self.bundle, self.options, int(m.group(2) or 40))
                except Exception:                       # noqa: BLE001
                    return 'cert'
            # {EARLIERn} (1.0.98): n renewals back, 3 months each - EARLIER, EARLIER2, EARLIER3...
            # (a keep-N cleanup listing more certificates than it keeps)
            nth = int(m.group(1)[7:] or 1) if m.group(1).startswith('EARLIER') else 0
            back = 91 * nth
            nb = getattr(self.bundle, 'not_before', None) or time.time()
            sl = int(m.group(3) or 8)

            class B(object):
                name = getattr(self.bundle, 'name', '')
                names = list(getattr(self.bundle, 'names', None) or ['cert'])
                not_before = float(nb) - back * 86400
                serial = '5a0e1d2c3b4a5968%02x' % max(0, 0x78 - max(nth, 1))
            try:
                if getattr(self, 'namer', None) is not None and not m.group(2):
                    got = self.namer(B() if back else self.bundle, self.options)
                else:
                    got = C.object_name(B() if back else self.bundle, self.options,
                                        int(m.group(2) or 63), sl)
            except Exception:                           # noqa: BLE001
                got = 'acme-cert-%s-5a0e1d2c' % time.strftime(
                    '%Y%m%d', time.gmtime(float(nb) - back * 86400))
            if m.group(4):
                got = re.sub(r'[^A-Za-z0-9_-]', m.group(4), got)
            return got
        return self.EARLIER_RE.sub(one, text)

    # a source's and a validation's answers (1.0.98): what a CA or a DNS provider answers holds
    # the certificate issued and the names of the run - {ZONE} (the registrable domain of the
    # name validated), {NAME}, {FQDN} (_acme-challenge.NAME), {TXT} (the value put in); {CERT}
    # (PEM of the certificate issued for the request's key), {CHAIN} (PEM of its intermediate),
    # {CERT_B64} / {CHAIN_B64} (their DER in base64), {P7_B64} (a PKCS#7 of both, DER, base64),
    # {CA_P7_B64} (one of the intermediate only), {CERT_SERIAL} (its serial, hex); {ZONE_B64},
    # {FQDN_B64}, {TXT_B64}: those three in base64 (the names absolute, "name."); {KEYAUTH}:
    # the key authorization an HTTP-01 file holds; {PLACED}: what a CA's DCV put in place last
    # (the content of its file, the value of its record)
    # {EARLIER_PEM} / {EARLIER_B64}: another certificate of the deployed one's names (its own
    # key; PEM / DER in base64) - the one a device holds and lists before a renewal
    PLAN_RE = re.compile(r'\{(ZONE|NAME|FQDN|TXT|CERT|CHAIN|CERT_B64|CHAIN_B64|P7_B64|CA_P7_B64|'
                         r'CERT_SERIAL|EARLIER_PEM|EARLIER_B64|ZONE_B64|FQDN_B64|TXT_B64|'
                         r'KEYAUTH|PLACED|ALT_ROOT)\}')
    _earlier_pem = None

    def earlier_pem(self):
        if self._earlier_pem is None:
            self._earlier_pem = ''
            try:
                from acmelib.certs import pki
                names = [str(n) for n in (getattr(self.bundle, 'names', None) or
                                          ['example.invalid'])]
                with _unrecorded(RECORDING[0]):
                    self._earlier_pem = pki.self_signed(pki.make_key('ec-256'), names,
                                                        days=90).strip() + '\n'
            except Exception:                           # noqa: BLE001
                pass
        return self._earlier_pem
    vname = ''
    issued = None

    def plan_re(self, pat):
        """A rule's url / sent regex with {ZONE}, {NAME}... in it: their values, escaped."""
        if '{' not in pat or not self.PLAN_RE.search(pat):
            return pat
        return self.PLAN_RE.sub(lambda m: re.escape(self.plan_fill(m.group(0), False)), pat)

    def plan_fill(self, text, js):
        if '{' not in text or not self.PLAN_RE.search(text):
            return text
        name = str(self.vname or '').lstrip('*.')
        vals = {'NAME': name, 'FQDN': '_acme-challenge.' + name if name else '', 'TXT': TXT,
                'KEYAUTH': PLACED_KEYAUTH[0] or KEYAUTH, 'PLACED': PLACED_TXT[-1] if PLACED_TXT else ''}
        try:
            from acmelib.plugins.challenges import _dns as D
            vals['ZONE'] = D.registrable(name) if name else ''
        except Exception:                               # noqa: BLE001
            vals['ZONE'] = ''
        vals.update(self.issued or {})
        if '{EARLIER_' in text:
            pem = self.earlier_pem()
            vals['EARLIER_PEM'] = pem
            vals['EARLIER_B64'] = ''.join(l for l in pem.splitlines() if l and '-----' not in l)
        if '_B64}' in text:
            import base64                   # {ZONE_B64}...: as a cPanel zone holds them
            for k in ('ZONE', 'FQDN', 'TXT'):           # a name absolute: with its dot
                vals[k + '_B64'] = base64.b64encode((str(vals.get(k) or '') + (
                    '.' if k != 'TXT' else '')).encode()).decode()

        def one(m):
            v = str(vals.get(m.group(1), ''))
            return json.dumps(v)[1:-1] if js else v
        return self.PLAN_RE.sub(one, text)

    def _take(self, kind, i, r):
        """Whether rule i may answer once more - counted when it does."""
        n = r.get('times')
        k = (kind, i)
        if n is not None and self.used.get(k, 0) >= int(n):
            return False
        self.used[k] = self.used.get(k, 0) + 1
        return True

    def _keep_sent(self, body):
        if isinstance(body, (bytes, bytearray)):
            body = bytes(body).decode('utf-8', 'replace')
        if isinstance(body, str):
            if re.match(r'^[A-Za-z0-9_.%\[\]-]+=[^&]*(&[A-Za-z0-9_.%\[\]-]+=[^&]*)*$',
                        body.strip()):
                # a form (application/x-www-form-urlencoded): {SENT:field} too (1.0.98)
                import urllib.parse
                for k, v in urllib.parse.parse_qsl(body.strip(), keep_blank_values=True):
                    self.sent[k] = v
                return
            if body.strip()[:1] not in ('{', '['):
                return
            try:
                body = json.loads(body)
            except ValueError:
                return
        if not isinstance(body, dict):
            return

        def walk(d, pre):
            for k, v in d.items():
                if isinstance(v, dict):
                    walk(v, pre + str(k) + '.')
                elif isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    self.sent[pre + str(k)] = str(v)
        walk(body, '')

    def _sent(self, m):
        return json.dumps(self.sent.get(m.group(1), ''))[1:-1]

    @staticmethod
    def sent_text(body):
        """The body a module sent, as text a rule's "sent" (a regex) is matched against: as
        sent (bytes decoded), a dict or list as JSON (json.dumps: "key": "value")."""
        if isinstance(body, (bytes, bytearray)):
            return bytes(body).decode('utf-8', 'replace')
        if isinstance(body, (dict, list)):
            return json.dumps(body, ensure_ascii=False, default=str)
        return '' if body is None else str(body)

    def __call__(self, method, url, body=None):
        self._keep_sent(body)
        sent_body = body
        # which kind of answer the last call got: None - a rule of the module's answered;
        # 'sign-in' / 'csr' / 'empty' - no rule did, a stand-in answered (marked on the event)
        self.fell = None
        # {SEEN:regex} in a body: the first group of the regex in this request (its method,
        # address and body) or one before it - a name the module asked for, answered back
        seen = self.__dict__.setdefault('_http_seen', [])
        seen.append('%s %s\n%s' % (method, url, self.sent_text(body)))
        for i, r in enumerate(self.rules):
            if r.get('method') and r['method'] != method:
                continue
            if r.get('url') and not re.search(self.plan_re(r['url']), url):
                continue
            if r.get('sent') and not re.search(self.plan_re(r['sent']), self.sent_text(body)):
                continue
            if not self._take('http', i, r):
                continue
            body = r.get('body', {})
            if isinstance(body, (dict, list)):
                import urllib.parse
                tail = urllib.parse.unquote(url.split('?', 1)[0].rstrip('/').rsplit('/', 1)[-1])
                body = json.dumps(body).replace('{SESSION}', SESSION).replace(
                    '{TAIL}', tail.replace('"', ''))
                body = re.sub(r'\{SENT:([A-Za-z0-9_.-]+)\}', self._sent, body)
                body = body.replace('{CSR}', json.dumps(self.csr or '')[1:-1])
                body = self.earlier(body)
            elif isinstance(body, str) and ('{SENT:' in body or '{CSR}' in body):
                # a text body: JSON written as text gets the values escaped as JSON strings,
                # anything else (XML, a PEM, plain text) as they are
                # (told by the body with its placeholders taken out: one that starts with
                # {CSR} or {SENT:x} is not JSON)
                js = re.sub(r'\{[A-Z]+(?::[A-Za-z0-9_.-]+)?\}', '',
                            body).lstrip()[:1] in ('{', '[')
                body = re.sub(r'\{SENT:([A-Za-z0-9_.-]+)\}', self._sent if js else (
                    lambda m: self.sent.get(m.group(1), '')), body)
                body = body.replace('{CSR}', json.dumps(self.csr or '')[1:-1] if js
                                    else (self.csr or ''))
            if isinstance(body, str) and '{SEEN:' in body:
                js = isinstance(r.get('body'), (dict, list))

                def echo(m, js=js):
                    pat = m.group(1)
                    if js:              # the regex was written into the JSON: as it was
                        try:
                            pat = json.loads('"%s"' % pat)
                        except ValueError:
                            pass
                    for old in reversed(seen):
                        got = re.search(pat, old)
                        if got:
                            v = got.group(1) if got.groups() else got.group(0)
                            return json.dumps(v)[1:-1] if js else v
                    return ''
                body = fill_seen(body, echo)
            if isinstance(body, str):
                body = self.earlier(body)
                body = self.plan_fill(body, isinstance(r.get('body'), (dict, list)) or re.sub(
                    r'\{[A-Z_0-9]+(?::[^}]*)?\}', '', body).lstrip()[:1] in ('{', '['))
            raw = str(body).encode('utf-8')
            if r.get('b64'):
                # a binary answer (DER, PKCS#7, CMP) written in the rule in base64
                import base64
                raw = base64.b64decode(raw)
            if r.get('scep') and self.issued and isinstance(sent_body, (bytes, bytearray)):
                # a SCEP server's CertRep to the request sent (issuers/scep.py)
                with _unrecorded(RECORDING[0]):
                    raw = scep_reply(self.issued, sent_body)
            return int(r.get('status', 200)), {k: self.plan_fill(str(v), False) for k, v in (
                r.get('headers') or {}).items()}, raw
        path = url.split('?', 1)[0]
        h = {'Content-Type': 'application/json',
             'Set-Cookie': 'NITRO_AUTH_TOKEN=%s; sessionid=%s; path=/' % (SESSION, SESSION),
             'X-Auth-Token': SESSION, 'X-Subject-Token': SESSION}
        if method == 'POST' and LOGIN_RE.search(path):
            body = {'sessionid': SESSION, 'token': SESSION, 'access_token': SESSION,
                    'session': SESSION, 'sid': SESSION, 'jwt': SESSION, 'success': True,
                    'data': {'token': SESSION, 'access_token': SESSION}}
            self.fell = 'sign-in'
            return 200, h, json.dumps(body).encode()
        if self.csr:
            self.fell = 'csr'
            return 200, h, json.dumps({'CSRString': self.csr, 'CSR': self.csr,
                                       'csr': self.csr}).encode()
        self.fell = 'empty'
        return 200, h, b'{}'

    def ssh(self, command, input=None):
        """(exit, stdout, stderr) of a command, None when no rule says. An answer's stdout may
        say {SEEN:regex}: the first group of the regex in what was sent over SSH before this
        (a name the module gave in an earlier command, listed back after the import); and
        {SERIAL} (1.0.96): the serial (hex, as pki.cert_info says it) of the last certificate
        sent over SSH - in this command's input or before - for a device that prints the
        serial of the certificate just imported (CUCM's show cert own); '' when none was."""
        seen = getattr(self, '_ssh_seen', None)
        if seen is None:
            seen = self._ssh_seen = []
        sent = str(command) + '\n' + (input.decode('utf-8', 'replace')
                                      if isinstance(input, (bytes, bytearray)) else str(input or ''))
        # the PowerShell script the command runs (1.0.98): -EncodedCommand decoded, or the
        # .ps1 uploaded before it (-File "path") - a rule's "script" (a regex) is matched
        # against it, {SEEN:..} looks in it too
        script = encoded_script(command)
        if not script:
            fm = re.search(r'-File\s+"([^"]+)"', str(command))
            script = (getattr(self, 'uploads', None) or {}).get(fm.group(1), '') if fm else ''
        if script:
            sent += '\n' + script

        def echo(m):
            for old in reversed(seen):
                got = re.search(m.group(1), old)
                if got:
                    return got.group(1) if got.groups() else got.group(0)
            return ''
        seen.append(sent)
        for i, r in enumerate(self.ssh_rules):
            if r.get('command') is not None and not re.search(r['command'], str(command)):
                continue
            inp = input.decode('utf-8', 'replace') if isinstance(input, (bytes, bytearray)) \
                else str(input or '')
            if r.get('input') is not None and not re.search(r['input'], inp):
                continue
            if r.get('script') is not None and not re.search(r['script'], script):
                continue
            if not self._take('ssh', i, r):
                continue
            out = str(r.get('stdout', '')).replace('{SESSION}', SESSION)
            if '{SERIAL}' in out:
                out = out.replace('{SERIAL}', sent_serial(seen))
            if r.get('seen_lines'):
                # one line a thing asked (1.0.98): {SEEN:..} looks in this command only, a
                # line where it found nothing is left out - sha256sum of 3 paths prints 3
                # lines, the rule has room for more
                def now(m):
                    got = re.search(m.group(1), sent)
                    return (got.group(1) if got.groups() else got.group(0)) if got else ''

                def every(m):
                    found = re.findall(m.group(1), sent)
                    return ', '.join(x if isinstance(x, str) else x[0] for x in found)

                def tag(text, name, fn):
                    # {NAME:regex} filled as {SEEN:..} is (the regex may hold braces)
                    hid = text.replace('{SEEN:', '\x02')
                    return fill_seen(hid.replace('{%s:' % name, '{SEEN:'), fn).replace(
                        '\x02', '{SEEN:')

                def kept(ln):
                    # {SEENALL:regex}: every match (its group) by ", " - the line left out when
                    # none; {SEEN?:regex}: '' when none, the line kept
                    got = []
                    # {IF:regex}: nothing printed - the line left out when it is not there
                    ln = tag(ln, 'IF', lambda m: got.append(
                        'y' if re.search(m.group(1), sent) else '') or '')
                    ln = tag(ln, 'SEENALL', lambda m: got.append(every(m)) or got[-1])
                    ln = tag(ln, 'SEEN?', now)
                    filled = fill_seen(ln, lambda m: got.append(now(m)) or got[-1])
                    return None if '' in got else filled
                out = ''.join(x for x in (kept(ln) for ln in out.splitlines(True))
                              if x is not None)
            out = self.plan_fill(self.earlier(fill_seen(out, echo)).replace(
                '{CSR}', self.csr or ''), False)
            return (int(r.get('exit', 0)), out, str(r.get('stderr', '')))
        return None


CERT_RE = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def sent_serial(seen):
    """The serial of the last certificate in what was sent (the lines of each SSH command and
    its input, oldest first) - '' when no certificate was sent."""
    from acmelib.certs import pki
    for old in reversed(seen):
        for pem in reversed(CERT_RE.findall(old)):
            try:
                return str(pki.cert_info(pem + '\n').get('serial') or '')
            except Exception:                           # noqa: BLE001
                continue
    return ''


def fill_seen(text, echo):
    """{SEEN:regex} in `text` replaced by echo(match) - the regex may hold braces of its own
    ({2}, {1,3}, \\{): it ends at the brace that closes the placeholder."""
    out, i = [], 0
    while True:
        j = text.find('{SEEN:', i)
        if j < 0:
            out.append(text[i:])
            return ''.join(out)
        out.append(text[i:j])
        k, depth, esc = j + 6, 0, False
        while k < len(text):
            c = text[k]
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '{':
                depth += 1
            elif c == '}':
                if depth == 0:
                    break
                depth -= 1
            k += 1
        if k >= len(text):                  # not closed: left as it is
            out.append(text[j:])
            return ''.join(out)
        pat = text[j + 6:k]
        try:
            out.append(echo(_Group(pat)) if pat else '')
        except re.error:                    # not a regex: nothing seen
            out.append('')
        i = k + 1


class _Group(object):
    """What echo() reads of a match: group(1), the regex."""
    def __init__(self, pat):
        self.pat = pat

    def group(self, n=0):
        return self.pat


def _shq(s):
    import shlex
    return shlex.quote(str(s))


def put_command(path, mode, owner, via, port=22):
    """How the real session (runtime.SshSession.put) puts a file - for the debug details:
    over the shell (cat into a temporary name, chmod, chown, mv) or with scp."""
    if via == 'scp':
        return 'scp -P %s -q ‹a file of its own› ‹user›@‹host›:%s' % (port, _shq(path))
    tmp = '%s.acme-‹random›.part' % path
    cmd = 'umask 077 && cat > %s' % _shq(tmp)
    if mode is not None:
        cmd += ' && chmod %o %s' % (int(mode), _shq(tmp))
    if owner:
        cmd += ' && chown %s %s' % (owner, _shq(tmp))
    cmd += ' && mv -f %s %s || { rm -f %s; exit 1; }' % (_shq(tmp), _shq(path), _shq(tmp))
    return cmd


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
             'trust_first': bool(self.conn.get('trust_first')),
             'timeout': int(self.conn.get('timeout') or 15),
             'key': bool(self.conn.get('key')), 'password': bool(self.conn.get('password')),
             'key_pass': bool(self.conn.get('key_pass')),
             'via': str(self.conn.get('via') or '')})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def run(self, command, input=None, timeout=120, check=True):
        note_sent(input)
        note_sent(str(command))
        ev = {'kind': 'ssh-run', 'host': self.host, 'command': str(command)}
        if input:
            f = blob_facts(input)
            ev['input'] = {'size': f['size'], 'format': f.get('format'),
                           'secret': bool(f.get('secret')) or 'sudo -S' in str(command)}
            if f.get('sha256'):
                ev['input']['sha256'] = f['sha256']
            # what goes on its input, readable (debug details): a script, a PEM as a
            # placeholder - sudo's password (its first line) never
            body = f.get('body')
            if body is None and 'PEM' in str(f.get('format') or ''):
                body = bytes(input if isinstance(input, (bytes, bytearray))
                             else str(input).encode('utf-8')).decode('utf-8', 'replace')[:60000]
            if body is not None:
                if 'sudo -S' in str(command):
                    body = '•••• (the sudo password)' + ('\n' + body.split('\n', 1)[1]
                                                        if '\n' in body else '')
                ev['input']['body'] = body[:60000]
        rec(ev)
        answers = getattr(self.ctx, 'answers', None)
        got = answers.ssh(command, input) if hasattr(answers, 'ssh') else None
        if got is None:
            # no answer was prepared for this command: a stand-in answers (marked)
            if 'http_code' in str(command):
                got = (0, '{}\n200', '')
            elif getattr(answers, 'csr', ''):
                got = (0, answers.csr, '')      # a device asked for its CSR prints it
            else:
                got = (0, '', '')
            ev['fallback'] = 'empty' if got == (0, '', '') else 'stand-in'
        ev['answer'] = {'exit': got[0], 'stdout': str(got[1])[:20000],
                        'stderr': str(got[2])[:4000]}
        return got

    def put(self, data, remote_path, mode=0o600, owner=None, via='shell'):
        note_sent(data)
        ev = dict({'kind': 'ssh-put', 'host': self.host, 'path': str(remote_path),
                   'mode': '%o' % int(mode) if mode is not None else None,
                   'owner': owner or None, 'via': via}, **blob_facts(data))
        ev['command'] = put_command(str(remote_path), mode, owner, via, self.port)
        rec(ev)
        answers = getattr(self.ctx, 'answers', None)
        if answers is not None and str(remote_path).lower().endswith(('.ps1', '.sh', '.py')):
            # a script uploaded to be run (1.0.98: a long PowerShell one, -File "path"): what
            # a rule's "script" is matched against, {SEEN:..} looks in
            try:
                raw = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
                answers.__dict__.setdefault('uploads', {})[str(remote_path)] = \
                    bytes(raw).decode('utf-8-sig', 'replace')
            except Exception:                           # noqa: BLE001
                pass

    def get(self, remote_path):
        rec({'kind': 'ssh-get', 'host': self.host, 'path': str(remote_path),
             'command': 'cat %s' % _shq(str(remote_path)), 'fallback': 'empty',
             'answer': {'exit': 0, 'stdout': '', 'stderr': ''}})
        return b''

    def close(self):
        pass


def push_confirm(raw, headers):
    """{PUSH_CONFIRM} in an answer (acme push's pair, runplan.ANSWERS['acme_push']): the
    confirmation the application makes with the pairing code - of the run's own code (its
    stand-in), the nonce the request said and the app_id / enc_key of the answer - so the
    pairing goes through as with the application."""
    try:
        from acmelib import engine as E
        d = json.loads(raw.decode('utf-8', 'replace').replace('{PUSH_CONFIRM}', ''))
        nonce = next((str(v) for k, v in (headers or {}).items()
                      if str(k).lower() == 'x-acme-push-nonce'), '')
        code = ((CURRENT[0] or {}).get('config') or {}).get('pair_code') or ''
        got = E.push_proof(code, 'paired', d.get('app_id'), 'acme-plan', nonce,
                           d.get('enc_key'))
        return raw.replace(b'{PUSH_CONFIRM}', got.encode())
    except Exception:                                   # noqa: BLE001
        return raw


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
        # what the target kept between its deployments that decides its way (runplan.kept_of:
        # the ARN of ACM's certificate imported before) - else nothing, as at the first one
        self._kv = dict(job.get('kv') or {})
        # acme push (targets/acme_push.py): the pin acme keeps of the application when it is
        # paired already (runplan.PUSH_PIN, the one its hello is answered with) - else none
        self._push_pin = job.get('push_pin') or None
        self._pages = job.get('pages') or None

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
        note_sent(body)
        st, hd, raw = self.answers(method, str(url), body)
        if b'{PUSH_CONFIRM}' in (raw or b''):
            raw = push_confirm(raw, h)
        ev = {'kind': 'http', 'method': method, 'url': str(url), 'headers': h, 'body': body,
              'verify': bool(verify), 'ca': bool(ca_pem), 'client_cert': bool(client_cert),
              'proxy': bool(proxy), 'answer': st, 'timeout': timeout,
              # what the stand-in device answered (debug details), and whether a rule of the
              # module's did or a generic stand-in (no answer prepared for this call)
              'answer_headers': {str(k): str(v) for k, v in dict(hd or {}).items()},
              'answer_body': raw}
        if getattr(self.answers, 'fell', None):
            ev['fallback'] = self.answers.fell
        rec(ev)
        return st, hd, raw

    def http_kept(self, method, url, body=None, headers=None, timeout=30, verify=True,
                  ca_pem=None, client_cert=None):
        """A request on a connection the module keeps open (issuers/ms_adcs.py: NTLM signs in
        a connection, not a request) - recorded as ctx.http is; never through a proxy."""
        got = self.http(method, url, body, headers, timeout, verify, ca_pem, client_cert,
                        proxy=False)
        ev = (RECORDING[0] or [None])[-1]
        if isinstance(ev, dict) and ev.get('kind') == 'http':
            ev['kept'] = True
        return got

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
        argv = [str(x) for x in argv]
        issued = getattr(self.answers, 'issued', None)
        if issued and argv[:2] and os.path.basename(argv[0]) == 'openssl' and 'cmp' in argv[1:2]:
            # openssl cmp (issuers/cmp.py) answered as the CMP server issues: the certificate
            # for the request's key written where -certout says, its chain where -chainout
            with _unrecorded(RECORDING[0]):
                for opt, key in (('-certout', 'CERT'), ('-chainout', 'CHAIN')):
                    if opt in argv[:-1] and _inside(argv[argv.index(opt) + 1]):
                        with _real['open'](argv[argv.index(opt) + 1], 'w') as fh:
                            fh.write(issued.get(key) or '')
        return 0, b'', b''

    def kv_get(self, key, default=None):
        return self._kv.get(str(key), default)

    def kv_keys(self, prefix=''):
        return {k: v for k, v in self._kv.items() if k.startswith(str(prefix))}

    def tidying(self):
        class _T(object):
            def __enter__(self):
                return None

            def __exit__(self, *a):
                return False
        return _T()

    def names_using(self):
        return []

    def kv_set(self, key, value, ttl_s=None):
        self._kv[str(key)] = value

    def seal(self, text, bind):
        return text

    def unseal(self, value, bind):
        return value

    def dns_put(self, name, type, value, ttl=60):
        rec({'kind': 'own-dns', 'name': str(name).rstrip('.').lower(),
             'type': str(type or 'TXT').upper(), 'value': str(value), 'ttl': ttl})
        # acme's own DNS server answers it from now on; the name's _acme-challenge is a CNAME
        # to it on a running setup (dns_answer)
        if str(type or 'TXT').upper() == 'TXT':
            PLACED_TXT.append(str(value))
            OWN_DNS.append(str(name).rstrip('.').lower())

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

    # acme's own pages as they are (runplan.pages_of, the job's "pages"): its nodes, the VIP
    # address, what each holds now
    def pages_where(self):
        got = (self._pages or {}).get('where')
        if isinstance(got, dict) and got.get('nodes'):
            return got
        return {'node': self.node, 'nodes': [self.node], 'cluster': False,
                'vip': {'on': False, 'fqdn': '', 'address': ''}}

    def pages_get(self, where):
        got = ((self._pages or {}).get('have') or {}).get(str(where))
        return dict(got) if isinstance(got, dict) else None

    def pages_put(self, where, cert_pem, key_pem, chain_pems=None, how='', alt=None):
        rec({'kind': 'pages', 'where': str(where), 'alt': bool(alt)})
        return {'cn': '', 'not_after': None, 'fingerprint': '', 'verify': '', 'alt': bool(alt)}

    def push_identity(self):
        # its public key as acme pastes it (a stand-in key: 32 zero bytes)
        import base64
        pub = b'\0' * 32
        return {'seed': b'\0' * 32, 'public': pub, 'id': 'acme-plan',
                'text': 'acme-push-ed25519 %s acme-push@acme-plan' % base64.b64encode(pub).decode()}

    def push_pin(self, url, pin=None):
        return dict(self._push_pin) if pin is None and self._push_pin else None


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
        if cert.get('csr_from'):
            key = None                  # the device made the key: the target gets none
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


def module(family, kind, version=None):
    from acmelib.plugins import base
    return base.REGISTRY.get(family, kind, version)


class _unrecorded(object):
    """What acme itself does in a run (a throwaway key, a CSR) not recorded - the recording
    on again afterwards, also when it raised."""
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        RECORDING[0] = None

    def __exit__(self, *exc):
        RECORDING[0] = self.events
        return False


KV_AFTER = [None]               # the last run's own state (ctx.kv_set) - seeds its later run


def kv_as_earlier(kv, bundle):
    """What a deployment kept (ctx.kv_set) as a renewal finds it: kept for the certificate
    deployed before - its fingerprints, thumbprint, serial (or their beginnings, 8+ hex
    characters) those of an earlier certificate of the same names, so the renewal does not
    take the new one for deployed already."""
    try:
        import hashlib
        from acmelib.certs import pki
        from acmelib.plugins.targets import _common as C
        if bundle is None:
            return dict(kv)
        pairs = []
        for v in C.variants_of(bundle):
            old = C.pem_to_der(pki.self_signed(pki.make_key('ec-256'), list(bundle.names or
                                                                            ['x.invalid']), days=90))
            new = C.pem_to_der(v.cert_pem)
            for fn in (hashlib.sha256, hashlib.sha1):
                pairs.append((fn(new).hexdigest(), fn(old).hexdigest()))
            ser = str(getattr(v, 'serial', '') or '').lower().replace(':', '')
            if ser:
                pairs.append((ser, hashlib.sha1(old).hexdigest()[:len(ser)]))

        def swap(m):
            t = m.group(0)
            for new, old in pairs:
                if len(t) <= len(new) and new.startswith(t.lower()):
                    o = old[:len(t)]
                    return o.upper() if t.isupper() else o
            return t
        text = re.sub(r'[0-9A-Fa-f]{8,}', swap, json.dumps(kv, default=str))
        return json.loads(text)
    except Exception:                                   # noqa: BLE001
        return dict(kv)


def run_one(job, r, bundle_holder):
    KV_AFTER[0] = None
    events = []
    RECORDING[0] = events
    CURRENT[0] = r
    del PLACED_TXT[:]
    PLACED_KEYAUTH[0] = ''
    PLACED_CNAME.clear()
    del OWN_DNS[:]
    err = None
    said = None
    PRINTED.take()                  # what was printed before this run is not its own
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(int(r.get('seconds') or 8))
    try:
        cls = module(r['family'], r['kind'], (r.get('config') or {}).get('_version'))
        answers = Answers(r.get('answers'), r.get('ssh_answers'))
        ANSWERS[0] = answers
        SENT_NEW[0] = False
        ctx = PlanContext(dict(job, deploy_id=r.get('deploy_id'), target_name=r.get('name'),
                               push_pin=r.get('push_pin'), kv=r.get('kv')),
                          '%s:%s' % (r['family'], r.get('name')), answers)
        KV_AFTER[0] = ctx._kv           # what it keeps: the later run starts with it (main)
        inst = cls(dict(r.get('config') or {}), ctx)
        op = r.get('op')
        if op == 'deploy':
            if bundle_holder[0] is None:
                with _unrecorded(events):
                    bundle_holder[0] = dummy_bundle(job.get('cert') or {})
            b = bundle_holder[0]
            if b.alt is not None and not getattr(cls, 'dual', False):
                from acmelib.certs.deployer import pick_variant
                b = pick_variant(b, r.get('options') or {}, cls)
            opts = dict(r.get('options') or {})
            answers.bundle, answers.options = b, dict(opts)
            # a module naming its objects otherwise than object_name (Junos ids): its own
            # plan_name(bundle, options) names {EARLIER} / {CURRENT}
            answers.namer = getattr(cls, 'plan_name', None)
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
            # no check of the module's own after it (1.0.92): what is served is looked at by
            # the tests attached to the certificate only - the Tests phase shows them
        elif op == 'device_csr':
            # the device asked for a new key and CSR (Target.device_csr): answered with a
            # CSR for the names, made here with a throwaway key
            from acmelib.certs import devicekey
            from acmelib.plugins import base
            cert = job.get('cert') or {}
            names = list(cert.get('names') or ['example.invalid'])
            with _unrecorded(events):
                answers.csr = devicekey.dummy_csr(names, cert.get('key_type') or 'ec-256')
            req = base.CertRequest(names=names, sans=list(r.get('sans') or names),
                                   key_type=cert.get('key_type') or 'ec-256',
                                   subject=dict(r.get('subject') or {'CN': names[0]}),
                                   profile={}, options=dict(r.get('options') or {}),
                                   name=cert.get('name') or names[0], cert_id=cert.get('id'),
                                   target=r.get('name'))
            got = inst.device_csr(req)
            said = 'the device gave its CSR' if got else None
        elif op == 'challenge':
            name = r.get('names', ['example.invalid'])[0]
            answers.vname = name
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
            with _unrecorded(events):
                key = pki.make_key(cert.get('key_type') or 'ec-256')
                csr_pem, csr_der = pki.make_csr(key, names)
                # what the CA answers holds a certificate for this key (1.0.98); a renewal
                # hands the certificate it renews (base.CertRequest.previous)
                answers.issued = issued_for(csr_pem, names)
                # a fingerprint the module checks the CA it is answered by against (SCEP's
                # ca_fingerprint): the stand-in CA's, in the length and shape set
                import hashlib
                for k in r.get('pinned') or ():
                    v = str(inst.config.get(k) or '')
                    hexed = re.sub(r'[^0-9a-fA-F]', '', v)
                    if hexed:
                        algo = {32: 'md5', 40: 'sha1'}.get(len(hexed), 'sha256')
                        fp = hashlib.new(algo, pki.pem_to_der(answers.issued['CHAIN'])).hexdigest()
                        inst.config[k] = ':'.join(fp[i:i + 2] for i in range(0, len(fp), 2)) \
                            if ':' in v else fp
                answers.vname = names[0]
                previous = pki.self_signed(pki.make_key(cert.get('key_type') or 'ec-256'),
                                           names, days=90) if r.get('previous') else None
                acme = r.get('acme') if isinstance(r.get('acme'), dict) else None
                if acme is not None:
                    # the plain ACME source (1.0.98): the certificate it renews is one the CA
                    # issued (its AKI and serial make the ARI id); the alternate chain ends at
                    # the root "Preferred chain" names; an account made before is used as it
                    # is - its key a throwaway one of its kind, here only
                    if previous is not None:
                        k0 = pki.make_key(cert.get('key_type') or 'ec-256')
                        previous = issued_for(pki.make_csr(k0, names)[0], names)['CERT']
                    answers.issued['ALT_ROOT'] = pki.self_signed(
                        pki.make_key('ec-256'), [], subject={'CN': str(
                            acme.get('preferred') or 'Plan Alternate Root')[:60]}, days=365,
                        is_ca=True)
                    if acme.get('account') and not r.get('kv'):
                        url = inst.directory_url()
                        kind = str(inst.c('account_key') or 'ec-256')
                        ctx.kv_set(inst.account_slot(url), json.dumps({
                            'url': acme['account'], 'key': pki.make_key(kind), 'kind': kind,
                            'contacts': inst.contacts(), 'directory': url}))
            # the certificate's own validations, for a commercial CA's DCV (1.0.98): each
            # puts the CA's record in place through its own module, recorded here too
            chal = {}
            proving = {'put': 0, 'gone': 0, 'ready': False}
            for n, c in (r.get('challenges') or {}).items():
                ccls = module('challenge', c['kind'], (c.get('config') or {}).get('_version'))
                ca = Answers(c.get('answers'), c.get('ssh_answers'))
                ca.vname = n
                chal[n] = ccls(dict(c.get('config') or {}), PlanContext(
                    job, 'challenge:%s' % c.get('name'), ca))

                def place(kind, name, where, content, _o=chal[n].place):
                    # what the CA asked for is what DNS answers once it is in place
                    if kind == 'cname':
                        PLACED_CNAME[str(where).lower().rstrip('.')] = str(content)
                    else:
                        PLACED_TXT.append(str(content))
                    return _o(kind, name, where, content)
                chal[n].place = place

                def present(name, token, key_authorization, txt_value, _o=chal[n].present):
                    # an ACME source's own proof (sslmarket_acme): seen once it is in place
                    PLACED_TXT.append(str(txt_value))
                    PLACED_KEYAUTH[0] = str(key_authorization)
                    proving['put'] += 1
                    proving['ready'] = False
                    return _o(name, token, key_authorization, txt_value)
                chal[n].present = present

                def ready(name, handle, _o=chal[n].ready):
                    # an ACME source's validations (1.0.98): the wait until each proof can be
                    # seen, the taking away after the CA has looked, then the order again
                    if proving['put'] and not proving['ready']:
                        proving['ready'] = True
                        rec({'kind': 'phase', 'what': 'ready'})
                    return _o(name, handle)
                chal[n].ready = ready

                def cleanup(name, handle, _o=chal[n].cleanup):
                    if proving['put'] and not proving['gone']:
                        rec({'kind': 'phase', 'what': 'cleanup'})
                    proving['gone'] += 1
                    try:
                        return _o(name, handle)
                    finally:
                        if proving['put'] and proving['gone'] == proving['put']:
                            rec({'kind': 'phase', 'what': 'order'})
                chal[n].cleanup = cleanup
            req = base.CertRequest(names=names, sans=names, key_type=cert.get('key_type'),
                                   key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                                   subject={}, days=cert.get('days'),
                                   profile={'acme_profile': acme['profile']} if acme and
                                   acme.get('profile') else {},
                                   challenges=chal, previous=previous, cert_id=cert.get('id'),
                                   ref=cert.get('ref') or None)
            if previous and acme is not None and acme.get('ari'):
                # a renewal: when to renew asked of the CA first (ARI, RFC 9773 - the
                # renewer, every 6 hours), then the order that says it replaces it
                rec({'kind': 'phase', 'what': 'ari'})
                win = inst.renewal_window(previous)
                if not win:
                    # the module's own decision: the directory has no renewalInfo
                    rec({'kind': 'phase', 'what': 'no-ari'})
                rec({'kind': 'phase', 'what': 'issue'})
            got = inst.issue(req)
            said = 'issued' if got else None
            if acme is not None and acme.get('preferred') and got is not None:
                # the chain the module took (Issued.info 'chain': 'default' or the alternate's
                # link) and the CA its top comes from (1.0.98)
                top = ''
                try:
                    from acmelib.plugins.issuers import _scep_pkcs7 as _der
                    pems = list(got.chain_pems or []) or [got.cert_pem]
                    top = _der.Cert(pems[-1]).issuer_cn or ''
                except Exception:                       # noqa: BLE001
                    pass
                rec({'kind': 'chain', 'preferred': str(acme['preferred']), 'top': top,
                     'where': str((got.info or {}).get('chain') or 'default')})
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
        ANSWERS[0] = None
    printed, over = PRINTED.take()
    if printed.strip():
        # what the module printed, aside (1.0.101): shown with the debug details
        events.append({'kind': 'output', 'text': printed, 'over': over})
    marks = r.get('marks') or {}
    return {'events': [clean(ev, marks) for ev in events], 'error': mask_text(err, marks)
            if err else None, 'said': mask_text(said, marks) if isinstance(said, str) else None}


def _hdr(headers, name):
    for k, v in dict(headers or {}).items():
        if str(k).lower() == name:
            return str(v)
    return ''


ARGV_SECRET_FLAG = re.compile(r'^(--?(password|passwd|pass|passphrase|secret|token|api-?key|'
                              r'storepass|keypass|key-?pass|pin)|-(Password|PlainPassword|Pin|'
                              r'Secret|Token|ApiKey|Passphrase|CertificatePassword))$', re.I)


def clean(ev, marks):
    """An event as it leaves: every secret masked."""
    ev = dict(ev)
    k = ev.get('kind')
    if k == 'http':
        raw_url, raw_headers, raw_body = ev['url'], dict(ev.get('headers') or {}), ev.get('body')
        ctype = _hdr(raw_headers, 'content-type')
        ev['url'] = mask_url(ev['url'], marks)
        ev['headers'] = {hk: header_shown(hk, hv, marks) for hk, hv in raw_headers.items()}
        body, facts = mask_body(raw_body, marks, ctype)
        jws = jws_shown(raw_body, marks) if 'jose' in ctype.lower() else None
        if jws is not None:
            # an ACME request (JWS, RFC 8555 6.2): its protected header and payload decoded,
            # the signature (and an EAB's within) never shown; on the wire as sent (1.0.98)
            body, facts = jws, dict(facts, format='jws')
            raw_body = jws_wire(raw_body)
        ev['body'] = body
        ev['body_facts'] = facts
        # the request exactly as it goes on the wire (debug details): every header - the
        # ones the transport adds too - and the body as sent, its secrets out
        try:
            from acmelib.certs import runtime as _rt
            w = _rt.wire_request(ev.get('method'), raw_url, raw_headers,
                                 raw_body if not isinstance(raw_body, (bytes, bytearray))
                                 else bytes(raw_body).decode('latin-1'), own=bool(ev.get('own')))
            murl = mask_url(raw_url, marks)
            import urllib.parse
            u = urllib.parse.urlsplit(murl)
            line = '%s %s HTTP/1.1' % (str(ev.get('method') or 'GET').upper(),
                                       (u.path or '/') + ('?' + u.query if u.query else ''))
            hs = []
            for h in w['headers']:
                v = h[1]
                if h[0].lower() == 'content-length' and raw_body is not None:
                    v = str(len(raw_body if isinstance(raw_body, (bytes, bytearray)) else
                                (json.dumps(raw_body) if isinstance(raw_body, (dict, list))
                                 else str(raw_body)).encode('utf-8')))
                hs.append([h[0], header_shown(h[0], v, marks), bool(h[2])])
            ev['wire'] = {'line': line, 'headers': hs,
                          'body': wire_body(raw_body, marks, ctype)}
        except Exception:                               # noqa: BLE001
            pass
        if 'answer_headers' in ev or 'answer_body' in ev:
            ah = dict(ev.pop('answer_headers', None) or {})
            ab = ev.pop('answer_body', None)
            shown, afacts = mask_body(ab if ab not in (None, b'') else None, marks,
                                      _hdr(ah, 'content-type'))
            ev['answered'] = {'status': ev.get('answer'),
                              'headers': [[hk, header_shown(hk, hv, marks)]
                                          for hk, hv in ah.items()],
                              'body': shown, 'body_facts': afacts}
    elif k in ('ssh-run',):
        # PowerShell's -EncodedCommand read too (1.0.23): the script as it runs, for people
        script = encoded_script(ev['command'])
        if script:
            ev['script'] = mask_command(script, marks)
        ev['command'] = mask_command(ev['command'], marks)
        if isinstance(ev.get('input'), dict) and ev['input'].get('body') is not None:
            ev['input'] = dict(ev['input'], body=mask_text(ev['input']['body'], marks))
        if isinstance(ev.get('answer'), dict):
            ev['answer'] = {a: (mask_text(b, marks) if isinstance(b, str) else b)
                            for a, b in ev['answer'].items()}
    elif k in ('ssh-put', 'file', 'ssh-get'):
        if ev.get('body') is not None:
            ev['body'] = mask_text(ev['body'], marks)
        if ev.get('command'):
            ev['command'] = mask_command(ev['command'], marks)
    elif k == 'command':
        argv = [mask_text(a, marks) for a in ev.get('argv') or []]
        for n in range(1, len(argv)):
            if ARGV_SECRET_FLAG.match(argv[n - 1]) and not argv[n].startswith('••••'):
                argv[n] = '••••'
        ev['argv'] = [mask_command(a, marks) if ' ' in a or 'pass:' in a else a for a in argv]
    elif k in ('ftp-cmd', 'ftp-put'):
        ev['cmd'] = mask_command(ev.get('cmd') or '', marks)
    elif k == 'bypass':
        ev['what'] = mask_command(ev.get('what') or '', marks)
    elif k == 'say':
        ev['words'] = mask_text(ev['words'], marks)
    elif k == 'output':
        ev['text'] = mask_text(str(ev.get('text') or ''), marks)
    elif k in ('dns-ask', 'dns-update'):
        ev = mask_json(ev, marks)
    for key in ('path', 'host'):
        if isinstance(ev.get(key), str):
            ev[key] = mask_text(ev[key], marks)
    return ev


def issued_for(csr_pem, names):
    """What a CA answers a request with (1.0.98): a certificate for the request's key and
    names, signed by an intermediate made here for the run - as the placeholders of
    Answers.plan_fill take it (PEM, DER in base64, PKCS#7 in base64, the serial)."""
    import base64
    from acmelib.certs import pki
    # an RSA request gets an RSA intermediate (SCEP encrypts to it and checks its signature)
    rsa = 'rsa' in str(pki.csr_info(csr_pem).get('key_type') or '')
    ca_key = pki.make_key('rsa-2048' if rsa else 'ec-256')
    ca = pki.self_signed(ca_key, [], subject={'CN': 'Plan Intermediate CA'}, days=365,
                         is_ca=True)
    san, _typed = pki.san_lines(names)
    ext = ['basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature, '
           'keyEncipherment', 'extendedKeyUsage = serverAuth, clientAuth',
           'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid:always'] + (
        ['subjectAltName = @san', '', '[san]'] + san if san else [])
    with pki.workdir() as d:
        out = pki.openssl(['x509', '-req', '-in', pki.wfile(d, 'r.csr', csr_pem),
                           '-CA', pki.wfile(d, 'ca.pem', ca), '-CAkey',
                           pki.wfile(d, 'ca.key', ca_key), '-set_serial',
                           '0x' + pki.random_serial(), '-days', '90', '-sha256',
                           '-extfile', pki.wfile(d, 'ext.cnf', '\n'.join(ext) + '\n')])
        leaf = pki.certs_in(out.decode() if isinstance(out, bytes) else out)[0]
        p7 = pki.openssl(['crl2pkcs7', '-nocrl', '-outform', 'DER', '-certfile',
                          pki.wfile(d, 'all.pem', leaf + ca)])
        ca7 = pki.openssl(['crl2pkcs7', '-nocrl', '-outform', 'DER', '-certfile',
                           pki.wfile(d, 'ca1.pem', ca)])

    def b64(pem):
        return base64.b64encode(pki.pem_to_der(pem)).decode()
    return {'CERT': leaf, 'CHAIN': ca, 'CERT_B64': b64(leaf), 'CHAIN_B64': b64(ca),
            'P7_B64': base64.b64encode(p7).decode(), 'CA_P7_B64': base64.b64encode(ca7).decode(),
            'CERT_SERIAL': str(pki.cert_info(leaf).get('serial') or ''), '_ca_key': ca_key}


def scep_reply(issued, sent):
    """A SCEP CertRep (SUCCESS) to the PKIOperation `sent` (DER): the certificate issued and
    its intermediate, in a certs-only PKCS#7 enveloped to the requester's signing
    certificate, signed by the intermediate with the request's transactionID and nonce."""
    from acmelib.certs import pki
    from acmelib.plugins.issuers import _scep_pkcs7 as p7
    req = p7.SignedMessage(bytes(sent))
    tid = req.attr_text(p7.OID_SCEP_TRANSACTION_ID) or ''
    nonce = req.attr_bytes(p7.OID_SCEP_SENDER_NONCE) or os.urandom(16)
    ca_der = pki.pem_to_der(issued['CHAIN'])
    with p7.Crypto(lambda args, data=None: pki.openssl(args, data)) as cr:
        inner = p7.build_degenerate([pki.pem_to_der(issued['CERT']), ca_der])
        env = p7.build_enveloped(cr, inner, req.signer_cert(), 'aes256')
        return p7.build_signed(cr, env, ca_der, cr.file(issued['_ca_key'], 'ca.key'), [
            (p7.OID_SCEP_MESSAGE_TYPE, p7.der_printable(p7.MESSAGE_TYPES['CertRep'])),
            (p7.OID_SCEP_TRANSACTION_ID, p7.der_printable(tid)),
            (p7.OID_SCEP_PKI_STATUS, p7.der_printable('0')),
            (p7.OID_SCEP_RECIPIENT_NONCE, p7.der_octets(nonce)),
            (p7.OID_SCEP_SENDER_NONCE, p7.der_octets(os.urandom(16)))], 'sha256')


CURRENT = [None]                # the run going on (run_one): its family, its settings
PLACED_TXT = []                 # TXT values a run wrote (UPDATE, a CA's DCV): seen when asked
PLACED_KEYAUTH = ['']           # the key authorization an ACME source's run put in (HTTP-01)
PLACED_CNAME = {}               # CNAMEs a CA's DCV put in place: {name: target}
OWN_DNS = []                    # names acme's own DNS server was given a TXT record at


def dns_answer(D, wire, r):
    """The answer of a DNS server to a validation's question (1.0.98), as the zone of a
    running domain gives it: the zone of a name is its registrable domain (SOA in the
    answer at the apex, in the authority section below it); NS ns1/ns2 of the zone, their
    addresses 192.0.2.53 / 2001:db8::53 (documentation ones); TXT at _acme-challenge (and
    any name written by UPDATE) the value put in; no CNAME. An UPDATE: NOERROR - signed
    back with its TSIG key when it came signed with one of the run's settings."""
    q = D.parse(wire)
    op = (q.flags >> 11) & 0xF
    m = D.Message(q.id, 0x8000 | (op << 11) | 0x0400 | (q.flags & 0x0100) | 0x0080)
    m.question = list(q.question)
    if op == D.OP_UPDATE:
        for x in q.authority:
            if x.rclass == D.CLASS_IN and x.rtype == 16 and x.text:
                PLACED_TXT.append(x.text.strip('"'))
        out = m.to_wire()
        if q.additional and q.additional[-1].rtype == 250:
            keyname = D.norm(q.additional[-1].name)
            t = D.tsig_read(wire)
            for v in (r.get('config') or {}).values():
                try:
                    D.tsig_verify(wire, keyname, str(v))
                except Exception:                       # noqa: BLE001
                    continue
                out, _mac = D.tsig_sign(out, keyname, str(v), t['alg'], request_mac=t['mac'])
                break
        return out
    for n, t, _c in q.question:
        n = D.norm(n)
        zone = D.registrable(n)
        soa = D.RR(zone, 6, D.CLASS_IN, 3600, 'ns1.%s hostmaster.%s 2026010101 7200 3600 '
                   '1209600 300' % (zone, zone))
        if t == 6:
            (m.answer if n == zone else m.authority).append(soa)
        elif t == 2 and n == zone:
            m.answer += [D.RR(zone, 2, D.CLASS_IN, 3600, 'ns%d.%s' % (i, zone)) for i in (1, 2)]
        elif t == 1:
            m.answer.append(D.RR(n, 1, D.CLASS_IN, 300, '192.0.2.53'))
        elif t == 28:
            m.answer.append(D.RR(n, 28, D.CLASS_IN, 300, '2001:db8::53'))
        elif t == 5 and n in PLACED_CNAME:
            m.answer.append(D.RR(n, 5, D.CLASS_IN, 300, PLACED_CNAME[n]))
        elif t == 5 and n.startswith('_acme-challenge.') and [x for x in OWN_DNS if x != n]:
            m.answer.append(D.RR(n, 5, D.CLASS_IN, 300, [x for x in OWN_DNS if x != n][-1]))
        elif t == 16:                                   # the value put in, seen
            for v in [TXT] + [x for x in PLACED_TXT if x != TXT]:
                m.answer.append(D.RR(n, 16, D.CLASS_IN, 60, v))
        else:
            m.authority.append(soa)                     # NOERROR, no such record (no CNAME)
    return m.to_wire()


def _patch_modules(job):
    """What reaches out is written down: DNS questions, TLS handshakes, the resolvers."""
    from acmelib.plugins.challenges import _dns as D
    from acmelib.plugins.targets import _common as TC
    res = job.get('resolvers') or {}

    # a password a module makes for the one run (_common.random_password: a PKCS#12's, a
    # one-time import password) is a secret no stand-in mark knows - masked wherever it shows
    # (a command line, a body, an SSH session's input), 1.0.98
    made = getattr(TC.random_password, 'plan_made', None) or TC.random_password

    def random_password(*a, **k):
        pw = made(*a, **k)
        r = CURRENT[0]
        if r is not None and pw:
            if not isinstance(r.get('marks'), dict):
                r['marks'] = {}
            r['marks'][pw] = 'a password made for this run'
        return pw
    random_password.plan_made = made
    TC.random_password = random_password
    for mname, mod in list(sys.modules.items()):
        if getattr(mod, 'random_password', None) is made:     # custom modules' too
            mod.random_password = random_password

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
                     'tsig': bool(q.additional and q.additional[-1].rtype == 250),
                     'tsig_name': D.norm(q.additional[-1].name) if (
                         q.additional and q.additional[-1].rtype == 250) else ''})
            else:
                for n, t, _c in q.question:
                    rec({'kind': 'dns-ask', 'server': str(server), 'port': port,
                         'name': D.norm(n), 'qtype': D.type_name(t)})
        except Exception:                               # noqa: BLE001
            pass
        r = CURRENT[0] or {}
        if r.get('family') in ('challenge', 'issuer'):
            # a validation's DNS (1.0.98): answered as the zone of a running domain answers -
            # the name's zone by its SOA, its name servers, their addresses, the TXT record put
            # in seen - so the module goes the way it goes when the record is there
            try:
                return dns_answer(D, wire, r)
            except Exception:                           # noqa: BLE001
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
        """What the device serves (1.0.98): before the new certificate was sent to it, an
        earlier one of the same names (its own key - the one {EARLIER_PEM} is), so a module
        that looks first takes the renewal's way ("serves another - replacing it"); once
        sent, the new one (of the key family asked for), so a check after it passes. Outside
        a deployment (no certificate): no handshake."""
        ev = {'kind': 'check', 'host': str(host), 'port': int(port), 'sni': sni or '',
              'only': only or ''}
        rec(ev)
        ans = ANSWERS[0]
        b = getattr(ans, 'bundle', None)
        if b is None:
            raise OSError('the run plan makes no handshake')
        if SENT_NEW[0]:
            v = TC.variant_of(b, only) if only else b
            ev['served'] = 'new'
            return TC.pem_to_der((v or b).cert_pem)
        pem = ans.earlier_pem()
        if not pem:
            raise OSError('the run plan makes no handshake')
        ev['served'] = 'earlier'
        return TC.pem_to_der(pem)
    TC.served_der = served_der
    try:
        from acmelib.certs import dnssets
        dnssets.for_module = resolver
        dnssets.ssh_address = lambda ctx, host: str(host or '').strip('[]')
    except Exception:                                   # noqa: BLE001
        pass


class Printed(io.TextIOBase):
    """sys.stdout and sys.stderr while modules run (1.0.101): what a module prints kept aside,
    at most CAP characters a run - never in the recording's own output (one print() lost the
    whole plan; one writing in a loop filled the daemon's memory)."""
    CAP = 4000

    def __init__(self):
        super().__init__()
        self.kept = []
        self.n = 0
        self.over = 0

    def writable(self):
        return True

    @property
    def encoding(self):
        return 'utf-8'

    @property
    def buffer(self):
        me = self

        class _Bytes:
            def write(self, b):
                me.write(bytes(b).decode('utf-8', 'replace'))
                return len(b)

            def flush(self):
                pass
        return _Bytes()

    def write(self, t):
        t = t if isinstance(t, str) else str(t)
        room = self.CAP - self.n
        if room > 0:
            self.kept.append(t[:room])
            self.n += min(len(t), room)
        self.over += max(0, len(t) - max(room, 0))
        return len(t)

    def take(self):
        out = (''.join(self.kept), self.over)
        self.kept, self.n, self.over = [], 0, 0
        return out


PRINTED = Printed()
RESULT_FD = [None]


def limits(lim):
    """The process's own limits, before any module is loaded (1.0.101): its memory, its
    processor time, the size of a file it writes (a bigger write fails, the process goes on).
    Programs it may start (openssl) have them too."""
    import resource
    lim = lim or {}

    def cap(what, soft, hard=None):
        try:
            _s, h = resource.getrlimit(what)
            hard = soft if hard is None else hard
            if h != resource.RLIM_INFINITY:
                soft, hard = min(soft, h), min(hard, h)
            resource.setrlimit(what, (soft, hard))
        except (ValueError, OSError):
            pass
    # the memory it writes (RLIMIT_DATA: the heap and private mappings), not its address space:
    # RLIMIT_AS counted the 64 MB glibc reserves for each malloc arena and the stack of each
    # thread, and a module starting threads (an SDK's transfers) stopped at about 13 of them
    mem = int(lim.get('mem_mb') or 1024) << 20
    if hasattr(resource, 'RLIMIT_DATA'):
        cap(resource.RLIMIT_DATA, mem)
    cpu = int(lim.get('cpu_s') or 80)
    cap(resource.RLIMIT_CPU, cpu, cpu + 5)
    try:
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    except (AttributeError, ValueError, OSError):
        pass
    cap(resource.RLIMIT_FSIZE, int(lim.get('file_mb') or 64) << 20)
    # RLIMIT_NPROC is not set: it counts every process of the user (the daemon's threads too),
    # and starting programs is shut off by lockdown() already.


def shut_output():
    """The recording's own answer to a copy of stdout kept aside; stdout and stderr, as files
    and as sys.stdout / sys.stderr, go nowhere (1.0.101) - what the modules print is kept in
    PRINTED; the end of the process's own trouble goes to the real stderr (see main())."""
    RESULT_FD[0] = os.dup(1)
    err = os.dup(2)
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.dup2(null, 2)
    os.close(null)
    sys.stdout = PRINTED
    sys.stderr = PRINTED
    return err


def answer(data):
    fd = RESULT_FD[0]
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def main():
    raw = sys.stdin.buffer.read()
    job = json.loads(raw.decode('utf-8'))
    limits(job.get('limits'))
    err_fd = shut_output()
    try:
        _main(job)
    except BaseException:                               # noqa: BLE001
        try:
            os.write(err_fd, traceback.format_exc()[-4000:].encode('utf-8', 'replace'))
        except OSError:
            pass
        os._exit(1)


def _main(job):
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
        if r.get('op') == 'issue' and r.get('previous') and not r.get('kv'):
            # a renewal at a source that keeps state of its own (Venafi's DN / certificate
            # id): what its first issue kept is there - the renewal in place shown (1.0.98);
            # that first one is not shown
            run_one(job, r, holder)
            if KV_AFTER[0]:
                r = dict(r, kv={str(k): v for k, v in dict(KV_AFTER[0]).items()})
        got = run_one(job, r, holder)
        # a later run: where answers of a renewal are given (LATER / SSH_LATER) - and where the
        # first run kept state of its own (ctx.kv_set), which a renewal reads (1.0.98)
        if r.get('op') == 'deploy' and not got.get('error') and r.get('later_answers') is None \
                and KV_AFTER[0] and not r.get('no_later'):
            r = dict(r, later_answers=r.get('answers') or [])
        if r.get('op') == 'deploy' and r.get('later_answers') is not None:
            later = dict(r, answers=r['later_answers'])
            # a renewal finds what the first deployment kept in acme's own state (an id at a
            # CDN, a thumbprint, a file name): the later run starts with it (1.0.98)
            if KV_AFTER[0]:
                later['kv'] = dict(r.get('kv') or {}, **{str(k): v for k, v in
                                                         kv_as_earlier(KV_AFTER[0],
                                                                       holder[0]).items()})
            if r.get('later_ssh_answers') is not None:
                later['ssh_answers'] = r['later_ssh_answers']
            got['later'] = run_one(job, later, holder)['events']
        if r.get('op') == 'issue' and isinstance(r.get('acme'), dict) and \
                r['acme'].get('later') and not got.get('error'):
            # the plain ACME source (1.0.98): a renewal after this first issue - the account
            # it made (or used) kept, the certificate it renews handed, ARI asked first
            later = dict(r, previous=True, acme=dict(r['acme'], account=None, ari=True),
                         kv={str(k): v for k, v in dict(KV_AFTER[0] or {}).items()})
            lg = run_one(job, later, holder)
            if not lg.get('error'):
                got['later'] = lg['events']
            else:
                got['later_error'] = lg['error']
        out[r['id']] = got
    answer(json.dumps({'runs': out}, default=str).encode('utf-8'))


if __name__ == '__main__':
    main()
