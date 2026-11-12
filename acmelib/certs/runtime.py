# -*- coding: utf-8 -*-
"""
What a module is handed: RunContext (the real acmelib.plugins.base.Context)
and SshSession (the ssh and scp programs of OpenSSH).

A module never touches the database, the sealing key or the network settings
itself - everything goes through here, and every step is written into the
job it runs in.

SSH: the server's host key is always checked. The target's config holds it
as known_hosts line(s) (`hostkey`); with none and `trust_first` on, the first
key the server shows (ssh-keyscan) is taken, written back into the target's
config and said in the job; with none and no trust_first the connection is
refused, saying the fingerprint the server shows so it can be checked and
pasted. A password or a key's passphrase goes through SSH_ASKPASS, never on a
command line; one connection is shared by every command of a session
(ControlMaster), so a password is asked for once.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S

KV_PREFIX = 'certs:kv:'
CHAL_PREFIX = 'acme:chal:'          # read by the engine's acme_challenge() for port 80
FILE_PREFIX = 'acme:file:'          # a CA's DCV file, read by the engine's acme_file() for port 80


def file_key(host, path):
    """The meta key of a DCV file answered for http://host/path."""
    h = hashlib.sha256(('%s|%s' % (str(host or '').strip().lower().rstrip('.'),
                                   str(path or ''))).encode('utf-8')).hexdigest()[:48]
    return FILE_PREFIX + h
HOSTKEY_ALIAS = 'acme-target'


def shq(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


def port_in(port, spec):
    """Is `port` in a firewall rule's ports ('' any, '80,443', '1000-2000', '1000:2000')."""
    spec = str(spec or '').replace(' ', '')
    if not spec:
        return True
    port = int(port)
    for part in spec.split(','):
        lo, sep, hi = part.replace(':', '-').partition('-')
        try:
            if sep and int(lo) <= port <= int(hi):
                return True
            if not sep and int(lo) == port:
                return True
        except ValueError:
            continue
    return False


SECRET_PARAM = re.compile(r'(key|token|pass|secret|sig|auth|credential|session|code)', re.I)


def header_dict(msg):
    """The headers of an answer as {name: value}. A header sent more than once is
    one value, joined by ", " as RFC 9110 joins them - Set-Cookie too (each cookie
    is still found by its name in it): a controller that hands its session and its
    CSRF token as two cookies (Avi) keeps both."""
    out, low = {}, {}
    for k, v in (msg.items() if msg is not None else []):
        first = low.get(k.lower())
        if first is None:
            low[k.lower()] = k
            out[k] = v
        else:
            out[first] = '%s, %s' % (out[first], v)
    return out


def url_shown(url):
    """A URL as a job's steps say it: an API key, token or password given in its
    query (Duck DNS, DreamHost...) or in the address itself as dots."""
    try:
        u = urllib.parse.urlsplit(str(url))
    except ValueError:
        return '?'
    net = u.netloc
    if '@' in net:
        net = '\u2022\u2022\u2022@' + net.rsplit('@', 1)[1]
    q = '&'.join(
        '%s=%s' % (k, '\u2022' * 8 if SECRET_PARAM.search(k) and v else v) if eq else k
        for k, eq, v in (p.partition('=') for p in u.query.split('&') if p)) if u.query else ''
    return urllib.parse.urlunsplit((u.scheme, net, u.path, q, ''))


def scope_hostkey_keeper(store, scope):
    """fn(known_hosts, field) writing the first host key seen into the row the scope names
    ('target:web1', 'challenge:ssh-dns', 'check:relay'), if that field is empty there."""
    fam, _, name = str(scope or '').partition(':')
    table = S.TABLE_OF.get(fam)
    if not table or not name or store is None:
        return None

    def keep(text, field='hostkey'):
        field = str(field or 'hostkey')
        if not re.match(r'^(?:[a-z_]{0,39}_)?hostkey$', field):
            return
        row = store.db.row('SELECT id, config FROM %s WHERE name = ?' % table, (name,))
        if not row:
            return
        cfg = S.jload(row.get('config'), {}) or {}
        # Added beside what is there (a list of hosts of a validation): the connection asked
        # because none of it was for this host.
        have = str(cfg.get(field) or '').strip()
        new = str(text).strip()
        if not new or new in have:
            return
        cfg[field] = (have + '\n' + new).strip()
        store.db.update(table, row['id'], {'config': json.dumps(cfg), 'updated': time.time()})
        store.add_event('certificates', 'the host key of %s %s was taken as the first one seen '
                        '(trust_first)' % (fam, name), 'warn')
    return keep


AIA_MISSING = 'unable to get local issuer certificate'
_AIA_FOUND = {}                 # (host, port) -> (when, the intermediates fetched for it)


def _aia_pem(data):
    """What an AIA (caIssuers) address gives - DER, PEM or PKCS#7 - as PEM certificates."""
    from acmelib.certs import pki
    data = bytes(data or b'')
    if b'-----BEGIN CERTIFICATE-----' in data:
        return ''.join(pki.certs_in(data.decode('ascii', 'replace')))
    try:
        pem = pki.der_to_pem(data)
        pki.cert_info(pem)
        return pem
    except Exception:                                   # noqa: BLE001
        pass
    try:
        got = pki.openssl(['pkcs7', '-inform', 'DER', '-print_certs'], data)
        text = got.decode('ascii', 'replace') if isinstance(got, bytes) else str(got)
        return ''.join(pki.certs_in(text))
    except Exception:                                   # noqa: BLE001
        return ''

class RunContext(base.Context):
    """The Context of acmelib/plugins/base.py, for one job (or a test).

    scope       whose little state kv_get/kv_set keep ('issuer:<name>', ...)
    job         the jobs.Job the steps go into (None: kept in .steps)
    on_hostkey  fn(known_hosts_text) - the first host key seen, to be kept
                (the target's trust_first)
    """

    def __init__(self, store, job=None, scope='', on_hostkey=None):
        self.store = store
        self.job = job
        self.scope = scope or 'any'
        # The first host key seen kept wherever the connection is set (1.0.51): only a target's
        # deployment kept it - a test, a validation over SSH and every run after took any key
        # that answered. False: kept nowhere (settings tried before they are saved).
        self.on_hostkey = scope_hostkey_keeper(store, self.scope) if on_hostkey is None \
            else (on_hostkey or None)
        self.steps = []
        self.node = E.node_name()
        self.settings = S.settings_view()
        self._stop = threading.Event()
        self.record_names = []          # dns_records written, for the cleanup at the end
        self.tokens = []
        self.children = []              # the Contexts of the modules made by validation()

    # ---- the job's log ------------------------------------------------------------------
    def step(self, words, level='info'):
        level = level if level in ('info', 'ok', 'warn', 'bad', 'debug') else 'info'
        if self.job is not None:
            if hasattr(self.job, 'ship'):               # a jobs.Job: the module named
                self.job.step(words, level, scope=self.scope)
            else:
                self.job.step(words, level)
        else:
            self.steps.append([time.time(), level, str(words)[:4000]])

    def ship(self, event, level, words, **fields):
        """A line of a module's with fields of its own for isemon (isemon_detail, 1.0.44):
        a validation, an order - in the job it works for, the module named."""
        if self.job is not None and hasattr(self.job, 'ship'):
            self.job.ship(event, level, words, scope=self.scope, **fields)

    def debug(self, words):
        # A script sent as -EncodedCommand is only base64 of it (1.0.48): the passwords in it
        # (an import's, the central store's) were in the job's steps and in isemon.
        words = re.sub(r'(?i)(-(?:EncodedCommand|enc|e|ec)\s+)[A-Za-z0-9+/=]{16,}',
                       r'\1<the script, not shown>', str(words))
        if E.CONFIG.get('debug'):
            self.step(words, 'debug')
        elif self.job is not None and hasattr(self.job, 'ship'):
            # Not kept in the job's steps without debugging on - but isemon gets it (1.0.44).
            self.job.ship('debug', 'debug', str(words)[:4000], scope=self.scope)

    def cancelled(self):
        if self._stop.is_set():
            return True
        return bool(self.job is not None and self.job.cancelled())

    def cancel(self):
        self._stop.set()

    def tidying(self):
        """What is taken away after a stop (1.0.88): a proof in DNS or on a web server, the
        copies of a key in /tmp - run although the job was stopped (they stayed for good)."""
        ctx = self

        class _T(object):
            def __enter__(self):
                ctx._tidy = getattr(ctx, '_tidy', 0) + 1

            def __exit__(self, *a):
                ctx._tidy = max(0, getattr(ctx, '_tidy', 1) - 1)
                return False
        return _T()

    # ---- HTTPS -------------------------------------------------------------------------
    shares_limits = True            # sign-ins and reads shared (acmelib/plugins/limits.py)

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True,
             ca_pem=None, client_cert=None, proxy=True, idempotent=None, retries=None):
        # (What goes on the wire is said by wire_request() below - What happens shows it.)
        """(status, {header: value}, bytes). An answer of 4xx/5xx is an answer,
        not an exception; a server that cannot be reached is a PluginError.

        Kind to the server (acmelib/plugins/limits.py): a few requests a second
        and two at once to one host at most; a host that asked to slow down is
        not asked before its time; an idempotent call (GET, HEAD, PUT, DELETE,
        or `idempotent`) answered 429 / 503 / "too many attempts" is asked again
        after the wait it asked for (else a growing one), at most `retries`
        times (limits.RETRIES) - the job told so in words."""
        from acmelib.plugins import limits as L
        if not re.match(r'^https?://', str(url or '')):
            raise base.PluginError('%r is not an http(s) address' % url, retry=False)
        if isinstance(body, str):
            body = body.encode('utf-8')
        elif isinstance(body, (dict, list)):
            body = json.dumps(body).encode('utf-8')
            headers = dict(headers or {})
            headers.setdefault('Content-Type', 'application/json')
        verb = str(method or 'GET').upper()
        if idempotent is None:
            idempotent = verb in L.IDEMPOTENT
        tries = L.RETRIES if retries is None else max(0, int(retries))
        req = urllib.request.Request(url, data=body, method=verb)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if not req.has_header('User-agent'):
            req.add_header('User-Agent', 'acme/%s' % E.__version__)
        ctx, tmp = None, None
        if url.startswith('https'):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            elif ca_pem:
                ctx = ssl.create_default_context(cadata=str(ca_pem))
            if client_cert:
                tmp = tempfile.mkdtemp(prefix='acme-http-')
                if isinstance(client_cert, (tuple, list)):
                    cert_text, key_text = client_cert[0], client_cert[1]
                elif isinstance(client_cert, dict):
                    cert_text, key_text = client_cert.get('cert'), client_cert.get('key')
                else:
                    cert_text, key_text = client_cert, None
                cf = os.path.join(tmp, 'c.pem')
                with open(os.open(cf, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as f:
                    f.write(str(cert_text))
                    if key_text:
                        f.write('\n' + str(key_text))
                try:
                    ctx.load_cert_chain(cf)
                except (ssl.SSLError, OSError) as e:
                    shutil.rmtree(tmp, ignore_errors=True)
                    raise base.PluginError('the client certificate cannot be used: %s' % e,
                                           retry=False)
        try:
            attempt = 0
            while True:
                with L.throttle(url, say=lambda w: self.step(w, 'warn'),
                                cancelled=self.cancelled, method=verb):
                    try:
                        got = self._http_once(req, url, timeout, ctx, proxy)
                    except base.PluginError as e:
                        # A server that sends its certificate without the intermediate
                        # authority (1.0.88): browsers fetch it from the certificate's AIA
                        # address, Python does not. Fetched here too, and trusted only as a
                        # link to a root of the system (no partial chains).
                        ctx2 = (self._aia_context(url, timeout, client_cert and ctx)
                                if ctx is not None and verify and not ca_pem and
                                AIA_MISSING in str(e) else None)
                        if ctx2 is None:
                            raise
                        try:
                            got = self._http_once(req, url, timeout, ctx2, proxy)
                        except base.PluginError as e2:
                            # the one kept before no longer fits (1.0.93: a renewed
                            # certificate from another intermediate - every call failed
                            # until a restart): fetched again once
                            u0 = urllib.parse.urlsplit(url)
                            if AIA_MISSING not in str(e2) or \
                                    _AIA_FOUND.pop((u0.hostname or '', u0.port or 443),
                                                   None) is None:
                                raise
                            ctx2 = self._aia_context(url, timeout, client_cert and ctx)
                            if ctx2 is None:
                                raise
                            got = self._http_once(req, url, timeout, ctx2, proxy)
                        ctx = ctx2
                wait = L.slowdown(*got)
                if wait is None:
                    return got
                pause = L.pause(attempt, wait)
                L.note_slow(url, pause)
                if not idempotent or attempt >= tries or pause > L.WAIT_MAX or \
                        self.cancelled():
                    self.step(L.slow_words(url, got[0]), 'warn')
                    return got
                self.step(L.waiting_words(url, pause, got[0]), 'warn')
                L._sleep(pause, self.cancelled)
                attempt += 1
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    def _aia_context(self, url, timeout, client_ctx=None):
        """A TLS context with the intermediates the server at url did not send, fetched from
        the AIA (caIssuers) address of its certificate - or None. The fetched ones only help
        the chain to a root of the system: a partial chain is not taken, so an intermediate
        named by anyone in between leads nowhere."""
        if client_ctx:
            return None                     # a client certificate: not rebuilt here
        u = urllib.parse.urlsplit(url)
        host, port = u.hostname or '', u.port or 443
        kept = _AIA_FOUND.get((host, port))
        pems = kept[1] if kept and time.time() - kept[0] < 86400 else None
        if pems is None:
            pems = self._aia_fetch(host, port, timeout)
            if pems:
                _AIA_FOUND[(host, port)] = (time.time(), pems)     # kept a day
        if not pems:
            return None
        ctx = ssl.create_default_context()
        ctx.verify_flags &= ~getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0)
        try:
            ctx.load_verify_locations(cadata=pems)
        except ssl.SSLError:
            return None
        return ctx

    def _aia_fetch(self, host, port, timeout):
        from acmelib.certs import pki
        try:
            leaf = ssl.get_server_certificate((host, port), timeout=min(timeout or 30, 30))
            info = pki.cert_info(leaf)
        except Exception:                               # noqa: BLE001
            return ''
        out = []
        for _ in range(3):                  # at most a few links up
            uris = [x for x in (info.get('ca_issuers') or []) if str(x).startswith('http://')
                    or str(x).startswith('https://')]
            if not uris or info.get('self_signed'):
                break
            got = ''
            for aia in uris[:2]:
                try:
                    with E.url_open(urllib.request.Request(aia, headers={
                            'User-Agent': 'acme/%s' % E.__version__}), timeout=15,
                            purpose='acme') as r:
                        data = r.read(200000)
                except Exception:                       # noqa: BLE001
                    continue
                got = _aia_pem(data)
                if got:
                    break
            if not got:
                break
            try:
                info = pki.cert_info(got)
            except Exception:                           # noqa: BLE001
                break
            if not info.get('is_ca') or info.get('self_signed'):
                break
            out.append(got)
        if out:
            self.step('%s does not send the intermediate authority with its certificate - '
                      'browsers fetch it themselves, acme fetched it too (%s); better: let '
                      'the server send its whole chain' % (
                          host, pki.cert_info(out[0]).get('subject', {}).get('CN', '?')),
                      'warn')
        return ''.join(out)

    def _http_shipped(self, method, url, began, status=None, size=None, error=None):
        """A module's HTTPS request, said to isemon (1.0.44): host, path - its query's names
        only, no value -, the answer, how long, how big."""
        job = self.job
        if job is None or not hasattr(job, 'ship'):
            return
        try:
            u = urllib.parse.urlsplit(str(url))
            q = ','.join(sorted({p.partition('=')[0] for p in u.query.split('&') if p}))
            job.ship('http', 'warn' if error or (status or 0) >= 400 else 'debug',
                     '%s %s%s -> %s' % (method, u.hostname or '', u.path or '/',
                                        error or status),
                     scope=self.scope, method=method, host=u.hostname, port=u.port,
                     path=u.path or '/', query_keys=q or None, status=status,
                     ms=int((time.time() - began) * 1000), bytes=size,
                     error=str(error)[:300] if error else None)
        except Exception:                               # noqa: BLE001
            pass

    def _http_once(self, req, url, timeout, ctx, proxy):
        self.debug('%s %s' % (req.get_method(), url_shown(url)))
        began = time.time()
        try:
            from acmelib.certs import dnssets       # the name asked of Settings → DNS
            with dnssets.scope(dnssets.purpose_of(self.scope), self.store, say=self.debug):
                got = E.url_open(req, timeout=timeout, context=ctx,
                                 purpose='acme' if proxy else '')
            with got:
                data = got.read()
                self._http_shipped(req.get_method(), url, began, got.status, len(data))
                return got.status, header_dict(got.headers), data
        except urllib.error.HTTPError as e:
            try:
                data = e.read()
            except Exception:                       # noqa: BLE001
                data = b''
            self._http_shipped(req.get_method(), url, began, e.code, len(data))
            return e.code, header_dict(e.headers), data
        except urllib.error.URLError as e:
            self._http_shipped(req.get_method(), url, began, error=getattr(e, 'reason', e))
            raise base.PluginError('%s could not be reached: %s' % (
                urllib.parse.urlsplit(url).netloc, getattr(e, 'reason', e)))
        except (OSError, ssl.SSLError) as e:
            self._http_shipped(req.get_method(), url, began, error=e)
            raise base.PluginError('%s: %s' % (urllib.parse.urlsplit(url).netloc, e))

    # ---- SSH and openssl ---------------------------------------------------------------
    def ssh(self, conn):
        return SshSession(self, conn)

    def openssl(self, args, data=None, timeout=60):
        exe = shutil.which('openssl')
        if not exe:
            raise base.PluginError('openssl is not on this machine', retry=False)
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            got = subprocess.run([exe] + [str(a) for a in args], input=data,
                                 capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise base.PluginError('openssl %s took more than %d s' % (
                args[0] if args else '', timeout))
        if got.returncode != 0:
            said = got.stderr.decode('utf-8', 'replace').strip().splitlines()
            raise base.PluginError('openssl %s: %s' % (args[0] if args else '',
                                                       ' / '.join(said[-3:])[:400]),
                                   detail=got.stderr.decode('utf-8', 'replace'))
        return got.stdout

    # ---- a little state of the module's own ---------------------------------------------
    def _kv_key(self, key):
        # a long one not cut short (1.0.80): the end that told two apart was cut away - two
        # deployments to one Azure target shared one record; the cut kept for the short ones
        key = str(key)
        if len(key) > 120:
            key = key[:56] + '~' + hashlib.sha256(key.encode()).hexdigest()
        return '%s%s:%s' % (KV_PREFIX, self.scope, key)

    def kv_get(self, key, default=None):
        raw = self.store.get_meta(self._kv_key(key))
        if raw is None and len(str(key)) > 120 and not str(key).startswith('deployed:'):
            # kept before 1.0.80 under the key cut at 120 (an ARN, a slot...) - still found;
            # never the "deployed" record, which two deployments shared that way
            raw = self.store.get_meta('%s%s:%s' % (KV_PREFIX, self.scope, str(key)[:120]))
        got = S.jload(raw, None)
        if not isinstance(got, dict):
            return default
        if got.get('exp') and float(got['exp']) < time.time():
            return default
        return got.get('v', default)

    def kv_keys(self, prefix=''):
        """{key: value} of the module's own state whose keys start with `prefix`
        (what it keeps for each certificate, say) - read-only."""
        own = self._kv_key('')
        start = own + str(prefix)
        out = {}
        # LIKE's _ and % only widen what is read; startswith() decides.
        for r in self.store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (start + '%',)):
            k = str(r.get('k') or '')
            got = S.jload(r.get('v'), None)
            if not k.startswith(start) or not isinstance(got, dict):
                continue
            if got.get('exp') and float(got['exp']) < time.time():
                continue
            out[k[len(own):]] = got.get('v')
        return out

    def kv_set(self, key, value, ttl_s=None):
        k = self._kv_key(key)
        if value is None:
            self.store.db.run('DELETE FROM meta WHERE k = ?', (k,))
            return
        self.store.set_meta(k, json.dumps({'v': value, 'exp': (time.time() + ttl_s)
                                                  if ttl_s else None}, default=str))

    # ---- acme's own DNS server ----------------------------------------------------------
    def dns_put(self, name, type, value, ttl=60):
        name = str(name).strip().rstrip('.').lower()
        rtype = str(type or 'TXT').upper()
        t = time.time()
        self.store.db.insert('dns_records', {
            'name': name, 'rtype': rtype, 'value': str(value), 'ttl': int(ttl or 60),
            'expires': t + 6 * 3600, 'created': t,
            'owner': ('job:%s' % self.job.id) if self.job is not None else self.scope,
            'note': 'put by %s' % self.scope})
        self.record_names.append((name, rtype, str(value)))
        self.step('DNS: %s %s "%s" put in acme\'s own DNS server' % (name, rtype, value))

    def dns_drop(self, name, type, value=None):
        name = str(name).strip().rstrip('.').lower()
        rtype = str(type or 'TXT').upper()
        if value is None:
            self.store.db.run('DELETE FROM dns_records WHERE name = ? AND rtype = ?',
                              (name, rtype))
        else:
            self.store.db.run('DELETE FROM dns_records WHERE name = ? AND rtype = ? AND value = ?',
                              (name, rtype, str(value)))

    # ---- HTTP-01 on this server's port 80 -----------------------------------------------
    def http_token_put(self, token, key_authorization):
        if not re.match(r'^[A-Za-z0-9_-]{8,256}\Z', str(token or '')):
            raise base.PluginError('that is not an ACME token', retry=False)
        self.store.set_meta(CHAL_PREFIX + token, json.dumps(
            {'auth': str(key_authorization), 'at': time.time()}))
        self.tokens.append(token)

    def http_token_drop(self, token):
        self.store.db.run('DELETE FROM meta WHERE k = ?', (CHAL_PREFIX + str(token),))

    def http_file_put(self, host, path, content, ttl_s=30 * 86400):
        """A commercial CA's DCV file answered on this server's port 80 for
        http://host/path (path under /.well-known/pki-validation/) - kept for days,
        not taken away when the job ends: the CA looks when it looks."""
        host = str(host or '').strip().lower().rstrip('.')
        path = str(path or '')
        if not re.match(r'^[a-z0-9_.-]{1,253}\Z', host) or \
                not re.match(r'^/\.well-known/pki-validation/[A-Za-z0-9_.-]{1,128}\Z', path) or \
                '..' in path:
            raise base.PluginError('acme answers a DCV file only under '
                                   '/.well-known/pki-validation/, not %s%s' % (host, path),
                                   retry=False)
        t = time.time()
        self.store.set_meta(file_key(host, path), json.dumps(
            {'host': host, 'path': path, 'content': str(content), 'at': t,
             'until': t + float(ttl_s or 30 * 86400)}))

    def http_file_drop(self, host, path):
        self.store.db.run('DELETE FROM meta WHERE k = ?', (file_key(host, path),))

    # ---- what a challenge's guide asks about acme ----------------------------------------
    def dns_server_info(self):
        from acmelib.certs import dnsserver
        return dnsserver.server_info(self.store)

    def own_addresses(self):
        """{'vip': the cluster's VIP address when it is on, 'nodes': the nodes' own}."""
        vip = None
        try:
            v = E.vip_conf(self.store) or {}
            if E.CONFIG.get('ha_mode') and v.get('on') and v.get('address'):
                vip = str(v['address']).split('/')[0].strip().strip('[]')
        except Exception:                               # noqa: BLE001
            vip = None
        nodes = []
        try:
            nodes = [str(n['address']).split('/')[0] for n in E.ha_nodes(self.store)
                     if n.get('address')]
        except Exception:                               # noqa: BLE001
            nodes = []
        if not nodes:
            try:
                nodes = [str(E.node_address())]
            except Exception:                           # noqa: BLE001
                nodes = []
        return {'vip': vip, 'nodes': [n for n in nodes if n and n != vip]}

    def port_open(self, proto, port):
        """Does acme's firewall let `proto` `port` in from anywhere: True, False,
        or None when acme does not keep the firewall of this machine."""
        try:
            c = E.fw_conf(self.store)
            if not c.get('set'):
                return None
            if not c.get('on'):
                return True
            rules = E.fw_rules_for(self.store, E.node_name())
        except Exception:                               # noqa: BLE001
            return None
        for r in rules:
            if (r.get('action') or 'accept') != 'accept' or r.get('source'):
                continue
            if str(r.get('proto') or 'any') not in (str(proto), 'any'):
                continue
            if port_in(port, r.get('port')):
                return True
        return False

    def http_probe(self):
        """(token, key authorization) of a probe acme answers on its own port 80
        (as an HTTP-01 answer), made once and kept fresh."""
        got = S.jload(self.store.get_meta('certs:guide_probe'), None)
        if not isinstance(got, dict) or not got.get('token') or not got.get('ka'):
            tok = 'acme-guide-' + secrets.token_hex(12)
            got = {'token': tok, 'ka': tok + '.' + secrets.token_hex(16)}
            self.store.set_meta('certs:guide_probe', json.dumps(got))
        have = S.jload(self.store.get_meta(CHAL_PREFIX + got['token']), {}) or {}
        if have.get('auth') != got['ka'] or time.time() - float(have.get('at') or 0) > 600:
            self.store.set_meta(CHAL_PREFIX + got['token'], json.dumps(
                {'auth': got['ka'], 'at': time.time()}))
        return got['token'], got['ka']

    # ---- acme push (targets/acme_push.py) ------------------------------------------------
    def push_identity(self):
        """This acme's own Ed25519 key for acme push: {'seed', 'public', 'id', 'text'} -
        made once, kept sealed in the database (every node signs with the same one)."""
        return E.push_identity(self.store)

    def push_pin(self, url, pin=None):
        """What acme keeps of the application at `url` it is paired with (or pin=...)."""
        return E.push_pin(self.store, url, pin)

    # ---- acme's own pages (targets/appliance.py) ----------------------------------------
    # Through the engine's Certificates and TLS: the profile of a node or of the
    # VIP address (meta web:tls:<where>) - each node puts its own into nginx
    # within seconds (web_tick), the VIP's whichever node holds the address.
    def pages_where(self):
        """{'node': this node, 'nodes': every node, 'cluster': bool, 'vip': {'on', 'fqdn'}}"""
        nodes = [t for t in E.tls_targets(self.store) if t != 'vip']
        v = E.vip_conf(self.store) or {}
        return {'node': E.node_name(), 'nodes': nodes, 'cluster': bool(E.CONFIG.get('ha_mode')),
                'vip': {'on': bool(v.get('on')) and bool(E.CONFIG.get('ha_mode')),
                        'fqdn': v.get('fqdn') or '', 'address': v.get('address') or ''}}

    @staticmethod
    def _pages_check(where):
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z', str(where or '')):
            raise base.PluginError('%r is not a node or vip' % where, retry=False)
        return str(where)

    def pages_get(self, where):
        """What the pages of `where` (a node, or vip) hold now, or None."""
        prof = E.tls_profile(self.store, self._pages_check(where)) or {}
        if not prof.get('cert'):
            return None
        info = prof.get('info') or {}
        alt = E.tls_alt(prof) or {}
        return {'fingerprint': str(info.get('fingerprint') or '').replace(':', '').lower(),
                'cn': info.get('cn') or '', 'not_after': info.get('not_after'),
                'subject': info.get('subject') or '', 'how': prof.get('how') or '',
                'at': prof.get('at'),
                'alt_fingerprint': str((alt.get('info') or {}).get('fingerprint') or '')
                .replace(':', '').lower()}

    def pages_put(self, where, cert_pem, key_pem, chain_pems=None, how='the certificate manager',
                  alt=None):
        """The certificate (and its key and chain) as the one of the pages of
        `where`, as Certificates and TLS would take an upload: its TLS settings
        kept, the engine's own ACME no longer renewing it. `alt` (cert_pem, key_pem,
        chain_pems): the twin of a dual certificate, the engine's second certificate
        of the pages (1.0.196) - nginx gives each client the one it takes."""
        where = self._pages_check(where)
        chain = ''.join(str(p).strip() + '\n' for p in (chain_pems or []) if str(p).strip())
        try:
            got = E.cert_bundle(cert_pem, key_pem, chain)
        except ValueError as e:
            raise base.PluginError('the pages do not take it: %s' % e, retry=False)
        info = got.get('info') or {}
        if info.get('not_after') and float(info['not_after']) < time.time():
            raise base.PluginError('the certificate has run out', retry=False)
        prof = E.tls_profile(self.store, where) or {}
        prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                    key=E.seal_secret(got['key'], 'web:tls'), info=info,
                    chain_info=got['chain_info'], root_info=got['root_info'], chain_state=got.get('chain_state'),
                    verify=got['verify'], how=str(how)[:190])
        for k in ('pending_key', 'csr', 'alt'):
            prof.pop(k, None)
        if alt:
            a_cert, a_key, a_chain = alt
            try:
                g2 = E.cert_bundle(a_cert, a_key, ''.join(str(p).strip() + '\n'
                                                          for p in (a_chain or [])
                                                          if str(p).strip()))
            except ValueError as e:
                raise base.PluginError('the pages do not take the twin: %s' % e, retry=False)
            prof['alt'] = {'cert': g2['cert'], 'chain': g2['chain'],
                           'key': E.seal_secret(g2['key'], 'web:tls'), 'info': g2['info'],
                           'for': E.tls_alt_for(got['cert'])}
        prof.setdefault('preset', 'standard')
        prof.setdefault('dh', 'none')
        by = 'certificates (%s)' % (self.scope or 'a job')
        E.tls_save(self.store, where, prof, by)
        try:
            E.acme_care_set(self.store, where, False, by, 'the certificate manager keeps it')
        except Exception as e:                          # noqa: BLE001
            self.step('the engine\'s own ACME could not be told to leave it: %s' % e, 'warn')
        self.store.add_event('settings', 'the certificate of the pages of %s is now %s (until %s), '
                             'from the certificate manager' % (
                                 'the VIP address' if where == 'vip' else where,
                                 info.get('subject') or '?',
                                 E.stamp(info.get('not_after')) if info.get('not_after') else '?'),
                             who=by)
        return {'cn': info.get('cn'), 'not_after': info.get('not_after'),
                'fingerprint': str(info.get('fingerprint') or '').replace(':', '').lower(),
                'verify': got.get('verify') or '', 'alt': bool(alt)}

    # ---- the modules a validation stands on (dns_persist.py) ----------------------------
    def acme_sources(self, names=None):
        """[(name, Issuer instance)] of the ACME sources (a module with persist_info),
        `names` only those; each with a Context of its own (scope issuer:NAME)."""
        want = set(str(n) for n in names) if names else None
        out = []
        for row in self.store.db.rows('SELECT * FROM cert_issuers ORDER BY name'):
            if want is not None and row['name'] not in want:
                continue
            cls = S.row_class('issuer', row)
            if cls is None or not callable(getattr(cls, 'persist_info', None)) or \
                    'dns-persist-01' not in (getattr(cls, 'challenge_types', None) or ()):
                continue
            ctx = RunContext(self.store, self.job, scope='issuer:%s' % row['name'])
            try:
                out.append((row['name'], S.plugin_instance(self.store, 'issuer', row, ctx)))
            except base.PluginError as e:
                self.debug('the source %s cannot be used: %s' % (row['name'], e))
        return out

    def validation(self, name):
        """Another validation by name, as the renewer makes it (None: not there or off);
        what it leaves behind is taken away with this Context's tidy()."""
        row = S.plugin_row(self.store, 'challenge', name) if name else None
        if not row or not row.get('enabled', 1) or str(row.get('enabled')) in ('0', 'False'):
            return None
        ctx = RunContext(self.store, self.job, scope='challenge:%s' % row['name'])
        self.children.append(ctx)
        return S.plugin_instance(self.store, 'challenge', row, ctx)

    def names_using(self):
        """The names of the certificates proved by this Context's validation (scope
        challenge:NAME), as the renewer chooses (store.challenge_for)."""
        if not str(self.scope).startswith('challenge:'):
            return []
        mine = self.scope.split(':', 1)[1]
        out = []
        for c in self.store.db.rows('SELECT names, challenge, challenge_map FROM certs '
                                    'ORDER BY name'):
            for n in S.jload(c.get('names'), []) or []:
                if S.challenge_for(c, n) == mine and n not in out:
                    out.append(n)
        return out

    def tidy(self):
        """Whatever the job left in the DNS server or on port 80 taken away."""
        for c in self.children:
            try:
                c.tidy()
            except Exception:                           # noqa: BLE001
                pass
        self.children = []
        for name, rtype, value in self.record_names:
            try:
                self.dns_drop(name, rtype, value)
            except Exception:                           # noqa: BLE001
                pass
        for tok in self.tokens:
            try:
                self.http_token_drop(tok)
            except Exception:                           # noqa: BLE001
                pass
        self.record_names, self.tokens = [], []


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
def hostkey_lines(text):
    """known_hosts lines with the host part made our alias: 'host type key',
    '[host]:port type key', '|1|hash type key' and a bare 'type key' alike."""
    out = []
    for line in str(text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if parts[0].startswith('@'):
            # @revoked says the key is NOT to be trusted, @cert-authority that it signs the
            # host's keys - neither is the host's key itself (1.0.51: both were taken for it)
            continue
        if len(parts) >= 2 and re.match(r'^(ssh-|ecdsa-|sk-)', parts[0]):
            typ, key = parts[0], parts[1]
        elif len(parts) >= 3:
            typ, key = parts[1], parts[2]
        else:
            continue
        try:
            base64.b64decode(key, validate=True)
        except (ValueError, TypeError):
            continue
        out.append('%s %s %s' % (HOSTKEY_ALIAS, typ, key))
    return out


def hostkey_fingerprint(line):
    parts = line.split()
    try:
        raw = base64.b64decode(parts[-1] if len(parts) == 2 else parts[2])
    except (ValueError, TypeError, IndexError):
        return '?'
    return '%s SHA256:%s' % (parts[-2] if len(parts) == 2 else parts[1],
                             base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='))


def keyscan(host, port, timeout=10):
    if not shutil.which('ssh-keyscan'):
        raise base.PluginError('ssh-keyscan is not on this machine (dnf install openssh-clients)',
                               retry=False)
    try:
        got = subprocess.run(['ssh-keyscan', '-T', str(int(timeout)), '-p', str(int(port)),
                              str(host).strip('[]')], capture_output=True, text=True,
                             timeout=timeout + 20)
    except subprocess.TimeoutExpired:
        raise base.PluginError('%s:%s showed no host key in time' % (host, port))
    lines = [x for x in got.stdout.splitlines() if x.strip() and not x.startswith('#')]
    if not lines:
        raise base.PluginError('%s:%s showed no host key: %s' % (
            host, port, ' '.join((got.stderr or '').strip().splitlines()[-1:]) or 'no answer'))
    return '\n'.join(lines) + '\n'


def ssh_options(addr, timeout, known_hosts, control, key_file=None):
    """The options every ssh of acme runs with (1.0.37: one place - SshSession and What
    happens, which shows them): this file only, the host key checked against the one
    kept, its time limits, one connection held for the commands that follow."""
    opts = ['-F', '/dev/null', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'HostKeyAlias=' + HOSTKEY_ALIAS, '-o', 'CheckHostIP=no',
            '-o', 'HostName=' + addr,
            '-o', 'ConnectTimeout=%d' % timeout,
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4',
            '-o', 'LogLevel=ERROR', '-o', 'IdentitiesOnly=yes',
            '-o', 'ControlMaster=auto', '-o', 'ControlPath=' + control,
            '-o', 'ControlPersist=120']
    opts += ['-i', key_file] if key_file else ['-o', 'IdentityFile=/dev/null']
    return opts


def ssh_auth_options(auths, asks):
    """How it signs in: the methods, in order; a secret asked for through SSH_ASKPASS."""
    return ['-o', 'PreferredAuthentications=' + ','.join(auths),
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'BatchMode=%s' % ('no' if asks else 'yes')]


class SshSession(base.SshSession):
    """ctx.ssh(conn), conn = {'host', 'port', 'user', 'password', 'key', 'key_pass',
    'hostkey', 'timeout', 'trust_first', 'scp_legacy'}.

        s.run(command, input=None, timeout=120, check=True) -> (rc, stdout, stderr)  (text)
        s.put(data, remote_path, mode=0o600, owner=None, via='shell'|'scp')
        s.get(remote_path) -> bytes
        s.close()
    put via 'shell' writes through `cat` into a file beside the one meant and
    moves it into place (whole or not at all); via 'scp' (for appliances with
    no shell: MikroTik, FortiGate) copies it with scp straight to the path."""

    def __init__(self, ctx, conn):
        self.ctx = ctx
        self.conn = dict(conn or {})
        self.d = None
        self.opts = []
        self.env = None
        self.jump = None
        try:
            self._open()
        except BaseException:
            # Whatever went wrong on the way (1.0.77): the temp folders with the private keys
            # of this server and of its connector, and the connector's held connection, gone -
            # a failed sign-in through a connector left both behind.
            self.close()
            raise

    # ---- opening -------------------------------------------------------------------------
    def _open(self):
        c = self.conn
        if not shutil.which('ssh'):
            raise base.PluginError('ssh is not on this machine (dnf install openssh-clients)',
                                   retry=False)
        self.host = str(c.get('host') or '').strip().strip('[]')
        if not self.host or not re.match(r'^[A-Za-z0-9_.:%-]{1,253}\Z', self.host) \
                or self.host.startswith('-'):
            raise base.PluginError('%r is not a host name or an address' % c.get('host'),
                                   retry=False)
        self.port = int(c.get('port') or 22)
        self.user = str(c.get('user') or 'root')
        if not re.match(r'^[A-Za-z0-9_.@\\-]{1,64}\Z', self.user) or self.user.startswith('-'):
            raise base.PluginError('%r is not an account name' % self.user, retry=False)
        self.timeout = int(c.get('timeout') or 20)
        # Through a connector (1.0.74): a Linux server of the tests' connectors signed in to
        # first, and this one reached from it (ProxyCommand ssh -W) - its name as that network
        # knows it, its host key read there.
        self.jump = self._jump(str(c.get('via') or '').strip()) if c.get('via') else None
        from acmelib.certs import dnssets               # the name asked of Settings → DNS
        self.addr = self.host if self.jump else dnssets.ssh_address(self.ctx, self.host)
        lines = hostkey_lines(c.get('hostkey'))
        if not lines:
            if self.jump:
                rc, scanned, err = self.jump.run('ssh-keyscan -T %d -p %d %s' % (
                    min(self.timeout, 15), self.port, shq(self.host)), timeout=60, check=False)
                if not hostkey_lines(scanned):
                    self.close()
                    raise base.PluginError('%s:%s showed no host key to %s: %s' % (
                        self.host, self.port, self.jump.host, (err or '').strip()[-200:] or 'no answer'))
            else:
                scanned = keyscan(self.addr, self.port, min(self.timeout, 15))
            lines = hostkey_lines(scanned)
            prints = ', '.join(hostkey_fingerprint(x) for x in lines)
            if not c.get('trust_first'):
                raise base.PluginError(
                    'the host key of %s is not trusted yet - it shows %s. Paste its known_hosts '
                    'line into the target (or switch on "trust the first key seen")'
                    % (self.host, prints), detail=scanned, retry=False)
            self.ctx.step('the host key of %s taken as the first one seen: %s'
                          % (self.host, prints), 'warn')
            if self.ctx.on_hostkey and not c.get('no_keep'):
                try:
                    # the lines kept under the host's name as set (1.0.51), not the address
                    # scanned: a validation's list of hosts finds them by that name
                    named = '\n'.join('%s %s' % (self.host, ln.split(None, 1)[1])
                                       for ln in lines if len(ln.split(None, 1)) == 2)
                    try:
                        self.ctx.on_hostkey(named or scanned, c.get('hostkey_field') or 'hostkey')
                    except TypeError:
                        self.ctx.on_hostkey(scanned)
                except Exception as e:                  # noqa: BLE001
                    self.ctx.step('the host key could not be kept: %s' % e, 'warn')
        self.d = tempfile.mkdtemp(prefix='acme-ssh-')
        kh = os.path.join(self.d, 'known_hosts')
        with open(kh, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        key = str(c.get('key') or '').strip()
        kf = None
        if key:
            kf = os.path.join(self.d, 'id')
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(key + '\n')
        self.opts = ssh_options(self.addr, self.timeout, kh, os.path.join(self.d, 'cm'), kf)
        pw = str(c.get('password') or '')
        kp = str(c.get('key_pass') or '')
        ask = os.path.join(self.d, 'ask')
        with open(ask, 'w') as f:
            f.write('#!/bin/sh\ncase "$1" in\n  *assphrase*) printf "%s\\n" "$ACME_SSH_KEYPASS";;\n'
                    '  *) printf "%s\\n" "$ACME_SSH_SECRET";;\nesac\n')
        os.chmod(ask, 0o700)
        self.env = dict(os.environ, DISPLAY=':0', SSH_ASKPASS_REQUIRE='force', SSH_ASKPASS=ask,
                        ACME_SSH_SECRET=pw or kp, ACME_SSH_KEYPASS=kp or pw)
        auths = ['publickey'] if key else []
        if pw:
            auths += ['password', 'keyboard-interactive']
        if not auths:
            self.close()
            raise base.PluginError('neither a key nor a password is set for %s' % self.host,
                                   retry=False)
        self.opts += ssh_auth_options(auths, bool(pw or kp))
        if self.jump:
            j = self.jump
            # Its connection held open as long as this session (1.0.77): with 120 s only, a long
            # session's proxy signed in to the connector again - with this server's secret.
            j.opts = [('ControlPersist=yes' if o == 'ControlPersist=120' else o) for o in j.opts]
            j.run('true', timeout=60)                   # its connection held open for the proxy
            # Never this server's secrets to the connector's ssh (1.0.77), and an IPv6 address
            # in brackets ("Bad stdio forwarding specification" without them).
            self.opts += ['-o', 'ProxyCommand=' + ' '.join(
                shq(x) for x in ['env', '-u', 'ACME_SSH_SECRET', '-u', 'ACME_SSH_KEYPASS', 'ssh'] +
                j.opts + ['-o', 'BatchMode=yes', '-p', str(j.port), '-W', '[%h]:%p', j.dest])]
            self.ctx.step('%s is reached through the connector %s (%s)' % (
                self.host, c.get('via'), j.host), 'info')
        self.dest = '%s@%s' % (self.user, self.host)
        self.rdest = '%s@[%s]' % (self.user, self.host) if ':' in self.host else self.dest

    def _jump(self, name):
        """The connector named (a test of the kind ssh_relay) signed in to."""
        store = getattr(self.ctx, 'store', None)
        # a connector of the targets (1.0.75) first, then one of the tests (1.0.74)
        fam, row = 'target', store.db.row("SELECT * FROM cert_targets WHERE name = ? AND "
                                          "kind = 'ssh_connector'", (name,)) if store else None
        if not row and store:
            fam, row = 'check', store.db.row("SELECT * FROM cert_tests WHERE name = ? AND "
                                             "kind = 'ssh_relay'", (name,))
        if not row:
            raise base.PluginError('there is no connector called %s (Targets → Connector over SSH)'
                                   % name, retry=False)
        if row.get('enabled') == 0:
            raise base.PluginError('the connector %s is switched off' % name, retry=False)
        from acmelib.plugins.targets._common import ssh_conn
        conn = ssh_conn(S.plugin_instance(store, fam, row, self.ctx))
        conn.update(via='', no_keep=True)
        return SshSession(self.ctx, conn)

    # ---- the programs --------------------------------------------------------------------
    def _exec(self, argv, data=None, timeout=120):
        if self.ctx.cancelled() and not getattr(self.ctx, '_tidy', 0):
            raise base.PluginError('the job was stopped', retry=False)
        try:
            return subprocess.run(argv, input=data, capture_output=True, timeout=timeout,
                                  env=self.env, start_new_session=True)
        except subprocess.TimeoutExpired:
            raise base.PluginError('%s on %s took more than %d s' % (argv[0], self.host, timeout))
        except OSError as e:
            raise base.PluginError('%s could not be run: %s' % (argv[0], e), retry=False)

    def tunnel(self, host, port, timeout=20):
        """A socket to host:port opened from the server (ssh -W, 1.0.32): what a test
        of a server only that network reaches goes through (checks/ssh_relay.py)."""
        import socket as _socket
        host = str(host or '').strip().strip('[]')
        if not host or not re.match(r'^[A-Za-z0-9_.:%-]{1,253}\Z', host) or host.startswith('-'):
            raise base.PluginError('%r is not a host name or an address' % host, retry=False)
        a, b = _socket.socketpair()
        argv = ['ssh'] + self.opts + ['-p', str(self.port), '-W',
                                      '[%s]:%d' % (host, int(port)) if ':' in host else
                                      '%s:%d' % (host, int(port)), self.dest]
        try:
            p = subprocess.Popen(argv, stdin=b, stdout=b, stderr=subprocess.PIPE, env=self.env,
                                 start_new_session=True)
        except OSError as e:
            a.close()
            b.close()
            raise base.PluginError('ssh could not be run: %s' % e, retry=False)
        b.close()
        a.settimeout(float(timeout))
        self._tunnels = getattr(self, '_tunnels', []) + [p]
        self.last_tunnel = p
        return a

    def tunnel_said(self, wait=2.0):
        """What ssh said about the last tunnel (a refused sign-in, a refused channel)."""
        p = getattr(self, 'last_tunnel', None)
        if p is None:
            return ''
        try:
            p.wait(wait)
        except subprocess.TimeoutExpired:
            return ''
        try:
            err = p.stderr.read() or b''
        except (OSError, ValueError):
            err = b''
        said = [x for x in err.decode('utf-8', 'replace').strip().splitlines() if x.strip()]
        return ' / '.join(said[-3:])[:400]

    def _why(self, err, rc):
        said = [x for x in err.decode('utf-8', 'replace').strip().splitlines()
                if x.strip() and not x.startswith('Warning: Permanently')]
        tail = ' / '.join(said[-3:])[:400] or 'exit %d' % rc
        if 'Host key verification failed' in tail or 'REMOTE HOST IDENTIFICATION' in tail \
                or 'host key for' in tail.lower():
            return ('%s shows another host key than the one trusted - if it was reinstalled on '
                    'purpose, put its new known_hosts line into the target' % self.host)
        if 'Permission denied' in tail:
            return '%s did not let %s in (%s)' % (self.host, self.user, tail)
        return tail

    def run(self, command, input=None, timeout=120, check=True):
        if isinstance(input, str):
            input = input.encode('utf-8')
        self.ctx.debug('ssh %s: %s' % (self.host, command))
        got = self._exec(['ssh'] + self.opts + ['-p', str(self.port), self.dest, str(command)],
                         data=input, timeout=timeout)
        out = got.stdout.decode('utf-8', 'replace')
        err = got.stderr.decode('utf-8', 'replace')
        if got.returncode == 255:
            raise base.PluginError('ssh to %s: %s' % (self.host, self._why(got.stderr, 255)))
        if check and got.returncode != 0:
            raise base.PluginError('on %s, "%s" ended with %d: %s' % (
                self.host, str(command)[:120], got.returncode,
                (err.strip() or out.strip())[-400:]), detail=err)
        return got.returncode, out, err

    def put(self, data, remote_path, mode=0o600, owner=None, via='shell'):
        if isinstance(data, str):
            data = data.encode('utf-8')
        path = str(remote_path)
        if not path or '\n' in path or '\0' in path:
            raise base.PluginError('%r is not a path' % remote_path, retry=False)
        if via == 'scp':
            local = os.path.join(self.d, 'up-' + secrets.token_hex(4))
            with open(os.open(local, os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
                f.write(data)
            argv = ['scp'] + self.opts + ['-P', str(self.port), '-q']
            if self.conn.get('scp_legacy'):
                argv.append('-O')
            got = self._exec(argv + [local, '%s:%s' % (self.rdest, path)], timeout=300)
            os.unlink(local)
            if got.returncode != 0:
                raise base.PluginError('scp to %s:%s: %s' % (self.host, path,
                                                            self._why(got.stderr, got.returncode)))
            return
        tmp = '%s.acme-%s.part' % (path, secrets.token_hex(4))
        cmd = 'umask 077 && cat > %s' % shq(tmp)
        if mode is not None:
            cmd += ' && chmod %o %s' % (int(mode), shq(tmp))
        if owner:
            if not re.match(r'^[A-Za-z0-9_.-]+(:[A-Za-z0-9_.-]+)?\Z', str(owner)):
                raise base.PluginError('%r is not an owner (user or user:group)' % owner,
                                       retry=False)
            cmd += ' && chown %s %s' % (owner, shq(tmp))
        cmd += ' && mv -f %s %s || { rm -f %s; exit 1; }' % (shq(tmp), shq(path), shq(tmp))
        self.run(cmd, input=data, timeout=300)

    def get(self, remote_path):
        got = self._exec(['ssh'] + self.opts + ['-p', str(self.port), self.dest,
                                                'cat %s' % shq(remote_path)], timeout=300)
        if got.returncode != 0:
            raise base.PluginError('%s:%s could not be read: %s' % (
                self.host, remote_path, self._why(got.stderr, got.returncode)))
        return got.stdout

    def close(self):
        for p in getattr(self, '_tunnels', None) or []:
            if p.poll() is None:
                try:
                    p.terminate()
                    p.wait(3)
                except Exception:                       # noqa: BLE001
                    pass
        self._tunnels = []
        if self.d:
            try:
                subprocess.run(['ssh'] + self.opts + ['-O', 'exit', self.dest],
                               capture_output=True, timeout=10, env=self.env)
            except Exception:                           # noqa: BLE001
                pass
            shutil.rmtree(self.d, ignore_errors=True)
            self.d = None
        if getattr(self, 'jump', None) is not None:
            j, self.jump = self.jump, None
            j.close()


def wire_request(method, url, headers=None, body=None, own=False):
    """What RunContext.http() sends, as it goes on the wire (1.0.37): the request line,
    every header in the order urllib writes them - the module's own and the ones
    added (`auto`): Accept-Encoding, Content-Length, Host, Content-Type, User-Agent,
    Connection - and the body as bytes are sent. For What happens (runplan.py).
    -> {'line', 'headers': [[name, value, auto]], 'body'}"""
    verb = str(method or 'GET').upper()
    u = urllib.parse.urlsplit(str(url))
    path = (u.path or '/') + ('?' + u.query if u.query else '')
    mine = dict(headers or {})
    if isinstance(body, (dict, list)):
        data = json.dumps(body)
        mine.setdefault('Content-Type', 'application/json')
    elif isinstance(body, bytes):
        data = body.decode('utf-8', 'replace')
    else:
        data = body
    low = {k.lower(): k for k in mine}
    out = [['Accept-Encoding', 'identity', True]]
    if data is not None:
        out.append(['Content-Length', str(len(str(data).encode('utf-8'))), True])
    out.append(['Host', u.netloc, True])
    for k, v in mine.items():
        if k.lower() not in ('content-type', 'user-agent', 'host', 'connection'):
            out.append([k, str(v), False])
    if 'content-type' in low:
        out.append([low['content-type'], str(mine[low['content-type']]),
                    isinstance(body, (dict, list)) and 'content-type' not in
                    {k.lower() for k in (headers or {})}])
    elif data is not None:
        out.append(['Content-Type', 'application/x-www-form-urlencoded', True])
    if 'user-agent' in low:
        out.append([low['user-agent'], str(mine[low['user-agent']]), False])
    elif not own:
        out.append(['User-Agent', 'acme/%s' % E.__version__, True])
    if own:
        # http.client as a module uses it itself: Host, Accept-Encoding, Content-Length of
        # its own first, then the headers as the module (or urllib) gave them, in their
        # order - nothing else added
        given = dict(headers or {})
        gl = {k.lower() for k in given}
        lines = []
        if 'host' not in gl:
            lines.append(['Host', u.netloc, True])
        if 'accept-encoding' not in gl:
            lines.append(['Accept-Encoding', 'identity', True])
        if data is not None and 'content-length' not in gl:
            lines.append(['Content-Length', str(len(str(data).encode('utf-8'))), True])
        lines += [[k, str(v), False] for k, v in given.items()]
        return {'line': '%s %s HTTP/1.1' % (verb, path), 'headers': lines, 'body': data}
    out.append(['Connection', 'close', True])
    return {'line': '%s %s HTTP/1.1' % (verb, path), 'headers': out, 'body': data}

