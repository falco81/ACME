#!/usr/bin/env python3
"""The card watched (1.0.113; 1.0.114 as the kit "card-removal-watch"): a sign-in made with a
certificate - a smart card, a YubiKey - ends (or is locked) when its card is taken out.

    python3 test/test_cert_card.py      (or python3 -m unittest test.test_cert_card)
    ACME_CARD_SHOTS=DIR      the browser's screenshots go there
    ACME_CARD_CS=FILE        {English: Czech} merged into the copy's cs.json (the Czech pages)

test/test_cert_login.py's PKI, directory and daemon (its setup borrowed, none of its tests run).
The kit's t_card.py, ui_card.js and t_cert_ha excerpt, ported:
  - off (the default): nothing new - no key `card` in any answer, whoami's keys as before, the
    check's routes 404, nginx's server of the certificate's port byte for byte as before, the
    pages' CSP as before; only the fingerprint kept in the sign-in's row;
  - the check (/api/certlogin/alive, as the page's picture on the certificate's port relays
    nginx's certificate): the same certificate - alive; another - ended at once (every mode);
    none or nginx's refusal - signed out (signout) or out and waiting (grace: every request but
    the check 423, code card) and back when the card is, ended past the grace;
  - the page's "the picture got nothing" (/api/certlogin/lost): held or ended, said in the events,
    only while the port is served here, its own sign-in only;
  - asleep is not out: no check for long - held (423), not ended; a check lets it go;
  - switched on, the certificate's sign-ins made before are watched (those of 1.0.113 end);
  - the settings: the ranges, "lock" taken as grace, the stale setting of 1.0.113 taken and left
    out, the card's facts;
  - nginx: every inherited ssl_session_* dropped, no TLS session, no connection kept, the check
    let through - and a real nginx with php-fpm and client certificates: off as before (a TLS
    1.2 session taken up again), on after a reload has settled (openssl -reconnect: all New;
    TLS 1.3 no ticket taken up), the picture's widths, no CORS, another site refused;
  - Chromium (Playwright, a client certificate): the notice (design B), its countdown, back in
    time, not back in time, signout, two tabs, Czech, a phone's width, the settings;
  - two daemons on one database (a cluster's shared database simulated) and a restart: a check
    on one node, the questions on the other;
  - a browser that cannot be checked (the kit's 3rd edition - a safety net since its 4th, which
    found the "iPad" was a CSP header blocking the check): never found in the
    background - not watched (allow, an event with why, 7 px, never held, whoami without card) or
    signed out (signout); found once - a card taken out as always; no cookie - 6 px and its reason;
    in Chromium the background's picture failing while the sign-in works - the notice;
  - 1.0.115, the kit's 4th edition: a check left waiting over 4 s (the card out for a proven
    browser only), one the page's policy blocked (said, never a verdict), no word before root has
    confirmed the port, a change of the mode counting afresh, a held sign-in given nothing of the
    person, F5 on from the server's clock, an IPv6 page's policy `https:`; in Chromium the hint,
    F5, waiting, a second policy header, ended on the server meanwhile;
  - 1.0.115 (hunt P): only "no answer at all" makes "cannot be checked", never for a sign-in held,
    out, or made before the watch was on; watched again once a check finds the card; the doer
    of a stricter rule watched; the port's check only for this name's page (Origin, CORS); nginx's
    429 / 5xx "try later" (8 px) and a limit of the checks' own.
"""
import http.client
import importlib.util
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_cert_login as TCL       # noqa: E402

HOST = TCL.HOST
SHOTS = os.environ.get('ACME_CARD_SHOTS', '')       # where the browser's screenshots go, if set
CS_EXTRA = os.environ.get('ACME_CARD_CS', '')       # {English: Czech} merged into the copy's cs.json


def load_web(tag):
    spec = importlib.util.spec_from_file_location('acme_web_' + tag,
                                                  os.path.join(ROOT, 'deploy', 'acme_web.py'))
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    return w


def head_web():
    """deploy/acme_web.py as the last commit before the card was watched has it (1.0.112's) -
    None where git cannot say."""
    log = subprocess.run(['git', 'log', '--format=%H', '-n', '40', '--', 'deploy/acme_web.py'],
                         cwd=ROOT, capture_output=True, text=True)
    got = None
    for h in log.stdout.split() if log.returncode == 0 else []:
        one = subprocess.run(['git', 'show', '%s:deploy/acme_web.py' % h], cwd=ROOT,
                             capture_output=True, text=True)
        if one.returncode == 0 and 'The card watched (1.0.113)' not in one.stdout:
            got = one
            break
    if got is None:
        return None
    d = tempfile.mkdtemp(prefix='acme-web-head-')
    p = os.path.join(d, 'acme_web.py')
    with open(p, 'w') as f:
        f.write(got.stdout)
    spec = importlib.util.spec_from_file_location('acme_web_head', p)
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    shutil.rmtree(d, ignore_errors=True)
    return w


@unittest.skipUnless(shutil.which('openssl'), 'no openssl here')
class CardWatch(unittest.TestCase):
    pass


# test_cert_login's setup and helpers, none of its tests.
for _k, _v in TCL.CertLogin.__dict__.items():
    if not _k.startswith('test') and _k not in ('__dict__', '__weakref__', '__module__', '__doc__'):
        setattr(CardWatch, _k, _v)


_SETUP = CardWatch.__dict__['setUpClass']


@classmethod
def _setup_drained(cls):
    """test_cert_login's setup, and the daemon's output read as it comes: left in its pipe, the
    daemon stopped in the middle of writing a line once the pipe was full (64 KiB of log - the
    later tests of this file got there), and every thread that logged with it."""
    _SETUP.__func__(cls)
    d = getattr(cls, 'daemon', None)
    if d is not None and d.stdout is not None:
        def drain(f=d.stdout):
            try:
                while f.read1(65536):
                    pass
            except (OSError, ValueError):
                pass
        threading.Thread(target=drain, name='daemon-out', daemon=True).start()


CardWatch.setUpClass = _setup_drained


def _t(fn):
    setattr(CardWatch, fn.__name__, fn)
    return fn


class _Serving:
    """Something answering on the certificate's port that takes every connection and closes it
    (test_cert_login's listens with a backlog of 8 and never accepts: the daemon's cl_listening()
    filled the queue, then read the port as down - 'unknown' - a flaky test)."""

    def __init__(self, lsn):
        self.lsn = lsn
        self.stop = threading.Event()
        self.th = threading.Thread(target=self.run, daemon=True)
        self.th.start()

    def run(self):
        self.lsn.settimeout(0.2)
        while not self.stop.is_set():
            try:
                c, _a = self.lsn.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                c.close()
            except OSError:
                pass

    def close(self):
        self.stop.set()
        self.th.join(5)
        self.lsn.close()


def serving(self, port=8443, path='/api/health'):
    lsn = socket.socket()
    lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsn.bind(('127.0.0.1', port))
    lsn.listen(128)
    srv = _Serving(lsn)
    on = False
    for _ in range(30):
        st, h = self.call('GET', path)
        on = bool((h.get('certlogin') or {}).get('on'))
        if (h.get('certlogin') or {}).get('ready') or not on:
            break
        time.sleep(0.5)
    # ...and this node's published state says so (cl_tick, every 15 s): until then a part
    # switched on is refused - "port 8443 is used by python3" (this very listener).
    for _ in range(40 if on else 0):
        if self.py('print(json.dumps(bool(E.cl_node_state(st, E.node_name()).get("listening"))))'):
            break
        time.sleep(1)
    return srv


CardWatch.serving = serving


def no_root_folder(self):
    """The test daemon has no root helper's folder (state/web), as always: with it there, the
    daemon's rounds ask root for the firewall, the trusted roots and the rest and wait minutes for
    an answer that never comes here - and what listens on the port is then all the daemon knows of
    it (1.0.115: see lost_root for root's word)."""
    shutil.rmtree(os.path.join(self.tmp, 'state', 'web'), ignore_errors=True)


CardWatch.no_root_folder = no_root_folder


def lost_root(self, token, why, said):
    """The page's word over 443 (/api/certlogin/lost) as the daemon takes it while root's status
    says `said` and the port listens - asked of the engine in a process of its own (root's status
    folder is never made for the test daemon: with it there, the daemon's rounds ask root for the
    firewall, the trusted roots and the rest and wait on it for minutes). Its state."""
    return self.py('import tempfile\nE.WEB_DIR = E.Path(tempfile.mkdtemp())\n'
                   'E.cl_listening = lambda p: True\nE.web_status = lambda: %r\n'
                   'class H:\n'
                   '    store = st\n'
                   '    route_path = "/api/certlogin/lost"\n'
                   '    headers = {"X-Acme-Session": %r}\n'
                   '    def body(self): return {"part": "admin", "v": 2, "why": %r}\n'
                   '    def client_ip(self): return "127.0.0.1"\n'
                   'print(json.dumps(E._certlogin_lost(H()).get("state")))' % (said, token, why))


CardWatch.lost_root = lost_root


def alive(self, token, cert=None, part='admin', failed=''):
    body = {'part': part}
    if cert:
        body['cert'] = self.pem(cert)
    if failed:
        body['failed'] = failed
    return self.call('POST', '/api/certlogin/alive', body, token)


def proven(self, token, cert='nested', part='admin'):
    """A check in the background that found the card (1.0.114): this browser can be checked -
    from now on a check without the card is a card taken out (before it, one that cannot be)."""
    st, got = self.alive(token, cert, part=part)
    self.assertEqual((st, got.get('state')), (200, 'ok'), got)
    self.assertGreater(float(self.session_data(token).get('card_ok') or 0), 0)


def card_on(self, part='admin', **kv):
    self.put()
    self.on(**dict({part + '_certlogin': 1, part + '_certlogin_card_watch': 'signout',
                    part + '_certlogin_card_every': 5}, **kv))


def card_off(self):
    self.no_root_folder()
    self.on(admin_certlogin_card_watch='off', portal_certlogin_card_watch='off',
            admin_certlogin_card_grace=30, admin_certlogin_card_every=15,
            portal_certlogin_card_every=15, portal_certlogin_card_grace=30,
            admin_certlogin_card_unable='allow', portal_certlogin_card_unable='allow',
            admin_certlogin=0, portal_certlogin=0)


def session_data(self, token):
    return self.py('import hashlib\nr = st.db.row("SELECT data, created FROM sessions WHERE '
                   'token_hash = ?", (hashlib.sha256(%r.encode()).hexdigest(),))\n'
                   'print(json.dumps(None if not r else dict(json.loads(r["data"] or "{}"), '
                   '_created=r["created"])))' % token)


def session_set(self, token, **kv):
    """Keys of a session's data (and `created`) set as if time had gone by."""
    created = kv.pop('created', None)
    self.py('import hashlib\nth = hashlib.sha256(%r.encode()).hexdigest()\n'
            'r = st.db.row("SELECT id FROM sessions WHERE token_hash = ?", (th,))\n'
            'st.session_merge(r["id"], %r)\n'
            'if %r is not None: st.db.run("UPDATE sessions SET created = ? WHERE id = ?", (%r, r["id"]))\n'
            'print("1")' % (token, kv, created, created))


def page_csp(self, token, host=HOST):
    """The CSP of /admin/ through php -S: signed out, and signed in with `token` - the page
    opened by `host` (its Host header)."""
    web = tempfile.mkdtemp(prefix='acme-card-web-')
    shutil.rmtree(web)
    shutil.copytree(os.path.join(ROOT, 'web'), web)
    api_php = os.path.join(web, 'acme-api.php')
    with open(api_php, encoding='utf-8') as f:
        text = f.read()
    with open(api_php, 'w', encoding='utf-8') as f:
        f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
    with open(os.path.join(web, 'router.php'), 'w') as f:
        f.write("<?php\n$_SERVER['HTTPS'] = 'on';\nchdir(__DIR__ . '/admin'); require __DIR__ . '/admin/index.php'; return true;\n")
    port = TCL.free_port()
    php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port, 'router.php'], cwd=web,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = []
    try:
        for _ in range(50):
            if self._open(port):
                break
            time.sleep(0.1)
        for cookie in ('', '__Host-acme_session=' + token):
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=60)
            conn.request('GET', '/admin/', headers=dict({'Host': host}, **({'Cookie': cookie} if cookie else {})))
            r = conn.getresponse()
            out += [v for k, v in r.getheaders() if k.lower() == 'content-security-policy']
            r.read()
            conn.close()
    finally:
        php.terminate()
        php.wait(10)
        shutil.rmtree(web, ignore_errors=True)
    return out


for _f in (alive, proven, card_on, card_off, session_data, session_set, page_csp):
    setattr(CardWatch, _f.__name__, _f)


@_t
def test_01_off_changes_nothing(self):
    """Off (the default): no key `card` in any answer, the check's routes 404, certlogin_desired
    without `watch` - nginx's server, the pages' CSP and whoami's shape as before. Only the
    certificate's fingerprint is kept in the sign-in's own row (1.0.114: switched on later, the
    sign-in is watched from then on)."""
    got = self.py('print(json.dumps([E.DEFAULTS[p + "_certlogin_card_" + k] for p in ("admin", '
                  '"portal") for k in ("watch", "every", "grace", "unable")]))')
    self.assertEqual(got, ['off', 15, 30, 'allow'] * 2)
    self.assertEqual(self.py('print(json.dumps([k for k in E.DEFAULTS if k.endswith("_card_stale")]))'), [])
    self.put()
    self.on(admin_certlogin=1, portal_certlogin=1)
    try:
        st, got = self.sign('admin', 'nested')
        self.assertEqual(st, 200, got)
        tok = got['token']
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertNotIn('card', me['who'])
        self.assertEqual(me['who']['how'], 'certificate')
        # whoami's shape: the keys it had before the card was watched (1.0.112's), no more.
        self.assertEqual(sorted(me['who']), sorted(['name', 'role', 'source', 'display', 'must_change',
                                                    'prefs', 'perf_meter', 'passkeys_on', 'cols',
                                                    'cols_edit', 'how', 'password_off']))
        self.assertEqual(sorted(me), ['idle_min', 'ok', 'who'])
        data = self.session_data(tok)
        self.assertRegex(data['card'], r'^[0-9a-f]{64}$')
        for no in ('card_seen', 'card_out', 'card_at', 'card_lock', 'card_ok'):
            self.assertNotIn(no, data)
        # A password's sign-in keeps nothing of the kind.
        self.assertNotIn('card', self.session_data(self.admin))
        v = self.ok('GET', '/api/certlogin', session=self.ro)
        for part in ('admin', 'portal'):
            self.assertNotIn('card', v['parts'][part])
        st, got = self.alive(tok, 'nested')
        self.assertEqual(st, 404, got)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, tok)
        self.assertEqual(st, 404, got)
        # Nothing held, nothing ended, however long nobody checked.
        self.session_set(tok, created=time.time() - 3600)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        st, got = self.sign('portal', 'falco')
        self.assertEqual(st, 200, got)
        ptok = got['token']
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertNotIn('card', me['me'])
        # 1.0.115 (the kit's 4th edition), off: the portal's `me`, /api/auth/mfa and the
        # portal's password change answer as before - nothing held, nothing trimmed.
        self.assertEqual(sorted(me['me']), ['about', 'display', 'help', 'idle_min', 'kind', 'must_change', 'name',
                                            'role', 'sees_all', 'sso', 'sso_logout', 'title'])
        st, got = self.call('GET', '/api/auth/mfa', None, tok)
        self.assertEqual(st, 200, got)
        self.assertEqual(sorted(got), ['dest', 'digits', 'display', 'kind', 'methods', 'name', 'ok',
                                       'passkey_hosts', 'stage', 'started'])
        self.assertEqual((got['name'], got['display']), ('nested', 'Nested Person'))
        st, got = self.call('POST', '/api/portal/password', {'old': 'x', 'new': 'y', 'again': 'y'}, ptok)
        self.assertEqual(st, 400, got)
        self.assertIn('directory password', got['error'])
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertNotIn('watch', want)
        W = load_web('off')
        c = W.certlogin_checked(want)
        self.assertNotIn('watch', c)
        # ...root's status of the port as before: no `watch` (the daemon takes no word of a
        # failed check without it - only while watched).
        self.assertEqual(W.certlogin_now(c), {'port': c['port'], 'busy': ''})
        self.assertEqual(W.certlogin_now(dict(c, watch=True)), {'port': c['port'], 'busy': '', 'watch': True})
        # ...and a settings save that leaves the watch off writes nothing into the sign-ins.
        raw = self.py('import hashlib\nprint(json.dumps(st.db.value("SELECT data FROM sessions WHERE '
                      'token_hash = ?", (hashlib.sha256(%r.encode()).hexdigest(),))))' % tok)
        self.on(admin_certlogin_card_watch='off', admin_certlogin_card_every=20)
        self.on(admin_certlogin_card_every=15)
        self.assertEqual(self.py('import hashlib\nprint(json.dumps(st.db.value("SELECT data FROM sessions WHERE '
                                 'token_hash = ?", (hashlib.sha256(%r.encode()).hexdigest(),))))' % tok), raw)
        self.assertEqual(self.events('count afresh'), [])
        # The packaged nginx configuration sends no policy header of its own (a browser given two
        # holds to both - the kit's 4th edition's key fix): one added here would block the check.
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            self.assertNotRegex(re.sub(r'(?m)#.*$', '', f.read()), r'(?i)add_header\s+Content-Security-Policy')
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            main = f.read()
        text = W.certlogin_text(main, None, c)
        for no in ('ssl_session_cache      off', 'keepalive_timeout', 'cert-alive'):
            self.assertNotIn(no, text)
        self.assertIn('ssl_session_cache', text)        # the 443 server's, kept as before
        self.assertIn('http2', text)
        H = head_web()
        if H is not None and hasattr(H, 'certlogin_text'):
            # Byte for byte what the last commit before the card was watched wrote.
            self.assertEqual(text, H.certlogin_text(main, None, H.certlogin_checked(want)))
        # The sweep does nothing while no part watches the card.
        self.assertEqual(self.py('print(json.dumps(E.cl_card_sweep(st)))'), 0)
        # The pages' Content-Security-Policy as before - a certificate's sign-in's too.
        if shutil.which('php'):
            csp = self.page_csp(tok)
            self.assertEqual(len(csp), 2, csp)
            for one in csp:
                self.assertRegex(one, r"^default-src 'self'; script-src 'self' 'nonce-[A-Za-z0-9+/=]+'; "
                                      r"style-src 'self' 'unsafe-inline'; style-src-elem 'self' "
                                      r"'nonce-[A-Za-z0-9+/=]+'; img-src 'self' data:; connect-src 'self'; "
                                      r"font-src 'self'; object-src 'none'; base-uri 'none'; "
                                      r"form-action 'self'; frame-ancestors 'none'$")
    finally:
        self.card_off()


@_t
def test_02_signed_out_when_taken_out(self):
    self.card_on()
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        data = self.session_data(tok)
        self.assertRegex(data['card'], r'^[0-9a-f]{64}$')
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertEqual(me['who']['card'], {'watch': 'signout', 'every': 5, 'grace': 30, 'port': 8443,
                                             'locked': False, 'left': 30, 'stale': False})
        # The same card: alive - and the check is no activity of the person (last untouched).
        last = self.py('print(json.dumps(st.db.value("SELECT MAX(last) FROM sessions WHERE '
                       'kind = \'admin\'")))')
        st, got = self.alive(tok, 'nested')
        self.assertEqual((st, got['state']), (200, 'ok'), got)
        self.assertTrue(self.session_data(tok).get('card_seen'))
        # The state is in the sign-in's row - nothing of it in `meta` (1.0.114).
        self.assertEqual(self.py('print(json.dumps(st.db.value("SELECT COUNT(*) FROM meta WHERE '
                                 'k LIKE \'certlogin:card%\'")))'), 0)
        # Another certificate of the same authority (falco's) with nested's sign-in: ended.
        st, got = self.alive(tok, 'falco')
        self.assertEqual((st, got['state'], got['why']), (200, 'gone', 'other'), got)
        self.assertIsNone(self.session_data(tok))
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 401)
        self.assertTrue(any('nested was signed out of these pages' in w and
                            'another certificate than the one signed in with was offered' in w
                            for w in self.events('another certificate than')))
        # Asked again: no such sign-in (the page's own word says why, not the server).
        st, got = self.alive(tok, 'nested')
        self.assertEqual(got['state'], 'none', got)
        # No certificate at all, and nginx's own refusal: taken out.
        for cert, failed in ((None, ''), ('nested', 'FAILED:certificate has expired')):
            st, got = self.sign('admin', 'nested')
            tok = got['token']
            self.proven(tok)
            st, got = self.alive(tok, cert, failed=failed)
            self.assertEqual((got['state'], got['why']), ('gone', 'out'), (cert, got))
            self.assertIsNone(self.session_data(tok))
        self.assertTrue(any('the card they signed in with was taken out' in w
                            for w in self.events('was taken out')))
        # A token that never was: none.
        st, got = self.alive('x' * 43, 'nested')
        self.assertEqual(got['state'], 'none', got)
        self.assertTrue(last is None or isinstance(last, (int, float)))
    finally:
        self.card_off()


@_t
def test_03_grace_and_back(self):
    # 1.0.113's word "lock" still taken: kept as grace.
    self.card_on(admin_certlogin_card_watch='lock', admin_certlogin_card_grace=30)
    try:
        self.assertEqual(self.py('print(json.dumps(E.CONFIG["admin_certlogin_card_watch"]))'), 'grace')
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.proven(tok)
        st, got = self.alive(tok, None)
        self.assertEqual((got['state'], got['left'], got['grace']), ('locked', 30, 30), got)
        # Out: nothing answered but the check, whoami and Sign out - 423, code card.
        st, got = self.call('GET', '/api/status', None, tok)
        self.assertEqual((st, got.get('code')), (423, 'card'), got)
        self.assertIn('put back the card you signed in with', got['error'])
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertTrue(me['who']['card']['locked'])
        self.assertEqual(me['who']['role'], '')             # the PHP pages' gates refuse it
        self.assertLessEqual(me['who']['card']['left'], 30)
        self.assertTrue(any('nested: the card they signed in with is out - the sign-in to these '
                            'pages waits 30 s for it' in w for w in self.events('waits 30 s')))
        # A second check without it does not start the time again.
        st, got = self.alive(tok, None)
        self.assertEqual(got['state'], 'locked')
        # The card back: on as before.
        st, got = self.alive(tok, 'nested')
        self.assertEqual((got['state'], got.get('resumed')), ('ok', True), got)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertEqual(me['who']['role'], 'fulladmin')
        self.assertTrue(any('the card they signed in with is back' in w for w in self.events('is back')))
        # Out again, past the grace: the next check without it ends it (not put back in time)...
        self.alive(tok, None)
        self.assertTrue(self.session_data(tok).get('card_out'))
        self.session_set(tok, card_out=time.time() - 31)
        st, got = self.alive(tok, None)
        self.assertEqual((got['state'], got['why']), ('gone', 'late'), got)
        # ...and a question does too once the check that would have said it is late as well.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.proven(tok)
        self.alive(tok, None)
        self.session_set(tok, card_out=time.time() - 40)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        self.session_set(tok, card_out=time.time() - 200)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 401)
        self.assertTrue(any('not put back in time' in w for w in self.events('not put back in time')))
        # Another card while out: ended at once, as in every mode.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.proven(tok)
        self.alive(tok, None)
        st, got = self.alive(tok, 'falco')
        self.assertEqual((got['state'], got['why']), ('gone', 'other'), got)
        # 1.0.113's names in a sign-in's row (card_lock, card_at) still read.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.session_set(tok, card_lock=time.time() - 5)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        st, got = self.alive(tok, 'nested')
        self.assertEqual(got['state'], 'ok', got)
        data = self.session_data(tok)
        self.assertNotIn('card_lock', data)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        # The portal: its own switch, the same way.
        self.on(portal_certlogin=1, portal_certlogin_card_watch='grace')
        st, got = self.sign('portal', 'falco')
        ptok = got['token']
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertEqual(me['me']['card']['watch'], 'grace')
        self.proven(ptok, 'falco', 'portal')
        st, got = self.alive(ptok, None, part='portal')
        self.assertEqual(got['state'], 'locked')
        st, got = self.call('GET', '/api/portal/certs', None, ptok)
        self.assertEqual((st, got.get('code')), (423, 'card'), got)
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertTrue(me['me']['card']['locked'])
        self.assertEqual(me['me']['role'], '')
        st, got = self.alive(ptok, 'falco', part='portal')
        self.assertEqual(got['state'], 'ok')
        self.assertNotEqual(self.call('GET', '/api/portal/certs', None, ptok)[0], 423)
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertFalse(me['me']['card']['locked'])
        # The administration's sign-in is no portal's: the admin's token checked as the portal's.
        st, got = self.sign('admin', 'nested')
        st, got = self.alive(got['token'], 'nested', part='portal')
        self.assertEqual(got['state'], 'none', got)
    finally:
        self.card_off()


@_t
def test_04_passwords_untouched(self):
    """A password's sign-in is never watched: no `card`, the check says unwatched, nothing held."""
    self.card_on(admin_certlogin_card_watch='grace')
    try:
        tok = self.login('viewer')
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertNotIn('card', me['who'])
        for cert in ('nested', None, 'falco'):
            st, got = self.alive(tok, cert)
            self.assertEqual(got['state'], 'unwatched', got)
        lsn = self.serving()
        try:
            st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, tok)
            self.assertEqual(got['state'], 'unwatched', got)
        finally:
            lsn.close()
        self.session_set(tok, created=time.time() - 3600)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.assertEqual(self.py('E.CL_CARD_SWEEP["at"] = 0\nE.cl_card_sweep(st)\n'
                                 'print(json.dumps(1))'), 1)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
    finally:
        self.card_off()


@_t
def test_05_asleep_is_held_not_ended(self):
    """A page that stopped checking (an iPad asleep): no check for late + grace + max(every, 30)
    - held (423), not signed out; a check that finds the card lets it go, one that does not
    counts as the card taken out."""
    self.card_on(admin_certlogin_card_watch='grace', admin_certlogin_card_grace=30)
    try:
        late = self.py('print(json.dumps([E.cl_card_late("admin"), E.cl_card_every("admin")]))')
        self.assertEqual(late, [150, 5])
        hold = 150 + 30 + 30
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        # Its first question starts the watch (card_seen).
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.assertTrue(self.session_data(tok).get('card_seen'))
        self.session_set(tok, card_seen=time.time() - hold + 15)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.session_set(tok, card_seen=time.time() - hold - 5)
        st, got = self.call('GET', '/api/status', None, tok)
        self.assertEqual((st, got.get('code')), (423, 'card'), got)
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertEqual((me['who']['name'], me['who']['role']), ('nested', ''))
        self.assertTrue(me['who']['card']['stale'])
        self.assertFalse(me['who']['card']['locked'])
        # Not ended by the sweep either, however long (the idle time ends it as any other).
        self.session_set(tok, card_seen=time.time() - 3000)
        self.assertEqual(self.py('E.CL_CARD_SWEEP["at"] = 0\nprint(json.dumps(E.cl_card_sweep(st)))'), 0)
        self.assertIsNotNone(self.session_data(tok))
        # The page wakes, its check finds the card: answered again.
        st, got = self.alive(tok, 'nested')
        self.assertEqual(got['state'], 'ok', got)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        # Held, and the check finds no card: out (grace - the time counted).
        self.session_set(tok, card_seen=time.time() - 3000)
        st, got = self.alive(tok, None)
        self.assertEqual(got['state'], 'locked', got)
        st, got = self.alive(tok, 'nested')
        # Sign out at once: held, then no card - ended as taken out.
        self.on(admin_certlogin_card_watch='signout')
        self.session_set(tok, card_seen=time.time() - 3000)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        st, got = self.alive(tok, None)
        self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
        # A setting of 1.0.113 for this ("No check of the card for") is taken, and left out.
        got = self.cli('--set', 'admin_certlogin_card_stale=60')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(self.py('print(json.dumps(st.db.value("SELECT COUNT(*) FROM settings '
                                 'WHERE k LIKE \'%card_stale%\'")))'), 0)
    finally:
        self.card_off()


@_t
def test_06_lost_only_while_served(self):
    """The page's picture got nothing at all (the handshake failed): the page says so over 443 -
    taken as the card out only while this node serves the port; it ends or holds the caller's
    own sign-in only, and the events say why."""
    self.card_on()
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.not_serving()
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, tok)
        self.assertEqual(got['state'], 'unknown', got)
        self.assertIsNotNone(self.session_data(tok))
        lsn = self.serving()
        try:
            self.proven(tok)
            st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, tok)
            self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
            self.assertIsNone(self.session_data(tok))
            self.assertTrue(any('was taken out' in w and 'the check got no answer at all' in w
                                for w in self.events('got no answer at all')))
            # grace: held, the time counted - the server answers nothing of it meanwhile.
            self.on(admin_certlogin_card_watch='grace')
            st, got = self.sign('admin', 'nested')
            tok = got['token']
            other = self.sign('admin', 'nested')[1]['token']
            self.proven(tok)
            st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, tok)
            self.assertEqual(got['state'], 'locked', got)
            self.assertTrue(0 < got['left'] <= 30, got)
            self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
            # ...its own sign-in only.
            self.assertEqual(self.call('GET', '/api/status', None, other)[0], 200)
            # Not signed in: nothing.
            st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, 'y' * 43)
            self.assertEqual(got['state'], 'none', got)
        finally:
            lsn.close()
    finally:
        self.card_off()


@_t
def test_07_switched_on_watches_the_ones_before(self):
    """Switched on: a certificate's sign-in made before kept its card's fingerprint (1.0.114) -
    watched from then on, not ended; one of 1.0.113 kept none - it ends; the password's of
    whoever switched it on stays."""
    self.put()
    self.on(admin_certlogin=1)
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = self.sign('admin', 'nested')
        old = got['token']
        self.session_set(old, card=None)                 # as 1.0.113 made it with the card off
        st, got = self.settings(admin_certlogin_card_watch='signout')
        self.assertEqual(st, 200, got)
        self.assertIsNotNone(self.session_data(tok))
        self.assertIsNone(self.session_data(old))
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertEqual(me['who']['card']['watch'], 'signout')
        self.assertEqual(self.call('GET', '/api/status', None, self.admin)[0], 200)
        self.assertTrue(any('the card watched' in w for w in self.events('the card watched')))
        # grace and the times changed while on: no sign-in ends for that.
        st, got = self.settings(admin_certlogin_card_watch='grace', admin_certlogin_card_every=30)
        self.assertEqual(st, 200, got)
        self.assertIsNotNone(self.session_data(tok))
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertEqual((me['who']['card']['watch'], me['who']['card']['every']), ('grace', 30))
        # Off again: not watched - the sign-in goes on, the check is 404.
        st, got = self.settings(admin_certlogin_card_watch='off')
        self.assertIsNotNone(self.session_data(tok))
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertNotIn('card', me['who'])
        self.assertEqual(self.alive(tok, None)[0], 404)
    finally:
        self.card_off()


@_t
def test_08_settings_and_the_card(self):
    self.put()
    self.on(admin_certlogin=1)
    try:
        for k, bad in (('admin_certlogin_card_watch', 'maybe'), ('admin_certlogin_card_every', '4'),
                       ('admin_certlogin_card_every', '301'), ('admin_certlogin_card_grace', '4'),
                       ('admin_certlogin_card_grace', '601'), ('portal_certlogin_card_every', 'x'),
                       ('admin_certlogin_card_unable', 'maybe'), ('portal_certlogin_card_unable', 'off')):
            st, got = self.settings(**{k: bad})
            self.assertEqual(st, 400, (k, got))
            if 'number' not in got.get('error', ''):
                self.assertIn(k, got.get('error', ''))
        got = self.cli('--set', 'admin_certlogin_card_watch=lock')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        got = self.cli('--set', 'admin_certlogin_card_grace=120')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        for _ in range(40):
            v = self.ok('GET', '/api/certlogin', session=self.ro)
            if (v['parts']['admin'].get('card') or {}).get('grace') == 120:
                break
            time.sleep(0.5)
        self.assertEqual(v['parts']['admin']['card'], {'watch': 'grace', 'every': 15, 'grace': 120,
                                                        'unable': 'allow', 'sessions': 0})
        self.assertNotIn('card', v['parts']['portal'])
        st, got = self.sign('admin', 'nested')
        v = self.ok('GET', '/api/certlogin', session=self.ro)
        self.assertEqual(v['parts']['admin']['card']['sessions'], 1)
        s = {x['key']: x for x in self.ok('GET', '/api/settings')['settings']}
        self.assertEqual(s['admin_certlogin_card_watch']['value'], 'grace')     # "lock" kept as grace
        self.assertEqual(s['admin_certlogin_card_watch']['choices'], ['off', 'signout', 'grace'])
        self.assertEqual((s['admin_certlogin_card_every'].get('min'), s['admin_certlogin_card_every'].get('max')), (5, 300))
        self.assertEqual((s['admin_certlogin_card_grace'].get('min'), s['admin_certlogin_card_grace'].get('max')), (5, 600))
        self.assertNotIn('admin_certlogin_card_stale', s)
        # A browser that cannot be checked (1.0.114): allow (the default) or signout.
        for part in ('admin', 'portal'):
            u = s[part + '_certlogin_card_unable']
            self.assertEqual((u['value'], u['choices']), ('allow', ['allow', 'signout']))
        got = self.cli('--set', 'admin_certlogin_card_unable=signout')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        for _ in range(40):
            v = self.ok('GET', '/api/certlogin', session=self.ro)
            if (v['parts']['admin'].get('card') or {}).get('unable') == 'signout':
                break
            time.sleep(0.5)
        self.assertEqual(v['parts']['admin']['card']['unable'], 'signout')
        # In the exported configuration (acme --export-config) as any other changed setting.
        exp = os.path.join(self.tmp, 'card-export.json')
        got = self.cli('--export-config', exp)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        with open(exp, encoding='utf-8') as f:
            self.assertEqual(json.load(f)['config']['settings'].get('admin_certlogin_card_unable'), 'signout')
        st, got = self.settings(admin_certlogin_card_unable='allow')
        self.assertEqual(st, 200, got)
        only = self.py('print(json.dumps([E.ONLY_WHEN[k] for k in ("admin_certlogin_card_watch", '
                       '"admin_certlogin_card_every", "admin_certlogin_card_grace", '
                       '"portal_certlogin_card_grace", "admin_certlogin_card_unable", '
                       '"portal_certlogin_card_unable")]))')
        self.assertEqual(only, [['admin_certlogin', '1'], ['admin_certlogin_card_watch', 'off-not'],
                                ['admin_certlogin_card_watch', 'grace'],
                                ['portal_certlogin_card_watch', 'grace'],
                                ['admin_certlogin_card_watch', 'off-not'],
                                ['portal_certlogin_card_watch', 'off-not']])
        self.assertTrue(self.py('print(json.dumps(all(k in E.PANES["admincert"] for k in '
                                '("admin_certlogin_card_unable",)) and "portal_certlogin_card_unable" '
                                'in E.PANES["portalcert"]))'))
        # A row of 1.0.113 saying "lock" read as grace.
        self.assertEqual(self.py('E.CONFIG["admin_certlogin_card_watch"] = "lock"\n'
                                 'print(json.dumps(E.cl_card_mode("admin")))'), 'grace')
        # Signed where access-granting settings are (db_guard): a row written past acme is no word.
        self.assertTrue(self.py('print(json.dumps(all(k in E.DBGUARD_SETTINGS for k in E.DEFAULTS '
                                'if "_certlogin_card_" in k)))'))
    finally:
        self.card_off()


@_t
def test_09_nginx_with_the_card_watched(self):
    """The server of the certificate's port with the card watched: every inherited ssl_session_*
    line dropped, no session resumed (cache, tickets), no connection kept (keepalive 0, no
    HTTP/2), the check's address let through on both parts' locations - and back as before once
    neither watches it."""
    self.card_on(portal_certlogin=1, portal_certlogin_card_watch='signout')
    try:
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertTrue(want.get('watch'))
        W = load_web('on')
        c = W.certlogin_checked(want)
        self.assertTrue(c['watch'])
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            main = f.read()
        # An inherited line of every kind (a ticket key too) in the server it is made from.
        main2 = main.replace('    ssl_session_tickets       off;\n',
                             '    ssl_session_tickets       on;\n    ssl_session_ticket_key    /etc/nginx/t.key;\n')
        self.assertNotEqual(main, main2)
        for m in (main, main2):
            text = W.certlogin_text(m, None, c)
            lines = [x.strip() for x in text.split('\n') if x.strip().startswith('ssl_session')]
            self.assertEqual(lines, ['ssl_session_cache      off;   # the card watched: every check a full handshake',
                                     'ssl_session_tickets    off;'] * 1, lines)
            self.assertIn('keepalive_timeout      0;', text)
            self.assertNotIn('shared:ACME', text)
            self.assertNotIn('http2', text)
            self.assertEqual(text.count('api=cert-alive&t=[0-9]{1,16}'), 2)      # admin and portal
            # 1.0.115: the checks out of acme_all, a zone of their own (once, for every server);
            # nginx's 429 / 5xx answered "try later" (8 px), for the checks only.
            self.assertEqual(text.count('limit_req_zone $binary_remote_addr zone=acme_card:'), 1)
            self.assertEqual(text.count('if ($args ~ "^api=cert-alive&") { return 418; }'), 2)
            self.assertIn('location @acme_card_admin {', text)
            self.assertIn('location @acme_card_portal {', text)
            self.assertEqual(text.count('limit_req zone=acme_card burst='), 2)
            # ...each part's own "try later", its allow / deny lines again (review round 2: a
            # client the part refuses got 200 once its checks were refused for their number).
            for part in ('admin', 'portal'):
                self.assertEqual(text.count('error_page 429 500 502 503 504 = @acme_card_later_%s;' % part), 1)
                later = text.split('location @acme_card_later_%s {' % part, 1)[1].split('}', 1)[0]
                self.assertIn('deny all;', later)
                self.assertIn('try_files /.acme-card-later-nothing-here =418;', later)
            self.assertIn('width="8" height="1"', text)
        text = W.certlogin_text(main, None, c)
        # nginx -t takes it, where nginx is here.
        if shutil.which('nginx'):
            d = tempfile.mkdtemp(prefix='acme-card-nginx-t-')
            try:
                body = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;',
                              main + '\n' + text)
                body = body.replace(W.CERTLOGIN_CA, os.path.join(self.pki, 'cas.pem'))
                body = body.replace('/etc/nginx/certs/acme.pem', os.path.join(self.pki, 'web-chain.pem')) \
                    .replace('/etc/nginx/certs/acme.key', os.path.join(self.pki, 'web.key')) \
                    .replace('/var/log/nginx/', d + '/')
                body = re.sub(r'(?m)^\s*ssl_dhparam[^\n]*\n', '', body)
                body = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', body)
                body = re.sub(r'listen(\s+)443 ', r'listen\g<1>%d ' % TCL.free_port(), body)
                body = re.sub(r'listen(\s+)80;', r'listen\g<1>%d;' % TCL.free_port(), body)
                body = re.sub(r'listen(\s+)8443 ', r'listen\g<1>%d ' % TCL.free_port(), body)
                with open(os.path.join(d, 'nginx.conf'), 'w') as f:
                    f.write('pid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\nhttp {\n'
                            'include /etc/nginx/mime.types;\n%s\n}\n' % (d, d, body))
                t = subprocess.run(['nginx', '-t', '-p', d, '-c', os.path.join(d, 'nginx.conf')],
                                   capture_output=True, text=True)
                self.assertEqual(t.returncode, 0, t.stderr)
            finally:
                shutil.rmtree(d, ignore_errors=True)
            if os.geteuid() == 0:
                self.later_allowed(W, main, c)
        self.on(admin_certlogin_card_watch='off')
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertTrue(want.get('watch'))                  # the portal's still
        self.on(portal_certlogin_card_watch='off')
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertNotIn('watch', want)
        off = W.certlogin_text(main, None, W.certlogin_checked(want))
        self.assertNotIn('keepalive_timeout', off)
        for x in ('acme_card', '418', 'recursive_error_pages', 'cert-alive'):
            self.assertNotIn(x, off)
    finally:
        self.card_off()


def later_allowed(self, W, main, c):
    """A real nginx, PHP not answering (no such socket - 502): a client the administration's
    allow list lets in gets "try later" (8 px); one it refuses (127.0.0.1 denied) - 403, also
    once its checks are refused for their number (review round 2, F5)."""
    for denied in (False, True):
        m = main.replace('        allow 127.0.0.1;\n', '        deny  127.0.0.1;\n') if denied else main
        self.assertNotEqual(m == main, denied)
        d = tempfile.mkdtemp(prefix='acme-card-later-')
        port = TCL.free_port()
        try:
            text = W.certlogin_text(m, None, c)
            body = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;', text)
            body = body.replace(W.CERTLOGIN_CA, os.path.join(self.pki, 'cas.pem'))
            body = body.replace('/etc/nginx/certs/acme.pem', os.path.join(self.pki, 'web-chain.pem')) \
                .replace('/etc/nginx/certs/acme.key', os.path.join(self.pki, 'web.key')) \
                .replace('/var/log/nginx/', d + '/')
            body = re.sub(r'unix:[^;\s]+', 'unix:' + os.path.join(d, 'no-such.sock'), body)
            body = re.sub(r'(?m)^\s*ssl_dhparam[^\n]*\n', '', body)
            body = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', body)
            body = re.sub(r'listen(\s+)8443 ', r'listen\g<1>%d ' % port, body)
            # the zones of the main server's http block the port's server uses
            zones = '\n'.join(re.findall(r'(?m)^limit_req_zone \$binary_remote_addr zone=acme_all:[^\n]+', main))
            conf = os.path.join(d, 'nginx.conf')
            with open(conf, 'w') as f:
                f.write('pid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\nhttp {\n'
                        'include /etc/nginx/mime.types;\naccess_log %s/access.log;\n'
                        'client_body_temp_path %s;\nfastcgi_temp_path %s;\nproxy_temp_path %s;\n'
                        'scgi_temp_path %s;\nuwsgi_temp_path %s;\n%s\n%s\n}\n'
                        % (d, d, d, d, d, d, d, d, zones, body))
            t = subprocess.run(['nginx', '-t', '-p', d, '-c', conf], capture_output=True, text=True)
            self.assertEqual(t.returncode, 0, t.stderr + body)
            ng = subprocess.Popen(['nginx', '-p', d, '-c', conf, '-g', 'daemon off;'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(50):
                    if self._open(port):
                        break
                    time.sleep(0.1)
                ctx = ssl.create_default_context(cafile=os.path.join(self.pki, 'root.pem'))
                ctx.check_hostname = False
                got = []
                for i in range(240):            # past the burst of 200: nginx's own 429 too
                    conn = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=30)
                    conn.request('GET', '/admin/?api=cert-alive&t=%d' % i,
                                 headers={'Host': 'localhost:%d' % port, 'Origin': 'https://localhost'})
                    r = conn.getresponse()
                    got.append((r.status, r.read()[:60]))
                    conn.close()
                with open(os.path.join(d, 'error.log')) as f:
                    log = f.read()
                if denied:
                    self.assertEqual({st for st, _b in got}, {403}, got[:3])
                    self.assertIn('limiting requests', log)        # the limit was reached
                else:
                    self.assertEqual({st for st, _b in got}, {200}, got[:3])
                    self.assertTrue(all(b'width="8"' in b for _st, b in got))
            finally:
                ng.terminate()
                ng.wait(10)
        finally:
            shutil.rmtree(d, ignore_errors=True)


CardWatch.later_allowed = later_allowed


def s_client(port, cert, key, *more, stdin='', hold=0):
    """openssl s_client's output (what it says of each handshake). `hold`: seconds its input
    stays open after `stdin` - a TLS 1.3 ticket comes after the handshake."""
    args = ['openssl', 's_client', '-connect', '127.0.0.1:%d' % port, '-servername', 'localhost']
    args += (['-cert', cert, '-key', key] if cert else []) + list(more)
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True)
    if stdin:
        p.stdin.write(stdin)
        p.stdin.flush()
    if hold:
        time.sleep(hold)
    try:
        return p.communicate('', timeout=120)[0]
    except subprocess.TimeoutExpired:
        p.kill()
        return p.communicate()[0]


@_t
def test_10_real_nginx_and_the_browser(self):
    """A real nginx (the root helper's servers, the page's 443 on 443 itself where it is free) and
    php-fpm with the pages, client certificates: the port as before while off (a TLS session of
    the main server's cache taken up again - nothing changes); switched on and nginx reloaded
    (settled first - `nginx -s reload` is asynchronous), every check a new handshake (openssl
    -reconnect: all New on TLS 1.2; TLS 1.3: no ticket), no connection kept; the check a picture
    whose width is the answer, let in by the page's policy for a watched sign-in only; and
    Chromium where it is."""
    fpm = shutil.which('php-fpm') or next((p for p in ('/usr/sbin/php-fpm8.3', '/usr/sbin/php-fpm8.2',
                                                       '/usr/sbin/php-fpm') if os.path.exists(p)), None)
    if not shutil.which('nginx') or not fpm or os.geteuid() != 0:
        self.skipTest('no nginx, php-fpm or root here')
    if self._open(443) or self._open(8443):
        self.skipTest('443 or 8443 is taken here')
    name = 'localhost'
    self.card_on(portal_certlogin=1, certlogin_port=8443, admin_certlogin_card_watch='off')
    d = tempfile.mkdtemp(prefix='acme-card-nginx-')
    procs = []
    pem, key = os.path.join(self.pki, 'nested.pem'), os.path.join(self.pki, 'nested.key')
    try:
        web = os.path.join(d, 'www')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        if CS_EXTRA and os.path.exists(CS_EXTRA):
            merge_cs(os.path.join(web, 'lang', 'cs.json'), CS_EXTRA)
        sock = os.path.join(d, 'fpm.sock')
        with open(os.path.join(d, 'fpm.conf'), 'w') as f:
            f.write('[global]\nerror_log = %s/fpm.log\n[www]\nlisten = %s\npm = static\n'
                    'pm.max_children = 6\nclear_env = no\nuser = root\ngroup = root\nlisten.mode = 0666\n'
                    % (d, sock))
        procs.append(subprocess.Popen([fpm, '-F', '-R', '-y', os.path.join(d, 'fpm.conf')],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        W = load_web('real')
        W.CERTLOGIN_CA = os.path.join(d, 'certlogin-ca.pem')
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            main = f.read()
        main = main.replace('acme.example.local', name) \
            .replace('/etc/nginx/certs/acme.pem', os.path.join(self.pki, 'web-chain.pem')) \
            .replace('/etc/nginx/certs/acme.key', os.path.join(self.pki, 'web.key')) \
            .replace('unix:/run/php-fpm/acme.sock', 'unix:' + sock) \
            .replace('/var/www/acme', web).replace('/var/log/nginx/', d + '/')
        main = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;', main)
        if not self._v6():
            main = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', main)
        p80 = TCL.free_port()
        main = re.sub(r'listen(\s+)80;', r'listen\g<1>%d;' % p80, main)
        main = re.sub(r'listen(\s+)\[::\]:80;', r'listen\g<1>[::]:%d;' % p80, main)
        main = re.sub(r'(?m)^\s*ssl_dhparam[^\n]*\n', '', main)
        conf = os.path.join(d, 'nginx.conf')

        def write_conf():
            """nginx's configuration as root's helper would write the port's server now."""
            want = self.py('print(json.dumps(E.certlogin_desired(st)))')
            c = W.certlogin_checked(want)
            cert_conf = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;',
                               W.certlogin_text(main, None, c))
            if not self._v6():
                cert_conf = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', cert_conf)
            cert_conf = re.sub(r'(?m)^\s*ssl_dhparam[^\n]*\n', '', cert_conf)
            with open(W.CERTLOGIN_CA, 'w') as f:
                f.write(c['cas'])
            with open(conf, 'w') as f:
                f.write('pid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\nhttp {\n'
                        'include /etc/nginx/mime.types;\naccess_log %s/access.log;\n'
                        'client_body_temp_path %s;\nfastcgi_temp_path %s;\nproxy_temp_path %s;\n'
                        'scgi_temp_path %s;\nuwsgi_temp_path %s;\n%s\n%s\n}\n'
                        % (d, d, d, d, d, d, d, d, main, cert_conf))
            t = subprocess.run(['nginx', '-t', '-p', d, '-c', conf], capture_output=True, text=True)
            self.assertEqual(t.returncode, 0, t.stderr + cert_conf)
            return c, cert_conf

        c, cert_conf = write_conf()
        self.assertNotIn('watch', c)
        procs.append(subprocess.Popen(['nginx', '-p', d, '-c', conf, '-g', 'daemon off;'],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for _ in range(50):
            if os.path.exists(sock) and self._open(8443) and self._open(443):
                break
            time.sleep(0.2)
        for _ in range(30):
            if (self.call('GET', '/api/health')[1].get('certlogin') or {}).get('ready'):
                break
            time.sleep(0.5)

        ctxs = {}

        def ask(port, path, cert=None, cookies=(), method='GET', body=None, origin=None, sess=None,
                tls12=False, headers=None):
            ctx = ctxs.get((cert, tls12))
            if ctx is None:
                ctx = ctxs[(cert, tls12)] = ssl.create_default_context(cafile=os.path.join(self.pki, 'root.pem'))
                ctx.check_hostname = False
                if tls12:
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                if cert:
                    ctx.load_cert_chain(os.path.join(self.pki, cert + '.pem'), os.path.join(self.pki, cert + '.key'))
            conn = http.client.HTTPSConnection('127.0.0.1', port, context=ctx, timeout=60)
            conn.connect()
            if sess is not None:
                # Offered the session of the last handshake: taken, the card would sign nothing.
                conn.sock.close()
                raw = socket.create_connection(('127.0.0.1', port), timeout=60)
                conn.sock = ctx.wrap_socket(raw, server_hostname=name, session=sess)
            hd = {'Host': name + ('' if port == 443 else ':%d' % port)}
            if cookies:
                hd['Cookie'] = '; '.join(cookies)
            if origin:
                hd['Origin'] = origin
            if body is not None:
                hd['Content-Type'] = 'application/json'
                hd['Sec-Fetch-Site'] = 'same-origin'
            hd.update(headers or {})
            conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=hd)
            sk = conn.sock
            facts = type('TLS', (), {'session': sk.session, 'session_reused': sk.session_reused})()
            r = conn.getresponse()
            out = (r.status, r.getheaders(), r.read(), facts)
            conn.close()
            return out

        def hget(headers, h):
            return [v for k, v in headers if k.lower() == h.lower()]

        def picture(st, hd, body):
            """(status, the picture's width or None) - as the page's <img> sees it (crossorigin
            use-credentials, 1.0.115: only with CORS for the page's own origin)."""
            ct = ' '.join(hget(hd, 'Content-Type'))
            if st != 200 or hget(hd, 'Access-Control-Allow-Origin') != ['https://' + name] or \
                    hget(hd, 'Access-Control-Allow-Credentials') != ['true']:
                return st, None
            if 'image/gif' in ct and body[:6] == b'GIF89a':
                return st, body[6] | body[7] << 8
            m = re.match(rb'<svg [^>]*width="(\d+)"', body)
            return st, int(m.group(1)) if 'image/svg+xml' in ct and m else None

        page_hd = {'Origin': 'https://' + name, 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Dest': 'image',
                   'Sec-Fetch-Mode': 'cors'}

        def check(n, cert, cookies, headers=None, **kw):
            for _ in range(20):
                st, hd, body, facts = ask(8443, '/admin/?api=cert-alive&t=%d' % n, cert, cookies,
                                          headers=headers or page_hd, **kw)
                if st != 429:           # far more questions here than a page asks: nginx's limit
                    break
                time.sleep(1)
            return picture(st, hd, body) + (hd, facts)

        def sign_in(cert='nested'):
            st, hd, body, _s = ask(443, '/admin/?api=cert-nonce', method='POST', body={})
            self.assertEqual(st, 200, body)
            path = json.loads(body)['url'].split(':8443', 1)[1]
            n = [x.split(';')[0] for x in hget(hd, 'Set-Cookie') if x.startswith('__Host-acme_certn_')][0]
            for _ in range(20):
                st, hd, body, _s = ask(8443, path, cert, [n])
                if st != 429:           # nginx's limit (not reached by PHP: the nonce unused)
                    break
                time.sleep(1)
            self.assertEqual(hget(hd, 'Location'), ['https://%s/admin/' % name], body)
            return [x.split(';')[0] for x in hget(hd, 'Set-Cookie') if x.startswith('__Host-acme_session=')]

        def reused(*more):
            o = s_client(8443, pem, key, '-reconnect', '-tls1_2', *more)
            return o.count('Reused,'), o.count('New,')

        # ---- off: the port as before ----
        sess = sign_in()
        st, hd, body, _s = ask(443, '/admin/', cookies=sess)
        csp = hget(hd, 'Content-Security-Policy')
        self.assertEqual(len(csp), 1, csp)
        self.assertIn("img-src 'self' data:; connect-src 'self';", csp[0])
        self.assertNotIn(b'"card"', body)
        self.assertEqual(check(1, 'nested', sess)[0], 404)                  # not let through
        r_off = reused()
        self.assertGreater(r_off[0], 0, 'off: the server as before - its inherited cache takes a '
                                        'TLS 1.2 session up again (%s)' % (r_off,))

        # ---- signout: root's helper writes the port again, nginx reloaded ----
        self.on(admin_certlogin_card_watch='signout', admin_certlogin_card_every=5)
        c, cert_conf = write_conf()
        self.assertTrue(c.get('watch'))
        self.assertNotIn('shared:', cert_conf)
        subprocess.run(['nginx', '-p', d, '-c', conf, '-s', 'reload'], check=True, capture_output=True)
        # nginx -s reload is asynchronous: for a moment the old workers take connections with
        # the old settings (a resumed session, no cert-alive). Measured once it has settled.
        time.sleep(4)
        for _ in range(20):
            if check(2, 'nested', sess)[0] != 404:
                break
            time.sleep(0.5)
        tries = []
        for _ in range(3):
            tries.append(reused())
            time.sleep(1)
        self.assertTrue(all(r == 0 and n >= 6 for r, n in tries), tries)
        print('openssl -reconnect TLS 1.2: off %s (Reused, New), on %s' % (r_off, tries))
        # The check of the check: 443 (its session cache) gives a TLS 1.3 ticket.
        sf443 = os.path.join(d, 'tls13-443.sess')
        s_client(443, None, None, '-tls1_3', '-sess_out', sf443, hold=1.5)
        self.assertTrue(os.path.exists(sf443) and os.path.getsize(sf443) > 0, '443 gives a TLS 1.3 ticket')
        sf = os.path.join(d, 'tls13.sess')
        s_client(8443, pem, key, '-tls1_3', '-sess_out', sf, hold=1.5)
        # No ticket given at all (nothing to write out), or one given and not taken.
        ticket = os.path.exists(sf) and os.path.getsize(sf) > 0
        if ticket:
            o = s_client(8443, pem, key, '-tls1_3', '-sess_in', sf)
            self.assertNotIn('Reused,', o)
            self.assertIn('New,', o)
        print('TLS 1.3: %s' % ('a ticket given, not taken up' if ticket else 'no ticket given'))
        # The sign-in made while off is watched from now on (its fingerprint was kept).
        st, hd, body, _s = ask(443, '/admin/', cookies=sess)
        csp = hget(hd, 'Content-Security-Policy')
        self.assertEqual(len(csp), 1, csp)
        self.assertIn("img-src 'self' data: https://%s:8443; connect-src 'self';" % name, csp[0])
        self.assertIn('"card":{"watch":"signout"', body.decode().replace(' ', ''))
        # A password's page: the policy as before.
        st, hd, body, _s = ask(443, '/admin/', cookies=['__Host-acme_session=' + self.admin])
        self.assertIn("img-src 'self' data:; connect-src 'self';", hget(hd, 'Content-Security-Policy')[0])
        # The check: a picture 1 px wide - nothing kept, the connection closed.
        st, wide, hd, s1 = check(3, 'nested', sess)
        self.assertEqual((st, wide), (200, 1))
        self.assertIn('no-store', ' '.join(hget(hd, 'Cache-Control')))
        self.assertIn('close', ' '.join(hget(hd, 'Connection')).lower())
        # CORS for the page's own origin only (1.0.115) - nothing for another to read.
        self.assertEqual(hget(hd, 'Access-Control-Allow-Origin'), ['https://' + name])
        # A full handshake every time: the session of the last one offered, not taken (TLS 1.2
        # and 1.3) - where 443, with its session cache, takes it (the check of the check).
        for tls12 in (True, False):
            a = ask(443, '/healthz', None, tls12=tls12)[3]
            b = ask(443, '/healthz', None, tls12=tls12, sess=a.session)[3]
            if tls12:
                self.assertTrue(b.session_reused, '443 resumes TLS 1.2 sessions')
            st, wide, hd, s1 = check(4, 'nested', sess, tls12=tls12)
            st, wide, hd, s2 = check(4, 'nested', sess, sess=s1.session, tls12=tls12)
            self.assertEqual(wide, 1)
            self.assertFalse(s2.session_reused, 'TLS 1.2' if tls12 else 'TLS 1.3')
        # No cookie came with the check (1.0.114): 6 px - said as such, nothing asked (the page
        # then says so over 443, where its cookie does come); another site's picture: 403.
        self.assertEqual(check(5, 'nested', [])[:2], (200, 6))
        st, hd, body, _s = ask(8443, '/admin/?api=cert-alive&t=5', 'nested', sess,
                               headers={'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(st, 403)
        # 1.0.115: only this name's page - a sibling host (same site: its pictures get the
        # cookie too), a navigation without an Origin, or not asked as a picture - 403, nothing
        # asked, no CORS.
        for bad in ({'Origin': 'https://sibling.' + name, 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Dest': 'image'},
                    {'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Dest': 'document'},
                    {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Dest': 'image'},
                    {'Origin': 'https://' + name, 'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Dest': 'document'},
                    {'Origin': 'https://' + name + ':8443', 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Dest': 'image'},
                    {'Origin': 'http://' + name}):
            st, hd, body, _s = ask(8443, '/admin/?api=cert-alive&t=5', 'nested', sess, headers=bad)
            self.assertEqual(st, 403, bad)
            self.assertEqual(hget(hd, 'Access-Control-Allow-Origin'), [], bad)
        # A picture without an Origin at all (review round 2): a page of 1.0.114 still open asks
        # so - a 403 was "no answer" and signed it out. A picture that says nothing, the same
        # for everybody (6 by 2, no CORS) - nothing asked of the daemon, nothing renewed; to the
        # old page "no cookie", which it says over 443 without `v` - told to load itself again.
        seen = time.time() - 50
        self.session_set(sess[0].split('=', 1)[1], card_seen=seen)
        for hd_bare in ({'Sec-Fetch-Site': 'same-site', 'Sec-Fetch-Dest': 'image', 'Sec-Fetch-Mode': 'no-cors'},
                        {}):
            for who in (sess, []):
                st, hd, body, _s = ask(8443, '/admin/?api=cert-alive&t=5', 'nested', who, headers=hd_bare)
                self.assertEqual((st, body[:6], body[6] | body[7] << 8, body[8] | body[9] << 8),
                                 (200, b'GIF89a', 6, 2), hd_bare)
                self.assertEqual(hget(hd, 'Access-Control-Allow-Origin'), [])
            st, hd, body, _s = ask(8443, '/admin/?api=cert-alive&t=5', None, sess, headers=hd_bare)
            self.assertEqual((st, body[6], body[8]), (200, 6, 2))           # no card: the same
        self.assertEqual(float(self.session_data(sess[0].split('=', 1)[1]).get('card_seen')), seen)
        st, hd, body, _s = ask(443, '/admin/?api=cert-lost', cookies=sess, method='POST',
                               body={'part': 'admin', 'why': 'nocookie'})
        self.assertEqual(json.loads(body)['state'], 'none', body)
        self.assertEqual(ask(443, '/admin/?api=status', cookies=sess)[0], 200)   # nothing changed
        self.assertNotIn('card_out', self.session_data(sess[0].split('=', 1)[1]))
        # A browser without Sec-Fetch-* (an older Safari): its Origin is enough.
        self.assertEqual(check(5, 'nested', sess, headers={'Origin': 'https://' + name})[:2], (200, 1))
        # The page on 443 has no such address; the port nothing else new.
        self.assertEqual(ask(443, '/admin/?api=cert-alive&t=6', None, sess)[0], 404)
        self.assertEqual(ask(8443, '/admin/?api=cert-alive&t=6&x=1', 'nested', sess)[0], 404)
        # Another person's card (falco's) with nested's sign-in: 3 px - ended.
        self.assertEqual(check(7, 'falco', sess)[:2], (200, 3))
        self.assertEqual(check(8, 'nested', sess)[0], 403)                  # no such sign-in now
        st, hd, body, _s = ask(443, '/admin/', cookies=sess)
        self.assertNotIn(b'id="signout"', body)
        # No certificate at all (the card out): 4 px - ended, said in the events.
        sess = sign_in()
        self.assertEqual(check(9, 'nested', sess)[:2], (200, 1))
        self.assertEqual(check(10, None, sess)[:2], (200, 4))
        self.assertTrue(any('nested was signed out of these pages' in w and 'was taken out' in w
                            for w in self.events('was taken out')))
        # ---- grace ----
        self.on(admin_certlogin_card_watch='grace', admin_certlogin_card_grace=30)
        sess = sign_in()
        self.assertEqual(check(11, 'nested', sess)[:2], (200, 1))
        self.assertEqual(check(12, None, sess)[:2], (200, 2))              # out, waiting
        st, hd, body, _s = ask(443, '/admin/?api=status', cookies=sess)
        self.assertEqual((st, json.loads(body).get('code')), (423, 'card'))
        self.assertEqual(check(13, 'nested', sess)[:2], (200, 1))          # back
        st, hd, body, _s = ask(443, '/admin/?api=status', cookies=sess)
        self.assertEqual(st, 200)
        # The page's picture got nothing (the handshake failed): it says so over 443 - held.
        st, hd, body, _s = ask(443, '/admin/?api=cert-lost', cookies=sess, method='POST', body={'v': 2, 'part': 'admin'})
        self.assertEqual(json.loads(body)['state'], 'locked', body)
        # Held (1.0.115, the kit's 4th edition): whoami through the page gives nothing of the
        # person; the page itself is drawn (covered).
        st, hd, body, _s = ask(443, '/admin/?api=whoami', cookies=sess)
        self.assertEqual(sorted(json.loads(body)['who']), ['card', 'how', 'name', 'role'], body)
        st, hd, body, _s = ask(443, '/admin/', cookies=sess)
        self.assertEqual(st, 200)
        self.assertIn(b'"card":{', body.replace(b' ', b''))
        self.assertNotIn(b'Nested Person', body)
        # ...a change of the mode counts afresh: signout now - not ended for the time out
        # counted under grace; a check with the card goes on.
        self.on(admin_certlogin_card_watch='signout')
        self.assertEqual(ask(443, '/admin/?api=status', cookies=sess)[0], 200)
        self.assertEqual(check(14, 'nested', sess)[:2], (200, 1))
        self.on(admin_certlogin_card_watch='grace')
        # ...waiting (1.0.115): a proven browser - held; through the page as the page says it.
        st, hd, body, _s = ask(443, '/admin/?api=cert-lost', cookies=sess, method='POST',
                               body={'v': 2, 'part': 'admin', 'why': 'waiting'})
        self.assertEqual(json.loads(body)['state'], 'locked', body)
        self.assertEqual(check(14, 'nested', sess)[:2], (200, 1))
        # ...root not having confirmed the port (its status without `watch`): no word of a
        # failed check taken - the port of this real nginx listening.
        self.assertEqual(self.lost_root(sess[0].split('=', 1)[1], 'nopicture', {}), 'unknown')
        self.assertEqual(self.lost_root(sess[0].split('=', 1)[1], 'nopicture',
                                        {'certlogin': {'port': 8443, 'busy': '', 'watch': True}}), 'locked')
        self.assertEqual(check(14, 'nested', sess)[:2], (200, 1))
        self.assertEqual(ask(443, '/admin/?api=status', cookies=sess)[0], 200)
        # A first check that came without the card (1.0.115): the card out, never "cannot be
        # checked" - 2 px, held; the page's word then changes nothing.
        sess = sign_in()
        self.assertEqual(check(15, None, sess)[:2], (200, 2))
        st, hd, body, _s = ask(443, '/admin/?api=cert-lost', cookies=sess, method='POST',
                               body={'v': 2, 'part': 'admin', 'why': 'nopicture'})
        self.assertEqual(json.loads(body)['state'], 'locked', body)
        self.assertEqual(ask(443, '/admin/?api=status', cookies=sess)[0], 423)
        self.assertEqual(check(16, 'nested', sess)[:2], (200, 1))
        # A browser that cannot be checked (1.0.114): the page's word over 443 for one that never
        # got a picture (a browser that signs nothing in the background) - 7 px, not watched; still checked now and then (its page's
        # policy lets the port in), and a check that finds the card watches it again (1.0.115).
        sess = sign_in()
        st, hd, body, _s = ask(443, '/admin/?api=cert-lost', cookies=sess, method='POST',
                               body={'v': 2, 'part': 'admin', 'why': 'nopicture'})
        self.assertEqual(json.loads(body)['state'], 'unable', body)
        self.assertEqual(check(17, None, sess)[:2], (200, 7))
        st, hd, body, _s = ask(443, '/admin/?api=status', cookies=sess)
        self.assertEqual(st, 200)
        st, hd, body, _s = ask(443, '/admin/', cookies=sess)
        self.assertIn(b'"unable":true', body.replace(b' ', b''))
        self.assertIn("img-src 'self' data: https://%s:8443; connect-src 'self';" % name,
                      hget(hd, 'Content-Security-Policy')[0])
        self.assertEqual(check(18, 'nested', sess)[:2], (200, 1))
        self.assertEqual(check(19, None, sess)[:2], (200, 2))              # now a card out
        self.assertEqual(check(20, 'nested', sess)[:2], (200, 1))
        # nginx's own errors (1.0.115): PHP not answering - the check "try later" (8 px, an SVG
        # with CORS for the page), never an HTML page the picture fails on; the sign-in's own
        # address on the port as before (nginx's 502).
        fpm_p = procs[0]
        fpm_p.terminate()
        fpm_p.wait(10)
        try:
            for _ in range(20):
                if not os.path.exists(sock) or check(21, 'nested', sess)[0] != 200:
                    break
                time.sleep(0.3)
            st, wide, hd, _f = check(21, 'nested', sess)
            self.assertEqual((st, wide), (200, 8), hd)
            self.assertIn('no-store', ' '.join(hget(hd, 'Cache-Control')))
            self.assertEqual(ask(8443, '/admin/?api=cert-login&n=' + '0' * 32, 'nested', [])[0], 502)
            # A sibling's picture gets "try later" as anybody would - and no CORS of its own.
            st, hd, body, _s = ask(8443, '/admin/?api=cert-alive&t=22', 'nested', sess,
                                   headers={'Origin': 'https://sibling.' + name})
            self.assertEqual(hget(hd, 'Access-Control-Allow-Origin'), ['https://' + name])
        finally:
            procs[0] = subprocess.Popen([fpm, '-F', '-R', '-y', os.path.join(d, 'fpm.conf')],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(50):
                if os.path.exists(sock) and check(23, 'nested', sess)[0] == 200:
                    break
                time.sleep(0.2)
        self.assertEqual(check(24, 'nested', sess)[:2], (200, 1))
        # The checks have a limit of their own, not acme_all's: far more of them than acme_all
        # lets through (burst 20) - none refused.
        got = [ask(8443, '/admin/?api=cert-alive&t=%d' % (30 + i), 'nested', sess, headers=page_hd)[0]
               for i in range(40)]
        self.assertEqual(got, [200] * 40)

        # Chromium, where Playwright is here.
        node = shutil.which('node')
        js = os.path.join(HERE, 'cert_card_page.js')
        if node and os.path.exists(js):
            # core.js of 1.0.114 (a page left open over the upgrade), where git can say it.
            old_js = os.path.join(d, 'core-1.0.114.js')
            rel = subprocess.run(['git', 'log', '--format=%H', '-n', '1', '--grep', '^Release 1.0.114$'],
                                 cwd=ROOT, capture_output=True, text=True).stdout.strip()
            got = subprocess.run(['git', 'show', '%s:web/assets/core.js' % rel], cwd=ROOT,
                                 capture_output=True) if rel else None
            if got is not None and got.returncode == 0 and got.stdout:
                with open(old_js, 'wb') as f:
                    f.write(got.stdout)

            def browser(phase):
                got = subprocess.run([node, js, phase, 'https://%s' % name, pem, key, 'tester',
                                      self.pw, SHOTS],
                                     capture_output=True, text=True, timeout=900, input='',
                                     env=dict(os.environ, NODE_PATH=os.environ.get('NODE_PATH') or
                                              '/opt/node22/lib/node_modules',
                                              ACME_OLD_CORE_JS=old_js))
                line = (got.stdout.strip().splitlines() or ['{}'])[-1]
                try:
                    res = json.loads(line)
                except ValueError:
                    res = {'error': got.stdout[-1500:] + got.stderr[-1500:]}
                if res.get('skip'):
                    print('the browser\'s part skipped: %s' % res['skip'])
                    return None
                self.assertTrue(res.get('ok'), phase + ': ' + json.dumps(res, indent=1) + got.stderr[-2000:])
                print('%s: %d checks, %s' % (phase, len(res.get('checks') or {}), json.dumps(res.get('timing'))))
                return res
            self.on(admin_certlogin_card_watch='signout', admin_certlogin_card_every=5)
            if browser('signout') is not None:
                self.assertTrue(any('nested was signed out of these pages' in w and 'got no answer at all' in w
                                    for w in self.events('got no answer at all')))
                self.on(admin_certlogin_card_watch='grace', admin_certlogin_card_grace=30)
                browser('grace')
                self.on(admin_certlogin_card_grace=5)
                browser('late')
                self.assertTrue(any('not put back in time' in w for w in self.events('not put back in time')))
                self.on(admin_certlogin_card_grace=30)
                browser('options')
                # An upgrade half way (review round 2): this page against a node of 1.0.114, and a
                # page of 1.0.114 (its core.js) against this version.
                n = len(self.events('cannot be checked in this browser'))
                browser('mixed')
                self.assertEqual(len(self.events('cannot be checked in this browser')), n)
                # A browser that signs nothing in the background simulated: the sign-in works,
                # the background's picture never does.
                browser('unable')
                self.assertTrue(any('cannot be checked in this browser - the check got no answer at all' in w
                                    for w in self.events('cannot be checked in this browser')))
                # The kit's 4th edition: the hint, F5, a check left waiting, ended meanwhile...
                browser('kit4')
                self.assertTrue(any('the check waited over 4 s on a window of the card\'s' in w
                                    for w in self.events('waited over 4 s')))
                # ...a policy header naming no port: said as such, never a verdict.
                n = len(self.events('cannot be checked in this browser'))
                browser('csp')
                self.assertTrue(any('was blocked: the page\'s policy blocked the check' in w
                                    for w in self.events('was blocked')))
                self.assertEqual(len(self.events('cannot be checked in this browser')), n)
                v = self.ok('GET', '/api/certlogin', session=self.ro)
                self.assertEqual(v['parts']['admin']['card']['csp']['name'], 'nested')
                # ...a browser not proven yet whose first check waits (grace 5 s).
                self.on(admin_certlogin_card_grace=5)
                browser('kit4new')
                self.on(admin_certlogin_card_grace=30)
        # Off again: nginx as it was before (byte for byte), the check not let through.
        self.on(admin_certlogin_card_watch='off')
        c, cert_conf2 = write_conf()
        self.assertNotIn('watch', c)
        self.assertNotIn('cert-alive', cert_conf2)
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        self.card_off()
        shutil.rmtree(d, ignore_errors=True)


@_t
def test_11_two_nodes_and_a_restart(self):
    """Two daemons on one database (a second node's process beside this one, both on the same
    SQLite file - the cluster's shared database simulated; the state of the watch is in the
    sign-in's row, nothing of it in a daemon's memory): a check on one node, the questions on the
    other (the kit's t_cert_ha excerpt); the second node started again in the middle - nothing
    forgotten."""
    self.card_on(admin_certlogin_card_watch='grace', admin_certlogin_card_every=5,
                 admin_certlogin_card_grace=30)
    tmp = tempfile.mkdtemp(prefix='acme-card-node-b-')
    nb = {'proc': None}
    try:
        for sub in ('run', 'log'):
            os.makedirs(os.path.join(tmp, sub))
        # Its own folder (keys as this node's - one installation's), the database this node's.
        state_a = os.path.join(self.tmp, 'state')
        shutil.copytree(state_a, os.path.join(tmp, 'state'),
                        ignore=lambda d, names: [n for n in names if n.startswith('acme.db') or n == 'acme.lock'])
        with open(self.conf) as f:
            conf = json.load(f)
        conf.update(api_port=TCL.free_port(), ssh_gate_port=TCL.free_port(),
                    db_path=os.path.join(state_a, 'acme.db'))
        for k in ('radius_auth_port', 'radius_acct_port'):
            if k in conf:
                conf[k] = TCL.free_port()
        with open(os.path.join(tmp, 'config.json'), 'w') as f:
            json.dump(conf, f)
        env = dict(self.env, ACME_CONFIG=os.path.join(tmp, 'config.json'),
                   ACME_STATE=os.path.join(tmp, 'state'),
                   ACME_RUN=os.path.join(tmp, 'run'), ACME_LOGDIR=os.path.join(tmp, 'log'))

        def start_b():
            nb['out'] = open(os.path.join(tmp, 'log', 'daemon.out'), 'ab')
            nb['proc'] = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                          env=env, stdout=nb['out'], stderr=subprocess.STDOUT, cwd=tmp)
            for _ in range(200):
                try:
                    with open(os.path.join(tmp, 'run', 'api-token')) as f:
                        nb['token'] = f.read().strip()
                    urllib.request.urlopen('http://127.0.0.1:%d/api/health' % conf['api_port'], timeout=2)
                    return
                except (OSError, ValueError):
                    time.sleep(0.3)
            with open(os.path.join(tmp, 'log', 'daemon.out'), errors='replace') as f:
                self.fail('the second node did not start: %s' % f.read()[-3000:])

        def stop_b():
            if nb['proc'] is not None and nb['proc'].poll() is None:
                nb['proc'].terminate()
                try:
                    nb['proc'].wait(20)
                except subprocess.TimeoutExpired:
                    nb['proc'].kill()
            nb['proc'] = None
            if nb.get('out'):
                nb['out'].close()
                nb['out'] = None
            try:
                os.unlink(os.path.join(tmp, 'run', 'api-token'))
            except OSError:
                pass

        def call(node, path, body=None, session=None):
            if node == 'a':
                return self.call('POST' if body is not None else 'GET', path, body, session)
            req = urllib.request.Request('http://127.0.0.1:%d%s' % (conf['api_port'], path),
                                         data=json.dumps(body).encode() if body is not None else None,
                                         method='POST' if body is not None else 'GET')
            req.add_header('X-Acme-Token', nb['token'])
            req.add_header('Content-Type', 'application/json')
            if session:
                req.add_header('X-Acme-Session', session)
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.status, json.loads(r.read().decode())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read().decode() or '{}')

        def check(node, tok, cert):
            return call(node, '/api/certlogin/alive', dict({'part': 'admin'},
                                                           **({'cert': self.pem(cert)} if cert else {})), tok)

        start_b()
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = check('b', tok, 'nested')
        self.assertEqual((st, got.get('state')), (200, 'ok'), ('node b: the same card - alive', got))
        st, got = check('a', tok, None)
        self.assertEqual(got.get('state'), 'locked', ('node a: no card - out, waiting', got))
        for n in 'ab':
            st, got = call(n, '/api/status', None, tok)
            self.assertEqual((st, got.get('code')), (423, 'card'), ('node %s: nothing answered meanwhile' % n, got))
        st, got = call('b', '/api/auth/whoami', None, tok)
        self.assertTrue(got['who']['card']['locked'], got)
        # Node b started again while the card is out: nothing forgotten.
        stop_b()
        start_b()
        st, got = call('b', '/api/status', None, tok)
        self.assertEqual(st, 423, ('node b, started again: still out', got))
        st, got = check('b', tok, 'nested')
        self.assertEqual((got.get('state'), got.get('resumed')), ('ok', True), ('node b: back', got))
        for n in 'ab':
            st, got = call(n, '/api/status', None, tok)
            self.assertEqual(st, 200, ('node %s: answered again' % n, got))
        # Out and back said once each, whichever node took the check.
        self.assertEqual(len([w for w in self.events('waits 30 s for it') if w.startswith('nested:')]) >= 1, True)
        # A page asleep: held on both nodes; its check on the other node lets it go on both.
        self.session_set(tok, card_seen=time.time() - 1000)
        for n in 'ab':
            st, got = call(n, '/api/status', None, tok)
            self.assertEqual(st, 423, ('node %s: held' % n, got))
        st, got = check('a', tok, 'nested')
        self.assertEqual(got.get('state'), 'ok', got)
        st, got = call('b', '/api/status', None, tok)
        self.assertEqual(st, 200, ('node b: let go', got))
        # Another card on node a: gone at once - node b knows.
        st, got = check('a', tok, 'falco')
        self.assertEqual((got.get('state'), got.get('why')), ('gone', 'other'), got)
        st, got = call('b', '/api/status', None, tok)
        self.assertEqual(st, 401, ('node b: signed out', got))
    finally:
        stop_b()
        self.card_off()
        shutil.rmtree(tmp, ignore_errors=True)


@_t
def test_12_a_browser_that_cannot_be_checked(self):
    """1.0.114, the kit's 3rd edition (isemon 1.10.355) - a safety net since its 4th (the iPad it
    was found on had a CSP header blocking the check): a browser that signs no connection for a
    page in the background - the card is in, yet the check never comes. A sign-in keeps whether a check in the background has ever found its card in this
    browser (card_ok; the sign-in itself does not count). Until one has, the page's word that its
    picture got no answer at all (nopicture) means "this browser cannot be checked": allow (the
    default) - not watched until a check finds the card, said in the events with why, never
    held, whoami's card `unable`; signout - signed out as a card taken out. 1.0.115: only
    nopicture - a check without a certificate, nginx's refusal, no cookie, none within 20 s are
    a card taken out; only for a sign-in made while the watch was on. Once found, a check
    without the card is a card taken out, as always."""
    self.card_on(admin_certlogin_card_watch='signout')
    lsn = self.serving()
    try:
        self.assertEqual(self.py('print(json.dumps(E.cl_card_unable_mode("admin")))'), 'allow')
        # Never found, the picture got no answer at all: not watched, why said.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        d = self.session_data(tok)
        self.assertNotIn('card_ok', d)                                  # the sign-in does not count
        self.assertEqual(d.get('card_w'), 1)                            # made while watched
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual((st, got['state']), (200, 'unable'), got)
        self.assertEqual(self.session_data(tok).get('card_ok'), -1)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.assertTrue(any("the card of nested's sign-in to these pages cannot be checked in this "
                            "browser - the check got no answer at all (the browser did not sign the "
                            "connection)" in w and 'it is not watched' in w
                            for w in self.events('cannot be checked in this browser')))
        # ...whoami: its page still checks now and then (`unable`), nothing held, a role.
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertTrue(me['who']['card']['unable'])
        self.assertFalse(me['who']['card']['locked'] or me['who']['card']['stale'])
        self.assertEqual(me['who']['role'], 'fulladmin')
        # ...its checks without the card say so (7 px on the port); said in the events once.
        n = len(self.events('cannot be checked in this browser'))
        self.assertEqual(self.alive(tok, None)[1]['state'], 'unable')
        self.assertEqual(self.alive(tok, None, failed='FAILED:x')[1]['state'], 'unable')
        self.assertEqual(self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, tok)[1]['state'], 'unable')
        self.assertEqual(len(self.events('cannot be checked in this browser')), n)
        # ...never held for its card: its page asleep for long, a card_out left over - answered.
        self.session_set(tok, card_seen=time.time() - 3600, card_out=time.time() - 3600)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.on(admin_certlogin_card_watch='grace')
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.assertEqual(self.py('E.CL_CARD_SWEEP["at"] = 0\nprint(json.dumps(E.cl_card_sweep(st)))'), 0)
        self.assertIsNotNone(self.session_data(tok))
        # ...not counted among the watched (the card's facts).
        v = self.ok('GET', '/api/certlogin', session=self.ro)
        self.assertEqual(v['parts']['admin']['card']['sessions'], 0)
        # ...not for ever (1.0.115): a check that finds its card watches it again - then a check
        # without it is a card taken out.
        st, got = self.alive(tok, 'nested')
        self.assertEqual(got['state'], 'ok', got)
        self.assertGreater(float(self.session_data(tok).get('card_ok') or 0), 0)
        self.assertTrue(any("the card of nested's sign-in to these pages was found in this browser "
                            "after all - it is watched again" in w for w in self.events('watched again')))
        self.assertNotIn('unable', self.call('GET', '/api/auth/whoami', None, tok)[1]['who']['card'])
        self.assertEqual(self.ok('GET', '/api/certlogin', session=self.ro)['parts']['admin']['card']['sessions'], 1)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual(got['state'], 'locked', got)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        self.assertEqual(self.alive(tok, 'nested')[1]['state'], 'ok')
        # ...another card on an unwatched one's check: ended, as on a watched one's.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertEqual(self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin'}, tok)[1]['state'], 'unable')
        st, got = self.alive(tok, 'falco')
        self.assertEqual((got['state'], got['why']), ('gone', 'other'), got)
        self.assertIsNone(self.session_data(tok))
        self.on(admin_certlogin_card_watch='signout')
        # Never found - but a check without a certificate, nginx's refusal, no cookie (1.0.115):
        # a card taken out (signout - ended), never "cannot be checked".
        for how in ('nocert', 'failed', 'nocookie'):
            st, got = self.sign('admin', 'nested')
            tok = got['token']
            if how == 'nocert':
                st, got = self.alive(tok, None)
            elif how == 'failed':
                st, got = self.alive(tok, None, failed='FAILED:unable to verify')
            else:
                st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': how}, tok)
            self.assertEqual((got['state'], got['why']), ('gone', 'out'), (how, got))
            self.assertIsNone(self.session_data(tok))
        self.assertTrue(any('was taken out (the browser sent no cookie with the check)' in w
                            for w in self.events('no cookie')))
        # None within 20 s (review round 2): as no answer at all - a browser may leave the
        # picture waiting rather than fail it; the same gates (held, out, made before: a card out).
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'timeout'}, tok)
        self.assertEqual(got['state'], 'unable', got)
        self.assertTrue(any("cannot be checked in this browser - the check got no answer within 20 s"
                            in w for w in self.events('within 20 s')))
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.proven(tok)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'timeout'}, tok)
        self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
        # A word of its own is no reason: taken as nopicture.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': '<b>x</b>'}, tok)
        self.assertEqual(got['state'], 'unable', got)
        self.assertFalse(any('<b>' in w for w in self.events('cannot be checked')))
        # Found once, then without it: a card taken out, as always (signout - ended).
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.proven(tok)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
        self.assertIsNone(self.session_data(tok))
        # unable = signout: never found - signed out as a card taken out.
        self.on(admin_certlogin_card_unable='signout')
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
        self.assertIsNone(self.session_data(tok))
        # The portal: its own setting, the same way.
        self.on(admin_certlogin_card_unable='allow', portal_certlogin=1,
                portal_certlogin_card_watch='signout')
        st, got = self.sign('portal', 'falco')
        ptok = got['token']
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertEqual(me['me']['card']['watch'], 'signout')
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'portal', 'why': 'nopicture'}, ptok)
        self.assertEqual(got['state'], 'unable', got)
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertTrue(me['me']['card']['unable'])
        self.assertEqual(self.call('GET', '/api/portal/me', None, ptok)[0], 200)
        self.assertTrue(any("sign-in to the enrolment pages cannot be checked" in w
                            for w in self.events('cannot be checked')), self.events('cannot be checked'))
        self.on(portal_certlogin_card_unable='signout')
        st, got = self.sign('portal', 'falco')
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'portal', 'why': 'nopicture'}, got['token'])
        self.assertEqual(got['state'], 'gone', got)
    finally:
        lsn.close()
        self.card_off()


@_t
def test_13_no_way_out_of_the_watch(self):
    """1.0.115 (hunt P): "cannot be checked" is no way out of the watch, nor is a change of the
    rules. A held sign-in (or one whose card is out) is never turned into one that cannot be
    checked; a sign-in made before the watch was switched on, its person away with the card,
    fails its first check as a card taken out; the sign-in of whoever made a certificate rule
    stricter (krb_kept) stays watched."""
    self.card_on(admin_certlogin_card_watch='grace')
    lsn = self.serving()
    try:
        # a) Held (its page stopped checking), never found: the page's word lets it out no more.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.session_set(tok, card_seen=time.time() - 3600)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual(got['state'], 'locked', got)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        self.assertEqual(float(self.session_data(tok).get('card_ok') or 0), 0)
        self.assertEqual(self.alive(tok, 'nested')[1]['state'], 'ok')      # the card: let go
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        # ...nor one whose card is out (grace): out it stays, and ends past the grace.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.session_set(tok, card_out=time.time() - 5)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual(got['state'], 'locked', got)
        self.session_set(tok, card_out=time.time() - 3600)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual(got['state'], 'gone', got)
        self.assertIsNone(self.session_data(tok))
        # A page of 1.0.114 (review round 2): its word with a why but no `v` - told to load
        # itself again, nothing of the sign-in changed; its word at the end of the grace (no why)
        # taken as before.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        for why in ('nocookie', 'nopicture', 'timeout'):
            st, got = self.call('POST', '/api/certlogin/lost', {'part': 'admin', 'why': why}, tok)
            self.assertEqual(got['state'], 'none', got)
        d = self.session_data(tok)
        self.assertFalse(d.get('card_out') or d.get('card_ok'))
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        st, got = self.call('POST', '/api/certlogin/lost', {'part': 'admin'}, tok)
        self.assertEqual(got['state'], 'unable', got)          # no answer, never found: as before
        # b) A transient first failure (nginx refused once) is the card out - not unwatched for
        # good: the next check with the card goes on, watched.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertEqual(self.alive(tok, None, failed='FAILED:transient')[1]['state'], 'locked')
        st, got = self.alive(tok, 'nested')
        self.assertEqual((got['state'], got['resumed']), ('ok', True), got)
        self.session_set(tok, card_seen=time.time() - 3600)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        # c) Made before the watch was switched on (the person away with the card): its first
        # check fails as a card taken out - whatever the page says.
        self.on(admin_certlogin_card_watch='off')
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertNotIn('card_w', self.session_data(tok))
        self.on(admin_certlogin_card_watch='signout')
        self.assertIn('card', self.call('GET', '/api/auth/whoami', None, tok)[1]['who'])
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
        self.assertIsNone(self.session_data(tok))
        # ...nor one made while on, then off and on again: switched on, none counts as made
        # while on.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertEqual(self.session_data(tok).get('card_w'), 1)
        self.on(admin_certlogin_card_watch='off')
        self.on(admin_certlogin_card_watch='grace')
        self.assertFalse(self.session_data(tok).get('card_w'))
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual(got['state'], 'locked', got)
        # ...nor held or out with none within 20 s (review round 2: timeout as nopicture).
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.session_set(tok, card_seen=time.time() - 3600)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'timeout'}, tok)
        self.assertEqual(got['state'], 'locked', got)
        self.assertEqual(float(self.session_data(tok).get('card_ok') or 0), 0)
        # ...but whoever switches it on (review round 2, F7): their own sign-in counts as made
        # while on - from a browser that cannot be checked not signed out right after saving;
        # everybody else's does not.
        self.on(admin_certlogin_card_watch='off')
        st, got = self.sign('admin', 'nested')
        mine = got['token']
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertNotIn('card_w', self.session_data(mine))
        self.assertEqual(self.settings(session=mine, admin_certlogin_card_watch='grace')[0], 200)
        self.assertEqual(self.session_data(mine).get('card_w'), 1)
        self.assertFalse(self.session_data(tok).get('card_w'))
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, mine)
        self.assertEqual(got['state'], 'unable', got)
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual(got['state'], 'locked', got)
        # ...switched off and on again by them: kept for them, not for the others.
        st, got = self.sign('admin', 'nested')
        mine = got['token']
        self.assertEqual(self.session_data(mine).get('card_w'), 1)
        self.assertEqual(self.settings(session=mine, admin_certlogin_card_watch='off')[0], 200)
        self.assertEqual(self.settings(session=mine, admin_certlogin_card_watch='grace')[0], 200)
        self.assertEqual(self.session_data(mine).get('card_w'), 1)
        # d) Whoever makes a rule stricter keeps their sign-in (krb_kept) - watched still.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.proven(tok)
        self.assertEqual(self.settings(session=tok, admin_certlogin_crl=0)[0], 200)
        self.assertEqual(self.settings(session=tok, admin_certlogin_crl=1)[0], 200)
        d = self.session_data(tok)
        self.assertTrue(d.get('krb_kept'))
        self.assertIn('card', self.call('GET', '/api/auth/whoami', None, tok)[1]['who'])
        st, got = self.alive(tok, None)
        self.assertEqual(got['state'], 'locked', got)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        self.assertEqual(self.alive(tok, 'nested')[1]['state'], 'ok')
        self.session_set(tok, card_seen=time.time() - 3600)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)       # held
        self.assertEqual(self.alive(tok, 'nested')[1]['state'], 'ok')
        v = self.ok('GET', '/api/certlogin', session=self.ro)
        self.assertGreaterEqual(v['parts']['admin']['card']['sessions'], 1)
        # ...not while the part no longer signs in with a certificate (its port not served).
        code = ('d = json.loads(%r)\nw = [E.cl_card_watched("admin", {"data": d})]\n'
                'E.CONFIG["admin_certlogin"] = 0\nw.append(E.cl_card_watched("admin", {"data": d}))\n'
                'print(json.dumps(w))' % json.dumps(dict(d, krb_kept=1)))
        self.assertEqual(self.py(code), [True, False])
    finally:
        lsn.close()
        self.card_off()
        self.on(admin_certlogin_crl=1)


@_t
def test_14_kit4_waiting_policy_held(self):
    """The kit's 4th edition (isemon 1.10.356-358), the daemon's half: a check left waiting over
    4 s (why waiting) - the card out only for a browser proven, never "cannot be checked"; a check
    the page's policy blocked (why csp) - said in the events and the card's facts, never a verdict;
    no word of a failed check before root has confirmed the port serves the watch; a held sign-in
    - whoami, /api/portal/me give nothing of the person, the second step's and the passkeys'
    questions and the portal's password change 423; F5 goes on from the server's clock; an IPv6
    page's policy `https:`."""
    self.card_on(admin_certlogin_card_watch='grace', admin_certlogin_card_grace=30)
    lsn = self.serving()

    def lost(tok, why, part='admin'):
        return self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': part, 'why': why}, tok)[1]

    try:
        # a) waiting, a browser not proven: nothing changes - no card out, no verdict, no event.
        n = len(self.events('waited over 4 s'))
        u = len(self.events('cannot be checked in this browser'))
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertEqual(self.session_data(tok).get('card_w'), 1)
        self.assertEqual(lost(tok, 'waiting'), {'ok': True, 'state': 'waiting'})
        d = self.session_data(tok)
        for no in ('card_out', 'card_ok', 'card_lock'):
            self.assertNotIn(no, d)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.on(admin_certlogin_card_unable='signout')
        self.assertEqual(lost(tok, 'waiting')['state'], 'waiting')
        self.assertIsNotNone(self.session_data(tok))
        self.on(admin_certlogin_card_unable='allow')
        self.assertEqual(len(self.events('waited over 4 s')), n)
        self.assertEqual(len(self.events('cannot be checked in this browser')), u)
        # ...proven (grace): the card out, the time counted, said with why.
        self.proven(tok)
        got = lost(tok, 'waiting')
        self.assertEqual(got['state'], 'locked', got)
        self.assertTrue(0 < got['left'] <= 30, got)
        self.assertTrue(self.session_data(tok).get('card_out'))
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 423)
        self.assertTrue(any('the check waited over 4 s on a window of the card\'s' in w and 'waits 30 s' in w
                            for w in self.events('waited over 4 s')))
        # OK pressed, the card back: the check finds it - on as before.
        st, got = self.alive(tok, 'nested')
        self.assertEqual((got['state'], got['resumed']), ('ok', True), got)
        # ...not proven, the card out already (a check came without it): still out, not undone.
        st, got = self.sign('admin', 'nested')
        tok3 = got['token']
        self.assertEqual(self.alive(tok3, None)[1]['state'], 'locked')
        self.assertEqual(lost(tok3, 'waiting')['state'], 'locked')
        # ...proven (signout): ended, as a card taken out.
        self.on(admin_certlogin_card_watch='signout')
        st, got = self.sign('admin', 'nested')
        tok2 = got['token']
        self.proven(tok2)
        got = lost(tok2, 'waiting')
        self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
        self.assertIsNone(self.session_data(tok2))
        self.on(admin_certlogin_card_watch='grace')

        # b) Root has not confirmed the port serves the watch (just switched on, its server not
        # rewritten yet): no word of a failed check taken - neither "cannot be checked" nor out.
        st, got = self.sign('admin', 'nested')
        tok4 = got['token']
        st, got = self.sign('admin', 'nested')
        tok5 = got['token']
        bare = {'certlogin': {'port': 8443, 'busy': ''}}
        for why in ('nopicture', 'timeout', 'waiting', 'nocookie'):
            self.assertEqual(self.lost_root(tok4, why, bare), 'unknown', why)
        d = self.session_data(tok4)
        self.assertFalse(d.get('card_ok') or d.get('card_out'), d)
        self.assertEqual(len(self.events('cannot be checked in this browser')), u)
        self.proven(tok4)
        self.assertEqual(self.lost_root(tok4, 'nopicture', bare), 'unknown')
        self.assertFalse(self.session_data(tok4).get('card_out'))
        # ...a policy in the way is said all the same (c, below).
        self.assertEqual(self.lost_root(tok5, 'csp', bare), 'unknown')
        self.assertTrue(self.session_data(tok5).get('card_csp'))
        watch = {'certlogin': {'port': 8443, 'busy': '', 'watch': True}}
        self.assertEqual(self.lost_root(tok5, 'nopicture', watch), 'unable')
        self.assertEqual(self.lost_root(tok4, 'nopicture', watch), 'locked')
        # ...root's word as cl_card_port_ready reads it: `watch` for this port, or exactly what
        # is wanted applied (a root of an older version); nothing listening - never.
        got = self.py('import tempfile\nE.WEB_DIR = E.Path(tempfile.mkdtemp())\n'
                      'E.cl_listening = lambda p: True\nout = []\nd = E.web_desired(st)\n'
                      'p = E.cl_port()\n'
                      'for said in ({}, {"certlogin": {"port": p, "busy": ""}},\n'
                      '             {"certlogin": {"port": p, "busy": "", "watch": True}},\n'
                      '             {"certlogin": {"port": 1, "watch": True}},\n'
                      '             {"state": "done", "hash": E.web_hash(d)},\n'
                      '             {"state": "failed", "hash": E.web_hash(d)},\n'
                      '             {"state": "done", "hash": "x"}):\n'
                      '    E.web_status = lambda said=said: said\n'
                      '    out.append(E.cl_card_port_ready(st))\n'
                      'E.cl_listening = lambda p: False\n'
                      'E.web_status = lambda: {"certlogin": {"port": p, "watch": True}}\n'
                      'out.append(E.cl_card_port_ready(st))\n'
                      '# no root helper on this node at all: what listens is all there is\n'
                      'E.WEB_DIR = E.Path("/nonexistent-acme-web")\n'
                      'E.web_status = lambda: {}\n'
                      'out.append(E.cl_card_port_ready(st))\n'
                      'E.cl_listening = lambda p: True\n'
                      'out.append(E.cl_card_port_ready(st))\n'
                      'print(json.dumps(out))')
        self.assertEqual(got, [False, False, True, False, True, False, False, False, False, True])

        # c) The page's own policy blocked the check (a CSP header of the web server or a proxy):
        # said - once an hour for a sign-in - and on the card's facts; never a verdict, never out.
        c0 = len(self.events('was blocked'))      # (tok5's above: its own, once)
        st, got = self.sign('admin', 'nested')
        tok6 = got['token']
        for _ in range(2):
            self.assertEqual(lost(tok6, 'csp'), {'ok': True, 'state': 'unknown', 'csp': True})
        d = self.session_data(tok6)
        self.assertFalse(d.get('card_out') or d.get('card_ok'), d)
        self.assertTrue(d.get('card_csp'))
        self.assertEqual(self.call('GET', '/api/status', None, tok6)[0], 200)
        said = [w for w in self.events('was blocked')]
        self.assertEqual(len(said), c0 + 1, said)
        self.assertTrue(any("the check of the card of nested's sign-in to these pages was blocked: the "
                            "page's policy blocked the check - a Content-Security-Policy header" in w
                            for w in said), said)
        v = self.ok('GET', '/api/certlogin', session=self.ro)
        self.assertEqual(v['parts']['admin']['card']['csp']['name'], 'nested')
        self.assertNotIn('card', v['parts']['portal'])

        # d) Held (the card out): nothing of the person.
        st, got = self.sign('admin', 'nested')
        tok7 = got['token']
        self.proven(tok7)
        self.assertEqual(self.alive(tok7, None)[1]['state'], 'locked')
        st, me = self.call('GET', '/api/auth/whoami', None, tok7)
        self.assertEqual(sorted(me), ['idle_min', 'ok', 'who'])
        self.assertEqual(sorted(me['who']), ['card', 'how', 'name', 'role'])
        self.assertEqual((me['who']['role'], me['who']['how']), ('', 'certificate'))
        self.assertTrue(me['who']['card']['locked'])
        for method, path, body in (('GET', '/api/auth/mfa', None), ('GET', '/api/auth/passkeys', None),
                                   ('POST', '/api/auth/passkeys', {'action': 'add_begin'})):
            st, got = self.call(method, path, body, tok7)
            self.assertEqual((st, got.get('code')), (423, 'card'), (path, got))
        # F5 during the countdown: the page goes on from the server's clock.
        # (the time it takes to set it - a python started, the engine loaded - counted: 2 s on a
        # slow machine made it 16)
        began = time.time()
        self.session_set(tok7, card_out=began - 12)
        st, me = self.call('GET', '/api/auth/whoami', None, tok7)
        took = int(time.time() - began + 0.999)
        self.assertTrue(17 - took <= me['who']['card']['left'] <= 19, (took, me))
        # Held as its page stopped checking: the same.
        self.assertEqual(self.alive(tok7, 'nested')[1]['state'], 'ok')
        self.session_set(tok7, card_seen=time.time() - 3600)
        st, me = self.call('GET', '/api/auth/whoami', None, tok7)
        self.assertTrue(me['who']['card']['stale'])
        self.assertEqual(sorted(me['who']), ['card', 'how', 'name', 'role'])
        self.assertEqual(self.alive(tok7, 'nested')[1]['state'], 'ok')
        st, me = self.call('GET', '/api/auth/whoami', None, tok7)
        for k in ('prefs', 'cols', 'display', 'source'):
            self.assertIn(k, me['who'])
        self.assertEqual(me['who']['role'], 'fulladmin')
        # The portal: its `me` held - nothing of the person; its password change 423.
        self.on(portal_certlogin=1, portal_certlogin_card_watch='grace')
        st, got = self.sign('portal', 'falco')
        ptok = got['token']
        self.proven(ptok, 'falco', 'portal')
        self.assertEqual(self.alive(ptok, None, part='portal')[1]['state'], 'locked')
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertEqual(sorted(me['me']), ['card', 'kind', 'name', 'role'])
        self.assertEqual(me['me']['role'], '')
        st, got = self.call('POST', '/api/portal/password', {'old': 'x', 'new': 'y'}, ptok)
        self.assertEqual((st, got.get('code')), (423, 'card'), got)
        self.assertEqual(self.alive(ptok, 'falco', part='portal')[1]['state'], 'ok')
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertIn('about', me['me'])

        # e) An IPv6 address is no host-source a CSP takes: such a page lets `https:` in; a name
        # its port, as before - one header either way.
        if shutil.which('php'):
            st, got = self.sign('admin', 'nested')
            tok8 = got['token']
            csp = self.page_csp(tok8, host='[::1]')
            self.assertEqual(len(csp), 2, csp)
            self.assertIn("img-src 'self' data:; connect-src", csp[0])
            self.assertIn("img-src 'self' data: https:; connect-src", csp[1])
            csp = self.page_csp(tok8)
            self.assertIn("img-src 'self' data: https://%s:%d; connect-src" % (HOST, self.py('print(json.dumps(E.cl_port()))')), csp[1])
    finally:
        lsn.close()
        self.card_off()


@_t
def test_15_a_change_of_the_mode_counts_afresh(self):
    """The kit's 4th edition (1.10.356): the watch's mode changed - off, signout, grace - starts
    every sign-in's count afresh (card_out, card_seen gone; card_ok and card_w kept), said once;
    a time counted under grace no longer ends a sign-in at once under signout, nor an old
    card_out one switched off and on again."""
    self.card_on(admin_certlogin_card_watch='grace', admin_certlogin_card_grace=30)
    lsn = self.serving()
    try:
        st, got = self.sign('admin', 'nested')
        mine = got['token']
        st, got = self.sign('admin', 'nested')
        other = got['token']
        for t in (mine, other):
            self.proven(t)
            self.assertEqual(self.alive(t, None)[1]['state'], 'locked')
        self.session_set(other, card_out=time.time() - 25)
        st, got = self.settings(admin_certlogin_card_watch='signout')
        self.assertEqual(st, 200, got)
        for t in (mine, other):
            d = self.session_data(t)
            self.assertIsNotNone(d)
            self.assertFalse(d.get('card_out') or d.get('card_seen'), d)
            self.assertGreater(float(d.get('card_ok') or 0), 0)
            self.assertEqual(d.get('card_w'), 1)
            self.assertEqual(self.call('GET', '/api/status', None, t)[0], 200)
        self.assertTrue(any('the card\'s watch of these pages changed (grace -> signout): 2 watched '
                            'sign-in(s) count afresh' in w for w in self.events('count afresh')), self.events('count afresh'))
        # The doer's card_w kept by its own change of the mode.
        st, got = self.settings(session=mine, admin_certlogin_card_watch='grace')
        self.assertEqual(st, 200, got)
        self.assertEqual(self.session_data(mine).get('card_w'), 1)
        # Off and on again with a card_out of the period before: alive, in.
        self.session_set(other, card_out=time.time() - 3600)
        self.on(admin_certlogin_card_watch='off')
        self.on(admin_certlogin_card_watch='grace')
        self.assertEqual(self.call('GET', '/api/status', None, other)[0], 200)
        st, me = self.call('GET', '/api/auth/whoami', None, other)
        self.assertFalse(me['who']['card']['locked'])
        # The times changed, the mode not: nothing counted afresh.
        n = len(self.events('count afresh'))
        self.assertEqual(self.alive(other, 'nested')[1]['state'], 'ok')
        self.on(admin_certlogin_card_every=7)
        self.assertTrue(self.session_data(other).get('card_seen'))
        self.assertEqual(len(self.events('count afresh')), n)
    finally:
        lsn.close()
        self.card_off()


@_t
def test_16_hunt_p_r3_port_given_away_and_held_details(self):
    """Hunt P round 3: (a) root gave nginx no port - another program listens there (a WAF's
    agent), or nginx could not - or another port: no word of a failed check is taken, though
    root's hash says it applied what is wanted (every browser's failed picture judged it: out,
    or "cannot be checked"); (b) a sign-in held for its card is not "signed in" for an error's
    details (a domain controller's name, the database's address) - as one without its second
    step since 1.0.149; with the watch off, as before."""
    self.card_on(admin_certlogin_card_watch='grace', admin_certlogin_card_grace=30)
    lsn = self.serving()
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        got = self.py('import tempfile\nE.WEB_DIR = E.Path(tempfile.mkdtemp())\n'
                      'E.cl_listening = lambda p: True\nd = E.web_desired(st)\n'
                      'p = E.cl_port()\nh = E.web_hash(d)\nout = []\n'
                      'for said in ({"port": 0, "busy": "port %d is used by wafd" % p, "want": p},\n'
                      '             {"port": 0, "busy": "nginx could not listen on %d" % p, "want": p},\n'
                      '             {"port": p + 1, "busy": ""},\n'
                      '             {"port": p, "busy": ""},\n'
                      '             ["odd"]):\n'
                      '    E.web_status = lambda said=said: {"state": "done", "hash": h, "certlogin": said}\n'
                      '    out.append(E.cl_card_port_ready(st))\n'
                      'print(json.dumps(out))')
        self.assertEqual(got, [False, False, False, True, True])
        busy = {'state': 'done', 'hash': self.py('print(json.dumps(E.web_hash(E.web_desired(st))))'),
                'certlogin': {'port': 0, 'busy': 'port 8443 is used by wafd', 'want': 8443}}
        for why in ('nopicture', 'timeout', 'waiting'):
            self.assertEqual(self.lost_root(tok, why, busy), 'unknown', why)
        d = self.session_data(tok)
        self.assertFalse(d.get('card_ok') or d.get('card_out'), d)

        # b) Held: no details; in, or the watch off: as before.
        def signed_in(t):
            return self.py('class H:\n'
                           '    store = st\n'
                           '    headers = {"X-Acme-Session": %r}\n'
                           'print(json.dumps(E.ApiHandler._signed_in(H())))' % t)
        self.proven(tok)
        self.assertTrue(signed_in(tok))
        self.assertEqual(self.alive(tok, None)[1]['state'], 'locked')
        self.assertFalse(signed_in(tok))
        self.assertEqual(self.alive(tok, 'nested')[1]['state'], 'ok')
        self.assertTrue(signed_in(tok))
        self.session_set(tok, card_seen=time.time() - 3600)
        self.assertFalse(signed_in(tok))
        self.assertTrue(signed_in(self.ro))
        self.on(admin_certlogin_card_watch='off')
        self.assertTrue(signed_in(tok))
    finally:
        lsn.close()
        self.card_off()


@_t
def test_17_unable_made_signout_watches_again(self):
    """Hunt P round 3: "A browser that cannot be checked" from allow to signout while the card is
    watched - "the setting that enforces the watch for every browser" - watches again the
    sign-ins found not to be checkable under allow (they stayed unwatched until their idle time
    ended them): their next check without the card signs them out. The doer's stays as it is;
    nothing changes for signout to allow, nor with the watch off."""
    self.card_on()
    lsn = self.serving()

    def unable(tok):
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual(got['state'], 'unable', got)
        self.assertEqual(self.session_data(tok).get('card_ok'), -1)

    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = self.sign('admin', 'nested')
        doer = got['token']
        for t in (tok, doer):
            unable(t)
        n = len(self.events('are watched again'))
        st, got = self.settings(session=doer, admin_certlogin_card_unable='signout')
        self.assertEqual(st, 200, got)
        self.assertNotIn('card_ok', self.session_data(tok))
        self.assertEqual(self.session_data(doer).get('card_ok'), -1)
        said = self.events('are watched again')
        self.assertEqual(len(said), n + 1, said)
        self.assertTrue(any('a browser that cannot be checked is signed out now on these pages: 1 '
                            'sign-in(s) not watched until now are watched again' in w for w in said), said)
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertNotIn('unable', me['who']['card'])
        # Its next check without the card: signed out, as a card taken out.
        st, got = self.call('POST', '/api/certlogin/lost', {'v': 2, 'part': 'admin', 'why': 'nopicture'}, tok)
        self.assertEqual((got['state'], got['why']), ('gone', 'out'), got)
        self.assertIsNone(self.session_data(tok))
        # signout -> allow, and allow -> signout with the watch off: nothing written.
        self.on(admin_certlogin_card_unable='allow')
        self.assertEqual(self.session_data(doer).get('card_ok'), -1)
        self.on(admin_certlogin_card_watch='off')
        self.on(admin_certlogin_card_unable='signout')
        self.assertEqual(self.session_data(doer).get('card_ok'), -1)
        self.assertEqual(len(self.events('are watched again')), n + 1)
    finally:
        lsn.close()
        self.card_off()


def merge_cs(path, extra):
    """{English: Czech} added to a copy of web/lang/cs.json (screenshots in Czech) - a string, or
    a pattern where it has {0}."""
    with open(path, encoding='utf-8') as f:
        pack = json.load(f)
    with open(extra, encoding='utf-8') as f:
        more = json.load(f)
    have = {v['source'] for sect in ('strings', 'patterns', 'rich') for v in pack.get(sect, {}).values()}
    i = 0
    for en, cs in more.items():
        if en in have:
            continue
        i += 1
        sect = 'patterns' if re.search(r'\{\d\}', en) else ('rich' if '<' in en else 'strings')
        pack.setdefault(sect, {})['%s9%04d' % (sect[0], i)] = {'source': en, 'text': cs}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(pack, f, ensure_ascii=False, indent=1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
