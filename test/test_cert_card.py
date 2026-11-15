#!/usr/bin/env python3
"""The card watched (1.0.113): a sign-in made with a certificate - a smart card, a YubiKey - ends
(or is locked) when its card is taken out.

    python3 test/test_cert_card.py      (or python3 -m unittest test.test_cert_card)

test/test_cert_login.py's PKI, directory and daemon (its setup borrowed, none of its tests run):
  - off (the default): nothing new - no key `card` anywhere, the check's routes 404, nginx's
    server of the certificate's port byte for byte as before;
  - the check (/api/certlogin/alive, as the page on the certificate's port relays nginx's
    certificate): the same certificate - alive; none, another one, nginx's refusal - signed out
    at once (signout), or locked (lock: every request but the check 423) and back when the card
    proves again, signed out after the grace time;
  - a check that could not be made (/api/certlogin/lost): taken as the card gone only while the
    port is served here;
  - no check for too long: the sign-in ends (a request of it, and the daemon's sweep);
  - password sign-ins never touched; switched on, the certificate's sign-ins made before end;
  - the settings: --set, refused values, the card's facts;
  - nginx: with the card watched no TLS session resumed, no connection kept, no HTTP/2, the
    check's address let through - and a real nginx with php-fpm where they are here (a full
    handshake on every check, CORS for the page's own origin only, signed out with another
    certificate), and Chromium (Playwright) where it is: a page signed in with the certificate
    goes to the sign-in page, saying why, when the check's handshake fails (the card's key no
    longer signing is simulated by failing the browser's requests to the port), and the lock
    over the page goes away when the card proves again.
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
import time
import unittest
import urllib.parse

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


def _t(fn):
    setattr(CardWatch, fn.__name__, fn)
    return fn


def alive(self, token, cert=None, part='admin', failed=''):
    body = {'part': part}
    if cert:
        body['cert'] = self.pem(cert)
    if failed:
        body['failed'] = failed
    return self.call('POST', '/api/certlogin/alive', body, token)


def card_on(self, part='admin', **kv):
    self.put()
    self.on(**dict({part + '_certlogin': 1, part + '_certlogin_card_watch': 'signout',
                    part + '_certlogin_card_every': 5}, **kv))


def card_off(self):
    self.on(admin_certlogin_card_watch='off', portal_certlogin_card_watch='off',
            admin_certlogin_card_grace=60, admin_certlogin_card_stale='auto',
            portal_certlogin_card_stale='auto', admin_certlogin_card_every=10,
            portal_certlogin_card_every=10, portal_certlogin_card_grace=60,
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


def page_csp(self, token):
    """The CSP of /admin/ through php -S: signed out, and signed in with `token`."""
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
            conn.request('GET', '/admin/', headers=dict({'Host': HOST}, **({'Cookie': cookie} if cookie else {})))
            r = conn.getresponse()
            out += [v for k, v in r.getheaders() if k.lower() == 'content-security-policy']
            r.read()
            conn.close()
    finally:
        php.terminate()
        php.wait(10)
        shutil.rmtree(web, ignore_errors=True)
    return out


for _f in (alive, card_on, card_off, session_data, session_set, page_csp):
    setattr(CardWatch, _f.__name__, _f)


@_t
def test_01_off_changes_nothing(self):
    """Off (the default): no key `card` in any answer, nothing kept in the session, the check's
    routes 404, certlogin_desired without `watch` - and nginx's server as before."""
    got = self.py('print(json.dumps([E.DEFAULTS[p + "_certlogin_card_" + k] for p in ("admin", '
                  '"portal") for k in ("watch", "every", "grace", "stale")]))')
    self.assertEqual(got, ['off', 10, 60, 'auto'] * 2)
    self.put()
    self.on(admin_certlogin=1, portal_certlogin=1)
    try:
        st, got = self.sign('admin', 'nested')
        self.assertEqual(st, 200, got)
        tok = got['token']
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertNotIn('card', me['who'])
        self.assertEqual(me['who']['how'], 'certificate')
        self.assertNotIn('card', self.session_data(tok))
        v = self.ok('GET', '/api/certlogin', session=self.ro)
        for part in ('admin', 'portal'):
            self.assertNotIn('card', v['parts'][part])
        st, got = self.alive(tok, 'nested')
        self.assertEqual(st, 404, got)
        st, got = self.call('POST', '/api/certlogin/lost', {'part': 'admin'}, tok)
        self.assertEqual(st, 404, got)
        st, got = self.sign('portal', 'falco')
        self.assertEqual(st, 200, got)
        st, me = self.call('GET', '/api/portal/me', None, got['token'])
        self.assertNotIn('card', me['me'])
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertNotIn('watch', want)
        W = load_web('off')
        c = W.certlogin_checked(want)
        self.assertNotIn('watch', c)
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            main = f.read()
        text = W.certlogin_text(main, None, c)
        for no in ('ssl_session_cache      off', 'keepalive_timeout', 'cert-alive'):
            self.assertNotIn(no, text)
        self.assertIn('ssl_session_cache', text)        # the 443 server's, kept as before
        self.assertIn('http2', text)
        H = head_web()
        if H is not None and hasattr(H, 'certlogin_text'):
            # Byte for byte what the last commit wrote.
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
        self.assertEqual(me['who']['card']['watch'], 'signout')
        self.assertEqual(me['who']['card']['every'], 5)
        self.assertEqual(me['who']['card']['port'], 8443)
        self.assertFalse(me['who']['card']['locked'])
        # The same card: alive - and the check is no activity of the person (last untouched).
        last = self.py('print(json.dumps(st.db.value("SELECT MAX(last) FROM sessions WHERE '
                       'kind = \'admin\'")))')
        st, got = self.alive(tok, 'nested')
        self.assertEqual((st, got['state']), (200, 'ok'), got)
        self.assertTrue(self.session_data(tok).get('card_at'))
        # Another certificate of the same person's authority (falco's) with nested's sign-in.
        st, got = self.alive(tok, 'falco')
        self.assertEqual((st, got['state']), (200, 'gone'), got)
        self.assertIsNone(self.session_data(tok))
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 401)
        self.assertTrue(any('nested was signed out of these pages' in w and 'another certificate' in w
                            for w in self.events('signed out of these pages')))
        # Its other tabs are told why (ten minutes), not just "signed out".
        st, got = self.alive(tok, 'nested')
        self.assertEqual(got['state'], 'gone', got)
        # No certificate at all, and nginx's own refusal: the same.
        for cert, failed in ((None, ''), ('nested', 'FAILED:certificate has expired')):
            st, got = self.sign('admin', 'nested')
            tok = got['token']
            st, got = self.alive(tok, cert, failed=failed)
            self.assertEqual(got['state'], 'gone', (cert, got))
            self.assertIsNone(self.session_data(tok))
        # A token that never was: none (the page reloads as usual).
        st, got = self.alive('x' * 43, 'nested')
        self.assertEqual(got['state'], 'none', got)
        # last was not moved by the checks
        self.assertTrue(last is None or isinstance(last, (int, float)))
    finally:
        self.card_off()


@_t
def test_03_locked_and_back(self):
    self.card_on(admin_certlogin_card_watch='lock', admin_certlogin_card_grace=30)
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        st, got = self.alive(tok, None)
        self.assertEqual((got['state'], got['left'], got['grace']), ('locked', 30, 30), got)
        # Locked: nothing answered but the check - and whoami says so (the page shows its lock).
        st, got = self.call('GET', '/api/status', None, tok)
        self.assertEqual(st, 423, got)
        self.assertIn('put your card back', got['error'])
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertTrue(me['who']['card']['locked'])
        self.assertLessEqual(me['who']['card']['left'], 30)
        # A second failed check does not start the lock again.
        st, got = self.alive(tok, None)
        self.assertEqual(got['state'], 'locked')
        # The card back: on as before.
        st, got = self.alive(tok, 'nested')
        self.assertEqual((got['state'], got.get('resumed')), ('ok', True), got)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.assertTrue(any('the card is back' in w for w in self.events('the card is back')))
        # Locked again, and the grace time gone by: signed out - by the check, by a request.
        self.alive(tok, 'falco')
        session = self.session_data(tok)
        self.assertTrue(session.get('card_lock'))
        self.session_set(tok, card_lock=time.time() - 31)
        st, got = self.alive(tok, 'nested')
        self.assertEqual(got['state'], 'gone', got)
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.alive(tok, None)
        self.session_set(tok, card_lock=time.time() - 31)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 401)
        self.assertTrue(any('not put back within 30 s' in w for w in self.events('not put back')))
        # The portal: its own switch, the same way.
        self.on(portal_certlogin=1, portal_certlogin_card_watch='lock')
        st, got = self.sign('portal', 'falco')
        ptok = got['token']
        st, me = self.call('GET', '/api/portal/me', None, ptok)
        self.assertEqual(me['me']['card']['watch'], 'lock')
        st, got = self.alive(ptok, None, part='portal')
        self.assertEqual(got['state'], 'locked')
        st, got = self.call('GET', '/api/portal/certs', None, ptok)
        self.assertEqual(st, 423, got)
        st, got = self.alive(ptok, 'falco', part='portal')
        self.assertEqual(got['state'], 'ok')
        # The administration's sign-in is no portal's: the admin's token checked as the portal's.
        st, got = self.sign('admin', 'nested')
        st, got = self.alive(got['token'], 'nested', part='portal')
        self.assertEqual(got['state'], 'none', got)
    finally:
        self.card_off()


@_t
def test_04_passwords_untouched(self):
    """A password's sign-in is never watched: no `card`, the check says unwatched, nothing ends."""
    self.card_on(admin_certlogin_card_stale='60')
    try:
        tok = self.login('viewer')
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertNotIn('card', me['who'])
        for cert in ('nested', None, 'falco'):
            st, got = self.alive(tok, cert)
            self.assertEqual(got['state'], 'unwatched', got)
        lsn = self.serving()
        try:
            st, got = self.call('POST', '/api/certlogin/lost', {'part': 'admin'}, tok)
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
def test_05_no_check_for_too_long(self):
    self.card_on(admin_certlogin_card_stale='60')
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.alive(tok, 'nested')
        self.session_set(tok, card_at=time.time() - 50, created=time.time() - 50)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 200)
        self.session_set(tok, card_at=time.time() - 70, created=time.time() - 70)
        self.assertEqual(self.call('GET', '/api/status', None, tok)[0], 401)
        self.assertTrue(any('no check of the card arrived' in w for w in self.events('no check of the card')))
        # The daemon's sweep ends one nobody asks about any more (the tab closed).
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        # (set and swept in one go: the daemon's own sweep, every 15 s, may come first otherwise)
        n = self.py('import hashlib\nth = hashlib.sha256(%r.encode()).hexdigest()\n'
                    'r = st.db.row("SELECT id FROM sessions WHERE token_hash = ?", (th,))\n'
                    'st.session_merge(r["id"], {"card_at": time.time() - 70})\n'
                    'st.db.run("UPDATE sessions SET created = ? WHERE id = ?", (time.time() - 70, r["id"]))\n'
                    'E.CL_CARD_SWEEP["at"] = 0\nprint(json.dumps(E.cl_card_sweep(st)))' % tok)
        self.assertGreaterEqual(n, 1)
        self.assertIsNone(self.session_data(tok))
        # auto: three checks missed and 30 s, two minutes at least; off: never.
        got = self.py('E.CONFIG["admin_certlogin_card_stale"] = "auto"\n'
                      'a = E.cl_card_stale("admin")\nE.CONFIG["admin_certlogin_card_every"] = 60\n'
                      'b = E.cl_card_stale("admin")\nE.CONFIG["admin_certlogin_card_stale"] = "off"\n'
                      'print(json.dumps([a, b, E.cl_card_stale("admin")]))')
        self.assertEqual(got, [120, 210, 0])
    finally:
        self.card_off()


@_t
def test_06_lost_only_while_served(self):
    self.card_on()
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        self.not_serving()
        st, got = self.call('POST', '/api/certlogin/lost', {'part': 'admin'}, tok)
        self.assertEqual(got['state'], 'unknown', got)
        self.assertIsNotNone(self.session_data(tok))
        lsn = self.serving()
        try:
            st, got = self.call('POST', '/api/certlogin/lost', {'part': 'admin'}, tok)
            self.assertEqual(got['state'], 'gone', got)
            self.assertIsNone(self.session_data(tok))
            self.assertTrue(any('could not be made' in w for w in self.events('could not be made')))
        finally:
            lsn.close()
    finally:
        self.card_off()


@_t
def test_07_switched_on_ends_the_ones_before(self):
    """Switched on (a stricter rule, as cl_rule): a certificate's sign-in made before kept no card
    to compare with - it ends; the password's of whoever switched it on stays."""
    self.put()
    self.on(admin_certlogin=1)
    try:
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = self.settings(admin_certlogin_card_watch='signout')
        self.assertEqual(st, 200, got)
        self.assertIsNone(self.session_data(tok))
        self.assertEqual(self.call('GET', '/api/status', None, self.admin)[0], 200)
        self.assertTrue(any('the card watched' in w for w in self.events('the card watched')))
        # Lock and the times changed while on: no sign-in ends for that.
        st, got = self.sign('admin', 'nested')
        tok = got['token']
        st, got = self.settings(admin_certlogin_card_watch='lock', admin_certlogin_card_every=30)
        self.assertEqual(st, 200, got)
        self.assertIsNotNone(self.session_data(tok))
        st, me = self.call('GET', '/api/auth/whoami', None, tok)
        self.assertEqual((me['who']['card']['watch'], me['who']['card']['every']), ('lock', 30))
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
        for k, bad in (('admin_certlogin_card_watch', 'maybe'), ('admin_certlogin_card_every', '7'),
                       ('admin_certlogin_card_grace', '5'), ('portal_certlogin_card_stale', '42')):
            st, got = self.settings(**{k: bad})
            self.assertEqual(st, 400, (k, got))
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
        self.assertEqual(v['parts']['admin']['card'], {'watch': 'lock', 'every': 10, 'grace': 120,
                                                        'stale': 120, 'sessions': 0})
        self.assertNotIn('card', v['parts']['portal'])
        st, got = self.sign('admin', 'nested')
        v = self.ok('GET', '/api/certlogin', session=self.ro)
        self.assertEqual(v['parts']['admin']['card']['sessions'], 1)
        s = {x['key']: x for x in self.ok('GET', '/api/settings')['settings']}
        self.assertEqual(s['admin_certlogin_card_watch']['choices'], ['off', 'signout', 'lock'])
        self.assertEqual(s['admin_certlogin_card_every']['choices'], ['5', '10', '15', '30', '60'])
        only = self.py('print(json.dumps([E.ONLY_WHEN[k] for k in ("admin_certlogin_card_watch", '
                       '"admin_certlogin_card_every", "admin_certlogin_card_grace", '
                       '"portal_certlogin_card_stale")]))')
        self.assertEqual(only, [['admin_certlogin', '1'], ['admin_certlogin_card_watch', 'off-not'],
                                ['admin_certlogin_card_watch', 'lock'],
                                ['portal_certlogin_card_watch', 'off-not']])
        # Signed where access-granting settings are (db_guard): a row written past acme is no word.
        self.assertTrue(self.py('print(json.dumps(all(k in E.DBGUARD_SETTINGS for k in E.DEFAULTS '
                                'if "_certlogin_card_" in k)))'))
    finally:
        self.card_off()


@_t
def test_09_nginx_with_the_card_watched(self):
    """The server of the certificate's port with the card watched: no session resumed (cache,
    tickets), no connection kept (keepalive 0, no HTTP/2), the check's address let through on
    both parts' locations - and back as before once neither watches it."""
    self.card_on(portal_certlogin=1, portal_certlogin_card_watch='signout')
    try:
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertTrue(want.get('watch'))
        W = load_web('on')
        c = W.certlogin_checked(want)
        self.assertTrue(c['watch'])
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            main = f.read()
        text = W.certlogin_text(main, None, c)
        self.assertIn('ssl_session_cache      off;', text)
        self.assertIn('ssl_session_tickets    off;', text)
        self.assertIn('keepalive_timeout      0;', text)
        self.assertNotIn('shared:ACME', text)
        self.assertNotIn('http2', text)
        self.assertEqual(text.count('api=cert-alive&t=[0-9]{1,16}'), 2)      # admin and portal
        self.assertNotIn('ssl_session_cache', main.split('server {', 1)[0])
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
        self.on(admin_certlogin_card_watch='off')
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertTrue(want.get('watch'))                  # the portal's still
        self.on(portal_certlogin_card_watch='off')
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        self.assertNotIn('watch', want)
        self.assertNotIn('keepalive_timeout', W.certlogin_text(main, None, W.certlogin_checked(want)))
    finally:
        self.card_off()


@_t
def test_10_real_nginx_and_the_browser(self):
    """A real nginx (the root helper's servers, the page's 443 on 443 itself where it is free:
    the check's CORS is for https://<name> with no port) and php-fpm with the pages: the check
    a full handshake every time, for the page's own origin only; and Chromium where it is."""
    fpm = shutil.which('php-fpm') or next((p for p in ('/usr/sbin/php-fpm8.3', '/usr/sbin/php-fpm8.2',
                                                       '/usr/sbin/php-fpm') if os.path.exists(p)), None)
    if not shutil.which('nginx') or not fpm or os.geteuid() != 0:
        self.skipTest('no nginx, php-fpm or root here')
    if self._open(443) or self._open(8443):
        self.skipTest('443 or 8443 is taken here')
    name = 'localhost'
    self.card_on(portal_certlogin=1, certlogin_port=8443, admin_certlogin_card_every=5)
    d = tempfile.mkdtemp(prefix='acme-card-nginx-')
    procs = []
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
                    'pm.max_children = 4\nclear_env = no\nuser = root\ngroup = root\nlisten.mode = 0666\n'
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
        want = self.py('print(json.dumps(E.certlogin_desired(st)))')
        c = W.certlogin_checked(want)
        self.assertTrue(c.get('watch'))
        cert_conf = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;',
                           W.certlogin_text(main, None, c))
        main = re.sub(r'include\s+fastcgi_params;', 'include /etc/nginx/fastcgi_params;', main)
        with open(W.CERTLOGIN_CA, 'w') as f:
            f.write(c['cas'])
        if not self._v6():
            cert_conf = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', cert_conf)
            main = re.sub(r'(?m)^\s*listen\s+\[::\][^\n]*\n', '', main)
        p80 = TCL.free_port()
        main = re.sub(r'listen(\s+)80;', r'listen\g<1>%d;' % p80, main)
        main = re.sub(r'listen(\s+)\[::\]:80;', r'listen\g<1>[::]:%d;' % p80, main)
        main = re.sub(r'(?m)^\s*ssl_dhparam[^\n]*\n', '', main)
        cert_conf = re.sub(r'(?m)^\s*ssl_dhparam[^\n]*\n', '', cert_conf)
        with open(os.path.join(d, 'nginx.conf'), 'w') as f:
            f.write('pid %s/nginx.pid;\nerror_log %s/error.log;\nevents {}\nhttp {\n'
                    'include /etc/nginx/mime.types;\naccess_log %s/access.log;\n'
                    'client_body_temp_path %s;\nfastcgi_temp_path %s;\nproxy_temp_path %s;\n'
                    'scgi_temp_path %s;\nuwsgi_temp_path %s;\n%s\n%s\n}\n'
                    % (d, d, d, d, d, d, d, d, main, cert_conf))
        t = subprocess.run(['nginx', '-t', '-p', d, '-c', os.path.join(d, 'nginx.conf')],
                           capture_output=True, text=True)
        self.assertEqual(t.returncode, 0, t.stderr + cert_conf)
        procs.append(subprocess.Popen(['nginx', '-p', d, '-c', os.path.join(d, 'nginx.conf'),
                                       '-g', 'daemon off;'], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))
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
                tls12=False):
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
            conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=hd)
            sk = conn.sock
            facts = type('TLS', (), {'session': sk.session, 'session_reused': sk.session_reused})()
            r = conn.getresponse()
            out = (r.status, r.getheaders(), r.read().decode('utf-8', 'replace'), facts)
            conn.close()
            return out

        def hget(headers, h):
            return [v for k, v in headers if k.lower() == h.lower()]

        # Signed in with the card through the port, the cookie back on 443.
        st, hd, body, _s = ask(443, '/admin/?api=cert-nonce', method='POST', body={})
        self.assertEqual(st, 200, body)
        url = json.loads(body)['url']
        path = url.split(':8443', 1)[1]
        n = [x.split(';')[0] for x in hget(hd, 'Set-Cookie') if x.startswith('__Host-acme_certn_')][0]
        st, hd, body, _s = ask(8443, path, 'nested', [n])
        self.assertEqual(hget(hd, 'Location'), ['https://%s/admin/' % name], body)
        sess = [x.split(';')[0] for x in hget(hd, 'Set-Cookie') if x.startswith('__Host-acme_session=')]
        # The page on 443: its CSP lets it ask the certificate's port, and the page knows it.
        st, hd, body, _s = ask(443, '/admin/', cookies=sess)
        csp = hget(hd, 'Content-Security-Policy')
        self.assertEqual(len(csp), 1, csp)
        self.assertIn("connect-src 'self' https://%s:8443;" % name, csp[0])
        self.assertIn('"card":{"watch":"signout"', body.replace(' ', ''))
        # The check, from the page's own origin: alive, CORS for it, the connection closed.
        origin = 'https://%s' % name
        st, hd, body, s1 = ask(8443, '/admin/?api=cert-alive&t=1', 'nested', sess, origin=origin)
        self.assertEqual((st, json.loads(body)['state']), (200, 'ok'), body)
        self.assertEqual(hget(hd, 'Access-Control-Allow-Origin'), [origin])
        self.assertEqual(hget(hd, 'Access-Control-Allow-Credentials'), ['true'])
        self.assertIn('close', ' '.join(hget(hd, 'Connection')).lower())
        # A full handshake every time: the session of the last one offered, not taken (TLS 1.2
        # and 1.3) - where 443, with its session cache, takes it (the check of the check).
        for tls12 in (True, False):
            a = ask(443, '/healthz', None, tls12=tls12)[3]
            b = ask(443, '/healthz', None, tls12=tls12, sess=a.session)[3]
            if tls12:
                self.assertTrue(b.session_reused, '443 resumes TLS 1.2 sessions')
            st, hd, body, s1 = ask(8443, '/admin/?api=cert-alive&t=2', 'nested', sess, origin=origin,
                                   tls12=tls12)
            st, hd, body, s2 = ask(8443, '/admin/?api=cert-alive&t=2', 'nested', sess, origin=origin,
                                   sess=s1.session, tls12=tls12)
            self.assertEqual(json.loads(body)['state'], 'ok', body)
            self.assertFalse(s2.session_reused, 'TLS 1.2' if tls12 else 'TLS 1.3')
        # Another site's page: refused, nothing said to it.
        st, hd, body, _s = ask(8443, '/admin/?api=cert-alive&t=3', 'nested', sess,
                               origin='https://evil.example')
        self.assertEqual(st, 403)
        self.assertEqual(hget(hd, 'Access-Control-Allow-Origin'), [])
        # The page on 443 has no such address; the port nothing else new.
        self.assertEqual(ask(443, '/admin/?api=cert-alive&t=4', None, sess)[0], 404)
        self.assertEqual(ask(8443, '/admin/?api=cert-alive&t=4&x=1', 'nested', sess, origin=origin)[0], 404)
        # Another person's card (falco's) with nested's sign-in: signed out.
        st, hd, body, _s = ask(8443, '/admin/?api=cert-alive&t=5', 'falco', sess, origin=origin)
        self.assertEqual(json.loads(body)['state'], 'gone', body)
        st, hd, body, _s = ask(443, '/admin/', cookies=sess)
        self.assertNotIn('id="signout"', body)
        # Chromium, where Playwright is here.
        node = shutil.which('node')
        js = os.path.join(HERE, 'cert_card_page.js')
        if node and os.path.exists(js):
            def browser(phase):
                got = subprocess.run([node, js, phase, 'https://%s' % name,
                                      os.path.join(self.pki, 'nested.pem'),
                                      os.path.join(self.pki, 'nested.key'), 'tester', self.pw, SHOTS],
                                     capture_output=True, text=True, timeout=900, input='',
                                     env=dict(os.environ, NODE_PATH=os.environ.get('NODE_PATH') or
                                              '/opt/node22/lib/node_modules'))
                line = (got.stdout.strip().splitlines() or ['{}'])[-1]
                try:
                    res = json.loads(line)
                except ValueError:
                    res = {'error': got.stdout[-1500:] + got.stderr[-1500:]}
                if res.get('skip'):
                    print('the browser\'s part skipped: %s' % res['skip'])
                    return None
                self.assertTrue(res.get('ok'), phase + ': ' + json.dumps(res, indent=1) + got.stderr[-2000:])
                print('%s: %s' % (phase, json.dumps(res.get('timing'))))
                return res
            if browser('signout') is not None:
                self.assertTrue(any('nested was signed out of these pages' in w and 'could not be made' in w
                                    for w in self.events('could not be made')))
                self.on(admin_certlogin_card_watch='lock', admin_certlogin_card_grace=60)
                browser('lock')
                browser('options')
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        self.card_off()
        shutil.rmtree(d, ignore_errors=True)


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
