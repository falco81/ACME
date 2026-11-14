#!/usr/bin/env python3
"""The sign-in page's ways together (1.0.100): a password, Windows (Kerberos) and a certificate
on one part - each a button, at once when the page opens, or off - and in which order those
tried by themselves are tried.

    python3 test/test_signin_modes.py      (or python3 -m unittest test.test_signin_modes)

Two halves:

- The page's own logic (web/assets/core.js: krbDoor, certDoor and what decides whether the
  certificate is gone to by itself), run with node against a page of its own - the order
  (Windows first, the certificate only when it did not sign in), no loop after a refusal, a
  certificate not chosen, Sign out, ?nocert, a broken setup. Skipped where node is not here.
- A real daemon with both ways on (test_kerberos.py's realm, test_cert_login.py's PKI): what the
  pages are told of each part (/api/health, /api/portal/info), both sign-ins with "no password
  at all" on, a password refused, and the pages themselves through php -S (the buttons, the
  form or none, data-auto, "Use a password instead"). Skipped where MIT Kerberos or openssl
  are not here.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import test_kerberos as TK           # noqa: E402  (the realm)
import test_cert_login as TCL        # noqa: E402  (the PKI)
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'
HOST = 'acme.corpnet.loc'
FULL = 'CN=CERT_SUPPLIER_X,OU=Groups,' + BASE        # nested: a full admin, both ways
WATCH = 'CN=CERT_USERS,OU=Groups,' + BASE


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


# ---- the page's logic, with node --------------------------------------------------------------
# A page of its own: the boxes the sign-in pages draw, sessionStorage of one tab (kept between
# the "loads" of a scenario, as a tab keeps it), fetch answering as the relay does, and every
# navigation written down. Each load runs what web/admin/index.php runs: certDoor(), then
# krbDoor(done, next).
HARNESS = r'''
var CODE = %(code)s;
var STORE = {}, NOW = 1700000000000, LOG = [];
var KRB_ANSWER = 'no_ticket';
global.sessionStorage = {getItem: function (k) { return Object.prototype.hasOwnProperty.call(STORE, k) ? STORE[k] : null; },
  setItem: function (k, v) { STORE[k] = String(v); }, removeItem: function (k) { delete STORE[k]; }};
Date.now = function () { return NOW; };
global.setTimeout = function (f) { f(); return 1; };
global.clearTimeout = function () { };
var ELS = {};
global.$ = function (id) { return ELS[id] || null; };
function box(id, data) {
  var span = {textContent: ''};
  var e = {id: id, dataset: data || {}, className: '', textContent: '', disabled: false, hidden: false,
           parentNode: {hidden: false}, onclick: null, querySelector: function () { return span; }, focus: function () { }};
  ELS[id] = e;
  return e;
}
global.location = {search: '', pathname: '/admin/', hash: ''};
Object.defineProperty(global.location, 'href', {set: function (v) { LOG.push('go ' + v); }, get: function () { return 'https://acme/admin/' + this.search; }});
global.history = {replaceState: function (a, b, u) { var q = u.indexOf('?'); location.search = q >= 0 ? u.slice(q) : ''; }};
global.fetch = function (url) {
  var what = String(url).replace(/^\?api=/, '');
  LOG.push('ask ' + what);
  if (what === 'kerberos-login') {
    if (KRB_ANSWER === 'ok') return Promise.resolve({ok: true, status: 200, text: function () { return Promise.resolve('{"ok":true}'); }});
    var body = KRB_ANSWER === 'no_ticket' ? '{"code":"no_ticket","error":"the browser sent no Kerberos ticket"}'
      : '{"error":"Windows sign-in refused: not allowed"}';
    return Promise.resolve({ok: false, status: KRB_ANSWER === 'no_ticket' ? 401 : 403, text: function () { return Promise.resolve(body); }});
  }
  return Promise.resolve({ok: true, status: 200, json: function () { return Promise.resolve({ok: true, url: 'https://acme:8443/admin/?api=cert-login&n=x'}); }});
};
eval(CODE);
function load(page) {
  ELS = {};
  LOG = [];
  location.search = page.search || '';
  if (page.krb) { box('krb-box', {part: 'admin', auto: page.krb === 'auto' ? '1' : '0', only: page.only ? '1' : '0'}); box('krb-go'); box('krb-said'); }
  if (page.cert) { box('cert-box', {part: 'admin', auto: page.cert === 'auto' ? '1' : '0', only: page.only ? '1' : '0'}); box('cert-go'); box('cert-said'); box('cert-pw'); }
  if (!page.only) { box('in-said'); box('in-name'); }
  var signed = false;
  var next = certDoor();
  krbDoor(function () { signed = true; }, next);
  return new Promise(function (done) { setImmediate(function () { setImmediate(function () {
    done({log: LOG.slice(), signed: signed, krb_said: ELS['krb-said'] ? ELS['krb-said'].textContent : null,
          cert_said: ELS['cert-said'] ? ELS['cert-said'].textContent : null,
          pw_hidden: ELS['cert-pw'] ? ELS['cert-pw'].parentNode.hidden : null, search: location.search});
  }); }); });
}
function tab() { STORE = {}; }
(async function () {
  var out = {};
  var both = {krb: 'auto', cert: 'auto'};
  // 1. Both by themselves: Windows first; it did not sign in - on to the certificate.
  tab(); KRB_ANSWER = 'no_ticket';
  out.order = await load(both);
  // 2. Windows signed in: the certificate never asked.
  tab(); KRB_ANSWER = 'ok';
  out.windows_in = await load(both);
  // 3. Windows refused (a ticket, not let in): said, and nothing else starts.
  tab(); KRB_ANSWER = 'deny';
  out.krb_refused = await load(both);
  // ...back from the port refused (?certsaid): nothing by itself, both buttons there, said.
  tab(); KRB_ANSWER = 'no_ticket';
  await load(both);
  out.back_refused = await load(Object.assign({search: '?certsaid=allowed'}, both));
  // 4. ...and the page loaded again in that tab: still nothing by itself.
  out.again = await load(both);
  // 5. A certificate not chosen (back with certsaid=certificate), the certificate alone.
  tab();
  out.alone = await load({cert: 'auto'});
  out.not_chosen = await load({cert: 'auto', search: '?certsaid=certificate'});
  out.not_chosen_again = await load({cert: 'auto'});
  // 6. Signed out in this tab: neither by itself.
  tab(); KRB_ANSWER = 'no_ticket';
  STORE['acme.krb.out.admin'] = '1';
  out.signed_out = await load(both);
  // 7. ?nocert ("Use a password instead"): Windows by itself still, the certificate not - and
  //    not on the next load of that tab either.
  tab();
  out.nocert = await load(Object.assign({search: '?nocert'}, both));
  out.nocert_again = await load({cert: 'auto'});
  // 8. A broken setup (back without a word - the browser's own error page and Back, a sign-in
  //    that never sticks): once in ten minutes, three times a tab at most.
  tab();
  var seen = [];
  for (var i = 0; i < 6; i++) {
    var got = await load({cert: 'auto'});
    seen.push(got.log.indexOf('ask cert-nonce') >= 0);
    NOW += (i === 0 ? 60000 : 11 * 60000);
  }
  out.guard = seen;
  // 9. Only Windows by itself: it did not sign in - the certificate stays a button.
  tab(); KRB_ANSWER = 'no_ticket';
  out.krb_only_auto = await load({krb: 'auto', cert: 'button'});
  // 10. Only the certificate by itself, Windows a button: straight to the certificate.
  tab();
  out.cert_only_auto = await load({krb: 'button', cert: 'auto'});
  // 11. Neither by itself: nothing asked.
  tab();
  out.buttons = await load({krb: 'button', cert: 'button'});
  console.log(JSON.stringify(out));
})().catch(function (e) { console.log('FAILED ' + e.stack); process.exit(1); });
'''


def page_code():
    core = read('web', 'assets', 'core.js')
    start = core.index('function krbAsk(')
    end = core.index('function certDoor() {')
    end = core.index('\n}\n', end) + 3
    return core[start:end]


@unittest.skipUnless(shutil.which('node'), 'no node here')
class PageLogic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        js = HARNESS % {'code': json.dumps(page_code())}
        got = subprocess.run([shutil.which('node'), '-e', js], capture_output=True, text=True,
                             timeout=120)
        if got.returncode or not got.stdout.strip().startswith('{'):
            raise RuntimeError('node: %s %s' % (got.stdout[-2000:], got.stderr[-2000:]))
        cls.out = json.loads(got.stdout)

    def test_windows_first_then_the_certificate(self):
        log = self.out['order']['log']
        self.assertEqual(log[:2], ['ask kerberos-login', 'ask cert-nonce'], log)
        self.assertTrue(log[-1].startswith('go https://acme:8443/'), log)
        # Windows signed in: the certificate is never asked.
        self.assertEqual(self.out['windows_in']['log'], ['ask kerberos-login'])
        self.assertTrue(self.out['windows_in']['signed'])

    def test_no_loop_after_a_refusal(self):
        # Windows refused by itself (a ticket, not let in): said why, the certificate not tried.
        self.assertEqual(self.out['krb_refused']['log'], ['ask kerberos-login'])
        self.assertEqual(self.out['krb_refused']['krb_said'], 'Windows sign-in refused: not allowed')
        back = self.out['back_refused']
        # Back from the certificate refused: nothing asked by itself, said, both buttons offered.
        self.assertEqual(back['log'], [], back)
        self.assertEqual(back['cert_said'], 'Certificate sign-in refused: not allowed')
        self.assertEqual(back['search'], '', 'certsaid taken out of the address')
        self.assertEqual(self.out['again']['log'], [])
        # The certificate alone: not chosen - never again in that tab.
        self.assertIn('ask cert-nonce', self.out['alone']['log'])
        self.assertEqual(self.out['not_chosen']['log'], [])
        self.assertEqual(self.out['not_chosen']['cert_said'],
                         'Certificate sign-in refused: certificate not accepted')
        self.assertEqual(self.out['not_chosen_again']['log'], [])

    def test_not_after_sign_out_nor_with_nocert(self):
        self.assertEqual(self.out['signed_out']['log'], [])
        self.assertEqual(self.out['nocert']['log'], ['ask kerberos-login'])
        self.assertTrue(self.out['nocert']['pw_hidden'])
        self.assertEqual(self.out['nocert_again']['log'], [])

    def test_a_broken_setup_never_loops(self):
        # once, not within ten minutes again, then after them - three times a tab at most
        self.assertEqual(self.out['guard'], [True, False, True, True, False, False])

    def test_one_by_itself_the_other_a_button(self):
        self.assertEqual(self.out['krb_only_auto']['log'], ['ask kerberos-login'])
        self.assertEqual(self.out['cert_only_auto']['log'][0], 'ask cert-nonce')
        self.assertNotIn('ask kerberos-login', self.out['cert_only_auto']['log'])
        self.assertEqual(self.out['buttons']['log'], [])

    def test_the_pages_run_it_in_that_order(self):
        for page, src in (('web/admin/index.php', read('web', 'admin', 'index.php')),
                          ('web/assets/portal.js', read('web', 'assets', 'portal.js'))):
            i, j = src.index('var certNext = certDoor();'), src.index('}, certNext);')
            self.assertLess(i, j, page)
            self.assertIn('krbDoor(function (d) {', src[i:j], page)


# ---- a daemon with both ways ------------------------------------------------------------------
@unittest.skipUnless(TK._have_kerberos() and shutil.which('openssl'),
                     'no MIT Kerberos or no openssl here')
class BothWays(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    py = TCC.CertsCore.py
    ticket = TK.Kerberos.__dict__['ticket']
    keytab_b64 = TK.Kerberos.__dict__['keytab_b64']
    must = TCL.CertLogin.__dict__['must']
    settings = TCL.CertLogin.__dict__['settings']
    pem = TCL.CertLogin.__dict__['pem']
    b64 = TCL.CertLogin.__dict__['b64']
    back_to_passwords = TCL.CertLogin.__dict__['back_to_passwords']

    @classmethod
    def setUpClass(cls):
        TK.Kerberos.kdc_up.__func__(cls)
        TCL.CertLogin.pki_up.__func__(cls)
        os.environ['KRB5_CONFIG'] = os.path.join(cls.kdc, 'krb5.conf')
        cls.ldap_was = {dn: dict(v) for dn, v in mockldap.PEOPLE.items()}
        cls.groups_was = json.dumps(mockldap.GROUPS)
        for dn, one in mockldap.PEOPLE.items():
            sam = (one.get('sAMAccountName') or [''])[0]
            if sam in TCL.SIDS:
                one['objectSid'] = [TCL.sid_bytes(TCL.SIDS[sam])]
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        # The CRLs are served on this machine: loopback is no address a CDP may have otherwise.
        os.environ['ACME_CDP_LOOPBACK_OK'] = '1'
        try:
            TCC.CertsCore.setUpClass.__func__(cls)
        finally:
            os.environ.pop('ACME_CDP_LOOPBACK_OK', None)
        try:
            cls.both_up()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def both_up(cls):
        cls.cport = TCL.free_port()
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'admin_directory': 'corp', 'admin_group_full': FULL, 'admin_group_readonly': WATCH,
            'portal': 1, 'portal_directory': 'corp', 'portal_who': 'groups',
            'portal_groups': WATCH, 'portal_tries': 50, 'login_tries': 50,
            # a port nothing here listens on (8443 may be another nginx's on this machine)
            'certlogin_port': cls.cport}})
        cls.must('POST', '/api/kerberos', {'action': 'put', 'data': cls.keytab_b64('http.keytab'),
                                           'name': 'http.keytab'})
        cls.must('POST', '/api/certlogin', {'action': 'put', 'data': TCL.CertLogin.b64(cls, 'cas.pem'),
                                            'name': 'cas.pem'})

    @classmethod
    def tearDownClass(cls):
        try:
            TCC.CertsCore.tearDownClass.__func__(cls)
        finally:
            cls.ldap_stop.set()
            mockldap.PEOPLE.clear()
            mockldap.PEOPLE.update(cls.ldap_was)
            mockldap.GROUPS.clear()
            mockldap.GROUPS.update(json.loads(cls.groups_was))
            proc = getattr(cls, 'kdc_proc', None)
            if proc is not None:
                proc.terminate()
                proc.wait(10)
            cls.crl_srv.shutdown()
            shutil.rmtree(cls.kdc, ignore_errors=True)
            shutil.rmtree(cls.pki, ignore_errors=True)
            os.environ.pop('KRB5_CONFIG', None)

    def setUp(self):
        self.call('POST', '/api/lockouts', {'action': 'clear_all'}, self.admin)

    def on(self, **kv):
        self.must('POST', '/api/settings', {'settings': kv})

    def krb(self, part, person):
        path = '/api/auth/kerberos' if part == 'admin' else '/api/portal/kerberos'
        return self.call('POST', path, {'header': 'Negotiate ' + self.ticket(person)})

    def cert(self, part, person):
        st, got = TCL.CertLogin.sign(self, part, person)     # as the page hands it on
        if st != 200:                   # the reason, from Events, for the message of a failure
            st2, ev = self.call('GET', '/api/events', None, self.admin,
                                args={'q': 'certificate was refused'})
            got['why'] = [e.get('words') for e in (ev.get('events') or ev.get('rows') or [])][:1] \
                if st2 == 200 else []
        return st, got

    def modes(self, whole=False):
        st, h = self.call('GET', '/api/health')
        st2, info = self.call('GET', '/api/portal/info')
        if whole:
            return h['signin'], info['signin']
        keys = ('password', 'windows', 'certificate', 'order')
        return tuple({k: x[k] for k in keys} for x in (h['signin'], info['signin']))

    def test_01_each_mode_of_each_part(self):
        self.on(admin_krb=0, admin_certlogin=0, portal_krb=0, portal_certlogin=0)
        off = {'password': True, 'windows': 'off', 'certificate': 'off', 'order': []}
        self.assertEqual(self.modes(), (off, off))
        try:
            # The administration: both, Windows a button, the certificate at once.
            self.on(admin_krb=1, admin_certlogin=1, admin_certlogin_auto=1)
            a, p = self.modes()
            self.assertEqual(a, {'password': True, 'windows': 'button', 'certificate': 'auto',
                                 'order': ['certificate']})
            self.assertEqual(p, off, 'the portal has switches of its own')
            st, h = self.call('GET', '/api/health')
            self.assertEqual(h['certlogin']['auto'], True)
            self.assertEqual(h['kerberos']['auto'], False)
            # Both by themselves: Windows first - whatever order they were switched on in.
            self.on(admin_krb_auto=1)
            self.assertEqual(self.modes()[0]['order'], ['windows', 'certificate'])
            # The portal: Windows at once, the certificate a button.
            self.on(portal_krb=1, portal_krb_auto=1, portal_certlogin=1)
            a, p = self.modes()
            self.assertEqual(p, {'password': True, 'windows': 'auto', 'certificate': 'button',
                                 'order': ['windows']})
            # The cards say the same.
            a, p = self.modes(whole=True)
            v = self.ok('GET', '/api/certlogin')
            self.assertEqual(v['parts']['admin']['signin'], a)
            self.assertEqual(v['parts']['portal']['signin'], p)
            self.assertTrue(v['parts']['admin']['auto'])
            k = self.ok('GET', '/api/kerberos')
            self.assertEqual(k['parts']['portal']['signin'], p)
            # The kit's object the page decides by: on, auto, cert, cert_port, cert_auto, only.
            self.assertEqual({x: a[x] for x in ('on', 'auto', 'cert', 'cert_port', 'cert_auto', 'only')},
                             {'on': True, 'auto': True, 'cert': True, 'cert_port': self.cport,
                              'cert_auto': True, 'only': False})
            self.assertTrue(k['parts']['admin']['cert'])
            # The certificate by itself switched off with its way: nothing at once of it.
            self.on(admin_certlogin=0)
            self.assertEqual(self.modes()[0]['certificate'], 'off')
            self.assertEqual(self.modes()[0]['order'], ['windows'])
            st, h = self.call('GET', '/api/health')
            self.assertEqual(h['certlogin'], {'on': False, 'auto': False, 'only': False, 'port': 0})
        finally:
            self.on(admin_krb=0, admin_krb_auto=0, admin_certlogin=0, admin_certlogin_auto=0,
                    portal_krb=0, portal_krb_auto=0, portal_certlogin=0)

    def test_02_both_ways_no_password(self):
        self.on(admin_krb=1, admin_certlogin=1, admin_krb_auto=1, admin_certlogin_auto=1)
        try:
            st, kerb = self.krb('admin', 'nested')
            self.assertEqual(st, 200, kerb)
            # "No password at all", switched on from the Windows sign-in.
            st, got = self.settings(session=kerb['token'], admin_password_off=1)
            self.assertEqual(st, 200, got)
            a = self.modes()[0]
            self.assertEqual(a, {'password': False, 'windows': 'auto', 'certificate': 'auto',
                                 'order': ['windows', 'certificate']})
            # A password refused - said as both ways are on.
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 403, got)
            self.assertIn('only Windows or a certificate', got['error'])
            # Both ways still sign in - and each one is the other's way back.
            st, got = self.cert('admin', 'nested')
            self.assertEqual(st, 200, got)
            st, me = self.call('GET', '/api/auth/whoami', None, got['token'])
            self.assertEqual((me['who']['name'], me['who']['how']), ('nested', 'certificate'))
            st, got = self.krb('admin', 'nested')
            self.assertEqual(st, 200, got)
            # A refusal by one way leaves the other: the certificate of somebody in no group
            # refused, Windows signs in next.
            st, got = self.cert('admin', 'outsider')
            self.assertIn(st, (401, 403), got)
            st, got = self.krb('admin', 'nested')
            self.assertEqual(st, 200, got)
            # Windows switched off: the certificate keeps "no password at all" in effect.
            st, got = self.settings(session=kerb['token'], admin_krb=0)
            self.assertEqual(st, 200, got)
            a = self.modes()[0]
            self.assertEqual((a['password'], a['windows'], a['certificate']), (False, 'off', 'auto'))
            st, got = self.call('POST', '/api/auth/login', {'name': 'tester', 'password': self.pw})
            self.assertEqual(st, 403, got)
            self.assertIn('only a certificate', got['error'])
        finally:
            self.back_to_passwords()
            self.on(admin_krb=0, admin_krb_auto=0, admin_certlogin=0, admin_certlogin_auto=0)

    def test_03_the_portal_both_ways(self):
        self.on(portal_krb=1, portal_certlogin=1, portal_certlogin_auto=1)
        try:
            st, got = self.krb('portal', 'falco')
            self.assertEqual(st, 200, got)
            st, got = self.cert('portal', 'falco')
            self.assertEqual(st, 200, got)
            self.assertEqual(got.get('how'), 'certificate')
        finally:
            self.on(portal_krb=0, portal_certlogin=0, portal_certlogin_auto=0)

    def test_04_the_pages(self):
        """The sign-in pages through php -S: the buttons, the form or none, data-auto and
        "Use a password instead"."""
        if not shutil.which('php'):
            self.skipTest('no php here')
        web = tempfile.mkdtemp(prefix='acme-modes-web-')
        shutil.rmtree(web)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        with open(os.path.join(web, 'router.php'), 'w') as f:
            f.write("<?php\n$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);\n"
                    "$_SERVER['HTTPS'] = 'on';\n"
                    "if ($p === '/' || $p === '/index.php') { chdir(__DIR__); require __DIR__ . '/index.php'; return true; }\n"
                    "if ($p === '/admin/') { chdir(__DIR__ . '/admin'); require __DIR__ . '/admin/index.php'; return true; }\n"
                    "return false;\n")
        port = TCL.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port, 'router.php'], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='2'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def page(path):
            for _ in range(50):
                try:
                    req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path))
                    req.add_header('Host', HOST)
                    with urllib.request.urlopen(req, timeout=60) as r:
                        return r.read().decode('utf-8', 'replace')
                except urllib.error.HTTPError as e:
                    return e.read().decode('utf-8', 'replace')
                except OSError:
                    time.sleep(0.1)
            raise RuntimeError('php -S did not answer')

        def boxes(body):
            krb = re.search(r'id="krb-box"[^>]*data-auto="(\d)"', body)
            cert = re.search(r'id="cert-box"[^>]*data-auto="(\d)"', body)
            return (krb.group(1) if krb else None, cert.group(1) if cert else None,
                    'id="in-pass"' in body, 'id="cert-pw"' in body)
        kerb = None
        try:
            self.on(admin_krb=1, admin_certlogin=1)
            # Both on, neither by itself: the form, then both buttons under it.
            body = page('/admin/')
            self.assertEqual(boxes(body), ('0', '0', True, False))
            self.assertLess(body.index('id="in-pass"'), body.index('id="krb-go"'))
            self.assertLess(body.index('id="krb-go"'), body.index('id="cert-go"'))
            # The certificate by itself: "Use a password instead" on the form.
            self.on(admin_certlogin_auto=1)
            body = page('/admin/')
            self.assertEqual(boxes(body), ('0', '1', True, True))
            self.assertIn('href="?nocert"', body)
            self.on(admin_krb_auto=1)
            self.assertEqual(boxes(page('/admin/')), ('1', '1', True, True))
            # The portal by its own switches.
            self.on(portal_krb=1, portal_certlogin=1, portal_certlogin_auto=1)
            self.assertEqual(boxes(page('/')), ('0', '1', True, True))
            # No password at all: both buttons, no form, no "Use a password".
            st, kerb = self.krb('admin', 'nested')
            st, got = self.settings(session=kerb['token'], admin_password_off=1)
            self.assertEqual(st, 200, got)
            body = page('/admin/')
            self.assertEqual(boxes(body), ('1', '1', False, False))
            self.assertIn('id="krb-go"', body)
            self.assertIn('id="cert-go"', body)
        finally:
            if kerb:
                self.back_to_passwords()
            self.on(admin_krb=0, admin_krb_auto=0, admin_certlogin=0, admin_certlogin_auto=0,
                    portal_krb=0, portal_certlogin=0, portal_certlogin_auto=0)
            php.terminate()
            php.wait(10)
            shutil.rmtree(web, ignore_errors=True)

    def test_06_the_last_way_in(self):
        """No password at all with Windows alone: Windows tried by itself whatever its switch
        says, and the keytab not taken away; with the certificate alone, the last authority
        not taken away (and the certificate stays a button unless its switch says otherwise)."""
        self.on(admin_krb=1, admin_krb_auto=0, admin_certlogin=0)
        try:
            st, kerb = self.krb('admin', 'nested')
            self.assertEqual(st, 200, kerb)
            st, got = self.settings(session=kerb['token'], admin_password_off=1)
            self.assertEqual(st, 200, got)
            a = self.modes()[0]
            self.assertEqual(a, {'password': False, 'windows': 'auto', 'certificate': 'off',
                                 'order': ['windows']})
            st, got = self.call('POST', '/api/kerberos', {'action': 'drop'}, kerb['token'])
            self.assertEqual(st, 409, got)
            self.assertIn('alone signs people in', got['error'])
            # The certificate on as well: Windows by its own switch again (a button).
            st, got = self.settings(session=kerb['token'], admin_certlogin=1)
            self.assertEqual(st, 200, got)
            a = self.modes()[0]
            self.assertEqual((a['windows'], a['certificate']), ('button', 'button'))
            # Windows off: the certificate alone - a button still, its authority kept.
            st, got = self.settings(session=kerb['token'], admin_krb=0)
            self.assertEqual(st, 200, got)
            st, card = self.cert('admin', 'nested')
            self.assertEqual(st, 200, card)
            a = self.modes()[0]
            self.assertEqual((a['password'], a['windows'], a['certificate']), (False, 'off', 'button'))
            v = self.ok('GET', '/api/certlogin', session=card['token'])
            for c in v['cas']:
                st, got = self.call('POST', '/api/certlogin', {'action': 'drop', 'sha256': c['sha256']},
                                    card['token'])
                if st != 200:
                    break
            self.assertEqual(st, 409, got)
            self.assertIn('alone signs people in', got['error'])
            self.assertEqual(len(self.ok('GET', '/api/certlogin', session=card['token'])['cas']), 1)
        finally:
            self.back_to_passwords()
            self.on(admin_krb=0, admin_certlogin=0)
            self.must('POST', '/api/certlogin', {'action': 'put', 'data': TCL.CertLogin.b64(self, 'cas.pem'),
                                                 'name': 'cas.pem'})

    def test_05_the_cards_and_the_command_line(self):
        self.on(admin_krb=1, admin_certlogin=1, admin_krb_auto=1, admin_certlogin_auto=1)
        try:
            for flag in ('--kerberos', '--cert-login'):
                got = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), flag],
                                     env=self.env, capture_output=True, text=True, timeout=120)
                self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
                self.assertIn('the sign-in page: a password yes, Windows at once, a certificate '
                              'at once (when it opens: windows then certificate)', got.stdout)
        finally:
            self.on(admin_krb=0, admin_krb_auto=0, admin_certlogin=0, admin_certlogin_auto=0)


class Static(unittest.TestCase):
    def test_the_sign_in_page_card(self):
        """A card The sign-in page for each part: the one switch both ways share, and the facts
        of what a person meets (the shared facts table - columns of one width)."""
        js = read('web', 'assets', 'admin.js')
        page = read('web', 'admin', 'index.php')
        for part in ('admin', 'portal'):
            self.assertIn('id="signin-card-%s"' % part, page)
            self.assertIn('id="sect-%ssignin"' % part, page)
            self.assertIn('id="signin-host-%s"' % part, page)
            # Next to the cards of Windows and of the certificate, before them.
            self.assertLess(page.index('id="signin-card-%s"' % part), page.index('id="krb-card-%s"' % part))
        self.assertEqual(js.count('drawSignin(part, p);'), 2)
        fn = js[js.index('function drawSignin(part, p) {'):]
        fn = fn[:fn.index('\n}\n')]
        for row in ('Name and password', 'Sign in with Windows', 'Sign in with a certificate',
                    'Tried by itself when the page opens', 'After a refusal', 'After Sign out'):
            self.assertIn("'%s'" % row, fn)
        self.assertIn('krbFacts(host, [', fn)
        defaults = read('acmelib', 'engine', '005_paths_and_defaults.py')
        self.assertIn("'adminsignin': ['admin_password_off'],", defaults)
        self.assertIn("'portalsignin': ['portal_password_off'],", defaults)

    def test_asleep_cannot_be_changed(self):
        js = read('web', 'assets', 'admin.js')
        self.assertIn("if (!live && !c.disabled) { c.disabled = true; c.dataset.asleep = '1'; }", js)


if __name__ == '__main__':
    unittest.main(verbosity=2)
