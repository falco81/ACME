#!/usr/bin/env python3
"""Bug hunt R run t6: the certificate portal outside the teams - "Your certificates", the
sign-in and its one-time code.

    python3 test/test_hunt_rt6_portal.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (test/hunt_rt6_portal_page.js) when node, php and Playwright
are here.

- The sign-in through the load balancer (portal_sso): a header that was not taken at all - not
  from a balancer named, or without its key (one made anew in the administration, the balancer
  not yet told) - signed out whoever was signed in on that browser: a person who then signed
  in with their password was signed straight out on the next page, and told to "sign in with
  your password". The daemon now says such a refusal is about the header (`untrusted`), and the
  page keeps the sign-in it has; a refusal of the person (the directory) still ends it.
- The one-time code of the sign-in: the box said "000 000" whatever code_digits (4-10) was, and
  nine or ten digits did not fit it (the last ones scrolled away). Now as long as the code is.
- "nobody can sign in here yet: no directory is set up ..." (no directory, no account of acme's
  own) came out half Czech ("no directory is nastavil for these pages") - its translation is in
  the scratch file of this hunt until it is merged into web/lang/cs.json.
"""
import json
import http.cookiejar
import os
import shutil
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)

SCRATCH_CS = os.environ.get('HUNT_CS') or os.path.join(
    '/tmp/claude-0/-home-user-ACME/845070b5-9900-5dee-8b93-2de7397138a5/scratchpad/huntr',
    'cs_rt6_portal.json')
NO_DIR = ('nobody can sign in here yet: no directory is set up for these pages. Administrators '
          'sign in at /admin/')

# i18n.js on texts, in node, with web/lang/cs.json (and the hunt's own words where they are not
# in it yet) - as test_hunt_r7_i18n.py does it
NODE_I18N = r"""
const vm = require('vm'), fs = require('fs'), path = require('path');
const [root, extra, texts] = process.argv.slice(2);
const all = JSON.parse(fs.readFileSync(path.join(root, 'web', 'lang', 'cs.json'), 'utf8'));
const pack = {code: 'cs', strings: {}, patterns: [], rich: {}};
for (const part of ['strings', 'patterns', 'rich']) for (const e of Object.values(all[part] || {})) {
  const from = String(e.source || ''), to = String(e.text || '');
  if (!from || !to || (to === from && part !== 'patterns')) continue;
  if (part === 'patterns') pack.patterns.push([from, to]); else pack[part][from] = to;
}
if (extra && fs.existsSync(extra)) {
  const more = JSON.parse(fs.readFileSync(extra, 'utf8'));
  for (const k of Object.keys(more)) if (!(k in pack.strings)) pack.strings[k] = more[k];
}
const ctx = {window: {}, Map, Set, WeakMap, console, ACME_LANG_PACK: pack,
  document: {readyState: 'loading', addEventListener() {}, documentElement: {setAttribute() {}, classList: {remove() {}}},
             querySelectorAll: () => [], createTreeWalker() { return {nextNode: () => null}; }},
  MutationObserver: function () { this.observe = () => {}; this.takeRecords = () => []; }, setTimeout: () => {}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(root, 'web', 'assets', 'i18n.js'), 'utf8')
                + ';this.i18nText = i18nText; this.i18nInit = i18nInit;', ctx);
ctx.i18nInit(pack);
const out = {};
for (const s of JSON.parse(fs.readFileSync(texts, 'utf8'))) out[s] = ctx.i18nText(s);
console.log(JSON.stringify(out));
"""

# The box of the one-time code at a phone's width, for codes of 6, 8, 9 and 10 digits.
NODE_GATE = r"""
const { chromium } = require('playwright');
(async () => {
  const [base] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await (await browser.newContext({viewport: {width: 390, height: 844}})).newPage();
  const out = {errors: [], codes: {}};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  try {
    await page.goto(base + '/');
    await page.waitForSelector('#signin-form');
    for (const n of [6, 8, 9, 10]) {
      await page.evaluate(n => gateForm({kind: 'mail', dest: 'j***@example.test', minutes: 5,
                                         live: true, sso: false, digits: n}), n);
      await page.fill('.gate-code', '7'.repeat(n));
      out.codes[n] = await page.$eval('.gate-code', c => ({placeholder: c.placeholder,
        over: c.scrollWidth - c.clientWidth}));
    }
    out.wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  } catch (e) { out.error = String(e && e.stack || e); }
  await browser.close();
  console.log(JSON.stringify(out));
})();
"""


class HuntRt6Portal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        # tester: a full administrator - seeing all off, so "Your certificates" as anybody's
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_admins_all': 0,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.ids = {}
        for name, names, owner in (
                ('t6-mine', ['t6-mine.example.test'], 'local:tester'),
                ('t6-other', ['t6-other.example.test'], 'local:viewer')):
            got = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': names, 'issuer': 'self', 'key_type': 'ec-256',
                'auto_renew': 0, 'owner': owner})
            cls.ids[name] = got['id']
            job = cls.must('POST', '/api/certs/renew', {'id': got['id'], 'force': True})['job_id']
            end = time.time() + 120
            while time.time() < end:
                j = cls.must('GET', '/api/certs/job?id=%d' % job)['job']
                if j['state'] not in ('queued', 'running'):
                    break
                time.sleep(0.3)
        cls.php = None

    @classmethod
    def tearDownClass(cls):
        if cls.php is not None:
            cls.php.terminate()
            cls.php.wait(10)
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def serve(cls):
        """The pages through php -S, against this daemon: their address."""
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
        with open(os.path.join(web, 'router.php'), 'w') as f:
            # nginx passes ACME_PEER (the balancer's own address) as a fastcgi_param; php -S has
            # none - set from here, as test_portal_sso.py does
            f.write("<?php\n$_SERVER['ACME_PEER'] = '127.0.0.1';\n"
                    "$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);\n"
                    "if ($p === '/' || $p === '/index.php') { chdir(__DIR__); "
                    "require __DIR__ . '/index.php'; return true; }\n"
                    "return false;\n")
        port = TCC.free_port()
        cls.php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port, 'router.php'], cwd=web,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 20
        while time.time() < end:
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=5)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        return 'http://127.0.0.1:%d' % port

    def portal(self, name='tester'):
        st, got = self.call('POST', '/api/portal/login', {'name': name, 'password': self.pw})
        self.assertEqual(st, 200, got)
        return got['token']

    @classmethod
    def sso_on(cls):
        if getattr(cls, 'sso_key', None):
            return cls.sso_key
        cls.sso_key = cls.must('POST', '/api/portal-sso', {'action': 'key'})['key']
        cls.must('POST', '/api/settings', {'settings': {'portal_sso': 1,
                                                        'portal_sso_from': '127.0.0.1'}})
        return cls.sso_key

    def sso(self, name, key, peer='127.0.0.1', session=None):
        url = 'http://127.0.0.1:%d/api/portal/sso' % self.port
        req = urllib.request.Request(url, data=json.dumps({'name': name, 'key': key}).encode(),
                                     method='POST')
        req.add_header('X-Acme-Token', self.token)
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-Acme-Peer', peer)
        if session:
            req.add_header('X-Acme-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def need_page_tools(self, browser=False):
        if not shutil.which('php') or (browser and not shutil.which('node')):
            self.skipTest('no php or node here')
        if browser and subprocess.run([shutil.which('node'), '-e', 'require("playwright")'],
                                      capture_output=True, cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        if self.php is None:
            type(self).base = self.serve()
        return self.base

    # ---- the sign-in through the load balancer -----------------------------------------------
    def test_01_a_header_not_taken_says_so(self):
        """Not from a balancer named, or without its key: `untrusted` - the page keeps whoever
        is signed in; a refusal of the person never says it."""
        key = self.sso_on()
        tok = self.portal()
        for st, got in (self.sso('jan.novak', 'not-the-key-at-all-not-the-key-at-all'),
                        self.sso('jan.novak', ''),
                        self.sso('jan.novak', key, peer='192.0.2.99')):
            self.assertEqual(st, 401, got)
            self.assertIs(got.get('untrusted'), True, got)
            self.assertNotIn('token', got)
        # the header taken, its name refused: about the person - nothing of `untrusted`
        st, got = self.sso('jan\x01novak', key)
        self.assertEqual(st, 401, got)
        self.assertNotIn('untrusted', got)
        # the sign-in with the password, untouched by any of it
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertEqual(st, 200, me)
        self.assertEqual((me.get('me') or {}).get('name'), 'tester', me)

    def test_02_the_page_keeps_a_password_sign_in(self):
        """The page: signed in with the password, the next page with the balancer's header but
        not its key - still signed in (it was signed out, and told to sign in with the
        password)."""
        self.sso_on()
        base = self.need_page_tools()
        jar = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        req = urllib.request.Request(base + '/?api=login', method='POST', data=json.dumps(
            {'name': 'tester', 'password': self.pw}).encode())
        req.add_header('Content-Type', 'application/json')
        with op.open(req, timeout=60) as r:
            self.assertEqual(r.status, 200)
        self.assertTrue(any(c.name == 'acme_portal' for c in jar), list(jar))
        req = urllib.request.Request(base + '/')
        req.add_header('X-Acme-User', 'jan.novak')
        with op.open(req, timeout=60) as r:
            page = r.read().decode('utf-8', 'replace')
        self.assertIn('id="signout"', page)
        self.assertNotIn('id="in-pass"', page)
        self.assertTrue(any(c.name == 'acme_portal' and c.value for c in jar), list(jar))

    # ---- the one-time code -------------------------------------------------------------------
    def test_03_the_code_box_as_long_as_the_code(self):
        base = self.need_page_tools(browser=True)
        script = os.path.join(self.tmp, 'gate_page.js')
        with open(script, 'w') as f:
            f.write(NODE_GATE)
        got = subprocess.run([shutil.which('node'), script, base], capture_output=True,
                             text=True, timeout=240, cwd=ROOT)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertNotIn('error', out, out.get('error'))
        self.assertEqual(out['errors'], [])
        self.assertLessEqual(out['wide'], 0, out)
        codes = out['codes']
        self.assertEqual(codes['6']['placeholder'], '000 000')
        for n in ('8', '9', '10'):
            self.assertEqual(codes[n]['placeholder'], '0' * int(n), codes)
        for n, one in codes.items():
            self.assertLessEqual(one['over'], 0, (n, codes))

    # ---- the words -----------------------------------------------------------------------------
    def test_04_no_directory_in_czech(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        # the daemon's words, as it says them
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_local': 0}}, self.admin)
        self.assertEqual(st, 200, got)
        try:
            st, got = self.call('POST', '/api/portal/login', {'name': 'x', 'password': 'y'})
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_local': 1}})
        self.assertEqual((st, got.get('error')), (503, NO_DIR), got)
        script = os.path.join(self.tmp, 'i18n.js')
        texts = os.path.join(self.tmp, 'texts.json')
        with open(script, 'w') as f:
            f.write(NODE_I18N)
        with open(texts, 'w') as f:
            json.dump([NO_DIR], f)
        got = subprocess.run([node, script, ROOT, SCRATCH_CS, texts], capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        cs = json.loads(got.stdout)[NO_DIR]
        self.assertTrue(cs and cs != NO_DIR, cs)
        for word in ('nobody', 'directory', 'these pages', 'Administrators'):
            self.assertNotIn(word, cs)


if __name__ == '__main__':
    if os.environ.get('HUNT_SERVE'):
        HuntRt6Portal.setUpClass()
        print(HuntRt6Portal.serve(), HuntRt6Portal.pw, HuntRt6Portal.port,
              HuntRt6Portal.token, HuntRt6Portal.admin, flush=True)
        try:
            time.sleep(int(os.environ['HUNT_SERVE']))
        finally:
            HuntRt6Portal.tearDownClass()
    else:
        unittest.main(verbosity=2)
