#!/usr/bin/env python3
"""Bug hunt R run u4: the portal's certificate request flow, end to end.

    python3 test/test_hunt_ru4_portalreq.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (node + Playwright) when they are here.

- A request profile that gives the certificate to the person asking (owner "person"), offered
  in the workspace of a team whose rule makes every request wait: the picker and the form said
  "approved first" (and the button "Ask for it") - and it was issued at once, as the server
  does (the team's rule is for the team's certificates). Now the team's rule is said only of a
  profile whose certificate becomes the team's.
- Declining a request in the workspace's "Requests": "The person who asked is told why, by
  mail" and "declined - the person who asked is told" when no mail goes (no address of theirs,
  or mail switched off) - the certificate's own Decline said it right since hunt Rt7. The
  inbox now says per request whether a mail goes (told_by_mail), the toast what the server did.
- A key download approved (approve_actions key): "approved - portal:jan may take the key now"
  - the person by name now.
- The overview right after the sign-in: drawn before what waits was known - "Waiting for you
  0", "All is well - nothing waits for you" beside Requests 1, and an approved key to take not
  offered, until the minute's refresh. Drawn again once it is known.
- Czech: the policy's "Also approved first: revoking" said "odvolává se" (the state's word);
  a CSR check for a source that takes the CSR as it is ("names the profile does not give ...")
  had no Czech. Their words are in the scratch file of this hunt until merged.
"""
import json
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
import test_teams_portal_ui as TPU   # noqa: E402  (merged_lang)

SCRATCH_CS = os.environ.get('HUNT_CS') or os.path.join(
    '/tmp/claude-0/-home-user-ACME/845070b5-9900-5dee-8b93-2de7397138a5/scratchpad/huntr',
    'cs_ru4_portalreq.json')

NODE_PAGE = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, user, pass, flow, lang] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: 1400, height: 900}});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  const pause = ms => page.waitForTimeout(ms);
  const toast = async () => (await page.textContent('#toast').catch(() => '')) || '';
  try {
    await page.goto(base + '/');
    await page.fill('#in-name', user);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#pw-main', {timeout: 20000});
    if (flow === 'person-profile') {
      await pause(1500);
      await page.click('#pw-ask');
      await page.waitForSelector('.cp-prof', {timeout: 15000});
      out.cards = await page.$$eval('.cp-prof', cs => cs.map(c => c.innerText.split('\n').slice(0, 2).join(' ')));
      await page.locator('.cp-prof', {hasText: 'U4 person'}).first().click();
      await page.waitForSelector('#modal textarea.cp-names', {timeout: 10000});
      out.head = await page.$eval('.cp-prof-head', e => e.innerText);
      out.button = await page.locator('#modal-foot button.primary').innerText();
      await page.fill('#modal textarea.cp-names', 'u4-person.example.test');
      await page.locator('#modal-foot button.primary').click();
      await page.waitForFunction(() => /asked for/i.test(document.getElementById('toast').textContent), null, {timeout: 20000});
      out.toast = await toast();
    }
    if (flow === 'home') {
      await page.waitForSelector('.pw-attn', {timeout: 15000});
      await pause(3000);
      out.attn = await page.$eval('.pw-attn', e => e.innerText);
      out.tiles = await page.$$eval('.pw-tiles > *', ts => ts.map(t => t.innerText.replace(/\n/g, ' | ')));
    }
    if (flow === 'decline') {
      await page.evaluate(() => { location.hash = '#inbox/Web'; });
      const card = page.locator('.pw-inbox .pw-req', {hasText: 'u4-decline.example.test'}).first();
      await card.waitFor({timeout: 15000});
      await card.locator('button', {hasText: /Decline|Zamítnout/}).click();
      await page.waitForSelector('#modal textarea', {timeout: 10000});
      out.note = await page.$eval('#modal-body p.note', e => e.textContent);
      await page.fill('#modal textarea', 'not needed');
      await page.locator('#modal-foot button:visible', {hasText: /Decline it|Zamítnout/}).first().click();
      await page.waitForFunction(() => /declined|zamítnuto/i.test(document.getElementById('toast').textContent), null, {timeout: 20000});
      out.toast = await toast();
    }
    if (flow === 'limits') {
      await page.waitForSelector('.pw-attn', {timeout: 15000});
      await pause(1500);
      out.limits = await page.evaluate(() => document.body.innerText);
    }
  } catch (e) { out.error = String(e && e.stack || e); }
  await browser.close();
  console.log(JSON.stringify(out));
})();
"""


class HuntRu4PortalReq(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.php = None
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'own',
            'portal_cert_max': 1000, 'portal_cert_keys': 1, 'mail_mode': 'off'}})
        cls.must('POST', '/api/cas/create', {'name': 'U4 Root', 'subject': {'CN': 'U4 Root CA'},
                                             'key_type': 'ec-256', 'days': 3650})
        cls.must('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                               'config': {'ca': 'U4 Root', 'days': 90}})
        for n in ('ureq', 'ulead1', 'ulead2', 'uops'):
            cls.must('POST', '/api/users', {'action': 'add', 'name': n, 'role': 'readonly',
                                            'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {
            'name': 'Web', 'description': 'web',
            'members': [{'who': 'local:ureq', 'roles': ['Requester']},
                        {'who': 'local:ulead1', 'roles': ['Approver']},
                        {'who': 'local:ulead2', 'roles': ['Approver']}],
            'policy': {'suffixes': ['example.test'],
                       'approval': {'mode': 'always', 'approvers': 'team', 'count': 2}}})
        cls.must('POST', '/api/teams/save', {
            'name': 'Ops', 'description': 'ops',
            'members': [{'who': 'local:uops', 'roles': ['Requester']},
                        {'who': 'local:ulead1', 'roles': ['Approver']}],
            'policy': {'approve_actions': ['key', 'revoke'], 'approval': {'mode': 'none'}}})
        # the person's own (owner "person"), issued at once; and one of the team's
        cls.must('POST', '/api/reqprofiles/save', {
            'name': 'U4 person', 'issuer': 'own', 'suffixes': ['example.test'],
            'key_types': ['ec-256'], 'make_key': True, 'pfx': True, 'approval': False})
        cls.must('POST', '/api/reqprofiles/save', {
            'name': 'U4 team', 'issuer': 'own', 'suffixes': ['example.test'],
            'key_types': ['ec-256'], 'make_key': True, 'pfx': True, 'owner': 'team',
            'teams': ['Web']})
        cls.must('POST', '/api/reqprofiles/save', {
            'name': 'U4 ops', 'issuer': 'own', 'suffixes': ['example.test'],
            'key_types': ['ec-256'], 'make_key': True, 'pfx': True, 'owner': 'fixed',
            'owner_team': 'Ops', 'teams': ['Ops']})

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

    def portal(self, name):
        st, got = self.call('POST', '/api/portal/login', {'name': name, 'password': self.pw})
        self.assertEqual(st, 200, got)
        return got['token']

    def wait_job(self, job, tok):
        end = time.time() + 120
        while time.time() < end:
            st, got = self.call('GET', '/api/portal/cert_job?id=%s' % job, None, tok)
            j = got.get('job', got)
            if j.get('state') not in ('queued', 'running'):
                return j
            time.sleep(0.3)
        self.fail('job %s did not end' % job)

    @classmethod
    def serve(cls):
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        os.environ.setdefault('TP_CS_EXTRA', SCRATCH_CS if os.path.isfile(SCRATCH_CS) else '')
        TPU.merged_lang(web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
        port = TCC.free_port()
        cls.php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
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

    def page(self, user, flow, lang='en'):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        if self.php is None:
            type(self).base = self.serve()
        script = os.path.join(self.tmp, 'u4_page.js')
        with open(script, 'w') as f:
            f.write(NODE_PAGE)
        got = subprocess.run([node, script, self.base, user, self.pw, flow, lang],
                             capture_output=True, text=True, timeout=300, cwd=ROOT)
        lines = [x for x in (got.stdout or '').splitlines() if x.startswith('{')]
        self.assertTrue(lines, (got.stdout or '')[-3000:] + got.stderr[-3000:])
        out = json.loads(lines[-1])
        self.assertNotIn('error', out, out.get('error'))
        self.assertEqual(out.get('errors'), [], out)
        return out

    # ---- the server ---------------------------------------------------------------------------
    def test_01_inbox_says_whether_a_mail_goes(self):
        tok = self.portal('ureq')
        st, got = self.call('POST', '/api/portal/cert_request', {
            'names': ['u4-inbox.example.test'], 'issuer': 'own', 'team': 'Web'}, tok)
        self.assertEqual(st, 200, got)
        st, box = self.call('GET', '/api/portal/inbox', None, self.portal('ulead1'))
        self.assertEqual(st, 200, box)
        one = [r for r in box['requests'] if r['id'] == got['id']]
        self.assertTrue(one, box)
        self.assertIs(one[0].get('told_by_mail'), False, one)     # mail off, no address

    def test_02_key_approved_names_the_person(self):
        tok = self.portal('uops')
        st, got = self.call('POST', '/api/portal/cert_request', {
            'profile': 'U4 ops', 'names': ['u4-key.example.test']}, tok)
        self.assertEqual(st, 200, got)
        self.assertEqual(self.wait_job(got['job_id'], tok).get('state'), 'ok')
        st, d = self.call('POST', '/api/portal/cert_download', {
            'id': got['id'], 'format': 'pfx', 'password': 'abcdefgh1'}, tok)
        self.assertEqual(st, 200, d)
        self.assertTrue(d.get('waits'), d)
        st, x = self.call('POST', '/api/portal/action_approve',
                          {'id': d['action']['id'], 'ok': 1}, self.portal('ulead1'))
        self.assertEqual(st, 200, x)
        self.assertEqual(x['message'], 'approved - uops may take the key now')

    # ---- the pages ----------------------------------------------------------------------------
    def test_10_person_profile_in_a_strict_team(self):
        """Asked from the workspace of a team whose every request waits: a profile that gives
        the certificate to the person says "issued at once", and is."""
        got = self.page('ureq', 'person-profile')
        cards = dict((c.split(' ', 2)[0] + ' ' + c.split(' ', 2)[1], c) for c in got['cards']
                     if c.startswith('U4 '))
        self.assertIn('ISSUED AT ONCE', cards['U4 person'].upper(), got)
        self.assertIn('APPROVED FIRST', cards['U4 team'].upper(), got)     # the team's: waits
        self.assertIn('ISSUED AT ONCE', got['head'].upper(), got)
        self.assertEqual(got['button'], 'Ask and issue', got)
        self.assertIn('being issued', got['toast'], got)
        st, rows = self.call('GET', '/api/certs', None, self.admin)
        mine = [r for r in rows.get('rows', rows.get('certs', []))
                if r['name'] == 'u4-person.example.test']
        self.assertTrue(mine and mine[0]['state'] != 'pending-approval', mine)

    def test_11_the_overview_knows_what_waits(self):
        tok = self.portal('ureq')
        st, got = self.call('POST', '/api/portal/cert_request', {
            'names': ['u4-home.example.test'], 'issuer': 'own', 'team': 'Web'}, tok)
        self.assertEqual(st, 200, got)
        out = self.page('ulead2', 'home')
        self.assertNotIn('All is well', out['attn'], out)
        self.assertIn('wait for you', out['attn'], out)
        tile = [t for t in out['tiles'] if t.startswith('Waiting for you')]
        self.assertTrue(tile and 'nothing to approve' not in tile[0], out)

    def test_12_decline_says_no_mail_goes(self):
        tok = self.portal('ureq')
        st, got = self.call('POST', '/api/portal/cert_request', {
            'names': ['u4-decline.example.test'], 'issuer': 'own', 'team': 'Web'}, tok)
        self.assertEqual(st, 200, got)
        out = self.page('ulead1', 'decline')
        self.assertIn('no mail is sent', out['note'], out)
        self.assertIn('no mail is sent', out['toast'], out)

    def test_13_czech_words(self):
        out = self.page('uops', 'limits', 'cs')
        self.assertNotIn('odvolává se', out['limits'])
        if os.path.isfile(SCRATCH_CS):
            self.assertIn('odvolání certifikátu', out['limits'])
            with open(SCRATCH_CS, encoding='utf-8') as f:
                words = json.load(f)
            self.assertIn('names the profile does not give (the source takes the CSR as it '
                          'is): {0}', words)
        # the words the reqprofiles check says, as written there
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'reqprofiles.py'),
                  encoding='utf-8') as f:
            self.assertIn("'names the profile does not give (the source takes the CSR as '\n"
                          "                                'it is): %s'", f.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
