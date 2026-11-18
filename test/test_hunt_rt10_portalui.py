#!/usr/bin/env python3
"""Bug hunt R run t10: the certificate portal's pages, swept in Chromium.

    python3 test/test_hunt_rt10_portalui.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (node + Playwright), when they are here.

- A device's deletion sent for approval (the team's approve_actions): the device's dialog stayed
  open, and its Delete clicked again asked a second time - two of the same waiting for the
  approvers. The dialog now closes. The same for a certificate's Delete in the workspace.
- A file with the private key (PFX) whose download waits for an approval: each click on its
  Download asked again. The button is now off once asked.
- A request profile of a team whose rule makes every request wait ("always"): the profile said
  "issued at once" and its button "Ask and issue" - and the request then waited. Now as the
  team's rule says.
- The members at 768 px: the change / remove buttons of a member with several roles wrapped to
  the left under the roles. Now on the right, as every other member's.
- On a phone the header has no room for the language: a person signed in had no way to change
  it but to sign out. Their account dialog (their name in the header) now offers it too.
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

NODE = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass, flow, width, lang] = process.argv.slice(1);
  const w = Number(width);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: w, height: 900}});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  const pause = ms => page.waitForTimeout(ms);
  const view = async (v) => {
    await page.evaluate(v => { location.hash = '#' + v + '/Web'; }, v);
    await pause(300);
    await page.waitForFunction(() => !document.querySelector('#pw-main .pw-skels, #pw-main .cp-skel'), null, {timeout: 20000}).catch(() => {});
    await pause(800);
  };
  const open = () => page.evaluate(() => !document.getElementById('modal').hidden);
  const foot = re => page.locator('#modal-foot button:not([hidden])', {hasText: re}).last();
  const user = {dev: 'rmgr', cert: 'rown', ask: 'rmgr', members: 'rmgr', me: 'rmgr'}[flow];
  try {
    await page.goto(base + '/');
    await page.fill('#in-name', user);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#signout', {timeout: 20000});
    await pause(1500);
    if (flow === 'dev') {
      await view('devices');
      await page.locator('#pw-main', {hasText: 'rt10-dev'}).locator('text=rt10-dev').first().click();
      await pause(1500);
      await foot(/^Delete$/).click(); await pause(400);
      await foot(/^Delete$/).click(); await pause(2000);
      out.open = await open();
      out.toast = await page.textContent('#toast');
      await view('inbox');
      out.mine = await page.locator('.pw-mine .pw-req', {hasText: 'rt10-dev'}).count();
    } else if (flow === 'cert') {
      await view('certs');
      await page.locator('#pw-main tbody tr', {hasText: 'rt10-del.example.test'}).first().click();
      await pause(1500);
      await foot(/^Delete$/).click(); await pause(400);
      await foot(/^Delete$/).click(); await pause(2000);
      out.open = await open();
      await page.locator('#pw-main tbody tr', {hasText: 'rt10-key.example.test'}).first().click();
      await pause(1500);
      await foot(/^Download$/).click(); await pause(1200);
      const pw = page.locator('.cp-pw input');
      await pw.nth(0).fill('a-password-1'); await pw.nth(1).fill('a-password-1');
      const b = page.locator('.cp-format', {has: page.locator('.cp-pw')}).locator('button');
      await b.click(); await pause(2000);
      out.pfxToast = await page.textContent('#toast');
      out.pfxOff = await b.isDisabled();
    } else if (flow === 'ask') {
      await view('certs');
      await page.locator('#pw-main button', {hasText: 'Ask for a certificate'}).first().click();
      await pause(1200);
      out.tags = await page.$$eval('.cp-prof .cp-prof-t .tag', ts => ts.map(t => t.textContent));
      await page.locator('.cp-prof', {hasText: 'RT10 profile'}).click();
      await pause(1200);
      out.buttons = await page.$$eval('#modal-foot button', bs => bs.filter(b => !b.hidden).map(b => b.textContent.trim()));
      out.head = await page.$eval('.cp-prof-head .tag', t => t.textContent);
    } else if (flow === 'members') {
      await view('members');
      out.rows = await page.$$eval('.pw-members > .pw-mem', rs => rs.map(r => {
        const b = r.querySelector('.pw-mem-b'); if (!b) return null;
        const rr = r.getBoundingClientRect(), br = b.getBoundingClientRect();
        return {who: r.querySelector('.pw-mem-t b').textContent, gap: Math.round(rr.right - br.right)};
      }).filter(Boolean));
    } else if (flow === 'me') {
      await page.click('#mebtn'); await pause(800);
      out.langs = await page.$$eval('#modal-body .langpick button', bs => bs.map(b => b.textContent));
      await Promise.all([page.waitForNavigation(), page.locator('#modal-body .langpick button', {hasText: 'EN'}).click()]);
      await pause(1500);
      out.signout = (await page.textContent('#signout')).trim();
    }
  } catch (e) { out.error = String(e && e.stack || e); }
  await browser.close();
  console.log(JSON.stringify(out));
})();
"""


class HuntRt10PortalUi(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.php = None
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 100,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self',
            'portal_cert_max': 1000, 'portal_cert_keys': 1, 'mail_mode': 'off'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        for name in ('rmgr', 'rown'):
            cls.must('POST', '/api/users', {'action': 'add', 'name': name, 'role': 'readonly',
                                            'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {
            'name': 'Web', 'description': 'public web servers',
            'members': [{'who': 'local:rmgr', 'roles': ['Team manager', 'Approver', 'Requester',
                                                        'Renewer', 'Device manager']},
                        {'who': 'local:rown', 'roles': ['Team owner']}],
            'policy': {'target_kinds': ['fake'], 'suffixes': ['example.test'],
                       'approval': {'mode': 'always', 'approvers': 'team', 'count': 1},
                       'approve_actions': ['delete', 'key', 'device']}})
        cls.must('POST', '/api/reqprofiles/save', {
            'name': 'RT10 profile', 'issuer': 'self', 'description': 'for the web servers',
            'suffixes': ['example.test'], 'key_types': ['ec-256'], 'key_default': 'ec-256',
            'teams': ['Web'], 'owner': 'team', 'approval': False})
        for name in ('rt10-del', 'rt10-key'):
            got = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'Web'})
            job = cls.must('POST', '/api/certs/renew', {'id': got['id'], 'force': True})['job_id']
            end = time.time() + 120
            while time.time() < end:
                if cls.must('GET', '/api/certs/job?id=%d' % job)['job']['state'] not in (
                        'queued', 'running'):
                    break
                time.sleep(0.3)
        cls.must('POST', '/api/targets/save', {
            'name': 'rt10-dev', 'kind': 'fake', 'owner': 'Web',
            'config': {'dir': os.path.join(cls.tmp, 'out'), 'password': 'p'}})

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
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
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

    def page(self, flow, width=1400, lang='en'):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        if self.php is None:
            type(self).base = self.serve()
        got = subprocess.run([node, '-e', NODE, '--', self.base, self.pw, flow, str(width), lang],
                             capture_output=True, text=True, timeout=300, cwd=ROOT)
        lines = [x for x in (got.stdout or '').splitlines() if x.startswith('{')]
        self.assertTrue(lines, (got.stdout or '')[-2000:] + (got.stderr or '')[-2000:])
        out = json.loads(lines[-1])
        self.assertNotIn('error', out, out.get('error'))
        self.assertEqual(out['errors'], [], out)
        return out

    def test_01_device_delete_waits_once(self):
        got = self.page('dev')
        self.assertIn('waits for an approval', got['toast'], got)
        self.assertFalse(got['open'], got)                  # stayed open: Delete again
        self.assertEqual(got['mine'], 1, got)               # asked once

    def test_02_cert_delete_and_pfx_wait_once(self):
        got = self.page('cert')
        self.assertFalse(got['open'], got)
        self.assertIn('waits for an approval', got['pfxToast'], got)
        self.assertTrue(got['pfxOff'], got)

    def test_03_profile_says_the_teams_rule(self):
        got = self.page('ask')
        self.assertIn('approved first', got['tags'], got)
        self.assertNotIn('issued at once', got['tags'], got)
        self.assertEqual(got['head'], 'approved first', got)
        self.assertIn('Ask for it', got['buttons'], got)
        self.assertNotIn('Ask and issue', got['buttons'], got)

    def test_04_member_buttons_on_the_right_at_768(self):
        got = self.page('members', 768)
        gaps = {r['who']: r['gap'] for r in got['rows']}
        self.assertIn('rmgr', gaps, got)
        self.assertLessEqual(gaps['rmgr'], 2, got)          # several roles: wrapped to the left
        self.assertLessEqual(gaps['rown'], 2, got)

    def test_05_language_in_the_account_dialog_on_a_phone(self):
        got = self.page('me', 390, 'cs')
        self.assertEqual(got['langs'], ['EN', 'CS'], got)
        self.assertEqual(got['signout'], 'Sign out', got)


if __name__ == '__main__':
    unittest.main(verbosity=2)
