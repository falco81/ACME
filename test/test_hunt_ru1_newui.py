#!/usr/bin/env python3
"""Hunt R u1 (the UI of 1.0.128): Teams from directory groups, Request profiles' search.

    python3 test/test_hunt_ru1_newui.py
    HUNT_OLD=REV python3 test/test_hunt_ru1_newui.py  # teams.js, reqprofiles.js of REV: fails

- Teams from directory groups: a preview, then the filter changed (or the role, where, what
  they are) and "Make the teams" pressed - the teams of the new filter were made without
  ever being shown. Now any change asks for the preview again; what was previewed is made.
- Settings -> Request profiles: the search did not find a domain as its card shows it with
  wildcards (*.example.com); now it does, and the plain domain as before.

A real daemon (test/test_certs_core.py's way), test/mockldap.py as the directory, php -S on a
copy of web/ on a free port, Chromium (node + Playwright) driving the pages.
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
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import mockldap                      # noqa: E402

BASE = 'DC=corpnet,DC=loc'

PAGE_JS = r"""
const { chromium } = require('playwright');
const [base, pass] = process.argv.slice(2);
(async () => {
  const out = {errors: []};
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({viewport: {width: 1400, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(1200);
    const teams = () => page.evaluate(() => api('teams').then(d => d.teams.map(t => t.name).sort()));
    // Teams from directory groups: previewed one filter, another one typed after
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.evaluate(() => document.querySelector('#ctl-nav button[data-pane="teams"]').click());
    await page.waitForSelector('#tmx-fromgroups', {state: 'attached', timeout: 20000});
    await page.evaluate(() => document.getElementById('tmx-fromgroups').click());
    await page.waitForSelector('#tmx-fg-filter');
    const preview = async () => {
      await page.click('#modal-foot .btn:has-text("Preview")');
      await page.waitForSelector('#tmx-fg-prev .tmx-fg-row', {timeout: 20000});
      return page.$$eval('#tmx-fg-prev .tmx-fg-row', a => a.map(x => x.dataset.cn));
    };
    const make = async () => {
      await page.click('#modal-foot .btn.primary');
      await page.waitForTimeout(1500);
      return teams();
    };
    await page.fill('#tmx-fg-filter', 'CN=PKI-Web');
    out.previewed = await preview();
    await page.fill('#tmx-fg-filter', 'CN=PKI-*');
    out.afterFilter = await make();
    // the kind changed after a preview: previewed again too
    out.previewed2 = await preview();
    await page.click('#modal-foot .tmx-segb[data-v="unit"], #modal-body .tmx-segb[data-v="unit"]');
    out.afterKind = await make();
    // previewed again: made, as before
    out.previewed3 = await preview();
    out.made = await make();
    await page.evaluate(() => closeModal());
    // Request profiles: the search finds a domain as the card shows it
    await page.evaluate(() => document.querySelector('#ctl-nav button[data-pane="reqprofiles"]').click());
    await page.waitForFunction(() => document.querySelectorAll('#rp-host .rpx-card').length >= 2, null, {timeout: 20000});
    out.found = {};
    for (const q of ['*.wild.example.test', 'wild.example.test', '*.tame.example.test', 'tame.example.test']) {
      await page.fill('#rpx-q', q);
      await page.waitForTimeout(400);
      out.found[q] = await page.$$eval('#rp-host .rpx-card', a => a.map(x => x.dataset.name));
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
"""


def node_ok():
    node = shutil.which('node')
    return bool(node and shutil.which('php') and not subprocess.run(
        [node, '-e', 'require("playwright")'], capture_output=True, cwd=ROOT).returncode)


class NewUI(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        for cn in ('PKI-Web', 'PKI-Mail'):
            mockldap.GROUPS['CN=%s,OU=Groups,%s' % (cn, BASE)] = {
                'cn': [cn], 'objectClass': ['top', 'group'], 'description': [cn + ' certificates'],
                'member': ['CN=Jan Novak,OU=People,' + BASE]}
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def test_pages(self):
        if not node_ok():
            self.skipTest('no node, php or playwright here')
        self.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': self.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        self.must('POST', '/api/settings', {'settings': {'admin_directory': 'corp'}})
        self.must('POST', '/api/cas/create', {'name': 'Test Root', 'subject': {'CN': 'Test Root CA'},
                                              'key_type': 'ec-256', 'days': 3650})
        self.must('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                                'config': {'ca': 'Test Root', 'days': 90}})
        self.must('POST', '/api/reqprofiles/save', {
            'name': 'Wild', 'issuer': 'own', 'wildcards': True, 'suffixes': ['wild.example.test'],
            'key_types': ['rsa-2048'], 'key_default': 'rsa-2048'})
        self.must('POST', '/api/reqprofiles/save', {
            'name': 'Tame', 'issuer': 'own', 'suffixes': ['tame.example.test'],
            'key_types': ['rsa-2048'], 'key_default': 'rsa-2048'})
        end = time.time() + 30
        while time.time() < end:
            st, _ = self.call('GET', '/api/dir/search', None, self.admin, {'q': 'pki', 'kind': 'group'})
            if st == 200:
                break
            time.sleep(0.3)
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        if os.environ.get('HUNT_OLD'):
            for rel in ('web/assets/teams.js', 'web/assets/reqprofiles.js'):
                old = subprocess.run(['git', 'show', os.environ['HUNT_OLD'] + ':' + rel], cwd=ROOT, capture_output=True)
                with open(os.path.join(self.tmp, rel), 'wb') as f:
                    f.write(old.stdout)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        self.assertNotIn(port, (8092, 8443, 5432, 5433))
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        js = os.path.join(self.tmp, 'hunt_ru1_newui_page.js')
        with open(js, 'w', encoding='utf-8') as f:
            f.write(PAGE_JS)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            drv = subprocess.run(['node', js, 'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=600)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-2000:])
        seen = json.loads([x for x in drv.stdout.splitlines() if x.startswith('{')][-1])
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # what was previewed is what is made - nothing else
        self.assertEqual(seen['previewed'], ['PKI-Web'])
        self.assertEqual(seen['afterFilter'], [], 'made without being previewed')
        self.assertEqual(sorted(seen['previewed2']), ['PKI-Mail', 'PKI-Web'])
        self.assertEqual(seen['afterKind'], [], 'made without being previewed')
        self.assertEqual(sorted(seen['previewed3']), ['PKI-Mail', 'PKI-Web'])
        self.assertEqual(seen['made'], ['PKI-Mail', 'PKI-Web'])
        # the search: the domain as the card shows it, the plain one as before
        self.assertEqual(seen['found'], {'*.wild.example.test': ['Wild'], 'wild.example.test': ['Wild'],
                                         '*.tame.example.test': [], 'tame.example.test': ['Tame']})


if __name__ == '__main__':
    unittest.main(verbosity=2)
