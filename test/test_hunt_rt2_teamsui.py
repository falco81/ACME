#!/usr/bin/env python3
"""Hunt R t2 (teamsui): Settings → Owners and teams, the bugs found driving it in Chromium.

    python3 test/test_hunt_rt2_teamsui.py

The daemon, the directory and the organisation of test/test_teams_admin_ui.py, and:
- after another team is chosen, "New team" / "New unit" say what each makes, under that team
  (the two hints were swapped, and the aria-label kept the team chosen first);
- the Certificates tab says a certificate's state in words ("valid"), not the bare "ok";
- a certificate administrator who sees only some teams opens the Activity of a team outside
  them without the daemon being asked (no 403, no console error) and sees why it is empty;
  the activity of a team of their own is still there.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_teams_admin_ui as TAU      # noqa: E402

PAGE_JS = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], http: []};
  const signIn = async (name) => {
    const ctx = await browser.newContext({viewport: {width: 1400, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', (e) => out.errors.push(name + ': ' + String(e.message || e)));
    page.on('console', (m) => { if (m.type() === 'error') out.errors.push(name + ' console: ' + m.text()); });
    page.on('response', (r) => { if (r.status() >= 400) out.http.push(name + ' ' + r.status() + ' ' + r.url()); });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(500);
    await page.goto(base + '/admin/index.php#settings/teams');
    await page.waitForSelector('#tmx .tmx-vbtn', {timeout: 30000});
    await page.waitForTimeout(400);
    return page;
  };
  const team = async (page, name) => {
    await page.evaluate(() => document.getElementById('tmx-expand').click());
    await page.waitForTimeout(150);
    await page.evaluate((n) => { [...document.querySelectorAll('.tmx-row')].find((x) => x.dataset.name === n).click(); }, name);
    await page.waitForSelector('.tmx-team[data-team="' + name + '"]', {timeout: 10000});
  };
  const tab = async (page, t) => { await page.click('.tmx-tab[data-tab="' + t + '"]'); await page.waitForTimeout(800); };
  try {
    const a = await signIn('tester');
    await team(a, 'Web');
    out.addTeam = await a.getAttribute('#tmx-add-team', 'aria-label');
    out.addUnit = await a.getAttribute('#tmx-add-unit', 'aria-label');
    await tab(a, 'certs');
    await a.waitForSelector('.tmx-crow', {timeout: 15000});
    out.states = await a.$$eval('.tmx-crow', (r) => Object.fromEntries(r.map((x) => [x.querySelector('b').textContent, x.querySelector('.tmx-cr .tag').textContent])));
    await a.context().close();

    const c = await signIn('certer');
    await team(c, 'Group HQ');
    await tab(c, 'activity');
    out.otherActivity = await c.$eval('#tmx-tl', (n) => n.textContent);
    await team(c, 'Web');
    await tab(c, 'activity');
    await c.waitForSelector('.tmx-tl-it', {timeout: 15000});
    out.ownActivity = await c.locator('.tmx-tl-it').count();
    await c.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


class Hunt(TAU.Pages):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # certer: a certificate administrator who sees only the teams it is a member of
        got = cls.must('GET', '/api/teams')
        prague = [t for t in got['teams'] if t['name'] == 'Prague'][0]
        members = [{k: m[k] for k in ('who', 'rights', 'roles', 'until', 'note') if k in m}
                   for m in prague['members']]
        members.append({'who': 'local:certer', 'roles': ['Certificate manager']})
        cls.must('POST', '/api/teams/save', {'old_name': 'Prague', 'name': 'Prague',
                                             'members': members})
        cls.must('POST', '/api/settings', {'settings': {'certs_certadmin_all': 0}})

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        js = tempfile.NamedTemporaryFile('w', suffix='.js', dir=HERE, prefix='.hunt_rt2_',
                                         delete=False)
        try:
            js.write(PAGE_JS)
            js.close()
            got = subprocess.run([node, js.name, base, self.pw], capture_output=True, text=True,
                                 timeout=600, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            os.unlink(js.name)
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen)
        self.assertEqual(seen['http'], [], seen)
        self.assertEqual(seen['addTeam'], 'A new team under Web', seen)
        self.assertEqual(seen['addUnit'], 'A new unit (a region, a site) under Web', seen)
        self.assertEqual(seen['states']['web-3'], 'valid', seen)
        self.assertEqual(seen['states']['web-5'], 'failed', seen)
        self.assertEqual(seen['states']['web-6'], 'waiting', seen)
        self.assertIn('Not yours to see', seen['otherActivity'], seen)
        self.assertGreater(seen['ownActivity'], 0, seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
