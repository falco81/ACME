#!/usr/bin/env python3
"""Hunt R t4 (certsui): the Certificates pane and the certificate's dialogs with teams in play,
the bugs found driving it in Chromium as a full, a scoped certificate and a read-only
administrator.

    python3 test/test_hunt_rt4_certsui.py

The daemon, the directory and the organisation of test/test_teams_admin_ui.py, and:
- the Overview's tile Failing (2 renewals, 1 deployment: 3) opens the 3 certificates
  (GET /api/certs?state=failing) - it opened the 2 failed renewals alone;
- a tile and "N waiting for approval" open every certificate they count: a search, source,
  owner or tag chosen on the list before no longer hides part of it (the tile said 3, the
  list 1);
- a certificate whose owner is written in other letters than its team ("web" of Web, as the
  API and the command line take it) keeps its owner when only its note is changed in Details
  (the box showed "nobody" and the owner was dropped);
- a certificate administrator of some teams is offered, for a team's certificate, only the
  devices of that team (above or below it) and of acme's own - another team's device was
  offered and refused on Save.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_teams_admin_ui as TAU      # noqa: E402


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class TheSources(unittest.TestCase):
    def test_open_certs_clears_the_filters(self):
        js = read('web/assets/certs.js')
        at = js.index('function openCerts(f)')
        self.assertIn("['ct-q', 'ct-issuer', 'ct-owner', 'ct-tag']", js[at:at + 1200])

    def test_failing_tile(self):
        js = read('web/assets/certs.js')
        self.assertIn("openCerts({state: t[4] === 'failed' && depBad ? 'failing' : t[4]});", js)
        self.assertIn("elif state == 'failing':", read('acmelib/certs/api.py'))

    def test_owner_picker_other_letters(self):
        js = read('web/assets/teams.js')
        self.assertIn('var same = teamOf(keep) || teamOf(cur);', js)


PAGE_JS = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass, lowId] = process.argv.slice(2);
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
    await page.waitForTimeout(800);
    return page;
  };
  const tab = async (page, t) => {
    await page.evaluate((t) => document.querySelector('.tabs button[data-tab="' + t + '"]').click(), t);
    await page.waitForTimeout(1500);
  };
  const said = (page) => page.evaluate(() => document.getElementById('ct-said').textContent);
  const shut = (page) => page.evaluate(() => { MODAL_TYPED = 0; let i = 0; while (!document.getElementById('modal').hidden && i++ < 6) closeModal(true); });
  const ids = (page) => page.evaluate(async () => { const d = await ACME_CERTS.api('certs?per=200'); const o = {}; d.rows.forEach((c) => { o[c.name] = c.id; }); return o; });
  try {
    const a = await signIn('tester');
    await tab(a, 'certs');
    /* the list filtered by an owner, then the Overview's tiles and the badge */
    await a.evaluate(() => { const s = document.getElementById('ct-owner'); s.value = 'Web'; s.dispatchEvent(new Event('change', {bubbles: true})); });
    await a.waitForTimeout(1200);
    out.filtered = await said(a);
    await tab(a, 'overview');
    out.failingTile = await a.evaluate(() => Array.from(document.querySelectorAll('.ct-ovtile')).find((t) => /Failing/.test(t.textContent)).querySelector('.value').textContent);
    await a.evaluate(() => Array.from(document.querySelectorAll('.ct-ovtile')).find((t) => /Failing/.test(t.textContent)).click());
    await a.waitForTimeout(1800);
    out.failingList = await said(a);
    out.failingRows = await a.evaluate(() => Array.from(document.querySelectorAll('#ct-table tbody tr b')).map((b) => b.textContent));
    out.ownerAfter = await a.evaluate(() => document.getElementById('ct-owner').value);
    await a.evaluate(() => { const s = document.getElementById('ct-owner'); s.value = 'Web'; s.dispatchEvent(new Event('change', {bubbles: true})); });
    await a.waitForTimeout(1200);
    out.badge = await a.evaluate(() => document.getElementById('ct-approvals').textContent.trim());
    await a.click('#ct-approvals');
    await a.waitForTimeout(1500);
    out.badgeList = await said(a);
    /* the owner in other letters, the note changed in Details */
    await a.evaluate((id) => ACME_CERTS.certPeek(id), Number(lowId));
    await a.waitForTimeout(1800);
    await a.click('#ct-d-edit');
    await a.waitForTimeout(800);
    out.ownerShown = await a.evaluate(() => document.querySelector('#ct-d-owner select').value);
    await a.evaluate(() => { const n = document.getElementById('ct-d-note'); n.value = 'changed'; n.dispatchEvent(new Event('input', {bubbles: true})); });
    await a.click('#ct-d-save');
    await a.waitForTimeout(1500);
    out.lowAfter = await a.evaluate(async (id) => { const c = (await ACME_CERTS.api('certs/one?id=' + id)).cert; return {owner: c.owner, note: c.note}; }, Number(lowId));
    await shut(a);
    /* the full administrator: every device offered */
    const pick = async (page) => {
      const id = (await ids(page))['web-2'];
      await page.evaluate((id) => ACME_CERTS.certPeek(id), id);
      await page.waitForTimeout(1800);
      await page.evaluate(() => Array.from(document.querySelectorAll('#modal-body button')).find((b) => /Deploy it on a target/.test(b.textContent)).click());
      await page.waitForSelector('#modal-body .dp-pick .ck-attach-row', {timeout: 15000});
      await page.waitForTimeout(500);
      const got = await page.evaluate(() => Array.from(document.querySelectorAll('#modal-body .dp-pick .ck-attach-row')).map((r) => r.querySelector('b').textContent).sort());
      await shut(page);
      return got;
    };
    out.devicesFull = await pick(a);
    await a.context().close();
    const c = await signIn('certer');
    await tab(c, 'certs');
    out.devicesScoped = await pick(c);
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
        # certer: a certificate administrator of Prague's teams only
        got = cls.must('GET', '/api/teams')
        prague = [t for t in got['teams'] if t['name'] == 'Prague'][0]
        members = [{k: m[k] for k in ('who', 'rights', 'roles', 'until', 'note') if k in m}
                   for m in prague['members']]
        members.append({'who': 'local:certer', 'roles': ['Certificate manager']})
        cls.must('POST', '/api/teams/save', {'old_name': 'Prague', 'name': 'Prague',
                                             'members': members})
        cls.must('POST', '/api/settings', {'settings': {'certs_certadmin_all': 0}})
        # devices of other teams than Web (Trading, Factory)
        for name, owner in (('ny-box', 'Trading'), ('tokyo-box', 'Factory')):
            cls.must('POST', '/api/targets/save', {'name': name, 'kind': 'fake',
                                                   'config': {'dir': '/tmp'}, 'owner': owner})
        # mail-1's deployment failed (beside the failed renewals of web-5, network-2)
        cls.must('POST', '/api/deploys/save', {'cert_id': cls.cert_ids['mail-1'], 'target': 'mx1',
                                               'options': {'file': 'x.pem'}})
        cls.sql([("UPDATE cert_deploys SET state = 'failed' WHERE target = 'mx1'", ())])
        # an owner written in other letters than its team
        cls.low_id = cls.must('POST', '/api/certs/save', {
            'name': 'lowown', 'names': ['lowown.example.com'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'web', 'note': 'first'})['id']

    def test_failing_filter(self):
        got = self.must('GET', '/api/certs', None, {'state': 'failing', 'per': 100})
        self.assertEqual(sorted(r['name'] for r in got['rows']), ['mail-1', 'network-2', 'web-5'])
        got = self.must('GET', '/api/certs', None, {'state': 'failed', 'per': 100})
        self.assertEqual(sorted(r['name'] for r in got['rows']), ['network-2', 'web-5'])

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        js = tempfile.NamedTemporaryFile('w', suffix='.js', dir=HERE, prefix='.hunt_rt4_',
                                         delete=False)
        try:
            js.write(PAGE_JS)
            js.close()
            got = subprocess.run([node, js.name, base, self.pw, str(self.low_id)],
                                 capture_output=True, text=True, timeout=600, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            os.unlink(js.name)
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen)
        self.assertEqual(seen['http'], [], seen)
        # the tile counts 3 and opens 3, every owner
        self.assertEqual(seen['failingTile'], '3', seen)
        self.assertEqual(seen['failingList'], '3 certificate(s)', seen)
        self.assertEqual(sorted(seen['failingRows']), ['mail-1', 'network-2', 'web-5'], seen)
        self.assertEqual(seen['ownerAfter'], '', seen)
        # the badge counts 2 (web-6, supplierx-1) and opens 2, though Web was chosen
        self.assertEqual(seen['badge'], '2 waiting for approval', seen)
        self.assertEqual(seen['badgeList'], '2 certificate(s)', seen)
        # "web": shown as Web, kept when only the note changed
        self.assertEqual(seen['ownerShown'], 'Web', seen)
        self.assertEqual(seen['lowAfter'], {'owner': 'web', 'note': 'changed'}, seen)
        # devices: every one to the full administrator, Web's and acme's own to certer
        self.assertIn('tokyo-box', seen['devicesFull'], seen)
        self.assertIn('mx1', seen['devicesFull'], seen)
        self.assertEqual(seen['devicesScoped'], ['spare-box', 'web-lb1', 'web-lb2'], seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
