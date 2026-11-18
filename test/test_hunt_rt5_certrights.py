#!/usr/bin/env python3
"""Hunt R t5 (certrights): what the Certificates pane offers on one certificate is what its
team gives the account, and "N days before the end" is the setting certs_renew_days.

    python3 test/test_hunt_rt5_certrights.py

The daemon, the directory and the organisation of test/test_teams_admin_ui.py, and:
- certer, a certificate administrator of some teams (certs_certadmin_all=0): Certificate
  manager of Prague (Web below it), only a Viewer of Security. On Security's certificate the
  page offered Renew, Delete, Change, Export, Deploy, the row's Renew and Run its tests - every
  one refused by the server (403). GET /api/certs/one and the list's rows say the account's
  capabilities on it now (caps), and the page offers only those;
- a certificate without days of its own: the list's tooltip, the renewal label and the
  wizard's summary said "30 days before the end" - the server renews it certs_renew_days
  before (45 here). The page is told the setting (renew_days_default) and says it.
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

sys.path.insert(0, ROOT)
from acmelib.certs import teams as T    # noqa: E402

ALL = list(T.CAPS) + ['manage']


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class TheSources(unittest.TestCase):
    def test_no_thirty_said(self):
        js = read('web/assets/certs.js')
        self.assertNotIn("(c.renew_days || 30) + ' days", js)
        self.assertNotIn("(W.d.renew_days || 30) + ' days", js)
        self.assertIn("'by itself, ' + renewDays(W.d.renew_days) + ' days before the end'", js)

    def test_buttons_by_caps(self):
        js = read('web/assets/certs.js')
        for one in ("mayOn(c, 'cert.delete')) buttons.push({words: 'Delete'",
                    "mayOn(c, 'cert.renew') && c.issuer && c.state !== 'revoked' && c.state !== 'pending' && !asked(c)",
                    "if (mayOn(c, 'manage')) {\n    var rt = iconButton('play'",
                    "return mayOn(c, 'cert.auto') && !!c.issuer"):
            self.assertIn(one, js)


PAGE_JS = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass, secId, webId] = process.argv.slice(2);
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
  const shut = (page) => page.evaluate(() => { MODAL_TYPED = 0; let i = 0; while (!document.getElementById('modal').hidden && i++ < 6) closeModal(true); });
  const row = (page, name) => page.evaluate((name) => {
    const tr = Array.from(document.querySelectorAll('#ct-table tbody tr')).find((t) => { const b = t.querySelector('b'); return b && b.textContent === name; });
    if (!tr) return null;
    const tag = tr.querySelector('.ct-auto .tag');
    return {tools: Array.from(tr.querySelectorAll('.rowtools button')).map((b) => b.getAttribute('aria-label') || b.title || ''),
            sw: !!tr.querySelector('.ct-auto input'),
            tip: tag ? tag.getAttribute('aria-label') : null};
  }, name);
  const peek = async (page, id) => {
    await page.evaluate((id) => ACME_CERTS.certPeek(id), Number(id));
    await page.waitForTimeout(1800);
    const got = await page.evaluate(() => ({
      buttons: Array.from(document.querySelectorAll('#modal button')).map((b) => b.textContent.trim()).filter(Boolean),
      edit: !!document.getElementById('ct-d-edit'),
      addDeploy: Array.from(document.querySelectorAll('#modal-body button')).some((b) => /Deploy it on a target/.test(b.textContent)),
      attach: Array.from(document.querySelectorAll('#modal-body button')).some((b) => /Attach a test/.test(b.textContent)),
      renews: (() => { const t = Array.from(document.querySelectorAll('#modal-body .ct-auto-wrap .tag, #modal-body .ct-auto-wrap span')).map((x) => x.textContent).filter((x) => /days before/.test(x)); return t[0] || null; })()
    }));
    await shut(page);
    return got;
  };
  try {
    const c = await signIn('certer');
    await tab(c, 'certs');
    out.cSec = await row(c, 'security-1');
    out.cWeb = await row(c, 'web-1');
    out.cSecPeek = await peek(c, secId);
    out.cWebPeek = await peek(c, webId);
    await c.context().close();
    const a = await signIn('tester');
    await tab(a, 'certs');
    out.aSec = await row(a, 'security-1');
    out.aSecPeek = await peek(a, secId);
    await a.context().close();
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
        got = cls.must('GET', '/api/teams')
        teams = {t['name']: t for t in got['teams']}

        def add(team, member):
            members = [{k: m[k] for k in ('who', 'rights', 'roles', 'until', 'note') if k in m}
                       for m in teams[team]['members']]
            members.append(member)
            cls.must('POST', '/api/teams/save', {'old_name': team, 'name': team,
                                                 'members': members})
        add('Prague', {'who': 'local:certer', 'roles': ['Certificate manager']})
        add('Security', {'who': 'local:certer', 'roles': ['Viewer']})
        cls.must('POST', '/api/settings', {'settings': {'certs_certadmin_all': 0,
                                                        'certs_renew_days': 45}})
        cls.sql([("UPDATE certs SET auto_renew = 1, renew_days = NULL WHERE name IN "
                  "('security-1', 'web-1')", ())])
        cls.certer = cls.login('certer')

    def as_certer(self, method, path, body=None, args=None):
        return self.call(method, path, body, self.certer, args)

    def test_caps_of_one(self):
        st, got = self.as_certer('GET', '/api/certs/one', None,
                                 {'id': self.cert_ids['security-1']})
        self.assertEqual(st, 200, got)
        caps = got['cert']['caps']
        self.assertIn('cert.view', caps)
        for no in ('cert.renew', 'cert.delete', 'cert.edit', 'cert.auto', 'deploy.run',
                   'deploy.manage', 'manage'):
            self.assertNotIn(no, caps)
        self.assertEqual(got['renew_days_default'], 45)
        # ...as the server refuses it
        st, _ = self.as_certer('POST', '/api/certs/renew', {'id': self.cert_ids['security-1']})
        self.assertEqual(st, 403)
        st, got = self.as_certer('GET', '/api/certs/one', None, {'id': self.cert_ids['web-1']})
        self.assertEqual(st, 200, got)
        for yes in ('cert.renew', 'cert.delete', 'cert.edit', 'cert.auto', 'deploy.run',
                    'deploy.manage', 'manage'):
            self.assertIn(yes, got['cert']['caps'])
        # a full administrator: every one
        got = self.must('GET', '/api/certs/one', None, {'id': self.cert_ids['security-1']})
        self.assertEqual(got['cert']['caps'], ALL)

    def test_caps_of_rows(self):
        st, got = self.as_certer('GET', '/api/certs', None, {'per': 200})
        self.assertEqual(st, 200, got)
        self.assertEqual(got['renew_days_default'], 45)
        by = {r['name']: r['caps'] for r in got['rows']}
        self.assertNotIn('cert.renew', by['security-1'])
        self.assertIn('cert.renew', by['web-1'])
        got = self.must('GET', '/api/certs', None, {'per': 200})
        self.assertTrue(all(r['caps'] == ALL for r in got['rows']))
        self.assertEqual(self.must('GET', '/api/certs/overview')['renew_days_default'], 45)

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        js = tempfile.NamedTemporaryFile('w', suffix='.js', dir=HERE, prefix='.hunt_rt5_',
                                         delete=False)
        try:
            js.write(PAGE_JS)
            js.close()
            got = subprocess.run([node, js.name, base, self.pw,
                                  str(self.cert_ids['security-1']), str(self.cert_ids['web-1'])],
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
        # certer, a Viewer of Security: nothing offered that would be refused
        self.assertEqual(seen['cSec']['tools'], [], seen)
        self.assertFalse(seen['cSec']['sw'], seen)
        self.assertEqual(seen['cSec']['tip'],
                         'Renewed 45 days before it runs out (or when the CA suggests).', seen)
        p = seen['cSecPeek']
        for no in ('Delete', 'Renew now', 'Issue now', 'Export', 'Revoke', 'Edit',
                   'Change names, key, source…', 'Deploy now'):
            self.assertNotIn(no, p['buttons'], seen)
        self.assertFalse(p['edit'], seen)
        self.assertFalse(p['addDeploy'], seen)
        self.assertFalse(p['attach'], seen)
        # ...and a Certificate manager of Web: everything, as before
        self.assertEqual(len(seen['cWeb']['tools']), 2, seen)
        self.assertTrue(seen['cWeb']['sw'], seen)
        p = seen['cWebPeek']
        self.assertIn('Delete', p['buttons'], seen)
        self.assertTrue(p['edit'] and p['addDeploy'] and p['attach'], seen)
        self.assertEqual(p['renews'], 'by itself, 45 days before the end', seen)
        # the full administrator: every one, the days of the setting
        self.assertEqual(len(seen['aSec']['tools']), 2, seen)
        self.assertTrue(seen['aSec']['sw'], seen)
        p = seen['aSecPeek']
        self.assertIn('Delete', p['buttons'], seen)
        self.assertTrue(p['edit'] and p['addDeploy'] and p['attach'], seen)
        self.assertEqual(p['renews'], 'by itself, 45 days before the end', seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
