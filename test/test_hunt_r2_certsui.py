#!/usr/bin/env python3
"""Bug hunt R, run 2, the certificate pages (1.0.124).

    python3 test/test_hunt_r2_certsui.py

- A certificate edited in its wizard and saved without a change: its days before the end
  (null: Renewal and notices says) and its key usage (none: the source's or authority's
  default) stay as they were - it was given 30 days of its own and serverAuth alone.
- A read-only account is not offered "Read from a file" beside a box it cannot change.
- What happens on a phone: the lead over several deployments beside the plan's rail.

The sources read as text; the pages through a real daemon (test/test_certs_core.py's way) and
php -S, in Chromium, when node, php and Playwright are here.
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
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class TheSources(unittest.TestCase):
    def test_wizard_keeps_what_it_did_not_have(self):
        js = read('web/assets/certs.js')
        self.assertIn("renew_days: c.id ? (c.renew_days || '') : 30,", js)
        self.assertIn("var RD_KEPT = W.d.renew_days === '';", js)
        self.assertIn("renew_days: d.renew_days === '' ? null : Number(d.renew_days || 30)", js)
        self.assertIn("var EKU0 = editing && !arr(prof.eku).length ? W.d.eku.slice() : null;", js)
        self.assertNotIn("if (d.eku.length) profile.eku = d.eku;", js)

    def test_reader_no_read_from_file(self):
        js = read('web/assets/certs.js')
        self.assertIn("if (!FULL) Array.prototype.forEach.call(body.querySelectorAll('.ct-pem-tools')", js)

    def test_junction_lead_on_phone(self):
        css = read('web/assets/runplan.css')
        at = css.index('.rp-junction{grid-template-columns:minmax(0,1fr);padding-top:0;padding-left:26px}')
        self.assertIn('.rp-junction-h{padding-left:26px}', css[at:at + 300])


PAGE_JS = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const open = async (user, width, lang) => {
    const ctx = await browser.newContext({viewport: {width: width, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    page.on('dialog', d => { out.errors.push('dialog: ' + d.message()); d.dismiss(); });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', user);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    return page;
  };
  const tab = async (page, t) => {
    await page.evaluate(t => document.querySelector('.tabs button[data-tab="' + t + '"]').click(), t);
    await page.waitForTimeout(1200);
  };
  const shut = async (page) => page.evaluate(() => { MODAL_TYPED = 0; let i = 0; while (!document.getElementById('modal').hidden && i++ < 6) closeModal(true); });
  const foot = async (page, re) => page.evaluate((re) => {
    const b = Array.from(document.querySelectorAll('#modal-foot button')).find(b => !b.hidden && new RegExp(re).test(b.textContent.trim()));
    if (b) b.click();
    return !!b;
  }, re);
  /* the wizard of a certificate: every step walked through, something done on one, saved */
  const wizard = async (page, id, onStep) => {
    await page.evaluate(id => ACME_CERTS.certPeek(id), id);
    await page.waitForTimeout(1500);
    await foot(page, '^Change names');
    await page.waitForTimeout(1500);
    for (let i = 0; i < 12; i++) {
      const st = await page.evaluate(() => (document.querySelector('.ct-wsteps li.on') || {}).textContent || '');
      if (onStep) await onStep(st);
      if (!(await foot(page, '^Next'))) break;
      await page.waitForTimeout(1000);
    }
    const saved = await foot(page, '^Save$');
    await page.waitForTimeout(1500);
    await shut(page);
    return saved;
  };
  try {
    const page = await open('tester', 1400);
    await tab(page, 'certs');
    const one = id => page.evaluate(id => ACME_CERTS.api('certs/one?id=' + id).then(d => d.cert), id);
    const ids = JSON.parse(process.argv[4]);
    out.cert = {};
    for (const k of ['bare', 'own']) {
      const saved = await wizard(page, ids[k]);
      const c = await one(ids[k]);
      out.cert[k] = {saved: saved, renew_days: c.renew_days, profile: c.profile};
    }
    /* a change made still saved: days typed, key usage changed */
    await wizard(page, ids.bare, async (st) => {
      if (/Renewal/.test(st)) await page.evaluate(() => {
        const i = document.querySelector('#modal-body input[type=number]');
        i.value = '20'; i.dispatchEvent(new Event('input', {bubbles: true}));
      });
      if (/Profile/.test(st)) await page.evaluate(() => {
        const b = Array.from(document.querySelectorAll('#modal-body .ct-ekus input')).find(x => !x.checked);
        b.click();
      });
    });
    const c = await one(ids.bare);
    out.changed = {renew_days: c.renew_days, eku: (c.profile || {}).eku || null};

    /* a reader: the source with a PEM box, "Read from a file" not offered */
    const pemSeen = async (p) => {
      await tab(p, 'sources');
      const n = await p.evaluate(() => document.querySelectorAll('#tab-sources tbody tr').length);
      let seen = 0;
      for (let i = 0; i < n; i++) {
        await p.evaluate(i => { const tr = document.querySelectorAll('#tab-sources tbody tr')[i]; (tr.querySelector('td:nth-child(2)') || tr).click(); }, i);
        await p.waitForTimeout(1200);
        seen += await p.evaluate(() => Array.from(document.querySelectorAll('#modal-body button')).filter(b => b.textContent.trim() === 'Read from a file' && b.getClientRects().length).length);
        await shut(p);
      }
      return seen;
    };
    out.pemAdmin = await pemSeen(page);
    const ro = await open('viewer', 1400);
    out.pemReader = await pemSeen(ro);

    /* a phone: the lead over the deployments beside the rail */
    const ph = await open('tester', 390);
    await tab(ph, 'certs');
    await ph.evaluate(id => ACME_CERTS.certPeek(id), ids.own);
    await ph.waitForTimeout(1500);
    await foot(ph, '^What happens');
    await ph.waitForFunction(() => document.querySelector('.rp-junction-h'), null, {timeout: 30000});
    out.lead = await ph.evaluate(() => {
      const h = document.querySelector('.rp-junction-h'), j = document.querySelector('.rp-junction');
      return {lead: h.getBoundingClientRect().left + parseFloat(getComputedStyle(h).paddingLeft),
              rail: j.getBoundingClientRect().left + 6 + 2};
    });
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


class ThePages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            raise unittest.SkipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            raise unittest.SkipTest('no playwright for node here')
        import test_certs_core as TCC
        cls.TCC = TCC
        cls.call = TCC.CertsCore.__dict__['call']
        cls.login = TCC.CertsCore.__dict__['login']
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.TCC.CertsCore.tearDownClass.__func__(cls)

    def ok(self, path, body):
        st, got = self.call('POST', path, body, self.admin)
        self.assertEqual(st, 200, (path, got))
        return got

    def test_the_pages(self):
        self.ok('/api/sources/save', {'name': 'self', 'kind': 'selfsigned', 'config': {'days': 40}})
        ids = {
            # neither days nor key usage of its own (as one imported or made by the API)
            'bare': self.ok('/api/certs/save', {'name': 'bare', 'names': ['bare.example.test'],
                                                'issuer': 'self', 'auto_renew': 0})['id'],
            # both of its own
            'own': self.ok('/api/certs/save', {'name': 'own', 'names': ['own.example.test'],
                                               'issuer': 'self', 'auto_renew': 0,
                                               'renew_days': 45,
                                               'profile': {'eku': ['clientAuth']}})['id'],
        }
        out1 = os.path.join(self.tmp, 'out')
        for n in ('files-a', 'files-b'):
            self.ok('/api/targets/save', {'name': n, 'kind': 'local', 'config': {'base': out1}})
        for n in ('files-a', 'files-b'):
            self.ok('/api/deploys/save', {'cert_id': ids['own'], 'target': n,
                                          'options': {'outputs': ['pem %s.pem' % n]}})
        for cid in ids.values():          # issued, as one in use
            job = self.ok('/api/certs/renew', {'id': cid})['job_id']
            end = time.time() + 120
            while time.time() < end:
                st, got = self.call('GET', '/api/certs/job', None, self.admin, {'id': job})
                if got['job']['state'] not in ('queued', 'running'):
                    break
                time.sleep(0.3)
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        script = os.path.join(self.tmp, 'r2_certsui_page.js')
        with open(script, 'w', encoding='utf-8') as f:
            f.write(PAGE_JS)
        port = self.TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
            got = subprocess.run([shutil.which('node'), script, 'http://127.0.0.1:%d' % port,
                                  self.pw, json.dumps(ids)],
                                 capture_output=True, text=True, timeout=500, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # saved unchanged: as it was
        self.assertTrue(seen['cert']['bare']['saved'], seen)
        self.assertIsNone(seen['cert']['bare']['renew_days'], seen)
        self.assertNotIn('eku', seen['cert']['bare']['profile'] or {}, seen)
        self.assertEqual(seen['cert']['own']['renew_days'], 45, seen)
        self.assertEqual(seen['cert']['own']['profile'].get('eku'), ['clientAuth'], seen)
        # a change still saved
        self.assertEqual(seen['changed']['renew_days'], 20, seen)
        self.assertTrue(seen['changed']['eku'] and len(seen['changed']['eku']) == 2, seen)
        # "Read from a file": the administrator's, never the reader's
        self.assertGreater(seen['pemAdmin'], 0, seen)
        self.assertEqual(seen['pemReader'], 0, seen)
        # the lead right of the rail
        self.assertGreater(seen['lead']['lead'], seen['lead']['rail'], seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
