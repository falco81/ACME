#!/usr/bin/env python3
"""Hunt R u2 (certsui): the Certificates pane and the certificate's dialogs.

    python3 test/test_hunt_ru2_certsui.py

- "Renews" switched in the certificate's window: the list and Details follow (the list kept
  "auto" and Details "only when asked" - window.CT, which nothing sets, was asked);
- the list filtered "has expired" holds what the Overview's tile Expired counts: one whose
  renewal failed past its end (state failed) too - the tile said 1, the list 0;
- the filter offers the states "added, not issued" (held) and "revocation failed";
- a certificate administrator saves a deployment of files as it was: the page sends the
  interpreter's default ("bash") of one saved without it, refused as "a command changed";
- a deployment saved with its options as they were stays "deployed" (it said "options changed");
- the job of a certificate deleted since no longer offers "The certificate" (it opened
  "there is no certificate N").

The sources read as text; the API and the pages through a real daemon (test/test_certs_core.py's
way) and php -S, in Chromium, when node, php and Playwright are here.
"""
import json
import os
import shutil
import sqlite3
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


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class TheSources(unittest.TestCase):
    def test_renews_switch_refreshes(self):
        js = read('web/assets/certs.js')
        self.assertNotIn('window.CT && CT.refresh', js)
        self.assertIn('CT.refresh(); if (details && details._show) details._show();', js)

    def test_state_filter_options(self):
        php = read('web/admin/certs-ui.php')
        self.assertIn('<option value="held">added, not issued</option>', php)
        self.assertIn('<option value="revoke-failed">revocation failed</option>', php)

    def test_expired_filter(self):
        self.assertIn("elif state == 'expired':", read('acmelib/certs/api.py'))

    def test_job_of_deleted_cert(self):
        self.assertIn("if (j.cert_id && j.cert_name) buttons.unshift({words: 'The certificate'",
                      read('web/assets/certs.js'))


PAGE_JS = r"""
const { chromium } = require('playwright');
(async () => {
  const [base, pass, idsJson] = process.argv.slice(2);
  const ids = JSON.parse(idsJson);
  const browser = await chromium.launch();
  const out = {errors: []};
  try {
    const ctx = await browser.newContext({viewport: {width: 1400, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="certs"]').click());
    await page.waitForTimeout(1500);
    const tag = () => page.evaluate((id) => {
      const tr = Array.from(document.querySelectorAll('#ct-table tbody tr')).find(t => (t.querySelector('b') || {}).textContent === 'auto1');
      return tr ? tr.querySelector('.ct-auto .tag').textContent : null;
    });
    const renews = () => page.evaluate(() => {
      const r = Array.from(document.querySelectorAll('#modal-body .tm-details tr')).find(t => /Renews/.test(t.textContent));
      return r ? r.textContent : null;
    });
    out.list0 = await tag();
    await page.evaluate(id => ACME_CERTS.certPeek(id), ids.auto1);
    await page.waitForTimeout(1500);
    out.details0 = await renews();
    await page.evaluate(() => document.querySelector('#modal-body .ct-auto-wrap input').click());
    await page.waitForTimeout(2500);
    out.list1 = await tag();
    out.details1 = await renews();
    await page.evaluate(() => { MODAL_TYPED = 0; let i = 0; while (!document.getElementById('modal').hidden && i++ < 6) closeModal(true); });
    /* the state filter */
    out.states = await page.evaluate(() => Array.from(document.querySelectorAll('#ct-state option')).map(o => o.value));
    /* the job of a certificate deleted since */
    await page.evaluate(id => ACME_CERTS.jobPeek(id), ids.goneJob);
    await page.waitForTimeout(1500);
    out.goneFoot = await page.evaluate(() => Array.from(document.querySelectorAll('#modal-foot button')).map(b => b.textContent.trim()));
    await page.evaluate(() => closeModal(true));
    await page.evaluate(id => ACME_CERTS.jobPeek(id), ids.liveJob);
    await page.waitForTimeout(1500);
    out.liveFoot = await page.evaluate(() => Array.from(document.querySelectorAll('#modal-foot button')).map(b => b.textContent.trim()));
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
"""


class TheDaemon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_certs_core as TCC
        cls.TCC = TCC
        cls.call = TCC.CertsCore.__dict__['call']
        cls.login = TCC.CertsCore.__dict__['login']
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.TCC.CertsCore.tearDownClass.__func__(cls)

    def ok(self, path, body, who=None):
        st, got = self.call('POST', path, body, who or self.admin)
        self.assertEqual(st, 200, (path, got))
        return got

    def issued(self, name):
        cid = self.ok('/api/certs/save', {'name': name, 'names': [name + '.example.test'],
                                          'issuer': 'self', 'auto_renew': 0})['id']
        job = self.ok('/api/certs/renew', {'id': cid})['job_id']
        end = time.time() + 120
        while time.time() < end:
            st, got = self.call('GET', '/api/certs/job', None, self.admin, {'id': job})
            if got['job']['state'] not in ('queued', 'running'):
                break
            time.sleep(0.3)
        return cid, job

    def test_all(self):
        self.ok('/api/sources/save', {'name': 'self', 'kind': 'selfsigned', 'config': {'days': 40}})
        out = os.path.join(self.tmp, 'out')
        self.ok('/api/targets/save', {'name': 'files', 'kind': 'local', 'config': {'base': out}})
        fake = os.path.join(self.tmp, 'fake')
        os.makedirs(fake, exist_ok=True)
        self.ok('/api/targets/save', {'name': 'fk', 'kind': 'fake',
                                      'config': {'dir': fake, 'password': 's3cret'}})

        # ---- the list "has expired" holds one whose renewal failed past its end
        run_out, _ = self.issued('runout')
        db = sqlite3.connect(os.path.join(self.tmp, 'state', 'acme.db'))
        db.execute("UPDATE certs SET not_after = ?, state = 'failed' WHERE id = ?",
                   (time.time() - 86400, run_out))
        db.commit()
        db.close()
        st, ov = self.call('GET', '/api/certs/overview', None, self.admin)
        st, lst = self.call('GET', '/api/certs', None, self.admin, {'state': 'expired'})
        self.assertEqual(ov['expired'], 1, ov)
        self.assertEqual(lst['total'], ov['expired'], lst)
        self.assertEqual([r['name'] for r in lst['rows']], ['runout'])
        st, lst = self.call('GET', '/api/certs', None, self.admin, {'state': 'failed'})
        self.assertEqual(lst['total'], 1)

        # ---- a deployment of files saved as it was by a certificate administrator
        cid, _ = self.issued('dep')
        files = self.ok('/api/deploys/save', {'cert_id': cid, 'target': 'files',
                                              'options': {'outputs': ['cert-pem a.pem']}})['id']
        # what the page sends back: every option, the interpreter's default among them
        st, got = self.call('POST', '/api/deploys/save', {
            'id': files, 'cert_id': cid, 'target': 'files', 'enabled': True,
            'options': {'outputs': ['cert-pem a.pem'], 'command': '', 'script_mode': '',
                        'script_path': '', 'script_args': '', 'script_interp': 'bash',
                        'script_body': ''}}, self.cert_admin)
        self.assertEqual(st, 200, got)
        # ...a command changed is still a full administrator's
        st, got = self.call('POST', '/api/deploys/save', {
            'id': files, 'cert_id': cid, 'target': 'files',
            'options': {'outputs': ['cert-pem a.pem'], 'script_mode': 'path',
                        'script_path': '/tmp/x.sh', 'script_interp': 'bash'}}, self.cert_admin)
        self.assertEqual(st, 403, got)
        st, got = self.call('POST', '/api/deploys/save', {
            'id': files, 'cert_id': cid, 'target': 'files',
            'options': {'outputs': ['cert-pem a.pem'], 'script_interp': 'sh'}}, self.cert_admin)
        self.assertEqual(st, 403, got)

        # ---- saved as it was: still deployed; changed: "options changed"
        fk = self.ok('/api/deploys/save', {'cert_id': cid, 'target': 'fk',
                                           'options': {'file': 'x.pem', 'pfx_password': 'pw1'}})['id']
        job = self.ok('/api/deploys/run', {'id': fk})['job_id']
        end = time.time() + 60
        while time.time() < end:
            st, got = self.call('GET', '/api/certs/job', None, self.admin, {'id': job})
            if got['job']['state'] not in ('queued', 'running'):
                break
            time.sleep(0.3)

        def state():
            st, got = self.call('GET', '/api/certs/one', None, self.admin, {'id': cid})
            return [d for d in got['deploys'] if d['id'] == fk][0]
        shown = state()
        self.assertEqual(shown['state'], 'ok', shown)
        self.ok('/api/deploys/save', {'id': fk, 'cert_id': cid, 'target': 'fk', 'enabled': True,
                                      'options': dict(shown['options'])})
        self.assertEqual(state()['state'], 'ok')
        self.ok('/api/deploys/save', {'id': fk, 'cert_id': cid, 'target': 'fk',
                                      'options': {'file': 'y.pem', 'pfx_password': ''}})
        self.assertEqual(state()['state'], 'changed')
        self.ok('/api/deploys/save', {'id': fk, 'cert_id': cid, 'target': 'fk',
                                      'options': {'file': 'y.pem', 'pfx_password': ''}})
        self.assertEqual(state()['state'], 'changed')
        self.assertTrue(state()['options'].get('pfx_password'))   # the password kept

        # ---- the pages
        node = shutil.which('node')
        if not node or not shutil.which('php') or subprocess.run(
                [node, '-e', 'require("playwright")'], capture_output=True, cwd=ROOT).returncode:
            self.skipTest('no node, php or playwright for node here')
        auto1, auto1_job = self.issued('auto1')
        gone, gone_job = self.issued('gone')
        self.ok('/api/certs/delete', {'id': gone, 'revoke': 0})
        ids = {'auto1': auto1, 'goneJob': gone_job, 'liveJob': auto1_job}
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        script = os.path.join(self.tmp, 'ru2_certsui_page.js')
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
            got = subprocess.run([node, script, 'http://127.0.0.1:%d' % port, self.pw,
                                  json.dumps(ids)],
                                 capture_output=True, text=True, timeout=300, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # the switch in its window: the list and Details follow
        self.assertEqual(seen['list0'], 'by hand', seen)
        self.assertEqual(seen['details0'], 'Renewsonly when asked', seen)
        self.assertEqual(seen['list1'], 'auto', seen)
        self.assertEqual(seen['details1'], 'Renewsautomatically', seen)
        self.assertIn('held', seen['states'])
        self.assertIn('revoke-failed', seen['states'])
        self.assertNotIn('The certificate', seen['goneFoot'], seen)
        self.assertIn('The certificate', seen['liveFoot'], seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
