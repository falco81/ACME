#!/usr/bin/env python3
"""Bug hunt Ru4 (1.0.134): the Overview, the Jobs tab and the header of the administration.

    python3 test/test_hunt_ru4_dash.py

- A running job's window, its certificate opened over it ("The certificate") and closed again:
  the window was no longer asked - it said "running, 13 s so far" with Stop it for good, the job
  long over. Asked again once it is on top.
- The tab Jobs' count of running jobs was counted on the page shown: a list filtered ("went
  well", a certificate) or a page further back took the "1" off the tab while a job ran. Now the
  running jobs are asked for by themselves there.
- Live updates paused in the header: the Jobs list went on being asked and drawn again every
  2.5 s while a job ran.
- The Overview's lists ("What needs a look", "Running out soonest") stopped at 520 px with a
  scrollbar of their own inside the page's - at a phone's width a dozen alerts did it.

A real daemon (test/test_certs_core.py's way) and php -S, in Chromium
(test/hunt_ru4_dash_page.js) when node, php and Playwright are here.
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


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Source(unittest.TestCase):

    def test_job_window_asked_again_after_its_certificate(self):
        js = read('web/assets/certs.js')
        body = js[js.index('function jobPeek('):js.index('function tabCount(')]
        self.assertIn('over(function () { certPeek(j.cert_id); }, function () {', body)
        self.assertIn('ticket = modalTicket();', body)
        self.assertIn('if (!drewDone) poll(true);', body)

    def test_running_count_of_every_job(self):
        js = read('web/assets/certs.js')
        body = js[js.index('function loadJobs('):js.index('var LEVEL = {')]
        self.assertNotIn("tabCount('tabn-jobs', running, false);\n    /* paged", body)
        self.assertIn("capi('certs/jobs' + qs({state: 'running', per: 1}))", body)

    def test_jobs_not_asked_while_paused(self):
        js = read('web/assets/certs.js')
        body = js[js.index('function loadJobs('):js.index('var LEVEL = {')]
        self.assertIn("(typeof LIVE === 'undefined' || LIVE)", body)

    def test_overview_lists_no_scrollbar_of_their_own(self):
        css = read('web/assets/certs.css')
        rule = css[css.index('.ct-ovlist{'):]
        rule = rule[:rule.index('}')]
        self.assertNotIn('overflow-y:auto', rule)
        self.assertNotIn('max-height', rule)


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    wait_job = TCC.CertsCore.__dict__['wait_job']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        self.ok('POST', '/api/cas/create', {'name': 'Test Root', 'subject': {'CN': 'Test Root CA'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Test Root', 'days': 90}})
        out = os.path.join(self.tmp, 'out')
        self.ok('POST', '/api/targets/save', {'name': 'badloc', 'kind': 'local',
                                              'config': {'base': '/proc/nonexist'}})
        self.ok('POST', '/api/targets/save', {'name': 'slow', 'kind': 'local',
                                              'config': {'base': out,
                                                         'allow_commands': ['/bin/sleep 45']}})
        # a dozen and more deployments failing: "What needs a look" longer than 520 px on a phone
        for i in range(16):
            cid = self.ok('POST', '/api/certs/save', {'name': 'bad%02d' % i,
                                                      'names': ['bad%02d.example.test' % i],
                                                      'issuer': 'own', 'auto_renew': 0})['id']
            self.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'badloc',
                                                  'options': {'outputs': ['fullchain-pem b%d/f.pem' % i]}})
            self.wait_job(self.ok('POST', '/api/certs/renew', {'id': cid})['job_id'])
        slow = self.ok('POST', '/api/certs/save', {'name': 'slow', 'names': ['slow.example.test'],
                                                   'issuer': 'own', 'auto_renew': 0})['id']
        self.ok('POST', '/api/deploys/save', {'cert_id': slow, 'target': 'slow',
                                              'options': {'outputs': ['fullchain-pem s/f.pem'],
                                                          'command': '/bin/sleep 45'}})
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        while port in (8092, 8443):
            port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        seen = None
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
            drv = subprocess.Popen([node, os.path.join(HERE, 'hunt_ru4_dash_page.js'),
                                    'http://127.0.0.1:%d' % port, self.pw],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   cwd=ROOT)
            try:
                for line in drv.stdout:
                    line = line.strip()
                    if not line.startswith('{'):
                        continue
                    got = json.loads(line)
                    if got.get('ready'):
                        self.ok('POST', '/api/certs/renew', {'id': slow})
                        continue
                    seen = got
                drv.wait(300)
            finally:
                if drv.poll() is None:
                    drv.kill()
            said = drv.stderr.read()
            drv.stdout.close()
            drv.stderr.close()
            self.assertEqual(drv.returncode, 0, said[-2000:])
        finally:
            php.terminate()
            php.wait(10)
        self.assertIsNotNone(seen)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # the Overview's lists: part of the page
        self.assertTrue(any(x['rows'] >= 12 for x in seen['ovlist']), seen)
        self.assertFalse(any(x['scrolls'] for x in seen['ovlist']), seen)
        # the running count on a list filtered "went well"
        self.assertEqual(seen['countFiltered'], '1', seen)
        # paused: the list not asked
        self.assertEqual(seen['pausedAsked'], 0, seen)
        # the job's window, back from its certificate: asked on, and how it ended said
        self.assertEqual(seen['overTitle'], 'slow', seen)
        self.assertTrue(seen['windowEnded'], seen)
        self.assertGreater(seen['windowAsked'], 0, seen)
        self.assertRegex(seen['windowTitle'], r'^(issue|renewal) #', seen)
        self.assertNotIn('Stop it', seen['windowButtons'], seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
