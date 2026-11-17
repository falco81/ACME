#!/usr/bin/env python3
"""Bug hunt r6 (1.0.125): the Overview, the Jobs tab and the header of the administration.

    python3 test/test_hunt_r6_overviewui.py

- The Overview at a phone's width opened 537 px down, under the header (Sign out and the account
  out of sight): the certificates' tiles drawn in front of isemon's tile pushed down what the
  redraw keeper (core.js VIEWKEEP) had picked in the middle of the frame, and it scrolled the page
  after it. A box at its very top now stays at its top.
- The tile The database said "4,3 MB · naposledy před copy 2 min" in Czech: "last copy 2 min ago"
  was taken by the pattern "last {0} min ago". Now "poslední kopie před 2 min".
- The count of running jobs on the tab Jobs was set only on the Jobs tab: a "1" stayed there for
  good once the job ended under the Overview.
- The tile Failing (and a failed deployment under "What needs a look") opened Jobs at
  "deployment · failed" - a deployment that fails is mostly a step of an issue or a renewal, so
  the list said "No job matches the filter" under a tile counting 2. Now every failed job, and a
  certificate chosen there before no longer hides them.

A real daemon (test/test_certs_core.py's way) and php -S, in Chromium
(test/hunt_r6_overviewui_page.js) when node, php and Playwright are here.
"""
import json
import os
import re
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

    def test_overview_sets_the_running_count(self):
        js = read('web/assets/certs.js')
        body = js[js.index('function loadOverviewCerts('):js.index('function drawOverviewCerts(')]
        self.assertIn("tabCount('tabn-jobs', Number(d.running || 0), false);", body)

    def test_failing_opens_every_failed_job(self):
        js = read('web/assets/certs.js')
        self.assertNotIn("openJobs({kind: 'deploy', ok: '0'})", js)
        opener = js[js.index('function openJobs('):js.index('function openCerts(')]
        self.assertIn("$('jb-cert').value = f.cert_id || ''", opener)

    def test_db_copy_words(self):
        js = read('web/assets/admin.js')
        self.assertNotIn("' · last copy ' + ago(db.last_backup)", js)
        self.assertIn("' · last copy \\u00a7'", js)

    def test_keeper_leaves_the_top(self):
        js = read('web/assets/core.js')
        self.assertIn('VIEWKEEP.at.atTop = VIEWKEEP.at.sc.scrollTop < 1;', js)
        self.assertIn('if (a.atTop && a.sc.scrollTop < 1) { viewTake(null); viewRoomBack(); return; }', js)


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
        # An authority of acme's own, a target that fails, one that takes a few seconds.
        self.ok('POST', '/api/cas/create', {'name': 'Test Root', 'subject': {'CN': 'Test Root CA'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Test Root', 'days': 90}})
        out = os.path.join(self.tmp, 'out')
        self.ok('POST', '/api/targets/save', {'name': 'badloc', 'kind': 'local',
                                              'config': {'base': '/proc/nonexist'}})
        self.ok('POST', '/api/targets/save', {'name': 'slow', 'kind': 'local',
                                              'config': {'base': out,
                                                         'allow_commands': ['/bin/sleep 12']}})
        bad = self.ok('POST', '/api/certs/save', {'name': 'bad', 'names': ['bad.example.test'],
                                                  'issuer': 'own', 'auto_renew': 0})['id']
        self.ok('POST', '/api/deploys/save', {'cert_id': bad, 'target': 'badloc',
                                              'options': {'outputs': ['fullchain-pem b/f.pem']}})
        job = self.wait_job(self.ok('POST', '/api/certs/renew', {'id': bad})['job_id'])
        self.assertEqual(job['state'], 'failed', job)
        slow = self.ok('POST', '/api/certs/save', {'name': 'slow', 'names': ['slow.example.test'],
                                                   'issuer': 'own', 'auto_renew': 0})['id']
        self.ok('POST', '/api/deploys/save', {'cert_id': slow, 'target': 'slow',
                                              'options': {'outputs': ['fullchain-pem s/f.pem'],
                                                          'command': '/bin/sleep 12'}})
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
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
            drv = subprocess.Popen([node, os.path.join(HERE, 'hunt_r6_overviewui_page.js'),
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
                        # the page is on the Overview: a job that runs a few seconds
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
        # a phone: at the top
        self.assertEqual(seen['phoneScrollY'], 0, seen)
        # the database's tile in Czech: no English word in a Czech sentence
        self.assertNotIn('copy', seen['dbSub'], seen)
        self.assertNotIn('naposledy před', seen['dbSub'], seen)
        self.assertTrue(re.search(r'(poslední kopie|zatím žádná kopie)', seen['dbSub']), seen)
        # the running count from the Overview: there, then gone
        self.assertEqual(seen['jobsCountBefore'], '', seen)
        self.assertEqual(seen['jobsCountRunning'], '1', seen)
        self.assertEqual(seen['jobsCountOnJobs'], '1', seen)
        self.assertEqual(seen['jobsCountAfter'], '', seen)
        # Failing: every failed job, the certificate chosen before let go
        tab, kind, ok, cert, rows = seen['failingOpened']
        self.assertEqual((tab, kind, ok, cert), ('jobs', '', '0', ''), seen)
        self.assertGreater(rows, 0, seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
