#!/usr/bin/env python3
"""Bug hunt t6: the Settings pane and High availability.

    python3 test/test_hunt_rt6_settings.py

- A value that is not of its setting's kind (a number box emptied, "abc" for a number, "maybe"
  for a switch) was refused with "a number is needed, and nothing was given" - no setting
  named: the save bar could not mark the box, nor say which of several changes it was.
- Settings → High availability at 390 px: the copy buttons of the load balancer's guides
  (and the message texts' "As it comes") were squeezed by their titles, their words ran out
  of them; the table of each node's own settings had "The cluster's" run over the first
  node's name, and a long node name made the page wider than the phone.
- "Heard from" of the nodes (High availability, and the cluster's card) was worked out by the
  browser's clock from the node's own time - a node answering was "10 min ago" on a laptop ten
  minutes ahead. Now by the age the daemon measured, as the settings' pill does.

A real daemon (test/test_certs_core.py's way) and php -S, in Chromium
(test/hunt_rt6_settings_page.js) when node, php and Playwright are here.
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
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


class Named(unittest.TestCase):
    """check_setting says which setting a value of the wrong kind was given for."""

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp(prefix='acme-rt6-')
        with open(os.path.join(tmp, 'config.json'), 'w') as f:
            f.write('{}')
        os.environ.update(ACME_CONFIG=os.path.join(tmp, 'config.json'), ACME_STATE=tmp,
                          ACME_RUN=tmp, ACME_LOGDIR=tmp)
        import acmelib.engine as E
        cls.E = E

    def refused(self, key, value):
        with self.assertRaises(self.E.BadSetting) as c:
            self.E.check_setting(key, value)
        return str(c.exception)

    def test_number_emptied(self):
        self.assertEqual(self.refused('certs_renew_days', ''),
                         'certs_renew_days: a number is needed, and nothing was given')
        self.assertEqual(self.refused('certs_renew_days', None),
                         'certs_renew_days: a number is needed, and nothing was given')

    def test_not_a_number(self):
        self.assertEqual(self.refused('certs_renew_days', 'abc'),
                         "certs_renew_days: 'abc' is not a number")

    def test_not_yes_or_no(self):
        key = [k for k, v in self.E.DEFAULTS.items() if isinstance(v, bool)][0]
        self.assertEqual(self.refused(key, 'maybe'), "%s: 'maybe' is not yes or no" % key)

    def test_good_values_as_before(self):
        self.assertEqual(self.E.check_setting('certs_renew_days', '20.7'), 20)
        self.assertEqual(self.E.check_setting('backup_at', '07:30'), '07:30')
        self.assertIn('must be between', self.refused('certs_renew_days', 99999))
        self.assertIn('is not a setting this version knows', self.refused('no_such_one', 1))


class Source(unittest.TestCase):
    def test_css(self):
        css = read('web/assets/acme.css')
        self.assertIn('.lb-block-h > .btn{flex-shrink:0}', css)
        self.assertIn('.tx-field-h > .btn{flex-shrink:0}', css)
        self.assertIn('table.node-own th,table.node-own td:first-child{white-space:normal;'
                      'overflow-wrap:anywhere}', css)

    def test_heard_by_age(self):
        js = read('web/assets/admin.js')
        self.assertIn("function haHeard(n) {\n  return ago(typeof n.age === 'number' ? "
                      "Date.now() / 1000 - n.age : n.at);", js)
        self.assertEqual(js.count("tr.appendChild(el('td', 'muted', haHeard(n)));"), 2)
        self.assertNotIn("tr.appendChild(el('td', 'muted', ago(n.at)));", js)


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

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
        # Two more nodes in the cluster's list: one answering, one with a long name.
        db = sqlite3.connect(os.path.join(self.tmp, 'state', 'acme.db'), timeout=30)
        now = time.time()
        for name, addr in (('acme2', '192.0.2.3'), ('acme3-with-a-rather-long-node-name',
                                                    '192.0.2.4')):
            db.execute('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)',
                       ('node:' + name, json.dumps({'at': now + 3600, 'version': '1.0.127',
                                                    'address': addr})))
        db.commit()
        db.close()
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
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rt6_settings_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, timeout=400, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        for lang in ('en', 'cs'):
            ha = seen['ha_' + lang]
            self.assertEqual(ha['wide'], 0, (lang, ha))
            self.assertEqual(ha['btnOver'], [], (lang, ha))
            self.assertEqual(ha['ths'], 5, (lang, ha))      # setting, the cluster's, 3 nodes
            self.assertEqual(ha['thOver'], [], (lang, ha))
            tx = seen['texts_' + lang]
            self.assertEqual(tx['btnOver'], [], (lang, tx))
        # by the daemon's age: this node heard from seconds ago, never "10 min ago"
        heard = dict((re.sub(r'\s.*', '', n.strip()), w) for n, w in seen['heard'])
        self.assertRegex(heard['testnode'], r'^\d+ s ago$', seen['heard'])
        self.assertEqual(seen['refused'], ['certs_renew_days'], seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
