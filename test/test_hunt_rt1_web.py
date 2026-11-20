#!/usr/bin/env python3
"""Bug hunt t1, area web (1.0.137): the pages and the API handlers.

    python3 test/test_hunt_rt1_web.py

- A target's window (Targets -> a row) listed a choice of its settings by the value kept:
  FortiGate's "SSH: sign in with" said "password" - English in the Czech page as well. It
  shows the choice's words (certs.js targetPeek), translated as the form's are.
- FortiGate's "Management VDOM" (a target setting with pattern=) took a line break or ".."
  on save: only a deployment's options were checked against a field's pattern. A module
  setting with a pattern is checked when given or changed (api._family_fill); one kept as it
  was is not asked again.

A real daemon (test/test_certs_core.py's way) and php -S, in Chromium
(test/hunt_rt1_web_page.js) when node, php and Playwright are here.
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

    def test_peek_shows_a_choice_in_words(self):
        js = read('web/assets/certs.js')
        at = js.index("var st = section('Settings', 'How acme reaches it.")
        part = js[at:at + 2000]
        self.assertIn("if (f.type === 'select')", part)
        self.assertIn('optionPairs(f)', part)


class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def save(self, cfg, ident=None, name='fw-mv'):
        body = {'name': name, 'kind': 'fortigate', 'config': cfg}
        if ident:
            body['id'] = ident
        return self.call('POST', '/api/targets/save', body, self.admin)

    def test_01_mgmt_vdom_pattern(self):
        base = {'host': '127.0.0.1', 'port': 9, 'token': 'tok-x', 'vdom': 'root'}
        for bad in ('ro\not', '..', 'a\tb'):
            st, got = self.save(dict(base, mgmt_vdom=bad))
            self.assertEqual(st, 400, (bad, got))
            self.assertEqual(got.get('field'), 'mgmt_vdom', got)
            self.assertIn('Management VDOM', got.get('error', ''))
        # nothing half made by a refused new one
        rows = self.ok('GET', '/api/targets')['rows']
        self.assertFalse([r for r in rows if r['name'] == 'fw-mv'])
        st, got = self.save(dict(base, mgmt_vdom='root'))
        self.assertEqual(st, 200, got)
        ident = got['id']
        st, got = self.save(dict(base, mgmt_vdom=''), ident)
        self.assertEqual(st, 200, got)
        # a refused change keeps what was saved
        st, got = self.save(dict(base, mgmt_vdom='x\ny'), ident)
        self.assertEqual(st, 400, got)
        st, got = self.save(dict(base, mgmt_vdom='mgmt'), ident)
        self.assertEqual(st, 200, got)
        t = [r for r in self.ok('GET', '/api/targets')['rows'] if r['name'] == 'fw-mv'][0]
        self.assertEqual(t['config']['mgmt_vdom'], 'mgmt')

    def test_02_kept_value_not_asked_again(self):
        # one saved before the check (straight into the database, as an older version could):
        # saving the target again with it unchanged is not refused
        st, got = self.save({'host': '127.0.0.1', 'token': 'tok-y', 'mgmt_vdom': 'root'},
                            name='fw-old')
        self.assertEqual(st, 200, got)
        ident = got['id']
        db = os.path.join(self.tmp, 'state', 'acme.db')
        if not os.path.exists(db):
            self.skipTest('the database is not SQLite here')
        import sqlite3
        con = sqlite3.connect(db)
        try:
            row = con.execute('SELECT config FROM cert_targets WHERE id = ?', (ident,)).fetchone()
            cfg = json.loads(row[0])
            cfg['mgmt_vdom'] = '..'
            con.execute('UPDATE cert_targets SET config = ? WHERE id = ?', (json.dumps(cfg), ident))
            con.commit()
        finally:
            con.close()
        st, got = self.save({'host': '127.0.0.1', 'token': '', 'mgmt_vdom': '..',
                             'vdom': 'root'}, ident, name='fw-old')
        self.assertEqual(st, 200, got)

    def test_03_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        self.ok('POST', '/api/targets/save', {'name': 'fw-ssh', 'kind': 'fortigate', 'config': {
            'host': '127.0.0.1', 'port': 9, 'token': 'tok-z', 'vdom': 'root',
            'ssh_user': 'u', 'ssh_auth': 'password', 'ssh_password': 'pw-z'}})
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
            drv = subprocess.run([node, os.path.join(HERE, 'hunt_rt1_web_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=300)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-2000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        by = {s['lang']: s for s in seen['seen']}
        self.assertEqual(by['en']['auth'], 'a password')
        self.assertEqual(by['cs']['auth'], 'heslo')
        for s in seen['seen']:
            self.assertEqual(s['hscroll'], 0, s)


if __name__ == '__main__':
    unittest.main(verbosity=2)
