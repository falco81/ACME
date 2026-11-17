#!/usr/bin/env python3
"""Bug hunt q4, the fixes (1.0.119).

    python3 test/test_hunt_q4_fix.py

The parts on their own (no daemon), then a real daemon in a folder of its own
(test/test_certs_core.py's way) and its pages from a copy of web/ through php -S, in
Chromium (test/hunt_q4_fix_page.js) when node, php and Playwright are here.

- The database on this machine (Settings -> The database): MySQL 8.4+ has no @@have_ssl -
  the card said the server was not running.
- /api/certs/import, parse, csr_answer: data_b64 that is no base64 read as nothing, said
  vaguely - now "<field> is not base64"; base64 in lines as before.
- DNS sets: Test from the form with the servers box empty tried the set as saved.
- Request profiles: the source of one deleted - its form chose the first source, silently.
- Request profiles: a save refused was said in English on a Czech page.
- Guides: a link with spaces or brackets in its address lost after a save.
- A read-only account opening #settings/sshkeys or #settings/modules from a link saw the
  pane, and only a 403.
"""
import base64
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

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


# ---------------------------------------------------------------------------
class FakeDb:
    def __init__(self, engine, have_ssl=True, tls='Yes'):
        self.engine, self.have_ssl, self.tls, self.asked = engine, have_ssl, tls, []

    def row(self, sql, args=()):
        self.asked.append(sql)
        if '@@have_ssl' in sql:
            if not self.have_ssl:
                raise RuntimeError("(1193, \"Unknown system variable 'have_ssl'\")")
            return {'v': '10.11.6-MariaDB', 's': 'YES', 'd': '/nowhere/q4/'}
        if 'VERSION()' in sql:
            return {'v': '8.4.3', 'd': '/nowhere/q4/'}
        return None

    def value(self, sql, args=(), default=None):
        self.asked.append(sql)
        if 'tls_channel_status' in sql:
            if isinstance(self.tls, Exception):
                raise self.tls
            return self.tls
        return default

    def rows(self, sql, args=()):
        return [{'Variable_name': 'Uptime', 'Value': '100'},
                {'Variable_name': 'Threads_connected', 'Value': '3'}]


class Store:
    def __init__(self, db):
        self.db = db


class DbLocalMysql84(unittest.TestCase):
    def facts(self, db):
        from acmelib import engine as E
        return E.db_local_facts(Store(db))

    def test_mysql_84(self):
        f = self.facts(FakeDb('mariadb', have_ssl=False, tls='Yes'))
        self.assertTrue(f['running'], f)
        self.assertEqual((f['version'], f['ssl'], f['connections']), ('8.4.3', True, 3))
        f = self.facts(FakeDb('mariadb', have_ssl=False, tls='No'))
        self.assertEqual((f['running'], f['ssl']), (True, False))
        f = self.facts(FakeDb('mariadb', have_ssl=False, tls=RuntimeError('denied')))
        self.assertEqual((f['running'], f['ssl']), (True, False))

    def test_mariadb_as_before(self):
        db = FakeDb('mariadb')
        f = self.facts(db)
        self.assertEqual((f['running'], f['version'], f['ssl']), (True, '10.11.6-MariaDB', True))
        self.assertFalse([q for q in db.asked if 'tls_channel_status' in q])

    def test_other_errors_still_not_running(self):
        class Down(FakeDb):
            def row(self, sql, args=()):
                raise RuntimeError('Access denied for user')
        f = self.facts(Down('mariadb'))
        self.assertFalse(f['running'])
        self.assertIn('Access denied', f['said'])


class B64Fields(unittest.TestCase):
    def test_not_base64(self):
        from acmelib.certs import api as A
        for bad in ('!!!***', 'not base64 at all, really: ü', '***'):
            with self.assertRaises(ValueError) as c:
                A._b64(bad, 'key_b64')
            self.assertEqual(str(c.exception), 'key_b64 is not base64')
        with self.assertRaises(ValueError) as c:
            A._b64('', 'data_b64')
        self.assertIn('no file was given', str(c.exception))

    def test_base64_in_lines_as_before(self):
        from acmelib.certs import api as A
        data = os.urandom(200)
        b = base64.b64encode(data).decode()
        self.assertEqual(A._b64(b), data)
        lines = '\n'.join(b[i:i + 64] for i in range(0, len(b), 64)) + '\r\n'
        self.assertEqual(A._b64(lines), data)
        self.assertEqual(A._b64('  ' + b[:40] + ' \t' + b[40:] + '\n'), data)


# ---------------------------------------------------------------------------
class HuntQ4Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        for src in ('q4-self', 'q4-doomed'):
            cls.must('POST', '/api/sources/save', {'name': src, 'kind': 'selfsigned',
                                                   'config': {'days': 30}})
        for prof, src in (('q4-gone', 'q4-doomed'), ('q4-fine', 'q4-self')):
            cls.must('POST', '/api/reqprofiles/save', {
                'name': prof, 'issuer': src, 'suffixes': ['example.test'], 'make_key': True,
                'key_types': ['ec-256'], 'key_default': 'ec-256'})
        # the source taken away under the profile (as deleted at the time it named it)
        db = sqlite3.connect(os.path.join(cls.tmp, 'state', 'acme.db'))
        db.execute("DELETE FROM cert_issuers WHERE name = 'q4-doomed'")
        db.commit()
        db.close()

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def test_01_import_not_base64(self):
        for path in ('/api/certs/import', '/api/certs/parse'):
            st, got = self.call('POST', path, {'data_b64': '!!! not base64 ***',
                                               'filename': 'c.pem'}, self.admin)
            self.assertEqual(st, 400, (path, got))
            self.assertIn('data_b64 is not base64', json.dumps(got), (path, got))

    def test_02_the_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        probe = subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                               cwd=ROOT)
        if probe.returncode != 0:
            self.skipTest('no playwright for node here')
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
            got = subprocess.run([node, os.path.join(HERE, 'hunt_q4_fix_page.js'),
                                  'http://127.0.0.1:%d' % port, 'tester', self.pw, 'viewer'],
                                 capture_output=True, text=True, timeout=400, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # DNS sets: not the set as saved - said what is missing, the form kept
        self.assertEqual(seen['dnsTitle'], 'The DNS set q4 set', seen)
        self.assertIn('at least one DNS server', seen['dnsToast'], seen)
        # request profiles: the source gone said, not changed to the first, nothing saved
        self.assertEqual(seen['rpIssuer'], 'q4-doomed', seen)
        self.assertIn('q4-doomed', seen['rpWarn'], seen)
        self.assertGreaterEqual(seen['rpKeys'], 1, seen)
        self.assertEqual(seen['rpAfter'], 'q4-doomed', seen)
        self.assertIn('choose the source', seen['rpSaid'] + seen['rpToast'], seen)
        self.assertEqual(seen['rpWarnPicked'], '', seen)
        self.assertEqual((seen['rpFineIssuer'], seen['rpFineWarn']), ('q4-self', False), seen)
        # the refusal in Czech
        self.assertIn('vyberte zdroj', seen['rpSaidCs'] + seen['rpToastCs'], seen)
        self.assertEqual(seen['rpTakenCs'], 'profil žádosti q4-gone už existuje', seen)
        # guides: the links kept
        g = seen['guide']
        self.assertTrue(g, seen)
        self.assertEqual(g['https://example.test/a b (c']['href'],
                         'https://example.test/a%20b%20%28c', g)
        self.assertEqual(g['https://example.test/x(y)z']['href'], 'https://example.test/x(y)z', g)
        self.assertEqual(g['http://[2001:db8::1]/p q']['href'], 'http://[2001:db8::1]/p%20q', g)
        for v in g.values():
            self.assertEqual(v['words'], 'the page', g)
        # a read-only account from a link: not the panes it may not open
        for p in ('sshkeys', 'modules'):
            self.assertNotEqual(seen['ro'][p]['pane'], p, seen['ro'])
            self.assertNotIn('pane-' + p, seen['ro'][p]['shown'], seen['ro'])
            self.assertEqual(seen['ro'][p]['bad'], [], seen['ro'])
        self.assertEqual(seen['ro']['dnssets']['pane'], 'dnssets', seen['ro'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
