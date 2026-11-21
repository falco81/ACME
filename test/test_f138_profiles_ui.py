#!/usr/bin/env python3
"""Request profiles 1.0.138 on the page (docs/request-profiles.md): a base profile in the editor,
the history and the diff of two versions, a dry run, the compliance check and ending a profile.

    python3 test/test_f138_profiles_ui.py
    F138_SHOTS=/some/dir python3 test/test_f138_profiles_ui.py      # and screenshots there
    F138_CS=/path/merged-cs.json ...                                # the Czech to test with

A real daemon (test/test_certs_core.py's), php -S on a free port, Chromium via
test/f138_profiles_page.js at 390 and 1400 px in English and in Czech: no error of the page, no
page wider than the window, no box scrolling inside another, every box labelled, and - with the
Czech of this package merged into the copy of web/lang/cs.json (F138_CS, or the package's
scratch files when they are there) - no English left on the Czech page. What the page does is
checked through the API: a field overridden and saved, a version restored, a profile ended and
offered again.
"""
import glob
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


def merged_cs(web):
    """web/lang/cs.json of the copy with this package's Czech put in (strings and patterns)."""
    src = os.environ.get('F138_CS')
    if src and os.path.isfile(src):
        shutil.copy(src, os.path.join(web, 'lang', 'cs.json'))
        return True
    pad = glob.glob('/tmp/claude-*/*/*/scratchpad/feat138/cs_profiles.json')
    if not pad:
        return False
    base = os.path.dirname(pad[0])
    path = os.path.join(web, 'lang', 'cs.json')
    with open(path, encoding='utf-8') as f:
        d = json.load(f)
    have = {e['source'] for part in ('strings', 'patterns') for e in d[part].values()}
    for part, name, pre in (('strings', 'cs_profiles.json', 's'),
                            ('patterns', 'cs_profiles_patterns.json', 'p')):
        fn = os.path.join(base, name)
        if not os.path.isfile(fn):
            continue
        with open(fn, encoding='utf-8') as f:
            add = json.load(f)
        n = 0
        for en, cs in add.items():
            if en in have:
                continue
            n += 1
            d[part]['%s9f138%04d' % (pre, n)] = {'source': en, 'text': cs}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(d, f, ensure_ascii=False)
    return True


class Pages(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']

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
        self.ok('POST', '/api/teams/save', {'name': 'Webteam', 'members': []})
        web = {'issuer': 'own', 'description': 'The company web servers: the source, the key and '
               'the subject of the company', 'suffixes': ['example.test'],
               'key_types': ['ec-256', 'rsa-2048'], 'key_default': 'ec-256', 'days': 90,
               'subject': {'O': {'mode': 'fixed', 'value': 'Example Ltd'},
                           'C': {'mode': 'fixed', 'value': 'CZ'}}}
        self.ok('POST', '/api/reqprofiles/save', dict(web, name='Company web'))
        self.ok('POST', '/api/reqprofiles/save', dict(web, name='Company web', old_name='Company web',
                                                      days=60, suffixes=['example.test',
                                                                         'corp.example.test']))
        self.ok('POST', '/api/reqprofiles/save', {
            'name': 'Shop', 'base': 'Company web', 'suffixes': ['shop.example.test'],
            'teams': ['Webteam'], 'description': 'The web shop - all but its domains from the base',
            'inherit': ['source', 'wildcards', 'max_names', 'make_key', 'csr', 'key_types',
                        'auto_renew', 'renew_days', 'days', 'eku', 'approval', 'owner', 'tags',
                        'pfx', 'subject.O', 'subject.OU', 'subject.L', 'subject.ST', 'subject.C',
                        'subject.emailAddress']})
        self.ok('POST', '/api/reqprofiles/save', dict(web, name='Old web', days=300,
                                                      description='Valid for 300 days'))
        # a certificate asked for from "Old web" (as the portal notes it)
        cid = self.ok('POST', '/api/certs/save', {'name': 'old-www', 'names': ['www.example.test'],
                                                  'issuer': 'own', 'key_type': 'rsa-2048',
                                                  'auto_renew': 0})['id']
        db = sqlite3.connect(glob.glob(os.path.join(self.tmp, 'state', '*.db'))[0], timeout=30)
        db.execute('INSERT INTO meta (k, v) VALUES (?, ?)', (
            'certs:portal:%d' % cid, json.dumps({'who': 'local:eva', 'profile': 'Old web',
                                                 'profile_version': 1, 'at': time.time()})))
        db.commit()
        db.close()
        webdir = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), webdir)
        czech = merged_cs(webdir)
        api_php = os.path.join(webdir, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        self.assertNotIn(port, (8092, 8443, 5432, 5433))
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=webdir,
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
            drv = subprocess.run([node, os.path.join(HERE, 'f138_profiles_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=900,
                                 env=dict(os.environ, F138_SHOTS=os.environ.get('F138_SHOTS', '')))
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-3000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 4, seen)
        for one in seen['runs']:
            tag = '%s %s' % (one['lang'], one['w'])
            self.assertEqual(one['hscroll'], [], tag)
            self.assertEqual(one['nested'], [], tag)
            self.assertEqual(one['unlabelled'], [], tag)
            if czech or one['lang'] == 'en':
                self.assertEqual(one['english'], [], tag)
            self.assertGreaterEqual(one['inherited'], 10, tag)
            self.assertTrue(one['overrideShown'], tag)
            self.assertGreaterEqual(one['versions'], 2, tag)
            self.assertGreaterEqual(one['diffRows'], 1, tag)
            self.assertTrue(one['dryFits'], tag)
            self.assertTrue(one['dryBad'], tag)
            self.assertGreaterEqual(one['steps'], 3, tag)
            self.assertTrue(one['impactMoves'], tag)
        # what the page did (the English wide run): Shop's validity overridden, Company web
        # restored, Old web ended and offered again
        st, d = self.call('GET', '/api/reqprofiles', None, self.admin)
        by = {p['name']: p for p in d['profiles']}
        self.assertNotIn('days', by['Shop']['inherit'])
        self.assertEqual(by['Shop']['days'], 30)
        self.assertEqual(by['Company web']['days'], 90)          # version 1 restored
        self.assertGreaterEqual(by['Company web']['version'], 3)
        self.assertIsNone(by['Old web']['ends'])
        st, v = self.call('GET', '/api/reqprofiles/versions', None, self.admin, {'name': 'Old web'})
        self.assertEqual([x['why'] for x in v['versions']][:2],
                         ['no longer ends', 'ends: its successor is Company web'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
