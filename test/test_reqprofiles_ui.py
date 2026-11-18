#!/usr/bin/env python3
"""Settings -> Request profiles drawn as Owners and teams is (1.0.128).

    python3 test/test_reqprofiles_ui.py
    RQUI_SHOTS=/some/dir python3 test/test_reqprofiles_ui.py     # and screenshots there

The list of profiles as cards (the view switcher, the search, the empty state with its "first
profile"), and the editor of one in sections with icons, a side navigation, chips for the
domains and the teams, segmented choices and what the portal will show.

- The source: the cards and the editor are made of teams.css's pieces (.tmx-vbtn, .tmx-find,
  .tmx-chip, .tmx-seg, .tmx-sec-h, .tmx-prow, .tmx-empty); every label of the editor names its
  box; nothing in reqprofiles.css scrolls on its own; every new text has its Czech.
- The pages (a real daemon as test/test_certs_core.py's, php -S on a free port, Chromium via
  test/reqprofiles_ui_page.js), at 390, 768 and 1400 px in English and Czech: the cards drawn,
  the search, a profile made with every section filled and saved exactly as asked, edited and
  saved, duplicated, deleted; no error of the page, no page wider than the window, no English
  left on the Czech page, no box scrolling inside another.
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


# the English of the new pieces, each with its Czech in web/lang/cs.json
NEW_WORDS = ['Cards', 'General', 'Find a profile…', 'Add the first profile', 'No request profile yet',
             'Nothing found', 'Duplicate this profile', 'On the portal', 'Sections', 'They give',
             'In the limits of', 'Teams']


class Source(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js = read('web/assets/reqprofiles.js')
        cls.css = read('web/assets/reqprofiles.css')

    def test_teams_pieces(self):
        for cls_ in ('tmx-vbtn', 'tmx-find', 'tmx-chip', 'tmx-seg', 'tmx-sec-h', 'tmx-prow', 'tmx-empty',
                     'tmx-lchips', 'tmx-addsel', 'tmx-addtx'):
            self.assertIn(cls_, self.js, cls_)

    def test_same_api_calls(self):
        self.assertEqual(sorted(set(re.findall(r"api\('(reqprofiles[^']*)'", self.js))),
                         ['reqprofiles', 'reqprofiles/delete', 'reqprofiles/save'])

    def test_nothing_scrolls_on_its_own(self):
        self.assertNotRegex(self.css, r'overflow(-y)?\s*:\s*(auto|scroll)')
        self.assertNotIn('max-height', self.css)

    def test_czech_of_every_new_text(self):
        d = json.loads(read('web/lang/cs.json'))
        have = {e['source']: e['text'] for part in ('strings', 'patterns') for e in d[part].values()}
        for w in NEW_WORDS:
            self.assertIn(w, have, w)
            self.assertTrue(have[w] and have[w] != w, w)


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
        self.ok('POST', '/api/teams/save', {'name': 'Mailteam', 'members': []})
        self.ok('POST', '/api/reqprofiles/save', {
            'name': 'Web server certificate', 'issuer': 'own',
            'description': 'For the intranet web servers of the company, issued at once',
            'suffixes': ['example.test', 'intranet.example.test'], 'teams': ['Webteam'],
            'key_types': ['ec-256', 'rsa-2048'], 'key_default': 'ec-256'})
        self.ok('POST', '/api/reqprofiles/save', {
            'name': 'Mail relay', 'issuer': 'own', 'approval': True, 'enabled': False,
            'suffixes': ['mail.example.test'], 'key_types': ['rsa-2048'], 'key_default': 'rsa-2048'})
        self.ok('POST', '/api/teams/save', {'name': 'Webteam', 'old_name': 'Webteam', 'members': [],
                                            'policy': {'profiles': ['Web server certificate']}})
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        self.assertNotIn(port, (8092, 8443, 5432, 5433))
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
            drv = subprocess.run([node, os.path.join(HERE, 'reqprofiles_ui_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=900)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-2000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 6, seen)
        for one in seen['runs']:
            tag = '%s %s' % (one['lang'], one['w'])
            self.assertEqual(one['cards'], 2, tag)
            self.assertEqual(one['found'], 1, tag)
            self.assertEqual(one['none'], True, tag)
            self.assertEqual(one['limits'], ['Webteam'], tag)
            self.assertEqual(one['hscroll'], [], tag)
            self.assertEqual(one['nested'], [], tag)
            self.assertEqual(one['unlabelled'], [], tag)
            self.assertEqual(one['english'], [], tag)
            self.assertEqual(one['sections'], 8, tag)
            self.assertTrue(one['preview'], tag)
            self.assertEqual(one['made'], one['wanted'], tag)
            self.assertEqual(one['edited'], {'description': 'changed ' + one['lang'] + str(one['w']),
                                             'suffixes': ['n%s%d.example.test' % (one['lang'], one['w']),
                                                          'more.example.test']}, tag)
            self.assertTrue(one['copied'], tag)
            self.assertEqual(one['copyName'], one['name'] + ' 2', tag)
            self.assertEqual(one['left'], ['Mail relay', 'Web server certificate'], tag)
        # the empty state, its button opening a new profile
        self.assertTrue(seen['emptyState'], seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
