#!/usr/bin/env python3
"""Hunt v2 (1.0.141), area "certs": the certificate subsystem.

    python3 test/test_hunt_rv2_certs.py
    HUNT_SHOTS=/some/dir python3 test/test_hunt_rv2_certs.py      # and screenshots there
    HUNT_CS=FILE[,FILE]  {English: Czech} merged into the copy's cs.json (before they are in it)

- a request profile made from a template on the Czech page keeps the description the page showed
  (Czech), as it keeps the name; the command line keeps acme's English words or its --note;
- the template's preview says what "Make the profile" would refuse (a public CA and a name that
  is never public) - it said "complies" and the profile was refused; what does not fit and what
  to do are Czech on the Czech page (compat.words joins them - patterns of their own);
- a name ending with an ideographic or full-width full stop (example.com。) is example.com - it
  was kept as "example.com." beside example.com (store.clean_names, pki.classify_name);
with a real daemon (test/test_certs_core.py's): the command line and the pages (php -S,
Chromium via test/hunt_rv2_certs_page.js).
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

import test_req_profiles as TRP  # noqa: E402  (its store and setup)
import test_certs_core as TCC  # noqa: E402  (the daemon, its helpers)

from acmelib import engine as E  # noqa: E402
from acmelib.certs import pki, store as S  # noqa: E402
from acmelib.certs import reqprofiles as R  # noqa: E402
from acmelib.certs import reqprofiles_templates as RT  # noqa: E402

STORE = TRP.STORE
SHOTS = os.environ.get('HUNT_SHOTS', '')
CS_EXTRA = [x for x in os.environ.get('HUNT_CS', '').split(',') if x]


def cs_text(en):
    with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
        pack = json.load(f)
    for sect in pack.values():
        if isinstance(sect, dict):
            for v in sect.values():
                if isinstance(v, dict) and v.get('source') == en:
                    return v.get('text')
    return None


class Names(unittest.TestCase):
    def test_wide_last_dot(self):
        for dot in ('。', '．', '｡'):
            self.assertEqual(S.clean_names(['example.com' + dot]), ['example.com'])
            self.assertEqual(S.clean_names(['www.example.com', 'WWW.example.com' + dot]),
                             ['www.example.com'])
            self.assertEqual(S.clean_names(['*.žluťoučký.cz' + dot]),
                             ['*.xn--luouk-uva4it5a4g.cz'])
            self.assertEqual(pki.classify_name('example.com' + dot), ('DNS', 'example.com'))
            self.assertEqual(pki.classify_name('žluť.cz' + dot), ('DNS', 'xn--lu-yta1h.cz'))
        # as before: the ASCII dot, a dot alone, a dot inside
        self.assertEqual(S.clean_names(['Example.COM.']), ['example.com'])
        self.assertEqual(S.clean_names(['例子。测试']), ['xn--fsqu00a.xn--0zwm56d'])
        with self.assertRaises(ValueError):
            S.clean_names(['。'])
        with self.assertRaises(ValueError):
            S.clean_names(['a。。b.cz'])
        with self.assertRaises(pki.PkiError):
            pki.classify_name('。')

    def test_profile_name_check(self):
        cfg = {'suffixes': R.clean_suffixes(['example.com。']), 'wildcards': False}
        self.assertEqual(cfg['suffixes'], ['example.com'])
        n = S.clean_names(['www.example.com。'])[0]
        self.assertEqual(R.name_why(n, cfg), '')


class Template(unittest.TestCase):
    def setUp(self):
        TRP.setup()
        STORE.db.run('DELETE FROM cert_req_profile_versions')

    def test_description(self):
        t = RT.template('web')
        cz = cs_text(t['about'])
        self.assertTrue(cz)
        got = RT.create(STORE, {'template': 'web', 'name': 'Weby', 'suffixes': ['example.test'],
                                'description': cz}, 'boss')
        self.assertEqual(got['profile']['description'], cz)
        self.assertEqual(R.profile_get(STORE, 'Weby')['description'], cz)
        # none given (the command line without --note): acme's English words, as before
        got = RT.create(STORE, {'template': 'web', 'name': 'Webs', 'suffixes': ['example.test']},
                        'boss')
        self.assertEqual(got['profile']['description'], t['about'])
        prev = RT.build(STORE, 'web', suffixes=['example.test'], description=cz)
        self.assertEqual(prev['body']['description'], cz)

    def test_preview_says_what_saving_refuses(self):
        STORE.db.insert('cert_issuers', {'name': 'LE', 'kind': 'acme', 'enabled': 1,
                                         'created': time.time(), 'config': json.dumps(
                                             {'directory': 'letsencrypt', 'contacts': []})})
        STORE.db.insert('cert_challenges', {'name': 'web', 'kind': 'http_local', 'enabled': 1,
                                            'created': time.time(), 'config': '{}'})
        try:
            got = RT.build(STORE, 'web', 'LE', 'web', ['web.test'], saved=True)
            self.assertEqual(got['status'], 'bad')
            said = [f['said'] for f in got['findings'] if f['rule'] == 'fits']
            self.assertTrue(said and '.test' in said[0], got['findings'])
            with self.assertRaises(E.ApiError):
                RT.create(STORE, {'template': 'web', 'name': 'Public', 'issuer': 'LE',
                                  'challenge': 'web', 'suffixes': ['web.test']}, 'boss')
            self.assertIsNone(R.profile_get(STORE, 'Public'))
            # a public name: nothing said, made
            got = RT.build(STORE, 'web', 'LE', 'web', ['example.com'], saved=True)
            self.assertFalse([f for f in got['findings'] if f['rule'] == 'fits'])
            RT.create(STORE, {'template': 'web', 'name': 'Public', 'issuer': 'LE',
                              'challenge': 'web', 'suffixes': ['example.com']}, 'boss')
            # the route (the page's preview) says it; the catalog's cards as before
            got = E.ROUTES[('POST', '/api/reqprofiles/template_preview')](TRP.FakeH(body={
                'template': 'web', 'issuer': 'LE', 'challenge': 'web', 'suffixes': ['web.test']}))
            self.assertEqual(got['status'], 'bad')
            self.assertEqual(RT.build(STORE, 'web', 'LE', 'web', ['web.test'])['status'], 'ok')
            # a source of acme's own: nothing to say
            got = RT.build(STORE, 'web', 'own', '', ['web.test'], saved=True)
            self.assertEqual(got['status'], 'ok')
        finally:
            STORE.db.run("DELETE FROM cert_issuers WHERE name = 'LE'")
            STORE.db.run("DELETE FROM cert_challenges WHERE name = 'web'")

    def test_page_sends_what_it_shows(self):
        with open(os.path.join(ROOT, 'web', 'assets', 'rptemplates.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertIn("description: tr(t.about || '')", js)
        self.assertIn('description: v.description', js)


class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    cli = TCC.CertsCore.__dict__['cli']
    cli_ok = TCC.CertsCore.__dict__['cli_ok']
    cli_json = TCC.CertsCore.__dict__['cli_json']
    py = TCC.CertsCore.__dict__['py']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def seed(self):
        if getattr(type(self), '_seeded', False):
            return
        type(self)._seeded = True
        self.ok('POST', '/api/cas/create', {'name': 'Test Root', 'subject': {'CN': 'Test Root CA'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Test Root', 'days': 90}})

    def test_1_cli(self):
        self.seed()
        made = self.cli_json('--profile-from-template', 'web', '--name', 'Web CLI',
                             '--names', 'web.test', '--issuer', 'own')
        self.assertEqual(made['profile']['description'], RT.template('web')['about'])
        made = self.cli_json('--profile-from-template', 'mail', '--name', 'Mail CLI',
                             '--names', 'mail.test', '--issuer', 'own', '--note', 'Pošta')
        self.assertEqual(made['profile']['description'], 'Pošta')
        # a name with a wide last dot: the certificate's names are the plain ones
        self.cli_ok('--cert-add', 'wide', '--names', 'a.example.test。,A.example.test',
                    '--issuer', 'own')
        got = self.ok('GET', '/api/certs')
        one = [c for c in got['rows'] if c['name'] == 'wide'][0]
        names = one['names'] if isinstance(one['names'], list) else json.loads(one['names'])
        self.assertEqual(names, ['a.example.test'])

    def test_2_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        self.seed()
        web = os.path.join(self.tmp, 'web')
        shutil.rmtree(web, ignore_errors=True)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        if CS_EXTRA:
            import test_f140_ui
            test_f140_ui.TCC_merge_cs(os.path.join(web, 'lang', 'cs.json'), CS_EXTRA)
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
            drv = subprocess.run([node, os.path.join(HERE, 'hunt_rv2_certs_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=900,
                                 env=dict(os.environ, HUNT_SHOTS=SHOTS))
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-3000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 3)
        en = RT.template('web')['about']
        cz = cs_text(en)
        profs = {p['name']: p for p in self.ok('GET', '/api/reqprofiles')['profiles']}
        for run in seen['runs']:
            want = cz if run['lang'] == 'cs' else en
            tag = '%s %s' % (run['lang'], run['w'])
            self.assertEqual(run['about'], want, tag)
            self.assertEqual(run['editorDesc'], want, tag)
            self.assertEqual(run['madeDesc'], want, tag)
            self.assertEqual(profs[run['name']]['description'], want, tag)
            self.assertTrue(run['previewBad'], tag)
            self.assertIn('.test', run['previewSays'], tag)
            self.assertFalse(run['previewOwnBad'], tag)
            if run['lang'] == 'cs' and (CS_EXTRA or cs_text(
                    '{0} - Use the full public name (e.g. {1}.example.com), or take an authority '
                    'of your own, AD CS or self-signed for internal names')):
                # what does not fit, and what to do, in Czech (compat.words joins them)
                self.assertNotIn('never public', run['previewSays'], tag)
                self.assertNotIn('Use the full', run['previewSays'], tag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
