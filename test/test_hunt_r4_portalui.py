#!/usr/bin/env python3
"""Bug hunt R run 4: the certificate portal's pages.

    python3 test/test_hunt_r4_portalui.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (test/hunt_r4_portalui_page.js) when node, php and Playwright are
here - in English and in Czech, at a phone's width and a desktop's.

- "Your certificates" at a phone's width: the table was 450-670 px wide in a ~308 px box -
  Expires and the download button only after a sideways scroll nobody was told of. Now each
  certificate is a card of its own there; the desktop's table is as it was.
- The sign-in form: `required` on the name and the password had the browser say what was missing
  in its own bubble, in the browser's language - the page's "type your name" (translated) never
  appeared. Now the page says it.
- Revoke was offered for a self-signed certificate (a source that cannot revoke), and its job
  failed "Self-signed cannot revoke a certificate". The list now says why it cannot be revoked
  (revoke_no, as the administration's) and Revoke is not offered there.
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

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class HuntR4PortalUi(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    wait_job = TCC.CertsCore.__dict__['wait_job']
    ok = TCC.CertsCore.__dict__['ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        # a team giving the viewer "manage": Revoke, Renew now would be offered
        cls.must('POST', '/api/teams/save', {'name': 'Ops4', 'members': ['local:viewer=manage']})
        cls.ids = {}
        for name, names in (
                ('r4-issued', ['r4-issued.example.test']),
                ('r4-a-rather-long-certificate-name-for-a-phone',
                 ['www.a-rather-long-host-name.example.test', 'api.example.test',
                  'mail.example.test', 'ftp.example.test', 'more.example.test'])):
            got = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': names, 'issuer': 'self', 'key_type': 'ec-256',
                'auto_renew': 0, 'owner': 'Ops4'})
            cls.ids[name] = got['id']
            job = cls.must('POST', '/api/certs/renew', {'id': got['id'], 'force': True})['job_id']
            end = time.time() + 120
            while time.time() < end:
                j = cls.must('GET', '/api/certs/job?id=%d' % job)['job']
                if j['state'] not in ('queued', 'running'):
                    break
                time.sleep(0.3)
        cls.must('POST', '/api/certs/save', {
            'name': 'r4-idle', 'names': ['r4-idle.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'local:viewer'})
        cls.php = None

    @classmethod
    def tearDownClass(cls):
        if cls.php is not None:
            cls.php.terminate()
            cls.php.wait(10)
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def serve(cls):
        """The pages through php -S, against this daemon: their address."""
        web = os.path.join(cls.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(cls.tmp, 'run') + '/'))
        port = TCC.free_port()
        cls.php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 20
        while time.time() < end:
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=5)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        return 'http://127.0.0.1:%d' % port

    def portal_rows(self):
        st, got = self.call('POST', '/api/portal/login', {'name': 'viewer', 'password': self.pw})
        self.assertEqual(st, 200, got)
        st, got = self.call('GET', '/api/portal/certs', None, got['token'])
        self.assertEqual(st, 200, got)
        return {r['name']: r for r in got['rows']}

    def test_01_revoke_no_in_the_list(self):
        rows = self.portal_rows()
        one = rows['r4-issued']
        self.assertIn('manage', one['may'])
        self.assertTrue(one.get('not_after'), one)
        # as the administration says it (api.revocable)
        self.assertEqual(one.get('revoke_no'), 'a self-signed certificate has no CA to revoke it at')
        # only where it may be managed and is issued: nothing said for the others
        self.assertNotIn('revoke_no', rows['r4-idle'])

    def test_02_the_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        probe = subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                               cwd=ROOT)
        if probe.returncode != 0:
            self.skipTest('no playwright for node here')
        base = self.serve()
        seen = {}
        for lang in ('en', 'cs'):
            for width in (390, 1400):
                got = subprocess.run([node, os.path.join(HERE, 'hunt_r4_portalui_page.js'),
                                      base, 'viewer', self.pw, lang, str(width)],
                                     capture_output=True, text=True, timeout=240, cwd=ROOT)
                self.assertEqual(got.returncode, 0, got.stderr[-2000:])
                seen[(lang, width)] = json.loads(got.stdout.strip().splitlines()[-1])
        words = {'en': ('type your name', 'type your password'),
                 'cs': None}
        for (lang, width), one in seen.items():
            where = (lang, width, one)
            self.assertNotIn('error', one, one.get('error'))
            self.assertEqual(one['errors'], [], where)
            # the page's own words for what is missing, not the browser's bubble
            self.assertTrue(one['noName'], where)
            self.assertTrue(one['noPass'], where)
            self.assertNotEqual(one['noName'], one['noPass'], where)
            if words[lang]:
                self.assertEqual((one['noName'], one['noPass']), words[lang], where)
            else:
                self.assertNotEqual((one['noName'], one['noPass']), words['en'], where)
            self.assertTrue(one['stillRequired'], where)
            # nothing wider than the page, nor than the list's box
            self.assertLessEqual(one['wide'], 0, where)
            self.assertLessEqual(one['listWide'], 0, where)
            # every row's download button and Expires seen without scrolling sideways
            for r in one['rows']:
                self.assertTrue(r['dlIn'], (r, where))
                self.assertTrue(r['expIn'], (r, where))
            # a phone: one card per certificate; a desktop: the table's header, as before
            if width == 390:
                self.assertFalse(one['headSeen'], where)
            else:
                self.assertTrue(one['headSeen'], where)
                self.assertEqual(one['cols'], 5, where)
            # a self-signed one: no Revoke (its CA cannot), Renew now still there
            self.assertFalse(one['revoke'], where)
            self.assertTrue(one['renew'], where)


if __name__ == '__main__':
    if os.environ.get('HUNT_SERVE'):
        HuntR4PortalUi.setUpClass()
        print(HuntR4PortalUi.serve(), HuntR4PortalUi.pw, flush=True)
        try:
            time.sleep(int(os.environ['HUNT_SERVE']))
        finally:
            HuntR4PortalUi.tearDownClass()
    else:
        unittest.main(verbosity=2)
