#!/usr/bin/env python3
"""Bug hunt R run t6: the certificate portal outside the teams - "Your certificates", the
sign-in and its one-time code.

    python3 test/test_hunt_rt6_portal.py

A real daemon in a folder of its own (test/test_certs_core.py's way); the pages from a copy of
web/ through php -S, in Chromium (test/hunt_rt6_portal_page.js) when node, php and Playwright
are here.
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


class HuntRt6Portal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        # tester: a full administrator - seeing all off, so "Your certificates" as anybody's
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_admins_all': 0,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.ids = {}
        for name, names, owner in (
                ('t6-mine', ['t6-mine.example.test'], 'local:tester'),
                ('t6-other', ['t6-other.example.test'], 'local:viewer')):
            got = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': names, 'issuer': 'self', 'key_type': 'ec-256',
                'auto_renew': 0, 'owner': owner})
            cls.ids[name] = got['id']
            job = cls.must('POST', '/api/certs/renew', {'id': got['id'], 'force': True})['job_id']
            end = time.time() + 120
            while time.time() < end:
                j = cls.must('GET', '/api/certs/job?id=%d' % job)['job']
                if j['state'] not in ('queued', 'running'):
                    break
                time.sleep(0.3)
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

    def portal(self, name='tester'):
        st, got = self.call('POST', '/api/portal/login', {'name': name, 'password': self.pw})
        self.assertEqual(st, 200, got)
        return got['token']


if __name__ == '__main__':
    if os.environ.get('HUNT_SERVE'):
        HuntRt6Portal.setUpClass()
        print(HuntRt6Portal.serve(), HuntRt6Portal.pw, HuntRt6Portal.port,
              HuntRt6Portal.token, HuntRt6Portal.admin, flush=True)
        try:
            time.sleep(int(os.environ['HUNT_SERVE']))
        finally:
            HuntRt6Portal.tearDownClass()
    else:
        unittest.main(verbosity=2)
