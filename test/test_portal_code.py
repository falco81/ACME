"""A one-time code at every sign-in to the certificate portal (1.0.40, as otp's code before the
first token, 1.0.228): by mail or SMS to what the directory has, typed back before anything of
the person is shown - at every sign-in, and after the sign-in by the load balancer too.

    python3 test/test_portal_code.py
"""
import glob
import os
import re
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-pcode-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402,F401
import test_certs_core as TCC  # noqa: E402
import mockldap  # noqa: E402

BASE = 'DC=corpnet,DC=loc'
SPOOL = os.path.join(TMP, 'sms')
os.makedirs(SPOOL, exist_ok=True)


class PortalCode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_directory': 'corp', 'portal_tries': 50,
            'sms_mode': 'spool', 'sms_spool_dir': SPOOL}})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def last_code(self):
        files = sorted(glob.glob(os.path.join(SPOOL, 'acme-*')), key=os.path.getmtime)
        self.assertTrue(files, 'no SMS written')
        with open(files[-1], encoding='utf-8') as f:
            return re.search(r'\b(\d{6})\b', f.read()).group(1)

    def test_01_off_as_until_now(self):
        st, got = self.call('POST', '/api/portal/login', {'name': 'marta', 'password': 'marta-password-1'})
        self.assertEqual(st, 200, got)
        self.assertNotIn('gate', got)

    def test_02_refused_without_a_way_to_send(self):
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_code': 'mail'}}, self.admin)
        self.assertEqual(st, 400, got)

    def test_03_every_sign_in_asks_the_code(self):
        self.must('POST', '/api/settings', {'settings': {'portal_code': 'sms'}})
        for _ in range(2):          # every sign-in, not only the first
            st, got = self.call('POST', '/api/portal/login', {'name': 'marta', 'password': 'marta-password-1'})
            self.assertEqual(st, 200, got)
            self.assertEqual(got['gate']['kind'], 'sms')
            tok = got['token']
            # nothing of the person until the code is typed
            st, me = self.call('GET', '/api/portal/me', None, tok)
            self.assertTrue(me['me']['gate'])
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 401)
            st, bad = self.call('POST', '/api/portal/gate', {'code': '000000'}, tok)
            self.assertEqual(st, 403, bad)
            code = self.last_code()
            st, ok = self.call('POST', '/api/portal/gate', {'code': code[:3] + ' ' + code[3:]}, tok)
            self.assertEqual(st, 200, ok)
            st, me = self.call('GET', '/api/portal/me', None, tok)
            self.assertNotIn('gate', me['me'])
            time.sleep(1.1)

    def test_04_sent_again(self):
        self.must('POST', '/api/settings', {'settings': {'portal_code': 'sms'}})
        st, got = self.call('POST', '/api/portal/login', {'name': 'marta', 'password': 'marta-password-1'})
        first = self.last_code()
        time.sleep(1.1)
        st, again = self.call('POST', '/api/portal/gate/again', {}, got['token'])
        self.assertEqual(st, 200, again)
        self.assertNotEqual(self.last_code(), '')

    def test_05_nobody_to_send_to(self):
        self.must('POST', '/api/settings', {'settings': {'portal_code': 'sms'}})
        st, got = self.call('POST', '/api/portal/login', {'name': 'falco', 'password': 'falco-password-1'})
        self.assertEqual(st, 403, got)

    def test_06_portal_logout_ends_portal_sign_ins_only(self):
        """POST /api/portal/logout ends a sign-in of the portal - never an administrator's
        given to it (1.0.101)."""
        admin = self.login('tester')
        st, _ = self.call('POST', '/api/portal/logout', {}, admin)
        self.assertEqual(st, 200)
        st, who = self.call('GET', '/api/auth/whoami', None, admin)
        self.assertEqual(st, 200, who)
        self.must('POST', '/api/settings', {'settings': {'portal_code': 'off'}})
        st, got = self.call('POST', '/api/portal/login', {'name': 'marta', 'password': 'marta-password-1'})
        self.assertEqual(st, 200, got)
        tok = got['token']
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertTrue(me['me'])
        st, _ = self.call('POST', '/api/portal/logout', {}, tok)
        self.assertEqual(st, 200)
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertIsNone(me['me'])


if __name__ == '__main__':
    unittest.main()
