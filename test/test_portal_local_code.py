"""The portal's one-time code for acme's own accounts (1.0.44): a setting of its own
(portal_local_code - as for the directory's people, off, or a way), sent to the e-mail address
or the mobile number the account has in Accounts; without what the way needs, it cannot sign in.
Before, the password alone let an account of acme's own in where the directory's people needed
the code.

    python3 test/test_portal_local_code.py
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
TMP = tempfile.mkdtemp(prefix='acme-plcode-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402,F401
from acmelib import engine as EN  # noqa: E402
import test_certs_core as TCC  # noqa: E402

SPOOL = os.path.join(TMP, 'sms')
os.makedirs(SPOOL, exist_ok=True)
PW = 'Eva-Password-2026!'


class PortalLocalCode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_tries': 50, 'portal_enrolers': 1,
            'sms_mode': 'spool', 'sms_spool_dir': SPOOL}})
        cls.must('POST', '/api/users', {'action': 'add', 'name': 'eva', 'role': 'portal',
                                        'password': PW, 'must_change': 0})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def settings(self, **kw):
        self.must('POST', '/api/settings', {'settings': kw})

    def contact(self, mail='', mobile=''):
        return self.call('POST', '/api/users', {'action': 'contact', 'name': 'eva', 'mail': mail,
                                                'mobile': mobile}, self.admin)

    def sign_in(self):
        time.sleep(1.05)            # codes to one address: one a second
        return self.call('POST', '/api/portal/login', {'name': 'eva', 'password': PW})

    def last_code(self):
        files = sorted(glob.glob(os.path.join(SPOOL, 'acme-*')), key=os.path.getmtime)
        self.assertTrue(files, 'no SMS written')
        with open(files[-1], encoding='utf-8') as f:
            return re.search(r'\b(\d{6})\b', f.read()).group(1)

    def test_01_off_as_until_now(self):
        self.settings(portal_code='off', portal_local_code='same')
        st, got = self.sign_in()
        self.assertEqual(st, 200, got)
        self.assertNotIn('gate', got)

    def test_02_same_as_the_directory_and_no_number(self):
        self.contact()
        self.settings(portal_code='sms', portal_local_code='same')
        st, got = self.sign_in()
        self.assertEqual(st, 403, got)
        self.assertIn('no e-mail address or mobile number', got.get('error', ''))
        users = self.must('GET', '/api/users')
        self.assertEqual(users['portal_code_ways'], ['sms'])

    def test_03_the_code_to_the_accounts_number(self):
        st, got = self.contact(mobile='+420 603 123 456')
        self.assertEqual(st, 200, got)
        self.settings(portal_code='sms', portal_local_code='same')
        st, got = self.sign_in()
        self.assertEqual(st, 200, got)
        self.assertEqual(got['gate']['kind'], 'sms')
        tok = got['token']
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertTrue(me['me']['gate'])
        st, _ = self.call('GET', '/api/portal/certs', None, tok)
        self.assertEqual(st, 401)
        st, bad = self.call('POST', '/api/portal/gate', {'code': '000000'}, tok)
        self.assertEqual(st, 403, bad)
        st, ok = self.call('POST', '/api/portal/gate', {'code': self.last_code()}, tok)
        self.assertEqual(st, 200, ok)
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertEqual(st, 200)
        self.assertNotIn('gate', me['me'])
        self.assertEqual(me['me']['about']['mobile'], '+420603123456')

    def test_04_its_own_setting(self):
        self.contact(mobile='+420603123456')
        # off for acme's own while the directory's people get it
        self.settings(portal_code='sms', portal_local_code='off')
        st, got = self.sign_in()
        self.assertEqual(st, 200, got)
        self.assertNotIn('gate', got)
        # on for acme's own while the directory's people do not
        self.settings(portal_code='off', portal_local_code='sms')
        st, got = self.sign_in()
        self.assertEqual(st, 200, got)
        self.assertEqual(got['gate']['kind'], 'sms')

    def test_05_by_mail_only_and_only_a_number(self):
        # no mail server here: the way by e-mail cannot be chosen at all
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_local_code': 'mail'}},
                            self.admin)
        self.assertEqual(st, 400, got)
        # e-mail first, SMS when there is no address: the number takes it
        self.contact(mobile='+420603123456')
        self.settings(portal_code='off', portal_local_code='mail_sms')
        st, got = self.sign_in()
        self.assertEqual(st, 200, got)
        self.assertEqual(got['gate']['kind'], 'sms')

    def test_06_contact_checked(self):
        st, got = self.contact(mail='not an address')
        self.assertEqual(st, 400, got)
        st, got = self.contact(mail='eva@example.cz', mobile='+420603123456')
        self.assertEqual(st, 200, got)
        acc = [u for u in self.must('GET', '/api/users')['users'] if u['name'] == 'eva'][0]
        self.assertEqual((acc['mail'], acc['mobile']), ('eva@example.cz', '+420603123456'))

    def test_07_no_admin_second_step_on_the_portal_while_on(self):
        self.contact(mobile='+420603123456')
        self.settings(portal_code='off', portal_local_code='sms', admin_2fa=1)
        try:
            st, got = self.sign_in()
            self.assertEqual(st, 200, got)
            self.assertFalse(got.get('mfa'))
            self.assertEqual(got['gate']['kind'], 'sms')
        finally:
            self.settings(admin_2fa=0)


class Signed(unittest.TestCase):
    def test_contact_signed_once_given(self):
        base = {'name': 'x', 'role': 'portal', 'pw': 'h', 'source': 'local', 'disabled': 0,
                'must_change': 0, 'dn': ''}
        self.assertEqual(EN.account_signed_cols(base), EN.ACCOUNT_SIGNED)
        self.assertEqual(EN.account_signed_cols(dict(base, mail='a@b.cz')),
                         EN.ACCOUNT_SIGNED + ('mail', 'mobile'))

    def test_ways(self):
        self.assertEqual(EN.portal_local_ways({'portal_code': 'sms', 'portal_local_code': 'same'}),
                         ('sms',))
        self.assertEqual(EN.portal_local_ways({'portal_code': 'sms', 'portal_local_code': 'off'}), ())
        self.assertEqual(EN.portal_local_ways({'portal_code': 'off', 'portal_local_code': 'sms_mail'}),
                         ('sms', 'mail'))


    def test_high_security_keeps_the_app(self):
        from unittest import mock
        with mock.patch.dict(EN.CONFIG, {'portal_code': 'sms', 'portal_local_code': 'same'}), \
                mock.patch.object(EN, 'hisec_enforced', return_value=True):
            self.assertEqual(EN.portal_local_ways(), ())
        with mock.patch.dict(EN.CONFIG, {'portal_code': 'sms', 'portal_local_code': 'same'}), \
                mock.patch.object(EN, 'hisec_enforced', return_value=False):
            self.assertEqual(EN.portal_local_ways(), ('sms',))


if __name__ == '__main__':
    unittest.main()
