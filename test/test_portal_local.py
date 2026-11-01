#!/usr/bin/env python3
"""acme's own accounts on the certificate portal, and who sees which certificate.

    python3 test/test_portal_local.py      (or python3 -m unittest test.test_portal_local)

A real daemon in a folder of its own (test/test_certs_core.py's way) and a
directory that is not there (test/mockldap.py). With portal_local on, an
account of Settings → Accounts signs in on the enrolment pages: its password,
its second step as the administration's (an app's code), the pause after
wrong passwords, refused when switched off. With portal_admins_all a
certificate administrator sees every certificate, a reader only the ones it
owns (its name, or local:NAME); the directory's people see what they did.
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import mockldap                      # noqa: E402

PW = 'Test-Password-4711!'
BASE = 'DC=corpnet,DC=loc'


def totp(secret_b32, when=None):
    s = secret_b32.replace(' ', '').upper()
    key = base64.b32decode(s + '=' * (-len(s) % 8))
    step = int((when or time.time()) // 30)
    mac = hmac.new(key, struct.pack('>Q', step), hashlib.sha1).digest()
    o = mac[-1] & 15
    return '%06d' % ((struct.unpack('>I', mac[o:o + 4])[0] & 0x7fffffff) % 1000000)


class PortalLocal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    py = TCC.CertsCore.py

    @classmethod
    def setUpClass(cls):
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.py_static('st.add_account("cadm", "certadmin", %r); '
                      'st.add_account("offacc", "readonly", %r); '
                      'st.set_account("offacc", disabled=1); '
                      'st.add_account("marta", "readonly", "Local-Only-Pw-77!"); print(1)'
                      % (PW, PW))
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_directory': 'corp',
            'portal_tries': 3, 'portal_wait_min': 5}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.ids = {}
        for name, owner in (('of-viewer', 'viewer'), ('of-local-viewer', 'local:viewer'),
                            ('of-falco', 'falco'), ('of-group', 'group:CERT_USERS'),
                            ('of-nobody', '')):
            cls.ids[name] = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': owner})['id']

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def py_static(cls, code):
        import subprocess
        head = ('import sys, json, time; sys.path.insert(0, %r); import acme; '
                'from acmelib import engine as E; acme.load_config(); '
                'st = acme.Storage(acme.open_db()); E.HA_STORE["store"] = st; '
                'E.load_config(saved=st.settings_saved())\n' % ROOT)
        got = subprocess.run([sys.executable, '-c', head + code], env=cls.env,
                             capture_output=True, text=True, timeout=180)
        if got.returncode:
            raise RuntimeError(got.stderr[-3000:])
        return json.loads(got.stdout.strip().splitlines()[-1])

    def setUp(self):
        # Every test from one address: the pause of one never reaches the next.
        self.call('POST', '/api/lockouts', {'action': 'clear_all'}, self.admin)

    def settings(self, **kw):
        self.ok('POST', '/api/settings', {'settings': kw})

    def portal_in(self, name, password=PW):
        return self.call('POST', '/api/portal/login', {'name': name, 'password': password})

    def certs_of(self, token):
        st, got = self.call('GET', '/api/portal/certs', None, token)
        self.assertEqual(st, 200, got)
        return {r['name']: r['via'] for r in got['rows']}, got

    def events(self, text):
        got = self.ok('GET', '/api/events', args={'q': text})
        return [e.get('words') or '' for e in got.get('events') or got.get('rows') or []]

    # ---- signing in -----------------------------------------------------------------------
    def test_01_local_without_second_step(self):
        st, got = self.portal_in('viewer')
        self.assertEqual(st, 200, got)
        self.assertEqual((got['kind'], got['mfa']), ('local', ''))
        st, me = self.call('GET', '/api/portal/me', None, got['token'])
        self.assertEqual((me['me']['kind'], me['me']['role'], me['me']['sees_all']),
                         ('local', 'readonly', False))
        self.assertTrue(any('viewer signed in to the enrolment pages' in w
                            for w in self.events('enrolment pages')))

    def test_02_off_by_default_and_when_switched_off(self):
        self.assertEqual(self.py('print(json.dumps([E.DEFAULTS["portal_local"], '
                                 'E.DEFAULTS["portal_admins_all"]]))'), [0, 1])
        self.settings(portal_local=0)
        try:
            st, got = self.portal_in('viewer')
            self.assertEqual(st, 401, got)
        finally:
            self.settings(portal_local=1)
        st, got = self.portal_in('viewer')
        tok = got['token']
        self.settings(portal_local=0)
        try:
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 401)
        finally:
            self.settings(portal_local=1)

    def test_03_disabled_account(self):
        st, got = self.portal_in('offacc')
        self.assertEqual(st, 401, got)
        self.assertNotIn('token', got)
        self.assertTrue(any('offacc, switched off, tried to sign in to the enrolment pages' in w
                            for w in self.events('switched off')))
        # Switched off while signed in: the sign-in ends.
        st, got = self.portal_in('viewer')
        tok = got['token']
        self.py('st.set_account("viewer", disabled=1); print(1)')
        try:
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 401)
        finally:
            self.py('st.set_account("viewer", disabled=0); print(1)')

    def test_04_wrong_password_pause(self):
        for _ in range(3):
            st, got = self.portal_in('viewer', 'not-the-password')
            self.assertEqual(st, 401, got)
        st, got = self.portal_in('viewer')
        self.assertEqual(st, 429, got)
        self.call('POST', '/api/lockouts', {'action': 'clear_all'}, self.admin)
        st, got = self.portal_in('viewer')
        self.assertEqual(st, 200, got)

    def test_05_second_step(self):
        secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
        self.py('st.set_meta(E.mfa_key("cadm"), json.dumps({"kind": "app", "at": time.time(), '
                '"secret": E.seal_secret(%r, E.mfa_key("cadm"))})); print(1)' % secret)
        self.settings(admin_2fa=1)
        try:
            st, got = self.portal_in('cadm')
            self.assertEqual((st, got.get('mfa')), (200, 'check'), got)
            half = got['token']
            # Until it is given the sign-in does nothing else.
            st, _ = self.call('GET', '/api/portal/certs', None, half)
            self.assertEqual(st, 401)
            st, me = self.call('GET', '/api/portal/me', None, half)
            self.assertEqual((me['me'], me['mfa']), (None, 'check'))
            st, view = self.call('GET', '/api/portal/mfa', None, half)
            self.assertEqual((st, view['stage'], view['kind']), (200, 'check', 'app'), view)
            st, bad = self.call('POST', '/api/portal/mfa', {'action': 'check', 'code': '000000'
                                                            if totp(secret) != '000000'
                                                            else '111111'}, half)
            self.assertEqual(st, 400, bad)
            st, done = self.call('POST', '/api/portal/mfa', {'action': 'check',
                                                             'code': totp(secret)}, half)
            self.assertEqual(st, 200, done)
            self.assertTrue(done['done'])
            full = done['token']
            st, _ = self.call('GET', '/api/portal/me', None, half)
            self.assertIsNone(_.get('me'))            # the half one is ended
            names, d = self.certs_of(full)
            self.assertTrue(d['sees_all'])
            # A reader without a second step set up: it sets one up first.
            st, got = self.portal_in('viewer')
            self.assertEqual(got.get('mfa'), 'enrol', got)
            st, view = self.call('GET', '/api/portal/mfa', None, got['token'])
            self.assertEqual(view['stage'], 'enrol')
            st, start = self.call('POST', '/api/portal/mfa', {'action': 'enrol_start',
                                                              'kind': 'app'}, got['token'])
            self.assertEqual(st, 200, start)
            st, done = self.call('POST', '/api/portal/mfa', {
                'action': 'enrol_confirm', 'code': totp(start['secret'])}, got['token'])
            self.assertEqual(st, 200, done)
            # The administration's own sign-in asks the same way now.
            st, adm = self.call('POST', '/api/auth/login', {'name': 'viewer', 'password': PW})
            self.assertEqual(adm.get('mfa'), 'check', adm)
            # A sign-in of the directory has no second step to give here.
            st, dgot = self.portal_in('falco', 'falco-password-1')
            self.assertEqual((st, dgot.get('mfa')), (200, None), dgot)
            st, _ = self.call('GET', '/api/portal/mfa', None, dgot['token'])
            self.assertEqual(st, 401)
        finally:
            self.settings(admin_2fa=0)
            self.py('st.db.run("DELETE FROM meta WHERE k LIKE \'adm2fa:%\'"); print(1)')

    # ---- who sees what --------------------------------------------------------------------
    def test_10_owner_only_for_a_reader(self):
        st, got = self.portal_in('viewer')
        names, d = self.certs_of(got['token'])
        self.assertEqual(names, {'of-viewer': 'me', 'of-local-viewer': 'me'})
        self.assertFalse(d['sees_all'])
        self.assertEqual(d['kind'], 'local')
        st, _ = self.call('POST', '/api/portal/cert_download',
                          {'id': self.ids['of-falco'], 'format': 'cert-pem'}, got['token'])
        self.assertEqual(st, 404)

    def test_11_admins_see_all(self):
        st, got = self.portal_in('cadm')
        self.assertEqual(st, 200, got)
        names, d = self.certs_of(got['token'])
        self.assertTrue(d['sees_all'])
        self.assertEqual(set(names), set(self.ids))
        self.assertEqual(set(names.values()), {'*'})
        st, job = self.call('GET', '/api/portal/cert_job', None, got['token'],
                            {'id': 999999})
        self.assertEqual(st, 404)
        self.settings(portal_admins_all=0)
        try:
            names, d = self.certs_of(got['token'])
            self.assertEqual(names, {})
            self.assertFalse(d['sees_all'])
        finally:
            self.settings(portal_admins_all=1)
        # The role as it is now: made a reader, it sees its own only.
        self.py('st.set_account("cadm", role="readonly"); print(1)')
        try:
            names, d = self.certs_of(got['token'])
            self.assertFalse(d['sees_all'])
        finally:
            self.py('st.set_account("cadm", role="certadmin"); print(1)')

    def test_12_directory_people_unchanged(self):
        st, got = self.portal_in('falco', 'falco-password-1')
        self.assertEqual(st, 200, got)
        st, me = self.call('GET', '/api/portal/me', None, got['token'])
        self.assertEqual((me['me']['kind'], me['me']['sees_all']), ('directory', False))
        names, d = self.certs_of(got['token'])
        self.assertEqual(names, {'of-falco': 'me', 'of-group': 'CERT_USERS'})
        # A name both here and in the directory: the account here's password signs
        # in here, the directory's goes on to the directory.
        st, got = self.portal_in('marta', 'marta-password-1')
        self.assertEqual(st, 200, got)
        st, me = self.call('GET', '/api/portal/me', None, got['token'])
        self.assertEqual(me['me']['kind'], 'directory')
        st, got = self.portal_in('marta', 'Local-Only-Pw-77!')
        st, me = self.call('GET', '/api/portal/me', None, got['token'])
        self.assertEqual(me['me']['kind'], 'local')
        # Without portal_local the account here is not asked at all.
        self.settings(portal_local=0)
        try:
            st, got = self.portal_in('marta', 'Local-Only-Pw-77!')
            self.assertEqual(st, 401)
            st, got = self.portal_in('falco', 'falco-password-1')
            self.assertEqual(st, 200)
        finally:
            self.settings(portal_local=1)

    def test_13_asked_for_by_an_account_here(self):
        self.settings(portal_cert_suffixes='example.test', portal_cert_issuers='self')
        st, got = self.portal_in('viewer')
        tok = got['token']
        st, r = self.call('POST', '/api/portal/cert_request',
                          {'names': ['asked.example.test'], 'issuer': 'self'}, tok)
        self.assertEqual(st, 200, r)
        owner = self.py('print(json.dumps(st.db.value("SELECT owner FROM certs WHERE id = ?", '
                        '(%d,))))' % r['id'])
        self.assertEqual(owner, 'local:viewer')
        names, d = self.certs_of(tok)
        self.assertEqual(names.get(r['name']), 'me')
        self.assertEqual(d['used'], 1)
        # Not the directory's person of the same name.
        st, got = self.portal_in('falco', 'falco-password-1')
        names, _ = self.certs_of(got['token'])
        self.assertNotIn(r['name'], names)


if __name__ == '__main__':
    unittest.main(verbosity=2)
