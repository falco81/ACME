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
    wait_job = TCC.CertsCore.wait_job
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
        # with a directory signing in here, "viewer" alone may be the directory's person
        # (1.0.88): the account of acme's own owns only what is local:viewer's
        self.assertEqual(names, {'of-local-viewer': 'me'})
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


    # ---- the role of the enrolment pages only (1.0.14) ---------------------------------------
    def test_20_enrolment_only_account(self):
        self.py('st.add_account("enrol", "portal", %r, must_change=1); print(1)' % PW)
        try:
            # never into the administration - said as the wrong door
            st, got = self.call('POST', '/api/auth/login', {'name': 'enrol', 'password': PW})
            self.assertEqual(st, 403, got)
            self.assertNotIn('token', got)
            # on the enrolment pages, even with portal_local off
            self.settings(portal_local=0)
            st, got = self.portal_in('enrol')
            self.assertEqual(st, 200, got)
            tok = got['token']
            st, me = self.call('GET', '/api/portal/me', None, tok)
            self.assertEqual((me['me']['role'], me['me']['must_change'], me['me']['sees_all']),
                             ('portal', True, False))
            # nothing until the password is changed - here
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 403)
            st, got = self.call('POST', '/api/portal/password', {'old': 'wrong', 'new': 'x'}, tok)
            self.assertEqual(st, 400, got)
            new = 'Enrol-Own-Pw-2026!'
            st, got = self.call('POST', '/api/portal/password', {'old': PW, 'new': new}, tok)
            self.assertEqual(st, 200, got)
            st, me = self.call('GET', '/api/portal/me', None, tok)
            self.assertFalse(me['me']['must_change'])
            # what it sees: its teams' certificates only
            names, _ = self.certs_of(tok)
            self.assertEqual(names, {})
            self.ok('POST', '/api/teams/save', {'name': 'Enrolers', 'members': ['local:enrol=view']})
            self.ok('POST', '/api/certs/save', {'id': self.ids['of-nobody'], 'owner': 'Enrolers'})
            names, _ = self.certs_of(tok)
            self.assertIn('of-nobody', names)
            # switched off for this role: out, even signed in
            self.settings(portal_enrolers=0)
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 401)
            st, got = self.portal_in('enrol', new)
            self.assertEqual(st, 401, got)
        finally:
            self.settings(portal_local=1, portal_enrolers=1)
            self.py('st.db.run("DELETE FROM accounts WHERE name = \'enrol\'"); print(1)')

    def test_21_enrolment_only_directory_group(self):
        self.settings(admin_directory='corp', admin_group_portal='CERT_USERS',
                      portal_who='groups', portal_groups='CERT_SUPPLIER_X')
        try:
            # in the group of the enrolment pages only, in none of portal_groups: let in
            st, got = self.portal_in('falco', 'falco-password-1')
            self.assertEqual(st, 200, got)
            # and never into the administration, no account made for it
            st, got = self.call('POST', '/api/auth/login',
                                {'name': 'falco', 'password': 'falco-password-1'})
            self.assertEqual(st, 403, got)
            self.assertIsNone(self.py('print(json.dumps(st.account("falco")))'))
            # switched off: the groups above only
            self.settings(portal_enrolers=0)
            st, got = self.portal_in('falco', 'falco-password-1')
            self.assertEqual(st, 403, got)
        finally:
            self.settings(admin_directory='', admin_group_portal='', portal_who='anyone',
                          portal_groups='', portal_enrolers=1)


    def test_22_team_rights_on_the_portal(self):
        """What a team gives on the portal (1.0.16): see only - no changes;
        manage - renew, renewed by itself or not, revoke; approve - its requests."""
        self.py('st.add_account("teamer", "portal", %r); print(1)' % PW)
        self.ok('POST', '/api/teams/save', {'name': 'Ops22', 'members': ['local:teamer=view']})
        a = self.ok('POST', '/api/certs/save', {'name': 'ops22-a', 'names': ['ops22-a.example.test'],
                                                'issuer': 'self', 'key_type': 'ec-256',
                                                'auto_renew': 1, 'owner': 'Ops22'})['id']
        # The renewer may take it first (auto_renew): one job at a time on a certificate (1.0.45).
        st, got = self.call('POST', '/api/certs/renew', {'id': a}, self.admin)
        if st == 200:
            self.wait_job(got['job_id'])
        else:
            self.assertEqual(st, 409, got)
            end = time.time() + 60
            while time.time() < end and self.ok('GET', '/api/certs/one',
                                                args={'id': a})['cert']['state'] != 'ok':
                time.sleep(0.3)
        try:
            st, got = self.portal_in('teamer')
            tok = got['token']
            st, d = self.call('GET', '/api/portal/certs', None, tok)
            one = [r for r in d['rows'] if r['id'] == a][0]
            self.assertEqual(one['may'], ['view'])
            for path, body in (('/api/portal/cert_renew', {'id': a}),
                               ('/api/portal/cert_auto', {'id': a, 'auto_renew': 0}),
                               ('/api/portal/cert_revoke', {'id': a})):
                st, got = self.call('POST', path, body, tok)
                self.assertEqual(st, 403, (path, got))
            # manage
            self.ok('POST', '/api/teams/save', {'name': 'Ops22', 'old_name': 'Ops22',
                                                'members': ['local:teamer=manage']})
            st, d = self.call('GET', '/api/portal/certs', None, tok)
            one = [r for r in d['rows'] if r['id'] == a][0]
            self.assertEqual(one['may'], ['view', 'request', 'manage'])
            self.assertEqual(d['teams'], ['Ops22'])
            st, got = self.call('POST', '/api/portal/cert_auto', {'id': a, 'auto_renew': 0}, tok)
            self.assertEqual(st, 200, got)
            self.assertEqual(self.py('print(st.db.value("SELECT auto_renew FROM certs WHERE id = ?", (%d,)))' % a), 0)
            st, got = self.call('POST', '/api/portal/cert_renew', {'id': a}, tok)
            self.assertEqual(st, 200, got)
            self.assertEqual(self.wait_job(got['job_id'])['state'], 'ok')
            st, got = self.call('POST', '/api/portal/cert_revoke', {'id': a, 'reason': 'superseded'}, tok)
            self.assertEqual(st, 200, got)
            job = self.wait_job(got['job_id'])
            # (a self-signed one cannot be revoked: the job says so - it ran, as the person)
            self.assertEqual((job['kind'], job['by_who']), ('revoke', 'portal:teamer'))
            # approve: a request of the team waiting
            self.settings(portal_cert_suffixes='example.test', portal_cert_issuers='self', portal_cert_auto=0)
            st, r = self.call('POST', '/api/portal/cert_request',
                              {'names': ['ops22-b.example.test'], 'issuer': 'self', 'team': 'Ops22'}, tok)
            self.assertEqual(st, 200, r)
            self.assertTrue(r['waits'])
            self.ok('POST', '/api/teams/save', {'name': 'Ops22', 'old_name': 'Ops22',
                                                'members': ['local:teamer=view']})
            st, got = self.call('POST', '/api/portal/cert_approve', {'id': r['id'], 'ok': 1}, tok)
            self.assertEqual(st, 403, got)
            self.ok('POST', '/api/teams/save', {'name': 'Ops22', 'old_name': 'Ops22',
                                                'members': ['local:teamer=approve']})
            st, got = self.call('POST', '/api/portal/cert_approve', {'id': r['id'], 'ok': 0}, tok)
            self.assertEqual(st, 400, got)          # a decline says why
            # never one's own (1.0.51): someone else approves it
            st, got = self.call('POST', '/api/portal/cert_approve', {'id': r['id'], 'ok': 1}, tok)
            self.assertEqual(st, 403, got)
            self.assertIn('yourself', got['error'])
            got = self.ok('POST', '/api/certs/approve', {'id': r['id'], 'ok': 1})
            self.wait_job(got['job_id'])
        finally:
            self.py('st.db.run("DELETE FROM accounts WHERE name = \'teamer\'"); print(1)')

    # ---- round 1 of 1.0.19 ------------------------------------------------------------------
    def test_30_enrolment_only_second_step_without_portal_local(self):
        """An account of the enrolment pages only signs in with portal_local off - and
        gives its second step there too (it was told it had none to give)."""
        secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
        self.py('st.add_account("enrol30", "portal", %r, must_change=0); '
                'st.set_meta(E.mfa_key("enrol30"), json.dumps({"kind": "app", "at": time.time(), '
                '"secret": E.seal_secret(%r, E.mfa_key("enrol30"))})); print(1)' % (PW, secret))
        self.settings(portal_local=0, admin_2fa=1)
        try:
            st, got = self.portal_in('enrol30')
            self.assertEqual((st, got.get('mfa')), (200, 'check'), got)
            half = got['token']
            st, view = self.call('GET', '/api/portal/mfa', None, half)
            self.assertEqual((st, view.get('stage')), (200, 'check'), view)
            st, done = self.call('POST', '/api/portal/mfa', {'action': 'check',
                                                             'code': totp(secret)}, half)
            self.assertEqual(st, 200, done)
            st, me = self.call('GET', '/api/portal/me', None, done['token'])
            self.assertEqual(me['me']['name'], 'enrol30')
            # an account that may not sign in there gets no second step either
            st, got = self.portal_in('viewer')
            self.assertEqual(st, 401, got)
        finally:
            self.settings(portal_local=1, admin_2fa=0)
            self.py('st.db.run("DELETE FROM accounts WHERE name = \'enrol30\'"); '
                    'st.db.run("DELETE FROM meta WHERE k LIKE \'adm2fa:%\'"); print(1)')

    def test_31_new_password_ends_portal_signins(self):
        """A new password set for an account (Accounts), or its second step reset, ends
        its sign-ins on the enrolment pages too - not those of the directory's person
        of the same name."""
        st, got = self.portal_in('marta', 'Local-Only-Pw-77!')
        self.assertEqual(st, 200, got)
        local = got['token']
        st, got = self.portal_in('marta', 'marta-password-1')
        self.assertEqual(st, 200, got)
        directory = got['token']
        self.ok('POST', '/api/users', {'action': 'password', 'name': 'marta',
                                        'password': 'Local-Only-Pw-77!', 'must_change': 0})
        st, me = self.call('GET', '/api/portal/me', None, local)
        self.assertIsNone(me.get('me'), me)
        st, _ = self.call('GET', '/api/portal/certs', None, local)
        self.assertEqual(st, 401)
        st, me = self.call('GET', '/api/portal/me', None, directory)
        self.assertEqual((me['me'] or {}).get('kind'), 'directory', me)
        st, got = self.portal_in('marta', 'Local-Only-Pw-77!')
        local = got['token']
        self.ok('POST', '/api/users', {'action': 'mfa_reset', 'name': 'marta'})
        st, me = self.call('GET', '/api/portal/me', None, local)
        self.assertIsNone(me.get('me'), me)

    def test_38_own_password_typed_again(self):
        """One's own new password (1.0.98): the one typed again the same as the new one, the
        rules of these accounts, not the one there is now - each said in words; in the
        administration, on the enrolment pages and where an administrator types one in."""
        self.py('st.add_account("pwself", "certadmin", %r, must_change=0); print(1)' % PW)
        try:
            st, got = self.call('POST', '/api/auth/login', {'name': 'pwself', 'password': PW})
            self.assertEqual(st, 200, got)
            tok = got['token']
            new = 'Pw-Self-Own-2026!'
            for body, said in (
                    ({'old': PW, 'new': new, 'again': new + 'x'}, 'typed again are not the same'),
                    ({'old': PW, 'new': 'short', 'again': 'short'}, 'at least eight characters'),
                    ({'old': PW, 'new': PW, 'again': PW}, 'the one you have now'),
                    ({'old': 'wrong-one', 'new': new, 'again': new}, 'is not right')):
                st, got = self.call('POST', '/api/auth/password', body, tok)
                self.assertEqual(st, 400, got)
                self.assertIn(said, got.get('error') or json.dumps(got))
            st, got = self.call('POST', '/api/auth/password', {'old': PW, 'new': new, 'again': new}, tok)
            self.assertEqual(st, 200, got)
            # ...and without "again" (an older page, the API): as before
            st, got = self.call('POST', '/api/auth/password', {'old': new, 'new': PW}, tok)
            self.assertEqual(st, 200, got)
            # the enrolment pages
            st, got = self.portal_in('pwself')
            self.assertEqual(st, 200, got)
            ptok = got['token']
            st, got = self.call('POST', '/api/portal/password', {'old': PW, 'new': new, 'again': new[:-1]}, ptok)
            self.assertEqual(st, 400, got)
            self.assertIn('typed again are not the same', got.get('error') or json.dumps(got))
            # an administrator typing one in for somebody else, and a new account's first one
            st, got = self.call('POST', '/api/users', {'action': 'password', 'name': 'pwself',
                                                       'password': new, 'again': new + '1'}, self.admin)
            self.assertEqual(st, 400, got)
            st, got = self.call('POST', '/api/users', {'action': 'add', 'name': 'pwtwice', 'role': 'readonly',
                                                       'password': new, 'again': 'other-one-1'}, self.admin)
            self.assertEqual(st, 400, got)
            self.assertIn('typed again are not the same', got.get('error') or json.dumps(got))
            self.ok('POST', '/api/users', {'action': 'password', 'name': 'pwself', 'password': new,
                                           'again': new, 'must_change': 0})
        finally:
            for name in ('pwself', 'pwtwice'):
                self.call('POST', '/api/users', {'action': 'delete', 'name': name}, self.admin)

    def test_32_not_approved_is_not_renewed_by_itself(self):
        """A request waiting for approval, or declined, cannot be switched to renew by
        itself (on the portal or in the administration) - the renewer issued it then."""
        self.py('st.add_account("teamer32", "portal", %r); print(1)' % PW)
        self.ok('POST', '/api/teams/save', {'name': 'Ops32', 'members': ['local:teamer32=manage']})
        self.settings(portal_cert_suffixes='example.test', portal_cert_issuers='self',
                      portal_cert_auto=0)
        try:
            st, got = self.portal_in('teamer32')
            tok = got['token']
            st, r = self.call('POST', '/api/portal/cert_request',
                              {'names': ['ops32.example.test'], 'issuer': 'self', 'team': 'Ops32'},
                              tok)
            self.assertEqual(st, 200, r)
            self.assertTrue(r['waits'])
            for state in ('pending-approval', 'declined'):
                self.py('st.db.update("certs", %d, {"state": %r}); print(1)' % (r['id'], state))
                st, got = self.call('POST', '/api/portal/cert_auto',
                                    {'id': r['id'], 'auto_renew': 1}, tok)
                self.assertEqual(st, 400, got)
                self.assertIn('has not been approved', got.get('error', ''))
                st, got = self.call('POST', '/api/certs/auto', {'id': r['id'], 'auto_renew': 1},
                                    self.admin)
                self.assertNotEqual(st, 200, got)
                # and set some other way, the renewer leaves it alone
                why = self.py('from acmelib.certs import renewer, store as S; '
                              'st.db.update("certs", %d, {"auto_renew": 1}); '
                              'print(json.dumps(renewer.main_due(S.cert_get(st, %d))))'
                              % (r['id'], r['id']))
                self.assertEqual(why, '')
            self.assertEqual(self.py('print(json.dumps(st.db.value("SELECT cert_pem FROM certs '
                                     'WHERE id = ?", (%d,))))' % r['id']), None)
        finally:
            self.settings(portal_cert_suffixes='', portal_cert_issuers='')
            self.py('st.db.run("DELETE FROM accounts WHERE name = \'teamer32\'"); print(1)')

    def test_33_a_team_named_as_a_group(self):
        """A certificate of a team is the team's members' only: a group of the directory
        (or a person) of the same name as the team saw it - and could take its key."""
        cid = self.ok('POST', '/api/certs/save', {
            'name': 'of-team33', 'names': ['of-team33.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'CERT_USERS'})['id']
        try:
            # before there is such a team: the group's, as it always was
            st, got = self.portal_in('falco', 'falco-password-1')
            tok = got['token']
            names, _ = self.certs_of(tok)
            self.assertEqual(names.get('of-team33'), 'CERT_USERS')
            # a team of that name, falco not in it: not theirs any more
            self.ok('POST', '/api/teams/save', {'name': 'CERT_USERS',
                                                'members': ['local:viewer=view']})
            names, _ = self.certs_of(tok)
            self.assertNotIn('of-team33', names)
            st, _ = self.call('POST', '/api/portal/cert_download',
                              {'id': cid, 'format': 'cert-pem'}, tok)
            self.assertEqual(st, 404)
            # a person of the name too
            self.ok('POST', '/api/teams/save', {'name': 'falco', 'members': ['local:viewer=view']})
            self.ok('POST', '/api/certs/save', {'id': cid, 'owner': 'falco'})
            names, _ = self.certs_of(tok)
            self.assertNotIn('of-team33', names)
            # the team's member does
            st, got = self.portal_in('viewer')
            names, _ = self.certs_of(got['token'])
            self.assertEqual(names.get('of-team33'), 'falco')
            # falco a member: theirs again, through the team
            self.ok('POST', '/api/teams/save', {'name': 'falco', 'old_name': 'falco',
                                                'members': ['falco=view']})
            names, _ = self.certs_of(tok)
            self.assertEqual(names.get('of-team33'), 'falco')
        finally:
            self.ok('POST', '/api/certs/save', {'id': cid, 'owner': ''})
            for t in ('CERT_USERS', 'falco'):
                self.call('POST', '/api/teams/delete', {'name': t}, self.admin)
            self.call('POST', '/api/certs/delete', {'id': cid}, self.admin)

    def test_34_a_long_name_is_cut(self):
        """A name of megabytes on the enrolment pages' sign-in went whole into the log and
        to the directory; cut at 190 characters as the administration's is."""
        st, got = self.portal_in('long34' + 'x' * 20000, 'nope')
        self.assertEqual(st, 401, got)
        words = [w for w in self.events('long34xxxx') if 'enrolment pages' in w]
        self.assertTrue(words)
        self.assertTrue(all(len(w) < 600 for w in words), [len(w) for w in words])

    def test_35_wrong_password_counts_with_the_directory_down(self):
        """A wrong password of an account here counts as one when the directory then
        cannot be reached: every guess was given back with the 503, without end."""
        import socket
        sk = socket.socket()
        sk.bind(('127.0.0.1', 0))
        dead = sk.getsockname()[1]
        sk.close()
        made = self.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'dead35', 'hosts': '127.0.0.1', 'port': dead, 'tls': 'none', 'verify': 0,
            'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        self.settings(portal_directory='dead35')
        try:
            for _ in range(3):
                st, got = self.portal_in('viewer', 'not-the-password')
                self.assertEqual(st, 503, got)
            st, got = self.portal_in('viewer', 'not-the-password')
            self.assertEqual(st, 429, got)
            # the right password is still paused, as with the directory there
            st, got = self.portal_in('viewer')
            self.assertEqual(st, 429, got)
        finally:
            self.settings(portal_directory='corp')
            self.must('POST', '/api/directories', {'action': 'delete', 'id': made['id']})


    def test_36_directory_person_asked_again(self):
        """A person of the directory out of the groups that let them in: the
        sign-in ends at the next look (every ten minutes), not when it runs out."""
        st, got = self.portal_in('falco', 'falco-password-1')
        self.assertEqual(st, 200, got)
        tok = got['token']
        self.settings(portal_who='groups', portal_groups='CERT_SUPPLIER_X')
        try:
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 200)                       # asked again only after 10 min
            self.py("""
for r in st.db.rows("SELECT id, data FROM sessions WHERE kind = 'portal'"):
    d = json.loads(r['data'] or '{}')
    if d.get('dir_checked'):
        d['dir_checked'] = time.time() - 3600
        st.db.run('UPDATE sessions SET data = ? WHERE id = ?', (json.dumps(d), r['id']))
print(1)""")
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 401)
        finally:
            self.settings(portal_who='anyone', portal_groups='')

    def test_37_key_only_for_its_owner_or_who_manages(self):
        """A member who may only see a team's certificate gets no PFX with its key."""
        self.settings(portal_cert_keys=1)
        self.py('st.add_account("seer", "portal", %r); print(1)' % PW)
        self.ok('POST', '/api/teams/save', {'name': 'Seers', 'members': ['local:seer=view']})
        cid = self.ok('POST', '/api/certs/save', {'name': 'seen37', 'names': ['seen37.example.test'],
                                                  'issuer': 'self', 'key_type': 'ec-256',
                                                  'auto_renew': 0, 'owner': 'Seers'})['id']
        self.wait_job(self.ok('POST', '/api/certs/renew', {'id': cid})['job_id'])
        try:
            st, got = self.portal_in('seer')
            tok = got['token']
            st, d = self.call('GET', '/api/portal/certs', None, tok)
            one = [r for r in d['rows'] if r['id'] == cid][0]
            self.assertNotIn('pfx', one['formats'])
            st, got = self.call('POST', '/api/portal/cert_download',
                                {'id': cid, 'format': 'pfx', 'password': 'Long-enough-1'}, tok)
            self.assertIn(st, (400, 403), got)
            self.ok('POST', '/api/teams/save', {'name': 'Seers', 'old_name': 'Seers',
                                                'members': ['local:seer=manage']})
            st, got = self.call('POST', '/api/portal/cert_download',
                                {'id': cid, 'format': 'pfx', 'password': 'Long-enough-1'}, tok)
            self.assertEqual(st, 200, got)
        finally:
            self.settings(portal_cert_keys=0)
            self.py('st.db.run("DELETE FROM accounts WHERE name = \'seer\'"); print(1)')


if __name__ == '__main__':
    unittest.main(verbosity=2)
