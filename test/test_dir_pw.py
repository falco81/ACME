#!/usr/bin/env python3
"""Wrong directory passwords per person (as otp 1.0.230, 1.0.232, 1.0.234).

    python3 test/test_dir_pw.py      (or python3 -m unittest test.test_dir_pw)

A directory password is tried at each sign-in of an administrator from the directory and at
each sign-in to the enrolment pages (the certificate portal). With dir_pw_tries set, after so
many wrong ones for one person within dir_pw_window_min - from anywhere, on any node - the
directory is no longer asked for that person: counted by the account the directory resolves
(novak, novak@corp.cz and CORP\\novak are one), a name the directory lacks held back the same
way, the right password not counted, an empty one never asked. Each directory its own cap or
the setting's; the domain's lockout and password policy read and a cap recommended.

Part one in this process (the arithmetic), part two against a real daemon and a directory
that is not there (test/mockldap.py).
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix='acme-dirpw-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE


class FakeH(object):
    """What dir_pw_take asks of a request: its store, and failed()."""
    def __init__(self):
        self.store = STORE
        self.failed_n = 0

    def failed(self, key):
        self.failed_n += 1


class TestCountedBy(unittest.TestCase):
    def setUp(self):
        # The cap goes with "Block a place that keeps guessing" (as otp 1.0.241).
        E.CONFIG['login_guard'] = 1
        E.CONFIG['dir_pw_tries'] = 0
        E.CONFIG['dir_pw_window_min'] = 30
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'adpw:%' OR k = 'dirpw:conf'")

    def test_one_person_whatever_the_spelling(self):
        names = ['novak', 'NOVAK', 'CORP\\novak', 'novak@corp.cz', ' Novak ']
        self.assertEqual({E.dir_pw_who(n) for n in names}, {'novak'})
        dn = 'CN=Jan Novak,OU=People,DC=corp,DC=loc'
        # By the account the directory resolves: its first part and a hash of the DN.
        a = E.dir_pw_who('novakj', {'dn': dn})
        b = E.dir_pw_who('jan.novak@corp.cz', {'dn': dn.upper()})
        self.assertEqual(a, b)
        self.assertTrue(a.startswith('jan novak#'))
        self.assertNotEqual(a, E.dir_pw_who('x', {'dn': 'CN=Other,DC=corp,DC=loc'}))

    def test_off_by_default(self):
        self.assertEqual(E.DEFAULTS['dir_pw_tries'], 0)
        h = FakeH()
        for _ in range(20):
            self.assertEqual(E.dir_pw_take(h, 'novak', 'corp'), '')

    def test_the_cap_and_a_place_given_back(self):
        E.CONFIG['dir_pw_tries'] = 3
        h = FakeH()
        entry = {'dn': 'CN=Jan Novak,DC=corp,DC=loc'}
        # A right password gives its place back: never counted.
        for _ in range(10):
            E.dir_pw_done(h, E.dir_pw_take(h, 'novak', 'corp', entry), False)
        for _ in range(3):
            E.dir_pw_done(h, E.dir_pw_take(h, 'novak', 'corp', entry), True)
        with self.assertRaises(E.ApiError) as e:
            E.dir_pw_take(h, 'jan.novak@corp.cz', 'corp', entry)
        self.assertEqual(e.exception.status, 429)
        # The address's count keeps its place too (otp 1.0.234).
        self.assertEqual(h.failed_n, 1)
        # Another directory's novak is somebody else.
        self.assertTrue(E.dir_pw_take(FakeH(), 'novak', 'other', entry))

    def test_seen_and_cleared_under_locked_out(self):
        E.CONFIG['dir_pw_tries'] = 2
        h = FakeH()
        for _ in range(2):
            E.dir_pw_done(h, E.dir_pw_take(h, 'ghost', 'corp'), True)
        rows = [r for r in E.lockouts_shared(STORE) if r['kind'] == 'dir-passwords']
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]['who'], rows[0]['fails'], rows[0]['limit'], rows[0]['locked']),
                         ('ghost|corp', 2, 2, True))
        self.assertIn('(corp)', rows[0]['what'])
        self.assertTrue(E.lockouts_shared_clear(STORE, 'dir-passwords', rows[0]['who'], 'test'))
        self.assertFalse([r for r in E.lockouts_shared(STORE) if r['kind'] == 'dir-passwords'])
        self.assertTrue(E.dir_pw_take(h, 'ghost', 'corp'))

    def test_each_directory_its_own(self):
        E.CONFIG['dir_pw_tries'] = 3
        STORE.db.run('DELETE FROM directories')
        STORE._dirs = None
        for n in ('corp', 'other'):
            STORE.directory_save({'name': n, 'hosts': 'dc.example.loc', 'base': 'DC=example,DC=loc',
                                  'tls': 'ldaps', 'port': 636, 'verify': 1}, 'test')
        said = E.dir_pw_caps_set(STORE, {'corp': {'tries': 5, 'window_min': 10},
                                         'other': {'tries': 0}}, 'test')
        self.assertEqual(len(said), 2)
        self.assertEqual(E.dir_pw_cap_of(STORE, 'corp'), (5, 600))
        self.assertEqual(E.dir_pw_cap_of(STORE, 'other')[0], 0)
        self.assertEqual(E.dir_pw_cap_of(STORE, 'third'), (3, 1800))
        # Back to the setting.
        E.dir_pw_caps_set(STORE, {'other': {'tries': None}}, 'test')
        self.assertEqual(E.dir_pw_cap_of(STORE, 'other'), (3, 1800))
        for bad in ({'corp': {'tries': 101}}, {'corp': {'window_min': 0}}, {'nope': {'tries': 1}},
                    {'corp': {'tries': 'x'}}, []):
            with self.assertRaises(ValueError):
                E.dir_pw_caps_set(STORE, bad, 'test')
        # Renamed, the directory keeps its cap; taken away, the cap goes with it.
        one = [d for d in STORE.directories() if d['name'] == 'corp'][0]
        STORE.directory_save(dict(one, name='corp2', bind_pw=None), 'test')
        self.assertEqual(E.dir_pw_cap_of(STORE, 'corp2'), (5, 600))
        STORE.directory_drop(one['id'])
        self.assertNotIn('corp2', E.dir_pw_caps(STORE))
        listed = E.dir_pw_caps_list(STORE)
        self.assertEqual([d['name'] for d in listed['directories']], ['other'])
        self.assertTrue(listed['in_use'])

    def test_old_counts_tidied(self):
        STORE.set_meta('adpw:old@@n1', json.dumps([time.time() - 7200]))
        STORE.set_meta('adpw:new@@n1', json.dumps([time.time()]))
        E.adpw_tidy(STORE)
        self.assertIsNone(STORE.get_meta('adpw:old@@n1'))
        self.assertIsNotNone(STORE.get_meta('adpw:new@@n1'))


class TestPolicy(unittest.TestCase):
    def test_recommend(self):
        r = E.policy_recommend({'lockout': {'threshold': 5, 'window_s': 1800}})
        self.assertEqual((r['tries'], r['window_min'], r['from']), (3, 30, 'the domain'))
        # The lowest threshold of the domain and its fine-grained policies, the longest window.
        r = E.policy_recommend({'lockout': {'threshold': 10, 'window_s': 900},
                                'psos': [{'name': 'Admins', 'threshold': 3, 'window_s': 3600}]})
        self.assertEqual((r['tries'], r['window_min'], r['threshold']), (2, 60, 3))
        self.assertIn('Admins', r['why'])
        r = E.policy_recommend({'lockout': {'threshold': 0}})
        self.assertEqual((r['tries'], r['threshold']), (10, 0))
        r = E.policy_recommend({'lockout': {'threshold': 1, 'window_s': 600}})
        self.assertEqual(r['tries'], 1)

    def test_ad_spans(self):
        self.assertEqual(E._ad_span('-18000000000'), 1800.0)
        self.assertEqual(E._ad_span('0', zero_is='manual'), 'manual')
        self.assertEqual(E._ad_span('-9223372036854775808'), 'never')
        self.assertIsNone(E._ad_span('x'))

    def test_read_from_the_directory(self):
        ad = E.Directory({'name': 'corp', 'hosts': 'dc', 'base': 'OU=People,DC=corp,DC=loc'})
        self.assertEqual(ad.domain_dn(), 'DC=corp,DC=loc')
        answers = [
            [{'dn': 'DC=corp,DC=loc', 'attrs': {
                'name': ['corp'], 'lockoutThreshold': ['5'], 'lockOutObservationWindow': ['-18000000000'],
                'lockoutDuration': ['0'], 'minPwdLength': ['12'], 'pwdHistoryLength': ['24'],
                'maxPwdAge': ['-36288000000000'], 'minPwdAge': ['-864000000000'], 'pwdProperties': ['1']}}],
            [{'dn': 'CN=Admins PSO,CN=Password Settings Container,CN=System,DC=corp,DC=loc', 'attrs': {
                'name': ['Admins PSO'], 'msDS-PasswordSettingsPrecedence': ['1'],
                'msDS-LockoutThreshold': ['3'], 'msDS-LockoutObservationWindow': ['-36000000000'],
                'msDS-PSOAppliesTo': ['CN=Domain Admins,CN=Users,DC=corp,DC=loc']}}]]
        ad.asked = lambda fn: answers.pop(0)
        pol = ad.policy()
        self.assertEqual(pol['lockout'], {'threshold': 5, 'window_s': 1800.0, 'duration_s': 'manual'})
        self.assertEqual((pol['password']['min_length'], pol['password']['complex']), (12, True))
        self.assertEqual(pol['psos'][0]['name'], 'Admins PSO')
        self.assertEqual(pol['psos'][0]['applies'], ['Domain Admins'])
        self.assertEqual((pol['recommend']['tries'], pol['recommend']['window_min']), (2, 60))

    def test_not_asked_is_not_counted(self):
        ad = E.Directory({'name': 'corp', 'hosts': 'dc', 'base': 'DC=corp,DC=loc'})
        for entry, pw in (({'dn': 'CN=x'}, ''), ({'dn': ''}, 'pw'), ({'dn': 'CN=x'}, 'a\x00b')):
            with self.assertRaises(E.LdapNotAsked):
                ad.password_ok(entry, pw)


class TestCardInABrowser(unittest.TestCase):
    """The card of Settings -> Accounts, drawn in a page of its own (test/dir_caps_page.js)."""

    def test_card(self):
        import shutil
        import subprocess
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(HERE, 'dir_caps_page.js'), os.path.join(ROOT, 'web')],
                             capture_output=True, text=True, timeout=180)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


# ---- against a daemon ------------------------------------------------------------------------
try:
    import test_certs_core as TCC        # noqa: E402
    import mockldap                      # noqa: E402
except Exception:                        # noqa: BLE001
    TCC = None

BASE = 'DC=corpnet,DC=loc'


@unittest.skipIf(TCC is None, 'no test daemon here')
class TestSignIns(unittest.TestCase):
    """Through the pages: the administrators' sign-in and the enrolment pages'."""

    @classmethod
    def setUpClass(cls):
        cls.ldap_port, cls.ldap_stop = mockldap.serve(0)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.ldap_port, 'tls': 'none',
            'verify': 0, 'base': BASE, 'bind_dn': 'CN=isemon,OU=Service,' + BASE,
            'bind_pw': 'the-service-password', 'enabled': 1}})
        cls.must('POST', '/api/settings', {'settings': {
            'admin_directory': 'corp', 'admin_group_full': 'CERT_USERS',
            'portal': 1, 'portal_directory': 'corp', 'portal_tries': 50, 'login_tries': 50,
            'dir_pw_tries': 2, 'dir_pw_window_min': 30,
            # The cap goes with the guard of places (as otp 1.0.241); its own limits out of the way.
            'login_guard': 1, 'login_guard_tries': 10000, 'login_guard_names': 0}})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)
        cls.ldap_stop.set()

    call = TCC.CertsCore.__dict__['call'] if TCC else None
    login = TCC.CertsCore.__dict__['login'] if TCC else None

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def setUp(self):
        self.call('POST', '/api/lockouts', {'action': 'clear_all'}, self.admin)
        self.call('POST', '/api/directories', {'action': 'pw_caps_save', 'caps': {'corp': {'tries': None}}},
                  self.admin)

    def admin_in(self, name, pw):
        return self.call('POST', '/api/auth/login', {'name': name, 'password': pw})[0]

    def portal_in(self, name, pw):
        return self.call('POST', '/api/portal/login', {'name': name, 'password': pw})[0]

    def test_01_admin_cap_by_account(self):
        self.assertEqual(self.admin_in('falco', 'falco-password-1'), 200)
        self.assertEqual(self.admin_in('falco', 'wrong-1'), 401)
        self.assertEqual(self.admin_in('falco@corpnet.cz', 'wrong-2'), 401)
        # The cap of 2 reached by both spellings together: the directory is not asked -
        # the right password too waits.
        self.assertEqual(self.admin_in('CORPNET\\falco', 'falco-password-1'), 429)
        st, got = self.call('GET', '/api/lockouts', None, self.admin)
        shared = [n for n in got['nodes'] if n.get('shared')][0]['rows']
        row = [r for r in shared if r['kind'] == 'dir-passwords']
        self.assertEqual(len(row), 1, shared)
        self.assertTrue(row[0]['locked'])
        st, _ = self.call('POST', '/api/lockouts', {'action': 'clear', 'kind': 'dir-passwords',
                                                     'who': row[0]['who']}, self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(self.admin_in('falco', 'falco-password-1'), 200)

    def test_02_unknown_names_held_back_alike(self):
        for _ in range(2):
            self.assertEqual(self.admin_in('nobody-at-all', 'whatever-1'), 401)
        self.assertEqual(self.admin_in('nobody-at-all', 'whatever-1'), 429)
        # A switched off account is a wrong password too (otp 1.0.235).
        for _ in range(2):
            self.assertEqual(self.admin_in('gone', 'gone-password-1'), 401)
        self.assertEqual(self.admin_in('gone', 'gone-password-1'), 429)

    def test_03_portal_counts_with_the_administrators(self):
        self.assertEqual(self.portal_in('marta', 'wrong-1'), 401)
        self.assertEqual(self.admin_in('marta@corpnet.cz', 'wrong-2'), 401)
        self.assertEqual(self.portal_in('marta', 'marta-password-1'), 429)

    def test_04_its_own_cap(self):
        st, got = self.call('POST', '/api/directories', {'action': 'pw_caps_save',
                                                          'caps': {'corp': {'tries': 0}}}, self.admin)
        self.assertEqual((st, got.get('message')), (200, 'saved'), got)
        for _ in range(4):
            self.assertEqual(self.portal_in('nested', 'wrong'), 401)
        st, got = self.call('POST', '/api/directories', {'action': 'pw_caps'}, self.admin)
        self.assertEqual(st, 200)
        self.assertEqual(got['directories'][0]['tries'], 0)
        self.assertEqual(got['setting'], {'tries': 2, 'window_min': 30})

    def test_05_empty_password_never_counted(self):
        for _ in range(5):
            self.assertIn(self.portal_in('outsider', ''), (400, 401))
        self.assertNotEqual(self.portal_in('outsider', 'outsider-password-1'), 429)

    def test_06_a_persons_attributes(self):
        # Every attribute of one person, for where the e-mail and the mobile are read (otp 1.0.229).
        st, d = self.call('GET', '/api/directories', None, self.admin)
        ident = d['directories'][0]['id']
        st, got = self.call('POST', '/api/directories', {'action': 'sample', 'user': 'falco',
                                                          'directory': {'id': ident}}, self.admin)
        self.assertEqual(st, 200, got)
        self.assertIn('falco', got['dn'].lower())
        names = {a['name'].lower(): a for a in got['attrs']}
        self.assertIn('userprincipalname', names)
        self.assertTrue(names['userprincipalname']['mail'])        # can hold an address
        self.assertFalse(names['samaccountname']['mail'])


if __name__ == '__main__':
    unittest.main()
