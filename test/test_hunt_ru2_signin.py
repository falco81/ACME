"""Hunt R, run u2, area sign-in: regressions.

    python3 test/test_hunt_ru2_signin.py

- The password asked again before a passkey is added (pk_password_again), for an account of the
  directory: a wrong one went out as the directory sign-in's 401, uncounted - any number of
  guesses at the owner's directory password from a session left open.
- A role group named by its sAMAccountName (cn "Cert Admins", sAMAccountName "cert-admins"):
  group_matches looked at it only when the name was also the cn of a group held, so nobody got
  its role.
- The directory away (503), a keytab or a CRL not to be had: counted as wrong passwords and by
  "Block a place that keeps guessing" - which says such refusals are not counted - so an office
  signing in rightly during an outage was locked out and its address blocked.
"""
import collections
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-ru2-signin-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402
from acmelib import engine as EN  # noqa: E402

STORE = E.Storage(E.open_db())
EN.HA_STORE['store'] = STORE


class D(object):
    def __init__(self):
        self.login_fails = collections.defaultdict(list)
        self.login_info = {}
        self.store = STORE
        self.dirs = {}


def handler(d, body=None, ip='192.0.2.5'):
    h = E.ApiHandler.__new__(E.ApiHandler)
    h.server = type('S', (), {'daemon': d})()
    h.headers = {}
    h.client_address = (ip, 1)
    h._body = dict(body or {})
    h._held = None
    h._failed = False
    h._guard = None
    return h


def run(h, fn, *a):
    """One request: the route, then what the server does after it (_release)."""
    try:
        return fn(h, *a)
    finally:
        h._release()


def counted(d):
    return sum(len(v) for v in d.login_fails.values())


class Patched(unittest.TestCase):
    def setUp(self):
        self.saved_conf = dict(EN.CONFIG)
        self.saved = {}

    def patch(self, name, value):
        if name not in self.saved:
            self.saved[name] = getattr(EN, name)
        setattr(EN, name, value)

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(EN, k, v)
        EN.CONFIG.clear()
        EN.CONFIG.update(self.saved_conf)


class PasswordAgainForAPasskey(Patched):
    def test_wrong_directory_password_counted_and_said(self):
        EN.CONFIG['admin_directory'] = 'corp'

        def refused(h, name, password):
            raise E.ApiError(401, 'the name or the password is not right')
        self.patch('admin_from_directory', refused)
        d = D()
        acc = {'name': 'jnovak', 'source': 'directory'}
        said = []
        for i in range(8):
            try:
                run(handler(d), EN.pk_password_again, acc, 'guess-%d' % i)
            except E.ApiError as e:
                said.append(e.status)
        # 400 (never the 401 the page takes for "signed out"), then the pause after five.
        self.assertEqual(said[:5], [400] * 5)
        self.assertEqual(set(said[5:]), {429})

    def test_directory_away_said_as_it_is(self):
        EN.CONFIG['admin_directory'] = 'corp'

        def away(h, name, password):
            raise E.ApiError(503, 'the directory cannot be reached')
        self.patch('admin_from_directory', away)
        d = D()
        with self.assertRaises(E.ApiError) as e:
            run(handler(d), EN.pk_password_again, {'name': 'jnovak', 'source': 'directory'}, 'x')
        self.assertEqual(e.exception.status, 503)

    def test_right_password_passes(self):
        EN.CONFIG['admin_directory'] = 'corp'
        self.patch('admin_from_directory', lambda h, n, p: {'name': 'JNovak'})
        d = D()
        run(handler(d), EN.pk_password_again, {'name': 'jnovak', 'source': 'directory'}, 'ok')
        self.assertEqual(counted(d), 0)


class FakeAd(object):
    name = 'corp'

    def __init__(self, groups):
        self.groups = groups        # {name typed: DN}, as group_dns resolves it
        self.asked = []

    def group_dns(self, name):
        self.asked.append(name)
        dn = self.groups.get(name.lower())
        return {dn.lower()} if dn else set()


class GroupBySamAccountName(unittest.TestCase):
    CA = 'CN=Cert Admins,OU=Groups,DC=corp,DC=loc'

    def test_sam_name_matches(self):
        ad = FakeAd({'cert-admins': self.CA, 'cert admins': self.CA})
        have = [(self.CA, 'Cert Admins')]
        self.assertEqual(E.group_matches(['cert-admins'], have, ad), 'cert-admins')
        self.assertEqual(E.group_matches(['Cert Admins'], have, ad), 'Cert Admins')   # as before

    def test_still_by_the_dn_only(self):
        # A name that is the cn of a group held but resolves elsewhere: no match, as before.
        ad = FakeAd({'cert admins': 'CN=Cert Admins,OU=Real,DC=corp,DC=loc'})
        self.assertIsNone(E.group_matches(['Cert Admins'], [(self.CA, 'Cert Admins')], ad))
        self.assertIsNone(E.group_matches(['cert-admins'], [(self.CA, 'Cert Admins')], None))

    def test_nobody_in_any_group_asks_nothing(self):
        ad = FakeAd({'cert-admins': self.CA})
        self.assertIsNone(E.group_matches(['cert-admins'], [], ad))
        self.assertEqual(ad.asked, [])

    def test_role_for(self):
        EN.CONFIG['admin_group_cert'] = 'cert-admins'
        try:
            ad = FakeAd({'cert-admins': self.CA})
            self.assertEqual(E.admin_role_for([(self.CA, 'Cert Admins')], ad), 'certadmin')
        finally:
            EN.CONFIG['admin_group_cert'] = ''


class ServerTroubleNotCounted(Patched):
    def setUp(self):
        Patched.setUp(self)
        EN.CONFIG.update(login_guard=1, login_guard_tries=2, login_guard_names=0,
                         login_guard_trusted='', login_tries=5, admin_directory='corp')

    def guard_blocked(self, d):
        return E.guard_blocked(d, '192.0.2.5')

    def test_password_directory_away(self):
        def away(h, name, password):
            raise E.ApiError(503, 'the directory cannot be reached')
        self.patch('admin_from_directory', away)
        d = D()
        for _ in range(4):
            with self.assertRaises(E.ApiError) as e:
                run(handler(d, {'name': 'jnovak', 'password': 'right-one-1'}), EN._login)
            self.assertEqual(e.exception.status, 503)
        self.assertEqual(counted(d), 0)
        self.assertIsNone(self.guard_blocked(d))

    def test_password_wrong_still_counted(self):
        def wrong(h, name, password):
            raise E.ApiError(401, 'the name or the password is not right')
        self.patch('admin_from_directory', wrong)
        d = D()
        for _ in range(2):
            with self.assertRaises(E.ApiError):
                run(handler(d, {'name': 'jnovak', 'password': 'wrong-one-1'}), EN._login)
        self.assertTrue(counted(d))
        self.assertTrue(self.guard_blocked(d))

    def windows(self, kind):
        self.patch('krb_on', lambda part: True)
        self.patch('krb_body', lambda h: {'header': 'Negotiate x'})

        def ticket(h, part, b, try_only=False):
            raise E.KrbRefused('the directory cannot be reached just now', kind)
        self.patch('krb_ticket', ticket)
        d = D()
        for _ in range(3):
            with self.assertRaises(E.ApiError):
                run(handler(d), EN._auth_kerberos)
        return d

    def test_windows_unavailable_not_counted(self):
        d = self.windows('unavailable')
        self.assertEqual(counted(d), 0)
        self.assertIsNone(self.guard_blocked(d))

    def test_windows_refused_still_counted(self):
        d = self.windows('allowed')
        self.assertTrue(counted(d))
        self.assertTrue(self.guard_blocked(d))

    def certificate(self, kind):
        self.patch('cl_on', lambda part: True)
        self.patch('cl_body', lambda h: {})

        def take(h, part, b):
            raise E.CertRefused('the CRL cannot be had', kind)
        self.patch('cl_take', take)
        d = D()
        for _ in range(3):
            with self.assertRaises(E.ApiError):
                run(handler(d), EN._auth_cert)
        return d

    def test_certificate_unavailable_not_counted(self):
        d = self.certificate('unavailable')
        self.assertEqual(counted(d), 0)
        self.assertIsNone(self.guard_blocked(d))

    def test_certificate_refused_still_counted(self):
        d = self.certificate('certificate')
        self.assertTrue(counted(d))
        self.assertTrue(self.guard_blocked(d))


if __name__ == '__main__':
    unittest.main()
