#!/usr/bin/env python3
"""The password policy of the local users and a user's own aging (1.0.43, as otp 1.0.245 - 1.0.246).

    python3 test/test_pwpolicy.py

1. The root helper, on copies of the system's files in a folder of the test's (ACME_SECURITY_DIR,
   ACME_PAM_DIR, ACME_LOGIN_DEFS, ACME_PWP_ORIG) and a fake authselect: read (the defaults, the
   drop-ins, PAM); put in (the drop-in, acme's lines between marks, login.defs with what it had,
   authselect's features); put in again changes nothing; given back (every file byte for byte,
   only acme's features out, acme 1.0.42's file taken out); a link refused; ranges refused.
2. As root on this very machine (a user of the test's own, taken away after): a user made with no
   password has no aging, with a password the policy's; a user's own aging; "existing" puts it on
   the users with a password and leaves those with none.
3. The daemon: the policy as asked (ranges), a password kept to it (without pwscore), a row the
   guard refused (pwp_refused), the node putting it in (osu_tick, root_ask mocked) and again on a
   new machine (its row forgotten), acme 1.0.42's settings taken over once.
"""
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-pwp-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402

AS_ROOT = os.geteuid() == 0
TOOLS = all(shutil.which(t) for t in ('useradd', 'userdel', 'chpasswd', 'chage', 'openssl'))
TAG = 'acmepw%d' % (os.getpid() % 10000)
DEFS = """# login.defs of the test
MAIL_DIR\t/var/spool/mail
PASS_MAX_DAYS\t99999
PASS_MIN_DAYS\t0
PASS_WARN_AGE\t7
UID_MIN\t1000
UID_MAX\t60000
"""
HISTORY = "# pwhistory.conf of the system\n# remember = 10\n"
FAILLOCK = "# faillock.conf of the system\n# deny = 3\n"
SYSTEM_AUTH = """auth required pam_env.so
auth sufficient pam_unix.so
password requisite pam_pwquality.so local_users_only
password sufficient pam_unix.so sha512 shadow use_authtok
"""
FAKE_AUTHSELECT = """#!/bin/sh
f="$(dirname "$0")/features"
touch "$f"
case "$1" in
  current) echo "sssd $(tr '\\n' ' ' < "$f")";;
  enable-feature) echo "$2" >> "$f";;
  disable-feature) grep -vx "$2" "$f" > "$f.new"; mv "$f.new" "$f";;
esac
"""


def helper(tmp, extra=None):
    env = {'ACME_STATE': tmp, 'ACME_SECURITY_DIR': os.path.join(tmp, 'security'),
           'ACME_PAM_DIR': os.path.join(tmp, 'pam.d'), 'ACME_LOGIN_DEFS': os.path.join(tmp, 'login.defs'),
           'ACME_PWP_ORIG': os.path.join(tmp, 'pwpolicy-orig.json'),
           'ACME_CONSOLE_FLAG': os.path.join(tmp, 'console-login'), 'ACME_VIP_NO_SERVICES': '1',
           'ACME_AUTHSELECT': os.path.join(tmp, 'authselect', 'authselect')}
    env.update(extra or {})
    os.environ.update(env)
    spec = importlib.util.spec_from_file_location('acme_web_pwp%d' % id(tmp), os.path.join(ROOT, 'deploy', 'acme_web.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def files_of(tmp):
    out = {}
    for d, _dirs, names in os.walk(tmp):
        for n in names:
            p = os.path.join(d, n)
            if '/authselect' in p or n.endswith('.json') or n == 'config.json':
                continue
            with open(p, 'rb') as f:
                out[os.path.relpath(p, tmp)] = f.read()
    return out


POL = {'managed': True, 'minlen': 14, 'minclass': 3, 'maxrepeat': 3, 'dictcheck': 1, 'usercheck': 1,
       'difok': 5, 'remember': 5, 'max_days': 90, 'min_days': 1, 'warn_days': 10, 'deny': 5,
       'unlock_time': 600, 'fail_interval': 900, 'existing': False}


class Helper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='acme-pwp-helper-')
        os.makedirs(os.path.join(self.tmp, 'security', 'pwquality.conf.d'))
        os.makedirs(os.path.join(self.tmp, 'pam.d'))
        os.makedirs(os.path.join(self.tmp, 'authselect'))
        for name, text in (('login.defs', DEFS), ('security/pwhistory.conf', HISTORY),
                           ('security/faillock.conf', FAILLOCK), ('security/pwquality.conf', 'minlen = 9\n'),
                           ('pam.d/system-auth', SYSTEM_AUTH)):
            with open(os.path.join(self.tmp, name), 'w') as f:
                f.write(text)
        a = os.path.join(self.tmp, 'authselect', 'authselect')
        with open(a, 'w') as f:
            f.write(FAKE_AUTHSELECT)
        os.chmod(a, 0o755)
        self.W = helper(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def features(self):
        try:
            with open(os.path.join(self.tmp, 'authselect', 'features')) as f:
                return [x for x in f.read().split() if x]
        except OSError:
            return []

    def test_1_read_as_the_system_has_it(self):
        r = self.W.pwp_read()
        self.assertFalse(r['managed'])
        self.assertEqual(r['pwquality']['minlen'], 9)
        self.assertTrue(r['pam']['pwquality'])
        self.assertFalse(r['pam']['pwhistory'])
        self.assertEqual(r['aging'], {'max_days': 99999, 'min_days': 0, 'warn_days': 7})
        self.assertEqual(r['authselect']['profile'], 'sssd')

    def test_2_put_in_and_again_nothing_changes(self):
        said = self.W.pwp_apply(POL)
        self.assertTrue(any('pwquality' in x for x in said))
        with open(os.path.join(self.tmp, 'security', 'pwquality.conf.d', '50-acme.conf')) as f:
            q = f.read()
        self.assertIn('minlen = 14', q)
        self.assertIn('minclass = 3', q)
        self.assertIn('retry = 3', q)
        with open(os.path.join(self.tmp, 'security', 'pwhistory.conf')) as f:
            h = f.read()
        self.assertTrue(h.startswith(HISTORY))
        self.assertIn(self.W.PWP_MARK_A + 'remember = 5\n' + self.W.PWP_MARK_B, h)
        with open(os.path.join(self.tmp, 'security', 'faillock.conf')) as f:
            fl = f.read()
        self.assertIn('deny = 5\nunlock_time = 600\nfail_interval = 900\n', fl)
        self.assertNotIn('even_deny_root', fl)
        with open(os.path.join(self.tmp, 'login.defs')) as f:
            d = f.read()
        self.assertIn('PASS_MAX_DAYS\t90\n', d)
        self.assertIn('# acme-was: PASS_MAX_DAYS PASS_MAX_DAYS\t99999', d)
        self.assertEqual(sorted(self.features()), ['with-faillock', 'with-pwhistory'])
        r = self.W.pwp_read()
        self.assertTrue(r['managed'])
        self.assertEqual(r['pwquality']['minlen'], 14)
        self.assertEqual(r['remember'], 5)
        self.assertEqual(r['aging']['max_days'], 90)
        before = files_of(self.tmp)
        self.W.pwp_apply(POL)
        self.assertEqual(files_of(self.tmp), before)
        self.assertEqual(sorted(self.features()), ['with-faillock', 'with-pwhistory'])

    def test_3_given_back_byte_for_byte(self):
        with open(os.path.join(self.tmp, 'authselect', 'features'), 'w') as f:
            f.write('with-mkhomedir\n')               # the system's own feature
        os.makedirs(os.path.join(self.tmp, 'security', 'pwquality.conf.d'), exist_ok=True)
        with open(os.path.join(self.tmp, 'security', 'pwquality.conf.d', '90-acme.conf'), 'w') as f:
            f.write('minlen = 12\n')                   # acme 1.0.42's own
        before = files_of(self.tmp)
        self.W.pwp_apply(POL)
        self.W.pwp_apply(dict(POL, max_days=30, remember=0))
        said = self.W.pwp_apply(dict(POL, managed=False))
        self.assertTrue(said)
        after = files_of(self.tmp)
        del before['security/pwquality.conf.d/90-acme.conf']
        self.assertEqual(after, before)
        self.assertEqual(self.features(), ['with-mkhomedir'])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'pwpolicy-orig.json')))
        # Off again with nothing of acme's there: nothing written.
        self.assertEqual(self.W.pwp_apply(dict(POL, managed=False)), ["nothing of acme's was there"])

    def test_4_a_link_refused(self):
        p = os.path.join(self.tmp, 'security', 'pwhistory.conf')
        os.unlink(p)
        os.symlink(os.path.join(self.tmp, 'login.defs'), p)
        with self.assertRaises(self.W.Refused):
            self.W.pwp_apply(POL)

    def test_5_ranges_refused(self):
        for k, v in (('minlen', 3), ('minclass', 5), ('max_days', 100000), ('fail_interval', 10),
                     ('deny', 'x')):
            with self.assertRaises(self.W.Refused):
                self.W.pwp_checked(dict(POL, **{k: v}))
        with self.assertRaises(self.W.Refused):
            self.W.pwp_checked('managed')


def sha512(pw):
    return subprocess.run(['openssl', 'passwd', '-6', '-stdin'], input=pw + '\n',
                          capture_output=True, text=True, check=True).stdout.strip()


def shadow(name):
    with open('/etc/shadow') as f:
        for ln in f:
            p = ln.rstrip('\n').split(':')
            if p[0] == name:
                return p
    return None


@unittest.skipUnless(AS_ROOT and TOOLS, 'needs root and shadow-utils')
class Users(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-pwp-users-')
        os.makedirs(os.path.join(cls.tmp, 'security'))
        os.makedirs(os.path.join(cls.tmp, 'pam.d'))
        shutil.copy('/etc/login.defs', os.path.join(cls.tmp, 'login.defs'))
        cls.W = helper(cls.tmp, {'ACME_AUTHSELECT': os.path.join(cls.tmp, 'none')})
        cls.a, cls.k = TAG + 'a', TAG + 'k'
        for n in (cls.a, cls.k):
            cls.gone(n)

    @classmethod
    def gone(cls, name):
        try:
            pwd.getpwnam(name)
        except KeyError:
            return
        subprocess.run(['userdel', '-r', name], capture_output=True)

    @classmethod
    def tearDownClass(cls):
        for n in (cls.a, cls.k):
            cls.gone(n)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_1_made_with_and_without_a_password(self):
        aging = {'max_days': 60, 'min_days': 1, 'warn_days': 10}
        got = self.W.lu_do({'do': 'add', 'name': self.a, 'shell': '/bin/bash', 'gecos': 'A',
                            'hash': sha512('Long-Enough-2026x'), 'uid': None, 'policy_aging': aging})
        p = shadow(self.a)
        self.assertEqual((p[3], p[4], p[5]), ('1', '60', '10'))
        u = next(x for x in got['users'] if x['name'] == self.a)
        self.assertEqual((u['max_days'], u['min_days'], u['warn_days']), (60, 1, 10))
        self.assertEqual(u['pw_ends'], u['changed'] + 60)
        self.W.lu_do({'do': 'add', 'name': self.k, 'shell': '/bin/bash', 'uid': None})
        p = shadow(self.k)
        self.assertEqual((p[4], p[6]), ('', ''), 'a key only: no aging')

    def test_2_a_users_own_aging(self):
        self.W.lu_do({'do': 'aging', 'name': self.a, 'aging': {'max_days': 30, 'min_days': 0, 'warn_days': 5}})
        p = shadow(self.a)
        self.assertEqual((p[3], p[4], p[5]), ('0', '30', '5'))
        with self.assertRaises(self.W.Refused):
            self.W.lu_do({'do': 'aging', 'name': self.a, 'aging': {'max_days': -2, 'min_days': 0, 'warn_days': 5}})

    def test_3_existing_with_a_password_only(self):
        said = self.W.pwp_apply(dict(POL, existing=True, max_days=45, deny=0, remember=0))
        self.assertTrue(any('left without' in x for x in said), said)
        self.assertEqual(shadow(self.a)[4], '45')
        self.assertEqual(shadow(self.k)[4], '')
        self.W.pwp_apply(dict(POL, managed=False))

    def test_4_a_new_password_with_the_policys_aging(self):
        self.W.lu_do({'do': 'password', 'name': self.k, 'hash': sha512('Another-Long-2026x'),
                      'policy_aging': {'max_days': 20, 'min_days': 0, 'warn_days': 3}})
        self.assertEqual(shadow(self.k)[4], '20')


class Daemon(unittest.TestCase):
    def setUp(self):
        self.store = E.Storage(E.open_db())
        self.store.db.run("DELETE FROM meta WHERE k IN ('host:pwpolicy:conf', 'pwpolicy:migrated', 'pwpolicy:migrated:2')")

    def test_1_as_asked(self):
        c = E.pwp_checked_api({'managed': True, 'minlen': 14, 'max_days': 90})
        self.assertTrue(c['managed'])
        self.assertEqual((c['minlen'], c['max_days'], c['minclass']), (14, 90, 3))
        for bad in ({'minlen': 5}, {'remember': 51}, {'max_days': 'x'}, {'min_days': 50, 'max_days': 30}):
            with self.assertRaises(ValueError):
                E.pwp_checked_api(bad)

    def test_2_a_password_kept_to_it(self):
        self.store.set_meta('host:pwpolicy:conf', json.dumps(dict(E.PWP_DEFAULT, managed=True, minlen=14)))
        real = shutil.which
        with mock.patch.object(E.shutil, 'which', side_effect=lambda n: None if n == 'pwscore' else real(n)):
            with self.assertRaises(ValueError) as c:
                E.pwp_password_check(self.store, 'Short-1x', 'jan')
            self.assertIn('14 characters', str(c.exception))
            with self.assertRaises(ValueError):
                E.pwp_password_check(self.store, 'alllowercaseletters', 'jan')
            with self.assertRaises(ValueError):
                E.pwp_password_check(self.store, 'Aaaaa-1111-bbbb', 'jan')
            with self.assertRaises(ValueError):
                E.pwp_password_check(self.store, 'Xy-jannovak-2026', 'jannovak')
            E.pwp_password_check(self.store, 'Good-Pass-2026x', 'jan')
            # Not managed: only the 8 of the pages.
            self.store.set_meta('host:pwpolicy:conf', json.dumps(dict(E.PWP_DEFAULT, managed=False)))
            E.pwp_password_check(self.store, 'short', 'jan')

    def test_3_a_row_the_guard_refused(self):
        self.assertFalse(E.pwp_refused(self.store))
        self.store.set_meta('host:pwpolicy:conf', json.dumps(dict(E.PWP_DEFAULT, managed=True)))
        self.assertFalse(E.pwp_refused(self.store))
        with mock.patch.object(E, '_meta_json', return_value=None):
            self.assertTrue(E.pwp_refused(self.store))
        self.assertIn('host:pwpolicy:conf', E.DBGUARD_META_EXACT)

    def tick(self, row):
        class D:
            pass
        d = D()
        d.store = self.store
        me = E.node_name()
        self.store.set_meta('host:users:now:' + me, json.dumps(dict(row, at=time.time())))
        asked = []

        def fake(ask, ans, q, timeout):
            asked.append(q)
            return {'users': [], 'said': 'put in', 'policy': {'managed': True}}
        E.OSU_WORK.update(busy=False, seen=time.time())
        with mock.patch.object(E, 'root_ask', side_effect=fake), mock.patch.object(E, 'osu_asks', return_value=[]):
            E.osu_tick(d)
            for _ in range(60):
                if not E.OSU_WORK['busy']:
                    break
                time.sleep(0.05)
        return asked, json.loads(self.store.get_meta('host:users:now:' + me))

    def test_4_the_node_puts_it_in(self):
        self.store.set_meta('host:pwpolicy:conf', json.dumps(dict(E.PWP_DEFAULT, managed=True, minlen=13)))
        want = E.pwp_hash(E.pwp_conf(self.store))
        asked, row = self.tick({})
        pol = [a for a in asked if a.get('do') == 'policy']
        self.assertEqual(len(pol), 1)
        self.assertEqual(pol[0]['conf']['minlen'], 13)
        self.assertEqual(row['policy_hash'], want)
        # Done: not asked again; a new machine (its row forgotten): asked again.
        asked, row = self.tick(row)
        self.assertFalse([a for a in asked if a.get('do') == 'policy'])
        asked, row = self.tick({})
        self.assertTrue([a for a in asked if a.get('do') == 'policy'])

    def test_5_never_set_nothing_asked(self):
        asked, row = self.tick({})
        self.assertFalse([a for a in asked if a.get('do') == 'policy'])

    def test_6_acme_1042_taken_over_once(self):
        self.store.save_setting('osu_pw_max_days', 90, 'test')
        self.store.save_setting('osu_pw_min', 12, 'test')
        self.store.save_setting('osu_pw_classes', '3', 'test')
        try:
            self.assertTrue(E.pwp_migrate(self.store))
            c = E.pwp_conf(self.store)
            self.assertTrue(c['managed'])
            self.assertEqual((c['minlen'], c['minclass'], c['max_days']), (12, 3, 90))
            self.store.db.run("DELETE FROM meta WHERE k = 'host:pwpolicy:conf'")
            self.assertFalse(E.pwp_migrate(self.store), 'once only')
        finally:
            for k in ('osu_pw_max_days', 'osu_pw_min', 'osu_pw_classes'):
                self.store.drop_setting(k)

    def test_7_nothing_to_take_over(self):
        self.assertFalse(E.pwp_migrate(self.store))
        self.assertIsNone(self.store.get_meta('host:pwpolicy:conf'))

    def test_8_sudo_with_no_password_refused(self):
        with mock.patch.object(E, 'host_nodes', return_value=[E.node_name()]), \
                mock.patch.object(E, 'osu_free_uid', return_value=1500):
            with self.assertRaises(ValueError) as c:
                E.osu_ask(self.store, [E.node_name()], 'add', 'test', name='nopw', sudo=True)
        self.assertIn('sudo asks', str(c.exception))


if __name__ == '__main__':
    unittest.main()
