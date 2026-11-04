#!/usr/bin/env python3
"""The password policy of the local users (Settings -> Local users -> The password policy, 1.0.42).

    python3 test/test_osu_policy.py

1. The daemon: a password is checked by the policy (its length, the kinds of characters, the
   user's name in it - backwards too) before its hash is made; what the nodes are asked to put
   in, and the policy as it comes (nothing asked of a node that never had one).
2. The root helper alone, as root on this very machine (a user of the test's own, taken away
   after): a user made and a password set get the days of the policy (chage -M/-m/-W); the
   policy put on every normal user; with "the same rules for passwd" pwquality's file of acme's
   own and the PASS_ lines of login.defs written (in a folder of the test's), and the file taken
   away again when it is off.
"""
import importlib.util
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-osupol-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402

TOOLS = all(shutil.which(t) for t in ('useradd', 'userdel', 'chpasswd', 'chage', 'openssl'))
AS_ROOT = os.geteuid() == 0
TAG = 'acmep%d' % (os.getpid() % 10000)


class Daemon(unittest.TestCase):
    def test_the_rules(self):
        pol = dict(E.osu_policy(), min=12, classes=3, not_name=True)
        self.assertIn('12 characters', E.osu_pw_problem('Short-1', 'jan', pol))
        self.assertIn('four kinds', E.osu_pw_problem('alllowercaseletters', 'jan', pol))
        self.assertIn('name', E.osu_pw_problem('Xx-jannovak-2026', 'jannovak', pol))
        self.assertIn('name', E.osu_pw_problem('Xx-kavonnaj-2026', 'jannovak', pol))
        self.assertEqual(E.osu_pw_problem('Long-Enough-2026', 'jannovak', pol), '')
        # The name not looked for when it is off.
        self.assertEqual(E.osu_pw_problem('Xx-jannovak-2026', 'jannovak', dict(pol, not_name=False)), '')

    def test_eight_at_the_least(self):
        with mock.patch.dict(E.CONFIG, {'osu_pw_min': 3}):
            self.assertEqual(E.osu_policy()['min'], 8)

    def test_checked_before_the_hash(self):
        with mock.patch.dict(E.CONFIG, {'osu_pw_min': 14, 'osu_pw_classes': 2}):
            with self.assertRaises(ValueError) as c:
                E.osu_hash('only-thirteen', 'x')
            self.assertIn('14', str(c.exception))
            if shutil.which('openssl'):
                self.assertTrue(E.osu_hash('Fourteen-chars', 'x').startswith('$6$'))

    def test_what_is_asked(self):
        with mock.patch.dict(E.CONFIG, {'osu_pw_max_days': 90, 'osu_pw_min_days': 1,
                                        'osu_pw_warn_days': 10, 'osu_pw_system': 1,
                                        'osu_pw_min': 12, 'osu_pw_classes': 3}):
            a = E.osu_policy_ask()
        self.assertEqual(a['aging'], {'max_days': 90, 'min_days': 1, 'warn_days': 10})
        self.assertEqual(a['rules'], {'min': 12, 'classes': 3, 'not_name': True})
        self.assertNotEqual(a['sig'], E.osu_policy_ask()['sig'])
        # The rules for passwd only when asked.
        self.assertIsNone(E.osu_policy_ask()['rules'])

    def test_both_nodes_said(self):
        # A cluster of two: each node puts the policy on itself and says so in its own row;
        # the view says it of each - one of a version before it as such.
        import json
        import time
        store = E.Storage(E.open_db())
        me = E.node_name()
        sig = E.osu_policy_ask()['sig']
        store.set_meta('node:' + me, json.dumps({'at': time.time(), 'version': E.__version__}))
        store.set_meta('node:peer-old', json.dumps({'at': time.time(), 'version': '1.0.41'}))
        store.set_meta('node:peer-new', json.dumps({'at': time.time(), 'version': E.__version__}))
        store.set_meta('host:users:now:' + me, json.dumps({'at': time.time(), 'policy': sig}))
        store.set_meta('host:users:now:peer-new', json.dumps({'at': time.time(), 'policy': 'other'}))
        store.set_meta('host:users:now:peer-old', json.dumps({'at': time.time()}))
        with mock.patch.object(E, 'host_nodes', return_value=[me, 'peer-new', 'peer-old']):
            v = {n['name']: n for n in E.osu_view(store)['nodes']}
        self.assertTrue(v[me]['policy_ok'])
        self.assertFalse(v['peer-new']['policy_ok'])
        self.assertFalse(v['peer-new']['policy_old'])
        self.assertTrue(v['peer-old']['policy_old'])

    def _tick(self, conf, row):
        import json
        import time

        class D:
            pass
        d = D()
        d.store = E.Storage(E.open_db())
        me = E.node_name()
        d.store.set_meta('host:users:now:' + me, json.dumps(dict(row, at=time.time())))
        asked = []

        def fake(ask, ans, q, timeout):
            asked.append(q)
            return {'users': [], 'said': 'put on 0 user(s)', 'policy': q.get('sig') or ''}
        E.OSU_WORK.update(busy=False, seen=time.time())
        with mock.patch.dict(E.CONFIG, conf), mock.patch.object(E, 'root_ask', side_effect=fake), \
                mock.patch.object(E, 'osu_asks', return_value=[]):
            E.osu_tick(d)
            for _ in range(50):
                if not E.OSU_WORK['busy']:
                    break
                time.sleep(0.05)
            sig = E.osu_policy_ask()['sig']
        return asked, json.loads(d.store.get_meta('host:users:now:' + me)), sig

    def test_the_node_puts_it_in(self):
        asked, row, sig = self._tick({'osu_pw_max_days': 90, 'osu_pw_warn_days': 10}, {'policy': 'old'})
        pol = [a for a in asked if a.get('do') == 'policy']
        self.assertEqual(len(pol), 1)
        self.assertEqual(pol[0]['aging'], {'max_days': 90, 'min_days': 0, 'warn_days': 10})
        self.assertEqual(row['policy'], sig)

    def test_as_until_now_nothing_touched(self):
        asked, row, sig = self._tick({}, {})
        self.assertFalse([a for a in asked if a.get('do') == 'policy'])
        self.assertEqual(row['policy'], sig)

    def test_spared_who_ssh_asks_a_code(self):
        conf = {'manage': True, 'radius': True, 'radius_users': ['jan'], 'radius_root': False}
        with mock.patch.dict(E.CONFIG, {'osu_pw_max_days': 90}), \
                mock.patch.object(E, 'sshd_conf', return_value=conf):
            self.assertEqual(E.osu_spared(object()), {'all': False, 'names': ['jan']})
            self.assertEqual(E.osu_aging_for(object(), 'jan')['max_days'], 0)
            self.assertEqual(E.osu_aging_for(object(), 'eva')['max_days'], 90)
            self.assertEqual(E.osu_aging_for(object(), 'eva', has_password=False)['max_days'], 0)
            self.assertEqual(E.osu_policy_ask(store=object())['spare'], {'all': False, 'names': ['jan']})
        with mock.patch.object(E, 'sshd_conf', return_value=dict(conf, radius_users=[])):
            self.assertTrue(E.osu_spared(object())['all'])
        with mock.patch.object(E, 'sshd_conf', return_value=dict(conf, radius=False)):
            self.assertFalse(E.osu_spared(object())['all'])

    def test_on_the_pages(self):
        for k in ('osu_pw_min', 'osu_pw_classes', 'osu_pw_not_name', 'osu_pw_max_days',
                  'osu_pw_min_days', 'osu_pw_warn_days', 'osu_pw_system'):
            self.assertIn(k, E.PANES['osusers'])
            self.assertIn(k, E.NAMES)
            self.assertIn(k, E.SAYS)
        with open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8') as f:
            self.assertIn('id="sect-osusers"', f.read())


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


@unittest.skipUnless(TOOLS and AS_ROOT, 'needs root and shadow-utils (useradd, chage...)')
class Helper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-osupol-helper-')
        os.makedirs(os.path.join(cls.tmp, 'web'))
        cls.defs = os.path.join(cls.tmp, 'login.defs')
        shutil.copy('/etc/login.defs', cls.defs)
        cls.pwq = os.path.join(cls.tmp, 'pwquality.conf.d', '90-acme.conf')
        os.environ.update(ACME_STATE=cls.tmp, ACME_LOGIN_DEFS=cls.defs, ACME_PWQUALITY=cls.pwq,
                          ACME_CONSOLE_FLAG=os.path.join(cls.tmp, 'console-login'),
                          ACME_VIP_NO_SERVICES='1')
        spec = importlib.util.spec_from_file_location('acme_web_pol', os.path.join(ROOT, 'deploy', 'acme_web.py'))
        cls.W = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.W)
        cls.name = TAG + 'a'
        cls.gone(cls.name)
        # Every normal user of the machine as it was, put back after.
        cls.was = {u['name']: shadow(u['name']) for u in cls.W.lu_list()['users'] if not u['root']}

    @classmethod
    def gone(cls, name):
        try:
            pwd.getpwnam(name)
        except KeyError:
            return
        subprocess.run(['userdel', '-r', name], capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.gone(cls.name)
        for n, p in cls.was.items():
            if p:
                subprocess.run(['chage', '-M', p[4] or '99999', '-m', p[3] or '0', '-W', p[5] or '7', n],
                               capture_output=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_1_made_with_the_days(self):
        got = self.W.lu_do({'do': 'add', 'name': self.name, 'shell': '/bin/bash', 'gecos': 'Policy',
                            'hash': sha512('Long-Enough-2026'), 'uid': None,
                            'aging': {'max_days': 90, 'min_days': 1, 'warn_days': 10}})
        u = next(x for x in got['users'] if x['name'] == self.name)
        self.assertEqual(u['max_days'], 90)
        p = shadow(self.name)
        self.assertEqual((p[3], p[4], p[5]), ('1', '90', '10'))
        # A new password: the days put on again.
        self.W.lu_do({'do': 'password', 'name': self.name, 'hash': sha512('Another-One-2026'),
                      'aging': {'max_days': 30, 'min_days': 0, 'warn_days': 5}})
        p = shadow(self.name)
        self.assertEqual((p[3], p[4], p[5]), ('0', '30', '5'))

    def test_2_bad_days_refused(self):
        with self.assertRaises(self.W.Refused):
            self.W.lu_do({'do': 'policy', 'aging': {'max_days': 99999}})
        with self.assertRaises(self.W.Refused):
            self.W.lu_do({'do': 'policy', 'aging': {'max_days': 30}, 'rules': {'min': 3, 'classes': 1}})

    def test_3_on_every_normal_user_and_for_passwd(self):
        got = self.W.lu_do({'do': 'policy', 'sig': 'abc',
                            'aging': {'max_days': 60, 'min_days': 2, 'warn_days': 9},
                            'rules': {'min': 12, 'classes': 3, 'not_name': True}})
        self.assertEqual(got['policy'], 'abc')
        self.assertIn('the same rules for passwd', got['said'])
        p = shadow(self.name)
        self.assertEqual((p[3], p[4], p[5]), ('2', '60', '9'))
        with open(self.pwq) as f:
            conf = f.read()
        self.assertIn('minlen = 12', conf)
        self.assertIn('minclass = 3', conf)
        self.assertIn('usercheck = 1', conf)
        with open(self.defs) as f:
            defs = [ln.split() for ln in f if ln.strip() and not ln.startswith('#')]
        got_defs = {w[0]: w[1] for w in defs if len(w) >= 2}
        self.assertEqual((got_defs['PASS_MAX_DAYS'], got_defs['PASS_MIN_DAYS'], got_defs['PASS_WARN_AGE']),
                         ('60', '2', '9'))
        # The other lines of login.defs kept.
        self.assertIn('UID_MIN', got_defs)
        # Asked a code by SSH: left out - always good, and said so.
        got = self.W.lu_do({'do': 'policy', 'spare': {'all': False, 'names': [self.name]},
                            'aging': {'max_days': 60, 'min_days': 2, 'warn_days': 9}})
        self.assertIn('always good', got['said'])
        p = shadow(self.name)
        self.assertEqual((p[3], p[4]), ('0', '99999'))
        # Off again: always good, and pwquality's file of acme's taken away.
        got = self.W.lu_do({'do': 'policy', 'aging': {'max_days': 0, 'min_days': 0, 'warn_days': 7}})
        self.assertFalse(os.path.exists(self.pwq))
        p = shadow(self.name)
        self.assertEqual((p[3], p[4], p[5]), ('0', '99999', '7'))


if __name__ == '__main__':
    unittest.main()
