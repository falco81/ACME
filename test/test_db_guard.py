"""The guard against writes to the database (1.0.40, from otp 1.0.231-1.0.235).

Rows that make a node act as root, accounts, directories and sign-ins to the
pages are signed when acme writes them; with `db_guard` on (config.json only)
a row written by anybody else reads as not there, a setting keeps its last good
value, an older signed row put back is refused - and with it off everything is
as before.

    python3 test/test_db_guard.py
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-guard-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def guard(on):
    E.CONFIG['db_guard'] = 1 if on else 0


def forged_meta(k, v):
    STORE.db.upsert('meta', 'k', {'k': k, 'v': v})


class TestSigned(unittest.TestCase):
    def setUp(self):
        guard(False)

    def test_off_by_default_and_as_before(self):
        self.assertEqual(E.DEFAULTS['db_guard'], 0)
        self.assertIn('db_guard', E.FILE_ONLY_KEYS)
        forged_meta('fw:conf', '{"on": true}')
        self.assertEqual(STORE.get_meta('fw:conf'), '{"on": true}')

    def test_written_by_acme_is_taken(self):
        STORE.set_meta('fw:conf', '{"on": false}')
        guard(True)
        self.assertEqual(STORE.get_meta('fw:conf'), '{"on": false}')

    def test_written_by_somebody_else_reads_as_not_there(self):
        STORE.set_meta('web:access', '{"a": 1}')
        forged_meta('web:access', '{"a": 2}')
        guard(True)
        self.assertIsNone(STORE.get_meta('web:access'))
        self.assertTrue(any(r['what'] == 'web:access' for r in E.dbguard_view()['refused']))

    def test_an_unsigned_row_not_guarded_is_read(self):
        forged_meta('something:else', 'x')
        guard(True)
        self.assertEqual(STORE.get_meta('something:else'), 'x')

    def test_an_older_one_put_back_is_refused(self):
        STORE.set_meta('ntp:conf', 'one')
        old_sig = [r for r in STORE.db.rows('SELECT k, v FROM meta') if r['k'].startswith('sig:m:')]
        guard(True)
        self.assertEqual(STORE.get_meta('ntp:conf'), 'one')
        time.sleep(0.01)
        STORE.set_meta('ntp:conf', 'two')
        self.assertEqual(STORE.get_meta('ntp:conf'), 'two')
        # the old row and its old signature put back
        forged_meta('ntp:conf', 'one')
        sid = E._dbguard_sid('m', 'ntp:conf')
        for r in old_sig:
            if r['k'] == sid:
                STORE.db.upsert('meta', 'k', {'k': r['k'], 'v': r['v']})
        self.assertIsNone(STORE.get_meta('ntp:conf'))

    def test_node_key_rows_left_out(self):
        STORE.set_meta('host:sshkeys:want:root@@n1', '[1]')
        forged_meta('host:sshkeys:want:root@@n2', '[2]')
        guard(True)
        got = {r['k'] for r in E.node_key_rows(STORE, 'host:sshkeys:want', 'root')}
        self.assertIn('host:sshkeys:want:root@@n1', got)
        self.assertNotIn('host:sshkeys:want:root@@n2', got)


class TestSettings(unittest.TestCase):
    def setUp(self):
        guard(False)

    def test_a_setting_keeps_its_last_good_value(self):
        STORE.save_setting('upgrade_url', 'https://good.example/', 'test')
        guard(True)
        got = E.dbguard_settings(STORE.settings_saved(), STORE)
        self.assertEqual(got['upgrade_url'], 'https://good.example/')
        STORE.db.upsert('settings', 'k', {'k': 'upgrade_url', 'v': json.dumps('https://evil.example/'),
                                          'at': time.time(), 'by_who': 'x'})
        got = E.dbguard_settings(STORE.settings_saved(), STORE)
        self.assertEqual(got['upgrade_url'], 'https://good.example/')

    def test_a_setting_not_guarded_is_taken(self):
        guard(True)
        STORE.db.upsert('settings', 'k', {'k': 'site_name', 'v': json.dumps('x'),
                                          'at': time.time(), 'by_who': 'x'})
        self.assertEqual(E.dbguard_settings(STORE.settings_saved(), STORE)['site_name'], 'x')


class TestAccountsAndSignIns(unittest.TestCase):
    def setUp(self):
        guard(False)

    def test_an_account_put_in_by_somebody_else(self):
        STORE.add_account('alice', 'fulladmin', 'Long-Password-2026!x')
        STORE.db.insert('accounts', {'name': 'mallory', 'role': 'fulladmin', 'pw': 'x', 'source': 'local',
                                     'disabled': 0, 'must_change': 0, 'created': time.time()})
        guard(True)
        self.assertIsNotNone(STORE.account('alice', checked=True))
        self.assertIsNone(STORE.account('mallory', checked=True))
        self.assertIsNotNone(STORE.account('mallory'))      # unchecked reads stay as they were

    def test_an_account_changed_by_somebody_else(self):
        STORE.add_account('bob', 'readonly', 'Long-Password-2026!x')
        guard(True)
        STORE.db.run("UPDATE accounts SET role = 'fulladmin' WHERE name = 'bob'")
        self.assertIsNone(STORE.account('bob', checked=True))
        guard(False)
        STORE.set_account('bob', role='fulladmin')
        guard(True)
        self.assertIsNotNone(STORE.account('bob', checked=True))

    def test_a_sign_in_put_in_by_somebody_else(self):
        tok = STORE.session_new('admin', 'alice2', 'fulladmin', '127.0.0.1', 1)
        guard(True)
        self.assertIsNotNone(STORE.session_get(tok, 'admin', 3600))
        import hashlib
        import secrets
        forged = secrets.token_urlsafe(32)
        t = time.time()
        STORE.db.insert('sessions', {'token_hash': hashlib.sha256(forged.encode()).hexdigest(),
                                     'kind': 'admin', 'name': 'alice2', 'role': 'fulladmin', 'created': t,
                                     'last': t, 'expires': t + 3600, 'ip': '', 'data': '{}'})
        self.assertIsNone(STORE.session_get(forged, 'admin', 3600))


class TestResign(unittest.TestCase):
    def test_switched_on_signs_what_is_there(self):
        guard(False)
        forged_meta('power:plan', '{"at": 1}')
        n = E.dbguard_resign(STORE, 'test')
        self.assertGreater(n, 0)
        guard(True)
        self.assertEqual(STORE.get_meta('power:plan'), '{"at": 1}')

    def test_forget_seen_signs_nothing(self):
        guard(False)
        forged_meta('fw:trial', 'x')
        E.dbguard_forget_seen('test')
        guard(True)
        self.assertIsNone(STORE.get_meta('fw:trial'))

    def test_downgrade_refused_while_on(self):
        guard(True)
        try:
            why = E.downgrade_why_not(STORE, '1.0.39')
        finally:
            guard(False)
        self.assertTrue(any('guard against writes' in w for w in why), why)

    def test_the_heartbeat_says_it(self):
        guard(True)
        try:
            E.heartbeat(STORE)
            beat = json.loads(STORE.db.value('SELECT v FROM meta WHERE k = ?', ('node:' + E.node_name(),)))
        finally:
            guard(False)
        self.assertTrue(beat.get('db_guard'))
        self.assertTrue(E.dbguard_node_ok(STORE, E.node_name()))


KEYGEN = shutil.which('ssh-keygen')


def helper():
    """acme_web.py (the root helper) loaded here: its state folder this test's, root's
    authorized_keys and config.json files of the test's own."""
    os.environ['ACME_VIP_NO_SERVICES'] = '1'
    spec = importlib.util.spec_from_file_location('acme_web_guard_t',
                                                  os.path.join(ROOT, 'deploy', 'acme_web.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.ROOT_AUTH = os.path.join(TMP, 'root-ssh', 'authorized_keys')
    mod.CONFIG_PATH = os.path.join(TMP, 'helper-config.json')
    mod.sshd_says = lambda: {'there': False}
    return mod


def pubkey(comment):
    path = os.path.join(TMP, 'k-%s' % comment)
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', path],
                   check=True, capture_output=True)
    with open(path + '.pub') as f:
        return f.read().strip()


@unittest.skipUnless(KEYGEN, 'ssh-keygen is not here')
class TestRootKeys(unittest.TestCase):
    """A key of root's added by the root helper (1.0.101): with db_guard on only from a row of
    the database acme signed - an ask laid in the helper's folder by itself is refused."""

    @classmethod
    def setUpClass(cls):
        cls.W = helper()
        os.makedirs(os.path.join(TMP, 'web'), exist_ok=True)

    def setUp(self):
        guard(True)
        self.helper_guard(True)
        try:
            os.unlink(self.W.ROOT_AUTH)
        except FileNotFoundError:
            pass

    def tearDown(self):
        guard(False)

    def helper_guard(self, on):
        with open(self.W.CONFIG_PATH, 'w') as f:
            json.dump({'db_guard': 1 if on else 0}, f)

    def fps(self):
        return [k['fp'] for k in self.W.auth_keys(self.W.auth_lines())]

    def asked(self, line):
        """The ask the daemon lays down for the helper, as sshkeys_tick makes it."""
        E.sshkeys_ask(STORE, [E.node_name()], 'add', 'tester', line=line)
        for r in E.node_key_rows(STORE, 'host:sshkeys:want', E.node_name()):
            for a in json.loads(r['v']):
                if a.get('line') == line:
                    return E.sshkeys_root_data(STORE, dict(a, _row=(r['k'], r['v'])))
        self.fail('the ask is not in the database')

    def test_signed_ask_is_taken(self):
        line = pubkey('pages')
        data = self.asked(line)
        self.assertIn('signed', data)
        got = self.W.sshkeys_do(data)
        self.assertEqual(len(got['keys']), 1)
        self.assertEqual(got['keys'][0]['comment'], 'pages')

    def test_forged_unsigned_ask_is_refused(self):
        line = pubkey('forged')
        with self.assertRaises(self.W.Refused) as e:
            self.W.sshkeys_do({'do': 'add', 'line': line, 'user': 'root'})
        self.assertIn('db_guard', str(e.exception))
        self.assertEqual(self.fps(), [])
        # ...also as a file in the helper's folder, the way the acme account would lay it down.
        with open(os.path.join(TMP, 'web', 'sshkeys.ask'), 'w') as f:
            json.dump({'id': 'x1', 'do': 'add', 'line': line, 'user': 'root'}, f)
        self.W.sshkeys_part()
        with open(os.path.join(TMP, 'web', 'sshkeys.json')) as f:
            said = json.load(f)
        self.assertFalse(said['ok'])
        self.assertIn('db_guard', said['said'])
        self.assertEqual(self.fps(), [])

    def test_forged_signatures_and_other_lines_are_refused(self):
        line, other = pubkey('asked'), pubkey('other')
        data = self.asked(line)
        bad = json.loads(json.dumps(data))
        bad['signed']['sigs'] = [{'n': s['n'], 'm': '0' * 64} for s in bad['signed']['sigs']]
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do(bad)
        # a row of the database written past acme: the signature is not of its value
        bad = json.loads(json.dumps(data))
        rows = json.loads(bad['signed']['v'])
        rows[-1]['line'] = other
        bad['signed']['v'] = json.dumps(rows)
        bad['line'] = other
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do(bad)
        # a signed row, but another key in the ask
        bad = dict(data, line=other)
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do(bad)
        # not a row of root's keys
        bad = json.loads(json.dumps(data))
        bad['signed']['k'] = 'fw:conf'
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do(bad)
        self.assertEqual(self.fps(), [])

    def test_unreadable_config_counts_as_on(self):
        with open(self.W.CONFIG_PATH, 'w') as f:
            f.write('{not json')
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do({'do': 'add', 'line': pubkey('broken'), 'user': 'root'})

    def test_guard_off_as_until_now(self):
        self.helper_guard(False)
        got = self.W.sshkeys_do({'do': 'add', 'line': pubkey('plain'), 'user': 'root'})
        self.assertEqual(len(got['keys']), 1)
        # dropping one needs no signature
        self.helper_guard(True)
        fp = got['keys'][0]['fp']
        got = self.W.sshkeys_do({'do': 'drop', 'fp': fp, 'user': 'root', 'last_ok': True})
        self.assertEqual(got['keys'], [])


if __name__ == '__main__':
    unittest.main()
