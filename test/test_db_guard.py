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

    def test_a_portal_sign_in_put_in_by_somebody_else(self):
        """The portal's sign-ins signed too (1.0.101): one put in past acme opened the
        enrolment pages - and every certificate's private key they hand out."""
        import hashlib
        import secrets
        tok = STORE.session_new('portal', 'carol', 'portal', '127.0.0.1', 1,
                                {'kind': 'directory', 'dn': 'CN=carol,DC=x'})
        guard(True)
        # A single node (or a cluster all on 1.0.101): taken under the guard at once, at the
        # daemon's start (dbguard_adopt) - the portal's sign-ins checked from then on.
        E.DBGUARD['adopted'] = {k: v for k, v in (E.DBGUARD.get('adopted') or {}).items()
                                if k != E.DBGUARD_ADOPT3_MARK}
        self.assertFalse(E.dbguard_adopted3())
        E.dbguard_adopt(STORE)
        self.assertTrue(E.dbguard_adopted3())
        self.assertIsNotNone(STORE.session_get(tok, 'portal', 3600))
        forged = secrets.token_urlsafe(32)
        t = time.time()
        th = hashlib.sha256(forged.encode()).hexdigest()
        STORE.db.insert('sessions', {'token_hash': th, 'kind': 'portal', 'name': 'carol',
                                     'role': 'portal', 'created': t, 'last': t, 'expires': t + 3600,
                                     'ip': '', 'data': json.dumps({'kind': 'directory', 'dn': '',
                                                                   'gate_ok': t})})
        self.assertIsNone(STORE.session_get(forged, 'portal', 3600))
        # ...and ended (as one opened before 1.0.101 while the guard was on is)
        self.assertIsNone(STORE.db.value('SELECT id FROM sessions WHERE token_hash = ?', (th,)))
        # Its name changed in the table: refused as well.
        STORE.db.run("UPDATE sessions SET name = 'mallory' WHERE token_hash = ?",
                     (hashlib.sha256(tok.encode()).hexdigest(),))
        self.assertIsNone(STORE.session_get(tok, 'portal', 3600))
        # The guard off: as before.
        guard(False)
        tok2 = secrets.token_urlsafe(32)
        STORE.db.insert('sessions', {'token_hash': hashlib.sha256(tok2.encode()).hexdigest(),
                                     'kind': 'portal', 'name': 'carol', 'role': 'portal',
                                     'created': t, 'last': t, 'expires': t + 3600, 'ip': '',
                                     'data': '{}'})
        self.assertIsNotNone(STORE.session_get(tok2, 'portal', 3600))
        # Switched on: what is there is signed as it is (dbguard_resign), every kind.
        E.dbguard_resign(STORE)
        guard(True)
        self.assertIsNotNone(STORE.session_get(tok2, 'portal', 3600))

    def test_a_portal_sign_in_of_a_node_still_on_1_0_100(self):
        """A rolling upgrade (1.0.101): until every node runs 1.0.101 (the adoption's mark) a
        portal's sign-in made unsigned on the old node is taken - not ended at the first request
        that lands here; the administration's are checked as before."""
        import hashlib
        import secrets
        guard(True)
        saved = dict(E.DBGUARD.get('adopted') or {})
        E.DBGUARD['adopted'] = {k: v for k, v in saved.items() if k != E.DBGUARD_ADOPT3_MARK}
        try:
            t = time.time()
            toks = {}
            for kind in ('portal', 'admin'):
                toks[kind] = secrets.token_urlsafe(32)
                STORE.db.insert('sessions', {
                    'token_hash': hashlib.sha256(toks[kind].encode()).hexdigest(), 'kind': kind,
                    'name': 'old', 'role': kind if kind == 'portal' else 'fulladmin', 'created': t,
                    'last': t, 'expires': t + 3600, 'ip': '', 'data': '{}'})
            self.assertIsNotNone(STORE.session_get(toks['portal'], 'portal', 3600))
            self.assertIsNone(STORE.session_get(toks['admin'], 'admin', 3600))
            # the whole cluster on 1.0.101: checked
            E.DBGUARD['adopted'][E.DBGUARD_ADOPT3_MARK] = time.time()
            self.assertIsNone(STORE.session_get(toks['portal'], 'portal', 3600))
        finally:
            E.DBGUARD['adopted'] = saved
            guard(False)

    def test_seen_of_sign_ins_over_tidied(self):
        """guard.json (1.0.101): the counter seen of every sign-in ever made stayed - one entry
        each, the whole file written again at each new one. Those of sign-ins over go."""
        import hashlib
        guard(True)
        try:
            toks = [STORE.session_new('portal' if i % 2 else 'admin', 'u%d' % i, 'portal', '', 1)
                    for i in range(300)]
            for i, tok in enumerate(toks):
                STORE.session_get(tok, 'portal' if i % 2 else 'admin', 3600)
            seen = lambda: [s for s in E.DBGUARD['seen'] if s.startswith('sig:x:')]  # noqa: E731
            self.assertGreaterEqual(len(seen()), 300)
            keep = toks[:5]
            for tok in toks[5:]:
                STORE.db.run('DELETE FROM sessions WHERE token_hash = ?',
                             (hashlib.sha256(tok.encode()).hexdigest(),))
            E.dbguard_tidy(STORE)
            held = {'sig:x:%s:*' % E._dbguard_hash(r['token_hash'])
                    for r in STORE.db.rows('SELECT token_hash FROM sessions')}
            self.assertTrue(set(seen()) <= held)
            self.assertFalse([s for s in E.DBGUARD['seen_h'] if s.startswith('sig:x:')
                              and s not in held])
            for i, tok in enumerate(keep):
                self.assertIsNotNone(STORE.session_get(tok, 'portal' if i % 2 else 'admin', 3600))
            E.dbguard_flush(force=True)
            with open(E.DBGUARD_FILE) as f:
                self.assertLessEqual(len([s for s in json.load(f)['seen'] if s.startswith('sig:x:')]),
                                     len(held))
        finally:
            guard(False)

    def test_the_portal_settings_are_guarded(self):
        """The settings that let people in to the portal or hand out keys (1.0.101)."""
        for k in ('portal', 'portal_cert', 'portal_cert_keys', 'portal_local', 'portal_admins_all',
                  'portal_directory', 'portal_who', 'portal_groups', 'portal_enrolers',
                  'portal_sso', 'portal_sso_key', 'portal_krb', 'portal_certlogin',
                  'portal_password_off', 'portal_code', 'portal_local_code', 'portal_cert_auto'):
            self.assertTrue(E.dbguard_setting_kept(k), k)
        self.assertFalse(E.dbguard_setting_kept('portal_title'))
        E.DBGUARD['adopted'] = dict(E.DBGUARD.get('adopted') or {})
        E.DBGUARD['adopted'][E.DBGUARD_ADOPT3_MARK] = time.time()
        STORE.save_setting('portal_cert_keys', 0, 'test')
        guard(True)
        self.assertEqual(E.dbguard_settings(STORE.settings_saved(), STORE)['portal_cert_keys'], 0)
        STORE.db.upsert('settings', 'k', {'k': 'portal_cert_keys', 'v': json.dumps(1),
                                          'at': time.time(), 'by_who': 'x'})
        got = E.dbguard_settings(STORE.settings_saved(), STORE)
        self.assertEqual(got['portal_cert_keys'], 0)

    def test_the_portal_settings_taken_under_it_once(self):
        """Unsigned from before 1.0.101: taken as they are until this node signs them once
        (dbguard_adopt), checked from then on."""
        guard(False)
        STORE.db.upsert('settings', 'k', {'k': 'portal_who', 'v': json.dumps('groups'),
                                          'at': time.time(), 'by_who': 'old'})
        E.DBGUARD['adopted'] = {k: v for k, v in (E.DBGUARD.get('adopted') or {}).items()
                                if k != E.DBGUARD_ADOPT3_MARK}
        guard(True)
        self.assertEqual(E.dbguard_settings(STORE.settings_saved(), STORE)['portal_who'], 'groups')
        E._dbguard_adopt3(STORE)
        self.assertTrue(E.DBGUARD['adopted'].get(E.DBGUARD_ADOPT3_MARK))
        self.assertEqual(E.dbguard_settings(STORE.settings_saved(), STORE)['portal_who'], 'groups')
        STORE.db.upsert('settings', 'k', {'k': 'portal_who', 'v': json.dumps('anyone'),
                                          'at': time.time(), 'by_who': 'x'})
        self.assertEqual(E.dbguard_settings(STORE.settings_saved(), STORE)['portal_who'], 'groups')
        guard(False)

    def test_the_portal_asks_only_a_directory_acme_wrote(self):
        """portal_directory (every way of signing in to the portal) and the recheck (1.0.101)."""
        class Dir(object):
            name = 'corpp'

        class H(object):
            store = STORE
            d = type('D', (), {'dirs': {'corpp': Dir()}})()
        E.CONFIG['portal_directory'] = 'corpp'
        try:
            STORE.db.run("DELETE FROM directories WHERE LOWER(name) = 'corpp'")
            STORE.db.insert('directories', {'name': 'corpp', 'hosts': 'ldap.example', 'port': 636,
                                            'tls': 'ldaps', 'base': 'DC=x', 'user_attr': 'auto',
                                            'enabled': 1})
            self.assertIsNotNone(E.portal_directory(H()))      # the guard off: as before
            guard(True)
            self.assertIsNone(E.portal_directory(H()))         # not acme's: not asked
            E.dbguard_directory_sign(STORE.db, 'corpp')
            self.assertIsNotNone(E.portal_directory(H()))
            # A sign-in of the directory without its DN is no sign-in acme made.
            self.assertFalse(E.portal_dir_still(H(), {'name': 'x', 'data': {'kind': 'directory'}}))
            self.assertTrue(E.portal_dir_still(H(), {'name': 'x', 'data': {'kind': 'local'}}))
        finally:
            E.CONFIG.pop('portal_directory', None)
            guard(False)


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

    def test_downgrade_says_the_sign_in_settings_lost(self):
        """Going back below the version of a sign-in setting switched on (1.0.101): it was
        dropped without a word - "no password" gone, passwords signed people in again."""
        keys = ('admin_password_off', 'portal_password_off', 'admin_certlogin',
                'portal_certlogin', 'admin_krb', 'portal_krb')
        was = {k: E.CONFIG.get(k) for k in keys}

        def lost(version):
            return [w for w in E.downgrade_why_not(STORE, version)
                    if 'sign-in setting' in w or 'portal\'s settings' in w]
        try:
            guard(False)
            self.assertEqual(lost('1.0.98'), [])
            E.CONFIG['admin_password_off'] = 1
            got = lost('1.0.98')
            self.assertEqual(len(got), 1)
            self.assertIn('admin_password_off', got[0])
            self.assertIn('passwords would sign people in again', got[0])
            self.assertEqual(lost('1.0.99'), [])
            E.CONFIG.update(admin_password_off=0, portal_certlogin=1, admin_krb=1)
            got = lost('1.0.99')
            self.assertEqual(len(got), 1)
            self.assertIn('portal_certlogin', got[0])
            self.assertNotIn('admin_krb', got[0])
            self.assertNotIn('passwords would', got[0])
            got = lost('1.0.98')
            self.assertIn('admin_krb', got[0])
            self.assertIn('portal_certlogin', got[0])
            self.assertEqual(lost('1.0.100'), [])
            guard(True)                     # the portal's guard came in 1.0.101
            got = lost('1.0.100')
            self.assertEqual(len(got), 1)
            self.assertIn('portal_certlogin', got[0])
            E.CONFIG['portal_certlogin'] = 0
            self.assertEqual(lost('1.0.100'), [])
        finally:
            guard(False)
            E.CONFIG.update(was)

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
    mod.GUARD_ONCE = os.path.join(TMP, 'root-ssh', 'asks-done.json')
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
            for a in reversed(json.loads(r['v'])):          # the newest of that line
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

    def test_another_ask_written_between_is_no_refusal(self):
        """The row read by the tick, another ask written to it before the helper is asked (the
        page's own refresh): the row is read again with its signatures (1.0.101 - refused as
        "not signed", and marked done: the key was never added)."""
        line = pubkey('raced')
        E.sshkeys_ask(STORE, [E.node_name()], 'add', 'tester', line=line)
        r = next(iter(E.node_key_rows(STORE, 'host:sshkeys:want', E.node_name())))
        a = next(x for x in json.loads(r['v']) if x.get('line') == line)
        E.sshkeys_ask(STORE, [E.node_name()], 'list', 'tester')          # in between
        got = self.W.sshkeys_do(E.sshkeys_root_data(STORE, dict(a, _row=(r['k'], r['v']))))
        self.assertIn('raced', [k['comment'] for k in got['keys']])
        # a refusal for the signature is asked again (a few times), any other is done
        tries = {}
        said = 'db_guard is on: the row this ask comes from is not signed by acme - not acted on'
        self.assertTrue(E.sig_retry(tries, {'id': 'a1'}, said))
        self.assertTrue(E.sig_retry(tries, {'id': 'a1'}, said))
        self.assertFalse(E.sig_retry(tries, {'id': 'a1'}, said))
        self.assertFalse(E.sig_retry(tries, {'id': 'a2'}, 'that ask is older than an hour'))
        self.assertEqual(E.SIG_REFUSED, self.W.SIG_REFUSED)

    def test_a_signed_ask_is_done_once(self):
        """The list of asks done is the node's own row: cleared, the daemon sent a signed add of
        the last hour again - a key taken away came back. The helper does each once (1.0.101)."""
        line = pubkey('once')
        data = self.asked(line)
        fp = self.W.sshkeys_do(data)['keys'][0]['fp']
        self.W.sshkeys_do({'do': 'drop', 'fp': fp, 'user': 'root', 'last_ok': True})
        with self.assertRaises(self.W.Refused) as e:
            self.W.sshkeys_do(data)
        self.assertIn('done here already', str(e.exception))
        self.assertEqual(self.fps(), [])
        # asked again on the pages: a new ask, taken
        got = self.W.sshkeys_do(self.asked(line))
        self.assertEqual(len(got['keys']), 1)
        # the file is root's own: one of somebody else's is not read
        self.assertTrue(self.W._once_read())

    def test_a_key_of_a_sudo_member_needs_the_signed_row(self):
        """A member of wheel/sudo is root with a password (1.0.101): their key as root's."""
        import pwd
        me = pwd.getpwuid(os.geteuid())
        home = os.path.join(TMP, 'home-sudo')
        os.makedirs(home, exist_ok=True)
        W = self.W
        saved = (W.ssh_user, W.lu_may_sudo, W.user_auth_read, W.user_auth_write, W.user_auth_paths,
                 W.normal_users)
        kept = []
        W.ssh_user = lambda name: me
        W.user_auth_read = lambda pw: list(kept)
        W.user_auth_write = lambda pw, lines: kept.__setitem__(slice(None), lines)
        W.user_auth_paths = lambda pw: (home, os.path.join(home, 'authorized_keys'))
        W.normal_users = lambda: []
        try:
            line = pubkey('sudoer')
            W.lu_may_sudo = lambda name: True
            with self.assertRaises(W.Refused):
                W.sshkeys_do({'do': 'add', 'line': line, 'user': 'opsuser'})
            self.assertEqual(kept, [])
            E.sshkeys_ask(STORE, [E.node_name()], 'add', 'tester', line=line, user='opsuser')
            r = next(iter(E.node_key_rows(STORE, 'host:sshkeys:want', E.node_name())))
            a = next(x for x in json.loads(r['v']) if x.get('line') == line)
            data = E.sshkeys_root_data(STORE, dict(a, _row=(r['k'], r['v'])))
            self.assertEqual(len(W.sshkeys_do(data)['keys']), 1)
            # ...not a member: as before, no row needed
            kept[:] = []
            W.lu_may_sudo = lambda name: False
            self.assertEqual(len(W.sshkeys_do({'do': 'add', 'line': line,
                                               'user': 'opsuser'})['keys']), 1)
        finally:
            (W.ssh_user, W.lu_may_sudo, W.user_auth_read, W.user_auth_write, W.user_auth_paths,
             W.normal_users) = saved

    def test_users_made_given_a_password_or_sudo_need_the_signed_row(self):
        """users.ask (1.0.101): add, password and sudo only from a signed row of
        host:users:want, each once; the rest as before."""
        W = self.W
        for r in ({'do': 'add', 'name': 'opsx', 'sudo': True},
                  {'do': 'password', 'name': 'opsx', 'hash': '$6$x'},
                  {'do': 'sudo', 'name': 'opsx', 'on': True}):
            with self.assertRaises(W.Refused) as e:
                W.users_signed(r)
            self.assertIn('db_guard', str(e.exception))
        self.assertIsNone(W.users_signed({'do': 'lock', 'name': 'opsx'}))
        k = E.node_key('host:users:want', E.node_name())
        ask = {'id': 'u1', 'do': 'sudo', 'name': 'opsx', 'on': True, 'at': time.time(), 'by': 't'}
        STORE.set_meta(k, json.dumps([ask]))
        STORE.set_meta(k, json.dumps([ask, dict(ask, id='u2', do='lock')]))   # written between
        q = {'do': 'sudo', 'name': 'opsx', 'on': True,
             'signed': E.signed_ask_row(STORE, (k, json.dumps([ask])), 'u1')}
        once = W.users_signed(q)
        self.assertTrue(once)
        with self.assertRaises(W.Refused):              # another thing than was asked
            W.users_signed(dict(q, on=False))
        W.ask_once_note(once)
        with self.assertRaises(W.Refused) as e:
            W.users_signed(q)
        self.assertIn('done here already', str(e.exception))
        # a row written past acme
        forged_meta(k, json.dumps([dict(ask, id='u3')]))
        with self.assertRaises(W.Refused) as e:
            W.users_signed({'do': 'sudo', 'name': 'opsx', 'on': True, 'signed': E.signed_ask_row(
                STORE, (k, json.dumps([dict(ask, id='u3')])), 'u3')})
        self.assertIn('not signed by acme', str(e.exception))
        self.helper_guard(False)
        self.assertIsNone(W.users_signed({'do': 'sudo', 'name': 'opsx', 'on': True}))

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
