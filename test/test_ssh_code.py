#!/usr/bin/env python3
"""Signing in over SSH with a code from acme (as otp 1.0.178 - 1.0.243).

    python3 test/test_ssh_code.py      (or python3 -m unittest test.test_ssh_code)

1. The gate (acmelib/engine/316): Access-Requests shaped as pam_radius sends them (User-Name,
   User-Password - empty with skip_passwd -, NAS-Identifier, Message-Authenticator, State),
   answered over a real UDP socket on 127.0.0.1 and in this process; a wrong secret or a
   Message-Authenticator that is wrong gets no answer at all, nor one from anywhere but the
   loopback. An app's code good once; mail and SMS codes sent (mocked) and asked in an
   Access-Challenge, asked again after a wrong one, every code still good taken; wrong codes
   counted per name, five in five minutes and even the right code is refused.
2. The tokens: made for an account of the nodes only (the API checks it again), one each, a new
   one in its place, taken away; their rows signed when the guard of root's actions is on.
3. High security: with the code asked and no system password when acme does not answer,
   keyboard-interactive is not a password sign-in, nor root's own block one with a password.
4. The root helper (deploy/acme_web.py): pam_radius's file names 127.0.0.1 and a port of
   18129-18199 only, the PAM block and sshd's lines (KbdInteractiveAuthentication, UsePAM,
   AuthenticationMethods), the block in and out of /etc/pam.d/sshd with nothing else touched.
5. The card of Settings -> SSH server in a browser, in English and in Czech (test/sshcode_page.js).
"""
import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix='acme-sshcode-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402
from acmelib import engine as ENG  # noqa: E402  (the namespace the parts run in)

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)

SENT = []


def fake_send(store, kind, to, code, purpose='admin', name='', lang=None, fmt=None, **kw):
    SENT.append({'kind': kind, 'to': to, 'code': code, 'purpose': purpose, 'name': name, 'lang': lang})
    return ''


class FakeDaemon(object):
    def __init__(self):
        self.store = STORE


def gate():
    """A gate that answers in this process, no thread of its own."""
    g = object.__new__(ENG.SshGate)
    g.d = FakeDaemon()
    return g


def pairs(user, nas='sshd'):
    u = user.encode()
    n = nas.encode()
    # As pam_radius 2.0 sends: User-Name, NAS-Identifier, NAS-Port-Type (Virtual), Service-Type.
    return [bytes([1, len(u) + 2]) + u, bytes([32, len(n) + 2]) + n,
            bytes([61, 6]) + struct.pack('>I', 5), bytes([6, 6]) + struct.pack('>I', 8)]


def ask(user, code, secret=None, state=None, g=None, addr=('127.0.0.1', 40000), with_ma=True):
    secret = (secret if secret is not None else E.ssh_gate_secret(STORE)).encode()
    ps = pairs(user)
    if state:
        ps.append(bytes([24, len(state) + 2]) + state.encode())
    raw, auth = E.build_request(7, ps, secret, password=code, with_ma=with_ma)
    out = (g or gate()).answer(raw, addr)
    if out is None:
        return None
    assert E.reply_ok(out, auth, secret), 'the answer is not signed with the secret'
    p = E.Packet.parse(out)
    return {'code': p.code, 'say': p.text(18), 'state': (p.get(24) or b'').decode(),
            'prompt': p.get(76)}


def app_code(name, when=None):
    rec = E.sshotp_get(STORE, name)
    secret = E.unseal_secret(rec['secret'], E.sshotp_key(name))
    return E.totp(secret, when if when is not None else E.clock_now('codes'))


def clean():
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'sshotp:%' OR k LIKE 'once:%' OR k LIKE 'host:sshd:%'"
                 " OR k LIKE 'host:sshkeys:now:%'")
    E.SSHOTP_FAILS.clear()
    E.SSHOTP_SENT.clear()
    E.SSHOTP_CHALLENGES.clear()
    E.SSHOTP_GONE.clear()
    del SENT[:]


class TestRadiusShapes(unittest.TestCase):
    def test_request_read_back(self):
        secret = b'a-secret-of-the-gate'
        raw, auth = E.build_request(9, pairs('jan'), secret, password='123456')
        p = E.Packet.parse(raw)
        self.assertEqual((p.code, p.ident, p.text(1)), (1, 9, 'jan'))
        self.assertEqual(p.password(secret), '123456')
        self.assertIs(p.message_authenticator_ok(secret), True)
        self.assertIs(p.message_authenticator_ok(b'another'), False)
        # skip_passwd: an empty User-Password, sixteen noughts hidden.
        raw, _ = E.build_request(9, pairs('jan'), secret, password='')
        self.assertEqual(len(E.Packet.parse(raw).get(2)), 16)
        self.assertEqual(E.Packet.parse(raw).password(secret), '')
        # Two Message-Authenticators, or one cut short, is wrong - not missing.
        bad = raw[:2] + struct.pack('>H', len(raw) + 18) + raw[4:] + bytes([80, 18]) + b'\0' * 16
        self.assertIs(E.Packet.parse(bad).message_authenticator_ok(secret), False)
        none, _ = E.build_request(9, pairs('jan'), secret, password='', with_ma=False)
        self.assertIsNone(E.Packet.parse(none).message_authenticator_ok(secret))

    def test_malformed(self):
        for data in (b'', b'\x01' * 19, b'\x01\x01\x00\x30' + b'\0' * 20,
                     b'\x01\x01\x00\x16' + b'\0' * 16 + b'\x01\x01'):
            with self.assertRaises(E.RadiusError):
                E.Packet.parse(data)

    def test_reply_message_only(self):
        self.assertEqual(E.attr_bytes('Reply-Message', 'acme: hi'), b'\x12\x0aacme: hi')
        with self.assertRaises(E.RadiusError):
            E.attr_bytes('Framed-IP-Address', '10.0.0.1')
        with self.assertRaises(E.RadiusError):
            E.attr_bytes('Reply-Message', '')


class TestGate(unittest.TestCase):
    def setUp(self):
        clean()
        E.CONFIG['mail_mode'] = 'smtp'
        self._send, self._ch = ENG.code_send, ENG.code_channels
        ENG.code_send = fake_send
        ENG.code_channels = lambda: ['mail', 'sms']
        E.ssh_gate_secret(STORE, make=True)

    def tearDown(self):
        ENG.code_send, ENG.code_channels = self._send, self._ch

    def test_app_code_once(self):
        got = E.sshotp_make(STORE, 'jan', 'admin', 'Jan')
        self.assertEqual(got['kind'], 'app')
        self.assertTrue(got['qr'].startswith('data:image/'))
        self.assertIn('otpauth://totp/', got['uri'])
        # skip_passwd: nothing typed yet - the gate asks for the app's code itself.
        r = ask('jan', '')
        self.assertEqual(r['code'], 11)
        self.assertEqual(r['say'], 'Kód z aplikace: ')
        self.assertTrue(r['state'])
        self.assertEqual(r['prompt'], struct.pack('!I', 1))       # shown as typed (the default)
        code = app_code('jan')
        r2 = ask('jan', code, state=r['state'])
        self.assertEqual(r2['code'], 2, r2)
        self.assertEqual(r2['say'], 'acme: signed in')
        # The same code again: used already.
        r3 = ask('jan', '')
        r4 = ask('jan', code, state=r3['state'])
        self.assertEqual(r4['code'], 11)                          # asked again
        self.assertEqual(E.sshotp_get(STORE, 'jan')['used_on'], E.node_name())
        ev = [x['words'] for x in STORE.db.rows("SELECT words FROM events WHERE kind = 'ssh' ORDER BY id")]
        self.assertTrue(any('jan signed in to SSH on' in w for w in ev), ev)
        self.assertTrue(any('typed a wrong code' in w and 'used already' in w for w in ev), ev)
        self.assertFalse(any(code in w for w in ev))

    def test_the_code_typed_with_the_password_too(self):
        # pam_radius without skip_passwd (a block from before): the code where the password is.
        E.sshotp_make(STORE, 'eva', 'admin', lang='en')
        self.assertEqual(ask('eva', app_code('eva'))['code'], 2)

    def test_hidden_as_typed(self):
        STORE.set_meta('host:sshd:conf', json.dumps({'manage': True, 'radius': True, 'radius_hide': True}))
        E.sshotp_make(STORE, 'jan', 'admin', lang='en')
        r = ask('jan', '')
        self.assertEqual(r['prompt'], struct.pack('!I', 0))
        self.assertEqual(r['say'], 'Code from the app: ')

    def test_czech_keyboard_row(self):
        E.sshotp_make(STORE, 'jan', 'admin')
        code = app_code('jan')
        row = ''.join('é+ěščřžýáí'[int(c)] for c in code)       # 1 is +, 0 is é
        self.assertEqual(E.ssh_code_typed(row), code)

    def test_mail_challenge(self):
        got = E.sshotp_make(STORE, 'petr', 'admin', kind='mail', dest='petr@example.cz', lang='en')
        self.assertEqual(got['dest'], 'p***@example.cz')
        r = ask('petr', '')
        self.assertEqual(r['code'], 11)
        self.assertTrue(r['say'].startswith('Type the code mailed to p***@example.cz ('), r['say'])
        self.assertEqual(len(SENT), 1)
        self.assertEqual((SENT[0]['purpose'], SENT[0]['to'], SENT[0]['name'], SENT[0]['lang']),
                         ('ssh', 'petr@example.cz', 'petr', 'en'))
        code = SENT[0]['code']
        # A wrong one: asked again, counted.
        bad = '000000' if code != '000000' else '111111'
        r2 = ask('petr', bad, state=r['state'])
        self.assertEqual(r2['code'], 11)
        self.assertEqual(r2['say'], 'That code was not right - type it again: ')
        self.assertEqual(len(E.SSHOTP_FAILS['petr']), 1)
        r3 = ask('petr', code, state=r2['state'])
        self.assertEqual(r3['code'], 2, r3)
        # Good once.
        r4 = ask('petr', '')
        self.assertEqual(r4['code'], 11)
        self.assertEqual(len(SENT), 2)
        ev = [x['words'] for x in STORE.db.rows("SELECT words FROM events WHERE kind = 'ssh'")]
        self.assertFalse(any(code in w or bad in w for w in ev), ev)

    def test_sms_again_within_20s_sends_none(self):
        E.sshotp_make(STORE, 'eva', 'admin', kind='sms', dest='+420777123456')
        r = ask('eva', '')
        r2 = ask('eva', '')
        self.assertEqual((r['code'], r2['code']), (11, 11))
        self.assertEqual(len(SENT), 1)
        self.assertEqual(SENT[0]['kind'], 'sms')
        self.assertIn('+420', r['say'])
        # The code sent first lets in from the second prompt too.
        self.assertEqual(ask('eva', SENT[0]['code'], state=r2['state'])['code'], 2)

    def test_mail_late_still_good(self):
        # Two codes went (the second after 20 s): the first, come late, still lets in once.
        E.sshotp_make(STORE, 'petr', 'admin', kind='mail', dest='petr@example.cz')
        r1 = ask('petr', '')
        E.SSHOTP_SENT['petr'] = [t - 30 for t in E.SSHOTP_SENT['petr']]
        r2 = ask('petr', '')
        self.assertEqual(len(SENT), 2)
        self.assertEqual(ask('petr', SENT[0]['code'], state=r2['state'])['code'], 2)
        self.assertIsNotNone(r1)

    def test_wrong_codes_counted(self):
        E.sshotp_make(STORE, 'jan', 'admin')
        for _ in range(E.SSHOTP_TRIES):
            ok, said = E.sshotp_check(STORE, 'jan', '000000' if app_code('jan') != '000000' else '111111')
            self.assertFalse(ok)
            self.assertEqual(said, 'the code is not right')
        ok, said = E.sshotp_check(STORE, 'jan', app_code('jan'))
        self.assertFalse(ok)
        self.assertIn('too many wrong codes', said)
        # Over the gate: refused as well, said why.
        r = ask('jan', app_code('jan'))
        self.assertEqual(r['code'], 3)
        self.assertIn('too many wrong codes', r['say'])
        # A name nobody has counts too: it cannot be used to guess freely.
        for _ in range(E.SSHOTP_TRIES):
            E.sshotp_check(STORE, 'nobody', '123456')
        self.assertIn('too many', E.sshotp_check(STORE, 'nobody', '123456')[1])
        # Counted in the database too (1.0.44), for every node of the cluster to see.
        self.assertTrue(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'sshfail:jan%'"))
        # Past the window it is asked again.
        E.SSHOTP_FAILS['jan'] = [time.time() - E.SSHOTP_WINDOW_S - 1] * 5
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'sshfail:%'")
        self.assertTrue(E.sshotp_check(STORE, 'jan', app_code('jan', E.clock_now('codes') + 30))[0])

    def test_mail_sends_at_most_five(self):
        E.sshotp_make(STORE, 'petr', 'admin', kind='mail', dest='petr@example.cz')
        for i in range(5):
            r = ask('petr', '')
            self.assertEqual(r['code'], 11)
            E.SSHOTP_SENT['petr'] = [t - 21 for t in E.SSHOTP_SENT['petr']]
        r = ask('petr', '')
        self.assertEqual(r['code'], 3)
        self.assertIn('5 codes in 15 min', r['say'])
        self.assertEqual(len(SENT), 5)

    def test_token_changed_since(self):
        E.sshotp_make(STORE, 'petr', 'admin', kind='mail', dest='petr@example.cz')
        r = ask('petr', '')
        E.sshotp_make(STORE, 'petr', 'admin', kind='mail', dest='other@example.cz', replace=True)
        r2 = ask('petr', SENT[0]['code'], state=r['state'])
        self.assertEqual(r2['code'], 3)
        self.assertIn('the token changed', r2['say'])

    def test_no_answer_without_the_secret(self):
        E.sshotp_make(STORE, 'jan', 'admin')
        self.assertIsNone(ask('jan', app_code('jan'), secret='not-the-gate-secret-at-all'))
        # Not from the loopback: no answer.
        self.assertIsNone(ask('jan', app_code('jan'), addr=('192.0.2.7', 40000)))
        # An Accounting-Request, or anything not an Access-Request: none either.
        secret = E.ssh_gate_secret(STORE).encode()
        raw, _ = E.build_request(1, pairs('jan'), secret, password='1')
        self.assertIsNone(gate().answer(b'\x04' + raw[1:], ('127.0.0.1', 1)))
        # No token for the name: refused, said so.
        r = ask('nobody', '123456')
        self.assertEqual((r['code'], r['say']), (3, 'acme: no SSH token for this account'))

    def test_over_udp(self):
        """The gate's own thread, its own socket on 127.0.0.1, as pam_radius asks it."""
        STORE.set_meta('host:sshd:conf', json.dumps({'manage': True, 'radius': True}))
        E.sshotp_make(STORE, 'jan', 'admin', lang='en')
        g = E.SshGate(FakeDaemon())
        try:
            for _ in range(100):
                if E.SSH_GATE_STATE.get('listening'):
                    break
                time.sleep(0.05)
            self.assertTrue(E.SSH_GATE_STATE['listening'], E.SSH_GATE_STATE)
            port = E.SSH_GATE_STATE['port']
            self.assertTrue(18129 <= port <= 18199)
            self.assertEqual(STORE.get_meta('sshotp:port:' + E.node_name()), str(port))
            self.assertEqual(E.ssh_gate_port(STORE), port)
            secret = E.ssh_gate_secret(STORE).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            try:
                raw, auth = E.build_request(3, pairs('jan'), secret, password='')
                s.sendto(raw, ('127.0.0.1', port))
                out, _ = s.recvfrom(4096)
                self.assertTrue(E.reply_ok(out, auth, secret))
                p = E.Packet.parse(out)
                self.assertEqual(p.code, 11)
                # pam_radius sending the same again: the same answer, nothing new.
                s.sendto(raw, ('127.0.0.1', port))
                again, _ = s.recvfrom(4096)
                self.assertEqual(again, out)
                raw2, auth2 = E.build_request(4, pairs('jan') + [bytes([24, len(p.get(24)) + 2]) + p.get(24)],
                                              secret, password=app_code('jan'))
                s.sendto(raw2, ('127.0.0.1', port))
                out2, _ = s.recvfrom(4096)
                self.assertTrue(E.reply_ok(out2, auth2, secret))
                self.assertEqual(E.Packet.parse(out2).code, 2)
            finally:
                s.close()
        finally:
            g.stop()
        self.assertFalse(E.SSH_GATE_STATE['listening'])

    def test_not_listening_when_off(self):
        self.assertFalse(E.ssh_gate_wanted(STORE))
        STORE.set_meta('host:sshd:conf', json.dumps({'manage': False, 'radius': True}))
        self.assertFalse(E.ssh_gate_wanted(STORE))

    def test_ports(self):
        E.CONFIG['ssh_gate_port'] = 18150
        try:
            got = E.ssh_gate_candidates(STORE)
            self.assertEqual(got[0], 18150)
            self.assertTrue(all(18129 <= p <= 18199 for p in got))
            E.CONFIG['ssh_gate_port'] = 1812
            self.assertTrue(all(18129 <= p <= 18199 for p in E.ssh_gate_candidates(STORE)))
        finally:
            E.CONFIG.pop('ssh_gate_port', None)


class TestTokens(unittest.TestCase):
    def setUp(self):
        clean()

    def test_one_each_and_replaced(self):
        E.sshotp_make(STORE, 'jan', 'admin', 'Jan')
        with self.assertRaises(ValueError):
            E.sshotp_make(STORE, 'JAN', 'admin')
        old = E.sshotp_get(STORE, 'jan')['secret']
        E.sshotp_make(STORE, 'jan', 'admin', replace=True)
        self.assertNotEqual(E.sshotp_get(STORE, 'jan')['secret'], old)
        rows = E.sshotp_all(STORE)
        self.assertEqual([(r['name'], r['kind']) for r in rows], [('jan', 'app')])
        self.assertNotIn('secret', rows[0])
        E.sshotp_remove(STORE, 'jan', 'admin')
        self.assertEqual(E.sshotp_all(STORE), [])
        with self.assertRaises(ValueError):
            E.sshotp_remove(STORE, 'jan', 'admin')
        for bad in ('', 'a b', '-x', 'x' * 65, 'jan;rm'):
            with self.assertRaises(ValueError):
                E.sshotp_make(STORE, bad, 'admin')

    def test_mail_needs_sending_set_up(self):
        was = ENG.code_channels
        ENG.code_channels = lambda: []
        try:
            with self.assertRaises(ValueError):
                E.sshotp_make(STORE, 'jan', 'admin', kind='mail', dest='jan@example.cz')
        finally:
            ENG.code_channels = was
        with self.assertRaises(ValueError):
            E.sshotp_make(STORE, 'jan', 'admin', kind='fax')

    def test_accounts_of_the_nodes(self):
        self.assertIsNone(E.sshotp_accounts(STORE))
        STORE.set_meta('host:sshkeys:now:' + E.node_name(), json.dumps({'users': [{'name': 'jan'}]}))
        STORE.set_meta('host:sshkeys:now:acme2', json.dumps({'users': [{'name': 'eva'}]}))
        self.assertEqual(E.sshotp_accounts(STORE), {'root', 'jan', 'eva'})

    def test_signed_rows(self):
        self.assertTrue(E.dbguard_meta_kept('sshotp:gate'))
        self.assertTrue(E.dbguard_meta_kept('sshotp:u:jan'))
        self.assertTrue(E.dbguard_meta_kept('sshotp:port:acme1'))
        self.assertTrue(E.dbguard_setting_kept('ssh_gate_port'))
        E.CONFIG['db_guard'] = 1
        try:
            E.sshotp_make(STORE, 'jan', 'admin')
            self.assertEqual([r['name'] for r in E.sshotp_all(STORE)], ['jan'])
            # A row written past acme (straight into the database): not there.
            STORE.db.run("UPDATE meta SET v = ? WHERE k = 'sshotp:u:jan'",
                         (json.dumps({'name': 'jan', 'kind': 'mail', 'dest': 'evil@example.cz'}),))
            E.dbguard_forget_seen('test')
            self.assertIsNone(E.sshotp_get(STORE, 'jan'))
            self.assertEqual(E.sshotp_all(STORE), [])
        finally:
            E.CONFIG['db_guard'] = 0

    def test_api_checks_the_account(self):
        class H(object):
            store = STORE

            def me(self, role):
                return {'name': 'admin'}

            def body(self):
                return self.b
        STORE.set_meta('host:sshkeys:now:' + E.node_name(), json.dumps({'users': [{'name': 'jan'}]}))
        h = H()
        h.b = {'action': 'sshotp_add', 'name': 'mallory'}
        with self.assertRaises(E.ApiError) as e:
            E._sshd_do(h)
        self.assertIn('not an account of the nodes', str(e.exception))
        h.b = {'action': 'sshotp_add', 'name': 'jan', 'note': 'Jan'}
        got = E._sshd_do(h)
        self.assertEqual(got['made']['name'], 'jan')
        self.assertEqual([x['name'] for x in got['sshotp']], ['jan'])
        self.assertEqual(got['gate_port'], E.ssh_gate_port(STORE))
        h.b = {'action': 'sshotp_add', 'name': 'jan'}
        with self.assertRaises(E.ApiError):
            E._sshd_do(h)                       # one each
        h.b = {'action': 'sshotp_remove', 'name': 'jan'}
        self.assertEqual(E._sshd_do(h)['sshotp'], [])


class TestSshdConf(unittest.TestCase):
    def setUp(self):
        clean()

    def test_off_by_default(self):
        c = E.sshd_checked_conf({'manage': True})
        self.assertFalse(c['radius'])
        self.assertFalse(E.SSHD_DEFAULT['radius'])
        # Without acme setting the SSH server, never.
        self.assertFalse(E.sshd_checked_conf({'manage': False, 'radius': True})['radius'])

    def test_checked(self):
        c = E.sshd_checked_conf({'manage': True, 'password': False, 'radius': True,
                                 'radius_users': 'jan eva', 'radius_fallback': True,
                                 'radius_with_key': True, 'radius_hide': True})
        self.assertEqual(c['radius_users'], ['jan', 'eva'])
        self.assertFalse(c['radius_fallback'])            # passwords off: no fallback
        self.assertTrue(c['radius_with_key'] and c['radius_hide'])
        with self.assertRaises(ValueError):
            E.sshd_checked_conf({'manage': True, 'radius': True, 'radius_users': ['jan;rm']})

    def test_allow_users_without_root(self):
        """AllowUsers without root (1.0.98): refused unless asked for on purpose (ok_no_root, the
        page asks in words first) - then saved, and said so in the event."""
        self.assertTrue(E.sshd_root_listed([]))
        self.assertTrue(E.sshd_root_listed(['jan', 'root']))
        self.assertTrue(E.sshd_root_listed(['r*']))
        self.assertTrue(E.sshd_root_listed('jan root@10.0.0.*'))
        self.assertFalse(E.sshd_root_listed(['jan', 'eva']))
        self.assertFalse(E.sshd_root_listed('jan ro'))
        b = {'manage': True, 'permit_root': 'prohibit-password', 'password': True,
             'allow_users': ['jan']}
        with self.assertRaises(ValueError) as e:
            E.sshd_save(STORE, dict(b), 'admin')
        self.assertIn('root will not be able to sign in over SSH', str(e.exception))
        c = E.sshd_save(STORE, dict(b, ok_no_root=True), 'admin')
        self.assertEqual(c['allow_users'], ['jan'])
        self.assertNotIn('ok_no_root', c)
        self.assertTrue(E.sshd_root_shut(c))
        ev = STORE.db.rows("SELECT words FROM events WHERE kind = 'settings' ORDER BY id DESC LIMIT 1")[0]['words']
        self.assertIn('root not at all - not in AllowUsers', ev)
        # root not signing in at all, or among them: nothing to ask
        self.assertFalse(E.sshd_root_shut(E.sshd_save(STORE, dict(b, permit_root='no'), 'admin')))
        self.assertFalse(E.sshd_root_shut(E.sshd_save(STORE, dict(b, allow_users=['jan', 'root']), 'admin')))

    def test_saved_makes_the_secret(self):
        self.assertEqual(E.ssh_gate_secret(STORE), '')
        E.sshd_save(STORE, {'manage': True, 'radius': True, 'permit_root': 'prohibit-password'}, 'admin')
        self.assertTrue(len(E.ssh_gate_secret(STORE)) >= 32)
        self.assertTrue(E.ssh_gate_wanted(STORE))
        ev = STORE.db.rows("SELECT words FROM events WHERE kind = 'settings' ORDER BY id DESC LIMIT 1")[0]['words']
        self.assertIn('a code from acme at sign-in (everybody but root', ev)
        v = E.sshd_view(STORE)
        self.assertIn('sshotp', v)
        self.assertIn('gate_port', v)
        self.assertIn('radius', v['nodes'][0])

    def test_selinux_wants(self):
        self.assertNotIn('authlogin_radius', [b['name'] for b in E.selinux_want(STORE)['booleans']])
        STORE.set_meta('host:sshd:conf', json.dumps({'manage': True, 'radius': True}))
        w = E.selinux_want(STORE)
        self.assertIn('authlogin_radius', [b['name'] for b in w['booleans']])
        self.assertIn(('udp', 'radius_port_t'), [(p['proto'], p['type']) for p in w['ports']])
        self.assertTrue(w['facts']['ssh_with_a_code'])


class TestHighSecurity(unittest.TestCase):
    def setUp(self):
        clean()

    def rules(self):
        return {r['rule']: r['bad'] for r in E.hisec_rules(STORE) if r['rule'].startswith('sshd:')}

    def test_code_only_is_not_a_password(self):
        me = E.node_name()
        # Root's own block (key and code): PermitRootLogin yes, keyboard-interactive for the code.
        STORE.set_meta('host:sshd:now:' + me, json.dumps({'values': {
            'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'yes',
            'permitrootlogin': 'yes', 'maxauthtries': '4'}}))
        STORE.set_meta('host:sshd:conf', json.dumps({'manage': True, 'radius': True,
                                                     'radius_fallback': False}))
        got = self.rules()
        self.assertFalse(got['sshd:password'])
        self.assertFalse(got['sshd:root'])
        # With the system password when acme does not answer: a password after all.
        STORE.set_meta('host:sshd:conf', json.dumps({'manage': True, 'radius': True,
                                                     'radius_fallback': True}))
        got = self.rules()
        self.assertTrue(got['sshd:password'])
        self.assertTrue(got['sshd:root'])
        # No code asked at all: keyboard-interactive is the password, as before.
        STORE.set_meta('host:sshd:conf', json.dumps({'manage': True, 'radius': False}))
        self.assertTrue(self.rules()['sshd:password'])

    def test_root_left_out_of_allow_users(self):
        """Root with a password, but not among AllowUsers (1.0.98): it signs in nowhere - not
        "root may sign in over SSH with a password"."""
        me = E.node_name()
        vals = {'passwordauthentication': 'yes', 'permitrootlogin': 'yes', 'maxauthtries': '4'}
        STORE.set_meta('host:sshd:now:' + me, json.dumps({'values': vals}))
        self.assertTrue(self.rules()['sshd:root'])
        STORE.set_meta('host:sshd:now:' + me, json.dumps({'values': dict(vals, allowusers='jan eva')}))
        self.assertFalse(self.rules()['sshd:root'])
        STORE.set_meta('host:sshd:now:' + me, json.dumps({'values': dict(vals, allowusers='jan root')}))
        self.assertTrue(self.rules()['sshd:root'])


def read(path):
    with open(path) as f:
        return f.read()


def helper(etc):
    os.environ['ACME_ETC'] = etc
    os.environ['ACME_NO_PKG'] = '1'
    os.environ['ACME_VIP_NO_SERVICES'] = '1'
    spec = importlib.util.spec_from_file_location('acme_web_sshc%d' % id(etc),
                                                  os.path.join(ROOT, 'deploy', 'acme_web.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHelper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.etc = tempfile.mkdtemp(prefix='acme-sshc-etc-')
        os.makedirs(os.path.join(cls.etc, 'pam.d'))
        cls.H = helper(cls.etc)

    def conf(self, **kw):
        c = {'manage': True, 'port': 22, 'permit_root': 'prohibit-password', 'password': True,
             'tries': 4, 'allow_users': [], 'notice': '', 'radius': True, 'radius_fallback': True}
        c.update(kw)
        return self.H.sshd_checked(c)

    def test_pam_radius_file(self):
        self.H.pam_radius_conf_write('s3cret-of-the-gate', 18131)
        path = self.H.pam_radius_conf_path()
        self.assertTrue(path.startswith(self.etc))
        lines = [l for l in read(path).splitlines() if not l.startswith('#')]
        self.assertEqual(lines, ['127.0.0.1:18131 s3cret-of-the-gate 30 127.0.0.1'])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        for port in (1812, 18128, 18200, 'x'):
            with self.assertRaises(self.H.Refused):
                self.H.pam_radius_conf_write('s3cret-of-the-gate', port)
        for secret in ('', 'short', 'with space in it', 'a' * 129):
            with self.assertRaises(self.H.Refused):
                self.H.pam_radius_conf_write(secret, 18131)
        self.assertEqual(self.H.pam_radius_conf_fp(),
                         E.ssh_gate_fp('s3cret-of-the-gate', 18131))

    def test_pam_block(self):
        b = self.H.pam_block(self.conf()).splitlines()
        self.assertEqual(b[0], self.H.PAM_BEGIN)
        self.assertEqual(b[-1], self.H.PAM_END)
        self.assertEqual(b[1], 'auth [success=1 default=ignore] pam_succeed_if.so quiet user = root')
        self.assertIn('pam_radius_auth.so conf=%s skip_passwd prompt_attribute localifdown'
                      % self.H.pam_radius_conf_path(), b[2])
        b = self.H.pam_block(self.conf(radius_users=['jan', 'eva'], password=False)).splitlines()
        self.assertIn('user notin jan:eva', b[1])
        self.assertNotIn('localifdown', b[2])
        self.assertEqual(b[3], 'auth requisite pam_deny.so')
        b = self.H.pam_block(self.conf(radius_root=True)).splitlines()
        self.assertNotIn('pam_succeed_if', b[1])

    def test_sshd_lines(self):
        t = self.H.sshd_text(self.conf(password=False))
        self.assertIn('KbdInteractiveAuthentication yes', t)
        self.assertIn('PasswordAuthentication no', t)
        self.assertIn('UsePAM yes', t)
        self.assertNotIn('AuthenticationMethods', t)
        t = self.H.sshd_text(self.conf(radius_with_key=True, radius_users=['jan']))
        self.assertIn('Match User jan\n    AuthenticationMethods publickey,keyboard-interactive', t)
        t = self.H.sshd_text(self.conf(radius_with_key=True, radius_root=True))
        self.assertIn('Match User root\n    PermitRootLogin yes\n    PasswordAuthentication no\n'
                      '    AuthenticationMethods publickey,keyboard-interactive', t)
        t = self.H.sshd_text(self.conf(radius=False))
        self.assertIn('KbdInteractiveAuthentication yes', t)        # passwords on, as before
        self.assertNotIn('UsePAM', t)
        t = self.H.sshd_text(self.conf(radius=False, password=False))
        self.assertIn('KbdInteractiveAuthentication no', t)

    def test_block_in_and_out(self):
        pam = os.path.join(self.etc, 'pam.d', 'sshd')
        before = ('#%PAM-1.0\nauth       substack     password-auth\nauth       include      postlogin\n'
                  'account    required     pam_nologin.so\n')
        with open(pam, 'w') as f:
            f.write(before)
        self.H.pam_set(self.conf(), 'the-secret-of-the-gate', 18140)
        text = read(pam)
        self.assertTrue(text.startswith('#%PAM-1.0\n' + self.H.PAM_BEGIN))
        self.assertIn('auth       substack     password-auth', text)
        self.assertIn('127.0.0.1:18140 ', read(self.H.pam_radius_conf_path()))
        # Again: one block, not two.
        self.H.pam_set(self.conf(), 'the-secret-of-the-gate', 18140)
        self.assertEqual(read(pam).count(self.H.PAM_BEGIN), 1)
        # Off: exactly as it was, the file of the secret gone.
        self.H.pam_set({'radius': False}, '', 0)
        self.assertEqual(read(pam), before)
        self.assertFalse(os.path.exists(self.H.pam_radius_conf_path()))

    def test_lockout_and_root_left_out(self):
        """Root's keys matter only where root may sign in (1.0.98): left out of AllowUsers, no
        key of root is no refusal; AllowUsers naming nobody of this machine still is."""
        c = self.conf(radius=False, allow_users=['root'])
        self.assertIn('has none here', self.H.sshd_lockout(c, 0))
        self.assertEqual(self.H.sshd_lockout(c, 1), '')
        c = self.conf(radius=False, password=False, permit_root='yes')
        self.assertIn('nobody would reach', self.H.sshd_lockout(c, 0))
        me = __import__('pwd').getpwuid(os.getuid()).pw_name
        other = 'nobody' if me == 'root' else me
        c = self.conf(radius=False, allow_users=[other])
        self.assertFalse(self.H.sshd_root_listed(c['allow_users']))
        self.assertEqual(self.H.sshd_lockout(c, 0), '')
        c = self.conf(radius=False, allow_users=['no-such-user-here-x'])
        self.assertIn('none of AllowUsers', self.H.sshd_lockout(c, 0))
        self.assertTrue(self.H.sshd_root_listed(['r*']))

    def test_selinux_needs_known(self):
        self.assertIn('authlogin_radius', self.H.SE_BOOLEANS)
        self.assertIn('radius_port_t', self.H.SE_PORT_TYPES)


class TestCardInABrowser(unittest.TestCase):
    """The card of Settings -> SSH server, drawn in a page of its own (test/sshcode_page.js)."""

    def test_card(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(HERE, 'sshcode_page.js'), os.path.join(ROOT, 'web')],
                             capture_output=True, text=True, timeout=240)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main()
