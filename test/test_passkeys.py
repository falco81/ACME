#!/usr/bin/env python3
"""A passkey (Face ID, Touch ID) as the second step of the administration (1.0.51,
docs/admin-second-step.md) - the real route, with a passkey made here as a device makes one (a P-256
key of openssl, CBOR and authenticatorData written by the test):

    python3 test/test_passkeys.py

Never instead of the password; off unless switched on; offered as a way when the second step
is set up; checked at each sign-in (the name, UP and UV, the signature, the counter, once);
reset as the others are; refused on an address; the pages' pieces.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-pk-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAEMON = E.Daemon(STORE, serve=False)
HOST = 'acme.example.test'


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def cbor(v):
    """Enough CBOR to write what a device sends."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, 'big')
    if isinstance(v, bool):
        return bytes([0xf5 if v else 0xf4])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b''.join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b''.join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


class Device(object):
    """A passkey kept on a 'device': a P-256 key, its id, its counter."""
    def __init__(self, count_from=0):
        self.dir = tempfile.mkdtemp(prefix='dev-', dir=TMP)
        self.key = os.path.join(self.dir, 'k.pem')
        subprocess.run(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out',
                        self.key], check=True, capture_output=True)
        der = subprocess.run(['openssl', 'ec', '-in', self.key, '-pubout', '-outform', 'DER'],
                             check=True, capture_output=True).stdout
        pt = der[-65:]
        self.x, self.y = pt[1:33], pt[33:]
        self.id = os.urandom(32)
        self.count = count_from

    def sign(self, data):
        p = os.path.join(self.dir, 'd')
        with open(p, 'wb') as f:
            f.write(data)
        return subprocess.run(['openssl', 'dgst', '-sha256', '-sign', self.key, p], check=True,
                              capture_output=True).stdout

    def auth_data(self, host, flags, attested=False):
        ad = hashlib.sha256(host.encode()).digest() + bytes([flags]) + self.count.to_bytes(4, 'big')
        if attested:
            cose = cbor({1: 2, 3: -7, -1: 1, -2: self.x, -3: self.y})
            ad += b'\x00' * 16 + len(self.id).to_bytes(2, 'big') + self.id + cose
        return ad

    def create(self, opts, host=HOST, origin=None, flags=0x45):
        cd = json.dumps({'type': 'webauthn.create', 'challenge': opts['publicKey']['challenge'],
                         'origin': origin or 'https://' + host}).encode()
        att = cbor({'fmt': 'none', 'attStmt': {}, 'authData': self.auth_data(host, flags, True)})
        return {'clientDataJSON': b64u(cd), 'attestationObject': b64u(att)}

    def get(self, opts, host=HOST, origin=None, flags=0x05, bad_sig=False):
        if self.count:
            self.count += 1
        cd = json.dumps({'type': 'webauthn.get', 'challenge': opts['publicKey']['challenge'],
                         'origin': origin or 'https://' + host}).encode()
        ad = self.auth_data(host, flags)
        sig = self.sign(ad + hashlib.sha256(cd).digest())
        if bad_sig:
            sig = self.sign(b'something else')
        return {'id': b64u(self.id), 'clientDataJSON': b64u(cd),
                'authenticatorData': b64u(ad), 'signature': b64u(sig)}


class Passkeys(unittest.TestCase):
    def setUp(self):
        E.CONFIG.update(admin_2fa=1, admin_2fa_app=1, admin_2fa_passkey=1, admin_2fa_mail=0,
                        admin_2fa_sms=0)
        for n in ('boss',):
            if not STORE.account(n):
                STORE.add_account(n, 'fulladmin', 'A-Long-Password-1!')
            E.mfa_reset(STORE, n, 'test')
        DAEMON.login_fails.clear()
        self.token = STORE.session_new('admin', 'boss', 'fulladmin', '127.0.0.1', 1,
                                       data={'mfa': 'enrol'})

    def tearDown(self):
        E.CONFIG.update(admin_2fa=0, admin_2fa_passkey=0)

    def call(self, body, host=HOST, stage=None):
        store, token = STORE, self.token

        class H(E.CliApiHandler):
            def session(self, kind='admin'):
                s = store.session_get(token, 'admin', 3600, touch=False)
                return s
        h = H(DAEMON, 'boss', body, {}, '/api/auth/mfa')
        if host:
            h.headers['X-Acme-Host'] = host
        return E.ROUTES[('POST', '/api/auth/mfa')](h)

    def err(self, body, **kw):
        try:
            self.call(body, **kw)
        except E.ApiError as e:
            return e.status, str(e)
        self.fail('not refused: %r' % body)

    def view(self):
        store, token = STORE, self.token

        class H(E.CliApiHandler):
            def session(self, kind='admin'):
                return store.session_get(token, 'admin', 3600, touch=False)
        return E.ROUTES[('GET', '/api/auth/mfa')](H(DAEMON, 'boss', {}, {}, '/api/auth/mfa'))

    def enrol(self, dev):
        opts = self.call({'action': 'enrol_start', 'kind': 'passkey'})
        got = self.call(dict(dev.create(opts), action='enrol_confirm', kind='passkey',
                             name='iPad · test'))
        self.assertTrue(got['done'])
        rec = E.mfa_get(STORE, 'boss')
        self.assertEqual(rec['kind'], 'passkey')
        self.assertEqual(rec['keys'][0]['host'], HOST)
        self.assertTrue(STORE.account('boss')['mfa_on'])
        self.token = STORE.session_new('admin', 'boss', 'fulladmin', '127.0.0.1', 1,
                                       data={'mfa': 'check'})

    def test_offered_only_when_switched_on_and_for_the_administration(self):
        self.assertIn('passkey', self.view()['methods'])
        self.assertNotIn('passkey', E.mfa_methods('portal'))
        E.CONFIG['admin_2fa_passkey'] = 0
        self.assertNotIn('passkey', self.view()['methods'])
        self.assertEqual(self.err({'action': 'enrol_start', 'kind': 'passkey'})[0], 400)

    def test_set_up_then_signed_in_with_it(self):
        dev = Device()
        self.enrol(dev)
        v = self.view()
        self.assertEqual((v['stage'], v['kind'], v['passkey_hosts']), ('check', 'passkey', [HOST]))
        opts = self.call({'action': 'pk_begin'})
        self.assertEqual(opts['publicKey']['rpId'], HOST)
        self.assertEqual(opts['publicKey']['userVerification'], 'required')
        got = self.call(dict(dev.get(opts), action='check'))
        self.assertTrue(got['done'] and got.get('token'))
        self.assertTrue(E.mfa_get(STORE, 'boss')['keys'][0]['last_used'])

    def test_what_is_refused(self):
        dev = Device(count_from=5)
        # never on an address, never without a name
        self.assertIn('not by an address', self.err({'action': 'enrol_start', 'kind': 'passkey'},
                                                    host='192.0.2.5')[1])
        # no face, finger or PIN (UV) - no second step
        opts = self.call({'action': 'enrol_start', 'kind': 'passkey'})
        self.assertIn('face', self.err(dict(dev.create(opts, flags=0x41), action='enrol_confirm',
                                            kind='passkey'))[1])
        # another page's origin; the question asked once only
        opts = self.call({'action': 'enrol_start', 'kind': 'passkey'})
        bad = dev.create(opts, origin='https://evil.example')
        self.assertIn('another page', self.err(dict(bad, action='enrol_confirm', kind='passkey'))[1])
        self.assertIn('answered already', self.err(dict(dev.create(opts), action='enrol_confirm',
                                                        kind='passkey'))[1])
        self.enrol(dev)
        # a wrong signature, another name, a question used twice, the counter going back
        opts = self.call({'action': 'pk_begin'})
        self.assertIn('signature', self.err(dict(dev.get(opts, bad_sig=True), action='check'))[1])
        opts = self.call({'action': 'pk_begin'})
        DAEMON.login_fails.clear()
        self.assertIn('another name', self.err(dict(dev.get(opts, host='other.example.test',
                                                            origin='https://' + HOST),
                                                    action='check'))[1])
        opts = self.call({'action': 'pk_begin'})
        ans = dev.get(opts)
        self.assertTrue(self.call(dict(ans, action='check'))['done'])
        self.token = STORE.session_new('admin', 'boss', 'fulladmin', '127.0.0.1', 1,
                                       data={'mfa': 'check'})
        DAEMON.login_fails.clear()
        opts = self.call({'action': 'pk_begin'})
        dev.count = 2                                   # went back from 6
        self.assertIn('went back', self.err(dict(dev.get(opts), action='check'))[1])
        # an unknown passkey
        opts = self.call({'action': 'pk_begin'})
        self.assertIn('not known', self.err(dict(Device().get(opts), action='check'))[1])

    def test_your_account(self):
        """Your account (1.0.53): listed, a second added, renamed, taken away - not the last."""
        dev = Device()
        self.enrol(dev)
        token = STORE.session_new('admin', 'boss', 'fulladmin', '127.0.0.1', 1, data={})

        def acc(method, body=None):
            class H(E.CliApiHandler):
                def session(self, kind='admin'):
                    return STORE.session_get(token, 'admin', 3600, touch=False)
            h = H(DAEMON, 'boss', body or {}, {}, '/api/auth/passkeys')
            h.headers['X-Acme-Host'] = HOST
            return E.ROUTES[(method, '/api/auth/passkeys')](h)
        got = acc('GET')
        self.assertTrue(got['on'])
        self.assertEqual(len(got['keys']), 1)
        self.assertNotIn('pem', got['keys'][0])
        two = Device()
        opts = acc('POST', {'action': 'add_begin'})
        self.assertEqual(len(opts['publicKey']['excludeCredentials']), 1)
        got = acc('POST', dict(two.create(opts), action='add_finish', name='Mac'))
        self.assertEqual([k['name'] for k in got['keys']], ['iPad · test', 'Mac'])
        kid = got['keys'][0]['id']
        got = acc('POST', {'action': 'rename', 'id': kid, 'name': 'iPad pracovní'})
        self.assertEqual(got['keys'][0]['name'], 'iPad pracovní')
        got = acc('POST', {'action': 'delete', 'id': kid})
        self.assertEqual([k['name'] for k in got['keys']], ['Mac'])
        with self.assertRaises(E.ApiError) as cm:
            acc('POST', {'action': 'delete', 'id': got['keys'][0]['id']})
        self.assertEqual(cm.exception.status, 409)              # the last one stays
        # the second one signs in
        self.token = STORE.session_new('admin', 'boss', 'fulladmin', '127.0.0.1', 1,
                                       data={'mfa': 'check'})
        opts = self.call({'action': 'pk_begin'})
        self.assertTrue(self.call(dict(two.get(opts), action='check'))['done'])
        # switched off: nothing of it
        E.CONFIG['admin_2fa_passkey'] = 0
        with self.assertRaises(E.ApiError) as cm:
            acc('POST', {'action': 'add_begin'})
        self.assertEqual(cm.exception.status, 403)
        self.assertFalse(acc('GET')['on'])

    def test_reset_as_the_others(self):
        self.enrol(Device())
        self.assertTrue(E.mfa_reset(STORE, 'boss', 'admin'))
        self.assertIsNone(E.mfa_get(STORE, 'boss'))
        self.assertFalse(STORE.account('boss')['mfa_on'])
        self.assertEqual(E.mfa_stage(STORE, 'boss'), 'enrol')

    def test_the_parts(self):
        # COSE keys of the three algorithms to PEM openssl reads
        dev = Device()
        pem, alg = E.pk_cose_pem({1: 2, 3: -7, -1: 1, -2: dev.x, -3: dev.y})
        self.assertEqual(alg, -7)
        data = b'hello'
        self.assertTrue(E.pk_verify(pem, -7, data, dev.sign(data)))
        self.assertFalse(E.pk_verify(pem, -7, b'other', dev.sign(data)))
        with self.assertRaises(ValueError):
            E.pk_cose_pem({1: 3, 3: -257, -1: b'\x01' * 128, -2: b'\x01\x00\x01'})   # 1024 bits
        self.assertEqual(E.pk_cbor(cbor({'a': [1, -2, b'x', True]}))[0], {'a': [1, -2, b'x', True]})

    def test_the_pages(self):
        js = open(os.path.join(ROOT, 'web', 'assets', 'core.js')).read()
        for bit in ("action: 'pk_begin'", 'navigator.credentials.get', 'navigator.credentials.create',
                    "kind: 'passkey'", 'NotAllowedError'):
            self.assertIn(bit, js)
        self.assertIn('admin_2fa_passkey', E.DEFAULTS)
        self.assertEqual(E.DEFAULTS['admin_2fa_passkey'], 0)


if __name__ == '__main__':
    unittest.main()
