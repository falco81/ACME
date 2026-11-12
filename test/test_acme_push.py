#!/usr/bin/env python3
"""acme push (docs/acme-push-protocol.md): both ends, without a network.

    python3 test/test_acme_push.py        (or python3 -m unittest test.test_acme_push)

The receiver is the engine's own (acmelib/engine/467_certificates_pushed_here_by.py),
the sender the target module acme_push; the HTTP between them is handed over
in-process the way the PHP page hands it to the daemon. One acme pushes to
itself here - the receiver's keys and the sender's are kept apart all the same.

What is tried: the cryptography against RFC 8032 / RFC 7748 and against
`cryptography` (the pure Python and the module agree), the test vectors of
the document, pairing (a wrong code, a code used up), the signature, the clock,
a replay, a key not paired, the names, the slots, a push twice (already), a
dual certificate, Try that changes nothing, Discover and what it makes.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-push-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "app1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401  (the engine, as the daemon loads it)
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, api_push, runtime, store as S  # noqa: E402
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
E.CONFIG['acme_node_name'] = 'app1.example.test'
S.registry()
NODE = E.node_name()
SLOT = 'node:' + NODE
CERTS = {}


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


def read(p):
    with open(p) as fh:
        return fh.read()


def setUpModule():
    j = lambda n: os.path.join(TMP, n)  # noqa: E731
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', j('ca.key'), '-out', j('ca.crt'), '-days', '30', '-subj', '/CN=Push CA')
    for leaf, names, kind in (('a', 'app1.example.test', 'ec'), ('b', 'app1.example.test', 'ec'),
                              ('r', 'app1.example.test', 'rsa'),
                              ('o', 'other.example.test', 'ec'),
                              ('w', '*.example.test', 'ec')):
        if kind == 'ec':
            key = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256']
        else:
            key = ['-newkey', 'rsa:2048']
        openssl('req', *key, '-nodes', '-keyout', j(leaf + '.key'), '-out', j(leaf + '.csr'),
                '-subj', '/CN=' + names.split(',')[0])
        with open(j(leaf + '.ext'), 'w') as fh:
            fh.write('subjectAltName=' + ','.join('DNS:' + n for n in names.split(',')) + '\n')
        openssl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j('ca.crt'), '-CAkey', j('ca.key'),
                '-CAcreateserial', '-days', '10', '-out', j(leaf + '.crt'), '-extfile',
                j(leaf + '.ext'))
        CERTS[leaf] = (read(j(leaf + '.crt')), read(j(leaf + '.key')), names.split(','))


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class Bundle(base.Bundle):
    def __init__(self, leaf='a', alt=None):
        self.cert_pem, self.key_pem, self.names = CERTS[leaf]
        self.chain_pems = [read(os.path.join(TMP, 'ca.crt'))]
        self.fullchain_pem = self.cert_pem + self.chain_pems[0]
        self.name = self.names[0]
        der = base64.b64decode(''.join(self.cert_pem.strip().splitlines()[1:-1]))
        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.not_after = time.time() + 86400
        self.serial = leaf
        self.key_type = 'rsa-2048' if leaf == 'r' else 'ec-256'
        self.alt = Bundle(alt) if alt else None


class Wire(object):
    """What the PHP page and the daemon do with a request of acme's: the body as it
    came, the X-Acme-Push-* headers - to the engine's push_handle()."""
    def __init__(self):
        self.seen = []
        self.tamper = None

    def __call__(self, method, url, body=None, headers=None, **kw):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        op = q['api'][0][len('acme-push-'):]
        raw = body or b''
        h = {k: v for k, v in (headers or {}).items() if k.startswith('X-Acme-Push-')}
        if self.tamper:
            raw, h = self.tamper(op, raw, h)
        self.seen.append((method, op, raw, dict(h)))
        st, out = E.push_handle(STORE, op, raw, h)
        return st, {'Content-Type': 'application/json'}, json.dumps(out).encode()


def ctx_for(name='app', wire=None):
    c = runtime.RunContext(STORE, None, scope='target:%s' % name)
    c.http = wire or Wire()
    return c


def target(cfg=None, wire=None, name='app'):
    cls = S.plugin_class('target', 'acme_push')
    ctx = ctx_for(name, wire)
    t = cls(dict({'url': 'https://app1.example.test/admin/'}, **(cfg or {})), ctx)
    t._sleep = lambda s: None
    return t, ctx


def receiver_reset(on=True):
    for k in ('acme_push:conf', 'acme_push:nonces', 'web:tls:' + NODE, 'web:tls:vip'):
        STORE.db.run('DELETE FROM meta WHERE k = ?', (k,))
    STORE.db.run('DELETE FROM meta WHERE k LIKE ?', ('certs:kv:target:%',))
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'acme_push:pin:%'")
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'acme:care:%'")
    if on:
        E.push_card_do(STORE, {'action': 'on'}, 'tester')


def code():
    return E.push_card_do(STORE, {'action': 'pair'}, 'tester')['code']


class Crypto(unittest.TestCase):
    def both(self, fn):
        """fn() with `cryptography`, and with the pure Python of the engine."""
        a = fn()
        real = E._push_crypto
        E._push_crypto = lambda: None
        try:
            b = fn()
        finally:
            E._push_crypto = real
        self.assertEqual(a, b)
        return a

    def test_rfc8032_ed25519(self):
        sk = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
        pk = self.both(lambda: E.ed25519_public(sk))
        self.assertEqual(pk.hex(), 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        sig = self.both(lambda: E.ed25519_sign(sk, b''))
        self.assertEqual(sig.hex(), 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
                                    '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.assertTrue(self.both(lambda: E.ed25519_verify(pk, b'', sig)))
        self.assertFalse(self.both(lambda: E.ed25519_verify(pk, b'x', sig)))
        bad = bytes([sig[0] ^ 1]) + sig[1:]
        self.assertFalse(self.both(lambda: E.ed25519_verify(pk, b'', bad)))

    def test_rfc7748_x25519(self):
        k = bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
        u = bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
        self.assertEqual(self.both(lambda: E.x25519(k, u)).hex(),
                         'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')
        a = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        self.assertEqual(self.both(lambda: E.x25519_public(a)).hex(),
                         '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')

    def test_rfc5869_hkdf(self):
        got = E.hkdf_sha256(bytes([0x0b] * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)), 42)
        self.assertEqual(got.hex(), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
                                    '34007208d5b887185865')

    def test_gcm_both_ways(self):
        k, n = bytes(range(32)), bytes(range(12))
        for size in (0, 1, 15, 16, 17, 250):
            data = os.urandom(size)
            ct = self.both(lambda: E.aes256gcm(k, n, data, b'aad'))
            self.assertEqual(self.both(lambda: E.aes256gcm(k, n, ct, b'aad', open_=True)), data)
            with self.assertRaises(ValueError):
                E.aes256gcm(k, n, ct, b'other', open_=True)

    def test_vectors_of_the_document(self):
        """The values docs/acme-push-protocol.md shows: printed with -v."""
        seed = bytes(range(32))                          # acme's Ed25519 key
        app = bytes(range(32, 64))                       # the server's X25519 key
        eph = bytes(range(64, 96))                       # the sender's ephemeral X25519
        nonce = bytes(range(96, 108))
        app_id = '00112233445566778899aabbccddeeff'
        pub = E.ed25519_public(seed)
        kid = E.push_key_id(pub)
        body = b'{"slots": ["auto"]}'
        canon = E.push_canonical('inventory', app_id, kid, 1793534400, 'n0nce-0123456789ab', body)
        h = E.push_signed(seed, 'inventory', app_id, body, ts=1793534400,
                          nonce='n0nce-0123456789ab')
        fp = 'ab' * 32
        sealed = self.both(lambda: E.push_seal_key('KEY\n', E.x25519_public(app), app_id, fp,
                                                   eph=eph, nonce=nonce))
        self.assertEqual(E.push_open_key(sealed, app, app_id, fp), 'KEY\n')
        with self.assertRaises(E.PushError):
            E.push_open_key(sealed, app, app_id, 'cd' * 32)
        shared = E.x25519(eph, E.x25519_public(app))
        aes = E.hkdf_sha256(shared, E.x25519_public(eph) + E.x25519_public(app),
                            b'acme-push/1 key_pem')
        out = {'acme_public': E.push_b64(pub), 'key_text': E.push_key_text(pub, 'acme@acme1'),
               'key_id': kid, 'canonical': canon.decode(), 'headers': h,
               'app_public': E.push_b64(E.x25519_public(app)), 'shared': shared.hex(),
               'aes_key': aes.hex(), 'aad': E.push_aad(app_id, fp).decode(), 'sealed': sealed,
               'proof': E.push_proof('ABCD-EFGH-JKMN-PQRS', 'pair', app_id, kid,
                                     'n0nce-0123456789ab')}
        if '-v' in sys.argv and os.environ.get('PUSH_VECTORS'):
            print(json.dumps(out, indent=2))
        # Kept as the document says them: a change here is a change of the protocol.
        self.assertEqual(kid, hashlib.sha256(pub).hexdigest()[:16])
        self.assertEqual(sealed['ct'], VECTOR['ct'])
        self.assertEqual(h['X-Acme-Push-Signature'], VECTOR['sig'])
        self.assertEqual(out['proof'], VECTOR['proof'])


VECTOR = {
    'ct': '2UbSrj9NwnCBu3qZW4U7MzxzlGw=',
    'sig': ('7nqJW4/NR3Et6pZx3B8qS3rvQGaQR0UTlNdptpRs4lxaZtc3Cf2zBRkOWPB0tV/rmQNfwbcl2/FKJ3Pu2h/'
            'bDg=='),
    'proof': 'e8e1978c03896460ce7f6e1697d5a5220c8f3a1cd8a01d2fc2e838dbd9318b39',
}


class Receiver(unittest.TestCase):
    def setUp(self):
        receiver_reset()

    def paired(self, **cfg):
        t, ctx = target(dict({'pair_code': code()}, **cfg))
        t.test()
        return t, ctx

    def test_hello_off_says_little(self):
        receiver_reset(on=False)
        st, out = E.push_handle(STORE, 'hello', b'', {})
        self.assertEqual(st, 200)
        self.assertFalse(out['on'])
        self.assertNotIn('enc_key', out)
        t, _ = target()
        with self.assertRaises(base.PluginError) as e:
            t.test()
        self.assertIn('switch it on', str(e.exception))
        st, out = E.push_handle(STORE, 'install', b'{}', {})
        self.assertEqual((st, out['code']), (403, 'off'))

    def test_not_paired_says_how(self):
        t, _ = target()
        with self.assertRaises(base.PluginError) as e:
            t.test()
        self.assertIn('Pairing code', str(e.exception))
        self.assertIn('acme-push-ed25519 ', str(e.exception))

    def test_pairing_and_test_change_nothing(self):
        before = E.tls_profile(STORE, NODE)
        t, ctx = self.paired()
        said = t.test()
        self.assertIn(SLOT, said)
        self.assertEqual(E.tls_profile(STORE, NODE), before)
        pin = ctx.push_pin(t.base_url())
        self.assertEqual(pin['how'], 'pairing code')
        conf = E.push_conf(STORE)
        self.assertEqual(len(conf['keys']), 1)
        self.assertIsNone(conf['pairing'], 'a code is used once')
        # The code is gone: a second acme cannot pair with it.
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'acme_push:pin:%'")
        t2, _ = target({'pair_code': 'AAAA-BBBB-CCCC-DDDD'}, name='other')
        with self.assertRaises(base.PluginError) as e:
            t2.test()
        self.assertIn('pairing_closed', str(e.exception))

    def test_the_route_php_hands_on(self):
        """POST /api/acme-push/<op> {body: base64 of the body as it came, headers: {...}}."""
        t, ctx = self.paired()
        box, me = E.push_box(STORE), E.push_identity(STORE)
        raw = b'{}'

        class H(object):
            store = STORE
            headers = E.push_signed(me['seed'], 'inventory', box['app_id'], raw)
            got = []

            def body(self):
                return {'body': base64.b64encode(raw).decode(),
                        'headers': {k[len('X-Acme-Push-'):]: v for k, v in self.headers.items()}}

            def send_json(self, data, status=200):
                self.got.append((status, data))
        fn = E.ROUTES[('POST', '/api/acme-push/inventory')]
        h = H()
        fn(h)
        self.assertEqual(h.got[0][0], 200)
        self.assertEqual(h.got[0][1]['slots'][0]['id'], SLOT)
        fn(h)
        self.assertEqual(h.got[1][0], 401)
        E.ROUTES[('GET', '/api/acme-push/hello')](h)
        self.assertEqual(h.got[2][1]['app_id'], box['app_id'])

    def test_try_asks_and_changes_nothing(self):
        t, ctx = self.paired()
        ctx.http.seen[:] = []
        t.test()
        self.assertEqual([x[1] for x in ctx.http.seen], ['hello', 'inventory'])
        t.action('discover')
        self.assertEqual(ctx.http.seen[-1][1], 'inventory')
        self.assertNotIn('install', [x[1] for x in ctx.http.seen])

    def test_tried_before_it_was_saved(self):
        """Try on a form not saved yet pairs it for the target saved after."""
        t, _ = target({'pair_code': code()}, name='unsaved')
        t.test()
        t2, _ = target({'pair_code': ''}, name='app')
        self.assertIn(SLOT, t2.deploy(Bundle('a'), {}))

    def test_wrong_code_burns_it(self):
        right = code()
        for i in range(E.PUSH_CODE_TRIES):
            t, _ = target({'pair_code': 'WRNG-WRNG-WRNG-WRN%d' % i})
            with self.assertRaises(base.PluginError) as e:
                t.test()
            self.assertIn('bad_code', str(e.exception))
        t, _ = target({'pair_code': right})
        with self.assertRaises(base.PluginError) as e:
            t.test()
        self.assertIn('pairing_closed', str(e.exception))
        self.assertEqual(E.push_conf(STORE)['keys'], [])

    def test_pasted_key_and_first_seen(self):
        me = E.push_identity(STORE)
        E.push_card_do(STORE, {'action': 'key_add', 'key': me['text']}, 'tester')
        t, ctx = target()
        t.test()
        self.assertEqual(ctx.push_pin(t.base_url())['how'], 'first seen')
        # The server's keys change (a reinstall, or somebody in between): refused.
        STORE.db.run('DELETE FROM meta WHERE k = ?', ('acme_push:box',))
        with self.assertRaises(base.PluginError) as e:
            t.test()
        self.assertIn('not the one paired', str(e.exception))

    def test_card_words_as_ai(self):
        """The card is ai's: switch {on}, pair_stop, key_forget {key_id}, a name for a
        pasted key, and key_id / how / enc_key / last.acme / last.said in the view."""
        E.push_card_do(STORE, {'action': 'switch', 'on': True}, 'tester')
        self.assertTrue(E.push_conf(STORE)['on'])
        E.push_card_do(STORE, {'action': 'pair'}, 'tester')
        v = E.push_card_do(STORE, {'action': 'pair_stop'}, 'tester')['view']
        self.assertIsNone(v['pairing'])
        self.assertTrue(v['enc_key'])
        me = E.push_identity(STORE)
        v = E.push_card_do(STORE, {'action': 'key_add', 'key': me['text'], 'name': 'acme1'},
                           'tester')['view']
        k = v['keys'][0]
        self.assertEqual((k['key_id'], k['name'], k['how']), (me['id'], 'acme1', 'pasted'))
        t, _ = target()
        t.deploy(Bundle('a'), {})
        last = E.push_view(STORE)['last']
        self.assertEqual(last['acme'], 'acme1')
        self.assertIn(SLOT, last['said'])
        v = E.push_card_do(STORE, {'action': 'key_forget', 'key_id': me['id']}, 'tester')['view']
        self.assertEqual(v['keys'], [])
        E.push_card_do(STORE, {'action': 'switch', 'on': False}, 'tester')
        self.assertFalse(E.push_conf(STORE)['on'])

    def test_signature_clock_replay_key(self):
        t, ctx = self.paired()
        box = E.push_box(STORE)
        me = E.push_identity(STORE)
        raw = b'{}'
        h = E.push_signed(me['seed'], 'inventory', box['app_id'], raw)
        self.assertEqual(E.push_handle(STORE, 'inventory', raw, h)[0], 200)
        st, out = E.push_handle(STORE, 'inventory', raw, h)
        self.assertEqual((st, out['code']), (401, 'replay'))
        h = E.push_signed(me['seed'], 'inventory', box['app_id'], raw)
        st, out = E.push_handle(STORE, 'inventory', b'{ }', h)
        self.assertEqual(out['code'], 'bad_signature')
        h = E.push_signed(me['seed'], 'install', box['app_id'], raw)
        self.assertEqual(E.push_handle(STORE, 'inventory', raw, h)[1]['code'], 'bad_signature',
                         'signed for another request')
        h = E.push_signed(me['seed'], 'inventory', 'f' * 32, raw)
        self.assertEqual(E.push_handle(STORE, 'inventory', raw, h)[1]['code'], 'bad_signature',
                         'signed for another server')
        h = E.push_signed(me['seed'], 'inventory', box['app_id'], raw, ts=time.time() - 400)
        self.assertEqual(E.push_handle(STORE, 'inventory', raw, h)[1]['code'], 'stale')
        h = E.push_signed(me['seed'], 'inventory', box['app_id'], raw, ts=time.time() + 400)
        self.assertEqual(E.push_handle(STORE, 'inventory', raw, h)[1]['code'], 'stale')
        h = E.push_signed(os.urandom(32), 'inventory', box['app_id'], raw)
        self.assertEqual(E.push_handle(STORE, 'inventory', raw, h)[1]['code'], 'unknown_key')
        st, out = E.push_handle(STORE, 'inventory', raw, {})
        self.assertEqual(out['code'], 'unsigned')
        # Forgotten on the card: nothing more is taken from it.
        E.push_card_do(STORE, {'action': 'key_forget', 'id': me['id']}, 'tester')
        h = E.push_signed(me['seed'], 'inventory', box['app_id'], raw)
        self.assertEqual(E.push_handle(STORE, 'inventory', raw, h)[1]['code'], 'not_paired')

    def test_deploy_names_already_and_dual(self):
        t, ctx = self.paired()
        b = Bundle('a')
        said = t.deploy(b, {})
        self.assertIn(SLOT, said)
        prof = E.tls_profile(STORE, NODE)
        self.assertEqual(prof['info']['fingerprint'].replace(':', '').lower(), b.fingerprint)
        self.assertTrue(prof['how'].startswith('acme push'))
        self.assertFalse(E.acme_care(STORE, NODE), 'its own ACME leaves it alone')
        self.assertEqual(E.unseal_secret(prof['key'], 'web:tls').strip(), b.key_pem.strip())
        self.assertIn('already', t.deploy(b, {}))
        self.assertIn(SLOT, t.deploy(b, {'force': True}))
        # Another name: refused, and nothing changed.
        with self.assertRaises(base.PluginError) as e:
            t.deploy(Bundle('o'), {'slots': SLOT})
        self.assertIn('(names)', str(e.exception))
        with self.assertRaises(base.PluginError) as e:
            t.deploy(Bundle('o'), {})
        self.assertIn('no slot here', str(e.exception))
        # ...unless the server allows other names and acme says so.
        with self.assertRaises(base.PluginError):
            t.deploy(Bundle('o'), {'slots': SLOT, 'check_names': False})
        E.push_card_do(STORE, {'action': 'other_names', 'on': True}, 'tester')
        self.assertIn(SLOT, t.deploy(Bundle('o'), {'slots': NODE, 'check_names': False}))
        # A wildcard covers the node's name; a dual one brings its twin.
        d = Bundle('w', alt=None)
        self.assertIn(SLOT, t.deploy(d, {}))
        dual = Bundle('b', alt='r')
        t.deploy(dual, {})
        prof = E.tls_profile(STORE, NODE)
        self.assertEqual(E.tls_alt(prof)['info']['fingerprint'].replace(':', '').lower(),
                         dual.alt.fingerprint)
        self.assertIsNone(t.verify(dual, {'verify_served': False}))
        # No such slot.
        with self.assertRaises(base.PluginError) as e:
            t.deploy(b, {'slots': 'vip'})
        self.assertIn('no_slot', str(e.exception))

    def test_key_not_of_the_cert_and_tampered(self):
        t, ctx = self.paired()
        b = Bundle('a')
        b.key_pem = CERTS['b'][1]
        with self.assertRaises(base.PluginError) as e:
            t.deploy(b, {})
        self.assertIn('key_mismatch', str(e.exception))
        # A body changed on the way: the signature says so.
        wire = Wire()
        wire.tamper = lambda op, raw, h: (raw.replace(b'"auto"', b'"this"'), h)
        t2, _ = target(wire=wire)
        with self.assertRaises(base.PluginError) as e:
            t2.deploy(Bundle('a'), {})
        self.assertIn('bad_signature', str(e.exception))

    def test_a_slot_that_follows_is_not_pushed_to(self):
        t, ctx = self.paired()
        real = E.push_slots
        E.push_slots = lambda store: real(store) + [
            {'id': 'front', 'kind': 'front', 'node': None, 'title': 'the server in front',
             'names': ['app1.example.test'], 'managed_by': 'follows:' + SLOT,
             'installable': True, 'current': None, 'why_not': ''}]
        try:
            got = t.deploy(Bundle('a'), {})
            self.assertNotIn('front', got, 'auto leaves a slot that follows')
            with self.assertRaises(base.PluginError) as e:
                t.deploy(Bundle('a'), {'slots': 'front'})
            self.assertIn('not_installable', str(e.exception))
        finally:
            E.push_slots = real

    def test_inventory_in_a_cluster(self):
        t, ctx = self.paired()
        was = dict(E.CONFIG)
        E.CONFIG['ha_mode'] = 'active'
        STORE.set_meta('web:vip', json.dumps({'on': True, 'fqdn': 'app.example.test',
                                              'address': '192.0.2.10'}))
        try:
            ids = [s['id'] for s in t.inventory()['slots']]
            self.assertIn('vip', ids)
            self.assertIn(SLOT, ids)
            with self.assertRaises(base.PluginError) as e:
                t.deploy(Bundle('a'), {'slots': 'vip'})
            self.assertIn('app.example.test', str(e.exception))
            got = t.deploy(Bundle('w'), {'slots': 'auto'})
            self.assertIn('vip', got)
            self.assertIn(SLOT, got)
        finally:
            E.CONFIG.clear()
            E.CONFIG.update(was)
            STORE.db.run('DELETE FROM meta WHERE k = ?', ('web:vip',))


class ServedWhere(unittest.TestCase):
    """After the push (1.0.91): what is served is asked at the application's own address
    first (SNI: the slot's name), then at the name - a slot named merit.cz while merit.cz is
    another server (the company's web) and isemon is monitor.merit.cz."""
    def test_the_application_address_first(self):
        from acmelib.plugins.targets import acme_push as AP
        cls = S.plugin_class('target', 'acme_push')
        t = cls({'url': 'https://monitor.merit.test/'}, ctx_for('mon'))
        t._installed = [{'slot': 'node:isemon', 'names': ['merit.test']}]
        asked = []

        def served(ctx, bundle, hps, sni=None, **kw):
            asked.append((hps[0], sni))
            return hps[0] == 'monitor.merit.test:443'
        real = AP.check_served
        AP.check_served = served
        try:
            self.assertTrue(t.verify(Bundle('a'), {}))
            self.assertEqual(asked, [('monitor.merit.test:443', 'merit.test')])
            # served nowhere: asked at both, and failed
            asked.clear()
            AP.check_served = lambda ctx, b, hps, sni=None, **kw: asked.append(hps[0]) or False
            self.assertFalse(t.verify(Bundle('a'), {}))
            self.assertEqual(asked, ['monitor.merit.test:443', 'merit.test:443'])
            # only the name serves it (a VIP slot reached apart from the address)
            AP.check_served = lambda ctx, b, hps, sni=None, **kw: hps[0] == 'merit.test:443'
            self.assertTrue(t.verify(Bundle('a'), {}))
        finally:
            AP.check_served = real


class Discovery(unittest.TestCase):
    def setUp(self):
        receiver_reset()
        STORE.db.run('DELETE FROM cert_deploys')
        STORE.db.run('DELETE FROM certs')
        STORE.db.run("DELETE FROM cert_targets WHERE kind = 'acme_push'")
        self.wire = Wire()
        real = runtime.RunContext.http
        runtime.RunContext.http = lambda ctx, *a, **kw: self.wire(*a, **kw)
        self.addCleanup(setattr, runtime.RunContext, 'http', real)
        A.family_save(STORE, 'target', {'kind': 'acme_push', 'name': 'app', 'config': {
            'url': 'https://app1.example.test/admin/', 'pair_code': code()}}, 'tester')

    def test_discover_then_adopt(self):
        got = api_push.discover(STORE, {'name': 'app'})
        self.assertEqual([s['id'] for s in got['slots']], [SLOT])
        self.assertEqual(got['slots'][0]['covered_by'], [])
        made = api_push.adopt(STORE, {'name': 'app', 'plan': 'each', 'issuer': '',
                                      'challenge': ''}, 'tester')
        self.assertEqual(len(made['made']), 1)
        self.assertEqual(made['made'][0]['names'], ['app1.example.test'])
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (made['made'][0]['deploy_id'],))
        self.assertEqual(json.loads(dep['options'])['slots'], SLOT)
        again = api_push.discover(STORE, {'name': 'app'})
        self.assertEqual(again['slots'][0]['covered_by'][0]['cert_id'], made['made'][0]['cert_id'])
        twice = api_push.adopt(STORE, {'name': 'app'}, 'tester')
        self.assertEqual(twice['made'], [])
        self.assertIn('already', twice['left'][0]['why'])

    def test_each_slot_its_own_way(self):
        """Discover (1.0.90): each slot given an existing certificate that holds its names,
        or a new one from a source of its own - an existing deployment takes the slot beside
        those it has."""
        wild = A.cert_save(STORE, {'names': ['*.example.test', 'example.test']}, 'tester')
        other = A.cert_save(STORE, {'names': ['other.example.test']}, 'tester')
        got = api_push.discover(STORE, {'name': 'app'})
        fits = [c['cert_id'] for c in got['slots'][0]['fits']]
        self.assertIn(wild, fits)
        self.assertNotIn(other, fits)
        bad = api_push.adopt(STORE, {'name': 'app', 'each': {
            SLOT: {'how': 'existing', 'cert_id': other}}}, 'tester')
        self.assertIn('does not hold its names', bad['left'][0]['why'])
        self.assertEqual(bad['linked'], [])
        ok = api_push.adopt(STORE, {'name': 'app', 'each': {
            SLOT: {'how': 'existing', 'cert_id': wild}, 'nope': {'how': 'new'}}}, 'tester')
        self.assertEqual([(x['cert_id'], x['slots']) for x in ok['linked']], [(wild, [SLOT])])
        self.assertEqual(ok['made'], [])
        self.assertIn('no such slot', ok['left'][0]['why'])
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ?', (wild,))
        self.assertEqual(json.loads(dep['options'])['slots'], SLOT)
        again = api_push.discover(STORE, {'name': 'app'})
        self.assertEqual(again['slots'][0]['covered_by'][0]['cert_id'], wild)
        twice = api_push.adopt(STORE, {'name': 'app', 'each': {
            SLOT: {'how': 'existing', 'cert_id': wild}}}, 'tester')
        self.assertIn('already', twice['left'][0]['why'])
        # a deployment of it to this target there already: the slot put beside its own
        STORE.db.run('DELETE FROM cert_deploys')
        A.deploy_save(STORE, {'cert_id': wild, 'target': 'app', 'options': {'slots': 'vip'}},
                      'tester')
        api_push.adopt(STORE, {'name': 'app', 'each': {
            SLOT: {'how': 'existing', 'cert_id': wild}}}, 'tester')
        rows = STORE.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ?', (wild,))
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['options'])['slots'], 'vip\n' + SLOT)
        # or a new one, from a source chosen for the slot
        STORE.db.run('DELETE FROM cert_deploys')
        new = api_push.adopt(STORE, {'name': 'app', 'each': {SLOT: {'how': 'new'}}}, 'tester')
        self.assertEqual(len(new['made']), 1)
        self.assertEqual(new['made'][0]['names'], ['app1.example.test'])
        with self.assertRaises(ValueError):
            api_push.adopt(STORE, {'name': 'app', 'each': {SLOT: {'how': 'what'}}}, 'tester')

    def test_together_in_a_cluster(self):
        was = dict(E.CONFIG)
        E.CONFIG['ha_mode'] = 'active'
        STORE.set_meta('web:vip', json.dumps({'on': True, 'fqdn': 'app.example.test'}))
        try:
            made = api_push.adopt(STORE, {'name': 'app', 'plan': 'together', 'issuer': '',
                                          'challenge': ''}, 'tester')
            self.assertEqual(len(made['made']), 1)
            one = made['made'][0]
            self.assertEqual(sorted(one['slots']), sorted([SLOT, 'vip']))
            self.assertEqual(sorted(one['names']), ['app.example.test', 'app1.example.test'])
        finally:
            E.CONFIG.clear()
            E.CONFIG.update(was)
            STORE.db.run('DELETE FROM meta WHERE k = ?', ('web:vip',))

    def test_follows_and_not_installable_are_left(self):
        real = E.push_slots

        def more(store):
            return real(store) + [
                {'id': 'front', 'kind': 'front', 'node': None, 'title': 'the server in front',
                 'names': ['front.example.test'], 'managed_by': 'follows:' + SLOT,
                 'installable': True, 'current': None},
                {'id': 'broker', 'kind': 'other', 'node': None, 'title': 'the broker',
                 'names': [], 'managed_by': 'none', 'installable': False,
                 'why_not': 'reads the dashboard\'s', 'current': None}]
        E.push_slots = more
        try:
            made = api_push.adopt(STORE, {'name': 'app', 'issuer': '', 'challenge': ''},
                                  'tester')
        finally:
            E.push_slots = real
        self.assertEqual([m['slots'] for m in made['made']], [[SLOT]])
        left = {x['slot']: x['why'] for x in made['left']}
        self.assertIn('follows', left['front'])
        self.assertIn('cannot be put in', left['broker'])


if __name__ == '__main__':
    unittest.main(verbosity=2, argv=[a for a in sys.argv if a != '-v'] + ['-v'])
