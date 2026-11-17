#!/usr/bin/env python3
"""Hunt R6 in acme's crypto plumbing of the target agents (acmelib/certs/agents.py):

    python3 test/test_hunt_r6_agentca.py

* a proof with a letter beyond ASCII (join, join/status, enroll) stopped the request with a
  TypeError of hmac.compare_digest - not a 403, and a wrong join not counted as a try;
* a renewal the agent did not take put back the certificate's fingerprint but not its end:
  the renewal looked done 30 days ahead, and the certificate the agent has ran out unrenewed;
* a renewal whose answer was lost (the agent took the new certificate): the next renewal let
  in only the newest and the oldest - the agent was locked out;
* the key check of a CSR read the whole request: a subject "NIST CURVE: P-256" let an RSA key
  of 1024 bits through.

No agent processes, no network: temporary folders only.
"""
import base64
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-huntr6ag-')
os.chmod(TMP, 0o755)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, store as S, agents as G  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
S.registry()


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def target(name, kind='agent', **cfg):
    rid = A.family_save(STORE, 'target', {'name': name, 'kind': kind, 'config': cfg,
                                         'enabled': 1}, 'tester')
    return S.plugin_row(STORE, 'target', rid)


def key_and_csr(*alg, subj='/CN=a'):
    k = os.path.join(TMP, 'k-%s.pem' % secrets.token_hex(4))
    subprocess.run(['openssl', 'genpkey'] + list(alg or ('-algorithm', 'EC', '-pkeyopt',
                                                         'ec_paramgen_curve:P-256')) +
                   ['-out', k], check=True, capture_output=True)
    csr = subprocess.run(['openssl', 'req', '-new', '-key', k, '-subj', subj], check=True,
                         capture_output=True, text=True).stdout
    return k, csr


class ProofsBeyondAscii(unittest.TestCase):
    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_names'] = '127.0.0.1:18444'

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0
        E.CONFIG['certs_agents_names'] = ''

    def test_refused_not_a_crash(self):
        row = target('r6-ascii', mode='active')
        G.code_new(STORE, row, 'tester')
        c = G.state(STORE, row['id'])['code']
        got = G.wire(STORE, 'join', {'i': c['id'], 'csr': 'x', 'enc_pub': 'x',
                                     'nonce': '0' * 32, 'proof': 'é' * 64}, '', '')
        self.assertEqual(got[0], 403, got)
        self.assertEqual(G.state(STORE, row['id'])['code']['tries'], 1)
        got = G.wire(STORE, 'status', {'i': c['id'], 'nonce': '0' * 32, 'proof': 'ž'}, '', '')
        self.assertEqual(got[0], 403, got)
        made = G.enroll_new(STORE, 'tester', title='R6', mode='active')
        got = G.wire(STORE, 'enroll', {'e': made['id'], 'csr': 'x', 'enc_pub': 'x',
                                       'nonce': '0' * 32, 'proof': 'ř'}, '', '')
        self.assertEqual(got[0], 403, got)
        # the right proof still proves
        secret = E.unseal_secret(c['secret'], G.M_T(row['id']) + ':code')
        nonce = secrets.token_hex(16)
        got = G.wire(STORE, 'status', {'i': c['id'], 'nonce': nonce,
                                       'proof': G.proof(secret, 'status', c['id'], nonce)},
                     '', '')
        self.assertEqual(got[0], 200, got)


class Renewal(unittest.TestCase):
    def joined(self, name):
        row = target(name, mode='passive', host='192.0.2.1')
        _k, csr = key_and_csr()
        old = G.sign_csr(STORE, csr, G.AGENT_CN + 'ag-0123456789ab', 5)
        st = G.state(STORE, row['id'])
        st.update(agent_id='ag-0123456789ab', cert_fp=G.fp_of_pem(old),
                  cert_end=G.cert_end(old), key_fp=G.spki_fp(csr))
        G.state_put(STORE, row['id'], st)
        return row, csr, old

    def renew(self, row, csr, answer):
        signed = []

        def fake(store, r, op, args=None, **kw):
            if op == 'csr':
                return {'ok': True, 'csr': csr}
            signed.append(args['cert_pem'])
            if isinstance(answer, Exception):
                raise answer
            return answer
        with mock.patch.object(G, 'call', fake):
            try:
                G.renew_cert(STORE, row)
            except G.PluginError:
                pass
        return signed[0]

    def test_not_taken_its_end_put_back(self):
        row, csr, old = self.joined('r6-renew-refused')
        new = self.renew(row, csr, {'ok': False, 'said': 'disk full'})
        st = G.state(STORE, row['id'])
        self.assertEqual(st['cert_fp'], G.fp_of_pem(old))
        self.assertEqual(st['cert_end'], G.cert_end(old))
        self.assertEqual(st['cert_prev_fp'], G.fp_of_pem(new))
        # still due: the next tick renews it again
        self.assertLess(st['cert_end'] - time.time(), G.RENEW_DAYS * 86400)

    def test_taken_its_answer_lost_never_locked_out(self):
        row, csr, old = self.joined('r6-renew-lost')
        new1 = self.renew(row, csr, G.PluginError('it does not answer'))
        st = G.state(STORE, row['id'])
        self.assertIn(G.fp_of_pem(new1), (st['cert_fp'], st['cert_prev_fp']))
        # the agent took it: it answers over it from now on (as _passive_post / poll see it)
        st['cert_seen_fp'] = G.fp_of_pem(new1)
        G.state_put(STORE, row['id'], st)
        # the next renewal (due: the end held is the old one's) - refused once, then taken
        new2 = self.renew(row, csr, {'ok': False, 'said': 'busy'})
        st = G.state(STORE, row['id'])
        self.assertIn(G.fp_of_pem(new1), (st['cert_fp'], st['cert_prev_fp']))
        self.assertEqual(st['cert_fp'], G.fp_of_pem(new1))
        self.assertEqual(st['cert_end'], G.cert_end(new1))
        self.assertEqual(st['cert_prev_fp'], G.fp_of_pem(new2))
        new3 = self.renew(row, csr, {'ok': True})
        st = G.state(STORE, row['id'])
        self.assertEqual(st['cert_fp'], G.fp_of_pem(new3))
        self.assertEqual(st['cert_prev_fp'], G.fp_of_pem(new1))

    def test_as_before_when_seen_with_the_current_one(self):
        row, csr, old = self.joined('r6-renew-plain')
        st = G.state(STORE, row['id'])
        st['cert_seen_fp'] = st['cert_fp']
        G.state_put(STORE, row['id'], st)
        new = self.renew(row, csr, {'ok': True})
        st = G.state(STORE, row['id'])
        self.assertEqual(st['cert_fp'], G.fp_of_pem(new))
        self.assertEqual(st['cert_prev_fp'], G.fp_of_pem(old))
        self.assertEqual(st['cert_end'], G.cert_end(new))

    def test_poll_says_the_certificate_it_has(self):
        with mock.patch.dict(E.CONFIG, certs_agents_active=1):
            row = target('r6-seen', mode='active')
        st = G.state(STORE, row['id'])
        st.update(agent_id='ag-0123456789ab', cert_fp='e' * 64, cert_prev_fp='f' * 64)
        G.state_put(STORE, row['id'], st)
        with mock.patch.object(G, 'who_is', lambda store, pem, v: (
                row, G.state(store, row['id']), 'f' * 64)), mock.patch.object(G, 'HOLD_MOST', 0):
            self.assertEqual(G.poll(STORE, {}, 'pem', 'SUCCESS')[0], 200)
        self.assertEqual(G.state(STORE, row['id'])['cert_seen_fp'], 'f' * 64)


class CsrKeyCheck(unittest.TestCase):
    def test_a_weak_key_named_strong_in_its_subject(self):
        _k, csr = key_and_csr('-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024',
                              subj='/CN=NIST CURVE: P-256')
        with self.assertRaises(G.PluginError):
            G.sign_csr(STORE, csr, G.AGENT_CN + 'ag-0123456789ab', 30)

    def test_the_keys_allowed_still_signed(self):
        for alg in (('-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'),
                    ('-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384'),
                    ('-algorithm', 'ED25519'),
                    ('-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048')):
            _k, csr = key_and_csr(*alg)
            pem = G.sign_csr(STORE, csr, G.AGENT_CN + 'ag-0123456789ab', 30)
            self.assertIn('BEGIN CERTIFICATE', pem, alg)


if __name__ == '__main__':
    unittest.main(verbosity=2)
