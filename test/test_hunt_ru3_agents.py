#!/usr/bin/env python3
"""Hunt R (run u3) in the target agents, acme's side:

    python3 test/test_hunt_ru3_agents.py

* a server enrolled with a team's code, its target moved to another team since, enrolling
  again with the same code made a second target of the first team for the same server (a
  duplicate) - now refused, nothing made and nothing confirmed in the other team's target;
* a target whose join code ran out unused said "joining" for ever;
* confirming a passive agent on its card (POST /api/agents/confirm) said "the agent is
  confirmed" while acme could not hand it its certificate (look says it in its answer).

No agent processes, no network but a refused local port: temporary folders only.
"""
import base64
import hashlib
import importlib.util
import os
import secrets
import shutil
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('hunt_rt2_agents_base',
                                               os.path.join(HERE, 'test_hunt_rt2_agents.py'))
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)
G, S, T, E, STORE = B.G, B.S, B.T, B.E, B.STORE
from acmelib.certs import api as A, api_agents  # noqa: E402


def tearDownModule():
    shutil.rmtree(B.TMP, ignore_errors=True)


def target_id(name):
    return STORE.db.value('SELECT id FROM cert_targets WHERE name = ?', (name,))


class MovedThenEnrolledAgain(B.Base):
    def test_no_second_target_none_confirmed(self):
        T.save_team(STORE, {'name': 'MoveA', 'policy': {'agents_auto_confirm': True}}, 'x')
        T.save_team(STORE, {'name': 'MoveB', 'policy': {'agents_auto_confirm': False}}, 'x')
        a = B.code_data(G.enroll_new(STORE, 'tester', title='a', team='MoveA', auto=True)['code'])
        b = B.code_data(G.enroll_new(STORE, 'tester', title='b', team='MoveB')['code'])
        csr = B.csr_new()
        got = G.wire(STORE, 'enroll', B.enroll_body(a, csr, 'mv1.example.test'), '', '', '10.2.0.1')
        self.assertEqual(got[0], 200, got)
        name = got[1]['target']
        tid = target_id(name)
        STORE.db.run("UPDATE cert_targets SET owner = 'MoveB' WHERE id = ?", (tid,))
        before = STORE.db.value("SELECT COUNT(*) FROM cert_targets")
        uses = G.enroll_get(STORE, a['e'])['uses']
        got = G.wire(STORE, 'enroll', B.enroll_body(a, csr, 'mv1.example.test'), '', '', '10.2.0.1')
        self.assertEqual(got[0], 403, got)
        self.assertIn('another owner', got[1]['said'])
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM cert_targets"), before)
        self.assertEqual(G.enroll_get(STORE, a['e'])['uses'], uses)
        # the new owner's code: its own target, waiting for a person (as before)
        got = G.wire(STORE, 'enroll', B.enroll_body(b, csr, 'mv1.example.test'), '', '', '10.2.0.1')
        self.assertEqual((got[0], got[1].get('target')), (200, name), got)
        pend = G.state(STORE, tid).get('pending') or {}
        self.assertTrue(pend.get('fp') and not pend.get('cert'))
        # another server (another key) with the first code: a target of its own, as before
        got = G.wire(STORE, 'enroll', B.enroll_body(a, B.csr_new(), 'mv2.example.test'), '', '',
                     '10.2.0.2')
        self.assertEqual(got[0], 200, got)


class ExpiredCodeIsNoJoin(B.Base):
    def test_pill(self):
        rid = A.family_save(STORE, 'target', {'name': 'exp1', 'kind': 'agent', 'config': {
            'mode': 'active', 'host': 'exp1.example.test'}, 'enabled': 1}, 'x')
        row = S.plugin_row(STORE, 'target', rid)
        self.assertEqual(G.info(STORE, row)['state'], 'new')
        G.code_new(STORE, row, 'x')
        self.assertEqual(G.info(STORE, row)['state'], 'joining')
        st = G.state(STORE, rid)
        st['code']['until'] = time.time() - 5
        G.state_put(STORE, rid, st)
        got = G.info(STORE, row)
        self.assertEqual((got['state'], got['code_until']), ('new', None))


class ConfirmSaysWhatWentWrong(unittest.TestCase):
    def test_passive_unreachable(self):
        rid = A.family_save(STORE, 'target', {'name': 'pas-u3', 'kind': 'agent', 'config': {
            'mode': 'passive', 'host': '127.0.0.1', 'port': 1, 'timeout': 2}, 'enabled': 1}, 'x')
        row = S.plugin_row(STORE, 'target', rid)
        G.code_new(STORE, row, 'x')
        row, st, c, secret = G._code_of(STORE, G.state(STORE, rid)['code']['id'])
        csr = B.csr_new()
        enc = base64.b64encode(secrets.token_bytes(32)).decode()
        nonce = secrets.token_hex(16)
        G.join_take(STORE, row, st, c, secret, {
            'csr': csr, 'enc_pub': enc, 'nonce': nonce,
            'proof': G.proof(secret, 'join', c['id'], hashlib.sha256(csr.encode()).hexdigest(),
                             enc, nonce)})
        fp = G.state(STORE, rid)['pending']['fp']

        class H(object):
            store = STORE

            def body(self):
                return {'id': rid, 'fp': fp}
        out = api_agents._confirm(H(), {'name': 'admin'})
        self.assertTrue(out.get('said'), out)
        self.assertIn('does not answer', out['said'])
        self.assertTrue((G.state(STORE, rid).get('pending') or {}).get('cert'))



class CsrSignedByItsKey(B.Base):
    def test_badly_signed_request_refused(self):
        """A request whose signature is not its key's is refused at enrollment (hunt u3)."""
        import re as _re
        a = B.code_data(G.enroll_new(STORE, 'tester', title='sig')['code'])
        csr = B.csr_new()
        der = bytearray(base64.b64decode(''.join(
            _re.findall(r'^[A-Za-z0-9+/=]+$', csr, _re.M))))
        der[-3] ^= 0x01                                 # inside the signature
        bad = ('-----BEGIN CERTIFICATE REQUEST-----\n' + '\n'.join(
            _re.findall('.{1,64}', base64.b64encode(bytes(der)).decode())) +
            '\n-----END CERTIFICATE REQUEST-----\n')
        before = STORE.db.value("SELECT COUNT(*) FROM cert_targets")
        got = G.wire(STORE, 'enroll', B.enroll_body(a, bad, 'sig.example.test'), '', '',
                     '10.2.0.9')
        self.assertEqual(got[0], 400, got)
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM cert_targets"), before)
        got = G.wire(STORE, 'enroll', B.enroll_body(a, csr, 'sig.example.test'), '', '',
                     '10.2.0.9')
        self.assertEqual(got[0], 200, got)

if __name__ == '__main__':
    unittest.main()
