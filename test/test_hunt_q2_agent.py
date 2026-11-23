#!/usr/bin/env python3
"""The second hunt of 1.0.119 in the target agent (docs/target-agent.md) - each fix checked here.

    python3 test/test_hunt_q2_agent.py

* an active agent's join: the answer with its certificate (join/status) lost, or the agent
  failing to take it - every question after was refused "no such join" (the code gone at the
  first answer), the agent stuck while acme said it joined. The code and the confirmed request
  stay until its first poll with the certificate;
* a passive agent's certificate taken, the answer lost: acme asked it again and again ("no join
  under way") - now it sees the agent answers with the certificate it was given;
* the join sent again with a new CSR (the agent makes one each time) of the same key: refused
  "the join code was used already" - the key is compared, not the CSR's text; another key (or
  another key to seal to) still refused;
* `acme-agent policy apply` kept the copies by name: policy.X-10 before policy.X-2;
* a design's words (agent_policy._txt) kept the C1 control characters;
* the agent's package (4 MB) read and hashed for every agent of the pages' list - kept by its
  path, time and size now; the program's hash the same;
* test/agents_page.js (the agents' pages in a browser) and test/hunt_q2_agents_page.js run here
  (node with playwright; skipped without).

No agent processes, no network: temporary folders only.
"""
import base64
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-huntq2-')
os.chmod(TMP, 0o755)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
AENV = {'ACME_AGENT_ETC': os.path.join(TMP, 'etc'), 'ACME_AGENT_STATE': os.path.join(TMP, 'st'),
        'ACME_AGENT_ROOT_STATE': os.path.join(TMP, 'rst'), 'ACME_AGENT_RUN': os.path.join(TMP, 'run'),
        'ACME_AGENT_NO_SYSTEMD': '1'}
os.environ.update(AENV)
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, store as S, agents as G, agent_policy as P  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
S.registry()


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def agent_mod():
    spec = importlib.util.spec_from_file_location(
        'acme_agent_q2', os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AG = agent_mod()


def target(name, **cfg):
    rid = A.family_save(STORE, 'target', {'name': name, 'kind': 'agent', 'config': cfg,
                                         'enabled': 1}, 'tester')
    return S.plugin_row(STORE, 'target', rid)


def new_key():
    k = os.path.join(TMP, 'k-%s.pem' % secrets.token_hex(4))
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-out', k], check=True, capture_output=True)
    return k


def csr_of(key):
    """A CSR as the agent makes it - each one anew (its signature differs)."""
    return subprocess.run(['openssl', 'req', '-new', '-key', key, '-subj', '/CN=acme-agent'],
                          check=True, capture_output=True, text=True).stdout


def code_parts(row):
    st = G.state(STORE, row['id'])
    c = st['code']
    return c, E.unseal_secret(c['secret'], G.M_T(row['id']) + ':code')


def join_req(c, secret, key, enc):
    csr = csr_of(key)
    nonce = secrets.token_hex(16)
    return {'i': c['id'], 'csr': csr, 'enc_pub': enc, 'nonce': nonce, 'host': 'vm1',
            'version': '1.0.119',
            'proof': G.proof(secret, 'join', c['id'], hashlib.sha256(csr.encode()).hexdigest(),
                             enc, nonce)}


def status_req(c, secret):
    nonce = secrets.token_hex(16)
    return {'i': c['id'], 'nonce': nonce, 'proof': G.proof(secret, 'status', c['id'], nonce)}


def events(like):
    return [r['words'] for r in STORE.db.rows('SELECT words FROM events WHERE words LIKE ?',
                                              (like,))]


class ActiveJoin(unittest.TestCase):
    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_names'] = '127.0.0.1:18444'

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0
        E.CONFIG['certs_agents_names'] = ''

    def test_resent_join_new_csr_same_key(self):
        row = target('q2-resend', mode='active')
        G.code_new(STORE, row, 'tester')
        c, secret = code_parts(row)
        key, enc = new_key(), base64.b64encode(secrets.token_bytes(32)).decode()
        got = G.wire(STORE, 'join', join_req(c, secret, key, enc), '', '')
        self.assertEqual(got[0], 200, got)
        fp = G.state(STORE, row['id'])['pending']['fp']
        # its answer lost: the agent asks again, a CSR made anew - the same key
        got = G.wire(STORE, 'join', join_req(c, secret, key, enc), '', '')
        self.assertEqual(got[0], 200, got)
        self.assertEqual(G.state(STORE, row['id'])['pending']['fp'], fp)
        # another key with the code (a copy of it): refused, the request kept
        got = G.wire(STORE, 'join', join_req(c, secret, new_key(), enc), '', '')
        self.assertEqual(got[0], 403)
        self.assertIn('used already', got[1]['said'])
        # the same key, another key to seal secrets to: refused
        other = base64.b64encode(secrets.token_bytes(32)).decode()
        got = G.wire(STORE, 'join', join_req(c, secret, key, other), '', '')
        self.assertEqual(got[0], 403)
        self.assertEqual(G.state(STORE, row['id'])['pending']['enc_pub'], enc)
        # confirmed: asked again with a new CSR, the confirmation stays
        G.confirm(STORE, row, fp, 'tester')
        cert = G.state(STORE, row['id'])['pending']['cert']
        got = G.wire(STORE, 'join', join_req(c, secret, key, enc), '', '')
        self.assertEqual(got[0], 200, got)
        self.assertEqual(G.state(STORE, row['id'])['pending'].get('cert'), cert)

    def test_wrong_proof_still_counts_and_runs_out(self):
        row = target('q2-tries', mode='active')
        G.code_new(STORE, row, 'tester')
        c, secret = code_parts(row)
        key, enc = new_key(), base64.b64encode(secrets.token_bytes(32)).decode()
        for _ in range(G.CODE_TRIES):
            bad = join_req(c, 'not-the-secret', key, enc)
            self.assertEqual(G.wire(STORE, 'join', bad, '', '')[0], 403)
        got = G.wire(STORE, 'join', join_req(c, secret, key, enc), '', '')
        self.assertEqual(got[0], 403)
        self.assertIn('too often', got[1]['said'])

    def test_status_answered_again_until_the_first_poll(self):
        row = target('q2-status', mode='active')
        G.code_new(STORE, row, 'tester')
        c, secret = code_parts(row)
        key, enc = new_key(), base64.b64encode(secrets.token_bytes(32)).decode()
        self.assertEqual(G.wire(STORE, 'join', join_req(c, secret, key, enc), '', '')[0], 200)
        fp = G.state(STORE, row['id'])['pending']['fp']
        got = G.wire(STORE, 'status', status_req(c, secret), '', '')
        self.assertEqual(got[1].get('state'), 'confirm')
        G.confirm(STORE, row, fp, 'tester')
        first = G.wire(STORE, 'status', status_req(c, secret), '', '')
        self.assertEqual((first[0], first[1].get('state')), (200, 'done'), first)
        # the answer lost (or join_finish failed): asked again, answered again
        again = G.wire(STORE, 'status', status_req(c, secret), '', '')
        self.assertEqual((again[0], again[1].get('state')), (200, 'done'), again)
        self.assertEqual(again[1]['cert_pem'], first[1]['cert_pem'])
        self.assertEqual(len(events('the agent of target q2-status joined acme%')), 1)
        # not the agent of the code: refused as before
        bad = status_req(c, 'not-the-secret')
        self.assertEqual(G.wire(STORE, 'status', bad, '', '')[0], 403)
        # its first poll with the certificate: the code and the request gone
        with mock.patch.object(G, 'HOLD_MOST', 0):
            got = G.wire(STORE, 'poll', {'results': [0]}, first[1]['cert_pem'], 'SUCCESS')
        self.assertEqual(got[0], 200, got)
        st = G.state(STORE, row['id'])
        self.assertNotIn('pending', st)
        self.assertNotIn('code', st)
        got = G.wire(STORE, 'status', status_req(c, secret), '', '')
        self.assertEqual(got[0], 403)
        self.assertEqual(G.info(STORE, row)['state'], 'answers')


class PassiveFinish(unittest.TestCase):
    def confirmed(self, name):
        row = target(name, mode='passive', host='127.0.0.1', port=1)
        G.code_new(STORE, row, 'tester')
        c, secret = code_parts(row)
        key, enc = new_key(), base64.b64encode(secrets.token_bytes(32)).decode()
        req = join_req(c, secret, key, enc)
        st = G.state(STORE, row['id'])
        fp = G.join_take(STORE, row, st, st['code'], secret, req)
        G.confirm(STORE, row, fp, 'tester')
        return row

    def test_taken_its_answer_lost(self):
        row = self.confirmed('q2-passive')
        said = {'ok': False, 'said': 'no join under way'}
        with mock.patch.object(G, '_passive_post', return_value=(said, None)), \
                mock.patch.object(G, 'hello', return_value={'ok': True}) as h:
            G.finish_passive(STORE, row, G.state(STORE, row['id']))
        self.assertTrue(h.called)
        st = G.state(STORE, row['id'])
        self.assertNotIn('pending', st)
        self.assertNotIn('code', st)

    def test_not_taken_still_said(self):
        row = self.confirmed('q2-passive2')
        said = {'ok': False, 'said': 'the certificate is not for this agent'}
        with mock.patch.object(G, '_passive_post', return_value=(said, None)), \
                mock.patch.object(G, 'hello', side_effect=G.PluginError('x')):
            with self.assertRaises(G.PluginError) as e:
                G.finish_passive(STORE, row, G.state(STORE, row['id']))
        self.assertIn('did not take its certificate', str(e.exception))
        self.assertTrue(G.state(STORE, row['id'])['pending'].get('cert'))
        with mock.patch.object(G, '_passive_post', side_effect=G.PluginError('does not answer')), \
                mock.patch.object(G, 'hello', side_effect=G.PluginError('x')):
            with self.assertRaises(G.PluginError) as e:
                G.finish_passive(STORE, row, G.state(STORE, row['id']))
        self.assertIn('does not answer', str(e.exception))


class PolicyCopies(unittest.TestCase):
    def test_order(self):
        names = ['policy.20261117-101010-10', 'policy.20261117-101010-2',
                 'policy.20261117-101010', 'policy.20261116-235959-3']
        self.assertEqual(sorted(names, key=AG.policy_copy_order), [
            'policy.20261116-235959-3', 'policy.20261117-101010', 'policy.20261117-101010-2',
            'policy.20261117-101010-10'])

    @unittest.skipUnless(os.geteuid() == 0, 'policy apply writes root:root')
    def test_apply_keeps_the_newest(self):
        etc = tempfile.mkdtemp(dir=TMP)
        stamp = time.strftime('%Y%m%d-%H%M%S')
        old = ['policy.20200101-000000', 'policy.' + stamp] + \
            ['policy.%s-%d' % (stamp, i) for i in range(2, 12)]
        for n in old:
            with open(os.path.join(etc, n), 'w') as fh:
                fh.write('# old\n')
        pol = os.path.join(etc, 'policy')
        with open(pol, 'w') as fh:
            fh.write('# the policy before\n')
        os.chmod(pol, 0o644)
        with mock.patch.object(AG, 'ETC', etc), mock.patch.object(AG, 'POLICY', pol), \
                mock.patch.object(AG, 'audit', lambda **k: None), \
                mock.patch('builtins.print'):
            self.assertEqual(AG.policy_apply('allow probe local\n'), 0)
        kept = sorted((n for n in os.listdir(etc) if n.startswith('policy.')),
                      key=AG.policy_copy_order)
        self.assertEqual(len(kept), AG.POLICY_COPIES)
        made = [n for n in kept if AG._read(os.path.join(etc, n), '') == '# the policy before\n']
        self.assertEqual(len(made), 1)                      # the copy just made
        self.assertEqual(kept[-1], made[0])
        for n in ('policy.%s-10' % stamp, 'policy.%s-11' % stamp):
            self.assertIn(n, kept)
        for n in ('policy.20200101-000000', 'policy.' + stamp, 'policy.%s-2' % stamp):
            self.assertNotIn(n, kept)


class Words(unittest.TestCase):
    def test_c1_controls(self):
        self.assertEqual(P._txt('a\x85b\x9bc\x80d', 50), 'abcd')
        self.assertEqual(P._txt('a\tb\nc', 50), 'a\tb\nc')         # a note keeps its lines
        self.assertEqual(G._txt('a\x9bb', 50), P._txt('a\x9bb', 50))


class PackageFacts(unittest.TestCase):
    def test_kept_by_path_time_size(self):
        p = os.path.join(TMP, 'acme-agent-9.9.9.tar.gz')
        with open(p, 'wb') as fh:
            fh.write(b'x' * 1000)
        real = open
        n = []

        def counting(path, *a, **k):
            if path == p:
                n.append(1)
            return real(path, *a, **k)
        with mock.patch('builtins.open', counting):
            one = G._pkg_facts(p, 'n', '9.9.9', True)
            two = G._pkg_facts(p, 'n', '9.9.9', True)
        self.assertEqual(len(n), 1)
        self.assertEqual(one, two)
        self.assertEqual(one['sha256'], hashlib.sha256(b'x' * 1000).hexdigest())
        with open(p, 'wb') as fh:
            fh.write(b'y' * 1001)
        three = G._pkg_facts(p, 'n', '9.9.9', True)
        self.assertEqual((three['size'], three['sha256']),
                         (1001, hashlib.sha256(b'y' * 1001).hexdigest()))

    def test_program_hash_kept(self):
        want = G.agent_mod().code_hash(G.AGENT_DIR)
        self.assertEqual(G.shipped_code(), want)
        with mock.patch.object(G.agent_mod(), 'code_hash', side_effect=AssertionError):
            self.assertEqual(G.shipped_code(), want)


class Pages(unittest.TestCase):
    def node(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        return node

    def test_hunt_q2_page(self):
        got = subprocess.run([self.node(), os.path.join(HERE, 'hunt_q2_agents_page.js'),
                              os.path.join(ROOT, 'web')],
                             capture_output=True, text=True, timeout=300)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
