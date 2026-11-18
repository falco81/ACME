#!/usr/bin/env python3
"""Hunt R (run t2) in the target agents, acme's side:

    python3 test/test_hunt_rt2_agents.py

* a team whose limits allow only Windows agents (target_kinds: agent_windows) could not make a
  team enrollment code - enroll_new and the portal checked the kind 'agent' only.

No agent processes, no network: temporary folders only.
"""
import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-huntrt2ag-')
os.chmod(TMP, 0o755)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, store as S, agents as G, teams as T  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
S.registry()


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def csr_new():
    key = subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                          'ec_paramgen_curve:P-256'], capture_output=True, check=True).stdout
    return subprocess.run(['openssl', 'req', '-new', '-key', '/dev/stdin', '-subj',
                           '/CN=acme-agent'], input=key, capture_output=True,
                          check=True).stdout.decode()


def code_data(code):
    raw = code.split('.', 1)[1]
    return json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))


def enroll_body(data, csr, fqdn, platform='linux'):
    nonce = secrets.token_hex(16)
    enc = base64.b64encode(secrets.token_bytes(32)).decode()
    sha = hashlib.sha256(csr.encode()).hexdigest()
    return {'e': data['e'], 'nonce': nonce, 'csr': csr, 'enc_pub': enc,
            'host': fqdn.split('.')[0], 'fqdn': fqdn, 'os': 'x', 'platform': platform,
            'version': '1.0.126', 'code': 'c0de',
            'proof': G.proof(data['s'], 'enroll', data['e'], sha, enc, nonce, fqdn)}


class Base(unittest.TestCase):
    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_names'] = '127.0.0.1:18444'

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0
        E.CONFIG['certs_agents_names'] = ''


class WindowsOnlyTeam(Base):
    def team(self, name, kinds):
        if T.team_get(STORE, name):
            T.save_team(STORE, {'old_name': name, 'name': name,
                                'policy': {'target_kinds': kinds}}, 'x')
        else:
            T.save_team(STORE, {'name': name, 'policy': {'target_kinds': kinds}}, 'x')

    def test_windows_only_team_makes_a_code(self):
        self.team('WinOps', ['agent_windows'])
        made = G.enroll_new(STORE, 'tester', title='win', team='WinOps')
        data = code_data(made['code'])
        # a Linux server is refused, a Windows one becomes an agent_windows target of the team
        got = G.wire(STORE, 'enroll', enroll_body(data, csr_new(), 'lin1.example.test'), '', '',
                     '10.0.0.5')
        self.assertEqual(got[0], 403, got)
        got = G.wire(STORE, 'enroll', enroll_body(data, csr_new(), 'win1.example.test',
                                                  'windows'), '', '', '10.0.0.6')
        self.assertEqual(got[0], 200, got)
        row = S.plugin_row(STORE, 'target', STORE.db.value(
            'SELECT id FROM cert_targets WHERE name = ?', (got[1]['target'],)))
        self.assertEqual((row['kind'], row['owner']), ('agent_windows', 'WinOps'))

    def test_other_limits_as_before(self):
        self.team('LinOps', ['agent'])
        data = code_data(G.enroll_new(STORE, 'tester', team='LinOps')['code'])
        got = G.wire(STORE, 'enroll', enroll_body(data, csr_new(), 'w2.example.test',
                                                  'windows'), '', '', '10.0.0.7')
        self.assertEqual(got[0], 403, got)
        self.team('SshOps', ['ssh'])
        with self.assertRaises(Exception) as e:
            G.enroll_new(STORE, 'tester', team='SshOps')
        self.assertIn('the team SshOps', str(e.exception))
        self.assertEqual(G.enroll_kind({}), 'agent')
        self.assertEqual(G.enroll_kind({'target_kinds': ['agent', 'agent_windows']}), 'agent')
        self.assertEqual(G.enroll_kind({'target_kinds': ['Agent_Windows']}), 'agent_windows')


if __name__ == '__main__':
    unittest.main(verbosity=2)
