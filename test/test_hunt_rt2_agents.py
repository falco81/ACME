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
from acmelib.certs import agent_policy as P  # noqa: E402

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


def enroll_body(data, csr, fqdn, platform='linux', key=None):
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


class EnrolledAgainOtherTeam(Base):
    """A server waiting in one team's target, enrolled again (the same name, the same key)
    with another team's code that confirms by itself: it was confirmed in the first team's
    target - that team's own confirmation (agents_auto_confirm off) passed over."""

    def test_other_teams_code_makes_its_own_target(self):
        T.save_team(STORE, {'name': 'TeamX', 'policy': {'agents_auto_confirm': False}}, 'x')
        T.save_team(STORE, {'name': 'TeamY', 'policy': {'agents_auto_confirm': True}}, 'x')
        a = code_data(G.enroll_new(STORE, 'tester', title='x', team='TeamX')['code'])
        b = code_data(G.enroll_new(STORE, 'tester', title='y', team='TeamY', auto=True)['code'])
        csr = csr_new()
        got = G.wire(STORE, 'enroll', enroll_body(a, csr, 'srvx.example.test'), '', '', '10.1.0.1')
        self.assertEqual(got[0], 200, got)
        x_name = got[1]['target']
        x_id = STORE.db.value('SELECT id FROM cert_targets WHERE name = ?', (x_name,))
        got = G.wire(STORE, 'enroll', enroll_body(b, csr, 'srvx.example.test'), '', '', '10.1.0.1')
        self.assertEqual(got[0], 200, got)
        # TeamX's target still waits for a person
        self.assertFalse((G.state(STORE, x_id).get('pending') or {}).get('cert'))
        self.assertFalse(G.state(STORE, x_id).get('cert_fp'))
        self.assertNotEqual(got[1]['target'], x_name)
        y = S.plugin_row(STORE, 'target', STORE.db.value(
            'SELECT id FROM cert_targets WHERE name = ?', (got[1]['target'],)))
        self.assertEqual(y['owner'], 'TeamY')
        # the same team's code again: the same target, as before
        a2 = code_data(G.enroll_new(STORE, 'tester', title='x2', team='TeamX')['code'])
        got = G.wire(STORE, 'enroll', enroll_body(a2, csr, 'srvx.example.test'), '', '',
                     '10.1.0.1')
        self.assertEqual((got[0], got[1].get('target')), (200, x_name), got)


class WindowsPolicyKept(unittest.TestCase):
    """A Windows agent's policy as acme keeps it (clean_policy): its folders, the store, IIS,
    Remote Desktop, its roles, read on the key, the roles it knows - all were left out, and a
    deployment with a Windows role was refused as if the agent were too old."""

    def test_kept_and_roles_deploy(self):
        W = G.agent_mod_windows()
        pol = W.parse_policy('allow file C:\\certs readers=IIS_IUSRS\nallow store\n'
                             'allow iis "Default Web Site"\nallow rdp\nallow role sql\n'
                             'allow key-read "NT SERVICE\\MSSQLSERVER"\n')
        said = G.clean_result({'ok': True, 'policy': json.loads(json.dumps(
            W.policy_report(pol, 'e' * 64)))})['policy']
        self.assertEqual(said['files'][0]['dir'], 'C:\\certs')
        self.assertEqual(said['files'][0]['readers'], ['IIS_IUSRS'])
        self.assertTrue(said['store'] and said['rdp'])
        self.assertEqual(said['iis'], ['Default Web Site'])
        self.assertEqual(said['roles'], {'sql': []})
        self.assertEqual(said['key_read'], ['NT SERVICE\\MSSQLSERVER'])
        self.assertIn('sql', said['roles_known'])
        # an older agent (no roles_known) still said as older
        rep = W.policy_report(pol, 'e' * 64)
        rep.pop('roles_known')
        self.assertNotIn('roles_known', G.clean_policy(rep))
        # a Linux agent's policy: as before
        L = G.agent_mod()
        lp = L.parse_policy('allow file /etc/ssl/x owner=root:root mode=0640\n')
        got = G.clean_policy(json.loads(json.dumps(L.policy_report(lp, 'e' * 64))))
        self.assertEqual(got['files'], [{'dir': '/etc/ssl/x', 'owner': 'root', 'group': 'root',
                                         'mode': 0o640}])
        self.assertFalse({'store', 'rdp', 'iis', 'roles', 'key_read', 'roles_known'} & set(got))
        # junk of the wrong shapes is left out
        got = G.clean_policy({'files': [{'dir': 'C:\\x', 'readers': 'nope'}], 'roles': {'BAD!': [],
                              'sql': 'x'}, 'iis': 'x', 'roles_known': [1, 'sql']})
        self.assertEqual(got['files'][0]['readers'], [])
        self.assertEqual(got['roles'], {'sql': []})
        self.assertNotIn('iis', got)
        self.assertEqual(got['roles_known'], ['sql'])


class TakeMoreThan20(Base):
    def test_jobs_beyond_20_wait_for_the_next_poll(self):
        tid = 990001
        for i in range(25):
            STORE.set_meta('agentq:%d:%024x' % (tid, i), json.dumps(
                {'env': {'job': str(i)}, 'state': 'queued', 'at': 1}))
        first, second = G._take(STORE, tid), G._take(STORE, tid)
        self.assertEqual((len(first), len(second)), (20, 5))
        self.assertEqual(G._take(STORE, tid), [])


BUILDER = os.path.join(ROOT, 'web', 'assets', 'policybuilder.js')
NODE = shutil.which('node')
# the builder's own fromPolicyText (inside open()) run with the core's helpers
RT_JS = r"""
const fs = require('fs');
const path = process.argv[1];
const C = require(path);
const m = fs.readFileSync(path, 'utf8').match(/  function fromPolicyText\(text\) \{[\s\S]*?\n  \}\n/);
const W = function () { return C.facts().platform === 'windows'; };
const fpt = new Function('empty', 'W', 'split', 'splitWin', 'addNeed', m[0] + '; return fromPolicyText;')(
  C.empty, W, C.split, C.splitWin, C.addNeed);
const inp = JSON.parse(fs.readFileSync(0, 'utf8'));
console.log(JSON.stringify(inp.map(function (c) {
  C.setFacts(c.facts);
  return {pol: C.check(C.fromPolicy(c.pol)).lines, text: C.check(fpt(c.text)).lines};
})));
"""

LINUX = """allow file /etc/nginx/ssl owner=root:nginx mode=0640
allow file '/srv/my certs' owner=www-data:www-data mode=0600
allow unit nginx.service reload,restart
allow unit foo@bar.service is-active
allow test -- nginx -t
allow test -- /usr/bin/check 'a b' "c'd"
allow script /usr/local/sbin/x.sh sha256=%s
allow script-hash %s
allow from 10.0.0.0/8
allow from 2001:db8::/32
allow probe local
allow probe web.example.test:443
allow probe [2001:db8::1]:443
allow connect db.example.test:5432
allow self-update
allow discover
limit files 30
limit size 2048""" % ('a' * 64, 'b' * 64)
WINDOWS = """allow file C:\\certs readers=IIS_IUSRS,"NT SERVICE\\W3SVC"
allow file "C:\\my certs"
allow service W3SVC restart,start
allow test -- "C:\\Program Files\\x\\y.exe" "a b"
allow script C:\\scripts\\x.ps1 sha256=%s
allow script-hash %s
allow from 192.168.1.0/24
allow probe local
allow probe web.example.test:443
allow connect db.example.test:1433
allow self-update
allow store
allow iis "Default Web Site"
allow iis *
allow rdp
allow role adfs
allow role ccs path=\\\\fs\\ccs
allow role wac msi=C:\\x\\WAC.msi
allow key-read "NT SERVICE\\MSSQLSERVER"
allow discover
allow adcs "ca01.example.local\\Example CA" template=WebServer,Web2
allow adcs "ca02.example.local\\Other" template=*
allow adcs "ca03.example.local\\Third CA" template="Web Server (v2),Other"
allow adcs-read
limit files 30
limit size 2048""" % ('c' * 64, 'd' * 64)


@unittest.skipUnless(NODE, 'needs node')
class DesignerRoundTrip(unittest.TestCase):
    """Every line the agent reads survives the designer: its policy as the agent said it, and
    a design's text, give the same lines back (an AD CS template with a space in its name was
    written unquoted - the agent refused the whole line)."""

    def test_round_trip(self):
        cases = []
        for mod, text in ((G.agent_mod(), LINUX), (G.agent_mod_windows(), WINDOWS)):
            pol = mod.parse_policy(text)
            self.assertEqual(pol['problems'], [])
            # the policy as acme keeps it: the agent's report, through clean_result
            said = G.clean_result({'ok': True, 'policy': json.loads(json.dumps(
                mod.policy_report(pol, 'e' * 64)))})['policy']
            self.assertEqual(P.compare(text, said, mod)['state'], 'matches')
            cases.append({'facts': mod.policy_facts(), 'pol': said, 'text': text,
                          'want': mod.policy_lines(pol)})
        got = json.loads(subprocess.run([NODE, '-e', RT_JS, BUILDER], input=json.dumps(cases),
                                        capture_output=True, text=True, timeout=60,
                                        check=True).stdout)
        for c, g in zip(cases, got):
            self.assertEqual(g['pol'], c['want'])
            self.assertEqual(g['text'], c['want'])
        self.assertIn('allow adcs "ca03.example.local\\Third CA" template="Web Server (v2),Other"',
                      got[1]['pol'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
