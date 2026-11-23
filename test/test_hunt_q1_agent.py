#!/usr/bin/env python3
"""The hunt of 1.0.119 in the target agent (docs/target-agent.md) - each fix checked here.

    python3 test/test_hunt_q1_agent.py

* A || B: an alternative the policy does not allow ran (as root) when the allowed one failed;
  alternatives that are no command at all passed as "nothing to run";
* a deployment whose command could not even be started (a value with a NUL, a staging folder
  not there) left the new files in place - the previous ones are back now;
* the same join sent again (or replayed) after the fingerprint was confirmed undid the
  confirmation (the pending request made anew, its certificate gone);
* an agent's policy with a number where a list is, or Infinity where a number is, stopped acme
  with an error of its own;
* a design's title with a line break went on as lines of its own into Events;
* the lines that allow a deployment's folder or script were not quoted for the shell;
* install.sh --join without a code ended without a word; acme-agent join CODE --listen without
  an address ended with an IndexError once the agent's key and agent.json were replaced.

No agent processes, no network: temporary folders only.
"""
import base64
import hashlib
import importlib.util
import json
import os
import secrets
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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-huntq1-')
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

import acmelib.engine as E  # noqa: E402
from acmelib.certs import agents as G, agent_policy as P  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)


def agent_mod():
    spec = importlib.util.spec_from_file_location(
        'acme_agent_q1', os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AG = agent_mod()


class AnyAlternatives(unittest.TestCase):
    def test_only_allowed_alternatives_kept(self):
        pol = AG.parse_policy('allow unit nginx reload\n')
        plan = AG.plan_check(pol, {'reload': [{'any': [
            {'unit': 'nginx', 'verb': 'reload'}, {'argv': ['rm', '-rf', '/tmp/x']}]}]})
        self.assertEqual(plan['reload'], [{'any': [{'unit': 'nginx.service', 'verb': 'reload'}]}])
        # the allowed one second: the same
        plan = AG.plan_check(pol, {'reload': [{'any': [
            {'unit': 'apache2', 'verb': 'reload'}, {'unit': 'nginx', 'verb': 'reload'}]}]})
        self.assertEqual(plan['reload'], [{'any': [{'unit': 'nginx.service', 'verb': 'reload'}]}])

    def test_none_allowed_says_what_each_needs(self):
        pol = AG.parse_policy('')
        with self.assertRaises(AG.Refused) as e:
            AG.plan_check(pol, {'reload': [{'any': [{'unit': 'apache2', 'verb': 'reload'},
                                                    {'unit': 'httpd', 'verb': 'reload'}]}]})
        allow = [n['allow'] for n in e.exception.needs]
        self.assertIn('acme-agent allow unit apache2.service reload', allow)
        self.assertIn('acme-agent allow unit httpd.service reload', allow)

    def test_no_alternative_a_command_refused(self):
        pol = AG.parse_policy('allow unit nginx reload\n')
        with self.assertRaises(AG.Refused):
            AG.plan_check(pol, {'reload': [{'any': [{'unit': '-bad', 'verb': 'reload'}]}]})
        with self.assertRaises(AG.Refused):
            AG.plan_check(pol, {'reload': [{'any': [{'what': 1}, {'unit': 'nginx',
                                                                  'verb': 'stop'}]}]})


class FakeRoot(object):
    def __init__(self, priv, aid):
        self.priv, self.aid = priv, aid

    def conf(self):
        return {'agent_id': self.aid}

    def enc_key(self):
        return self.priv

    def systemctl(self):
        return 'systemctl'


@unittest.skipUnless(os.geteuid() == 0, 'needs root (chown of the files written)')
class DeployPutBack(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TMP)
        os.chmod(self.d, 0o755)
        self.path = os.path.join(self.d, 'a.pem')
        with open(self.path, 'wb') as fh:
            fh.write(b'OLD\n')
        os.chmod(self.path, 0o644)
        self.pol = AG.parse_policy('allow file %s owner=root:root mode=0644\n'
                                   'allow test -- true\n' % self.d)
        self.priv = secrets.token_bytes(32)
        self.aid = 'ag-0123456789abcdef'

    def deploy(self, extra=None):
        args = {'files': [{'path': self.path, 'mode': 0o644, 'owner': 'root:root',
                           'data': base64.b64encode(b'NEW\n').decode()}],
                'test': [{'argv': ['true']}], 'backup': 'none'}
        args.update(extra or {})
        with mock.patch.object(AG, 'policy_load', return_value=(self.pol, 'h' * 64, '')):
            return AG.Deploy(FakeRoot(self.priv, self.aid), args, {}), args

    def test_a_command_that_cannot_start_puts_back(self):
        dep, _args = self.deploy()
        with mock.patch.object(AG, 'policy_load', return_value=(self.pol, 'h' * 64, '')), \
                mock.patch.object(dep, 'run_op', side_effect=RuntimeError('no stage')):
            got = dep.run()
        self.assertFalse(got['ok'])
        self.assertTrue(got.get('rolled_back'))
        with open(self.path, 'rb') as fh:
            self.assertEqual(fh.read(), b'OLD\n')

    def test_sealed_value_with_nul_left_out(self):
        pub = base64.b64encode(AG.x25519_public(self.priv)).decode()
        sealed = G.seal(pub, self.aid, 'env', json.dumps({'ACME_PASSWORD': 'a\x00b'}).encode())
        dep, _args = self.deploy({'env_sealed': sealed})
        with mock.patch.object(AG, 'policy_load', return_value=(self.pol, 'h' * 64, '')):
            got = dep.run()
        self.assertTrue(got['ok'], got)
        with open(self.path, 'rb') as fh:
            self.assertEqual(fh.read(), b'NEW\n')


class JoinAgain(unittest.TestCase):
    def test_same_join_after_confirm_keeps_the_confirmation(self):
        row = {'id': 4711, 'name': 'q1-web'}
        secret = 'sec-' + secrets.token_hex(8)
        cid = secrets.token_hex(6)
        c = {'id': cid, 'agent_id': 'ag-' + secrets.token_hex(8), 'until': time.time() + 3600,
             'tries': 0, 'mode': 'active'}
        G.state_put(STORE, row['id'], {'code': c})
        key = os.path.join(TMP, 'join.key')
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-out', key], check=True, capture_output=True)
        csr = subprocess.run(['openssl', 'req', '-new', '-key', key, '-subj', '/CN=acme-agent'],
                             check=True, capture_output=True, text=True).stdout
        enc = base64.b64encode(secrets.token_bytes(32)).decode()
        nonce = secrets.token_hex(16)
        req = {'csr': csr, 'enc_pub': enc, 'nonce': nonce, 'host': 'vm1', 'version': '1.0.119',
               'proof': G.proof(secret, 'join', cid, hashlib.sha256(csr.encode()).hexdigest(),
                                enc, nonce)}
        st = G.state(STORE, row['id'])
        fp = G.join_take(STORE, row, st, st['code'], secret, req)
        st = G.state(STORE, row['id'])
        self.assertEqual(st['pending']['fp'], fp)
        st['pending']['cert'] = 'THE CERTIFICATE'          # a person confirmed it
        G.state_put(STORE, row['id'], st)
        st = G.state(STORE, row['id'])
        self.assertEqual(G.join_take(STORE, row, st, st['code'], secret, req), fp)
        self.assertEqual(G.state(STORE, row['id'])['pending'].get('cert'), 'THE CERTIFICATE')
        # another request with the used code: refused as before
        other = dict(req, csr=csr.replace('A', 'B', 1))
        st = G.state(STORE, row['id'])
        with self.assertRaises(G.PluginError):
            G.join_take(STORE, row, st, st['code'], secret, other)


class AgentWords(unittest.TestCase):
    def test_policy_of_odd_shapes(self):
        inf = float('inf')
        pol = {'hash': 'x', 'files': [{'dir': '/etc/x', 'mode': inf}, {'dir': '/etc/y'}],
               'limits': {'files': inf, 'size': 'big'}, 'from': 5, 'tests': {'a': 1},
               'units': [], 'probe': 'abc', 'problems': None, 'scripts': 7}
        got = G.clean_policy(pol)
        self.assertEqual([f['dir'] for f in got['files']], ['/etc/y'])
        self.assertEqual(got['limits'], {'files': 20, 'size': 1048576})
        self.assertEqual((got['from'], got['tests'], got['probe'], got['scripts']),
                         ([], [], [], []))
        out = G.clean_result({'ok': True, 'policy': pol})
        self.assertTrue(out['ok'])


class Design(unittest.TestCase):
    def test_title_one_line(self):
        row = {'id': 4712, 'name': 'q1-design'}
        v = P.design_save(STORE, row, 'allow probe local\n', {}, 'one\ntwo\r\nthree', 'a\nnote',
                          'tester')
        self.assertEqual(v['title'], 'one two three')
        self.assertEqual(v['note'], 'a\nnote')
        ev = STORE.db.rows("SELECT words FROM events WHERE words LIKE '%q1-design%'")
        self.assertTrue(ev and all('\n' not in e['words'] for e in ev), ev)

    def test_allow_lines_quoted(self):
        from acmelib.certs import api_deploys, runtime

        class Bundle(object):
            key_pem = 'K'

        class Cls(object):
            def __init__(self, conf, ctx):
                pass

            def resolved(self, *a, **k):
                return {'files': []}

            def agent_key_of(self, bundle):
                return False

            def plan(self, *a, **k):
                return {'files': [{'path': '/etc/my certs/a.pem', 'mode': 0o640,
                                   'owner': 'root:ssl'}], 'pre': [], 'test': [], 'reload': [],
                        'post': [], 'script': {'mode': 'path', 'path': '/opt/my app/x.sh'}}

            def served_places(self, opts):
                return []

        class Ctx(object):
            def __init__(self, *a, **k):
                pass

            def tidy(self):
                pass

        store = mock.Mock()
        store.db.rows.return_value = [{'id': 1, 'cert_id': 1, 'enabled': 1, 'cert': 'c'}]
        with mock.patch.object(api_deploys, '_setup', return_value=(
                {'name': 't'}, Cls, {}, {}, {}, None)), \
                mock.patch.object(api_deploys, '_bundle', return_value=Bundle()), \
                mock.patch.object(runtime, 'RunContext', Ctx), \
                mock.patch('acmelib.certs.store.plugin_config', return_value={}):
            got = P.deploy_needs(store, {'name': 't'})
        allow = [it['allow'] for it in got[0]['items']]
        self.assertIn("acme-agent allow file '/etc/my certs' --owner root:ssl --mode 0640", allow)
        self.assertIn("acme-agent allow script '/opt/my app/x.sh'", allow)


class CommandLine(unittest.TestCase):
    def test_install_join_without_code_says_so(self):
        # stops while its words are read - before the check that it runs as root
        got = subprocess.run(['bash', os.path.join(ROOT, 'deploy', 'agent', 'install.sh'),
                              '--join'], capture_output=True, text=True, timeout=30)
        self.assertEqual(got.returncode, 1)
        self.assertIn('--join CODE', got.stderr)

    @unittest.skipUnless(os.geteuid() == 0, 'acme-agent join runs as root')
    def test_join_listen_without_address_before_anything_changes(self):
        data = {'v': 1, 't': 1, 'n': 'x', 'm': 'passive', 'i': 'a' * 12, 's': 'sec',
                'ca': 'a' * 64, 'ck': 'b' * 64, 'u': int(time.time()) + 600, 'p': 8446}
        code = 'ACAG1.' + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        os.makedirs(AENV['ACME_AGENT_ETC'], exist_ok=True)
        conf = os.path.join(AENV['ACME_AGENT_ETC'], 'agent.json')
        with open(conf, 'w') as fh:
            fh.write('{"joined": true, "agent_id": "ag-0123456789abcdef"}')
        with self.assertRaises(SystemExit) as e:
            AG.cmd_join([code, '--listen'])
        self.assertIn('--listen ADDRESS', str(e.exception))
        with open(conf) as fh:
            self.assertIn('ag-0123456789abcdef', fh.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
