#!/usr/bin/env python3
"""Bug hunt R1, the Windows agent (ACME_AGENT_FAKE_WINDOWS=1, never wine).

    python3 test/test_hunt_r1_winagent.py

* a deployment's files on Windows are one file whatever the case of their names: a stale path
  that differs only in case from a file written now is never taken away after it is written
  (acme compares the paths case-sensitively), and the same file twice is refused;
* windows-install --join on an agent that joined already (an upgrade or repair run with the same
  msiexec line, JOINCODE=...) keeps its identity - no join;
* the MSI hides the join's command line from the install log (HideTarget, set after wixl);
* an import into the machine store that finds no private key takes the certificate out again.
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT = os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py')
TMP = tempfile.mkdtemp(prefix='acme-hunt-r1-win-')
for k in ('ACME_AGENT_ETC', 'ACME_AGENT_STATE', 'ACME_AGENT_ROOT_STATE', 'ACME_AGENT_RUN',
          'ACME_AGENT_FAKE_SID', 'ACME_AGENT_FAKE_ELEVATED'):
    os.environ.pop(k, None)
os.environ.update(ACME_AGENT_FAKE_ROOT=os.path.join(TMP, 'fake'), ACME_AGENT_NO_SERVICES='1',
                  ACME_AGENT_NO_SYSTEMD='1')
os.makedirs(os.environ['ACME_AGENT_FAKE_ROOT'])


def load(name, fake):
    old = os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
    if fake:
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
    try:
        spec = importlib.util.spec_from_file_location(name, AGENT)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
        if old is not None:
            os.environ['ACME_AGENT_FAKE_WINDOWS'] = old


AG = load('acme_agent_hunt_r1_win', True)
LX = load('acme_agent_hunt_r1_lx', False)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class CaseOfNames(unittest.TestCase):
    def test_stale_differing_in_case_is_the_file_written(self):
        pol = AG.parse_policy('allow file C:\\certs\n')
        self.assertEqual(pol['problems'], [])
        plan = AG.plan_check(pol, {'files': [{'path': 'C:\\certs\\Site.pem'}],
                                   'stale': ['C:\\CERTS\\site.pem', 'C:\\certs\\old.pem']})
        self.assertEqual([f['path'] for f in plan['files']], ['C:\\certs\\Site.pem'])
        self.assertEqual(plan['stale'], ['C:\\certs\\old.pem'])

    def test_the_same_file_twice_refused(self):
        pol = AG.parse_policy('allow file C:\\certs\n')
        with self.assertRaises(AG.Refused) as cm:
            AG.plan_check(pol, {'files': [{'path': 'C:\\certs\\a.pem'},
                                          {'path': 'c:/Certs/A.pem'}]})
        self.assertIn('twice', str(cm.exception))

    def test_linux_names_keep_their_case(self):
        pol = LX.parse_policy('allow file /etc/ssl/acme\n')
        plan = LX.plan_check(pol, {'files': [{'path': '/etc/ssl/acme/A.pem'},
                                             {'path': '/etc/ssl/acme/a.pem'}],
                                   'stale': ['/etc/ssl/acme/B.pem']})
        self.assertEqual(len(plan['files']), 2)
        self.assertEqual(plan['stale'], ['/etc/ssl/acme/B.pem'])


class InstallWithCode(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._join = AG.cmd_join
        AG.cmd_join = lambda argv: self.calls.append(list(argv)) or 0
        AG.WIN['cmd_init']()

    def tearDown(self):
        AG.cmd_join = self._join
        key, crt = AG.tls_paths()
        for p in (AG.CONF, key, crt):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

    def test_not_joined_joins(self):
        self.assertEqual(AG.main(['windows-install', '--join', 'ACAE1.abc']), 0)
        self.assertEqual(self.calls, [['ACAE1.abc', '--no-wait']])

    def test_joined_keeps_its_identity(self):
        key, crt = AG.tls_paths()
        os.makedirs(os.path.dirname(key), exist_ok=True)
        for p in (key, crt):
            with open(p, 'w') as fh:
                fh.write('x')
        with open(AG.CONF, 'w') as fh:
            json.dump({'joined': True, 'agent_id': 'ag-1'}, fh)
        self.assertEqual(AG.main(['windows-install', '--join', 'ACAE1.abc']), 0)
        self.assertEqual(self.calls, [])


class Scripts(unittest.TestCase):
    def test_import_without_key_takes_it_out(self):
        ps = AG._wincert().PS_IMPORT
        i = ps.index('if (-not $cert.HasPrivateKey)')
        j = ps.index("throw 'the certificate in the machine store has no private key'")
        self.assertIn('Remove-Item', ps[i:j])
        self.assertIn('if (-not $had)', ps[i:j])


class Msi(unittest.TestCase):
    def test_join_action_hides_its_target(self):
        sys.path.insert(0, os.path.join(ROOT, 'tools'))
        try:
            import agent_windows as T
        finally:
            sys.path.pop(0)
        self.assertEqual(T.HIDE_TARGET, 0x2000)
        self.assertIn('AgentInstallJoin', T.HIDDEN_ACTIONS)
        self.assertIn('CustomAction', T.SCHEMA)
        joins = [a for a in T.ACTIONS if 'JOINCODE' in a[1]]
        self.assertTrue(joins)
        self.assertEqual({a[0] for a in joins}, set(T.HIDDEN_ACTIONS))


if __name__ == '__main__':
    unittest.main(verbosity=2)
