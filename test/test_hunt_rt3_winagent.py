#!/usr/bin/env python3
"""Hunt t3, the Windows agent (deploy/agent/acme_agent_win*.py) - regressions, on Linux with the
FakeWin facade (ACME_AGENT_FAKE_WINDOWS=1) and PowerShell faked (wincert.powershell).

    python3 test/test_hunt_rt3_winagent.py

  * a script the policy allows (allow script C:\\Scripts\\Reload.ps1) named by a job in another
    case (c:\\scripts\\reload.ps1) - one file on Windows - was refused by the plan;
  * allow role ccs path=\\\\.\\C:\\Windows\\System32 (a device path, not a share) went past the
    protected places;
  * a discovery asking roles could run PowerShell 120 s + 300 s - acme waits 180 s;
  * stdout in the ANSI code page: a name it has no letter for ended a command (UnicodeEncodeError).
"""
import importlib.util
import io
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT = os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py')
TMP = tempfile.mkdtemp(prefix='acme-hunt-t3w-')


def load(name):
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(TMP, sub), exist_ok=True)
        os.environ[k] = os.path.join(TMP, sub)
    os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
    os.environ['ACME_AGENT_FAKE_ROOT'] = os.path.join(TMP, 'fake')
    spec = importlib.util.spec_from_file_location(name, AGENT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AG = load('acme_agent_hunt_t3w')
WIN = AG.WIN
WC = AG._wincert()


class ScriptCase(unittest.TestCase):
    def test_script_path_any_case(self):
        pol = AG.parse_policy('allow script C:\\Scripts\\Reload.ps1 sha256=' + 'a' * 64)
        self.assertEqual(pol['problems'], [])
        for p in ('C:\\Scripts\\Reload.ps1', 'c:\\scripts\\reload.ps1', 'C:/SCRIPTS/RELOAD.PS1'):
            plan = AG.plan_check(pol, {'files': [], 'script': {'mode': 'path', 'path': p}})
            self.assertEqual(plan['script']['path'].lower(), 'c:\\scripts\\reload.ps1')
            plan = AG.plan_check(pol, {'files': [], 'post': [{'script': p}]})
            self.assertEqual(len(plan['post']), 1)

    def test_other_script_still_refused(self):
        pol = AG.parse_policy('allow script C:\\Scripts\\Reload.ps1 sha256=' + 'a' * 64)
        with self.assertRaises(AG.Refused) as e:
            AG.plan_check(pol, {'files': [], 'post': [{'script': 'C:\\Scripts\\Other.ps1'}]})
        self.assertEqual(e.exception.needs[0]['kind'], 'script')


class CcsPath(unittest.TestCase):
    def test_device_paths_refused(self):
        for x in ('\\\\.\\C:\\Windows\\System32', '\\\\.\\pipe\\x', '\\\\?\\C:\\ccs',
                  '\\\\?\\UNC\\srv\\share'):
            with self.assertRaises(AG.Refused, msg=x):
                WIN['role_entry'](['ccs', 'path=' + x])
            pol = AG.parse_policy('allow role ccs path=%s' % x)
            self.assertTrue(pol['problems'], x)
            self.assertNotIn('ccs', pol.get('roles') or {}, x)

    def test_shares_and_folders_as_before(self):
        self.assertEqual(WIN['role_entry'](['ccs', 'path=\\\\srv\\share\\ccs\\']),
                         ('ccs', '\\\\srv\\share\\ccs'))
        self.assertEqual(WIN['role_entry'](['ccs', 'path=\\\\srv.example.local\\ccs$']),
                         ('ccs', '\\\\srv.example.local\\ccs$'))
        self.assertEqual(WIN['role_entry'](['ccs', 'path=d:\\ccs']), ('ccs', 'D:\\ccs'))
        with self.assertRaises(AG.Refused):
            WIN['role_entry'](['ccs', 'path=C:\\Windows\\ccs'])


class DiscoverTime(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._ps, WC.powershell = WC.powershell, self.ps
        self._t = WC.time.time

    def tearDown(self):
        WC.powershell = self._ps
        WC.time.time = self._t

    def ps(self, script, env, timeout):
        self.calls.append(timeout)
        if '# acme-agent: discover' in script:
            # the script took 100 s
            now = self._t()
            WC.time.time = lambda: now + 100
            return 0, 'ACME {"store": [], "iis": [], "rdp": "", "roles": {}}'
        return 0, 'ROLE sql yes MSSQLSERVER\n'

    def test_roles_detection_gets_what_is_left(self):
        got = WC.discover(AG._Here(), {}, ['store', 'sql'])
        self.assertEqual(self.calls[0], WC.DISCOVER_PS_S)
        self.assertLessEqual(self.calls[1], 50)
        self.assertGreaterEqual(self.calls[1], 15)
        self.assertLess(WC.DISCOVER_PS_S + 15, 180)
        self.assertEqual([f['kind'] for f in got['found']], ['sql'])

    def test_detect_default_as_before(self):
        WC.detect(AG._Here())
        self.assertEqual(self.calls, [WC.PS_TIMEOUT])


class AnsiStdout(unittest.TestCase):
    def test_unencodable_name_written_escaped(self):
        raw = io.BytesIO()
        out = io.TextIOWrapper(raw, encoding='cp1252')
        old, sys.stdout = sys.stdout, out
        try:
            WIN['_out_never_fails']()
            print('IIS site \u010ce\u0161tina - Caf\xe9')
            out.flush()
        finally:
            sys.stdout = old
        self.assertEqual(raw.getvalue(), b'IIS site \\u010ce\x9atina - Caf\xe9\n')

    def test_no_stdout_no_failure(self):
        old, sys.stdout = sys.stdout, None
        try:
            WIN['_out_never_fails']()
        finally:
            sys.stdout = old


if __name__ == '__main__':
    unittest.main()
