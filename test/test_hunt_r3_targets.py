#!/usr/bin/env python3
"""Hunt R, run 3, area "targets": the bugs found and fixed, each kept fixed.

    python3 test/test_hunt_r3_targets.py

- windows_ssh: the old acme certificates were removed when only IIS did not use them - one the
  Remote Desktop listener, SQL Server, WinRM or an http.sys binding (netsh) still used went;
  now the same look as the roles' clean-up and the agent's (_win_roles.USED).
- windows_ssh: a failing script put the previous files back from <path>.acme-prev and left
  that copy (of the old key) beside the file.
- deployfiles.js: a read-only account could still click the modes of the script and of the
  password, "As text" (and type into it), the chips, "From a template..." and type into the
  module's other options.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make  # noqa: E402
from acmelib.plugins.targets import _win_roles as WR  # noqa: E402


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def scripts_of(ssh):
    """Every PowerShell script run: -EncodedCommand decoded, or the .ps1 uploaded."""
    out = []
    ps1 = [d for p, d, _m in ssh.puts if p.endswith('.ps1')]
    for cmd, _inp in ssh.runs:
        if '-EncodedCommand ' in cmd:
            out.append(base64.b64decode(cmd.split('-EncodedCommand ')[1]).decode('utf-16-le'))
        elif '-File ' in cmd and ps1:
            out.append(ps1.pop(0).decode('utf-8-sig'))
    return out


def win(ssh):
    return make('windows_ssh', {'host': 'win', 'user': 'Administrator', 'auth': 'password',
                                'password': 'pw'}, FakeCtx(ssh=ssh))


class WindowsCleanupTest(unittest.TestCase):
    def test_the_old_ones_still_used_anywhere_are_kept(self):
        t = win(FakeSsh())
        sc = t.script(FakeBundle(), {'keep': 1}, 'C:/Windows/Temp/x.pfx', 'pw')
        for line in WR.USED:
            self.assertIn(line, sc)
        # Run-Native (netsh) defined before it is used
        self.assertLess(sc.index('function Run-Native'), sc.index("Run-Native 'netsh.exe'"))
        self.assertLess(sc.index('$used = @($used | Where-Object'), sc.index('$old = '))
        # RDP, SQL Server, WinRM and http.sys looked at - not IIS alone
        for what in ('netsh.exe', 'Win32_TSGeneralSetting', 'SuperSocketNetLib',
                     'WSMan:\\localhost\\Listener'):
            self.assertIn(what, sc.split('$used = @()')[1])
        self.assertIn('INUSE', sc)

    def test_keep_off_looks_at_nothing(self):
        t = win(FakeSsh())
        sc = t.script(FakeBundle(), {'keep': -1}, 'C:/Windows/Temp/x.pfx', 'pw')
        self.assertNotIn('$used', sc)
        self.assertNotIn('Run-Native', sc)

    def test_deploy_still_imports_and_says_what_it_did(self):
        ssh = FakeSsh([(r'EncodedCommand|-File ', (0, 'IMPORTED X\nRDP\nINUSE AB\n'
                                                      'REMOVED CD\n', ''))])
        t = win(ssh)
        words = t.deploy(FakeBundle(), {'rdp': True})
        self.assertIn('RDP', words)
        sc = [x for x in scripts_of(ssh) if 'Import-PfxCertificate' in x]
        self.assertTrue(sc)
        self.assertIn('WSMan:\\localhost\\Listener', sc[0])
        steps = [w for _l, w in t.ctx.steps]
        self.assertIn('the old AB is still bound: kept', steps)
        self.assertIn('removed the old CD', steps)


class WindowsPutBackTest(unittest.TestCase):
    def test_the_copy_only_for_putting_back_goes(self):
        ssh = FakeSsh()
        t = win(ssh)
        pairs = [({'path': 'C:/certs/a.pem', 'format': 'fullchain-pem'}, None),
                 ({'path': 'C:/certs/b.pem', 'format': 'fullchain-pem'}, None)]
        t._put_back(ssh, pairs, ['C:/certs/a.pem'])
        sc = scripts_of(ssh)[-1]
        self.assertIn("Copy-Item -LiteralPath 'C:/certs/a.pem.acme-prev' -Destination "
                      "'C:/certs/a.pem' -Force", sc)
        self.assertIn("Remove-Item -LiteralPath 'C:/certs/a.pem.acme-prev'", sc)
        self.assertLess(sc.index('Copy-Item'), sc.index("Remove-Item -LiteralPath "
                                                        "'C:/certs/a.pem.acme-prev'"))
        self.assertIn("Remove-Item -LiteralPath 'C:/certs/b.pem' -Force", sc)

    def test_a_kept_copy_stays(self):
        from acmelib.plugins.targets import _files as F
        ssh = FakeSsh()
        t = win(ssh)
        pairs = [({'path': 'C:/certs/a.pem', 'format': 'fullchain-pem'}, None)]
        t._put_back(ssh, pairs, ['C:/certs/a.pem'], lambda p: F.backup_path(p, 'bak'))
        sc = scripts_of(ssh)[-1]
        self.assertIn("Copy-Item -LiteralPath 'C:/certs/a.pem.bak'", sc)
        self.assertNotIn("Remove-Item -LiteralPath 'C:/certs/a.pem.bak'", sc)


@unittest.skipUnless(shutil.which('node'), 'no node')
class DeployFilesReadOnlyTest(unittest.TestCase):
    def run_page(self, role):
        p = subprocess.run(['node', os.path.join(HERE, 'deployfiles_readonly_page.js'), role],
                           capture_output=True, text=True, timeout=180)
        line = (p.stdout.strip().splitlines() or ['{}'])[-1]
        got = json.loads(line)
        if got.get('skip'):
            self.skipTest(got['skip'])
        self.assertNotIn('error', got, got.get('error'))
        return got

    def test_nothing_clickable_for_readonly(self):
        got = self.run_page('readonly')
        self.assertEqual(got['enabled'], [])
        self.assertGreater(got['buttons'], 5)

    def test_an_administrator_still_has_it_all(self):
        got = self.run_page('fulladmin')
        words = ' '.join(got['enabled'])
        for want in ('df-lay', 'As text', 'df-chip', 'Written here', 'Made by acme',
                     'From a template', 'textarea.test_cmd', 'input.service'):
            self.assertIn(want, words)


if __name__ == '__main__':
    unittest.main(verbosity=2)
