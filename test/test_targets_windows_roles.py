#!/usr/bin/env python3
"""The roles of the windows_ssh target (acmelib/plugins/targets/_win_roles.py), with
the fake SSH world of test_targets.py: the PowerShell each role makes, the order
(import -> key read -> roles -> old ones), a role not installed, the test, the
preview, LDAPS's check on 636 - and windows_ssh unchanged without roles.

    python3 -m unittest test/test_targets_windows_roles.py
"""
import base64
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeSsh, FakeCtx, make  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import _win_roles as WR  # noqa: E402

CONF = {'host': 'win.example.test', 'user': 'Administrator', 'auth': 'password',
        'password': 'pw'}


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def script_of(cmd, ssh=None):
    """The PowerShell a command ran: -EncodedCommand, or the .ps1 uploaded for -File."""
    if '-EncodedCommand ' in cmd:
        return base64.b64decode(cmd.split('-EncodedCommand ')[1]).decode('utf-16-le')
    m = re.search(r'-File "([^"]+)"', cmd)
    if m and ssh is not None:
        for path, data, _mode in ssh.puts:
            if path == m.group(1):
                return data.decode('utf-8-sig')
    return ''


def balanced(ps):
    """Quotes, braces, brackets and parentheses of a PowerShell text close (a here-string
    is not used): -> '' or what is wrong."""
    stack, i, n = [], 0, len(ps)
    pairs = {')': '(', '}': '{', ']': '['}
    while i < n:
        c = ps[i]
        if c == "'":
            j = i + 1
            while True:
                if j >= n:
                    return 'an unclosed \' at %d' % i
                if ps[j] == "'":
                    if j + 1 < n and ps[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            while True:
                if j >= n:
                    return 'an unclosed " at %d' % i
                if ps[j] == '`':
                    j += 2
                    continue
                if ps[j] == '"':
                    if j + 1 < n and ps[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if c == '`':
            i += 2
            continue
        if c == '#' and (i == 0 or ps[i - 1] in ' \n\t;'):
            while i < n and ps[i] != '\n':
                i += 1
            continue
        if c in '({[':
            stack.append((c, i))
        elif c in ')}]':
            if not stack or stack[-1][0] != pairs[c]:
                return 'a stray %s at %d: %r' % (c, i, ps[max(0, i - 60):i + 1])
            stack.pop()
        i += 1
    if stack:
        return 'unclosed %s at %d: %r' % (stack[-1][0], stack[-1][1],
                                          ps[stack[-1][1]:stack[-1][1] + 80])
    return ''


ALL_ON = {'role_' + r[0]: True for r in WR.ROLES}
ALL_ON.update({'ccs_path': '\\\\files\\ccs', 'ccs_password': "it's", 'sp_url':
               'https://intranet.example.test', 'key_read': ['NT Service\\Foo'],
               'ex_imap': True, 'ex_pop': True, 'ex_remove_old': True, 'winrm_create': True,
               'winrm_firewall': True, 'sql_force': 'on', 'cs_restart': True,
               'ftp_site': 'FTP site', 'ftp_restart': True, 'sp_host': 'intranet.example.test',
               'wac_msi': 'C:\\i\\wac.msi'})


class World(object):
    """A Windows server over the fake SSH: each run answers by what it is."""
    def __init__(self, detect=None, fail=None):
        self.detect = detect or {}
        self.fail = fail or {}
        self.ssh = FakeSsh([(r'powershell', self.answer)])
        self.scripts = []

    def answer(self, cmd, inp):
        ps = script_of(cmd, self.ssh)
        self.scripts.append(ps)
        if 'ROLE ' in ps and 'function R(' in ps:
            return 0, ''.join('ROLE %s %s %s\n' % (k, 'yes' if v[0] else 'no', v[1])
                              for k, v in self.detect.items()), ''
        if "{ 'YES' }" in ps:
            return 0, 'YES\n', ''
        if '$adm = ' in ps:
            return 0, 'Administrator|Windows Server 2022|5.1|True\n', ''
        for marker, words in self.fail.items():
            if marker in ps:
                return 1, 'STEP info about to fail\nERROR: %s\n' % words, ''
        if 'Import-PfxCertificate' in ps:
            return 0, 'IMPORTED X\n', ''
        return 0, 'STEP ok it worked\n', ''

    def runs(self, rx):
        return [s for s in self.scripts if re.search(rx, s)]


def target(world):
    ctx = FakeCtx(ssh=world.ssh)
    return make('windows_ssh', CONF, ctx), ctx


class RoleScriptTest(unittest.TestCase):
    """Each role's PowerShell, as made."""
    def env(self, b):
        return {'names': b.names, 'pfx': 'C:/Windows/Temp/r.pfx', 'pfx_pw': 'pfxpw',
                'ccs_pfx': 'C:/Windows/Temp/c.pfx', 'ccs_pw': "it's"}

    def full(self, key, opts):
        b = FakeBundle()
        body = WR.role_script(key, dict(ALL_ON, **opts), self.env(b))
        return '\n'.join(WR.head(C.sha1_thumb(b), 'acme-www-', '\n'.join(body)) + body)

    def test_every_role_is_balanced(self):
        b = FakeBundle()
        for key, _l, _t, _n in WR.ROLES:
            for opts in (ALL_ON, {k: False for k in ALL_ON if k.startswith(('ex_r', 'sql_r'))}):
                ps = self.full(key, opts)
                self.assertEqual(balanced(ps), '', '%s: %s' % (key, balanced(ps)))
                self.assertIn("$thumb = '%s'" % C.sha1_thumb(b), ps)
                self.assertIn('is not in LocalMachine\\My', ps)
        for body in (WR.cleanup_script('acme-x-', 1), WR.DETECT, WR.key_read_script(["a'b"])):
            ps = '\n'.join(WR.head('AB', 'p', '\n'.join(body)) + body)
            self.assertEqual(balanced(ps), '', balanced(ps))

    def test_helpers_only_when_used(self):
        ps = self.full('ftp', {'ftp_restart': False})
        self.assertNotIn('function Grant-KeyRead', ps)
        self.assertIn('function Need-Service', ps)
        self.assertIn('function Say', ps)
        self.assertIn('function Grant-KeyRead', self.full('sql', {}))
        self.assertIn('function Run-Native', self.full('sql', {}))    # Grant-KeyRead needs it

    def test_rds(self):
        ps = self.full('rds', {'rds_publishing': False, 'rds_broker': "cb'1.example.test"})
        self.assertIn("Need-Module 'RemoteDesktop'", ps)
        self.assertIn("$broker = 'cb''1.example.test'", ps)
        self.assertIn("foreach ($r in @('RDGateway', 'RDWebAccess', 'RDRedirector'))", ps)
        self.assertIn("Set-RDCertificate -Role $r -ImportPath 'C:/Windows/Temp/r.pfx' -Password "
                      "$pfxpw -ConnectionBroker $broker -Force", ps)
        self.assertIn('Get-RDCertificate -Role $r', ps)                # idempotent
        self.assertIn('GetHostEntry', self.full('rds', {'rds_broker': ''}))

    def test_rdgw(self):
        ps = self.full('rdgw', {})
        self.assertIn("Import-Module -Name $m", ps)
        self.assertIn("Need-Module 'RemoteDesktopServices'", ps)
        self.assertIn("Set-Item -Path $p -Value $thumb", ps)
        self.assertIn("RDS:\\GatewayServer\\SSLCertificate\\Thumbprint", ps)
        self.assertIn("Restart-Role 'TSGateway'", ps)
        self.assertLess(ps.index('-eq $thumb'), ps.index('Set-Item -Path $p'))
        self.assertNotIn("Restart-Role 'TSGateway'", self.full('rdgw', {'rdgw_restart': False}))

    def test_adfs(self):
        ps = self.full('adfs', {})
        for words in ("Set-AdfsSslCertificate -Thumbprint $thumb",
                      "Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint "
                      "$thumb", "Grant-KeyRead $cert $svc.StartName", "Restart-Role 'adfssrv'",
                      "Name='adfssrv'"):
            self.assertIn(words, ps)
        ps = self.full('adfs', {'adfs_service_comm': False, 'adfs_grant': False,
                                'adfs_restart': False})
        self.assertNotIn('Service-Communications -Thumbprint', ps)
        self.assertNotIn('Grant-KeyRead $cert', ps)
        self.assertNotIn("Restart-Role 'adfssrv'", ps)

    def test_wap(self):
        ps = self.full('wap', {})
        self.assertIn('Set-WebApplicationProxySslCertificate -Thumbprint $thumb', ps)
        self.assertIn('Set-WebApplicationProxyApplication -ID $a.ID -ExternalCertificateThumbprint '
                      '$thumb', ps)
        self.assertIn('$olds -contains $_.ExternalCertificateThumbprint', ps)
        # the old thumbprints are read before the new one is set
        self.assertLess(ps.index('$olds = '), ps.index('Set-WebApplicationProxySslCertificate'))
        self.assertNotIn('Set-WebApplicationProxyApplication',
                         self.full('wap', {'wap_apps': False}))

    def test_sql(self):
        ps = self.full('sql', {'sql_instance': 'SQLEXPRESS'})
        self.assertIn("$inst = 'SQLEXPRESS'", ps)
        self.assertIn("Instance Names\\SQL", ps)
        self.assertIn("\\MSSQLServer\\SuperSocketNetLib", ps)
        self.assertIn("$want = $thumb.ToLowerInvariant()", ps)
        self.assertIn("-Name 'Certificate' -Value $want -PropertyType String", ps)
        self.assertIn("'MSSQL$' + $inst", ps)
        self.assertIn("Grant-KeyRead $cert $svc.StartName", ps)
        self.assertIn("-Name 'ForceEncryption' -Value 1 -PropertyType DWord", ps)
        self.assertIn("Restart-Role $svcName", ps)
        self.assertIn('DependentServices', ps)                          # SQL Agent comes back
        self.assertIn('$cur -ceq $want', ps)                            # idempotent
        ps = self.full('sql', {'sql_force': 'keep', 'sql_restart': False})
        self.assertNotIn('ForceEncryption', ps)
        self.assertNotIn('Restart-Role $svcName', ps)
        self.assertIn('is restarted', ps)

    def test_ldaps(self):
        ps = self.full('ldaps', {})
        self.assertIn('Services\\NTDS\\SystemCertificates\\My\\Certificates', ps)
        self.assertIn('Copy-Item -LiteralPath $src -Destination $dst -Recurse', ps)
        self.assertIn('dn:`r`nchangetype: modify`r`nadd: renewServerCertificate`r`n'
                      'renewServerCertificate: 1`r`n-`r`n', ps)
        self.assertIn("Run-Native 'ldifde.exe' @('-i', '-f', $ldf)", ps)
        self.assertLess(ps.index('Copy-Item'), ps.index('ldifde.exe\' @'))
        ps = self.full('ldaps', {'ldaps_store': 'my'})
        self.assertNotIn('Services\\NTDS', ps)
        self.assertIn('renewServerCertificate', ps)

    def test_winrm(self):
        ps = self.full('winrm', {})
        self.assertIn("'WSMan:\\localhost\\Listener\\' + $l.Name + '\\CertificateThumbprint'", ps)
        self.assertIn("Set-Item -Path $p -Value $thumb -Force", ps)
        self.assertIn("New-Item -Path WSMan:\\localhost\\Listener -Transport HTTPS -Address * "
                      "-HostName $h -CertificateThumbPrint $thumb", ps)
        self.assertIn("$h = 'www.example.test'", ps)
        self.assertIn("-LocalPort 5986", ps)
        ps = self.full('winrm', {'winrm_create': False, 'winrm_firewall': False})
        self.assertIn("there is no HTTPS listener", ps)
        self.assertNotIn("New-NetFirewallRule", ps)

    def test_sstp(self):
        ps = self.full('sstp', {})
        self.assertIn("Need-Module 'RemoteAccess'", ps)
        self.assertIn("Set-RemoteAccess -SslCertificate $cert", ps)
        self.assertIn("Restart-Role 'RemoteAccess'", ps)

    def test_ccs(self):
        ps = self.full('ccs', {})
        self.assertIn("$dir = '\\\\files\\ccs'", ps)
        self.assertIn("ConvertTo-SecureString -String 'it''s'", ps)
        self.assertIn("@('www.example.test.pfx', 'example.test.pfx')", ps)
        self.assertIn('Get-PfxData -FilePath $dstf', ps)                # idempotent
        self.assertEqual(WR.ccs_file_names(['*.Example.com', 'a.example.com']),
                         ['_.example.com.pfx', 'a.example.com.pfx'])
        self.assertEqual(WR.ccs_file_names(['a.x', 'b.x'], 'first'), ['a.x.pfx'])
        self.assertRaises(PluginError, WR.ccs_file_names, ['a\\..\\b'])
        self.assertIn('New-Object System.Security.SecureString',
                      '\n'.join(WR.role_script('ccs', ALL_ON, {'names': ['a.x']})))

    def test_ftp(self):
        ps = self.full('ftp', {'ftp_site': "Bob's FTP"})
        self.assertIn("$site = 'Bob''s FTP'", ps)
        self.assertIn("SetAttributeValue('serverCertHash', $thumb)", ps)
        self.assertIn("$sm.CommitChanges()", ps)
        self.assertIn("Restart-Role 'ftpsvc'", ps)
        self.assertIn("$sm.SiteDefaults", self.full('ftp', {'ftp_site': ''}))

    def test_exchange(self):
        ps = self.full('exchange', {})
        self.assertIn("$want = @('IIS', 'SMTP', 'IMAP', 'POP')", ps)
        self.assertIn("Enable-ExchangeCertificate -Thumbprint $thumb -Services ($want -join ',') "
                      "-Force -Confirm:$false", ps)
        self.assertNotIn('DoNotRequireSsl', ps)
        self.assertIn("MSExchangeIMAP4", ps)
        self.assertIn("MSExchangePOP3", ps)
        self.assertIn("[string]$x.Services -eq 'None'", ps)
        self.assertIn("Remove-ExchangeCertificate -Thumbprint $x.Thumbprint -Confirm:$false", ps)
        self.assertIn("is not on this server", ps)
        ps = self.full('exchange', {'ex_imap': False, 'ex_pop': False, 'ex_remove_old': False})
        self.assertNotIn('MSExchangeIMAP4', ps)
        self.assertNotIn('Remove-ExchangeCertificate', ps)

    def test_lync(self):
        ps = self.full('lync', {'cs_external': False})
        self.assertIn("@('Default', 'WebServicesInternal')", ps)
        self.assertIn("Set-CsCertificate -Type $ty -Thumbprint $thumb", ps)
        self.assertIn("Start-CsWindowsService", ps)

    def test_sharepoint(self):
        ps = self.full('sharepoint', {'sp_zone': 'Internet', 'sp_port': 8443})
        self.assertIn("Import-SPCertificate -Path 'C:/Windows/Temp/r.pfx' -Password $pfxpw "
                      "-Exportable", ps)
        self.assertIn("Set-SPWebApplication -Identity $url -Zone 'Internet' -Port 8443 "
                      "-SecureSocketsLayer -Certificate $spc -HostHeader 'intranet.example.test' "
                      "-UseServerNameIndication", ps)
        self.assertLess(ps.index('Import-SPCertificate'), ps.index('Set-SPWebApplication'))

    def test_wac(self):
        ps = self.full('wac', {})
        self.assertIn("Microsoft.WindowsAdminCenter.Configuration", ps)
        self.assertIn("Set-WACCertificateSubjectName @a", ps)
        self.assertIn("ContainsKey('Thumbprint')", ps)
        self.assertIn("Restart-Role 'WindowsAdminCenter'", ps)
        self.assertIn("('SME_THUMBPRINT=' + $thumb)", ps)
        self.assertIn("$msi = 'C:\\i\\wac.msi'", ps)
        self.assertIn("ServerManagementGateway", ps)

    def test_key_read_and_escaping(self):
        self.assertEqual(WR.key_read_script(["DOM\\o'neil"]),
                         ["Grant-KeyRead $cert 'DOM\\o''neil'"])
        self.assertEqual(WR.ps_str("a'b"), "'a''b'")
        ps = self.full('sql', {})
        self.assertIn("icacls.exe", ps)
        self.assertIn("'*' + $sid + ':(R)'", ps)

    def test_refused_before_anything(self):
        bad = WR.check_options({'role_ccs': True, 'role_sql': True, 'sql_instance': 'a;b',
                                'role_sharepoint': True, 'sp_url': 'intranet',
                                'role_exchange': True, 'ex_iis': False, 'ex_smtp': False})
        words = ' '.join(bad)
        self.assertIn('give the folder', words)
        self.assertIn('not an instance name', words)
        self.assertIn('is an URL', words)
        self.assertIn('at least one service', words)
        self.assertEqual(WR.check_options({}), [])

    def test_fields(self):
        keys = [f['key'] for f in WR.role_fields()]
        self.assertEqual(len(keys), len(set(keys)))
        for f in WR.role_fields():
            if f['key'].startswith('role_') or f['key'] == 'key_read':
                self.assertNotIn('show_if', f)
            else:
                self.assertTrue(any(k.startswith('role_') for k in f['show_if']), f['key'])
        self.assertEqual([f for f in WR.role_fields() if f['key'] == 'ccs_password'][0]['type'],
                         'secret')


class DeployTest(unittest.TestCase):
    def test_order_import_keyread_roles_cleanup(self):
        w = World()
        t, ctx = target(w)
        b = FakeBundle()
        words = t.deploy(b, {'role_sql': True, 'role_rds': True, 'key_read': ['NT Service\\X'],
                             'iis': 'Default Web Site | www.example.test | 443'})
        self.assertIn('SQL Server', words)
        self.assertIn('Remote Desktop Services', words)
        s = w.scripts
        imp = [i for i, x in enumerate(s) if 'Import-PfxCertificate' in x][0]
        kr = [i for i, x in enumerate(s) if "Grant-KeyRead $cert 'NT Service\\X'" in x][0]
        rds = [i for i, x in enumerate(s) if 'Set-RDCertificate' in x][0]
        sql = [i for i, x in enumerate(s) if 'SuperSocketNetLib' in x and 'Instance Names' in x][0]
        old = [i for i, x in enumerate(s) if 'Select-Object -Skip 1' in x and 'Say' in x][0]
        clean = [i for i, x in enumerate(s) if 'acme-roles-' in x and 'Remove-Item' in x
                 and 'Set-RDCertificate' not in x][0]
        self.assertTrue(imp < kr < rds < sql < old < clean, (imp, kr, rds, sql, old, clean))
        # the import does not remove the old ones itself when roles are on
        self.assertNotIn('REMOVED', s[imp])
        self.assertIn('New-WebBinding', s[imp])
        # one PFX for the import, one for the RDS role - both random passwords, deleted
        pfx = [p for p, _d, _m in w.ssh.puts if p.endswith('.pfx')]
        self.assertEqual(len(pfx), 2)
        self.assertIn(pfx[1], s[rds])
        self.assertIn(pfx[1], s[clean])
        steps = [x[1] for x in ctx.steps]
        self.assertIn('roles on the server: Remote Desktop Services, SQL Server', steps)
        self.assertIn('SQL Server: done', steps)
        self.assertIn('it worked', steps)
        # remembered: the same again is a no-op
        n = len(w.scripts)
        self.assertIn('unchanged', t.deploy(b, {'role_sql': True, 'role_rds': True,
                                                'key_read': ['NT Service\\X'],
                                                'iis': 'Default Web Site | www.example.test | '
                                                       '443'}))
        self.assertEqual(len(w.scripts), n + 1)                    # only "is it there?"

    def test_role_not_installed(self):
        w = World(fail={'RDS:\\GatewayServer': "RD Gateway: the service TSGateway is not on this "
                                               "server - is the role installed?"})
        t, ctx = target(w)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'role_rdgw': True, 'role_sstp': True})
        self.assertIn('RD Gateway failed (SSTP VPN done)', str(e.exception))
        self.assertIn('the old certificates are kept', str(e.exception))
        bad = [x[1] for x in ctx.steps if x[0] == 'bad']
        self.assertTrue(any('TSGateway is not on this server' in x for x in bad), bad)
        self.assertIn('about to fail', [x[1] for x in ctx.steps])
        self.assertFalse(w.runs(r'Select-Object -Skip'))            # nothing removed
        self.assertEqual(ctx.kv, {})                                  # not remembered
        self.assertIn('SSTP VPN: done', [x[1] for x in ctx.steps])

    def test_key_read_failure_stops(self):
        w = World(fail={"Grant-KeyRead $cert 'nobody'": 'the account nobody is not known here'})
        t, ctx = target(w)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'role_sql': True, 'key_read': ['nobody']})
        self.assertIn('read on the key could not be given', str(e.exception))
        self.assertFalse(w.runs(r'SuperSocketNetLib'))

    def test_refused_options_change_nothing(self):
        w = World()
        t, ctx = target(w)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'role_ccs': True})
        self.assertFalse(e.exception.retry)
        self.assertEqual(w.ssh.runs, [])

    def test_ccs_pfx_with_its_password(self):
        w = World()
        t, ctx = target(w)
        t.deploy(FakeBundle(), {'role_ccs': True, 'ccs_path': 'D:\\CCS', 'ccs_password': 'sesame'})
        ccs = [d for p, d, _m in w.ssh.puts if 'acme-ccs-' in p][0]
        T.openssl('pkcs12', '-in', '/dev/stdin', '-nokeys', '-passin', 'pass:sesame', data=ccs)
        self.assertTrue(w.runs(r"ConvertTo-SecureString -String 'sesame'"))

    def test_big_script_goes_as_a_file(self):
        w = World()
        t, ctx = target(w)
        t.deploy(FakeBundle(), {'role_wac': True})
        cmd = [c for c, _i in w.ssh.runs if 'WindowsAdminCenter' in script_of(c, w.ssh)][0]
        self.assertIn('-File "C:/Windows/Temp/acme-', cmd)
        ps = script_of(cmd, w.ssh)
        self.assertTrue(ps.startswith('Remove-Item -LiteralPath $PSCommandPath'))
        self.assertLessEqual(max(len(c) for c, _i in w.ssh.runs), WR.CMD_MOST + 100)

    def test_ldaps_checked_on_636(self):
        t, ctx = target(World())
        seen = []
        orig = C.check_served
        try:
            import acmelib.plugins.targets._common as CC
            CC.check_served = lambda ctx, b, hp, sni=None, **k: seen.append(list(hp)) or True
            t.verify(FakeBundle(), {'role_ldaps': True, 'verify': ['www.example.test:443']})
            t.verify(FakeBundle(), {'role_ldaps': True, 'ldaps_verify': False})
            t.verify(FakeBundle(), {})
        finally:
            CC.check_served = orig
        self.assertEqual(seen, [['www.example.test:443', 'win.example.test:636']])

    def test_without_roles_unchanged(self):
        w = World()
        t, ctx = target(w)
        b = FakeBundle()
        t.deploy(b, {'iis': 'Default Web Site | www.example.test | 443', 'rdp': True})
        self.assertEqual(len(w.runs('Import-PfxCertificate')), 1)
        imp = w.runs('Import-PfxCertificate')[0]
        self.assertIn('REMOVED', imp)                                 # keep as before
        self.assertFalse(w.runs(r'function Say'))
        self.assertEqual(len([p for p, _d, _m in w.ssh.puts if p.endswith('.pfx')]), 1)


class TestAndPreviewTest(unittest.TestCase):
    def test_test_lists_roles(self):
        w = World(detect={'sql': (True, 'MSSQLSERVER, SQLEXPRESS'), 'adfs': (True, ''),
                          'rds': (False, '')})
        t, ctx = target(w)
        words = t.test()
        self.assertIn('signed in as Administrator', words)
        self.assertIn('roles on this server: AD FS, SQL Server (MSSQLSERVER, SQLEXPRESS)', words)
        self.assertNotIn('Remote Desktop', words)
        det = w.runs('function R\\(')[0]
        self.assertNotRegex(det, r'Set-|New-Item|Remove-|Restart-')     # changes nothing

    def test_preview_has_the_script(self):
        t, ctx = target(World())
        got = t.preview(FakeBundle(), {'role_sql': True, 'role_rds': True,
                                       'key_read': ['X\\y']})
        self.assertEqual([r['key'] for r in got['roles']['on']], ['rds', 'sql'])
        sc = got['roles']['script']
        self.assertIn('# --- SQL Server ---', sc)
        self.assertIn("ConvertTo-SecureString -String '********'", sc)
        self.assertLess(sc.index('read on the key'), sc.index('Remote Desktop Services'))
        self.assertTrue(any('after the import' in p['words'] for p in got['problems']))
        got = t.preview(FakeBundle(), {'role_ccs': True})
        self.assertTrue(any(p['level'] == 'bad' and 'give the folder' in p['words']
                            for p in got['problems']))
        self.assertNotIn('roles', t.preview(FakeBundle(), {}))

    def test_dry_run_checks_installed(self):
        w = World(detect={'sql': (True, 'MSSQLSERVER'), 'adfs': (False, '')})
        t, ctx = target(w)
        with self.assertRaises(PluginError) as e:
            t.dry_run(FakeBundle(), {'role_sql': True, 'role_adfs': True})
        self.assertIn('not installed: AD FS', str(e.exception))
        steps = [x[1] for x in ctx.steps]
        self.assertTrue(any(x.startswith('the PowerShell of SQL Server (not run') for x in steps))
        self.assertFalse(w.runs('Import-PfxCertificate'))
        self.assertFalse(w.runs('SuperSocketNetLib'))                 # shown, not run
        w = World(detect={'sql': (True, 'MSSQLSERVER')})
        t, ctx = target(w)
        self.assertIn('the test passed', t.dry_run(FakeBundle(), {'role_sql': True}))


class RequiredOnlyWhenOn(unittest.TestCase):
    """A required field of a role switched off is not asked for when the deployment is
    saved (1.0.21: "Folder of the store is needed" with IIS CCS off)."""

    def test_roles_off_ask_nothing(self):
        from acmelib.certs import api as A
        from acmelib.plugins.targets import windows_ssh as W
        req = [f for f in W.WindowsSshTarget.deploy_fields if f.get('required') and
               f.get('show_if')]
        self.assertTrue(any(f['key'] == 'ccs_path' for f in req))
        for f in req:
            self.assertFalse(A.field_shown(f, {}), f['key'])
            self.assertFalse(A.field_shown(f, {'role_ccs': False}), f['key'])
        ccs = [f for f in req if f['key'] == 'ccs_path'][0]
        self.assertTrue(A.field_shown(ccs, {'role_ccs': True}))


if __name__ == '__main__':
    unittest.main()
