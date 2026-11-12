#!/usr/bin/env python3
"""The Microsoft products of acmelib/plugins/targets/windows_products.py (1.0.96) -
WSUS, Hyper-V Replica, Reporting Services / Power BI Report Server, Operations
Manager - over the fake SSH of test_targets.py: the PowerShell each one runs (the
commands the vendor documents), the order (import -> product -> old ones), the
refusals before anything is changed, a failure keeping the old certificate, Try,
the test of a deployment, the preview, where it serves, the guides.

    python3 test/test_targets_microsoft.py
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeSsh, FakeCtx  # noqa: E402
from test_targets_windows_roles import script_of, balanced  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import windows_products as WP  # noqa: E402

CONF = {'host': 'srv.example.test', 'user': 'Administrator', 'auth': 'password',
        'password': 'pw'}
KINDS = ['windows_wsus', 'windows_hyperv_replica', 'windows_ssrs', 'windows_scom']
MARK = {'windows_wsus': 'New-IISSiteBinding', 'windows_hyperv_replica': 'Set-VMReplication',
        'windows_ssrs': 'CreateSSLCertificateBinding', 'windows_scom': 'MOMCertImport'}


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class Server(object):
    """A Windows server: each PowerShell run answered by what it is."""
    def __init__(self, found=True, admin=True, fail=None, present=False):
        self.found, self.admin, self.fail, self.present = found, admin, fail, present
        self.ssh = FakeSsh([(r'powershell', self.answer)])
        self.scripts = []

    def answer(self, cmd, inp):
        ps = script_of(cmd, self.ssh)
        self.scripts.append(ps)
        if '$adm = ' in ps:
            return 0, 'Administrator|Microsoft Windows Server 2022 Standard|5.1|%s\n' % (
                'True' if self.admin else 'False'), ''
        if "Write-Output ('FOUND yes" in ps or "Write-Output 'FOUND yes" in ps:
            return 0, ('FOUND yes here\n' if self.found else 'FOUND no it is not installed\n'), ''
        if "{ 'YES' }" in ps:
            return 0, 'YES\n' if self.present else 'NO\n', ''
        if 'Import-PfxCertificate' in ps or "'-importPFX'" in ps:
            return 0, 'IMPORTED X\n', ''
        if self.fail and self.fail[0] in ps:
            return 1, 'STEP info half-way\nERROR: %s\n' % self.fail[1], ''
        return 0, 'STEP ok it worked\n', ''

    def runs(self, rx):
        return [i for i, s in enumerate(self.scripts) if re.search(rx, s)]


def make(kind, server):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    ctx = FakeCtx(ssh=server.ssh)
    return reg.get('target', kind)(dict(CONF), ctx), ctx


def product_script(kind, opts, bundle=None):
    t, _ctx = make(kind, Server())
    return t._script(bundle or FakeBundle(), dict(opts))


class RegisteredTest(unittest.TestCase):
    def test_kinds(self):
        reg = Registry(extra_dirs=[]).reload()
        d = {x['kind']: x for x in reg.describe()['target']}
        for k in KINDS:
            self.assertEqual(list(reg.versions_of('target', k)), [''], k)
            cls = reg.get('target', k)
            self.assertEqual(cls.vendor, 'Microsoft')
            self.assertEqual(cls.module_version, '')
            self.assertTrue(re.search(r'\d{4}', cls.description), 'its versions said: ' + k)
            self.assertIn(k, d)
            keys = [f['key'] for f in cls.deploy_fields]
            self.assertIn('keep', keys)
            self.assertNotIn('iis', keys, 'windows_ssh\'s own fields are not repeated')
        self.assertNotIn('', [c.kind for c in reg.versions_of('target', 'windows_ssh').values()])
        # windows_ssh is still the one module of its kind, untouched
        self.assertEqual(list(reg.versions_of('target', 'windows_ssh')), [''])
        self.assertEqual(reg.get('target', 'windows_ssh').__module__,
                         'acmelib.plugins.targets.windows_ssh')

    def test_every_script_is_balanced(self):
        b = FakeBundle()
        sets = {
            'windows_wsus': [{}, {'wsus_require_ssl': True, 'wsus_configuressl': 'changed'},
                             {'wsus_configuressl': 'never'}],
            'windows_hyperv_replica': [{}, {'hvr_vms': ['VM1', "it's"], 'hvr_test': False},
                                       {'hvr_server': False}],
            'windows_ssrs': [{}, {'ssrs_instance': 'PBIRS'}],
            'windows_scom': [{}, {'scom_tool': 'C:\\T\\MOMCertImport.exe', 'scom_restart': False}],
        }
        for k, optss in sets.items():
            t, _c = make(k, Server())
            for o in optss:
                ps = t._script(b, o)
                self.assertEqual(balanced(ps), '', '%s %s: %s' % (k, o, balanced(ps)))
                self.assertIn("$thumb = '%s'" % C.sha1_thumb(b), ps)
            body = WP.WR.cleanup_script('acme-x-', 1)
            body[1:1] = t.used()
            ps = '\n'.join(WP.WR.head('AB', 'p', '\n'.join(body)) + body)
            self.assertEqual(balanced(ps), '', '%s cleanup: %s' % (k, balanced(ps)))
            self.assertEqual(balanced('\n'.join(t.detect())), '', k)
        self.assertEqual(balanced(WP.PROBE), '')


class WsusTest(unittest.TestCase):
    def test_script(self):
        ps = product_script('windows_wsus', {})
        self.assertIn("Need-Service 'WsusService' 'WSUS'", ps)
        self.assertIn("$site = 'WSUS Administration'", ps)
        self.assertIn('$port = 8531', ps)
        self.assertIn('Remove-IISSiteBinding -Name $site -BindingInformation $bi -Protocol https', ps)
        self.assertIn('New-IISSiteBinding -Name $site -BindingInformation $bi -Protocol https '
                      "-CertificateThumbPrint $thumb -CertStoreLocation 'Cert:\\LocalMachine\\My'",
                      ps)
        self.assertIn("Update Services\\Tools\\WsusUtil.exe", ps)
        # the certificate's first name when none is given
        self.assertIn("$r = Run-Native $wu @('configuressl', 'www.example.test')", ps)
        self.assertNotIn('sslFlags', ps)
        self.assertIn('function Run-Native', ps)

    def test_require_ssl_and_modes(self):
        ps = product_script('windows_wsus', {'wsus_require_ssl': True, 'wsus_port': 443,
                                             'wsus_fqdn': 'wsus01.corp.example.test',
                                             'wsus_configuressl': 'changed'})
        for v in ('SimpleAuthWebService', 'DSSAuthWebService', 'ServerSyncWebService',
                  'APIremoting30', 'ClientWebService'):
            self.assertIn("'%s'" % v, ps)
        for v in ('Content', 'Inventory', 'ReportingWebService', 'SelfUpdate'):
            self.assertNotIn("'%s'" % v, ps)
        self.assertIn("-Name sslFlags -Value 'Ssl'", ps)
        self.assertIn('$port = 443', ps)
        self.assertIn("@('configuressl', 'wsus01.corp.example.test')", ps)
        self.assertIn('if ($changed) {', ps)
        self.assertNotIn('WsusUtil', product_script('windows_wsus', {'wsus_configuressl': 'never'}))

    def test_deploy_order_and_cleanup(self):
        sv = Server()
        t, ctx = make('windows_wsus', sv)
        b = FakeBundle()
        words = t.deploy(b, {'keep': 1})
        self.assertIn('WSUS uses it', words)
        imp = sv.runs(r'Import-PfxCertificate')[0]
        prod = sv.runs(r'New-IISSiteBinding')[0]
        old = sv.runs(r'Select-Object -Skip 1')[0]
        self.assertTrue(imp < prod < old, (imp, prod, old))
        self.assertNotIn('REMOVED', sv.scripts[imp], 'the import itself removes nothing')
        self.assertIn('netsh.exe', sv.scripts[old], 'http.sys bindings count as used')
        pfx = [p for p, _d, _m in sv.ssh.puts if p.endswith('.pfx')]
        self.assertEqual(len(pfx), 1)
        self.assertTrue(sv.runs(re.escape("Remove-Item -LiteralPath '%s'" % pfx[0])))
        steps = [w for _l, w in ctx.steps]
        self.assertIn('WSUS: done', steps)
        self.assertIn('it worked', steps)
        self.assertTrue(ctx.kv, 'remembered')
        # the same again, still in the store: nothing done
        sv.present = True
        n = len(sv.scripts)
        self.assertIn('unchanged', t.deploy(b, {'keep': 1}))
        self.assertEqual(len(sv.scripts), n + 1)

    def test_served_places(self):
        t, _c = make('windows_wsus', Server())
        self.assertEqual(t.served_places({}), [('srv.example.test', 8531)])
        self.assertEqual(t.served_places({'wsus_fqdn': 'wsus.example.test', 'wsus_port': '443'}),
                         [('wsus.example.test', 443)])

    def test_bad_port_refused_before_anything(self):
        sv = Server()
        t, _c = make('windows_wsus', sv)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'wsus_port': 70000})
        self.assertFalse(e.exception.retry)
        self.assertEqual(sv.scripts, [])
        self.assertEqual(sv.ssh.puts, [])


class HyperVTest(unittest.TestCase):
    def test_script(self):
        ps = product_script('windows_hyperv_replica', {'hvr_vms': ['VM01']})
        self.assertIn("Need-Module 'Hyper-V' 'Hyper-V Replica'", ps)
        self.assertIn("'1.3.6.1.5.5.7.3.1'", ps)
        self.assertIn("'1.3.6.1.5.5.7.3.2'", ps)
        self.assertIn('Set-VMReplicationServer -CertificateThumbprint $thumb -Force', ps)
        self.assertIn('Test-VMReplicationConnection -ReplicaServerName $r.ReplicaServer '
                      '-ReplicaServerPort $r.ReplicaPort -AuthenticationType Certificate '
                      '-CertificateThumbprint $thumb', ps)
        self.assertIn('Set-VMReplication -VMName $r.VMName -CertificateThumbprint $thumb', ps)
        self.assertIn("$only = @('VM01')", ps)
        # every replica server tested before any VM is changed; the EKU checked before all
        self.assertLess(ps.index('Test-VMReplicationConnection'),
                        ps.index('Set-VMReplication -VMName'))
        self.assertLess(ps.index('1.3.6.1.5.5.7.3.2'), ps.index('Set-VMReplicationServer'))

    def test_parts(self):
        ps = product_script('windows_hyperv_replica', {'hvr_server': False, 'hvr_test': False})
        self.assertNotIn('Set-VMReplicationServer', ps)
        self.assertNotIn('Test-VMReplicationConnection', ps)
        ps = product_script('windows_hyperv_replica', {'hvr_primary': False})
        self.assertNotIn('Set-VMReplication -VMName', ps)
        sv = Server()
        t, _c = make('windows_hyperv_replica', sv)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'hvr_server': False, 'hvr_primary': False})
        self.assertIn('choose the Replica server', str(e.exception))
        self.assertEqual(sv.scripts, [])

    def test_used_thumbprints_kept(self):
        t, _c = make('windows_hyperv_replica', Server())
        used = '\n'.join(t.used())
        self.assertIn('(Get-VMReplicationServer -ErrorAction Stop).CertificateThumbprint', used)
        self.assertIn('Get-VMReplication -ErrorAction Stop', used)
        self.assertEqual(t.served_places({}), [], 'mutual TLS: no plain TLS test')

    def test_failure_keeps_the_old(self):
        sv = Server(fail=('Set-VMReplication', 'Hyper-V Replica: hv2:443 does not take the new '
                                               'certificate, nothing changed: refused'))
        t, ctx = make('windows_hyperv_replica', sv)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {})
        self.assertIn('does not take the new certificate', str(e.exception))
        self.assertIn('nothing was removed', str(e.exception))
        self.assertFalse(sv.runs(r'Select-Object -Skip'), 'no old certificate removed')
        self.assertEqual(ctx.kv, {}, 'not remembered')
        self.assertIn('half-way', [w for _l, w in ctx.steps])


class SsrsTest(unittest.TestCase):
    def test_script(self):
        ps = product_script('windows_ssrs', {'ssrs_instance': 'PBIRS'})
        self.assertIn("$root = 'root\\Microsoft\\SqlServer\\ReportServer'", ps)
        self.assertIn("$want = 'PBIRS'", ps)
        self.assertIn("$ns = $root + '\\' + $inst + '\\' + $vers[0] + '\\Admin'", ps)
        self.assertIn('MSReportServer_ConfigurationSetting', ps)
        self.assertIn('$rs.ListSSLCertificateBindings(1033)', ps)
        self.assertIn('$rs.RemoveSSLCertificateBindings($a, $h, $ip, $p, 1033)', ps)
        self.assertIn('$rs.CreateSSLCertificateBinding($a, $new, $ip, $p, 1033)', ps)
        self.assertIn('$new = $thumb.ToLowerInvariant()', ps, 'the hash in small letters')
        # the old one put back when the new one is refused
        self.assertIn('$rs.CreateSSLCertificateBinding($a, $h, $ip, $p, 1033)', ps)
        self.assertIn('there is no HTTPS binding yet', ps)
        self.assertLess(ps.index('RemoveSSLCertificateBindings'),
                        ps.index('CreateSSLCertificateBinding($a, $new'))

    def test_options(self):
        t, _c = make('windows_ssrs', Server())
        self.assertEqual(t.served_places({}), [('srv.example.test', 443)])
        self.assertEqual(t.served_places({'ssrs_port': 0}), [])
        self.assertEqual(t.served_places({'ssrs_port': '4443'}), [('srv.example.test', 4443)])
        self.assertTrue(t.check_options({'ssrs_instance': 'a b'}))
        self.assertEqual(t.check_options({'ssrs_instance': 'SSRS'}), [])

    def test_deploy(self):
        sv = Server()
        t, ctx = make('windows_ssrs', sv)
        self.assertIn('Reporting Services uses it', t.deploy(FakeBundle(), {}))
        self.assertTrue(sv.runs('CreateSSLCertificateBinding'))
        self.assertIn('Reporting Services: done', [w for _l, w in ctx.steps])


class ScomTest(unittest.TestCase):
    def test_import_as_key_exchange(self):
        sv = Server()
        t, ctx = make('windows_scom', sv)
        b = FakeBundle()
        t.deploy(b, {'scom_tool': 'C:\\Tools\\MOMCertImport.exe'})
        self.assertFalse(sv.runs('Import-PfxCertificate'), 'not Import-PfxCertificate')
        imp = sv.runs(r"'-importPFX', 'My', \$pfx, 'AT_KEYEXCHANGE'")[0]
        pfx = [p for p, _d, _m in sv.ssh.puts if p.endswith('.pfx')][0]
        self.assertIn("$pfx = '%s'" % pfx, sv.scripts[imp])
        self.assertIn('} finally { Remove-Item -LiteralPath $pfx', sv.scripts[imp])
        self.assertIn("$cert.FriendlyName = '%s'" % C.object_name(b, {}), sv.scripts[imp])
        prod = sv.runs('MOMCertImport')[0]
        ps = sv.scripts[prod]
        self.assertIn("$tool = 'C:\\Tools\\MOMCertImport.exe'", ps)
        self.assertIn("Run-Native $tool @('/SubjectName', $subj)", ps)
        self.assertIn("KeyNumber", ps)
        self.assertIn("Restart-Role 'HealthService'", ps)
        self.assertIn('ChannelCertificateSerialNumber', ps)
        old = sv.runs(r'Select-Object -Skip 1')[0]
        self.assertTrue(imp < prod < old)
        self.assertIn('ScomSerial', sv.scripts[old], 'the one SCOM uses is never removed')
        # the one-time password is in no step
        pw = re.search(r"'-p', '([^']+)'", sv.scripts[imp]).group(1)
        self.assertGreaterEqual(len(pw), 16)
        self.assertFalse([w for _l, w in ctx.steps if pw in w])

    def test_no_restart_and_default_tool(self):
        ps = product_script('windows_scom', {'scom_restart': False})
        self.assertNotIn("Restart-Role 'HealthService'", ps)
        self.assertIn("System Center Operations Manager\\Gateway\\MOMCertImport.exe", ps)

    def test_ec_key_refused(self):
        sv = Server()
        t, _c = make('windows_scom', sv)
        b = FakeBundle()
        b.family = 'ec'
        with self.assertRaises(PluginError) as e:
            t.deploy(b, {})
        self.assertIn('needs an RSA key', str(e.exception))
        self.assertEqual(sv.scripts, [])
        b.family = 'rsa'
        t.deploy(b, {})


class TryTestPreviewTest(unittest.TestCase):
    def test_try(self):
        for k in KINDS:
            t, _c = make(k, Server())
            got = t.test()
            self.assertIn('signed in as Administrator on Microsoft Windows Server 2022', got)
            self.assertIn('(here)', got)
            with self.assertRaises(PluginError) as e:
                make(k, Server(found=False))[0].test()
            self.assertIn('is not on this server: it is not installed', str(e.exception))
            with self.assertRaises(PluginError) as e:
                make(k, Server(admin=False))[0].test()
            self.assertIn('not as an administrator', str(e.exception))

    def test_dry_run_changes_nothing(self):
        for k in KINDS:
            sv = Server()
            t, ctx = make(k, sv)
            self.assertIn('the test passed', t.dry_run(FakeBundle(), {}))
            self.assertFalse(sv.runs(MARK[k]), 'the product\'s script is not run: ' + k)
            self.assertFalse(sv.runs('Import-PfxCertificate|importPFX'))
            self.assertTrue([w for _l, w in ctx.steps if 'not run on a test' in w and MARK[k] in w])
            with self.assertRaises(PluginError):
                make(k, Server(found=False))[0].dry_run(FakeBundle(), {})

    def test_preview(self):
        for k in KINDS:
            t, _c = make(k, Server())
            got = t.preview(FakeBundle(), {})
            self.assertEqual(got['files'], [])
            self.assertIn(MARK[k], got['roles']['script'])
            self.assertEqual(got['roles']['on'][0]['key'], k)
        t, _c = make('windows_wsus', Server())
        bad = t.preview(FakeBundle(), {'wsus_port': -1})['problems']
        self.assertTrue([p for p in bad if p['level'] == 'bad'])


class GuidesTest(unittest.TestCase):
    def test_both_languages(self):
        d = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
        must = {'windows_wsus': 'configuressl', 'windows_hyperv_replica': 'Set-VMReplicationServer',
                'windows_ssrs': 'MSReportServer_ConfigurationSetting',
                'windows_scom': 'MOMCertImport'}
        for k in KINDS:
            for suffix in ('.md', '.cs.md'):
                with open(os.path.join(d, k + suffix), encoding='utf-8') as f:
                    md = f.read()
                self.assertTrue(md.startswith('# '), k + suffix)
                self.assertIn(must[k], md, k + suffix)
                self.assertIn('administrators_authorized_keys', md, k + suffix)
                self.assertIn('```', md)
                if suffix == '.cs.md':
                    self.assertTrue(re.search('[ěščřžýáíéůú]', md), k)


if __name__ == '__main__':
    unittest.main(verbosity=1)
