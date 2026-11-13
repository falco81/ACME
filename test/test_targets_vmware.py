#!/usr/bin/env python3
"""The VMware targets (1.0.94), without a network - against fakes that answer as the vendor
APIs document (navody/certifikaty/vmware/*.md, 2026-11).

    python3 test/test_targets_vmware.py

  esxi             ''        SSH (esxi.py) - its fix: /sbin/auto-backup.sh after the files
                   '8.0.3'   ESXi 8.0 U3 - 9.1 through vCenter's HostCertificateManager
  vcenter          '8.0.2'   vCenter 8.0 U2 - 9.1, no restart (the plain one is vcenter.py)
  nsx_manager      ''        NSX 4.2 - 9.1 MP API: import, validate, apply_certificate
  horizon_cs       ''        Horizon 8 Connection Server: PowerShell over SSH
  sddc_manager     ''        SDDC Manager trust store
  aria_lifecycle   ''        Aria Suite Lifecycle 8.18: Locker + Replace Certificate
  aria_automation  ''        Aria Automation 8.18: vracli over SSH
  vcd              ''        Cloud Director 10.5.1 - 10.6: Certificates Library + accessEndpoints
  vmware_dr        ''        Live Site Recovery / vSphere Replication: Configuration API
  vsphere_supervisor ''/9.0/9.1  the Supervisor's API endpoint certificate

The fake Context, SSH session and certificates are those of test_targets.py.
"""
import base64
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import _vmware as V  # noqa: E402
from acmelib.plugins.targets import vsphere_supervisor as SUP  # noqa: E402

GUIDES = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
NEW = {'esxi': ['8.0.3'], 'vcenter': ['8.0.2'], 'nsx_manager': [''], 'horizon_cs': [''],
       'sddc_manager': [''], 'aria_lifecycle': [''], 'aria_automation': [''], 'vcd': [''],
       'vmware_dr': [''], 'vsphere_supervisor': ['', '9.0', '9.1']}


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(kind, version, ctx, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, version)
    assert cls.module_version == version, (kind, cls.module_version, version)
    t = cls(cfg, ctx)
    t._sleep = lambda s: None
    return t


def bundle(family=None):
    b = FakeBundle()
    if family:
        b.family = family
    return b


def methods(ctx):
    return [(c['method'], c['path']) for c in ctx.calls]


def changed(ctx):
    return [(c['method'], c['path']) for c in ctx.calls if c['method'] != 'GET']


# ---------------------------------------------------------------------------
class RegistryTest(unittest.TestCase):
    def test_versions_and_descriptions(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(reg.broken, [])
        for kind, vers in NEW.items():
            have = reg.versions_of('target', kind)
            for v in vers:
                self.assertIn(v, have, (kind, v))
                c = have[v]
                self.assertTrue(c.description and c.title and c.vendor, kind)
                if v:
                    self.assertTrue(c.version_label, (kind, v))
                    self.assertIn(c.version_label.split(' (')[0], c.description, (kind, v))
        # the plain ones of existing kinds stay the existing modules, still the default
        self.assertEqual(reg.get('target', 'esxi').__module__, 'acmelib.plugins.targets.esxi')
        self.assertEqual(reg.get('target', 'vcenter').__module__,
                         'acmelib.plugins.targets.vcenter')
        for k in ('nsx', 'avi', 'omnissa_uag'):
            self.assertEqual(sorted(reg.versions_of('target', k)), [''], k)
        self.assertEqual(sorted(reg.versions_of('target', 'vsphere_supervisor')),
                         ['', '9.0', '9.1'])

    def test_helpers(self):
        self.assertEqual(V.parse_version('9.1.1.0'), (9, 1, 1))
        self.assertEqual(V.parse_version('8.0'), (8, 0, 0))
        self.assertIsNone(V.parse_version('n/a'))
        b = FakeBundle()
        self.assertTrue(V.has_cert(json.dumps({'cert': b.cert_pem}), b))
        self.assertFalse(V.has_cert('{"cert": ""}', b))
        self.assertEqual(V.root_of(b).strip(), b.chain_pems[0].strip(), 'the self-signed CA')
        self.assertEqual(V.intermediates(b), [])
        self.assertEqual(SUP.version_for((9, 0, 2))[0], '9.0')
        self.assertEqual(SUP.version_for((9, 1, 1))[0], '9.1')
        self.assertEqual(SUP.version_for((8, 0, 3)), ('', ''))


class GuidesTest(unittest.TestCase):
    def test_a_guide_for_each_new_module_and_version_in_both_languages(self):
        for kind, vers in NEW.items():
            for v in vers:
                for suffix in ('.md', '.cs.md'):
                    p = os.path.join(GUIDES, '%s%s%s' % (kind, '@' + v if v else '', suffix))
                    with open(p, encoding='utf-8') as f:
                        md = f.read()
                    self.assertTrue(md.startswith('# '), p)
                    self.assertIn('```', md, p)
                    self.assertIn('|', md, p)
                    if suffix == '.cs.md':
                        self.assertRegex(md, '[ěščřžýáíéůú]', p)
        # never the existing plain guides of existing kinds touched: they are still there
        for k in ('esxi', 'vcenter', 'nsx', 'avi', 'omnissa_uag'):
            self.assertTrue(os.path.exists(os.path.join(GUIDES, k + '.md')), k)


# ---------------------------------------------------------------------------
class EsxiSshFixTest(unittest.TestCase):
    """esxi.py (the plain one): the files saved to the boot bank after the restart."""
    def test_auto_backup_after_the_restart(self):
        ssh = FakeSsh()
        ctx = FakeCtx(ssh=ssh)
        make('esxi', '', ctx, host='esx1', user='root', auth='password', password='p').deploy(
            FakeBundle(), {})
        cmds = [c for c, _ in ssh.runs]
        i = [n for n, c in enumerate(cmds) if '/etc/init.d/hostd restart' in c][0]
        j = [n for n, c in enumerate(cmds) if '/sbin/auto-backup.sh' in c][0]
        self.assertLess(i, j, 'saved after the restart went through')
        self.assertTrue([w for lv, w in ctx.steps if 'boot bank' in w])

    def test_auto_backup_failing_warns(self):
        ssh = FakeSsh([(r'auto-backup', (1, '', 'no space'))])
        ctx = FakeCtx(ssh=ssh)
        make('esxi', '', ctx, host='esx1').deploy(FakeBundle(), {'restart': 'none'})
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'auto-backup' in w])


# ---------------------------------------------------------------------------
def esxi_routes(esx='8.0.3', vc='8.0.3', install=(204, ''), extra=()):
    rel = r'/sdk/vim25/8\.0\.3\.0/'
    return list(extra) + [
        ('GET', rel + r'ServiceInstance/ServiceInstance/content$',
         (200, {'sessionManager': {'type': 'SessionManager', 'value': 'SessionManager'},
                'about': {'version': vc, 'build': '1', 'apiVersion': '8.0.3.0'}})),
        ('POST', rel + r'SessionManager/SessionManager/Login$',
         (200, {'key': 'k'}, {'vmware-api-session-id': 'SID1'})),
        ('POST', rel + r'SessionManager/SessionManager/Logout$', (204, '')),
        ('GET', rel + r'HostSystem/host-12/summary$',
         (200, {'config': {'name': 'esx01.example.test',
                           'product': {'version': esx, 'fullName': 'VMware ESXi %s' % esx}}})),
        ('GET', rel + r'HostSystem/host-12/configManager$',
         (200, {'certificateManager': {'type': 'HostCertificateManager',
                                       'value': 'certificateManager-12'}})),
        ('POST', r'/api/session$', (201, '"RESTTOKEN"')),
        ('DELETE', r'/api/session$', (204, '')),
        ('POST', r'/trusted-root-chains$', (201, '"chain-1"')),
        ('POST', rel + r'HostCertificateManager/certificateManager-12/ProvisionServerPrivateKey$',
         (204, '')),
        ('POST', rel + r'HostCertificateManager/certificateManager-12/InstallServerCertificate$',
         install),
        ('POST', rel + r'HostCertificateManager/certificateManager-12/NotifyAffectedServices$',
         (204, '')),
    ]


ESXCFG = dict(host='vc1', user='svc@vsphere.local', password='pw', host_id='host-12')


class EsxiApiTest(unittest.TestCase):
    def test_the_calls_in_order(self):
        b = bundle('rsa')
        ctx = FakeCtx(esxi_routes())
        words = make('esxi', '8.0.3', ctx, **ESXCFG).deploy(b, {})
        self.assertIn('esx01.example.test', words)
        seq = [p.rsplit('/', 1)[-1] for m, p in methods(ctx)]
        self.assertEqual(seq, ['content', 'Login', 'summary', 'configManager', 'session',
                               'trusted-root-chains', 'session', 'ProvisionServerPrivateKey',
                               'InstallServerCertificate', 'NotifyAffectedServices', 'Logout'])
        login = ctx.find('POST', 'Login')[0]
        self.assertEqual(ctx.json(login), {'userName': 'svc@vsphere.local', 'password': 'pw'})
        prov = ctx.find('POST', 'ProvisionServerPrivateKey')[0]
        self.assertEqual(prov['headers']['vmware-api-session-id'], 'SID1')
        self.assertEqual(ctx.json(prov), {'key': b.key_pem})
        self.assertEqual(ctx.json(ctx.find('POST', 'InstallServerCertificate')[0]),
                         {'cert': b.cert_pem})
        self.assertEqual(ctx.json(ctx.find('POST', 'NotifyAffectedServices')[0]), {})
        roots = ctx.find('POST', 'trusted-root-chains')[0]
        self.assertEqual(roots['headers']['vmware-api-session-id'], 'RESTTOKEN')
        self.assertTrue(ctx.find('POST', r'/api/session$')[0]['headers']['Authorization']
                        .startswith('Basic '))
        self.assertEqual(ctx.json(roots)['cert_chain']['cert_chain'], [b.chain_pems[0]])
        # again: nothing
        again = make('esxi', '8.0.3', ctx, **ESXCFG).deploy(b, {})
        self.assertTrue(again.startswith('unchanged'))

    def test_older_esx_refused_before_any_change(self):
        ctx = FakeCtx(esxi_routes(esx='8.0.2'))
        with self.assertRaises(PluginError) as e:
            make('esxi', '8.0.3', ctx, **ESXCFG).deploy(bundle('rsa'), {})
        self.assertFalse(e.exception.retry)
        self.assertIn('VMware ESXi 8.0.2', str(e.exception))
        self.assertIn('VMware ESXi host (SSH)', str(e.exception))
        self.assertFalse([p for m, p in changed(ctx) if 'Login' not in p and 'Logout' not in p])

    def test_ec_key_refused_nothing_sent(self):
        ctx = FakeCtx(esxi_routes())
        with self.assertRaises(PluginError) as e:
            make('esxi', '8.0.3', ctx, **ESXCFG).deploy(bundle('ec'), {})
        self.assertIn('RSA', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_install_refused(self):
        ctx = FakeCtx(esxi_routes(install=(500, {'faultstring': 'HostConfigFault'})))
        with self.assertRaises(PluginError) as e:
            make('esxi', '8.0.3', ctx, **ESXCFG).deploy(bundle('rsa'), {'trust_chain': False})
        self.assertIn('HostConfigFault', str(e.exception))
        self.assertFalse(ctx.find('POST', 'NotifyAffectedServices'))
        self.assertTrue(ctx.find('POST', 'Logout'), 'signed out all the same')

    def test_try_and_served_place(self):
        t = make('esxi', '8.0.3', FakeCtx(esxi_routes(esx='9.1.0')), **ESXCFG)
        self.assertIn('VMware ESXi 9.1.0', t.test())
        t = make('esxi', '8.0.3', FakeCtx(), **dict(ESXCFG, esx_name='esx9'))
        self.assertEqual(t.served_places({}), [('esx9', 443)])


# ---------------------------------------------------------------------------
def vc_routes(ver='8.0.3', put=(204, '')):
    return [
        ('GET', r'/sdk/vim25/8\.0\.1\.0/ServiceInstance/ServiceInstance/content$',
         (200, {'about': {'version': ver}}) if ver else (404, {})),
        ('POST', r'/api/session$', (201, '"S"')),
        ('DELETE', r'/api/session$', (204, '')),
        ('GET', r'/certificate-management/vcenter/tls$', (200, {'thumbprint': 'AA:BB',
                                                                 'subject_dn': 'CN=vc'})),
        ('POST', r'/trusted-root-chains$', (201, '"c"')),
        ('PUT', r'/certificate-management/vcenter/tls$', put),
    ]


class VCenter802Test(unittest.TestCase):
    def test_replaced_without_restart(self):
        b = bundle('rsa')
        ctx = FakeCtx(vc_routes('9.0.0'))
        t = make('vcenter', '8.0.2', ctx, host='vc1', user='u', password='p')
        words = t.deploy(b, {})
        self.assertIn('no restart', words)
        put = ctx.json(ctx.find('PUT', 'vcenter/tls')[0])
        self.assertEqual(put, {'cert': b.cert_pem, 'key': b.key_pem, 'root_cert': b.chain_pems[0]})
        self.assertLess(t.served_wait[0] * t.served_wait[1], 20 * 15)
        self.assertFalse([w for lv, w in ctx.steps if 'restarts its services' in w])

    def test_older_refused_before_any_change(self):
        ctx = FakeCtx(vc_routes('8.0.1'))
        with self.assertRaises(PluginError) as e:
            make('vcenter', '8.0.2', ctx, host='vc1', user='u', password='p').deploy(
                bundle('rsa'), {})
        self.assertIn('runs 8.0.1', str(e.exception))
        self.assertIn('VMware vCenter Server', str(e.exception))
        self.assertEqual(changed(ctx), [])

    def test_ec_refused(self):
        ctx = FakeCtx(vc_routes())
        with self.assertRaises(PluginError):
            make('vcenter', '8.0.2', ctx, host='vc1', user='u', password='p').deploy(
                bundle('ec'), {})
        self.assertEqual(ctx.calls, [])

    def test_unknown_version_warned_and_already_there(self):
        ctx = FakeCtx(vc_routes(None, put=(400, {'error_type': 'ALREADY_EXISTS',
                                                 'messages': ['AlreadyExists']})))
        words = make('vcenter', '8.0.2', ctx, host='vc1', user='u', password='p').deploy(
            bundle('rsa'), {})
        self.assertTrue(words.startswith('unchanged'))
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'cannot be read' in w])

    def test_try_says_the_version(self):
        self.assertIn('vCenter 9.1.0', make('vcenter', '8.0.2', FakeCtx(vc_routes('9.1.0')),
                                            host='vc1', user='u', password='p').test())


# ---------------------------------------------------------------------------
def nsx_routes(listed=None, valid='OK', import_id='cert-new', extra=()):
    return list(extra) + [
        ('GET', r'/trust-management/certificates/[^/?]+\?action=validate',
         (200, {'status': valid, 'error_message': 'chain does not verify'})),
        ('GET', r'/api/v1/trust-management/certificates$', (200, {'results': listed or []})),
        ('POST', r'/certificates\?action=import$', (201, {'results': [{'id': import_id}],
                                                          'result_count': 1})),
        ('POST', r'action=apply_certificate', (200, {})),
        ('DELETE', r'/trust-management/certificates/', (200, {})),
    ]


class NsxManagerTest(unittest.TestCase):
    def test_import_validate_apply_cleanup(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        prefix = C.name_prefix(b, {})
        listed = [{'id': 'old1', 'display_name': prefix + '20250101-aaaaaaaa', 'used_by': []},
                  {'id': 'old2', 'display_name': prefix + '20240101-bbbbbbbb',
                   'used_by': [{'service_types': ['API']}]},
                  {'id': 'other', 'display_name': 'MGMT_CLUSTER site', 'used_by': []}]
        ctx = FakeCtx(nsx_routes(listed))
        words = make('nsx_manager', '', ctx, host='nsx1', user='admin', password='p').deploy(
            b, {'node_ids': 'n-1\nn-2', 'vip': True, 'keep': 0})
        self.assertIn('virtual IP', words)
        imp = ctx.json(ctx.find('POST', 'action=import')[0])
        self.assertEqual(imp['display_name'], name)
        self.assertEqual(imp['private_key'], b.key_pem)
        self.assertEqual(V.pem_body(imp['pem_encoded']), V.pem_body(b.cert_pem))
        self.assertNotIn('\n\n', imp['pem_encoded'])
        self.assertIn(V.pem_body(b.chain_pems[0]), re.sub(r'\s', '', imp['pem_encoded']))
        applies = [(c['query'].get('service_type'), c['query'].get('node_id'))
                   for c in ctx.find('POST', 'apply_certificate')]
        self.assertEqual(applies, [(['API'], ['n-1']), (['API'], ['n-2']),
                                   (['MGMT_CLUSTER'], None)])
        self.assertTrue(all('/certificates/cert-new' in c['path']
                            for c in ctx.find('POST', 'apply_certificate')))
        self.assertTrue(ctx.find('GET', r'cert-new\?action=validate&usage=SERVER'))
        self.assertEqual([c['path'] for c in ctx.find('DELETE', '')],
                         ['/api/v1/trust-management/certificates/old1'])
        self.assertTrue([w for lv, w in ctx.steps if 'NSX still uses it' in w])
        self.assertTrue(ctx.calls[0]['headers']['Authorization'].startswith('Basic '))

    def test_not_valid_refused_before_apply(self):
        ctx = FakeCtx(nsx_routes(valid='ERROR'))
        with self.assertRaises(PluginError) as e:
            make('nsx_manager', '', ctx, host='nsx1', user='a', password='p').deploy(
                FakeBundle(), {})
        self.assertIn('chain does not verify', str(e.exception))
        self.assertFalse(ctx.find('POST', 'apply_certificate'))

    def test_there_already_not_imported_again_and_nothing_to_apply(self):
        b = FakeBundle()
        ctx = FakeCtx(nsx_routes([{'id': 'c9', 'display_name': C.object_name(b, {})}]))
        make('nsx_manager', '', ctx, host='nsx1', user='a', password='p').deploy(
            b, {'vip': True})
        self.assertFalse(ctx.find('POST', 'action=import'))
        self.assertTrue(ctx.find('POST', r'certificates/c9\?action=apply_certificate'))
        with self.assertRaises(PluginError):
            make('nsx_manager', '', FakeCtx(nsx_routes()), host='n', user='a',
                 password='p').deploy(b, {'vip': False})

    def test_web_service_restarting_asked_again(self):
        n = {'i': 0}

        def flaky(call):
            n['i'] += 1
            return (503, {'error_message': 'restarting'}) if n['i'] == 1 else (200, {})
        ctx = FakeCtx(nsx_routes(extra=[('POST', r'action=apply_certificate', flaky)]))
        make('nsx_manager', '', ctx, host='nsx1', user='a', password='p').deploy(
            FakeBundle(), {'vip': True})
        self.assertEqual(len(ctx.find('POST', 'apply_certificate')), 2)


# ---------------------------------------------------------------------------
def ps_scripts(ssh):
    """The PowerShell each run carried (encoded, or uploaded as a .ps1)."""
    out = []
    for cmd, _inp in ssh.runs:
        m = re.search(r'-EncodedCommand (\S+)', cmd)
        if m:
            out.append(base64.b64decode(m.group(1)).decode('utf-16-le'))
            continue
        m = re.search(r'-File "([^"]+)"', cmd)
        if m:
            data = [d for p, d, _m in ssh.puts if p == m.group(1)][-1]
            out.append(data.decode('utf-8-sig'))
    return out


class HorizonTest(unittest.TestCase):
    CFG = dict(host='cs01.example.test', user='Administrator', auth='password', password='p')

    def test_import_friendly_name_restart(self):
        b = FakeBundle()
        ssh = FakeSsh([(r'.', (0, 'STEP ok fine\n', ''))])
        ctx = FakeCtx(ssh=ssh)
        words = make('horizon_cs', '', ctx, **self.CFG).deploy(b, {})
        self.assertIn('the service restarted', words)
        sc = ps_scripts(ssh)
        imp = [s for s in sc if 'Import-PfxCertificate' in s][0]
        self.assertIn('-Exportable', imp)
        self.assertIn("$cert.FriendlyName = 'vdm'", imp)
        self.assertIn("FriendlyName -eq 'vdm'", imp)
        self.assertIn('Cert:\\LocalMachine\\CA', imp)
        self.assertIn(C.sha1_thumb(b), imp)
        rs = [s for s in sc if 'Restart-Service' in s][0]
        self.assertIn('wsbroker', rs)
        paths = [p for p, d, m in ssh.puts]
        self.assertTrue(any(p.endswith('.pfx') for p in paths))
        self.assertTrue(any(p.endswith('.cer') for p in paths))
        self.assertTrue(all(v == 'scp' for v in ssh.vias))
        self.assertNotIn('ConvertTo-SecureString', ' '.join(w for _l, w in ctx.steps))

    def test_no_restart_warned_and_ec_name(self):
        ssh = FakeSsh()
        ctx = FakeCtx(ssh=ssh)
        make('horizon_cs', '', ctx, **self.CFG).deploy(
            FakeBundle(), {'restart': False, 'friendly_name': 'vdm.ec', 'intermediates': False})
        sc = ps_scripts(ssh)
        self.assertFalse([s for s in sc if 'Restart-Service' in s])
        self.assertTrue([s for s in sc if "$cert.FriendlyName = 'vdm.ec'" in s])
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'not restarted' in w])

    def test_import_refused_staged_files_removed(self):
        # 1.0.96: the PKCS#12 and the .cer files stayed in the temporary folder on a failure
        ssh = FakeSsh()

        def answer(cmd, inp):
            probe = FakeSsh()
            probe.runs, probe.puts = [(cmd, inp)], ssh.puts
            sc = ps_scripts(probe)
            if sc and 'Import-PfxCertificate' in sc[0]:
                return 1, '', 'Import-PfxCertificate : The PFX file could not be read'
            return 0, '', ''
        ssh.answers.append((r'.', answer))
        ctx = FakeCtx(ssh=ssh)
        with self.assertRaises(PluginError):
            make('horizon_cs', '', ctx, **self.CFG).deploy(FakeBundle(), {})
        staged = [p for p, d, m in ssh.puts if re.search(r'acme-hz-\w+\.(pfx|cer)$', p)]
        self.assertTrue(any(p.endswith('.pfx') for p in staged))
        self.assertTrue(any(p.endswith('.cer') for p in staged))
        # a run of its own: the import script, which removes them itself, failed
        rm = [s for s in ps_scripts(ssh) if 'Remove-Item' in s and
              'Import-PfxCertificate' not in s]
        self.assertTrue(rm)
        for p in staged:
            self.assertIn(p.replace("'", "''"), rm[-1], p)
        self.assertFalse([s for s in ps_scripts(ssh) if 'Restart-Service' in s])

    def test_older_ones_only_acmes(self):
        ctx = FakeCtx(ssh=FakeSsh())
        ctx.kv['horizon-thumbs:cs01.example.test:22'] = ['AAAA', 'BBBB']
        t = make('horizon_cs', '', ctx, **self.CFG)
        sc = t.script(FakeBundle(), {'keep': 1}, 'C:/x.pfx', 'pw', [])
        self.assertIn("$mine = @('AAAA', 'BBBB')", sc)
        self.assertIn('Select-Object -Skip 1', sc)

    def test_try_needs_an_administrator_and_the_service(self):
        ok = FakeSsh([(r'.', (0, 'HZ|Administrator|True|wsbroker|Running|CN=cs01|2027\n', ''))])
        self.assertIn('wsbroker is Running', make('horizon_cs', '', FakeCtx(ssh=ok),
                                                  **self.CFG).test())
        bad = FakeSsh([(r'.', (0, 'HZ|u|False|wsbroker|Running||\n', ''))])
        with self.assertRaises(PluginError):
            make('horizon_cs', '', FakeCtx(ssh=bad), **self.CFG).test()
        none = FakeSsh([(r'.', (0, 'HZ|u|True||||\n', ''))])
        with self.assertRaises(PluginError) as e:
            make('horizon_cs', '', FakeCtx(ssh=none), **self.CFG).test()
        self.assertIn('no Horizon Connection Server', str(e.exception))


# ---------------------------------------------------------------------------
class SddcManagerTest(unittest.TestCase):
    def routes(self, have=None):
        return [('POST', r'/v1/tokens$', (201, {'accessToken': 'JWT', 'refreshToken': {'id': 'r'}})),
                ('GET', r'/v1/sddc-manager/trusted-certificates$',
                 (200, {'elements': have or []})),
                ('POST', r'/v1/sddc-manager/trusted-certificates$', (200, {}))]

    def test_root_added_once(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes())
        t = make('sddc_manager', '', ctx, host='sddc', user='u', password='p')
        self.assertIn('1 CA certificate added', t.deploy(b, {}))
        post = ctx.find('POST', 'trusted-certificates')[0]
        self.assertEqual(post['headers']['Authorization'], 'Bearer JWT')
        self.assertEqual(ctx.json(post), {'certificate': b.chain_pems[0].strip() + '\n',
                                          'certificateUsageType': 'TRUSTED_FOR_OUTBOUND'})
        self.assertTrue([w for lv, w in ctx.steps if 'sddcmanager_restart_services.sh' in w])
        ctx2 = FakeCtx(self.routes([{'alias': 'x', 'certificate': b.chain_pems[0]}]))
        make('sddc_manager', '', ctx2, host='sddc', user='u', password='p').deploy(b, {})
        self.assertFalse(ctx2.find('POST', 'trusted-certificates'))

    def test_nothing_to_add_and_bad_sign_in(self):
        b = FakeBundle()
        b.chain_pems = []
        with self.assertRaises(PluginError) as e:
            make('sddc_manager', '', FakeCtx(self.routes()), host='s', user='u',
                 password='p').deploy(b, {})
        self.assertFalse(e.exception.retry)
        ctx = FakeCtx([('POST', r'/v1/tokens$', (401, {'message': 'bad'}))])
        with self.assertRaises(PluginError) as e:
            make('sddc_manager', '', ctx, host='s', user='u', password='p').test()
        self.assertFalse(e.exception.retry)


# ---------------------------------------------------------------------------
class AriaLifecycleTest(unittest.TestCase):
    def routes(self, state='COMPLETED', after=None):
        b = FakeBundle()
        alias = C.object_name(b, {})
        prefix = C.name_prefix(b, {})
        listed = {'n': 0}

        def locker(call):
            listed['n'] += 1
            items = [{'alias': prefix + '20250101-aaaaaaaa', 'vmid': 'v-old'},
                     {'alias': 'someone-else', 'vmid': 'v-x'}]
            if listed['n'] > 1 or after:
                items.append({'alias': alias, 'vmid': 'v-new'})
            return 200, items
        return [('GET', r'/lcm/locker/api/v2/certificates$', locker),
                ('POST', r'/lcm/locker/api/v2/certificates/import$', (200, {})),
                ('POST', r'/pre-validate$', (200, {})),
                ('PUT', r'/products/vrops/certificates/v-new$', (200, {'requestId': 'r-1'})),
                ('GET', r'/lcm/request/api/v2/requests/r-1$', (200, {'state': state})),
                ('DELETE', r'/lcm/locker/api/v2/certificates/', (200, {}))]

    def test_import_replace_wait_cleanup(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes())
        words = make('aria_lifecycle', '', ctx, host='lcm', user='admin@local',
                     password='p').deploy(b, {'products': 'env-1 vrops', 'keep': 0})
        self.assertIn('vrops', words)
        imp = ctx.json(ctx.find('POST', 'import')[0])
        self.assertEqual(sorted(imp), ['alias', 'certificateChain', 'passphrase', 'privateKey'])
        self.assertEqual(imp['privateKey'], b.key_pem)
        self.assertTrue(imp['certificateChain'].startswith(b.cert_pem.strip()))
        self.assertEqual([p for m, p in methods(ctx) if 'lcops' in p],
                         ['/lcm/lcops/api/v2/environments/env-1/products/vrops/certificates/'
                          'v-new/pre-validate',
                          '/lcm/lcops/api/v2/environments/env-1/products/vrops/certificates/'
                          'v-new'])
        self.assertTrue(ctx.find('GET', 'requests/r-1'))
        self.assertEqual([c['path'] for c in ctx.find('DELETE', '')],
                         ['/lcm/locker/api/v2/certificates/v-old'])
        self.assertTrue(ctx.calls[0]['headers']['Authorization'].startswith('Basic '))

    def test_failed_request_and_bad_line(self):
        ctx = FakeCtx(self.routes('FAILED'))
        with self.assertRaises(PluginError) as e:
            make('aria_lifecycle', '', ctx, host='lcm', user='a', password='p').deploy(
                FakeBundle(), {'products': 'env-1 vrops'})
        self.assertIn('failed', str(e.exception))
        with self.assertRaises(PluginError):
            make('aria_lifecycle', '', FakeCtx(self.routes()), host='lcm', user='a',
                 password='p').deploy(FakeBundle(), {'products': 'only-one-word'})

    def test_in_the_locker_already_only_locker(self):
        ctx = FakeCtx(self.routes(after=True))
        make('aria_lifecycle', '', ctx, host='lcm', user='a', password='p').deploy(
            FakeBundle(), {'keep': -1})
        self.assertFalse(ctx.find('POST', 'import'))
        self.assertFalse(ctx.find('PUT', ''))


# ---------------------------------------------------------------------------
class AriaAutomationTest(unittest.TestCase):
    CFG = dict(host='vra1', user='root', auth='password', password='p')

    def test_validate_set_deploy(self):
        b = FakeBundle()
        ssh = FakeSsh([(r'ingress --list', (0, 'no certificate', ''))])
        ctx = FakeCtx(ssh=ssh)
        words = make('aria_automation', '', ctx, **self.CFG).deploy(b, {})
        self.assertIn('services deployed', words)
        path, data, mode = ssh.puts[0]
        self.assertTrue(path.startswith('/root/acme-ingress-'))
        self.assertEqual(mode, 0o600)
        text = data.decode()
        self.assertTrue(text.startswith(b.key_pem.strip()), 'the key first (KB 325876)')
        self.assertLess(text.index(V.pem_body(b.cert_pem)[:40]),
                        text.index(V.pem_body(b.chain_pems[0])[:40]))
        self.assertNotIn('-----\n\n', text)
        cmds = [c for c, _ in ssh.runs]
        order = [n for n, c in enumerate(cmds) for w in ('--validate stdin', '--set ',
                                                          '/opt/scripts/deploy.sh', 'rm -f ')
                 if w in c]
        self.assertEqual(order, sorted(order))
        self.assertEqual(len(order), 4)

    def test_same_nothing_and_errors(self):
        b = FakeBundle()
        ssh = FakeSsh([(r'ingress --list', (0, b.fullchain_pem, ''))])
        self.assertTrue(make('aria_automation', '', FakeCtx(ssh=ssh), **self.CFG).deploy(
            b, {}).startswith('unchanged'))
        self.assertEqual(ssh.puts, [])
        bad = FakeSsh([(r'--validate', (1, '', 'invalid chain'))])
        with self.assertRaises(PluginError) as e:
            make('aria_automation', '', FakeCtx(ssh=bad), **self.CFG).deploy(b, {})
        self.assertIn('invalid chain', str(e.exception))
        self.assertFalse([c for c, _ in bad.runs if '--set ' in c])
        self.assertTrue([c for c, _ in bad.runs if 'rm -f' in c], 'the key file removed')
        sha = FakeSsh([(r'--set', (0, 'run again with --sha256 abc', ''))])
        with self.assertRaises(PluginError) as e:
            make('aria_automation', '', FakeCtx(ssh=sha), **self.CFG).deploy(b, {})
        self.assertIn('KB 423843', str(e.exception))
        self.assertFalse([c for c, _ in sha.runs if 'deploy.sh' in c])

    def test_ec_refused(self):
        with self.assertRaises(PluginError):
            make('aria_automation', '', FakeCtx(), **self.CFG).deploy(bundle('ec'), {})


# ---------------------------------------------------------------------------
class VcdTest(unittest.TestCase):
    def routes(self, have=None, consumers=0):
        b = FakeBundle()
        prefix = C.name_prefix(b, {})
        lib = [{'id': 'urn:vcloud:certificateLibraryItem:old', 'alias': prefix + '20250101-aaaaaaaa'},
               {'id': 'urn:vcloud:certificateLibraryItem:jmx', 'alias': 'jmx-cert'}] + (have or [])

        def library(call):
            if 'filter=' in call['url']:
                a = call['query']['filter'][0].split('==', 1)[1]
                return 200, {'values': [x for x in lib if x['alias'] == a], 'pageCount': 1}
            return 200, {'values': lib, 'pageCount': 1}
        return [
            ('POST', r'/sessions/provider$', (200, {'name': 'svc'},
                                              {'X-VMWARE-VCLOUD-ACCESS-TOKEN': 'TOK'})),
            ('GET', r'/ssl/certificateLibrary/[^/?]+/consumers', (200, {'resultTotal': consumers})),
            ('GET', r'/ssl/certificateLibrary\?', library),
            ('POST', r'/ssl/certificateLibrary$', (201, {'id': 'urn:vcloud:certificateLibraryItem:new',
                                                         'alias': 'x'})),
            ('DELETE', r'/ssl/certificateLibrary/', (204, '')),
            ('GET', r'/cells\?', (200, {'values': [{'id': 'urn:vcloud:cell:1', 'name': 'cell1'},
                                                   {'id': 'urn:vcloud:cell:2', 'name': 'cell2'}],
                                        'pageCount': 1})),
            ('GET', r'/accessEndpoints$', (200, {
                'apiSslCertRef': {'id': 'urn:vcloud:certificateLibraryItem:old', 'name': 'o'},
                'jmxSslCertRef': {'id': 'urn:vcloud:certificateLibraryItem:jmx', 'name': 'jmx'},
                'publicPort': 443})),
            ('PUT', r'/accessEndpoints$', (202, '', {'Location': 'https://vcd/api/task/t1'})),
            ('GET', r'/api/task/t1$', (200, {'status': 'success'})),
            ('GET', r'/cells/urn%3Avcloud%3Acell%3A1$', (200, {'id': 'urn:vcloud:cell:1',
                                                               'name': 'cell1', 'status': 'ACTIVE'})),
            ('PUT', r'/cells/urn%3Avcloud%3Acell%3A1$', (202, '', {'Location': 'https://vcd/api/task/t1'})),
        ]

    def test_library_then_each_cell(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes())
        words = make('vcd', '', ctx, host='vcd', user='svc', password='p').deploy(b, {'keep': 0})
        self.assertIn('cell1, cell2', words)
        login = ctx.find('POST', 'sessions/provider')[0]
        self.assertIn('svc@System', base64.b64decode(login['headers']['Authorization'][6:]).decode())
        self.assertEqual(login['headers']['Accept'], 'application/json;version=39.0')
        post = ctx.json(ctx.find('POST', r'certificateLibrary$')[0])
        self.assertEqual(post['certificate'], b.fullchain_pem)
        self.assertEqual(post['privateKey'], b.key_pem)
        self.assertEqual(post['alias'], C.object_name(b, {}))
        puts = [ctx.json(c) for c in ctx.find('PUT', 'accessEndpoints')]
        self.assertEqual(len(puts), 2)
        self.assertEqual(puts[0]['apiSslCertRef']['id'], 'urn:vcloud:certificateLibraryItem:new')
        self.assertEqual(puts[0]['jmxSslCertRef']['id'], 'urn:vcloud:certificateLibraryItem:jmx')
        self.assertEqual(puts[0]['publicPort'], 443, 'the rest kept')
        self.assertTrue(all(c['headers']['Authorization'] == 'Bearer TOK'
                            for c in ctx.find('PUT', '')))
        self.assertEqual([c['path'] for c in ctx.find('DELETE', '')],
                         ['/cloudapi/1.0.0/ssl/certificateLibrary/'
                          'urn%3Avcloud%3AcertificateLibraryItem%3Aold'])

    def test_one_cell_in_maintenance(self):
        ctx = FakeCtx(self.routes(consumers=1))
        make('vcd', '', ctx, host='vcd', user='svc@System', password='p').deploy(
            FakeBundle(), {'cells': 'cell1', 'maintenance': True})
        sts = [ctx.json(c)['status'] for c in ctx.find('PUT', r'/cells/urn%3Avcloud%3Acell%3A1$')]
        self.assertEqual(sts, ['MAINTENANCE', 'ACTIVE'])
        self.assertEqual(len(ctx.find('PUT', 'accessEndpoints')), 1)
        self.assertFalse(ctx.find('DELETE', ''), 'used: kept')

    def test_unknown_cell_and_no_token(self):
        with self.assertRaises(PluginError):
            make('vcd', '', FakeCtx(self.routes()), host='vcd', user='u', password='p').deploy(
                FakeBundle(), {'cells': 'nope'})
        ctx = FakeCtx([('POST', r'/sessions/provider$', (200, {}))])
        with self.assertRaises(PluginError) as e:
            make('vcd', '', ctx, host='vcd', user='u', password='p').test()
        self.assertIn('ACCESS-TOKEN', str(e.exception))


# ---------------------------------------------------------------------------
class VmwareDrTest(unittest.TestCase):
    def routes(self, cur=None, session=(200, {'session_id': 'DR1'})):
        return [('POST', r':5480/configure/requests/session$', session),
                ('GET', r'/appliance/certificates/server$', (200, cur or {'thumbprint': 'AA'})),
                ('POST', r'/appliance/certificates/ca$', (204, '')),
                ('POST', r'/appliance/certificates/server$', (204, ''))]

    def test_ca_then_pkcs12(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes())
        make('vmware_dr', '', ctx, host='vlsr1', password='p').deploy(b, {})
        self.assertEqual(ctx.find('POST', 'session')[0]['url'],
                         'https://vlsr1:5480/configure/requests/session')
        ca = ctx.find('POST', 'certificates/ca')[0]
        self.assertEqual(ca['headers']['x-dr-session'], 'DR1')
        self.assertEqual(ctx.json(ca), [{'value': b.chain_pems[0].strip() + '\n'}])
        body = ctx.json(ctx.find('POST', r'certificates/server$')[0])['pkcs12_format']
        self.assertLessEqual(len(body['password']), 31)
        p12 = base64.b64decode(body['certificate'])
        self.assertGreater(len(p12), 100)
        out = T.openssl('pkcs12', '-in', '/dev/stdin', '-nokeys', '-passin',
                        'pass:' + body['password'], data=p12)
        self.assertIn(V.pem_body(b.cert_pem)[:60], out.decode().replace('\n', ''))
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'Reconnect' in w])

    def test_same_and_vr_restart_and_wrong_path(self):
        b = FakeBundle()
        ctx = FakeCtx(self.routes({'certificate': b.cert_pem}))
        self.assertTrue(make('vmware_dr', '', ctx, host='v', password='p').deploy(
            b, {}).startswith('unchanged'))
        self.assertFalse(ctx.find('POST', r'certificates/server$'))
        ctx = FakeCtx(self.routes())
        make('vmware_dr', '', ctx, host='vr1', password='p', product='vr').deploy(b, {})
        self.assertTrue([w for lv, w in ctx.steps if lv == 'warn' and 'restart the vSphere '
                         'Replication appliance' in w])
        ctx = FakeCtx(self.routes(session=(404, 'Not Found')))
        with self.assertRaises(PluginError) as e:
            make('vmware_dr', '', ctx, host='v', password='p').test()
        self.assertIn('API path', str(e.exception))


# ---------------------------------------------------------------------------
def sup_routes(ver='9.1.0', has_sup=True):
    return [
        ('GET', r'/sdk/vim25/8\.0\.1\.0/ServiceInstance/ServiceInstance/content$',
         (200, {'about': {'version': ver}}) if ver else (404, '')),
        ('POST', r'/api/session$', (201, '"S"')),
        ('DELETE', r'/api/session$', (204, '')),
        ('GET', r'/supervisors/domain-c8/certificates$',
         (200, {'tls_endpoint_certificate': ''}) if has_sup else (404, {})),
        ('PATCH', r'/supervisors/domain-c8/certificates$', (204, '')),
        ('GET', r'/namespace-management/clusters/domain-c8$', (200, {'api_server_management_endpoint': 'x'})),
        ('PATCH', r'/namespace-management/clusters/domain-c8$', (204, '')),
    ]


SUPCFG = dict(host='vc1', user='u', password='p', supervisor='domain-c8')


class SupervisorTest(unittest.TestCase):
    def test_plain_on_91_and_90(self):
        b = FakeBundle()
        ctx = FakeCtx(sup_routes('9.1.1'))
        make('vsphere_supervisor', '', ctx, **SUPCFG).deploy(b, {'endpoint': 'DEFAULT_NSX_INGRESS'})
        body = ctx.json(ctx.find('PATCH', 'supervisors')[0])
        self.assertEqual(body['endpoint'], 'DEFAULT_NSX_INGRESS')
        self.assertEqual(body['tls_endpoint_private_key'], b.key_pem)
        self.assertTrue(body['tls_endpoint_certificate'].startswith(b.cert_pem.strip()))
        self.assertFalse(ctx.find('PATCH', 'clusters'))
        ctx = FakeCtx(sup_routes('9.0.2'))
        make('vsphere_supervisor', '', ctx, **SUPCFG).deploy(b, {})
        body = ctx.json(ctx.find('PATCH', 'clusters/domain-c8')[0])
        self.assertEqual(sorted(body), ['tls_endpoint_certificate', 'tls_endpoint_private_key'])
        self.assertFalse(ctx.find('PATCH', 'supervisors'))

    def test_plain_unknown_version_falls_back(self):
        ctx = FakeCtx(sup_routes(None, has_sup=False))
        make('vsphere_supervisor', '', ctx, **SUPCFG).deploy(FakeBundle(), {})
        self.assertTrue(ctx.find('PATCH', 'clusters/domain-c8'))

    def test_versions_refuse_others_before_any_change(self):
        for version, ver, fit in (('9.0', '9.1.0', 'vCenter 9.1 and later 9.x'),
                                  ('9.1', '9.0.1', 'vCenter 9.0'),
                                  ('', '8.0.3', None), ('9.1', '8.0.3', None)):
            ctx = FakeCtx(sup_routes(ver))
            with self.assertRaises(PluginError) as e:
                make('vsphere_supervisor', version, ctx, **SUPCFG).deploy(FakeBundle(), {})
            self.assertFalse(e.exception.retry)
            self.assertIn('runs %s' % ver, str(e.exception))
            if fit:
                self.assertIn('"%s"' % fit, str(e.exception))
            self.assertEqual(changed(ctx), [], (version, ver))

    def test_versions_use_their_own_calls(self):
        ctx = FakeCtx(sup_routes('9.0.0'))
        make('vsphere_supervisor', '9.0', ctx, **SUPCFG).deploy(FakeBundle(), {})
        self.assertTrue(ctx.find('PATCH', 'clusters'))
        ctx = FakeCtx(sup_routes('9.1.0'))
        make('vsphere_supervisor', '9.1', ctx, **SUPCFG).deploy(FakeBundle(), {})
        self.assertTrue(ctx.find('PATCH', 'supervisors'))
        with self.assertRaises(PluginError):
            make('vsphere_supervisor', '9.0', FakeCtx(sup_routes('9.0.0')), **SUPCFG).deploy(
                FakeBundle(), {'endpoint': 'DEFAULT_NSX_INGRESS'})

    def test_try_and_served(self):
        t = make('vsphere_supervisor', '', FakeCtx(sup_routes('9.1.0')),
                 **dict(SUPCFG, endpoint_host='sup.example.test'))
        self.assertIn('supervisors calls', t.test())
        self.assertEqual(t.served_places({}), [('sup.example.test', 443)])
        self.assertEqual(t.served_places({'endpoint': 'KUBERNETES_API_SERVER'}),
                         [('sup.example.test', 443)])
        # 1.0.96: the API endpoint serves its own certificate, not the NSX ingress's - no test
        # made there for an ingress deployment
        for v in ('', '9.1'):
            t = make('vsphere_supervisor', v, FakeCtx(), **dict(SUPCFG,
                                                               endpoint_host='sup.example.test'))
            self.assertEqual(t.served_places({'endpoint': 'DEFAULT_NSX_INGRESS'}), [])


def verify_asked(t, options=None):
    """The (host, port) each verify() of a target checks (check_served not run)."""
    seen = []
    old = C.check_served
    C.check_served = lambda ctx, b, hp, *a, **k: seen.extend(
        C.split_hostport(x) for x in hp) or 'ok'
    try:
        t.verify(FakeBundle(), dict(options or {}, verify_tries=1))
    finally:
        C.check_served = old
    return seen


class Ipv6Test(unittest.TestCase):
    def test_esxi_and_horizon_verify_ipv6(self):
        # 1.0.96: "2001:db8::1:443" was read as a host without a port
        t = make('esxi', '8.0.3', FakeCtx([]), **dict(ESXCFG, esx_name='2001:db8::5'))
        self.assertEqual(verify_asked(t), [('2001:db8::5', 443)])
        t = make('horizon_cs', '', FakeCtx([]), **dict(HorizonTest.CFG, host='2001:db8::6'))
        self.assertEqual(verify_asked(t), [('2001:db8::6', 443)])


if __name__ == '__main__':
    unittest.main(verbosity=1)
