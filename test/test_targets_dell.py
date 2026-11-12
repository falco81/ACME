#!/usr/bin/env python3
"""The Dell targets (1.0.94), without a network.

    python3 test/test_targets_dell.py

  redfish@6.00.02       iDRAC9 6.00.02+ / iDRAC10: Dell OEM UploadSSLKey + ImportSSLCertificate
  powerscale            OneFS 8.2 - 9.12: RAN upload to /ifs, certificate/server, settings
  powerstore            PowerStoreOS 3.0 - 4.4: x509_certificate with private_key
  unity                 Unity OE 5.x: service shell, svc_custom_cert
  unisphere_powermax    Unisphere 10.x: the Solutions Enabler certificate (Serviceability)

Each fake answers as the vendor's documents say; the requests made are asserted
(method, path, body). The fake Context and certificates are those of test_targets.py.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import redfish_idrac as RI  # noqa: E402

GUIDES = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(kind, ctx, version='', served=False, **cfg):
    """The module; no TLS handshake leaves the test - what is served is `served`."""
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, version)
    assert cls.module_version == version, (cls.module_version, version)
    t = cls(cfg, ctx)
    if hasattr(t, 'served_now'):
        t.served_now = lambda bundle: served
    return t


# ---------------------------------------------------------------------------
# iDRAC through Dell's OEM service
# ---------------------------------------------------------------------------
MGR = '/redfish/v1/Managers/iDRAC.Embedded.1'
SVC = MGR + '/Oem/Dell/DelliDRACCardService'


def idrac(fw='7.10.70.00', model='14G Monolithic', acts=True, extra=()):
    ok = (200, {})
    actions = {'#DelliDRACCardService.UploadSSLKey': {'target': SVC + '/Actions/x'},
               '#DelliDRACCardService.ImportSSLCertificate': {}} if acts else \
        {'#DelliDRACCardService.ExportSSLCertificate': {}}
    return list(extra) + [
        ('GET', r'/redfish/v1/$', (200, {'Links': {'Sessions': {
            '@odata.id': '/redfish/v1/SessionService/Sessions'}}, 'RedfishVersion': '1.20.1'})),
        ('POST', r'/SessionService/Sessions$', (201, {}, {
            'X-Auth-Token': 'TOK', 'Location': '/redfish/v1/SessionService/Sessions/9'})),
        ('DELETE', r'/Sessions/9$', ok),
        ('GET', r'/redfish/v1/Managers$', (200, {'Members': [{'@odata.id': MGR}]})),
        ('GET', r'iDRAC.Embedded.1$', (200, {'Model': model, 'FirmwareVersion': fw,
                                            'Oem': {'Dell': {}}})),
        ('GET', r'DelliDRACCardService$', (200, {'Actions': actions})),
        ('POST', r'UploadSSLKey$', ok),
        ('POST', r'ImportSSLCertificate$', ok),
        ('POST', r'Manager.Reset$', (204, b'')),
    ]


IDRAC = {'host': 'idrac', 'user': 'acme', 'password': 'pw'}


class IdracTest(unittest.TestCase):
    def test_registered_beside_the_plain_one(self):
        reg = Registry(extra_dirs=[]).reload()
        vers = reg.versions_of('target', 'redfish')
        self.assertIn('6.00.02', vers)
        plain, oem = vers[''], vers['6.00.02']
        self.assertIs(reg.get('target', 'redfish', ''), plain)
        self.assertFalse(oem.__dict__.get('default_version'), 'the plain one stays the default')
        self.assertEqual(oem.fields, plain.fields, 'saved settings fit both')
        self.assertEqual(oem.deploy_fields, plain.deploy_fields)
        self.assertIn(oem.version_label, oem.description)

    def test_generations(self):
        self.assertEqual(RI.generation(RI.fw_tuple('7.10.70.00')), 'iDRAC9')
        self.assertEqual(RI.generation(RI.fw_tuple('1.20.50.50')), 'iDRAC10')
        self.assertEqual(RI.generation(RI.fw_tuple('2.84.84.84')), '')
        self.assertIsNone(RI.fw_tuple('?'))

    def deploy(self, fw='7.10.70.00', **opt):
        b = FakeBundle()
        ctx = FakeCtx(idrac(fw))
        got = make('redfish', ctx, '6.00.02', **IDRAC).deploy(b, opt)
        return b, ctx, got

    def test_key_then_certificate(self):
        for fw in ('7.10.70.00', '6.00.02.00', '1.20.50.50'):
            b, ctx, got = self.deploy(fw)
            posts = [(c['method'], c['path']) for c in ctx.calls if c['method'] == 'POST']
            self.assertEqual(posts, [
                ('POST', '/redfish/v1/SessionService/Sessions'),
                ('POST', SVC + '/Actions/DelliDRACCardService.UploadSSLKey'),
                ('POST', SVC + '/Actions/DelliDRACCardService.ImportSSLCertificate')], fw)
            self.assertEqual(ctx.json(ctx.find('POST', 'UploadSSLKey')[0]),
                             {'SSLKeyString': b.key_pem})
            self.assertEqual(ctx.json(ctx.find('POST', 'ImportSSLCertificate')[0]),
                             {'CertificateType': 'Server', 'SSLCertificateFile': b.fullchain_pem})
            self.assertTrue(all(c['headers'].get('X-Auth-Token') == 'TOK'
                                for c in ctx.find('POST', 'DelliDRACCardService')))
            self.assertFalse(ctx.find('POST', 'ReplaceCertificate'))
            self.assertFalse(ctx.find('POST', 'Manager.Reset'), 'no reset unless asked')
            self.assertIn('iDRAC1' if fw.startswith('1.') else 'iDRAC9', got)

    def test_pem_only_and_reset(self):
        b, ctx, got = self.deploy(cert_type='PEM', reset=True)
        self.assertEqual(ctx.json(ctx.find('POST', 'ImportSSLCertificate')[0])
                         ['SSLCertificateFile'], b.cert_pem)
        self.assertEqual(ctx.json(ctx.find('POST', 'Manager.Reset')[0]),
                         {'ResetType': 'GracefulRestart'})
        self.assertEqual(RI.IdracOemTarget.served_wait({'reset': True}), (20, 15))
        self.assertEqual(RI.IdracOemTarget.served_wait({}), (8, 10))

    def test_refused_before_any_change(self):
        for fw, model in (('5.10.50.00', '14G Monolithic'), ('2.83.83.83', '13G Monolithic')):
            ctx = FakeCtx(idrac(fw, model))
            with self.assertRaises(PluginError) as e:
                make('redfish', ctx, '6.00.02', **IDRAC).deploy(FakeBundle(), {})
            self.assertFalse(e.exception.retry)
            self.assertIn('firmware %s' % fw, str(e.exception))
            self.assertFalse(ctx.find('POST', 'DelliDRACCardService'), 'nothing changed')

    def test_not_an_idrac(self):
        routes = [('GET', r'/redfish/v1/Managers$', (200, {'Members': [{'@odata.id':
                                                                        '/redfish/v1/Managers/1'}]})),
                  ('GET', r'/Managers/1$', (200, {'Model': 'iLO 6', 'FirmwareVersion': '1.55',
                                                  'Manufacturer': 'HPE'}))]
        ctx = FakeCtx(idrac(extra=routes))
        with self.assertRaises(PluginError) as e:
            make('redfish', ctx, '6.00.02', **IDRAC).deploy(FakeBundle(), {})
        self.assertIn('not a Dell iDRAC', str(e.exception))
        self.assertFalse(ctx.find('POST', 'Dell'))

    def test_no_upload_action(self):
        ctx = FakeCtx(idrac(acts=False))
        with self.assertRaises(PluginError) as e:
            make('redfish', ctx, '6.00.02', **IDRAC).deploy(FakeBundle(), {})
        self.assertIn('UploadSSLKey', str(e.exception))
        self.assertFalse(ctx.find('POST', 'UploadSSLKey'))

    def test_unknown_firmware_warned_and_newer_warned(self):
        for fw, words in (('', 'cannot be read'), ('7.40.00.00', 'newer')):
            ctx = FakeCtx(idrac(fw))
            make('redfish', ctx, '6.00.02', **IDRAC).deploy(FakeBundle(), {})
            self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and words in w], fw)
            self.assertTrue(ctx.find('POST', 'ImportSSLCertificate'))

    def test_served_already_and_try(self):
        b = FakeBundle()
        ctx = FakeCtx(idrac())
        got = make('redfish', ctx, '6.00.02', served=True, **IDRAC).deploy(b, {})
        self.assertIn('unchanged', got)
        self.assertFalse(ctx.calls)
        said = make('redfish', FakeCtx(idrac('1.30.10.00')), '6.00.02', **IDRAC).test()
        self.assertIn('firmware 1.30.10.00 (iDRAC10)', said)
        with self.assertRaises(PluginError):
            make('redfish', FakeCtx(idrac('4.40.00.00')), '6.00.02', **IDRAC).test()


# ---------------------------------------------------------------------------
# PowerScale OneFS
# ---------------------------------------------------------------------------
PS = {'host': 'onefs', 'port': 8080, 'user': 'acme', 'password': 'pw'}


def onefs(release='9.7.0.0', certs=(), default='old1', post=None, extra=()):
    ok = (200, {})
    return list(extra) + [
        ('GET', r'/platform/1/cluster/config$', (200, {'name': 'isi01', 'onefs_version': {
            'release': release}})),
        ('GET', r'/platform/4/certificate/server$', (200, {'certificates': list(certs)})),
        ('GET', r'/platform/7/certificate/settings$', (200, {'settings': {
            'default_https_certificate': default}})),
        ('PUT', r'/platform/7/certificate/settings$', (204, b'')),
        ('PUT', r'/namespace/ifs/', ok),
        ('DELETE', r'/namespace/ifs/', (204, b'')),
        ('POST', r'/platform/4/certificate/server$', post or (201, {'id': 'new1'})),
        ('DELETE', r'/platform/4/certificate/server/', (204, b'')),
    ]


class PowerScaleTest(unittest.TestCase):
    def test_import_default_cleanup(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        prefix = C.name_prefix(b, {})
        olds = [{'id': 'o%d' % i, 'name': prefix + '2026010%d-aaaa000%d' % (i, i)}
                for i in range(1, 5)]
        ctx = FakeCtx(onefs(certs=olds + [{'id': 'x', 'name': 'other'}], default='o4'))
        got = make('powerscale', ctx, **PS).deploy(b, {'keep': 2})
        put = [c for c in ctx.calls if c['method'] == 'PUT' and '/namespace/' in c['path']]
        self.assertEqual([c['path'] for c in put], [
            '/namespace/ifs/local', '/namespace/ifs/local/%s.crt' % name,
            '/namespace/ifs/local/%s.key' % name])
        self.assertEqual(put[0]['query'], {'recursive': ['true']})
        self.assertEqual(put[0]['headers']['x-isi-ifs-target-type'], 'container')
        self.assertEqual(put[1]['body'], b.fullchain_pem.encode())
        self.assertEqual(put[2]['body'], b.key_pem.encode())
        self.assertEqual(put[2]['headers']['x-isi-ifs-access-control'], '0600')
        imp = ctx.json(ctx.find('POST', 'certificate/server')[0])
        self.assertEqual((imp['name'], imp['certificate_path'], imp['certificate_key_path']),
                         (name, '/ifs/local/%s.crt' % name, '/ifs/local/%s.key' % name))
        self.assertEqual(ctx.json(ctx.find('PUT', 'certificate/settings')[0]),
                         {'default_https_certificate': 'new1'})
        self.assertEqual(sorted(c['path'] for c in ctx.find('DELETE', 'namespace')),
                         ['/namespace/ifs/local/%s.crt' % name,
                          '/namespace/ifs/local/%s.key' % name], 'the files go')
        self.assertEqual([c['path'] for c in ctx.find('DELETE', 'certificate/server/')],
                         ['/platform/4/certificate/server/o2', '/platform/4/certificate/server/o1'])
        self.assertTrue(all(c['headers']['Authorization'].startswith('Basic ')
                            for c in ctx.calls))
        self.assertIn('the default HTTPS certificate', got)
        # the order: files, import, then the files deleted, then the default
        order = [(c['method'], c['path'].split('/')[1]) for c in ctx.calls
                 if c['method'] != 'GET']
        self.assertEqual(order[:7], [('PUT', 'namespace')] * 3 + [
            ('POST', 'platform'), ('DELETE', 'namespace'), ('DELETE', 'namespace'),
            ('PUT', 'platform')])

    def test_files_deleted_when_the_import_fails(self):
        ctx = FakeCtx(onefs(post=(400, {'errors': [{'message': 'key does not match'}]})))
        with self.assertRaises(PluginError) as e:
            make('powerscale', ctx, **PS).deploy(FakeBundle(), {})
        self.assertIn('key does not match', str(e.exception))
        self.assertEqual(len(ctx.find('DELETE', 'namespace')), 2)
        self.assertFalse(ctx.find('PUT', 'certificate/settings'))

    def test_not_default_and_the_default_kept(self):
        b = FakeBundle()
        prefix = C.name_prefix(b, {})
        olds = [{'id': 'o1', 'name': prefix + '20260101-aaaa0001'}]
        ctx = FakeCtx(onefs(certs=olds, default='o1'))
        make('powerscale', ctx, **PS).deploy(b, {'default': False, 'keep': 0,
                                                 'folder': '/ifs/data/acme'})
        self.assertFalse(ctx.find('PUT', 'certificate/settings'))
        self.assertFalse(ctx.find('DELETE', 'certificate/server/'), 'the default is never deleted')
        self.assertTrue(ctx.find('PUT', '/namespace/ifs/data/acme/'))
        self.assertEqual(make('powerscale', ctx, **PS).served_places({'default': False}), [])
        self.assertEqual(make('powerscale', ctx, **PS).served_places({}), [('onefs', 8080)])

    def test_there_already_and_same(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        ctx = FakeCtx(onefs(certs=[{'id': 'n', 'name': name, 'fingerprints': [
            {'type': 'SHA256', 'value': ':'.join(b.fingerprint[i:i + 2]
                                                 for i in range(0, 64, 2))}]}], default='n'))
        t = make('powerscale', ctx, **PS)
        t.deploy(b, {})
        self.assertFalse(ctx.find('POST', 'certificate/server'), 'not imported twice')
        self.assertFalse(ctx.find('PUT', 'certificate/settings'), 'already the default')
        self.assertIn('unchanged', make('powerscale', ctx, **PS).deploy(b, {}))

    def test_versions(self):
        for rel in ('8.1.2.0', '7.2.1.0'):
            ctx = FakeCtx(onefs(rel))
            with self.assertRaises(PluginError) as e:
                make('powerscale', ctx, **PS).deploy(FakeBundle(), {})
            self.assertIn('OneFS %s' % rel, str(e.exception))
            self.assertEqual({c['method'] for c in ctx.calls}, {'GET'})
        ctx = FakeCtx(onefs('9.13.0.0'))
        make('powerscale', ctx, **PS).deploy(FakeBundle(), {})
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'newer' in w])
        self.assertIn('OneFS 9.5.0.0, default HTTPS certificate old1',
                      make('powerscale', FakeCtx(onefs('9.5.0.0')), **PS).test())

    def test_bad_folder(self):
        for f in ('/tmp', '/ifs/../etc', '/ifs/a b'):
            with self.assertRaises(PluginError):
                make('powerscale', FakeCtx(onefs()), **PS).deploy(FakeBundle(), {'folder': f})


# ---------------------------------------------------------------------------
# PowerStore
# ---------------------------------------------------------------------------
PST = {'host': 'pstore', 'user': 'acme', 'password': 'pw'}


def pstore(release='4.1.0.0', post=None, current=True):
    ok = (204, b'')
    return [
        ('GET', r'/api/rest/login_session$', (200, [{'id': 's'}], {
            'DELL-EMC-TOKEN': 'PSTOK', 'Set-Cookie': 'auth_cookie=AC; Path=/; Secure'})),
        ('GET', r'/api/rest/software_installed', (200, [{'release_version': release,
                                                         'is_cluster': True}])),
        ('POST', r'/api/rest/x509_certificate$', post or (201, {'id': 'c-1'})),
        ('GET', r'/api/rest/x509_certificate/c-1', (200, {'id': 'c-1', 'is_current': current,
                                                         'is_valid': True})),
        ('GET', r'/api/rest/x509_certificate\?', (200, [{'id': 'c-0'}])),
        ('POST', r'/api/rest/logout$', ok),
    ]


class PowerStoreTest(unittest.TestCase):
    def test_import(self):
        b = FakeBundle()
        ctx = FakeCtx(pstore())
        got = make('powerstore', ctx, **PST).deploy(b, {})
        login = ctx.find('GET', 'login_session')[0]
        self.assertTrue(login['headers']['Authorization'].startswith('Basic '))
        post = ctx.find('POST', 'x509_certificate$')[0]
        self.assertEqual(ctx.json(post), {
            'type': 'Server', 'service': 'Management_HTTP', 'scope': 'External',
            'certificate': b.fullchain_pem.strip(), 'private_key': b.key_pem.strip(),
            'is_current': True})
        self.assertIn('\\n', post['body'].decode(), 'one string, the line ends escaped')
        self.assertEqual((post['headers']['DELL-EMC-TOKEN'], post['headers']['Cookie']),
                         ('PSTOK', 'auth_cookie=AC'))
        self.assertTrue(ctx.find('POST', 'logout'))
        self.assertIn('4.1.0.0', got)

    def test_refused_said_in_words(self):
        ctx = FakeCtx(pstore(post=(400, {'messages': [{'code': '0xE09010010013'}]})))
        with self.assertRaises(PluginError) as e:
            make('powerstore', ctx, **PST).deploy(FakeBundle(), {})
        self.assertFalse(e.exception.retry)
        self.assertIn('does not take a key made elsewhere', str(e.exception))
        self.assertTrue(ctx.find('POST', 'logout'), 'signed out all the same')

    def test_not_current(self):
        with self.assertRaises(PluginError) as e:
            make('powerstore', FakeCtx(pstore(current=False)), **PST).deploy(FakeBundle(), {})
        self.assertIn('is_current false', str(e.exception))

    def test_versions(self):
        ctx = FakeCtx(pstore('2.1.1.0'))
        with self.assertRaises(PluginError) as e:
            make('powerstore', ctx, **PST).deploy(FakeBundle(), {})
        self.assertIn('PowerStoreOS 2.1.1.0', str(e.exception))
        self.assertFalse(ctx.find('POST', 'x509_certificate'))
        ctx = FakeCtx(pstore('4.5.0.0'))
        make('powerstore', ctx, **PST).deploy(FakeBundle(), {})
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'newer' in w])
        self.assertIn('PowerStoreOS 3.0.0.0, management certificates: 1',
                      make('powerstore', FakeCtx(pstore('3.0.0.0')), **PST).test())

    def test_served_already(self):
        b = FakeBundle()
        ctx = FakeCtx(pstore())
        self.assertIn('unchanged', make('powerstore', ctx, served=True, **PST).deploy(b, {}))
        self.assertFalse(ctx.calls)
        self.assertEqual(make('powerstore', ctx, **PST).served_places({}), [('pstore', 443)])


# ---------------------------------------------------------------------------
# Unity
# ---------------------------------------------------------------------------
UN = {'host': 'unity', 'user': 'service', 'auth': 'password', 'password': 'svc'}


def rsa_bundle():
    b = FakeBundle()
    b.key_type = 'rsa-2048'
    return b


class UnityTest(unittest.TestCase):
    def deploy(self, answer=(0, 'Successfully installed custom certificate files.\n'
                              'Restarting web server ...\n', ''), **opt):
        b = rsa_bundle()
        ssh = FakeSsh([(r'^svc_custom_cert', answer)])
        ctx = FakeCtx(ssh=ssh)
        got = make('unity', ctx, **UN).deploy(b, opt)
        return b, ssh, ctx, got

    def test_files_command_cleanup(self):
        b, ssh, ctx, got = self.deploy()
        self.assertEqual([(p, d) for p, d, m in ssh.puts], [
            ('/home/service/user/acmecert.crt', b.fullchain_pem.encode()),
            ('/home/service/user/acmecert.pk', b.key_pem.encode())])
        self.assertEqual({m for p, d, m in ssh.puts}, {0o600})
        self.assertEqual([c for c, i in ssh.runs], [
            'svc_custom_cert acmecert',
            'rm -f /home/service/user/acmecert.crt /home/service/user/acmecert.pk'])
        self.assertEqual((ssh.conns[0]['user'], ssh.conns[0]['password']), ('service', 'svc'))
        self.assertIn('installed', got)

    def test_leaf_only_and_base(self):
        b, ssh, ctx, got = self.deploy(with_chain=False, base='uni01')
        self.assertEqual(ssh.puts[0], ('/home/service/user/uni01.crt', b.cert_pem.encode(), 0o600))
        self.assertIn('without the intermediates', got)

    def test_failure_cleans_up(self):
        for ans in ((1, '', 'ERROR: File <acmecert.pk> does not exist'),
                    (0, 'ERROR: Certificate acmecert.crt is invalid', '')):
            with self.assertRaises(PluginError) as e:
                self.deploy(answer=ans)
            self.assertIn('ERROR', str(e.exception))

    def test_cleanup_after_a_failure_runs(self):
        ssh = FakeSsh([(r'^svc_custom_cert', (1, '', 'ERROR: x'))])
        with self.assertRaises(PluginError):
            make('unity', FakeCtx(ssh=ssh), **UN).deploy(rsa_bundle(), {})
        self.assertTrue(ssh.runs[-1][0].startswith('rm -f /home/service/user/acmecert.crt'))

    def test_refused(self):
        b = FakeBundle()
        b.key_type = 'ec-256'
        ssh = FakeSsh()
        with self.assertRaises(PluginError) as e:
            make('unity', FakeCtx(ssh=ssh), **UN).deploy(b, {})
        self.assertIn('RSA', str(e.exception))
        with self.assertRaises(PluginError):
            make('unity', FakeCtx(ssh=ssh), **UN).deploy(rsa_bundle(), {'base': 'a;rm'})
        self.assertFalse(ssh.puts)

    def test_fields_try_and_served(self):
        t = make('unity', FakeCtx(ssh=FakeSsh([(r'^id -un', (0, 'service\n/home/service/user\n',
                                                              ''))])), **UN)
        self.assertIn('as service', t.test())
        auth = [f for f in t.fields if f['key'] == 'auth'][0]
        self.assertEqual(auth['default'], 'password')
        self.assertEqual(t.served_places({}), [('unity', 443)])
        with self.assertRaises(PluginError):
            make('unity', FakeCtx(ssh=FakeSsh([(r'^id -un', (2, '', 'No such file'))])),
                 **UN).test()
        b = rsa_bundle()
        ssh = FakeSsh()
        self.assertIn('unchanged', make('unity', FakeCtx(ssh=ssh), served=True, **UN)
                      .deploy(b, {}))
        self.assertFalse(ssh.runs)


# ---------------------------------------------------------------------------
# Unisphere for PowerMax: the Solutions Enabler certificate
# ---------------------------------------------------------------------------
UP = {'host': 'u4p', 'port': 8443, 'user': 'acme', 'password': 'pw', 'array': '000120000123'}


def u4p(version=None, extra=()):
    return list(extra) + [
        ('GET', r'/univmax/restapi/version$', (200, version or {
            'version': 'V10.1.0.2', 'api_version': '101',
            'supported_api_versions': ['101', '100']})),
        ('GET', r'/application/unisphere$', (200, {'status': 'running'})),
        ('POST', r'/custom_certificate/import$', (200, {'success': True})),
    ]


class PowerMaxTest(unittest.TestCase):
    def test_import_per_node(self):
        b = FakeBundle()
        ctx = FakeCtx(u4p())
        got = make('unisphere_powermax', ctx, **UP).deploy(b, {})
        posts = ctx.find('POST', 'custom_certificate/import')
        self.assertEqual({c['path'] for c in posts}, {
            '/univmax/restapi/101/serviceability/symmetrix/000120000123/application/'
            'solutions_enabler/custom_certificate/import'})
        self.assertEqual(len(posts), 2)
        for node, c in zip(('Semgmt0', 'Semgmt1'), posts):
            self.assertTrue(c['headers']['Content-Type'].startswith('multipart/form-data'))
            body = c['body']
            self.assertIn(b'name="node_name"\r\n\r\n' + node.encode(), body)
            self.assertIn(b'name="keyfile"; filename=', body)
            self.assertIn(b.key_pem.encode(), body)
            self.assertIn(b'name="certfile"; filename=', body)
            self.assertIn(b.fullchain_pem.encode(), body)
            self.assertIn(b'name="trustfile"; filename=', body)
            self.assertIn(b.chain_pems[0].strip().encode(), body)
            self.assertTrue(c['headers']['Authorization'].startswith('Basic '))
        self.assertIn('Semgmt0, Semgmt1', got)
        self.assertIn('unchanged', make('unisphere_powermax', ctx, **UP).deploy(b, {}))
        self.assertEqual(make('unisphere_powermax', ctx, **UP).served_places({}), [])

    def test_trust_and_nodes_given(self):
        b = FakeBundle()
        ctx = FakeCtx(u4p({'version': 'V10.0.0.1'}))
        make('unisphere_powermax', ctx, **UP).deploy(b, {'nodes': 'Semgmt1',
                                                         'trust': b.cert_pem})
        posts = ctx.find('POST', 'custom_certificate/import')
        self.assertEqual(len(posts), 1)
        self.assertIn('/restapi/100/', posts[0]['path'], 'the API version from the words')
        self.assertIn(b'Semgmt1', posts[0]['body'])

    def test_refused(self):
        ctx = FakeCtx(u4p({'version': 'V9.2.1.4', 'api_version': '92'}))
        with self.assertRaises(PluginError) as e:
            make('unisphere_powermax', ctx, **UP).deploy(FakeBundle(), {})
        self.assertIn('10.0 or later', str(e.exception))
        self.assertFalse(ctx.find('POST', ''))
        for cfg, opt in ((dict(UP, array='12/34'), {}), (UP, {'nodes': 'a b'})):
            with self.assertRaises(PluginError):
                make('unisphere_powermax', FakeCtx(u4p()), **cfg).deploy(FakeBundle(), opt)
        b = FakeBundle()
        b.chain_pems = []
        with self.assertRaises(PluginError) as e:
            make('unisphere_powermax', FakeCtx(u4p()), **UP).deploy(b, {})
        self.assertIn('Trusted CA', str(e.exception))

    def test_try(self):
        self.assertIn('Unisphere V10.1.0.2 (REST API 101), array 000120000123',
                      make('unisphere_powermax', FakeCtx(u4p()), **UP).test())
        ctx = FakeCtx(u4p({'version': 'V10.5.0.0', 'api_version': '105'}))
        make('unisphere_powermax', ctx, **UP).test()
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'newer' in w])


# ---------------------------------------------------------------------------
class GuidesTest(unittest.TestCase):
    def test_both_languages(self):
        for name, must in (('redfish@6.00.02', ('UploadSSLKey', 'racadm')),
                           ('powerscale', ('ISI_PRIV_CERTIFICATE', 'isi auth roles')),
                           ('powerstore', ('x509_certificate', 'local_user')),
                           ('unity', ('svc_custom_cert', '/home/service/user')),
                           ('unisphere_powermax', ('custom_certificate', 'SecurityAdmin'))):
            for suffix in ('.md', '.cs.md'):
                p = os.path.join(GUIDES, name + suffix)
                with open(p, encoding='utf-8') as f:
                    md = f.read()
                self.assertTrue(md.startswith('# '), p)
                self.assertIn('```', md, p)
                for m in must:
                    self.assertIn(m, md, p)
        for k in ('openmanage', 'ome'):
            self.assertFalse(os.path.exists(os.path.join(GUIDES, k + '.md')))


if __name__ == '__main__':
    unittest.main(verbosity=1)
