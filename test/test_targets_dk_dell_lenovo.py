#!/usr/bin/env python3
"""Dell OpenManage Enterprise (dell_ome) and Lenovo XClarity Administrator (lenovo_lxca): the
device makes the key.

    python3 test/test_targets_dk_dell_lenovo.py

Without a network and without a device - a fake OME / LXCA REST API (test_targets.FakeCtx) and
the exact calls checked: the CSR asked (the names, the subject), the certificate uploaded with
no key (OME: octet-stream, the chain from 3.10; LXCA: the CAs into the trust store, the chain in
the multipart field "uploadedfile"), the versions of OME read and refused, and what is refused
before anything is asked of the device.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx  # noqa: E402
from acmelib.plugins.base import CertRequest, PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import dell_ome as O  # noqa: E402
from acmelib.plugins.targets import lenovo_lxca as L  # noqa: E402
from acmelib.certs import pki  # noqa: E402

OME_CFG = {'host': 'ome.test', 'user': 'svc-cert', 'password': 'pw', 'csr_country': 'CZ',
           'csr_state': 'Praha', 'csr_city': 'Praha', 'csr_org': 'Example s.r.o.',
           'csr_ou': 'IT', 'csr_email': 'admin@example.test'}
LX_CFG = {'host': 'lxca.test', 'user': 'svc-cert', 'password': 'pw', 'csr_country': 'CZ',
          'csr_state': 'Praha', 'csr_city': 'Praha', 'csr_org': 'Example s.r.o.'}
SESS = '/api/SessionService/Sessions'
SESS_ONE = "/api/SessionService/Sessions('a1b2-c3')"


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(kind, version, ctx, base, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, version)
    assert cls.module_version == version, (cls.module_version, version)
    t = cls(dict(base, **cfg), ctx)
    t.served_now = lambda *a: False
    return t


def a_csr(names, key_type='rsa-2048'):
    return pki.make_csr(pki.make_key(key_type), names)[0]


def creq(names=('ome.example.test', '10.0.0.20'), key_type='rsa-2048', **subj):
    return CertRequest(names=list(names), sans=list(names), key_type=key_type,
                       subject=dict({'CN': names[0]}, **subj), options={}, name='dev')


def calls(ctx):
    return [(c['method'], c['path']) for c in ctx.calls]


def bundle_without_key():
    b = FakeBundle()
    b.key_pem = None            # the device made the key: acme holds none
    return b


# ---------------------------------------------------------------------------------------------
def ome_routes(version='4.6.0', csr=None, info_status=200):
    return [
        ('POST', r'/api/SessionService/Sessions$', (201, {'Id': 'a1b2-c3'}, {
            'X-Auth-Token': 'TOK'})),
        ('GET', r'/api/ApplicationService/Info$', (info_status, {'Version': version})),
        ('POST', r'ApplicationService\.GenerateCSR$', (200, {
            'CertificateData': csr or a_csr(['ome.example.test'])})),
        ('POST', r'ApplicationService\.Upload(CertChain|Certificate)$', (200, b'')),
        ('DELETE', r"Sessions\('a1b2-c3'\)$", (204, b'')),
    ]


class OmeRegistered(unittest.TestCase):
    def test_versions_and_contract(self):
        reg = Registry(extra_dirs=[]).reload()
        vers = reg.versions_of('target', 'dell_ome')
        self.assertEqual(sorted(vers), ['', '3.0', '3.10'])
        self.assertIs(reg.get('target', 'dell_ome'), vers[''])
        for v in vers.values():
            d = v.describe()
            self.assertTrue(d['device_key'])
            self.assertEqual(d['device_key_types'], ['rsa-2048'])
            self.assertEqual(v.fields, vers[''].fields, 'saved settings fit every version')
        t = make('dell_ome', '', FakeCtx(), OME_CFG)
        self.assertEqual(t.served_places({}), [('ome.test', 443)])
        self.assertTrue(O.DellOmeTarget.served_wait)

    def test_guides_shipped(self):
        root = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
        for n in ('dell_ome', 'dell_ome@3.0', 'dell_ome@3.10', 'lenovo_lxca'):
            for lang in ('.md', '.cs.md'):
                with open(os.path.join(root, n + lang)) as f:
                    text = f.read()
                self.assertTrue(text.startswith('# '), n)
                self.assertIn('GenerateCSR' if n.startswith('dell') else
                              'certificateSigningRequest', text, n + lang)


class OmeCsr(unittest.TestCase):
    def test_generate_csr_exact(self):
        want = a_csr(['ome.example.test', '10.0.0.20'])
        ctx = FakeCtx(ome_routes(csr=want))
        got = make('dell_ome', '', ctx, OME_CFG).device_csr(creq())
        self.assertEqual(got, want)
        self.assertEqual(calls(ctx), [
            ('POST', SESS), ('GET', '/api/ApplicationService/Info'),
            ('POST', '/api/ApplicationService/Actions/ApplicationService.GenerateCSR'),
            ('DELETE', SESS_ONE)])
        self.assertEqual(ctx.json(ctx.calls[0]), {'UserName': 'svc-cert', 'Password': 'pw',
                                                  'SessionType': 'API'})
        self.assertNotIn('X-Auth-Token', ctx.calls[0]['headers'])
        gen = ctx.find('POST', r'GenerateCSR$')[0]
        self.assertEqual(gen['headers'].get('X-Auth-Token'), 'TOK')
        self.assertEqual(ctx.json(gen), {
            'DistinguishedName': 'ome.example.test', 'DepartmentName': 'IT',
            'BusinessName': 'Example s.r.o.', 'Locality': 'Praha', 'State': 'Praha',
            'Country': 'CZ', 'Email': 'admin@example.test',
            'San': 'ome.example.test,10.0.0.20'})
        self.assertEqual(ctx.find('DELETE', r'Sessions')[0]['headers'].get('X-Auth-Token'), 'TOK')

    def test_profile_subject_wins(self):
        ctx = FakeCtx(ome_routes())
        make('dell_ome', '', ctx, OME_CFG).device_csr(creq(O='Other a.s.', C='SK', OU='Ops'))
        body = ctx.json(ctx.find('POST', r'GenerateCSR$')[0])
        self.assertEqual((body['BusinessName'], body['Country'], body['DepartmentName']),
                         ('Other a.s.', 'SK', 'Ops'))

    def test_refused_before_anything_is_asked(self):
        ctx = FakeCtx(ome_routes())
        t = make('dell_ome', '', ctx, OME_CFG)
        for r, words in ((creq(names=('*.example.test',)), 'wildcard'),
                         (creq(names=('a.t', 'b.t', 'c.t', 'd.t', 'e.t')), 'at most 4'),
                         (creq(key_type='ec-256'), 'rsa-2048')):
            with self.assertRaises(PluginError) as e:
                t.device_csr(r)
            self.assertIn(words, str(e.exception))
            self.assertFalse(e.exception.retry)
        with self.assertRaises(PluginError) as e:
            make('dell_ome', '', ctx, OME_CFG, csr_email='').device_csr(creq())
        self.assertIn('E-mail', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_version_refused(self):
        ctx = FakeCtx(ome_routes(version='3.9.0'))
        with self.assertRaises(PluginError) as e:
            make('dell_ome', '3.10', ctx, OME_CFG).device_csr(creq())
        self.assertIn('runs OpenManage Enterprise 3.9.0', str(e.exception))
        self.assertIn('OpenManage Enterprise 3.0 - 3.9', str(e.exception))
        self.assertFalse(ctx.find('POST', r'GenerateCSR$'), 'nothing asked')
        self.assertTrue(ctx.find('DELETE', r'Sessions'), 'signed out all the same')
        ctx = FakeCtx(ome_routes(version='4.5.1'))
        with self.assertRaises(PluginError) as e:
            make('dell_ome', '3.0', ctx, OME_CFG).device_csr(creq())
        self.assertIn('3.10 - 4.x', str(e.exception))
        # the plain one takes any
        ctx = FakeCtx(ome_routes(version='3.5.0'))
        make('dell_ome', '', ctx, OME_CFG).device_csr(creq())
        self.assertTrue(ctx.find('POST', r'GenerateCSR$'))

    def test_no_csr_in_the_answer(self):
        routes = [('POST', r'GenerateCSR$', (200, {'Message': 'x'}))] + ome_routes()
        with self.assertRaises(PluginError) as e:
            make('dell_ome', '', FakeCtx(routes), OME_CFG).device_csr(creq())
        self.assertIn('without a CSR', str(e.exception))


class OmeDeploy(unittest.TestCase):
    def test_chain_uploaded_octet_stream(self):
        b = bundle_without_key()
        ctx = FakeCtx(ome_routes())
        words = make('dell_ome', '', ctx, OME_CFG).deploy(b, {})
        self.assertIn('OME 4.6.0', words)
        self.assertEqual(calls(ctx), [
            ('POST', SESS), ('GET', '/api/ApplicationService/Info'),
            ('POST', '/api/ApplicationService/Actions/ApplicationService.UploadCertChain'),
            ('DELETE', SESS_ONE)])
        up = ctx.calls[2]
        self.assertEqual(up['headers']['Content-Type'], 'application/octet-stream')
        self.assertEqual(up['headers']['Accept'], 'application/octet-stream')
        self.assertEqual(C.pem_blocks(up['body'].decode()),
                         C.pem_blocks(b.cert_pem) + C.pem_blocks(b.chain_pems[0]))
        self.assertNotIn(b'PRIVATE KEY', up['body'])

    def test_root_added_and_certificate_alone(self):
        b = bundle_without_key()
        root = FakeBundle('b').cert_pem
        ctx = FakeCtx(ome_routes(version='3.10.2'))
        make('dell_ome', '3.10', ctx, OME_CFG).deploy(b, {'root_pem': root})
        body = ctx.find('POST', r'UploadCertChain$')[0]['body'].decode()
        self.assertEqual(C.pem_blocks(body)[-1].strip(), C.pem_blocks(root)[0].strip())
        ctx = FakeCtx(ome_routes())
        make('dell_ome', '', ctx, OME_CFG).deploy(b, {'send_chain': False})
        up = ctx.find('POST', r'Upload')
        self.assertEqual(up[0]['path'],
                         '/api/ApplicationService/Actions/ApplicationService.UploadCertificate')
        self.assertEqual(C.pem_blocks(up[0]['body'].decode()), C.pem_blocks(b.cert_pem))

    def test_older_ome_certificate_alone(self):
        b = bundle_without_key()
        for ver, mv in (('3.8.3', ''), ('3.8.3', '3.0')):
            ctx = FakeCtx(ome_routes(version=ver))
            make('dell_ome', mv, ctx, OME_CFG).deploy(b, {'send_chain': True})
            self.assertEqual([c['path'] for c in ctx.find('POST', r'Upload')],
                             ['/api/ApplicationService/Actions/'
                              'ApplicationService.UploadCertificate'])

    def test_version_refused_before_upload(self):
        ctx = FakeCtx(ome_routes(version='4.0.0'))
        with self.assertRaises(PluginError):
            make('dell_ome', '3.0', ctx, OME_CFG).deploy(bundle_without_key(), {})
        self.assertFalse(ctx.find('POST', r'Upload'))

    def test_version_unreadable_goes_on(self):
        ctx = FakeCtx(ome_routes(info_status=404))
        make('dell_ome', '3.10', ctx, OME_CFG).deploy(bundle_without_key(), {})
        self.assertTrue(ctx.find('POST', r'UploadCertChain$'))
        self.assertTrue(any(l == 'warn' and 'cannot be read' in w for l, w in ctx.steps))

    def test_a_key_of_acme_refused(self):
        ctx = FakeCtx(ome_routes())
        with self.assertRaises(PluginError) as e:
            make('dell_ome', '', ctx, OME_CFG).deploy(FakeBundle(), {})
        self.assertIn('Key made by the device', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_the_test_changes_nothing(self):
        ctx = FakeCtx(ome_routes(version='4.6.0'))
        words = make('dell_ome', '3.0', ctx, OME_CFG).test()
        self.assertIn('OpenManage Enterprise 4.6.0', words)
        self.assertIn('NOT the version', words)
        self.assertEqual(calls(ctx), [('POST', SESS), ('GET', '/api/ApplicationService/Info'),
                                      ('DELETE', SESS_ONE)])


# ---------------------------------------------------------------------------------------------
def lx_routes(csr=None, trust=(200, {}), upload=None, csr_post=None):
    return [
        ('POST', r'/certificateSigningRequest$', csr_post or (200, {
            'response': [{'path': '1'}], 'result': 'success',
            'messages': [{'id': 'FQXHMSE0001I'}]})),
        ('GET', r'/certificateSigningRequest\?path=1$', (200, csr or a_csr(['lxca.example.test']),
                                                          {'Content-Type': 'text/plain'})),
        ('POST', r'/trustedCertificates$', trust),
        ('POST', r'/serverCertificate/tmp$', upload or (200, {
            'result': 'success', 'messages': [{'id': 'FQXHMSE0134I'}],
            'response': {'jobPath': '/serverCertificate/jobs/383'}})),
        ('GET', r'/serverCertificate$', (200, FakeBundle().cert_pem)),
    ]


class LxcaRegistered(unittest.TestCase):
    def test_contract(self):
        reg = Registry(extra_dirs=[]).reload()
        vers = reg.versions_of('target', 'lenovo_lxca')
        self.assertEqual(sorted(vers), [''])
        d = vers[''].describe()
        self.assertTrue(d['device_key'])
        self.assertEqual(d['device_key_types'], ['rsa-2048', 'rsa-3072'])
        t = make('lenovo_lxca', '', FakeCtx(), LX_CFG)
        self.assertEqual(t.served_places({}), [('lxca.test', 443)])


class LxcaCsr(unittest.TestCase):
    def test_csr_exact(self):
        want = a_csr(['lxca.example.test', '10.0.0.60'])
        ctx = FakeCtx(lx_routes(csr=want))
        got = make('lenovo_lxca', '', ctx, LX_CFG, csr_ou='IT').device_csr(
            creq(names=('lxca.example.test', '10.0.0.60')))
        self.assertEqual(got, want)
        self.assertEqual(calls(ctx), [('POST', '/certificateSigningRequest'),
                                      ('GET', '/certificateSigningRequest')])
        self.assertEqual(ctx.calls[1]['query'], {'path': ['1']})
        self.assertEqual(ctx.json(ctx.calls[0]), {
            'CommonName': 'lxca.example.test', 'Country': 'CZ', 'StateProvince': 'Praha',
            'StateLocality': 'Praha', 'Organization': 'Example s.r.o.',
            'OrganizationUnit': 'IT',
            'subjectAlternativeNames': {'generalNames': [
                {'type': 'dNSName', 'name': 'lxca.example.test'},
                {'type': 'iPAddress', 'name': '10.0.0.60'}]}})
        import base64
        self.assertEqual(ctx.calls[0]['headers']['Authorization'],
                         'Basic ' + base64.b64encode(b'svc-cert:pw').decode())

    def test_refused_before_anything_is_asked(self):
        ctx = FakeCtx(lx_routes())
        with self.assertRaises(PluginError) as e:
            make('lenovo_lxca', '', ctx, LX_CFG).device_csr(creq(key_type='ec-256'))
        self.assertIn('RSA keys only', str(e.exception))
        with self.assertRaises(PluginError) as e:
            make('lenovo_lxca', '', ctx, LX_CFG, csr_org='').device_csr(creq())
        self.assertIn('Organization', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_csr_failed_said(self):
        ctx = FakeCtx(lx_routes(csr_post=(200, {'result': 'failed', 'messages': [
            {'id': 'FQXHMSE0002J', 'text': 'bad'}]})))
        with self.assertRaises(PluginError) as e:
            make('lenovo_lxca', '', ctx, LX_CFG).device_csr(creq())
        self.assertIn('FQXHMSE0002J', str(e.exception))
        self.assertFalse(ctx.find('GET', r'certificateSigningRequest'))

    def test_csr_as_json(self):
        want = a_csr(['lxca.example.test'])
        routes = [('GET', r'/certificateSigningRequest\?path=1$', (200, {'csr': want}))] + \
            lx_routes()
        got = make('lenovo_lxca', '', FakeCtx(routes), LX_CFG).device_csr(
            creq(names=('lxca.example.test',)))
        self.assertEqual(got, want)


class LxcaDeploy(unittest.TestCase):
    def test_trust_then_upload_exact(self):
        b = bundle_without_key()          # its chain: the test CA, a root (self-signed)
        ctx = FakeCtx(lx_routes())
        words = make('lenovo_lxca', '', ctx, LX_CFG).deploy(b, {})
        self.assertIn('/serverCertificate/jobs/383', words)
        self.assertEqual(calls(ctx), [('POST', '/trustedCertificates'),
                                      ('POST', '/serverCertificate/tmp')])
        self.assertEqual(C.pem_blocks(ctx.json(ctx.calls[0])['certificate']),
                         C.pem_blocks(b.chain_pems[0]))
        up = ctx.calls[1]
        self.assertTrue(up['headers']['Content-Type'].startswith('multipart/form-data'))
        raw = up['body'].decode()
        self.assertIn('name="uploadedfile"; filename="cert_chain.pem"', raw)
        self.assertEqual(C.pem_blocks(raw), C.pem_blocks(b.cert_pem) +
                         C.pem_blocks(b.chain_pems[0]))
        self.assertNotIn('PRIVATE KEY', raw)

    def test_root_given_and_no_trust(self):
        b = bundle_without_key()
        b.chain_pems = []
        root = T.read(os.path.join(T.TMP, 'ca.crt'))
        ctx = FakeCtx(lx_routes())
        make('lenovo_lxca', '', ctx, LX_CFG).deploy(b, {'root_pem': root, 'trust_ca': False})
        self.assertEqual(calls(ctx), [('POST', '/serverCertificate/tmp')])
        self.assertEqual(C.pem_blocks(ctx.calls[0]['body'].decode()),
                         C.pem_blocks(b.cert_pem) + C.pem_blocks(root))

    def test_no_root_warned(self):
        b = bundle_without_key()
        b.chain_pems = []
        ctx = FakeCtx(lx_routes())
        make('lenovo_lxca', '', ctx, LX_CFG).deploy(b, {})
        self.assertTrue(any(l == 'warn' and 'root' in w for l, w in ctx.steps))
        self.assertEqual(calls(ctx), [('POST', '/serverCertificate/tmp')])

    def test_trust_already_there(self):
        ctx = FakeCtx(lx_routes(trust=(409, {'message': 'The certificate already exists'})))
        make('lenovo_lxca', '', ctx, LX_CFG).deploy(bundle_without_key(), {})
        self.assertTrue(ctx.find('POST', r'/serverCertificate/tmp$'))
        ctx = FakeCtx(lx_routes(trust=(403, {'message': 'forbidden'})))
        with self.assertRaises(PluginError):
            make('lenovo_lxca', '', ctx, LX_CFG).deploy(bundle_without_key(), {})
        self.assertFalse(ctx.find('POST', r'/serverCertificate/tmp$'))

    def test_upload_refused(self):
        ctx = FakeCtx(lx_routes(upload=(200, {'result': 'failed', 'messages': [
            {'id': 'FQXHMSE0135J', 'text': 'does not match the CSR'}]})))
        with self.assertRaises(PluginError) as e:
            make('lenovo_lxca', '', ctx, LX_CFG).deploy(bundle_without_key(), {})
        self.assertIn('did not take', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_a_key_of_acme_refused(self):
        ctx = FakeCtx(lx_routes())
        with self.assertRaises(PluginError) as e:
            make('lenovo_lxca', '', ctx, LX_CFG).deploy(FakeBundle(), {})
        self.assertIn('Key made by the device', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_the_test_reads_only(self):
        ctx = FakeCtx(lx_routes())
        words = make('lenovo_lxca', '', ctx, LX_CFG).test()
        self.assertIn('gave its server certificate', words)
        self.assertEqual(calls(ctx), [('GET', '/serverCertificate')])

    def test_served_now_ipv6(self):
        # 1.0.96: an IPv6 host asked as itself, not as "2001:db8::1:443"
        self.assertEqual(T.served_asked('lenovo_lxca', dict(LX_CFG)),
                         [('2001:db8::1', 8443)] * 2)


class OmeIpv6(unittest.TestCase):
    def test_served_now_ipv6(self):
        # 1.0.96: "2001:db8::1:8443" was read as a host without a port
        self.assertEqual(T.served_asked('dell_ome', OME_CFG), [('2001:db8::1', 8443)] * 2)


if __name__ == '__main__':
    unittest.main()
