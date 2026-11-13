#!/usr/bin/env python3
"""Lenovo XClarity Controller (target lenovo_xcc): the device makes the key.

    python3 test/test_targets_lenovo_xcc.py

Without a network and without a device - a fake Redfish (test_targets.FakeCtx) and the exact
calls checked: the CSR asked with CertificateService.GenerateCSR (the HTTPS collection, the
names, the subject, the key type of XCC3), the certificate imported with ReplaceCertificate
(CertificateType PEM, no key); the version xcc2 with no key type sent and Lenovo's OEM
security service where the standard GenerateCSR is missing; what is refused before anything
is asked of the XCC.
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
from acmelib.plugins.targets import lenovo_xcc as X  # noqa: E402
from acmelib.certs import pki  # noqa: E402

CFG = {'host': 'xcc.test', 'user': 'svccert', 'password': 'pw', 'csr_country': 'CZ',
       'csr_state': 'Praha', 'csr_city': 'Praha', 'csr_org': 'Example s.r.o.'}
COLL = '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates'
GEN = '/redfish/v1/CertificateService/Actions/CertificateService.GenerateCSR'
REP = '/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate'
OEM = '/redfish/v1/Managers/1/Oem/Lenovo/Security/Actions/LenovoSecurityService.'


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(version, ctx, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', 'lenovo_xcc', version)
    assert cls.module_version == version, (cls.module_version, version)
    t = cls(dict(CFG, **cfg), ctx)
    t.served_now = lambda *a: False
    return t


def a_csr(names, key_type='ec-256'):
    return pki.make_csr(pki.make_key(key_type), names)[0]


def routes(standard=True, csr_answer=None, extra=()):
    svc = {'@odata.id': '/redfish/v1/CertificateService'}
    if standard:
        svc['Actions'] = {'#CertificateService.GenerateCSR': {'target': GEN},
                          '#CertificateService.ReplaceCertificate': {'target': REP}}
    else:
        svc['Actions'] = {'#CertificateService.Other': {'target': '/x'}}
    return list(extra) + [
        ('GET', r'/redfish/v1/$', (200, {'RedfishVersion': '1.22.0', 'Vendor': 'Lenovo',
                                         'CertificateService': {
                                             '@odata.id': '/redfish/v1/CertificateService'},
                                         'Links': {'Sessions': {
                                             '@odata.id': '/redfish/v1/SessionService/Sessions'}}})),
        ('POST', r'/SessionService/Sessions$', (201, {}, {
            'X-Auth-Token': 'TOK', 'Location': '/redfish/v1/SessionService/Sessions/7'})),
        ('GET', r'/redfish/v1/Managers$', (200, {'Members': [
            {'@odata.id': '/redfish/v1/Managers/1'}]})),
        ('GET', r'/redfish/v1/Managers/1$', (200, {
            'Manufacturer': 'Lenovo', 'Model': 'Lenovo XClarity Controller 3',
            'FirmwareVersion': 'ESX3-1.20',
            'NetworkProtocol': {'@odata.id': '/redfish/v1/Managers/1/NetworkProtocol'}})),
        ('GET', r'/redfish/v1/CertificateService$', (200, svc)),
        ('POST', r'CertificateService\.GenerateCSR$', (200, {
            'CSRString': csr_answer or a_csr(['xcc01.example.test']),
            'CertificateCollection': {'@odata.id': COLL}})),
        ('GET', r'/HTTPS/Certificates$', (200, {'Members': [{'@odata.id': COLL + '/1'}]})),
        ('POST', r'CertificateService\.ReplaceCertificate$', (200, {})),
        ('POST', r'LenovoSecurityService\.', (200, {})),
        ('DELETE', r'/Sessions/7$', (204, b'')),
    ]


def methods(ctx):
    return [(c['method'], c['path']) for c in ctx.calls]


class Registered(unittest.TestCase):
    def test_versions_and_contract(self):
        reg = Registry(extra_dirs=[]).reload()
        vers = reg.versions_of('target', 'lenovo_xcc')
        self.assertEqual(sorted(vers), ['', 'xcc2'])
        self.assertIs(reg.get('target', 'lenovo_xcc'), vers[''])
        for v, kts in (('', ['ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096']),
                       ('xcc2', ['rsa-2048'])):
            d = vers[v].describe()
            self.assertTrue(d['device_key'])
            self.assertEqual(d['device_key_types'], kts)
            self.assertEqual(vers[v].fields, vers[''].fields, 'saved settings fit both')
        self.assertEqual(X.LenovoXccTarget.served_wait, (32, 30))
        t = make('', FakeCtx())
        self.assertEqual(t.served_places({}), [('xcc.test', 443)])

    def test_guides_shipped(self):
        root = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
        for n in ('lenovo_xcc.md', 'lenovo_xcc.cs.md', 'lenovo_xcc@xcc2.md',
                  'lenovo_xcc@xcc2.cs.md'):
            with open(os.path.join(root, n)) as f:
                text = f.read()
            self.assertIn('GenerateCSR', text, n)
            self.assertTrue(text.startswith('# '), n)


class Csr(unittest.TestCase):
    def req(self, names=('xcc01.example.test', '10.0.0.50'), key_type='ec-256', **subj):
        return CertRequest(names=list(names), sans=list(names), key_type=key_type,
                           subject=dict({'CN': names[0]}, **subj), options={}, name='xcc01')

    def test_xcc3_generate_csr(self):
        want = a_csr(['xcc01.example.test', '10.0.0.50'])
        ctx = FakeCtx(routes(csr_answer=want))
        got = make('', ctx).device_csr(self.req())
        self.assertEqual(got, want)
        self.assertEqual(methods(ctx), [
            ('GET', '/redfish/v1/'), ('POST', '/redfish/v1/SessionService/Sessions'),
            ('GET', '/redfish/v1/CertificateService'), ('GET', '/redfish/v1/Managers'),
            ('GET', '/redfish/v1/Managers/1'), ('POST', GEN),
            ('DELETE', '/redfish/v1/SessionService/Sessions/7')])
        self.assertEqual(ctx.json(ctx.calls[1]), {'UserName': 'svccert', 'Password': 'pw'})
        self.assertEqual(ctx.json(ctx.find('POST', r'GenerateCSR$')[0]), {
            'CertificateCollection': {'@odata.id': COLL},
            'CommonName': 'xcc01.example.test',
            'AlternativeNames': ['xcc01.example.test', '10.0.0.50'],
            'Country': 'CZ', 'State': 'Praha', 'City': 'Praha', 'Organization': 'Example s.r.o.',
            'KeyPairAlgorithm': 'TPM_ALG_ECDH', 'KeyCurveId': 'TPM_ECC_NIST_P256'})
        self.assertEqual(ctx.find('POST', r'GenerateCSR$')[0]['headers'].get('X-Auth-Token'),
                         'TOK')

    def test_rsa_and_the_profile_subject(self):
        ctx = FakeCtx(routes())
        make('', ctx, csr_ou='IT').device_csr(self.req(key_type='rsa-3072', O='Other a.s.',
                                                        C='SK'))
        body = ctx.json(ctx.find('POST', r'GenerateCSR$')[0])
        self.assertEqual((body['KeyPairAlgorithm'], body['KeyBitLength']), ('TPM_ALG_RSA', 3072))
        self.assertNotIn('KeyCurveId', body)
        self.assertEqual((body['Organization'], body['Country'], body['OrganizationalUnit']),
                         ('Other a.s.', 'SK', 'IT'))
        ctx = FakeCtx(routes())
        make('', ctx).device_csr(self.req(key_type='ec-384'))
        self.assertEqual(ctx.json(ctx.find('POST', r'GenerateCSR$')[0])['KeyCurveId'],
                         'TPM_ECC_NIST_P384')

    def test_refused_before_anything_is_asked(self):
        ctx = FakeCtx(routes())
        with self.assertRaises(PluginError) as e:
            make('', ctx, csr_city='').device_csr(self.req())
        self.assertIn('City', str(e.exception))
        with self.assertRaises(PluginError) as e:
            make('', ctx).device_csr(self.req(key_type='ed25519'))
        self.assertIn('cannot be asked', str(e.exception))
        with self.assertRaises(PluginError) as e:
            make('xcc2', ctx).device_csr(self.req(key_type='ec-256'))
        self.assertIn('rsa-2048', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_xcc2_no_key_type_sent(self):
        ctx = FakeCtx(routes())
        make('xcc2', ctx).device_csr(self.req(key_type='rsa-2048'))
        body = ctx.json(ctx.find('POST', r'GenerateCSR$')[0])
        self.assertNotIn('KeyPairAlgorithm', body)
        self.assertNotIn('KeyBitLength', body)

    def test_no_standard_generate_csr(self):
        ctx = FakeCtx(routes(standard=False))
        with self.assertRaises(PluginError) as e:
            make('', ctx).device_csr(self.req())
        self.assertIn('"xcc2"', str(e.exception))
        self.assertTrue(ctx.find('DELETE', r'/Sessions/7$'), 'signed out all the same')
        # the version xcc2: Lenovo's OEM security service, one host name only
        with self.assertRaises(PluginError) as e:
            make('xcc2', FakeCtx(routes(standard=False))).device_csr(self.req(key_type='rsa-2048'))
        self.assertIn('one host name', str(e.exception))
        want = a_csr(['xcc01.example.test'], 'rsa-2048')
        ctx = FakeCtx(routes(standard=False, extra=[
            ('POST', r'LenovoSecurityService\.DownloadCSR$', (200, {'CSRString': want}))]))
        got = make('xcc2', ctx, csr_ou='IT').device_csr(
            self.req(names=('xcc01.example.test',), key_type='rsa-2048'))
        self.assertEqual(got, want)
        gen, dl = ctx.find('POST', r'GenerateCSR$'), ctx.find('POST', r'DownloadCSR$')
        self.assertEqual(gen[0]['path'], OEM + 'GenerateCSR')
        self.assertEqual(ctx.json(gen[0]), {
            'Title': 'GenerateCSR', 'Target': OEM + 'GenerateCSR',
            'RequiredCertificateData': {'Service': 'Server', 'CountryName': 'CZ',
                                        'StateOrProvinceName': 'Praha', 'LocalityName': 'Praha',
                                        'OrganizationName': 'Example s.r.o.',
                                        'HostName': 'xcc01.example.test'},
            'OptionalCertificateData': {'OrganizationalUnitName': 'IT'}})
        self.assertEqual(ctx.json(dl[0]), {'Title': 'DownloadCSR', 'Service': 'Server',
                                           'Format': 'PEM'})

    def test_find_csr(self):
        pem = a_csr(['a.example.test'])
        self.assertEqual(X.find_csr({'x': {'CSRString': pem}}), pem)
        der = pki.csr_info(pem)['der']
        got = X.find_csr({'Data': list(der)})
        self.assertEqual(pki.csr_info(got)['der'], der)
        self.assertEqual(X.find_csr({'Message': 'nothing'}), '')


class Deploy(unittest.TestCase):
    def bundle(self):
        b = FakeBundle()
        b.key_pem = None            # the device made the key: acme holds none
        return b

    def test_replace_certificate_without_a_key(self):
        b = self.bundle()
        ctx = FakeCtx(routes())
        words = make('', ctx).deploy(b, {})
        self.assertIn('imported', words)
        self.assertEqual(methods(ctx), [
            ('GET', '/redfish/v1/'), ('POST', '/redfish/v1/SessionService/Sessions'),
            ('GET', '/redfish/v1/CertificateService'), ('GET', '/redfish/v1/Managers'),
            ('GET', '/redfish/v1/Managers/1'), ('GET', COLL), ('POST', REP),
            ('DELETE', '/redfish/v1/SessionService/Sessions/7')])
        body = ctx.json(ctx.find('POST', r'ReplaceCertificate$')[0])
        self.assertEqual(body, {'CertificateUri': {'@odata.id': COLL + '/1'},
                                'CertificateType': 'PEM',
                                'CertificateString': b.cert_pem.strip() + '\n'})
        self.assertNotIn('PRIVATE KEY', ctx.calls[-2]['body'].decode())
        self.assertTrue(any('15 minutes' in w for _l, w in ctx.steps))

    def test_with_the_chain(self):
        b = self.bundle()
        ctx = FakeCtx(routes())
        make('', ctx).deploy(b, {'send_chain': True,
                                 'certificate_uri': COLL + '/1'})
        body = ctx.json(ctx.find('POST', r'ReplaceCertificate$')[0])
        self.assertEqual(C.pem_blocks(body['CertificateString']),
                         C.pem_blocks(b.cert_pem) + C.pem_blocks(b.chain_pems[0]))
        self.assertFalse(ctx.find('GET', r'/HTTPS/Certificates$'), 'the URI given is used')

    def test_a_key_of_acme_refused(self):
        ctx = FakeCtx(routes())
        with self.assertRaises(PluginError) as e:
            make('', ctx).deploy(FakeBundle(), {})
        self.assertIn('Key made by the device', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_xcc2_oem_import(self):
        b = self.bundle()
        ctx = FakeCtx(routes(standard=False))
        make('xcc2', ctx).deploy(b, {})
        imp = ctx.find('POST', r'ImportCertificate$')
        self.assertEqual(imp[0]['path'], OEM + 'ImportCertificate')
        body = ctx.json(imp[0])
        self.assertEqual(body['SignedCertificates'], list(C.pem_to_der(b.cert_pem)))
        self.assertEqual({k: v for k, v in body.items() if k != 'SignedCertificates'},
                         {'Title': 'ImportCertificate', 'Service': 'Server',
                          'ImportCertificateType': 'CSR'})
        self.assertFalse(ctx.find('POST', r'ReplaceCertificate$'))

    def test_the_test_changes_nothing(self):
        ctx = FakeCtx(routes())
        words = make('', ctx).test()
        self.assertIn('Lenovo XClarity Controller 3', words)
        self.assertIn('GenerateCSR', words)
        self.assertEqual({m for m, _p in methods(ctx)} - {'GET', 'DELETE'}, {'POST'})
        self.assertEqual([p for m, p in methods(ctx) if m == 'POST'],
                         ['/redfish/v1/SessionService/Sessions'])


if __name__ == '__main__':
    unittest.main()
