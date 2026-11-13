#!/usr/bin/env python3
"""HPE devices that make the key themselves: Synergy Composer / OneView and its enclosures
(hpe_synergy), iLO 5/6/7 with its own key (hpe_ilo_devkey), Alletra 9000 / MP B10000
(hpe_alletra_mp).

    python3 test/test_targets_dk_hpe_fujitsu.py

Without a network and without a device - a fake OneView REST API and Redfish service
(test_targets.FakeCtx) and a fake array CLI (test_targets.FakeSsh), the exact calls and
commands checked: the CSR asked for exactly the certificate's names, the certificate imported
with no key, what is refused in words before anything is asked of the device.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh  # noqa: E402
from acmelib.plugins.base import CertRequest, PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.certs import pki  # noqa: E402

SUBJ = {'csr_country': 'CZ', 'csr_state': 'Praha', 'csr_city': 'Praha',
        'csr_org': 'Example s.r.o.'}


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(kind, ctx, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, '')
    t = cls(dict(cfg), ctx)
    t.served_now = lambda *a: False
    t._sleep = lambda s: None
    return t


def a_csr(names, key_type='rsa-2048'):
    return pki.make_csr(pki.make_key(key_type), names)[0]


def req(names, key_type='rsa-2048', options=None, **subj):
    return CertRequest(names=list(names), sans=list(names), key_type=key_type,
                       subject=dict({'CN': names[0]}, **subj), options=dict(options or {}),
                       name='x')


def keyless():
    b = FakeBundle()
    b.key_pem = None
    return b


def methods(ctx):
    return [(c['method'], c['url'].split('://', 1)[-1].split('/', 1)[-1]) for c in ctx.calls]


class Registered(unittest.TestCase):
    def test_contract_and_guides(self):
        reg = Registry(extra_dirs=[]).reload()
        root = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
        for kind, kts in (('hpe_synergy', ['rsa-2048', 'rsa-3072']),
                          ('hpe_ilo_devkey', ['rsa-2048', 'ec-384']),
                          ('hpe_alletra_mp', ['rsa-2048', 'rsa-3072', 'rsa-4096'])):
            self.assertEqual(sorted(reg.versions_of('target', kind)), [''])
            d = reg.get('target', kind).describe()
            self.assertTrue(d['device_key'], kind)
            self.assertEqual(d['device_key_types'], kts)
            for n in (kind + '.md', kind + '.cs.md'):
                with open(os.path.join(root, n)) as f:
                    txt = f.read()
                self.assertTrue(txt.startswith('# '), n)
                self.assertTrue('Key made by the device' in txt or 'Klíč vytváří zařízení' in txt
                                , n)


# ---------------------------------------------------------------------------
# HPE Synergy Composer / OneView
SY = dict(SUBJ, host='composer.test', user='svc-acme', password='pw')
ENC = '/rest/enclosures/0000A66101'


def sy_routes(csr=None, csr_task=False, extra=()):
    csr = csr or a_csr(['composer.example.test', '10.0.0.20'])
    post = (202, {'uri': '/rest/tasks/T1'}, {'Location': '/rest/tasks/T1'}) if csr_task else \
        (200, {'type': 'CertificateSigningRequestV2', 'base64Data': csr})
    return list(extra) + [
        ('GET', r'/rest/version$', (200, {'currentVersion': 9200})),
        ('POST', r'/rest/login-sessions$', (200, {'sessionID': 'SID'})),
        ('DELETE', r'/rest/login-sessions$', (204, b'')),
        ('POST', r'/rest/certificates/https/certificaterequest$', post),
        ('GET', r'/rest/certificates/https/certificaterequest$', (200, {'base64Data': csr})),
        ('PUT', r'/rest/certificates/https/certificaterequest$', (
            202, {}, {'Location': 'https://composer.test/rest/tasks/T2'})),
        ('GET', r'/rest/tasks/T\d$', (200, {'taskState': 'Completed'})),
        ('GET', r'/rest/certificates/ca/', (404, {})),
        ('POST', r'/rest/certificates/ca$', (202, {}, {'Location': '/rest/tasks/T3'})),
        ('GET', r'/rest/enclosures\?filter=', (200, {'members': [
            {'name': 'Frame1', 'uri': ENC, 'enclosureType': 'SY12000'}]})),
        ('POST', r'/https/certificaterequest\?bayNumber=1$', (
            202, {}, {'Location': '/rest/tasks/T4'})),
        ('GET', r'/https/certificaterequest\?bayNumber=1$', (200, {
            'base64Data': a_csr(['frame1-flm1.example.test'])})),
        ('PUT', r'/https/certificaterequest\?bayNumber=1$', (
            202, {}, {'Location': '/rest/tasks/T5'})),
        ('GET', r'/rest/certificates/https$', (200, {'commonName': 'composer.example.test',
                                                      'expiresOn': '2027-01-01'})),
        ('GET', r'/rest/enclosures\?start', (200, {'members': [{'name': 'Frame1'}]})),
    ]


class Synergy(unittest.TestCase):
    def test_appliance_csr(self):
        want = a_csr(['composer.example.test', '10.0.0.20'])
        ctx = FakeCtx(sy_routes(csr=want))
        got = make('hpe_synergy', ctx, **SY).device_csr(
            req(['composer.example.test', '10.0.0.20'], OU='IT'))
        self.assertEqual(got, want)
        self.assertEqual(methods(ctx), [
            ('GET', 'rest/version'), ('POST', 'rest/login-sessions'),
            ('POST', 'rest/certificates/https/certificaterequest'),
            ('DELETE', 'rest/login-sessions')])
        self.assertEqual(ctx.json(ctx.calls[1]), {
            'userName': 'svc-acme', 'password': 'pw', 'authLoginDomain': 'LOCAL',
            'loginMsgAck': True})
        post = ctx.find('POST', r'certificaterequest$')[0]
        self.assertEqual(ctx.json(post), {
            'type': 'CertificateSigningRequestV2', 'country': 'CZ', 'state': 'Praha',
            'locality': 'Praha', 'organization': 'Example s.r.o.', 'organizationalUnit': 'IT',
            'commonName': 'composer.example.test',
            'alternativeName': 'composer.example.test,10.0.0.20', 'cnsaCertRequested': False})
        self.assertEqual((post['headers'].get('Auth'), post['headers'].get('X-API-Version')),
                         ('SID', '9200'))

    def test_cnsa_and_a_task(self):
        ctx = FakeCtx(sy_routes(csr_task=True))
        got = make('hpe_synergy', ctx, **SY).device_csr(
            req(['composer.example.test'], key_type='rsa-3072'))
        self.assertIn('CERTIFICATE REQUEST', got)
        self.assertTrue(ctx.json(ctx.find('POST', r'certificaterequest$')[0])['cnsaCertRequested'])
        self.assertEqual([m for m in methods(ctx)][2:5], [
            ('POST', 'rest/certificates/https/certificaterequest'), ('GET', 'rest/tasks/T1'),
            ('GET', 'rest/certificates/https/certificaterequest')])

    def test_refused_before_anything(self):
        ctx = FakeCtx(sy_routes())
        t = make('hpe_synergy', ctx, **dict(SY, csr_city=''))
        with self.assertRaises(PluginError) as e:
            t.device_csr(req(['composer.example.test']))
        self.assertIn('locality', str(e.exception))
        t = make('hpe_synergy', ctx, **SY)
        with self.assertRaises(PluginError) as e:
            t.device_csr(req(['composer.example.test'], key_type='ec-256'))
        self.assertIn('RSA 2048', str(e.exception))
        with self.assertRaises(PluginError) as e:
            t.device_csr(req(['a.example.test', 'b.example.test'],
                             options={'part': 'enclosure', 'enclosure': 'Frame1'}))
        self.assertIn('one name', str(e.exception))
        with self.assertRaises(PluginError) as e:
            make('hpe_synergy', ctx, **dict(SY, csr_country='CZE')).device_csr(
                req(['composer.example.test']))
        self.assertIn('two letters', str(e.exception))
        # 1.0.96: an enclosure's CSR asks for no key size (the bay makes RSA 2048) - another
        # key type refused before signing in, not after the bay dropped its pending key
        with self.assertRaises(PluginError) as e:
            t.device_csr(req(['frame1-flm1.example.test'], key_type='rsa-3072',
                             options={'part': 'enclosure', 'enclosure': 'Frame1', 'bay': 1}))
        self.assertIn('RSA 2048 keys only', str(e.exception))
        # the bay: 1 or 2 (the Frame Link Module / Onboard Administrator), said so
        for bay in (-1, 3, 8):
            with self.assertRaises(PluginError) as e:
                t.device_csr(req(['frame1-flm1.example.test'],
                                 options={'part': 'enclosure', 'enclosure': 'Frame1',
                                          'bay': bay}))
            self.assertIn('1 or 2', str(e.exception))
        self.assertEqual(ctx.calls, [])

    def test_enclosure_cn_is_the_name(self):
        # 1.0.96: the enclosure's CSR has no SAN - its CN is the certificate's name, not the
        # profile's other CN (acme's check of the CSR would refuse it after the bay made its key)
        ctx = FakeCtx(sy_routes())
        make('hpe_synergy', ctx, **SY).device_csr(
            req(['frame1-flm1.example.test'], CN='Other Name',
                options={'part': 'enclosure', 'enclosure': 'Frame1', 'bay': 1}))
        posted = ctx.find('POST', r'certificaterequest\?bayNumber=1$')
        self.assertEqual(ctx.json(posted[0])['commonName'], 'frame1-flm1.example.test')

    def test_enclosure_csr_and_import(self):
        ctx = FakeCtx(sy_routes())
        opts = {'part': 'enclosure', 'enclosure': 'Frame1', 'bay': 1}
        got = make('hpe_synergy', ctx, **SY).device_csr(
            req(['frame1-flm1.example.test'], options=opts))
        self.assertIn('CERTIFICATE REQUEST', got)
        self.assertEqual(methods(ctx), [
            ('GET', 'rest/version'), ('POST', 'rest/login-sessions'),
            ('GET', 'rest/enclosures?filter=name%3D%27Frame1%27'),
            ('POST', 'rest/enclosures/0000A66101/https/certificaterequest?bayNumber=1'),
            ('GET', 'rest/tasks/T4'),
            ('GET', 'rest/enclosures/0000A66101/https/certificaterequest?bayNumber=1'),
            ('DELETE', 'rest/login-sessions')])
        self.assertEqual(ctx.json(ctx.find('POST', r'bayNumber=1$')[0]), {
            'type': 'CertificateDtoV2', 'country': 'CZ', 'state': 'Praha', 'locality': 'Praha',
            'organization': 'Example s.r.o.', 'commonName': 'frame1-flm1.example.test'})
        b = keyless()
        ctx = FakeCtx(sy_routes())
        make('hpe_synergy', ctx, **SY).deploy(b, dict(opts, enclosure=ENC))
        self.assertFalse(ctx.find('GET', r'filter='), 'the URI given is used')
        put = ctx.find('PUT', r'bayNumber=1$')
        self.assertEqual(ctx.json(put[0]), {'type': 'CertificateDataV2',
                                            'base64Data': C.pem_blocks(b.cert_pem)[0].strip()
                                            + '\n'})
        self.assertFalse(ctx.find('POST', r'/rest/certificates/ca$'), 'no trust store here')
        self.assertEqual(make('hpe_synergy', ctx, **SY).served_places(opts), [])

    def test_appliance_import(self):
        b = keyless()
        ctx = FakeCtx(sy_routes())
        words = make('hpe_synergy', ctx, **SY).deploy(b, {})
        self.assertIn('own key', words)
        seq = [x for x in methods(ctx) if x[0] != 'GET' or 'tasks' not in x[1]]
        self.assertEqual(seq[:3], [('GET', 'rest/version'), ('POST', 'rest/login-sessions'),
                                   ('GET', seq[2][1])])
        self.assertTrue(seq[2][1].startswith('rest/certificates/ca/acme-'))
        self.assertTrue(ctx.find('POST', r'/rest/certificates/ca$'))
        put = ctx.find('PUT', r'/rest/certificates/https/certificaterequest$')[0]
        body = ctx.json(put)
        self.assertEqual(body['type'], 'CertificateDataV2')
        self.assertNotIn('PRIVATE KEY', put['body'].decode())
        self.assertEqual(C.pem_blocks(body['base64Data']), C.pem_blocks(b.cert_pem)[:1])
        self.assertTrue(ctx.find('GET', r'/rest/tasks/T2$'))
        self.assertEqual(methods(ctx)[-1], ('DELETE', 'rest/login-sessions'))
        self.assertEqual(make('hpe_synergy', ctx, **SY).served_places({}),
                         [('composer.test', 443)])

    def test_a_key_of_acme_refused_and_the_test(self):
        ctx = FakeCtx(sy_routes())
        with self.assertRaises(PluginError) as e:
            make('hpe_synergy', ctx, **SY).deploy(FakeBundle(), {})
        self.assertIn('Key made by the device', str(e.exception))
        self.assertEqual(ctx.calls, [])
        words = make('hpe_synergy', ctx, **SY).test()
        self.assertIn('Frame1', words)
        self.assertEqual({m for m, _p in methods(ctx)}, {'GET', 'POST', 'DELETE'})
        self.assertEqual([p for m, p in methods(ctx) if m == 'POST'], ['rest/login-sessions'])

    def test_no_enclosure_said(self):
        ctx = FakeCtx(sy_routes(extra=[('GET', r'/rest/enclosures\?filter=', (200, {
            'members': []}))]))
        with self.assertRaises(PluginError) as e:
            make('hpe_synergy', ctx, **SY).device_csr(req(['f.example.test'], options={
                'part': 'enclosure', 'enclosure': 'Nope'}))
        self.assertIn('no enclosure named Nope', str(e.exception))
        self.assertFalse(ctx.find('POST', r'certificaterequest'))

    def test_bay_and_names_checked_at_the_save(self):
        # 1.0.96: bay 3 and an IP address as an enclosure's name were refused only at the
        # issue - the bay field has its min and max, the module says what it takes
        from acmelib.plugins.targets import hpe_synergy as M
        cls = M.HpeSynergyTarget
        bay = [f for f in cls.deploy_fields if f['key'] == 'bay'][0]
        self.assertEqual((bay.get('min'), bay.get('max')), (1, 2))
        enc = {'part': 'enclosure', 'enclosure': 'Frame1'}
        self.assertEqual(cls.device_key_problem(['10.0.0.5'], 'rsa-2048', {}), '')
        self.assertIn('is a host name', cls.device_key_problem(['10.0.0.5'], 'rsa-2048', enc))
        self.assertIn('one name', cls.device_key_problem(['a.test', 'b.test'], 'rsa-2048', enc))
        self.assertIn('RSA 2048 keys only', cls.device_key_problem(['a.test'], 'rsa-3072', enc))
        self.assertEqual(cls.device_key_problem(['a.test'], 'rsa-2048', enc), '')
        self.assertIn('DNS name', cls.describe()['device_key_names'])


# ---------------------------------------------------------------------------
# HPE iLO with its own key
ILO = dict(SUBJ, host='ilo.test', user='svc-cert', password='pw', csr_ou='IT')
HC = '/redfish/v1/Managers/1/SecurityService/HttpsCert/'
GEN = HC + 'Actions/HpeHttpsCert.GenerateCSR/'
IMP = HC + 'Actions/HpeHttpsCert.ImportCertificate/'


def ilo_routes(model='iLO 6', fw='iLO 6 v1.62', state='Production', key_type=None,
               csrs=None, extra=()):
    seq = list(csrs if csrs is not None else ['', a_csr(['ilo01.example.test'])])

    def hc(call):
        d = {'Actions': {'#HpeHttpsCert.GenerateCSR': {'target': GEN},
                         '#HpeHttpsCert.ImportCertificate': {'target': IMP}},
             'CertificateSigningRequest': seq.pop(0) if len(seq) > 1 else seq[0],
             'X509CertificateInformation': {'Subject': 'CN=ilo01', 'ValidNotAfter': '2027'}}
        if key_type:
            d['KeyType'] = key_type
        return 200, d
    return list(extra) + [
        ('GET', r'/redfish/v1/$', (200, {'RedfishVersion': '1.13.0', 'Links': {
            'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions/'}}})),
        ('POST', r'/SessionService/Sessions/$', (201, {}, {
            'X-Auth-Token': 'TOK', 'Location': '/redfish/v1/SessionService/Sessions/s1/'})),
        ('DELETE', r'/Sessions/s1/$', (200, {})),
        ('GET', r'/redfish/v1/Managers$', (200, {'Members': [
            {'@odata.id': '/redfish/v1/Managers/1/'}]})),
        ('GET', r'/redfish/v1/Managers/1/$', (200, {'Model': model, 'FirmwareVersion': fw})),
        ('GET', r'/SecurityService/$', (200, {'SecurityState': state, 'Links': {
            'HttpsCert': {'@odata.id': HC}}})),
        ('GET', r'/HttpsCert/$', hc),
        ('PATCH', r'/HttpsCert/$', (200, {})),
        ('POST', r'GenerateCSR/$', (200, {'error': {'@Message.ExtendedInfo': [
            {'MessageId': 'iLO.2.15.GeneratingCertificate'}]}})),
        ('POST', r'ImportCertificate/$', (200, {})),
    ]


class Ilo(unittest.TestCase):
    def test_csr_rsa_production(self):
        want = a_csr(['ilo01.example.test'])
        ctx = FakeCtx(ilo_routes(csrs=['', '', want]))
        got = make('hpe_ilo_devkey', ctx, **ILO).device_csr(req(['ilo01.example.test']))
        self.assertEqual(got.strip(), want.strip())
        self.assertEqual(methods(ctx), [
            ('GET', 'redfish/v1/'), ('POST', 'redfish/v1/SessionService/Sessions/'),
            ('GET', 'redfish/v1/Managers'), ('GET', 'redfish/v1/Managers/1/'),
            ('GET', 'redfish/v1/Managers/1/SecurityService/'), ('GET', HC[1:]),
            ('POST', GEN[1:]), ('GET', HC[1:]), ('GET', HC[1:]),
            ('DELETE', 'redfish/v1/SessionService/Sessions/s1/')])
        self.assertEqual(ctx.json(ctx.find('POST', r'GenerateCSR/$')[0]), {
            'OrgName': 'Example s.r.o.', 'OrgUnit': 'IT', 'Country': 'CZ', 'State': 'Praha',
            'City': 'Praha', 'CommonName': 'ilo01.example.test', 'IncludeIP': False})
        self.assertFalse(ctx.find('PATCH', r'.'), 'no KeyType: nothing patched')

    def test_old_csr_is_not_taken(self):
        old = a_csr(['ilo01.example.test'])
        new = a_csr(['ilo01.example.test'])
        ctx = FakeCtx(ilo_routes(csrs=[old, old, new]))
        got = make('hpe_ilo_devkey', ctx, **ILO).device_csr(req(['ilo01.example.test']))
        self.assertEqual(got.strip(), new.strip())
        ctx = FakeCtx(ilo_routes(csrs=[old]))
        with self.assertRaises(PluginError) as e:
            make('hpe_ilo_devkey', ctx, **dict(ILO, csr_wait=30)).device_csr(
                req(['ilo01.example.test']))
        self.assertIn('no new CSR', str(e.exception))
        self.assertTrue(ctx.find('DELETE', r'/Sessions/s1/$'), 'signed out all the same')

    def test_key_type_patched_and_ip(self):
        ctx = FakeCtx(ilo_routes(fw='iLO 6 v1.70', key_type='RSA'))
        make('hpe_ilo_devkey', ctx, **ILO).device_csr(
            req(['ilo01.example.test', '10.0.0.5'], key_type='ec-384'))
        self.assertEqual(ctx.json(ctx.find('PATCH', r'/HttpsCert/$')[0]), {'KeyType': 'ECDSA'})
        self.assertTrue(ctx.json(ctx.find('POST', r'GenerateCSR/$')[0])['IncludeIP'])
        # HighSecurity with no KeyType: ECDSA only
        ctx = FakeCtx(ilo_routes(state='HighSecurity'))
        with self.assertRaises(PluginError) as e:
            make('hpe_ilo_devkey', ctx, **ILO).device_csr(req(['ilo01.example.test']))
        self.assertIn('ec-384', str(e.exception))
        self.assertFalse(ctx.find('POST', r'GenerateCSR'))
        ctx = FakeCtx(ilo_routes(state='FIPS', model='iLO 5', fw='iLO 5 v2.10'))
        make('hpe_ilo_devkey', ctx, **ILO).device_csr(req(['ilo01.example.test'],
                                                          key_type='ec-384'))
        self.assertTrue(ctx.find('POST', r'GenerateCSR/$'))

    def test_refused(self):
        ctx = FakeCtx(ilo_routes())
        t = make('hpe_ilo_devkey', ctx, **ILO)
        for names, kt, words in ((['a.example.test', 'b.example.test'], 'rsa-2048', 'one host'),
                                 (['10.0.0.5'], 'rsa-2048', 'one host'),
                                 (['ilo01.example.test'], 'ec-256', 'cannot be asked')):
            with self.assertRaises(PluginError) as e:
                t.device_csr(req(names, key_type=kt))
            self.assertIn(words, str(e.exception))
        self.assertEqual(ctx.calls, [])
        ctx = FakeCtx(ilo_routes(model='iLO 4', fw='iLO 4 v2.80'))
        with self.assertRaises(PluginError) as e:
            make('hpe_ilo_devkey', ctx, **ILO).device_csr(req(['ilo01.example.test']))
        self.assertIn('iLO 4', str(e.exception))
        self.assertFalse(ctx.find('POST', r'GenerateCSR'))

    def test_import(self):
        b = keyless()
        ctx = FakeCtx(ilo_routes())
        words = make('hpe_ilo_devkey', ctx, **ILO).deploy(b, {})
        self.assertIn('resets', words)
        imp = ctx.find('POST', r'ImportCertificate/$')[0]
        self.assertEqual(ctx.json(imp), {'Certificate': C.pem_blocks(b.cert_pem)[0].strip()
                                         + '\n'})
        self.assertFalse(ctx.find('DELETE', r'.'), 'the session is gone with the reset')
        with self.assertRaises(PluginError) as e:
            make('hpe_ilo_devkey', FakeCtx([]), **ILO).deploy(FakeBundle(), {})
        self.assertIn('Key made by the device', str(e.exception))

    def test_the_test(self):
        ctx = FakeCtx(ilo_routes(key_type='ECDSA', fw='iLO 7 v1.20', model='iLO 7'))
        words = make('hpe_ilo_devkey', ctx, **ILO).test()
        self.assertIn('iLO 7', words)
        self.assertIn('key type ECDSA', words)
        self.assertEqual([m for m, _p in methods(ctx) if m not in ('GET', 'DELETE')], ['POST'])


# ---------------------------------------------------------------------------
# HPE Alletra 9000 / MP B10000
AL = dict(SUBJ, host='alletra.test', user='svc-cert', auth='password', password='pw',
          csr_ou='IT')


class Alletra(unittest.TestCase):
    def test_csr(self):
        want = a_csr(['alletra01.example.test', '10.0.0.60'])
        ssh = FakeSsh([(r'^createcert ', (0, 'Generating CSR...\n' + want + '\n', ''))])
        got = make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL).device_csr(
            req(['alletra01.example.test', '10.0.0.60']))
        self.assertEqual(got.strip(), want.strip())
        self.assertEqual(ssh.runs, [(
            'createcert unified-server -csr -keysize 2048 -C "CZ" -ST "Praha" -L "Praha" '
            '-O "Example s.r.o." -OU "IT" -CN "alletra01.example.test" '
            '-SAN "DNS:alletra01.example.test,IP:10.0.0.60"', None)])
        self.assertEqual(ssh.conns[0]['host'], 'alletra.test')

    def test_csr_refused_and_errors(self):
        ssh = FakeSsh()
        t = make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL)
        with self.assertRaises(PluginError) as e:
            t.device_csr(req(['a.example.test'], key_type='ec-256'))
        self.assertIn('RSA', str(e.exception))
        with self.assertRaises(PluginError) as e:
            t.device_csr(req(['a.example.test'], O='Bad "quote"'))
        self.assertIn('cannot be given', str(e.exception))
        with self.assertRaises(PluginError):
            make('hpe_alletra_mp', FakeCtx(ssh=ssh), **dict(AL, csr_org='')).device_csr(
                req(['a.example.test']))
        self.assertEqual(ssh.runs, [])
        ssh = FakeSsh([(r'^createcert ', (1, '', 'Error: invalid option -SAN\n'))])
        with self.assertRaises(PluginError) as e:
            make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL).device_csr(
                req(['a.example.test'], key_type='rsa-4096'))
        self.assertIn('invalid option', str(e.exception))
        self.assertIn('-keysize 4096', ssh.runs[0][0])
        ssh = FakeSsh([(r'^createcert ', (0, 'done\n', ''))])
        with self.assertRaises(PluginError) as e:
            make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL).device_csr(req(['a.example.test']))
        self.assertIn('no CSR', str(e.exception))

    def test_import(self):
        b = keyless()
        ssh = FakeSsh()
        words = make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL).deploy(b, {})
        self.assertIn('own key', words)
        # 1.0.96: one order in both - the options before the file (-f was after "stdin")
        self.assertEqual([c for c, _i in ssh.runs], ['importcert unified-server -f -ca stdin',
                                                     'importcert unified-server -f stdin'])
        self.assertEqual(C.pem_blocks(ssh.runs[0][1]), C.pem_blocks(''.join(b.chain_pems)))
        self.assertEqual(C.pem_blocks(ssh.runs[1][1]), C.pem_blocks(b.cert_pem)[:1])
        self.assertNotIn('PRIVATE', ''.join(i for _c, i in ssh.runs))
        ssh = FakeSsh()
        make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL).deploy(keyless(),
                                                               {'import_chain': False})
        self.assertEqual([c for c, _i in ssh.runs], ['importcert unified-server -f stdin'])
        ssh = FakeSsh()
        with self.assertRaises(PluginError) as e:
            make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL).deploy(FakeBundle(), {})
        self.assertIn('Key made by the device', str(e.exception))
        self.assertEqual(ssh.runs, [])
        ssh = FakeSsh([(r'-f stdin', (0, 'Error: certificate does not match the key\n', ''))])
        with self.assertRaises(PluginError) as e:
            make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL).deploy(keyless(), {})
        self.assertIn('does not match', str(e.exception))

    def test_the_test(self):
        ssh = FakeSsh([(r'^showversion', (0, 'Release version 10.4.2\nPatches: None\n', '')),
                       (r'^showcert', (0, 'Service        Type Issuer\nunified-server cert '
                                          'CA1\n', ''))])
        t = make('hpe_alletra_mp', FakeCtx(ssh=ssh), **AL)
        words = t.test()
        self.assertIn('10.4.2', words)
        self.assertEqual([c for c, _i in ssh.runs],
                         ['showversion', 'showcert -service unified-server'])
        self.assertEqual(t.served_places({}), [('alletra.test', 443)])


if __name__ == '__main__':
    unittest.main()
