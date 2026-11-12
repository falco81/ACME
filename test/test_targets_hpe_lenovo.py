#!/usr/bin/env python3
"""The HPE and Lenovo targets (1.0.95), without a network and without a device.

    python3 test/test_targets_hpe_lenovo.py

  redfish@ilo     HPE iLO 5 (2.78+) / 6 (1.30+) / 7: HpeHttpsCert.ImportCertificate with
                  the key, KeyType matched first, other controllers and firmware refused
  hpe_oneview     HPE OneView 9.x - 11.x, Synergy Composer: CA into the trust store,
                  PKCS#12 PUT /rest/certificates/https/pkcs12, the task waited for
  hpe_nimble      HPE Alletra 5000/6000, Nimble (NimbleOS): token, import, use

Lenovo XClarity Controller (XCC/XCC2/XCC3) and XClarity Administrator take no key of
acme's (only a certificate for their own CSR) - no module, nothing to test.

The fake Context and certificates are those of test_targets.py; an RSA certificate is
made here beside its EC ones.
"""
import base64
import email.parser
import email.policy
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import redfish_ilo as ILO  # noqa: E402


def setUpModule():
    T.setUpModule()
    j = lambda n: os.path.join(T.TMP, n)  # noqa: E731
    T.openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', j('r.key'), '-out', j('r.csr'),
              '-subj', '/CN=www.example.test')
    T.openssl('x509', '-req', '-in', j('r.csr'), '-CA', j('ca.crt'), '-CAkey', j('ca.key'),
              '-CAcreateserial', '-days', '10', '-out', j('r.crt'), '-extfile', j('ext'))
    T.CERTS['r'] = (j('r.crt'), j('r.key'))


def tearDownModule():
    T.tearDownModule()


def make(kind, version, ctx, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', kind, version)
    assert cls.module_version == version, (kind, cls.module_version, version)
    t = cls(cfg, ctx)
    t.served_now = lambda *a: False
    t._sleep = lambda s: None
    return t


def methods(ctx):
    return [(c['method'], c['path']) for c in ctx.calls]


# ---------------------------------------------------------------------------
# HPE iLO: the redfish version "ilo"
# ---------------------------------------------------------------------------
def ilo_routes(fw='iLO 6 v1.62', state='Production', keytype='RSA', extra=(), model=None,
               target=None):
    hc = {'@odata.id': '/redfish/v1/Managers/1/SecurityService/HttpsCert/',
          'X509CertificateInformation': {'Subject': 'CN=ilo', 'ValidNotAfter': '2027-01-01'},
          'Actions': {'#HpeHttpsCert.GenerateCSR': {'target': '/x'}}}
    if target:
        hc['Actions']['#HpeHttpsCert.ImportCertificate'] = {'target': target}
    if keytype is not None:
        hc['KeyType'] = keytype
    return list(extra) + [
        ('GET', r'/redfish/v1/$', (200, {'RedfishVersion': '1.20.0', 'Links': {'Sessions': {
            '@odata.id': '/redfish/v1/SessionService/Sessions/'}}})),
        ('POST', r'/SessionService/Sessions/$', (201, {}, {
            'X-Auth-Token': 'TOK', 'Location': '/redfish/v1/SessionService/Sessions/abc/'})),
        ('GET', r'/redfish/v1/Managers$', (200, {'Members': [
            {'@odata.id': '/redfish/v1/Managers/1/'}]})),
        ('GET', r'/redfish/v1/Managers/1/$', (200, {
            'FirmwareVersion': fw, 'Model': model or fw.split(' v')[0]})),
        ('GET', r'/Managers/1/SecurityService/$', (200, {
            'SecurityState': state, 'Links': {'HttpsCert': {
                '@odata.id': '/redfish/v1/Managers/1/SecurityService/HttpsCert/'}}})),
        ('GET', r'/SecurityService/HttpsCert/$', (200, hc)),
        ('PATCH', r'/SecurityService/HttpsCert/$', (200, {})),
        ('POST', r'HpeHttpsCert\.ImportCertificate', (200, {'error': {'@Message.ExtendedInfo': [
            {'MessageId': 'iLO.2.15.ImportCertSuccessfuliLOResetinProgress'}]}})),
        ('DELETE', r'/Sessions/', (200, {})),
    ]


ILO_CFG = {'host': 'ilo.test', 'user': 'acme', 'password': 'pw'}


class IloRegisteredTest(unittest.TestCase):
    def test_a_version_of_redfish(self):
        reg = Registry(extra_dirs=[]).reload()
        vers = reg.versions_of('target', 'redfish')
        self.assertIn('ilo', vers)
        self.assertIs(reg.get('target', 'redfish'), vers[''], 'the plain one stays the default')
        c = vers['ilo']
        self.assertEqual(c.version_label, 'HPE iLO 5 (2.78+), iLO 6 (1.30+), iLO 7')
        self.assertIn(c.version_label, c.description)
        self.assertEqual(c.fields, vers[''].fields, 'saved settings fit both')
        self.assertEqual([f['key'] for f in c.deploy_fields], ['verify', 'verify_sni'])
        self.assertEqual(c.served_wait({}), (20, 15))

    def test_versions_read(self):
        self.assertEqual(ILO.ilo_version('iLO 5 v2.78'), (5, (2, 78)))
        self.assertEqual(ILO.ilo_version('iLO 7 v1.12.00'), (7, (1, 12)))
        self.assertEqual(ILO.ilo_version('', 'iLO 6'), (6, None))
        self.assertIsNone(ILO.ilo_version('7.10.70.00', 'Integrated Dell Remote Access Controller'))

    def test_key_family(self):
        self.assertEqual(ILO.key_family(FakeBundle()), 'ECDSA')
        self.assertEqual(ILO.key_family(FakeBundle('r')), 'RSA')


class IloDeployTest(unittest.TestCase):
    def deploy(self, bundle, **kw):
        ctx = FakeCtx(ilo_routes(**kw))
        words = make('redfish', 'ilo', ctx, **ILO_CFG).deploy(bundle, {})
        return ctx, words

    def imported(self, ctx):
        posts = ctx.find('POST', r'HpeHttpsCert\.ImportCertificate')
        self.assertEqual(len(posts), 1)
        return posts[0]

    def test_ilo6_ec_key_type_patched_first(self):
        b = FakeBundle()
        ctx, words = self.deploy(b, fw='iLO 6 v1.73', state='HighSecurity', keytype='RSA')
        self.assertEqual(ctx.json(ctx.find('POST', r'/Sessions/$')[0]),
                         {'UserName': 'acme', 'Password': 'pw'})
        self.assertEqual([ctx.json(c) for c in ctx.find('PATCH', 'HttpsCert')],
                         [{'KeyType': 'ECDSA'}])
        imp = self.imported(ctx)
        self.assertEqual(imp['path'], '/redfish/v1/Managers/1/SecurityService/HttpsCert/'
                                      'Actions/HpeHttpsCert.ImportCertificate')
        self.assertEqual(imp['headers']['X-Auth-Token'], 'TOK')
        self.assertEqual(ctx.json(imp), {'Certificate': b.cert_pem.strip() + '\n' +
                                         b.key_pem.strip() + '\n'})
        order = [m for m, p in methods(ctx) if m in ('PATCH', 'POST')]
        self.assertEqual(order, ['POST', 'PATCH', 'POST'], 'sign in, key type, import')
        self.assertFalse(ctx.find('DELETE', 'Sessions'), 'the session is gone with the reset')
        self.assertIn('resets', words)

    def test_ilo7_rsa_in_secure_standard_no_patch(self):
        ctx, words = self.deploy(FakeBundle('r'), fw='iLO 7 v1.12.00', state='SecureStandard',
                                 keytype='RSA')
        self.assertFalse(ctx.find('PATCH', ''))
        self.imported(ctx)

    def test_ilo5_has_no_key_type(self):
        ctx, words = self.deploy(FakeBundle('r'), fw='iLO 5 v2.78', state='HighSecurity',
                                 keytype=None)
        self.assertFalse(ctx.find('PATCH', ''))
        self.imported(ctx)

    def test_action_target_from_the_resource(self):
        ctx, words = self.deploy(FakeBundle(), fw='iLO 6 v1.62', keytype='ECDSA',
                                 target='/redfish/v1/Managers/1/SecurityService/HttpsCert/'
                                        'Actions/Oem/HpeHttpsCert.ImportCertificate/')
        self.assertIn('/Oem/', self.imported(ctx)['path'])

    def test_newer_than_checked_warned(self):
        ctx, words = self.deploy(FakeBundle(), fw='iLO 7 v1.40.00', state='SecureStandard')
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'newer' in w])
        self.imported(ctx)

    def refused(self, bundle, words, **kw):
        ctx = FakeCtx(ilo_routes(**kw))
        with self.assertRaises(PluginError) as e:
            make('redfish', 'ilo', ctx, **ILO_CFG).deploy(bundle, {})
        self.assertFalse(e.exception.retry)
        self.assertIn(words, str(e.exception))
        self.assertFalse([m for m, p in methods(ctx) if m in ('PATCH', 'PUT')] +
                         [p for m, p in methods(ctx) if 'ImportCertificate' in p],
                         'nothing changed')
        return ctx

    def test_refused_before_any_change(self):
        self.refused(FakeBundle(), 'firmware 2.72 - it takes a private key from 2.78',
                     fw='iLO 5 v2.72')
        self.refused(FakeBundle(), 'firmware 1.20 - it takes a private key from 1.30',
                     fw='iLO 6 v1.20')
        self.refused(FakeBundle(), 'this is an iLO 4', fw='iLO 4 v2.82')
        self.refused(FakeBundle(), 'is not an HPE iLO', fw='7.10.70.00',
                     model='Integrated Dell Remote Access Controller')
        self.refused(FakeBundle('r'), 'security state HighSecurity - it takes an RSA key only '
                                      'in Production', fw='iLO 6 v1.62', state='HighSecurity')
        self.refused(FakeBundle('r'), 'only in SecureStandard', fw='iLO 7 v1.12.00',
                     state='FIPS')

    def test_try(self):
        ctx = FakeCtx(ilo_routes(fw='iLO 6 v1.62'))
        words = make('redfish', 'ilo', ctx, **ILO_CFG).test()
        self.assertIn('iLO 6 firmware 1.62', words)
        self.assertIn('security state Production', words)
        self.assertEqual({m for m, p in methods(ctx)}, {'GET', 'POST', 'DELETE'})
        self.assertEqual(len(ctx.find('POST', '')), 1, 'only the sign-in')

    def test_unchanged_when_served(self):
        ctx = FakeCtx(ilo_routes())
        t = make('redfish', 'ilo', ctx, **ILO_CFG)
        t.served_now = lambda b: True
        self.assertTrue(t.deploy(FakeBundle(), {}).startswith('unchanged'))
        self.assertEqual(ctx.calls, [])


class RedfishPlainMessageTest(unittest.TestCase):
    """The plain module's words where ReplaceCertificate is missing (1.0.95: iLO 6 does take
    a key - through HpeHttpsCert, the version "ilo")."""
    def test_points_to_the_ilo_version(self):
        from test_targets_more import RedfishTest
        ctx = FakeCtx([('GET', r'/redfish/v1/CertificateService$', (200, {'Actions': {
            '#CertificateService.GenerateCSR': {'target': '/x'}}}))] + RedfishTest.routes(None))
        t = make('redfish', '', ctx, host='bmc.test', user='u', password='p')
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {})
        self.assertIn('no CertificateService.ReplaceCertificate', str(e.exception))
        self.assertIn('module version for HPE iLO', str(e.exception))
        self.assertNotIn('only for a request it made itself', str(e.exception))


# ---------------------------------------------------------------------------
# HPE OneView / Synergy Composer
# ---------------------------------------------------------------------------
def ov_routes(current=9200, task_states=('Running', 'Completed'), ca_there=False, extra=()):
    states = list(task_states)

    def task(call):
        st = states.pop(0) if len(states) > 1 else states[0]
        if st == 401:
            return (401, {'message': 'session expired'})
        return (200, {'taskState': st, 'taskErrors': [{'message': 'bad pfx'}]
                      if st == 'Error' else []})
    return list(extra) + [
        ('GET', r'/rest/version$', (200, {'currentVersion': current, 'minimumVersion': 120})),
        ('POST', r'/rest/login-sessions$', (200, {'sessionID': 'SID'})),
        ('DELETE', r'/rest/login-sessions$', (204, b'')),
        ('GET', r'/rest/certificates/ca/acme-', (200, {}) if ca_there else (404, {})),
        ('POST', r'/rest/certificates/ca$', (202, {}, {'Location': 'https://ov.test/rest/tasks/7'})),
        ('PUT', r'/rest/certificates/https/pkcs12', (202, {'uri': '/rest/tasks/9'})),
        ('GET', r'/rest/tasks/7$', (200, {'taskState': 'Completed'})),
        ('GET', r'/rest/tasks/9$', task),
        ('GET', r'/rest/certificates/https$', (200, {'commonName': 'ov.test',
                                                     'expiresOn': '2027-01-01'})),
    ]


OV_CFG = {'host': 'ov.test', 'user': 'svc-acme', 'password': 'pw'}


def parts_of(call):
    ctype = call['headers'].get('Content-Type')
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b'Content-Type: ' + ctype.encode() + b'\r\n\r\n' + call['body'])
    return {p.get_param('name', header='content-disposition'):
            (p.get_filename(), p.get_payload(decode=True)) for p in msg.iter_parts()}


class OneViewTest(unittest.TestCase):
    def test_registered(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(sorted(reg.versions_of('target', 'hpe_oneview')), [''])
        c = reg.get('target', 'hpe_oneview')
        self.assertEqual((c.vendor, c.version_label), ('HPE', 'any version (detects it)'))
        self.assertIn('Synergy', c.title)

    def test_deploy(self):
        b = FakeBundle('r')
        ctx = FakeCtx(ov_routes())
        words = make('hpe_oneview', '', ctx, **OV_CFG).deploy(b, {})
        self.assertEqual(ctx.calls[0]['path'], '/rest/version')
        self.assertNotIn('Auth', ctx.calls[0]['headers'])
        login = ctx.find('POST', 'login-sessions')[0]
        self.assertEqual(ctx.json(login), {'userName': 'svc-acme', 'password': 'pw',
                                           'authLoginDomain': 'LOCAL', 'loginMsgAck': True})
        for c in ctx.calls[1:]:
            self.assertEqual(c['headers']['X-API-Version'], '9200')
        for c in ctx.calls[2:]:
            self.assertEqual(c['headers']['Auth'], 'SID')
        alias = 'acme-%s' % C.chain_id(b.chain_pems[0])
        ca = ctx.json(ctx.find('POST', r'/rest/certificates/ca$')[0])
        self.assertEqual(ca, {'type': 'CertificateAuthorityInfoCollection', 'members': [{
            'type': 'CertificateAuthorityInfo', 'certificateDetails': {
                'type': 'CertificateDetailV2', 'aliasName': alias,
                'base64Data': C.chain_list(b)[0]}}]})
        put = ctx.find('PUT', 'pkcs12')[0]
        self.assertEqual(put['query'], {'uploadfilename': ['acme.pfx']})
        self.assertEqual(put['headers']['uploadfilename'], 'acme.pfx')
        pw = put['headers']['Password']
        self.assertTrue(len(pw) >= 16)
        fn, pfx = parts_of(put)['file']
        self.assertEqual(fn, 'acme.pfx')
        got = subprocess.run(['openssl', 'pkcs12', '-nokeys', '-passin', 'pass:' + pw],
                             input=pfx, capture_output=True, check=True).stdout.decode()
        self.assertIn(b.cert_pem.split('\n')[1], got, 'the PKCS#12 opens with its password')
        self.assertEqual(len(ctx.find('GET', r'/rest/tasks/9$')), 2, 'waited for the task')
        self.assertEqual(ctx.calls[-1]['method'], 'DELETE', 'signed out')
        self.assertIn('imported the appliance certificate', words)
        self.assertIn('CA', words)
        order = [m + ' ' + c for m, c in methods(ctx) if m != 'GET']
        self.assertLess(order.index('POST /rest/certificates/ca'),
                        order.index('PUT /rest/certificates/https/pkcs12'), 'CA first')

    def test_api_version(self):
        ctx = FakeCtx(ov_routes(current=8000))
        make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertEqual(ctx.find('PUT', 'pkcs12')[0]['headers']['X-API-Version'], '8000')
        ctx = FakeCtx(ov_routes(current=9800))
        make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertEqual(ctx.find('PUT', 'pkcs12')[0]['headers']['X-API-Version'], '9200')
        ctx = FakeCtx(ov_routes(current=4200))
        make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'older' in w])
        ctx = FakeCtx(ov_routes())
        make('hpe_oneview', '', ctx, api_version=7600, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertFalse(ctx.find('GET', r'/rest/version$'))
        self.assertEqual(ctx.find('PUT', 'pkcs12')[0]['headers']['X-API-Version'], '7600')

    def test_ca_there_and_chain_off(self):
        ctx = FakeCtx(ov_routes(ca_there=True))
        make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertFalse(ctx.find('POST', r'/rest/certificates/ca$'))
        ctx = FakeCtx(ov_routes())
        make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {'import_chain': False})
        self.assertFalse(ctx.find('GET', r'/rest/certificates/ca/'))
        self.assertFalse(ctx.find('POST', r'/rest/certificates/ca$'))

    def test_task_failed(self):
        ctx = FakeCtx(ov_routes(task_states=('Error',)))
        with self.assertRaises(PluginError) as e:
            make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertIn('ended Error - bad pfx', str(e.exception))
        self.assertEqual(ctx.calls[-1]['method'], 'DELETE', 'signed out all the same')

    def test_session_cut_by_the_import(self):
        ctx = FakeCtx(ov_routes(task_states=(401, 'Completed')))
        make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertEqual(len(ctx.find('POST', 'login-sessions')), 2, 'signed in again')

    def test_task_end_not_read(self):
        ctx = FakeCtx(ov_routes(task_states=('Running',)))
        t = make('hpe_oneview', '', ctx, **OV_CFG)
        words = t.deploy(FakeBundle('r'), {'task_wait': 0})
        self.assertIn('imported', words)
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'could not be read' in w])

    def test_ecdsa_refused_before_anything(self):
        ctx = FakeCtx(ov_routes())
        with self.assertRaises(PluginError) as e:
            make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle(), {})
        self.assertIn('only an RSA certificate', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertEqual(ctx.calls, [])

    def test_wrong_password(self):
        ctx = FakeCtx([('POST', r'/rest/login-sessions$', (401, {'message': 'bad'}))] +
                      ov_routes())
        with self.assertRaises(PluginError) as e:
            make('hpe_oneview', '', ctx, **OV_CFG).deploy(FakeBundle('r'), {})
        self.assertFalse(e.exception.retry)
        self.assertFalse(ctx.find('PUT', ''))

    def test_try(self):
        ctx = FakeCtx(ov_routes())
        words = make('hpe_oneview', '', ctx, **OV_CFG).test()
        self.assertIn('API 9200', words)
        self.assertIn('ov.test', words)
        self.assertEqual({m for m, p in methods(ctx)}, {'GET', 'POST', 'DELETE'})

    def test_served(self):
        t = make('hpe_oneview', '', FakeCtx(), **OV_CFG)
        self.assertEqual(t.served_places({}), [('ov.test', 443)])
        self.assertEqual(t.served_wait({}), (12, 10))


# ---------------------------------------------------------------------------
# HPE Alletra 5000/6000, Nimble (NimbleOS)
# ---------------------------------------------------------------------------
def ns_routes(extra=()):
    return list(extra) + [
        ('POST', r':5392/v1/tokens$', (201, {'data': {'session_token': 'NST', 'id': 'tok1'}})),
        ('DELETE', r':5392/v1/tokens/tok1$', (200, {})),
        ('GET', r':5392/v1/certificates/detail$', (200, {'data': [
            {'name': 'default'}, {'name': 'custom'}]})),
        ('POST', r':5392/v1/certificates/actions/import$', (200, {'data': {}})),
        ('POST', r':5392/v1/certificates/actions/use$', (200, {'data': {
            'reload_https': True, 'reload_apis': True}})),
    ]


NS_CFG = {'host': 'nimble.test', 'user': 'svc-acme', 'password': 'pw'}


class NimbleTest(unittest.TestCase):
    def test_registered(self):
        reg = Registry(extra_dirs=[]).reload()
        self.assertEqual(sorted(reg.versions_of('target', 'hpe_nimble')), [''])

    def test_deploy(self):
        b = FakeBundle('r')
        ctx = FakeCtx(ns_routes())
        words = make('hpe_nimble', '', ctx, **NS_CFG).deploy(b, {})
        self.assertEqual(methods(ctx), [('POST', '/v1/tokens'),
                                        ('POST', '/v1/certificates/actions/import'),
                                        ('POST', '/v1/certificates/actions/use'),
                                        ('DELETE', '/v1/tokens/tok1')])
        self.assertEqual(ctx.json(ctx.calls[0]), {'data': {
            'username': 'svc-acme', 'password': 'pw', 'app_name': 'acme'}})
        self.assertNotIn('X-Auth-Token', ctx.calls[0]['headers'])
        for c in ctx.calls[1:]:
            self.assertEqual(c['headers']['X-Auth-Token'], 'NST')
        imp = ctx.json(ctx.calls[1])['data']
        self.assertEqual((imp['name'], imp['pkcs12'], imp['force']), ('custom', True, True))
        got = subprocess.run(['openssl', 'pkcs12', '-nodes', '-passin', 'pass:' + imp['password']],
                             input=base64.b64decode(imp['input']), capture_output=True,
                             check=True).stdout.decode()
        self.assertIn('PRIVATE KEY', got)
        self.assertEqual(ctx.json(ctx.calls[2]), {'data': {'name': 'custom', 'https': True,
                                                           'apis': True}})
        self.assertIn('the HTTPS GUI and the REST API', words)

    def test_only_the_gui_other_actions(self):
        ctx = FakeCtx([('POST', r'/v1/certificates/custom/actions/import_cert$', (200, {})),
                       ('POST', r'/v1/certificates/custom/actions/use_cert$', (200, {}))] +
                      ns_routes())
        t = make('hpe_nimble', '', ctx, **NS_CFG)
        t.deploy(FakeBundle(), {'apis': False, 'cert_name': 'custom',
                                'import_action': '/v1/certificates/custom/actions/import_cert',
                                'use_action': '/v1/certificates/custom/actions/use_cert'})
        self.assertEqual(ctx.json(ctx.find('POST', 'use_cert')[0]),
                         {'data': {'name': 'custom', 'https': True, 'apis': False}})
        self.assertEqual(t.served_places({'apis': False}), [('nimble.test', 443)])
        self.assertEqual(t.served_places({}), [('nimble.test', 443), ('nimble.test', 5392)])

    def test_unknown_action_said(self):
        ctx = FakeCtx([('POST', r'/actions/import$', (404, {'messages': [
            {'code': 'SM_http_not_found', 'text': 'Not found'}]}))] + ns_routes())
        with self.assertRaises(PluginError) as e:
            make('hpe_nimble', '', ctx, **NS_CFG).deploy(FakeBundle(), {})
        self.assertIn('has no action /v1/certificates/actions/import', str(e.exception))
        self.assertIn('REST API Reference', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertFalse(ctx.find('POST', 'actions/use'), 'not put to use')
        self.assertEqual(ctx.calls[-1]['method'], 'DELETE', 'signed out')

    def test_nothing_to_use_it_for(self):
        ctx = FakeCtx(ns_routes())
        with self.assertRaises(PluginError):
            make('hpe_nimble', '', ctx, **NS_CFG).deploy(FakeBundle(), {'https': False,
                                                                        'apis': False})
        self.assertEqual(ctx.calls, [])

    def test_wrong_password(self):
        ctx = FakeCtx([('POST', r'/v1/tokens$', (401, {'messages': [{'text': 'bad'}]}))])
        with self.assertRaises(PluginError) as e:
            make('hpe_nimble', '', ctx, **NS_CFG).deploy(FakeBundle(), {})
        self.assertFalse(e.exception.retry)

    def test_try(self):
        ctx = FakeCtx(ns_routes())
        words = make('hpe_nimble', '', ctx, **NS_CFG).test()
        self.assertIn('default, custom', words)
        self.assertEqual({m for m, p in methods(ctx)}, {'GET', 'POST', 'DELETE'})


# ---------------------------------------------------------------------------
class GuidesTest(unittest.TestCase):
    def test_each_module_and_version_in_both_languages(self):
        d = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
        for name, must in (('redfish@ilo', 'HpeHttpsCert'), ('hpe_oneview', 'pkcs12'),
                           ('hpe_nimble', '5392')):
            for suffix in ('.md', '.cs.md'):
                p = os.path.join(d, name + suffix)
                with open(p, encoding='utf-8') as f:
                    md = f.read()
                self.assertTrue(md.startswith('# '), p)
                self.assertIn(must, md, p)
                self.assertIn('```', md, p)
                self.assertIn('openssl s_client', md, p)


if __name__ == '__main__':
    unittest.main(verbosity=1)
