#!/usr/bin/env python3
"""Discovery of the sources (1.0.29) - "Find the settings from the account".

    python3 test/test_discover_sources.py

Each source's form asks only the sign-in; the module reads the rest from its
account (discover_setup) and the form is offered it. Against the fake servers of
the modules' own test files (test_sources_resellers, test_sources_more_resellers,
test_sources_vendors, test_issuers_more), with the answers discovery reads added in
the shapes the vendors document: what is asked, what is found and offered, and that
only reading calls were made - nothing ordered, changed or saved.
"""
import json
import os
import re
import sys
import tempfile
import unittest
import urllib.parse
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-discover-src-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme as E  # noqa: E402
from acmelib.certs import api_discover, runtime  # noqa: E402,F401  (the routes)
from acmelib.certs import store as S  # noqa: E402
from acmelib.plugins.base import Issuer, PluginError, field  # noqa: E402
from acmelib.plugins.issuers import _source_common as sc  # noqa: E402
from acmelib.plugins.issuers.aws_pca import AwsPcaIssuer  # noqa: E402
from acmelib.plugins.issuers.certum import CertumIssuer  # noqa: E402
from acmelib.plugins.issuers.cloudflare_origin_ca import CloudflareOriginCaIssuer  # noqa: E402
from acmelib.plugins.issuers.digicert import DigicertIssuer  # noqa: E402
from acmelib.plugins.issuers.ejbca import EjbcaIssuer  # noqa: E402
from acmelib.plugins.issuers.freeipa import FreeIpaIssuer  # noqa: E402
from acmelib.plugins.issuers.globalsign_atlas import GlobalSignAtlasIssuer  # noqa: E402
from acmelib.plugins.issuers.globalsign_mssl import GlobalSignMsslIssuer  # noqa: E402
from acmelib.plugins.issuers.gogetssl import GoGetSslIssuer  # noqa: E402
from acmelib.plugins.issuers.google_cas import GoogleCasIssuer  # noqa: E402
from acmelib.plugins.issuers.keyfactor_command import KeyfactorCommandIssuer  # noqa: E402
from acmelib.plugins.issuers.namecheap_ssl import NamecheapSslIssuer  # noqa: E402
from acmelib.plugins.issuers.sectigo_scm import SectigoScmIssuer  # noqa: E402
from acmelib.plugins.issuers.sslcom import SslComIssuer  # noqa: E402
from acmelib.plugins.issuers.sslstore import SslStoreIssuer  # noqa: E402
from acmelib.plugins.issuers.step_ca import StepCaIssuer  # noqa: E402
from acmelib.plugins.issuers.vault_pki import VaultPkiIssuer  # noqa: E402
from acmelib.plugins.issuers.venafi_cloud import VenafiCloudIssuer  # noqa: E402
from acmelib.plugins.issuers.zerossl import ZeroSslIssuer  # noqa: E402
import test_issuers_more as I  # noqa: E402
import test_sources_more_resellers as M  # noqa: E402
import test_sources_resellers as R  # noqa: E402
import test_sources_vendors as V  # noqa: E402
from test_issuers import openssl, rd  # noqa: E402
from test_issuers_more import CannedContext, hdr  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)

# The test classes whose fake servers are used (their CAs made once).
SERVED = (R.TestGoGetSsl, R.TestNamecheap, R.TestSectigoScm, R.TestCertum, M.TestSslCom,
          M.TestSslStore, M.TestGlobalSignMssl, V.TestZeroSsl, V.TestVenafiCloud,
          V.TestKeyfactor, V.TestCloudflareOriginCa, I.TestDigicert)


def setUpModule():
    for cls in SERVED:
        cls.setUpClass()


def tearDownModule():
    for cls in SERVED:
        cls.tearDownClass()


def served(cls, **kw):
    """(handler, state) of the fake server of the module's own test file."""
    name = next(n for n in sorted(vars(cls)) if n.startswith('test_'))
    return cls(name).server(**kw)


def path_of(call):
    return urllib.parse.urlsplit(call['url']).path


def opts(choice):
    return [o[0] for o in (choice or {}).get('options') or []]


class Reads(object):
    """Only reading calls: GETs, and the POSTs given (signing in, a read of a POST API)."""
    def only_reads(self, ctx, posts=()):
        for c in ctx.calls:
            if c['method'] == 'GET':
                continue
            self.assertEqual(c['method'], 'POST', c['url'])
            self.assertTrue(any(re.search(rx, path_of(c)) for rx in posts),
                            '%s %s is not a read' % (c['method'], c['url']))

    def soap_ops(self, ctx):
        out = []
        for c in ctx.calls:
            body = ET.fromstring(c['body'])
            op = list(list(body)[-1])[0]
            out.append(op.tag.split('}')[-1])
        return out


# ---------------------------------------------------------------------------
# What the popup asks
# ---------------------------------------------------------------------------
class TestDescribed(unittest.TestCase):
    ASKED = {
        'gogetssl': ['user', 'api_password', 'api_url'],
        'sslstore': ['partner_code', 'auth_token', 'environment', 'api_url'],
        'certum': ['env', 'user', 'password', 'api_url'],
        'ejbca': ['url', 'client_cert', 'client_key', 'ca_pem', 'verify'],
        'freeipa': ['url', 'user', 'password', 'ca_pem', 'verify'],
        'zerossl': ['api_key', 'api_url'],
        'step_ca': ['url', 'root_pem', 'provisioner_key', 'verify'],
    }

    def test_asks_the_sign_in_only(self):
        reg = S.registry()
        for kind, keys in self.ASKED.items():
            self.assertEqual(reg.get('issuer', kind).discover_keys_of(), keys, kind)
        # what discovery finds is never asked
        for kind, found in (('sectigo_scm', 'org_id'), ('certum', 'customer'),
                            ('freeipa', 'realm'), ('ejbca', 'username'),
                            ('ejbca', 'enroll_code'), ('venafi_cloud', 'application'),
                            ('vault_pki', 'mount'), ('google_cas', 'location'),
                            ('aws_pca', 'ca_arn'), ('step_ca', 'provisioner')):
            self.assertNotIn(found, reg.get('issuer', kind).discover_keys_of(), kind)
        # signing in that the automatic list missed
        self.assertIn('role_id', reg.get('issuer', 'vault_pki').discover_keys_of())
        self.assertIn('customer_uri', reg.get('issuer', 'sectigo_scm').discover_keys_of())
        self.assertIn('instance', reg.get('issuer', 'sectigo_scm').discover_keys_of())
        self.assertIn('user_name', reg.get('issuer', 'namecheap_ssl').discover_keys_of())

    def test_offered_and_not(self):
        reg = S.registry()
        for kind in ('gogetssl', 'namecheap_ssl', 'sslstore', 'sslcom', 'sectigo_scm', 'certum',
                     'globalsign_mssl', 'globalsign_atlas', 'digicert', 'zerossl',
                     'venafi_cloud', 'venafi_tpp', 'keyfactor_command', 'ejbca', 'vault_pki',
                     'google_cas', 'aws_pca', 'step_ca', 'ms_adcs', 'freeipa',
                     'cloudflare_origin_ca'):
            d = reg.get('issuer', kind).describe()
            self.assertTrue(d['discover'] and d['discover']['keys'], kind)
        for kind in ('acme', 'internal_ca', 'selfsigned', 'est', 'scep', 'cmp'):
            self.assertIsNone(reg.get('issuer', kind).describe()['discover'], kind)


class ShownDepends(Issuer):
    kind = 'shown_test'
    fields = [field('auth', 'Signing in', 'select', default='token',
                    options=[['token', 'Token'], ['password', 'Password']]),
              field('token', 'Token', 'secret', show_if={'auth': ['token']}),
              field('user', 'User', 'text', show_if={'auth': ['password']}),
              field('things', 'Things', 'catalog', catalog='things',
                    depends=['auth', 'token', 'user'])]

    def catalog(self, key):
        return {'options': [['a', 'A']]}


class TestShared(unittest.TestCase):
    def test_lists_need_only_the_shown_sign_in(self):
        got = sc.discover_lists(ShownDepends({'token': 'T'}, None))
        self.assertEqual(opts(got['choices']['things']), ['a'])
        self.assertEqual(got['notes'], [])
        got = sc.discover_lists(ShownDepends({'auth': 'password'}, None))
        self.assertIn('set User first', ' '.join(got['notes']))

    def test_reuse_never_picked_and_ended_left_out(self):
        p = ShownDepends({}, None)
        out = {'sets': {}, 'choices': {}, 'facts': [], 'notes': []}
        n = sc.reuse_choice(p, out, 'things', [
            {'ref': '1', 'cn': 'a.cz', 'renewable': 'reissue', 'not_after': 4102444800},
            {'ref': '2', 'cn': 'b.cz', 'renewable': 'reissue', 'not_after': 1000},
            {'ref': '3', 'cn': 'c.cz', 'renewable': 'order'}], 'Empty: none.')
        self.assertEqual(n, 1)
        self.assertEqual(out['choices']['things']['pick'], '')
        self.assertEqual(opts(out['choices']['things']), ['', '1'])

    def test_assumed_puts_the_settings_back(self):
        p = ShownDepends({'token': 'T'}, None)
        with sc.assumed(p, {'user': 'u', 'token': 'other'}):
            self.assertEqual((p.c('user'), p.c('token')), ('u', 'T'))
        self.assertEqual(p.config, {'token': 'T'})


# ---------------------------------------------------------------------------
# The resellers
# ---------------------------------------------------------------------------
ACCOUNT = {'first_name': 'John', 'last_name': 'Smith', 'company_name': 'Company Name',
           'company_phone': '+3711111111', 'phone': '', 'country': 'LV',
           'email': 'admin@domain.tld', 'success': True}


class TestGoGetSsl(Reads, unittest.TestCase):
    def ctx(self):
        h, _st = served(R.TestGoGetSsl)

        def handler(method, url, body, headers, cc):
            if urllib.parse.urlsplit(url).path == '/api/account':
                return 200, {}, ACCOUNT        # getAccountDetails (gogetssl-api-v1 Postman)
            return h(method, url, body, headers, cc)
        return CannedContext(handler)

    def test_contact_products_orders(self):
        ctx = self.ctx()
        got = GoGetSslIssuer({'user': 'reseller', 'api_password': 'APIPW'}, ctx).discover_setup()
        s = got['sets']
        self.assertEqual((s['contact_firstname'], s['contact_lastname'], s['contact_email'],
                          s['contact_phone']), ('John', 'Smith', 'admin@domain.tld',
                                                '+3711111111'))
        self.assertEqual(opts(got['choices']['product']), ['77'])
        o = got['choices']['order_id']
        self.assertEqual((opts(o), o['pick']), (['', '1332864'], ''))
        self.assertIn(['Company', 'Company Name'], got['facts'])
        self.only_reads(ctx, posts=[r'^/api/auth$'])

    def test_wrong_password_said(self):
        with self.assertRaises(PluginError) as e:
            GoGetSslIssuer({'user': 'reseller', 'api_password': 'nope'},
                           self.ctx()).discover_setup()
        self.assertIn('Wrong username/password', str(e.exception))


class TestNamecheap(unittest.TestCase):
    def test_certificates_to_reuse_with_their_type(self):
        h, st = served(R.TestNamecheap)
        ctx = CannedContext(h)
        got = NamecheapSslIssuer({'env': 'sandbox', 'api_user': 'ncuser', 'api_key': 'NCKEY',
                                  'client_ip': '198.51.100.7'}, ctx).discover_setup()
        c = got['choices']['cert_id']
        self.assertEqual((opts(c), c['pick']), (['', '5001', '5002'], ''))
        self.assertEqual(c['sets']['5002'], {'ssl_type': 'PositiveSSL'})
        self.assertIn('ssl_type', got['choices'])
        self.assertEqual(set(st['commands']), {'namecheap.ssl.getList'})


class TestSslStore(Reads, unittest.TestCase):
    def test_contact_of_the_newest_order(self):
        h, _st = served(M.TestSslStore)

        def handler(method, url, body, headers, cc):
            b = json.loads(body)
            if urllib.parse.urlsplit(url).path == '/rest/order/info' and \
                    b.get('TheSSLStoreOrderID') == 'TSSL-9876543':
                return 200, {}, {'AuthResponse': {'isError': False}, 'TheSSLStoreOrderID':
                                 'TSSL-9876543', 'OrderStatus': {'MajorStatus': 'Active'},
                                 'WebServerType': 'nginx',
                                 'TechnicalContact': {'FirstName': 'Eva', 'LastName': 'Nova',
                                                      'Phone': '420555', 'Email': 'eva@firma.cz',
                                                      'Title': 'CTO'}}
            return h(method, url, body, headers, cc)
        ctx = CannedContext(handler)
        got = SslStoreIssuer({'partner_code': 'P123', 'auth_token': 'TOK'}, ctx).discover_setup()
        s = got['sets']
        self.assertEqual((s['contact_firstname'], s['contact_email'], s['contact_title'],
                          s['web_server']), ('Eva', 'eva@firma.cz', 'CTO', 'nginx'))
        o = got['choices']['order_id']
        self.assertEqual((opts(o), o['pick']), (['', 'TSSL-9876543'], ''))
        self.assertEqual(opts(got['choices']['product']), ['positivessl'])
        # a POST API: only its reading operations
        self.only_reads(ctx, posts=[r'^/rest/(product/query|order/query|order/info)$'])


class TestSslCom(Reads, unittest.TestCase):
    def test_orders_country_and_software(self):
        h, _st = served(M.TestSslCom)

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if method == 'GET' and u.path == '/certificate/co-ac1ecm200':
                return 200, {}, {'order_status': 'issued', 'product': '106',
                                 'common_name': 'www.firma.cz', 'server_software': 15,
                                 'registrant': {'organization': 'Firma', 'country': 'cz'},
                                 'expiration_date': '2099-11-03T11:22:37.000-05:00'}
            return h(method, url, body, headers, cc)
        ctx = CannedContext(handler)
        got = SslComIssuer({'account_key': 'ACC', 'secret_key': 'SEC'}, ctx).discover_setup()
        self.assertEqual((got['sets']['contact_country'], got['sets']['server_software']),
                         ('CZ', 15))
        o = got['choices']['order_ref']
        self.assertEqual((opts(o), o['pick']), (['', 'co-ac1ecm200', 'co-581eclsap'], ''))
        self.assertEqual(o['sets']['co-ac1ecm200'], {'product': '106'})
        self.only_reads(ctx)


class TestSectigoScm(Reads, unittest.TestCase):
    def test_organization_profiles_and_certificates(self):
        h, st = served(R.TestSectigoScm)

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.path == '/api/ssl/v2':
                status, rh, data = h(method, url, body, headers, cc)
                for c in data:                 # SSLIdentity: orgId, orgName, certTypeId
                    c.update(orgId=42, orgName='Firma', certTypeId=78)
                return status, rh, data
            return h(method, url, body, headers, cc)
        ctx = CannedContext(handler)
        got = SectigoScmIssuer({'instance': 'eu', 'client_id': 'cid', 'client_secret': 'csec'},
                               ctx).discover_setup()
        org = got['choices']['org_id']
        self.assertEqual((opts(org), org['pick']), (['42'], '42'))
        ct = got['choices']['cert_type']
        self.assertEqual((opts(ct), ct['pick']), (['77', '78'], '78'), 'the one used most')
        sid = got['choices']['ssl_id']
        self.assertEqual((opts(sid), sid['pick']), (['', '1001'], ''))
        self.assertFalse([n for n in got['notes'] if 'first' in n], got['notes'])
        types = [c for c in ctx.calls if path_of(c) == '/api/ssl/v2/types']
        self.assertIn('organizationId=42', types[0]['url'])
        self.only_reads(ctx, posts=[r'/openid-connect/token$'])


class TestCertum(unittest.TestCase):
    def test_customer_requestor_and_orders(self):
        h, st = served(R.TestCertum)

        def handler(method, url, body, headers, cc):
            op = list(list(ET.fromstring(body))[0])[0]
            if op.tag.endswith('getOrdersByDateRange') and \
                    op.find('orderOption/orderDetails').text == 'true':
                st['ops'].append('getOrdersByDateRange')
                return 200, {}, R.soap('getOrdersByDateRange', (
                    '<orders><Order><certificateDetails><certificateStatus>VALID'
                    '</certificateStatus><commonName>www.firma.cz</commonName><endDate>'
                    '2099-01-01T00:00:00Z</endDate></certificateDetails><orderDetails>'
                    '<organizationInfo><taxIdentificationNumber>CZ123</taxIdentificationNumber>'
                    '</organizationInfo><requestorInfo><email>it@firma.cz</email><firstName>Jan'
                    '</firstName><lastName>Novak</lastName></requestorInfo></orderDetails>'
                    '<orderStatus><customer>firma</customer><orderDate>2026-06-01T00:00:00Z'
                    '</orderDate><orderID>ORD-1</orderID><orderStatus>ENROLLED</orderStatus>'
                    '<productCode>631</productCode><productValidityDate>2099-01-01T00:00:00Z'
                    '</productValidityDate></orderStatus></Order></orders>'))
            return h(method, url, body, headers, cc)
        ctx = CannedContext(handler)
        got = CertumIssuer({'env': 'test', 'user': 'partner', 'password': 'pw'},
                           ctx).discover_setup()
        self.assertEqual(got['choices']['customer']['pick'], 'firma')
        self.assertEqual(got['sets']['requestor'], ['email=it@firma.cz', 'firstName=Jan',
                                                    'lastName=Novak'])
        self.assertEqual(got['sets']['tax_id'], 'CZ123')
        o = got['choices']['order_id']
        self.assertEqual((opts(o), o['pick']), (['', 'ORD-1'], ''))
        self.assertEqual(opts(got['choices']['product']), ['631'])
        self.assertEqual(set(st['ops']), {'getProductList', 'getOrdersByDateRange'})


class TestGlobalSignMssl(unittest.TestCase):
    def test_profile_domains_orders(self):
        h, st = served(M.TestGlobalSignMssl)
        ctx = CannedContext(h)
        got = GlobalSignMsslIssuer({'user': 'api', 'password': 'PW'}, ctx).discover_setup()
        self.assertEqual(got['choices']['profile_id']['pick'], '01_SSL_1')
        self.assertIn(['Approved domains', 'firma.cz'], got['facts'])
        o = got['choices']['order_id']
        self.assertEqual((opts(o), o['pick']), (['', 'CE1'], ''))
        self.assertEqual(set(st['ops']), {'GetMSSLProfiles', 'GetDomains',
                                          'GetOrderByDateRange'})


class TestDigicert(Reads, unittest.TestCase):
    def test_organizations_products_orders(self):
        h, _st = served(I.TestDigicert)

        def handler(method, url, body, headers, cc):
            p = urllib.parse.urlsplit(url).path[len('/services/v2'):]
            if p == '/organization':
                return 200, {}, {'organizations': [{'id': 42, 'name': 'Firma s.r.o.',
                                                    'status': 'active'}]}
            if p == '/product':
                return 200, {}, {'products': [{'name_id': 'ssl_basic', 'name': 'Basic OV'},
                                              {'name_id': 'private_ssl', 'name': 'Private'}]}
            if p == '/domain':
                return 200, {}, {'domains': [{'name': 'firma.cz', 'is_active': True,
                                              'dcv_expiration': {'ev': '2099-01-01'}}]}
            if p == '/order/certificate' and method == 'GET':
                return 200, {}, {'orders': [
                    {'id': 555, 'status': 'issued', 'order_valid_till': '2099-01-01',
                     'certificate': {'common_name': 'www.firma.cz', 'valid_till': '2027-01-01'},
                     'product': {'name_id': 'ssl_basic', 'name': 'Basic OV'}},
                    {'id': 556, 'status': 'rejected', 'certificate': {}}],
                    'page': {'total': 2}}
            return h(method, url, body, headers, cc)
        ctx = CannedContext(handler)
        got = DigicertIssuer({'api_key': 'DEVKEY'}, ctx).discover_setup()
        self.assertEqual(got['choices']['organization_id']['pick'], '42')
        self.assertEqual(opts(got['choices']['product']), ['ssl_basic'])
        pc = got['choices']['product_code']
        self.assertEqual((opts(pc), pc['pick'], pc['sets']['private_ssl']),
                         (['', 'private_ssl'], '', {'product': 'other'}))
        o = got['choices']['order_id']
        self.assertEqual((opts(o), o['pick']), (['', '555'], ''))
        self.assertIn(['Domains validated', 'firma.cz'], got['facts'])
        self.only_reads(ctx)


class TestZeroSsl(Reads, unittest.TestCase):
    def test_key_way_and_validity_found(self):
        h, _st = served(V.TestZeroSsl)

        def handler(method, url, body, headers, cc):
            if hdr(headers, 'Authorization'):          # an older account: the parameter only
                return 200, {}, {'success': False, 'error': {'code': 101,
                                                             'type': 'invalid_access_key'}}
            status, rh, data = h(method, url, body, headers, cc)
            for c in data.get('results') or []:
                c['validity_days'] = 365
            return status, rh, data
        ctx = CannedContext(handler)
        z = ZeroSslIssuer({'api_key': 'ZKEY'}, ctx)
        got = z.discover_setup()
        self.assertEqual((got['sets']['key_in'], got['sets']['validity']), ('query', '365'))
        self.assertNotIn('key_in', z.config, 'nothing kept by the module')
        self.only_reads(ctx)


# ---------------------------------------------------------------------------
# The vendors' and private CAs
# ---------------------------------------------------------------------------
class TestVenafiCloud(Reads, unittest.TestCase):
    def ctx(self):
        h, _st = served(V.TestVenafiCloud)

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.path == '/outagedetection/v1/applications':
                self.assertEqual(u.query, 'issuingTemplateAssigned=true')
                return 200, {}, {'applications': [
                    {'id': 'app-1', 'name': 'Store front', 'certificateIssuingTemplateAliasIdMap':
                     {'Public Trust': 'cit-1', 'Default': 'cit-0'}},
                    {'id': 'app-2', 'name': 'Lab', 'certificateIssuingTemplateAliasIdMap':
                     {'Default': 'cit-9'}}]}
            return h(method, url, body, headers, cc)
        return CannedContext(handler)

    def test_applications_with_their_templates(self):
        ctx = self.ctx()
        got = VenafiCloudIssuer({'region': 'eu', 'api_key': 'VKEY'}, ctx).discover_setup()
        a = got['choices']['application']
        self.assertEqual((opts(a), a['pick']), (['Lab', 'Store front'], ''))
        self.assertEqual(a['sets'], {'Lab': {'template': 'Default'}})
        self.assertNotIn('template', got['choices'])
        got = VenafiCloudIssuer({'region': 'eu', 'api_key': 'VKEY', 'application': 'Store front'},
                                ctx).discover_setup()
        self.assertEqual(opts(got['choices']['template']), ['Default', 'Public Trust'])
        self.only_reads(ctx)


class TestKeyfactor(Reads, unittest.TestCase):
    def test_templates_and_cas_either_way_of_signing_in(self):
        h, _st = served(V.TestKeyfactor)
        ctx = CannedContext(h)
        got = KeyfactorCommandIssuer({'url': 'https://kf.example.test', 'domain': 'EXAMPLE',
                                      'user': 'acme', 'password': 'pw'}, ctx).discover_setup()
        t = got['choices']['template']
        self.assertEqual(t['sets']['WebServer'], {'ca': 'ca01.example.test\\Issuing CA'})
        self.assertEqual(opts(got['choices']['ca']), ['ca01.example.test\\Issuing CA', 'a\\A',
                                                      'b\\B', 'ejbca\\Other'])
        self.assertEqual(got['notes'], [])
        got = KeyfactorCommandIssuer({'url': 'https://kf.example.test', 'auth': 'oauth',
                                      'token_url': 'https://idp.example.test/token',
                                      'client_id': 'acme', 'client_secret': 'S', 'scope': 'kf'},
                                     CannedContext(h)).discover_setup()
        self.assertEqual(sorted(opts(got['choices']['template'])), ['Approved', 'WebServer'])
        self.only_reads(ctx)


class TestCloudflareOriginCa(Reads, unittest.TestCase):
    def test_zone_and_validity(self):
        h, _st = served(V.TestCloudflareOriginCa)
        ctx = CannedContext(h)
        got = CloudflareOriginCaIssuer({'api_token': 'T'}, ctx).discover_setup()
        self.assertEqual(got['choices']['zone']['pick'], V.TestCloudflareOriginCa.ZONE)
        self.assertEqual(got['sets']['validity'], '90')
        self.assertIn(['Origin CA certificates', '1'], got['facts'])
        got = CloudflareOriginCaIssuer({'auth': 'service_key', 'service_key': 'K'},
                                       CannedContext(h)).discover_setup()
        self.assertIn('zone', got['choices'], 'no API token asked for with an Origin CA Key')
        self.only_reads(ctx)


class TestAtlas(Reads, unittest.TestCase):
    def test_policy_said(self):
        def handler(method, url, body, headers, cc):
            p = urllib.parse.urlsplit(url).path
            if p.endswith('/login'):
                return 200, {}, {'access_token': 'AT'}
            if p.endswith('/validationpolicy'):
                return 200, {}, {'validity': {'secondsmax': 200 * 86400},
                                 'subject_dn': {'common_name': {'presence': 'REQUIRED'},
                                                'organization': {'presence': 'REQUIRED'},
                                                'country': {'presence': 'STATIC'}},
                                 'public_key': {'key_format': 'PKCS10'}}
            return 404, {}, {}
        ctx = CannedContext(handler)
        cfg = {'api_key': 'K', 'api_secret': 'S', 'client_cert': 'C', 'client_key': 'CK'}
        got = GlobalSignAtlasIssuer(cfg, ctx).discover_setup()
        self.assertIn(['Longest validity (days)', '200'], got['facts'])
        self.assertIn('requires organization', ' '.join(got['notes']))
        got = GlobalSignAtlasIssuer(dict(cfg, subject_extra=['organization=Firma']),
                                    ctx).discover_setup()
        self.assertEqual(got['notes'], [])
        self.only_reads(ctx, posts=[r'/login$'])


class TestEjbca(Reads, unittest.TestCase):
    def test_profiles_with_their_profiles_and_cas(self):
        def handler(method, url, body, headers, cc):
            self.assertEqual(cc, ('ADMIN CERT', 'ADMIN KEY'))
            p = urllib.parse.urlsplit(url).path[len('/ejbca/ejbca-rest-api'):]
            if p == '/v1/ca':
                return 200, {}, {'certificate_authorities': [
                    {'name': 'IssuingCA', 'subject_dn': 'CN=Issuing'},
                    {'name': 'RootCA', 'subject_dn': 'CN=Root'}]}
            if p == '/v2/endentity/profiles/authorized':
                return 200, {}, {'end_entitie_profiles': [{'name': 'TLS', 'id': 1}]}
            if p == '/v2/endentity/profile/TLS':
                return 200, {}, {'end_entity_profile_name': 'TLS', 'available_cas': ['IssuingCA'],
                                 'available_certificate_profiles': ['SERVER']}
            if p == '/v1/certificate/status':
                return 200, {}, {'status': 'OK', 'version': '1.0', 'revision': 'EJBCA 9.1'}
            return 404, {}, {}
        ctx = CannedContext(handler)
        got = EjbcaIssuer({'url': 'https://ejbca.example.test', 'client_cert': 'ADMIN CERT',
                           'client_key': 'ADMIN KEY'}, ctx).discover_setup()
        ee = got['choices']['ee_profile']
        self.assertEqual((ee['pick'], ee['sets']['TLS']),
                         ('TLS', {'cert_profile': 'SERVER', 'ca_name': 'IssuingCA'}))
        self.assertEqual(opts(got['choices']['cert_profile']), ['SERVER'])
        self.assertEqual(opts(got['choices']['ca_name']), ['IssuingCA', 'RootCA'])
        self.assertIn(['Version', 'EJBCA 9.1'], got['facts'])
        self.assertEqual(got['notes'], [])
        self.only_reads(ctx)


class TestVault(Reads, unittest.TestCase):
    def handler(self, method, url, body, headers, cc):
        u = urllib.parse.urlsplit(url)
        if u.path == '/v1/auth/approle/login':
            return 200, {}, {'auth': {'client_token': 'TOK'}}
        self.assertEqual(hdr(headers, 'X-Vault-Token'), 'TOK')
        if u.path == '/v1/sys/internal/ui/mounts':
            return 200, {}, {'data': {'secret': {'pki_int/': {'type': 'pki'},
                                                 'kv/': {'type': 'kv'}}}}
        if u.path == '/v1/pki_int/roles' and u.query == 'list=true':
            return 200, {}, {'data': {'keys': ['web']}}
        if u.path == '/v1/pki_int/issuers' and u.query == 'list=true':
            return 200, {}, {'data': {'keys': ['id-a', 'id-b'], 'key_info': {
                'id-a': {'issuer_name': 'old'}, 'id-b': {'issuer_name': 'new'}}}}
        return 404, {}, {'errors': []}

    def test_mount_role_issuers(self):
        ctx = CannedContext(self.handler)
        got = VaultPkiIssuer({'url': 'https://vault.example.test', 'auth': 'approle',
                              'role_id': 'R', 'secret_id': 'S'}, ctx).discover_setup()
        self.assertEqual(got['choices']['mount']['pick'], 'pki_int')
        self.assertEqual(got['choices']['role']['pick'], 'web', 'no token field needed')
        i = got['choices']['issuer_ref']
        self.assertEqual((opts(i), i['pick']), (['', 'id-a', 'id-b'], ''))
        self.only_reads(ctx, posts=[r'^/v1/auth/approle/login$'])


class TestGoogleCas(Reads, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w = sc.Work()
        kf = w.path('sa.pem')
        openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', kf])
        cls.sa = json.dumps({'client_email': 'acme@p1.iam.gserviceaccount.com',
                             'private_key': rd(kf), 'project_id': 'p1',
                             'token_uri': 'https://oauth2.googleapis.com/token'})
        w.close()

    def handler(self, method, url, body, headers, cc):
        u = urllib.parse.urlsplit(url)
        if u.netloc == 'oauth2.googleapis.com':
            return 200, {}, {'access_token': 'GT', 'expires_in': 3600}
        self.assertEqual(hdr(headers, 'Authorization'), 'Bearer GT')
        p = u.path[len('/v1/'):]
        if p == 'projects/p1/locations':
            return 200, {}, {'locations': [{'locationId': 'europe-west3'},
                                           {'locationId': 'us-east1'}]}
        if p == 'projects/p1/locations/europe-west3/caPools':
            return 200, {}, {'caPools': [{'name': 'projects/p1/locations/europe-west3/caPools/'
                                                  'tls-pool', 'tier': 'DEVOPS'}]}
        if p == 'projects/p1/locations/us-east1/caPools':
            return 200, {}, {}
        if p == 'projects/p1/locations/europe-west3/caPools/tls-pool/certificateAuthorities':
            return 200, {}, {'certificateAuthorities': [
                {'name': 'projects/p1/locations/europe-west3/caPools/tls-pool/'
                         'certificateAuthorities/ca-1', 'state': 'ENABLED'},
                {'name': 'projects/p1/locations/europe-west3/caPools/tls-pool/'
                         'certificateAuthorities/ca-2', 'state': 'ENABLED'}]}
        if p == 'projects/p1/locations/europe-west3/certificateTemplates':
            return 200, {}, {'certificateTemplates': [
                {'name': 'projects/p1/locations/europe-west3/certificateTemplates/tls'}]}
        return 404, {}, {'error': {'message': 'no ' + p}}

    def test_location_pool_cas_templates(self):
        ctx = CannedContext(self.handler)
        g = GoogleCasIssuer({'service_account': self.sa}, ctx)
        got = g.discover_setup()
        loc = got['choices']['location']
        self.assertEqual((opts(loc), loc['pick'], loc['sets']),
                         (['europe-west3'], 'europe-west3', {'europe-west3': {'pool': 'tls-pool'}}))
        self.assertEqual(got['choices']['pool']['pick'], 'tls-pool')
        ca = got['choices']['ca_id']
        self.assertEqual((opts(ca), ca['pick']), (['', 'ca-1', 'ca-2'], ''))
        self.assertEqual(opts(got['choices']['template']),
                         ['projects/p1/locations/europe-west3/certificateTemplates/tls'])
        self.assertEqual(g.config, {'service_account': self.sa}, 'nothing kept')
        self.only_reads(ctx, posts=[r'^/token$'])


class TestAwsPca(Reads, unittest.TestCase):
    ARN = 'arn:aws:acm-pca:eu-central-1:123456789012:certificate-authority/' \
          '11111111-2222-3333-4444-555555555555'

    def test_cas_of_the_region(self):
        targets = []

        def handler(method, url, body, headers, cc):
            self.assertEqual(urllib.parse.urlsplit(url).netloc,
                             'acm-pca.eu-central-1.amazonaws.com')
            targets.append(hdr(headers, 'X-Amz-Target'))
            self.assertEqual(json.loads(body)['ResourceOwner'], 'SELF')
            return 200, {}, {'CertificateAuthorities': [
                {'Arn': self.ARN, 'Status': 'ACTIVE', 'Type': 'SUBORDINATE',
                 'CertificateAuthorityConfiguration': {'SigningAlgorithm': 'SHA256WITHECDSA',
                                                       'Subject': {'CommonName': 'Issuing'}}},
                {'Arn': self.ARN[:-1] + '6', 'Status': 'DISABLED', 'Type': 'ROOT'}]}
        ctx = CannedContext(handler)
        got = AwsPcaIssuer({'access_key': 'AK', 'secret_key': 'SK',
                            'endpoint': 'https://acm-pca.eu-central-1.amazonaws.com'},
                           ctx).discover_setup()
        c = got['choices']['ca_arn']
        self.assertEqual((opts(c), c['pick']), ([self.ARN], self.ARN))
        self.assertEqual(targets, ['ACMPrivateCA.ListCertificateAuthorities'])
        self.only_reads(ctx, posts=[r'^/$'])
        ctx = CannedContext(handler)
        got = AwsPcaIssuer({'access_key': 'AK', 'secret_key': 'SK'}, ctx).discover_setup()
        self.assertIn('give the API endpoint', ' '.join(got['notes']))
        self.assertEqual(ctx.calls, [])


class TestStepCa(Reads, unittest.TestCase):
    def test_provisioner_of_the_key(self):
        w = sc.Work()
        kf = w.path('p.pem')
        openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', kf])
        jwk = I.jwk_of_text(openssl(['pkey', '-in', kf, '-noout', '-text']).decode(), 'ec')
        pem = rd(kf)
        w.close()
        root = I.TestCA('Step Root')
        try:
            jwk['kid'] = 'KID2'

            def handler(method, url, body, headers, cc):
                p = urllib.parse.urlsplit(url).path
                if p == '/1.0/provisioners':
                    return 200, {}, {'provisioners': [
                        {'type': 'JWK', 'name': 'one', 'key': {'kid': 'KID1'}},
                        {'type': 'JWK', 'name': 'two', 'key': {'kid': 'KID2'}},
                        {'type': 'ACME', 'name': 'acme'}], 'nextCursor': ''}
                if p == '/version':
                    return 200, {}, {'version': '0.28.1'}
                return 404, {}, {}
            ctx = CannedContext(handler)
            cfg = {'url': 'https://ca.example.test:9000', 'root_pem': root.pem}
            got = StepCaIssuer(dict(cfg, provisioner_key=json.dumps(jwk)), ctx).discover_setup()
            p = got['choices']['provisioner']
            self.assertEqual((opts(p), p['pick'], p['sets']), (['one', 'two'], 'two', {}))
            self.assertIn(['Version', '0.28.1'], got['facts'])
            got = StepCaIssuer(dict(cfg, provisioner_key=pem), ctx).discover_setup()
            p = got['choices']['provisioner']
            self.assertEqual((p['pick'], p['sets']['one']), ('', {'kid': 'KID1'}))
            self.only_reads(ctx)
        finally:
            root.close()


class TestFreeIpa(Reads, unittest.TestCase):
    def test_realm_profiles_cas(self):
        methods = []

        def handler(method, url, body, headers, cc):
            p = urllib.parse.urlsplit(url).path
            if p == '/ipa/session/login_password':
                return 200, {'Set-Cookie': 'ipa_session=abc; path=/ipa'}, b''
            b = json.loads(body)
            methods.append(b['method'])
            if b['method'] == 'env/1':
                self.assertEqual(b['params'][0], ['realm'])
                return 200, {}, {'result': {'result': {'realm': 'EXAMPLE.TEST'}, 'count': 1}}
            if b['method'] == 'certprofile_find/1':
                return 200, {}, {'result': {'result': [{'cn': ['caIPAserviceCert']}]}}
            if b['method'] == 'ca_find/1':
                return 200, {}, {'result': {'result': [
                    {'cn': ['ipa'], 'ipacasubjectdn': ['CN=Certificate Authority']},
                    {'cn': ['web'], 'ipacasubjectdn': ['CN=Web CA']}]}}
            return 200, {}, {'error': {'message': 'no ' + b['method']}}
        ctx = CannedContext(handler)
        got = FreeIpaIssuer({'url': 'https://ipa.example.test', 'user': 'admin',
                             'password': 'pw'}, ctx).discover_setup()
        self.assertEqual(got['sets']['realm'], 'EXAMPLE.TEST')
        self.assertEqual(got['choices']['profile']['pick'], 'caIPAserviceCert')
        c = got['choices']['cacn']
        self.assertEqual((opts(c), c['pick']), (['ipa', 'web'], 'ipa'))
        self.assertEqual(set(methods), {'env/1', 'certprofile_find/1', 'ca_find/1'})
        self.only_reads(ctx, posts=[r'^/ipa/session/(login_password|json)$'])


# ---------------------------------------------------------------------------
# Through the API, as the page asks
# ---------------------------------------------------------------------------
class FakeH(object):
    def __init__(self, role, body=None):
        self.store, self.role, self._body = STORE, role, body or {}

    def me(self, _role):
        return {'name': 'someone', 'role': self.role}

    def body(self):
        return self._body


class TestApi(unittest.TestCase):
    def test_gogetssl_found_nothing_saved(self):
        h, _st = served(R.TestGoGetSsl)
        fake = CannedContext(lambda m, u, b, hd, cc: (
            200, {}, ACCOUNT) if urllib.parse.urlsplit(u).path == '/api/account' else
            h(m, u, b, hd, cc))
        old = runtime.RunContext.http

        def http(self, method, url, *a, **kw):
            if url.startswith('https://my.gogetssl.com/'):
                return fake.http(method, url, *a, **kw)
            return old(self, method, url, *a, **kw)
        runtime.RunContext.http = http
        try:
            got = E.ROUTES[('POST', '/api/sources/discover')](FakeH('fulladmin', {
                'kind': 'gogetssl', 'config': {'user': 'reseller', 'api_password': 'APIPW'}}))
        finally:
            runtime.RunContext.http = old
        self.assertTrue(got['ok'], got)
        self.assertEqual(got['found']['sets']['contact_email'], 'admin@domain.tld')
        self.assertEqual(got['found']['choices']['order_id']['pick'], '')
        self.assertNotIn('APIPW', json.dumps(got))
        self.assertEqual({c['method'] for c in fake.calls}, {'GET', 'POST'})
        self.assertEqual({path_of(c) for c in fake.calls if c['method'] == 'POST'},
                         {'/api/auth'})
        json.dumps(got)


if __name__ == '__main__':
    unittest.main(verbosity=2)
