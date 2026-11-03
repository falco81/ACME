#!/usr/bin/env python3
"""SSL.com (SWS API), The SSL Store (REST API) and GlobalSign MSSL (the GCC SOAP API) -
against canned answers of the shapes their vendors' own API descriptions show
(the files named in docs/sources.md: sslcom/openapi.json, sslstore/swagger.json,
globalsign/ManagedSSLService-v1.wsdl, GASService-v1.wsdl and the MSSL API User
Guide) - and the 30-day windows of GlobalSign Atlas's /stats/issued.

    python3 test/test_sources_more_resellers.py

No network. Each fake server signs the request it is sent with the test CA of
test_issuers_more and checks what the module sends: the path or operation (a
contract per module, as the vendor documents it), how it signs in, the bodies. The
DCV records go in place through the placement API of the certificate's validation
(a DNS board, this server's HTTP files). Nothing is bought unless paid orders are
allowed, every module lists and hands out the account's certificates (Import from a
source), and every English word of the modules is in web/lang/cs.json.
"""
import base64
import json
import os
import re
import sys
import unittest
import urllib.parse
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

from test_issuers_more import Base, CannedContext, csr_der_of, hdr, p7_of, req_for  # noqa: E402
from test_digicert import Board, Files  # noqa: E402
from test_sources_vendors import english_of  # noqa: E402
from test_sources_resellers import csr_cn  # noqa: E402

from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.challenges.http_local import HttpLocal  # noqa: E402
from acmelib.plugins.issuers import _scep_pkcs7 as p7  # noqa: E402
from acmelib.plugins.issuers.globalsign_atlas import GlobalSignAtlasIssuer  # noqa: E402
from acmelib.plugins.issuers.globalsign_mssl import GlobalSignMsslIssuer  # noqa: E402
from acmelib.plugins.issuers.sslcom import SslComIssuer  # noqa: E402
from acmelib.plugins.issuers.sslstore import SslStoreIssuer  # noqa: E402

KINDS = ('sslcom', 'sslstore', 'globalsign_mssl')

# Every call each module may make, as the vendor documents it.
CONTRACT = {
    # api-docs/sslcom/openapi.json (paths)
    'sslcom': [('GET', r'^/certificates$'), ('POST', r'^/certificates$'),
               ('GET', r'^/certificate/[\w-]+$'), ('PUT', r'^/certificate/[\w-]+$'),
               ('DELETE', r'^/certificate/[\w-]+$'),
               ('GET', r'^/certificate/[\w-]+/validations/methods$')],
    # api-docs/sslstore/swagger.json (paths; /rest/order/download: its texts)
    'sslstore': [('POST', r'^/rest/health/validate$'), ('POST', r'^/rest/product/query$'),
                 ('POST', r'^/rest/order/neworder$'), ('POST', r'^/rest/order/approverlist$'),
                 ('POST', r'^/rest/order/reissue$'), ('POST', r'^/rest/order/info$'),
                 ('POST', r'^/rest/order/certificate/download$'),
                 ('POST', r'^/rest/order/download$'),
                 ('POST', r'^/rest/order/certificaterevokerequest$'),
                 ('POST', r'^/rest/order/query$')],
    # api-docs/globalsign/ManagedSSLService-v1.wsdl, GASService-v1.wsdl (operations)
    'globalsign_mssl': {'/kb/ws/v1/ManagedSSLService': ['GetMSSLProfiles', 'GetDomains',
                                                         'AddDomainToProfile', 'VerifyMsslDomain',
                                                         'PVOrder', 'RevokeMSSLOrder'],
                        '/kb/ws/v1/GASService': ['GetOrderByOrderID', 'GetOrderByDateRange',
                                                 'ReIssue']},
}


class Contract(object):
    def check(self, kind, calls):
        for c in calls:
            u = urllib.parse.urlsplit(c['url'])
            self.assertTrue(any(c['method'] == m and re.match(rx, u.path)
                                for m, rx in CONTRACT[kind]),
                            '%s %s is not in the contract of %s' % (c['method'], u.path, kind))


# ---------------------------------------------------------------------------
# SSL.com
# ---------------------------------------------------------------------------
class TestSslCom(Contract, Base):
    def server(self, **kw):
        st = dict(orders=[], rekeys=[], leaf=None, status='validation required', polls=0,
                  issue_after=1, revoked=[], old_leaf=None)
        st.update(kw)

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual(u.netloc, 'sws.sslpki.com')
            q = dict(urllib.parse.parse_qsl(u.query))
            b = json.loads(body) if body else {}
            keys = q if method == 'GET' else b
            if keys.get('secret_key') != 'SEC' or keys.get('account_key') != 'ACC':
                return 400, {}, {'errors': {'login': ['account_key not found or wrong '
                                                      'secret_key']}}
            if method == 'GET':
                self.assertNotIn('secret_key', b)
            else:
                self.assertNotIn('secret_key', q)
            p = u.path
            if p == '/certificates' and method == 'POST':
                st['orders'].append(b)
                st['leaf'] = self.sign(csr_der_of(b['csr']), list(b['domains']))
                return 201, {}, {'ref': 'co-ac1ecm200', 'order_status': 'validation required',
                                 'order_amount': '$49.00'}
            if p == '/certificates':
                return 200, {}, [{'ref': 'co-ac1ecm200', 'order_status': 'issued',
                                  'description': '1 Year Basic SSL'},
                                 {'ref': 'co-581eclsap', 'order_status':
                                  'validating, please wait'}]
            m = re.match(r'^/certificate/([\w-]+)/validations/methods$', p)
            if m:
                return 200, {}, {'dcv_methods': {n: {
                    'email_addresses': ['admin@%s' % n],
                    'http_csr_hash': {'http': 'http://%s/.well-known/pki-validation/29BD.txt' % n,
                                      'allow_https': 'true',
                                      'contents': 'BF34\nssl.com\n167c8a5c49'},
                    'cname_csr_hash': {'name': '_29BD.%s' % n, 'value': 'BF.ssl.com.'}}
                    for n in st.get('names') or ['www.firma.cz']}}
            m = re.match(r'^/certificate/([\w-]+)$', p)
            if m and method == 'PUT':
                st['rekeys'].append((m.group(1), b))
                st['leaf'] = self.sign(csr_der_of(b['csr']), list(b['domains']))
                st['status'] = 'validating, please wait'
                return 200, {}, {'ref': m.group(1), 'order_status': st['status']}
            if m and method == 'DELETE':
                st['revoked'].append((m.group(1), b))
                return 200, {}, {'status': 'revoked'}
            if m:
                if m.group(1) == 'co-old' and not st['rekeys']:
                    return 200, {}, {'order_status': 'issued',
                                     'expiration_date': '2099-05-02T11:22:37.000-05:00',
                                     'certificates': st['old_leaf'] or ''}
                st['polls'] += 1
                if st['polls'] >= st['issue_after'] and st['status'] != 'issued':
                    st['status'] = 'issued'
                out = {'order_status': st['status'], 'common_name': 'www.firma.cz',
                       'subject_alternative_names': ['www.firma.cz'],
                       'description': '1 Year Basic SSL',
                       'effective_date': '2026-11-03T11:22:37.000-05:00',
                       'expiration_date': '2027-11-03T11:22:37.000-05:00'}
                if st['status'] == 'issued':
                    if q.get('response_type') == 'pkcs7':
                        out['certificates'] = base64.b64encode(p7_of(
                            [st['leaf'], self.ca.pem, self.root.pem])).decode()
                    else:
                        out['certificates'] = st['leaf']
                return 200, {}, out
            return 404, {}, {'errors': ['no route ' + p]}
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'account_key': 'ACC', 'secret_key': 'SEC', 'product': '106',
                'contact_firstname': 'Jan', 'contact_lastname': 'Novak',
                'contact_email': 'it@firma.cz', 'contact_phone': '+420123',
                'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        s = SslComIssuer(conf, ctx)
        s._sleep = lambda x: None
        return s

    def test_nothing_bought_then_new_order_file_issued_revoked(self):
        h, st = self.server()
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': here})
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req)
        self.assertIn('paid orders are not allowed', str(e.exception))
        self.assertEqual(st['orders'], [])
        s = self.issuer(ctx, allow_paid=True)
        out = s.issue(req)
        self.check_issued(out, req)
        b = st['orders'][0]
        self.assertEqual((b['product'], b['period'], b['domains']),
                         ('106', '365', {'www.firma.cz': {'dcv': 'HTTP_CSR_HASH'}}))
        self.assertEqual(b['contacts']['all']['email'], 'it@firma.cz')
        self.assertEqual(ctx.files, {})
        self.assertEqual(out.info['ref'], 'co-ac1ecm200')
        self.assertIn('revoked serial', s.revoke(out.cert_pem, 'superseded'))
        ref, body = st['revoked'][0]
        self.assertEqual(ref, 'co-ac1ecm200')
        self.assertEqual(body['reason'], 'superseded')
        self.assertTrue(re.match(r'^[0-9a-f]{2}(:[0-9a-f]{2})*$', body['serials'][0]))
        self.check('sslcom', ctx.calls)
        self.assertFalse(any('SEC' in w for _l, w in ctx.steps))

    def test_rekey_inside_the_order_and_waiting_kept(self):
        h, st = self.server(issue_after=3)
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        old = req_for(['www.firma.cz'])
        st['old_leaf'] = self.sign(csr_der_of(old.csr_pem), ['www.firma.cz'])
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': here})
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, order_ref='co-old', wait_issue=0).issue(req)
        self.assertIn('has not issued yet', str(e.exception))
        self.assertEqual(st['rekeys'][0][0], 'co-old')
        self.assertEqual(ctx.files, {('www.firma.cz', '/.well-known/pki-validation/29BD.txt'):
                                     'BF34\nssl.com\n167c8a5c49'})
        out = self.issuer(ctx, order_ref='co-old').issue(req)
        self.check_issued(out, req)
        self.assertEqual(len(st['rekeys']), 1)
        self.assertEqual(st['orders'], [])
        self.check('sslcom', ctx.calls)

    def test_email_wildcard_list_fetch_and_refusal(self):
        h, st = self.server()
        ctx = CannedContext(h)
        s = self.issuer(ctx, dcv='email', approver='hostmaster', allow_paid=True)
        self.assertFalse(s.needs_challenge)
        s.issue(req_for(['www.firma.cz']))
        self.assertEqual(st['orders'][0]['domains'],
                         {'www.firma.cz': {'dcv': 'hostmaster@www.firma.cz'}})
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req_for(['*.firma.cz']))
        self.assertIn('wildcard', str(e.exception))
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, allow_paid=True).issue(req_for(['a.firma.cz', 'b.firma.cz'],
                                                            cert_id=99))
        self.assertIn('one name only', str(e.exception))
        self.assertEqual(s.catalog('products')['options'][0], ['106', '106 - Basic SSL'])
        items = {x['ref']: x for x in s.list_existing()}
        self.assertEqual(items['co-ac1ecm200']['names'], ['www.firma.cz'])
        self.assertTrue(items['co-ac1ecm200']['downloadable'])
        self.assertFalse(items['co-581eclsap']['downloadable'])
        got = s.fetch_existing('co-ac1ecm200')
        self.assertEqual([p7.Cert(c).subject_cn for c in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        with self.assertRaises(PluginError):
            s.fetch_existing('../x')
        self.check('sslcom', ctx.calls)
        with self.assertRaises(PluginError) as e:
            self.issuer(CannedContext(h), secret_key='nope').test()
        self.assertIn('account_key not found', str(e.exception))
        self.assertNotIn('nope', str(e.exception) + str(e.exception.detail or ''))

    def test_compat(self):
        self.assertEqual(SslComIssuer.proofs_for({'dcv': 'http'}), ['http-file-any'])
        self.assertEqual(SslComIssuer.proofs_for({'dcv': 'email'}), [])
        self.assertNotIn('cname', SslComIssuer.dcv)


# ---------------------------------------------------------------------------
# The SSL Store
# ---------------------------------------------------------------------------
class TestSslStore(Contract, Base):
    def server(self, **kw):
        st = dict(orders=[], reissues=[], leaf=None, status='Pending', polls=0, issue_after=1,
                  revoked=[], approvers=0, download_404=False, downloads=[])
        st.update(kw)

        def vet(names, how):
            out = []
            for n in names:
                if how == 'cname':
                    out.append({'domain': n, 'dcvMethod': 'CNAME', 'DNSName': '_AB12.%s' % n,
                                'DNSEntry': 'CD34.EF56.sectigo.com'})
                else:
                    out.append({'domain': n, 'dcvMethod': 'HTTP', 'FileName': 'AB12.txt',
                                'FileContents': 'CD34\r\nsectigo.com'})
            return out

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual((method, u.netloc), ('POST', 'api.thesslstore.com'))
            b = json.loads(body)
            if b['AuthRequest'] != {'PartnerCode': 'P123', 'AuthToken': 'TOK',
                                    'UserAgent': 'acme'}:
                return 200, {}, {'AuthResponse': {'isError': True, 'Message': [
                    '-9008 Authentication Failure']}}
            p = u.path
            ok = {'isError': False, 'Message': []}
            if p == '/rest/health/validate':
                return 200, {}, ok
            if p == '/rest/product/query':
                return 200, {}, [{'AuthResponse': ok, 'ProductCode': 'positivessl',
                                  'ProductName': 'Sectigo PositiveSSL', 'isDVProduct': True,
                                  'PricingInfo': [{'NumberOfMonths': 12}, {'NumberOfMonths': 24}]},
                                 {'AuthResponse': ok, 'ProductCode': 'cs', 'isCodeSigning': True}]
            if p == '/rest/order/approverlist':
                st['approvers'] += 1
                return 200, {}, {'AuthResponse': ok, 'ApproverEmailList': [
                    'admin@firma.cz', 'hostmaster@firma.cz']}
            if p in ('/rest/order/neworder', '/rest/order/reissue'):
                how = 'cname' if b.get('CNAMEAuthDVIndicator') else 'http'
                if p.endswith('neworder'):
                    st['orders'].append(b)
                    names = [b['DomainName']] + b['DNSNames']
                else:
                    st['reissues'].append(b)
                    names = ['www.firma.cz'] + [x['NewValue'] for x in b['AddSAN']]
                st['leaf'] = self.sign(csr_der_of(b['CSR']), names)
                st['status'] = 'Pending'
                return 200, {}, {'AuthResponse': ok, 'TheSSLStoreOrderID': b.get(
                    'TheSSLStoreOrderID') or 'TSSL-9876543', 'OrderStatus': {
                    'MajorStatus': 'Pending', 'DomainAuthVettingStatus': vet(names, how)}}
            if p == '/rest/order/info':
                oid = b['TheSSLStoreOrderID']
                if oid == 'TSSL-1' and not st['reissues']:
                    return 200, {}, {'AuthResponse': ok, 'TheSSLStoreOrderID': oid,
                                     'OrderStatus': {'MajorStatus': 'Active'},
                                     'CommonName': 'www.firma.cz', 'DNSNames': 'www.firma.cz',
                                     'CertificateEndDateInUTC': '1/15/2099 10:30:00 AM'}
                st['polls'] += 1
                if st['polls'] >= st['issue_after']:
                    st['status'] = 'Complete'
                return 200, {}, {'AuthResponse': ok, 'TheSSLStoreOrderID': oid,
                                 'OrderStatus': {'MajorStatus': st['status']}}
            if p in ('/rest/order/certificate/download', '/rest/order/download'):
                st['downloads'].append(p)
                if st['download_404'] and 'certificate' in p:
                    return 404, {}, ''
                return 200, {}, {'AuthResponse': ok, 'CertificateStatus': 'Issued',
                                 'Certificates': [
                                     {'FileName': 'Root.crt', 'FileContent': self.root.pem},
                                     {'FileName': 'www_firma_cz.crt', 'FileContent': st['leaf']},
                                     {'FileName': 'CA.crt', 'FileContent': self.ca.pem}]}
            if p == '/rest/order/certificaterevokerequest':
                st['revoked'].append(b)
                return 200, {}, ok
            if p == '/rest/order/query':
                self.assertTrue(re.match(r'^/Date\(\d+\)/$', b['StartDate']))
                self.assertEqual((b['PageNumber'], b['PageSize']), (1, 100))
                return 200, {}, [{'AuthResponse': ok, 'TheSSLStoreOrderID': 'TSSL-9876543',
                                  'OrderStatus': {'MajorStatus': 'Active'},
                                  'CommonName': 'www.firma.cz', 'DNSNames': 'firma.cz',
                                  'ProductName': 'PositiveSSL', 'SerialNumber': '053F',
                                  'CertificateEndDateInUTC': '1/15/2027 10:30:00 AM'},
                                 {'AuthResponse': ok, 'TheSSLStoreOrderID': 'TSSL-2',
                                  'OrderStatus': {'MajorStatus': 'Cancelled'},
                                  'CommonName': 'x.firma.cz'}]
            return 200, {}, {'AuthResponse': {'isError': True, 'Message': ['no route ' + p]}}
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'partner_code': 'P123', 'auth_token': 'TOK', 'product': 'positivessl',
                'contact_firstname': 'Jan', 'contact_lastname': 'Novak',
                'contact_email': 'it@firma.cz', 'contact_phone': '420123',
                'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        s = SslStoreIssuer(conf, ctx)
        s._sleep = lambda x: None
        return s

    def test_new_order_cname_placed_issued_revoked(self):
        h, st = self.server()
        ctx = CannedContext(h)
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req_for(['www.firma.cz']))
        self.assertIn('paid orders are not allowed', str(e.exception))
        board = Board()
        s = self.issuer(ctx, allow_paid=True)
        req = req_for(['www.firma.cz', 'firma.cz'], challenges={'www.firma.cz': board,
                                                                'firma.cz': board})
        out = s.issue(req)
        self.check_issued(out, req)
        b = st['orders'][0]
        self.assertEqual((b['ProductCode'], b['ValidityPeriod'], b['DomainName'], b['DNSNames'],
                          b['CNAMEAuthDVIndicator'], b['FileAuthDVIndicator']),
                         ('positivessl', 12, 'www.firma.cz', ['firma.cz'], True, False))
        self.assertEqual(b['AdminContact']['Email'], 'it@firma.cz')
        self.assertIn(('cname', '_ab12.www.firma.cz', 'cd34.ef56.sectigo.com'), board.log)
        self.assertIn(('cname', '_ab12.firma.cz', 'cd34.ef56.sectigo.com'), board.log)
        self.assertEqual(board.cname, {})
        self.assertEqual(out.info['ref'], 'TSSL-9876543')
        self.assertIn('took the revocation', s.revoke(out.cert_pem, 'keyCompromise'))
        self.assertEqual(st['revoked'][0]['RevokeReason'], 'keycompromise')
        self.check('sslstore', ctx.calls)
        self.assertFalse(any('TOK' in w for _l, w in ctx.steps))

    def test_reissue_http_file_waiting_and_download_fallback(self):
        h, st = self.server(issue_after=3, download_404=True)
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        req = req_for(['www.firma.cz', 'firma.cz'],
                      challenges={'www.firma.cz': here, 'firma.cz': here})
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, dcv='http', order_id='TSSL-1', wait_issue=0).issue(req)
        self.assertIn('has not issued yet', str(e.exception))
        r = st['reissues'][0]
        self.assertEqual((r['TheSSLStoreOrderID'], r['AddSAN'], r['DeleteSAN'],
                          r['FileAuthDVIndicator']),
                         ('TSSL-1', [{'OldValue': '', 'NewValue': 'firma.cz'}], [], True))
        self.assertEqual(ctx.files[('www.firma.cz', '/.well-known/pki-validation/AB12.txt')],
                         'CD34\nsectigo.com')
        out = self.issuer(ctx, dcv='http', order_id='TSSL-1').issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['orders'], [])
        self.assertEqual(st['downloads'][-2:], ['/rest/order/certificate/download',
                                                '/rest/order/download'])
        self.assertEqual(ctx.files, {})
        self.check('sslstore', ctx.calls)

    def test_email_catalog_list_fetch_and_refusal(self):
        h, st = self.server()
        ctx = CannedContext(h)
        s = self.issuer(ctx, dcv='email', approver='hostmaster', allow_paid=True)
        self.assertFalse(s.needs_challenge)
        s.issue(req_for(['firma.cz']))
        self.assertEqual(st['orders'][0]['ApproverEmail'], 'hostmaster@firma.cz')
        self.assertEqual(st['approvers'], 1)
        self.assertEqual(s.catalog('products')['options'],
                         [['positivessl', 'Sectigo PositiveSSL - DV (12, 24 months)']])
        self.assertIn('let in', s.test())
        items = {x['ref']: x for x in s.list_existing()}
        self.assertEqual(items['TSSL-9876543']['names'], ['www.firma.cz', 'firma.cz'])
        self.assertTrue(items['TSSL-9876543']['downloadable'])
        self.assertFalse(items['TSSL-2']['downloadable'])
        got = s.fetch_existing('TSSL-9876543')
        self.assertEqual([p7.Cert(c).subject_cn for c in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        with self.assertRaises(PluginError) as e:
            self.issuer(CannedContext(h), auth_token='nope').test()
        self.assertIn('Authentication Failure', str(e.exception))
        self.assertIn('auth token is wrong', str(e.exception))
        self.assertNotIn('nope', str(e.exception))
        self.check('sslstore', ctx.calls)

    def test_records_of_the_aggregate_fields(self):
        s = self.issuer(CannedContext(lambda *a: (200, {}, {})))
        recs = s.dcv_records(req_for(['www.firma.cz']), {
            'CNAMEAuthName': '_x1', 'CNAMEAuthValue': 'y2.comodoca.com.'})
        self.assertEqual(recs, [{'domain': 'www.firma.cz', 'type': 'cname',
                                 'fqdn': '_x1.www.firma.cz', 'value': 'y2.comodoca.com'}])
        self.assertEqual(SslStoreIssuer.proofs_for({'dcv': 'cname'}), ['cname-any'])
        self.assertEqual(SslStoreIssuer.proofs_for({'dcv': 'http'}), ['http-file-any'])
        self.assertEqual(SslStoreIssuer.proofs_for({'dcv': 'email'}), [])


# ---------------------------------------------------------------------------
# GlobalSign MSSL (SOAP)
# ---------------------------------------------------------------------------
def gs(op, inner, code='0', head='OrderResponseHeader', errors=''):
    return ('<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/'
            'envelope/"><soap:Body><ns2:%sResponse xmlns:ns2="https://system.globalsign.com/kb/'
            'ws/v1/"><Response><%s><SuccessCode>%s</SuccessCode><Errors>%s</Errors><Timestamp>'
            '2026-11-03T10:00:00.000Z</Timestamp></%s>%s</Response></ns2:%sResponse>'
            '</soap:Body></soap:Envelope>' % (op, head, code, errors, head, inner, op))


def x(el, path):
    got = el.find(path)
    return (got.text or '') if got is not None else None


class TestGlobalSignMssl(Base):
    def server(self, **kw):
        st = dict(domains=[('firma.cz', 'D1', '3', '')], ops=[], orders=[], reissues=[],
                  added=[], verified=[], revoked=[], leaf=None, status='1', polls=0,
                  issue_after=1, old_names=['www.firma.cz'])
        st.update(kw)

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual((method, u.netloc), ('POST', 'system.globalsign.com'))
            env = ET.fromstring(body)
            op_el = list(env.find('{http://schemas.xmlsoap.org/soap/envelope/}Body'))[0]
            self.assertEqual(op_el.tag.split('}')[0], '{https://system.globalsign.com/kb/ws/v1/')
            op = op_el.tag.split('}')[1]
            self.assertIn(op, CONTRACT['globalsign_mssl'][u.path], (u.path, op))
            st['ops'].append(op)
            r = op_el.find('Request')
            head = r[0]
            self.assertIn(head.tag, ('OrderRequestHeader', 'QueryRequestHeader'))
            if x(head, 'AuthToken/Password') != 'PW' or x(head, 'AuthToken/UserName') != 'api':
                return 200, {}, gs(op, '', '-1', errors='<Error><ErrorCode>-4001</ErrorCode>'
                                   '<ErrorMessage>Login failure</ErrorMessage></Error>')
            if op == 'GetMSSLProfiles':
                return 200, {}, gs(op, '<SearchMSSLProfileDetails><SearchMsslProfileDetail>'
                                   '<MSSLProfileId>01_SSL_1</MSSLProfileId><VettingLevel>OV'
                                   '</VettingLevel><MSSLOVProfileInfo><MSSLOVProfile>'
                                   '<OrganizationName>Firma s.r.o.</OrganizationName>'
                                   '</MSSLOVProfile></MSSLOVProfileInfo>'
                                   '</SearchMsslProfileDetail></SearchMSSLProfileDetails>',
                                   head='QueryResponseHeader')
            if op == 'GetDomains':
                self.assertEqual(x(r, 'ProfileID'), '01_SSL_1')
                rows = ''.join('<DomainDetail><MSSLProfileID>01_SSL_1</MSSLProfileID><DomainID>'
                               '%s</DomainID><DomainName>%s</DomainName><DomainStatus>%s'
                               '</DomainStatus><DomainValidationCode>%s</DomainValidationCode>'
                               '</DomainDetail>' % (i, n, s, c) for n, i, s, c in st['domains'])
                return 200, {}, gs(op, '<DomainDetails>%s</DomainDetails>' % rows,
                                   head='QueryResponseHeader')
            if op == 'AddDomainToProfile':
                st['added'].append((x(r, 'DomainName'), x(r, 'VettingType'), x(r, 'VettingLevel')))
                self.assertEqual(x(r, 'ContactInfo/Email'), 'it@firma.cz')
                st['domains'].append((x(r, 'DomainName'), 'D2', '1', ''))
                return 200, {}, gs(op, '<MSSLDomainID>D2</MSSLDomainID><DnsTXT>globalsign-domain-'
                                   'verification=TXT9</DnsTXT>')
            if op == 'VerifyMsslDomain':
                st['verified'].append((x(r, 'DomainID'), x(r, 'TagLocation'), x(r, 'VettingType')))
                st['domains'] = [(n, i, '3' if i == x(r, 'DomainID') else s, c)
                                 for n, i, s, c in st['domains']]
                return 200, {}, gs(op, '<DomainID>D2</DomainID>')
            if op == 'PVOrder':
                p = r.find('OrderRequestParameter')
                sans = [x(e, 'SubjectAltName') for e in r.findall('SANEntries/SANEntry')]
                st['orders'].append({'product': x(p, 'ProductCode'), 'kind': x(p, 'OrderKind'),
                                     'months': x(p, 'ValidityPeriod/Months'),
                                     'domain': x(r, 'MSSLDomainID'), 'sans': sans,
                                     'types': [x(e, 'SANOptionType') for e in
                                               r.findall('SANEntries/SANEntry')],
                                     'base': x(p, 'BaseOption'),
                                     'san_opt': x(p, 'Options/Option/OptionName')})
                csr = x(p, 'CSR')
                st['leaf'] = self.sign(csr_der_of(csr), [csr_cn(csr)] + sans)
                return 200, {}, gs(op, '<OrderID>CE2026110300001</OrderID>',
                                   head='PVOrderResponseHeader')
            if op == 'ReIssue':
                st['reissues'].append(x(r, 'TargetOrderID'))
                csr = x(r, 'OrderParameter/CSR')
                st['leaf'] = self.sign(csr_der_of(csr), st['old_names'])
                st['status'] = '1'
                return 200, {}, gs(op, '<OrderID>CE2026110300009</OrderID><TargetOrderID>%s'
                                   '</TargetOrderID>' % x(r, 'TargetOrderID'))
            if op == 'GetOrderByOrderID':
                oid = x(r, 'OrderID')
                if oid == 'CEOLD':
                    st_ = '4'
                else:
                    st['polls'] += 1
                    if st['polls'] >= st['issue_after']:
                        st['status'] = '4'
                    st_ = st['status']
                ful = ''
                if st_ == '4' and oid != 'CEOLD' and x(r, 'OrderQueryOption/ReturnFulfillment'):
                    def b64(pem):
                        return base64.b64encode(p7.cert_der(pem)).decode()
                    ful = ('<Fulfillment><CACertificates><CACertificate><CACertType>ROOT'
                           '</CACertType><CACert>%s</CACert></CACertificate><CACertificate>'
                           '<CACertType>INTER</CACertType><CACert>%s</CACert></CACertificate>'
                           '</CACertificates><ServerCertificate><X509Cert>%s</X509Cert>'
                           '</ServerCertificate></Fulfillment>' % (b64(self.root.pem),
                                                                   b64(self.ca.pem),
                                                                   b64(st['leaf'])))
                sans = ''.join('<SANEntry><SANOptionType>7</SANOptionType><SubjectAltName>%s'
                               '</SubjectAltName></SANEntry>' % n for n in st['old_names'][1:])
                return 200, {}, gs(op, '<OrderID>%s</OrderID><OrderDetail><OrderInfo><OrderId>%s'
                                   '</OrderId><ProductCode>PV_SHA2</ProductCode><OrderStatus>%s'
                                   '</OrderStatus><DomainName>%s</DomainName></OrderInfo>'
                                   '<CertificateInfo><CommonName>%s</CommonName><EndDate>'
                                   '2099-01-01T00:00:00.000Z</EndDate></CertificateInfo>'
                                   '<SANEntries>%s</SANEntries>%s</OrderDetail>' % (
                                       oid, oid, st_, st['old_names'][0], st['old_names'][0],
                                       sans, ful), head='OrderResponseHeader')
            if op == 'GetOrderByDateRange':
                self.assertTrue(re.match(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$',
                                         x(r, 'FromDate')))
                return 200, {}, gs(op, '<OrderDetails><OrderDetail><OrderInfo><OrderId>CE1'
                                   '</OrderId><ProductCode>PV_SHA2</ProductCode><OrderStatus>4'
                                   '</OrderStatus></OrderInfo><CertificateInfo><CommonName>'
                                   'www.firma.cz</CommonName><SerialNumber>0a1b</SerialNumber>'
                                   '<StartDate>2026-06-01T00:00:00.000Z</StartDate><EndDate>'
                                   '2026-12-17T00:00:00.000Z</EndDate></CertificateInfo>'
                                   '</OrderDetail><OrderDetail><OrderInfo><OrderId>CE2</OrderId>'
                                   '<OrderStatus>7</OrderStatus></OrderInfo></OrderDetail>'
                                   '</OrderDetails>', head='QueryResponseHeader')
            if op == 'RevokeMSSLOrder':
                st['revoked'].append((x(r, 'OrderID'), x(r, 'RevokeReason')))
                return 200, {}, gs(op, '')
            return 500, {}, '<x/>'
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'user': 'api', 'password': 'PW', 'profile_id': '01_SSL_1',
                'contact_firstname': 'Jan', 'contact_lastname': 'Novak',
                'contact_phone': '+420123', 'contact_email': 'it@firma.cz',
                'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        g = GlobalSignMsslIssuer(conf, ctx)
        g._sleep = lambda s: None
        return g

    def test_approved_domain_new_order_issued_revoked(self):
        h, st = self.server()
        ctx = CannedContext(h)
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req_for(['www.firma.cz']))
        self.assertIn('paid orders are not allowed', str(e.exception))
        self.assertFalse(GlobalSignMsslIssuer({}, ctx).needs_challenge)
        g = self.issuer(ctx, allow_paid=True)
        req = req_for(['www.firma.cz', '*.shop.firma.cz'])
        out = g.issue(req)
        self.check_issued(out, req)
        o = st['orders'][0]
        self.assertEqual((o['product'], o['kind'], o['months'], o['domain'], o['sans'], o['types'],
                          o['base'], o['san_opt']),
                         ('PV_SHA2', 'new', '6', 'D1', ['*.shop.firma.cz'], ['13'], None, 'SAN'))
        self.assertEqual(out.info['ref'], 'CE2026110300001')
        self.assertIn('revoked order CE2026110300001', g.revoke(out.cert_pem, 'keyCompromise'))
        self.assertEqual(st['revoked'], [('CE2026110300001', '1')])
        self.assertFalse(any('PW' in w for _l, w in ctx.steps))

    def test_not_covered_said_then_dns_txt_added_and_verified(self):
        h, st = self.server(domains=[])
        ctx = CannedContext(h)
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, allow_paid=True).issue(req_for(['www.firma.cz']))
        self.assertIn('no approved domain', str(e.exception))
        board = Board()
        g = self.issuer(ctx, allow_paid=True, dcv='dns')
        self.assertTrue(g.needs_challenge)
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': board})
        out = g.issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['added'], [('firma.cz', 'DNS', 'OV')])
        self.assertIn(('txt', 'firma.cz', 'globalsign-domain-verification=TXT9'), board.log)
        self.assertEqual(st['verified'], [('D2', 'firma.cz', 'DNS')])
        self.assertEqual(board.txt.get('firma.cz'), [])
        self.assertEqual(st['orders'][0]['domain'], 'D2')
        self.assertEqual(GlobalSignMsslIssuer.proofs_for({'dcv': 'dns'}), ['txt-any'])
        self.assertEqual(GlobalSignMsslIssuer.proofs_for({'dcv': 'profile'}), [])

    def test_reissue_waiting_kept_catalog_list_fetch_refusal(self):
        h, st = self.server(issue_after=3)
        ctx = CannedContext(h)
        req = req_for(['www.firma.cz'])
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, order_id='CEOLD', wait_issue=0).issue(req)
        self.assertIn('has not issued yet', str(e.exception))
        self.assertEqual(st['reissues'], ['CEOLD'])
        out = self.issuer(ctx, order_id='CEOLD').issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['reissues'], ['CEOLD'])        # asked for once
        self.assertEqual(st['orders'], [])
        self.assertEqual(out.info['ref'], 'CE2026110300009')
        g = self.issuer(ctx)
        self.assertEqual(g.catalog('profiles')['options'],
                         [['01_SSL_1', '01_SSL_1 - Firma s.r.o. (OV)']])
        self.assertEqual(g.catalog('products')['options'][0], ['PV_SHA2',
                                                               'PV_SHA2 - OrganizationSSL (SHA-256)'])
        self.assertIn('1 approved domain', g.test())
        items = {i['ref']: i for i in self.issuer(ctx, list_days=30).list_existing()}
        self.assertEqual(items['CE1']['serial'], '0A1B')
        self.assertTrue(items['CE1']['downloadable'])
        self.assertEqual(items['CE2']['status'], 'revoked')
        got = g.fetch_existing('CE2026110300009')
        self.assertEqual([p7.Cert(c).subject_cn for c in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        with self.assertRaises(PluginError) as e:
            self.issuer(CannedContext(h), password='nope').test()
        self.assertIn('-4001', str(e.exception))
        self.assertIn('password is wrong', str(e.exception))


# ---------------------------------------------------------------------------
# GlobalSign Atlas: /stats/issued 30 days at a time
# ---------------------------------------------------------------------------
class TestAtlasWindows(Base):
    def test_windows_of_30_days(self):
        seen = []

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.path.endswith('/login'):
                return 200, {}, {'access_token': 'T'}
            if u.path.endswith('/stats/issued'):
                q = dict(urllib.parse.parse_qsl(u.query))
                seen.append((int(q['from']), int(q['to'])))
                return 200, {'Total-Count': '1'}, [{'serial_number': '0A', 'not_before': 1,
                                                    'not_after': 2}]
            return 404, {}, {}
        g = GlobalSignAtlasIssuer({'api_key': 'a' * 16, 'api_secret': 'b' * 40,
                                   'client_cert': 'C', 'client_key': 'K'},
                                  CannedContext(handler))
        g.READ_MOST = 0
        got = g.list_existing()
        self.assertEqual(len(got), 1)                      # one serial, seen in every window
        self.assertEqual(len(seen), 14)                    # 400 days, 30 at a time
        self.assertTrue(all(t - f <= 30 * 86400 for f, t in seen))


# ---------------------------------------------------------------------------
# The registry, the forms, the docs, Czech
# ---------------------------------------------------------------------------
class TestForms(unittest.TestCase):
    def test_found_and_forms(self):
        from acmelib.plugins.base import FIELD_TYPES
        reg = Registry().reload()
        self.assertFalse([b for b in reg.broken if 'issuers' in b[0]], reg.broken)
        for kind in KINDS:
            cls = reg.get('issuer', kind)
            d = cls.describe()
            self.assertTrue(d['title'] and d['description'] and d['fields'], kind)
            self.assertTrue(d['lists_existing'], kind)
            self.assertTrue(d['public_names'], kind)
            self.assertEqual(d['doc'], 'docs/sources.md')
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            self.assertIn('allow_paid', keys, kind)
            for f in d['fields']:
                self.assertIn(f['type'], FIELD_TYPES)
                for k in (f.get('show_if') or {}):
                    self.assertIn(k, keys, '%s.%s' % (kind, f['key']))
                for k in f.get('depends') or []:
                    self.assertIn(k, keys, '%s.%s' % (kind, f['key']))
                if re.search(r'password|secret|_key$|token', f['key']):
                    self.assertEqual(f['type'], 'secret', '%s.%s' % (kind, f['key']))
                if f['type'] == 'catalog':
                    self.assertTrue(callable(getattr(cls, 'catalog', None)), kind)
            self.assertIn(cls.dcv_default, cls.dcv, kind)

    def test_docs_name_the_sources(self):
        with open(os.path.join(ROOT, 'docs', 'sources.md'), encoding='utf-8') as f:
            text = f.read()
        for kind in KINDS:
            self.assertTrue('`%s`' % kind in text, kind)
        for where in ('sslcom/openapi.json', 'sslstore/swagger.json',
                      'ManagedSSLService-v1.wsdl', 'GASService-v1.wsdl',
                      'globalsign-mssl-api-user-guide.pdf', 'api.eu.venafi.cloud'):
            self.assertTrue(where in text, where)

    def test_every_english_sentence_translated(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = json.load(f)
        known = {v['source'] for v in cs['strings'].values() if v.get('text')}
        pats = {v['source'] for v in cs['patterns'].values() if v.get('text')}
        missing = []
        for kind in KINDS + ('zerossl', 'venafi_cloud', 'venafi_tpp', 'keyfactor_command',
                             'globalsign_atlas'):
            strings, patterns = english_of(os.path.join(
                ROOT, 'acmelib', 'plugins', 'issuers', kind + '.py'))
            missing += sorted('%s: %s' % (kind, s) for s in strings if s not in known)
            missing += sorted('%s: PATTERN %s' % (kind, p) for p in patterns if p not in pats)
        self.assertEqual(missing, [], '\n'.join(missing))


if __name__ == '__main__':
    unittest.main()
