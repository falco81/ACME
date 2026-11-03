#!/usr/bin/env python3
"""Sectigo Certificate Manager (Admin API), Certum (SOAP partner API), GoGetSSL
(API v1) and Namecheap SSL - against canned answers of the shapes their vendors'
own API documentation shows (the files and pages named in docs/sources.md) - and
the lists of AWS Private CA (its documented templates) and EJBCA (CAs and
profiles).

    python3 test/test_sources_resellers.py

No network. Each fake server signs the request it is sent with the test CA of
test_issuers_more and checks what the module sends: the path or command (a
contract per module, as the vendor documents it), the headers or fields that sign
in, the bodies. The DCV records go in place through the placement API of the
certificate's validation (a DNS board, this server's HTTP files), as DigiCert's do.
Every module lists and hands out the account's certificates (Import from a source),
nothing is bought unless paid orders are allowed, and every English word of the
modules is in web/lang/cs.json.
"""
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

from test_issuers_more import Base, CannedContext, csr_der_of, hdr, req_for  # noqa: E402
from test_digicert import Board, Files  # noqa: E402
from test_sources_vendors import english_of  # noqa: E402

from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.challenges.http_local import HttpLocal  # noqa: E402
from acmelib.plugins.issuers import _scep_pkcs7 as p7  # noqa: E402
from acmelib.plugins.issuers.aws_pca import TEMPLATES, AwsPcaIssuer  # noqa: E402
from acmelib.plugins.issuers.certum import CertumIssuer  # noqa: E402
from acmelib.plugins.issuers.ejbca import EjbcaIssuer  # noqa: E402
from acmelib.plugins.issuers.gogetssl import GoGetSslIssuer  # noqa: E402
from acmelib.plugins.issuers.namecheap_ssl import NamecheapSslIssuer  # noqa: E402
from acmelib.plugins.issuers.sectigo_scm import SectigoScmIssuer  # noqa: E402

KINDS = ('sectigo_scm', 'certum', 'gogetssl', 'namecheap_ssl')

# Every call each module may make, as the vendor documents it.
CONTRACT = {
    # api-docs/sectigo/scm-admin-api.openapi.json (+ createaccesstoken.json)
    'sectigo_scm': [('POST', r'^/auth/realms/apiclients/protocol/openid-connect/token$'),
                    ('GET', r'^/api/ssl/v2/types$'), ('POST', r'^/api/ssl/v2/enroll$'),
                    ('GET', r'^/api/ssl/v2/\d+$'), ('GET', r'^/api/ssl/v2/collect/\d+$'),
                    ('POST', r'^/api/ssl/v2/renewById/\d+$'),
                    ('POST', r'^/api/ssl/v2/replace/\d+$'),
                    ('POST', r'^/api/ssl/v2/revoke/\d+$'),
                    ('POST', r'^/api/ssl/v2/revoke/serial/[0-9A-F]+$'),
                    ('GET', r'^/api/ssl/v2$'),
                    ('POST', r'^/api/dcv/v2/validation/status$'),
                    ('POST', r'^/api/dcv/v2/validation/start/domain/(cname|http|email)$'),
                    ('POST', r'^/api/dcv/v2/validation/submit/domain/(cname|http|txt|email)$')],
    # api-docs/certum/PartnerApi-test.wsdl (the operations)
    'certum': ['getProductList', 'quickOrder', 'reissueCertificate', 'performSanVerification',
               'getSanVerificationState', 'getOrderState', 'getOrderByOrderID',
               'getCertificate', 'revokeCertificate', 'getOrdersByDateRange'],
    # api-docs/gogetssl/gogetssl-api-v1.postman_collection.json
    'gogetssl': [('POST', r'^/api/auth$'), ('GET', r'^/api/products/ssl$'),
                 ('GET', r'^/api/account/balance$'), ('POST', r'^/api/orders/add_ssl_order$'),
                 ('POST', r'^/api/orders/ssl/reissue/\d+$'), ('GET', r'^/api/orders/status/\d+$'),
                 ('POST', r'^/api/orders/ssl/revalidate/\d+$'),
                 ('GET', r'^/api/orders/ssl/all$'), ('POST', r'^/api/orders/cancel_ssl_order$')],
    # api-docs/namecheap/notes.md (the namecheap.ssl.* pages)
    'namecheap_ssl': ['namecheap.ssl.create', 'namecheap.ssl.activate', 'namecheap.ssl.reissue',
                      'namecheap.ssl.getInfo', 'namecheap.ssl.getList',
                      'namecheap.ssl.resendApproverEmail', 'namecheap.ssl.revokecertificate'],
}


class Contract(object):
    def check(self, kind, calls):
        for c in calls:
            u = urllib.parse.urlsplit(c['url'])
            self.assertTrue(any(c['method'] == m and re.match(rx, u.path)
                                for m, rx in CONTRACT[kind]),
                            '%s %s is not in the contract of %s' % (c['method'], u.path, kind))


def form_of(body):
    return dict(urllib.parse.parse_qsl(body.decode() if isinstance(body, bytes) else body or ''))


# ---------------------------------------------------------------------------
# Sectigo Certificate Manager
# ---------------------------------------------------------------------------
class TestSectigoScm(Contract, Base):
    def server(self, **kw):
        st = dict(validated=set(), checks=0, issue_after=1, polls=0, enrolled=[], leaf=None,
                  status='Requested', renewed=[], replaced=[], revoked=[], tokens=0, submits=[],
                  next_id=1001)
        st.update(kw)

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            p = u.path
            if p.endswith('/openid-connect/token'):
                st['tokens'] += 1
                self.assertEqual(u.netloc, 'auth.sso.sectigo.com')
                self.assertEqual(form_of(body), {'client_id': 'cid', 'client_secret': 'csec',
                                                 'grant_type': 'client_credentials'})
                return 200, {}, {'access_token': 'TOK', 'expires_in': 300, 'token_type': 'Bearer'}
            self.assertEqual(u.netloc, 'admin.eu.sectigo.com')
            self.assertEqual(hdr(headers, 'Authorization'), 'Bearer TOK')
            b = json.loads(body) if body else {}
            if p == '/api/dcv/v2/validation/status':
                d = b['domain']
                if d in st['validated']:
                    return 200, {}, {'status': 'Validated', 'orderStatus': 'Submitted'}
                st['checks'] += 1
                if st['checks'] > st['issue_after'] and d in st['submitted_ok']:
                    return 200, {}, {'status': 'Validated', 'orderStatus': 'Submitted'}
                return 200, {}, {'status': 'Not validated', 'orderStatus': 'Awaiting submission'}
            if p == '/api/dcv/v2/validation/start/domain/cname':
                return 200, {}, {'host': '_abc123.%s' % b['domain'],
                                 'point': 'C1.D2.sectigo.com'}
            if p == '/api/dcv/v2/validation/start/domain/http':
                return 200, {}, {'url': 'http://%s/.well-known/pki-validation/AB12.txt' % b['domain'],
                                 'firstLine': 'HASHLINE', 'secondLine': 'sectigo.com'}
            if p.startswith('/api/dcv/v2/validation/submit/domain/'):
                st['submits'].append((p.rsplit('/', 1)[1], b['domain']))
                st['submitted_ok'].add(b['domain'])
                if p.endswith('/txt'):
                    return 200, {}, {'status': 'Not validated', 'orderStatus': 'Submitted',
                                     'host': '_pki-validation', 'point': 'TXTVALUE'}
                return 200, {}, {'status': 'Not validated', 'orderStatus': 'Submitted'}
            if p == '/api/dcv/v2/validation/start/domain/email':
                return 200, {}, {'emails': ['admin@%s' % b['domains'][0],
                                            'hostmaster@%s' % b['domains'][0]]}
            if p == '/api/ssl/v2/types':
                return 200, {}, [{'id': 77, 'name': 'OV Multi', 'terms': [365, 199]},
                                 {'id': 78, 'name': 'DV', 'terms': [199]}]
            if p == '/api/ssl/v2/enroll':
                st['enrolled'].append(b)
                names = [csr_cn(b['csr'])] + [x for x in (b.get('subjAltNames') or '').split(',')
                                              if x]
                st['leaf'] = self.sign(csr_der_of(b['csr']), names)
                sid = st['next_id']
                st['next_id'] += 1
                return 200, {}, {'sslId': sid, 'renewId': 'R%d' % sid}
            m = re.match(r'^/api/ssl/v2/renewById/(\d+)$', p)
            if m:
                st['renewed'].append((m.group(1), b))
                st['leaf'] = self.sign(csr_der_of(b['csr']), ['www.firma.cz', 'firma.cz'])
                st['status'] = 'Requested'
                return 200, {}, {'sslId': 2002}
            m = re.match(r'^/api/ssl/v2/replace/(\d+)$', p)
            if m:
                st['replaced'].append((m.group(1), b))
                st['leaf'] = self.sign(csr_der_of(b['csr']), [b['commonName']] +
                                       b['subjectAlternativeNames'])
                return 204, {}, b''
            m = re.match(r'^/api/ssl/v2/(\d+)$', p)
            if m and method == 'GET':
                st['polls'] += 1
                if m.group(1) == '555':
                    return 200, {}, {'status': 'Issued', 'commonName': 'www.firma.cz',
                                     'subjectAlternativeNames': ['www.firma.cz', 'firma.cz']}
                if st['polls'] >= st['issue_after']:
                    st['status'] = 'Issued'
                return 200, {}, {'status': st['status'], 'commonName': 'www.firma.cz'}
            m = re.match(r'^/api/ssl/v2/collect/(\d+)$', p)
            if m:
                self.assertEqual(urllib.parse.parse_qs(u.query)['format'], ['x509'])
                return 200, {}, st['leaf'] + self.ca.pem + self.root.pem
            m = re.match(r'^/api/ssl/v2/revoke/(.+)$', p)
            if m:
                st['revoked'].append((m.group(1), b))
                return 204, {}, b''
            if p == '/api/ssl/v2':
                q = urllib.parse.parse_qs(u.query)
                self.assertEqual(q['size'], ['200'])
                return 200, {'X-Total-Count': '2'}, [
                    {'sslId': 1001, 'commonName': 'www.firma.cz',
                     'subjectAlternativeNames': ['www.firma.cz', 'firma.cz'],
                     'certTypeName': 'OV Multi', 'status': 'Issued',
                     'serialNumber': '0a:1b', 'expires': '2027-01-01T00:00:00Z',
                     'issued': '2026-06-01T00:00:00Z'},
                    {'sslId': 1003, 'commonName': 'x.firma.cz', 'status': 'Requested'}]
            return 404, {}, {'code': -1, 'description': 'no route ' + p}
        st['submitted_ok'] = set()
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'instance': 'eu', 'client_id': 'cid', 'client_secret': 'csec', 'org_id': '42',
                'cert_type': '77', 'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        s = SectigoScmIssuer(conf, ctx)
        s._sleep = lambda x: None
        return s

    def test_cname_dcv_enroll_collect_revoke(self):
        h, st = self.server()
        ctx = CannedContext(h)
        board = Board()
        s = self.issuer(ctx)
        req = req_for(['www.firma.cz', 'firma.cz'], challenges={'www.firma.cz': board,
                                                                'firma.cz': board})
        out = s.issue(req)
        self.check_issued(out, req)
        self.assertIn(('cname', '_abc123.www.firma.cz', 'c1.d2.sectigo.com'), board.log)
        self.assertIn(('cname', '_abc123.firma.cz', 'c1.d2.sectigo.com'), board.log)
        self.assertEqual(board.cname, {})
        self.assertEqual(sorted(st['submits']), [('cname', 'firma.cz'), ('cname', 'www.firma.cz')])
        b = st['enrolled'][0]
        self.assertEqual((b['orgId'], b['certType'], b['term'], b['dcvMode'], b['subjAltNames']),
                         (42, 77, 199, 'CNAME', 'firma.cz'))
        self.assertEqual(out.info['ref'], '1001')
        self.assertEqual(st['tokens'], 1)
        self.assertIn('SCM revoked certificate 1001', s.revoke(out.cert_pem, 'keyCompromise'))
        self.assertEqual(st['revoked'], [('1001', {'reasonCode': '1',
                                                   'reason': 'revoked by acme'})])
        self.check('sectigo_scm', ctx.calls)
        self.assertFalse(any('csec' in w or 'TOK' in w for _l, w in ctx.steps))

    def test_validated_skipped_and_http_file_and_waiting_kept(self):
        h, st = self.server(validated={'firma.cz'}, issue_after=3)
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        s = self.issuer(ctx, dcv='http', wait_issue=0)
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': here})
        with self.assertRaises(PluginError) as e:
            s.issue(req)
        self.assertIn('not validated', str(e.exception))
        self.assertEqual(ctx.files, {('www.firma.cz', '/.well-known/pki-validation/AB12.txt'):
                                     'HASHLINE\nsectigo.com'})
        self.assertEqual(st['enrolled'], [])
        s = self.issuer(ctx, dcv='http')
        out = s.issue(req)
        self.check_issued(out, req)
        self.assertEqual(len(st['enrolled']), 1)
        self.assertEqual(st['submits'], [('http', 'www.firma.cz')])
        self.assertEqual(ctx.files, {})
        # a domain validated already: no record, no submit
        h2, st2 = self.server(validated={'firma.cz', 'www.firma.cz'})
        ctx2 = CannedContext(h2)
        self.issuer(ctx2).issue(req_for(['www.firma.cz', 'firma.cz']))
        self.assertEqual(st2['submits'], [])
        self.check('sectigo_scm', ctx.calls + ctx2.calls)

    def test_txt_email_and_wildcard_http_refused(self):
        h, st = self.server()
        ctx = CannedContext(h)
        board = Board()
        s = self.issuer(ctx, dcv='txt')
        s.issue(req_for(['firma.cz'], challenges={'firma.cz': board}))
        self.assertIn(('txt', '_pki-validation.firma.cz', 'TXTVALUE'), board.log)
        h, st = self.server()
        ctx = CannedContext(h)
        s = self.issuer(ctx, dcv='email', approver='hostmaster')
        self.assertFalse(s.needs_challenge)
        s.issue(req_for(['firma.cz']))
        self.assertEqual(st['submits'], [('email', 'firma.cz')])
        self.assertTrue(any(c['body'] and b'hostmaster@firma.cz' in c['body'] for c in ctx.calls))
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, dcv='http').issue(req_for(['*.firma.cz']))
        self.assertIn('wildcard', str(e.exception))
        self.check('sectigo_scm', ctx.calls)

    def test_renew_and_replace_the_imported_one(self):
        h, st = self.server(validated={'firma.cz', 'www.firma.cz'})
        ctx = CannedContext(h)
        req = req_for(['www.firma.cz', 'firma.cz'], ref='555')
        out = self.issuer(ctx).issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['renewed'][0][0], '555')
        self.assertEqual(out.info['ref'], '2002')
        self.assertEqual(st['enrolled'], [])
        out = self.issuer(ctx, renew_how='replace', ssl_id='555').issue(
            req_for(['www.firma.cz', 'firma.cz'], cert_id=8))
        self.assertEqual(st['replaced'][0][0], '555')
        self.assertEqual(st['replaced'][0][1]['reason'], 'renewed by acme')
        self.assertEqual(out.info['ref'], '555')
        self.check('sectigo_scm', ctx.calls)

    def test_catalog_list_fetch_and_header_login(self):
        h, st = self.server()
        ctx = CannedContext(h)
        s = self.issuer(ctx)
        got = s.catalog('types')
        self.assertEqual(got['options'][0], ['77', 'OV Multi (365, 199 days)'])
        self.assertIn('2 SSL certificate profile', s.test())
        items = {x['ref']: x for x in s.list_existing()}
        self.assertEqual(items['1001']['names'], ['www.firma.cz', 'firma.cz'])
        self.assertEqual(items['1001']['serial'], '0A1B')
        self.assertTrue(items['1001']['downloadable'])
        self.assertFalse(items['1003']['downloadable'])
        st['leaf'] = self.sign(csr_der_of(req_for(['www.firma.cz']).csr_pem), ['www.firma.cz'])
        got = s.fetch_existing('1001')
        self.assertEqual([p7.Cert(c).subject_cn for c in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        with self.assertRaises(PluginError):
            s.fetch_existing('../1')
        self.check('sectigo_scm', ctx.calls)
        seen = []

        def h2(method, url, body, headers, cc):
            seen.append((url, hdr(headers, 'login'), hdr(headers, 'customerUri')))
            return 200, {}, []
        SectigoScmIssuer({'auth': 'password', 'login': 'api', 'password': 'pw',
                          'customer_uri': 'firma', 'org_id': '1'}, CannedContext(h2)).test()
        self.assertEqual(seen[0], ('https://cert-manager.com/api/ssl/v2/types?organizationId=1',
                                   'api', 'firma'))

    def test_compat(self):
        self.assertEqual(SectigoScmIssuer.proofs_for({'dcv': 'cname'}), ['cname-any'])
        self.assertEqual(SectigoScmIssuer.proofs_for({'dcv': 'txt'}), ['txt-any'])
        self.assertEqual(SectigoScmIssuer.proofs_for({'dcv': 'http'}), ['http-file-any'])
        self.assertEqual(SectigoScmIssuer.proofs_for({'dcv': 'email'}), [])


def csr_cn(pem):
    import subprocess
    out = subprocess.run(['openssl', 'req', '-noout', '-subject', '-nameopt', 'RFC2253'],
                         input=pem.encode(), capture_output=True).stdout.decode()
    m = re.search(r'CN=([^,\n]+)', out)
    return m.group(1).strip() if m else ''


# ---------------------------------------------------------------------------
# Certum (SOAP)
# ---------------------------------------------------------------------------
NS = 'http://webservice.api.muc.unizeto.pl/'


def soap(op, inner, code=0, errors=''):
    return ('<?xml version="1.0"?><S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">'
            '<S:Body><ns2:%sResponse xmlns:ns2="%s"><responseHeader><successCode>%d</successCode>'
            '%s<timestamp>2026-11-03T10:00:00.000Z</timestamp></responseHeader>%s'
            '</ns2:%sResponse></S:Body></S:Envelope>' % (op, NS, code, errors, inner, op))


class TestCertum(Base):
    def server(self, **kw):
        st = dict(ops=[], bodies={}, leaf=None, state='AWAITING', polls=0, issue_after=1,
                  verified=0, revoked=[])
        st.update(kw)

        def handler(method, url, body, headers, cc):
            self.assertEqual(url, 'https://gs.test.certum.pl/service/PartnerApi')
            self.assertEqual(hdr(headers, 'Content-Type'), 'text/xml; charset=utf-8')
            root = ET.fromstring(body)
            op_el = list(list(root)[0])[0]
            self.assertTrue(op_el.tag.startswith('{%s}' % NS), op_el.tag)
            op = op_el.tag.split('}')[1]
            st['ops'].append(op)
            self.assertEqual(op_el.find('requestHeader/authToken/userName').text, 'partner')
            self.assertEqual(op_el.find('requestHeader/authToken/password').text, 'pw')
            st['bodies'][op] = op_el
            if op == 'getProductList':
                return 200, {}, soap(op, '<products><product><code>631</code><type>ISSUE</type>'
                                         '<validityPeriod>365</validityPeriod></product>'
                                         '<product><code>636</code><type>RENEWAL</type>'
                                         '</product></products>')
            if op in ('quickOrder', 'reissueCertificate'):
                csr = (op_el.find('orderParameters/CSR') if op == 'quickOrder' else
                       op_el.find('CSR')).text
                names = [e.text for e in op_el.iter('DNSName')] or ['www.firma.cz']
                st['leaf'] = self.sign(csr_der_of(csr), names)
                st['state'] = 'AWAITING'
                fq = ''.join('<FQDN>%s</FQDN>' % n for n in names)
                meth = op_el.find('SANApprover/approverMethod').text
                return 200, {}, soap(op, '<orderID>ORD-1</orderID><SANVerification>'
                                         '<approverMethod>%s</approverMethod><code>CODE42</code>'
                                         '<approverEmail></approverEmail><FQDNs>%s</FQDNs>'
                                         '</SANVerification>' % (meth, fq))
            if op == 'performSanVerification':
                self.assertEqual(op_el.find('code').text, 'CODE42')
                st['verified'] += 1
                st['state'] = 'VERIFICATION'
                return 200, {}, soap(op, '')
            if op == 'getOrderState':
                st['polls'] += 1
                if st['state'] == 'VERIFICATION' and st['polls'] >= st['issue_after']:
                    st['state'] = 'ENROLLED'
                return 200, {}, soap(op, '<verifications/><lastUpdateDate>2026-11-03T10:00:00Z'
                                         '</lastUpdateDate><orderStatus>%s</orderStatus>'
                                         % st['state'])
            if op == 'getSanVerificationState':
                return 200, {}, soap(op, '<sanVerifications><sanVerification><FQDN>www.firma.cz'
                                         '</FQDN><manualVerification><state>REQUIRED</state>'
                                         '<info>DNS_NO_RECORDS</info></manualVerification>'
                                         '</sanVerification></sanVerifications>')
            if op == 'getCertificate':
                return 200, {}, soap(op, '<certificateDetails><X509Cert>%s</X509Cert>'
                                         '</certificateDetails><caBundle><X509Cert>%s</X509Cert>'
                                         '<X509Cert>%s</X509Cert></caBundle>' % (
                                             st['leaf'], self.ca.pem, self.root.pem))
            if op == 'getOrderByOrderID':
                return 200, {}, soap(op, '<orders><Order><certificateDetails><serialNumber>0A1B'
                                         '</serialNumber><DNSNames>www.firma.cz</DNSNames>'
                                         '<endDate>2027-01-01T00:00:00Z</endDate><startDate>'
                                         '2026-01-01T00:00:00Z</startDate><X509Cert>x</X509Cert>'
                                         '</certificateDetails><orderStatus><customer>c'
                                         '</customer><orderDate>2026-01-01T00:00:00Z</orderDate>'
                                         '<orderID>ORD-0</orderID><orderStatus>ENROLLED'
                                         '</orderStatus><productCode>631</productCode>'
                                         '<productValidityDate>2099-01-01T00:00:00Z'
                                         '</productValidityDate></orderStatus></Order></orders>')
            if op == 'revokeCertificate':
                p = op_el.find('revokeCertificateParameters')
                st['revoked'].append((p.find('serialNumber').text, p.find('revocationReason').text))
                return 200, {}, soap(op, '')
            if op == 'getOrdersByDateRange':
                self.assertTrue(re.match(r'^\d{4}-\d\d-\d\dT', op_el.find('fromDate').text))
                return 200, {}, soap(op, '<orders><Order><certificateDetails><certificateStatus>'
                                         'VALID</certificateStatus><commonName>www.firma.cz'
                                         '</commonName><DNSNames>www.firma.cz,firma.cz</DNSNames>'
                                         '<endDate>2027-01-01T00:00:00Z</endDate><serialNumber>'
                                         '0a1b</serialNumber><startDate>2026-06-01T00:00:00Z'
                                         '</startDate><X509Cert>x</X509Cert></certificateDetails>'
                                         '<orderStatus><customer>c</customer><orderDate>'
                                         '2026-06-01T00:00:00Z</orderDate><orderID>ORD-1'
                                         '</orderID><orderStatus>ENROLLED</orderStatus>'
                                         '<productCode>631</productCode><productValidityDate>'
                                         '2099-01-01T00:00:00Z</productValidityDate>'
                                         '</orderStatus></Order><Order><orderStatus><customer>c'
                                         '</customer><orderDate>2026-06-02T00:00:00Z</orderDate>'
                                         '<orderID>ORD-2</orderID><orderStatus>AWAITING'
                                         '</orderStatus><productCode>631</productCode>'
                                         '</orderStatus></Order></orders>').replace(
                    '<timestamp>', '<pagesCount>1</pagesCount><timestamp>')
            return 500, {}, ('<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">'
                             '<S:Body><S:Fault><faultstring>no %s</faultstring></S:Fault>'
                             '</S:Body></S:Envelope>' % op)
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'env': 'test', 'user': 'partner', 'password': 'pw', 'customer': 'firma',
                'product': '631', 'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        c = CertumIssuer(conf, ctx)
        c._sleep = lambda x: None
        return c

    def test_nothing_bought_unless_allowed(self):
        h, st = self.server()
        ctx = CannedContext(h)
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req_for(['www.firma.cz']))
        self.assertIn('paid orders are not allowed', str(e.exception))
        self.assertNotIn('quickOrder', st['ops'])

    def test_quick_order_txt_prefix_verify_fetch_revoke(self):
        h, st = self.server()
        ctx = CannedContext(h)
        board = Board()
        c = self.issuer(ctx, allow_paid=True)
        req = req_for(['www.firma.cz', 'firma.cz'], challenges={'www.firma.cz': board,
                                                                'firma.cz': board})
        out = c.issue(req)
        self.check_issued(out, req)
        self.assertIn(('txt', '_certum.www.firma.cz', 'CODE42'), board.log)
        self.assertIn(('txt', '_certum.firma.cz', 'CODE42'), board.log)
        self.assertEqual(board.txt, {'_certum.www.firma.cz': [], '_certum.firma.cz': []})
        q = st['bodies']['quickOrder']
        self.assertEqual([x.tag for x in q], ['requestHeader', 'SANApprover', 'orderParameters',
                                              'SANEntries'])
        self.assertEqual(q.find('orderParameters/productCode').text, '631')
        self.assertEqual(q.find('orderParameters/customer').text, 'firma')
        self.assertEqual(q.find('orderParameters/hashAlgorithm').text, 'ECC-SHA256')
        self.assertEqual(q.find('SANApprover/approverMethod').text, 'DNS_TXT_PREFIX')
        self.assertEqual(st['verified'], 1)
        self.assertEqual(out.info['ref'], 'ORD-1')
        self.assertIn('revoked', c.revoke(out.cert_pem, 'superseded'))
        self.assertEqual(st['revoked'][0][1], 'SUPERSEDED')
        self.assertTrue(set(st['ops']) <= set(CONTRACT['certum']), st['ops'])
        self.assertFalse(any('pw' in w for _l, w in ctx.steps))

    def test_reissue_cname_and_file_and_waiting(self):
        h, st = self.server(issue_after=3)
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        c = self.issuer(ctx, dcv='FILE', order_id='ORD-0', wait_issue=0)
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': here})
        with self.assertRaises(PluginError) as e:
            c.issue(req)
        self.assertIn('not verified: www.firma.cz REQUIRED (DNS_NO_RECORDS)', str(e.exception))
        self.assertIn('reissueCertificate', st['ops'])
        self.assertNotIn('quickOrder', st['ops'])
        r = st['bodies']['reissueCertificate']
        self.assertEqual(r.find('serialNumber').text, '0A1B')
        self.assertIsNone(r.find('SANEntries'))            # the same names: none sent
        self.assertEqual(ctx.files, {('www.firma.cz', '/.well-known/pki-validation/certum.txt'):
                                     'CODE42-certum.pl'})
        out = self.issuer(ctx, dcv='FILE', order_id='ORD-0').issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['ops'].count('reissueCertificate'), 1)
        self.assertEqual(ctx.files, {})
        h, st = self.server()
        board = Board()
        self.issuer(CannedContext(h), dcv='DNS_CNAME', allow_paid=True).issue(
            req_for(['firma.cz'], challenges={'firma.cz': board}))
        self.assertIn(('cname', 'firma.cz', 'code42.certum.pl'), board.log)
        with self.assertRaises(PluginError):
            self.issuer(CannedContext(h), dcv='FILE').issue(req_for(['*.firma.cz']))

    def test_catalog_list_fetch_and_refusal(self):
        h, st = self.server()
        ctx = CannedContext(h)
        c = self.issuer(ctx)
        self.assertEqual(c.catalog('products')['options'], [['631', '631 (365 days)']])
        self.assertIn('2 product', c.test())
        items = {x['ref']: x for x in c.list_existing()}
        self.assertEqual(items['ORD-1']['names'], ['www.firma.cz', 'firma.cz'])
        self.assertEqual(items['ORD-1']['serial'], '0A1B')
        self.assertTrue(items['ORD-1']['downloadable'])
        self.assertEqual(items['ORD-1']['renewable'], 'reissue')
        self.assertFalse(items['ORD-2']['downloadable'])
        st['leaf'] = self.sign(csr_der_of(req_for(['www.firma.cz']).csr_pem), ['www.firma.cz'])
        got = c.fetch_existing('ORD-1')
        self.assertEqual([p7.Cert(x).subject_cn for x in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])

        def refused(method, url, body, headers, cc):
            return 200, {}, soap('getProductList', '', code=3, errors='<errors><Error><errorCode>3'
                                                                     '</errorCode></Error></errors>')
        with self.assertRaises(PluginError) as e:
            self.issuer(CannedContext(refused)).test()
        self.assertIn('user name or password is wrong', str(e.exception))
        self.assertEqual(CertumIssuer.dcv_where({'dcv': 'DNS_TXT_PREFIX'}, '*.firma.cz',
                                                'txt-any'), '_certum.firma.cz')
        self.assertEqual(CertumIssuer.dcv_where({'dcv': 'DNS_TXT'}, 'firma.cz', 'txt-any'),
                         'firma.cz')
        self.assertEqual(CertumIssuer.proofs_for({'dcv': 'DNS_CNAME_PREFIX'}), ['cname-any'])
        self.assertEqual(CertumIssuer.proofs_for({'dcv': 'FILE'}), ['http-file-any'])


# ---------------------------------------------------------------------------
# GoGetSSL (API v1)
# ---------------------------------------------------------------------------
class TestGoGetSsl(Contract, Base):
    def server(self, **kw):
        st = dict(auths=0, orders=[], reissues=[], leaf=None, status='processing', polls=0,
                  issue_after=1, revalidated=[], cancelled=[])
        st.update(kw)

        def record(n):
            return {'dns': {'record': '_FEA0%s.%s CNAME 6849.153D.t024.comodoca.com' % (
                        n.split('.')[0].upper(), n)},
                    'http': {'link': 'http://%s/.well-known/pki-validation/FEA0.txt' % n,
                             'filename': 'FEA0.txt',
                             'content': '6849ECE\r\ncomodoca.com\r\nt0767'}}

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual(u.netloc, 'my.gogetssl.com')
            q = dict(urllib.parse.parse_qsl(u.query))
            p = u.path
            f = form_of(body)
            if p == '/api/auth':
                st['auths'] += 1
                if f.get('pass') != 'APIPW':
                    return 200, {}, {'error': True, 'message': 'Wrong username/password',
                                     'description': 'Check your username and password'}
                return 200, {}, {'key': 'KEY1'}
            self.assertEqual(q.get('auth_key'), 'KEY1')
            if p == '/api/products/ssl':
                return 200, {}, {'products': [{'id': '77', 'product': 'Sectigo PositiveSSL',
                                               'product_type': 'domain_validation',
                                               'wildcard_enabled': 0}], 'success': True}
            if p == '/api/account/balance':
                return 200, {}, {'balance': '1000.00', 'currency': 'EUR', 'success': True}
            if p in ('/api/orders/add_ssl_order',) or p.startswith('/api/orders/ssl/reissue/'):
                names = [csr_cn(f['csr'])] + [x for x in f.get('dns_names', '').split(',') if x]
                st['leaf'] = self.sign(csr_der_of(f['csr']), names)
                st['status'] = 'processing' if 'add_ssl' in p else 'reissue'
                main = record(names[0])
                sans = [{'san_name': n, 'status': 1, 'validation': {f['dcv_method']:
                                                                    record(n)[f['dcv_method']]}}
                        for n in names[1:]]
                out = {'order_id': 1332864, 'order_status': 'processing', 'success': True,
                       'san': sans}
                if 'add_ssl' in p:
                    st['orders'].append(f)
                    out['approver_method'] = {f['dcv_method']: main[f['dcv_method']]}
                else:
                    st['reissues'].append((p.rsplit('/', 1)[1], f))
                    out['validation'] = {f['dcv_method']: main[f['dcv_method']]}
                    out['order_id'] = p.rsplit('/', 1)[1]
                return 200, {}, out
            m = re.match(r'^/api/orders/status/(\d+)$', p)
            if m:
                if m.group(1) == '999' and not st['reissues']:
                    return 200, {}, {'order_id': 999, 'status': 'active', 'end_date': '2099-01-01',
                                     'crt_code': 'OLD', 'domain': 'www.firma.cz'}
                st['polls'] += 1
                if st['polls'] >= st['issue_after'] and st['status'] in ('processing', 'reissue'):
                    st['status'] = 'active'
                out = {'order_id': int(m.group(1)), 'status': st['status'],
                       'domain': 'www.firma.cz', 'domains': 'www.firma.cz,firma.cz',
                       'valid_from': '2026-11-03', 'valid_till': '2027-05-20',
                       'end_date': '2027-11-03'}
                if st['status'] == 'active':
                    out.update({'crt_code': st['leaf'], 'ca_code': self.ca.pem + self.root.pem})
                return 200, {}, out
            if p.startswith('/api/orders/ssl/revalidate/'):
                st['revalidated'].append(f.get('domain'))
                return 200, {}, {'message': 'Revalidate request submitted.', 'success': True}
            if p == '/api/orders/ssl/all':
                self.assertEqual((q.get('limit'), q.get('offset')), ('100', '0'))
                return 200, {}, {'orders': [{'order_id': '1332864', 'status': 'active'},
                                            {'order_id': '1332865', 'status': 'cancelled'}],
                                 'count': 2, 'success': True}
            if p == '/api/orders/cancel_ssl_order':
                st['cancelled'].append(f)
                return 200, {}, {'message': 'Cancell request submitted.', 'success': True}
            return 200, {}, {'error': True, 'message': 'no route', 'description': p}
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'user': 'reseller', 'api_password': 'APIPW', 'product': '77',
                'contact_firstname': 'Jan', 'contact_lastname': 'Novak',
                'contact_phone': '+420123', 'contact_email': 'it@firma.cz',
                'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        g = GoGetSslIssuer(conf, ctx)
        g._sleep = lambda x: None
        return g

    def test_new_order_cname_placed_issued(self):
        h, st = self.server()
        ctx = CannedContext(h)
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req_for(['www.firma.cz']))
        self.assertIn('paid orders are not allowed', str(e.exception))
        self.assertEqual(st['orders'], [])
        board = Board()
        g = self.issuer(ctx, allow_paid=True)
        req = req_for(['www.firma.cz', 'firma.cz'], challenges={'www.firma.cz': board,
                                                                'firma.cz': board})
        out = g.issue(req)
        self.check_issued(out, req)
        f = st['orders'][0]
        self.assertEqual((f['product_id'], f['period'], f['dcv_method'], f['dns_names'],
                          f['server_count']), ('77', '12', 'dns', 'firma.cz', '1'))
        self.assertEqual((f['admin_firstname'], f['tech_email'], f['tech_title']),
                         ('Jan', 'it@firma.cz', 'IT'))
        self.assertIn(('cname', '_fea0www.www.firma.cz', '6849.153d.t024.comodoca.com'),
                      board.log)
        self.assertIn(('cname', '_fea0firma.firma.cz', '6849.153d.t024.comodoca.com'), board.log)
        self.assertEqual(board.cname, {})
        self.assertEqual(st['revalidated'], ['www.firma.cz'])
        self.assertEqual(st['auths'], 1)
        with self.assertRaises(PluginError) as e:
            g.revoke(out.cert_pem)
        self.assertIn('cannot revoke', str(e.exception))
        self.check('gogetssl', ctx.calls)
        self.assertFalse(any('APIPW' in w or 'KEY1' in w for _l, w in ctx.steps))

    def test_reissue_http_file_and_waiting(self):
        h, st = self.server(issue_after=3)
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        g = self.issuer(ctx, dcv='http', order_id='999', wait_issue=0)
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': here})
        with self.assertRaises(PluginError) as e:
            g.issue(req)
        self.assertIn('has not issued yet', str(e.exception))
        self.assertEqual(st['reissues'][0][0], '999')
        self.assertEqual(ctx.files, {('www.firma.cz', '/.well-known/pki-validation/FEA0.txt'):
                                     '6849ECE\ncomodoca.com\nt0767'})
        out = self.issuer(ctx, dcv='http', order_id='999').issue(req)
        self.check_issued(out, req)
        self.assertEqual(len(st['reissues']), 1)
        self.assertEqual(st['orders'], [])
        self.assertEqual(ctx.files, {})
        self.check('gogetssl', ctx.calls)

    def test_records_put_in_place_again_after_a_failed_try(self):
        h, st = self.server()
        ctx = CannedContext(h)

        class Flaky(Board):
            fails = 1

            def add_cname(self, fqdn, target):
                if Flaky.fails:
                    Flaky.fails -= 1
                    raise PluginError('the DNS API is down')
                Board.add_cname(self, fqdn, target)
        board = Flaky()
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': board})
        with self.assertRaises(PluginError):
            self.issuer(ctx, allow_paid=True).issue(req)
        self.assertEqual(len(st['orders']), 1)
        out = self.issuer(ctx, allow_paid=True).issue(req)
        self.check_issued(out, req)
        self.assertEqual(len(st['orders']), 1)               # not ordered (paid) twice
        self.assertIn(('cname', '_fea0www.www.firma.cz', '6849.153d.t024.comodoca.com'),
                      board.log)

    def test_catalog_list_fetch_cancel_and_wrong_password(self):
        h, st = self.server()
        ctx = CannedContext(h)
        g = self.issuer(ctx, order_id='1332864')
        self.assertEqual(g.catalog('products')['options'], [['77', 'Sectigo PositiveSSL - DV']])
        self.assertIn('1000.00 EUR', g.test())
        st['status'] = 'active'
        st['leaf'] = self.sign(csr_der_of(req_for(['www.firma.cz']).csr_pem), ['www.firma.cz'])
        items = {x['ref']: x for x in g.list_existing()}
        self.assertEqual(items['1332864']['names'], ['www.firma.cz', 'firma.cz'])
        self.assertTrue(items['1332864']['downloadable'])
        self.assertFalse(items['1332865']['downloadable'])
        got = g.fetch_existing('1332864')
        self.assertEqual([p7.Cert(x).subject_cn for x in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        self.assertIn('Cancell request submitted', g.action('cancel'))
        self.assertEqual(st['cancelled'][0]['order_id'], '1332864')
        self.check('gogetssl', ctx.calls)
        with self.assertRaises(PluginError) as e:
            self.issuer(CannedContext(h), api_password='nope').test()
        self.assertIn('Wrong username/password', str(e.exception))
        self.assertNotIn('nope', str(e.exception))

    def test_compat(self):
        self.assertEqual(GoGetSslIssuer.proofs_for({'dcv': 'dns'}), ['cname-any'])
        self.assertEqual(GoGetSslIssuer.proofs_for({'dcv': 'http'}), ['http-file-any'])
        self.assertEqual(GoGetSslIssuer.proofs_for({'dcv': 'email'}), [])


# ---------------------------------------------------------------------------
# Namecheap SSL
# ---------------------------------------------------------------------------
def nc(command, inner, status='OK', errors=''):
    return ('<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="%s" '
            'xmlns="http://api.namecheap.com/xml.response"><Errors>%s</Errors><Warnings />'
            '<RequestedCommand>%s</RequestedCommand><CommandResponse Type="%s">%s'
            '</CommandResponse><Server>X</Server></ApiResponse>' % (
                status, errors, command.lower(), command, inner))


class TestNamecheap(Base):
    def server(self, **kw):
        st = dict(commands=[], forms={}, leaf=None, status={}, polls=0, issue_after=1,
                  retried=0, revoked=[])
        st.update(kw)

        def dcv(names, how):
            if how == 'cname':
                return '<DNSDCValidation ValueAvailable="true">%s</DNSDCValidation>' % ''.join(
                    '<DNS domain="%s"><HostName><![CDATA[_4E33.%s]]></HostName><Target><![CDATA['
                    '6694.DE66.5a95.comodoca.com]]></Target></DNS>' % (n, n) for n in names)
            return '<HttpDCValidation ValueAvailable="true">%s</HttpDCValidation>' % ''.join(
                '<DNS domain="%s"><FileName><![CDATA[4E33.txt]]></FileName><FileContent><![CDATA['
                '6694 comodoca.com 5a95]]></FileContent></DNS>' % n for n in names)

        def handler(method, url, body, headers, cc):
            self.assertEqual(method, 'POST')
            self.assertEqual(url, 'https://api.sandbox.namecheap.com/xml.response')
            f = form_of(body)
            self.assertEqual((f['ApiUser'], f['ApiKey'], f['UserName'], f['ClientIp']),
                             ('ncuser', 'NCKEY', 'ncuser', '198.51.100.7'))
            cmd = f['Command']
            st['commands'].append(cmd)
            st['forms'][cmd] = f
            if cmd == 'namecheap.ssl.create':
                st['status']['5001'] = 'newpurchase'
                return 200, {}, nc(cmd, '<SSLCreateResult IsSuccess="true" OrderId="1" '
                                        'TransactionId="1" ChargedAmount="9.00"><SSLCertificate '
                                        'CertificateID="5001" Created="11/03/2026" SSLType="%s" '
                                        'Years="1" Status="NewPurchase"/></SSLCreateResult>'
                                   % f['Type'])
            if cmd in ('namecheap.ssl.activate', 'namecheap.ssl.reissue'):
                cid = f['CertificateID']
                names = [csr_cn(f['CSR'])] + [x for x in f.get('DNSNames', '').split(',') if x]
                st['leaf'] = self.sign(csr_der_of(f['CSR']), names)
                how = 'http' if f.get('HTTPDCValidation') or 'HTTPCSRHASH' in f.get(
                    'ApproverEmail', '') else 'cname'
                new = cid
                if cmd == 'namecheap.ssl.reissue':
                    new = '6001'
                    st['status']['6001'] = 'purchased'
                else:
                    st['status'][cid] = 'purchased'
                return 200, {}, nc(cmd, '<SSLActivateResult ID="%s" IsSuccess="true">%s'
                                        '</SSLActivateResult>' % (new, dcv(names, how)))
            if cmd == 'namecheap.ssl.resendApproverEmail':
                st['retried'] += 1
                return 200, {}, nc(cmd, '<SSLResendApproverEmailResult ID="%s" IsSuccess="true"/>'
                                   % f['CertificateID'])
            if cmd == 'namecheap.ssl.getInfo' and f['CertificateID'] != '77':
                cid = f['CertificateID']
                s = st['status'].get(cid, 'active')
                if s == 'purchased':
                    st['polls'] += 1
                    if st['polls'] >= st['issue_after']:
                        s = st['status'][cid] = 'active'
                certs = ''
                if s == 'active' and f.get('Returncertificate') == 'true':
                    self.assertEqual(f['Returntype'], 'Individual')
                    certs = ('<Certificates CertificateReturned="true" ReturnType="Individual">'
                             '<Certificate><![CDATA[%s]]></Certificate><CaCertificates>'
                             '<Certificate Type="INTERMEDIATE"><Certificate><![CDATA[%s]]>'
                             '</Certificate></Certificate><Certificate Type="ROOT"><Certificate>'
                             '<![CDATA[%s]]></Certificate></Certificate></CaCertificates>'
                             '</Certificates>' % (st['leaf'] or self.ca.pem, self.ca.pem,
                                                  self.root.pem))
                return 200, {}, nc(cmd, '<SSLGetInfoResult Status="%s" Type="positivessl" '
                                        'Expires="11/03/2027" SANSCount="0"><CertificateDetails>'
                                        '%s</CertificateDetails></SSLGetInfoResult>' % (s, certs))
            if cmd == 'namecheap.ssl.getList':
                return 200, {}, nc(cmd, '<SSLListResult><SSL CertificateID="5001" '
                                        'HostName="www.firma.cz" SSLType="PositiveSSL" '
                                        'PurchaseDate="11/03/2026" ExpireDate="11/03/2027" '
                                        'Status="active"/><SSL CertificateID="5002" '
                                        'HostName="x.firma.cz" SSLType="PositiveSSL" '
                                        'Status="newpurchase"/></SSLListResult><Paging>'
                                        '<TotalItems>2</TotalItems><CurrentPage>1</CurrentPage>'
                                        '<PageSize>100</PageSize></Paging>')
            if cmd == 'namecheap.ssl.revokecertificate':
                st['revoked'].append((f['CertificateID'], f['CertificateType']))
                return 200, {}, nc(cmd, '<RevokeCertificateResult IsSuccess="true" ID="%s"/>'
                                   % f['CertificateID'])
            return 200, {}, nc(cmd, '', status='ERROR', errors='<Error Number="2011294">'
                                                               'CertificateID is invalid</Error>')
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'env': 'sandbox', 'api_user': 'ncuser', 'api_key': 'NCKEY',
                'client_ip': '198.51.100.7', 'admin_email': 'it@firma.cz', 'poll_every': 1,
                'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        n = NamecheapSslIssuer(conf, ctx)
        n._sleep = lambda x: None
        return n

    def test_bought_activated_cname_issued_revoked(self):
        h, st = self.server()
        ctx = CannedContext(h)
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx).issue(req_for(['www.firma.cz']))
        self.assertIn('paid certificates are not allowed', str(e.exception))
        self.assertNotIn('namecheap.ssl.create', st['commands'])
        board = Board()
        n = self.issuer(ctx, allow_paid=True)
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': board})
        out = n.issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['forms']['namecheap.ssl.create']['Type'], 'PositiveSSL')
        a = st['forms']['namecheap.ssl.activate']
        self.assertEqual((a['CertificateID'], a['DNSDCValidation'], a['AdminEmailAddress']),
                         ('5001', 'true', 'it@firma.cz'))
        self.assertIn(('cname', '_4e33.www.firma.cz', '6694.de66.5a95.comodoca.com'), board.log)
        self.assertEqual(board.cname, {})
        self.assertEqual(st['retried'], 1)
        self.assertIn('revoked certificate 5001', n.revoke(out.cert_pem, 'superseded'))
        self.assertEqual(st['revoked'], [('5001', 'positivessl')])
        self.assertTrue(set(st['commands']) <= set(CONTRACT['namecheap_ssl']), st['commands'])
        self.assertFalse(any('NCKEY' in w for _l, w in ctx.steps))

    def test_reissue_http_multi_follows_the_child(self):
        h, st = self.server(issue_after=3)
        st['status']['4000'] = 'active'
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        n = self.issuer(ctx, dcv='http', cert_id='4000', wait_issue=0)
        req = req_for(['www.firma.cz', 'firma.cz'], challenges={'www.firma.cz': here,
                                                                'firma.cz': here})
        with self.assertRaises(PluginError) as e:
            n.issue(req)
        self.assertIn('has not issued yet', str(e.exception))
        r = st['forms']['namecheap.ssl.reissue']
        self.assertEqual((r['CertificateID'], r['ApproverEmail'], r['DNSNames'],
                          r['DNSApproverEmails']), ('4000', 'HTTPCSRHASH', 'firma.cz',
                                                     'HTTPCSRHASH'))
        self.assertNotIn('AdminEmailAddress', r)
        self.assertEqual(ctx.files[('www.firma.cz', '/.well-known/pki-validation/4E33.txt')],
                         '6694 comodoca.com 5a95')
        out = self.issuer(ctx, dcv='http', cert_id='4000').issue(req)
        self.check_issued(out, req)
        self.assertEqual(out.info['ref'], '6001')
        self.assertEqual(st['commands'].count('namecheap.ssl.reissue'), 1)
        self.assertNotIn('namecheap.ssl.create', st['commands'])
        self.assertEqual(ctx.files, {})

    def test_catalog_list_fetch_and_refusal(self):
        h, st = self.server()
        ctx = CannedContext(h)
        n = self.issuer(ctx)
        opts = n.catalog('types')['options']
        self.assertEqual(len(opts), 13)
        self.assertEqual(opts[0], ['PositiveSSL', 'PositiveSSL - DV, one name'])
        self.assertIn('2 certificate', n.test())
        st['leaf'] = self.sign(csr_der_of(req_for(['www.firma.cz']).csr_pem), ['www.firma.cz'])
        items = {x['ref']: x for x in n.list_existing()}
        self.assertTrue(items['5001']['downloadable'])
        self.assertFalse(items['5002']['downloadable'])
        got = n.fetch_existing('5001')
        self.assertEqual([p7.Cert(x).subject_cn for x in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        with self.assertRaises(PluginError) as e:
            n.info('77')
        self.assertIn('2011294 CertificateID is invalid', str(e.exception))
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, client_ip='2001:db8::1').test()
        self.assertIn('IPv4', str(e.exception))

    def test_compat(self):
        self.assertEqual(NamecheapSslIssuer.proofs_for({'dcv': 'cname'}), ['cname-any'])
        self.assertEqual(NamecheapSslIssuer.proofs_for({'dcv': 'http'}), ['http-file-any'])
        self.assertEqual(NamecheapSslIssuer.proofs_for({'dcv': 'email'}), [])


# ---------------------------------------------------------------------------
# AWS Private CA and EJBCA: their lists
# ---------------------------------------------------------------------------
class TestCatalogsOfPrivateCas(Base):
    def test_aws_templates(self):
        self.assertEqual(len(TEMPLATES), 18)
        self.assertTrue(all(t.startswith('arn:aws:acm-pca:::template/') and t.endswith('/V1')
                            for t in TEMPLATES))
        ctx = CannedContext(lambda *a: self.fail('the list asks nothing'))
        got = AwsPcaIssuer({}, ctx).catalog('templates')
        self.assertEqual([o[0] for o in got['options']], TEMPLATES)
        self.assertIn('default', got['options'][0][1])
        d = AwsPcaIssuer.describe()
        f = next(x for x in d['fields'] if x['key'] == 'template_arn')
        self.assertEqual((f['type'], f['catalog']), ('catalog', 'templates'))
        self.assertEqual(d['per_cert'][0]['catalog'], 'templates')
        with self.assertRaises(PluginError):
            AwsPcaIssuer({}, ctx).catalog('nothing')

    def test_ejbca_lists_and_community_said(self):
        def handler(method, url, body, headers, cc):
            p = urllib.parse.urlsplit(url).path
            if p.endswith('/v1/ca'):
                return 200, {}, {'certificate_authorities': [{'name': 'IssuingCA',
                                                              'subject_dn': 'CN=Issuing'}]}
            if p.endswith('/v2/endentity/profiles/authorized'):
                return 200, {}, {'end_entitie_profiles': [{'name': 'TLS', 'id': 1,
                                                           'description': 'servers'}]}
            if p.endswith('/v2/endentity/profile/TLS'):
                return 200, {}, {'end_entity_profile_name': 'TLS',
                                 'available_certificate_profiles': ['SERVER', 'SERVER2'],
                                 'available_cas': ['IssuingCA']}
            return 404, {}, {'error_code': 404, 'error_message': 'not found'}
        cfg = {'url': 'https://ejbca.example.test', 'client_cert': 'C', 'client_key': 'K',
               'ee_profile': 'TLS'}
        e = EjbcaIssuer(cfg, CannedContext(handler))
        self.assertEqual(e.catalog('cas')['options'], [['IssuingCA', 'IssuingCA (CN=Issuing)']])
        self.assertEqual(e.catalog('ee_profiles')['options'], [['TLS', 'TLS - servers']])
        self.assertEqual([o[0] for o in e.catalog('cert_profiles')['options']],
                         ['SERVER', 'SERVER2'])
        community = EjbcaIssuer(dict(cfg, ee_profile='OTHER'), CannedContext(handler))
        with self.assertRaises(PluginError) as err:
            community.catalog('cert_profiles')
        self.assertIn('Enterprise', str(err.exception))
        self.assertIn('type the name', str(err.exception))
        d = EjbcaIssuer.describe()
        types = {f['key']: f['type'] for f in d['fields']}
        self.assertEqual((types['ca_name'], types['cert_profile'], types['ee_profile']),
                         ('catalog', 'catalog', 'catalog'))
        self.assertEqual(d['per_cert'][0]['catalog'], 'cert_profiles')

    def test_ejbca_approval_said(self):
        def handler(method, url, body, headers, cc):
            return 202, {}, {}
        e = EjbcaIssuer({'url': 'https://ejbca.example.test', 'client_cert': 'C',
                         'client_key': 'K', 'ca_name': 'CA', 'cert_profile': 'P',
                         'ee_profile': 'E'}, CannedContext(handler))
        with self.assertRaises(PluginError) as err:
            e.issue(req_for(['www.example.test']))
        self.assertIn('approval', str(err.exception))
        self.assertTrue(err.exception.retry)


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
            for f in d['fields']:
                self.assertIn(f['type'], FIELD_TYPES)
                for k in (f.get('show_if') or {}):
                    self.assertIn(k, keys, '%s.%s' % (kind, f['key']))
                for k in f.get('depends') or []:
                    self.assertIn(k, keys, '%s.%s' % (kind, f['key']))
                if re.search(r'password|secret$|api_key$', f['key']):
                    self.assertEqual(f['type'], 'secret', '%s.%s' % (kind, f['key']))
                if f['type'] == 'catalog':
                    self.assertTrue(callable(getattr(cls, 'catalog', None)), kind)
            self.assertIn(cls.dcv_default, cls.dcv, kind)
            for pc in d['per_cert']:
                self.assertIn(pc['field'], keys, kind)

    def test_docs_name_the_sources(self):
        with open(os.path.join(ROOT, 'docs', 'sources.md'), encoding='utf-8') as f:
            text = f.read()
        for kind in KINDS:
            self.assertTrue('`%s`' % kind in text, kind)
        for where in ('scm-admin-api.openapi.json', 'PartnerApi-test.wsdl',
                      'gogetssl-api-v1.postman_collection.json',
                      'namecheap.com/support/api/methods/ssl/activate',
                      'template-varieties.html', '/v2/endentity/profiles/authorized',
                      'Entrust'):
            self.assertTrue(where in text, where)

    def test_every_english_sentence_translated(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = json.load(f)
        known = {v['source'] for v in cs['strings'].values() if v.get('text')}
        pats = {v['source'] for v in cs['patterns'].values() if v.get('text')}
        missing = []
        for kind in KINDS + ('aws_pca', 'ejbca'):
            strings, patterns = english_of(os.path.join(
                ROOT, 'acmelib', 'plugins', 'issuers', kind + '.py'))
            missing += sorted('%s: %s' % (kind, s) for s in strings if s not in known)
            missing += sorted('%s: PATTERN %s' % (kind, p) for p in patterns if p not in pats)
        self.assertEqual(missing, [], '\n'.join(missing))


if __name__ == '__main__':
    unittest.main()
