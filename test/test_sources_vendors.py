#!/usr/bin/env python3
"""ZeroSSL (REST API), CyberArk Certificate Manager Self-Hosted (Venafi TPP) and
SaaS (Venafi Cloud), Keyfactor Command and Cloudflare Origin CA - against canned
answers of the shapes their vendors' own clients read.

    python3 test/test_sources_vendors.py

No network. Each fake server signs the request it is sent with the test CA of
test_issuers_more and checks what the module sends: the path and method (a
contract per module, as the vendor's client has them - see docs/sources.md for
where each comes from), the headers that sign in, the bodies. ZeroSSL's DCV
records go in place through the placement API of the certificate's validation
(a DNS board, this server's HTTP files), as DigiCert's do. Every module also
lists and hands out the account's certificates (Import from a source), and
every English word of the modules is in web/lang/cs.json.
"""
import base64
import json
import os
import re
import sys
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

from test_issuers_more import Base, CannedContext, csr_der_of, hdr, p7_of, req_for  # noqa: E402
from test_digicert import Board, Files  # noqa: E402

from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.challenges.http_local import HttpLocal  # noqa: E402
from acmelib.plugins.issuers import _scep_pkcs7 as p7  # noqa: E402
from acmelib.plugins.issuers.cloudflare_origin_ca import CloudflareOriginCaIssuer  # noqa: E402
from acmelib.plugins.issuers.keyfactor_command import KeyfactorCommandIssuer  # noqa: E402
from acmelib.plugins.issuers.venafi_cloud import VenafiCloudIssuer  # noqa: E402
from acmelib.plugins.issuers.venafi_tpp import VenafiTppIssuer, policy_dn  # noqa: E402
from acmelib.plugins.issuers.zerossl import ZeroSslIssuer  # noqa: E402

KINDS = ('zerossl', 'venafi_tpp', 'venafi_cloud', 'keyfactor_command', 'cloudflare_origin_ca')

# Every call each module may make, as the vendor's own client makes it.
CONTRACT = {
    # github.com/caddyserver/zerossl endpoints.go
    'zerossl': [('POST', r'^/certificates$'), ('POST', r'^/certificates/\w+/challenges$'),
                ('GET', r'^/certificates/\w+$'), ('GET', r'^/certificates/\w+/download/return$'),
                ('GET', r'^/certificates$'), ('POST', r'^/certificates/\w+/revoke$')],
    # github.com/Venafi/vcert pkg/venafi/tpp/tpp.go (urlResource...)
    'venafi_tpp': [('POST', r'^/vedauth/authorize/oauth$'), ('GET', r'^/vedsdk/Identity/Self$'),
                   ('POST', r'^/vedsdk/certificates/request$'),
                   ('POST', r'^/vedsdk/certificates/retrieve$'),
                   ('POST', r'^/vedsdk/certificates/renew$'),
                   ('POST', r'^/vedsdk/certificates/revoke$'),
                   ('GET', r'^/vedsdk/certificates/$'),
                   ('POST', r'^/vedsdk/config/findobjectsofclass$')],
    # github.com/Venafi/vcert pkg/venafi/cloud/connector.go
    'venafi_cloud': [('GET', r'^/v1/useraccounts$'),
                     ('GET', r'^/outagedetection/v1/applications/name/[^/]+$'),
                     ('POST', r'^/outagedetection/v1/certificaterequests$'),
                     ('GET', r'^/outagedetection/v1/certificaterequests/[\w-]+$'),
                     ('GET', r'^/outagedetection/v1/certificates/[\w-]+$'),
                     ('GET', r'^/outagedetection/v1/certificates/[\w-]+/contents$'),
                     ('POST', r'^/outagedetection/v1/certificatesearch$')],
    # github.com/Keyfactor/keyfactor-go-client-sdk README.md (API list)
    'keyfactor_command': [('GET', r'^/KeyfactorAPI/Enrollment/CSR/Context/My$'),
                          ('POST', r'^/KeyfactorAPI/Enrollment/CSR$'),
                          ('GET', r'^/KeyfactorAPI/Certificates$'),
                          ('POST', r'^/KeyfactorAPI/Certificates/Download$'),
                          ('POST', r'^/KeyfactorAPI/Certificates/Revoke$')],
    # github.com/cloudflare/cloudflare-go origin_ca.go, zone.go, api_token.go
    'cloudflare_origin_ca': [('POST', r'^/client/v4/certificates$'),
                             ('GET', r'^/client/v4/certificates$'),
                             ('GET', r'^/client/v4/certificates/\w+$'),
                             ('DELETE', r'^/client/v4/certificates/\w+$'),
                             ('GET', r'^/client/v4/zones$'),
                             ('GET', r'^/client/v4/user/tokens/verify$'),
                             ('GET', r'^/ssl/static/origin_ca_(rsa|ecc)_root\.pem$')],
}


def english_of(path):
    """What test_ssls reads of a module (its form, errors, steps by _say, returns) and
    the steps these modules say through _source_common.say(ctx, words)."""
    import ast
    from test_ssls import _english_of_module
    strings, patterns = _english_of_module(path)

    def add(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value
            if len(re.findall(r'[A-Za-z]{2,}', s)) < 2:
                return
            if '%' in s:
                n = [0]

                def slot(_m):
                    n[0] += 1
                    return '{%d}' % (n[0] - 1)
                patterns.add(re.sub(r'%[sd]', slot, s))
            else:
                strings.add(s)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            add(node.left)
        elif isinstance(node, ast.IfExp):
            add(node.body)
            add(node.orelse)
    with open(path, encoding='utf-8') as f:
        tree = ast.parse(f.read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                node.func.attr == 'say' and len(node.args) >= 2:
            add(node.args[1])
    return strings, patterns


class Contract(object):
    """Records each call and checks it is one of the module's contract."""
    def check(self, kind, calls):
        for c in calls:
            u = urllib.parse.urlsplit(c['url'])
            self.assertTrue(any(c['method'] == m and re.match(rx, u.path)
                                for m, rx in CONTRACT[kind]),
                            '%s %s is not in the contract of %s' % (c['method'], u.path, kind))


# ---------------------------------------------------------------------------
# ZeroSSL
# ---------------------------------------------------------------------------
class TestZeroSsl(Contract, Base):
    def server(self, **kw):
        st = dict(made=0, issue_after=1, polls=0, method=None, emails=None, leaf=None,
                  status='draft', bodies=[], revoked=[], key_seen=[])
        st.update(kw)
        cid = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            q = dict(urllib.parse.parse_qsl(u.query))
            st['key_seen'].append(hdr(headers, 'Authorization') or ('q:' + q.get('access_key',
                                                                                  '')))
            b = json.loads(body) if body else {}
            p = u.path
            if p == '/certificates' and method == 'POST':
                st['made'] += 1
                st['bodies'].append(b)
                names = b['certificate_domains'].split(',')
                st['leaf'] = self.sign(csr_der_of(b['certificate_csr']), names)
                other = {n: {'file_validation_url_http': 'http://%s/.well-known/pki-validation/'
                                                         'ABCDEF.txt' % n.lstrip('*.'),
                             'file_validation_content': ['HASH1', 'comodoca.com', 'TOK'],
                             'cname_validation_p1': '_ABCDEF.%s' % n.lstrip('*.'),
                             'cname_validation_p2': 'AA.BB.ID.zerossl.com'} for n in names}
                return 200, {}, {'id': cid, 'status': 'draft', 'common_name': names[0],
                                 'validation': {'email_validation': {
                                     n: ['admin@%s' % n, 'webmaster@%s' % n] for n in names},
                                     'other_methods': other}}
            if p == '/certificates/%s/challenges' % cid:
                st['method'] = b.get('validation_method')
                st['emails'] = b.get('validation_email')
                st['status'] = 'pending_validation'
                return 200, {}, {'id': cid, 'status': 'pending_validation'}
            if p == '/certificates/%s' % cid:
                st['polls'] += 1
                if st['status'] == 'pending_validation' and st['polls'] >= st['issue_after']:
                    st['status'] = 'issued'
                return 200, {}, {'id': cid, 'status': st['status']}
            if p == '/certificates/%s/download/return' % cid:
                return 200, {}, {'certificate.crt': st['leaf'],
                                 'ca_bundle.crt': self.ca.pem + self.root.pem}
            if p == '/certificates/%s/revoke' % cid:
                st['revoked'].append(q.get('reason'))
                return 200, {}, {'success': 1}
            if p == '/certificates' and method == 'GET':
                return 200, {}, {'total_count': 2, 'result_count': 2, 'page': '1', 'limit': 100,
                                 'results': [
                                     {'id': cid, 'common_name': 'www.firma.cz',
                                      'additional_domains': 'firma.cz', 'status': 'issued',
                                      'created': '2026-10-01 10:00:00',
                                      'expires': '2026-12-30 23:59:59'},
                                     {'id': 'f' * 32, 'common_name': 'x.firma.cz',
                                      'additional_domains': '', 'status': 'draft',
                                      'created': '2026-10-02 10:00:00',
                                      'expires': '2026-12-31 23:59:59'}]}
            return 200, {}, {'success': False, 'error': {'code': 2800, 'type': 'invalid_api'}}
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'api_key': 'ZKEY', 'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        z = ZeroSslIssuer(conf, ctx)
        z._sleep = lambda s: None
        return z

    def test_cname_placed_issued_and_taken_away(self):
        h, st = self.server()
        ctx = CannedContext(h)
        board = Board()
        z = self.issuer(ctx)
        req = req_for(['www.firma.cz', 'firma.cz'], challenges={'www.firma.cz': board,
                                                                'firma.cz': board})
        out = z.issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['bodies'][0]['certificate_domains'], 'www.firma.cz,firma.cz')
        self.assertEqual(st['bodies'][0]['strict_domains'], 1)
        self.assertEqual(st['bodies'][0]['certificate_validity_days'], 90)
        self.assertEqual(st['method'], 'CNAME_CSR_HASH')
        self.assertIn(('cname', '_abcdef.www.firma.cz', 'aa.bb.id.zerossl.com'), board.log)
        self.assertEqual(board.cname, {})                   # taken away again
        self.assertEqual(set(st['key_seen']), {'ApiKey ZKEY'})
        self.assertEqual(out.info['ref'], 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')
        self.assertIn('ZeroSSL revoked', z.revoke(out.cert_pem, 'keyCompromise'))
        self.assertEqual(st['revoked'], ['keyCompromise'])
        self.check('zerossl', ctx.calls)
        # the key never in a step
        self.assertFalse(any('ZKEY' in w for _l, w in ctx.steps))

    def test_waiting_kept_then_asked_again_not_made_twice(self):
        h, st = self.server(issue_after=3)
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        z = self.issuer(ctx, dcv='http', wait_issue=0)
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': here})
        with self.assertRaises(PluginError) as e:
            z.issue(req)
        self.assertIn('has not issued yet', str(e.exception))
        self.assertEqual(ctx.files, {('www.firma.cz', '/.well-known/pki-validation/ABCDEF.txt'):
                                     'HASH1\ncomodoca.com\nTOK'})
        self.assertEqual(st['method'], 'HTTP_CSR_HASH')
        z = self.issuer(ctx, dcv='http')
        out = z.issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['made'], 1)
        self.assertEqual(ctx.files, {})

    def test_email_and_query_key_and_wildcard_by_http_refused(self):
        h, st = self.server()
        ctx = CannedContext(h)
        z = self.issuer(ctx, dcv='email', approver='webmaster', key_in='query')
        self.assertFalse(z.needs_challenge)
        out = z.issue(req_for(['www.firma.cz']))
        self.assertTrue(out.cert_pem)
        self.assertEqual((st['method'], st['emails']), ('EMAIL', 'webmaster@www.firma.cz'))
        self.assertEqual(set(st['key_seen']), {'q:ZKEY'})
        with self.assertRaises(PluginError) as e:
            self.issuer(ctx, dcv='http').issue(req_for(['*.firma.cz']))
        self.assertIn('wildcard', str(e.exception))

    def test_refusal_said_in_words_without_the_key(self):
        def handler(method, url, body, headers, cc):
            return 200, {}, {'success': False, 'error': {'code': 101,
                                                         'type': 'invalid_access_key'}}
        z = self.issuer(CannedContext(handler), key_in='query')
        with self.assertRaises(PluginError) as e:
            z.test()
        self.assertIn('invalid_access_key', str(e.exception))
        self.assertIn('API key is wrong', str(e.exception))
        self.assertNotIn('ZKEY', str(e.exception) + (e.exception.detail or ''))

    def test_list_and_fetch(self):
        h, st = self.server()
        ctx = CannedContext(h)
        z = self.issuer(ctx)
        z.issue(req_for(['www.firma.cz'], challenges={'www.firma.cz': Board()}))
        items = {x['ref']: x for x in z.list_existing()}
        one = items['a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6']
        self.assertEqual(one['names'], ['www.firma.cz', 'firma.cz'])
        self.assertTrue(one['downloadable'])
        self.assertEqual(one['acme_cert_id'], 7)
        self.assertEqual(one['not_after'], 1798675199)
        self.assertFalse(items['f' * 32]['downloadable'])
        got = z.fetch_existing('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6')
        self.assertEqual([p7.Cert(c).subject_cn for c in got['chain_pems']],
                         ['More Issuing CA', 'More Root X1'])
        with self.assertRaises(PluginError):
            z.fetch_existing('../x')
        self.assertIn('2 certificate', z.test())
        self.check('zerossl', ctx.calls)

    def test_compat(self):
        self.assertEqual(ZeroSslIssuer.proofs_for({'dcv': 'cname'}), ['cname-any'])
        self.assertEqual(ZeroSslIssuer.proofs_for({'dcv': 'http'}), ['http-file-any'])
        self.assertEqual(ZeroSslIssuer.proofs_for({'dcv': 'email'}), [])
        self.assertTrue(ZeroSslIssuer.public_for({}))


# ---------------------------------------------------------------------------
# CyberArk Certificate Manager Self-Hosted (Venafi TPP)
# ---------------------------------------------------------------------------
class TestVenafiTpp(Contract, Base):
    def server(self, pending=0):
        st = dict(leaf=None, retrieves=0, bodies={}, logins=0, revoked=[], renewed=[])

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            p = u.path
            b = json.loads(body) if body else {}
            if p == '/vedauth/authorize/oauth':
                st['logins'] += 1
                self.assertEqual(b, {'client_id': 'vcert-sdk', 'username': 'acme',
                                     'password': 'pw', 'scope': 'certificate:manage,revoke'})
                return 200, {}, {'access_token': 'TOK', 'expires': time.time() + 3600}
            self.assertEqual(hdr(headers, 'Authorization'), 'Bearer TOK')
            st['bodies'][p] = b
            if p == '/vedsdk/certificates/request':
                self.assertEqual(b['PolicyDN'], '\\VED\\Policy\\DevOps\\Web')
                st['leaf'] = self.sign(csr_der_of(b['PKCS10']), [s['Name'] for s in
                                                               b['SubjectAltNames']])
                return 200, {}, {'CertificateDN': '\\VED\\Policy\\DevOps\\Web\\www.firma.cz'}
            if p == '/vedsdk/certificates/renew':
                st['renewed'].append(b['CertificateDN'])
                st['leaf'] = self.sign(csr_der_of(b['PKCS10']), ['www.firma.cz'])
                return 200, {}, {'Success': True}
            if p == '/vedsdk/certificates/retrieve':
                st['retrieves'] += 1
                self.assertEqual(b['Format'], 'base64')
                self.assertTrue(b['IncludeChain'])
                if st['retrieves'] <= pending:
                    return 202, {}, {'Status': 'Post CSR', 'Stage': 500}
                pem = st['leaf'] + self.ca.pem + self.root.pem
                return 200, {}, {'CertificateData': base64.b64encode(pem.encode()).decode(),
                                 'Format': 'Base64'}
            if p == '/vedsdk/certificates/revoke':
                st['revoked'].append(b)
                return 200, {}, {'Requested': True, 'Success': True}
            if p == '/vedsdk/Identity/Self':
                return 200, {}, {'Identities': [{'Name': 'acme', 'FullName': '\\VED\\Identity\\acme'}]}
            if p == '/vedsdk/config/findobjectsofclass':
                self.assertEqual(b, {'Class': 'Policy', 'ObjectDN': '\\VED\\Policy'})
                return 200, {}, {'Objects': [{'DN': '\\VED\\Policy\\DevOps', 'Name': 'DevOps'},
                                             {'DN': '\\VED\\Policy\\DevOps\\Web', 'Name': 'Web'}]}
            if p == '/vedsdk/certificates/':
                q = dict(urllib.parse.parse_qsl(u.query))
                self.assertEqual(q['ParentDNRecursive'], '\\VED\\Policy\\DevOps\\Web')
                self.assertIn('ValidToGreater', q)
                return 200, {}, {'Certificates': [{
                    'DN': '\\VED\\Policy\\DevOps\\Web\\www.firma.cz',
                    'X509': {'CN': 'www.firma.cz', 'SANS': {'DNS': ['www.firma.cz', 'firma.cz']},
                             'Serial': '0a1b', 'Thumbprint': 'AB',
                             'ValidFrom': '2026-10-01T00:00:00.0000000Z',
                             'ValidTo': '2027-01-01T00:00:00.0000000Z'}}]}
            return 404, {}, {'Error': 'no ' + p}
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'url': 'https://tpp.example.test/vedsdk', 'user': 'acme', 'password': 'pw',
                'zone': 'DevOps\\Web', 'poll_every': 1, 'wait': 5}
        conf.update(cfg)
        v = VenafiTppIssuer(conf, ctx)
        v._sleep = lambda s: None
        return v

    def test_request_retrieve_renew_revoke(self):
        h, st = self.server(pending=1)
        ctx = CannedContext(h)
        v = self.issuer(ctx)
        req = req_for(['www.firma.cz', '10.0.0.5'])
        out = v.issue(req)
        self.check_issued(out, req)
        body = st['bodies']['/vedsdk/certificates/request']
        self.assertEqual(body['SubjectAltNames'], [{'Type': 2, 'Name': 'www.firma.cz'},
                                                   {'Type': 7, 'Name': '10.0.0.5'}])
        self.assertTrue(body['DisableAutomaticRenewal'])
        self.assertEqual(st['retrieves'], 2)
        dn = '\\VED\\Policy\\DevOps\\Web\\www.firma.cz'
        self.assertEqual(out.info['ref'], dn)
        # the renewal renews the same object
        out2 = v.issue(req_for(['www.firma.cz', '10.0.0.5']))
        self.assertEqual(st['renewed'], [dn])
        self.assertTrue(out2.cert_pem)
        self.assertIn('took the revocation', v.revoke(out.cert_pem, 'superseded'))
        self.assertEqual(st['revoked'][0]['Reason'], 4)
        self.assertEqual(len(st['revoked'][0]['Thumbprint']), 40)
        self.assertIn('\\VED\\Identity\\acme', v.test())
        self.check('venafi_tpp', ctx.calls)

    def test_pending_kept_and_token_mode(self):
        h, st = self.server(pending=50)
        ctx = CannedContext(h)
        v = self.issuer(ctx, auth='token', access_token='TOK', wait=0)
        with self.assertRaises(PluginError) as e:
            v.issue(req_for(['www.firma.cz']))
        self.assertIn('has not issued', str(e.exception))
        self.assertEqual(st['logins'], 0)
        self.assertTrue(any(k.startswith('venafi-tpp-pending:') for k in ctx.kv))

    def test_catalog_list_fetch(self):
        h, st = self.server()
        ctx = CannedContext(h)
        v = self.issuer(ctx)
        got = v.catalog('zones')
        self.assertEqual([o[0] for o in got['options']], ['DevOps', 'DevOps\\Web'])
        items = v.list_existing()
        self.assertEqual(items[0]['names'], ['www.firma.cz', 'firma.cz'])
        self.assertEqual(items[0]['serial'], '0A1B')
        self.assertEqual(items[0]['not_after'], 1798761600)
        v.issue(req_for(['www.firma.cz']))
        got = v.fetch_existing(items[0]['ref'])
        self.assertEqual(len(got['chain_pems']), 2)
        with self.assertRaises(PluginError):
            v.fetch_existing('somewhere else')
        self.assertEqual(policy_dn('\\VED\\Policy\\X'), '\\VED\\Policy\\X')
        self.assertEqual(policy_dn('\\X'), '\\VED\\Policy\\X')
        self.check('venafi_tpp', ctx.calls)

    def test_typed_folder_wins_and_imported_ref_renews(self):
        h, st = self.server()
        ctx = CannedContext(h)
        v = self.issuer(ctx, zone='Elsewhere', zone_typed='DevOps\\Web')
        self.assertEqual(v.zone(), '\\VED\\Policy\\DevOps\\Web')
        req = req_for(['www.firma.cz'], ref='\\VED\\Policy\\DevOps\\Web\\imported')
        v.issue(req)
        self.assertEqual(st['renewed'], ['\\VED\\Policy\\DevOps\\Web\\imported'])


# ---------------------------------------------------------------------------
# CyberArk Certificate Manager SaaS (Venafi Cloud)
# ---------------------------------------------------------------------------
class TestVenafiCloud(Contract, Base):
    def server(self, wait=0):
        st = dict(leaf=None, polls=0, bodies=[], searches=[])

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            self.assertEqual(u.netloc, 'api.venafi.eu')
            self.assertEqual(hdr(headers, 'tppl-api-key'), 'VKEY')
            p = u.path
            b = json.loads(body) if body else {}
            if p == '/v1/useraccounts':
                return 200, {}, {'user': {'username': 'ann@firma.cz'}, 'company': {'name': 'Firma'}}
            if p == '/outagedetection/v1/applications/name/Store%20front':
                return 200, {}, {'id': 'app-1', 'certificateIssuingTemplateAliasIdMap': {
                    'Public Trust': 'cit-1', 'Default': 'cit-0'}}
            if p == '/outagedetection/v1/certificaterequests' and method == 'POST':
                st['bodies'].append(b)
                st['leaf'] = self.sign(csr_der_of(b['certificateSigningRequest']),
                                       ['www.firma.cz'])
                return 201, {}, {'certificateRequests': [{'id': 'req-1', 'status': 'REQUESTED'}]}
            if p == '/outagedetection/v1/certificaterequests/req-1':
                st['polls'] += 1
                if st['polls'] <= wait:
                    return 200, {}, {'id': 'req-1', 'status': 'PENDING'}
                return 200, {}, {'id': 'req-1', 'status': 'ISSUED', 'certificateIds': ['cert-1'],
                                 'applicationId': 'app-1',
                                 'certificateIssuingTemplateId': 'cit-1'}
            if p == '/outagedetection/v1/certificates/cert-1':
                return 200, {}, {'id': 'cert-1', 'certificateRequestId': 'req-1'}
            if p == '/outagedetection/v1/certificates/cert-1/contents':
                self.assertEqual(dict(urllib.parse.parse_qsl(u.query)),
                                 {'chainOrder': 'EE_FIRST', 'format': 'PEM'})
                return 200, {}, st['leaf'] + self.ca.pem + self.root.pem
            if p == '/outagedetection/v1/certificatesearch':
                st['searches'].append(b)
                return 200, {}, {'count': 1, 'certificates': [{
                    'id': 'cert-1', 'subjectCN': ['www.firma.cz'],
                    'subjectAlternativeNamesByType': {'dNSName': ['www.firma.cz', 'firma.cz']},
                    'serialNumber': '0c', 'validityStart': '2026-10-01T00:00:00.000+00:00',
                    'validityEnd': '2027-01-01T00:00:00.000+00:00'}]}
            return 404, {}, {'errors': [{'message': 'no ' + p}]}
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'region': 'eu', 'api_key': 'VKEY', 'application': 'Store front',
                'template': 'Public Trust', 'poll_every': 1, 'wait': 5}
        conf.update(cfg)
        v = VenafiCloudIssuer(conf, ctx)
        v._sleep = lambda s: None
        return v

    def test_request_then_renewal_of_it(self):
        h, st = self.server(wait=1)
        ctx = CannedContext(h)
        v = self.issuer(ctx, days=30)
        req = req_for(['www.firma.cz'])
        out = v.issue(req)
        self.check_issued(out, req)
        self.assertEqual(st['bodies'][0]['applicationId'], 'app-1')
        self.assertEqual(st['bodies'][0]['certificateIssuingTemplateId'], 'cit-1')
        self.assertEqual(st['bodies'][0]['validityPeriod'], 'P30D')
        self.assertNotIn('existingCertificateId', st['bodies'][0])
        self.assertEqual(out.info['ref'], 'cert-1')
        v.issue(req_for(['www.firma.cz']))
        self.assertEqual(st['bodies'][1]['existingCertificateId'], 'cert-1')
        self.assertIn('ann@firma.cz', v.test())
        self.assertEqual(v.catalog('templates')['options'], [['Default', 'Default'],
                                                             ['Public Trust', 'Public Trust']])
        self.check('venafi_cloud', ctx.calls)

    def test_unknown_template_said(self):
        h, st = self.server()
        v = self.issuer(CannedContext(h), template='Nope')
        with self.assertRaises(PluginError) as e:
            v.issue(req_for(['www.firma.cz']))
        self.assertIn('Public Trust', str(e.exception))
        self.assertEqual(st['bodies'], [])

    def test_list_and_fetch(self):
        h, st = self.server()
        ctx = CannedContext(h)
        v = self.issuer(ctx)
        v.issue(req_for(['www.firma.cz']))
        items = v.list_existing()
        self.assertEqual(items[0]['ref'], 'cert-1')
        self.assertEqual(items[0]['names'], ['www.firma.cz', 'firma.cz'])
        self.assertEqual(items[0]['acme_cert_id'], 7)
        ops = st['searches'][0]['expression']['operands']
        self.assertEqual(ops[0], {'field': 'appstackIds', 'operator': 'MATCH', 'value': 'app-1'})
        self.assertEqual(st['searches'][0]['paging'], {'pageNumber': 0, 'pageSize': 50})
        got = v.fetch_existing('cert-1')
        self.assertEqual(len(got['chain_pems']), 2)
        with self.assertRaises(PluginError):
            v.revoke(got['cert_pem'])                   # not offered: GraphQL in vcert
        self.check('venafi_cloud', ctx.calls)


# ---------------------------------------------------------------------------
# Keyfactor Command
# ---------------------------------------------------------------------------
class TestKeyfactor(Contract, Base):
    def server(self, disposition='ISSUED'):
        st = dict(leaf=None, bodies={}, auth=[], revoked=[], queries=[])

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            if u.netloc == 'idp.example.test':
                f = dict(urllib.parse.parse_qsl(body.decode()))
                self.assertEqual(f, {'grant_type': 'client_credentials', 'client_id': 'acme',
                                     'client_secret': 'S', 'scope': 'kf'})
                return 200, {}, {'access_token': 'OT', 'expires_in': 300}
            self.assertEqual(hdr(headers, 'x-keyfactor-api-version'), '1')
            self.assertEqual(hdr(headers, 'x-keyfactor-requested-with'), 'APIClient')
            st['auth'].append(hdr(headers, 'Authorization'))
            p = u.path
            b = json.loads(body) if body else {}
            st['bodies'][p] = b
            if p == '/KeyfactorAPI/Enrollment/CSR/Context/My':
                return 200, {}, {'Templates': [
                    {'Name': 'WebServer', 'DisplayName': 'Web Server', 'RequiresApproval': False,
                     'CAs': [{'Name': 'ca01.example.test\\Issuing CA'}]},
                    {'Name': 'Approved', 'DisplayName': 'Approved', 'RequiresApproval': True,
                     'CAs': [{'Name': 'a\\A'}, {'Name': 'b\\B'}]}],
                    'StandaloneCAs': [{'Name': 'ejbca\\Other'}]}
            if p == '/KeyfactorAPI/Enrollment/CSR':
                self.assertEqual(hdr(headers, 'x-certificateformat'), 'PEM')
                if disposition != 'ISSUED':
                    return 200, {}, {'CertificateInformation': {
                        'RequestDisposition': disposition, 'KeyfactorRequestId': 44,
                        'DispositionMessage': 'Waiting for approval', 'Certificates': []}}
                st['leaf'] = self.sign(csr_der_of(b['CSR']), b['SANs']['dns'])
                return 200, {}, {'CertificateInformation': {
                    'SerialNumber': '0D', 'KeyfactorID': 321, 'KeyfactorRequestId': 44,
                    'RequestDisposition': 'ISSUED',
                    'Certificates': [st['leaf'], self.ca.pem, self.root.pem]}}
            if p == '/KeyfactorAPI/Certificates' and method == 'GET':
                q = dict(urllib.parse.parse_qsl(u.query))
                st['queries'].append(q)
                if 'pq.queryString' in q and q['pq.queryString'].startswith('Thumbprint'):
                    return 200, {}, [{'Id': 99}]
                return 200, {}, [{'Id': 321, 'IssuedCN': 'www.firma.cz', 'SerialNumber': '0d',
                                  'NotBefore': '2026-10-01T00:00:00Z',
                                  'NotAfter': '2027-01-01T00:00:00Z',
                                  'CertStateString': 'Active', 'TemplateName': 'Web Server',
                                  'SubjectAltNameElements': [{'Value': 'www.firma.cz', 'Type': 4},
                                                             {'Value': 'firma.cz', 'Type': 4}]}]
            if p == '/KeyfactorAPI/Certificates/Download':
                self.assertEqual(hdr(headers, 'x-certificateformat'), 'P7B')
                self.assertEqual(b, {'CertID': 321, 'IncludeChain': True})
                return 200, {}, {'Content': base64.b64encode(p7_of([st['leaf'], self.ca.pem,
                                                                   self.root.pem])).decode()}
            if p == '/KeyfactorAPI/Certificates/Revoke':
                st['revoked'].append(b)
                return 204, {}, b''
            return 404, {}, {'Message': 'no ' + p}
        return handler, st

    def issuer(self, ctx, **cfg):
        conf = {'url': 'https://kf.example.test', 'domain': 'EXAMPLE', 'user': 'acme',
                'password': 'pw', 'template': 'WebServer', 'ca': 'ca01.example.test\\Issuing CA'}
        conf.update(cfg)
        return KeyfactorCommandIssuer(conf, ctx)

    def test_enroll_basic_revoke_list_fetch(self):
        h, st = self.server()
        ctx = CannedContext(h)
        k = self.issuer(ctx)
        req = req_for(['www.firma.cz', 'firma.cz', '10.1.2.3'])
        out = k.issue(req)
        self.check_issued(out, req)
        body = st['bodies']['/KeyfactorAPI/Enrollment/CSR']
        self.assertEqual(body['Template'], 'WebServer')
        self.assertEqual(body['CertificateAuthority'], 'ca01.example.test\\Issuing CA')
        self.assertEqual(body['SANs'], {'dns': ['www.firma.cz', 'firma.cz'], 'ip4': ['10.1.2.3']})
        self.assertEqual(st['auth'][0], 'Basic ' + base64.b64encode(
            b'EXAMPLE\\acme:pw').decode())
        self.assertEqual(out.info['ref'], '321')
        self.assertIn('revoked certificate 321', k.revoke(out.cert_pem, 'keyCompromise'))
        self.assertEqual(st['revoked'][0]['CertificateIds'], [321])
        self.assertEqual(st['revoked'][0]['Reason'], 1)
        items = k.list_existing()
        self.assertEqual(items[0]['names'], ['www.firma.cz', 'firma.cz'])
        self.assertEqual(items[0]['acme_cert_id'], 7)
        self.assertEqual(st['queries'][-1]['pq.includeExpired'], 'false')
        got = k.fetch_existing('321')
        self.assertEqual(len(got['chain_pems']), 2)
        self.check('keyfactor_command', ctx.calls)

    def test_oauth_catalog_and_approval_said(self):
        h, st = self.server(disposition='EXTERNAL VALIDATION PENDING')
        ctx = CannedContext(h)
        k = self.issuer(ctx, auth='oauth', token_url='https://idp.example.test/token',
                        client_id='acme', client_secret='S', scope='kf')
        temps = k.catalog('templates')
        self.assertEqual(temps['options'][0], ['Approved', 'Approved (needs an approval)'])
        self.assertEqual(temps['sets'], {'WebServer': {'ca': 'ca01.example.test\\Issuing CA'}})
        self.assertEqual(k.catalog('cas')['options'],
                         [['ca01.example.test\\Issuing CA', 'ca01.example.test\\Issuing CA'],
                          ['ejbca\\Other', 'ejbca\\Other']])
        self.assertIn('among them', k.test())
        with self.assertRaises(PluginError) as e:
            k.issue(req_for(['www.firma.cz']))
        self.assertIn('approval', str(e.exception))
        self.assertEqual(set(st['auth']), {'Bearer OT'})
        # a revocation of a certificate acme did not make: found by its thumbprint
        leaf = self.sign(req_for(['x.firma.cz']).csr_der, ['x.firma.cz'])
        k.revoke(leaf)
        self.assertEqual(st['revoked'][0]['CertificateIds'], [99])
        self.check('keyfactor_command', [c for c in ctx.calls if 'idp.' not in c['url']])

    def test_typed_wins(self):
        k = self.issuer(CannedContext(lambda *a: (500, {}, b'')), template_typed='Other',
                        ca_typed='x\\Y')
        self.assertEqual((k.template(), k.ca()), ('Other', 'x\\Y'))


# ---------------------------------------------------------------------------
# Cloudflare Origin CA
# ---------------------------------------------------------------------------
class TestCloudflareOriginCa(Contract, Base):
    ZONE = '023e105f4ecef8ad9ca31a8372d0c353'

    def server(self):
        st = dict(leaf=None, bodies=[], deleted=[], heads=[])

        def handler(method, url, body, headers, cc):
            u = urllib.parse.urlsplit(url)
            p = u.path
            if u.netloc == 'developers.cloudflare.com':
                return 200, {}, self.root.pem
            st['heads'].append(hdr(headers, 'Authorization') or
                               'svc:' + str(hdr(headers, 'X-Auth-User-Service-Key')))
            q = dict(urllib.parse.parse_qsl(u.query))
            b = json.loads(body) if body else {}
            if p == '/client/v4/certificates' and method == 'POST':
                st['bodies'].append(b)
                st['leaf'] = self.ca.sign_csr(csr_der_of(b['csr']), b['hostnames'])
                return 200, {}, {'success': True, 'errors': [], 'messages': [],
                                 'result': {'id': '328578533902268680212849205732770752308931942',
                                            'certificate': st['leaf'],
                                            'hostnames': b['hostnames'],
                                            'request_type': b['request_type'],
                                            'requested_validity': b['requested_validity']}}
            if p == '/client/v4/certificates' and method == 'GET':
                self.assertEqual(q['zone_id'], self.ZONE)
                return 200, {}, {'success': True, 'result': [
                    {'id': '111', 'certificate': st['leaf'], 'hostnames': ['www.firma.cz'],
                     'request_type': 'origin-ecc', 'requested_validity': 90},
                    {'id': '222', 'certificate': st['leaf'], 'hostnames': ['old.firma.cz'],
                     'revoked_at': '2026-01-01T00:00:00Z'}],
                    'result_info': {'page': 1, 'per_page': 50, 'total_pages': 1,
                                    'total_count': 2}}
            if p == '/client/v4/certificates/111' and method == 'GET':
                return 200, {}, {'success': True, 'result': {'id': '111',
                                                             'certificate': st['leaf'],
                                                             'request_type': 'origin-ecc'}}
            if p.startswith('/client/v4/certificates/') and method == 'DELETE':
                st['deleted'].append(p.rsplit('/', 1)[1])
                return 200, {}, {'success': True, 'result': {'id': p.rsplit('/', 1)[1]}}
            if p == '/client/v4/zones':
                return 200, {}, {'success': True, 'result': [{'id': self.ZONE,
                                                              'name': 'firma.cz'}],
                                 'result_info': {'page': 1, 'total_pages': 1}}
            if p == '/client/v4/user/tokens/verify':
                return 200, {}, {'success': True, 'result': {'id': 't', 'status': 'active'}}
            return 403, {}, {'success': False, 'errors': [{'code': 10000,
                                                           'message': 'Authentication error'}]}
        return handler, st

    def test_issue_root_chain_revoke(self):
        h, st = self.server()
        ctx = CannedContext(h)
        cf = CloudflareOriginCaIssuer({'api_token': 'CFT', 'validity': '365'}, ctx)
        req = req_for(['www.firma.cz', '*.firma.cz'])
        out = cf.issue(req)
        leaf = p7.Cert(out.cert_pem)
        self.assertEqual(leaf.spki_der, p7.csr_spki(req.csr_der))
        self.assertEqual([p7.Cert(c).subject_cn for c in out.chain_pems], ['More Root X1'])
        self.assertEqual(st['bodies'][0]['request_type'], 'origin-ecc')       # an EC key
        self.assertEqual(st['bodies'][0]['requested_validity'], 365)
        self.assertEqual(st['bodies'][0]['hostnames'], ['www.firma.cz', '*.firma.cz'])
        self.assertIn('revoked', cf.revoke(out.cert_pem))
        self.assertEqual(st['deleted'], ['328578533902268680212849205732770752308931942'])
        self.assertEqual(set(st['heads']), {'Bearer CFT'})
        self.assertIn('active', cf.test())
        self.check('cloudflare_origin_ca', ctx.calls)
        rsa = req_for(['www.firma.cz'], kind='rsa', key_type='rsa-2048')
        cf.issue(rsa)
        self.assertEqual(st['bodies'][1]['request_type'], 'origin-rsa')

    def test_service_key_zones_list_fetch_and_refusal(self):
        h, st = self.server()
        ctx = CannedContext(h)
        cf = CloudflareOriginCaIssuer({'auth': 'service_key', 'service_key': 'v1.0-KEY'}, ctx)
        self.assertEqual(cf.catalog('zones')['options'], [[self.ZONE, 'firma.cz']])
        with self.assertRaises(PluginError):
            cf.list_existing()                          # no zone set yet
        cf.config['zone'] = self.ZONE
        cf.issue(req_for(['www.firma.cz']))
        items = {x['ref']: x for x in cf.list_existing()}
        self.assertTrue(items['111']['downloadable'])
        self.assertEqual(items['222']['status'], 'revoked')
        self.assertFalse(items['222']['downloadable'])
        got = cf.fetch_existing('111')
        self.assertEqual(len(got['chain_pems']), 1)
        self.assertEqual(set(st['heads']), {'svc:v1.0-KEY'})
        bad = CloudflareOriginCaIssuer({'api_token': 'WRONG', 'api_url':
                                        'https://api.cloudflare.com/client/v4/x'},
                                       CannedContext(h))
        with self.assertRaises(PluginError) as e:
            bad.test()
        self.assertIn('Authentication error (10000)', str(e.exception))
        self.check('cloudflare_origin_ca', ctx.calls)

    def test_validity_only_cloudflares(self):
        cf = CloudflareOriginCaIssuer({'api_token': 'T', 'validity': '45'},
                                      CannedContext(lambda *a: (500, {}, b'')))
        with self.assertRaises(PluginError) as e:
            cf.issue(req_for(['www.firma.cz']))
        self.assertIn('5475', str(e.exception))


# ---------------------------------------------------------------------------
# The registry, the forms, Czech
# ---------------------------------------------------------------------------
class TestForms(unittest.TestCase):
    def test_found_and_forms(self):
        from acmelib.plugins.base import FIELD_TYPES
        reg = Registry().reload()
        self.assertFalse([b for b in reg.broken if 'issuers' in b[0]], reg.broken)
        for kind in KINDS:
            d = reg.get('issuer', kind).describe()
            self.assertTrue(d['title'] and d['description'] and d['fields'], kind)
            self.assertTrue(d['lists_existing'], kind)
            self.assertEqual(d['doc'], 'docs/sources.md')
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            for f in d['fields']:
                self.assertIn(f['type'], FIELD_TYPES)
                for k in (f.get('show_if') or {}):
                    self.assertIn(k, keys, '%s.%s' % (kind, f['key']))
                for k in f.get('depends') or []:
                    self.assertIn(k, keys, '%s.%s' % (kind, f['key']))
                if re.search(r'password|secret|token$|api_key$|service_key', f['key']) and \
                        f['key'] not in ('token_url',):
                    self.assertEqual(f['type'], 'secret', '%s.%s' % (kind, f['key']))
                # a list fetched has a typed field beside it (where it cannot be loaded)
                if f['type'] == 'catalog':
                    self.assertTrue([k for k in keys if k.startswith(f['key'] + '_')
                                     and k != f['key']], '%s.%s' % (kind, f['key']))

    def test_docs_name_the_sources(self):
        with open(os.path.join(ROOT, 'docs', 'sources.md'), encoding='utf-8') as f:
            text = f.read()
        for kind in KINDS:
            self.assertTrue('`%s`' % kind in text, kind)
        for url in ('github.com/caddyserver/zerossl', 'github.com/Venafi/vcert',
                    'github.com/Keyfactor/keyfactor-go-client-sdk',
                    'github.com/cloudflare/cloudflare-go'):
            self.assertTrue(url in text, url)

    def test_every_english_sentence_translated(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = json.load(f)
        known = {v['source'] for v in cs['strings'].values() if v.get('text')}
        pats = {v['source'] for v in cs['patterns'].values() if v.get('text')}
        missing = []
        for kind in KINDS:
            strings, patterns = english_of(os.path.join(
                ROOT, 'acmelib', 'plugins', 'issuers', kind + '.py'))
            missing += sorted('%s: %s' % (kind, s) for s in strings if s not in known)
            missing += sorted('%s: PATTERN %s' % (kind, p) for p in patterns if p not in pats)
        self.assertEqual(missing, [], '\n'.join(missing))


if __name__ == '__main__':
    unittest.main()
