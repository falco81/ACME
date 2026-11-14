#!/usr/bin/env python3
"""The SSLS.cz source (acmelib/plugins/issuers/ssls.py) against a fake SAPI v2
built from SSLS.cz's documentation (SAPI v2.3.3) and its PHP client: every
call is checked against it - the URL https://api.ssls.cz/v2/{method}/ with the
method's name as written (case-sensitive), a POST of a form (PHP's
http_build_query: dcv[method]=…, san[0]=…), the token in every request, the
parameters each method takes and every one it requires - and answered in the
documentation's shapes ({"auth": …, "errors": {isError, errorCode,
errorMessage}} for a mistake).

    python3 -m unittest test/test_ssls.py -v
    python3 test/test_ssls.py

No network: the certificates are real (a test intermediate signs the CSR the
module sent, with openssl), the DCV records go through fake validation
modules and are checked there before the fake CA issues.
"""
import ast
import hashlib
import json
import os
import re
import sys
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from acmelib.plugins.base import CertRequest, PluginError, Registry, FIELD_TYPES  # noqa: E402
from acmelib.plugins.issuers import ssls as SS                                   # noqa: E402
from acmelib.plugins.issuers.ssls import SslsIssuer                               # noqa: E402
from acmelib.certs import pki, compat                                             # noqa: E402
from test_issuers import FakeContext, TestCA, make_key_csr                        # noqa: E402
from test_sslmarket import FakeDns, FakeHttp                                      # noqa: E402

TOKEN = 'T0KEN-of-the-SSLS-account-42'
BASE = 'https://api.ssls.cz/v2/'
DAY = 86400

# ---------------------------------------------------------------------------
# The contract, as SAPI v2.3.3 writes it
# ---------------------------------------------------------------------------
PERSON = ('title', 'firstname', 'lastname', 'phone', 'email', 'organization', 'city',
          'country', 'fax')
METHODS = {
    # method: (allowed parameters, required parameters) - besides token / private /
    # accountDetail, which every method takes
    'allProducts': (set(), set()),
    'csrGen': ({'CN', 'C', 'ST', 'L', 'O', 'OU', 'E'}, {'CN', 'C', 'ST', 'L', 'O', 'OU', 'E'}),
    'csr': ({'csr'}, {'csr'}),
    'emails': ({'productCode', 'domain'}, {'productCode', 'domain'}),
    'servers': ({'productCode'}, {'productCode'}),
    'newOrder': ({'orderType', 'productCode', 'csr', 'san', 'server', 'period', 'dcv', 'admin',
                  'tech', 'org'},
                 {'productCode', 'csr', 'admin'}),
    'certStatus': ({'certID'}, {'certID'}),
    'getCert': ({'certID'}, {'certID'}),
    'myCerts': (set(), set()),
    'quickReissue': ({'certID', 'csr', 'dcv'}, {'certID', 'csr'}),
}
NESTED = {'dcv': {'method', 'method2', 'email', 'emails'},
          'admin': set(PERSON), 'tech': set(PERSON),
          'org': {'street', 'postalcode', 'email', 'businessId', 'duns', 'phone', 'fax'}}
ADMIN_REQUIRED = {'firstname', 'lastname', 'phone', 'email', 'country'}

PRODUCTS = [
    {'productCode': 'positive', 'productName': 'PositiveSSL', 'brand': 'Sectigo',
     'validation': 'DV', 'maxPeriod': 5, 'maxSan': 0, 'price1': '290'},
    {'productCode': 'positivemd', 'productName': 'PositiveSSL Multi-Domain', 'brand': 'Sectigo',
     'validation': 'DV', 'maxPeriod': 5, 'maxSan': 249, 'price1': '990'},
    {'productCode': 'alpirosslprem', 'productName': 'AlpiroSSL Premium', 'brand': 'AlpiroSSL',
     'validation': 'DV', 'maxPeriod': 2, 'maxSan': 0, 'price1': '390'},
    {'productCode': 'instant', 'productName': 'InstantSSL', 'brand': 'Sectigo',
     'validation': 'OV', 'maxPeriod': 2, 'maxSan': 0, 'price1': '1990'},
    {'productCode': 'commercial', 'productName': 'Commercial SSL', 'brand': 'Certum',
     'validation': 'DV', 'maxPeriod': 3, 'maxSan': 0, 'price1': '350'},
]
CERTUM = ('commercial',)
SECTIGO_LIKE = ('positive', 'positivemd', 'alpirosslprem', 'instant')


def php_parse(body):
    """application/x-www-form-urlencoded as PHP reads it: a[b]=c and a[0]=c nested."""
    out = {}
    for k, v in urllib.parse.parse_qsl(body, keep_blank_values=True, strict_parsing=True):
        m = re.match(r'^([^\[\]]+)((?:\[[^\[\]]*\])*)$', k)
        assert m, 'not a PHP parameter name: %r' % k
        keys = [m.group(1)] + re.findall(r'\[([^\[\]]*)\]', m.group(2))
        node = out
        for kk in keys[:-1]:
            node = node.setdefault(kk, {})
            assert isinstance(node, dict), k
        assert keys[-1] not in node, 'sent twice: %s' % k
        node[keys[-1]] = v
    return out


class FakeSapi(object):
    """SAPI v2: POST https://api.ssls.cz/v2/{method}/, a form, the token in it."""
    def __init__(self, ca, root, zone, files):
        self.ca, self.root = ca, root
        self.zone, self.files = zone, files     # what the fake validations put in place
        self.calls = []
        self.certs = {}
        self.next_cert = 1234567890
        self.next_order = 555000
        self.ip_allowed = True
        self.pending_polls = 2       # certStatus answers P this many times after the DCV is seen
        self.used_csrs = set()
        self.credit = '5000.00'
        self.approved = set()        # certIDs whose DCV e-mail somebody clicked
        self.products = PRODUCTS

    # -- the contract -----------------------------------------------------------------
    def check(self, method, params):
        assert method in METHODS, 'not a method of SAPI (case matters): %s' % method
        allowed, required = METHODS[method]
        given = set(params) - {'token', 'private', 'accountDetail'}
        extra = given - allowed
        assert not extra, 'parameters %s does not take: %s' % (method, sorted(extra))
        missing = required - set(params)
        assert not missing, 'parameters %s requires: %s' % (method, sorted(missing))
        for k in given & set(NESTED):
            assert isinstance(params[k], dict), (k, params[k])
            bad = set(params[k]) - NESTED[k]
            assert not bad, 'not in the documentation: %s.%s' % (k, sorted(bad))
        if 'san' in params:
            san = params['san']
            assert isinstance(san, dict) and sorted(san) == [str(i) for i in range(len(san))], san
        if 'accountDetail' in params:
            assert params['accountDetail'] in ('true', 'false', '1', '0')

    def __call__(self, method, url, body=None, headers=None, timeout=30, verify=True,
                 ca_pem=None, client_cert=None, proxy=True):
        assert method == 'POST', 'SAPI takes POST only (%s %s)' % (method, url)
        assert url.startswith(BASE) and url.endswith('/'), url
        assert verify, 'TLS is always checked'
        name = url[len(BASE):-1]
        assert '/' not in name and '?' not in name, url
        assert (headers or {}).get('Content-Type') == 'application/x-www-form-urlencoded'
        assert TOKEN not in url, 'the token never in the address'
        params = php_parse(body.decode('utf-8'))
        self.check(name, params)
        self.calls.append((name, params))
        if params.get('token') != TOKEN:
            return self.err(1002, 'Invalid token')
        if not self.ip_allowed:
            return self.err(1003, 'Access from IP address 203.0.113.9 is not allowed')
        got = getattr(self, 'm_' + name)(params)
        if isinstance(got, tuple):
            return got
        got = dict({'auth': {'responseID': '1392261777CJo'}}, **got)
        if params.get('private'):
            got['private'] = params['private']
        if params.get('accountDetail') == 'true':
            got['account'] = {'credit': self.credit, 'currency': 'CZK'}
        return 200, {'content-type': 'application/json'}, json.dumps(got).encode()

    @staticmethod
    def err(code, message):
        return 200, {'content-type': 'application/json'}, json.dumps(
            {'auth': {'responseID': '1394562148KdD'},
             'errors': {'isError': True, 'errorCode': code, 'errorMessage': message}}).encode()

    def product(self, code):
        return next((p for p in self.products if p['productCode'] == code), None)

    # -- the methods ----------------------------------------------------------------------
    def m_allProducts(self, p):
        return {'products': self.products}

    def m_servers(self, p):
        if self.product(p['productCode']) is None:
            return self.err(2001, 'Unknown productCode')
        return {'servers': {'Apache+OpenSSL': '2', 'Apache+ModSSL': '2', 'ApacheSSL': '3',
                            'Citrix': '34', 'Ostatní': '-1'}}

    def m_emails(self, p):
        d = p['domain']
        assert not d.startswith('*.'), d
        out = ['%s@%s' % (b, d) for b in SS.MAILBOXES]
        if d.count('.') > 1:
            out += ['%s@%s' % (b, d.split('.', 1)[1]) for b in SS.MAILBOXES]
        return {'emails': out}

    def m_myCerts(self, p):
        return {'myCerts': [{'certID': k, 'orderType': c['orderType'], 'orderDate': 1,
                             'paidDate': 2, 'paymentMethod': 'Credit', 'invoiceNumber': 0,
                             'productName': c['product'], 'period': int(c['period']),
                             'status': c['status'], 'NVB': c['NVB'], 'NVA': c['NVA'],
                             'SNVB': c['SNVB'], 'SNVA': c['SNVA'], 'CN': c['names'][0],
                             'SAN': ','.join(c['names'][1:])} for k, c in self.certs.items()]}

    def auth_for(self, cid, c):
        """The DCV a new order / a reissue gives back (fileAuth / dnsAuth)."""
        out = {}
        h = hashlib.md5(c['csr'].encode()).hexdigest().upper()
        if c['method'] == 'file':
            out['fileAuth'] = {'fileName': '%s.txt' % h,
                               'fileContent': 'sectigo.com\n%s' % h[:16].lower()}
        elif c['method'] == 'dns':
            if c['product'] in CERTUM:
                out['dnsAuth'] = {'code': 'certum-%s' % h[:20].lower(), 'type': 'TXT'}
            else:
                out['dnsAuth'] = {'code': '_%s.%s CNAME %s.%s.sectigo.com' % (
                    h, SS._base(c['names'][0]), h[:16].lower(), h[16:].lower()), 'type': 'CNAME'}
        return out

    def dcv_done(self, cid, c):
        """Whether the CA sees the DCV of every domain - in the fake validations."""
        a = c['auth']
        bases = sorted({SS._base(n) for n in c['names']})
        if c['method'] == 'email':
            return cid in self.approved
        if 'fileAuth' in a:
            want = '/.well-known/pki-validation/' + a['fileAuth']['fileName']
            return self.files.get(want) == a['fileAuth']['fileContent'] and len(bases) >= 1
        code = a['dnsAuth']['code']
        if a['dnsAuth']['type'] == 'TXT':
            return all(code in self.zone.get(b, []) for b in bases)
        label = code.split()[0].split('.', 1)[0].lower()      # DNS: case does not matter
        target = code.split()[-1]
        return all(target in self.zone.get('%s.%s' % (label, b), []) for b in bases)

    def m_newOrder(self, p):
        prod = self.product(p['productCode'])
        if prod is None:
            return self.err(2001, 'Unknown productCode')
        assert ADMIN_REQUIRED <= set(p['admin']), sorted(ADMIN_REQUIRED - set(p['admin']))
        assert re.match(r'^00\d+$', p['admin']['phone']), p['admin']['phone']
        assert re.match(r'^[A-Z]{2}$', p['admin']['country'])
        dcv = p.get('dcv') or {}
        method = dcv.get('method', 'email')
        assert method in ('email', 'file', 'dns'), 'lower case: %s' % method
        san = [p['san'][str(i)] for i in range(len(p.get('san') or {}))]
        ci = pki.csr_info(p['csr'])
        cn = ci.get('cn') or ci.get('subject', {}).get('CN')
        assert cn not in san, 'the CN is never among san.n'
        if method == 'email':
            assert dcv.get('email'), 'dcv.email: required for e-mail validation'
            if san:
                assert len(dcv.get('emails', '').split(',')) == len(san), dcv
                assert ' ' not in dcv['emails']
        if prod['validation'] in ('OV', 'EV') or p['productCode'] in CERTUM:
            assert {'organization', 'city'} <= set(p['admin']), p['admin']
            assert {'street', 'postalcode'} <= set(p.get('org') or {}), p.get('org')
        if p.get('orderType', 'new') not in ('new', 'renew'):
            return self.err(2002, 'Invalid orderType')
        if p.get('orderType') == 'renew' and p['productCode'] in CERTUM:
            return self.err(2003, 'Certum certificates cannot be renewed, use orderType new')
        if int(p.get('period', '1')) > prod['maxPeriod']:
            return self.err(2004, 'Invalid period')
        if len(san) > prod['maxSan']:
            return self.err(2005, 'Too many SAN domains')
        cid = str(self.next_cert)
        self.next_cert += 1
        oid = str(self.next_order)
        self.next_order += 1
        now = time.time()
        self.certs[cid] = {'product': p['productCode'], 'names': [cn] + san, 'csr': p['csr'],
                           'method': method, 'status': 'U', 'polls': 0, 'period': p.get('period',
                                                                                          '1'),
                           'orderType': p.get('orderType', 'new'), 'params': p, 'NVB': 0,
                           'NVA': 0, 'SNVB': 0, 'SNVA': 0, 'cert': None, 'reissues': 0,
                           'sub_end': now + int(p.get('period', '1')) * 365 * DAY}
        self.used_csrs.add(p['csr'])
        c = self.certs[cid]
        c['auth'] = self.auth_for(cid, c)
        return dict({'orderID': oid, 'certID': cid}, **c['auth'])

    def m_quickReissue(self, p):
        c = self.certs.get(p['certID'])
        if c is None:
            return self.err(3001, 'Unknown certID')
        if c['product'] in CERTUM:
            return self.err(3002, 'Certum certificates cannot be reissued')
        if p['csr'] in self.used_csrs:
            return self.err(3003, 'This CSR was used already')
        ci = pki.csr_info(p['csr'])
        cn = ci.get('cn') or ci.get('subject', {}).get('CN')
        if cn != c['names'][0]:
            return self.err(3004, 'The CN must be the domain of the certificate')
        m = (p.get('dcv') or {}).get('method')
        if m is not None:
            assert m in ('file', 'dns'), 'quickReissue: dcv.method file or dns only (%s)' % m
            c['method'] = m
        self.used_csrs.add(p['csr'])
        c.update(csr=p['csr'], status='P', polls=0, reissuing=True)
        c['auth'] = self.auth_for(p['certID'], c)
        out = {'certID': p['certID'], 'method': c['method']}
        if c['method'] == 'email':
            out['emailAuth'] = (c['params'].get('dcv') or {}).get('email', '')
        out.update(c['auth'])
        return out

    def m_certStatus(self, p):
        c = self.certs.get(p['certID'])
        if c is None:
            return self.err(3001, 'Unknown certID')
        c['polls'] += 1
        if c['status'] in ('U', 'P'):
            if c['status'] == 'U' and c['polls'] > 1:
                c['status'] = 'P'
            elif c['status'] == 'P' and self.dcv_done(p['certID'], c):
                c['seen'] = c.get('seen', 0) + 1
                if c['seen'] > self.pending_polls:
                    now = time.time()
                    c['cert'] = self.ca.sign_csr(pki.pem_to_der(c['csr']), c['names'])
                    c['status'] = 'R' if c.get('reissuing') else 'A'
                    c['NVB'], c['NVA'] = int(now), int(now + 199 * DAY)
                    if int(c['period']) > 1:
                        c['SNVB'], c['SNVA'] = int(now), int(c['sub_end'])
                    c['seen'] = 0
                    c['reissuing'] = False
        st = {'certID': p['certID'], 'status': c['status'],
              'message': {'P': 'Čeká na ověření', 'A': 'Vystaven a aktivní',
                          'R': 'Přegenerován', 'U': 'Nezjištěno', 'C': 'Zrušen',
                          'E': 'Expiroval', 'N': 'Neuhrazeno'}[c['status']],
              'CN': c['names'][0], 'SAN': c['names'][1:],
              'dcv': {'method': c['method'], 'method2': ''}}
        if c['status'] in ('A', 'R'):
            st.update(vendorID='16011593', NVB=c['NVB'], NVA=c['NVA'], SNVB=c['SNVB'],
                      SNVA=c['SNVA'])
        return {'status': st}

    def m_getCert(self, p):
        c = self.certs.get(p['certID'])
        if c is None or not c['cert']:
            return self.err(3005, 'Certificate has not been issued yet')
        # the chain file with the root before the intermediate: acme puts it in order
        return {'certificates': [
            {'FileName': 'Intermediate_CA_chain.cer', 'Contents': self.root.pem + self.ca.pem},
            {'FileName': '%s.cer' % c['names'][0], 'Contents': c['cert']}]}

    def names(self):
        return [c[0] for c in self.calls]

    def of(self, method):
        return [c[1] for c in self.calls if c[0] == method]


class Ctx(FakeContext):
    def __init__(self, sapi):
        FakeContext.__init__(self)
        self.sapi = sapi

    def http(self, method, url, *a, **kw):
        if url.startswith('https://api.ssls.cz/'):
            return self.sapi(method, url, *a, **kw)
        raise AssertionError('no other address is asked: %s' % url)


class TxtDns(FakeDns):
    """FakeDns that also puts CNAME records in place (the zone: fqdn -> [values])."""
    kind = 'fakedns'

    def place(self, kind, name, where, content):
        if kind not in ('txt', 'cname'):
            raise NotImplementedError('no %s records' % kind)
        self.add_txt(where, content)
        return {'fqdn': where, 'txt': content}


CONF = {'token': TOKEN, 'product': 'positivemd', 'product_level': 'DV', 'product_ca': 'Sectigo',
        'admin_first': 'Jana', 'admin_last': 'Nováková', 'admin_email': 'pki@example.cz',
        'admin_phone': '00420123456789', 'admin_country': 'cz', 'poll_every': 30,
        'wait_issue': 3600, 'wait_ready': 5}


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = TestCA(cn='Fake USERTrust Root')
        cls.ca = TestCA(cn='Fake Sectigo DV CA', parent=cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.ca.close()
        cls.root.close()

    def setUp(self):
        self.zone, self.files = {}, {}
        self.sapi = FakeSapi(self.ca, self.root, self.zone, self.files)
        self.ctx = Ctx(self.sapi)
        self.clock = [time.time()]
        self._now = SS._now
        SS._now = lambda: self.clock[0]

    def tearDown(self):
        SS._now = self._now

    def sleep(self, s):
        self.clock[0] += s

    def issuer(self, **more):
        conf = dict(CONF)
        conf.update(more)
        iss = SslsIssuer(conf, self.ctx)
        iss._sleep = self.sleep
        return iss

    def req(self, names=('www.example.cz', 'example.cz'), cert_id=5, kind='ec', http=False,
            previous=None):
        key, csr_pem, csr_der = make_key_csr(list(names), kind)
        ch = FakeHttp(self.files) if http else TxtDns(self.zone)
        return CertRequest(names=list(names), key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                           key_type='rsa-2048' if kind == 'rsa' else 'ec-256',
                           challenges={n: ch for n in names}, cert_id=cert_id,
                           previous=previous)

    def said(self):
        return '\n'.join(w for _l, w in self.ctx.steps)

    def assert_no_secret(self):
        self.assertNotIn(TOKEN, self.said())
        self.assertNotIn(TOKEN, json.dumps(self.ctx.kv))


# ---------------------------------------------------------------------------
class TestContract(Base):
    def test_form_encoding_is_phps(self):
        got = SS.form_encode({'token': 'x', 'dcv': {'method': 'dns'}, 'san': ['a.cz', 'b.cz'],
                              'admin': {'firstname': 'Jana'}, 'none': None})
        self.assertEqual(php_parse(got), {'token': 'x', 'dcv': {'method': 'dns'},
                                          'san': {'0': 'a.cz', '1': 'b.cz'},
                                          'admin': {'firstname': 'Jana'}})
        self.assertIn('dcv%5Bmethod%5D=dns', got)

    def test_method_names_as_documented(self):
        for m in (SS.M_PRODUCTS, SS.M_SERVERS, SS.M_EMAILS, SS.M_ORDER, SS.M_REISSUE,
                  SS.M_STATUS, SS.M_GET, SS.M_MINE):
            self.assertIn(m, METHODS)
        self.assertEqual(SS.API_URL + '/', BASE)

    def test_catalog_and_test_read_only(self):
        iss = self.issuer()
        cat = iss.catalog('products')
        codes = [o[0] for o in cat['options']]
        self.assertEqual(sorted(codes), sorted(p['productCode'] for p in PRODUCTS))
        self.assertEqual(cat['sets']['instant'], {'product_level': 'OV', 'product_ca': 'Sectigo',
                                                  'needs_org': True})
        self.assertEqual(cat['sets']['commercial']['needs_org'], True)      # Certum
        self.assertEqual(cat['sets']['positive']['needs_org'], False)
        self.assertIn('credit 5000.00', cat['said'])
        srv = iss.catalog('servers')
        self.assertIn(['2', 'Apache+OpenSSL, Apache+ModSSL'], srv['options'])
        said = iss.test()
        self.assertIn('5 products', said)
        self.assertIn('credit 5000.00', said)
        self.assertIn('the product positivemd is offered', said)
        self.assertIn('not allowed', said)
        self.assertEqual(set(self.sapi.names()), {'allProducts', 'servers'})
        self.assertTrue(all(c[1]['accountDetail'] == 'true' for c in self.sapi.calls
                            if c[0] == 'allProducts'))
        self.assert_no_secret()

    def test_catalog_of_other_shapes(self):
        grouped = {'auth': {}, 'products': {'Certum': [
            {'productCode': 'commercial', 'productName': 'Commercial SSL', 'type': 'DV',
             'price1': 1, 'price3': 2}],
            'Sectigo': {'1': {'productCode': 'ev', 'productName': 'Sectigo EV SSL'}}}}
        got = {p['code']: p for p in SS.products_of(grouped)}
        self.assertEqual(got['commercial']['ca'], 'Certum')
        self.assertEqual(got['commercial']['years'], 3)
        self.assertEqual(got['ev']['ca'], 'Sectigo')
        self.assertEqual(got['ev']['level'], 'EV')
        self.assertTrue(SS.needs_org(got['commercial']))

    def test_bad_token_and_ip_said_plainly(self):
        iss = self.issuer(token='wrong-token-1')
        with self.assertRaises(PluginError) as e:
            iss.test()
        self.assertIn('refuses the API token', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertNotIn('wrong-token-1', str(e.exception) + str(e.exception.detail))
        self.sapi.ip_allowed = False
        with self.assertRaises(PluginError) as e:
            self.issuer().test()
        self.assertIn('does not allow the API from this server\'s address', str(e.exception))
        self.assertIn('203.0.113.9', str(e.exception))
        with self.assertRaises(PluginError) as e:
            self.issuer(token='').test()
        self.assertIn('set the API token', str(e.exception))

    def test_compat_says_which_validations_fit(self):
        info = compat.source_info(SslsIssuer, {'dcv': 'dns', 'product': 'positive'})
        self.assertEqual(info['proofs'], ['cname-any'])
        self.assertTrue(info['needs_validation'])
        self.assertTrue(info['public'])
        info = compat.source_info(SslsIssuer, {'dcv': 'dns', 'product': 'commercial',
                                               'product_ca': 'Certum'})
        self.assertEqual(info['proofs'], ['txt-any'])
        self.assertEqual(compat.source_info(SslsIssuer, {'dcv': 'file'})['proofs'],
                         ['http-file-any'])
        info = compat.source_info(SslsIssuer, {'dcv': 'email'})
        self.assertEqual((info['proofs'], info['needs_validation']), ([], False))
        self.assertFalse(SslsIssuer({'dcv': 'email'}, self.ctx).needs_challenge)
        self.assertEqual(SslsIssuer.dcv_where({'txt_label': '@'}, '*.example.cz', 'txt-any'),
                         'example.cz')


class TestOrders(Base):
    def test_paid_orders_off_nothing_is_sent(self):
        iss = self.issuer()
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req())
        w = str(e.exception)
        self.assertIn('nothing ordered', w)
        self.assertIn('Allow new orders (paid)', w)
        self.assertFalse(e.exception.retry)
        self.assertNotIn('newOrder', self.sapi.names())
        self.assertEqual(self.sapi.calls, [])

    def test_dns_order_cname_put_in_place_and_removed(self):
        iss = self.issuer(allow_paid=True, period='2')
        r = self.req()
        out = iss.issue(r)
        order = self.sapi.of('newOrder')[0]
        self.assertEqual(order['productCode'], 'positivemd')
        self.assertEqual(order['dcv'], {'method': 'dns'})
        self.assertEqual(order['san'], {'0': 'example.cz'})
        self.assertEqual(order['period'], '2')
        self.assertNotIn('orderType', order)
        self.assertEqual(order['admin']['country'], 'CZ')
        self.assertNotIn('org', order)
        # the leaf for the key, the chain intermediate first then the root
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        self.assertEqual([pki.cert_info(c)['subject_cn'] if 'subject_cn' in pki.cert_info(c)
                          else pki.cert_info(c).get('cn') for c in out.chain_pems],
                         ['Fake Sectigo DV CA', 'Fake USERTrust Root'])
        # the CNAME was there for both domains when the CA looked, and is gone now
        self.assertEqual({k: v for k, v in self.zone.items() if v}, {})
        cid = out.info['ssls_id']
        self.assertEqual(json.loads(self.ctx.kv['ssls-order:5:ec'])['cert_id'], cid)
        self.assertNotIn('ssls-pending:5:ec', self.ctx.kv)
        self.assertIn('asked again in 30 s', self.said())
        self.assert_no_secret()

    def test_certum_txt_at_the_name(self):
        iss = self.issuer(allow_paid=True, product='commercial', product_ca='Certum',
                          needs_org=True, org_name='Example s.r.o.', org_city='Praha',
                          org_street='Ulice 1', org_postalcode='11000',
                          org_email='info@example.cz')
        r = self.req(names=('example.cz',))
        seen = []
        orig = self.sapi.dcv_done

        def spy(cid, c):
            ok = orig(cid, c)
            seen.append((ok, dict((k, list(v)) for k, v in self.zone.items())))
            return ok
        self.sapi.dcv_done = spy
        out = iss.issue(r)
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        ok_zone = [z for ok, z in seen if ok][0]
        self.assertTrue(ok_zone['example.cz'][0].startswith('certum-'))
        order = self.sapi.of('newOrder')[0]
        self.assertEqual(order['admin']['organization'], 'Example s.r.o.')
        self.assertEqual(order['org'], {'street': 'Ulice 1', 'postalcode': '11000',
                                        'email': 'info@example.cz'})
        self.assertNotIn('san', order)

    def test_org_details_needed_said(self):
        iss = self.issuer(allow_paid=True, product='instant', needs_org=True)
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req(names=('www.example.cz',)))
        self.assertIn('an order needs the organisation', str(e.exception))
        self.assertNotIn('newOrder', self.sapi.names())

    def test_file_dcv(self):
        iss = self.issuer(allow_paid=True, dcv='file')
        r = self.req(http=True)
        seen = []
        orig = self.sapi.dcv_done
        self.sapi.dcv_done = lambda cid, c: seen.append(dict(self.files)) or orig(cid, c)
        out = iss.issue(r)
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        self.assertEqual(self.sapi.of('newOrder')[0]['dcv'], {'method': 'file'})
        placed = [f for f in seen if f]
        path = [k for k in placed[0]][0]
        self.assertTrue(path.startswith('/.well-known/pki-validation/') and path.endswith('.txt'))
        self.assertEqual(self.files, {})        # taken away again

    def test_email_dcv_nothing_placed(self):
        iss = self.issuer(allow_paid=True, dcv='email', approver='hostmaster',
                          wait_issue=60)
        r = self.req(names=('www.example.cz', 'shop.example.org'))
        with self.assertRaises(PluginError) as e:
            iss.issue(r)
        self.assertTrue(e.exception.retry)
        self.assertIn('waits at SSLS.cz', str(e.exception))
        order = self.sapi.of('newOrder')[0]
        self.assertEqual(order['dcv'], {'method': 'email', 'email': 'hostmaster@www.example.cz',
                                        'emails': 'hostmaster@shop.example.org'})
        self.assertEqual(self.zone, {})
        self.assertEqual(self.files, {})
        self.assertEqual([p['domain'] for p in self.sapi.of('emails')],
                         ['www.example.cz', 'shop.example.org'])
        # somebody clicks; the next try fetches it - nothing ordered again
        cid = list(self.sapi.certs)[0]
        self.sapi.approved.add(cid)
        out = iss.issue(r)
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        self.assertEqual(len(self.sapi.of('newOrder')), 1)
        self.assertIn('nothing is ordered', self.said())

    def test_waiting_order_kept_and_key_given_back(self):
        iss = self.issuer(allow_paid=True, wait_issue=40)
        self.sapi.pending_polls = 5
        r = self.req()
        with self.assertRaises(PluginError):
            iss.issue(r)
        held = json.loads(self.ctx.kv['ssls-pending:5:ec'])
        self.assertNotIn(r.key_pem, json.dumps(held))      # sealed
        self.assertTrue(held['dcv'])
        # the next try with a new key: the waiting order is asked for again
        r2 = self.req()
        r2.challenges = r.challenges
        out = self.issuer(allow_paid=True).issue(r2)
        self.assertEqual(len(self.sapi.of('newOrder')), 1)
        self.assertEqual(out.key_pem, r.key_pem)
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))

    def test_waiting_order_with_a_revoked_key_let_go(self):
        """Held with the key of a version revoked since: not finished (1.0.101) - a new request
        with the new key; the renewer's drop at a revoke finds its slot."""
        from acmelib.certs import renewer
        self.assertEqual(renewer.HELD_RE.search('ssls-pending:5:ec').group(1), '5')
        iss = self.issuer(allow_paid=True, wait_issue=40)
        self.sapi.pending_polls = 5
        r = self.req()
        with self.assertRaises(PluginError):
            iss.issue(r)
        self.assertIn('ssls-pending:5:ec', self.ctx.kv)
        r2 = self.req()
        r2.challenges = r.challenges
        r2.no_held_key = [pki.key_info(r.key_pem)['pub_sha256']]
        # never finished with the revoked key: let go (the CA still validating that one, nothing
        # is ordered meanwhile - asked again at the next try)
        with self.assertRaises(PluginError) as e:
            self.issuer(allow_paid=True).issue(r2)
        self.assertTrue(e.exception.retry)
        self.assertNotIn('ssls-pending:5:ec', self.ctx.kv)
        self.assertIn('has the key of a version revoked', self.said())
        self.assertEqual(len(self.sapi.of('newOrder')), 1)

    def test_renewal_reissues_inside_the_subscription(self):
        iss = self.issuer(allow_paid=True, period='2')
        first = iss.issue(self.req())
        cid = first.info['ssls_id']
        # the renewal: paid orders off now - a free reissue all the same
        iss = self.issuer(allow_paid=False, period='2')
        r = self.req(previous=first.cert_pem)
        out = iss.issue(r)
        self.assertEqual(len(self.sapi.of('newOrder')), 1)
        re_ = self.sapi.of('quickReissue')
        self.assertEqual(len(re_), 1)
        self.assertEqual(re_[0]['certID'], cid)
        self.assertEqual(re_[0]['dcv'], {'method': 'dns'})
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        self.assertEqual(out.info['ssls_id'], cid)
        self.assertIn('free, nothing is bought', self.said())
        self.assertEqual({k: v for k, v in self.zone.items() if v}, {})

    def test_subscription_ending_needs_a_paid_renewal(self):
        iss = self.issuer(allow_paid=True)          # 1 year: SNVA 0, the end is NVA
        first = iss.issue(self.req())
        self.clock[0] += 180 * DAY
        r = self.req(previous=first.cert_pem)
        with self.assertRaises(PluginError) as e:
            self.issuer().issue(r)
        self.assertIn('nothing ordered', str(e.exception))
        self.assertEqual(self.sapi.of('quickReissue'), [])
        out = self.issuer(allow_paid=True).issue(r)
        orders = self.sapi.of('newOrder')
        self.assertEqual(len(orders), 2)
        self.assertEqual(orders[1]['orderType'], 'renew')
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))

    def test_certum_never_reissued(self):
        conf = dict(product='commercial', product_ca='Certum', needs_org=True,
                    org_name='Example s.r.o.', org_city='Praha', org_street='Ulice 1',
                    org_postalcode='11000', org_email='info@example.cz', period='3')
        first = self.issuer(allow_paid=True, **conf).issue(self.req(names=('example.cz',)))
        with self.assertRaises(PluginError):
            self.issuer(**conf).issue(self.req(names=('example.cz',), previous=first.cert_pem))
        self.assertEqual(self.sapi.of('quickReissue'), [])
        self.issuer(allow_paid=True, **conf).issue(self.req(names=('example.cz',),
                                                            previous=first.cert_pem))
        self.assertNotIn('orderType', self.sapi.of('newOrder')[1])   # Certum: never renew

    def test_certificate_to_reuse_bought_elsewhere(self):
        first = self.issuer(allow_paid=True, period='2').issue(self.req(cert_id=1))
        cid = first.info['ssls_id']
        out = self.issuer(cert_reuse=cid).issue(self.req(cert_id=9))
        self.assertEqual(out.info['ssls_id'], cid)
        self.assertEqual(len(self.sapi.of('quickReissue')), 1)

    def test_too_many_names_and_years(self):
        iss = self.issuer(allow_paid=True, product='positive')
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req())
        self.assertIn('takes at most 0 more names', str(e.exception))
        iss = self.issuer(allow_paid=True, product='alpirosslprem', period='5')
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req(names=('www.example.cz',)))
        self.assertIn('at most 2 years', str(e.exception))
        self.assertNotIn('newOrder', self.sapi.names())

    def test_cancelled_order_said(self):
        iss = self.issuer(allow_paid=True)
        orig = self.sapi.m_certStatus

        def cancelled(p):
            self.sapi.certs[p['certID']]['status'] = 'C'
            return orig(p)
        self.sapi.m_certStatus = cancelled
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req())
        self.assertIn('revoked, cancelled or refused', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertNotIn('ssls-pending:5:ec', self.ctx.kv)
        self.assertEqual({k: v for k, v in self.zone.items() if v}, {})

    def test_revoke_said(self):
        with self.assertRaises(PluginError) as e:
            self.issuer().revoke('x')
        self.assertIn('cannot revoke', str(e.exception))

    def test_actions(self):
        iss = self.issuer(allow_paid=True)
        iss.issue(self.req())
        self.assertIn('5 products', iss.action('products'))
        self.assertEqual(iss.action('certs'), '1 certificates')
        cid = list(self.sapi.certs)[0]
        self.assertEqual(self.issuer(cert_reuse=cid).action('status'), '1 certificate(s)')
        self.assertIn('SSLS ID %s' % cid, self.said())
        self.assertEqual(self.sapi.names().count('newOrder'), 1)
        self.assert_no_secret()


class TestModule(unittest.TestCase):
    def test_registered_with_a_catalog_field(self):
        reg = Registry().reload()
        d = reg.get('issuer', 'ssls').describe()
        self.assertEqual(d['doc'], 'docs/ssls.md')
        self.assertTrue(os.path.isfile(os.path.join(ROOT, d['doc'])))
        types = {f['key']: f['type'] for f in d['fields']}
        self.assertEqual(types['product'], 'catalog')
        self.assertEqual(types['token'], 'secret')
        for f in d['fields']:
            self.assertIn(f['type'], FIELD_TYPES)
        self.assertFalse(SslsIssuer({}, None).c('allow_paid'))

    def test_page_part_is_there(self):
        with open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8') as f:
            self.assertIn('/assets/catalog.js?v=', f.read())
        with open(os.path.join(ROOT, 'web', 'assets', 'catalog.js'), encoding='utf-8') as f:
            self.assertIn('ACME_FIELD_TYPES.catalog', f.read())


# ---------------------------------------------------------------------------
# Czech: every English sentence of the module in web/lang/cs.json
# ---------------------------------------------------------------------------
def _english_of_module(path):
    """(strings, patterns) the module says: the words of its form, its actions, its
    steps and its errors - a %s / %d made {0}, {1}…"""
    tree = ast.parse(open(path, encoding='utf-8').read())
    strings, patterns = set(), set()

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
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(
                fn, ast.Attribute) else '')
            for kw in node.keywords:
                if kw.arg == 'what':
                    add(kw.value)       # said inside "SSLS.cz refused {0}: …"
            if name in ('PluginError', '_say', 'append'):
                if node.args:
                    add(node.args[0])
            elif name in ('field', '_catalog_field'):
                for a in node.args[1:2]:
                    add(a)
                for kw in node.keywords:
                    if kw.arg in ('help', 'placeholder'):
                        add(kw.value)
                    if kw.arg == 'options' and isinstance(kw.value, ast.List):
                        for o in kw.value.elts:
                            if isinstance(o, ast.List) and len(o.elts) > 1:
                                add(o.elts[1])
        elif isinstance(node, ast.Return) and node.value is not None:
            add(node.value)
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value in ('label', 'help', 'confirm',
                                                                 'words', 'record'):
                    add(v)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in (
                'title', 'description', 'STATUS_WORDS') for t in node.targets):
            if isinstance(node.value, ast.Dict):
                for v in node.value.values:
                    add(v)
            else:
                add(node.value)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'more'
                                                  for t in node.targets):
            add(node.value)
    return strings, patterns


class TestCzech(unittest.TestCase):
    def test_every_english_sentence_translated(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = json.load(f)
        known = {v['source'] for v in cs['strings'].values() if v.get('text')}
        pats = {v['source'] for v in cs['patterns'].values() if v.get('text')}
        strings, patterns = _english_of_module(os.path.join(ROOT, 'acmelib', 'plugins',
                                                            'issuers', 'ssls.py'))
        missing = sorted(s for s in strings if s not in known)
        missing += sorted('PATTERN ' + p for p in patterns if p not in pats)
        # the page's own words (catalog.js)
        for s in ('Load the list', 'asking…', 'not in the list', 'not loaded yet - Load the list',
                  'chosen before - Load the list to see the others'):
            if s not in known:
                missing.append(s)
        self.assertEqual(missing, [], '\n'.join(missing))

    def test_keys_unique_and_file_shape(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            text = f.read()
        self.assertTrue(text.endswith('}\n'))
        seen = {}

        def hook(pairs):
            keys = [k for k, _v in pairs]
            self.assertEqual(len(keys), len(set(keys)), [k for k in keys if keys.count(k) > 1])
            return dict(pairs)
        json.loads(text, object_pairs_hook=hook)
        d = json.loads(text)
        for sec in ('strings', 'patterns', 'rich'):
            for k, v in d[sec].items():
                seen.setdefault(v['source'], []).append(k)


if __name__ == '__main__':
    unittest.main()
