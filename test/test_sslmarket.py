#!/usr/bin/env python3
"""The SSLmarket sources (acmelib/plugins/issuers/sslmarket.py) against a fake
SSLmarket API built from SSLmarket's own OpenAPI 3.0 specification
(test/fixtures/sslmarket-openapi.json): every call the modules make is checked
against it - the path and method exist, the body has the fields the
specification names (and every required one), the answers have its shape.

    python3 -m unittest test/test_sslmarket.py -v
    python3 test/test_sslmarket.py

No network: the certificates are real (a test CA signs the CSR the module
sent, with openssl), the DCV records go through fake validation modules, the
ACME source orders from the mock ACME CA of test_issuers.py (with EAB).
"""
import json
import os
import re
import sys
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from acmelib.plugins.base import Challenge, CertRequest, PluginError, Registry  # noqa: E402
from acmelib.plugins.issuers import sslmarket as SM                            # noqa: E402
from acmelib.plugins.issuers.sslmarket import SslmarketIssuer, SslmarketAcmeIssuer  # noqa: E402
from acmelib.certs import pki                                                  # noqa: E402
from test_issuers import (FakeContext, FakeChallenge, MockAcme, TestCA,        # noqa: E402
                          b64u, make_key_csr)

TOKEN = 'k3y-0f-the-account'
DAY = 86400
BASE = 'https://www.sslmarket.cz/api'
SPEC = json.load(open(os.path.join(HERE, 'fixtures', 'sslmarket-openapi.json'), encoding='utf-8'))


def schema(ref_or_schema):
    s = ref_or_schema or {}
    while '$ref' in s:
        s = SPEC['components']['schemas'][s['$ref'].split('/')[-1]]
    return s


def operation(method, path):
    """The OpenAPI operation of a concrete call, and its path template - or (None, None)."""
    for tmpl, ops in SPEC['paths'].items():
        rx = '^' + re.sub(r'\\\{[A-Za-z_]+\\\}', '[^/]+', re.escape(tmpl)) + '$'
        if re.match(rx, path) and method.lower() in ops:
            return ops[method.lower()], tmpl
    return None, None


def response_props(tmpl, method, status):
    op = SPEC['paths'][tmpl][method.lower()]
    r = op['responses'].get(str(status)) or {}
    s = schema(((r.get('content') or {}).get('application/json') or {}).get('schema'))
    return s.get('properties') or {}


def shaped(props, values):
    """An answer with only the properties the specification has (its contract)."""
    bad = set(values) - set(props)
    assert not bad, 'not in the specification: %s' % sorted(bad)
    return dict(values)


class FakeApi(object):
    """SSLmarket's API, from the OpenAPI: X-Auth-Token, JSON, {message} on 4XX."""
    def __init__(self, ca, acme_url=None, kid='kid-1', hmac='c2VjcmV0'):
        self.ca = ca
        self.calls = []
        self.orders = {}
        self.next_id = 777
        self.pending_polls = 1       # detail calls after the DCV before the certificate is there
        self.fail = {}               # (method, template) -> (status, message)
        self.dv_content = lambda oid, o: 'dcv-token-%s' % oid
        self.created_body = None     # what the 201 of a new order carries (None: nothing)
        self.acmes = []
        self.acme_url, self.kid, self.hmac = acme_url, kid, hmac
        self.serials = 0

    # -- the contract -------------------------------------------------------------------
    def check(self, method, path, query, body):
        op, tmpl = operation(method, path)
        assert op is not None, 'not in the OpenAPI: %s %s' % (method, path)
        names = {p['name'] for p in op.get('parameters') or [] if p['in'] == 'query'}
        assert set(query) <= names, (tmpl, query)
        rb = op.get('requestBody')
        if rb:
            assert body is not None, 'a body is required: %s %s' % (method, tmpl)
            s = schema(rb['content']['application/json']['schema'])
            props = s.get('properties') or {}
            extra = set(body) - set(props)
            assert not extra, 'fields not in the OpenAPI for %s %s: %s' % (method, tmpl, sorted(extra))
            missing = set(s.get('required') or []) - set(body)
            assert not missing, 'required fields missing for %s %s: %s' % (method, tmpl, sorted(missing))
            for k, v in body.items():
                t = props[k].get('type')
                assert t != 'string' or isinstance(v, str), (k, v)
                assert t != 'integer' or isinstance(v, int), (k, v)
                if props[k].get('enum'):
                    assert v in props[k]['enum'], (k, v)
        else:
            assert body is None, 'no body in the OpenAPI for %s %s' % (method, tmpl)
        return tmpl

    def __call__(self, method, url, body=None, headers=None, timeout=30, verify=True,
                 ca_pem=None, client_cert=None, proxy=True):
        assert url.startswith(BASE), url
        u = urllib.parse.urlsplit(url)
        path = u.path[len('/api'):]
        query = dict(urllib.parse.parse_qsl(u.query))
        data = json.loads(body.decode()) if body else None
        if data is not None:
            assert headers.get('Content-Type') == 'application/json'
        tmpl = self.check(method, path, query, data)
        self.calls.append((method, tmpl, path, data))
        if (headers or {}).get('X-Auth-Token') != TOKEN:
            return self.err(401, 'Invalid token')
        if (method, tmpl) in self.fail:
            st, msg = self.fail[(method, tmpl)]
            return self.err(st, msg)
        fn = getattr(self, 'h_%s_%s' % (method.lower(), re.sub(r'\W+', '_', tmpl).strip('_')))
        return fn(path, data, tmpl)

    @staticmethod
    def err(status, message):
        return status, {'content-type': 'application/json'}, json.dumps({'message': message}).encode()

    def ok(self, tmpl, method, values, status=200):
        return status, {'content-type': 'application/json'}, json.dumps(
            shaped(response_props(tmpl, method, status), values)).encode()

    @staticmethod
    def text(data, status=200):
        return status, {'content-type': 'text/plain'}, data.encode() if isinstance(data, str) else data

    # -- the calls ------------------------------------------------------------------------
    def h_get_product_list(self, path, data, tmpl):
        prod = schema(response_props(tmpl, 'GET', 200)['products']['items'])['properties']
        return self.ok(tmpl, 'GET', {'products': [
            shaped(prod, {'product_type': 'ssl_certificate', 'product_code': 'RAPIDSSL_STANDARD',
                          'title': 'RapidSSL Standard', 'type': 'ssl', 'validate_type': 'DV',
                          'csr_required': 'yes', 'max_years': 3, 'min_san_values': 0,
                          'max_san_values': 1}),
            shaped(prod, {'product_type': 'ssl_certificate', 'product_code': 'DIGICERT_SECURE_SITE',
                          'title': 'Secure Site', 'type': 'ssl', 'validate_type': 'OV',
                          'csr_required': 'yes', 'max_years': 5, 'min_san_values': 0,
                          'max_san_values': 250})]})

    def order_row(self, oid, o):
        props = schema(response_props('/order/list', 'GET', 200)['orders']['items'])['properties']
        return shaped(props, {'order_id': int(oid), 'product_type': 'ssl_certificate',
                              'product_code': o['product'], 'domain': o['domain'],
                              'dns_names': o['dns_names'], 'sans_order_count': o['sans'],
                              'years': o['years'], 'inserted': o['inserted'],
                              'published': o['published'], 'expired': o['expired'],
                              'state': o['state']})

    def h_get_order_list(self, path, data, tmpl):
        return self.ok(tmpl, 'GET', {'orders': [self.order_row(k, o) for k, o in self.orders.items()]})

    def add_order(self, oid, names, expired, csr=None, serial='', product='RAPIDSSL_STANDARD',
                  state='Issued', method='DNS'):
        self.orders[str(oid)] = {
            'product': product, 'domain': names[0], 'dns_names': ','.join(names[1:]),
            'sans': len(names) - 1, 'years': 1, 'inserted': time.strftime('%Y-%m-%d %H:%M:%S'),
            'published': '', 'expired': expired, 'state': state, 'csr': csr, 'serial': serial,
            'reissue_pending': False, 'method': method, 'polls': 0, 'names': names,
            'has_child': False, 'child_id': None}
        return self.orders[str(oid)]

    def h_post_order_certificate_PRODUCT_CODE(self, path, data, tmpl):
        oid = str(self.next_id)
        self.next_id += 1
        names = [data['domain']] + [n for n in (data.get('dns_names') or '').split(',') if n]
        o = self.add_order(oid, names, time.strftime('%Y-%m-%d', time.gmtime(time.time() + 365 * DAY)),
                           csr=data['csr'], product=path.rsplit('/', 1)[-1],
                           state='Waiting for validation', method=data.get('dv_auth_method'))
        o['body'] = data
        if self.created_body is None:
            return 201, {}, b''                  # the OpenAPI's 201 has no body
        return 201, {'content-type': 'application/json'}, json.dumps(self.created_body(oid)).encode()

    def h_get_order_order_id_ORDER_ID(self, path, data, tmpl):
        oid = path.rsplit('/', 1)[-1]
        o = self.orders.get(oid)
        if o is None:
            return self.err(404, 'Order not found')
        o['polls'] += 1
        working = o['state'] != 'Issued' or o['reissue_pending']
        if working and o['polls'] > self.pending_polls:
            if o['state'] != 'Issued' or o['reissue_pending']:
                self.serials += 1
                o['serial'] = '%X' % (int(oid) * 1000 + self.serials)
                o['published'] = time.strftime('%Y-%m-%d')
                o['state'] = 'Issued'
                o['reissue_pending'] = False
        v = {'product_type': 'ssl_certificate', 'product_code': o['product'], 'domain': o['domain'],
             'dns_names': o['dns_names'], 'sans_order_count': o['sans'], 'years': o['years'],
             'csr': o['csr'] or '', 'state': o['state'], 'published': o['published'],
             'expired': o['expired'], 'reissue_pending': o['reissue_pending'],
             'certificate_serial_number': o['serial'], 'has_parent': False,
             'has_child': o['has_child'], 'dv_auth_method': o['method'] or 'Email'}
        if o['has_child']:
            v['child_id'] = o['child_id']
        if o['method'] in ('DNS', 'FILE') and o['polls'] > 1:
            v['dv_auth_content'] = self.dv_content(oid, o)      # not at once: asked again
        return self.ok(tmpl, 'GET', v)

    def h_put_order_order_id_ORDER_ID(self, path, data, tmpl):
        o = self.orders[path.rsplit('/', 1)[-1]]
        o['csr'] = data.get('csr', o['csr'])
        o['method'] = data.get('dv_auth_method', o['method'])
        o['polls'] = 0
        return 200, {}, b''

    def h_post_certificate_order_id_ORDER_ID_reissue(self, path, data, tmpl):
        o = self.orders[path.split('/')[3]]
        o['csr'] = data['csr']
        o['reissue_pending'] = True
        o['polls'] = 0
        return 202, {}, b''

    def h_put_certificate_order_id_ORDER_ID_cancel_reissue(self, path, data, tmpl):
        self.orders[path.split('/')[3]]['reissue_pending'] = False
        return 202, {}, b''

    def h_put_certificate_order_id_ORDER_ID_revoke(self, path, data, tmpl):
        return self.err(400, 'Revocation is available for DigiCert Client Premium only')

    def h_put_certificate_order_id_ORDER_ID_resend(self, path, data, tmpl):
        return 202, {}, b''

    def h_get_certificate_order_id_ORDER_ID_format_FORMAT(self, path, data, tmpl):
        parts = path.split('/')
        o, fmt = self.orders[parts[3]], parts[5]
        if fmt == 'pem_intermediate':
            return self.text(self.ca.pem)
        if fmt == 'p7b':
            return self.text(b'')
        if o.get('cert_for') != (o['serial'], o['csr']):
            o['cert'] = self.ca.sign_csr(pki.pem_to_der(o['csr']), o['names'])
            o['cert_for'] = (o['serial'], o['csr'])
        return self.text(o['cert'])

    def h_post_acme(self, path, data, tmpl):
        aid = 50 + len(self.acmes)
        self.acmes.append({'acme_id': aid, 'name': data['name'], 'status': 'active',
                           'product_code': data['product_code'],
                           'certificate_validity_days': data['certificate_validity_days'],
                           'organization_id': data.get('organization_id'),
                           'acme_directory_url': self.acme_url, 'inserted': '2026-11-01 10:00:00'})
        return self.ok(tmpl, 'POST', {'acme_id': aid, 'status': 'active',
                                      'acme_directory_url': self.acme_url, 'ext_act_kid': self.kid,
                                      'ext_act_hmac': self.hmac,
                                      'certbot_format': '--eab-kid %s --eab-hmac-key %s --server %s'
                                      % (self.kid, self.hmac, self.acme_url)}, 201)

    def h_get_acme_list(self, path, data, tmpl):
        item = schema(response_props(tmpl, 'GET', 200)['acmes']['items'])['properties']
        return self.ok(tmpl, 'GET', {'acmes': [shaped(item, a) for a in self.acmes]})

    def h_put_acme_acme_id_ACME_ID_revoke(self, path, data, tmpl):
        aid = int(path.split('/')[3])
        for a in self.acmes:
            if a['acme_id'] == aid:
                a['status'] = 'revoked'
        return self.ok(tmpl, 'PUT', {'acme_id': aid, 'status': 'revoked'}, 202)

    def h_get_acme_organization_list(self, path, data, tmpl):
        return self.ok(tmpl, 'GET', {'organizations': [
            {'organization_id': 12, 'status': 'active', 'name': 'Example s.r.o.', 'tel': '+420.1',
             'street': 'Ulice 1', 'zip': '11000', 'city': 'Praha', 'country': 'CZ', 'state': None,
             'validations': [{'type': 'OV', 'status': 'active', 'valid_till': '2027-06-01'}],
             'contacts': {'role': 'admin', 'first_name': 'Jana', 'last_name': 'N', 'email': 'j@x.cz',
                          'tel': '+420.1'}}]})

    def posts(self, tmpl, method='POST'):
        return [c for c in self.calls if c[0] == method and c[1] == tmpl]


class Ctx(FakeContext):
    def __init__(self, api):
        FakeContext.__init__(self)
        self.api = api

    def http(self, method, url, *a, **kw):
        if url.startswith(BASE):
            return self.api(method, url, *a, **kw)
        return FakeContext.http(self, method, url, *a, **kw)


class FakeDns(Challenge):
    """A DNS module as _common.DnsChallenge makes them: add_txt / del_txt."""
    kind = 'fakedns'
    types = ('dns-01',)

    def __init__(self, zone):
        Challenge.__init__(self, {}, None)
        self.zone = zone

    def target(self, rr):
        return rr

    def add_txt(self, fqdn, value):
        self.zone.setdefault(fqdn, []).append(value)
        return {'n': 1}

    def del_txt(self, fqdn, value, handle):
        if value in self.zone.get(fqdn, []):
            self.zone[fqdn].remove(value)

    def present(self, name, token, key_authorization, txt_value):
        rr = '_acme-challenge.' + name.lstrip('*.')
        self.add_txt(rr, txt_value)
        return {'rr': rr, 'fqdn': rr, 'txt': txt_value}

    def ready(self, name, handle):
        return handle['txt'] in self.zone.get(handle['fqdn'], [])

    def cleanup(self, name, handle):
        self.del_txt(handle['fqdn'], handle['txt'], None)

    # a commercial CA's DCV record (base.Challenge.place): a TXT at any name
    def place(self, kind, name, where, content):
        if kind != 'txt':
            raise NotImplementedError('no %s records' % kind)
        self.add_txt(where, content)
        return {'fqdn': where, 'txt': content}

    def placed_ready(self, handle):
        return handle['txt'] in self.zone.get(handle['fqdn'], [])

    def unplace(self, handle):
        self.del_txt(handle['fqdn'], handle['txt'], None)


class FakeHttp(Challenge):
    kind = 'fakehttp'
    types = ('http-01',)

    def __init__(self, files):
        Challenge.__init__(self, {}, None)
        self.files = files

    def present(self, name, token, key_authorization, txt_value):
        self.files[token] = key_authorization
        return {'token': token}

    def cleanup(self, name, handle):
        self.files.pop(handle['token'], None)

    # a commercial CA's DCV file (base.Challenge.place): any path under /.well-known/
    def place(self, kind, name, where, content):
        if kind != 'file':
            raise NotImplementedError('no %s records' % kind)
        self.files[where] = content
        return {'path': where}

    def unplace(self, handle):
        self.files.pop(handle['path'], None)


CONF = {'token': TOKEN, 'product': 'RAPIDSSL_STANDARD', 'owner_name': 'Example s.r.o.',
        'owner_street': 'Ulice 1', 'owner_city': 'Praha', 'owner_zip': '11000',
        'owner_country': 'cz', 'owner_tel': '+420.123456789', 'contact_first': 'Jana',
        'contact_last': 'Nováková', 'contact_email': 'pki@example.cz',
        'contact_tel': '+420.123456789', 'poll_every': 1, 'wait_issue': 60, 'wait_ready': 5}


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = TestCA(cn='Fake DigiCert G2 TLS CA')

    @classmethod
    def tearDownClass(cls):
        cls.ca.close()

    def setUp(self):
        self.api = FakeApi(self.ca)
        self.ctx = Ctx(self.api)
        self.zone = {}
        # a clock of the test's own: the waits pass at once
        self.clock = [time.time()]
        self._now = SM._now
        SM._now = lambda: self.clock[0]

    def tearDown(self):
        SM._now = self._now

    def sleep(self, s):
        self.clock[0] += s

    def issuer(self, **more):
        conf = dict(CONF)
        conf.update(more)
        iss = SslmarketIssuer(conf, self.ctx)
        iss._sleep = self.sleep
        return iss

    def req(self, names=('www.example.cz', 'example.cz'), cert_id=5, kind='ec'):
        key, csr_pem, csr_der = make_key_csr(list(names), kind)
        ch = FakeDns(self.zone)
        return CertRequest(names=list(names), key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                           key_type='rsa-2048' if kind == 'rsa' else 'ec-256',
                           challenges={n: ch for n in names}, cert_id=cert_id)


class TestContract(unittest.TestCase):
    def test_every_path_is_in_the_spec(self):
        self.assertEqual(SPEC['servers'][0]['url'], BASE)
        self.assertEqual(SPEC['components']['securitySchemes']['XAuthToken']['name'], 'X-Auth-Token')
        self.assertEqual(SM.API_URLS['cz'], BASE)
        used = {(SM.P_PRODUCTS, 'get'), (SM.P_ORDERS, 'get'), (SM.P_ORDER, 'post'),
                (SM.P_DETAIL, 'get'), (SM.P_DETAIL, 'put'), (SM.P_REISSUE, 'post'),
                (SM.P_CANCEL_REISSUE, 'put'), (SM.P_REVOKE, 'put'), (SM.P_RESEND, 'put'),
                (SM.P_DOWNLOAD, 'get'), (SM.P_ACME, 'post'), (SM.P_ACME_LIST, 'get'),
                (SM.P_ACME_REVOKE, 'put'), (SM.P_ACME_ORGS, 'get')}
        for p, m in used:
            self.assertIn(m, SPEC['paths'].get(p, {}), p)
        fmt = SPEC['paths'][SM.P_DOWNLOAD]['get']['parameters'][1]['schema']['enum']
        self.assertEqual(sorted(fmt), ['p7b', 'pem_intermediate', 'pem_server'])
        enum = SPEC['paths'][SM.P_DETAIL]['put']['requestBody']['content']['application/json'][
            'schema']['properties']['dv_auth_method']['enum']
        self.assertEqual(sorted(enum), sorted(SM.DV_METHODS))
        self.assertEqual([o[0] for o in [f for f in SslmarketIssuer.fields if f['key'] == 'dcv'][0]
                          ['options']], ['DNS', 'FILE', 'Email'])


class TestOrder(Base):
    def test_new_paid_order_full_flow(self):
        iss = self.issuer(allow_paid=True)
        r = self.req()
        seen = {}
        orig = FakeDns.add_txt

        def spy(ch, fqdn, value):
            seen[fqdn] = value
            return orig(ch, fqdn, value)
        FakeDns.add_txt = spy
        try:
            out = iss.issue(r)
        finally:
            FakeDns.add_txt = orig
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        self.assertIsNone(out.key_pem)
        self.assertEqual(len(out.chain_pems), 1)
        self.assertEqual(out.info['order_id'], '777')
        posts = self.api.posts(SM.P_ORDER)
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][2], '/order/certificate/RAPIDSSL_STANDARD')
        body = posts[0][3]
        self.assertEqual(body['domain'], 'www.example.cz')
        self.assertEqual(body['dns_names'], 'example.cz')
        self.assertEqual(body['years'], '1')
        self.assertEqual(body['dv_auth_method'], 'DNS')
        self.assertEqual(body['owner_country'], 'CZ')
        self.assertEqual(body['invoice_name'], 'Example s.r.o.')      # from the owner
        self.assertEqual(body['invoice_email'], 'pki@example.cz')
        self.assertIn('BEGIN CERTIFICATE REQUEST', body['csr'])
        # the order found in the list (the 201 has no body), the list read before and after
        self.assertEqual(len([c for c in self.api.calls if c[1] == SM.P_ORDERS]), 2)
        # dv_auth_content put in place through the validation module, then taken away
        self.assertEqual(seen, {'_dnsauth.www.example.cz': 'dcv-token-777',
                                '_dnsauth.example.cz': 'dcv-token-777'})
        self.assertFalse(any(self.zone.values()))
        self.assertIsNone(self.ctx.kv.get('sslmarket-pending:5:ec'))
        self.assertEqual(json.loads(self.ctx.kv['sslmarket-order:5:ec'])['order_id'], '777')
        self.assertTrue(any('dcv-token-777' in w for _l, w in self.ctx.steps))
        # the next renewal reissues inside the order: nothing bought
        r2 = self.req()
        out2 = iss.issue(r2)
        self.assertTrue(pki.key_matches(out2.cert_pem, r2.key_pem))
        self.assertEqual(len(self.api.posts(SM.P_ORDER)), 1)
        self.assertEqual(len(self.api.posts(SM.P_REISSUE)), 1)
        self.assertEqual(self.api.posts(SM.P_REISSUE)[0][3], {'csr': r2.csr_pem.strip()})
        self.assertTrue(any('free, nothing is bought' in w for _l, w in self.ctx.steps))

    def test_order_id_in_the_answer(self):
        self.api.created_body = lambda oid: {'order_id': int(oid)}
        out = self.issuer(allow_paid=True).issue(self.req())
        self.assertEqual(out.info['order_id'], '777')

    def test_no_paid_order_allowed(self):
        with self.assertRaises(PluginError) as e:
            self.issuer().issue(self.req())
        self.assertFalse(e.exception.retry)
        self.assertIn('Allow new orders (paid)', str(e.exception))
        self.assertIn('Order to reuse', str(e.exception))
        self.assertEqual([c for c in self.api.calls if c[0] != 'GET'], [])
        with self.assertRaises(PluginError):
            self.issuer(policy='new').issue(self.req())
        self.assertEqual([c for c in self.api.calls if c[0] != 'GET'], [])

    def test_reissue_of_a_given_order_and_its_child(self):
        end = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 500 * DAY))
        old = self.api.add_order(4241, ['www.example.cz'], '2026-01-01', serial='AA')
        old['has_child'], old['child_id'] = True, 4242
        self.api.add_order(4242, ['www.example.cz'], end, serial='0BEEF')
        r = self.req(names=('www.example.cz',))
        out = self.issuer(order_id='4241').issue(r)
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        self.assertEqual(self.api.posts(SM.P_ORDER), [])
        self.assertEqual([c[2] for c in self.api.posts(SM.P_REISSUE)],
                         ['/certificate/order_id/4242/reissue'])
        self.assertTrue(any('renewed as 4242' in w for _l, w in self.ctx.steps))

    def test_running_reissue_is_cancelled_first(self):
        end = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 500 * DAY))
        o = self.api.add_order(4242, ['www.example.cz'], end, serial='0BEEF')
        o['reissue_pending'] = True
        self.issuer(order_id='4242').issue(self.req(names=('www.example.cz',)))
        self.assertEqual(len(self.api.posts(SM.P_CANCEL_REISSUE, 'PUT')), 1)

    def test_order_not_issued_yet_is_filled(self):
        end = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 365 * DAY))
        self.api.add_order(9000, ['www.example.cz'], end, state='New', method='Email')
        r = self.req(names=('www.example.cz',))
        out = self.issuer(order_id='9000').issue(r)
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        put = self.api.posts(SM.P_DETAIL, 'PUT')
        self.assertEqual(put[0][3], {'csr': r.csr_pem.strip(), 'dv_auth_method': 'DNS'})
        self.assertEqual(self.api.posts(SM.P_ORDER), [])

    def test_order_ending_needs_a_new_order(self):
        end = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 10 * DAY))
        self.api.add_order(4242, ['www.example.cz'], end, serial='0BEEF')
        with self.assertRaises(PluginError) as e:
            self.issuer(order_id='4242').issue(self.req(names=('www.example.cz',)))
        self.assertIn('order 4242 ends', str(e.exception))
        self.assertFalse(e.exception.retry)
        out = self.issuer(order_id='4242', allow_paid=True).issue(self.req(names=('www.example.cz',)))
        self.assertEqual(len(self.api.posts(SM.P_ORDER)), 1)
        self.assertEqual(out.info['order_id'], '777')

    def test_pending_across_runs(self):
        self.api.pending_polls = 10 ** 6         # OV: the CA takes days
        iss = self.issuer(allow_paid=True, wait_issue=0)
        r1 = self.req()
        with self.assertRaises(PluginError) as e:
            iss.issue(r1)
        self.assertTrue(e.exception.retry)
        self.assertIn('waits at SSLmarket', str(e.exception))
        held = json.loads(self.ctx.kv['sslmarket-pending:5:ec'])
        self.assertEqual(held['order_id'], '777')
        self.assertTrue(held['key'].startswith('sealed:'))
        self.assertTrue(self.zone['_dnsauth.www.example.cz'])        # left for the CA
        with self.assertRaises(PluginError):
            iss.issue(self.req())
        self.assertEqual(len(self.api.posts(SM.P_ORDER)), 1)
        self.api.pending_polls = 0
        out = iss.issue(self.req())
        self.assertEqual(len(self.api.posts(SM.P_ORDER)), 1)
        self.assertTrue(pki.key_matches(out.cert_pem, r1.key_pem))
        self.assertEqual(out.key_pem.strip(), r1.key_pem.strip())
        self.assertNotIn('sslmarket-pending:5:ec', self.ctx.kv)
        self.assertFalse(any(self.zone.values()))

    def test_dual_twin_has_its_own_order(self):
        self.assertFalse(SslmarketIssuer.dual_for(CONF))
        self.assertTrue(SslmarketIssuer.dual_for({'dual_order': True}))
        iss = self.issuer(allow_paid=True, dual_order=True)
        a = iss.issue(self.req())
        b = iss.issue(self.req(kind='rsa'))
        self.assertNotEqual(a.info['order_id'], b.info['order_id'])
        self.assertEqual(len(self.api.posts(SM.P_ORDER)), 2)
        # renewed: each reissued inside its own order
        iss.issue(self.req())
        iss.issue(self.req(kind='rsa'))
        self.assertEqual(sorted(c[2] for c in self.api.posts(SM.P_REISSUE)),
                         ['/certificate/order_id/777/reissue', '/certificate/order_id/778/reissue'])

    def test_twin_order_to_reuse_by_key_type(self):
        end = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 500 * DAY))
        ec, rsa = self.req(names=('www.example.cz',)), self.req(names=('www.example.cz',), kind='rsa')
        self.api.add_order(1, ['www.example.cz'], end, serial='01', csr=ec.csr_pem)
        self.api.add_order(2, ['www.example.cz'], end, serial='02', csr=rsa.csr_pem)
        iss = self.issuer(order_id='1', order_id_alt='2')
        self.assertEqual(iss.issue(self.req(names=('www.example.cz',), kind='rsa')).info['order_id'], '2')
        self.assertEqual(iss.issue(self.req(names=('www.example.cz',))).info['order_id'], '1')

    def test_failed_order(self):
        self.api.pending_polls = 10 ** 6
        iss = self.issuer(allow_paid=True, wait_issue=0)
        with self.assertRaises(PluginError):
            iss.issue(self.req())
        self.api.orders['777']['state'] = 'Cancelled'
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req())
        self.assertIn('order 777 is Cancelled', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertFalse(any(self.zone.values()))
        # without the permission, the cancelled order is not replaced
        with self.assertRaises(PluginError) as e:
            self.issuer().issue(self.req())
        self.assertIn('nothing ordered: the order 777 is Cancelled', str(e.exception))

    def test_email_dcv_and_resend(self):
        iss = self.issuer(allow_paid=True, dcv='Email', wait_issue=0)
        self.assertFalse(iss.needs_challenge)
        self.api.pending_polls = 10 ** 6
        r = self.req()
        r.challenges = {}
        with self.assertRaises(PluginError) as e:
            iss.issue(r)
        self.assertIn('Send the DCV e-mail again', str(e.exception))
        self.assertEqual(self.api.posts(SM.P_ORDER)[0][3]['dv_auth_method'], 'Email')
        self.assertTrue(any('hostmaster@example.cz' in w and 'webmaster@www.example.cz' in w
                            for _l, w in self.ctx.steps))
        self.assertIn('777', iss.action('resend'))
        self.assertEqual([c[2] for c in self.api.posts(SM.P_RESEND, 'PUT')],
                         ['/certificate/order_id/777/resend'])

    def test_file_dcv(self):
        files = {}
        self.api.dv_content = lambda oid, o: 'http://www.example.cz/.well-known/acme-challenge/f%s c-%s' % (oid, oid)
        iss = self.issuer(allow_paid=True, dcv='FILE')
        r = self.req(names=('www.example.cz',))
        r.challenges = {'www.example.cz': FakeHttp(files)}
        seen = []
        orig = FakeHttp.place
        FakeHttp.place = lambda ch, *a: (seen.append(a), orig(ch, *a))[1]
        try:
            iss.issue(r)
        finally:
            FakeHttp.place = orig
        # put in place through the validation's placement API (base.Challenge.place)
        self.assertEqual(seen, [('file', 'www.example.cz', '/.well-known/acme-challenge/f777',
                                 'c-777')])
        self.assertEqual(files, {})
        self.assertEqual(self.api.posts(SM.P_ORDER)[0][3]['dv_auth_method'], 'FILE')

    def test_manual_dcv_when_no_module_can(self):
        self.api.dv_content = lambda oid, o: '_h.www.example.cz. CNAME h.sectigo.com.'
        self.api.pending_polls = 10 ** 6
        with self.assertRaises(PluginError) as e:
            self.issuer(allow_paid=True, wait_issue=0).issue(self.req(names=('www.example.cz',)))
        self.assertTrue(e.exception.retry)
        self.assertIn('by hand', str(e.exception))
        self.assertTrue(any('_h.www.example.cz. CNAME "h.sectigo.com"' in w
                            for _l, w in self.ctx.steps))


class TestPieces(Base):
    def test_errors_from_message(self):
        with self.assertRaises(PluginError) as e:
            self.issuer(token='wrong').test()
        self.assertFalse(e.exception.retry)
        self.assertIn('refuses the API key (401): Invalid token', str(e.exception))
        iss = self.issuer(allow_paid=True)
        for status, msg, words, retry in (
                (400, 'Invalid CSR', 'SSLmarket refused the order (400): Invalid CSR', False),
                (402, 'Not enough credit', 'Not enough credit', False),
                (500, 'Internal error', 'busy or broken (500): Internal error', True),
                (429, 'Slow down', 'busy or broken (429)', True)):
            self.api.fail = {('POST', SM.P_ORDER): (status, msg)}
            with self.assertRaises(PluginError) as e:
                iss.issue(self.req())
            self.assertIn(words, str(e.exception))
            self.assertEqual(e.exception.retry, retry, words)
        self.api.fail = {}
        with self.assertRaises(PluginError) as e:
            self.issuer(order_id='999').issue(self.req())
        self.assertIn('does not know the order 999 (404): Order not found', str(e.exception))

    def test_form_checks(self):
        r = self.req()
        with self.assertRaises(PluginError) as e:
            self.issuer(owner_tel='123 456').order_body(r)
        self.assertIn('+420.123456789', str(e.exception))
        with self.assertRaises(PluginError):
            self.issuer(owner_country='Czechia').order_body(r)
        with self.assertRaises(PluginError) as e:
            self.issuer(owner_street='').order_body(r)
        self.assertIn('owner\'s street', str(e.exception))
        with self.assertRaises(PluginError):
            self.issuer(extra=['no equals sign']).order_body(r)
        b = self.issuer(extra=['tech_email=tech@example.cz'], invoice_dic='CZ1', voucher='V1',
                        contact_title='Ing.').order_body(r)
        self.assertEqual((b['tech_email'], b['invoice_dic'], b['voucher'], b['auth_title']),
                         ('tech@example.cz', 'CZ1', 'V1', 'Ing.'))
        self.api.check('POST', '/order/certificate/X', {}, b)       # the contract holds
        with self.assertRaises(PluginError):
            self.issuer(api='custom', api_url='http://plain.example/api').base_url()
        self.assertEqual(self.issuer(api='custom', api_url='https://t.example/api/').base_url(),
                         'https://t.example/api')

    def test_product_limits(self):
        iss = self.issuer(allow_paid=True, years='5')
        iss.action('products')
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req())
        self.assertIn('at most 3 years', str(e.exception))
        with self.assertRaises(PluginError) as e:
            self.issuer(allow_paid=True).issue(self.req(names=('a.example.cz', 'b.example.cz',
                                                                'c.example.cz')))
        self.assertIn('at most 1 more names', str(e.exception))

    def test_test_and_actions(self):
        words = self.issuer().test()
        self.assertIn('2 products', words)
        self.assertIn('RAPIDSSL_STANDARD is offered (RapidSSL Standard, DV)', words)
        self.assertIn('0 orders', words)
        self.assertIn('not allowed', words)
        self.assertIn('NOT among them', self.issuer(product='X').test())
        self.assertEqual([c for c in self.api.calls if c[0] != 'GET'], [])
        self.assertEqual(self.issuer().action('products'), '2 products; put the code under Product code')
        self.assertEqual(len(json.loads(self.ctx.kv['sslmarket-products'])['products']), 2)
        self.api.add_order(1, ['a.example.cz', 'b.example.cz'], '2027-05-01')
        self.assertEqual(self.issuer().action('orders'), '1 orders')
        self.assertTrue(any('ends 2027-05-01' in w and '+ b.example.cz' in w for _l, w in self.ctx.steps))
        self.assertIn('cancelled', self.issuer(order_id='1').action('cancel_reissue'))
        with self.assertRaises(PluginError):
            self.issuer().action('resend')
        with self.assertRaises(PluginError):
            self.issuer().action('nothing')

    def test_revoke_says_what_the_api_can(self):
        out = self.issuer(allow_paid=True).issue(self.req())
        with self.assertRaises(PluginError) as e:
            self.issuer().revoke(out.cert_pem, 'keyCompromise')
        self.assertIn('Client Premium', str(e.exception))
        self.assertEqual([c[2] for c in self.api.posts(SM.P_REVOKE, 'PUT')],
                         ['/certificate/order_id/777/revoke'])

    def test_dcv_content_shapes(self):
        iss = self.issuer()
        names = ['www.example.cz', '*.example.cz']
        self.assertEqual(iss.dcv_records('tok1', 'DNS', names), [
            {'domain': 'www.example.cz', 'type': 'txt', 'fqdn': '_dnsauth.www.example.cz', 'value': 'tok1'},
            {'domain': 'example.cz', 'type': 'txt', 'fqdn': '_dnsauth.example.cz', 'value': 'tok1'}])
        self.assertEqual(self.issuer(txt_label='@').dcv_records('tok1', 'DNS', ['example.cz'])[0]['fqdn'],
                         'example.cz')
        self.assertEqual(iss.dcv_records('_dnsauth.example.cz. 300 IN TXT "abc"', 'DNS', names),
                         [{'domain': 'example.cz', 'type': 'txt', 'fqdn': '_dnsauth.example.cz',
                           'value': 'abc'}])
        self.assertEqual(iss.dcv_records('_x CNAME y.sectigo.com.', 'DNS', ['example.cz']),
                         [{'domain': 'example.cz', 'type': 'cname', 'fqdn': '_x.example.cz',
                           'value': 'y.sectigo.com'}])
        self.assertEqual(iss.dcv_records('{"name": "_dnsauth.example.cz", "value": "j1"}', 'DNS',
                                         ['example.cz'])[0]['value'], 'j1')
        f = iss.dcv_records('abc123', 'FILE', ['example.cz'])
        self.assertEqual(f, [{'domain': 'example.cz', 'type': 'file',
                              'path': '/.well-known/pki-validation/fileauth.txt', 'value': 'abc123'}])
        f = iss.dcv_records('/.well-known/pki-validation/AB12.txt\nline1\nline2', 'FILE', ['example.cz'])
        self.assertEqual((f[0]['path'], f[0]['value']), ('/.well-known/pki-validation/AB12.txt',
                                                         'line1\nline2'))
        self.assertEqual(iss.dcv_records('some words that are not a value', 'DNS', names), [])
        st = SslmarketIssuer
        self.assertTrue(st.failed({'state': 'Cancelled'}))
        self.assertTrue(st.failed({'state': 'Zamítnuto'}))
        self.assertFalse(st.failed({'state': 'Issued'}))
        self.assertEqual(SM._when('2027-01-02'), 1798848000.0)
        self.assertEqual(SM._when('02.01.2027'), 1798848000.0)

    def test_registry(self):
        reg = Registry().reload()
        self.assertFalse([b for b in reg.broken if 'sslmarket' in b[0]])
        d = reg.get('issuer', 'sslmarket').describe()
        self.assertEqual(d['vendor'], 'SSLmarket')
        self.assertTrue(d['needs_challenge'])
        self.assertEqual(d['dual_field'], 'dual_order')
        self.assertIs([f for f in d['fields'] if f['key'] == 'allow_paid'][0]['default'], False)
        a = reg.get('issuer', 'sslmarket_acme').describe()
        keys = [f['key'] for f in a['fields']]
        self.assertNotIn('directory', keys)
        self.assertNotIn('eab_hmac', keys)
        self.assertIn('contacts', keys)
        from acmelib.certs import store as S
        for dd in (d, a):
            self.assertTrue(S.NAME_RE.match(dd['default_name']), dd['default_name'])


class TestAcmeKey(unittest.TestCase):
    """SSLmarket ACME: the key made through the API, then ACME with its EAB."""
    def setUp(self):
        self.acme = MockAcme(require_eab=True)
        self.api = FakeApi(None, acme_url=self.acme.base + '/dir', kid=MockAcme.EAB_KID,
                           hmac=b64u(MockAcme.EAB_KEY))
        self.ctx = Ctx(self.api)

    def tearDown(self):
        self.acme.close()

    def issuer(self, **more):
        conf = {'token': TOKEN, 'acme_product': 'DIGICERT_ACME_DV', 'acme_name': 'web',
                'validity_days': 90, 'contacts': ['pki@example.cz'], 'poll_every': 0.2,
                'wait_ready': 10, 'wait_valid': 10, 'wait_order': 10}
        conf.update(more)
        return SslmarketAcmeIssuer(conf, self.ctx)

    def req(self, names=('www.example.cz',)):
        key, csr_pem, csr_der = make_key_csr(list(names))
        web = FakeChallenge(('http-01',), self.acme.board)
        return CertRequest(names=list(names), key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                           challenges={n: web for n in names}, cert_id=9)

    def test_end_to_end(self):
        iss = self.issuer()
        self.assertIn('none kept for this source yet', iss.test())
        self.assertEqual(self.api.posts(SM.P_ACME), [])
        out = iss.issue(self.req())
        self.assertIn('BEGIN CERTIFICATE', out.cert_pem)
        self.assertEqual(out.info['directory'], self.acme.base + '/dir')
        body = self.api.posts(SM.P_ACME)[0][3]
        self.assertEqual(body, {'product_code': 'DIGICERT_ACME_DV', 'name': 'web',
                                'certificate_validity_days': 90})
        slot = [k for k in self.ctx.kv if k.startswith('sslmarket-acme:')]
        self.assertEqual(len(slot), 1)
        row = json.loads(self.ctx.kv[slot[0]])
        self.assertTrue(row['hmac'].startswith('sealed:'))
        self.assertEqual(row['kid'], MockAcme.EAB_KID)
        # renewals: the same key and ACME account, nothing asked of SSLmarket's API
        n = len(self.api.calls)
        iss2 = self.issuer()
        out2 = iss2.issue(self.req())
        self.assertEqual(out2.info['account_url'], out.info['account_url'])
        self.assertEqual(len(self.api.calls), n)
        self.assertEqual(len(self.acme.accounts), 1)
        self.assertIn('ACME key 50', self.issuer().test())
        # the actions
        self.assertEqual(self.issuer().action('acme_keys'), '1 ACME keys')
        self.assertEqual(self.issuer().action('organizations'), '1 organisations')
        self.assertTrue(any('organisation 12: Example s.r.o.' in w for _l, w in self.ctx.steps))
        self.assertIn('revoked', self.issuer().action('revoke_key'))
        self.assertEqual(self.api.acmes[0]['status'], 'revoked')
        self.assertFalse([k for k in self.ctx.kv if k.startswith('sslmarket-acme:')])

    def test_settings_and_refusals(self):
        with self.assertRaises(PluginError):
            self.issuer(validity_days=200).issue(self.req())
        with self.assertRaises(PluginError):
            self.issuer(organization_id='Example').issue(self.req())
        with self.assertRaises(PluginError) as e:
            self.issuer(make_key=False).issue(self.req())
        self.assertIn('Make an ACME key', str(e.exception))
        self.assertEqual(self.api.posts(SM.P_ACME), [])
        cred = self.issuer(organization_id='12').credentials()
        self.assertEqual(self.api.posts(SM.P_ACME)[0][3]['organization_id'], 12)
        self.assertEqual(cred['url'], self.acme.base + '/dir')
        # a key made in the administration: its EAB pasted, its URL found by the name
        self.ctx.kv.clear()
        out = self.issuer(make_key=False, given_kid=MockAcme.EAB_KID,
                          given_hmac=b64u(MockAcme.EAB_KEY), organization_id='12').issue(self.req())
        self.assertIn('BEGIN CERTIFICATE', out.cert_pem)
        self.assertEqual(len(self.api.posts(SM.P_ACME)), 1)




class TestLegacyDcv(unittest.TestCase):
    """An order waiting across the upgrade to 1.0.5 holds its DCV records in the
    way of before ('present', 'txt', 'file', 'record'): taken away all the same."""
    def test_legacy_records_taken_away(self):
        from acmelib.plugins.issuers import _dcv
        gone = []

        class Ch(object):
            kind = 'fake'
            def cleanup(self, name, handle): gone.append(('present', name, handle))
            def del_txt(self, fqdn, txt, h): gone.append(('txt', fqdn, txt))
            def cleanup_record(self, name, handle): gone.append(('record', name, handle))
            def unplace(self, handle): gone.append(('placed', handle))

        class Req(object):
            challenges = {'www.example.com': Ch()}

        class Iss(object):
            ctx = None
            def c(self, k, d=None): return d
        placer = _dcv.Placer.__new__(_dcv.Placer)
        placer.issuer = Iss()
        placer._say = lambda *a, **k: None
        rec = {'domain': 'example.com'}
        placer.cleanup(Req(), [
            {'rec': rec, 'name': 'www.example.com', 'how': 'present', 'handle': {'x': 1}, 'kind': 'fake'},
            {'rec': rec, 'name': 'www.example.com', 'how': 'txt', 'kind': 'fake',
             'handle': {'fqdn': '_dnsauth.example.com', 'txt': 'v1'}},
            {'rec': rec, 'name': 'www.example.com', 'how': 'record', 'handle': {'r': 2}, 'kind': 'fake'},
            {'rec': rec, 'name': 'www.example.com', 'how': 'placed', 'handle': {'p': 3}, 'kind': 'fake'},
            {'rec': rec, 'name': 'www.example.com', 'how': 'manual', 'handle': None, 'kind': ''}])
        self.assertEqual([g[0] for g in gone], ['present', 'txt', 'record', 'placed'])
        self.assertIn(('txt', '_dnsauth.example.com', 'v1'), gone)


if __name__ == '__main__':
    unittest.main(verbosity=2)
