#!/usr/bin/env python3
"""The SSLmarket issuer (acmelib/plugins/issuers/sslmarket.py) against a fake
SSLmarket API: canned answers through ctx.http, no network.

    python3 -m unittest test/test_sslmarket.py -v
    python3 test/test_sslmarket.py

The certificates are real (a test CA signs the CSR the module sent, with
the openssl program); the DCV records go through fake challenge modules.
"""
import json
import os
import sys
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from acmelib.plugins.base import Challenge, CertRequest, PluginError, Registry  # noqa: E402
from acmelib.plugins.issuers import sslmarket as SM                            # noqa: E402
from acmelib.plugins.issuers.sslmarket import SslmarketIssuer                  # noqa: E402
from acmelib.certs import pki                                                  # noqa: E402
from test_issuers import FakeContext, TestCA, make_key_csr                     # noqa: E402

TOKEN = 'k3y-0f-the-account'
DAY = 86400


class FakeApi(object):
    """SSLmarket as the module expects it: X-Auth-Token, JSON, the paths of PATHS."""
    def __init__(self, ca, base='https://www.sslmarket.cz/api'):
        self.ca = ca
        self.base = base
        self.calls = []
        self.orders = {}             # id -> {'csr', 'state', 'polls', 'end', 'names'}
        self.next_id = 777
        self.pending_polls = 1       # detail says pending this many times, then Issued
        self.fail = {}               # path -> (status, body)
        self.dcv_answer = None       # fn(order_id, names) -> the dcv part of an answer

    def add_order(self, oid, names, end, state='Issued', csr_pem=None):
        self.orders[str(oid)] = {'csr': csr_pem, 'state': state, 'polls': 0, 'end': end,
                                 'names': names}

    def _dcv(self, oid, names):
        if self.dcv_answer:
            return self.dcv_answer(oid, names)
        return [{'domain': n, 'method': 'dns', 'record_name': '_dnsauth.' + n,
                 'record_value': 'tok-%s-%s' % (oid, n)} for n in names]

    def __call__(self, method, url, body=None, headers=None, timeout=30, verify=True,
                 ca_pem=None, client_cert=None, proxy=True):
        assert url.startswith(self.base), url
        path = urllib.parse.urlsplit(url).path[len(urllib.parse.urlsplit(self.base).path):]
        data = json.loads(body.decode()) if body else None
        self.calls.append((method, path, data, dict(headers or {})))
        if (headers or {}).get('X-Auth-Token') != TOKEN:
            return 401, {}, json.dumps({'errors': [{'message': 'Invalid token'}]}).encode()
        if path in self.fail:
            st, b = self.fail[path]
            return st, {}, json.dumps(b).encode()
        j = lambda o, st=200: (st, {'content-type': 'application/json'}, json.dumps(o).encode())  # noqa: E731
        if method == 'GET' and path == '/product/list':
            return j({'data': [{'code': 'RAPIDSSL_RAPIDSSL', 'name': 'RapidSSL', 'price': 290},
                               {'code': 'GEOTRUST_TRUE_BUSINESSID', 'name': 'True BusinessID',
                                'price': 2190}]})
        if method == 'GET' and path == '/account/detail':
            return j({'data': {'credit': '1500.00 CZK'}})
        if method == 'GET' and path == '/order/list':
            return j({'data': [{'order_id': k, 'domain': o['names'][0], 'product': 'X',
                                'status': o['state'], 'subscription_end': o['end']}
                               for k, o in self.orders.items()]})
        if method == 'POST' and path.startswith('/order/certificate/'):
            oid = str(self.next_id)
            self.next_id += 1
            names = [data['domain']] + [n for n in (data.get('sans') or '').split(',') if n]
            self.add_order(oid, names, time.strftime('%Y-%m-%d', time.gmtime(time.time() + 365 * DAY)),
                           state='Waiting for validation', csr_pem=data['csr'])
            return j({'ack': 'Success', 'data': {'order_id': int(oid),
                                                 'dcv': self._dcv(oid, names)}}, 201)
        oid = path.rsplit('/', 1)[-1]
        o = self.orders.get(oid)
        if o is None:
            return j({'errors': [{'message': 'Order not found'}]}, 404)
        if method == 'POST' and path.startswith('/order/reissue/'):
            o['csr'] = data['csr']
            o['state'] = 'Reissue pending'
            o['polls'] = 0
            names = [data['domain']] + [n for n in (data.get('sans') or '').split(',') if n]
            return j({'order_id': oid, 'dcv': self._dcv(oid, names)})
        if method == 'GET' and path.startswith('/order/detail/'):
            if o['state'] != 'Issued':
                o['polls'] += 1
                if o['polls'] > self.pending_polls:
                    o['state'] = 'Issued'
            return j({'data': {'order': {'id': oid, 'status': o['state'],
                                         'subscription_end': o['end'],
                                         'domain': o['names'][0]}}})
        if method == 'GET' and path.startswith('/order/download/'):
            csr_der = pki.pem_to_der(o['csr'])
            leaf = self.ca.sign_csr(csr_der, o['names'])
            return j({'certificate': leaf, 'ca_bundle': self.ca.pem})
        if method == 'POST' and path.startswith('/order/revoke/'):
            o['state'] = 'Revoked'
            return j({'ack': 'Success'})
        return j({'errors': ['no such call %s %s' % (method, path)]}, 400)

    def posts(self, prefix):
        return [c for c in self.calls if c[0] == 'POST' and c[1].startswith(prefix)]


class Ctx(FakeContext):
    def __init__(self, api):
        FakeContext.__init__(self)
        self.api = api

    def http(self, *a, **kw):
        return self.api(*a, **kw)


class FakeDns(Challenge):
    """A DNS provider module as _common.DnsChallenge makes them: add_txt / del_txt."""
    kind = 'fakedns'
    types = ('dns-01',)

    def __init__(self, zone):
        Challenge.__init__(self, {}, None)
        self.zone = zone
        self.ready_calls = 0

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
        self.ready_calls += 1
        return handle['txt'] in self.zone.get(handle['fqdn'], [])

    def cleanup(self, name, handle):
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


CONF = {'token': TOKEN, 'product': 'RAPIDSSL_RAPIDSSL', 'contact_first': 'Jana',
        'contact_last': 'Nováková', 'contact_email': 'pki@example.cz',
        'contact_phone': '+420.123456789', 'poll_every': 1, 'wait_issue': 60,
        'wait_ready': 5}


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

    def issuer(self, **more):
        conf = dict(CONF)
        conf.update(more)
        iss = SslmarketIssuer(conf, self.ctx)
        iss._sleep = lambda s: None
        return iss

    def req(self, names=('www.example.cz', 'example.cz'), cert_id=5):
        key, csr_pem, csr_der = make_key_csr(list(names))
        ch = FakeDns(self.zone)
        return CertRequest(names=list(names), key_pem=key, csr_pem=csr_pem, csr_der=csr_der,
                           challenges={n: ch for n in names}, cert_id=cert_id)


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
        self.assertIsNone(out.key_pem)                  # the request's own key
        self.assertEqual(len(out.chain_pems), 1)
        self.assertEqual(out.info['order_id'], '777')
        posts = self.api.posts('/order/certificate/RAPIDSSL_RAPIDSSL')
        self.assertEqual(len(posts), 1)
        body, headers = posts[0][2], posts[0][3]
        self.assertEqual(headers['X-Auth-Token'], TOKEN)
        self.assertEqual(headers['Content-Type'], 'application/json')
        self.assertEqual(body['domain'], 'www.example.cz')
        self.assertEqual(body['sans'], 'example.cz')
        self.assertEqual(body['sans_count'], 1)
        self.assertEqual(body['dv_auth_method'], 'DNS')
        self.assertEqual(body['method'], 'new')
        self.assertEqual(body['certificate'], 'RAPIDSSL_RAPIDSSL')
        self.assertIn('BEGIN CERTIFICATE REQUEST', body['csr'])
        self.assertEqual(body['tech_email'], 'pki@example.cz')
        # the DCV records went through the challenge module, and are gone again
        self.assertEqual(seen, {'_dnsauth.www.example.cz': 'tok-777-www.example.cz',
                                '_dnsauth.example.cz': 'tok-777-example.cz'})
        self.assertFalse(any(self.zone.values()))
        self.assertIsNone(self.ctx.kv.get('sslmarket-pending:5'))
        self.assertEqual(json.loads(self.ctx.kv['sslmarket-order:5'])['order_id'], '777')
        # the next renewal reissues inside the order: nothing bought
        r2 = self.req()
        out2 = iss.issue(r2)
        self.assertTrue(pki.key_matches(out2.cert_pem, r2.key_pem))
        self.assertEqual(len(self.api.posts('/order/certificate/')), 1)
        self.assertEqual(len(self.api.posts('/order/reissue/777')), 1)
        self.assertNotIn('certificate', self.api.posts('/order/reissue/777')[0][2])

    def test_no_paid_order_allowed(self):
        iss = self.issuer()
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req())
        self.assertFalse(e.exception.retry)
        self.assertIn('Allow new orders (paid)', str(e.exception))
        self.assertIn('Order to reuse', str(e.exception))
        self.assertEqual(self.api.posts('/'), [])
        # a policy of "always new" without the permission: refused just the same
        with self.assertRaises(PluginError):
            self.issuer(policy='new').issue(self.req())
        self.assertEqual(self.api.posts('/'), [])

    def test_reissue_of_a_given_order(self):
        end = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 500 * DAY))
        self.api.add_order(4242, ['www.example.cz'], end)
        iss = self.issuer(order_id='4242')
        r = self.req(names=('www.example.cz',))
        out = iss.issue(r)
        self.assertTrue(pki.key_matches(out.cert_pem, r.key_pem))
        self.assertEqual(self.api.posts('/order/certificate/'), [])
        self.assertEqual(len(self.api.posts('/order/reissue/4242')), 1)
        self.assertTrue(any('free, nothing is bought' in w for _l, w in self.ctx.steps))

    def test_subscription_ending_needs_a_renewal_order(self):
        end = time.strftime('%Y-%m-%d', time.gmtime(time.time() + 10 * DAY))
        self.api.add_order(4242, ['www.example.cz'], end)
        with self.assertRaises(PluginError) as e:
            self.issuer(order_id='4242').issue(self.req(names=('www.example.cz',)))
        self.assertIn('subscription of order 4242 ends', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertEqual(self.api.posts('/'), [])
        out = self.issuer(order_id='4242', allow_paid=True).issue(self.req(names=('www.example.cz',)))
        posts = self.api.posts('/order/certificate/')
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][2]['method'], 'renew')
        self.assertEqual(out.info['order_id'], '777')

    def test_pending_across_runs(self):
        self.api.pending_polls = 10 ** 6         # OV: the CA takes days
        iss = self.issuer(allow_paid=True, wait_issue=0, validation='ov', org_name='Example s.r.o.',
                          org_street='Ulice 1', org_city='Praha', org_zip='11000', org_country='cz')
        r1 = self.req()
        with self.assertRaises(PluginError) as e:
            iss.issue(r1)
        self.assertTrue(e.exception.retry)
        self.assertIn('waits at SSLmarket', str(e.exception))
        self.assertIn('OV/EV', str(e.exception))
        body = self.api.posts('/order/certificate/')[0][2]
        self.assertEqual(body['owner_name'], 'Example s.r.o.')
        self.assertEqual(body['owner_country'], 'CZ')
        held = json.loads(self.ctx.kv['sslmarket-pending:5'])
        self.assertEqual(held['order_id'], '777')
        self.assertTrue(held['key'].startswith('sealed:'))
        self.assertTrue(self.zone['_dnsauth.www.example.cz'])       # left for the CA
        # the second try: another key and CSR made by the renewer - no new order
        with self.assertRaises(PluginError):
            iss.issue(self.req())
        self.assertEqual(len(self.api.posts('/order/certificate/')), 1)
        # the CA is done: the certificate of the first request, with its key
        self.api.pending_polls = 0
        r3 = self.req()
        out = iss.issue(r3)
        self.assertEqual(len(self.api.posts('/order/certificate/')), 1)
        self.assertTrue(pki.key_matches(out.cert_pem, r1.key_pem))
        self.assertEqual(out.key_pem.strip(), r1.key_pem.strip())
        self.assertNotIn('sslmarket-pending:5', self.ctx.kv)
        self.assertFalse(any(self.zone.values()))

    def test_failed_order_and_other_names(self):
        self.api.pending_polls = 10 ** 6
        iss = self.issuer(allow_paid=True, wait_issue=0)
        with self.assertRaises(PluginError):
            iss.issue(self.req())
        # names changed meanwhile: the waiting order is let go, its records taken away
        self.api.orders['777']['state'] = 'Rejected'
        with self.assertRaises(PluginError) as e:
            iss.issue(self.req(names=('other.example.cz',)))
        self.assertTrue(any('was for other names' in w for _l, w in self.ctx.steps))
        self.assertFalse(self.zone.get('_dnsauth.www.example.cz'))
        self.assertTrue(e.exception.retry)              # a new order, waiting in its turn
        self.assertTrue(any('order 777 is Rejected' in w for _l, w in self.ctx.steps))
        posts = self.api.posts('/order/certificate/')
        self.assertEqual([p[2]['method'] for p in posts], ['new', 'new'])
        self.assertEqual(posts[1][2]['domain'], 'other.example.cz')
        # without the permission, the rejected order is not replaced
        self.ctx.kv.pop('sslmarket-pending:5')
        self.ctx.kv['sslmarket-order:5'] = json.dumps({'order_id': '777'})
        with self.assertRaises(PluginError) as e:
            self.issuer().issue(self.req(names=('other.example.cz',)))
        self.assertIn('nothing ordered: the order 777 is Rejected', str(e.exception))
        self.assertFalse(e.exception.retry)

    def test_email_dcv_and_http_file(self):
        iss = self.issuer(allow_paid=True, dcv='email', approver='hostmaster@')
        self.assertFalse(iss.needs_challenge)
        r = self.req()
        r.challenges = {}
        iss.issue(r)
        body = self.api.posts('/order/certificate/')[0][2]
        self.assertEqual(body['dv_auth_method'], 'Email')
        self.assertEqual(body['verify_mailbox'], 'hostmaster@')
        # a file under /.well-known/acme-challenge/: written by the HTTP-01 module
        files = {}
        self.api.dcv_answer = lambda oid, names: [
            {'domain': n, 'file_url': 'http://%s/.well-known/acme-challenge/f%s' % (n, oid),
             'file_content': 'c-' + n} for n in names]
        self.ctx.kv.clear()
        iss = self.issuer(allow_paid=True, dcv='http-file')
        r = self.req(names=('www.example.cz',))
        r.challenges = {'www.example.cz': FakeHttp(files)}
        seen = []
        orig = FakeHttp.present
        FakeHttp.present = lambda ch, *a: (seen.append(a), orig(ch, *a))[1]
        try:
            iss.issue(r)
        finally:
            FakeHttp.present = orig
        self.assertEqual(seen, [('www.example.cz', 'f778', 'c-www.example.cz', '')])
        self.assertEqual(files, {})
        self.assertEqual(self.api.posts('/order/certificate/')[-1][2]['dv_auth_method'], 'FILE')


class TestPieces(Base):
    def test_errors(self):
        iss = self.issuer(token='wrong')
        with self.assertRaises(PluginError) as e:
            iss.test()
        self.assertFalse(e.exception.retry)
        self.assertIn('refuses the API key (401)', str(e.exception))
        self.assertIn('Invalid token', str(e.exception))
        iss = self.issuer(allow_paid=True)
        for status, body, words, retry in (
                (402, {'message': 'Insufficient credit'}, 'not enough credit', False),
                (500, {}, 'busy or broken (500)', True),
                (422, {'errors': [{'field': 'csr', 'message': 'CSR is not valid'}]},
                 'csr: CSR is not valid', False),
                (200, {'ack': 'Error', 'errors': ['Unknown product']}, 'Unknown product', False)):
            self.api.fail = {'/order/certificate/RAPIDSSL_RAPIDSSL': (status, body)}
            with self.assertRaises(PluginError) as e:
                iss.issue(self.req())
            self.assertIn(words, str(e.exception))
            self.assertEqual(e.exception.retry, retry, words)
        self.api.fail = {}
        with self.assertRaises(PluginError) as e:
            self.issuer(order_id='999').issue(self.req())
        self.assertIn('404', str(e.exception))

    def test_test_and_actions(self):
        words = self.issuer().test()
        self.assertIn('2 products', words)
        self.assertIn('RAPIDSSL_RAPIDSSL is offered', words)
        self.assertIn('credit 1500.00 CZK', words)
        self.assertIn('not allowed', words)
        self.assertIn('NOT among them', self.issuer(product='other', product_code='X').test())
        self.assertEqual(self.api.posts('/'), [])
        self.assertEqual(self.issuer().action('products'), '2 products; put the code under '
                                                           'Product → Another product')
        self.assertEqual(len(json.loads(self.ctx.kv['sslmarket-products'])['products']), 2)
        self.api.add_order(1, ['a.example.cz'], '2027-05-01')
        self.assertEqual(self.issuer().action('orders'), '1 orders')
        self.assertTrue(any('subscription until 2027-05-01' in w for _l, w in self.ctx.steps))
        with self.assertRaises(PluginError):
            self.issuer().action('nothing')

    def test_revoke(self):
        out = self.issuer(allow_paid=True).issue(self.req())
        self.assertIn('777', self.issuer().revoke(out.cert_pem, 'keyCompromise'))
        self.assertEqual(self.api.posts('/order/revoke/777')[0][2]['reason'], 'keyCompromise')

    def test_state_dates_and_dcv_shapes(self):
        st = SslmarketIssuer.state_of
        self.assertEqual(st({'status': 'Issued'})[0], 'issued')
        self.assertEqual(st({'data': {'state': 'completed'}})[0], 'issued')
        self.assertEqual(st({'status': 'Waiting for validation'})[0], 'pending')
        self.assertEqual(st({'status': 'validation'})[0], 'pending')
        self.assertEqual(st({'status': 'Cancelled'})[0], 'failed')
        self.assertEqual(st({'status': {'code': 'REJECTED'}})[0], 'failed')
        self.assertEqual(SM._when('2027-01-02'), 1798848000.0)
        self.assertEqual(SM._when('02.01.2027'), 1798848000.0)
        self.assertEqual(SM._when(1798848000000), 1798848000.0)
        self.assertIsNone(SM._when('soon'))
        iss = self.issuer()
        recs = iss.dcv_records({'data': {'domain': 'www.example.cz',
                                         'dcv': {'www.example.cz': {'txt_value': 'v1'},
                                                 'example.cz': {'host': '@', 'value': 'v2'}}}})
        self.assertEqual(recs, [
            {'domain': 'www.example.cz', 'type': 'txt', 'fqdn': '_dnsauth.www.example.cz', 'value': 'v1'},
            {'domain': 'example.cz', 'type': 'txt', 'fqdn': 'example.cz', 'value': 'v2'}])
        self.assertEqual(self.issuer(txt_label='@').dcv_records(
            {'domain': 'example.cz', 'dns_txt_value': 'v3'})[0]['fqdn'], 'example.cz')
        recs = self.issuer(dcv='dns-cname').dcv_records({'dcv': [
            {'domain': 'example.cz', 'cname_name': '_abc', 'cname_value': 'x.sectigo.com.'}]})
        self.assertEqual(recs, [{'domain': 'example.cz', 'type': 'cname',
                                 'fqdn': '_abc.example.cz', 'value': 'x.sectigo.com'}])
        recs = self.issuer(dcv='http-file').dcv_records({'dcv': [
            {'domain': 'example.cz', 'file_name': 'fileauth.txt', 'file_content': 'abc'}]})
        self.assertEqual(recs[0]['path'], '/.well-known/pki-validation/fileauth.txt')
        self.assertEqual(iss.dcv_records({'order_id': 5}), [])

    def test_manual_dcv_when_no_module_can(self):
        # a CNAME record: no challenge module writes one - said in the job, the order waits
        self.api.dcv_answer = lambda oid, names: [
            {'domain': n, 'method': 'cname', 'cname_name': '_h.' + n, 'cname_value': 'h.sectigo.com'}
            for n in names]
        self.api.pending_polls = 10 ** 6
        with self.assertRaises(PluginError) as e:
            self.issuer(allow_paid=True, dcv='dns-cname', wait_issue=0).issue(self.req())
        self.assertTrue(e.exception.retry)
        self.assertTrue(any('_h.www.example.cz. CNAME "h.sectigo.com"' in w
                            for _l, w in self.ctx.steps))
        self.assertEqual(self.api.posts('/order/certificate/')[0][2]['dv_auth_method'], 'CNAME')

    def test_form_body_and_custom_url(self):
        self.api.base = 'https://test.sslmarket.example/api'
        iss = self.issuer(api='custom', api_url='https://test.sslmarket.example/api/', body='form')
        self.assertEqual(iss.base_url(), 'https://test.sslmarket.example/api')
        orig = self.api.__class__.__call__
        got = []

        def capture(api, method, url, body=None, headers=None, *a, **kw):
            got.append((body, headers))
            if body:
                body = json.dumps(dict(urllib.parse.parse_qsl(body.decode()))).encode()
            return orig(api, method, url, body, headers, *a, **kw)
        self.api.__class__.__call__ = capture
        try:
            self.issuer(api='custom', api_url='https://test.sslmarket.example/api', body='form',
                        allow_paid=True, extra=['invoice_vat_id=CZ12345678']).issue(self.req())
        finally:
            self.api.__class__.__call__ = orig
        post = [g for g in got if g[0]][0]
        self.assertEqual(post[1]['Content-Type'], 'application/x-www-form-urlencoded')
        self.assertIn(b'invoice_vat_id=CZ12345678', post[0])
        with self.assertRaises(PluginError):
            self.issuer(api='custom', api_url='http://plain.example/api').base_url()
        with self.assertRaises(PluginError):
            self.issuer(extra=['no equals sign']).order_body(self.req())

    def test_registry(self):
        reg = Registry().reload()
        cls = reg.get('issuer', 'sslmarket')
        d = cls.describe()
        self.assertEqual(d['vendor'], 'SSLmarket')
        self.assertTrue(d['needs_challenge'])
        self.assertIn('allow_paid', [f['key'] for f in d['fields']])
        paid = [f for f in d['fields'] if f['key'] == 'allow_paid'][0]
        self.assertIs(paid['default'], False)
        self.assertFalse([b for b in reg.broken if 'sslmarket' in b[0]])
        from acmelib.plugins.issuers import _acme_client as ac
        self.assertIn('digicert', ac.DIRECTORIES)


if __name__ == '__main__':
    unittest.main()
