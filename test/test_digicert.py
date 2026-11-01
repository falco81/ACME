#!/usr/bin/env python3
"""DigiCert CertCentral (acmelib/plugins/issuers/digicert.py) - DigiCert,
GeoTrust, Thawte, RapidSSL - against canned CertCentral answers.

    python3 test/test_digicert.py

No network. A little CertCentral in memory (orders, reissues, the account's
domains and organizations, DCV checks) signs with a test CA of openssl's. The
DCV records go in place through the placement API of the certificate's own
validation (base.Challenge.place): a TXT and a CNAME on a DNS board, the file
of http-token answered by this server (http_local). And a contract test: every
path the module may call, as CertCentral documents it.
"""
import json
import os
import re
import sys
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from test_issuers_more import Base, CannedContext, csr_der_of, hdr, req_for  # noqa: E402

from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.challenges._common import DnsChallenge  # noqa: E402
from acmelib.plugins.challenges.http_local import HttpLocal  # noqa: E402
from acmelib.plugins.issuers import digicert as DC  # noqa: E402
from acmelib.plugins.issuers.digicert import DigicertIssuer  # noqa: E402

# Every path the module calls, as CertCentral's Services API v2 has them
# (github.com/sapcc/go-certcentral, github.com/metorial/metorial
# integrations/digicert/docs/API_RESEARCH.md - dev.digicert.com not reachable here).
CONTRACT = {
    'path_order': ('POST', r'^/order/certificate/[a-z0-9_]+$'),
    'path_reissue': ('POST', r'^/order/certificate/\d+/reissue$'),
    'path_detail': ('GET', r'^/order/certificate/\d+$'),
    'path_random': ('PUT', r'^/order/certificate/\d+/dcv-random-value$'),
    'path_check': ('PUT', r'^/order/certificate/\d+/check-dcv$'),
    'path_domains': ('GET', r'^/domain$'),
    'path_orgs': ('GET', r'^/organization$'),
    'path_products': ('GET', r'^/product$'),
    'path_download': ('GET', r'^/certificate/download/order/\d+/format/pem_all$'),
    'path_revoke': ('PUT', r'^/certificate/\d+/revoke$'),
    'path_me': ('GET', r'^/user/me$'),
}


class Board(DnsChallenge):
    """A DNS validation that writes TXT and CNAME records anywhere (as deSEC does)."""
    kind = 'board'
    fields = []

    def __init__(self):
        class Ctx(object):
            settings = {}

            def step(self, *a, **k):
                pass

            def debug(self, *a):
                pass
        DnsChallenge.__init__(self, {'follow_cname': False, 'propagation': 'none'}, Ctx())
        self.txt, self.cname, self.log = {}, {}, []

    def add_txt(self, fqdn, value):
        self.txt.setdefault(fqdn, []).append(value)
        self.log.append(('txt', fqdn, value))

    def del_txt(self, fqdn, value, handle):
        self.txt.get(fqdn, []).remove(value)

    def add_cname(self, fqdn, target):
        self.cname[fqdn] = target
        self.log.append(('cname', fqdn, target))

    def del_cname(self, fqdn, target, handle):
        self.cname.pop(fqdn, None)


class Files(CannedContext):
    def __init__(self, handler):
        CannedContext.__init__(self, handler)
        self.files = {}

    def http_file_put(self, host, path, content, ttl_s=0):
        self.files[(host, path)] = content

    def http_file_drop(self, host, path):
        self.files.pop((host, path), None)


class TestCertCentral(Base):
    def central(self, **kw):
        state = dict(orders=0, reissues=0, leaf=None, checked=0, issue_after=1, polls=0,
                     validated=[], bodies=[], paths=[], valid_till='2099-01-01',
                     domain_tokens=False)
        state.update(kw)

        def handler(method, url, body, headers, cc):
            self.assertEqual(hdr(headers, 'X-DC-DEVKEY'), 'DEVKEY')
            u = urllib.parse.urlsplit(url)
            self.assertTrue(u.path.startswith('/services/v2/'))
            p = u.path[len('/services/v2'):]
            state['paths'].append((method, p, u.query))
            b = json.loads(body) if body else {}
            m = re.match(r'^/order/certificate/([a-z0-9_]+)$', p)
            if m and method == 'POST':
                state['orders'] += 1
                state['bodies'].append(b)
                c = b['certificate']
                state['leaf'] = self.sign(csr_der_of(c['csr']), [c['common_name']] + c['dns_names'])
                out = {'id': 555, 'certificate_id': 9001}
                if state['domain_tokens']:
                    out['domains'] = [{'id': 1, 'name': n, 'dcv_token': {'token': 'TOK-' + n,
                                                                        'status': 'pending'}}
                                      for n in [c['common_name']] + c['dns_names']]
                else:
                    out['dcv_random_value'] = 'RANDOM1'
                return 201, {}, out
            if re.match(r'^/order/certificate/\d+/reissue$', p) and method == 'POST':
                state['reissues'] += 1
                state['bodies'].append(b)
                state['leaf'] = self.sign(csr_der_of(b['certificate']['csr']),
                                          [b['certificate']['common_name']] +
                                          b['certificate'].get('dns_names', []))
                return 201, {}, {'id': int(p.split('/')[3]), 'dcv_random_value': 'RANDOM3'}
            m = re.match(r'^/order/certificate/(\d+)$', p)
            if m and method == 'GET':
                state['polls'] += 1
                st = 'issued' if state['checked'] >= state['issue_after'] else 'pending'
                if m.group(1) == '111':
                    return 200, {}, {'id': 111, 'status': 'issued',
                                     'order_valid_till': state['valid_till'],
                                     'certificate': {'id': 8000}}
                return 200, {}, {'id': int(m.group(1)), 'status': st,
                                 'order_valid_till': state['valid_till'],
                                 'certificate': {'id': 9001}}
            if re.match(r'^/order/certificate/\d+/dcv-random-value$', p):
                return 200, {}, {'dcv_random_value': 'RANDOM2'}
            if re.match(r'^/order/certificate/\d+/check-dcv$', p):
                state['checked'] += 1
                return 200, {}, {'dcv_status': 'valid', 'order_status': 'pending'}
            if p == '/domain':
                return 200, {}, {'domains': [
                    {'id': 7, 'name': n, 'is_active': True,
                     'validations': [{'type': 'dv', 'status': 'active',
                                      'validated_until': '2099-01-01T00:00:00Z'}],
                     'dcv_expiration': {'ev': '2099-01-01'}} for n in state['validated']]}
            if p == '/organization':
                return 200, {}, {'organizations': [{'id': 42, 'name': 'Firma s.r.o.',
                                                    'status': 'active'}]}
            if p == '/product':
                return 200, {}, {'products': [{'name_id': n, 'name': t}
                                              for n, _b, t, _l, _w in DC.BRANDS]}
            if re.match(r'^/certificate/download/order/\d+/format/pem_all$', p):
                return 200, {}, state['leaf'] + self.ca.pem + self.root.pem
            if re.match(r'^/certificate/\d+/revoke$', p):
                return 201, {}, {'id': 1, 'status': 'pending'}
            if p == '/user/me':
                return 200, {}, {'first_name': 'Ann', 'last_name': 'Admin'}
            return 404, {}, {'errors': [{'message': 'no route ' + p}]}
        return handler, state

    def issuer(self, ctx, **cfg):
        conf = {'api_key': 'DEVKEY', 'poll_every': 1, 'wait_ready': 1, 'wait_issue': 5}
        conf.update(cfg)
        d = DigicertIssuer(conf, ctx)
        d._sleep = lambda s: None
        return d

    def test_brands_and_products(self):
        ids = {n for n, *_r in DC.BRANDS}
        for n in ('ssl_basic', 'ssl_securesite_flex', 'ssl_ev_securesite_flex',
                  'ssl_geotrust_truebizid', 'ssl_dv_geotrust', 'ssl_dv_geotrust_flex',
                  'ssl_thawte_webserver', 'ssl_dv_thawte', 'ssl_dv_rapidssl',
                  'wildcard_dv_rapidssl'):
            self.assertIn(n, ids)
        self.assertEqual({b for _n, b, *_r in DC.BRANDS},
                         {'DigiCert', 'GeoTrust', 'Thawte', 'RapidSSL'})
        opts = dict(next(f for f in DigicertIssuer.fields if f['key'] == 'product')['options'])
        self.assertIn('Thawte SSL123 DV (ssl_dv_thawte)', opts.values())
        # a product with no wildcards refuses one before anything is ordered
        h, state = self.central()
        ctx = CannedContext(h)
        d = self.issuer(ctx, product='ssl_dv_rapidssl', allow_paid=True)
        with self.assertRaises(PluginError) as e:
            d.issue(req_for(['*.firma.cz'], challenges={'*.firma.cz': Board()}))
        self.assertIn('no wildcard', str(e.exception))
        self.assertEqual(state['orders'], 0)

    def test_dv_order_txt_then_pending_kept_across_runs(self):
        h, state = self.central(issue_after=2)
        ctx = CannedContext(h)
        board = Board()
        d = self.issuer(ctx, product='ssl_dv_geotrust_flex', allow_paid=True, wait_issue=0)
        req = req_for(['www.firma.cz', 'firma.cz'], challenges={'www.firma.cz': board,
                                                                'firma.cz': board})
        with self.assertRaises(PluginError) as e:
            d.issue(req)
        self.assertIn('has not issued yet', str(e.exception))
        self.assertEqual(state['orders'], 1)
        self.assertNotIn('organization', state['bodies'][0])            # DV: no organization
        self.assertEqual(state['bodies'][0]['dcv_method'], 'dns-txt-token')
        self.assertEqual(board.txt, {'_dnsauth.www.firma.cz': ['RANDOM1'],
                                     '_dnsauth.firma.cz': ['RANDOM1']})   # kept while it waits
        # the next run: nothing ordered again, the check asked again, then issued
        out = d.issue(req)
        self.check_issued(out, req)
        self.assertEqual(state['orders'], 1)
        self.assertEqual(board.txt, {'_dnsauth.www.firma.cz': [], '_dnsauth.firma.cz': []})

    def test_cname_and_validated_domains(self):
        h, state = self.central(validated=['firma.cz'], domain_tokens=True)
        ctx = CannedContext(h)
        board = Board()
        d = self.issuer(ctx, product='ssl_basic', allow_paid=True, organization_id='42',
                        dcv='dns-cname')
        req = req_for(['www.firma.cz', 'shop.jina.cz'], challenges={'www.firma.cz': board,
                                                                   'shop.jina.cz': board})
        out = d.issue(req)
        self.check_issued(out, req)
        self.assertEqual(state['bodies'][0]['organization'], {'id': 42})
        self.assertEqual(state['bodies'][0]['dcv_method'], 'dns-cname-token')
        # www.firma.cz is under a domain validated in the account: no record for it
        self.assertEqual(board.log, [('cname', '_dnsauth.shop.jina.cz',
                                      'tok-shop.jina.cz.dcv.digicert.com')])
        self.assertEqual(board.cname, {})                                 # taken away again

    def test_http_token_answered_here(self):
        h, state = self.central()
        ctx = Files(h)
        here = HttpLocal({}, ctx)
        d = self.issuer(ctx, order_id='777', dcv='http-file')
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': here})
        seen = []
        orig = ctx.http_file_put

        def put(host, path, content, ttl_s=0):
            seen.append((host, path, content))
            orig(host, path, content, ttl_s)
        ctx.http_file_put = put
        out = d.issue(req)
        self.check_issued(out, req)
        self.assertEqual((state['orders'], state['reissues']), (0, 1))       # free, inside it
        self.assertEqual(state['bodies'][0]['dcv_method'], 'http-token')
        self.assertEqual(seen, [('www.firma.cz', '/.well-known/pki-validation/fileauth.txt',
                                 'RANDOM3')])
        self.assertEqual(ctx.files, {})

    def test_renewal_order_only_when_paid_allowed(self):
        h, state = self.central(valid_till='2020-01-01')
        ctx = CannedContext(h)
        board = Board()
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': board})
        d = self.issuer(ctx, order_id='111')
        with self.assertRaises(PluginError) as e:
            d.issue(req)
        self.assertIn('paid orders are not allowed', str(e.exception))
        self.assertEqual(state['orders'], 0)
        d = self.issuer(ctx, order_id='111', allow_paid=True, organization_id='42')
        d.issue(req)
        self.assertEqual(state['bodies'][-1]['renewal_of_order_id'], 111)

    def test_actions(self):
        h, state = self.central(validated=['firma.cz'])
        d = self.issuer(CannedContext(h))
        self.assertIn('42 = Firma s.r.o.', d.action('organizations'))
        self.assertIn('ssl_dv_thawte', d.action('products'))
        self.assertIn('firma.cz', d.action('domains'))
        self.assertIn('Ann Admin', d.test())

    def test_contract_every_path(self):
        """Each path the module calls is one CertCentral has, with its method."""
        keys = [k for k, _w, _d in DC.PATHS]
        self.assertEqual(sorted(keys), sorted(CONTRACT))
        defaults = {k: d for k, _w, d in DC.PATHS}
        for k, (method, rx) in CONTRACT.items():
            path = defaults[k].split('?')[0].replace('{order}', '123').replace(
                '{product}', 'ssl_basic').replace('{certificate}', '456')
            self.assertRegex(path, rx, k)
        # ... and every call made in the tests above is one of them
        h, state = self.central(validated=['x.cz'], domain_tokens=False)
        ctx = Files(h)
        board = Board()
        d = self.issuer(ctx, allow_paid=True, organization_id='42')
        req = req_for(['www.firma.cz'], challenges={'www.firma.cz': board})
        out = d.issue(req)
        d.revoke(out.cert_pem, 'superseded')
        d.action('organizations')
        d.action('products')
        d.test()
        for method, p, _q in state['paths']:
            self.assertTrue(any(method == m and re.match(rx, p) for m, rx in CONTRACT.values()),
                            '%s %s is not in the contract' % (method, p))

    def test_compat_says_what_fits(self):
        self.assertEqual(DigicertIssuer.proofs_for({'dcv': 'dns-txt'}), ['txt-any'])
        self.assertEqual(DigicertIssuer.proofs_for({'dcv': 'dns-cname'}), ['cname-any'])
        self.assertEqual(DigicertIssuer.proofs_for({'dcv': 'http-file'}), ['http-file-any'])
        self.assertEqual(DigicertIssuer.proofs_for({'dcv': 'email'}), [])
        self.assertEqual(DigicertIssuer.dcv_where({}, 'www.firma.cz', 'txt-any'),
                         '_dnsauth.www.firma.cz')
        self.assertEqual(DigicertIssuer.dcv_where({'txt_label': '@'}, '*.firma.cz', 'txt-any'),
                         'firma.cz')
        self.assertEqual(DigicertIssuer.dcv_where({'dcv_scope': 'base_domain'}, 'a.b.firma.cz',
                                                  'cname-any'), '_dnsauth.firma.cz')
        self.assertTrue(DigicertIssuer.public_for({}))


if __name__ == '__main__':
    unittest.main()
