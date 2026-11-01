# -*- coding: utf-8 -*-
"""
Commercial certificates from DigiCert CertCentral through its Services API
(v2): reissued inside an order paid already, or - only when "Allow new
orders (paid)" is on - ordered anew. The domain validation (DCV) record or
file is put in place by the certificate's own challenge module, as for
SSLmarket (whose placing of records this module uses).

What is known of the API, and from where (dev.digicert.com could not be read
from where this was written; the paths are from DigiCert's pages as search
engines show them, 2026-11, and DigiCert's long-standing Services API):

* https://www.digicert.com/services/v2 (Europe: https://certcentral.digicert.eu/
  services/v2), the API key in the header X-DC-DEVKEY
  (https://dev.digicert.com/en/certcentral-apis/authentication.html).
* POST /order/certificate/{product_name_id} {certificate {common_name,
  dns_names, csr, signature_hash, server_platform}, organization {id},
  order_validity {years}, dcv_method, payment_method} -> {id, requests,
  dcv_random_value, domains [...]}.
* POST /order/certificate/{order_id}/reissue {certificate {...}}.
* GET /order/certificate/{order_id} - the order (status, certificate,
  order_valid_till).
* PUT /order/certificate/{order_id}/dcv-random-value - the order's random
  value (https://dev.digicert.com/en/certcentral-apis/services-api/orders/
  dv-ssl--generate-dcv-token.html); PUT /order/certificate/{order_id}/check-dcv.
* GET /certificate/download/order/{order_id}/format/pem_all - the order's
  certificate with its chain.
* PUT /certificate/{certificate_id}/revoke {reason, comments}.
* GET /user/me for "Try it".

UNCERTAIN: the shape of an order's answer between products, the exact name
of the TXT record (the random value at the domain itself or at _dnsauth.,
both accepted by DigiCert for dns-txt-token: the label is a setting), and the
states of a reissue. Every path is a setting (More). Check a product's
name_id in CertCentral (Settings → Product settings) before the first paid
order.

Money: a NEW order is a purchase. It is only made when "Allow new orders
(paid)" is on; otherwise only reissues inside an order paid already (the
one given, or the one acme made last for the certificate) run.
"""
from __future__ import annotations

import calendar
import json
import re
import time

from acmelib.plugins.base import Issuer, PluginError, field, dual_order_field
from acmelib.plugins.issuers import _source_common as sc
from acmelib.plugins.issuers import sslmarket as _sm

API = {'us': 'https://www.digicert.com/services/v2',
       'eu': 'https://certcentral.digicert.eu/services/v2'}
PRODUCTS = [['ssl_basic', 'Basic OV (ssl_basic)'], ['ssl_securesite_flex', 'Secure Site OV '
                                                                           '(ssl_securesite_flex)'],
            ['ssl_ev_basic', 'Basic EV (ssl_ev_basic)'],
            ['ssl_ev_securesite_flex', 'Secure Site EV (ssl_ev_securesite_flex)'],
            ['ssl_dv_geotrust', 'GeoTrust DV (ssl_dv_geotrust)'],
            ['ssl_dv_rapidssl', 'RapidSSL DV (ssl_dv_rapidssl)'],
            ['wildcard_dv_rapidssl', 'RapidSSL Wildcard DV (wildcard_dv_rapidssl)'],
            ['other', 'Another product (its name_id)']]
DCV = {'dns-txt': 'dns-txt-token', 'dns-cname': 'dns-cname-token', 'http-file': 'http-token',
       'email': 'email'}
ISSUED = ('issued',)
FAILED = ('rejected', 'canceled', 'cancelled', 'revoked', 'denied', 'expired')
REVOKE = {0: 'unspecified', 1: 'key_compromise', 3: 'affiliation_changed', 4: 'superseded',
          5: 'cessation_of_operation'}
PATHS = [
    ('path_order', 'New order', '/order/certificate/{product}'),
    ('path_reissue', 'Reissue', '/order/certificate/{order}/reissue'),
    ('path_detail', 'Order detail', '/order/certificate/{order}'),
    ('path_random', 'DCV random value', '/order/certificate/{order}/dcv-random-value'),
    ('path_check', 'DCV check', '/order/certificate/{order}/check-dcv'),
    ('path_download', 'Download', '/certificate/download/order/{order}/format/pem_all'),
    ('path_revoke', 'Revocation', '/certificate/{certificate}/revoke'),
]


class DigicertIssuer(Issuer):
    kind = 'digicert'
    dual_field = 'dual_order'       # a twin is a second order, paid for: only when allowed
    title = 'DigiCert CertCentral (API)'
    description = ('Commercial DigiCert, GeoTrust and RapidSSL certificates through the '
                   'CertCentral Services API: reissued inside a paid order, the DCV record put '
                   'in place by the certificate\'s challenge. New (paid) orders only when allowed.')
    vendor = 'DigiCert'
    doc = 'docs/sources.md'
    needs_challenge = True
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    fields = [
        field('region', 'CertCentral', 'select', default='us',
              options=[['us', 'CertCentral (www.digicert.com)'], ['eu', 'CertCentral Europe'],
                       ['custom', 'Another address']]),
        field('api_url', 'API address', 'text', show_if={'region': ['custom']},
              placeholder='https://www.digicert.com/services/v2'),
        field('api_key', 'API key', 'secret', required=True,
              help='CertCentral → Automation → API Keys: a key of a user who may order and '
                   'reissue. Sent as X-DC-DEVKEY.'),
        field('order_id', 'Order to reuse', 'text', placeholder='12345678',
              help='An order bought already (a multi-year plan): the certificate is reissued '
                   'inside it. Empty: the order acme made last for the certificate.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders paid already, '
                   'and stops with words where a purchase would be needed.'),
        field('product', 'Product of a new order', 'select', default='ssl_basic', options=PRODUCTS),
        field('product_code', 'Product name_id', 'text', show_if={'product': ['other']}),
        field('organization_id', 'Organization ID', 'text',
              help='The organization of a new OV/EV order (CertCentral → Organizations).'),
        field('years', 'Order validity (years)', 'select', default='1',
              options=[['1', '1 year'], ['2', '2 years'], ['3', '3 years']]),
        field('payment', 'Payment of a new order', 'select', default='balance',
              options=[['balance', 'Account balance'], ['profile', 'Credit card on file'],
                       ['card', 'As the account sets it']], advanced=True),
        field('dcv', 'Domain validation (DCV)', 'select', default='dns-txt',
              options=[['dns-txt', 'DNS TXT record (by the certificate\'s DNS challenge)'],
                       ['dns-cname', 'DNS CNAME record'],
                       ['http-file', 'HTTP file in /.well-known/pki-validation/'],
                       ['email', 'E-mail (a person clicks)']]),
        field('txt_label', 'Label of the DNS TXT record', 'text', default='_dnsauth', advanced=True,
              help='LABEL.domain holds the random value (@ for the domain itself).'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600, advanced=True),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=15, advanced=True),
    ] + [field(k, 'Path: ' + words, 'text', default=d, advanced=True,
               help='Under the API address; {order}, {product} and {certificate} are filled in.')
         for k, words, d in PATHS]
    fields = fields + [dual_order_field()]

    # The DCV records are put in place as SSLmarket's module does it.
    _challenge_for = _sm.SslmarketIssuer._challenge_for
    _place_all = _sm.SslmarketIssuer._place_all
    _place = _sm.SslmarketIssuer._place
    _wait_visible = _sm.SslmarketIssuer._wait_visible
    _cleanup = _sm.SslmarketIssuer._cleanup

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep

    @classmethod
    def describe(cls):
        d = Issuer.describe.__func__(cls)
        d.update(needs_challenge=True, challenge_types=list(cls.challenge_types))
        return d

    def _say(self, words, level='info'):
        sc.say(self.ctx, words, level)

    def _base(self):
        r = self.c('region') or 'us'
        url = str(self.c('api_url') or '').strip().rstrip('/') if r == 'custom' else API.get(r)
        if not url or not re.match(r'^https://[^\s/]+\S*\Z', url):
            raise PluginError('set the CertCentral API address', retry=False)
        return url

    def _path(self, key, **fill):
        p = str(self.c(key) or '')
        for k, v in fill.items():
            v = str(v)
            if not re.match(r'^[A-Za-z0-9_-]+\Z', v):
                raise PluginError('an order or product id of letters and digits only', retry=False)
            p = p.replace('{%s}' % k, v)
        if '{' in p or not p.startswith('/'):
            raise PluginError('the path %s is not complete: %s' % (key, p), retry=False)
        return p

    def call(self, method, key, body=None, what='', raw=False, **fill):
        if not self.c('api_key'):
            raise PluginError('set the CertCentral API key', retry=False)
        status, _h, data = sc.http(self.ctx, method, self._base() + self._path(key, **fill), body,
                                   {'X-DC-DEVKEY': str(self.c('api_key')).strip(),
                                    'Accept': '*/*' if raw else 'application/json'},
                                   who='DigiCert')
        parsed = None if raw else sc.parse_json(data)
        if status not in (200, 201, 204):
            raise sc.refusal('DigiCert (%s)' % (what or key), status, sc.parse_json(data), data,
                             'the API key is wrong or its user may not do this')
        return data if raw else (parsed or {})

    def product(self):
        p = self.c('product') or 'ssl_basic'
        if p == 'other':
            p = str(self.c('product_code') or '').strip()
        if not re.match(r'^[a-z0-9_]+\Z', p or ''):
            raise PluginError('set the product (its name_id)', retry=False)
        return p

    def cert_body(self, req):
        names = list(req.names or [])
        return {'common_name': names[0], 'dns_names': names[1:], 'csr': sc.csr_pem(req),
                'signature_hash': 'sha256', 'server_platform': {'id': -1}}

    @staticmethod
    def _until(order):
        v = (order or {}).get('order_valid_till') or (order or {}).get('valid_till')
        try:
            return calendar.timegm(time.strptime(str(v)[:10], '%Y-%m-%d'))
        except (TypeError, ValueError):
            return None

    def _order_to_use(self, req, sub_key):
        """(how, order_id): 'reissue' inside an order, or 'new' (paid)."""
        oid = str(self.c('order_id') or '').strip()
        if not oid:
            kept = sc.parse_json(self.ctx.kv_get(sub_key) or '') or {}
            oid = str(kept.get('order_id') or '')
        allowed = sc.as_bool(self.c('allow_paid'))
        if oid:
            det = self.call('GET', 'path_detail', what='the order %s' % oid, order=oid)
            st = str(det.get('status') or '').lower()
            end = self._until(det)
            if st not in FAILED and (end is None or end > time.time() + 7 * 86400):
                return 'reissue', oid
            why = 'the order %s is %s%s' % (oid, st or '?', (', its validity ends %s' % time.strftime(
                '%Y-%m-%d', time.gmtime(end))) if end else '')
        else:
            why = 'there is no order to reissue in (set "Order to reuse")'
        if not allowed:
            raise PluginError('nothing ordered: %s, and paid orders are not allowed for this '
                              'source - set "Order to reuse" to an order you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        self._say('%s - a new order is made (paid: allowed for this source)' % why, 'warn')
        return 'new', None

    def issue(self, req):
        ck = str(req.cert_id or '') or sc.pending_slot('x', '', req).split(':')[-1]
        slot = sc.pending_slot('digicert', self._base(), req)
        sub_key = 'digicert-order:%s' % ck
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        if held:
            oid = str(held['id'])
            self._say('the order %s (%s) waits at DigiCert since %s - asked for again, nothing is '
                      'ordered' % (oid, held.get('how'), time.strftime(
                          '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
        else:
            how, oid = self._order_to_use(req, sub_key)
            dcv = DCV.get(self.c('dcv') or 'dns-txt', 'dns-txt-token')
            if how == 'reissue':
                got = self.call('POST', 'path_reissue', {'certificate': self.cert_body(req),
                                                         'dcv_method': dcv},
                                what='the reissue', order=oid)
                self._say('reissue inside order %s asked for (free)' % oid, 'ok')
            else:
                body = {'certificate': self.cert_body(req), 'dcv_method': dcv,
                        'order_validity': {'years': int(self.c('years') or 1)},
                        'payment_method': self.c('payment') or 'balance'}
                if self.c('organization_id'):
                    body['organization'] = {'id': int(str(self.c('organization_id')).strip())}
                got = self.call('POST', 'path_order', body, what='the order', product=self.product())
                oid = str(got.get('id') or '')
                if not re.match(r'^\d+\Z', oid):
                    raise PluginError('DigiCert took the order but said no order number - look in '
                                      'CertCentral before trying again (a second order would be '
                                      'paid again)', retry=False)
                self._say('order %s made at DigiCert: %s for %s' % (oid, self.product(),
                                                                     ', '.join(req.names)), 'ok')
                self.ctx.kv_set(sub_key, json.dumps({'order_id': oid, 'at': time.time()}),
                                ttl_s=5 * 366 * 86400)
            held = sc.pending_put(self.ctx, slot, req, {'id': oid, 'how': how, 'dcv': [],
                                                        'csr_pem': sc.csr_pem(req)}, ttl_days=120)
            r = req
            self._dcv(req, slot, held, oid, got)
        return self._await(r, slot, held, oid, req)

    def _random_value(self, oid, answer):
        v = (answer or {}).get('dcv_random_value')
        if not v:
            try:
                v = self.call('PUT', 'path_random', {}, what='the DCV random value',
                              order=oid).get('dcv_random_value')
            except PluginError as e:
                self._say('the order\'s DCV random value could not be had: %s' % e, 'warn')
        return v

    def _dcv(self, req, slot, held, oid, answer):
        how = self.c('dcv') or 'dns-txt'
        if how == 'email':
            self._say('DigiCert sends its DCV e-mails - someone at the domain approves them')
            return
        value = self._random_value(oid, answer)
        if not value:
            self._say('DigiCert said no DCV random value (the domains are validated already?)')
            return
        label = str(self.c('txt_label') or '').strip().strip('.')
        recs = []
        for d in sorted({_sm._base(n) for n in req.names or []}):
            if how == 'http-file':
                recs.append({'domain': d, 'type': 'file', 'value': value,
                             'path': '/.well-known/pki-validation/fileauth.txt'})
            else:
                fqdn = d if label in ('', '@') else '%s.%s' % (label, d)
                recs.append({'domain': d, 'type': 'cname' if how == 'dns-cname' else 'txt',
                             'fqdn': fqdn, 'value': value if how != 'dns-cname' else
                             '%s.dcv.digicert.com' % value})
        held['dcv'] = self._place_all(req, recs)
        sc.pending_put(self.ctx, slot, req, held, ttl_days=120)
        if held['dcv']:
            self._wait_visible(req, held['dcv'])
            try:
                self.call('PUT', 'path_check', {}, what='the DCV check', order=oid)
            except PluginError as e:
                self._say('the DCV check could not be asked for: %s' % e, 'warn')

    def _await(self, r, slot, held, oid, req):
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 15))
        while True:
            det = self.call('GET', 'path_detail', what='the order %s' % oid, order=oid)
            st = str(det.get('status') or '').lower()
            if st in ISSUED:
                data = self.call('GET', 'path_download', what='the download', raw=True, order=oid)
                certs = sc.certs_of(data)
                try:
                    out = sc.finish(self.ctx, r, certs, who='DigiCert',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'order_id': oid,
                                          'certificate_id': (det.get('certificate') or {}).get('id')})
                except PluginError:
                    out = None              # the order's old certificate still: the reissue waits
                if out:
                    self._cleanup(req, held.get('dcv') or [])
                    sc.pending_drop(self.ctx, slot)
                    cid = (det.get('certificate') or {}).get('id')
                    if cid:
                        self.ctx.kv_set('digicert-cert:%s' % sc.fingerprint(out.cert_pem)[:40],
                                        str(cid), ttl_s=5 * 366 * 86400)
                    return out
            elif st in FAILED:
                self._cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('DigiCert did not issue: the order %s is %s' % (oid, st),
                                  retry=False)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('DigiCert has not issued yet (order %s: %s) - the DCV records '
                                  'stay in place; acme asks again at the next try' % (oid, st or '?'))
            self._sleep(every)

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        cid = self.ctx.kv_get('digicert-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if not cid:
            raise PluginError('acme does not know the certificate\'s id at DigiCert - revoke it in '
                              'CertCentral', retry=False)
        self.call('PUT', 'path_revoke', {'reason': REVOKE.get(sc.reason_code(reason), 'unspecified'),
                                         'comments': 'revoked by acme'},
                  what='the revocation', certificate=cid)
        return 'DigiCert took the revocation of certificate %s (an administrator may have to '\
               'approve it)' % cid

    def test(self):
        me = self.call('GET', 'path_detail', what='the order', order=self.c('order_id')) \
            if self.c('order_id') else None
        status, _h, data = sc.http(self.ctx, 'GET', self._base() + '/user/me', None,
                                   {'X-DC-DEVKEY': str(self.c('api_key') or '').strip()},
                                   who='DigiCert')
        who = sc.parse_json(data) or {}
        if status != 200:
            raise sc.refusal('DigiCert', status, who, data, 'the API key is wrong')
        words = 'DigiCert answers: the API key is %s %s\'s' % (who.get('first_name') or '',
                                                               who.get('last_name') or '?')
        if me is not None:
            words += '; order %s is %s' % (self.c('order_id'), me.get('status') or '?')
        words += '; new paid orders %s' % ('ALLOWED' if sc.as_bool(self.c('allow_paid'))
                                           else 'not allowed')
        return words
