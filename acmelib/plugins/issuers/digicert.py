# -*- coding: utf-8 -*-
"""
Commercial certificates of the DigiCert family - DigiCert, GeoTrust, Thawte,
RapidSSL (DigiCert's brands, all ordered through CertCentral) - by the
CertCentral Services API (v2): reissued inside an order paid already (free), or
- only when "Allow new orders (paid)" is on - ordered anew (a renewal order of
the one that ends). The domain validation (DCV) record or file is put in place
by the certificate's own validation, through the placement API every
validation module keeps (base.Challenge.place; acmelib/plugins/issuers/_dcv.py);
acmelib/certs/compat.py refuses a validation that cannot put it in place
before anything is ordered. Domains validated in the account already (their
DCV still valid) are not validated again.

When the ACME preset "DigiCert (EAB)" of the ACME source is the better choice:
DV (and OV/EV of an organization validated already) fully automatic, the CA's
own ACME - no orders, no random values. This module is for what ACME cannot:
an OV/EV order of a chosen organization, multi-year plans reissued inside,
the brands' products by name, DCV by e-mail.

What is known of the API, and from where (dev.digicert.com cannot be read from
where this was written, 2026-11; cross-checked against code that speaks it -
github.com/sapcc/go-certcentral (paths, base URL), github.com/lexiconn-internet-
services/digicert src/lang/en/certs.php (the product name_ids),
github.com/metorial/metorial integrations/digicert/docs/API_RESEARCH.md (bodies,
answers, DCV endpoints), github.com/grindsa/acme2certifier docs/digicert.md):

* https://www.digicert.com/services/v2 (Europe: https://certcentral.digicert.eu/
  services/v2), the API key in the header X-DC-DEVKEY.
* POST /order/certificate/{name_id} {certificate {common_name, dns_names, csr,
  signature_hash, server_platform}, organization {id} (OV/EV), order_validity
  {years}, dcv_method, payment_method, renewal_of_order_id} -> {id,
  certificate_id, requests, dcv_random_value (DV), domains [{id, name,
  dcv_token {token, status}}] (OV/EV)}.
* POST /order/certificate/{order_id}/reissue {certificate {...}, dcv_method}
  -> {id, requests, dcv_random_value}.
* GET /order/certificate/{order_id} - status (pending, issued, rejected,
  revoked...), certificate {id, valid_till}, order_valid_till.
* PUT /order/certificate/{order_id}/check-dcv - DigiCert looks at the DCV
  record now (dns-txt-token, dns-cname-token, http-token).
* GET /domain?include_validation=true - the account's domains, their
  validations and dcv_expiration (pre-validated domains need no DCV).
* GET /organization - the organizations (OV/EV); GET /product - the products.
* GET /certificate/{certificate_id}/download/format/pem_all - the certificate with
  root and intermediate ("Download certificate by format", the order's certificate.id;
  checked in 1.0.27 against https://dev.digicert.com/certcentral-apis/services-api/
  certificates/download-certificate-by-format.html); where the certificate's id is not
  known, GET /certificate/download/order/{order_id}/format/pem_all.
* PUT /certificate/{certificate_id}/revoke {reason, comments}; GET /user/me.
* GET /order/certificate?offset=&limit= - every order of the account ("List orders",
  https://dev.digicert.com/en/certcentral-apis/services-api/orders/list-orders.html):
  {orders [{id, certificate {common_name, dns_names, valid_till...}, status,
  product {name_id, name}...}], page {total, limit, offset}} - limit at most 1000
  (5000 in newer versions of the page): Import from a source, page by page.

UNCERTAIN (every path is a setting, More): the exact shape of the DCV records
(the TXT at the domain itself or at _dnsauth. - both are accepted by DigiCert,
the label is a setting; the CNAME as _dnsauth.DOMAIN -> RANDOM.dcv.digicert.com
or RANDOM.DOMAIN -> dcv.digicert.com - a setting), whether GET /domain takes a
search filter (all are read, at most 1000), and the states of a reissue. Check
a product's name_id in CertCentral (Settings → Product settings, or the action
"List the products") before the first paid order.

Money: a NEW order is a purchase. It is only made when "Allow new orders
(paid)" is on; otherwise only reissues inside an order paid already (the
one given, or the one acme made last for the certificate) run.
"""
from __future__ import annotations

import calendar
import json
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Plugin, PluginError, field, dual_order_field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

API = {'us': 'https://www.digicert.com/services/v2',
       'eu': 'https://certcentral.digicert.eu/services/v2'}
# (name_id, brand, product, validation level, wildcard: 'no' | 'also' | 'only')
BRANDS = [
    ('ssl_basic', 'DigiCert', 'Basic OV', 'ov', 'also'),
    ('ssl_ev_basic', 'DigiCert', 'Basic EV', 'ev', 'no'),
    ('ssl_securesite_flex', 'DigiCert', 'Secure Site OV', 'ov', 'also'),
    ('ssl_ev_securesite_flex', 'DigiCert', 'Secure Site EV', 'ev', 'no'),
    ('ssl_securesite_pro', 'DigiCert', 'Secure Site Pro OV', 'ov', 'also'),
    ('ssl_ev_securesite_pro', 'DigiCert', 'Secure Site Pro EV', 'ev', 'no'),
    ('ssl_geotrust_truebizid', 'GeoTrust', 'TrueBusiness ID OV', 'ov', 'also'),
    ('ssl_ev_geotrust_truebizid', 'GeoTrust', 'TrueBusiness ID EV', 'ev', 'no'),
    ('ssl_dv_geotrust', 'GeoTrust', 'Standard DV', 'dv', 'no'),
    ('ssl_dv_geotrust_flex', 'GeoTrust', 'QuickSSL Premium DV', 'dv', 'also'),
    ('wildcard_dv_geotrust', 'GeoTrust', 'Wildcard DV', 'dv', 'only'),
    ('cloud_dv_geotrust', 'GeoTrust', 'Cloud DV', 'dv', 'also'),
    ('ssl_thawte_webserver', 'Thawte', 'SSL Webserver OV', 'ov', 'also'),
    ('ssl_ev_thawte_webserver', 'Thawte', 'SSL Webserver EV', 'ev', 'no'),
    ('ssl_dv_thawte', 'Thawte', 'SSL123 DV', 'dv', 'also'),
    ('ssl_dv_rapidssl', 'RapidSSL', 'Standard DV', 'dv', 'no'),
    ('wildcard_dv_rapidssl', 'RapidSSL', 'Wildcard DV', 'dv', 'only'),
    ('ssl_dv_ee', 'DigiCert', 'Encryption Everywhere DV', 'dv', 'also'),
]
PRODUCTS = [[n, '%s %s (%s)' % (b, t, n)] for n, b, t, _lv, _w in BRANDS] + \
    [['other', 'Another product (its name_id)']]
DCV = {'dns-txt': 'dns-txt-token', 'dns-cname': 'dns-cname-token', 'http-file': 'http-token',
       'email': 'email'}
FILE_PATH = '/.well-known/pki-validation/fileauth.txt'
ISSUED = ('issued',)
FAILED = ('rejected', 'canceled', 'cancelled', 'revoked', 'denied', 'expired')
REVOKE = {0: 'unspecified', 1: 'key_compromise', 3: 'affiliation_changed', 4: 'superseded',
          5: 'cessation_of_operation'}
PATHS = [
    ('path_order', 'New order', '/order/certificate/{product}'),
    ('path_reissue', 'Reissue', '/order/certificate/{order}/reissue'),
    ('path_detail', 'Order detail', '/order/certificate/{order}'),
    ('path_orders', 'List of orders', '/order/certificate'),
    ('path_random', 'DCV random value', '/order/certificate/{order}/dcv-random-value'),
    ('path_check', 'DCV check', '/order/certificate/{order}/check-dcv'),
    ('path_domains', 'Domains of the account', '/domain?include_validation=true&limit=1000'),
    ('path_orgs', 'Organizations', '/organization'),
    ('path_products', 'Products', '/product'),
    ('path_download', 'Download', '/certificate/download/order/{order}/format/pem_all'),
    ('path_download_cert', 'Download by certificate ID',
     '/certificate/{certificate}/download/format/pem_all'),
    ('path_revoke', 'Revocation', '/certificate/{certificate}/revoke'),
    ('path_me', 'Who the key is', '/user/me'),
]


def product_info(name_id):
    for n, b, t, lv, w in BRANDS:
        if n == name_id:
            return {'name_id': n, 'brand': b, 'title': t, 'level': lv, 'wildcard': w}
    return None


class DigicertIssuer(Issuer):
    kind = 'digicert'
    dual_field = 'dual_order'       # a twin is a second order, paid for: only when allowed
    title = 'DigiCert CertCentral (API)'
    description = ('Commercial DigiCert, GeoTrust, Thawte and RapidSSL certificates through the '
                   'CertCentral Services API: reissued inside a paid order, the DCV record put '
                   'in place by the certificate\'s validation. New (paid) orders only when allowed.')
    vendor = 'DigiCert'
    doc = 'docs/sources.md'
    needs_challenge = True
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    lists_existing = True           # List orders + download: Certificates → Import from a source
    public_names = True
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    # The domain validation: which proof each method needs of the certificate's validation.
    dcv_field = 'dcv'
    dcv_default = 'dns-txt'
    dcv = {
        'dns-txt': {'proof': 'txt-any', 'words': 'DNS TXT record (dns-txt-token)',
                    'record': 'TXT at _dnsauth.DOMAIN (or DOMAIN itself) holding the random '
                              'value'},
        'dns-cname': {'proof': 'cname-any', 'words': 'DNS CNAME record (dns-cname-token)',
                      'record': 'CNAME _dnsauth.DOMAIN to RANDOM.dcv.digicert.com'},
        'http-file': {'proof': 'http-file-any', 'words': 'HTTP file (http-token)',
                      'record': 'http://DOMAIN' + FILE_PATH + ' holding the random value'},
        'email': {'proof': None, 'words': 'E-mail (a person approves)',
                  'record': 'an e-mail to admin@, administrator@, webmaster@, hostmaster@, '
                            'postmaster@ the domain'},
    }
    actions = [{'key': 'organizations', 'label': 'List the organizations',
                'help': 'The organizations of the account (for an OV/EV order) with their '
                        'IDs and validation.'},
               {'key': 'products', 'label': 'List the products',
                'help': 'The products the account may order, with their name_id.'},
               {'key': 'domains', 'label': 'List the validated domains',
                'help': 'The domains of the account and until when their DCV holds - those '
                        'need no DCV record.'}]
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
                   'inside it, free. Empty: the order acme made last for the certificate.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders paid already, '
                   'and stops with words where a purchase would be needed (a new certificate, '
                   'or a renewal order when the order ends).'),
        field('product', 'Product of a new order', 'select', default='ssl_basic', options=PRODUCTS,
              help='DigiCert, GeoTrust, Thawte and RapidSSL are all DigiCert\'s and ordered here. '
                   'DV: the domain only; OV/EV: an organization validated in CertCentral.'),
        field('product_code', 'Product name_id', 'text', show_if={'product': ['other']}),
        field('organization_id', 'Organization ID', 'text',
              help='The organization of an OV/EV order (the action "List the organizations" '
                   'shows them). Not used for DV.'),
        field('years', 'Order validity (years)', 'select', default='1',
              options=[['1', '1 year'], ['2', '2 years'], ['3', '3 years']],
              help='A multi-year plan: one order, the certificate reissued inside it (free) as '
                   'each one ends.'),
        field('payment', 'Payment of a new order', 'select', default='balance',
              options=[['balance', 'Account balance'], ['profile', 'Credit card on file'],
                       ['card', 'As the account sets it']], advanced=True),
        field('dcv', 'Domain validation (DCV)', 'select', default='dns-txt',
              options=[['dns-txt', 'DNS TXT record (by the certificate\'s DNS validation)'],
                       ['dns-cname', 'DNS CNAME record (a DNS validation that writes CNAMEs)'],
                       ['http-file', 'HTTP file in /.well-known/pki-validation/ (an HTTP '
                                     'validation; no wildcards)'],
                       ['email', 'E-mail (a person clicks; no validation needed)']],
              help='How DigiCert checks the domains. The certificate\'s validation must be able to '
                   'put that record or file in place - the wizard offers only those that can.'),
        field('txt_label', 'Label of the DNS TXT record', 'text', default='_dnsauth', advanced=True,
              help='LABEL.domain holds the random value (@ for the domain itself).'),
        field('cname_shape', 'Shape of the DNS CNAME record', 'select', default='dnsauth',
              advanced=True,
              options=[['dnsauth', '_dnsauth.DOMAIN → RANDOM.dcv.digicert.com'],
                       ['random', 'RANDOM.DOMAIN → dcv.digicert.com']]),
        field('dcv_scope', 'DCV for', 'select', default='fqdn', advanced=True,
              options=[['fqdn', 'each name (www.example.com)'],
                       ['base_domain', 'the registered domain (example.com) - covers its '
                                       'names']]),
        field('reuse_validated', 'Skip domains validated already', 'bool', default=True,
              advanced=True,
              help='A domain whose DCV in the account is still valid gets no DCV record.'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600, advanced=True),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=15, advanced=True),
    ] + [field(k, 'Path: ' + words, 'text', default=d, advanced=True,
               help='Under the API address; {order}, {product} and {certificate} are filled in.')
         for k, words, d in PATHS]
    fields = fields + [dual_order_field()]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep

    # -- what fits (acmelib/certs/compat.py) ------------------------------------------------
    @classmethod
    def dcv_where(cls, config, name, proof):
        cfg = config or {}
        d = _dcv.base_of(name)
        if str(cfg.get('dcv_scope') or 'fqdn') == 'base_domain':
            from acmelib.plugins.challenges import _dns as D
            d = D.registrable(d)
        if proof == 'http-file-any':
            return FILE_PATH
        if proof == 'cname-any':
            return d if str(cfg.get('cname_shape') or 'dnsauth') == 'random' else '_dnsauth.' + d
        label = str(cfg.get('txt_label') if cfg.get('txt_label') is not None else
                    '_dnsauth').strip().strip('.')
        return d if label in ('', '@') else '%s.%s' % (label, d)

    @classmethod
    def describe(cls):
        d = Issuer.describe.__func__(cls)
        d.update(needs_challenge=True, challenge_types=list(cls.challenge_types),
                 brands=[{'name_id': n, 'brand': b, 'title': t, 'level': lv, 'wildcard': w}
                         for n, b, t, lv, w in BRANDS])
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

    def call(self, method, key, body=None, what='', raw=False, ok=(200, 201, 204), query=None,
             **fill):
        if not self.c('api_key'):
            raise PluginError('set the CertCentral API key', retry=False)
        url = self._base() + self._path(key, **fill)
        if query:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(query)
        status, _h, data = sc.http(self.ctx, method, url, body,
                                   {'X-DC-DEVKEY': str(self.c('api_key')).strip(),
                                    'Accept': '*/*' if raw else 'application/json'},
                                   who='DigiCert')
        parsed = None if raw else sc.parse_json(data)
        if status not in ok:
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

    def _check_product(self, req, new=False):
        info = product_info(self.product())
        if not info:
            return
        wild = [n for n in req.names or [] if n.startswith('*.')]
        if wild and info['wildcard'] == 'no':
            raise PluginError('%s %s gives no wildcard certificates (%s) - choose a product that '
                              'does' % (info['brand'], info['title'], ', '.join(wild)), retry=False)
        if info['wildcard'] == 'only' and not wild:
            raise PluginError('%s %s is a wildcard product - give the certificate a wildcard name'
                              % (info['brand'], info['title']), retry=False)
        if new and info['level'] in ('ov', 'ev') and not str(self.c('organization_id') or '').strip():
            raise PluginError('%s %s is %s: set the organization ID (the action "List the '
                              'organizations")' % (info['brand'], info['title'],
                                                   info['level'].upper()), retry=False)

    def cert_body(self, req):
        names = list(req.names or [])
        cn = names[0]
        subj = getattr(req, 'subject', None) or {}
        if subj.get('CN') and subj['CN'] in names:
            cn = subj['CN']
        return {'common_name': cn, 'dns_names': [n for n in names if n != cn],
                'csr': sc.csr_pem(req), 'signature_hash': 'sha256',
                'server_platform': {'id': -1}}

    @staticmethod
    def _until(order):
        v = (order or {}).get('order_valid_till') or (order or {}).get('valid_till')
        try:
            return calendar.timegm(time.strptime(str(v)[:10], '%Y-%m-%d'))
        except (TypeError, ValueError):
            return None

    def _order_to_use(self, req, sub_key):
        """(how, order_id, renewal_of): 'reissue' inside an order, or 'new' (paid) -
        a renewal order of the one that ends where there is one."""
        # A certificate imported from this account (Import from a source) names its own
        # order: that one is reissued, whatever "Order to reuse" says.
        oid = str(getattr(req, 'ref', None) or '').strip() or str(self.c('order_id') or '').strip()
        if not oid:
            kept = sc.parse_json(self.ctx.kv_get(sub_key) or '') or {}
            oid = str(kept.get('order_id') or '')
        allowed = sc.as_bool(self.c('allow_paid'))
        renewal = None
        if oid:
            det = self.call('GET', 'path_detail', what='the order %s' % oid, order=oid)
            st = str(det.get('status') or '').lower()
            end = self._until(det)
            if st not in FAILED and (end is None or end > time.time() + 7 * 86400):
                return 'reissue', oid, None
            why = 'the order %s is %s%s' % (oid, st or '?', (', its validity ends %s' % time.strftime(
                '%Y-%m-%d', time.gmtime(end))) if end else '')
            if st not in ('rejected', 'canceled', 'cancelled'):
                renewal = oid
        else:
            why = 'there is no order to reissue in (set "Order to reuse")'
        if not allowed:
            raise PluginError('nothing ordered: %s, and paid orders are not allowed for this '
                              'source - set "Order to reuse" to an order you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        self._say('%s - a new %sorder is made (paid: allowed for this source)'
                  % (why, 'renewal ' if renewal else ''), 'warn')
        return 'new', None, renewal

    def issue(self, req):
        ck = str(req.cert_id or '') or sc.pending_slot('x', '', req).split(':')[-1]
        slot = sc.pending_slot('digicert', self._base(), req)
        sub_key = 'digicert-order:%s' % ck
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        if held:
            oid = str(held['id'])
            self._say('the order %s (%s) waits at DigiCert since %s - asked for again, nothing is '
                      'ordered' % (oid, held.get('how'), time.strftime(
                          '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
            if held.get('dcv'):
                placer.refresh(req, held['dcv'])
                self._ask_check(oid)
        else:
            self._check_product(req)
            how, oid, renewal = self._order_to_use(req, sub_key)
            dcv = DCV.get(self.c('dcv') or 'dns-txt', 'dns-txt-token')
            scope = self.c('dcv_scope') or 'fqdn'
            if how == 'reissue':
                got = self.call('POST', 'path_reissue', {'certificate': self.cert_body(req),
                                                         'dcv_method': dcv,
                                                         'certificate_dcv_scope': scope},
                                what='the reissue', order=oid)
                self._say('reissue inside order %s asked for (free)' % oid, 'ok')
            else:
                self._check_product(req, new=True)
                body = {'certificate': self.cert_body(req), 'dcv_method': dcv,
                        'certificate_dcv_scope': scope,
                        'order_validity': {'years': int(self.c('years') or 1)},
                        'payment_method': self.c('payment') or 'balance'}
                if renewal:
                    body['renewal_of_order_id'] = int(renewal)
                info = product_info(self.product())
                if self.c('organization_id') and (info is None or info['level'] != 'dv'):
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
            self._dcv(req, slot, held, oid, got, placer)
        return self._await(r, slot, held, oid, req, placer)

    # -- the domain validation -----------------------------------------------------------------
    def _random_value(self, oid, answer):
        v = (answer or {}).get('dcv_random_value')
        if not v:
            try:
                v = self.call('PUT', 'path_random', {}, what='the DCV random value',
                              order=oid).get('dcv_random_value')
            except PluginError as e:
                self._say('the order\'s DCV random value could not be had: %s' % e, 'warn')
        return v

    def validated_domains(self):
        """{domain: until (epoch)} of the account's domains whose DCV still holds."""
        try:
            got = self.call('GET', 'path_domains', what='the domains', ok=(200,))
        except PluginError as e:
            self._say('the account\'s validated domains could not be read (%s) - every domain '
                      'gets its DCV record' % e, 'info')
            return {}
        out = {}
        for d in got.get('domains') or []:
            if not d.get('is_active', True):
                continue
            ends = []
            exp = d.get('dcv_expiration') or {}
            for v in (exp.values() if isinstance(exp, dict) else [exp]):
                try:
                    ends.append(calendar.timegm(time.strptime(str(v)[:10], '%Y-%m-%d')))
                except (TypeError, ValueError):
                    pass
            for val in d.get('validations') or []:
                if str(val.get('status') or '').lower() in ('active', 'approved', 'valid') and \
                        val.get('dcv_status', 'complete') not in ('pending',):
                    try:
                        ends.append(calendar.timegm(time.strptime(
                            str(val.get('validated_until') or '')[:10], '%Y-%m-%d')))
                    except (TypeError, ValueError):
                        pass
            if ends and max(ends) > time.time() + 86400:
                out[str(d.get('name') or '').lower()] = max(ends)
        return out

    def dcv_records(self, req, value, tokens=None):
        """The records DigiCert looks for, one per domain to validate."""
        how = self.c('dcv') or 'dns-txt'
        recs = []
        for n in req.names or []:
            d = _dcv.base_of(n)
            if (self.c('dcv_scope') or 'fqdn') == 'base_domain':
                from acmelib.plugins.challenges import _dns as D
                d = D.registrable(d)
            if any(x['domain'] == d for x in recs):
                continue
            v = (tokens or {}).get(d) or value
            if not v:
                continue
            if how == 'http-file':
                recs.append({'domain': d, 'type': 'file', 'value': v, 'path': FILE_PATH})
            elif how == 'dns-cname':
                if (self.c('cname_shape') or 'dnsauth') == 'random':
                    recs.append({'domain': d, 'type': 'cname', 'fqdn': '%s.%s' % (v, d),
                                 'value': 'dcv.digicert.com'})
                else:
                    recs.append({'domain': d, 'type': 'cname', 'fqdn': '_dnsauth.' + d,
                                 'value': '%s.dcv.digicert.com' % v})
            else:
                recs.append({'domain': d, 'type': 'txt',
                             'fqdn': self.dcv_where(self.config, d, 'txt-any'), 'value': v})
        return recs

    def _ask_check(self, oid):
        try:
            got = self.call('PUT', 'path_check', {}, what='the DCV check', order=oid)
            st = got.get('dcv_status') or got.get('order_status')
            if st:
                self._say('DigiCert looked at the DCV: %s' % st)
        except PluginError as e:
            self._say('the DCV check could not be asked for: %s' % e, 'warn')

    def _dcv(self, req, slot, held, oid, answer, placer):
        how = self.c('dcv') or 'dns-txt'
        if how == 'email':
            self._say('DigiCert sends its DCV e-mails - someone at the domain approves them')
            return
        tokens = {}
        for d in (answer or {}).get('domains') or []:
            tok = (d.get('dcv_token') or {}).get('token')
            if tok and d.get('name') and str((d.get('dcv_token') or {}).get('status') or
                                             'pending') != 'active':
                tokens[str(d['name']).lower()] = tok
        value = None if tokens and len(tokens) >= len({_dcv.base_of(n) for n in req.names}) \
            else self._random_value(oid, answer)
        recs = self.dcv_records(req, value, tokens)
        if not recs:
            self._say('DigiCert said no DCV random value (the domains are validated already?)')
            return
        if sc.as_bool(self.c('reuse_validated'), True):
            done = self.validated_domains()
            skip = [r for r in recs if r['domain'] in done or any(
                r['domain'].endswith('.' + v) for v in done)]
            if skip:
                self._say('validated in the account already, no DCV record: %s' % ', '.join(
                    r['domain'] for r in skip), 'ok')
            recs = [r for r in recs if r not in skip]
        held['dcv'] = placer.place_all(req, recs)
        sc.pending_put(self.ctx, slot, req, held, ttl_days=120)
        if any(p.get('how') == 'placed' for p in held['dcv']):
            placer.wait_visible(req, held['dcv'])
        if held['dcv']:
            self._ask_check(oid)

    def _await(self, r, slot, held, oid, req, placer):
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 15))
        while True:
            det = self.call('GET', 'path_detail', what='the order %s' % oid, order=oid)
            st = str(det.get('status') or '').lower()
            if st in ISSUED:
                certs = sc.certs_of(self.download(oid, (det.get('certificate') or {}).get('id')))
                try:
                    out = sc.finish(self.ctx, r, certs, who='DigiCert',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'order_id': oid, 'ref': oid,
                                          'certificate_id': (det.get('certificate') or {}).get('id')})
                except PluginError:
                    out = None              # the order's old certificate still: the reissue waits
                if out:
                    placer.cleanup(req, held.get('dcv') or [])
                    sc.pending_drop(self.ctx, slot)
                    cid = (det.get('certificate') or {}).get('id')
                    if cid:
                        self.ctx.kv_set('digicert-cert:%s' % sc.fingerprint(out.cert_pem)[:40],
                                        str(cid), ttl_s=5 * 366 * 86400)
                    return out
            elif st in FAILED:
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('DigiCert did not issue: the order %s is %s' % (oid, st),
                                  retry=False)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('DigiCert has not issued yet (order %s: %s) - the DCV records '
                                  'stay in place; acme asks again at the next try' % (oid, st or '?'))
            self._sleep(every)

    def download(self, oid, cid=None):
        """pem_all of the order's certificate: by its certificate ID where it is known (the
        documented "Download certificate by format"), else by the order."""
        if cid and re.match(r'^\d{1,20}\Z', str(cid)):
            try:
                return self.call('GET', 'path_download_cert', what='the download', raw=True,
                                 certificate=cid)
            except PluginError as e:
                if 'answered 404' not in str(e):
                    raise
                self._say('the certificate %s was not found by its ID - downloaded by the order'
                          % cid, 'info')
        return self.call('GET', 'path_download', what='the download', raw=True, order=oid)

    # -- the orders of the account (Certificates → Import from a source) -----------------------
    def _acme_ids(self):
        """{order id: acme's certificate id} of the orders acme made here."""
        out = {}
        try:
            kept = self.ctx.kv_keys('digicert-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('order_id') and cid.isdigit():
                out[str(v['order_id'])] = int(cid)
        return out

    def list_existing(self):
        """Every order of the account (List orders, page by page) - read only."""
        mine = self._acme_ids()
        out, offset, per = [], 0, 1000
        for _page in range(50):
            got = self.call('GET', 'path_orders', what='the list of orders',
                            query={'offset': offset, 'limit': per})
            orders = [o for o in (got.get('orders') or []) if isinstance(o, dict)]
            for o in orders:
                oid = str(o.get('id') or '').strip()
                if not oid:
                    continue
                c = o.get('certificate') if isinstance(o.get('certificate'), dict) else {}
                cn = str(c.get('common_name') or '').strip()
                names = [cn] + [str(n).strip() for n in (c.get('dns_names') or [])
                                if str(n).strip()]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                st = str(o.get('status') or '').lower()
                prod = o.get('product') if isinstance(o.get('product'), dict) else {}
                end = self._until(o)
                cert_end = self._day(c.get('valid_till'))
                out.append({'ref': oid, 'cn': cn or (names[0] if names else ''),
                            'names': names,
                            'product': str(prod.get('name') or prod.get('name_id') or ''),
                            'status': st, 'not_before': self._day(c.get('valid_from')),
                            'not_after': cert_end,
                            'paid_until': end if end and end != cert_end else None,
                            'serial': str(c.get('serial_number') or ''),
                            'downloadable': st in ISSUED,
                            'renewable': 'reissue' if st in ISSUED and (
                                end is None or end > time.time() + 7 * 86400) else 'order',
                            'note': '' if st in ISSUED else 'the order is %s' % (st or '?'),
                            'acme_cert_id': mine.get(oid)})
            page = got.get('page') if isinstance(got.get('page'), dict) else {}
            total = int(sc.num(page.get('total'), 0))
            offset += len(orders)
            if not orders or len(orders) < per or (total and offset >= total):
                break
        return out

    @staticmethod
    def _day(v):
        try:
            return calendar.timegm(time.strptime(str(v)[:10], '%Y-%m-%d')) if v else None
        except (TypeError, ValueError):
            return None

    def fetch_existing(self, ref):
        """The certificate of order `ref` and its chain (the download, pem_all) - read
        only."""
        oid = str(ref or '').strip()
        if not re.match(r'^\d{1,20}\Z', oid):
            raise PluginError('%s is not an order number' % (oid or '?'), retry=False)
        try:
            det = self.call('GET', 'path_detail', what='the order %s' % oid, order=oid)
        except PluginError as e:
            self._say('the order %s could not be read (%s) - downloaded by its number' % (oid, e),
                      'warn')
            det = {}
        cert = det.get('certificate') if isinstance(det.get('certificate'), dict) else {}
        out = sc.existing(sc.certs_of(self.download(oid, cert.get('id'))), who='DigiCert',
                          ref=oid)
        out['acme_cert_id'] = self._acme_ids().get(oid)
        return out

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

    def action(self, key):
        if key == 'organizations':
            got = self.call('GET', 'path_orgs', what='the organizations')
            orgs = got.get('organizations') or []
            if not orgs:
                return 'the account has no organization (DV products need none)'
            for o in orgs:
                self._say('organization %s: %s (%s)' % (o.get('id'), o.get('name') or '?',
                                                        o.get('status') or '?'))
            return '%d organization(s): %s' % (len(orgs), ', '.join(
                '%s = %s' % (o.get('id'), o.get('name')) for o in orgs))
        if key == 'products':
            got = self.call('GET', 'path_products', what='the products')
            ps = got.get('products') or []
            for p in ps:
                self._say('%s: %s' % (p.get('name_id'), p.get('name') or ''))
            return '%d product(s) the account may order: %s' % (len(ps), ', '.join(
                str(p.get('name_id')) for p in ps))
        if key == 'domains':
            done = self.validated_domains()
            if not done:
                return 'no domain of the account has a DCV that still holds'
            return 'validated: %s' % ', '.join('%s (until %s)' % (d, time.strftime(
                '%Y-%m-%d', time.gmtime(t))) for d, t in sorted(done.items()))
        return Issuer.action(self, key)

    def test(self):
        me = self.call('GET', 'path_detail', what='the order', order=self.c('order_id')) \
            if self.c('order_id') else None
        who = self.call('GET', 'path_me', what='the API key')
        words = 'DigiCert answers: the API key is %s %s\'s' % (who.get('first_name') or '',
                                                               who.get('last_name') or '?')
        if me is not None:
            words += '; order %s is %s' % (self.c('order_id'), me.get('status') or '?')
        words += '; new paid orders %s' % ('ALLOWED' if sc.as_bool(self.c('allow_paid'))
                                           else 'not allowed')
        return words

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['region', 'api_url', 'api_key']

    def discover_setup(self):
        """Read-only: the organizations (GET /organization), the products the account may
        order (GET /product - one of the brands' list as Product, another as its name_id),
        the domains whose DCV still holds, and the issued orders (List orders) - one to
        reissue in, never picked by itself."""
        out = Plugin.discover_setup(self)
        got = self.call('GET', 'path_orgs', what='the organizations')
        orgs = [o for o in got.get('organizations') or [] if isinstance(o, dict) and o.get('id')]
        self.offer(out, 'organization_id', [[str(o['id']), '%s (%s)' % (
            o.get('name') or o['id'], o.get('status') or '?')] for o in orgs])
        got = self.call('GET', 'path_products', what='the products')
        known = {n for n, _b, _t, _lv, _w in BRANDS}
        ours, others = [], []
        for p in got.get('products') or []:
            nid = str((p or {}).get('name_id') or '').strip() if isinstance(p, dict) else ''
            if re.match(r'^[a-z0-9_]+\Z', nid):
                (ours if nid in known else others).append([nid, str(p.get('name') or nid)])
        out['facts'].append(['Products', str(len(ours) + len(others))])
        self.offer(out, 'product', ours)
        if others:
            self.offer(out, 'product_code', [['', 'Empty: the product chosen above']] + others,
                       {o[0]: {'product': 'other'} for o in others}, pick='')
        done = self.validated_domains()
        out['facts'].append(['Domains validated', ', '.join(sorted(done)[:20]) + (
            ' …' if len(done) > 20 else '') if done else '0'])
        rows = self.list_existing()
        out['facts'].append(['Orders', str(len(rows))])
        sc.reuse_choice(self, out, 'order_id', rows,
                        'Empty: the order acme made last for the certificate')
        return out
