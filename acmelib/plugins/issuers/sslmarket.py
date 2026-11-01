# -*- coding: utf-8 -*-
"""
Commercial certificates (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo…)
bought through SSLmarket (SSLmarket.cz / .sk / .com / .de / .at / .ch / .hu /
.co.uk - one platform of ZONER a.s.) with its REST API. See docs/sslmarket.md.

What is known of the API, and from where (read 2026-11):

* https://www.sslmarket.com/ssl/sslmarket-api-for-ordering-certificates
  (also .co.uk / .cz): every call carries the account's API key in the header
  X-Auth-Token; the key appears in the customer administration once
  "Account access via API" ("Přístup k účtu přes API") is switched on in the
  account settings. Example: GET https://www.sslmarket.com/api/order/list.
  2XX on success, 4XX with the kind of error and its description in the body.
  Functions: product list, new order, order list, order detail, order change,
  reissue (and cancelling a reissue), revocation, certificate download,
  resending the DCV e-mail, a CSR / certificate decoder, OCSP status.
* https://www.sslmarket.cz/api/swagger-ui/ - the OpenAPI (Swagger) of it.
* https://www.sslmarket.com/ssl/manual-work-with-api-using-the-postman-tool
  and https://www.sslmarket.cz/blog/nebojte-se-api-usetri-vam-cas (Postman).
* https://www.sslmarket.cz/blog/vyuzijte-vylepsenou-api-pro-objednani-vsech-typu-certifikatu
  (2020: the second generation - all kinds of certificates, downloads).
* An older page of the API (sslmarket-api-for-ordering-certificates-old)
  names GET /product/list and POST /order/certificate/{PRODUCT_CODE}.
* https://github.com/SSLmarket-from-ZONER/SSLmarket-API (2015, archived): the
  first API - one form POST to /api with customer_id + password, "new" or
  "renew", the order's parameters (domain, years, certificate, sans,
  sans_count, csr, dv_auth_method Email|DNS|FILE, verify_mailbox, owner_*,
  auth_*, tech_*, invoice_*, voucher, note, test), answer {ack, errors, data}.
  It could not download certificates; it is not spoken here, but its
  parameter names are the best documented ones and are sent (see below).

UNCERTAIN - the Swagger could not be read from where this was written, so:
the paths other than /order/list and /product/list, the names of the JSON
fields of an order (the 2015 names are sent), how the API hands back the DCV
record or file, the order's states and the download's shape. Every path is a
setting of the module (More), the answers are read tolerantly (several names
for each thing, PEM / PKCS#7 / JSON), and anything else can be added to the
order as "key=value" lines. Check against the Swagger before the first paid
order; docs/sslmarket.md says what to compare.

Money: a NEW order (or a renewal order) is a purchase. It is only made when
"Allow new orders (paid)" is on; otherwise only reissues inside an order
that is paid already run, and a renewal that would need a purchase stops
with words saying so. Multi-year subscriptions: the certificate is reissued
inside the order for as long as the subscription runs (the default).

DCV (domain control validation): the record or file the API asks for is put
in place by the certificate's own challenge module (acme's DNS server, deSEC,
Cloudflare, HTTP over SSH…), and left there until the certificate is issued -
a CA checks in its own time. OV/EV validation can take days: the order is then
kept in the module's state and the job ends "pending"; every later try asks
for the order again instead of buying another.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import posixpath
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Issued, PluginError, field, dual_order_field

API_URLS = {
    'cz': 'https://www.sslmarket.cz/api',
    'sk': 'https://www.sslmarket.sk/api',
    'com': 'https://www.sslmarket.com/api',
    'de': 'https://www.sslmarket.de/api',
    'at': 'https://www.sslmarket.at/api',
    'ch': 'https://www.sslmarket.ch/api',
    'hu': 'https://www.sslmarket.hu/api',
    'uk': 'https://www.sslmarket.co.uk/api',
}

# The product codes of the documented API (2015). The codes of today may
# differ: the action "Load the products" lists them from the account.
PRODUCTS = [
    ['RAPIDSSL_RAPIDSSL', 'RapidSSL (DV)'],
    ['RAPIDSSL_RAPIDSSL_WILDCARD', 'RapidSSL Wildcard (DV)'],
    ['GEOTRUST_QUICKSSL_PREMIUM', 'GeoTrust QuickSSL Premium (DV)'],
    ['GEOTRUST_TRUE_BUSINESSID', 'GeoTrust True BusinessID (OV)'],
    ['GEOTRUST_TRUE_BUSINESSID_WILDCARD', 'GeoTrust True BusinessID Wildcard (OV)'],
    ['GEOTRUST_TRUE_BUSINESSID_EV', 'GeoTrust True BusinessID EV'],
    ['THAWTE_SSL_123', 'Thawte SSL 123 (DV)'],
    ['THAWTE_WEB_SERVER', 'Thawte Web Server (OV)'],
    ['THAWTE_WEB_SERVER_WILDCARD', 'Thawte Web Server Wildcard (OV)'],
    ['THAWTE_WEB_SERVER_EV', 'Thawte Web Server EV'],
    ['SYMANTEC_SECURE_SITE', 'DigiCert Secure Site (OV)'],
    ['SYMANTEC_SECURE_SITE_PRO', 'DigiCert Secure Site Pro (OV)'],
    ['SYMANTEC_SECURE_SITE_WILDCARD', 'DigiCert Secure Site Wildcard (OV)'],
    ['SYMANTEC_SECURE_SITE_EV', 'DigiCert Secure Site EV'],
    ['SYMANTEC_SECURE_SITE_PRO_EV', 'DigiCert Secure Site Pro EV'],
    ['other', 'Another product (its code)'],
]

# The DCV methods, as acme names them -> the value of dv_auth_method (the
# 2015 API: Email, DNS, FILE; CNAME is a guess for the CNAME method of Sectigo).
DCV_METHODS = {'dns-txt': 'DNS', 'dns-cname': 'CNAME', 'http-file': 'FILE', 'email': 'Email'}

# The states of an order, by the words they might come in.
ISSUED = ('issued', 'active', 'completed', 'complete', 'done', 'valid', 'vydano', 'vydany',
          'vydaný', 'vydáno', 'finished', 'ready', 'certificate issued')
ISSUED_START = ('issued', 'vydan', 'vydán', 'completed')
FAILED = ('rejected', 'cancelled', 'canceled', 'revoked', 'denied', 'failed', 'refunded',
          'expired', 'zamitnuto', 'zamítnuto', 'zrušeno', 'zruseno', 'storno')

PATHS = [
    ('path_products', 'Products', '/product/list'),
    ('path_orders', 'Order list', '/order/list'),
    ('path_account', 'Account (credit)', '/account/detail'),
    ('path_order', 'New order', '/order/certificate/{product}'),
    ('path_detail', 'Order detail', '/order/detail/{order}'),
    ('path_reissue', 'Reissue', '/order/reissue/{order}'),
    ('path_download', 'Certificate download', '/order/download/{order}'),
    ('path_revoke', 'Revocation', '/order/revoke/{order}'),
    ('path_dcv_check', 'Ask for the DCV check (empty: none)', ''),
]


def _now():
    return time.time()


def _as_bool(v):
    if isinstance(v, bool):
        return v
    return str(v or '').strip().lower() in ('1', 'true', 'yes', 'on', 'ano')


def _num(v, default):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _when(v):
    """An epoch from what an API says a date is: epoch, ISO 8601, 'YYYY-MM-DD', 'DD.MM.YYYY'."""
    if v in (None, ''):
        return None
    if isinstance(v, (int, float)):
        return float(v) / (1000.0 if v > 1e11 else 1.0)
    s = str(v).strip()
    if re.match(r'^\d{9,13}$', s):
        return _when(int(s))
    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?', s)
    if m:
        y, mo, d, hh, mm, ss = (int(x or 0) for x in m.groups())
        return float(calendar.timegm((y, mo, d, hh, mm, ss, 0, 0, 0)))
    m = re.match(r'^(\d{1,2})\.\s*(\d{1,2})\.\s*(\d{4})', s)
    if m:
        d, mo, y = (int(x) for x in m.groups())
        return float(calendar.timegm((y, mo, d, 0, 0, 0, 0, 0, 0)))
    return None


def _dig(obj, *keys, depth=0):
    """The first value under any of `keys` (any case, - or _), looked for in
    `obj` and the dicts inside it (data, order, result…), nearest first."""
    if depth > 5:
        return None
    want = [k.lower().replace('-', '_') for k in keys]
    if isinstance(obj, dict):
        norm = {str(k).lower().replace('-', '_'): v for k, v in obj.items()}
        for k in want:
            if k in norm and norm[k] not in (None, ''):
                return norm[k]
        for v in obj.values():
            if isinstance(v, dict):
                got = _dig(v, *keys, depth=depth + 1)
                if got not in (None, ''):
                    return got
    return None


def _base(name):
    n = str(name or '').strip().lower().rstrip('.')
    while n.startswith('*.'):
        n = n[2:]
    return n


def _pem_all(data):
    """Every certificate in what a download gave: PEM, base64 DER / PKCS#7,
    JSON holding either."""
    from acmelib.certs import formats, pki
    if isinstance(data, bytes):
        text = data.decode('utf-8', 'replace')
    else:
        text = str(data or '')
    pieces = []
    try:
        j = json.loads(text)
    except ValueError:
        j = None
    if j is not None:
        def walk(o):
            if isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
            elif isinstance(o, str) and len(o) > 200:
                pieces.append(o)
        walk(j)
    else:
        pieces.append(data if isinstance(data, bytes) else text)
    out = []
    for p in pieces:
        try:
            got = formats.read_any(p if isinstance(p, bytes) else p.replace('\\n', '\n'))
        except PluginError:
            continue
        for c in got.get('certs') or []:
            c = pki.cert_pem(c)
            if c not in out:
                out.append(c)
    return out


class SslmarketIssuer(Issuer):
    kind = 'sslmarket'
    dual_field = 'dual_order'       # a twin is a second order, paid for: only when allowed
    title = 'SSLmarket.cz (DigiCert, Sectigo, GeoTrust…)'
    description = ('Commercial certificates (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo) '
                   'ordered and reissued through the API of SSLmarket; the DCV record or file '
                   'put in place by the certificate\'s challenge. New (paid) orders only when '
                   'allowed; OV/EV orders waiting for validation are fetched later.')
    vendor = 'SSLmarket'
    doc = 'docs/sslmarket.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    choose_days = False
    actions = [
        {'key': 'products', 'label': 'Load the products',
         'help': 'Lists the products (codes, prices) the account can order and keeps them for '
                 'the check of the product code. Orders nothing.', 'changes': False},
        {'key': 'orders', 'label': 'List the orders',
         'help': 'The orders of the account, with their state and the end of the subscription '
                 '- to find the order to reuse. Orders nothing.', 'changes': False},
    ]
    fields = [
        field('api', 'SSLmarket', 'select', default='cz',
              options=[['cz', 'SSLmarket.cz'], ['sk', 'SSLmarket.sk'], ['com', 'SSLmarket.com'],
                       ['de', 'SSLmarket.de'], ['at', 'SSLmarket.at'], ['ch', 'SSLmarket.ch'],
                       ['hu', 'SSLmarket.hu'], ['uk', 'SSLmarket.co.uk'],
                       ['custom', 'Another address (a test system SSLmarket gave you)']],
              help='The SSLmarket your customer account is at (the account and its credit '
                   'belong to that one).'),
        field('api_url', 'API address', 'text', placeholder='https://www.sslmarket.cz/api',
              show_if={'api': ['custom']},
              help='SSLmarket offers no public sandbox: a test address only where SSLmarket '
                   'gave you one.'),
        field('token', 'API key', 'secret', required=True,
              help='Customer administration → account settings → "Account access via API" '
                   '(Přístup k účtu přes API): switched on, it shows the key. Sent as '
                   'X-Auth-Token.'),
        field('product', 'Product', 'select', default='RAPIDSSL_RAPIDSSL', options=PRODUCTS,
              help='What is ordered. The codes are those of SSLmarket\'s documentation; '
                   '"Load the products" lists the codes of your account.'),
        field('product_code', 'Product code', 'text', placeholder='DIGICERT_SECURE_SITE',
              show_if={'product': ['other']},
              help='The code as "Load the products" (or the Swagger) shows it.'),
        field('years', 'Subscription (years)', 'select', default='1',
              options=[['1', '1 year'], ['2', '2 years'], ['3', '3 years'], ['4', '4 years'],
                       ['5', '5 years']],
              help='What a new order buys. A certificate lives at most 200 days (CA/B Forum, '
                   'since March 2026): a longer subscription is served by reissues, free.'),
        field('validation', 'Kind of validation', 'select', default='dv',
              options=[['dv', 'DV - the domain only'], ['ov', 'OV - the organisation too'],
                       ['ev', 'EV - extended']],
              help='OV and EV need the organisation\'s details and take the CA hours or days.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='dns-txt',
              options=[['dns-txt', 'DNS TXT record (by the certificate\'s DNS challenge)'],
                       ['dns-cname', 'DNS CNAME record (Sectigo)'],
                       ['http-file', 'HTTP file in /.well-known/pki-validation/ (by the '
                                     'certificate\'s HTTP challenge)'],
                       ['email', 'E-mail to the domain\'s approver address']],
              help='How the CA checks the domain. DNS and HTTP are done by the challenge module '
                   'of the certificate, as for ACME; e-mail needs a person to click.'),
        field('approver', 'Approver e-mail', 'text', placeholder='admin@',
              show_if={'dcv': ['email']},
              help='admin@, administrator@, hostmaster@, webmaster@, postmaster@ (of the '
                   'domain), or WHOIS.'),
        field('org_name', 'Organisation', 'text', show_if={'validation': ['ov', 'ev']},
              placeholder='Example s.r.o.', help='As in the commercial register.'),
        field('org_street', 'Street', 'text', show_if={'validation': ['ov', 'ev']}),
        field('org_city', 'City', 'text', show_if={'validation': ['ov', 'ev']}),
        field('org_zip', 'Post code', 'text', show_if={'validation': ['ov', 'ev']}),
        field('org_country', 'Country (2 letters)', 'text', default='CZ',
              show_if={'validation': ['ov', 'ev']}),
        field('org_id', 'Company ID (IČO)', 'text', show_if={'validation': ['ov', 'ev']}),
        field('org_phone', 'Organisation\'s phone', 'text', show_if={'validation': ['ov', 'ev']},
              placeholder='+420.123456789'),
        field('contact_first', 'Contact: first name', 'text', required=True),
        field('contact_last', 'Contact: last name', 'text', required=True),
        field('contact_email', 'Contact: e-mail', 'text', required=True,
              placeholder='pki@example.com',
              help='The person who asks for the certificate; the CA may call or write to them '
                   '(OV/EV).'),
        field('contact_phone', 'Contact: phone', 'text', required=True,
              placeholder='+420.123456789'),
        field('policy', 'At a renewal', 'select', default='reissue',
              options=[['reissue', 'Reissue inside the order while its subscription runs '
                                   '(free); a renewal order only when paid orders are allowed'],
                       ['renew', 'Always a renewal order (paid)'],
                       ['new', 'Always a new order (paid)']],
              help='A renewal of a commercial certificate costs money; a reissue inside a '
                   'paid multi-year subscription does not.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders paid '
                   'already, and stops with words where a purchase would be needed. On: the '
                   'first certificate and an ended subscription are ordered (and paid from the '
                   'credit) by themselves.'),
        field('order_id', 'Order to reuse', 'text', placeholder='123456',
              help='An order bought already (e.g. in the customer administration, a '
                   'multi-year subscription): the certificate is reissued inside it. Empty: '
                   'the order acme made last for the certificate.'),
        field('min_days', 'Reissue while the subscription runs at least (days)', 'number',
              default=30, advanced=True,
              help='Fewer days left: a renewal order is needed (when allowed).'),
        field('voucher', 'Discount voucher', 'text', advanced=True),
        field('extra', 'More order fields', 'list', advanced=True,
              placeholder='invoice_vat_id=CZ12345678',
              help='key=value lines added to every new order and reissue, for what the API '
                   'wants and this form does not ask.'),
        field('txt_label', 'Label of the DNS TXT record', 'text', default='_dnsauth',
              advanced=True,
              help='Where the TXT record goes when the API does not say: LABEL.NAME '
                   '(DigiCert: _dnsauth; @ for NAME itself).'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600, advanced=True,
              help='How long a try waits for the CA (DV: minutes). Longer: the order is asked '
                   'for again at the next try (OV/EV: days).'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=15, advanced=True),
        field('body', 'Sent as', 'select', default='json', advanced=True,
              options=[['json', 'JSON'], ['form', 'Form fields (x-www-form-urlencoded)']]),
        field('auth_header', 'Header of the API key', 'text', default='X-Auth-Token',
              advanced=True),
    ] + [field(k, 'Path: ' + words, 'text', default=d, advanced=True,
               help='Under the API address; {order} and {product} are filled in.')
         for k, words, d in PATHS]
    fields = fields + [dual_order_field()]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        # E-mail DCV needs no challenge module for the names.
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep

    @classmethod
    def describe(cls):
        d = Issuer.describe.__func__(cls)
        d.update(needs_challenge=True, challenge_types=list(cls.challenge_types),
                 wildcards=cls.wildcards, ip_names=cls.ip_names, makes_key=False,
                 choose_days=False)
        return d

    # -- talking to it ------------------------------------------------------------------
    def _say(self, words, level='info'):
        try:
            self.ctx.step(words, level)
        except Exception:                               # noqa: BLE001
            pass

    def base_url(self):
        api = self.c('api') or 'cz'
        if api == 'custom':
            url = str(self.c('api_url') or '').strip().rstrip('/')
            if not url:
                raise PluginError('set the API address', retry=False)
            if not re.match(r'^https://', url):
                raise PluginError('the API address must be https://…', retry=False)
            return url
        if api not in API_URLS:
            raise PluginError('an unknown SSLmarket: %s' % api, retry=False)
        return API_URLS[api]

    def _path(self, key, **fill):
        p = str(self.c(key) or '').strip()
        if not p:
            return ''
        for k, v in fill.items():
            p = p.replace('{%s}' % k, urllib.parse.quote(str(v), safe=''))
        return p if p.startswith('/') else '/' + p

    def call(self, method, key, body=None, what='', **fill):
        """(status, parsed JSON or raw bytes) of one call; PluginError for what failed."""
        path = self._path(key, **fill)
        if not path:
            raise PluginError('the path of "%s" is not set (More)' % (what or key), retry=False)
        token = str(self.c('token') or '').strip()
        if not token:
            raise PluginError('set the API key of SSLmarket', retry=False)
        headers = {str(self.c('auth_header') or 'X-Auth-Token'): token,
                   'Accept': 'application/json, application/x-pem-file, */*',
                   'User-Agent': 'acme certificate manager'}
        data = None
        if body is not None:
            if self.c('body') == 'form':
                data = urllib.parse.urlencode({k: v for k, v in body.items() if v not in (None, '')}
                                              ).encode('utf-8')
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            else:
                data = json.dumps(body).encode('utf-8')
                headers['Content-Type'] = 'application/json'
        url = self.base_url() + path
        self.ctx.debug('%s %s' % (method, url))
        try:
            status, hdrs, raw = self.ctx.http(method, url, data, headers, 60)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('SSLmarket\'s API does not answer (%s): %s' % (url, e))
        raw = raw or b''
        try:
            parsed = json.loads(raw.decode('utf-8')) if raw.strip()[:1] in (b'{', b'[') else None
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if status in (401, 403):
            raise PluginError('SSLmarket refuses the API key (%d) - check the key, and that '
                              '"Account access via API" is on in the account settings%s'
                              % (status, self._errors(parsed, ' - it says: ')),
                              detail=raw[:1000].decode('utf-8', 'replace'), retry=False)
        if status == 402:
            raise PluginError('SSLmarket: not enough credit for the order (402)%s - top the '
                              'credit up in the customer administration'
                              % self._errors(parsed, ' - '), retry=False)
        if status == 404:
            raise PluginError('SSLmarket answers 404 for %s %s%s - the %s is not known (a wrong '
                              'order number, or the path under More differs from the API\'s '
                              'Swagger)' % (method, path, self._errors(parsed, ': '),
                                            what or 'address'),
                              detail=raw[:1000].decode('utf-8', 'replace'), retry=False)
        if status == 429 or status >= 500:
            raise PluginError('SSLmarket\'s API is busy or broken (%d)%s - tried again later'
                              % (status, self._errors(parsed, ': ')),
                              detail=raw[:1000].decode('utf-8', 'replace'), retry=True)
        if status >= 400:
            raise PluginError('SSLmarket refused %s (%d)%s' % (what or path, status,
                                                               self._errors(parsed, ': ')),
                              detail=raw[:2000].decode('utf-8', 'replace'), retry=False)
        if isinstance(parsed, dict) and str(parsed.get('ack') or '').lower() == 'error':
            raise PluginError('SSLmarket refused %s%s' % (what or path, self._errors(parsed, ': ')),
                              detail=raw[:2000].decode('utf-8', 'replace'), retry=False)
        return status, (parsed if parsed is not None else raw)

    @staticmethod
    def _errors(parsed, lead=''):
        if not isinstance(parsed, (dict, list)):
            return ''
        bits = []

        def add(v):
            if isinstance(v, dict):
                words = v.get('message') or v.get('description') or v.get('detail') or v.get('title')
                where = v.get('field') or v.get('property') or v.get('propertyPath') or v.get('code')
                if words:
                    bits.append('%s%s' % ('%s: ' % where if where else '', words))
                else:
                    for k, x in v.items():
                        if isinstance(x, (str, int)):
                            bits.append('%s: %s' % (k, x))
                        elif isinstance(x, list):
                            bits.extend('%s: %s' % (k, y) for y in x if isinstance(y, str))
            elif isinstance(v, list):
                for x in v:
                    add(x)
            elif v not in (None, ''):
                bits.append(str(v))
        if isinstance(parsed, list):
            add(parsed)
        else:
            for k in ('errors', 'error', 'violations', 'message', 'detail', 'title'):
                if parsed.get(k):
                    add(parsed[k])
                    break
        said = '; '.join(b for b in bits if b)[:500]
        return lead + said if said else ''

    # -- settings ------------------------------------------------------------------------
    def product(self):
        p = str(self.c('product') or '').strip()
        if p == 'other':
            p = str(self.c('product_code') or '').strip()
        if not p:
            raise PluginError('set the product (or its code)', retry=False)
        return p

    def _extra(self):
        out = {}
        v = self.c('extra') or []
        if isinstance(v, str):
            v = v.splitlines()
        for line in v:
            line = str(line).strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                raise PluginError('"%s" under More order fields is not key=value' % line,
                                  retry=False)
            k, val = line.split('=', 1)
            out[k.strip()] = val.strip()
        return out

    def _contact(self):
        need = [('contact_first', 'first name'), ('contact_last', 'last name'),
                ('contact_email', 'e-mail'), ('contact_phone', 'phone')]
        miss = [w for k, w in need if not str(self.c(k) or '').strip()]
        if miss:
            raise PluginError('set the contact person\'s %s' % ', '.join(miss), retry=False)
        email = str(self.c('contact_email')).strip()
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            raise PluginError('%s is not an e-mail address' % email, retry=False)
        return {k: str(self.c(k)).strip() for k, _w in need}

    def order_body(self, req, reissue=False):
        """The order's fields, by the names of SSLmarket's documented API."""
        names = list(req.names or [])
        if not names:
            raise PluginError('the certificate has no names', retry=False)
        dcv = self.c('dcv') or 'dns-txt'
        if dcv not in DCV_METHODS:
            raise PluginError('an unknown DCV method: %s' % dcv, retry=False)
        sans = names[1:]
        body = {'domain': names[0], 'csr': req.csr_pem.strip(),
                'dv_auth_method': DCV_METHODS[dcv], 'hash_algorithm': 'SHA2-256'}
        if sans:
            body['sans'] = ','.join(sans)
            body['sans_count'] = len(sans)
        if dcv == 'email':
            body['verify_mailbox'] = str(self.c('approver') or 'admin@').strip()
        if not reissue:
            c = self._contact()
            body.update(certificate=self.product(), years=int(_num(self.c('years'), 1) or 1),
                        auth_firstname=c['contact_first'], auth_lastname=c['contact_last'],
                        auth_email=c['contact_email'], auth_tel=c['contact_phone'],
                        tech_firstname=c['contact_first'], tech_lastname=c['contact_last'],
                        tech_email=c['contact_email'], tech_tel=c['contact_phone'])
            if self.c('validation') in ('ov', 'ev'):
                need = [('org_name', 'organisation'), ('org_street', 'street'),
                        ('org_city', 'city'), ('org_zip', 'post code'),
                        ('org_country', 'country')]
                miss = [w for k, w in need if not str(self.c(k) or '').strip()]
                if miss:
                    raise PluginError('an OV/EV certificate needs the organisation\'s %s'
                                      % ', '.join(miss), retry=False)
                body.update(owner_name=self.c('org_name'), owner_street=self.c('org_street'),
                            owner_city=self.c('org_city'), owner_zip=self.c('org_zip'),
                            owner_country=str(self.c('org_country')).upper(),
                            owner_tel=self.c('org_phone') or c['contact_phone'],
                            owner_business_id=self.c('org_id') or None)
            else:
                body['owner_name'] = '%s %s' % (c['contact_first'], c['contact_last'])
            if self.c('voucher'):
                body['voucher'] = self.c('voucher')
        body.update(self._extra())
        return {k: v for k, v in body.items() if v not in (None, '')}

    # -- state ---------------------------------------------------------------------------------
    def _cert_key(self, req):
        if getattr(req, 'cert_id', None):
            return str(req.cert_id)
        return hashlib.sha256(','.join(sorted(req.names or [])).encode()).hexdigest()[:24]

    def _get(self, key):
        v = self.ctx.kv_get(key)
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                return None
        return v if isinstance(v, dict) else None

    def _put(self, key, value, ttl_s=None):
        self.ctx.kv_set(key, json.dumps(value) if value is not None else None, ttl_s=ttl_s)

    def _seal(self, text, bind):
        from acmelib.plugins.issuers.acme import _seal
        return _seal(self.ctx, text, bind)

    def _unseal(self, value, bind):
        from acmelib.plugins.issuers.acme import _unseal
        return _unseal(self.ctx, value, bind)

    # -- an order -------------------------------------------------------------------------------
    def order_id_of(self, answer):
        oid = _dig(answer, 'order_id', 'orderId', 'order_number', 'orderNumber', 'id', 'number')
        if isinstance(oid, dict):
            oid = None
        return str(oid) if oid not in (None, '') else None

    def detail(self, order_id):
        _st, got = self.call('GET', 'path_detail', what='order %s' % order_id, order=order_id)
        if not isinstance(got, dict):
            raise PluginError('SSLmarket sent no order detail for %s' % order_id,
                              detail=bytes(got or b'')[:500].decode('utf-8', 'replace'))
        return got

    @staticmethod
    def state_of(detail):
        """'issued' | 'failed' | 'pending', and the words the API used."""
        s = _dig(detail, 'status', 'state', 'order_status', 'orderStatus', 'certificate_status')
        if isinstance(s, dict):
            s = _dig(s, 'code', 'name', 'value', 'status')
        words = str(s or '').strip()
        low = words.lower()
        if low in ISSUED or low.startswith(ISSUED_START):
            return 'issued', words
        if any(w in low for w in FAILED):
            return 'failed', words
        return 'pending', words or 'not said'

    @staticmethod
    def subscription_end(detail):
        return _when(_dig(detail, 'subscription_end', 'subscription_valid_to', 'subscription_to',
                          'subscriptionEnd', 'valid_to_subscription', 'order_valid_to',
                          'order_expiration', 'paid_until', 'service_end', 'valid_till',
                          'expiration', 'expires'))

    def _choose(self, req, sub_key):
        """('reissue', order_id) or ('new' | 'renew', None) - or a PluginError where a
        purchase would be needed and is not allowed."""
        policy = self.c('policy') or 'reissue'
        allowed = _as_bool(self.c('allow_paid'))
        given = str(self.c('order_id') or '').strip()
        kept = self._get(sub_key) or {}
        order = given or kept.get('order_id')
        why, renewable = '', bool(order)
        if policy == 'reissue' and order:
            try:
                det = self.detail(order)
            except PluginError as e:
                if given:
                    raise PluginError('the order to reuse, %s, cannot be read: %s' % (order, e),
                                      retry=e.retry)
                det, why = None, 'the order %s acme made is not known to SSLmarket (%s)' % (order, e)
                renewable = False
            if det is not None:
                state, words = self.state_of(det)
                end = self.subscription_end(det)
                left = (end - _now()) / 86400.0 if end else None
                margin = _num(self.c('min_days'), 30)
                if state == 'failed' and not re.search(r'expir', words, re.I):
                    why, renewable = 'the order %s is %s' % (order, words), False
                elif left is not None and left < margin:
                    why = 'the subscription of order %s ends %s (%d days)' % (
                        order, time.strftime('%Y-%m-%d', time.gmtime(end)), max(0, int(left)))
                elif state == 'failed':
                    why = 'the order %s has %s' % (order, words)
                else:
                    self._say('the order %s is reissued (its subscription runs%s) - free, nothing '
                              'is bought' % (order, ' until %s' % time.strftime(
                                  '%Y-%m-%d', time.gmtime(end)) if end else ''), 'ok')
                    return 'reissue', order
        elif policy == 'reissue':
            why = 'there is no order to reissue in (set "Order to reuse", or allow a paid order ' \
                  'for the first certificate)'
        else:
            why = 'the policy is to make a %s order at every renewal' % policy
        kind = 'renew' if (policy == 'renew' or (policy == 'reissue' and renewable)) else 'new'
        if not allowed:
            raise PluginError('nothing ordered: %s, and a %s order would be a purchase. Paid orders '
                              'are not allowed for this source - switch on "Allow new orders '
                              '(paid)", or buy the order in SSLmarket\'s customer administration '
                              'and set it as "Order to reuse"' % (why, kind), retry=False)
        self._say('%s - a %s order is made (paid from the account\'s credit: allowed for this '
                  'source)' % (why[:1].upper() + why[1:], kind), 'warn')
        return kind, None

    def issue(self, req):
        if not req.csr_pem:
            raise PluginError('there is no request (CSR) to send to SSLmarket', retry=False)
        ck = self._cert_key(req)
        slot = 'sslmarket-pending:%s' % ck
        sub_key = 'sslmarket-order:%s' % ck
        held = self._get(slot)
        if held and sorted(held.get('names') or []) != sorted(req.names or []):
            self._say('the order %s waiting at SSLmarket was for other names (%s) - it is left '
                      'alone, and its DCV records taken away' % (
                          held.get('order_id'), ', '.join(held.get('names') or [])), 'warn')
            self._cleanup(req, held.get('dcv') or [])
            self._put(slot, None)
            held = None
        if held:
            order_id = str(held['order_id'])
            key_pem = self._unseal(held.get('key'), slot) if held.get('key') else req.key_pem
            if not key_pem:
                self._put(slot, None)
                raise PluginError('the key of the waiting order %s cannot be opened - asked again '
                                  'with a new order' % order_id)
            self._say('the order %s (%s) waits at SSLmarket since %s - asked for again, nothing '
                      'is ordered' % (order_id, held.get('how'), time.strftime(
                          '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
        else:
            how, order_id = self._choose(req, sub_key)
            key_pem = req.key_pem
            if how == 'reissue':
                _st, got = self.call('POST', 'path_reissue', self.order_body(req, reissue=True),
                                     what='the reissue of order %s' % order_id, order=order_id)
                self._say('reissue of order %s asked for' % order_id, 'ok')
            else:
                body = self.order_body(req)
                body['method'] = how
                _st, got = self.call('POST', 'path_order', body, what='the order',
                                     product=self.product())
                order_id = self.order_id_of(got)
                if not order_id:
                    raise PluginError('SSLmarket took the order but said no order number - look '
                                      'in the customer administration before trying again (a '
                                      'second order would be paid again)', retry=False,
                                      detail=json.dumps(got)[:2000] if isinstance(got, (dict, list))
                                      else None)
                self._say('order %s made at SSLmarket: %s for %s, %s year(s)' % (
                    order_id, self.product(), ', '.join(req.names), self.c('years') or 1), 'ok')
                self._put(sub_key, {'order_id': order_id, 'product': self.product(),
                                    'at': _now()})
            held = {'order_id': order_id, 'how': how, 'at': _now(), 'names': list(req.names),
                    'key': self._seal(key_pem, slot), 'dcv': [], 'placed': False}
            # Kept at once: whatever happens next, the order is not bought twice.
            self._put(slot, held, ttl_s=120 * 86400)
            held['answer'] = got if isinstance(got, dict) else None
        if not held.get('placed'):
            self._dcv(req, slot, held, order_id, held.pop('answer', None))
        return self._await(req, slot, held, order_id, key_pem)

    def _dcv(self, req, slot, held, order_id, answer):
        """The DCV records of the order put in place (once per order)."""
        recs = self.dcv_records(answer) if answer else []
        if not recs and self.c('dcv') != 'email':
            try:
                recs = self.dcv_records(self.detail(order_id))
            except PluginError as e:
                self._say('the order\'s DCV could not be read: %s' % e, 'warn')
        if not recs and self.c('dcv') != 'email':
            self._say('SSLmarket said no DCV record for order %s (done already, or another '
                      'shape of answer - see docs/sslmarket.md)' % order_id)
        held['dcv'] = self._place_all(req, recs)
        held['placed'] = True
        self._put(slot, held, ttl_s=120 * 86400)
        if held['dcv']:
            self._wait_visible(req, held['dcv'])
            if self._path('path_dcv_check', order=order_id):
                try:
                    self.call('POST', 'path_dcv_check', {}, what='the DCV check', order=order_id)
                except PluginError as e:
                    self._say('the DCV check could not be asked for: %s' % e, 'warn')

    def _await(self, req, slot, held, order_id, key_pem):
        end = _now() + _num(self.c('wait_issue'), 600)
        every = max(1.0, _num(self.c('poll_every'), 15))
        while True:
            det = self.detail(order_id)
            state, words = self.state_of(det)
            if state == 'issued':
                out = self.download(order_id, key_pem, req)
                self._cleanup(req, held.get('dcv') or [])
                self._put(slot, None)
                if key_pem.strip() != (req.key_pem or '').strip():
                    out.key_pem = key_pem       # the key the waiting order was made with
                return out
            if state == 'failed':
                self._cleanup(req, held.get('dcv') or [])
                self._put(slot, None)
                reason = _dig(det, 'reason', 'status_reason', 'note', 'message')
                raise PluginError('SSLmarket: the order %s is %s%s' % (
                    order_id, words, ' - %s' % str(reason)[:300] if reason else ''), retry=False)
            if self.ctx.cancelled():
                raise PluginError('stopped', retry=False)
            if _now() >= end:
                more = ''
                if self.c('validation') in ('ov', 'ev'):
                    more = ' (OV/EV: the CA checks the organisation - it may phone the contact)'
                elif self.c('dcv') == 'email':
                    more = ' (the approver must confirm the e-mail the CA sent)'
                raise PluginError('the order %s waits at SSLmarket (%s)%s; the DCV stays in '
                                  'place and acme asks for the certificate again at the next try '
                                  '- nothing is ordered again' % (order_id, words, more),
                                  retry=True)
            self._say('order %s: %s - asked again in %d s' % (order_id, words, int(every)))
            self._sleep(min(every, max(1.0, end - _now())))
            every = min(every * 1.5, 120.0)

    def download(self, order_id, key_pem, req):
        _st, got = self.call('GET', 'path_download', what='the certificate of order %s' % order_id,
                             order=order_id)
        from acmelib.certs import pki
        certs = _pem_all(json.dumps(got) if isinstance(got, (dict, list)) else got)
        if not certs:
            raise PluginError('SSLmarket sent no certificate for order %s' % order_id)
        leaf = None
        for c in certs:
            if pki.key_matches(c, key_pem):
                leaf = c
                break
        if not leaf:
            raise PluginError('the certificate of order %s is for another key than this request '
                              '(another reissue of the order?) - it is not used' % order_id,
                              retry=False)
        chain = pki.order_chain(leaf, [c for c in certs if c != leaf]) or \
            [c for c in certs if c != leaf]
        info = pki.cert_info(leaf)
        self._say('the certificate came: order %s, serial %s, until %s' % (
            order_id, info.get('serial') or '?',
            time.strftime('%Y-%m-%d', time.gmtime(info.get('not_after') or 0))), 'ok')
        try:
            self._put('sslmarket-serial:%s' % pki.norm_serial(info.get('serial') or '')[:80],
                      {'order_id': order_id}, ttl_s=5 * 366 * 86400)
        except Exception:                               # noqa: BLE001
            pass
        return Issued(leaf, chain, info={'order_id': order_id, 'api': self.base_url()})

    # -- DCV -----------------------------------------------------------------------------------
    def dcv_records(self, answer):
        """[{'domain', 'type': 'txt'|'cname'|'file'|'email', 'fqdn', 'value', 'path'}]
        from an order's answer, read in the several shapes it might come in."""
        dcv = self.c('dcv') or 'dns-txt'
        if dcv == 'email':
            return []
        found = _dig(answer, 'dcv', 'dcvs', 'dcv_details', 'dcv_data', 'validation',
                     'validations', 'domain_validation', 'domainValidation', 'dcv_records',
                     'dns', 'file', 'auth')
        items = []
        if isinstance(found, list):
            items = [x for x in found if isinstance(x, dict)]
        elif isinstance(found, dict):
            direct = {str(k).lower() for k in found}
            if any(isinstance(v, dict) for v in found.values()) and not direct & {
                    'value', 'record_value', 'txt_value', 'txt', 'token', 'content',
                    'file_content', 'cname_value'}:
                for k, v in found.items():
                    if isinstance(v, dict):
                        items.append(dict(v, domain=v.get('domain') or k))
            else:
                items = [found]
        if not items and isinstance(answer, dict) and _dig(
                answer, 'record_value', 'txt_value', 'dns_txt_value', 'cname_value', 'dns_value',
                'file_content', 'file_contents'):
            items = [answer]            # the record's fields at the top of the answer
        domain0 = _dig(answer, 'domain', 'common_name', 'commonName', 'cn')
        out = []
        for it in items:
            domain = _base(it.get('domain') or it.get('dns_name') or it.get('domain_name') or
                           domain0 or '')
            value = _dig(it, 'record_value', 'txt_value', 'dns_txt_value', 'cname_value',
                         'dns_value', 'value', 'txt', 'token', 'target', 'points_to',
                         'emailHash', 'hash')
            fqdn = _dig(it, 'record_name', 'txt_name', 'cname_name', 'dns_record', 'host',
                        'record', 'fqdn', 'dns_name_record')
            path = _dig(it, 'file_path', 'path', 'file_url', 'url', 'file_name', 'filename')
            content = _dig(it, 'file_content', 'content', 'file_contents', 'body', 'file_value')
            kind = str(_dig(it, 'type', 'method', 'dcv_method') or '').lower()
            if dcv == 'http-file' or 'file' in kind or 'http' in kind:
                if not content:
                    content = value
                if not (content and (path or domain)):
                    continue
                p = str(path or 'fileauth.txt')
                if re.match(r'^https?://', p):
                    u = urllib.parse.urlsplit(p)
                    domain = domain or _base(u.hostname)
                    p = u.path
                if not p.startswith('/'):
                    p = '/.well-known/pki-validation/' + p
                out.append({'domain': domain, 'type': 'file', 'path': p,
                            'value': str(content)})
                continue
            if not value or not domain:
                continue
            rtype = 'cname' if (dcv == 'dns-cname' or 'cname' in kind) else 'txt'
            if fqdn:
                fqdn = str(fqdn).strip().rstrip('.').lower()
                if '.' not in fqdn or not fqdn.endswith(domain):
                    fqdn = '%s.%s' % (fqdn.strip('.'), domain) if fqdn not in ('@', '') else domain
            else:
                label = str(self.c('txt_label') or '').strip().strip('.')
                fqdn = '%s.%s' % (label, domain) if label and label != '@' else domain
            out.append({'domain': domain, 'type': rtype, 'fqdn': fqdn,
                        'value': str(value).strip().rstrip('.') if rtype == 'cname' else str(value)})
        return out

    def _challenge_for(self, req, domain):
        ch = req.challenges or {}
        for n in (domain, '*.' + domain):
            if n in ch:
                return n, ch[n]
        best = None
        for n, c in ch.items():
            b = _base(n)
            if domain == b or domain.endswith('.' + b) or b.endswith('.' + domain):
                if best is None or len(b) > len(_base(best[0])):
                    best = (n, c)
        return best if best else (None, None)

    def _place_all(self, req, recs):
        placed, manual = [], []
        for rec in recs:
            name, ch = self._challenge_for(req, rec['domain'])
            how, handle = None, None
            if ch is not None:
                how, handle = self._place(ch, name, rec)
            if how is None:
                manual.append(rec)
                placed.append({'rec': rec, 'name': name, 'how': 'manual', 'handle': None})
                continue
            placed.append({'rec': rec, 'name': name, 'how': how, 'handle': handle,
                           'kind': getattr(ch, 'kind', '')})
        for rec in manual:
            if rec['type'] == 'file':
                self._say('put in place by hand, for the CA: http://%s%s holding "%s" (no '
                          'challenge module of the certificate can write it)' % (
                              rec['domain'], rec['path'], rec['value']), 'warn')
            else:
                self._say('put in place by hand, for the CA: %s. %s "%s" (no challenge module of '
                          'the certificate can write it)' % (rec['fqdn'], rec['type'].upper(),
                                                             rec['value']), 'warn')
        return placed

    def _place(self, ch, name, rec):
        """(how, handle) - how the record went in, or (None, None) where it cannot."""
        fn = getattr(ch, 'present_record', None)
        if callable(fn):
            # A challenge module that writes any record or file (none does yet).
            h = fn(name, rec['type'], rec.get('fqdn') or rec.get('path'), rec['value'])
            return 'record', h
        types = tuple(getattr(ch, 'types', ()) or ())
        if rec['type'] == 'txt' and 'dns-01' in types:
            if rec['fqdn'] == '_acme-challenge.' + rec['domain']:
                return 'present', ch.present(name, '', '', rec['value'])
            add, target = getattr(ch, 'add_txt', None), getattr(ch, 'target', None)
            if callable(add) and callable(getattr(ch, 'del_txt', None)):
                fqdn = target(rec['fqdn']) if callable(target) else rec['fqdn']
                h = add(fqdn, rec['value'])
                self._say('%s TXT "%s" put in (%s)' % (fqdn, rec['value'], ch.kind or ch.title))
                return 'txt', {'rr': rec['fqdn'], 'fqdn': fqdn, 'txt': rec['value'],
                               'at': _now(), 'h': h}
        if rec['type'] == 'file' and 'http-01' in types:
            p = rec['path']
            if posixpath.dirname(p) == '/.well-known/acme-challenge':
                return 'present', ch.present(name, posixpath.basename(p), rec['value'], '')
            webroot = getattr(ch, 'webroot', None)
            each, write = getattr(ch, '_each', None), getattr(ch, '_write', None)
            if callable(webroot) and callable(each) and callable(write) and \
                    p.startswith('/.well-known/'):
                root = webroot()
                if posixpath.basename(root) == 'acme-challenge':
                    path = posixpath.join(posixpath.dirname(posixpath.dirname(root)), p.lstrip('/'))
                    data = rec['value'].encode('utf-8')
                    failed = each(lambda s, h: write(s, path, data), 'write')
                    if failed:
                        raise PluginError('the DCV file could not be written on %s' % '; '.join(
                            '%s: %s' % f for f in failed))
                    self._say('%s written (%s)' % (path, ch.kind or ch.title))
                    return 'file', {'path': path}
        return None, None

    def _wait_visible(self, req, placed):
        end = _now() + _num(self.c('wait_ready'), 300)
        todo = [p for p in placed if p['how'] in ('present', 'txt', 'record')]
        while todo:
            left = []
            for p in todo:
                _n, ch = self._challenge_for(req, p['rec']['domain'])
                try:
                    ok = ch is None or ch.ready(p['name'], p['handle'])
                except PluginError as e:
                    self._say('whether the DCV record is visible could not be told: %s' % e, 'warn')
                    ok = True
                if not ok:
                    left.append(p)
            todo = left
            if not todo or _now() >= end or self.ctx.cancelled():
                break
            self._sleep(min(10, max(1, end - _now())))
        if todo:
            self._say('the DCV record of %s is not visible yet - the CA checks again by itself'
                      % ', '.join(p['rec']['domain'] for p in todo), 'warn')

    def _cleanup(self, req, placed):
        for p in placed or []:
            if p.get('how') in (None, 'manual'):
                continue
            _n, ch = self._challenge_for(req, p['rec']['domain'])
            if ch is None or getattr(ch, 'kind', '') != p.get('kind', getattr(ch, 'kind', '')):
                # the names changed since: a module of the same kind takes it away
                ch = next((c for c in (req.challenges or {}).values()
                           if getattr(c, 'kind', '') == p.get('kind')), None)
            if ch is None:
                self._say('the DCV record of %s is left (no challenge module of kind %s here) - '
                          'take it away by hand' % (p['rec']['domain'], p.get('kind') or '?'),
                          'warn')
                continue
            try:
                if p['how'] == 'record':
                    fn = getattr(ch, 'cleanup_record', None)
                    if callable(fn):
                        fn(p['name'], p['handle'])
                elif p['how'] == 'present':
                    ch.cleanup(p['name'], p['handle'])
                elif p['how'] == 'txt':
                    h = p['handle'] or {}
                    ch.del_txt(h.get('fqdn'), h.get('txt'), h.get('h'))
                elif p['how'] == 'file':
                    path = (p['handle'] or {}).get('path')
                    rm = getattr(ch, '_remove', None)
                    if path and callable(rm):
                        ch._each(lambda s, h: rm(s, path), 'remove')
            except Exception as e:                      # noqa: BLE001
                self._say('the DCV record of %s could not be taken away: %s'
                          % (p['rec']['domain'], e), 'warn')

    # -- revocation, trying it, the actions ------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        from acmelib.certs import pki
        info = pki.cert_info(cert_pem)
        kept = self._get('sslmarket-serial:%s' % pki.norm_serial(info.get('serial') or '')[:80])
        order_id = (kept or {}).get('order_id') or str(self.c('order_id') or '').strip()
        if not order_id:
            raise PluginError('the order of this certificate is not known to acme - revoke it in '
                              'SSLmarket\'s customer administration', retry=False)
        self.call('POST', 'path_revoke', {'reason': reason, 'serial': info.get('serial')},
                  what='the revocation of order %s' % order_id, order=order_id)
        self._say('SSLmarket asked to revoke the certificate of order %s (reason %s)'
                  % (order_id, reason), 'ok')
        return 'revocation of order %s asked for' % order_id

    def _items(self, got):
        if isinstance(got, list):
            return [x for x in got if isinstance(x, dict)]
        if isinstance(got, dict):
            for k in ('data', 'items', 'products', 'orders', 'list', 'result', 'results'):
                v = got.get(k)
                if isinstance(v, list):
                    return [x for x in v if isinstance(x, dict)]
                if isinstance(v, dict):
                    inner = self._items(v)
                    if inner:
                        return inner
            if all(isinstance(v, dict) for v in got.values()) and got:
                return [dict(v, code=v.get('code') or k) for k, v in got.items()]
        return []

    def products(self):
        _st, got = self.call('GET', 'path_products', what='the product list')
        out = []
        for p in self._items(got):
            code = _dig(p, 'code', 'product_code', 'productCode', 'id', 'sku')
            if code in (None, ''):
                continue
            out.append({'code': str(code),
                        'name': str(_dig(p, 'name', 'title', 'product_name') or code),
                        'price': _dig(p, 'price', 'price_without_vat', 'amount', 'cost')})
        return out

    def test(self):
        prods = self.products()
        bits = ['signed in to %s' % self.base_url(), '%d products' % len(prods)]
        code = self.product()
        if prods and code not in [p['code'] for p in prods]:
            bits.append('the product %s is NOT among them ("Load the products" lists the codes)'
                        % code)
        elif prods:
            bits.append('the product %s is offered' % code)
        try:
            _st, acc = self.call('GET', 'path_account', what='the account')
            credit = _dig(acc, 'credit', 'balance', 'credit_balance', 'zustatek', 'amount')
            if credit not in (None, ''):
                bits.append('credit %s' % credit)
        except PluginError:
            pass                    # not every API says the credit
        bits.append('new paid orders %s' % ('ALLOWED' if _as_bool(self.c('allow_paid'))
                                            else 'not allowed (reissues only)'))
        return '; '.join(bits)

    def action(self, key):
        if key == 'products':
            prods = self.products()
            for p in prods:
                self._say('%s - %s%s' % (p['code'], p['name'],
                                         ' - %s' % p['price'] if p['price'] not in (None, '') else ''))
            self._put('sslmarket-products', {'at': _now(), 'products': prods[:500]},
                      ttl_s=30 * 86400)
            return '%d products; put the code under Product → Another product' % len(prods)
        if key == 'orders':
            _st, got = self.call('GET', 'path_orders', what='the order list')
            items = self._items(got)
            for o in items[:200]:
                state = self.state_of(o)[1]
                end = self.subscription_end(o)
                self._say('order %s: %s, %s, %s%s' % (
                    self.order_id_of(o) or '?', _dig(o, 'domain', 'common_name', 'cn') or '?',
                    _dig(o, 'product', 'product_code', 'certificate') or '?', state,
                    ', subscription until %s' % time.strftime('%Y-%m-%d', time.gmtime(end))
                    if end else ''))
            return '%d orders' % len(items)
        return Issuer.action(self, key)
