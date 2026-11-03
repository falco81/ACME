# -*- coding: utf-8 -*-
"""
Commercial certificates (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo…)
from SSLmarket (SSLmarket.cz / .sk / .com / .de / .at / .ch / .hu / .co.uk -
one platform of ZONER a.s.) through its REST API. Two sources:

    sslmarket        orders and free reissues (POST /order/certificate/{CODE},
                     POST /certificate/order_id/{ID}/reissue), the DCV string
                     put in place by the certificate's validation, the
                     certificate downloaded (…/format/pem_server)
    sslmarket_acme   an ACME key made through the API (POST /acme: directory
                     URL + EAB), then every certificate by ACME (the `acme`
                     source's own code) - renewals with no order and no DCV
                     of SSLmarket's

The API as SSLmarket describes it - OpenAPI 3.0, "SSLmarket's API for ordering
certificates" (test/fixtures/sslmarket-openapi.json, the contract the tests
check every call against): server https://www.sslmarket.cz/api, the account's
key in the header X-Auth-Token, 2XX on success, 4XX with {message}. Also:
https://www.sslmarket.com/ssl/sslmarket-api-for-ordering-certificates,
https://www.sslmarket.cz/api/swagger-ui/. See docs/sslmarket.md.

What the specification leaves open, and how it is read here:
* dns_names is "An array of domains included as SANs" of type string: sent as
  the SANs joined by commas (as the order list gives them back).
* The 201 of a new order has no body schema: an order_id in it is taken, else
  the new order is found in /order/list (the domain and product, inserted
  after the order was sent, not one known before).
* The order's `state` has no list of values: "Issued" is the only one named
  (cancel-reissue). Issued is therefore told by certificate_serial_number
  (a new one after a reissue, and reissue_pending false), failed by words
  (cancelled, rejected, revoked…), anything else is waiting.
* dv_auth_content ("the string required for authentication, FILE and DNS
  only") has no format: a record line ("NAME TXT VALUE"), a URL and content,
  or a bare token are all understood; a bare token goes to TXT
  _dnsauth.NAME (DigiCert; a setting) or /.well-known/pki-validation/
  fileauth.txt. It is always shown in the job, for doing it by hand.
* The reissue's csr is "in Base64": the PEM request is sent.

Money: a new order is a purchase - only made when "Allow new orders (paid)"
is on. A reissue inside an order whose term runs (expired = the order's end)
is free, and the default at every renewal.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Issued, Plugin, PluginError, field, dual_order_field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers.acme import AcmeIssuer, _seal, _unseal

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

# Every call the modules make, as the OpenAPI names them (checked by the tests).
P_PRODUCTS = '/product/list'
P_ORDERS = '/order/list'
P_ORDER = '/order/certificate/{PRODUCT_CODE}'
P_DETAIL = '/order/order_id/{ORDER_ID}'                     # GET, and PUT (edit before issuance)
P_REISSUE = '/certificate/order_id/{ORDER_ID}/reissue'
P_CANCEL_REISSUE = '/certificate/order_id/{ORDER_ID}/cancel-reissue'
P_REVOKE = '/certificate/order_id/{ORDER_ID}/revoke'
P_RESEND = '/certificate/order_id/{ORDER_ID}/resend'
P_DOWNLOAD = '/certificate/order_id/{ORDER_ID}/format/{FORMAT}'
P_ACME = '/acme'
P_ACME_LIST = '/acme/list'
P_ACME_REVOKE = '/acme/acme_id/{ACME_ID}/revoke'
P_ACME_ORGS = '/acme/organization/list'

DV_METHODS = ('DNS', 'FILE', 'Email')
DCV_MAIL_BOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')
FAILED = ('cancel', 'reject', 'revok', 'denied', 'fail', 'refund', 'storno', 'zamít', 'zamit',
          'zruš', 'zrus', 'odmít', 'odmit')

API_FIELDS = [
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
    """An epoch from a date of the API: epoch, ISO 8601, 'YYYY-MM-DD', 'DD.MM.YYYY'."""
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


def _day(t):
    return time.strftime('%Y-%m-%d', time.gmtime(t)) if t else '?'


def _base(name):
    n = str(name or '').strip().lower().rstrip('.')
    while n.startswith('*.'):
        n = n[2:]
    return n


def _family(key_type):
    return 'rsa' if str(key_type or '').lower().startswith('rsa') else 'ec'


def _csr_family(csr_pem):
    if not csr_pem:
        return None
    try:
        from acmelib.certs import pki
        inf = pki.csr_info(csr_pem)
        return _family(inf.get('key_type') or '')
    except Exception:                                   # noqa: BLE001
        return None


def _certs_in(data):
    """Every certificate in a download: PEM, or PKCS#7 (PEM, base64 or DER)."""
    from acmelib.certs import formats, pki
    if not data:
        return []
    try:
        got = formats.read_any(data if isinstance(data, bytes) else str(data).encode('utf-8'))
    except PluginError:
        return []
    return [pki.cert_pem(c) for c in got.get('certs') or []]


# ---------------------------------------------------------------------------
# The API, as both sources speak it
# ---------------------------------------------------------------------------
class SslmarketApi(object):
    """Calls to SSLmarket's API for a module whose settings hold api / api_url / token."""
    def __init__(self, plugin):
        self.p = plugin
        self.calls = 0

    def base_url(self):
        api = self.p.c('api') or 'cz'
        if api == 'custom':
            url = str(self.p.c('api_url') or '').strip().rstrip('/')
            if not url:
                raise PluginError('set the API address', retry=False)
            if not re.match(r'^https://', url):
                raise PluginError('the API address must be https://…', retry=False)
            return url
        if api not in API_URLS:
            raise PluginError('an unknown SSLmarket: %s' % api, retry=False)
        return API_URLS[api]

    @staticmethod
    def path(template, **fill):
        p = template
        for k, v in fill.items():
            p = p.replace('{%s}' % k, urllib.parse.quote(str(v), safe=''))
        if '{' in p:
            raise ValueError('a path not filled in: %s' % p)
        return p

    def call(self, method, template, body=None, what='', query=None, **fill):
        """(status, JSON or text) of one call; PluginError for what failed."""
        path = self.path(template, **fill)
        token = str(self.p.c('token') or '').strip()
        if not token:
            raise PluginError('set the API key of SSLmarket', retry=False)
        headers = {'X-Auth-Token': token, 'Accept': 'application/json, text/plain, */*',
                   'User-Agent': 'acme certificate manager'}
        data = None
        if body is not None:
            data = json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        url = self.base_url() + path + (('?' + urllib.parse.urlencode(query)) if query else '')
        self.p.ctx.debug('%s %s' % (method, url))
        self.calls += 1
        try:
            status, _hdrs, raw = self.p.ctx.http(method, url, data, headers, 60)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('SSLmarket\'s API does not answer (%s): %s' % (url, e))
        raw = raw or b''
        text = raw.decode('utf-8', 'replace')
        try:
            parsed = json.loads(text) if text.strip()[:1] in ('{', '[') else None
        except ValueError:
            parsed = None
        said = self.message(parsed, text)
        what = what or '%s %s' % (method, path)
        if status in (401, 403):
            raise PluginError('SSLmarket refuses the API key (%d)%s - check the key, and that '
                              '"Account access via API" is on in the account settings'
                              % (status, ': ' + said if said else ''),
                              detail=text[:1000], retry=False)
        if status == 404:
            raise PluginError('SSLmarket does not know %s (404)%s' % (what, ': ' + said if said
                                                                       else ''),
                              detail=text[:1000], retry=False)
        if status == 429 or status >= 500:
            raise PluginError('SSLmarket\'s API is busy or broken (%d)%s - tried again later'
                              % (status, ': ' + said if said else ''), detail=text[:1000],
                              retry=True)
        if status >= 400:
            raise PluginError('SSLmarket refused %s (%d)%s' % (what, status,
                                                              ': ' + said if said else ''),
                              detail=text[:2000], retry=False)
        return status, (parsed if parsed is not None else text)

    @staticmethod
    def message(parsed, text=''):
        """The {message} of an error answer (the OpenAPI's Error), or a short text."""
        if isinstance(parsed, dict):
            m = parsed.get('message')
            if isinstance(m, (list, tuple)):
                m = '; '.join(str(x) for x in m)
            elif isinstance(m, dict):
                m = '; '.join('%s: %s' % kv for kv in m.items())
            if m:
                return str(m)[:500]
            for k in ('error', 'type', 'errors'):
                if parsed.get(k):
                    return str(parsed[k])[:500]
            return ''
        t = re.sub(r'<[^>]+>', ' ', text or '')
        t = re.sub(r'\s+', ' ', t).strip()
        return t[:200]

    # -- the lists ------------------------------------------------------------------
    def products(self):
        _st, got = self.call('GET', P_PRODUCTS, what='the product list')
        return [p for p in ((got or {}).get('products') or []) if isinstance(p, dict)] \
            if isinstance(got, dict) else []

    def orders(self):
        _st, got = self.call('GET', P_ORDERS, what='the order list')
        return [o for o in ((got or {}).get('orders') or []) if isinstance(o, dict)] \
            if isinstance(got, dict) else []

    def acme_keys(self):
        out, page = [], 1
        while page <= 20:
            _st, got = self.call('GET', P_ACME_LIST, what='the ACME keys',
                                 query={'page': page, 'count': 1000})
            items = [a for a in ((got or {}).get('acmes') or []) if isinstance(a, dict)] \
                if isinstance(got, dict) else []
            out.extend(items)
            if len(items) < 1000:
                break
            page += 1
        return out

    def organizations(self):
        _st, got = self.call('GET', P_ACME_ORGS, what='the organisations')
        return [o for o in ((got or {}).get('organizations') or []) if isinstance(o, dict)] \
            if isinstance(got, dict) else []


class _Common(object):
    """What both sources share: the API, the module's state, words in the job."""
    def api(self):
        a = getattr(self, '_api', None)
        if a is None:
            a = self._api = SslmarketApi(self)
        return a

    def base_url(self):
        return self.api().base_url()

    def _say(self, words, level='info'):
        try:
            self.ctx.step(words, level)
        except Exception:                               # noqa: BLE001
            pass

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

    def _say_products(self):
        prods = self.api().products()
        for p in prods:
            self._say('%s - %s (%s, %s%s%s)' % (
                p.get('product_code'), p.get('title') or '?', p.get('type') or
                p.get('product_type') or '?', p.get('validate_type') or '?',
                ', up to %s years' % p['max_years'] if p.get('max_years') else '',
                ', SANs %s-%s' % (p.get('min_san_values') or 0, p['max_san_values'])
                if p.get('max_san_values') else ''))
        self._put('sslmarket-products', {'at': _now(), 'products': prods[:1000]},
                  ttl_s=30 * 86400)
        return prods


# ---------------------------------------------------------------------------
# Orders and reissues
# ---------------------------------------------------------------------------
class SslmarketIssuer(_Common, Issuer):
    kind = 'sslmarket'
    default_name = 'SSLmarket'
    dual_field = 'dual_order'       # a twin is a second order, paid for: only when allowed
    title = 'SSLmarket.cz (DigiCert, Sectigo, GeoTrust…)'
    description = ('Commercial certificates (DigiCert, GeoTrust, Thawte, RapidSSL, Sectigo) '
                   'ordered and reissued through the API of SSLmarket; the DCV record or file '
                   'put in place by the certificate\'s validation. New (paid) orders only when '
                   'allowed; orders waiting for validation are fetched later.')
    vendor = 'SSLmarket'
    doc = 'docs/sslmarket.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    choose_days = False
    # What fits (acmelib/certs/compat.py): a publicly trusted CA; the DCV method of the
    # setting `dcv` and the proof each needs of the certificate's validation - a record
    # or file put in place through base.Challenge.place (acmelib/plugins/issuers/_dcv.py).
    public_names = True
    lists_existing = True           # /order/list + download: Certificates → Import from a source
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    dcv_field = 'dcv'
    dcv_default = 'DNS'
    dcv = {
        'DNS': {'proof': 'txt-any', 'words': 'DNS - a TXT record',
                'record': 'TXT (or CNAME) at the name the CA says, its value'},
        'FILE': {'proof': 'http-file-any', 'words': 'FILE - a file',
                 'record': 'http://NAME/.well-known/pki-validation/FILE holding the CA\'s value'},
        'Email': {'proof': None, 'words': 'E-mail',
                  'record': 'an e-mail to admin@, administrator@, hostmaster@, postmaster@, '
                            'webmaster@ the domain'},
    }
    actions = [
        {'key': 'products', 'label': 'Load the products',
         'help': 'Lists the products (codes, kind, validation, years, SANs) the account can '
                 'order through the API. Orders nothing.', 'changes': False},
        {'key': 'orders', 'label': 'List the orders',
         'help': 'The orders of the account, with their state and end - to find the order to '
                 'reuse. Orders nothing.', 'changes': False},
        {'key': 'resend', 'label': 'Send the DCV e-mail again',
         'help': 'For the orders waiting here (and the order to reuse): the CA writes again to '
                 'admin@, administrator@, hostmaster@, postmaster@ and webmaster@ of the domain.',
         'changes': True},
        {'key': 'cancel_reissue', 'label': 'Cancel the running reissue',
         'help': 'Of the order to reuse: the certificate goes back to Issued, no new one is '
                 'issued.', 'confirm': 'Cancel the reissue running in the order to reuse?',
         'changes': True},
    ]
    fields = API_FIELDS + [
        field('product', 'Product code', 'text', required=True,
              placeholder='a code from "Load the products"',
              help='The product_code of the product to order (the action "Load the products" '
                   'lists those of your account).'),
        field('years', 'Order term (years)', 'select', default='1',
              options=[['1', '1 year'], ['2', '2 years'], ['3', '3 years'], ['4', '4 years'],
                       ['5', '5 years']],
              help='What a new order buys (at most the product\'s max_years). A certificate '
                   'lives at most 200 days (CA/B Forum, since March 2026): a longer order is '
                   'served by reissues, free.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='DNS',
              options=[['DNS', 'DNS - a TXT record (by the certificate\'s DNS validation)'],
                       ['FILE', 'FILE - a file in /.well-known/pki-validation/ (by the '
                                'certificate\'s HTTP validation)'],
                       ['Email', 'E-mail to admin@, administrator@, hostmaster@, postmaster@, '
                                 'webmaster@ of the domain']],
              help='How the CA checks the domain (dv_auth_method). DNS and FILE are done by the '
                   'validation module of the certificate, as for ACME; e-mail needs a person '
                   'to click.'),
        field('owner_name', 'Owner (organisation or person)', 'text', required=True,
              placeholder='Example s.r.o.',
              help='The certificate\'s owner - for OV/EV as in the commercial register.'),
        field('owner_street', 'Street', 'text', required=True),
        field('owner_city', 'City', 'text', required=True),
        field('owner_zip', 'Post code', 'text', required=True),
        field('owner_country', 'Country (2 letters)', 'text', default='CZ', required=True),
        field('owner_tel', 'Owner\'s phone', 'text', required=True, placeholder='+420.123456789',
              help='As +420.123456789 (country code, a dot, the number).'),
        field('contact_title', 'Contact: title', 'text', placeholder='Ing.',
              help='Sent as auth_title and tech_title.'),
        field('contact_first', 'Contact: first name', 'text', required=True),
        field('contact_last', 'Contact: last name', 'text', required=True),
        field('contact_email', 'Contact: e-mail', 'text', required=True,
              placeholder='pki@example.com',
              help='The person who asks for the certificate and its technical contact; the CA '
                   'may call or write to them (OV/EV).'),
        field('contact_tel', 'Contact: phone', 'text', required=True,
              placeholder='+420.123456789'),
        field('invoice_name', 'Invoice: name', 'text',
              help='Empty: the owner\'s name, street, city, post code and country.'),
        field('invoice_street', 'Invoice: street', 'text'),
        field('invoice_city', 'Invoice: city', 'text'),
        field('invoice_zip', 'Invoice: post code', 'text'),
        field('invoice_country', 'Invoice: country', 'text'),
        field('invoice_email', 'Invoice: e-mail', 'text',
              help='Empty: the contact\'s e-mail.'),
        field('invoice_ic', 'Invoice: company ID (IČO)', 'text'),
        field('invoice_dic', 'Invoice: VAT ID (DIČ)', 'text', placeholder='CZ12345678'),
        field('policy', 'At a renewal', 'select', default='reissue',
              options=[['reissue', 'Reissue inside the order while it runs (free); a new order '
                                   'only when paid orders are allowed'],
                       ['new', 'Always a new order (paid)']],
              help='A new order of a commercial certificate costs money; a reissue inside an '
                   'order that still runs does not.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders paid '
                   'already, and stops with words where a purchase would be needed. On: the '
                   'first certificate and an ended order are ordered (and paid from the '
                   'credit) by themselves.'),
        field('order_id', 'Order to reuse', 'text', placeholder='123456',
              help='An order bought already (e.g. in the customer administration): the '
                   'certificate is reissued inside it, or - not issued yet - the request is put '
                   'into it. Empty: the order acme made last for the certificate.'),
        field('order_id_alt', 'Order to reuse for the twin', 'text', advanced=True,
              help='A dual certificate: the order of the second key type (its own order).'),
        field('min_days', 'Reissue while the order runs at least (days)', 'number',
              default=30, advanced=True,
              help='Fewer days left: a new order is needed (when allowed).'),
        field('voucher', 'Discount voucher', 'text', advanced=True),
        field('extra', 'More order fields', 'list', advanced=True,
              placeholder='tech_email=hostmaster@example.cz',
              help='key=value lines added to every new order, for a field of the API this form '
                   'fills otherwise (e.g. another technical contact).'),
        field('txt_label', 'Label of the DNS TXT record', 'text', default='_dnsauth',
              advanced=True,
              help='Where the TXT record goes when dv_auth_content is only the value: '
                   'LABEL.NAME (DigiCert: _dnsauth; @ for NAME itself).'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600, advanced=True,
              help='How long a try waits for the CA (DV: minutes). Longer: the order is asked '
                   'for again at the next try (OV/EV: days).'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=15, advanced=True),
        dual_order_field(),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'Email'    # e-mail DCV: no validation needed
        self._sleep = time.sleep

    @classmethod
    def describe(cls):
        d = Issuer.describe.__func__(cls)
        d.update(needs_challenge=True, challenge_types=list(cls.challenge_types),
                 wildcards=cls.wildcards, ip_names=cls.ip_names, makes_key=False,
                 choose_days=False)
        return d

    # -- settings ------------------------------------------------------------------------
    def product(self):
        p = str(self.c('product') or '').strip()
        if not p:
            raise PluginError('set the product code ("Load the products" lists them)',
                              retry=False)
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

    def _s(self, key):
        return str(self.c(key) or '').strip()

    def order_body(self, req):
        """The body of POST /order/certificate/{PRODUCT_CODE}, every field the OpenAPI
        requires filled."""
        names = list(req.names or [])
        if not names:
            raise PluginError('the certificate has no names', retry=False)
        need = [('owner_name', 'owner'), ('owner_street', 'owner\'s street'),
                ('owner_city', 'owner\'s city'), ('owner_zip', 'owner\'s post code'),
                ('owner_country', 'owner\'s country'), ('owner_tel', 'owner\'s phone'),
                ('contact_first', 'contact\'s first name'), ('contact_last', 'contact\'s last name'),
                ('contact_email', 'contact\'s e-mail'), ('contact_tel', 'contact\'s phone')]
        miss = [w for k, w in need if not self._s(k)]
        if miss:
            raise PluginError('an order needs the %s' % ', '.join(miss), retry=False)
        email = self._s('contact_email')
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            raise PluginError('%s is not an e-mail address' % email, retry=False)
        for k in ('owner_tel', 'contact_tel'):
            if not re.match(r'^\+\d{1,4}\.\d{4,14}$', self._s(k).replace(' ', '')):
                raise PluginError('the phone "%s" is not as SSLmarket wants it: +420.123456789'
                                  % self._s(k), retry=False)
        for k in ('owner_country', 'invoice_country'):
            if self._s(k) and not re.match(r'^[A-Za-z]{2}$', self._s(k)):
                raise PluginError('"%s" is not a two-letter country code' % self._s(k),
                                  retry=False)
        dcv = self.c('dcv') or 'DNS'
        if dcv not in DV_METHODS:
            raise PluginError('an unknown DCV method: %s' % dcv, retry=False)
        title = self._s('contact_title')
        tel = self._s('contact_tel').replace(' ', '')
        body = {
            'domain': names[0], 'years': str(int(_num(self.c('years'), 1) or 1)),
            'csr': req.csr_pem.strip(), 'dv_auth_method': dcv,
            'owner_name': self._s('owner_name'), 'owner_street': self._s('owner_street'),
            'owner_city': self._s('owner_city'), 'owner_zip': self._s('owner_zip'),
            'owner_country': self._s('owner_country').upper(),
            'owner_tel': self._s('owner_tel').replace(' ', ''),
            'auth_title': title, 'auth_firstname': self._s('contact_first'),
            'auth_lastname': self._s('contact_last'), 'auth_tel': tel, 'auth_email': email,
            'tech_title': title, 'tech_firstname': self._s('contact_first'),
            'tech_lastname': self._s('contact_last'), 'tech_tel': tel, 'tech_email': email,
            'invoice_name': self._s('invoice_name') or self._s('owner_name'),
            'invoice_street': self._s('invoice_street') or self._s('owner_street'),
            'invoice_city': self._s('invoice_city') or self._s('owner_city'),
            'invoice_zip': self._s('invoice_zip') or self._s('owner_zip'),
            'invoice_country': (self._s('invoice_country') or self._s('owner_country')).upper(),
            'invoice_email': self._s('invoice_email') or email,
        }
        if len(names) > 1:
            # "An array of domains included as SANs", of type string: joined by commas.
            body['dns_names'] = ','.join(names[1:])
        for k in ('invoice_ic', 'invoice_dic', 'voucher'):
            if self._s(k):
                body[k] = self._s(k)
        body.update(self._extra())
        return body

    def _check_product(self, req):
        """The product against the list kept by "Load the products" (when there is one)."""
        kept = (self._get('sslmarket-products') or {}).get('products') or []
        p = next((x for x in kept if x.get('product_code') == self.product()), None)
        if not kept:
            return None
        if p is None:
            self._say('the product %s is not in the list "Load the products" kept - the order '
                      'is sent all the same' % self.product(), 'warn')
            return None
        years = int(_num(self.c('years'), 1) or 1)
        if p.get('max_years') and years > int(p['max_years']):
            raise PluginError('%s is sold for at most %s years (the order asks %d)'
                              % (self.product(), p['max_years'], years), retry=False)
        sans = len(req.names) - 1
        if p.get('max_san_values') not in (None, '') and sans > int(_num(p['max_san_values'], 0)):
            raise PluginError('%s takes at most %s more names (the certificate has %d)'
                              % (self.product(), p['max_san_values'], sans), retry=False)
        return p

    # -- an order -----------------------------------------------------------------------------
    def detail(self, order_id):
        _st, got = self.api().call('GET', P_DETAIL, what='the order %s' % order_id,
                                   ORDER_ID=order_id)
        if not isinstance(got, dict):
            raise PluginError('SSLmarket sent no detail of order %s' % order_id,
                              detail=str(got)[:500])
        return got

    @staticmethod
    def failed(det):
        st = str(det.get('state') or '').lower()
        return any(w in st for w in FAILED)

    @staticmethod
    def order_end(det):
        return _when(det.get('expired'))

    def _cert_key(self, req):
        base = str(req.cert_id) if getattr(req, 'cert_id', None) else \
            hashlib.sha256(','.join(sorted(req.names or [])).encode()).hexdigest()[:24]
        return '%s:%s' % (base, _family(req.key_type))

    def _follow_children(self, order, det):
        """A renewed order (has_child) is followed to its newest child."""
        seen = {str(order)}
        while det.get('has_child') and det.get('child_id') and str(det['child_id']) not in seen:
            child = str(det['child_id'])
            self._say('the order %s was renewed as %s - that one is used' % (order, child))
            seen.add(child)
            order, det = child, self.detail(child)
        return order, det

    def _given(self, req):
        """The order of the settings for this request: "Order to reuse", or for the
        other key type of a dual certificate "Order to reuse for the twin"."""
        main, alt = self._s('order_id'), self._s('order_id_alt')
        if not alt:
            return main or None
        fam = _family(req.key_type)
        for oid in (main, alt):
            if not oid:
                continue
            try:
                if _csr_family(self.detail(oid).get('csr')) == fam:
                    return oid
            except PluginError:
                continue
        return main or None

    def _choose(self, req, sub_key):
        """('reissue' | 'fill', order_id, detail) or ('new', None, None) - or a
        PluginError where a purchase would be needed and is not allowed."""
        policy = self.c('policy') or 'reissue'
        allowed = _as_bool(self.c('allow_paid'))
        # A certificate imported from this account (Import from a source) names its own
        # order: that one is reissued, whatever "Order to reuse" says.
        given = str(getattr(req, 'ref', None) or '').strip() or self._given(req)
        kept = self._get(sub_key) or {}
        order = given or kept.get('order_id')
        why = ''
        if policy == 'reissue' and order:
            try:
                det = self.detail(order)
            except PluginError as e:
                if given:
                    raise PluginError('the order to reuse, %s, cannot be read: %s' % (order, e),
                                      retry=e.retry)
                det = None
                why = 'the order %s acme made is not known to SSLmarket (%s)' % (order, e)
            if det is not None:
                order, det = self._follow_children(order, det)
                end = self.order_end(det)
                left = (end - _now()) / 86400.0 if end else None
                if self.failed(det):
                    why = 'the order %s is %s' % (order, det.get('state'))
                elif left is not None and left < _num(self.c('min_days'), 30):
                    why = 'the order %s ends %s (%d days)' % (order, _day(end), max(0, int(left)))
                elif not det.get('certificate_serial_number'):
                    self._say('the order %s has no certificate yet (%s): the request is put '
                              'into it - nothing is bought' % (order, det.get('state') or '?'),
                              'ok')
                    return 'fill', order, det
                else:
                    self._say('the order %s is reissued (it runs until %s) - free, nothing is '
                              'bought' % (order, _day(end)), 'ok')
                    return 'reissue', order, det
        elif policy == 'reissue':
            why = 'there is no order to reissue in (set "Order to reuse", or allow a paid order ' \
                  'for the first certificate)'
        else:
            why = 'the policy is a new order at every renewal'
        if not allowed:
            raise PluginError('nothing ordered: %s, and a new order would be a purchase. Paid '
                              'orders are not allowed for this source - switch on "Allow new '
                              'orders (paid)", or buy the order in SSLmarket\'s customer '
                              'administration and set it as "Order to reuse"' % why, retry=False)
        self._say('%s - a new order is made (paid from the account\'s credit: allowed for this '
                  'source)' % (why[:1].upper() + why[1:]), 'warn')
        return 'new', None, None

    def _new_order(self, req):
        product = self.product()
        self._check_product(req)
        body = self.order_body(req)
        try:
            before = {str(o.get('order_id')) for o in self.api().orders()}
        except PluginError as e:
            if not e.retry:
                raise
            before = None
        sent_at = _now()
        st, got = self.api().call('POST', P_ORDER, body, what='the order', PRODUCT_CODE=product)
        oid = got.get('order_id') if isinstance(got, dict) else None
        if not oid:
            # The 201 of the OpenAPI has no body: the order is found in the list.
            oid = self._find_order(req.names[0], product, before, sent_at)
        if not oid:
            raise PluginError('SSLmarket took the order (%d) but it cannot be found in the order '
                              'list - look in the customer administration and set it as "Order '
                              'to reuse" (a second order would be paid again)' % st, retry=False,
                              detail=str(got)[:1000])
        self._say('order %s made at SSLmarket: %s for %s, %s year(s)' % (
            oid, product, ', '.join(req.names), body['years']), 'ok')
        return str(oid)

    def _find_order(self, domain, product, before, sent_at):
        cands = []
        for o in self.api().orders():
            if str(o.get('domain') or '').lower() != domain.lower() or \
                    str(o.get('product_code') or '') != product:
                continue
            if before is not None and str(o.get('order_id')) in before:
                continue
            at = _when(o.get('inserted')) or 0
            if before is None and at and at < sent_at - 86400:
                continue
            cands.append((at, int(_num(o.get('order_id'), 0)), str(o.get('order_id'))))
        return max(cands)[2] if cands else None

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
            _dcv.Placer(self).cleanup(req, held.get('dcv') or [])
            self._waiting(held.get('order_id'), None)
            self._put(slot, None)
            held = None
        if held:
            order_id = str(held['order_id'])
            key_pem = _unseal(self.ctx, held['key'], slot) if held.get('key') else None
            if not key_pem:
                self._put(slot, None)
                raise PluginError('the key of the waiting order %s cannot be opened - it is let '
                                  'go; the next try starts again' % order_id)
            self._say('the order %s (%s) waits at SSLmarket since %s - asked for again, nothing '
                      'is ordered' % (order_id, held.get('how'), time.strftime(
                          '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
            if held.get('dcv'):
                # what went away with the last job (acme's own DNS server) put back
                _dcv.Placer(self).refresh(req, held['dcv'])
        else:
            how, order_id, det = self._choose(req, sub_key)
            key_pem = req.key_pem
            old_serial = ''
            if how == 'reissue':
                old_serial = str(det.get('certificate_serial_number') or '')
                if det.get('reissue_pending'):
                    self._say('a reissue of order %s is running already (not acme\'s) - it is '
                              'cancelled and asked again with this request' % order_id, 'warn')
                    self.api().call('PUT', P_CANCEL_REISSUE, what='the cancelling of the reissue '
                                    'of order %s' % order_id, ORDER_ID=order_id)
                self.api().call('POST', P_REISSUE, {'csr': req.csr_pem.strip()},
                                what='the reissue of order %s' % order_id, ORDER_ID=order_id)
                self._say('reissue of order %s asked for' % order_id, 'ok')
            elif how == 'fill':
                edit = {'csr': req.csr_pem.strip(), 'dv_auth_method': self.c('dcv') or 'DNS'}
                self.api().call('PUT', P_DETAIL, edit, what='the editing of order %s' % order_id,
                                ORDER_ID=order_id)
                self._say('the request and the DCV method (%s) put into order %s'
                          % (edit['dv_auth_method'], order_id), 'ok')
            else:
                order_id = self._new_order(req)
            self._put(sub_key, {'order_id': order_id, 'product': self.c('product'), 'at': _now()})
            held = {'order_id': order_id, 'how': how, 'at': _now(), 'names': list(req.names),
                    'key': _seal(self.ctx, key_pem, slot), 'old_serial': old_serial, 'dcv': [],
                    'placed': False}
            # Kept at once: whatever happens next, the order is not bought twice.
            self._put(slot, held, ttl_s=120 * 86400)
            self._waiting(order_id, req.names)
        if not held.get('placed'):
            self._dcv(req, slot, held, order_id)
        return self._await(req, slot, held, order_id, key_pem)

    def _waiting(self, order_id, names):
        """The orders waiting here, for the actions (resend)."""
        w = self._get('sslmarket-waiting') or {}
        if names:
            w[str(order_id)] = {'names': list(names), 'at': _now()}
        else:
            w.pop(str(order_id), None)
        self._put('sslmarket-waiting', w or None, ttl_s=120 * 86400)

    # -- DCV -------------------------------------------------------------------------------
    def _dcv(self, req, slot, held, order_id):
        """The DCV of the order put in place (once per order)."""
        method = self.c('dcv') or 'DNS'
        if method == 'Email':
            boxes = sorted({'%s@%s' % (b, _base(n)) for n in req.names for b in DCV_MAIL_BOXES})
            self._say('DCV by e-mail: the CA writes to %s - somebody has to confirm it ("Send '
                      'the DCV e-mail again" sends it once more)' % ', '.join(boxes))
            held['placed'] = True
            self._put(slot, held, ttl_s=120 * 86400)
            return
        content, det = None, None
        end = _now() + min(120.0, _num(self.c('wait_issue'), 600))
        while True:
            det = self.detail(order_id)
            content = str(det.get('dv_auth_content') or '').strip()
            if content or self.failed(det) or det.get('certificate_serial_number') and \
                    held.get('how') != 'reissue' or _now() >= end or self.ctx.cancelled():
                break
            self._sleep(min(10.0, max(1.0, end - _now())))
        if not content:
            self._say('SSLmarket said no dv_auth_content for order %s yet (%s) - asked again at '
                      'the next try' % (order_id, det.get('state') if det else '?'), 'warn')
            return
        if det.get('dv_auth_method') and det['dv_auth_method'] != method:
            self._say('the order %s is validated by %s, not %s as set here - its own method is '
                      'used' % (order_id, det['dv_auth_method'], method), 'warn')
            method = det['dv_auth_method']
        self._say('SSLmarket\'s DCV for order %s (%s): %s' % (order_id, method, content[:500]))
        recs = self.dcv_records(content, method, req.names)
        placer = _dcv.Placer(self)
        held['dcv'] = placer.place_all(req, recs)
        held['placed'] = True
        self._put(slot, held, ttl_s=120 * 86400)
        if held['dcv']:
            placer.wait_visible(req, held['dcv'])

    def dcv_records(self, content, method, names):
        """[{'domain', 'type': 'txt'|'cname'|'file', 'fqdn'|'path', 'value'}] out of
        dv_auth_content - its format is not specified, so read in the shapes it may have:
        JSON, record lines ("NAME [TTL] [IN] TXT VALUE"), a URL and the file's content,
        or a bare value (for every name of the certificate)."""
        text = str(content or '').strip()
        bases = []
        for n in names:
            b = _base(n)
            if b and b not in bases:
                bases.append(b)
        try:
            j = json.loads(text) if text[:1] in ('{', '[') else None
        except ValueError:
            j = None
        if isinstance(j, dict):
            j = [j]
        if isinstance(j, list):
            out = []
            for it in j:
                if not isinstance(it, dict):
                    continue
                low = {str(k).lower(): v for k, v in it.items()}
                value = low.get('value') or low.get('token') or low.get('content') or \
                    low.get('txt') or low.get('hash')
                where = low.get('name') or low.get('host') or low.get('record') or \
                    low.get('path') or low.get('url') or low.get('file')
                if value:
                    line = ('%s %s' % (where, value)) if where else str(value)
                    out.extend(self.dcv_records(line if method == 'FILE' else
                                                ('%s TXT %s' % (where, value) if where else value),
                                                method, [low.get('domain') or n for n in names]
                                                if low.get('domain') else names))
            return out
        if method == 'FILE':
            url = re.search(r'(https?://[^\s"\']+)', text)
            path, body = None, text
            if url:
                u = urllib.parse.urlsplit(url.group(1))
                path = u.path
                body = (text[:url.start()] + text[url.end():]).strip()
                hosts = [_base(u.hostname)] if u.hostname else bases
            else:
                m = re.match(r'^(/?\.well-known/\S+|/\S+\.txt)\s+(.+)$', text, re.S)
                if m:
                    path, body = m.group(1), m.group(2).strip()
                hosts = bases
            if not path:
                path = '/.well-known/pki-validation/fileauth.txt'
            if not path.startswith('/'):
                path = '/' + path
            return [{'domain': h, 'type': 'file', 'path': path, 'value': body.strip('"')}
                    for h in hosts]
        out = []
        for line in [ln.strip() for ln in text.splitlines() if ln.strip()]:
            m = re.match(r'^(\S+?)\.?\s+(?:\d+\s+)?(?:IN\s+)?(TXT|CNAME)\s+"?(.+?)"?\s*$', line, re.I)
            if m:
                fqdn, rtype, value = m.group(1).lower(), m.group(2).lower(), m.group(3).strip()
                dom = next((b for b in sorted(bases, key=len, reverse=True)
                            if fqdn == b or fqdn.endswith('.' + b)), None)
                if dom is None:
                    dom = bases[0] if bases else _base(fqdn)
                    fqdn = '%s.%s' % (fqdn, dom) if fqdn not in ('@',) else dom
                out.append({'domain': dom, 'type': rtype, 'fqdn': fqdn,
                            'value': value.rstrip('.') if rtype == 'cname' else value})
        if out:
            return out
        if not re.match(r'^\S+$', text):
            return []           # words acme cannot read: shown in the job, done by hand
        label = self._s('txt_label').strip('.')
        return [{'domain': b, 'type': 'txt',
                 'fqdn': '%s.%s' % (label, b) if label and label != '@' else b, 'value': text}
                for b in bases]

    # -- waiting, downloading -------------------------------------------------------------------
    def _done(self, det, held):
        """Whether the order's certificate is there for this request."""
        serial = str(det.get('certificate_serial_number') or '')
        if not serial or det.get('reissue_pending'):
            return False
        if held.get('how') == 'reissue' and serial == str(held.get('old_serial') or ''):
            return False
        return True

    def _await(self, req, slot, held, order_id, key_pem):
        end = _now() + _num(self.c('wait_issue'), 600)
        every = max(1.0, _num(self.c('poll_every'), 15))
        while True:
            det = self.detail(order_id)
            if self.failed(det):
                _dcv.Placer(self).cleanup(req, held.get('dcv') or [])
                self._waiting(order_id, None)
                self._put(slot, None)
                raise PluginError('SSLmarket: the order %s is %s' % (order_id, det.get('state')),
                                  retry=False)
            if self._done(det, held):
                out = self.download(order_id, key_pem, held.get('how') == 'reissue')
                if out is not None:
                    _dcv.Placer(self).cleanup(req, held.get('dcv') or [])
                    self._waiting(order_id, None)
                    self._put(slot, None)
                    if key_pem.strip() != (req.key_pem or '').strip():
                        out.key_pem = key_pem   # the key the waiting order was made with
                    return out
            if not held.get('placed'):
                self._dcv(req, slot, held, order_id)
            if self.ctx.cancelled():
                raise PluginError('stopped', retry=False)
            if _now() >= end:
                more = ''
                if self.c('dcv') == 'Email':
                    more = ' (the CA\'s e-mail to admin@, hostmaster@… of the domain has to be ' \
                           'confirmed; "Send the DCV e-mail again" sends it once more)'
                elif any(p.get('how') == 'manual' for p in held.get('dcv') or []):
                    more = ' (the DCV record said in the job has to be put in place by hand)'
                raise PluginError('the order %s waits at SSLmarket (%s%s)%s; acme asks for the '
                                  'certificate again at the next try - nothing is ordered again '
                                  '(OV/EV: the CA checks the organisation, it may take days)' % (
                                      order_id, det.get('state') or 'no state said',
                                      ', reissue running' if det.get('reissue_pending') else '',
                                      more), retry=True)
            self._say('order %s: %s - asked again in %d s' % (order_id, det.get('state') or '?',
                                                              int(every)))
            self._sleep(min(every, max(1.0, end - _now())))
            every = min(every * 1.5, 120.0)

    def _fetch(self, order_id, fmt):
        _st, got = self.api().call('GET', P_DOWNLOAD, what='the certificate of order %s (%s)'
                                   % (order_id, fmt), ORDER_ID=order_id, FORMAT=fmt)
        if isinstance(got, (dict, list)):
            got = json.dumps(got)
        return got

    def download(self, order_id, key_pem, reissue=False):
        """Issued, or None when the order still has the certificate of before (a reissue
        that is not through)."""
        from acmelib.certs import pki
        leafs = _certs_in(self._fetch(order_id, 'pem_server'))
        if not leafs:
            raise PluginError('SSLmarket sent no certificate for order %s' % order_id)
        leaf = next((c for c in leafs if pki.key_matches(c, key_pem)), None)
        if not leaf:
            if reissue:
                self._say('the certificate of order %s is still the one before the reissue' %
                          order_id)
                return None
            raise PluginError('the certificate of order %s is for another key than this request '
                              '(reissued meanwhile in the administration?) - it is not used'
                              % order_id, retry=False)
        others = [c for c in leafs if c != leaf]
        try:
            others += _certs_in(self._fetch(order_id, 'pem_intermediate'))
        except PluginError as e:
            self._say('the intermediate certificates could not be read (%s) - from the PKCS#7'
                      % e, 'warn')
        if not others:
            try:
                others = [c for c in _certs_in(self._fetch(order_id, 'p7b')) if c != leaf]
            except PluginError:
                pass
        chain = pki.order_chain(leaf, others) or others
        info = pki.cert_info(leaf)
        self._say('the certificate came: order %s, serial %s, until %s' % (
            order_id, info.get('serial') or '?', _day(info.get('not_after'))), 'ok')
        try:
            self._put('sslmarket-serial:%s' % pki.norm_serial(info.get('serial') or '')[:80],
                      {'order_id': order_id}, ttl_s=5 * 366 * 86400)
        except Exception:                               # noqa: BLE001
            pass
        return Issued(leaf, chain, info={'order_id': order_id, 'api': self.base_url(),
                                         'ref': order_id})

    # -- revocation, trying it, the actions ------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        from acmelib.certs import pki
        info = pki.cert_info(cert_pem)
        kept = self._get('sslmarket-serial:%s' % pki.norm_serial(info.get('serial') or '')[:80])
        order_id = (kept or {}).get('order_id') or self._s('order_id')
        if not order_id:
            raise PluginError('the order of this certificate is not known to acme - revoke it in '
                              'SSLmarket\'s customer administration', retry=False)
        try:
            self.api().call('PUT', P_REVOKE, what='the revocation of order %s' % order_id,
                            ORDER_ID=order_id)
        except PluginError as e:
            raise PluginError('%s - SSLmarket\'s API revokes only DigiCert Client Premium '
                              '(Class 1 and 2) certificates; a TLS certificate is revoked in the '
                              'customer administration (or by the CA\'s support)' % e,
                              detail=e.detail, retry=False)
        self._say('SSLmarket revokes the certificate of order %s (%s)' % (order_id, reason), 'ok')
        return 'revocation of order %s asked for' % order_id

    def test(self):
        prods = self.api().products()
        bits = ['signed in to %s' % self.base_url(), '%d products' % len(prods)]
        code = self.product()
        p = next((x for x in prods if x.get('product_code') == code), None)
        if p is None:
            bits.append('the product %s is NOT among them ("Load the products" lists the codes)'
                        % code)
        else:
            bits.append('the product %s is offered (%s, %s)' % (code, p.get('title') or '?',
                                                                 p.get('validate_type') or '?'))
        bits.append('%d orders' % len(self.api().orders()))
        bits.append('new paid orders %s' % ('ALLOWED' if _as_bool(self.c('allow_paid'))
                                            else 'not allowed (reissues only)'))
        return '; '.join(bits)

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['api', 'api_url', 'token']

    def discover_setup(self):
        """Read-only: the products of the account (the product to order), its orders (one
        to reuse - never picked by itself) and, from the last order's detail, its owner,
        contact and invoice data and its DCV method; with no order, the organisation of
        the account (/acme/organization/list)."""
        out = Plugin.discover_setup(self)
        api = self.api()
        prods = api.products()
        out['facts'].append(['Products', str(len(prods))])
        opts = []
        for p in prods:
            code = str(p.get('product_code') or '').strip()
            if code:
                opts.append([code, '%s (%s%s)' % (p.get('title') or code, p.get('validate_type')
                                                  or p.get('type') or '?',
                                                  ', up to %s years' % p['max_years']
                                                  if p.get('max_years') else '')])
        self.offer(out, 'product', opts)
        try:
            orders = api.orders()
            out['facts'].append(['Orders', str(len(orders))])
        except PluginError as e:
            orders = []
            out['notes'].append('the orders could not be read: %s' % e)
        live = []
        for o in orders:
            oid = str(o.get('order_id') or '').strip()
            if oid and not self.failed(o):
                end = _when(o.get('expired'))
                live.append((oid, o, end))
        live.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=True)
        runs = [x for x in live if not x[2] or x[2] > _now()]
        if runs:
            self.offer(out, 'order_id', [['', 'Empty: the order acme made last for the '
                                               'certificate']] + [
                [oid, '%s · %s%s' % (o.get('domain') or '?', o.get('product_code') or '?',
                                     ' · until %s' % _day(end) if end else '')]
                for oid, o, end in runs[:300]], pick='')
        det = None
        for oid, _o, _end in live[:3]:
            try:
                det = self.detail(oid)
                out['facts'].append(['Contacts taken from the order', oid])
                break
            except PluginError as e:
                out['notes'].append('the order %s could not be read: %s' % (oid, e))
        sets = out['sets']
        if det:
            for k in ('owner_name', 'owner_street', 'owner_city', 'owner_zip', 'owner_country',
                      'owner_tel', 'invoice_name', 'invoice_street', 'invoice_city',
                      'invoice_zip', 'invoice_country', 'invoice_email', 'invoice_ic',
                      'invoice_dic'):
                if str(det.get(k) or '').strip():
                    sets[k] = str(det[k]).strip()
            for mine, theirs in (('contact_title', 'title'), ('contact_first', 'firstname'),
                                 ('contact_last', 'lastname'), ('contact_email', 'email'),
                                 ('contact_tel', 'tel')):
                v = det.get('tech_' + theirs) or det.get('auth_' + theirs)
                if str(v or '').strip():
                    sets[mine] = str(v).strip()
            if str(det.get('dv_auth_method') or '') in DV_METHODS:
                sets['dcv'] = str(det['dv_auth_method'])
        else:
            try:
                orgs = [o for o in api.organizations() if str(o.get('status') or 'active') ==
                        'active']
            except PluginError as e:
                orgs = []
                out['notes'].append('the organisations could not be read: %s' % e)
            if orgs:
                o = orgs[0]
                out['facts'].append(['Contacts taken from the organisation',
                                     str(o.get('name') or o.get('organization_id') or '?')])
                for mine, theirs in (('owner_name', 'name'), ('owner_street', 'street'),
                                     ('owner_city', 'city'), ('owner_zip', 'zip'),
                                     ('owner_country', 'country'), ('owner_tel', 'tel')):
                    if str(o.get(theirs) or '').strip():
                        sets[mine] = str(o[theirs]).strip()
                cs = o.get('contacts')
                cs = cs if isinstance(cs, list) else [cs] if isinstance(cs, dict) else []
                c = next((x for x in cs if isinstance(x, dict) and x.get('email')), None)
                if c:
                    for mine, theirs in (('contact_first', 'first_name'),
                                         ('contact_last', 'last_name'),
                                         ('contact_email', 'email'), ('contact_tel', 'tel')):
                        if str(c.get(theirs) or '').strip():
                            sets[mine] = str(c[theirs]).strip()
            elif not orders:
                out['notes'].append('the account has no order and no organisation yet: the '
                                    'owner and the contact are set by hand')
        if sets.get('owner_country'):
            sets['owner_country'] = sets['owner_country'].upper()[:2]
        return out

    # -- the orders of the account (Certificates → Import from a source) ---------------------
    def _acme_ids(self):
        """{order id: acme's certificate id} of the orders acme made or reissued here."""
        out = {}
        try:
            kept = self.ctx.kv_keys('sslmarket-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            if isinstance(v, str):
                try:
                    v = json.loads(v)
                except ValueError:
                    continue
            cid = k.split(':')[1] if k.count(':') >= 2 else ''
            if isinstance(v, dict) and v.get('order_id') and cid.isdigit():
                out[str(v['order_id'])] = int(cid)
        return out

    def list_existing(self):
        """Every order of the account (/order/list) - read only."""
        mine = self._acme_ids()
        out = []
        for o in self.api().orders():
            oid = str(o.get('order_id') or '').strip()
            if not oid:
                continue
            names = [str(o.get('domain') or '').strip()] + [
                x.strip() for x in re.split(r'[\s,;]+', str(o.get('dns_names') or ''))
                if x.strip()]
            names = [n for i, n in enumerate(names) if n and n not in names[:i]]
            end = _when(o.get('expired'))
            failed = self.failed(o)
            issued = bool(_when(o.get('published'))) and not failed
            note = ''
            if failed:
                note = 'the order is %s' % (o.get('state') or '?')
            elif not issued:
                note = 'the order has no certificate yet (%s)' % (o.get('state') or '?')
            out.append({'ref': oid, 'cn': names[0] if names else '', 'names': names,
                        'product': str(o.get('product_code') or ''),
                        'status': str(o.get('state') or ''),
                        'not_before': _when(o.get('published')), 'not_after': None,
                        'paid_until': end, 'downloadable': issued,
                        'renewable': 'reissue' if issued and (not end or end > _now())
                        else 'order', 'note': note, 'acme_cert_id': mine.get(oid)})
        return out

    def fetch_existing(self, ref):
        """The certificate of order `ref` and its chain (…/format/pem_server and
        pem_intermediate) - read only."""
        from acmelib.certs import pki
        oid = str(ref or '').strip()
        if not re.match(r'^\d{1,20}$', oid):
            raise PluginError('%s is not an order number' % (oid or '?'), retry=False)
        pems = _certs_in(self._fetch(oid, 'pem_server'))
        leafs = [c for c in pems if not pki.cert_info(c).get('is_ca')]
        if not leafs:
            raise PluginError('SSLmarket sent no certificate for order %s (not issued yet?)'
                              % oid, retry=False)
        leaf = max(leafs, key=lambda c: pki.cert_info(c).get('not_before') or 0)
        others = [c for c in pems if c != leaf]
        try:
            others += _certs_in(self._fetch(oid, 'pem_intermediate'))
        except PluginError as e:
            self._say('the intermediate certificates could not be read (%s)' % e, 'warn')
        chain = pki.order_chain(leaf, others) or [c for c in others
                                                  if pki.cert_info(c).get('is_ca')]
        return {'cert_pem': leaf, 'chain_pems': [c for c in chain if c.strip() != leaf.strip()],
                'ref': oid, 'acme_cert_id': self._acme_ids().get(oid)}

    def _orders_to_act_on(self):
        out = [self._s('order_id')] if self._s('order_id') else []
        out += [k for k in (self._get('sslmarket-waiting') or {}) if k not in out]
        return out

    def action(self, key):
        if key == 'products':
            prods = self._say_products()
            return '%d products; put the code under Product code' % len(prods)
        if key == 'orders':
            items = self.api().orders()
            for o in items[:300]:
                self._say('order %s: %s%s, %s, %s year(s), %s, inserted %s, ends %s' % (
                    o.get('order_id') or '?', o.get('domain') or '?',
                    ' + %s' % o['dns_names'] if o.get('dns_names') else '',
                    o.get('product_code') or '?', o.get('years') or '?', o.get('state') or '?',
                    o.get('inserted') or '?', o.get('expired') or '?'))
            return '%d orders' % len(items)
        if key == 'resend':
            todo = self._orders_to_act_on()
            if not todo:
                raise PluginError('no order is waiting here, and no order to reuse is set',
                                  retry=False)
            for oid in todo:
                self.api().call('PUT', P_RESEND, what='the DCV e-mail of order %s' % oid,
                                ORDER_ID=oid)
                self._say('the DCV e-mail of order %s sent again' % oid, 'ok')
            return 'DCV e-mail sent again for order %s' % ', '.join(todo)
        if key == 'cancel_reissue':
            oid = self._s('order_id')
            if not oid:
                raise PluginError('set the order to reuse first', retry=False)
            self.api().call('PUT', P_CANCEL_REISSUE, what='the cancelling of the reissue of order '
                            '%s' % oid, ORDER_ID=oid)
            return 'the reissue of order %s cancelled' % oid
        return Issuer.action(self, key)


# ---------------------------------------------------------------------------
# ACME with a key made through the API
# ---------------------------------------------------------------------------
_ACME_OWN = ('directory', 'directory_url', 'eab_kid', 'eab_hmac')


class SslmarketAcmeIssuer(_Common, AcmeIssuer):
    kind = 'sslmarket_acme'
    default_name = 'SSLmarket ACME'
    title = 'SSLmarket ACME (DigiCert, EAB made through the API)'
    description = ('An ACME key made at SSLmarket through its API (directory URL and EAB), then '
                   'every certificate ordered by ACME and each name proved by DNS-01 or HTTP-01 '
                   '- renewals with no order and no DCV of SSLmarket\'s.')
    vendor = 'SSLmarket'
    doc = 'docs/sslmarket.md'
    actions = [
        {'key': 'acme_keys', 'label': 'Load the ACME keys',
         'help': 'The ACME keys of the account (name, product, validity, state).',
         'changes': False},
        {'key': 'organizations', 'label': 'Load the organisations',
         'help': 'The organisations ACME may use, with their validations - the id goes in '
                 '"Organisation" (OV/EV products).', 'changes': False},
        {'key': 'make_key', 'label': 'Make an ACME key',
         'help': 'A new ACME key of these settings at SSLmarket, kept for this source (the one '
                 'before stays active until revoked).', 'changes': True},
        {'key': 'revoke_key', 'label': 'Revoke the ACME key',
         'help': 'The key this source uses is revoked at SSLmarket: no certificate can be '
                 'issued with it any more.', 'confirm': 'Revoke the ACME key at SSLmarket? '
                                                        'Certificates of it stay valid.',
         'changes': True},
    ]
    fields = API_FIELDS + [
        field('acme_product', 'ACME product code', 'text', required=True,
              placeholder='a product code of an ACME product',
              help='The product_code of an ACME-enabled product (SSLmarket\'s offer, "Load the '
                   'ACME keys" shows those of keys made before).'),
        field('acme_name', 'Name of the ACME key', 'text', default='acme',
              help='The key is made under this name, and found again by it.'),
        field('validity_days', 'Certificate validity (days)', 'number', default=199,
              help='1-199 - each certificate of the key is issued for this long.'),
        field('organization_id', 'Organisation', 'text', placeholder='12345',
              help='The organisation_id ("Load the organisations") - for products that '
                   'validate the organisation (OV/EV).'),
        field('make_key', 'Make the ACME key when there is none', 'bool', default=True,
              help='Off: only a key made before (with "Make an ACME key", or its EAB pasted '
                   'below) is used.'),
        field('given_kid', 'EAB key id of a key made elsewhere', 'text', advanced=True,
              help='A key made in the customer administration: its EAB key id and HMAC (shown '
                   'once at its making); its directory URL is found by its name.'),
        field('given_hmac', 'EAB HMAC of a key made elsewhere', 'secret', advanced=True),
    ] + [f for f in AcmeIssuer.fields if f['key'] not in _ACME_OWN]

    public_names = True             # SSLmarket's ACME: a public CA (its directory is its own)

    @classmethod
    def public_for(cls, config):
        return True

    @classmethod
    def key_types_for(cls, config):
        return list(AcmeIssuer.key_types)

    def __init__(self, config, ctx):
        AcmeIssuer.__init__(self, config, ctx)
        self._cred = None

    @classmethod
    def describe(cls):
        d = AcmeIssuer.describe.__func__(cls)
        d.update(needs_challenge=True, challenge_types=list(cls.challenge_types),
                 wildcards=cls.wildcards, ip_names=cls.ip_names)
        return d

    # -- what the ACME code reads -------------------------------------------------------
    def c(self, key, default=None):
        if key == 'directory':
            return 'custom'
        if key in ('directory_url', 'eab_kid', 'eab_hmac'):
            cred = self.credentials()
            return {'directory_url': cred['url'], 'eab_kid': cred['kid'],
                    'eab_hmac': cred['hmac']}[key]
        return AcmeIssuer.c(self, key, default)

    def _settings(self):
        product = str(AcmeIssuer.c(self, 'acme_product') or '').strip()
        if not product:
            raise PluginError('set the ACME product code', retry=False)
        name = str(AcmeIssuer.c(self, 'acme_name') or 'acme').strip()
        days = int(_num(AcmeIssuer.c(self, 'validity_days'), 199))
        if not 1 <= days <= 199:
            raise PluginError('the validity must be 1-199 days (it is %d)' % days, retry=False)
        org = str(AcmeIssuer.c(self, 'organization_id') or '').strip()
        if org and not org.isdigit():
            raise PluginError('the organisation is its number ("Load the organisations")',
                              retry=False)
        return product, name, days, (int(org) if org else None)

    def _slot(self):
        product, name, days, org = self._settings()
        h = hashlib.sha256(json.dumps([self.base_url(), product, name, days, org]).encode())
        return 'sslmarket-acme:%s' % h.hexdigest()[:32]

    def credentials(self, fresh=False):
        """{'acme_id', 'url', 'kid', 'hmac'} of the ACME key: kept, pasted, or made."""
        if self._cred and not fresh:
            return self._cred
        slot = self._slot()
        row = None if fresh else self._get(slot)
        if row and row.get('hmac'):
            hmac = _unseal(self.ctx, row['hmac'], slot)
            if hmac:
                self._cred = dict(row, hmac=hmac)
                return self._cred
        product, name, days, org = self._settings()
        kid = str(AcmeIssuer.c(self, 'given_kid') or '').strip()
        mac = str(AcmeIssuer.c(self, 'given_hmac') or '').strip()
        if kid and mac and not fresh:
            keys = [a for a in self.api().acme_keys() if a.get('name') == name and
                    str(a.get('status') or '').lower() == 'active']
            if not keys:
                raise PluginError('there is no active ACME key named "%s" at SSLmarket for the '
                                  'EAB given' % name, retry=False)
            a = max(keys, key=lambda x: _when(x.get('inserted')) or 0)
            return self._keep(slot, a.get('acme_id'), a.get('acme_directory_url'), kid, mac,
                              'pasted')
        if not _as_bool(AcmeIssuer.c(self, 'make_key')) and not fresh:
            raise PluginError('there is no ACME key for this source - "Make an ACME key", or '
                              'switch on "Make the ACME key when there is none"', retry=False)
        if not fresh:
            known = [a for a in self.api().acme_keys() if a.get('name') == name and
                     str(a.get('status') or '').lower() == 'active']
            if known:
                self._say('SSLmarket has an active ACME key "%s" (%s), but its EAB is shown only '
                          'when it is made - a new key is made' % (
                              name, ', '.join(str(a.get('acme_id')) for a in known)), 'warn')
        body = {'product_code': product, 'name': name, 'certificate_validity_days': days}
        if org is not None:
            body['organization_id'] = org
        _st, got = self.api().call('POST', P_ACME, body, what='the making of an ACME key')
        if not isinstance(got, dict) or not (got.get('acme_directory_url') and
                                             got.get('ext_act_kid') and got.get('ext_act_hmac')):
            raise PluginError('SSLmarket made no usable ACME key (no directory URL or EAB in '
                              'the answer)', detail=str(got)[:1000], retry=False)
        if str(got.get('status') or 'active').lower() != 'active':
            raise PluginError('SSLmarket\'s new ACME key %s is %s' % (got.get('acme_id'),
                                                                     got.get('status')),
                              retry=False)
        self._say('ACME key %s made at SSLmarket ("%s", %s, %d days%s): %s' % (
            got.get('acme_id'), name, product, days, ', organisation %s' % org if org else '',
            got['acme_directory_url']), 'ok')
        return self._keep(slot, got.get('acme_id'), got['acme_directory_url'],
                          got['ext_act_kid'], got['ext_act_hmac'], 'made')

    def _keep(self, slot, acme_id, url, kid, hmac, how):
        if not url:
            raise PluginError('SSLmarket gave no ACME directory URL', retry=False)
        row = {'acme_id': acme_id, 'url': url, 'kid': kid, 'at': _now(), 'how': how}
        self._put(slot, dict(row, hmac=_seal(self.ctx, hmac, slot)))
        self._cred = dict(row, hmac=hmac)
        return self._cred

    # -- trying it, the actions --------------------------------------------------------------
    # -- discovery (1.0.29) -------------------------------------------------------------------
    discover_keys = ['api', 'api_url', 'token']

    def discover_setup(self):
        """Read-only: the ACME keys of the account (one found again by its name - its
        product, validity and organisation with it), the products, the organisations."""
        out = Plugin.discover_setup(self)
        api = self.api()
        keys = [k for k in api.acme_keys() if str(k.get('status') or 'active') == 'active']
        out['facts'].append(['ACME keys', str(len(keys))])
        if keys:
            sets = {}
            for k in keys:
                more = {}
                if k.get('product_code'):
                    more['acme_product'] = str(k['product_code'])
                if k.get('certificate_validity_days'):
                    more['validity_days'] = int(k['certificate_validity_days'])
                if k.get('organization_id'):
                    more['organization_id'] = str(k['organization_id'])
                if k.get('name'):
                    sets[str(k['name'])] = more
            self.offer(out, 'acme_name', [[str(k['name']), '%s · %s' % (
                k['name'], k.get('product_code') or '?')] for k in keys if k.get('name')],
                sets)
        prods = api.products()
        self.offer(out, 'acme_product', [[str(p['product_code']), '%s (%s)' % (
            p.get('title') or p['product_code'], p.get('validate_type') or p.get('type') or '?')]
            for p in prods if p.get('product_code')])
        try:
            orgs = api.organizations()
        except PluginError as e:
            orgs = []
            out['notes'].append('the organisations could not be read: %s' % e)
        if orgs:
            self.offer(out, 'organization_id', [['', 'None (a DV product)']] + [
                [str(o['organization_id']), '%s%s' % (o.get('name') or o['organization_id'],
                                                      '' if str(o.get('status') or 'active') ==
                                                      'active' else ' (inactive)')]
                for o in orgs if o.get('organization_id')])
        return out

    def test(self):
        product, name, days, org = self._settings()
        bits = ['signed in to %s' % self.base_url()]
        keys = self.api().acme_keys()
        row = self._get(self._slot())
        if row:
            mine = next((a for a in keys if str(a.get('acme_id')) == str(row.get('acme_id'))), None)
            if mine is not None and str(mine.get('status')).lower() != 'active':
                raise PluginError('the ACME key %s of this source is %s at SSLmarket - "Make an '
                                  'ACME key"' % (row.get('acme_id'), mine.get('status')),
                                  retry=False)
            bits.append('ACME key %s (%s)' % (row.get('acme_id'), row.get('url')))
            bits.append(AcmeIssuer.test(self))
        else:
            bits.append('%d ACME keys; none kept for this source yet - it is made at the first '
                        'certificate (or with "Make an ACME key")' % len(keys))
        return '; '.join(bits)

    def action(self, key):
        if key == 'acme_keys':
            keys = self.api().acme_keys()
            for a in keys:
                self._say('ACME key %s "%s": %s, %s, %s days%s, %s, made %s' % (
                    a.get('acme_id'), a.get('name'), a.get('status'), a.get('product_code'),
                    a.get('certificate_validity_days') or '?',
                    ', organisation %s' % a['organization_id'] if a.get('organization_id') else '',
                    a.get('acme_directory_url'), a.get('inserted')))
            return '%d ACME keys' % len(keys)
        if key == 'organizations':
            orgs = self.api().organizations()
            for o in orgs:
                vals = ', '.join('%s %s%s' % (v.get('type'), v.get('status'),
                                              ' until %s' % v['valid_till'] if v.get('valid_till')
                                              else '') for v in o.get('validations') or [])
                self._say('organisation %s: %s (%s, %s) - %s' % (
                    o.get('organization_id'), o.get('name'), o.get('status'),
                    o.get('country') or '?', vals or 'no validations'))
            return '%d organisations' % len(orgs)
        if key == 'make_key':
            cred = self.credentials(fresh=True)
            return 'ACME key %s made: %s' % (cred.get('acme_id'), cred.get('url'))
        if key == 'revoke_key':
            slot = self._slot()
            row = self._get(slot)
            if not row or not row.get('acme_id'):
                raise PluginError('this source keeps no ACME key', retry=False)
            _st, got = self.api().call('PUT', P_ACME_REVOKE, what='the revocation of ACME key %s'
                                       % row['acme_id'], ACME_ID=row['acme_id'])
            self._put(slot, None)
            self._cred = None
            return 'ACME key %s: %s' % (row['acme_id'], (got or {}).get('status', 'revoked')
                                        if isinstance(got, dict) else 'revoked')
        return AcmeIssuer.action(self, key)
