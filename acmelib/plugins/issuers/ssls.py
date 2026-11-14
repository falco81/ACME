# -*- coding: utf-8 -*-
"""
Commercial certificates (AlpiroSSL, Sectigo, PositiveSSL, Certum, GeoTrust,
DigiCert, Thawte, RapidSSL…) from SSLS.cz - the Czech reseller of ZONER a.s.
(www.ssls.cz) - through its API "SAPI" v2 (SAPI v2.3.3, the PDF and the PHP
client SSLS.cz hands out; the tests check every call against it).

The API as SSLS.cz describes it:

* https://api.ssls.cz/v2/{method}/ - the method's name case-sensitive (csrGen,
  not csrgen); HTTPS only;
* every request a POST "in the form of an array" - the PHP client sends
  http_build_query(): application/x-www-form-urlencoded, nested values as
  dcv[method]=dns, admin[firstname]=…, san[0]=…;
* the parameter `token` in every request (the account's API settings make it,
  with the list of IPv4 addresses the API may be used from); `accountDetail`
  = true adds the account's state (its credit) to any answer;
* JSON back; a request with a mistake has `errors` {isError, errorCode,
  errorMessage} and is not done ("1002 Invalid token");
* at most 60 requests a minute and 2000 an hour - over them the API is blocked
  for 15 minutes, then 60, then a day: acme asks certStatus every
  `poll_every` seconds at the least (30 by default), more slowly as it waits.

The methods used here, and when:

    allProducts    the form's product list ("Load the list"), Try it (with
                   accountDetail: the credit), the action "Load the products"
    servers        the form's list of server types for the product (optional)
    emails         DCV by e-mail: the approver address of each domain, picked
                   from those SSLS.cz offers for the product and domain
    newOrder       a new order (orderType new) or a renewal (orderType renew) -
                   paid from the credit: only with "Allow new orders (paid)" on
    quickReissue   a free reissue inside the subscription, with the new CSR
    certStatus     the state of the certificate (P, A, R, C, U, N, E), its end
                   (NVA) and the end of its subscription (SNVA)
    getCert        the certificate and the intermediate certificates
    myCerts        the action "List the certificates", and Import from a source
                   (list_existing: every certificate of the account)

What the documentation leaves open, and how it is read here:

* allProducts: its answer has no documented shape. Every object that holds a
  productCode is taken for a product, wherever it is in the answer (a list, or
  grouped by the certification authority); its name, authority, validation
  level, longest period and SAN count are read from the keys that say so.
* The DCV record or file is given only in the answer of newOrder and
  quickReissue (certStatus says only the method): kept with the waiting order
  at once, put in place by the certificate's own validation (_dcv.Placer).
* dnsAuth: for a CNAME (AlpiroSSL, Sectigo, PositiveSSL) the whole record
  ("_1234.ssls.cz CNAME 678.abc.A123.sectigo.com"); Sectigo's label is made of
  the CSR alone, so the same label and target are put under every domain of
  the certificate. For a TXT (Certum) only the code: it goes at the domain
  itself (a setting: "Label of the TXT record").
* fileAuth: the file http://DOMAIN/.well-known/pki-validation/NAME for every
  domain of the certificate.
* dcv.emails: "for each SAN domain, in the order of san.n" - the approver of
  the common name goes in dcv.email, those of the other names in dcv.emails.
* quickReissue cannot change the names, and Certum is never reissued: then a
  new order is needed (when allowed). Certum is never renewed as orderType
  renew either (the documentation says so).
* The end of a subscription is SNVA (0 for a certificate without one: then
  the certificate's own end, NVA).

Money: newOrder is a purchase - only made when "Allow new orders (paid)" is
on. A reissue inside a subscription that runs is free, and the default.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Issued, PluginError, field, dual_order_field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers.acme import _seal, _unseal

API_URL = 'https://api.ssls.cz/v2'

# Every method used, as SAPI names them (case-sensitive).
M_PRODUCTS = 'allProducts'
M_SERVERS = 'servers'
M_EMAILS = 'emails'
M_ORDER = 'newOrder'
M_REISSUE = 'quickReissue'
M_STATUS = 'certStatus'
M_GET = 'getCert'
M_MINE = 'myCerts'

DCV_METHODS = ('dns', 'file', 'email')
MAILBOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')
ISSUED = ('A', 'R')                 # active; reissued and active
WAITING = ('P', 'U', 'N')           # being validated / not known yet / not activated yet
GONE = ('C', 'E')                   # cancelled, revoked, refused; expired
STATUS_WORDS = {
    'P': 'being validated or issued', 'A': 'issued and active', 'R': 'reissued and active',
    'C': 'revoked, cancelled or refused', 'U': 'not known yet (still in the queue)',
    'N': 'not activated yet or not paid', 'E': 'expired',
}


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


def _day(t):
    return time.strftime('%Y-%m-%d', time.gmtime(t)) if t else '?'


def _base(name):
    n = str(name or '').strip().lower().rstrip('.')
    while n.startswith('*.'):
        n = n[2:]
    return n


def _family(key_type):
    return 'rsa' if str(key_type or '').lower().startswith('rsa') else 'ec'


def _certs_in(data):
    """Every certificate in a text: PEM (one or more), or PKCS#7."""
    from acmelib.certs import formats, pki
    if not data:
        return []
    try:
        got = formats.read_any(data if isinstance(data, bytes) else str(data).encode('utf-8'))
    except PluginError:
        return []
    return [pki.cert_pem(c) for c in got.get('certs') or []]


def form_encode(params):
    """PHP's http_build_query(): nested values as a[b]=c, lists as a[0]=c."""
    out = []

    def walk(prefix, v):
        if isinstance(v, dict):
            for k, x in v.items():
                walk('%s[%s]' % (prefix, k) if prefix else str(k), x)
        elif isinstance(v, (list, tuple)):
            for i, x in enumerate(v):
                walk('%s[%d]' % (prefix, i), x)
        elif v is None:
            return
        else:
            if isinstance(v, bool):
                v = 'true' if v else 'false'
            out.append((prefix, str(v)))
    walk('', params)
    return urllib.parse.urlencode(out)


# ---------------------------------------------------------------------------
# The catalog: allProducts read whatever its shape
# ---------------------------------------------------------------------------
def _low(d):
    return {str(k).lower(): v for k, v in d.items()} if isinstance(d, dict) else {}


def _pick(low, *keys):
    for k in keys:
        v = low.get(k.lower())
        if v not in (None, '', [], {}):
            return v
    return None


def _level(*texts):
    for t in texts:
        s = str(t or '').upper()
        for lv in ('EV', 'OV', 'DV'):
            if re.search(r'(^|[^A-Z])%s([^A-Z]|$)' % lv, s):
                return lv
        if 'EXTENDED' in s:
            return 'EV'
        if 'ORGANI' in s:
            return 'OV'
        if 'DOMAIN' in s:
            return 'DV'
    return ''


def _years(low):
    v = _pick(low, 'maxPeriod', 'periodMax', 'maxYears', 'years', 'maxSubscription')
    if v is not None and str(v).strip().isdigit():
        return int(str(v).strip())
    # prices for each period (price1 … price5, 1y … 5y, price.1 …): the longest offered
    best = 0
    for k, v in low.items():
        m = re.match(r'^(?:price|cena)[_\-]?(\d)(?:y|yr|years?|let|roky)?$', k) or \
            re.match(r'^(\d)(?:y|yr|years?|let|roky)$', k)
        if m and v not in (None, '', 0, '0', False):
            best = max(best, int(m.group(1)))
    for k in ('price', 'prices', 'ceny'):
        if isinstance(low.get(k), dict):
            for pk, pv in low[k].items():
                m = re.match(r'^\D*(\d)\D*$', str(pk))
                if m and pv not in (None, '', 0, '0', False):
                    best = max(best, int(m.group(1)))
    return best or None


def products_of(answer):
    """[{code, name, ca, level, years, sans, wildcard, price}] of an allProducts
    answer - every object holding a productCode, its authority from the object or
    from the group it is in."""
    out, seen = [], set()

    def walk(node, group):
        if isinstance(node, list):
            for x in node:
                walk(x, group)
            return
        if not isinstance(node, dict):
            return
        low = _low(node)
        code = _pick(low, 'productCode', 'product_code')
        if code is not None and not isinstance(code, (dict, list)):
            code = str(code).strip()
            if code and code not in seen:
                seen.add(code)
                name = str(_pick(low, 'productName', 'name', 'title', 'product') or code)
                ca = str(_pick(low, 'brand', 'vendor', 'ca', 'authority', 'certificateAuthority',
                               'certAuthority', 'issuer', 'manufacturer', 'znacka') or group or '')
                level = _level(_pick(low, 'validation', 'validationType', 'validationLevel',
                                     'level', 'type', 'productType'), name)
                sans = _pick(low, 'maxSan', 'maxSans', 'maxSAN', 'maxDomains', 'sanMax', 'domains')
                wild = _pick(low, 'isWildcard', 'wildcard')
                out.append({'code': code, 'name': name, 'ca': ca, 'level': level,
                            'years': _years(low),
                            'sans': int(str(sans).strip()) if sans is not None and
                            str(sans).strip().isdigit() else None,
                            'wildcard': _as_bool(wild) if wild is not None else
                            ('wildcard' in name.lower()),
                            'price': _pick(low, 'price1', 'price', 'cena')
                            if not isinstance(_pick(low, 'price1', 'price', 'cena'), dict)
                            else None})
                return
        for k, v in node.items():
            if str(k).lower() in ('auth', 'errors', 'account', 'accountdetail'):
                continue
            walk(v, group if isinstance(node.get(k), (dict, list)) and str(k).isdigit()
                 else (str(k) if isinstance(v, (dict, list)) and str(k).lower() not in
                       ('products', 'allproducts', 'items', 'list', 'data', 'certificates')
                       else group))
    walk(answer, '')
    return out


def is_certum(ca='', code='', name=''):
    return 'certum' in ('%s %s %s' % (ca, code, name)).lower() or str(code).strip() == 'commercial'


def needs_org(p):
    """Whether a product needs the organisation's details: OV, EV, and every Certum."""
    return p.get('level') in ('OV', 'EV') or is_certum(p.get('ca'), p.get('code'), p.get('name'))


def credit_of(answer):
    """The credit of the account, where an answer with accountDetail says it."""
    found = []

    def walk(node, depth):
        if depth > 6:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if 'credit' in str(k).lower() or 'kredit' in str(k).lower():
                    if isinstance(v, (int, float, str)) and str(v).strip():
                        found.append(str(v).strip())
                        continue
                walk(v, depth + 1)
        elif isinstance(node, list):
            for x in node:
                walk(x, depth + 1)
    walk(answer, 0)
    return found[0] if found else None


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------
class SslsApi(object):
    """Calls to SAPI v2 for the module whose settings hold the token."""
    def __init__(self, plugin):
        self.p = plugin
        self.calls = 0

    def token(self):
        t = str(self.p.c('token') or '').strip()
        if not t:
            raise PluginError('set the API token of SSLS.cz', retry=False)
        return t

    def hide(self, text):
        """The token never in words or details."""
        t = str(self.p.c('token') or '').strip()
        s = str(text or '')
        return s.replace(t, '•' * 8) if len(t) >= 4 else s

    def call(self, method, params=None, what=''):
        """The JSON answer of one method; PluginError (in words) for what failed."""
        body = dict(params or {})
        body['token'] = self.token()
        url = '%s/%s/' % (API_URL, method)
        what = what or method
        self.p.ctx.debug('POST %s' % url)
        self.calls += 1
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json', 'User-Agent': 'acme certificate manager'}
        try:
            status, _h, raw = self.p.ctx.http('POST', url, form_encode(body).encode('utf-8'),
                                              headers, 100)
        except PluginError as e:
            raise PluginError(self.hide(str(e)), detail=self.hide(e.detail), retry=e.retry)
        except Exception as e:                          # noqa: BLE001
            raise PluginError('the API of SSLS.cz does not answer: %s' % self.hide(e))
        text = (raw or b'').decode('utf-8', 'replace')
        try:
            got = json.loads(text) if text.strip()[:1] in ('{', '[') else None
        except ValueError:
            got = None
        detail = self.hide(text[:2000])
        errs = got.get('errors') if isinstance(got, dict) else None
        if isinstance(errs, dict) and (errs.get('isError') or errs.get('errorCode') or
                                       errs.get('errorMessage')):
            self.refused(what, errs, detail)
        if status == 429 or status >= 500:
            raise PluginError('the API of SSLS.cz is busy or broken (HTTP %d) - tried again later'
                              % status, detail=detail, retry=True)
        if status >= 400:
            raise PluginError('SSLS.cz refused %s (HTTP %d)' % (what, status), detail=detail,
                              retry=status in (408, 425))
        if not isinstance(got, dict):
            raise PluginError('SSLS.cz answered %s with something that is not JSON' % what,
                              detail=detail)
        return got

    def refused(self, what, errs, detail):
        code = str(errs.get('errorCode') or '').strip()
        msg = self.hide(str(errs.get('errorMessage') or '').strip())[:400] or '?'
        low = msg.lower()
        if code == '1002' or 'token' in low:
            raise PluginError('SSLS.cz refuses the API token (%s) - check it in the account\'s '
                              'API settings at www.ssls.cz, where the API must be switched on'
                              % msg, detail=detail, retry=False)
        if re.search(r'\bip\b|ip address|ip adres|ipv4|adresa ip|z této ip|not allowed from',
                     low):
            raise PluginError('SSLS.cz does not allow the API from this server\'s address (%s) '
                              '- add the public IPv4 address acme reaches the internet from to '
                              'the allowed addresses in the account\'s API settings' % msg,
                              detail=detail, retry=False)
        if re.search(r'rate limit|limit (?:of|for) (?:requests|queries)|too many (?:requests|'
                     r'queries|calls)|počet dotaz|blocked|zablokov|blokov', low):
            raise PluginError('SSLS.cz blocks the API for a while: too many requests (%s) - '
                              'tried again later' % msg, detail=detail, retry=True)
        if re.search(r'credit|kredit|insufficient|nedostate', low):
            raise PluginError('SSLS.cz did not take %s: not enough credit in the account (%s)'
                              % (what, msg), detail=detail, retry=False)
        raise PluginError('SSLS.cz refused %s: %s (error %s)' % (what, msg, code or '?'),
                          detail=detail, retry=False)

    # -- the reads -------------------------------------------------------------------
    def products(self, account=False):
        got = self.call(M_PRODUCTS, {'accountDetail': 'true'} if account else None,
                        what='the product list')
        return products_of(got), got

    def servers(self, product):
        got = self.call(M_SERVERS, {'productCode': product}, what='the server types')
        s = got.get('servers')
        if isinstance(s, dict):
            return [(str(k), str(v)) for k, v in s.items()]
        if isinstance(s, list):
            out = []
            for x in s:
                low = _low(x)
                if low:
                    out.append((str(_pick(low, 'name', 'server') or '?'),
                                str(_pick(low, 'code', 'id', 'value') or '')))
            return out
        return []

    def emails(self, product, domain):
        got = self.call(M_EMAILS, {'productCode': product, 'domain': domain},
                        what='the approver addresses of %s' % domain)
        e = got.get('emails')
        return [str(x) for x in e if x] if isinstance(e, list) else \
            [x for x in re.split(r'[\s,;]+', str(e or '')) if '@' in x]

    def status(self, cert_id):
        got = self.call(M_STATUS, {'certID': cert_id}, what='the state of certificate %s'
                        % cert_id)
        st = got.get('status')
        if not isinstance(st, dict):
            raise PluginError('SSLS.cz said no state of certificate %s' % cert_id,
                              detail=self.hide(json.dumps(got)[:1000]))
        return st

    def mine(self):
        got = self.call(M_MINE, what='the certificates of the account')
        m = got.get('myCerts')
        if isinstance(m, dict):
            m = list(m.values())
        return [x for x in (m or []) if isinstance(x, dict)]


# ---------------------------------------------------------------------------
# The source
# ---------------------------------------------------------------------------
def _catalog_field(key, label, catalog, **more):
    """A choice from a list the module fetches (base.py: the type `catalog`)."""
    return field(key, label, 'catalog', catalog=catalog, **more)


ORG_SHOWN = {'needs_org': [True]}


class SslsIssuer(Issuer):
    kind = 'ssls'
    default_name = 'SSLS.cz'
    dual_field = 'dual_order'       # a twin is a second order, paid for: only when allowed
    title = 'SSLS.cz (AlpiroSSL, Sectigo, Certum…)'
    description = ('Commercial certificates (AlpiroSSL, Sectigo, PositiveSSL, Certum, GeoTrust, '
                   'DigiCert…) ordered and reissued through the API of SSLS.cz; the DCV record '
                   'or file put in place by the certificate\'s validation. New (paid) orders '
                   'only when allowed; certificates waiting for validation are fetched later.')
    vendor = 'SSLS.cz'
    doc = 'docs/ssls.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    choose_days = False
    public_names = True
    lists_existing = True           # myCerts + getCert: Certificates → Import from a source
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    dcv_field = 'dcv'
    dcv_default = 'dns'
    dcv = {
        'dns': {'proof': 'cname-any', 'words': 'DNS - a CNAME record (a TXT record for Certum)',
                'record': 'CNAME _LABEL.NAME to the target the CA says (Certum: TXT at NAME)'},
        'file': {'proof': 'http-file-any', 'words': 'FILE - a file',
                 'record': 'http://NAME/.well-known/pki-validation/FILE holding the CA\'s value'},
        'email': {'proof': None, 'words': 'E-mail',
                  'record': 'an e-mail to an approver address of the domain (admin@, '
                            'hostmaster@…)'},
    }
    actions = [
        {'key': 'products', 'label': 'Load the products',
         'help': 'Lists the certificates the account can order through the API (code, '
                 'authority, validation, years). Orders nothing.', 'changes': False},
        {'key': 'certs', 'label': 'List the certificates',
         'help': 'The certificates of the account (SSLS ID, state, end, subscription) - to find '
                 'the one to reuse. Orders nothing.', 'changes': False},
        {'key': 'status', 'label': 'State of the waiting certificates',
         'help': 'certStatus of the certificate to reuse and of those waiting here. Orders '
                 'nothing.', 'changes': False},
    ]
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='At www.ssls.cz: My account → API settings (API nastavení) - switch the API '
                   'on, make the token, and add the public IPv4 address(es) acme reaches the '
                   'internet from (several separated by spaces). Sent in every request as the '
                   'parameter token, never in the address.'),
        _catalog_field('product', 'Product', 'products', required=True, depends=['token'],
                       help='Load the list (SSLS.cz is asked with the token above - nothing is '
                            'ordered) and pick the certificate. Its validation and authority '
                            'are filled in under More by themselves.'),
        field('period', 'Subscription (years)', 'select', default='1',
              options=[['1', '1 year'], ['2', '2 years'], ['3', '3 years'], ['4', '4 years'],
                       ['5', '5 years']],
              help='What a new order buys (the parameter period; 2-5 years only where the '
                   'product sells them). A certificate lives at most 200 days (CA/B Forum, '
                   'since March 2026): a longer subscription is served by free reissues.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='dns',
              options=[['dns', 'DNS - a CNAME record (Certum: TXT) by the certificate\'s DNS '
                                'validation'],
                       ['file', 'FILE - a file in /.well-known/pki-validation/ (by the '
                                 'certificate\'s HTTP validation)'],
                       ['email', 'E-mail to an approver address of the domain']],
              help='How the CA checks the domain (dcv.method). DNS and FILE are put in place by '
                   'the validation module of the certificate, as for ACME, and taken away '
                   'after; e-mail needs a person to click. FILE and DNS: AlpiroSSL, Sectigo, '
                   'PositiveSSL and Certum only.'),
        field('approver', 'Approver mailbox', 'select', default='admin',
              options=[['admin', 'admin@'], ['administrator', 'administrator@'],
                       ['hostmaster', 'hostmaster@'], ['postmaster', 'postmaster@'],
                       ['webmaster', 'webmaster@'], ['first', 'the first address SSLS.cz '
                                                              'offers']],
              show_if={'dcv': ['email']},
              help='For each domain the address is picked from those SSLS.cz offers for the '
                   'product and the domain (the method emails): this mailbox at the domain '
                   'itself, else at the domain above it, else the first offered.'),
        field('admin_first', 'Contact: first name', 'text', required=True,
              help='The person who asks for the certificate (admin.*, also the technical '
                   'contact) - every order needs them.'),
        field('admin_last', 'Contact: last name', 'text', required=True),
        field('admin_email', 'Contact: e-mail', 'text', required=True,
              placeholder='pki@example.com'),
        field('admin_phone', 'Contact: phone', 'text', required=True,
              placeholder='00420123456789',
              help='International, digits only: 00 instead of +, no spaces (00420123456789). '
                   'For OV/EV best the organisation\'s number a public register shows.'),
        field('admin_country', 'Contact: country (2 letters)', 'text', default='CZ',
              required=True),
        field('needs_org', 'The product needs the organisation\'s details', 'bool',
              default=False,
              help='OV and EV certificates and every Certum one. Set by itself when a product '
                   'is picked from the list.'),
        field('org_name', 'Organisation', 'text', show_if=ORG_SHOWN,
              placeholder='Example s.r.o.', help='As in the commercial register (admin.'
                                                 'organization).'),
        field('org_city', 'Organisation: city', 'text', show_if=ORG_SHOWN),
        field('org_street', 'Organisation: street', 'text', show_if=ORG_SHOWN,
              placeholder='Ulice 123/45'),
        field('org_postalcode', 'Organisation: post code', 'text', show_if=ORG_SHOWN),
        field('org_phone', 'Organisation: phone', 'text', show_if=ORG_SHOWN,
              placeholder='00420123456789', help='Empty: the contact\'s phone.'),
        field('org_business_id', 'Organisation: company ID (IČO)', 'text', show_if=ORG_SHOWN,
              help='IČ or DIČ - Certum OV/EV needs it.'),
        field('org_duns', 'Organisation: D-U-N-S number', 'text', show_if=ORG_SHOWN,
              help='Not needed, but it makes the CA\'s check of the organisation much faster.'),
        field('org_email', 'Organisation: e-mail', 'text', show_if=ORG_SHOWN,
              help='Certum only, and only where the request (CSR) holds no e-mail - acme\'s '
                   'requests hold none: give it for Certum.'),
        field('policy', 'At a renewal', 'select', default='reissue',
              options=[['reissue', 'Reissue inside the subscription while it runs (free); a '
                                   'new order only when paid orders are allowed'],
                       ['new', 'Always a new order (paid)']],
              help='A new order costs money; a reissue (quickReissue) inside a subscription '
                   'that still runs does not. Certum is never reissued, and a reissue cannot '
                   'change the names.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside certificates paid '
                   'already, and stops with words where a purchase would be needed. On: the '
                   'first certificate and an ended subscription are ordered (and paid from '
                   'the credit) by themselves.'),
        field('cert_reuse', 'Certificate to reuse (SSLS ID)', 'text', placeholder='1234567890',
              help='A certificate bought already (e.g. at www.ssls.cz): it is reissued with '
                   'acme\'s request. Empty: the certificate acme ordered last for this one. '
                   '"List the certificates" shows the IDs.'),
        field('cert_reuse_alt', 'Certificate to reuse for the twin', 'text', advanced=True,
              help='A dual certificate: the SSLS ID of the second key type (its own order).'),
        field('product_manual', 'Product code typed', 'text', advanced=True,
              placeholder='positive',
              help='Only where the list cannot be loaded here: the productCode, used instead of '
                   'Product.'),
        field('product_level', 'Validation of the product', 'select', advanced=True,
              default='', options=[['', 'not known'], ['DV', 'DV - the domain'],
                                   ['OV', 'OV - the organisation'],
                                   ['EV', 'EV - extended validation']],
              help='Set by itself when a product is picked from the list.'),
        field('product_ca', 'Authority of the product', 'text', advanced=True,
              placeholder='Sectigo',
              help='Set by itself when a product is picked from the list. Certum: a TXT record '
                   'for DNS, never a reissue.'),
        _catalog_field('server', 'Server type', 'servers', advanced=True, depends=['product'],
                       help='Where the certificate is installed (the parameter server). Not '
                            'needed: the certificate comes as PEM all the same; empty is '
                            'Apache+OpenSSL.'),
        field('order_type', 'A new order for a certificate that had one', 'select',
              default='auto', advanced=True,
              options=[['auto', 'a renewal (orderType renew), Certum a new one'],
                       ['new', 'always a new one (orderType new)']],
              help='A renewal may carry the days left over into the new certificate.'),
        field('dns_record', 'DNS record the CA asks for', 'select', default='auto',
              advanced=True, options=[['auto', 'by the product: Certum TXT, the others CNAME'],
                                      ['cname', 'CNAME'], ['txt', 'TXT']],
              help='What the validation of the certificate must be able to put in place.'),
        field('txt_label', 'Label of the DNS TXT record', 'text', default='@', advanced=True,
              help='Where a TXT code goes (Certum): @ is the name itself, else LABEL.NAME.'),
        field('min_days', 'Reissue while the subscription runs at least (days)', 'number',
              default=30, advanced=True,
              help='Fewer days left: a new order is needed (when allowed).'),
        field('extra', 'More order fields', 'list', advanced=True,
              placeholder='tech[email]=hostmaster@example.cz',
              help='key=value lines added to every new order, for a parameter of newOrder this '
                   'form does not fill (tech[...], org[fax]...).'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=900,
              advanced=True,
              help='How long a try waits for the CA (DV: minutes). Longer: the certificate is '
                   'asked for again at the next try (OV/EV: days).'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=30, advanced=True,
              help='At least 30 s: SSLS.cz blocks the API for 15 minutes over 60 requests a '
                   'minute or 2000 an hour.'),
        dual_order_field(),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep
        self._api = None

    @classmethod
    def describe(cls):
        d = Issuer.describe.__func__(cls)
        d.update(needs_challenge=True, challenge_types=list(cls.challenge_types),
                 wildcards=cls.wildcards, ip_names=cls.ip_names, makes_key=False,
                 choose_days=False)
        return d

    # -- what fits (acmelib/certs/compat.py) ---------------------------------------------
    @classmethod
    def dns_type(cls, config):
        config = config or {}
        t = str(config.get('dns_record') or 'auto')
        if t in ('cname', 'txt'):
            return t
        code = str(config.get('product_manual') or config.get('product') or '')
        return 'txt' if is_certum(config.get('product_ca') or '', code) else 'cname'

    @classmethod
    def proofs_for(cls, config):
        if cls.dcv_method(config) == 'dns':
            return ['txt-any' if cls.dns_type(config) == 'txt' else 'cname-any']
        return Issuer.proofs_for.__func__(cls, config)

    @classmethod
    def dcv_where(cls, config, name, proof):
        bare = _base(name)
        if proof == 'txt-any':
            label = str((config or {}).get('txt_label') or '@').strip('.')
            return bare if label in ('', '@') else '%s.%s' % (label, bare)
        return Issuer.dcv_where.__func__(cls, config, name, proof)

    # -- settings ---------------------------------------------------------------------------
    def api(self):
        if self._api is None:
            self._api = SslsApi(self)
        return self._api

    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _say(self, words, level='info'):
        try:
            self.ctx.step(self.api().hide(words), level)
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

    def product(self):
        p = self._s('product_manual') or self._s('product')
        if not p:
            raise PluginError('pick the product (Product → Load the list)', retry=False)
        return p

    def certum(self):
        return is_certum(self._s('product_ca'), self.product())

    def method(self):
        m = self._s('dcv') or 'dns'
        if m not in DCV_METHODS:
            raise PluginError('an unknown DCV method: %s' % m, retry=False)
        return m

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

    # -- the form's lists (base.py: a field of the type catalog) ----------------------------
    def catalog(self, key):
        """{'options': [[value, words]], 'sets': {value: {field: value}}, 'said'} of the
        list a field picks from - read-only."""
        if key == 'products':
            prods, got = self.api().products(account=True)
            prods = sorted(prods, key=lambda p: (p['ca'].lower(), p['level'], p['name'].lower()))
            opts, sets = [], {}
            for p in prods:
                bits = [x for x in (p['ca'], p['level']) if x]
                if p['years']:
                    bits.append('%d y' % p['years'])
                opts.append([p['code'], '%s%s' % (p['name'], ' (%s)' % ', '.join(bits)
                                                   if bits else '')])
                sets[p['code']] = {'product_level': p['level'], 'product_ca': p['ca'],
                                   'needs_org': needs_org(p)}
            credit = credit_of(got)
            said = '%d products' % len(prods)
            if credit is not None:
                said = '%d products; credit %s' % (len(prods), credit)
            return {'options': opts, 'sets': sets, 'said': said}
        if key == 'servers':
            byc = {}
            for name, code in self.api().servers(self.product()):
                byc.setdefault(code, []).append(name)
            opts = [[c, ', '.join(n)] for c, n in byc.items() if c != '']
            return {'options': opts, 'said': '%d server types' % len(opts)}
        raise PluginError('there is no list called %s here' % key, retry=False)

    # -- the order ----------------------------------------------------------------------------
    def _need(self):
        need = [('admin_first', 'contact\'s first name'), ('admin_last', 'contact\'s last name'),
                ('admin_email', 'contact\'s e-mail'), ('admin_phone', 'contact\'s phone'),
                ('admin_country', 'contact\'s country')]
        if _as_bool(self.c('needs_org')):
            need += [('org_name', 'organisation'), ('org_city', 'organisation\'s city'),
                     ('org_street', 'organisation\'s street'),
                     ('org_postalcode', 'organisation\'s post code')]
            if self.certum() and self._s('product_level') in ('OV', 'EV'):
                need.append(('org_business_id', 'organisation\'s company ID'))
            if self.certum():
                need.append(('org_email', 'organisation\'s e-mail'))
        miss = [w for k, w in need if not self._s(k)]
        if miss:
            raise PluginError('an order needs the %s' % ', '.join(miss), retry=False)
        email = self._s('admin_email')
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            raise PluginError('%s is not an e-mail address' % email, retry=False)
        for k in ('admin_phone', 'org_phone'):
            v = self._s(k).replace(' ', '')
            if v and not re.match(r'^00\d{6,16}$', v):
                raise PluginError('the phone "%s" is not as SSLS.cz wants it: 00420123456789 '
                                  '(00 instead of +, digits only)' % self._s(k), retry=False)
        if not re.match(r'^[A-Za-z]{2}$', self._s('admin_country')):
            raise PluginError('"%s" is not a two-letter country code' % self._s('admin_country'),
                              retry=False)

    def approvers(self, names):
        """{base domain: address} for DCV by e-mail, each picked from `emails`."""
        box = self._s('approver') or 'admin'
        out = {}
        for n in names:
            b = _base(n)
            if b in out:
                continue
            offered = self.api().emails(self.product(), b)
            if not offered:
                raise PluginError('SSLS.cz offers no approver address for %s (product %s) - '
                                  'choose DNS or FILE validation' % (b, self.product()),
                                  retry=False)
            pick = None
            if box != 'first':
                low = [x.lower() for x in offered]
                parts = b.split('.')
                for i in range(len(parts) - 1):
                    want = '%s@%s' % (box, '.'.join(parts[i:]))
                    if want in low:
                        pick = offered[low.index(want)]
                        break
                if pick is None:
                    self._say('%s@ is not among the approver addresses SSLS.cz offers for %s - '
                              'the first one is used' % (box, b), 'warn')
            out[b] = pick or offered[0]
        return out

    def order_params(self, req, order_type='new'):
        """The parameters of newOrder (the documentation's table)."""
        names = list(req.names or [])
        if not names:
            raise PluginError('the certificate has no names', retry=False)
        self._need()
        method = self.method()
        p = {'productCode': self.product(), 'csr': req.csr_pem.strip(),
             'period': str(int(_num(self.c('period'), 1) or 1)),
             'dcv': {'method': method},
             'admin': {'firstname': self._s('admin_first'), 'lastname': self._s('admin_last'),
                       'phone': self._s('admin_phone').replace(' ', ''),
                       'email': self._s('admin_email'),
                       'country': self._s('admin_country').upper()}}
        if order_type == 'renew':
            p['orderType'] = 'renew'
        sans = names[1:]
        if sans:
            p['san'] = sans
        if self._s('server'):
            p['server'] = self._s('server')
        if method == 'email':
            ap = self.approvers(names)
            p['dcv']['email'] = ap[_base(names[0])]
            if sans:
                p['dcv']['emails'] = ','.join(ap[_base(n)] for n in sans)
        if _as_bool(self.c('needs_org')):
            p['admin']['organization'] = self._s('org_name')
            p['admin']['city'] = self._s('org_city')
            org = {'street': self._s('org_street'), 'postalcode': self._s('org_postalcode')}
            for k, key in (('phone', 'org_phone'), ('businessId', 'org_business_id'),
                           ('duns', 'org_duns'), ('email', 'org_email')):
                if self._s(key):
                    org[k] = self._s(key).replace(' ', '') if k == 'phone' else self._s(key)
            p['org'] = org
        for k, v in self._extra().items():
            m = re.match(r'^(\w+)\[(\w+)\]$', k) or re.match(r'^(\w+)\.(\w+)$', k)
            if m:
                p.setdefault(m.group(1), {})
                if isinstance(p[m.group(1)], dict):
                    p[m.group(1)][m.group(2)] = v
            else:
                p[k] = v
        return p

    def _check_product(self, req):
        """The product against the catalog (when it can be read): years, SANs, wildcards."""
        try:
            prods, _got = self.api().products()
        except PluginError as e:
            if not e.retry:
                raise
            return None
        p = next((x for x in prods if x['code'] == self.product()), None)
        if p is None:
            if prods:
                raise PluginError('SSLS.cz does not offer the product %s (any more) - pick one '
                                  'from the list' % self.product(), retry=False)
            return None
        years = int(_num(self.c('period'), 1) or 1)
        if p.get('years') and years > p['years']:
            raise PluginError('%s is sold for at most %d years (the order asks %d)'
                              % (self.product(), p['years'], years), retry=False)
        if p.get('sans') is not None and len(req.names) - 1 > p['sans']:
            raise PluginError('%s takes at most %d more names (the certificate has %d)'
                              % (self.product(), p['sans'], len(req.names) - 1), retry=False)
        return p

    def _cert_key(self, req):
        base = str(req.cert_id) if getattr(req, 'cert_id', None) else \
            hashlib.sha256(','.join(sorted(req.names or [])).encode()).hexdigest()[:24]
        return '%s:%s' % (base, _family(req.key_type))

    def _given(self, req):
        """The certificate of the settings for this request ("Certificate to reuse", or
        the twin's for the other key type of a dual certificate)."""
        main, alt = self._s('cert_reuse'), self._s('cert_reuse_alt')
        if not alt:
            return main or None
        from acmelib.certs import pki
        fam = _family(req.key_type)
        for cid in (main, alt):
            if not cid:
                continue
            try:
                got = self.api().call(M_GET, {'certID': cid}, what='the certificate %s' % cid)
                items = got.get('certificates') or []
                first = items[0].get('Contents') if items and isinstance(items[0], dict) else ''
                leaf = (_certs_in(first) or [None])[0]
                if leaf and _family(pki.cert_info(leaf).get('key_type') or '') == fam:
                    return cid
            except (PluginError, ValueError, IndexError, AttributeError):
                continue
        return main or None

    @staticmethod
    def sub_end(st):
        """The end of what was paid: the subscription (SNVA), else the certificate (NVA)."""
        for k in ('SNVA', 'NVA'):
            v = _num(st.get(k), 0)
            if v > 0:
                return v
        return None

    def _choose(self, req, sub_key):
        """('reissue', cert_id, status) or ('new' | 'renew', previous cert_id, status) - or a
        PluginError where a purchase would be needed and is not allowed."""
        policy = self.c('policy') or 'reissue'
        allowed = _as_bool(self.c('allow_paid'))
        # A certificate imported from this account (Import from a source) names its own
        # SSLS ID: that one is reissued, whatever "Certificate to reuse" says.
        given = str(getattr(req, 'ref', None) or '').strip() or self._given(req)
        kept = self._get(sub_key) or {}
        cert = given or kept.get('cert_id')
        st = None
        if cert:
            try:
                st = self.api().status(cert)
            except PluginError as e:
                if given:
                    raise PluginError('the certificate to reuse, %s, cannot be read: %s'
                                      % (cert, e), retry=e.retry)
                self._say('the certificate %s acme ordered is not known to SSLS.cz: %s'
                          % (cert, e), 'warn')
                st = None
        code = str((st or {}).get('status') or '').upper()
        if policy == 'reissue' and st is not None:
            end = self.sub_end(st)
            left = (end - _now()) / 86400.0 if end else None
            if code in ('P', 'U'):
                raise PluginError('the certificate %s is still being validated or issued at '
                                  'SSLS.cz (state %s) - nothing is ordered; acme asks again at '
                                  'the next try' % (cert, code), retry=True)
            if code not in ISSUED:
                self._say('the certificate %s is %s (state %s) - it cannot be reissued'
                          % (cert, STATUS_WORDS.get(code, 'in an unknown state'), code or '?'),
                          'warn')
            elif self.certum():
                self._say('Certum certificates cannot be reissued through the API '
                          '(quickReissue)', 'warn')
            elif left is not None and left < _num(self.c('min_days'), 30):
                self._say('the subscription of certificate %s ends %s (%d days)'
                          % (cert, _day(end), max(0, int(left))), 'warn')
            else:
                self._say('the certificate %s is reissued (its subscription runs until %s) - '
                          'free, nothing is bought' % (cert, _day(end)), 'ok')
                return 'reissue', cert, st
        elif policy == 'reissue':
            self._say('there is no certificate to reissue (set "Certificate to reuse", or allow '
                      'a paid order for the first certificate)', 'warn')
        else:
            self._say('the policy is a new order at every renewal')
        if not allowed:
            raise PluginError('nothing ordered: a new order would be a purchase, and paid orders '
                              'are not allowed for this source - switch on "Allow new orders '
                              '(paid)", or buy the certificate at www.ssls.cz and set its SSLS '
                              'ID as "Certificate to reuse"', retry=False)
        how = 'new'
        if (cert or req.previous) and self._s('order_type') != 'new' and not self.certum():
            how = 'renew'
        self._say('a new order is made (orderType %s, paid from the account\'s credit: allowed '
                  'for this source)' % how, 'warn')
        return how, cert, st

    def issue(self, req):
        if not req.csr_pem:
            raise PluginError('there is no request (CSR) to send to SSLS.cz', retry=False)
        ck = self._cert_key(req)
        slot = 'ssls-pending:%s' % ck
        sub_key = 'ssls-order:%s' % ck
        held = self._get(slot)
        if held and sorted(held.get('names') or []) != sorted(req.names or []):
            self._say('the certificate %s waiting at SSLS.cz was for other names (%s) - it is '
                      'left alone, and its DCV records taken away' % (
                          held.get('cert_id'), ', '.join(held.get('names') or [])), 'warn')
            _dcv.Placer(self).cleanup(req, held.get('dcv') or [])
            self._waiting(held.get('cert_id'), None)
            self._put(slot, None)
            held = None
        if held and self._held_revoked(req, slot, held):
            # Its key revoked since (1.0.101, as the other sources' held requests): a revoke for
            # keyCompromise, then "issue a new one" - finished with the compromised key.
            self._say('the certificate %s waiting at SSLS.cz has the key of a version revoked - '
                      'it is let go, and a new request with a new key is sent'
                      % held.get('cert_id'), 'warn')
            _dcv.Placer(self).cleanup(req, held.get('dcv') or [])
            self.held_dropped(held)
            self._put(slot, None)
            held = None
        if held:
            cert_id = str(held['cert_id'])
            key_pem = _unseal(self.ctx, held['key'], slot) if held.get('key') else None
            if not key_pem:
                self._put(slot, None)
                raise PluginError('the key of the waiting certificate %s cannot be opened - it '
                                  'is let go; the next try starts again' % cert_id)
            self._say('the certificate %s waits at SSLS.cz since %s - asked for again, nothing '
                      'is ordered' % (cert_id, time.strftime('%Y-%m-%d %H:%M',
                                                             time.gmtime(held.get('at') or 0))))
            if held.get('dcv'):
                _dcv.Placer(self).refresh(req, held['dcv'])
        else:
            how, cert_id, _st = self._choose(req, sub_key)
            key_pem = req.key_pem
            if how == 'reissue':
                params = {'certID': cert_id, 'csr': req.csr_pem.strip()}
                if self.method() != 'email':
                    params['dcv'] = {'method': self.method()}
                got = self.api().call(M_REISSUE, params, what='the reissue of certificate %s'
                                      % cert_id)
                cert_id = str(got.get('certID') or cert_id)
                order_id = None
                self._say('reissue of certificate %s asked for (validation: %s)'
                          % (cert_id, got.get('method') or self.method()), 'ok')
            else:
                self._check_product(req)
                params = self.order_params(req, how)
                got = self.api().call(M_ORDER, params, what='the order')
                cert_id = str(got.get('certID') or '')
                order_id = str(got.get('orderID') or '')
                if not cert_id:
                    raise PluginError('SSLS.cz took the order %s but gave no certificate ID - '
                                      'find it at www.ssls.cz and set it as "Certificate to '
                                      'reuse" (a second order would be paid again)'
                                      % (order_id or '?'), retry=False,
                                      detail=self.api().hide(json.dumps(got)[:1000]))
                self._say('order %s made at SSLS.cz: certificate %s, %s for %s, %s year(s)' % (
                    order_id or '?', cert_id, self.product(), ', '.join(req.names),
                    params['period']), 'ok')
            self._put(sub_key, {'cert_id': cert_id, 'order_id': order_id,
                                'product': self.product(), 'at': _now()},
                      ttl_s=6 * 366 * 86400)
            held = {'cert_id': cert_id, 'order_id': order_id, 'how': how, 'at': _now(),
                    'names': list(req.names), 'key': _seal(self.ctx, key_pem, slot),
                    'auth': self.auth_of(got), 'dcv': [], 'placed': False}
            # Kept at once: whatever happens next, nothing is bought twice.
            self._put(slot, held, ttl_s=120 * 86400)
            self._waiting(cert_id, req.names)
        if not held.get('placed'):
            self._place(req, slot, held)
        return self._await(req, slot, held, cert_id, key_pem)

    def _held_revoked(self, req, slot, held):
        """Whether the certificate held has the key of a version revoked (req.no_held_key)."""
        from acmelib.plugins.issuers import _source_common as sc
        if not getattr(req, 'no_held_key', None) or not held.get('key'):
            return False
        key_pem = _unseal(self.ctx, held['key'], slot)
        return bool(key_pem) and sc.held_refused(req, {'key_pem': key_pem})

    def held_dropped(self, held):
        """The renewer dropped this held certificate (a revoke, renewer.drop_held): off the list
        of those waiting."""
        if isinstance(held, dict) and held.get('cert_id'):
            self._waiting(held.get('cert_id'), None)

    def _waiting(self, cert_id, names):
        """The certificates waiting here, for the action "State of the waiting certificates"."""
        w = self._get('ssls-waiting') or {}
        if names:
            w[str(cert_id)] = {'names': list(names), 'at': _now()}
        else:
            w.pop(str(cert_id), None)
        self._put('ssls-waiting', w or None, ttl_s=120 * 86400)

    # -- DCV -------------------------------------------------------------------------------
    @staticmethod
    def auth_of(got):
        """What a newOrder / quickReissue answer says of the DCV."""
        got = got if isinstance(got, dict) else {}
        out = {}
        for k in ('method', 'emailAuth', 'fileAuth', 'dnsAuth'):
            if got.get(k):
                out[k] = got[k]
        dcv = got.get('dcv') if isinstance(got.get('dcv'), dict) else {}
        if dcv.get('method') and 'method' not in out:
            out['method'] = dcv['method']
        return out

    def dcv_records(self, auth, names):
        """[{'domain', 'type', 'fqdn' | 'path', 'value'}] for every domain of the
        certificate, out of fileAuth / dnsAuth."""
        bases = []
        for n in names:
            b = _base(n)
            if b and b not in bases:
                bases.append(b)
        fa = auth.get('fileAuth') if isinstance(auth.get('fileAuth'), dict) else {}
        da = auth.get('dnsAuth') if isinstance(auth.get('dnsAuth'), dict) else {}
        if fa.get('fileName'):
            fname = str(fa['fileName']).strip().lstrip('/')
            path = fname if fname.startswith('.well-known/') else \
                '.well-known/pki-validation/' + fname
            return [{'domain': b, 'type': 'file', 'path': '/' + path,
                     'value': str(fa.get('fileContent') or '')} for b in bases]
        code = str(da.get('code') or '').strip()
        if not code:
            return []
        rtype = str(da.get('type') or '').strip().upper()
        m = re.match(r'^(\S+?)\.?\s+(?:\d+\s+)?(?:IN\s+)?(CNAME|TXT)\s+"?(.+?)"?\.?\s*$', code,
                     re.I)
        if m:
            fqdn, rt, value = m.group(1).lower(), m.group(2).lower(), m.group(3).strip()
            own = next((b for b in sorted(bases, key=len, reverse=True)
                        if fqdn == b or fqdn.endswith('.' + b)), None)
            if own is None:
                return [{'domain': bases[0] if bases else _base(fqdn), 'type': rt,
                         'fqdn': fqdn, 'value': value}]
            label = fqdn[:-len(own)].rstrip('.')
            return [{'domain': b, 'type': rt, 'fqdn': '%s.%s' % (label, b) if label else b,
                     'value': value} for b in bases]
        if rtype == 'CNAME' or not re.match(r'^\S+$', code):
            return []                   # words acme cannot read: shown in the job
        label = (self._s('txt_label') or '@').strip('.')
        return [{'domain': b, 'type': 'txt',
                 'fqdn': b if label in ('', '@') else '%s.%s' % (label, b), 'value': code}
                for b in bases]

    def _place(self, req, slot, held):
        """The DCV of the order put in place (once per order)."""
        auth = held.get('auth') or {}
        method = str(auth.get('method') or self.method()).lower()
        if method == 'email':
            said = auth.get('emailAuth') or ''
            self._say('DCV by e-mail: the CA writes to %s - somebody has to confirm it'
                      % (said or 'the approver addresses chosen'))
            held['placed'] = True
            self._put(slot, held, ttl_s=120 * 86400)
            return
        if method != self.method():
            self._say('the certificate %s is validated by %s, not %s as set here - its own '
                      'method is used' % (held.get('cert_id'), method, self.method()), 'warn')
        recs = self.dcv_records(auth, req.names)
        shown = auth.get('fileAuth') or auth.get('dnsAuth') or {}
        if shown:
            self._say('SSLS.cz\'s DCV for certificate %s (%s): %s' % (
                held.get('cert_id'), method, json.dumps(shown, ensure_ascii=False)[:600]))
        if not recs:
            self._say('SSLS.cz gave no DCV record acme can put in place for certificate %s - '
                      'do it at www.ssls.cz (the certificate\'s detail), or by hand'
                      % held.get('cert_id'), 'warn')
            held['placed'] = True
            self._put(slot, held, ttl_s=120 * 86400)
            return
        placer = _dcv.Placer(self)
        held['dcv'] = placer.place_all(req, recs)
        held['placed'] = True
        self._put(slot, held, ttl_s=120 * 86400)
        if held['dcv']:
            placer.wait_visible(req, held['dcv'])

    # -- waiting, downloading -------------------------------------------------------------------
    def _drop(self, req, slot, held, cert_id):
        _dcv.Placer(self).cleanup(req, held.get('dcv') or [])
        self._waiting(cert_id, None)
        self._put(slot, None)

    def _await(self, req, slot, held, cert_id, key_pem):
        end = _now() + _num(self.c('wait_issue'), 900)
        every = max(30.0, _num(self.c('poll_every'), 30))
        while True:
            st = self.api().status(cert_id)
            code = str(st.get('status') or '').upper()
            if code in GONE:
                self._drop(req, slot, held, cert_id)
                raise PluginError('SSLS.cz: the certificate %s is %s (state %s)%s' % (
                    cert_id, STATUS_WORDS[code], code,
                    ': %s' % st['message'] if st.get('message') else ''), retry=False)
            if code in ISSUED:
                out = self.download(cert_id, key_pem, held.get('how') == 'reissue')
                if out is not None:
                    self._drop(req, slot, held, cert_id)
                    if key_pem.strip() != (req.key_pem or '').strip():
                        out.key_pem = key_pem   # the key the waiting order was made with
                    return out
            if self.ctx.cancelled():
                raise PluginError('stopped', retry=False)
            if _now() >= end:
                more = ''
                if self.method() == 'email':
                    more = ' - the CA\'s e-mail to the approver address has to be confirmed'
                elif any(p.get('how') == 'manual' for p in held.get('dcv') or []):
                    more = ' - the DCV record said in the job has to be put in place by hand'
                raise PluginError('the certificate %s waits at SSLS.cz (state %s: %s)%s; acme '
                                  'asks for it again at the next try - nothing is ordered again'
                                  % (cert_id, code or '?', STATUS_WORDS.get(code, '?'), more),
                                  retry=True)
            self._say('certificate %s: %s (%s) - asked again in %d s' % (
                cert_id, code or '?', st.get('message') or STATUS_WORDS.get(code, '?'),
                int(every)))
            self._sleep(min(every, max(1.0, end - _now())))
            every = min(every * 1.5, 300.0)

    def download(self, cert_id, key_pem, reissue=False):
        """Issued, or None while getCert still gives the certificate of before (a reissue
        that is not through)."""
        from acmelib.certs import pki
        got = self.api().call(M_GET, {'certID': cert_id}, what='the certificate %s' % cert_id)
        items = got.get('certificates') or []
        if isinstance(items, dict):
            items = list(items.values())
        pems = []
        for it in items:
            text = it.get('Contents') if isinstance(it, dict) else it
            for c in _certs_in(text):
                if c not in pems:
                    pems.append(c)
        if not pems:
            raise PluginError('SSLS.cz sent no certificate for %s' % cert_id,
                              detail=self.api().hide(json.dumps(got)[:1000]))
        leaf = next((c for c in pems if pki.key_matches(c, key_pem)), None)
        if not leaf:
            if reissue:
                self._say('the certificate %s is still the one before the reissue' % cert_id)
                return None
            raise PluginError('the certificate %s is for another key than this request '
                              '(reissued meanwhile at www.ssls.cz?) - it is not used' % cert_id,
                              retry=False)
        others = [c for c in pems if c != leaf]
        chain = pki.order_chain(leaf, others) or others
        chain = [c for c in chain if c.strip() != leaf.strip()]
        info = pki.cert_info(leaf)
        self._say('the certificate came: SSLS ID %s, serial %s, until %s' % (
            cert_id, info.get('serial') or '?', _day(info.get('not_after'))), 'ok')
        try:
            self._put('ssls-serial:%s' % pki.norm_serial(info.get('serial') or '')[:80],
                      {'cert_id': cert_id}, ttl_s=6 * 366 * 86400)
        except Exception:                               # noqa: BLE001
            pass
        return Issued(leaf, chain, info={'ssls_id': cert_id, 'ref': cert_id})

    # -- the certificates of the account (Certificates → Import from a source) -------------
    def _acme_ids(self):
        """{SSLS ID: acme's certificate id} of the orders acme made or reissued here."""
        out = {}
        try:
            kept = self.ctx.kv_keys('ssls-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            if isinstance(v, str):
                try:
                    v = json.loads(v)
                except ValueError:
                    continue
            cid = k.split(':')[1] if k.count(':') >= 2 else ''
            if isinstance(v, dict) and v.get('cert_id') and cid.isdigit():
                out[str(v['cert_id'])] = int(cid)
        return out

    def list_existing(self):
        """Every certificate of the account (myCerts) - read only."""
        mine = self._acme_ids()
        out = []
        for c in self.api().mine():
            cid = str(c.get('certID') or '').strip()
            if not cid:
                continue
            code = str(c.get('status') or '').upper()
            names = [str(c.get('CN') or '').strip()] + [
                x.strip() for x in re.split(r'[\s,;]+', str(c.get('SAN') or '')) if x.strip()]
            names = [n for i, n in enumerate(names) if n and n not in names[:i]]
            end = _num(c.get('SNVA'), 0) or _num(c.get('NVA'), 0)
            product = str(c.get('productName') or '')
            certum = is_certum('', '', product)
            if code in ISSUED and not certum and (not end or end > _now()):
                renew = 'reissue'
            else:
                renew = 'order'
            note = ''
            if code not in ISSUED:
                note = 'SSLS.cz says it is %s (state %s)' % (
                    STATUS_WORDS.get(code, 'in an unknown state'), code or '?')
            elif certum:
                note = 'Certum certificates are never reissued through the API: a renewal is a ' \
                       'new (paid) order'
            out.append({'ref': cid, 'cn': names[0] if names else '', 'names': names,
                        'product': product, 'status': STATUS_WORDS.get(code, code or '?'),
                        'not_before': _num(c.get('NVB'), 0) or None,
                        'not_after': _num(c.get('NVA'), 0) or None,
                        'paid_until': _num(c.get('SNVA'), 0) or None,
                        'downloadable': code in ISSUED, 'renewable': renew, 'note': note,
                        'acme_cert_id': mine.get(cid)})
        return out

    def fetch_existing(self, ref):
        """The certificate of the SSLS ID `ref` and its chain (getCert) - read only."""
        from acmelib.certs import pki
        cid = str(ref or '').strip()
        if not re.match(r'^\d{1,20}$', cid):
            raise PluginError('%s is not an SSLS ID' % (cid or '?'), retry=False)
        got = self.api().call(M_GET, {'certID': cid}, what='the certificate %s' % cid)
        items = got.get('certificates') or []
        if isinstance(items, dict):
            items = list(items.values())
        pems = []
        for it in items:
            text = it.get('Contents') if isinstance(it, dict) else it
            for c in _certs_in(text):
                if c not in pems:
                    pems.append(c)
        leafs = [c for c in pems if not pki.cert_info(c).get('is_ca')]
        if not leafs:
            raise PluginError('SSLS.cz sent no certificate for %s (not issued yet?)' % cid,
                              retry=False)
        leaf = max(leafs, key=lambda c: pki.cert_info(c).get('not_before') or 0)
        others = [c for c in pems if c != leaf and pki.cert_info(c).get('is_ca')]
        chain = pki.order_chain(leaf, others) or others
        return {'cert_pem': leaf, 'chain_pems': [c for c in chain if c.strip() != leaf.strip()],
                'ref': cid, 'acme_cert_id': self._acme_ids().get(cid)}

    # -- revocation, trying it, the actions ------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        raise PluginError('the API of SSLS.cz cannot revoke a certificate - revoke it at '
                          'www.ssls.cz (My certificates) or ask its support', retry=False)

    def test(self):
        prods, got = self.api().products(account=True)
        bits = ['signed in to %s' % API_URL, '%d products' % len(prods)]
        credit = credit_of(got)
        if credit is not None:
            bits.append('credit %s' % credit)
        code = self._s('product_manual') or self._s('product')
        if code:
            p = next((x for x in prods if x['code'] == code), None)
            if p is None:
                bits.append('the product %s is NOT among them' % code)
            else:
                bits.append('the product %s is offered (%s)' % (code, p['name']))
        bits.append('new paid orders %s' % ('ALLOWED' if _as_bool(self.c('allow_paid'))
                                            else 'not allowed (reissues only)'))
        return '; '.join(bits)

    def action(self, key):
        if key == 'products':
            prods, got = self.api().products(account=True)
            for p in prods:
                self._say('%s - %s (%s, %s%s)' % (
                    p['code'], p['name'], p['ca'] or '?', p['level'] or '?',
                    ', up to %d years' % p['years'] if p['years'] else ''))
            credit = credit_of(got)
            return '%d products%s' % (len(prods), '; credit %s' % credit if credit else '')
        if key == 'certs':
            items = self.api().mine()
            for c in items[:300]:
                self._say('SSLS ID %s: %s%s, %s, %s, state %s, until %s, subscription until %s'
                          % (c.get('certID') or '?', c.get('CN') or '?',
                             ' + %s' % c['SAN'] if c.get('SAN') else '',
                             c.get('productName') or '?', c.get('orderType') or '?',
                             c.get('status') or '?', _day(_num(c.get('NVA'), 0)),
                             _day(_num(c.get('SNVA'), 0))))
            return '%d certificates' % len(items)
        if key == 'status':
            todo = [self._s('cert_reuse')] if self._s('cert_reuse') else []
            todo += [k for k in (self._get('ssls-waiting') or {}) if k not in todo]
            if not todo:
                raise PluginError('no certificate is waiting here, and no certificate to reuse '
                                  'is set', retry=False)
            for cid in todo:
                st = self.api().status(cid)
                code = str(st.get('status') or '?').upper()
                self._say('certificate %s (%s): %s - %s, until %s' % (
                    cid, st.get('CN') or '?', code, st.get('message') or
                    STATUS_WORDS.get(code, '?'), _day(self.sub_end(st))))
            return '%d certificate(s)' % len(todo)
        return Issuer.action(self, key)
