# -*- coding: utf-8 -*-
"""
Certificates from Certum (Asseco) through its partner API - the SOAP
PartnerApi: the request (CSR) ordered (quickOrder), the domain validation (DCV)
record or file put in place by the certificate's own validation
(base.Challenge.place; acmelib/plugins/issuers/_dcv.py), Certum asked to look
(performSanVerification), the certificate fetched once the order is ENROLLED. A
certificate is reissued inside its order (free, within the product's validity);
a new order is a purchase and is only made when "Allow new orders (paid)" is
on. The account's orders are listed for Certificates → Import from a source.

Certum's ACME (with EAB) is the `acme` source's preset; Certum's REST
CertManager API (v0_2) only orders ACME products (it hands out EAB keys), so
this module speaks the SOAP API, which takes a CSR.

What the API is, and from where - Certum's own documents (read 2026-11):
the WSDL https://gs.test.certum.pl/service/PartnerApi.wsdl (the production
one, https://gs.certum.pl/service/PartnerApi.wsdl, is behind an IP allow
list) and the "API - User Guide EN 5.19"
(https://repository.certum.pl/API/EN/API%20-%20User%20Guide%20EN%205.19.pdf),
https://support.certum.eu/en/domain-verification-methods/:

* SOAP 1.1, document/literal, namespace http://webservice.api.muc.unizeto.pl/, its
  child elements unqualified; every request starts with
  <requestHeader><authToken><userName/><password/></authToken></requestHeader>, every
  answer with <responseHeader><successCode> (0 = done; 1, 3 = an error) and
  <errors><Error><errorCode/><value/></Error></errors>.
* getProductList -> products/product {code, type ISSUE | RENEWAL, validityPeriod}.
* quickOrder {orderParameters {CSR, customer, language, orderID, productCode,
  userAgent, hashAlgorithm RSA-SHA256 | ECC-SHA256}, SANEntries/SANEntry/DNSName,
  SANApprover {approverMethod FILE | DNS_TXT | DNS_CNAME | DNS_TXT_PREFIX |
  DNS_CNAME_PREFIX, verificationNotificationEnabled}, requestorInfo,
  organizationInfo} -> {orderID, SANVerification {approverMethod, code, FQDNs}}.
* The records (User Guide 4.2.3): DNS_TXT - TXT at the domain holding the code;
  DNS_TXT_PREFIX - TXT at _certum.DOMAIN; DNS_CNAME - CNAME at the domain to
  CODE.certum.pl; DNS_CNAME_PREFIX - CNAME at _certum.DOMAIN to CODE.certum.pl;
  FILE - /.well-known/pki-validation/certum.txt holding CODE-certum.pl (no
  wildcards). One code for every domain of the order.
* performSanVerification {code}; getSanVerificationState {orderID}; getOrderState
  {orderID} -> orderStatus AWAITING | VERIFICATION | ACCEPTED | ENROLLED | REJECTED.
* getCertificate {orderID} -> certificateDetails/X509Cert and caBundle/X509Cert (PEM).
* reissueCertificate {serialNumber, hashAlgorithm, CSR, SANApprover, SANEntries
  (only for new domains)} -> {orderID, SANVerification}.
* revokeCertificate {revokeCertificateParameters {revocationReason, serialNumber
  (hex)}}.
* getOrdersByDateRange {fromDate, orderOption {certificateDetails, orderDetails,
  orderStatus}, pageNumber, toDate} -> orders/Order (100 a page; responseHeader
  pagesCount): Import from a source.

LESS CERTAIN: the production endpoint (https://gs.certum.pl/service/PartnerApi, from
the address of its WSDL - a setting); the order of the child elements (the WSDL's is
used); whether the TXT record holds the code with no suffix (the guide says "place
the code in the TXT record"); the file's name certum.txt (from the support page - the
API does not say it); the date-time format of getOrdersByDateRange (the WSDL says
xs:dateTime, the guide YYYY-MM-DD); whether a reissue keeps the order's ID (the ID
answered is used). A renewal order (renewCertificate) is not made - a new order is.
"""
from __future__ import annotations

import calendar
import json
import re
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from acmelib.plugins.base import Issuer, Plugin, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

NS = 'http://webservice.api.muc.unizeto.pl/'
ENDPOINTS = {'production': 'https://gs.certum.pl/service/PartnerApi',
             'test': 'https://gs.test.certum.pl/service/PartnerApi'}
METHODS = ('DNS_TXT_PREFIX', 'DNS_TXT', 'DNS_CNAME_PREFIX', 'DNS_CNAME', 'FILE')
FILE_PATH = '/.well-known/pki-validation/certum.txt'
REVOKE = {0: 'UNSPECIFIED', 1: 'KEYCOMPROMISE', 3: 'AFFILIATIONCHANGED', 4: 'SUPERSEDED',
          5: 'CESSATIONOFOPERATION'}
WAITING = ('AWAITING', 'VERIFICATION', 'ACCEPTED')
STATUS_WORDS = {'AWAITING': 'waiting for the verification', 'VERIFICATION': 'being verified',
                'ACCEPTED': 'verified, being issued', 'ENROLLED': 'issued',
                'REJECTED': 'cancelled or rejected'}
ERRORS = {3: 'the user name or password is wrong', 1006: 'the product is discontinued',
          1013: 'the product code is wrong', 1023: 'the customer must not be the partner login',
          1032: 'the key of the CSR was used before'}


# ---------------------------------------------------------------------------
# SOAP by hand: an envelope from nested (name, value) pairs, the answer as dicts
# ---------------------------------------------------------------------------
def _xml(items):
    out = []
    for k, v in items:
        if v is None or v == '':
            continue
        if isinstance(v, list):
            out.append('<%s>%s</%s>' % (k, _xml(v), k))
        elif isinstance(v, bool):
            out.append('<%s>%s</%s>' % (k, 'true' if v else 'false', k))
        else:
            out.append('<%s>%s</%s>' % (k, escape(str(v)), k))
    return ''.join(out)


def envelope(op, user, password, items):
    head = [('requestHeader', [('authToken', [('password', password), ('userName', user)])])]
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:tns="%s"><soapenv:Body><tns:%s>%s</tns:%s></soapenv:Body>'
            '</soapenv:Envelope>' % (NS, op, _xml(head + list(items)), op)).encode('utf-8')


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def kids(el, name):
    return [c for c in list(el) if _local(c.tag) == name] if el is not None else []


def kid(el, name):
    got = kids(el, name)
    return got[0] if got else None


def text(el, name, default=''):
    c = kid(el, name)
    return (c.text or '').strip() if c is not None and c.text else default


def children(el):
    return list(el) if el is not None else []


def find(el, name):
    """The first element `name` anywhere under `el`."""
    if el is None:
        return None
    for c in el.iter():
        if _local(c.tag) == name:
            return c
    return None


def _when(v):
    s = str(v or '').strip()
    for fmt, n in (('%Y-%m-%dT%H:%M:%S', 19), ('%Y-%m-%d', 10)):
        try:
            return calendar.timegm(time.strptime(s[:n], fmt))
        except (TypeError, ValueError):
            continue
    return None


class CertumIssuer(Issuer):
    kind = 'certum'
    title = 'Certum (partner API)'
    description = ('Certificates from Certum through its SOAP partner API: ordered with acme\'s '
                   'request, the domain validation record or file put in place by the '
                   'certificate\'s validation, reissued inside the order. Lists the account\'s '
                   'orders for importing.')
    vendor = 'Certum'
    doc = 'docs/sources.md'
    needs_challenge = True
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # getOrdersByDateRange + getCertificate: Import from a source
    dcv_field = 'dcv'
    dcv_default = 'DNS_TXT_PREFIX'
    dcv = {
        'DNS_TXT_PREFIX': {'proof': 'txt-any', 'words': 'DNS TXT at _certum. (DNS_TXT_PREFIX)',
                           'record': 'TXT at _certum.DOMAIN holding Certum\'s code'},
        'DNS_TXT': {'proof': 'txt-any', 'words': 'DNS TXT at the domain (DNS_TXT)',
                    'record': 'TXT at the domain holding Certum\'s code'},
        'DNS_CNAME_PREFIX': {'proof': 'cname-any',
                             'words': 'DNS CNAME at _certum. (DNS_CNAME_PREFIX)',
                             'record': 'CNAME _certum.DOMAIN to CODE.certum.pl'},
        'DNS_CNAME': {'proof': 'cname-any', 'words': 'DNS CNAME at the domain (DNS_CNAME)',
                      'record': 'CNAME at the domain to CODE.certum.pl'},
        'FILE': {'proof': 'http-file-any', 'words': 'HTTP file (FILE)',
                 'record': 'http://NAME/.well-known/pki-validation/certum.txt holding '
                           'CODE-certum.pl'},
    }
    fields = [
        field('env', 'Certum', 'select', default='production',
              options=[['production', 'Production (gs.certum.pl)'],
                       ['test', 'Test (gs.test.certum.pl)']],
              help='The partner API answers only the IP addresses registered for the account.'),
        field('user', 'Partner login', 'text', required=True,
              help='The partner\'s identifier agreed with Certum (its SSO account).'),
        field('password', 'Password', 'secret', required=True),
        field('customer', 'Customer', 'text', required=True,
              help='The customer the certificates are for (its ID or SimplySign login) - not the '
                   'partner login.'),
        field('product', 'Product of a new order', 'catalog', catalog='products',
              placeholder='631', depends=['env', 'user', 'password'],
              help='Load the list: the products of the account (getProductList, type ISSUE) - a '
                   'code can be typed too.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders bought '
                   'already, and stops with words where a purchase would be needed.'),
        field('order_id', 'Order to reuse', 'text', placeholder='a Certum order ID',
              help='An order bought already: its certificate is reissued (free, within the '
                   'product\'s validity). Empty: the order acme made last for the certificate.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='DNS_TXT_PREFIX',
              options=[['DNS_TXT_PREFIX', 'DNS TXT record at _certum.DOMAIN'],
                       ['DNS_TXT', 'DNS TXT record at the domain itself'],
                       ['DNS_CNAME_PREFIX', 'DNS CNAME record at _certum.DOMAIN'],
                       ['DNS_CNAME', 'DNS CNAME record at the domain itself'],
                       ['FILE', 'HTTP file /.well-known/pki-validation/certum.txt (no '
                                'wildcards)']],
              help='How Certum checks the domains (one method for the whole order). The '
                   'certificate\'s validation must be able to put that record or file in place.'),
        field('requestor', 'Requestor (OV/EV)', 'list', advanced=True,
              placeholder='email=it@example.com',
              help='For an OV or EV product: email=, firstName=, lastName=, phone= one a line '
                   '(requestorInfo).'),
        field('tax_id', 'Tax identification number (OV/EV)', 'text', advanced=True,
              help='organizationInfo/taxIdentificationNumber of an OV or EV order.'),
        field('language', 'Language', 'text', default='en', advanced=True),
        field('list_days', 'Orders listed (days back)', 'number', default=825, advanced=True,
              help='Import from a source: the orders placed in so many days back '
                   '(getOrdersByDateRange).'),
        field('api_url', 'API address', 'text', advanced=True,
              placeholder='https://gs.certum.pl/service/PartnerApi',
              help='Empty: as "Certum" says.'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600,
              advanced=True,
              help='Longer: it is asked for again at the next try - nothing is ordered twice.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=20, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self._sleep = time.sleep

    # -- what fits (acmelib/certs/compat.py) -------------------------------------------------
    @classmethod
    def dcv_where(cls, config, name, proof):
        bare = _dcv.base_of(name)
        m = cls.dcv_method(config)
        if proof == 'http-file-any':
            return '/.well-known/pki-validation/'
        return '_certum.' + bare if m.endswith('_PREFIX') else bare

    # -- the API ---------------------------------------------------------------------------
    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _url(self):
        url = self._s('api_url') or ENDPOINTS.get(self._s('env') or 'production')
        if not url or not re.match(r'^https://[^\s]+\Z', url):
            raise PluginError('the Certum API address is an https address', retry=False)
        return url

    def call(self, op, items, what=''):
        """The answer's element <op>Response, or a PluginError in words."""
        if not self._s('user') or not self._s('password'):
            raise PluginError('set the partner login and the password', retry=False)
        body = envelope(op, self._s('user'), self._s('password'), items)
        status, _h, data = sc.http(self.ctx, 'POST', self._url(), body,
                                   {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '""',
                                    'Accept': 'text/xml'}, who='Certum')
        pw = self._s('password')
        said = (data or b'').decode('utf-8', 'replace').replace(pw, '********') if pw else \
            (data or b'').decode('utf-8', 'replace')
        try:
            root = ET.fromstring(data or b'')
        except ET.ParseError:
            raise PluginError('Certum answered %s to %s, and not in SOAP' % (status, what or op),
                              detail=said[:3000], retry=status >= 500)
        fault = find(root, 'Fault')
        if fault is not None:
            raise PluginError('Certum refused %s: %s' % (what or op, text(fault, 'faultstring') or
                                                         'a SOAP fault'),
                              detail=said[:3000], retry=status >= 500)
        resp = find(root, op + 'Response')
        head = find(resp, 'responseHeader')
        code = text(head, 'successCode', '')
        if resp is None or head is None or code != '0':
            errs = []
            for e in children(find(head, 'errors')):
                n = text(e, 'errorCode')
                v = text(e, 'value')
                words = ERRORS.get(int(n)) if n.isdigit() and int(n) in ERRORS else ''
                errs.append('%s%s%s' % (n or '?', (' ' + v) if v else '',
                                        (' - ' + words) if words else ''))
            raise PluginError('Certum refused %s: error %s' % (what or op, '; '.join(errs) or
                                                              code or '?'),
                              detail=said[:3000], retry=False)
        return resp

    # -- the products (the form's list) ------------------------------------------------------
    def products(self):
        resp = self.call('getProductList', [('hashAlgorithm', True)], what='the product list')
        out = []
        for p in resp.iter():
            if _local(p.tag) != 'product':
                continue
            algs = [(a.text or '').strip() for a in p.iter() if _local(a.tag) == 'hashAlgorithm']
            out.append({'code': text(p, 'code'), 'type': text(p, 'type'),
                        'days': text(p, 'validityPeriod'), 'hash': [a for a in algs if a]})
        return [p for p in out if p['code']]

    def catalog(self, key):
        """The products of the account: getProductList, those of type ISSUE (quickOrder).
        Read-only."""
        if key != 'products':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = [[p['code'], '%s (%s days%s)' % (p['code'], p['days'] or '?',
                                                 ', ' + '/'.join(p['hash']) if p['hash'] else '')]
                for p in self.products() if p['type'] in ('', 'ISSUE')]
        return {'options': opts, 'said': '%d product(s) to order' % len(opts)}

    def test(self):
        prods = self.products()
        return 'Certum answers: signed in; %d product(s) on the account; new paid orders %s' % (
            len(prods), 'ALLOWED' if sc.as_bool(self.c('allow_paid')) else 'not allowed')

    # -- the order ---------------------------------------------------------------------------
    @staticmethod
    def _hash(req):
        return 'ECC-SHA256' if str(getattr(req, 'key_type', '') or '').startswith('ec') \
            else 'RSA-SHA256'

    def _method(self):
        m = self._s('dcv') or 'DNS_TXT_PREFIX'
        if m not in METHODS:
            raise PluginError('the DCV method is one of %s' % ', '.join(METHODS), retry=False)
        return m

    def _approver(self):
        return [('approverMethod', self._method()), ('verificationNotificationEnabled', False)]

    def _requestor(self):
        info = {}
        for line in sc.lines(self.c('requestor')):
            if '=' in line:
                k, v = line.split('=', 1)
                info[k.strip()] = v.strip()
        if not info:
            return None
        return [(k, info.get(k)) for k in ('email', 'firstName', 'lastName', 'phone')]

    def _sans(self, req):
        return [('SANEntry', [('DNSName', n)]) for n in req.names]

    def _serial_of(self, oid):
        resp = self.call('getOrderByOrderID', [('orderID', oid), ('orderOption', [
            ('certificateDetails', True), ('orderDetails', False), ('orderStatus', True)])],
            what='the order %s' % oid)
        order = find(resp, 'Order')
        st = find(order, 'orderStatus')
        det = find(order, 'certificateDetails')
        return (text(det, 'serialNumber') or text(st, 'serialNumber'),
                text(st, 'orderStatus'), _when(text(st, 'productValidityDate')),
                sorted(n.strip().lower() for n in text(det, 'DNSNames').split(',') if n.strip()))

    def _order(self, req, kept):
        """(how, orderID, SANVerification element) of what was asked for."""
        oid = str(getattr(req, 'ref', None) or '').strip() or self._s('order_id') or \
            str((kept or {}).get('id') or '')
        why = 'there is no order to reissue in (set "Order to reuse")'
        if oid:
            serial, st, until, names = self._serial_of(oid)
            if st == 'ENROLLED' and serial and (until is None or until > time.time() + 86400):
                items = [('serialNumber', serial), ('hashAlgorithm', self._hash(req)),
                         ('CSR', sc.csr_pem(req)), ('SANApprover', self._approver())]
                if names and names != sorted(n.lower() for n in req.names):
                    items.append(('SANEntries', self._sans(req)))
                resp = self.call('reissueCertificate', items, what='the reissue in %s' % oid)
                sc.say(self.ctx, 'reissue inside order %s asked for (free)' % oid, 'ok')
                return 'reissue', text(resp, 'orderID') or oid, kid(resp, 'SANVerification')
            why = 'the order %s is %s%s' % (oid, STATUS_WORDS.get(st, st or '?'),
                                           ', its product\'s validity is over' if until and
                                           until <= time.time() + 86400 else '')
        if not sc.as_bool(self.c('allow_paid')):
            raise PluginError('nothing ordered: %s, and paid orders are not allowed for this '
                              'source - set "Order to reuse" to an order you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        if not self._s('customer'):
            raise PluginError('set the customer', retry=False)
        product = self._s('product')
        if not re.match(r'^\d{3}\Z', product):
            raise PluginError('set the product of a new order (its 3-digit code)', retry=False)
        sc.say(self.ctx, '%s - a new order is made (paid: allowed for this source)' % why, 'warn')
        params = [('CSR', sc.csr_pem(req)), ('customer', self._s('customer')),
                  ('language', self._s('language') or 'en'), ('productCode', product),
                  ('userAgent', 'acme'), ('hashAlgorithm', self._hash(req))]
        items = [('SANApprover', self._approver()), ('orderParameters', params)]
        if self._s('tax_id'):
            items.append(('organizationInfo', [('taxIdentificationNumber', self._s('tax_id'))]))
        rq = self._requestor()
        if rq:
            items.append(('requestorInfo', rq))
        items.append(('SANEntries', self._sans(req)))
        resp = self.call('quickOrder', items, what='the order')
        oid = text(resp, 'orderID')
        if not oid:
            raise PluginError('Certum took the order but said no order ID - look in the partner '
                              'panel before trying again (a second order would be paid again)',
                              retry=False)
        sc.say(self.ctx, 'order %s made at Certum: product %s for %s' % (
            oid, product, ', '.join(req.names)), 'ok')
        return 'new', oid, kid(resp, 'SANVerification')

    def dcv_records(self, req, ver):
        """The records Certum looks for (one code for every domain of the order)."""
        code = text(ver, 'code')
        if not code:
            return [], ''
        m = text(ver, 'approverMethod') or self._method()
        fq = [(f.text or '').strip() for f in children(find(ver, 'FQDNs')) if (f.text or '').strip()]
        recs = []
        for n in fq or req.names:
            d = _dcv.base_of(n)
            if any(r['domain'] == d for r in recs):
                continue
            if m == 'FILE':
                recs.append({'domain': d, 'type': 'file', 'path': FILE_PATH,
                             'value': code + '-certum.pl'})
            elif m.startswith('DNS_CNAME'):
                recs.append({'domain': d, 'type': 'cname', 'value': code + '.certum.pl',
                             'fqdn': ('_certum.' + d) if m.endswith('_PREFIX') else d})
            else:
                recs.append({'domain': d, 'type': 'txt', 'value': code,
                             'fqdn': ('_certum.' + d) if m.endswith('_PREFIX') else d})
        return recs, code

    def _place(self, req, slot, held, placer, recs, ttl=90):
        """The records kept with the order first (a try that stops while they are put in
        place puts them again the next time), then put in place."""
        held['recs'] = recs
        sc.pending_put(self.ctx, slot, req, held, ttl_days=ttl)
        held['dcv'] = placer.place_all(req, recs)
        sc.pending_put(self.ctx, slot, req, held, ttl_days=ttl)
        return any(p.get('how') == 'placed' for p in held['dcv'])

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        if self._method() == 'FILE' and any(n.startswith('*.') for n in req.names):
            raise PluginError('Certum proves a wildcard name by DNS, not by the FILE method - '
                              'choose a DNS record', retry=False)
        ck = str(req.cert_id or '') or sc.pending_slot('x', '', req).split(':')[-1]
        made_key = 'certum-order:%s' % ck
        slot = sc.pending_slot('certum', self._url(), req)
        held = sc.pending_get(self.ctx, slot, req, issuer=self)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        if held:
            oid = held['id']
            sc.say(self.ctx, 'the order %s waits at Certum since %s - asked for again, nothing is '
                             'ordered' % (oid, time.strftime('%Y-%m-%d %H:%M',
                                                             time.gmtime(held.get('at') or 0))))
            if held.get('recs') and not held.get('dcv'):
                if self._place(req, slot, held, placer, held['recs']):
                    placer.wait_visible(req, held['dcv'])
            elif held.get('dcv'):
                placer.refresh(req, held['dcv'])
            if held.get('code'):
                self._verify(held['code'])
        else:
            kept = sc.parse_json(self.ctx.kv_get(made_key) or '') or {}
            how, oid, ver = self._order(req, kept)
            if how == 'new':
                self.ctx.kv_set(made_key, json.dumps({'id': oid, 'at': time.time()}),
                                ttl_s=5 * 366 * 86400)
            held = sc.pending_put(self.ctx, slot, req, {'id': oid, 'how': how, 'dcv': [],
                                                        'csr_pem': sc.csr_pem(req)}, ttl_days=90)
            r = req
            recs, code = self.dcv_records(req, ver)
            if recs:
                held['code'] = code
                if self._place(req, slot, held, placer, recs):
                    placer.wait_visible(req, held['dcv'])
                self._verify(code)
        return self._await(r, req, slot, held, placer)

    def _verify(self, code):
        try:
            self.call('performSanVerification', [('code', code)], what='the domain verification')
            sc.say(self.ctx, 'Certum was asked to verify the domains')
        except PluginError as e:
            sc.say(self.ctx, 'Certum was not asked to verify the domains: %s' % e, 'warn')

    def _san_state(self, oid):
        try:
            resp = self.call('getSanVerificationState', [('orderID', oid)],
                             what='the domain verification')
        except PluginError:
            return ''
        out = []
        for v in resp.iter():
            if _local(v.tag) != 'sanVerification':
                continue
            man = kid(v, 'manualVerification')
            st = text(man, 'state')
            if st and st != 'VERIFIED':
                out.append('%s %s%s' % (text(v, 'FQDN'), st, (' (%s)' % text(man, 'info'))
                                        if text(man, 'info') else ''))
        return ', '.join(out)

    def fetch(self, oid):
        resp = self.call('getCertificate', [('orderID', oid)], what='the certificate of %s' % oid)
        leaf = sc.certs_of(text(find(resp, 'certificateDetails'), 'X509Cert'))
        chain = []
        for b in resp.iter():
            if _local(b.tag) == 'caBundle':
                for x in kids(b, 'X509Cert'):
                    chain += sc.certs_of((x.text or '').strip())
        return leaf, chain

    def _await(self, r, req, slot, held, placer):
        oid = held['id']
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 20))
        while True:
            resp = self.call('getOrderState', [('orderID', oid)], what='the order %s' % oid)
            st = text(resp, 'orderStatus')
            if st == 'ENROLLED':
                leaf, chain = self.fetch(oid)
                try:
                    out = sc.finish(self.ctx, r, leaf, chain, who='Certum',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'certum_order': oid, 'ref': oid})
                except PluginError:
                    out = None              # the order's old certificate still: the reissue waits
                if out is not None:
                    placer.cleanup(req, held.get('dcv') or [])
                    sc.pending_drop(self.ctx, slot)
                    if getattr(req, 'cert_id', None):
                        self.ctx.kv_set('certum-order:%s' % req.cert_id,
                                        json.dumps({'id': oid, 'at': time.time()}),
                                        ttl_s=5 * 366 * 86400)
                    return out
            elif st == 'REJECTED':
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('Certum did not issue: the order %s is %s' % (
                    oid, STATUS_WORDS['REJECTED']), retry=False)
            if time.time() >= end or self.ctx.cancelled():
                left = self._san_state(oid)
                raise PluginError('Certum has not issued yet (order %s: %s%s) - the DCV records '
                                  'stay in place; acme asks again at the next try' % (
                                      oid, STATUS_WORDS.get(st, st or '?'),
                                      '; not verified: ' + left if left else ''))
            self._sleep(every)

    # -- revocation ---------------------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        serial = sc.serial_hex(cert_pem)
        why = REVOKE.get(sc.reason_code(reason), 'UNSPECIFIED')
        self.call('revokeCertificate', [('revokeCertificateParameters', [
            ('note', 'revoked by acme'), ('revocationReason', why), ('serialNumber', serial)])],
            what='the revocation')
        return 'Certum revoked serial %s (%s)' % (serial, why)

    # -- the orders of the account (Certificates → Import from a source) ---------------------
    def _acme_ids(self):
        out = {}
        try:
            kept = self.ctx.kv_keys('certum-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('id') and cid.isdigit():
                out[str(v['id'])] = int(cid)
        return out

    def list_existing(self):
        """The orders placed in "Orders listed" days (getOrdersByDateRange) - read only."""
        mine = self._acme_ids()
        now = time.time()
        days = max(1, int(sc.num(self.c('list_days'), 825)))
        frm = time.strftime('%Y-%m-%dT00:00:00.000Z', time.gmtime(now - days * 86400))
        to = time.strftime('%Y-%m-%dT23:59:59.000Z', time.gmtime(now))
        out, page, pages = [], 1, 1
        while page <= min(pages, 100):
            resp = self.call('getOrdersByDateRange', [
                ('fromDate', frm), ('orderOption', [('certificateDetails', True),
                                                    ('orderDetails', False),
                                                    ('orderStatus', True)]),
                ('pageNumber', page), ('toDate', to)], what='the list of orders')
            pages = int(sc.num(text(find(resp, 'responseHeader'), 'pagesCount'), 1)) or 1
            for o in resp.iter():
                if _local(o.tag) != 'Order':
                    continue
                st, det = kid(o, 'orderStatus'), kid(o, 'certificateDetails')
                oid = text(st, 'orderID')
                if not oid:
                    continue
                state = text(st, 'orderStatus')
                cstate = text(det, 'certificateStatus')
                names = [n.strip() for n in text(det, 'DNSNames').split(',') if n.strip()]
                cn = text(det, 'commonName') or (names[0] if names else '')
                if cn and cn not in names:
                    names.insert(0, cn)
                until = _when(text(st, 'productValidityDate'))
                ok = state == 'ENROLLED' and cstate in ('', 'VALID')
                out.append({'ref': oid, 'cn': cn, 'names': names,
                            'product': text(st, 'productCode'),
                            'status': STATUS_WORDS.get(state, state or '?') +
                            (' (%s)' % cstate.lower() if cstate and cstate != 'VALID' else ''),
                            'not_before': _when(text(det, 'startDate')),
                            'not_after': _when(text(det, 'endDate')),
                            'paid_until': until,
                            'serial': (text(det, 'serialNumber') or
                                       text(st, 'serialNumber')).upper(),
                            'downloadable': ok,
                            'renewable': 'reissue' if ok and (until is None or until > now)
                            else 'order',
                            'note': '' if ok else 'the order is %s' % (
                                STATUS_WORDS.get(state, state or '?')),
                            'acme_cert_id': mine.get(oid)})
            page += 1
        return out

    def fetch_existing(self, ref):
        """The certificate of order `ref` and its chain (getCertificate) - read only."""
        oid = str(ref or '').strip()
        if not re.match(r'^[A-Za-z0-9._-]{1,50}\Z', oid):
            raise PluginError('%s is not a Certum order ID' % (oid or '?'), retry=False)
        leaf, chain = self.fetch(oid)
        out = sc.existing(leaf, chain, who='Certum', ref=oid)
        out['acme_cert_id'] = self._acme_ids().get(oid)
        return out

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['env', 'user', 'password', 'api_url']

    def discover_setup(self):
        """Read-only: the products (the form's list) and the orders of "Orders listed" days
        (getOrdersByDateRange with their order details, the first page): the customers they
        were for, the requestor and tax ID of the newest, and an order to reissue in (never
        picked by itself)."""
        out = Plugin.discover_setup(self)
        now = time.time()
        days = max(1, int(sc.num(self.c('list_days'), 825)))
        resp = self.call('getOrdersByDateRange', [
            ('fromDate', time.strftime('%Y-%m-%dT00:00:00.000Z', time.gmtime(now - days * 86400))),
            ('orderOption', [('certificateDetails', True), ('orderDetails', True),
                             ('orderStatus', True)]),
            ('pageNumber', 1),
            ('toDate', time.strftime('%Y-%m-%dT23:59:59.000Z', time.gmtime(now)))],
            what='the list of orders')
        orders = [o for o in resp.iter() if _local(o.tag) == 'Order']
        out['facts'].append(['Orders', str(len(orders))])
        orders.sort(key=lambda o: text(kid(o, 'orderStatus'), 'orderDate'), reverse=True)
        customers, rows, newest = [], [], None
        for o in orders:
            st, det, more = kid(o, 'orderStatus'), kid(o, 'certificateDetails'), \
                kid(o, 'orderDetails')
            cust = text(st, 'customer')
            if cust and cust not in customers:
                customers.append(cust)
            if newest is None and kid(more, 'requestorInfo') is not None:
                newest = more
            oid, until = text(st, 'orderID'), _when(text(st, 'productValidityDate'))
            if oid and text(st, 'orderStatus') == 'ENROLLED' and \
                    text(det, 'certificateStatus') in ('', 'VALID'):
                rows.append({'ref': oid, 'cn': text(det, 'commonName'),
                             'product': text(st, 'productCode'), 'paid_until': until,
                             'not_after': _when(text(det, 'endDate')),
                             'renewable': 'reissue' if until is None or until > now else 'order'})
        self.offer(out, 'customer', customers)
        if newest is not None:
            who = kid(newest, 'requestorInfo')
            lines = ['%s=%s' % (k, text(who, k)) for k in ('email', 'firstName', 'lastName',
                                                            'phone') if text(who, k)]
            if lines:
                out['sets']['requestor'] = lines
            tax = text(kid(newest, 'organizationInfo'), 'taxIdentificationNumber')
            if tax:
                out['sets']['tax_id'] = tax
        sc.reuse_choice(self, out, 'order_id', rows,
                        'Empty: the order acme made last for the certificate')
        return out
