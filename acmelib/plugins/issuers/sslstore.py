# -*- coding: utf-8 -*-
"""
Certificates from The SSL Store (TheSSLStore.com, the reseller) through its REST
API: the request (CSR) reissued inside an order bought already, or ordered (a
purchase, only when "Allow new orders (paid)" is on), the domain validation
(DCV) record or file the order answers with put in place by the certificate's
own validation (base.Challenge.place; acmelib/plugins/issuers/_dcv.py), the
certificate downloaded once the order is complete. The account's orders are
listed for Certificates → Import from a source.

What the API is, and from where - The SSL Store's own documents (read 2026-11):
its OpenAPI 3.0.4 description, served by the API itself
(https://api.thesslstore.com/swagger/v1/swagger.json; the sandbox's at
https://sandbox-wbapi.thesslstore.com/swagger/v1/swagger.json), and the REST API
Guide https://www.thesslstore.com/api/ (read from its copies in the Wayback
Machine - the live site refuses scripts): where the two differ, swagger.json is
followed.

* https://api.thesslstore.com/rest (live), https://api.thesslstore.eu/rest (live,
  Europe), https://sandbox-wbapi.thesslstore.com/rest (sandbox); every call a POST of
  JSON with AuthRequest {PartnerCode, AuthToken} inside the body.
* An error is HTTP 200 with AuthResponse {isError: true, Message [..]} - in the
  answer, or as the answer (certificaterevokerequest, health/validate).
* POST /health/validate - the partner code and token checked (Try it).
* POST /product/query {ProductCode?} -> [{ProductCode, ProductName, isDVProduct,
  isOVProduct, isEVProduct, isWildcard, PricingInfo [{NumberOfMonths}]}].
* POST /order/neworder {CustomOrderID, ProductCode, ValidityPeriod (months),
  ServerCount, CSR, DomainName, DNSNames [..], WebServerType, isCUOrder,
  isRenewalOrder, isTrialOrder, AdminContact, TechnicalContact {FirstName,
  LastName, Phone, Email, Title}, ApproverEmail, FileAuthDVIndicator,
  CNAMEAuthDVIndicator, HTTPSFileAuthDVIndicator} -> OrderResponse
  {TheSSLStoreOrderID, OrderStatus {MajorStatus, MinorStatus,
  DomainAuthVettingStatus [{domain, dcvMethod, FileName, FileContents, DNSName,
  DNSEntry}]}, AuthFileName, AuthFileContent, CNAMEAuthName, CNAMEAuthValue}.
* POST /order/approverlist (the NewOrderRequest) -> {ApproverEmailList} - "You must
  have to call /order/approverlist/ API method before passing the value in
  ApproverEmail field for COMODO Products".
* POST /order/reissue {TheSSLStoreOrderID, CSR, WebServerType, isWildCard,
  ReissueEmail, AddSAN / DeleteSAN [{OldValue, NewValue}], FileAuthDVIndicator,
  CNAMEAuthDVIndicator, ApproverEmails, PreferEnrollmentLink false} -> OrderResponse.
* POST /order/info {TheSSLStoreOrderID} -> OrderResponse (refreshed every 5
  minutes; /order/status is deprecated). MajorStatus PENDING, ACTIVE / COMPLETE,
  CANCELLED, EXPIRED, INITIAL.
* POST /order/certificate/download {TheSSLStoreOrderID} -> {CertificateStatus,
  Certificates [{FileName, FileContent}]}.
* POST /order/certificaterevokerequest {TheSSLStoreOrderID, RevokeReason}.
* POST /order/query {StartDate, EndDate ("/Date(ms)/"), PageNumber, PageSize
  (at most 999)} -> [OrderResponse] (no total: until a page comes short).

LESS CERTAIN (the documents leave it open or disagree): the download's path -
swagger.json's /order/certificate/download is used (its own text and the guide say
/order/download, asked when the first answers 404); the word for done - ACTIVE (the
guide, the examples) or COMPLETE (swagger.json's text): both are taken; the shape of
DNSName and FileName (a name ending in the domain is used as it is, a bare label
gets the domain; a bare file name goes under /.well-known/pki-validation/); whether
the CSR must be URL-encoded in JSON ("both base64 and URI encoded") - it is sent as
PEM, as swagger.json's example shows it; what ApproverEmail holds for a CNAME or file
validation (not sent); the values of WebServerType (a setting, "Other"); the exact
meaning of AddSAN/DeleteSAN pairs in a reissue (an added name {OldValue "",
NewValue NAME}, a removed one {OldValue NAME, NewValue ""}). No call asks the CA to
look at the validation now for other than DigiCert products: the order is read
again. A renewal order (isRenewalOrder, RelatedTheSSLStoreOrderID) is not made - a
new order is (only with "Allow new orders (paid)").
"""
from __future__ import annotations

import calendar
import hashlib
import json
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Plugin, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

ENDPOINTS = {'live': 'https://api.thesslstore.com/rest',
             'live_eu': 'https://api.thesslstore.eu/rest',
             'sandbox': 'https://sandbox-wbapi.thesslstore.com/rest'}
DONE = ('active', 'complete', 'completed')
FAILED = ('cancelled', 'canceled', 'expired', 'rejected')
MAILBOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')
FILE_DIR = '/.well-known/pki-validation/'


def _when(v):
    """'1/15/2025 10:30:00 AM' (or ISO) as epoch, or None."""
    s = str(v or '').strip()
    for fmt in ('%m/%d/%Y %I:%M:%S %p', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d'):
        try:
            return calendar.timegm(time.strptime(s, fmt))
        except ValueError:
            continue
    return None


def _ms_date(epoch):
    return '/Date(%d)/' % int(epoch * 1000)


class SslStoreIssuer(Issuer):
    kind = 'sslstore'
    title = 'The SSL Store (REST API)'
    description = ('Certificates bought through The SSL Store\'s REST API: reissued inside an '
                   'order bought already, or ordered (only when paid orders are allowed), the '
                   'domain validation record or file put in place by the certificate\'s '
                   'validation. Lists the account\'s orders for importing.')
    vendor = 'The SSL Store'
    doc = 'docs/sources.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # order/query + order/certificate/download: Import
    dcv_field = 'dcv'
    dcv_default = 'cname'
    dcv = {
        'cname': {'proof': 'cname-any', 'words': 'DNS CNAME record (CNAMEAuthDVIndicator)',
                  'record': 'CNAME at the name the order says (DNSName) to its target (DNSEntry)'},
        'http': {'proof': 'http-file-any', 'words': 'HTTP file (FileAuthDVIndicator)',
                 'record': 'http://NAME/.well-known/pki-validation/FILE holding the order\'s '
                           'lines'},
        'email': {'proof': None, 'words': 'E-mail (a person approves)',
                  'record': 'an e-mail to an approver address of the domain (admin@, '
                            'hostmaster@…)'},
    }
    fields = [
        field('partner_code', 'Partner code', 'text', required=True,
              help='The SSL Store account → API Settings: the partner code.'),
        field('auth_token', 'Auth token', 'secret', required=True,
              help='The API auth token made in API Settings. Never written into a job\'s steps.'),
        field('environment', 'Environment', 'select', default='live',
              options=[['live', 'Live (api.thesslstore.com)'],
                       ['live_eu', 'Live, Europe (api.thesslstore.eu)'],
                       ['sandbox', 'Sandbox (sandbox-wbapi.thesslstore.com - dummy products)']]),
        field('order_id', 'Order to reuse', 'text', placeholder='TSSL-9876543',
              help='TheSSLStoreOrderID of an order bought already: its certificate is reissued '
                   '(free). Empty: the order acme made last for the certificate.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders bought '
                   'already, and stops with words where a purchase would be needed.'),
        field('product', 'Product of a new order', 'catalog', catalog='products',
              placeholder='positivessl', depends=['partner_code', 'auth_token', 'environment'],
              help='Load the list: the products of the account (product/query) - a product code '
                   'can be typed too.'),
        field('validity', 'Validity of a new order (months)', 'select', default='12',
              options=[['12', '12 months'], ['24', '24 months'], ['36', '36 months'],
                       ['48', '48 months'], ['60', '60 months']],
              help='ValidityPeriod: one of the product\'s NumberOfMonths.'),
        field('server_count', 'Server licences', 'number', default=1, advanced=True),
        field('web_server', 'Web server type', 'text', default='Other', advanced=True,
              help='WebServerType of the order and the reissue.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='cname',
              options=[['cname', 'DNS CNAME record (by the certificate\'s DNS validation)'],
                       ['http', 'HTTP file in /.well-known/pki-validation/ (by the '
                                'certificate\'s HTTP validation; no wildcards)'],
                       ['email', 'E-mail to an approver address of the domain']],
              help='How the CA checks the domains. The certificate\'s validation must be able '
                   'to put that record or file in place - the wizard offers only those that '
                   'can.'),
        field('approver', 'Approver mailbox', 'select', default='admin',
              options=[['admin', 'admin@'], ['administrator', 'administrator@'],
                       ['hostmaster', 'hostmaster@'], ['postmaster', 'postmaster@'],
                       ['webmaster', 'webmaster@'], ['first', 'the first address offered']],
              show_if={'dcv': ['email']},
              help='Picked from the addresses the order offers (order/approverlist).'),
        field('contact_firstname', 'Contact: first name', 'text', required=True),
        field('contact_lastname', 'Contact: last name', 'text', required=True),
        field('contact_phone', 'Contact: phone', 'text', required=True, placeholder='420123456789',
              help='Numbers only, as The SSL Store asks.'),
        field('contact_email', 'Contact: e-mail', 'text', required=True),
        field('contact_title', 'Contact: title', 'text', default='IT'),
        field('api_url', 'API address', 'text', advanced=True,
              placeholder='https://api.thesslstore.com/rest',
              help='Empty: the one of the environment.'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600, advanced=True,
              help='Longer: it is asked for again at the next try - nothing is ordered twice. '
                   'The order\'s details are refreshed every 5 minutes.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=60, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep

    # -- the API ---------------------------------------------------------------------------
    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _base(self):
        url = (self._s('api_url') or ENDPOINTS.get(self._s('environment') or 'live') or
               ENDPOINTS['live']).rstrip('/')
        if not re.match(r'^https://[^\s/]+(/\S*)?\Z', url):
            raise PluginError('The SSL Store API address is not an https address', retry=False)
        return url

    def _hide(self, words):
        v = self._s('auth_token')
        return str(words).replace(v, '********') if v else str(words)

    @staticmethod
    def _auth_of(got):
        if isinstance(got, list):
            got = got[0] if got and isinstance(got[0], dict) else {}
        if not isinstance(got, dict):
            return {}
        a = got.get('AuthResponse')
        return a if isinstance(a, dict) else (got if 'isError' in got else {})

    def call(self, path, body=None, what='', ok404=False):
        """The answer of The SSL Store (a dict or a list), or a PluginError in words."""
        if not self._s('partner_code') or not self._s('auth_token'):
            raise PluginError('set the partner code and the auth token', retry=False)
        b = dict(body or {})
        b['AuthRequest'] = {'PartnerCode': self._s('partner_code'),
                            'AuthToken': self._s('auth_token'), 'UserAgent': 'acme'}
        try:
            status, _h, data = sc.http(self.ctx, 'POST', self._base() + path, b, None,
                                       who='The SSL Store')
        except PluginError as e:
            raise PluginError(self._hide(e), retry=e.retry)
        if status == 404 and ok404:
            return None
        got = sc.parse_json(data)
        said = self._hide((data or b'').decode('utf-8', 'replace'))
        auth = self._auth_of(got)
        if auth.get('isError') in (True, 'true', 'True'):
            msg = auth.get('Message')
            words = '; '.join(str(m) for m in (msg if isinstance(msg, list) else [msg]) if m)
            wrong = re.search(r'-90(03|08|27)\b|authenticat|partnercode', words, re.I)
            raise PluginError('The SSL Store refused %s: %s%s' % (
                what or path, self._hide(words) or '?',
                ' - the partner code or auth token is wrong' if wrong else ''),
                detail=said[:3000], retry=False)
        if status >= 400 or got is None:
            raise sc.refusal('The SSL Store (%s)' % (what or path), status,
                             got if isinstance(got, dict) else None, said.encode(),
                             'the partner code or auth token is wrong')
        return got

    @staticmethod
    def _oid(v):
        v = str(v or '').strip()
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,40}\Z', v):
            raise PluginError('"%s" is not a TheSSLStoreOrderID' % v, retry=False)
        return v

    def info(self, oid):
        got = self.call('/order/info', {'TheSSLStoreOrderID': self._oid(oid)},
                        what='the order %s' % oid)
        return got if isinstance(got, dict) else {}

    @staticmethod
    def major(o):
        return str(((o or {}).get('OrderStatus') or {}).get('MajorStatus') or '').lower()

    def download(self, oid):
        body = {'TheSSLStoreOrderID': self._oid(oid)}
        got = self.call('/order/certificate/download', body, what='the download of %s' % oid,
                        ok404=True)
        if got is None:                 # the path the guide and the operation's text give
            got = self.call('/order/download', body, what='the download of %s' % oid)
        files = [f for f in (got or {}).get('Certificates') or [] if isinstance(f, dict)]
        return sc.certs_of([str(f.get('FileContent') or '') for f in files])

    # -- the products (the form's list) ------------------------------------------------------
    def catalog(self, key):
        """The products of the account: product/query. Read-only."""
        if key != 'products':
            raise PluginError('there is no list called %s here' % key, retry=False)
        got = self.call('/product/query', {}, what='the products')
        opts = []
        for p in got if isinstance(got, list) else []:
            if not isinstance(p, dict) or not p.get('ProductCode'):
                continue
            if p.get('isCodeSigning') or p.get('isSMIMEProduct') or p.get('isScanProduct'):
                continue
            kind = 'EV' if p.get('isEVProduct') else 'OV' if p.get('isOVProduct') else \
                'DV' if p.get('isDVProduct') else ''
            months = sorted({int(sc.num(x.get('NumberOfMonths'), 0)) for x in
                             p.get('PricingInfo') or [] if isinstance(x, dict)} - {0})
            words = '%s%s%s%s' % (p.get('ProductName') or p['ProductCode'],
                                  (' - ' + kind) if kind else '',
                                  ' - wildcard' if p.get('isWildcard') else '',
                                  (' (%s months)' % ', '.join(str(m) for m in months))
                                  if months else '')
            opts.append([str(p['ProductCode']), words])
        return {'options': opts, 'said': '%d SSL product(s)' % len(opts)}

    def test(self):
        self.call('/health/validate', {}, what='the partner code and token')
        return 'The SSL Store answers: the partner code and auth token are let in; new paid ' \
               'orders %s' % ('ALLOWED' if sc.as_bool(self.c('allow_paid')) else 'not allowed')

    # -- the order ---------------------------------------------------------------------------
    def _contact(self):
        c = {}
        for k, f in (('FirstName', 'contact_firstname'), ('LastName', 'contact_lastname'),
                     ('Phone', 'contact_phone'), ('Email', 'contact_email')):
            v = self._s(f)
            if not v:
                raise PluginError('set the contact (first and last name, phone, e-mail)',
                                  retry=False)
            c[k] = v
        c['Title'] = self._s('contact_title') or 'IT'
        return c

    def _dcv_flags(self):
        how = self.c('dcv') or 'cname'
        return {'FileAuthDVIndicator': how == 'http', 'CNAMEAuthDVIndicator': how == 'cname',
                'HTTPSFileAuthDVIndicator': False}

    def _approver(self, body, req):
        """The address of order/approverlist for the e-mail validation."""
        got = self.call('/order/approverlist', body, what='the approver addresses')
        offered = [str(x).strip() for x in (got or {}).get('ApproverEmailList') or []
                   if '@' in str(x)]
        if not offered:
            raise PluginError('The SSL Store offered no approver address for %s' % req.names[0],
                              retry=False)
        box = self.c('approver') or 'admin'
        pick = None
        if box in MAILBOXES:
            pick = next((a for a in offered if a.lower().startswith(box + '@')), None)
        return pick or offered[0]

    def _new_body(self, req):
        product = self._s('product')
        if not product or not re.match(r'^[A-Za-z0-9_.-]{1,60}\Z', product):
            raise PluginError('set the product of a new order (its code - Load the list)',
                              retry=False)
        contact = self._contact()
        body = {'CustomOrderID': 'acme-%s' % hashlib.sha256(
                    ('%s|%s' % (','.join(req.names), time.time())).encode()).hexdigest()[:20],
                'ProductCode': product, 'ValidityPeriod': int(sc.num(self.c('validity'), 12)),
                'ServerCount': int(sc.num(self.c('server_count'), 1)),
                'CSR': sc.csr_pem(req).strip(), 'DomainName': req.names[0],
                'DNSNames': list(req.names[1:]), 'WebServerType': self._s('web_server') or 'Other',
                'isCUOrder': False, 'isRenewalOrder': False, 'isTrialOrder': False,
                'AutoWWW': False, 'AdminContact': contact, 'TechnicalContact': dict(contact)}
        body.update(self._dcv_flags())
        if (self.c('dcv') or 'cname') == 'email':
            body['ApproverEmail'] = self._approver(body, req)
        return body

    def _names_of(self, o):
        cn = str((o or {}).get('CommonName') or '').strip().lower()
        more = (o or {}).get('DNSNames')
        more = more if isinstance(more, list) else str(more or '').split(',')
        names = [cn] + [str(x).strip().lower() for x in more]
        return [n for i, n in enumerate(names) if n and n not in names[:i]]

    def _order(self, req, kept):
        """(how, order id, the answer)."""
        oid = str(getattr(req, 'ref', None) or '').strip() or self._s('order_id') or \
            str((kept or {}).get('id') or '')
        why = 'there is no order to reissue in (set "Order to reuse")'
        if oid:
            o = self.info(oid)
            s = self.major(o)
            end = _when(o.get('CertificateEndDateInUTC')) or _when(o.get('OrderExpiryDateInUTC'))
            if s in DONE and (end is None or end > time.time() + 86400):
                old = self._names_of(o)
                want = [n.lower() for n in req.names]
                body = {'TheSSLStoreOrderID': self._oid(oid), 'CSR': sc.csr_pem(req).strip(),
                        'WebServerType': self._s('web_server') or 'Other',
                        'isWildCard': req.names[0].startswith('*.'),
                        'ReissueEmail': self._s('contact_email'), 'PreferEnrollmentLink': False,
                        'AddSAN': [{'OldValue': '', 'NewValue': n} for n in want[1:]
                                   if n not in old],
                        'DeleteSAN': [{'OldValue': n, 'NewValue': ''} for n in old[1:]
                                      if n not in want]}
                if old and old[0] != want[0]:
                    raise PluginError('the order %s is for %s, the certificate for %s - a reissue '
                                      'keeps the common name; set another "Order to reuse"' % (
                                          oid, old[0], want[0]), retry=False)
                body.update(self._dcv_flags())
                if (self.c('dcv') or 'cname') == 'email':
                    box = self.c('approver') if self.c('approver') in MAILBOXES else 'admin'
                    body['ApproverEmails'] = ','.join('%s@%s' % (box, _dcv.base_of(n))
                                                      for n in req.names)
                got = self.call('/order/reissue', body, what='the reissue of order %s' % oid)
                sc.say(self.ctx, 'reissue inside order %s asked for (free)' % oid, 'ok')
                return 'reissue', str((got or {}).get('TheSSLStoreOrderID') or oid), got
            why = 'the order %s is %s' % (oid, s or '?')
        if not sc.as_bool(self.c('allow_paid')):
            raise PluginError('nothing ordered: %s, and paid orders are not allowed for this '
                              'source - set "Order to reuse" to an order you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        body = self._new_body(req)
        sc.say(self.ctx, '%s - a new order is made (paid: allowed for this source)' % why, 'warn')
        got = self.call('/order/neworder', body, what='the new order')
        oid = str((got or {}).get('TheSSLStoreOrderID') or '')
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,40}\Z', oid):
            raise PluginError('The SSL Store took the order but said no order ID - look in the '
                              'account (custom order ID %s) before trying again (a second order '
                              'would be paid again)' % body['CustomOrderID'], retry=False)
        sc.say(self.ctx, 'order %s made at The SSL Store: product %s for %s' % (
            oid, body['ProductCode'], ', '.join(req.names)), 'ok')
        return 'new', oid, got

    @staticmethod
    def _rec(domain, how, dns_name, dns_entry, file_name, file_content):
        d = _dcv.base_of(domain)
        if how == 'cname':
            name = str(dns_name or '').strip().rstrip('.').lower()
            target = str(dns_entry or '').strip().rstrip('.').lower()
            if not name or not target:
                return None
            if name != d and not name.endswith('.' + d):
                name = '%s.%s' % (name, d)
            return {'domain': d, 'type': 'cname', 'fqdn': name, 'value': target}
        if how == 'http':
            fn = str(file_name or '').strip()
            content = str(file_content or '').replace('\r\n', '\n')
            if not fn or not content:
                return None
            u = urllib.parse.urlsplit(fn)
            path = u.path if u.path.startswith('/') else FILE_DIR + fn.lstrip('/')
            if '/.well-known/' in path and not path.startswith('/.well-known/'):
                path = path[path.index('/.well-known/'):]
            if not path.startswith(FILE_DIR):
                path = FILE_DIR + path.rsplit('/', 1)[-1]
            return {'domain': (u.hostname or d).lower(), 'type': 'file', 'path': path,
                    'value': content}
        return None

    def dcv_records(self, req, o):
        how = self.c('dcv') or 'cname'
        recs = []
        vet = ((o or {}).get('OrderStatus') or {}).get('DomainAuthVettingStatus') or []
        for v in vet if isinstance(vet, list) else []:
            if not isinstance(v, dict):
                continue
            r = self._rec(v.get('domain') or v.get('DomainToValidate') or req.names[0], how,
                          v.get('DNSName'), v.get('DNSEntry'), v.get('FileName'),
                          v.get('FileContents'))
            if r and r not in recs:
                recs.append(r)
        if not recs:
            r = self._rec(req.names[0], how, (o or {}).get('CNAMEAuthName'),
                          (o or {}).get('CNAMEAuthValue'), (o or {}).get('AuthFileName'),
                          (o or {}).get('AuthFileContent'))
            if r:
                recs.append(r)
        return recs

    def _place(self, req, slot, held, placer, recs, ttl=90):
        held['recs'] = recs
        sc.pending_put(self.ctx, slot, req, held, ttl_days=ttl)
        held['dcv'] = placer.place_all(req, recs)
        sc.pending_put(self.ctx, slot, req, held, ttl_days=ttl)
        return any(p.get('how') == 'placed' for p in held['dcv'])

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        how = self.c('dcv') or 'cname'
        if how == 'http' and any(n.startswith('*.') for n in req.names):
            raise PluginError('a wildcard name is proved by DNS or e-mail, not by an HTTP file - '
                              'choose the DNS CNAME record', retry=False)
        ck = str(req.cert_id or '') or sc.pending_slot('x', '', req).split(':')[-1]
        made_key = 'sslstore-order:%s' % ck
        slot = sc.pending_slot('sslstore', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        if held:
            oid = held['id']
            sc.say(self.ctx, 'the order %s waits at The SSL Store since %s - asked for again, '
                             'nothing is ordered' % (oid, time.strftime(
                                 '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
            if held.get('recs') and not held.get('dcv'):
                if self._place(req, slot, held, placer, held['recs']):
                    placer.wait_visible(req, held['dcv'])
            elif held.get('dcv'):
                placer.refresh(req, held['dcv'])
        else:
            kept = sc.parse_json(self.ctx.kv_get(made_key) or '') or {}
            kind, oid, got = self._order(req, kept)
            if kind == 'new':
                self.ctx.kv_set(made_key, json.dumps({'id': oid, 'at': time.time()}),
                                ttl_s=5 * 366 * 86400)
            held = sc.pending_put(self.ctx, slot, req, {'id': oid, 'how': kind, 'dcv': [],
                                                        'csr_pem': sc.csr_pem(req)}, ttl_days=90)
            r = req
            if how == 'email':
                sc.say(self.ctx, 'the CA mails the approver address - someone there approves the '
                                 'certificate')
            else:
                recs = self.dcv_records(req, got)
                if not recs:
                    recs = self.dcv_records(req, self.info(oid))
                if not recs:
                    raise PluginError('The SSL Store said no DCV record or file for order %s - '
                                      'acme asks again at the next try' % oid)
                if self._place(req, slot, held, placer, recs):
                    placer.wait_visible(req, held['dcv'])
                sc.say(self.ctx, 'the DCV records are in place - the CA looks at them by itself')
        return self._await(r, req, slot, held, placer)

    def _await(self, r, req, slot, held, placer):
        oid = held['id']
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 60))
        while True:
            o = self.info(oid)
            s = self.major(o)
            if s in DONE:
                out = None
                try:
                    out = sc.finish(self.ctx, r, self.download(oid), who='The SSL Store',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'sslstore_order': oid, 'ref': oid})
                except PluginError as e:
                    if 'another key' not in str(e) and 'sent no certificate' not in str(e):
                        raise
                if out is not None:
                    placer.cleanup(req, held.get('dcv') or [])
                    sc.pending_drop(self.ctx, slot)
                    self.ctx.kv_set('sslstore-cert:%s' % sc.fingerprint(out.cert_pem)[:40], oid,
                                    ttl_s=5 * 366 * 86400)
                    if getattr(req, 'cert_id', None):
                        self.ctx.kv_set('sslstore-order:%s' % req.cert_id,
                                        json.dumps({'id': oid, 'at': time.time()}),
                                        ttl_s=5 * 366 * 86400)
                    return out
            elif s in FAILED:
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('The SSL Store did not issue: the order %s is %s' % (oid, s),
                                  retry=False)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('The SSL Store has not issued yet (order %s: %s) - the DCV '
                                  'records stay in place; acme asks again at the next try' % (
                                      oid, s or '?'))
            self._sleep(every)

    # -- revocation -------------------------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        oid = self.ctx.kv_get('sslstore-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if not oid:
            raise PluginError('acme does not know the certificate\'s order at The SSL Store - '
                              'revoke it in the account', retry=False)
        why = sc.REASON_NAMES.get(sc.reason_code(reason), 'unspecified')
        self.call('/order/certificaterevokerequest', {'TheSSLStoreOrderID': self._oid(oid),
                                                       'RevokeReason': why},
                  what='the revocation')
        return 'The SSL Store took the revocation of order %s (%s)' % (oid, why)

    # -- the orders of the account (Certificates → Import from a source) ---------------------
    def _acme_ids(self):
        out = {}
        try:
            kept = self.ctx.kv_keys('sslstore-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('id') and cid.isdigit():
                out[str(v['id'])] = int(cid)
        return out

    def list_existing(self):
        """The account's orders (order/query, page by page) - read only."""
        mine = self._acme_ids()
        out, per = [], 100
        start = calendar.timegm((2012, 1, 1, 0, 0, 0))
        for page in range(1, 101):
            got = self.call('/order/query', {'StartDate': _ms_date(start),
                                             'EndDate': _ms_date(time.time()),
                                             'PageNumber': page, 'PageSize': per},
                            what='the list of orders')
            items = [o for o in (got if isinstance(got, list) else []) if isinstance(o, dict)]
            for o in items:
                oid = str(o.get('TheSSLStoreOrderID') or '').strip()
                if not oid:
                    continue
                s = self.major(o)
                names = self._names_of(o)
                end = _when(o.get('CertificateEndDateInUTC'))
                out.append({'ref': oid, 'cn': names[0] if names else '', 'names': names,
                            'product': str(o.get('ProductName') or o.get('ProductCode') or ''),
                            'status': s or '?', 'serial': str(o.get('SerialNumber') or '')
                            .replace(':', '').upper() or None,
                            'not_before': _when(o.get('CertificateStartDateInUTC')),
                            'not_after': end,
                            'paid_until': _when(o.get('OrderExpiryDateInUTC')),
                            'downloadable': s in DONE,
                            'renewable': 'reissue' if s in DONE else 'order',
                            'note': '' if s in DONE else 'the order is %s' % (s or '?'),
                            'acme_cert_id': mine.get(oid)})
            if len(items) < per or self.ctx.cancelled():
                break
        return out

    def fetch_existing(self, ref):
        """The certificate of order `ref` and its chain (order/certificate/download) -
        read only."""
        oid = self._oid(ref)
        out = sc.existing(self.download(oid), who='The SSL Store', ref=oid)
        self.ctx.kv_set('sslstore-cert:%s' % sc.fingerprint(out['cert_pem'])[:40], oid,
                        ttl_s=5 * 366 * 86400)
        out['acme_cert_id'] = self._acme_ids().get(oid)
        return out

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['partner_code', 'auth_token', 'environment', 'api_url']

    def discover_setup(self):
        """Read-only: the products (the form's list), the orders of the account (order/query:
        one to reuse - never picked by itself) and, from the newest complete one (order/info),
        its contact and web server type."""
        out = Plugin.discover_setup(self)
        rows = self.list_existing()
        out['facts'].append(['Orders', str(len(rows))])
        sc.reuse_choice(self, out, 'order_id', rows,
                        'Empty: the order acme made last for the certificate')
        done = sorted((r for r in rows if r.get('downloadable')),
                      key=lambda r: r.get('not_after') or 0, reverse=True)
        for r in done[:3]:
            try:
                o = self.info(r['ref'])
            except PluginError as e:
                out['notes'].append('the order %s could not be read: %s' % (r['ref'], e))
                continue
            c = o.get('TechnicalContact') if isinstance(o.get('TechnicalContact'), dict) else {}
            if not c.get('Email'):
                c = o.get('AdminContact') if isinstance(o.get('AdminContact'), dict) else {}
            for mine, theirs in (('contact_firstname', 'FirstName'),
                                 ('contact_lastname', 'LastName'), ('contact_phone', 'Phone'),
                                 ('contact_email', 'Email'), ('contact_title', 'Title')):
                if str(c.get(theirs) or '').strip():
                    out['sets'][mine] = str(c[theirs]).strip()
            if str(o.get('WebServerType') or '').strip():
                out['sets']['web_server'] = str(o['WebServerType']).strip()
            if out['sets']:
                out['facts'].append(['Contacts taken from the order', r['ref']])
                break
        return out
