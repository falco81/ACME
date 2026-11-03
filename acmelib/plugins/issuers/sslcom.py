# -*- coding: utf-8 -*-
"""
Certificates from SSL.com through its SSL Web Services (SWS) API: the request
(CSR) ordered (POST /certificates - a purchase, only when "Allow new orders
(paid)" is on) or rekeyed inside an order bought already (PUT
/certificate/{ref} - the call SSL.com documents for "process a voucher, rekey
an existing certificate order"), the domain validation (DCV) file SSL.com
answers with put in place by the certificate's own validation
(base.Challenge.place; acmelib/plugins/issuers/_dcv.py), the certificate read
from the order once it is issued. The account's orders are listed for
Certificates → Import from a source.

What the API is, and from where - SSL.com's own documents (read 2026-11):
the OpenAPI 3.0.1 description "SSL Web Services (SWS) API"
(https://api.swaggerhub.com/apis/SSL.com/ssl_certificate_api/1.0.0, embedded in
https://www.ssl.com/ssl-web-services-sws-api/) and the guide
https://www.ssl.com/guide/ssl-coms-sws-api-introduction/ :

* https://sws.sslpki.com (production), https://sws-test.sslpki.com (sandbox, an
  account of its own), JSON. account_key and secret_key in the query of a GET,
  in the JSON body of a POST, PUT and DELETE (the guide's examples).
* An error: 4xx with {"errors": {...}} (GET) or {"response_type": "ERROR",
  "response_code": 400, "message": {...}}.
* POST /certificates {product (100 EV UCC, 101 UCC, 102 EV, 103 High Assurance,
  104 Free, 105 Wildcard, 106 Basic, 107 Premium), period (days: 365, 730, 1095,
  1461, 1826; 30 or 90 for Free), csr, server_software, domains {NAME: {dcv:
  HTTP_CSR_HASH | an e-mail address}}, contacts {all {first_name, last_name,
  email, phone, country}}} -> {ref, order_status, ...} (the price taken from the
  account).
* PUT /certificate/{ref} {csr, server_software, domains} - the order (or voucher)
  processed or rekeyed with this CSR.
* GET /certificate/{ref}/validations/methods -> {dcv_methods {NAME {email_addresses,
  http_csr_hash {http (http://NAME/.well-known/pki-validation/MD5.txt), contents},
  cname_csr_hash {name, value}}}}.
* GET /certificate/{ref}?response_type=individually|pkcs7&response_encoding=base64
  -> {order_status ("validation required", "validating, please wait", "issued"...),
  certificates (one string), common_name, subject_alternative_names,
  effective_date, expiration_date, description, product}.
* GET /certificates?per_page=N&page=M -> [{ref, description, order_status,
  order_date}] (no total: until a page comes short).
* DELETE /certificate/{ref} {reason, serials [colon hex]} - without serials every
  certificate of the order is revoked, so the serial is always sent.

LESS CERTAIN (the documents leave it open): the DNS CNAME method is not offered -
its record is answered (cname_csr_hash), but the value to ask for it in "dcv" is
not documented (only HTTP_CSR_HASH and e-mail addresses are); no call asks SSL.com
to look at the validation now (it looks by itself; the order is read again); the
list of order_status values (those of the examples are used, anything with
"revoked", "expired", "cancel" or "reject" is the end); whether "certificates"
holds the chain (when it holds one certificate, the pkcs7 form is read for the
chain); the names of the organization fields (only DV certificates are asked for -
OV/EV take them from the CSR); a renewal call (none documented: a renewal is a
rekey inside the order, or a new order).
"""
from __future__ import annotations

import datetime
import json
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

ENDPOINTS = {'production': 'https://sws.sslpki.com', 'sandbox': 'https://sws-test.sslpki.com'}
# The SSL products of the product field (openapi.json, POST /certificates "product").
PRODUCTS = [('106', 'Basic SSL'), ('107', 'Premium SSL (multi-domain)'),
            ('105', 'Wildcard SSL'), ('103', 'High Assurance SSL (OV)'),
            ('101', 'UCC SSL (multi-domain)'), ('100', 'EV UCC SSL (multi-domain)'),
            ('102', 'EV SSL'), ('104', 'Free SSL (30 or 90 days)')]
MULTI = ('100', '102', '107')       # "Multiple domains can only be listed for ... 100, 102, 107"
ISSUED = ('issued',)
DEAD = ('revoked', 'expired', 'cancel', 'reject', 'refund')
MAILBOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')


def _when(v):
    """'2019-05-03T11:22:37.000-05:00' as epoch, or None."""
    s = str(v or '').strip()
    if not s:
        return None
    try:
        d = datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return int(d.timestamp())


def _flat(o, key=''):
    """{"login": ["account_key not found"]} as 'login: account_key not found'."""
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            got = _flat(v, k)
            if got:
                out.append(got)
    elif isinstance(o, list):
        out = [_flat(x, key) for x in o if _flat(x, key)]
        return '; '.join(out)
    elif o not in (None, ''):
        return ('%s: %s' % (key, o)) if key else str(o)
    return '; '.join(out)[:400]


def _dead(status):
    s = str(status or '').lower()
    return any(w in s for w in DEAD)


class SslComIssuer(Issuer):
    kind = 'sslcom'
    title = 'SSL.com (SWS API)'
    description = ('Certificates bought through SSL.com\'s SWS API: ordered (only when paid '
                   'orders are allowed) or rekeyed inside an order bought already, the domain '
                   'validation file put in place by the certificate\'s validation (or an '
                   'e-mail). Lists the account\'s orders for importing.')
    vendor = 'SSL.com'
    doc = 'docs/sources.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('http-01',)
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # GET /certificates + GET /certificate/{ref}: Import
    dcv_field = 'dcv'
    dcv_default = 'http'
    dcv = {
        'http': {'proof': 'http-file-any', 'words': 'HTTP file (HTTP_CSR_HASH)',
                 'record': 'http://NAME/.well-known/pki-validation/MD5.txt holding SSL.com\'s '
                           'lines'},
        'email': {'proof': None, 'words': 'E-mail (a person approves)',
                  'record': 'an e-mail to an approver address of the domain (admin@, '
                            'hostmaster@…)'},
    }
    fields = [
        field('account_key', 'Account key', 'secret', required=True,
              help='SSL.com dashboard → API credentials: the account_key.'),
        field('secret_key', 'Secret key', 'secret', required=True,
              help='The secret_key beside it. Neither is written into a job\'s steps.'),
        field('environment', 'Environment', 'select', default='production',
              options=[['production', 'Production (sws.sslpki.com)'],
                       ['sandbox', 'Sandbox (sws-test.sslpki.com - an account of its own)']]),
        field('order_ref', 'Order to reuse', 'text', placeholder='co-ac1ecm200',
              help='An order (or voucher) bought already: its certificate is rekeyed with acme\'s '
                   'request. Empty: the order acme made last for the certificate.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only rekeys inside orders bought already, '
                   'and stops with words where a purchase would be needed.'),
        field('product', 'Product of a new order', 'catalog', catalog='products',
              placeholder='106',
              help='Load the list: the SSL products SSL.com documents - a code can be typed too. '
                   'Only 100, 102 and 107 take more than one name.'),
        field('period', 'Period of a new order (days)', 'select', default='365',
              options=[['365', '365 days'], ['730', '730 days'], ['1095', '1095 days'],
                       ['1461', '1461 days'], ['1826', '1826 days'],
                       ['90', '90 days (Free SSL)'], ['30', '30 days (Free SSL)']]),
        field('server_software', 'Server software (code)', 'number', default=1, advanced=True,
              help='server_software of SSL.com\'s list (1: OTHER).'),
        field('dcv', 'Domain validation (DCV)', 'select', default='http',
              options=[['http', 'HTTP file in /.well-known/pki-validation/ (by the '
                                'certificate\'s HTTP validation; no wildcards)'],
                       ['email', 'E-mail to an approver address of the domain']],
              help='How SSL.com checks the domains. A DNS method is not offered: its value is '
                   'not documented.'),
        field('approver', 'Approver mailbox', 'select', default='admin',
              options=[['admin', 'admin@'], ['administrator', 'administrator@'],
                       ['hostmaster', 'hostmaster@'], ['postmaster', 'postmaster@'],
                       ['webmaster', 'webmaster@']],
              show_if={'dcv': ['email']},
              help='The address of each domain SSL.com writes to.'),
        field('contact_firstname', 'Contact: first name', 'text', required=True),
        field('contact_lastname', 'Contact: last name', 'text', required=True),
        field('contact_email', 'Contact: e-mail', 'text', required=True),
        field('contact_phone', 'Contact: phone', 'text', required=True, placeholder='+420123456789'),
        field('contact_country', 'Contact: country', 'text', default='CZ', placeholder='CZ'),
        field('api_url', 'API address', 'text', advanced=True,
              placeholder='https://sws.sslpki.com',
              help='Empty: the one of the environment.'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600, advanced=True,
              help='Longer: it is asked for again at the next try - nothing is ordered twice.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=30, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep

    # -- the API ---------------------------------------------------------------------------
    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _base(self):
        url = (self._s('api_url') or ENDPOINTS.get(self._s('environment') or 'production') or
               ENDPOINTS['production']).rstrip('/')
        if not re.match(r'^https://[^\s/]+(/\S*)?\Z', url):
            raise PluginError('the SSL.com API address is not an https address', retry=False)
        return url

    def _hide(self, words):
        out = str(words)
        for k in ('account_key', 'secret_key'):
            v = self._s(k)
            if v:
                out = out.replace(v, '********').replace(urllib.parse.quote(v, safe=''),
                                                         '********')
        return out

    def call(self, method, path, body=None, query=None, what=''):
        """SSL.com's answer (a dict or a list), or a PluginError in words."""
        if not self._s('account_key') or not self._s('secret_key'):
            raise PluginError('set the account key and the secret key', retry=False)
        keys = {'account_key': self._s('account_key'), 'secret_key': self._s('secret_key')}
        q = dict(query or {})
        if method == 'GET':
            q.update(keys)
            data_in = None
        else:
            data_in = dict(body or {})
            data_in.update(keys)
        url = self._base() + path + ('?' + urllib.parse.urlencode(q) if q else '')
        try:
            status, _h, data = sc.http(self.ctx, method, url, data_in, None, who='SSL.com')
        except PluginError as e:
            raise PluginError(self._hide(e), retry=e.retry)
        got = sc.parse_json(data)
        said = self._hide((data or b'').decode('utf-8', 'replace'))
        bad = isinstance(got, dict) and (
            str(got.get('response_type') or '').upper() == 'ERROR' or
            (got.get('errors') not in (None, [], {}, '')))
        if status >= 400 or bad:
            err = got.get('errors') if isinstance(got, dict) and got.get('errors') else \
                (got.get('message') if isinstance(got, dict) else None)
            words = self._hide(_flat(err) if err else sc.said_of(got, data))
            wrong = 'account_key' in words or 'secret_key' in words or status in (401, 403)
            raise PluginError('SSL.com refused %s: %s%s' % (
                what or path, words or ('HTTP %s' % status),
                ' - the account key or secret key is wrong' if wrong else ''),
                detail=said[:3000], retry=status >= 500 or status == 429)
        if got is None and method == 'GET':
            raise PluginError('SSL.com answered %s to %s, and not in JSON' % (status, what or path),
                              detail=said[:3000], retry=status >= 500)
        return got if got is not None else {}

    @staticmethod
    def _ref(v):
        v = str(v or '').strip()
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9-]{3,40}\Z', v):
            raise PluginError('"%s" is not an SSL.com order reference' % v, retry=False)
        return v

    def order(self, ref, response_type=None):
        q = {'response_type': response_type, 'response_encoding': 'base64'} if response_type \
            else None
        got = self.call('GET', '/certificate/%s' % self._ref(ref), query=q,
                        what='the order %s' % ref)
        return got if isinstance(got, dict) else {}

    # -- the products (the form's list) ------------------------------------------------------
    def catalog(self, key):
        """The SSL products of SSL.com's API description (no call lists them)."""
        if key != 'products':
            raise PluginError('there is no list called %s here' % key, retry=False)
        return {'options': [[c, '%s - %s' % (c, w)] for c, w in PRODUCTS],
                'said': '%d SSL products (SSL.com\'s documented list)' % len(PRODUCTS)}

    def test(self):
        got = self.call('GET', '/certificates', query={'per_page': 1, 'page': 1},
                        what='the list of orders')
        n = len(self._rows(got))
        return 'SSL.com answers: the keys are let in (%s); new paid orders %s' % (
            'orders found' if n else 'no orders yet',
            'ALLOWED' if sc.as_bool(self.c('allow_paid')) else 'not allowed')

    # -- the order ---------------------------------------------------------------------------
    def _domains(self, req):
        how = self.c('dcv') or 'http'
        box = self.c('approver') if self.c('approver') in MAILBOXES else 'admin'
        out = {}
        for n in req.names:
            out[n] = {'dcv': ('%s@%s' % (box, _dcv.base_of(n))) if how == 'email'
                      else 'HTTP_CSR_HASH'}
        return out

    def _contacts(self):
        c = {}
        for k, f in (('first_name', 'contact_firstname'), ('last_name', 'contact_lastname'),
                     ('email', 'contact_email'), ('phone', 'contact_phone')):
            v = self._s(f)
            if not v:
                raise PluginError('set the contact (first and last name, e-mail, phone)',
                                  retry=False)
            c[k] = v
        c['country'] = self._s('contact_country') or 'CZ'
        return {'all': c}

    def _new_body(self, req):
        product = self._s('product')
        if not re.match(r'^\d{3}\Z', product):
            raise PluginError('set the product of a new order (its code - Load the list)',
                              retry=False)
        if len(req.names) > 1 and product not in MULTI:
            raise PluginError('the product %s takes one name only - SSL.com lists more than one '
                              'only for 100, 102 and 107' % product, retry=False)
        return {'product': product, 'period': self._s('period') or '365',
                'csr': sc.csr_pem(req).strip(),
                'server_software': int(sc.num(self.c('server_software'), 1)),
                'domains': self._domains(req), 'contacts': self._contacts()}

    def _order(self, req, kept):
        """(how, ref, the answer)."""
        ref = str(getattr(req, 'ref', None) or '').strip() or self._s('order_ref') or \
            str((kept or {}).get('id') or '')
        why = 'there is no order to rekey (set "Order to reuse")'
        if ref:
            st = self.order(ref)
            s = str(st.get('order_status') or '').lower()
            end = _when(st.get('expiration_date'))
            if not _dead(s) and (end is None or end > time.time() + 86400):
                got = self.call('PUT', '/certificate/%s' % self._ref(ref), {
                    'csr': sc.csr_pem(req).strip(),
                    'server_software': int(sc.num(self.c('server_software'), 1)),
                    'domains': self._domains(req)}, what='the rekey of order %s' % ref)
                sc.say(self.ctx, 'the order %s is rekeyed with acme\'s request (no new purchase)'
                       % ref, 'ok')
                return 'reissue', str((got or {}).get('ref') or ref), got
            why = 'the order %s is %s' % (ref, s or ('expired' if end else '?'))
        if not sc.as_bool(self.c('allow_paid')):
            raise PluginError('nothing ordered: %s, and paid orders are not allowed for this '
                              'source - set "Order to reuse" to an order you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        body = self._new_body(req)
        sc.say(self.ctx, '%s - a new order is made (paid: allowed for this source)' % why, 'warn')
        got = self.call('POST', '/certificates', body, what='the new order')
        ref = str((got or {}).get('ref') or '')
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9-]{3,40}\Z', ref):
            raise PluginError('SSL.com took the order but said no reference - look in the SSL.com '
                              'dashboard before trying again (a second order would be paid '
                              'again)', retry=False)
        sc.say(self.ctx, 'order %s made at SSL.com: product %s for %s (%s)' % (
            ref, body['product'], ', '.join(req.names), got.get('order_amount') or '?'), 'ok')
        return 'new', ref, got

    def dcv_records(self, req, methods):
        recs = []
        per = (methods or {}).get('dcv_methods') if isinstance(methods, dict) else None
        for name, v in (per.items() if isinstance(per, dict) else []):
            h = (v or {}).get('http_csr_hash') if isinstance(v, dict) else None
            if not isinstance(h, dict):
                continue
            u = urllib.parse.urlsplit(str(h.get('http') or ''))
            content = str(h.get('contents') or '').replace('\r\n', '\n')
            if u.path.startswith('/.well-known/pki-validation/') and content:
                rec = {'domain': (u.hostname or _dcv.base_of(name)).lower(), 'type': 'file',
                       'path': u.path, 'value': content}
                if rec not in recs:
                    recs.append(rec)
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
        how = self.c('dcv') or 'http'
        if how == 'http' and any(n.startswith('*.') for n in req.names):
            raise PluginError('a wildcard name is proved by e-mail here, not by an HTTP file - '
                              'choose the e-mail validation', retry=False)
        ck = str(req.cert_id or '') or sc.pending_slot('x', '', req).split(':')[-1]
        made_key = 'sslcom-order:%s' % ck
        slot = sc.pending_slot('sslcom', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        if held:
            ref = held['id']
            sc.say(self.ctx, 'the order %s waits at SSL.com since %s - asked for again, nothing '
                             'is ordered' % (ref, time.strftime('%Y-%m-%d %H:%M',
                                                                time.gmtime(held.get('at') or 0))))
            if held.get('recs') and not held.get('dcv'):
                if self._place(req, slot, held, placer, held['recs']):
                    placer.wait_visible(req, held['dcv'])
            elif held.get('dcv'):
                placer.refresh(req, held['dcv'])
        else:
            kept = sc.parse_json(self.ctx.kv_get(made_key) or '') or {}
            kind, ref, _got = self._order(req, kept)
            if kind == 'new':
                self.ctx.kv_set(made_key, json.dumps({'id': ref, 'at': time.time()}),
                                ttl_s=5 * 366 * 86400)
            held = sc.pending_put(self.ctx, slot, req, {'id': ref, 'how': kind, 'dcv': [],
                                                        'csr_pem': sc.csr_pem(req)}, ttl_days=90)
            r = req
            if how == 'email':
                sc.say(self.ctx, 'SSL.com mails %s - someone there approves the certificate' %
                       ', '.join(v['dcv'] for v in self._domains(req).values()))
            else:
                methods = self.call('GET', '/certificate/%s/validations/methods' % self._ref(ref),
                                    what='the validation of order %s' % ref)
                recs = self.dcv_records(req, methods)
                if not recs:
                    raise PluginError('SSL.com said no validation file for order %s' % ref)
                if self._place(req, slot, held, placer, recs):
                    placer.wait_visible(req, held['dcv'])
                sc.say(self.ctx, 'the validation files are in place - SSL.com looks at them by '
                                 'itself')
        return self._await(r, req, slot, held, placer)

    def _certs(self, ref, st):
        """(certificates, chain) of an issued order: 'certificates' as it comes, the
        pkcs7 form read too when that holds the certificate alone."""
        certs = sc.certs_of(st.get('certificates') or '')
        chain = []
        if len(certs) <= 1:
            try:
                chain = sc.certs_of(self.order(ref, 'pkcs7').get('certificates') or '')
            except PluginError as e:
                sc.say(self.ctx, 'the chain could not be read (%s)' % e, 'warn')
        return certs, chain

    def _await(self, r, req, slot, held, placer):
        ref = held['id']
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 30))
        while True:
            st = self.order(ref, 'individually')
            s = str(st.get('order_status') or '').lower()
            if s in ISSUED and st.get('certificates'):
                certs, chain = self._certs(ref, st)
                try:
                    out = sc.finish(self.ctx, r, certs, chain, who='SSL.com',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'sslcom_ref': ref, 'ref': ref})
                except PluginError:
                    out = None              # the order's old certificate still: the rekey waits
                if out is not None:
                    placer.cleanup(req, held.get('dcv') or [])
                    sc.pending_drop(self.ctx, slot)
                    self.ctx.kv_set('sslcom-cert:%s' % sc.fingerprint(out.cert_pem)[:40], ref,
                                    ttl_s=5 * 366 * 86400)
                    if getattr(req, 'cert_id', None):
                        self.ctx.kv_set('sslcom-order:%s' % req.cert_id,
                                        json.dumps({'id': ref, 'at': time.time()}),
                                        ttl_s=5 * 366 * 86400)
                    return out
            elif _dead(s):
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('SSL.com did not issue: the order %s is %s' % (ref, s),
                                  retry=False)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('SSL.com has not issued yet (order %s: %s) - the validation '
                                  'files stay in place; acme asks again at the next try' % (
                                      ref, s or '?'))
            self._sleep(every)

    # -- revocation -------------------------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        ref = self.ctx.kv_get('sslcom-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if not ref:
            raise PluginError('acme does not know the certificate\'s order at SSL.com - revoke it '
                              'in the SSL.com dashboard', retry=False)
        serial = sc.serial_hex(cert_pem, ':').lower()
        why = sc.REASON_NAMES.get(sc.reason_code(reason), 'unspecified')
        self.call('DELETE', '/certificate/%s' % self._ref(ref),
                  {'reason': why, 'serials': [serial]}, what='the revocation')
        return 'SSL.com revoked serial %s of order %s (%s)' % (serial, ref, why)

    # -- the orders of the account (Certificates → Import from a source) ---------------------
    READ_MOST = 150                 # orders read one by one in a listing

    @staticmethod
    def _rows(got):
        if isinstance(got, list):
            return [x for x in got if isinstance(x, dict)]
        if isinstance(got, dict) and isinstance(got.get('arrayOfObjects'), list):
            return [x for x in got['arrayOfObjects'] if isinstance(x, dict)]
        return []

    def _acme_ids(self):
        out = {}
        try:
            kept = self.ctx.kv_keys('sslcom-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('id') and cid.isdigit():
                out[str(v['id'])] = int(cid)
        return out

    def list_existing(self):
        """The account's orders (GET /certificates, page by page), the issued ones read
        one by one - read only."""
        mine = self._acme_ids()
        rows, per = [], 100
        for page in range(1, 101):
            got = self.call('GET', '/certificates', query={'per_page': per, 'page': page},
                            what='the list of orders')
            items = self._rows(got)
            rows += items
            if len(items) < per or self.ctx.cancelled():
                break
        out, read = [], 0
        for o in rows:
            ref = str(o.get('ref') or '').strip()
            s = str(o.get('order_status') or '').lower()
            if not ref:
                continue
            item = {'ref': ref, 'cn': '', 'names': [], 'product': str(o.get('description') or ''),
                    'status': s or '?', 'downloadable': False,
                    'renewable': 'order' if _dead(s) else 'reissue',
                    'note': '' if s in ISSUED else 'SSL.com says it is %s' % (s or '?'),
                    'acme_cert_id': mine.get(ref)}
            if s in ISSUED and read < self.READ_MOST and not self.ctx.cancelled():
                read += 1
                try:
                    st = self.order(ref)
                except PluginError as e:
                    item['note'] = 'it cannot be read: %s' % e
                    out.append(item)
                    continue
                cn = str(st.get('common_name') or '').strip()
                names = [cn] + [str(x).strip() for x in st.get('subject_alternative_names') or []]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                item.update({'cn': cn, 'names': names,
                             'product': str(st.get('description') or item['product']),
                             'not_before': _when(st.get('effective_date')),
                             'not_after': _when(st.get('expiration_date')),
                             'downloadable': bool(st.get('certificates'))})
            elif s in ISSUED:
                item.update({'downloadable': True,
                             'note': 'more than %d orders: this one is read when it is imported'
                                     % self.READ_MOST})
            out.append(item)
        return out

    def fetch_existing(self, ref):
        """The certificate of order `ref` and its chain - read only."""
        ref = self._ref(ref)
        st = self.order(ref, 'individually')
        if not st.get('certificates'):
            raise PluginError('the order %s has no certificate (it is %s)' % (
                ref, st.get('order_status') or '?'), retry=False)
        certs, chain = self._certs(ref, st)
        out = sc.existing(certs, chain, who='SSL.com', ref=ref)
        self.ctx.kv_set('sslcom-cert:%s' % sc.fingerprint(out['cert_pem'])[:40], ref,
                        ttl_s=5 * 366 * 86400)
        out['acme_cert_id'] = self._acme_ids().get(ref)
        return out
