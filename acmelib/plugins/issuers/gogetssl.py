# -*- coding: utf-8 -*-
"""
Certificates from GoGetSSL (the reseller) through its API v1: the request (CSR)
ordered or reissued inside an order bought already, the domain validation (DCV)
record or file GoGetSSL answers with put in place by the certificate's own
validation (base.Challenge.place; acmelib/plugins/issuers/_dcv.py), the
certificate read from the order's status once it is active. A new order is a
purchase and is only made when "Allow new orders (paid)" is on. The account's
orders are listed for Certificates → Import from a source. GoGetSSL's API has
no revocation - an order can only be cancelled (the action "Cancel the order to
reuse").

What the API is, and from where - GoGetSSL's own documentation, published as
Postman collections (read 2026-11): https://doc-v1.gogetssl.com
(https://documenter.getpostman.com/view/5593375/T1LHFp7m) and
https://doc-v2.gogetssl.com:

* https://my.gogetssl.com/api/, forms in (application/x-www-form-urlencoded), JSON
  out; an error is answered 200 with {"error": true, "message", "description"}.
* POST /auth {user, pass (the API password of Reseller Modules → API settings)} ->
  {key} (it lives 365 days); every other call carries ?auth_key=KEY.
* GET /products/ssl -> {products [{id, brand, product, max_period (months),
  product_type, wildcard_enabled, san_enabled, dcv_email, dcv_dns, dcv_http}]}.
* POST /orders/add_ssl_order {product_id, period (months), csr, server_count,
  dcv_method email | dns | http | https, dns_names (the other names, commas),
  approver_email, approver_emails, webserver_type, admin_* and tech_* (firstname,
  lastname, phone, title, email), org_* (OV/EV)} -> {order_id, order_status,
  approver_method {dns {record} | http {link, filename, content} | email},
  san [{san_name, validation {...}}]}.
* The DNS record is one string "NAME CNAME TARGET"; the file is link
  (http://NAME/.well-known/pki-validation/HASH.txt) and content (lines).
* POST /orders/ssl/reissue/{order_id} {csr, dcv_method, dns_names, approver_email,
  approver_emails} -> {order_id, order_status reissue, validation {...}}.
* GET /orders/status/{order_id} -> {status active | processing | pending |
  reissue | new_order | unpaid | incomplete | cancelled | expired | rejected,
  crt_code (the certificate, PEM), ca_code (the CA's, PEM), valid_from,
  valid_till, end_date (the subscription), domain, domains, approver_method, san}.
* POST /orders/ssl/revalidate/{order_id} {domain} - GoGetSSL looks at the CNAME or
  file again (at most once in 300 seconds).
* GET /orders/ssl/all?limit=&offset= -> {orders [{order_id, status}], count}.
* POST /orders/cancel_ssl_order {order_id, reason}.

LESS CERTAIN: whether ca_code holds the whole chain (what it holds is put in
order above the certificate); the largest limit of /orders/ssl/all (100 a page is
asked); "test", seen in examples without a description, is not sent. API v2 (the
header "Authorization: GGS CODE:PASSWORD") is not used: its dns-txt record has no
documented name. HTTPS file validation is not offered (the validations put files
for http://).
"""
from __future__ import annotations

import calendar
import json
import re
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import Issuer, Plugin, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

API = 'https://my.gogetssl.com/api'
ISSUED = ('active',)
WAITING = ('processing', 'pending', 'reissue', 'new_order', 'incomplete')
FAILED = ('cancelled', 'canceled', 'expired', 'rejected')
STATUS_WORDS = {'active': 'issued and active', 'processing': 'being validated',
                'pending': 'pending', 'reissue': 'being reissued', 'new_order': 'a new order',
                'unpaid': 'not paid', 'incomplete': 'incomplete', 'cancelled': 'cancelled',
                'expired': 'expired', 'rejected': 'rejected'}
MAILBOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')
CONTACT = ('firstname', 'lastname', 'phone', 'title', 'email')


def _day(v):
    try:
        s = str(v or '')[:10]
        return calendar.timegm(time.strptime(s, '%Y-%m-%d')) if s and s != '0000-00-00' else None
    except (TypeError, ValueError):
        return None


class GoGetSslIssuer(Issuer):
    kind = 'gogetssl'
    title = 'GoGetSSL (reseller API)'
    description = ('Certificates bought through GoGetSSL\'s reseller API: ordered (only when '
                   'paid orders are allowed) or reissued inside an order bought already, the '
                   'domain validation record or file put in place by the certificate\'s '
                   'validation. Lists the account\'s orders for importing.')
    vendor = 'GoGetSSL'
    doc = 'docs/sources.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # orders/ssl/all + orders/status: Import from a source
    dcv_field = 'dcv'
    dcv_default = 'dns'
    dcv = {
        'dns': {'proof': 'cname-any', 'words': 'DNS CNAME record (dns)',
                'record': 'CNAME at the name GoGetSSL says (_HASH.NAME) to its target'},
        'http': {'proof': 'http-file-any', 'words': 'HTTP file (http)',
                 'record': 'http://NAME/.well-known/pki-validation/HASH.txt holding '
                           'GoGetSSL\'s lines'},
        'email': {'proof': None, 'words': 'E-mail (a person approves)',
                  'record': 'an e-mail to admin@, administrator@, hostmaster@, postmaster@ or '
                            'webmaster@ the domain'},
    }
    actions = [{'key': 'cancel', 'label': 'Cancel the order to reuse',
                'help': 'Asks GoGetSSL to cancel (and refund) the order in "Order to reuse" - '
                        'its API has no revocation. GoGetSSL reviews it in 2 to 48 hours.',
                'confirm': 'Ask GoGetSSL to cancel the order in "Order to reuse"?',
                'changes': True}]
    fields = [
        field('user', 'User', 'text', required=True,
              help='The login of the GoGetSSL client area.'),
        field('api_password', 'API password', 'secret', required=True,
              help='Client area → Reseller Modules → API settings: the API password (not the '
                   'account\'s password).'),
        field('order_id', 'Order to reuse', 'text', placeholder='1332864',
              help='An order bought already: its certificate is reissued (free). Empty: the '
                   'order acme made last for the certificate.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders bought '
                   'already, and stops with words where a purchase would be needed.'),
        field('product', 'Product of a new order', 'catalog', catalog='products',
              placeholder='77', depends=['user', 'api_password'],
              help='Load the list: the SSL products of the account (GET /products/ssl) - an '
                   'ID can be typed too.'),
        field('period', 'Period of a new order (months)', 'select', default='12',
              options=[['12', '12 months'], ['24', '24 months'], ['36', '36 months'],
                       ['48', '48 months'], ['60', '60 months']]),
        field('server_count', 'Server licences', 'number', default=1, advanced=True,
              help='server_count of a new order (-1: unlimited).'),
        field('dcv', 'Domain validation (DCV)', 'select', default='dns',
              options=[['dns', 'DNS CNAME record (by the certificate\'s DNS validation)'],
                       ['http', 'HTTP file in /.well-known/pki-validation/ (by the '
                                'certificate\'s HTTP validation; no wildcards)'],
                       ['email', 'E-mail to an approver address of the domain']],
              help='How the CA checks the domains. The certificate\'s validation must be able '
                   'to put that record or file in place - the wizard offers only those that '
                   'can.'),
        field('approver', 'Approver mailbox', 'select', default='admin',
              options=[['admin', 'admin@'], ['administrator', 'administrator@'],
                       ['hostmaster', 'hostmaster@'], ['postmaster', 'postmaster@'],
                       ['webmaster', 'webmaster@']],
              show_if={'dcv': ['email']},
              help='The address of each domain the CA writes to.'),
        field('contact_firstname', 'Contact: first name', 'text', required=True),
        field('contact_lastname', 'Contact: last name', 'text', required=True),
        field('contact_phone', 'Contact: phone', 'text', required=True, placeholder='+420123456789'),
        field('contact_title', 'Contact: title', 'text', default='IT'),
        field('contact_email', 'Contact: e-mail', 'text', required=True),
        field('more', 'More fields of a new order', 'list', advanced=True,
              placeholder='org_name=Firma s.r.o.',
              help='name=value, one a line, sent as they are (an OV/EV order\'s org_*, '
                   'admin_organization, webserver_type...).'),
        field('api_url', 'API address', 'text', default=API, advanced=True),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600,
              advanced=True,
              help='Longer: it is asked for again at the next try - nothing is ordered twice.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=20, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep
        self._key = None

    # -- the API ---------------------------------------------------------------------------
    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _base(self):
        url = (self._s('api_url') or API).rstrip('/')
        if not re.match(r'^https://[^\s/]+(/\S*)?\Z', url):
            raise PluginError('the GoGetSSL API address is not an https address', retry=False)
        return url

    def _hide(self, words):
        out = str(words)
        for v in (self._s('api_password'), self._key):
            if v:
                out = out.replace(v, '********')
        return out

    def _sign_in(self):
        if not self._s('user') or not self._s('api_password'):
            raise PluginError('set the user and the API password', retry=False)
        got = self._send('POST', '/auth', {'user': self._s('user'),
                                           'pass': self._s('api_password')}, None, 'signing in')
        key = str(got.get('key') or '')
        if not key:
            raise PluginError('GoGetSSL gave no key for the user', retry=False)
        return key, 30 * 86400.0

    def auth_key(self):
        if limits.sharing(self.ctx):
            return limits.session(limits.key_of(self, 'key'), self._sign_in)
        if not self._key:
            self._key = self._sign_in()[0]
        return self._key

    def _send(self, method, path, form, key, what, query=None):
        url = self._base() + path
        q = dict({'auth_key': key} if key else {}, **(query or {}))
        if q:
            url += '?' + urllib.parse.urlencode(q)
        body, h = None, {}
        if form is not None:
            body = urllib.parse.urlencode(form)
            h['Content-Type'] = 'application/x-www-form-urlencoded'
        try:
            status, _h, data = sc.http(self.ctx, method, url, body, h, who='GoGetSSL')
        except PluginError as e:
            raise PluginError(self._hide(e), retry=e.retry)
        got = sc.parse_json(data)
        if isinstance(got, dict) and got.get('error') in (True, 'true', 1, '1'):
            said = ' - '.join(str(got.get(k)) for k in ('message', 'description') if got.get(k))
            wrong = 'username' in said.lower() or 'auth' in said.lower()
            raise PluginError('GoGetSSL refused %s: %s%s' % (what, said or '?', (
                ' - the user or API password is wrong' if wrong else '')),
                detail=self._hide(json.dumps(got))[:3000], retry=False)
        if status >= 400 or not isinstance(got, dict):
            raise sc.refusal('GoGetSSL (%s)' % what, status, got if isinstance(got, dict) else None,
                             self._hide((data or b'').decode('utf-8', 'replace')).encode(),
                             'the user or API password is wrong')
        return got

    def call(self, method, path, form=None, what='', query=None):
        return self._send(method, path, form, self.auth_key(), what or path, query)

    @staticmethod
    def _oid(v):
        v = str(v or '').strip()
        if not re.match(r'^\d{1,15}\Z', v):
            raise PluginError('"%s" is not a GoGetSSL order ID' % v, retry=False)
        return v

    # -- the products (the form's list) ------------------------------------------------------
    def products(self):
        got = self.call('GET', '/products/ssl', what='the products')
        return [p for p in got.get('products') or [] if isinstance(p, dict) and p.get('id')]

    def catalog(self, key):
        """The SSL products: GET /products/ssl (getSslProducts). Read-only."""
        if key != 'products':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = []
        for p in self.products():
            kind = {'domain_validation': 'DV', 'business_validation': 'OV',
                    'extended_validation': 'EV'}.get(str(p.get('product_type') or ''), '')
            words = '%s%s%s' % (p.get('product') or p['id'], (' - ' + kind) if kind else '',
                                ' - wildcard' if str(p.get('wildcard_enabled')) in ('1', 'true')
                                else '')
            opts.append([str(p['id']), words])
        return {'options': opts, 'said': '%d SSL product(s)' % len(opts)}

    def test(self):
        bal = self.call('GET', '/account/balance', what='the balance')
        return 'GoGetSSL answers: signed in; the balance is %s %s; new paid orders %s' % (
            bal.get('balance', '?'), bal.get('currency', ''),
            'ALLOWED' if sc.as_bool(self.c('allow_paid')) else 'not allowed')

    # -- the order ---------------------------------------------------------------------------
    def _mails(self, req):
        box = self.c('approver') or 'admin'
        if box not in MAILBOXES:
            box = 'admin'
        mails = ['%s@%s' % (box, _dcv.base_of(n)) for n in req.names]
        return mails[0], ','.join(mails[1:])

    def _dcv_form(self, req):
        how = self.c('dcv') or 'dns'
        form = {'dcv_method': how}
        if req.names[1:]:
            form['dns_names'] = ','.join(req.names[1:])
        if how == 'email':
            form['approver_email'], more = self._mails(req)
            if more:
                form['approver_emails'] = more
        return form

    def _new_form(self, req):
        product = self._s('product')
        if not re.match(r'^\d{1,9}\Z', product):
            raise PluginError('set the product of a new order (its ID - Load the list)',
                              retry=False)
        form = {'product_id': product, 'period': int(sc.num(self.c('period'), 12)),
                'csr': sc.csr_pem(req), 'server_count': int(sc.num(self.c('server_count'), 1))}
        form.update(self._dcv_form(req))
        for k in CONTACT:
            v = self._s('contact_' + k)
            if not v and k != 'title':
                raise PluginError('set the contact (first and last name, phone, e-mail)',
                                  retry=False)
            form['admin_' + k] = form['tech_' + k] = v or 'IT'
        for line in sc.lines(self.c('more')):
            if '=' not in line:
                raise PluginError('a field of a new order is name=value: %s' % line, retry=False)
            k, v = line.split('=', 1)
            form[k.strip()] = v.strip()
        return form

    def _order(self, req, kept):
        """(how, order_id, the answer)."""
        oid = str(getattr(req, 'ref', None) or '').strip() or self._s('order_id') or \
            str((kept or {}).get('id') or '')
        why = 'there is no order to reissue in (set "Order to reuse")'
        if oid:
            st = self.status(oid)
            s = str(st.get('status') or '').lower()
            end = _day(st.get('end_date'))
            if s in ISSUED and (end is None or end > time.time() + 86400):
                form = {'csr': sc.csr_pem(req)}
                form.update(self._dcv_form(req))
                got = self.call('POST', '/orders/ssl/reissue/%s' % self._oid(oid), form,
                                what='the reissue of order %s' % oid)
                sc.say(self.ctx, 'reissue inside order %s asked for (free)' % oid, 'ok')
                return 'reissue', str(got.get('order_id') or oid), got
            why = 'the order %s is %s%s' % (oid, STATUS_WORDS.get(s, s or '?'),
                                           ', its subscription ends' if end and
                                           end <= time.time() + 86400 else '')
        if not sc.as_bool(self.c('allow_paid')):
            raise PluginError('nothing ordered: %s, and paid orders are not allowed for this '
                              'source - set "Order to reuse" to an order you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        form = self._new_form(req)
        sc.say(self.ctx, '%s - a new order is made (paid: allowed for this source)' % why, 'warn')
        got = self.call('POST', '/orders/add_ssl_order', form, what='the new order')
        oid = str(got.get('order_id') or '')
        if not re.match(r'^\d+\Z', oid):
            raise PluginError('GoGetSSL took the order but said no order ID - look in the client '
                              'area before trying again (a second order would be paid again)',
                              retry=False)
        sc.say(self.ctx, 'order %s made at GoGetSSL: product %s for %s' % (
            oid, form['product_id'], ', '.join(req.names)), 'ok')
        return 'new', oid, got

    def status(self, oid):
        return self.call('GET', '/orders/status/%s' % self._oid(oid), what='the order %s' % oid)

    @staticmethod
    def _rec(name, v, how):
        """One record of GoGetSSL's validation data {dns {record}} or {http {link, content}}."""
        if not isinstance(v, dict):
            return None
        d = _dcv.base_of(name)
        if how == 'dns':
            rec = str(((v.get('dns') or {}) if isinstance(v.get('dns'), dict) else {})
                      .get('record') or '')
            m = re.match(r'^\s*(\S+)\s+CNAME\s+(\S+)\s*$', rec, re.I)
            if m:
                return {'domain': d, 'type': 'cname', 'fqdn': m.group(1).rstrip('.').lower(),
                        'value': m.group(2).rstrip('.').lower()}
        elif how == 'http':
            h = v.get('http') if isinstance(v.get('http'), dict) else {}
            u = urllib.parse.urlsplit(str(h.get('link') or ''))
            content = str(h.get('content') or '').replace('\r\n', '\n')
            if u.path.startswith('/.well-known/pki-validation/') and content:
                return {'domain': (u.hostname or d).lower(), 'type': 'file', 'path': u.path,
                        'value': content}
        return None

    def dcv_records(self, req, got):
        how = self.c('dcv') or 'dns'
        recs = []
        main = got.get('approver_method') or got.get('validation')
        first = self._rec(req.names[0], main, how)
        if first:
            recs.append(first)
        for s in got.get('san') or []:
            if isinstance(s, dict) and str(s.get('status')) != '2':
                r = self._rec(s.get('san_name') or '', s.get('validation'), how)
                if r and not any(x['domain'] == r['domain'] and x.get('fqdn') == r.get('fqdn')
                                 and x.get('path') == r.get('path') for x in recs):
                    recs.append(r)
        return recs

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
        how = self.c('dcv') or 'dns'
        if how == 'http' and any(n.startswith('*.') for n in req.names):
            raise PluginError('a wildcard name is proved by DNS or e-mail, not by an HTTP file - '
                              'choose the DNS CNAME record', retry=False)
        ck = str(req.cert_id or '') or sc.pending_slot('x', '', req).split(':')[-1]
        made_key = 'gogetssl-order:%s' % ck
        slot = sc.pending_slot('gogetssl', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        if held:
            oid = held['id']
            sc.say(self.ctx, 'the order %s waits at GoGetSSL since %s - asked for again, nothing '
                             'is ordered' % (oid, time.strftime('%Y-%m-%d %H:%M',
                                                                time.gmtime(held.get('at') or 0))))
            if held.get('recs') and not held.get('dcv'):
                if self._place(req, slot, held, placer, held['recs']):
                    placer.wait_visible(req, held['dcv'])
                    self._revalidate(held['id'], req.names[0])
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
                sc.say(self.ctx, 'the CA mails %s - someone there approves the certificate'
                       % ', '.join(a for a in self._mails(req) if a))
            else:
                recs = self.dcv_records(req, got)
                if not recs:
                    recs = self.dcv_records(req, self.status(oid))
                if self._place(req, slot, held, placer, recs):
                    placer.wait_visible(req, held['dcv'])
                    self._revalidate(oid, req.names[0])
        return self._await(r, req, slot, held, placer)

    def _revalidate(self, oid, name):
        try:
            self.call('POST', '/orders/ssl/revalidate/%s' % self._oid(oid),
                      {'domain': _dcv.base_of(name)}, what='the revalidation')
            sc.say(self.ctx, 'GoGetSSL was asked to look at the domain validation again')
        except PluginError as e:
            sc.say(self.ctx, 'GoGetSSL looks at the validation by itself (%s)' % e, 'info')

    def _await(self, r, req, slot, held, placer):
        oid = held['id']
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 20))
        while True:
            st = self.status(oid)
            s = str(st.get('status') or '').lower()
            if s in ISSUED and st.get('crt_code'):
                try:
                    out = sc.finish(self.ctx, r, sc.certs_of(st.get('crt_code')),
                                    sc.certs_of(st.get('ca_code') or ''), who='GoGetSSL',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'gogetssl_order': oid, 'ref': oid})
                except PluginError:
                    out = None              # the order's old certificate still: the reissue waits
                if out is not None:
                    placer.cleanup(req, held.get('dcv') or [])
                    sc.pending_drop(self.ctx, slot)
                    if getattr(req, 'cert_id', None):
                        self.ctx.kv_set('gogetssl-order:%s' % req.cert_id,
                                        json.dumps({'id': oid, 'at': time.time()}),
                                        ttl_s=5 * 366 * 86400)
                    return out
            elif s in FAILED:
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('GoGetSSL did not issue: the order %s is %s' % (
                    oid, STATUS_WORDS.get(s, s)), retry=False)
            elif s == 'unpaid':
                raise PluginError('the order %s is not paid at GoGetSSL - top up the balance; '
                                  'acme asks again at the next try' % oid)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('GoGetSSL has not issued yet (order %s: %s) - the DCV records '
                                  'stay in place; acme asks again at the next try' % (
                                      oid, STATUS_WORDS.get(s, s or '?')))
            self._sleep(every)

    # -- no revocation; the cancellation ------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        raise PluginError('GoGetSSL\'s API cannot revoke a certificate - revoke it in the '
                          'GoGetSSL client area, or cancel its order (the action "Cancel the '
                          'order to reuse")', retry=False)

    def action(self, key):
        if key == 'cancel':
            oid = self._oid(self._s('order_id'))
            got = self.call('POST', '/orders/cancel_ssl_order',
                            {'order_id': oid, 'reason': 'cancelled from acme'},
                            what='the cancellation of %s' % oid)
            return 'GoGetSSL: %s (order %s)' % (got.get('message') or 'cancellation asked for',
                                                oid)
        return Issuer.action(self, key)

    # -- the orders of the account (Certificates → Import from a source) ---------------------
    READ_MOST = 150                 # orders read one by one in a listing

    def _acme_ids(self):
        out = {}
        try:
            kept = self.ctx.kv_keys('gogetssl-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('id') and cid.isdigit():
                out[str(v['id'])] = int(cid)
        return out

    def list_existing(self):
        """The account's SSL orders (orders/ssl/all), the active ones read one by one -
        read only."""
        mine = self._acme_ids()
        orders, offset, per = [], 0, 100
        for _page in range(100):
            got = self.call('GET', '/orders/ssl/all', what='the list of orders',
                            query={'limit': per, 'offset': offset})
            items = [o for o in got.get('orders') or [] if isinstance(o, dict)]
            orders += items
            offset += len(items)
            if len(items) < per:
                break
        out, read = [], 0
        for o in orders:
            oid = str(o.get('order_id') or '').strip()
            s = str(o.get('status') or '').lower()
            if not oid:
                continue
            item = {'ref': oid, 'cn': '', 'names': [], 'product': '',
                    'status': STATUS_WORDS.get(s, s or '?'), 'downloadable': False,
                    'renewable': 'order', 'note': 'the order is %s' % STATUS_WORDS.get(s, s or '?'),
                    'acme_cert_id': mine.get(oid)}
            if s in ISSUED and read < self.READ_MOST and not self.ctx.cancelled():
                read += 1
                try:
                    st = self.status(oid)
                except PluginError as e:
                    item['note'] = 'it cannot be read: %s' % e
                    out.append(item)
                    continue
                cn = str(st.get('domain') or '').strip()
                names = [cn] + [x.strip() for x in str(st.get('domains') or '').split(',')]
                names += [str(x.get('san_name') or '').strip() for x in st.get('san') or []
                          if isinstance(x, dict)]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                end = _day(st.get('end_date'))
                item.update({'cn': cn, 'names': names, 'product': str(st.get('product_id') or ''),
                             'not_before': _day(st.get('valid_from')),
                             'not_after': _day(st.get('valid_till')), 'paid_until': end,
                             'downloadable': bool(st.get('crt_code')),
                             'renewable': 'reissue' if end is None or end > time.time() else
                             'order', 'note': ''})
            elif s in ISSUED:
                item.update({'downloadable': True, 'renewable': 'reissue',
                             'note': 'more than %d orders: this one is read when it is imported'
                                     % self.READ_MOST})
            out.append(item)
        return out

    def fetch_existing(self, ref):
        """The certificate of order `ref` and its CA's (orders/status) - read only."""
        oid = self._oid(ref)
        st = self.status(oid)
        if not st.get('crt_code'):
            raise PluginError('the order %s has no certificate (it is %s)' % (
                oid, STATUS_WORDS.get(str(st.get('status') or '').lower(), '?')), retry=False)
        out = sc.existing(sc.certs_of(st.get('crt_code')), sc.certs_of(st.get('ca_code') or ''),
                          who='GoGetSSL', ref=oid)
        out['acme_cert_id'] = self._acme_ids().get(oid)
        return out

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['user', 'api_password', 'api_url']
    DISCOVER_READ = 10              # active orders read one by one for the choice

    def discover_setup(self):
        """Read-only: the products (the form's list), the contact of the account (GET
        /account - getAccountDetails) and its active orders (orders/ssl/all, the newest
        read by orders/status) - an order to reuse is never picked by itself."""
        out = Plugin.discover_setup(self)
        acc = self.call('GET', '/account', what='the account details')
        for mine, theirs in (('contact_firstname', 'first_name'),
                             ('contact_lastname', 'last_name'), ('contact_email', 'email'),
                             ('contact_phone', 'phone'), ('contact_phone', 'company_phone')):
            v = str(acc.get(theirs) or '').strip()
            if v and mine not in out['sets']:
                out['sets'][mine] = v
        if str(acc.get('company_name') or '').strip():
            out['facts'].append(['Company', str(acc['company_name']).strip()])
        got = self.call('GET', '/orders/ssl/all', what='the list of orders',
                        query={'limit': 100, 'offset': 0})
        live = [str(o.get('order_id') or '').strip() for o in got.get('orders') or []
                if isinstance(o, dict) and str(o.get('status') or '').lower() in ISSUED]
        live = sorted({o for o in live if o.isdigit()}, key=int, reverse=True)
        out['facts'].append(['Active orders', str(len(live))])
        words = {o[0]: o[1] for o in (out['choices'].get('product') or {}).get('options') or []}
        rows = []
        for oid in live[:self.DISCOVER_READ]:
            try:
                st = self.status(oid)
            except PluginError as e:
                out['notes'].append('the order %s could not be read: %s' % (oid, e))
                continue
            end = _day(st.get('end_date'))
            pid = str(st.get('product_id') or '')
            rows.append({'ref': oid, 'cn': str(st.get('domain') or '').strip(),
                         'product': words.get(pid, pid), 'paid_until': end,
                         'not_after': _day(st.get('valid_till')),
                         'renewable': 'reissue' if end is None or end > time.time() else 'order'})
        sc.reuse_choice(self, out, 'order_id', rows,
                        'Empty: the order acme made last for the certificate')
        return out
