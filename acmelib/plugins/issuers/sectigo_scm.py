# -*- coding: utf-8 -*-
"""
Certificates from Sectigo Certificate Manager (SCM) through its Admin API
(/api/ssl/v2, /api/dcv/v2): the domains validated first (DCV - a CNAME, TXT,
file or e-mail, the record or file put in place by the certificate's own
validation: base.Challenge.place, acmelib/plugins/issuers/_dcv.py), then the
request (CSR) enrolled with a certificate profile of the account, the
certificate collected. Renewals renew (or replace) the certificate acme made or
imported. The account's certificates are listed for Certificates → Import from
a source, the certificate profiles for the form's list.

SCM's ACME with EAB stays the `acme` source's preset; this module is for the
Admin API: profiles, terms and custom fields of the account, DCV by e-mail, the
certificates of the account seen and imported.

What the API is, and from where - Sectigo's own reference (OpenAPI definitions
embedded in each page; read 2026-11):
https://scm.devx.sectigo.com/docs/authentication.md, .../docs/base-url-explanation.md,
.../reference/enroll-ssl-certificate.md, collect-ssl-certificate.md,
get-ssl-certificate-details.md, get-ssl-certificates-list.md, get-ssl-cert-types.md,
renew-ssl-certificate-by-id.md, replace-ssl-certificate-by-id.md,
revokessl-certificate-by-id.md, revoke-ssl-certificate-by-serial-number.md,
get-dcv-status.md, start-cname-dcv.md, submit-cname-dcv.md, start-http-dcv.md,
submit-http-dcv.md, submit-txt-dcv.md, start-email-dcv.md, submit-email-dcv.md,
createaccesstoken.md:

* Base https://admin.{instance}.sectigo.com (OAuth 2.0: a Bearer token from
  POST https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/
  token, form client_id, client_secret, grant_type=client_credentials -> access_token,
  expires_in 300) or https://cert-manager.com (headers login, password, customerUri).
  The paths are the same on both.
* POST /api/dcv/v2/validation/status {domain} -> {status Not validated | Validated |
  Expired, orderStatus, host, point, url, firstLine, secondLine}.
* CNAME: POST .../validation/start/domain/cname {domain} -> {host, point}; then
  POST .../submit/domain/cname {domain}.
* TXT: POST .../submit/domain/txt {domain} -> {status, orderStatus, host, point}
  ("does not require start operation").
* HTTP: POST .../start/domain/http {domain} -> {url, firstLine, secondLine}; then
  POST .../submit/domain/http {domain}.
* E-mail: POST .../start/domain/email {domains: [d]} -> {emails, dcvEmails [{domainName,
  adminEmails, whoisEmails, dnsTxtEmails}]}; POST .../submit/domain/email {domain, email}.
* POST /api/ssl/v2/enroll {orgId, certType, term, csr, subjAltNames (commas),
  comments, externalRequester, customFields [{name, value}], dcvMode, dcvEmail} ->
  {sslId, renewId}.
* GET /api/ssl/v2/{sslId} -> {status (Requested, Approved, Applied, Issued, Declined,
  Rejected, Revoked, Expired, Replaced, Invalid, SA Approved, Init), commonName,
  subjectAlternativeNames, ...}; GET /api/ssl/v2/collect/{sslId}?format=x509 - the
  certificate with its chain, PEM.
* POST /api/ssl/v2/renewById/{sslId} {csr, dcvMode, dcvEmail} -> {sslId (the new
  one)}; POST /api/ssl/v2/replace/{sslId} {csr, reason, commonName,
  subjectAlternativeNames} -> 204 (the same id).
* POST /api/ssl/v2/revoke/{id} (or /revoke/serial/{serialNumber}) {reasonCode "0",
  "1", "3", "4" or "5", reason} -> 204.
* GET /api/ssl/v2?size=200&position=N -> [SSLIdentity {sslId, commonName,
  subjectAlternativeNames, serialNumber, certTypeName, status, expires, issued}],
  X-Total-Count: Import from a source.
* GET /api/ssl/v2/types?organizationId= -> [{id, name, description, terms [days],
  keyTypes}]: the certificate profiles (the form's list).

LESS CERTAIN (the reference does not say): the exact shape of DCV's host and point
(a name ending in the domain is used as it is, a bare label gets the domain added);
whether subjAltNames should hold the common name as well (the other names are sent);
whether a certificate still waiting is answered 404 by collect (the status is read
first, collect only once Issued); the serial's format for revoke/serial (hex, used
only where the certificate's id is not known); whether "Replaced" is the state of a
replaced certificate's id (after a replace, the certificate is collected until it is
the one of the new key).
"""
from __future__ import annotations

import calendar
import json
import re
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

TOKEN_URL = 'https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token'
HEADER_BASE = 'https://cert-manager.com'
INSTANCES = ('enterprise', 'hard', 'eu')
MODES = {'cname': 'CNAME', 'txt': 'TXT', 'http': 'HTTP', 'email': 'EMAIL'}
ISSUED = ('issued',)
WAITING = ('requested', 'approved', 'applied', 'sa approved', 'init')
FAILED = ('declined', 'rejected', 'revoked', 'expired', 'invalid', 'replaced')
REVOKE = {0: '0', 1: '1', 3: '3', 4: '4', 5: '5'}
MAILBOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')
STATUS_WORDS = {'requested': 'requested (waiting for approval)', 'approved': 'approved',
                'applied': 'applied (at the CA)', 'issued': 'issued', 'declined': 'declined',
                'rejected': 'rejected', 'revoked': 'revoked', 'expired': 'expired',
                'replaced': 'replaced', 'invalid': 'invalid', 'sa approved': 'approved',
                'init': 'being made'}


def _when(v):
    """An ISO date-time (or date) as epoch, or None."""
    s = str(v or '').strip()
    for fmt, n in (('%Y-%m-%dT%H:%M:%S', 19), ('%Y-%m-%d', 10)):
        try:
            return calendar.timegm(time.strptime(s[:n], fmt))
        except (TypeError, ValueError):
            continue
    return None


class SectigoScmIssuer(Issuer):
    kind = 'sectigo_scm'
    title = 'Sectigo Certificate Manager (Admin API)'
    description = ('Certificates from Sectigo Certificate Manager through its Admin API: the '
                   'domains validated (the record or file put in place by the certificate\'s '
                   'validation, or an e-mail), the request enrolled with a certificate profile, '
                   'the certificate collected and renewed. Lists the account\'s certificates for '
                   'importing.')
    vendor = 'Sectigo'
    doc = 'docs/sources.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # GET /api/ssl/v2 + collect: Import from a source
    dcv_field = 'dcv'
    dcv_default = 'cname'
    dcv = {
        'cname': {'proof': 'cname-any', 'words': 'DNS CNAME record (CNAME)',
                  'record': 'CNAME at the host SCM says (start CName validation) to its point'},
        'txt': {'proof': 'txt-any', 'words': 'DNS TXT record (TXT)',
                'record': 'TXT at the host SCM says (submit DNS TXT validation) holding its '
                          'point'},
        'http': {'proof': 'http-file-any', 'words': 'HTTP file (HTTP)',
                 'record': 'http://NAME/.well-known/pki-validation/FILE holding the two lines '
                           'SCM gives'},
        'email': {'proof': None, 'words': 'E-mail (a person approves)',
                  'record': 'an e-mail to an address SCM offers for the domain'},
    }
    per_cert = [{'key': 'template', 'field': 'cert_type', 'catalog': 'types',
                 'label': 'Certificate profile', 'placeholder': '1234',
                 'help': 'The SCM certificate profile (its ID) for this certificate. Empty: the '
                         'source\'s own.'}]
    fields = [
        field('auth', 'Signing in', 'select', default='oauth',
              options=[['oauth', 'OAuth 2.0 client (admin.INSTANCE.sectigo.com)'],
                       ['password', 'Login and password (cert-manager.com)']],
              help='Sectigo recommends OAuth 2.0: an API client made in SCM (its client ID and '
                   'secret). The login and password of an API administrator go to '
                   'cert-manager.com in headers.'),
        field('instance', 'SCM instance', 'select', default='enterprise',
              options=[['enterprise', 'enterprise'], ['hard', 'hard'], ['eu', 'eu']],
              show_if={'auth': ['oauth']},
              help='The production instance given at onboarding: the API is '
                   'https://admin.INSTANCE.sectigo.com.'),
        field('client_id', 'Client ID', 'text', show_if={'auth': ['oauth']}),
        field('client_secret', 'Client secret', 'secret', show_if={'auth': ['oauth']}),
        field('token_url', 'Token address', 'text', default=TOKEN_URL, advanced=True,
              show_if={'auth': ['oauth']},
              help='Sectigo says the authentication server may differ for a customer: a 401 '
                   'answer names it (authorization_uri).'),
        field('login', 'Login', 'text', show_if={'auth': ['password']}),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('customer_uri', 'Customer URI', 'text', show_if={'auth': ['password']},
              help='The customer identifier of the account (customerUri).'),
        field('org_id', 'Organization ID', 'text', required=True, placeholder='12345',
              help='The SCM organization (or department) the certificates are enrolled for '
                   '(orgId).'),
        field('cert_type', 'Certificate profile', 'catalog', catalog='types', required=True,
              placeholder='1234',
              depends=['auth', 'instance', 'client_id', 'client_secret', 'login', 'password',
                       'customer_uri', 'org_id'],
              help='Load the list: the SSL certificate profiles of the account (GET '
                   '/api/ssl/v2/types) - an ID can be typed too. A certificate\'s own profile '
                   '(Add a certificate → Settings) wins.'),
        field('term', 'Term (days)', 'number', placeholder='365',
              help='The validity asked for (term). Empty: the shortest term the profile '
                   'offers.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='cname',
              options=[['cname', 'DNS CNAME record (by the certificate\'s DNS validation)'],
                       ['txt', 'DNS TXT record (by the certificate\'s DNS validation)'],
                       ['http', 'HTTP file in /.well-known/pki-validation/ (by the '
                                'certificate\'s HTTP validation; no wildcards)'],
                       ['email', 'E-mail to an address SCM offers for the domain']],
              help='How SCM checks the domains. Domains validated in the account already are '
                   'not validated again. The certificate\'s validation must be able to put the '
                   'record or file in place - the wizard offers only those that can.'),
        field('approver', 'Approver mailbox', 'select', default='admin',
              options=[['admin', 'admin@'], ['administrator', 'administrator@'],
                       ['hostmaster', 'hostmaster@'], ['postmaster', 'postmaster@'],
                       ['webmaster', 'webmaster@'],
                       ['first', 'the first address SCM offers']],
              show_if={'dcv': ['email']},
              help='For each domain the address is picked from those SCM offers: this '
                   'mailbox, else the first offered.'),
        field('ssl_id', 'Certificate to reuse', 'text', placeholder='123456',
              help='An SCM certificate ID renewed (or replaced) for this certificate. Empty: '
                   'the one acme made last for it (or the one it was imported from).'),
        field('renew_how', 'A renewal', 'select', default='renew', advanced=True,
              options=[['renew', 'renews it (renewById: a new certificate ID)'],
                       ['replace', 'replaces it (the same certificate ID)'],
                       ['enroll', 'is a new enrollment']],
              help='What acme does with the certificate acme made (or imported) when it is '
                   'renewed. Names that differ from that certificate\'s are always a new '
                   'enrollment.'),
        field('custom_fields', 'Custom fields', 'list', advanced=True,
              placeholder='Cost center=1234',
              help='name=value, one a line: the account\'s mandatory custom fields '
                   '(customFields).'),
        field('comments', 'Comments', 'text', advanced=True, default='requested by acme'),
        field('external_requester', 'External requester', 'text', advanced=True,
              placeholder='it@example.com'),
        field('api_url', 'API address', 'text', advanced=True,
              placeholder='https://admin.enterprise.sectigo.com',
              help='Empty: as Signing in and the instance say.'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600,
              advanced=True,
              help='Longer: it is asked for again at the next try - nothing is enrolled twice.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=15, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep
        self._token = None
        self._types = None

    # -- the API ---------------------------------------------------------------------------
    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _base(self):
        url = self._s('api_url').rstrip('/')
        if not url:
            if (self.c('auth') or 'oauth') == 'password':
                url = HEADER_BASE
            else:
                inst = self._s('instance') or 'enterprise'
                if inst not in INSTANCES:
                    raise PluginError('the SCM instance is enterprise, hard or eu', retry=False)
                url = 'https://admin.%s.sectigo.com' % inst
        if not re.match(r'^https://[^\s/]+\Z', url):
            raise PluginError('the SCM API address is https://HOST', retry=False)
        return url

    def _hide(self, words):
        out = str(words)
        for k in ('client_secret', 'password'):
            v = self._s(k)
            if v:
                out = out.replace(v, '********')
        if self._token:
            out = out.replace(self._token, '********')
        return out

    def _sign_in(self):
        cid, secret = self._s('client_id'), self._s('client_secret')
        if not cid or not secret:
            raise PluginError('set the client ID and the client secret of the SCM API client',
                              retry=False)
        url = self._s('token_url') or TOKEN_URL
        if not re.match(r'^https://[^\s]+\Z', url):
            raise PluginError('the token address is an https address', retry=False)
        body = urllib.parse.urlencode({'client_id': cid, 'client_secret': secret,
                                       'grant_type': 'client_credentials'})
        status, _h, data = sc.http(self.ctx, 'POST', url, body,
                                   {'Content-Type': 'application/x-www-form-urlencoded'},
                                   who='Sectigo (sign-in)')
        got = sc.parse_json(data) or {}
        if status != 200 or not got.get('access_token'):
            raise sc.refusal('Sectigo (sign-in)', status, got,
                             self._hide((data or b'').decode('utf-8', 'replace')).encode(),
                             'the client ID or secret is wrong')
        return got['access_token'], float(got.get('expires_in') or 300)

    def _bearer(self):
        if limits.sharing(self.ctx):
            return limits.session(limits.key_of(self, 'token'), self._sign_in)
        if not self._token:
            self._token = self._sign_in()[0]
        return self._token

    def _headers(self):
        if (self.c('auth') or 'oauth') == 'password':
            if not self._s('login') or not self._s('password') or not self._s('customer_uri'):
                raise PluginError('set the login, the password and the customer URI', retry=False)
            return {'login': self._s('login'), 'password': self._s('password'),
                    'customerUri': self._s('customer_uri')}
        return {'Authorization': 'Bearer ' + self._bearer()}

    def call(self, method, path, body=None, query=None, what='', ok=(200, 201, 202, 204),
             raw=False, headers_back=False):
        """SCM's answer (JSON, or the bytes with raw=True), or a PluginError in words."""
        url = self._base() + path + ('?' + urllib.parse.urlencode(query) if query else '')
        for attempt in (0, 1):
            h = self._headers()
            if raw:
                h['Accept'] = '*/*'
            status, rh, data = sc.http(self.ctx, method, url, body, h, who='Sectigo SCM')
            if status == 401 and attempt == 0 and (self.c('auth') or 'oauth') == 'oauth':
                tok = h.get('Authorization', '')[7:]
                if limits.sharing(self.ctx):
                    limits.session_drop(limits.key_of(self, 'token'), tok)
                self._token = None
                continue
            break
        if status not in ok:
            raise sc.refusal('Sectigo SCM (%s)' % (what or path), status, sc.parse_json(data),
                             self._hide((data or b'').decode('utf-8', 'replace')).encode(),
                             'the API client (or administrator) may not do this')
        out = data if raw else (sc.parse_json(data) if data else {})
        if out is None:
            out = {}
        return (out, rh) if headers_back else out

    @staticmethod
    def _id(v):
        v = str(v or '').strip()
        if not re.match(r'^\d{1,12}\Z', v):
            raise PluginError('"%s" is not an SCM certificate ID' % v, retry=False)
        return v

    # -- the profiles (the form's list) ------------------------------------------------------
    def types(self):
        if self._types is None:
            q = {'organizationId': self._s('org_id')} if self._s('org_id').isdigit() else None
            got = self.call('GET', '/api/ssl/v2/types', query=q,
                            what='the certificate profiles')
            self._types = [t for t in (got if isinstance(got, list) else [])
                           if isinstance(t, dict) and t.get('id') is not None]
        return self._types

    def catalog(self, key):
        """The SSL certificate profiles: GET /api/ssl/v2/types (get-ssl-cert-types).
        Read-only."""
        if key != 'types':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = []
        for t in self.types():
            terms = [str(x) for x in (t.get('terms') or [])]
            words = str(t.get('name') or t['id'])
            if terms:
                words += ' (%s days)' % ', '.join(terms)
            opts.append([str(t['id']), words])
        return {'options': opts, 'said': '%d certificate profile(s)' % len(opts)}

    def cert_type(self, req=None):
        v = str(((req.profile or {}).get('template') if req is not None else '') or
                self._s('cert_type')).strip()
        if not re.match(r'^\d{1,9}\Z', v):
            raise PluginError('set the certificate profile (its ID - Load the list)', retry=False)
        return int(v)

    def term(self, ctype):
        t = str(self.c('term') or '').strip()
        if t:
            try:
                return int(float(t))
            except ValueError:
                raise PluginError('the term is a number of days', retry=False)
        try:
            prof = next((x for x in self.types() if str(x.get('id')) == str(ctype)), None)
        except PluginError as e:
            sc.say(self.ctx, 'the profiles could not be read (%s) - no term is sent' % e, 'warn')
            return None
        terms = [int(x) for x in ((prof or {}).get('terms') or []) if str(x).isdigit()]
        return min(terms) if terms else None

    # -- the domain validation ---------------------------------------------------------------
    def _dcv_status(self, domain):
        return self.call('POST', '/api/dcv/v2/validation/status', {'domain': domain},
                         what='the validation of %s' % domain)

    @staticmethod
    def _host(host, domain):
        h = str(host or '').strip().rstrip('.').lower()
        if not h:
            return ''
        return h if h == domain or h.endswith('.' + domain) else '%s.%s' % (h, domain)

    def _approver(self, domain, offered):
        offered = [str(x).strip() for x in offered or [] if '@' in str(x)]
        want = self.c('approver') or 'admin'
        if want in MAILBOXES:
            pick = next((a for a in offered if a.lower() == '%s@%s' % (want, domain)), None) or \
                next((a for a in offered if a.lower().startswith(want + '@')), None)
            if pick:
                return pick
        return offered[0] if offered else None

    def _domains(self, req):
        out = []
        for n in req.names or []:
            d = _dcv.base_of(n)
            if d and d not in out:
                out.append(d)
        return out

    def start_dcv(self, req, placer):
        """Each domain not validated yet: its DCV started (records put in place, SCM asked
        to look). -> (placed, [domains waiting])."""
        how = self.c('dcv') or 'cname'
        recs, todo, submit, mails = [], [], [], []
        for d in self._domains(req):
            st = self._dcv_status(d)
            if str(st.get('status') or '').lower() == 'validated':
                sc.say(self.ctx, '%s is validated in the account already - no DCV' % d, 'ok')
                continue
            todo.append(d)
            if how == 'email':
                got = self.call('POST', '/api/dcv/v2/validation/start/domain/email',
                                {'domains': [d]}, what='the e-mail validation of %s' % d)
                offered = list(got.get('emails') or [])
                for e in got.get('dcvEmails') or []:
                    if isinstance(e, dict) and str(e.get('domainName') or d).lower() == d:
                        for k in ('adminEmails', 'whoisEmails', 'dnsTxtEmails'):
                            offered += list(e.get(k) or [])
                mail = self._approver(d, offered)
                if not mail:
                    raise PluginError('SCM offered no address for the e-mail validation of %s' % d,
                                      retry=False)
                self.call('POST', '/api/dcv/v2/validation/submit/domain/email',
                          {'domain': d, 'email': mail}, what='the e-mail validation of %s' % d)
                mails.append(mail)
            elif how == 'cname':
                got = self.call('POST', '/api/dcv/v2/validation/start/domain/cname',
                                {'domain': d}, what='the CNAME validation of %s' % d)
                host, point = self._host(got.get('host'), d), str(got.get('point') or '').strip()
                if not host or not point:
                    raise PluginError('SCM said no CNAME record for %s' % d, retry=False)
                recs.append({'domain': d, 'type': 'cname', 'fqdn': host,
                             'value': point.rstrip('.').lower()})
                submit.append(('cname', d))
            elif how == 'txt':
                got = self.call('POST', '/api/dcv/v2/validation/submit/domain/txt',
                                {'domain': d}, what='the TXT validation of %s' % d)
                host, point = self._host(got.get('host'), d), str(got.get('point') or '').strip()
                if not host or not point:
                    raise PluginError('SCM said no TXT record for %s' % d, retry=False)
                recs.append({'domain': d, 'type': 'txt', 'fqdn': host, 'value': point})
            else:
                got = self.call('POST', '/api/dcv/v2/validation/start/domain/http',
                                {'domain': d}, what='the HTTP validation of %s' % d)
                path = urllib.parse.urlsplit(str(got.get('url') or '')).path
                lines = [str(got.get(k) or '') for k in ('firstLine', 'secondLine')
                         if got.get(k)]
                if not path.startswith('/.well-known/pki-validation/') or not lines:
                    raise PluginError('SCM said no validation file for %s' % d, retry=False)
                recs.append({'domain': d, 'type': 'file', 'path': path, 'value': '\n'.join(lines)})
                submit.append(('http', d))
        if mails:
            sc.say(self.ctx, 'SCM mails %s - someone there approves the domains' % ', '.join(mails))
        placed = placer.place_all(req, recs) if recs else []
        if any(p.get('how') == 'placed' for p in placed):
            placer.wait_visible(req, placed)
        for kind, d in submit:
            self.call('POST', '/api/dcv/v2/validation/submit/domain/%s' % kind, {'domain': d},
                      what='the %s validation of %s' % (kind.upper(), d))
        if submit or recs:
            sc.say(self.ctx, 'SCM was asked to check %s (%s)' % (', '.join(todo),
                                                                 MODES.get(how, how)))
        return placed, todo

    def wait_dcv(self, todo, end, every):
        """Until every domain of `todo` is validated (True), or the time is over (False)."""
        left = list(todo)
        while left:
            left = [d for d in left if str(self._dcv_status(d).get('status') or '').lower()
                    != 'validated']
            if not left:
                break
            if time.time() >= end or self.ctx.cancelled():
                return left
            self._sleep(every)
        return []

    # -- the certificate ---------------------------------------------------------------------
    def _custom_fields(self):
        out = []
        for line in sc.lines(self.c('custom_fields')):
            if '=' not in line:
                raise PluginError('a custom field is name=value: %s' % line, retry=False)
            k, v = line.split('=', 1)
            out.append({'name': k.strip(), 'value': v.strip()})
        return out

    def _reuse(self, req, kept):
        """The SCM certificate ID to renew or replace, or None."""
        if (self.c('renew_how') or 'renew') == 'enroll':
            return None
        for v in (getattr(req, 'ref', None), self._s('ssl_id'), (kept or {}).get('id')):
            if v and re.match(r'^\d{1,12}\Z', str(v).strip()):
                return str(v).strip()
        return None

    @staticmethod
    def _names_of(det):
        cn = str(det.get('commonName') or '').strip().lower()
        sans = [str(x).strip().lower() for x in det.get('subjectAlternativeNames') or []]
        return sorted(set([cn] + sans) - {''})

    def _order(self, req):
        """-> (how, sslId) of what was asked for: 'enroll', 'renew' or 'replace'."""
        kept = sc.parse_json(self.ctx.kv_get('sectigo-made:%s' % req.cert_id) or '') \
            if req.cert_id else None
        old = self._reuse(req, kept)
        mode = MODES.get(self.c('dcv') or 'cname', 'CNAME')
        if old:
            det = self.call('GET', '/api/ssl/v2/%s' % old, what='the certificate %s' % old)
            st = str(det.get('status') or '').lower()
            same = self._names_of(det) == sorted(set(n.lower() for n in req.names))
            how = self.c('renew_how') or 'renew'
            if st in ('issued', 'expired') and (same or how == 'replace'):
                if how == 'replace':
                    self.call('POST', '/api/ssl/v2/replace/%s' % old,
                              {'csr': sc.csr_pem(req), 'reason': 'renewed by acme',
                               'commonName': req.names[0],
                               'subjectAlternativeNames': list(req.names[1:])},
                              what='the replacement of %s' % old)
                    sc.say(self.ctx, 'SCM replaces certificate %s (the same ID)' % old, 'ok')
                    return 'replace', old
                got = self.call('POST', '/api/ssl/v2/renewById/%s' % old,
                                {'csr': sc.csr_pem(req), 'dcvMode': mode},
                                what='the renewal of %s' % old)
                new = str(got.get('sslId') or '')
                self._id(new)
                sc.say(self.ctx, 'SCM renews certificate %s: the new one is %s' % (old, new), 'ok')
                return 'renew', new
            sc.say(self.ctx, 'the certificate %s is %s%s - a new one is enrolled' % (
                old, STATUS_WORDS.get(st, st or '?'),
                '' if same else ' and has other names'), 'warn')
        ctype = self.cert_type(req)
        org = self._s('org_id')
        if not org.isdigit():
            raise PluginError('set the organization ID (a number)', retry=False)
        body = {'orgId': int(org), 'certType': ctype, 'csr': sc.csr_pem(req),
                'dcvMode': mode}
        term = self.term(ctype)
        if term:
            body['term'] = term
        if req.names[1:]:
            body['subjAltNames'] = ','.join(req.names[1:])
        for k, key in (('comments', 'comments'), ('external_requester', 'externalRequester')):
            if self._s(k):
                body[key] = self._s(k)
        cf = self._custom_fields()
        if cf:
            body['customFields'] = cf
        got = self.call('POST', '/api/ssl/v2/enroll', body, what='the enrollment')
        new = str(got.get('sslId') or '')
        self._id(new)
        sc.say(self.ctx, 'SCM took the request for %s: certificate %s (profile %s)' % (
            ', '.join(req.names), new, ctype), 'ok')
        return 'enroll', new

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        how = self.c('dcv') or 'cname'
        if how == 'http' and any(n.startswith('*.') for n in req.names):
            raise PluginError('SCM proves a wildcard name by DNS or e-mail, not by an HTTP file - '
                              'choose a DNS record', retry=False)
        slot = sc.pending_slot('sectigo_scm', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 15))
        if held:
            sc.say(self.ctx, 'the request for %s waits at SCM since %s (%s) - asked for again, '
                             'nothing new is enrolled' % (', '.join(req.names), time.strftime(
                                 '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0)),
                                 held.get('id') or 'the domain validation'))
            if held.get('dcv'):
                placer.refresh(req, held['dcv'])
        else:
            held = sc.pending_put(self.ctx, slot, req, {'stage': 'dcv', 'dcv': [],
                                                        'csr_pem': sc.csr_pem(req)}, ttl_days=60)
            r = req
            try:
                held['dcv'], held['todo'] = self.start_dcv(req, placer)
            except Exception:                           # noqa: BLE001
                # nothing was enrolled: the next try starts the validation anew
                sc.pending_drop(self.ctx, slot)
                raise
            sc.pending_put(self.ctx, slot, req, held, ttl_days=60)
        if held.get('stage') == 'dcv':
            left = self.wait_dcv(held.get('todo') or [], end, every)
            if left:
                raise PluginError('SCM has not validated %s yet - the DCV records stay in place; '
                                  'acme asks again at the next try' % ', '.join(left))
            held['how'], held['id'] = self._order(r)
            held['stage'] = 'issue'
            sc.pending_put(self.ctx, slot, req, held, ttl_days=60)
        return self._await(r, req, slot, held, placer, end, every)

    def collect(self, sid):
        data = self.call('GET', '/api/ssl/v2/collect/%s' % self._id(sid),
                         query={'format': 'x509'}, raw=True, what='the collection of %s' % sid)
        return sc.certs_of(data)

    def _await(self, r, req, slot, held, placer, end, every):
        sid = held['id']
        while True:
            det = self.call('GET', '/api/ssl/v2/%s' % sid, what='the certificate %s' % sid)
            st = str(det.get('status') or '').lower()
            out = None
            if st in ISSUED:
                certs = self.collect(sid)
                try:
                    out = sc.finish(self.ctx, r, certs, who='Sectigo SCM',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'scm_ssl_id': sid, 'ref': sid})
                except PluginError:
                    out = None              # the old certificate still: the replacement waits
            if out is not None:
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                self.ctx.kv_set('sectigo-cert:%s' % sc.fingerprint(out.cert_pem)[:40], sid,
                                ttl_s=3 * 366 * 86400)
                if getattr(req, 'cert_id', None):
                    self.ctx.kv_set('sectigo-made:%s' % req.cert_id,
                                    json.dumps({'id': sid, 'at': time.time()}),
                                    ttl_s=3 * 366 * 86400)
                return out
            if st in FAILED and not (st == 'replaced' and held.get('how') == 'replace'):
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('SCM did not issue: the certificate %s is %s' % (
                    sid, STATUS_WORDS.get(st, st)), retry=False)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('SCM has not issued yet (certificate %s: %s) - acme asks again '
                                  'at the next try' % (sid, STATUS_WORDS.get(st, st or '?')))
            self._sleep(every)

    # -- revocation, trying it ----------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        sid = self.ctx.kv_get('sectigo-cert:%s' % sc.fingerprint(cert_pem)[:40])
        code = REVOKE.get(sc.reason_code(reason), '0')
        body = {'reasonCode': code, 'reason': 'revoked by acme'}
        if sid:
            self.call('POST', '/api/ssl/v2/revoke/%s' % self._id(sid), body,
                      what='the revocation')
            return 'SCM revoked certificate %s (reason %s)' % (sid, code)
        serial = sc.serial_hex(cert_pem)
        self.call('POST', '/api/ssl/v2/revoke/serial/%s' % serial, body, what='the revocation')
        return 'SCM revoked the certificate of serial %s (reason %s)' % (serial, code)

    def test(self):
        n = len(self.types())
        words = 'SCM answers: signed in; the account has %d SSL certificate profile(s)' % n
        want = self._s('cert_type')
        if want and n and not any(str(t.get('id')) == want for t in self.types()):
            raise PluginError('%s - there is no profile %s' % (words, want), retry=False)
        return words

    # -- the certificates of the account (Certificates → Import from a source) ---------------
    def _acme_ids(self):
        out = {}
        try:
            kept = self.ctx.kv_keys('sectigo-made:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('id') and cid.isdigit():
                out[str(v['id'])] = int(cid)
        return out

    def list_existing(self):
        """Every SSL certificate of the account (GET /api/ssl/v2, 200 a page) - read only."""
        mine = self._acme_ids()
        out, pos, per = [], 0, 200
        for _page in range(100):
            got, rh = self.call('GET', '/api/ssl/v2', query={'size': per, 'position': pos},
                                what='the list of certificates', headers_back=True)
            items = [x for x in (got if isinstance(got, list) else []) if isinstance(x, dict)]
            for c in items:
                sid = str(c.get('sslId') or '').strip()
                if not sid:
                    continue
                cn = str(c.get('commonName') or '').strip()
                names = [cn] + [str(x).strip() for x in c.get('subjectAlternativeNames') or []]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                st = str(c.get('status') or '').lower()
                out.append({'ref': sid, 'cn': cn or (names[0] if names else ''), 'names': names,
                            'product': str(c.get('certTypeName') or ''),
                            'status': STATUS_WORDS.get(st, st or '?'),
                            'not_before': _when(c.get('issued')),
                            'not_after': _when(c.get('expires')),
                            'serial': str(c.get('serialNumber') or '').replace(':', '').upper(),
                            'downloadable': st in ISSUED,
                            'renewable': 'reissue' if st in ISSUED + ('expired',) else 'none',
                            'note': '' if st in ISSUED else 'SCM says it is %s' % (
                                STATUS_WORDS.get(st, st or '?')),
                            'acme_cert_id': mine.get(sid)})
            total = int(sc.num((rh or {}).get('x-total-count'), 0))
            pos += len(items)
            if len(items) < per or (total and pos >= total):
                break
        return out

    def fetch_existing(self, ref):
        """The certificate `ref` with its chain (collect, x509) - read only."""
        sid = self._id(ref)
        out = sc.existing(self.collect(sid), who='Sectigo SCM', ref=sid)
        self.ctx.kv_set('sectigo-cert:%s' % sc.fingerprint(out['cert_pem'])[:40], sid,
                        ttl_s=3 * 366 * 86400)
        out['acme_cert_id'] = self._acme_ids().get(sid)
        return out

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['auth', 'instance', 'client_id', 'client_secret', 'token_url', 'login',
                     'password', 'customer_uri', 'api_url']

    def discover_setup(self):
        """Read-only: the organizations of the account's certificates (GET /api/ssl/v2 -
        SSLIdentity orgId, orgName; else the newest one's details), the certificate profiles
        of the organization (GET /api/ssl/v2/types) - the one its certificates use most
        picked -, and an issued certificate to renew (never picked by itself)."""
        out = {'sets': {}, 'choices': {}, 'facts': [], 'notes': []}
        got = self.call('GET', '/api/ssl/v2', query={'size': 200, 'position': 0},
                        what='the list of certificates')
        items = [x for x in (got if isinstance(got, list) else []) if isinstance(x, dict)]
        out['facts'].append(['Certificates', str(len(items))])
        orgs = {}
        for c in items:
            if str(c.get('orgId') or '').strip():
                orgs.setdefault(str(c['orgId']).strip(), str(c.get('orgName') or '').strip())
        if not orgs and items and str(items[0].get('sslId') or '').strip().isdigit():
            sid = str(items[0]['sslId']).strip()
            try:
                det = self.call('GET', '/api/ssl/v2/%s' % sid, what='the certificate %s' % sid)
                if str(det.get('orgId') or '').strip():
                    orgs[str(det['orgId']).strip()] = ''
            except PluginError as e:
                out['notes'].append('the certificate %s could not be read: %s' % (sid, e))
        self.offer(out, 'org_id', [[k, '%s (%s)' % (v, k) if v else k]
                                   for k, v in sorted(orgs.items())])
        org = self._s('org_id') or (out['choices'].get('org_id') or {}).get('pick') or ''
        mine = [c for c in items if not org or str(c.get('orgId') or '') in ('', org)]
        used = {}
        for c in mine:
            if str(c.get('certTypeId') or '').strip():
                used[str(c['certTypeId']).strip()] = used.get(str(c['certTypeId']).strip(), 0) + 1
        with sc.assumed(self, {'org_id': org}):
            self._types = None
            sc.merge_found(out, sc.discover_lists(self))
        self._types = None
        ct = out['choices'].get('cert_type')
        if ct and not ct['pick'] and used:
            best = max(sorted(used), key=lambda k: used[k])
            if best in [o[0] for o in ct['options']]:
                ct['pick'] = best
        rows = []
        for c in mine:
            sid = str(c.get('sslId') or '').strip()
            if sid and str(c.get('status') or '').lower() in ISSUED:
                rows.append({'ref': sid, 'cn': str(c.get('commonName') or '').strip(),
                             'product': str(c.get('certTypeName') or ''),
                             'not_after': _when(c.get('expires')), 'renewable': 'reissue'})
        sc.reuse_choice(self, out, 'ssl_id', rows,
                        'Empty: the one acme had last for the certificate')
        return out
