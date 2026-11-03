# -*- coding: utf-8 -*-
"""
Certificates from Keyfactor Command through its REST API (KeyfactorAPI): acme's
request (CSR) enrolled with a template and a CA, the certificate and its chain
in the answer, revoked; the certificates Command knows listed for Certificates
→ Import from a source.

What the API is, and from where: Keyfactor's own clients of it -
github.com/Keyfactor/keyfactor-go-client-sdk (generated from Command's OpenAPI:
README.md, docs/EnrollmentApi.md, docs/CertificateApi.md and the models'
pages), github.com/Keyfactor/keyfactor-go-client (v3/api/certificate.go,
certificate_models.go, client.go) and github.com/Keyfactor/keyfactor-auth-client-go
(auth_providers: the API path, Basic and OAuth), read 2026-11:

* https://HOST/KeyfactorAPI/..., every request with the headers
  x-keyfactor-api-version: 1 and x-keyfactor-requested-with: APIClient.
* Signing in: HTTP Basic (DOMAIN\\user:password), or an OAuth 2.0 access token
  (client credentials at the identity provider's token address) as Bearer.
* GET Enrollment/CSR/Context/My -> {Templates [{Name, DisplayName, CAs
  [{Name}], RequiresApproval...}], StandaloneCAs [{Name}]} - the templates and
  CAs the user may enroll with (the form's lists, Try it).
* POST Enrollment/CSR (header x-certificateformat: PEM) {CSR, Template,
  CertificateAuthority, IncludeChain, Timestamp, SANs {dns [..], ip [..]} (the
  keys of Command's reference, EnrollmentPOSTCSR.htm: "dns", "ip", "email",
  "upn", "uri"), Metadata} -> {CertificateInformation {SerialNumber, IssuerDN, Thumbprint,
  KeyfactorID, KeyfactorRequestId, Certificates [PEM..], RequestDisposition,
  DispositionMessage}}.
* GET Certificates?pq.queryString=..&pq.pageReturned=N&pq.returnLimit=M
  &pq.includeRevoked=false&pq.includeExpired=false -> [{Id, IssuedCN, NotBefore,
  NotAfter, SerialNumber, Thumbprint, CertStateString, TemplateName,
  CertificateAuthorityName, SubjectAltNameElements [{Value, Type}]}].
* POST Certificates/Download (x-certificateformat: P7B) {CertID, IncludeChain}
  -> {Content: base64 PKCS#7}.
* POST Certificates/Revoke {CertificateIds [id], Reason, Comment, EffectiveDate}
  -> 200/204. Reason is Command's own list (CertificatesPOSTRevoke.htm): 0
  Unspecified, 1 Key Compromised, 2 CA Compromised, 3 Affiliation Changed, 4
  Superseded, 5 Cessation of Operation, 6 Certificate Hold, 7 Remove from CRL - not
  RFC 5280's (where removeFromCRL is 8); other reasons are sent as 0.

LESS CERTAIN: whether the query parameters of GET Certificates take the "pq."
prefix (the Go SDK's names) or not (Command's reference lists QueryString,
PageReturned, ReturnLimit) - the SDK's are sent.

A template that needs an approval in Command (RequiresApproval) leaves the
request waiting there: acme says so and does not ask again by itself.
"""
from __future__ import annotations

import base64
import calendar
import hashlib
import ipaddress
import re
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc
from acmelib.plugins.issuers import _scep_pkcs7 as p7

HEADERS = {'x-keyfactor-api-version': '1', 'x-keyfactor-requested-with': 'APIClient'}
# RFC 5280 reason -> Command's Reason (CertificatesPOSTRevoke.htm: 7 is Remove from CRL).
REASONS = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 8: 7}


def _epoch(v):
    try:
        return calendar.timegm(time.strptime(str(v or '')[:19], '%Y-%m-%dT%H:%M:%S'))
    except (TypeError, ValueError):
        return None


def _is_ip(n):
    try:
        ipaddress.ip_address(n)
        return True
    except ValueError:
        return False


class KeyfactorCommandIssuer(Issuer):
    kind = 'keyfactor_command'
    title = 'Keyfactor Command'
    description = ('Certificates from Keyfactor Command through its REST API: acme\'s request '
                   'enrolled with a template and a CA, the certificate with its chain, revoked. '
                   'Lists the certificates Command knows for importing.')
    vendor = 'Keyfactor'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    lists_existing = True           # GET Certificates + Certificates/Download: Import from a source
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    fields = [
        field('url', 'Command address', 'text', required=True,
              placeholder='https://keyfactor.example.local',
              help='The address of the Command server (its REST API is under /KeyfactorAPI).'),
        field('auth', 'Signing in', 'select', default='basic',
              options=[['basic', 'User and password (HTTP Basic)'],
                       ['oauth', 'OAuth client (client ID and secret)']]),
        field('domain', 'Domain of the user', 'text', show_if={'auth': ['basic']},
              placeholder='EXAMPLE',
              help='Sent as DOMAIN\\user. Empty: the user alone.'),
        field('user', 'User', 'text', show_if={'auth': ['basic']}),
        field('password', 'Password', 'secret', show_if={'auth': ['basic']}),
        field('token_url', 'Token address', 'text', show_if={'auth': ['oauth']},
              placeholder='https://idp.example.local/realms/Keyfactor/protocol/openid-connect/'
                          'token',
              help='The token endpoint of the identity provider Command trusts.'),
        field('client_id', 'Client ID', 'text', show_if={'auth': ['oauth']}),
        field('client_secret', 'Client secret', 'secret', show_if={'auth': ['oauth']}),
        field('scope', 'Scopes', 'text', show_if={'auth': ['oauth']}, advanced=True,
              help='Space separated, when the identity provider wants them.'),
        field('audience', 'Audience', 'text', show_if={'auth': ['oauth']}, advanced=True),
        field('template', 'Template', 'catalog', catalog='templates',
              depends=['url', 'auth', 'user', 'password', 'client_id', 'client_secret'],
              help='Load the list (the CSR enrollment templates the user may use - nothing '
                   'changes) and pick one. Its CA is set by itself when it has only one.'),
        field('ca', 'Certificate authority', 'catalog', catalog='cas', depends=['template'],
              help='The CA of the template, as Command names it (HOST\\CA name).'),
        field('template_typed', 'Template typed', 'text', advanced=True, placeholder='WebServer',
              help='Only where the list cannot be loaded here: the template\'s short name, used '
                   'instead of Template.'),
        field('ca_typed', 'Certificate authority typed', 'text', advanced=True,
              placeholder='ca01.example.local\\Example Issuing CA',
              help='Only where the list cannot be loaded here, used instead of Certificate '
                   'authority.'),
        field('list_query', 'Which certificates to list', 'text', advanced=True,
              placeholder='IssuedCN -contains "example.cz"',
              help='A Command query (pq.queryString) for Import from a source. Empty: every '
                   'certificate the user may see that is valid.'),
        field('api_path', 'API path', 'text', default='KeyfactorAPI', advanced=True),
        field('ca_pem', 'CA certificate of Command\'s TLS', 'pem', advanced=True),
        field('verify', 'Check Command\'s TLS certificate', 'bool', default=True, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self._token = None
        self._context = None

    # -- the API ---------------------------------------------------------------------------
    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        if not re.match(r'^https://[^\s/]+(/\S*)?\Z', url):
            raise PluginError('set the Command address (https://host)', retry=False)
        path = str(self.c('api_path') or 'KeyfactorAPI').strip('/ ')
        if not re.match(r'^[A-Za-z0-9_./-]+\Z', path):
            raise PluginError('the API path "%s" is not a path' % path, retry=False)
        return '%s/%s/' % (url, path)

    def _tls(self):
        return {'verify': sc.as_bool(self.c('verify'), True), 'ca_pem': self.c('ca_pem') or None}

    def _auth(self):
        if (self.c('auth') or 'basic') == 'oauth':
            return 'Bearer ' + self.token()
        user = str(self.c('user') or '').strip()
        if not user or not self.c('password'):
            raise PluginError('set the user and the password', retry=False)
        dom = str(self.c('domain') or '').strip()
        who = ('%s\\%s' % (dom, user)) if dom else user
        return 'Basic ' + base64.b64encode(('%s:%s' % (who, self.c('password'))).encode(
            'utf-8')).decode('ascii')

    def token(self):
        if self._token:
            return self._token
        if limits.sharing(self.ctx):
            self._token = limits.session(limits.key_of(self, 'token'), self._sign_in)
        else:
            self._token = self._sign_in()[0]
        return self._token

    def _sign_in(self):
        url = str(self.c('token_url') or '').strip()
        if not re.match(r'^https://\S+\Z', url):
            raise PluginError('set the token address (https://…)', retry=False)
        if not self.c('client_id') or not self.c('client_secret'):
            raise PluginError('set the client ID and the client secret', retry=False)
        form = {'grant_type': 'client_credentials', 'client_id': str(self.c('client_id')),
                'client_secret': str(self.c('client_secret'))}
        if str(self.c('scope') or '').strip():
            form['scope'] = str(self.c('scope')).strip()
        if str(self.c('audience') or '').strip():
            form['audience'] = str(self.c('audience')).strip()
        status, _h, data = sc.http(self.ctx, 'POST', url, urllib.parse.urlencode(form),
                                   {'Content-Type': 'application/x-www-form-urlencoded'},
                                   who='the identity provider', **self._tls())
        got = sc.parse_json(data) or {}
        if status != 200 or not got.get('access_token'):
            raise sc.refusal('The identity provider', status, got, data,
                             'the client ID or secret is wrong')
        return got['access_token'], max(60.0, sc.num(got.get('expires_in'), 300) - 30)

    def _raw(self, method, path, body=None, fmt=None):
        h = dict(HEADERS)
        h['Authorization'] = self._auth()
        if fmt:
            h['x-certificateformat'] = fmt
        return sc.http(self.ctx, method, self._base() + path, body, h, who='Keyfactor Command',
                       **self._tls())

    def call(self, method, path, body=None, what='', fmt=None, ok=(200, 201, 204)):
        status, _h, data = self._raw(method, path, body, fmt)
        if status == 401 and self._token and limits.sharing(self.ctx):
            limits.session_drop(limits.key_of(self, 'token'), self._token)
            self._token = None
            status, _h, data = self._raw(method, path, body, fmt)
        got = sc.parse_json(data)
        if status not in ok:
            raise sc.refusal('Keyfactor Command (%s)' % (what or path), status, got, data,
                             'the user, password or client may not do this')
        return got if got is not None else {}

    # -- the templates and CAs (the form's lists) ----------------------------------------------
    def context(self):
        if self._context is None:
            self._context = self.call('GET', 'Enrollment/CSR/Context/My',
                                      what='the enrollment templates')
        return self._context

    def catalog(self, key):
        got = self.context()
        temps = [t for t in (got.get('Templates') or []) if isinstance(t, dict) and t.get('Name')]
        if key == 'templates':
            opts, sets = [], {}
            for t in sorted(temps, key=lambda t: str(t.get('DisplayName') or t['Name']).lower()):
                cas = [c.get('Name') for c in t.get('CAs') or [] if isinstance(c, dict)
                       and c.get('Name')]
                words = str(t.get('DisplayName') or t['Name'])
                if t.get('RequiresApproval'):
                    words += ' (needs an approval)'
                opts.append([t['Name'], words])
                if len(cas) == 1:
                    sets[t['Name']] = {'ca': cas[0]}
            return {'options': opts, 'sets': sets, 'said': '%d templates' % len(opts)}
        if key == 'cas':
            want = self.template()
            t = next((t for t in temps if t['Name'] == want), None)
            cas = [c.get('Name') for c in ((t or {}).get('CAs') or []) if isinstance(c, dict)]
            cas += [c.get('Name') for c in got.get('StandaloneCAs') or [] if isinstance(c, dict)]
            cas = [c for i, c in enumerate(cas) if c and c not in cas[:i]]
            return {'options': [[c, c] for c in cas], 'said': '%d CAs' % len(cas)}
        raise PluginError('there is no list called %s here' % key, retry=False)

    def template(self):
        t = str(self.c('template_typed') or '').strip() or str(self.c('template') or '').strip()
        if not t:
            raise PluginError('set the template', retry=False)
        return t

    def ca(self):
        c = str(self.c('ca_typed') or '').strip() or str(self.c('ca') or '').strip()
        if not c:
            raise PluginError('set the certificate authority', retry=False)
        return c

    # -- the certificate ---------------------------------------------------------------------------
    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        sans = {}
        dns = [n for n in req.names if not _is_ip(n)]
        ips = [n for n in req.names if _is_ip(n)]
        if dns:
            sans['dns'] = dns
        if ips:
            sans['ip'] = ips
        body = {'CSR': sc.csr_pem(req).strip(), 'Template': self.template(),
                'CertificateAuthority': self.ca(), 'IncludeChain': True,
                'Timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'SANs': sans, 'Metadata': {}}
        got = self.call('POST', 'Enrollment/CSR', body, what='the enrollment', fmt='PEM')
        info = got.get('CertificateInformation') if isinstance(
            got.get('CertificateInformation'), dict) else {}
        certs = sc.certs_of(info.get('Certificates') or got.get('Certificates') or [])
        disp = str(info.get('RequestDisposition') or '')
        if not certs:
            said = '; '.join(x for x in (disp, str(info.get('DispositionMessage') or ''))
                             if x) or '?'
            rid = info.get('KeyfactorRequestId') or '?'
            if 'pend' in disp.lower() or 'approv' in disp.lower():
                raise PluginError('Keyfactor Command keeps request %s waiting for an approval '
                                  '(%s) - approve it in Command, or use a template that needs '
                                  'none' % (rid, said), retry=False)
            raise PluginError('Keyfactor Command did not issue request %s: %s' % (rid, said),
                              retry=False)
        kid = info.get('KeyfactorID')
        out = sc.finish(self.ctx, req, certs, who='Keyfactor Command',
                        info={'keyfactor_id': kid, 'ref': str(kid) if kid else None})
        if kid:
            self.ctx.kv_set('keyfactor-cert:%s' % sc.fingerprint(out.cert_pem)[:40], str(kid),
                            ttl_s=5 * 366 * 86400)
            if getattr(req, 'cert_id', None):
                self.ctx.kv_set('keyfactor-made:%s' % req.cert_id, str(kid),
                                ttl_s=5 * 366 * 86400)
        return out

    def _id_of(self, cert_pem):
        kid = self.ctx.kv_get('keyfactor-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if kid:
            return int(kid)
        thumb = hashlib.sha1(p7.cert_der(cert_pem)).hexdigest().upper()
        got = self.call('GET', 'Certificates?' + urllib.parse.urlencode(
            {'pq.queryString': 'Thumbprint -eq "%s"' % thumb}), what='the certificate')
        rows = got if isinstance(got, list) else []
        if not rows or not rows[0].get('Id'):
            raise PluginError('Keyfactor Command does not know the certificate %s' % thumb,
                              retry=False)
        return int(rows[0]['Id'])

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        kid = self._id_of(cert_pem)
        self.call('POST', 'Certificates/Revoke', {
            'CertificateIds': [kid], 'Reason': REASONS.get(sc.reason_code(reason), 0),
            'Comment': 'revoked by acme',
            'EffectiveDate': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
            what='the revocation')
        return 'Keyfactor Command revoked certificate %s' % kid

    def test(self):
        got = self.context()
        temps = [t.get('Name') for t in got.get('Templates') or [] if isinstance(t, dict)]
        words = 'Keyfactor Command answers: signed in; %d template(s) to enroll with' % len(temps)
        t = str(self.c('template_typed') or '').strip() or str(self.c('template') or '').strip()
        if t:
            words += '; the template %s is %s' % (t, 'among them' if t in temps else
                                                  'NOT among them')
        return words

    # -- the certificates Command knows (Certificates → Import from a source) -----------------
    def list_existing(self):
        mine = {}
        try:
            for k, v in self.ctx.kv_keys('keyfactor-made:').items():
                cid = k.split(':', 1)[1]
                if cid.isdigit() and v:
                    mine[str(v)] = int(cid)
        except (AttributeError, NotImplementedError):
            pass
        out, page, per = [], 1, 100
        while page <= 200:
            q = {'pq.pageReturned': page, 'pq.returnLimit': per, 'pq.includeRevoked': 'false',
                 'pq.includeExpired': 'false'}
            if str(self.c('list_query') or '').strip():
                q['pq.queryString'] = str(self.c('list_query')).strip()
            got = self.call('GET', 'Certificates?' + urllib.parse.urlencode(q),
                            what='the certificates')
            rows = [r for r in (got if isinstance(got, list) else []) if isinstance(r, dict)]
            for r in rows:
                kid = str(r.get('Id') or '')
                if not kid:
                    continue
                cn = str(r.get('IssuedCN') or '')
                sans = [str(s.get('Value') or '') for s in r.get('SubjectAltNameElements') or []
                        if isinstance(s, dict)]
                names = [cn] + [s for s in sans if re.match(r'^[\w*.:-]+\Z', s)]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                st = str(r.get('CertStateString') or '')
                out.append({'ref': kid, 'cn': cn or (names[0] if names else ''), 'names': names,
                            'product': str(r.get('TemplateName') or
                                           r.get('CertificateAuthorityName') or ''),
                            'status': st.lower() or 'issued',
                            'not_before': _epoch(r.get('NotBefore')),
                            'not_after': _epoch(r.get('NotAfter')),
                            'serial': str(r.get('SerialNumber') or '').upper(),
                            'downloadable': True, 'renewable': 'issue',
                            'note': '', 'acme_cert_id': mine.get(kid)})
            if len(rows) < per:
                break
            page += 1
        return out

    def fetch_existing(self, ref):
        kid = str(ref or '').strip()
        if not kid.isdigit():
            raise PluginError('%s is not a certificate id of Command' % (kid or '?'),
                              retry=False)
        got = self.call('POST', 'Certificates/Download', {'CertID': int(kid),
                                                          'IncludeChain': True},
                        what='the certificate %s' % kid, fmt='P7B')
        out = sc.existing(sc.certs_of(got.get('Content') or ''), who='Keyfactor Command',
                          ref=kid)
        self.ctx.kv_set('keyfactor-cert:%s' % sc.fingerprint(out['cert_pem'])[:40], kid,
                        ttl_s=5 * 366 * 86400)
        return out

    # -- discovery (1.0.29): the form filled in from Command --------------------------------
    discover_keys = ['url', 'auth', 'domain', 'user', 'password', 'token_url', 'client_id',
                     'client_secret', 'scope', 'audience', 'api_path', 'ca_pem', 'verify']

    def discover_setup(self):
        """Read-only: the templates the user may enroll with (Enrollment/CSR/Context/My) -
        each with its CA where it has one - and, with no template yet, every CA of them."""
        out = sc.discover_lists(self)               # either way of signing in
        if 'ca' not in out['choices'] and not self.c('template_typed') and \
                not self.c('template') and 'template' in out['choices']:
            got = self.context()
            cas = [c.get('Name') for t in got.get('Templates') or [] if isinstance(t, dict)
                   for c in t.get('CAs') or [] if isinstance(c, dict)]
            cas += [c.get('Name') for c in got.get('StandaloneCAs') or [] if isinstance(c, dict)]
            cas = [c for i, c in enumerate(cas) if c and c not in cas[:i]]
            self.offer(out, 'ca', [[c, c] for c in cas])
            out['notes'] = [n for n in out['notes'] if not n.startswith(
                'Certificate authority: set ')]
        return out
