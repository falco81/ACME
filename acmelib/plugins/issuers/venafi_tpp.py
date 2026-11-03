# -*- coding: utf-8 -*-
"""
Certificates from CyberArk Certificate Manager, Self-Hosted - Venafi Trust
Protection Platform (TPP) - through its WebSDK REST API: acme's request (CSR)
sent into a policy folder, the certificate fetched when the platform's CA has
issued it, renewed in place, revoked; the folder's certificates listed for
Certificates → Import from a source.

What the API is, and from where: Venafi's (now CyberArk's) own client of it,
github.com/Venafi/vcert (pkg/venafi/tpp/tpp.go, connector.go, search.go;
README-CLI-PLATFORM.md), read 2026-11, and the WebSDK reference
(https://docs.venafi.com/Docs/current/TopNav/Content/SDK/WebSDK/r-SDK-POST-Certificates-request.php,
...-retrieve.php, ...-renew.php, ...-revoke.php, r-SDK-GET-Certificates.php): the
SANs as {"TypeName": "2", "Name": ...}, the Format "Base64" ("case sensitive
values"). Every path is under https://HOST/:

* POST vedauth/authorize/oauth {client_id, username, password, scope} ->
  {access_token, expires (epoch), refresh_token}; sent after as "Authorization:
  Bearer". Defaults of vcert: client_id "vcert-sdk", scope
  "certificate:manage,revoke". Or a token made in the platform, used as given.
* GET vedsdk/Identity/Self -> {Identities [{Name, FullName...}]} (Try it).
* POST vedsdk/certificates/request {PolicyDN (\\VED\\Policy\\FOLDER), PKCS10,
  SubjectAltNames [{TypeName 2 DNS | 7 IP, Name}], CADN, ObjectName,
  DisableAutomaticRenewal true, CertificateType "AUTO", Origin,
  CASpecificAttributes [{Name "Origin", Value}]} -> {CertificateDN}.
* POST vedsdk/certificates/retrieve {CertificateDN, Format "Base64",
  IncludeChain true, RootFirstOrder false} -> {CertificateData (base64 of PEM),
  Status, Stage}; while it is being made CertificateData is empty (200 or 202).
* POST vedsdk/certificates/renew {CertificateDN, PKCS10} -> {Success, Error}.
* POST vedsdk/certificates/revoke {Thumbprint (SHA-1), Reason (0 none, 1 key
  compromise, 2 CA compromise, 3 affiliation changed, 4 superseded, 5 cessation),
  Comments, Disable} -> {Requested, Success, Error}.
* GET vedsdk/certificates/?ParentDNRecursive=POLICY&limit=N&offset=M
  [&ValidToGreater=RFC3339] -> {Certificates [{DN, X509 {CN, SANS {DNS, IP},
  Serial, Thumbprint, ValidFrom, ValidTo}}]} (Import from a source).
* POST vedsdk/config/findobjectsofclass {Class "Policy", ObjectDN
  "\\VED\\Policy"} -> {Objects [{DN, Name}]} (the folders for the form's list).

UNCERTAIN: findobjectsofclass may need the "configuration" scope - the list in
the form says so and the folder is typed instead.
"""
from __future__ import annotations

import base64
import calendar
import hashlib
import re
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc
from acmelib.plugins.issuers import _scep_pkcs7 as p7

ROOT = '\\VED\\Policy'
# RFC 5280 codes the WebSDK takes (vcert RevocationReasonsMap); others are sent as 0.
REASONS = (0, 1, 2, 3, 4, 5)


def policy_dn(zone):
    """vcert's getPolicyDN: a folder under \\VED\\Policy (written with or without it)."""
    z = str(zone or '').strip()
    if z.upper().startswith(ROOT.upper()):
        return z
    return ROOT + ('' if z.startswith('\\') else '\\') + z


def _epoch(v):
    s = str(v or '')
    for fmt, n in (('%Y-%m-%dT%H:%M:%S', 19), ('%Y-%m-%d', 10)):
        try:
            return calendar.timegm(time.strptime(s[:n], fmt))
        except (TypeError, ValueError):
            continue
    m = re.match(r'^/Date\((\d+)', s)
    return int(m.group(1)) // 1000 if m else None


class VenafiTppIssuer(Issuer):
    kind = 'venafi_tpp'
    title = 'CyberArk Certificate Manager Self-Hosted (Venafi TPP)'
    description = ('Certificates from CyberArk Certificate Manager, Self-Hosted (Venafi Trust '
                   'Protection Platform) through its WebSDK: acme\'s request sent into a policy '
                   'folder, fetched when issued, renewed in place, revoked. Lists the folder\'s '
                   'certificates for importing.')
    vendor = 'CyberArk (Venafi)'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    lists_existing = True           # vedsdk/certificates/ + retrieve: Import from a source
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    fields = [
        field('url', 'Platform address', 'text', required=True,
              placeholder='https://tpp.example.local',
              help='The address of the platform (WebSDK); /vedsdk at its end is left out by '
                   'itself.'),
        field('auth', 'Signing in', 'select', default='password',
              options=[['password', 'User and password (an OAuth token made by acme)'],
                       ['token', 'An access token made in the platform']]),
        field('user', 'User', 'text', show_if={'auth': ['password']},
              help='A user with WebSDK access and the right to request certificates in the '
                   'folder.'),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('access_token', 'Access token', 'secret', show_if={'auth': ['token']},
              help='Made for the API application with the scope certificate:manage,revoke. It '
                   'is used as it is - make a new one before it ends.'),
        field('zone', 'Policy folder', 'catalog', catalog='zones',
              depends=['url', 'auth', 'user', 'password', 'access_token'],
              help='Load the list (the platform is asked, nothing changes) and pick the folder '
                   'the certificates go into.'),
        field('zone_typed', 'Policy folder typed', 'text', advanced=True,
              placeholder='DevOps\\Web servers',
              help='Only where the list cannot be loaded here: the folder under \\VED\\Policy '
                   '(written with or without it), used instead of Policy folder.'),
        field('ca_dn', 'CA template (CADN)', 'text', advanced=True,
              placeholder='\\VED\\Policy\\Certificate Authorities\\Issuing CA',
              help='Empty: the one the folder\'s policy sets.'),
        field('object_name', 'Name of the certificate object', 'select', default='',
              advanced=True,
              options=[['', 'as the platform names it (the common name)'],
                       ['first', 'the first name of the certificate']]),
        field('renew_in_place', 'Renew the same certificate object', 'bool', default=True,
              advanced=True,
              help='A renewal (and a certificate imported from the platform) renews its object '
                   '(certificates/renew) instead of asking for a new one.'),
        field('client_id', 'API application (client_id)', 'text', default='vcert-sdk',
              advanced=True, show_if={'auth': ['password']}),
        field('scope', 'Scope of the token', 'text', default='certificate:manage,revoke',
              advanced=True, show_if={'auth': ['password']}),
        field('wait', 'Wait for the certificate (s)', 'number', default=120, advanced=True,
              help='Longer (an approval in the platform): acme asks again at the next try.'),
        field('poll_every', 'Ask again every (s)', 'number', default=5, advanced=True),
        field('ca_pem', 'CA certificate of the platform\'s TLS', 'pem', advanced=True),
        field('verify', 'Check the platform\'s TLS certificate', 'bool', default=True,
              advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self._sleep = time.sleep
        self._token = None

    # -- the API ---------------------------------------------------------------------------
    def _base(self):
        url = str(self.c('url') or '').strip().rstrip('/')
        url = re.sub(r'/vedsdk\Z', '', url, flags=re.I)
        if not re.match(r'^https://[^\s/]+\Z', url):
            raise PluginError('set the platform address (https://host)', retry=False)
        return url + '/'

    def _raw(self, method, path, body=None, auth=True):
        h = {}
        if auth:
            h['Authorization'] = 'Bearer ' + self.token()
        return sc.http(self.ctx, method, self._base() + path, body, h, who='the platform',
                       verify=sc.as_bool(self.c('verify'), True), ca_pem=self.c('ca_pem') or None)

    def call(self, method, path, body=None, what='', ok=(200, 201, 202), auth=True):
        status, _h, data = self._raw(method, path, body, auth)
        if status == 401 and auth and (self.c('auth') or 'password') == 'password' and \
                limits.sharing(self.ctx):
            limits.session_drop(limits.key_of(self, 'token'), self._token)
            self._token = None
            status, _h, data = self._raw(method, path, body, auth)
        got = sc.parse_json(data)
        if status not in ok:
            raise sc.refusal('The platform (%s)' % (what or path), status, got, data,
                             'the user, password or token is wrong, or may not do this')
        return got if got is not None else {}

    def token(self):
        if (self.c('auth') or 'password') == 'token':
            t = str(self.c('access_token') or '').strip()
            if not t:
                raise PluginError('set the access token', retry=False)
            return t
        if self._token:
            return self._token
        if limits.sharing(self.ctx):
            self._token = limits.session(limits.key_of(self, 'token'), self._sign_in)
        else:
            self._token = self._sign_in()[0]
        return self._token

    def _sign_in(self):
        if not self.c('user') or not self.c('password'):
            raise PluginError('set the user and the password', retry=False)
        got = self.call('POST', 'vedauth/authorize/oauth', {
            'client_id': str(self.c('client_id') or 'vcert-sdk'),
            'username': str(self.c('user')), 'password': str(self.c('password')),
            'scope': str(self.c('scope') or 'certificate:manage,revoke')},
            what='signing in', ok=(200,), auth=False)
        tok = got.get('access_token')
        if not tok:
            raise PluginError('the platform gave no access token', retry=False)
        lives = sc.num(got.get('expires'), 0) - time.time() if got.get('expires') else 3600
        return tok, max(60.0, min(lives - 60, 3600.0))

    def zone(self):
        z = str(self.c('zone_typed') or '').strip() or str(self.c('zone') or '').strip()
        if not z:
            raise PluginError('set the policy folder', retry=False)
        return policy_dn(z)

    # -- discovery (1.0.29): the policy folders, signed in either way ----------------------
    discover_keys = ['url', 'auth', 'user', 'password', 'access_token', 'client_id', 'scope',
                     'ca_pem', 'verify']

    def discover_setup(self):
        """Read-only: the policy folders (the form's list) - with an access token too (the
        user and password it hides are not needed)."""
        return sc.discover_lists(self)

    # -- the form's list (base.py: a field of the type catalog) -------------------------------
    def catalog(self, key):
        if key != 'zones':
            raise PluginError('there is no list called %s here' % key, retry=False)
        got = self.call('POST', 'vedsdk/config/findobjectsofclass',
                        {'Class': 'Policy', 'ObjectDN': ROOT}, what='the policy folders',
                        ok=(200, 202))
        dns = sorted({str(o.get('DN') or '') for o in got.get('Objects') or []
                      if isinstance(o, dict) and o.get('DN')}, key=str.lower)
        opts = [[d[len(ROOT) + 1:] if d.upper().startswith(ROOT.upper() + '\\') else d,
                 d[len(ROOT) + 1:] if d.upper().startswith(ROOT.upper() + '\\') else d]
                for d in dns]
        return {'options': opts, 'said': '%d policy folders' % len(opts)}

    # -- the certificate ---------------------------------------------------------------------------
    def request_body(self, req):
        sans = []
        for n in req.names or []:
            sans.append({'TypeName': '7' if re.match(r'^[\d.]+\Z|:', n) else '2', 'Name': n})
        body = {'PolicyDN': self.zone(), 'PKCS10': sc.csr_pem(req).strip(),
                'SubjectAltNames': sans, 'DisableAutomaticRenewal': True,
                'CertificateType': 'AUTO', 'Origin': 'acme',
                'CASpecificAttributes': [{'Name': 'Origin', 'Value': 'acme'}]}
        if str(self.c('ca_dn') or '').strip():
            body['CADN'] = str(self.c('ca_dn')).strip()
        if (self.c('object_name') or '') == 'first' and req.names:
            body['ObjectName'] = req.names[0]
        return body

    def _kept_dn(self, req):
        if getattr(req, 'ref', None):
            return str(req.ref)
        if not sc.as_bool(self.c('renew_in_place'), True) or not getattr(req, 'cert_id', None):
            return None
        return self.ctx.kv_get('venafi-tpp-dn:%s' % req.cert_id)

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        slot = sc.pending_slot('venafi-tpp', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        if held:
            dn = held['id']
            sc.say(self.ctx, 'the request %s waits in the platform - asked for again' % dn)
        else:
            dn = self._kept_dn(req)
            if dn and sc.as_bool(self.c('renew_in_place'), True):
                got = self.call('POST', 'vedsdk/certificates/renew',
                                {'CertificateDN': dn, 'PKCS10': sc.csr_pem(req).strip()},
                                what='the renewal of %s' % dn)
                if not got.get('Success'):
                    raise PluginError('the platform did not renew %s: %s' % (
                        dn, got.get('Error') or 'no reason given'), retry=False)
                sc.say(self.ctx, 'the platform renews %s with acme\'s request' % dn, 'ok')
            else:
                got = self.call('POST', 'vedsdk/certificates/request', self.request_body(req),
                                what='the request')
                dn = str(got.get('CertificateDN') or '')
                if not dn:
                    raise PluginError('the platform took no request: %s' % (
                        got.get('Error') or 'it said no certificate DN'), retry=False)
                sc.say(self.ctx, 'the platform took the request: %s' % dn, 'ok')
            held = sc.pending_put(self.ctx, slot, req, {'id': dn, 'csr_pem': sc.csr_pem(req)},
                                  ttl_days=30)
            r = req
        certs = self._await(dn)
        out = sc.finish(self.ctx, r, certs, who='the platform',
                        key_pem=r.key_pem if r is not req else None,
                        info={'certificate_dn': dn, 'ref': dn})
        sc.pending_drop(self.ctx, slot)
        if getattr(req, 'cert_id', None):
            self.ctx.kv_set('venafi-tpp-dn:%s' % req.cert_id, dn, ttl_s=5 * 366 * 86400)
        return out

    def retrieve(self, dn):
        """The certificates (DER) of `dn`, [] while it is being made."""
        got = self.call('POST', 'vedsdk/certificates/retrieve', {
            'CertificateDN': dn, 'Format': 'Base64', 'IncludeChain': True,
            'RootFirstOrder': False}, what='the certificate %s' % dn)
        data = got.get('CertificateData') or ''
        if not data:
            return [], got
        try:
            raw = base64.b64decode(data)
        except ValueError:
            raw = data.encode() if isinstance(data, str) else data
        return sc.certs_of(raw), got

    def _await(self, dn):
        end = time.time() + sc.num(self.c('wait'), 120)
        every = max(1.0, sc.num(self.c('poll_every'), 5))
        while True:
            certs, got = self.retrieve(dn)
            if certs:
                return certs
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('the platform has not issued %s yet (%s) - acme asks again at '
                                  'the next try' % (dn, got.get('Status') or 'waiting'))
            self._sleep(every)

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        thumb = hashlib.sha1(p7.cert_der(cert_pem)).hexdigest().upper()
        code = sc.reason_code(reason)
        code = code if code in REASONS else 0
        got = self.call('POST', 'vedsdk/certificates/revoke', {
            'Thumbprint': thumb, 'Reason': code, 'Comments': 'revoked by acme'},
            what='the revocation')
        if got.get('Success') is False or got.get('Error'):
            raise PluginError('the platform did not revoke it: %s' % (got.get('Error') or '?'),
                              retry=False)
        if got.get('Requested', True):
            return 'the platform took the revocation of %s' % thumb
        return 'the platform had revoked %s already' % thumb

    def test(self):
        got = self.call('GET', 'vedsdk/Identity/Self', what='who signs in')
        ids = got.get('Identities') or []
        who = (ids[0].get('FullName') or ids[0].get('Name')) if ids and isinstance(
            ids[0], dict) else '?'
        words = 'the platform answers: signed in as %s' % who
        z = str(self.c('zone_typed') or '').strip() or str(self.c('zone') or '').strip()
        words += '; folder %s' % policy_dn(z) if z else '; no policy folder set yet'
        return words

    # -- the certificates of the folder (Certificates → Import from a source) -----------------
    def list_existing(self):
        """The valid certificates of the folder and those under it - read only."""
        zone = self.zone()
        now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        out, offset, per = [], 0, 500
        for _page in range(200):
            q = urllib.parse.urlencode({'ParentDNRecursive': zone, 'limit': per,
                                        'offset': offset, 'ValidToGreater': now})
            got = self.call('GET', 'vedsdk/certificates/?' + q, what='the certificates')
            items = [x for x in (got.get('Certificates') or []) if isinstance(x, dict)]
            for c in items:
                dn = str(c.get('DN') or '')
                x = c.get('X509') if isinstance(c.get('X509'), dict) else {}
                sans = x.get('SANS') if isinstance(x.get('SANS'), dict) else {}
                cn = str(x.get('CN') or '')
                names = [cn] + [str(n) for n in (sans.get('DNS') or []) + (sans.get('IP') or [])]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                out.append({'ref': dn, 'cn': cn or (names[0] if names else ''), 'names': names,
                            'product': dn.rsplit('\\', 1)[0][len(ROOT) + 1:] if '\\' in dn
                            else '', 'status': 'issued',
                            'not_before': _epoch(x.get('ValidFrom')),
                            'not_after': _epoch(x.get('ValidTo')),
                            'serial': str(x.get('Serial') or '').upper(),
                            'downloadable': bool(dn), 'renewable': 'reissue',
                            'note': '', 'acme_cert_id': None})
            offset += len(items)
            if len(items) < per:
                break
        mine = {}
        try:
            for k, v in self.ctx.kv_keys('venafi-tpp-dn:').items():
                cid = k.split(':', 1)[1]
                if cid.isdigit() and v:
                    mine[str(v)] = int(cid)
        except (AttributeError, NotImplementedError):
            pass
        for o in out:
            o['acme_cert_id'] = mine.get(o['ref'])
        return out

    def fetch_existing(self, ref):
        dn = str(ref or '').strip()
        if not dn.upper().startswith(ROOT.upper() + '\\'):
            raise PluginError('%s is not a certificate of the platform (\\VED\\Policy\\…)'
                              % (dn or '?'), retry=False)
        certs, got = self.retrieve(dn)
        if not certs:
            raise PluginError('the platform has no certificate in %s (%s)' % (
                dn, got.get('Status') or 'not issued'), retry=False)
        return sc.existing(certs, who='the platform', ref=dn)

