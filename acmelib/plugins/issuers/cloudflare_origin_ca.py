# -*- coding: utf-8 -*-
"""
Cloudflare Origin CA certificates: certificates for the server behind
Cloudflare's proxy (the "origin"), trusted by Cloudflare's edge only - not by
browsers. acme's request (CSR) goes to the Origin CA API, the certificate comes
back at once; the root of the Origin CA is put above it. A zone's Origin CA
certificates are listed for Certificates → Import from a source.

What the API is, and from where: Cloudflare's own Go client,
github.com/cloudflare/cloudflare-go - origin_ca.go and consts.go (branch v0),
origin_ca_certificates/origincacertificate.go, shared/shared.go,
ssl/certificatepack.go and zones (branch main), api_token.go, pagination.go -
read 2026-11 (the API's documentation: https://developers.cloudflare.com/api/
resources/origin_ca_certificates/, not readable from where this was written):

* https://api.cloudflare.com/client/v4, JSON {success, errors [{code, message}],
  result, result_info {page, per_page, total_pages, count, total_count}}.
* Signing in: an API token ("Authorization: Bearer", the permission Zone → SSL
  and Certificates → Edit) or the account's Origin CA Key as the header
  X-Auth-User-Service-Key.
* POST /certificates {csr, hostnames [..], request_type origin-rsa | origin-ecc,
  requested_validity 7 | 30 | 90 | 365 | 730 | 1095 | 5475 (days)} -> result {id,
  certificate (PEM), hostnames, expires_on, request_type, requested_validity}.
* GET /certificates?zone_id=ZONE&page=N&per_page=M -> the zone's certificates;
  GET /certificates/{id}; DELETE /certificates/{id} -> revoked {id, revoked_at}.
* GET /zones?page=N&per_page=M -> result [{id, name}] (the form's list of zones);
  GET /user/tokens/verify -> {status} (Try it with an API token).
* The Origin CA roots: https://developers.cloudflare.com/ssl/static/
  origin_ca_rsa_root.pem and origin_ca_ecc_root.pem.

The hostnames must be in zones of the account (Cloudflare refuses others).
"""
from __future__ import annotations

import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _source_common as sc

API = 'https://api.cloudflare.com/client/v4'
ROOTS = {'origin-rsa': 'https://developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem',
         'origin-ecc': 'https://developers.cloudflare.com/ssl/static/origin_ca_ecc_root.pem'}
VALIDITY = ('7', '30', '90', '365', '730', '1095', '5475')


class CloudflareOriginCaIssuer(Issuer):
    kind = 'cloudflare_origin_ca'
    title = 'Cloudflare Origin CA'
    description = ('Certificates for a server behind Cloudflare\'s proxy from the Cloudflare '
                   'Origin CA: trusted by Cloudflare only, not by browsers. Issued at once for '
                   'names in the account\'s zones; revocation included. Lists a zone\'s Origin '
                   'CA certificates for importing.')
    vendor = 'Cloudflare'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = False
    public_names = False            # trusted by Cloudflare's edge only
    lists_existing = True           # GET /certificates?zone_id + GET one: Import from a source
    fields = [
        field('auth', 'Signing in', 'select', default='token',
              options=[['token', 'API token (Zone - SSL and Certificates - Edit)'],
                       ['service_key', 'Origin CA Key (X-Auth-User-Service-Key)']],
              help='An API token is the better one: it can be limited to the zones it needs.'),
        field('api_token', 'API token', 'secret', show_if={'auth': ['token']},
              help='My Profile → API Tokens → Create Token, with Zone → SSL and Certificates '
                   '→ Edit (and Zone → Zone → Read for the list of zones).'),
        field('service_key', 'Origin CA Key', 'secret', show_if={'auth': ['service_key']},
              help='My Profile → API Tokens → Origin CA Key → View.'),
        field('validity', 'Validity', 'select', default='90',
              options=[['7', '7 days'], ['30', '30 days'], ['90', '90 days'],
                       ['365', '1 year'], ['730', '2 years'], ['1095', '3 years'],
                       ['5475', '15 years']],
              help='requested_validity of each certificate.'),
        field('request_type', 'Kind of the certificate', 'select', default='auto',
              options=[['auto', 'as the key: ECDSA keys origin-ecc, RSA keys origin-rsa'],
                       ['origin-ecc', 'origin-ecc'], ['origin-rsa', 'origin-rsa']],
              advanced=True),
        field('zone', 'Zone (for importing)', 'catalog', catalog='zones',
              depends=['auth', 'api_token', 'service_key'],
              help='Only for Import from a source: Cloudflare lists Origin CA certificates zone '
                   'by zone. Load the list and pick the zone.'),
        field('zone_id', 'Zone ID typed', 'text', advanced=True,
              placeholder='023e105f4ecef8ad9ca31a8372d0c353',
              help='Only where the list cannot be loaded here (an Origin CA Key reads no '
                   'zones): the zone\'s ID from its Overview page, used instead of Zone.'),
        field('add_root', 'Put the Origin CA root above the certificate', 'bool', default=True,
              advanced=True,
              help='Cloudflare\'s answer holds the certificate alone; its root is fetched from '
                   'developers.cloudflare.com for the chain.'),
        field('api_url', 'API address', 'text', default=API, advanced=True),
    ]

    # -- the API ---------------------------------------------------------------------------
    def _base(self):
        url = str(self.c('api_url') or API).strip().rstrip('/')
        if not re.match(r'^https://[^\s/]+(/\S*)?\Z', url):
            raise PluginError('the Cloudflare API address is not an https address', retry=False)
        return url

    def _headers(self):
        if (self.c('auth') or 'token') == 'service_key':
            k = str(self.c('service_key') or '').strip()
            if not k:
                raise PluginError('set the Origin CA Key', retry=False)
            return {'X-Auth-User-Service-Key': k}
        t = str(self.c('api_token') or '').strip()
        if not t:
            raise PluginError('set the API token', retry=False)
        return {'Authorization': 'Bearer ' + t}

    def call(self, method, path, body=None, what=''):
        status, _h, data = sc.http(self.ctx, method, self._base() + path, body, self._headers(),
                                   who='Cloudflare')
        got = sc.parse_json(data)
        if status >= 400 or not isinstance(got, dict) or got.get('success') is False:
            errs = (got or {}).get('errors') if isinstance(got, dict) else None
            if errs:
                said = '; '.join('%s (%s)' % (e.get('message'), e.get('code')) for e in errs
                                 if isinstance(e, dict))
                detail = data.decode('utf-8', 'replace')[:3000]
                if status in (401, 403):
                    raise PluginError('Cloudflare refused %s: %s - the token or key is wrong, or '
                                      'may not do this' % (what or path, said), detail=detail,
                                      retry=False)
                raise PluginError('Cloudflare refused %s: %s' % (what or path, said),
                                  detail=detail, retry=status >= 500 or status == 429)
            raise sc.refusal('Cloudflare (%s)' % (what or path), status, got, data,
                             'the token or key is wrong, or may not do this')
        return got

    def zone_id(self):
        z = str(self.c('zone_id') or '').strip() or str(self.c('zone') or '').strip()
        if not re.match(r'^[0-9a-f]{32}\Z', z):
            raise PluginError('set the zone (Load the list) or type its ID', retry=False)
        return z

    def request_type(self, req):
        t = self.c('request_type') or 'auto'
        if t in ROOTS:
            return t
        return 'origin-rsa' if str(getattr(req, 'key_type', '') or '').startswith('rsa') \
            else 'origin-ecc'

    def _root(self, rtype):
        if not sc.as_bool(self.c('add_root'), True):
            return []
        try:
            status, _h, data = sc.http(self.ctx, 'GET', ROOTS[rtype], None,
                                       {'Accept': '*/*'}, who='developers.cloudflare.com')
            if status == 200:
                return sc.certs_of(data)
            sc.say(self.ctx, 'the Origin CA root could not be fetched (%s) - the certificate '
                             'comes without it' % status, 'warn')
        except PluginError as e:
            sc.say(self.ctx, 'the Origin CA root could not be fetched (%s) - the certificate '
                             'comes without it' % e, 'warn')
        return []

    # -- the form's list -------------------------------------------------------------------------
    def catalog(self, key):
        if key != 'zones':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts, page = [], 1
        while page <= 20:
            got = self.call('GET', '/zones?' + urllib.parse.urlencode({'page': page,
                                                                        'per_page': 50}),
                            what='the zones')
            for z in got.get('result') or []:
                if isinstance(z, dict) and z.get('id'):
                    opts.append([str(z['id']), str(z.get('name') or z['id'])])
            info = got.get('result_info') or {}
            if page >= int(sc.num(info.get('total_pages'), 1)):
                break
            page += 1
        return {'options': opts, 'said': '%d zones' % len(opts)}

    # -- the certificate ---------------------------------------------------------------------------
    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        days = str(self.c('validity') or '90')
        if days not in VALIDITY:
            raise PluginError('Cloudflare gives Origin CA certificates for %s days only'
                              % ', '.join(VALIDITY), retry=False)
        rtype = self.request_type(req)
        got = self.call('POST', '/certificates', {
            'csr': sc.csr_pem(req).strip(), 'hostnames': list(req.names),
            'request_type': rtype, 'requested_validity': int(days)}, what='the certificate')
        res = got.get('result') or {}
        cid = str(res.get('id') or '')
        out = sc.finish(self.ctx, req, sc.certs_of(res.get('certificate') or ''),
                        self._root(rtype), who='Cloudflare',
                        info={'origin_ca_id': cid, 'ref': cid or None})
        if cid:
            self.ctx.kv_set('cf-origin-cert:%s' % sc.fingerprint(out.cert_pem)[:40], cid,
                            ttl_s=16 * 366 * 86400)
            if getattr(req, 'cert_id', None):
                self.ctx.kv_set('cf-origin-made:%s' % req.cert_id, cid, ttl_s=16 * 366 * 86400)
        return out

    @staticmethod
    def _safe(cid):
        cid = str(cid or '').strip()
        if not re.match(r'^[0-9A-Za-z]{1,80}\Z', cid):
            raise PluginError('"%s" is not an Origin CA certificate id' % cid, retry=False)
        return cid

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        cid = self.ctx.kv_get('cf-origin-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if not cid:
            raise PluginError('acme does not know the certificate\'s id at Cloudflare - revoke '
                              'it in the dashboard (SSL/TLS → Origin Server)', retry=False)
        self.call('DELETE', '/certificates/%s' % self._safe(cid), what='the revocation')
        return 'Cloudflare revoked the Origin CA certificate %s' % cid

    def test(self):
        if (self.c('auth') or 'token') == 'token':
            got = self.call('GET', '/user/tokens/verify', what='the API token')
            words = 'Cloudflare answers: the API token is %s' % (
                (got.get('result') or {}).get('status') or '?')
        else:
            words = 'Cloudflare answers'
        z = str(self.c('zone_id') or '').strip() or str(self.c('zone') or '').strip()
        if z:
            got = self.call('GET', '/certificates?' + urllib.parse.urlencode(
                {'zone_id': self.zone_id(), 'page': 1, 'per_page': 5}),
                what='the zone\'s certificates')
            words += '; the zone has %s Origin CA certificate(s)' % (
                (got.get('result_info') or {}).get('total_count', len(got.get('result') or [])))
        elif words == 'Cloudflare answers':
            words += ' nothing yet: an Origin CA Key is checked by the first certificate (or ' \
                     'set the zone)'
        return words

    # -- a zone's certificates (Certificates → Import from a source) ---------------------------
    def list_existing(self):
        from acmelib.certs import pki
        zone = self.zone_id()
        mine = {}
        try:
            for k, v in self.ctx.kv_keys('cf-origin-made:').items():
                cid = k.split(':', 1)[1]
                if cid.isdigit() and v:
                    mine[str(v)] = int(cid)
        except (AttributeError, NotImplementedError):
            pass
        out, page = [], 1
        while page <= 100:
            got = self.call('GET', '/certificates?' + urllib.parse.urlencode(
                {'zone_id': zone, 'page': page, 'per_page': 50}), what='the certificates')
            for c in got.get('result') or []:
                if not isinstance(c, dict) or not c.get('id'):
                    continue
                cid = str(c['id'])
                info = {}
                try:
                    info = pki.cert_info(c.get('certificate') or '') if c.get('certificate') \
                        else {}
                except Exception:                       # noqa: BLE001
                    info = {}
                names = [str(n) for n in c.get('hostnames') or []] or list(info.get('names') or [])
                revoked = bool(c.get('revoked_at'))
                na = info.get('not_after')
                expired = bool(na and na < time.time())
                out.append({'ref': cid, 'cn': info.get('cn') or (names[0] if names else ''),
                            'names': names, 'product': 'Origin CA (%s, %s days)' % (
                                c.get('request_type') or '?', c.get('requested_validity') or '?'),
                            'status': 'revoked' if revoked else 'expired' if expired else 'issued',
                            'not_before': info.get('not_before'), 'not_after': na,
                            'serial': str(info.get('serial') or '').upper(),
                            'downloadable': bool(c.get('certificate')) and not revoked,
                            'renewable': 'none' if revoked else 'issue',
                            'note': 'revoked' if revoked else '',
                            'acme_cert_id': mine.get(cid)})
            info = got.get('result_info') or {}
            if page >= int(sc.num(info.get('total_pages'), 1)):
                break
            page += 1
        return out

    def fetch_existing(self, ref):
        cid = self._safe(ref)
        got = self.call('GET', '/certificates/%s' % cid, what='the certificate %s' % cid)
        res = got.get('result') or {}
        if res.get('revoked_at'):
            raise PluginError('the certificate %s is revoked' % cid, retry=False)
        certs = sc.certs_of(res.get('certificate') or '')
        rtype = res.get('request_type') if res.get('request_type') in ROOTS else 'origin-rsa'
        out = sc.existing(certs, self._root(rtype), who='Cloudflare', ref=cid)
        self.ctx.kv_set('cf-origin-cert:%s' % sc.fingerprint(out['cert_pem'])[:40], cid,
                        ttl_s=16 * 366 * 86400)
        return out

    # -- discovery (1.0.29): the form filled in from the account ------------------------------
    discover_keys = ['auth', 'api_token', 'service_key', 'api_url']

    def discover_setup(self):
        """Read-only: the zones (the form's list, with the API token) and, of the zone set or
        the only one, its Origin CA certificates (GET /certificates?zone_id=): the validity of
        the newest one."""
        out = sc.discover_lists(self)               # either way of signing in
        zone = str(self.c('zone_id') or '').strip() or str(self.c('zone') or '').strip() or \
            (out['choices'].get('zone') or {}).get('pick') or ''
        if not re.match(r'^[0-9a-f]{32}\Z', zone):
            return out
        got = self.call('GET', '/certificates?' + urllib.parse.urlencode(
            {'zone_id': zone, 'page': 1, 'per_page': 50}), what='the certificates')
        live = [c for c in got.get('result') or [] if isinstance(c, dict) and
                not c.get('revoked_at')]
        out['facts'].append(['Origin CA certificates', str(len(live))])
        live.sort(key=lambda c: str(c.get('expires_on') or ''), reverse=True)
        days = next((str(c['requested_validity']) for c in live if c.get('requested_validity')),
                    '')
        if days in VALIDITY:
            out['sets']['validity'] = days
        return out
