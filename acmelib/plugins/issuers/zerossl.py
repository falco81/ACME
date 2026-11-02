# -*- coding: utf-8 -*-
"""
Certificates from ZeroSSL through its REST API (not ACME): the certificate
asked for with acme's request (CSR), the domain validation (DCV) record or file
put in place by the certificate's own validation (base.Challenge.place;
acmelib/plugins/issuers/_dcv.py), the certificate downloaded. The account's
certificates are listed for Certificates → Import from a source.

The ZeroSSL ACME server (with EAB) is the `acme` source's preset; this module is
for what goes through the REST API: certificates of the account's plan seen in
its dashboard, 1-year certificates where the plan sells them, DCV by e-mail.

What the API is, and from where: ZeroSSL's documentation
(https://zerossl.com/documentation/api/ - not readable from where this was
written, 2026-11) and ZeroSSL's own Go client of it, github.com/caddyserver/zerossl
(Caddy is ZeroSSL's project; endpoints.go, client.go, models.go, zerossl.go):

* https://api.zerossl.com, JSON both ways. The API key: since August 2026 in the
  header "Authorization: ApiKey KEY" (client.go); before, the query parameter
  access_key (a setting, for an account that still wants it).
* The HTTP status says nothing: an error is {"success": false, "error": {code,
  type}} (client.go, models.go APIError).
* POST /certificates {certificate_domains (the names, joined by commas),
  certificate_csr (PEM), certificate_validity_days (90 or 365), strict_domains 1}
  -> the certificate object {id, status, validation {email_validation {domain:
  [addresses]}, other_methods {domain: {file_validation_url_http,
  file_validation_content [lines], cname_validation_p1, cname_validation_p2}}}}.
* POST /certificates/{id}/challenges {validation_method EMAIL | CNAME_CSR_HASH |
  HTTP_CSR_HASH | HTTPS_CSR_HASH, validation_email (EMAIL: addresses, commas)}.
* GET /certificates/{id} - status draft, pending_validation, issued, cancelled,
  revoked, expired (zerossl.go ListAllCertificates).
* GET /certificates/{id}/download/return -> {"certificate.crt", "ca_bundle.crt"}.
* GET /certificates?certificate_status=..&page=N&limit=M -> {total_count,
  result_count, page, limit, results [the objects: common_name,
  additional_domains (commas), created, expires ("Y-m-d H:i:s"), status]}.
* POST /certificates/{id}/revoke?reason=unspecified|keyCompromise|
  affiliationChanged|Superseded|cessationOfOperation.
* POST /certificates/{id}/cancel - a draft or pending one given up.

UNCERTAIN: what replacement_for_certificate does to the account (not sent);
whether an account wants the key in the header or in access_key (a setting).
"""
from __future__ import annotations

import calendar
import json
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

API = 'https://api.zerossl.com'
METHODS = {'cname': 'CNAME_CSR_HASH', 'http': 'HTTP_CSR_HASH', 'email': 'EMAIL'}
ISSUED = ('issued',)
WAITING = ('draft', 'pending_validation')
FAILED = ('cancelled', 'canceled', 'revoked', 'expired')
LISTED = 'draft,pending_validation,issued,cancelled,revoked,expired'
STATUS_WORDS = {'draft': 'a draft (not validated yet)', 'pending_validation':
                'waiting for the domain validation', 'issued': 'issued',
                'cancelled': 'cancelled', 'revoked': 'revoked', 'expired': 'expired'}
REVOKE = {0: 'unspecified', 1: 'keyCompromise', 3: 'affiliationChanged', 4: 'Superseded',
          5: 'cessationOfOperation'}
MAILBOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')


def _when(v):
    """'Y-m-d H:i:s' (UTC) as epoch, or None."""
    try:
        return calendar.timegm(time.strptime(str(v or '')[:19], '%Y-%m-%d %H:%M:%S'))
    except (TypeError, ValueError):
        try:
            return calendar.timegm(time.strptime(str(v or '')[:10], '%Y-%m-%d'))
        except (TypeError, ValueError):
            return None


class ZeroSslIssuer(Issuer):
    kind = 'zerossl'
    title = 'ZeroSSL (REST API)'
    description = ('Certificates from ZeroSSL through its REST API: asked for with acme\'s '
                   'request, the domain validation record or file put in place by the '
                   'certificate\'s validation (or an e-mail), the certificate downloaded. Lists '
                   'the account\'s certificates for importing.')
    vendor = 'ZeroSSL'
    doc = 'docs/sources.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # GET /certificates + download: Import from a source
    key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
    dcv_field = 'dcv'
    dcv_default = 'cname'
    dcv = {
        'cname': {'proof': 'cname-any', 'words': 'DNS CNAME record (CNAME_CSR_HASH)',
                  'record': 'CNAME at the name ZeroSSL says (_HASH.NAME) to its target'},
        'http': {'proof': 'http-file-any', 'words': 'HTTP file (HTTP_CSR_HASH)',
                 'record': 'http://NAME/.well-known/pki-validation/HASH.txt holding ZeroSSL\'s '
                           'lines'},
        'email': {'proof': None, 'words': 'E-mail (a person approves)',
                  'record': 'an e-mail to an approver address of the domain (admin@, '
                            'hostmaster@…)'},
    }
    fields = [
        field('api_key', 'API key', 'secret', required=True,
              help='ZeroSSL dashboard → Developer: the account\'s API access key. Never '
                   'written into a job\'s steps.'),
        field('key_in', 'How the API key is sent', 'select', default='header',
              options=[['header', 'In the header Authorization: ApiKey (since August 2026)'],
                       ['query', 'As the parameter access_key (older accounts)']],
              help='ZeroSSL moved the key into the Authorization header in August 2026; the '
                   'parameter in the address is for an account that still wants it.'),
        field('validity', 'Validity', 'select', default='90',
              options=[['90', '90 days'], ['365', '1 year (only where the plan sells it)']],
              help='certificate_validity_days of a new certificate.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='cname',
              options=[['cname', 'DNS CNAME record (by the certificate\'s DNS validation)'],
                       ['http', 'HTTP file in /.well-known/pki-validation/ (by the '
                                'certificate\'s HTTP validation; no wildcards)'],
                       ['email', 'E-mail to an approver address of the domain']],
              help='How ZeroSSL checks the domains. The certificate\'s validation must be able '
                   'to put that record or file in place - the wizard offers only those that '
                   'can; e-mail needs a person to click.'),
        field('approver', 'Approver mailbox', 'select', default='admin',
              options=[['admin', 'admin@'], ['administrator', 'administrator@'],
                       ['hostmaster', 'hostmaster@'], ['postmaster', 'postmaster@'],
                       ['webmaster', 'webmaster@'],
                       ['first', 'the first address ZeroSSL offers']],
              show_if={'dcv': ['email']},
              help='For each domain the address is picked from those ZeroSSL offers: this '
                   'mailbox, else the first offered.'),
        field('api_url', 'API address', 'text', default=API, advanced=True),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600,
              advanced=True,
              help='Longer: the certificate is asked for again at the next try - nothing is '
                   'asked for twice.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=15, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep

    # -- the API ---------------------------------------------------------------------------
    def _key(self):
        k = str(self.c('api_key') or '').strip()
        if not k:
            raise PluginError('set the ZeroSSL API key', retry=False)
        return k

    def _base(self):
        url = str(self.c('api_url') or API).strip().rstrip('/')
        if not re.match(r'^https://[^\s/]+(/\S*)?\Z', url):
            raise PluginError('the ZeroSSL API address is not an https address', retry=False)
        return url

    def _hide(self, words):
        k = str(self.c('api_key') or '').strip()
        return str(words).replace(k, '********') if k else str(words)

    def call(self, method, path, body=None, query=None, what=''):
        """The answer of ZeroSSL (a dict), or a PluginError in words."""
        key = self._key()
        q = dict(query or {})
        headers = {}
        if (self.c('key_in') or 'header') == 'query':
            q['access_key'] = key
        else:
            headers['Authorization'] = 'ApiKey ' + key
        url = self._base() + path + ('?' + urllib.parse.urlencode(q) if q else '')
        try:
            status, _h, data = sc.http(self.ctx, method, url, body, headers, who='ZeroSSL')
        except PluginError as e:
            raise PluginError(self._hide(e), retry=e.retry)
        got = sc.parse_json(data)
        if isinstance(got, dict) and str(got.get('success')).lower() in ('false', '0', 'no'):
            err = got.get('error') if isinstance(got.get('error'), dict) else {}
            kind, code = err.get('type') or '?', err.get('code') or '?'
            detail = self._hide(json.dumps(got)[:3000])
            if str(code) in ('101', '102') or 'access_key' in str(kind):
                raise PluginError('ZeroSSL refused %s: %s (error %s) - the API key is wrong or '
                                  'not active' % (what or path, kind, code), detail=detail,
                                  retry=False)
            raise PluginError('ZeroSSL refused %s: %s (error %s)' % (what or path, kind, code),
                              detail=detail, retry=False)
        if status >= 400 or got is None:
            raise sc.refusal('ZeroSSL (%s)' % (what or path), status, got,
                             self._hide((data or b'').decode('utf-8', 'replace')).encode(),
                             'the API key is wrong or not active')
        return got

    @staticmethod
    def _id(v):
        v = str(v or '').strip()
        if not re.match(r'^[0-9A-Za-z]{8,64}\Z', v):
            raise PluginError('"%s" is not a ZeroSSL certificate id' % v, retry=False)
        return v

    def detail(self, cid):
        return self.call('GET', '/certificates/%s' % self._id(cid),
                         what='the certificate %s' % cid)

    def download(self, cid):
        got = self.call('GET', '/certificates/%s/download/return' % self._id(cid),
                        what='the download of %s' % cid)
        return sc.certs_of(got.get('certificate.crt') or ''), \
            sc.certs_of(got.get('ca_bundle.crt') or '')

    # -- the order ----------------------------------------------------------------------------
    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        how = self.c('dcv') or 'cname'
        if how == 'http' and any(n.startswith('*.') for n in req.names):
            raise PluginError('ZeroSSL proves a wildcard name by DNS or e-mail, not by an HTTP '
                              'file - choose the DNS CNAME record', retry=False)
        slot = sc.pending_slot('zerossl', self._base(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        if held:
            cid = held['id']
            sc.say(self.ctx, 'the certificate %s waits at ZeroSSL since %s - asked for again, '
                             'nothing new is asked for' % (cid, time.strftime(
                                 '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
            if held.get('dcv'):
                placer.refresh(req, held['dcv'])
        else:
            body = {'certificate_domains': ','.join(req.names),
                    'certificate_csr': sc.csr_pem(req).strip(),
                    'certificate_validity_days': int(self.c('validity') or 90),
                    'strict_domains': 1}
            got = self.call('POST', '/certificates', body, what='the new certificate')
            cid = str(got.get('id') or '')
            self._id(cid)
            sc.say(self.ctx, 'ZeroSSL took the request for %s: certificate %s' % (
                ', '.join(req.names), cid), 'ok')
            held = sc.pending_put(self.ctx, slot, req, {'id': cid, 'dcv': [], 'asked': False,
                                                        'csr_pem': sc.csr_pem(req)},
                                  ttl_days=60)
            r = req
            self._dcv(req, slot, held, got, placer)
        return self._await(r, req, slot, held, placer)

    def dcv_records(self, obj):
        """The records ZeroSSL looks for, one per domain (CNAME or file)."""
        how = self.c('dcv') or 'cname'
        other = ((obj or {}).get('validation') or {}).get('other_methods') or {}
        recs = []
        for name, v in (other.items() if isinstance(other, dict) else []):
            if not isinstance(v, dict):
                continue
            d = _dcv.base_of(name)
            if how == 'http':
                url = str(v.get('file_validation_url_http') or '')
                path = urllib.parse.urlsplit(url).path
                lines = v.get('file_validation_content') or []
                if isinstance(lines, str):
                    lines = [lines]
                if path.startswith('/.well-known/') and lines:
                    recs.append({'domain': d, 'type': 'file', 'path': path,
                                 'value': '\n'.join(str(x) for x in lines)})
            else:
                p1 = str(v.get('cname_validation_p1') or '').strip().rstrip('.').lower()
                p2 = str(v.get('cname_validation_p2') or '').strip().rstrip('.').lower()
                if p1 and p2:
                    recs.append({'domain': d, 'type': 'cname', 'fqdn': p1, 'value': p2})
        return recs

    def approvers(self, obj):
        mails = ((obj or {}).get('validation') or {}).get('email_validation') or {}
        want = self.c('approver') or 'admin'
        out = []
        for name, offered in (mails.items() if isinstance(mails, dict) else []):
            offered = [str(x).strip() for x in (offered or []) if '@' in str(x)]
            if not offered:
                continue
            pick = None
            if want in MAILBOXES:
                d = _dcv.base_of(name)
                pick = next((a for a in offered if a.lower() == '%s@%s' % (want, d)), None) or \
                    next((a for a in offered if a.lower().startswith(want + '@')), None)
            pick = pick or offered[0]
            if pick not in out:
                out.append(pick)
        return out

    def _dcv(self, req, slot, held, obj, placer):
        how = self.c('dcv') or 'cname'
        if how == 'email':
            mails = self.approvers(obj)
            if not mails:
                raise PluginError('ZeroSSL offered no approver address for the domains',
                                  retry=False)
            self.call('POST', '/certificates/%s/challenges' % held['id'],
                      {'validation_method': 'EMAIL', 'validation_email': ','.join(mails)},
                      what='the e-mail validation')
            sc.say(self.ctx, 'ZeroSSL mails %s - someone there approves the certificate'
                             % ', '.join(mails))
        else:
            recs = self.dcv_records(obj)
            if not recs:
                raise PluginError('ZeroSSL said no file for the domains' if how == 'http' else
                                  'ZeroSSL said no CNAME record for the domains', retry=False)
            held['dcv'] = placer.place_all(req, recs)
            sc.pending_put(self.ctx, slot, req, held, ttl_days=60)
            if any(p.get('how') == 'placed' for p in held['dcv']):
                placer.wait_visible(req, held['dcv'])
            self.call('POST', '/certificates/%s/challenges' % held['id'],
                      {'validation_method': METHODS[how]}, what='the domain validation')
            sc.say(self.ctx, 'ZeroSSL was asked to check the domains (%s)' % METHODS[how])
        held['asked'] = True
        sc.pending_put(self.ctx, slot, req, held, ttl_days=60)

    def _await(self, r, req, slot, held, placer):
        cid = held['id']
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 15))
        while True:
            obj = self.detail(cid)
            st = str(obj.get('status') or '').lower()
            if st in ISSUED:
                leaf, bundle = self.download(cid)
                out = sc.finish(self.ctx, r, leaf, bundle, who='ZeroSSL',
                                key_pem=r.key_pem if r is not req else None,
                                info={'zerossl_id': cid, 'ref': cid})
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                self.ctx.kv_set('zerossl-cert:%s' % sc.fingerprint(out.cert_pem)[:40], cid,
                                ttl_s=2 * 366 * 86400)
                if getattr(req, 'cert_id', None):
                    self.ctx.kv_set('zerossl-made:%s' % req.cert_id, cid, ttl_s=2 * 366 * 86400)
                return out
            if st in FAILED:
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('ZeroSSL did not issue: the certificate %s is %s' % (
                    cid, STATUS_WORDS.get(st, st)), retry=False)
            if st == 'draft' and not held.get('asked'):
                self._dcv(req, slot, held, obj, placer)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('ZeroSSL has not issued yet (certificate %s: %s) - the DCV '
                                  'records stay in place; acme asks again at the next try'
                                  % (cid, STATUS_WORDS.get(st, st or '?')))
            self._sleep(every)

    # -- revocation, trying it ------------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        cid = self.ctx.kv_get('zerossl-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if not cid:
            raise PluginError('acme does not know the certificate\'s id at ZeroSSL - revoke it '
                              'in the ZeroSSL dashboard', retry=False)
        why = REVOKE.get(sc.reason_code(reason), 'unspecified')
        self.call('POST', '/certificates/%s/revoke' % self._id(cid), query={'reason': why},
                  what='the revocation')
        return 'ZeroSSL revoked certificate %s (%s)' % (cid, why)

    def test(self):
        got = self.call('GET', '/certificates', query={'certificate_status': LISTED,
                                                       'limit': 1, 'page': 1},
                        what='the list of certificates')
        return 'ZeroSSL answers: the API key is let in; the account has %s certificate(s)' % (
            got.get('total_count') if got.get('total_count') is not None else '?')

    # -- the certificates of the account (Certificates → Import from a source) -----------------
    def _acme_ids(self):
        """{ZeroSSL id: acme's certificate id} of the certificates acme asked for here."""
        out = {}
        try:
            kept = self.ctx.kv_keys('zerossl-made:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            cid = k.split(':', 1)[1] if ':' in k else ''
            if v and cid.isdigit():
                out[str(v)] = int(cid)
        return out

    def list_existing(self):
        """Every certificate of the account (GET /certificates, page by page) - read only."""
        mine = self._acme_ids()
        out, page, per = [], 1, 100
        while page <= 100:
            got = self.call('GET', '/certificates', query={'certificate_status': LISTED,
                                                           'page': page, 'limit': per},
                            what='the list of certificates')
            items = [x for x in (got.get('results') or []) if isinstance(x, dict)]
            for c in items:
                cid = str(c.get('id') or '').strip()
                if not cid:
                    continue
                cn = str(c.get('common_name') or '').strip()
                more = str(c.get('additional_domains') or '').split(',')
                names = [cn] + [x.strip() for x in more]
                names = [n for i, n in enumerate(names) if n and n not in names[:i]]
                st = str(c.get('status') or '').lower()
                out.append({'ref': cid, 'cn': cn or (names[0] if names else ''), 'names': names,
                            'product': '%s-day certificate' % c['validity_days']
                            if c.get('validity_days') else 'ZeroSSL',
                            'status': STATUS_WORDS.get(st, st or '?'),
                            'not_before': _when(c.get('created')),
                            'not_after': _when(c.get('expires')),
                            'downloadable': st in ISSUED,
                            'renewable': 'issue' if st in ISSUED + ('expired',) else 'none',
                            'note': '' if st in ISSUED else 'ZeroSSL says it is %s' % (
                                STATUS_WORDS.get(st, st or '?')),
                            'acme_cert_id': mine.get(cid)})
            total = int(sc.num(got.get('total_count'), 0))
            if len(items) < per or (total and page * per >= total):
                break
            page += 1
        return out

    def fetch_existing(self, ref):
        """The certificate `ref` and its chain (download/return) - read only."""
        cid = self._id(ref)
        leaf, bundle = self.download(cid)
        out = sc.existing(leaf, bundle, who='ZeroSSL', ref=cid)
        self.ctx.kv_set('zerossl-cert:%s' % sc.fingerprint(out['cert_pem'])[:40], cid,
                        ttl_s=2 * 366 * 86400)
        out['acme_cert_id'] = self._acme_ids().get(cid)
        return out
