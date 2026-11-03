# -*- coding: utf-8 -*-
"""
DirectAdmin: the certificate of a domain replaced through the new API
(/api/domain-tls: a certificate slot of the domain, its id read from the
domain's list, the files replaced in place, ACME's skip list updated so
DirectAdmin's own ACME leaves it alone) - or, on an older DirectAdmin,
through the legacy CMD_API_SSL (type=paste, then the CA certificate).
DirectAdmin restarts or reloads the web server itself.

    HTTP basic authentication: the user (or "admin|user" to act as a user) and a login key
    GET  /api/domain-tls/domains/<domain>/certs            -> certIds, certs[].certificate
    GET  /api/domain-tls/domains/<domain>/certs/<id>/files -> cert (the one there)
    PUT  /api/domain-tls/domains/<domain>/certs/<id>/files?update-acme-skiplist=true
         {"cert", "chain": [..], "key"}    (first with dry-run=true: checked, not saved)
    (/api/admin-domain-tls/... the same as an administrator)
    legacy:
    GET  /CMD_API_SSL?domain=<domain>                      -> certificate=... (urlencoded)
    POST /CMD_API_SSL  domain, action=save, type=paste, certificate=<cert>\\n<key>\\n
    POST /CMD_API_SSL  domain, action=save, type=cacert, active=yes, cacert=<chain>

Checked against (the user's collection of the vendor's documents, api-docs/directadmin_ssl/
and api-docs/directadmin/notes.md for the sign-in):
    notes.md - quotes from
      https://docs.directadmin.com/developer/api/ (basic authentication, login keys,
      impersonation with "|", "the new API ... should always be prioritized")
      https://docs.directadmin.com/changelog/version-1.24.4.html (CMD_API_SSL save/paste,
      CMD_SSL cacert)
      https://docs.directadmin.com/changelog/version-1.37.0.html
      https://docs.directadmin.com/changelog/version-1.666.html
      https://docs.directadmin.com/changelog/version-1.53.1.html (the web server restarted)
      https://docs.directadmin.com/changelog/version-1.706.html (manual certificates and ACME)
    directadmin-swagger.json - https://demo.directadmin.com:2222/static/swagger.json
      (TLS: web.domainTLSListCertsResponse, web.domainTLSCertFilesRequest, the dry-run,
      force and update-acme-skiplist parameters, the errors 400 / 404 / 409)

Less certain:
    - how a new certificate id comes about is not documented: acme replaces an id the
      domain lists (the one set, or the only one, or the one whose names cover the
      certificate's) and does not make new ones - so there are no older copies to keep;
    - "chain" one intermediate a string (the type is an array of strings);
    - legacy: CMD_API_SSL with type=cacert is documented for CMD_SSL only (the CMD_API_
      commands take the same values, the documents say); the shape of its answers.
"""
from __future__ import annotations

import base64
import hashlib
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, text, http_fields, tls_fields, verify_fields,
    covers, pem_blocks, pem_to_der, chain_list, form)


def fp_pem(pem):
    try:
        return hashlib.sha256(pem_to_der(pem)).hexdigest()
    except PluginError:
        return ''


def q(s):
    return urllib.parse.quote(text(s), safe='')


def legacy_answer(raw):
    """error=0&text=...&details=... (or the key=value lines of a view) -> dict."""
    s = text(raw).strip()
    return {k: v[0] if v else '' for k, v in urllib.parse.parse_qs(s, keep_blank_values=True)
            .items()}


class DirectAdminSslTarget(HttpTarget):
    kind = 'directadmin_ssl'
    title = 'DirectAdmin (domain certificate)'
    vendor = 'DirectAdmin'
    description = ('Replaces the TLS certificate of a DirectAdmin domain through the new API '
                   '(or the legacy CMD_API_SSL); DirectAdmin reloads the web server itself.')
    doc = 'targets.md'
    fields = http_fields(2222, 'server.example.com') + [
        field('user', 'User', 'text', required=True,
              help='the user the domain belongs to, or an admin / reseller acting for them '
                   '(below)'),
        field('password', 'Login key', 'secret', required=True,
              help='a login key made for acme (or the password)'),
        field('as_user', 'Act as the user', 'text', advanced=True,
              help='an admin or reseller signs in as "admin|user": the user here'),
        field('api', 'API', 'select', default='new',
              options=[['new', 'the new API (/api/domain-tls)'],
                       ['admin', 'the new API as an administrator (/api/admin-domain-tls)'],
                       ['legacy', 'the legacy CMD_API_SSL (older DirectAdmin)']]),
    ] + tls_fields()
    deploy_fields = [
        field('da_domain', 'Domain', 'text', required=True, placeholder='example.com',
              help='the DirectAdmin domain whose certificate this is'),
        field('cert_id', 'Certificate slot', 'catalog', catalog='cert_ids', autoload=False,
              help='the id of the domain\'s certificate to replace (new API); empty: the only '
                   'one, or the one whose names cover this certificate'),
        field('skiplist', 'Keep DirectAdmin\'s ACME off it', 'bool', default=True,
              help='update-acme-skiplist: DirectAdmin\'s own ACME does not replace it'),
    ] + verify_fields()

    def auth_headers(self):
        u = text(self.c('user'))
        if text(self.c('as_user')).strip():
            u = '%s|%s' % (u, text(self.c('as_user')).strip())
        raw = '%s:%s' % (u, self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def root(self):
        return '/api/admin-domain-tls' if self.c('api', 'new') == 'admin' else '/api/domain-tls'

    # -- the new API ------------------------------------------------------------------------
    def listed(self, domain):
        st, hd, d = self.req('GET', '%s/domains/%s/certs' % (self.root(), q(domain)),
                             ok=(200, 404), what='reading the certificates of %s' % domain)
        if st == 404:
            raise PluginError('DirectAdmin has no domain "%s" here' % domain, retry=False)
        return d if isinstance(d, dict) else {}

    def pick(self, domain, bundle, options):
        want = text(options.get('cert_id')).strip()
        if want:
            return want
        d = self.listed(domain)
        ids = [text(i) for i in d.get('certIds') or []]
        if len(ids) == 1:
            return ids[0]
        first = next((n for n in bundle.names if not n.startswith('*')), bundle.names[0])
        fit = []
        for c in d.get('certs') or []:
            if not isinstance(c, dict):
                continue
            names = (c.get('certificate') or {}).get('dnsNames') or []
            if covers(names, first) or first in names:
                fit.append(text(c.get('id')))
        if len(fit) == 1:
            return fit[0]
        if not ids:
            raise PluginError('the domain %s has no certificate slot yet: make one in '
                              'DirectAdmin (SSL Certificates) first, or use the legacy API'
                              % domain, retry=False)
        raise PluginError('the domain %s has several certificates (%s): choose the slot'
                          % (domain, ', '.join(ids)), retry=False)

    def files_path(self, domain, cid):
        return '%s/domains/%s/certs/%s/files' % (self.root(), q(domain), q(cid))

    def catalog(self, key):
        if key != 'cert_ids':
            raise PluginError('there is no list called %s here' % key, retry=False)
        domain = text(self.c('da_domain')).strip()
        if not domain:
            raise PluginError('set the domain first', retry=False)
        opts = []
        for c in self.listed(domain).get('certs') or []:
            if isinstance(c, dict) and c.get('id'):
                crt = c.get('certificate') or {}
                opts.append([text(c['id']), '%s: %s%s' % (
                    c['id'], ', '.join(crt.get('dnsNames') or []) or '-',
                    ', until %s' % crt['notAfter'] if crt.get('notAfter') else '')])
        return {'options': opts, 'sets': {}, 'said': '%d certificates' % len(opts)}

    def test(self):
        if self.c('api', 'new') == 'legacy':
            st, hd, d = self.req('GET', '/CMD_API_SSL', ok=range(200, 500),
                                 what='signing in')
            if st in (401, 403):
                raise PluginError('DirectAdmin does not let acme in (%d)' % st, retry=False)
            return 'reached DirectAdmin %s (legacy API)' % self.c('host')
        self.req('GET', '/api/session', what='signing in')
        return 'signed in to DirectAdmin %s as %s' % (self.c('host'), self.c('as_user') or
                                                      self.c('user'))

    def deploy(self, bundle, options):
        options = options or {}
        domain = text(options.get('da_domain')).strip()
        if not domain:
            raise PluginError('no domain is set', retry=False)
        if self.c('api', 'new') == 'legacy':
            return self.deploy_legacy(bundle, options, domain)
        cid = self.pick(domain, bundle, options)
        path = self.files_path(domain, cid)

        def present():
            st, hd, d = self.req('GET', path, ok=(200, 404), what='reading %s/%s' % (domain, cid))
            return st == 200 and isinstance(d, dict) and \
                fp_pem(d.get('cert') or d.get('certificate') or '') == fp_pem(bundle.cert_pem)
        if self.unchanged(bundle, options, present=present):
            return self.same(bundle, 'on %s (%s)' % (domain, cid))
        body = {'cert': text(bundle.as_format('cert-pem')).strip() + '\n',
                'chain': [p for p in chain_list(bundle)],
                'key': text(bundle.as_format('key-pem')).strip() + '\n'}
        qs = 'update-acme-skiplist=%s' % ('true' if as_bool(self.opt(options, 'skiplist', True),
                                                            True) else 'false')
        self.req('PUT', path + '?dry-run=true&' + qs, body,
                 what='checking the certificate for %s (dry run)' % domain)
        self.ctx.step('DirectAdmin checked the certificate (dry run)')
        st, hd, d = self.req('PUT', path + '?' + qs, body,
                             what='replacing the certificate of %s' % domain)
        err = text((d or {}).get('error')) if isinstance(d, dict) else ''
        if err:
            self.ctx.step('DirectAdmin says of the certificate: %s' % err, 'warn')
        self.ctx.step('replaced the certificate %s of %s' % (cid, domain), 'ok')
        self.remember(bundle, options, id=cid)
        return 'replaced the certificate %s of %s' % (cid, domain)

    # -- the legacy API ---------------------------------------------------------------------
    def legacy(self, params, what):
        st, hd, raw = self.req('POST', '/CMD_API_SSL', form(params),
                               {'Content-Type': 'application/x-www-form-urlencoded'}, what=what)
        a = legacy_answer(raw if isinstance(raw, (bytes, str)) else '')
        if text(a.get('error')) not in ('', '0'):
            raise PluginError('%s: DirectAdmin said %s' % (what, a.get('text') or 'error'),
                              detail=text(a.get('details'))[:4000], retry=False)
        return a

    def deploy_legacy(self, bundle, options, domain):
        def present():
            st, hd, raw = self.req('GET', '/CMD_API_SSL?domain=%s' % q(domain),
                                   what='reading the certificate of %s' % domain)
            a = legacy_answer(raw if isinstance(raw, (bytes, str)) else '')
            got = pem_blocks(a.get('certificate') or '')
            return bool(got) and fp_pem(got[0]) == fp_pem(bundle.cert_pem)
        if self.unchanged(bundle, options, present=present):
            return self.same(bundle, 'on %s' % domain)
        cert = text(bundle.as_format('cert-pem')).strip()
        key = text(bundle.as_format('key-pem')).strip()
        self.legacy({'domain': domain, 'action': 'save', 'type': 'paste',
                     'certificate': cert + '\n' + key + '\n'},
                    what='pasting the certificate of %s' % domain)
        self.ctx.step('pasted the certificate and key of %s' % domain, 'ok')
        chain = ''.join(chain_list(bundle))
        if chain:
            self.legacy({'domain': domain, 'action': 'save', 'type': 'cacert', 'active': 'yes',
                         'cacert': chain}, what='setting the CA certificate of %s' % domain)
            self.ctx.step('set the CA certificate (the chain) of %s' % domain, 'ok')
        self.remember(bundle, options)
        return 'pasted the certificate of %s (legacy API)' % domain
