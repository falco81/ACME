# -*- coding: utf-8 -*-
"""
Fastly TLS (customer-provided certificates): the new key uploaded under a
dated name, then the certificate acme put there before replaced in place, so
its activations - which domains it serves, on which TLS configuration - stay;
the first time a new certificate is added and is activated once in Fastly.
Older acme keys no certificate uses any more are deleted.

    https://api.fastly.com, header Fastly-Key: <API token>, JSON:API
    (Content-Type and Accept application/vnd.api+json)
    POST   /tls/private_keys   {"data": {"type": "tls_private_key",
                                         "attributes": {"key", "name"}}}
    GET    /tls/certificates?page[size]=100&page[number]=N     acme's one, by its name
    PATCH  /tls/certificates/<id>  {"data": {"type": "tls_certificate", "id",
                                             "attributes": {"cert_blob", "name"}}}
    POST   /tls/certificates   {"data": {"type": "tls_certificate",
                                         "attributes": {"cert_blob", "name"}}}
    GET    /tls/private_keys?filter[in_use]=false              keys no certificate uses
    DELETE /tls/private_keys/<id>

Sources (Fastly's official Go client, which the Fastly CLI and Terraform provider use):
    https://github.com/fastly/go-fastly/blob/main/fastly/tls_custom_certificate.go
    https://github.com/fastly/go-fastly/blob/main/fastly/tls_private_keys.go
    https://github.com/fastly/go-fastly/blob/main/fastly/client.go   (Fastly-Key, the endpoint)
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, as_int, object_name, name_prefix, prune, text, verify_fields,
    keep_field, ours)
from acmelib.plugins.targets._cloud import CloudTarget, cloud_fields

API = 'https://api.fastly.com'
JSONAPI = 'application/vnd.api+json'


class FastlyTarget(CloudTarget):
    kind = 'fastly'
    discovery = False       # nothing to find: its only field is the sign-in
    title = 'Fastly TLS (your own certificate)'
    vendor = 'Fastly'
    description = ('Uploads the key and replaces the certificate acme put on Fastly before, '
                   'keeping its activations; deletes the older keys.')
    doc = 'targets.md'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='Fastly → Account → API tokens: a token with the scope global (TLS '
                   'management needs it) of a user who may manage TLS'),
    ] + cloud_fields()
    deploy_fields = [
        field('certificate_id', 'Fastly certificate ID', 'text', advanced=True,
              help='the certificate to replace; empty: the one acme put there before for this '
                   'certificate (found by its name), else a new one is added'),
        keep_field(1),
    ] + verify_fields()

    def auth_headers(self):
        return {'Fastly-Key': self.c('token') or '', 'Accept': JSONAPI}

    def api(self, method, path, body=None, ok=None, what=None):
        st, hd, d = self.req(method, API + path, body,
                             {'Content-Type': JSONAPI} if body is not None else None,
                             ok=ok, what=what)
        return st, (d if isinstance(d, dict) else {})

    def http_error(self, status, parsed, raw, method, path, what=None):
        if isinstance(parsed, dict) and isinstance(parsed.get('errors'), list):
            msg = '; '.join(text(e.get('detail') or e.get('title') or e)
                            if isinstance(e, dict) else text(e) for e in parsed['errors'])
            parsed = {'message': msg}
        return CloudTarget.http_error(self, status, parsed, raw, method, path, what)

    def test(self):
        st, d = self.api('GET', '/tls/certificates?page%5Bsize%5D=100', what='signing in')
        n = len(d.get('data') or [])
        return 'signed in to Fastly; %d TLS certificate%s' % (n, '' if n == 1 else 's')

    def paged(self, path):
        out, page = [], 1
        while page and page < 50:
            sep = '&' if '?' in path else '?'
            st, d = self.api('GET', '%s%spage%%5Bsize%%5D=100&page%%5Bnumber%%5D=%d'
                             % (path, sep, page), what='listing %s' % path.split('?')[0])
            got = [x for x in d.get('data') or [] if isinstance(x, dict)]
            out += got
            last = as_int(((d.get('meta') or {}).get('total_pages')), 0)
            page = page + 1 if (got and (page < last or (not last and len(got) == 100))) else 0
        return out

    @staticmethod
    def name_of(x):
        return text((x.get('attributes') or {}).get('name'))

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        certs = self.paged('/tls/certificates')
        given = text(options.get('certificate_id')).strip()
        if self.unchanged(bundle, options, present=lambda: any(
                self.name_of(c) == name for c in certs)):
            return self.same(bundle, 'as %s' % name)
        target = None
        if given:
            target = next((c for c in certs if text(c.get('id')) == given), None)
            if target is None:
                raise PluginError('there is no TLS certificate %s at Fastly' % given,
                                  retry=False)
        else:
            mine = sorted((c for c in certs if ours(self.name_of(c), prefix) or
                           self.name_of(c) == name), key=self.name_of, reverse=True)
            target = mine[0] if mine else None
        if self.key_there(name):
            self.ctx.step('the key %s is at Fastly already' % name)
        else:
            self.api('POST', '/tls/private_keys', {'data': {
                'type': 'tls_private_key',
                'attributes': {'key': text(bundle.as_format('key-pem')), 'name': name}}},
                what='uploading the key')
            self.ctx.step('uploaded the key %s' % name, 'ok')
        body = {'data': {'type': 'tls_certificate', 'attributes': {
            'cert_blob': text(bundle.as_format('fullchain-pem')), 'name': name}}}
        if target is not None:
            body['data']['id'] = target['id']
            self.api('PATCH', '/tls/certificates/%s' % urllib.parse.quote(text(target['id'])),
                     body, what='replacing the certificate %s' % target['id'])
            self.ctx.step('replaced the certificate %s (%s → %s); its activations stay'
                          % (target['id'], self.name_of(target) or '-', name), 'ok')
            words = 'replaced %s' % target['id']
        else:
            st, d = self.api('POST', '/tls/certificates', body, what='adding the certificate')
            cid = text((d.get('data') or {}).get('id'))
            self.ctx.step('added the certificate %s (%s) - activate it once in Fastly (Secure → '
                          'TLS management) for its domains; renewals then replace it in place'
                          % (cid or '?', name), 'warn')
            words = 'added %s (to be activated)' % (cid or name)
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return words

    def key_there(self, name):
        try:
            keys = self.paged('/tls/private_keys')
        except PluginError:
            return False
        return any(self.name_of(k) == name for k in keys)

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            keys = self.paged('/tls/private_keys?filter%5Bin_use%5D=false')
        except PluginError as e:
            self.ctx.step('the older keys cannot be listed: %s' % e, 'warn')
            return
        byname = {self.name_of(k): k for k in keys}
        for old in prune(list(byname), prefix, keep, current):
            try:
                self.api('DELETE', '/tls/private_keys/%s'
                         % urllib.parse.quote(text(byname[old]['id'])),
                         what='deleting the key %s' % old)
                self.ctx.step('deleted the older key %s' % old)
            except PluginError as e:
                self.ctx.step('the older key %s stays: %s' % (old, e), 'warn')
