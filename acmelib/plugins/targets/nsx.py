# -*- coding: utf-8 -*-
"""
VMware NSX (Policy API): the certificate imported under a new id - an NSX
certificate cannot be overwritten - the client SSL binding of the load
balancer's virtual servers switched to it, the older acme certificates no
virtual server uses deleted.

    https://<nsx-manager>/policy/api/v1, HTTP basic authentication
    GET    /infra/certificates/<id>               there already? (404: no)
    PUT    /infra/certificates/<id>   {"display_name", "pem_encoded" (leaf + chain),
                                       "private_key", "tags": [{"scope", "tag"}]}
    GET    /infra/lb-virtual-servers[?cursor=]   the virtual servers (the list)
    GET    /infra/lb-virtual-servers/<vs>         the whole object, with its _revision
    PUT    /infra/lb-virtual-servers/<vs>         the same object, client_ssl_profile_binding
                                       .default_certificate_path (and/or
                                       .sni_certificate_paths) = /infra/certificates/<id>
    GET    /infra/certificates[?cursor=]          the older ones
    DELETE /infra/certificates/<id>

Checked against (the user's collection of the vendor's documents, api-docs/nsx/):
    notes.md - quotes from
      https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/ (basic
      authentication, _revision with PUT on /policy, PATCH and partial patch)
      https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/all_errors.html
      https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/networking_load_balancing_lb_virtual_servers.html
      https://github.com/vmware/terraform-provider-nsxt (client_ssl: default_certificate_path,
      sni_paths, ssl_profile_path)
    nsx_policy_api.json - the NSX Policy API 9.1.1.0 specification (AddTlsCertificate:
      "This PUT method does not modify an existing certificate."; TlsTrustData;
      ListTlsCertificates; DeleteTlsCertificate; UpdateLBVirtualServer / ReadLBVirtualServer;
      LBClientSslProfileBinding)

Less certain:
    - that the virtual server read with GET is taken back whole by PUT (read-only
      properties such as _create_user in it) - the documents say PUT is "a full replace"
      and needs the _revision, which is sent as read;
    - what DELETE answers for a certificate still referenced (409 is likely); acme deletes
      only those no virtual server refers to;
    - the chain sent in pem_encoded after the leaf (the list in the specification shows
      several blocks in one pem_encoded, no example of an import with a chain).
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, text, object_name, name_prefix, ours, prune,
    http_fields, tls_fields, verify_fields, keep_field, fp_of, SEG_PATTERN)

API = '/policy/api/v1'


def q(s):
    return urllib.parse.quote(text(s), safe='')


class NsxTarget(HttpTarget):
    kind = 'nsx'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'VMware NSX load balancer (Policy API)'
    vendor = 'VMware'
    description = ('Imports the certificate into NSX under a new id, switches the client SSL '
                   'binding of the load balancer\'s virtual servers to it and deletes the '
                   'older one.')
    doc = 'targets.md'
    fields = http_fields(443, 'nsx-manager.example.local') + [
        field('user', 'User', 'text', required=True, default='admin'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('virtual_server', 'Virtual server', 'catalog', pattern=SEG_PATTERN, catalog='virtual_servers',
              autoload=False,
              help='the id of the LB virtual server to use the certificate; picked from the '
                   'list or typed'),
        field('virtual_servers', 'More virtual servers', 'list', pattern=SEG_PATTERN, placeholder='vs-www-443',
              help='one a line: the ids of more virtual servers'),
        field('place', 'As', 'select', default='default',
              options=[['default', 'the default certificate of the virtual server'],
                       ['sni', 'an SNI certificate (the older acme one replaced)'],
                       ['both', 'both']]),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the virtual servers',
                'help': 'Lists the load balancer\'s virtual servers and the certificates of '
                        'their client SSL binding - it changes nothing.',
                'changes': False}]

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def api(self, method, path, body=None, ok=None, what=None):
        st, hd, d = self.req(method, API + path, body, ok=ok, what=what)
        return st, (d if isinstance(d, dict) else {})

    def paged(self, path, what):
        out, cursor = [], None
        for _i in range(200):
            sep = '&' if '?' in path else '?'
            st, d = self.api('GET', path + ('%scursor=%s' % (sep, q(cursor)) if cursor else ''),
                             what=what)
            out += [x for x in d.get('results') or [] if isinstance(x, dict)]
            cursor = d.get('cursor')
            if not cursor:
                break
        return out

    def vservers(self):
        return self.paged('/infra/lb-virtual-servers', 'listing the virtual servers')

    def certs(self):
        return self.paged('/infra/certificates', 'listing the certificates')

    def test(self):
        vs = self.vservers()
        st, d = self.api('GET', '/infra/certificates?page_size=1', what='listing the certificates')
        return 'signed in to NSX %s; %d virtual server%s, %s certificate%s' % (
            self.c('host'), len(vs), '' if len(vs) == 1 else 's', d.get('result_count', '?'),
            '' if d.get('result_count') == 1 else 's')

    def catalog(self, key):
        if key != 'virtual_servers':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = []
        for v in self.vservers():
            b = v.get('client_ssl_profile_binding') or {}
            opts.append([text(v.get('id')), '%s (%s:%s)%s' % (
                v.get('display_name') or v.get('id'), v.get('ip_address') or '?',
                ','.join(map(text, v.get('ports') or [])), '' if b else ' - no client SSL')])
        return {'options': opts, 'sets': {}, 'said': '%d virtual servers' % len(opts)}

    def action(self, key):
        if key != 'look':
            return HttpTarget.action(self, key)
        vs = self.vservers()
        for v in vs:
            b = v.get('client_ssl_profile_binding') or {}
            self.ctx.step('%s (%s:%s): %s%s' % (
                v.get('id'), v.get('ip_address') or '?', ','.join(map(text, v.get('ports') or [])),
                b.get('default_certificate_path') or 'no client SSL',
                '; SNI ' + ', '.join(b.get('sni_certificate_paths')) if
                b.get('sni_certificate_paths') else ''))
        return '%d virtual server%s' % (len(vs), '' if len(vs) == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        cid = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        path = '/infra/certificates/%s' % cid
        st, d = self.api('GET', '/infra/certificates/%s' % q(cid), ok=(200, 404),
                         what='looking for %s' % cid)
        if self.unchanged(bundle, options, present=lambda: st == 200):
            return self.same(bundle, 'as %s' % cid)
        did = []
        if st == 404:
            self.api('PUT', '/infra/certificates/%s' % q(cid), {
                'display_name': cid,
                'pem_encoded': text(bundle.as_format('fullchain-pem')),
                'private_key': text(bundle.as_format('key-pem')),
                'tags': [{'scope': 'acme', 'tag': fp_of(bundle)[:16]}]},
                what='importing %s' % cid)
            self.ctx.step('imported the certificate %s' % cid, 'ok')
            did.append('imported %s' % cid)
        else:
            self.ctx.step('the certificate %s is in NSX already' % cid)
        place = text(options.get('place') or 'default')
        refs = []
        one = text(options.get('virtual_server')).strip()
        if one:
            refs.append(one)
        refs += [r for r in lines(options.get('virtual_servers')) if r not in refs]
        for ref in refs:
            st, vs = self.api('GET', '/infra/lb-virtual-servers/%s' % q(ref), ok=(200, 404),
                              what='reading the virtual server %s' % ref)
            if st == 404:
                raise PluginError('NSX has no virtual server "%s"' % ref, retry=False)
            b = vs.get('client_ssl_profile_binding')
            if not isinstance(b, dict) or not b:
                raise PluginError('the virtual server %s has no client SSL binding (it does not '
                                  'serve HTTPS): give it a client SSL profile in NSX first'
                                  % ref, retry=False)
            before = (b.get('default_certificate_path'), list(b.get('sni_certificate_paths')
                                                              or []))
            if place in ('default', 'both'):
                b['default_certificate_path'] = path
            if place in ('sni', 'both'):
                sni = [p for p in b.get('sni_certificate_paths') or []
                       if not ours(p.rsplit('/', 1)[-1], prefix) and p != path]
                b['sni_certificate_paths'] = sni + [path]
            if (b.get('default_certificate_path'), list(b.get('sni_certificate_paths') or [])) \
                    == before:
                self.ctx.step('the virtual server %s uses %s already' % (ref, cid))
                continue
            vs['client_ssl_profile_binding'] = b
            self.api('PUT', '/infra/lb-virtual-servers/%s' % q(ref), vs,
                     what='switching the virtual server %s to %s' % (ref, cid))
            self.ctx.step('the virtual server %s uses %s' % (ref, cid), 'ok')
            did.append(ref)
        self.cleanup(prefix, cid, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % cid

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            mine = [text(c.get('id')) for c in self.certs() if ours(text(c.get('id')), prefix)]
            gone = prune(mine, prefix, keep, current)
            used = set()
            if gone:
                for v in self.vservers():
                    b = v.get('client_ssl_profile_binding') or {}
                    for p in [b.get('default_certificate_path')] + list(
                            b.get('sni_certificate_paths') or []):
                        if p:
                            used.add(text(p).rsplit('/', 1)[-1])
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        for old in gone:
            if old in used:
                self.ctx.step('the older %s stays: a virtual server still uses it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '/infra/certificates/%s' % q(old), what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
