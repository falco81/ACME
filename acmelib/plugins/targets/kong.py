# -*- coding: utf-8 -*-
"""
Kong Gateway through its Admin API: the certificate added as a certificate
object of its own (tagged), each SNI pointed at it, older acme ones deleted.

    GET    /                                      the version (Try it)
    GET    /certificates?tags=acme-fp-<16 hex>    this very certificate, there already?
    POST   /certificates   {"cert", "key", ["cert_alt", "key_alt"], "tags"}
    PUT    /snis/<name>    {"certificate": {"id": ...}}     (an upsert by its name)
    GET    /certificates?tags=acme-<label>        the older ones (paged by "next")
    DELETE /certificates/<id>                     an older one no SNI uses any more
    Kong Gateway Enterprise: /<workspace>/... and the header Kong-Admin-Token (RBAC)

A dual certificate (ECDSA and RSA of the same names): the twin goes in the
same certificate object as cert_alt / key_alt; Kong serves each client the
one it takes.

Sources (Kong's own open-source code):
    https://github.com/Kong/kong/blob/master/kong/db/schema/entities/certificates.lua
    https://github.com/Kong/kong/blob/master/kong/db/schema/entities/snis.lua
    https://github.com/Kong/kong/blob/master/kong/api/routes/certificates.lua
    https://github.com/Kong/kong/blob/master/kong/api/endpoints.lua   (?tags=a,b filtering)
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, label_of, fp_of, tls_fields,
    verify_fields, keep_field, prune, text, alt_of, stamp, short_serial, SEG_PATTERN)


class KongTarget(HttpTarget):
    kind = 'kong'
    discovery = False       # nothing to find: Kong lists no workspaces through the calls acme makes
    title = 'Kong Gateway'
    vendor = 'Kong'
    description = ('Adds the certificate through the Kong Admin API, points its SNIs at it '
                   'and deletes the older ones acme put there.')
    doc = 'targets.md'
    dual = True             # a dual certificate: the twin as cert_alt / key_alt
    fields = [
        field('url', 'Admin API', 'text', required=True,
              placeholder='http://kong.example.local:8001',
              help='the address of the Kong Admin API, with http:// or https:// and its port'),
        field('token', 'Admin token', 'secret',
              help='Kong Gateway Enterprise with RBAC: the Kong-Admin-Token of an admin that '
                   'may change certificates and SNIs; empty for Kong without RBAC'),
        field('workspace', 'Workspace', 'text', advanced=True,
              help='Kong Gateway Enterprise: the workspace; empty: the default one'),
    ] + tls_fields()
    deploy_fields = [
        field('snis', 'SNIs', 'list', pattern=SEG_PATTERN, placeholder='www.example.com\n*.example.com',
              help='one a line: the server names Kong serves this certificate for; empty: '
                   'the names of the certificate'),
        keep_field(1),
    ] + verify_fields()

    def base_url(self):
        u = text(self.c('url')).strip().rstrip('/')
        if not u.startswith(('http://', 'https://')):
            u = 'http://' + u
        ws = text(self.c('workspace')).strip().strip('/')
        return u + ('/' + urllib.parse.quote(ws, safe='') if ws else '')

    def root_url(self):
        u = text(self.c('url')).strip().rstrip('/')
        return u if u.startswith(('http://', 'https://')) else 'http://' + u

    def auth_headers(self):
        tok = self.c('token')
        return {'Kong-Admin-Token': tok} if tok else {}

    def http_error(self, status, parsed, raw, method, path, what=None):
        words = HttpTarget.http_error(self, status, parsed, raw, method, path, what)
        if status == 405 and 'db-less' in text(raw).lower():
            words += ' (Kong runs without a database: its Admin API cannot change anything)'
        return words

    def test(self):
        st, hd, d = self.req('GET', self.root_url() + '/', what='reading the version')
        st, hd, c = self.req('GET', '/certificates?size=1', what='reading the certificates')
        if not isinstance(d, dict):
            raise PluginError('%s does not answer as a Kong Admin API' % self.root_url())
        return 'Kong %s at %s%s' % (d.get('version', '?'), self.root_url(),
                                    ', workspace %s' % self.c('workspace')
                                    if self.c('workspace') else '')

    # -- the objects -----------------------------------------------------------------------
    def listed(self, tags):
        out, path = [], '/certificates?tags=%s&size=1000' % urllib.parse.quote(tags, safe=',')
        for _ in range(50):
            st, hd, d = self.req('GET', path, what='listing the certificates')
            d = d if isinstance(d, dict) else {}
            out += [x for x in d.get('data') or [] if isinstance(x, dict)]
            nxt = d.get('next')
            if not nxt:
                break
            path = nxt if nxt.startswith('http') else self.root_url() + nxt
        return out

    @staticmethod
    def tags_of(bundle, options):
        label = 'acme-' + label_of(bundle, options, 40)
        return label, 'acme-fp-' + fp_of(bundle)[:16]

    def stamp_tag(self, bundle):
        return 'acme-at-%s-%s' % (stamp(bundle), short_serial(bundle))

    def deploy(self, bundle, options):
        options = options or {}
        label, fptag = self.tags_of(bundle, options)
        snis = lines(options.get('snis')) or list(getattr(bundle, 'names', None) or [])
        if not snis:
            raise PluginError('no SNI to point at the certificate', retry=False)
        have = self.listed(fptag)
        if self.unchanged(bundle, options, present=lambda: bool(have)):
            return self.same(bundle, 'in Kong')
        did = []
        if have and not as_bool(options.get('force')):
            cid = text(have[0].get('id'))
            self.ctx.step('the certificate is in Kong already (%s)' % cid)
        else:
            body = {'cert': text(bundle.as_format('fullchain-pem')),
                    'key': text(bundle.as_format('key-pem')),
                    'tags': ['acme', label, fptag, self.stamp_tag(bundle)]}
            alt = alt_of(bundle)
            if alt is not None:
                body['cert_alt'] = text(alt.as_format('fullchain-pem'))
                body['key_alt'] = text(alt.as_format('key-pem'))
            st, hd, d = self.req('POST', '/certificates', body, what='adding the certificate')
            cid = text((d or {}).get('id') if isinstance(d, dict) else '')
            if not cid:
                raise PluginError('Kong gave no id for the certificate added', detail=text(d))
            self.ctx.step('added the certificate %s%s' % (
                cid, ' (with its twin as cert_alt)' if alt is not None else ''), 'ok')
            did.append('added %s' % cid)
        for name in snis:
            self.req('PUT', '/snis/%s' % urllib.parse.quote(name, safe='*'),
                     {'certificate': {'id': cid}}, what='pointing the SNI %s' % name)
            self.ctx.step('SNI %s uses %s' % (name, cid), 'ok')
        did.append('%d SNI%s' % (len(snis), '' if len(snis) == 1 else 's'))
        self.cleanup(label, cid, self.keep(options))
        self.remember(bundle, options, id=cid)
        return ', '.join(did)

    def cleanup(self, label, current, keep):
        if keep < 0:
            return
        try:
            mine = self.listed(label)
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        # the date and serial are in a tag: acme-at-<YYYYMMDD>-<serial>
        by_name, ids = {}, {}
        for c in mine:
            at = [t for t in c.get('tags') or [] if text(t).startswith('acme-at-')]
            n = 'x-%s' % (at[0][len('acme-at-'):] if at else '00000000-%s' % text(c.get('id'))[:8])
            by_name[n] = c
            ids[text(c.get('id'))] = n
        cur = ids.get(current, '')
        for old in prune(list(by_name), 'x-', keep, cur):
            c = by_name[old]
            cid = text(c.get('id'))
            if c.get('snis'):
                self.ctx.step('the older certificate %s stays: SNIs still use it (%s)'
                              % (cid, ', '.join(map(text, c['snis']))), 'warn')
                continue
            try:
                self.req('DELETE', '/certificates/%s' % urllib.parse.quote(cid, safe=''),
                         what='deleting %s' % cid)
                self.ctx.step('deleted the older certificate %s' % cid)
            except PluginError as e:
                self.ctx.step('the older certificate %s stays: %s' % (cid, e), 'warn')
