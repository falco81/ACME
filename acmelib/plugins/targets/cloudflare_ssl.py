# -*- coding: utf-8 -*-
"""
Cloudflare custom certificates (Business and Enterprise zones, or the
Advanced Certificate Manager add-on): the certificate uploaded once, then
replaced on each renewal with PATCH, which Cloudflare swaps on its edge
without a gap. For sni_custom the PATCH "will result in a new resource id
being returned, and the previous one being deleted": acme keeps the id the
answer gives for the next renewal.

    GET   https://api.cloudflare.com/client/v4/zones?name=<zone>
    GET   /zones/<zone_id>/custom_certificates
    POST  /zones/<zone_id>/custom_certificates   {certificate, private_key,
          bundle_method, type}
    PATCH /zones/<zone_id>/custom_certificates/<id>  {certificate, private_key,
          bundle_method}

An API token with Zone → SSL and Certificates → Edit (and Zone → Zone → Read
to find the zone by its name).

Sources:
    https://developers.cloudflare.com/api/resources/custom_certificates/methods/create/
    https://developers.cloudflare.com/api/resources/custom_certificates/methods/edit/
    https://developers.cloudflare.com/ssl/edge-certificates/custom-certificates/uploading/
Checked against api-docs/cloudflare_ssl/notes.md and cloudflare-ssl-extract.json.
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.targets._common import (
    PluginError, field, label_of, text, verify_fields)
from acmelib.plugins.targets._cloud import CloudTarget, cloud_fields

BASE = 'https://api.cloudflare.com/client/v4'


class CloudflareSslTarget(CloudTarget):
    kind = 'cloudflare_ssl'
    title = 'Cloudflare custom certificate'
    vendor = 'Cloudflare'
    description = ('Uploads the certificate as a custom certificate of a Cloudflare zone and '
                   'replaces it in place on each renewal.')
    doc = 'targets.md'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='My Profile → API Tokens: Zone → SSL and Certificates → Edit (and Zone → '
                   'Zone → Read when the zone is given by its name)'),
        field('zone', 'Zone', 'text', required=True, placeholder='example.com',
              help='its name, or its zone ID (32 hex characters)'),
    ] + cloud_fields()
    deploy_fields = [
        field('bundle_method', 'Chain', 'select', default='force',
              options=[['force', 'as acme gives it (force)'],
                       ['ubiquitous', 'the most compatible Cloudflare can build (ubiquitous)'],
                       ['optimal', 'the shortest (optimal)']]),
        field('type', 'Served to', 'select', default='sni_custom', advanced=True,
              options=[['sni_custom', 'clients with SNI (sni_custom)'],
                       ['legacy_custom', 'every client (legacy_custom)']]),
    ] + verify_fields()

    _zone_id = None

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.c('token')}

    def http_error(self, status, parsed, raw, method, path, what=None):
        if isinstance(parsed, dict) and parsed.get('errors'):
            msg = '; '.join('%s %s' % (e.get('code', ''), e.get('message', ''))
                            for e in parsed['errors'] if isinstance(e, dict))
            return '%s: Cloudflare said %d - %s' % (what or path, status, msg.strip())
        return CloudTarget.http_error(self, status, parsed, raw, method, path, what)

    def zone_id(self):
        if self._zone_id:
            return self._zone_id
        z = text(self.c('zone')).strip().rstrip('.')
        if re.match(r'^[0-9a-f]{32}$', z):
            self._zone_id = z
            return z
        st, hd, d = self.req('GET', '%s/zones?name=%s' % (BASE, urllib.parse.quote(z)),
                             what='finding the zone %s' % z)
        res = (d or {}).get('result') or [] if isinstance(d, dict) else []
        if not res:
            raise PluginError('Cloudflare has no zone %s for this token' % z, retry=False)
        self._zone_id = res[0]['id']
        return self._zone_id

    def kv_key(self, bundle, options):
        return 'cloudflare-ssl:%s:%s' % (self.c('zone'), label_of(bundle, options))

    def listed(self):
        st, hd, d = self.req('GET', '%s/zones/%s/custom_certificates?per_page=50'
                             % (BASE, self.zone_id()), what='listing the custom certificates')
        return (d or {}).get('result') or [] if isinstance(d, dict) else []

    def test(self):
        st, hd, d = self.req('GET', '%s/zones/%s' % (BASE, self.zone_id()),
                             what='reading the zone')
        r = (d or {}).get('result') or {}
        n = len(self.listed())
        return 'signed in: zone %s (%s plan), %d custom certificate%s' % (
            r.get('name', '?'), (r.get('plan') or {}).get('name', '?'), n, '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        have = self.listed()
        ids = {c.get('id') for c in have}
        try:
            cid = text(self.ctx.kv_get(self.kv_key(bundle, options)) or '')
        except Exception:                               # noqa: BLE001
            cid = ''
        if cid not in ids:
            cid = ''
            want = sorted(n.lower() for n in bundle.names)
            same = [c for c in have if sorted(h.lower() for h in c.get('hosts') or []) == want]
            if len(same) == 1:
                cid = same[0]['id']
                self.ctx.step('the custom certificate %s has the same names: replacing it' % cid)
        if cid and self.unchanged(bundle, options):
            return self.same(bundle, 'in %s' % cid)
        body = {'certificate': text(bundle.as_format('fullchain-pem')),
                'private_key': text(bundle.as_format('key-pem')),
                'bundle_method': self.opt(options, 'bundle_method', 'force')}
        z = self.zone_id()
        if cid:
            st, hd, d = self.req('PATCH', '%s/zones/%s/custom_certificates/%s' % (BASE, z, cid),
                                 body, what='replacing the custom certificate %s' % cid)
            how = 'replaced'
        else:
            body['type'] = self.opt(options, 'type', 'sni_custom')
            st, hd, d = self.req('POST', '%s/zones/%s/custom_certificates' % (BASE, z), body,
                                 what='uploading the custom certificate')
            how = 'uploaded'
        new = ((d or {}).get('result') or {}).get('id') if isinstance(d, dict) else None
        new = new or cid
        try:
            self.ctx.kv_set(self.kv_key(bundle, options), new)
        except Exception as e:                          # noqa: BLE001
            self.ctx.debug('cannot keep the id: %s' % e)
        self.ctx.step('%s the custom certificate %s' % (how, new), 'ok')
        self.remember(bundle, options)
        return '%s the custom certificate %s of %s' % (how, new, self.c('zone'))

    def remove(self, bundle, options):
        cid = text(self.ctx.kv_get(self.kv_key(bundle, options)) or '')
        if cid:
            self.req('DELETE', '%s/zones/%s/custom_certificates/%s'
                     % (BASE, self.zone_id(), cid), ok=(200, 404))
