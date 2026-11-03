# -*- coding: utf-8 -*-
"""DNS-01 through Cloudflare's API (an API token that may edit the zone's DNS).

    GET    https://api.cloudflare.com/client/v4/zones?name={zone}
    GET    .../zones/{zone_id}/dns_records?type=TXT&name={fqdn}        (name = name.exact)
    POST   .../zones/{zone_id}/dns_records  {type: TXT, name: fqdn, content, ttl, comment}
    DELETE .../zones/{zone_id}/dns_records/{id}

Each value is a record of its own with its id: cleanup deletes only ours.
Cloudflare keeps a TXT content in double quotes ("if you save your TXT content
without any quotes, Cloudflare will automatically add double quotes"), so a
listed content is compared with its quotes taken away. TTL 60 to 86400, or 1
for "automatic" (30 for Enterprise zones).

Checked against the user's collection (api-docs/cloudflare/): openapi-dns-zones.json
(an extract of https://github.com/cloudflare/api-schemas openapi.json) and
notes.md (https://developers.cloudflare.com/api/resources/dns/subresources/records/,
https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/).
Less certain: the code 81058 for an identical record is known only from
Cloudflare's community forum (the record is then looked up and adopted).
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, api, unquote_txt


class Cloudflare(DnsChallenge):
    kind = 'cloudflare'
    api_provider = True             # its zones are asked of its API (guide)
    title = 'Cloudflare'
    vendor = 'Cloudflare'
    description = 'TXT records through the Cloudflare API, with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='My Profile → API Tokens → Create Token → "Edit zone DNS", limited to the '
                   'zones acme may change (Zone:DNS:Edit and Zone:Zone:Read).'),
        field('zone_id', 'Zone ID', 'text', default='', advanced=True,
              help='Empty: found by the name (needs Zone:Read).'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='60 or more (1 is Cloudflare\'s "auto").'),
        field('api', 'API address', 'text', default='https://api.cloudflare.com/client/v4',
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _api(self, method, path, body=None, missing_ok=False):
        base = str(self.c('api')).rstrip('/')
        st, got = api(self.ctx, method, base + path, body,
                      {'Authorization': 'Bearer ' + str(self.c('token', ''))},
                      who='Cloudflare', missing_ok=missing_ok)
        if st == 404 and missing_ok:
            return None
        if isinstance(got, dict) and got.get('success') is False:
            raise PluginError('Cloudflare said no: %s' % '; '.join(
                '%s (%s)' % (e.get('message'), e.get('code')) for e in got.get('errors') or []))
        return got.get('result') if isinstance(got, dict) else None

    def _zone_id(self, fqdn):
        if self.c('zone_id'):
            return self.c('zone_id'), self.c('zone', '') or None
        labels = D.norm(fqdn).split('.')
        for i in range(len(labels) - 1):
            cand = '.'.join(labels[i:])
            got = self._api('GET', '/zones?name=' + urllib.parse.quote(cand))
            if got:
                return got[0]['id'], cand
        raise PluginError('Cloudflare has no zone for %s that this token may see' % fqdn,
                          retry=False)

    def zone_hint(self, fqdn):
        try:
            return self._zone_id(fqdn)[1]
        except PluginError:
            return None

    def add_txt(self, fqdn, value):
        zid, _z = self._zone_id(fqdn)
        try:
            rec = self._api('POST', '/zones/%s/dns_records' % zid,
                            {'type': 'TXT', 'name': D.norm(fqdn), 'content': value,
                             'ttl': max(self.ttl(), 1), 'comment': 'acme DNS-01'})
        except PluginError as e:
            if '81058' not in str(e) and 'already exists' not in str(e):
                raise
            rec = ([r for r in self._txt(zid, fqdn) if unquote_txt(r.get('content')) == value]
                   or [{}])[0]
        return {'zone_id': zid, 'id': (rec or {}).get('id')}

    def _txt(self, zid, fqdn):
        return [r for r in self._api('GET', '/zones/%s/dns_records?type=TXT&name=%s' % (
            zid, urllib.parse.quote(D.norm(fqdn)))) or [] if isinstance(r, dict)]

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zid = h.get('zone_id') or self._zone_id(fqdn)[0]
        ids = [h['id']] if h.get('id') else [
            r['id'] for r in self._txt(zid, fqdn) if unquote_txt(r.get('content')) == value]
        for rid in ids:
            self._api('DELETE', '/zones/%s/dns_records/%s' % (zid, rid), missing_ok=True)

    def add_cname(self, fqdn, target):
        zid, _z = self._zone_id(fqdn)
        rec = self._api('POST', '/zones/%s/dns_records' % zid,
                        {'type': 'CNAME', 'name': D.norm(fqdn), 'content': D.norm(target),
                         'ttl': max(self.ttl(), 1), 'proxied': False,
                         'comment': 'acme DCV'}) or {}
        return {'zone_id': zid, 'id': rec.get('id')}

    def del_cname(self, fqdn, target, handle):
        h = handle or {}
        zid = h.get('zone_id') or self._zone_id(fqdn)[0]
        ids = [h['id']] if h.get('id') else [
            r['id'] for r in self._api('GET', '/zones/%s/dns_records?type=CNAME&name=%s' % (
                zid, urllib.parse.quote(D.norm(fqdn)))) or []
            if D.norm(r.get('content') or '') == D.norm(target)]
        for rid in ids:
            self._api('DELETE', '/zones/%s/dns_records/%s' % (zid, rid), missing_ok=True)

    def test(self):
        if self.c('zone_id'):
            z = self._api('GET', '/zones/%s' % self.c('zone_id')) or {}
            return 'the token sees the zone %s (%s)' % (z.get('name'), z.get('status'))
        zones = self._api('GET', '/zones?per_page=50') or []
        if not zones:
            raise PluginError('the token works but sees no zone - give it Zone:Read and '
                              'Zone:DNS:Edit on your zones', retry=False)
        return 'the token sees %d zone(s): %s' % (len(zones), ', '.join(
            z.get('name', '?') for z in zones[:10]))
