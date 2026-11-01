# -*- coding: utf-8 -*-
"""DNS-01 at Netlify DNS, through Netlify's API v1:

    GET    https://api.netlify.com/api/v1/dns_zones                             [{id, name}]
    GET    .../dns_zones/{zone id}/dns_records                                  [{id, hostname, type, value, ttl}]
    POST   .../dns_zones/{zone id}/dns_records   {type, hostname, value, ttl}   {id}
    DELETE .../dns_zones/{zone id}/dns_records/{record id}

Authorization: Bearer <personal access token>. "hostname" is the full name.

Sources: https://open-api.netlify.com/#tag/dnsZone - not reachable from where
this was written; as lego's providers/dns/netlify sends it.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns

API = 'https://api.netlify.com/api/v1'


class Netlify(RecordApiDns):
    kind = 'netlify'
    title = 'Netlify DNS'
    vendor = 'Netlify'
    who = 'Netlify'
    min_ttl = 60
    description = 'TXT records in a zone at Netlify DNS, with a personal access token.'
    fields = [
        field('token', 'Personal access token', 'secret', required=True,
              help='app.netlify.com → User settings → Applications → Personal access tokens → '
                   'New access token.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        _st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                       {'Authorization': 'Bearer ' + str(self.c('token', ''))}, who='Netlify',
                       missing_ok=missing_ok)
        return got

    def _zones(self):
        if getattr(self, '_zids', None) is None:
            self._zids = {D.norm(z.get('name')): z.get('id')
                          for z in self._call('GET', '/dns_zones') or [] if isinstance(z, dict)}
        return self._zids

    def zone_names(self):
        return list(self._zones())

    def _zid(self, zone):
        zid = self._zones().get(D.norm(zone))
        if not zid:
            raise PluginError('Netlify has no DNS zone %s on this account' % zone, retry=False)
        return urllib.parse.quote(str(zid), safe='')

    def txt_records(self, zone, fqdn):
        return [(r.get('id'), r.get('value')) for r in
                self._call('GET', '/dns_zones/%s/dns_records' % self._zid(zone)) or []
                if isinstance(r, dict) and str(r.get('type')).upper() == 'TXT' and
                D.norm(r.get('hostname') or '') == fqdn]

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/dns_zones/%s/dns_records' % self._zid(zone), {
            'type': 'TXT', 'hostname': fqdn, 'value': value, 'ttl': self.ttl()}) or {}
        return got.get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/dns_zones/%s/dns_records/%s' % (self._zid(zone), record_id),
                   missing_ok=True)
