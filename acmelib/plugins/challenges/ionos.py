# -*- coding: utf-8 -*-
"""DNS-01 at IONOS, through the IONOS Hosting DNS API:

    GET    https://api.hosting.ionos.com/dns/v1/zones                    [{id, name, type}]
    GET    .../zones/{id}?recordName={fqdn}&recordType=TXT              {records: [{id, name, content}]}
    POST   .../zones/{id}/records  [{name, type, content, ttl, prio, disabled}]
    DELETE .../zones/{id}/records/{record id}

Header X-API-Key: "<public prefix>.<secret>" - both halves, a dot between, as
the developer portal shows them. Every value is a record of its own. (This is
the API of the IONOS hosting/domain contracts, not the IONOS Cloud DNS of
DCD - that one has its own API.)
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, no_zone,
                                                unquote_txt)

API = 'https://api.hosting.ionos.com/dns/v1'


class Ionos(ApiDns):
    kind = 'ionos'
    title = 'IONOS (Hosting API)'
    vendor = 'IONOS'
    who = 'IONOS'
    description = 'TXT records in a zone at IONOS, with a Hosting API key.'
    fields = [
        field('prefix', 'Public prefix', 'text', required=True,
              help='developer.hosting.ionos.com → Get started → API keys → Create: its public '
                   'prefix here, its secret below.'),
        field('secret', 'Secret', 'secret', required=True),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, API + path, body,
                      {'X-API-Key': '%s.%s' % (self.c('prefix', ''), self.c('secret', ''))},
                      who='IONOS', missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _zone_ids(self):
        if getattr(self, '_ids', None) is None:
            self._ids = {D.norm(z.get('name')): z.get('id') for z in
                         self._call('GET', '/zones') or []}
        return self._ids

    def zone_names(self):
        return list(self._zone_ids())

    def _id(self, zone):
        zid = self._zone_ids().get(zone)
        if not zid:
            raise no_zone('IONOS', zone)
        return zid

    def _ours(self, zid, fqdn, value):
        got = self._call('GET', '/zones/%s?recordName=%s&recordType=TXT' % (
            zid, urllib.parse.quote(D.norm(fqdn)))) or {}
        return [r['id'] for r in got.get('records') or []
                if D.norm(r.get('name')) == D.norm(fqdn) and r.get('type', 'TXT') == 'TXT' and
                unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zid = self._id(self.zone_for(fqdn))
        have = self._ours(zid, fqdn, value)
        if have:
            return {'zone_id': zid, 'id': have[0]}
        got = self._call('POST', '/zones/%s/records' % zid, [{
            'name': D.norm(fqdn), 'type': 'TXT', 'content': value, 'ttl': self.ttl(),
            'prio': 0, 'disabled': False}]) or []
        return {'zone_id': zid, 'id': (got[0] if got and isinstance(got, list) else {}).get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zid = h.get('zone_id') or self._id(self.zone_for(fqdn))
        ids = [h['id']] if h.get('id') else self._ours(zid, fqdn, value)
        for rid in ids:
            self._call('DELETE', '/zones/%s/records/%s' % (zid, rid), missing_ok=True)
