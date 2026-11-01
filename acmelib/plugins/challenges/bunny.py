# -*- coding: utf-8 -*-
"""DNS-01 at bunny.net DNS, through its API:

    GET    https://api.bunny.net/dnszone?page=N&perPage=1000   {Items: [{Id, Domain}], HasMoreItems}
    GET    .../dnszone/{id}                                     {Records: [{Id, Type, Name, Value}]}
    PUT    .../dnszone/{id}/records  {Type: 3, Name, Value, Ttl}       (3 is TXT)
    DELETE .../dnszone/{id}/records/{record id}

Header AccessKey: the account's API key. Every value is a record of its own.
"""
from __future__ import annotations

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, no_zone,
                                                relative, unquote_txt)

API = 'https://api.bunny.net'
TXT = 3                         # bunny.net's number for a TXT record


class Bunny(ApiDns):
    kind = 'bunny'
    title = 'bunny.net DNS'
    vendor = 'bunny.net'
    who = 'bunny.net'
    description = 'TXT records in a bunny.net DNS zone, with the account\'s API key.'
    fields = [
        field('api_key', 'API key', 'secret', required=True,
              help='dash.bunny.net → Account settings → API key (the account\'s; bunny.net '
                   'has no key limited to DNS).'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, API + path, body,
                      {'AccessKey': str(self.c('api_key', ''))}, who='bunny.net',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _zone_ids(self):
        if getattr(self, '_ids', None) is None:
            ids = {}
            for page in range(1, 51):
                got = self._call('GET', '/dnszone?page=%d&perPage=1000' % page) or {}
                for z in got.get('Items') or []:
                    ids[str(z.get('Domain', '')).lower().rstrip('.')] = z.get('Id')
                if not got.get('HasMoreItems'):
                    break
            self._ids = ids
        return self._ids

    def zone_names(self):
        return list(self._zone_ids())

    def _id(self, zone):
        zid = self._zone_ids().get(zone)
        if zid is None:
            raise no_zone('bunny.net', zone)
        return zid

    def _ours(self, zid, rel, value):
        name = '' if rel == '@' else rel
        z = self._call('GET', '/dnszone/%s' % zid) or {}
        return [r['Id'] for r in z.get('Records') or []
                if r.get('Type') == TXT and (r.get('Name') or '') == name and
                unquote_txt(r.get('Value')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        zid, rel = self._id(zone), relative(fqdn, zone)
        have = self._ours(zid, rel, value)
        if have:
            return {'zone_id': zid, 'id': have[0]}
        got = self._call('PUT', '/dnszone/%s/records' % zid, {
            'Type': TXT, 'Name': '' if rel == '@' else rel, 'Value': value,
            'Ttl': self.ttl()}) or {}
        return {'zone_id': zid, 'id': got.get('Id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zid = h.get('zone_id') or self._id(self.zone_for(fqdn))
        ids = [h['id']] if h.get('id') else self._ours(
            zid, relative(fqdn, self.zone_for(fqdn)), value)
        for rid in ids:
            self._call('DELETE', '/dnszone/%s/records/%s' % (zid, rid), missing_ok=True)
