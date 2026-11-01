# -*- coding: utf-8 -*-
"""DNS-01 at Vultr, through API v2:

    GET    https://api.vultr.com/v2/domains?per_page=500&cursor=   {domains: [{domain}], meta}
    GET    .../domains/{domain}/records?per_page=500               {records: [{id, type, name, data}]}
    POST   .../domains/{domain}/records  {name, type, data, ttl}
    DELETE .../domains/{domain}/records/{id}

Vultr keeps a TXT value with its quotes ("value"); both forms are recognised
when ours is looked for. The API key only works from the addresses listed
under Account → API → Access Control.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                unquote_txt)

API = 'https://api.vultr.com/v2'


class Vultr(ApiDns):
    kind = 'vultr'
    title = 'Vultr'
    vendor = 'Vultr'
    who = 'Vultr'
    description = 'TXT records in a Vultr DNS domain, with an API key.'
    fields = [
        field('token', 'API key', 'secret', required=True,
              help='my.vultr.com → Account → API → Enable API; under Access Control, allow the '
                   'address acme reaches the internet from (Vultr refuses the key elsewhere).'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, API + path, body,
                      {'Authorization': 'Bearer ' + str(self.c('token', ''))}, who='Vultr',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _all(self, path, key):
        out, cursor = [], ''
        for _page in range(50):
            got = self._call('GET', '%s?per_page=500%s' % (
                path, '&cursor=' + urllib.parse.quote(cursor) if cursor else '')) or {}
            out += got.get(key) or []
            cursor = (((got.get('meta') or {}).get('links') or {}).get('next') or '')
            if not cursor:
                break
        return out

    def zone_names(self):
        return [d.get('domain') for d in self._all('/domains', 'domains')]

    def _ours(self, zone, rel, value):
        name = '' if rel == '@' else rel
        return [r['id'] for r in self._all('/domains/%s/records' % urllib.parse.quote(zone),
                                           'records')
                if r.get('type') == 'TXT' and (r.get('name') or '') == name and
                unquote_txt(r.get('data')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        have = self._ours(zone, rel, value)
        if have:
            return {'zone': zone, 'id': have[0]}
        got = self._call('POST', '/domains/%s/records' % urllib.parse.quote(zone), {
            'name': '' if rel == '@' else rel, 'type': 'TXT', 'data': '"%s"' % value,
            'ttl': self.ttl()}) or {}
        return {'zone': zone, 'id': (got.get('record') or {}).get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = [h['id']] if h.get('id') else self._ours(zone, relative(fqdn, zone), value)
        for rid in ids:
            self._call('DELETE', '/domains/%s/records/%s' % (urllib.parse.quote(zone), rid),
                       missing_ok=True)
