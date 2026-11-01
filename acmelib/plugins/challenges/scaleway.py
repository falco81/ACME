# -*- coding: utf-8 -*-
"""DNS-01 at Scaleway, through the Domains and DNS API (v2beta1):

    GET   https://api.scaleway.com/domain/v2beta1/dns-zones?page=N&page_size=100
                                       {dns_zones: [{domain, subdomain}], total_count}
    GET   .../dns-zones/{zone}/records?name={sub}&type=TXT      {records: [{id, name, data}]}
    PATCH .../dns-zones/{zone}/records  {changes: [{add: {records: [{name, type, data, ttl}]}}]}
                                        {changes: [{delete: {id: ...}}]}

Header X-Auth-Token: the secret key of an API key. A TXT value is kept with
its quotes. Each value is added or removed by itself.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                unquote_txt)

API = 'https://api.scaleway.com/domain/v2beta1'


class Scaleway(ApiDns):
    kind = 'scaleway'
    title = 'Scaleway'
    vendor = 'Scaleway'
    who = 'Scaleway'
    description = 'TXT records in a Scaleway DNS zone, with an API key.'
    fields = [
        field('secret_key', 'Secret key', 'secret', required=True,
              help='console.scaleway.com → IAM → API keys → Generate: of an application whose '
                   'policy gives DomainsDNSFullAccess (or DomainsDNSRead and DomainsDNSWrite… as '
                   'Scaleway names them) on the project of the zone.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone the key may see that the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, API + path, body,
                      {'X-Auth-Token': str(self.c('secret_key', ''))}, who='Scaleway',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        out = []
        for page in range(1, 51):
            got = self._call('GET', '/dns-zones?page=%d&page_size=100' % page) or {}
            zs = got.get('dns_zones') or []
            out += [('%s.%s' % (z['subdomain'], z['domain'])) if z.get('subdomain')
                    else z.get('domain') for z in zs]
            if len(zs) < 100 or len(out) >= int(got.get('total_count') or 0):
                break
        return out

    def _ours(self, zone, rel, value):
        name = '' if rel == '@' else rel
        got = self._call('GET', '/dns-zones/%s/records?name=%s&type=TXT&page_size=100' % (
            urllib.parse.quote(zone), urllib.parse.quote(name))) or {}
        return [r['id'] for r in got.get('records') or []
                if (r.get('name') or '') == name and unquote_txt(r.get('data')) == value]

    def _patch(self, zone, change):
        self._call('PATCH', '/dns-zones/%s/records' % urllib.parse.quote(zone),
                   {'changes': [change], 'return_all_records': False})

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        if not self._ours(zone, rel, value):
            self._patch(zone, {'add': {'records': [{
                'name': '' if rel == '@' else rel, 'type': 'TXT', 'data': '"%s"' % value,
                'ttl': self.ttl()}]}})
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        for rid in self._ours(zone, h.get('rel') or relative(fqdn, zone), value):
            self._patch(zone, {'delete': {'id': rid}})
