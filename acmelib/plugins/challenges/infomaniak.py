# -*- coding: utf-8 -*-
"""DNS-01 at Infomaniak (Switzerland), through its API v2:

    GET    https://api.infomaniak.com/2/zones/{zone}/exists                 {result, data: true|false}
    GET    .../2/zones/{zone}/records?with=idn                              {data: [{id, source, source_idn, type, target, ttl}]}
    POST   .../2/zones/{zone}/records   {source, type: "TXT", target, ttl}  {data: {id}}
    DELETE .../2/zones/{zone}/records/{id}

Authorization: Bearer <token>; every answer {result: "success" | "error",
data, error: {code, description}}. "source" is relative to the zone ("." the
apex); a TXT "target" is kept in quotes. The zone is found by asking
/exists name by name (the API lists products, not zones).

Sources: https://developer.infomaniak.com/docs/api/get/2/zones/{zone}/records
and .../post/2/zones/{zone}/records - not reachable from where this was
written; as lego's providers/dns/infomaniak and Posh-ACME's InfomaniakV2
plugin send them. Infomaniak takes no TTL under 300.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api, suffixes
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://api.infomaniak.com'


class Infomaniak(RecordApiDns):
    kind = 'infomaniak'
    discovery = False               # discovery: nothing to read from an account
    title = 'Infomaniak'
    vendor = 'Infomaniak'
    who = 'Infomaniak'
    min_ttl = 300
    description = 'TXT records in a zone at Infomaniak, with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='manager.infomaniak.com → (your profile) → Developer → API tokens → create a '
                   'token with the scope "domain:read" and "dns:write" (or "accounts" and '
                   '"domain" for older tokens).'),
        field('zone', 'Zone', 'text', default='', placeholder='example.ch',
              help='Empty: the longest name the name is in that Infomaniak says is a zone.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='Infomaniak takes 300 or more.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'Authorization': 'Bearer ' + str(self.c('token', ''))}, who='Infomaniak',
                      missing_ok=missing_ok)
        if st == 404 and missing_ok:
            return None
        if isinstance(got, dict) and got.get('result') not in (None, 'success'):
            e = got.get('error') or {}
            raise PluginError('Infomaniak said no: %s (%s)' % (e.get('description'), e.get('code')),
                              detail=got, retry=False)
        return (got or {}).get('data') if isinstance(got, dict) else got

    def zone_names(self):
        return None

    def zone_hint(self, fqdn):
        z = D.norm(self.c('zone', ''))
        if z and D.in_zone(fqdn, z):
            return z
        seen = []
        for cand in suffixes(fqdn):
            if self._call('GET', '/2/zones/%s/exists' % urllib.parse.quote(cand),
                          missing_ok=True) is True:
                seen.append(cand)
                break
        self._zone_list = seen
        if not seen:
            raise PluginError('Infomaniak has no zone for %s that this token may see'
                              % D.norm(fqdn), retry=False)
        return seen[0]

    def txt_records(self, zone, fqdn):
        rel = rel_name(fqdn, zone, apex='.')
        got = self._call('GET', '/2/zones/%s/records?with=idn' % urllib.parse.quote(zone)) or []
        return [(r.get('id'), r.get('target')) for r in got if isinstance(r, dict) and
                str(r.get('type')).upper() == 'TXT' and
                (r.get('source') == rel or D.norm(r.get('source_idn') or '') == fqdn)]

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/2/zones/%s/records' % urllib.parse.quote(zone), {
            'source': rel_name(fqdn, zone, apex='.'), 'type': 'TXT', 'target': '"%s"' % value,
            'ttl': self.ttl()}) or {}
        return got.get('id') if isinstance(got, dict) else got

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/2/zones/%s/records/%s' % (urllib.parse.quote(zone), record_id),
                   missing_ok=True)

    def test(self):
        z = D.norm(self.c('zone', ''))
        if not z:
            return ('Infomaniak: the token is set; the zones cannot be listed - set the zone to '
                    'have it checked here')
        if self._call('GET', '/2/zones/%s/exists' % urllib.parse.quote(z)) is not True:
            raise PluginError('Infomaniak says there is no zone %s for this token' % z,
                              retry=False)
        return 'Infomaniak: the token sees the zone %s' % z
