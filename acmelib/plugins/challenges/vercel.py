# -*- coding: utf-8 -*-
"""DNS-01 at Vercel DNS, through Vercel's REST API:

    GET    https://api.vercel.com/v5/domains                                  {domains: [{name}]}
    GET    .../v4/domains/{domain}/records?limit=100                          {records: [{id, name, type, value}]}
    POST   .../v2/domains/{domain}/records   {name, type: "TXT", value, ttl}  {uid}
    DELETE .../v2/domains/{domain}/records/{record id}

Authorization: Bearer <token>; ?teamId=... on every call for a team's
domains. "name" is relative to the domain ("" the apex).

Sources: https://vercel.com/docs/rest-api/reference/endpoints/dns (and
.../domains/list-all-the-domains) - not reachable from where this was written;
records POST and DELETE as lego's providers/dns/vercel sends them. Less
certain: the version numbers of the two lists (v5 domains, v4 records) -
Vercel keeps older versions answering.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://api.vercel.com'


class Vercel(RecordApiDns):
    kind = 'vercel'
    title = 'Vercel DNS'
    vendor = 'Vercel'
    who = 'Vercel'
    min_ttl = 60
    description = 'TXT records in a domain at Vercel DNS, with an access token.'
    fields = [
        field('token', 'Access token', 'secret', required=True,
              help='vercel.com → Account settings → Tokens → Create (scoped to the team that '
                   'holds the domains).'),
        field('team', 'Team ID', 'text', default='', placeholder='team_...',
              help='For domains of a team: its ID (Team settings → General). Empty: your own.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain the token sees that the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False, query=None):
        q = dict(query or {})
        if self.c('team'):
            q['teamId'] = self.c('team')
        url = str(self.c('api', API)).rstrip('/') + path + (
            ('?' + urllib.parse.urlencode(q)) if q else '')
        _st, got = api(self.ctx, method, url, body,
                       {'Authorization': 'Bearer ' + str(self.c('token', ''))}, who='Vercel',
                       missing_ok=missing_ok)
        return got or {}

    def zone_names(self):
        return [d.get('name') for d in self._call('GET', '/v5/domains',
                                                  query={'limit': 100}).get('domains') or []]

    def txt_records(self, zone, fqdn):
        name = rel_name(fqdn, zone, apex='')
        got = self._call('GET', '/v4/domains/%s/records' % urllib.parse.quote(zone),
                         query={'limit': 100})
        return [(r.get('id'), r.get('value')) for r in got.get('records') or []
                if str(r.get('type')).upper() == 'TXT' and (r.get('name') or '') == name]

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/v2/domains/%s/records' % urllib.parse.quote(zone), {
            'name': rel_name(fqdn, zone, apex=''), 'type': 'TXT', 'value': value,
            'ttl': self.ttl()})
        return got.get('uid') or got.get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/v2/domains/%s/records/%s' % (urllib.parse.quote(zone), record_id),
                   missing_ok=True)
