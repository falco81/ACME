# -*- coding: utf-8 -*-
"""DNS-01 at GoDaddy, through its Domains API v1:

    GET    https://api.godaddy.com/v1/domains?statuses=ACTIVE&limit=1000   [{domain}]
    GET    .../domains/{domain}/records/TXT/{name}                          [{data, ttl}]
    PUT    .../domains/{domain}/records/TXT/{name}  [{data, ttl}, ...]      that name's TXT, whole
    DELETE .../domains/{domain}/records/TXT/{name}                          all of them

Authorization: sso-key KEY:SECRET. The values at the name are read, ours
added or taken away, and written back (DELETE when none is left).

GoDaddy has limited its production API to accounts with enough domains (or a
Discount Domain Club plan) since 2024: other keys get 403 "ACCESS_DENIED".
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                rmw_lock, unquote_txt)

APIS = {'production': 'https://api.godaddy.com/v1', 'ote': 'https://api.ote-godaddy.com/v1'}


class GoDaddy(ApiDns):
    kind = 'godaddy'
    title = 'GoDaddy'
    vendor = 'GoDaddy'
    who = 'GoDaddy'
    min_ttl = 600
    description = 'TXT records in a domain at GoDaddy, with an API key and its secret.'
    fields = [
        field('api_key', 'API key', 'text', required=True,
              help='developer.godaddy.com → API Keys → Create New API Key, environment '
                   '"Production". GoDaddy lets only some accounts use the production API.'),
        field('api_secret', 'API secret', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True,
              help='GoDaddy takes 600 or more.'),
        field('endpoint', 'Endpoint', 'select', default='production', advanced=True,
              options=[['production', 'api.godaddy.com'],
                       ['ote', 'api.ote-godaddy.com (the test environment)']]),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        base = APIS.get(self.c('endpoint', 'production'), APIS['production'])
        st, got = api(self.ctx, method, base + path, body, {
            'Authorization': 'sso-key %s:%s' % (self.c('api_key', ''), self.c('api_secret', ''))},
            who='GoDaddy', missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        return [d.get('domain') for d in
                self._call('GET', '/domains?statuses=ACTIVE&limit=1000') or []]

    def _path(self, zone, rel):
        return '/domains/%s/records/TXT/%s' % (urllib.parse.quote(zone),
                                               urllib.parse.quote(rel, safe='@'))

    def _values(self, zone, rel):
        return [r for r in self._call('GET', self._path(zone, rel), missing_ok=True) or []
                if isinstance(r, dict)]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        with rmw_lock('godaddy'):
            have = self._values(zone, rel)
            if value not in [unquote_txt(r.get('data')) for r in have]:
                recs = [{'data': r.get('data'), 'ttl': int(r.get('ttl') or self.ttl())}
                        for r in have] + [{'data': value, 'ttl': self.ttl()}]
                self._call('PUT', self._path(zone, rel), recs)
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        rel = h.get('rel') or relative(fqdn, zone)
        with rmw_lock('godaddy'):
            have = self._values(zone, rel)
            left = [{'data': r.get('data'), 'ttl': int(r.get('ttl') or self.ttl())}
                    for r in have if unquote_txt(r.get('data')) != value]
            if len(left) == len(have):
                return
            if left:
                self._call('PUT', self._path(zone, rel), left)
            else:
                self._call('DELETE', self._path(zone, rel), missing_ok=True)
