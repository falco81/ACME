# -*- coding: utf-8 -*-
"""DNS-01 at NS1 (IBM NS1 Connect), through API v1:

    GET    https://api.nsone.net/v1/zones                        [{zone}]
    GET    .../zones/{zone}/{domain}/TXT                          {answers: [{answer: [..]}], ttl}
    PUT    .../zones/{zone}/{domain}/TXT  {zone, domain, type, answers, ttl}    made new
    POST   .../zones/{zone}/{domain}/TXT  {answers, ttl}                         changed
    DELETE .../zones/{zone}/{domain}/TXT

(NS1 makes a record with PUT and changes it with POST.) Header X-NSONE-Key.
The answers are read, ours added or taken away, and written back (DELETE when
none is left).
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ApiDns, api, rmw_lock

API = 'https://api.nsone.net/v1'


class Ns1(ApiDns):
    kind = 'ns1'
    title = 'NS1 (IBM NS1 Connect)'
    vendor = 'NS1'
    who = 'NS1'
    description = 'TXT records in an NS1 zone, with an API key.'
    fields = [
        field('api_key', 'API key', 'secret', required=True,
              help='The NS1 portal → Account settings → Users & teams → API keys → Add key: '
                   'DNS "View zones" and "Manage zones", limited to the zones acme may change.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True,
              help='For a private NS1 (DDI) deployment, its own address.'),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'X-NSONE-Key': str(self.c('api_key', ''))}, who='NS1',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        return [z.get('zone') for z in self._call('GET', '/zones') or []]

    def _path(self, zone, fqdn):
        return '/zones/%s/%s/TXT' % (urllib.parse.quote(zone), urllib.parse.quote(D.norm(fqdn)))

    def _answers(self, zone, fqdn):
        got = self._call('GET', self._path(zone, fqdn), missing_ok=True)
        if got is None:
            return None, None
        return [list(a.get('answer') or []) for a in got.get('answers') or []], got.get('ttl')

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        with rmw_lock('ns1'):
            have, ttl = self._answers(zone, fqdn)
            if have is None:
                self._call('PUT', self._path(zone, fqdn), {
                    'zone': zone, 'domain': D.norm(fqdn), 'type': 'TXT', 'ttl': self.ttl(),
                    'answers': [{'answer': [value]}]})
            elif [value] not in have:
                self._call('POST', self._path(zone, fqdn), {
                    'answers': [{'answer': a} for a in have + [[value]]],
                    'ttl': int(ttl or self.ttl())})
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        with rmw_lock('ns1'):
            have, ttl = self._answers(zone, fqdn)
            if not have or [value] not in have:
                return
            left = [a for a in have if a != [value]]
            if left:
                self._call('POST', self._path(zone, fqdn), {
                    'answers': [{'answer': a} for a in left], 'ttl': int(ttl or self.ttl())})
            else:
                self._call('DELETE', self._path(zone, fqdn), missing_ok=True)
