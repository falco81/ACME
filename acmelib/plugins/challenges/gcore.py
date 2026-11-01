# -*- coding: utf-8 -*-
"""DNS-01 at Gcore Managed DNS, through its API v2:

    GET    https://api.gcore.com/dns/v2/zones                            {zones: [{name}]}
    GET    .../dns/v2/zones/{zone}/{fqdn}/TXT                            {name, type, ttl, resource_records: [{content: [v]}]}  (404: none)
    POST   .../dns/v2/zones/{zone}/{fqdn}/TXT  {ttl, resource_records}  the RRset made
    PUT    .../dns/v2/zones/{zone}/{fqdn}/TXT  {ttl, resource_records}  the RRset written whole
    DELETE .../dns/v2/zones/{zone}/{fqdn}/TXT                           the RRset away

Authorization: APIKey <permanent API token>. The RRset is read, our value
added (or taken away) and written back - one change at a time on this node.

Sources: https://api.gcore.com/docs/dns (the RRset calls) - not reachable
from where this was written; as lego's providers/dns/internal/gcore and
acme.sh's dnsapi/dns_gcore.sh send them. Less certain: the zone list
(GET /v2/zones, its "zones" field) - when it fails, the zone is found by
asking GET /v2/zones/{name} name by name.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, rmw_lock,
                                                suffixes)

API = 'https://api.gcore.com/dns'


class Gcore(ApiDns):
    kind = 'gcore'
    title = 'Gcore DNS'
    vendor = 'Gcore'
    who = 'Gcore'
    min_ttl = 60
    description = 'TXT records in a zone at Gcore Managed DNS, with a permanent API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='Gcore portal → Profile → API tokens → create a permanent token (a role that '
                   'may edit DNS zones).'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=120, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'Authorization': 'APIKey ' + str(self.c('token', ''))}, who='Gcore',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else (got if got is not None else {})

    def zone_names(self):
        got = self._call('GET', '/v2/zones?limit=1000') or {}
        return [z.get('name') for z in got.get('zones') or [] if isinstance(z, dict)]

    def zone_hint(self, fqdn):
        try:
            return ApiDns.zone_hint(self, fqdn)
        except PluginError as e:                    # no list: asked name by name
            self.ctx.debug('Gcore zones: %s' % e)
        for cand in suffixes(fqdn):
            if self._call('GET', '/v2/zones/%s' % urllib.parse.quote(cand), missing_ok=True):
                return cand
        raise PluginError('Gcore has no zone for %s that this token may see' % D.norm(fqdn),
                          retry=False)

    def _path(self, zone, fqdn):
        return '/v2/zones/%s/%s/TXT' % (urllib.parse.quote(zone), urllib.parse.quote(fqdn))

    def _rrset(self, zone, fqdn):
        got = self._call('GET', self._path(zone, fqdn), missing_ok=True)
        if not got:
            return None, []
        vals = []
        for rr in got.get('resource_records') or []:
            vals += [str(v).strip('"') for v in rr.get('content') or []]
        return got.get('ttl'), vals

    def _write(self, method, zone, fqdn, ttl, vals):
        self._call(method, self._path(zone, fqdn), {'ttl': ttl, 'resource_records': [
            {'content': [v], 'enabled': True} for v in vals]})

    def add_txt(self, fqdn, value):
        zone, fqdn = self.zone_for(fqdn), D.norm(fqdn)
        with rmw_lock('gcore'):
            ttl, have = self._rrset(zone, fqdn)
            if value not in have:
                self._write('PUT' if have else 'POST', zone, fqdn, ttl or self.ttl(), have + [value])
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        fqdn = D.norm(fqdn)
        with rmw_lock('gcore'):
            ttl, have = self._rrset(zone, fqdn)
            if value not in have:
                return
            left = [v for v in have if v != value]
            if left:
                self._write('PUT', zone, fqdn, ttl or self.ttl(), left)
            else:
                self._call('DELETE', self._path(zone, fqdn), missing_ok=True)
