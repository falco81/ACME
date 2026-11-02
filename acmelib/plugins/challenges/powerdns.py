# -*- coding: utf-8 -*-
"""DNS-01 through the PowerDNS Authoritative HTTP API (/api/v1)."""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, api, as_bool, \
    rmw_lock


class PowerDns(DnsChallenge):
    kind = 'powerdns'
    api_provider = True             # its zones are asked of its API (guide)
    title = 'PowerDNS (HTTP API)'
    vendor = 'PowerDNS'
    description = 'TXT records through the PowerDNS Authoritative server\'s HTTP API.'
    fields = [
        field('url', 'API address', 'text', required=True, placeholder='http://pdns.example.com:8081',
              help='The webserver of pdns.conf (webserver-address, webserver-port), api=yes.'),
        field('api_key', 'API key', 'secret', required=True, help='api-key of pdns.conf.'),
        field('server_id', 'Server id', 'text', default='localhost', advanced=True),
        field('zone', 'Zone', 'text', default='', help='Empty: the longest zone the server has '
              'that the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('verify_tls', 'Check the API\'s certificate', 'bool', default=True, advanced=True),
    ] + PROPAGATION_FIELDS

    def _base(self):
        u = str(self.c('url', '')).rstrip('/')
        if not u:
            raise PluginError('the API address is not set', retry=False)
        if not u.endswith('/api/v1'):
            u += '/api/v1'
        return '%s/servers/%s' % (u, urllib.parse.quote(self.c('server_id', 'localhost')))

    def _api(self, method, path, body=None, missing_ok=False):
        return api(self.ctx, method, self._base() + path, body,
                   {'X-API-Key': str(self.c('api_key', ''))}, who='PowerDNS',
                   verify=as_bool(self.c('verify_tls', True)), missing_ok=missing_ok)[1]

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        best = None
        for zz in self._api('GET', '/zones') or []:
            name = D.norm(zz.get('name'))
            if D.in_zone(fqdn, name) and (best is None or len(name) > len(best)):
                best = name
        if not best:
            raise PluginError('PowerDNS has no zone for %s' % fqdn, retry=False)
        return best

    def _values(self, zone, fqdn):
        got = self._api('GET', '/zones/%s.?rrsets=true&rrset_name=%s.&rrset_type=TXT' % (
            urllib.parse.quote(zone), urllib.parse.quote(D.norm(fqdn)))) or {}
        out = []
        for rs in got.get('rrsets') or []:
            if D.norm(rs.get('name')) == D.norm(fqdn) and rs.get('type') == 'TXT':
                out += [r.get('content') for r in rs.get('records') or []]
        return out

    def _put(self, zone, fqdn, contents):
        rs = {'name': D.norm(fqdn) + '.', 'type': 'TXT', 'ttl': self.ttl()}
        if contents:
            rs.update(changetype='REPLACE',
                      records=[{'content': c, 'disabled': False} for c in contents])
        else:
            rs['changetype'] = 'DELETE'
        self._api('PATCH', '/zones/%s.' % urllib.parse.quote(zone), {'rrsets': [rs]})

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        one = '"%s"' % value
        # the RRset is written whole (REPLACE): one writer at a time
        with rmw_lock(('powerdns', str(self.c('url', '')), zone)):
            have = self._values(zone, fqdn)
            if one not in have:
                self._put(zone, fqdn, have + [one])
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        one = '"%s"' % value
        with rmw_lock(('powerdns', str(self.c('url', '')), zone)):
            have = self._values(zone, fqdn)
            if one in have:
                self._put(zone, fqdn, [x for x in have if x != one])

    def test(self):
        info = self._api('GET', '') or {}
        zones = self._api('GET', '/zones') or []
        return 'PowerDNS %s %s answers; %d zone(s): %s' % (
            info.get('daemon_type', ''), info.get('version', ''), len(zones),
            ', '.join(D.norm(z.get('name')) for z in zones[:10]))
