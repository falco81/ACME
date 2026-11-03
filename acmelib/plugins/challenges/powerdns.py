# -*- coding: utf-8 -*-
"""DNS-01 through the PowerDNS Authoritative HTTP API (/api/v1):

    GET   {url}/api/v1/servers/{server}                  {daemon_type, version}
    GET   .../servers/{server}/zones                      [{id, name}]
    GET   .../zones/{zone id}?rrset_name={fqdn.}&rrset_type=TXT    {rrsets: [{ttl, records}]}
    PATCH .../zones/{zone id}  {rrsets: [{name, type: TXT, changetype, records}]}

Header X-API-Key. A server of 4.9.12 or later in 4.9, or 5.0.2 and later,
takes "changetype": "EXTEND" (our record added to the RRset "if not already
present") and "PRUNE" (only our record taken away) - nothing else of the
RRset is written. An older one (or one whose version cannot be read) gets the
RRset read and written whole with REPLACE, its TTL kept, one change at a
time on this node; DELETE only when ours was its last value. A TXT content is
in double quotes (the API wants it "in expected format", else 422). The zone
is addressed by the id the server lists ("Opaque zone id ... should not be
interpreted"), its name with the final dot when it was set by hand.

Checked against the user's collection (api-docs/powerdns/):
authoritative-api-openapi.yaml (PowerDNS/pdns docs/http-api/openapi, 0.0.22)
and notes.md (https://doc.powerdns.com/authoritative/http-api/zone.html -
"Adding a single record to a RRset", "Deleting a single record from a RRset",
both "added in versions 4.9.12 and 5.0.2"; .../http-api/index.html;
.../appendices/types.html#txt; ws-auth.cc for the content check). Less certain:
the TTL an EXTEND gives a new RRset (ours is sent along); a version string
that is not "x.y.z" (taken as old: REPLACE).
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, api, as_bool, \
    discover_read, rmw_lock


def extend_prune(version):
    """Whether a PowerDNS of this version takes EXTEND / PRUNE (4.9.12+, 5.0.2+)."""
    m = re.match(r'^\s*(\d+)\.(\d+)\.(\d+)', str(version or ''))
    if not m:
        return False
    v = tuple(int(x) for x in m.groups())
    return (v[:2] == (4, 9) and v[2] >= 12) or (v[:2] == (5, 0) and v[2] >= 2) or \
        (v[0] == 5 and v[1] >= 1) or v[0] >= 6


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

    def _root(self):
        u = str(self.c('url', '')).rstrip('/')
        if not u:
            raise PluginError('the API address is not set', retry=False)
        if not u.endswith('/api/v1'):
            u += '/api/v1'
        return u

    def _base(self):
        return '%s/servers/%s' % (self._root(),
                                  urllib.parse.quote(self.c('server_id', 'localhost')))

    def _api(self, method, path, body=None, missing_ok=False, root=False):
        return api(self.ctx, method, (self._root() if root else self._base()) + path, body,
                   {'X-API-Key': str(self.c('api_key', ''))}, who='PowerDNS',
                   verify=as_bool(self.c('verify_tls', True)), missing_ok=missing_ok)[1]

    _ids = None
    _ep = None

    def _zone_list(self):
        if self._ids is None:
            self._ids = {D.norm(zz.get('name')): zz.get('id') for zz in self._api(
                'GET', '/zones') or [] if isinstance(zz, dict) and zz.get('name')}
        return self._ids

    def _zid(self, zone):
        zid = (self._ids or {}).get(D.norm(zone))
        return urllib.parse.quote(str(zid), safe='=') if zid else \
            urllib.parse.quote(D.norm(zone)) + '.'

    def _extend_prune(self):
        """EXTEND / PRUNE (4.9.12+, 5.0.2+), else the RRset written whole."""
        if self._ep is None:
            try:
                info = self._api('GET', '') or {}
            except PluginError as e:
                self.ctx.debug('PowerDNS: the version could not be read (%s)' % e)
                info = {}
            self._ep = extend_prune(info.get('version') if isinstance(info, dict) else None)
        return self._ep

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            try:
                self._zone_list()
            except PluginError as e:
                self.ctx.debug('PowerDNS: the zones could not be listed (%s)' % e)
            return z
        best = None
        for name in self._zone_list():
            if D.in_zone(fqdn, name) and (best is None or len(name) > len(best)):
                best = name
        if not best:
            raise PluginError('PowerDNS has no zone for %s' % fqdn, retry=False)
        return best

    def _rrset(self, zone, fqdn):
        """(ttl or None, [contents]) of the TXT RRset at fqdn."""
        got = self._api('GET', '/zones/%s?rrsets=true&rrset_name=%s.&rrset_type=TXT' % (
            self._zid(zone), urllib.parse.quote(D.norm(fqdn)))) or {}
        ttl, out = None, []
        for rs in got.get('rrsets') or []:
            if D.norm(rs.get('name')) == D.norm(fqdn) and rs.get('type') == 'TXT':
                ttl = rs.get('ttl') if ttl is None else ttl
                out += [r.get('content') for r in rs.get('records') or []]
        return ttl, out

    def _values(self, zone, fqdn):
        return self._rrset(zone, fqdn)[1]

    def _patch(self, zone, rs):
        self._api('PATCH', '/zones/%s' % self._zid(zone), {'rrsets': [rs]})

    def _put(self, zone, fqdn, contents, ttl=None):
        rs = {'name': D.norm(fqdn) + '.', 'type': 'TXT'}
        if contents:
            rs.update(changetype='REPLACE', ttl=int(ttl or self.ttl()),
                      records=[{'content': c, 'disabled': False} for c in contents])
        else:
            rs['changetype'] = 'DELETE'
        self._patch(zone, rs)

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        one = '"%s"' % value
        # the RRset is written whole (REPLACE): one writer at a time
        with rmw_lock(('powerdns', str(self.c('url', '')), zone)):
            ttl, have = self._rrset(zone, fqdn)
            if one in have:
                return {'zone': zone}
            if self._extend_prune():
                self._patch(zone, {'name': D.norm(fqdn) + '.', 'type': 'TXT',
                                   'changetype': 'EXTEND', 'ttl': int(ttl or self.ttl()),
                                   'records': [{'content': one, 'disabled': False}]})
            else:
                self._put(zone, fqdn, have + [one], ttl)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        one = '"%s"' % value
        with rmw_lock(('powerdns', str(self.c('url', '')), zone)):
            ttl, have = self._rrset(zone, fqdn)
            if one not in have:
                return
            if self._extend_prune():
                self._patch(zone, {'name': D.norm(fqdn) + '.', 'type': 'TXT',
                                   'changetype': 'PRUNE', 'records': [{'content': one}]})
            else:
                self._put(zone, fqdn, [x for x in have if x != one], ttl)

    # -- discovery: the servers of the API, the zones of the one picked -----------
    def zone_names(self):
        return list(self._zone_list())

    def discover_setup(self):
        """The servers the API serves (GET /api/v1/servers - an authoritative one for the
        Server id field) and the zones of the one picked (the Zone field)."""
        out0 = {'notes': []}
        servers = discover_read(out0, lambda: self._api('GET', '/servers', root=True),
                                'the servers could not be listed: %s') or []
        servers = [x for x in servers if isinstance(x, dict) and x.get('id') and
                   x.get('daemon_type', 'authoritative') == 'authoritative']
        now = str(self.c('server_id', 'localhost') or 'localhost')
        ids = [str(x['id']) for x in servers]
        pick = now if now in ids or not ids else ids[0]
        mod = self if pick == now else type(self)(dict(self.config, server_id=pick), self.ctx)
        out = DnsChallenge.discover_setup(mod)
        out['notes'] = out0['notes'] + out['notes']
        self.offer(out, 'server_id', [[str(x['id']), '%s (PowerDNS %s)' % (
            x['id'], x.get('version') or '?')] for x in servers], pick=pick)
        for x in servers:
            if str(x['id']) == pick:
                out['facts'].append(['Version', 'PowerDNS %s' % (x.get('version') or '?')])
                if not extend_prune(x.get('version')):
                    out['notes'].append('this PowerDNS is older than 4.9.12 / 5.0.2: each TXT '
                                        'RRset is read and written whole')
        return out

    def test(self):
        info = self._api('GET', '') or {}
        zones = self._api('GET', '/zones') or []
        return 'PowerDNS %s %s answers; %d zone(s): %s' % (
            info.get('daemon_type', ''), info.get('version', ''), len(zones),
            ', '.join(D.norm(z.get('name')) for z in zones[:10]))
