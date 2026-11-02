# -*- coding: utf-8 -*-
"""DNS-01 at Hostinger, through the Hostinger API (DNS zone and domains
portfolio):

    GET    https://developers.hostinger.com/api/domains/v1/portfolio     [{id, domain, type, status}]
    GET    .../api/dns/v1/zones/{domain}                                 [{name, type, ttl, records: [{content, is_disabled}]}]
    PUT    .../api/dns/v1/zones/{domain}  {overwrite: false, zone: [{name, type, ttl, records: [{content}]}]}
                                         (overwrite false: the records are added to the RRset)
    PUT    .../api/dns/v1/zones/{domain}  {overwrite: true, zone: [...]} the RRset written whole
    DELETE .../api/dns/v1/zones/{domain}  {filters: [{name, type}]}     the RRset away

Authorization: Bearer <API token> (hPanel → Account → API). "name" is
relative to the zone, "@" the apex. Our value is added with overwrite false;
cleanup writes the RRset back without it (overwrite true), or deletes the
RRset when ours was its last value - one change at a time on this node.

Sources: Hostinger's official Python SDK, generated from its OpenAPI
description (https://github.com/hostinger/api-python-sdk: docs/DNSZoneApi.md -
get_dns_records_v1, update_dns_records_v1, delete_dns_records_v1;
docs/DomainsPortfolioApi.md - get_domain_list_v1; the models
DNSV1ZoneUpdateRequest, DNSV1ZoneDestroyRequest, DNSV1ZoneRecordResource),
whose reference is https://developers.hostinger.com; cross-checked with lego's
providers/dns/hostinger. Less certain: a domain whose DNS is at Hostinger
but which is not in the portfolio - it is asked for by name
(GET /api/dns/v1/zones/{name}); set the domain to skip the list.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                rmw_lock, suffixes, unquote_txt)

API = 'https://developers.hostinger.com'


class Hostinger(ApiDns):
    kind = 'hostinger'
    title = 'Hostinger'
    vendor = 'Hostinger'
    who = 'Hostinger'
    min_ttl = 60
    description = 'TXT records in a domain\'s DNS zone at Hostinger, with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='hPanel → Account → API → New token (best with an expiry and only the '
                   'domains acme needs).'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'Authorization': 'Bearer ' + str(self.c('token', ''))}, who='Hostinger',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        got = self._call('GET', '/api/domains/v1/portfolio') or []
        if isinstance(got, dict):
            got = got.get('data') or []
        return [d.get('domain') for d in got if isinstance(d, dict) and d.get('domain')]

    def zone_hint(self, fqdn):
        try:
            return ApiDns.zone_hint(self, fqdn)
        except PluginError as e:                    # not in the portfolio: asked by name
            self.ctx.debug('Hostinger domains: %s' % e)
        for cand in suffixes(fqdn):
            if self._call('GET', '/api/dns/v1/zones/' + urllib.parse.quote(cand),
                          missing_ok=True) is not None:
                return cand
        raise PluginError('Hostinger has no DNS zone for %s that this token may see - set the '
                          'domain' % D.norm(fqdn), retry=False)

    def _path(self, zone):
        return '/api/dns/v1/zones/' + urllib.parse.quote(D.norm(zone))

    def _rrset(self, zone, name):
        """(ttl, [record contents as written]) of the TXT RRset at name."""
        for rs in self._call('GET', self._path(zone)) or []:
            if isinstance(rs, dict) and str(rs.get('type')).upper() == 'TXT' and \
                    (rs.get('name') or '@') == name:
                return rs.get('ttl'), [r.get('content') for r in rs.get('records') or []
                                       if isinstance(r, dict) and r.get('content') is not None]
        return None, []

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        name = relative(fqdn, zone)
        with rmw_lock('hostinger'):
            _ttl, have = self._rrset(zone, name)
            if value not in [unquote_txt(v) for v in have]:
                self._call('PUT', self._path(zone), {'overwrite': False, 'zone': [{
                    'name': name, 'type': 'TXT', 'ttl': self.ttl(),
                    'records': [{'content': value}]}]})
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        name = relative(fqdn, zone)
        with rmw_lock('hostinger'):
            ttl, have = self._rrset(zone, name)
            left = [v for v in have if unquote_txt(v) != value]
            if len(left) == len(have):
                return                                  # gone already
            if left:
                self._call('PUT', self._path(zone), {'overwrite': True, 'zone': [{
                    'name': name, 'type': 'TXT', 'ttl': ttl or self.ttl(),
                    'records': [{'content': v} for v in left]}]})
            else:
                self._call('DELETE', self._path(zone),
                           {'filters': [{'name': name, 'type': 'TXT'}]}, missing_ok=True)

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            got = self._call('GET', self._path(z)) or []
            return 'Hostinger: signed in; the zone %s has %d record set(s)' % (z, len(got))
        return ApiDns.test(self)
