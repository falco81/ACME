# -*- coding: utf-8 -*-
"""DNS-01 at Active24 (active24.cz, of the Websupport group), through its
REST API v2 (https://rest.active24.cz):

    GET    /v1/user/self/service                       the services: [{id, serviceName, name}]
                                                       (a domain is serviceName "domain")
    GET    /v2/service/{id}/dns/record?filters[type][]=TXT&filters[name]={sub}
                                                       {data: [{id, type, name, content}]}
    POST   /v2/service/{id}/dns/record  {type, name, content, ttl}
    DELETE /v2/service/{id}/dns/record/{record id}

signed as Websupport signs (websupport.py: HMAC-SHA1 over "METHOD PATH
UNIXTIME", basic authentication KEY:SIGNATURE), with a Date header of that
time in RFC 3339 (2025-01-31T12:00:00Z; until 1.0.22 the basic ISO 8601 form
of API v1 was sent).

Checked again (1.0.22) against lego's providers/dns/internal/active24 (the
client lego's active24 and websupport providers share, written to
https://rest.active24.cz/v2/docs): the same paths, filters[name] and
filters[type][], record fields and service list (/v1/user/self/service,
{items: [{id, serviceName, name}]}).

How sure this is: Active24 moved its customers to the Websupport platform
in 2023-2024 and documents this v2 API at rest.active24.cz; the signature
and the record calls are written as documented there. The list of services
(which id is which domain) is the least certain part: when it does not
find the domain, set its service ID (the number in the address of the
domain's page in the administration) and it is not asked.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, no_zone,
                                                relative, unquote_txt)
from acmelib.plugins.challenges.websupport import ws_headers

API = 'https://rest.active24.cz'
V2_DATE = '%Y-%m-%dT%H:%M:%SZ'      # the Date header, RFC 3339 (as lego's v2 client sends it)


class Active24(ApiDns):
    kind = 'active24'
    title = 'Active24'
    vendor = 'Active24'
    who = 'Active24'
    description = 'TXT records in a domain at Active24, through its REST API v2.'
    fields = [
        field('api_key', 'API key', 'text', required=True,
              help='The Active24 administration → (your name) → Security and login → API '
                   'access → Generate new access: the identifier here, the secret below.'),
        field('api_secret', 'API secret', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.cz',
              help='Empty: the longest domain of the account the name is in.'),
        field('service_id', 'Service ID', 'text', default='', advanced=True,
              help='The domain\'s service number in the administration. Empty: found in the '
                   'list of services.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False, now=None):
        h = ws_headers(str(self.c('api_key', '')), str(self.c('api_secret', '')), method, path,
                       now, date_format=V2_DATE)
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body, h,
                      who='Active24', missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _services(self):
        if getattr(self, '_ids', None) is None:
            got = self._call('GET', '/v1/user/self/service') or []
            if isinstance(got, dict):
                got = got.get('items') or got.get('data') or []
            self._ids = {D.norm(s.get('name')): s.get('id') for s in got
                         if isinstance(s, dict) and s.get('name') and
                         s.get('serviceName', 'domain') == 'domain'}
        return self._ids

    def zone_names(self):
        return list(self._services())

    def zone_hint(self, fqdn):
        if self.c('service_id') and not self.c('zone'):
            return None                         # the zone by its SOA
        return ApiDns.zone_hint(self, fqdn)

    def _sid(self, zone):
        if self.c('service_id'):
            return str(self.c('service_id'))
        sid = self._services().get(zone)
        if not sid:
            raise no_zone('Active24', zone)
        return sid

    def _ours(self, sid, rel, value):
        got = self._call('GET', '/v2/service/%s/dns/record?%s' % (sid, urllib.parse.urlencode(
            [('filters[type][]', 'TXT'), ('filters[name]', rel)]))) or {}
        return [r['id'] for r in got.get('data') or []
                if r.get('type') == 'TXT' and (r.get('name') or '@') == rel and
                unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        sid, rel = self._sid(zone), relative(fqdn, zone)
        have = self._ours(sid, rel, value)
        if have:
            return {'sid': sid, 'id': have[0]}
        got = self._call('POST', '/v2/service/%s/dns/record' % sid, {
            'type': 'TXT', 'name': rel, 'content': value, 'ttl': self.ttl()}) or {}
        return {'sid': sid, 'id': got.get('id') if isinstance(got, dict) else None}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = self.zone_for(fqdn)
        sid = h.get('sid') or self._sid(zone)
        ids = [h['id']] if h.get('id') else self._ours(sid, relative(fqdn, zone), value)
        for rid in ids:
            self._call('DELETE', '/v2/service/%s/dns/record/%s' % (sid, rid), missing_ok=True)

    def test(self):
        if self.c('service_id'):
            self._call('GET', '/v2/service/%s/dns/record?filters[type][]=TXT' % self.c(
                'service_id'))
            return 'Active24: signed in; the service %s answers' % self.c('service_id')
        return ApiDns.test(self)

