# -*- coding: utf-8 -*-
"""DNS-01 at Domeneshop (Norway), through its API v0:

    GET    https://api.domeneshop.no/v0/domains                       [{id, domain, services: {dns}}]
    GET    .../domains/{id}/dns?host={host}&type=TXT                  [{id, host, type, data, ttl}]
    POST   .../domains/{id}/dns     {host, type: "TXT", data, ttl}    {id}
    DELETE .../domains/{id}/dns/{record id}

Basic authentication with the API token and secret. "host" is relative to
the domain, "@" the apex. Domeneshop takes no TTL under 60.

Sources: https://api.domeneshop.no/docs/ - not reachable from where this was
written; as lego's providers/dns/domeneshop and Posh-ACME's Domeneshop
plugin send it.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, basic, rel_name

API = 'https://api.domeneshop.no/v0'


class Domeneshop(RecordApiDns):
    kind = 'domeneshop'
    title = 'Domeneshop'
    vendor = 'Domeneshop'
    who = 'Domeneshop'
    min_ttl = 60
    description = 'TXT records in a domain at Domeneshop, with an API token and secret.'
    fields = [
        field('token', 'API token', 'text', required=True,
              help='domene.shop → My page → API access (https://domene.shop/admin?view=api): '
                   'make new API credentials.'),
        field('secret', 'API secret', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.no',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        _st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                       {'Authorization': basic(self.c('token', ''), self.c('secret', ''))},
                       who='Domeneshop', missing_ok=missing_ok)
        return got

    def _domains(self):
        if getattr(self, '_doms', None) is None:
            self._doms = {D.norm(d.get('domain')): d.get('id')
                          for d in self._call('GET', '/domains') or [] if isinstance(d, dict)}
        return self._doms

    def zone_names(self):
        return list(self._domains())

    def _id(self, zone):
        did = self._domains().get(D.norm(zone))
        if did is None:
            raise PluginError('Domeneshop has no domain %s on this account' % zone, retry=False)
        return did

    def txt_records(self, zone, fqdn):
        host = rel_name(fqdn, zone)
        got = self._call('GET', '/domains/%s/dns?%s' % (self._id(zone), urllib.parse.urlencode(
            {'host': host, 'type': 'TXT'}))) or []
        return [(r.get('id'), r.get('data')) for r in got if isinstance(r, dict) and
                str(r.get('type')).upper() == 'TXT' and r.get('host') == host]

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/domains/%s/dns' % self._id(zone), {
            'host': rel_name(fqdn, zone), 'type': 'TXT', 'data': value, 'ttl': self.ttl()}) or {}
        return got.get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/domains/%s/dns/%s' % (self._id(zone), record_id), missing_ok=True)
