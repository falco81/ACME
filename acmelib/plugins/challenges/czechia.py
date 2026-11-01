# -*- coding: utf-8 -*-
"""DNS-01 at CZECHIA.COM (ZONER's registrar and DNS), through its REST API:

    POST   https://api.czechia.com/api/DNS/{zone}/TXT   {hostName, text, ttl, publishZone: 1}
    DELETE https://api.czechia.com/api/DNS/{zone}/TXT   the same body: that one value away

Header AuthorizationToken: <token> (made in the CZECHIA.COM administration).
Each value is a record of its own and is removed by its value, so other
orders' values stay. "publishZone": 1 makes the change live at once.

Sources: https://api.czechia.com/swagger/index.html (the API's own
description; it could not be fetched from where this was written - the calls
are as lego's providers/dns/czechia and acme.sh's dnsapi/dns_czechia.sh send
them). Less certain: the API has no call acme knows to list the zones or the
records, so the zone is found by its SOA (or set), test() can only check
that a zone is there by DNS, and a value already there is taken from the
answer "already exists". A dry run is the real test.
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ApiDns, DnsChallenge, api
from acmelib.plugins.challenges._records import rel_name

API = 'https://api.czechia.com/api'


class Czechia(ApiDns):
    kind = 'czechia'
    title = 'CZECHIA.COM (ZONER)'
    vendor = 'CZECHIA.COM'
    who = 'CZECHIA.COM'
    min_ttl = 60
    guide_needs_dry_run = True
    description = 'TXT records in a domain at CZECHIA.COM (ZONER), with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='The CZECHIA.COM administration → API: the authorization token of the '
                   'account.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.cz',
              help='Empty: found by its SOA (the API cannot list the domains).'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def zone_names(self):
        return None

    def zone_hint(self, fqdn):
        return DnsChallenge.zone_hint(self, fqdn)       # the zone set, else its SOA

    def _call(self, method, zone, fqdn, value):
        body = {'hostName': rel_name(fqdn, zone), 'text': value, 'ttl': self.ttl(),
                'publishZone': 1}
        try:
            st, got = api(self.ctx, method, '%s/DNS/%s/TXT' % (
                str(self.c('api', API)).rstrip('/'), D.norm(zone)), body,
                {'AuthorizationToken': str(self.c('token', ''))}, who='CZECHIA.COM')
        except PluginError as e:
            if method == 'POST' and 'already exists' in str(e):
                return None
            if method == 'DELETE' and ('404' in str(e) or 'not found' in str(e).lower()):
                return None
            raise
        if isinstance(got, dict) and (got.get('isError') or got.get('errors')):
            if method == 'POST' and 'already exists' in str(got):
                return None
            raise PluginError('CZECHIA.COM said no: %s' % (got.get('message') or got.get(
                'errors') or got), detail=got)
        return got

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        self._call('POST', zone, fqdn, value)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        self._call('DELETE', zone, fqdn, value)

    def test(self):
        if not str(self.c('token', '') or '').strip():
            raise PluginError('no API token is set', retry=False)
        z = D.norm(self.c('zone', ''))
        return ('CZECHIA.COM: a token is set%s; the API has no call that only reads, so a dry '
                'run is what tries it' % ((' for the domain %s' % z) if z else ''))
