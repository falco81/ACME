# -*- coding: utf-8 -*-
"""DNS-01 at CZECHIA.COM (ZONER's registrar and DNS), through its REST API -
as its own description says it (https://api.czechia.com/swagger/v1/swagger.json,
"Zoner REST API Documentation" v1, OpenAPI 3.0.1; 1.0.24):

    GET    /api/DNS/{domain}        the zone: {txtRecords: [{hostName, text, ttl}], ...}
    POST   /api/DNS/{domain}/TXT    {hostName, text, ttl, publishZone: 1}   200
    DELETE /api/DNS/{domain}/TXT    {hostName, text, ttl, publishZone: 1}   200: that value away
    GET    /api/Domains             [{seviceId, name, ...}] - the domains of the account

Header authorizationToken: <token> (the CZECHIA.COM administration → account →
REST API token). Each value is a record of its own and is removed by its value,
so other orders' values stay; "publishZone": 1 makes the change live at once.
A TTL is 120 to 172800 seconds.

The token can be of two kinds (napoveda.czechia.com, "Aktivace REST API"):
"ACME" - only the TXT records of DNS, from anywhere - or full access, from the
addresses allowed. With an ACME token the list of domains may be refused: the
zone is then found by its SOA (or set), never guessed from that list.

Sources: the API's own description above (swagger.json, sent by the user from
api.czechia.com/swagger/index.html) and napoveda.czechia.com/clanek/aktivace-rest-api/.
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, DnsChallenge, api,
                                                unquote_txt)
from acmelib.plugins.challenges._records import rel_name

API = 'https://api.czechia.com/api'


class Czechia(ApiDns):
    kind = 'czechia'
    title = 'CZECHIA.COM (ZONER)'
    vendor = 'CZECHIA.COM'
    who = 'CZECHIA.COM'
    min_ttl = 120                   # the API takes 120-172800 s
    description = 'TXT records in a domain at CZECHIA.COM (ZONER), with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='The CZECHIA.COM administration → your account → REST API token: an "ACME" '
                   'token (only the TXT records of DNS, from any address) is enough.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.cz',
              help='Empty: found by its SOA.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='120 to 172800 seconds.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def zone_names(self):
        return None

    def zone_hint(self, fqdn):
        return DnsChallenge.zone_hint(self, fqdn)       # the zone set, else its SOA

    def _base(self):
        return str(self.c('api') or API).rstrip('/')

    def _head(self):
        return {'AuthorizationToken': str(self.c('token', ''))}

    def _records(self, zone):
        """[{hostName, text, ttl}] of the zone's TXT records, or None when it cannot be
        read (then each change is made as asked, as before 1.0.24)."""
        try:
            st, got = api(self.ctx, 'GET', '%s/DNS/%s' % (self._base(), D.norm(zone)), None,
                          self._head(), who='CZECHIA.COM', missing_ok=True)
        except PluginError as e:
            self.ctx.step('CZECHIA.COM: the records of %s could not be read (%s) - changed '
                          'as asked' % (zone, e), 'warn')
            return None
        if st == 404 or not isinstance(got, dict):
            return None
        recs = got.get('txtRecords') or got.get('TxtRecords') or []
        return [r for r in recs if isinstance(r, dict)]

    def _same(self, rec, host, value):
        return str(rec.get('hostName') or '@').lower() in (host.lower(), host.lower() + '.') and \
            unquote_txt(rec.get('text')) == value

    def _call(self, method, zone, fqdn, value, ttl=None):
        body = {'hostName': rel_name(fqdn, zone), 'text': value, 'ttl': int(ttl or self.ttl()),
                'publishZone': 1}
        try:
            st, got = api(self.ctx, method, '%s/DNS/%s/TXT' % (self._base(), D.norm(zone)), body,
                          self._head(), who='CZECHIA.COM')
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
        host = rel_name(fqdn, zone)
        have = self._records(zone)
        if have is not None and any(self._same(r, host, value) for r in have):
            self.ctx.step('CZECHIA.COM: %s holds this value already' % fqdn)
            return {'zone': zone}
        self._call('POST', zone, fqdn, value)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        host = rel_name(fqdn, zone)
        have = self._records(zone)
        if have is not None:
            mine = [r for r in have if self._same(r, host, value)]
            if not mine:
                return                                  # gone already
            self._call('DELETE', zone, fqdn, value, mine[0].get('ttl'))
            return
        self._call('DELETE', zone, fqdn, value)

    def test(self):
        if not str(self.c('token', '') or '').strip():
            raise PluginError('no API token is set', retry=False)
        z = D.norm(self.c('zone', ''))
        if z:
            st, got = api(self.ctx, 'GET', '%s/DNS/%s' % (self._base(), z), None, self._head(),
                          who='CZECHIA.COM', missing_ok=True)
            if st == 404:
                raise PluginError('CZECHIA.COM has no DNS zone %s for this token' % z,
                                  retry=False)
            n = len((got or {}).get('txtRecords') or []) if isinstance(got, dict) else 0
            return 'CZECHIA.COM: the token reads the zone %s (%d TXT record(s))' % (z, n)
        try:
            st, got = api(self.ctx, 'GET', '%s/Domains' % self._base(), None, self._head(),
                          who='CZECHIA.COM')
        except PluginError as e:
            if any(c in str(e) for c in ('401', '403')):
                return ('CZECHIA.COM: the token may not list the domains (an ACME token only '
                        'writes TXT records) - set the domain and Test reads its zone')
            raise
        names = [D.norm(d.get('name')) for d in (got or []) if isinstance(d, dict) and
                 d.get('name')] if isinstance(got, list) else []
        return 'CZECHIA.COM: the token sees %d domain(s)%s' % (
            len(names), (': ' + ', '.join(names[:8])) if names else '')
