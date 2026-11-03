# -*- coding: utf-8 -*-
"""DNS-01 at easyDNS, through its REST API:

    GET    https://rest.easydns.net/zones/records/all/{domain}?format=json      {data: [{id, domain, host, type, rdata, ttl}]}
    PUT    .../zones/records/add/{domain}/TXT?format=json  {domain, host, ttl, prio, type, rdata}
    DELETE .../zones/records/{domain}/{id}?format=json
    GET    .../domains/list/{user}?format=json                         (Test only, with a user name)

Basic authentication: the API token and the API key. "host" is relative to
the domain, "@" the apex. Each value is a record of its own: ours is added,
cleanup deletes only the records holding ours. easyDNS takes TTLs of 300 to
86400. The API has no list of domains acme reads without the user name, so
the domain is the one set or found by its SOA. The sandbox is
https://sandbox.rest.easydns.net.

Sources: easyDNS's own MCP server for its REST API
(https://github.com/easydns/easydns-mcp: docs/API-REFERENCE.md; src/auth.ts -
the two addresses and the Basic header; src/client.ts - ?format=json;
src/tools/dns-records-list.ts, dns-record-add.ts, dns-record-delete.ts,
domain-list.ts). The reference is https://docs.sandbox.rest.easydns.net.
Cross-checked with lego's providers/dns/easydns (the record fields).
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, api
from acmelib.plugins.challenges._records import RecordApiDns, basic, rel_name

API = 'https://rest.easydns.net'
SANDBOX = 'https://sandbox.rest.easydns.net'


class EasyDns(RecordApiDns):
    kind = 'easydns'
    discovery = False               # discovery: nothing to read from an account
    title = 'easyDNS'
    vendor = 'easyDNS'
    who = 'easyDNS'
    min_ttl = 300
    description = 'TXT records in a domain at easyDNS, with an API token and key.'
    fields = [
        field('token', 'API token', 'text', required=True,
              help='The API token and API key from the easyDNS control panel: the token here, '
                   'the key below.'),
        field('key', 'API key', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: found by its SOA (the API lists domains only by user name).'),
        field('user', 'User name', 'text', default='', advanced=True,
              help='The easyDNS user name: Test then lists its domains. Empty: Test reads the '
                   'domain set.'),
        field('endpoint', 'API', 'select', default='live',
              options=[['live', 'easyDNS (rest.easydns.net)'],
                       ['sandbox', 'the sandbox (sandbox.rest.easydns.net)']], advanced=True),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='easyDNS takes 300 to 86400.'),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        base = SANDBOX if self.c('endpoint', 'live') == 'sandbox' else API
        st, got = api(self.ctx, method, base + path + '?format=json', body,
                      {'Authorization': basic(self.c('token', ''), self.c('key', ''))},
                      who='easyDNS', missing_ok=missing_ok)
        if isinstance(got, dict) and isinstance(got.get('error'), dict):
            raise PluginError('easyDNS said no: %s' % (got['error'].get('message') or got),
                              detail=str(got), retry=False)
        return None if st == 404 and missing_ok else (got if isinstance(got, dict) else {})

    def zone_names(self):
        return None

    def zone_hint(self, fqdn):
        return DnsChallenge.zone_hint(self, fqdn)       # the domain set, else its SOA

    def ttl(self):
        return min(RecordApiDns.ttl(self), 86400)

    def txt_records(self, zone, fqdn):
        host = rel_name(fqdn, zone)
        got = self._call('GET', '/zones/records/all/' + urllib.parse.quote(D.norm(zone)),
                         missing_ok=True) or {}
        return [(r.get('id'), r.get('rdata')) for r in got.get('data') or []
                if isinstance(r, dict) and str(r.get('type')).upper() == 'TXT' and
                (r.get('host') or '@') in (host, D.norm(fqdn), D.norm(fqdn) + '.')]

    def create_txt(self, zone, fqdn, value):
        z = D.norm(zone)
        got = self._call('PUT', '/zones/records/add/%s/TXT' % urllib.parse.quote(z), {
            'domain': z, 'host': rel_name(fqdn, zone), 'ttl': self.ttl(), 'prio': 0,
            'type': 'TXT', 'rdata': value})
        data = got.get('data')
        return data.get('id') if isinstance(data, dict) else None

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/zones/records/%s/%s' % (urllib.parse.quote(D.norm(zone)),
                                                       record_id), missing_ok=True)

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            got = self._call('GET', '/zones/records/all/' + urllib.parse.quote(z)) or {}
            return 'easyDNS: signed in; the domain %s has %d record(s)' % (
                z, len(got.get('data') or []))
        user = str(self.c('user', '') or '').strip()
        if user:
            self._call('GET', '/domains/list/' + urllib.parse.quote(user))
            return 'easyDNS: signed in as %s; the domain of each name is found by its SOA' % user
        raise PluginError('easyDNS: set the domain (or the user name) for Test to have '
                          'something to read', retry=False)
