# -*- coding: utf-8 -*-
"""DNS-01 at Forpsi F-DNS (INTERNET CZ's paid "DNS as a service", DNSaaS),
through its REST API (1.0.27):

    GET    https://api.forpsi.com/dnsaas/v1/                     {service_renew_date,
                                                                  domains_allowed, domains_used}
    GET    .../domains?skip=&limit=                               {domains: [{name}], total_count,
                                                                  next_page}
    GET    .../domains/{domain}/records?skip=&limit=              {dnsrecords: [{id, name, type,
                                                                  data, ttl}], next_page}
    POST   .../domains/{domain}/records  {name, type: TXT, data, ttl}   the record, with its id
    DELETE .../domains/{domain}/records/{id}                     {msg}

Header "token: <TOKEN>" (not Authorization) - a token from admin.forpsi.com,
"you must have DNSaaS service active". Each value is a record of its own with
its id: cleanup deletes only ours; a 404 there is a record gone already. The
records cannot be filtered by name or type: the zone is read page by page
(1000 a page) and ours picked out. TTL 60 to 86400, data at most 255
characters, no publish step.

Only F-DNS has this API. Forpsi's ordinary DNS - the free DNS hosting with a
domain or a web hosting - has none (only its web administration and a CSV
import): for names there, delegate _acme-challenge by a CNAME to a zone acme
can write (acme's own DNS, acme-dns, or a provider with an API).

Sources (the user's collection, api-docs/forpsi/): openapi.json (OpenAPI
3.1.0, from https://api.forpsi.com/dnsaas/v1/docs/ - the paths, DNSRecord,
DomainsList, DNSRecordsList, the token security scheme) and notes.md, quoting
https://www.forpsi.com/ForpsiCZ/media/Forpsi/Documents/tc-files/ICZ_podminky_DNS.pdf
(art. IV: the API only for the service "c." - the business solution),
https://www.forpsi.com/f-dns/ and https://support.forpsi.com/kb/a4408/importing-dns-records.aspx
(TTL 60 - 86400).

Less certain: whether "name" is relative to the domain (the specification's
example is "subdomain"; it is written relative, and a listed name is read
relative or whole); the apex ("@" is written, "" and "@" read); whether a TXT
"data" goes with quotes (nothing said - sent as it is, a listed one compared
without them); the error answers beyond {"msg": "Invalid token"}; how soon a
change reaches the name servers (acme asks them).
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api, relative
from acmelib.plugins.challenges._records import RecordApiDns, SoftZones, rel_name, zone_field

API = 'https://api.forpsi.com/dnsaas/v1'
PAGE = 1000                 # the largest "limit" the specification allows
PAGES = 50


class Forpsi(SoftZones, RecordApiDns):
    kind = 'forpsi'
    title = 'Forpsi F-DNS (DNSaaS)'
    vendor = 'Forpsi'
    who = 'Forpsi F-DNS'
    min_ttl = 60
    description = ('TXT records in Forpsi F-DNS, the paid DNS-as-a-service, through its API. '
                   'Ordinary Forpsi DNS (with a domain or web hosting) has no API.')
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='admin.forpsi.com, with the F-DNS (DNSaaS) service active. Ordinary Forpsi '
                   'DNS hosting has no API: for such a domain point _acme-challenge by a CNAME '
                   'to a zone acme can write instead.'),
        zone_field(['token']),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='F-DNS takes 60 to 86400.'),
    ] + PROPAGATION_FIELDS

    def ttl(self):
        return min(RecordApiDns.ttl(self), 86400)

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, API + path, body, {'token': str(self.c('token', ''))},
                      who='Forpsi F-DNS', missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _pages(self, path, key):
        out, skip = [], 0
        for _page in range(PAGES):
            got = self._call('GET', '%s%sskip=%d&limit=%d' % (path, '&' if '?' in path else '?',
                                                              skip, PAGE)) or {}
            items = [x for x in got.get(key) or [] if isinstance(x, dict)]
            out += items
            if not got.get('next_page') or len(items) < PAGE:
                break
            skip += PAGE
        return out

    # -- zones and records ----------------------------------------------------------
    def zone_names(self):
        return [d.get('name') for d in self._pages('/domains', 'domains') if d.get('name')]

    def txt_records(self, zone, fqdn):
        rel = relative(fqdn, zone).lower()
        out = []
        for r in self._pages('/domains/%s/records' % urllib.parse.quote(D.norm(zone)),
                             'dnsrecords'):
            name = D.norm(r.get('name') or '')
            if str(r.get('type') or '').upper() == 'TXT' and r.get('id') is not None and (
                    name == rel or name == D.norm(fqdn) or (rel == '@' and name in ('', '@'))):
                out.append((r.get('id'), str(r.get('data') or '')))
        return out

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/domains/%s/records' % urllib.parse.quote(D.norm(zone)), {
            'name': rel_name(fqdn, zone), 'type': 'TXT', 'data': value, 'ttl': self.ttl()})
        return (got or {}).get('id') if isinstance(got, dict) else None

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/domains/%s/records/%s' % (
            urllib.parse.quote(D.norm(zone)), urllib.parse.quote(str(record_id))), missing_ok=True)

    def test(self):
        info = self._call('GET', '/') or {}
        if not isinstance(info, dict):
            raise PluginError('Forpsi F-DNS answered something that is not its API', retry=False)
        z = D.norm(self.c('zone', ''))
        if z:
            n = len(self._pages('/domains/%s/records' % urllib.parse.quote(z), 'dnsrecords'))
            return 'Forpsi F-DNS: signed in; the domain %s has %d record(s)' % (z, n)
        return '%s (F-DNS: %s of %s domains used)' % (
            RecordApiDns.test(self), info.get('domains_used', '?'),
            info.get('domains_allowed', '?'))
