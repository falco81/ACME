# -*- coding: utf-8 -*-
"""DNS-01 in the DNS of a froxlor server, through the froxlor API (1.0.27) -
every call a POST of JSON to api.php:

    POST https://{froxlor}/api.php  {"command": "...", "params": {...}}
         Domains.listing / SubDomains.listing        {data: {count, list: [{domain,
                                                      parentdomainid, isbinddomain, ...}]}}
         DomainZones.listing {domainname}            {data: {count, list: [{id, record,
                                                      type, content, ttl}]}}
         DomainZones.add {domainname, record, type: TXT, content, ttl}
         DomainZones.delete {domainname, entry_id}

HTTP basic authentication with an API key and its secret (made in froxlor
under the user's API keys; the external API must be allowed in the system
settings). An admin key lists the domains with Domains.listing, a customer's
with SubDomains.listing - acme asks the first and falls back to the second.
A zone is a main domain (parentdomainid 0) with DNS on (isbinddomain).

Each value is an entry of its own with its id: DomainZones.add answers the
whole zone file, not the new id, so the entries are listed and ours found by
its record + type + content; cleanup deletes only those ids (a 304 there is an
entry gone already). The record is relative to the zone (at most 63
characters), the value without quotes (froxlor adds them for BIND and leaves
them away for PowerDNS). froxlor writes the zone through its cron
(REBUILD_DNS), so the record reaches the name servers only after the next
cron run: acme waits until every name server has it.

froxlor's documentation and its code differ (the code is taken): an error's
words come in "message" (the documentation says "status_message" - both are
read); DomainZones.* take "domainname" (used here) or the domain's "id".

Sources (the user's collection, api-docs/froxlor/notes.md):
https://docs.froxlor.org/latest/api-guide/ (enabling, keys, the request, the
answer), https://docs.froxlor.org/latest/api-guide/commands/domainzones.html
and froxlor 2.3.16's source (lib/Froxlor/Api/FroxlorRPC.php, Response.php,
Commands/DomainZones.php - the checks, the 304, the record label; Dns.php -
the TXT quotes; doc/example/list_functions.php - "message").

Less certain: the fields of a Domains.listing / SubDomains.listing entry
(parentdomainid and isbinddomain are read where present, else every domain
listed is taken); no lowest TTL is documented (0 or less becomes 18000 - 60 is
sent); how long until the cron writes the zone (not documented).
"""
from __future__ import annotations

import json

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, as_bool, http_call,
                                                relative)
from acmelib.plugins.challenges._records import RecordApiDns, SoftZones, basic, zone_field


class Froxlor(SoftZones, RecordApiDns):
    kind = 'froxlor'
    title = 'froxlor'
    vendor = 'froxlor'
    who = 'froxlor'
    min_ttl = 1
    description = 'TXT records in the DNS zones of a froxlor server, through the froxlor API.'
    fields = [
        field('url', 'froxlor address', 'text', required=True, placeholder='froxlor.example.com',
              help='The froxlor panel (name or https://…/); acme calls api.php there.'),
        field('api_key', 'API key', 'text', required=True,
              help='froxlor → (your name) → API keys → Create: the key here, its secret below. '
                   'Settings → System settings → "Enable external API usage" must be on; '
                   'limit the key to acme\'s address where offered.'),
        field('api_secret', 'API secret', 'secret', required=True),
        zone_field(['url', 'api_key', 'api_secret']),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _url(self):
        h = str(self.c('url', '') or '').strip()
        if not h:
            raise PluginError('the froxlor address is not set', retry=False)
        if '://' not in h:
            h = 'https://' + h
        h = h.rstrip('/')
        return h if h.endswith('/api.php') else h + '/api.php'

    def _call(self, command, params=None, ok=(200,)):
        """(status, data) of one API command; an error said with froxlor's words."""
        body = json.dumps({'command': command, 'params': params or {}}).encode()
        st, _rh, got = http_call(self.ctx, 'POST', self._url(), body, {
            'Authorization': basic(self.c('api_key', ''), self.c('api_secret', '')),
            'Content-Type': 'application/json', 'Accept': 'application/json',
            'User-Agent': 'acme-challenge'}, who='froxlor',
            verify=as_bool(self.c('verify_tls', True)))
        parsed = None
        try:
            parsed = json.loads(got.decode('utf-8') if isinstance(got, bytes) else got)
        except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
            pass
        if st not in ok:
            words = ''
            if isinstance(parsed, dict):
                words = str(parsed.get('message') or parsed.get('status_message') or '')
            words = words or (got or b'')[:300].decode('utf-8', 'replace')
            extra = ' - the key or secret is wrong, or the API is not enabled' \
                if st in (401, 403) else ''
            raise PluginError('froxlor said %s to %s: %s%s' % (st, command, words.strip() or
                                                              'nothing more', extra),
                              detail=words, retry=st >= 500 or st == 429)
        return st, (parsed.get('data') if isinstance(parsed, dict) else None)

    # -- zones and records ----------------------------------------------------------
    def zone_names(self):
        last = None
        for command in ('Domains.listing', 'SubDomains.listing'):
            try:
                _st, data = self._call(command)
            except PluginError as e:
                last = e
                continue
            out = []
            for d in (data or {}).get('list') or []:
                if not isinstance(d, dict) or not d.get('domain'):
                    continue
                if str(d.get('parentdomainid', '0')) not in ('0', '', 'None'):
                    continue
                if 'isbinddomain' in d and str(d.get('isbinddomain')) not in ('1', 'True'):
                    continue
                out.append(D.norm(d['domain']))
            return out
        raise last

    def txt_records(self, zone, fqdn):
        rel = relative(fqdn, zone).lower()
        rel = '' if rel == '@' else rel
        _st, data = self._call('DomainZones.listing', {'domainname': D.norm(zone)})
        out = []
        for r in (data or {}).get('list') or []:
            if isinstance(r, dict) and str(r.get('type') or '').upper() == 'TXT' and \
                    str(r.get('record') or '').strip().lower() in (rel, '@' if not rel else rel) \
                    and r.get('id') is not None:
                out.append((r.get('id'), str(r.get('content') or '')))
        return out

    def create_txt(self, zone, fqdn, value):
        rel = relative(fqdn, zone)
        rel = '' if rel == '@' else rel
        if len(rel) > 63:
            raise PluginError('froxlor takes a record of at most 63 characters - %s is longer '
                              '(set a deeper zone, or point it by a CNAME)' % rel, retry=False)
        self._call('DomainZones.add', {'domainname': D.norm(zone), 'record': rel, 'type': 'TXT',
                                       'content': value, 'ttl': self.ttl()})
        return None                     # froxlor answers the zone file: found by its value

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DomainZones.delete', {'domainname': D.norm(zone), 'entry_id': int(record_id)},
                   ok=(200, 304))

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            _st, data = self._call('DomainZones.listing', {'domainname': z})
            return 'froxlor: signed in; the zone %s has %d entries of its own' % (
                z, int((data or {}).get('count') or len((data or {}).get('list') or [])))
        return RecordApiDns.test(self)
