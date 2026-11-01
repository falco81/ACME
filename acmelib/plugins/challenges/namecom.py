# -*- coding: utf-8 -*-
"""DNS-01 at Name.com, through its API v4:

    GET    https://api.name.com/v4/domains                              {domains: [{domainName}], nextPage}
    GET    .../v4/domains/{domain}/records                              {records: [{id, host, fqdn, type, answer, ttl}], nextPage}
    POST   .../v4/domains/{domain}/records  {host, type: "TXT", answer, ttl}   {id, ...}
    DELETE .../v4/domains/{domain}/records/{id}

Basic authentication: the user name and an API token. "host" is relative to
the domain ("" the apex); "fqdn" ends in a dot. Name.com takes no TTL under
300.

Sources: https://www.name.com/api-docs/DNS (ListRecords, CreateRecord,
DeleteRecord) and https://www.name.com/api-docs/Domains - not reachable from
where this was written; as Posh-ACME's NameCom plugin and lego's
providers/dns/namedotcom (the namecom library) call them. Less certain:
Name.com announced a newer "Core API"; when v4 is retired, set its address
under API address (the calls may then differ). The test API is
https://api.dev.name.com/v4 (a user name ending in "-test").
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, basic, rel_name

API = 'https://api.name.com/v4'


class NameCom(RecordApiDns):
    kind = 'namecom'
    title = 'Name.com'
    vendor = 'Name.com'
    who = 'Name.com'
    min_ttl = 300
    description = 'TXT records in a domain at Name.com, with a user name and an API token.'
    fields = [
        field('user', 'User name', 'text', required=True,
              help='name.com → Account → Settings → Security → API access: turn it on and make a '
                   'production token; the user name is the account\'s.'),
        field('token', 'API token', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='Name.com takes 300 or more.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        _st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                       {'Authorization': basic(self.c('user', ''), self.c('token', ''))},
                       who='Name.com', missing_ok=missing_ok)
        return got or {}

    def _all(self, path, key):
        out, page = [], 1
        while page and page < 50:
            got = self._call('GET', '%s?page=%d&perPage=1000' % (path, page))
            out += got.get(key) or []
            page = got.get('nextPage') or 0
        return out

    def zone_names(self):
        return [d.get('domainName') for d in self._all('/domains', 'domains')]

    def txt_records(self, zone, fqdn):
        host = rel_name(fqdn, zone, apex='')
        return [(r.get('id'), r.get('answer')) for r in
                self._all('/domains/%s/records' % urllib.parse.quote(zone), 'records')
                if str(r.get('type')).upper() == 'TXT' and
                (D.norm(r.get('fqdn') or '') == fqdn or (r.get('host') or '') == host)]

    def create_txt(self, zone, fqdn, value):
        return self._call('POST', '/domains/%s/records' % urllib.parse.quote(zone), {
            'host': rel_name(fqdn, zone, apex=''), 'type': 'TXT', 'answer': value,
            'ttl': self.ttl()}).get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/domains/%s/records/%s' % (urllib.parse.quote(zone), record_id),
                   missing_ok=True)
