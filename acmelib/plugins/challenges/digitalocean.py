# -*- coding: utf-8 -*-
"""DNS-01 through DigitalOcean's API (Networking → Domains)."""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, api,
                                                relative)

BASE = 'https://api.digitalocean.com/v2'


class DigitalOcean(DnsChallenge):
    kind = 'digitalocean'
    api_provider = True             # its zones are asked of its API (guide)
    title = 'DigitalOcean'
    vendor = 'DigitalOcean'
    description = 'TXT records in a DigitalOcean domain, with a personal access token.'
    fields = [
        field('token', 'Personal access token', 'secret', required=True,
              help='API → Tokens: with the scopes domain:read, domain:create, domain:delete '
                   '(or Write).'),
        field('zone', 'Domain', 'text', default='', help='Empty: found by the name.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='DigitalOcean takes 30 or more.'),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        return api(self.ctx, method, BASE + path, body,
                   {'Authorization': 'Bearer ' + str(self.c('token', ''))},
                   who='DigitalOcean', missing_ok=missing_ok)

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        labels = D.norm(fqdn).split('.')
        for i in range(len(labels) - 1):
            cand = '.'.join(labels[i:])
            st, _got = self._call('GET', '/domains/' + urllib.parse.quote(cand), missing_ok=True)
            if st == 200:
                return cand
        raise PluginError('DigitalOcean has no domain for %s that this token may see' % fqdn,
                          retry=False)

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        _st, got = self._call('POST', '/domains/%s/records' % urllib.parse.quote(zone),
                              {'type': 'TXT', 'name': relative(fqdn, zone), 'data': value,
                               'ttl': max(30, self.ttl())})
        return {'zone': zone, 'id': ((got or {}).get('domain_record') or {}).get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = [h['id']] if h.get('id') else []
        if not ids:
            _st, got = self._call('GET', '/domains/%s/records?type=TXT&name=%s' % (
                urllib.parse.quote(zone), urllib.parse.quote(D.norm(fqdn))))
            ids = [r['id'] for r in (got or {}).get('domain_records') or []
                   if r.get('data') == value]
        for rid in ids:
            self._call('DELETE', '/domains/%s/records/%s' % (urllib.parse.quote(zone), rid),
                       missing_ok=True)

    def zone_names(self):
        """Every domain of the token (discovery offers them for the Domain field)."""
        out = []
        for page in range(1, 51):
            _st, got = self._call('GET', '/domains?per_page=200&page=%d' % page)
            got = got or {}
            out += [d.get('name') for d in got.get('domains') or [] if isinstance(d, dict)]
            if not ((got.get('links') or {}).get('pages') or {}).get('next'):
                break
        return out

    def test(self):
        _st, got = self._call('GET', '/domains?per_page=50')
        names = [d.get('name') for d in (got or {}).get('domains') or []]
        return 'the token sees %d domain(s): %s' % (len(names), ', '.join(names[:20]))
