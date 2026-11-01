# -*- coding: utf-8 -*-
"""DNS-01 at Gandi, through LiveDNS (API v5):

    GET    https://api.gandi.net/v5/livedns/domains                       the domains
    GET    .../domains/{fqdn}/records/{name}/TXT     {rrset_ttl, rrset_values}   (404: none)
    PUT    .../domains/{fqdn}/records/{name}/TXT     {rrset_ttl, rrset_values}   written whole
    DELETE .../domains/{fqdn}/records/{name}/TXT

A personal access token is sent as "Authorization: Bearer", the older API key
as "Authorization: Apikey" (Gandi has retired new API keys; both still work).
The RRset is read, our value added or taken away, and written back.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                rmw_lock, unquote_txt)

API = 'https://api.gandi.net/v5/livedns'


class Gandi(ApiDns):
    kind = 'gandi'
    title = 'Gandi LiveDNS'
    vendor = 'Gandi'
    who = 'Gandi'
    min_ttl = 300
    description = 'TXT records in a domain at Gandi (LiveDNS), with a personal access token.'
    fields = [
        field('auth', 'Signs in with', 'select', default='pat',
              options=[['pat', 'a personal access token'], ['apikey', 'an API key (older)']]),
        field('token', 'Token', 'secret', required=True,
              help='admin.gandi.net → Organizations → (yours) → Sharing → Personal Access Tokens '
                   '(or User settings → Authentication options): with "Manage domain name '
                   'technical configurations", limited to the domains acme may change.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='Gandi takes 300 or more.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        scheme = 'Apikey ' if self.c('auth', 'pat') == 'apikey' else 'Bearer '
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'Authorization': scheme + str(self.c('token', ''))}, who='Gandi',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        return [d.get('fqdn') for d in self._call('GET', '/domains') or []]

    def _path(self, zone, rel):
        return '/domains/%s/records/%s/TXT' % (urllib.parse.quote(zone),
                                               urllib.parse.quote(rel, safe='@'))

    def _values(self, zone, rel):
        got = self._call('GET', self._path(zone, rel), missing_ok=True) or {}
        return list(got.get('rrset_values') or []), got.get('rrset_ttl')

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        with rmw_lock('gandi'):
            have, ttl = self._values(zone, rel)
            if value not in [unquote_txt(v) for v in have]:
                self._call('PUT', self._path(zone, rel), {
                    'rrset_ttl': int(ttl or self.ttl()), 'rrset_values': have + ['"%s"' % value]})
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        rel = h.get('rel') or relative(fqdn, zone)
        with rmw_lock('gandi'):
            have, ttl = self._values(zone, rel)
            left = [v for v in have if unquote_txt(v) != value]
            if len(left) == len(have):
                return
            if left:
                self._call('PUT', self._path(zone, rel), {'rrset_ttl': int(ttl or self.ttl()),
                                                          'rrset_values': left})
            else:
                self._call('DELETE', self._path(zone, rel), missing_ok=True)
