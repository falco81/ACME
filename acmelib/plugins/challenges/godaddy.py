# -*- coding: utf-8 -*-
"""DNS-01 at GoDaddy, through its Domains API v3 (a personal access token):

    GET    https://api.godaddy.com/v3/domains/domain-names?statuses=ACTIVE&pageSize=200
                                     {items: [{domain}], links: [{rel: next, href}]}
    GET    .../v3/domains/zones/{zone}/dns-records?type=TXT&name={relative}&pageSize=100
                                     {items: [{recordId, name, type, data, ttl}], links}
    POST   .../v3/domains/zones/{zone}/dns-records  {type: TXT, name, data, ttl}   201 + the record
    DELETE .../v3/domains/zones/{zone}/dns-records/{recordId}                     204

Authorization: Bearer <PAT> (scopes domains.domain:read and domains.dns:update).
Each value is a record of its own with its recordId: cleanup deletes only
ours, and a 404 there is a record gone already. Names are relative to the
zone ("@" for the apex), the value without quotes, TTL 600 to 86400.

The older Domains API v1 with an API key and secret ("sso-key", which "does not
work with v3" and is "deprecated for Domains (through 2026)") stays selectable,
and is what a validation saved before 1.0.27 with a key and no token uses. v1
has no record ids: the values at the name are read, ours added or taken away
and written back with PUT (DELETE when none is left), one change at a time on
this node.

GoDaddy refuses an account that is not eligible with 403 and a code of its own
("Check the code field on the response body").

Sources (the user's collection, api-docs/godaddy/): domains-v3.json (the
OpenAPI 3.1 "Domain Lifecycle Management API", from
https://developer.godaddy.com/openapi/domains-v3.json), domains-v1-dns.json and
notes.md, quoting https://developer.godaddy.com/en/docs/api-users/domains/manage/dns,
https://developer.godaddy.com/en/docs/api-users/auth and .../rate-limits.

Less certain: whether a TXT value may be sent with quotes (the examples have
none - none are sent; a listed one is compared without them); the recordId
when the 201 has no body (it is read from the Location header, else found by
its value at cleanup); the date the sso-key stops working for v1.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                rmw_lock, unquote_txt)

HOSTS = {'production': 'https://api.godaddy.com', 'ote': 'https://api.ote-godaddy.com'}


class GoDaddy(ApiDns):
    kind = 'godaddy'
    title = 'GoDaddy'
    vendor = 'GoDaddy'
    who = 'GoDaddy'
    min_ttl = 600
    description = 'TXT records in a domain at GoDaddy, with a personal access token (API v3).'
    fields = [
        field('api', 'API', 'select', default='v3',
              options=[['v3', 'Domains API v3 with a personal access token'],
                       ['v1', 'Domains API v1 with an API key and secret (older)']]),
        field('pat', 'Personal access token', 'secret', show_if={'api': ['v3']},
              help='developer.godaddy.com → Personal Access Token: the scopes '
                   'domains.domain:read and domains.dns:update, an expiry you will remember.'),
        field('api_key', 'API key', 'text', show_if={'api': ['v1']},
              help='developer.godaddy.com → API Keys (the older "sso-key", not taken by v3).'),
        field('api_secret', 'API secret', 'secret', show_if={'api': ['v1']}),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True,
              help='GoDaddy takes 600 or more.'),
        field('endpoint', 'Endpoint', 'select', default='production', advanced=True,
              options=[['production', 'api.godaddy.com'],
                       ['ote', 'api.ote-godaddy.com (the test environment)']]),
    ] + PROPAGATION_FIELDS

    # -- which API ---------------------------------------------------------------------
    def _v3(self):
        if self.config.get('api') == 'v1':
            return False
        if self.config.get('pat') or not self.config.get('api_key'):
            return True
        # saved before v3 came (or saved again with the form's default): a key and secret
        # and no token - the API they work with
        self.say_once('godaddy-v1', 'GoDaddy: no personal access token is set - the older '
                      'Domains API v1 is used with the API key and secret')
        return False

    def _host(self):
        return HOSTS.get(self.c('endpoint', 'production'), HOSTS['production'])

    def _call(self, method, path, body=None, missing_ok=False, with_headers=False):
        if self._v3():
            if not self.c('pat'):
                raise PluginError('GoDaddy: the personal access token is not set', retry=False)
            auth = 'Bearer %s' % self.c('pat', '')
            base = self._host() + '/v3/domains'
        else:
            auth = 'sso-key %s:%s' % (self.c('api_key', ''), self.c('api_secret', ''))
            base = self._host() + '/v1'
        url = path if path.startswith('http') else base + path
        got = api(self.ctx, method, url, body, {'Authorization': auth}, who='GoDaddy',
                  missing_ok=missing_ok, with_headers=with_headers)
        if with_headers:
            return got
        return None if got[0] == 404 and missing_ok else got[1]

    def _pages(self, path):
        """The items of a v3 collection, its links[rel=next] followed."""
        out, url = [], path
        for _page in range(50):
            got = self._call('GET', url) or {}
            out += [x for x in got.get('items') or [] if isinstance(x, dict)]
            nxt = [ln.get('href') for ln in got.get('links') or []
                   if isinstance(ln, dict) and ln.get('rel') == 'next' and ln.get('href')]
            if not nxt:
                break
            url = nxt[0] if nxt[0].startswith('http') else self._host() + nxt[0]
        return out

    def zone_names(self):
        if self._v3():
            return [d.get('domain') for d in
                    self._pages('/domain-names?statuses=ACTIVE&pageSize=200')]
        return [d.get('domain') for d in
                self._call('GET', '/domains?statuses=ACTIVE&limit=1000') or []]

    # -- v3: one record a value --------------------------------------------------------
    def _records(self, zone, rel):
        return [r for r in self._pages('/zones/%s/dns-records?%s' % (
            urllib.parse.quote(zone), urllib.parse.urlencode({'type': 'TXT', 'name': rel,
                                                              'pageSize': 100})))
                if str(r.get('type') or 'TXT').upper() == 'TXT' and
                str(r.get('name') or rel).lower() == rel.lower()]

    def _add3(self, zone, rel, value):
        for r in self._records(zone, rel):
            if unquote_txt(r.get('data')) == value:
                return r.get('recordId')
        st, got, rh = self._call('POST', '/zones/%s/dns-records' % urllib.parse.quote(zone), {
            'type': 'TXT', 'name': rel, 'data': value, 'ttl': self.ttl()}, with_headers=True)
        rid = (got or {}).get('recordId') if isinstance(got, dict) else None
        if not rid:
            loc = ''
            for k, v in (rh or {}).items():
                if str(k).lower() == 'location':
                    loc = str(v)
            rid = loc.rstrip('/').rsplit('/', 1)[-1] if '/dns-records/' in loc else None
        return rid

    def _del3(self, zone, rel, value, rid):
        ids = [r.get('recordId') for r in self._records(zone, rel)
               if unquote_txt(r.get('data')) == value and r.get('recordId')]
        if rid and rid not in ids and not ids:
            ids = [rid]
        for one in ids:
            self._call('DELETE', '/zones/%s/dns-records/%s' % (
                urllib.parse.quote(zone), urllib.parse.quote(str(one))), missing_ok=True)

    # -- v1: the values at the name written whole --------------------------------------
    def _path(self, zone, rel):
        return '/domains/%s/records/TXT/%s' % (urllib.parse.quote(zone),
                                               urllib.parse.quote(rel, safe='@'))

    def _values(self, zone, rel):
        return [r for r in self._call('GET', self._path(zone, rel), missing_ok=True) or []
                if isinstance(r, dict)]

    def _add1(self, zone, rel, value):
        with rmw_lock('godaddy'):
            have = self._values(zone, rel)
            if value not in [unquote_txt(r.get('data')) for r in have]:
                recs = [{'data': r.get('data'), 'ttl': int(r.get('ttl') or self.ttl())}
                        for r in have] + [{'data': value, 'ttl': self.ttl()}]
                self._call('PUT', self._path(zone, rel), recs)

    def _del1(self, zone, rel, value):
        with rmw_lock('godaddy'):
            have = self._values(zone, rel)
            left = [{'data': r.get('data'), 'ttl': int(r.get('ttl') or self.ttl())}
                    for r in have if unquote_txt(r.get('data')) != value]
            if len(left) == len(have):
                return
            if left:
                self._call('PUT', self._path(zone, rel), left)
            else:
                self._call('DELETE', self._path(zone, rel), missing_ok=True)

    # -- the contract ------------------------------------------------------------------
    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        if self._v3():
            return {'zone': zone, 'rel': rel, 'id': self._add3(zone, rel, value)}
        self._add1(zone, rel, value)
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        rel = h.get('rel') or relative(fqdn, zone)
        if self._v3():
            self._del3(zone, rel, value, h.get('id'))
        else:
            self._del1(zone, rel, value)
