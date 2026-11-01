# -*- coding: utf-8 -*-
"""DNS-01 at DNSimple, through API v2:

    GET    https://api.dnsimple.com/v2/whoami                       {data: {account, user}}
    GET    .../{account}/zones?per_page=100&page=N                  {data: [{name}], pagination}
    GET    .../{account}/zones/{zone}/records?type=TXT&name={sub}   {data: [{id, content}]}
    POST   .../{account}/zones/{zone}/records  {name, type, content, ttl}
    DELETE .../{account}/zones/{zone}/records/{id}

An account token knows its account (whoami); with a user token the account
ID has to be set.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                unquote_txt)

APIS = {'production': 'https://api.dnsimple.com/v2',
        'sandbox': 'https://api.sandbox.dnsimple.com/v2'}


class Dnsimple(ApiDns):
    kind = 'dnsimple'
    title = 'DNSimple'
    vendor = 'DNSimple'
    who = 'DNSimple'
    description = 'TXT records in a DNSimple zone, with an API access token.'
    fields = [
        field('token', 'API access token', 'secret', required=True,
              help='dnsimple.com → (the account) → Account → Access tokens → New access token '
                   '(an account token; a user token needs the account ID below).'),
        field('account_id', 'Account ID', 'text', default='', advanced=True,
              help='Empty: the account of the token.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('endpoint', 'Endpoint', 'select', default='production', advanced=True,
              options=[['production', 'api.dnsimple.com'],
                       ['sandbox', 'api.sandbox.dnsimple.com (the sandbox)']]),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        base = APIS.get(self.c('endpoint', 'production'), APIS['production'])
        st, got = api(self.ctx, method, base + path, body,
                      {'Authorization': 'Bearer ' + str(self.c('token', ''))}, who='DNSimple',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _account(self):
        if self.c('account_id'):
            return str(self.c('account_id'))
        if not getattr(self, '_acct', None):
            who = (self._call('GET', '/whoami') or {}).get('data') or {}
            acct = who.get('account') or {}
            if not acct.get('id'):
                raise PluginError('the DNSimple token is a user token: set the account ID',
                                  retry=False)
            self._acct = str(acct['id'])
        return self._acct

    def zone_names(self):
        out = []
        for page in range(1, 51):
            got = self._call('GET', '/%s/zones?per_page=100&page=%d' % (self._account(), page)) or {}
            out += [z.get('name') for z in got.get('data') or []]
            if page >= int((got.get('pagination') or {}).get('total_pages') or 1):
                break
        return out

    def _records(self, zone):
        return '/%s/zones/%s/records' % (self._account(), urllib.parse.quote(zone))

    def _ours(self, zone, rel, value):
        name = '' if rel == '@' else rel
        got = self._call('GET', '%s?type=TXT&name=%s&per_page=100' % (
            self._records(zone), urllib.parse.quote(name))) or {}
        return [r['id'] for r in got.get('data') or []
                if (r.get('name') or '') == name and unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        have = self._ours(zone, rel, value)
        if have:
            return {'zone': zone, 'id': have[0]}
        got = self._call('POST', self._records(zone), {
            'name': '' if rel == '@' else rel, 'type': 'TXT', 'content': value,
            'ttl': self.ttl()}) or {}
        return {'zone': zone, 'id': (got.get('data') or {}).get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = [h['id']] if h.get('id') else self._ours(zone, relative(fqdn, zone), value)
        for rid in ids:
            self._call('DELETE', '%s/%s' % (self._records(zone), rid), missing_ok=True)
