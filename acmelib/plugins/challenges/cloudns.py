# -*- coding: utf-8 -*-
"""DNS-01 at ClouDNS, through its HTTP API (https://api.cloudns.net/dns/...,
the credentials in every call, a form POST each):

    login.json                                         signs in
    list-zones.json  page, rows-per-page               [{name, type}]
    records.json     domain-name, host, type=TXT       {id: {id, host, type, record}}  ({} / [] none)
    add-record.json  domain-name, record-type, host, record, ttl
    delete-record.json  domain-name, record-id

Answers: {"status": "Success"|"Failed", "statusDescription": ...}. An API user
(auth-id) or a sub-user (sub-auth-id, best limited to the zones acme may
change) - from the API page of the account; the API answers only the
addresses that user allows.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                unquote_txt)

API = 'https://api.cloudns.net/dns'
TTLS = (60, 300, 900, 1800, 3600, 21600, 43200, 86400, 172800, 259200, 604800, 1209600,
        2592000)


class Cloudns(ApiDns):
    kind = 'cloudns'
    discover_keys = ['user_kind', 'auth_id', 'auth_password']     # how one signs in
    title = 'ClouDNS'
    vendor = 'ClouDNS'
    who = 'ClouDNS'
    description = 'TXT records in a ClouDNS zone, with an API user or sub-user.'
    fields = [
        field('user_kind', 'Signs in as', 'select', default='sub',
              options=[['sub', 'an API sub-user (sub-auth-id)'],
                       ['main', 'the main API user (auth-id)']]),
        field('auth_id', 'Auth ID', 'text', required=True, placeholder='1234',
              help='cloudns.net → API & Resellers → API users → Add new user (or a sub-user, '
                   'given only the zones acme may change); with the address acme calls from '
                   'allowed.'),
        field('auth_password', 'Auth password', 'secret', required=True),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='ClouDNS knows 60, 300, 900, 1800, 3600 …: another is raised to the next.'),
    ] + PROPAGATION_FIELDS

    def ttl(self):
        want = ApiDns.ttl(self)
        return next((t for t in TTLS if t >= want), TTLS[-1])

    def _call(self, path, params=None):
        q = {('sub-auth-id' if self.c('user_kind', 'sub') == 'sub' else 'auth-id'):
             str(self.c('auth_id', '')), 'auth-password': str(self.c('auth_password', ''))}
        q.update(params or {})
        _st, got = api(self.ctx, 'POST', '%s/%s' % (API, path), who='ClouDNS',
                       raw_body=urllib.parse.urlencode(q).encode(),
                       headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if isinstance(got, dict) and got.get('status') == 'Failed':
            raise PluginError('ClouDNS said no: %s' % got.get('statusDescription'),
                              detail=got, retry=False)
        return got

    def zone_names(self):
        out = []
        for page in range(1, 51):
            got = self._call('list-zones.json', {'page': page, 'rows-per-page': 100})
            got = got if isinstance(got, list) else []
            out += [z.get('name') for z in got if z.get('type') in (None, 'master')]
            if len(got) < 100:
                break
        return out

    def _ours(self, zone, rel, value):
        host = '' if rel == '@' else rel
        got = self._call('records.json', {'domain-name': zone, 'host': host, 'type': 'TXT'})
        recs = got.values() if isinstance(got, dict) else []
        return [r['id'] for r in recs if isinstance(r, dict) and r.get('type') == 'TXT' and
                (r.get('host') or '') == host and unquote_txt(r.get('record')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        have = self._ours(zone, rel, value)
        if have:
            return {'zone': zone, 'id': have[0]}
        got = self._call('add-record.json', {
            'domain-name': zone, 'record-type': 'TXT', 'host': '' if rel == '@' else rel,
            'record': value, 'ttl': self.ttl()}) or {}
        return {'zone': zone, 'id': (got.get('data') or {}).get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        for rid in self._ours(zone, relative(fqdn, zone), value):
            try:
                self._call('delete-record.json', {'domain-name': zone, 'record-id': rid})
            except PluginError as e:
                if 'not found' not in str(e).lower() and 'invalid record' not in str(e).lower():
                    raise

    def test(self):
        self._call('login.json')
        return ApiDns.test(self)
