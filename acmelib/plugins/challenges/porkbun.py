# -*- coding: utf-8 -*-
"""DNS-01 at Porkbun, through API v3 - every call a POST whose JSON body holds
the keys:

    POST https://api.porkbun.com/api/json/v3/ping                          signs in
    POST .../domain/listAll                                                 {domains: [{domain}]}
    POST .../dns/retrieveByNameType/{domain}/TXT/{subdomain}                {records: [{id, content}]}
    POST .../dns/create/{domain}  {name, type, content, ttl}                {id}
    POST .../dns/delete/{domain}/{id}

Each answer says {"status": "SUCCESS"} or {"status": "ERROR", "message": ...}.
API access has to be switched on for each domain (Domain Management → the
domain → Details → API Access). Porkbun takes no TTL under 600.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                unquote_txt)

API = 'https://api.porkbun.com/api/json/v3'


class Porkbun(ApiDns):
    kind = 'porkbun'
    title = 'Porkbun'
    vendor = 'Porkbun'
    who = 'Porkbun'
    min_ttl = 600
    description = 'TXT records in a domain at Porkbun, with an API key and its secret.'
    fields = [
        field('api_key', 'API key', 'text', required=True, placeholder='pk1_...',
              help='porkbun.com → Account → API Access → Create API Key; then, for each '
                   'domain, Domain Management → Details → API Access on.'),
        field('secret_key', 'Secret API key', 'secret', required=True, placeholder='sk1_...'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True,
              help='Porkbun takes 600 or more.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, path, body=None, missing_ok=False):
        data = {'apikey': str(self.c('api_key', '')), 'secretapikey': str(self.c('secret_key', ''))}
        data.update(body or {})
        st, got = api(self.ctx, 'POST', str(self.c('api', API)).rstrip('/') + path, data,
                      who='Porkbun', ok=(200, 201, 202, 204, 400), missing_ok=missing_ok)
        if st == 404 and missing_ok:
            return None
        got = got if isinstance(got, dict) else {}
        if got.get('status') != 'SUCCESS':
            words = str(got.get('message') or 'status %s' % st)
            if missing_ok and ('not found' in words.lower() or 'invalid record id' in words.lower()):
                return None
            raise PluginError('Porkbun said no: %s' % words, retry=st >= 500,
                              detail=words)
        return got

    def zone_names(self):
        out = []
        for start in range(0, 5000, 1000):
            got = (self._call('/domain/listAll', {'start': str(start)}) or {}).get('domains') or []
            out += [d.get('domain') for d in got]
            if len(got) < 1000:
                break
        return out

    def _ours(self, zone, rel, value):
        got = self._call('/dns/retrieveByNameType/%s/TXT/%s' % (
            urllib.parse.quote(zone), '' if rel == '@' else urllib.parse.quote(rel)),
            missing_ok=True) or {}
        return [r['id'] for r in got.get('records') or [] if unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        have = self._ours(zone, rel, value)
        if have:
            return {'zone': zone, 'id': have[0]}
        got = self._call('/dns/create/%s' % urllib.parse.quote(zone), {
            'name': '' if rel == '@' else rel, 'type': 'TXT', 'content': value,
            'ttl': str(self.ttl())}) or {}
        return {'zone': zone, 'id': got.get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = self._ours(zone, relative(fqdn, zone), value)
        for rid in ids:
            self._call('/dns/delete/%s/%s' % (urllib.parse.quote(zone), rid), missing_ok=True)

    def test(self):
        got = self._call('/ping') or {}
        self._zone_list = None
        words = ApiDns.test(self)
        return '%s (calling from %s)' % (words, got.get('yourIp') or '?')
