# -*- coding: utf-8 -*-
"""DNS-01 in a Technitium DNS Server, through its HTTP API (form POSTs):

    /api/zones/list                                         {response: {zones: [{name, type}]}}
    /api/zones/records/get     domain, zone                 {response: {records: [{name, type, rData}]}}
    /api/zones/records/add     domain, zone, type=TXT, ttl, text
    /api/zones/records/delete  domain, zone, type=TXT, text

the API token in each (token=...). Answers {"status": "ok"|"error"|"invalid-token",
"errorMessage"}. A second TXT value at a name is added beside the first;
delete takes away only the value given.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ApiDns, api, as_bool


class Technitium(ApiDns):
    kind = 'technitium'
    title = 'Technitium DNS Server'
    vendor = 'Technitium'
    who = 'Technitium'
    description = 'TXT records in a zone of a Technitium DNS Server, with an API token.'
    fields = [
        field('url', 'Server address', 'text', required=True,
              placeholder='https://dns.example.local:53443',
              help='The web console\'s address (http://HOST:5380 or https://HOST:53443).'),
        field('token', 'API token', 'secret', required=True,
              help='Web console → (your user) → Create API Token; or Administration → Sessions '
                   '→ Create Token, for a user given Modify on the zones (Administration → '
                   'Permissions).'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest primary zone of the server the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, path, params=None):
        u = str(self.c('url', '')).rstrip('/')
        if not u:
            raise PluginError('the server address is not set', retry=False)
        q = {'token': str(self.c('token', ''))}
        q.update(params or {})
        _st, got = api(self.ctx, 'POST', u + path, who='Technitium',
                       raw_body=urllib.parse.urlencode(q).encode(),
                       headers={'Content-Type': 'application/x-www-form-urlencoded'},
                       verify=as_bool(self.c('verify_tls', True)))
        got = got if isinstance(got, dict) else {}
        if got.get('status') != 'ok':
            words = got.get('errorMessage') or got.get('status') or 'no answer'
            if got.get('status') == 'invalid-token':
                words = 'the API token is not valid'
            raise PluginError('Technitium said no: %s' % words, detail=got,
                              retry=False)
        return got.get('response') or {}

    def zone_names(self):
        return [z.get('name') for z in self._call('/api/zones/list').get('zones') or []
                if z.get('type') in (None, 'Primary', 'Forwarder') and not z.get('disabled')]

    def _values(self, zone, fqdn):
        recs = self._call('/api/zones/records/get', {'domain': D.norm(fqdn), 'zone': zone,
                                                     'listZone': 'false'}).get('records') or []
        return [(r.get('rData') or {}).get('text') for r in recs
                if r.get('type') == 'TXT' and D.norm(r.get('name')) == D.norm(fqdn)]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        if value not in self._values(zone, fqdn):
            self._call('/api/zones/records/add', {'domain': D.norm(fqdn), 'zone': zone,
                                                  'type': 'TXT', 'ttl': self.ttl(),
                                                  'text': value})
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        if value in self._values(zone, fqdn):
            self._call('/api/zones/records/delete', {'domain': D.norm(fqdn), 'zone': zone,
                                                     'type': 'TXT', 'text': value})
