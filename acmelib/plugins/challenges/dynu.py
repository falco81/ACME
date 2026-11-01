# -*- coding: utf-8 -*-
"""DNS-01 at Dynu, through its API v2:

    GET    https://api.dynu.com/v2/dns                                   {domains: [{id, name}]}
    GET    .../v2/dns/{id}/record                                        {dnsRecords: [{id, nodeName, hostname, recordType, textData}]}
    POST   .../v2/dns/{id}/record  {nodeName, recordType: "TXT", textData, ttl, state: true}   {id}
    DELETE .../v2/dns/{id}/record/{record id}

Header API-Key: <key>. "nodeName" is relative to the domain ("" the apex),
"hostname" the full name.

Sources: https://www.dynu.com/Support/API - not reachable from where this was
written; as Posh-ACME's Dynu plugin and lego's providers/dns/dynu call it.
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://api.dynu.com/v2'


class Dynu(RecordApiDns):
    kind = 'dynu'
    title = 'Dynu'
    vendor = 'Dynu'
    who = 'Dynu'
    min_ttl = 60
    description = 'TXT records in a domain at Dynu, with an API key.'
    fields = [
        field('key', 'API key', 'secret', required=True,
              help='dynu.com → Control Panel → API Credentials: the API key.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        _st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                       {'API-Key': str(self.c('key', ''))}, who='Dynu', missing_ok=missing_ok)
        return got or {}

    def _domains(self):
        if getattr(self, '_doms', None) is None:
            self._doms = {D.norm(d.get('name')): d.get('id')
                          for d in self._call('GET', '/dns').get('domains') or []}
        return self._doms

    def zone_names(self):
        return list(self._domains())

    def _id(self, zone):
        did = self._domains().get(D.norm(zone))
        if did is None:
            raise PluginError('Dynu has no domain %s on this account' % zone, retry=False)
        return did

    def txt_records(self, zone, fqdn):
        node = rel_name(fqdn, zone, apex='')
        return [(r.get('id'), r.get('textData')) for r in
                self._call('GET', '/dns/%s/record' % self._id(zone)).get('dnsRecords') or []
                if str(r.get('recordType')).upper() == 'TXT' and
                (D.norm(r.get('hostname') or '') == fqdn or (r.get('nodeName') or '') == node)]

    def create_txt(self, zone, fqdn, value):
        return self._call('POST', '/dns/%s/record' % self._id(zone), {
            'nodeName': rel_name(fqdn, zone, apex=''), 'recordType': 'TXT', 'textData': value,
            'ttl': self.ttl(), 'state': True}).get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/dns/%s/record/%s' % (self._id(zone), record_id), missing_ok=True)
