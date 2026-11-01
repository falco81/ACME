# -*- coding: utf-8 -*-
"""DNS-01 at Njalla, through its JSON-RPC API:

    POST https://njal.la/api/1/   {method, params}   Authorization: Njalla <token>
    list-domains   {}                                       result.domains: [{name}]
    list-records   {domain}                                 result.records: [{id, name, type, content, ttl}]
    add-record     {domain, name, type: "TXT", content, ttl}   result: {id, ...}
    remove-record  {domain, id}

"name" is relative to the domain ("@" the apex). An error comes as
{error: {code, message}}.

Sources: https://njal.la/api/ - not reachable from where this was written;
as lego's providers/dns/njalla calls it.
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://njal.la/api/1/'


class Njalla(RecordApiDns):
    kind = 'njalla'
    title = 'Njalla'
    vendor = 'Njalla'
    who = 'Njalla'
    min_ttl = 60
    description = 'TXT records in a domain at Njalla, with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='njal.la → Settings → API access → Add token (best limited to the address '
                   'acme calls from).'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _rpc(self, method, **params):
        _st, got = api(self.ctx, 'POST', str(self.c('api', API)), {'method': method,
                                                                   'params': params},
                       {'Authorization': 'Njalla ' + str(self.c('token', ''))}, who='Njalla')
        got = got or {}
        if got.get('error'):
            e = got['error']
            raise PluginError('Njalla said no to %s: %s' % (method, e.get('message') if isinstance(
                e, dict) else e), detail=got, retry=False)
        return got.get('result') or {}

    def zone_names(self):
        return [d.get('name') for d in self._rpc('list-domains').get('domains') or []]

    def txt_records(self, zone, fqdn):
        rel = rel_name(fqdn, zone)
        return [(r.get('id'), r.get('content')) for r in
                self._rpc('list-records', domain=zone).get('records') or []
                if str(r.get('type')).upper() == 'TXT' and
                (r.get('name') == rel or D.norm(r.get('name') or '') == fqdn)]

    def create_txt(self, zone, fqdn, value):
        return self._rpc('add-record', domain=zone, name=rel_name(fqdn, zone), type='TXT',
                         content=value, ttl=self.ttl()).get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._rpc('remove-record', domain=zone, id=record_id)
