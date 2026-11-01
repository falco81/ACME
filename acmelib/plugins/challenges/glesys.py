# -*- coding: utf-8 -*-
"""DNS-01 at GleSYS (Sweden), through its API:

    POST https://api.glesys.com/domain/list                                    response.domains: [{domainname}]
    POST .../domain/listrecords   {domainname}                                 response.records: [{recordid, host, type, data, ttl}]
    POST .../domain/addrecord     {domainname, host, type: "TXT", data, ttl}   response.record: {recordid}
    POST .../domain/deleterecord  {recordid}

Basic authentication: the project's name (CL12345) and an API key. Every
answer has response.status.code (200 when done). "host" is relative to the
domain, "@" the apex. TTL at least 60.

Sources: https://github.com/GleSYS/API/wiki/API-Documentation and
https://api.glesys.com/domain - not reachable from where this was written;
addrecord and deleterecord as lego's providers/dns/glesys sends them; list
and listrecords from GleSYS's API documentation as remembered (less
certain: the field names of their answers - read here as above).
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, basic, rel_name

API = 'https://api.glesys.com'


class Glesys(RecordApiDns):
    kind = 'glesys'
    title = 'GleSYS'
    vendor = 'GleSYS'
    who = 'GleSYS'
    min_ttl = 60
    description = 'TXT records in a domain at GleSYS, with a project and an API key.'
    fields = [
        field('project', 'Project', 'text', required=True, placeholder='CL12345',
              help='GleSYS Cloud → the project → API: its name (CL...), and an API key made '
                   'there with the permissions domain: list, listrecords, addrecord, '
                   'deleterecord - and acme\'s address allowed.'),
        field('key', 'API key', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.se',
              help='Empty: the longest domain of the project the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, path, body=None):
        _st, got = api(self.ctx, 'POST', str(self.c('api', API)).rstrip('/') + path, body or {},
                       {'Authorization': basic(self.c('project', ''), self.c('key', ''))},
                       who='GleSYS')
        resp = (got or {}).get('response') or {}
        code = (resp.get('status') or {}).get('code')
        if code not in (None, 200):
            raise PluginError('GleSYS said %s: %s' % (code, (resp.get('status') or {}).get(
                'text') or 'no'), detail=got, retry=False)
        return resp

    def zone_names(self):
        return [d.get('domainname') for d in self._call('/domain/list').get('domains') or []
                if isinstance(d, dict)]

    def txt_records(self, zone, fqdn):
        host = rel_name(fqdn, zone)
        return [(r.get('recordid'), r.get('data')) for r in
                self._call('/domain/listrecords', {'domainname': zone}).get('records') or []
                if isinstance(r, dict) and str(r.get('type')).upper() == 'TXT' and
                (r.get('host') == host or D.norm(r.get('host') or '') == fqdn)]

    def create_txt(self, zone, fqdn, value):
        got = self._call('/domain/addrecord', {'domainname': zone, 'host': rel_name(fqdn, zone),
                                               'type': 'TXT', 'data': value, 'ttl': self.ttl()})
        return (got.get('record') or {}).get('recordid')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('/domain/deleterecord', {'recordid': int(record_id)})
