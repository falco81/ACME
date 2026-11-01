# -*- coding: utf-8 -*-
"""DNS-01 at hosting.de (and http.net, on the same platform), through its
JSON API: every call a POST with the API key as "authToken" in the body.

    POST https://secure.hosting.de/api/dns/v1/json/zoneConfigsFind
         {authToken, filter: {field: "zoneName", value}, limit, page}     -> response.data: [zoneConfig]
    POST .../recordsFind
         {authToken, filter: {subFilterConnective: "AND", subFilter: [
             {field: "zoneConfigId", value}, {field: "recordName", value},
             {field: "recordType", value: "TXT"}]}, limit}                 -> response.data: [record]
    POST .../zoneUpdate
         {authToken, zoneConfig, recordsToAdd: [{name, type, content, ttl}],
          recordsToDelete: [{name, type, content}]}

Each answer {status: success|pending|error, errors: [{code, text}], response}.
A TXT value is given without quotes and comes back in quotes ("..."); a
record to delete is named by its content as it is kept, in quotes.

Sources: https://www.hosting.de/api/#dns (zoneConfigsFind, recordsFind,
zoneUpdate) - not reachable from where this was written; zoneConfigsFind and
zoneUpdate are as lego's providers/dns/internal/hostingde sends them. Less
certain: recordsFind and its filter fields (zoneConfigId, recordName,
recordType) and the wildcard "*" listing every zone in test() - written from
the API's documented filter scheme; should recordsFind fail, the records of
the zone are not looked at and a value already there is added again
(hosting.de then answers that it exists).
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api, unquote_txt
from acmelib.plugins.challenges._records import RecordApiDns

API = 'https://secure.hosting.de/api/dns/v1/json'


class HostingDe(RecordApiDns):
    kind = 'hostingde'
    title = 'hosting.de / http.net'
    vendor = 'hosting.de'
    who = 'hosting.de'
    min_ttl = 60
    description = 'TXT records in a zone at hosting.de (or http.net), with an API key.'
    fields = [
        field('token', 'API key', 'secret', required=True,
              help='hosting.de: Profile → API keys → new key, with the rights "DNS: list zones", '
                   '"DNS: edit zones" (and list records). For http.net set its API address '
                   'below.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.de',
              help='Empty: the longest zone the key sees that the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=120, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True,
              help='http.net: https://partner.http.net/api/dns/v1/json'),
    ] + PROPAGATION_FIELDS

    def _call(self, command, body):
        b = {'authToken': str(self.c('token', ''))}
        b.update(body)
        _st, got = api(self.ctx, 'POST', '%s/%s' % (str(self.c('api', API)).rstrip('/'), command),
                       b, who='hosting.de')
        got = got or {}
        if got.get('status') not in ('success', 'pending'):
            errs = '; '.join('%s (%s)' % (e.get('text'), e.get('code'))
                             for e in got.get('errors') or [] if isinstance(e, dict))
            raise PluginError('hosting.de said no to %s: %s' % (command, errs or got.get('status')),
                              detail=got, retry=False)
        return got.get('response') or {}

    def _configs(self, value, limit=1):
        got = self._call('zoneConfigsFind', {'filter': {'field': 'zoneName', 'value': value},
                                             'limit': limit, 'page': 1})
        return [z for z in got.get('data') or [] if isinstance(z, dict)]

    def zone_names(self):
        return [z.get('name') for z in self._configs('*', limit=1000)]

    def _config(self, zone):
        if not hasattr(self, '_cfg'):
            self._cfg = {}
        if zone not in self._cfg:
            got = self._configs(zone)
            if not got:
                raise PluginError('hosting.de has no zone %s that the key may see' % zone,
                                  retry=False)
            self._cfg[zone] = got[0]
        return self._cfg[zone]

    def txt_records(self, zone, fqdn):
        cfg = self._config(zone)
        try:
            got = self._call('recordsFind', {'filter': {'subFilterConnective': 'AND', 'subFilter': [
                {'field': 'zoneConfigId', 'value': cfg.get('id')},
                {'field': 'recordName', 'value': fqdn},
                {'field': 'recordType', 'value': 'TXT'}]}, 'limit': 100})
        except PluginError as e:
            self.ctx.debug('hosting.de recordsFind: %s' % e)
            self._blind = True
            return []
        return [(r.get('content'), r.get('content')) for r in got.get('data') or []
                if isinstance(r, dict) and D.norm(r.get('name') or '') == fqdn and
                str(r.get('type')).upper() == 'TXT']

    def create_txt(self, zone, fqdn, value):
        try:
            self._call('zoneUpdate', {'zoneConfig': self._config(zone), 'recordsToAdd': [
                {'name': fqdn, 'type': 'TXT', 'content': value, 'ttl': self.ttl()}],
                'recordsToDelete': []})
        except PluginError as e:
            if 'exist' not in str(e).lower():
                raise
        return '"%s"' % value

    def delete_txt(self, zone, fqdn, record_id, value):
        content = record_id if unquote_txt(record_id) == value else '"%s"' % value
        self._call('zoneUpdate', {'zoneConfig': self._config(zone), 'recordsToAdd': [],
                                  'recordsToDelete': [{'name': fqdn, 'type': 'TXT',
                                                       'content': content}]})

    def del_txt(self, fqdn, value, handle):
        self._blind = False
        RecordApiDns.del_txt(self, fqdn, value, handle)
        if self._blind:                         # the records could not be listed: by its value
            zone = (handle or {}).get('zone') or self.zone_for(fqdn)
            try:
                self.delete_txt(zone, D.norm(fqdn), '"%s"' % value, value)
            except PluginError as e:
                if 'exist' not in str(e).lower() and 'not found' not in str(e).lower():
                    raise

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            cfg = self._config(z)
            return 'hosting.de: the key sees the zone %s (%s)' % (cfg.get('name'), cfg.get('status'))
        return RecordApiDns.test(self)
