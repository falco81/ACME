# -*- coding: utf-8 -*-
"""DNS-01 at EfficientIP SOLIDserver (DDI), through its REST API v2.0:

    GET    https://{sds}/api/v2.0/dns/zone/list?where=server_name='..'     {success, data: [{zone_name, zone_type, view_name}]}
    GET    .../api/v2.0/dns/rr/list?where=rr_full_name='..' AND rr_type='TXT' AND server_name='..'
                                                                         {data: [{rr_id, rr_full_name, rr_type, rr_value1}]}
    POST   .../api/v2.0/dns/rr/add  {server_name, view_name, rr_name, rr_type, rr_value1, rr_ttl}
                                                                         {data: [{rr_id}]}
    DELETE .../api/v2.0/dns/rr/delete?rr_id={id}

Basic authentication: a SOLIDserver user allowed those services (and the
zones). *DNS server* is the server - or the SMART architecture - the zones
are on, as SOLIDserver names it; *View* where the zones are in a view. Each
value is a record of its own; cleanup deletes only the records holding ours.
SOLIDserver pushes the change to the DNS servers itself.

Sources: EfficientIP's official API client, generated from SOLIDserver's
OpenAPI description (https://github.com/EfficientIP-Labs/solidserver-go-client:
sdsclient/api/openapi.yaml and sdsclient/docs/DnsAPI.md - /dns/rr/add,
/dns/rr/list, /dns/rr/delete, /dns/zone/list; the models dns_rr_add_input,
DataInnerDnsRrData, DataInnerDnsZoneData, DataInnerDnsRrAddSuccess; the
servers "https://{host}:{port}/api/v2.0" and BasicAuth). Cross-checked with
lego's providers/dns/efficientip (which speaks the older /rest/dns_rr_*
calls of the same services). Less certain: the answer when nothing matches
(an empty list or 204 - both read as nothing).
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, DnsChallenge, api,
                                                as_bool, discover_read)
from acmelib.plugins.challenges._records import RecordApiDns, basic


def _sql(v):
    """A value in a where clause, quoted as SQL quotes it."""
    return "'%s'" % str(v).replace("'", "''")


class EfficientIp(RecordApiDns):
    kind = 'efficientip'
    title = 'EfficientIP SOLIDserver'
    vendor = 'EfficientIP'
    who = 'SOLIDserver'
    min_ttl = 60
    description = 'TXT records in a zone of an EfficientIP SOLIDserver (DDI), through its ' \
                  'REST API.'
    fields = [
        field('host', 'SOLIDserver address', 'text', required=True,
              placeholder='sds.example.local',
              help='The name or address of the SOLIDserver management appliance (a port as '
                   'name:port).'),
        field('user', 'User', 'text', required=True,
              help='A SOLIDserver user whose group may list zones and add and delete resource '
                   'records in them.'),
        field('password', 'Password', 'secret', required=True),
        field('server', 'DNS server', 'text', required=True, placeholder='smart.example.local',
              help='The DNS server (or SMART architecture) the zones are on, as SOLIDserver '
                   'names it.'),
        field('view', 'DNS view', 'text', default='', advanced=True,
              help='The DNS view of the zones. Empty: no view.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of that server the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
        field('ca_pem', 'CA certificate', 'pem', default='', advanced=True,
              help='The CA that signed the appliance\'s certificate, when it is not a public '
                   'one.'),
    ] + PROPAGATION_FIELDS
    # discovery signs in to the appliance; the DNS server and the view are read from
    # the zones it lists
    discover_keys = ['host', 'user', 'password', 'verify_tls', 'ca_pem']

    def _base(self):
        h = str(self.c('host', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the SOLIDserver address is not set', retry=False)
        if '://' not in h:
            h = 'https://' + h
        return h + '/api/v2.0'

    def _call(self, method, path, query=None, body=None):
        url = self._base() + path + ('?' + urllib.parse.urlencode(query) if query else '')
        _st, got = api(self.ctx, method, url, body,
                       {'Authorization': basic(self.c('user', ''), self.c('password', ''))},
                       who='SOLIDserver', verify=as_bool(self.c('verify_tls', True)),
                       ca_pem=str(self.c('ca_pem', '') or '').strip() or None)
        if isinstance(got, dict) and got.get('success') is False:
            raise PluginError('SOLIDserver said no: %s' % (got.get('messages') or got),
                              detail=str(got), retry=False)
        return got

    @staticmethod
    def _rows(got):
        if isinstance(got, dict):
            got = got.get('data')
        return [r for r in got or [] if isinstance(r, dict)]

    def _where(self, *parts):
        w = list(parts) + ['server_name=' + _sql(self.c('server', ''))]
        if self.c('view'):
            w.append('view_name=' + _sql(self.c('view')))
        return {'where': ' AND '.join(w)}

    def zone_names(self):
        rows = self._rows(self._call('GET', '/dns/zone/list', self._where()))
        return [r.get('zone_name') for r in rows if r.get('zone_name') and
                str(r.get('zone_is_reverse', '0')) in ('0', '', 'None', 'False', 'false')]

    def txt_records(self, zone, fqdn):
        rows = self._rows(self._call('GET', '/dns/rr/list', self._where(
            'rr_full_name=' + _sql(D.norm(fqdn)), "rr_type='TXT'")))
        return [(r.get('rr_id'), r.get('rr_value1')) for r in rows
                if D.norm(r.get('rr_full_name') or '') == D.norm(fqdn) and
                str(r.get('rr_type', 'TXT')).upper() == 'TXT']

    def create_txt(self, zone, fqdn, value):
        body = {'server_name': self.c('server', ''), 'rr_name': D.norm(fqdn), 'rr_type': 'TXT',
                'rr_value1': value, 'rr_ttl': self.ttl()}
        if self.c('view'):
            body['view_name'] = self.c('view')
        rows = self._rows(self._call('POST', '/dns/rr/add', body=body))
        return rows[0].get('rr_id') if rows else None

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/dns/rr/delete', {'rr_id': record_id})

    # -- discovery: every zone of the appliance, with its server and view ----------
    def discover_setup(self):
        """The DNS servers and views the zones are on (the DNS server and DNS view
        fields) and the zones of the server picked (choosing one sets its view)."""
        out = DnsChallenge.discover_setup(self) if str(self.c('server', '') or '').strip() \
            else {'sets': {}, 'choices': {}, 'facts': [], 'notes': []}
        rows = discover_read(out, lambda: self._rows(self._call('GET', '/dns/zone/list')))
        if rows is None:
            out['notes'] = list(dict.fromkeys(out['notes']))
            return out
        rows = [r for r in rows if r.get('zone_name') and
                str(r.get('zone_is_reverse', '0')) in ('0', '', 'None', 'False', 'false')]
        servers = sorted({str(r['server_name']) for r in rows if r.get('server_name')})
        now = str(self.c('server', '') or '').strip()
        pick = now if now in servers else (servers[0] if len(servers) == 1 else '')
        self.offer(out, 'server', [[x, x] for x in servers], pick=pick)
        mine = [r for r in rows if not pick or str(r.get('server_name') or '') == pick]
        views = sorted({str(r['view_name']) for r in mine
                        if r.get('view_name') not in (None, '', '#')})
        if views:
            self.offer(out, 'view', [['', 'Empty: no view']] + [[v, v] for v in views],
                       pick=str(self.c('view', '') or ''))
        if pick:
            # the zones of that server, each with its view (choosing one sets the view)
            zones = {}
            for r in mine:
                zones.setdefault(D.norm(r['zone_name']), set()).add(
                    '' if r.get('view_name') in (None, '#') else str(r['view_name']))
            out['facts'] = [f for f in out['facts'] if f[0] != 'Zones the account sees']
            out['facts'].append(['Zones the account sees', str(len(zones))])
            sets = {z: {'view': list(v)[0]} for z, v in zones.items() if len(v) == 1}
            znow = D.norm(self.config.get('zone') or '')
            self.offer(out, 'zone', [['', 'Empty: each name in the longest zone of the '
                                          'account it is in']] +
                       [[z, z] for z in sorted(zones)[:500]], sets,
                       pick=znow if znow in zones else '')
        return out

    def test(self):
        if not str(self.c('server', '') or '').strip():
            raise PluginError('the DNS server is not set', retry=False)
        return ApiDns.test(self)
