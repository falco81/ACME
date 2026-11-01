# -*- coding: utf-8 -*-
"""DNS-01 at Simply.com (formerly UnoEuro), through its REST API v2:

    GET    https://api.simply.com/2/my/products/                          {products: [{object, domain: {name, name_idn}}]}
    GET    .../my/products/{object}/dns/records/                          {records: [{record_id, name, type, data, ttl}]}
    POST   .../my/products/{object}/dns/records/   {name, type, data, ttl}   {record: {id}}
    DELETE .../my/products/{object}/dns/records/{record_id}/

Signed in with the account number and the API key as basic authentication;
with only an API key (the newer keys) as a bearer token. "name" is relative
to the domain ("@" the apex).

Sources: https://www.simply.com/en/docs/api/ and the API's own description
https://api.simply.com/2/doc.json - not reachable from where this was
written; as lego's providers/dns/simply and Posh-ACME's SimplyCom plugin
send it.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, basic, rel_name

API = 'https://api.simply.com/2'


class Simply(RecordApiDns):
    kind = 'simply'
    title = 'Simply.com'
    vendor = 'Simply.com'
    who = 'Simply.com'
    min_ttl = 60
    description = 'TXT records in a domain at Simply.com (UnoEuro), with an API key.'
    fields = [
        field('account', 'Account number', 'text', default='', placeholder='S123456',
              help='Simply.com control panel → Account → API: the account number shown there. '
                   'Empty: the API key alone is sent (as a bearer token).'),
        field('key', 'API key', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.dk',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=120, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        acct = str(self.c('account', '') or '').strip()
        key = str(self.c('key', ''))
        auth = basic(acct, key) if acct else 'Bearer ' + key
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'Authorization': auth}, who='Simply.com', missing_ok=missing_ok)
        return got

    def _products(self):
        if getattr(self, '_prod', None) is None:
            got = self._call('GET', '/my/products/') or {}
            self._prod = {}
            for p in got.get('products') or []:
                dom = p.get('domain') or {}
                name = D.norm(dom.get('name_idn') or dom.get('name') or '')
                if name:
                    self._prod[name] = p.get('object') or name
        return self._prod

    def zone_names(self):
        return list(self._products())

    def _obj(self, zone):
        return urllib.parse.quote(str(self._products().get(D.norm(zone)) or zone), safe='')

    def txt_records(self, zone, fqdn):
        got = self._call('GET', '/my/products/%s/dns/records/' % self._obj(zone)) or {}
        rel = rel_name(fqdn, zone)
        return [(r.get('record_id'), r.get('data')) for r in got.get('records') or []
                if str(r.get('type')).upper() == 'TXT' and
                (r.get('name') == rel or D.norm(r.get('name') or '') == fqdn)]

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/my/products/%s/dns/records/' % self._obj(zone), {
            'name': rel_name(fqdn, zone), 'type': 'TXT', 'data': value, 'ttl': self.ttl()}) or {}
        return (got.get('record') or {}).get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/my/products/%s/dns/records/%s/' % (self._obj(zone), record_id),
                   missing_ok=True)

    def test(self):
        if not str(self.c('key', '') or ''):
            raise PluginError('no API key is set', retry=False)
        return RecordApiDns.test(self)
