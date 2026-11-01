# -*- coding: utf-8 -*-
"""DNS-01 at DreamHost, through its API (GET, the key in the query):

    https://api.dreamhost.com/?key=K&format=json&cmd=dns-list_records
         {result: "success", data: [{record, zone, type, value, editable}]}
    ...&cmd=dns-add_record&record={fqdn}&type=TXT&value={value}
    ...&cmd=dns-remove_record&record={fqdn}&type=TXT&value={value}

A value is added and removed by itself, so other values at the name stay;
"record_already_exists..." and "no_such_..." are taken as done. DreamHost
sets the TTL itself.

Sources: https://help.dreamhost.com/hc/en-us/articles/217555707-DNS-API-commands
- not reachable from where this was written; as Posh-ACME's Dreamhost plugin
and lego's providers/dns/dreamhost call it. The key is made at
https://panel.dreamhost.com/?tree=home.api with the dns-* functions allowed.
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS
from acmelib.plugins.challenges._records import RecordApiDns, form_call

API = 'https://api.dreamhost.com/'


class Dreamhost(RecordApiDns):
    kind = 'dreamhost'
    title = 'DreamHost'
    vendor = 'DreamHost'
    who = 'DreamHost'
    min_ttl = 300
    description = 'TXT records in a domain hosted at DreamHost, with an API key.'
    fields = [
        field('key', 'API key', 'secret', required=True,
              help='panel.dreamhost.com → Advanced → API: generate a key with "All dns '
                   'functions" (dns-list_records, dns-add_record, dns-remove_record).'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, cmd, ok_words=(), **params):
        p = {'key': str(self.c('key', '')), 'format': 'json', 'cmd': cmd}
        p.update(params)
        _st, got, raw = form_call(self.ctx, 'GET', str(self.c('api', API)), p, who='DreamHost')
        if not isinstance(got, dict):
            raise PluginError('DreamHost answered something that is not JSON', detail=raw)
        if got.get('result') != 'success':
            data = str(got.get('data') or '')
            if any(data.startswith(w) for w in ok_words):
                return []
            raise PluginError('DreamHost said no to %s: %s' % (cmd, data or got.get('result')),
                              detail=got, retry=data.startswith('slow_down'))
        return got.get('data')

    def _records(self):
        return [r for r in self._call('dns-list_records') or [] if isinstance(r, dict)]

    def zone_names(self):
        return sorted({D.norm(r.get('zone')) for r in self._records() if r.get('zone')})

    def txt_records(self, zone, fqdn):
        return [(r.get('value'), r.get('value')) for r in self._records()
                if str(r.get('type')).upper() == 'TXT' and D.norm(r.get('record') or '') == fqdn]

    def create_txt(self, zone, fqdn, value):
        self._call('dns-add_record', ok_words=('record_already_exists',), record=fqdn,
                   type='TXT', value=value)
        return value

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('dns-remove_record', ok_words=('no_such_',), record=fqdn, type='TXT',
                   value=value)
