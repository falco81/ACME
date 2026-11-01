# -*- coding: utf-8 -*-
"""DNS-01 at NameSilo, through its API (GET requests, the key in the query):

    https://www.namesilo.com/api/listDomains?version=1&type=json&key=K
    .../dnsListRecords?version=1&type=json&key=K&domain=D
         reply.resource_record: [{record_id, type, host (full name), value, ttl}]
    .../dnsAddRecord?...&domain=D&rrtype=TXT&rrhost=_acme-challenge.www&rrvalue=V&rrttl=3600
         reply.record_id
    .../dnsDeleteRecord?...&domain=D&rrid=ID

Every answer {request, reply: {code, detail, ...}}: code 300 is success
(280: a value not taken, 110: the key wrong, 200: not a domain of the
account). "rrhost" is relative to the domain ("" the apex).

Sources: https://www.namesilo.com/api-reference - not reachable from where
this was written; as Posh-ACME's NameSilo plugin (XML) and lego's
providers/dns/namesilo call it. Less certain: the shape of listDomains in
JSON (a list of names, or of objects) - both are read. NameSilo takes no TTL
under 3600 and its name servers can take 15 minutes or more to have a
change - acme waits for them (Wait until it is seen).
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS
from acmelib.plugins.challenges._records import RecordApiDns, form_call, rel_name

API = 'https://www.namesilo.com/api'


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


class NameSilo(RecordApiDns):
    kind = 'namesilo'
    title = 'NameSilo'
    vendor = 'NameSilo'
    who = 'NameSilo'
    min_ttl = 3600
    description = 'TXT records in a domain at NameSilo, with an API key.'
    fields = [
        field('key', 'API key', 'secret', required=True,
              help='namesilo.com → Account → API Manager (https://www.namesilo.com/account/'
                   'api-manager): generate a key; best limited to the address acme calls from.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=3600, advanced=True,
              help='NameSilo takes 3600 or more.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, op, **params):
        p = {'version': '1', 'type': 'json', 'key': str(self.c('key', ''))}
        p.update(params)
        _st, got, raw = form_call(self.ctx, 'GET', '%s/%s' % (str(self.c('api', API)).rstrip('/'),
                                                             op), p, who='NameSilo')
        reply = (got or {}).get('reply') if isinstance(got, dict) else None
        if not isinstance(reply, dict):
            raise PluginError('NameSilo answered something that is not JSON', detail=raw)
        code = str(reply.get('code'))
        if code != '300':
            words = 'NameSilo said %s: %s' % (code, reply.get('detail') or 'no')
            if code == '110':
                words += ' - the API key is wrong, or this address may not use it'
            raise PluginError(words, detail=reply, retry=code in ('113', '210', '400'))
        return reply

    def zone_names(self):
        doms = self._call('listDomains').get('domains')
        if isinstance(doms, dict):
            doms = doms.get('domain')
        out = []
        for d in _as_list(doms):
            out.append(d.get('domain') or d.get('name') if isinstance(d, dict) else d)
        return out

    def txt_records(self, zone, fqdn):
        return [(r.get('record_id'), r.get('value')) for r in
                _as_list(self._call('dnsListRecords', domain=zone).get('resource_record'))
                if isinstance(r, dict) and str(r.get('type')).upper() == 'TXT' and
                D.norm(r.get('host') or '') == fqdn]

    def create_txt(self, zone, fqdn, value):
        return self._call('dnsAddRecord', domain=zone, rrtype='TXT',
                          rrhost=rel_name(fqdn, zone, apex=''), rrvalue=value,
                          rrttl=str(self.ttl())).get('record_id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('dnsDeleteRecord', domain=zone, rrid=record_id)

    def wait_words(self):
        return RecordApiDns.wait_words(self) + '; NameSilo\'s name servers often take 15 minutes'
