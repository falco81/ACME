# -*- coding: utf-8 -*-
"""DNS-01 at Loopia (Sweden; also Loopia.rs and .no), through its XML-RPC API
(xmlrpc.client only writes and reads the XML here; ctx.http sends it):

    POST https://api.loopia.se/RPCSERV
    getDomains(user, password)                                -> [{domain, ...}]
    getZoneRecords(user, password, domain, subdomain)         -> [{type, ttl, priority, rdata, record_id}]
    addSubdomain(user, password, domain, subdomain)           -> "OK"
    addZoneRecord(user, password, domain, subdomain, {type, ttl, priority, rdata, record_id: 0}) -> "OK"
    removeZoneRecord(user, password, domain, subdomain, record_id)               -> "OK"
    removeSubdomain(user, password, domain, subdomain)        -> "OK"

Answers other than "OK" ("AUTH_ERROR", "UNKNOWN_ERROR", "RATE_LIMITED",
"BAD_INDATA") are refusals. The API user is made in Loopia's customer zone
(Account settings → LoopiaAPI) and needs the functions above allowed.

Sources: https://www.loopia.com/api/ (the function list) and
https://www.loopia.com/api/addzonerecord/ - not reachable from where this
was written; the calls are as lego's providers/dns/loopia sends them.
Loopia's name servers can take long to have a change (lego waits up to 40
minutes); the TTL is at least 300.
"""
from __future__ import annotations

import xmlrpc.client

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, http_call
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://api.loopia.se/RPCSERV'


class Loopia(RecordApiDns):
    kind = 'loopia'
    title = 'Loopia'
    vendor = 'Loopia'
    who = 'Loopia'
    min_ttl = 300
    description = 'TXT records in a domain at Loopia, through LoopiaAPI (XML-RPC).'
    fields = [
        field('user', 'API user', 'text', required=True, placeholder='acme@loopiaapi',
              help='Loopia customer zone → Account settings → LoopiaAPI → create an API user, '
                   'with getDomains, getZoneRecords, addSubdomain, addZoneRecord, '
                   'removeZoneRecord and removeSubdomain allowed.'),
        field('password', 'API password', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.se',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='Loopia takes 300 or more.'),
        field('api', 'API address', 'text', default=API, advanced=True,
              help='https://api.loopia.rs/RPCSERV for Loopia Serbia.'),
    ] + PROPAGATION_FIELDS

    def _rpc(self, method, *args):
        body = xmlrpc.client.dumps((str(self.c('user', '')), str(self.c('password', ''))) + args,
                                   method, encoding='utf-8').encode('utf-8')
        st, _rh, got = http_call(self.ctx, 'POST', str(self.c('api', API)), body, {
            'Content-Type': 'text/xml', 'User-Agent': 'acme-challenge'}, who='Loopia')
        if st != 200:
            raise PluginError('Loopia said %s' % st, detail=got, retry=st >= 500)
        try:
            ans = xmlrpc.client.loads(got)[0]
        except xmlrpc.client.Fault as e:
            raise PluginError('Loopia said no to %s: %s' % (method, e.faultString), detail=got)
        except Exception as e:                          # noqa: BLE001
            raise PluginError('Loopia answered something that is not XML-RPC (%s)' % e,
                              detail=got)
        ans = ans[0] if ans else None
        if isinstance(ans, str) and ans != 'OK':
            words = 'Loopia said %s to %s' % (ans, method)
            if ans == 'AUTH_ERROR':
                words += ' - the API user or password is wrong, or it may not call this'
            raise PluginError(words, retry=ans in ('RATE_LIMITED', 'UNKNOWN_ERROR'))
        if isinstance(ans, list) and ans and ans[0] == 'AUTH_ERROR':
            raise PluginError('Loopia said AUTH_ERROR - the API user or password is wrong',
                              retry=False)
        return ans

    def zone_names(self):
        return [d.get('domain') for d in self._rpc('getDomains') or [] if isinstance(d, dict)]

    def txt_records(self, zone, fqdn):
        sub = rel_name(fqdn, zone)
        return [(r.get('record_id'), r.get('rdata')) for r in
                self._rpc('getZoneRecords', zone, sub) or []
                if isinstance(r, dict) and str(r.get('type')).upper() == 'TXT']

    def create_txt(self, zone, fqdn, value):
        sub = rel_name(fqdn, zone)
        if sub != '@':
            try:
                self._rpc('addSubdomain', zone, sub)
            except PluginError as e:
                if 'AUTH_ERROR' in str(e):
                    raise
        self._rpc('addZoneRecord', zone, sub, {'type': 'TXT', 'ttl': self.ttl(), 'priority': 0,
                                               'rdata': value, 'record_id': 0})
        return None

    def delete_txt(self, zone, fqdn, record_id, value):
        sub = rel_name(fqdn, zone)
        self._rpc('removeZoneRecord', zone, sub, int(record_id))
        if sub != '@' and sub.startswith('_acme-challenge') and \
                not self._rpc('getZoneRecords', zone, sub):
            try:
                self._rpc('removeSubdomain', zone, sub)       # made by acme, now empty
            except PluginError as e:
                self.ctx.debug('Loopia removeSubdomain %s: %s' % (sub, e))

    def wait_words(self):
        return RecordApiDns.wait_words(self) + '; Loopia\'s name servers can take many minutes'
