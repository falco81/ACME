# -*- coding: utf-8 -*-
"""DNS-01 at Duck DNS (free names under duckdns.org), through its update URL:

    GET https://www.duckdns.org/update?domains={sub}&token={token}&txt={value}&verbose=true
    GET ...&clear=true                        the TXT value taken away
        -> "OK\\n..." | "KO"

What it can and cannot do - Duck DNS has nothing besides this:
  * a name holds ONE TXT value, and Duck DNS answers it for the name and
    every name under it (_acme-challenge.SUB.duckdns.org included). Two
    values at once (SUB.duckdns.org and *.SUB.duckdns.org in one
    certificate) cannot both be there: acme proves such names one after
    another (this module is not parallel) and refuses a second value while
    the first is in use;
  * your own name can be proved through it: _acme-challenge.www.example.com
    CNAME SUB.duckdns.org (the CNAME is followed);
  * "KO" says only that something is wrong (the token, the name);
  * Test cannot try the token without changing the TXT value: it asks Duck
    DNS's name servers what the names hold.

Source: https://www.duckdns.org/spec.jsp - not reachable from where this was
written; as lego's providers/dns/duckdns, acme.sh's dnsapi/dns_duckdns.sh and
Posh-ACME's DuckDNS plugin call it.
"""
from __future__ import annotations

import time

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ApiDns, as_list
from acmelib.plugins.challenges._records import form_call

API = 'https://www.duckdns.org/update'
IN_USE_S = 3600


class DuckDns(ApiDns):
    kind = 'duckdns'
    discovery = False               # discovery: nothing to read from an account
    title = 'Duck DNS'
    vendor = 'Duck DNS'
    who = 'Duck DNS'
    parallel = False
    min_ttl = 60
    description = 'The TXT value of a name at Duck DNS (duckdns.org), with the account\'s ' \
                  'token. One value a name at a time.'
    fields = [
        field('token', 'Token', 'secret', required=True,
              help='duckdns.org → signed in: the token shown at the top of the page.'),
        field('domains', 'Duck DNS names', 'list', required=True,
              placeholder='myhome\nmyoffice.duckdns.org',
              help='The names of the account acme may set the TXT value of (with or without '
                   '.duckdns.org). A name of your own is proved through one of them by a CNAME: '
                   '_acme-challenge.www.example.com CNAME myhome.duckdns.org.'),
        field('zone', 'Zone', 'text', default='', advanced=True,
              help='Empty: the Duck DNS name the record is under.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS


    # DuckDNS keeps one TXT value per subdomain of duckdns.org - not a record at any
    # name: it proves ACME's _acme-challenge, not a commercial CA's DCV.
    @classmethod
    def proofs_for(cls, config):
        return ['acme-dns-01']

    def _names(self):
        out = []
        for d in as_list(self.c('domains', '')):
            d = D.norm(d)
            if not d.endswith('.duckdns.org'):
                d += '.duckdns.org'
            out.append(d)
        return out

    def zone_names(self):
        return self._names()

    def _sub(self, fqdn):
        z = self.zone_for(fqdn)
        if not z.endswith('.duckdns.org'):
            raise PluginError('%s is not under a Duck DNS name - point it there by a CNAME'
                              % fqdn, retry=False)
        return z, z[:-len('.duckdns.org')]

    def _update(self, sub, **more):
        p = {'domains': sub, 'token': str(self.c('token', '')), 'verbose': 'true'}
        p.update(more)
        _st, _got, raw = form_call(self.ctx, 'GET', str(self.c('api', API)), p, who='Duck DNS')
        said = (raw or b'').decode('utf-8', 'replace').strip()
        if not said.startswith('OK'):
            raise PluginError('Duck DNS said "%s" for %s - check the token and that the name '
                              'is one of the account' % (said[:40] or 'nothing', sub),
                              retry=False)
        return said

    def add_txt(self, fqdn, value):
        zone, sub = self._sub(fqdn)
        key = 'duckdns:' + zone
        used = self.ctx.kv_get(key) or {}
        if isinstance(used, dict) and used.get('v') not in (None, value) and \
                time.time() - float(used.get('at') or 0) < IN_USE_S:
            raise PluginError('%s holds the value of another order now, and Duck DNS keeps one '
                              'value a name - it is tried again once that order is done' % zone)
        self._update(sub, txt=value)
        self.ctx.kv_set(key, {'v': value, 'at': time.time()}, ttl_s=IN_USE_S)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone, sub = self._sub(fqdn)
        key = 'duckdns:' + zone
        used = self.ctx.kv_get(key) or {}
        if isinstance(used, dict) and used.get('v') not in (None, value):
            return                              # another order's value now: left alone
        self._update(sub, txt='', clear='true')
        self.ctx.kv_set(key, {}, ttl_s=60)

    def authority(self, fqdn):
        """The name servers asked: duckdns.org's own (SUB is no zone of its own)."""
        try:
            return 'duckdns.org', D.zone_servers('duckdns.org', self.resolvers())
        except D.DnsError as e:
            self.say_once('ns:duckdns.org', 'the name servers of duckdns.org could not be '
                          'found: %s' % e, 'warn')
            return 'duckdns.org', []

    def test(self):
        names = self._names()
        if not names:
            raise PluginError('no Duck DNS name is set', retry=False)
        if not str(self.c('token', '') or ''):
            raise PluginError('no token is set', retry=False)
        return 'Duck DNS: %s (the token cannot be tried without changing the TXT value)' % (
            ', '.join(names))
