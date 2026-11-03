# -*- coding: utf-8 -*-
"""DNS-01 at Hurricane Electric's free DNS (dns.he.net), through its dynamic
update for TXT records:

    POST https://dyn.dns.he.net/nic/update  hostname={fqdn}&password={key}&txt={value}
         -> "good {value}" | "nochg {value}" | "badauth" | "interval" | ...

What it can and cannot do - dns.he.net has no API besides this:
  * the TXT record has to exist first: made by hand in dns.he.net, at
    _acme-challenge.NAME, with "Enable entry for dynamic dns" ticked, and a
    key generated for it (the circular-arrows button) - one key per record;
  * that record holds ONE value: it is changed, never added to. So two
    orders that need the same name at once (example.com and *.example.com in
    one certificate are two values at one name) cannot both be proved: acme
    proves such names one after another (this module is not parallel) and
    refuses a second value while the first is in use;
  * cleanup cannot remove the record, only set it to a harmless value
    ("Value when idle");
  * Test cannot try a key without changing the record: it only checks that
    each record is there, asking HE's name servers.
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, DnsChallenge, as_list,
                                                http_call)

URL = 'https://dyn.dns.he.net/nic/update'
HE_NS = ('ns1.he.net', 'ns2.he.net', 'ns3.he.net', 'ns4.he.net', 'ns5.he.net')
IN_USE_S = 3600


class HeNet(ApiDns):
    kind = 'he_net'
    discovery = False               # discovery: nothing to read from an account
    title = 'Hurricane Electric (dns.he.net)'
    vendor = 'Hurricane Electric'
    who = 'dns.he.net'
    parallel = False
    description = 'The TXT record at _acme-challenge.NAME, made by hand at dns.he.net for ' \
                  'dynamic updates, changed with its key. One value a name at a time.'
    fields = [
        field('keys', 'Records and their keys', 'secret', multiline=True, required=True,
              placeholder='_acme-challenge.example.com  Kx9...\n_acme-challenge.www.example.com  P2b...',
              help='One line a record: its full name, then the key generated for it in '
                   'dns.he.net (the record made by hand there as TXT, "Enable entry for dynamic '
                   'dns" ticked). A line with only a key: used for every name not listed.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: found by its SOA.'),
        field('idle_value', 'Value when idle', 'text', default='acme-idle', advanced=True,
              help='What the record is set to on cleanup - dns.he.net cannot remove it.'),
    ] + PROPAGATION_FIELDS

    def zone_names(self):
        return None

    def zone_hint(self, fqdn):
        return DnsChallenge.zone_hint(self, fqdn)       # the zone set, else its SOA

    def _keys(self):
        out, default = {}, None
        for line in as_list(str(self.c('keys', '') or '').replace(',', '\n').replace(';', '\n')):
            bits = line.split()
            if len(bits) == 1:
                default = bits[0]
            elif len(bits) >= 2:
                out[D.norm(bits[0])] = bits[1]
        return out, default

    def _key(self, fqdn):
        keys, default = self._keys()
        k = keys.get(D.norm(fqdn)) or default
        if not k:
            raise PluginError('no dynamic key is set for %s: make the TXT record in dns.he.net, '
                              'generate its key and add the line "%s KEY"' % (fqdn, fqdn),
                              retry=False)
        return k

    def _update(self, fqdn, value):
        body = urllib.parse.urlencode({'hostname': D.norm(fqdn), 'password': self._key(fqdn),
                                       'txt': value}).encode()
        st, _rh, got = http_call(self.ctx, 'POST', URL, body, {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'acme-challenge'}, who='dns.he.net')
        said = (got or b'').decode('utf-8', 'replace').strip()
        word = said.split(' ', 1)[0].lower()
        if st == 200 and word in ('good', 'nochg'):
            return said
        hints = {'badauth': 'the key is wrong, or the record is not enabled for dynamic dns',
                 'nohost': 'there is no such record enabled for dynamic dns',
                 'interval': 'updated too often - wait a few minutes',
                 'abuse': 'updated too often - wait a few minutes'}
        raise PluginError('dns.he.net said "%s" for %s%s' % (
            said[:120] or st, fqdn, (' - ' + hints[word]) if word in hints else ''),
            detail=said, retry=word in ('interval', 'abuse') or st >= 500)

    def add_txt(self, fqdn, value):
        key = 'he_net:' + D.norm(fqdn)
        used = self.ctx.kv_get(key) or {}
        if isinstance(used, dict) and used.get('v') not in (None, value) and \
                time.time() - float(used.get('at') or 0) < IN_USE_S:
            raise PluginError('%s holds the value of another order now, and dns.he.net keeps one '
                              'value a name - it is tried again once that order is done' % fqdn)
        self._update(fqdn, value)
        self.ctx.kv_set(key, {'v': value, 'at': time.time()}, ttl_s=IN_USE_S)
        return {'fqdn': D.norm(fqdn)}

    def del_txt(self, fqdn, value, handle):
        key = 'he_net:' + D.norm(fqdn)
        used = self.ctx.kv_get(key) or {}
        if isinstance(used, dict) and used.get('v') not in (None, value):
            return                              # another order's value now: left alone
        try:
            self._update(fqdn, str(self.c('idle_value', 'acme-idle') or 'acme-idle'))
        except PluginError as e:
            self.ctx.step('the TXT record %s was left as it is: %s' % (fqdn, e), 'warn')
        self.ctx.kv_set(key, {}, ttl_s=60)

    def test(self):
        keys, default = self._keys()
        if not keys and not default:
            raise PluginError('no record and key is set', retry=False)
        out = []
        for fqdn in sorted(keys):
            got = None
            for ns in HE_NS:
                addrs = D.addresses(ns, self.resolvers())
                for a in addrs[:1]:
                    try:
                        got = D.txt_at(a, fqdn, port=self.auth_port)
                    except (D.DnsError, D.FormErr, OSError):
                        continue
                if got is not None:
                    break
            if got is None:
                out.append('%s: HE\'s name servers did not answer' % fqdn)
            elif not got:
                out.append('%s: no TXT record at HE - make it first' % fqdn)
            else:
                out.append('%s: there (%s)' % (fqdn, ', '.join(got)[:60]))
        return 'dns.he.net: %s (a key cannot be tried without changing the record)' % (
            '; '.join(out) or 'one key for every name')
