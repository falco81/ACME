# -*- coding: utf-8 -*-
"""DNS-01 at deSEC.io (also a dedyn.io name), through its REST API:

    GET   https://desec.io/api/v1/domains/                     the domains of the account
    GET   .../domains/{domain}/rrsets/{subname}/TXT/            one RRset (404: none)
    PATCH .../domains/{domain}/rrsets/  [{subname, type, ttl, records}]
                                                                written whole; records [] removes it

Authorization: Token <token>. deSEC throttles (429 with Retry-After - waited
out), and takes no TTL under the domain's minimum_ttl (3600 unless deSEC
lowered it for the account). The RRset is read, our value added (or taken
away) and written back, so the values of other orders stay - the same as
the appliance's own deSEC certificates do it (acmelib/engine/270_dns_01_the_txt.py).
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                rmw_lock)

API = 'https://desec.io/api/v1'


class Desec(ApiDns):
    kind = 'desec'
    title = 'deSEC'
    vendor = 'deSEC'
    who = 'deSEC'
    min_ttl = 3600
    description = 'TXT records in a domain at deSEC.io (dedyn.io names too), with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='desec.io → Token management → +: a token of the account. Best one restricted '
                   'with a token policy to write TXT records at _acme-challenge names only, and '
                   'to the addresses acme calls from.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.dedyn.io',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=3600, advanced=True,
              help='deSEC takes no less than the domain\'s minimum TTL (3600 s, as a rule): '
                   'less is raised to it.'),
        field('settle', 'Wait after it is seen (seconds)', 'number', default=60, advanced=True,
              help='deSEC\'s name servers are anycast: once both have the record, other places '
                   'of the world may not yet, and the CA asks from several. This many seconds '
                   'more before the CA is told to look.'),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'Authorization': 'Token ' + str(self.c('token', ''))}, who='deSEC',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        return [d.get('name') for d in self._call('GET', '/domains/') or []]

    def _domain(self, zone):
        info = self._call('GET', '/domains/%s/' % urllib.parse.quote(zone), missing_ok=True)
        if info is None:
            raise PluginError('deSEC has no domain %s that the token may see' % zone, retry=False)
        return info

    def _rrset(self, zone, sub):
        got = self._call('GET', '/domains/%s/rrsets/%s/TXT/' % (
            urllib.parse.quote(zone), urllib.parse.quote(sub or '@')), missing_ok=True) or {}
        return list(got.get('records') or []), got.get('ttl')

    def _write(self, zone, sub, ttl, records):
        self._call('PATCH', '/domains/%s/rrsets/' % urllib.parse.quote(zone),
                   [{'subname': sub, 'type': 'TXT', 'ttl': ttl, 'records': records}])

    def _ttl(self, info):
        return max(self.ttl(), int(info.get('minimum_ttl') or self.min_ttl))

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        sub = relative(fqdn, zone)
        sub = '' if sub == '@' else sub
        info = self._domain(zone)
        one = '"%s"' % value
        with rmw_lock('desec'):
            recs, _ttl = self._rrset(zone, sub)
            if one not in recs:
                self._write(zone, sub, self._ttl(info), recs + [one])
        return {'zone': zone, 'sub': sub}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        sub = h.get('sub')
        if sub is None:
            sub = relative(fqdn, zone)
            sub = '' if sub == '@' else sub
        one = '"%s"' % value
        with rmw_lock('desec'):
            recs, ttl = self._rrset(zone, sub)
            if one not in recs:
                return
            left = [r for r in recs if r != one]
            self._write(zone, sub, int(ttl or self.min_ttl), left)

    def ready(self, name, handle):
        if not ApiDns.ready(self, name, handle):
            return False
        key = 'settle:%s:%s' % ((handle or {}).get('fqdn'), (handle or {}).get('txt'))
        first = self._said.setdefault(key, time.time())
        wait = self.num('settle', 60)
        if time.time() < first + wait:
            self.say_once('desec-settle:' + key, '%d s more for deSEC\'s other places of the '
                          'world, then the CA is asked' % wait)
            return False
        return True

    def wait_words(self):
        return ApiDns.wait_words(self) + (
            '; then %d s more for deSEC\'s name servers elsewhere in the world (anycast). A TTL '
            'under the domain\'s minimum (3600 s as a rule) is raised to it' % self.num('settle', 60))

    def test(self):
        doms = self._call('GET', '/domains/') or []
        if self.c('zone'):
            info = self._domain(D.norm(self.c('zone')))
            return 'deSEC: signed in; the domain %s is there (minimum TTL %s s)' % (
                info.get('name'), info.get('minimum_ttl'))
        self._zone_list = [D.norm(d.get('name')) for d in doms]
        return ApiDns.test(self)
