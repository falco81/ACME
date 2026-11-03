# -*- coding: utf-8 -*-
"""DNS-01 through the OVHcloud API (application key, secret and consumer key,
each call signed with $1$ SHA-1 as OVH asks):

    GET    /1.0/domain/zone                                        [zone names]
    POST   /1.0/domain/zone/{zone}/record  {fieldType: TXT, subDomain, target, ttl}
    GET    /1.0/domain/zone/{zone}/record?fieldType=TXT&subDomain=  [ids]
    GET    /1.0/domain/zone/{zone}/record/{id}                     {target, ...}
    DELETE /1.0/domain/zone/{zone}/record/{id}
    POST   /1.0/domain/zone/{zone}/refresh                         after every change

The value is sent without quotes (OVH quotes a TXT target itself); a listed
target is compared with its quotes taken away. A TTL is 0 (the zone's) or at
least 60, as OVH's own Terraform provider checks. A record id 0 in the answer
(a known OVH bug) is not kept: cleanup then finds ours by its target.

Checked against the user's collection (api-docs/ovh/): domain-zone-dns.json
(from https://eu.api.ovh.com/1.0/domain.json), auth.json and notes.md
(https://docs.ovhcloud.com/en/guides/manage-and-operate/api/first-steps.md,
https://github.com/ovh/python-ovh ovh/client.py,
https://github.com/ovh/terraform-provider-ovh resource_domain_zone_record.go).
Less certain: that the refresh is needed (only OVH's Terraform provider says
so by calling it after every change); the rate limit of /domain (not found).
"""
from __future__ import annotations

import hashlib
import json
import time

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, api,
                                                relative)

ENDPOINTS = {'ovh-eu': 'https://eu.api.ovh.com/1.0', 'ovh-ca': 'https://ca.api.ovh.com/1.0',
             'ovh-us': 'https://api.us.ovhcloud.com/1.0'}


def ovh_signature(app_secret, consumer_key, method, url, body, ts):
    raw = '+'.join([app_secret, consumer_key, method.upper(), url, body, str(ts)])
    return '$1$' + hashlib.sha1(raw.encode()).hexdigest()


class Ovh(DnsChallenge):
    kind = 'ovh'
    api_provider = True             # its zones are asked of its API (guide)
    title = 'OVHcloud'
    vendor = 'OVHcloud'
    description = 'TXT records in a zone at OVHcloud, through its API.'
    fields = [
        field('endpoint', 'Endpoint', 'select', default='ovh-eu',
              options=[['ovh-eu', 'OVH Europe'], ['ovh-ca', 'OVH Canada'], ['ovh-us', 'OVH US']]),
        field('app_key', 'Application key', 'text', required=True,
              help='From https://eu.api.ovh.com/createToken/ with GET/POST/DELETE on '
                   '/domain/zone/*.'),
        field('app_secret', 'Application secret', 'secret', required=True),
        field('consumer_key', 'Consumer key', 'secret', required=True),
        field('zone', 'Zone', 'text', default='', help='Empty: the longest zone the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    _delta = None

    def _base(self):
        return ENDPOINTS.get(self.c('endpoint', 'ovh-eu'), ENDPOINTS['ovh-eu'])

    def _call(self, method, path, body=None, missing_ok=False):
        url = self._base() + path
        if self._delta is None:
            try:
                _st, got = api(self.ctx, 'GET', self._base() + '/auth/time', who='OVH')
                self._delta = int(got) - int(time.time())
            except (PluginError, TypeError, ValueError):
                self._delta = 0
        ts = int(time.time()) + self._delta
        data = json.dumps(body) if body is not None else ''
        h = {'X-Ovh-Application': str(self.c('app_key', '')),
             'X-Ovh-Consumer': str(self.c('consumer_key', '')),
             'X-Ovh-Timestamp': str(ts),
             'X-Ovh-Signature': ovh_signature(str(self.c('app_secret', '')),
                                              str(self.c('consumer_key', '')), method, url,
                                              data, ts)}
        if body is not None:
            h['Content-Type'] = 'application/json'
        return api(self.ctx, method, url, None, h, who='OVH', raw_body=data.encode() or None,
                   missing_ok=missing_ok)[1]

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        best = None
        for name in self._call('GET', '/domain/zone') or []:
            name = D.norm(name)
            if D.in_zone(fqdn, name) and (best is None or len(name) > len(best)):
                best = name
        if not best:
            raise PluginError('OVH has no zone for %s that these keys may see' % fqdn,
                              retry=False)
        return best

    def ttl(self):
        t = DnsChallenge.ttl(self)
        return 60 if 0 < t < 60 else t           # 0 (the zone's) or 60 and more

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        got = self._call('POST', '/domain/zone/%s/record' % zone, {
            'fieldType': 'TXT', 'subDomain': '' if relative(fqdn, zone) == '@' else
            relative(fqdn, zone), 'target': value, 'ttl': self.ttl()}) or {}
        self._call('POST', '/domain/zone/%s/refresh' % zone)
        return {'zone': zone, 'id': got.get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = [h['id']] if h.get('id') else []
        if not ids:
            sub = relative(fqdn, zone)
            for rid in self._call('GET', '/domain/zone/%s/record?fieldType=TXT&subDomain=%s' % (
                    zone, '' if sub == '@' else sub)) or []:
                rec = self._call('GET', '/domain/zone/%s/record/%s' % (zone, rid),
                                 missing_ok=True) or {}
                if str(rec.get('target', '')).strip('"') == value:
                    ids.append(rid)
        for rid in ids:
            self._call('DELETE', '/domain/zone/%s/record/%s' % (zone, rid), missing_ok=True)
        self._call('POST', '/domain/zone/%s/refresh' % zone)

    # -- discovery: the zones of the keys; the endpoint they belong to ------------
    def zone_names(self):
        return [z for z in self._call('GET', '/domain/zone') or [] if isinstance(z, str)]

    def discover_setup(self):
        """The zones (the Zone field). Keys refused at the endpoint set are tried at the
        other OVHcloud endpoints (keys are made for one of them): one that answers is
        offered for the Endpoint field, with its zones."""
        out = DnsChallenge.discover_setup(self)
        if 'zone' in out['choices'] or not out['notes']:
            return out
        now = self.c('endpoint', 'ovh-eu')
        works = []
        for ep in ENDPOINTS:
            if ep == now:
                continue
            other = type(self)(dict(self.config, endpoint=ep), self.ctx)
            try:
                other.zone_names()
            except PluginError:
                continue
            works.append(other)
        if not works:
            return out
        found = DnsChallenge.discover_setup(works[0])
        words = dict(next(f for f in self.fields if f['key'] == 'endpoint')['options'])
        self.offer(found, 'endpoint', [[o.c('endpoint'), words.get(o.c('endpoint'))]
                                       for o in works], pick=works[0].c('endpoint'))
        found['notes'] = out['notes'] + found['notes']
        return found

    def test(self):
        zones = self._call('GET', '/domain/zone') or []
        return 'the keys see %d zone(s): %s' % (len(zones), ', '.join(zones[:20]))
