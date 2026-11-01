# -*- coding: utf-8 -*-
"""DNS-01 through the OVHcloud API (application key, secret and consumer key,
each call signed with $1$ SHA-1 as OVH asks)."""
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

    def test(self):
        zones = self._call('GET', '/domain/zone') or []
        return 'the keys see %d zone(s): %s' % (len(zones), ', '.join(zones[:20]))
