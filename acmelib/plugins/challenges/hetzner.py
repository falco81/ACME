# -*- coding: utf-8 -*-
"""DNS-01 at Hetzner: the Cloud API's DNS zones (api.hetzner.cloud, where Hetzner
DNS has moved), or the old DNS Console API (dns.hetzner.com)."""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, api,
                                                relative)


class Hetzner(DnsChallenge):
    kind = 'hetzner'
    title = 'Hetzner DNS'
    vendor = 'Hetzner'
    description = 'TXT records in a zone at Hetzner, with an API token.'
    fields = [
        field('api', 'API', 'select', default='cloud',
              options=[['cloud', 'Hetzner Console / Cloud API (api.hetzner.cloud)'],
                       ['dns', 'the old DNS Console (dns.hetzner.com)']]),
        field('token', 'API token', 'secret', required=True,
              help='Cloud: a project\'s API token with Read & Write. Old DNS Console: an API '
                   'token from dns.hetzner.com → API tokens.'),
        field('zone', 'Zone', 'text', default='', help='Empty: found by the name.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _cloud(self):
        return self.c('api', 'cloud') != 'dns'

    def _call(self, method, path, body=None, missing_ok=False):
        if self._cloud():
            url = 'https://api.hetzner.cloud/v1' + path
            h = {'Authorization': 'Bearer ' + str(self.c('token', ''))}
        else:
            url = 'https://dns.hetzner.com/api/v1' + path
            h = {'Auth-API-Token': str(self.c('token', ''))}
        return api(self.ctx, method, url, body, h, who='Hetzner', missing_ok=missing_ok)[1]

    def _zone(self, fqdn):
        want = D.norm(self.c('zone', ''))
        labels = D.norm(fqdn).split('.')
        cands = [want] if want else ['.'.join(labels[i:]) for i in range(len(labels) - 1)]
        for cand in cands:
            got = self._call('GET', '/zones?name=' + urllib.parse.quote(cand)) or {}
            for z in got.get('zones') or []:
                if D.norm(z.get('name')) == cand:
                    return str(z.get('id')), cand
        raise PluginError('Hetzner has no zone for %s that this token may see' % fqdn,
                          retry=False)

    def zone_hint(self, fqdn):
        try:
            return self._zone(fqdn)[1]
        except PluginError:
            return None

    def add_txt(self, fqdn, value):
        zid, zone = self._zone(fqdn)
        rel = relative(fqdn, zone)
        if self._cloud():
            self._call('POST', '/zones/%s/rrsets/%s/TXT/actions/add_records' % (
                zid, urllib.parse.quote(rel, safe='@')),
                {'ttl': self.ttl(), 'records': [{'value': '"%s"' % value}]})
            return {'zone_id': zid, 'rel': rel}
        got = self._call('POST', '/records', {'zone_id': zid, 'type': 'TXT', 'name': rel,
                                              'value': value, 'ttl': self.ttl()}) or {}
        return {'zone_id': zid, 'rel': rel, 'id': (got.get('record') or {}).get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        if not h.get('zone_id'):
            zid, zone = self._zone(fqdn)
            h = {'zone_id': zid, 'rel': relative(fqdn, zone)}
        if self._cloud():
            self._call('POST', '/zones/%s/rrsets/%s/TXT/actions/remove_records' % (
                h['zone_id'], urllib.parse.quote(h['rel'], safe='@')),
                {'records': [{'value': '"%s"' % value}]}, missing_ok=True)
            return
        ids = [h['id']] if h.get('id') else [
            r['id'] for r in (self._call('GET', '/records?zone_id=' + h['zone_id']) or {}).get(
                'records') or [] if r.get('type') == 'TXT' and r.get('name') == h['rel'] and
            r.get('value', '').strip('"') == value]
        for rid in ids:
            self._call('DELETE', '/records/' + rid, missing_ok=True)

    def test(self):
        got = self._call('GET', '/zones') or {}
        names = [z.get('name') for z in got.get('zones') or []]
        return 'the token sees %d zone(s): %s' % (len(names), ', '.join(names[:20]))
