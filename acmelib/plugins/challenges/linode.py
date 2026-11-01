# -*- coding: utf-8 -*-
"""DNS-01 at Linode (Akamai Cloud), through API v4:

    GET    https://api.linode.com/v4/domains?page=N           {data: [{id, domain}], pages}
    GET    .../domains/{id}/records?page=N                     {data: [{id, type, name, target}]}
    POST   .../domains/{id}/records  {type, name, target, ttl_sec}
    DELETE .../domains/{id}/records/{record id}

Every value is a record of its own, so two orders never touch each other's.
"""
from __future__ import annotations

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, no_zone,
                                                relative, unquote_txt)

API = 'https://api.linode.com/v4'


class Linode(ApiDns):
    kind = 'linode'
    title = 'Linode (Akamai)'
    vendor = 'Akamai'
    who = 'Linode'
    min_ttl = 300
    description = 'TXT records in a Linode domain, with a personal access token.'
    fields = [
        field('token', 'Personal access token', 'secret', required=True,
              help='cloud.linode.com → (your name) → API Tokens → Create a Personal Access '
                   'Token: Domains "Read/Write", nothing else.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='Linode rounds it to the values it knows (300 at least).'),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, API + path, body,
                      {'Authorization': 'Bearer ' + str(self.c('token', ''))}, who='Linode',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _all(self, path):
        out, page = [], 1
        while True:
            got = self._call('GET', '%s%spage=%d&page_size=500' % (
                path, '&' if '?' in path else '?', page)) or {}
            out += got.get('data') or []
            if page >= int(got.get('pages') or 1) or page >= 50:
                return out
            page += 1

    def _domains(self):
        if getattr(self, '_doms', None) is None:
            self._doms = {d.get('domain', '').lower(): d.get('id') for d in self._all('/domains')}
        return self._doms

    def zone_names(self):
        return list(self._domains())

    def _id(self, zone):
        did = self._domains().get(zone)
        if did is None:
            raise no_zone('Linode', zone)
        return did

    def _ours(self, did, rel, value):
        name = '' if rel == '@' else rel
        return [r['id'] for r in self._all('/domains/%s/records' % did)
                if r.get('type') == 'TXT' and (r.get('name') or '') == name and
                unquote_txt(r.get('target')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        did, rel = self._id(zone), relative(fqdn, zone)
        have = self._ours(did, rel, value)
        if have:
            return {'domain_id': did, 'id': have[0]}
        got = self._call('POST', '/domains/%s/records' % did, {
            'type': 'TXT', 'name': '' if rel == '@' else rel, 'target': value,
            'ttl_sec': self.ttl()}) or {}
        return {'domain_id': did, 'id': got.get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        did = h.get('domain_id')
        if not did:
            did = self._id(self.zone_for(fqdn))
        ids = [h['id']] if h.get('id') else self._ours(did, relative(fqdn, self.zone_for(fqdn)),
                                                       value)
        for rid in ids:
            self._call('DELETE', '/domains/%s/records/%s' % (did, rid), missing_ok=True)
