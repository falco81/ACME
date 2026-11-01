# -*- coding: utf-8 -*-
"""DNS-01 at Exoscale, through API v2 (https://api-{zone}.exoscale.com/v2):

    GET    /dns-domain                        {dns-domains: [{id, unicode-name}]}
    GET    /dns-domain/{id}/record            {dns-domain-records: [{id, name, type, content}]}
    POST   /dns-domain/{id}/record  {name, type, content, ttl}
    DELETE /dns-domain/{id}/record/{record id}

Every request is signed (EXO2-HMAC-SHA256): HMAC-SHA256 with the API secret
over the lines

    METHOD /path
    body
    the values of the signed query arguments, joined (none here)
    (the signed headers - none, an empty line)
    expires (unix time)

base64, sent as  Authorization: EXO2-HMAC-SHA256 credential=KEY,expires=T,signature=SIG.
This is the scheme of Exoscale's own SDKs (egoscale v2/v3) as acme knows
them; the API is only asked without query arguments, so that part stays empty.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, no_zone,
                                                relative, unquote_txt)
from acmelib.plugins.challenges import _dns as D


def exo2_auth(key, secret, method, url, body, expires):
    """The Authorization header of one request."""
    path = urllib.parse.urlsplit(url).path
    msg = '\n'.join(['%s %s' % (method.upper(), path),
                     (body or b'').decode('utf-8') if isinstance(body, bytes) else body or '',
                     '', '', str(int(expires))])
    sig = base64.b64encode(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest())
    return 'EXO2-HMAC-SHA256 credential=%s,expires=%d,signature=%s' % (
        key, int(expires), sig.decode())


class Exoscale(ApiDns):
    kind = 'exoscale'
    title = 'Exoscale'
    vendor = 'Exoscale'
    who = 'Exoscale'
    description = 'TXT records in an Exoscale DNS domain, with an API key (signed requests).'
    fields = [
        field('api_key', 'API key', 'text', required=True, placeholder='EXO...',
              help='portal.exoscale.com → IAM → API keys → Add: with a role that may use the '
                   'DNS operations (list-dns-domains, list-dns-domain-records, '
                   'create-dns-domain-record, delete-dns-domain-record).'),
        field('api_secret', 'API secret', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the organization the name is in.'),
        field('api_zone', 'API zone', 'text', default='ch-gva-2', advanced=True,
              help='The Exoscale zone whose API is called (DNS is the same from each).'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _base(self):
        return 'https://api-%s.exoscale.com/v2' % (str(self.c('api_zone', 'ch-gva-2')).strip()
                                                   or 'ch-gva-2')

    def _call(self, method, path, body=None, missing_ok=False, now=None):
        url = self._base() + path
        raw = json.dumps(body).encode() if body is not None else b''
        expires = int(time.time() if now is None else now) + 600
        h = {'Authorization': exo2_auth(str(self.c('api_key', '')), str(self.c('api_secret', '')),
                                        method, url, raw, expires)}
        if body is not None:
            h['Content-Type'] = 'application/json'
        st, got = api(self.ctx, method, url, None, h, who='Exoscale', raw_body=raw or None,
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _zone_ids(self):
        if getattr(self, '_ids', None) is None:
            self._ids = {D.norm(d.get('unicode-name')): d.get('id') for d in
                         (self._call('GET', '/dns-domain') or {}).get('dns-domains') or []}
        return self._ids

    def zone_names(self):
        return list(self._zone_ids())

    def _id(self, zone):
        did = self._zone_ids().get(zone)
        if not did:
            raise no_zone('Exoscale', zone)
        return did

    def _ours(self, did, rel, value):
        name = '' if rel == '@' else rel
        got = self._call('GET', '/dns-domain/%s/record' % did) or {}
        return [r['id'] for r in got.get('dns-domain-records') or []
                if r.get('type') == 'TXT' and (r.get('name') or '') == name and
                unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        did, rel = self._id(zone), relative(fqdn, zone)
        if not self._ours(did, rel, value):
            self._call('POST', '/dns-domain/%s/record' % did, {
                'name': '' if rel == '@' else rel, 'type': 'TXT', 'content': value,
                'ttl': self.ttl()})
        return {'domain_id': did, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        did = h.get('domain_id') or self._id(self.zone_for(fqdn))
        rel = h.get('rel') or relative(fqdn, self.zone_for(fqdn))
        for rid in self._ours(did, rel, value):
            self._call('DELETE', '/dns-domain/%s/record/%s' % (did, rid), missing_ok=True)
