# -*- coding: utf-8 -*-
"""DNS-01 at Constellix (DigiCert), through its DNS API v1:

    GET    https://api.dns.constellix.com/v1/domains                     [{id, name}]
    GET    .../v1/domains/{id}/records/txt                               [{id, name, ttl, roundRobin: [{value}]}]
    POST   .../v1/domains/{id}/records/txt  {name, ttl, roundRobin: [{value, disableFlag}]}
    PUT    .../v1/domains/{id}/records/txt/{record id}  {name, ttl, roundRobin}   the record written whole
    DELETE .../v1/domains/{id}/records/txt/{record id}

Every request carries x-cns-security-token: "API key:HMAC:time" - time the
milliseconds since 1970, HMAC the base64 of HMAC-SHA1 of that time with the
secret key (this machine's clock must be right). A TXT record of Constellix
keeps every value of its name ("roundRobin", each value in quotes): ours is
added to it, cleanup writes it back without ours, or deletes it when ours
was its last value - one change at a time on this node. "name" is relative
to the domain ("" the apex).

Sources: Constellix's official Go client (https://github.com/Constellix/
constellix-go-client: client/client.go - the base address and getToken();
models/model_txt.go) and its official Terraform provider
(https://github.com/Constellix/terraform-provider-constellix:
constellix/resource_constellix_txt_record.go and
datasource_constellix_domain.go - v1/domains, v1/domains/{id}/records/txt,
POST, GET, PUT and DELETE by id, the values quoted by the server); the API
reference is https://api-docs.constellix.com. Cross-checked with lego's
providers/dns/constellix.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                rmw_lock, unquote_txt)

API = 'https://api.dns.constellix.com'


def cns_token(key, secret, now_ms=None):
    """x-cns-security-token: "key:base64(HMAC-SHA1(secret, ms)):ms"."""
    ms = str(int(time.time() * 1000) if now_ms is None else int(now_ms))
    mac = base64.b64encode(hmac.new(secret.encode(), ms.encode(), hashlib.sha1).digest())
    return '%s:%s:%s' % (key, mac.decode(), ms)


class Constellix(ApiDns):
    kind = 'constellix'
    title = 'Constellix'
    vendor = 'Constellix'
    who = 'Constellix'
    min_ttl = 60
    description = 'TXT records in a domain at Constellix DNS, with an API key and its secret.'
    fields = [
        field('api_key', 'API key', 'text', required=True,
              help='The API key of your Constellix account (its API keys, in the account\'s '
                   'profile): the API key here, the secret key below.'),
        field('secret_key', 'Secret key', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                      {'x-cns-security-token': cns_token(str(self.c('api_key', '')),
                                                          str(self.c('secret_key', '')))},
                      who='Constellix', missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _domains(self):
        if getattr(self, '_doms', None) is None:
            got = self._call('GET', '/v1/domains') or []
            self._doms = {D.norm(d.get('name')): d.get('id') for d in got
                          if isinstance(d, dict) and d.get('name')}
        return self._doms

    def zone_names(self):
        return list(self._domains())

    def _id(self, zone):
        did = self._domains().get(D.norm(zone))
        if did is None:
            raise PluginError('Constellix has no domain %s that this key may see' % zone,
                              retry=False)
        return did

    @staticmethod
    def _values(rec):
        return [v.get('value') for v in (rec.get('roundRobin') or rec.get('value') or [])
                if isinstance(v, dict) and v.get('value') is not None]

    def _record(self, did, name):
        for r in self._call('GET', '/v1/domains/%s/records/txt' % did) or []:
            if isinstance(r, dict) and (r.get('name') or '') == name:
                return r
        return None

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        did = self._id(zone)
        name = '' if relative(fqdn, zone) == '@' else relative(fqdn, zone)
        with rmw_lock('constellix'):
            rec = self._record(did, name)
            if rec is None:
                self._call('POST', '/v1/domains/%s/records/txt' % did, {
                    'name': name, 'ttl': self.ttl(),
                    'roundRobin': [{'value': '"%s"' % value, 'disableFlag': False}]})
            else:
                have = self._values(rec)
                if value not in [unquote_txt(v) for v in have]:
                    self._call('PUT', '/v1/domains/%s/records/txt/%s' % (did, rec.get('id')), {
                        'name': name, 'ttl': rec.get('ttl') or self.ttl(),
                        'roundRobin': [{'value': v, 'disableFlag': False} for v in have] +
                        [{'value': '"%s"' % value, 'disableFlag': False}]})
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        did = self._id(zone)
        name = '' if relative(fqdn, zone) == '@' else relative(fqdn, zone)
        with rmw_lock('constellix'):
            rec = self._record(did, name)
            if rec is None:
                return
            have = self._values(rec)
            left = [v for v in have if unquote_txt(v) != value]
            if len(left) == len(have):
                return
            path = '/v1/domains/%s/records/txt/%s' % (did, rec.get('id'))
            if left:
                self._call('PUT', path, {'name': name, 'ttl': rec.get('ttl') or self.ttl(),
                                         'roundRobin': [{'value': v, 'disableFlag': False}
                                                        for v in left]})
            else:
                self._call('DELETE', path, missing_ok=True)
