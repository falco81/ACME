# -*- coding: utf-8 -*-
"""DNS-01 at Active24, on either of its two platforms (1.0.24):

* **REST API v2** (rest.active24.cz - the Czech and Slovak Active24 on the
  Websupport platform; its OpenAPI 3 description, rest.active24.cz/v2/docs,
  "Rest API 2.0.0"):

    GET    /v2/check                                   {verified} - signed in?
    GET    /v1/user/self/service                       the services: [{id, serviceName, name}]
    GET    /v1/user/self/zone/{domain}                 one domain's service: {id, ...}
    GET    /v2/service/{id}/dns/zone                   {name, lastCheck, dnssecSigning}
    GET    /v2/service/{id}/dns/record?filters[type][]=TXT&filters[name]={sub}
                                                       {currentPage, data: [{id, type, name,
                                                        content, ttl}], ...}
    POST   /v2/service/{id}/dns/record  {type, name, content, ttl}     204
    DELETE /v2/service/{id}/dns/record/{record id}                     204

  signed as Websupport signs (websupport.py: HMAC-SHA1 over "METHOD PATH
  UNIXTIME", HTTP basic KEY:SIGNATURE - the description's securityScheme
  basicAuth), with a Date header of that time in RFC 3339. The two /v1 lookups
  are not in the v2 description; they are as acme.sh's dns_active24.sh and
  lego's providers/dns/internal/active24 use them - a domain not found there is
  set by its service ID (then its name is read from /v2/service/{id}/dns/zone).

* **Active24 API** (api.active24.com - Active24's own API, "Active24 REST API
  Documentation", Swagger 2.0), with a token (Authorization: Bearer):

    GET    /dns/domains/v1                             ["example.com", ...]
    GET    /dns/{domain}/records/v1                    [{hashId, type, name, text, ttl}]
    POST   /dns/{domain}/txt/v1   {name, text, ttl}                    204
    DELETE /dns/{domain}/{hashId}/v1                                   204

  as the description says; the fields of a record listed (hashId, type,
  text) as Posh-ACME's Active24 plugin (rmbolger/Posh-ACME
  Plugins/Active24.ps1) reads them, the description naming only name and ttl
  for the list's items.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, no_zone,
                                                relative, unquote_txt)
from acmelib.plugins.challenges.websupport import ws_headers

API = 'https://rest.active24.cz'
API_COM = 'https://api.active24.com'
V2_DATE = '%Y-%m-%dT%H:%M:%SZ'      # the Date header, RFC 3339 (as lego's v2 client sends it)


class Active24(ApiDns):
    kind = 'active24'
    title = 'Active24'
    vendor = 'Active24'
    who = 'Active24'
    description = ('TXT records in a domain at Active24 - through its REST API v2 '
                   '(rest.active24.cz) or its Active24 API (api.active24.com).')
    fields = [
        field('platform', 'API', 'select', default='rest',
              options=[['rest', 'REST API v2 - rest.active24.cz (an API key and secret)'],
                       ['com', 'Active24 API - api.active24.com (a token)']],
              help='Which one your account has: the Czech and Slovak administration (on the '
                   'Websupport platform) gives a key and a secret; the older Active24 '
                   'administration a token.'),
        field('api_key', 'API key', 'text', required=True, show_if={'platform': ['rest']},
              help='The Active24 administration → (your name) → Security and login → API '
                   'access → Generate new access: the identifier here, the secret below.'),
        field('api_secret', 'API secret', 'secret', required=True,
              show_if={'platform': ['rest']}),
        field('token', 'API token', 'secret', required=True, show_if={'platform': ['com']},
              help='The token of the Active24 API (the administration → API).'),
        field('zone', 'Domain', 'text', default='', placeholder='example.cz',
              help='Empty: the longest domain of the account the name is in.'),
        field('service_id', 'Service ID', 'text', default='', advanced=True,
              show_if={'platform': ['rest']},
              help='The domain\'s service number in the administration. Empty: found in the '
                   'list of services.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True),
        field('api', 'API address', 'text', default='', advanced=True,
              placeholder='https://rest.active24.cz',
              help='Empty: the platform\'s own (rest.active24.cz or api.active24.com).'),
    ] + PROPAGATION_FIELDS

    def _com(self):
        return str(self.c('platform') or 'rest') == 'com'

    def _base(self):
        given = str(self.c('api') or '').strip().rstrip('/')
        if given and not (self._com() and given == API):
            return given
        return API_COM if self._com() else API

    def _call(self, method, path, body=None, missing_ok=False, now=None):
        if self._com():
            h = {'Authorization': 'Bearer %s' % str(self.c('token', ''))}
        else:
            h = ws_headers(str(self.c('api_key', '')), str(self.c('api_secret', '')), method,
                           path, now, date_format=V2_DATE)
        st, got = api(self.ctx, method, self._base() + path, body, h, who='Active24',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    # -- api.active24.com ------------------------------------------------------------
    def _com_records(self, zone, rel, value):
        got = self._call('GET', '/dns/%s/records/v1' % urllib.parse.quote(zone)) or []
        if isinstance(got, dict):
            got = got.get('data') or got.get('items') or []
        return [r.get('hashId') for r in got if isinstance(r, dict) and r.get('hashId') and
                str(r.get('type') or 'TXT').upper() == 'TXT' and
                D.norm(r.get('name') or '@') in (D.norm(rel or '@'), D.norm(
                    (rel + '.' + zone) if rel and rel != '@' else zone)) and
                unquote_txt(r.get('text') if r.get('text') is not None else r.get('content'))
                == value]

    def _services(self):
        if getattr(self, '_ids', None) is None:
            got = self._call('GET', '/v1/user/self/service') or []
            if isinstance(got, dict):
                got = got.get('items') or got.get('data') or []
            self._ids = {D.norm(s.get('name')): s.get('id') for s in got
                         if isinstance(s, dict) and s.get('name') and
                         s.get('serviceName', 'domain') == 'domain'}
        return self._ids

    def zone_names(self):
        if self._com():
            got = self._call('GET', '/dns/domains/v1') or []
            return [d if isinstance(d, str) else (d or {}).get('name') for d in got
                    if d] if isinstance(got, list) else []
        names = list(self._services())
        if self.c('service_id'):
            got = self._call('GET', '/v2/service/%s/dns/zone' % self.c('service_id'),
                             missing_ok=True) or {}
            if got.get('name'):
                names.append(D.norm(got['name']))
        return names

    def zone_hint(self, fqdn):
        if self.c('service_id') and not self.c('zone') and not self._com():
            got = self._call('GET', '/v2/service/%s/dns/zone' % self.c('service_id'),
                             missing_ok=True) or {}
            if got.get('name'):
                return D.norm(got['name'])      # the service's own zone (/v2 .../dns/zone)
            return None                         # the zone by its SOA
        return ApiDns.zone_hint(self, fqdn)

    def _sid(self, zone):
        if self.c('service_id'):
            return str(self.c('service_id'))
        sid = self._services().get(zone)
        if not sid:
            # Not in the list of services: asked for that domain itself (acme.sh's way).
            got = self._call('GET', '/v1/user/self/zone/%s' % urllib.parse.quote(zone),
                             missing_ok=True) or {}
            sid = got.get('id') if isinstance(got, dict) else None
            if sid:
                self._ids[zone] = sid
        if not sid:
            raise no_zone('Active24', zone)
        return sid

    def _ours(self, sid, rel, value):
        got = self._call('GET', '/v2/service/%s/dns/record?%s' % (sid, urllib.parse.urlencode(
            [('filters[type][]', 'TXT'), ('filters[name]', rel)]))) or {}
        return [r['id'] for r in got.get('data') or []
                if r.get('type') == 'TXT' and (r.get('name') or '@') == rel and
                unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        if self._com():
            rel = relative(fqdn, zone)
            have = self._com_records(zone, rel, value)
            if have:
                return {'zone': zone, 'hash': have[0]}
            self._call('POST', '/dns/%s/txt/v1' % urllib.parse.quote(zone), {
                'name': rel, 'text': value, 'ttl': self.ttl()})
            got = self._com_records(zone, rel, value)
            return {'zone': zone, 'hash': got[0] if got else None}
        sid, rel = self._sid(zone), relative(fqdn, zone)
        have = self._ours(sid, rel, value)
        if have:
            return {'sid': sid, 'id': have[0]}
        got = self._call('POST', '/v2/service/%s/dns/record' % sid, {
            'type': 'TXT', 'name': rel, 'content': value, 'ttl': self.ttl()}) or {}
        return {'sid': sid, 'id': got.get('id') if isinstance(got, dict) else None}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        if self._com():
            zone = h.get('zone') or self.zone_for(fqdn)
            hashes = [h['hash']] if h.get('hash') else self._com_records(
                zone, relative(fqdn, zone), value)
            for one in hashes:
                try:
                    self._call('DELETE', '/dns/%s/%s/v1' % (urllib.parse.quote(zone),
                                                            urllib.parse.quote(str(one))),
                               missing_ok=True)
                except PluginError as e:
                    # gone already: 400 DNS_RECORD_TO_DELETE_NOT_FOUND (its description)
                    if 'DNS_RECORD_TO_DELETE_NOT_FOUND' not in str(e):
                        raise
            return
        zone = self.zone_for(fqdn)
        sid = h.get('sid') or self._sid(zone)
        ids = [h['id']] if h.get('id') else self._ours(sid, relative(fqdn, zone), value)
        for rid in ids:
            self._call('DELETE', '/v2/service/%s/dns/record/%s' % (sid, rid), missing_ok=True)

    def test(self):
        if not self._com():
            got = self._call('GET', '/v2/check') or {}
            if isinstance(got, dict) and got.get('verified') is False:
                raise PluginError('Active24 did not take the API key and secret '
                                  '(/v2/check: not verified)', retry=False)
        if self.c('service_id') and not self._com():
            self._call('GET', '/v2/service/%s/dns/record?filters[type][]=TXT' % self.c(
                'service_id'))
            return 'Active24: signed in; the service %s answers' % self.c('service_id')
        return ApiDns.test(self)

