# -*- coding: utf-8 -*-
"""DNS-01 at Openprovider, through its REST API (v1beta):

    POST   https://api.openprovider.eu/v1beta/auth/login  {username, password}    {data: {token, reseller_id}}
    GET    .../v1beta/dns/zones?limit=500&offset=N                   {data: {results: [{name, provider}], total}}
    GET    .../v1beta/dns/zones/{zone}/records?type=TXT&limit=500&offset=N
                                                                     {data: {results: [{name, type, value, ttl}], total}}
    PUT    .../v1beta/dns/zones/{zone}  {name, provider, records: {add: [{name, type, value, ttl}]}}
    PUT    .../v1beta/dns/zones/{zone}  {name, provider, records: {remove: [{name, type, value, ttl}]}}

Authorization: Bearer <token>; the token is kept (and shared) for a few
hours, a 401 signs in once more. Records are written with their name
relative to the zone ("" the apex); the list gives them whole
(www.example.com) - both are read. Each value is a record of its own: ours
is added, and cleanup removes only ours. *DNS* is "openprovider" (the
standard DNS) or "sectigo" (Premium DNS).

Sources: Openprovider's official API client, generated from its OpenAPI
description (https://github.com/openprovider/rest-client-php:
src/Auth/Api/AuthApi.php - /v1beta/auth/login; src/Dns/Api/ZoneServiceApi.php
- listZones, updateZone; src/Dns/Api/ZoneRecordServiceApi.php -
listZoneRecords and its query; the models AuthLoginRequest,
ZoneUpdateZoneRequest, ZoneRecordUpdates, ZoneRecord, RecordRecordInfo;
src/Base/Configuration.php - https://api.openprovider.eu) and Openprovider's
own WHMCS module (https://github.com/openprovider/Openprovider-WHMCS-domains:
OpenProvider/API/ApiHelper.php - removeDnsRecord() and updateDnsRecords()
through modifyZoneDnsRequest, the zone's provider; Controllers/System/
DnsController.php - names listed whole, written relative). Less certain:
the token's lifetime (acme keeps it six hours), the lowest TTL Openprovider
takes (600 is used) and whether the list filter type=TXT is honoured (the
answer is filtered again here).
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ApiDns, api, unquote_txt
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://api.openprovider.eu'
TOKEN_S = 6 * 3600


class Openprovider(RecordApiDns):
    kind = 'openprovider'
    title = 'Openprovider'
    vendor = 'Openprovider'
    who = 'Openprovider'
    min_ttl = 60
    description = 'TXT records in a DNS zone at Openprovider, with an API user.'
    fields = [
        field('user', 'User name', 'text', required=True,
              help='An Openprovider user with API access (best one of its own for acme, its '
                   'access limited to the address acme calls from).'),
        field('password', 'Password', 'secret', required=True),
        field('provider', 'DNS', 'select', default='openprovider',
              options=[['openprovider', 'Openprovider DNS'],
                       ['sectigo', 'Premium DNS (Sectigo)']]),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _base(self):
        return str(self.c('api', API)).rstrip('/')

    def _sign_in(self):
        _st, got = api(self.ctx, 'POST', self._base() + '/v1beta/auth/login',
                       {'username': self.c('user', ''), 'password': self.c('password', '')},
                       who='Openprovider (sign-in)')
        tok = ((got or {}).get('data') or {}).get('token') if isinstance(got, dict) else None
        if not tok:
            raise PluginError('Openprovider: signed in, but no token came back: %s' % (
                (got or {}).get('desc') if isinstance(got, dict) else got), retry=False)
        return tok, TOKEN_S

    def _token(self):
        if limits.sharing(self.ctx):
            return limits.session(limits.key_of(self, 'token'), self._sign_in)
        if getattr(self, '_tok', None) and self._tok[1] > time.time():
            return self._tok[0]
        tok, life = self._sign_in()
        self._tok = (tok, time.time() + life)
        return tok

    def _call(self, method, path, body=None):
        for again in (True, False):
            tok = self._token()
            try:
                _st, got = api(self.ctx, method, self._base() + path, body,
                               {'Authorization': 'Bearer ' + tok}, who='Openprovider')
            except PluginError as e:
                if again and 'said 401' in str(e):
                    if limits.sharing(self.ctx):
                        limits.session_drop(limits.key_of(self, 'token'), tok)
                    self._tok = None
                    continue
                raise
            if isinstance(got, dict) and got.get('code') not in (None, 0):
                raise PluginError('Openprovider said no (%s): %s' % (got.get('code'), got.get(
                    'desc') or got), detail=str(got), retry=False)
            return got if isinstance(got, dict) else {}

    def _pages(self, path, query):
        out, offset = [], 0
        for _page in range(40):
            q = dict(query, limit=500, offset=offset)
            data = (self._call('GET', path + '?' + urllib.parse.urlencode(q)) or {}).get(
                'data') or {}
            got = data.get('results') or []
            out += [r for r in got if isinstance(r, dict)]
            offset += len(got)
            if not got or offset >= int(data.get('total') or 0):
                break
        return out

    def zone_names(self):
        return [z.get('name') for z in self._pages('/v1beta/dns/zones', {})
                if z.get('name') and not z.get('is_deleted')]

    def _zpath(self, zone):
        return '/v1beta/dns/zones/' + urllib.parse.quote(D.norm(zone))

    def _records(self, zone, fqdn):
        rel = rel_name(fqdn, zone, apex='')
        return [r for r in self._pages(self._zpath(zone) + '/records', {'type': 'TXT'})
                if str(r.get('type', 'TXT')).upper() == 'TXT' and
                (D.norm(r.get('name') or zone) == D.norm(fqdn) or (r.get('name') or '') == rel)]

    def txt_records(self, zone, fqdn):
        return [(i, r.get('value')) for i, r in enumerate(self._records(zone, fqdn))]

    def _update(self, zone, what, recs):
        self._call('PUT', self._zpath(zone), {
            'name': D.norm(zone), 'provider': self.c('provider', 'openprovider'),
            'records': {what: recs}})

    def create_txt(self, zone, fqdn, value):
        self._update(zone, 'add', [{'name': rel_name(fqdn, zone, apex=''), 'type': 'TXT',
                                    'value': value, 'ttl': self.ttl()}])
        return None

    def delete_txt(self, zone, fqdn, record_id, value):
        mine = [r for r in self._records(zone, fqdn) if unquote_txt(r.get('value')) == value]
        if mine:
            self._update(zone, 'remove', [{'name': rel_name(fqdn, zone, apex=''),
                                           'type': 'TXT', 'value': r.get('value'),
                                           'ttl': r.get('ttl') or self.ttl()} for r in mine])

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        self.delete_txt(zone, D.norm(fqdn), None, value)

    def test(self):
        return ApiDns.test(self)
