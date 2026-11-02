# -*- coding: utf-8 -*-
"""DNS-01 at UltraDNS (Vercara, now DigiCert), through its REST API:

    POST   https://api.ultradns.com/v1/authorization/token
           grant_type=password&username=..&password=..                -> {accessToken, refreshToken, expiresIn}
    GET    .../v3/zones?limit=1000[&cursor=..]                         {zones: [{properties: {name}}], cursorInfo: {next}}
    GET    .../v1/zones/{zone}/rrsets/TXT/{owner}                      {rrSets: [{ownerName, ttl, rdata: [..]}]}  (404: none)
    POST   .../v1/zones/{zone}/rrsets/TXT/{owner}  {ttl, rdata}        the RRset made
    PUT    .../v1/zones/{zone}/rrsets/TXT/{owner}  {ttl, rdata}        the RRset written whole
    DELETE .../v1/zones/{zone}/rrsets/TXT/{owner}                      the RRset away

Authorization: Bearer <access token>; the token is kept for its lifetime
and shared (acmelib/plugins/limits.py), a 401 (or UltraDNS's error 60001,
"invalid token") signs in once more. The owner is written absolute (with its
final dot). The RRset is read, our value added (or taken away) and written
back - one change at a time on this node; the last value gone, the RRset is
deleted.

Sources: UltraDNS's official Python client (https://github.com/ultradns/
python_rest_api_client: src/ultra_rest_client/connection.py - auth(),
_refresh(), the Bearer header and errorCode 60001; ultra_rest_client.py -
get_zones_v3, get_rrsets_by_type_owner, create_rrset, edit_rrset,
delete_rrset) and its official Go SDK (https://github.com/ultradns/
ultradns-go-sdk: pkg/zone - v3/zones and its cursorInfo; pkg/rrset - the
rrSets fields); UltraDNS's REST API User Guide is
https://ultra-portalstatic.ultradns.com/static/docs/REST-API_User_Guide.pdf.
Cross-checked with lego's providers/dns/ultradns (which writes the RRset
whole and deletes it whole - acme keeps the other values).
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, rmw_lock,
                                                unquote_txt)
from acmelib.plugins.challenges._records import form_call

API = 'https://api.ultradns.com'


class UltraDns(ApiDns):
    kind = 'ultradns'
    title = 'UltraDNS'
    vendor = 'UltraDNS'
    who = 'UltraDNS'
    min_ttl = 60
    description = 'TXT records in a primary zone at UltraDNS (Vercara), with an API user.'
    fields = [
        field('user', 'User name', 'text', required=True,
              help='An UltraDNS user (best one of its own for acme) with the rights to change '
                   'records of the zones.'),
        field('password', 'Password', 'secret', required=True),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone the user sees that the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _base(self):
        return str(self.c('api', API)).rstrip('/')

    def _sign_in(self):
        _st, got, _raw = form_call(self.ctx, 'POST', self._base() + '/v1/authorization/token',
                                   {'grant_type': 'password', 'username': self.c('user', ''),
                                    'password': self.c('password', '')}, body=None,
                                   who='UltraDNS (sign-in)')
        got = got if isinstance(got, dict) else {}
        tok = got.get('accessToken') or got.get('access_token')
        if not tok:
            raise PluginError('UltraDNS: signed in, but no token came back', retry=False)
        life = float(got.get('expiresIn') or got.get('expires_in') or 3600)
        return tok, max(60.0, life - 60)

    def _token(self):
        if limits.sharing(self.ctx):
            return limits.session(limits.key_of(self, 'token'), self._sign_in)
        if getattr(self, '_tok', None) and self._tok[1] > time.time():
            return self._tok[0]
        tok, life = self._sign_in()
        self._tok = (tok, time.time() + life)
        return tok

    def _drop(self, tok):
        if limits.sharing(self.ctx):
            limits.session_drop(limits.key_of(self, 'token'), tok)
        self._tok = None

    def _call(self, method, path, body=None, missing_ok=False):
        for again in (True, False):
            tok = self._token()
            try:
                st, got = api(self.ctx, method, self._base() + path, body,
                              {'Authorization': 'Bearer ' + tok}, who='UltraDNS',
                              missing_ok=missing_ok)
            except PluginError as e:
                if again and ('said 401' in str(e) or '60001' in str(e.detail or '')):
                    self._drop(tok)
                    continue
                raise
            return None if st == 404 and missing_ok else got

    def zone_names(self):
        out, cursor = [], None
        for _page in range(50):
            path = '/v3/zones?limit=1000' + ('&cursor=' + urllib.parse.quote(cursor)
                                             if cursor else '')
            got = self._call('GET', path) or {}
            out += [(z.get('properties') or {}).get('name') for z in got.get('zones') or []
                    if isinstance(z, dict)]
            cursor = (got.get('cursorInfo') or {}).get('next')
            if not cursor:
                break
        return out

    def _path(self, zone, fqdn):
        return '/v1/zones/%s/rrsets/TXT/%s' % (urllib.parse.quote(D.norm(zone)),
                                               urllib.parse.quote(D.norm(fqdn) + '.'))

    def _rrset(self, zone, fqdn):
        got = self._call('GET', self._path(zone, fqdn), missing_ok=True)
        for rs in (got or {}).get('rrSets') or []:
            if isinstance(rs, dict):
                return rs.get('ttl'), [str(v) for v in rs.get('rdata') or []]
        return None, None

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        with rmw_lock('ultradns'):
            ttl, have = self._rrset(zone, fqdn)
            if have is None:
                self._call('POST', self._path(zone, fqdn), {'ttl': self.ttl(), 'rdata': [value]})
            elif value not in [unquote_txt(v) for v in have]:
                self._call('PUT', self._path(zone, fqdn), {'ttl': ttl or self.ttl(),
                                                           'rdata': have + [value]})
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        with rmw_lock('ultradns'):
            ttl, have = self._rrset(zone, fqdn)
            if not have:
                return
            left = [v for v in have if unquote_txt(v) != value]
            if len(left) == len(have):
                return
            if left:
                self._call('PUT', self._path(zone, fqdn), {'ttl': ttl or self.ttl(),
                                                           'rdata': left})
            else:
                self._call('DELETE', self._path(zone, fqdn), missing_ok=True)
