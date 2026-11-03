# -*- coding: utf-8 -*-
"""DNS-01 at Websupport (websupport.sk / websupport.cz), through REST API v1
(https://rest.websupport.sk):

    GET    /v1/user/self/zone                          {items: [{name}]}
    GET    /v1/user/self/zone/{domain}/record          {items: [{id, type, name, content}]}
    POST   /v1/user/self/zone/{domain}/record  {type, name, content, ttl}   {status, item}
    DELETE /v1/user/self/zone/{domain}/record/{id}

Each request is signed: HMAC-SHA1 with the API secret over
"METHOD PATH UNIXTIME" (the path without the query), hex; sent as HTTP basic
authentication KEY:SIGNATURE, with a Date header of that same time
(YYYYmmddTHHMMSSZ, UTC). The clock of this machine has to be right.
Websupport has published a v2 API beside it (the scheme Active24 uses too -
see active24.py); v1 is the one documented for zones by name, and is used here.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, relative,
                                                unquote_txt)

API = 'https://rest.websupport.sk'


def ws_headers(key, secret, method, path, now=None, date_format='%Y%m%dT%H%M%SZ'):
    """The Authorization and Date headers of one signed request (Websupport and
    Active24 alike). The Date of REST API v2 is RFC 3339 (2025-01-31T12:00:00Z,
    date_format='%Y-%m-%dT%H:%M:%SZ'); v1 takes the basic ISO 8601 form."""
    ts = int(time.time() if now is None else now)
    canonical = '%s %s %d' % (method.upper(), urllib.parse.urlsplit(path).path, ts)
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha1).hexdigest()
    when = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(date_format)
    # X-Date as well (1.0.28): REST API v2 asks for it ("all request must contain a valid
    # X-Date header", rest.active24.cz/v2/docs/intro); Date stays, as v1 reads it.
    return {'Authorization': 'Basic ' + base64.b64encode(('%s:%s' % (key, sig)).encode()).decode(),
            'Date': when, 'X-Date': when}


class Websupport(ApiDns):
    kind = 'websupport'
    title = 'Websupport'
    vendor = 'Websupport'
    who = 'Websupport'
    description = 'TXT records in a domain at Websupport (.sk / .cz), with an API key and secret.'
    fields = [
        field('api_key', 'API key', 'text', required=True,
              help='admin.websupport.sk → (your name) → Security and login → API access → '
                   'Generate new access: the identifier here, the secret below. Limit it to '
                   'the address acme calls from where it is offered.'),
        field('api_secret', 'API secret', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.sk',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=600, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False, now=None):
        h = ws_headers(str(self.c('api_key', '')), str(self.c('api_secret', '')), method, path,
                       now)
        st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body, h,
                      who='Websupport', missing_ok=missing_ok)
        if st == 404 and missing_ok:
            return None
        if isinstance(got, dict) and got.get('status') == 'error':
            raise PluginError('Websupport said no: %s' % (got.get('errors') or got),
                              detail=got, retry=False)
        return got

    def zone_names(self):
        return [z.get('name') for z in (self._call('GET', '/v1/user/self/zone') or {}).get(
            'items') or []]

    def _ours(self, zone, rel, value):
        got = self._call('GET', '/v1/user/self/zone/%s/record' % urllib.parse.quote(zone)) or {}
        return [r['id'] for r in got.get('items') or []
                if r.get('type') == 'TXT' and (r.get('name') or '@') == rel and
                unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        have = self._ours(zone, rel, value)
        if have:
            return {'zone': zone, 'id': have[0]}
        got = self._call('POST', '/v1/user/self/zone/%s/record' % urllib.parse.quote(zone), {
            'type': 'TXT', 'name': rel, 'content': value, 'ttl': self.ttl()}) or {}
        return {'zone': zone, 'id': (got.get('item') or {}).get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = [h['id']] if h.get('id') else self._ours(zone, relative(fqdn, zone), value)
        for rid in ids:
            self._call('DELETE', '/v1/user/self/zone/%s/record/%s' % (
                urllib.parse.quote(zone), rid), missing_ok=True)
