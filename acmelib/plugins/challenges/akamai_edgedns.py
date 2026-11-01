# -*- coding: utf-8 -*-
"""DNS-01 at Akamai Edge DNS (Fast DNS), through its Zone Management API v2,
signed with EdgeGrid (EG1-HMAC-SHA256) written here:

    GET    https://{host}/config-dns/v2/zones?showAll=true&types=primary   {zones: [{zone}]}
    GET    .../config-dns/v2/zones/{zone}/names/{fqdn}/types/TXT          {name, type, ttl, rdata: ['"v"']}  (404: none)
    POST   ... the same, {name, type: "TXT", ttl, rdata}                  the RRset made
    PUT    ... the same                                                   the RRset written whole
    DELETE ... the same                                                   the RRset away

EdgeGrid: Authorization: EG1-HMAC-SHA256 client_token=..;access_token=..;
timestamp=YYYYmmddTHH:MM:SS+0000;nonce=..;signature=..; the signing key is
base64(HMAC-SHA256(client_secret, timestamp)); the data signed is METHOD \\t
https \\t host \\t path?query \\t (canonical headers: none here) \\t
base64(SHA-256 of a POST body, the first max_body bytes; empty otherwise)
\\t the auth header so far. The RRset is read, our value added (or taken
away) and written back, one change at a time on this node.

Sources: https://techdocs.akamai.com/developer/docs/authenticate-with-edgegrid
and https://techdocs.akamai.com/edge-dns/reference/ - not reachable from where
this was written; EdgeGrid is checked against Akamai's own test cases
(AkamaiOPEN-edgegrid-python, test/testcases.json), the DNS calls as
Posh-ACME's Akamai plugin and lego's providers/dns/edgedns make them. The
API client needs "DNS—Zone Record Management" READ-WRITE.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import urllib.parse
import uuid

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ApiDns, api, rmw_lock

MAX_BODY = 131072


def _b64hmac(key, msg):
    return base64.b64encode(hmac.new(key.encode('utf-8'), msg.encode('utf-8'),
                                     hashlib.sha256).digest()).decode()


def edgegrid(method, url, body, client_token, client_secret, access_token, timestamp=None,
             nonce=None, max_body=MAX_BODY):
    """(Authorization header, data signed) of one request."""
    ts = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H:%M:%S+0000')
    head = 'EG1-HMAC-SHA256 client_token=%s;access_token=%s;timestamp=%s;nonce=%s;' % (
        client_token, access_token, ts, nonce or str(uuid.uuid4()))
    u = urllib.parse.urlsplit(url)
    path = (u.path or '/') + (('?' + u.query) if u.query else '')
    chash = ''
    if method.upper() == 'POST' and body:
        chash = base64.b64encode(hashlib.sha256(body[:max_body]).digest()).decode()
    data = '\t'.join([method.upper(), u.scheme, u.netloc.lower(), path, '', chash, head])
    key = _b64hmac(client_secret, ts)
    return head + 'signature=' + _b64hmac(key, data), data


class AkamaiEdgeDns(ApiDns):
    kind = 'akamai_edgedns'
    title = 'Akamai Edge DNS'
    vendor = 'Akamai'
    who = 'Akamai Edge DNS'
    min_ttl = 30
    description = 'TXT records in a primary zone at Akamai Edge DNS, with an EdgeGrid API client.'
    fields = [
        field('host', 'API host', 'text', required=True,
              placeholder='akab-xxxxxxxx.luna.akamaiapis.net',
              help='Akamai Control Center → Identity and access → API clients → a client with '
                   '"DNS—Zone Record Management" READ-WRITE: its host, client token, client '
                   'secret and access token (the .edgerc section).'),
        field('client_token', 'Client token', 'text', required=True),
        field('client_secret', 'Client secret', 'secret', required=True),
        field('access_token', 'Access token', 'secret', required=True),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone the client sees that the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        host = str(self.c('host', '')).strip().replace('https://', '').rstrip('/')
        url = 'https://%s%s' % (host, path)
        data = json.dumps(body).encode() if body is not None else None
        auth, _d = edgegrid(method, url, data, str(self.c('client_token', '')),
                            str(self.c('client_secret', '')), str(self.c('access_token', '')))
        h = {'Authorization': auth}
        if data is not None:
            h['Content-Type'] = 'application/json'
        st, got = api(self.ctx, method, url, headers=h, raw_body=data, who='Akamai Edge DNS',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        got = self._call('GET', '/config-dns/v2/zones?showAll=true&types=primary') or {}
        return [z.get('zone') for z in got.get('zones') or [] if isinstance(z, dict)]

    def _path(self, zone, fqdn):
        return '/config-dns/v2/zones/%s/names/%s/types/TXT' % (urllib.parse.quote(zone),
                                                               urllib.parse.quote(fqdn))

    def _rrset(self, zone, fqdn):
        got = self._call('GET', self._path(zone, fqdn), missing_ok=True)
        if not got:
            return None, []
        return got.get('ttl'), list(got.get('rdata') or [])

    def _write(self, zone, fqdn, method, ttl, rdata):
        self._call(method, self._path(zone, fqdn), {'name': fqdn, 'type': 'TXT', 'ttl': ttl,
                                                    'rdata': rdata}, missing_ok=method == 'DELETE')

    def add_txt(self, fqdn, value):
        zone, fqdn = self.zone_for(fqdn), D.norm(fqdn)
        one = '"%s"' % value
        with rmw_lock('akamai:' + str(self.c('client_token', ''))):
            ttl, have = self._rrset(zone, fqdn)
            if one not in have and value not in have:
                self._write(zone, fqdn, 'PUT' if have else 'POST', ttl or self.ttl(),
                            have + [one])
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        fqdn = D.norm(fqdn)
        with rmw_lock('akamai:' + str(self.c('client_token', ''))):
            ttl, have = self._rrset(zone, fqdn)
            left = [v for v in have if v not in ('"%s"' % value, value)]
            if len(left) == len(have):
                return
            if left:
                self._write(zone, fqdn, 'PUT', ttl or self.ttl(), left)
            else:
                self._call('DELETE', self._path(zone, fqdn), missing_ok=True)

    def test(self):
        if not str(self.c('host', '') or '').strip():
            raise PluginError('no API host is set', retry=False)
        return ApiDns.test(self)
