# -*- coding: utf-8 -*-
"""DNS-01 at Mythic Beasts (UK), through its DNS API v2:

    POST   https://auth.mythic-beasts.com/login   grant_type=client_credentials
           (basic authentication: key ID and secret)                  -> {access_token, expires_in}
    GET    https://api.mythic-beasts.com/dns/v2/zones                    {zones: [name]}
    GET    .../zones/{zone}/records/{host}/TXT                           {records: [{host, type, data, ttl}]}
    POST   .../zones/{zone}/records/{host}/TXT  {records: [{host, ttl, type, data}]}   {records_added}
    DELETE .../zones/{zone}/records/{host}/TXT?data={value}                            {records_removed}

"host" is relative to the zone, "@" the apex. A value is removed by its
data, so other values at the name stay. The API key is made in the control
panel (API keys) with the zone (or only _acme-challenge records) allowed.

Sources: https://www.mythic-beasts.com/support/api/dnsv2 and
https://www.mythic-beasts.com/support/api/auth - not reachable from where
this was written; as lego's providers/dns/mythicbeasts sends it.
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, basic, form_call, rel_name

API = 'https://api.mythic-beasts.com/dns/v2'
AUTH = 'https://auth.mythic-beasts.com/login'


class MythicBeasts(RecordApiDns):
    kind = 'mythic_beasts'
    title = 'Mythic Beasts'
    vendor = 'Mythic Beasts'
    who = 'Mythic Beasts'
    min_ttl = 60
    description = 'TXT records in a zone at Mythic Beasts, with a DNS API key.'
    fields = [
        field('key_id', 'API key ID', 'text', required=True,
              help='Mythic Beasts control panel → API keys → create a key with DNS API access '
                   'to the zone (it can be limited to _acme-challenge records of type TXT).'),
        field('secret', 'API secret', 'secret', required=True),
        field('zone', 'Zone', 'text', default='', placeholder='example.co.uk',
              help='Empty: the longest zone the key sees that the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True),
        field('auth', 'Sign-in address', 'text', default=AUTH, advanced=True),
    ] + PROPAGATION_FIELDS

    def _token(self):
        if limits.sharing(self.ctx):
            # one token for every run with these settings, for its lifetime
            return limits.session(limits.key_of(self, 'token'), self._sign_in)
        if getattr(self, '_tok', None) and self._tok[1] > time.time() + 30:
            return self._tok[0]
        tok, life = self._sign_in()
        self._tok = (tok, time.time() + life)
        return tok

    def _sign_in(self):
        _st, got, _raw = form_call(self.ctx, 'POST', str(self.c('auth', AUTH)),
                                   {'grant_type': 'client_credentials'},
                                   {'Authorization': basic(self.c('key_id', ''),
                                                           self.c('secret', ''))},
                                   who='Mythic Beasts (sign-in)')
        tok = (got or {}).get('access_token')
        if not tok:
            raise PluginError('Mythic Beasts: signed in, but no token came back', retry=False)
        return tok, float((got or {}).get('expires_in') or 300)

    def _call(self, method, path, body=None):
        _st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                       {'Authorization': 'Bearer ' + self._token()}, who='Mythic Beasts',
                       missing_ok=method == 'GET')
        return got or {}

    def _path(self, zone, fqdn):
        return '/zones/%s/records/%s/TXT' % (urllib.parse.quote(zone),
                                             urllib.parse.quote(rel_name(fqdn, zone)))

    def zone_names(self):
        got = self._call('GET', '/zones').get('zones') or []
        return [z.get('name') if isinstance(z, dict) else z for z in got]

    def txt_records(self, zone, fqdn):
        return [(r.get('data'), r.get('data')) for r in
                self._call('GET', self._path(zone, fqdn)).get('records') or []
                if isinstance(r, dict) and str(r.get('type', 'TXT')).upper() == 'TXT']

    def create_txt(self, zone, fqdn, value):
        self._call('POST', self._path(zone, fqdn), {'records': [
            {'host': rel_name(fqdn, zone), 'ttl': self.ttl(), 'type': 'TXT', 'data': value}]})
        return value

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', self._path(zone, fqdn) + '?' + urllib.parse.urlencode(
            {'data': value}))
