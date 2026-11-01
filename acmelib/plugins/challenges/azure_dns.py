# -*- coding: utf-8 -*-
"""DNS-01 through Azure DNS - an app registration (service principal) signing
in with a client secret (OAuth2 client credentials), the ARM REST API."""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, api,
                                                relative)

CLOUDS = {'public': ('https://login.microsoftonline.com', 'https://management.azure.com'),
          'china': ('https://login.chinacloudapi.cn', 'https://management.chinacloudapi.cn'),
          'usgov': ('https://login.microsoftonline.us', 'https://management.usgovcloudapi.net')}
API_VERSION = '2018-05-01'


class AzureDns(DnsChallenge):
    kind = 'azure_dns'
    title = 'Azure DNS'
    vendor = 'Microsoft'
    description = 'TXT records in an Azure DNS zone, with an app registration\'s client secret.'
    fields = [
        field('tenant_id', 'Tenant (directory) ID', 'text', required=True),
        field('client_id', 'Client (application) ID', 'text', required=True,
              help='An app registration with the role "DNS Zone Contributor" on the zone (or '
                   'its resource group).'),
        field('client_secret', 'Client secret', 'secret', required=True),
        field('subscription_id', 'Subscription ID', 'text', required=True),
        field('resource_group', 'Resource group', 'text', default='',
              help='Of the DNS zone. Empty: every zone of the subscription is looked through.'),
        field('zone', 'Zone', 'text', default='', help='Empty: the longest zone the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('cloud', 'Cloud', 'select', default='public', advanced=True,
              options=[['public', 'Azure'], ['china', 'Azure China (21Vianet)'],
                       ['usgov', 'Azure US Government']]),
    ] + PROPAGATION_FIELDS

    _token = None
    _token_until = 0.0
    _zone_ids = None  # {zone: its ARM id}

    def _urls(self):
        return CLOUDS.get(self.c('cloud', 'public'), CLOUDS['public'])

    def token(self):
        if self._token and time.time() < self._token_until - 60:
            return self._token
        login, mgmt = self._urls()
        body = urllib.parse.urlencode({
            'grant_type': 'client_credentials', 'client_id': self.c('client_id', ''),
            'client_secret': self.c('client_secret', ''), 'scope': mgmt + '/.default'}).encode()
        _st, got = api(self.ctx, 'POST', '%s/%s/oauth2/v2.0/token' % (
            login, urllib.parse.quote(str(self.c('tenant_id', '')))), raw_body=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}, who='Microsoft Entra')
        if not got or not got.get('access_token'):
            raise PluginError('Microsoft Entra gave no token', retry=False)
        self._token = got['access_token']
        self._token_until = time.time() + float(got.get('expires_in') or 3000)
        return self._token

    def _arm(self, method, path, body=None, missing_ok=False):
        _login, mgmt = self._urls()
        sep = '&' if '?' in path else '?'
        return api(self.ctx, method, '%s%s%sapi-version=%s' % (mgmt, path, sep, API_VERSION), body,
                   {'Authorization': 'Bearer ' + self.token()}, who='Azure',
                   missing_ok=missing_ok)

    def _zone_list(self):
        if self._zone_ids is None:
            sub = urllib.parse.quote(str(self.c('subscription_id', '')))
            rg = self.c('resource_group', '')
            path = '/subscriptions/%s%s/providers/Microsoft.Network/dnsZones' % (
                sub, '/resourceGroups/%s' % urllib.parse.quote(rg) if rg else '')
            out = {}
            _st, got = self._arm('GET', path)
            for _page in range(50):
                for z in (got or {}).get('value') or []:
                    out[D.norm(z.get('name'))] = z.get('id')
                nxt = (got or {}).get('nextLink')
                if not nxt:
                    break
                _st, got = api(self.ctx, 'GET', nxt, None,
                               {'Authorization': 'Bearer ' + self.token()}, who='Azure')
            self._zone_ids = out
        return self._zone_ids

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        zones = self._zone_list()
        if z:
            return z
        best = None
        for name in zones:
            if D.in_zone(fqdn, name) and (best is None or len(name) > len(best)):
                best = name
        if not best:
            raise PluginError('Azure has no DNS zone for %s that this app may see' % fqdn,
                              retry=False)
        return best

    def _rs(self, fqdn):
        zone = self.zone_for(fqdn)
        zid = self._zone_list().get(zone)
        if not zid:
            raise PluginError('the zone %s is not in the subscription/resource group' % zone,
                              retry=False)
        return '%s/TXT/%s' % (zid, urllib.parse.quote(relative(fqdn, zone), safe='@'))

    def _values(self, path):
        st, got = self._arm('GET', path, missing_ok=True)
        if st == 404 or not got:
            return []
        return [''.join(r.get('value') or []) for r in
                (got.get('properties') or {}).get('TXTRecords') or []]

    def _put(self, path, values):
        if values:
            self._arm('PUT', path, {'properties': {'TTL': self.ttl(), 'TXTRecords': [
                {'value': [v]} for v in values]}})
        else:
            self._arm('DELETE', path, missing_ok=True)

    def add_txt(self, fqdn, value):
        path = self._rs(fqdn)
        have = self._values(path)
        if value not in have:
            self._put(path, have + [value])
        return {'path': path}

    def del_txt(self, fqdn, value, handle):
        path = (handle or {}).get('path') or self._rs(fqdn)
        have = self._values(path)
        if value in have:
            self._put(path, [v for v in have if v != value])

    def test(self):
        zones = self._zone_list()
        return 'signed in to Azure; %d DNS zone(s): %s' % (len(zones), ', '.join(sorted(zones)))
