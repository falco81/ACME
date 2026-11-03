# -*- coding: utf-8 -*-
"""DNS-01 through Azure DNS - an app registration (service principal) signing
in with a client secret (OAuth2 client credentials), the ARM REST API
(api-version 2018-05-01):

    GET    .../providers/Microsoft.Network/dnsZones                      the zones (nextLink)
    GET    .../dnsZones/{zone}/TXT/{relative name}       {etag, properties: {TTL, metadata,
                                                          TXTRecords: [{value: [..]}]}}
    PUT    the same, If-Match: <etag> (If-None-Match: * for a new one)   written whole
    DELETE the same, If-Match: <etag>                                    when ours was last

The record set is written whole, so it is read, ours added or taken away and
written back with the etag just read - "Specify the last-seen etag value to
prevent accidentally overwriting any concurrent changes" - keeping its TTL and
metadata; a write refused because the set changed meanwhile is read again and
tried again (three times at most). One value is one TXTRecords item of one
string, without quotes.

Checked against the user's collection (api-docs/azure_dns/): dns-2018-05-01.json
(azure-rest-api-specs, RecordSets_Get / CreateOrUpdate / Delete, the If-Match
and If-None-Match headers) and notes.md (https://learn.microsoft.com/en-us/rest/api/dns/record-sets/create-or-update,
https://learn.microsoft.com/en-us/azure/dns/dns-zones-records - relative names,
TTL 1 to 2147483647, the Etag table). Less certain: the status of an etag that
does not match (not documented - 412 and 409 are read as "changed meanwhile");
the token's scope https://management.azure.com/.default (only the <resource>/.default
form is documented).
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, api,
                                                relative, rmw_lock)

CLOUDS = {'public': ('https://login.microsoftonline.com', 'https://management.azure.com'),
          'china': ('https://login.chinacloudapi.cn', 'https://management.chinacloudapi.cn'),
          'usgov': ('https://login.microsoftonline.us', 'https://management.usgovcloudapi.net')}
API_VERSION = '2018-05-01'


class AzureDns(DnsChallenge):
    kind = 'azure_dns'
    api_provider = True             # its zones are asked of its API (guide)
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
        if limits.sharing(self.ctx):
            # one token for every run with these settings, for its lifetime
            return limits.session(limits.key_of(self, 'token'), self._sign_in)
        if self._token and time.time() < self._token_until - 60:
            return self._token
        self._token, life = self._sign_in()
        self._token_until = time.time() + life
        return self._token

    def _sign_in(self):
        login, mgmt = self._urls()
        body = urllib.parse.urlencode({
            'grant_type': 'client_credentials', 'client_id': self.c('client_id', ''),
            'client_secret': self.c('client_secret', ''), 'scope': mgmt + '/.default'}).encode()
        _st, got = api(self.ctx, 'POST', '%s/%s/oauth2/v2.0/token' % (
            login, urllib.parse.quote(str(self.c('tenant_id', '')))), raw_body=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}, who='Microsoft Entra')
        if not got or not got.get('access_token'):
            raise PluginError('Microsoft Entra gave no token', retry=False)
        return got['access_token'], float(got.get('expires_in') or 3000)

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

    def _read(self, path):
        """The record set as it is: {etag, ttl, metadata, records: [[strings], ..]} or None."""
        st, got = self._arm('GET', path, missing_ok=True)
        if st == 404 or not got:
            return None
        props = got.get('properties') or {}
        return {'etag': got.get('etag'), 'ttl': props.get('TTL'),
                'metadata': props.get('metadata'),
                'records': [list(r.get('value') or []) for r in props.get('TXTRecords') or []]}

    def _write(self, path, rs, records):
        """The set written back with the etag read (If-None-Match: * when it was not there)."""
        h = {}
        if rs is not None and rs.get('etag'):
            h['If-Match'] = rs['etag']
        elif rs is None:
            h['If-None-Match'] = '*'
        _login, mgmt = self._urls()
        url = '%s%s?api-version=%s' % (mgmt, path, API_VERSION)
        h['Authorization'] = 'Bearer ' + self.token()
        if records:
            props = {'TTL': int((rs or {}).get('ttl') or self.ttl()),
                     'TXTRecords': [{'value': r} for r in records]}
            if (rs or {}).get('metadata'):
                props['metadata'] = rs['metadata']
            api(self.ctx, 'PUT', url, {'properties': props}, h, who='Azure')
        else:
            api(self.ctx, 'DELETE', url, None, h, who='Azure', missing_ok=True)

    def _change(self, path, value, adding):
        last = None
        for attempt in range(3):
            rs = self._read(path)
            have = (rs or {}).get('records') or []
            joined = [''.join(r) for r in have]
            if adding == (value in joined):
                return                                  # as it should be already
            records = have + [[value]] if adding else [r for r in have if ''.join(r) != value]
            try:
                self._write(path, rs, records)
                return
            except PluginError as e:
                last = e
                if not any('said %d' % c in str(e) for c in (409, 412)):
                    raise
                self.ctx.step('Azure: the record set changed meanwhile - read again', 'warn')
        raise last

    def add_txt(self, fqdn, value):
        path = self._rs(fqdn)
        # the record set is written whole (PUT): one writer at a time here, the etag elsewhere
        with rmw_lock(('azure', path)):
            self._change(path, value, True)
        return {'path': path}

    def del_txt(self, fqdn, value, handle):
        path = (handle or {}).get('path') or self._rs(fqdn)
        with rmw_lock(('azure', path)):
            self._change(path, value, False)

    def test(self):
        zones = self._zone_list()
        return 'signed in to Azure; %d DNS zone(s): %s' % (len(zones), ', '.join(sorted(zones)))
