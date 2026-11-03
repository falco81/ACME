# -*- coding: utf-8 -*-
"""DNS-01 in Infoblox NIOS, through WAPI (the Grid Master's REST API):

    GET    https://GM/wapi/v2.10/zone_auth?view=V&_return_fields=fqdn     [{_ref, fqdn}]
    GET    .../record:txt?name={fqdn}&view=V&_return_fields=name,text     [{_ref, name, text}]
    POST   .../record:txt  {name, text, ttl, use_ttl, view}               -> its _ref
    DELETE .../{_ref}

HTTP basic authentication. Each value is a record:txt of its own. The Grid
Master's certificate is often made by the organisation's own CA: give that CA
(PEM) rather than switching the check off.
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, DnsChallenge, api,
                                                as_bool, discover_read, unquote_txt)


class Infoblox(ApiDns):
    kind = 'infoblox'
    title = 'Infoblox NIOS (WAPI)'
    vendor = 'Infoblox'
    who = 'Infoblox'
    description = 'TXT records in an Infoblox NIOS authoritative zone, through WAPI.'
    fields = [
        field('url', 'Grid Master', 'text', required=True, placeholder='https://gm.example.local',
              help='The address of the Grid Master (or its VIP), without /wapi.'),
        field('wapi_version', 'WAPI version', 'text', default='2.10', advanced=True,
              help='What the grid speaks: Help → About, or /wapi/v1.0/?_schema.'),
        field('username', 'User name', 'text', required=True,
              help='An admin of a group with the "API" access and read-write permission on the '
                   'zones (or only on TXT records in them) - best a user of its own for acme.'),
        field('password', 'Password', 'secret', required=True),
        field('view', 'DNS view', 'text', default='default'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest authoritative zone of the view the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('verify_tls', 'Check the Grid Master\'s certificate', 'bool', default=True),
        field('ca_pem', 'CA of the Grid Master\'s certificate', 'pem', default='',
              show_if={'verify_tls': [True]},
              help='The CA (PEM) that signed the Grid Master\'s certificate, where it is not one '
                   'this machine trusts already. Empty: the system\'s CAs.'),
    ] + PROPAGATION_FIELDS
    # discovery signs in to the Grid Master (its WAPI version and CA are how it is
    # reached); the view and the zone are read
    discover_keys = ['url', 'wapi_version', 'username', 'password', 'verify_tls', 'ca_pem']

    def _base(self):
        u = str(self.c('url', '')).rstrip('/')
        if not u:
            raise PluginError('the Grid Master\'s address is not set', retry=False)
        if not u.startswith(('http://', 'https://')):
            u = 'https://' + u
        return '%s/wapi/v%s' % (u, str(self.c('wapi_version', '2.10')).lstrip('v'))

    def _call(self, method, path, body=None, missing_ok=False):
        auth = base64.b64encode(('%s:%s' % (self.c('username', ''), self.c('password', '')))
                                .encode()).decode()
        verify = as_bool(self.c('verify_tls', True))
        st, got = api(self.ctx, method, self._base() + path, body,
                      {'Authorization': 'Basic ' + auth}, who='Infoblox', verify=verify,
                      ca_pem=(self.c('ca_pem') or None) if verify else None,
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def _view(self):
        return urllib.parse.quote(str(self.c('view', 'default') or 'default'))

    def zone_names(self):
        return [z.get('fqdn') for z in self._call(
            'GET', '/zone_auth?view=%s&_return_fields=fqdn&_max_results=10000' % self._view()) or []]

    # -- discovery: the DNS views of the grid, the zones of the view ---------------
    def discover_setup(self):
        """The zones of the view set (the Zone field) and the grid's DNS views (GET
        /view - the DNS view field)."""
        out = DnsChallenge.discover_setup(self)
        views = discover_read(out, lambda: self._call('GET', '/view?_return_fields=name'),
                              'the DNS views could not be listed: %s') or []
        names = sorted({str(v['name']) for v in views if isinstance(v, dict) and v.get('name')})
        self.offer(out, 'view', [[v, v] for v in names],
                   pick=str(self.c('view', 'default') or 'default'))
        if 'view' in out['choices'] and len(names) > 1:
            out['notes'].append('the zones offered are those of the view %s - choose another '
                                'view and ask again for its zones' % (
                                    self.c('view', 'default') or 'default'))
        return out

    def _ours(self, fqdn, value):
        got = self._call('GET', '/record:txt?name=%s&view=%s&_return_fields=name,text' % (
            urllib.parse.quote(D.norm(fqdn)), self._view())) or []
        return [r['_ref'] for r in got if D.norm(r.get('name')) == D.norm(fqdn) and
                unquote_txt(r.get('text')) == value]

    def add_txt(self, fqdn, value):
        self.zone_for(fqdn)
        have = self._ours(fqdn, value)
        if have:
            return {'ref': have[0]}
        ref = self._call('POST', '/record:txt', {
            'name': D.norm(fqdn), 'text': value, 'ttl': self.ttl(), 'use_ttl': True,
            'view': str(self.c('view', 'default') or 'default'),
            'comment': 'acme DNS-01'})
        return {'ref': ref if isinstance(ref, str) else None}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        refs = [h['ref']] if h.get('ref') else self._ours(fqdn, value)
        for ref in refs:
            self._call('DELETE', '/' + ref, missing_ok=True)
