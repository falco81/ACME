# -*- coding: utf-8 -*-
"""DNS-01 at a Mail-in-a-Box server (its own name servers), through its
control panel API (https://BOX/admin):

    GET    https://{box}/admin/dns/zones                                ["example.com", ...]
    GET    .../admin/dns/custom/{qname}/TXT                             [{qname, rtype, value}]
    POST   .../admin/dns/custom/{qname}/TXT   body: the value (text/plain)   one value added
    DELETE .../admin/dns/custom/{qname}/TXT   body: the value (text/plain)   that one value removed

Basic authentication: an administrator's e-mail address and password. An
account with two-factor sign-in (TOTP) cannot sign in so (the code would be
needed each time; the session key of POST /admin/login lives two days at
most): give acme an administrator of its own without it. Each change makes
the box write its zone files and reload nsd; it keeps the TTL itself.

Sources: Mail-in-a-Box's own API description and code
(https://github.com/mail-in-a-box/mailinabox: api/mailinabox.yml - /dns/zones,
/dns/custom/{qname}/{rtype} with GET, POST, PUT, DELETE; and
management/daemon.py - dns_zones(), dns_get_records(), dns_set_record(): POST
adds a value next to the others, DELETE with a value removes only that
value), rendered at https://mailinabox.email/api-docs.html. Cross-checked
with lego's providers/dns/mailinabox.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ApiDns, api, as_bool
from acmelib.plugins.challenges._records import basic


class MailInABox(ApiDns):
    kind = 'mailinabox'
    title = 'Mail-in-a-Box'
    vendor = 'Mail-in-a-Box'
    who = 'Mail-in-a-Box'
    description = 'TXT records in the DNS a Mail-in-a-Box server keeps, through its control ' \
                  'panel API.'
    fields = [
        field('host', 'Box address', 'text', required=True, placeholder='box.example.com',
              help='The name (or https://name) of the Mail-in-a-Box server, as its control '
                   'panel is reached: https://box.example.com/admin.'),
        field('user', 'Administrator e-mail', 'text', required=True,
              placeholder='admin@example.com'),
        field('password', 'Password', 'secret', required=True,
              help='The administrator\'s password. An administrator with two-factor sign-in '
                   'cannot be used: make one for acme without it.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: the longest zone of the box the name is in.'),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _base(self):
        h = str(self.c('host', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the box address is not set', retry=False)
        if '://' not in h:
            h = 'https://' + h
        return h if h.endswith('/admin') else h + '/admin'

    def _call(self, method, path, value=None):
        h = {'Authorization': basic(self.c('user', ''), self.c('password', ''))}
        raw = None
        if value is not None:
            raw = value.encode('ascii')
            h['Content-Type'] = 'text/plain'
        _st, got = api(self.ctx, method, self._base() + path, None, h, who='Mail-in-a-Box',
                       raw_body=raw, verify=as_bool(self.c('verify_tls', True)))
        return got

    def zone_names(self):
        got = self._call('GET', '/dns/zones') or []
        return [z for z in got if isinstance(z, str)]

    def _path(self, fqdn):
        return '/dns/custom/%s/TXT' % urllib.parse.quote(D.norm(fqdn))

    def _have(self, fqdn):
        return [r.get('value') for r in self._call('GET', self._path(fqdn)) or []
                if isinstance(r, dict) and D.norm(r.get('qname') or '') == D.norm(fqdn) and
                str(r.get('rtype', 'TXT')).upper() == 'TXT']

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        if value not in self._have(fqdn):
            self._call('POST', self._path(fqdn), value)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        if value in self._have(fqdn):
            self._call('DELETE', self._path(fqdn), value)
