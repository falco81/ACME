# -*- coding: utf-8 -*-
"""DNS-01 in the DNS of a DirectAdmin server, through its legacy API (1.0.26):

    GET  https://{server}:2222/CMD_API_SHOW_DOMAINS              list[]=example.com&list[]=...
    GET  .../CMD_API_DNS_CONTROL?domain=example.com&urlencoded=yes
         one line a type, url encoded:  TXT=<name>=<value>&<name>=<value>  (values in quotes)
    POST .../CMD_API_DNS_CONTROL  domain=..&action=add&type=TXT&name=_acme-challenge.www&value=..
    POST .../CMD_API_DNS_CONTROL  domain=..&action=select&txtrecs0=<url encoded "name=..&value=..">
                                  that record (by its name and value) away
         -> error=0|1&text=..&details=..

Signed in with basic authentication: the DirectAdmin user and a login key
(Account → Login Keys - best one for acme alone, limited to acme's address).
Each value is a record of its own and is removed by its name and value, so
other values at the name stay. The record is read back after each change to
see it done.

DirectAdmin's new API (/api/..., its swagger.json) has no DNS calls, so the
legacy CMD_API_DNS_CONTROL is used.

Sources (the user's collection of DirectAdmin's documentation,
api-docs/directadmin/notes.md, quoting): https://docs.directadmin.com/developer/api/
(basic authentication, login keys, impersonation with "|"),
https://docs.directadmin.com/developer/api/legacy-api.html (CMD_API_SHOW_DOMAINS,
list[]), and the changelog entries that describe CMD_API_DNS_CONTROL:
https://docs.directadmin.com/changelog/version-1.24.2.html (action=add,
action=select with selecttype=encoded "name=www&value=1.2.3.4"),
https://docs.directadmin.com/changelog/version-1.26.4.html (urlencoded=yes and
its TXT line), https://docs.directadmin.com/changelog/version-1.31.0.html
("txtrecs"), https://docs.directadmin.com/changelog/version-1.53.1.html (TXT
among the types, records told apart by their value),
https://docs.directadmin.com/changelog/version-1.28.2.html (error=0|1, text,
details); api-docs/directadmin_ssl/directadmin-swagger.json (no DNS in the new
API).

Less certain (the documentation leaves it open): CMD_API_DNS_CONTROL is
described only in the changelog, with no example for TXT - type=TXT on add
and txtrecs0 on select follow the pattern documented for the other types
(arecs0, nsrecs0, ... and "txtrecs"); whether a TXT value is sent with its
quotes (it is added without them; on delete the name and value are sent as
the listing gives them, quotes and all); the shape of an error answer to
these calls (error=1 with text and details, as other legacy calls); no TTL is
sent (the zone's own, per-record TTL needs dns_ttl=1 on the server). Because
of that, every change is read back, and a record still there after the
delete is said in the job, never taken for done.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, as_bool, http_call, relative,
                                                said_error, unquote_txt)
from acmelib.plugins.challenges._records import RecordApiDns, SoftZones, basic, zone_field


class DirectAdmin(SoftZones, RecordApiDns):
    kind = 'directadmin'
    title = 'DirectAdmin'
    vendor = 'DirectAdmin'
    who = 'DirectAdmin'
    min_ttl = 1                     # no TTL is sent
    description = 'TXT records in the DNS of a DirectAdmin server, with a login key.'
    fields = [
        field('host', 'DirectAdmin address', 'text', required=True,
              placeholder='server.example.com',
              help='The DirectAdmin server as its panel is reached (name, name:port or '
                   'https://…); the port is 2222 when not given.'),
        field('user', 'User name', 'text', required=True,
              help='The DirectAdmin user the domains belong to (an admin or reseller acting for '
                   'a user: admin|user).'),
        field('password', 'Login key', 'secret', required=True,
              help='A login key made for acme (Login Keys in DirectAdmin) - best limited to '
                   'CMD_API_SHOW_DOMAINS and CMD_API_DNS_CONTROL and to acme\'s address. The '
                   'user\'s password works too.'),
        zone_field(['host', 'user', 'password'], label='Domain'),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _base(self):
        h = str(self.c('host', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the DirectAdmin address is not set', retry=False)
        u = urllib.parse.urlsplit(h if '://' in h else 'https://' + h)
        try:
            port = u.port
        except ValueError:
            raise PluginError('the DirectAdmin address %s has a port that is not a number' % h,
                              retry=False)
        host = u.hostname or ''
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%d' % (u.scheme or 'https', host, port or 2222)

    def _cmd(self, method, cmd, params):
        """The answer's text of a legacy command; error=1 a PluginError in words."""
        url = '%s/%s' % (self._base(), cmd)
        h = {'Authorization': basic(self.c('user', ''), self.c('password', '')),
             'User-Agent': 'acme-challenge'}
        data = None
        if method == 'GET':
            url += '?' + urllib.parse.urlencode(params)
        else:
            data = urllib.parse.urlencode(params).encode()
            h['Content-Type'] = 'application/x-www-form-urlencoded'
        st, _rh, got = http_call(self.ctx, method, url, data, h, who='DirectAdmin',
                                 verify=as_bool(self.c('verify_tls', True)))
        text = got.decode('utf-8', 'replace') if isinstance(got, bytes) else str(got or '')
        if st != 200:
            raise said_error('DirectAdmin', st, None, got)
        if '<html' in text[:500].lower():
            raise PluginError('DirectAdmin answered a web page, not the API - is the user or '
                              'the login key wrong, or the key not allowed %s?' % cmd,
                              detail=text[:300], retry=False)
        if text.startswith('error='):
            ans = dict(urllib.parse.parse_qsl(text.strip(), keep_blank_values=True))
            if ans.get('error') not in ('0', None):
                words = ans.get('details') or ans.get('text') or text[:200]
                raise PluginError('DirectAdmin said no to %s: %s' % (cmd, words.strip()),
                                  detail=text[:500])
        return text

    # -- zones and records -----------------------------------------------------------------
    def zone_names(self):
        text = self._cmd('GET', 'CMD_API_SHOW_DOMAINS', [])
        return [v for k, v in urllib.parse.parse_qsl(text.strip(), keep_blank_values=True)
                if k in ('list[]', 'list') and v]

    def _txt(self, zone):
        """[(name as listed, value as listed)] of the zone's TXT records."""
        text = self._cmd('GET', 'CMD_API_DNS_CONTROL', [('domain', D.norm(zone)),
                                                        ('urlencoded', 'yes')])
        for line in text.replace('\r\n', '\n').split('\n'):
            if line.startswith('TXT='):
                return urllib.parse.parse_qsl(line[4:].strip(), keep_blank_values=True)
        return []

    @staticmethod
    def _at(name, fqdn, zone):
        n = str(name or '').strip()
        if n.endswith('.'):
            return D.norm(n) == D.norm(fqdn)
        return D.norm(n + '.' + zone if n not in ('', '@') else zone) == D.norm(fqdn)

    def txt_records(self, zone, fqdn):
        return [((n, v), v) for n, v in self._txt(zone) if self._at(n, fqdn, zone)]

    def create_txt(self, zone, fqdn, value):
        self._cmd('POST', 'CMD_API_DNS_CONTROL', [
            ('domain', D.norm(zone)), ('action', 'add'), ('type', 'TXT'),
            ('name', relative(fqdn, zone)), ('value', value)])
        if not self._ours(zone, fqdn, value):
            raise PluginError('DirectAdmin took the TXT record %s, but it is not in the zone '
                              'when read again' % fqdn)
        return None

    def delete_txt(self, zone, fqdn, record_id, value):
        name, listed = record_id
        self._cmd('POST', 'CMD_API_DNS_CONTROL', [
            ('domain', D.norm(zone)), ('action', 'select'),
            ('txtrecs0', 'name=%s&value=%s' % (name, listed))])   # url encoded once, as documented

    def del_txt(self, fqdn, value, handle):
        RecordApiDns.del_txt(self, fqdn, value, handle)
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        if self._ours(zone, fqdn, value):
            raise PluginError('DirectAdmin did not take the TXT record %s "%s" away - remove '
                              'it in its DNS management by hand' % (fqdn, value), retry=False)

    def _ours(self, zone, fqdn, value):
        return [rid for rid, v in self.txt_records(zone, D.norm(fqdn)) or []
                if unquote_txt(v) == value]

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            return 'DirectAdmin: signed in; the domain %s has %d TXT record(s)' % (
                z, len(self._txt(z)))
        return RecordApiDns.test(self)
