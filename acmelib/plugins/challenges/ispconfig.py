# -*- coding: utf-8 -*-
"""DNS-01 in the DNS of an ISPConfig 3 panel, through its Remote API - the
JSON transport (1.0.27):

    POST https://{panel}:8080/remote/json.php?login     {username, password}      -> session id
    POST ...?dns_zone_get         {session_id, primary_id: {origin: "example.com."}}
                                                       -> [{id, server_id, origin, ...}]
         (primary_id -1: every zone the remote user may see - the form's list)
    POST ...?dns_rr_get_all_by_zone {session_id, zone_id}  -> [{id, name, type, data, ttl}]
    POST ...?dns_txt_add          {session_id, client_id, params: {server_id, zone, name,
                                   type: txt, data, aux, ttl, active: y, ...}, update_serial: true}
                                                       -> the new record's id
    POST ...?dns_txt_delete       {session_id, primary_id: id, update_serial: true}
    POST ...?logout               {session_id}

Each answer is {code: "ok" | "remote_fault" | ..., message, response}; the
keys of a request are the names of the PHP function's parameters (missing
ones are null). The user is a remote user of the panel (System → Remote
Users) with the function groups "DNS zone functions" and "DNS txt functions",
from the addresses allowed for it; the Remote API must be allowed in the
security settings. A session is opened for each piece of work and closed
(it lives 30 minutes).

Each value is a record of its own (dns_rr) with its id: cleanup deletes only
ours. update_serial raises the zone's SOA serial with the change (without it
the secondaries may not take it). The name is written relative to the zone
(the BIND template prints it as it is, the origin appended), the value without
quotes (the template adds them). The panel applies changes through its server
cron, about a minute later: acme waits until the zone's name servers have
the value. TTL at least 60.

Sources (the user's collection, api-docs/ispconfig/notes.md - from the official
ISPConfig 3.3.2p1 package, https://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz):
remoting_client/API-docs (login.html, dns_txt_add.html, dns_txt_delete.html,
dns_zone_get_by_user.html, dns_rr_get_all_by_zone.html), remoting_client/examples
(rest_example.php, dns_txt_add.php, dns_txt_delete.php),
interface/lib/classes/json_handler.inc.php (the parameters by name, the answer),
remoting.inc.php (the session, the remote IPs), remoting_lib.inc.php
(getDataRecord: an id, -1 or an array of filters), remote.d/dns.inc.php,
dns_txt.tform.php (name, data, the TTL range "60:") and
server/conf/bind_pri.domain.master.

Less certain: which client_id dns_txt_add wants (the example has 1; the
meaning - whose limits apply - is not documented; 0, the remote user's own,
is used unless set); dns_zone_get with -1 or a filter is documented for
getDataRecord as a whole, not for dns_zone_get by name; whether a zone's
origin is stored with the final dot (both are asked); the "stamp" and "serial"
of the example's params (sent as it sends them); the highest TTL (not found).
"""
from __future__ import annotations

import contextlib
import json
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, as_bool, http_call,
                                                relative, said_error)
from acmelib.plugins.challenges._records import RecordApiDns, SoftZones, rel_name, zone_field


class IspConfig(SoftZones, RecordApiDns):
    kind = 'ispconfig'
    title = 'ISPConfig'
    vendor = 'ISPConfig'
    who = 'ISPConfig'
    min_ttl = 60
    description = 'TXT records in the DNS zones of an ISPConfig 3 panel, through its Remote API.'
    fields = [
        field('url', 'Panel address', 'text', required=True, placeholder='panel.example.com:8080',
              help='The ISPConfig panel (name, name:port or https://…); the port is 8080 when '
                   'not given. acme calls /remote/json.php there.'),
        field('user', 'Remote user', 'text', required=True,
              help='System → Remote Users: a user of its own for acme with "DNS zone functions" '
                   'and "DNS txt functions", and acme\'s address in its allowed addresses.'),
        field('password', 'Password', 'secret', required=True),
        zone_field(['url', 'user', 'password']),
        field('client_id', 'Client ID', 'number', default=0, advanced=True,
              help='The ISPConfig client the records are added for (dns_txt_add\'s client_id); '
                   '0: the remote user\'s own.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='ISPConfig takes 60 or more.'),
        field('verify_tls', 'Check the panel\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    # -- the API ------------------------------------------------------------------------
    def _url(self):
        h = str(self.c('url', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the ISPConfig address is not set', retry=False)
        u = urllib.parse.urlsplit(h if '://' in h else 'https://' + h)
        try:
            port = u.port
        except ValueError:
            raise PluginError('the ISPConfig address %s has a port that is not a number' % h,
                              retry=False)
        host = u.hostname or ''
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%d/remote/json.php' % (u.scheme or 'https', host, port or 8080)

    def _rpc(self, method, params):
        """The response of one Remote API function, or a PluginError with its message."""
        st, _rh, got = http_call(self.ctx, 'POST', '%s?%s' % (self._url(), method),
                                 json.dumps(params).encode(), {
                                     'Content-Type': 'application/json',
                                     'Accept': 'application/json',
                                     'User-Agent': 'acme-challenge'},
                                 who='ISPConfig', verify=as_bool(self.c('verify_tls', True)))
        parsed = None
        try:
            parsed = json.loads(got.decode('utf-8') if isinstance(got, bytes) else got)
        except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
            pass
        if st != 200:
            raise said_error('ISPConfig', st, parsed, got)
        if not isinstance(parsed, dict) or 'code' not in parsed:
            raise PluginError('ISPConfig answered something that is not its Remote API (%s) - '
                              'is this the panel\'s address, and the Remote API allowed?'
                              % method, detail=str(got[:300]), retry=False)
        if parsed.get('code') != 'ok':
            words = str(parsed.get('message') or parsed.get('code'))
            low = words.lower()
            raise PluginError('ISPConfig said no to %s: %s' % (method, words), detail=words,
                              retry=not any(w in low for w in (
                                  'permission', 'password wrong', 'login', 'disabled')))
        return parsed.get('response')

    # -- the session --------------------------------------------------------------------
    @contextlib.contextmanager
    def session(self):
        """One remote session for the work inside, closed at the end."""
        if getattr(self, '_sid', None):
            yield
            return
        sid = self._rpc('login', {'username': self.c('user', ''),
                                  'password': self.c('password', ''), 'client_login': False})
        if not sid:
            raise PluginError('ISPConfig: signed in, but no session came back', retry=False)
        self._sid = sid
        try:
            yield
        finally:
            self._sid = None
            try:
                self._rpc('logout', {'session_id': sid})
            except PluginError as e:
                self.ctx.debug('ISPConfig: the session was not closed (%s)' % e)

    def _call(self, method, params):
        with self.session():
            return self._rpc(method, dict(params, session_id=self._sid))

    # -- zones and records --------------------------------------------------------------
    def zone_names(self):
        got = self._call('dns_zone_get', {'primary_id': -1}) or []
        if isinstance(got, dict):
            got = [got]
        return [D.norm(z.get('origin')) for z in got if isinstance(z, dict) and z.get('origin')]

    def _zone(self, zone):
        """The zone's record (its id and server_id)."""
        cache = self.__dict__.setdefault('_zrecs', {})
        z = D.norm(zone)
        if z not in cache:
            for origin in (z + '.', z):
                got = self._call('dns_zone_get', {'primary_id': {'origin': origin}}) or []
                if isinstance(got, dict):
                    got = [got]
                rec = [r for r in got if isinstance(r, dict) and D.norm(r.get('origin')) == z]
                if rec:
                    cache[z] = rec[0]
                    break
            else:
                raise PluginError('ISPConfig has no DNS zone %s that this remote user may see'
                                  % z, retry=False)
        return cache[z]

    def txt_records(self, zone, fqdn):
        zid = self._zone(zone).get('id')
        rel = relative(fqdn, zone).lower()
        got = self._call('dns_rr_get_all_by_zone', {'zone_id': zid}) or []
        out = []
        for r in got if isinstance(got, list) else []:
            if not isinstance(r, dict) or str(r.get('type') or '').upper() != 'TXT':
                continue
            name = str(r.get('name') or '').strip().lower()
            if name.endswith('.'):
                name = D.norm(name)
                same = name == D.norm(fqdn)
            else:
                same = name == rel or (rel == '@' and name in ('', '@'))
            if same and r.get('id') is not None:
                out.append((r.get('id'), str(r.get('data') or '')))
        return out

    def create_txt(self, zone, fqdn, value):
        z = self._zone(zone)
        rid = self._call('dns_txt_add', {
            'client_id': int(self.num('client_id', 0) or 0),
            'params': {'server_id': z.get('server_id'), 'zone': z.get('id'),
                       'name': rel_name(fqdn, zone), 'type': 'txt', 'data': value, 'aux': '0',
                       'ttl': str(self.ttl()), 'active': 'y', 'stamp': 'CURRENT_TIMESTAMP',
                       'serial': '1'},
            'update_serial': True})
        if not rid:
            raise PluginError('ISPConfig did not add the TXT record %s (no id came back)' % fqdn)
        return rid

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('dns_txt_delete', {'primary_id': int(record_id), 'update_serial': True})

    def add_txt(self, fqdn, value):
        with self.session():
            return RecordApiDns.add_txt(self, fqdn, value)

    def del_txt(self, fqdn, value, handle):
        with self.session():
            return RecordApiDns.del_txt(self, fqdn, value, handle)

    def test(self):
        with self.session():
            z = D.norm(self.c('zone', ''))
            if z:
                rec = self._zone(z)
                got = self._call('dns_rr_get_all_by_zone', {'zone_id': rec.get('id')}) or []
                return 'ISPConfig: signed in as %s; the zone %s has %d record(s)' % (
                    self.c('user', ''), z, len(got) if isinstance(got, list) else 0)
            return RecordApiDns.test(self)

    def catalog(self, key):
        with self.session():
            return SoftZones.catalog(self, key)
