# -*- coding: utf-8 -*-
"""DNS-01 at Joker.com, through DMAPI (the Domain Management API, 1.0.26):

    POST https://dmapi.joker.com/request/login          api-key=..  (or username=..&password=..)
         -> "Auth-SID: <session>" among the reply's header lines
    POST .../request/dns-zone-list   auth-sid=..         the zones served by Joker.com, one a line
    POST .../request/dns-zone-get    auth-sid=..&domain=example.com
         -> the zone, one record a line:  <label> <type> <pri> <target> <ttl> ...
    POST .../request/dns-zone-put    auth-sid=..&domain=example.com&zone=<the whole zone>
         (it REPLACES the zone: every record not in it is gone)

A reply is header lines (Status-Code, Status-Text, Error, ...), an empty line,
then its body; Status-Code 0 (or 1000-1999) is success, an Error line a
refusal. The session (Auth-SID) is kept and shared; a refused request signs in
once more and is asked again, as the documentation tells.

DMAPI has no call for one record, so acme reads the zone, adds its own line
(  _acme-challenge.www  TXT  0  "<value>"  300  ) or takes away only the TXT
lines at that label whose value is ours, and writes the zone back - every
other line exactly as it was read, under a lock (one change of a zone at a
time on this node). A zone read empty is never written (it would wipe it),
and the zone is read again after each write to see the change in it.

Not used: svc.joker.com/nic/replace (Joker's Let's Encrypt helper with the
domain's Dynamic DNS credentials) - it "will replace all TXT records for the
specified label", which would take other orders' values at the same name
away.

Sources (the user's collection of Joker.com's documentation, api-docs/joker/):
DMAPI-ext.txt (https://dmapi.joker.com/docs/DMAPI-ext.txt - Basics: the reply
format, auth-sid, "send login request again"; login; dns-zone-list;
dns-zone-get; dns-zone-put and its record format, "Quoting of values for TXT
records is mandatory", the TTL of at least 300) and notes.md, quoting
https://joker.com/faq/books/reseller-documentation-en/page/basics (the address,
Status-Code 0 or 1000-1999), .../page/account-and-handling (the API key),
.../page/modify-zonedata (include-defaults), .../page/what-is-an-ote-system
(dmapi.ote.joker.com) and https://joker.com/faq/books/jokercom-faq-en/page/lets-encrypt-ssl-certificates
(nic/replace).

Less certain (the documentation leaves it open): no example of a real
dns-zone-get answer is published - it is read as header lines, an empty line
and the zone in the dns-zone-put format; whether the default records Joker
leaves out without include-defaults=1 stay when the zone is written back
without them (it is read and written without them, as Joker keeps them by
default); which refusals are "authorization failures" (any refused request
signs in once more and is asked once again); how long a session lives (1 hour
of inactivity by default - acme keeps it 30 minutes); the lowest TTL (300 in
DMAPI-ext.txt, 60 on the modify-zonedata page - 300 is used); whether
dns-zone-* is open to accounts that are not resellers.
"""
from __future__ import annotations

import re
import time

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, relative, rmw_lock,
                                                unquote_txt)
from acmelib.plugins.challenges._records import SoftZones, form_call, zone_field

ENDPOINTS = {'live': 'https://dmapi.joker.com', 'ote': 'https://dmapi.ote.joker.com'}
SESSION_S = 1800.0          # DMAPI: a session ends after an hour without requests (by default)
WORD = re.compile(r'"(?:[^"\\]|\\.)*"|\S+')


def reply(raw):
    """(headers {lower name: [values]}, body) of a DMAPI reply."""
    text = (raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else str(raw or ''))
    text = text.replace('\r\n', '\n')
    head, _sep, body = text.partition('\n\n')
    hdr = {}
    for line in head.split('\n'):
        k, sep, v = line.partition(':')
        if sep and k.strip() and ' ' not in k.strip():
            hdr.setdefault(k.strip().lower(), []).append(v.strip())
    return hdr, body


def refused(hdr):
    """The words of a refusal, or None when the reply says success."""
    if hdr.get('error'):
        return '; '.join(hdr['error'])
    code = (hdr.get('status-code') or [''])[0]
    if code and code != '0' and not (code.isdigit() and 1000 <= int(code) <= 1999):
        return '%s %s' % (code, (hdr.get('status-text') or [''])[0])
    if (hdr.get('result') or [''])[0].upper() == 'NACK':
        return 'NACK %s' % (hdr.get('status-text') or [''])[0]
    return None


def zone_line(line):
    """(label, type, target unquoted) of a zone line in the dns-zone-put format, or None."""
    s = line.strip()
    if not s or s.startswith('#') or s.startswith('$'):
        return None
    w = WORD.findall(s)
    if len(w) < 4:
        return None
    return w[0], w[1].upper(), unquote_txt(w[3])


class Joker(SoftZones, ApiDns):
    kind = 'joker'
    title = 'Joker.com'
    vendor = 'Joker.com'
    who = 'Joker.com'
    min_ttl = 300                   # DMAPI-ext.txt: "<ttl> must be at least 300"
    description = ('TXT records in a zone served by Joker.com, through DMAPI (the zone read, '
                   'our line added or taken away, written back).')
    fields = [
        field('auth', 'Sign in with', 'select', default='key',
              options=[['key', 'a DMAPI API key'], ['password', 'user name and password']]),
        field('api_key', 'API key', 'secret', default='', show_if={'auth': ['key']},
              help='Joker.com → My Profile → Manage Joker.com API access keys: a key allowed '
                   '"modifications only" is enough (a read-only one cannot write the zone).'),
        field('user', 'User name', 'text', default='', show_if={'auth': ['password']},
              help='The Joker.com account (DMAPI asks for a reseller account).'),
        field('password', 'Password', 'secret', default='', show_if={'auth': ['password']}),
        zone_field(['auth', 'api_key', 'user', 'password', 'endpoint']),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='Joker.com takes 300 or more.'),
        field('endpoint', 'API', 'select', default='live', advanced=True,
              options=[['live', 'dmapi.joker.com'],
                       ['ote', 'dmapi.ote.joker.com (OT&E, the test system)']]),
    ] + PROPAGATION_FIELDS

    def _base(self):
        return ENDPOINTS.get(str(self.c('endpoint') or 'live'), ENDPOINTS['live'])

    def _post(self, name, params, who='Joker.com'):
        st, _p, got = form_call(self.ctx, 'POST', '%s/request/%s' % (self._base(), name),
                                params, {'Accept': 'text/plain'}, who=who,
                                ok=tuple(range(200, 600)))
        hdr, body = reply(got)
        why = refused(hdr)
        if why is None and st != 200:
            why = 'HTTP %s' % st
        if why:
            raise PluginError('%s said no to %s: %s' % (who, name, why), detail=body[:300] or why,
                              retry=st >= 500)
        return hdr, body

    def _sign_in(self):
        if str(self.c('auth') or 'key') == 'password':
            params = {'username': self.c('user', ''), 'password': self.c('password', '')}
        else:
            params = {'api-key': self.c('api_key', '')}
        hdr, _body = self._post('login', params, who='Joker.com (sign-in)')
        sid = (hdr.get('auth-sid') or [''])[0]
        if not sid:
            raise PluginError('Joker.com: signed in, but no Auth-SID came back', retry=False)
        return sid, SESSION_S

    def _sid(self):
        if limits.sharing(self.ctx):
            return limits.session(limits.key_of(self, 'token'), self._sign_in)
        if getattr(self, '_s', None) and self._s[1] > time.time():
            return self._s[0]
        sid, life = self._sign_in()
        self._s = (sid, time.time() + life)
        return sid

    def _drop(self, sid):
        if limits.sharing(self.ctx):
            limits.session_drop(limits.key_of(self, 'token'), sid)
        self._s = None

    def _req(self, name, params=None):
        """The body of a request; a refusal signs in once more and asks again."""
        for again in (True, False):
            sid = self._sid()
            try:
                return self._post(name, dict(params or {}, **{'auth-sid': sid}))[1]
            except PluginError as e:
                if not again:
                    raise
                self.ctx.debug('Joker.com refused %s (%s): signing in again' % (name, e))
                self._drop(sid)

    # -- zones ----------------------------------------------------------------------------
    def zone_names(self):
        return [ln.split()[0] for ln in self._req('dns-zone-list').split('\n') if ln.strip()]

    def _lines(self, zone):
        body = self._req('dns-zone-get', {'domain': D.norm(zone)})
        lines = body.replace('\r\n', '\n').split('\n')
        while lines and not lines[-1].strip():
            lines.pop()
        return lines

    @staticmethod
    def _is_ours(line, label, value):
        z = zone_line(line)
        return bool(z) and z[0].lower() == label.lower() and z[1] == 'TXT' and z[2] == value

    def _write(self, zone, read, lines, label, value, want):
        if not [ln for ln in read if zone_line(ln)]:
            raise PluginError('Joker.com: the zone %s was read empty - acme does not write it '
                              'back (dns-zone-put would replace the whole zone)' % zone,
                              retry=False)
        self._req('dns-zone-put', {'domain': D.norm(zone), 'zone': '\n'.join(lines) + '\n'})
        seen = any(self._is_ours(ln, label, value) for ln in self._lines(zone))
        if seen != want:
            raise PluginError('Joker.com took the zone %s, but our TXT value is %s in it when '
                              'read again' % (zone, 'not' if want else 'still'))

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        label = relative(fqdn, zone)
        with rmw_lock('joker|%s' % D.norm(zone)):
            lines = self._lines(zone)
            if not any(self._is_ours(ln, label, value) for ln in lines):
                self._write(zone, lines,
                            lines + ['%s TXT 0 "%s" %d' % (label, value, self.ttl())],
                            label, value, True)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        label = relative(fqdn, zone)
        with rmw_lock('joker|%s' % D.norm(zone)):
            lines = self._lines(zone)
            left = [ln for ln in lines if not self._is_ours(ln, label, value)]
            if len(left) != len(lines):
                self._write(zone, lines, left, label, value, False)

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            n = len([ln for ln in self._lines(z) if zone_line(ln)])
            return 'Joker.com: signed in; the zone %s has %d record(s)' % (z, n)
        return ApiDns.test(self)
