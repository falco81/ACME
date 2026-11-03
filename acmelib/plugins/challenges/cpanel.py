# -*- coding: utf-8 -*-
"""DNS-01 in the DNS of a cPanel account, through cPanel's UAPI (1.0.26):

    GET https://{cpanel}:2083/execute/DomainInfo/list_domains
        {result: {status, errors, data: {main_domain, addon_domains, parked_domains, sub_domains}}}
    GET .../execute/DNS/parse_zone?zone=example.com
        data: [{type: record|control|comment, line_index, dname_b64, record_type, ttl,
                data_b64: [..]}]   (owner and content base64; an owner without a final
                                    dot is relative to the zone)
    GET .../execute/DNS/mass_edit_zone?zone=example.com&serial=<SOA serial>
        &add={"dname":"_acme-challenge.www","ttl":300,"record_type":"TXT","data":["<value>"]}
        &remove=<line_index>&remove=...
        data: {new_serial}       (the serial must be the zone's current one, else it fails)

Authorization: cpanel <user>:<API token> (cPanel → Security → Manage API
Tokens). Our value is added as a TXT record of its own (other values at the
name stay); cleanup removes, by their line_index, only the TXT records at the
name whose content is our value. Each change is read → written with the
serial just read, one at a time on this node; a change refused (the serial
moved on) is read again and tried up to three times. The zone is the one set,
else the longest of the account's domains the name is in that parse_zone
reads (the domains list does not say which of them is a zone of its own),
else by its SOA.

Sources (the user's collection of cPanel's documentation, api-docs/cpanel/):
the excerpt of cPanel's official UAPI OpenAPI description
cpanel-uapi-dns-domaininfo.openapi.json (cPanel UAPI 11.138.0.10, from
https://api.docs.cpanel.net/_bundle/specifications/cpanel.openapi.json:
/DNS/parse_zone, /DNS/mass_edit_zone, /DomainInfo/list_domains, the schemas
ResponseRR / ResponseBase, the result envelope with status 1|0 and errors)
and notes.md, quoting https://api.docs.cpanel.net/specifications/cpanel.openapi/dns/dns-parse_zone,
https://api.docs.cpanel.net/specifications/cpanel.openapi/dns/dns-mass_edit_zone,
https://api.docs.cpanel.net/cpanel/tokens (the "Authorization: cpanel
username:APITOKEN" header) and https://api.docs.cpanel.net/cpanel/introduction
(port 2083).

Less certain (the documentation leaves it open): where the serial comes from -
it is read from the SOA record of parse_zone (its third field), as the
documentation only says "the current serial number in the DNS zone's SOA
record"; that each item of a TXT record's data_b64 is one of its strings (they
are joined); the error words of a serial that moved on (any refusal is read
again and tried again, at most three times); that dname may be relative (the
documentation's examples are) - it is written relative to the zone; no lowest
TTL is documented (300 is used when not set).
"""
from __future__ import annotations

import base64
import binascii
import json
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, DnsChallenge, as_bool,
                                                http_call, relative, rmw_lock, said_error,
                                                suffixes, unquote_txt)
from acmelib.plugins.challenges._records import SoftZones, zone_field

TRIES = 3                   # a mass_edit_zone refused (the serial moved on): read again, so often


def b64text(v):
    """A base64 field of parse_zone as text (octets that are not UTF-8 kept as U+FFFD)."""
    try:
        return base64.b64decode(str(v or ''), validate=False).decode('utf-8', 'replace')
    except (binascii.Error, ValueError):
        return ''


def soa_serial(parts):
    """The serial of an SOA record's content as parse_zone gives it (its third field)."""
    words = parts if len(parts) >= 3 else ' '.join(parts).split()
    try:
        return int(str(words[2]).strip())
    except (IndexError, ValueError):
        return None


class Cpanel(SoftZones, ApiDns):
    kind = 'cpanel'
    title = 'cPanel'
    vendor = 'cPanel'
    who = 'cPanel'
    min_ttl = 1                     # no lowest TTL documented
    description = 'TXT records in the DNS zones of a cPanel account, through UAPI with an API token.'
    fields = [
        field('host', 'cPanel address', 'text', required=True, placeholder='cpanel.example.com',
              help='The cPanel server as the account reaches it (name, name:port or https://…); '
                   'the port is 2083 when not given.'),
        field('user', 'User name', 'text', required=True,
              help='The cPanel account the domains belong to.'),
        field('token', 'API token', 'secret', required=True,
              help='cPanel → Security → Manage API Tokens → Create (best one for acme alone, '
                   'with an expiry; not a read-only one).'),
        zone_field(['host', 'user', 'token']),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    # -- the API ------------------------------------------------------------------------
    def _base(self):
        h = str(self.c('host', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the cPanel address is not set', retry=False)
        u = urllib.parse.urlsplit(h if '://' in h else 'https://' + h)
        try:
            port = u.port
        except ValueError:
            raise PluginError('the cPanel address %s has a port that is not a number' % h,
                              retry=False)
        host = u.hostname or ''
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%d/execute' % (u.scheme or 'https', host, port or 2083)

    def _uapi(self, module, func, params):
        """result.data of one UAPI call (params a list of pairs, a key repeated as given)."""
        url = '%s/%s/%s?%s' % (self._base(), module, func, urllib.parse.urlencode(params))
        h = {'Authorization': 'cpanel %s:%s' % (self.c('user', ''), self.c('token', '')),
             'Accept': 'application/json', 'User-Agent': 'acme-challenge'}
        st, _rh, got = http_call(self.ctx, 'GET', url, None, h, who='cPanel',
                                 verify=as_bool(self.c('verify_tls', True)))
        parsed = None
        try:
            parsed = json.loads(got.decode('utf-8') if isinstance(got, bytes) else got)
        except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
            pass
        if st != 200:
            raise said_error('cPanel', st, parsed, got)
        res = parsed.get('result') if isinstance(parsed, dict) else None
        if not isinstance(res, dict):
            raise PluginError('cPanel answered something that is not UAPI (%s::%s) - is this '
                              'the cPanel address (port 2083)?' % (module, func),
                              detail=str(got[:300]))
        if str(res.get('status')) != '1':
            words = '; '.join(str(e) for e in res.get('errors') or []) or 'status 0'
            raise PluginError('cPanel said no to %s::%s: %s' % (module, func, words),
                              detail=words)
        return res.get('data')

    # -- zones ----------------------------------------------------------------------------
    def zone_names(self):
        d = self._uapi('DomainInfo', 'list_domains', []) or {}
        out = [d.get('main_domain')] if d.get('main_domain') else []
        for k in ('addon_domains', 'parked_domains', 'sub_domains'):
            out += [x for x in d.get(k) or [] if isinstance(x, str)]
        return out

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        try:
            names = set(self._zone_names())
        except PluginError as e:
            self.say_once('zones', 'cPanel: the domains could not be listed (%s) - each name '
                          'above %s is asked for as a zone' % (e, D.norm(fqdn)), 'warn')
            names = set()
        cands = [s for s in suffixes(fqdn) if not names or s in names]
        for cand in cands:                  # the longest that cPanel reads as a zone
            try:
                self._zone(cand)
            except PluginError as e:
                self.ctx.debug('cPanel: %s is not a zone here (%s)' % (cand, e))
                continue
            return cand
        self.say_once('zones:' + D.norm(fqdn), 'cPanel: no zone of this account holds %s - '
                      'the zone is found by its SOA (or set it)' % D.norm(fqdn))
        return None

    def _zone(self, zone):
        """(SOA serial, [(line_index, owner fqdn, value, ttl)] of the TXT records)."""
        serial, txt = None, []
        for it in self._uapi('DNS', 'parse_zone', [('zone', D.norm(zone))]) or []:
            if not isinstance(it, dict) or it.get('type') != 'record':
                continue
            rtype = str(it.get('record_type') or '').upper()
            owner = b64text(it.get('dname_b64')).strip()
            if owner.endswith('.'):
                full = D.norm(owner)
            elif owner in ('', '@'):
                full = D.norm(zone)
            else:
                full = D.norm(owner + '.' + zone)
            parts = [b64text(x) for x in it.get('data_b64') or []]
            if rtype == 'SOA' and serial is None:
                serial = soa_serial(parts)
            elif rtype == 'TXT':
                txt.append((it.get('line_index'), full, ''.join(parts), it.get('ttl')))
        return serial, txt

    @staticmethod
    def _mine(txt, fqdn, value):
        return [r for r in txt if r[1] == D.norm(fqdn) and unquote_txt(r[2]) == value and
                r[0] is not None]

    def _edit(self, zone, fqdn, value, adding):
        """Read, then add (or remove) ours with the serial just read - tried again
        when refused, the zone read anew each time."""
        last = None
        for attempt in range(TRIES):
            serial, txt = self._zone(zone)
            mine = self._mine(txt, fqdn, value)
            if adding and mine or not adding and not mine:
                return                                  # as it should be already
            if serial is None:
                raise PluginError('cPanel: the SOA serial of %s could not be read from '
                                  'parse_zone - nothing changed' % zone, retry=False)
            params = [('zone', D.norm(zone)), ('serial', serial)]
            if adding:
                params.append(('add', json.dumps({'dname': relative(fqdn, zone),
                                                  'ttl': self.ttl(), 'record_type': 'TXT',
                                                  'data': [value]})))
            else:
                params += [('remove', int(r[0])) for r in mine]
            try:
                self._uapi('DNS', 'mass_edit_zone', params)
                return
            except PluginError as e:
                last = e
                if attempt + 1 < TRIES:
                    self.ctx.step('cPanel: the change of %s was refused (%s) - read again' %
                                  (zone, e), 'warn')
        raise last

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        with rmw_lock('cpanel|%s|%s' % (self._base(), D.norm(zone))):
            self._edit(zone, fqdn, value, True)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        with rmw_lock('cpanel|%s|%s' % (self._base(), D.norm(zone))):
            self._edit(zone, fqdn, value, False)

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            serial, txt = self._zone(z)
            return 'cPanel: signed in as %s; the zone %s (serial %s) has %d TXT record(s)' % (
                self.c('user', ''), z, serial, len(txt))
        return ApiDns.test(self)
