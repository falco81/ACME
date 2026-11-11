# -*- coding: utf-8 -*-
"""What the DNS provider modules added with acme 1.1 share (the name starts
with "_": the registry does not take it for a module).

    RecordApiDns    the base of a provider whose API keeps one record a value
                    (most of them): the TXT records at a name listed, ours
                    added only when it is not there, cleanup deleting only the
                    records that hold our value - so other orders' values stay
                    and a second cleanup finds nothing to do.
    rel_name()      the name relative to the zone as the provider writes it
    form_call()     a form or query API through ctx.http, its JSON parsed
    basic()         an Authorization: Basic header
    xml_text()      the text of an XML element, its namespace ignored
    SoftZones       a mixin (1.0.26): the zone set, else the longest of the zones
                    listed - and when the list cannot be read or has none for the
                    name, the zone by its SOA (a step says so) instead of an error;
                    catalog('zones') for a Zone field of the type catalog
    zone_field()    that Zone field: a list to load and pick from, or typed

Nothing here changes what _common.py does; it is only built on it.
"""
from __future__ import annotations

import base64
import json
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (ApiDns, DnsChallenge, http_call, longest_zone,
                                                relative, said_error, unquote_txt)


def rel_name(fqdn, zone, apex='@'):
    """fqdn relative to zone; the apex as the provider writes it ('@', '' or '.')."""
    r = relative(fqdn, zone)
    return apex if r == '@' else r


def basic(user, password):
    return 'Basic ' + base64.b64encode(('%s:%s' % (user, password)).encode('utf-8')).decode()


def form_call(ctx, method, url, params=None, headers=None, who='the API', body=None,
              ok=(200, 201, 202, 204)):
    """(status, parsed JSON or None, raw): a GET with `params` in the query
    (or a POST of them as a form when body is True), a 429 waited out."""
    h = {'Accept': 'application/json', 'User-Agent': 'acme-challenge'}
    h.update(headers or {})
    data = None
    if params is not None and method == 'GET':
        url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params)
    elif params is not None:
        data = urllib.parse.urlencode(params).encode()
        h.setdefault('Content-Type', 'application/x-www-form-urlencoded')
    if body is not None:
        data = body
    st, _rh, got = http_call(ctx, method, url, data, h, who=who)
    parsed = None
    if got:
        try:
            parsed = json.loads(got.decode('utf-8') if isinstance(got, bytes) else got)
        except (ValueError, UnicodeDecodeError):
            parsed = None
    if st not in ok:
        raise said_error(who, st, parsed, got)
    return st, parsed, got


def xml_text(el, name):
    """The text of the first child of el called `name` (any namespace), or ''."""
    if el is None:
        return ''
    for c in el.iter():
        if c is not el and str(c.tag).rsplit('}', 1)[-1] == name:
            return (c.text or '').strip()
    return ''


class RecordApiDns(ApiDns):
    """A provider's API with one record a value. A module writes zone_names()
    (or zone_hint()), and

        txt_records(zone, fqdn) -> [(record id, value)]   the TXT records at fqdn
        create_txt(zone, fqdn, value) -> record id (or None)
        delete_txt(zone, fqdn, record_id, value)          quiet when it is gone

    The value compared is the one acme wrote (quotes the API puts round it
    taken away)."""

    def txt_records(self, zone, fqdn):
        raise NotImplementedError

    def create_txt(self, zone, fqdn, value):
        raise NotImplementedError

    def delete_txt(self, zone, fqdn, record_id, value):
        raise NotImplementedError

    def _ours(self, zone, fqdn, value):
        return [rid for rid, v in self.txt_records(zone, D.norm(fqdn)) or []
                if unquote_txt(v) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        have = self._ours(zone, fqdn, value)
        rid = have[0] if have else self.create_txt(zone, D.norm(fqdn), value)
        return {'zone': zone, 'id': rid}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ours = self._ours(zone, fqdn, value)
        # the one made, by its id, too (1.0.79): a listing that does not show it (past a page,
        # not yet visible) left it behind
        if h.get('id') and h['id'] not in ours:
            ours.append(h['id'])
        for rid in ours:
            try:
                self.delete_txt(zone, D.norm(fqdn), rid, value)
            except PluginError as e:
                if '404' not in str(e):
                    raise


ZONE_HELP = ('Load the list and pick it, or type it. Empty: the longest zone of the account '
             'the name is in - and when the list cannot be read, the zone by its SOA.')


def zone_field(depends, label='Zone', placeholder='example.com', help=ZONE_HELP):
    """The Zone field of a module with SoftZones: the provider's list, or typed."""
    return field('zone', label, 'catalog', catalog='zones', default='', depends=list(depends),
                 placeholder=placeholder, help=help)


class SoftZones(object):
    """A mixin before ApiDns: zone discovery that never stops a run. The zone set
    (when the name is in it) wins; else the longest of zone_names() the name is
    in; when the list cannot be read, or has none for the name, None - so
    zone_for() finds the zone by its SOA - and the job says so once."""

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        who = self.who or self.title
        try:
            names = self._zone_names()
        except PluginError as e:
            self.say_once('zones', '%s: the zones could not be listed (%s) - the zone of %s is '
                          'found by its SOA (or set it)' % (who, e, D.norm(fqdn)), 'warn')
            return None
        best = longest_zone(fqdn, names)
        if not best:
            self.say_once('zones:' + D.norm(fqdn), '%s: none of the %d zone(s) listed holds %s - '
                          'the zone is found by its SOA (or set it)' % (who, len(names or []),
                                                                       D.norm(fqdn)))
        return best

    def catalog(self, key):
        """The form's list of zones (read-only)."""
        if key != 'zones':
            raise PluginError('there is no list called %s here' % key, retry=False)
        names = sorted(set(D.norm(z) for z in (self.zone_names() or []) if z))
        return {'options': [[n, n] for n in names], 'said': '%d zone(s)' % len(names)}
