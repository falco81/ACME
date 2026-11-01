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

Nothing here changes what _common.py does; it is only built on it.
"""
from __future__ import annotations

import base64
import json
import urllib.parse

from acmelib.plugins.base import PluginError
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (ApiDns, http_call, relative, said_error,
                                                unquote_txt)


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
        for rid in self._ours(zone, fqdn, value):
            try:
                self.delete_txt(zone, D.norm(fqdn), rid, value)
            except PluginError as e:
                if '404' not in str(e):
                    raise
