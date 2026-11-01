# -*- coding: utf-8 -*-
"""DNS-01 at WEDOS, through WAPI (https://api.wedos.com/wapi/json): every call
a POST of the form field request=<JSON>

    {"request": {"user": LOGIN, "auth": AUTH, "command": ..., "clTRID": ..., "data": {...}}}

AUTH = sha1(LOGIN + sha1(WAPI password) + the hour now in Europe/Prague, "00".."23"),
hex - so the clock of this machine has to be right (NTP). Commands:

    ping                                                      signs in
    dns-domains-list                                          {domain: [{name, type, status}]}
    dns-rows-list    {domain}                                 {row: [{ID, name, rdtype, rdata}]}
    dns-row-add      {domain, name, ttl, type, rdata, auth_comment}
    dns-row-delete   {domain, row_id}
    dns-domain-commit {name}                                  the changes made live

Answers {"response": {"code": 1000, "result": "OK", "data": ...}}; a code of
2000 or more is a refusal. WAPI is ordered and switched on in the customer
administration (Customer → WAPI interface), and answers only the IP addresses
allowed there. WEDOS takes no TTL under 300, and its name servers take a few
minutes after the commit.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, http_call, relative,
                                                said_error, unquote_txt)

API = 'https://api.wedos.com/wapi/json'


def prague_hour(now=None):
    """The hour in Europe/Prague ("00".."23"): zoneinfo where it has the data,
    else the EU rule (CEST from the last Sunday of March 01:00 UTC to the last
    Sunday of October 01:00 UTC)."""
    now = time.time() if now is None else now
    utc = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    try:
        from zoneinfo import ZoneInfo
        return utc.astimezone(ZoneInfo('Europe/Prague')).strftime('%H')
    except Exception:                                   # noqa: BLE001
        pass

    def last_sunday(month):
        d = datetime.datetime(utc.year, month + 1, 1, 1, tzinfo=datetime.timezone.utc) - \
            datetime.timedelta(days=1)
        return d - datetime.timedelta(days=(d.weekday() + 1) % 7)
    summer = last_sunday(3) <= utc < last_sunday(10)
    return (utc + datetime.timedelta(hours=2 if summer else 1)).strftime('%H')


def wedos_auth(login, password, now=None):
    inner = hashlib.sha1(password.encode('utf-8')).hexdigest()
    return hashlib.sha1((login + inner + prague_hour(now)).encode('utf-8')).hexdigest()


class Wedos(ApiDns):
    kind = 'wedos'
    title = 'WEDOS'
    vendor = 'WEDOS'
    who = 'WEDOS'
    min_ttl = 300
    description = 'TXT records in a domain at WEDOS (its DNS), through WAPI.'
    fields = [
        field('login', 'Login', 'text', required=True, placeholder='you@example.cz',
              help='The e-mail you sign in to the WEDOS customer administration with.'),
        field('wapi_password', 'WAPI password', 'secret', required=True,
              help='Customer administration → Customer → WAPI interface: order WAPI (free), set '
                   'its own password, choose the JSON protocol, and allow the IP address acme '
                   'calls from (WEDOS refuses every other).'),
        field('zone', 'Domain', 'text', default='', placeholder='example.cz',
              help='Empty: the longest domain in WEDOS DNS the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='WEDOS takes 300 or more.'),
    ] + PROPAGATION_FIELDS

    def _call(self, command, data=None, ok=(1000,), now=None):
        login = str(self.c('login', ''))
        req = {'request': {'user': login,
                           'auth': wedos_auth(login, str(self.c('wapi_password', '')), now),
                           'command': command, 'clTRID': 'acme-%d' % int(time.time() * 1000)}}
        if data is not None:
            req['request']['data'] = data
        body = urllib.parse.urlencode({'request': json.dumps(req)}).encode()
        st, _rh, got = http_call(self.ctx, 'POST', API, body, {
            'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json',
            'User-Agent': 'acme-challenge'}, who='WEDOS')
        if st != 200:
            raise said_error('WEDOS', st, None, got)
        try:
            ans = (json.loads(got.decode('utf-8')) or {}).get('response') or {}
        except (ValueError, UnicodeDecodeError, AttributeError):
            raise PluginError('WEDOS answered something that is not JSON', detail=got)
        code = int(ans.get('code') or 0)
        if code not in ok:
            words = 'WEDOS said %s: %s' % (code, ans.get('result') or 'nothing more')
            if code in (2050, 2051, 2052, 2053):
                words += ' - check the login, the WAPI password, this machine\'s clock and the ' \
                         'IP addresses allowed for WAPI'
            raise PluginError(words, detail=ans, retry=code < 2000 or code >= 5000)
        return ans.get('data') or {}

    def zone_names(self):
        got = self._call('dns-domains-list').get('domain') or []
        if isinstance(got, dict):
            got = list(got.values())
        return [d.get('name') for d in got if isinstance(d, dict)]

    def _ours(self, zone, rel, value):
        name = '' if rel == '@' else rel
        rows = self._call('dns-rows-list', {'domain': zone}).get('row') or []
        if isinstance(rows, dict):
            rows = list(rows.values())
        return [r.get('ID') for r in rows if isinstance(r, dict) and
                str(r.get('rdtype')).upper() == 'TXT' and (r.get('name') or '') == name and
                unquote_txt(r.get('rdata')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        if not self._ours(zone, rel, value):
            self._call('dns-row-add', {'domain': zone, 'name': '' if rel == '@' else rel,
                                       'ttl': self.ttl(), 'type': 'TXT', 'rdata': value,
                                       'auth_comment': 'acme DNS-01'})
            self._call('dns-domain-commit', {'name': zone})
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = self._ours(zone, h.get('rel') or relative(fqdn, zone), value)
        for rid in ids:
            self._call('dns-row-delete', {'domain': zone, 'row_id': rid})
        if ids:
            self._call('dns-domain-commit', {'name': zone})

    def test(self):
        self._call('ping')
        return ApiDns.test(self)
