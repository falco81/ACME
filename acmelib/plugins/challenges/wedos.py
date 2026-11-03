# -*- coding: utf-8 -*-
"""DNS-01 at WEDOS, through WAPI (https://api.wedos.com/wapi/json): every call
a POST of the form field request=<JSON>

    {"request": {"user": LOGIN, "auth": AUTH, "command": ..., "clTRID": ..., "data": {...}}}

AUTH = sha1(LOGIN + sha1(WAPI password) + the hour now in Europe/Prague, "00".."23"),
hex - so the clock of this machine has to be right (NTP). Commands:

    ping                                                      signs in
    dns-domains-list {page, page_limit}                       {domain: [{name, type, status}],
                                                               total, page, page_limit}
    dns-rows-list    {domain}                                 {row: [{ID, name, rdtype, rdata}]}
                                                              (or row1, row2... as the docs show)
    dns-row-add      {domain, name, ttl, type, rdata, author_comment}
    dns-row-delete   {domain, row_id}
    dns-domain-commit {name}                                  the changes made live

Answers {"response": {"code": 1000, "result": "OK", "data": ...}}; a code of
2000 or more is a refusal. WAPI is ordered and switched on in the customer
administration (Customer → WAPI interface), and answers only the IP addresses
allowed there. WEDOS takes no TTL under 300, and its name servers take a few
minutes after the commit.

WAPI's own limits (its manual): 1000 requests an hour per account, and more
than 10 invalid requests (a wrong auth, an address not allowed, a wrong input)
block the address for a minute per request, longer with each - so a refused
sign-in holds every call to WAPI for a while (1.0.21) instead of trying again.
Only primary, active domains are written to (a secondary one refuses, 2318);
2316 (the record is there already) is the record being there.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, http_call, relative,
                                                said_error, unquote_txt)

API = 'https://api.wedos.com/wapi/json'
AUTH_CODES = (2050, 2051, 2052, 2053)
AUTH_HOLD_S = 300           # a refused sign-in: WAPI not asked again for this long
PAGE = 500


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
        wait = limits.held(API)
        if wait > 0:
            raise PluginError('WEDOS refused the sign-in a moment ago: WAPI is not asked again '
                              'for %d s (more wrong requests would block this address) - check '
                              'the login, the WAPI password, this machine\'s clock and the IP '
                              'addresses allowed for WAPI' % int(wait + 0.5), retry=True)
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
            if code in AUTH_CODES:
                words += ' - check the login, the WAPI password, this machine\'s clock and the ' \
                         'IP addresses allowed for WAPI'
                limits.note_slow(API, AUTH_HOLD_S)
            raise PluginError(words, detail=ans, retry=code < 2000 or code >= 5000)
        return ans.get('data') or {}

    def zone_names(self):
        """Every primary, active domain of the account - page by page (WAPI gives 50 a
        page unless asked for more)."""
        out, page = [], 1
        while page <= 100:
            got = self._call('dns-domains-list', {'page': page, 'page_limit': PAGE})
            rows = got.get('domain') or []
            if isinstance(rows, dict):
                rows = list(rows.values())
            rows = [d for d in rows if isinstance(d, dict)]
            out += [d.get('name') for d in rows
                    if str(d.get('type') or 'primary').lower() == 'primary' and
                    str(d.get('status') or 'active').lower() == 'active']
            try:
                total = int(got.get('total') or 0)
            except (TypeError, ValueError):
                total = 0
            if len(rows) < PAGE or not total or page * PAGE >= total:
                break
            page += 1
        return out

    @staticmethod
    def _rows(data):
        """The records of dns-rows-list: data.row (a list or a map), or row1, row2..."""
        rows = data.get('row')
        if rows is None:
            rows = [v for k, v in data.items() if str(k).startswith('row')]
        if isinstance(rows, dict):
            rows = list(rows.values()) if not ('ID' in rows or 'name' in rows) else [rows]
        return [r for r in rows or [] if isinstance(r, dict)]

    def _txt_rows(self, zone, rel):
        """The TXT records of one name. Asked with the filters WAPI documents (1.0.28:
        row_name - "@" for the domain itself - and rdtype), so the answer is data.row[];
        refused (an older WAPI), asked for the whole zone as before. Filtered here too."""
        name = '' if rel == '@' else rel
        try:
            got = self._call('dns-rows-list', {'domain': zone, 'row_name': name or '@',
                                               'rdtype': 'TXT'})
        except PluginError as e:
            # Only a refusal of the request's data (2xxx) is asked again without the filters:
            # never a sign-in or anything else - wrong requests block the address at WEDOS.
            code = (e.detail or {}).get('code') if isinstance(e.detail, dict) else None
            try:
                code = int(code)
            except (TypeError, ValueError):
                raise e
            if not 2000 <= code < 3000 or code in AUTH_CODES or limits.held(API) > 0:
                raise
            got = self._call('dns-rows-list', {'domain': zone})
        return [r for r in self._rows(got) if
                str(r.get('rdtype')).upper() == 'TXT' and (r.get('name') or '') == name]

    def _ours(self, zone, rel, value):
        return [r.get('ID') for r in self._txt_rows(zone, rel)
                if unquote_txt(r.get('rdata')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        rows = self._txt_rows(zone, rel)
        if not any(unquote_txt(r.get('rdata')) == value for r in rows):
            # Records of one name and type share one TTL at WEDOS (kb.vedos.cz/dns-zaznamy,
            # 1.0.28): a TXT already there (the wildcard's beside the domain's) gives ours.
            ttl = self.ttl()
            for r in rows:
                try:
                    if int(r.get('ttl') or 0) > 0:
                        ttl = int(r['ttl'])
                        break
                except (TypeError, ValueError):
                    pass
            # 2316: the record is there already (put in a moment ago by another job)
            self._call('dns-row-add', {'domain': zone, 'name': '' if rel == '@' else rel,
                                       'ttl': ttl, 'type': 'TXT', 'rdata': value,
                                       'author_comment': 'acme DNS-01'}, ok=(1000, 2316))
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
