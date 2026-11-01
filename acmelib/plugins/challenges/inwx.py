# -*- coding: utf-8 -*-
"""DNS-01 at INWX, through its JSON-RPC API (DomRobot):

    POST https://api.domrobot.com/jsonrpc/  {"method": "account.login", "params": {user, pass}}
         -> {code: 1000, resData: {tfa: "0" | "GOOGLE-AUTH"}}, the session in the cookie "domrobot"
    account.unlock {tan}                      with two-factor sign-in: the current 6-digit code
    nameserver.list {}                        {domains: [{domain}]}
    nameserver.info {domain, type, name}      {record: [{id, name, type, content}]}
    nameserver.createRecord {domain, type, name, content, ttl}     {id}
    nameserver.deleteRecord {id}
    account.logout

code 1000 is "done" (1500 for logout); 2303 "object does not exist" is taken
as gone already on delete. Two-factor: INWX asks for a TOTP code after the
password - acme makes it from the shared secret (the base32 key shown when
2FA was set up), so the secret has to be given; better a separate account
(Account → Sub-accounts / extra users) with no 2FA and only DNS rights.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, _header, http_call,
                                                said_error, unquote_txt)

APIS = {'production': 'https://api.domrobot.com/jsonrpc/',
        'ote': 'https://api.ote.domrobot.com/jsonrpc/'}


def totp(secret_b32, now=None, step=30, digits=6):
    """RFC 6238 TOTP (HMAC-SHA1) of a base32 secret."""
    key = base64.b32decode(secret_b32.replace(' ', '').upper() + '=' * (-len(secret_b32.replace(
        ' ', '')) % 8))
    counter = int((time.time() if now is None else now) // step)
    mac = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


class Inwx(ApiDns):
    kind = 'inwx'
    title = 'INWX'
    vendor = 'INWX'
    who = 'INWX'
    min_ttl = 300
    description = 'TXT records in a domain at INWX, through its JSON-RPC API.'
    fields = [
        field('username', 'User name', 'text', required=True,
              help='An INWX account (best an extra user with DNS rights only, under Account → '
                   'Account access).'),
        field('password', 'Password', 'secret', required=True),
        field('tfa_secret', 'Two-factor secret', 'secret', default='',
              help='Only when the account signs in with two factors: the base32 key shown when '
                   '2FA was set up (not a 6-digit code) - acme makes the code from it. Without '
                   'it an account with 2FA cannot be used.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='INWX takes 300 or more.'),
        field('endpoint', 'Endpoint', 'select', default='production', advanced=True,
              options=[['production', 'api.domrobot.com'],
                       ['ote', 'api.ote.domrobot.com (the test environment)']]),
    ] + PROPAGATION_FIELDS

    _cookie = None

    def _rpc(self, method, params=None, ok=(1000,)):
        h = {'Content-Type': 'application/json', 'Accept': 'application/json',
             'User-Agent': 'acme-challenge'}
        if self._cookie:
            h['Cookie'] = self._cookie
        url = APIS.get(self.c('endpoint', 'production'), APIS['production'])
        st, rh, got = http_call(self.ctx, 'POST', url, json.dumps(
            {'method': method, 'params': params or {}}).encode(), h, who='INWX')
        if st != 200:
            raise said_error('INWX', st, None, got)
        try:
            ans = json.loads(got.decode('utf-8'))
        except (ValueError, UnicodeDecodeError, AttributeError):
            raise PluginError('INWX answered something that is not JSON', detail=got)
        cookie = _header(rh, 'set-cookie')
        if cookie and 'domrobot=' in cookie:
            self._cookie = cookie.split(';', 1)[0].strip()
        if int(ans.get('code') or 0) not in ok:
            raise PluginError('INWX said %s: %s%s' % (
                ans.get('code'), ans.get('msg'), (' (%s)' % ans.get('reason')) if
                ans.get('reason') else ''), detail=ans,
                retry=int(ans.get('code') or 0) >= 2400)
        return ans.get('resData') or {}

    def _login(self):
        if self._cookie:
            return
        got = self._rpc('account.login', {'user': str(self.c('username', '')),
                                          'pass': str(self.c('password', ''))})
        tfa = str(got.get('tfa') or '0')
        if tfa not in ('0', '', 'None'):
            secret = str(self.c('tfa_secret', '') or '')
            if not secret:
                self._cookie = None
                raise PluginError('the INWX account signs in with two factors (%s): set its '
                                  'two-factor secret, or use a user without 2FA' % tfa,
                                  retry=False)
            try:
                code = totp(secret)
            except (ValueError, TypeError, base64.binascii.Error):
                raise PluginError('the two-factor secret is not a base32 key', retry=False)
            self._rpc('account.unlock', {'tan': code})

    def _call(self, method, params=None, ok=(1000,)):
        self._login()
        return self._rpc(method, params, ok)

    def zone_names(self):
        out = []
        for page in range(1, 51):
            got = self._call('nameserver.list', {'page': page, 'pagelimit': 100})
            doms = got.get('domains') or []
            out += [d.get('domain') for d in doms]
            if len(doms) < 100 or len(out) >= int(got.get('count') or 0):
                break
        return out

    def _ours(self, zone, fqdn, value):
        got = self._call('nameserver.info', {'domain': zone, 'type': 'TXT',
                                             'name': D.norm(fqdn)}, ok=(1000,))
        return [r['id'] for r in got.get('record') or []
                if D.norm(r.get('name')) == D.norm(fqdn) and
                unquote_txt(r.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        have = self._ours(zone, fqdn, value)
        if have:
            return {'zone': zone, 'id': have[0]}
        got = self._call('nameserver.createRecord', {
            'domain': zone, 'type': 'TXT', 'name': D.norm(fqdn), 'content': value,
            'ttl': self.ttl()})
        return {'zone': zone, 'id': got.get('id')}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        ids = [h['id']] if h.get('id') else self._ours(zone, fqdn, value)
        for rid in ids:
            self._call('nameserver.deleteRecord', {'id': int(rid)}, ok=(1000, 2303))

    def test(self):
        words = ApiDns.test(self)
        try:
            self._rpc('account.logout', ok=(1000, 1500))
        except PluginError:
            pass
        self._cookie = None
        return words
