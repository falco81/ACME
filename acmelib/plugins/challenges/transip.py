# -*- coding: utf-8 -*-
"""DNS-01 at TransIP, through REST API v6:

    POST   https://api.transip.nl/v6/auth  {login, nonce, read_only, expiration_time, label,
                                            global_key}
           header Signature: base64(RSA-SHA512 of that body, with the account's key pair)
           -> {token}: a JWT, then "Authorization: Bearer"
    GET    .../domains                                     {domains: [{name}]}
    GET    .../domains/{domain}/dns                        {dnsEntries: [{name, expire, type, content}]}
    POST   .../domains/{domain}/dns  {dnsEntry: {name, expire, type, content}}     one added
    DELETE .../domains/{domain}/dns  {dnsEntry: {...}}                             that one removed

The private key never leaves this machine: the openssl program signs the
sign-in. The key pair is made in the control panel (Account → API → Key
pairs), with "Accept only from whitelisted IP addresses" either off or the
address acme calls from on the list.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import time

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, openssl_sign,
                                                relative, unquote_txt)

API = 'https://api.transip.nl/v6'
EXPIRES = (60, 300, 3600, 86400)


def sign_body(ctx, key_pem, body):
    """The Signature header of a TransIP sign-in: base64 of RSA-SHA512."""
    return base64.b64encode(openssl_sign(ctx, key_pem, body, 'sha512')).decode('ascii')


class TransIp(ApiDns):
    kind = 'transip'
    title = 'TransIP'
    vendor = 'TransIP'
    who = 'TransIP'
    description = 'TXT records in a domain at TransIP, signed in with the account\'s key pair.'
    fields = [
        field('login', 'Login', 'text', required=True, help='The TransIP account name.'),
        field('private_key', 'Private key', 'pem', secret=True, required=True,
              help='Control panel → Account → API → Key pairs → Generate: the private key '
                   'shown once, pasted whole. Either switch "Accept only from whitelisted IP '
                   'addresses" off, or whitelist the address acme calls from.'),
        field('global_key', 'The key pair is not limited to whitelisted addresses', 'bool',
              default=True, advanced=True,
              help='As the key pair was made in the control panel: on for a key pair that '
                   'works from any address.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='TransIP knows 60, 300, 3600 and 86400: another is raised to the next.'),
    ] + PROPAGATION_FIELDS

    _token = None
    _token_until = 0.0

    def ttl(self):
        want = ApiDns.ttl(self)
        return next((t for t in EXPIRES if t >= want), EXPIRES[-1])

    def token(self, now=None):
        now = time.time() if now is None else now
        if self._token and now < self._token_until - 60:
            return self._token
        body = json.dumps({'login': str(self.c('login', '')),
                           'nonce': binascii.hexlify(os.urandom(16)).decode(),
                           'read_only': False, 'expiration_time': '30 minutes',
                           'label': 'acme %d' % int(now),
                           'global_key': bool(self.flag('global_key'))}).encode()
        sig = sign_body(self.ctx, self.c('private_key', ''), body)
        _st, got = api(self.ctx, 'POST', API + '/auth', raw_body=body, who='TransIP',
                       headers={'Content-Type': 'application/json', 'Signature': sig})
        if not isinstance(got, dict) or not got.get('token'):
            raise PluginError('TransIP gave no token', retry=False)
        self._token, self._token_until = got['token'], now + 1800
        return self._token

    def _call(self, method, path, body=None, missing_ok=False):
        st, got = api(self.ctx, method, API + path, body,
                      {'Authorization': 'Bearer ' + self.token()}, who='TransIP',
                      missing_ok=missing_ok)
        return None if st == 404 and missing_ok else got

    def zone_names(self):
        return [d.get('name') for d in (self._call('GET', '/domains') or {}).get('domains') or []]

    def _ours(self, zone, rel, value):
        got = self._call('GET', '/domains/%s/dns' % zone) or {}
        return [e for e in got.get('dnsEntries') or []
                if e.get('type') == 'TXT' and e.get('name') == rel and
                unquote_txt(e.get('content')) == value]

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        if not self._ours(zone, rel, value):
            self._call('POST', '/domains/%s/dns' % zone, {'dnsEntry': {
                'name': rel, 'expire': self.ttl(), 'type': 'TXT', 'content': value}})
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        for e in self._ours(zone, h.get('rel') or relative(fqdn, zone), value):
            self._call('DELETE', '/domains/%s/dns' % zone, {'dnsEntry': {
                'name': e.get('name'), 'expire': e.get('expire'), 'type': 'TXT',
                'content': e.get('content')}}, missing_ok=True)
