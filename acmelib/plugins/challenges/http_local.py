# -*- coding: utf-8 -*-
"""HTTP-01 answered by this server itself: its nginx on port 80 serves
/.well-known/acme-challenge/<token> (web/acme.php reads meta acme:chal:<token>)."""
from __future__ import annotations

import binascii
import os

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import HttpChallenge


class HttpLocal(HttpChallenge):
    kind = 'http_local'
    title = 'HTTP-01 on this server'
    vendor = 'HTTP'
    description = ('The CA fetches http://NAME/.well-known/acme-challenge/… from acme itself, on '
                   'port 80 - the name must point at acme (or a proxy that sends that path to '
                   'it). Not for wildcards.')
    fields = [
        field('self_check', 'Check before the CA is asked', 'bool', default=False,
              help='Fetch http://NAME/.well-known/acme-challenge/TOKEN from here first. Off '
                   'where this machine cannot reach its own public name (no hairpin NAT).'),
        field('test_url', 'Address tried by Test', 'text', default='http://127.0.0.1',
              advanced=True,
              help='Where Test fetches a probe token from: this machine\'s nginx on port 80.'),
    ]

    def present(self, name, token, key_authorization, txt_value):
        n = self.check_name(name)
        self.check_token(token)
        self.ctx.http_token_put(token, key_authorization)
        self.ctx.step('http://%s/.well-known/acme-challenge/%s is answered by acme' % (n, token))
        return {'token': token, 'ka': key_authorization, 'name': n}

    def ready(self, name, handle):
        handle = handle or {}
        if not self.flag('self_check'):
            return True
        ok, words = self.fetch('http://%s/.well-known/acme-challenge/%s' % (
            handle.get('name') or name, handle.get('token')), handle.get('ka'))
        self.ctx.step(words, 'ok' if ok else 'info')
        return ok

    def cleanup(self, name, handle):
        handle = handle or {}
        if handle.get('token'):
            try:
                self.ctx.http_token_drop(handle['token'])
            except Exception as e:                      # noqa: BLE001
                self.ctx.step('the token could not be taken away: %s' % e, 'warn')

    def test(self):
        token = 'acme-probe-' + binascii.hexlify(os.urandom(8)).decode()
        ka = token + '.' + binascii.hexlify(os.urandom(8)).decode()
        base = str(self.c('test_url', 'http://127.0.0.1')).rstrip('/')
        self.ctx.http_token_put(token, ka)
        try:
            ok, words = self.fetch('%s/.well-known/acme-challenge/%s' % (base, token), ka)
        finally:
            try:
                self.ctx.http_token_drop(token)
            except Exception:                           # noqa: BLE001
                pass
        if not ok:
            raise PluginError('this server does not answer a probe token: %s - is nginx '
                              'serving /.well-known/acme-challenge/ on port 80?' % words)
        return words + ' (a probe token, taken away again)'
