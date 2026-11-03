# -*- coding: utf-8 -*-
"""
Synology DSM: the certificate imported (or the one acme put there before
replaced) through the DSM web API, optionally made the default.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, label_of, http_fields, tls_fields, verify_fields,
    multipart, form, text)


class SynologyTarget(HttpTarget):
    kind = 'synology'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Synology DSM'
    vendor = 'Synology'
    description = ('Imports the certificate through the DSM web API, replacing the one acme '
                   'put there before, and can make it the default certificate.')
    doc = 'targets.md'
    default_verify_port = 5001
    fields = http_fields(5001, 'nas.example.local') + [
        field('user', 'User', 'text', required=True,
              help='a member of the administrators group, without 2-step verification'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('desc', 'Description on the NAS', 'text',
              help='the certificate acme replaces each time; empty: acme <name>'),
        field('default', 'Make it the default certificate', 'bool', default=False),
    ] + verify_fields(5001)

    sid = None
    syno_token = None

    def api(self, params, body=None, ctype=None, what=None):
        q = dict(params)
        if self.sid:
            q['_sid'] = self.sid
        h = {}
        if self.syno_token:
            h['X-SYNO-TOKEN'] = self.syno_token
        if body is None:
            body, ctype = form(q), 'application/x-www-form-urlencoded'
            path = '/webapi/entry.cgi'
        else:
            path = '/webapi/entry.cgi?' + urllib.parse.urlencode(q)
        h['Content-Type'] = ctype
        st, hd, d = self.req('POST', path, body, h, what=what)
        if not isinstance(d, dict) or not d.get('success'):
            code = (d.get('error') or {}).get('code') if isinstance(d, dict) else '?'
            raise PluginError('%s: DSM said error %s' % (what or params.get('api'), code),
                              detail=text(d), retry=code not in (400, 401, 402, 403, 404))
        return d.get('data') or {}

    def login(self):
        d = self.api({'api': 'SYNO.API.Auth', 'version': 6, 'method': 'login',
                      'account': self.c('user'), 'passwd': self.c('password'),
                      'session': 'Certificate', 'format': 'sid', 'enable_syno_token': 'yes'},
                     what='signing in')
        self.sid, self.syno_token = d.get('sid'), d.get('synotoken')
        if not self.sid:
            raise PluginError('DSM gave no session', retry=False)

    def logout(self):
        if self.sid:
            try:
                self.api({'api': 'SYNO.API.Auth', 'version': 6, 'method': 'logout',
                          'session': 'Certificate'})
            except PluginError:
                pass
            self.sid = self.syno_token = None

    def certs(self):
        return self.api({'api': 'SYNO.Core.Certificate.CRT', 'version': 1, 'method': 'list'},
                        what='listing the certificates').get('certificates') or []

    def test(self):
        self.login()
        try:
            return 'signed in to %s, %d certificates' % (self.c('host'), len(self.certs()))
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        desc = (options.get('desc') or '').strip() or 'acme %s' % label_of(bundle, options)
        self.login()
        try:
            cur = [c for c in self.certs() if c.get('desc') == desc]
            if self.unchanged(bundle, options, present=lambda: bool(cur)):
                return self.same(bundle, 'as "%s"' % desc)
            chain = text(bundle.as_format('chain-pem'))
            parts = [('key', ('privkey.pem', bundle.as_format('key-pem'), 'application/x-pem-file')),
                     ('cert', ('cert.pem', bundle.as_format('cert-pem'), 'application/x-pem-file'))]
            if chain.strip():
                parts.append(('inter_cert', ('chain.pem', chain.encode(),
                                             'application/x-pem-file')))
            parts += [('id', cur[0].get('id', '') if cur else ''), ('desc', desc)]
            make_default = as_bool(options.get('default')) or bool(cur and cur[0].get('is_default'))
            if make_default:
                parts.append(('as_default', 'true'))
            body, ctype = multipart(parts)
            self.api({'api': 'SYNO.Core.Certificate', 'version': 1, 'method': 'import'},
                     body, ctype, what='importing the certificate')
            words = '%s "%s"%s' % ('replaced' if cur else 'imported', desc,
                                   ' (default)' if make_default else '')
            self.ctx.step(words, 'ok')
            self.remember(bundle, options)
            return words
        finally:
            self.logout()
