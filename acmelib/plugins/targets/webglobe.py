# -*- coding: utf-8 -*-
"""
Webglobe web hosting: the certificate stored as the hosting's own SSL
certificate of a domain, through the Webglobe API (the sign-in is the one of
the Webglobe validation, acmelib/plugins/challenges/webglobe.py - a JWT from
POST /auth/login with the login and an API key):

    GET  /domains, /domains/{id or name}      the domain's ID
    POST /{domainId}/ssl/validate      {certificate, private_key, chain}   checked, nothing stored
    POST /{domainId}/ssl/own-certificate {certificate, private_key, chain} stored and used
    POST /{domainId}/ssl/httpsRedirect {https_redirect: 0 | 1}            optional
    GET  /{domainId}/ssl                      the certificates (Test only reads it)

Webglobe takes its customers' own certificates only with its paid support
(otherwise the API refuses with code 3, "Access to requested module is
denied"). The certificate, its private key and the chain go as PEM, the
chain apart from the certificate.

Source: the Webglobe API's OpenAPI description ("Webglobe API" 1.0,
https://api.webglobe.com/ and https://api.staging.core.webglobe.com/),
kept as test/fixtures/webglobe-openapi.yaml.
"""
from __future__ import annotations

from acmelib.plugins.challenges.webglobe import (DENIED, WebglobeClient, WebglobeError,
                                                 ascii_name, credential_fields)
from acmelib.plugins.targets._common import (Base, PluginError, as_bool, field, text,
                                              verify_fields)


class WebglobeTarget(Base):
    kind = 'webglobe'
    title = 'Webglobe hosting'
    vendor = 'Webglobe'
    description = ('Stores the certificate as the own SSL certificate of a domain hosted at '
                   'Webglobe, through the Webglobe API.')
    doc = 'targets.md'
    fields = credential_fields() + [
        field('domain', 'Domain', 'text', required=True, placeholder='example.cz',
              help='The hosted domain the certificate is for, as the Webglobe administration '
                   'lists it (or its ID there).'),
    ]
    deploy_fields = [
        field('validate', 'Let Webglobe check it first', 'bool', default=True,
              help='The certificate, key and chain are sent to Webglobe\'s check '
                   '(ssl/validate) before they are stored.'),
        field('https_redirect', 'Redirect http to https', 'select', default='',
              options=[['', 'leave as it is'], ['1', 'on'], ['0', 'off']]),
    ] + verify_fields()

    def __init__(self, config, ctx):
        Base.__init__(self, config, ctx)
        self.wg = WebglobeClient(self)
        self._did = None

    def ident(self):
        return '%s:%s' % (text(self.c('login')).strip().lower(),
                          text(self.c('domain')).strip().lower())

    def domain_id(self):
        if self._did is not None:
            return self._did
        d = text(self.c('domain')).strip().rstrip('.')
        if not d:
            raise PluginError('set the domain', retry=False)
        if d.isdigit():
            self._did = int(d)
            return self._did
        name = ascii_name(d)
        did = self.wg.domains().get(name)
        if did is None:
            one = self.wg.domain(name)
            did = one[1] if one and one[0] == name else None
        if did is None:
            raise PluginError('the domain %s is not in this Webglobe account (or the login may '
                              'not see it)' % name, retry=False)
        self._did = did
        return did

    def _denied(self, e, what):
        if isinstance(e, WebglobeError) and e.code in DENIED:
            return PluginError('Webglobe refused %s: its own certificates are only for an '
                               'account with Webglobe\'s paid support (code 3, access to the '
                               'module denied)' % what, detail=e.detail, retry=False)
        return e

    def test(self):
        did = self.domain_id()
        try:
            got = self.wg.call('GET', '/%s/ssl' % did, what='the certificates of the domain')
        except WebglobeError as e:
            return 'Webglobe: signed in; the domain %s is ID %s (its certificates could not be ' \
                   'read: %s)' % (self.c('domain'), did, e)
        n = 0
        for row in (got or {}).get('data') or [] if isinstance(got, dict) else []:
            if isinstance(row, dict):
                n += len(row.get('ssls') or [])
        return 'Webglobe: signed in; the domain %s is ID %s, %d certificate(s) there' % (
            self.c('domain'), did, n)

    def deploy(self, bundle, options):
        options = options or {}
        if self.unchanged(bundle, options):
            return self.same(bundle, 'at Webglobe')
        did = self.domain_id()
        body = {'certificate': text(bundle.as_format('cert-pem')),
                'private_key': text(bundle.as_format('key-pem')),
                'chain': text(bundle.as_format('chain-pem'))}
        if as_bool(self.opt(options, 'validate', True), True):
            try:
                got = self.wg.call('POST', '/%s/ssl/validate' % did, body,
                                   what='the check of the certificate')
            except WebglobeError as e:
                raise self._denied(e, 'the check of the certificate')
            d = (got or {}).get('data') if isinstance(got, dict) else None
            if isinstance(d, dict):
                self.ctx.step('Webglobe checked it: %s, valid to %s' % (
                    d.get('domain') or '?', d.get('valid_to') or '?'))
        try:
            got = self.wg.call('POST', '/%s/ssl/own-certificate' % did, body,
                               what='the certificate')
        except WebglobeError as e:
            raise self._denied(e, 'the certificate')
        cid = None
        if isinstance(got, dict):
            cid = got.get('id')
            if cid is None and isinstance(got.get('data'), dict):
                cid = got['data'].get('id')
        if cid:
            self.ctx.step('stored as the own certificate of %s (%s)' % (self.c('domain'), cid),
                          'ok')
        else:
            self.ctx.step('stored as the own certificate of %s' % self.c('domain'), 'ok')
        redir = text(self.opt(options, 'https_redirect', '')).strip()
        if redir in ('0', '1'):
            self.wg.call('POST', '/%s/ssl/httpsRedirect' % did, {'https_redirect': int(redir)},
                         what='the redirect to https')
            self.ctx.step('http to https redirect on' if redir == '1' else
                          'http to https redirect off')
        self.remember(bundle, options, id=cid)
        return 'stored as the own certificate of %s at Webglobe' % self.c('domain')
