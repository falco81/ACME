# -*- coding: utf-8 -*-
"""
Flowmon (Progress Flowmon OS 13.1) through its REST API: the certificate and its key put where
Flowmon takes TLS certificates in - a certificate pair of a reusable TLS setting (Configuration
center -> Reusable settings -> TLS: what the probes decrypt the monitored servers' TLS with), and
the listening ports of the collector that take flows over TLS.

    POST /resources/oauth/token   form: grant_type=password, client_id=invea-tech, username,
                                  password -> {access_token, token_type: bearer, expires_in,
                                  refresh_token}; then Authorization: bearer <access_token>
    GET  /rest/version            [{version}]
    GET  /rest/fcc/reusable-settings-tls               [TlsItem {id, name, certificatePairs,
                                                       usage, usageCount}]
    POST /rest/fcc/reusable-settings-tls               multipart: entity {name, description}
                                                       + entity.tlsCaFile (the CA certificate)
    PUT  /rest/fcc/reusable-settings-tls               multipart: entity {id, name, description}
                                                       + entity.tlsCaFile
    GET  /rest/fcc/reusable-settings-tls/{tlsId}/pairs [TlsPairItem {id, name, parsedCertificate
                                                       {subject, issuer, validFrom, validTo}}]
    POST /rest/fcc/reusable-settings-tls/{tlsId}/pairs multipart: entity {name, description}
                                                       + entity.tlsPrivateKeyFile
                                                       + entity.tlsCertificateFile
    PUT  /rest/fcc/reusable-settings-tls/{tlsId}/pairs multipart: entity {id, name, description}
                                                       + the two files (403: an invalid
                                                       certificate or key)
    GET  /rest/fcc/listening-ports                     [{id, name, secure, certificates
                                                       {key, keyExtension, crt, crtExtension,
                                                       cacrt, cacrtExtension} - base64}]
    PUT  /rest/fcc/listening-ports                     {"entity": {...the port, id and its
                                                       collector's name kept}}

Source: the Flowmon REST API 13.1 (OpenAPI 3, "Flowmon REST API 13.01.00").
Less certain: how the "entity" object of the multipart requests is laid out - the specification
names its parts "entity" and "entity.tlsCaFile" without saying more. The form most such APIs take
(entity[name], entity[tlsCaFile]) is the default; "dotted" (entity.name, entity.tlsCaFile) and
"json" (the entity as one JSON part, the files beside it) are the option "form_style".
"""
from __future__ import annotations

import base64
import json
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, label_of, http_fields, tls_fields,
    verify_fields, chain_list, text, multipart)


class FlowmonTarget(HttpTarget):
    kind = 'flowmon'
    discovery = False
    title = 'Flowmon (REST API)'
    vendor = 'Progress Flowmon'
    description = ('Puts the certificate and its key into a certificate pair of a reusable TLS '
                   'setting (what the probes decrypt the servers\' TLS with) and into the '
                   'listening ports of the collector that take flows over TLS.')
    doc = 'targets.md'
    fields = http_fields(443, 'flowmon.example.local') + [
        field('user', 'User', 'text', required=True, default='admin'),
        field('password', 'Password', 'secret', required=True),
        field('client_id', 'OAuth client', 'text', default='invea-tech', advanced=True,
              help='the client_id of the token request - invea-tech unless Flowmon says another'),
        field('form_style', 'Form of the uploads', 'select', default='brackets', advanced=True,
              options=[['brackets', 'entity[name], entity[tlsCaFile] (the usual)'],
                       ['dotted', 'entity.name, entity.tlsCaFile'],
                       ['json', 'the entity as JSON, the files beside it']],
              help='how the parts of a certificate upload are named - change it only when '
                   'Flowmon refuses an upload'),
    ] + tls_fields()
    deploy_fields = [
        field('tls_setting', 'Reusable TLS setting', 'text', placeholder='Web servers',
              help='its name in Configuration center -> Reusable settings -> TLS: the '
                   'certificate pair goes there (made, with the issuing authority as its CA, '
                   'when there is none of that name). Empty: none'),
        field('pair', 'Certificate pair', 'text', placeholder='www.example.com',
              help='the name of the pair in that setting: replaced when it is there, made '
                   'when not. Empty: the certificate\'s name'),
        field('listening_ports', 'Listening ports over TLS', 'list', placeholder='IPFIX-TLS',
              help='one a line: the collector\'s listening ports (their names) that take flows '
                   'over TLS - each given this certificate, its key and the issuing authority'),
    ] + verify_fields()

    token = None

    def auth_headers(self):
        return {'Authorization': 'bearer %s' % self.token} if self.token else {}

    # -- signing in ------------------------------------------------------------------------
    def login(self):
        body = urllib.parse.urlencode({
            'grant_type': 'password', 'client_id': self.c('client_id') or 'invea-tech',
            'username': self.c('user') or '', 'password': self.c('password') or ''})
        st, hd, d = self.req('POST', '/resources/oauth/token', body,
                             {'Content-Type': 'application/x-www-form-urlencoded'},
                             auth=False, ok=range(200, 500), what='signing in')
        if st >= 400 or not isinstance(d, dict) or not d.get('access_token'):
            raise PluginError('Flowmon did not sign in %s (%s)' % (
                self.c('user'), (d.get('error_description') or d.get('error') or st)
                if isinstance(d, dict) else st), retry=st >= 500)
        self.token = text(d['access_token'])

    def call(self, method, path, body=None, ok=None, what=None, headers=None):
        st, hd, d = self.req(method, path, body, headers, ok=ok, what=what)
        return st, d

    def test(self):
        self.login()
        st, d = self.call('GET', '/rest/version', what='reading the version')
        ver = d[0].get('version') if isinstance(d, list) and d and isinstance(d[0], dict) else '?'
        tls = self.settings()
        ports = [p for p in self.ports() if p.get('secure')]
        return 'signed in to Flowmon %s at %s: %d reusable TLS setting%s, %d listening port%s ' \
               'over TLS' % (ver, self.c('host'), len(tls), '' if len(tls) == 1 else 's',
                             len(ports), '' if len(ports) == 1 else 's')

    # -- what is there ---------------------------------------------------------------------
    def settings(self):
        st, d = self.call('GET', '/rest/fcc/reusable-settings-tls', ok=(200, 204),
                          what='listing the TLS settings')
        return [x for x in (d if isinstance(d, list) else []) if isinstance(x, dict)]

    def pairs(self, tls_id):
        st, d = self.call('GET', '/rest/fcc/reusable-settings-tls/%s/pairs'
                          % urllib.parse.quote(tls_id, safe=''), ok=(200, 204),
                          what='listing its certificate pairs')
        return [x for x in (d if isinstance(d, list) else []) if isinstance(x, dict)]

    def ports(self):
        st, d = self.call('GET', '/rest/fcc/listening-ports', ok=(200, 204),
                          what='listing the listening ports')
        return [x for x in (d if isinstance(d, list) else []) if isinstance(x, dict)]

    # -- uploads ---------------------------------------------------------------------------
    def form(self, entity, files):
        """The multipart body of an upload: the entity's fields and the files, as form_style
        says. files: [(field, filename, bytes)]."""
        style = text(self.c('form_style') or 'brackets')
        parts = []
        if style == 'json':
            parts.append(('entity', ('entity.json', json.dumps(entity).encode(),
                                     'application/json')))
            for k, fn, data in files:
                parts.append((k, (fn, data, 'application/x-pem-file')))
        else:
            name = (lambda k: 'entity.%s' % k) if style == 'dotted' else \
                (lambda k: 'entity[%s]' % k)
            for k, v in entity.items():
                parts.append((name(k), text(v)))
            for k, fn, data in files:
                parts.append((name(k), (fn, data, 'application/x-pem-file')))
        return multipart(parts)

    def send(self, method, path, entity, files, what):
        body, ctype = self.form(entity, files)
        st, d = self.call(method, path, body, headers={'Content-Type': ctype},
                          ok=range(200, 300), what=what)
        return d if isinstance(d, dict) else {}

    # -- the work --------------------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        setting = text(options.get('tls_setting')).strip()
        port_names = lines(options.get('listening_ports'))
        if not setting and not port_names:
            raise PluginError('say where the certificate goes: a reusable TLS setting, or '
                              'listening ports', retry=False)
        pair_name = text(options.get('pair')).strip() or label_of(bundle, options, 100)
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on %s' % self.c('host'))
        self.login()
        did = []
        cert = text(bundle.as_format('cert-pem'))
        key = text(bundle.as_format('key-pem'))
        chain = ''.join(chain_list(bundle))
        if setting:
            did.append(self.put_pair(bundle, setting, pair_name, cert, key, chain))
        if port_names:
            did += self.put_ports(port_names, cert, key, chain)
        self.remember(bundle, options)
        return '; '.join(did)

    def put_pair(self, bundle, setting, pair_name, cert, key, chain):
        tls = next((x for x in self.settings() if text(x.get('name')) == setting), None)
        if tls is None:
            if not chain.strip():
                raise PluginError('the TLS setting %s is not there, and it is made with the '
                                  'issuing authority as its CA - the certificate came with no '
                                  'chain' % setting, retry=False)
            tls = self.send('POST', '/rest/fcc/reusable-settings-tls',
                            {'name': setting, 'description': 'made by acme'},
                            [('tlsCaFile', 'ca.crt', chain.encode())],
                            'making the TLS setting %s' % setting)
            if not tls.get('id'):
                raise PluginError('Flowmon gave no id for the TLS setting %s' % setting,
                                  detail=text(tls)[:4000])
            self.ctx.step('made the reusable TLS setting %s' % setting, 'ok')
        tid = text(tls.get('id'))
        files = [('tlsPrivateKeyFile', 'private.key', key.encode()),
                 ('tlsCertificateFile', 'certificate.crt', cert.encode())]
        old = next((p for p in self.pairs(tid) if text(p.get('name')) == pair_name), None)
        path = '/rest/fcc/reusable-settings-tls/%s/pairs' % urllib.parse.quote(tid, safe='')
        if old:
            self.send('PUT', path, {'id': text(old.get('id')), 'name': pair_name,
                                    'description': 'acme %s' % time.strftime('%Y-%m-%d')},
                      files, 'replacing the pair %s of %s' % (pair_name, setting))
            self.ctx.step('the certificate pair %s of %s replaced%s' % (
                pair_name, setting, (' - used by %d' % int(old.get('usageCount') or 0))
                if old.get('usageCount') else ''), 'ok')
            return 'pair %s of %s replaced' % (pair_name, setting)
        self.send('POST', path, {'name': pair_name, 'description': 'acme %s'
                                 % time.strftime('%Y-%m-%d')},
                  files, 'adding the pair %s to %s' % (pair_name, setting))
        self.ctx.step('the certificate pair %s added to %s' % (pair_name, setting), 'ok')
        return 'pair %s added to %s' % (pair_name, setting)

    def put_ports(self, names, cert, key, chain):
        have = {text(p.get('name')): p for p in self.ports()}
        missing = [n for n in names if n not in have]
        if missing:
            raise PluginError('there is no listening port %s on Flowmon' % ', '.join(missing),
                              retry=False)
        out = []

        def b64(s):
            return base64.b64encode(s.encode()).decode('ascii')
        for n in names:
            port = dict(have[n])
            port.pop('stats', None)
            port['secure'] = True
            port['certificates'] = {'keyExtension': 'pem', 'key': b64(key),
                                    'crtExtension': 'pem', 'crt': b64(cert),
                                    'cacrtExtension': 'pem', 'cacrt': b64(chain or cert)}
            self.call('PUT', '/rest/fcc/listening-ports', {'entity': port},
                      ok=range(200, 300), what='the listening port %s' % n)
            self.ctx.step('the listening port %s takes flows over TLS with it' % n, 'ok')
            out.append('listening port %s' % n)
        return out

    # -- checked -----------------------------------------------------------------------------
    def verify(self, bundle, options):
        """The pair Flowmon holds now: its certificate's end as this one's. None: nothing to look
        at (only listening ports, which say nothing of their certificate)."""
        options = options or {}
        served = super().verify(bundle, options)       # "Check what is served", when asked
        if served is False:
            return False
        setting = text(options.get('tls_setting')).strip()
        if not setting:
            return served
        pair_name = text(options.get('pair')).strip() or label_of(bundle, options, 100)
        if not self.token:
            self.login()
        tls = next((x for x in self.settings() if text(x.get('name')) == setting), None)
        if not tls:
            return False
        p = next((x for x in self.pairs(text(tls.get('id'))) if text(x.get('name')) == pair_name),
                 None)
        if not p:
            return False
        to = text((p.get('parsedCertificate') or {}).get('validTo'))
        end = getattr(bundle, 'not_after', None)
        if not to or not end:
            return served
        try:
            import datetime
            got = datetime.datetime.fromisoformat(to.replace('Z', '+00:00')).timestamp()
        except ValueError:
            return served
        return (abs(got - float(end)) < 120) and served is not False
