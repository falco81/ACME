# -*- coding: utf-8 -*-
"""
HPE Alletra 5000/6000 and Nimble Storage (NimbleOS 5.x, 6.x): the group's custom
certificate - the HTTPS GUI (443) and the REST API (5392) - imported with its key as
PKCS#12 through the NimbleOS REST API and put to use.

    POST   /v1/tokens {"data": {username, password, app_name}}  -> data.session_token, data.id
    GET    /v1/certificates/detail                              (Try)
    POST   /v1/certificates/actions/import
           {"data": {name, input: base64 PKCS#12, pkcs12: true, password, force: true}}
    POST   /v1/certificates/actions/use {"data": {name, https, apis}}
    DELETE /v1/tokens/<id>                                      (signing out)

Sources: HPE's SDKs on GitHub (the NimbleOS REST reference is behind an InfoSight
sign-in): nimble-python-sdk restclient.py (port 5392, POST v1/tokens, X-Auth-Token, the
/{object}/actions/{action} convention, NimbleOS 5.0+), nimble-golang-sdk certificate.go
(generated from the API schema: the object "certificates" - name, input "base-64 encoded
string for either PKCS-12 input or PEM encoded certificate(s)", pkcs12, password, force,
https / apis "for use command", reload_https / reload_apis), ns_user_roles.go (roles
administrator, poweruser, operator, guest).

UNVERIFIED - the names of the two actions. The schema has the fields of an import and of
a "use command", the SDK the URL convention, but the action names themselves (import,
use) could not be read in HPE's reference. They are fields of the deployment (More), with
those defaults; a 404 there is said in words with what to check. Nothing is sent before
the sign-in, and nothing is changed when the import is refused.
NimbleOS 5.x and 6.x: the SDKs show no difference in the certificates object - one module.
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    text, random_password, served_fingerprint, fp_of, split_hostport)

API_PORT = 5392


class HpeNimbleTarget(HttpTarget):
    kind = 'hpe_nimble'
    discovery = False           # nothing to find: its fields are the sign-in
    title = 'HPE Alletra 5000/6000, Nimble Storage (NimbleOS)'
    vendor = 'HPE'
    module_version = ''
    version_label = 'any version'
    description = ('HPE Alletra 5000/6000 and Nimble Storage, NimbleOS 5.x and 6.x: imports '
                   'the certificate with its key (PKCS#12) as the group\'s custom certificate '
                   'through the NimbleOS REST API (port 5392) and uses it for the HTTPS GUI '
                   'and/or the REST API, which reload. The names of the import and use '
                   'actions are not in HPE\'s public documents - check them (More).')
    doc = 'targets.md'
    fields = http_fields(API_PORT, 'nimble.example.local') + [
        field('user', 'User', 'text', required=True, default='svc-acme'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('https', 'Use it for the HTTPS GUI (443)', 'bool', default=True),
        field('apis', 'Use it for the REST API (5392)', 'bool', default=True,
              help='clients that pin the old one (vCenter plugin, VASA, CSI, PowerShell '
                   'Toolkit) must take the new one'),
        field('cert_name', 'Certificate name', 'text', default='custom', advanced=True,
              help='the group\'s certificate replaced: custom'),
        field('import_action', 'Import action', 'text', advanced=True,
              default='/v1/certificates/actions/import',
              help='as the NimbleOS REST API Reference of your version names it'),
        field('use_action', 'Use action', 'text', advanced=True,
              default='/v1/certificates/actions/use',
              help='as the NimbleOS REST API Reference of your version names it'),
    ] + verify_fields()

    token = None
    token_id = None

    def auth_headers(self):
        return {'X-Auth-Token': self.token} if self.token else {}

    def login(self):
        try:
            st, hd, d = self.req('POST', '/v1/tokens', {'data': {
                'username': self.c('user'), 'password': self.c('password') or '',
                'app_name': 'acme'}}, auth=False, what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry='(401)' not in str(e))
        data = (d or {}).get('data') if isinstance(d, dict) else None
        data = data if isinstance(data, dict) else {}
        self.token = data.get('session_token')
        self.token_id = data.get('id')
        if not self.token:
            raise PluginError('the group gave no session_token on signing in')

    def logout(self):
        if self.token and self.token_id:
            try:
                self.req('DELETE', '/v1/tokens/%s' % urllib.parse.quote(text(self.token_id),
                                                                        safe=''),
                         ok=range(0, 600))
            except PluginError:
                pass
        self.token = self.token_id = None

    def call_action(self, path, data, what):
        try:
            return self.req('POST', path, {'data': data}, timeout=120, what=what)
        except PluginError as e:
            if '(404)' in str(e) or '(405)' in str(e):
                raise PluginError(
                    '%s: the group has no action %s - check its name in the NimbleOS REST '
                    'API Reference of this NimbleOS (InfoSight) and set it under More' % (
                        what, path), detail=e.detail, retry=False)
            raise

    def test(self):
        self.login()
        try:
            st, hd, d = self.req('GET', '/v1/certificates/detail',
                                 what='reading the certificates')
            rows = (d or {}).get('data') if isinstance(d, dict) else None
            names = [text(r.get('name')) for r in rows or [] if isinstance(r, dict)]
            return 'signed in to %s: certificates %s' % (self.c('host'),
                                                         ', '.join(names) or 'none listed')
        finally:
            self.logout()

    def served_now(self, bundle, options):
        try:
            for host, port in self.served_places(options):
                h, p = split_hostport('%s:%s' % (host, port))
                if served_fingerprint(h, p, None) != fp_of(bundle):
                    return False
            return bool(self.served_places(options))
        except (OSError, ValueError):
            return False

    def deploy(self, bundle, options):
        options = options or {}
        https = as_bool(self.opt(options, 'https', True), True)
        apis = as_bool(self.opt(options, 'apis', True), True)
        if not (https or apis):
            raise PluginError('neither the HTTPS GUI nor the REST API is to use the '
                              'certificate - tick one', retry=False)
        if not as_bool(options.get('force')) and self.served_now(bundle, options):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the group')
        name = text(self.opt(options, 'cert_name', 'custom')).strip() or 'custom'
        pw = random_password()
        p12 = base64.b64encode(bundle.as_format('pfx', password=pw, alias=name)).decode()
        self.login()
        try:
            self.call_action(text(self.opt(options, 'import_action')).strip(), {
                'name': name, 'input': p12, 'pkcs12': True, 'password': pw, 'force': True},
                'importing the certificate as %s' % name)
            self.ctx.step('imported the certificate with its key as %s' % name, 'ok')
            st, hd, d = self.call_action(text(self.opt(options, 'use_action')).strip(), {
                'name': name, 'https': https, 'apis': apis}, 'putting %s to use' % name)
            uses = ' and '.join(w for w, on in (('the HTTPS GUI', https),
                                                ('the REST API', apis)) if on)
            self.ctx.step('%s uses %s - it reloads' % (uses, name), 'ok')
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'imported %s, used for %s' % (name, uses)

    @staticmethod
    def served_wait(options):
        """The GUI and the API reload after "use": seconds, a minute at most."""
        return (8, 10)

    def served_places(self, options):
        if not self.c('host'):
            return []
        options = options or {}
        out = []
        if as_bool(self.opt(options, 'https', True), True):
            out.append((self.c('host'), 443))
        if as_bool(self.opt(options, 'apis', True), True):
            out.append((self.c('host'), as_int(self.c('port', API_PORT), API_PORT)))
        return out
