# -*- coding: utf-8 -*-
"""
Pure Storage (Everpure) FlashArray and FlashBlade: the certificate of the management
interface (GUI, REST API; on a FlashArray also the VASA ones, vasa-ct0 / vasa-ct1) replaced
in place through REST API 2.x with an API token. The data path is not touched.

    GET   /api/api_version                    the REST versions the array speaks (no sign-in)
    POST  /api/2.x/login   (FlashBlade: /api/login)
          api-token: <token>                  -> header x-auth-token, sent with every call
    GET   /api/2.x/certificates?names=<name>  the certificate there now
    PATCH /api/2.x/certificates?names=<name>  {"certificate", "intermediate_certificate",
          "key"}                              FlashBlade: "private_key" in place of "key"
    POST  /api/2.x/logout

One module each - FlashArray (Purity//FA 6.x, REST 2.x up to 2.59) and FlashBlade (Purity//FB
4.x, REST 2.x up to 2.30): every 2.x version has these calls.

Sources (the vendor guide navody/certifikaty/storage-hci/pure-storage.md, 2026-11, citing):
    https://code.purestorage.com/swagger/redoc/fa2.59-api-reference.html
    https://code.purestorage.com/swagger/redoc/fb2.30-api-reference.html
    https://docs.ansible.com/ansible/latest/collections/purestorage/flasharray/purefa_certs_module.html
    https://docs.ansible.com/ansible/latest/collections/purestorage/flashblade/purefb_certs_module.html

Less certain: GET /api/api_version (the list of versions) is from the REST reference in
general, not quoted by the guide - the version can be set by hand; the least role is not
documented (array_admin is what the guide counts on); the name of a FlashBlade's management
certificate ("global") is not verified, so it is asked; renewing the management certificate
breaks trust of clients that pinned the old one (VASA in vCenter, Pure1, the vSphere plug-in).
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, http_fields, tls_fields, verify_fields, pem_blocks,
    pem_to_der, as_bool, as_int)


def ver_key(v):
    return tuple(int(x) for x in re.findall(r'\d+', text(v)))


class PureFlashArrayTarget(HttpTarget):
    kind = 'pure_flasharray'
    title = 'Pure Storage FlashArray'
    vendor = 'Pure Storage'
    description = ('Replaces the management certificate of a Pure Storage (Everpure) '
                   'FlashArray - Purity//FA 6.x, REST API 2.x - with its key and chain, in '
                   'place; the GUI and REST API use it at once.')
    doc = 'targets.md'
    discovery = False
    login_path = '/api/2.%s/login'
    key_field = 'key'
    fields = http_fields(443, 'array01.example.local') + [
        field('api_token', 'API token', 'secret', required=True,
              help='of an array_admin account: pureadmin create --api-token, or POST '
                   '/api/2.x/admins/api-tokens'),
        field('api_version', 'REST API version', 'text', advanced=True, placeholder='2.59',
              help='empty: the newest 2.x the array lists (GET /api/api_version)'),
    ] + tls_fields()
    deploy_fields = [
        field('cert_name', 'Certificate on the array', 'text', default='management',
              help='management (the GUI and REST API), or vasa-ct0 / vasa-ct1 on a '
                   'FlashArray'),
    ] + verify_fields()

    token = None

    def auth_headers(self):
        return {'x-auth-token': self.token} if self.token else {}

    def version(self):
        v = text(self.c('api_version')).strip()
        if v:
            if not re.match(r'^2\.\d+$', v):
                raise PluginError('the REST API version is 2.<n> (like 2.59)', retry=False)
            return v
        st, hd, d = self.req('GET', '/api/api_version', auth=False,
                             what='asking for the REST API versions')
        # 1.0.96: an answer that is not JSON (a proxy's page, a login form) said in words,
        # not an AttributeError of bytes
        if not isinstance(d, dict):
            raise PluginError('asking for the REST API versions: the array did not answer '
                              'with JSON - is it a FlashArray / FlashBlade?', retry=False)
        listed = d.get('version') if isinstance(d.get('version'), list) else []
        vers = [x for x in listed if text(x).startswith('2.')]
        if not vers:
            said = ', '.join(map(text, listed)) or '-'
            raise PluginError('the array speaks no REST API 2.x (it said %s)' % said,
                              retry=False)
        return sorted(vers, key=ver_key)[-1]

    def login(self):
        self.v = self.version()
        path = self.login_path % self.v.split('.', 1)[1] if '%s' in self.login_path \
            else self.login_path
        st, hd, d = self.req('POST', path, headers={'api-token': text(self.c('api_token'))},
                             auth=False, what='signing in')
        self.token = hd.get('x-auth-token')
        if not self.token:
            raise PluginError('the array gave no x-auth-token', retry=False)

    def logout(self):
        if self.token:
            try:
                self.req('POST', '/api/%s/logout' % self.v, what='signing out')
            except PluginError:
                pass
            self.token = None

    def cert(self, name):
        st, hd, d = self.req('GET', '/api/%s/certificates?names=%s' % (self.v, name),
                             what='reading the certificate %s' % name)
        if not isinstance(d, dict):
            raise PluginError('reading the certificate %s: the array did not answer with '
                              'JSON' % name)
        items = d.get('items') or []
        return items[0] if isinstance(items, list) and items and isinstance(items[0], dict) \
            else None

    @staticmethod
    def name_of(options):
        n = text((options or {}).get('cert_name') or 'management').strip()
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$', n):
            raise PluginError('"%s" is not a certificate name of the array' % n, retry=False)
        return n

    def test(self):
        self.login()
        try:
            c = self.cert('management') if self.key_field == 'key' else None
            return 'signed in to %s, REST API %s%s' % (
                self.c('host'), self.v, ('; management: %s' % (c.get('common_name') or '?'))
                if c else '')
        finally:
            self.logout()

    def deploy(self, bundle, options):
        options = options or {}
        name = self.name_of(options)
        want = pem_to_der(bundle.cert_pem)
        self.login()
        try:
            now = self.cert(name)
            if now is None:
                raise PluginError('the array has no certificate "%s"' % name, retry=False)
            blocks = pem_blocks(now.get('certificate'))
            if blocks and pem_to_der(blocks[0]) == want and not as_bool(options.get('force')):
                self.remember(bundle, options)
                return self.same(bundle, 'as %s' % name)
            self.ctx.step('%s holds this certificate already - replaced again (forced)' % name
                          if blocks and pem_to_der(blocks[0]) == want else
                          '%s holds another certificate - replacing it' % name if blocks else
                          '%s holds no certificate yet - putting it there' % name)
            body = {'certificate': text(bundle.as_format('cert-pem')),
                    self.key_field: text(bundle.as_format('key-pem'))}
            chain = text(bundle.as_format('chain-pem')).strip()
            if chain:
                body['intermediate_certificate'] = chain + '\n'
            try:
                self.req('PATCH', '/api/%s/certificates?names=%s' % (self.v, name), body,
                         what='replacing %s' % name)
            except PluginError as e:
                raise PluginError(str(e), retry=e.retry)        # no key in the detail
            self.ctx.step('%s holds the new certificate' % name, 'ok')
            if name.startswith('vasa'):
                self.ctx.step('the VASA provider in vCenter may need to be registered again',
                              'warn')
        finally:
            self.logout()
        self.remember(bundle, options)
        return 'replaced %s' % name

    def served_places(self, options):
        if self.c('host') and self.name_of(options) in ('management', 'global'):
            # 1.0.96: the configured port (443 was asked whatever the port)
            return [(self.c('host'), as_int(self.c('port', 443), 443))]
        return []


class PureFlashBladeTarget(PureFlashArrayTarget):
    kind = 'pure_flashblade'
    discovery = False
    title = 'Pure Storage FlashBlade'
    description = ('Replaces a certificate of a Pure Storage (Everpure) FlashBlade - '
                   'Purity//FB 4.x, REST API 2.x - with its key and chain, in place.')
    login_path = '/api/login'
    key_field = 'private_key'
    fields = http_fields(443, 'flashblade01.example.local') + [
        field('api_token', 'API token', 'secret', required=True,
              help='of an array_admin account'),
        field('api_version', 'REST API version', 'text', advanced=True, placeholder='2.30',
              help='empty: the newest 2.x the FlashBlade lists (GET /api/api_version)'),
    ] + tls_fields()
    deploy_fields = [
        field('cert_name', 'Certificate on the FlashBlade', 'text', required=True,
              placeholder='global',
              help='its name as GET /api/2.x/certificates (purecert list) shows it'),
    ] + verify_fields()
