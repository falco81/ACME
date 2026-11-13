# -*- coding: utf-8 -*-
"""
NetScaler (Citrix ADC) over NITRO: files uploaded to /nsconfig/ssl, the
certkey added or updated in place, linked to its intermediates, bound to
SSL virtual servers, the configuration saved.
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, object_name, name_prefix, prune,
    label_of, http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id, text)

SSL_DIR = '/nsconfig/ssl'
# NITRO says an object is not there as HTTP 599 (NetScaler's own status) with an
# errorcode, or as 404 on some builds: 258 "No such resource", 1540 "Certificate
# does not exist" (a certkey, as a NetScaler answered acme's GET sslcertkey/NAME,
# 1.0.31). Read as "not there"; any other 599 stays an error.
NOT_THERE = (258, 1540)


def b64(data):
    import base64
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


class NetScalerTarget(HttpTarget):
    kind = 'netscaler'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'NetScaler / Citrix ADC'
    vendor = 'Citrix'
    description = ('Uploads the certificate and key over NITRO, updates the certkey in place '
                   '(or adds it), links the intermediates, binds SSL virtual servers and '
                   'saves the configuration.')
    doc = 'targets.md'
    fields = http_fields(443, 'adc.example.local') + [
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('certkey', 'Certkey name', 'text',
              help='the certkey kept across renewals; empty: acme-<certificate name>'),
        field('vservers', 'SSL virtual servers', 'list', placeholder='vs_www_ssl\nvs_mail sni',
              help='one a line; "name sni" binds it as an SNI certificate'),
        field('key_format', 'Key as', 'select', default='key-rsa', advanced=True,
              options=[['key-rsa', 'traditional RSA (BEGIN RSA PRIVATE KEY; EC keys go as PKCS#8)'],
                       ['key-pem', 'PKCS#8 (BEGIN PRIVATE KEY)']]),
        keep_field(2),
    ] + verify_fields()

    session = None

    def auth_headers(self):
        return {'Cookie': 'NITRO_AUTH_TOKEN=%s' % self.session} if self.session else {}

    def nitro(self, method, path, body=None, ok=None, what=None, missing_ok=False):
        """(status, answer). missing_ok: an object that is not there - 404, or 599 with
        one of NOT_THERE - comes back as (404, answer) instead of an error."""
        if missing_ok:
            ok = tuple(ok or (200,)) + (404, 599)
        st, hd, d = self.req(method, '/nitro/v1/config/' + path, body, ok=ok, what=what)
        if not isinstance(d, dict):
            d = {}
        if missing_ok and st == 599:
            try:
                code = int(d.get('errorcode') or 0)
            except (TypeError, ValueError):
                code = 0
            if code not in NOT_THERE:
                raise PluginError('%s: the device said 599 - %s' % (
                    what or path, d.get('message') or 'error %s' % (code or '?')), detail=str(d))
            return 404, d
        if st < 300 and d.get('errorcode') not in (None, 0):
            raise PluginError('%s: %s' % (what or path, d.get('message') or
                                          'error %s' % d.get('errorcode')), detail=str(d))
        return st, d

    def login(self):
        st, hd, d = self.req('POST', '/nitro/v1/config/login', {'login': {
            'username': self.c('user'), 'password': self.c('password'), 'timeout': 900}},
            auth=False, what='signing in')
        sid = (d or {}).get('sessionid') if isinstance(d, dict) else None
        if not sid:
            m = re.search(r'NITRO_AUTH_TOKEN=([^;,\s]+)', str(hd.get('set-cookie') or ''))
            if m:                   # (several cookies come joined by ", ")
                sid = m.group(1)
        if not sid:
            raise PluginError('the NetScaler gave no session on signing in')
        self.session = sid

    def logout(self):
        if self.session:
            try:
                self.req('POST', '/nitro/v1/config/logout', {'logout': {}}, ok=range(0, 600))
            except PluginError:
                pass
            self.session = None

    def test(self):
        self.login()
        try:
            st, d = self.nitro('GET', 'nsversion')
            v = (d.get('nsversion') or {})
            if isinstance(v, list):
                v = v[0] if v else {}
            return 'signed in to %s, %s' % (self.c('host'), v.get('version', '?'))
        finally:
            self.logout()

    def upload(self, filename, data):
        self.req('DELETE', '/nitro/v1/config/systemfile/%s?args=filelocation:%s' % (
            urllib.parse.quote(filename), urllib.parse.quote(SSL_DIR, safe='')),
            ok=range(0, 600))
        self.nitro('POST', 'systemfile', {'systemfile': {
            'filename': filename, 'filelocation': SSL_DIR, 'filecontent': b64(data),
            'fileencoding': 'BASE64'}}, what='uploading %s' % filename)

    def certkey(self, name):
        st, d = self.nitro('GET', 'sslcertkey/%s' % urllib.parse.quote(name), ok=(200,),
                           what='reading %s' % name, missing_ok=True)
        if st != 200:
            return None
        items = d.get('sslcertkey') or []
        return items[0] if items else None

    def link(self, name, ca):
        cur = self.certkey(name) or {}
        have = cur.get('linkcertkeyname') or ''
        if have == ca:
            return False
        if have:
            self.nitro('POST', 'sslcertkey?action=unlink', {'sslcertkey': {'certkey': name}},
                       what='unlinking %s' % name)
        self.nitro('POST', 'sslcertkey?action=link', {'sslcertkey': {
            'certkey': name, 'linkcertkeyname': ca}}, what='linking %s to %s' % (name, ca))
        return True

    def deploy(self, bundle, options):
        options = options or {}
        ck = (options.get('certkey') or '').strip() or ('acme-' + label_of(bundle, options, 26))
        stem = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        crt, key = stem + '.crt', stem + '.key'
        self.login()
        try:
            cur = self.certkey(ck)
            if self.unchanged(bundle, options, present=lambda: bool(cur) and
                              cur.get('cert', '').split('/')[-1] == crt):
                return self.same(bundle, 'in %s' % ck)
            self.ctx.step('%s is there (on %s) - updated with the new files' % (
                ck, text(cur.get('cert')).split('/')[-1] or '?') if cur else
                '%s is not there yet - added' % ck)
            self.upload(crt, bundle.as_format('cert-pem'))
            try:
                key_data = bundle.as_format(options.get('key_format') or 'key-rsa')
            except Exception:                           # noqa: BLE001 - an EC key: PKCS#8
                key_data = bundle.as_format('key-pem')
            self.upload(key, key_data)
            if cur:
                self.nitro('POST', 'sslcertkey?action=update', {'sslcertkey': {
                    'certkey': ck, 'cert': crt, 'key': key, 'nodomaincheck': True}},
                    what='updating %s' % ck)
                did = ['updated %s' % ck]
            else:
                self.nitro('POST', 'sslcertkey', {'sslcertkey': {
                    'certkey': ck, 'cert': crt, 'key': key}}, what='adding %s' % ck)
                did = ['added %s' % ck]
            self.ctx.step(did[0], 'ok')
            below = ck
            for pem in chain_list(bundle):
                ca = 'acme-ca-%s' % chain_id(pem)
                if not self.certkey(ca):
                    self.upload(ca + '.crt', pem.encode())
                    self.nitro('POST', 'sslcertkey', {'sslcertkey': {
                        'certkey': ca, 'cert': ca + '.crt'}}, what='adding %s' % ca)
                    self.ctx.step('added the intermediate %s' % ca)
                else:
                    self.ctx.step('the intermediate %s is there already' % ca)
                if self.link(below, ca):
                    self.ctx.step('linked %s to %s' % (below, ca))
                else:
                    self.ctx.step('%s is linked to %s already' % (below, ca))
                below = ca
            for line in lines(options.get('vservers')):
                parts = line.split()
                vs, sni = parts[0], len(parts) > 1 and parts[1].lower() == 'sni'
                st, d = self.nitro('GET', 'sslvserver_sslcertkey_binding/%s'
                                   % urllib.parse.quote(vs), ok=(200,),
                                   what='reading %s' % vs, missing_ok=True)
                if st == 404:
                    raise PluginError('there is no SSL virtual server %s' % vs, retry=False)
                bound = [b.get('certkeyname') for b in
                         (d.get('sslvserver_sslcertkey_binding') or [])]
                if ck in bound:
                    self.ctx.step('%s is bound to %s already' % (ck, vs))
                    continue
                b = {'vservername': vs, 'certkeyname': ck}
                if sni:
                    b['snicert'] = True
                self.nitro('PUT', 'sslvserver_sslcertkey_binding',
                           {'sslvserver_sslcertkey_binding': b}, what='binding %s' % vs)
                self.ctx.step('bound %s to %s%s' % (ck, vs, ' (SNI)' if sni else ''), 'ok')
                did.append('bound to %s' % vs)
            self.nitro('POST', 'nsconfig?action=save', {'nsconfig': {}},
                       what='saving the configuration')
            self.cleanup(prefix, stem, self.keep(options))
            self.remember(bundle, options)
            return ', '.join(did) + ', saved'
        finally:
            self.logout()

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            st, d = self.nitro('GET', 'systemfile?args=filelocation:%s'
                               % urllib.parse.quote(SSL_DIR, safe=''))
        except PluginError as e:
            self.ctx.step('the old files cannot be listed: %s' % e, 'warn')
            return
        files = [f.get('filename', '') for f in (d.get('systemfile') or [])]
        stems = set(f.rsplit('.', 1)[0] for f in files if f.endswith(('.crt', '.key')))
        for stem in prune(stems, prefix, keep, current):
            for ext in ('.crt', '.key'):
                if stem + ext in files:
                    self.req('DELETE', '/nitro/v1/config/systemfile/%s?args=filelocation:%s' % (
                        urllib.parse.quote(stem + ext), urllib.parse.quote(SSL_DIR, safe='')),
                        ok=range(0, 600))
            self.ctx.step('deleted the old files %s.*' % stem)
