# -*- coding: utf-8 -*-
"""
Dell PowerScale (Isilon) OneFS 8.2 - 9.12: the HTTPS certificate of the WebUI
and the Platform API (port 8080), through the OneFS REST API with HTTP basic
authentication.

    GET    /platform/1/cluster/config                -> onefs_version.release ("9.7.0.0")
    PUT    /namespace/ifs/<folder>?recursive=true      x-isi-ifs-target-type: container
    PUT    /namespace/ifs/<folder>/<name>.crt|.key     the certificate + chain, the key (0600)
    POST   /platform/4/certificate/server  {name, description, certificate_path,
                                            certificate_key_path}            -> {"id"}
    PUT    /platform/7/certificate/settings {"default_https_certificate": id}
    DELETE /namespace/ifs/<folder>/<name>.crt|.key     (always, the key does not stay on /ifs)
    GET    /platform/4/certificate/server  -> certificates [{id, name}]   older acme ones
    DELETE /platform/4/certificate/server/<id>                            beyond "keep"

OneFS imports a certificate only from files on the cluster (/ifs), never from
the request: the files go there through the RESTful Access to Namespace (RAN)
of the same port, and are deleted after the import. The default HTTPS
certificate is a setting from OneFS 8.2 (/platform/7/certificate/settings;
8.0/8.1 had "isi certificate server modify --default"): an older OneFS is
refused before anything is changed. Every documented 9.x (9.5 - 9.12, PAPI
v9_12_0) uses the same calls - hence one module.

Sources: Dell KB 000157711 (replace the WebUI certificate), OneFS 9.5 and 9.7 CLI
Administration Guides (certificate management), the PowerScale Python SDK
isilon_sdk v9_12_0 CertificateApi (paths and models), the Ansible module
dellemc.powerscale.server_certificate. Rights: ISI_PRIV_LOGIN_PAPI,
ISI_PRIV_CERTIFICATE (write), and for the files ISI_PRIV_NS_IFS_ACCESS.
Uncertain: whether isi_webui must be restarted for the new default to be served
(the 9.5 guide says so, KB 000157711 does not) - acme does not restart it and its
test of what is served says it when the old one is still there.
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, as_bool, as_int, http_fields, tls_fields, verify_fields,
    keep_field, object_name, name_prefix, prune, ours, text, fp_of, norm_fp)


def onefs_tuple(v):
    m = re.match(r'^\s*v?(\d+)\.(\d+)(?:\.(\d+))?', text(v))
    return tuple(int(x or 0) for x in m.groups()) if m else None


class PowerScaleTarget(HttpTarget):
    kind = 'powerscale'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Dell PowerScale OneFS'
    vendor = 'Dell'
    description = ('Imports the certificate into Dell PowerScale OneFS 8.2 - 9.12 through its '
                   'REST API (the files put on /ifs and deleted after the import) and makes it '
                   'the default HTTPS certificate of the WebUI and Platform API; deletes older '
                   'ones acme put there.')
    doc = 'targets.md'
    fields = http_fields(8080, 'cluster.example.local') + [
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('default', 'Make it the default HTTPS certificate', 'bool', default=True,
              help='the certificate of the WebUI and the Platform API (port 8080)'),
        field('folder', 'Folder on /ifs for the import', 'text', default='/ifs/local',
              advanced=True, help='the files are written there and deleted after the import'),
        keep_field(2),
    ] + verify_fields(8080)

    onefs_min = (8, 2, 0)
    checked_to = (9, 12)

    def auth_headers(self):
        return {'Authorization': 'Basic ' + base64.b64encode(
            ('%s:%s' % (self.c('user'), self.c('password') or '')).encode()).decode()}

    def onefs(self):
        st, hd, d = self.req('GET', '/platform/1/cluster/config', what='signing in')
        d = d if isinstance(d, dict) else {}
        ver = d.get('onefs_version') or {}
        return text(ver.get('release') if isinstance(ver, dict) else ver).strip(), \
            text(d.get('name')).strip()

    def check_version(self):
        rel, name = self.onefs()
        ver = onefs_tuple(rel)
        if ver is None:
            self.ctx.step('the OneFS version cannot be read - the calls of OneFS 9 are used',
                          'warn')
        elif ver < self.onefs_min:
            raise PluginError('this cluster runs OneFS %s - acme needs OneFS 8.2 or later (the '
                              'default HTTPS certificate is a setting from 8.2 on)' % rel,
                              retry=False)
        elif ver[:2] > self.checked_to:
            self.ctx.step('OneFS %s is newer than the documents this module was checked '
                          'against (9.12)' % rel, 'warn')
        return rel, name

    def test(self):
        rel, name = self.check_version()
        st, hd, d = self.req('GET', '/platform/7/certificate/settings',
                             what='reading the certificate settings')
        s = (d.get('settings') if isinstance(d, dict) else None) or {}
        return 'signed in to %s (%s), OneFS %s, default HTTPS certificate %s' % (
            self.c('host'), name or '?', rel or '?', s.get('default_https_certificate') or '?')

    def folder(self, options):
        f = text(self.opt(options, 'folder', '/ifs/local')).strip().rstrip('/') or '/ifs/local'
        if not re.match(r'^/ifs(/[A-Za-z0-9_.-]+)*$', f) or '/..' in f:
            raise PluginError('"%s" is not a folder on /ifs' % f, retry=False)
        return f

    def ns(self, path):
        return '/namespace' + urllib.parse.quote(path)

    def certificates(self):
        st, hd, d = self.req('GET', '/platform/4/certificate/server',
                             what='listing the server certificates')
        return [c for c in ((d or {}).get('certificates') or []) if isinstance(c, dict)] \
            if isinstance(d, dict) else []

    def fingerprint_of(self, cert):
        for f in cert.get('fingerprints') or []:
            if isinstance(f, dict) and text(f.get('type')).upper().replace('-', '') == 'SHA256':
                return norm_fp(f.get('value'))
        return ''

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        folder = self.folder(options)
        make_default = as_bool(self.opt(options, 'default', True), True)
        rel, cname = self.check_version()
        certs = self.certificates()
        mine = [c for c in certs if c.get('name') == name]
        st, hd, d = self.req('GET', '/platform/7/certificate/settings',
                             what='reading the certificate settings')
        current = text(((d or {}).get('settings') or {}).get('default_https_certificate')) \
            if isinstance(d, dict) else ''
        if mine and self.unchanged(bundle, options) and \
                (not make_default or text(mine[0].get('id')) == current):
            return self.same(bundle, 'as %s' % name)
        force = as_bool(options.get('force'))
        there = self.fingerprint_of(mine[0]) if mine else None
        # 1.0.96: on force the same name was posted again - OneFS refuses a second
        # certificate of one name; the one there is used when it is this certificate (or
        # cannot be told and is the default), deleted first when it is another
        if mine and (there == fp_of(bundle) or (there == '' and (
                not force or text(mine[0].get('id')) == current))):
            cid = text(mine[0].get('id'))
            self.ctx.step('%s is there already' % name)
            did = ['%s there already' % name]
        else:
            if mine:
                old = text(mine[0].get('id'))
                if old == current:
                    raise PluginError(
                        'OneFS has another certificate named %s and it is the default HTTPS '
                        'certificate - make another one the default, then deploy again' % name,
                        retry=False)
                self.req('DELETE', '/platform/4/certificate/server/%s'
                         % urllib.parse.quote(old, safe=''),
                         what='deleting the certificate %s there before' % name)
                self.ctx.step('deleted the certificate %s there before (%s)' % (name, old))
            cid = self.import_cert(bundle, name, folder)
            did = ['imported %s' % name]
        if make_default and cid != current:
            self.req('PUT', '/platform/7/certificate/settings',
                     {'default_https_certificate': cid},
                     what='making %s the default HTTPS certificate' % name)
            self.ctx.step('%s is the default HTTPS certificate' % name, 'ok')
            did.append('the default HTTPS certificate')
            current = cid
        self.cleanup(prefix, name, current, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did)

    def import_cert(self, bundle, name, folder):
        crt, key = '%s/%s.crt' % (folder, name), '%s/%s.key' % (folder, name)
        put = {'x-isi-ifs-target-type': 'object', 'x-isi-ifs-access-control': '0600',
               'Content-Type': 'application/octet-stream'}
        self.req('PUT', self.ns(folder) + '?recursive=true',
                 headers={'x-isi-ifs-target-type': 'container',
                          'x-isi-ifs-access-control': '0700'},
                 ok=range(200, 300), what='making the folder %s' % folder)
        try:
            self.req('PUT', self.ns(crt), bundle.as_format('fullchain-pem'), headers=put,
                     what='writing %s' % crt)
            self.req('PUT', self.ns(key), bundle.as_format('key-pem'), headers=put,
                     what='writing the key beside it')
            self.ctx.step('wrote the certificate and key to %s' % folder)
            st, hd, d = self.req('POST', '/platform/4/certificate/server', {
                'name': name, 'description': 'acme %s' % fp_of(bundle)[:16],
                'certificate_path': crt, 'certificate_key_path': key},
                what='importing %s' % name)
        finally:
            for p in (key, crt):
                try:
                    self.req('DELETE', self.ns(p), ok=range(200, 600))
                except PluginError as e:
                    self.ctx.step('%s could not be deleted - delete it by hand: %s' % (p, e),
                                  'warn')
        cid = text((d or {}).get('id')) if isinstance(d, dict) else ''
        if not cid:
            cid = next((text(c.get('id')) for c in self.certificates()
                        if c.get('name') == name), '')
        if not cid:
            raise PluginError('OneFS took %s but gave no id of it' % name)
        self.ctx.step('imported %s (%s)' % (name, cid), 'ok')
        return cid

    def cleanup(self, prefix, current_name, default_id, keep):
        if keep < 0:
            return
        try:
            certs = self.certificates()
        except PluginError as e:
            self.ctx.step('the old certificates cannot be listed: %s' % e, 'warn')
            return
        ids = {text(c.get('name')): text(c.get('id')) for c in certs
               if ours(c.get('name'), prefix)}
        for old in prune(list(ids), prefix, keep, current_name):
            if ids[old] == default_id:
                self.ctx.step('the old %s stays: it is the default HTTPS certificate' % old,
                              'warn')
                continue
            try:
                self.req('DELETE', '/platform/4/certificate/server/%s'
                         % urllib.parse.quote(ids[old], safe=''), what='deleting %s' % old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays: %s' % (old, e), 'warn')

    served_wait = (6, 10)

    def served_places(self, options):
        if not as_bool(self.opt(options, 'default', True), True) or not self.c('host'):
            return []
        return [(self.c('host'), as_int(self.c('port', 8080), 8080))]
