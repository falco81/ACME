# -*- coding: utf-8 -*-
"""
Nginx Proxy Manager through its API: the certificate added as a custom
certificate ("other") under a dated name, its files uploaded, the hosts asked
for - and those that used the older acme one - pointed at it (NPM writes their
nginx configuration and reloads nginx), older acme ones deleted when no host
uses them.

    POST   /api/tokens   {"identity": e-mail, "secret": password}  -> {"token", "expires"}
                         (an account with two-factor sign-in: {"requires_2fa"} - not usable)
    GET    /api/nginx/certificates?expand=proxy_hosts,redirection_hosts,dead_hosts
    POST   /api/nginx/certificates   {"provider": "other", "nice_name": NAME}
    POST   /api/nginx/certificates/<id>/upload   multipart: certificate, certificate_key,
                                                  intermediate_certificate
    GET    /api/nginx/proxy-hosts | redirection-hosts | dead-hosts
    PUT    /api/nginx/proxy-hosts/<id>   {"certificate_id": <id>}   (also the other two)
    DELETE /api/nginx/certificates/<id>

Sources (the project's own code):
    https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/routes/nginx/certificates.js
    https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/internal/certificate.js
    https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/routes/tokens.js
    https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/internal/token.js
    https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/internal/proxy-host.js
    https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/schema/paths/nginx/certificates/post.json
    https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/backend/schema/paths/nginx/proxy-hosts/hostID/put.json
"""
from __future__ import annotations

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    tls_fields, verify_fields, keep_field, text, multipart, ours)

KINDS = (('proxy_hosts', 'proxy-hosts', 'proxy host'),
         ('redirection_hosts', 'redirection-hosts', 'redirection host'),
         ('dead_hosts', 'dead-hosts', '404 host'))


class NginxProxyManagerTarget(HttpTarget):
    kind = 'nginx_proxy_manager'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Nginx Proxy Manager'
    vendor = 'Nginx Proxy Manager'
    description = ('Adds the certificate as a custom certificate through the Nginx Proxy '
                   'Manager API and points its hosts at it; deletes the older ones.')
    doc = 'targets.md'
    fields = [
        field('url', 'Address', 'text', required=True, placeholder='http://npm.example.local:81',
              help='the address of the Nginx Proxy Manager administration, with http:// or '
                   'https:// and its port (81 by default)'),
        field('user', 'E-mail', 'text', required=True,
              help='the e-mail an NPM user signs in with - one without two-factor sign-in, '
                   'allowed to manage certificates and hosts'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('proxy_hosts', 'Proxy hosts', 'list', placeholder='www.example.com\n12',
              help='one a line: a domain name a proxy host serves, or its ID'),
        field('redirection_hosts', 'Redirection hosts', 'list', advanced=True,
              help='one a line: a domain name or ID'),
        field('dead_hosts', '404 hosts', 'list', advanced=True,
              help='one a line: a domain name or ID'),
        field('follow', 'Also the hosts that use the older one', 'bool', default=True,
              help='every host that used an older acme certificate of this name is pointed '
                   'at the new one'),
        keep_field(1),
    ] + verify_fields()

    token = None

    def base_url(self):
        u = text(self.c('url')).strip().rstrip('/')
        if not u.startswith(('http://', 'https://')):
            u = 'http://' + u
        return u[:-4] if u.endswith('/api') else u

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.token} if self.token else {}

    def login(self):
        st, hd, d = self.req('POST', '/api/tokens', {'identity': self.c('user') or '',
                                                      'secret': self.c('password') or ''},
                             auth=False, what='signing in')
        d = d if isinstance(d, dict) else {}
        if d.get('requires_2fa'):
            raise PluginError('this NPM user signs in with a second factor: give acme a user '
                              'of its own without one', retry=False)
        if not d.get('token'):
            raise PluginError('Nginx Proxy Manager gave no token on signing in', detail=text(d))
        self.token = d['token']

    def test(self):
        st, hd, d = self.req('GET', '/api/', auth=False, what='reading the version')
        self.login()
        certs = self.certs(expand=False)
        v = (d or {}).get('version') if isinstance(d, dict) else None
        ver = '.'.join(text(v.get(k)) for k in ('major', 'minor', 'revision')) \
            if isinstance(v, dict) else '?'
        return 'signed in to Nginx Proxy Manager %s; %d certificate%s' % (
            ver, len(certs), '' if len(certs) == 1 else 's')

    def certs(self, expand=True):
        path = '/api/nginx/certificates'
        if expand:
            path += '?expand=proxy_hosts,redirection_hosts,dead_hosts'
        st, hd, d = self.req('GET', path, what='listing the certificates')
        return [c for c in d if isinstance(c, dict)] if isinstance(d, list) else []

    def hosts(self, path):
        st, hd, d = self.req('GET', '/api/nginx/%s' % path, what='listing the %s' % path)
        return [h for h in d if isinstance(h, dict)] if isinstance(d, list) else []

    def resolve(self, items, path, words):
        ids = []
        if not items:
            return ids
        listed = self.hosts(path)
        for it in items:
            if it.isdigit() and any(text(h.get('id')) == it for h in listed):
                ids.append(int(it))
                continue
            got = [h['id'] for h in listed if it.lower() in
                   [text(n).lower() for n in h.get('domain_names') or []]]
            if not got:
                raise PluginError('there is no %s "%s" in Nginx Proxy Manager' % (words, it),
                                  retry=False)
            ids += [g for g in got if g not in ids]
        return ids

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        self.login()
        certs = self.certs()
        cur = next((c for c in certs if c.get('nice_name') == name and
                    c.get('provider') == 'other'), None)
        if self.unchanged(bundle, options, present=lambda: cur is not None):
            return self.same(bundle, 'as %s' % name)
        did = []
        if cur is None:
            st, hd, cur = self.req('POST', '/api/nginx/certificates',
                                   {'provider': 'other', 'nice_name': name},
                                   what='adding %s' % name)
            if not isinstance(cur, dict) or not cur.get('id'):
                raise PluginError('Nginx Proxy Manager gave no id for %s' % name,
                                  detail=text(cur))
            self.ctx.step('added the custom certificate %s (%s)' % (name, cur['id']))
            did.append('added %s' % name)
        parts = [('certificate', ('certificate.pem', bundle.as_format('cert-pem'),
                                  'application/x-pem-file')),
                 ('certificate_key', ('key.pem', bundle.as_format('key-pem'),
                                      'application/x-pem-file'))]
        chain = bundle.as_format('chain-pem')
        if chain.strip():
            parts.append(('intermediate_certificate', ('chain.pem', chain,
                                                       'application/x-pem-file')))
        body, ctype = multipart(parts)
        self.req('POST', '/api/nginx/certificates/%s/upload' % cur['id'], body,
                 {'Content-Type': ctype}, what='uploading the files of %s' % name)
        self.ctx.step('uploaded the certificate, key and chain of %s' % name, 'ok')
        new_id = cur['id']
        older = [c for c in certs if ours(c.get('nice_name'), prefix) and c['id'] != new_id]
        for key, path, words in KINDS:
            ids = self.resolve(lines(options.get(key)), path, words)
            if as_bool(self.opt(options, 'follow', True), True):
                for c in older:
                    for h in c.get(key) or []:
                        if isinstance(h, dict) and h.get('id') and h['id'] not in ids:
                            ids.append(h['id'])
            for hid in ids:
                self.req('PUT', '/api/nginx/%s/%s' % (path, hid), {'certificate_id': new_id},
                         what='pointing the %s %s at %s' % (words, hid, name))
                self.ctx.step('the %s %s uses %s' % (words, hid, name), 'ok')
                did.append('%s %s' % (words, hid))
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options, id=new_id)
        return ', '.join(did) or 'uploaded %s' % name

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            certs = self.certs()
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        byname = {text(c.get('nice_name')): c for c in certs if c.get('provider') == 'other'}
        for old in prune(list(byname), prefix, keep, current):
            c = byname[old]
            users = sum(len(c.get(k) or []) for k, _p, _w in KINDS)
            if users:
                self.ctx.step('the older %s stays: %d host%s still use%s it' % (
                    old, users, '' if users == 1 else 's', 's' if users == 1 else ''), 'warn')
                continue
            try:
                self.req('DELETE', '/api/nginx/certificates/%s' % c['id'],
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
