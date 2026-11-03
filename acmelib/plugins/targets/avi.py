# -*- coding: utf-8 -*-
"""
VMware Avi Load Balancer (NSX Advanced Load Balancer) through the Controller's
REST API: the certificate added as an SSL key and certificate object under a
dated name, the intermediates as CA certificates (Avi builds the chain from
them), the virtual services asked for - and the Controller's own portal,
when asked - pointed at it, older acme ones deleted.

    POST  /login   {"username", "password"}  -> the cookies sessionid + csrftoken
          every call then: the cookies, X-CSRFToken, Referer, X-Avi-Version, X-Avi-Tenant
    GET   /api/sslkeyandcertificate?name=NAME          there already?
    POST  /api/sslkeyandcertificate  {"name", "type": "SSL_CERTIFICATE_TYPE_VIRTUALSERVICE",
                                      "certificate": {"certificate": PEM}, "key": PEM}
                                     {"name", "type": "SSL_CERTIFICATE_TYPE_CA", ...}
    GET   /api/virtualservice?name=NAME
    PATCH /api/virtualservice/<uuid>  {"replace": {"ssl_key_and_certificate_refs": [...]}}
    GET / PATCH /api/systemconfiguration  {"replace": {"portal_configuration": {...}}}
    DELETE /api/sslkeyandcertificate/<uuid>             an older one nothing uses
    POST  /logout

A dual certificate (ECDSA and RSA of the same names): both added, the twin
under acme-<name>-<kind>-<date>-<serial>; a virtual service and the portal
take one of each kind ("one or two certificates, EC and/or RSA").

Sources (VMware's official Avi SDK and object model):
    https://github.com/vmware/alb-sdk/blob/eng/python/avi/sdk/avi_api.py
    https://github.com/vmware/alb-sdk/blob/eng/python/avi/sdk/utils/ansible_utils.py
    https://github.com/vmware/alb-sdk/blob/eng/go/models/s_s_l_key_and_certificate.go
    https://github.com/vmware/alb-sdk/blob/eng/go/models/s_s_l_certificate.go
    https://github.com/vmware/alb-sdk/blob/eng/go/models/virtual_service.go
    https://github.com/vmware/alb-sdk/blob/eng/go/models/portal_configuration.go
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.base import Plugin
from acmelib.plugins.targets._common import (
    ours,
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    label_of, http_fields, tls_fields, verify_fields, keep_field, chain_list, chain_id, text,
    alt_of, family_of)

KIND_VS = 'SSL_CERTIFICATE_TYPE_VIRTUALSERVICE'
KIND_SYSTEM = 'SSL_CERTIFICATE_TYPE_SYSTEM'
KIND_CA = 'SSL_CERTIFICATE_TYPE_CA'


def uuid_of(ref):
    """https://ctl/api/sslkeyandcertificate/sslkeyandcertificate-1a2b#name -> the uuid"""
    return text(ref).split('#', 1)[0].rstrip('/').rsplit('/', 1)[-1]


class AviTarget(HttpTarget):
    kind = 'avi'
    title = 'VMware Avi Load Balancer (NSX ALB)'
    vendor = 'VMware'
    description = ('Adds the certificate through the Avi Controller API under a new name, '
                   'points virtual services (and the Controller portal) at it and deletes '
                   'the older ones.')
    doc = 'targets.md'
    dual = True             # a dual certificate: one EC and one RSA reference
    fields = http_fields(443, 'avi-controller.example.local') + [
        field('user', 'User', 'text', required=True, default='admin'),
        field('password', 'Password', 'secret', required=True),
        field('tenant', 'Tenant', 'text', default='admin',
              help='the tenant of the virtual services and certificates'),
        field('api_version', 'API version', 'text', advanced=True, placeholder='22.1.3',
              help='X-Avi-Version sent with each call; empty: the Controller\'s own version'),
    ] + tls_fields()
    deploy_fields = [
        field('virtual_services', 'Virtual services', 'list', placeholder='vs-www',
              help='one a line: the names of the virtual services to use the certificate'),
        field('portal', 'Controller portal certificate', 'bool', default=False,
              help='also the certificate of the Controller\'s own web interface and API'),
        field('ca_certs', 'Add the intermediates as CA certificates', 'bool', default=True,
              advanced=True, help='Avi finds the chain among its CA certificates'),
        keep_field(1),
    ] + verify_fields()

    session = None
    csrf = None
    cookie_name = 'sessionid'
    version = ''

    def auth_headers(self):
        h = {'Referer': self.base_url(), 'X-Avi-Tenant': self.c('tenant') or 'admin'}
        v = text(self.c('api_version')).strip() or self.version
        if v:
            h['X-Avi-Version'] = v
        if self.session:
            h['Cookie'] = '%s=%s; csrftoken=%s' % (self.cookie_name, self.session, self.csrf or '')
            h['X-CSRFToken'] = self.csrf or ''
        return h

    def login(self):
        st, hd, d = self.req('POST', '/login', {'username': self.c('user') or '',
                                                 'password': self.c('password') or ''},
                             auth=False, what='signing in')
        d = d if isinstance(d, dict) else {}
        self.cookie_name = text(d.get('session_cookie_name') or 'sessionid')
        cookies = text(hd.get('set-cookie'))
        m = re.search(r'(?:^|[\s,;])%s=([^;,\s]+)' % re.escape(self.cookie_name), cookies)
        c = re.search(r'(?:^|[\s,;])csrftoken=([^;,\s]+)', cookies)
        if not m or not c:
            raise PluginError('the Controller gave no session on signing in (no %s and '
                              'csrftoken cookies)' % self.cookie_name)
        self.session, self.csrf = m.group(1), c.group(1)
        ver = d.get('version')
        if isinstance(ver, dict):
            self.version = text(ver.get('Version') or ver.get('version') or '')
        return d

    def logout(self):
        if self.session:
            try:
                self.req('POST', '/logout', {}, ok=range(0, 600))
            except PluginError:
                pass
            self.session = None

    def test(self):
        self.login()
        try:
            st, hd, d = self.req('GET', '/api/sslkeyandcertificate?page_size=1',
                                 what='reading the certificates')
            n = d.get('count', '?') if isinstance(d, dict) else '?'
            return 'signed in to %s%s, tenant %s; %s certificates' % (
                self.c('host'), ' (Avi %s)' % self.version if self.version else '',
                self.c('tenant') or 'admin', n)
        finally:
            self.logout()

    # -- discovery (1.0.29): the form filled in from the Controller -------------------------
    discover_keys = ['host', 'port', 'user', 'password', 'verify_tls']

    def discover_setup(self):
        """Read-only: signed in and out as test() is; the version the Controller says on
        signing in offered as the API version (X-Avi-Version), empty - the same, the
        Controller's own - first."""
        out = Plugin.discover_setup(self)
        self.login()
        try:
            if self.version:
                out['facts'].append(['Controller version', self.version])
                self.offer(out, 'api_version', [['', 'Empty: the Controller\'s own version'],
                                                [self.version, self.version]], pick='')
        finally:
            self.logout()
        return out

    # -- objects ----------------------------------------------------------------------------
    def find(self, kind, name):
        st, hd, d = self.req('GET', '/api/%s?name=%s' % (kind, urllib.parse.quote(name)),
                             what='looking for %s' % name)
        got = [x for x in (d.get('results') if isinstance(d, dict) else None) or []
               if x.get('name') == name]
        return got[0] if got else None

    def all_certs(self):
        """Every SSL key and certificate, page by page as the SDK's paginator asks
        (page_size 200 at most, page=2, 3, ... while the answer has a "next")."""
        out = []
        for page in range(1, 51):
            st, hd, d = self.req('GET', '/api/sslkeyandcertificate?page_size=200%s' % (
                '&page=%d' % page if page > 1 else ''), what='listing the certificates')
            d = d if isinstance(d, dict) else {}
            out += [x for x in d.get('results') or [] if isinstance(x, dict)]
            if not d.get('next'):
                break
        return out

    def add(self, b, name, kind):
        st, hd, d = self.req('POST', '/api/sslkeyandcertificate', {
            'name': name, 'type': kind,
            'certificate': {'certificate': text(b.as_format('cert-pem'))},
            'key': text(b.as_format('key-pem'))}, what='adding %s' % name)
        if not isinstance(d, dict) or not d.get('uuid'):
            raise PluginError('the Controller gave no uuid for %s' % name, detail=text(d))
        return d

    def names_for(self, bundle, options):
        """[(bundle, name, prefix)] - the main one, and the twin of a dual certificate;
        the portal's (of the kind "system") named acme-<name>-portal-..."""
        label = label_of(bundle, options, 40)
        if as_bool(options.get('portal')):
            label += '-portal'
        o = dict(options, object_name=label)
        out = [(bundle, object_name(bundle, o), name_prefix(bundle, o))]
        alt = alt_of(bundle)
        if alt is not None:
            o = dict(options, object_name='%s-%s' % (label, family_of(alt)))
            out.append((alt, object_name(alt, o), name_prefix(alt, o)))
        return out

    def deploy(self, bundle, options):
        options = options or {}
        kind = KIND_SYSTEM if as_bool(options.get('portal')) else KIND_VS
        if as_bool(options.get('portal')) and lines(options.get('virtual_services')):
            raise PluginError('the portal takes a certificate of the kind "system", virtual '
                              'services one of the kind "virtual service": make one '
                              'deployment for each', retry=False)
        self.login()
        try:
            wanted = self.names_for(bundle, options)
            have = {n: self.find('sslkeyandcertificate', n) for _b, n, _p in wanted}
            if self.unchanged(bundle, options, present=lambda: all(have.values())):
                return self.same(bundle, 'as %s' % wanted[0][1])
            did = []
            if as_bool(self.opt(options, 'ca_certs', True), True):
                for pem in chain_list(bundle):
                    ca = 'acme-ca-%s' % chain_id(pem)
                    if self.find('sslkeyandcertificate', ca) is None:
                        self.req('POST', '/api/sslkeyandcertificate', {
                            'name': ca, 'type': KIND_CA, 'certificate': {'certificate': pem}},
                            what='adding the CA certificate %s' % ca)
                        self.ctx.step('added the CA certificate %s' % ca)
            refs = []
            for b, name, prefix in wanted:
                obj = have.get(name)
                if obj is None:
                    obj = self.add(b, name, kind)
                    self.ctx.step('added %s' % name, 'ok')
                    did.append('added %s' % name)
                else:
                    self.ctx.step('%s is there already' % name)
                refs.append('/api/sslkeyandcertificate/%s' % obj['uuid'])
            mine = set()
            listed = None
            if lines(options.get('virtual_services')) or as_bool(options.get('portal')):
                listed = self.all_certs()
                for _b, name, prefix in wanted:
                    mine.update(x['uuid'] for x in listed
                                if x.get('name') != name and ours(x.get('name'), prefix))
            new = set(uuid_of(r) for r in refs)
            for vs_name in lines(options.get('virtual_services')):
                vs = self.find('virtualservice', vs_name)
                if vs is None:
                    raise PluginError('there is no virtual service "%s" in the tenant %s'
                                      % (vs_name, self.c('tenant') or 'admin'), retry=False)
                cur = list(vs.get('ssl_key_and_certificate_refs') or [])
                keep = [r for r in cur if uuid_of(r) not in mine and uuid_of(r) not in new]
                if len(refs) == 2 or len(keep) > 1:
                    keep = []           # one of each kind at most: ours take both places
                if [uuid_of(r) for r in cur] == [uuid_of(r) for r in keep + refs]:
                    self.ctx.step('%s uses %s already' % (vs_name, wanted[0][1]))
                    continue
                self.req('PATCH', '/api/virtualservice/%s' % vs['uuid'], {
                    'replace': {'ssl_key_and_certificate_refs': keep + refs}},
                    what='pointing %s at %s' % (vs_name, wanted[0][1]))
                self.ctx.step('%s uses %s' % (vs_name, ', '.join(n for _b, n, _p in wanted)),
                              'ok')
                did.append(vs_name)
            if as_bool(options.get('portal')):
                st, hd, sc = self.req('GET', '/api/systemconfiguration',
                                      what='reading the system configuration')
                pc = dict((sc or {}).get('portal_configuration') or {})
                pc['sslkeyandcertificate_refs'] = refs
                self.req('PATCH', '/api/systemconfiguration',
                         {'replace': {'portal_configuration': pc}},
                         what='setting the portal certificate')
                self.ctx.step('the Controller portal uses %s' % wanted[0][1], 'ok')
                did.append('portal')
            for _b, name, prefix in wanted:
                self.cleanup(listed, prefix, name, self.keep(options))
            self.remember(bundle, options)
            return ', '.join(did) or 'already %s' % wanted[0][1]
        finally:
            self.logout()

    def cleanup(self, listed, prefix, current, keep):
        if keep < 0:
            return
        try:
            listed = self.all_certs() if listed is None else listed
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        byname = {text(x.get('name')): x for x in listed}
        for old in prune(list(byname), prefix, keep, current):
            try:
                self.req('DELETE', '/api/sslkeyandcertificate/%s' % byname[old]['uuid'],
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays (still used?): %s' % (old, e), 'warn')
