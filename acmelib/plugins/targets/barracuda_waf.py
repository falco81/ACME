# -*- coding: utf-8 -*-
"""
Barracuda Web Application Firewall (REST API v3 / v3.1 / v3.2): the
certificate uploaded under a new name - a certificate's content cannot be
changed in place - each service's SSL security pointed at it, the older acme
certificates no service uses deleted; signed out.

    POST   /restapi/<v>/login   {"username", "password"} -> {"token"};
           then Authorization: Basic base64(<token> + ":")
    GET    /restapi/<v>/certificates/signed-certificate/<name>    there already? (404: no;
           v3: /certificates/<name>)
    POST   /restapi/<v>/certificates/signed-certificate      (v3.1, v3.2; JSON, base64)
           {"name", "signed-certificate", "certificate-key", "intermediary-certificates": [],
            "certificate-type": "PEM Certificate", "key-type": "RSA" | "ECDSA",
            "assign-associated-key": "No", "allow-private-key-export": "No",
            "auto-renew-cert": "No"}
    POST   /restapi/v3/certificates?upload=signed            (v3; multipart: name, type=pem,
           key_type, assign_associated_key=no, allow_private_key_export=no,
           signed_certificate, key, intermediary_certificate)
    GET    /restapi/<v>/services                              the services (the list)
    GET    /restapi/<v>/services/<svc>/ssl-security          -> data.<svc>."SSL Security"
    PUT    /restapi/<v>/services/<svc>/ssl-security          the same, "certificate" (or
           "ecdsa-certificate") the new name; older acme names in "sni-certificate" replaced
    GET    /restapi/<v>/certificates/signed-certificate      the older ones (v3: /certificates)
    DELETE /restapi/<v>/certificates/signed-certificate/<name>   (v3: /certificates/<name>)
    DELETE /restapi/<v>/logout

Checked against (the user's collection of the vendor's documents, api-docs/barracuda/):
    notes.md - quotes from
      https://documentation.campus.barracuda.com/wiki/spaces/BWAFv76/pages/2721541 (login, token)
      https://documentation.campus.barracuda.com/wiki/spaces/BWAFv76/pages/2720415 (status codes)
      https://documentation.campus.barracuda.com/wiki/spaces/BWAFv76/pages/2720418 (examples, v3.2)
      https://documentation.campus.barracuda.com/wiki/spaces/BWAFv76/pages/2720984 (upload=signed)
      https://github.com/barracudanetworks/waf-automation (waf-api/python/LetsEncrypt:
      waf_direct_api.py, waf_acme.py - the upload, then GET + PUT of ssl-security)
      https://github.com/barracudanetworks/terraform-provider-barracudawaf (the token header)
    swagger-v3.1-12.2.0/Login.json, Logout.json, Certificates.json, Signed_Certificate.json,
      Service.json (firmware 12.2.0, API v3.1)
    openapi-github-v11.0.0-v3.2/Service_ssl_security.json, Signed_Certificate.json,
      Service.json, Login.json, Logout.json (firmware 11.0, API v3.2)

Less certain:
    - ssl-security is described only in the v3.2 specification of firmware 11.0 (the 12.x
      reference has no page for it; the official script calls it on v3 too);
    - the shape of the lists of certificates and of GET /services (taken as {"data": {<name>: ...}},
      the general shape of GET answers in the documents);
    - what DELETE answers for a certificate still in use: acme reads every service's SSL
      security first and deletes only those none uses.
"""
from __future__ import annotations

import base64
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, text, object_name, name_prefix, ours, prune,
    http_fields, tls_fields, verify_fields, keep_field, chain_list, family_of, multipart)


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


def q(s):
    return urllib.parse.quote(text(s), safe='')


def names_in(d):
    """The names a GET listed: {"data": {name: {...}}} or a list of {"name"}."""
    data = d.get('data') if isinstance(d, dict) else d
    if isinstance(data, dict):
        return [text(k) for k in data]
    if isinstance(data, list):
        return [text(x.get('name') if isinstance(x, dict) else x) for x in data if x]
    return []


class BarracudaWafTarget(HttpTarget):
    kind = 'barracuda_waf'
    discovery = False       # nothing to find: the WAF does not say its API version
    title = 'Barracuda Web Application Firewall'
    vendor = 'Barracuda'
    description = ('Uploads the certificate to a Barracuda WAF under a new name, points the '
                   'services\' SSL security at it and deletes the older one.')
    doc = 'targets.md'
    fields = http_fields(8443, 'waf.example.local') + [
        field('user', 'User', 'text', required=True, default='admin'),
        field('password', 'Password', 'secret', required=True),
        field('api_version', 'API version', 'select', default='v3.2', advanced=True,
              options=[['v3.2', 'v3.2'], ['v3.1', 'v3.1'], ['v3', 'v3']]),
    ] + tls_fields()
    deploy_fields = [
        field('service', 'Service', 'catalog', catalog='services', autoload=False,
              help='the service (web application) to use the certificate; picked from the '
                   'list or typed'),
        field('services', 'More services', 'list', placeholder='www-https',
              help='one a line: more services'),
        field('slot', 'As', 'select', default='certificate',
              options=[['certificate', 'the certificate of the service'],
                       ['ecdsa-certificate', 'the ECDSA certificate of the service'],
                       ['sni', 'an SNI domain certificate only (the older acme one replaced)']]),
        keep_field(1),
    ] + verify_fields()
    actions = [{'key': 'look', 'label': 'List the services',
                'help': 'Lists the services and the certificates their SSL security uses - it '
                        'changes nothing.',
                'changes': False}]

    token = None

    def v(self):
        v = text(self.c('api_version') or 'v3.2')
        return v if v in ('v3', 'v3.1', 'v3.2') else 'v3.2'

    def auth_headers(self):
        if not self.token:
            return {}
        return {'Authorization': 'Basic ' + b64(self.token + ':')}

    def api(self, method, path, body=None, ok=None, what=None, headers=None):
        st, hd, d = self.req(method, '/restapi/%s/%s' % (self.v(), path), body, headers,
                             ok=ok, what=what)
        return st, (d if isinstance(d, (dict, list)) else {})

    def login(self):
        try:
            st, d = self.api('POST', 'login', {'username': self.c('user') or '',
                                               'password': self.c('password') or ''},
                             what='signing in')
        except PluginError as e:
            raise PluginError(str(e), detail=e.detail, retry=False)
        if not isinstance(d, dict) or not d.get('token'):
            raise PluginError('the WAF gave no token on signing in', retry=False)
        self.token = text(d['token'])

    def logout(self):
        if self.token:
            try:
                self.api('DELETE', 'logout', ok=range(0, 600))
            except PluginError:
                pass
            self.token = None

    def certs_path(self):
        """Where the certificates acme uploads are: signed-certificate on v3.1 / v3.2."""
        return 'certificates' if self.v() == 'v3' else 'certificates/signed-certificate'

    def services(self):
        st, d = self.api('GET', 'services', what='listing the services')
        return names_in(d)

    def ssl_of(self, svc):
        st, d = self.api('GET', 'services/%s/ssl-security' % q(svc), ok=(200, 404),
                         what='reading the SSL security of %s' % svc)
        if st == 404:
            raise PluginError('the WAF has no service "%s"' % svc, retry=False)
        got = ((d.get('data') or {}).get(svc) or {}) if isinstance(d, dict) else {}
        ssl = got.get('SSL Security')
        if not isinstance(ssl, dict):
            raise PluginError('the WAF did not say the SSL security of %s' % svc,
                              detail=text(d)[:4000])
        return ssl

    def test(self):
        self.login()
        try:
            svcs = self.services()
            st, d = self.api('GET', self.certs_path(), what='listing the certificates')
            n = len(names_in(d))
            return 'signed in to the WAF %s (API %s); %d service%s, %d certificate%s' % (
                self.c('host'), self.v(), len(svcs), '' if len(svcs) == 1 else 's', n,
                '' if n == 1 else 's')
        finally:
            self.logout()

    def catalog(self, key):
        if key != 'services':
            raise PluginError('there is no list called %s here' % key, retry=False)
        self.login()
        try:
            opts = [[s, s] for s in self.services()]
            return {'options': opts, 'sets': {}, 'said': '%d services' % len(opts)}
        finally:
            self.logout()

    def action(self, key):
        if key != 'look':
            return HttpTarget.action(self, key)
        self.login()
        try:
            svcs = self.services()
            for s in svcs:
                try:
                    ssl = self.ssl_of(s)
                except PluginError as e:
                    self.ctx.step('%s: %s' % (s, e), 'warn')
                    continue
                sni = [text(x) for x in ssl.get('sni-certificate') or [] if x] \
                    if isinstance(ssl.get('sni-certificate'), list) else []
                self.ctx.step('%s: %s%s%s' % (
                    s, ssl.get('certificate') or '-',
                    ', ECDSA %s' % ssl['ecdsa-certificate'] if ssl.get('ecdsa-certificate')
                    else '', '; SNI ' + ', '.join(sni) if sni else ''))
            return '%d service%s' % (len(svcs), '' if len(svcs) == 1 else 's')
        finally:
            self.logout()

    def upload(self, bundle, name):
        fam = family_of(bundle)
        chain = chain_list(bundle)
        if self.v() == 'v3':
            parts = [('name', name), ('type', 'pem'),
                     ('key_type', 'ecdsa' if fam == 'ec' else 'rsa'),
                     ('assign_associated_key', 'no'), ('allow_private_key_export', 'no'),
                     ('signed_certificate', ('cert.crt', bundle.as_format('cert-pem'),
                                             'application/octet-stream')),
                     ('key', ('cert.key', bundle.as_format('key-pem'),
                              'application/octet-stream'))]
            if chain:
                parts.append(('intermediary_certificate', ('chain.crt', ''.join(chain).encode(),
                                                           'application/octet-stream')))
            body, ctype = multipart(parts)
            self.api('POST', 'certificates?upload=signed', body, headers={'Content-Type': ctype},
                     what='uploading %s' % name)
            return
        self.api('POST', 'certificates/signed-certificate', {
            'name': name,
            'signed-certificate': b64(bundle.as_format('cert-pem')),
            'certificate-key': b64(bundle.as_format('key-pem')),
            'intermediary-certificates': [b64(p) for p in chain],
            'certificate-type': 'PEM Certificate',
            'key-type': 'ECDSA' if fam == 'ec' else 'RSA',
            'assign-associated-key': 'No',
            'allow-private-key-export': 'No',
            'auto-renew-cert': 'No'}, what='uploading %s' % name)

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=63)
        prefix = name_prefix(bundle, options, maxlen=63)
        refs = []
        one = text(options.get('service')).strip()
        if one:
            refs.append(one)
        refs += [r for r in lines(options.get('services')) if r not in refs]
        slot = text(options.get('slot') or 'certificate')
        self.login()
        try:
            st, d = self.api('GET', '%s/%s' % (self.certs_path(), q(name)),
                             ok=(200, 404), what='looking for %s' % name)
            if self.unchanged(bundle, options, present=lambda: st == 200):
                return self.same(bundle, 'as %s' % name)
            did = []
            if st == 404:
                self.upload(bundle, name)
                self.ctx.step('uploaded the certificate %s' % name, 'ok')
                did.append('uploaded %s' % name)
            else:
                self.ctx.step('the certificate %s is on the WAF already' % name)
            for svc in refs:
                ssl = self.ssl_of(svc)
                before = dict(ssl)
                if slot in ('certificate', 'ecdsa-certificate'):
                    ssl[slot] = name
                for k in ('sni-certificate', 'sni-ecdsa-certificate'):
                    if isinstance(ssl.get(k), list):
                        ssl[k] = [name if ours(text(x), prefix) else x for x in ssl[k]]
                if ssl == before:
                    if slot == 'sni':
                        self.ctx.step('%s has no older acme SNI certificate of this name to '
                                      'replace' % svc, 'warn')
                    else:
                        self.ctx.step('%s uses %s already' % (svc, name))
                    continue
                self.api('PUT', 'services/%s/ssl-security' % q(svc), ssl,
                         what='pointing %s at %s' % (svc, name))
                was = [text(before.get(k)) for k in ('certificate', 'ecdsa-certificate')
                       if before.get(k) and before.get(k) != ssl.get(k)]
                self.ctx.step('the service %s uses %s%s' % (svc, name, ' (before: %s)' % ', '.join(
                    was) if was else ''), 'ok')
                did.append(svc)
            self.cleanup(prefix, name, self.keep(options))
            self.remember(bundle, options)
            return ', '.join(did) or 'already %s' % name
        finally:
            self.logout()

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        try:
            st, d = self.api('GET', self.certs_path(), what='listing the certificates')
            gone = prune([n for n in names_in(d) if ours(n, prefix)], prefix, keep, current)
            used = set()
            if gone:
                for s in self.services():
                    ssl = self.ssl_of(s)
                    for k in ('certificate', 'ecdsa-certificate'):
                        if ssl.get(k):
                            used.add(text(ssl[k]))
                    for k in ('sni-certificate', 'sni-ecdsa-certificate'):
                        if isinstance(ssl.get(k), list):
                            used.update(text(x) for x in ssl[k])
        except PluginError as e:
            self.ctx.step('the older certificates cannot be listed: %s' % e, 'warn')
            return
        for old in gone:
            if old in used:
                self.ctx.step('the older %s stays: a service still uses it' % old, 'warn')
                continue
            try:
                self.api('DELETE', '%s/%s' % (self.certs_path(), q(old)),
                         what='deleting %s' % old)
                self.ctx.step('deleted the older %s' % old)
            except PluginError as e:
                self.ctx.step('the older %s stays: %s' % (old, e), 'warn')
