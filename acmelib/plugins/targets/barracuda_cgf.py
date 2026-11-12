# -*- coding: utf-8 -*-
"""
Barracuda CloudGen Firewall (CGF) and Firewall Control Center (REST API of 10.0 / 10.5):
the certificate and its key imported into a Certificate Store entry in place - the
services that use the entry (SSL VPN / CudaLaunch, TLS Inspection, the Access Control
Service...) refer to it by its name and keep it - checked by its fingerprint afterwards.

    https://<host>:8443, X-API-Token: <token> (or HTTP basic: an administrator and password)
    stand-alone box:
    GET    /rest/config/v1/box/store/certificates/<name>     the entry (404: not there)
           -> {"subCertificates": [{"subject", "validity", "fingerprint"...}], ...}
    POST   /rest/config/v1/box/store/certificates            a new entry (self-signed)
           {"name", "comment", "key": {"cryptosystem", "size" | "curve"},
            "certificate": {"subject": {"commonName"}, "subjectAltName"}}
    PUT    /rest/config/v1/box/store/certificates/<name>
           {"action": "import", "certificates": "<PEM leaf + chain>", "key": "<PEM>", "comment"}
    Control Center (the managed boxes have no store of their own):
           /rest/cc/v1/config/global/store/certificates[/<name>]
           /rest/cc/v1/config/ranges/<range>/store/certificates[/<name>]
           /rest/cc/v1/config/ranges/<range>/clusters/<cluster>/store/certificates[/<name>]

Checked against the vendor guide of 2026-11 (barracuda-cloudgen-firewall.md: the Campus
pages "How to Manage Certificates in the Certificate Store" 10.0 / 10.5, "REST API" 10.0 /
10.5, "How to Create a CC Admin to Access the REST API", and the Swagger attachments "Box
configuration - 10.5 / 10.0 / 9.0" and "CC Configuration - 10.5"). The calls are the same in
10.0 and 10.5; 9.0 has only GET /rest/config/v1/box/certificates (read-only): there a
missing store endpoint is said in words, nothing is changed.

Less certain (the guide's "unverified" points):
    - whether a store change is active at once or waits for Activate (the store endpoints
      list no session token; "If no token is given, a temporary session will be started"
      is said of the others) - acme reads the entry back and compares the fingerprint;
    - whether PUT ... action=import makes an entry that is not there - acme makes one first
      (POST, a self-signed placeholder) and imports over it, as the guide advises;
    - the PEM text in JSON with "\n" (the Swagger examples' shape);
    - where in the entry's answer the fingerprint is (subCertificates[].fingerprint, the
      guide's jq example) and its spelling (hex, with or without colons - both read).
A service is pointed at an entry only in Firewall Admin (no REST endpoint for it): acme
replaces the content of the entry the services already use.
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, text, as_bool, norm_fp, fp_of, family_of,
    split_hostport, http_fields, tls_fields, verify_fields)

NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')


def q(s):
    return urllib.parse.quote(text(s), safe='')


def fingerprints_of(d):
    """Every fingerprint an entry's answer holds (subCertificates[], or the entry itself),
    as hex without colons, lower case (norm_fp)."""
    out = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if 'fingerprint' in k.lower() and isinstance(v, (str, dict)):
                    vals = v.values() if isinstance(v, dict) else [v]
                    for x in vals:
                        if isinstance(x, str) and x.strip():
                            out.append(norm_fp(x))
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    walk(d)
    return out


class BarracudaCgfTarget(HttpTarget):
    kind = 'barracuda_cgf'
    discovery = False       # nothing to find: the REST API lists no ranges or clusters to acme
    title = 'Barracuda CloudGen Firewall'
    vendor = 'Barracuda'
    description = ('Imports the certificate and key into a Certificate Store entry of a '
                   'CloudGen Firewall or of a Firewall Control Center (global, range or '
                   'cluster store) through the REST API, in place: the services that use the '
                   'entry keep it. CloudGen Firewall / Control Center 10.0 - 10.5 (9.0 has '
                   'no store endpoints and is refused).')
    doc = 'targets.md'
    fields = http_fields(8443, 'cgf.example.local') + [
        field('auth', 'Sign in with', 'select', default='token',
              options=[['token', 'an API token (X-API-Token)'],
                       ['password', 'an administrator and password']]),
        field('token', 'API token', 'secret', show_if={'auth': ['token']},
              help='Box → Infrastructure Services → REST API Service → Access Tokens'),
        field('user', 'User', 'text', show_if={'auth': ['password']}),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('store', 'Certificate Store', 'select', default='box',
              options=[['box', 'of this firewall (stand-alone box)'],
                       ['global', 'Control Center: global'],
                       ['range', 'Control Center: a range'],
                       ['cluster', 'Control Center: a cluster']],
              help='a firewall managed by a Control Center has no store of its own: use the '
                   'Control Center\'s'),
        field('range', 'Range', 'text', placeholder='1', show_if={'store': ['range', 'cluster']}),
        field('cluster', 'Cluster', 'text', placeholder='prague', show_if={'store': ['cluster']}),
    ] + tls_fields()
    deploy_fields = [
        field('entry', 'Certificate Store entry', 'text', required=True, placeholder='vpn-portal',
              help='the entry the services use (SSL VPN, TLS Inspection...); its certificate '
                   'and key are replaced in place, the services keep pointing at it'),
        field('create', 'Make the entry when it is not there', 'bool', default=True,
              help='a placeholder entry is made first (self-signed), then the certificate is '
                   'imported over it; point the service at it in Firewall Admin once'),
        field('key_format', 'Key as', 'select', default='key-pem', advanced=True,
              options=[['key-pem', 'PKCS#8 (BEGIN PRIVATE KEY)'],
                       ['key-traditional', 'traditional (BEGIN RSA / EC PRIVATE KEY)']]),
    ] + verify_fields()

    def auth_headers(self):
        if (self.c('auth') or 'token') == 'token':
            return {'X-API-Token': text(self.c('token'))}
        raw = '%s:%s' % (text(self.c('user')), text(self.c('password')))
        return {'Authorization': 'Basic ' + base64.b64encode(raw.encode()).decode()}

    def store_path(self):
        """The certificates of the store the target names."""
        where = self.c('store') or 'box'
        if where == 'box':
            return '/rest/config/v1/box/store/certificates'
        if where == 'global':
            return '/rest/cc/v1/config/global/store/certificates'
        rng = text(self.c('range')).strip()
        if not rng:
            raise PluginError('the Control Center range is not set', retry=False)
        if where == 'range':
            return '/rest/cc/v1/config/ranges/%s/store/certificates' % q(rng)
        cl = text(self.c('cluster')).strip()
        if not cl:
            raise PluginError('the Control Center cluster is not set', retry=False)
        return '/rest/cc/v1/config/ranges/%s/clusters/%s/store/certificates' % (q(rng), q(cl))

    def store_words(self):
        where = self.c('store') or 'box'
        return {'box': 'the firewall\'s store', 'global': 'the Control Center\'s global store',
                'range': 'the store of range %s' % self.c('range'),
                'cluster': 'the store of cluster %s/%s' % (self.c('range'), self.c('cluster'))
                }.get(where, where)

    def no_store(self, e):
        """A 404 on the list of the store itself: 9.0 (read-only certificates) or the wrong
        range / cluster."""
        if (self.c('store') or 'box') == 'box':
            return PluginError('the firewall has no Certificate Store endpoints in its REST API '
                               '(CloudGen Firewall 9.0 has only read-only certificates there) - '
                               '10.0 or later is needed; on 9.0 import it in Firewall Admin',
                               detail=e.detail, retry=False)
        return PluginError('the Control Center has no such store (%s) - check the range and '
                           'cluster, and that the range / cluster has its own certificate store '
                           '(Own certificate store Settings: Yes)' % self.store_words(),
                           detail=e.detail, retry=False)

    def test(self):
        try:
            st, hd, d = self.req('GET', self.store_path() + '?expand=true',
                                 what='listing %s' % self.store_words())
        except PluginError as e:
            if 'not found' in str(e):
                raise self.no_store(e)
            raise
        return 'signed in to %s; %s answers' % (self.c('host'), self.store_words())

    def entry(self, name):
        """The entry's answer, None when it is not there."""
        path = '%s/%s' % (self.store_path(), q(name))
        st, hd, d = self.req('GET', path, ok=(200, 404), what='reading the entry %s' % name)
        if st == 404:
            # the store itself missing (9.0, a wrong range) or only the entry: the list says
            try:
                self.req('GET', self.store_path(), what='listing %s' % self.store_words())
            except PluginError as e:
                if 'not found' in str(e):
                    raise self.no_store(e)
                raise
            return None
        return d if isinstance(d, (dict, list)) else {}

    def served_places(self, options):
        return [split_hostport(x) for x in lines((options or {}).get('verify'))]

    def deploy(self, bundle, options):
        options = options or {}
        name = text(options.get('entry')).strip()
        if not NAME_RE.match(name):
            raise PluginError('"%s" is not a Certificate Store entry name (letters, digits, '
                              '. _ -)' % name, retry=False)
        fp = norm_fp(fp_of(bundle))
        cur = self.entry(name)
        if self.unchanged(bundle, options, present=lambda: cur is not None and
                          fp in fingerprints_of(cur)):
            return self.same(bundle, 'in the entry %s' % name)
        if cur is not None and fp in fingerprints_of(cur) and not as_bool(options.get('force')):
            self.ctx.step('the entry %s holds this certificate already' % name, 'ok')
            self.remember(bundle, options)
            return 'already in %s' % name
        did = []
        if cur is None:
            if not as_bool(self.opt(options, 'create', True), True):
                raise PluginError('%s has no entry %s - make it in Firewall Admin, or let acme '
                                  'make it' % (self.store_words(), name), retry=False)
            cn = (list(getattr(bundle, 'names', None) or []) or [bundle.name])[0]
            key = {'cryptosystem': 'EC', 'curve': 'prime256v1'} \
                if family_of(bundle) == 'ec' else {'cryptosystem': 'RSA', 'size': 2048}
            self.req('POST', self.store_path(), {
                'name': name, 'comment': 'acme: placeholder, replaced at once',
                'key': key, 'certificate': {'subject': {'commonName': cn},
                                            'subjectAltName': 'DNS:%s' % cn}},
                what='making the entry %s' % name)
            self.ctx.step('made the entry %s in %s' % (name, self.store_words()))
            did.append('made %s' % name)
        fmt = self.opt(options, 'key_format', 'key-pem')
        try:
            key_pem = text(bundle.as_format(fmt if fmt in ('key-pem', 'key-traditional')
                                            else 'key-pem'))
        except Exception:                               # noqa: BLE001 - a key it cannot be
            key_pem = text(bundle.as_format('key-pem'))
        self.req('PUT', '%s/%s' % (self.store_path(), q(name)), {
            'action': 'import',
            'certificates': text(bundle.as_format('fullchain-pem')),
            'key': key_pem,
            'comment': 'acme %s' % fp_of(bundle)[:16]},
            what='importing the certificate into %s' % name)
        after = self.entry(name)
        if after is None:
            raise PluginError('the entry %s is gone after the import' % name)
        got = fingerprints_of(after)
        if got and fp not in got:
            raise PluginError('the entry %s does not hold the new certificate after the import '
                              '(the change may wait to be activated in Firewall Admin)' % name,
                              detail=text(after)[:4000])
        if not got:
            self.ctx.step('the entry %s says no fingerprint - the import could not be checked'
                          % name, 'warn')
        self.ctx.step('imported the certificate into %s (%s); the services using it keep it'
                      % (name, self.store_words()), 'ok')
        did.append('imported into %s' % name)
        self.remember(bundle, options)
        return ', '.join(did)
