# -*- coding: utf-8 -*-
"""
Kubernetes over its API with a bearer token: a kubernetes.io/tls secret made
or replaced; deployments rolled when asked. A dual certificate: the twin in the
same secret beside tls.crt / tls.key, as tls-rsa.crt / tls-rsa.key (or tls-ec.*)
- an ingress reads tls.*, whatever else needs the other kind reads those.
"""
from __future__ import annotations

import base64
import time
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, label_of, tls_fields, verify_fields,
    alt_of, family_of, dual_fp)


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


class KubernetesTarget(HttpTarget):
    kind = 'kubernetes'
    title = 'Kubernetes TLS secret'
    vendor = 'Kubernetes'
    description = ('Makes or replaces a kubernetes.io/tls secret through the API server, '
                   'and can restart deployments that read it.')
    doc = 'targets.md'
    dual = True             # a dual certificate: tls-<kind>.crt / .key beside tls.*
    fields = [
        field('host', 'API server', 'text', required=True,
              placeholder='https://k8s.example.local:6443'),
        field('token', 'Bearer token', 'secret', required=True,
              help='of a service account allowed to get, create and patch secrets'),
        field('namespace', 'Namespace', 'text', default='default'),
    ] + tls_fields()
    deploy_fields = [
        field('secret', 'Secret name', 'text', help='empty: the certificate\'s name'),
        field('namespace', 'Namespace', 'text', help='empty: the target\'s'),
        field('ca', 'Add ca.crt (the chain)', 'bool', default=False),
        field('restart', 'Restart these deployments', 'list', advanced=True,
              help='one a line, deployment names in the namespace (a rollout restart)'),
    ] + verify_fields()

    def auth_headers(self):
        return {'Authorization': 'Bearer %s' % self.c('token')}

    def ns(self, options=None):
        return ((options or {}).get('namespace') or self.c('namespace') or 'default').strip()

    def test(self):
        st, hd, d = self.req('GET', '/version', what='reaching the API server')
        self.req('GET', '/api/v1/namespaces/%s/secrets?limit=1' % urllib.parse.quote(self.ns()),
                 what='reading secrets in %s' % self.ns())
        return 'signed in to Kubernetes %s, secrets in %s can be read' % (
            (d or {}).get('gitVersion', '?'), self.ns())

    def deploy(self, bundle, options):
        options = options or {}
        ns = self.ns(options)
        name = (options.get('secret') or '').strip() or label_of(bundle, options, 63).replace(
            '_', '-')
        url = '/api/v1/namespaces/%s/secrets/%s' % (urllib.parse.quote(ns),
                                                     urllib.parse.quote(name))
        data = {'tls.crt': b64(bundle.as_format('fullchain-pem')),
                'tls.key': b64(bundle.as_format('key-pem'))}
        if as_bool(options.get('ca')):
            data['ca.crt'] = b64(bundle.as_format('chain-pem'))
        alt = alt_of(bundle)
        if alt is not None:
            fam = family_of(alt)
            data['tls-%s.crt' % fam] = b64(alt.as_format('fullchain-pem'))
            data['tls-%s.key' % fam] = b64(alt.as_format('key-pem'))
        st, hd, cur = self.req('GET', url, ok=(200, 404), what='reading %s/%s' % (ns, name))
        if st == 200:
            have = (cur or {}).get('data') or {}
            if all(have.get(k) == v for k, v in data.items() if k.endswith('.crt')) and \
                    not as_bool(options.get('force')):
                return self.same(bundle, 'in %s/%s' % (ns, name))
            if (cur or {}).get('type') not in (None, 'kubernetes.io/tls'):
                raise PluginError('%s/%s is a secret of another type (%s)' % (
                    ns, name, cur.get('type')), retry=False)
            self.req('PATCH', url, {'data': data, 'metadata': {'annotations': {
                'acme/fingerprint': dual_fp(bundle)}}},
                {'Content-Type': 'application/merge-patch+json'},
                what='updating %s/%s' % (ns, name))
            words = ['updated %s/%s' % (ns, name)]
        else:
            self.req('POST', '/api/v1/namespaces/%s/secrets' % urllib.parse.quote(ns), {
                'apiVersion': 'v1', 'kind': 'Secret', 'type': 'kubernetes.io/tls',
                'metadata': {'name': name, 'namespace': ns, 'labels': {
                    'app.kubernetes.io/managed-by': 'acme'},
                    'annotations': {'acme/fingerprint': dual_fp(bundle)}},
                'data': data}, what='making %s/%s' % (ns, name))
            words = ['made %s/%s' % (ns, name)]
        self.ctx.step(words[0], 'ok')
        stamp_ = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        for dep in lines(options.get('restart')):
            self.req('PATCH', '/apis/apps/v1/namespaces/%s/deployments/%s' % (
                urllib.parse.quote(ns), urllib.parse.quote(dep)),
                {'spec': {'template': {'metadata': {'annotations': {
                    'kubectl.kubernetes.io/restartedAt': stamp_}}}}},
                {'Content-Type': 'application/strategic-merge-patch+json'},
                what='restarting %s' % dep)
            self.ctx.step('restarting deployment %s' % dep, 'ok')
            words.append('restarted %s' % dep)
        self.remember(bundle, options)
        return ', '.join(words)
