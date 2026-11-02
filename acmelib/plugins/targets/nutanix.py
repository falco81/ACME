# -*- coding: utf-8 -*-
"""
Nutanix: the SSL certificate of a cluster (its Prism web console and API)
replaced through the v4 API of Prism Central, the task it starts waited for.

    GET /api/clustermgmt/<v>/config/clusters                       the clusters (the list)
    GET /api/clustermgmt/<v>/config/clusters/<extId>/ssl-certificate   -> its ETag
    PUT /api/clustermgmt/<v>/config/clusters/<extId>/ssl-certificate
        If-Match: <ETag>, NTNX-Request-Id: <a new UUID>
        {"publicCertificate": base64(PEM), "privateKey": base64(PEM),
         "caChain": base64(PEM), "privateKeyAlgorithm": "ECDSA_256" | "RSA_2048" | ...}
        -> {"data": {"extId": <task>}}
    GET /api/prism/<v>/config/tasks/<extId>                          until SUCCEEDED / FAILED
    (HTTP basic authentication of a Prism Central user)

Sources (Nutanix's official v4 Go client and Terraform provider):
    https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/clustermgmt-go-client/api/ssl_certificate_api.go
    https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/clustermgmt-go-client/api/clusters_api.go
    https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/clustermgmt-go-client/models/clustermgmt/v4/config/config_model.go
    https://github.com/nutanix/ntnx-api-golang-clients/blob/df3e26f212cf436be4eaad979d67907ab887ccf3/prism-go-client/api/tasks_api.go
    https://github.com/nutanix/terraform-provider-nutanix/blob/dadc2b20bd0a96f6358104a555f89a3e0b3638ca/nutanix/services/clustersv2/resource_nutanix_ssl_certificate_v2.go
    https://github.com/nutanix/terraform-provider-nutanix/blob/dadc2b20bd0a96f6358104a555f89a3e0b3638ca/website/docs/r/ssl_certificate_v2.html.markdown
"""
from __future__ import annotations

import base64
import time
import urllib.parse
import uuid

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, http_fields, tls_fields, verify_fields, family_of)

ALGORITHMS = {'ec-256': 'ECDSA_256', 'ec-384': 'ECDSA_384', 'ec-521': 'ECDSA_521',
              'rsa-2048': 'RSA_2048', 'rsa-4096': 'RSA_4096'}


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


class NutanixTarget(HttpTarget):
    kind = 'nutanix'
    title = 'Nutanix cluster (Prism Central v4 API)'
    vendor = 'Nutanix'
    description = ('Replaces the SSL certificate of a Nutanix cluster (its Prism web console) '
                   'through the v4 API of Prism Central.')
    doc = 'targets.md'
    fields = http_fields(9440, 'prism-central.example.local') + [
        field('user', 'User', 'text', required=True, default='admin'),
        field('password', 'Password', 'secret', required=True),
        field('cluster', 'Cluster', 'text', required=True,
              placeholder='00061de0-6c4e-25a1-0000-00000000aa11',
              help='the extId of the cluster, or its name; "Load the list" below fills it in'),
        field('cluster_pick', 'Clusters of Prism Central', 'catalog', catalog='clusters',
              depends=['host', 'user', 'password'],
              help='picked from the list, the cluster above is set to it'),
        field('api_version', 'API version', 'select', default='v4.3', advanced=True,
              options=[['v4.3', 'v4.3'], ['v4.2', 'v4.2'], ['v4.1', 'v4.1'],
                       ['v4.0', 'v4.0']],
              help='the version of the clustermgmt and prism APIs your Prism Central serves'),
    ] + tls_fields()
    deploy_fields = [
        field('algorithm', 'Key algorithm', 'select', default='auto', advanced=True,
              options=[['auto', 'as the certificate\'s key'], ['ECDSA_256', 'ECDSA P-256'],
                       ['ECDSA_384', 'ECDSA P-384'], ['RSA_2048', 'RSA 2048'],
                       ['RSA_4096', 'RSA 4096']]),
        field('task_timeout', 'Wait for the task (s)', 'number', default=600, advanced=True),
    ] + verify_fields(9440)
    default_verify_port = 9440

    _sleep = staticmethod(time.sleep)

    def auth_headers(self):
        raw = '%s:%s' % (self.c('user') or '', self.c('password') or '')
        return {'Authorization': 'Basic ' + b64(raw)}

    def v(self):
        return text(self.c('api_version') or 'v4.3')

    def clusters(self):
        st, hd, d = self.req('GET', '/api/clustermgmt/%s/config/clusters' % self.v(),
                             what='listing the clusters')
        return [c for c in (d.get('data') if isinstance(d, dict) else None) or []
                if isinstance(c, dict)]

    def cluster_id(self):
        want = text(self.c('cluster')).strip()
        if not want:
            raise PluginError('no cluster is set', retry=False)
        if len(want) >= 32 and want.count('-') == 4:
            return want
        got = [c for c in self.clusters() if text(c.get('name')) == want]
        if not got:
            raise PluginError('Prism Central has no cluster named "%s"' % want, retry=False)
        return text(got[0].get('extId'))

    def catalog(self, key):
        if key != 'clusters':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts, sets = [], {}
        for c in self.clusters():
            ext = text(c.get('extId'))
            funcs = ','.join(map(text, ((c.get('config') or {}).get('clusterFunction') or [])))
            opts.append([ext, '%s%s' % (c.get('name') or ext, ' (%s)' % funcs if funcs else '')])
            sets[ext] = {'cluster': ext}
        return {'options': opts, 'sets': sets, 'said': '%d clusters' % len(opts)}

    def path(self, cid):
        return '/api/clustermgmt/%s/config/clusters/%s/ssl-certificate' % (
            self.v(), urllib.parse.quote(cid, safe=''))

    def test(self):
        cid = self.cluster_id()
        st, hd, d = self.req('GET', self.path(cid), what='reading the cluster\'s certificate')
        alg = ((d.get('data') or {}).get('privateKeyAlgorithm') if isinstance(d, dict) else '')
        return 'signed in to Prism Central %s; cluster %s%s' % (
            self.c('host'), cid, ', its key %s' % alg if alg else '')

    def algorithm(self, bundle, options):
        a = text(options.get('algorithm') or 'auto')
        if a != 'auto':
            return a
        kt = text(getattr(bundle, 'key_type', '')).lower()
        if kt in ALGORITHMS:
            return ALGORITHMS[kt]
        fam = family_of(bundle)
        if not kt and fam in ('ec', 'rsa'):
            raise PluginError('the size of the certificate\'s key is not known here: choose '
                              'the Key algorithm of the deployment', retry=False)
        raise PluginError('Nutanix takes ECDSA P-256/P-384/P-521 and RSA 2048/4096 keys, not '
                          '%s' % (kt or fam or 'this key'), retry=False)

    def deploy(self, bundle, options):
        options = options or {}
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on the cluster')
        alg = self.algorithm(bundle, options)
        cid = self.cluster_id()
        st, hd, d = self.req('GET', self.path(cid), what='reading the cluster\'s certificate')
        etag = hd.get('etag')
        if not etag:
            raise PluginError('Prism Central gave no ETag for the cluster\'s certificate')
        body = {'publicCertificate': b64(bundle.as_format('cert-pem')),
                'privateKey': b64(bundle.as_format('key-pem')),
                'privateKeyAlgorithm': alg}
        chain = bundle.as_format('chain-pem')
        if chain.strip():
            body['caChain'] = b64(chain)
        st, hd, d = self.req('PUT', self.path(cid), body,
                             {'If-Match': etag, 'NTNX-Request-Id': str(uuid.uuid4())},
                             what='replacing the cluster\'s certificate')
        task = text(((d.get('data') or {}) if isinstance(d, dict) else {}).get('extId'))
        self.ctx.step('the cluster %s takes the certificate%s' % (
            cid, ' (task %s)' % task if task else ''), 'ok')
        if task:
            self.wait(task, float(options.get('task_timeout') or 600))
        self.remember(bundle, options)
        return 'cluster %s: certificate replaced (%s)' % (cid, alg)

    def wait(self, task, timeout):
        end = time.time() + timeout
        path = '/api/prism/%s/config/tasks/%s' % (self.v(), urllib.parse.quote(task, safe=''))
        while True:
            st, hd, d = self.req('GET', path, what='asking for the task %s' % task)
            t = (d.get('data') or {}) if isinstance(d, dict) else {}
            status = text(t.get('status')).upper()
            if status == 'SUCCEEDED':
                self.ctx.step('the task %s succeeded' % task, 'ok')
                return
            if status in ('FAILED', 'CANCELED', 'CANCELLED'):
                msgs = '; '.join(text(m.get('message') if isinstance(m, dict) else m)
                                 for m in t.get('errorMessages') or [])
                raise PluginError('the task %s %s%s' % (task, status.lower(),
                                                        ': ' + msgs if msgs else ''),
                                  detail=text(d)[:4000])
            if self.ctx.cancelled() or time.time() > end:
                raise PluginError('the task %s has not finished in %d s' % (task, timeout))
            self._sleep(5)
