# -*- coding: utf-8 -*-
"""
Versions of the Nutanix target (nutanix.py stays the plain one, unchanged).

  '7.5'   Prism Central 7.3 - 7.5 with AOS 7.x clusters: the v4.4 clustermgmt / prism APIs
          (the path the official SDK 4.4.1 calls), signed in with HTTP basic or with the API
          key of a Prism Central service account (X-ntnx-api-key), and the key types of
          AOS 7.5 - RSA 2048 / 4096, ECDSA P-256 / P-384; P-521 is gone from AOS 7.x.

What is the same as the plain module: GET the certificate for its ETag, PUT it with If-Match
and a new NTNX-Request-Id ({"publicCertificate", "privateKey", "caChain" - base64 of the
PEM -, "privateKeyAlgorithm"}), the task waited for at /api/prism/<v>/config/tasks/<extId>.

Sources (the vendor guide navody/certifikaty/storage-hci/nutanix.md, 2026-11, citing):
    https://pypi.org/project/ntnx-clustermgmt-py-client/
    https://developers.nutanix.com/api-reference?namespace=clustermgmt
    https://portal.nutanix.com/page/documents/details?targetId=Command-Ref-AOS-v7_5:acl-ncli-ssl-certificate-auto-r.html
    https://portal.nutanix.com/page/documents/details?targetId=Nutanix-Security-Guide-v7_5:mul-service-account-configure-pc-t.html
    https://github.com/nutanix/nutanix.ansible/blob/main/plugins/modules/ntnx_ssl_certificates_v2.py

Less certain: from which Prism Central v4.4 is served (the SDK 4.4 only shows the path -
older ones can still be chosen in API version); X-ntnx-api-key is the header of the SDK's
configuration; the version of Prism Central is not read (no documented call), so nothing
is refused by it.
"""
from __future__ import annotations

from acmelib.plugins.base import field
from acmelib.plugins.targets._common import PluginError, text, http_fields, tls_fields
from acmelib.plugins.targets.nutanix import NutanixTarget

AOS7 = ('ECDSA_256', 'ECDSA_384', 'RSA_2048', 'RSA_4096')


class Nutanix75Target(NutanixTarget):
    module_version = '7.5'
    version_label = 'Prism Central 7.3 - 7.5 (v4.4 API)'
    description = ('Prism Central 7.3 - 7.5 (v4.4 API), AOS 7.x clusters: signed in '
                   'with a service account\'s API key or a user, and the key types of AOS 7.5 '
                   '(RSA 2048/4096, ECDSA P-256/P-384). Replaces the SSL certificate of a '
                   'cluster (its Prism web console) and waits for the task.')
    fields = http_fields(9440, 'prism-central.example.local') + [
        field('auth', 'Sign in with', 'select', default='api_key',
              options=[['api_key', 'a service account\'s API key'],
                       ['password', 'a user and password']]),
        field('api_key', 'API key', 'secret', show_if={'auth': ['api_key']},
              help='Admin Center > IAM > Identities > Service Accounts > the account > Add New '
                   'Key (API Key); the role Cluster Admin by an authorization policy'),
        field('user', 'User', 'text', default='admin', show_if={'auth': ['password']}),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
        field('cluster', 'Cluster', 'text', required=True,
              placeholder='00061de0-6c4e-25a1-0000-00000000aa11',
              help='the extId of the cluster, or its name; "Load the list" below fills it in'),
        field('cluster_pick', 'Clusters of Prism Central', 'catalog', catalog='clusters',
              depends=['host'],
              help='picked from the list, the cluster above is set to it'),
        field('api_version', 'API version', 'select', default='v4.4', advanced=True,
              options=[['v4.4', 'v4.4'], ['v4.3', 'v4.3'], ['v4.2', 'v4.2'], ['v4.1', 'v4.1'],
                       ['v4.0', 'v4.0']],
              help='the version of the clustermgmt and prism APIs your Prism Central serves'),
    ] + tls_fields()
    deploy_fields = [
        field('algorithm', 'Key algorithm', 'select', default='auto', advanced=True,
              options=[['auto', 'as the certificate\'s key'], ['ECDSA_256', 'ECDSA P-256'],
                       ['ECDSA_384', 'ECDSA P-384'], ['RSA_2048', 'RSA 2048'],
                       ['RSA_4096', 'RSA 4096']]),
        field('task_timeout', 'Wait for the task (s)', 'number', default=600, advanced=True),
    ] + NutanixTarget.deploy_fields[2:]
    discover_keys = ['host', 'port', 'auth', 'api_key', 'user', 'password', 'api_version',
                     'verify_tls']

    def auth_headers(self):
        if text(self.c('auth') or 'api_key') == 'api_key':
            if not self.c('api_key'):
                raise PluginError('no API key is set', retry=False)
            return {'X-ntnx-api-key': text(self.c('api_key'))}
        if not self.c('user') or not self.c('password'):
            raise PluginError('a user and a password are needed', retry=False)
        return NutanixTarget.auth_headers(self)

    def v(self):
        return text(self.c('api_version') or 'v4.4')

    def algorithm(self, bundle, options):
        alg = NutanixTarget.algorithm(self, bundle, options)
        if alg not in AOS7:
            raise PluginError('AOS 7.x takes RSA 2048/4096 and ECDSA P-256/P-384 keys, not %s '
                              '(ECDSA P-521 is gone from AOS 7.5)' % alg, retry=False)
        return alg
