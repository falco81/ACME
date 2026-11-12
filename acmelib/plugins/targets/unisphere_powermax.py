# -*- coding: utf-8 -*-
"""
Dell Unisphere for PowerMax 10.x (embedded management, eMGMT): the Solutions
Enabler (SYMAPI) server certificate of the management nodes, through
Unisphere's Serviceability REST API - NOT the HTTPS certificate of Unisphere.

    GET  /univmax/restapi/version                       -> api_version ("101") - 10.x needed
    POST /univmax/restapi/<api>/serviceability/symmetrix/<array>/application/
         solutions_enabler/custom_certificate/import      multipart: node_name, keyfile,
                                                           certfile, trustfile  (per node)

Unisphere's own HTTPS certificate (port 8443) has no API at all in 10.x - Dell
documents it only in the GUI (Settings → Security → Server Certificates), from a
CSR Unisphere made itself, the key never leaving it: acme cannot put its
certificate there. What has an API is the Solutions Enabler server of the
embedded management (nodes Semgmt0, Semgmt1): its key, certificate and trust file
of one's own. Those calls are the ones of Dell's Python SDK PyU4V
(serviceability.import_custom_certificate); Unisphere's REST reference was not
read - the uncertain part of this module. The trust file holds the CA
certificates the SE server trusts its clients' certificates by: empty, acme puts
the chain of the certificate there (its intermediates).

Sources: PyU4V serviceability.py (Dell), PowerMax Family Security Configuration
Guide (PowerMaxOS 10: Solutions Enabler certificate files, user roles), Dell KB
000210816. Role: Administrator or SecurityAdmin.
"""
from __future__ import annotations

import base64
import re
import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, http_fields, tls_fields, lines, text, multipart,
    chain_list, pem_blocks)


class UnispherePowerMaxTarget(HttpTarget):
    kind = 'unisphere_powermax'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Dell Unisphere for PowerMax (Solutions Enabler certificate)'
    vendor = 'Dell'
    description = ('Imports the key and certificate as the Solutions Enabler (SYMAPI) server '
                   'certificate of the embedded management nodes of Unisphere for PowerMax 10.x '
                   'through its Serviceability REST API. Unisphere\'s own HTTPS certificate has '
                   'no API (only its own CSR in the GUI) and is not changed.')
    doc = 'targets.md'
    fields = http_fields(8443, 'unisphere.example.local') + [
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret', required=True),
        field('array', 'Array ID', 'text', required=True, placeholder='000120000123',
              help='the 12-digit Symmetrix ID of the PowerMax'),
    ] + tls_fields()
    deploy_fields = [
        field('nodes', 'Management nodes', 'list', default='Semgmt0\nSemgmt1',
              help='one a line: the Solutions Enabler nodes of the embedded management'),
        field('trust', 'Trusted CA certificates', 'pem', advanced=True,
              help='the trust file: the CAs of the clients\' certificates; empty: the '
                   'intermediates of this certificate'),
    ]

    api_min = 100

    def auth_headers(self):
        return {'Authorization': 'Basic ' + base64.b64encode(
            ('%s:%s' % (self.c('user'), self.c('password') or '')).encode()).decode()}

    def api_version(self):
        st, hd, d = self.req('GET', '/univmax/restapi/version', what='signing in')
        d = d if isinstance(d, dict) else {}
        api = text(d.get('api_version')).strip()
        words = text(d.get('version')).strip()
        if not api:
            m = re.match(r'^[A-Za-z]?(\d+)\.(\d)', words)
            api = (m.group(1) + m.group(2)) if m else ''
        if not api.isdigit():
            raise PluginError('Unisphere did not say its REST API version (%s)' % (words or '?'),
                              retry=False)
        if int(api) < self.api_min:
            raise PluginError('this Unisphere is %s (REST API %s) - acme needs Unisphere for '
                              'PowerMax 10.0 or later' % (words or '?', api), retry=False)
        if int(api) > 104:
            self.ctx.step('Unisphere %s is newer than the documents this module was checked '
                          'against (10.4)' % (words or api), 'warn')
        return api, words

    def array(self):
        a = text(self.c('array')).strip()
        if not re.match(r'^[0-9A-Za-z]{1,20}$', a):
            raise PluginError('"%s" is not an array ID' % a, retry=False)
        return a

    def test(self):
        api, words = self.api_version()
        a = self.array()
        self.req('GET', '/univmax/restapi/%s/serviceability/symmetrix/%s/application/unisphere'
                 % (api, a), what='reading the embedded management of %s' % a)
        return 'signed in to %s, Unisphere %s (REST API %s), array %s' % (
            self.c('host'), words or '?', api, a)

    def nodes(self, options):
        got = lines(self.opt(options, 'nodes', 'Semgmt0\nSemgmt1'))
        for n in got:
            if not re.match(r'^[A-Za-z0-9_.-]+$', n):
                raise PluginError('"%s" is not a node name' % n, retry=False)
        if not got:
            raise PluginError('no management node is set', retry=False)
        return got

    def deploy(self, bundle, options):
        options = options or {}
        if self.unchanged(bundle, options):
            return self.same(bundle, 'on the Solutions Enabler nodes')
        nodes = self.nodes(options)
        api, words = self.api_version()
        a = self.array()
        trust = ''.join(pem_blocks(options.get('trust'))) or ''.join(chain_list(bundle))
        if not trust:
            raise PluginError('no trusted CA certificate: the certificate has no intermediates '
                              '- give "Trusted CA certificates"', retry=False)
        path = ('/univmax/restapi/%s/serviceability/symmetrix/%s/application/'
                'solutions_enabler/custom_certificate/import'
                % (api, urllib.parse.quote(a, safe='')))
        for n in nodes:
            body, ctype = multipart([
                ('node_name', n),
                ('keyfile', ('acme_key.pem', bundle.as_format('key-pem'), 'application/x-pem-file')),
                ('certfile', ('acme_cert.pem', bundle.as_format('fullchain-pem'),
                              'application/x-pem-file')),
                ('trustfile', ('acme_trust.pem', trust.encode(), 'application/x-pem-file')),
            ])
            self.req('POST', path, body, headers={'Content-Type': ctype},
                     what='importing the certificate on %s' % n, timeout=180)
            self.ctx.step('%s: the Solutions Enabler certificate imported' % n, 'ok')
        self.remember(bundle, options)
        return 'the Solutions Enabler certificate on %s' % ', '.join(nodes)
