# -*- coding: utf-8 -*-
"""
Proxmox VE over its API with an API token: the custom certificate of each
node's web interface (pveproxy) replaced, pveproxy restarted.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, field, lines, as_bool, http_fields, tls_fields, verify_fields,
    norm_fp, fp_of, form, text)


class ProxmoxTarget(HttpTarget):
    kind = 'proxmox'
    discovery = False       # nothing to find: the sign-in only (nodes: per deployment)
    title = 'Proxmox VE (API)'
    vendor = 'Proxmox'
    description = ('Uploads the certificate as the custom certificate of the nodes\' web '
                   'interface through the Proxmox VE API and restarts pveproxy.')
    doc = 'targets.md'
    default_verify_port = 8006
    fields = http_fields(8006, 'pve1.example.local') + [
        field('token_id', 'API token ID', 'text', required=True, placeholder='acme@pve!deploy'),
        field('token_secret', 'API token secret', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('nodes', 'Nodes', 'list', help='one a line; empty: every node of the cluster'),
        field('restart', 'Restart pveproxy', 'bool', default=True),
    ] + verify_fields(8006)

    def auth_headers(self):
        return {'Authorization': 'PVEAPIToken=%s=%s' % (self.c('token_id'),
                                                        self.c('token_secret'))}

    def test(self):
        st, hd, d = self.req('GET', '/api2/json/version', what='signing in')
        v = (d or {}).get('data') or {}
        nodes = self.nodes({})
        return 'signed in to %s, Proxmox VE %s, nodes %s' % (self.c('host'), v.get('version', '?'),
                                                             ', '.join(nodes))

    def nodes(self, options):
        want = lines((options or {}).get('nodes'))
        if want:
            return want
        st, hd, d = self.req('GET', '/api2/json/nodes', what='listing the nodes')
        return sorted(n.get('node') for n in (d or {}).get('data') or [] if n.get('node'))

    def served(self, node):
        st, hd, d = self.req('GET', '/api2/json/nodes/%s/certificates/info'
                             % urllib.parse.quote(node), what='reading %s' % node)
        for c in (d or {}).get('data') or []:
            if c.get('filename') == 'pveproxy-ssl.pem':
                return norm_fp(c.get('fingerprint'))
        return None

    def deploy(self, bundle, options):
        options = options or {}
        fp = fp_of(bundle)
        force = as_bool(options.get('force'))
        done, same = [], []
        for node in self.nodes(options):
            if not force and self.served(node) == fp:
                same.append(node)
                continue
            self.req('POST', '/api2/json/nodes/%s/certificates/custom' % urllib.parse.quote(node),
                     form({'certificates': text(bundle.as_format('fullchain-pem')),
                           'key': text(bundle.as_format('key-pem')), 'force': 1,
                           'restart': 1 if as_bool(self.opt(options, 'restart', True), True)
                           else 0}),
                     {'Content-Type': 'application/x-www-form-urlencoded'},
                     what='uploading to %s' % node, timeout=120)
            self.ctx.step('%s has the new certificate' % node, 'ok')
            done.append(node)
        if not done:
            return self.same(bundle, 'on %s' % ', '.join(same))
        self.remember(bundle, options)
        return 'uploaded to %s%s' % (', '.join(done), ' (%s already)' % ', '.join(same)
                                     if same else '')
