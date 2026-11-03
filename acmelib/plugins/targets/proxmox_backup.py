# -*- coding: utf-8 -*-
"""
Proxmox Backup Server over its API with an API token: the custom
certificate of its web interface and API (proxy.pem / proxy.key) replaced.
PBS reloads its proxy itself.

    https://<pbs>:8007/api2/json, Authorization: PBSAPIToken=<user@realm!token>:<secret>
    GET  /api2/json/nodes/<node>/certificates/info      the certificate now (fingerprint)
    POST /api2/json/nodes/<node>/certificates/custom     form: certificates (the chain, PEM),
         key (PEM), force=1                              <node>: localhost by default

Checked against (the user's collection of the vendor's documents,
api-docs/proxmox/notes.md and pbs_apidoc_certificates.json - the part of PBS's apidoc.js
for /nodes/{node}/certificates), quoting:
    https://pbs.proxmox.com/docs/api-viewer/index.html
    https://pbs.proxmox.com/docs/sysadmin.html
    https://pbs.proxmox.com/docs/user-management.html
    https://git.proxmox.com/?p=proxmox-backup.git;a=blob_plain;f=src/api2/node/certificates.rs;hb=HEAD

Less certain:
    - the base path /api2/json and form-urlencoded bodies are those of Proxmox VE (the PBS
      notes derive them from the API viewer);
    - the token header is PBSAPIToken=<id>:<secret> - a colon, not the "=" of Proxmox VE;
    - "force" is not used by PBS's code (sent anyway, as the schema has it); "restart" is
      ignored by PBS, which reloads its proxy itself;
    - Proxmox VE storages and remotes that pin PBS's fingerprint stop trusting it after the
      change: acme says the new fingerprint in the job (put it there, or have them trust the
      CA instead);
    - PBS's own ACME client writes the same files: do not have both.
"""
from __future__ import annotations

import urllib.parse

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, text, norm_fp, fp_of, form, http_fields, tls_fields,
    verify_fields)


def colons(fp):
    fp = norm_fp(fp)
    return ':'.join(fp[i:i + 2] for i in range(0, len(fp), 2)).upper()


class ProxmoxBackupTarget(HttpTarget):
    kind = 'proxmox_backup'
    title = 'Proxmox Backup Server (API)'
    vendor = 'Proxmox'
    description = ('Uploads the certificate as the custom certificate of a Proxmox Backup '
                   'Server through its API; PBS reloads its proxy by itself.')
    doc = 'targets.md'
    default_verify_port = 8007
    fields = http_fields(8007, 'pbs.example.local') + [
        field('token_id', 'API token ID', 'text', required=True, placeholder='acme@pbs!deploy',
              help='a token with Sys.Modify on /system/certificates'),
        field('token_secret', 'API token secret', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('node', 'Node', 'text', default='localhost', advanced=True,
              help='the node name, or localhost'),
    ] + verify_fields(8007)

    def auth_headers(self):
        return {'Authorization': 'PBSAPIToken=%s:%s' % (self.c('token_id'),
                                                       self.c('token_secret'))}

    def node(self, options):
        n = text((options or {}).get('node')).strip() or 'localhost'
        return urllib.parse.quote(n, safe='')

    def info(self, node):
        st, hd, d = self.req('GET', '/api2/json/nodes/%s/certificates/info' % node,
                             what='reading the certificate')
        data = (d or {}).get('data') if isinstance(d, dict) else None
        if isinstance(data, dict):
            data = [data]
        return [x for x in data or [] if isinstance(x, dict)]

    def test(self):
        got = self.info('localhost')
        c = next((x for x in got if x.get('filename') == 'proxy.pem'), got[0] if got else {})
        return 'signed in to PBS %s; its certificate: %s, until %s' % (
            self.c('host'), c.get('subject') or '?', c.get('notafter') or '?')

    def deploy(self, bundle, options):
        options = options or {}
        node = self.node(options)
        fp = fp_of(bundle)
        now = [norm_fp(x.get('fingerprint')) for x in self.info(node)]
        if fp in now and not options.get('force'):
            self.remember(bundle, options)
            return self.same(bundle, 'on %s' % self.c('host'))
        try:
            self.req('POST', '/api2/json/nodes/%s/certificates/custom' % node, form({
                'certificates': text(bundle.as_format('fullchain-pem')),
                'key': text(bundle.as_format('key-pem')),
                'force': '1'}), {'Content-Type': 'application/x-www-form-urlencoded'},
                what='uploading the certificate')
        except PluginError as e:
            raise PluginError(str(e), retry=e.retry)            # no key in the detail
        self.ctx.step('uploaded the custom certificate; PBS reloads its proxy', 'ok')
        self.ctx.step('the new fingerprint is %s: Proxmox VE storages and remotes that pin the '
                      'old one need it' % colons(fp), 'warn')
        self.remember(bundle, options)
        return 'uploaded to %s' % self.c('host')
