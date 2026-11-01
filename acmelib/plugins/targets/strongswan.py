# -*- coding: utf-8 -*-
"""
strongSwan (IPsec / IKEv2 VPN) over SSH: the certificate, its intermediates
and the key written where strongSwan reads its credentials, then loaded
without dropping a tunnel - "swanctl --load-creds" (vici, swanctl.conf) or
"ipsec rereadall" (the older stroke, ipsec.conf).

    swanctl:  <dir>/x509/<name>.crt  <dir>/x509ca/acme-ca-<id>.crt  <dir>/private/<name>.key
    stroke:   <dir>/ipsec.d/certs/..  ipsec.d/cacerts/..  ipsec.d/private/..

Rights: root, or a user with sudo. The connection's "certs =" (swanctl.conf)
or "leftcert=" (ipsec.conf) names <name>.crt; the key is found by itself.

Sources:
    https://docs.strongswan.org/docs/latest/swanctl/swanctlDir.html
    https://docs.strongswan.org/docs/latest/swanctl/swanctl.html  (--load-creds)
    https://github.com/acmesh-official/acme.sh/blob/master/deploy/strongswan.sh
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, label_of, chain_id, ssh_fields, text)
from acmelib.plugins.targets._x509 import split_chain
from acmelib.plugins.targets import _files as F


class StrongswanTarget(SshMixin, Base):
    kind = 'strongswan'
    title = 'strongSwan (IPsec VPN)'
    vendor = 'strongSwan'
    description = ('Writes the certificate, intermediates and key where strongSwan reads them '
                   'over SSH and loads them with swanctl --load-creds (or ipsec rereadall) - no '
                   'tunnel dropped.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('mode', 'Configured with', 'select', default='swanctl',
              options=[['swanctl', 'swanctl.conf (vici)'], ['stroke', 'ipsec.conf (stroke)']]),
        field('dir', 'Folder', 'text', default='/etc/swanctl',
              help='/etc/swanctl (or /etc/strongswan/swanctl) for swanctl; /etc (holding '
                   'ipsec.d) for stroke'),
        field('file_name', 'File name', 'text', advanced=True,
              help='<this>.crt and <this>.key; empty: the certificate\'s name'),
    ]

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, '(swanctl --version || ipsec version) 2>/dev/null | head -1',
                                   what='signing in', check=False)
        return 'signed in; %s' % (out.strip() or 'strongSwan not found on the PATH')

    def deploy(self, bundle, options):
        options = options or {}
        mode = self.opt(options, 'mode', 'swanctl')
        d = text(self.opt(options, 'dir', '/etc/swanctl')).strip().rstrip('/')
        if not re.match(r'^/[A-Za-z0-9._/-]*$', d) or '..' in d.split('/'):
            raise PluginError('the folder must be an absolute path without shell characters',
                              retry=False)
        name = text(options.get('file_name')).strip() or label_of(bundle, options)
        if not re.match(r'^[A-Za-z0-9._-]+$', name):
            raise PluginError('the file name may hold letters, digits, . - _ only', retry=False)
        sub = {'swanctl': ('x509', 'x509ca', 'private'),
               'stroke': ('ipsec.d/certs', 'ipsec.d/cacerts', 'ipsec.d/private')}[
            'stroke' if mode == 'stroke' else 'swanctl']
        inter, root = split_chain(bundle)
        files = [{'path': '%s/%s/%s.crt' % (d, sub[0], name), 'data': bundle.as_format('cert-pem'),
                  'mode': 0o644, 'owner': None},
                 {'path': '%s/%s/%s.key' % (d, sub[2], name), 'data': bundle.as_format('key-pem'),
                  'mode': 0o600, 'owner': None}]
        for pem in inter + ([root] if root else []):
            files.append({'path': '%s/%s/acme-ca-%s.crt' % (d, sub[1], chain_id(pem)),
                          'data': pem.encode(), 'mode': 0o644, 'owner': None})
        cmd = 'swanctl --load-creds' if mode != 'stroke' else 'ipsec rereadall'
        with self.ssh() as s:
            if not as_bool(options.get('force')) and F.all_same(self, s, files):
                self.remember(bundle, options)
                return self.same(bundle, 'in %s' % files[0]['path'])
            existed = F.write_files(self, s, files)
            self.ctx.step('wrote %s and its key' % files[0]['path'], 'ok')
            rc, out, err = self.sh(s, cmd, check=False)
            if rc != 0:
                F.put_back(self, s, files, existed)
                self.sh(s, cmd, check=False)
                raise PluginError('"%s" failed, the previous files are back: %s'
                                  % (cmd, (text(err) or text(out)).strip()[-300:]))
            self.ctx.step('ran %s' % cmd, 'ok')
            F.drop_previous(self, s, files)
        self.remember(bundle, options)
        return '%s written, %s' % (files[0]['path'], cmd)
