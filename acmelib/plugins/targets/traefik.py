# -*- coding: utf-8 -*-
"""
Traefik Proxy (v2 and v3) through its file provider: the certificate and key
written over SSH under dated names, and a dynamic configuration file of their
own listing them (tls.certificates, and the default certificate when asked).
Traefik watches the folder and takes it without a restart; the old files are
deleted after.

    /etc/traefik/dynamic/acme-www.example.com.yml
        tls:
          certificates:
            - certFile: /etc/traefik/certs/acme-www.example.com-20261101-0a1b2c3d.crt
              keyFile:  /etc/traefik/certs/acme-www.example.com-20261101-0a1b2c3d.key

Rights: a user who may write both folders (root, or through sudo). Traefik
started with a file provider watching the folder:
    providers.file.directory=/etc/traefik/dynamic  providers.file.watch=true

Sources:
    https://doc.traefik.io/traefik/https/tls/#user-defined
    https://doc.traefik.io/traefik/providers/file/
    https://doc.traefik.io/traefik/https/tls/#default-certificate
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, object_name, name_prefix, prune,
    ssh_fields, verify_fields, keep_field, quote, text)
from acmelib.plugins.targets import _files as F

_PATH_RE = re.compile(r'^/[A-Za-z0-9._/-]*$')


class TraefikTarget(SshMixin, Base):
    kind = 'traefik'
    discovery = False       # nothing to find: a server over SSH
    title = 'Traefik Proxy (file provider)'
    vendor = 'Traefik Labs'
    description = ('Writes the certificate and a dynamic configuration file for Traefik\'s file '
                   'provider over SSH; Traefik takes it without a restart, the old files are '
                   'deleted.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('cert_dir', 'Folder for the certificates', 'text', default='/etc/traefik/certs'),
        field('dynamic_dir', 'Folder of the file provider', 'text',
              default='/etc/traefik/dynamic',
              help='providers.file.directory - Traefik must watch it'),
        field('seen_as', 'The certificates\' folder as Traefik sees it', 'text', advanced=True,
              placeholder='/certs',
              help='when Traefik runs in a container with the folder mounted elsewhere; '
                   'empty: the same'),
        field('default_cert', 'Also the default certificate', 'bool', default=False,
              help='tls.stores.default.defaultCertificate: served when no other one matches'),
        keep_field(1),
    ] + F.file_fields() + verify_fields()

    def folder(self, options, key):
        p = text(self.opt(options, key)).strip().rstrip('/') or '/'
        if not _PATH_RE.match(p) or '..' in p.split('/'):
            raise PluginError('"%s" is not an absolute path without spaces or shell characters'
                              % p, retry=False)
        return p

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, 'id -un; (traefik version 2>/dev/null || docker ps '
                                      '--format "{{.Image}}" 2>/dev/null | grep -i traefik) '
                                      '| head -3; true', what='signing in')
        o = out.strip().splitlines()
        return 'signed in as %s%s' % ((o or ['?'])[0],
                                      ('; ' + ' '.join(o[1:])) if o[1:] else '')

    def deploy(self, bundle, options):
        options = options or {}
        cdir = self.folder(options, 'cert_dir')
        ddir = self.folder(options, 'dynamic_dir')
        seen = text(options.get('seen_as')).strip().rstrip('/')
        seen = self.folder({'x': seen}, 'x') if seen else cdir
        name = object_name(bundle, options)
        prefix = name_prefix(bundle, options)
        conf = '%s/%s.yml' % (ddir, prefix.rstrip('-'))
        yml = ['# made by acme - each renewal writes it anew', 'tls:', '  certificates:',
               '    - certFile: %s/%s.crt' % (seen, name),
               '      keyFile: %s/%s.key' % (seen, name)]
        if as_bool(options.get('default_cert')):
            yml += ['  stores:', '    default:', '      defaultCertificate:',
                    '        certFile: %s/%s.crt' % (seen, name),
                    '        keyFile: %s/%s.key' % (seen, name)]
        files = [{'path': '%s/%s.crt' % (cdir, name), 'data': bundle.as_format('fullchain-pem'),
                  'mode': 0o644, 'owner': None},
                 {'path': '%s/%s.key' % (cdir, name), 'data': bundle.as_format('key-pem'),
                  'mode': 0o600, 'owner': None},
                 {'path': conf, 'data': ('\n'.join(yml) + '\n').encode(), 'mode': 0o644,
                  'owner': None}]
        with self.ssh() as s:
            if F.skip_same(options) and not self.pending() and \
                    F.all_same_said(self, s, files):
                self.remember(bundle, options)
                return self.same(bundle, 'in %s' % conf)
            # the certificate first, the configuration naming it last
            self.mark_pending(bundle)       # done_pending() once through (1.0.79)
            F.write_files(self, s, files[:2], options=options)
            F.write_files(self, s, files[2:], options=options)
            F.drop_previous(self, s, files, options)
            self.ctx.step('wrote %s.crt/.key and %s' % (name, conf), 'ok')
            self.cleanup(s, cdir, prefix, name, self.keep(options))
        self.remember(bundle, options)
        self.done_pending()
        return 'Traefik\'s %s points at %s' % (conf, name)

    def cleanup(self, s, cdir, prefix, current, keep):
        if keep < 0:
            return
        names = {n.rsplit('.', 1)[0] for n in F.ls(self, s, cdir) if n.endswith(('.crt', '.key'))}
        old = prune(names, prefix, keep, current)
        if old:
            self.sh(s, 'rm -f ' + ' '.join(quote('%s/%s.%s' % (cdir, n, ext))
                                           for n in old for ext in ('crt', 'key')), check=False)
            self.ctx.step('deleted the old %s' % ', '.join(old))
