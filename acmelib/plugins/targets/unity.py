# -*- coding: utf-8 -*-
"""
Dell Unity / Unity XT / UnityVSA (Unity OE 5.x): the Unisphere management
certificate (GUI, REST API, uemcli), over SSH as the "service" user with Dell's
own service command.

    put   /home/service/user/<base>.crt     the certificate (+ the intermediates)
    put   /home/service/user/<base>.pk      the RSA key, PEM, not encrypted
    run   svc_custom_cert <base>            "Successfully installed custom certificate
                                             files." - Unisphere's web server restarts
    run   rm -f /home/service/user/<base>.crt /home/service/user/<base>.pk   (always)

Unity has no REST call nor uemcli command for its own management certificate:
Dell's way (KB 000021122) is the service shell - the files with the same base
name in /home/service/user of the primary SP (where an SSH session to the
management address lands) and svc_custom_cert. A file with anything but PEM
blocks in it (a PKCS#7 bundle, text) can panic the SP: acme writes PEM only.
Unity OE 5.5.0 refuses a file with CA certificates in it ("Unable to validate
the specified certificate", fixed in 5.5.1): "Include the intermediates" off
there. The OE version cannot be read in the service shell the documents
describe, so this is one module for OE 5.x (5.3 - 5.5.x, the same command).
Only RSA keys are documented (Dell's example: RSA 2048) - another key is refused.

Sources: Dell KB 000021122, KB 000429916 (pre-checks: primary SP, the folder),
KB 000317557 (5.5.0 and chains), KB 000308965 (5.5.0 key strength). The account:
"service" (its password is set at the initial configuration); SSH enabled in
Settings → Service → Service Tasks.
"""
from __future__ import annotations

import re

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, as_int, ssh_fields, text, quote,
    family_of, served_fingerprint, fp_of, split_hostport)

FOLDER = '/home/service/user'


def _ssh_fields():
    out = []
    for f in ssh_fields(sudo=False, user_default='service', howto='generic',
                        try_command='id -un; ls -d %s' % FOLDER):
        if f['key'] == 'auth':
            f = dict(f, default='password')     # the service account signs in with its password
        out.append(f)
    return out


class UnityTarget(SshMixin, Base):
    kind = 'unity'
    discovery = False       # nothing to find: a service shell over SSH
    title = 'Dell Unity (service shell)'
    vendor = 'Dell'
    description = ('Installs the certificate as the Unisphere management certificate of Dell '
                   'Unity, Unity XT and UnityVSA (Unity OE 5.x) over SSH as the service user, '
                   'with Dell\'s svc_custom_cert; Unisphere\'s web server restarts (storage I/O '
                   'is not touched).')
    doc = 'targets.md'
    fields = _ssh_fields() + [
        field('mgmt_port', 'Unisphere HTTPS port', 'number', default=443, advanced=True,
              help='where the management certificate is served, for the check'),
    ]
    deploy_fields = [
        field('with_chain', 'Include the intermediates', 'bool', default=True,
              help='off on Unity OE 5.5.0 - it refuses a file with CA certificates in it '
                   '(fixed in 5.5.1)'),
        field('base', 'File name', 'text', default='acmecert', advanced=True,
              help='the base name of the .crt and .pk files in /home/service/user'),
    ]

    def base_name(self, options):
        b = text(self.opt(options, 'base', 'acmecert')).strip() or 'acmecert'
        if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$', b):
            raise PluginError('"%s" is not a plain file name (letters, digits, - and _)' % b,
                              retry=False)
        return b

    def test(self):
        with self.ssh() as s:
            rc, out, err = s.run('id -un; ls -d %s' % FOLDER, check=False)
        if rc != 0:
            raise PluginError('signed in to %s, but %s is not there (%s) - sign in as the '
                              'service user' % (self.c('host'), FOLDER,
                                                text(err or out).strip()[-200:]), retry=False)
        who = text(out).strip().splitlines()[0] if text(out).strip() else '?'
        return 'signed in to %s as %s, %s is there' % (self.c('host'), who, FOLDER)

    def served_port(self):
        return as_int(self.c('mgmt_port', 443), 443)

    def served_now(self, bundle):
        try:
            host, port = split_hostport('%s:%s' % (self.c('host'), self.served_port()))
            return served_fingerprint(host, port, None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by Unisphere')
        fam = family_of(bundle)
        if fam in ('ec', 'ed'):
            raise PluginError('Unity documents only RSA keys for its management certificate - '
                              'give this certificate an RSA key type', retry=False)
        base = self.base_name(options)
        crt, pk = '%s/%s.crt' % (FOLDER, base), '%s/%s.pk' % (FOLDER, base)
        with_chain = as_bool(self.opt(options, 'with_chain', True), True)
        data = bundle.as_format('fullchain-pem' if with_chain else 'cert-pem')
        try:
            key = bundle.as_format('key-rsa')
        except Exception:                               # noqa: BLE001
            key = bundle.as_format('key-pem')
        with self.ssh() as s:
            try:
                s.put(data, crt, 0o600)
                s.put(key, pk, 0o600)
                self.ctx.step('wrote %s.crt and %s.pk to %s' % (base, base, FOLDER))
                rc, out, err = s.run('svc_custom_cert %s' % quote(base), timeout=300,
                                     check=False)
                said = (text(out) + '\n' + text(err)).strip()
                if rc != 0 or 'ERROR' in said or 'uccessfully' not in said:
                    raise PluginError('svc_custom_cert did not install the certificate: %s'
                                      % (said[-400:] or 'exit %d' % rc), detail=said[-4000:],
                                      retry=False)
            finally:
                s.run('rm -f %s %s' % (quote(crt), quote(pk)), check=False)
        self.ctx.step('installed - Unisphere\'s web server restarts', 'ok')
        self.remember(bundle, options)
        return 'installed as the Unisphere certificate%s' % (
            '' if with_chain else ' (without the intermediates)')

    served_wait = (10, 10)

    def served_places(self, options):
        return [(self.c('host'), self.served_port())] if self.c('host') else []
