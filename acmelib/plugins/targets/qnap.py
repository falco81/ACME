# -*- coding: utf-8 -*-
"""
QNAP QTS / QuTS hero / QuTScloud over SSH: the system certificate of the NAS (its
administration web pages, and the Web Server, which shares it) written where the stunnel
in front of them reads it, stunnel restarted:

    /etc/stunnel/stunnel.pem   the private key, then the certificate (one file)
    /etc/stunnel/uca.pem       the intermediate certificate(s)
    /etc/init.d/stunnel.sh restart        (and, when asked, /etc/init.d/Qthttpd.sh restart)

QNAP publishes no API for certificates: its manuals give only the GUI (Control Panel >
System > Security > SSL Certificate & Private Key > Replace Certificate > Import
certificate). These files and the restart are what acme.sh's ssh deploy hook documents
for QNAP (tested there with QTS 4.2.3) - **not QNAP's own documentation**: acme keeps the
files it replaces (.acme-prev) and puts them back when stunnel does not start again.

Sources (the vendor guide navody/certifikaty/storage-hci/qnap.md, 2026-11, citing):
    https://docs.qnap.com/operating-system/qts/5.2.x/en-us/replacing-the-server-certificate-8E7C1926.html
    https://docs.qnap.com/operating-system/qts/5.2.x/en-us/enabling-ssh-on-the-nas-61C229CD.html
    https://docs.qnap.com/operating-system/quts-hero/5.3.x/en-us/replacing-the-server-certificate-BA03E8A9.html
    https://github.com/acmesh-official/acme.sh/wiki/deployhooks

Less certain (the guide's unverified points, all of the mechanism): the paths and the
script are known from acme.sh's wiki and the community only, for QTS 4.2.3 - not checked
for QTS 5.2 / QuTS hero h5.x; QTS may write them over at a restart or an update (then
deploy again, or import in the GUI); whether an SSH command runs past Console Management
(acme.sh's hook does); an HA cluster of QuTS hero h5.3 may not copy it to the passive node.
"""
from __future__ import annotations

import secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, as_int, ssh_fields, verify_fields, pem_blocks,
    pem_to_der, text, quote)

PEM = '/etc/stunnel/stunnel.pem'
UCA = '/etc/stunnel/uca.pem'


class QnapTarget(SshMixin, Base):
    kind = 'qnap'
    title = 'QNAP QTS / QuTS hero (SSH)'
    vendor = 'QNAP'
    description = ('Writes the NAS\'s system certificate over SSH (stunnel.pem and uca.pem in '
                   '/etc/stunnel, as acme.sh\'s hook does - QNAP documents no API) and '
                   'restarts stunnel; the previous files come back when it does not start. '
                   'QTS 5.2, QuTS hero h5.2 / h5.3.')
    doc = 'targets.md'
    discovery = False
    fields = ssh_fields(sudo=False, user_default='admin', howto='generic',
                        try_command='id -un; uname -n') + [
        field('https_port', 'HTTPS port of the NAS', 'number', default=443,
              help='where acme checks what is served (Control Panel > System > General '
                   'Settings > System Administration)'),
        field('tmp_dir', 'Folder for uploads', 'text', default='/tmp', advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('restart_web', 'Restart the web server too (Qthttpd)', 'bool', default=False,
              advanced=True, help='/etc/init.d/Qthttpd.sh restart after stunnel - when the old '
                                  'certificate is still shown'),
    ] + verify_fields(443)

    def run(self, s, cmd, what, check=True):
        return self.sh(s, cmd, sudo=False, check=check, what=what)

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.run(s, 'id -un; test -f %s && test -x /etc/init.d/stunnel.sh '
                                       '&& echo STUNNEL' % PEM, 'signing in', check=False)
        said = text(out).split()
        if 'STUNNEL' not in said:
            raise PluginError('signed in, but %s or /etc/init.d/stunnel.sh is not there - this '
                              'NAS does not keep its certificate where acme writes it' % PEM,
                              retry=False)
        return 'signed in to %s as %s; %s is there' % (self.c('host'), said[0] if said else '?',
                                                       PEM)

    def served_now(self, s):
        rc, out, err = self.run(s, "sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' %s" % PEM,
                                'reading the certificate', check=False)
        blocks = pem_blocks(out)
        return pem_to_der(blocks[0]) if blocks else None

    def deploy(self, bundle, options):
        options = options or {}
        want = pem_to_der(bundle.cert_pem)
        with self.ssh() as s:
            if not as_bool(options.get('force')) and self.served_now(s) == want and \
                    not self.pending():
                self.remember(bundle, options)
                return self.same(bundle, 'in %s' % PEM)
            tmp = '%s/acme-%s' % ((self.c('tmp_dir') or '/tmp').rstrip('/'), secrets.token_hex(6))
            pem = bundle.as_format('key-pem') + bundle.as_format('cert-pem')
            chain = bundle.as_format('chain-pem')
            try:
                s.put(pem, tmp + '.pem', 0o600)
                s.put(chain, tmp + '.uca', 0o600)
                self.mark_pending(bundle)
                self.run(s, ' && '.join([
                    'cp -p %s %s.acme-prev' % (PEM, PEM),
                    '{ test ! -f %s || cp -p %s %s.acme-prev; }' % (UCA, UCA, UCA),
                    'cat %s > %s' % (quote(tmp + '.pem'), PEM),
                    'cat %s > %s' % (quote(tmp + '.uca'), UCA),
                    'chmod 600 %s' % PEM]),
                    'writing %s' % PEM)
            finally:
                # 1.0.96: the staged key removed on every path - a failed cp or cat left it
                # in the temporary directory (the rm was the last link of the && chain)
                try:
                    self.run(s, 'rm -f %s %s' % (quote(tmp + '.pem'), quote(tmp + '.uca')),
                             'removing the staged files', check=False)
                except (PluginError, OSError):
                    pass
            self.ctx.step('wrote %s and %s' % (PEM, UCA), 'ok')
            rc, out, err = self.run(s, '/etc/init.d/stunnel.sh restart', 'restarting stunnel',
                                    check=False)
            if rc != 0:
                self.run(s, 'cp -p %s.acme-prev %s; test ! -f %s.acme-prev || cp -p %s.acme-prev '
                            '%s; /etc/init.d/stunnel.sh restart' % (PEM, PEM, UCA, UCA, UCA),
                         'putting the previous certificate back', check=False)
                self.done_pending()
                raise PluginError('stunnel did not restart (exit %s) - the previous certificate '
                                  'is back: %s' % (rc, (text(err) or text(out)).strip()[-300:]))
            self.ctx.step('stunnel restarted', 'ok')
            if as_bool(options.get('restart_web')):
                self.run(s, '/etc/init.d/Qthttpd.sh restart', 'restarting Qthttpd')
                self.ctx.step('the web server restarted', 'ok')
        self.done_pending()
        self.remember(bundle, options)
        return 'wrote %s, stunnel restarted' % PEM

    served_wait = (5, 5)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('https_port', 443), 443))] if self.c('host') \
            else []
