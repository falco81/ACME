# -*- coding: utf-8 -*-
"""
Fujitsu / Fsas Technologies ETERNUS DX / AF storage: the SSL certificate of ETERNUS Web
GUI - the RESTful API (port 5665) shares it - registered with the ETERNUS CLI over SSH,
which takes the key and certificate only from an FTP / FTPS server it is told of.

    FTP(S) <file server>  STOR [folder/]acme-….key, acme-….crt          (acme puts them)
    SSH    <array> CLI>   import ssl-certificate -port maintenance -server <file server>
                              -user <ftp user> -cert-filename … -key-filename …
                              [-server-port-number N] [-disable-ftps yes]
                          Password : <the FTP password>                 (asked by the CLI)
    SSH    CLI>           set smi-s -function disable / enable -ssl-certificate shared-with-webgui
                                                                        (when asked)
    FTP(S)                DELE the two files                            (the key does not stay)
    SSH    CLI>           show ssl-version                              (Try: read only)

Sources (2026-11): ETERNUS DX S6 series CLI User's Guide C140-0003-06ENZ3 - "SSH/SSL
Security Configuration" (export ssl-certificate-request, import ssl-certificate and its
parameters, FTPS (explicit) by default from S6, -disable-ftps yes for FTP, passive mode,
the FTP server's certificate not checked; the SMI-S warning "please disable and enable the
SMI-S function"), "SMI-S" (set smi-s -ssl-certificate), User Management (create role
-policy, default roles); ETERNUS DX S6 Web GUI User's Guide C140-0005-06ENZ3 (Register SSL
Certificate: PEM key and certificate as a pair, no PKCS#12; Storage Management policy;
HTTP/HTTPS stops for minutes, then check the event log); RESTful API Reference
C140-0052-03ENZ3 ("The HTTPS server of the RESTful API shares the SSL certificate with
ETERNUS Web GUI"; no certificate endpoint).

One module: checked against the S6 manuals (DX S6, and the AF on the same firmware line).
DX S5 / AF S3 / AF S2 have the same commands but no FTPS: "File transfer" FTP on DX S5 /
AF S3 sends no FTPS option (those CLIs have none - from the S6 manual's notes, not their
own). Whether a certificate file may hold the intermediates is not said - "the certificate alone" is the default; a refused pair
leaves HTTPS down until a good one is registered (over SSH, as here).
"""
from __future__ import annotations

import ftplib
import re

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, as_int, ssh_fields, verify_fields, text,
    short_serial, served_fingerprint, fp_of, family_of)
from acmelib.plugins.targets._ftp_stage import FtpStage

# What may go into a CLI argument: the CLI is no shell, but a space would split it.
ARG_RE = re.compile(r'^[A-Za-z0-9_.@:/%-]{1,255}\Z')
ERROR_RE = re.compile(r'^\s*(Error|ERROR)\b.*$', re.M)


def arg(v, what):
    v = text(v).strip()
    if not ARG_RE.match(v):
        raise PluginError('the %s may hold letters, digits and _ . @ : / %% - only' % what,
                          retry=False)
    return v


class EternusDxTarget(SshMixin, Base):
    kind = 'eternus_dx'
    discovery = False
    title = 'Fujitsu ETERNUS DX / AF (Web GUI certificate)'
    vendor = 'Fujitsu / Fsas Technologies'
    description = ('Registers the SSL certificate of ETERNUS Web GUI and RESTful API on an '
                   'ETERNUS DX S6 / AF storage system: the key and certificate put on an FTPS '
                   '(or FTP) server, "import ssl-certificate" run in the ETERNUS CLI over SSH, '
                   'the files deleted again. Data access is not touched; the GUI is away for '
                   'minutes. RSA keys only.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, user_default='svc-cert', howto='generic',
                        try_command='show ssl-version') + [
        field('lan_port', 'LAN port of the array to the file server', 'select',
              default='maintenance',
              options=[['maintenance', 'MNT (maintenance)'], ['remote', 'RMT (remote)'],
                       ['fst', 'FST']],
              help='-port of import ssl-certificate'),
        field('ftp_host', 'File server', 'text', required=True, placeholder='ftp.example.local',
              help='an FTPS or FTP server both acme and the array reach'),
        field('ftp_port', 'File server port', 'number', default=21),
        field('ftp_mode', 'File transfer', 'select', default='ftps',
              options=[['ftps', 'FTPS, explicit TLS (S6 default)'],
                       ['ftp', 'FTP on S6 (-disable-ftps yes)'],
                       ['ftp_old', 'FTP on DX S5 / AF S3 / AF S2 (no FTPS option sent)']],
              help='how the array fetches the files; acme puts them there the same way'),
        field('ftp_user', 'File server user', 'text', required=True),
        field('ftp_password', 'File server password', 'secret', required=True),
        field('ftp_folder', 'Folder on the file server', 'text', advanced=True,
              placeholder='eternus',
              help='empty: the user\'s home; the array is given the files by this path'),
        field('ftp_verify', 'Check the file server\'s certificate', 'bool', default=True,
              advanced=True, help='acme\'s own FTPS connection (the array does not check it)'),
        field('https_port', 'HTTPS port of the Web GUI', 'number', default=443, advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('with_chain', 'Send the chain with the certificate', 'bool', default=False,
              help='the certificate file holds the intermediates too - the manual does not say '
                   'the array takes them: try it once'),
        field('smis', 'Restart SMI-S on the new certificate', 'bool', default=False,
              help='set smi-s -function disable, then enable -ssl-certificate shared-with-webgui '
                   '- only where SMI-S is on and shares the Web GUI certificate'),
    ] + verify_fields()

    FTP = ftplib.FTP                # a test puts its own here
    FTP_TLS = ftplib.FTP_TLS

    def ftp(self):
        return FtpStage(self, self.c('ftp_host'), as_int(self.c('ftp_port', 21), 21),
                        self.c('ftp_user'), self.c('ftp_password'),
                        tls=self.mode() == 'ftps',
                        verify=as_bool(self.c('ftp_verify', True), True),
                        timeout=as_int(self.c('timeout', 30), 30))

    def mode(self):
        m = text(self.c('ftp_mode') or 'ftps').strip()
        return m if m in ('ftps', 'ftp', 'ftp_old') else 'ftps'

    def cli(self, s, cmd, what, answer=None, timeout=300):
        rc, out, err = s.run(cmd, input=answer, timeout=timeout, check=False)
        out, err = text(out), text(err)
        bad = ERROR_RE.search(out) or ERROR_RE.search(err)
        if rc != 0 or bad:
            said = bad.group(0).strip() if bad else (err.strip() or out.strip())[-300:]
            raise PluginError('%s: the ETERNUS CLI said %s' % (what, said or 'exit %s' % rc),
                              detail='CLI> %s\n%s\n%s' % (cmd, out, err), retry=False)
        return out

    def served_now(self, bundle):
        try:
            return served_fingerprint(self.c('host'), as_int(self.c('https_port', 443), 443),
                                      None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    def test(self):
        folder = text(self.c('ftp_folder')).strip().strip('/')
        with self.ftp() as st:
            st.listing(folder)
        with self.ssh() as s:
            out = self.cli(s, 'show ssl-version', 'reading the SSL versions', timeout=60)
        first = [ln.strip() for ln in out.splitlines() if ln.strip()][:2]
        return 'signed in to %s and to the file server %s: %s' % (
            self.c('host'), self.c('ftp_host'), ' / '.join(first) or 'the CLI answered')

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the Web GUI')
        if family_of(bundle) not in ('rsa', ''):
            raise PluginError('ETERNUS DX / AF take RSA keys only (1024 - 4096 bits) - choose an '
                              'RSA key type', retry=False)
        try:
            key = bundle.as_format('key-rsa')
        except Exception as e:                          # noqa: BLE001
            raise PluginError('the key cannot be written as an RSA key: %s' % e, retry=False)
        if b'BEGIN RSA PRIVATE KEY' not in (key if isinstance(key, bytes) else key.encode()):
            raise PluginError('ETERNUS DX / AF take RSA keys only - choose an RSA key type',
                              retry=False)
        crt = bundle.as_format('fullchain-pem' if as_bool(self.opt(options, 'with_chain', False))
                               else 'cert-pem')
        folder = text(self.c('ftp_folder')).strip().strip('/')
        if folder:
            arg(folder, 'folder on the file server')
        base = 'acme-%s' % short_serial(bundle)
        server = arg(self.c('ftp_host'), 'file server')
        user = arg(self.c('ftp_user'), 'file server user')
        port = arg(self.c('lan_port') or 'maintenance', 'LAN port')
        cmd = ('import ssl-certificate -port %s -server %s -user %s -cert-filename %s '
               '-key-filename %s' % (port, server, user, FtpStage.path(base + '.crt', folder),
                                     FtpStage.path(base + '.key', folder)))
        ftp_port = as_int(self.c('ftp_port', 21), 21)
        if ftp_port != 21:
            cmd += ' -server-port-number %d' % ftp_port
        if self.mode() == 'ftp':
            cmd += ' -disable-ftps yes'     # S6 only: older CLIs have FTP alone, no option
        with self.ssh() as s:
            with self.ftp() as st:
                # the try opens before the first upload (1.0.96): the certificate refused
                # after the key went up must not leave the key there
                try:
                    st.put(base + '.key', key, folder)
                    st.put(base + '.crt', crt, folder)
                    self.ctx.step('put %s.key and %s.crt on %s' % (base, base, st.words()),
                                  'ok')
                    out = self.cli(s, cmd, 'registering the certificate',
                                   answer=text(self.c('ftp_password') or '') + '\n')
                finally:
                    # the key does not stay on the file server
                    st.clean()
            self.ctx.step('the array registered the certificate - HTTPS of the Web GUI and the '
                          'RESTful API restart (a few minutes)', 'ok')
            did = 'registered the SSL certificate'
            if 'SMI-S' in out and not as_bool(options.get('smis')):
                self.ctx.step('SMI-S keeps the old certificate until it is disabled and enabled '
                              'again ("Restart SMI-S on the new certificate")', 'warn')
            if as_bool(options.get('smis')):
                self.cli(s, 'set smi-s -function disable', 'disabling SMI-S')
                self.cli(s, 'set smi-s -function enable -ssl-certificate shared-with-webgui',
                         'enabling SMI-S')
                self.ctx.step('SMI-S restarted on the Web GUI certificate', 'ok')
                did += ', SMI-S restarted'
        self.remember(bundle, options)
        return did

    served_wait = (20, 15)          # HTTP/HTTPS of the array stops until it is applied

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('https_port', 443), 443))] \
            if self.c('host') else []
