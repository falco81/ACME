# -*- coding: utf-8 -*-
"""
Fujitsu / Fsas Technologies Infrastructure Manager (ISM, formerly ServerView Infrastructure
Manager; also ISM for PRIMEFLEX): the HTTPS certificate of the ISM-VA (GUI and REST API,
port 25566), the way the User's Guide says it: the key and certificate put into the FTP
area of the ISM-VA, "ismadm sslcert set" on its console over SSH, then the ISM-VA restarted.

    FTP   <ism-va>:21  login <user>, STOR <group>/ftp/acme-….key, …crt
    SSH   <ism-va>:22  ismadm sslcert set -key /<group>/ftp/acme-….key -crt /<group>/ftp/acme-….crt
                       ismadm power restart
    FTP   DELE <group>/ftp/acme-….key, …crt      (the key does not stay there)
    SSH   ismadm sslcert show                    (Try: read only)

Sources (2026-11): Infrastructure Manager V3.1.0 User's Guide CA92344-5875-03 - 2.1.2 FTP
Access ("You cannot use the FTPS protocol"), 2.1.3 Console Access (who may: Administrator
role in the Administrator group, or a group with "Manage all nodes"), 4.7.1 (ismadm sslcert
set -key -crt, then ismadm power restart), 4.23 File Upload; V2.9.0 User's Guide
CA92344-5430-09 - the same commands in 2.x; REST API Reference V2.7.0 (PATCH
/ismva/settings/sslcert answers Restart: "ISM-VA").

ISM 2.x and 3.x take the same commands - one module. Not used: the REST API (its password
must be sent encrypted with AES-256-CBC, which the Python standard library cannot do). The
REST API documents a CA file besides; the CLI none - the certificate file carries the chain
(choose "the certificate alone" if this ISM refuses it). The FTP of the ISM-VA is plain:
the key travels unencrypted on the management network and is deleted at once.
"""
from __future__ import annotations

import ftplib
import re

from acmelib.plugins.targets._common import (
    Base, PluginError, field, as_bool, as_int, verify_fields, text, short_serial,
    served_fingerprint, fp_of)
from acmelib.plugins.targets._ftp_stage import FtpStage

GROUP_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}\Z')


class FujitsuIsmTarget(Base):
    kind = 'fujitsu_ism'
    discovery = False
    title = 'Fujitsu Infrastructure Manager (ISM-VA)'
    vendor = 'Fujitsu / Fsas Technologies'
    description = ('Replaces the HTTPS certificate of an Infrastructure Manager virtual '
                   'appliance (ISM / ISM for PRIMEFLEX 2.x and 3.x): the files over its FTP, '
                   '"ismadm sslcert set" over SSH, then "ismadm power restart" - the ISM is '
                   'away for a few minutes.')
    doc = 'targets.md'
    default_verify_port = 25566
    fields = [
        field('host', 'Address', 'text', required=True, placeholder='ism.example.local',
              help='name or IP address of the ISM-VA'),
        field('user', 'User', 'text', required=True, default='administrator',
              help='an ISM user with the Administrator role in the Administrator group - for '
                   'the console (SSH) and the FTP area'),
        field('password', 'Password', 'secret', required=True),
        field('group', 'User group', 'text', default='Administrator', advanced=True,
              help='the files go to /<user group>/ftp'),
        field('ssh_port', 'SSH port', 'number', default=22, advanced=True),
        field('ftp_port', 'FTP port', 'number', default=21, advanced=True),
        field('https_port', 'HTTPS port of the GUI', 'number', default=25566, advanced=True),
        field('hostkey', 'Host key', 'text', advanced=True,
              placeholder='ism.example.local ssh-ed25519 AAAA…',
              help='a known_hosts line; empty with "trust the first" takes the one seen first'),
        field('trust_first', 'Trust the first host key seen', 'bool', default=True,
              advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('with_chain', 'Send the chain with the certificate', 'bool', default=True,
              help='the .crt file holds the certificate and the intermediates (off: the '
                   'certificate alone)'),
        field('restart', 'Restart the ISM-VA afterwards', 'bool', default=True,
              help='ismadm power restart - the new certificate is served only after it; GUI, '
                   'REST API and monitoring are away for a few minutes'),
    ] + verify_fields(25566)

    FTP = ftplib.FTP                # a test puts its own here
    FTP_TLS = ftplib.FTP_TLS

    def group(self):
        g = text(self.c('group') or 'Administrator').strip()
        if not GROUP_RE.match(g):
            raise PluginError('the user group is letters, digits and _ . - only', retry=False)
        return g

    def conn(self):
        return {'host': self.c('host'), 'port': as_int(self.c('ssh_port', 22), 22),
                'user': self.c('user'), 'password': self.c('password') or '', 'key': None,
                'key_pass': None, 'hostkey': self.c('hostkey') or None,
                'hostkey_field': 'hostkey',
                'trust_first': as_bool(self.c('trust_first', True), True),
                'timeout': as_int(self.c('timeout', 30), 30), 'via': ''}

    def ftp(self):
        return FtpStage(self, self.c('host'), as_int(self.c('ftp_port', 21), 21), self.c('user'),
                        self.c('password'), tls=False,
                        timeout=as_int(self.c('timeout', 30), 30))

    def ismadm(self, s, args, what, answer='y\n', timeout=300):
        rc, out, err = s.run('ismadm ' + args, input=answer, timeout=timeout, check=False)
        out, err = text(out), text(err)
        if rc != 0:
            raise PluginError('%s: ismadm said (exit %s) %s' % (
                what, rc, (err.strip() or out.strip())[-300:] or '-'),
                detail='$ ismadm %s\n%s\n%s' % (args, out, err), retry=False)
        return out

    def restart(self, s):
        """ismadm power restart. The console goes away with the restart: a cut session is no
        failure. ssh ends with 255 then, which the SSH session of acme raises as "ssh to
        <host>: ..." whatever check says, or the command does not come back in time (1.0.96:
        both were taken as a failed deployment, retried, and the certificate not remembered).
        ismadm refusing the restart (it answers, exit 1) stays a failure."""
        try:
            rc, out, err = s.run('ismadm power restart', input='y\n', timeout=120, check=False)
        except PluginError as e:
            if str(e).startswith('ssh to ') or 'took more than' in str(e):
                self.ctx.debug('the session ended with the restart: %s' % e)
                return
            raise
        if rc not in (0, -1, 255, None):
            out, err = text(out), text(err)
            raise PluginError('%s: ismadm said (exit %s) %s' % (
                'restarting the ISM-VA', rc, (err.strip() or out.strip())[-300:] or '-'),
                detail='$ ismadm power restart\n%s\n%s' % (out, err), retry=False)

    def served_now(self, bundle):
        try:
            return served_fingerprint(self.c('host'), as_int(self.c('https_port', 25566), 25566),
                                      None) == fp_of(bundle)
        except (OSError, ValueError):
            return False

    def test(self):
        folder = '%s/ftp' % self.group()
        with self.ftp() as st:
            st.listing(folder)
        with self.ctx.ssh(self.conn()) as s:
            out = self.ismadm(s, 'sslcert show', 'reading the certificate', answer=None,
                              timeout=60)
        first = [ln.strip() for ln in out.splitlines() if ln.strip()][:2]
        return 'signed in to %s (FTP and console): %s' % (self.c('host'),
                                                            ' / '.join(first) or 'ismadm answered')

    def deploy(self, bundle, options):
        options = options or {}
        if not as_bool(options.get('force')) and self.served_now(bundle):
            self.remember(bundle, options)
            return self.same(bundle, 'served by the ISM-VA')
        g = self.group()
        folder = '%s/ftp' % g
        base = 'acme-%s' % short_serial(bundle)
        crt = bundle.as_format('fullchain-pem' if as_bool(self.opt(options, 'with_chain', True),
                                                           True) else 'cert-pem')
        with self.ctx.ssh(self.conn()) as s:
            with self.ftp() as st:
                # the try opens before the first upload (1.0.96): the certificate refused
                # after the key went up must not leave the key there
                try:
                    st.put(base + '.key', bundle.as_format('key-pem'), folder)
                    st.put(base + '.crt', crt, folder)
                    self.ctx.step('put %s.key and %s.crt into /%s over FTP' % (
                        base, base, folder), 'ok')
                    self.ismadm(s, 'sslcert set -key /%s/%s.key -crt /%s/%s.crt' % (
                        folder, base, folder, base), 'setting the certificate')
                finally:
                    # The key must not stay in the FTP area (the User's Guide says to delete
                    # it) - taken away before the restart, while the FTP still answers.
                    st.clean()
            self.ctx.step('ismadm sslcert set: the ISM-VA took the certificate', 'ok')
            did = 'certificate set'
            if as_bool(self.opt(options, 'restart', True), True):
                self.restart(s)
                self.ctx.step('the ISM-VA restarts (a few minutes: GUI, REST API and '
                              'monitoring are away)', 'ok')
                did += ', the ISM-VA restarts'
            else:
                self.ctx.step('no restart asked: the ISM-VA serves the new certificate after '
                              'its next restart', 'warn')
        self.remember(bundle, options)
        return did

    @staticmethod
    def served_wait(options):
        return (40, 15) if as_bool((options or {}).get('restart', True), True) else None

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('https_port', 25566), 25566))] \
            if self.c('host') else []
