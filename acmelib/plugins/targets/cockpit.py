# -*- coding: utf-8 -*-
"""
Linux: the certificate of the Cockpit web console (port 9090) over SSH, and when asked the
certificate's CA certificates added to the system's trust store.

    /etc/cockpit/ws-certs.d/<NN>-acme-<name>-<date>-<serial>.crt   the certificate + chain
    /etc/cockpit/ws-certs.d/<NN>-acme-<name>-<date>-<serial>.key   the key (0600 root:root)
    cockpit-certificate-ensure --check       which certificate Cockpit takes (the last one by
                                             name): it must be the new one
    systemctl restart cockpit.service        taken at once (cockpit-tls reads it again only
                                             when it starts, after 90 s idle)
    trust store: /etc/pki/ca-trust/source/anchors + update-ca-trust extract (RHEL, Fedora),
                 /usr/local/share/ca-certificates/*.crt + update-ca-certificates (Debian,
                 Ubuntu), /etc/pki/trust/anchors + update-ca-certificates (SLES, openSUSE)

Each command runs on its own through sudo (not in one sh -c), so a sudoers file can allow
exactly these (install, rm of acme's own files, the check, the restart) and nothing more.
A new file each time, the older ones deleted once the new one is taken - the old one keeps
being served when something fails, the new files are then removed.

Sources (the vendor guide navody/certifikaty/storage-hci/linux-cockpit-truststore.md, 2026-11):
    https://docs.cockpit-project.org/cockpit-guide/latest/guide/https.html
    https://docs.cockpit-project.org/cockpit-guide/latest/man/cockpit-tls.8.html
    https://src.fedoraproject.org/rpms/ca-certificates/blob/rawhide/f/update-ca-trust.8.txt
    https://manpages.debian.org/trixie/ca-certificates/update-ca-certificates.8.en.html
    https://github.com/linux-system-roles/certificate

Less certain: what cockpit-certificate-ensure --check prints (acme looks for the file name in
it; when it names none, that is only said); that the restart is needed - it follows from the
socket activation and the idle timeout, Cockpit does not say it; SLES's anchors folder is from
Linux System Roles' README only. Cockpit releases before the separate .key (an older
cockpit-tls(8) took the key inside the .cert) are not covered.
"""
from __future__ import annotations

import re
import secrets

from acmelib.plugins.targets._common import (
    Base, PluginError, field, as_bool, as_int, ssh_fields, ssh_conn, verify_fields, keep_field,
    object_name, name_prefix, prune, chain_list, chain_id, text, quote)

WS = '/etc/cockpit/ws-certs.d'
ENSURE = ('/usr/libexec/cockpit-certificate-ensure', '/usr/lib/cockpit/cockpit-certificate-ensure')
TRUST = (('/etc/pki/ca-trust/source/anchors', '/usr/bin/update-ca-trust extract'),
         ('/usr/local/share/ca-certificates', '/usr/sbin/update-ca-certificates'),
         ('/etc/pki/trust/anchors', '/usr/sbin/update-ca-certificates'))


class CockpitTarget(Base):
    kind = 'cockpit'
    title = 'Cockpit web console (Linux, SSH)'
    vendor = 'Linux / Unix'
    description = ('Puts the certificate into /etc/cockpit/ws-certs.d over SSH under a name '
                   'Cockpit takes (checked by cockpit-certificate-ensure), restarts Cockpit '
                   'and deletes older ones; can add the CA certificates to the system trust '
                   'store. RHEL 8 - 10, Fedora, Debian, Ubuntu, SLES.')
    doc = 'targets.md'
    discovery = False
    fields = ssh_fields(sudo=True, user_default='svc-cert') + [
        field('web_port', 'Cockpit port', 'number', default=9090,
              help='where acme checks what is served'),
        field('tmp_dir', 'Folder for uploads', 'text', default='/tmp', advanced=True,
              help='the files are put here first, then installed with sudo install - the '
                   'sudoers lines of the setup guide name this folder'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('file_prefix', 'File name prefix', 'text', default='90', advanced=True,
              help='Cockpit takes the last file by name: higher than 10-ipa.cert and your own '
                   'ones'),
        field('restart', 'Restart cockpit.service', 'bool', default=True,
              help='open Cockpit sessions are signed out; off: taken when cockpit-tls starts '
                   'again by itself'),
        field('trust_ca', 'Add its CA certificates to the system trust store', 'bool',
              default=False,
              help='the chain\'s CA certificates as trust anchors (update-ca-trust / '
                   'update-ca-certificates) - for a certificate of your own CA'),
        keep_field(1),
    ] + verify_fields(9090)
    default_verify_port = 9090

    def ssh(self):
        return self.ctx.ssh(ssh_conn(self))

    def root(self, s, cmd, what, check=True):
        """One command as root: through sudo when the target says so (sudo -n, or -S with
        the sudo password) - never wrapped in sh -c, so sudoers can name it."""
        inp = None
        if as_bool(self.c('sudo')):
            pw = self.c('sudo_password')
            if pw:
                cmd, inp = "sudo -S -p '' " + cmd, pw + '\n'
            else:
                cmd = 'sudo -n ' + cmd
        rc, out, err = s.run(cmd, input=inp, timeout=as_int(self.c('timeout', 30), 30) * 4,
                             check=False)
        out, err = text(out), text(err)
        if check and rc != 0:
            raise PluginError('%s failed (exit %s): %s' % (what, rc, (err.strip() or
                                                                     out.strip())[-300:]))
        return rc, out, err

    def plain(self, s, cmd):
        rc, out, err = s.run(cmd, timeout=as_int(self.c('timeout', 30), 30) * 4, check=False)
        return rc, text(out), text(err)

    def ensure_path(self, s):
        rc, out, err = self.plain(s, ' ; '.join('test -x %s && echo %s' % (p, p) for p in ENSURE))
        got = [x.strip() for x in out.splitlines() if x.strip() in ENSURE]
        return got[0] if got else None

    def listing(self, s):
        rc, out, err = self.plain(s, 'ls -1 %s' % WS)
        if rc != 0:
            raise PluginError('%s cannot be listed - is Cockpit installed? %s'
                              % (WS, (err or out).strip()[-200:]), retry=False)
        return [x.strip() for x in out.splitlines() if x.strip()]

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.plain(s, 'id -un')
            files = self.listing(s)
            ens = self.ensure_path(s)
            if as_bool(self.c('sudo')):
                self.root(s, 'true', 'sudo')
        return 'signed in as %s; %s holds %s; %s' % (
            out.strip() or '?', WS, ', '.join(files) or 'nothing',
            'cockpit-certificate-ensure at %s' % ens if ens else
            'no cockpit-certificate-ensure found')

    def base_of(self, bundle, options):
        pre = text(self.opt(options, 'file_prefix', '90')).strip() or '90'
        if not re.match(r'^[0-9A-Za-z_]{1,8}$', pre):
            raise PluginError('the file name prefix is letters and digits only', retry=False)
        return '%s-%s' % (pre, object_name(bundle, options)), '%s-%s' % (
            pre, name_prefix(bundle, options))

    def deploy(self, bundle, options):
        options = options or {}
        base, prefix = self.base_of(bundle, options)
        with self.ssh() as s:
            files = self.listing(s)
            there = base + '.crt' in files and base + '.key' in files
            if there and self.unchanged(bundle, options):
                return self.same(bundle, 'as %s/%s.crt' % (WS, base))
            ens = self.ensure_path(s)
            tmp = '%s/acme-%s' % ((self.c('tmp_dir') or '/tmp').rstrip('/'), secrets.token_hex(6))
            put = []
            try:
                s.put(bundle.as_format('fullchain-pem'), tmp + '.crt', 0o600)
                put.append(tmp + '.crt')
                s.put(bundle.as_format('key-pem'), tmp + '.key', 0o600)
                put.append(tmp + '.key')
                self.root(s, 'install -m 0644 -o root -g root %s %s/%s.crt'
                          % (quote(tmp + '.crt'), WS, base), 'installing the certificate')
                self.root(s, 'install -m 0600 -o root -g root %s %s/%s.key'
                          % (quote(tmp + '.key'), WS, base), 'installing the key')
            finally:
                if put:
                    self.plain(s, 'rm -f %s' % ' '.join(quote(p) for p in put))
            self.ctx.step('wrote %s/%s.crt and .key' % (WS, base), 'ok')
            if ens:
                rc, out, err = self.root(s, '%s --check' % ens, 'cockpit-certificate-ensure',
                                         check=False)
                said = (out + err)
                others = [f for f in re.findall(r'[\w.@-]+\.(?:cert|crt)', said)
                          if f != base + '.crt']
                if rc != 0 or (base + '.crt' not in said and others):
                    self.root(s, 'rm -f %s/%s.crt %s/%s.key' % (WS, base, WS, base),
                              'taking the new files away', check=False)
                    raise PluginError('Cockpit would not use the new certificate (%s) - the new '
                                      'files are taken away: %s' % (
                                          'cockpit-certificate-ensure exit %s' % rc if rc else
                                          'it takes %s' % others[-1], said.strip()[-300:]),
                                      retry=False)
                if base + '.crt' in said:
                    self.ctx.step('Cockpit takes %s.crt' % base, 'ok')
                else:
                    self.ctx.step('cockpit-certificate-ensure --check names no file: %s'
                                  % said.strip()[-200:], 'warn')
            later = sorted(f for f in files if f.endswith(('.cert', '.crt')) and f > base + '.crt')
            if later and not ens:
                self.ctx.step('%s sort after the new file - Cockpit takes the last one: raise '
                              'the file name prefix' % ', '.join(later), 'warn')
            if as_bool(self.opt(options, 'trust_ca', False)):
                self.trust(s, bundle)
            if as_bool(self.opt(options, 'restart', True), True):
                self.root(s, 'systemctl restart cockpit.service', 'restarting Cockpit')
                self.ctx.step('cockpit.service restarted', 'ok')
            self.cleanup(s, files, prefix, base, self.keep(options))
        self.remember(bundle, options)
        return 'Cockpit certificate %s.crt in place' % base

    def trust(self, s, bundle):
        cas = chain_list(bundle)
        if not cas:
            self.ctx.step('the certificate has no CA certificates to trust', 'warn')
            return
        rc, out, err = self.plain(s, ' ; '.join('test -d %s && echo %s' % (d, d)
                                                for d, _c in TRUST))
        dirs = [x.strip() for x in out.splitlines()]
        pick = next(((d, c) for d, c in TRUST if d in dirs), None)
        if not pick:
            raise PluginError('no system trust store folder found (%s)'
                              % ', '.join(d for d, _c in TRUST), retry=False)
        d, cmd = pick
        tmp = '%s/acme-%s' % ((self.c('tmp_dir') or '/tmp').rstrip('/'), secrets.token_hex(6))
        for pem in cas:
            name = 'acme-ca-%s.crt' % chain_id(pem)
            s.put(pem.encode(), tmp + '.crt', 0o600)
            try:
                self.root(s, 'install -m 0644 -o root -g root %s %s/%s'
                          % (quote(tmp + '.crt'), d, name), 'adding a CA certificate')
            finally:
                self.plain(s, 'rm -f %s' % quote(tmp + '.crt'))
            self.ctx.step('%s/%s' % (d, name), 'ok')
        self.root(s, cmd, cmd.split()[0].rsplit('/', 1)[-1])
        self.ctx.step('the system trust store is updated (%s)' % cmd, 'ok')

    def cleanup(self, s, files, prefix, current, keep):
        if keep < 0:
            return
        bases = sorted({f.rsplit('.', 1)[0] for f in files if f.endswith(('.crt', '.key'))})
        for old in prune(bases, prefix, keep, current):
            self.root(s, 'rm -f %s/%s.crt %s/%s.key' % (WS, old, WS, old),
                      'deleting %s' % old, check=False)
            self.ctx.step('deleted the old %s' % old)

    served_wait = (4, 5)

    def served_places(self, options):
        return [(self.c('host'), as_int(self.c('web_port', 9090), 9090))] if self.c('host') \
            else []
