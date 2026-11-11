# -*- coding: utf-8 -*-
"""
VMware ESXi over SSH: the host's certificate written to
/etc/vmware/ssl/rui.crt and rui.key (the previous ones kept as .acme-prev),
then hostd and vpxa restarted so the host client and vCenter see it; the old
files put back when hostd does not come up.

Rights: root (or an administrator) with SSH enabled (Host → Actions →
Services → Enable Secure Shell).

Sources:
    https://knowledge.broadcom.com/external/article?legacyId=2113926  (Replacing a default ESXi
        certificate with a custom certificate: rui.crt / rui.key, restart hostd and vpxa)
    https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security-8-0/securing-esxi-hosts/certificate-management-for-esxi-hosts.html
A host managed by vCenter in its default VMCA mode gets its certificate
renewed by vCenter, which overwrites this one: set vCenter's
vpxd.certmgmt.mode to "custom" (or "thumbprint") first. Uncertain: ESXi
before 8.0 takes RSA keys only - choose an RSA key type for the certificate.
"""
from __future__ import annotations

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, ssh_fields, verify_fields, text)
from acmelib.plugins.targets import _files as F

SSL = '/etc/vmware/ssl'


class EsxiTarget(SshMixin, Base):
    kind = 'esxi'
    discovery = False       # nothing to find: a server over SSH
    title = 'VMware ESXi host (SSH)'
    vendor = 'VMware'
    description = ('Writes the host certificate to /etc/vmware/ssl/rui.crt and rui.key over SSH '
                   'and restarts hostd and vpxa; puts the old files back when hostd fails.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, try_command='vmware -v') + [
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('restart', 'Restart', 'select', default='hostd_vpxa',
              options=[['hostd_vpxa', 'hostd and vpxa'], ['services', 'every service '
                                                                       '(services.sh restart)'],
                       ['none', 'nothing (done by hand)']]),
    ] + F.file_fields() + verify_fields()

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, 'vmware -v; id -un', what='signing in')
        o = out.strip().splitlines()
        return 'signed in as %s: %s' % ((o[1:] or ['?'])[0], (o or ['?'])[0])

    def deploy(self, bundle, options):
        options = options or {}
        files = [{'path': SSL + '/rui.crt', 'data': bundle.as_format('fullchain-pem'),
                  'mode': 0o644, 'owner': None},
                 {'path': SSL + '/rui.key', 'data': bundle.as_format('key-rsa'),
                  'mode': 0o400, 'owner': None}]
        with self.ssh() as s:
            if not as_bool(options.get('force')) and F.skip_same(options) and \
                    F.all_same(self, s, files):
                self.remember(bundle, options)
                return self.same(bundle, 'in rui.crt / rui.key')
            existed = F.write_files(self, s, files, options=options)
            self.ctx.step('wrote %s/rui.crt and rui.key' % SSL, 'ok')
            how = self.opt(options, 'restart', 'hostd_vpxa')
            cmd = {'hostd_vpxa': '/etc/init.d/hostd restart && /etc/init.d/vpxa restart',
                   'services': 'services.sh restart'}.get(how)
            if cmd:
                rc, out, err = self.sh(s, cmd, timeout=600, check=False)
                if rc != 0:
                    F.put_back(self, s, files, existed)
                    self.sh(s, cmd, timeout=600, check=False)
                    raise PluginError('"%s" failed, the previous certificate is back: %s'
                                      % (cmd, (text(err).strip() or text(out).strip())[-300:]))
                self.ctx.step('ran %s' % cmd, 'ok')
            F.drop_previous(self, s, files, options)
        self.remember(bundle, options)
        return 'rui.crt / rui.key written on %s%s' % (self.c('host'),
                                                     ', hostd restarted' if cmd else '')

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify'):
            options['verify'] = '%s:443' % self.c('host')
        options.setdefault('verify_tries', 10)
        options.setdefault('verify_wait', 6)
        return Base.verify(self, bundle, options)

