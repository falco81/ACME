# -*- coding: utf-8 -*-
"""
A connector of the targets (1.0.75): a Linux server of yours (AlmaLinux, RHEL, Rocky... - any
with OpenSSH) that acme signs in to over SSH, to reach from it the targets only that network
reaches. Defined under Targets; a target that signs in over SSH chooses it in More → Through a
connector, and is then signed in to from there (ProxyCommand ssh -W, acmelib/certs/runtime.py) -
nothing installed there, nothing left behind. No certificate is deployed on the connector itself.

The tests have connectors of their own (Tests → Tests on a server over SSH, checks/ssh_relay.py):
those for the deployments and those for the tests may be different servers.
"""
from __future__ import annotations

from acmelib.plugins.targets._common import Base, PluginError, SshMixin, ssh_fields, text


class SshConnectorTarget(SshMixin, Base):
    kind = 'ssh_connector'
    title = 'Connector over SSH'
    vendor = 'Connector'
    connector = True                # a way to other targets, not a place for certificates
    discovery = False
    sshkey_howto = 'linux'
    description = ('A connector: a Linux server of yours (AlmaLinux, RHEL, Rocky…) acme signs in to '
                   'over SSH, to reach from it the targets only that network reaches - chosen in '
                   'their More → Through a connector. Nothing is deployed on it.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, try_command='id -un; uname -n; command -v ssh-keyscan || true',
                        via=False) + []
    deploy_fields = []

    def test(self):
        s = self.ssh()
        try:
            rc, out, err = s.run('id -un; uname -n; command -v ssh-keyscan >/dev/null && echo keyscan',
                                 timeout=30, check=False)
            if rc != 0:
                raise PluginError('signed in, but a command failed: %s' % (err or out).strip()[-200:])
            got = [x.strip() for x in text(out).splitlines() if x.strip()]
            return 'signed in to %s as %s%s - targets set to go through it are reached from there' % (
                got[1] if len(got) > 1 else self.c('host'), got[0] if got else '?',
                '' if 'keyscan' in got else ' (ssh-keyscan is not there: pin each target\'s host key)')
        finally:
            s.close()

    def deploy(self, bundle, options):
        raise PluginError('%s is a connector: certificates go to the targets reached through it, '
                          'not to it' % (self.c('host') or 'this'), retry=False)
