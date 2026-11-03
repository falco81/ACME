# -*- coding: utf-8 -*-
"""
Tests run from another server (1.0.32): a connector. acme signs in over SSH to a
Linux server of yours (AlmaLinux, RHEL, Rocky... - any with OpenSSH) - its
address, user and key, as a Linux / Unix (SSH) target signs in - and runs the
tests chosen for it from there, each through `ssh -W host:port`: nothing
installed there, nothing left behind. For servers only that network reaches.

Defined as any test (Certificates → Tests), with the tests it carries chosen
from those already defined - HTTPS of the intranet, SMTP of the relay, RDP of a
Windows server...; attached to a certificate, every one of them is run through
it and compared with that certificate. The worst of them is the result.
"""
from __future__ import annotations

from acmelib.plugins.base import Check, PluginError, field
from acmelib.plugins.targets._common import SshMixin, ssh_fields


class SshRelayCheck(SshMixin, Check):
    kind = 'ssh_relay'
    title = 'Tests on a server over SSH'
    vendor = 'Connector'
    protocol = 'SSH connector'
    default_port = 22
    composite = True                # a set of other tests (checks.py runs each)
    sshkey_howto = 'linux'
    description = ('A connector: signs in over SSH to a Linux server of yours (AlmaLinux, RHEL, '
                   'Rocky…) and runs the tests chosen for it from there - for servers only that '
                   'network reaches.')
    fields = ssh_fields(sudo=False, try_command='id -un; uname -n; command -v ssh || true') + [
        field('tests', 'Tests run from there', 'list', required=True, options=[],
              options_from='tests',
              help='Tests defined on Certificates → Tests (HTTPS of an internal site, SMTP of a '
                   'relay, RDP…): each is run from this server as it is set, through "ssh -W". '
                   'Its OpenSSH must allow it (AllowTcpForwarding, on by default).'),
        field('timeout', 'Time limit (s)', 'number', default=20, min=1, max=120, advanced=True),
    ]

    def plan(self):
        names = self.c('tests') or []
        if isinstance(names, str):
            names = [x.strip() for x in names.splitlines()]
        names = [str(n).strip() for n in names if str(n).strip()]
        if not names:
            raise PluginError('no test is chosen to run from there', retry=False)
        return names

    def served(self, host, port, sni, verify=True):
        raise PluginError('a connector runs other tests - checks.py runs each', retry=False)

    def test(self):
        """Try it: signed in, and whether this server may open connections (ssh -W)."""
        s = self.ssh()
        try:
            rc, out, err = s.run('id -un; uname -n', timeout=30, check=False)
            if rc != 0:
                raise PluginError('signed in, but a command failed: %s' % (
                    (err or out).strip()[-200:]))
            who = [x.strip() for x in str(out).splitlines() if x.strip()]
            return 'signed in to %s as %s - %d test(s) run from there: %s' % (
                who[1] if len(who) > 1 else self.c('host'), who[0] if who else '?',
                len(self.plan()), ', '.join(self.plan()))
        finally:
            s.close()
