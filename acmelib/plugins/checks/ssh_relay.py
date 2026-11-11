# -*- coding: utf-8 -*-
"""
A connector of the tests (1.0.32; 1.0.76: each test chooses it - More → Through a connector,
checks.py _through()). The older way below still works: one with tests ticked, attached to a
certificate, runs them. Tests run from another server: a connector. acme signs in over SSH to a
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
    title = 'Connector over SSH'
    vendor = 'Connector'
    protocol = 'SSH connector'
    default_port = 22
    composite = True                # a set of other tests (checks.py runs each)
    sshkey_howto = 'linux'
    description = ('A connector: a Linux server of yours (AlmaLinux, RHEL, Rocky…) acme signs in to '
                   'over SSH, to test from it the servers only that network reaches - chosen in '
                   'each test\'s More → Through a connector.')
    fields = ssh_fields(sudo=False, try_command='id -un; uname -n; command -v ssh || true', via=False) + [
        field('tests', 'Tests run from there (the older way)', 'list', options=[],
              options_from='tests', add_words='Add a test', advanced=True,
              help='The older way (before 1.0.76): this connector attached to certificates runs '
                   'the tests ticked here. Now each test chooses its connector itself - More → '
                   'Through a connector - and this stays empty.'),
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
            tests = self.c('tests') or []
            tests = [x for x in (tests.splitlines() if isinstance(tests, str) else tests) if str(x).strip()]
            return 'signed in to %s as %s - the tests set to go through it are run from there%s' % (
                who[1] if len(who) > 1 else self.c('host'), who[0] if who else '?',
                ' (and, the older way, %s)' % ', '.join(tests) if tests else '')
        finally:
            s.close()
