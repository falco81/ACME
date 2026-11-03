# -*- coding: utf-8 -*-
"""
Tests run from another server (1.0.32): acme signs in over SSH to a Linux server
of yours (AlmaLinux, RHEL, Rocky... - any with OpenSSH) as one of its SSH
targets does, and each test of the set goes from there - `ssh -W host:port`,
nothing installed there, nothing left behind. For servers only that network
reaches: an internal web server, a mail relay, RDP behind a firewall.

The set, one test a line:    KIND HOST[:PORT] [SNI] [SETTING=VALUE ...]

    https intranet.example.local
    https 10.0.5.10 www.example.local http=1 host_header=www.example.local path=/health
    smtp  mail.example.local:25
    rdp   10.0.5.20:3389  rdp.example.local tls_max=TLSv1_2

The settings are those of that kind of test (check_name, expect, tls_min,
ciphers, alpn, http, method, path, host_header, expect_status...).

Each is run as the test of that kind would run it (the TLS, STARTTLS...),
only connected through the server, and compared with the certificate as any
test is (acmelib/certs/checks.py); the worst of them is the result.
"""
from __future__ import annotations

import re

from acmelib.plugins.base import Check, PluginError, field

HEAD_RE = re.compile(r'^([a-z0-9_]+)\s+(\[[^\]]+\]|[^\s:\[\]]+)(?::(\d{1,5}))?(?:\s+(.*))?$')
OPT_RE = re.compile(r'^([a-z_][a-z0-9_]{0,40})=(.*)$')


class SshRelayCheck(Check):
    kind = 'ssh_relay'
    title = 'Through an SSH server'
    protocol = 'SSH relay'
    default_port = 22
    composite = True                # a set of other tests (checks.py runs each)
    description = ('Signs in over SSH to a Linux server of yours (AlmaLinux, RHEL, Rocky…) and '
                   'runs a set of tests from there - for servers only that network reaches.')
    fields = [
        field('relay', 'Through the server', 'select', required=True, options=[['', '–']],
              options_from='ssh_targets',
              help='A Linux / Unix (SSH) target of acme: its address, user and key are used. '
                   'Nothing is installed there; only "ssh -W" is asked of its OpenSSH (on by '
                   'default; AllowTcpForwarding must not be "no").'),
        field('checks', 'Tests run from there', 'list', required=True,
              placeholder='https intranet.example.local\nsmtp mail.example.local:25\n'
                          'rdp 10.0.5.20:3389 rdp.example.local',
              help='One a line: the kind of test, the address (with :port when not its '
                   'usual), the name sent as SNI when not the certificate\'s first, then any '
                   'setting of that kind of test as SETTING=VALUE (http=1 host_header=… '
                   'path=/health check_name=… tls_max=TLSv1_2 expect=any).'),
        field('timeout', 'Time limit (s)', 'number', default=15, min=1, max=120,
              advanced=True),
        field('require_trusted', 'Fail when not trusted here', 'bool', default=False,
              advanced=True),
    ]

    def plan(self):
        """[{kind, host, port, sni, line}] of the set, or PluginError in words."""
        lines = self.c('checks') or []
        if isinstance(lines, str):
            lines = lines.splitlines()
        out = []
        for raw in lines:
            line = str(raw).strip()
            if not line or line.startswith('#'):
                continue
            m = HEAD_RE.match(line)
            if not m:
                raise PluginError('"%s" is not KIND HOST[:PORT] [SNI] [SETTING=VALUE...]' % line,
                                  retry=False)
            if m.group(1) == self.kind:
                raise PluginError('"%s": a test through SSH cannot run another one' % line,
                                  retry=False)
            sni, opts = '', {}
            for tok in (m.group(4) or '').split():
                o = OPT_RE.match(tok)
                if o:
                    opts[o.group(1)] = o.group(2)
                elif not sni:
                    sni = tok
                else:
                    raise PluginError('"%s": "%s" is neither the SNI nor SETTING=VALUE' % (
                        line, tok), retry=False)
            out.append({'kind': m.group(1), 'host': m.group(2).strip('[]'),
                        'port': int(m.group(3)) if m.group(3) else None, 'sni': sni,
                        'options': opts, 'line': line})
        if not out:
            raise PluginError('no test is set to run from there', retry=False)
        return out

    def served(self, host, port, sni, verify=True):
        raise PluginError('this test is a set of others - checks.py runs each', retry=False)
