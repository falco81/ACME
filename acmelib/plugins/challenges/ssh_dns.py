# -*- coding: utf-8 -*-
"""DNS-01 by commands run over SSH on the DNS server itself: nsupdate -l (BIND's
local session key), nsupdate with a key file there, PowerShell's
Add-DnsServerResourceRecord on Windows DNS (through OpenSSH for Windows), or
commands of your own (edit a zone file, rndc reload)."""
from __future__ import annotations

import re

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, relative, shq,
                                                ssh_conn, ssh_fields)

SAFE = re.compile(r'^[A-Za-z0-9_.@*-]+$')


def _ps(s):
    """A word for PowerShell, in single quotes."""
    return "'" + str(s).replace("'", "''") + "'"


class SshDns(DnsChallenge):
    kind = 'ssh_dns'
    guide_needs_dry_run = True
    title = 'Commands on the DNS server over SSH'
    vendor = 'DNS'
    description = ('acme signs in to the DNS server over SSH and puts the record in there: '
                   'nsupdate -l (BIND), nsupdate with a key, PowerShell on Windows DNS, or '
                   'commands of your own.')
    fields = [
        field('host', 'DNS server', 'hostport', required=True, placeholder='ns1.example.com:22'),
    ] + ssh_fields(user='acme') + [
        field('flavour', 'How', 'select', default='nsupdate_local',
              options=[['nsupdate_local', 'nsupdate -l (BIND on that machine, its session key)'],
                       ['nsupdate_key', 'nsupdate -k KEYFILE (a TSIG key file there)'],
                       ['powershell', 'Windows DNS: PowerShell DnsServer cmdlets'],
                       ['custom', 'commands of my own']]),
        field('sudo', 'Through sudo', 'bool', default=False,
              help='Commands run as "sudo -n ..." (a sudoers line for exactly them).'),
        field('keyfile', 'Key file there', 'text', default='/etc/bind/acme.key',
              show_if={'flavour': ['nsupdate_key']}),
        field('nsupdate_server', 'Server nsupdate sends to', 'text', default='127.0.0.1',
              show_if={'flavour': ['nsupdate_key']}),
        field('zone', 'Zone', 'text', default='',
              help='Empty: found by its SOA. Windows DNS needs it right (the zone as in DNS '
                   'Manager).'),
        field('computer', 'DNS server for the cmdlets', 'text', default='',
              show_if={'flavour': ['powershell']},
              help='-ComputerName: empty for the machine signed in to.'),
        field('add_command', 'Command to add', 'textarea', default='',
              show_if={'flavour': ['custom']},
              placeholder='echo "{fqdn}. {ttl} IN TXT \\"{value}\\"" >> /var/named/acme.inc && '
                          'rndc reload {zone}',
              help='{fqdn} {relative} {zone} {value} {ttl} {name} are put in, shell-quoted.'),
        field('del_command', 'Command to take away', 'textarea', default='',
              show_if={'flavour': ['custom']},
              placeholder='sed -i "/{value}/d" /var/named/acme.inc && rndc reload {zone}'),
        field('test_command', 'Command to try', 'text', default='',
              show_if={'flavour': ['custom']}, placeholder='rndc status'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _conn(self):
        host, port = D.split_hostport(self.c('host', ''), 22)
        if not host:
            raise PluginError('the DNS server is not set', retry=False)
        return ssh_conn(self, host, port)

    def _sudo(self, cmd):
        return ('sudo -n ' + cmd) if self.flag('sudo') else cmd

    def _run(self, cmd, stdin=None):
        conn = self._conn()
        try:
            with self.ctx.ssh(conn) as s:
                rc, out, err = s.run(cmd, input=stdin, timeout=120, check=False)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('%s over SSH: %s' % (conn['host'], e))
        if rc != 0:
            said = (err or out or b'')
            said = said.decode('utf-8', 'replace') if isinstance(said, bytes) else str(said)
            raise PluginError('%s: "%s" ended with %s: %s' % (conn['host'], cmd.split()[0], rc,
                                                            said.strip()[-300:]), detail=said)
        return out

    def _words(self, fqdn, value):
        zone = self.zone_for(fqdn)
        for w in (fqdn, zone, value):
            if not SAFE.match(str(w)):
                raise PluginError('%r is not something acme will put on a command line' % w,
                                  retry=False)
        return zone, relative(fqdn, zone)

    def _nsupdate(self, op, fqdn, value):
        zone, _rel = self._words(fqdn, value)
        script = ''
        if self.c('flavour') == 'nsupdate_key':
            script += 'server %s\n' % self.c('nsupdate_server', '127.0.0.1')
            cmd = 'nsupdate -k %s' % shq(self.c('keyfile', ''))
        else:
            cmd = 'nsupdate -l'
        script += 'zone %s\n' % zone
        if op == 'add':
            script += 'update add %s. %d TXT "%s"\n' % (fqdn, self.ttl(), value)
        else:
            script += 'update delete %s. TXT "%s"\n' % (fqdn, value)
        script += 'send\n'
        self._run(self._sudo(cmd), stdin=script.encode())

    def _powershell(self, op, fqdn, value):
        zone, rel = self._words(fqdn, value)
        comp = (' -ComputerName ' + _ps(self.c('computer'))) if self.c('computer') else ''
        if op == 'add':
            ps = ('Add-DnsServerResourceRecord%s -ZoneName %s -Name %s -Txt -DescriptiveText %s '
                  '-TimeToLive (New-TimeSpan -Seconds %d)' % (comp, _ps(zone), _ps(rel),
                                                             _ps(value), self.ttl()))
        else:
            ps = ('Get-DnsServerResourceRecord%s -ZoneName %s -Name %s -RRType Txt '
                  '-ErrorAction SilentlyContinue | Where-Object { $_.RecordData.DescriptiveText '
                  '-eq %s } | Remove-DnsServerResourceRecord%s -ZoneName %s -Force'
                  % (comp, _ps(zone), _ps(rel), _ps(value), comp, _ps(zone)))
        self._run('powershell -NoProfile -NonInteractive -Command "%s"' % ps.replace('"', '\\"'))

    def _custom(self, op, fqdn, value):
        zone, rel = self._words(fqdn, value)
        tpl = self.c('add_command' if op == 'add' else 'del_command', '')
        if not tpl:
            if op == 'add':
                raise PluginError('the command to add is not set', retry=False)
            return
        words = {'fqdn': fqdn, 'relative': rel, 'zone': zone, 'value': value,
                 'ttl': str(self.ttl()), 'name': fqdn}
        cmd = tpl
        for k, v in words.items():
            cmd = cmd.replace('{%s}' % k, shq(v))
        self._run(self._sudo(cmd) if self.flag('sudo') else cmd)

    def _do(self, op, fqdn, value):
        how = self.c('flavour', 'nsupdate_local')
        if how in ('nsupdate_local', 'nsupdate_key'):
            self._nsupdate(op, fqdn, value)
        elif how == 'powershell':
            self._powershell(op, fqdn, value)
        else:
            self._custom(op, fqdn, value)

    def add_txt(self, fqdn, value):
        self._do('add', fqdn, value)
        return None

    def del_txt(self, fqdn, value, handle):
        self._do('del', fqdn, value)

    def test(self):
        how = self.c('flavour', 'nsupdate_local')
        if how in ('nsupdate_local', 'nsupdate_key'):
            cmd = self._sudo('nsupdate -V') if how == 'nsupdate_local' else \
                self._sudo('test -r %s && nsupdate -V' % shq(self.c('keyfile', '')))
        elif how == 'powershell':
            cmd = 'powershell -NoProfile -NonInteractive -Command "Get-DnsServerZone%s | ' \
                  'Select-Object -First 20 -ExpandProperty ZoneName"' % (
                      (' -ComputerName ' + _ps(self.c('computer'))) if self.c('computer') else '')
        else:
            cmd = self.c('test_command', '') or 'true'
            cmd = self._sudo(cmd)
        out = self._run(cmd)
        out = out.decode('utf-8', 'replace') if isinstance(out, bytes) else str(out or '')
        return '%s: %s' % (self._conn()['host'], out.strip()[:400] or 'it worked')
