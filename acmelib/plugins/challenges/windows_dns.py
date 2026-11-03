# -*- coding: utf-8 -*-
"""DNS-01 on a Windows Server DNS server, through its PowerShell DnsServer
cmdlets run over OpenSSH for Windows (1.0.27) - the "Windows DNS" flavour of
ssh_dns as a validation of its own, with nothing else in its form:

    Get-DnsServerZone                                            Test: the zones
    Get-DnsServerResourceRecord -ZoneName Z -Name N -RRType Txt -Node
    Add-DnsServerResourceRecord -ZoneName Z -Name N -Txt -DescriptiveText V
                                -TimeToLive (New-TimeSpan -Seconds T)
    Remove-DnsServerResourceRecord -ZoneName Z -RRType Txt -Name N -RecordData V -Force

each as `powershell -NoProfile -NonInteractive -Command "..."` (ssh_dns.ps_txt).
The name is relative to the zone ("@" for the apex). A value is added only
when the name (-Node: that name, not the names below it) does not hold it
already, and taken away only when it does - and always with -RecordData,
since "If you do not specify RecordData, the cmdlet deletes all records that
match RRtype and Name for the specified zone", and with -Force, without which
the cmdlet waits for a confirmation. Windows DNS raises the zone's serial by
itself; an Active Directory-integrated zone reaches the other domain
controllers by AD replication, so acme waits until every name server of the
zone has the value, as for every DNS-01 module.

The account signs in with an SSH key (or password) and must be allowed to
change the zone (its ACL; a member of DnsAdmins is the usual way). With
"DNS server for the cmdlets" set, the cmdlets reach that server by
-ComputerName from the machine signed in to.

Sources (the user's collection, api-docs/windows_dns/notes.md - no REST API
exists): https://learn.microsoft.com/en-us/powershell/module/dnsserver/add-dnsserverresourcerecord,
https://learn.microsoft.com/en-us/powershell/module/dnsserver/remove-dnsserverresourcerecord,
https://learn.microsoft.com/en-us/powershell/module/dnsserver/get-dnsserverresourcerecord,
https://learn.microsoft.com/en-us/powershell/module/dnsserver/get-dnsserverzone,
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/37eea101-00b8-4958-99eb-de8cda4b8417
(the serial raised by the server) and
https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update
(why RFC 2136 with a TSIG key is not the way to Windows DNS).

Less certain: -RecordData for a TXT record is documented only with an A
record's example - it is given the text as written with -DescriptiveText; the
property RecordData.DescriptiveText of a listed record is not in the cmdlet's
documentation (it is the WMI class MicrosoftDNS_TXTType's); the lowest TTL
(not documented - 60 s is used); how long AD replication takes.
"""
from __future__ import annotations

from acmelib.plugins.base import field
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, ssh_fields
from acmelib.plugins.challenges.ssh_dns import SshDns


def _windows_key(fields):
    out = []
    for f in fields:
        if f.get('type') == 'sshkey':
            f = dict(f, howto='windows', try_command='whoami',
                     help='Made here (ed25519) or your own; its public half in the account\'s '
                          'authorized_keys on the Windows server (for an administrator: '
                          'C:\\ProgramData\\ssh\\administrators_authorized_keys).')
        out.append(f)
    return out


class WindowsDns(SshDns):
    kind = 'windows_dns'
    guide_needs_dry_run = True
    title = 'Windows DNS Server (PowerShell over SSH)'
    vendor = 'Microsoft'
    description = ('TXT records in a zone of a Windows Server DNS server: its PowerShell '
                   'DnsServer cmdlets run over OpenSSH for Windows.')
    actions = []
    fields = [
        field('host', 'Windows DNS server', 'hostport', required=True,
              placeholder='dc1.example.com:22',
              help='The machine acme signs in to over SSH (OpenSSH for Windows): the DNS server '
                   'itself, or one with the DNS Server Tools that reaches it (below).'),
    ] + _windows_key(ssh_fields(user='acme')) + [
        field('zone', 'Zone', 'text', default='',
              help='The zone as DNS Manager shows it. Empty: the longest of "Zones there" the '
                   'name is in, else found by its SOA.'),
        field('zones', 'Zones there', 'list', default='', placeholder='example.com\nexample.net',
              help='The zones this server holds (Test lists them): a record goes in the '
                   'longest of them its name is in.'),
        field('computer', 'DNS server for the cmdlets', 'text', default='',
              help='-ComputerName: empty for the machine signed in to.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _how(self):
        return 'powershell'

    def _sudo(self, cmd):
        return cmd                      # Windows: no sudo
