#!/usr/bin/env python3
"""DNS-01 by commands on the DNS server over SSH (acmelib/plugins/challenges/ssh_dns.py
and _sshdns.py): what "Find out what runs there" reads of BIND, PowerDNS, Knot,
NSD, dnsmasq, Unbound and Windows DNS (from outputs those print), that it sends
read-only commands only, the commands and scripts of each way of writing, the
zone-file editor (acme's lines only, the serial, the backup put back), the zone
a name goes in - and, where the servers are installed here (named, knotd, nsd,
pdns_server, unbound, dnsmasq), the whole thing for real over a "SSH" that runs
its commands on this machine, the records asked of the server with dig.

    python3 test/test_ssh_dns.py          (or: python3 -m unittest test.test_ssh_dns)

The real servers need root (BIND's nsupdate -l asks 127.0.0.1 port 53); each is
skipped where it is not installed or cannot be started.
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from acmelib.plugins.base import PluginError, Registry, SshSession  # noqa: E402
from acmelib.plugins.challenges import _dns as D                     # noqa: E402
from acmelib.plugins.challenges import _sshdns as X                  # noqa: E402

import test_challenges as TC                                         # noqa: E402

REG = Registry(extra_dirs=[]).reload()
SshDns = REG.get('challenge', 'ssh_dns')
NOW = 1793577600            # 2026-11-02 00:00 UTC


# ---------------------------------------------------------------------------
# What the servers print (taken from BIND 9.18, PowerDNS 4.8, Knot 3.3, NSD 4.8,
# dnsmasq 2.91, Unbound 1.19 - the paths those of Debian)
# ---------------------------------------------------------------------------
BIND_CONF = '''options {
	directory "/var/cache/bind";
	listen-on-v6  {
		"any";
	};
	dnssec-validation auto;
};
key "rndc-key" {
	algorithm "hmac-sha256";
	secret "g5z5pEbAMSsvXjtOaOxE+20VsUwvOjNWs+ITW1s3XTA=";
};
key "acme-key" {
	algorithm "hmac-sha256";
	secret "ZB5dGu92ajGbfHqV0mlWaXgqD1ZuUIZsyCaqEFg7UGo=";
};
zone "." {
	type hint;
	file "/usr/share/dns/root.hints";
};
zone "localhost" {
	type master;
	file "/etc/bind/db.local";
};
zone "example.com" {
	type primary;
	file "/var/lib/bind/db.example.com";
	update-policy local;
};
zone "static.example.org" {
	type primary;
	file "db.static.example.org";
};
zone "keyed.example.net" {
	type primary;
	file "/var/lib/bind/db.keyed.example.net";
	update-policy {
		grant "acme-key" zonesub "TXT";
	};
};
zone "sec.example.com" {
	type secondary;
	file "db.sec.example.com";
	primaries {
		192.0.2.1;
	};
};
view "inside" {
	match-clients {
		"any";
	};
	zone "intra.example.com" {
		type primary;
		file "/var/lib/bind/db.intra";
	};
};
'''
BIND_STATIC_CONF = '''options {
	directory "/var/named";
};
zone "example.org" {
	type master;
	file "example.org.zone";
};
zone "example.info" IN {
	type master;
	file "/var/named/example.info.zone";
};
'''
LS_BIND = '''drwxrwxr-x 2 0 118 4096 Nov  1 23:18 /var/lib/bind
-rw-r--r-- 1 118 118  419 Nov  1 23:18 /var/lib/bind/db.example.com
-rw-r--r-- 1 118 118  848 Nov  1 23:18 /var/lib/bind/db.example.com.jnl
-rw-r--r-- 1 118 118  419 Nov  1 23:18 /var/lib/bind/db.keyed.example.net
-rw-r--r-- 1 0 0  300 Oct 30 10:00 /var/cache/bind/db.static.example.org
drwxrwxr-x 2 118 118 4096 Oct 30 10:00 /var/cache/bind
-rw-r--r-- 1 0 0  300 Oct 30 10:00 /var/lib/bind/db.intra
-rw------- 1 118 118   77 Nov  1 23:18 /run/named/session.key
'''
KEYS_GREP = '''/etc/bind/rndc.key:key "rndc-key" {
/etc/bind/acme.key:key "acme-key" {
'''
PDNS_ZONES = 'example.com\nsigned.example.net\nsec.example.org\n'
PDNS_SHOW = {
    'example.com': 'This is a Native zone\nZone is not actively secured\nMetadata items: None\n'
                   "No keys for zone 'example.com'.\n",
    'signed.example.net': 'This is a Native zone\nMetadata items: None\nZone has NSEC semantics'
                          '\nkeys: \nID = 1 (CSK), flags = 257, tag = 31294, algo = 13, bits = 256'
                          '\t  Active\t Published  ( ECDSAP256SHA256 ) \n',
    'sec.example.org': 'This is a Slave zone\nZone is not actively secured\n'}
PDNS_GREP = 'launch=gsqlite3\napi=yes\nwebserver=yes\nwebserver-address=127.0.0.1\n' \
            'webserver-port=8081\n'
PDNS_LIST = ('$ORIGIN .\n_acme-challenge.www.example.com\t300\tIN\tTXT\t"someone-else"\n'
             'example.com\t3600\tIN\tNS\tns1.example.com.\n'
             'example.com\t3600\tIN\tSOA\ta.misconfigured.dns.server.invalid hostmaster.example.'
             'com 0 10800 3600 604800 3600\n')
KNOT_STATUS = ('[example.com.] role: master | serial: 2026010101\n'
               '[other.example.net.] role: master | serial: 2026010101\n'
               '[sec.example.org.] role: slave | serial: 7\n')
NSD_ZONES = 'example.com\nsecond.example.net\nsec.example.org\n'
NSD_FILES = {'example.com': 'example.com.zone', 'second.example.net': '/var/nsd/second.zone',
             'sec.example.org': 'sec.example.org.zone'}
LS_NSD = '''drwxr-xr-x 2 0 0 4096 Nov  1 23:18 /etc/nsd
-rw-r--r-- 1 0 0  200 Nov  1 23:18 /etc/nsd/example.com.zone
drwxr-xr-x 2 0 0 4096 Nov  1 23:18 /var/nsd
-rw-r--r-- 1 0 0  200 Nov  1 23:18 /var/nsd/second.zone
'''
DNSMASQ_GREP = ('conf-dir=/etc/dnsmasq.d/,*.conf\nlocal=/lan.example.com/\n'
                'domain=lan.example.com\nauth-zone=office.example.net,192.0.2.0/24\n'
                'txt-record=_acme-challenge.www.lan.example.com,"someone-else"\n')
UNBOUND_ZONES = ('home.arpa. static\n0.in-addr.arpa. static\nlocalhost. redirect\n'
                 'intra.example.com. static\ntest. static\n'
                 '8.b.d.0.1.0.0.2.ip6.arpa. static\n')
WIN_ZONES = ('_msdcs.corp.example.com;Primary;True;False;False\n'
             'corp.example.com;Primary;True;False;False\n'
             '0.in-addr.arpa;Primary;False;True;True\nTrustAnchors;Primary;True;False;False\n'
             'partner.example.net;Secondary;False;False;False\n')
TOOLS_ALL = '\n'.join('/usr/sbin/' + t for t in X.TOOLS) + '\n'


def tools(*names):
    return ''.join('/usr/bin/%s\n' % n for n in names + ('sudo', 'timeout', 'pgrep',
                                                          'sha256sum'))


# ---------------------------------------------------------------------------
# A scripted SSH: commands answered by rules, every one written down
# ---------------------------------------------------------------------------
class Scripted(SshSession):
    def __init__(self, world, conn):
        self.world = world
        if world.down:
            raise PluginError('ssh to %s: Connection refused' % conn['host'])
        world.conns.append(conn)

    def run(self, command, input=None, timeout=120, check=True):
        w = self.world
        w.commands.append(command)
        w.inputs.append(input)
        sudo = 'sudo -n ' in command
        core = X.read_only_core(command)
        if sudo and core == 'true':
            return (0 if w.sudo else 1), '', '' if w.sudo else 'sudo: a password is required'
        for pat, ans in w.rules:
            m = re.match(pat, core)
            if m:
                if callable(ans):
                    ans = ans(core, input, sudo)
                rc, out, err = ans
                if w.need_sudo and not sudo and re.match(w.need_sudo, core):
                    return 1, '', 'permission denied'
                return rc, out, err
        return 127, '', '%s: not found' % core.split()[0]


class World(object):
    def __init__(self, rules, uid=1001, sudo=True, need_sudo=None):
        self.rules = [(r'^uname -s$', (0, 'Linux\n', '')),
                      (r'^id -u$', (0, '%d\n' % uid, '')),
                      (r'^id -un$', (0, 'acme\n' if uid else 'root\n', '')),
                      (r'^id -G$', (0, '%d 27\n' % uid, ''))] + list(rules)
        self.commands, self.inputs, self.conns = [], [], []
        self.sudo, self.need_sudo, self.down = sudo, need_sudo, False


class Ctx(TC.FakeCtx):
    def __init__(self, world=None, ssh_cls=Scripted, **kw):
        TC.FakeCtx.__init__(self, **kw)
        self.world, self.ssh_cls = world, ssh_cls

    def ssh(self, conn):
        return self.ssh_cls(self.world, conn)


def module(cfg, world=None, ssh_cls=Scripted):
    base = {'host': 'ns1.example.com', 'user': 'acme', 'key': 'K', 'propagation': 'none',
            'follow_cname': False}
    base.update(cfg)
    return SshDns(base, Ctx(world, ssh_cls))


# Not one of these words is in a command discovery sends.
WRITES = re.compile(r'(add-record|replace-rrset|delete-rrset|rectify|increase-serial|zone-begin|'
                    r'zone-set|zone-unset|zone-commit|zone-abort|local_data|freeze|thaw|reload|'
                    r'restart|start|stop|kill|nsupdate|rndc|\brm\b|\bmv\b|\bcp\b|\btee\b|'
                    r'sed -i|>|\bchmod\b|\bchown\b|\btouch\b|\bmkdir\b|install|curl|Add-Dns|'
                    r'Remove-Dns|Set-Dns)')
# What discovery may run, as the first words of each (an allow-list of this test's own).
ALLOWED_START = ('uname -s', 'id -u', 'id -un', 'id -G', 'true', 'for c in ', 'systemctl '
                 'is-active ', 'pgrep -l -x ', 'named -v', 'named-checkconf -p', 'ls -lnd -- ',
                 "grep -sH -E '^[[:space:]]*key", 'pdns_server --version', 'pdnsutil ',
                 'grep -hsE ', 'knotc ', 'nsd -v', 'nsd-checkconf ', 'dnsmasq --version',
                 'unbound -V', 'unbound-control ', 'powershell -NoProfile -NonInteractive '
                 '-Command "Get-DnsServerZone')
READS_ONLY = ('list-all-zones', 'show-zone', 'zone-status', 'conf-read', '-V', 'list_local_zones',
              'status')


def assert_read_only(tc, commands):
    tc.assertTrue(commands)
    for cmd in commands:
        core = X.read_only_core(cmd)
        tc.assertTrue(cmd.startswith(X.PATH_PRE) or cmd == X.WIN_PROBE, cmd)
        tc.assertTrue(core.startswith(ALLOWED_START), core)
        if core == X.TOOLS_PROBE:                    # names the tools, runs none
            tc.assertTrue(core.startswith('for c in ') and core.endswith(
                'do command -v "$c"; done'))
            continue
        tc.assertIsNone(WRITES.search(core.replace('2>&1', '')), core)
        if core.startswith(('pdnsutil ', 'knotc ', 'unbound-control ')):
            tc.assertTrue(core.split()[-1] in READS_ONLY or core.split()[-2] in READS_ONLY,
                          core)
        tc.assertTrue(X.is_read_only(cmd), cmd)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def bind_world(conf=BIND_CONF, ls=LS_BIND, **kw):
    return World([
        (r'^for c in ', (0, tools('named', 'named-checkconf', 'named-checkzone', 'rndc',
                                  'nsupdate', 'systemctl'), '')),
        (r'^systemctl is-active', (3, 'active\nunknown\ninactive\ninactive\ninactive\ninactive\n'
                                      'inactive\n', '')),
        (r'^pgrep', (1, '', '')),
        (r'^named -v$', (0, 'BIND 9.18.28-1~deb12u2-Debian (Extended Support Version) <id:>\n',
                         '')),
        (r'^named-checkconf -p', (0, conf, '')),
        (r'^ls -lnd', (2, ls, 'ls: cannot access \'/var/run/named/session.key\': No such file')),
        (r"^grep -sH -E '\^\[\[:space:\]\]\*key", (0, KEYS_GREP, '')),
    ], **kw)


class TestDiscovery(unittest.TestCase):
    def test_bind_local_session_key(self):
        w = bind_world(need_sudo=r'^(named-checkconf|grep -sH)')
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertTrue(got['ok'], got)
        self.assertEqual((got['server'], got['version'], got['flavour_suggested']),
                         ('BIND', '9.18.28-1~deb12u2-Debian', 'nsupdate_local'))
        z = {x['name']: x for x in got['zones']}
        self.assertNotIn('localhost', z)
        self.assertEqual(z['example.com']['flavour'], 'nsupdate_local')
        self.assertTrue(z['example.com']['dynamic'] and z['example.com']['journal'])
        self.assertEqual(z['static.example.org']['file'], '/var/cache/bind/db.static.example.org')
        self.assertEqual(z['static.example.org']['flavour'], 'bind_file')
        self.assertEqual(z['keyed.example.net']['flavour'], 'nsupdate_key')
        self.assertIn('/etc/bind/acme.key', z['keyed.example.net']['how_writable'])
        self.assertEqual(z['sec.example.com']['flavour'], '')
        self.assertIn('192.0.2.1', z['sec.example.com']['how_writable'])
        self.assertEqual(z['intra.example.com']['view'], 'inside')
        # the session key is 0600 bind:bind - acme (1001) reads it through sudo
        self.assertEqual(got['fields'], {'flavour': 'nsupdate_local', 'sudo': True,
                                         'zones': ['example.com'], 'zone': 'example.com'})
        self.assertEqual({k['name']: k['file'] for k in got['keys']},
                         {'rndc-key': '/etc/bind/rndc.key', 'acme-key': '/etc/bind/acme.key'})
        self.assertNotIn('ZB5dGu92', json.dumps(got))
        self.assertTrue(any('another validation' in p for p in got['problems']))
        # what needed root was read through sudo -n, after the plain try
        self.assertTrue(any(c.endswith('sudo -n named-checkconf -p') for c in w.commands))
        self.assertIn('timeout 10 ', [c for c in w.commands if 'named -v' in c][0])

    def test_bind_static_zone_files(self):
        ls = ('drwxrwx--- 2 0 25 4096 Oct 30 10:00 /var/named\n'
              '-rw-r----- 1 0 25 300 Oct 30 10:00 /var/named/example.org.zone\n'
              '-rw-r----- 1 0 25 300 Oct 30 10:00 /var/named/example.info.zone\n')
        w = bind_world(conf=BIND_STATIC_CONF, ls=ls, uid=0)
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual(got['flavour_suggested'], 'bind_file')
        self.assertEqual(got['fields']['zone_files'], [
            'example.org /var/named/example.org.zone', 'example.info /var/named/example.info.zone'])
        self.assertEqual(got['fields']['sudo'], False)          # root
        self.assertEqual(got['fields']['zones'], ['example.org', 'example.info'])
        self.assertNotIn('zone', got['fields'])
        self.assertFalse(any('sudo -n' in c for c in w.commands))

    def test_bind_unreadable_without_sudo(self):
        w = bind_world(sudo=False, need_sudo=r'^named-checkconf')
        got = module({}, w).discover()
        self.assertTrue(got['ok'])
        self.assertEqual(got['server'], 'BIND')
        self.assertTrue(any('sudo -n does not work' in p for p in got['problems']), got)
        self.assertEqual(got['fields'], {})

    def test_powerdns(self):
        w = World([
            (r'^for c in ', (0, tools('pdnsutil', 'pdns_server', 'curl'), '')),
            (r'^pgrep', (0, '812 pdns_server\n', '')),
            (r'^pdns_server --version', (0, '', 'Nov 01 23:17:31 PowerDNS Authoritative Server '
                                                '4.8.3 (C) 2001-2022 PowerDNS.COM BV\n')),
            (r'^grep -hsE', (0, PDNS_GREP, '')),
            (r'^pdnsutil list-all-zones$', (0, PDNS_ZONES, '')),
            (r'^pdnsutil show-zone (\S+)$', lambda c, i, s: (0, PDNS_SHOW[c.split()[-1]], '')),
        ], need_sudo=r'^pdnsutil')
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual((got['server'], got['version'], got['flavour_suggested']),
                         ('PowerDNS', '4.8.3', 'pdnsutil'))
        z = {x['name']: x for x in got['zones']}
        self.assertEqual((z['example.com']['dnssec'], z['signed.example.net']['dnssec']),
                         (False, True))
        self.assertEqual(z['sec.example.org']['flavour'], '')
        self.assertEqual(got['fields'], {'flavour': 'pdnsutil', 'sudo': True, 'pdns_rectify': True,
                                         'zones': ['example.com', 'signed.example.net']})
        self.assertNotIn('api-key', ' '.join(w.commands))

    def test_knot(self):
        w = World([
            (r'^for c in ', (0, tools('knotc', 'knotd'), '')),
            (r'^pgrep', (0, '77 knotd\n', '')),
            (r'^knotc -V$', (0, 'knotc (Knot DNS), version 3.3.4\n', '')),
            (r'^knotc zone-status$', (0, KNOT_STATUS, '')),
        ], uid=0)
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual((got['server'], got['version'], got['flavour_suggested']),
                         ('Knot DNS', '3.3.4', 'knot'))
        self.assertEqual(got['fields'], {'flavour': 'knot', 'sudo': False,
                                         'zones': ['example.com', 'other.example.net']})

    def test_knot_not_running_reads_its_config(self):
        w = World([
            (r'^for c in ', (0, tools('knotc'), '')),
            (r'^knotc -c /etc/knot/knot.conf -V$', (0, 'knotc (Knot DNS), version 3.3.4\n', '')),
            (r'^knotc -c /etc/knot/knot.conf zone-status$', (1, '', 'error: failed to connect')),
            (r'^knotc -c /etc/knot/knot.conf conf-read zone.domain$',
             (0, 'zone.domain = example.com.\nzone.domain = example.net.\n', '')),
        ], uid=0)
        got = module({'knot_conf': '/etc/knot/knot.conf'}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual(got['fields']['zones'], ['example.com', 'example.net'])
        self.assertEqual(got['fields']['knot_conf'], '/etc/knot/knot.conf')
        self.assertTrue(any('does not answer' in p for p in got['problems']))

    def test_nsd(self):
        def zonefile(core, i, s):
            z = core.split()[2]
            return 0, NSD_FILES[z] + '\n', ''

        def xfr(core, i, s):
            return 0, '192.0.2.1 NOKEY\n' if core.split()[2] == 'sec.example.org' else '', ''
        w = World([
            (r'^for c in ', (0, tools('nsd', 'nsd-checkconf', 'nsd-control', 'nsd-checkzone'),
                             '')),
            (r'^nsd -v$', (1, '', 'NSD version 4.8.0\nWritten by NLnet Labs.\n')),
            (r'^nsd-checkconf -o zones /etc/nsd/nsd.conf$', (0, NSD_ZONES, '')),
            (r'^nsd-checkconf -o zonesdir', (0, '/etc/nsd\n', '')),
            (r'^nsd-checkconf -z \S+ -o zonefile', zonefile),
            (r'^nsd-checkconf -z \S+ -o request-xfr', xfr),
            (r'^ls -lnd', (0, LS_NSD, '')),
        ])
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual((got['server'], got['version'], got['flavour_suggested']),
                         ('NSD', '4.8.0', 'nsd'))
        self.assertEqual(got['fields']['zone_files'], ['example.com /etc/nsd/example.com.zone',
                                                       'second.example.net /var/nsd/second.zone'])
        self.assertTrue(got['fields']['sudo'])                  # root:root 0644, acme is 1001
        self.assertIn('192.0.2.1', {z['name']: z for z in got['zones']}['sec.example.org']
                      ['how_writable'])

    def test_dnsmasq(self):
        w = World([
            (r'^for c in ', (0, tools('dnsmasq'), '')),
            (r'^pgrep', (0, '311 dnsmasq\n', '')),
            (r'^dnsmasq --version', (0, 'Dnsmasq version 2.91  Copyright (c) 2000-2025\n', '')),
            (r'^grep -hsE', (0, DNSMASQ_GREP, '')),
            (r'^ls -lnd -- /etc/dnsmasq.d$', (0, 'drwxr-xr-x 2 0 0 4096 Nov  1 23:18 '
                                                 '/etc/dnsmasq.d\n', '')),
        ])
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual((got['server'], got['flavour_suggested']), ('dnsmasq', 'dnsmasq'))
        self.assertEqual(got['fields']['zones'], ['lan.example.com', 'office.example.net'])
        self.assertTrue(got['fields']['sudo'])
        self.assertTrue(any('restarts it' in p for p in got['problems']))

    def test_unbound(self):
        w = World([
            (r'^for c in ', (0, tools('unbound', 'unbound-control'), '')),
            (r'^unbound -V', (0, 'Version 1.19.2\n', '')),
            (r'^unbound-control list_local_zones$', (0, UNBOUND_ZONES, '')),
        ], need_sudo=r'^unbound-control')
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual(got['fields'], {'flavour': 'unbound', 'sudo': True,
                                         'zones': ['intra.example.com'],
                                         'zone': 'intra.example.com'})

    def test_windows(self):
        w = World([(r'^powershell ', (0, WIN_ZONES, ''))])
        w.rules[0] = (r'^uname -s$', (1, '', "'uname' is not recognized as an internal or "
                                            "external command"))
        got = module({}, w).discover()
        assert_read_only(self, w.commands)
        self.assertEqual(got['flavour_suggested'], 'powershell')
        self.assertEqual(got['fields'], {'flavour': 'powershell',
                                         'zones': ['_msdcs.corp.example.com', 'corp.example.com']})
        self.assertEqual({z['name']: z['flavour'] for z in got['zones']}['partner.example.net'],
                         '')

    def test_two_servers_the_running_one_suggested(self):
        w = bind_world()
        w.rules[4:4] = [(r'^for c in ', (0, tools('named', 'named-checkconf', 'unbound-control',
                                                  'systemctl'), ''))]
        w.rules.append((r'^unbound-control list_local_zones$', (0, UNBOUND_ZONES, '')))
        got = module({}, w).discover()
        self.assertEqual(got['server'], 'BIND')
        self.assertEqual([s['server'] for s in got['servers']], ['BIND', 'Unbound'])

    def test_nothing_there(self):
        w = World([(r'^for c in ', (0, tools(), ''))])
        got = module({}, w).discover()
        self.assertTrue(got['ok'])
        self.assertEqual(got['server'], '')
        self.assertEqual(got['fields'], {})
        self.assertTrue(any('set the fields by hand' in p for p in got['problems']))

    def test_cannot_sign_in(self):
        w = World([])
        w.down = True
        got = module({}, w).discover()
        self.assertFalse(got['ok'])
        self.assertIn('Connection refused', got['problems'][0])
        with self.assertRaises(PluginError):
            module({}, w).action('discover')

    def test_action_words(self):
        said = module({}, bind_world()).action('discover')
        self.assertIn('BIND 9.18.28-1~deb12u2-Debian, suggested: nsupdate_local', said)
        self.assertIn('set flavour = nsupdate_local', said)

    def test_refuses_what_is_not_read_only(self):
        for cmd in ('rndc reload example.com', 'pdnsutil add-record example.com x TXT 1 "a"',
                    'knotc zone-begin example.com', 'ls -lnd -- /x; rm -rf /',
                    'named-checkconf -p /etc/named.conf && reboot', 'grep -hsE x /etc/shadow',
                    "unbound-control local_data 'x TXT \"a\"'", 'nsupdate -l', 'true; id',
                    'named-checkconf -p $(reboot)', 'ls -lnd -- `reboot`'):
            self.assertFalse(X.is_read_only(X.PATH_PRE + cmd), cmd)
        d = X.Discovery(lambda c, t: (0, '', ''))
        with self.assertRaises(PluginError):
            d.sh('rndc reload example.com')

    def test_tolerates_tools_that_fail(self):
        w = bind_world()
        w.rules = [(p, (124, '', 'timed out')) if p == r'^named -v$' else (p, a)
                   for p, a in w.rules]
        w.rules.insert(5, (r'^named-checkconf -p', (1, '', '/etc/bind/named.conf:3: missing ;')))
        got = module({}, w).discover()
        self.assertTrue(got['ok'])
        self.assertEqual(got['version'], '')
        self.assertTrue(any('missing ;' in p for p in got['problems']))


class TestNamedConf(unittest.TestCase):
    def test_parse(self):
        cf = X.parse_named_conf(BIND_CONF)
        self.assertEqual(cf['directory'], '/var/cache/bind')
        self.assertEqual([k['name'] for k in cf['keys']], ['rndc-key', 'acme-key'])
        self.assertNotIn('secret', json.dumps(cf))
        z = {x['name']: x for x in cf['zones']}
        self.assertEqual(z['example.com']['policy'], ['local'])
        self.assertEqual(X.zone_keys(z['keyed.example.net']), ['acme-key'])
        self.assertEqual(z['sec.example.com']['primaries'], ['192.0.2.1'])
        self.assertEqual(z['intra.example.com']['view'], 'inside')
        old = X.parse_named_conf('zone "x.test" { type master; file "x"; allow-update { key '
                                 '"k1"; 127.0.0.1; }; }; // comment\n/* more */')
        self.assertEqual(X.zone_keys(old['zones'][0]), ['k1'])

    def test_ls(self):
        got = X.parse_ls(LS_BIND)
        self.assertEqual(got['/run/named/session.key'], {'kind': '-', 'mode': 'rw-------',
                                                        'uid': 118, 'gid': 118})
        self.assertTrue(X.may(got['/run/named/session.key'], 118, set(), 'r'))
        self.assertFalse(X.may(got['/run/named/session.key'], 1001, {118}, 'r'))
        self.assertTrue(X.may(got['/var/lib/bind'], 1001, {118}, 'w'))
        self.assertTrue(X.may(got['/var/lib/bind'], 0, set(), 'w'))


# ---------------------------------------------------------------------------
# The zone file editor
# ---------------------------------------------------------------------------
ZONE = '''$ORIGIN example.org.
$TTL 3600
@   IN  SOA ns1.example.org. hostmaster.example.org. (
        2026010103 ; serial
        3600 600 1209600 300 )
    IN  NS  ns1
ns1 IN  A   192.0.2.53
_acme-challenge IN TXT "someone else's ; not a comment"
www IN  A   192.0.2.80
'''


class TestZoneFile(unittest.TestCase):
    FQDN = '_acme-challenge.www.example.org'

    def test_add_and_remove_only_ours(self):
        new, changed, old, serial = X.edit_zone_text(ZONE, self.FQDN, 'AbC-1_x', 60, 'add',
                                                     now=NOW)
        self.assertTrue(changed)
        self.assertEqual((old, serial), (2026010103, 2026110200))
        self.assertTrue(new.startswith(ZONE.replace('2026010103', '2026110200')))
        self.assertTrue(new.endswith('_acme-challenge.www.example.org. 60 IN TXT "AbC-1_x" '
                                     '; acme-challenge\n'))
        again, changed2, _o, s2 = X.edit_zone_text(new, self.FQDN, 'AbC-1_x', 60, 'add', now=NOW)
        self.assertEqual((again, changed2, s2), (new, False, 2026110200))
        two, _c, _o, s3 = X.edit_zone_text(new, self.FQDN, 'second', 60, 'add', now=NOW)
        self.assertEqual(s3, 2026110201)
        gone, changed3, _o, s4 = X.edit_zone_text(two, self.FQDN, 'AbC-1_x', 60, 'del', now=NOW)
        self.assertTrue(changed3)
        self.assertEqual(s4, 2026110202)
        self.assertNotIn('AbC-1_x', gone)
        self.assertIn('"second" ; acme-challenge', gone)
        self.assertIn("someone else's", gone)
        # the same line typed by a person, without the mark, is not acme's to take
        hand = ZONE + '_acme-challenge.www.example.org. 60 IN TXT "AbC-1_x"\n'
        _t, changed4, _o, _s = X.edit_zone_text(hand, self.FQDN, 'AbC-1_x', 60, 'del', now=NOW)
        self.assertFalse(changed4)

    def test_serials(self):
        self.assertEqual(X.next_serial(2026010103, 'auto', NOW), 2026110200)
        self.assertEqual(X.next_serial(2026110299, 'auto', NOW), 2026110300)
        self.assertEqual(X.next_serial(2026120105, 'auto', NOW), 2026120106)   # ahead: + 1
        self.assertEqual(X.next_serial(41, 'auto', NOW), 42)
        self.assertEqual(X.next_serial(41, 'date', NOW), 2026110200)
        self.assertEqual(X.next_serial(41, 'unixtime', NOW), NOW)
        self.assertEqual(X.next_serial(1793577700, 'unixtime', NOW), 1793577701)
        self.assertEqual(X.next_serial(1793577700, 'auto', NOW), 1793577701)
        with self.assertRaises(PluginError):
            X.next_serial(0xFFFFFFFF, 'increment', NOW)

    def test_one_line_soa_and_crlf(self):
        z = '@ 3600 IN SOA ns. host. 7 1 1 1 1\r\n@ IN NS ns.\r\n'
        new, _c, old, serial = X.edit_zone_text(z, 'x.example.org', 'v', 60, 'add', now=NOW)
        self.assertEqual((old, serial), (7, 8))
        self.assertTrue(new.endswith('x.example.org. 60 IN TXT "v" ; acme-challenge\r\n'))
        back, _c, _o, _s = X.edit_zone_text(new, 'x.example.org', 'v', 60, 'del', now=NOW)
        self.assertEqual(back, z.replace(' 7 ', ' 9 '))

    def test_refused(self):
        for text, why in (('$INCLUDE /etc/bind/other.db\n' + ZONE, '$INCLUDE'),
                          (ZONE + ZONE.split('\n', 2)[2], '2 SOA'),
                          ('@ IN NS ns.\n', 'no SOA'),
                          (ZONE.replace('300 )', '300'), '"(" that does not end'),
                          ('\0\0raw' + ZONE, 'not a text file'),
                          (ZONE.replace('2026010103', 'x2026'), 'not a plain number'),
                          (ZONE + 'a TXT "open\n', 'over two lines')):
            with self.assertRaises(PluginError) as e:
                X.edit_zone_text(text, self.FQDN, 'v', 60, 'add', path='/var/named/z')
            self.assertIn(why, str(e.exception))
            self.assertIn('use a dynamic zone (nsupdate)', str(e.exception))
        with self.assertRaises(PluginError):
            X.edit_zone_text(ZONE, self.FQDN, 'bad"value', 60, 'add')
        with self.assertRaises(PluginError):
            X.edit_zone_text(ZONE, 'evil;name', 'v', 60, 'add')

    def test_dnsmasq_text(self):
        t, c = X.edit_dnsmasq_text('', 'x.lan.example.com', 'v1', 'add')
        self.assertEqual(t, X.DNSMASQ_HEAD + '\ntxt-record=x.lan.example.com,"v1"\n')
        t2, c2 = X.edit_dnsmasq_text(t, 'x.lan.example.com', 'v1', 'add')
        self.assertEqual((t2, c2), (t, False))
        t3, _c = X.edit_dnsmasq_text(t, 'x.lan.example.com', 'v2', 'add')
        t4, c4 = X.edit_dnsmasq_text(t3, 'x.lan.example.com', 'v1', 'del')
        self.assertTrue(c4)
        self.assertEqual(t4, X.DNSMASQ_HEAD + '\ntxt-record=x.lan.example.com,"v2"\n')


class TestWriteScript(unittest.TestCase):
    """The script that puts a file in place, run here by sh."""
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-sshdns-')
        self.f = os.path.join(self.d, 'db.example.org')
        with open(self.f, 'w') as fh:
            fh.write(ZONE)
        os.chmod(self.f, 0o640)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_script(self, content, sha, check=None, reload=None, check_after=False):
        s = X.write_script(self.f, content, sha, check=check, reload=reload,
                           check_after=check_after)
        p = subprocess.run(['sh', '-s'], input=s.encode(), capture_output=True, timeout=30)
        return p.returncode, p.stderr.decode()

    def read(self):
        with open(self.f) as fh:
            return fh.read()

    def test_written_checked_kept(self):
        new = ZONE + 'x 60 IN TXT "v" ; acme-challenge\n'
        rc, err = self.run_script(new, X.sha256(ZONE), check='grep -q acme-challenge "$t"',
                                  reload='true')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.read(), new)
        self.assertEqual(oct(os.stat(self.f).st_mode & 0o777), '0o640')
        with open(os.path.join(self.d, '.db.example.org.acme-bak')) as fh:
            self.assertEqual(fh.read(), ZONE)
        self.assertEqual(sorted(os.listdir(self.d)), ['.db.example.org.acme-bak', 'db.example.org'])

    def test_check_refuses(self):
        rc, err = self.run_script(ZONE + 'junk\n', X.sha256(ZONE), check='false', reload='true')
        self.assertEqual(rc, 6)
        self.assertIn('the check refused', err)
        self.assertEqual(self.read(), ZONE)
        self.assertNotIn('.db.example.org.acme-new', os.listdir(self.d))

    def test_reload_fails_old_back(self):
        rc, err = self.run_script(ZONE + 'x\n', X.sha256(ZONE), check='true', reload='false')
        self.assertEqual(rc, 7, err)
        self.assertIn('the file is back as it was', err)
        self.assertEqual(self.read(), ZONE)

    def test_changed_meanwhile(self):
        rc, err = self.run_script(ZONE + 'x\n', X.sha256('something else'), check='true',
                                  reload='true')
        self.assertEqual(rc, 4)
        self.assertIn('changed by something else', err)
        self.assertEqual(self.read(), ZONE)

    def test_not_a_plain_file(self):
        os.unlink(self.f)
        os.symlink('/etc/passwd', self.f)
        rc, err = self.run_script('x\n', X.sha256('x'), check='true', reload='true')
        self.assertEqual(rc, 3)
        self.assertTrue(os.path.islink(self.f))

    def test_new_file_and_check_after(self):
        os.unlink(self.f)
        rc, err = self.run_script('txt-record=a,"b"\n', None, check='false', check_after=True)
        self.assertEqual(rc, 6)
        self.assertFalse(os.path.exists(self.f))                # it was not there: not left
        rc, err = self.run_script('txt-record=a,"b"\n', None, check='true', reload='true',
                                  check_after=True)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.read(), 'txt-record=a,"b"\n')

    def test_heredoc_cannot_be_escaped(self):
        nasty = ZONE + "ACME_EOF\n$(touch %s/pwned)\n`touch %s/pwned2`\n'\n" % (self.d, self.d)
        rc, err = self.run_script(nasty, X.sha256(ZONE), check='true', reload='true')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.read(), nasty)
        self.assertFalse(os.path.exists(os.path.join(self.d, 'pwned')))
        self.assertFalse(os.path.exists(os.path.join(self.d, 'pwned2')))


# ---------------------------------------------------------------------------
# What each way of writing sends
# ---------------------------------------------------------------------------
class TestWriting(unittest.TestCase):
    def test_zone_pick_longest_suffix(self):
        m = module({'zones': ['example.com', 'sub.example.com', 'example.net']})
        self.assertEqual(m.zone_for('_acme-challenge.a.sub.example.com'), 'sub.example.com')
        self.assertEqual(m.zone_for('_acme-challenge.www.example.com'), 'example.com')
        m = module({'zones': 'example.com\nsub.example.com', 'zone': 'example.com'})
        self.assertEqual(m.zone_for('_acme-challenge.a.sub.example.com'), 'example.com')
        m = module({'flavour': 'nsd', 'zone_files': ['example.org /etc/nsd/example.org.zone',
                                                     'in.example.org /etc/nsd/in.zone']})
        self.assertEqual(m.zone_for('_acme-challenge.x.in.example.org'), 'in.example.org')
        self.assertEqual(m.zone_files(), {'example.org': '/etc/nsd/example.org.zone',
                                          'in.example.org': '/etc/nsd/in.zone'})

    def test_nsupdate_unchanged(self):
        w = World([(r'^nsupdate', (0, '', ''))])
        m = module({'zone': 'example.com', 'sudo': True}, w)
        m.present('www.example.com', 't', 'k', 'v1')
        self.assertEqual(w.commands, ['sudo -n nsupdate -l'])
        w2 = World([(r'^nsupdate', (0, '', ''))])
        module({'zone': 'example.com', 'session_key': '/var/named/session.key'},
               w2).present('www.example.com', 't', 'k', 'v1')
        self.assertEqual(w2.commands, ['nsupdate -l -k /var/named/session.key'])

    def test_pdnsutil(self):
        listing = {'text': PDNS_LIST}
        w = World([(r'^pdnsutil list-zone example.com$', lambda c, i, s: (0, listing['text'], '')),
                   (r'^pdnsutil ', (0, 'New rrset:\n', ''))])
        m = module({'flavour': 'pdnsutil', 'sudo': True, 'zones': 'example.com'}, w)
        h = m.present('www.example.com', 't', 'k', 'v1')
        cores = [X.read_only_core(c) for c in w.commands]
        self.assertEqual(cores, [
            'pdnsutil list-zone example.com',
            'pdnsutil add-record example.com _acme-challenge.www TXT 300 \'"v1"\'',
            'pdnsutil increase-serial example.com', 'pdnsutil rectify-zone example.com'])
        self.assertTrue(all(c.startswith(X.PATH_PRE + 'sudo -n pdnsutil') for c in w.commands))
        # there already: nothing more
        listing['text'] = PDNS_LIST + '_acme-challenge.www.example.com\t300\tIN\tTXT\t"v1"\n'
        w.commands[:] = []
        m.present('www.example.com', 't', 'k', 'v1')
        self.assertEqual(len(w.commands), 1)
        # taken away: the other value stays
        w.commands[:] = []
        m.cleanup('www.example.com', h)
        self.assertEqual(X.read_only_core(w.commands[1]), 'pdnsutil replace-rrset example.com '
                         '_acme-challenge.www TXT 300 \'"someone-else"\'')
        # the last one: the RRset goes
        listing['text'] = '_acme-challenge.x.example.com\t60\tIN\tTXT\t"v2"\n'
        w.commands[:] = []
        m.del_txt('_acme-challenge.x.example.com', 'v2', None)
        self.assertEqual(X.read_only_core(w.commands[1]),
                         'pdnsutil delete-rrset example.com _acme-challenge.x TXT')

    def test_pdns_api(self):
        seen = []

        def curl(core, stdin, sudo):
            seen.append((core, stdin.decode()))
            if 'request = "PATCH"' in stdin.decode():
                return 0, '\n204', ''
            return 0, json.dumps({'name': 'example.com.', 'dnssec': False, 'rrsets': [
                {'name': '_acme-challenge.www.example.com.', 'type': 'TXT', 'ttl': 300,
                 'records': [{'content': '"someone-else"', 'disabled': False}]}]}) + '\n200', ''
        w = World([(r'^curl ', curl)])
        m = module({'flavour': 'pdns_api', 'pdns_api_key': 's3cr"et', 'zones': 'example.com'}, w)
        m.present('www.example.com', 't', 'k', 'v1')
        self.assertNotIn('s3cr', ' '.join(w.commands))
        get, patch = seen
        self.assertIn("http://127.0.0.1:8081/api/v1/servers/localhost/zones/example.com.?rrsets="
                      "true&rrset_name=_acme-challenge.www.example.com.&rrset_type=TXT", get[0])
        self.assertIn('header = "X-API-Key: s3cr\\"et"', get[1])
        body = re.search(r'^data = (".*")$', patch[1], re.M).group(1)
        rr = json.loads(json.loads(body))['rrsets'][0]
        self.assertEqual((rr['changetype'], [r['content'] for r in rr['records']], rr['ttl']),
                         ('REPLACE', ['"someone-else"', '"v1"'], 300))

    def test_knot(self):
        reads = {'out': '[example.com.] _acme-challenge.www.example.com. 300 TXT "someone-else"\n'}
        w = World([(r'^knotc zone-read', lambda c, i, s: (0, reads['out'], '')),
                   (r'^knotc zone-set .*"bad"', (1, '', 'error: (malformed data)')),
                   (r'^knotc ', (0, 'OK\n', ''))])
        m = module({'flavour': 'knot', 'zones': 'example.com'}, w)
        m.add_txt('_acme-challenge.www.example.com', 'v1')
        self.assertEqual([X.read_only_core(c) for c in w.commands], [
            'knotc zone-read example.com _acme-challenge.www.example.com. TXT',
            'knotc zone-begin example.com',
            "knotc zone-set example.com _acme-challenge.www.example.com. 300 TXT '\"v1\"'",
            'knotc zone-commit example.com'])
        w.commands[:] = []
        reads['out'] += '[example.com.] _acme-challenge.www.example.com. 300 TXT "v1"\n'
        m.add_txt('_acme-challenge.www.example.com', 'v1')
        self.assertEqual(len(w.commands), 1)
        m.del_txt('_acme-challenge.www.example.com', 'v1', None)
        self.assertEqual(X.read_only_core(w.commands[-2]), "knotc zone-unset example.com "
                         "_acme-challenge.www.example.com. TXT '\"v1\"'")
        w.commands[:] = []
        with self.assertRaises(PluginError):
            m.add_txt('_acme-challenge.www.example.com', 'bad')
        self.assertEqual(X.read_only_core(w.commands[-1]), 'knotc zone-abort example.com')

    def test_unbound(self):
        data = {'out': '_acme-challenge.x.intra.example.com.\t300\tIN\tTXT\t"keep"\n'
                       '_acme-challenge.x.intra.example.com.\t300\tIN\tTXT\t"v1"\n'
                       'www.intra.example.com.\t300\tIN\tA\t192.0.2.5\n'}
        w = World([(r'^unbound-control list_local_data$', lambda c, i, s: (0, data['out'], '')),
                   (r'^unbound-control ', (0, 'ok\n', ''))])
        m = module({'flavour': 'unbound'}, w)
        m.add_txt('_acme-challenge.x.intra.example.com', 'v1')
        self.assertEqual(len(w.commands), 1)
        m.del_txt('_acme-challenge.x.intra.example.com', 'v1', None)
        self.assertEqual([X.read_only_core(c) for c in w.commands[2:]], [
            'unbound-control local_data_remove _acme-challenge.x.intra.example.com.',
            "unbound-control local_data '_acme-challenge.x.intra.example.com. 300 IN TXT "
            "\"keep\"'"])

    def test_zone_file_flow(self):
        files = {'/var/named/example.org.zone': ZONE}
        scripts = []

        def cat(core, i, s):
            return 0, files[core.split()[-1]], ''

        def sh(core, stdin, s):
            scripts.append((s, stdin.decode()))
            return 0, 'acme: written', ''
        w = World([(r'^cat -- ', cat), (r'^test -e .*\.jnl$', (1, '', '')),
                   (r'^sh -s$', sh)])
        m = module({'flavour': 'bind_file', 'sudo': True,
                    'zone_files': 'example.org /var/named/example.org.zone',
                    'rndc': 'rndc -c /etc/rndc.conf'}, w)
        m.add_txt('_acme-challenge.www.example.org', 'v1')
        sudo, script = scripts[0]
        self.assertTrue(sudo)
        self.assertIn('sudo -n sh -s', w.commands)
        self.assertIn('named-checkzone example.org "$t"', script)
        self.assertIn('rndc -c /etc/rndc.conf reload example.org', script)
        self.assertIn('_acme-challenge.www.example.org. 60 IN TXT "v1" ; acme-challenge', script)
        self.assertIn(X.sha256(ZONE), script)
        self.assertNotIn('freeze', ' '.join(w.commands))

    def test_zone_file_dynamic_frozen_and_thawed(self):
        def sh(core, stdin, s):
            return 6, '', 'zone example.org/IN: has no NS records'
        w = World([(r'^cat -- ', (0, ZONE, '')), (r'^test -e .*\.jnl$', (0, '', '')),
                   (r'^sh -s$', sh), (r'^rndc ', (0, '', ''))])
        m = module({'flavour': 'bind_file', 'zone_files': 'example.org /var/named/example.org.zone'},
                   w)
        with self.assertRaises(PluginError) as e:
            m.add_txt('_acme-challenge.www.example.org', 'v1')
        self.assertIn('has no NS records', str(e.exception))
        cores = [X.read_only_core(c) for c in w.commands]
        self.assertEqual(cores[1], 'rndc freeze example.org')
        self.assertEqual(cores[-1], 'rndc thaw example.org')
        w2 = World([(r'^test -e .*\.jnl$', (0, '', ''))])
        with self.assertRaises(PluginError) as e:
            module({'flavour': 'bind_file', 'bind_freeze': False,
                    'zone_files': 'example.org /var/named/example.org.zone'},
                   w2).add_txt('_acme-challenge.www.example.org', 'v1')
        self.assertIn('use nsupdate', str(e.exception))

    def test_unsafe_settings_refused(self):
        for cfg in ({'flavour': 'bind_file', 'zone_files': 'example.org /var/named/x;rm -rf /'},
                    {'flavour': 'bind_file', 'zone_files': 'example.org ../../etc/passwd'},
                    {'flavour': 'bind_file', 'zone_files': 'example.org /var/named/x',
                     'rndc': 'rndc; reboot'},
                    {'flavour': 'dnsmasq', 'dnsmasq_file': '/etc/dnsmasq.d/x.sh'},
                    {'flavour': 'dnsmasq', 'dnsmasq_reload': 'systemctl restart dnsmasq && id'},
                    {'flavour': 'pdns_api', 'pdns_api_key': 'k',
                     'pdns_api_url': "http://x/'$(id)'"}):
            w = World([(r'^cat -- ', (0, ZONE, '')), (r'^test ', (1, '', '')),
                       (r'^sh -s$', (0, '', '')), (r'^curl', (0, '{}\n200', ''))])
            with self.assertRaises(PluginError, msg=cfg):
                module(dict(cfg, zones='example.org'), w).add_txt(
                    '_acme-challenge.www.example.org', 'v1')
            self.assertNotIn('sh -s', w.commands, cfg)

    def test_test_is_read_only(self):
        w = World([(r'^cat -- ', (0, ZONE, '')), (r'^(named-checkzone|rndc status)', (0, 'OK',
                                                                                       ''))])
        said = module({'flavour': 'bind_file', 'zone_files': 'example.org /var/named/z'},
                      w).test()
        self.assertIn('serial 2026010103', said)
        for c in w.commands:
            self.assertIsNone(re.search(r'sh -s|freeze|reload|add-record', c), c)
        w = World([(r'^nsupdate -V', (0, 'nsupdate 9.18', ''))])
        self.assertIn('a dry run', module({}, w).test())

    def test_describe(self):
        d = SshDns.describe()
        keys = [f['key'] for f in d['fields']]
        self.assertEqual(len(keys), len(set(keys)))
        flav = [o[0] for o in [f for f in d['fields'] if f['key'] == 'flavour'][0]['options']]
        self.assertEqual(flav, ['nsupdate_local', 'nsupdate_key', 'bind_file', 'pdnsutil',
                                'pdns_api', 'knot', 'nsd', 'dnsmasq', 'unbound', 'powershell',
                                'custom'])
        for f in d['fields']:
            v = (f.get('show_if') or {}).get('flavour')
            if v:
                self.assertTrue(set(v) <= set(flav), f['key'])
        self.assertEqual(d['actions'][0]['key'], 'discover')
        self.assertFalse(d['actions'][0]['changes'])

    def test_czech(self):
        with open(os.path.join(os.path.dirname(HERE), 'web', 'lang', 'cs.json'),
                  encoding='utf-8') as f:
            got = json.load(f)
        cs = {v['source'] for v in got['strings'].values() if v.get('text')}
        d = SshDns.describe()
        want = [d['title'], d['description']] + [x for fl in d['fields'] for x in (
            [fl['label'], fl.get('help')] + [o[1] for o in fl.get('options') or []])] + [
            x for a in d['actions'] for x in (a['label'], a['help'])]
        self.assertEqual([s for s in want if s and s not in cs], [])
        with open(os.path.join(os.path.dirname(HERE), 'web', 'assets', 'certs.js'),
                  encoding='utf-8') as f:
            js = f.read()
        part = js[js.index('function sshDnsHere'):js.index('function persistHere')]
        words = re.findall(r"el\('(?:p|b|h4|span|th|summary)', '[^']*', '([^']+)'\)", part)
        words += re.findall(r"cmdButton\('([^']+)'", part)
        words += re.findall(r"\['(Server|Suggested|Signed in as|sudo -n)'", part)
        self.assertGreater(len(words), 10)
        self.assertEqual([w for w in words if w not in cs and re.search('[a-z]', w)], [])
        pats = {v['source'] for v in got['patterns'].values() if v.get('text')}
        for p in ('Filled in: {0} - save the validation to keep it.',
                  '{0} is not a zone file acme edits safely ({1}) - use a dynamic zone (nsupdate) '
                  'for it instead'):
            self.assertIn(p, pats)


# ---------------------------------------------------------------------------
# The real servers, over a "SSH" that runs on this machine
# ---------------------------------------------------------------------------
class LocalSsh(SshSession):
    """ctx.ssh(): the command run here by sh, as the real session gives it (text)."""
    log = []

    def __init__(self, world, conn):
        self.world = world

    def run(self, command, input=None, timeout=120, check=True):
        LocalSsh.log.append(command)
        if isinstance(input, str):
            input = input.encode()
        p = subprocess.run(['sh', '-c', command], input=input, capture_output=True,
                           timeout=timeout)
        out, err = p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')
        if check and p.returncode:
            raise PluginError('%s ended with %d: %s' % (command, p.returncode, err))
        return p.returncode, out, err


def have(*progs):
    return all(shutil.which(p) or os.path.exists('/usr/sbin/' + p) for p in progs)


def port_free(port, host='127.0.0.1'):
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        s = socket.socket(socket.AF_INET, kind)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
        except OSError:
            return False
        finally:
            s.close()
    return True


def dig(port, name):
    """The TXT values at name, asked of 127.0.0.1:port - by dig where it is here."""
    if shutil.which('dig'):
        p = subprocess.run(['dig', '+short', '+norec', '-p', str(port), '@127.0.0.1', name, 'TXT'],
                           capture_output=True, timeout=15)
        return sorted(x.strip().strip('"') for x in p.stdout.decode().splitlines() if x.strip())
    return sorted(D.txt_at('127.0.0.1', name, port=port))


def wait_for(fn, s=8.0):
    end = time.time() + s
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:                               # noqa: BLE001
            pass
        time.sleep(0.2)
    return False


ZTEXT = '''$TTL 300
@ IN SOA ns1.%(z)s. hostmaster.%(z)s. ( 2026010101 ; serial
   3600 600 86400 300 )
  IN NS ns1
ns1 IN A 127.0.0.1
www IN A 192.0.2.10
_acme-challenge.www IN TXT "someone-else"
'''


def real_module(cfg):
    return module(dict(cfg, user='root'), None, LocalSsh)


def roundtrip(tc, m, port, name, label):
    """present -> seen by the server -> cleanup -> gone; the other value stays."""
    rr = '_acme-challenge.' + name
    h = m.present(name, 't', 'k', 'acme-' + label)
    tc.assertTrue(wait_for(lambda: 'acme-' + label in dig(port, rr)), dig(port, rr))
    tc.assertIn('someone-else', dig(port, rr))
    m.present(name, 't', 'k', 'acme-' + label)                 # idempotent
    m.cleanup(name, h)
    tc.assertTrue(wait_for(lambda: 'acme-' + label not in dig(port, rr)), dig(port, rr))
    tc.assertEqual(dig(port, rr), ['someone-else'])
    m.cleanup(name, h)                                         # quiet when gone


@unittest.skipUnless(os.geteuid() == 0, 'the real servers need root')
class TestRealServers(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='acme-sshdns-real-')
        self.stops = []
        LocalSsh.log[:] = []

    def tearDown(self):
        for fn in reversed(self.stops):
            try:
                fn()
            except Exception:                           # noqa: BLE001
                pass
        # every server here was started with this directory in its arguments: gone before
        # the next one (a discovery there would see it run)
        left = lambda: subprocess.run(['pgrep', '-f', self.d], capture_output=True).stdout.split()
        if not wait_for(lambda: not left(), 10):
            for pid in left():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except OSError:
                    pass
            wait_for(lambda: not left(), 5)
        shutil.rmtree(self.d, ignore_errors=True)

    def zone(self, name, path=None):
        path = path or os.path.join(self.d, 'db.' + name)
        with open(path, 'w') as f:
            f.write(ZTEXT % {'z': name})
        return path

    def kill_pidfile(self, pidfile):
        def stop():
            try:
                with open(pidfile) as f:
                    os.kill(int(f.read().split()[0]), signal.SIGTERM)
            except (OSError, ValueError):
                pass
            time.sleep(0.3)
        return stop

    # -- BIND: nsupdate -l, and the zone file of a static zone ---------------------------
    @unittest.skipUnless(have('named', 'nsupdate', 'rndc', 'named-checkzone', 'tsig-keygen'),
                         'BIND is not installed')
    def test_bind(self):
        if not port_free(53):
            self.skipTest('port 53 is in use')
        d = self.d
        subprocess.run(['rndc-confgen', '-a', '-c', d + '/rndc.key', '-k', 'rndc-key'],
                       capture_output=True, check=True)
        with open(d + '/rndc.conf', 'w') as f:
            f.write('include "%s/rndc.key";\noptions { default-key "rndc-key"; default-server '
                    '127.0.0.1; default-port 9953; };\n' % d)
        self.zone('dyn.test')
        static = self.zone('static.test')
        with open(d + '/named.conf', 'w') as f:
            f.write('include "%(d)s/rndc.key";\noptions { directory "%(d)s"; listen-on port 53 '
                    '{ 127.0.0.1; }; listen-on-v6 { none; }; pid-file "%(d)s/named.pid"; '
                    'session-keyfile "%(d)s/session.key"; recursion no; dnssec-validation no; };\n'
                    'controls { inet 127.0.0.1 port 9953 allow { 127.0.0.1; } keys { "rndc-key";'
                    ' }; };\nzone "dyn.test" { type primary; file "db.dyn.test"; update-policy '
                    'local; };\nzone "static.test" { type primary; file "db.static.test"; };\n'
                    % {'d': d})
        p = subprocess.run(['named', '-c', d + '/named.conf', '-u', 'root'], capture_output=True)
        if p.returncode:
            self.skipTest('named would not start: %s' % p.stderr.decode()[-200:])
        self.stops.append(lambda: subprocess.run(['rndc', '-c', d + '/rndc.conf', 'stop'],
                                                 capture_output=True, timeout=15))
        self.stops.append(self.kill_pidfile(d + '/named.pid'))
        self.assertTrue(wait_for(lambda: os.path.exists(d + '/session.key') and
                                 dig(53, 'www.static.test') == []))
        # discovery, for real: read-only, and what it says is what is there
        def rb(f):
            with open(os.path.join(d, f), 'rb') as fh:
                return fh.read()
        before = {f: rb(f) for f in os.listdir(d) if f.startswith('db.') or
                  f.endswith(('.conf', '.key'))}
        got = real_module({'named_conf': d + '/named.conf'}).discover()
        assert_read_only(self, LocalSsh.log)
        after = {f: rb(f) for f in before}
        self.assertEqual(before, after)
        self.assertEqual((got['server'], got['flavour_suggested']), ('BIND', 'nsupdate_local'))
        self.assertEqual(got['fields']['session_key'], d + '/session.key')
        z = {x['name']: x for x in got['zones']}
        self.assertEqual(z['static.test']['flavour'], 'bind_file')
        self.assertEqual(z['static.test']['file'], static)
        # nsupdate -l with the session key
        m = real_module(dict(got['fields'], zone=''))
        self.assertIn('a dry run', m.test())
        roundtrip(self, m, 53, 'www.dyn.test', 'nsupd')
        # the zone file of the static zone
        m = real_module({'flavour': 'bind_file', 'zone_files': 'static.test ' + static,
                         'rndc': 'rndc -c %s/rndc.conf' % d})
        self.assertIn('serial 2026010101', m.test())
        h = m.present('www.static.test', 't', 'k', 'acme-file')
        with open(static) as f:
            text = f.read()
        self.assertIn('"acme-file" ; acme-challenge', text)
        serial = X.find_serial(text)[0]
        self.assertGreater(serial, 2026010101)
        self.assertTrue(wait_for(lambda: 'acme-file' in dig(53, '_acme-challenge.www.static.test')))
        m.cleanup('www.static.test', h)
        self.assertTrue(wait_for(lambda: dig(53, '_acme-challenge.www.static.test') ==
                                 ['someone-else']))
        with open(static) as f:
            back = f.read()
        self.assertEqual(back, (ZTEXT % {'z': 'static.test'}).replace(
            '2026010101', str(X.find_serial(back)[0])))
        self.assertTrue(os.path.exists(os.path.join(d, '.db.static.test.acme-bak')))
        # a zone file named-checkzone refuses: nothing changed, the old one serves on
        with open(static, 'a') as f:
            f.write('bad IN CNAME www\nbad IN A 192.0.2.9\n')
        with self.assertRaises(PluginError) as e:
            m.present('www.static.test', 't', 'k', 'acme-refused')
        self.assertIn('the check refused', str(e.exception))
        with open(static) as f:
            self.assertNotIn('acme-refused', f.read())
        # the dry run of the framework, against it: put in, seen, taken away
        m = real_module(dict(got['fields'], zone='', propagation='auth', resolvers=['127.0.0.1'],
                             public_resolvers=['127.0.0.1']))
        res = m.dry_run('www.dyn.test', wait=10)
        self.assertTrue(res['ok'], res)
        self.assertEqual([s['key'] for s in res['steps']], ['present', 'ready', 'authoritative',
                                                             'public'])
        self.assertEqual(dig(53, '_acme-challenge.www.dyn.test'), ['someone-else'])

    # -- Knot ------------------------------------------------------------------------
    @unittest.skipUnless(have('knotd', 'knotc'), 'Knot is not installed')
    def test_knot(self):
        port = 5354
        if not port_free(port):
            self.skipTest('port %d is in use' % port)
        d = self.d
        os.mkdir(d + '/db')
        self.zone('knot.test', d + '/knot.test.zone')
        with open(d + '/knot.conf', 'w') as f:
            f.write('server:\n    rundir: "%(d)s"\n    listen: 127.0.0.1@%(p)d\ndatabase:\n'
                    '    storage: "%(d)s/db"\ncontrol:\n    listen: "%(d)s/knot.sock"\n'
                    'template:\n  - id: default\n    storage: "%(d)s"\n    file: "%%s.zone"\n'
                    'zone:\n  - domain: knot.test\n' % {'d': d, 'p': port})
        p = subprocess.run(['knotd', '-c', d + '/knot.conf', '-d'], capture_output=True)
        if p.returncode:
            self.skipTest('knotd would not start')
        self.stops.append(lambda: subprocess.run(['knotc', '-s', d + '/knot.sock', 'stop'],
                                                 capture_output=True, timeout=15))
        self.assertTrue(wait_for(lambda: dig(port, '_acme-challenge.www.knot.test') ==
                                 ['someone-else']))
        cfg = {'knot_conf': d + '/knot.conf', 'knot_socket': d + '/knot.sock'}
        got = real_module(cfg).discover()
        assert_read_only(self, LocalSsh.log)
        self.assertEqual(got['fields']['zones'], ['knot.test'])
        m = real_module(dict(cfg, **got['fields']))
        self.assertIn('knot.test', m.test())
        roundtrip(self, m, port, 'www.knot.test', 'knot')

    # -- NSD ---------------------------------------------------------------------------
    @unittest.skipUnless(have('nsd', 'nsd-control', 'nsd-checkzone', 'nsd-checkconf'),
                         'NSD is not installed')
    def test_nsd(self):
        port = 5355
        if not port_free(port):
            self.skipTest('port %d is in use' % port)
        d = self.d
        self.zone('nsd.test', d + '/nsd.test.zone')
        with open(d + '/nsd.conf', 'w') as f:
            f.write('server:\n    ip-address: 127.0.0.1@%(p)d\n    zonesdir: "%(d)s"\n'
                    '    pidfile: "%(d)s/nsd.pid"\n    database: ""\n    xfrdfile: '
                    '"%(d)s/xfrd.state"\n    zonelistfile: "%(d)s/zone.list"\n    username: ""\n'
                    '    chroot: ""\nremote-control:\n    control-enable: yes\n'
                    '    control-interface: %(d)s/nsd.ctl\nzone:\n    name: nsd.test\n'
                    '    zonefile: nsd.test.zone\n' % {'d': d, 'p': port})
        p = subprocess.run(['nsd', '-c', d + '/nsd.conf'], capture_output=True)
        if p.returncode:
            self.skipTest('nsd would not start')
        self.stops.append(lambda: subprocess.run(['nsd-control', '-c', d + '/nsd.conf', 'stop'],
                                                 capture_output=True, timeout=15))
        self.assertTrue(wait_for(lambda: dig(port, '_acme-challenge.www.nsd.test') ==
                                 ['someone-else']))
        got = real_module({'nsd_conf': d + '/nsd.conf'}).discover()
        assert_read_only(self, LocalSsh.log)
        self.assertEqual(got['fields'].get('zone_files'), ['nsd.test %s/nsd.test.zone' % d], got)
        m = real_module(dict(got['fields'], nsd_conf=d + '/nsd.conf'))
        self.assertIn('serial 2026010101', m.test())
        roundtrip(self, m, port, 'www.nsd.test', 'nsd')

    # -- PowerDNS ------------------------------------------------------------------------
    @unittest.skipUnless(have('pdns_server', 'pdnsutil', 'sqlite3') and os.path.exists(
        '/usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql'), 'PowerDNS (sqlite3) is '
                                                                      'not installed')
    def test_powerdns(self):
        port, api = 5356, 18091
        if not port_free(port) or not port_free(api):
            self.skipTest('ports in use')
        d = self.d
        with open('/usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql', 'rb') as f:
            subprocess.run(['sqlite3', d + '/pdns.sqlite3'], input=f.read(), check=True)
        with open(d + '/pdns.conf', 'w') as f:
            f.write('launch=gsqlite3\ngsqlite3-database=%(d)s/pdns.sqlite3\ngsqlite3-dnssec=yes\n'
                    'local-address=127.0.0.1\nlocal-port=%(p)d\nsocket-dir=%(d)s\napi=yes\n'
                    'api-key=test-key\nwebserver=yes\nwebserver-address=127.0.0.1\n'
                    'webserver-port=%(a)d\ncache-ttl=0\nnegquery-cache-ttl=0\nquery-cache-ttl=0\n'
                    % {'d': d, 'p': port, 'a': api})
        pu = ['pdnsutil', '--config-dir=' + d]
        subprocess.run(pu + ['create-zone', 'pdns.test', 'ns1.pdns.test'], capture_output=True,
                       check=True)
        subprocess.run(pu + ['add-record', 'pdns.test', '_acme-challenge.www', 'TXT', '300',
                             '"someone-else"'], capture_output=True, check=True)
        srv = subprocess.Popen(['pdns_server', '--config-dir=' + d, '--daemon=no',
                                '--guardian=no', '--disable-syslog', '--write-pid=no'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.stops.append(lambda: (srv.terminate(), srv.wait(10)))
        if not wait_for(lambda: dig(port, '_acme-challenge.www.pdns.test') == ['someone-else']):
            self.skipTest('pdns_server would not answer')
        got = real_module({'pdns_config_dir': d}).discover()
        assert_read_only(self, LocalSsh.log)
        self.assertEqual(got['fields']['zones'], ['pdns.test'])
        self.assertEqual([s.get('api') for s in got['servers'] if s['server'] == 'PowerDNS'],
                         ['http://127.0.0.1:%d' % api])
        m = real_module(dict(got['fields']))
        self.assertIn('pdns.test', m.test())
        roundtrip(self, m, port, 'www.pdns.test', 'pdnsutil')
        if shutil.which('curl'):
            m = real_module({'flavour': 'pdns_api', 'pdns_api_url': 'http://127.0.0.1:%d' % api,
                             'pdns_api_key': 'test-key', 'zones': 'pdns.test'})
            self.assertIn('pdns.test', m.test())
            roundtrip(self, m, port, 'www.pdns.test', 'api')

    # -- Unbound -------------------------------------------------------------------------
    @unittest.skipUnless(have('unbound', 'unbound-control'), 'Unbound is not installed')
    def test_unbound(self):
        port = 5357
        if not port_free(port):
            self.skipTest('port %d is in use' % port)
        d = self.d
        with open(d + '/unbound.conf', 'w') as f:
            f.write('server:\n    interface: 127.0.0.1@%(p)d\n    username: ""\n    chroot: ""\n'
                    '    directory: "%(d)s"\n    pidfile: "%(d)s/unbound.pid"\n'
                    '    use-syslog: no\n    local-zone: "intra.test." static\n'
                    '    local-data: \'_acme-challenge.www.intra.test. 300 IN TXT '
                    '"someone-else"\'\n    local-data: "www.intra.test. 300 IN A 192.0.2.5"\n'
                    'remote-control:\n    control-enable: yes\n    control-interface: '
                    '%(d)s/unbound.ctl\n' % {'d': d, 'p': port})
        p = subprocess.run(['unbound', '-c', d + '/unbound.conf'], capture_output=True)
        if p.returncode:
            self.skipTest('unbound would not start')
        self.stops.append(lambda: subprocess.run(['unbound-control', '-c', d + '/unbound.conf',
                                                  'stop'], capture_output=True, timeout=15))
        self.assertTrue(wait_for(lambda: dig(port, '_acme-challenge.www.intra.test') ==
                                 ['someone-else']))
        got = real_module({'unbound_conf': d + '/unbound.conf'}).discover()
        assert_read_only(self, LocalSsh.log)
        self.assertEqual(got['fields']['zones'], ['intra.test'])
        m = real_module(dict(got['fields'], unbound_conf=d + '/unbound.conf'))
        roundtrip(self, m, port, 'www.intra.test', 'unbound')

    # -- dnsmasq -------------------------------------------------------------------------
    @unittest.skipUnless(have('dnsmasq'), 'dnsmasq is not installed')
    def test_dnsmasq(self):
        port = 5358
        if not port_free(port):
            self.skipTest('port %d is in use' % port)
        d = self.d
        os.mkdir(d + '/d')
        conf = d + '/dnsmasq.conf'
        with open(conf, 'w') as f:
            f.write('port=%(p)d\nlisten-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\n'
                    'pid-file=%(d)s/dnsmasq.pid\nconf-dir=%(d)s/d,*.conf\nlocal=/lan.test/\n'
                    'txt-record=_acme-challenge.www.lan.test,"someone-else"\n'
                    % {'d': d, 'p': port})
        with open(d + '/restart.sh', 'w') as f:
            f.write('[ -f %(d)s/dnsmasq.pid ] && kill $(cat %(d)s/dnsmasq.pid); sleep 0.3\n'
                    'exec dnsmasq -C %(c)s --user=root </dev/null >/dev/null 2>&1\n'
                    % {'d': d, 'c': conf})
        os.chmod(d + '/restart.sh', 0o755)
        subprocess.run(['sh', d + '/restart.sh'], check=True)
        self.stops.append(self.kill_pidfile(d + '/dnsmasq.pid'))
        self.assertTrue(wait_for(lambda: dig(port, '_acme-challenge.www.lan.test') ==
                                 ['someone-else']))
        m = real_module({'flavour': 'dnsmasq', 'dnsmasq_file': d + '/d/acme-challenge.conf',
                         'dnsmasq_conf': conf, 'dnsmasq_reload': d + '/restart.sh',
                         'zones': 'lan.test'})
        self.assertIn('acme\'s lines go in', m.test())
        roundtrip(self, m, port, 'www.lan.test', 'dnsmasq')
        with open(d + '/d/acme-challenge.conf') as f:
            self.assertEqual(f.read(), X.DNSMASQ_HEAD + '\n')
        self.assertEqual(sorted(os.listdir(d + '/d')), ['.acme-challenge.conf.acme-bak',
                                                        'acme-challenge.conf'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
