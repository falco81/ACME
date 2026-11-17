#!/usr/bin/env python3
"""What the agent tells about its server (1.0.120, docs/target-agent.md "What the agent tells
about its server"):

    python3 test/test_agent_system_info.py

* Linux: the facts collected from a layout of /proc, /sys, /etc of the test's own
  (ACME_AGENT_SYS_ROOT) - the OS, kernel, host, CPU, memory, load, boot, time zone, SELinux, the
  init, a newer kernel installed (a restart pending), the known services (their unit files, one
  systemctl is-active of the test's own); the real machine's disks and addresses;
* the facts bounded: each text one line of 200 characters, the lists cut, the whole under
  SYS_MOST; a fact that fails is left out, one that is slow is left out in its time - never the
  hello; the hash leaves out what changes all the time (the clock, the uptime, the memory free);
* Windows (FakeWin, ACME_AGENT_FAKE_WINDOWS=1): the registry's product, edition, version and
  build, the CPU, the memory, the uptime, the AD domain, the roles by their services (IIS
  running, AD CS installed, WinRM with its HTTPS listener, a named SQL Server instance), a restart
  pending by the registry's keys, the system drive and the policy's drives; a failing and a slow
  fact left out;
* acme's cleaning of hostile facts: huge, NaN and Infinity, nested, line breaks, wrong types,
  bad addresses, a disk with more free than its size;
* the skew against acme's clock (the middle of a short hello; an active agent's poll), its
  levels (60 s amber, 120 s red - an alert), the view's warnings (a disk over 85 %, a restart);
  an agent too old to tell;
* a real agent (both processes, as test_target_agent.py has them): a passive one's hello brings
  its server's facts - in info(), GET /api/agents' rows, the command line (show, system,
  system --json) - and an active one's poll its clock; Prometheus and SNMP say the skew and the
  restart pending;
* the pages: test/agents_sysinfo_page.js (node with playwright; skipped without) - the card's
  "The server", the tiles' line, the Servers overview, at 1400 and 390 px, in English and Czech.

Never port 8092 nor PostgreSQL: temporary folders and ports only (test_target_agent's).
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_target_agent as T  # noqa: E402  (its folders, its engine, its agents)

E, G, STORE, AG = T.E, T.G, T.STORE, T.AG
from acmelib.certs import agent_system as AS  # noqa: E402

ROOT = os.path.dirname(HERE)


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fh:
        fh.write(text)
    os.chmod(path, mode)


class Linux(unittest.TestCase):
    """The Linux facts from a layout of the test's own."""

    def setUp(self):
        self.top = tempfile.mkdtemp(prefix='acme-sysinfo-')
        t = lambda p: os.path.join(self.top, p.lstrip('/'))  # noqa: E731
        write(t('/etc/os-release'), 'NAME="Rocky Linux"\nVERSION_ID="9.4"\nID="rocky"\n'
              'ID_LIKE="rhel centos fedora"\nPRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\n')
        write(t('/proc/sys/kernel/osrelease'), '5.14.0-427.13.1.el9_4.x86_64\n')
        write(t('/proc/sys/kernel/hostname'), 'web1\n')
        write(t('/proc/sys/kernel/domainname'), '(none)\n')
        write(t('/proc/cpuinfo'), ''.join('processor\t: %d\nmodel name\t: Intel(R) Xeon(R) '
                                          'Gold 6338 CPU @ 2.00GHz\n\n' % i for i in range(4)))
        write(t('/proc/meminfo'), 'MemTotal:       16000000 kB\nMemFree:  1000 kB\n'
              'MemAvailable:    9000000 kB\n')
        write(t('/proc/loadavg'), '0.42 0.37 0.31 1/234 5678\n')
        write(t('/proc/uptime'), '3600.5 7000.1\n')
        write(t('/proc/stat'), 'cpu 1 2 3\nbtime 1790000000\n')
        write(t('/proc/1/comm'), 'systemd\n')
        write(t('/proc/self/mounts'), '/dev/sda1 / xfs rw 0 0\n')
        write(t('/sys/fs/selinux/enforce'), '1')
        write(t('/sys/class/dmi/id/sys_vendor'), 'VMware, Inc.\n')
        write(t('/sys/class/dmi/id/product_name'), 'VMware7,1\n')
        write(t('/etc/timezone'), 'Europe/Prague\n')
        for k in ('5.14.0-427.13.1.el9_4.x86_64', '5.14.0-503.11.1.el9_5.x86_64'):
            os.makedirs(t('/lib/modules/' + k))
        for u in ('nginx', 'postfix', 'haproxy'):
            write(t('/usr/lib/systemd/system/%s.service' % u), '[Unit]\n')
        # a systemctl of the layout's own: nginx and postfix run, haproxy does not
        write(t('/usr/bin/systemctl'), '#!/bin/sh\nshift 2\nfor u in "$@"; do case "$u" in '
              'haproxy.service) echo inactive;; *) echo active;; esac; done\n', 0o755)
        self.saved = AG.SYS_ROOT, dict(AG._SYS)
        AG.SYS_ROOT = self.top
        AG._SYS.update(at=0.0, facts=None, hash='', cli=(0.0, None))

    def tearDown(self):
        AG.SYS_ROOT = self.saved[0]
        AG._SYS.update(self.saved[1])
        AG._SYS.update(at=0.0, facts=None)
        shutil.rmtree(self.top, ignore_errors=True)

    def test_facts(self):
        pol = AG.parse_policy('allow file %s owner=root:root mode=0644\n' % self.top)
        f = AG.sys_bound(AG.system_facts(pol))
        self.assertEqual(f['platform'], 'linux')
        self.assertEqual(f['os'], 'Rocky Linux 9.4 (Blue Onyx)')
        self.assertEqual((f['os_id'], f['os_version']), ('rocky', '9.4'))
        self.assertEqual(f['kernel'], '5.14.0-427.13.1.el9_4.x86_64')
        self.assertEqual(f['hostname'], 'web1')
        self.assertEqual(f['cpu'], 'Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz')
        self.assertEqual(f['cores'], 4)
        self.assertEqual((f['mem_total'], f['mem_avail']), (16000000 * 1024, 9000000 * 1024))
        self.assertEqual(f['load'], [0.42, 0.37, 0.31])
        self.assertEqual(f['boot'], 1790000000)
        self.assertEqual(f['tz'], 'Europe/Prague')
        self.assertEqual(f['selinux'], 'enforcing')
        self.assertEqual(f['init'], 'systemd')
        self.assertEqual(f['machine'], 'VMware, Inc. VMware7,1')
        self.assertIs(f['reboot'], True)
        self.assertIn('5.14.0-503.11.1.el9_5.x86_64', f['reboot_why'])
        self.assertEqual(sorted(f['services'], key=lambda x: x['name']),
                         [{'name': 'haproxy', 'state': 'present'},
                          {'name': 'nginx', 'state': 'active'},
                          {'name': 'postfix', 'state': 'active'}])
        self.assertTrue(f['python'] and f['openssl'].startswith('OpenSSL'))
        self.assertTrue(f['disks'] and f['disks'][0]['size'] >= f['disks'][0]['free'])
        self.assertTrue(any(d['path'] == '/' for d in f['disks']))
        self.assertNotIn('clock', f)                     # said at the hello, not kept
        # what acme takes of it is all of it
        self.assertEqual(AS.clean(f), {k: v for k, v in f.items()})

    def test_no_restart_and_debian_reboot_required(self):
        shutil.rmtree(os.path.join(self.top, 'lib/modules/5.14.0-503.11.1.el9_5.x86_64'))
        self.assertEqual(AG._sf_reboot_linux('5.14.0-427.13.1.el9_4.x86_64'),
                         {'reboot': False, 'reboot_why': ''})
        write(os.path.join(self.top, 'run/reboot-required'), '*** System restart required ***\n')
        write(os.path.join(self.top, 'run/reboot-required.pkgs'), 'linux-image-6.8.0-48\n')
        got = AG._sf_reboot_linux('5.14.0-427.13.1.el9_4.x86_64')
        self.assertTrue(got['reboot'])
        self.assertIn('linux-image-6.8.0-48', got['reboot_why'])

    def test_info_cached_clock_now_hash_stable(self):
        f1, h1 = AG.system_info()
        time.sleep(0.05)
        f2, h2 = AG.system_info()
        self.assertEqual(h1, h2)
        self.assertEqual(f1['hash'], h1)
        self.assertGreater(f2['clock'], f1['clock'])
        self.assertLess(abs(f2['clock'] - time.time()), 2)
        self.assertGreaterEqual(f2['uptime'], 0)
        # what changes all the time does not change the hash: the clock, the memory free, load
        f3 = dict(f1, clock=1, uptime=5, mem_avail=1, load=[9, 9, 9])
        self.assertEqual(AG.sys_hash(f3), AG.sys_hash(f1))
        # ...a disk filling up by whole percents does, so does a restart pending
        d = [dict(x, free=x['free'] // 2) for x in f1['disks']]
        self.assertNotEqual(AG.sys_hash(dict(f1, disks=d)), AG.sys_hash(f1))
        self.assertNotEqual(AG.sys_hash(dict(f1, reboot=not f1['reboot'])), AG.sys_hash(f1))

    def test_a_failing_and_a_slow_fact_left_out(self):
        orig = AG._sf_hw_linux, AG._linux_addrs, AG.SYS_FACT_S

        def boom():
            raise OSError('no /proc here')

        def slow():
            time.sleep(5)
            return [{'if': 'x', 'ip': '192.0.2.1'}]
        AG._sf_hw_linux, AG._linux_addrs, AG.SYS_FACT_S = boom, slow, 0.5
        try:
            t0 = time.time()
            f = AG.system_facts(None)
            took = time.time() - t0
        finally:
            AG._sf_hw_linux, AG._linux_addrs, AG.SYS_FACT_S = orig
        self.assertLess(took, 3.5)
        for k in ('cpu', 'mem_total', 'boot'):
            self.assertNotIn(k, f)
        self.assertNotIn({'if': 'x', 'ip': '192.0.2.1'}, f.get('addrs') or [])
        self.assertEqual(f['os_id'], 'rocky')           # the rest said
        # the whole collection failing: the hello still answers, its platform said
        orig2 = AG.system_facts
        AG.system_facts = lambda pol=None: 1 / 0
        try:
            got, h = AG.system_info(fresh=True)
        finally:
            AG.system_facts = orig2
        self.assertEqual(got['platform'], 'linux')
        self.assertTrue(h)


class Bounded(unittest.TestCase):
    def test_sizes(self):
        huge = {'os': 'A' * 100000 + '\nB', 'kernel': 'k\x00\x1b[31m\r\nx', 'cores': 2 ** 80,
                'load': [float('nan')] * 50, 'boot': float('inf'),
                'addrs': [{'if': 'eth%d' % i, 'ip': '10.0.0.%d' % (i % 250)} for i in range(5000)],
                'disks': [{'path': '/' + 'd' * 5000, 'size': 10, 'free': 1}] * 300,
                'services': [{'name': 'svc%d' % i, 'state': 'active', 'detail': 'x' * 900}
                             for i in range(900)],
                'nested': {'a': {'b': {'c': {'d': 1}}}}}
        huge.update({'k%d' % i: 'v' * 900 for i in range(200)})
        f = AG.sys_bound(huge)
        raw = json.dumps(f)
        self.assertLessEqual(len(raw), AG.SYS_MOST)
        self.assertLessEqual(len(f.get('os', '')), AG.SYS_TEXT)
        self.assertNotIn('\n', f.get('os', ''))
        self.assertNotIn('\x1b', raw)
        self.assertLessEqual(len(f.get('addrs') or []), 16)
        self.assertNotIn('cores', f)                    # no number that big
        self.assertNotIn('boot', f)


class Windows(unittest.TestCase):
    """The Windows facts (FakeWin): run in a process of their own, as the agent does."""

    def run_fake(self, sysinfo=None, services=None, policy=''):
        top = tempfile.mkdtemp(prefix='acme-sysinfo-win-')
        self.addCleanup(shutil.rmtree, top, True)
        os.makedirs(os.path.join(top, '.fakewin'))
        if sysinfo is not None:
            write(os.path.join(top, '.fakewin', 'sysinfo.json'), json.dumps(sysinfo))
        write(os.path.join(top, '.fakewin', 'services.json'), json.dumps(services or {}))
        os.makedirs(os.path.join(top, 'D'), exist_ok=True)
        code = ('import sys, json, time; sys.path.insert(0, %r); import acme_agent as a; '
                't = time.time(); f = a.sys_bound(a.system_facts(a.parse_policy(%r))); '
                'print(json.dumps({"f": f, "took": time.time() - t}))' % (
                    os.path.join(ROOT, 'deploy', 'agent'), policy))
        got = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True,
                             timeout=60, env=dict(os.environ, ACME_AGENT_FAKE_WINDOWS='1',
                                                  ACME_AGENT_FAKE_ROOT=top))
        self.assertEqual(got.returncode, 0, got.stderr)
        return json.loads(got.stdout.strip().splitlines()[-1])

    def test_facts(self):
        reg = {
            r'SOFTWARE\Microsoft\Windows NT\CurrentVersion': {
                'ProductName': 'Windows Server 2022 Datacenter', 'EditionID': 'ServerDatacenter',
                'DisplayVersion': '21H2', 'CurrentBuild': '20348', 'UBR': 2849,
                'CurrentMajorVersionNumber': 10, 'CurrentMinorVersionNumber': 0,
                'InstallationType': 'Server Core'},
            r'HARDWARE\DESCRIPTION\System\CentralProcessor\0': {
                'ProcessorNameString': 'AMD EPYC 7763 64-Core Processor'},
            r'SYSTEM\CurrentControlSet\Control\TimeZoneInformation': {
                'TimeZoneKeyName': 'W. Europe Standard Time'},
            r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters': {
                'Hostname': 'IIS01', 'Domain': 'corp.example.com'},
            r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment': {
                'PROCESSOR_ARCHITECTURE': 'AMD64'},
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTPS': {},
            r'SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL': {
                'SQLEXPRESS': 'MSSQL16.SQLEXPRESS'},
            r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
            r'\RebootRequired': {},
            r'SYSTEM\CurrentControlSet\Control\Terminal Server': {'fDenyTSConnections': 0}}
        svcs = {'w3svc': {'state': 'Running'}, 'certsvc': {'state': 'Stopped'},
                'winrm': {'state': 'Running'}, 'remoteaccess': {'state': 'Stopped'},
                'mssql$sqlexpress': {'state': 'Running'}, 'termservice': {'state': 'Running'}}
        got = self.run_fake({'reg': reg, 'mem': [32 * 2 ** 30, 5 * 2 ** 30], 'uptime': 86400,
                             'join': ['CORP', 'domain'],
                             'disks': {'C:': [127 * 2 ** 30, 20 * 2 ** 30],
                                       'D:': [500 * 2 ** 30, 400 * 2 ** 30]}}, svcs,
                            'allow file D:\\certs\n')
        f = got['f']
        self.assertEqual(f['platform'], 'windows')
        self.assertEqual(f['os'], 'Windows Server 2022 Datacenter')
        self.assertEqual((f['os_version'], f['edition'], f['build'], f['install']),
                         ('21H2', 'ServerDatacenter', '10.0.20348.2849', 'Server Core'))
        self.assertEqual(f['arch'], 'AMD64')
        self.assertEqual(f['cpu'], 'AMD EPYC 7763 64-Core Processor')
        self.assertEqual((f['mem_total'], f['mem_avail']), (32 * 2 ** 30, 5 * 2 ** 30))
        self.assertLess(abs(f['boot'] - (time.time() - 86400)), 30)
        self.assertEqual((f['hostname'], f['fqdn'], f['domain'], f['ad_domain']),
                         ('IIS01', 'IIS01.corp.example.com', 'corp.example.com', 'CORP'))
        self.assertEqual(f['tz'], 'W. Europe Standard Time')
        self.assertTrue(f['reboot'])
        self.assertIn('Windows Update', f['reboot_why'])
        roles = {(r['name'], r.get('detail', '')): r['state'] for r in f['services']}
        self.assertEqual(roles, {('IIS', ''): 'active', ('AD CS', ''): 'present',
                                 ('WinRM', 'HTTPS listener'): 'active',
                                 ('SQL Server', 'SQLEXPRESS'): 'active',
                                 ('Remote Desktop', ''): 'active'})   # RRAS: not running
        self.assertEqual([d['path'] for d in f['disks']], ['C:\\', 'D:\\'])
        self.assertEqual(f['disks'][0]['free'], 20 * 2 ** 30)
        self.assertEqual(AS.clean(f), f)

    def test_defaults_and_a_failing_and_slow_fact(self):
        f = self.run_fake()['f']                        # the fake's own registry
        self.assertEqual(f['os'], 'Windows Server 2022 Standard')
        self.assertFalse(f['reboot'])
        got = self.run_fake({'fail': ['memory', 'net_join'], 'slow': {'services_states': 20}})
        f = got['f']
        self.assertLess(got['took'], 10)
        self.assertNotIn('mem_total', f)
        self.assertNotIn('ad_domain', f)
        self.assertNotIn('services', f)                 # the slow one left out
        self.assertEqual(f['os'], 'Windows Server 2022 Standard')
        self.assertIn('boot', f)


class Cleaning(unittest.TestCase):
    def test_hostile(self):
        bad = {'os': 'Evil\nLinux\r\n\x1b[2J\u202eX' + 'y' * 5000, 'os_id': ['nested'],
               'kernel': {'a': 1}, 'hostname': 42, 'cores': float('nan'),
               'mem_total': float('inf'), 'mem_avail': -5, 'boot': True, 'uptime': '12',
               'tz_offset': 99999, 'platform': 'solaris', 'selinux': 'maybe',
               'reboot': 'yes', 'clock': float('nan'), 'hash': 'x' * 64, 'unknown': 'z',
               'load': [1, float('nan'), 3],
               'addrs': [{'if': 'eth0\n', 'ip': '10.0.0.1/24'}, {'ip': '999.1.1.1'},
                         {'ip': '<script>'}, {'ip': '2001:db8::1/200'}, 'x', None] * 10,
               'disks': [{'path': '/', 'size': 100, 'free': 500}, {'path': '', 'size': 1,
                                                                   'free': 0},
                         {'path': '/x', 'size': float('nan'), 'free': 1},
                         {'path': '/ok', 'size': 100, 'free': 10, 'fs': 'ext4\nX'}],
               'services': [{'name': 'nginx', 'state': 'evil'}, {'name': ''}, 7,
                            {'name': 'n' * 300, 'state': 'active', 'detail': {'x': 1}}]}
        f = AS.clean(bad)
        self.assertNotIn('\n', f['os'])
        self.assertNotIn('\x1b', f['os'])
        self.assertNotIn('\u202e', f['os'])
        self.assertLessEqual(len(f['os']), 120)
        for k in ('os_id', 'kernel', 'hostname', 'cores', 'mem_total', 'mem_avail', 'boot',
                  'uptime', 'tz_offset', 'platform', 'selinux', 'reboot', 'clock', 'hash',
                  'unknown', 'load'):
            self.assertNotIn(k, f)
        self.assertEqual(f['addrs'][0], {'if': 'eth0', 'ip': '10.0.0.1/24'})
        self.assertIn({'if': '', 'ip': '2001:db8::1'}, f['addrs'])
        self.assertLessEqual(len(f['addrs']), 16)
        self.assertEqual(f['disks'], [{'path': '/ok', 'size': 100, 'free': 10, 'fs': 'ext4 X'}])
        self.assertEqual(f['services'][0], {'name': 'nginx', 'state': 'present'})
        self.assertEqual(len(f['services'][1]['name']), 40)
        self.assertNotIn('detail', f['services'][1])
        for nothing in (None, 'x', [], 5, {}, {'unknown': 1}):
            self.assertIsNone(AS.clean(nothing))
        # in an agent's answer (clean_result): a hostile one is nothing; old acme ignored it
        r = G.clean_result({'ok': True, 'system': 'not an object'})
        self.assertNotIn('system', r)
        r = G.clean_result({'ok': True, 'system': {'os': 'x\ny', 'cores': 4}})
        self.assertEqual(r['system'], {'os': 'x y', 'cores': 4})
        json.dumps(f, allow_nan=False)


class Skew(unittest.TestCase):
    def test_skew_and_view(self):
        self.assertEqual(AS.skew_of(1000.0, 990.0), 10.0)
        for bad in (None, 'x', float('nan'), float('inf'), True, -1, 2 ** 40):
            self.assertIsNone(AS.skew_of(bad, 1000.0))
        self.assertEqual([AS.skew_level(x) for x in (0, 59, -61, 120, 121, -500)],
                         ['ok', 'ok', 'warn', 'warn', 'bad', 'bad'])
        now = time.time()
        st = {}
        AS.seen_hello(st, {'ok': True, 'version': '1.0.121', 'system': {
            'os': 'Rocky', 'clock': now + 100, 'boot': int(now - 3600), 'uptime': 3600,
            'disks': [{'path': '/', 'size': 100, 'free': 3}], 'reboot': True,
            'reboot_why': 'a newer kernel', 'hash': 'a' * 64}}, now - 1, now + 1)
        self.assertAlmostEqual(st['skew'], 100, delta=0.2)
        v = AS.view(st, now + 60)
        self.assertEqual(v['state'], 'ok')
        self.assertEqual(v['skew_level'], 'warn')
        self.assertGreaterEqual(v['uptime'], 3660 - 1)
        self.assertEqual(v['facts']['disks'][0]['used_pct'], 97.0)
        self.assertEqual({w['key']: w['level'] for w in v['warnings']},
                         {'skew': 'warn', 'disk': 'bad', 'reboot': 'warn'})
        # a hello that took long (an active agent's job waiting for its poll): no skew from it
        st2 = {}
        AS.seen_hello(st2, {'ok': True, 'system': {'os': 'x', 'clock': now}}, now - 30, now)
        self.assertNotIn('skew', st2)
        # its poll says it: written when it changes
        self.assertTrue(AS.seen_skew(st2, AS.skew_of(now - 200, now), now))
        self.assertFalse(AS.seen_skew(st2, -199.6, now + 1))
        self.assertEqual(AS.view(st2)['skew_level'], 'bad')
        # the hash an active poll says
        self.assertTrue(AS.asked_for(st, 'b' * 64))
        self.assertFalse(AS.asked_for(st, 'a' * 64))
        self.assertFalse(AS.asked_for(st, 'nonsense'))

    def test_too_old_to_tell(self):
        st = {}
        AS.seen_hello(st, G.clean_result({'ok': True, 'version': '1.0.118', 'os': 'Rocky'}),
                      0, 1)
        self.assertEqual(AS.view(st)['state'], 'old')
        self.assertEqual(AS.lines(AS.view(st)),
                         [('server', 'the agent is too old to tell (update it)')])
        self.assertEqual(AS.view({})['state'], 'unknown')


def cli(name, *what, js=False):
    from acmelib.certs import cli as C
    a = C.Cli.__new__(C.Cli)
    a.store = STORE
    a.json = js
    a.WHO = 'tester'
    buf = io.StringIO()
    with redirect_stdout(buf):
        C.Cli.target_agent(a, [name] + list(what))
    return buf.getvalue()


@unittest.skipUnless(T.CAN, 'needs root, setpriv, openssl')
class RealAgent(unittest.TestCase):
    def test_1_passive_hello(self):
        port = T.free_port()
        row, ag = T.join_passive(self, 'sysinfo1', port)
        try:
            T.www_policy(ag)
            got = G.hello(STORE, row)
            self.assertTrue(got['system']['os'])
            info = G.info(STORE, row)
            sv = info['system']
            self.assertEqual(sv['state'], 'ok', sv)
            f = sv['facts']
            self.assertEqual(f['platform'], 'linux')
            self.assertTrue(f['hostname'] and f['kernel'] and f['python'])
            self.assertTrue(any(d['path'] == '/' for d in f['disks']))
            self.assertLess(abs(sv['skew']), 5)
            self.assertEqual(sv['skew_level'], 'ok')
            self.assertLess(time.time() - sv['at'], 30)
            self.assertTrue(AS.HEX64.match(f['hash']))
            # the API's rows carry it
            rows = [G.info(STORE, r) for r in G.rows(STORE)]
            self.assertTrue(any(r['name'] == 'sysinfo1' and r['system']['facts'] for r in rows))
            # the command line
            show = cli('sysinfo1', 'show')
            self.assertIn('server             %s' % (f.get('fqdn') or f['hostname']), show)
            out = cli('sysinfo1', 'system')
            self.assertIn('kernel', out)
            self.assertIn(f['kernel'], out)
            self.assertIn('clock', out)
            self.assertIn('against acme\'s', out)
            js = json.loads(cli('sysinfo1', 'system', js=True))
            self.assertEqual(js['system']['facts']['hostname'], f['hostname'])
            # the monitoring: the skew, the restart pending
            from acmelib.certs import monitor as MO
            st = G.state(STORE, row['id'])
            st['skew'], st['skew_at'] = -150.0, time.time()
            st['system']['reboot'] = True
            G.state_put(STORE, row['id'], st)
            al = [a for a in G.alerts(STORE) if a['key'] == 'agent-clock:%s' % row['id']]
            self.assertEqual(len(al), 1)
            self.assertIn('150 s behind', al[0]['words'])
            prom = self.prometheus()
            self.assertIn('acme_agent_clock_skew_seconds{target="sysinfo1"} -150', prom)
            self.assertIn('acme_agent_pending_reboot{target="sysinfo1"} 1', prom)
            vals = {tuple(o): v for o, _t, v in MO.snmp_rows(STORE)}
            self.assertEqual(vals[MO.SNMP_AGENTS + (11, row['id'])], -150)
            self.assertEqual(vals[MO.SNMP_AGENTS + (12, row['id'])], 1)
        finally:
            ag.stop()

    def prometheus(self):
        from acmelib.certs import monitor as MO
        out = []
        for name, _help, _kind, samples in MO.metrics(STORE):
            for labels, v in samples:
                out.append('%s{%s} %s' % (name, ','.join('%s="%s"' % kv for kv in
                                                         sorted(labels.items())), v))
        return '\n'.join(out)

    def test_2_active_poll_clock(self):
        E.CONFIG['certs_agents_active'] = 1
        node = T.Wire(STORE)
        E.CONFIG['certs_agents_names'] = '127.0.0.1:%d' % node.port
        row = T.target('sysinfo2', mode='active', host='sysinfo2.example.test')
        code = G.code_new(STORE, row, 'tester')
        ag = T.Agent('sysinfo2')
        try:
            T.www_policy(ag)
            ag.start_root()
            ag.cli('join', code['code'], '--no-wait')
            ag.start_net()
            for _ in range(100):
                if G.info(STORE, row).get('pending'):
                    break
                time.sleep(0.1)
            G.confirm(STORE, row, G.info(STORE, row)['pending']['fp'], 'tester')
            self.assertTrue(ag.wait('joined', 20), ag.status())
            # its polls say its clock (and the hash of its facts: acme asks its hello)
            for _ in range(150):
                st = G.state(STORE, row['id'])
                if st.get('skew') is not None and isinstance(st.get('system'), dict):
                    break
                if not st.get('pending'):
                    G.tick(STORE)
                time.sleep(0.2)
            sv = G.info(STORE, row)['system']
            self.assertIsNotNone(sv['skew'], G.state(STORE, row['id']))
            self.assertLess(abs(sv['skew']), 5)
            self.assertEqual(sv['state'], 'ok')
        finally:
            ag.stop()
            node.stop()
            E.CONFIG['certs_agents_active'] = 0
            E.CONFIG['certs_agents_names'] = ''


class Pages(unittest.TestCase):
    def test_sysinfo_page(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        args = [node, os.path.join(HERE, 'agents_sysinfo_page.js'), os.path.join(ROOT, 'web')]
        # the Czech words: web/lang/cs.json, and (until they are merged into it) a file of them
        extra = os.environ.get('ACME_TEST_CS_EXTRA')
        args.append(extra if extra and os.path.exists(extra) else '')
        if os.environ.get('ACME_TEST_SHOTS'):
            args.append(os.environ['ACME_TEST_SHOTS'])
        got = subprocess.run(args, capture_output=True, text=True, timeout=900)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        bad = [k for k, v in (out.get('checks') or {}).items() if not v]
        self.assertTrue(out.get('ok'), json.dumps({'failed': bad, 'error': out.get('error'),
                                                   'errors': out.get('errors')})
                        + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
