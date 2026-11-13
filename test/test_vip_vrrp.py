#!/usr/bin/env python3
"""The cluster's web address (VIP) moved by real VRRP between two nodes.

    python3 test/test_vip_vrrp.py      (as root; keepalived, ip netns, unshare)

Two network namespaces (acme1, acme2) joined by a veth pair stand for the two
nodes. Each runs, as production does:

  * keepalived, from the file deploy/acme_web.py's ka_conf() writes - the
    request checked by the helper's own checked() first;
  * keepalived's check, deploy/acme-vip-check itself (in place: the repository's
    folders are root's and keepalived's script security takes them);
  * the daemon's side: acme's own vip_watch() (acmelib/engine/245) writing
    /run/acme/vip-state every 3 s, with acme's daemon_lock() in
    /var/lib/acme/acme.lock - in an acme process of the node's own (its own
    SQLite, its own config), maintenance switched with maintenance_set().

acme-vip-check reads /run/acme/vip-state and /var/lib/acme/acme.lock and writes
/run/acme/vip-role by those names, with no override: each keepalived runs in a
mount namespace of its own (unshare -m) where the node's folders are bound on
those two paths.

What only the test changes, and why:
  * the script user: keepalived's file says `script_user acme`; with no acme
    account on the machine (a test box) the file is used with `nobody`
    instead, and the node's acme process runs as that account too, so the
    file modes are those of production (vip-state 0640, its owner's);
  * the check's path (ACME_VIP_CHECK, the helper's own override): the
    repository's deploy/acme-vip-check, not /usr/libexec/keepalived;
  * the daemon's health look at https://127.0.0.1/healthz is off
    (ACME_VIP_HEALTH_URL=none, as the test beds do): no nginx here.

Checked: one node holds the address within seconds, the preferred one; never
both at any moment sampled (every 0.2 s); maintenance moves it to the other,
back (after preempt_delay) when it ends; the preference moved; acme's own
process gone (its lock's pid) moves it; keepalived stopped (SIGTERM) and
killed (SIGKILL) on the holder moves it - the killed one keeps the address on its
interface until keepalived starts again there (acme's systemd drop-in, Restart=on-failure,
after its RestartSec), which takes the stale address away at once; the notify call writes vip-role;
the IPv6 address beside the IPv4 one (virtual_ipaddress_excluded) moves with
it; an IPv6-only pair (VRRPv3, no authentication) does the same - both IPv6 parts left
out on a kernel without IPv6. acme-vip-check's exit codes against what vip_watch() writes;
the alert for a keepalived stopped (its last notify says STOP) and for one killed (no
keepalived in /proc, from the node's health row - a /proc made up); the drop-in vip_part()
writes and takes away (the file alone: no systemd here).

    ACME_VRRP_KEEP=1   the nodes' folders (keepalived's and acme's logs) kept, path printed
"""
import importlib.util
import itertools
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CHECK = os.path.join(ROOT, 'deploy', 'acme-vip-check')
KEEPALIVED = shutil.which('keepalived') or '/usr/sbin/keepalived'
VRID = 51
AUTH = 'Ab3dE6gH'
NODES = ('acme1', 'acme2')
IFACE = 'acmevr0'


def load_helper():
    os.environ['ACME_VIP_NO_SERVICES'] = '1'
    os.environ['ACME_VIP_CHECK'] = CHECK
    spec = importlib.util.spec_from_file_location('acme_web_vrrp', os.path.join(
        ROOT, 'deploy', 'acme_web.py'))
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)
    return W


def script_user():
    for name in ('acme', 'nobody'):
        try:
            return pwd.getpwnam(name)
        except KeyError:
            pass
    return None


def path_secure(p):
    """What keepalived's enable_script_security wants of the check: it and every
    folder above it root's and not writable by anybody else."""
    p = os.path.realpath(p)
    while True:
        st = os.stat(p)
        if st.st_uid != 0 or st.st_mode & 0o022:
            return False
        if p == '/':
            return True
        p = os.path.dirname(p)


def why_skip():
    if os.geteuid() != 0:
        return 'not root'
    if not os.access(KEEPALIVED, os.X_OK):
        return 'keepalived is not installed'
    for tool in ('ip', 'unshare', 'mount'):
        if not shutil.which(tool):
            return '%s is not there' % tool
    if script_user() is None:
        return 'neither an acme nor a nobody account'
    if not path_secure(CHECK):
        return '%s (or a folder above it) is not root\'s alone: keepalived would refuse it' % CHECK
    name = 'acmevrrp-probe-%d' % os.getpid()
    if subprocess.run(['ip', 'netns', 'add', name], capture_output=True).returncode != 0:
        return 'network namespaces cannot be made here'
    subprocess.run(['ip', 'netns', 'del', name], capture_output=True)
    return ''


SKIP = why_skip()
IPV6 = os.path.isdir('/proc/sys/net/ipv6')      # a kernel without it: the IPv6 parts skipped
SERIAL = itertools.count(1)

# The daemon's side of one node: acme's own code, in a process of the node's own.
AGENT = r'''
import json, os, sys, threading, time, types
sys.path.insert(0, sys.argv[1])
ctl = sys.argv[2]
import acme  # noqa: F401
from acmelib import engine as E
E.load_config()                         # ACME_CONFIG: the node's name
assert E.node_name() == sys.argv[3], E.node_name()
STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.daemon_lock()                         # /var/lib/acme/acme.lock: this pid
E.CONFIG.update(ha_mode='replicated', split_mode='off')
daemon = types.SimpleNamespace(store=STORE, stop_flag=threading.Event(),
                               api=types.SimpleNamespace(httpd=True))
last = {}


def apply(c):
    vip = {'on': True, 'address': c['address'], 'prefer': c['prefer'], 'mode': 'back'}
    if last.get('vip') != vip:
        STORE.set_meta('web:vip', json.dumps(vip))
        last['vip'] = vip
    if last.get('maint') != c['maint']:
        E.maintenance_set(STORE, c['maint'], why='test' if c['maint'] else '', by='test')
        last['maint'] = c['maint']


apply(json.load(open(ctl)))
threading.Thread(target=E.vip_watch, args=(daemon,), daemon=True).start()
print('ready', flush=True)
while True:
    time.sleep(0.2)
    try:
        apply(json.load(open(ctl)))
    except ValueError:
        pass
'''


def sh(*a, check=True):
    r = subprocess.run(list(a), capture_output=True, text=True)
    if check and r.returncode != 0:
        raise AssertionError('%s: %s' % (' '.join(a), (r.stderr or r.stdout).strip()))
    return r


class Node(object):
    def __init__(self, name, top, user):
        self.name = name
        self.ns = 'acmevrrp-%s-%d-%d' % (name, os.getpid(), next(SERIAL))
        self.dir = os.path.join(top, name)
        self.run = os.path.join(self.dir, 'run')         # its /run/acme
        self.state = os.path.join(self.dir, 'state')     # its /var/lib/acme
        self.ka = os.path.join(self.dir, 'ka')
        self.ctl = os.path.join(self.dir, 'ctl.json')
        for d in (self.run, self.state, self.ka):
            os.makedirs(d)
        for d in (self.run, self.state):
            os.chown(d, user.pw_uid, user.pw_gid)
            os.chmod(d, 0o750)
        with open(os.path.join(self.state, 'config.json'), 'w') as f:
            json.dump({'node_name': name, 'upgrade_check': 0}, f)
        os.chown(os.path.join(self.state, 'config.json'), user.pw_uid, user.pw_gid)
        self.user = user
        self.agent = None
        self.keepalived = None
        self.conf = os.path.join(self.ka, 'keepalived.conf')

    # -- what the test sees
    def addresses(self):
        r = subprocess.run(['ip', '-n', self.ns, '-o', 'addr', 'show', 'dev', IFACE],
                           capture_output=True, text=True)
        return r.stdout

    def holds(self, address):
        return (' %s ' % address) in self.addresses()

    def file(self, name):
        try:
            with open(os.path.join(self.run, name)) as f:
                return f.read()
        except OSError:
            return ''

    # -- the daemon's side
    def control(self, **c):
        try:
            with open(self.ctl) as f:
                now = json.load(f)
        except OSError:
            now = {}
        now.update(c)
        tmp = self.ctl + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(now, f)
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.ctl)

    def start_agent(self):
        env = dict(os.environ, ACME_CONFIG=os.path.join(self.state, 'config.json'),
                   ACME_STATE=self.state, ACME_RUN=self.run, ACME_LOGDIR=self.state,
                   ACME_PLUGINS=os.path.join(self.state, 'plugins'),
                   ACME_VIP_HEALTH_URL='none', HOME=self.state, PYTHONDONTWRITEBYTECODE='1')
        uid, gid = self.user.pw_uid, self.user.pw_gid

        def drop():
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
        with open(os.path.join(self.dir, 'agent.log'), 'a') as log:
            self.agent = subprocess.Popen([sys.executable, '-c', AGENT, ROOT, self.ctl, self.name],
                                          env=env, stdout=subprocess.PIPE, stderr=log,
                                          preexec_fn=drop, cwd=self.state)
        line = self.agent.stdout.readline()
        if b'ready' not in line:
            raise AssertionError('acme on %s did not start: %s' % (
                self.name, open(os.path.join(self.dir, 'agent.log')).read()[-2000:]))

    def stop_agent(self, sig=signal.SIGTERM):
        if self.agent and self.agent.poll() is None:
            self.agent.send_signal(sig)
            self.agent.wait(10)
        if self.agent:
            self.agent.stdout.close()

    # -- keepalived
    def start_keepalived(self):
        # Its own mount namespace: the node's folders on the paths acme-vip-check reads.
        inner = ('mount --bind %s /run/acme && mount --bind %s /var/lib/acme && '
                 'exec %s -n -l -D -P -f %s -p %s -r %s --no-syslog') % (
            self.run, self.state, KEEPALIVED, self.conf, os.path.join(self.ka, 'ka.pid'),
            os.path.join(self.ka, 'vrrp.pid'))
        with open(os.path.join(self.dir, 'keepalived.log'), 'a') as log:
            self.keepalived = subprocess.Popen(
                ['ip', 'netns', 'exec', self.ns, 'unshare', '-m', '--propagation', 'private',
                 'sh', '-c', inner], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)

    def keepalived_pids(self):
        out = []
        for f in ('ka.pid', 'vrrp.pid'):
            try:
                with open(os.path.join(self.ka, f)) as fh:
                    out.append(int(fh.read().strip()))
            except (OSError, ValueError):
                pass
        return out

    def stop_keepalived(self, sig=signal.SIGTERM):
        if self.keepalived is None:
            return
        if sig == signal.SIGKILL:
            # The whole of it gone at once (parent and VRRP child), as a crash.
            for pid in self.keepalived_pids()[::-1]:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            try:
                os.killpg(self.keepalived.pid, signal.SIGKILL)
            except OSError:
                pass
        elif self.keepalived.poll() is None:
            self.keepalived.send_signal(sig)
        try:
            self.keepalived.wait(15)
        except subprocess.TimeoutExpired:
            os.killpg(self.keepalived.pid, signal.SIGKILL)
            self.keepalived.wait(5)
        for f in ('ka.pid', 'vrrp.pid'):
            try:
                os.unlink(os.path.join(self.ka, f))
            except OSError:
                pass
        self.keepalived = None

    def log(self):
        try:
            with open(os.path.join(self.dir, 'keepalived.log')) as f:
                return f.read()
        except OSError:
            return ''


def dropin_restart_sec(W):
    for line in W.ka_dropin().splitlines():
        if line.startswith('RestartSec='):
            return float(line.split('=', 1)[1])
    raise AssertionError('no RestartSec in the drop-in')


@unittest.skipIf(SKIP, SKIP)
class VrrpPair(unittest.TestCase):
    family = 4
    own = {'acme1': '192.0.2.11', 'acme2': '192.0.2.12'}
    prefix = 24
    vip = '192.0.2.250/24'
    vip6 = '2001:db8:5::250/64'           # beside it, virtual_ipaddress_excluded
    own6 = {'acme1': '2001:db8:5::11/64', 'acme2': '2001:db8:5::12/64'}

    @classmethod
    def setUpClass(cls):
        cls.W = load_helper()

    def setUp(self):
        self.made = []
        for d in ('/run/acme', '/var/lib/acme'):
            if not os.path.isdir(d):        # mount points only; nothing is written there
                os.makedirs(d)
                self.made.append(d)
        self.addCleanup(self._rmdirs)
        self.top = tempfile.mkdtemp(prefix='acme-vrrp-')
        os.chmod(self.top, 0o755)
        if os.environ.get('ACME_VRRP_KEEP'):           # the logs looked at afterwards
            print('\n  kept: %s' % self.top)
        else:
            self.addCleanup(shutil.rmtree, self.top, True)
        self.user = script_user()
        self.samples = []
        self.both = []
        self.allow_stale = set()
        self.sampling = threading.Event()
        if self.family == 6 or self.own6:
            if not IPV6:
                if self.family == 6:
                    self.skipTest('no IPv6 in this kernel')
                self.own6 = {}
                self.vip6 = ''
        self.n = {name: Node(name, self.top, self.user) for name in NODES}
        self.addCleanup(self._teardown_nodes)
        a, b = self.n['acme1'], self.n['acme2']
        for x in (a, b):
            sh('ip', 'netns', 'add', x.ns)
        ends = ('avr%d' % (os.getpid() % 100000), 'bvr%d' % (os.getpid() % 100000))
        sh('ip', 'link', 'add', ends[0], 'type', 'veth', 'peer', 'name', ends[1])
        self.addCleanup(subprocess.run, ['ip', 'link', 'del', ends[0]], capture_output=True)
        for x, end in ((a, ends[0]), (b, ends[1])):
            sh('ip', 'link', 'set', end, 'netns', x.ns)
            sh('ip', '-n', x.ns, 'link', 'set', end, 'name', IFACE)
            sh('ip', '-n', x.ns, 'link', 'set', 'lo', 'up')
            if self.family == 4:
                sh('ip', '-n', x.ns, 'addr', 'add', '%s/%d' % (self.own[x.name], self.prefix),
                   'dev', IFACE)
            if self.own6:
                sh('ip', '-n', x.ns, 'addr', 'add', self.own6[x.name], 'dev', IFACE, 'nodad')
            sh('ip', '-n', x.ns, 'link', 'set', IFACE, 'up')

    def _rmdirs(self):
        for d in self.made[::-1]:
            try:
                os.rmdir(d)
            except OSError:
                pass

    def _teardown_nodes(self):
        self.sampling.clear()
        time.sleep(0.3)
        for x in self.n.values():
            try:
                x.stop_keepalived(signal.SIGKILL)
            except Exception:                           # noqa: BLE001
                pass
            try:
                x.stop_agent(signal.SIGKILL)
            except Exception:                           # noqa: BLE001
                pass
        for x in self.n.values():
            subprocess.run(['ip', 'netns', 'del', x.ns], capture_output=True)

    # -- the pair
    def own_addr(self, name):
        return self.own[name] if self.family == 4 else self.own6[name].split('/')[0]

    def request(self, name):
        other = 'acme2' if name == 'acme1' else 'acme1'
        vip = {'on': True, 'address': self.vip, 'own': self.own_addr(name),
               'peer': self.own_addr(other), 'iface': IFACE, 'vrid': VRID, 'auth': AUTH}
        if self.family == 4 and self.vip6:
            vip['address6'] = self.vip6
        return self.W.checked({'node': name, 'vip': vip})

    def render(self, x):
        text = self.W.ka_conf(x.name, self.request(x.name)['vip'])
        if self.user.pw_name != 'acme':
            self.assertIn('    script_user acme\n', text)
            text = text.replace('    script_user acme\n', '    script_user %s\n' % self.user.pw_name)
        with open(x.conf, 'w') as f:
            f.write(text)
        os.chmod(x.conf, 0o640)
        # What vip_part() asks before it reloads: keepalived takes the file.
        t = subprocess.run(['ip', 'netns', 'exec', x.ns, KEEPALIVED, '-t', '-f', x.conf],
                           capture_output=True, text=True)
        self.assertEqual(t.returncode, 0, 'keepalived -t: %s' % (t.stderr or t.stdout))
        self.assertNotIn('WARNING', t.stderr + t.stdout)
        return text

    def start(self, prefer='acme1'):
        for x in self.n.values():
            self.render(x)
            x.control(address=self.vip, prefer=prefer, maint=False)
            x.start_agent()
        for x in self.n.values():
            x.start_keepalived()
        self.sampling.set()
        t = threading.Thread(target=self._sample, daemon=True)
        t.start()

    def _sample(self):
        addr = self.vip.split('/')[0] + '/' + self.vip.split('/')[1]
        while self.sampling.is_set():
            got = tuple(sorted(x.name for x in self.n.values() if x.holds(addr)))
            self.samples.append((time.time(), got))
            if len(got) > 1 and not (self.allow_stale & set(got)):
                self.both.append((time.time(), got))
            time.sleep(0.2)

    def holders(self, address=None):
        address = address or self.vip
        return sorted(x.name for x in self.n.values() if x.holds(address))

    def wait_holder(self, name, within, address=None):
        t0 = time.time()
        while time.time() - t0 < within:
            h = self.holders(address)
            if h == [name]:
                return time.time() - t0
            time.sleep(0.2)
        self.fail('%s did not come to hold %s alone within %ds: %s\n--- acme1:\n%s\n--- acme2:\n%s'
                  % (name, address or self.vip, within, self.holders(address),
                     self.n['acme1'].log()[-3000:], self.n['acme2'].log()[-3000:]))

    def wait_file(self, x, name, starts, within=8):
        t0 = time.time()
        while time.time() - t0 < within:
            if x.file(name).startswith(starts):
                return
            time.sleep(0.2)
        self.fail('%s/%s does not start with %r: %r' % (x.name, name, starts, x.file(name)))

    def assert_never_both(self):
        self.assertEqual(self.both, [], 'both nodes held the address at once')
        self.assertGreater(len(self.samples), 20)

    def assert_scripts_ran(self):
        for x in self.n.values():
            log = x.log()
            for bad in ('unsafe', 'SECURITY VIOLATION', 'Disabling track script',
                        'Unable to set', 'not executable', 'timed out'):
                self.assertNotIn(bad, log, '%s: %s' % (x.name, bad))

    # -- the scenario
    def test_failover(self):
        a, b = self.n['acme1'], self.n['acme2']
        self.start(prefer='acme1')
        took = self.wait_holder('acme1', 15)
        print('\n  first holder acme1 after %.1fs' % took)
        self.wait_file(a, 'vip-state', 'ok prefer')
        self.wait_file(b, 'vip-state', 'ok\n')
        self.assertEqual(oct(os.stat(os.path.join(a.run, 'vip-state')).st_mode & 0o777), '0o640')
        self.assertEqual(os.stat(os.path.join(a.run, 'vip-state')).st_uid, self.user.pw_uid)
        # notify: keepalived's word on each node, written by acme-vip-check as its user.
        self.wait_file(a, 'vip-role', 'MASTER ')
        self.wait_file(b, 'vip-role', 'BACKUP ')
        self.assertEqual(os.stat(os.path.join(a.run, 'vip-role')).st_uid, self.user.pw_uid)
        if self.family == 4 and self.vip6:
            self.wait_holder('acme1', 3, self.vip6)

        # Maintenance on the holder: acme says "fail in maintenance", the address goes.
        t0 = time.time()
        a.control(maint=True)
        self.wait_file(a, 'vip-state', 'fail in maintenance', 6)
        took = self.wait_holder('acme2', 15)
        print('  maintenance on acme1: on acme2 after %.1fs' % (time.time() - t0))
        self.wait_file(a, 'vip-role', 'FAULT ')
        self.wait_file(b, 'vip-role', 'MASTER ')
        if self.family == 4 and self.vip6:
            self.wait_holder('acme2', 3, self.vip6)

        # Back in service, the preferred node: back to it, after preempt_delay.
        t0 = time.time()
        a.control(maint=False)
        self.wait_file(a, 'vip-state', 'ok prefer', 6)
        t_ok = time.time()
        self.wait_holder('acme1', 25)
        print('  maintenance off: back on acme1 after %.1fs (%.1fs after "ok prefer")'
              % (time.time() - t0, time.time() - t_ok))
        # rise 2 x interval 2 and preempt_delay 5: not at once.
        self.assertGreater(time.time() - t_ok, 4)

        # The preference moved (the pages' "move"): acme2.
        t0 = time.time()
        a.control(prefer='acme2')
        b.control(prefer='acme2')
        self.wait_holder('acme2', 25)
        print('  preference to acme2: moved after %.1fs' % (time.time() - t0))

        # acme itself gone on the holder (its lock's pid): moved without waiting for the
        # file to go stale.
        t0 = time.time()
        b.stop_agent(signal.SIGKILL)
        self.wait_holder('acme1', 12)
        print('  acme killed on acme2: on acme1 after %.1fs' % (time.time() - t0))
        b.start_agent()
        self.wait_holder('acme2', 25)

        # keepalived stopped on the holder (systemctl stop): it lets the address go.
        t0 = time.time()
        b.stop_keepalived(signal.SIGTERM)
        self.assertNotIn(self.vip.split('/')[0], b.addresses())
        self.wait_holder('acme1', 8)
        print('  keepalived stopped on acme2: on acme1 after %.1fs' % (time.time() - t0))
        # Its last notify: STOP (what the alert "keepalived is not running" reads).
        self.wait_file(b, 'vip-role', 'STOP ', 3)
        b.start_keepalived()
        self.wait_holder('acme2', 25)

        # keepalived killed on the holder: the other takes it when the adverts stop
        # (3 x advert_int and the skew). The killed one keeps the address on its
        # interface - nobody is left there to take it away - until keepalived starts
        # again there, which drops it: started as BACKUP, it takes away the addresses
        # of its instance it finds on the interface. acme's drop-in has systemd start it
        # again (Restart=on-failure); here the test does, after the drop-in's RestartSec.
        t0 = time.time()
        self.allow_stale.add('acme2')
        b.stop_keepalived(signal.SIGKILL)
        t_k = time.time()
        while time.time() - t_k < 8 and not a.holds(self.vip):
            time.sleep(0.2)
        self.assertTrue(a.holds(self.vip), 'acme1 did not take the address of a dead keepalived')
        stale = b.holds(self.vip)
        print('  keepalived killed on acme2: acme1 holds it after %.1fs; acme2 still has it: %s'
              % (time.time() - t0, stale))
        self.assertTrue(stale, 'acme2 dropped the address with no keepalived running')
        restart = dropin_restart_sec(self.W)
        time.sleep(max(0.0, restart - (time.time() - t_k)))
        b.start_keepalived()
        t_s = time.time()
        while time.time() - t_s < 10 and b.holds(self.vip):
            time.sleep(0.2)
        self.assertFalse(b.holds(self.vip), 'keepalived started again kept the stale address')
        self.assertEqual(self.holders(), ['acme1'])
        print('  keepalived started again on acme2 (%gs after, RestartSec): stale address gone '
              'after %.1fs' % (restart, time.time() - t_s))
        time.sleep(0.6)             # a sample taken while it was still there: let it finish
        self.allow_stale.discard('acme2')
        self.wait_holder('acme2', 25)

        self.sampling.clear()
        time.sleep(0.3)
        self.assert_never_both()
        self.assert_scripts_ran()


class VrrpPairV6(VrrpPair):
    """IPv6 alone: VRRP version 3 over IPv6 unicast, no authentication."""
    family = 6
    own = {}
    vip = '2001:db8:6::250/64'
    vip6 = ''
    own6 = {'acme1': '2001:db8:6::11/64', 'acme2': '2001:db8:6::12/64'}

    def test_failover(self):
        a, b = self.n['acme1'], self.n['acme2']
        self.start(prefer='acme1')
        self.assertNotIn('auth_pass', open(a.conf).read())
        took = self.wait_holder('acme1', 15)
        print('\n  IPv6: first holder acme1 after %.1fs' % took)
        a.control(maint=True)
        self.wait_holder('acme2', 15)
        self.wait_file(a, 'vip-role', 'FAULT ')
        a.control(maint=False)
        self.wait_holder('acme1', 25)
        b.stop_keepalived(signal.SIGTERM)
        a.stop_keepalived(signal.SIGTERM)
        self.assertEqual(self.holders(), [])
        self.sampling.clear()
        time.sleep(0.3)
        self.assert_never_both()
        self.assert_scripts_ran()


@unittest.skipIf(SKIP, SKIP)
class CheckScript(unittest.TestCase):
    """acme-vip-check on its own, against what vip_watch() writes: its exit codes."""

    def setUp(self):
        self.made = []
        for d in ('/run/acme', '/var/lib/acme'):
            if not os.path.isdir(d):
                os.makedirs(d)
                self.made.append(d)
        self.top = tempfile.mkdtemp(prefix='acme-vipcheck-')
        self.addCleanup(shutil.rmtree, self.top, True)
        self.run_d = os.path.join(self.top, 'run')
        self.state = os.path.join(self.top, 'state')
        os.makedirs(self.run_d)
        os.makedirs(self.state)
        self.user = script_user()
        for d in (self.run_d, self.state):
            os.chown(d, self.user.pw_uid, self.user.pw_gid)
            os.chmod(d, 0o750)
        os.chmod(self.top, 0o755)

    def tearDown(self):
        for d in self.made[::-1]:
            try:
                os.rmdir(d)
            except OSError:
                pass

    def ask(self, *args):
        inner = 'mount --bind %s /run/acme && mount --bind %s /var/lib/acme && ' \
                'exec setpriv --reuid=%d --regid=%d --clear-groups %s %s' % (
                    self.run_d, self.state, self.user.pw_uid, self.user.pw_gid, CHECK,
                    ' '.join(args))
        return subprocess.run(['unshare', '-m', '--propagation', 'private', 'sh', '-c', inner],
                              capture_output=True, text=True).returncode

    def state_is(self, line, age=0):
        p = os.path.join(self.run_d, 'vip-state')
        with open(p, 'w') as f:
            f.write(line)
        os.chown(p, self.user.pw_uid, self.user.pw_gid)
        os.chmod(p, 0o640)
        if age:
            os.utime(p, (time.time() - age, time.time() - age))

    @unittest.skipUnless(shutil.which('setpriv'), 'no setpriv')
    def test_exit_codes(self):
        self.assertEqual(self.ask('ok'), 1)              # no file
        self.assertEqual(self.ask('prefer'), 1)
        self.state_is('ok prefer\n')
        self.assertEqual((self.ask('ok'), self.ask('prefer')), (0, 0))
        self.state_is('ok\n')
        self.assertEqual((self.ask('ok'), self.ask('prefer')), (0, 1))
        self.state_is('fail in maintenance\n')
        self.assertEqual((self.ask('ok'), self.ask('prefer')), (1, 1))
        self.state_is('ok prefer\n', age=20)              # acme silent: stale
        self.assertEqual(self.ask('ok'), 1)
        self.state_is('ok prefer\n')
        lock = os.path.join(self.state, 'acme.lock')
        with open(lock, 'w') as f:
            f.write(str(os.getpid()))                     # alive (root's: kill -0 says EPERM)
        self.assertEqual(self.ask('ok'), 0)
        dead = subprocess.Popen(['true'])
        dead.wait()
        with open(lock, 'w') as f:
            f.write(str(dead.pid))
        self.assertEqual(self.ask('ok'), 1)               # acme gone: no at once
        self.assertEqual(self.ask('whatever'), 2)
        self.assertEqual(self.ask('notify', 'INSTANCE', 'acme_web', 'MASTER', '150'), 0)
        with open(os.path.join(self.run_d, 'vip-role')) as f:
            self.assertRegex(f.read(), r'^MASTER \d+\n\Z')


class KeepalivedDropIn(unittest.TestCase):
    """vip_part() writes systemd's drop-in for keepalived when the address is on
    (Restart=on-failure: a keepalived killed is started again and drops the address it
    left behind - seen above) and takes it away when it goes off, only if it is acme's.
    No systemd under the namespaces: the file itself (ACME_VIP_NO_SERVICES). Runs anywhere."""

    def setUp(self):
        self.W = load_helper()
        top = tempfile.mkdtemp(prefix='acme-vrrp-dropin-')
        self.addCleanup(shutil.rmtree, top, True)
        self.W.KA_CONF = os.path.join(top, 'keepalived', 'keepalived.conf')
        self.W.KA_DROPIN = os.path.join(top, 'system', 'keepalived.service.d', 'acme.conf')
        self.W.progress = lambda *a, **k: None
        self.W.keepalived_installed = lambda: 'there'

    def vip(self, on=True):
        return {'node': 'acme1', 'vip': {
            'on': on, 'address': '192.0.2.250/24', 'own': '192.0.2.11', 'peer': '192.0.2.12',
            'iface': 'lo', 'vrid': VRID, 'auth': AUTH, 'family': 4}}

    def test_written_and_taken_away(self):
        W = self.W
        said, _ = W.vip_part(self.vip(), {})
        with open(W.KA_DROPIN) as f:
            text = f.read()
        self.assertTrue(text.startswith(W.MARK + '\n'))
        self.assertEqual([x for x in text.splitlines() if x and not x.startswith('#')],
                         ['[Service]', 'Restart=on-failure', 'RestartSec=2'])
        self.assertEqual(oct(os.stat(W.KA_DROPIN).st_mode & 0o777), '0o644')
        self.assertTrue(any('started again by systemd' in x for x in said), said)
        # The same again: not written again, not said.
        said, _ = W.vip_part(self.vip(), {})
        self.assertFalse(any('started again by systemd' in x for x in said), said)
        W.vip_part(self.vip(False), {'peer': '192.0.2.12', 'family': 4})
        self.assertFalse(os.path.exists(W.KA_DROPIN))
        self.assertFalse(os.path.exists(os.path.dirname(W.KA_DROPIN)))   # left empty: gone
        self.assertFalse(os.path.exists(W.KA_CONF))

    def test_someone_elses_kept(self):
        W = self.W
        os.makedirs(os.path.dirname(W.KA_DROPIN))
        with open(W.KA_DROPIN, 'w') as f:
            f.write('[Service]\nRestart=always\n')
        said, _ = W.vip_part(self.vip(), {})
        self.assertTrue(any('is not acme' in x for x in said), said)
        W.vip_part(self.vip(False), {})
        with open(W.KA_DROPIN) as f:
            self.assertEqual(f.read(), '[Service]\nRestart=always\n')

    def test_put_back_with_the_conf(self):
        W = self.W
        snap = W.snapshot([W.KA_CONF, W.KA_DROPIN])
        W.vip_part(self.vip(), {})
        W.put_back(snap)
        self.assertFalse(os.path.exists(W.KA_DROPIN))
        self.assertFalse(os.path.exists(W.KA_CONF))


class KeepalivedStoppedAlert(unittest.TestCase):
    """keepalived stopped calls notify a last time with STOP (seen above, keepalived 2.2.8):
    vip-role then says STOP, and the alert "keepalived is not running" has to come for it as
    for no word at all. Needs nothing of the above - runs anywhere."""

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp(prefix='acme-vrrp-alert-')
        cls.addClassCleanup(shutil.rmtree, tmp, True)
        os.environ.update(ACME_CONFIG=os.path.join(tmp, 'config.json'), ACME_STATE=tmp,
                          ACME_RUN=tmp, ACME_LOGDIR=tmp)
        sys.path.insert(0, ROOT)
        import acme  # noqa: F401
        from acmelib import engine as E
        cls.E = E
        cls.store = E.Storage(E.open_db())
        E.HA_STORE['store'] = cls.store
        E.CONFIG.update(ha_mode='replicated', node_name='acme1', alerts_vrrp=1)

    def alerts(self, role2):
        E, st = self.E, self.store
        st.set_meta('web:vip', json.dumps({'on': True, 'address': '192.0.2.250/24'}))
        for name, web in (('acme1', {'vip_here': True, 'role': 'MASTER'}),
                          ('acme2', {'vip_here': False, 'role': role2})):
            st.set_meta('node:' + name, json.dumps({'at': time.time(), 'web': web,
                                                    'version': E.__version__}))
        return E.alert_problems(st)

    def proc(self, comms, hide=False):
        """A folder made to look like /proc: pid -> comm."""
        d = tempfile.mkdtemp(prefix='acme-vrrp-proc-')
        self.addCleanup(shutil.rmtree, d, True)
        for pid, comm in comms.items():
            os.makedirs(os.path.join(d, str(pid)))
            with open(os.path.join(d, str(pid), 'comm'), 'w') as f:
                f.write(comm + '\n')
        if not hide:
            os.makedirs(os.path.join(d, '1'), exist_ok=True)
            if 1 not in comms:
                with open(os.path.join(d, '1', 'comm'), 'w') as f:
                    f.write('systemd\n')
        os.makedirs(os.path.join(d, 'self'))             # not a pid: skipped
        old = self.E.PROC_DIR
        self.E.PROC_DIR = d
        self.addCleanup(setattr, self.E, 'PROC_DIR', old)

    def test_keepalived_alive_from_proc(self):
        E = self.E
        self.proc({55: 'keepalived', 56: 'keepalived', 77: 'nginx'})
        self.assertIs(E.keepalived_alive(), True)
        self.proc({77: 'nginx', 78: 'keepalived-x'})
        self.assertIs(E.keepalived_alive(), False)
        self.proc({500: 'python3'}, hide=True)           # hidepid: other users' unseen
        self.assertIsNone(E.keepalived_alive())

    def test_killed_is_not_running(self):
        """keepalived killed says no STOP: vip-role keeps MASTER/BACKUP. The node's health
        row (written once a minute, health_publish) says no keepalived process is alive."""
        E, st = self.E, self.store
        import types
        daemon = types.SimpleNamespace(store=st, dirs={})
        self.proc({55: 'keepalived', 77: 'nginx'})
        st.set_meta('web:vip', json.dumps({'on': True, 'address': '192.0.2.250/24'}))
        self.assertIs(E.health_publish(daemon).get('keepalived'), True)
        self.assertNotIn('vip:ka:acme1', self.alerts('BACKUP'))
        self.proc({77: 'nginx'})
        self.assertIs(E.health_publish(daemon).get('keepalived'), False)
        got = self.alerts('BACKUP')
        self.assertIn('vip:ka:acme1', got)
        self.assertIn('killed', got['vip:ka:acme1']['said'])
        # Stale (the node's row 10 minutes old): not this node's word now.
        row = json.loads(st.get_meta('host:health:acme1'))
        row['at'] = time.time() - 600
        st.set_meta('host:health:acme1', json.dumps(row))
        self.assertNotIn('vip:ka:acme1', self.alerts('BACKUP'))
        # The VIP address off: not looked at.
        st.set_meta('web:vip', json.dumps({'on': False}))
        self.assertNotIn('keepalived', E.health_publish(daemon))
        st.set_meta('host:health:acme1', json.dumps({'at': time.time()}))

    def test_stop_is_not_running(self):
        self.assertIn('vip:ka:acme2', self.alerts('STOP'))
        self.assertIn('vip:ka:acme2', self.alerts(''))
        got = self.alerts('BACKUP')
        self.assertNotIn('vip:ka:acme2', got)
        self.assertNotIn('vip:fault:acme2', got)
        self.assertIn('vip:fault:acme2', self.alerts('FAULT'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
