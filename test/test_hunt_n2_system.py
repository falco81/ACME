#!/usr/bin/env python3
"""Hunt N round 2 (1.0.102), the system: what was found and is shut now - each checked here.

    python3 test/test_hunt_n2_system.py

The floor for going back follows every CHANGELOG entry marked "(security)"; an upgrade keeps
the logs Settings keep (install.sh carries rotate/maxsize over, the daemon writes them again
once after a version change); a notice at the console put back after a change of sshd on trial
keeps its backslashes; --uninstall takes acme's roots out of the system's trust (and the rest
that is acme's alone) and says what it leaves; the plugin examples written through one
descriptor of the plugins folder, never through a link put in its place.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-huntn2s-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'none'),
                  ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402

WEB = os.path.join(ROOT, 'deploy', 'acme_web.py')
AS_ROOT = os.geteuid() == 0


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


def cat(path, mode='r'):
    with open(path, mode) as f:
        return f.read()


def vt(v):
    return tuple(int(x) for x in v.split('.'))


def sh_function(name):
    """One function of install.sh, as it is there."""
    m = re.search(r'(?ms)^%s\(\) \{\n.*?^\}\n' % re.escape(name), read('install.sh'))
    assert m, name
    return m.group(0)


HARNESS = ('note() { printf "NOTE %s\\n" "$1"; }\nwarn() { printf "WARN %s\\n" "$1"; }\n'
           'fail() { printf "FAIL %s\\n" "$1" >&2; exit 1; }\nrun() { "$@"; }\n')


def bash(script, **env):
    return subprocess.run(['bash', '-c', 'set -eEuo pipefail\n' + HARNESS + script],
                          capture_output=True, text=True, env=dict(os.environ, **env))


class Floor(unittest.TestCase):
    def test_floor_follows_security_entries(self):
        newest = None
        for sec in re.split(r'(?m)^## ', read('CHANGELOG.md'))[1:]:
            ver = sec.split()[0]
            if re.fullmatch(r'\d+\.\d+\.\d+', ver) and '(security)' in sec:
                newest = ver
                break
        self.assertIsNotNone(newest)
        self.assertGreaterEqual(vt(E.DOWNGRADE_FLOOR), vt(newest),
                                'a "(security)" entry in %s: DOWNGRADE_FLOOR must be %s at least '
                                '(docs/releasing.md)' % (newest, newest))

    def test_this_release_raised_it(self):
        self.assertGreaterEqual(vt(E.DOWNGRADE_FLOOR), (1, 0, 102))
        self.assertIn('(security)', read('CHANGELOG.md').split('\n## 1.0.101')[0])
        self.assertIn('(security)', read('docs/releasing.md'))
        # The floor install.sh writes is the same one.
        got = subprocess.run(['bash', '-c', "sed -n \"s/^DOWNGRADE_FLOOR = '\\([0-9.]*\\)'.*/\\1/p\" "
                              "%s/acmelib/engine/[0-9]*.py | head -n 1" % ROOT],
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(got, E.DOWNGRADE_FLOOR)


class Logrotate(unittest.TestCase):
    def put(self, before, dry=''):
        d = tempfile.mkdtemp(dir=TMP)
        dest = os.path.join(d, 'logrotate.d', 'acme')
        if before is not None:
            os.makedirs(os.path.dirname(dest))
            with open(dest, 'w') as f:
                f.write(before)
        got = bash(sh_function('logrotate_put') + 'logrotate_put\n', LOGROTATE_FILE=dest,
                   SOURCE_DIR=ROOT, DRY_RUN=dry)
        self.assertEqual(got.returncode, 0, got.stderr)
        text = cat(dest) if os.path.exists(dest) else None
        return got.stdout, text

    def test_kept_over_an_upgrade(self):
        before = read('deploy/acme.logrotate').replace('rotate 30', 'rotate 365') \
            .replace('maxsize 200M', 'maxsize 50M')
        _o, text = self.put(before)
        self.assertIn('    rotate 365\n', text)
        self.assertIn('    maxsize 50M\n', text)
        self.assertEqual(text, before)
        self.assertEqual(text.count('rotate '), 1)

    def test_first_install_and_nonsense(self):
        _o, text = self.put(None)
        self.assertEqual(text, read('deploy/acme.logrotate'))
        _o, text = self.put('rotate 0\nmaxsize 5T\nrotate 1;touch /x\n')
        self.assertEqual(text, read('deploy/acme.logrotate'))

    def test_dry_run_writes_nothing(self):
        out, text = self.put('    rotate 90\n', dry='yes')
        self.assertIn('rotate 90 kept', out)
        self.assertEqual(text, '    rotate 90\n')

    def test_daemon_applies_again_after_a_version_change(self):
        meta = {}

        class Store:
            def get_meta(self, k):
                return meta.get(k)

            def set_meta(self, k, v):
                meta[k] = v

        class D:
            store = Store()
        asked = []

        def ask(*a, **k):
            asked.append(a)
            return {'said': []}
        with mock.patch.object(E, 'root_ask', side_effect=ask):
            E.LOGS_WORK['again'] = ''
            E.logs_tick(D())
            self.assertEqual(len(asked), 1)
            E.logs_tick(D())                           # ok and recent: not again
            self.assertEqual(len(asked), 1)
            k = 'host:logs:' + E.node_name()
            row = json.loads(meta[k])
            self.assertEqual(row['version'], E.__version__)
            row['version'] = '1.0.1'                   # written by the version before
            meta[k] = json.dumps(row)
            E.logs_tick(D())
            self.assertEqual(len(asked), 2)


WEB_ENV_KEYS = ('ACME_ETC', 'ACME_SSH_DIR', 'ACME_STATE', 'ACME_VIP_NO_SERVICES', 'ACME_ROOT_AUTHKEYS')


class Notice(unittest.TestCase):
    def test_backslashes_kept_over_a_put_back(self):
        t = tempfile.mkdtemp(dir=TMP)
        code = r'''
import os, sys
t = sys.argv[1]
etc, ssh, state = os.path.join(t, 'etc'), os.path.join(t, 'etc/ssh'), os.path.join(t, 'state')
os.makedirs(os.path.join(ssh, 'sshd_config.d')); os.makedirs(os.path.join(etc, 'issue.d'))
os.makedirs(os.path.join(state, 'web'))
open(os.path.join(ssh, 'sshd_config'), 'w').write('Include %s/sshd_config.d/*.conf\n' % ssh)
os.environ.update(ACME_ETC=etc, ACME_SSH_DIR=ssh, ACME_STATE=state, ACME_VIP_NO_SERVICES='1',
                  ACME_ROOT_AUTHKEYS=os.path.join(t, 'ak'), ACME_NET_SNAP_DIR=os.path.join(t, 'net'))
sys.path.insert(0, sys.argv[2])
import acme_web as w
w.SSHD_BIN = '/bin/true'
w.sshd_selinux_port = lambda port: ''
w.sshd_arm = lambda *a, **k: ''
w.sshd_disarm = lambda *a, **k: None
issue = os.path.join(etc, 'issue.d', 'acme.issue')
conf = {'manage': True, 'notice': 'Authorised use only \\ see C:\\policy', 'notice_console': True,
        'password': True, 'permit_root': 'yes'}
w.sshd_do({'do': 'apply', 'conf': conf, 'id': 'a1'})
out = [open(issue).read()]
for i in range(2):
    w.sshd_do({'do': 'apply', 'conf': dict(conf, port=2222), 'trial_min': 1, 'id': 'b%d' % i})
    w.sshd_put_back()
    out.append(open(issue).read())
sys.stdout.write('\x00'.join(out))
'''
        got = subprocess.run([sys.executable, '-I', '-c', code, t, os.path.join(ROOT, 'deploy')],
                             capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stderr)
        kept, one, two = got.stdout.split('\x00')
        self.assertIn('C:\\\\policy', kept)          # agetty's escape: one \ doubled once
        self.assertEqual(one, kept)
        self.assertEqual(two, kept)

    def test_notice_raw(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('acme_web_n2s', WEB)
        W = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(W)
        self.assertEqual(W.notice_raw('issue', 'a \\\\ b\n\n'), 'a \\ b\n')
        self.assertEqual(W.notice_raw('motd', 'a \\\\ b\n'), 'a \\\\ b\n')


@unittest.skipUnless(AS_ROOT, 'acme_web.py runs as root only')
class Uninstall(unittest.TestCase):
    def setUp(self):
        t = self.t = tempfile.mkdtemp(dir=TMP)
        p = self.p = {k: os.path.join(t, v) for k, v in (
            ('etc', 'etc'), ('ssh', 'etc/ssh'), ('sec', 'etc/security'), ('anchors', 'anchors'),
            ('chrony', 'etc/chrony.conf'), ('sysctl', 'etc/sysctl.d/90-acme-vip.conf'),
            ('haca', 'etc/pki/acme/ha-ca.pem'), ('fw4', 'etc/sysconfig/iptables'),
            ('fw6', 'etc/sysconfig/ip6tables'), ('defs', 'etc/login.defs'))}
        for d in ('etc/ssh/sshd_config.d', 'etc/security/pwquality.conf.d', 'anchors',
                  'etc/sysctl.d', 'etc/pki/acme', 'etc/sysconfig', 'etc/systemd/journald.conf.d',
                  'state', 'net'):
            os.makedirs(os.path.join(t, d), exist_ok=True)
        files = {
            os.path.join(p['anchors'], 'acme-0123456789abcdef.pem'): 'x',
            os.path.join(p['anchors'], 'theirs.pem'): 'y',
            os.path.join(p['sec'], 'pwquality.conf.d/50-acme.conf'): '# written by acme\nminlen = 14\n',
            os.path.join(p['sec'], 'faillock.conf'): ('# the system\'s own\n'
                                                     '# ---- acme: Settings -> Local users -> Password policy (from here) ----\n'
                                                     'deny = 5\n# ---- acme: (to here) ----\n'),
            p['chrony']: ('#acme# pool 2.pool.ntp.org iburst\ndriftfile /var/lib/chrony/drift\n\n'
                          '# ---- acme: the time servers, set on its pages (Settings - Time) ----\n'
                          'server ntp.example iburst\nmakestep 1 3\n# ---- acme: end ----\n'),
            os.path.join(t, 'etc/systemd/journald.conf.d/00-acme.conf'):
                '# Written by acme (Settings - Disks and logs); changed there, not here.\n[Journal]\n',
            p['sysctl']: '# written by acme (acme_web.py) - acme keeps this file; change it on its pages\n'
                         'net.ipv4.ip_nonlocal_bind = 1\n',
            os.path.join(p['ssh'], 'sshd_config.d/00-acme.conf'): 'Port 2222\n',
            p['haca']: 'ca',
            p['fw4']: '*filter\n:ACME-IN - [0:0]\n# acme: begin\n-A ACME-IN -p tcp --dport 443 -j ACCEPT\nCOMMIT\n',
            p['defs']: 'PASS_MAX_DAYS 99999\n',
        }
        for path, text in files.items():
            with open(path, 'w') as f:
                f.write(text)
        self.files = files
        self.env = dict(os.environ, ACME_ETC=p['etc'], ACME_SSH_DIR=p['ssh'], ACME_SECURITY_DIR=p['sec'],
                        ACME_LOGIN_DEFS=p['defs'], ACME_CHRONY_CONF=p['chrony'],
                        ACME_SYSCTL_FILE=p['sysctl'], ACME_HA_CA=p['haca'], ACME_FW_FILE4=p['fw4'],
                        ACME_FW_FILE6=p['fw6'], ACME_OSROOTS_FLAVOUR='rhel',
                        ACME_OSROOTS_DIR=p['anchors'], ACME_OSROOTS_EXTRACT='true',
                        ACME_VIP_NO_SERVICES='1', ACME_AUTHSELECT='', ACME_STATE=os.path.join(t, 'state'),
                        ACME_NET_SNAP_DIR=os.path.join(t, 'net'),
                        ACME_PWP_ORIG=os.path.join(t, 'net', 'pwpolicy-orig.json'),
                        ACME_ROOT_AUTHKEYS=os.path.join(t, 'ak'))

    def run_it(self, *extra):
        got = subprocess.run([sys.executable, '-I', WEB, '--leftovers'] + list(extra),
                             capture_output=True, text=True, env=self.env)
        self.assertEqual(got.returncode, 0, got.stderr)
        return got.stdout

    def test_dry_run_changes_nothing(self):
        out = self.run_it('--dry-run')
        for path, text in self.files.items():
            self.assertEqual(cat(path), text, path)
        self.assertIn('[would remove] the system\'s trust: acme-0123456789abcdef.pem', out)
        self.assertIn('true', out)
        for word in ('password policy', 'chrony.conf', '00-acme.conf', '90-acme-vip.conf'):
            self.assertIn(word, out)
        self.assertRegex(out, r'(?m)^left: .*sshd_config\.d/00-acme\.conf')
        self.assertRegex(out, r'(?m)^left: the firewall: .*iptables')
        self.assertRegex(out, r'(?m)^left: .*ha-ca\.pem')

    def test_taken_out(self):
        out = self.run_it()
        a = self.p['anchors']
        self.assertFalse(os.path.exists(os.path.join(a, 'acme-0123456789abcdef.pem')))
        self.assertTrue(os.path.exists(os.path.join(a, 'theirs.pem')))
        self.assertIn('removed acme-0123456789abcdef.pem', out)
        self.assertIn('true run', out)
        self.assertFalse(os.path.exists(os.path.join(self.p['sec'], 'pwquality.conf.d/50-acme.conf')))
        self.assertEqual(cat(os.path.join(self.p['sec'], 'faillock.conf')), '# the system\'s own\n')
        chrony = cat(self.p['chrony'])
        self.assertNotIn('acme', chrony)
        self.assertIn('pool 2.pool.ntp.org iburst', chrony)
        self.assertFalse(os.path.exists(os.path.join(self.t, 'etc/systemd/journald.conf.d/00-acme.conf')))
        self.assertFalse(os.path.exists(self.p['sysctl']))
        # said, not touched: what could shut somebody out or stop the database
        self.assertTrue(os.path.exists(os.path.join(self.p['ssh'], 'sshd_config.d/00-acme.conf')))
        self.assertTrue(os.path.exists(self.p['haca']))
        self.assertIn('ACME-IN', cat(self.p['fw4']))
        self.assertEqual(len(re.findall(r'(?m)^left: ', out)), 3, out)
        # and once more: nothing left of what it takes out
        out = self.run_it()
        self.assertNotIn('removed', out)

    def test_chrony_block_not_whole_hunt_n3(self):
        """Hunt N3 (1.0.102): a block of chrony.conf without its end line is left whole (it was
        cut to the end of the file, the file's own lines with it) and said; the copy ntp_apply
        kept (chrony.conf.acme-before) goes once the block went."""
        broken = ('#acme# pool 2.pool.ntp.org iburst\n'
                  '# ---- acme: the time servers, set on its pages (Settings - Time) ----\n'
                  'server ntp.example iburst\nkeyfile /etc/chrony.keys\nlogdir /var/log/chrony\n')
        with open(self.p['chrony'], 'w') as f:
            f.write(broken)
        before = self.p['chrony'] + '.acme-before'
        with open(before, 'w') as f:
            f.write('pool 2.pool.ntp.org iburst\n')
        out = self.run_it()
        self.assertEqual(cat(self.p['chrony']), broken)
        self.assertRegex(out, r'(?m)^left: acme\'s time servers in .*not whole')
        self.assertTrue(os.path.exists(before))
        with open(self.p['chrony'], 'w') as f:
            f.write(self.files[self.p['chrony']])
        out = self.run_it()
        self.assertNotIn('acme', cat(self.p['chrony']))
        self.assertFalse(os.path.exists(before))
        self.assertIn('chrony.conf.acme-before', out)

    def test_trust_tool_failed_hunt_n3(self):
        """Hunt N3 (1.0.102): the anchors removed but the system's tool did not run - said as
        removed, with the tool to run (it was "not taken out")."""
        self.env['ACME_OSROOTS_EXTRACT'] = 'no-such-tool-acme-test'
        out = self.run_it()
        self.assertFalse(os.path.exists(os.path.join(self.p['anchors'], 'acme-0123456789abcdef.pem')))
        self.assertRegex(out, r'(?m)^removed: the system\'s trust: acme-0123456789abcdef\.pem .*'
                              r'but no-such-tool-acme-test must be run')
        self.assertNotIn('not taken out', out)

    def test_install_sh_runs_it(self):
        sh = read('install.sh')
        self.assertIn('--leftovers ${DRY_RUN:+--dry-run}', sh)
        self.assertIn('left:*) warn', sh)


@unittest.skipUnless(AS_ROOT, 'the examples are written as root')
class PluginExamples(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(dir=TMP)
        self.top = os.path.join(self.t, 'plugins')
        os.mkdir(self.top, 0o755)
        os.chmod(self.top, 0o755)

    def put(self):
        return bash(sh_function('plugin_examples_put') + 'plugin_examples_put\n',
                    PLUGINS_DIR=self.top, SOURCE_DIR=ROOT, DRY_RUN='')

    def test_written(self):
        os.makedirs(os.path.join(self.top, 'examples', 'old'))
        open(os.path.join(self.top, 'examples', 'old', 'stale.py.example'), 'w').close()
        got = self.put()
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.top, 'examples', 'old')))
        want = []
        src = os.path.join(ROOT, 'deploy', 'plugins', 'examples')
        for here, _d, files in os.walk(src):
            want += [os.path.relpath(os.path.join(here, n), src) for n in files if n.endswith('.py.example')]
        self.assertTrue(want)
        for rel in want:
            p = os.path.join(self.top, 'examples', rel)
            self.assertEqual(cat(p, 'rb'), cat(os.path.join(src, rel), 'rb'))
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o644)
        if os.path.exists(os.path.join(ROOT, 'deploy', 'plugins', 'README')):
            self.assertTrue(os.path.isfile(os.path.join(self.top, 'README')))

    def test_a_link_in_its_place_is_refused(self):
        elsewhere = os.path.join(self.t, 'elsewhere')
        os.makedirs(os.path.join(elsewhere, 'examples'))
        open(os.path.join(elsewhere, 'examples', 'mine'), 'w').close()
        os.rmdir(self.top)
        os.symlink(elsewhere, self.top)
        got = self.put()
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('FAIL', got.stderr)
        self.assertTrue(os.path.exists(os.path.join(elsewhere, 'examples', 'mine')))
        self.assertEqual(os.listdir(elsewhere), ['examples'])

    def test_not_roots_alone_is_refused(self):
        os.chmod(self.top, 0o775)
        got = self.put()
        self.assertNotEqual(got.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.top, 'examples')))


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    t0 = time.time()
    unittest.main(verbosity=1)
