#!/usr/bin/env python3
"""The local users of the machines, the SSH keys of every user who may sign in and the console
at login for normal users (as otp 1.0.240 - 1.0.243).

    python3 test/test_osusers.py          (or python3 -m unittest test.test_osusers)

1. The root helper alone (acme_web.py, as root, on this very machine - users made with a name of
   the test's own and taken away after): only the normal range is touched, root and the
   accounts of the system and of the services never; a password comes as a hash only and a
   wrong one is refused before anything is done; lock, unlock, sudo, the full name and the
   shell, taken away with and without the home folder, asked twice; a normal user's
   authorized_keys written as that user (~/.ssh 0700, the file 0600, theirs; a link refused);
   the second line of the console's file.
2. A daemon (as test_sshkeys starts one) with its root helper in a thread of this test: the
   pages' API makes, changes and takes away a user on the node, the password never in the
   database as itself and its hash taken out once done, root and the service accounts refused;
   the keys of a normal user; the console at login for normal users.
3. The command line: acme --local-users, acme --local-user (a password asked at a terminal only,
   in a pty here), acme --console-users.
"""
import importlib.util
import json
import os
import pty
import pwd
import grp
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (its helpers)

TOOLS = all(shutil.which(t) for t in ('useradd', 'userdel', 'usermod', 'chpasswd', 'chage',
                                      'gpasswd', 'openssl', 'ssh-keygen'))
AS_ROOT = os.geteuid() == 0
TAG = 'acmet%d' % (os.getpid() % 10000)


def sha512(pw):
    got = subprocess.run(['openssl', 'passwd', '-6', '-stdin'], input=pw + '\n',
                         capture_output=True, text=True, check=True)
    return got.stdout.strip()


def gone(name):
    """A user of the test taken away, whatever is left of it."""
    try:
        pwd.getpwnam(name)
    except KeyError:
        return
    subprocess.run(['pkill', '-u', name], capture_output=True)
    subprocess.run(['userdel', '-r', name], capture_output=True)


def helper(state, flag):
    """acme_web.py loaded as a module of this test, its folders the test's."""
    os.environ['ACME_STATE'] = state
    os.environ['ACME_CONSOLE_FLAG'] = flag
    os.environ['ACME_VIP_NO_SERVICES'] = '1'
    spec = importlib.util.spec_from_file_location('acme_web_t%d' % id(state),
                                                  os.path.join(ROOT, 'deploy', 'acme_web.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def keyline(tmp, comment):
    path = os.path.join(tmp, 'k-' + comment)
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', comment, '-f', path],
                   check=True, capture_output=True)
    with open(path + '.pub') as f:
        return f.read().strip()


@unittest.skipUnless(TOOLS and AS_ROOT, 'needs root and shadow-utils (useradd, chpasswd...)')
class Helper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-osusers-helper-')
        os.makedirs(os.path.join(cls.tmp, 'web'))
        cls.W = helper(cls.tmp, os.path.join(cls.tmp, 'console-login'))
        cls.names = ['%s%s' % (TAG, x) for x in ('a', 'b', 'c', 'k')]
        for n in cls.names:
            gone(n)

    @classmethod
    def tearDownClass(cls):
        for n in cls.names:
            gone(n)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def refused(self, r):
        with self.assertRaises(self.W.Refused):
            self.W.lu_do(r)

    def user(self, data, name):
        return next((u for u in data['users'] if u['name'] == name), None)

    def test_01_root_system_and_services_never(self):
        for name in ('root', 'acme', 'acme-web', 'postgres', 'nginx', 'sshd'):
            self.refused({'do': 'lock', 'name': name})
            self.refused({'do': 'drop', 'name': name})
        # An account of the system (below UID_MIN) is not one this may change.
        sysname = next(p.pw_name for p in pwd.getpwall() if 0 < p.pw_uid < 1000)
        self.refused({'do': 'lock', 'name': sysname})
        self.refused({'do': 'add', 'name': 'Bad Name'})
        listed = self.W.lu_do({'do': 'list'})
        self.assertTrue(self.user(listed, 'root')['root'])
        self.assertFalse(any(u['name'] in ('acme', 'acme-web', 'nobody') for u in listed['users']))
        self.assertTrue(listed['shells'] and listed['shells'][-1].endswith('nologin'))

    def test_02_bad_hash_refused_before_anything(self):
        a = self.names[0]
        self.refused({'do': 'add', 'name': a, 'hash': 'plain-password', 'shell': '/bin/bash'})
        with self.assertRaises(KeyError):
            pwd.getpwnam(a)

    def test_03_made_changed_taken_away(self):
        a = self.names[0]
        h = sha512('Long-Enough-1')
        got = self.W.lu_do({'do': 'add', 'name': a, 'gecos': 'Test User', 'shell': '/bin/bash',
                            'hash': h, 'must_change': True, 'sudo': True, 'uid': None})
        u = self.user(got, a)
        self.assertTrue(u['password'] and u['must_change'] and not u['locked'])
        self.assertEqual(u['gecos'], 'Test User')
        if got['admin_group']:
            self.assertTrue(u['sudo'])
        p = pwd.getpwnam(a)
        self.assertTrue(os.path.isdir(p.pw_dir))
        # Asked again: the same UID is no fault, another one is.
        self.assertIn('here already', self.W.lu_do({'do': 'add', 'name': a, 'uid': p.pw_uid,
                                                    'shell': '/bin/bash'})['said'])
        self.refused({'do': 'add', 'name': a, 'uid': p.pw_uid + 1, 'shell': '/bin/bash'})
        u = self.user(self.W.lu_do({'do': 'lock', 'name': a}), a)
        self.assertTrue(u['locked'])
        u = self.user(self.W.lu_do({'do': 'unlock', 'name': a}), a)
        self.assertFalse(u['locked'])
        u = self.user(self.W.lu_do({'do': 'sudo', 'name': a, 'on': False}), a)
        self.assertFalse(u['sudo'])
        u = self.user(self.W.lu_do({'do': 'set', 'name': a, 'gecos': 'Other Name',
                                    'shell': self.W.lu_shells()[0]}), a)
        self.assertEqual(u['gecos'], 'Other Name')
        self.refused({'do': 'set', 'name': a, 'shell': '/bin/not-a-shell'})
        self.refused({'do': 'set', 'name': a, 'gecos': 'a:b'})
        u = self.user(self.W.lu_do({'do': 'password', 'name': a, 'hash': sha512('Another-One-2')}), a)
        self.assertFalse(u['must_change'])
        self.refused({'do': 'password', 'name': a, 'hash': 'nope'})
        got = self.W.lu_do({'do': 'drop', 'name': a, 'home': True})
        self.assertIsNone(self.user(got, a))
        self.assertFalse(os.path.exists(p.pw_dir))
        self.assertIn('was not here', self.W.lu_do({'do': 'drop', 'name': a})['said'])

    def test_04_no_password_is_not_locked(self):
        b = self.names[1]
        u = self.user(self.W.lu_do({'do': 'add', 'name': b, 'shell': '/bin/bash'}), b)
        self.assertFalse(u['password'])
        self.assertFalse(u['locked'])          # a key still lets them in
        self.W.lu_do({'do': 'drop', 'name': b})
        self.assertTrue(os.path.isdir('/home/' + b))     # the home folder kept
        shutil.rmtree('/home/' + b, ignore_errors=True)

    def test_05_keys_of_a_normal_user_written_as_them(self):
        k = self.names[3]
        self.W.lu_do({'do': 'add', 'name': k, 'shell': '/bin/bash'})
        p = pwd.getpwnam(k)
        line = keyline(self.tmp, 'one@laptop')
        got = self.W.sshkeys_do({'do': 'add', 'line': line, 'user': k})
        self.assertEqual(len(got['keys']), 1)
        self.assertTrue(any(u['name'] == k for u in got['users']))
        ssh = os.path.join(p.pw_dir, '.ssh')
        auth = os.path.join(ssh, 'authorized_keys')
        self.assertEqual(stat.S_IMODE(os.stat(ssh).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(auth).st_mode), 0o600)
        self.assertEqual(os.stat(auth).st_uid, p.pw_uid)
        self.assertEqual(os.stat(ssh).st_uid, p.pw_uid)
        fp = got['keys'][0]['fp']
        got = self.W.sshkeys_do({'do': 'drop', 'fp': fp, 'user': k})
        self.assertEqual(got['keys'], [])
        # A link put in their own home is refused, never followed.
        os.unlink(auth)
        os.symlink('/etc/shadow', auth)
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do({'do': 'add', 'line': line, 'user': k})
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do({'do': 'list', 'user': k})
        os.unlink(auth)
        # Only a user who may sign in: not a system account, not one with nologin.
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do({'do': 'list', 'user': 'daemon'})
        self.W.lu_do({'do': 'set', 'name': k, 'shell': self.W.lu_shells()[-1]})
        with self.assertRaises(self.W.Refused):
            self.W.sshkeys_do({'do': 'list', 'user': k})
        self.W.lu_do({'do': 'drop', 'name': k, 'home': True})

    def test_06_the_console_file(self):
        W = self.W
        W.console_flag_set(True, ['alice', 'bob'])
        self.assertEqual(W.console_flag_read(), (True, ['alice', 'bob']))
        with open(W.CONSOLE_FLAG) as f:
            self.assertEqual(f.read(), 'on\nusers: alice bob\n')
        W.console_flag_set(False)                       # the users as they were
        self.assertEqual(W.console_flag_read(), (False, ['alice', 'bob']))
        W.console_flag_set(False, '*')
        self.assertEqual(W.console_flag_read(), (False, '*'))
        W.console_flag_set(True, [])
        self.assertEqual(W.console_flag_read(), (True, []))
        for bad in (['root'], ['a b'], 'everyone', ['x'] * 201):
            with self.assertRaises(W.Refused):
                W.console_users_checked(bad)


@unittest.skipUnless(TOOLS and AS_ROOT, 'needs root and shadow-utils (useradd, chpasswd...)')
class Daemon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-osusers-test-')
        for d in ('state/web', 'run', 'log', 'plugins'):
            os.makedirs(os.path.join(cls.tmp, d), exist_ok=True)
        cls.flag = os.path.join(cls.tmp, 'console-login')
        cls.names = ['%s%s' % (TAG, x) for x in ('d', 'e', 'f')]
        for n in cls.names:
            gone(n)
        cls.port = TCC.free_port()
        conf = {'api_port': cls.port, 'node_name': 'usernode', 'upgrade_check': 0}
        cls.conf = os.path.join(cls.tmp, 'config.json')
        with open(cls.conf, 'w') as f:
            json.dump(conf, f)
        cls.env = dict(os.environ, ACME_CONFIG=cls.conf,
                       ACME_STATE=os.path.join(cls.tmp, 'state'),
                       ACME_RUN=os.path.join(cls.tmp, 'run'),
                       ACME_LOGDIR=os.path.join(cls.tmp, 'log'),
                       ACME_PLUGINS=os.path.join(cls.tmp, 'plugins'),
                       ACME_CONSOLE_FLAG=cls.flag,
                       ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        cls.pw = 'Test-Password-4711!'
        made = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); '
            'st.add_account("tester", "fulladmin", %r); '
            'st.add_account("viewer", "readonly", %r)') % (ROOT, cls.pw, cls.pw)],
            env=cls.env, capture_output=True, text=True, timeout=120)
        if made.returncode != 0:
            raise RuntimeError('the accounts could not be made: %s' % made.stderr[-2000:])
        # The root helper, as acme-web.path would run it: each part a few times a second.
        cls.W = helper(os.path.join(cls.tmp, 'state'), cls.flag)
        cls.stop = threading.Event()

        def loop():
            while not cls.stop.is_set():
                for fn in (cls.W.users_part, cls.W.sshkeys_part, cls.W.console_part):
                    try:
                        fn()
                    except Exception as e:              # noqa: BLE001
                        print('helper: %s' % e, file=sys.stderr)
                cls.stop.wait(0.2)
        cls.loop = threading.Thread(target=loop, daemon=True)
        cls.loop.start()
        cls.daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                      env=cls.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, cwd=cls.tmp)
        end = time.time() + 60
        while time.time() < end:
            if cls.daemon.poll() is not None:
                raise RuntimeError('the daemon stopped: %s' % cls.daemon.stdout.read()
                                   .decode('utf-8', 'replace')[-3000:])
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/api/health' % cls.port, timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError('the daemon did not answer within a minute')
        with open(os.path.join(cls.tmp, 'run', 'api-token')) as f:
            cls.token = f.read().strip()
        cls.admin = cls.login('tester')
        cls.ro = cls.login('viewer')

    @classmethod
    def tearDownClass(cls):
        cls.stop.set()
        d = getattr(cls, 'daemon', None)
        if d is not None and d.poll() is None:
            d.send_signal(signal.SIGTERM)
            try:
                d.wait(20)
            except subprocess.TimeoutExpired:
                d.kill()
        for n in cls.names:
            gone(n)
        if os.environ.get('ACME_TEST_KEEP'):
            print('kept: %s' % cls.tmp)
        else:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    call = classmethod(TCC.CertsCore.call.__func__)
    login = classmethod(TCC.CertsCore.login.__func__)

    def api(self, method, path, body=None, session=None):
        return self.call(method, path, body, session or self.admin)

    def ok(self, method, path, body=None):
        st, got = self.api(method, path, body)
        self.assertEqual(st, 200, '%s %s -> %s %s' % (method, path, st, got))
        return got

    def settle(self, path='/api/osusers', secs=60):
        end = time.time() + secs
        while time.time() < end:
            v = self.ok('GET', path)
            n = v['nodes'][0]
            if not n.get('pending') and n.get('at'):
                return v
            time.sleep(0.4)
        self.fail('%s did not settle: %s' % (path, v))

    def user(self, v, name):
        return next((u for u in v['nodes'][0]['users'] if u['name'] == name), None)

    def meta(self, like):
        code = ('import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
                'st = acme.Storage(acme.open_db()); '
                'print(json.dumps([dict(r) for r in st.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (%r,))]))'
                % (ROOT, like))
        got = subprocess.run([sys.executable, '-c', code], env=self.env, capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        return json.loads(got.stdout.strip().splitlines()[-1])

    def events(self):
        return json.dumps(self.ok('GET', '/api/events?per=200'))

    def test_01_the_users_of_the_node(self):
        self.ok('POST', '/api/osusers', {'action': 'refresh'})
        v = self.settle()
        n = v['nodes'][0]
        self.assertEqual(n['name'], 'usernode')
        self.assertTrue(self.user(v, 'root')['root'])
        self.assertGreaterEqual(n['uid_min'], 1000)
        self.assertEqual(v['pw_min'], 8)
        # Full administrators only.
        st, _ = self.api('GET', '/api/osusers', session=self.ro)
        self.assertEqual(st, 403)

    def test_02_made_with_a_password_never_kept_as_itself(self):
        d = self.names[0]
        self.ok('POST', '/api/osusers', {'action': 'refresh'})
        self.settle()
        pw = 'Pw-Typed-On-The-Page-9'
        got = self.ok('POST', '/api/osusers', {'action': 'add', 'name': d, 'gecos': 'Dana',
                                               'shell': '/bin/bash', 'password': pw,
                                               'must_change': True, 'sudo': False})
        self.assertEqual(got['nodes'], ['usernode'])
        rows = self.meta('host:users:%')
        self.assertNotIn(pw, json.dumps(rows))
        v = self.settle()
        u = self.user(v, d)
        self.assertIsNotNone(u, v['nodes'][0])
        self.assertTrue(u['password'] and u['must_change'])
        self.assertEqual(pwd.getpwnam(d).pw_uid, u['uid'])
        said = v['nodes'][0]['said'][-1]
        self.assertTrue(said['ok'], said)
        # The sealed hash taken out of the asking row once done.
        end = time.time() + 30
        while time.time() < end:
            asks = [a for r in self.meta('host:users:want:%') for a in json.loads(r['v'])]
            if not any(a.get('hash') for a in asks):
                break
            time.sleep(0.5)
        made = [a for a in asks if a.get('do') == 'add' and a.get('name') == d]
        self.assertTrue(made and made[-1].get('hash_gone'), asks)
        self.assertFalse(any(a.get('hash') for a in asks))
        self.assertIn('made the local user %s' % d, self.events())
        self.assertNotIn(pw, self.events())

    def test_03_root_and_services_refused(self):
        for body in ({'action': 'lock', 'name': 'root'}, {'action': 'add', 'name': 'acme'},
                     {'action': 'drop', 'name': 'postgres'}, {'action': 'add', 'name': 'Bad'},
                     {'action': 'password', 'name': self.names[0], 'password': 'short'},
                     {'action': 'nothing', 'name': self.names[0]}):
            st, got = self.api('POST', '/api/osusers', body)
            self.assertEqual(st, 400, (body, got))

    def test_04_changed_and_taken_away(self):
        d = self.names[0]
        self.settle()
        if not self.user(self.settle(), d):
            self.ok('POST', '/api/osusers', {'action': 'add', 'name': d, 'shell': '/bin/bash'})
            self.settle()
        self.ok('POST', '/api/osusers', {'action': 'lock', 'name': d})
        self.assertTrue(self.user(self.settle(), d)['locked'])
        self.ok('POST', '/api/osusers', {'action': 'unlock', 'name': d})
        self.assertFalse(self.user(self.settle(), d)['locked'])
        self.ok('POST', '/api/osusers', {'action': 'set', 'name': d, 'gecos': 'Dana Nova'})
        self.assertEqual(self.user(self.settle(), d)['gecos'], 'Dana Nova')
        self.ok('POST', '/api/osusers', {'action': 'password', 'name': d,
                                         'password': 'Another-Good-One-3'})
        self.assertTrue(self.user(self.settle(), d)['password'])
        if self.settle()['nodes'][0]['admin_group']:
            self.ok('POST', '/api/osusers', {'action': 'sudo', 'name': d, 'on': True})
            self.assertTrue(self.user(self.settle(), d)['sudo'])
        self.ok('POST', '/api/osusers', {'action': 'drop', 'name': d, 'home': True})
        self.assertIsNone(self.user(self.settle(), d))
        with self.assertRaises(KeyError):
            pwd.getpwnam(d)

    def test_05_keys_of_a_normal_user(self):
        e = self.names[1]
        self.ok('POST', '/api/osusers', {'action': 'add', 'name': e, 'shell': '/bin/bash'})
        self.settle()
        self.ok('POST', '/api/sshkeys', {'action': 'refresh', 'user': e})
        line = keyline(self.tmp, 'two@laptop')
        self.ok('POST', '/api/sshkeys', {'action': 'add', 'line': line, 'user': e})
        end, of = time.time() + 30, {}
        while time.time() < end:
            v = self.ok('GET', '/api/sshkeys')
            of = (v['nodes'][0].get('keys_of') or {}).get(e) or {}
            if of.get('keys'):
                break
            time.sleep(0.4)
        self.assertEqual(len(of['keys']), 1, of)
        self.assertTrue(any(u['name'] == e for u in v['nodes'][0]['users']))
        # Root's keys as they were - a normal user's apart.
        self.assertFalse(any(k.get('comment') == 'two@laptop' for k in v['nodes'][0]['keys']))
        made = self.ok('POST', '/api/sshkeys', {'action': 'uk_make', 'user': e})
        self.assertIn('PRIVATE KEY', made['private'])
        self.assertTrue(made['file'].startswith('acme-%s-' % e))
        st, _ = self.api('POST', '/api/sshkeys', {'action': 'uk_make', 'user': 'root'})
        self.assertEqual(st, 400)
        st, _ = self.api('POST', '/api/sshkeys', {'action': 'refresh', 'user': 'not a name'})
        self.assertEqual(st, 400)
        self.assertIn('for %s on usernode' % e, self.events())

    def test_06_the_console_for_normal_users(self):
        self.ok('POST', '/api/console-login', {'on': True, 'users': ['alice', 'bob']})
        end = time.time() + 30
        while time.time() < end:
            n = self.ok('GET', '/api/console-login')['nodes'][0]
            if not n['pending'] and n.get('users') == ['alice', 'bob']:
                break
            time.sleep(0.4)
        self.assertEqual(n['users'], ['alice', 'bob'])
        with open(self.flag) as f:
            self.assertEqual(f.read(), 'on\nusers: alice bob\n')
        st, _ = self.api('POST', '/api/console-login', {'on': True, 'users': ['root']})
        self.assertEqual(st, 400)
        # Left out: as they are.
        self.ok('POST', '/api/console-login', {'on': False})
        end = time.time() + 30
        while time.time() < end:
            n = self.ok('GET', '/api/console-login')['nodes'][0]
            if not n['pending'] and n.get('on') is False:
                break
            time.sleep(0.4)
        with open(self.flag) as f:
            self.assertEqual(f.read(), 'off\nusers: alice bob\n')
        self.assertIn('for normal users: alice, bob (through sudo)', self.events())

    # ---- the command line ------------------------------------------------------------------
    def cli(self, *args, env=None):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                              env=dict(self.env, **(env or {})), capture_output=True, text=True,
                              input='', timeout=180)

    def pty_cli(self, args, answers, env=None):
        """The command line at a terminal, its questions answered as they come."""
        pid, fd = pty.fork()
        if pid == 0:
            os.environ.clear()
            os.environ.update(dict(self.env, **(env or {})))
            os.execv(sys.executable, [sys.executable, os.path.join(ROOT, 'acme.py')] + list(args))
        out, todo = b'', list(answers)
        end = time.time() + 120
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                if todo and out.rstrip().endswith(todo[0][0].encode()):
                    os.write(fd, (todo.pop(0)[1] + '\n').encode())
            elif os.waitpid(pid, os.WNOHANG) != (0, 0):
                break
        try:
            _, status = os.waitpid(pid, 0)
        except ChildProcessError:
            status = 0
        return os.waitstatus_to_exitcode(status), out.decode('utf-8', 'replace')

    def test_07_cli(self):
        f = self.names[2]
        got = self.cli('--local-users')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('usernode', got.stdout)
        self.assertIn('root', got.stdout)
        self.assertIn('view only', got.stdout)
        # A password is never taken from anything but a terminal.
        got = self.cli('--local-user', 'add', f)
        self.assertEqual(got.returncode, 2)
        self.assertIn('asked at a terminal only', got.stdout)
        rc, out = self.pty_cli(['--local-user', 'add', f, '--local-full-name', 'Filip',
                                '--local-must-change'],
                               [(':', 'Cli-Password-77'), ('again:', 'Cli-Password-77')])
        self.assertEqual(rc, 0, out)
        self.assertIn('usernode: done', out)
        self.assertNotIn('Cli-Password-77', out)
        self.assertEqual(pwd.getpwnam(f).pw_gecos.split(',')[0], 'Filip')
        rc, out = self.pty_cli(['--local-user', 'password', f],
                               [(':', 'One-Pass-123'), ('again:', 'Two-Pass-456')])
        self.assertEqual(rc, 1, out)
        self.assertIn('not the same', out)
        rc, out = self.pty_cli(['--local-user', 'drop-home', f], [('go on:', 'yes')])
        self.assertEqual(rc, 0, out)
        with self.assertRaises(KeyError):
            pwd.getpwnam(f)
        got = self.cli('--local-user', 'lock', 'root')
        self.assertEqual(got.returncode, 1)
        self.assertIn('never changed', got.stdout)
        got = self.cli('--local-user', 'fly', f)
        self.assertEqual(got.returncode, 2)

    def test_08_cli_console_users(self):
        got = self.cli('--console-users', 'carol dave')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        with open(self.flag) as f:
            self.assertIn('users: carol dave', f.read())
        got = self.cli('--console-at-login', 'status')
        self.assertIn('carol, dave', got.stdout)
        got = self.cli('--console-users', 'root')
        self.assertNotEqual(got.returncode, 0)
        got = self.cli('--console-users', 'none')
        with open(self.flag) as f:
            self.assertNotIn('users:', f.read())

    def test_09_who_through_sudo(self):
        got = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; from acmelib import engine as E; '
            'print(E.cli_who())') % ROOT], env=dict(self.env, SUDO_USER='alice'),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(got.stdout.strip(), 'command line (sudo alice)')
        got = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; from acmelib import engine as E; '
            'print(E.cli_who())') % ROOT], env=dict(self.env, SUDO_USER='bad name; rm'),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(got.stdout.strip(), 'command line')

    def test_10_the_pages(self):
        """In Chromium (Playwright), English and Czech, wide and a phone: the pages from a copy of
        web/ whose acme-api.php asks this daemon (its run folder, not /run/acme)."""
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        e = self.names[1]
        if not self.user(self.settle(), e):
            self.ok('POST', '/api/osusers', {'action': 'add', 'name': e, 'shell': '/bin/bash',
                                             'gecos': 'Eva Test'})
            self.settle()
        # What SSH keys lists of the node's users: read once before the pages look.
        self.ok('POST', '/api/sshkeys', {'action': 'refresh'})
        end, users = time.time() + 60, []
        while time.time() < end:
            users = [u['name'] for u in self.ok('GET', '/api/sshkeys')['nodes'][0].get('users') or []]
            if e in users:
                break
            time.sleep(0.5)
        self.assertIn(e, users)
        web = os.path.join(self.tmp, 'web')
        shutil.rmtree(web, ignore_errors=True)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=2)
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'osusers_page.js'),
                                  'http://127.0.0.1:%d' % port, 'tester', self.pw, e],
                                 capture_output=True, text=True, timeout=600, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        words = {'en': ('Local users', 'view only', 'Close', 'Take the user away', 'Add a user',
                        'Everybody', 'normal users:', 'Nobody'),
                 'cs': ('Místní uživatelé', 'jen zobrazit', 'Zavřít', 'Odebrat uživatele',
                        'Přidat uživatele', 'Všichni', 'běžní uživatelé:', 'Nikdo')}
        for lang in ('en', 'cs'):
            for width in (1300, 390):
                s = {k: (v.lower() if isinstance(v, str) else [x.lower() for x in v]
                         if isinstance(v, list) and v and isinstance(v[0], str) else v)
                     for k, v in seen[lang + str(width)].items()}
                w = [x.lower() for x in words[lang]]
                self.assertEqual(s['errors'], [], (lang, width))
                self.assertEqual(s['nav'].strip(), w[0])
                self.assertIn('root', s['first'])
                self.assertIn(w[1], s['first'])
                self.assertIn(e, s['host'])
                self.assertLessEqual(s['overflow'], 0, (lang, width))
                self.assertLessEqual(s['overflow_about'], 0, (lang, width))
                self.assertEqual(s['root_inputs'], 0)
                self.assertEqual([b.strip() for b in s['root_buttons']], [w[2]])
                self.assertIn(w[3], [b.strip() for b in s['user_buttons']])
                self.assertNotIn('password', s['pw_types'])
                self.assertEqual(s['add_title'].strip(), w[4])
                self.assertIn('root', s['sk_users'])
                self.assertIn(e, s['sk_users'])
                self.assertIn(w[5], s['sd_picker'])
                self.assertIn(w[6], s['con_row'])
                self.assertIn(w[7], s['con_panel'])
                self.assertIn(e, s['con_panel'])
        # Czech: none of the English words of the pane left.
        cs = seen['cs1300']
        for english in ('Users of the nodes', 'Add a user', 'Whose keys', 'Password',
                        'What they may do', 'Name and shell', 'may not sign in',
                        'with everything in it', 'public half goes into'):
            self.assertNotIn(english, cs['host'] + cs['user_popup'] + cs['sk_host'], english)


class Static(unittest.TestCase):
    """What needs no root."""

    def test_path_unit_asks_for_users(self):
        with open(os.path.join(ROOT, 'deploy', 'acme-web.path')) as f:
            self.assertIn('PathExists=/var/lib/acme/web/users.ask', f.read())

    def test_login_script(self):
        path = os.path.join(ROOT, 'deploy', 'acme-console-login.sh')
        self.assertEqual(subprocess.run(['bash', '-n', path]).returncode, 0)
        with open(path) as f:
            text = f.read()
        self.assertIn("sed -n 's/^users: //p' /etc/acme-console-login", text)
        self.assertIn('sudo -p', text)
        self.assertNotIn('otp', text)

    def test_service_accounts_kept_both_sides(self):
        with open(os.path.join(ROOT, 'deploy', 'acme_web.py')) as f:
            helper_text = f.read()
        for name in ('acme', 'acme-web', 'postgres', 'mysql', 'nginx', 'sshd'):
            self.assertIn("'%s'" % name, helper_text[helper_text.index('KEEP_NAMES'):][:400])
        sys.path.insert(0, ROOT)
        import acme  # noqa: F401
        from acmelib import engine as E
        for name in ('root', 'acme', 'acme-web', 'postgres', 'mysql', 'nginx'):
            self.assertIn(name, E.OSU_KEEP)


if __name__ == '__main__':
    unittest.main()
