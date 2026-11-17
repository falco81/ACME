#!/usr/bin/env python3
"""The pages during an upgrade (1.0.120, docs/upgrades.md "The pages during an upgrade").

    python3 test/test_upgrade_ui.py

Root says how far it is in .upgrade.json beside the pages (acme_upgrade.py, install.sh
--upgrade); PHP reads it from disk while the API, nginx and PHP restart. Here:

- the reader (PHP and the daemon's): freshness, fields that do not read, a time to come, a state
  it does not know - as if there were no file;
- install.sh's writer, its step() wrapper and its way out (a run stopped by a signal is said
  failed, never left running), the steps counted honestly, the file carried over with the pages;
- the root helper: running when it takes the request, failed when it refuses, done at the end -
  install.sh's own word kept;
- the daemon: step N of M from root's file, the cluster's rows in the status, the alerts and the
  checks by hand quiet while it runs;
- PHP without the API: 503 {upgrading} instead of "not answering", ?api=upgrade-state, the
  status with root's word and the pages' version; /healthz's status codes unchanged (what
  keepalived, the balancers and split_peer_says read), its words with "being upgraded";
- the pages in Chromium (test/upgrade_ui_page.js), as the kit's sim.js: one server - running,
  the API killed, PHP killed, back, done (one reload), failed, signed out; and two nodes - the
  cluster's plan says one node is still at it while the answering node's own file says done (no
  reload), the page answered by the other node's PHP (the band and the session stay), then done
  (one reload). In English and Czech, at 1300 and 390 px.

No root needed beyond what the container has, no port of a real installation: a daemon of its
own (test_certs_core's way) and php -S on ports of their own.
"""
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix='acme-upgui-')
PROGRESS = os.path.join(TMP, 'pages', '.upgrade.json')
os.makedirs(os.path.dirname(PROGRESS))
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_UPGRADE_PROGRESS=PROGRESS)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def write_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


CASES = [
    # (what, the file, believed)
    ('running, fresh', {'state': 'running', 'at': 0, 'part': 3, 'parts': 9}, True),
    ('running, 29 min', {'state': 'running', 'at': -29 * 60}, True),
    ('running, 31 min', {'state': 'running', 'at': -31 * 60}, False),
    ('done, 9 min', {'state': 'done', 'at': -9 * 60}, True),
    ('done, 11 min', {'state': 'done', 'at': -11 * 60}, False),
    ('failed, 11 min', {'state': 'failed', 'at': -11 * 60}, False),
    ('a time to come', {'state': 'running', 'at': 120}, False),
    ('a state not known', {'state': 'upgrading', 'at': 0}, False),
    ('no time', {'state': 'running'}, False),
    ('a time that is words', {'state': 'running', 'at': 'soon'}, False),
]


# ---------------------------------------------------------------------------
class Reader(unittest.TestCase):
    """PHP's acme_upgrading_checked() and the daemon's upgrade_progress() believe the same."""

    def php(self, items):
        if not shutil.which('php'):
            self.skipTest('no php here')
        code = ('require %r; $now = time(); $out = [];'
                'foreach (json_decode($argv[1], true) as $d) {'
                ' if (array_key_exists("at", $d) && is_int($d["at"])) { $d["at"] += $now; }'
                ' $out[] = acme_upgrading_checked($d, $now); }'
                'echo json_encode($out);') % os.path.join(ROOT, 'web', 'acme-api.php')
        r = subprocess.run(['php', '-r', code, json.dumps(items)], capture_output=True, text=True,
                           timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_freshness_and_states(self):
        got = self.php([c[1] for c in CASES])
        for (what, _d, ok), g in zip(CASES, got):
            self.assertEqual(g is not None, ok, what)

    def test_fields_checked(self):
        bad = {'state': 'running', 'at': 0, 'version': '1.0.121; rm -rf /', 'from': '1.0',
               'part': 12, 'parts': 9, 'words': 'The\x1b[31m pages\n' + 'x' * 500, 'id': '../x',
               'by': 'a\x07dmin', 'downgrade': 'yes', 'started': 10 ** 12}
        g = self.php([bad, dict(bad, part=-1, parts=200)])
        self.assertEqual(g[0]['version'], '')
        self.assertEqual(g[0]['from'], '')
        self.assertEqual((g[0]['part'], g[0]['parts']), (9, 9))       # never past the whole
        self.assertNotIn('\x1b', g[0]['words'])
        self.assertNotIn('\n', g[0]['words'])
        self.assertLessEqual(len(g[0]['words']), 200)
        self.assertEqual(g[0]['id'], '')
        self.assertEqual(g[0]['by'], 'admin')
        self.assertIs(g[0]['downgrade'], False)
        self.assertLessEqual(g[0]['started'], g[0]['at'])
        self.assertEqual((g[1]['part'], g[1]['parts']), (0, 0))

    def test_daemon_reads_alike(self):
        now = time.time()
        for what, d, ok in CASES:
            d = dict(d)
            if isinstance(d.get('at'), int):
                d['at'] += now
            write_json(PROGRESS, d)
            self.assertEqual(bool(E.upgrade_progress(now=now)), ok, what)
        os.unlink(PROGRESS)
        self.assertEqual(E.upgrade_progress(), {})
        # a link is not followed, a folder is not a file
        os.symlink('/etc/hostname', PROGRESS)
        try:
            self.assertEqual(E.upgrade_progress(), {})
        finally:
            os.unlink(PROGRESS)


# ---------------------------------------------------------------------------
class InstallSh(unittest.TestCase):
    """install.sh's own pieces, run in a folder of their own."""

    @classmethod
    def setUpClass(cls):
        cls.src = read('install.sh')

    def fn(self, name):
        m = re.search(r'^%s\(\) *\{.*?^\}\n' % re.escape(name), self.src, re.M | re.S)
        self.assertTrue(m, name)
        return m.group(0)

    def script(self, d, tail):
        m = re.search(r'^UPGRADE_TELL="" UPGRADE_PART=0.*?\n.*?\n', self.src, re.M)
        lib = os.path.join(d, 'lib')
        os.makedirs(os.path.join(lib, 'current', 'acmelib'), exist_ok=True)
        with open(os.path.join(lib, 'current', 'acmelib', '__init__.py'), 'w') as f:
            f.write("__version__ = '1.0.120'\n")
        body = ('set -Eeuo pipefail\nC_HEAD="" C_OFF="" C_BAD="" DRY_RUN="" VERSION=1.0.121\n'
                'LIB_DIR=%s\n' % lib + m.group(0) + ''.join(self.fn(n) for n in (
                    'step', 'json_str', 'upgrade_tell', 'tree_version_of', 'upgrade_exit')) +
                'UPGRADE_TELL=%s/.upgrade.json; UPGRADE_ID=k1; UPGRADE_PARTS=4; '
                'UPGRADE_FROM=1.0.120; UPGRADE_NODE=n1; UPGRADE_STARTED=$(date +%%s)\n' % d + tail)
        path = os.path.join(d, 't.sh')
        with open(path, 'w') as f:
            f.write(body)
        return path

    def got(self, d):
        with open(os.path.join(d, '.upgrade.json')) as f:
            return json.load(f)

    def test_steps_told(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.script(d, 'trap upgrade_exit EXIT\nstep \'The "program" \\ x\'\n'
                               'cp .upgrade.json one.json\nstep two\nstep three\n')
            r = subprocess.run(['bash', p], cwd=d, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('==> two', r.stdout)
            with open(os.path.join(d, 'one.json')) as f:
                one = json.load(f)
            self.assertEqual((one['state'], one['part'], one['parts']), ('running', 1, 4))
            self.assertEqual(one['words'], 'The "program" \\ x')
            got = self.got(d)
            self.assertEqual((got['state'], got['part'], got['words'], got['id'], got['node'],
                              got['version'], got['from']),
                             ('running', 3, 'three', 'k1', 'n1', '1.0.121', '1.0.120'))
            self.assertEqual(os.stat(os.path.join(d, '.upgrade.json')).st_mode & 0o777, 0o644)
            # no temporary file left beside it
            self.assertEqual(sorted(x for x in os.listdir(d) if x.startswith('.')), ['.upgrade.json'])

    def test_a_failure_said(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.script(d, 'trap upgrade_exit EXIT\nstep one\nfalse\nstep two\n')
            r = subprocess.run(['bash', p], cwd=d, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(r.returncode, 0)
            got = self.got(d)
            self.assertEqual(got['state'], 'failed')
            self.assertEqual(got['part'], 1)
            self.assertIn('install.sh --upgrade stopped (exit 1)', got['said'])
            self.assertIn('1.0.120 runs again', got['said'])

    def test_a_killed_run_is_failed_not_running(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.script(d, "trap upgrade_exit EXIT\ntrap 'exit 130' INT\ntrap 'exit 129' HUP\n"
                               "trap 'exit 143' TERM\nstep one\nstep two\n"
                               "while :; do sleep 0.2; done\n")
            proc = subprocess.Popen(['bash', p], cwd=d, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            end = time.time() + 10
            while time.time() < end:
                try:
                    if self.got(d)['part'] == 2:
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.1)
            proc.send_signal(signal.SIGTERM)
            proc.wait(10)
            self.assertEqual(proc.returncode, 143)
            got = self.got(d)
            self.assertEqual(got['state'], 'failed')
            self.assertIn('(exit 143)', got['said'])

    def test_done(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.script(d, 'trap upgrade_exit EXIT\nstep a\nstep b\nstep c\nstep Done\n'
                               'UPGRADE_WORDS="acme $VERSION runs"\nupgrade_tell done || true\n')
            r = subprocess.run(['bash', p], cwd=d, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            got = self.got(d)
            self.assertEqual((got['state'], got['part'], got['parts']), ('done', 4, 4))

    def test_nothing_written_without_a_folder(self):
        with tempfile.TemporaryDirectory() as d:
            p = self.script(d, 'UPGRADE_TELL=%s/none/.upgrade.json\nstep one\necho fine\n' % d)
            r = subprocess.run(['bash', p], cwd=d, capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn('fine', r.stdout)

    def block(self):
        a = self.src.index('if [[ -n "$DO_UPGRADE" ]]; then')
        return self.src[a:self.src.index('\nfi\n', a)]

    def test_steps_counted_honestly(self):
        """The parts said are the step calls the --upgrade path can make: the six always there,
        the database's tools when they come, PHP and the pages with the pages."""
        block = self.block()
        called = set(re.findall(r'^\s+([a-z_]+)(?:\s|$)', block, re.M))
        steps = re.findall(r'(?<![a-z_])step "([^"]+)"', block)
        for name in sorted(called):
            m = re.search(r'^%s\(\) *\{.*?^\}\n' % re.escape(name), self.src, re.M | re.S)
            if m:
                steps += re.findall(r'(?<![a-z_])step "([^"]+)"', m.group(0))
                # one level deeper: install_program calls runtime_python
                for inner in set(re.findall(r'^\s+([a-z_]+)\s*$', m.group(0), re.M)):
                    mm = re.search(r'^%s\(\) *\{.*?^\}\n' % re.escape(inner), self.src,
                                   re.M | re.S)
                    if mm and inner != name:
                        steps += re.findall(r'(?<![a-z_])step "([^"]+)"', mm.group(0))
        steps = sorted(set(steps))
        self.assertEqual(steps, sorted(['Upgrading acme to $VERSION', 'The program', 'Python',
                                        'The tree', "The database's own tools",
                                        'PHP, and php2shell', 'The pages', 'The service',
                                        'Done']))
        self.assertIn('UPGRADE_PARTS=6', block)
        self.assertIn('UPGRADE_PARTS=$((UPGRADE_PARTS + 2))', block)
        self.assertIn('if db_tools_step_comes; then UPGRADE_PARTS=$((UPGRADE_PARTS + 1)); fi', block)
        # the way out set before the first step, so a check that stops it says so
        self.assertLess(block.index('trap upgrade_exit EXIT'), block.index('step "Upgrading acme'))

    def test_pages_carry_it(self):
        fn = self.fn('pages_from')
        self.assertIn("--exclude='.upgrade.json'", fn)
        self.assertIn('cp -p "$WEB_DIR/.upgrade.json" "$wnew/.upgrade.json"', fn)
        with tempfile.TemporaryDirectory() as d:
            web = os.path.join(d, 'www', 'acme')
            src = os.path.join(d, 'src')
            os.makedirs(web)
            os.makedirs(src)
            for p, t in ((os.path.join(web, 'old.php'), 'old'), (os.path.join(src, 'new.php'), 'new'),
                         (os.path.join(src, '.upgrade.json'), '{"stale": 1}'),
                         (os.path.join(web, '.upgrade.json'), '{"state": "running"}')):
                with open(p, 'w') as f:
                    f.write(t)
            p = os.path.join(d, 't.sh')
            with open(p, 'w') as f:
                f.write('set -Eeuo pipefail\nWEB_DIR=%s\n%s\npages_from %s\n' % (web, fn, src))
            r = subprocess.run(['bash', p], capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(sorted(os.listdir(web)), ['.upgrade.json', 'new.php'])
            with open(os.path.join(web, '.upgrade.json')) as f:
                self.assertEqual(json.load(f), {'state': 'running'})


# ---------------------------------------------------------------------------
class RootHelper(unittest.TestCase):
    """acme_upgrade.py writes running when it takes the request, failed when it refuses or
    install.sh fails, done at the end - install.sh's own word kept where it said it."""

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise unittest.SkipTest('the helper writes only into a folder of root\'s')
        cls.d = tempfile.mkdtemp(prefix='acme-upgui-helper-')
        cls.pages = os.path.join(cls.d, 'www')
        cls.state = os.path.join(cls.d, 'state')
        os.makedirs(cls.pages, mode=0o755)
        os.makedirs(os.path.join(cls.state, 'upgrade'))
        os.chmod(cls.pages, 0o755)
        sys.path.insert(0, os.path.join(ROOT, 'deploy'))
        import importlib
        import acme_upgrade as U
        U = importlib.reload(U)
        U.PAGES_DIR = cls.pages
        U.STATE_DIR = cls.state
        U.UPGRADE_DIR = os.path.join(cls.state, 'upgrade')
        U.UP_FD[0] = None
        cls.U = U

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def file(self):
        with open(os.path.join(self.pages, '.upgrade.json')) as f:
            return json.load(f)

    def request(self, **more):
        req = dict({'id': 'p9', 'file': 'acme-1.0.121.tar.gz', 'sha': '0' * 64, 'version': '1.0.121',
                    'by': 'tester', 'node': 'acmeB', 'downgrade': False}, **more)
        with open(os.path.join(self.state, 'upgrade', 'request.json'), 'w') as f:
            json.dump(req, f)

    def serve(self, put_in):
        was = self.U.put_in
        self.U.put_in = put_in
        try:
            return self.U.serve_request()
        finally:
            self.U.put_in = was

    def test_refused_is_failed(self):
        self.request()

        def refuse(*a, **k):
            seen.append(self.file())
            raise self.U.Refused('the signature is not by any release key this machine trusts')
        seen = []
        self.assertEqual(self.serve(refuse), 0)
        self.assertEqual(seen[0]['state'], 'running')
        self.assertEqual(seen[0]['words'], 'root checks the package')
        self.assertEqual((seen[0]['id'], seen[0]['node'], seen[0]['by']), ('p9', 'acmeB', 'tester'))
        got = self.file()
        self.assertEqual(got['state'], 'failed')
        self.assertIn('signature', got['said'])
        self.assertEqual(os.stat(os.path.join(self.pages, '.upgrade.json')).st_mode & 0o777, 0o644)

    def test_done_and_install_sh_word_kept(self):
        self.request()
        env_seen = {}

        def ok(*a, **k):
            env_seen.update(k.get('env_more') or {})
            # install.sh's own steps and its own done
            self.U.progress(state='done', id='p9', version='1.0.121', part=9, parts=9,
                            words='acme 1.0.121 runs', said='', node='acmeB')
            return 0, {'version': '1.0.121'}, []
        self.serve(ok)
        self.assertEqual(env_seen['ACME_UPGRADE_ID'], 'p9')
        self.assertEqual(env_seen['ACME_UPGRADE_NODE'], 'acmeB')
        self.assertEqual(self.file()['state'], 'done')
        self.assertEqual(self.file()['parts'], 9)
        # install.sh failed and said why: its words stay
        self.request(id='p10')

        def bad(*a, **k):
            self.U.progress(state='failed', id='p10', version='1.0.121', part=4, parts=9,
                            words='The tree', said='install.sh --upgrade stopped (exit 1) - 1.0.120 '
                                                   'runs again', node='acmeB')
            return 1, {'version': '1.0.121'}, []
        self.serve(bad)
        got = self.file()
        self.assertEqual((got['state'], got['part'], got['id']), ('failed', 4, 'p10'))
        self.assertTrue(got['said'].startswith('install.sh --upgrade stopped (exit 1)'))
        # install.sh never got to say anything: root says it
        self.request(id='p11')
        self.serve(lambda *a, **k: (2, {'version': '1.0.121'}, []))
        got = self.file()
        self.assertEqual((got['state'], got['id']), ('failed', 'p11'))
        self.assertIn('install.sh --upgrade ended with 2', got['said'])

    def test_not_a_folder_of_roots(self):
        was = self.U.PAGES_DIR
        try:
            self.U.PAGES_DIR = os.path.join(self.d, 'nothere')
            self.assertFalse(self.U.progress(state='running', id='x'))
            open_dir = os.path.join(self.d, 'open')
            os.makedirs(open_dir)
            os.chmod(open_dir, 0o777)
            self.U.PAGES_DIR = open_dir
            self.assertFalse(self.U.progress(state='running', id='x'))
            self.assertFalse(os.path.exists(os.path.join(open_dir, '.upgrade.json')))
        finally:
            self.U.PAGES_DIR = was


# ---------------------------------------------------------------------------
class Daemon(unittest.TestCase):
    """The daemon's side: quiet alerts and checks by hand while root is at it."""

    def setUp(self):
        self.store = E.Storage(E.open_db())

    def tearDown(self):
        try:
            os.unlink(PROGRESS)
        except OSError:
            pass

    def test_alerts_quiet_while_it_runs(self):
        write_json(PROGRESS, {'state': 'running', 'at': time.time(), 'id': 'k'})
        self.assertTrue(E.alerts_upgrading(self.store))
        os.unlink(PROGRESS)
        self.assertFalse(E.alerts_upgrading(self.store))

    def test_hand_checks_held_while_it_runs(self):
        calls = []

        def check(store):
            calls.append(1)
            return []
        E.HAND_CHECKS.append(check)
        try:
            write_json(PROGRESS, {'state': 'running', 'at': time.time(), 'id': 'k'})
            E.hand_tick(self.store, force=True)
            self.assertEqual(calls, [])
            write_json(PROGRESS, {'state': 'done', 'at': time.time(), 'id': 'k'})
            E.HAND['at'] = time.time()             # looked a moment ago: still looked again
            E.hand_tick(self.store)
            self.assertEqual(calls, [1])
        finally:
            E.HAND_CHECKS.remove(check)

    def test_status_carries_the_rows(self):
        node = E.node_name()
        plan = {'id': 'p1', 'version': '9.9.9', 'sha': 'x', 'order': [node], 'by': 'tester',
                'at': time.time(), 'from': node, 'downgrade': False}
        self.store.set_meta('upgrade:plan', json.dumps(plan))
        self.store.set_meta('upgrade:node:' + node, json.dumps(
            {'id': 'p1', 'state': 'installing', 'part': 4, 'parts': 9, 'part_words': 'The tree',
             'at': time.time(), 'from_version': '1.0.120', 'tail': ['secret-ish output']}))
        try:
            d = E.Daemon.__new__(E.Daemon)
            d.store = self.store
            got = d._upgrade_summary()['plan']
            self.assertEqual((got['id'], got['state'], got['version']), ('p1', 'running', '9.9.9'))
            st = got['steps'][0]
            self.assertEqual((st['name'], st['state'], st['part'], st['parts'], st['part_words'],
                              st['from_version']), (node, 'installing', 4, 9, 'The tree', '1.0.120'))
            self.assertNotIn('tail', st)
        finally:
            self.store.db.run("DELETE FROM meta WHERE k LIKE 'upgrade:%'")

    def test_cli_follow_this_node(self):
        write_json(PROGRESS, {'state': 'done', 'at': time.time(), 'id': 'k', 'version': '1.0.121',
                              'part': 9, 'parts': 9, 'words': 'acme 1.0.121 runs', 'node': 'n1'})

        class Pal:
            def __getattr__(self, k):
                return lambda s: s
        import io
        import contextlib
        buf = io.StringIO()
        was = E.upgrade_progress
        seen = []

        def prog(*a, **k):
            got = was(*a, **k)
            if not seen:
                seen.append(1)
                return dict(got, state='running', part=7, words='The pages')
            return got
        E.upgrade_progress = prog
        try:
            with contextlib.redirect_stdout(buf):
                rc = E.cli_upgrade_follow(self.store, Pal())
        finally:
            E.upgrade_progress = was
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertIn('step 7 of 9', buf.getvalue())
        self.assertIn('this node runs 1.0.121', buf.getvalue())


# ---------------------------------------------------------------------------
CTL = r'''
import json, os, signal, socket, sqlite3, subprocess, sys, time
C = json.load(open(%r))
act = sys.argv[1]


def up(port, path, t=60):
    end = time.time() + t
    while time.time() < end:
        try:
            s = socket.create_connection(('127.0.0.1', port), 1)
            s.close()
            return
        except OSError:
            time.sleep(0.2)


def kill(pidfile):
    try:
        pid = int(open(pidfile).read().strip())
        os.kill(pid, signal.SIGKILL)
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except OSError:
                break
            try:
                os.waitpid(pid, os.WNOHANG)
            except OSError:
                pass
            time.sleep(0.05)
    except (OSError, ValueError):
        pass


if act == 'file':
    p = os.path.join(C['web'][sys.argv[2]], '.upgrade.json')
    with open(p + '.t', 'w') as f:
        f.write(sys.argv[3])
    os.chmod(p + '.t', 0o644)
    os.replace(p + '.t', p)
elif act == 'rm':
    try:
        os.unlink(os.path.join(C['web'][sys.argv[2]], '.upgrade.json'))
    except OSError:
        pass
elif act == 'kill-api':
    kill(C['api_pid'])
elif act == 'start-api':
    p = subprocess.Popen(C['api_cmd'], env=C['api_env'], cwd=C['api_cwd'], start_new_session=True,
                         stdout=open(C['api_log'], 'ab'), stderr=subprocess.STDOUT)
    open(C['api_pid'], 'w').write(str(p.pid))
    up(C['api_port'], '/api/health')
elif act == 'kill-php':
    kill(C['php_pid'][sys.argv[2]])
elif act == 'start-php':
    n = sys.argv[2]
    p = subprocess.Popen(['php', '-S', '127.0.0.1:%%d' %% C['php_port'][n]], cwd=C['web'][n],
                         env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'), start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(C['php_pid'][n], 'w').write(str(p.pid))
    up(C['php_port'][n], '/')
elif act == 'plan':
    d = json.loads(sys.argv[2])
    db = sqlite3.connect(C['db'], timeout=30)
    plan = {k: d[k] for k in ('id', 'version', 'order', 'by', 'at', 'from')}
    plan.update(sha='0' * 64, downgrade=False)
    rows = [('upgrade:plan', json.dumps(plan))]
    for name, st in d['steps'].items():
        rows.append(('upgrade:node:' + name, json.dumps(dict(st, id=d['id']))))
    for k, v in rows:
        db.execute('INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)', (k, v))
    db.commit()
    db.close()
'''


class ThePages(unittest.TestCase):
    """PHP and the pages, with a daemon of their own."""

    @classmethod
    def setUpClass(cls):
        if not shutil.which('php'):
            raise unittest.SkipTest('no php here')
        import test_certs_core as TCC
        cls.TCC = TCC
        cls.call = TCC.CertsCore.__dict__['call']
        cls.login = TCC.CertsCore.__dict__['login']
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.webs, cls.phps, cls.pids = {}, {}, {}
        for n in ('A', 'B', 'C'):
            web = os.path.join(cls.tmp, 'web' + n)
            shutil.copytree(os.path.join(ROOT, 'web'), web)
            run = os.path.join(cls.tmp, 'run') if n != 'C' else os.path.join(cls.tmp, 'runC')
            os.makedirs(run, exist_ok=True)
            p = os.path.join(web, 'acme-api.php')
            with open(p, encoding='utf-8') as f:
                text = f.read()
            with open(p, 'w', encoding='utf-8') as f:
                f.write(text.replace('/run/acme/', run + '/'))
            extra = os.environ.get('ACME_TEST_CS_EXTRA')
            if extra:
                cls.merge_cs(os.path.join(web, 'lang', 'cs.json'), extra)
            cls.webs[n] = web
            cls.phps[n] = free_port()
            cls.pids[n] = os.path.join(cls.tmp, 'php%s.pid' % n)
        # C: the API token there, the port of nothing - a daemon that does not answer
        with open(os.path.join(cls.tmp, 'runC', 'api-token'), 'w') as f:
            f.write(cls.token)
        with open(os.path.join(cls.tmp, 'runC', 'api-port'), 'w') as f:
            f.write(str(free_port()))
        dbs = [os.path.join(cls.tmp, 'state', x) for x in os.listdir(os.path.join(cls.tmp, 'state'))
               if x.endswith('.db')]
        cls.conf_ctl = os.path.join(cls.tmp, 'ctl.json')
        cls.api_pid = os.path.join(cls.tmp, 'api.pid')
        with open(cls.api_pid, 'w') as f:
            f.write(str(cls.daemon.pid))
        with open(cls.conf_ctl, 'w') as f:
            json.dump({'web': cls.webs, 'php_port': cls.phps, 'php_pid': cls.pids,
                       'api_pid': cls.api_pid, 'api_port': cls.port,
                       'api_cmd': [sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                       'api_env': cls.env, 'api_cwd': cls.tmp,
                       'api_log': os.path.join(cls.tmp, 'api-again.log'),
                       'db': dbs[0] if dbs else ''}, f)
        cls.ctl_py = os.path.join(cls.tmp, 'ctl.py')
        with open(cls.ctl_py, 'w') as f:
            f.write(CTL % cls.conf_ctl)
        for n in cls.webs:
            cls.ctl('start-php', n)

    @classmethod
    def merge_cs(cls, path, extra):
        with open(path, encoding='utf-8') as f:
            pack = json.load(f)
        with open(extra, encoding='utf-8') as f:
            more = json.load(f)
        n = 0
        for en, cs in more.items():
            n += 1
            part = 'patterns' if '{0}' in en else 'strings'
            pack[part]['zz%04d' % n] = {'source': en, 'text': cs}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(pack, f, ensure_ascii=False)

    @classmethod
    def ctl(cls, *args):
        subprocess.run([sys.executable, cls.ctl_py] + list(args), check=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        for n in getattr(cls, 'pids', {}):
            cls.ctl('kill-php', n)
        try:
            with open(cls.api_pid) as f:
                pid = int(f.read().strip())
            if pid != cls.daemon.pid:
                os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError, AttributeError):
            pass
        cls.TCC.CertsCore.tearDownClass.__func__(cls)

    def setUp(self):
        for n in self.webs:
            self.ctl('rm', n)

    # ---- asking PHP ---------------------------------------------------------------------
    def ask(self, node, path, cookie=None, body=None):
        url = 'http://127.0.0.1:%d%s' % (self.phps[node], path)
        req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None)
        if body is not None:
            req.add_header('Content-Type', 'application/json')
        if cookie:
            req.add_header('Cookie', cookie)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e.headers

    def tell(self, node, **d):
        d.setdefault('at', int(time.time()))
        write_json(os.path.join(self.webs[node], '.upgrade.json'), d)

    def session(self, node='A'):
        st, body, h = self.ask(node, '/admin/index.php?api=login', body={'name': 'tester', 'password': self.pw})
        self.assertEqual(st, 200, body)
        m = re.search(r'acme_session=([A-Za-z0-9_-]+)', h.get('Set-Cookie') or '')
        self.assertTrue(m, h)
        return 'acme_session=' + m.group(1)

    def test_relay_without_the_api(self):
        # no file: "not answering", as ever
        st, body, _ = self.ask('C', '/admin/index.php?api=status')
        self.assertEqual(st, 503)
        self.assertIn('not answering', json.loads(body)['error'])
        self.assertNotIn('upgrading', json.loads(body))
        # an upgrade said: 503 with how far it is - who and why only with a session's cookie
        self.tell('C', state='running', id='k1', version='1.0.121', **{'from': '1.0.120'},
                  by='tester on the pages', node='acmeB', part=7, parts=9, words='The pages')
        st, body, h = self.ask('C', '/admin/index.php?api=status')
        self.assertEqual(st, 503)
        d = json.loads(body)
        self.assertEqual(d['upgrading']['state'], 'running')
        self.assertEqual((d['upgrading']['part'], d['upgrading']['parts']), (7, 9))
        self.assertEqual(d['upgrading']['by'], '')
        self.assertEqual(d['upgrading']['node'], '')
        st, body, _ = self.ask('C', '/admin/index.php?api=certs', cookie='acme_session=' + 'x' * 24)
        self.assertEqual(st, 503)
        self.assertEqual(json.loads(body)['upgrading']['by'], 'tester on the pages')
        # a write too
        st, body, _ = self.ask('C', '/admin/index.php?api=settings', body={})
        self.assertEqual(st, 503)
        self.assertIn('upgrading', json.loads(body))
        # ?api=upgrade-state: no API needed
        st, body, _ = self.ask('C', '/admin/index.php?api=upgrade-state')
        self.assertEqual(st, 200)
        d = json.loads(body)
        self.assertEqual(d['upgrading']['words'], 'The pages')
        self.assertIs(d['api'], False)
        self.assertRegex(d['pages'], r'^\d+\.\d+\.\d+$')
        # stale: as if there were none
        self.tell('C', state='running', id='k1', at=int(time.time()) - 31 * 60)
        st, body, _ = self.ask('C', '/admin/index.php?api=status')
        self.assertNotIn('upgrading', json.loads(body))
        # nginx would never serve it (a dot file); here: no secret in it at all
        self.assertIn('location ~ /\\.    { deny all; }', read('deploy/nginx-acme.conf'))

    def test_status_merged_and_upgrade_state(self):
        cookie = self.session('A')
        st, body, _ = self.ask('A', '/admin/index.php?api=status', cookie=cookie)
        self.assertEqual(st, 200, body)
        d = json.loads(body)
        self.assertIsNone(d['upgrading'])
        self.assertRegex(d['pages'], r'^\d+\.\d+\.\d+$')
        self.assertIn('upgrade', d)                     # the daemon's own, untouched
        self.tell('A', state='running', id='k1', version='1.0.121', part=2, parts=9,
                  words='Upgrading acme to 1.0.121', by='tester', node='testnode')
        d = json.loads(self.ask('A', '/admin/index.php?api=status', cookie=cookie)[1])
        self.assertEqual(d['upgrading']['state'], 'running')
        self.assertEqual(d['upgrading']['by'], 'tester')
        st, body, _ = self.ask('A', '/admin/index.php?api=upgrade-state', cookie=cookie)
        self.assertIs(json.loads(body)['api'], True)

    def test_healthz_codes_unchanged(self):
        # the daemon away, no upgrade
        st, body, _ = self.ask('C', '/healthz.php')
        self.assertEqual((st, body), (503, 'down: the daemon is not answering\n'))
        # ...in an upgrade: the same code, the same first word, the reason after it
        self.tell('C', state='running', id='k1', version='1.0.121')
        st, body, _ = self.ask('C', '/healthz.php')
        self.assertEqual(st, 503)
        self.assertTrue(body.startswith('down: the daemon is not answering'), body)
        self.assertIn('maintenance: being upgraded', body)
        self.assertNotIn('1.0.121', body)               # no version for anybody
        # the daemon answering, in service, root's file saying it runs: still 200 ok
        self.tell('A', state='running', id='k1', version='1.0.121')
        st, body, _ = self.ask('A', '/healthz.php')
        self.assertEqual((st, body), (200, 'ok up\n'))
        # in maintenance: 503 maintenance, as before - with why after it
        st, got = self.call('POST', '/api/upgrade', {'action': 'maintenance', 'on': True, 'why': 'test'},
                            self.admin)
        self.assertEqual(st, 200, got)
        try:
            time.sleep(2.5)                             # the maintenance cache: two seconds
            st, body, _ = self.ask('A', '/healthz.php')
            self.assertEqual((st, body), (503, 'maintenance: being upgraded\n'))
            self.ctl('rm', 'A')
            st, body, _ = self.ask('A', '/healthz.php')
            self.assertEqual((st, body), (503, 'maintenance\n'))
        finally:
            self.call('POST', '/api/upgrade', {'action': 'maintenance', 'on': False}, self.admin)
            time.sleep(2.5)
        # what split_peer_says reads of the other node: unchanged by the words
        self.assertIn("e.code == 503 and body.startswith('down')", read(
            'acmelib/engine/197_when_the_two_nodes.py'))

    def test_signin_page_band(self):
        self.tell('C', state='running', id='k1', version='1.0.121', part=8, parts=9,
                  words='The service', by='tester')
        st, body, _ = self.ask('C', '/admin/index.php')
        self.assertEqual(st, 200)
        self.assertIn('id="upband"', body)
        self.assertIn('data-api="0"', body)
        self.assertIn('The service', body)
        self.assertNotIn('tester', body)                 # who asked: not before signing in
        self.assertNotIn('The daemon is not answering. Nobody can sign in', body)
        self.ctl('rm', 'C')
        st, body, _ = self.ask('C', '/admin/index.php')
        self.assertNotIn('id="upband"', body)
        self.assertIn('The daemon is not answering', body)

    # ---- the pages in Chromium -----------------------------------------------------------
    def browser(self, mode, lang, width):
        node = shutil.which('node')
        if not node or subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                                      cwd=ROOT).returncode != 0:
            self.skipTest('no node or playwright here')
        ctl = '%s %s' % (sys.executable, self.ctl_py)
        got = subprocess.run([node, os.path.join(HERE, 'upgrade_ui_page.js'), mode,
                              'http://127.0.0.1:%d' % self.phps['A'],
                              'http://127.0.0.1:%d' % self.phps['B'], 'tester', self.pw, ctl,
                              lang, str(width)],
                             capture_output=True, text=True, timeout=600, cwd=ROOT)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        seen = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen)
        return seen

    def czech(self):
        with open(os.path.join(self.webs['A'], 'lang', 'cs.json'), encoding='utf-8') as f:
            return 'acme is being upgraded to {0}' in f.read()

    def fits(self, b, what):
        self.assertTrue(b, what)
        self.assertLessEqual(b['wide'], b['inner'], what)
        self.assertLessEqual(b['right'], b['inner'], what)

    def single(self, lang, width):
        s = self.browser('single', lang, width)
        en = lang == 'en'
        r = s['running']
        self.fits(r, 'running')
        if en:
            self.assertIn('acme is being upgraded to 1.0.121', r['title'])
            self.assertIn('step 1 of 9', r['line'])
            self.assertEqual(r['pill'], 'in maintenance')
            self.assertEqual(r['maint'], 'upgrading')
        elif self.czech():
            self.assertNotIn('is being upgraded', r['title'])
        self.assertIn('warn', r['pillCls'])
        self.assertFalse(r['offline'])
        # the API restarting: said, no red
        a = s['apiDown']
        self.fits(a, 'api down')
        self.assertFalse(a['offline'])
        self.assertIn('warn', a['pillCls'])
        if en:
            self.assertIn('not answering for', a['means'])
            self.assertIn('step 7 of 9', a['line'])
            self.assertEqual(a['server'], 'maintenance')
        p = s['phpDown']
        self.assertTrue(p, s)
        self.assertFalse(p['offline'])
        if en:
            self.assertIn('nginx and PHP are restarting', p['means'])
        self.assertTrue(s['phpBack'], s)
        if en:
            self.assertIn('step 8 of 9', s['phpBack']['line'])
        self.assertTrue(s['apiBack'], s)
        self.assertEqual(s['navsWhileRunning'], 0, s)
        self.assertEqual(s['redWhileRunning'], [], s)
        # done: once
        self.assertEqual(s['reloads'], 1, s)
        self.assertTrue(s['afterDone'] and 'good' in s['afterDone']['cls'], s)
        if en:
            self.assertIn('acme is upgraded to 1.0.121', s['afterDone']['title'])
        # failed: red, why, a way to the log, dismissible - and stays dismissed
        f = s['failed']
        self.fits(f, 'failed')
        self.assertIn('bad', f['cls'])
        self.assertTrue(f['x'])
        self.assertTrue(f['open'])
        self.assertIn('1.0.120 runs again', f['text'])
        if en:
            self.assertIn('The upgrade to acme 1.0.121 failed', f['title'])
        self.assertIsNone(s['failedHidden'])
        self.assertIsNone(s['failedHiddenAfterReload'])
        # signed out during an upgrade: the sign-in page's band, loaded again when the API is back
        si = s['signin']
        self.assertTrue(si['band'] and si['form'], si)
        self.assertEqual(si['api'], '0')
        self.assertEqual(si['offline'], [])
        self.assertLessEqual(si['wide'], si['inner'])
        if en:
            self.assertIn('acme is being upgraded to 1.0.121', si['text'])
            self.assertIn('step 8 of 9', si['text'])
        self.assertEqual(s['signinReloaded'], 1, s)
        self.assertEqual(s['signinAfter']['api'], '1')

    def test_single_en_1300(self):
        self.single('en', 1300)

    def test_single_cs_390(self):
        self.single('cs', 390)

    def short(self, lang, width):
        s = self.browser('short', lang, width)
        self.fits(s['running'], 'running')
        self.fits(s['failed'], 'failed')
        self.assertIn('bad', s['failed']['cls'])
        self.assertEqual(s['red'], [])
        if lang == 'cs' and self.czech():
            self.assertNotIn('failed', s['failed']['title'])

    def test_short_en_390(self):
        self.short('en', 390)

    def test_short_cs_1300(self):
        self.short('cs', 1300)

    def test_cluster(self):
        if not self.conf_db():
            self.skipTest('no SQLite database to write the plan into')
        s = self.browser('cluster', 'en', 1300)
        try:
            # A's own file says done, the cluster's plan says B is at it: no reload
            self.assertEqual(s['onA']['rows'], 2, s)
            self.assertIn('acme is being upgraded to 1.0.121', s['onA']['title'])
            self.assertIn('acmeB', s['onA']['line'])
            self.assertIn('1 of 2 node(s) done', s['onA']['line'])
            self.assertEqual(s['reloadsWhileBRuns'], 0, s)
            # answered by B's PHP: the band stays, the session too, B's step from its own file
            b = s['onB']
            self.assertTrue(b and b['signedIn'], s)
            self.assertIn('step 5 of 9', b['line'])
            self.assertIn('not answering for', s['onBapiDown']['means'])
            self.assertFalse(s['onBapiDown']['offline'])
            self.assertTrue(s['onBback'] and s['onBback']['signedIn'], s)
            self.assertEqual(s['reloadsBeforeEnd'], 0, s)
            self.assertEqual(s['redBeforeEnd'], [], s)
            # every node done: once
            self.assertEqual(s['reloadsAtEnd'], 1, s)
            self.assertTrue(s['afterEnd'] and 'good' in s['afterEnd']['cls'], s)
            self.assertIn('on every node', s['afterEnd']['title'])
        finally:
            db = sqlite3.connect(self.conf_db(), timeout=30)
            db.execute("DELETE FROM meta WHERE k LIKE 'upgrade:%'")
            db.commit()
            db.close()

    def conf_db(self):
        with open(self.conf_ctl) as f:
            return json.load(f)['db']


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
