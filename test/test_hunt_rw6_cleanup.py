#!/usr/bin/env python3
"""Hunt w6, cleanup: what the tests and the daemon make is taken away again.

    python3 test/test_hunt_rw6_cleanup.py

* The tests (test/tmpclean.py): the folders a test file makes are removed and the processes it
  started stopped when it ends - normally, after a failed setUpClass, on SIGTERM; a run killed
  outright is cleaned up by the next test that starts. What acme itself makes is not touched
  (so the tests still see its leftovers).
* CertsCore (test_certs_core.py): a setUpClass that fails after the daemon started left the
  daemon running and its folder behind (tearDownClass is not called then) - now a class cleanup
  stops it and removes the folder.
* The daemon: a connection through an agent (AgentHop) left a thread waiting in accept() for
  good, holding the socket, at every close - one more thread and descriptor each time.
* The daemon's start: the copy of the whole SQLite database a backup reads (.acme-snapshot-),
  the ACME client's work folder with an account key (acme-acme-) and the nsupdate TSIG key
  folder (acme-dns-) left by a stop half way were never taken away.
* The root helper: a file put back (put_back) or the firewall's file kept over a reboot left a
  temporary file beside it when writing failed.
"""
import io
import os
import signal
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rw6-cleanup-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
import test_certs_core as TCC  # noqa: E402

TC = sys.modules['tmpclean'] if 'tmpclean' in sys.modules else sys.modules['test.tmpclean']


def _alive(pid):
    try:
        with open('/proc/%d/stat' % pid) as f:
            return f.read().rsplit(')', 1)[1].split()[0] not in ('Z', 'X')
    except OSError:
        return False


# Run in a process of its own: a folder made (from a file of this folder - a test's), a process
# started inside it, what both are written to WHERE; then the end asked for.
CHILD = """
import os, subprocess, tempfile, time
d = tempfile.mkdtemp(prefix='acme-rw6-child-')
ns = {}
exec(compile('import tempfile\\nd = tempfile.mkdtemp(prefix="acme-rw6-app-")\\n', APP, 'exec'), ns)
p = subprocess.Popen(['sleep', '300'], cwd=d)
with open(WHERE, 'w') as f:
    f.write('%s %d %s\\n' % (d, p.pid, ns['d']))
if MODE == 'fail':
    raise SystemExit(1)
if MODE == 'wait':
    time.sleep(300)
"""


class Helper(unittest.TestCase):
    def run_child(self, mode, env=None, stop=None):
        where = os.path.join(TMP, 'said-%s' % mode)
        # (what acme itself would make: from a file of acmelib - not the tests' to take away)
        code = ('import sys; sys.path.insert(0, %r); import tmpclean; exec(compile(%r, %r, '
                '"exec"), {"MODE": %r, "WHERE": %r, "APP": %r})' % (
                    HERE, CHILD, os.path.join(HERE, 'rw6_child.py'), mode, where,
                    os.path.join(ROOT, 'acmelib', 'not_a_test.py')))
        p = subprocess.Popen([sys.executable, '-c', code], env=dict(os.environ, **(env or {})),
                             cwd=ROOT)
        if stop:
            for _ in range(200):
                if os.path.exists(where) and os.path.getsize(where):
                    break
                time.sleep(0.05)
            time.sleep(0.3)
            p.send_signal(stop)
        p.wait(60)
        with open(where) as f:
            d, pid, app = f.read().split()
        self.addCleanup(TC._remove, app)
        return d, int(pid), app

    def gone(self, d, pid):
        for _ in range(100):
            if not _alive(pid):
                break
            time.sleep(0.1)
        self.assertFalse(os.path.exists(d), d)
        self.assertFalse(_alive(pid), 'the process started by the test still runs')

    def test_normal_end(self):
        d, pid, app = self.run_child('end')
        self.gone(d, pid)
        self.assertTrue(os.path.isdir(app), 'what acme made is left for the tests to see')

    def test_failed(self):
        d, pid, _app = self.run_child('fail')
        self.gone(d, pid)

    def test_sigterm(self):
        d, pid, _app = self.run_child('wait', stop=signal.SIGTERM)
        self.gone(d, pid)

    def test_kept_when_asked(self):
        d, pid, _app = self.run_child('end', env={'ACME_TEST_KEEP': '1'})
        self.addCleanup(TC._remove, d)
        self.assertTrue(os.path.isdir(d))
        self.assertFalse(_alive(pid))

    def test_killed_run_swept_by_the_next(self):
        d, pid, _app = self.run_child('wait', stop=signal.SIGKILL)
        self.addCleanup(lambda: _alive(pid) and os.kill(pid, signal.SIGKILL))
        self.assertTrue(os.path.isdir(d))            # SIGKILL: nothing could be done then
        self.assertTrue(_alive(pid))                 # ...the sleep left running inside it
        TC.sweep()                                   # what the next test does when it starts
        self.gone(d, pid)


class CertsCoreHalfWay(unittest.TestCase):
    def test_daemon_stopped_when_setup_fails_after_it(self):
        seen = {}

        class Broken(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                TCC.CertsCore.setUpClass.__func__(cls)
                seen['tmp'], seen['daemon'] = cls.tmp, cls.daemon
                raise RuntimeError('something after the daemon fails')

            def test_x(self):
                pass
        Broken.call = TCC.CertsCore.__dict__['call']
        Broken.login = TCC.CertsCore.__dict__['login']
        got = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Broken))
        self.assertEqual(len(got.errors), 1)
        self.assertIn('daemon', seen)
        # before this process ends (not tmpclean's doing): the class cleanup
        self.assertIsNotNone(seen['daemon'].poll(), 'the daemon still runs')
        self.assertFalse(os.path.exists(seen['tmp']), seen['tmp'])


class AgentHopClosed(unittest.TestCase):
    def hops(self):
        return [t for t in threading.enumerate() if t.name == 'agent-hop']

    def test_thread_and_socket_gone(self):
        from acmelib.certs import runtime
        before = len(self.hops())
        hop = runtime.AgentHop(None, {'name': 'srv1'})
        self.assertEqual(len(self.hops()), before + 1)
        fd = hop.srv.fileno()
        self.assertEqual(os.stat(hop.d).st_mode & 0o777, 0o700)
        hop.close()
        for _ in range(50):
            if len(self.hops()) == before:
                break
            time.sleep(0.05)
        self.assertEqual(len(self.hops()), before, 'the thread waits in accept() for good')
        self.assertFalse(os.path.exists(hop.d))
        self.assertFalse(os.path.exists('/proc/self/fd/%d' % fd) and
                         'socket' in os.readlink('/proc/self/fd/%d' % fd))

    def test_folder_gone_when_it_cannot_listen(self):
        from acmelib.certs import runtime
        made = []
        real = tempfile.mkdtemp

        def mk(*a, **kw):
            made.append(real(*a, **kw))
            return made[-1]
        with mock.patch.object(runtime.tempfile, 'mkdtemp', mk), \
                mock.patch.object(runtime.os, 'chmod', side_effect=OSError('refused')):
            with self.assertRaises(OSError):
                runtime.AgentHop(None, {'name': 'srv1'})
        self.assertEqual(len(made), 1)
        self.assertFalse(os.path.exists(made[0]))


class StaleWork(unittest.TestCase):
    def test_left_from_a_stop_half_way(self):
        old = time.time() - 7 * 3600
        made = []
        for pre, folder in (('.acme-snapshot-', False), ('acme-acme-', True),
                            ('acme-dns-', True)):
            if folder:
                p = tempfile.mkdtemp(prefix=pre, dir=TMP)
                with open(os.path.join(p, 'account.pem'), 'w') as f:
                    f.write('a key\n')
            else:
                fd, p = tempfile.mkstemp(prefix=pre, suffix='.sqlite', dir=TMP)
                os.close(fd)
            os.utime(p, (old, old))
            made.append(p)
        fd, fresh = tempfile.mkstemp(prefix='.acme-snapshot-', suffix='.sqlite', dir=TMP)
        os.close(fd)
        E.stale_work_away()
        for p in made:
            self.assertFalse(os.path.exists(p), p)
        self.assertTrue(os.path.exists(fresh), 'one being made now stays')


class RootHelperTemp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.update(ACME_VIP_NO_SERVICES='1',
                          ACME_NET_SNAP_DIR=os.path.join(TMP, 'root-only'))
        sys.path.insert(0, os.path.join(ROOT, 'deploy'))
        import acme_web
        cls.W = acme_web

    def test_put_back_leaves_nothing_when_writing_fails(self):
        folder = tempfile.mkdtemp(prefix='acme-rw6-putback-', dir=TMP)
        path = os.path.join(folder, 'site.conf')
        with open(path, 'w') as f:
            f.write('now\n')
        with mock.patch.object(self.W.os, 'replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.W.put_back({path: (b'before\n', 0o644)})
        self.assertEqual(os.listdir(folder), ['site.conf'])
        self.W.put_back({path: (b'before\n', 0o644)})
        with open(path) as f:
            self.assertEqual(f.read(), 'before\n')
        self.assertEqual(os.listdir(folder), ['site.conf'])


if __name__ == '__main__':
    unittest.main()
