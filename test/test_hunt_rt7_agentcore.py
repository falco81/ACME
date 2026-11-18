#!/usr/bin/env python3
"""Hunt R run t7 (agentcore): regressions of the Linux agent's core operations.

    python3 test/test_hunt_rt7_agentcore.py

- a command (a test, a reload, a script) that ended at once but left a process in the
  background holding its output (`app &`) was said "did not end in N s" after the whole
  timeout - the deployment that had worked was undone: now its own end is waited for;
- a self-update whose files could not all be written (the disk full) left the agent half
  new, half old, and a half-written .NAME.new beside it: now all of them or none.
"""
import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'deploy', 'agent'))

import acme_agent as AG  # noqa: E402


class _Root(object):
    def conf(self):
        return {'agent_id': 'ag-000000000000'}

    def enc_key(self):
        return None


class RunArgv(unittest.TestCase):
    def setUp(self):
        self.d = AG.Deploy(_Root(), {}, {})

    def test_background_child_does_not_hold_it(self):
        t0 = time.time()
        rc, said = self.d.run_argv(['/bin/sh', '-c', 'echo started; sleep 30 & exit 0'], {},
                                   timeout=10)
        self.assertEqual((rc, said), (0, 'started'))
        self.assertLess(time.time() - t0, 6)

    def test_as_before(self):
        self.assertEqual(self.d.run_argv(['/bin/sh', '-c', 'echo out; echo err >&2; exit 3'],
                                         {}), (3, 'out\nerr'))
        rc, said = self.d.run_argv(['/bin/sh', '-c', 'sleep 10'], {}, timeout=1)
        self.assertEqual((rc, said), (124, 'it did not end in 1 s'))
        rc, said = self.d.run_argv(['/bin/sh', '-c', 'exec >/dev/null 2>&1; sleep 10'], {},
                                   timeout=1)
        self.assertEqual(rc, 124)
        self.assertEqual(self.d.run_argv(['/nonexistent/x'], {})[0], 127)
        rc, said = self.d.run_argv(['/bin/sh', '-c', 'head -c 300000 /dev/zero | tr "\\0" a; '
                                    'echo; echo END'], {})
        self.assertEqual(rc, 0)
        self.assertTrue(said.endswith('\nEND'))
        self.assertEqual(len(said), AG.OUT_MOST)


class InstallFiles(unittest.TestCase):
    def setUp(self):
        self.here = tempfile.mkdtemp(prefix='acme-rt7-')
        self.names = AG.AGENT_FILES + ('release',)
        for n in self.names:
            with open(os.path.join(self.here, n), 'w') as f:
                f.write('old ' + n)
        self.files = {n: ('new ' + n).encode() for n in self.names}

    def tearDown(self):
        shutil.rmtree(self.here, ignore_errors=True)

    def listing(self):
        out = {}
        for n in os.listdir(self.here):
            with open(os.path.join(self.here, n)) as f:
                out[n] = f.read()
        return out

    def test_all_or_none(self):
        real, n = os.fsync, {'n': 0}

        def full(fd):
            n['n'] += 1
            if n['n'] == 3:
                raise OSError(28, 'No space left on device')
            return real(fd)
        AG.os.fsync = full
        try:
            with self.assertRaises(OSError):
                AG.install_files(self.here, self.files, self.names)
        finally:
            AG.os.fsync = real
        self.assertEqual(self.listing(), {n: 'old ' + n for n in self.names})

    def test_replace_failing_puts_back(self):
        real, n = os.replace, {'n': 0}

        def bad(a, b):
            n['n'] += 1
            if n['n'] == 3:
                raise OSError(5, 'I/O error')
            return real(a, b)
        AG.os.replace = bad
        try:
            with self.assertRaises(OSError):
                AG.install_files(self.here, self.files, self.names)
        finally:
            AG.os.replace = real
        self.assertEqual(self.listing(), {n: 'old ' + n for n in self.names})

    def test_installed(self):
        AG.install_files(self.here, self.files, self.names)
        self.assertEqual(self.listing(), {n: 'new ' + n for n in self.names})
        self.assertEqual(os.stat(os.path.join(self.here, 'acme_agent.py')).st_mode & 0o777,
                         0o755)
        self.assertEqual(os.stat(os.path.join(self.here, 'release')).st_mode & 0o777, 0o644)


if __name__ == '__main__':
    unittest.main()
