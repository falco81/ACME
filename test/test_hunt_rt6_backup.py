#!/usr/bin/env python3
"""Hunt R t6 - backups, putting back, export.

    python3 test/test_hunt_rt6_backup.py

- a backup sent says how many certificates it holds (the node's card on Settings -> Backups
  showed an empty "Certificates" for every node), and the page reads the manifest's count when
  a backup file is sent to be put back (it read m.certs, which no manifest has: always "-");
- what was left in the state folder by a command line or an upload never put back - a copy
  with its key opened in clear, a backup file - is taken away at the start.
"""
import json
import os
import re
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunt-rt6-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)


class BackupCounts(unittest.TestCase):
    def test_run_says_how_many_certificates(self):
        for i in range(3):
            STORE.db.insert('certs', {'name': 'c%d.example' % i, 'names': '[]',
                                      'created': time.time(), 'version': 0})
        dest = os.path.join(TMP, 'dest')
        os.makedirs(dest)
        E.CONFIG['rbackup_password'] = E.seal_secret('Backup-Password-4711',
                                                     E.setting_bind('rbackup_password'))
        E.rb_save(STORE, {'kind': 'folder', 'name': 'here', 'path': dest, 'enabled': 1}, 'test')
        run = E.rb_run(STORE, 'test')
        self.assertTrue(run['ok'], run)
        self.assertEqual(run.get('certs'), 3, run)
        last = E.rb_page(STORE)['last_by_node'][E.node_name()]
        self.assertEqual(last.get('certs'), 3)

    def test_page_reads_the_manifests_count(self):
        with open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8') as f:
            js = f.read()
        body = js[js.index('function rbPutBackConfirm('):js.index('function rbRestoreWatch(')]
        self.assertNotIn('m.certs', body)
        self.assertIn('(m.counts || {}).certs', body)


class LeftOvers(unittest.TestCase):
    def test_left_from_before_taken_away(self):
        old = time.time() - 7 * 3600
        made = []
        for pre in ('acme-bundle-', '.acme-cli-'):
            d = tempfile.mkdtemp(prefix=pre, dir=TMP)
            with open(os.path.join(d, 'secrets.key'), 'w') as f:
                f.write('00' * 32 + '\n')
            os.utime(os.path.join(d, 'secrets.key'), (old, old))
            os.utime(d, (old, old))
            made.append(d)
        fresh = tempfile.mkdtemp(prefix='acme-bundle-', dir=TMP)
        ups = []
        for sub in ('rbackup-uploads', 'db-uploads'):
            os.makedirs(os.path.join(TMP, sub), exist_ok=True)
            p = os.path.join(TMP, sub, 'a' * 16)
            with open(p, 'wb') as f:
                f.write(b'\x1f\x8b old')
            os.utime(p, (old, old))
            n = os.path.join(TMP, sub, 'b' * 16)
            with open(n, 'wb') as f:
                f.write(b'\x1f\x8b new')
            ups.append((p, n))
        E.stale_work_away()
        for d in made:
            self.assertFalse(os.path.exists(d), d)
        self.assertTrue(os.path.isdir(fresh))
        for p, n in ups:
            self.assertFalse(os.path.exists(p), p)
            self.assertTrue(os.path.exists(n), n)


if __name__ == '__main__':
    unittest.main()
