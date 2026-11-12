#!/usr/bin/env python3
"""Hunt H (1.0.80): the backup audit and the two rounds of the bug hunt - what was put right.

    python3 test/test_hunt_h.py
"""
import gzip
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-h-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib import i18n_mail  # noqa: E402
from acmelib.certs import portal as P  # noqa: E402
from acmelib.certs import runtime  # noqa: E402
from acmelib.plugins.targets import _files as F  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE


def src_of(rel):
    with open(os.path.join(ROOT, rel)) as f:
        return f.read()


class Release(unittest.TestCase):
    def test_version_line_read_by_every_reader(self):
        line = src_of('acmelib/__init__.py')
        self.assertTrue(re.search(r"^__version__ = '[0-9.]+'$", line, re.M))
        sys.path.insert(0, os.path.join(ROOT, 'deploy'))
        import acme_upgrade as U
        self.assertTrue(U.VERSION_RE.search('__version__ = "1.2.3"'))
        self.assertTrue(U.VERSION_RE.search("__version__ = '1.2.3'"))


class Backup(unittest.TestCase):
    def test_older_copy_empties_tables_it_did_not_have(self):
        STORE.db.insert('cert_tests', {'name': 'leftover', 'kind': 'tls', 'config': '{}'})
        path = os.path.join(TMP, 'old-copy.json.gz')
        with gzip.open(path, 'wt', encoding='utf-8') as f:
            f.write(json.dumps({'acme': '1.0.30'}) + '\n')
            f.write(json.dumps({'table': 'certs'}) + '\n')
        E.load_tables(STORE.db, path)
        self.assertFalse(STORE.db.rows('SELECT id FROM cert_tests'))

    def test_console_at_login_kept_as_wanted(self):
        STORE.set_meta('console:now:oldbox', json.dumps({'on': True, 'at': 1}))
        E.machine_changed_check(STORE, put_back=True, name='oldbox')
        want = json.loads(STORE.get_meta('console:want:oldbox') or '{}')
        self.assertTrue(want.get('on'))

    def test_config_json_settings_carried(self):
        got = E.carry_file_settings(STORE, {'site_name': 'plant', 'node_name': 'x',
                                            'db_engine': 'sqlite'})
        self.assertEqual(got, ['site_name'])


class Certs(unittest.TestCase):
    def test_long_kv_keys_kept_apart(self):
        rc = runtime.RunContext.__new__(runtime.RunContext)
        rc.scope = 'target:t'
        a = rc._kv_key('x' * 200 + 'one')
        b = rc._kv_key('x' * 200 + 'two')
        self.assertNotEqual(a, b)

    def test_portal_holds_names_under_another_owners_wildcard(self):
        self.assertTrue(P._covers('*.corp.example.test', 'mail.corp.example.test'))
        self.assertFalse(P._covers('*.corp.example.test', 'a.b.corp.example.test'))

    def test_files_placed_under_names_nobody_guesses(self):
        lines = '\n'.join(F.place_lines('/etc/x/site.key', '/etc/x/site.key.bak', '/tmp/t', 0o600,
                                        'app:app', 0))
        self.assertNotIn('site.key.acme-new', lines)
        self.assertIn('set -C', lines)
        self.assertIn('chown -h', lines)


class Mail(unittest.TestCase):
    def test_report_lines_in_czech(self):
        self.assertEqual(i18n_mail.tr('x:443 cannot be reached: [Errno 111] Connection refused',
                                      'cs'), 'x:443 není dosažitelný: Spojení odmítnuto')
        self.assertEqual(i18n_mail.tr('nothing known here at all', 'cs'),
                         'nothing known here at all')


class CommandLine(unittest.TestCase):
    def acme(self, *argv):
        r = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(argv),
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
        return r.returncode, r.stdout + r.stderr

    def test_private_key_not_written_out(self):
        rc, said = self.acme('--api', 'POST', '/api/sshkey/use_own',
                             '{"family":"target","id":1,"pem":"-----BEGIN OPENSSH PRIVATE KEY-----"}')
        self.assertIn('private key is not taken', said)

    def test_lone_debug_from_a_script(self):
        rc, said = self.acme('--debug')
        self.assertIn('alone asks for nothing', said)


if __name__ == '__main__':
    unittest.main(verbosity=2)
