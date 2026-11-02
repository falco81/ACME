#!/usr/bin/env python3
"""The engine's edges (1.0.19): what a configuration read back does with the
numbers its rows name each other by, and a number beyond 64 bits asked of
SQLite.

    python3 test/test_engine_edges.py     (or python3 -m unittest test.test_engine_edges)

In one process, SQLite, as test_split.py.
"""
import collections
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-edges-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DB = STORE.db


def wipe(*tables):
    for t in tables:
        DB.run('DELETE FROM %s' % t)


class CarriedNumbers(unittest.TestCase):
    """A row of the file matched by its name, or made where its number was taken here,
    has another number here: the rows naming it by number follow it."""

    def test_deployment_stays_with_its_certificate(self):
        wipe('cert_deploys', 'certs')
        a = DB.insert('certs', {'name': 'alpha', 'state': 'new', 'enabled': 1})
        b = DB.insert('certs', {'name': 'beta', 'state': 'new', 'enabled': 1})
        DB.insert('cert_deploys', {'cert_id': a, 'target': 'to-alpha', 'enabled': 1})
        DB.insert('cert_deploys', {'cert_id': b, 'target': 'to-beta', 'enabled': 1})
        tables = json.loads(json.dumps(E.carry_export(STORE, False)))
        # Another installation: a certificate of its own has alpha's number, beta is
        # there under another number.
        wipe('cert_deploys', 'certs')
        DB.insert('certs', {'id': a, 'name': 'zeta', 'state': 'new', 'enabled': 1})
        DB.insert('certs', {'id': b + 10, 'name': 'beta', 'state': 'new', 'enabled': 1})
        E.carry_import(STORE, tables, 'test', False, collections.Counter())
        names = {r['id']: r['name'] for r in DB.rows('SELECT id, name FROM certs')}
        got = {r['target']: names.get(r['cert_id'])
               for r in DB.rows('SELECT cert_id, target FROM cert_deploys')}
        self.assertEqual(got, {'to-alpha': 'alpha', 'to-beta': 'beta'})

    def test_with_replace_too(self):
        wipe('cert_deploys', 'certs')
        a = DB.insert('certs', {'name': 'alpha', 'state': 'new', 'enabled': 1})
        DB.insert('cert_deploys', {'cert_id': a, 'target': 'to-alpha', 'enabled': 1})
        tables = json.loads(json.dumps(E.carry_export(STORE, False)))
        wipe('cert_deploys', 'certs')
        DB.insert('certs', {'id': a, 'name': 'zeta', 'state': 'new', 'enabled': 1})
        E.carry_import(STORE, tables, 'test', True, collections.Counter())
        row = DB.row('SELECT c.name FROM cert_deploys d JOIN certs c ON c.id = d.cert_id')
        self.assertEqual((row or {}).get('name'), 'alpha')

    def test_authority_and_what_it_signed(self):
        wipe('cert_ca_issued', 'cert_cas', 'certs')
        root = DB.insert('cert_cas', {'name': 'Root', 'serial_next': 0})
        sub = DB.insert('cert_cas', {'name': 'Sub', 'parent_id': root, 'serial_next': 0})
        c = DB.insert('certs', {'name': 'leaf', 'state': 'new', 'enabled': 1})
        DB.insert('cert_ca_issued', {'ca_id': sub, 'serial': '0A', 'cert_id': c})
        tables = json.loads(json.dumps(E.carry_export(STORE, False)))
        wipe('cert_ca_issued', 'cert_cas', 'certs')
        DB.insert('cert_cas', {'id': root, 'name': 'Other', 'serial_next': 0})
        DB.insert('cert_cas', {'id': sub, 'name': 'Other two', 'serial_next': 0})
        DB.insert('certs', {'id': c, 'name': 'other-leaf', 'state': 'new', 'enabled': 1})
        E.carry_import(STORE, tables, 'test', False, collections.Counter())
        cas = {r['id']: r for r in DB.rows('SELECT id, name, parent_id FROM cert_cas')}
        byname = {r['name']: r for r in cas.values()}
        self.assertEqual(cas[byname['Sub']['parent_id']]['name'], 'Root')
        self.assertIsNone(byname['Other two']['parent_id'])
        got = DB.row('SELECT ca_id, cert_id FROM cert_ca_issued')
        self.assertEqual(cas[got['ca_id']]['name'], 'Sub')
        self.assertEqual(DB.value('SELECT name FROM certs WHERE id = ?', (got['cert_id'],)), 'leaf')


class BackupTried(unittest.TestCase):
    def test_rows_written_while_the_copy_is_made(self):
        """A job, a sign-in, a code used once written between the copy and the count of the
        manifest: the backup is still good when tried (it was "not good": cert_jobs 0 of 1)."""
        import time
        g = sys.modules['acmelib.engine'].__dict__
        real = g['dump_tables']

        def dump(db, f):
            real(db, f)
            DB.insert('cert_jobs', {'ts': time.time(), 'kind': 'renew', 'state': 'queued'})
            DB.insert('sessions', {'token_hash': 'x' * 40 + str(time.time()), 'kind': 'admin',
                                   'name': 'boss', 'created': time.time(),
                                   'expires': time.time() + 60})
            DB.insert('used_once', {'k': 'k%s' % time.time(), 'node': 1, 'ts': time.time()})
        if not STORE.account('boss'):
            STORE.add_account('boss', 'fulladmin', 'Long-Password-1!x')
        g['dump_tables'] = dump
        try:
            work = tempfile.mkdtemp(dir=TMP)
            out, _m, _md = E.rb_build(STORE, work)
        finally:
            g['dump_tables'] = real
        checks, _m = E.rb_verify_file(out, E.rb_password(), tempfile.mkdtemp(dir=TMP))
        self.assertEqual([c for c in checks if not c['ok']], [])
        # A row of a table that is set up, missing from the copy, still makes it not good.
        g['dump_tables'] = lambda db, f: (real(db, f), DB.insert(
            'cert_tags', {'name': 'late%s' % time.time()}))
        try:
            out, _m, _md = E.rb_build(STORE, tempfile.mkdtemp(dir=TMP))
        finally:
            g['dump_tables'] = real
        checks, _m = E.rb_verify_file(out, E.rb_password(), tempfile.mkdtemp(dir=TMP))
        self.assertIn('cert_tags', ' '.join(c['said'] for c in checks if not c['ok']))


class BigNumbers(unittest.TestCase):
    def test_beyond_64_bits_finds_nothing(self):
        """SQLite raised OverflowError (`acme --job 99999999999999999999` a traceback);
        PostgreSQL and MariaDB find no row."""
        big = 99999999999999999999
        self.assertIsNone(DB.row('SELECT id FROM certs WHERE id = ?', (big,)))
        self.assertEqual(DB.value('SELECT COUNT(*) FROM cert_jobs WHERE id = ?', (-big,)), 0)
        self.assertEqual(DB.value('SELECT ?', ((1 << 63) - 1,)), (1 << 63) - 1)  # still exact
        self.assertEqual(DB.value('SELECT ?', (True,)), 1)


class JobOfANodeGone(unittest.TestCase):
    def test_stopped_when_its_node_is_gone(self):
        """A job left running by another node that is gone: Stop marks it stopped (it was
        asked of that node for ever, and its certificate stayed busy for two hours); one of
        a node alive is asked of it."""
        import time
        from acmelib.certs import jobs
        c = DB.insert('certs', {'name': 'busy%s' % time.time(), 'state': 'renewing', 'enabled': 1})
        STORE.set_meta('node:acme2', json.dumps({'at': time.time() - 3600}))
        STORE.set_meta('node:acme3', json.dumps({'at': time.time()}))
        try:
            gone = DB.insert('cert_jobs', {'ts': time.time(), 'kind': 'renew', 'cert_id': c,
                                           'node': 'acme2', 'state': 'running'})
            self.assertTrue(jobs.cert_busy(STORE, c))
            self.assertIn('marked stopped', jobs.stop(STORE, gone))
            self.assertEqual(DB.value('SELECT state FROM cert_jobs WHERE id = ?', (gone,)),
                             'stopped')
            self.assertFalse(jobs.cert_busy(STORE, c))
            alive = DB.insert('cert_jobs', {'ts': time.time(), 'kind': 'renew', 'cert_id': c,
                                            'node': 'acme3', 'state': 'running'})
            self.assertIn('acme3 is asked to stop', jobs.stop(STORE, alive))
            self.assertEqual(DB.value('SELECT state FROM cert_jobs WHERE id = ?', (alive,)),
                             'running')
        finally:
            DB.run("DELETE FROM meta WHERE k IN ('node:acme2', 'node:acme3')")


class CommandLine(unittest.TestCase):
    def test_events_limit_below_one(self):
        """--events --limit -5: every event on SQLite, the database's error elsewhere."""
        with self.assertRaises(SystemExit) as got:
            E.cli_main(['--events', '--limit', '-5'])
        self.assertIn('--limit is 1 or more', str(got.exception))


if __name__ == '__main__':
    unittest.main()
