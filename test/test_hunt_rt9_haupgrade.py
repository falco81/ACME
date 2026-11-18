#!/usr/bin/env python3
"""Hunt Rt9 - HA replication of the newest data across an upgrade, and install.sh's migrations.

    python3 test/test_hunt_rt9_haupgrade.py

- a replicated pair upgraded by hand, one node after the other, to a version with a new table
  (1.0.125's cert_roles): what the node upgraded first wrote there before the other was upgraded
  (a custom role) never came to the other one - its subscription took the table with
  copy_data = false. Two private PostgreSQL servers of this test on free ports (never 5432/5433),
  skipped where PostgreSQL is not installed;
- install.sh's update of an nginx file of before 1.0.99: the sign-in limit did not cover signing
  in with Windows (api=kerberos-login) and with a certificate (api=cert-nonce) - only a new file
  had them. Added once, a second run changes nothing.
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rt9-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

PG_BIN = next((p for p in sorted(
    ('/usr/lib/postgresql/%s/bin' % v for v in os.listdir('/usr/lib/postgresql')), reverse=True)
    if os.path.exists(os.path.join(p, 'initdb'))), None) \
    if os.path.isdir('/usr/lib/postgresql') else None
try:
    import psycopg2
except ImportError:
    psycopg2 = None


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    if port in (5432, 5433, 8092, 3306):
        return free_port()
    return port


def as_user(user, cmd, **kw):
    if os.geteuid() == 0:
        cmd = ['runuser', '-u', user, '--'] + cmd
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kw)


def wait_port(port, s=30):
    end = time.time() + s
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


@unittest.skipUnless(PG_BIN and psycopg2, 'PostgreSQL is not installed')
class UpgradedByHand(unittest.TestCase):
    """Node 1 upgraded to a version with cert_roles, node 2 still the older one; then node 2."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='acme-rt9-pg-')
        os.chmod(cls.dir, 0o777)
        cls.ports, cls.datas = [], []
        for n in (1, 2):
            port, data = free_port(), os.path.join(cls.dir, 'n%d' % n)
            r = as_user('postgres', [os.path.join(PG_BIN, 'initdb'), '-D', data, '-A', 'trust',
                                     '-U', 'postgres', '-E', 'UTF8'])
            if r.returncode != 0:
                cls.tearDownClass()
                raise unittest.SkipTest('initdb: %s' % r.stdout[-300:])
            cls.datas.append(data)
            r = as_user('postgres', [os.path.join(PG_BIN, 'pg_ctl'), '-D', data, '-w', '-l',
                                     data + '.log', '-o',
                                     '-p %d -k %s -c listen_addresses=127.0.0.1 -c wal_level=logical'
                                     % (port, cls.dir), 'start'])
            if r.returncode != 0 or not wait_port(port):
                cls.tearDownClass()
                raise unittest.SkipTest('PostgreSQL did not start: %s' % r.stdout[-300:])
            cls.ports.append(port)
            subprocess.run(['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'postgres', '-qc',
                            "CREATE USER acme PASSWORD 'pw' SUPERUSER"], check=True,
                           stdout=subprocess.PIPE)
            subprocess.run(['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'postgres', '-qc',
                            'CREATE DATABASE acme OWNER acme'], check=True, stdout=subprocess.PIPE)

    @classmethod
    def tearDownClass(cls):
        for port in getattr(cls, 'ports', []):
            for sub in ('acme_from_1', 'acme_from_2'):
                try:
                    cls.sql(port, 'ALTER SUBSCRIPTION %s DISABLE' % sub)
                    cls.sql(port, 'ALTER SUBSCRIPTION %s SET (slot_name = NONE)' % sub)
                    cls.sql(port, 'DROP SUBSCRIPTION %s' % sub)
                except Exception:                       # noqa: BLE001
                    pass
        for data in getattr(cls, 'datas', []):
            as_user('postgres', [os.path.join(PG_BIN, 'pg_ctl'), '-D', data, '-m', 'immediate',
                                 'stop'])
        shutil.rmtree(cls.dir, ignore_errors=True)

    @staticmethod
    def sql(port, text, args=()):
        c = psycopg2.connect(host='127.0.0.1', port=port, dbname='acme', user='acme',
                             password='pw')
        c.autocommit = True
        try:
            cur = c.cursor()
            cur.execute(text, args)
            return cur.fetchall() if cur.description else None
        finally:
            c.close()

    def db(self, port):
        return E.Db('postgres', '127.0.0.1', port, 'acme', 'acme', 'pw', 10)

    def names(self, port, table):
        return sorted(r[0] for r in self.sql(port, 'SELECT name FROM %s' % table))

    def wait_for(self, port, table, name, s=20):
        end = time.time() + s
        while time.time() < end:
            if name in self.names(port, table):
                return True
            time.sleep(0.3)
        return False

    def test_rows_of_a_new_table_made_between_the_upgrades(self):
        p1, p2 = self.ports
        older = [(n, d) for n, d in E.SCHEMA if n != 'cert_roles']    # as 1.0.124 made them
        for port in (p1, p2):
            for _n, ddl in older:
                self.sql(port, ddl.format(**E.TYPES['postgres']))
            self.sql(port, "CREATE PUBLICATION acme_pub FOR ALL TABLES WITH "
                           "(publish = 'insert, update, delete')")
        for here, there, sub in ((p2, p1, 'acme_from_1'), (p1, p2, 'acme_from_2')):
            self.sql(here, "CREATE SUBSCRIPTION %s CONNECTION 'host=127.0.0.1 port=%d dbname=acme "
                           "user=acme password=pw' PUBLICATION acme_pub WITH (copy_data = false, "
                           "origin = none)" % (sub, there))
        # node 1 upgraded: its tables, and the other node's (ha_peer_columns)
        n1, n2 = self.db(p1), self.db(p2)
        n1.make_tables()
        for name, ddl in E.SCHEMA:
            if name not in set(n2.tables()):
                n2.run(ddl.format(**E.TYPES['postgres']))
        n2.add_missing_columns()
        # ...the plan's refresh of node 1's own subscription: its cert_roles is empty - nothing
        # comes, nothing breaks
        self.assertTrue(E.ha_refresh_sub(n1, 'acme_from_2'))
        now = time.time()
        n1.insert('cert_roles', {'name': 'Web deployer', 'caps': '["cert.view"]', 'created': now})
        n1.insert('cert_teams', {'name': 'Ops', 'kind': 'team', 'members': '[]', 'created': now})
        self.assertTrue(self.wait_for(p2, 'cert_teams', 'Ops'))
        self.assertEqual(self.names(p2, 'cert_roles'), [])  # node 2 does not take it yet
        # node 2 upgraded by hand: its first hourly look reads its subscription's tables again
        n2.make_tables()
        self.assertTrue(E.ha_refresh_sub(n2, 'acme_from_1'))
        self.assertTrue(self.wait_for(p2, 'cert_roles', 'Web deployer'),
                        'the role made on node 1 before node 2 was upgraded is not on node 2')
        n1.insert('cert_roles', {'name': 'Later', 'caps': '[]', 'created': time.time()})
        self.assertTrue(self.wait_for(p2, 'cert_roles', 'Later'))
        # and the other way still
        n2.insert('cert_tags', {'name': 'from-two', 'colour': 'ok', 'created': time.time()})
        self.assertTrue(self.wait_for(p1, 'cert_tags', 'from-two'))
        # Read again with nothing new to take: nothing copied, nothing doubled.
        self.assertFalse(E.ha_refresh_sub(n2, 'acme_from_1'))
        self.assertEqual(self.names(p2, 'cert_roles'), ['Later', 'Web deployer'])
        # A table not taken yet that has rows here already: nothing copied (they would collide).
        self.sql(p1, 'CREATE TABLE extra_t (id BIGSERIAL PRIMARY KEY, name TEXT)')
        self.sql(p2, 'CREATE TABLE extra_t (id BIGSERIAL PRIMARY KEY, name TEXT)')
        self.sql(p1, "INSERT INTO extra_t (name) VALUES ('one')")
        self.sql(p2, "INSERT INTO extra_t (name) VALUES ('two')")
        self.assertFalse(E.ha_refresh_sub(n2, 'acme_from_1'))
        time.sleep(1)
        self.assertEqual(self.names(p2, 'extra_t'), ['two'])
        for db in (n1, n2):
            db.close()


class NginxLoginLimit(unittest.TestCase):
    """install.sh's update of an nginx file that is there (upgrade or not)."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, 'install.sh')) as f:
            text = f.read()
        m = re.search(r'python3 - "\$NGINX_CONF" <<\'PY\'\n(.*?)\nPY\n', text, re.S)
        cls.script = os.path.join(TMP, 'nginx_update.py')
        with open(cls.script, 'w') as f:
            f.write(m.group(1))
        with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as f:
            cls.shipped = f.read()

    def update(self, text):
        p = os.path.join(TMP, 'acme.conf')
        with open(p, 'w') as f:
            f.write(text)
        subprocess.run([sys.executable, '-I', self.script, p], check=True, stdout=subprocess.PIPE)
        with open(p) as f:
            return f.read()

    def test_an_older_file_gets_the_windows_and_certificate_sign_ins(self):
        old = re.sub(r'(?m)^[^\n]*api=(kerberos-login|cert-nonce)[^\n]*\n', '', self.shipped)
        self.assertNotIn('kerberos-login', old)
        got = self.update(old)
        m = re.search(r'map \$args \$acme_login_key \{\n(.*?)\n\}', got, re.S)
        self.assertTrue(m)
        for api in ('login', 'kerberos-login', 'cert-nonce'):
            self.assertIn('"~(^|&)api=%s(&|$)"' % api, m.group(1))
        self.assertEqual(self.update(got), got)          # a second run changes nothing

    def test_the_old_arg_api_map(self):
        old = re.sub(r'(?m)^[^\n]*api=(kerberos-login|cert-nonce)[^\n]*\n', '', self.shipped)
        old = old.replace('map $args $acme_login_key {\n    "~(^|&)api=login(&|$)"   '
                          '$binary_remote_addr;', 'map $arg_api $acme_login_key {\n    "login"   '
                          '$binary_remote_addr;')
        self.assertIn('$arg_api', old)
        got = self.update(old)
        top = got.split('limit_req_zone')[0]
        self.assertIn('map $args $acme_login_key', top)
        self.assertIn('api=kerberos-login(&|$)', top)
        self.assertIn('api=cert-nonce(&|$)', top)
        self.assertEqual(self.update(got), got)

    def test_the_shipped_file_is_left_as_it_is(self):
        self.assertEqual(self.update(self.shipped), self.shipped)


if __name__ == '__main__':
    unittest.main(verbosity=2)
