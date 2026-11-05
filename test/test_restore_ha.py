#!/usr/bin/env python3
"""A backup put back on a clean installation, a cluster built from it - everything as it was.

    python3 test/test_restore_ha.py

1. An installation (node acme1, SQLite) with what a working one holds: its own authorities,
   sources, certificates issued and revoked, a target and a deployment, an owner, a tag, a DNS
   set, accounts, settings (the password policy among them), the SSH server wanted, the console
   at login, the time, a key of root made on the pages, its local users and SSH keys as its
   machine said, the SNMP engine, the guard against writes to the database on.
2. Its backup (as the daemon makes it, the same as a remote one) put back on a clean
   installation on PostgreSQL: every row of every table, the node's name, the key of the sealed
   secrets, the guard on again, the SNMP engine the same.
3. That node started on its new machine: what the old machine said it had is forgotten (so the
   SSH server, the time, the console and the password policy are put in there again), its users
   kept to be made again, the key of root made on the pages asked on again.
4. A cluster built from it (the replicated wizard, a second clean node joining): the second node
   has every row too, opens the sealed secrets (its own authority signs a renewal there).
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from test_ha import (Node, PG, PG2, PG_PORT, PG2_PORT, pg_empty, pg2_empty, need_pg,  # noqa: E402
                     pg_admin_ok, passphrase_of, wait_for, db_rows)

DUMP = r'''
import acmelib.engine as E
out = {}
for t in E.TABLES:
    out[t] = st.db.rows('SELECT * FROM %s' % t)
print(json.dumps({'node': E.node_name(), 'guard': bool(E.CONFIG.get('db_guard')),
                  'tables': out}, default=str))
'''
# Not compared: what belongs to the moment and to the machine, and what the putting back, the
# start on the new machine and the cluster's wizard write themselves.
MOMENT = ('sessions', 'events', 'cert_jobs')
META_MOMENT = ('upgrade:', 'node:', 'maint:', 'restore', 'putback', 'conf_serial', 'sig:', 'ha',
               'hatls', 'dbtls', 'split:', 'clock:', 'lease', 'leader', 'sync:', 'beat_asked',
               'host:sshd:now:', 'host:sshd:fmt:', 'ntp:', 'console:now:', 'host:users:',
               'host:sshkeys:', 'host:selinux:', 'net:', 'fw:', 'snmp:boots:', 'web:', 'vip',
               'db_sizes:', 'tune_', 'isemon:client:', 'sshotp:', 'rbackup:verified:', 'rbackup:vforgot:', 'osu',
               'lockouts:', 'power:', 'health', 'host:health', 'alerts:', 'alert', 'certs:',
               'cert_', 'job', 'mail', 'sms', 'last_', 'backup', 'dumps', 'guard',
               'custom-modules:', 'schema:', 'downgrade:', 'host:rootkey:again:', 'acme:host:')
OLD_MACHINE = 'the-old-machine-0123456789abcdef'
ROOT_PUB = ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMbn6v1d7Y0dvd0Ac8Pw2l4xQ5gq3p8yYb6i3m2lKx9T '
            'acme@pages')

STATE = r'''
import acmelib.engine as E, time
from acmelib.certs import api
E.HA_STORE['store'] = st
me = E.node_name()
# The password policy of the local users (as otp 1.0.245): set for the cluster.
st.set_meta('host:pwpolicy:conf', json.dumps(dict(E.PWP_DEFAULT, managed=True, minlen=14,
            max_days=90, at=time.time(), by='test')))
st.save_setting('session_hours', 7, 'test')
st.save_setting('backup_at@' + me, '04:15', 'test')
st.set_meta('host:sshd:conf', json.dumps({'manage': True, 'permit_root': 'prohibit-password',
            'password': False, 'port': 22, 'hash': 'h-sshd-1', 'radius': False}))
st.set_meta('host:sshd:keep', json.dumps({'hash': 'h-sshd-1', 'at': time.time() - 3600}))
# What the old machine said it had - all of it in place there.
st.set_meta('host:sshd:now:' + me, json.dumps({'hash': 'h-sshd-1', 'kept_at': time.time() - 3500,
            'at': time.time() - 100}))
st.set_meta('console:want:' + me, json.dumps({'id': 'c1', 'on': True}))
st.set_meta('console:now:' + me, json.dumps({'done': 'c1', 'on': True, 'at': time.time() - 100}))
st.set_meta('ntp:applied:' + me, json.dumps({'hash': 'n1', 'ok': True, 'at': time.time() - 100}))
st.set_meta('host:users:now:' + me, json.dumps({'at': time.time() - 100, 'policy': 'p1', 'users': [
    {'name': 'root', 'uid': 0, 'root': True},
    {'name': 'falco', 'uid': 1000, 'gecos': 'Falco', 'shell': '/bin/bash', 'sudo': True,
     'login': True, 'password': True}]}))
st.set_meta('host:sshkeys:now:' + me, json.dumps({'at': time.time() - 100, 'keys': [
    {'fp': 'SHA256:aaaa', 'type': 'rsa', 'bits': 4096, 'comment': 'root@laptop'}]}))
st.set_meta('host:rootkey:all', json.dumps({'scope': 'all', 'pub': PUB, 'fp': 'SHA256:pages',
            'kind': 'ed25519', 'how': 'made', 'by': 'test', 'at': time.time() - 3600}))
st.set_meta('host:sshd:now:acme2', json.dumps({'hash': 'h-sshd-1', 'at': time.time() - 100}))
st.set_meta('host:users:now:acme2', json.dumps({'at': time.time() - 100, 'users': [
    {'name': 'eva', 'uid': 1001, 'shell': '/bin/bash', 'login': True, 'password': True}]}))
st.set_meta('snmp:engine:' + me, '80001f8805aabbccddeeff00112233')
st.set_meta('snmp:boots:' + me, '41')
# The old machine's last heartbeat: its machine, long ago.
st.set_meta('node:' + me, json.dumps({'at': time.time() - 7200, 'mid': OLD, 'version': E.__version__}))
'''


class RestoreThenCluster(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls._setup()
        except BaseException:
            # A setup that failed leaves no daemon behind on the shared PostgreSQL (the other
            # tests of the clusters found its node acme1 there, the leader).
            cls.tearDownClass()
            raise

    @classmethod
    def _setup(cls):
        need_pg(cls)
        if not (pg_admin_ok(PG_PORT) and pg_admin_ok(PG2_PORT)):
            raise unittest.SkipTest('the replicated wizard needs root and psql as postgres on '
                                    'both clusters (%d, %d)' % (PG_PORT, PG2_PORT))
        cls.nodes = []
        cls.tmp = tempfile.mkdtemp(prefix='acme-restore-ha-')
        # 1. The installation as it was.
        cls.o = Node('acme1')
        cls.nodes.append(cls.o)
        o = cls.o
        for args in (
                ('--ca-create', 'Root T', '--subject', 'CN=Root T,O=Example', '--key-type', 'ec-256',
                 '--days', '3650'),
                ('--ca-sub', 'Issuing T', '--parent', 'Root T', '--subject', 'CN=Issuing T,O=Example',
                 '--key-type', 'ec-256', '--days', '1825'),
                ('--source-add', 'Own', '--kind', 'internal_ca', '--set', 'ca=Issuing T'),
                ('--cert-add', 'web.example.test', '--issuer', 'Own', '--names',
                 'web.example.test,www.example.test'),
                ('--cert-add', 'old.example.test', '--issuer', 'Own', '--names', 'old.example.test'),
                ('--renew', 'web.example.test', '--force'),
                ('--renew', 'old.example.test', '--force'),
                ('--revoke', 'old.example.test', '--reason', 'superseded', '--yes'),
                ('--target-add', 'files', '--kind', 'local', '--set',
                 'base=' + os.path.join(o.tmp, 'out-files')),
                ('--deploy-add', 'web.example.test', 'files', '--set',
                 'outputs=fullchain-pem {name}.crt\nkey-pem {name}.key 0600'),
                ('--team-add', 'Ops', '--members', 'local:keeper=manage'),
                ('--tag-add', 'prod', '--colour', 'crit'),
                ('--dns-set-add', 'Inside', '--servers', '192.0.2.53')):
            got = o.cli(*args)
            if got.returncode != 0:
                raise RuntimeError('%s: %s' % (args, (got.stderr or got.stdout)[-2000:]))
        o.add_account()
        o.py(STATE.replace('PUB', repr(ROOT_PUB)).replace('OLD', repr(OLD_MACHINE)))
        got = o.cli('--set', 'db_guard=1')
        if got.returncode != 0:
            raise RuntimeError('db_guard: %s' % (got.stderr or got.stdout))
        cls.before = json.loads(o.py(DUMP).strip().splitlines()[-1])
        # 2. Its backup, as the daemon makes it (and sends it away).
        out = os.path.join(cls.tmp, 'bk')
        os.makedirs(out)
        cls.bundle = o.py('import acmelib.engine as E\nprint(E.rb_build(st, %r)[0])' % out).strip()
        # 3. A clean installation on PostgreSQL, the backup put back.
        pg_empty()
        pg2_empty()
        cls.r = Node('fresh', PG)
        cls.nodes.append(cls.r)
        got = cls.r.cli('--restore-bundle', cls.bundle, '--yes')
        cls.restore_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--restore-bundle: %s' % cls.restore_out[-3000:])
        cls.restored = json.loads(cls.r.py(DUMP).strip().splitlines()[-1])
        # 4. Started there once (its new machine), then the cluster built from it.
        cls.r.env['ACME_HA_NO_RESTART'] = '1'
        cls.r.start()
        wait_for(lambda: cls.r.py("print(st.get_meta('host:users:before:acme1') or '')").strip(),
                 60, 1, 'the users of the old machine kept')
        wait_for(lambda: ROOT_PUB.split()[1] in cls.r.py(
            "print(' '.join(r['v'] for r in st.db.rows(\"SELECT v FROM meta WHERE k LIKE "
            "'host:sshkeys:want%'\")))"), 90, 2, 'the key of root asked on again')
        cls.after_start = json.loads(cls.r.py(DUMP).strip().splitlines()[-1])
        cls.r.stop()
        cls.b = Node('acme2', PG2)
        cls.nodes.append(cls.b)
        cls.cadir = tempfile.mkdtemp(prefix='acme-restore-ha-ca-')
        os.chmod(cls.cadir, 0o755)
        for n in (cls.r, cls.b):
            n.env['ACME_HA_NO_RESTART'] = '1'
            n.env['ACME_HA_CA'] = os.path.join(cls.cadir, n.name + '.pem')
            os.makedirs(os.path.join(n.tmp, 'state', 'web'), exist_ok=True)
        hb = os.path.join(cls.tmp, 'ha-bundle.json')
        got = cls.r.cli('--ha-setup', '--ha-peer', '127.0.0.1', '--ha-peer-port', str(PG2_PORT),
                        '--ha-address', '127.0.0.1', '--node-name', 'acme1', '--ha-bundle', hb,
                        '--yes')
        if got.returncode != 0:
            raise RuntimeError('--ha-setup: %s' % (got.stdout + got.stderr)[-3000:])
        cls.b.env['ACME_HA_PASSPHRASE'] = passphrase_of(got.stdout)
        got = cls.b.cli('--ha-join', hb, '--node-name', 'acme2', '--ha-address', '127.0.0.1',
                        '--yes')
        cls.join_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--ha-join: %s' % cls.join_out[-3000:])
        cls.joined = json.loads(cls.b.py(DUMP).strip().splitlines()[-1])
        cls.r_joined = json.loads(cls.r.py(DUMP).strip().splitlines()[-1])

    @classmethod
    def tearDownClass(cls):
        for n in getattr(cls, 'nodes', []):
            try:
                n.cleanup()
            except Exception:                           # noqa: BLE001
                pass
        if not os.environ.get('ACME_TEST_KEEP'):
            for port in (PG_PORT, PG2_PORT):
                try:
                    pg_empty(port)
                except Exception:                       # noqa: BLE001
                    pass

    def same(self, got, what, base=None):
        base = base or self.before
        for t, rows in base['tables'].items():
            if t in MOMENT:
                continue

            def keyed(rs):
                # When an account last signed in is the moment's too (the test signs in).
                rs = [{k: v for k, v in r.items() if k not in ('last_in', 'last_from')}
                      if t == 'accounts' else r for r in rs]
                return {json.dumps(r, sort_keys=True, default=str) for r in rs
                        if not (t == 'meta' and str(r.get('k', '')).startswith(META_MOMENT))}
            a, b = keyed(rows), keyed(got['tables'].get(t, []))
            self.assertEqual(a, b, '%s: table %s differs - only before: %s, only after: %s' % (
                what, t, sorted(a - b)[:3], sorted(b - a)[:3]))
        for t in ('certs', 'cert_versions', 'cert_cas', 'cert_issuers', 'cert_targets',
                  'cert_deploys', 'cert_teams', 'cert_tags', 'dns_sets', 'accounts', 'settings'):
            self.assertTrue(got['tables'][t], '%s: nothing in %s' % (what, t))

    def meta(self, got, k):
        return next((r['v'] for r in got['tables']['meta'] if r['k'] == k), None)

    def test_1_put_back_whole(self):
        self.assertEqual(self.restored['node'], 'acme1')
        self.same(self.restored, 'put back')

    def test_2_the_guard_on_again(self):
        self.assertTrue(self.before['guard'])
        self.assertTrue(self.restored['guard'], self.restore_out)
        self.assertIn('guard against writes', self.restore_out)

    def test_3_the_snmp_engine_kept(self):
        got = self.r.py("import acmelib.engine as E\nprint(E.snmp_engine_id(st).hex())").strip()
        self.assertEqual(got.splitlines()[-1], '80001f8805aabbccddeeff00112233')
        boots = int(self.r.py("import acmelib.engine as E\nprint(E.snmp_boots_next(st))").strip().splitlines()[-1])
        self.assertGreater(boots, 41)

    def test_4_the_new_machine_given_what_is_wanted(self):
        a = self.after_start
        # What the old machine said it had: forgotten, so that it is put in here.
        for k in ('console:now:acme1', 'ntp:applied:acme1', 'host:users:now:acme1'):
            v = json.loads(self.meta(a, k) or '{}')
            self.assertFalse(v.get('done') == 'c1' or v.get('hash') == 'n1' or v.get('policy') == 'p1'
                             or 'falco' in json.dumps(v.get('users') or []),
                             '%s still the old machine\'s: %s' % (k, v))
        sshd = json.loads(self.meta(a, 'host:sshd:now:acme1') or '{}')
        self.assertNotEqual(sshd.get('hash'), 'h-sshd-1', 'the SSH server taken as in place')
        # The wishes themselves kept.
        self.assertTrue(self.meta(a, 'host:sshd:conf'))
        self.assertTrue(self.meta(a, 'console:want:acme1'))
        # Its users kept, to be made again; the key of root made on the pages asked on again.
        before = json.loads(self.meta(a, 'host:users:before:acme1'))
        self.assertEqual([u['name'] for u in before['users']], ['falco'])
        self.assertTrue(before['users'][0]['sudo'])
        self.assertIn('SHA256:aaaa', self.meta(a, 'host:sshkeys:before:acme1'))
        asks = ' '.join(r['v'] for r in a['tables']['meta'] if r['k'].startswith('host:sshkeys:want'))
        self.assertIn(ROOT_PUB.split()[1], asks)

    def test_4b_the_other_node_built_again_too(self):
        a = self.after_start
        sshd = json.loads(self.meta(a, 'host:sshd:now:acme2') or '{}')
        self.assertNotEqual(sshd.get('hash'), 'h-sshd-1')
        before = json.loads(self.meta(a, 'host:users:before:acme2') or '{}')
        self.assertEqual([u['name'] for u in before.get('users') or []], ['eva'])

    def test_5_the_cluster_built_from_it(self):
        self.assertEqual(self.joined['node'], 'acme2')
        # Every row the first node has (the one put back, which ran once since), on the second.
        self.same(self.joined, 'the second node', self.r_joined)
        # And what was before, there too: the certificates, their keys, every version.
        for t in ('certs', 'cert_versions', 'cert_cas', 'cert_ca_versions', 'cert_issuers',
                  'accounts', 'settings'):
            self.assertEqual(len(self.joined['tables'][t]), len(self.before['tables'][t]), t)

    def test_6_the_second_node_opens_the_secrets(self):
        self.b.set_conf(api_port=self.b.port)
        got = self.b.cli('--renew', 'web.example.test', '--force')
        self.assertEqual(got.returncode, 0, (got.stdout + got.stderr)[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
