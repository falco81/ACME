#!/usr/bin/env python3
"""A cluster backed up to another machine, lost, and built again from that backup - the same.

    python3 test/test_remote_backup_ha.py

1. A cluster of two nodes (acme1 on PostgreSQL :5432, acme2 on :5433, replicated both ways - the
   wizard for real) with what a working one holds: its own authorities, sources, certificates
   issued and revoked, a target and a deployment, an owner, a tag, a DNS set, accounts, settings,
   the SSH server wanted, the console at login, a key of root. As a cluster in production is set:
   PostgreSQL 16 on both, the link between the databases encrypted (TLS, verify-full), every
   daemon's own connection to its PostgreSQL encrypted too, the VIP address with VRRP, SELinux
   asked enforcing on both nodes, the guard against writes to the database (rows signed by
   root) on. Both daemons running.
2. A backup to another machine, as the pages make it (acme --rbackup-now): SFTP to an SSH server
   of its own (sshd on 127.0.0.1), signed in with a key made here, its host key trusted - the
   file, its .sha256 and its RESTORE.md there, locked with the backups' password.
3. Both nodes lost: their databases emptied. A machine installed from nothing (acme1 again, on
   PostgreSQL), the backup fetched from the SSH server and put back (acme --restore-bundle).
4. The cluster built again (acme --ha-setup on it, acme --ha-join on a second clean machine).
5. Both nodes of the new cluster hold every row the cluster had when it was backed up - what
   belongs to the moment and to the machine aside - the same key of the sealed secrets, and the
   second one issues a certificate with the authority's key it opened.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from test_ha import (Node, PG, PG2, PG_PORT, PG2_PORT, pg_empty, pg2_empty, need_pg,  # noqa: E402
                     pg_admin_ok, passphrase_of, wait_for, free_port, RootHelper, link_steps,
                     _link_failed, pg_admin_sql)
from test_restore_ha import DUMP, MOMENT, META_MOMENT, STATE, ROOT_PUB, OLD_MACHINE  # noqa: E402

BACKUP_PW = 'Backup-Password-4711!'
# Not compared besides: how the backups to another machine went (written after the copy was
# made - the copy cannot hold its own result).
META_MOMENT2 = META_MOMENT + ('rbackup:history', 'rbackup:run', 'rbackup:last', 'rbackup:state',
                              'rbackup:job', 'ask:', 'dbtls:node:', 'dbtls:rescued:', 'dbguard:')


def ssh_server(tmp, user_pub):
    """An SSH server of its own on 127.0.0.1 (root, only the key given) - the other machine."""
    port = free_port()
    keys = os.path.join(tmp, 'hostkey')
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', keys], check=True)
    auth = os.path.join(tmp, 'authorized_keys')
    with open(auth, 'w') as f:
        f.write(user_pub.strip() + '\n')
    os.chmod(auth, 0o600)
    conf = os.path.join(tmp, 'sshd_config')
    with open(conf, 'w') as f:
        f.write('Port %d\nListenAddress 127.0.0.1\nHostKey %s\nAuthorizedKeysFile %s\n'
                'PermitRootLogin prohibit-password\nPasswordAuthentication no\n'
                'StrictModes no\nUsePAM no\nPidFile %s\n'
                'Subsystem sftp internal-sftp\n' % (port, keys, auth, os.path.join(tmp, 'pid')))
    os.makedirs('/run/sshd', exist_ok=True)
    proc = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', conf],
                            stdout=subprocess.DEVNULL, stderr=open(os.path.join(tmp, 'sshd.log'), 'w'))
    end = time.time() + 20
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            return proc, port
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError('the SSH server did not start: %s' % open(os.path.join(tmp, 'sshd.log')).read())


class RemoteBackupOfCluster(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nodes, cls.sshd = [], None
        try:
            cls._setup()
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def _setup(cls):
        need_pg(cls)
        if not (pg_admin_ok(PG_PORT) and pg_admin_ok(PG2_PORT)):
            raise unittest.SkipTest('the replicated wizard needs root and psql as postgres on '
                                    'both clusters (%d, %d)' % (PG_PORT, PG2_PORT))
        if not shutil.which('/usr/sbin/sshd') and not shutil.which('sshd'):
            raise unittest.SkipTest('no sshd here for the other machine')
        cls.tmp = tempfile.mkdtemp(prefix='acme-rb-ha-')
        cls.cadir = tempfile.mkdtemp(prefix='acme-rb-ha-ca-')
        os.chmod(cls.cadir, 0o755)
        pg_empty()
        pg2_empty()
        # 1. The cluster.
        cls.a = Node('acme1', PG)
        cls.b = Node('acme2', PG2)
        cls.nodes += [cls.a, cls.b]
        for n in (cls.a, cls.b):
            n.env['ACME_HA_NO_RESTART'] = '1'
            n.env['ACME_HA_CA'] = os.path.join(cls.cadir, n.name + '-1.pem')
            os.makedirs(os.path.join(n.tmp, 'state', 'web'), exist_ok=True)
        cls.a.add_account()
        hb = os.path.join(cls.tmp, 'ha-bundle.json')
        got = cls.a.cli('--ha-setup', '--ha-peer', '127.0.0.1', '--ha-peer-port', str(PG2_PORT),
                        '--ha-address', '127.0.0.1', '--node-name', 'acme1', '--ha-bundle', hb,
                        '--yes')
        if got.returncode != 0:
            raise RuntimeError('--ha-setup: %s' % (got.stdout + got.stderr)[-3000:])
        cls.b.env['ACME_HA_PASSPHRASE'] = passphrase_of(got.stdout)
        got = cls.b.cli('--ha-join', hb, '--node-name', 'acme2', '--ha-address', '127.0.0.1',
                        '--yes')
        if got.returncode != 0:
            raise RuntimeError('--ha-join: %s' % (got.stdout + got.stderr)[-3000:])
        a = cls.a
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
                 'base=' + os.path.join(a.tmp, 'out-files')),
                ('--deploy-add', 'web.example.test', 'files', '--set',
                 'outputs=fullchain-pem {name}.crt\nkey-pem {name}.key 0600'),
                # deployed before the backup: what a daemon does on its own after the restore
                # (a deployment still waiting) is not then counted as a difference
                ('--deploy', 'web.example.test'),
                ('--team-add', 'Ops', '--members', 'local:keeper=manage'),
                ('--tag-add', 'prod', '--colour', 'crit'),
                ('--dns-set-add', 'Inside', '--servers', '192.0.2.53')):
            got = a.cli(*args)
            if got.returncode != 0:
                raise RuntimeError('%s: %s' % (args, (got.stderr or got.stdout)[-2000:]))
        a.py(STATE.replace('PUB', repr(ROOT_PUB)).replace('OLD', repr(OLD_MACHINE)))
        for n in (cls.a, cls.b):                # the guard on both nodes
            got = n.cli('--set', 'db_guard=1')
            if got.returncode != 0:
                raise RuntimeError('db_guard: %s' % (got.stderr or got.stdout))
        # 2. The other machine, and the backups to it (as the pages set them).
        sdir = os.path.join(cls.tmp, 'sshd')
        cls.remote = os.path.join(cls.tmp, 'remote-backups')
        os.makedirs(sdir)
        os.makedirs(cls.remote)
        made = json.loads(a.py(r'''
import acmelib.engine as E
private, public = E.ssh_keygen('acme-backup@acme1')
print(json.dumps({'private': private, 'public': public}))
''').strip().splitlines()[-1])
        cls.key_private = made['private']
        cls.sshd, cls.sport = ssh_server(sdir, made['public'])
        got = a.py(r'''
import acmelib.engine as E
E.HA_STORE['store'] = st
st.save_setting('rbackup_password', E.seal_secret(%r), 'test')
t = E.rb_save(st, {'kind': 'sftp', 'name': 'the other machine', 'host': '127.0.0.1',
                   'port': %d, 'user': 'root', 'path': %r, 'enabled': 1}, 'test')
lines, fps = E.ssh_keyscan('127.0.0.1', %d)
E.rb_set_fields(st, t['id'], 'test', 'trusted', hostkey=lines,
                key=E.seal_secret(%r, bind=E.RB_BIND), pub=%r)
print(json.dumps(E.rb_try(E.rb_target(st, t['id']))))
''' % (BACKUP_PW, cls.sport, cls.remote, cls.sport, made['private'], made['public']))
        tried = json.loads(got.strip().splitlines()[-1])
        if not tried.get('ok'):
            raise RuntimeError('the destination does not work: %s' % tried)
        # Both nodes running, as a cluster at work.
        for n in (cls.a, cls.b):
            n.set_conf(api_port=n.port, dns_port=n.dns_port)
        cls.a.start()
        cls.b.start()
        wait_for(lambda: len([x for x in cls.a.ok('GET', '/api/ha')['nodes'] if x.get('alive')]) == 2,
                 90, 1, 'both nodes alive')
        # As in production: TLS on the link and on each daemon's own connection, the VIP with
        # VRRP, SELinux enforcing asked on both, the guard on (above).
        cls.helper = RootHelper([cls.a, cls.b])
        cls.tls_on(cls.a, cls.b)
        cls.a.py(r'''
import acmelib.engine as E
E.HA_STORE['store'] = st
v = E.vip_checked({'address': '192.0.2.250/24', 'vrid': 77, 'fqdn': 'acme.example.test'}, st)
E.vip_set(st, 'test', on=True, **v)
for n in ('acme1', 'acme2'):
    E.selinux_ask(st, n, 'enforce', 'test')
''')
        cls.helper.stop()
        cls.sync()
        # What the cluster holds at the moment of the backup, on both nodes.
        cls.before_a = json.loads(cls.a.py(DUMP).strip().splitlines()[-1])
        cls.before_b = json.loads(cls.b.py(DUMP).strip().splitlines()[-1])
        got = cls.a.cli('--rbackup-now', '--json')
        cls.backup_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--rbackup-now: %s' % cls.backup_out[-3000:])
        cls.sent = json.loads(got.stdout[got.stdout.index('{'):])
        # 3. Both lost.
        for n in (cls.a, cls.b):
            n.stop()
        pg_empty()
        pg2_empty()
        # A machine from nothing; the backup fetched from the other machine, as a person would.
        cls.r = Node('fresh', PG)
        cls.nodes.append(cls.r)
        keyf = os.path.join(cls.tmp, 'fetch.key')
        with open(keyf, 'w') as f:
            f.write(cls.key_private)
        os.chmod(keyf, 0o600)
        fetched = os.path.join(cls.r.tmp, 'from-remote')
        os.makedirs(fetched)
        got = subprocess.run(['scp', '-q', '-P', str(cls.sport), '-i', keyf, '-o',
                              'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                              'root@127.0.0.1:%s/%s' % (cls.remote, cls.sent['file']),
                              'root@127.0.0.1:%s/%s.sha256' % (cls.remote, cls.sent['file']),
                              fetched + '/'], capture_output=True, text=True, timeout=60)
        if got.returncode != 0:
            raise RuntimeError('fetching the backup: %s' % got.stderr)
        cls.bundle = os.path.join(fetched, cls.sent['file'])
        cls.r.env['ACME_BACKUP_PASSWORD'] = BACKUP_PW
        got = cls.r.cli('--restore-bundle', cls.bundle, '--yes')
        cls.restore_out = got.stdout + got.stderr
        if got.returncode != 0:
            raise RuntimeError('--restore-bundle: %s' % cls.restore_out[-3000:])
        # 4. The cluster built again: the restored one first, a second clean machine joins.
        cls.n2 = Node('acme2', PG2)
        cls.nodes.append(cls.n2)
        for n in (cls.r, cls.n2):
            n.env['ACME_HA_NO_RESTART'] = '1'
            n.env['ACME_HA_CA'] = os.path.join(cls.cadir, n.name + '-2.pem')
            os.makedirs(os.path.join(n.tmp, 'state', 'web'), exist_ok=True)
        cls.r.start()
        time.sleep(5)
        cls.r.stop()
        hb2 = os.path.join(cls.tmp, 'ha-bundle-2.json')
        got = cls.r.cli('--ha-setup', '--ha-peer', '127.0.0.1', '--ha-peer-port', str(PG2_PORT),
                        '--ha-address', '127.0.0.1', '--node-name', 'acme1', '--ha-bundle', hb2,
                        '--yes')
        if got.returncode != 0:
            raise RuntimeError('--ha-setup again: %s' % (got.stdout + got.stderr)[-3000:])
        cls.n2.env['ACME_HA_PASSPHRASE'] = passphrase_of(got.stdout)
        got = cls.n2.cli('--ha-join', hb2, '--node-name', 'acme2', '--ha-address', '127.0.0.1',
                         '--yes')
        if got.returncode != 0:
            raise RuntimeError('--ha-join again: %s' % (got.stdout + got.stderr)[-3000:])
        cls.after_a = json.loads(cls.r.py(DUMP).strip().splitlines()[-1])
        cls.after_b = json.loads(cls.n2.py(DUMP).strip().splitlines()[-1])
        # The new cluster at work: what it was set to comes back by itself (the encrypted link,
        # each connection encrypted, the VIP, SELinux asked again on the new machines).
        for n in (cls.r, cls.n2):
            n.set_conf(api_port=n.port, dns_port=n.dns_port)
        cls.helper2 = RootHelper([cls.r, cls.n2])
        cls.r.start()
        cls.n2.start()
        wait_for(lambda: len([x for x in cls.r.ok('GET', '/api/ha')['nodes'] if x.get('alive')]) == 2,
                 90, 1, 'both new nodes alive')
        try:
            wait_for(lambda: link_steps(cls.r) == {'acme1': 'done', 'acme2': 'done'} or
                     _link_failed(cls.r), 300, 2, 'the link encrypted again')
        except Exception:                               # noqa: BLE001
            pass
        cls.link_after = (link_steps(cls.r), link_steps(cls.n2))
        # each node's own connection encrypted again, and the guard on, by themselves
        try:
            wait_for(lambda: all(n.conf.get('db_tls') == 'verify-full' and n.conf.get('db_guard')
                                 for n in (cls.r, cls.n2)), 300, 3,
                     'the connections encrypted and the guard on again')
        except Exception:                               # noqa: BLE001
            pass
        cls.views = {n.name: json.loads(n.py(r'''
import acmelib.engine as E
E.HA_STORE['store'] = st
print(json.dumps({'vip': E.vip_conf(st), 'selinux': E.selinux_view(st)['nodes'],
                  'conf': {k: E.CONFIG.get(k) for k in ('ha_mode', 'ha_tls', 'db_tls', 'db_guard',
                                                        'db_engine', 'db_port')}}, default=str))
''').strip().splitlines()[-1]) for n in (cls.r, cls.n2)}
        cls.vip_before = json.loads(next(r['v'] for r in cls.before_a['tables']['meta']
                                         if r['k'] == 'web:vip'))

    @classmethod
    def tls_on(cls, a, b):
        """The link between the databases encrypted (the button of Settings -> High availability),
        then each daemon's own connection to its PostgreSQL (Settings -> The database)."""
        a.ok('POST', '/api/ha', {'action': 'tls_link'})
        for n in (a, b):
            wait_for(lambda: link_steps(n) == {'acme1': 'done', 'acme2': 'done'} or _link_failed(n),
                     300, 2, 'the link encrypted (%s)' % n.name)
            if link_steps(n) != {'acme1': 'done', 'acme2': 'done'}:
                raise RuntimeError('the link: %s %s' % (link_steps(n), n.out()[-2000:]))
        got = a.ok('POST', '/api/dbtls', {'action': 'apply', 'phase': 'connect',
                                          'mode': 'verify-full', 'ca_source': 'acme'})

        def done():
            r = a.ok('POST', '/api/dbtls', {'action': 'result', 'id': got.get('id')})['nodes']
            return r if len(r) == 2 and all(x for x in r.values()) else None
        res = wait_for(done, 120, 1, 'each connection encrypted')
        bad = {k: v for k, v in res.items() if not (v or {}).get('ok')}
        if bad:
            raise RuntimeError('the connections: %s' % bad)
        for n in (a, b):
            if n.conf.get('db_tls') != 'verify-full':
                raise RuntimeError('%s: db_tls %r' % (n.name, n.conf.get('db_tls')))

    @classmethod
    def sync(cls):
        mark = 'sync:%s' % time.time()
        from test_ha import pg_conn, db_rows
        for port, other, nm in ((PG_PORT, PG2_PORT, 'a'), (PG2_PORT, PG_PORT, 'b')):
            c = pg_conn(port)
            c.cursor().execute("INSERT INTO meta (k, v) VALUES (%s, '1')", (mark + ':' + nm,))
            c.close()
            wait_for(lambda: db_rows(other, 'SELECT 1 FROM meta WHERE k = %s', (mark + ':' + nm,)),
                     30, 0.3, 'replication')

    @classmethod
    def tearDownClass(cls):
        for n in getattr(cls, 'nodes', []):
            try:
                n.cleanup()
            except Exception:                           # noqa: BLE001
                pass
        if getattr(cls, 'sshd', None):
            cls.sshd.kill()
        for h in ('helper', 'helper2'):
            if getattr(cls, h, None):
                getattr(cls, h).stop()
        if not os.environ.get('ACME_TEST_KEEP'):
            for port in (PG_PORT, PG2_PORT):
                try:
                    pg_empty(port)
                except Exception:                       # noqa: BLE001
                    pass

    def same(self, got, base, what):
        for t, rows in base['tables'].items():
            if t in MOMENT:
                continue

            def keyed(rs):
                rs = [{k: v for k, v in r.items() if k not in ('last_in', 'last_from')}
                      if t == 'accounts' else r for r in rs]
                # what a machine said it had, turned into what is wanted of the new one when the
                # backup was put back (the console at login): checked apart, in test_10
                return {json.dumps(r, sort_keys=True, default=str) for r in rs
                        if not (t == 'meta' and str(r.get('k', '')).startswith(META_MOMENT2))
                        and not (t == 'meta' and str(r.get('k', '')).startswith('console:want:')
                                 and 'the backup put back' in str(r.get('v')))}
            x, y = keyed(rows), keyed(got['tables'].get(t, []))
            self.assertEqual(x, y, '%s: table %s differs - only then: %s, only now: %s' % (
                what, t, sorted(x - y)[:3], sorted(y - x)[:3]))
        for t in ('certs', 'cert_versions', 'cert_cas', 'cert_issuers', 'cert_targets',
                  'cert_deploys', 'cert_teams', 'cert_tags', 'dns_sets', 'accounts', 'settings'):
            self.assertTrue(got['tables'][t], '%s: nothing in %s' % (what, t))

    def test_1_the_pair_was_one(self):
        # the two nodes of the cluster held the same before (the yardstick itself sound)
        self.same(self.before_b, self.before_a, 'acme2 against acme1, at the backup')

    def test_2_sent_to_the_other_machine_locked(self):
        self.assertTrue(self.sent.get('ok'), self.backup_out)
        self.assertTrue(self.sent.get('encrypted'))
        there = sorted(os.listdir(self.remote))
        self.assertIn(self.sent['file'], there)
        self.assertIn(self.sent['file'] + '.sha256', there)
        self.assertTrue([x for x in there if x.endswith('-RESTORE.md')], there)
        with open(self.bundle, 'rb') as f:
            head = f.read(64)
        self.assertNotIn(b'BEGIN', head)                # locked, not readable
        import hashlib
        with open(self.bundle, 'rb') as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        with open(self.bundle + '.sha256') as f:
            self.assertIn(sha, f.read())

    def test_3_put_back_as_it_was(self):
        self.assertEqual(self.after_a['node'], 'acme1')
        self.same(self.after_a, self.before_a, 'acme1 put back and in a cluster again')

    def test_4_the_new_second_node_the_same(self):
        self.assertEqual(self.after_b['node'], 'acme2')
        self.same(self.after_b, self.before_b, 'the new acme2')

    def test_5_the_same_key_of_the_secrets(self):
        with open(os.path.join(self.a.tmp, 'state', 'secrets.key')) as f:
            then = f.read()
        for n in (self.r, self.n2):
            with open(os.path.join(n.tmp, 'state', 'secrets.key')) as f:
                self.assertEqual(f.read(), then, n.name)

    def test_6_the_cluster_settings(self):
        c1, c2 = self.r.conf, self.n2.conf
        self.assertEqual((c1['ha_mode'], c1['ha_slot']), ('replicated', 1))
        self.assertEqual((c2['ha_mode'], c2['ha_slot']), ('replicated', 2))
        self.assertTrue(self.before_a['guard'] and self.before_b['guard'])
        # put back: on at once; the new second node: on by itself once it runs beside the first
        self.assertTrue(self.after_a['guard'])
        for n in (self.r, self.n2):
            self.assertTrue(n.conf.get('db_guard'), n.name)

    def test_8_the_link_and_the_connections_encrypted_again(self):
        self.assertEqual(self.link_after[0], {'acme1': 'done', 'acme2': 'done'}, self.link_after)
        for n in (self.r, self.n2):
            c = self.views[n.name]['conf']
            self.assertEqual(c['ha_tls'], 'verify-full', n.name)
            self.assertEqual(n.conf.get('db_tls'), 'verify-full', n.name)
            self.assertEqual(c['db_engine'], 'postgres', n.name)
        for port in (PG_PORT, PG2_PORT):
            self.assertEqual(pg_admin_sql(port, 'SHOW ssl'), 'on')
            self.assertTrue(pg_admin_sql(port, 'SHOW server_version').startswith('16'))
            conn = pg_admin_sql(port, "SELECT subconninfo FROM pg_subscription WHERE subname LIKE "
                                      "'acme!_from!_%' ESCAPE '!'", 'acme')
            self.assertIn("sslmode='verify-full'", conn)
            # the daemons' own connections: encrypted
            enc = pg_admin_sql(port, "SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a "
                                     "ON a.pid = s.pid WHERE a.datname = 'acme' AND a.usename = "
                                     "'acme' AND NOT s.ssl", 'acme')
            self.assertEqual(enc.strip(), '0', 'an acme connection without TLS on %d' % port)

    def test_9_the_vip_and_selinux_as_they_were(self):
        for n in (self.r, self.n2):
            v = self.views[n.name]['vip']
            for k in ('on', 'address', 'vrid', 'fqdn'):
                self.assertEqual(v.get(k), self.vip_before.get(k), (n.name, k))
            se = {x['name']: x for x in self.views[n.name]['selinux']}
            for node in ('acme1', 'acme2'):
                # enforcing asked of each new machine again - not taken as done there
                # (here there is no SELinux: tried, and said so)
                self.assertTrue(se[node]['pending'] == 'enforce' or se[node]['action'] == 'enforce',
                                (n.name, node, se[node]))

    def test_7_the_second_node_works_with_what_came_back(self):
        self.n2.set_conf(api_port=self.n2.port)
        got = self.n2.cli('--renew', 'web.example.test', '--force')
        self.assertEqual(got.returncode, 0, (got.stdout + got.stderr)[-2000:])
        got = self.n2.cli('--deploy', 'web.example.test')
        self.assertEqual(got.returncode, 0, (got.stdout + got.stderr)[-2000:])

    def test_10_the_console_at_login_asked_of_the_new_machines(self):
        def meta(d, k):
            return next((r['v'] for r in d['tables']['meta'] if r['k'] == k), None)
        for node in ('acme1', 'acme2'):
            was = json.loads(meta(self.before_a, 'console:now:' + node) or '{}')
            if 'on' not in was:
                continue
            now = json.loads(meta(self.after_a, 'console:want:' + node) or '{}')
            self.assertEqual(bool(now.get('on')), bool(was.get('on')), node)


if __name__ == '__main__':
    unittest.main(verbosity=2)
