#!/usr/bin/env python3
"""Hunt w7, deploy: the SSH layer and the deployment engine.

    python3 test/test_hunt_rw7_deploy.py
"""
import os
import json
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-w7-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import api_sshkeys as K  # noqa: E402
from acmelib.certs import runtime as RT  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from acmelib.certs import ca as CA, deployer, jobs, notices, renewer  # noqa: E402
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry()

KEY = 'AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def is_open(port):
    with socket.socket() as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


class HostNamedLikeAKeyType(unittest.TestCase):
    """A known_hosts line of a host whose name begins like a key type (ssh-gw, sk-web01)
    was dropped: the key asked again every run, any key taken with trust_first."""

    def test_lines(self):
        for host in ('ssh-gw.example.com', 'sk-web01,10.0.0.5', 'ecdsa-host', '[ssh-x]:2222'):
            got = RT.hostkey_lines('%s ssh-ed25519 %s' % (host, KEY))
            self.assertEqual(got, ['%s ssh-ed25519 %s' % (RT.HOSTKEY_ALIAS, KEY)], host)
        # the bare form and the usual one as before
        self.assertEqual(RT.hostkey_lines('ssh-ed25519 %s root@x' % KEY),
                         ['%s ssh-ed25519 %s' % (RT.HOSTKEY_ALIAS, KEY)])
        self.assertEqual(RT.hostkey_lines('web1 ssh-ed25519 %s' % KEY),
                         ['%s ssh-ed25519 %s' % (RT.HOSTKEY_ALIAS, KEY)])
        self.assertEqual(RT.hostkey_lines('@revoked ssh-gw ssh-ed25519 %s' % KEY), [])

    def test_page_report(self):
        line = 'ssh-gw.example.com ssh-ed25519 %s' % KEY
        self.assertEqual(K._line_hosts(line), {'ssh-gw.example.com'})
        self.assertEqual(K._line_hosts('ssh-ed25519 %s' % KEY), set())
        got = K.hostkey_report([('ssh-gw.example.com', 22, line + '\n')], line)
        self.assertEqual(got[0]['status'], 'same')

    def test_js(self):
        with open(os.path.join(ROOT, 'web', 'assets', 'sshkey.js')) as f:
            src = f.read()
        self.assertIn("p.length >= 3 && /^(ssh-|ecdsa-|sk-)/.test(p[1] || '')", src)


@unittest.skipUnless(os.geteuid() == 0 and os.path.exists('/usr/sbin/sshd'),
                     'two sshd need root and OpenSSH')
class ConnectorKeyKept(unittest.TestCase):
    """The connector's host key, taken as the first one seen, was never kept: every
    connection through it took whatever key answered (its password to anyone between)."""

    @classmethod
    def setUpClass(cls):
        d = cls.d = tempfile.mkdtemp(prefix='acme-hunt-w7-d-')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', d + '/client'],
                       check=True)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', d + '/hk'],
                       check=True)
        shutil.copy(d + '/client.pub', d + '/authorized_keys')
        cls.procs, cls.ports = [], {}
        for name in ('jump', 'target'):
            port = cls.ports[name] = free_port()
            conf = d + '/%s.conf' % name
            with open(conf, 'w') as f:
                f.write('Port %d\nListenAddress 127.0.0.1\nHostKey %s/hk\nPidFile %s/%s.pid\n'
                        'AuthorizedKeysFile %s/authorized_keys\nPermitRootLogin '
                        'prohibit-password\nPasswordAuthentication no\n'
                        'KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\n'
                        'AllowTcpForwarding yes\n' % (port, d, d, name, d))
            cls.procs.append(subprocess.Popen(['/usr/sbin/sshd', '-D', '-f', conf, '-E',
                                               d + '/%s.log' % name]))
        for _ in range(50):
            if all(is_open(p) for p in cls.ports.values()):
                break
            time.sleep(0.1)
        with open(d + '/client') as f:
            cls.key = f.read()
        with open(d + '/hk.pub') as f:
            cls.hk = f.read().split()[1]

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.send_signal(signal.SIGTERM)
            p.wait(5)
        shutil.rmtree(cls.d, ignore_errors=True)

    def _cfg(self, fam, name):
        table = S.TABLE_OF[fam]
        return S.jload(STORE.db.value('SELECT config FROM %s WHERE name = ?' % table, (name,)),
                       {}) or {}

    def _via(self, fam, name, kind):
        A.family_save(STORE, fam, {'name': name, 'kind': kind, 'config': {
            'host': '127.0.0.1', 'port': self.ports['jump'], 'user': 'root', 'auth': 'key',
            'key': self.key, 'trust_first': True}}, 'tester')
        self.assertFalse(self._cfg(fam, name).get('hostkey'))
        ctx = RT.RunContext(STORE, scope='target:w7-nothing')
        s = ctx.ssh({'host': '127.0.0.1', 'port': self.ports['target'], 'user': 'root',
                     'key': self.key, 'trust_first': True, 'timeout': 15, 'via': name})
        try:
            self.assertEqual(s.run('echo ok')[1].strip(), 'ok')
        finally:
            s.close()
        kept = self._cfg(fam, name).get('hostkey') or ''
        self.assertIn(self.hk, kept)
        self.assertIn('127.0.0.1 ', kept)
        # the next connection goes on the key kept, nothing taken again
        ctx = RT.RunContext(STORE, scope='target:w7-nothing')
        s = ctx.ssh({'host': '127.0.0.1', 'port': self.ports['target'], 'user': 'root',
                     'key': self.key, 'trust_first': True, 'timeout': 15, 'via': name})
        try:
            self.assertEqual(s.run('echo ok')[1].strip(), 'ok')
        finally:
            s.close()
        self.assertEqual(self._cfg(fam, name).get('hostkey'), kept)
        self.assertFalse(any('127.0.0.1 taken as the first' in str(x) and 'connector' in str(x)
                             for x in ctx.steps))

    def test_targets_connector(self):
        self._via('target', 'w7-jump-t', 'ssh_connector')

    def test_tests_connector(self):
        self._via('check', 'w7-jumpbox', 'ssh_relay')


class W7Takes(base.Target):
    kind = 'w7takes'
    title = 'A target that takes anything (tests)'

    def deploy(self, bundle, options):
        return 'took it'


class W7Stopped(base.Target):
    """Stop pressed while it works: the module says so as its own error, as SshSession does."""
    kind = 'w7stopped'
    title = 'A target stopped half way (tests)'
    job = None

    def deploy(self, bundle, options):
        W7Stopped.job.stop.set()
        raise base.PluginError('the job was stopped', retry=False)


base.REGISTRY.found['target'][W7Takes.kind] = W7Takes
base.REGISTRY.found['target'][W7Stopped.kind] = W7Stopped


def _add(table, name, kind, config):
    return STORE.db.insert(table, {'name': name, 'kind': kind, 'config': json.dumps(config),
                                   'state': '{}', 'enabled': 1, 'created': time.time()})


class KeeperOfATarget(unittest.TestCase):
    """A target's host key field holding no key the connection uses (a comment, a
    @cert-authority line): the key seen was taken on every run, never kept."""

    def _cfg(self, name):
        return S.jload(STORE.db.value('SELECT config FROM cert_targets WHERE name = ?',
                                      (name,)), {}) or {}

    def test_kept_beside(self):
        line = '10.0.0.9 ssh-ed25519 %s' % KEY
        for name, have in (('w7k1', '# the web server'), ('w7k2', '@cert-authority *.x ssh-ed25519 %s'
                                                         % KEY), ('w7k3', '')):
            tid = _add('cert_targets', name, 'ssh', {'host': '10.0.0.9', 'hostkey': have})
            deployer.hostkey_keeper(STORE, {'id': tid, 'name': name})(line)
            got = self._cfg(name)['hostkey']
            self.assertTrue(got.endswith(line), got)
            if have:
                self.assertTrue(got.startswith(have))
            self.assertEqual(RT.hostkey_lines(got), ['%s ssh-ed25519 %s' % (RT.HOSTKEY_ALIAS, KEY)])

    def test_a_key_there_stays(self):
        have = 'web ssh-ed25519 %s' % KEY
        tid = _add('cert_targets', 'w7k4', 'ssh', {'host': 'web', 'hostkey': have})
        deployer.hostkey_keeper(STORE, {'id': tid, 'name': 'w7k4'})('web ssh-rsa AAAAB3NzaC1yc2E=')
        self.assertEqual(self._cfg('w7k4')['hostkey'], have)


class StoppedIsNotFailed(unittest.TestCase):
    """Stop pressed during a deployment whose module said it as an error (SSH: "the job was
    stopped"): counted as a failure of the target - its wait doubled, an event "failed" and a
    notice sent. And those put in place before it were never said deployed."""

    @classmethod
    def setUpClass(cls):
        ca_id = CA.ca_create(STORE, 'W7 Root', {'CN': 'W7 Root'}, key_type='ec-256', by='t')
        _add('cert_issuers', 'w7own', 'internal_ca', {'ca': ca_id, 'days': 60})
        _add('cert_targets', 'w7box', 'w7takes', {})
        _add('cert_targets', 'w7stop', 'w7stopped', {})
        cls.cid = STORE.db.insert('certs', {
            'name': 'w7.example', 'names': json.dumps(['w7.example']), 'cn': 'w7.example',
            'issuer': 'w7own', 'challenge': '', 'challenge_map': '{}', 'key_type': 'ec-256',
            'auto_renew': 1, 'state': 'new', 'enabled': 1, 'version': 0, 'fails': 0,
            'ari': '{}', 'profile': '{}', 'created': time.time()})
        job = jobs.run_now(STORE, 'renew', renewer.renew_job(cls.cid, False, 'test'),
                           cert_id=cls.cid, by='test')
        assert job.ok, job.steps

    def _dep(self, target, pos):
        return STORE.db.insert('cert_deploys', {'cert_id': self.cid, 'target': target,
                                                'options': '{}', 'enabled': 1, 'state': 'new',
                                                'fails': 0, 'position': pos,
                                                'created': time.time() - 3600})

    def test_stop(self):
        ok_id = self._dep('w7box', 1)
        stop_id = self._dep('w7stop', 2)
        sent = []
        old = notices.send
        notices.send = lambda store, mid, key, values, *a, **kw: sent.append(mid) or \
            {'mail': [], 'sms': []}
        try:
            def fn(j):
                W7Stopped.job = j
                return deployer.run_deploys(STORE, j, self.cid, only=[ok_id, stop_id])
            job = jobs.run_now(STORE, 'deploy', fn, cert_id=self.cid, by='test')
        finally:
            notices.send = old
        self.assertEqual(job.state, 'stopped', job.steps)
        row = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (stop_id,))
        self.assertEqual(row['state'], 'failed')
        self.assertEqual(int(row['fails'] or 0), 0)
        self.assertEqual(row['last_error'], 'stopped before it was done')
        self.assertLess(float(row['next_try']) - time.time(), 400)
        self.assertNotIn('cert_deploy_failed', sent)
        events = ' '.join(str(r.get('words') or r.get('message') or r) for r in STORE.db.rows(
            'SELECT * FROM events ORDER BY id'))
        self.assertNotIn('to w7stop failed', events)
        # the one before it went through: said deployed
        self.assertEqual(STORE.db.value('SELECT state FROM cert_deploys WHERE id = ?',
                                        (ok_id,)), 'ok')
        self.assertIn('deployed to w7box', events)


if __name__ == '__main__':
    unittest.main()
