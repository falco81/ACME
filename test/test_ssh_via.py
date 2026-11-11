#!/usr/bin/env python3
"""A server reached through a connector (1.0.74): a Linux / Unix (SSH) target with "Through a
connector" signs in to the connector's server (a test of the kind ssh_relay) and from it to the
target (ProxyCommand ssh -W) - its host key read there, the files put and the commands run.

    python3 test/test_ssh_via.py

Two sshd of this machine (root): the connector, which logs each forwarding, and the target.
"""
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-ssh-via-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import runtime as RT  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def is_open(port):
    with socket.socket() as s:
        return s.connect_ex(('127.0.0.1', port)) == 0


@unittest.skipUnless(os.geteuid() == 0 and os.path.exists('/usr/sbin/sshd'),
                     'two sshd need root and OpenSSH')
class ViaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = cls.d = tempfile.mkdtemp(prefix='acme-ssh-via-d-')
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', d + '/client'], check=True)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', d + '/hk'], check=True)
        shutil.copy(d + '/client.pub', d + '/authorized_keys')
        cls.procs = []
        cls.ports = {}
        for name in ('jump', 'target'):
            port = cls.ports[name] = free_port()
            conf = d + '/%s.conf' % name
            with open(conf, 'w') as f:
                f.write('Port %d\nListenAddress 127.0.0.1\nHostKey %s/hk\nPidFile %s/%s.pid\n'
                        'AuthorizedKeysFile %s/authorized_keys\nPermitRootLogin prohibit-password\n'
                        'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'
                        'StrictModes no\nAllowTcpForwarding yes\nLogLevel DEBUG1\n'
                        % (port, d, d, name, d))
            cls.procs.append(subprocess.Popen(['/usr/sbin/sshd', '-D', '-f', conf, '-E', d + '/%s.log' % name]))
        for _ in range(50):
            if all(is_open(p) for p in cls.ports.values()):
                break
            time.sleep(0.1)
        with open(d + '/client') as f:
            cls.key = f.read()
        A.family_save(STORE, 'check', {'name': 'jumpbox', 'kind': 'ssh_relay', 'config': {
            'host': '127.0.0.1', 'port': cls.ports['jump'], 'user': 'root', 'auth': 'key',
            'key': cls.key, 'trust_first': True, 'tests': []}}, 'tester')

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.send_signal(signal.SIGTERM)
            p.wait(5)
        shutil.rmtree(cls.d, ignore_errors=True)

    def conn(self, **more):
        c = {'host': '127.0.0.1', 'port': self.ports['target'], 'user': 'root', 'key': self.key,
             'trust_first': True, 'timeout': 15, 'via': 'jumpbox'}
        c.update(more)
        return c

    def test_through_the_connector(self):
        ctx = RT.RunContext(STORE)
        s = ctx.ssh(self.conn())
        try:
            rc, out, _err = s.run('echo hello-from-$(id -un)')
            self.assertEqual(out.strip(), 'hello-from-root')
            path = self.d + '/put.txt'
            s.put(b'certificate', path, mode=0o640)
            self.assertEqual(s.get(path), b'certificate')
        finally:
            s.close()
        with open(self.d + '/jump.log') as f:
            log = f.read()
        self.assertIn('direct-tcpip', log)                     # it went through the connector
        self.assertIn('port %d' % self.ports['target'], log)
        self.assertTrue(any('through the connector jumpbox' in str(x) for x in ctx.steps))

    def test_no_such_connector(self):
        with self.assertRaises(PluginError) as e:
            RT.RunContext(STORE).ssh(self.conn(via='nope'))
        self.assertIn('no connector called nope', str(e.exception))

    def test_offered_and_not_on_itself(self):
        self.assertIn(['jumpbox', 'jumpbox'], A.options_for(STORE, 'connectors'))
        relay = S.registry().all()['check']['ssh_relay']
        self.assertNotIn('via', [f['key'] for f in relay.fields])
        ssh = S.registry().all()['target']['ssh']
        self.assertIn('via', [f['key'] for f in ssh.fields])


if __name__ == '__main__':
    unittest.main()
