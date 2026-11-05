#!/usr/bin/env python3
"""What was left of the hunt of 1.0.44 and is shut now - each checked here.

    python3 test/test_hunt_r4.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-hunt4-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Catcher(object):
    """A TCP receiver that keeps every line."""

    def __init__(self, port):
        self.lines = []
        self.raw = b''
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(('127.0.0.1', port))
        self.srv.listen(5)
        self.stop = False
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        self.srv.settimeout(0.2)
        while not self.stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                continue
            c.settimeout(0.2)
            buf = b''
            while not self.stop:
                try:
                    got = c.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not got:
                    break
                buf += got
                self.raw += got
                while b'\n' in buf:
                    one, buf = buf.split(b'\n', 1)
                    self.lines.append(one.decode())
            c.close()

    def close(self):
        self.stop = True
        self.srv.close()


class IsemonHeld(unittest.TestCase):
    def test_lines_kept_while_down_and_sent_after(self):
        port = free_port()
        sh = E.Shipper.__new__(E.Shipper)
        sh.__dict__.update(tcp={}, udp4=None, udp6=None, sent=__import__('collections').Counter(),
                           trouble={}, down={}, missed=__import__('collections').Counter(),
                           backlog={}, last_sent=0.0, ctx=None)
        target = ('127.0.0.1', port, 'tcp')
        with mock.patch.object(E, 'log'):
            for i in range(3):              # nobody listens: held
                sh._to_target(target, 'line %d' % i)
        self.assertEqual(len(sh.backlog['127.0.0.1:%d/tcp' % port]), 3)
        c = Catcher(port)
        try:
            sh.down.clear()                 # its wait over
            sh._to_target(target, 'line 3')
            end = time.time() + 3
            while time.time() < end and len(c.lines) < 4:
                time.sleep(0.05)
            self.assertEqual(c.lines, ['line 0', 'line 1', 'line 2', 'line 3'])
            self.assertFalse(sh.backlog['127.0.0.1:%d/tcp' % port])
        finally:
            c.close()

    def test_held_capped(self):
        sh = E.Shipper.__new__(E.Shipper)
        sh.__dict__.update(tcp={}, udp4=None, udp6=None, sent=__import__('collections').Counter(),
                           trouble={}, missed=__import__('collections').Counter(), backlog={},
                           last_sent=0.0, ctx=None,
                           down={'127.0.0.1:9/tcp': (time.monotonic() + 999, 15)})
        with mock.patch.object(E, 'ISEMON_BACKLOG', 5):
            for i in range(8):
                sh._to_target(('127.0.0.1', 9, 'tcp'), 'l%d' % i)
        self.assertEqual([x.decode() for x in sh.backlog['127.0.0.1:9/tcp']],
                         ['l3', 'l4', 'l5', 'l6', 'l7'])
        self.assertEqual(sh.missed['127.0.0.1:9/tcp'], 3)


class SiemHeld(unittest.TestCase):
    def test_held_then_sent(self):
        port = free_port()
        si = E.Siem.__new__(E.Siem)
        si.__dict__.update(lock=threading.Lock(), conns={}, udp={}, down={}, backlog={},
                           sent=__import__('collections').Counter(), trouble={}, dropped=0,
                           last_sent=0.0, ctx=None)
        t = ('127.0.0.1', port, 'tcp')
        self.assertTrue(si._send(t, 'a', hold=True))        # refused: held
        self.assertEqual(si._send(t, 'b', hold=True), 'held')
        c = Catcher(port)
        try:
            si.down.clear()
            self.assertEqual(si._send(t, 'c', hold=True), '')
            end = time.time() + 3
            while time.time() < end and len(c.raw) < 9:
                time.sleep(0.05)
            # octet counted (RFC 6587), in their order: the two held first
            self.assertEqual(c.raw, b'1 a1 b1 c')
            self.assertFalse(si.backlog['127.0.0.1:%d/tcp' % port])
        finally:
            c.close()


class BackupRuns(unittest.TestCase):
    def test_each_node_its_own_row(self):
        store = E.Storage(E.open_db())
        store.db.run("DELETE FROM meta WHERE k LIKE 'rbackup:runs%'")
        store.set_meta('rbackup:runs', json.dumps([{'at': 10, 'node': 'old', 'file': 'a'}]))
        store.set_meta('rbackup:runs@@peer', json.dumps([{'at': 30, 'node': 'peer', 'file': 'c'}]))
        E.rb_history_add(store, {'at': 20, 'node': E.node_name(), 'file': 'b'})
        self.assertEqual([r['file'] for r in E.rb_history(store)], ['c', 'b', 'a'])
        self.assertIsNotNone(store.get_meta(E.node_key('rbackup', 'runs')))
        # this node forgets its own lines (and those of before); the other node's row is never
        # rewritten here - its line is noted as forgotten in this node's own row (1.0.45)
        self.assertEqual(E.rb_history_forget(store, 20, 'b'), 1)
        self.assertEqual([r['file'] for r in E.rb_history(store)], ['c', 'a'])
        self.assertEqual(E.rb_history_forget(store, 30, 'c'), 1)
        self.assertEqual(json.loads(store.get_meta('rbackup:runs@@peer'))[0]['file'], 'c')
        self.assertEqual([r['file'] for r in E.rb_history(store)], ['a'])
        E.rb_history_add(store, {'at': time.time() + 5, 'node': 'x', 'file': 'd'})
        E.rb_history_forget(store)
        self.assertEqual(E.rb_history(store), [])
        store.db.run("DELETE FROM meta WHERE k LIKE 'rbackup:forgot%'")


class SecondStepGone(unittest.TestCase):
    def test_lost_not_enrolled_again(self):
        store = E.Storage(E.open_db())
        try:
            store.add_account('mfauser', 'fulladmin', 'Long-Enough-Pw-1!')
        except ValueError:
            pass
        store.db.run('DELETE FROM meta WHERE k = ?', (E.mfa_key('mfauser'),))
        store.set_account('mfauser', mfa_on=0)
        self.assertEqual(E.mfa_stage(store, 'mfauser'), 'enrol')
        store.set_meta(E.mfa_key('mfauser'), json.dumps({'kind': 'app', 'secret': 'x'}))
        with mock.patch.dict(E.CONFIG, {'ha_mode': ''}):
            self.assertEqual(E.mfa_marks_adopt(store), 1)
        self.assertEqual(E.mfa_stage(store, 'mfauser'), 'check')
        store.db.run('DELETE FROM meta WHERE k = ?', (E.mfa_key('mfauser'),))   # written past acme
        self.assertEqual(E.mfa_stage(store, 'mfauser'), 'lost')
        E.mfa_reset(store, 'mfauser', 'admin')
        self.assertEqual(E.mfa_stage(store, 'mfauser'), 'enrol')

    def test_signed_with_it(self):
        base = {'name': 'x', 'role': 'fulladmin', 'pw': 'h', 'source': 'local', 'disabled': 0,
                'must_change': 0, 'dn': ''}
        self.assertEqual(E.account_signed_cols(base), E.ACCOUNT_SIGNED)
        self.assertIn('mfa_on', E.account_signed_cols(dict(base, mfa_on=1)))

    def test_waits_for_every_node(self):
        store = E.Storage(E.open_db())
        old = [{'name': 'a', 'me': True, 'alive': True, 'version': '1.0.44'},
               {'name': 'b', 'alive': True, 'version': '1.0.43'}]
        with mock.patch.dict(E.CONFIG, {'ha_mode': 'replicated'}), \
                mock.patch.object(E, 'ha_nodes', return_value=old):
            self.assertEqual(E.mfa_marks_adopt(store), 0)


class PluginsFolder(unittest.TestCase):
    def test_not_roots_moved_aside(self):
        if os.geteuid() != 0:
            self.skipTest('not root')
        d = tempfile.mkdtemp(prefix='acme-plug-')
        os.mkdir(os.path.join(d, 'p'))
        os.chown(os.path.join(d, 'p'), 65534, -1)
        os.mkdir(os.path.join(d, 'q'))
        os.symlink('/etc', os.path.join(d, 'r'))
        script = ('source <(sed -n "/^plugin_dir_take() {/,/^}/p" %s/install.sh); '
                  'warn(){ echo "WARN $*"; }; fail(){ echo "FAIL $*"; exit 3; }; note(){ :; }; '
                  'run(){ "$@"; }; DRY_RUN=""; plugin_dir_take %s/p; plugin_dir_take %s/q; '
                  'plugin_dir_take %s/r' % (ROOT, d, d, d))
        got = subprocess.run(['bash', '-c', script], capture_output=True, text=True)
        self.assertIn('WARN', got.stdout)
        self.assertIn('FAIL', got.stdout)
        self.assertEqual(os.stat(os.path.join(d, 'p')).st_uid, 0)
        self.assertTrue([n for n in os.listdir(d) if n.startswith('p.not-roots.')])
        self.assertEqual(os.stat(os.path.join(d, 'q')).st_uid, 0)
        self.assertEqual(os.readlink(os.path.join(d, 'r')), '/etc')


if __name__ == '__main__':
    unittest.main()
