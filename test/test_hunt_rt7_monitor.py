#!/usr/bin/env python3
"""Hunt R run t7, monitoring: the metrics' networks, SNMP's own test over IPv6, the lines held
for isemon and the SIEM, a certificate deployed twice to one target.

    python3 test/test_hunt_rt7_monitor.py

- /metrics from the networks set (metrics_from): an IPv4 client seen as ::ffff:10.1.2.3 (a
  socket of both kinds) was refused by 10.0.0.0/8.
- The node's own SNMP test ("Ask it") asked over IPv4 whatever the agent was bound to: bound to
  an IPv6 address, it failed with "Address family for hostname not supported".
- isemon and the SIEM over TCP/TLS: the lines held while a server was down, and its trouble
  ("tried again in 15 s") with the alert, waited for the next event - days on a quiet machine.
- Prometheus: one certificate deployed twice to one target gave two samples of one series.
"""
import collections
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix='acme-hunt-rt7-monitor-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE


class D(object):
    store = STORE
    started = time.time()
    dirs = []


class MetricsFrom(unittest.TestCase):
    def setUp(self):
        self.was = E.CONFIG.get('metrics_from')

    def tearDown(self):
        E.CONFIG['metrics_from'] = self.was

    def test_ipv4_mapped(self):
        E.CONFIG['metrics_from'] = '10.0.0.0/8'
        self.assertTrue(E.metrics_allowed('10.1.2.3'))
        self.assertTrue(E.metrics_allowed('::ffff:10.1.2.3'))
        self.assertFalse(E.metrics_allowed('::ffff:192.168.1.1'))
        self.assertFalse(E.metrics_allowed('192.168.1.1'))
        self.assertFalse(E.metrics_allowed('not an address'))

    def test_ipv6_as_before(self):
        E.CONFIG['metrics_from'] = '2001:db8::/64, ::ffff:0:0/96'
        self.assertTrue(E.metrics_allowed('2001:db8::5'))
        self.assertTrue(E.metrics_allowed('::ffff:10.1.2.3'))
        self.assertFalse(E.metrics_allowed('10.1.2.3'))
        E.CONFIG['metrics_from'] = ''
        self.assertTrue(E.metrics_allowed('192.168.1.1'))


class SnmpOwnTestFamily(unittest.TestCase):
    def test_family_of_the_address(self):
        made = []
        real = socket.socket

        class Rec(object):
            def __init__(self, fam, kind, *a):
                made.append(fam)
                raise OSError('recorded')
        socket.socket = Rec
        try:
            c = {'user': 'u', 'auth': 'SHA-256', 'priv': 'AES-128', 'ap': 'a' * 10, 'pp': 'b' * 10}
            for host in ('::1', '[2001:db8::1]', '127.0.0.1'):
                with self.assertRaises(OSError):
                    E.snmp_get(host, 161, c, [E.SNMP_SYS + (1, 0)])
        finally:
            socket.socket = real
        self.assertEqual(made, [socket.AF_INET6, socket.AF_INET6, socket.AF_INET])


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class HeldLines(unittest.TestCase):
    def setUp(self):
        self.was = {k: E.CONFIG.get(k) for k in ('isemon', 'isemon_targets', 'ship_files', 'siem',
                                                 'siem_targets', 'siem_events')}
        self.port = free_port()
        E.CONFIG.update(isemon=1, isemon_targets='127.0.0.1:%d/tcp' % self.port, ship_files=0,
                        siem=1, siem_targets='tcp://127.0.0.1:%d' % self.port, siem_events=1)
        self.srv = None

    def tearDown(self):
        for o in getattr(self, 'objs', []):
            o.stop_flag = True
        if self.srv:
            self.srv.close()
        E.CONFIG.update(self.was)

    def listen(self, got):
        srv = self.srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', self.port))
        srv.listen(5)

        def acc():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return

                def rd(c=c):
                    while True:
                        d = c.recv(65535)
                        if not d:
                            return
                        got.append(d)
                threading.Thread(target=rd, daemon=True).start()
        threading.Thread(target=acc, daemon=True).start()

    def test_sent_once_the_server_is_back_without_a_new_line(self):
        sh, si = E.Shipper(), E.Siem()
        self.objs = [sh, si]
        sh.put('acme-certs', 'daemon', 'held isemon line')
        si.event_line('settings', 'held siem line', 'info', 'tester')
        until = time.time() + 10
        while time.time() < until and not (sh.state()['trouble'] and si.state()['trouble']):
            time.sleep(0.1)
        self.assertTrue(sh.state()['trouble'])
        self.assertTrue(si.state()['trouble'])
        got = []
        self.listen(got)
        # the wait after the failure over (15 s and 30 s otherwise)
        for k in list(sh.down):
            sh.down[k] = (0.0, sh.down[k][1])
        for k in list(si.down):
            si.down[k] = 0.0
        until = time.time() + 10
        while time.time() < until and not (sh.state()['trouble'] == {} and
                                           si.state()['trouble'] == {} and len(got) >= 2):
            time.sleep(0.1)
        joined = b''.join(got)
        self.assertIn(b'held isemon line', joined)
        self.assertIn(b'held siem line', joined)
        self.assertEqual(sh.state()['trouble'], {})
        self.assertEqual(si.state()['trouble'], {})
        self.assertEqual(sh.state()['held'], {})
        self.assertEqual(si.state()['held'], {})

    def test_not_before_the_wait_is_over(self):
        sh = E.Shipper()
        self.objs = [sh]
        E.CONFIG['siem'] = 0
        sh.put('acme-certs', 'daemon', 'early line')
        until = time.time() + 10
        while time.time() < until and not sh.state()['trouble']:
            time.sleep(0.1)
        got = []
        self.listen(got)
        time.sleep(2.5)                     # 15 s not over: still held, not asked again
        self.assertEqual(got, [])
        self.assertEqual(list(sh.state()['held'].values()), [1])


class DeployedTwice(unittest.TestCase):
    def test_series_once(self):
        cid = STORE.db.insert('certs', {'name': 'web-twice', 'cn': 'www.example.test',
                                        'state': 'ok', 'not_after': time.time() + 86400 * 60})
        ids = [STORE.db.insert('cert_deploys', {
            'cert_id': cid, 'target': 'srv1', 'state': 'ok', 'enabled': 1,
            'last_ok': time.time(), 'options': '{}'}) for _ in range(2)]
        one = STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'srv2', 'state': 'ok',
                                               'enabled': 1, 'last_ok': time.time(),
                                               'options': '{}'})
        try:
            t = E.metrics_text(D())
            ser = collections.Counter(line.rsplit(' ', 1)[0] for line in t.split('\n')
                                      if line and not line.startswith('#'))
            self.assertEqual([k for k, v in ser.items() if v > 1], [])
            for i in ids:
                self.assertIn('acme_cert_deploy_state{cert="web-twice",enabled="1",id="%d",'
                              'state="ok",target="srv1"} 1' % i, t)
                self.assertIn('acme_cert_deploy_last_ok_timestamp_seconds{cert="web-twice",'
                              'id="%d",target="srv1"}' % i, t)
            # the one deployment there as before - no id
            self.assertIn('acme_cert_deploy_state{cert="web-twice",enabled="1",state="ok",'
                          'target="srv2"} 1', t)
            self.assertIn('acme_cert_deploy_last_ok_timestamp_seconds{cert="web-twice",'
                          'target="srv2"}', t)
        finally:
            for i in ids + [one]:
                STORE.db.run('DELETE FROM cert_deploys WHERE id = ?', (i,))
            STORE.db.run('DELETE FROM certs WHERE id = ?', (cid,))


if __name__ == '__main__':
    unittest.main()
