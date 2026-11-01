#!/usr/bin/env python3
"""Where acme's DNS server answers: the VIP only, the nodes only, or both.

    python3 test/test_dns_expose.py

127.0.0.2 stands for the cluster's VIP address, 127.0.0.1 for the node's own.
"""
import os
import socket
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from test_challenges import MemStore, free_port, server_config, ZONE  # noqa: E402
from acmelib.certs.dnsserver import DnsServer  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402

VIP, NODE = '127.0.0.2', '127.0.0.1'


def ask(addr, port, tcp=False):
    q = D.make_query('ns1.' + ZONE, 'A').to_wire()
    if tcp:
        try:
            s = socket.create_connection((addr, port), timeout=2)
        except OSError:
            return False
        try:
            s.sendall(len(q).to_bytes(2, 'big') + q)
            n = int.from_bytes(s.recv(2), 'big')
            return bool(n and s.recv(n))
        except (OSError, socket.timeout):
            return False
        finally:
            s.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.sendto(q, (addr, port))
        data, src = s.recvfrom(4096)
        return src[0] == addr and bool(data)
    except (OSError, socket.timeout):
        return False
    finally:
        s.close()


class Expose(unittest.TestCase):
    def run_with(self, expose, listen='0.0.0.0'):
        port = free_port()
        srv = DnsServer(MemStore(), server_config(port, dns_listen=listen, dns_expose=expose))
        srv.vip_address = lambda: VIP
        st = srv.start()
        try:
            self.assertEqual(st['expose'], expose)
            return {(a, tcp): ask(a, port, tcp) for a in (VIP, NODE) for tcp in (False, True)}
        finally:
            srv.stop()

    def test_both(self):
        got = self.run_with('both')
        self.assertTrue(all(got.values()), got)

    def test_nodes_only(self):
        got = self.run_with('nodes')
        self.assertTrue(got[(NODE, False)] and got[(NODE, True)], got)
        self.assertFalse(got[(VIP, False)] or got[(VIP, True)], got)

    def test_vip_only(self):
        got = self.run_with('vip')
        self.assertTrue(got[(VIP, False)] and got[(VIP, True)], got)
        self.assertFalse(got[(NODE, False)] or got[(NODE, True)], got)

    def test_vip_only_without_a_vip_answers_on_the_nodes(self):
        port = free_port()
        srv = DnsServer(MemStore(), server_config(port, dns_listen=NODE, dns_expose='vip'))
        srv.vip_address = lambda: None
        st = srv.start()
        try:
            self.assertTrue(st['expose_note'])
            self.assertTrue(ask(NODE, port))
        finally:
            srv.stop()

    def test_glue_follows_the_choice(self):
        srv = DnsServer(MemStore(), server_config(free_port(), dns_ns_addresses='', dns_expose='vip'))
        srv.vip_address = lambda: VIP
        srv.answering_addresses = lambda cfg: [VIP] if cfg.get('dns_expose') == 'vip' else [NODE]
        self.assertEqual(srv.cfg()['dns_ns_addresses'], VIP)



class BuiltinAsksWhereItAnswers(unittest.TestCase):
    """The validation 'acme's own DNS server' asks the server where it really
    answers: on the VIP only, the VIP - not 127.0.0.1, where it does not listen
    then (Test said "does not answer on 127.0.0.1 port 53 ... refused")."""

    def test_vip_only_test_and_ready(self):
        from test_challenges import FakeCtx, plugin
        port = free_port()
        cfg = server_config(port, dns_listen='0.0.0.0', dns_expose='vip')
        store = MemStore()
        srv = DnsServer(store, cfg)
        srv.vip_address = lambda: VIP
        srv.start()
        try:
            ctx = FakeCtx(store, settings=cfg)
            ctx.dns_server_info = lambda: {'answering': [VIP], 'expose': 'vip'}
            m = plugin('dns_builtin')({'zone': ZONE}, ctx)
            self.assertEqual(m._own_address(cfg), (VIP, port))
            from acmelib.plugins.base import PluginError
            try:
                said = m.test()
            except PluginError as e:         # no delegation in a test - that part may fail
                said = str(e.detail or e)
            self.assertIn('answers for %s on %s port %d' % (ZONE, VIP, port), said)
            self.assertNotIn('does not answer', said)
            name = 'www.example.com'
            h = m.present(name, 'tok', 'tok.key', 'proof-of-it')
            import time
            for _ in range(20):                 # the server reads records at most every 1 s
                if m.ready(name, h):
                    break
                time.sleep(0.2)
            else:
                self.fail('not answered on the VIP: %s' % ctx.steps)
            m.cleanup(name, h)
            # and on the nodes it is not reachable at all - which is the point
            self.assertFalse(ask(NODE, port))
        finally:
            srv.stop()

    def test_both_still_asks_here(self):
        from acmelib.plugins.challenges import _dns as DD
        self.assertEqual(DD.own_server_address({'dns_port': 53, 'dns_expose': 'both'},
                                               [VIP, NODE])[0], '127.0.0.1')
        self.assertEqual(DD.own_server_address({'dns_port': 53, 'dns_expose': 'vip'},
                                               [VIP])[0], VIP)


if __name__ == '__main__':
    unittest.main(verbosity=2)
