#!/usr/bin/env python3
"""Hunt R t6, area dns: regressions for the bugs fixed in DNS-01 and acme's own DNS server.

    python3 test/test_hunt_rt6_dns.py

- ready(): the zone of the record not found by its SOA once (a resolver that did not
  answer) failed the whole order - now "not yet", the resolvers decide;
- "A script of your own": a CA's DCV TXT record (txt-any) failed with an AttributeError,
  or ran the script with the name of the order before;
- acme's own DNS server with an international zone (příklad.cz): every question REFUSED,
  the validation wrote its records under the Unicode name.
"""
import os
import stat
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_challenges as T  # noqa: E402
from acmelib.certs.dnsserver import DnsServer  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402
from acmelib.plugins.challenges._common import DnsChallenge  # noqa: E402
from acmelib.plugins.challenges.script import Script  # noqa: E402


class Plain(DnsChallenge):
    kind = 'plain_t6'
    title = 'plain'
    fields = []

    def add_txt(self, fqdn, value):
        return None

    def del_txt(self, fqdn, value, handle):
        pass


class ReadyZoneNotFound(unittest.TestCase):
    def test_soa_lookup_failure_is_not_yet(self):
        m = Plain({'follow_cname': False, 'resolvers': '192.0.2.1'}, T.FakeCtx())

        def no_answer(*a, **k):
            raise D.DnsError('no DNS server answered')
        h = {'rr': '_acme-challenge.www.example.com', 'fqdn': '_acme-challenge.www.example.com',
             'txt': 'abc', 'at': time.time() - 10}
        with mock.patch.object(D, 'find_zone', no_answer), \
                mock.patch.object(D, 'ask_server', no_answer):
            self.assertIs(m.ready('www.example.com', h), False)
        self.assertTrue(any('could not be asked' in w for _l, w in m.ctx.steps))

    def test_found_as_before(self):
        m = Plain({'follow_cname': False, 'zone': 'example.com'}, T.FakeCtx())
        h = {'rr': '_acme-challenge.www.example.com', 'fqdn': '_acme-challenge.www.example.com',
             'txt': 'abc', 'at': time.time() - 10}
        with mock.patch.object(D, 'zone_servers', lambda *a, **k: [('ns1', ['192.0.2.1'])]), \
                mock.patch.object(D, 'txt_at', lambda *a, **k: ['abc']):
            self.assertIs(m.ready('www.example.com', h), True)


class ScriptPlace(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, 'log')
        self.hook = os.path.join(self.dir, 'hook.sh')
        with open(self.hook, 'w') as f:
            f.write('#!/bin/sh\necho "$1 $2 $ACME_NAME $ACME_CHALLENGE_NAME" >> %s\n' % self.log)
        os.chmod(self.hook, stat.S_IRWXU)

    def lines(self):
        with open(self.log) as f:
            return f.read().splitlines()

    def test_dcv_txt_placed_and_taken_away(self):
        m = Script({'path': self.hook, 'follow_cname': False}, T.FakeCtx())
        h = m.place('txt', 'example.com', '_dnsauth.example.com', 'abc123')
        m.unplace(h)
        self.assertEqual(self.lines(), [
            'present _dnsauth.example.com example.com _dnsauth.example.com',
            'cleanup _dnsauth.example.com example.com _dnsauth.example.com'])

    def test_not_the_name_of_the_order_before(self):
        m = Script({'path': self.hook, 'follow_cname': False}, T.FakeCtx())
        m.present('www.example.com', 'tok12345', 'k', 'AAAA')
        m.place('txt', '*.example.org', '_dnsauth.example.org', 'abc123')
        self.assertEqual(self.lines(), [
            'present _acme-challenge.www.example.com www.example.com '
            '_acme-challenge.www.example.com',
            'present _dnsauth.example.org example.org _dnsauth.example.org'])


class InternationalZone(unittest.TestCase):
    ZONE = 'acme.příklad.cz'
    ASCII = 'acme.xn--pklad-zsa96e.cz'

    def test_ascii_name(self):
        self.assertEqual(D.ascii_name('WWW.Příklad.CZ.'), 'www.xn--pklad-zsa96e.cz')
        self.assertEqual(D.ascii_name('www.example.com.'), 'www.example.com')

    def test_server_answers(self):
        st = T.MemStore()
        cfg = T.server_config(0, dns_static='', dns_zone=self.ZONE,
                              dns_ns_names='ns1.' + self.ZONE, dns_ns_addresses='192.0.2.1')
        srv = DnsServer(st, cfg)
        st.put('www.example.com.' + self.ZONE, 'TXT', 'AAA')
        for name, qtype, want in (('www.example.com.' + self.ASCII, 16, 'AAA'),
                                  (self.ASCII, 2, 'ns1.' + self.ASCII),
                                  ('ns1.' + self.ASCII, 1, '192.0.2.1')):
            m = D.parse(srv.answer(D.make_query(name, qtype).to_wire()))
            self.assertEqual(m.rcode, D.NOERROR, name)
            self.assertEqual([r.text for r in m.answer], [want])

    def test_ascii_zone_as_before(self):
        st = T.MemStore()
        srv = DnsServer(st, T.server_config(0, dns_static=''))
        st.put('www.example.com.' + T.ZONE, 'TXT', 'AAA')
        m = D.parse(srv.answer(D.make_query('www.example.com.' + T.ZONE, 16).to_wire()))
        self.assertEqual([r.text for r in m.answer], ['AAA'])

    def test_builtin_writes_the_ascii_name(self):
        ctx = T.FakeCtx(store=T.MemStore(), settings={'dns_zone': self.ZONE})
        m = T.plugin('dns_builtin')({}, ctx)
        self.assertEqual(m.target_of('*.www.example.com'), 'www.example.com.' + self.ASCII)
        self.assertEqual(T.plugin('dns_builtin')({'zone': self.ZONE}, ctx).zone(), self.ASCII)


if __name__ == '__main__':
    unittest.main()
