#!/usr/bin/env python3
"""Hunt R2, area validdns: regressions for the bugs fixed in the validations.

    python3 test/test_hunt_r2_validdns.py
"""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_challenges as T  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402


class Ipv6Urls(unittest.TestCase):
    """An IP certificate for an IPv6 address: the URL acme checks has it in brackets."""

    def setUp(self):
        self.urls = []

        def h(method, url, body, headers):
            self.urls.append(url)
            return 200, {}, b'KA'
        self.ctx = T.FakeCtx(http=h)

    def test_http_ssh_check_by_name(self):
        m = T.plugin('http_ssh')({'hosts': ['web1'], 'check': 'name'}, self.ctx)
        ok = m.ready('2001:db8::1', {'token': 'tok12345678', 'ka': 'KA', 'name': '2001:db8::1'})
        self.assertTrue(ok)
        self.assertEqual(self.urls, ['http://[2001:db8::1]/.well-known/acme-challenge/tok12345678'])

    def test_http_ssh_check_by_name_dns(self):
        m = T.plugin('http_ssh')({'hosts': ['web1'], 'check': 'name'}, self.ctx)
        m.ready('www.example.com', {'token': 'tok12345678', 'ka': 'KA', 'name': 'www.example.com'})
        self.assertEqual(self.urls, ['http://www.example.com/.well-known/acme-challenge/tok12345678'])

    def test_dcv_file_placed_ready(self):
        m = T.plugin('http_local')({'self_check': True}, self.ctx)
        ok = m.placed_ready({'kind': 'file', 'name': '2001:db8::1',
                             'path': '/.well-known/pki-validation/x.txt', 'content': 'KA'})
        self.assertTrue(ok)
        self.assertEqual(self.urls, ['http://[2001:db8::1]/.well-known/pki-validation/x.txt'])


class BuiltinFails(unittest.TestCase):
    """acme's own DNS server: three failures in a row for a record, not three in all."""

    def module(self):
        ctx = T.FakeCtx(settings={'dns_zone': 'acme.example.net', 'dns_port': 5300})
        return T.plugin('dns_builtin')({}, ctx)

    @staticmethod
    def handle(name):
        fq = name + '.acme.example.net'
        return {'fqdn': fq, 'rr': fq, 'txt': 'v'}

    def run_seq(self, m, seq, names):
        def fake(*a, **k):
            x = seq.pop(0)
            if isinstance(x, Exception):
                raise x
            return x
        out = []
        with mock.patch.object(D, 'txt_at', fake):
            for n in names:
                out.append(m.ready(n, self.handle(n)))
        return out

    def test_spread_failures_do_not_fail(self):
        m = self.module()
        err = D.DnsError('timeout')
        got = self.run_seq(m, [err, ['v'], err, ['v'], err, ['v']], ['a.example.com'] * 6)
        self.assertEqual(got, [False, True, False, True, False, True])

    def test_one_moment_for_three_names(self):
        m = self.module()
        err = D.DnsError('timeout')
        got = self.run_seq(m, [err, err, err], ['a.example.com', 'b.example.com', 'c.example.com'])
        self.assertEqual(got, [False, False, False])

    def test_three_in_a_row_still_fail(self):
        m = self.module()
        err = D.DnsError('timeout')
        with self.assertRaises(PluginError):
            self.run_seq(m, [err, err, err], ['a.example.com'] * 3)


if __name__ == '__main__':
    unittest.main()
