#!/usr/bin/env python3
"""Hunt 1.0.142, run v5, area "targets": the bugs found and fixed, each kept fixed.

    python3 test/test_hunt_rv5_targets.py

- flowmon: "Check" read a validTo without a time zone as this machine's local time (a
  machine not on UTC said the pair on Flowmon was not this certificate).
- the sources keyfactor_command, venafi_cloud, venafi_tpp, sectigo_scm, certum and
  globalsign_mssl read a date-time by its first 19 characters: '...T19:00:00+09:00' came out
  as 19:00 UTC, nine hours late (GlobalSign answers in JST).
- dnssets.parse_server dropped the zone of an IPv6 link-local address (fe80::1%eth0), so the
  system could not tell which interface the DNS server is on.
"""
import calendar
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as TT  # noqa: E402
from acmelib.certs import dnssets  # noqa: E402
from acmelib.plugins.issuers import _source_common as sc  # noqa: E402
from acmelib.plugins.issuers import (  # noqa: E402
    certum, globalsign_mssl, keyfactor_command, sectigo_scm, venafi_cloud, venafi_tpp)


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


TOKEN = (200, {'access_token': 'TOK', 'token_type': 'bearer', 'expires_in': 86400})


class FlowmonValidToTest(unittest.TestCase):
    def setUp(self):
        self.tz = os.environ.get('TZ')
        os.environ['TZ'] = 'Asia/Tokyo'
        time.tzset()

    def tearDown(self):
        if self.tz is None:
            os.environ.pop('TZ', None)
        else:
            os.environ['TZ'] = self.tz
        time.tzset()

    def check(self, valid_to):
        b = TT.FakeBundle()
        ctx = TT.FakeCtx([
            ('POST', r'/resources/oauth/token$', TOKEN),
            ('GET', r'/rest/fcc/reusable-settings-tls$', (200, [{'id': 't1', 'name': 'Web'}])),
            ('GET', r'/reusable-settings-tls/t1/pairs$', (200, [
                {'id': 'p9', 'name': 'www', 'parsedCertificate': {'validTo': valid_to}}])),
        ])
        t = TT.make('flowmon', {'host': 'flowmon.example.local', 'user': 'admin',
                                'password': 'P'}, ctx)
        return t.verify(b, {'tls_setting': 'Web', 'pair': 'www'})

    def test_no_zone_is_utc(self):
        end = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(TT.FakeBundle().not_after))
        self.assertIsNot(self.check(end), False)
        self.assertIsNot(self.check(end + 'Z'), False)
        self.assertIs(self.check(time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(
            TT.FakeBundle().not_after - 86400))), False)


class SourceOffsetTest(unittest.TestCase):
    AT = calendar.timegm((2026, 5, 1, 10, 0, 0))

    def test_offset(self):
        self.assertEqual(sc.utc_offset('2026-05-01T19:00:00.000+09:00'), 9 * 3600)
        self.assertEqual(sc.utc_offset('2026-05-01T04:30:00-0530'), -19800)
        self.assertEqual(sc.utc_offset('2026-05-01T10:00:00Z'), 0)
        self.assertEqual(sc.utc_offset('2026-05-01'), 0)

    def test_each_source(self):
        for f in (keyfactor_command._epoch, venafi_cloud._epoch, venafi_tpp._epoch,
                  sectigo_scm._when, certum._when, globalsign_mssl._when):
            for v in ('2026-05-01T19:00:00.000+09:00', '2026-05-01T10:00:00Z',
                      '2026-05-01T10:00:00', '2026-05-01T05:00:00.0000000-05:00',
                      '2026-05-01T12:00:00+02:00'):
                self.assertEqual(f(v), self.AT, '%s %s' % (f.__module__, v))
            self.assertIsNone(f('nonsense'))


class DnsZoneTest(unittest.TestCase):
    def test_zone_kept(self):
        self.assertEqual(dnssets.parse_server('fe80::1%eth0'), ('fe80::1%eth0', 53))
        self.assertEqual(dnssets.parse_server('[fe80::1%eth0]:5353'), ('fe80::1%eth0', 5353))
        self.assertEqual(dnssets.clean_servers('fe80::1%eth0\n[fe80::1%eth0]:5353'),
                         ['fe80::1%eth0', '[fe80::1%eth0]:5353'])
        # as before
        self.assertEqual(dnssets.parse_server('2001:DB8::1'), ('2001:db8::1', 53))
        self.assertEqual(dnssets.parse_server('192.0.2.1:5353'), ('192.0.2.1', 5353))
        with self.assertRaises(ValueError):
            dnssets.parse_server('ns.example.com')


if __name__ == '__main__':
    unittest.main()
