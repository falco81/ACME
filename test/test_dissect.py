#!/usr/bin/env python3
"""Bytes taken apart for What happens, as Wireshark shows them (1.0.37).

    python3 test/test_dissect.py

What the tests send before TLS - built by the very functions they send with - and
what a module sends over UDP: each read into named fields with the bytes they come
from; a secret never shown, neither as text nor as bytes.
"""
import base64
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from acmelib.certs import dissect as X  # noqa: E402
from acmelib.plugins.checks import ldap, mssql, mysql, postgres, rdp  # noqa: E402


def names(d):
    return {f[3]: f[4] for f in d['fields']}


class TestDissect(unittest.TestCase):
    def test_ldap_starttls(self):
        d = X.dissect(ldap.request(1), 'ldap')
        n = names(d)
        self.assertEqual(n['messageID: INTEGER'], '1')
        self.assertIn('StartTLS', n['requestName (OID): [0]'])

    def test_postgres(self):
        n = names(X.dissect(postgres.SSL_REQUEST, 'postgres'))
        self.assertIn('SSLRequest', n['Request code'])
        self.assertEqual(n['Length'], '8')

    def test_mysql_flags(self):
        n = names(X.dissect(mysql.ssl_request(0xffffffff), 'mysql'))
        self.assertEqual(n['CLIENT_SSL'], 'set')
        self.assertEqual(n['CLIENT_PROTOCOL_41'], 'set')
        self.assertEqual(n['CLIENT_MULTI_STATEMENTS'], 'not set')

    def test_tds_prelogin(self):
        msg, _ = mssql.packets(mssql.PRELOGIN, mssql.prelogin_body(mssql.ENCRYPT_ON))
        n = names(X.dissect(msg, 'mssql'))
        self.assertIn('PRELOGIN', n['Type'])
        self.assertIn('ENCRYPT_ON', n['ENCRYPTION'])

    def test_rdp_flags(self):
        n = names(X.dissect(rdp.connection_request(), 'rdp'))
        self.assertIn('Connection Request', n['PDU type'])
        self.assertEqual(n['PROTOCOL_SSL (TLS)'], 'requested')
        self.assertEqual(n['PROTOCOL_RDSTLS'], 'not requested')

    def test_snmp_community_never_shown(self):
        pkt = bytes.fromhex('302602010104067075626c6963a01902046e2c8c0c020100020100300b3009'
                            '06052b060102010500')
        d = X.dissect(pkt, port=161)
        self.assertEqual(d['summary'], 'SNMP GetRequest')
        n = names(d)
        self.assertIn('v2c', n['version: INTEGER'])
        self.assertTrue(n['community: OCTET STRING'].startswith('••••'))
        text = repr(d)
        self.assertNotIn('public', text)
        self.assertNotIn('7075626c6963', text.replace(' ', ''))

    def test_dns_query(self):
        q = (b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0f_acme-challenge\x04test'
             b'\x00\x00\x10\x00\x01')
        d = X.dissect(q, port=53)
        n = names(d)
        self.assertEqual(n['Name'], '_acme-challenge.test')
        self.assertEqual(n['Type'], 'TXT (16)')
        self.assertEqual(n['RD - recursion desired'], 'yes')

    def test_malformed_said(self):
        d = X.dissect(bytes.fromhex('302902010104067075626c6963a01c0204'), port=161)
        self.assertIn('malformed', d['summary'])
        self.assertTrue(any(f[3].startswith('[Malformed') for f in d['fields']))

    def test_a_stand_in_never_shown(self):
        si = base64.b64encode(b'plansecret03')
        d = X.dissect(b'<13>token=' + si + b' end', port=514)
        text = repr(d)
        self.assertNotIn(si.decode(), text)
        self.assertNotIn(si.hex(), text.replace(' ', ''))

    def test_unknown_is_its_bytes(self):
        d = X.dissect(b'\x00\x01hello', port=9999)
        self.assertEqual(d['fields'], [])
        self.assertTrue(d['hex'][0].startswith('0000  00 01 68 65'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
