#!/usr/bin/env python3
"""acme's own DNS server and the firewall: switched on, it is let in by itself.

    python3 test/test_fw_dns.py
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-fwdns-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())


def dns_item():
    return [i for i in E.fw_auto(STORE, E.node_name()) if i['key'] == 'dns']


class DnsServerOpensTheFirewall(unittest.TestCase):
    def tearDown(self):
        E.CONFIG['dns_server'] = 0
        E.CONFIG['dns_port'] = 53
        STORE.set_meta('fw:conf', json.dumps({}))

    def test_off_no_card(self):
        E.CONFIG['dns_server'] = 0
        self.assertEqual(dns_item(), [])

    def test_on_card_with_udp_and_tcp_both_families(self):
        E.CONFIG['dns_server'] = 1
        E.CONFIG['dns_port'] = 53
        item, = dns_item()
        self.assertTrue(item['on'])
        got = sorted((r['family'], r['proto'], r['port'], r['source']) for r in item['rules'])
        self.assertEqual(got, [(4, 'tcp', '53', ''), (4, 'udp', '53', ''),
                               (6, 'tcp', '53', ''), (6, 'udp', '53', '')])

    def test_port_follows_the_setting(self):
        E.CONFIG['dns_server'] = 1
        E.CONFIG['dns_port'] = 5353
        item, = dns_item()
        self.assertEqual({r['port'] for r in item['rules']}, {'5353'})

    def test_in_the_chain_when_the_firewall_is_on(self):
        E.CONFIG['dns_server'] = 1
        STORE.set_meta('fw:conf', json.dumps({'on': True, 'set': True}))
        rules = E.fw_rules_for(STORE, E.node_name())
        self.assertEqual(len([r for r in rules if r.get('note') == 'DNS server (DNS-01)']), 4)

    def test_may_be_turned_off_on_its_card(self):
        E.CONFIG['dns_server'] = 1
        STORE.set_meta('fw:conf', json.dumps({'on': True, 'set': True, 'off': ['dns']}))
        item, = dns_item()
        self.assertFalse(item['on'])
        rules = E.fw_rules_for(STORE, E.node_name())
        self.assertFalse([r for r in rules if r.get('note') == 'DNS server (DNS-01)'])


if __name__ == '__main__':
    unittest.main()
