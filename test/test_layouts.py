#!/usr/bin/env python3
"""The quick layouts of the files on a target (1.0.64: full chain, chain, key):

    python3 test/test_layouts.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from acmelib.plugins.targets import _script as S  # noqa: E402


class Layouts(unittest.TestCase):
    def test_full_chain_chain_key(self):
        one = [x for x in S.layouts('/etc/nginx/certs') if x['key'] == 'fullchain_chain'][0]
        self.assertEqual(one['outputs'], ['fullchain-pem {dir}/{name}.crt 0644',
                                          'chain-pem {dir}/{name}.ca 0644',
                                          'key-pem {dir}/{name}.key 0600'])
        self.assertEqual(one['folder'], '/etc/nginx/certs')

    def test_every_format_known(self):
        for x in S.layouts('/x') + S.layouts('C:/x', 'windows'):
            for o in x['outputs']:
                self.assertIn(o.split()[0], S.FORMATS)


if __name__ == '__main__':
    unittest.main(verbosity=1)
