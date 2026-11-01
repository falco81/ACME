# -*- coding: utf-8 -*-
"""The engine's parts share one namespace: a name defined twice replaces the
first everywhere (1.0.6: acme push's GCM helper took the place of the QR codes'
_gf_mul, and every QR code of a second factor came out wrong)."""
import hashlib
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class EngineNames(unittest.TestCase):
    def test_every_top_level_name_once(self):
        engine = os.path.join(ROOT, 'acmelib', 'engine')
        seen, twice = {}, []
        for part in sorted(f for f in os.listdir(engine) if f[:3].isdigit() and f.endswith('.py')):
            with open(os.path.join(engine, part), encoding='utf-8') as f:
                for n, line in enumerate(f, 1):
                    m = re.match(r'^(?:async\s+)?(?:def|class)\s+([A-Za-z_]\w*)', line)
                    if m:
                        if m.group(1) in seen:
                            twice.append('%s: %s:%d and %s:%d' % ((m.group(1),) + seen[m.group(1)]
                                                                 + (part, n)))
                        seen.setdefault(m.group(1), (part, n))
        self.assertEqual(twice, [])

    def test_qr_code_as_otp_draws_it(self):
        import acmelib.engine as E
        svg = E.qr_svg('otpauth://totp/acme:admin?secret=JBSWY3DPEHPK3PXP&issuer=acme')
        # the same picture otp 1.0.209 draws for this text
        self.assertEqual(hashlib.sha256(svg.encode()).hexdigest(),
                         'bd5e0621d392d7eced930259b095206bf4ee0a63dedcb0dfcf02b730fb9eeb7c')


if __name__ == '__main__':
    unittest.main(verbosity=2)
