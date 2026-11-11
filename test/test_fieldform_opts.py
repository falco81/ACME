#!/usr/bin/env python3
"""The form of a module hands its options (the module, the row, the family) to the fields drawn
by a part of their own - the SSH key card (sshkey.js), the catalog picker (catalog.js) - 1.0.63:

    python3 test/test_fieldform_opts.py

A `var opts` of a list field inside the loop over the fields hid the form's own `opts` (var is
the whole function's): every SSH key card got no module and no row, and Make a key, Use my own,
Download, Forget and Try reaching it all said: there is no target module (an empty name).
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FieldFormOpts(unittest.TestCase):
    def test_nothing_hides_opts(self):
        js = open(os.path.join(ROOT, 'web/assets/certs.js'), encoding='utf-8').read()
        start = js.index('function fieldForm(fields, values, secrets, opts) {')
        end = js.index('\nfunction ', start + 10)
        body = js[start:end]
        self.assertIn('opts: opts', body)
        self.assertIsNone(re.search(r'\bvar\s+opts\b', body))
        self.assertIsNone(re.search(r'\b(var|let|const)\s+(plug|row|family)\b\s*=\s*(?!el\()', body))

    def test_card_names_its_module(self):
        js = open(os.path.join(ROOT, 'web/assets/sshkey.js'), encoding='utf-8').read()
        self.assertIn("var b = {family: family, kind: plug.kind, field: f.key, name: nameNow()};", js)


if __name__ == '__main__':
    unittest.main(verbosity=1)
