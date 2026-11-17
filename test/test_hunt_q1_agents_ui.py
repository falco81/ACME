#!/usr/bin/env python3
"""Hunt Q1 (1.0.119): the target agents' pages and the policy builder in a browser -
test/hunt_q1_agents_page.js says what each check is:

    python3 test/test_hunt_q1_agents_ui.py

Needs node with playwright (skipped without them).
"""
import json
import os
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


class AgentsPages(unittest.TestCase):
    def test_hunt_q1_page(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(HERE, 'hunt_q1_agents_page.js'),
                              os.path.join(ROOT, 'web')],
                             capture_output=True, text=True, timeout=300)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
