#!/usr/bin/env python3
"""Every setting has a pane of its own.

    python3 test/test_settings_panes.py

A setting in no pane is drawn in the card of "everything else", which shows
under every pane of Settings - one added without its pane turned up
everywhere (db_path, 1.0.2).
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-panes-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

# The cluster's own wiring, set by its wizard and never listed (settings_state).
WIRING = {'ha_mode', 'ha_slot', 'ha_peer', 'ha_peer_port', 'ha_address', 'ha_tls',
          'ha_tls_ca'}


class Panes(unittest.TestCase):
    def test_every_setting_in_a_pane(self):
        placed = set(k for keys in E.PANES.values() for k in keys)
        loose = sorted(k for k in E.DEFAULTS if k not in placed and k not in WIRING)
        self.assertEqual(loose, [], 'settings in no pane (shown under every pane): %s' % loose)

    def test_no_pane_names_an_unknown_setting(self):
        unknown = sorted(k for keys in E.PANES.values() for k in keys if k not in E.DEFAULTS)
        self.assertEqual(unknown, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
