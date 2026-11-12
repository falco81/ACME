#!/usr/bin/env python3
"""Hunt L (1.0.96): fixes of three rounds of looking for bugs.

    python3 test/test_hunt_l.py
"""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TMP = tempfile.mkdtemp(prefix='acme-huntl-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
DAEMON = E.Daemon(STORE, serve=False)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def call(method, path, body=None, args=None, role='fulladmin'):
    h = E.CliApiHandler(DAEMON, 'tester', body or {}, args or {}, path)
    h.me = lambda need=None: {'name': 'tester', 'role': role}
    return E.ROUTES[(method, path)](h)


class Events(unittest.TestCase):
    def test_1_words_of_the_page_language_find_the_english(self):
        """The page sends the English the typed words stand for (i18nBack): any of them."""
        STORE.add_event('auth', 'alice signed in from 10.0.0.1', who='alice')
        STORE.add_event('settings', 'bob changed the firewall', who='bob')
        self.assertEqual(call('GET', '/api/events', args={'q': 'přihlásil'})['rows'], [])
        got = call('GET', '/api/events', args={'q': 'přihlásil', 'q_alt': 'signed in from\nsigned in'})
        self.assertEqual([r['words'] for r in got['rows']], ['alice signed in from 10.0.0.1'])
        got = call('GET', '/api/events', args={'q': 'kind:auth přihlásil', 'q_alt': 'signed in'})
        self.assertEqual(len(got['rows']), 1)
        got = call('GET', '/api/events', args={'q': 'kind:settings přihlásil', 'q_alt': 'signed in'})
        self.assertEqual(got['rows'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
