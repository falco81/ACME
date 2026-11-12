#!/usr/bin/env python3
"""The setup guides of the modules (1.0.94, acmelib/certs/guides.py): where one comes from -
written on the page, carried by a module of your own, shipped (versioned, then plain; Czech,
then English), made from the module's fields - the API (anybody reads, a full administrator
writes and gives back) and the configuration file carrying the written ones.

    python3 test/test_guides.py
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
TMP = tempfile.mkdtemp(prefix='acme-guides-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A, guides as G  # noqa: E402,F401
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
DAEMON = E.Daemon(STORE, serve=False)
SHIPPED = os.path.join(TMP, 'guides')


def setUpModule():
    os.makedirs(os.path.join(SHIPPED, 'targets'))
    for name, text in (('f5.md', '# F5 plain\n'), ('f5.cs.md', '# F5 česky\n'),
                       ('f5@17.md', '# F5 for 17\n')):
        with open(os.path.join(SHIPPED, 'targets', name), 'w') as f:
            f.write(text)
    G.HERE = SHIPPED


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def call(method, path, body=None, role='fulladmin', args=None):
    h = E.CliApiHandler(DAEMON, 'tester', body or {}, args or {}, path)
    h.me = lambda need=None: {'name': 'tester', 'role': role}
    return E.ROUTES[(method, path)](h)


class Guides(unittest.TestCase):
    def test_1_shipped_versioned_language(self):
        got = G.guide(STORE, 'target', 'f5', '', 'en')
        self.assertEqual((got['origin'], got['md'].strip()), ('shipped', '# F5 plain'))
        self.assertEqual(G.guide(STORE, 'target', 'f5', '17', 'en')['md'].strip(), '# F5 for 17')
        # a version without its own: the plain one
        self.assertEqual(G.guide(STORE, 'target', 'f5', '16', 'en')['md'].strip(), '# F5 plain')
        self.assertEqual(G.guide(STORE, 'target', 'f5', '', 'cs')['md'].strip(), '# F5 česky')
        # Czech asked, none for that version in Czech: English of that version
        cs17 = G.guide(STORE, 'target', 'f5', '17', 'cs')
        self.assertEqual((cs17['md'].strip(), cs17['lang']), ('# F5 česky', 'cs'))

    def test_2_made_when_none(self):
        got = G.guide(STORE, 'target', 'kemp', '', 'en')
        self.assertEqual(got['origin'], 'made')
        self.assertIn('Kemp', got['md'])
        self.assertIn('| Field |', got['md'])
        self.assertIn('nastavení pro acme', G.guide(STORE, 'target', 'kemp', '', 'cs')['md'])

    def test_3_written_over_and_given_back(self):
        G.save(STORE, 'target', 'f5', '17', 'cs', '# Můj návod\n\n```text\nset x\n```', 'tester')
        got = G.guide(STORE, 'target', 'f5', '17', 'cs')
        self.assertEqual((got['origin'], got['written_by']), ('written', 'tester'))
        # only that version and language
        self.assertEqual(G.guide(STORE, 'target', 'f5', '17', 'en')['origin'], 'shipped')
        self.assertEqual(G.default_of('target', 'f5', '17', 'cs')['origin'], 'shipped')
        self.assertEqual([(x['kind'], x['version'], x['lang']) for x in G.written(STORE)],
                         [('f5', '17', 'cs')])
        G.save(STORE, 'target', 'f5', '17', 'cs', '', 'tester')
        self.assertEqual(G.guide(STORE, 'target', 'f5', '17', 'cs')['origin'], 'shipped')

    def test_4_checked(self):
        for bad in (('nope', 'f5', '', 'en'), ('target', '../x', '', 'en'),
                    ('target', 'f5', 'a/b', 'en')):
            with self.assertRaises(ValueError):
                G.guide(STORE, *bad)
        with self.assertRaises(ValueError):
            G.save(STORE, 'target', 'f5', '', 'en', 'x' * (G.MAX_MD + 1), 'tester')

    def test_5_a_module_of_your_own_carries_one(self):
        d = os.path.join(TMP, 'plugins', 'targets')
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'mine.py'), 'w') as f:
            f.write('from acmelib.plugins.targets.local import LocalTarget\n'
                    'class Mine(LocalTarget):\n    kind = "mine"\n    title = "Mine"\n'
                    '    guide = "# Mine in the class"\n')
        with open(os.path.join(d, 'mine.cs.md'), 'w') as f:
            f.write('# Můj vedle souboru\n')
        base.REGISTRY.reload()
        self.assertEqual(G.guide(STORE, 'target', 'mine', '', 'en')['md'], '# Mine in the class')
        got = G.guide(STORE, 'target', 'mine', '', 'cs')
        self.assertEqual((got['origin'], got['md'].strip()), ('module', '# Můj vedle souboru'))

    def test_6_api_and_roles(self):
        got = call('GET', '/api/modules/guide', role='readonly',
                   args={'family': 'target', 'kind': 'f5', 'version': '17', 'lang': 'en'})
        self.assertEqual(got['md'].strip(), '# F5 for 17')
        self.assertFalse(got['may'])
        self.assertTrue(call('GET', '/api/modules/guide', args={'family': 'target', 'kind': 'f5'})['may'])
        r = call('POST', '/api/modules/guide', {'family': 'target', 'kind': 'f5', 'version': '',
                                                'lang': 'en', 'md': '# Ours'})
        self.assertTrue(r['written'])
        self.assertEqual(G.guide(STORE, 'target', 'f5', '', 'en')['md'], '# Ours')

    def test_7_carried_by_the_configuration_file(self):
        G.save(STORE, 'check', 'tls', '', 'en', '# TLS ours', 'tester')
        conf = E.config_export(STORE, False)
        self.assertIn('guide:check:tls@:en', conf['guides'])
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'guide:%'")
        said = E.config_import(STORE, DAEMON, {'guides': conf['guides']}, 'tester')
        self.assertGreaterEqual(said.get('setup guides', 0), 1)
        self.assertEqual(G.guide(STORE, 'check', 'tls', '', 'en')['md'], '# TLS ours')


if __name__ == '__main__':
    unittest.main(verbosity=2)
