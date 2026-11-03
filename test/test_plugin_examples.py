#!/usr/bin/env python3
"""The examples installed into /etc/acme/plugins/examples (deploy/plugins) work.

    python3 test/test_plugin_examples.py

Each is copied where its words say (/etc/acme/plugins/<folder>/<name>.py - here
a folder of the test's own) and loaded as acme loads it: what it says it is -
a new module, another version of one shipped, an override - it is, and nothing
breaks. The new target is deployed into a folder of the test.
"""
import os
import re
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from acmelib.plugins import base  # noqa: E402

EX = os.path.join(ROOT, 'deploy', 'plugins', 'examples')
# example -> (the file name its words say, family, kind, version, override)
WANT = {
    'targets/example_folder.py.example': ('example_folder.py', 'target', 'example_folder', '', False),
    'targets/example_netscaler_version.py.example': ('netscaler_14_1.py', 'target', 'netscaler', '14.1', False),
    'targets/example_ssh_override.py.example': ('ssh.py', 'target', 'ssh', '', True),
    'checks/example_tls_8443.py.example': ('example_tls_8443.py', 'check', 'example_tls_8443', '', False),
    'challenges/example_desec_version.py.example': ('desec_slow.py', 'challenge', 'desec', 'slow', False),
    'issuers/example_selfsigned_version.py.example': ('selfsigned_10y.py', 'issuer', 'selfsigned', '10y', False),
}


class TestExamples(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='acme-examples-')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_every_example_is_listed_and_says_where_it_goes(self):
        found = sorted('%s/%s' % (d, f) for d in os.listdir(EX) for f in os.listdir(os.path.join(EX, d)))
        self.assertEqual(found, sorted(WANT))
        for rel, (fname, _fam, _k, _v, _o) in WANT.items():
            with open(os.path.join(EX, rel)) as f:
                text = f.read()
            self.assertIn('/etc/acme/plugins/%s/%s' % (rel.split('/')[0], fname), text, rel)

    def test_each_loads_as_it_says(self):
        for rel, (fname, fam, kind, ver, over) in WANT.items():
            d = os.path.join(self.tmp, rel.split('/')[0])
            os.makedirs(d, exist_ok=True)
            shutil.copy(os.path.join(EX, rel), os.path.join(d, fname))
        reg = base.Registry(extra_dirs=[self.tmp]).reload()
        self.assertEqual(reg.broken, [], reg.broken)
        for rel, (fname, fam, kind, ver, over) in WANT.items():
            cls = reg.versions[fam][kind][ver]
            self.assertEqual(cls._origin, 'custom', rel)
            self.assertEqual(bool(cls._overrides), over, rel)
            self.assertTrue(cls._module_file.endswith('/' + fname), rel)
            cls.describe()                              # the page can draw it
        # a version leaves the shipped one there, and its default
        self.assertEqual(sorted(reg.versions['target']['netscaler']), ['', '14.1'])
        self.assertEqual(reg.found['target']['netscaler'].module_version, '')
        self.assertEqual(dict((f['key'], f.get('default')) for f in
                              reg.versions['challenge']['desec']['slow'].fields)['settle'], 180)

    def test_the_new_target_deploys(self):
        d = os.path.join(self.tmp, 'targets')
        os.makedirs(d)
        shutil.copy(os.path.join(EX, 'targets/example_folder.py.example'), os.path.join(d, 'example_folder.py'))
        reg = base.Registry(extra_dirs=[self.tmp]).reload()
        cls = reg.found['target']['example_folder']
        out = os.path.join(self.tmp, 'out')

        class Bundle(object):
            name = 'www.example.test'
            fullchain_pem = '-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n'
            key_pem = '-----BEGIN PRIVATE KEY-----\nY\n-----END PRIVATE KEY-----\n'
        t = cls({'folder': out}, None)
        self.assertIn('can be written', t.test())
        said = t.deploy(Bundle(), {})
        self.assertIn('www.example.test', said)
        key = os.path.join(out, 'www.example.test', 'privkey.pem')
        self.assertEqual(oct(os.stat(key).st_mode & 0o777), '0o600')
        with self.assertRaises(base.PluginError):
            cls({'folder': '/'}, None).test()


if __name__ == '__main__':
    unittest.main(verbosity=2)
