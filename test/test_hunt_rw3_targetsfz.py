#!/usr/bin/env python3
"""Hunt 1.0.143, run w3, area "targetsfz" (the target modules fortiadc ... zimbra): the bugs
found and fixed, each kept fixed.

    python3 test/test_hunt_rw3_targetsfz.py

- fritzbox: the key went as key-rsa, which refuses every EC key - a certificate with an
  ECDSA key (which FRITZ!OS 7.24+ takes, as the guide says) failed before anything was sent.
- local: a path through a link inside the folder made the link's folders outside it (makedirs
  followed the link) before the file was refused as leading outside.
"""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as TT  # noqa: E402
from acmelib.certs.bundle import CertBundle  # noqa: E402


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


def real_bundle(leaf='a'):
    """A CertBundle of the test's EC certificate - as_format as the daemon makes it."""
    crt, key = TT.CERTS[leaf]
    return CertBundle('www.example.test', TT.read(crt), TT.read(key),
                      [TT.read(os.path.join(TT.TMP, 'ca.crt'))])


class FritzBoxEcKeyTest(unittest.TestCase):
    def test_ec_key_uploaded(self):
        sid = 'abcdef0123456789'
        got = {}

        def upload(call):
            got['file'] = call['body']
            return 200, '<html><p>Das SSL-Zertifikat wurde erfolgreich importiert.</p></html>'
        routes = [
            ('GET', r'/login_sid\.lua\?version=2$', (200, '<SessionInfo><Challenge>2$10000$5A1711'
                                                         '$2000$5A1722</Challenge></SessionInfo>')),
            ('POST', r'/login_sid\.lua\?version=2$', (200, '<SessionInfo><SID>%s</SID>'
                                                          '</SessionInfo>' % sid)),
            ('POST', r'/cgi-bin/firmwarecfg$', upload),
            ('GET', r'logout=1', (200, '<SessionInfo><SID>0000000000000000</SID></SessionInfo>')),
        ]
        t = TT.make('fritzbox', {'host': 'fritz.box', 'user': 'acme', 'password': '1example!'},
                    TT.FakeCtx(routes))
        t.served_now = lambda b: False
        b = real_bundle()
        self.assertTrue(b.key_type.startswith('ec'))
        self.assertIn('uploaded', t.deploy(b, {}))
        body = got['file'] if isinstance(got['file'], bytes) else got['file'].encode()
        self.assertIn(b'BEGIN EC PRIVATE KEY', body)
        self.assertIn(b'BEGIN CERTIFICATE', body)


class LocalLinkTest(unittest.TestCase):
    def test_no_folder_made_outside(self):
        d = tempfile.mkdtemp(prefix='acme-w3-local-')
        self.addCleanup(shutil.rmtree, d, True)
        base, out = os.path.join(d, 'base'), os.path.join(d, 'outside')
        os.makedirs(base)
        os.makedirs(out)
        os.symlink(out, os.path.join(base, 'link'))
        t = TT.make('local', {'base': base}, TT.FakeCtx([]))
        with self.assertRaises(TT.PluginError):
            t._place(os.path.realpath(base), 'link/newdir/x.pem')
        self.assertEqual(os.listdir(out), [])
        # a folder inside is still made
        full = t._place(os.path.realpath(base), 'www/x.pem')
        self.assertTrue(os.path.isdir(os.path.dirname(full)))


if __name__ == '__main__':
    unittest.main()
