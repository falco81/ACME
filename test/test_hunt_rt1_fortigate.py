#!/usr/bin/env python3
"""Hunt R (run t1), FortiGate replace in place: regressions, on test_fortigate_replace's fake
FortiGate.

    python3 test/test_hunt_rt1_fortigate.py

- A key that is not the certificate's (checked here) stopped the deployment only after the
  intermediates were imported as CA certificates and acme's own copy was deleted - over the
  REST API and over SSH; now before anything is written.
- A typed "Management VDOM" that differs from the one the FortiGate says: the FortiGate's
  taken; one that is not a VDOM of the FortiGate: not known.
- A token of one VDOM (cmdb system vdom lists only it): VDOMs on.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_fortigate_replace as F  # noqa: E402
from test_fortigate_replace import (Base, Bundle, OtherKeyBundle, make, REPLACE, SSHR,  # noqa
                                    der)
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402


def setUpModule():
    F.setUpModule()


def tearDownModule():
    F.tearDownModule()


class NothingWrittenBeforeKeyCheck(Base):
    def copy(self, b):
        name = C.name_prefix(b, {}, maxlen=35, serial_len=6) + '20261118-191aae'
        self.fg.add(name, b.cert_pem, q_ref=0)
        return name

    def run_bad_key(self, opts):
        b = OtherKeyBundle()
        n = self.copy(b)
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(opts))
        self.assertIn('checked here, nothing was sent to the FortiGate', str(e.exception))
        self.assertEqual(self.fg.writes(), [], 'nothing written before the stop')
        self.assertIn(n, self.fg.local, 'acme\'s copy kept')
        self.assertFalse(self.fg.cas, 'no CA certificate imported')
        return ctx

    def test_api(self):
        self.run_bad_key(REPLACE)

    def test_ssh(self):
        ctx = self.run_bad_key(SSHR)
        self.assertFalse([r for r in ctx.cli.runs() if 'config vpn certificate' in r])



class TypedManagementVdom(Base):
    """The target's "Management VDOM" typed wrong while the FortiGate says its own (a token
    that reads system global): FortiOS's is taken - the way through the global range in a VDOM
    that is not the management one empties the certificate (measured on 7.4.13)."""

    def setUp(self):
        Base.setUp(self)
        self.fg.fos7413 = True
        self.fg.vdom_mode = 'multi-vdom'
        self.fg.version = 'v7.4.13'
        self.fg.mgmt_vdom = 'root'
        self.fg.local['web-cert']['range'] = 'vdom'

    def test_wrong_typed_not_taken(self):
        t, ctx = make(self.fg, ssh=False, vdom='Naj', mgmt_vdom='Naj')
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), dict(REPLACE))
        self.assertIn('management VDOM, root', str(e.exception))
        self.assertEqual(self.fg.writes(), [])

    def test_typed_not_a_vdom_is_not_known(self):
        self.fg.global_defaults = True
        t, ctx = make(self.fg, ssh=False, vdom='Naj', mgmt_vdom='nope')
        self.assertIsNone(t.mgmt_vdom())

    def test_typed_right_taken(self):
        self.fg.global_defaults = True
        t, ctx = make(self.fg, ssh=False, mgmt_vdom='root')
        b = Bundle()
        t.deploy(b, dict(REPLACE))
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))



class OneVdomToken(Base):
    """A token of one VDOM lists that VDOM only (cmdb system vdom): VDOMs are on all the
    same - the copy of the global range deleted in the management VDOM, its rest elsewhere."""

    def test_multi_vdom(self):
        orig = self.fg.answer

        def answer(m, path, q, body):
            if path == '/api/v2/cmdb/system/vdom':
                return 200, {'status': 'success', 'http_status': 200,
                             'results': [{'name': 'Naj'}]}
            return orig(m, path, q, body)
        self.fg.answer = answer
        t, ctx = make(self.fg, vdom='Naj')
        self.assertTrue(t.multi_vdom())
        t, ctx = make(self.fg, vdom='root')
        self.fg.answer = lambda m, path, q, body: (
            (200, {'status': 'success', 'results': [{'name': 'root'}]})
            if path == '/api/v2/cmdb/system/vdom' else orig(m, path, q, body))
        self.assertFalse(t.multi_vdom())


if __name__ == '__main__':
    unittest.main()
