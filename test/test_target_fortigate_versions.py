#!/usr/bin/env python3
"""The versions of the FortiGate target (1.0.94), without a network.

    python3 test/test_target_fortigate_versions.py

Each version of the module is for a range of FortiOS versions and sends the
shapes of that range only (Fortinet's Ansible collection, 6.0.0 - 8.0.0):

  ''        any version: reads the FortiOS version, the other shape tried after
  '6.0'     6.0 - 6.4     ssl-ssh-profile server-cert a name, vip ssl-certificate a name
  '7.0'     7.0 - 7.4.1   server-cert a list of {name},       ssl-certificate a name
  '7.4.2'   7.4.2 - 8.0   server-cert a list,                 ssl-certificate a list

The fake Context and certificates are those of test_targets.py.
"""
import os
import json
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import fortigate as FG  # noqa: E402


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


def make(version, ctx, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', 'fortigate', version)
    assert cls.module_version == version, (cls.module_version, version)
    return cls(dict({'host': 'fw', 'token': 'TKN', 'vdom': 'root'}, **cfg), ctx)


def routes(fos, profile=None, vip=None, put=None, extra=()):
    """A FortiGate on FortiOS `fos`, the profile "inbound" and the VIP "web" holding
    these server-cert / ssl-certificate values."""
    ok = (200, {'status': 'success'})
    return list(extra) + [
        ('GET', r'/monitor/system/status', (200, {'status': 'success', 'version': fos,
                                                  'serial': 'FG100F', 'vdom': 'root',
                                                  'results': {'hostname': 'fw1',
                                                              'model_name': 'FortiGate'}})),
        ('GET', r'/cmdb/vpn.certificate/local/acme', (404, {'status': 'error'})),
        ('POST', r'/monitor/vpn-certificate/local/import', ok),
        ('POST', r'/monitor/vpn-certificate/ca/import', ok),
        ('PUT', r'/cmdb/system/global', ok),
        ('PUT', r'/cmdb/vpn.ssl/settings', ok),
        ('GET', r'/cmdb/firewall/ssl-ssh-profile/inbound',
         (200, {'results': [{'name': 'inbound', 'server-cert': profile}]})),
        ('GET', r'/cmdb/firewall/vip/web', (200, {'results': [{'name': 'web',
                                                               'ssl-certificate': vip}]})),
        ('PUT', r'/cmdb/firewall/(ssl-ssh-profile|vip)/', put or ok),
        ('GET', r'/cmdb/vpn.certificate/local\?', (200, {'results': []})),
    ]


ALL = {'admin': True, 'sslvpn': True, 'ssl_ssh_profiles': 'inbound', 'vips': 'web'}


class VersionsTest(unittest.TestCase):
    def test_registered(self):
        reg = Registry(extra_dirs=[]).reload()
        vers = reg.versions_of('target', 'fortigate')
        self.assertEqual(sorted(vers), ['', '6.0', '7.0', '7.4.2'])
        self.assertIs(reg.get('target', 'fortigate'), vers[''], 'the plain one stays the default')
        self.assertIs(reg.get('target', 'fortigate', ''), vers[''])
        labels = {k: c.version_label for k, c in vers.items()}
        self.assertEqual(labels, {'': 'any version (detects it)', '6.0': 'FortiOS 6.0 - 6.4',
                                  '7.0': 'FortiOS 7.0 - 7.4.1', '7.4.2': 'FortiOS 7.4.2 - 8.0'})
        for k, c in vers.items():
            self.assertEqual(c.fields, vers[''].fields, 'saved settings fit every version')
            self.assertEqual(c.deploy_fields, vers[''].deploy_fields)
            self.assertTrue(c.description)
            if k:
                self.assertIn(c.version_label, c.description)
        d = [x for x in reg.describe()['target'] if x['kind'] == 'fortigate'][0]
        self.assertEqual([v['version'] for v in d['versions']], ['', '6.0', '7.0', '7.4.2'])
        self.assertEqual(d['default_version'], '')

    def test_version_for(self):
        self.assertEqual(FG.version_for((6, 2, 16))[0], '6.0')
        self.assertEqual(FG.version_for((6, 4, 15))[0], '6.0')
        self.assertEqual(FG.version_for((7, 0, 0))[0], '7.0')
        self.assertEqual(FG.version_for((7, 4, 1))[0], '7.0')
        self.assertEqual(FG.version_for((7, 4, 2))[0], '7.4.2')
        self.assertEqual(FG.version_for((7, 6, 4))[0], '7.4.2')
        self.assertEqual(FG.version_for((8, 0, 0))[0], '7.4.2')
        self.assertEqual(FG.version_for((5, 6, 14)), ('', ''))


class ShapesTest(unittest.TestCase):
    """Each version: the requests made and the bodies of the four uses."""
    def deploy(self, version, fos, profile=None, vip=None):
        b = FakeBundle()
        ctx = FakeCtx(routes(fos, profile, vip))
        make(version, ctx).deploy(b, dict(ALL, keep=1))
        return ctx, C.object_name(b, {}, maxlen=35, serial_len=6), \
            C.name_prefix(b, {}, maxlen=35, serial_len=6)

    def common(self, ctx, name):
        self.assertTrue(all(c['headers']['Authorization'] == 'Bearer TKN' for c in ctx.calls))
        imp = ctx.json(ctx.find('POST', 'vpn-certificate/local/import')[0])
        self.assertEqual((imp['type'], imp['certname'], imp['scope']), ('pkcs12', name, 'global'))
        ca = ctx.json(ctx.find('POST', 'vpn-certificate/ca/import')[0])
        self.assertEqual((ca['import_method'], ca['scope']), ('file', 'global'))
        self.assertEqual(ctx.json(ctx.find('PUT', 'system/global')[0]), {'admin-server-cert': name})
        sv = ctx.find('PUT', 'vpn.ssl/settings')[0]
        self.assertEqual((ctx.json(sv), sv['query']['vdom']), ({'servercert': name}, ['root']))
        self.assertEqual(len(ctx.find('GET', 'monitor/system/status')), 1, 'read once')

    def puts(self, ctx, what):
        return [ctx.json(c) for c in ctx.find('PUT', 'firewall/%s/' % what)]

    def test_60(self):
        ctx, name, _p = self.deploy('6.0', 'v6.4.15')
        self.common(ctx, name)
        self.assertEqual(self.puts(ctx, 'ssl-ssh-profile'), [{'server-cert': name}])
        self.assertEqual(self.puts(ctx, 'vip'), [{'ssl-certificate': name}])
        self.assertFalse(ctx.find('GET', 'firewall/'), 'a name: nothing to keep, nothing read')

    def test_70(self):
        ctx, name, prefix = self.deploy('7.0', 'v7.2.11', profile=[
            {'name': 'Fortinet_SSL_ECDSA256'}, {'name': prefix_of() + '20250101-aaaaaa'}])
        self.common(ctx, name)
        self.assertEqual(self.puts(ctx, 'ssl-ssh-profile'), [{'server-cert': [
            {'name': 'Fortinet_SSL_ECDSA256'}, {'name': name}]}], 'others kept, ours replaced')
        self.assertEqual(self.puts(ctx, 'vip'), [{'ssl-certificate': name}])

    def test_70_edge_741(self):
        ctx, name, _p = self.deploy('7.0', 'v7.4.1')
        self.assertEqual(self.puts(ctx, 'vip'), [{'ssl-certificate': name}])

    def test_742(self):
        for fos in ('v7.4.2', 'v7.4.8', 'v7.6.4', 'v8.0.0'):
            ctx, name, prefix = self.deploy('7.4.2', fos, profile=[{'name': 'Fortinet_SSL'}],
                                            vip=[{'name': 'web-ecdsa'},
                                                 {'name': prefix_of() + '20250101-aaaaaa'}])
            self.common(ctx, name)
            self.assertEqual(self.puts(ctx, 'ssl-ssh-profile'), [{'server-cert': [
                {'name': 'Fortinet_SSL'}, {'name': name}]}], fos)
            self.assertEqual(self.puts(ctx, 'vip'), [{'ssl-certificate': [
                {'name': 'web-ecdsa'}, {'name': name}]}], fos)

    def test_plain_still_detects(self):
        ctx, name, _p = self.deploy('', 'v7.4.3', vip=[{'name': 'x'}])
        self.common(ctx, name)
        self.assertEqual(self.puts(ctx, 'vip'), [{'ssl-certificate': [{'name': 'x'},
                                                                      {'name': name}]}])
        ctx, name, _p = self.deploy('', 'v6.4.9')
        self.assertEqual(self.puts(ctx, 'ssl-ssh-profile'), [{'server-cert': name}])

    def test_plain_unknown_version_tries_both(self):
        b = FakeBundle()
        name = C.object_name(b, {}, maxlen=35, serial_len=6)
        ctx = FakeCtx(routes('?', put=lambda c: (500, {'status': 'error', 'error': -651})
                             if isinstance(json.loads(c['body'])['ssl-certificate'], str)
                             else (200, {'status': 'success'})))
        make('', ctx).deploy(b, {'vips': 'web', 'import_chain': False})
        self.assertEqual(self.puts(ctx, 'vip'), [{'ssl-certificate': name},
                                                 {'ssl-certificate': [{'name': name}]}])


def prefix_of():
    return C.name_prefix(FakeBundle(), {}, maxlen=35, serial_len=6)


class RefusedTest(unittest.TestCase):
    def test_another_fortios_refused_before_any_change(self):
        for version, fos, fit in (('6.0', 'v7.0.12', 'FortiOS 7.0 - 7.4.1'),
                                  ('7.0', 'v7.4.2', 'FortiOS 7.4.2 - 8.0'),
                                  ('7.0', 'v6.4.15', 'FortiOS 6.0 - 6.4'),
                                  ('7.4.2', 'v7.4.1', 'FortiOS 7.0 - 7.4.1'),
                                  ('7.4.2', 'v5.6.14', 'any version (detects it)')):
            ctx = FakeCtx(routes(fos))
            with self.assertRaises(PluginError) as e:
                make(version, ctx).deploy(FakeBundle(), dict(ALL))
            self.assertFalse(e.exception.retry)
            self.assertIn('runs FortiOS %s' % fos[1:], str(e.exception))
            self.assertIn('"%s"' % fit, str(e.exception), (version, fos))
            self.assertEqual({c['method'] for c in ctx.calls}, {'GET'}, 'nothing changed')

    def test_try_says_it(self):
        ctx = FakeCtx(routes('v7.6.4'))
        self.assertIn('FortiOS v7.6.4', make('7.4.2', ctx).test())
        with self.assertRaises(PluginError) as e:
            make('6.0', FakeCtx(routes('v7.6.4'))).test()
        self.assertIn('choose the version "FortiOS 7.4.2 - 8.0"', str(e.exception))
        self.assertIn('FortiOS v7.6.4', make('', FakeCtx(routes('v7.6.4'))).test())

    def test_the_other_shape_not_tried(self):
        """A version sends its own shape only: refused, it is an error (no guessing)."""
        ctx = FakeCtx(routes('v7.2.0', put=(500, {'status': 'error', 'error': -3})))
        with self.assertRaises(PluginError):
            make('7.0', ctx).deploy(FakeBundle(), {'vips': 'web', 'import_chain': False})
        self.assertEqual(len(ctx.find('PUT', 'firewall/vip')), 1)

    def test_version_unknown_warned_own_shapes(self):
        b = FakeBundle()
        name = C.object_name(b, {}, maxlen=35, serial_len=6)
        ctx = FakeCtx(routes('', extra=[('GET', r'/monitor/system/status', (403, {}))]))
        make('7.4.2', ctx).deploy(b, {'vips': 'web', 'import_chain': False})
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'cannot be read' in w])
        self.assertEqual([ctx.json(c) for c in ctx.find('PUT', 'firewall/vip')],
                         [{'ssl-certificate': [{'name': name}]}])

    def test_newer_than_checked_warned(self):
        ctx = FakeCtx(routes('v8.2.0'))
        make('7.4.2', ctx).deploy(FakeBundle(), {'vips': 'web', 'import_chain': False})
        self.assertTrue([w for lvl, w in ctx.steps if lvl == 'warn' and 'newer' in w])

    def test_discovery_says_the_version_for_it(self):
        got = make('', FakeCtx(routes('v7.4.8'))).discover_setup()
        self.assertIn(['Module version for it', 'FortiOS 7.4.2 - 8.0'], got['facts'])
        got = make('', FakeCtx(routes('v6.2.3'))).discover_setup()
        self.assertIn(['Module version for it', 'FortiOS 6.0 - 6.4'], got['facts'])


class GuidesTest(unittest.TestCase):
    def test_a_guide_for_each_version_in_both_languages(self):
        d = os.path.join(os.path.dirname(HERE), 'acmelib', 'plugins', 'guides', 'targets')
        for v in ('', '6.0', '7.0', '7.4.2'):
            for suffix in ('.md', '.cs.md'):
                p = os.path.join(d, 'fortigate%s%s' % ('@' + v if v else '', suffix))
                with open(p, encoding='utf-8') as f:
                    md = f.read()
                self.assertTrue(md.startswith('# '), p)
                self.assertIn('config system accprofile', md, p)
                self.assertIn('config system api-user', md, p)
                self.assertIn('execute api-user generate-key', md, p)


if __name__ == '__main__':
    unittest.main(verbosity=1)
