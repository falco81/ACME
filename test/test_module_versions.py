#!/usr/bin/env python3
"""Modules of your own and versions of a module (1.0.32).

    python3 test/test_module_versions.py

A file in ACME_PLUGINS with the kind (and version) of a module shipped replaces
it - an override, said on the page; with another module_version it adds a
version; a saved source, validation or target keeps the version it uses. The
files are kept in the database (every copy, the other node of a cluster) and
written back by `acme --plugins-sync NODE`.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-versions-')
PLUG = os.path.join(TMP, 'plugins')
os.makedirs(os.path.join(PLUG, 'targets'))
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')

# The shipped NetScaler has no version: overridden here, with two versions of its own
# beside it (the scenario of a device with two API generations).
OWN_NETSCALER = '''from acmelib.plugins.targets.netscaler import NetScalerTarget
from acmelib.plugins.base import field


class Plain(NetScalerTarget):
    title = 'NetScaler (mine)'           # the override of the shipped one


class Nitro13(NetScalerTarget):
    module_version = '13.1'
    version_label = 'NITRO of 13.1'
    fields = NetScalerTarget.fields + [field('partition13', 'Partition', 'text')]


class Nitro14(NetScalerTarget):
    module_version = '14.1'
    version_label = 'NITRO of 14.1'
    default_version = True
    fields = NetScalerTarget.fields + [field('token14', 'Token', 'secret')]

    def test(self):
        return 'v14'
'''
# A kind of its own, in two versions; neither is plain.
OWN_KIND = '''from acmelib.plugins.base import Target, field


class A(Target):
    kind = 'my_box'
    title = 'My box'
    module_version = 'v1'
    fields = [field('host', 'Host')]


class B(Target):
    kind = 'my_box'
    title = 'My box'
    module_version = 'v2'
    fields = [field('host', 'Host'), field('key2', 'Key', 'secret')]
'''
with open(os.path.join(PLUG, 'targets', 'netscaler.py'), 'w') as f:
    f.write(OWN_NETSCALER)
with open(os.path.join(PLUG, 'targets', 'my_box.py'), 'w') as f:
    f.write(OWN_KIND)
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=PLUG)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import custom_modules as CM  # noqa: E402
from acmelib.certs import store as S  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
NS = {'host': 'adc', 'user': 'u', 'password': 'pw'}


class TestRegistry(unittest.TestCase):
    def test_override_and_versions(self):
        reg = S.registry()
        vers = reg.versions_of('target', 'netscaler')
        self.assertEqual(sorted(vers), ['', '13.1', '14.1'])
        self.assertEqual(vers[''].title, 'NetScaler (mine)')
        self.assertEqual(vers['']._origin, 'custom')
        self.assertTrue(vers['']._overrides.endswith('acmelib/plugins/targets/netscaler.py'))
        self.assertEqual(vers['14.1']._overrides, '', 'a version of its own adds, not replaces')
        self.assertIs(reg.get('target', 'netscaler'), vers['14.1'], 'default_version')
        self.assertIs(reg.get('target', 'netscaler', '13.1'), vers['13.1'])
        self.assertIs(reg.get('target', 'netscaler', ''), vers[''])
        self.assertIs(reg.get('target', 'netscaler', 'gone'), vers['14.1'], 'missing: default')
        # a kind of its own with no plain version: the first by name is the default
        self.assertEqual(reg.get('target', 'my_box').module_version, 'v1')
        # a shipped module nobody touched
        self.assertEqual(reg.get('target', 'f5')._origin, 'builtin')

    def test_described(self):
        d = {x['kind']: x for x in A.plugins_view(STORE)['target']}
        ns = d['netscaler']
        self.assertEqual(ns['default_version'], '14.1')
        self.assertEqual([v['version'] for v in ns['versions']], ['', '13.1', '14.1'])
        self.assertEqual([v['default'] for v in ns['versions']], [False, False, True])
        plain = ns['versions'][0]
        self.assertEqual((plain['origin'], bool(plain['overrides'])), ('custom', True))
        self.assertIn('partition13', [f['key'] for f in ns['versions'][1]['fields']])
        self.assertEqual(d['f5']['versions'], [])
        self.assertEqual(d['f5']['origin'], 'builtin')

    def test_secrets_of_every_version_sealed(self):
        cls = S.plugin_class('target', 'netscaler', '13.1')
        self.assertIn('token14', S.secret_fields(cls))


class TestRows(unittest.TestCase):
    def save(self, name, cfg):
        return A.family_save(STORE, 'target', {'name': name, 'kind': 'netscaler',
                                               'config': dict(NS, **cfg)}, 'tester')

    def test_kept_and_used(self):
        rid = self.save('ns13', {'_version': '13.1', 'partition13': 'p1'})
        row = S.plugin_row(STORE, 'target', rid)
        self.assertEqual(S.row_class('target', row).module_version, '13.1')
        pub = S.plugin_public(STORE, 'target', row, True)
        self.assertEqual((pub['version'], pub['version_missing'], pub['origin']),
                         ('13.1', False, 'custom'))
        rid2 = self.save('nsdef', {})
        self.assertEqual(S.row_class('target', S.plugin_row(STORE, 'target', rid2))
                         .module_version, '14.1', 'none said: the default')

    def test_a_version_not_there_refused(self):
        with self.assertRaises(ValueError) as e:
            self.save('nsbad', {'_version': '9.9'})
        self.assertIn('no version "9.9"', str(e.exception))

    def test_a_version_gone_said(self):
        rid = self.save('nsgone', {'_version': '13.1'})
        STORE.db.update('cert_targets', rid, {'config': json.dumps(
            dict(S.jload(S.plugin_row(STORE, 'target', rid)['config']), _version='12.0'))})
        row = S.plugin_row(STORE, 'target', rid)
        pub = S.plugin_public(STORE, 'target', row, True)
        self.assertTrue(pub['version_missing'])
        self.assertEqual((pub['version_kept'], pub['version']), ('12.0', '14.1'))

    def test_the_version_tried(self):
        rid = self.save('ns14', {'_version': '14.1'})
        got = A.family_test(STORE, 'target', {'id': rid}, 'tester')
        self.assertEqual(got['said'], 'v14')
        self.assertTrue(got['ok'])

    def test_secret_of_a_version_sealed_in_the_database(self):
        rid = self.save('ns14s', {'_version': '14.1', 'token14': 'tok-14'})
        raw = S.plugin_row(STORE, 'target', rid)['config']
        self.assertNotIn('tok-14', raw)
        self.assertEqual(S.plugin_config('target', S.plugin_row(STORE, 'target', rid))
                         ['token14'], 'tok-14')


class TestKept(unittest.TestCase):
    def test_kept_compared_and_written_back(self):
        CM.record(STORE)
        me = CM._node()
        got = CM.kept(STORE)[me]
        self.assertEqual(sorted(got['files']), ['targets/my_box.py', 'targets/netscaler.py'])
        # another node with one file less and one different
        other = json.loads(json.dumps(got))
        other['files'].pop('targets/my_box.py')
        import base64
        import hashlib
        changed = OWN_NETSCALER.replace('mine', 'theirs').encode()
        other['files']['targets/netscaler.py'] = {
            'sha256': hashlib.sha256(changed).hexdigest(), 'bytes': len(changed),
            'text': base64.b64encode(changed).decode()}
        STORE.set_meta(CM.KEY + 'node-b', json.dumps(other))
        st = CM.status(STORE)
        o = [x for x in st['others'] if x['node'] == 'node-b'][0]
        self.assertEqual(o['only_here'], ['targets/my_box.py'])
        self.assertEqual(o['different'], ['targets/netscaler.py'])
        # written back into another folder (a new machine), node-b's way
        dst = os.path.join(TMP, 'restored')
        done = CM.sync(STORE, 'node-b', dst)
        self.assertEqual(done, [('written', 'targets/netscaler.py')])
        with open(os.path.join(dst, 'targets', 'netscaler.py'), 'rb') as f:
            self.assertEqual(f.read(), changed)
        self.assertEqual(CM.sync(STORE, 'node-b', dst), [], 'the same: nothing written')
        with self.assertRaises(ValueError):
            CM.sync(STORE, 'nobody', dst)

    def test_in_every_copy(self):
        """The nightly copy holds the table meta: the files with it."""
        import gzip
        CM.record(STORE)
        out = os.path.join(TMP, 'copy.json.gz')
        E.dump_tables(STORE.db, out, child=True)
        with gzip.open(out, 'rt') as f:
            text = f.read()
        self.assertIn(CM.KEY + CM._node(), text)


class FakeH(object):
    def __init__(self, role, body=None, args=None):
        self.store, self.role, self._body, self._args = STORE, role, body or {}, args or {}

    def me(self, _role):
        return {'name': 'someone', 'role': self.role}

    def body(self):
        return self._body

    def arg(self, k, default=''):
        return self._args.get(k, default)


UPLOAD = """from acmelib.plugins.targets.f5 import F5Target


class F5v17(F5Target):
    module_version = '17'
    version_label = 'BIG-IP 17'
"""


class TestUpload(unittest.TestCase):
    def call(self, method, path, role='fulladmin', body=None, args=None):
        return E.ROUTES[(method, path)](FakeH(role, body, args))

    def test_analyse_install_load_remove(self):
        b = {'family': 'target', 'filename': 'f5_v17.py', 'text': UPLOAD}
        got = self.call('POST', '/api/modules/analyse', body=b)
        self.assertTrue(got['ok'], got)
        self.assertEqual([(c['kind'], c['version'], c['does']) for c in got['classes']],
                         [('f5', '17', 'version')])
        got = self.call('POST', '/api/modules/install', body=b)
        self.assertTrue(got['ok'])
        v = S.registry().versions_of('target', 'f5')
        self.assertEqual(sorted(v), ['', '17'])
        self.assertEqual(v['17']._source, 'uploaded')
        self.assertIs(S.plugin_class('target', 'f5'), v[''], 'the plain one stays the default')
        lst = self.call('GET', '/api/modules', role='certadmin')
        self.assertIn('targets/f5_v17.py', lst['uploaded'])
        self.assertNotIn('text', lst['uploaded']['targets/f5_v17.py'])
        f5 = [d for d in lst['target'] if d['kind'] == 'f5'][0]
        self.assertEqual([x['version'] for x in f5['versions']], ['', '17'])
        # the same again: an override of the upload
        again = self.call('POST', '/api/modules/analyse', body=b)
        self.assertTrue(again['replaces_upload'])
        self.assertEqual(again['classes'][0]['does'], 'override')
        src = self.call('GET', '/api/modules/uploaded', args={'path': 'targets/f5_v17.py'})
        self.assertEqual(src['text'], UPLOAD)
        self.call('POST', '/api/modules/remove', body={'path': 'targets/f5_v17.py'})
        self.assertEqual(sorted(S.registry().versions_of('target', 'f5')), [''])

    def test_source_of_a_shipped_module(self):
        got = self.call('GET', '/api/modules/source', args={'family': 'target', 'kind': 'f5'})
        self.assertEqual(got['file'], 'f5.py')
        self.assertIn('class', got['text'])
        got = self.call('GET', '/api/modules/source', args={
            'family': 'target', 'kind': 'netscaler', 'version': '', 'has_version': '1'})
        self.assertIn('NetScaler (mine)', got['text'], 'the version asked: the override')

    def test_bad_uploads_said(self):
        bad = self.call('POST', '/api/modules/analyse', body={
            'family': 'target', 'filename': 'x.py', 'text': 'def (:'})
        self.assertFalse(bad['ok'])
        self.assertIn('line 1', bad['error'])
        bad = self.call('POST', '/api/modules/analyse', body={
            'family': 'target', 'filename': 'x.py', 'text': 'import nothing_like_this\n'})
        self.assertFalse(bad['ok'])
        self.assertIn('nothing_like_this', bad['error'])
        bad = self.call('POST', '/api/modules/analyse', body={
            'family': 'target', 'filename': 'x.py', 'text': 'X = 1\n'})
        self.assertIn('no target module', bad['error'])
        with self.assertRaises(ValueError):
            self.call('POST', '/api/modules/analyse', body={
                'family': 'target', 'filename': '../evil.py', 'text': 'X = 1'})
        with self.assertRaises(ValueError):
            self.call('POST', '/api/modules/install', body={
                'family': 'target', 'filename': 'x.py', 'text': 'X = 1\n'})

    def test_a_full_administrator_only(self):
        from acmelib import engine as EN
        with self.assertRaises(EN.ApiError):
            self.call('POST', '/api/modules/analyse', role='certadmin', body={
                'family': 'target', 'filename': 'x.py', 'text': 'X = 1'})

    def test_written_by_another_node(self):
        """Uploaded on one node: the other writes it into its folder and loads it."""
        b = {'family': 'target', 'filename': 'f5_v18.py',
             'text': UPLOAD.replace("'17'", "'18'").replace('F5v17', 'F5v18')}
        self.call('POST', '/api/modules/install', body=b)
        os.remove(os.path.join(CM.uploaded_dir(), 'targets', 'f5_v18.py'))
        CM._SEEN['sig'] = None                  # as a node that has not seen it
        CM._SEEN['at'] = 0
        S.registry(True)
        self.assertNotIn('18', S.registry().versions_of('target', 'f5'))
        self.assertTrue(CM.keep_current(STORE))
        self.assertIn('18', S.registry().versions_of('target', 'f5'))
        self.call('POST', '/api/modules/remove', body={'path': 'targets/f5_v18.py'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
