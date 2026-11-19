#!/usr/bin/env python3
"""Bug hunt u3 (1.0.134): Sources, Validation, Targets and Tests - their forms and their API.

    python3 test/test_hunt_ru3_srcval.py

- A module's form, another version of the module picked (FortiGate 6.0 instead of 7.0): the
  form was drawn again and a secret typed (the API token) came back empty, the tags chosen
  gone. Both stay (certs.js modForm: keep.tags, fieldForm's opts.typed).
- "Find the settings from the account": a secret typed in the form came up empty in the
  popup and "Find out" asked for it again (discover.js: typed); the version the form shows
  was not sent (no _version), so the daemon asked the version saved or the default one.
- Delete allowed while in use: a target with acme-agent named by a source "Microsoft CA
  through acme-agent" (its server), a validation named by a dns-persist-01 validation (its
  fallback, its writer), a passive agent that targets go through (via) - deleted at once,
  and what named them failed after. Now in its uses ("change it there first"), refused.
- Renamed, the same: those settings kept the old name. They follow (api._renamed).

A real daemon (test/test_certs_core.py's way); the pages also in Chromium
(test/hunt_ru3_srcval_page.js) when node, php and Playwright are here.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Source(unittest.TestCase):

    def test_version_switch_keeps_typed(self):
        js = read('web/assets/certs.js')
        self.assertIn('typed: keep && keep.config ? keep.config : null', js)
        self.assertIn("tags: tags ? tags.value : undefined});", js)
        self.assertIn('keep && keep.tags !== undefined ? splitNames(keep.tags)', js)
        self.assertEqual(js.count('secretBox(sv, '), 1)
        self.assertEqual(js.count('secretPemBox(sv, '), 1)

    def test_discover_sends_typed_and_version(self):
        js = read('web/assets/discover.js')
        self.assertIn('none: false, typed: now}', js)
        self.assertIn("c._version = String(p.version || '')", js)


class Api(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def rows(self, path):
        return {r['name']: r for r in self.ok('GET', '/api/%s' % path)['rows']}

    def refused(self, path, body):
        st, got = self.call('POST', path, body, self.admin)
        self.assertFalse(got.get('ok'), got)
        return got.get('error') or ''

    def test_1_named_in_settings_is_a_use(self):
        win = self.ok('POST', '/api/targets/save', {
            'name': 'win1', 'kind': 'agent_windows',
            'config': {'mode': 'passive', 'host': 'win1.example.test'}})['id']
        self.ok('POST', '/api/sources/save', {
            'name': 'adcs1', 'kind': 'ms_adcs_agent',
            'config': {'agent': 'win1', 'ca': 'ca01\\Example CA', 'template': 'WebServer'}})
        self.ok('POST', '/api/targets/save', {
            'name': 'web1', 'kind': 'ssh',
            'config': {'host': 'web1.example.test', 'user': 'root', 'via': 'win1'}})
        dns = self.ok('POST', '/api/validations/save', {
            'name': 'dns1', 'kind': 'cloudflare', 'config': {'token': 'abcdefgh12'}})['id']
        self.ok('POST', '/api/validations/save', {
            'name': 'persist1', 'kind': 'dns_persist',
            'config': {'fallback': 'dns1', 'writer': 'dns1'}})
        uses = self.ok('GET', '/api/targets/uses', args={'id': win})['uses']
        got = sorted((u['where'], u['name'], u['free']) for u in uses)
        self.assertEqual(got, [('source', 'adcs1', False), ('target', 'web1', False)])
        self.assertIn('in use', self.refused('/api/targets/delete', {'id': win, 'force': 1}))
        uses = self.ok('GET', '/api/validations/uses', args={'id': dns})['uses']
        self.assertEqual([(u['where'], u['name'], u['free']) for u in uses],
                         [('validation', 'persist1', False)])
        self.assertIn('in use', self.refused('/api/validations/delete', {'id': dns}))
        self.assertIn('win1', self.rows('targets'))
        self.assertIn('dns1', self.rows('validations'))
        # a module that names nothing: as before, no use
        other = self.ok('POST', '/api/validations/save', {
            'name': 'dns9', 'kind': 'cloudflare', 'config': {'token': 'zzzzzzzz99'}})['id']
        self.assertEqual(self.ok('GET', '/api/validations/uses', args={'id': other})['uses'], [])

    def test_2_renamed_follows(self):
        t = self.rows('targets')['win1']
        self.ok('POST', '/api/targets/save', {'id': t['id'], 'name': 'win2', 'kind': 'agent_windows',
                                              'config': {'mode': 'passive', 'host': 'win1.example.test'}})
        v = self.rows('validations')['dns1']
        self.ok('POST', '/api/validations/save', {'id': v['id'], 'name': 'dns2', 'kind': 'cloudflare',
                                                  'config': {'token': v['config']['token']}})
        self.assertEqual(self.rows('sources')['adcs1']['config']['agent'], 'win2')
        self.assertEqual(self.rows('targets')['web1']['config']['via'], 'win2')
        p = self.rows('validations')['persist1']['config']
        self.assertEqual((p['fallback'], p['writer']), ('dns2', 'dns2'))
        # the token kept: the dots sent back are the one kept
        self.assertTrue(self.rows('validations')['dns2']['config']['token'].endswith('12'))

    def test_3_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        self.ok('POST', '/api/teams/adopt', {'tag': 'prod'})
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            drv = subprocess.run([node, os.path.join(HERE, 'hunt_ru3_srcval_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=300)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-2000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(seen['switched']['token'], 'Typed-Token-77', seen)
        self.assertEqual(seen['switched']['tags'], 'prod', seen)
        self.assertIn('6.0', seen['switched']['on'])
        self.assertEqual(seen['fgSent']['config'].get('_version'), '6.0', seen['fgSent'])
        self.assertEqual(seen['fgSent']['config'].get('token'), 'Typed-Token-77')
        self.assertEqual(seen['popupToken'], ['Cf-Token-1234', 'Cf-Token-1234'], seen)
        self.assertEqual(seen['cfSent']['config'].get('token'), 'Cf-Token-1234', seen['cfSent'])
        self.assertNotIn('_version', seen['cfSent']['config'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
