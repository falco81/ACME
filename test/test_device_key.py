#!/usr/bin/env python3
"""The device makes the key (docs/certificates.md "Key made by the device", certs.csr_from,
acmelib/certs/devicekey.py).

    python3 test/test_device_key.py          (or python3 -m unittest test.test_device_key)

In this process, no network: acme's own authority issues for the CSR a fake device module
makes with keys the test holds (its folder FAKE_DEVICE_DIR); the whole flow - the CSR asked
at the issue, the deployment right after it with no key, the certificate for the device's
key, a new CSR at a renewal; what is refused (another target, a twin, keeping the key, a CSR
sent in, a source that signs no CSR, a key type the device does not make, a CSR naming
other names or not all of them, a certificate not for the CSR's key, the target switched
off or gone); a held deployment said; the configuration file and a rename carrying
csr_from; the API and the command line (--csr-from).
"""
import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-devkey-')
DEV = os.path.join(TMP, 'device')
os.makedirs(os.path.join(TMP, 'plugins', 'targets'))
os.makedirs(DEV)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')

FAKE_DEVICE = r'''
import json
import os
from acmelib.plugins.base import Target, PluginError, field

DIR = os.environ.get('FAKE_DEVICE_DIR', '/nonexistent')


def _load(name, default):
    try:
        with open(os.path.join(DIR, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _save(name, value):
    with open(os.path.join(DIR, name), 'w') as f:
        json.dump(value, f)


class FakeDevice(Target):
    kind = 'fakedevice'
    title = 'A device that makes its key (tests)'
    vendor = 'Test'
    device_key = True
    device_key_types = ('ec-256', 'rsa-2048')
    fields = [field('host', 'Address', 'text')]
    deploy_fields = [field('slot', 'Slot', 'text', default='https')]

    def test(self):
        return 'the fake device answers'

    def device_csr(self, req):
        from acmelib.certs import pki
        mode = _load('mode.json', 'ok')
        if mode == 'refuse':
            raise PluginError('the device says no', retry=False)
        key = pki.make_key(req.key_type)
        names = list(req.names)
        if mode == 'extra':
            names.append('other.example')
        elif mode == 'missing':
            names = names[:1]
        csr = pki.make_csr(key, names, subject={'CN': req.subject.get('CN') or names[0]})
        csr = csr[0] if isinstance(csr, (tuple, list)) else csr
        keys = _load('keys.json', [])
        keys.append({'key': key, 'names': list(req.names), 'key_type': req.key_type,
                     'options': req.options, 'subject': req.subject, 'name': req.name})
        _save('keys.json', keys)
        self.ctx.step('the fake device made a %s key' % req.key_type)
        return csr

    def deploy(self, bundle, options):
        got = _load('deployed.json', [])
        got.append({'cert_pem': bundle.cert_pem, 'key_pem': bundle.key_pem,
                    'chain': list(bundle.chain_pems or []), 'options': dict(options)})
        _save('deployed.json', got)
        return 'installed the certificate'


class PlainTarget(Target):
    kind = 'plaintarget'
    title = 'A target that takes acme\'s key (tests)'
    vendor = 'Test'

    def deploy(self, bundle, options):
        return 'took it'
'''
with open(os.path.join(TMP, 'plugins', 'targets', 'fake_device.py'), 'w') as f:
    f.write(FAKE_DEVICE)

ENVS = dict(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
            ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'), FAKE_DEVICE_DIR=DEV)
os.environ.update(ENVS)
sys.path.insert(0, ROOT)

import acme as E  # noqa: E402
from acmelib.certs import api, ca as CA, deployer, devicekey, jobs, pki, renewer  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry(again=True)
assert base.REGISTRY.get('target', 'fakedevice'), base.REGISTRY.broken


class WrongKeyCa(base.Issuer):
    """Signs a certificate of its own key whatever the CSR says."""
    kind = 'wrongkeyca'
    title = 'A CA that ignores the CSR (tests)'

    def issue(self, req):
        key = pki.make_key('ec-256')
        return base.Issued(pki.self_signed(key, req.names, days=30), [])


base.REGISTRY.found['issuer'][WrongKeyCa.kind] = WrongKeyCa


def add(table, name, kind, config, enabled=1):
    return STORE.db.insert(table, {'name': name, 'kind': kind, 'config': json.dumps(config),
                                   'state': '{}', 'enabled': enabled, 'created': time.time()})


def state(name, default):
    try:
        with open(os.path.join(DEV, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def mode(m):
    with open(os.path.join(DEV, 'mode.json'), 'w') as f:
        json.dump(m, f)


def fresh_device():
    for n in ('keys.json', 'deployed.json', 'mode.json'):
        try:
            os.unlink(os.path.join(DEV, n))
        except OSError:
            pass


def renew(cid, force=True):
    return jobs.run_now(STORE, 'renew', renewer.renew_job(cid, force, 'test'), cert_id=cid,
                        by='test')


def words(job):
    return '\n'.join(str(s[2]) for s in job.steps)


def save(**b):
    return api.cert_save(STORE, b, 'test', full=True)


CA_ID = CA.ca_create(STORE, 'Device Root', {'CN': 'Device Root'}, key_type='ec-256', by='t')
add('cert_issuers', 'own', 'internal_ca', {'ca': CA_ID, 'days': 60})
add('cert_issuers', 'self', 'selfsigned', {})
add('cert_issuers', 'wrong', 'wrongkeyca', {})
add('cert_targets', 'xcc1', 'fakedevice', {'host': 'xcc1.example.test'})
add('cert_targets', 'xcc2', 'fakedevice', {'host': 'xcc2.example.test'})
add('cert_targets', 'web', 'plaintarget', {})
add('cert_targets', 'off', 'fakedevice', {}, enabled=0)


# ---------------------------------------------------------------------------
class Flow(unittest.TestCase):
    """Issued for the device's CSR, deployed with no key, renewed with a new CSR."""
    @classmethod
    def setUpClass(cls):
        fresh_device()
        cls.cid = save(name='bmc1', names=['xcc1.example.test', '192.0.2.10'], issuer='own',
                       key_type='ec-256', csr_from='xcc1')

    def test_1_the_deployment_made_with_it(self):
        row = S.cert_get(STORE, self.cid)
        self.assertEqual(row['csr_from'], 'xcc1')
        deps = STORE.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ?', (self.cid,))
        self.assertEqual([d['target'] for d in deps], ['xcc1'])
        # saved again: not a second deployment
        save(id=self.cid, csr_from='xcc1', note='again')
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ?',
                                        (self.cid,)), 1)

    def test_2_issued_for_the_device_key_and_deployed_without_one(self):
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ?', (self.cid,))
        api.deploy_save(STORE, {'id': dep['id'], 'options': {'slot': 'web-1'}}, 'test')
        job = renew(self.cid)
        self.assertTrue(job.ok, words(job))
        said = words(job)
        self.assertIn('made by the device of xcc1', said)
        self.assertIn('made a ec-256 key', said)
        keys, got = state('keys.json', []), state('deployed.json', [])
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(got), 1, said)
        row = S.cert_get(STORE, self.cid)
        self.assertIsNone(row.get('key_sealed'))
        self.assertTrue(pki.key_matches(row['cert_pem'], keys[0]['key']))
        self.assertEqual(got[0]['cert_pem'].strip(), row['cert_pem'].strip())
        self.assertFalse(got[0]['key_pem'])
        self.assertTrue(got[0]['chain'])
        # the device was asked with the names, the subject and its deployment's options
        self.assertEqual(keys[0]['names'], ['xcc1.example.test', '192.0.2.10'])
        self.assertEqual(keys[0]['options'].get('slot'), 'web-1')
        self.assertEqual(keys[0]['subject'].get('CN'), 'xcc1.example.test')
        self.assertEqual(keys[0]['name'], 'bmc1')
        info = pki.cert_info(row['cert_pem'])
        self.assertEqual(sorted(info['names']), sorted(['xcc1.example.test', '192.0.2.10']))
        d = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ?', (self.cid,))
        self.assertEqual((d['state'], d['deployed_version']), ('ok', 1))

    def test_3_a_renewal_asks_a_new_csr(self):
        job = renew(self.cid)
        self.assertTrue(job.ok, words(job))
        keys, got = state('keys.json', []), state('deployed.json', [])
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0]['key'], keys[1]['key'])
        row = S.cert_get(STORE, self.cid)
        self.assertEqual(row['version'], 2)
        self.assertTrue(pki.key_matches(row['cert_pem'], keys[1]['key']))
        self.assertFalse(pki.key_matches(row['cert_pem'], keys[0]['key']))
        self.assertEqual(got[-1]['cert_pem'].strip(), row['cert_pem'].strip())

    def test_4_no_key_anywhere(self):
        s = {'role': 'fulladmin', 'name': 't'}
        with self.assertRaises(ValueError) as e:
            api.cert_export(STORE, {'id': self.cid, 'format': 'key-pem'}, s)
        self.assertIn('device of xcc1', str(e.exception))
        got = api.cert_export(STORE, {'id': self.cid, 'format': 'cert-pem'}, s)
        self.assertTrue(got['data_b64'])
        view = api.cert_one(STORE, self.cid)['cert']
        self.assertEqual(view['csr_from'], 'xcc1')
        self.assertFalse(view['has_key'])

    def test_5_a_held_deployment_said(self):
        row = S.cert_get(STORE, self.cid)
        S.deploy_hold_set(STORE, row, True, 'test')
        try:
            job = renew(self.cid)
            self.assertTrue(job.ok, words(job))
            self.assertIn('keeps its old certificate', words(job))
            self.assertEqual(len(state('deployed.json', [])), 2)     # not deployed
        finally:
            S.deploy_hold_set(STORE, S.cert_get(STORE, self.cid), False, 'test')

    def test_6_the_device_key_type(self):
        cid = save(name='bmc-rsa', names=['rsa.example.test'], issuer='own', key_type='rsa-2048',
                   csr_from='xcc2')
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertEqual(pki.cert_info(S.cert_get(STORE, cid)['cert_pem'])['key_type'], 'rsa-2048')
        # none said: the first the device makes
        cid2 = api.cert_save(STORE, {'name': 'bmc-none', 'names': ['none.example.test'],
                                     'issuer': 'own', 'csr_from': 'xcc2'}, 'test', full=True)
        self.assertEqual(S.cert_get(STORE, cid2)['key_type'], 'ec-256')
        with self.assertRaises(ValueError) as e:
            save(id=cid2, key_type='ec-384')
        self.assertIn('ec-256, rsa-2048', str(e.exception))


class Refused(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_device()

    def refused(self, words_in, **b):
        with self.assertRaises(ValueError) as e:
            save(**b)
        self.assertIn(words_in, str(e.exception))
        return str(e.exception)

    def test_a_target_that_makes_no_key(self):
        self.refused('does not make keys', name='r1', names=['r1.example.test'], issuer='own',
                     csr_from='web')
        self.refused('there is no target', name='r1', names=['r1.example.test'], issuer='own',
                     csr_from='nowhere')

    def test_with_a_twin_or_the_key_kept(self):
        self.refused('twin', name='r2', names=['r2.example.test'], issuer='own',
                     csr_from='xcc1', key_type_alt='rsa-2048')
        self.refused('reuse_key', name='r3', names=['r3.example.test'], issuer='own',
                     csr_from='xcc1', reuse_key=1)
        self.assertIsNone(STORE.db.row("SELECT id FROM certs WHERE name IN ('r2', 'r3')"))

    def test_a_source_that_signs_no_csr(self):
        self.refused('cannot sign a CSR', name='r4', names=['r4.example.test'], issuer='self',
                     csr_from='xcc1')

    def test_with_a_csr_sent_in(self):
        cid = save(name='r5', names=['r5.example.test'], issuer='own')
        key = pki.make_key('ec-256')
        STORE.db.update('certs', cid, {'csr_given': pki.make_csr(key, ['r5.example.test'])[0]})
        self.refused('CSR sent in', id=cid, csr_from='xcc1')

    def test_deployed_elsewhere_and_to_elsewhere(self):
        cid = save(name='r6', names=['r6.example.test'], issuer='own', csr_from='xcc1')
        with self.assertRaises(ValueError) as e:
            api.deploy_save(STORE, {'cert_id': cid, 'target': 'web'}, 'test')
        self.assertIn('only to xcc1', str(e.exception))
        with self.assertRaises(ValueError) as e:
            api.deploy_save(STORE, {'cert_id': cid, 'target': 'xcc2'}, 'test')
        self.assertIn('only to xcc1', str(e.exception))
        # a certificate of acme's key on a device that makes its own: refused, said what to do
        plain = save(name='r7', names=['r7.example.test'], issuer='own')
        with self.assertRaises(ValueError) as e:
            api.deploy_save(STORE, {'cert_id': plain, 'target': 'xcc1'}, 'test')
        self.assertIn('makes the key itself', str(e.exception))
        self.assertIn('--csr-from xcc1', str(e.exception))
        # one deployed elsewhere does not get its key made by a device
        api.deploy_save(STORE, {'cert_id': plain, 'target': 'web'}, 'test')
        self.refused('take those deployments away', id=plain, csr_from='xcc1')
        # its device changed while deployed there: take the deployment away first
        self.refused('take that deployment away first', id=cid, csr_from='xcc2')

    def test_a_csr_with_other_names(self):
        cid = save(name='r8', names=['r8.example.test'], issuer='own', csr_from='xcc1')
        mode('extra')
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('other.example', words(job))
            self.assertIn('does not ask for', words(job))
        finally:
            mode('ok')
        cid = save(name='r9', names=['r9.example.test', 'www.r9.example.test'], issuer='own',
                   csr_from='xcc1')
        mode('missing')
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('does not name www.r9.example.test', words(job))
            self.assertIsNone(S.cert_get(STORE, cid).get('cert_pem'))
        finally:
            mode('ok')

    def test_the_device_refuses(self):
        cid = save(name='r10', names=['r10.example.test'], issuer='own', csr_from='xcc1')
        mode('refuse')
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('the device says no', words(job))
            self.assertEqual(S.cert_get(STORE, cid)['state'], 'failed')
        finally:
            mode('ok')

    def test_a_certificate_not_for_the_csr_key(self):
        cid = save(name='r11', names=['r11.example.test'], issuer='wrong', csr_from='xcc1')
        n = len(state('deployed.json', []))
        job = renew(cid)
        self.assertFalse(job.ok)
        self.assertIn('not for the key of the CSR the device of xcc1 made', words(job))
        self.assertEqual(len(state('deployed.json', [])), n)

    def test_the_target_off_or_gone(self):
        cid = save(name='r12', names=['r12.example.test'], issuer='own', csr_from='xcc2')
        STORE.db.run("UPDATE cert_targets SET enabled = 0 WHERE name = 'xcc2'")
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('xcc2, which is switched off', words(job))
        finally:
            STORE.db.run("UPDATE cert_targets SET enabled = 1 WHERE name = 'xcc2'")
        STORE.db.update('certs', cid, {'csr_from': 'gone'})
        job = renew(cid)
        self.assertFalse(job.ok)
        self.assertIn('target gone, which is not there any more', words(job))
        STORE.db.update('certs', cid, {'csr_from': 'xcc2'})
        # its deployment taken away: refused before the device is asked
        STORE.db.run("DELETE FROM cert_deploys WHERE cert_id = ?", (cid,))
        n = len(state('keys.json', []))
        job = renew(cid)
        self.assertFalse(job.ok)
        self.assertIn('no deployment to xcc2', words(job))
        self.assertEqual(len(state('keys.json', [])), n)

    def test_a_target_in_use_not_deleted(self):
        save(name='r13', names=['r13.example.test'], issuer='own', csr_from='xcc2')
        trow = S.plugin_row(STORE, 'target', 'xcc2')
        uses = api.family_uses(STORE, 'target', trow)
        self.assertIn('its key is made there', [u['said'] for u in uses])
        with self.assertRaises(ValueError):
            api.family_delete(STORE, 'target', {'id': trow['id'], 'force': 1}, 'test')


class Carried(unittest.TestCase):
    def test_config_file_keeps_it(self):
        cid = save(name='c1', names=['c1.example.test'], issuer='own', csr_from='xcc1')
        tables = json.loads(json.dumps(E.carry_export(STORE, False)))
        mine = [r for r in tables['certs'] if r['name'] == 'c1'][0]
        self.assertEqual(mine['csr_from'], 'xcc1')
        STORE.db.update('certs', cid, {'csr_from': ''})
        E.carry_import(STORE, tables, 'test', False, collections.Counter())
        self.assertEqual(S.cert_get(STORE, cid)['csr_from'], 'xcc1')

    def test_a_target_renamed(self):
        add('cert_targets', 'xcc9', 'fakedevice', {})
        cid = save(name='c2', names=['c2.example.test'], issuer='own', csr_from='xcc9')
        api._renamed(STORE, 'target', 'xcc9', 'xcc9b')
        self.assertEqual(S.cert_get(STORE, cid)['csr_from'], 'xcc9b')
        self.assertEqual(STORE.db.value('SELECT target FROM cert_deploys WHERE cert_id = ?',
                                        (cid,)), 'xcc9b')

    def test_described_for_the_page(self):
        d = base.REGISTRY.get('target', 'fakedevice').describe()
        self.assertTrue(d['device_key'])
        self.assertEqual(d['device_key_types'], ['ec-256', 'rsa-2048'])
        self.assertFalse(base.REGISTRY.get('target', 'plaintarget').describe()['device_key'])

    def test_the_sandbox_csr(self):
        info = pki.csr_info(devicekey.dummy_csr(['a.example.test', 'b.example.test']))
        devicekey.check_csr(info, ['a.example.test', 'b.example.test'])
        with self.assertRaises(base.PluginError):
            devicekey.check_csr(info, ['a.example.test'])


class WhatHappens(unittest.TestCase):
    """The plan: the key phase says the device makes the key, its device_csr() recorded in
    the sandbox (answered with a CSR for the names), the deployment with no key."""
    def test_plan_of_a_device_key(self):
        from acmelib.certs import runplan
        add('cert_targets', 'xccplan', 'lenovo_xcc', {
            'host': 'xcc.example.test', 'user': 'svccert', 'password': 'pw', 'csr_country': 'CZ',
            'csr_state': 'Praha', 'csr_city': 'Praha', 'csr_org': 'Example'})
        cid = save(name='p1', names=['xcc.example.test'], issuer='own', csr_from='xccplan')
        row = S.cert_get(STORE, cid)
        deps = STORE.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ?', (cid,))
        got = runplan.plan(STORE, row, deps, full=True)
        self.assertFalse(got['recording'], got['recording'])
        key = [p for p in got['phases'] if p['key'] == 'key'][0]
        text = json.dumps(key)
        self.assertIn('made by the device of xccplan', text)
        self.assertIn('GenerateCSR', text)
        self.assertNotIn('"stop"', text)
        if os.environ.get("SHOW_PLAN"):
            print(json.dumps(key, indent=1)[:3000])
        dep = [p for p in got['phases'] if p['key'] == 'deploy'][0]
        dtext = json.dumps(dep)
        self.assertIn('ReplaceCertificate', dtext)
        self.assertNotIn('"stop"', dtext)
        # the sandbox's own answer to a device asked for its CSR, for any module
        from acmelib.certs import plansandbox as P
        a = P.Answers([{'url': r'/csr$', 'body': {'pem': '{CSR}'}}])
        a.csr = devicekey.dummy_csr(['x.example.test'])
        st, hd, body = a('POST', 'https://d/csr')
        self.assertEqual(json.loads(body)['pem'], a.csr)
        self.assertEqual(json.loads(a('GET', 'https://d/other')[2])['CSRString'], a.csr)


class ApiAndCli(unittest.TestCase):
    def test_api(self):
        daemon = E.Daemon(STORE, serve=False)

        def call(method, path, body=None, args=None):
            h = E.CliApiHandler(daemon, 'tester', body or {}, args or {}, path)
            h.me = lambda need=None: {'name': 'tester', 'role': 'fulladmin'}
            return E.ROUTES[(method, path)](h)
        got = call('POST', '/api/certs/save', {'name': 'a1', 'names': ['a1.example.test'],
                                                'issuer': 'own', 'csr_from': 'xcc1'})
        one = call('GET', '/api/certs/one', args={'id': str(got['id'])})
        self.assertEqual(one['cert']['csr_from'], 'xcc1')
        self.assertEqual([d['target'] for d in one['deploys']], ['xcc1'])
        listed = [r for r in call('GET', '/api/certs', args={'per': '1000'})['rows']
                  if r['name'] == 'a1'][0]
        self.assertEqual(listed['csr_from'], 'xcc1')
        plugs = call('GET', '/api/plugins')
        dev = [p for p in plugs['target'] if p['kind'] == 'fakedevice'] if isinstance(
            plugs.get('target'), list) else None
        if dev is not None:
            self.assertTrue(dev[0]['device_key'])

    def run_cli(self, *args):
        env = dict(os.environ, ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1',
                   **ENVS)
        return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                              env=env, capture_output=True, text=True, timeout=180)

    def test_cli(self):
        got = self.run_cli('--cert-add', 'cli1', '--names', 'cli1.example.test', '--issuer',
                           'own', '--csr-from', 'xcc1')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        row = STORE.db.row("SELECT * FROM certs WHERE name = 'cli1'")
        self.assertEqual(row['csr_from'], 'xcc1')
        self.assertEqual(STORE.db.value('SELECT target FROM cert_deploys WHERE cert_id = ?',
                                        (row['id'],)), 'xcc1')
        got = self.run_cli('--cert', 'cli1')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('key made by', got.stdout)
        self.assertIn('xcc1', got.stdout)
        got = self.run_cli('--cert-edit', 'cli1', '--csr-from', 'web')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('does not make keys', got.stdout + got.stderr)
        got = self.run_cli('--cert-edit', 'cli1', '--set', 'reuse_key=on')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('reuse_key', got.stdout + got.stderr)
        got = self.run_cli('--cert-add', 'cli2', '--names', 'cli2.example.test', '--issuer',
                           'own', '--set', 'csr_from=xcc2', '--json')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(STORE.db.value("SELECT csr_from FROM certs WHERE name = 'cli2'"),
                         'xcc2')


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
