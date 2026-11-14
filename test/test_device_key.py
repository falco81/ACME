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


_DEVS = [0]


def device(prefix='dev'):
    """A target of its own whose device makes the key (one certificate per device)."""
    _DEVS[0] += 1
    name = '%s%d' % (prefix, _DEVS[0])
    add('cert_targets', name, 'fakedevice', {'host': name + '.example.test'})
    return name


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
                   csr_from=device())
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertEqual(pki.cert_info(S.cert_get(STORE, cid)['cert_pem'])['key_type'], 'rsa-2048')
        # none said: the first the device makes
        cid2 = api.cert_save(STORE, {'name': 'bmc-none', 'names': ['none.example.test'],
                                     'issuer': 'own', 'csr_from': device()}, 'test', full=True)
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
        d = device()
        cid = save(name='r6', names=['r6.example.test'], issuer='own', csr_from=d)
        with self.assertRaises(ValueError) as e:
            api.deploy_save(STORE, {'cert_id': cid, 'target': 'web'}, 'test')
        self.assertIn('only to ' + d, str(e.exception))
        with self.assertRaises(ValueError) as e:
            api.deploy_save(STORE, {'cert_id': cid, 'target': 'xcc2'}, 'test')
        self.assertIn('only to ' + d, str(e.exception))
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
        cid = save(name='r8', names=['r8.example.test'], issuer='own', csr_from=device())
        mode('extra')
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('other.example', words(job))
            self.assertIn('does not ask for', words(job))
        finally:
            mode('ok')
        cid = save(name='r9', names=['r9.example.test', 'www.r9.example.test'], issuer='own',
                   csr_from=device())
        mode('missing')
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('does not name www.r9.example.test', words(job))
            self.assertIsNone(S.cert_get(STORE, cid).get('cert_pem'))
        finally:
            mode('ok')

    def test_the_device_refuses(self):
        cid = save(name='r10', names=['r10.example.test'], issuer='own', csr_from=device())
        mode('refuse')
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('the device says no', words(job))
            self.assertEqual(S.cert_get(STORE, cid)['state'], 'failed')
        finally:
            mode('ok')

    def test_a_certificate_not_for_the_csr_key(self):
        d = device()
        cid = save(name='r11', names=['r11.example.test'], issuer='wrong', csr_from=d)
        n = len(state('deployed.json', []))
        job = renew(cid)
        self.assertFalse(job.ok)
        self.assertIn('not for the key of the CSR the device of %s made' % d, words(job))
        self.assertEqual(len(state('deployed.json', [])), n)

    def test_the_target_off_or_gone(self):
        d = device()
        cid = save(name='r12', names=['r12.example.test'], issuer='own', csr_from=d)
        STORE.db.run("UPDATE cert_targets SET enabled = 0 WHERE name = ?", (d,))
        try:
            job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn('%s, which is switched off' % d, words(job))
        finally:
            STORE.db.run("UPDATE cert_targets SET enabled = 1 WHERE name = ?", (d,))
        STORE.db.update('certs', cid, {'csr_from': 'gone'})
        job = renew(cid)
        self.assertFalse(job.ok)
        self.assertIn('target gone, which is not there any more', words(job))
        STORE.db.update('certs', cid, {'csr_from': d})
        # its deployment taken away: refused before the device is asked
        STORE.db.run("DELETE FROM cert_deploys WHERE cert_id = ?", (cid,))
        n = len(state('keys.json', []))
        job = renew(cid)
        self.assertFalse(job.ok)
        self.assertIn('no deployment to ' + d, words(job))
        self.assertEqual(len(state('keys.json', [])), n)

    def test_a_target_in_use_not_deleted(self):
        d = device()
        save(name='r13', names=['r13.example.test'], issuer='own', csr_from=d)
        trow = S.plugin_row(STORE, 'target', d)
        uses = api.family_uses(STORE, 'target', trow)
        self.assertIn('its key is made there', [u['said'] for u in uses])
        with self.assertRaises(ValueError):
            api.family_delete(STORE, 'target', {'id': trow['id'], 'force': 1}, 'test')


class Carried(unittest.TestCase):
    def test_config_file_keeps_it(self):
        d = device()
        cid = save(name='c1', names=['c1.example.test'], issuer='own', csr_from=d)
        tables = json.loads(json.dumps(E.carry_export(STORE, False)))
        mine = [r for r in tables['certs'] if r['name'] == 'c1'][0]
        self.assertEqual(mine['csr_from'], d)
        STORE.db.update('certs', cid, {'csr_from': ''})
        E.carry_import(STORE, tables, 'test', False, collections.Counter())
        self.assertEqual(S.cert_get(STORE, cid)['csr_from'], d)

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
        # the page's lede and header say the device makes the key (round 1e)
        self.assertEqual(got['cert']['csr_from'], 'xccplan')
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
        dv = device('api')
        got = call('POST', '/api/certs/save', {'name': 'a1', 'names': ['a1.example.test'],
                                                'issuer': 'own', 'csr_from': dv})
        one = call('GET', '/api/certs/one', args={'id': str(got['id'])})
        self.assertEqual(one['cert']['csr_from'], dv)
        self.assertEqual([d['target'] for d in one['deploys']], [dv])
        listed = [r for r in call('GET', '/api/certs', args={'per': '1000'})['rows']
                  if r['name'] == 'a1'][0]
        self.assertEqual(listed['csr_from'], dv)
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
        d1, d2 = device('cli'), device('cli')
        got = self.run_cli('--cert-add', 'cli1', '--names', 'cli1.example.test', '--issuer',
                           'own', '--csr-from', d1)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        row = STORE.db.row("SELECT * FROM certs WHERE name = 'cli1'")
        self.assertEqual(row['csr_from'], d1)
        self.assertEqual(STORE.db.value('SELECT target FROM cert_deploys WHERE cert_id = ?',
                                        (row['id'],)), d1)
        got = self.run_cli('--cert', 'cli1')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('key made by', got.stdout)
        self.assertIn(d1, got.stdout)
        got = self.run_cli('--cert-edit', 'cli1', '--csr-from', 'web')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('does not make keys', got.stdout + got.stderr)
        got = self.run_cli('--cert-edit', 'cli1', '--set', 'reuse_key=on')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('reuse_key', got.stdout + got.stderr)
        got = self.run_cli('--cert-add', 'cli2', '--names', 'cli2.example.test', '--issuer',
                           'own', '--set', 'csr_from=' + d2, '--json')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(STORE.db.value("SELECT csr_from FROM certs WHERE name = 'cli2'"),
                         d2)


# ---------------------------------------------------------------------------
# What the bug hunt found (r1a): each one again
# ---------------------------------------------------------------------------
from acmelib.plugins.issuers import _source_common as SC  # noqa: E402


class HeldCa(base.Issuer):
    """As ms_adcs (a manager's approval), digicert, sectigo, est...: the request (its CSR) held
    at the CA at the first try, the certificate for that held CSR fetched at the next."""
    kind = 'heldca'
    title = 'A CA that holds the request (tests)'

    def issue(self, req):
        slot = SC.pending_slot('heldca', 'x', req)
        held = SC.pending_get(self.ctx, slot, req)
        if not held:
            SC.pending_put(self.ctx, slot, req, {'id': '7', 'csr_pem': req.csr_pem})
            raise base.PluginError('request 7 waits for approval at the CA')
        r = SC.held_request(req, held)
        cert, chain = CA.ca_sign(STORE, CA_ID, r.csr_pem, 30, {'names': list(req.names)},
                                 cert_id=req.cert_id, by='t')
        SC.pending_drop(self.ctx, slot)
        return base.Issued(cert, chain)


base.REGISTRY.found['issuer'][HeldCa.kind] = HeldCa
add('cert_issuers', 'held', 'heldca', {})
FAKE = base.REGISTRY.get('target', 'fakedevice')


def deploy_now(cid):
    return jobs.run_now(STORE, 'deploy', deployer.deploy_job(cid, None), cert_id=cid, by='t')


class Patched(object):
    """A method of the fake device swapped for the time of a with."""
    def __init__(self, name, fn):
        self.name, self.fn = name, fn

    def __enter__(self):
        self.was = FAKE.__dict__[self.name]
        setattr(FAKE, self.name, self.fn)

    def __exit__(self, *exc):
        setattr(FAKE, self.name, self.was)


class Found(unittest.TestCase):
    def test_1_a_held_request_finishes_with_the_csr_kept(self):
        d = device()
        cid = save(name='h1', names=['h1.example.test'], issuer='held', csr_from=d)
        keys0, dep0 = len(state('keys.json', [])), len(state('deployed.json', []))
        job = renew(cid)
        self.assertFalse(job.ok)
        self.assertIn('waits for approval', words(job))
        kept = devicekey.held_csr(S.cert_get(STORE, cid), d)
        self.assertTrue(kept and kept['csr_pem'])
        self.assertFalse(api.cert_one(STORE, cid)['cert']['csr_waiting'])
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertIn('is used again', words(job))
        keys = state('keys.json', [])
        self.assertEqual(len(keys), keys0 + 1)           # the device asked once
        self.assertEqual(len(state('deployed.json', [])), dep0 + 1)
        row = S.cert_get(STORE, cid)
        self.assertTrue(pki.key_matches(row['cert_pem'], keys[-1]['key']))
        self.assertIsNone(row.get('csr_pending'))
        # the next issue: a new key again
        renew(cid)
        self.assertEqual(len(state('keys.json', [])), keys0 + 2)

    def test_2_switched_to_the_device_after_it_was_issued(self):
        cid = save(name='s1', names=['s1.example.test'], issuer='own')
        self.assertTrue(renew(cid).ok)
        STORE.db.update('certs', cid, {'csr_pending': json.dumps({'csr_pem': 'x', 'at': 1})})
        d = device()
        save(id=cid, csr_from=d)
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['state'], 'due')
        self.assertIsNone(row.get('csr_pending'))
        self.assertIn('due for a new issue', renewer.main_due(row))
        n = len(state('deployed.json', []))
        job = deploy_now(cid)
        self.assertFalse(job.ok)
        self.assertIn('holds a key acme made', words(job))
        self.assertEqual(len(state('deployed.json', [])), n)
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        got = state('deployed.json', [])
        self.assertEqual(len(got), n + 1)
        self.assertFalse(got[-1]['key_pem'])
        self.assertIsNone(S.cert_get(STORE, cid).get('key_sealed'))

    def test_3_switched_away_from_the_device(self):
        d = device()
        cid = save(name='s2', names=['s2.example.test'], issuer='own', csr_from=d)
        self.assertTrue(renew(cid).ok)
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (cid,))
        save(id=cid, csr_from='')
        self.assertEqual(S.cert_get(STORE, cid)['state'], 'due')
        api.deploy_save(STORE, {'cert_id': cid, 'target': 'web'}, 'test')
        job = deploy_now(cid)
        self.assertFalse(job.ok)
        self.assertIn('issued for a key its device made', words(job))
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertTrue(S.cert_get(STORE, cid).get('key_sealed'))

    def test_4_no_csr_answer_on_a_device_certificate(self):
        d = device()
        cid = save(name='s3', names=['s3.example.test'], issuer='own', csr_from=d)

        class H(object):
            store = STORE

            def body(self):
                return {'id': cid, 'data_b64': ''}
        with self.assertRaises(ValueError) as e:
            api._cert_csr_answer(H(), {'name': 't', 'role': 'fulladmin'})
        self.assertIn('made by the device of ' + d, str(e.exception))

    def test_5_import_no_twin_no_key(self):
        import base64
        d = device()
        cid = save(name='i1', names=['i1.example.test'], issuer='own', csr_from=d)
        self.assertTrue(renew(cid).ok)
        k = pki.make_key('rsa-2048')
        c = pki.self_signed(k, ['i1.example.test'], days=30)
        for as_, data, said in (('alt', c + k, 'it has no twin'),
                                ('main', c + k, 'without its key')):
            with self.assertRaises(ValueError) as e:
                api.cert_import(STORE, {'id': cid, 'data_b64': base64.b64encode(
                    data.encode()).decode(), 'filename': 'x.pem', 'as': as_}, 'test')
            self.assertIn(said, str(e.exception))
        row = S.cert_get(STORE, cid)
        self.assertFalse(row.get('key_type_alt'))
        self.assertFalse(row.get('key_sealed'))
        # a twin renewal: nothing asked of the device
        n = len(state('keys.json', []))
        j = jobs.run_now(STORE, 'renew', renewer.renew_job(cid, True, 'test', only='alt'),
                         cert_id=cid, by='t')
        self.assertTrue(j.ok)
        self.assertEqual(len(state('keys.json', [])), n)
        self.assertEqual(renewer.alt_due(dict(row, key_type_alt='rsa-2048',
                                              auto_renew=1)), '')

    def test_6_a_key_not_asked_for_refused(self):
        import subprocess as sp
        d = device()
        cid = save(name='k1', names=['k1.example.test'], issuer='own', csr_from=d,
                   key_type='ec-256')
        for made, said in (('rsa-1024', 'weak rsa-1024 key'),
                           ('ec-384', 'made a ec-384 key, which its module does not list'),
                           ('rsa-2048', 'made a rsa-2048 key, but ec-256 was asked for')):
            def dcsr(self, req, made=made):
                if made == 'rsa-1024':
                    key = sp.run(['openssl', 'genrsa', '1024'], capture_output=True,
                                 text=True).stdout
                else:
                    key = pki.make_key(made)
                csr = pki.make_csr(key, list(req.names), subject={'CN': req.names[0]})
                return csr[0] if isinstance(csr, (tuple, list)) else csr
            with Patched('device_csr', dcsr):
                job = renew(cid)
            self.assertFalse(job.ok)
            self.assertIn(said, words(job))
            row = S.cert_get(STORE, cid)
            self.assertFalse(row.get('cert_pem'))
            self.assertIsNone(devicekey.held_csr(row))

    def test_7_a_target_module_not_changed_under_certificates(self):
        d = device()
        save(name='m1', names=['m1.example.test'], issuer='own', csr_from=d)
        tid = S.plugin_row(STORE, 'target', d)['id']
        with self.assertRaises(ValueError) as e:
            api.family_save(STORE, 'target', {'id': tid, 'kind': 'plaintarget', 'config': {}},
                            'test')
        self.assertIn('makes the key of m1', str(e.exception))
        add('cert_targets', 'web7', 'plaintarget', {})
        plain = save(name='m2', names=['m2.example.test'], issuer='own')
        api.deploy_save(STORE, {'cert_id': plain, 'target': 'web7'}, 'test')
        wid = S.plugin_row(STORE, 'target', 'web7')['id']
        with self.assertRaises(ValueError) as e:
            api.family_save(STORE, 'target', {'id': wid, 'kind': 'fakedevice',
                                              'config': {'host': 'w'}}, 'test')
        self.assertIn("takes certificates with acme's key (m2)", str(e.exception))
        # unused: changed freely
        add('cert_targets', 'free7', 'plaintarget', {})
        fid = S.plugin_row(STORE, 'target', 'free7')['id']
        api.family_save(STORE, 'target', {'id': fid, 'kind': 'fakedevice', 'config': {}}, 'test')
        self.assertEqual(S.plugin_row(STORE, 'target', 'free7')['kind'], 'fakedevice')

    def test_8_one_certificate_per_device(self):
        d = device()
        save(name='o1', names=['o1.example.test'], issuer='own', csr_from=d)
        with self.assertRaises(ValueError) as e:
            save(name='o2', names=['o2.example.test'], issuer='own', csr_from=d)
        self.assertIn('already makes the key of the certificate o1', str(e.exception))
        other = save(name='o3', names=['o3.example.test'], issuer='own')
        with self.assertRaises(ValueError):
            save(id=other, csr_from=d)

    def test_9_a_device_that_lost_its_key_issued_anew_once(self):
        d = device()
        cid = save(name='l1', names=['l1.example.test'], issuer='own', csr_from=d)
        self.assertTrue(renew(cid).ok)
        v1 = S.cert_get(STORE, cid)['version']

        def lost(self, bundle, options):
            raise base.PluginError('the device has no pending key for this certificate')
        with Patched('deploy', lost):
            for i in range(devicekey.REISSUE_AFTER - 1):
                self.assertFalse(deploy_now(cid).ok)
                self.assertEqual(S.cert_get(STORE, cid)['state'], 'ok')
            job = deploy_now(cid)
            self.assertIn('issued anew', words(job))
            row = S.cert_get(STORE, cid)
            self.assertEqual(row['state'], 'due')
            self.assertTrue(renewer.main_due(row))
            n = len(state('keys.json', []))
            job = renew(cid, force=False)
            self.assertFalse(job.ok)                    # deployed: failed again
            row = S.cert_get(STORE, cid)
            self.assertEqual(row['version'], v1 + 1)
            self.assertEqual(len(state('keys.json', [])), n + 1)   # a new key and CSR
            # ...and not again: no loop of issues
            self.assertEqual(row['state'], 'ok')
            self.assertFalse(renewer.main_due(row))
            deploy_now(cid)
            self.assertEqual(S.cert_get(STORE, cid)['state'], 'ok')
        self.assertTrue(deploy_now(cid).ok)
        self.assertFalse(STORE.get_meta(devicekey.REISSUE_KEY % cid))


class Wizard(unittest.TestCase):
    """The certificate form (web/assets/certs.js): a target's address as the name without its
    port; devices switched off not offered; a source that signs no CSR cleared; the default
    deployment back when acme makes the key again."""
    SRC = open(os.path.join(ROOT, 'web', 'assets', 'certs.js'), encoding='utf-8').read()

    def test_bare_host(self):
        import re
        import shutil as sh
        if not sh.which('node'):
            self.skipTest('no node')
        fn = re.search(r'\nfunction bareHost[\s\S]*?\n}\n', self.SRC).group(0)
        cases = {'https://admin@xcc1.example.com:8443/redfish': 'xcc1.example.com',
                 'xcc1.example.com:443': 'xcc1.example.com', '[2001:db8::1]:443': '2001:db8::1',
                 '2001:db8::1': '2001:db8::1', 'Host.Example.': 'host.example'}
        js = fn + 'console.log(JSON.stringify(%s.map(bareHost)));' % json.dumps(list(cases))
        got = subprocess.run(['node', '-e', js], capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(got.stdout), list(cases.values()), got.stderr)
        self.assertIn('bareHost(first(cfg.host, cfg.address', self.SRC)

    def test_the_form(self):
        self.assertIn("!!devPlug(t) && t.enabled !== 0 && t.enabled !== false", self.SRC)
        self.assertIn('var devSource = function () { if (W.d.csr_from && W.d.issuer && '
                      'signsNoCsr(W.d.issuer)) W.d.issuer = \'\'; };', self.SRC)
        self.assertIn('if (W.d.csr_from && !devPlug(t)) W.devKept[k] = W.deploys[k];', self.SRC)
        self.assertIn('if (!W.deploys[k]) W.deploys[k] = W.devKept[k];', self.SRC)


class Round1e(unittest.TestCase):
    """What the UI bug hunt of the device-made key found (round 1e): a device-key target as
    the default target, tests made from deployments left behind, a required list field."""

    def test_device_key_target_is_never_the_default(self):
        from acmelib.certs import defaults as DF
        with self.assertRaises(ValueError) as e:
            DF.set_default(STORE, 'target', 'xcc1', 'test')
        self.assertIn('xcc1 makes its own key and takes only the certificate made for it - it '
                      'cannot be the default target', str(e.exception))
        self.assertNotEqual(DF.default_name(STORE, 'target'), 'xcc1')
        self.assertEqual(DF.set_default(STORE, 'target', 'web', 'test'), 'web')
        DF.set_default(STORE, 'target', '', 'test')

    def _served(self, cname, target):
        from acmelib.certs import checks as C
        cid = save(name=cname, names=[cname + '.example.test'], issuer='own', key_type='ec-256')
        api.deploy_save(STORE, {'cert_id': cid, 'target': target, 'options': {}}, 'test')
        name = C.for_target(STORE, cid, target, 'test', 'tls', cname + '.example.test', 443)
        self.assertTrue(C.auto_made(STORE, name))
        return cid, name

    def test_auto_tests_go_with_the_certificate(self):
        from acmelib.certs import checks as C
        cid, name = self._served('autogo', 'web')
        # a test of a person's own, attached too, stays
        add('cert_tests', 'mine-autogo', 'tls', {'host': 'autogo.example.test', 'port': 8443})
        C.attach(STORE, cid, ['mine-autogo'], 'test')
        api.cert_drop(STORE, S.cert_get(STORE, cid), 'test')
        self.assertIsNone(S.plugin_row(STORE, 'check', name))
        self.assertIsNotNone(S.plugin_row(STORE, 'check', 'mine-autogo'))
        # one another certificate still uses stays
        cid2, name2 = self._served('autokeep', 'web')
        cid3 = save(name='autokeep2', names=['autokeep.example.test'], issuer='own')
        C.attach(STORE, cid3, [name2], 'test')
        api.cert_drop(STORE, S.cert_get(STORE, cid2), 'test')
        self.assertIsNotNone(S.plugin_row(STORE, 'check', name2))

    def test_auto_tests_go_with_the_target(self):
        from acmelib.certs import checks as C
        add('cert_targets', 'gone1', 'plaintarget', {})
        cid, name = self._served('tgone', 'gone1')
        # its deployment taken away (the test stays attached, run by its schedule only)
        dep = STORE.db.row('SELECT id FROM cert_deploys WHERE cert_id = ? AND target = ?',
                           (cid, 'gone1'))
        STORE.db.run('DELETE FROM cert_deploys WHERE id = ?', (dep['id'],))
        C.target_gone(STORE, cid, 'gone1')
        self.assertIsNotNone(S.plugin_row(STORE, 'check', name))
        row = S.plugin_row(STORE, 'target', 'gone1')
        api.family_delete(STORE, 'target', {'id': row['id']}, 'test')
        self.assertIsNone(S.plugin_row(STORE, 'check', name))
        self.assertIsNone(STORE.db.row('SELECT id FROM cert_checks WHERE test = ?', (name,)))
        # one a person chose "only by its schedule" for stays
        add('cert_targets', 'gone2', 'plaintarget', {})
        cid2, name2 = self._served('tgone2', 'gone2')
        chk = STORE.db.row('SELECT id FROM cert_checks WHERE cert_id = ? AND test = ?',
                           (cid2, name2))
        C.after(STORE, chk['id'], C.AFTER_NONE, 'person')
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (cid2,))
        api.family_delete(STORE, 'target', {'id': S.plugin_row(STORE, 'target', 'gone2')['id']},
                          'test')
        self.assertIsNotNone(S.plugin_row(STORE, 'check', name2))

    def test_required_list_of_blank_lines(self):
        add('cert_targets', 'ib1', 'infoblox', {'host': '192.0.2.35', 'user': 'u', 'password': 'p'})
        cid = save(name='ibc', names=['ibc.example.test'], issuer='own')
        for members in ([''], [' ', ''], '\n'):
            with self.assertRaises(ValueError) as e:
                api.deploy_save(STORE, {'cert_id': cid, 'target': 'ib1',
                                        'options': {'members': members}}, 'test')
            self.assertIn('fill in \u201cGrid members\u201d', str(e.exception))
        self.assertIsNone(STORE.db.row('SELECT id FROM cert_deploys WHERE cert_id = ?', (cid,)))
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'api.py'), encoding='utf-8') as f:
            self.assertIn("b = dict(b, options={})", f.read())


class Round2a(unittest.TestCase):
    """The round-1 fixes of the device-made key reviewed (round 2a)."""

    def test_1_legacy_twins_still_saved_and_warned(self):
        # two certificates on one device, saved before one per device was refused: each can
        # still be edited (csr_from not changed), and a renewal warns of the other
        d = device()
        a = save(name='lg1', names=['lg1.example.test'], issuer='own', csr_from=d)
        b = save(name='lg2', names=['lg2.example.test'], issuer='own')
        STORE.db.update('certs', b, {'csr_from': d})
        for cid, nm in ((a, 'lg1'), (b, 'lg2')):
            row = S.cert_get(STORE, cid)
            save(id=cid, name=nm, names=json.loads(row['names']), issuer='own', csr_from=d,
                 key_type='ec-256', note='only the note')
            self.assertEqual(S.cert_get(STORE, cid)['note'], 'only the note')
        job = renew(a)
        self.assertIn('makes the key of the certificate lg2 too', words(job))
        # set anew (another device, then this one again): refused
        c = save(name='lg3', names=['lg3.example.test'], issuer='own')
        with self.assertRaises(ValueError):
            save(id=c, csr_from=d)

    def test_2_no_auto_renewal_said_by_hand(self):
        d = device()
        cid = save(name='na2', names=['na2.example.test'], issuer='own', csr_from=d,
                   auto_renew=0)
        self.assertTrue(renew(cid).ok)

        def lost(self, bundle, options):
            raise base.PluginError('unreachable: connection timed out')
        with Patched('deploy', lost):
            for i in range(devicekey.REISSUE_AFTER):
                job = deploy_now(cid)
        self.assertNotIn('issued anew', words(job))
        self.assertIn('renew it by hand', words(job))
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['state'], 'ok')
        self.assertFalse(STORE.get_meta(devicekey.REISSUE_KEY % cid))

    def test_3_switched_with_on_or_off_in_one_save(self):
        d = device()
        cid = save(name='sw3', names=['sw3.example.test'], issuer='own', csr_from=d)
        self.assertTrue(renew(cid).ok)
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (cid,))
        save(id=cid, enabled=0)
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (cid,))
        save(id=cid, enabled=1, csr_from='')
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['state'], 'due')
        self.assertTrue(renewer.main_due(row))
        d2 = device()
        c2 = save(name='sw4', names=['sw4.example.test'], issuer='own')
        self.assertTrue(renew(c2).ok)
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (c2,))
        save(id=c2, enabled=0, csr_from=d2)
        row = S.cert_get(STORE, c2)
        self.assertEqual((row['enabled'], row['state']), (0, 'disabled'))
        # switched on again later: the version it holds fits no key there - due
        save(id=c2, enabled=1)
        self.assertEqual(S.cert_get(STORE, c2)['state'], 'due')

    def test_4_import_clears_the_kept_csr(self):
        import base64
        d = device()
        cid = save(name='im2', names=['im2.example.test'], issuer='held', csr_from=d)
        self.assertFalse(renew(cid).ok)
        held = devicekey.held_csr(S.cert_get(STORE, cid), d)
        self.assertTrue(held)
        cert, chain = CA.ca_sign(STORE, CA_ID, held['csr_pem'], 30,
                                 {'names': ['im2.example.test']}, by='t')
        api.cert_import(STORE, {'id': cid, 'data_b64': base64.b64encode(
            (cert + ''.join(chain)).encode()).decode(), 'filename': 'x.pem', 'as': 'main'},
            'test')
        self.assertIsNone(devicekey.held_csr(S.cert_get(STORE, cid)))
        STORE.db.update('certs', cid, {'issuer': 'own'})
        n = len(state('keys.json', []))
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertNotIn('is used again', words(job))
        self.assertEqual(len(state('keys.json', [])), n + 1)

    def test_5_rename_keeps_the_held_csr(self):
        d = device()
        cid = save(name='rn2', names=['rn2.example.test'], issuer='held', csr_from=d)
        self.assertFalse(renew(cid).ok)
        tid = S.plugin_row(STORE, 'target', d)['id']
        api.family_save(STORE, 'target', {'id': tid, 'name': d + 'x', 'kind': 'fakedevice',
                                          'config': {'host': 'h'}}, 'test')
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['csr_from'], d + 'x')
        self.assertTrue(devicekey.held_csr(row, d + 'x'))
        n = len(state('keys.json', []))
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertEqual(len(state('keys.json', [])), n)

    def test_6_device_module_with_other_key_types_refused(self):
        class Ec384Device(FAKE):
            kind = 'fakedevice384'
            device_key_types = ('ec-384',)
        base.REGISTRY.found['target'][Ec384Device.kind] = Ec384Device
        try:
            d = device()
            save(name='kt1', names=['kt1.example.test'], issuer='own', csr_from=d,
                 key_type='ec-256')
            tid = S.plugin_row(STORE, 'target', d)['id']
            with self.assertRaises(ValueError) as e:
                api.family_save(STORE, 'target', {'id': tid, 'kind': 'fakedevice384',
                                                  'config': {'host': 'h'}}, 'test')
            self.assertIn('makes ec-384 keys only', str(e.exception))
        finally:
            base.REGISTRY.found['target'].pop(Ec384Device.kind, None)


class Round2c(unittest.TestCase):
    """1.0.96, round 2c: one deployment to the device, saved once from the wizard, the device
    taken by another certificate said in its row, what the module takes checked at the save."""

    def events(self, like):
        return [r['words'] for r in STORE.db.rows(
            'SELECT words FROM events WHERE words LIKE ? ORDER BY id', ('%' + like + '%',))]

    def test_second_deployment_to_the_device_refused(self):
        d = device()
        cid = save(name='dup1', names=['dup1.example.test'], issuer='own', csr_from=d,
                   key_type='ec-256')
        deps = STORE.db.rows('SELECT id FROM cert_deploys WHERE cert_id = ?', (cid,))
        self.assertEqual(len(deps), 1)
        with self.assertRaises(ValueError) as e:
            api.deploy_save(STORE, {'cert_id': cid, 'target': d, 'options': {}}, 'test')
        self.assertIn('is deployed to %s already' % d, str(e.exception))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ?',
                                        (cid,)), 1)
        # the one there is changed as before
        api.deploy_save(STORE, {'id': deps[0]['id'], 'cert_id': cid, 'target': d,
                                'options': {'slot': 'ldap'}}, 'test')
        opts = S.jload(STORE.db.value('SELECT options FROM cert_deploys WHERE id = ?',
                                      (deps[0]['id'],)), {})
        self.assertEqual(opts.get('slot'), 'ldap')

    def test_wizard_options_saved_once(self):
        d = device()
        out = {}
        cid = api.cert_save(STORE, {'name': 'once1', 'names': ['once1.example.test'],
                                    'issuer': 'own', 'csr_from': d, 'key_type': 'ec-256',
                                    'deploy_options': {'slot': 'ldap'}}, 'test', full=True,
                            out=out)
        deps = STORE.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ?', (cid,))
        self.assertEqual(len(deps), 1)
        self.assertEqual(out.get('device_deploy'), deps[0]['id'])
        self.assertEqual(S.jload(deps[0]['options'], {}).get('slot'), 'ldap')
        self.assertEqual(len(self.events('deployment of once1 to %s saved' % d)), 1)

    def test_wizard_options_refused_made_without(self):
        d = device()
        out = {}
        cid = api.cert_save(STORE, {'name': 'once2', 'names': ['once2.example.test'],
                                    'issuer': 'own', 'csr_from': d, 'key_type': 'ec-256',
                                    'deploy_options': {'slot': ['not', 'text']}}, 'test',
                            full=True, out=out)
        self.assertIsNone(out.get('device_deploy'))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ?',
                                        (cid,)), 1)

    def test_key_of_in_the_target_row(self):
        d = device()
        row = S.plugin_row(STORE, 'target', d)
        self.assertEqual(S.plugin_public(STORE, 'target', row).get('key_of'), '')
        save(name='taken1', names=['taken1.example.test'], issuer='own', csr_from=d,
             key_type='ec-256')
        self.assertEqual(S.plugin_public(STORE, 'target', row).get('key_of'), 'taken1')
        self.assertNotIn('key_of', S.plugin_public(STORE, 'target',
                                                   S.plugin_row(STORE, 'target', 'web')))

    def test_module_problem_at_the_save(self):
        class Picky(base.REGISTRY.get('target', 'fakedevice')):
            kind = 'fakepicky'

            @classmethod
            def device_key_problem(cls, names, key_type, options):
                return 'no %s here' % options.get('slot') if options.get('slot') == 'bad' else ''
        base.REGISTRY.found['target'][Picky.kind] = Picky
        try:
            add('cert_targets', 'picky1', 'fakepicky', {'host': 'p'})
            cid = save(name='pk1', names=['pk1.example.test'], issuer='own', csr_from='picky1',
                       key_type='ec-256')
            dep = STORE.db.row('SELECT id FROM cert_deploys WHERE cert_id = ?', (cid,))
            with self.assertRaises(ValueError) as e:
                api.deploy_save(STORE, {'id': dep['id'], 'cert_id': cid, 'target': 'picky1',
                                        'options': {'slot': 'bad'}}, 'test')
            self.assertIn('no bad here', str(e.exception))
        finally:
            base.REGISTRY.found['target'].pop(Picky.kind, None)

    def test_version_named_in_the_refusal(self):
        class Rsa(base.REGISTRY.get('target', 'fakedevice')):
            kind = 'fakedevice'
            module_version = 'v2'
            device_key_types = ('rsa-2048',)
        d = device()
        save(name='vn1', names=['vn1.example.test'], issuer='own', csr_from=d, key_type='ec-256')
        row = S.plugin_row(STORE, 'target', d)
        with self.assertRaises(ValueError) as e:
            api._device_kind_kept(STORE, row, Rsa)
        self.assertIn('(version v2) makes rsa-2048 keys only', str(e.exception))


class Round3a(unittest.TestCase):
    """1.0.96, round 3a: where the version's key was made recorded, not guessed; a misfit's
    "renew it by hand" said once."""

    def test_1_an_ordinary_certificate_without_its_key_is_not_a_device_one(self):
        # a configuration put in without its secrets drops key_sealed: switched off and on, it
        # was "issued for a key its device made" and issued anew
        cid = save(name='r3n', names=['r3n.example.test'], issuer='own')
        self.assertTrue(renew(cid).ok)
        STORE.db.update('certs', cid, {'key_sealed': None})
        cert = S.cert_get(STORE, cid)
        self.assertEqual(devicekey.version_problem(STORE, cert), '')
        save(id=cid, enabled=0)
        save(id=cid, enabled=1)
        self.assertEqual(S.cert_get(STORE, cid)['state'], 'ok')

    def test_2_the_device_version_recorded(self):
        d = device()
        cid = save(name='r3d', names=['r3d.example.test'], issuer='own', csr_from=d)
        self.assertTrue(renew(cid).ok)
        cert = S.cert_get(STORE, cid)
        self.assertTrue(devicekey.device_made(STORE, cert))
        rec = json.loads(STORE.get_meta(S.CERT_META['devmade'] % cid))
        self.assertEqual((rec['version'], rec['device']), (cert['version'], d))
        # where its key is made taken away (by the database): the recorded version says so
        STORE.db.update('certs', cid, {'csr_from': None})
        self.assertIn('issued for a key its device made',
                      devicekey.version_problem(STORE, S.cert_get(STORE, cid)))
        # a version from before the record: a device's when its key is made by one
        STORE.db.run('DELETE FROM meta WHERE k = ?', (S.CERT_META['devmade'] % cid,))
        self.assertEqual(devicekey.version_problem(STORE, S.cert_get(STORE, cid)), '')
        STORE.db.update('certs', cid, {'csr_from': d})
        self.assertEqual(devicekey.version_problem(STORE, S.cert_get(STORE, cid)), '')

    def test_3_a_misfit_said_once_for_the_version(self):
        d = device()
        cid = save(name='r3m', names=['r3m.example.test'], issuer='own', csr_from=d,
                   auto_renew=0)
        self.assertTrue(renew(cid).ok)
        cert = S.cert_get(STORE, cid)
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE cert_id = ?', (cid,))

        class J(object):
            def step(self, *a, **k):
                pass
        said = [devicekey.deploy_failed(STORE, J(), cert, dep, 0, misfit=True)
                for _ in range(3)]
        self.assertIn('renew it by hand', said[0])
        self.assertEqual(said[1:], ['', ''])
        devicekey.deploy_worked(STORE, cert, dep)
        self.assertIn('renew it by hand',
                      devicekey.deploy_failed(STORE, J(), cert, dep, 0, misfit=True))


class KeptHoldCa(base.Issuer):
    """Holds the request (its key kept with it) while HOLD[0]; finishes the held one after."""
    kind = 'keptholdca'
    title = 'A CA that holds the request with its key (tests)'
    HOLD = [False]

    def issue(self, req):
        slot = SC.pending_slot('keptholdca', 'x', req)
        held = SC.pending_get(self.ctx, slot, req)
        r = SC.held_request(req, held)
        if held is None and self.HOLD[0]:
            SC.pending_put(self.ctx, slot, req, {'id': 'order-1', 'csr_pem': SC.csr_pem(req)})
            raise base.PluginError('the order waits for approval')
        SC.pending_drop(self.ctx, slot)
        return base.Issued(pki.self_signed(r.key_pem, r.names, days=30), [], key_pem=r.key_pem)

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        return 'revoked'


base.REGISTRY.found['issuer'][KeptHoldCa.kind] = KeptHoldCa
add('cert_issuers', 'kepthold', 'keptholdca', {})


class HuntM1(unittest.TestCase):
    """1.0.101, hunt M round 1 (the certificate engine)."""

    def _pub(self, cid):
        return pki.cert_info(S.cert_need(STORE, cid)['cert_pem'])['pub_sha256']

    def _revoke(self, cid):
        return jobs.run_now(STORE, 'revoke', lambda job: renewer.revoke_cert(
            STORE, job, cid, 'keyCompromise', 'test'), cert_id=cid, by='test')

    def test_1_a_request_held_with_the_revoked_key_is_dropped(self):
        cid = save(name='hm1', names=['hm1.example.test'], issuer='kepthold', challenge='',
                   reuse_key=1)
        KeptHoldCa.HOLD[0] = False
        self.assertTrue(renew(cid).ok)
        k1 = self._pub(cid)
        try:
            KeptHoldCa.HOLD[0] = True
            self.assertFalse(renew(cid).ok)         # held at the CA, with the key k1
        finally:
            KeptHoldCa.HOLD[0] = False
        held = lambda: [k for k in STORE.db.rows("SELECT k FROM meta WHERE k LIKE ?",  # noqa
                                                  ('%keptholdca-pending:%:' + str(cid) + '%',))]
        self.assertEqual(len(held()), 1)
        job = self._revoke(cid)
        self.assertTrue(job.ok, words(job))
        self.assertEqual(held(), [], 'dropped at the revoke')
        self.assertIn('dropped', words(job))
        self.assertTrue(renew(cid).ok)
        self.assertNotEqual(self._pub(cid), k1, 'never the revoked key again')

    def test_2_a_held_request_with_a_revoked_key_is_refused(self):
        # one held with the revoked key all the same (put back, or by another node): the
        # source drops it, the new key is used
        cid = save(name='hm2', names=['hm2.example.test'], issuer='kepthold', challenge='',
                   reuse_key=1)
        self.assertTrue(renew(cid).ok)
        cert = S.cert_need(STORE, cid)
        k1 = self._pub(cid)
        self.assertTrue(self._revoke(cid).ok)
        req = base.CertRequest(names=['hm2.example.test'], key_type='ec-256',
                               key_pem=S.cert_key(cert), cert_id=cid)
        req.csr_pem = pki.make_csr(req.key_pem, req.names)[0]
        from acmelib.certs import runtime
        ctx = runtime.RunContext(STORE, None, scope='issuer:kepthold')
        SC.pending_put(ctx, SC.pending_slot('keptholdca', 'x', req), req,
                       {'id': 'order-2', 'csr_pem': req.csr_pem})
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertNotEqual(self._pub(cid), k1)
        self.assertIn('has the key of a version revoked', words(job))
        # a held request with a key not revoked is finished as before
        fresh = base.CertRequest(names=req.names, key_pem=pki.make_key('ec-256'),
                                 no_held_key=[k1])
        self.assertFalse(SC.held_refused(fresh, {'key_pem': fresh.key_pem}))
        self.assertTrue(SC.held_refused(fresh, {'key_pem': req.key_pem}))

    def test_3_another_device_is_no_fit_for_the_version(self):
        a, b = device(), device()
        cid = save(name='hm3', names=['hm3.example.test'], issuer='own', csr_from=a)
        self.assertTrue(renew(cid).ok)
        STORE.set_meta(S.CERT_META['devhand'] % cid, '1')
        STORE.db.run('DELETE FROM cert_deploys WHERE cert_id = ?', (cid,))
        save(id=cid, csr_from=b)
        cert = S.cert_need(STORE, cid)
        self.assertEqual(cert['state'], 'due')
        self.assertFalse(devicekey.device_made(STORE, cert))
        why = devicekey.version_problem(STORE, cert)
        self.assertIn('issued for a key the device of %s made' % a, why)
        self.assertIn(why, devicekey.deploy_problem(STORE, cert, S.plugin_row(STORE, 'target', b)))
        self.assertIsNone(STORE.get_meta(S.CERT_META['devhand'] % cid))
        # back to acme's key: still a device's version
        STORE.db.update('certs', cid, {'csr_from': None})
        self.assertTrue(devicekey.device_made(STORE, S.cert_need(STORE, cid)))

    def test_4_an_ip_address_has_a_validation_of_its_own(self):
        add('cert_challenges', 'hmweb', 'http01', {})
        cid = save(name='hm4', names=['www.hm4.example.test', '2001:db8::10', '192.0.2.44'],
                   issuer='own', challenge='',
                   challenge_map={'2001:DB8:0::10': 'hmweb', '192.0.2.44': 'hmweb',
                                  '*.hm4.example.test': 'hmweb'})
        cert = S.cert_need(STORE, cid)
        self.assertEqual(json.loads(cert['challenge_map']),
                         {'2001:db8::10': 'hmweb', '192.0.2.44': 'hmweb',
                          '*.hm4.example.test': 'hmweb'})
        self.assertEqual(S.challenge_for(cert, '2001:db8::10'), 'hmweb')
        with self.assertRaises(ValueError):
            save(id=cid, challenge_map={'fe80::1%eth0': 'hmweb'})
        with self.assertRaises(ValueError):
            save(id=cid, challenge_map={'bad name!': 'hmweb'})
        # the run plan's draft checked and written the same way
        from acmelib.certs import api_runplan
        got = api_runplan._draft(STORE, {'draft': {
            'names': ['www.hm4.example.test', '2001:db8::10'], 'issuer': 'own',
            'challenge_map': {'2001:DB8::0:10': 'hmweb'}}})
        cert2 = got[0] if isinstance(got, tuple) else got
        self.assertEqual(json.loads(cert2['challenge_map']), {'2001:db8::10': 'hmweb'})
        with self.assertRaises(ValueError):
            api_runplan._draft(STORE, {'draft': {'names': ['x.example.test'], 'issuer': 'own',
                                                 'challenge_map': {'bad name!': 'hmweb'}}})


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
