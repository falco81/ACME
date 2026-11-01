#!/usr/bin/env python3
"""The certificate manager, through a real daemon.

    python3 test/test_certs_core.py          (or python3 -m unittest test.test_certs_core)

No root, no network: a daemon is started in a folder of its own (ACME_CONFIG,
ACME_STATE, ACME_RUN, ACME_LOGDIR, ACME_PLUGINS there; unusual ports), and
asked over its API the way the pages ask - the token of run/api-token in
X-Acme-Token, a signed-in session in X-Acme-Session. A fake target module
is put in the plugins folder and receives the deployments.

What is tried: a self-signed issuer, a certificate added and renewed (the
job and its steps), renewed by the renewer by itself, exports in several
formats (and the roles that may take them), a PFX imported, an authority
made and a certificate issued from it, the fake target tried and deployed
to, the masking of secrets, the DNS records, the leader's lease, the CLI.
"""
import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

FAKE_TARGET = r'''
import os
from acmelib.plugins.base import Target, PluginError, field


class FakeTarget(Target):
    kind = 'fake'
    title = 'Fake target (tests)'
    vendor = 'Test'
    fields = [field('dir', 'Folder', 'text', required=True),
              field('password', 'Password', 'secret')]
    deploy_fields = [field('file', 'File', 'text', required=True),
                     field('pfx_password', 'PFX password', 'secret')]

    def test(self):
        if self.c('password') != 's3cret':
            raise PluginError('the fake target refused the password')
        return 'the fake target answers'

    def deploy(self, bundle, options):
        path = os.path.join(self.c('dir'), options['file'])
        with open(path, 'wb') as f:
            f.write(bundle.as_format('fullchain-pem'))
        with open(path + '.pfx', 'wb') as f:
            f.write(bundle.as_format('pfx', options.get('pfx_password') or 'x'))
        with open(path + '.opts', 'w') as f:
            f.write(repr(sorted(options.items())))
        self.ctx.step('written to %s' % path)
        self.ctx.kv_set('last', bundle.serial)
        return 'put in place'

    def verify(self, bundle, options):
        return self.ctx.kv_get('last') == bundle.serial
'''


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class CertsCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-certs-test-')
        for d in ('state', 'run', 'log', 'plugins/targets', 'out'):
            os.makedirs(os.path.join(cls.tmp, d), exist_ok=True)
        with open(os.path.join(cls.tmp, 'plugins/targets/fake_target.py'), 'w') as f:
            f.write(FAKE_TARGET)
        cls.port = free_port()
        conf = {'api_port': cls.port, 'radius_bind': '127.0.0.1',
                'radius_auth_port': free_port(), 'radius_acct_port': free_port(),
                'ssh_gate_port': free_port(), 'node_name': 'testnode', 'upgrade_check': 0}
        cls.conf = os.path.join(cls.tmp, 'config.json')
        with open(cls.conf, 'w') as f:
            json.dump(conf, f)
        cls.env = dict(os.environ, ACME_CONFIG=cls.conf,
                       ACME_STATE=os.path.join(cls.tmp, 'state'),
                       ACME_RUN=os.path.join(cls.tmp, 'run'),
                       ACME_LOGDIR=os.path.join(cls.tmp, 'log'),
                       ACME_PLUGINS=os.path.join(cls.tmp, 'plugins'),
                       ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        # The accounts, made before the daemon starts (as acme --add-user would).
        cls.pw = 'Test-Password-4711!'
        made = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); '
            'st.add_account("tester", "fulladmin", %r); '
            'st.add_account("viewer", "readonly", %r)') % (ROOT, cls.pw, cls.pw)],
            env=cls.env, capture_output=True, text=True, timeout=120)
        if made.returncode != 0:
            raise RuntimeError('the accounts could not be made: %s' % made.stderr[-2000:])
        cls.daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                      env=cls.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, cwd=cls.tmp)
        end = time.time() + 60
        while time.time() < end:
            if cls.daemon.poll() is not None:
                raise RuntimeError('the daemon stopped: %s' % cls.daemon.stdout.read()
                                   .decode('utf-8', 'replace')[-3000:])
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/api/health' % cls.port, timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError('the daemon did not answer within a minute')
        with open(os.path.join(cls.tmp, 'run', 'api-token')) as f:
            cls.token = f.read().strip()
        cls.admin = cls.login('tester')
        cls.ro = cls.login('viewer')

    @classmethod
    def tearDownClass(cls):
        d = getattr(cls, 'daemon', None)
        if d is not None and d.poll() is None:
            d.send_signal(signal.SIGTERM)
            try:
                d.wait(20)
            except subprocess.TimeoutExpired:
                d.kill()
        if os.environ.get('ACME_TEST_KEEP'):
            print('kept: %s' % cls.tmp)
        else:
            shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- asking ---------------------------------------------------------------------------
    @classmethod
    def call(cls, method, path, body=None, session=None, args=None):
        url = 'http://127.0.0.1:%d%s' % (cls.port, path)
        if args:
            url += '?' + urllib.parse.urlencode(args)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('X-Acme-Token', cls.token)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Acme-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    @classmethod
    def login(cls, name):
        st, got = cls.call('POST', '/api/auth/login', {'name': name, 'password': cls.pw})
        if st != 200:
            raise RuntimeError('signing in as %s: %s %s' % (name, st, got))
        return got['token']

    def ok(self, method, path, body=None, session=None, args=None):
        st, got = self.call(method, path, body, session or self.admin, args)
        self.assertEqual(st, 200, '%s %s -> %s %s' % (method, path, st, got))
        self.assertTrue(got.get('ok'), got)
        return got

    def wait_job(self, job_id, secs=120):
        end = time.time() + secs
        while time.time() < end:
            got = self.ok('GET', '/api/certs/job', args={'id': job_id})['job']
            if got['state'] not in ('queued', 'running'):
                return got
            time.sleep(0.3)
        self.fail('job %s did not end' % job_id)

    def cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                              env=self.env, capture_output=True, text=True, input=stdin,
                              timeout=180)

    # ---- the tests (in order: test_NN_) ------------------------------------------------------
    def test_01_plugins(self):
        got = self.ok('GET', '/api/plugins')
        kinds = {d['kind'] for d in got['target']}
        self.assertIn('fake', kinds, got.get('broken'))
        self.assertIn('selfsigned', {d['kind'] for d in got['issuer']})
        fake = [d for d in got['target'] if d['kind'] == 'fake'][0]
        self.assertEqual([f['key'] for f in fake['deploy_fields']], ['file', 'pfx_password'])

    def test_02_selfsigned_renew_deploy(self):
        sid = self.ok('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                                    'config': {'days': 40}})['id']
        self.assertTrue(sid)
        cid = self.ok('POST', '/api/certs/save', {
            'name': 'web', 'names': ['www.example.test', 'example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'tags': ['test'], 'owner': 'novak'})['id']
        out = os.path.join(self.tmp, 'out')
        self.ok('POST', '/api/targets/save', {'name': 'fake1', 'kind': 'fake',
                                              'config': {'dir': out, 'password': 's3cret'}})
        # The secret never comes back; "" keeps it.
        t = [r for r in self.ok('GET', '/api/targets')['rows'] if r['name'] == 'fake1'][0]
        self.assertEqual(t['config']['password'], '')
        self.assertIn('password', t['secret_set'])
        self.ok('POST', '/api/targets/save', {'id': t['id'], 'name': 'fake1', 'kind': 'fake',
                                              'config': {'dir': out, 'password': ''}})
        tested = self.ok('POST', '/api/targets/test', {'id': t['id']})
        self.assertTrue(tested['ok'], tested)
        self.assertIn('the fake target answers', tested['said'])
        did = self.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'fake1',
                                                    'options': {'file': 'web.pem',
                                                                'pfx_password': 'pfxpw'}})['id']
        d = self.ok('GET', '/api/certs/one', args={'id': cid})['deploys'][0]
        self.assertEqual(d['options']['pfx_password'], '')
        self.assertEqual(d['secret_set'], ['pfx_password'])
        # Renewed (the first issue), then deployed, every step in the job.
        jid = self.ok('POST', '/api/certs/renew', {'id': cid})['job_id']
        job = self.wait_job(jid)
        self.assertEqual(job['state'], 'ok', job)
        words = ' '.join(s[2] for s in job['steps'])
        self.assertIn('issued: version 1', words)
        self.assertIn('fake1: in place and served', words)
        with open(os.path.join(out, 'web.pem')) as f:
            self.assertIn('BEGIN CERTIFICATE', f.read())
        with open(os.path.join(out, 'web.pem.opts')) as f:
            self.assertIn("('pfx_password', 'pfxpw')", f.read())     # opened for the module
        one = self.ok('GET', '/api/certs/one', args={'id': cid})
        self.assertEqual(one['cert']['state'], 'ok')
        self.assertEqual(one['cert']['version'], 1)
        self.assertTrue(one['cert']['has_key'])
        self.assertNotIn('key_sealed', one['cert'])
        self.assertEqual(one['deploys'][0]['state'], 'ok')
        self.assertEqual(one['deploys'][0]['deployed_version'], 1)
        # Again: version 2, the old one kept.
        job = self.wait_job(self.ok('POST', '/api/certs/renew', {'id': cid,
                                                                 'force': True})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        one = self.ok('GET', '/api/certs/one', args={'id': cid})
        self.assertEqual([v['version'] for v in one['versions']], [2, 1])
        # Deploy alone.
        job = self.wait_job(self.ok('POST', '/api/deploys/run', {'id': did})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        jobs = self.ok('GET', '/api/certs/jobs', args={'cert_id': cid})
        self.assertGreaterEqual(jobs['total'], 3)
        self.__class__.cid = cid

    def test_03_exports_and_roles(self):
        cid = self.cid
        for fmt, head in (('cert-pem', b'-----BEGIN CERTIFICATE'),
                          ('fullchain-pem', b'-----BEGIN CERTIFICATE'),
                          ('cert-der', b'\x30'), ('p7b', b'\x30'),
                          ('key-pem', b'-----BEGIN PRIVATE KEY'),
                          ('combined-pem', b'-----BEGIN PRIVATE KEY'),
                          ('pfx', b'\x30')):
            got = self.ok('POST', '/api/certs/export', {'id': cid, 'format': fmt,
                                                        'password': 'Export-pw1'})
            data = base64.b64decode(got['data_b64'])
            self.assertTrue(data.startswith(head), '%s: %r' % (fmt, data[:40]))
            if fmt == 'pfx':
                self.__class__.pfx = data
        # readonly may look but not export, and nobody but a full admin takes a key.
        st, got = self.call('POST', '/api/certs/export', {'id': cid, 'format': 'cert-pem'},
                            self.ro)
        self.assertEqual(st, 403, got)
        st, got = self.call('POST', '/api/certs/save', {'name': 'x', 'names': ['x.test']},
                            self.ro)
        self.assertEqual(st, 403, got)
        self.ok('GET', '/api/certs', session=self.ro)
        st, got = self.call('GET', '/api/certs', session=None)
        self.assertEqual(st, 401, got)

    def test_04_import_pfx(self):
        b64 = base64.b64encode(self.pfx).decode()
        parsed = self.ok('POST', '/api/certs/parse', {'data_b64': b64, 'filename': 'web.pfx',
                                                      'password': 'Export-pw1'})
        self.assertTrue(parsed['has_key'])
        self.assertTrue(parsed.get('key_matches'))
        self.assertIn('www.example.test', parsed['certs'][0]['names'])
        got = self.ok('POST', '/api/certs/import', {'name': 'imported-web', 'data_b64': b64,
                                                    'filename': 'web.pfx',
                                                    'password': 'Export-pw1', 'note': 'test'})
        one = self.ok('GET', '/api/certs/one', args={'id': got['id']})['cert']
        self.assertEqual(one['source'], 'import')
        self.assertTrue(one['has_key'])
        self.assertFalse(one['auto_renew'])
        self.assertEqual(one['state'], 'ok')
        # An imported one is not renewed: it has no issuer.
        st, err = self.call('POST', '/api/certs/renew', {'id': got['id']}, self.admin)
        self.assertEqual(st, 400, err)

    def test_05_own_ca(self):
        caid = self.ok('POST', '/api/cas/create', {'name': 'Test Root',
                                                   'subject': {'CN': 'Test Root CA',
                                                               'O': 'Example'},
                                                   'key_type': 'ec-256', 'days': 3650})['id']
        self.assertTrue(caid)
        plug = self.ok('GET', '/api/plugins')
        ica = [d for d in plug['issuer'] if d['kind'] == 'internal_ca']
        if ica:
            f = [x for x in ica[0]['fields'] if x.get('options_from') == 'cas'][0]
            self.assertIn(['Test Root', 'Test Root'], f['options'])
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Test Root', 'days': 90}})
        cid = self.ok('POST', '/api/certs/save', {'name': 'intranet',
                                                  'names': ['intranet.example.test'],
                                                  'issuer': 'own', 'auto_renew': 0})['id']
        job = self.wait_job(self.ok('POST', '/api/certs/renew', {'id': cid})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        one = self.ok('GET', '/api/certs/one', args={'id': cid})['cert']
        self.assertIn('Test Root CA', one['issuer_dn'])
        self.assertIn('BEGIN CERTIFICATE', one['chain_pem'])
        ca = self.ok('GET', '/api/cas/one', args={'id': caid})
        self.assertEqual(len(ca['issued']), 1)
        self.assertEqual(len(self.ok('GET', '/api/cas')['rows']), 1)
        crl = self.ok('POST', '/api/cas/crl', {'id': caid})
        self.assertIn('BEGIN X509 CRL', crl['crl_pem'])
        exp = self.ok('POST', '/api/cas/export', {'id': caid, 'format': 'cert'}, session=self.ro)
        self.assertIn(b'BEGIN CERTIFICATE', base64.b64decode(exp['data_b64']))
        st, _got = self.call('POST', '/api/cas/export', {'id': caid, 'format': 'key'}, self.ro)
        self.assertEqual(st, 403)

    def test_06_renewed_by_itself(self):
        cid = self.ok('POST', '/api/certs/save', {'name': 'auto', 'names': ['auto.example.test'],
                                                  'issuer': 'self', 'auto_renew': 1})['id']
        end = time.time() + 60
        state = None
        while time.time() < end:
            state = self.ok('GET', '/api/certs/one', args={'id': cid})['cert']['state']
            if state == 'ok':
                break
            time.sleep(0.5)
        self.assertEqual(state, 'ok')
        ov = self.ok('GET', '/api/certs/overview')
        self.assertEqual((ov['leader'] or {}).get('node'), 'testnode')
        self.assertGreaterEqual(ov['total'], 4)

    def test_07_dns_records(self):
        rid = self.ok('POST', '/api/dns/record', {'name': '_acme-challenge.www.example.test',
                                                  'rtype': 'TXT', 'value': 'abc', 'ttl': 30})['id']
        got = self.ok('GET', '/api/dns')
        self.assertIn(rid, [r['id'] for r in got['records']])
        st, _x = self.call('POST', '/api/dns/record', {'name': 'a.test', 'rtype': 'A',
                                                       'value': 'nope'}, self.admin)
        self.assertEqual(st, 400)
        self.ok('POST', '/api/dns/record_delete', {'id': rid})

    def test_08_failure_and_stop(self):
        st, got = self.call('POST', '/api/certs/save', {'name': 'bad', 'names': ['bad name!']},
                            self.admin)
        self.assertEqual(st, 400, got)
        st, got = self.call('POST', '/api/sources/delete',
                            {'id': [r for r in self.ok('GET', '/api/sources')['rows']
                                    if r['name'] == 'self'][0]['id']}, self.admin)
        self.assertEqual(st, 400, got)              # in use
        st, got = self.call('POST', '/api/certs/job_stop', {'id': 999999}, self.admin)
        self.assertEqual(st, 404, got)

    def test_09_cli(self):
        got = self.cli('--certs', '--json')
        self.assertEqual(got.returncode, 0, got.stderr)
        names = {r['name'] for r in json.loads(got.stdout)['rows']}
        self.assertTrue({'web', 'imported-web', 'intranet'} <= names, names)
        got = self.cli('--cert', 'web')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('www.example.test', got.stdout)
        pem = os.path.join(self.tmp, 'out', 'cli.pem')
        got = self.cli('--export', 'web', '--format', 'fullchain-pem', '--out', pem)
        self.assertEqual(got.returncode, 0, got.stderr)
        with open(pem) as f:
            self.assertIn('BEGIN CERTIFICATE', f.read())
        got = self.cli('--jobs', '--json')
        self.assertGreaterEqual(json.loads(got.stdout)['total'], 4)
        got = self.cli('--target-test', 'fake1')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        for opt in ('--sources', '--validations', '--targets', '--cas', '--plugins',
                    '--dns-records', '--status'):
            got = self.cli(opt)
            self.assertEqual(got.returncode, 0, '%s: %s' % (opt, got.stderr))


if __name__ == '__main__':
    import urllib.parse  # noqa: F401
    unittest.main(verbosity=2)
