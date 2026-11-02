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

Then (test_10_ on) what the pages can do done on the command line too: the
sources, validations, targets and deployments added, changed, tried and
deleted with --set checked against the module's fields (a secret from stdin,
never shown), a module's action, the certificates edited, a CSR answered by
an authority of acme's own, the authorities and DNS records; the defaults of
a first start (Let's Encrypt first, never made again once deleted); the
message texts and the notifications in their words; the Prometheus metrics,
the SNMP rows and ACME-MIB agreeing; the fields of the events for isemon and
the SIEM; the alerts; and the certificate of acme's own pages (appliance).
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
              field('password', 'Password', 'secret'),
              field('mode', 'Mode', 'select', default='a', options=[['a', 'A'], ['b', 'B']]),
              field('port', 'Port', 'number', default=1),
              field('names', 'Names', 'list'),
              field('flag', 'Flag', 'bool', default=False)]
    deploy_fields = [field('file', 'File', 'text', required=True),
                     field('pfx_password', 'PFX password', 'secret')]
    actions = [{'key': 'hello', 'label': 'Say hello', 'changes': False}]

    def action(self, key):
        if key != 'hello':
            return Target.action(self, key)
        self.ctx.step('saying hello to %s' % self.c('dir'))
        return 'hello from %s' % self.c('mode')

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
            'st.add_account("viewer", "readonly", %r); '
            'st.add_account("certer", "certadmin", %r)') % (ROOT, cls.pw, cls.pw, cls.pw)],
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
        cls.cert_admin = cls.login('certer')

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

    def cli(self, *args, stdin=None, env=None):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                              env=dict(self.env, **(env or {})), capture_output=True, text=True,
                              input=stdin if stdin is not None else '', timeout=180)

    def cli_ok(self, *args, **kw):
        got = self.cli(*args, **kw)
        self.assertEqual(got.returncode, 0, '%s: %s %s' % (args, got.stdout[-2000:],
                                                           got.stderr[-2000:]))
        return got

    def cli_json(self, *args, **kw):
        return json.loads(self.cli_ok(*(list(args) + ['--json']), **kw).stdout)

    def py(self, code):
        """Python run against the test daemon's database (the engine loaded, `st` the
        store, `E` the engine); what it prints as JSON comes back."""
        head = ('import sys, json, time; sys.path.insert(0, %r); import acme; '
                'from acmelib import engine as E; acme.load_config(); '
                'st = acme.Storage(acme.open_db()); E.HA_STORE["store"] = st; '
                'E.load_config(saved=st.settings_saved())\n' % ROOT)
        got = subprocess.run([sys.executable, '-c', head + code], env=self.env,
                             capture_output=True, text=True, timeout=180)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        return json.loads(got.stdout.strip().splitlines()[-1])

    # ---- the tests (in order: test_NN_) ------------------------------------------------------
    def test_00_first_start(self):
        """Let's Encrypt first: the sources and the validation a new installation has."""
        src = {r['name']: r for r in self.ok('GET', '/api/sources')['rows']}
        self.assertIn('LetsEncrypt', src)
        self.assertIn('LetsEncrypt staging', src)
        self.assertEqual(src['LetsEncrypt']['kind'], 'acme')
        self.assertEqual(src['LetsEncrypt']['config']['directory'], 'letsencrypt')
        self.assertEqual(src['LetsEncrypt staging']['config']['directory'],
                         'letsencrypt-staging')
        self.assertTrue(src['LetsEncrypt']['is_default'])
        vals = {r['name']: r for r in self.ok('GET', '/api/validations')['rows']}
        self.assertEqual(vals['This server HTTP-01']['kind'], 'http_local')
        self.assertTrue(vals['This server HTTP-01']['is_default'])
        self.assertNotIn('acme DNS server', vals)          # no dns_zone set
        ov = self.ok('GET', '/api/certs/overview')
        self.assertEqual({k: ov['defaults'][k] for k in ('issuer', 'challenge')},
                         {'issuer': 'LetsEncrypt', 'challenge': 'This server HTTP-01'})
        self.assertEqual((ov['defaults']['target'], ov['defaults']['ca']), ('', ''))
        self.assertIn('LetsEncrypt', ov['contact_missing'])
        # A new certificate with nothing said: Let's Encrypt, proved by HTTP-01 here.
        cid = self.ok('POST', '/api/certs/save', {'name': 'le-default',
                                                  'names': ['le.example.com'],
                                                  'auto_renew': 0})['id']
        one = self.ok('GET', '/api/certs/one', args={'id': cid})['cert']
        self.assertEqual((one['issuer'], one['challenge']), ('LetsEncrypt',
                                                             'This server HTTP-01'))
        # ... and with an empty issuer said, nothing (a CSR for outside).
        cid2 = self.ok('POST', '/api/certs/save', {'name': 'le-none', 'names': ['n.example.test'],
                                                   'issuer': '', 'auto_renew': 0})['id']
        self.assertEqual(self.ok('GET', '/api/certs/one', args={'id': cid2})['cert']['issuer'],
                         '')
        for i in (cid, cid2):
            self.ok('POST', '/api/certs/delete', {'id': i})
        # Deleted by an administrator: never made again (the meta flag).
        self.ok('POST', '/api/sources/delete', {'id': src['LetsEncrypt staging']['id']})
        got = self.py('from acmelib.certs import defaults; print(json.dumps(defaults.ensure(st)))')
        self.assertEqual(got, [])
        self.assertNotIn('LetsEncrypt staging',
                         [r['name'] for r in self.ok('GET', '/api/sources')['rows']])
        # The contact e-mail, asked for when missing.
        st, err = self.call('POST', '/api/sources/contact', {'email': 'nope'}, self.admin)
        self.assertEqual(st, 400, err)
        got = self.cli_ok('--acme-contact', 'pki@example.test')
        self.assertIn('LetsEncrypt', got.stdout)
        src = {r['name']: r for r in self.ok('GET', '/api/sources')['rows']}
        self.assertEqual(src['LetsEncrypt']['config']['contacts'], ['pki@example.test'])
        self.assertEqual(self.ok('GET', '/api/certs/overview')['contact_missing'], [])

    def test_01_plugins(self):
        got = self.ok('GET', '/api/plugins')
        kinds = {d['kind'] for d in got['target']}
        self.assertIn('fake', kinds, got.get('broken'))
        self.assertIn('selfsigned', {d['kind'] for d in got['issuer']})
        fake = [d for d in got['target'] if d['kind'] == 'fake'][0]
        self.assertEqual([f['key'] for f in fake['deploy_fields'] if not f.get('dual_only')],
                         ['file', 'pfx_password'])

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
        # The secret never comes back in clear: dots and its last two (a full
        # administrator), dots alone (a reader); "" keeps it.
        t = [r for r in self.ok('GET', '/api/targets')['rows'] if r['name'] == 'fake1'][0]
        self.assertEqual(t['config']['password'], '\u2022' * 8 + 'et')
        t_ro = [r for r in self.ok('GET', '/api/targets', session=self.ro)['rows']
                if r['name'] == 'fake1'][0]
        self.assertEqual(t_ro['config']['password'], '\u2022' * 8)
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
        self.assertEqual(d['options']['pfx_password'], '\u2022' * 8 + 'pw')
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
        # The alias asked for is the keystore's (it was dropped: always the default, 1.0.19).
        got = self.ok('POST', '/api/certs/export', {'id': cid, 'format': 'jks',
                                                    'password': 'Export-pw1',
                                                    'alias': 'tomcat-web'})
        self.assertIn(b'\x00\x0atomcat-web', base64.b64decode(got['data_b64']))
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
        # ...nor can it be switched to renew by itself.
        st, err = self.call('POST', '/api/certs/auto', {'id': got['id'], 'auto_renew': 1}, self.admin)
        self.assertEqual(st, 400, err)

    def test_04c_add_and_issue_now(self):
        # saved, the look starts issuing it at once; "issue now" then gets that job
        cid = self.ok('POST', '/api/certs/save', {'name': 'add-issue', 'names': ['ai.example.test'],
                                                  'issuer': 'self', 'auto_renew': 1})['id']
        import glob
        import sqlite3
        db = sqlite3.connect(glob.glob(os.path.join(self.tmp, 'state', '*.db'))[0], timeout=30)
        # as the look's job, working on it
        db.execute("DELETE FROM cert_jobs WHERE cert_id = ?", (cid,))
        cur = db.execute("INSERT INTO cert_jobs (id, ts, kind, cert_id, state, by_who) VALUES "
                         "(?, ?, 'renew', ?, 'running', 'test')", (987654321, time.time(), cid))
        db.commit()
        got = self.ok('POST', '/api/certs/renew', {'id': cid, 'force': True})
        self.assertEqual(got['job_id'], 987654321)
        db.execute("UPDATE cert_jobs SET state = 'ok' WHERE id = ?", (987654321,))
        db.commit()
        db.close()

    def test_04b_auto_renew_switch(self):
        cid = self.ok('POST', '/api/certs/save', {'name': 'auto-switch', 'names': ['as.example.test'],
                                                  'issuer': 'self', 'auto_renew': 1})['id']
        got = self.ok('POST', '/api/certs/auto', {'id': cid, 'auto_renew': 0})
        self.assertEqual(got['auto_renew'], 0)
        one = self.ok('GET', '/api/certs/one', args={'id': cid})['cert']
        self.assertFalse(one['auto_renew'])
        self.assertNotEqual(one['state'], 'revoked')
        self.ok('POST', '/api/certs/auto', {'id': cid, 'auto_renew': 1})
        self.assertTrue(self.ok('GET', '/api/certs/one', args={'id': cid})['cert']['auto_renew'])
        # A read-only one may not.
        if getattr(self, 'reader', None):
            st, err = self.call('POST', '/api/certs/auto', {'id': cid, 'auto_renew': 0}, self.reader)
            self.assertEqual(st, 403, err)

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
        # Revoked and a new one at once: a new key even with reuse_key, renewed by itself.
        self.ok('POST', '/api/certs/save', {'id': cid, 'reuse_key': 1})
        was = self.ok('GET', '/api/certs/one', args={'id': cid})['cert']
        job = self.wait_job(self.ok('POST', '/api/certs/revoke', {'id': cid, 'reason':
                                                                  'keyCompromise', 'renew': 1})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        self.assertIn('a new key', json.dumps(job.get('steps')))
        one = self.ok('GET', '/api/certs/one', args={'id': cid})['cert']
        self.assertEqual(one['state'], 'ok')
        self.assertTrue(one['auto_renew'])
        self.assertNotEqual(one['serial'], was['serial'])
        issued = self.ok('GET', '/api/cas/one', args={'id': caid})['issued']
        self.assertEqual(sorted(bool(i.get('revoked')) for i in issued), [False, True])

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
                    '--dns-records'):
            got = self.cli(opt)
            self.assertEqual(got.returncode, 0, '%s: %s' % (opt, got.stderr))
        # --status says 1 for the engine's own reasons here (no RADIUS client, no realm);
        # its certificate lines are what is looked at.
        got = self.cli('--status')
        self.assertIn('certificates', got.stdout)
        self.assertIn('renewed by        testnode', got.stdout)

    # ---- what the pages do, on the command line ----------------------------------------------
    def test_10_cli_modules(self):
        out = os.path.join(self.tmp, 'out')
        # The fields of a module, as --set takes them.
        got = self.cli_json('--plugin', 'fake')
        mod = got['modules'][0]
        self.assertEqual([f['key'] for f in mod['deploy_fields'] if not f.get('dual_only')],
                         ['file', 'pfx_password'])
        self.assertEqual(mod['actions'][0]['key'], 'hello')
        self.assertIn('pfx_password', self.cli_ok('--plugin', 'target/fake').stdout)
        # Checked against them: a needed one, a choice, a number, a key it has not.
        for sets, words in ((['mode=a'], 'needs dir'), (['dir=%s' % out, 'mode=c'], 'one of'),
                            (['dir=%s' % out, 'port=x'], 'number'),
                            (['dir=%s' % out, 'nope=1'], 'has no setting nope'),
                            (['dir=%s' % out, 'password=s3cret'], 'not taken on the command')):
            args = ['--target-add', 'fake2', '--kind', 'fake']
            for one in sets:
                args += ['--set', one]
            bad = self.cli(*args)
            self.assertNotEqual(bad.returncode, 0, sets)
            self.assertIn(words, bad.stderr, sets)
        # A secret from stdin (KEY=-), never shown; the others as their types.
        self.cli_ok('--target-add', 'fake2', '--kind', 'fake', '--set', 'dir=%s' % out,
                    '--set', 'password=-', '--set', 'mode=b', '--set', 'port=7',
                    '--set', 'names=a.test,b.test', '--set', 'flag=yes', stdin='s3cret\n')
        row = self.cli_json('--target-show', 'fake2')
        self.assertEqual(row['config']['password'], '\u2022' * 8 + 'et')
        self.assertEqual(row['secret_set'], ['password'])
        self.assertEqual((row['config']['mode'], row['config']['port'], row['config']['names'],
                          row['config']['flag']), ('b', 7, ['a.test', 'b.test'], True))
        self.assertNotIn('s3cret', self.cli_ok('--target-show', 'fake2').stdout)
        self.assertEqual(self.cli_json('--target-test', 'fake2')['ok'], True)
        # Changed: what is not said stays (the secret too); a list grows; a new name.
        self.cli_ok('--target-edit', 'fake2', '--set', 'names+=c.test', '--set', 'mode=a',
                    '--name', 'fake3', '--enabled', 'off')
        row = self.cli_json('--target-show', 'fake3')
        self.assertEqual(row['config']['names'], ['a.test', 'b.test', 'c.test'])
        self.assertEqual((row['config']['dir'], row['enabled']), (out, 0))
        self.assertEqual(row['secret_set'], ['password'])
        self.assertTrue(self.cli_json('--target-test', 'fake3')['ok'])
        self.cli_ok('--target-edit', 'fake3', '--enabled', 'on')
        # A module's action: on the command line and through the API.
        got = self.cli_json('--target-action', 'fake3', 'hello')
        self.assertTrue(got['ok'], got)
        self.assertEqual(got['said'], 'hello from a')
        self.assertIn('saying hello', ' '.join(st[2] for st in got['steps']))
        t3 = [r for r in self.ok('GET', '/api/targets')['rows'] if r['name'] == 'fake3'][0]
        self.assertEqual(t3['actions'][0]['key'], 'hello')
        got = self.ok('POST', '/api/targets/action', {'id': t3['id'], 'action': 'hello'})
        self.assertTrue(got['ok'], got)
        st, err = self.call('POST', '/api/targets/action', {'id': t3['id'], 'action': 'nope'},
                            self.admin)
        self.assertEqual(st, 400, err)
        st, err = self.call('POST', '/api/validations/action', {'name': 'This server HTTP-01',
                                                                'action': 'prepare'}, self.admin)
        self.assertEqual(st, 400, err)
        bad = self.cli('--target-action', 'fake3', 'nope')
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('can do hello', bad.stderr)
        # Sources and validations the same way.
        self.cli_ok('--source-add', 'self2', '--kind', 'selfsigned', '--set', 'days=20')
        self.assertTrue(self.cli_json('--source-test', 'self2')['ok'])
        self.cli_ok('--validation-add', 'web-ssh', '--kind', 'http_ssh', '--set',
                    'hosts=192.0.2.21,192.0.2.22', '--set', 'auth=password', '--set',
                    'password=@env', env={'ACME_VALUE_PASSWORD': 'pw-from-env'})
        v = self.cli_json('--validation-show', 'web-ssh')
        self.assertEqual(v['config']['hosts'], ['192.0.2.21', '192.0.2.22'])
        self.assertEqual(v['secret_set'], ['password'])
        self.assertEqual([a['key'] for a in v['actions']], ['nginx_files', 'prepare'])
        self.assertIn('prepare', self.cli_ok('--plugin', 'http_ssh').stdout)
        self.cli_ok('--validation-del', 'web-ssh', '--yes')
        self.cli_ok('--source-del', 'self2', '--yes')
        listed = self.cli_json('--sources')['rows']
        self.assertNotIn('self2', [r['name'] for r in listed])
        # Deployments: added with their options (a secret from the environment), listed by
        # certificate and by target (GET /api/deploys?target=), run, changed, taken away.
        got = self.cli_json('--deploy-add', 'web', 'fake3', '--set', 'file=cli.pem', '--set',
                            'pfx_password=@env', env={'ACME_VALUE_PFX_PASSWORD': 'pfx-env'})
        did = got['id']
        bad = self.cli('--deploy-add', 'web', 'fake3', '--set', 'pfx_password=x')
        self.assertIn('not taken on the command line', bad.stderr)
        bad = self.cli('--deploy-add', 'web', 'fake3')
        self.assertIn('needs file', bad.stderr)
        rows = self.cli_json('--deploys', 'web')['rows']
        mine = [d for d in rows if d['id'] == did][0]
        self.assertEqual((mine['target'], mine['options']['file'], mine['options']['pfx_password'],
                          mine['secret_set']), ('fake3', 'cli.pem', '\u2022' * 8 + 'nv',
                                                ['pfx_password']))
        by_t = self.ok('GET', '/api/deploys', args={'target': 'fake3'})
        self.assertEqual([d['id'] for d in by_t['rows']], [did])
        self.assertEqual(by_t['rows'][0]['cert_name'], 'web')
        st, err = self.call('GET', '/api/deploys', None, self.admin, {'target': 'none-such'})
        self.assertEqual(st, 404, err)
        got = self.cli('--deploy-run', str(did))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('fake3: in place and served', got.stdout)
        with open(os.path.join(out, 'cli.pem.opts')) as f:
            self.assertIn("('pfx_password', 'pfx-env')", f.read())
        self.cli_ok('--deploy-edit', str(did), '--set', 'file=cli2.pem', '--enabled', 'off')
        mine = [d for d in self.cli_json('--deploys')['rows'] if d['id'] == did][0]
        self.assertEqual((mine['options']['file'], mine['enabled'], mine['secret_set']),
                         ('cli2.pem', 0, ['pfx_password']))
        target = self.cli_json('--target-show', 'fake3')
        self.assertEqual([d['id'] for d in target['deploys']], [did])
        bad = self.cli('--target-del', 'fake3', '--yes')
        self.assertIn('in use', bad.stderr)
        self.cli_ok('--deploy-del', str(did), '--yes')
        self.cli_ok('--target-del', 'fake3', '--yes')
        self.assertNotIn('fake3', [r['name'] for r in self.cli_json('--targets')['rows']])

    def test_11_cli_certs(self):
        self.cli_ok('--cert-add', 'clicert', '--names', 'cli.example.test', '--issuer', 'self',
                    '--set', 'auto_renew=no', '--set', 'tags=a,b')
        one = self.cli_json('--cert', 'clicert')['cert']
        self.assertEqual((one['issuer'], one['auto_renew'], one['tags']), ('self', 0, ['a', 'b']))
        self.cli_ok('--cert-edit', 'clicert', '--names', 'cli.example.test,cli2.example.test',
                    '--set', 'renew_days=21', '--set', 'tags+=c', '--set', 'owner=novak',
                    '--set', 'profile.eku=serverAuth,clientAuth', '--set',
                    'profile.must_staple=no', '--set', 'challenge_map.cli2.example.test=' +
                    'This server HTTP-01', '--note', 'from the cli')
        one = self.cli_json('--cert', 'clicert')['cert']
        self.assertEqual(one['names'], ['cli.example.test', 'cli2.example.test'])
        self.assertEqual((one['renew_days'], one['tags'], one['owner'], one['note']),
                         (21, ['a', 'b', 'c'], 'novak', 'from the cli'))
        self.assertEqual(one['profile'], {'eku': ['serverAuth', 'clientAuth'],
                                          'must_staple': False})
        self.assertEqual(one['challenge_map'], {'cli2.example.test': 'This server HTTP-01'})
        bad = self.cli('--cert-edit', 'clicert', '--set', 'colour=red')
        self.assertIn('has no colour', bad.stderr)
        # Renewed here, then revoked where it was issued (an authority of acme's own).
        self.cli_ok('--cert-edit', 'clicert', '--issuer', 'own', '--set', 'challenge_map.'
                    'cli2.example.test=')
        got = self.cli('--renew', 'clicert')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        bad = self.cli('--revoke', 'clicert', '--reason', 'nonsense', '--yes')
        self.assertIn('the reason is one of', bad.stderr)
        got = self.cli('--revoke', 'clicert', '--reason', 'superseded', '--yes')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(self.cli_json('--cert', 'clicert')['cert']['state'], 'revoked')
        # A CSR for an outside authority, answered by --ca-sign, taken back by --csr-answer.
        self.cli_ok('--cert-add', 'outside', '--names', 'out.example.test', '--issuer', '')
        csr = os.path.join(self.tmp, 'out', 'outside.csr')
        self.cli_ok('--csr', 'outside', '--out', csr)
        with open(csr) as f:
            self.assertIn('CERTIFICATE REQUEST', f.read())
        self.assertIn('CERTIFICATE REQUEST', self.cli_ok('--csr', 'outside').stdout)
        signed = os.path.join(self.tmp, 'out', 'outside.pem')
        self.cli_ok('--ca-sign', 'Test Root', '--csr', csr, '--days', '30', '--set',
                    'eku=serverAuth', '--out', signed)
        got = self.cli_json('--csr-answer', 'outside', signed)
        self.assertEqual(got['version'], 1)
        one = self.cli_json('--cert', 'outside')['cert']
        self.assertEqual((one['state'], one['has_key']), ('ok', True))
        self.cli_ok('--cert-del', 'outside', '--yes')
        self.cli_ok('--cert-del', 'clicert', '--yes')
        names = {r['name'] for r in self.cli_json('--certs')['rows']}
        self.assertFalse({'outside', 'clicert'} & names)
        bad = self.cli('--cert-del', 'web')         # no terminal, no --yes: refused
        self.assertIn('again with --yes', bad.stderr)

    def test_12_cli_cas_and_dns(self):
        self.cli_ok('--ca-sub', 'Test Issuing', '--parent', 'Test Root', '--subject',
                    'CN=Test Issuing CA', '--set', 'crl_days=3', '--set',
                    'crl_url=http://pki.example.test/issuing.crl')
        cas = {r['name']: r for r in self.cli_json('--cas')['rows']}
        self.assertEqual(cas['Test Issuing']['parent_id'], cas['Test Root']['id'])
        got = self.cli_json('--ca-show', 'Test Issuing')
        self.assertTrue(got['ca']['has_key'])
        self.assertIn('Test Issuing', self.cli_ok('--cas').stdout)
        crl = os.path.join(self.tmp, 'out', 'issuing.crl')
        self.cli_ok('--ca-crl', 'Test Issuing', '--out', crl)
        with open(crl) as f:
            self.assertIn('BEGIN X509 CRL', f.read())
        cert = os.path.join(self.tmp, 'out', 'issuing.pem')
        self.cli_ok('--ca-export', 'Test Issuing', '--what', 'cert', '--out', cert)
        with open(cert) as f:
            self.assertIn('BEGIN CERTIFICATE', f.read())
        bad = self.cli('--ca-export', 'Test Issuing', '--what', 'key')
        self.assertIn('--out', bad.stderr)
        issued = self.cli_json('--ca-show', 'Test Root')['issued']
        serial = [i for i in issued if 'out.example.test' in json.dumps(i)][0]['serial']
        self.cli_ok('--ca-revoke', 'Test Root', serial, '--reason', 'superseded', '--yes')
        issued = self.cli_json('--ca-show', 'Test Root')['issued']
        self.assertTrue([i for i in issued if i['serial'] == serial][0]['revoked'])
        self.cli_ok('--ca-del', 'Test Issuing', '--yes')
        self.assertNotIn('Test Issuing', [r['name'] for r in self.cli_json('--cas')['rows']])
        # acme's own DNS server: a record added and taken away again.
        got = self.cli_json('--dns-add', 'www.example.test', 'A', '192.0.2.80', '--ttl', '30')
        recs = self.cli_json('--dns-records')['records']
        mine = [r for r in recs if r['id'] == got['id']][0]
        self.assertEqual((mine['value'], mine['ttl']), ('192.0.2.80', 30))
        bad = self.cli('--dns-add', 'www.example.test', 'A', 'not-an-address')
        self.assertNotEqual(bad.returncode, 0)
        self.cli_ok('--dns-del', 'www.example.test', 'A')
        self.assertFalse([r for r in self.cli_json('--dns-records')['records']
                          if r['id'] == got['id']])

    def test_13_help_groups(self):
        got = self.cli_ok('--help')
        for g in ('CERTIFICATES', 'CERTIFICATES: SOURCES, VALIDATIONS AND TARGETS',
                  'CERTIFICATES: DEPLOYMENTS', 'CERTIFICATES: AUTHORITIES OF ACME\'S OWN',
                  'CERTIFICATES: ACME\'S OWN DNS SERVER'):
            self.assertIn(g, got.stdout)
        for opt in ('--source-add', '--validation-action', '--deploy-add', '--ca-sign',
                    '--dns-add', '--plugin', '--csr-answer', '--acme-contact'):
            self.assertIn(opt, got.stdout)

    def test_14_texts(self):
        got = self.ok('GET', '/api/texts')
        ids = {m['id'] for m in got['messages']}
        for mid in ('cert_expiring', 'cert_expiring_sms', 'cert_expired', 'cert_renewed',
                    'cert_renew_failed', 'cert_renew_failed_sms', 'cert_deployed',
                    'cert_deploy_failed', 'cert_deploy_failed_sms', 'cert_portal_issued',
                    'cert_portal_declined'):
            self.assertIn(mid, ids)
        self.assertIn('cert', got['placeholders'])
        one = [m for m in got['messages'] if m['id'] == 'cert_renew_failed'][0]
        f = [x for x in one['fields'] if x['where'] == 'subject'][0]
        self.assertEqual(f['default']['en'], 'Renewing {cert} failed')
        self.assertEqual(f['default']['cs'], 'Obnovení {cert} selhalo')
        for lang in ('en', 'cs'):
            r = self.ok('GET', '/api/texts', args={'render': 'cert_renew_failed', 'lang': lang})
            self.assertIn('www', r['subject'])
            self.assertIn('<html', r['html'])
            self.assertIn('rateLimited', r['text'])
        sms = self.ok('GET', '/api/texts', args={'render': 'cert_deploy_failed_sms',
                                                 'lang': 'en'})
        self.assertIn('f5-prague', sms['sms'])
        # Changed on Settings → Message texts: the notifications speak those words.
        self.ok('POST', '/api/texts', {'action': 'save', 'id': 'cert_renew_failed', 'lang': 'en',
                                       'fields': {f['key']: 'RENEW-FAIL {cert}: {error}'}})
        st, err = self.call('POST', '/api/texts', {'action': 'save', 'id': 'cert_renew_failed',
                                                   'lang': 'en',
                                                   'fields': {f['key']: 'bad {code}'}},
                            self.admin)
        self.assertEqual(st, 400, err)
        got = self.py(r"""
E.CONFIG.update(alerts_lang='en', certs_notify_mail='ops@example.test',
                certs_notify_sms='+420600000000')
sent = []
E.mail_deliver = lambda store, msg, to, **kw: sent.append(('mail', msg['Subject'], to,
                                                           msg.get_body(('plain',)).get_content()))
E.sms_send = lambda tel, text: sent.append(('sms', tel, text))
from acmelib.certs import notices, renewer, store as S
print(notices.install(renewer), file=sys.stderr)
cid = S.cert_get(st, 'web')['id']
renewer.notify(st, 'renew:%s' % cid, 'Renewing web failed', 'the CA said no', force=True)
renewer.notify(st, 'expired:%s' % cid, 'web has expired', 'It ended.', force=True)
renewer.notify(st, 'whatever', 'Something', 'else', force=True)
print(json.dumps(sent))
""")
        self.assertEqual(got[0][0], 'mail')
        self.assertIn('RENEW-FAIL web: the CA said no', got[0][1])
        self.assertEqual(got[0][2], ['ops@example.test'])
        self.assertEqual(got[1][:2], ['sms', '+420600000000'])
        self.assertIn('renewing web failed: the CA said no', got[1][2])
        self.assertIn('Certificate web has expired', got[2][1])
        self.assertIn('EXPIRED', got[3][2])
        self.assertEqual(got[4][1], '[acme testnode] Something')
        self.ok('POST', '/api/texts', {'action': 'reset', 'id': 'cert_renew_failed',
                                       'lang': 'en'})

    def test_15_metrics_and_snmp(self):
        got = self.py(r"""
class D(object):
    store = st; started = time.time(); dirs = []
class Ag(object):
    started = time.monotonic(); engine = b'test'; boots = 1
print(json.dumps({'text': E.metrics_text(D()),
                  'rows': [[list(o), k, v] for o, k, v in E.snmp_mib(D(), Ag())],
                  'base': list(E.SNMP_BASE)}, default=str))
""")
        text = got['text']
        for name in ('acme_certs{state="ok"}', 'acme_cert_not_after_timestamp_seconds{cn=',
                     'acme_cert_state{name="web",state="ok"} 1', 'acme_cert_renewals_total{',
                     'acme_cert_deploys{state="ok"}', 'acme_cert_last_job_timestamp_seconds{',
                     'acme_cert_leader{node="testnode"}', 'acme_cert_expiry_seconds{name="web"}'):
            self.assertIn(name, text)
        self.assertRegex(text, r'acme_cert_not_after_timestamp_seconds\{cn="www\.example\.test",'
                               r'issuer="self",name="web"\} \d{10}')
        self.assertIn('# TYPE acme_cert_renewals_total counter', text)
        base = tuple(got['base'])
        rows = {tuple(o): (k, v) for o, k, v in got['rows']}
        # The table of the certificates kept, by their id.
        web = self.ok('GET', '/api/certs/one', args={'name': 'web'})['cert']
        T = base + (6, 2, 1)
        self.assertEqual(rows[T + (2, web['id'])], ('str', 'web'))
        self.assertEqual(rows[T + (3, web['id'])], ('str', 'www.example.test'))
        self.assertEqual(rows[T + (4, web['id'])][1], int(web['not_after']))
        self.assertEqual(rows[T + (6, web['id'])], ('str', 'ok'))
        self.assertEqual(rows[T + (7, web['id'])], ('str', 'self'))
        self.assertEqual(rows[base + (6, 3, 2, 0)][0], 'gauge')
        # ... and every one of them an object of ACME-MIB (deploy/ACME-MIB.txt).
        import re
        with open(os.path.join(ROOT, 'deploy', 'ACME-MIB.txt')) as f:
            mib = f.read()
        defs = {'acme': base}
        pairs = re.findall(r'^(\w+)\s+(?:OBJECT-TYPE|OBJECT IDENTIFIER)[^\n]*(?:\n[ \t].*)*?'
                           r'::=\s*\{\s*(\w+)\s+(\d+)\s*\}', mib, re.M)
        for _ in range(8):
            for name, parent, n in pairs:
                if parent in defs:
                    defs[name] = defs[parent] + (int(n),)
        known = set(defs.values())
        mine = [o for o in rows if o[:len(base) + 2] in (base + (6, 2), base + (6, 3))]
        self.assertGreater(len(mine), 10)
        for o in mine:
            self.assertIn(o[:-1], known, 'the agent answers %s, ACME-MIB has no object there'
                          % '.'.join(map(str, o)))
        for col in range(1, 11):
            self.assertIn(base + (6, 2, 1, col), known)
            self.assertIn(base + (6, 3, col), known)

    def test_16_events_for_isemon_and_siem(self):
        got = self.py(r"""
w = 'web renewed (version 2, until 2026-12-01)'
f = E.event_fields('certificates', w, 'info')
line = E.event_kv('certificates', w, 'info', 'acme', 'testnode', f)
with E.event_with(cert='web', action='deployed', result='ok', target='t1'):
    f2 = E.event_fields('certificates', 'web (version 2) deployed to t1', 'info')
s = E.Siem()
E.CONFIG['siem_format'] = 'json'
frame = s.frame('event', 6, dict(f, event='event', kind='certificates'), 'certificates: ' + w)
print(json.dumps({'f': f, 'line': line, 'f2': f2, 'frame': frame,
                  'other': E.event_fields('settings', 'x', 'info')}))
""")
        f = got['f']
        self.assertEqual((f['cert'], f['action'], f['result'], f['version'], f['issuer']),
                         ('web', 'renewed', 'ok', '2', 'self'))
        self.assertTrue(f['serial'] and f['not_after'].endswith('Z'))
        self.assertIn('names="www.example.test,example.test"', got['line'])
        self.assertIn('action=renewed cert=web', got['line'])
        self.assertTrue(got['line'].endswith('msg="web renewed (version 2, until 2026-12-01)"'))
        self.assertEqual(got['f2'], {'cert': 'web', 'action': 'deployed', 'result': 'ok',
                                     'target': 't1'})
        body = json.loads(got['frame'].split('﻿', 1)[1])
        self.assertEqual((body['cert'], body['action'], body['type']), ('web', 'renewed',
                                                                        'event'))
        self.assertEqual(got['other'], {})
        # What the daemon wrote for the deployments: in acme-certs.log with its fields.
        path = os.path.join(self.tmp, 'log', 'acme-certs.log')
        if os.path.exists(path):
            with open(path) as fh:
                lines = [ln for ln in fh if 'deployed to fake1' in ln]
            if lines:
                self.assertIn('target=fake1', lines[-1])
                self.assertIn('action=deployed', lines[-1])

    def test_17_appliance_and_alerts(self):
        """The certificate of acme's own pages from the certificate database."""
        self.cli_ok('--target-add', 'pages', '--kind', 'appliance')
        self.assertIn('this node is testnode', self.cli_json('--target-test', 'pages')['said'])
        did = self.cli_json('--deploy-add', 'web', 'pages', '--set', 'where=this')['id']
        job = self.wait_job(self.ok('POST', '/api/deploys/run', {'id': did})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        words = ' '.join(s[2] for s in job['steps'])
        self.assertIn('the pages of testnode take www.example.test', words)
        self.assertIn('pages: in place and served', words)
        web = self.ok('GET', '/api/certs/one', args={'name': 'web'})['cert']
        got = self.py(r"""
prof = E.tls_profile(st, 'testnode') or {}
print(json.dumps({'fp': (prof.get('info') or {}).get('fingerprint'), 'how': prof.get('how'),
                  'key': bool(E.unseal_secret(prof.get('key'), 'web:tls')),
                  'care': E.acme_care(st, 'testnode'), 'vip': E.tls_profile(st, 'vip')}))
""")
        self.assertEqual(got['fp'].replace(':', '').lower(), web['fingerprint'].replace(
            ':', '').lower())
        self.assertEqual(got['how'], 'the certificate manager: web')
        self.assertTrue(got['key'])
        self.assertFalse(got['care'])           # the engine's own ACME leaves it alone
        self.assertIsNone(got['vip'])
        # Renewed: put on the pages again by itself.
        job = self.wait_job(self.ok('POST', '/api/certs/renew', {'id': web['id'],
                                                                 'force': True})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        web2 = self.ok('GET', '/api/certs/one', args={'name': 'web'})['cert']
        fp = self.py("print(json.dumps((E.tls_profile(st, 'testnode') or {}).get('info', {})"
                     ".get('fingerprint')))")
        self.assertEqual(fp.replace(':', '').lower(), web2['fingerprint'].replace(':', '').lower())
        self.assertNotEqual(web2['fingerprint'], web['fingerprint'])
        # The VIP address on one server: refused - a failed deployment, and an alert.
        self.cli_ok('--deploy-edit', str(did), '--set', 'where=vip')
        job = self.wait_job(self.ok('POST', '/api/deploys/run', {'id': did})['job_id'])
        self.assertEqual(job['state'], 'failed', job)
        self.assertIn('no VIP address', job['said'])
        got = self.py("print(json.dumps(sorted(E.alert_problems(st, 'en'))))")
        self.assertIn('mod:cert-deploy:%s' % did, got)
        snmp = self.py("from acmelib.certs import monitor\n"
                       "print(json.dumps([[list(o), v] for o, k, v in monitor.snmp_rows(st)]))")
        self.assertIn([[6, 3, 6, 0], 1], [[o, v] for o, v in snmp if o == [6, 3, 6, 0]])
        self.cli_ok('--deploy-del', str(did), '--yes')
        self.cli_ok('--target-del', 'pages', '--yes')

    @staticmethod
    def _read(path):
        with open(path) as f:
            return f.read()

    def test_18_deploy_files_preview_password_script(self):
        """A deployment's files: the preview the page shows, the password acme makes
        (sealed, shown as a full administrator sees a secret), the script written in
        it (only a full administrator changes it), the test that changes nothing."""
        web = self.ok('GET', '/api/certs/one', args={'name': 'web'})['cert']
        base = os.path.join(self.tmp, 'files-out')
        self.ok('POST', '/api/targets/save', {'name': 'files1', 'kind': 'local', 'config': {
            'base': base, 'allow_scripts': True}})
        said = os.path.join(self.tmp, 'script-said.txt')
        opts = {'outputs': ['fullchain-pem {name}/fullchain.pem 0644',
                            'key-pem {name}/privkey.pem 0600', 'pfx {name}/site.pfx'],
                'pfx_password_mode': 'generate', 'script_mode': 'inline', 'script_interp': 'sh',
                # appended: the daemon may deploy it by itself meanwhile (a new deployment
                # is run by the next look) - each run its own line
                'script_body': 'echo "$ACME_DRY_RUN $ACME_PASSWORD $ACME_FILE_PFX" >> %s\n' % said}
        got = self.ok('POST', '/api/deploys/preview', {'cert_id': web['id'], 'target': 'files1',
                                                       'options': opts})
        self.assertEqual([f['format'] for f in got['files']], ['fullchain-pem', 'key-pem', 'pfx'])
        self.assertEqual(got['files'][0]['full'], os.path.join(base, 'web/fullchain.pem'))
        self.assertEqual(got['env']['ACME_PASSWORD'], '\u2022' * 8)
        self.assertTrue(got['issued'])
        # not issued yet (or no certificate at all): the names, sizes guessed
        got = self.ok('POST', '/api/deploys/preview', {'target': 'files1', 'options': opts,
                                                       'names': ['shop.example.test']})
        self.assertEqual(got['files'][0]['path'], 'shop.example.test/fullchain.pem')
        self.assertFalse(got['files'][0]['exact'])
        # a certificate administrator may not write the script
        count = self.py('print(st.db.value("SELECT COUNT(*) FROM cert_deploys"))')
        st, refused = self.call('POST', '/api/deploys/save', {
            'cert_id': web['id'], 'target': 'files1', 'options': opts}, self.cert_admin)
        self.assertEqual(st, 403, refused)
        # ...and the refused one is not left behind (1.0.21: every failed Save made one)
        self.assertEqual(self.py('print(st.db.value("SELECT COUNT(*) FROM cert_deploys"))'), count)
        did = self.ok('POST', '/api/deploys/save', {'cert_id': web['id'], 'target': 'files1',
                                                    'options': opts})['id']
        d = [x for x in self.ok('GET', '/api/deploys', args={'target': 'files1'})['rows']
             if x['id'] == did][0]
        self.assertIn('pfx_password', d['secret_set'])
        self.assertTrue(d['options']['pfx_password'].startswith('\u2022' * 8))
        # ...but may change the rest, the script kept as it is
        self.ok('POST', '/api/deploys/save', {'id': did, 'options': dict(opts, jks_alias='x')},
                session=self.cert_admin)
        # the test: the script told ACME_DRY_RUN=1, nothing in place
        t = self.ok('POST', '/api/deploys/dry_run', {'id': did})
        self.assertTrue(t['ok'], t)
        runs = [ln.split() for ln in self._read(said).splitlines() if ln.strip()]
        dry, pw, pfx = [r for r in runs if r[0] == '1'][-1]
        self.assertEqual(dry, '1')
        self.assertEqual(len(pw), 24)
        self.assertNotIn(base, pfx)                     # a copy in a temporary folder...
        self.assertFalse(os.path.exists(pfx))           # ...deleted after
        # deployed: the same password, kept; the file where it belongs
        job = self.wait_job(self.ok('POST', '/api/deploys/run', {'id': did})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        dry2, pw2, pfx2 = self._read(said).splitlines()[-1].split()
        self.assertEqual((dry2, pw2), ('0', pw))
        self.assertEqual(pfx2, os.path.join(os.path.realpath(base), 'web', 'site.pfx'))
        self.assertTrue(os.path.exists(pfx2))
        # a new one asked for: another password
        self.ok('POST', '/api/deploys/save', {'id': did, 'options': dict(
            opts, pfx_password_new=True)})
        self.ok('POST', '/api/deploys/dry_run', {'id': did})
        last_dry = [ln.split() for ln in self._read(said).splitlines() if ln.startswith('1 ')][-1]
        self.assertNotEqual(last_dry[1], pw)


    def test_19_delete_revokes_first(self):
        """Delete with revoke (1.0.21): revoked at its CA in a job, then gone; without,
        gone at once; one that cannot be revoked is said so and kept."""
        cid = self.ok('POST', '/api/certs/save', {'name': 'delrev', 'names': ['delrev.example.test'],
                                                  'issuer': 'own', 'auto_renew': 0})['id']
        self.wait_job(self.ok('POST', '/api/certs/renew', {'id': cid})['job_id'])
        one = self.ok('GET', '/api/certs/one', args={'id': cid})['cert']
        self.assertEqual(one['revoke_no'], '')
        serial = one.get('serial') or (one.get('info') or {}).get('serial')
        got = self.ok('POST', '/api/certs/delete', {'id': cid, 'revoke': 1,
                                                    'reason': 'cessationOfOperation'})
        job = self.wait_job(got['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        st, _ = self.call('GET', '/api/certs/one', None, self.admin, {'id': cid})
        self.assertEqual(st, 404)
        issued = self.py('print(json.dumps([r["revoked"] for r in st.db.rows("SELECT revoked FROM '
                         'cert_ca_issued WHERE names LIKE ?", ("%%delrev.example.test%%",))]))')
        self.assertTrue(issued and all(issued), (serial, issued))
        # never issued: cannot be revoked - refused with revoke, deleted without
        cid2 = self.ok('POST', '/api/certs/save', {'name': 'delnew', 'names': ['delnew.example.test'],
                                                   'issuer': 'own', 'auto_renew': 0})['id']
        self.assertTrue(self.ok('GET', '/api/certs/one', args={'id': cid2})['cert']['revoke_no'])
        st, got = self.call('POST', '/api/certs/delete', {'id': cid2, 'revoke': 1}, self.admin)
        self.assertEqual(st, 400, got)
        self.ok('POST', '/api/certs/delete', {'id': cid2})


if __name__ == '__main__':
    import urllib.parse  # noqa: F401
    unittest.main(verbosity=2)
