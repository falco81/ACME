# -*- coding: utf-8 -*-
"""A backup put back on a clean installation is the installation it came from:
every row of every table (the certificates and their keys, every version, the
own authorities with their keys and every certificate they had, sources,
validations, targets, deployments, owners and tags, DNS sets, accounts,
settings), the key of the sealed secrets, the node's name and the modules of
your own - and it works: its own authority signs a renewal there.

Only what belongs to the moment is not compared: sign-ins (sessions), the
events the putting back writes itself, and the meta rows of the running
machine (its upgrade state, its node's heartbeat)."""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]

DUMP = r'''
import acmelib.engine as E, json
E.load_config()
st = E.Storage(E.open_db())
out = {}
for t in E.TABLES:
    out[t] = st.db.rows('SELECT * FROM %s' % t)
print(json.dumps({'node': E.node_name(), 'tables': out}, default=str))
'''
BUILD = r'''
import acmelib.engine as E, sys
E.load_config()
st = E.Storage(E.open_db())
print(E.rb_build(st, sys.argv[1])[0])
'''
PROFILE = r'''
import acmelib.engine as E, json, time
E.load_config()
st = E.Storage(E.open_db())
E.HA_STORE['store'] = st
from acmelib.certs import reqprofiles as R, pki, jobs, renewer, api
R.save_profile(st, {'name': 'Web', 'issuer': 'Own', 'suffixes': ['example.test'],
                    'make_key': True, 'csr': True, 'key_types': ['ec-256'], 'max_names': 2,
                    'subject': {'O': {'mode': 'fixed', 'value': 'Example'}}, 'owner': 'fixed',
                    'owner_team': 'Ops', 'tags': ['prod'], 'teams': ['Ops']}, 'test')
csr = pki.make_csr(pki.make_key('ec-256'), ['csr.example.test'])[0]
t = time.time()
cid = st.db.insert('certs', {'name': 'csr.example.test', 'cn': 'csr.example.test',
                             'names': json.dumps(['csr.example.test']), 'key_type': 'ec-256',
                             'issuer': 'Own', 'challenge': '', 'challenge_map': '{}',
                             'auto_renew': 1, 'reuse_key': 0, 'profile': '{}', 'source': 'portal',
                             'state': 'new', 'state_at': t, 'version': 0, 'fails': 0,
                             'tags': '[]', 'owner': 'Ops', 'created': t, 'enabled': 1,
                             'ari': '{}', 'csr_given': csr})
jobs.run_now(st, 'issue', renewer.renew_job(cid, True, 'test'), cert_id=cid)
assert st.db.row('SELECT cert_pem FROM certs WHERE id = ?', (cid,))['cert_pem']
'''
UPLOAD = '''
import acmelib.engine as E
E.load_config()
st = E.Storage(E.open_db())
from acmelib.certs import custom_modules as CM
CM.install(st, 'target', 'f5_v17.py', "from acmelib.plugins.targets.f5 import F5Target\\n\\n\\n"
           "class F5v17(F5Target):\\n    module_version = '17.9'\\n", 'test')
CM.set_mark(st, 'target', 'f5', '17.9', 'works', 'tried', 'test')
'''
LOADED = '''
import json
import acmelib.engine as E
E.load_config()
st = E.Storage(E.open_db())
from acmelib.certs import custom_modules as CM, store as S
CM.materialize(st, force=True)
S.registry().reload()
print(json.dumps({'versions': sorted(S.registry().versions_of('target', 'f5')),
                  'mark': (CM.marks(st).get('target/f5@17.9') or {}).get('state')}))
'''
MOMENT = ('sessions', 'events')                 # not carried / written by the restore
# sig: - the signatures of the guard against writes (1.0.40), made again when a copy is put back.
META_MOMENT = ('upgrade:', 'node:', 'maint:', 'restore', 'putback', 'conf_serial', 'sig:')


class FullRestore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-fullrestore-')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def env(self, name, port):
        base = os.path.join(self.tmp, name)
        for d in ('etc', 'state', 'log', 'run', 'plugins/targets'):
            os.makedirs(os.path.join(base, d), exist_ok=True)
        conf = os.path.join(base, 'etc', 'config.json')
        if not os.path.exists(conf):
            with open(conf, 'w') as f:
                json.dump({'api_port': port}, f)
        return dict(os.environ, ACME_CONFIG=conf, ACME_STATE=os.path.join(base, 'state'),
                    ACME_RUN=os.path.join(base, 'run'), ACME_LOGDIR=os.path.join(base, 'log'),
                    ACME_PLUGINS=os.path.join(base, 'plugins'))

    def run_ok(self, env, *args, stdin=''):
        got = subprocess.run(ACME + list(args), env=env, capture_output=True, text=True,
                             input=stdin, timeout=300, cwd=ROOT)
        self.assertEqual(got.returncode, 0, '%s\n%s\n%s' % (args, got.stdout[-3000:],
                                                            got.stderr[-3000:]))
        return got.stdout

    def py(self, env, code, *args):
        got = subprocess.run([sys.executable, '-c', code] + list(args), env=env,
                             capture_output=True, text=True, timeout=300, cwd=ROOT)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        return got.stdout

    def test_everything_back_and_working(self):
        a = self.env('old', 0)
        with open(a['ACME_CONFIG'], 'w') as f:
            json.dump({'node_name': 'acme7'}, f)
        # what an installation holds: an own root and intermediate (renewed once,
        # so it has a history), a source from it, certificates (one dual) issued,
        # a revoked one, a target and a deployment, an owner, a tag, a DNS set,
        # an account, and a module of your own
        A = a
        self.run_ok(A, '--ca-create', 'Root T', '--subject', 'CN=Root T,O=Example', '--key-type',
                    'ec-256', '--days', '3650')
        self.run_ok(A, '--ca-sub', 'Issuing T', '--parent', 'Root T', '--subject',
                    'CN=Issuing T,O=Example', '--key-type', 'ec-256', '--days', '1825')
        self.run_ok(A, '--ca-renew', 'Issuing T')
        self.run_ok(A, '--source-add', 'Own', '--kind', 'internal_ca', '--set', 'ca=Issuing T')
        self.run_ok(A, '--cert-add', 'web.example.test', '--issuer', 'Own', '--names',
                    'web.example.test,www.example.test')
        self.run_ok(A, '--cert-add', 'dual.example.test', '--issuer', 'Own', '--names',
                    'dual.example.test', '--set', 'key_type_alt=rsa-2048')
        self.run_ok(A, '--cert-add', 'old.example.test', '--issuer', 'Own', '--names',
                    'old.example.test')
        for c in ('web.example.test', 'dual.example.test', 'old.example.test'):
            self.run_ok(A, '--renew', c, '--force')
        self.run_ok(A, '--revoke', 'old.example.test', '--reason', 'superseded', '--yes')
        out_dir = os.path.join(self.tmp, 'out-files')
        self.run_ok(A, '--target-add', 'files', '--kind', 'local', '--set', 'base=' + out_dir)
        self.run_ok(A, '--deploy-add', 'web.example.test', 'files', '--set',
                    'outputs=fullchain-pem {name}.crt\nkey-pem {name}.key 0600')
        self.run_ok(A, '--team-add', 'Ops', '--members', 'local:keeper=manage',
                    '--contact-mail', 'ops@example.test')
        self.run_ok(A, '--tag-add', 'prod', '--colour', 'crit')
        self.run_ok(A, '--cert-edit', 'web.example.test', '--set', 'owner=Ops', '--set',
                    'tags=prod')
        self.run_ok(A, '--dns-set-add', 'Inside', '--servers', '192.0.2.53')
        # a request profile (1.0.18) and a certificate issued for a CSR sent in (no key here)
        self.py(A, PROFILE)
        a_env_pw = dict(A, ACME_PASSWORD='Keeper-Password-4711!')
        self.run_ok(a_env_pw, '--add-user', 'keeper', '--role', 'certadmin')
        with open(os.path.join(A['ACME_PLUGINS'], 'targets', 'mine.py'), 'w') as f:
            f.write('# a module of my own\n')
        # every kind of module of your own (1.0.34): a test on the disk too, one
        # uploaded on the page (in the database), a mark - and the examples and the
        # README install.sh writes, which are not taken (written again by it)
        os.makedirs(os.path.join(A['ACME_PLUGINS'], 'checks'), exist_ok=True)
        with open(os.path.join(A['ACME_PLUGINS'], 'checks', 'my_check.py'), 'w') as f:
            f.write('# a test of my own\n')
        os.makedirs(os.path.join(A['ACME_PLUGINS'], 'examples', 'targets'), exist_ok=True)
        with open(os.path.join(A['ACME_PLUGINS'], 'examples', 'targets', 'x.py.example'), 'w') as f:
            f.write('# an example\n')
        with open(os.path.join(A['ACME_PLUGINS'], 'README'), 'w') as f:
            f.write('words\n')
        self.py(A, UPLOAD)

        # a job at work when the copy is made (1.0.19): it comes back failed, not running
        self.py(A, '''
import acmelib.engine as E, time
E.load_config()
st = E.Storage(E.open_db())
st.db.insert('cert_jobs', {'ts': time.time() - 5, 'kind': 'renew', 'cert_id': 1, 'node': 'acme7',
                           'state': 'running', 'ok': 0, 'steps': '[]', 'by_who': 'x', 'said': ''})
''')

        # the backup, as the daemon makes it
        out = os.path.join(self.tmp, 'bk')
        os.makedirs(out)
        bundle = self.py(A, BUILD, out).strip()
        self.assertTrue(os.path.isfile(bundle), bundle)

        # a clean installation, somewhere else, another node name to begin with
        b = self.env('new', 0)
        with open(b['ACME_CONFIG'], 'w') as f:
            json.dump({'node_name': 'fresh'}, f)
        said = self.run_ok(b, '--restore-bundle', bundle, '--yes')
        self.assertIn('acme7', said)

        old = json.loads(self.py(A, DUMP))
        new = json.loads(self.py(b, DUMP))
        self.assertEqual(new['node'], 'acme7')
        self.assertFalse([j for j in new['tables']['cert_jobs']
                          if j['state'] in ('queued', 'running')])
        self.assertTrue([j for j in new['tables']['cert_jobs'] if j['state'] == 'failed'
                         and 'backup put back' in (j['said'] or '')])
        for t, rows in old['tables'].items():
            if t in MOMENT or t == 'cert_jobs':
                continue
            ka = {json.dumps(r, sort_keys=True, default=str) for r in rows
                  if not (t == 'meta' and str(r.get('k', '')).startswith(META_MOMENT))}
            kb = {json.dumps(r, sort_keys=True, default=str) for r in new['tables'].get(t, [])
                  if not (t == 'meta' and str(r.get('k', '')).startswith(META_MOMENT))}
            self.assertEqual(ka, kb, 'table %s differs after the putting back: %d only before, '
                             '%d only after' % (t, len(ka - kb), len(kb - ka)))
        for t in ('certs', 'cert_versions', 'cert_cas', 'cert_ca_versions', 'cert_ca_issued',
                  'cert_issuers', 'cert_targets', 'cert_deploys', 'cert_teams', 'cert_tags',
                  'dns_sets', 'accounts', 'cert_req_profiles'):
            self.assertTrue(new['tables'][t], 'nothing in %s' % t)
        with open(os.path.join(os.path.dirname(A['ACME_STATE']), 'state', 'secrets.key')) as f1, \
                open(os.path.join(b['ACME_STATE'], 'secrets.key')) as f2:
            self.assertEqual(f1.read(), f2.read())
        self.assertTrue(os.path.isfile(os.path.join(b['ACME_PLUGINS'], 'targets', 'mine.py')))
        self.assertTrue(os.path.isfile(os.path.join(b['ACME_PLUGINS'], 'checks', 'my_check.py')))
        self.assertFalse(os.path.exists(os.path.join(b['ACME_PLUGINS'], 'examples')))
        self.assertFalse(os.path.exists(os.path.join(b['ACME_PLUGINS'], 'README')))
        # the uploaded module and its mark came back with the database - and it loads
        got = json.loads(self.py(b, LOADED))
        self.assertEqual(got['versions'], ['', '17.9'], got)
        self.assertEqual(got['mark'], 'works', got)

        # and it works: the sealed keys open - its authority signs a renewal, the
        # certificate is deployed with its key
        self.run_ok(b, '--renew', 'web.example.test', '--force')
        self.assertTrue(glob.glob(os.path.join(out_dir, 'web.example.test.key')))
        self.run_ok(b, '--renew', 'dual.example.test', '--force')
        self.run_ok(b, '--renew', 'csr.example.test', '--force')       # its CSR, back too


if __name__ == '__main__':
    unittest.main(verbosity=2)
