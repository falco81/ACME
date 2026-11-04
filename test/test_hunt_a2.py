#!/usr/bin/env python3
"""The hunt of 1.0.45, round 2 (the certificates, the modules, the flows end to end).

    python3 test/test_hunt_a2.py
"""
import concurrent.futures
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-hunta2-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402,F401
from acmelib.certs import api as A, compat, renewer as R, store as S  # noqa: E402
from acmelib.plugins.targets import _script  # noqa: E402
import test_certs_core as TCC  # noqa: E402


class Units(unittest.TestCase):
    def test_powershell_curly_quotes(self):
        self.assertEqual(_script.ps_str("a'b"), "'a''b'")
        self.assertEqual(_script.ps_str('a’b'), "'a’’b'")

    def test_post_ps_is_a_command(self):
        self.assertIn('post_ps', A.DEPLOY_COMMANDS)

    def test_no_zone_ids_in_names(self):
        self.assertEqual(compat.kind_of('fd00::5%x.example.com'), 'bad')
        with self.assertRaises(ValueError):
            S.clean_names(['fd00::5%x.example.com'])
        with self.assertRaises(ValueError):
            S.clean_names(5)

    def test_true_is_no_id(self):
        with self.assertRaises(ValueError):
            A._id(True)
        self.assertEqual(A._id('5'), 5)

    def test_twin_not_due_where_main_is_not(self):
        t = time.time()
        for st in ('pending-approval', 'declined', 'deleting', 'revoke-failed', 'held'):
            row = {'key_type_alt': 'rsa-2048', 'cert_pem': 'x', 'alt_cert_pem': 'y',
                   'auto_renew': 1, 'issuer': 'x', 'state': st, 'alt_not_after': t + 86400,
                   'alt_not_before': t - 89 * 86400}
            self.assertEqual(R.alt_due(row, t), '', st)


class Flows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    wait_job = TCC.CertsCore.__dict__['wait_job']

    def test_01_a_refused_new_one_is_not_left(self):
        st, got = self.call('POST', '/api/targets/save', {'name': 'half1', 'kind': 'fake',
                                                          'config': {'password': 'x'}}, self.admin)
        self.assertEqual(st, 400, got)
        names = [r['name'] for r in self.ok('GET', '/api/targets')['rows']]
        self.assertNotIn('half1', names)
        out = os.path.join(self.tmp, 'out')
        self.ok('POST', '/api/targets/save', {'name': 'half1', 'kind': 'fake',
                                              'config': {'dir': out}})

    def test_02_one_renewal_at_a_time(self):
        self.ok('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                              'config': {'days': 40}})
        cid = self.ok('POST', '/api/certs/save', {'name': 'par', 'names': ['par.example.test'],
                                                  'issuer': 'self', 'key_type': 'ec-256',
                                                  'auto_renew': 0})['id']
        self.wait_job(self.ok('POST', '/api/certs/renew', {'id': cid})['job_id'])

        def one(_):
            return self.call('POST', '/api/certs/renew', {'id': cid, 'force': True}, self.admin)
        with concurrent.futures.ThreadPoolExecutor(10) as ex:
            got = list(ex.map(one, range(10)))
        # each one is told the job already at work: one job, whoever asked
        jobs_ = {g['job_id'] for st, g in got if st == 200}
        self.assertEqual(len(jobs_), 1, got)
        self.wait_job(jobs_.pop())
        self.__class__.cid = cid

    def test_03_waiting_requests_not_renewed_past_approval(self):
        cid = self.ok('POST', '/api/certs/save', {'name': 'waits', 'names': ['waits.example.test'],
                                                  'issuer': 'self', 'auto_renew': 0})['id']
        self.py_state(cid, 'pending-approval')
        st, got = self.call('POST', '/api/certs/renew', {'id': cid}, self.admin)
        self.assertEqual(st, 400, got)
        self.assertIn('approve', got['error'])

    def py_state(self, cid, state):
        import subprocess
        code = ('import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
                'st = acme.Storage(acme.open_db()); '
                'st.db.run("UPDATE certs SET state = ? WHERE id = ?", (%r, %d))') % (ROOT, state, cid)
        subprocess.run([sys.executable, '-c', code], env=self.env, check=True, timeout=60)

    def test_04_deployment_options_of_their_kind(self):
        st, got = self.call('POST', '/api/deploys/save', {'cert_id': self.cid, 'target': 'half1',
                                                          'options': {'file': 123}}, self.admin)
        self.assertEqual(st, 200, got)          # a number for a text: taken as its text
        st, got = self.call('POST', '/api/deploys/save', {'cert_id': self.cid, 'target': 'half1',
                                                          'options': {'file': {'a': 1}}}, self.admin)
        self.assertEqual(st, 400, got)

    def test_05_a_rename_followed_by_the_portal_setting(self):
        self.ok('POST', '/api/settings', {'settings': {'portal_cert_issuers': 'self'}})
        sid = [r for r in self.ok('GET', '/api/sources')['rows'] if r['name'] == 'self'][0]['id']
        self.ok('POST', '/api/sources/save', {'id': sid, 'name': 'self-renamed', 'kind': 'selfsigned'})
        got = self.ok('GET', '/api/settings')
        vals = got.get('settings') or got.get('values') or got
        self.assertIn('self-renamed', str(vals.get('portal_cert_issuers') if isinstance(vals, dict)
                                          else vals))


if __name__ == '__main__':
    unittest.main()
