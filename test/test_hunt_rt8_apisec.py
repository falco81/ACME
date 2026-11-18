#!/usr/bin/env python3
"""Bug hunt R run t8, area apisec: what a certificate administrator kept to some teams could do
with what is not theirs - each found with requests against a running daemon.

    python3 test/test_hunt_rt8_apisec.py

- POST /api/mailq (Delete failed, Delete sent, Send again, or by a mail's id) took every team's
  mail out of the outgoing mail, or sent it again - though GET /api/mailq hides the mails of
  other teams' certificates (and the sign-in codes) from them. Now only the mail they are shown.
- POST /api/deploys/save {id, target} - a deployment saved without its certificate - moved one
  of the team's certificates to another team's device: its team's limits on the device were
  checked only when cert_id was in the body. Now with the deployment's own certificate too.
- POST /api/deploys/dry_run made acme sign in to another team's device and write a team's
  certificate and key into a folder there: the team's limits on the device were checked on a
  save only. Now on the test too.
"""
import json
import os
import sqlite3
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        # the daemon's output read, or it stops at a full pipe
        threading.Thread(target=lambda: [None for _ in iter(
            lambda: cls.daemon.stdout.read(4096), b'')], daemon=True).start()
        cls.must('POST', '/api/settings', {'settings': {'mail_mode': 'off'}})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.must('POST', '/api/users', {'action': 'add', 'name': 'rt8ca', 'role': 'certadmin',
                                        'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {'name': 'RtA', 'members': [
            {'who': 'local:rt8ca', 'roles': ['Team owner']}]})
        cls.must('POST', '/api/teams/save', {'name': 'RtB'})
        cls.ids = {}
        for name, owner in (('rt8a.example.test', 'RtA'), ('rt8b.example.test', 'RtB')):
            cls.ids[owner] = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': [name], 'issuer': 'self', 'auto_renew': 0,
                'owner': owner})['id']
        out = os.path.join(cls.tmp, 'out')
        for name, owner in (('rt8-devA', 'RtA'), ('rt8-devB', 'RtB')):
            os.makedirs(os.path.join(out, name), exist_ok=True)
            cls.must('POST', '/api/targets/save', {'name': name, 'kind': 'fake', 'owner': owner,
                                                   'config': {'dir': os.path.join(out, name)}})
        # SSH to a port nothing answers on: a module with a test (the fake one has none)
        cls.must('POST', '/api/targets/save', {'name': 'rt8-sshB', 'kind': 'ssh', 'owner': 'RtB',
                                               'config': {'host': '127.0.0.1', 'port': 1,
                                                          'user': 'root', 'password': 'x'}})
        cls.scoped = cls.login('rt8ca')

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None, session=None, args=None):
        st, got = cls.call(method, path, body, session or cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def scoped_on(self):
        self.must('POST', '/api/settings', {'settings': {'certs_certadmin_all': 0}})
        self.addCleanup(self.must, 'POST', '/api/settings',
                        {'settings': {'certs_certadmin_all': 1}})

    # ---- the outgoing mail ------------------------------------------------------------------
    def put_mail(self, tail, subject, name, state='failed', kind='certs'):
        now = time.time()
        qid = '%013d-%s' % (int(now * 1000), tail)
        rec = {'to': ['someone@example.test'], 'kind': kind, 'subject': subject, 'name': name,
               'state': state, 'created': now, 'expires': now + 3600, 'tries': 1,
               'node': 'testnode', 'history': [], 'said': 'refused', 'steps': []}
        db = sqlite3.connect(os.path.join(self.tmp, 'state', 'acme.db'), timeout=30)
        try:
            db.execute('INSERT INTO meta (k, v) VALUES (?, ?)', ('mailq:' + qid, json.dumps(rec)))
            db.commit()
        finally:
            db.close()
        return qid

    def qids(self, session=None):
        return {r['qid'] for r in self.must('GET', '/api/mailq', session=session)['rows']}

    def test_mailq_kept_to_what_is_shown(self):
        self.scoped_on()
        mine = self.put_mail('aaaa0001', 'rt8a.example.test: the renewal failed',
                             'rt8a.example.test')
        other = self.put_mail('bbbb0001', 'rt8b.example.test: the renewal failed',
                              'rt8b.example.test')
        code = self.put_mail('cccc0001', 'Your sign-in code', 'novak', kind='code')
        self.assertEqual(self.qids(self.scoped) & {mine, other, code}, {mine})
        # by its id: the other team's and the code stay
        got = self.must('POST', '/api/mailq', {'action': 'drop', 'ids': [other, code]},
                        self.scoped)
        self.assertEqual(got['done'], 0, got)
        self.assertTrue({other, code} <= self.qids())
        # Delete failed: their own only
        got = self.must('POST', '/api/mailq', {'action': 'drop_failed', 'ids': []}, self.scoped)
        self.assertEqual(got['done'], 1, got)
        left = self.qids()
        self.assertNotIn(mine, left)
        self.assertTrue({other, code} <= left)
        # a full administrator: every one, as before
        got = self.must('POST', '/api/mailq', {'action': 'drop', 'ids': [other]})
        self.assertEqual(got['done'], 1)
        got = self.must('POST', '/api/mailq', {'action': 'drop_failed', 'ids': []})
        self.assertGreaterEqual(got['done'], 1)
        self.assertNotIn(code, self.qids())

    # ---- a team's certificate to another team's device -------------------------------------
    def test_deployment_moved_by_its_id_alone(self):
        self.scoped_on()
        a = self.ids['RtA']
        st, got = self.call('POST', '/api/deploys/save', {'cert_id': a, 'target': 'rt8-devB',
                                                          'options': {'file': 'x.pem'}},
                            self.scoped)
        self.assertEqual(st, 403, got)
        dep = self.must('POST', '/api/deploys/save', {'cert_id': a, 'target': 'rt8-devA',
                                                      'options': {'file': 'x.pem'}},
                        self.scoped)['id']
        for body in ({'id': dep, 'target': 'rt8-devB'},
                     {'id': dep, 'cert_id': 0, 'target': 'rt8-devB'},
                     {'id': dep, 'cert_id': '', 'target': 'rt8-devB', 'options': {'file': 'y'}}):
            st, got = self.call('POST', '/api/deploys/save', body, self.scoped)
            self.assertEqual(st, 403, (body, got))
            self.assertIn('another team', got['error'])
        rows = self.must('GET', '/api/deploys', args={'cert_id': a})['rows']
        self.assertEqual([r['target'] for r in rows if r['id'] == dep], ['rt8-devA'])
        # its own device, by its id alone: as before
        self.must('POST', '/api/deploys/save', {'id': dep, 'target': 'rt8-devA',
                                                'options': {'file': 'z.pem'}}, self.scoped)
        # a full administrator moves it anywhere, as before
        self.must('POST', '/api/deploys/save', {'id': dep, 'target': 'rt8-devB'})
        self.must('POST', '/api/deploys/delete', {'id': dep})

    def test_deployment_test_on_another_teams_device(self):
        self.scoped_on()
        a = self.ids['RtA']
        job = self.must('POST', '/api/certs/renew', {'id': a})['job_id']
        end = time.time() + 60
        while time.time() < end:
            j = self.must('GET', '/api/certs/job', args={'id': job})['job']
            if j['state'] not in ('queued', 'running'):
                break
            time.sleep(0.3)
        st, got = self.call('POST', '/api/deploys/dry_run', {
            'cert_id': a, 'target': 'rt8-sshB', 'options': {'preset': 'nginx'}}, self.scoped)
        self.assertEqual(st, 403, got)
        self.assertIn('another team', got['error'])
        # the full administrator's test goes on to the device, as before
        got = self.must('POST', '/api/deploys/dry_run', {
            'cert_id': a, 'target': 'rt8-sshB', 'options': {'preset': 'nginx'}})
        self.assertIn('testing the deployment', json.dumps(got['steps']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
