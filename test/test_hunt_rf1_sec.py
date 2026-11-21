#!/usr/bin/env python3
"""Hunt R, run f1, security of the routes of 1.0.138 - against a real daemon
(test/test_certs_core.py's way):

- the history of a team (its members, its addresses) only to who sees the team, as /api/teams
  shows them; a version's preview only to who may see the object as it is now;
- an access review takes out only a member who holds no more than the one answering;
- "view as" ends once the one viewing is no longer a full administrator.

    python3 test/test_hunt_rf1_sec.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class HuntF1Sec(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'certs_readonly_all': 0, 'certs_certadmin_all': 0, 'mail_mode': 'off'}})
        for name, role in (('jan', 'readonly'), ('boss', 'readonly'), ('mgr', 'readonly'),
                           ('own', 'readonly'), ('boss2', 'fulladmin'),
                           ('admin3', 'fulladmin')):
            cls.must('POST', '/api/users', {'action': 'add', 'name': name, 'role': role,
                                            'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None, args=None, session=None):
        st, got = cls.call(method, path, body, session or cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def test_01_team_history_only_to_who_sees_the_team(self):
        self.must('POST', '/api/teams/save', {
            'name': 'Web', 'members': [{'who': 'local:jan', 'roles': ['Viewer']}]})
        self.must('POST', '/api/teams/save', {
            'name': 'Hidden', 'contact_mail': 'one@example.test',
            'members': [{'who': 'local:boss', 'roles': ['Team owner']}]})
        self.must('POST', '/api/teams/save', {
            'name': 'Hidden', 'old_name': 'Hidden', 'contact_mail': 'two@example.test',
            'members': [{'who': 'local:boss', 'roles': ['Team owner']},
                        {'who': 'local:ceo', 'roles': ['Viewer']}]})
        jan = self.login('jan')
        # /api/teams: the other team's members and addresses are not shown to jan
        seen = {t['name']: t for t in self.must('GET', '/api/teams', session=jan)['teams']}
        self.assertEqual(seen['Hidden']['members'], [])
        # ...nor in its history
        st, got = self.call('GET', '/api/history', None, jan, {'type': 'team', 'name': 'Hidden'})
        self.assertEqual(st, 403, got)
        self.assertNotIn('two@example.test', str(got))
        feed = self.must('GET', '/api/history', args={'feed': 1, 'type': 'team'}, session=jan)
        self.assertNotIn('Hidden', [e['name'] for e in feed['entries']])
        entry = self.must('GET', '/api/history', args={'type': 'team', 'name': 'Hidden'}
                          )['entries'][-1]['id']
        st, got = self.call('POST', '/api/history/preview', {'entry': entry}, jan)
        self.assertEqual(st, 403, got)
        # its own team's history is still there
        got = self.must('GET', '/api/history', args={'type': 'team', 'name': 'Web'}, session=jan)
        self.assertTrue(got['entries'])
        self.assertIn('Web', [e['name'] for e in self.must(
            'GET', '/api/history', args={'feed': 1, 'type': 'team'}, session=jan)['entries']])
        # a full administrator sees every one
        got = self.must('GET', '/api/history', args={'type': 'team', 'name': 'Hidden'})
        self.assertIn('two@example.test', str(got))

    def test_02_preview_of_a_certificate_given_to_another_team(self):
        self.must('POST', '/api/teams/save', {
            'name': 'TA', 'members': [{'who': 'local:certer', 'roles': ['Certificate manager']}]})
        self.must('POST', '/api/teams/save', {'name': 'TB'})
        body = {'name': 'moved', 'names': ['moved.example.test'], 'issuer': 'self',
                'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'TA'}
        cid = self.must('POST', '/api/certs/save', body)['id']
        self.must('POST', '/api/certs/save', dict(body, id=cid, owner='TB',
                                                  note='now of the team TB'))
        entries = self.must('GET', '/api/history', args={'type': 'cert', 'id': cid})['entries']
        first = entries[-1]['id']
        ca = self.login('certer')
        st, got = self.call('POST', '/api/history/preview', {'entry': first}, ca)
        self.assertEqual(st, 403, got)
        self.assertNotIn('now of the team TB', str(got))
        st, got = self.call('POST', '/api/history/restore', {'entry': first}, ca)
        self.assertEqual(st, 403, got)
        # the administrator: the preview as before
        got = self.must('POST', '/api/history/preview', {'entry': first})
        self.assertTrue(got['changes'])

    def test_03_review_takes_out_only_who_holds_no_more(self):
        self.must('POST', '/api/teams/save', {
            'name': 'Rev', 'members': [{'who': 'local:mgr', 'roles': ['Team manager']},
                                       {'who': 'local:own', 'roles': ['Team owner']},
                                       {'who': 'local:jan', 'roles': ['Viewer']}]})
        mgr = self.login('mgr')
        rid = self.must('POST', '/api/teams/review_open', {'team': 'Rev'},
                        session=mgr)['review']['id']
        st, got = self.call('POST', '/api/teams/review_answer',
                            {'id': rid, 'who': 'local:own', 'keep': False}, mgr)
        self.assertEqual(st, 403, got)
        members = {t['name']: t for t in self.must('GET', '/api/teams')['teams']}['Rev']['members']
        self.assertIn('local:own', [m['who'] for m in members])
        # confirming them stays theirs, and taking out one who holds less too
        self.must('POST', '/api/teams/review_answer',
                  {'id': rid, 'who': 'local:own', 'keep': True}, session=mgr)
        self.must('POST', '/api/teams/review_answer',
                  {'id': rid, 'who': 'local:jan', 'keep': False}, session=mgr)
        members = {t['name']: t for t in self.must('GET', '/api/teams')['teams']}['Rev']['members']
        self.assertNotIn('local:jan', [m['who'] for m in members])

    def test_04_view_as_ends_with_the_full_administrator_role(self):
        b = self.login('boss2')
        self.must('POST', '/api/teams/view_as', {'who': 'local:admin3'}, session=b)
        self.assertEqual(self.must('GET', '/api/auth/whoami', session=b)['who']['role'],
                         'fulladmin')
        self.must('POST', '/api/users', {'action': 'role', 'name': 'boss2', 'role': 'readonly'})
        st, got = self.call('GET', '/api/sshkeys', None, b)
        self.assertEqual(st, 403, got)
        who = self.must('GET', '/api/auth/whoami', session=b)['who']
        self.assertEqual(who['role'], 'readonly')
        self.assertFalse(who.get('view_as'))
        self.assertFalse(self.must('GET', '/api/teams/view_as', session=b)['active'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
