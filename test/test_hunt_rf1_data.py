#!/usr/bin/env python3
"""Hunt f1, the data layer of 1.0.138 (history and trash, request profile versions, the teams'
governance) - each a bug found and fixed:

    python3 test/test_hunt_rf1_data.py

- a request profile made before 1.0.138 and renamed at its first change: its version 1 is
  filed under its new name (it stayed under the old one: the profile began at version 2, and a
  profile made later under the old name took that version over);
- a deployment of a certificate restored from the trash that could not come back with it (its
  target not here) and was left in the trash on its own names the certificate by its new
  number - it could never be restored ("its certificate is not here any more");
- a team restored from the trash comes back with its governance (separation of duties...) and
  its webhooks, sealed again for its new number - they were lost;
- the trash and the history are forgotten only by the node that leads (a look at them on the
  other node deleted there too), and the note of an UPDATE/DELETE reads at most the 5000 rows it
  keeps, not every row the statement touches (PEMs and all).
"""
import contextlib
import json
import os
import sqlite3
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    wait_job = TCC.CertsCore.__dict__['wait_job']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.outdir = os.path.join(cls.tmp, 'out')

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @contextlib.contextmanager
    def db(self):
        c = sqlite3.connect(os.path.join(self.tmp, 'state', 'acme.db'), timeout=30)
        try:
            with c:
                yield c
        finally:
            c.close()

    def test_profile_renamed_at_first_change(self):
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'selfsigned', 'config': {}})
        b = {'name': 'Old prof', 'issuer': 'own', 'suffixes': ['example.test'],
             'max_names': 3, 'make_key': True, 'key_types': ['ec-256'],
             'key_default': 'ec-256', 'days': 90, 'teams': []}
        self.ok('POST', '/api/reqprofiles/save', b)
        with self.db() as c:      # as a profile made before versions were kept
            c.execute('DELETE FROM cert_req_profile_versions')
        self.ok('POST', '/api/reqprofiles/save', dict(b, name='New prof', old_name='Old prof'))
        v = self.ok('GET', '/api/reqprofiles/versions', args={'name': 'New prof'})
        self.assertEqual([x['version'] for x in v['versions']], [2, 1], v)
        self.assertEqual(v['versions'][1]['snapshot']['name'], 'Old prof')
        with self.db() as c:
            left = c.execute("SELECT COUNT(*) FROM cert_req_profile_versions WHERE "
                             "profile = 'Old prof'").fetchone()[0]
        self.assertEqual(left, 0)
        # a new profile under the old name starts at 1, with nothing of the other's
        self.ok('POST', '/api/reqprofiles/save', b)
        v = self.ok('GET', '/api/reqprofiles/versions', args={'name': 'Old prof'})
        self.assertEqual([x['version'] for x in v['versions']], [1], v)

    def test_deploy_left_in_trash_follows_its_certificate(self):
        self.ok('POST', '/api/targets/save', {'name': 'kid-t', 'kind': 'fake',
                                              'config': {'dir': self.outdir, 'mode': 'a'}})
        self.ok('POST', '/api/sources/save', {'name': 'kidsrc', 'kind': 'selfsigned',
                                              'config': {}})
        cid = self.ok('POST', '/api/certs/save', {'name': 'kid-cert', 'names': ['k.example.test'],
                                                  'issuer': 'kidsrc', 'hold': 1})['id']
        self.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'kid-t',
                                              'options': {'file': 'k.pem'}})
        self.ok('POST', '/api/certs/delete', {'id': cid})
        tid = [r for r in self.ok('GET', '/api/targets')['rows'] if r['name'] == 'kid-t'][0]['id']
        self.ok('POST', '/api/targets/delete', {'id': tid})
        tr = self.ok('GET', '/api/trash')
        cert = [i for i in tr['items'] if i['name'] == 'kid-cert'][0]
        tgt = [i for i in tr['items'] if i['name'] == 'kid-t'][0]
        did = self.ok('POST', '/api/trash/restore', {'id': cert['id']})
        self.assertTrue(did['left'], did)           # its target is not here: left behind
        dep = [i for i in self.ok('GET', '/api/trash')['items']
               if i['name'] == 'kid-cert → kid-t'][0]
        self.ok('POST', '/api/trash/restore', {'id': tgt['id']})
        st, got = self.call('POST', '/api/trash/restore', {'id': dep['id']}, session=self.admin)
        self.assertEqual(st, 200, got)
        with self.db() as c:
            n = c.execute("SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ? AND target = "
                          "'kid-t'", (did['id'],)).fetchone()[0]
        self.assertEqual(n, 1)

    def test_team_back_with_its_governance(self):
        self.ok('POST', '/api/teams/save', {'name': 'Gov team', 'members': []})
        self.ok('POST', '/api/teams/governance', {'team': 'Gov team', 'sod': {
            'no_self_approval': True, 'exclusive': ['Approver + Certificate manager']}})
        self.ok('POST', '/api/teams/hooks', {'team': 'Gov team',
                                             'slack': 'https://hooks.slack.invalid/T0/B0/x'})
        teams = self.ok('GET', '/api/teams')['teams']
        before = [t for t in teams if t['name'] == 'Gov team'][0]['gov']
        self.assertTrue(before.get('sod'), before)
        self.ok('POST', '/api/teams/delete', {'name': 'Gov team'})
        it = [i for i in self.ok('GET', '/api/trash')['items'] if i['name'] == 'Gov team'][0]
        self.ok('POST', '/api/trash/restore', {'id': it['id']})
        teams = self.ok('GET', '/api/teams')['teams']
        after = [t for t in teams if t['name'] == 'Gov team'][0]['gov']
        self.assertEqual(after.get('sod'), before['sod'])
        self.assertEqual(after['hooks'], {'teams': False, 'slack': True})


class Unit(unittest.TestCase):
    def test_purge_only_on_the_leader(self):
        from acmelib import engine as E
        from acmelib.certs import history as H

        class Db(object):
            def __init__(self):
                self.ran = []

            def run(self, sql, args=()):
                self.ran.append(sql)
                return 0

        class St(object):
            db = Db()
        st = St()
        old = E.ha_lead
        E.ha_lead = lambda _s: False
        try:
            H._PURGE['at'] = 0
            H.purge(st)
            self.assertEqual(st.db.ran, [])
            H.purge(st, force=True)                 # the leader's hourly loop asks itself
            self.assertTrue(st.db.ran)
            E.ha_lead = lambda _s: True
            st.db.ran[:] = []
            H._PURGE['at'] = 0
            H.purge(st)
            self.assertTrue(st.db.ran)
        finally:
            E.ha_lead = old

    def test_note_reads_at_most_what_it_keeps(self):
        from acmelib.certs import history as H
        seen = []

        def q(_db, sql, args=(), fetch=True):
            seen.append(sql)
            return [], 0, None
        had = H._ORIG.get('query')
        H._ORIG['query'] = q
        try:
            ctx = H._Ctx(object(), {'name': 'x'}, 'POST', '/api/x')
            H._note_before(None, ctx, 'certs', 'UPDATE',
                           'UPDATE certs SET issuer = ? WHERE issuer = ?', ('a', 'b'))
            H._note_before(None, ctx, 'certs', 'DELETE', 'DELETE FROM certs WHERE id = ?', (1,))
        finally:
            if had is None:
                H._ORIG.pop('query', None)
            else:
                H._ORIG['query'] = had
        self.assertEqual(seen, ['SELECT * FROM certs WHERE issuer = ? LIMIT 5000',
                                'SELECT * FROM certs WHERE id = ? LIMIT 5000'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
