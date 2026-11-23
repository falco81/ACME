#!/usr/bin/env python3
"""Hunt w6, area perf: a big installation (thousands of certificates, deployments, targets, agents).

- The certificates whose key an agent's server makes (certs.csr_from) were asked with no index,
  once for every agent of Agents and Fleet: a scan of every certificate each time (3 s and more
  with 1000 agents and 20000 certificates). certs_csr_from is made with the tables.
- The renewer's look (every five minutes) read every certificate twice more (ARI asked or not),
  and asked three statements for every deployment (revoked? held?) - 100000 statements a look for
  20000 certificates and 30000 deployments; it read every certificate's PEMs and key (150 MB).
- The list of certificates asked six statements a row (its deployments counted three times, its
  last job, its hold, what the portal kept): 6000 for a page of 1000.
- Who holds a name (a request waiting for approval) compared every certificate's every name with
  each name asked, for each request of the list: seconds for a page with 70 requests.
- A team asked by name (contact_mails, every warning of the renewer) read every team.
- The alerts (the Overview, SNMP, Prometheus) asked two statements for each certificate of a
  failed deployment; the Targets page two statements a target; GET /api/deploys three a row;
  the Fleet read every row of meta again for each agent's template.

Each answer is checked against what it was, the statements counted (bounds generous).

    python3 test/test_hunt_rw6_perf.py
"""
import json
import os
import random
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-rw6-perf-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import acme as E  # noqa: E402
from acmelib import engine as EN  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import jobs, portal as P, renewer, reports, store as S  # noqa: E402
from acmelib.certs import teams as T, fleet as F  # noqa: E402

STORE = E.Storage(E.open_db())
EN.HA_STORE['store'] = STORE
E.sealing_key(make=True)
S.registry()
PEM = None


class Count(object):
    """with Count() as c: c.n statements, c.sql [the statements]."""
    def __enter__(self):
        self.n, self.sql, self.rows = 0, [], 0
        self.orig = STORE.db._run

        def run(sql, args, fetch):
            self.n += 1
            self.sql.append(' '.join(str(sql).split()))
            got = self.orig(sql, args, fetch)
            self.rows += len(got[0] or []) if fetch else 0
            return got
        STORE.db._run = run
        return self

    def __exit__(self, *a):
        STORE.db._run = self.orig

    def like(self, word):
        return sum(1 for s in self.sql if word in s)


def pem():
    global PEM
    if PEM is None:
        from acmelib.certs import pki
        key = pki.make_key('ec-256')
        PEM = pki.self_signed(key, ['x.example'], days=90)
    return PEM


def wipe():
    for t in ('certs', 'cert_deploys', 'cert_targets', 'cert_jobs', 'cert_versions', 'cert_teams',
              'cert_issuers'):
        STORE.db.run('DELETE FROM %s' % t)
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:%' OR k LIKE 'fleet:%' OR "
                 "k LIKE 'agents:%'")
    T.changed()


def seed(n, deploys_each=2, targets=10, pending=0):
    """n certificates, deployments, targets, jobs - fast, as a big installation has them."""
    now = time.time()
    STORE.db.insert('cert_issuers', {'name': 'src', 'kind': 'selfsigned', 'config': '{}',
                                     'state': '{}', 'enabled': 1, 'created': now})
    STORE.db.insert_many('cert_targets', ('name', 'kind', 'config', 'state', 'enabled',
                                          'created'),
                         [('tg%02d' % i, 'local_files', '{}', '{}', 0 if i == 1 else 1, now)
                          for i in range(targets)])
    rows = []
    for i in range(n):
        st = 'pending-approval' if i < pending else 'ok'
        rows.append(('c%04d.example' % i, json.dumps(['c%04d.example' % i]), 'src', 1, st,
                     now - 10 * 86400, now + (60 + i % 200) * 86400, 'team%d' % (i % 3), 1,
                     pem(), json.dumps({'checked': now}), 'FP%04d' % i, 1, now, 'admin'))
    STORE.db.insert_many('certs', ('name', 'names', 'issuer', 'auto_renew', 'state', 'not_before',
                                   'not_after', 'owner', 'version', 'cert_pem', 'ari',
                                   'fingerprint', 'enabled', 'created', 'created_by'), rows)
    ids = [r['id'] for r in STORE.db.rows('SELECT id FROM certs ORDER BY id')]
    deps, js = [], []
    for k, cid in enumerate(ids):
        for j in range(deploys_each):
            deps.append((cid, 'tg%02d' % ((k + j) % targets), '{}', 1, j,
                         'failed' if (k + j) % 7 == 0 else 'ok', 1, now - 3600, now - 3600,
                         now + 3600))
        js.append((now - k, 'renew', cid, 'done', 1, 'scheduler'))
        js.append((now - k + 0.5, 'deploy', cid, 'failed', 0, 'scheduler'))
    STORE.db.insert_many('cert_deploys', ('cert_id', 'target', 'options', 'enabled', 'position',
                                          'state', 'deployed_version', 'created', 'last_try',
                                          'next_try'),
                         deps)
    STORE.db.insert_many('cert_jobs', ('ts', 'kind', 'cert_id', 'state', 'ok', 'by_who'), js)
    return ids


class Indexes(unittest.TestCase):
    def test_csr_from_has_an_index_and_it_is_used(self):
        names = {r['name'] for r in STORE.db.rows("SELECT name FROM sqlite_master WHERE "
                                                  "type = 'index' AND tbl_name = 'certs'")}
        self.assertIn('certs_csr_from', names)
        plan = ' '.join(str(tuple(r)) for r in STORE.db.conn.execute(
            'EXPLAIN QUERY PLAN SELECT name FROM certs WHERE csr_from = ? ORDER BY name',
            ('t',)).fetchall())
        self.assertIn('certs_csr_from', plan)
        # made on an older database too (the schema mechanism: CREATE INDEX IF NOT EXISTS)
        STORE.db.run('DROP INDEX certs_csr_from')
        STORE.db.make_tables()
        self.assertTrue(STORE.db.value("SELECT 1 FROM sqlite_master WHERE name = "
                                       "'certs_csr_from'"))


def old_holders(names, who, exclude, waiting, rows, unowned=False):
    """holders() as it was (every row, every name) - what the new one must answer."""
    me = str(who or '').strip().lower()
    want = [str(n).lower() for n in names or [] if n]
    out = {}
    for rid, owner, state, theirs in rows:
        if exclude is not None and rid == exclude:
            continue
        if not waiting and state == P.WAITING:
            continue
        if owner.lower() == me or (not owner and not unowned):
            continue
        for n in want:
            for t in theirs:
                if P._covers(t, n) or P._covers(n, t) or \
                        (n.startswith('*.') and t.startswith('*.') and n == t):
                    got = out.setdefault(owner, [])
                    if n not in got:
                        got.append(n)
    return out


class Holders(unittest.TestCase):
    def test_the_same_answer_in_the_same_order(self):
        rnd = random.Random(5)
        labels = ['a', 'b', 'www', 'mail', 'x-1', 'Api']
        doms = ['corp.example', 'Example.COM', 'b.example.com', 'test', 'example.com.']

        def name():
            r = rnd.random()
            d = rnd.choice(doms)
            if r < 0.2:
                return '*.' + d
            if r < 0.3:
                return d
            return '%s.%s' % (rnd.choice(labels), d)
        rows = P._HolderRows()
        for i in range(400):
            rows.append((i, rnd.choice(['', 'Web', 'web ', 'Mail', 'ops']).strip(),
                         rnd.choice(['ok', P.WAITING, 'new']),
                         [name().lower() for _ in range(rnd.randint(0, 4))]))
        for _ in range(300):
            want = [name() for _ in range(rnd.randint(1, 4))]
            who = rnd.choice(['web', 'ops', '', 'nobody'])
            ex = rnd.choice([None, rnd.randrange(400)])
            for waiting in (True, False):
                for unowned in (False, True):
                    exp = old_holders(want, who, ex, waiting, rows, unowned)
                    self.assertEqual(list(exp.items()), list(P.holders(
                        STORE, want, who, ex, waiting=waiting, rows=rows,
                        unowned=unowned).items()), (want, who, ex))
                    # a plain list (not read by holder_rows) too
                    self.assertEqual(exp, P.holders(STORE, want, who, ex, waiting=waiting,
                                                    rows=list(rows), unowned=unowned))


    def test_a_list_of_20000_asked_200_times_in_seconds(self):
        wipe()
        now = time.time()
        STORE.db.insert_many('certs', ('name', 'names', 'owner', 'state', 'not_after'), [
            ('h%05d' % i, json.dumps(['h%05d.example' % i, '*.w%05d.example' % i]),
             'team%d' % (i % 9), 'ok', now + 86400) for i in range(20000)])
        rows = P.holder_rows(STORE)
        t = time.time()
        for i in range(200):
            got = P.holders(STORE, ['h%05d.example' % (i * 7), 'a.w%05d.example' % (i * 11)],
                            'someone', rows=rows)
            self.assertEqual(sorted(n for ns in got.values() for n in ns),
                             sorted(['h%05d.example' % (i * 7), 'a.w%05d.example' % (i * 11)]))
        self.assertLess(time.time() - t, 3.0)
        wipe()


class CertList(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        wipe()
        cls.ids = seed(300, pending=4, targets=30)
        # one held, one with its last job tied (same time, the higher id wins)
        S.deploy_hold_set(STORE, {'id': cls.ids[5], 'version': 1}, True, 'admin')
        STORE.db.insert('cert_jobs', {'ts': time.time() - 4 + 0.5, 'kind': 'issue',
                                      'cert_id': cls.ids[4], 'state': 'done', 'ok': 1})

    def expected(self, r):
        cid = r['id']
        v = STORE.db.value
        return {
            'deploys': v('SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ?', (cid,)),
            'deploys_failed': v("SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ? AND state = "
                                "'failed'", (cid,)),
            'deploys_target_off': v('SELECT COUNT(*) FROM cert_deploys d JOIN cert_targets t ON '
                                    't.name = d.target WHERE d.cert_id = ? AND t.enabled = 0',
                                    (cid,)),
            'deploy_hold': S.deploy_hold(STORE, cid) is not None,
            'last_job': (STORE.db.row('SELECT id FROM cert_jobs WHERE cert_id = ? ORDER BY ts '
                                      'DESC, id DESC LIMIT 1', (cid,)) or {}).get('id')}

    def test_a_page_of_300_in_few_statements_with_the_same_numbers(self):
        s = {'name': 'admin', 'role': 'fulladmin', 'account': {'name': 'admin'}}
        with Count() as c:
            got = A.cert_list(STORE, per=1000, s=s)
        self.assertEqual(len(got['rows']), 300)
        self.assertLess(c.n, 40, c.sql[:60])
        for r in got['rows']:
            want = self.expected(r)
            for k in ('deploys', 'deploys_failed', 'deploys_target_off', 'deploy_hold'):
                self.assertEqual(r[k], want[k], (r['name'], k))
            self.assertEqual((r['last_job'] or {}).get('id'), want['last_job'], r['name'])
        self.assertTrue([r for r in got['rows'] if r['deploys_target_off']])
        self.assertTrue([r for r in got['rows'] if r['deploy_hold']])
        self.assertEqual(sum(1 for r in got['rows'] if r['deploy_hold']), 1)
        # as many statements for 300 as for 30
        with Count() as c30:
            A.cert_list(STORE, per=30, s=s)
        self.assertLessEqual(c.n, c30.n + 5)

    def test_targets_list_counts_once(self):
        with Count() as c:
            rows = A.family_rows(STORE, 'target', True)
        self.assertLess(c.n, 20, c.sql)
        for r in rows:
            self.assertEqual(r['used_by'], STORE.db.value(
                'SELECT COUNT(*) FROM cert_deploys WHERE target = ?', (r['name'],)))
            self.assertEqual(r, S.plugin_public(STORE, 'target', S.plugin_row(
                STORE, 'target', r['name']), True))

    def test_deploy_rows_read_each_target_once(self):
        with Count() as c:
            rows = A.deploy_rows(STORE, full=True)
        self.assertEqual(len(rows), 600)
        self.assertLess(c.n, 40, c.sql[:40])
        for r in rows[:50]:
            self.assertEqual(r['target_off'], r['target'] == 'tg01')
        one = S.deploy_public(STORE, STORE.db.row('SELECT d.* FROM cert_deploys d WHERE '
                                                  "target = 'tg01' LIMIT 1"), True)
        self.assertTrue(one['target_off'])


class Scan(unittest.TestCase):
    def setUp(self):
        wipe()
        self.subs = []
        self.orig = (jobs.submit, reports.tick)
        jobs.submit = lambda store, kind, fn, **kw: self.subs.append((kind, kw.get('cert_id')))
        reports.tick = lambda store, *a, **k: None

    def tearDown(self):
        jobs.submit, reports.tick = self.orig

    def look(self):
        del self.subs[:]
        with Count() as c:
            renewer.scan(STORE)
        return c

    def test_statements_do_not_grow_with_the_certificates(self):
        ids = seed(40)
        small = self.look().n
        wipe()
        ids = seed(400)
        # nothing due, nothing to deploy: as many statements as for 40
        c = self.look()
        self.assertLess(c.n, small + 40, (small, c.n))
        self.assertEqual(c.like('SELECT * FROM certs WHERE id = ?'), 0)
        self.assertEqual(c.like('FROM cert_versions WHERE cert_id = ?'), 0)
        self.assertEqual(self.subs, [])
        # the certificates themselves (their PEMs, keys) not read by the look
        first = [q for q in c.sql if 'FROM certs WHERE COALESCE(enabled, 1)' in q][0]
        got = STORE.db.rows(first)
        self.assertEqual(len(got), 400)
        self.assertEqual({r['cert_pem'] for r in got}, {'x'})       # whether there is one
        self.assertEqual({r['key_sealed'] for r in got}, {None})
        # a new version of each: every one's deployments put on, a job each
        STORE.db.run('UPDATE certs SET version = 2')
        STORE.db.run("UPDATE cert_deploys SET state = 'ok'")
        STORE.db.run('UPDATE cert_targets SET enabled = 1')
        self.look()
        deployed = {cid for kind, cid in self.subs if kind == 'deploy'}
        self.assertEqual(deployed, set(ids))
        # one due by its end: renewed
        STORE.db.run('UPDATE certs SET not_after = ? WHERE id = ?', (time.time() + 86400, ids[9]))
        self.look()
        self.assertIn(('renew', ids[9]), self.subs)

    def test_revoked_and_held_are_still_passed_over(self):
        ids = seed(30)
        STORE.db.run('UPDATE certs SET version = 2')
        # one holds a version revoked at the CA, one has revoked fingerprints written in meta,
        # one is held (a newer version waits for Deploy now)
        STORE.db.insert('cert_versions', {'cert_id': ids[0], 'version': 2, 'fingerprint': 'fp0000',
                                          'revoked': time.time()})
        S.revoked_keys_add(STORE, ids[1], fps=['FP0001'])
        S.deploy_hold_set(STORE, {'id': ids[2], 'version': 1}, True, 'admin')
        # ...and one whose revoked version is not the one it holds now
        STORE.db.insert('cert_versions', {'cert_id': ids[3], 'version': 1, 'fingerprint': 'old',
                                          'revoked': time.time()})
        self.look()
        deployed = {cid for kind, cid in self.subs if kind == 'deploy'}
        self.assertNotIn(ids[0], deployed)
        self.assertNotIn(ids[1], deployed)
        self.assertNotIn(ids[2], deployed)
        self.assertIn(ids[3], deployed)
        self.assertEqual(len(deployed), 27)

    def test_ari_asked_when_due_only(self):
        ids = seed(20)
        asked = []
        orig = renewer.ari_refresh
        renewer.ari_refresh = lambda store, row, variant='': asked.append(row['id'])
        try:
            STORE.db.run('UPDATE certs SET ari = ? WHERE id = ?',
                         (json.dumps({'checked': time.time() - 7 * 3600}), ids[7]))
            STORE.db.run("UPDATE certs SET ari = '' WHERE id = ?", (ids[8],))
            self.look()
        finally:
            renewer.ari_refresh = orig
        self.assertEqual(sorted(asked), sorted([ids[7], ids[8]]))

    def test_alerts_same_and_bounded(self):
        ids = seed(200)
        STORE.db.insert('cert_versions', {'cert_id': ids[0], 'version': 1, 'fingerprint': 'fp0000',
                                          'revoked': time.time()})
        with Count() as c:
            got = renewer.alerts(STORE)
        self.assertLess(c.n, 20, c.sql[:30])
        keys = {a['key'] for a in got}
        for d in STORE.db.rows("SELECT id, cert_id, target FROM cert_deploys WHERE state = "
                               "'failed'"):
            # (not to a target switched off: tg01)
            self.assertEqual('cert-deploy:%s' % d['id'] in keys,
                             d['cert_id'] != ids[0] and d['target'] != 'tg01')


class Teams(unittest.TestCase):
    def test_team_by_name_in_one_statement_any_case(self):
        wipe()
        for i in range(50):
            STORE.db.insert('cert_teams', {'name': 'Team %d' % i, 'kind': 'team',
                                           'members': '[]', 'created': time.time()})
        with Count() as c:
            got = T.team_get(STORE, 'Team 7')
        self.assertEqual(got['name'], 'Team 7')
        self.assertEqual(c.n, 1)
        self.assertEqual(c.rows, 1)             # not every team read for it
        self.assertEqual(T.team_get(STORE, ' team 7 ')['name'], 'Team 7')
        self.assertEqual(T.team_get(STORE, 'TEAM 49')['name'], 'Team 49')
        self.assertIsNone(T.team_get(STORE, 'Team 50'))
        self.assertIsNone(T.team_get(STORE, ''))


class Fleet(unittest.TestCase):
    def test_groups_read_once_for_the_view(self):
        wipe()
        now = time.time()
        STORE.db.insert_many('cert_targets', ('name', 'kind', 'config', 'state', 'enabled',
                                              'created'),
                             [('ag%02d' % i, 'agent', '{}', '{}', 1, now) for i in range(30)])
        with Count() as c:
            v = F.view(STORE)
        self.assertEqual(len(v['agents']), 30)
        self.assertLessEqual(c.like("LIKE ? ORDER BY k"), 3, c.sql[:20])


if __name__ == '__main__':
    unittest.main()
