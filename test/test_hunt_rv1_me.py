"""Hunt v1 (1.0.140), fixes of my own: a team renamed - its periodic reports and their runs follow.

    python3 test/test_hunt_rv1_me.py
"""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class FakeDb:
    def __init__(self):
        self.t = {'cert_reports': [{'id': 1, 'teams': json.dumps(['Web', 'Mail'])},
                                   {'id': 2, 'teams': '[]'}],
                  'cert_report_runs': [{'id': 7, 'teams': json.dumps(['web'])},
                                       {'id': 8, 'teams': None}]}

    def rows(self, sql, args=()):
        return [dict(r) for r in self.t[sql.split('FROM ')[1].strip()]]

    def run(self, sql, args=()):
        table = sql.split('UPDATE ')[1].split(' ')[0]
        for r in self.t[table]:
            if r['id'] == args[1]:
                r['teams'] = args[0]
        return 1


class Rename(unittest.TestCase):
    def test_reports_follow(self):
        from acmelib.certs import reports as R

        class St:
            db = FakeDb()
        R.follow_rename(St, 'WEB', 'Websites')
        t = St.db.t
        self.assertEqual(json.loads(t['cert_reports'][0]['teams']), ['Websites', 'Mail'])
        self.assertEqual(t['cert_reports'][1]['teams'], '[]')
        self.assertEqual(json.loads(t['cert_report_runs'][0]['teams']), ['Websites'])
        self.assertIsNone(t['cert_report_runs'][1]['teams'])

    def test_called_by_teams(self):
        with open(os.path.join(ROOT, 'acmelib/certs/teams.py'), encoding='utf-8') as f:
            self.assertIn('_reports.follow_rename(store, old_name, name)', f.read())


class Uninstall(unittest.TestCase):
    """install.sh --uninstall without --purge (1.0.141): the keys go, so the files that said the
    agent had joined go too; the policy stays."""
    def test_identity_files_go(self):
        with open(os.path.join(ROOT, 'deploy/agent/install.sh')) as f:
            sh = f.read()
        block = sh.split('if [[ -n "$PURGE" ]]; then', 1)[1].split('exit 0', 1)[0]
        keep = block.split('else', 1)[1]
        self.assertIn('rm -f /etc/acme-agent/agent.json /etc/acme-agent/ca.pem', keep)
        self.assertNotIn('/etc/acme-agent/policy', keep)


class ActivityMasked(unittest.TestCase):
    def test_digest_addresses_masked(self):
        from acmelib.certs import digest as D
        rows = [{'words': 'the team Web: the digest was sent to a@x.test, b.c@y.test'},
                {'words': 'the team Web: contact mail set to web@x.test'}]
        got = D.activity_masked([dict(r) for r in rows])
        self.assertEqual(got[0]['words'], 'the team Web: the digest was sent to …, …')
        self.assertEqual(got[1]['words'], rows[1]['words'])
        for p, needle in (('acmelib/certs/api_teams.py', '_digest.activity_masked(rows)'),
                          ('acmelib/certs/portal_teams.py', '_digest.activity_masked(rows)')):
            with open(os.path.join(ROOT, p), encoding='utf-8') as f:
                self.assertIn(needle, f.read())


class HaproxyRuntime(unittest.TestCase):
    def test_separator_refused(self):
        from acmelib.plugins.targets import haproxy
        from acmelib.plugins.base import PluginError
        cls = [v for v in vars(haproxy).values() if isinstance(v, type) and hasattr(v, 'runtime')][0]
        obj = cls.__new__(cls)
        obj.sh = lambda *a, **k: (0, 'Success!', '')
        obj.sock = lambda: '/run/haproxy.sock'
        obj.c = lambda k: ''
        for bad in ('add ssl crt-list /x.txt /a.pem;shutdown frontend fe', 'set ssl cert /a\nshow info'):
            with self.assertRaises(PluginError):
                obj.runtime(None, bad)
        self.assertEqual(obj.runtime(None, 'show ssl cert /a.pem')[0], 0)


class TeamsVersionPerRequest(unittest.TestCase):
    """1.0.144: within one request the teams' version is read once - again after a write."""
    def test_memo(self):
        from acmelib.certs import teams as T
        asked = []

        class Db:
            writes = 0

            def row(self, sql, args=()):
                asked.append(sql)
                return {'tn': 1}
        class St:
            db = Db()
        T._REQ.on = False
        T._version(St)
        T._version(St)
        self.assertEqual(len(asked), 2)            # outside a request: every time
        T.request_begin()
        T._version(St)
        T._version(St)
        self.assertEqual(len(asked), 3)            # once in a request
        St.db.writes += 1
        T._version(St)
        self.assertEqual(len(asked), 4)            # again after a write
        T.request_begin()
        T._version(St)
        self.assertEqual(len(asked), 5)            # again in the next request
        T._REQ.on = False


if __name__ == '__main__':
    unittest.main()
