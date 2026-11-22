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


if __name__ == '__main__':
    unittest.main()
