# -*- coding: utf-8 -*-
"""A database made by an older acme gets every column a later one declares
(1.0.23: a column declared last before a table's UNIQUE (...) was never added -
cert_ca_issued.cert_pem)."""
import os
import sqlite3
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class Upgrade(unittest.TestCase):
    def test_columns_added_before_a_constraint(self):
        tmp = tempfile.mkdtemp(prefix='acme-schema-')
        os.environ['ACME_STATE'] = tmp
        path = os.path.join(tmp, 'acme.db')
        # cert_ca_issued as an earlier version made it: no cert_pem
        c = sqlite3.connect(path)
        c.execute('CREATE TABLE cert_ca_issued (id INTEGER PRIMARY KEY AUTOINCREMENT, ca_id INTEGER '
                  'NOT NULL, serial TEXT NOT NULL, subject_dn TEXT, names TEXT, not_before REAL, '
                  'not_after REAL, fingerprint TEXT, cert_id INTEGER, revoked REAL, reason TEXT, '
                  'created REAL, by_who TEXT, UNIQUE (ca_id, serial))')
        c.commit()
        c.close()
        import acmelib.engine as E
        E.load_config()
        db = E.open_db()
        db.add_missing_columns()
        cols = [r['name'] for r in db.rows('PRAGMA table_info(cert_ca_issued)')]
        self.assertIn('cert_pem', cols)


if __name__ == '__main__':
    unittest.main(verbosity=2)
