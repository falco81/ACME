#!/usr/bin/env python3
"""A report of the tests run (1.0.73, acmelib/certs/checkreport.py).

    python3 test/test_check_report.py

The results grouped by certificate in a mail (HTML and text), the subject saying how many are
fine, warned and failed; one SMS line naming the failing; the addresses and numbers checked;
a mail that cannot go said, never raised.
"""
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-check-report-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import checkreport as R  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


class ReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.family_save(STORE, 'issuer', {'name': 'Own SS', 'kind': 'selfsigned', 'config': {}}, 'tester')
        cid = A.cert_save(STORE, {'name': 'shop.example.test', 'names': ['shop.example.test'],
                                  'issuer': 'Own SS'}, 'tester')
        cls.ids = []
        for test, st, said in (('web', 'ok', 'serves it'), ('smtp', 'unreachable', 'cannot be reached: refused'),
                               ('imap', 'warn', 'no intermediate <b>')):
            cls.ids.append(STORE.db.insert('cert_checks', {
                'cert_id': cid, 'test': test, 'enabled': 1, 'position': 0, 'last_state': st,
                'last_said': said, 'last_at': time.time()}))

    def test_mail(self):
        subject, page, text = R.build(STORE, self.ids, 'every test', 'en')
        self.assertIn('1 fine, 1 with a warning, 1 failed', subject)
        self.assertIn('shop.example.test', page)
        self.assertIn('not reached', page)
        self.assertIn('no intermediate &lt;b&gt;', page)          # escaped
        self.assertIn('- smtp', text)
        _s, page_cs, _t = R.build(STORE, self.ids, 'every test', 'cs')
        self.assertIn('nedostupné', page_cs)

    def test_sms_and_inputs(self):
        line = R.sms_line(STORE, self.ids, 'en')
        self.assertIn('1 failed', line)
        self.assertIn('shop.example.test/smtp', line)
        self.assertEqual(R.addresses('a@x.cz, b@y.cz'), ['a@x.cz', 'b@y.cz'])
        with self.assertRaises(ValueError):
            R.addresses('nope')
        self.assertEqual(R.phones('+420 600 111 222'), ['+420600111222'])
        with self.assertRaises(ValueError):
            R.phones('call me')

    def test_cannot_go_is_said(self):
        steps = []
        said = R.send(STORE, self.ids, 'every test', ['a@x.cz'], [], 'tester',
                      lambda w, lv: steps.append((w, lv)))
        self.assertIn('did not go', said)
        self.assertEqual(steps[0][1], 'warn')


if __name__ == '__main__':
    unittest.main()
