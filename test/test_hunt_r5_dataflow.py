#!/usr/bin/env python3
"""Hunt R run 5, area "dataflow": export/import, owners, the renewer's words.

    python3 test/test_hunt_r5_dataflow.py
"""
import calendar
import json
import os
import sys
import tempfile
import time
import unittest
import unittest.mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-r5df-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import agents, runplan  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
E.load_config()
DAEMON = E.Daemon(STORE, serve=False)


def _next(cert):
    with unittest.mock.patch('acmelib.certs.notices.recipients', return_value=[]):
        ph = runplan.after_phase(None, cert, None, [])
    return [s for s in ph['steps'] if s['words'].startswith('Next renewal: ')]


class HuntR5Dataflow(unittest.TestCase):
    def test_failed_certificate_next_renewal_is_its_next_try(self):
        """A certificate whose renewal failed is tried again at next_try (renewer.main_due):
        What happens said the end of its renew window - weeks away - instead."""
        t = time.time()
        cert = {'id': 1, 'auto_renew': 1, 'renew_days': 30, 'state': 'failed',
                'not_before': t - 80 * 86400, 'not_after': t + 10 * 86400,
                'next_try': t + 3 * 3600}
        nxt = _next(cert)
        self.assertEqual(len(nxt), 1)
        at = calendar.timegm(time.strptime(nxt[0]['words'][len('Next renewal: '):],
                                           '%Y-%m-%d %H:%M UTC'))
        self.assertLess(abs(at - cert['next_try']), 120)
        self.assertIn('failed', nxt[0]['note'])
        # one never issued, failed: not "at the next look (within minutes)"
        cert = {'id': 2, 'auto_renew': 1, 'state': 'failed', 'next_try': t + 7200}
        nxt = _next(cert)
        self.assertEqual(len(nxt), 1)
        # one made due for a new issue: at the next look, not at the end of its window
        cert = {'id': 3, 'auto_renew': 1, 'renew_days': 30, 'state': 'due',
                'not_before': t - 10 * 86400, 'not_after': t + 80 * 86400}
        at = calendar.timegm(time.strptime(_next(cert)[0]['words'][len('Next renewal: '):],
                                           '%Y-%m-%d %H:%M UTC'))
        self.assertLess(abs(at - t), 120)
        # an ok one: as before
        cert = dict(cert, state='ok')
        at = calendar.timegm(time.strptime(_next(cert)[0]['words'][len('Next renewal: '):],
                                           '%Y-%m-%d %H:%M UTC'))
        self.assertLess(abs(at - (t + 50 * 86400)), 120)

    def test_replace_import_lets_the_agent_of_a_target_taken_away_go(self):
        """A configuration imported "replacing all" took a target of an agent away, but its
        agent stayed let in (agents:id / agents:t) - and a target put in later under the same
        number took that agent over."""
        tid = STORE.db.insert('cert_targets', {'name': 'win-old', 'kind': 'agent_windows',
                                               'enabled': 1, 'created': time.time(),
                                               'config': json.dumps({'mode': 'active'})})
        keep = STORE.db.insert('cert_targets', {'name': 'kept', 'kind': 'agent',
                                                'enabled': 1, 'created': time.time(),
                                                'config': json.dumps({'mode': 'active'})})
        for one, aid in ((tid, 'ag-0123456789ab'), (keep, 'ag-ba9876543210')):
            agents.state_put(STORE, one, {'agent_id': aid, 'cert_fp': 'fp-' + aid})
            STORE.set_meta(agents.M_ID(aid), str(one))
        conf = json.loads(json.dumps(E.config_export(STORE, False)))
        conf['tables']['cert_targets'] = [r for r in conf['tables']['cert_targets']
                                          if r['name'] != 'win-old']
        E.config_import(STORE, DAEMON, {'tables': conf['tables']}, 'tester', replace=True)
        self.assertIsNone(STORE.db.row('SELECT id FROM cert_targets WHERE id = ?', (tid,)))
        self.assertIsNone(STORE.get_meta(agents.M_ID('ag-0123456789ab')))
        self.assertIsNone(STORE.get_meta(agents.M_T(tid)))
        # the one in the file keeps its agent
        self.assertEqual(STORE.get_meta(agents.M_ID('ag-ba9876543210')), str(keep))
        self.assertEqual(agents.state(STORE, keep).get('agent_id'), 'ag-ba9876543210')


if __name__ == '__main__':
    unittest.main()
