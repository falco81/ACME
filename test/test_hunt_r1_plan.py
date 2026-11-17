#!/usr/bin/env python3
"""Hunt R run 1, area "plan": What happens said what the real run does.

    python3 test/test_hunt_r1_plan.py
"""
import json
import os
import sys
import time
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from acmelib.certs import pki, renewer, runplan  # noqa: E402
from acmelib.certs import store as S  # noqa: E402


class HuntR1Plan(unittest.TestCase):
    def test_generated_password_is_kept_not_new_each_time(self):
        """pfx_password_mode 'generate': one password made once and kept sealed with the
        deployment (deployer.generated_password) - not a new one at every deployment."""
        ev = {'op': 'deploy', 'target': 'srv', 'mode': 'passive', 'host': 'h', 'port': 8446,
              'platform': 'linux', 'policy_known': True, 'skip_same': True,
              'meta': {'password': 'generate', 'alias': 'a1'},
              'items': [{'what': 'file', 'path': '/etc/a.pfx', 'format': 'pfx', 'mode': '0600',
                         'ok': True, 'allow': ''}]}
        text = json.dumps(runplan._agent_steps(ev), ensure_ascii=False)
        self.assertNotIn('new password each time', text)
        self.assertIn('protected by a password acme made, kept sealed with the deployment', text)

    def test_next_renewal_of_a_short_lived_certificate(self):
        """A 6-day certificate with 30 renew days is renewed a third of its life before its
        end (renewer.renew_window), not at once."""
        t = time.time()
        cert = {'auto_renew': 1, 'renew_days': 30, 'not_before': t, 'not_after': t + 6 * 86400}
        with unittest.mock.patch('acmelib.certs.notices.recipients', return_value=[]):
            ph = runplan.after_phase(None, cert, None, [])
        nxt = [s for s in ph['steps'] if s['words'].startswith('Next renewal: ')][0]
        when = time.strptime(nxt['words'][len('Next renewal: '):], '%Y-%m-%d %H:%M UTC')
        import calendar
        at = calendar.timegm(when)
        want = cert['not_after'] - renewer.renew_window(cert, cert['not_after'], t)
        self.assertLess(abs(at - want), 120)
        self.assertGreater(at, t + 3 * 86400)
        self.assertIn('a third of its life', nxt['note'])
        # a long-lived one: its renew days, as before
        cert = {'auto_renew': 1, 'renew_days': 30, 'not_before': t, 'not_after': t + 90 * 86400}
        with unittest.mock.patch('acmelib.certs.notices.recipients', return_value=[]):
            ph = runplan.after_phase(None, cert, None, [])
        nxt = [s for s in ph['steps'] if s['words'].startswith('Next renewal: ')][0]
        self.assertEqual(nxt['note'], '30 days before the end, or sooner in the window its CA '
                                      'suggests (ARI)')

    def test_kept_key_of_another_type_is_not_kept(self):
        """Keep the key, the key type changed: the renewal makes a new key of the type asked
        (renewer, 1.0.48) - What happens said the key it has is kept."""
        key = pki.make_key('ec-256')
        cert = {'id': 1, 'names': ['a.example.com'], 'key_type': 'ec-384', 'reuse_key': 1,
                'key_sealed': 'sealed:x', 'state': 'ok'}
        with unittest.mock.patch.object(S, 'cert_key', return_value=key):
            ph = runplan.key_phase(cert, {}, None, None)
            self.assertEqual(ph['steps'][0]['words'], 'A new ec-384 key is made here, on this '
                                                      'machine')
            self.assertIn('ec-256', ph['steps'][0]['note'])
            self.assertNotIn('PRIVATE', json.dumps(ph))
            cert['key_type'] = 'ec-256'
            ph = runplan.key_phase(cert, {}, None, None)
            self.assertEqual(ph['steps'][0]['words'], 'The ec-256 key it has is kept (sealed in '
                                                      'acme\'s database)')


if __name__ == '__main__':
    unittest.main()
