#!/usr/bin/env python3
"""Hunt R (run u1), FortiGate: regressions.

    python3 test/test_hunt_ru1_fortigate.py

- What happens (runplan) of "Replace an existing certificate in place" for a certificate whose
  name starts with acme- (an earlier import of the default mode, chosen to be replaced - the
  case of the 1.0.128 report): the canned FortiGate said 404 for it, so the dry run said
  "there is no local certificate" while the real run replaces it. The default mode's own new
  name is still not there (imported).
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

SSH = {'ssh_user': 'acme-admin', 'ssh_auth': 'password', 'ssh_password': 'SSH-pw-0002'}


class DryRunAcmeNameTest(unittest.TestCase):
    def record(self, opts, version='', ssh=False):
        from acmelib.certs import runplan as R
        cfg = dict({'host': 'fw', 'token': 't', 'vdom': 'root', '_version': version},
                   **(SSH if ssh else {}))
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': 'fortigate', 'name': 't', 'op': 'deploy',
            'config': cfg, 'options': opts, 'seconds': 30,
            'answers': R.answers_of('fortigate', cfg, opts, version=version),
            'ssh_answers': R.ssh_answers_of('fortigate', cfg, opts, version=version)}],
            'cert': {'names': ['www.example.com'], 'key_type': 'ec-256'}}, timeout=120)
        self.assertEqual(err, '')
        return got['r1']

    @staticmethod
    def says(r):
        return [e.get('words') for e in r['events'] if e['kind'] in ('say', 'step')]

    @staticmethod
    def http(r):
        return [(e['method'], e['url'].split('?')[0]) for e in r['events']
                if e['kind'] == 'http']

    def test_replace_an_acme_named_certificate(self):
        name = 'acme-acmetest.example.com'
        for ver in ('', '7.4.2'):
            r = self.record({'mode': 'replace', 'replace_name': name}, ver)
            self.assertFalse(r.get('error'), r.get('error'))
            says = self.says(r)
            self.assertFalse([w for w in says if 'there is no local certificate' in w], says)
            self.assertIn('%s replaced in place - its name and every use of it kept' % name,
                          says)
            self.assertIn(('PUT', 'https://fw/api/v2/cmdb/vpn.certificate/local/' + name),
                          self.http(r))
            self.assertTrue([w for w in says if w.startswith(
                'checked: %s holds the new certificate now' % name)], says)

    def test_replace_an_acme_named_certificate_over_ssh(self):
        name = 'acme-acmetest.example.com'
        r = self.record({'mode': 'replace', 'replace_name': name, 'replace_via': 'ssh'},
                        ssh=True)
        self.assertFalse(r.get('error'), r.get('error'))
        self.assertIn('%s replaced in place - its name and every use of it kept' % name,
                      self.says(r))

    def test_default_mode_still_imports_its_new_name(self):
        r = self.record({})
        self.assertFalse(r.get('error'), r.get('error'))
        http = self.http(r)
        self.assertIn(('POST', 'https://fw/api/v2/monitor/vpn-certificate/local/import'), http)
        self.assertFalse([h for h in http if h[0] == 'PUT' and 'vpn.certificate/local' in h[1]])
        self.assertFalse([w for w in self.says(r) if 'is there already' in w])


if __name__ == '__main__':
    unittest.main(verbosity=2)
