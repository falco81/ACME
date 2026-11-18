#!/usr/bin/env python3
"""Hunt R t1, AD CS sources (ms_adcs_agent / the agent's op adcs / ms_adcs_rpc): regressions.

    python3 test/test_hunt_rt1_adcs.py

- A template name with a space ("Web Server 2") written into the agent's policy (allow adcs,
  the line the refusal names, acme-agent adcs cas, acme --target-agent adcs-templates) unquoted:
  the policy's own line read back was refused and the CA's line lost.
- The agent's script said an HRESULT sign-extended (0xffffffff80094012: PowerShell reads
  0xffffffff as the Int32 -1): no word of the CA's codes matched it.
- CR_PROP_TEMPLATES: a template of schema 1 has an empty OID line - empty lines were dropped
  before the name/OID pairing, so every other template was lost.
- ms_adcs_rpc: a template with a line break added attributes of its own (SAN:...) (security);
  an IPv6 address given as a domain controller without brackets was split into host and port.
"""
import contextlib
import io
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_ms_adcs_agent as T  # noqa: E402

from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.issuers import ms_adcs_rpc as M  # noqa: E402

AG, W, CA = T.AG, T.W, T.CA


class PolicySpaces(unittest.TestCase):
    def test_round_trip(self):
        pol = AG.parse_policy('allow adcs "%s" template="Web Server 2,WebServer"\n' % CA)
        self.assertEqual(pol['problems'], [])
        self.assertEqual(pol['adcs'][0]['templates'], ['Web Server 2', 'WebServer'])
        lines = AG.policy_lines(pol)
        self.assertIn('allow adcs "%s" template="Web Server 2,WebServer"' % CA, lines)
        again = AG.parse_policy('\n'.join(lines))
        self.assertEqual(again['problems'], [])
        self.assertEqual(again['adcs'], pol['adcs'])

    def test_simple_names_unchanged(self):
        self.assertEqual(W.adcs_line({'ca': CA, 'templates': ['WebServer', 'Web-2']}),
                         'adcs "%s" template=WebServer,Web-2' % CA)
        self.assertEqual(W.adcs_line({'ca': CA, 'templates': ['*']}), 'adcs "%s" template=*' % CA)

    def test_needs_line_reads_back(self):
        needs = W.adcs_needs(AG.parse_policy(''), {'action': 'submit', 'ca': CA,
                                                   'template': 'Web Server'})
        line = needs[0]['allow'].replace('acme-agent ', '', 1)
        pol = AG.parse_policy(line)
        self.assertEqual(pol['problems'], [])
        self.assertEqual(pol['adcs'], [{'ca': CA, 'templates': ['Web Server']}])

    def test_cli_allow_spaces(self):
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
        try:
            if os.path.exists(AG.POLICY):
                os.unlink(AG.POLICY)
            with contextlib.redirect_stdout(io.StringIO()):
                AG.main(['allow', 'adcs', CA, 'template=Web Server'])
                AG.main(['allow', 'adcs', CA, 'template=Other'])
            with open(AG.POLICY) as fh:
                text = fh.read()
            got = [x for x in text.splitlines() if x.startswith('allow adcs')]
            self.assertEqual(got, ['allow adcs "%s" template="Web Server,Other"' % CA])
            self.assertEqual(AG.parse_policy(text)['adcs'],
                             [{'ca': CA, 'templates': ['Web Server', 'Other']}])
        finally:
            os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
            if os.path.exists(AG.POLICY):
                os.unlink(AG.POLICY)


class Codes(unittest.TestCase):
    def test_sign_extended_code(self):
        for v in ('0xffffffff80094012', '-2146877422', '0x80094012', '0X80094012'):
            self.assertEqual(W.adcs_code(v), '0x80094012', v)
        self.assertEqual(W.adcs_code(None), '')
        said = W.adcs_said({'disposition': 2, 'status': '0xffffffff80094012',
                            'message': 'Denied by Policy Module'})
        self.assertIn('may not enroll for this template', said)
        self.assertIn('0x80094012', said)

    def test_script_masks_64_bits(self):
        self.assertIn('-band 0xffffffffL)', W.ADCS_PS)
        self.assertNotIn('-band 0xffffffff)', W.ADCS_PS)

    def test_templates_not_filtered_before_pairing(self):
        self.assertNotIn("ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })", W.ADCS_PS)

    def test_denied_code_through_the_source(self):
        class CA2(T.FakeCA):
            def _answer(self, rid):
                out = T.FakeCA._answer(self, rid)
                if out.get('disposition') == 2:
                    out['status'] = '0xffffffff80094012'
                return out
        ps, W.powershell = W.powershell, CA2()
        pl = AG.policy_load
        AG.policy_load = lambda: (AG.parse_policy(T.POLICY), 'h', T.POLICY)
        try:
            src = T.source(T.Ctx(AG), template='Denied')
            with self.assertRaises(PluginError) as e:
                src.issue(T.new_req())
            self.assertIn('may not enroll for this template', str(e.exception))
        finally:
            W.powershell = ps
            AG.policy_load = pl


class Rpc(unittest.TestCase):
    def issuer(self, **cfg):
        c = {'host': 'ca01.example.local', 'ca_name': 'EXAMPLE-CA', 'template': 'WebServer',
             'user': 'svc', 'password': 'pw'}
        c.update(cfg)
        return M.MsAdcsRpcIssuer(c, T.Ctx(AG))

    def test_template_line_break_refused(self):
        iss = self.issuer()
        req = T.new_req()
        req.profile = {'template': 'WebServer\nSAN:dns=evil.example'}
        with self.assertRaises(PluginError) as e:
            iss._template(req)
        self.assertFalse(e.exception.retry)
        req.profile = {'template': 'Web Server 2'}
        self.assertEqual(iss._template(req), 'Web Server 2')

    def test_kdc_ipv6(self):
        iss = self.issuer(kdc='2001:db8::10, [2001:db8::11]:8888, dc01.example.local:88, '
                              '10.0.0.5')
        self.assertEqual(iss._kdcs(), [('2001:db8::10', 88), ('2001:db8::11', 8888),
                                       ('dc01.example.local', 88), ('10.0.0.5', 88)])


if __name__ == '__main__':
    unittest.main()
