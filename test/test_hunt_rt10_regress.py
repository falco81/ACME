#!/usr/bin/env python3
"""Hunt t10, a regression review of the fixes since 1.0.126.

    python3 test/test_hunt_rt10_regress.py

  * the Windows agent's Find-Binding (hunt t9) compared the whole IP:PORT:HOST - with no address
    in the IIS line (the server sends '*' then) a binding on 10.0.0.5:443 was no longer found
    (before t9 it was): a second binding was made on *:443 beside it, and 10.0.0.5 kept its old
    certificate. Now '*' takes the binding of that host and port on any address, the *: first,
    as windows_ssh does;
  * windows_ssh's look-up without an address compared the host name with its case: a line
    "Site | www.Example.test" missed the binding www.example.test and New-WebBinding then
    refused the duplicate - the deployment failed. Now compared in lower case, both sides.
"""
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


def find_binding_model(infos, ip, port, host):
    """Find-Binding of the agent's PRELUDE as Python (as it is after the fix)."""
    ip = ip or '*'
    tail = ':%d:%s' % (port, host or '')
    if ip == '*':
        hits = [i for i in infos if i.lower().endswith(tail.lower())]
        hits.sort(key=lambda i: not i.startswith('*:'))
        return hits[0] if hits else None
    want = [(ip + tail).lower(), ('[' + ip + ']' + tail).lower()]
    return next((i for i in infos if i.lower() in want), None)


class AgentFindBinding(unittest.TestCase):
    def fb(self):
        src = read('deploy', 'agent', 'acme_agent_wincert.py')
        fb = src[src.index('function Find-Binding'):]
        return fb[:fb.index('\n}\n')]

    def test_star_takes_any_address(self):
        fb = self.fb()
        star = fb[fb.index("if ($ip -eq '*')"):]
        self.assertIn('.ToLower().EndsWith($t)', star)
        self.assertIn("StartsWith('*:')", star)
        # an address said: still exactly that binding (t9)
        self.assertIn('$want -contains [string]$_.bindingInformation', fb)

    def test_model(self):
        only_ip = ['10.0.0.5:443:', '10.0.0.5:443:www.other.test']
        self.assertEqual(find_binding_model(only_ip, '*', 443, ''), '10.0.0.5:443:')
        both = ['10.0.0.5:443:www.example.test', '*:443:www.example.test']
        self.assertEqual(find_binding_model(both, '*', 443, 'www.example.test'),
                         '*:443:www.example.test')
        self.assertEqual(find_binding_model(both, '10.0.0.5', 443, 'www.example.test'),
                         '10.0.0.5:443:www.example.test')
        self.assertIsNone(find_binding_model(['*:8443:www.example.test'], '*', 443,
                                             'www.example.test'))
        self.assertIsNone(find_binding_model(['*:443:a.www.example.test'], '*', 443,
                                             'www.example.test'))
        self.assertEqual(find_binding_model(['*:443:WWW.Example.TEST'], '*', 443,
                                            'www.example.test'), '*:443:WWW.Example.TEST')
        # t9's own cases
        infos = ['*:443:', '*:443:www.other.test', '10.0.0.5:443:', '[2001:db8::1]:443:']
        self.assertEqual(find_binding_model(infos, '*', 443, ''), '*:443:')
        self.assertEqual(find_binding_model(infos, '2001:db8::1', 443, ''), '[2001:db8::1]:443:')
        self.assertIsNone(find_binding_model(infos, '10.0.0.6', 443, ''))


class WinSshHostCase(unittest.TestCase):
    def test_script(self):
        from test_agent_windows_parity import FakeB
        from acmelib.plugins.targets import windows_ssh as WS
        t = WS.WindowsSshTarget.__new__(WS.WindowsSshTarget)
        sc = WS.WindowsSshTarget.script(t, FakeB(), {'iis': 'Default Web Site | www.Example.test'},
                                        'C:/x.pfx', 'pw')
        self.assertIn(".ToLower().EndsWith(':443:www.example.test')", sc)
        # the binding made keeps the host as written
        self.assertIn("-HostHeader 'www.Example.test'", sc)
        # an address said: compared whole (-contains takes any case)
        sc = WS.WindowsSshTarget.script(t, FakeB(), {'iis': 'S | www.example.test | 443 | 10.0.0.5'},
                                        'C:/x.pfx', 'pw')
        self.assertIn("@('10.0.0.5:443:www.example.test', '[10.0.0.5]:443:www.example.test') "
                      "-contains", sc)
        self.assertFalse(re.search(r"EndsWith\('[^']*[A-Z]", sc))


if __name__ == '__main__':
    unittest.main(verbosity=1)
