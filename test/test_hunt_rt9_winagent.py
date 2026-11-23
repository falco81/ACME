#!/usr/bin/env python3
"""Hunt t9, the Windows agent (deploy/agent/acme_agent_wincert.py, the server's
acmelib/plugins/targets/agent_windows.py) - regressions, on Linux with the FakeWin facade
(ACME_AGENT_FAKE_WINDOWS=1) and PowerShell faked (wincert.powershell).

    python3 test/test_hunt_rt9_winagent.py

  * Find-Binding looked an https binding up by site, port and host only - Get-WebBinding takes an
    empty -HostHeader as any host and the address was never asked: a binding on 10.0.0.5:443
    took the certificate of *:443 (or of www.other:443), and the undo removed by port and host;
  * the "allow" lines (typed in an elevated PowerShell) put a name with $ into "...": PowerShell
    expanded it ("Shop $live" -> "Shop ") and the policy got another name;
  * discovery read only LocalMachine\\My: an IIS binding on a certificate of the Web Hosting
    store, and the Remote Desktop listener's own (self-signed) certificate in the Remote Desktop
    store were said "not in the machine store" (missing).
"""
import importlib.util
import json
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
AGENT = os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py')
TMP = tempfile.mkdtemp(prefix='acme-hunt-t9w-')


def load(name):
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(TMP, sub), exist_ok=True)
        os.environ[k] = os.path.join(TMP, sub)
    os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
    os.environ['ACME_AGENT_FAKE_ROOT'] = os.path.join(TMP, 'fake')
    spec = importlib.util.spec_from_file_location(name, AGENT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


AG = load('acme_agent_hunt_t9w')
WC = AG._wincert()


def find_binding(infos, w):
    """Find-Binding of PRELUDE as Python: the binding whose bindingInformation is IP:PORT:HOST
    (-contains: any case)."""
    ip = w.get('ip') or '*'
    tail = ':%d:%s' % (int(w['port']), w.get('host') or '')
    want = [(ip + tail).lower(), ('[' + ip + ']' + tail).lower()]
    for i in infos:
        if i.lower() in want:
            return i
    return None


class FindBinding(unittest.TestCase):
    def test_script_matches_the_whole_binding(self):
        fb = WC.PRELUDE[WC.PRELUDE.index('function Find-Binding'):]
        fb = fb[:fb.index('\n}\n')]
        self.assertIn('bindingInformation', fb)
        self.assertIn('[string]$w.ip', fb)
        self.assertNotIn('-HostHeader ([string]', fb)
        # the undo removes the binding found - not every one of that port and host
        self.assertIn('$b | Remove-WebBinding', WC.PS_UNBIND)
        self.assertNotIn('Remove-WebBinding -Name', WC.PS_UNBIND)
        # a binding made and not found again is said, never a null method call
        self.assertIn('is not found', WC.PS_BIND)

    def test_the_binding_asked_for(self):
        infos = ['*:443:', '*:443:www.other.test', '10.0.0.5:443:', '[2001:db8::1]:443:',
                 '*:8443:WWW.Example.TEST']
        self.assertEqual(find_binding(infos, {'ip': '10.0.0.5', 'port': 443, 'host': ''}),
                         '10.0.0.5:443:')
        self.assertEqual(find_binding(infos, {'ip': '*', 'port': 443, 'host': ''}), '*:443:')
        self.assertIsNone(find_binding(infos, {'ip': '*', 'port': 443,
                                               'host': 'www.example.test'}))
        self.assertEqual(find_binding(infos, {'ip': '*', 'port': 8443,
                                              'host': 'www.example.test'}),
                         '*:8443:WWW.Example.TEST')
        self.assertEqual(find_binding(infos, {'ip': '2001:db8::1', 'port': 443, 'host': ''}),
                         '[2001:db8::1]:443:')
        self.assertIsNone(find_binding(infos, {'ip': '10.0.0.6', 'port': 443, 'host': ''}))


class CmdWord(unittest.TestCase):
    def test_powershell_would_expand(self):
        from acmelib.plugins.targets import agent_windows as AW
        for f in (WC.cmd_word, AW.cmd_word):
            self.assertEqual(f('Shop $live'), "'Shop $live'")
            self.assertEqual(f("it's $(x)"), "'it''s $(x)'")
            self.assertEqual(f('a`b'), "'a`b'")
            self.assertEqual(f('${x}'), "'${x}'")
            self.assertEqual(f('#shop'), '"#shop"')
            # as before
            self.assertEqual(f('Default Web Site'), '"Default Web Site"')
            self.assertEqual(f('\\\\fs\\c$\\certs'), '"\\\\fs\\c$\\certs"')
            self.assertEqual(f('C:\\certs'), 'C:\\certs')
            self.assertEqual(f("O'Brien"), '"O\'Brien"')
            self.assertEqual(f('W3SVC'), 'W3SVC')
            self.assertEqual(f(''), '""')
        self.assertEqual(WC.allow_iis_words('Shop $live'), "acme-agent allow iis 'Shop $live'")
        self.assertEqual(WC.allow_iis_words('Default Web Site'),
                         'acme-agent allow iis "Default Web Site"')


T_WH, T_RDP, T_MY = 'A' * 40, 'B' * 40, 'C' * 40


class DiscoverOtherStores(unittest.TestCase):
    def setUp(self):
        self._ps, WC.powershell = WC.powershell, self.ps

    def tearDown(self):
        WC.powershell = self._ps

    def ps(self, script, env, timeout):
        def one(t, cn, store=None):
            d = {'thumb': t, 'subject': 'CN=%s' % cn, 'issuer': 'CN=ca', 'not_after': 2000000000,
                 'serial': '01', 'sans': [cn], 'friendly': '', 'has_key': True}
            if store:
                d['store'] = store
            return d
        got = {'store': [one(T_MY, 'my.test')],
               'other': [one(T_WH, 'www.example.test', 'WebHosting'),
                         one(T_RDP, 'host1', 'Remote Desktop')],
               'iis': [{'site': 'Default Web Site', 'state': 'Started', 'bindings': [
                   {'info': '*:443:www.example.test', 'thumb': T_WH.lower(),
                    'store': 'WebHosting', 'sni': 1},
                   {'info': '*:8443:', 'thumb': 'D' * 40, 'store': 'My', 'sni': 0}]}],
               'rdp': T_RDP, 'roles': {}}
        return 0, 'ACME ' + json.dumps(got)

    def test_bound_from_another_store_is_not_missing(self):
        got = WC.discover(AG._Here(), {}, ['iis', 'rdp'])
        iis = [f for f in got['found'] if f['kind'] == 'iis'][0]
        self.assertEqual(iis['cert']['thumbprint'], T_WH)
        self.assertNotIn('missing', iis['cert'])
        self.assertEqual(iis['cert']['cn'], 'www.example.test')
        rdp = [f for f in got['found'] if f['kind'] == 'rdp'][0]
        self.assertEqual(rdp['cert']['thumbprint'], T_RDP)
        self.assertNotIn('missing', rdp['cert'])
        # a certificate that is nowhere still says so
        self.assertEqual(WC._thumb('D' * 40), 'D' * 40)
        self.assertNotIn('D' * 40, [c['thumbprint'] for c in got['certs']])
        # only those the services use without 'store'
        self.assertEqual(sorted(c['thumbprint'] for c in got['certs']), sorted([T_WH, T_RDP]))

    def test_script_reads_them(self):
        self.assertIn("Other-Cert $out.rdp 'Remote Desktop'", WC.DISCOVER_PS)
        self.assertIn('Other-Cert ([string]$b.certificateHash) ([string]$b.certificateStoreName)',
                      WC.DISCOVER_PS)
        # the thumbprint and the store's name checked before a path is made of them
        self.assertIn("$t -notmatch '^[0-9A-Fa-f]{40}$'", WC.DISCOVER_PS)


if __name__ == '__main__':
    unittest.main(verbosity=1)
