#!/usr/bin/env python3
"""Hunt R, run t5, area "targets": the bugs found and fixed, each kept fixed.

    python3 test/test_hunt_rt5_targets.py

- f5: a key (or certificate) the BIG-IP refused to install stayed uploaded, the key in clear,
  in /var/config/rest/downloads - unix-rm ran only after an install that went through.
- windows_ssh: an import that failed half-way left the PKCS#12 with the key in the temporary
  folder of the machine (its Remove-Item comes after the import in the script).
- mikrotik (RouterOS 6, SSH): with "force", a refused remove of the certificate of the same
  name left the uploaded key's file on the router (the remove was outside the try).
- qnap: a write of stunnel.pem / uca.pem that failed half-way left the new (or a cut)
  stunnel.pem beside the old uca.pem, nothing put back; an older .acme-prev could be taken
  for this one's.
"""
import base64
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402


def setUpModule():
    T.setUpModule()


def tearDownModule():
    T.tearDownModule()


class F5UploadGoneTest(unittest.TestCase):
    def routes(self, refuse):
        return [
            ('POST', r'/mgmt/shared/authn/login$', (200, {'token': {'token': 'TOK'}})),
            ('DELETE', r'/mgmt/shared/authz/tokens/TOK', (200, {})),
            ('GET', r'/mgmt/tm/sys/crypto/(cert|key)/', (404, {'code': 404})),
            ('POST', r'/mgmt/shared/file-transfer/uploads/', (200, {})),
            ('POST', r'/mgmt/tm/sys/crypto/%s$' % refuse, (400, {'message': 'bad key'})),
            ('POST', r'/mgmt/tm/sys/crypto/(cert|key)$', (200, {})),
            ('POST', r'/mgmt/tm/util/unix-rm', (200, {})),
        ]

    def removed(self, ctx):
        return [ctx.json(c)['utilCmdArgs'] for c in ctx.find('POST', '/util/unix-rm')]

    def test_a_refused_key_is_taken_off(self):
        ctx = FakeCtx(self.routes('key'))
        t = make('f5', {'host': 'bigip', 'user': 'acme', 'password': 'pw'}, ctx)
        b = FakeBundle()
        name = C.object_name(b, {})
        with self.assertRaises(PluginError):
            t.deploy(b, {'profiles': 'www_ssl'})
        self.assertEqual(self.removed(ctx), ['/var/config/rest/downloads/%s.key' % name])

    def test_a_refused_certificate_too(self):
        ctx = FakeCtx(self.routes('cert'))
        t = make('f5', {'host': 'bigip', 'user': 'acme', 'password': 'pw'}, ctx)
        b = FakeBundle()
        name = C.object_name(b, {})
        with self.assertRaises(PluginError):
            t.deploy(b, {'profiles': 'www_ssl'})
        self.assertEqual(self.removed(ctx), ['/var/config/rest/downloads/%s.key' % name,
                                             '/var/config/rest/downloads/%s.crt' % name])


def scripts_of(ssh):
    out = []
    ps1 = [d for p, d, _m in ssh.puts if p.endswith('.ps1')]
    for cmd, _inp in ssh.runs:
        if '-EncodedCommand ' in cmd:
            out.append(base64.b64decode(cmd.split('-EncodedCommand ')[1]).decode('utf-16-le'))
        elif '-File ' in cmd and ps1:
            out.append(ps1.pop(0).decode('utf-8-sig'))
    return out


class WindowsPfxGoneTest(unittest.TestCase):
    def test_a_failed_import_takes_the_pfx_away(self):
        def run(cmd, inp):
            sc = scripts_of(type('S', (), {'runs': [(cmd, inp)], 'puts': ssh.puts})())
            if sc and 'Import-PfxCertificate' in sc[0]:
                return 1, 'ERROR: the password is wrong', ''
            if sc and "'YES'" in sc[0]:
                return 0, 'NO', ''
            return 0, '', ''
        ssh = FakeSsh([(r'powershell', run)])
        t = make('windows_ssh', {'host': 'win', 'user': 'Administrator', 'auth': 'password',
                                 'password': 'pw'}, FakeCtx(ssh=ssh))
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), {})
        pfx = [p for p, _d, _m in ssh.puts if p.endswith('.pfx')]
        self.assertEqual(len(pfx), 1)
        last = scripts_of(ssh)[-1]
        self.assertIn("Remove-Item -LiteralPath '%s'" % pfx[0], last)
        self.assertNotIn('Import-PfxCertificate', last)


class MikrotikKeyFileGoneTest(unittest.TestCase):
    def test_a_refused_remove_still_takes_the_files_away(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        ssh = FakeSsh([
            (r'^:foreach c in=\[/certificate find where name~', (0, name, '')),
            (r'^/certificate remove', (1, '', 'failure: certificate is in use')),
        ])
        t = make('mikrotik', {'host': 'rtr', 'user': 'a', 'password': 'p', 'mode': 'ssh'},
                 FakeCtx(ssh=ssh))
        with self.assertRaises(PluginError):
            t.deploy(b, {'services': 'api-ssl', 'force': True})
        cmds = [c for c, _ in ssh.runs]
        self.assertIn('/file remove [find where name="%s.crt" or name="%s.key"]' % (name, name),
                      cmds)


class QnapPartialWriteTest(unittest.TestCase):
    def deploy(self, answer):
        ssh = FakeSsh([(r'cat \S+\.pem > /etc/stunnel/stunnel\.pem', answer)])
        t = make('qnap', {'host': 'nas', 'user': 'admin', 'auth': 'password', 'password': 'p'},
                 FakeCtx(ssh=ssh))
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {})
        cmds = [c for c, _ in ssh.runs]
        self.assertNotIn('stunnel.sh restart', ' '.join(cmds))
        return str(e.exception), cmds

    def test_a_write_failing_half_way_puts_the_previous_back(self):
        words, cmds = self.deploy((1, 'SAVED-PEM\nSAVED-UCA\n', 'No space left on device'))
        self.assertIn('writing /etc/stunnel/stunnel.pem failed (exit 1): No space left', words)
        i = next(i for i, c in enumerate(cmds) if 'cat ' in c)
        back = cmds[i + 1]
        self.assertIn('cp -p /etc/stunnel/stunnel.pem.acme-prev /etc/stunnel/stunnel.pem', back)
        self.assertIn('cp -p /etc/stunnel/uca.pem.acme-prev /etc/stunnel/uca.pem', back)

    def test_only_the_copies_made_now(self):
        # the copy of stunnel.pem not made: an older .acme-prev is not put over it
        words, cmds = self.deploy((1, '', 'cp: read-only file system'))
        self.assertFalse([c for c in cmds if '.acme-prev /etc/stunnel/' in c])


if __name__ == '__main__':
    unittest.main()
