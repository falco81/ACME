#!/usr/bin/env python3
"""Hunt Q2 (1.0.119): targets and deployments.

    python3 test/test_hunt_q2_targets.py

* This machine (local): a file's path given whole, under the target's folder - the preview
  ("What it will be", What happens) and the test said <folder>/<folder>/<file>, while the
  deployment writes <folder>/<file>; ACME_FILE_* of the preview the same.
* The password of the PKCS#12 / keystore files printed by the script after them (an echo,
  set -x): in clear in the job's steps and the jobs' log file, which a reader sees - dots now,
  for this machine, a server over SSH and Windows.
* The page (static): the files' row names the placeholder that is not one (it named the first
  of the path, {name}, in "{name}/{foo}.crt"); a deployment opened from a target's window
  asks for its certificate's row (its card said "web -", no state, no names).
"""
import os
import re
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_targets as TT  # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make  # noqa: E402

PW = 'Pfx-Very-Secret-0042'


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


class LocalPathUnderTheFolder(unittest.TestCase):
    def test_preview_and_test_say_where_it_is_written(self):
        base = os.path.realpath(tempfile.mkdtemp(dir=TT.TMP))
        o = {'outputs': ['cert-pem %s/abs.crt' % base, 'key-pem {name}/k.pem 0600',
                         'cert-pem /etc/x.crt']}
        t = make('local', {'base': base}, FakeCtx())
        got = t.preview(FakeBundle(), o)
        fulls = [f['full'] for f in got['files']]
        self.assertEqual(fulls, [os.path.join(base, 'abs.crt'),
                                 os.path.join(base, 'www.example.test', 'k.pem'),
                                 os.path.join(base, 'etc', 'x.crt')])
        self.assertFalse([p for p in got['problems'] if p['level'] == 'bad'], got['problems'])
        self.assertEqual(got['env']['ACME_FILE_CERT_PEM'], os.path.join(base, 'abs.crt'))
        # ...as the deployment writes them
        t.deploy(FakeBundle(), o)
        for p in fulls:
            self.assertTrue(os.path.isfile(p), p)
        self.assertFalse(os.path.exists(os.path.join(base, base.lstrip('/'))))
        # ...and the test says it so
        ctx = FakeCtx()
        make('local', {'base': base}, ctx).dry_run(FakeBundle(), o)
        said = ' '.join(w for _l, w in ctx.steps)
        self.assertIn(os.path.join(base, 'abs.crt') + ':', said)
        self.assertNotIn(base + base, said)


class PasswordNotInTheLog(unittest.TestCase):
    O = {'outputs': ['pfx {name}.pfx 0600'], 'pfx_password_mode': 'fixed', 'pfx_password': PW,
         'script_mode': 'inline', 'script_interp': 'sh', 'skip_same': False}

    def said(self, ctx):
        return '\n'.join(str(w) for _l, w in ctx.steps)

    def test_local(self):
        base = tempfile.mkdtemp(dir=TT.TMP)
        ctx = FakeCtx()
        t = make('local', {'base': base, 'allow_scripts': True}, ctx)
        t.deploy(FakeBundle(), dict(self.O, script_body='echo "pw=$ACME_PASSWORD"\n'
                                                        'echo "$ACME_PASSWORD" >&2\n'))
        self.assertIn('pw=•', self.said(ctx))
        self.assertNotIn(PW, self.said(ctx))
        # a failing one: its last line in the error too
        ctx = FakeCtx()
        t = make('local', {'base': base, 'allow_scripts': True}, ctx)
        with self.assertRaises(Exception) as e:
            t.deploy(FakeBundle(), dict(self.O, force=True,
                                        script_body='echo "bad $ACME_PASSWORD"; exit 3\n'))
        self.assertNotIn(PW, str(e.exception))
        self.assertNotIn(PW, self.said(ctx))
        # the test the same
        ctx = FakeCtx()
        make('local', {'base': base, 'allow_scripts': True}, ctx).dry_run(
            FakeBundle(), dict(self.O, script_body='echo "pw=$ACME_PASSWORD"\n'))
        self.assertIn('pw=•', self.said(ctx))
        self.assertNotIn(PW, self.said(ctx))

    def test_ssh(self):
        ssh = FakeSsh(local=True)
        ctx = FakeCtx(ssh=ssh)
        t = make('ssh', {'host': 'web1', 'user': 'root', 'password': 'x'}, ctx)
        tmp = tempfile.mkdtemp(dir=TT.TMP)
        t.deploy(FakeBundle(), dict(self.O, outputs=['pfx %s/{name}.pfx 0600' % tmp],
                                    script_body='echo "pw=$ACME_PASSWORD"\n'))
        self.assertIn('pw=•', self.said(ctx))
        self.assertNotIn(PW, self.said(ctx))

    def test_tell_itself(self):
        from acmelib.plugins.targets import _script as SC
        ctx = FakeCtx()
        t = make('local', {'base': tempfile.mkdtemp(dir=TT.TMP)}, ctx)
        sc = {'mode': 'inline', 'interp': 'sh', 'from': ''}
        words = SC.tell(t, sc, 1, ('a %s b' % PW).encode(), b'', env={'ACME_PASSWORD': PW})
        self.assertNotIn(PW, words)
        self.assertNotIn(PW, self.said(ctx))
        # without a password: as it was said
        self.assertEqual(SC.tell(t, sc, 0, b'plain', b''), 'plain')


class ThePage(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(ROOT, 'web', 'assets', name), encoding='utf-8') as f:
            return f.read()

    def test_the_placeholder_named_is_the_wrong_one(self):
        js = self.read('deployfiles.js')
        m = re.search(r"else if \((/\\\{\(\?!\([^/]+/)\.test\(p\)\) bad = 'not a placeholder "
                      r"there is: ' \+ p\.match\((/[^/]+/)\)\[0\];", js)
        self.assertTrue(m, 'the check of the placeholders in deployfiles.js')
        self.assertEqual(m.group(1), m.group(2))

    def test_the_certificate_asked_for_from_a_target(self):
        js = self.read('certs.js')
        i = js.index('function deployEdit(o)')
        body = js[i:js.index('\n}\n', i)]
        self.assertIn("capi('certs/one' + qs({id: certId}))", body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
