#!/usr/bin/env python3
"""Bug hunt 1.0.144, run w10, the command line and the console against what changed since
1.0.143 - each command run for real against a state of its own:

- `acme --passwd NAME` and `acme --reset-2fa NAME` (and the console's accounts, which run them)
  ended the account's sign-ins but kept its calendar link - the pages take it back since
  1.0.144 (a link made from a stolen session outlived the new password); a configuration
  imported with a new password for an account kept it too;
- `acme --teams` (and the console's Owners and teams → 6) said nothing of what the page says
  above its tree: the enrolment pages or Certificates on the portal off, or Certificates on the
  portal on with no name or no source open to asking and no request profile (1.0.144);
- docs: backup-and-recovery.md dated the snapshot backups 1.0.143.

    python3 test/test_hunt_rw10_cli.py
"""
import json
import os
import subprocess
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
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rw10cli-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
os.environ.update({k: v for k, v in ENV.items() if k.startswith('ACME_')})


def run(*args, env=None):
    return subprocess.run(ACME + [str(a) for a in args], env=dict(ENV, **(env or {})),
                          capture_output=True, text=True, timeout=240, stdin=subprocess.DEVNULL)


def ok(test, *args, env=None):
    got = run(*args, env=env)
    test.assertEqual(got.returncode, 0, '%s: %s%s' % (args, got.stdout, got.stderr))
    return got


def store():
    import acme
    return acme.Storage(acme.open_db())


class A_CalendarLinkTakenBack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        got = run('--add-user', 'calja', '--role', 'certadmin',
                  env={'ACME_PASSWORD': 'Very-long-pass-123'})
        assert got.returncode == 0, got.stdout + got.stderr

    def _feed(self):
        from acmelib.certs import expirycal as X
        st = store()
        X.feed_new(st, 'calja')
        self.assertIsNotNone(X.feed_of(st, 'calja'))
        self.assertIn('calja', ok(self, '--calendar-feeds').stdout)

    def _gone(self):
        from acmelib.certs import expirycal as X
        self.assertIsNone(X.feed_of(store(), 'calja'))
        self.assertIn('nobody has a link', ok(self, '--calendar-feeds').stdout)

    def test_passwd(self):
        self._feed()
        ok(self, '--passwd', 'calja', env={'ACME_PASSWORD': 'Other-long-pass-456'})
        self._gone()
        self.assertIn('calendar link', ok(self, '--help').stdout)

    def test_reset_2fa(self):
        self._feed()
        ok(self, '--reset-2fa', 'calja')
        self._gone()

    def test_import_with_new_password(self):
        from acmelib import engine as E
        self._feed()
        st = store()
        acc = st.account('calja')
        # the same password: the link stays (nothing changed)
        conf = {'accounts': [{'name': 'calja', 'role': acc['role'], 'pw': acc['pw']}]}
        E.config_import(st, None, conf, 'root')
        from acmelib.certs import expirycal as X
        self.assertIsNotNone(X.feed_of(st, 'calja'))
        new = E.password_hash('Third-long-pass-789')
        conf['accounts'][0]['pw'] = new
        E.config_import(st, None, conf, 'root')
        self._gone()


class B_TeamsSaysThePortal(unittest.TestCase):
    def _said(self):
        return ok(self, '--teams').stdout

    def test_notes(self):
        ok(self, '--set', 'portal=0')
        self.assertIn('The enrolment pages are switched off', self._said())
        ok(self, '--set', 'portal=1')
        ok(self, '--set', 'portal_cert=0')
        self.assertIn('Certificates on the portal is off', self._said())
        ok(self, '--set', 'portal_cert=1')
        ok(self, '--set', 'portal_cert_suffixes=')
        ok(self, '--set', 'portal_cert_issuers=')
        out = self._said()
        self.assertIn('nobody can ask for one there: Names people may ask for and Sources '
                      'people may ask are empty', out)
        ok(self, '--set', 'portal_cert_suffixes=example.com')
        out = self._said()
        self.assertIn('Sources people may ask is empty', out)
        self.assertIn('acme --set portal_cert_issuers=', out)
        ok(self, '--set', 'portal_cert_issuers=LetsEncrypt')
        out = self._said()
        self.assertNotIn('nobody can ask', out)
        self.assertNotIn('\n! ', out)
        # the JSON is as it was (the console reads it)
        got = json.loads(ok(self, '--teams', '--json').stdout)
        self.assertEqual(set(got), {'teams', 'tags', 'legacy'})

    def test_console_item(self):
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'console.py'), encoding='utf-8') as f:
            src = f.read()
        self.assertIn("lambda: con.act('--teams')", src)


class C_Docs(unittest.TestCase):
    def test_docs(self):
        def doc(n):
            with open(os.path.join(ROOT, 'docs', n), encoding='utf-8') as f:
                return f.read()
        self.assertIn('at one moment (1.0.144)', doc('backup-and-recovery.md'))
        self.assertIn('acme --passwd NAME', doc('expiry-calendar.md'))
        cl = doc('command-line.md')
        self.assertIn('its calendar link is taken back', cl)
        self.assertIn('can ask for nothing there', cl)
        self.assertIn('`acme --teams`) also says', doc('console.md'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
