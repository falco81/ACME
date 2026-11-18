#!/usr/bin/env python3
"""Bug hunt R, run t10, the command line (acme ...) and the console.

    python3 test/test_hunt_rt10_cli.py

- acme --certs --owner TEAM (and --issuer SOURCE) listed every certificate: the options were
  taken and left out - now the list's own filters, as the page's;
- acme --import FILE --owner TEAM --note TEXT imported it with neither (the page's Import sends
  both); with --into they are refused (a new version keeps the certificate's);
- options that only go with some others were taken beside any other and left out without a
  word: --selfsigned --owner, --ca-create --parent (meant --ca-sub), --tag-add --description,
  --team-add --caps, --teams --owner, --team-show --below, --team-del --strip ... - refused now,
  nothing done;
- --set beside --selfsigned, --import, --check-names, --cert-check, --dry-run was let by: the
  certificate was made or imported, the job run, and only then "nothing of it was saved", exit 2
  - refused before anything is done now;
- the console's member form took a day that is not one (2026-13-45) and ended in a traceback.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
TMP = tempfile.mkdtemp(prefix='acme-rt10cli-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
ENV = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
ENV.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
           ACME_RUN=TMP, ACME_LOGDIR=TMP, NO_COLOR='1',
           ACME_CONSOLE_FLAG=os.path.join(TMP, 'console-flag'))
sys.path.insert(0, ROOT)


def run(*args):
    got = subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True, timeout=120,
                         input='')
    assert 'Traceback' not in got.stderr + got.stdout, got.stderr
    return got


def names(*args):
    got = run('--certs', '--json', *args)
    assert got.returncode == 0, got.stderr
    return sorted(r['name'] for r in json.loads(got.stdout)['rows'])


def cert(name):
    return json.loads(run('--cert', name, '--json').stdout)['cert']


class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for args in (('--team-add', 'Web'), ('--team-add', 'Db'),
                     ('--selfsigned', 'one', '--names', 'one.example.com'),
                     ('--cert-add', 'two', '--names', 'two.example.com', '--issuer',
                      'self-signed', '--owner', 'Web'),
                     ('--ca-create', 'Root', '--subject', 'CN=Root')):
            got = run(*args)
            assert got.returncode == 0, got.stdout + got.stderr
        cls.pem = os.path.join(TMP, 'one.pem')
        got = run('--export', 'one', '--format', 'combined-pem', '--out', cls.pem)
        assert got.returncode == 0, got.stderr

    def test_certs_filters(self):
        self.assertEqual(names(), ['one', 'two'])
        self.assertEqual(names('--owner', 'Web'), ['two'])
        self.assertEqual(names('--owner', 'web'), ['two'])
        self.assertEqual(names('--owner', 'Db'), [])
        self.assertEqual(names('--issuer', 'self-signed'), ['one', 'two'])
        self.assertEqual(names('--issuer', 'nowhere'), [])
        got = run('--certs', '--owner', 'Web')
        self.assertIn('two', got.stdout)
        self.assertNotIn('one.example.com', got.stdout)

    def test_import_owner_note(self):
        got = run('--import', self.pem, '--name', 'imp', '--owner', 'Web', '--note', 'from rt10')
        self.assertEqual(got.returncode, 0, got.stderr)
        c = cert('imp')
        self.assertEqual((c.get('owner'), c.get('note')), ('Web', 'from rt10'))
        got = run('--import', self.pem, '--into', 'imp', '--owner', 'Db')
        self.assertEqual(got.returncode, 1)
        self.assertIn('--cert-edit imp --owner', got.stderr)
        self.assertEqual(cert('imp')['version'], 1)       # nothing was imported
        got = run('--import', self.pem, '--name', 'imp2')  # as before
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertFalse(cert('imp2').get('owner'))

    def test_options_beside_others_refused(self):
        for args, said in (
                (('--selfsigned', 'three', '--names', 'three.example.com', '--owner', 'Web'),
                 '--owner goes with'),
                (('--ca-create', 'Sub', '--parent', 'Root'), '--parent goes with --ca-sub'),
                (('--tag-add', 'green', '--description', 'x'), '--description goes with'),
                (('--team-add', 'T1', '--caps', 'cert.view'), '--caps goes with --role-add'),
                (('--teams', '--owner', 'Web'), 'not with --teams'),
                (('--team-show', 'Web', '--below'), '--below goes with --team-activity'),
                (('--team-del', 'Db', '--strip', '--yes'), '--strip goes with'),
                (('--team-access', 'local:jan', '--member-role', 'Viewer'),
                 '--member-role goes with --teams-from-groups'),
                (('--role-add', 'R1', '--caps', 'cert.view', '--members', 'local:a'),
                 '--members goes with')):
            got = run(*args)
            self.assertEqual(got.returncode, 1, (args, got.stdout))
            self.assertIn(said, got.stderr, args)
            self.assertIn('nothing was done', got.stderr, args)
        self.assertNotIn('three', names())
        self.assertNotIn('Sub', run('--cas').stdout)
        teams = {t['name'] for t in json.loads(run('--teams', '--json').stdout)['teams']}
        self.assertIn('Db', teams)
        self.assertNotIn('T1', teams)
        roles = {r['name'] for r in json.loads(run('--roles', '--json').stdout)['roles']}
        self.assertNotIn('R1', roles)
        # where they go, as before
        got = run('--ca-sub', 'Sub', '--parent', 'Root')
        self.assertEqual(got.returncode, 0, got.stderr)
        got = run('--role-add', 'R2', '--caps', 'cert.view', '--description', 'd')
        self.assertEqual(got.returncode, 0, got.stderr)
        got = run('--role-del', 'R2', '--strip', '--yes')
        self.assertEqual(got.returncode, 0, got.stderr)
        got = run('--cert-edit', 'two', '--owner', 'Db')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(cert('two')['owner'], 'Db')
        # a source's owner: refused in its own words, as before (hunt R t3)
        got = run('--source-edit', 'self-signed', '--owner', 'Web')
        self.assertIn('a source has no owner', got.stderr)

    def test_set_refused_first(self):
        for args, opt in ((('--selfsigned', 'four', '--names', 'four.example.com', '--set',
                            'owner=Web'), '--selfsigned'),
                          (('--import', self.pem, '--name', 'imp4', '--set', 'owner=Web'),
                           '--import'),
                          (('--check-names', 'a.example.com', '--set', 'x=y'), '--check-names'),
                          (('--cert-check', 'one', '--set', 'x=y'), '--cert-check'),
                          (('--dry-run', 'one', '--set', 'x=y'), '--dry-run')):
            got = run(*args)
            self.assertEqual(got.returncode, 1, (args, got.stdout))
            self.assertIn('--set does not go with %s - nothing was done' % opt, got.stderr)
            self.assertNotIn('job', got.stdout)
        self.assertNotIn('four', names())
        self.assertNotIn('imp4', names())


class Console(unittest.TestCase):
    def test_member_day_not_a_day(self):
        from acmelib.certs import console as C

        class Con(object):
            refused = None

            def out(self, *a):
                return {'roles': [{'name': 'Viewer'}]}
            _rows = staticmethod(lambda got, *k: got.get(k[0]))

            def form(self, title, fields, *a, **k):
                vals = {f['key']: str(f.get('value') or '') for f in fields}
                vals.update(self.answer)
                for f in fields:
                    bad = f.get('check') and f['check'](vals[f['key']], vals)
                    if bad:
                        self.refused = (f['key'], bad)
                        return None
                return vals
        con = Con()
        con.answer = {'who': 'local:x', 'roles': 'Viewer', 'until': '2026-13-45'}
        self.assertIsNone(C.member_form(con, 'a member', {}))
        self.assertEqual(con.refused[0], 'until')
        con.answer = {'who': 'local:x', 'roles': 'Viewer', 'until': '2026-12-31'}
        got = C.member_form(con, 'a member', {})
        self.assertEqual(C._day(got['until']), '2026-12-31')


if __name__ == '__main__':
    unittest.main(verbosity=2)


class MemberUntilBounded(unittest.TestCase):
    """A membership end after the year 9999 is refused (hunt t10): kept, every view of the
    team failed on it."""
    def test_far_until_refused(self):
        from acmelib.certs import teams as TT
        with self.assertRaises(ValueError):
            TT.clean_member({'who': 'local:eva', 'until': 99999999999999})
        self.assertEqual(TT.clean_member({'who': 'local:eva', 'until': 1900000000})['until'],
                         1900000000)
