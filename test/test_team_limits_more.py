#!/usr/bin/env python3
"""More limits of a team (1.0.128, docs/teams.md "Limits (policy)", "Tests of a team",
"Typical setup").

    python3 test/test_team_limits_more.py

- `wildcards: false`: a name "*.x" refused (403, an event, the team named) on the portal's
  free form, from a request profile, in a CSR, for a scoped certificate administrator making or
  changing a certificate, in a new CSR with other names; allowed without the limit; off
  anywhere above - off; approval.outside.wildcards: false - a wildcard waits;
- `pairs`: a source only with its validations; a source not paired only where the same team's
  `issuers` lists it; the intersection down the tree (every level must allow the pair);
  followed when a source or a validation is renamed; the portal's free form told which
  sources are left; a team below never wider (the portal's designer);
- `test_kinds` and the capabilities test.view / test.manage: the portal's routes list, add,
  change, delete and run only the team's tests, of the modules allowed, never a secret;
  acme's own tests and another team's never seen; a connector of another team refused;
- the migration: an old cert_tests without `owner` given the column, its rows acme's own;
- the defaults: a team without these keys - everything as before; the old rights unchanged.
"""
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-team-limits-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402  (the routes)
from acmelib.certs import teams as T, teampolicy as TP  # noqa: E402
from acmelib.certs import portal as P, store as S, pki, ca as CA  # noqa: E402
from acmelib.certs import reqprofiles as R  # noqa: E402
from acmelib.certs import portal_teams as PT  # noqa: E402
from acmelib.certs import api_teams, api_reqprofiles  # noqa: E402,F401

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
SECRET = 'Sup3r-Secret-Pw!42'
OWN = {}


class FakeH(object):
    def __init__(self, who='boss', role='fulladmin', body=None, args=None, portal=None):
        self.store, self._body = STORE, dict(body or {})
        self.args = {k: str(v) for k, v in (args or {}).items()}
        self.who, self.role, self.portal = who, role, portal
        self.headers = {}
        self.d = type('D', (), {'dirs': {}})()

    def me(self, _role='readonly'):
        return {'name': self.who, 'role': self.role,
                'account': {'name': self.who, 'role': self.role, 'source': 'local',
                            'dn': '', 'group_list': ''}}

    def session(self, kind):
        return self.portal if kind == 'portal' else self.me()

    def body(self):
        return self._body

    def arg(self, name, default=''):
        return self.args.get(name, default)

    def num(self, name, default, lo=0, hi=10 ** 9):
        try:
            return max(lo, min(hi, int(self.args.get(name, default))))
        except (TypeError, ValueError):
            return default


def person(name):
    if not STORE.account(name):
        STORE.add_account(name, 'readonly', 'Local-Only-Pw-77!x' + name)
    return {'name': name, 'kind': 'portal',
            'data': {'kind': 'local', 'mail': '', 'about': {}, 'cert_groups': [],
                     'cert_groups_at': time.time()}}


def admin(method, path, body=None, who='boss', role='fulladmin'):
    return E.ROUTES[(method, path)](FakeH(who=who, role=role, body=body))


def portal(who, method, name, body=None, args=None):
    s = who if isinstance(who, dict) else person(who)
    path = name if name.startswith('/') else '/api/portal/' + name
    return E.ROUTES[(method, path)](FakeH(portal=s, body=body, args=args))


def outcome(fn, *a, **kw):
    """(status, words)"""
    try:
        fn(*a, **kw)
        return 200, ''
    except E.ApiError as e:
        return e.status, str(e)
    except LookupError as e:
        return 404, str(e)
    except ValueError as e:
        return 400, str(e)


def wait_jobs():
    from acmelib.certs import jobs
    end = time.time() + 30
    while time.time() < end and (jobs.RUNNING or jobs.BUSY_CERTS):
        time.sleep(0.05)


def clean():
    wait_jobs()
    for t in ('certs', 'cert_teams', 'cert_versions', 'cert_jobs', 'cert_deploys',
              'cert_targets', 'cert_roles', 'cert_checks', 'cert_tests', 'cert_req_profiles',
              'cert_challenges'):
        STORE.db.run('DELETE FROM %s' % t)
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:portal:%' OR k LIKE 'teams:action:%'")
    T.changed()
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1, certs_notify_mail='',
                    portal=1, portal_cert=1, portal_local=1, mail_mode='off',
                    portal_cert_auto=0, portal_cert_suffixes='example.test',
                    portal_cert_issuers='self other', portal_cert_max=1000,
                    portal_cert_challenge='', portal_directory='', admin_directory='')
    for name in ('self', 'other'):
        if not STORE.db.row('SELECT id FROM cert_issuers WHERE name = ?', (name,)):
            STORE.db.insert('cert_issuers', {'name': name, 'kind': 'selfsigned',
                                             'config': '{}', 'enabled': 1})
    for name in ('dnsA', 'dnsB'):
        STORE.db.insert('cert_challenges', {'name': name, 'kind': 'dns_builtin',
                                            'config': '{}', 'enabled': 1, 'state': '{}'})


def tree(web_policy=None, top_policy=None, members=None):
    T.save_team(STORE, {'name': 'Top', 'kind': 'unit', 'policy': top_policy or {}}, 'x')
    T.save_team(STORE, {'name': 'Web', 'parent': 'Top', 'policy': web_policy or {},
                        'members': members or ['local:eva=request', 'local:mgr=manage']}, 'x')


def setp(team, policy):
    T.save_team(STORE, {'old_name': team, 'name': team, 'policy': policy}, 'x')


def events(words):
    return [r['words'] for r in STORE.db.rows('SELECT words FROM events WHERE words LIKE ?',
                                              ('%' + words + '%',))]


class Clean(unittest.TestCase):
    def test_keys_cleaned(self):
        got = T.clean_policy({'wildcards': 'false', 'test_kinds': 'HTTPS, smtp',
                              'pairs': {'acme-le': ['dns-web', 'dns-web'], 'own': []},
                              'approval': {'mode': 'outside', 'outside': {'wildcards': 0}}})
        self.assertEqual(got['wildcards'], False)
        self.assertEqual(got['test_kinds'], ['https', 'smtp'])
        self.assertEqual(got['pairs'], {'acme-le': ['dns-web'], 'own': []})
        self.assertIs(got['approval']['outside']['wildcards'], False)
        for bad in ({'pairs': ['x']}, {'pairs': {'': ['a']}}, {'pairs': {'a': [{'x': 1}]}},
                    {'wildcards': 'maybe'}, {'pairs': {'A': [], 'a': []}},
                    {'approval': {'mode': 'outside', 'outside': {'wildcards': 'x'}}}):
            with self.assertRaises(ValueError, msg=bad):
                T.clean_policy(bad)
        # the JSON of the command line: the same
        self.assertEqual(T.clean_policy('{"pairs": {"s": ["v"]}, "wildcards": false}'),
                         {'pairs': {'s': ['v']}, 'wildcards': False})
        self.assertIn('pairs', T.POLICY_KEYS)
        self.assertIn('test_kinds', T.POLICY_LISTS)
        self.assertTrue(T.POLICY_BOOLS['wildcards'])

    def test_defaults_unchanged(self):
        # a team without the new keys: nothing in force, wildcards and any pair allowed
        self.assertEqual(T.merge_policies([('A', {}), ('B', {})]), {})
        self.assertTrue(T.policy_value({}, 'wildcards'))
        self.assertTrue(T.pair_allowed({}, 'x', 'y'))
        self.assertIsNone(TP.test_kinds_allowed({}))
        # the old rights give what they gave
        self.assertEqual(T.RIGHT_CAPS['view'], {'cert.view', 'deploy.view', 'target.view',
                                                'team.view'})
        self.assertNotIn('test.manage', T.RIGHT_CAPS['manage'])
        roles = {n: set(c) for n, c, _w in T.BUILTIN_ROLES}
        self.assertIn('test.view', roles['Viewer'])
        self.assertNotIn('test.manage', roles['Viewer'])
        self.assertTrue({'test.view', 'test.manage'} <= roles['Device manager'])
        self.assertTrue({'test.view', 'test.manage'} <= roles['Team owner'])
        self.assertNotIn('test.manage', roles['Certificate manager'])
        self.assertIn('test.manage', T.CAP_WORDS)


class Intersection(unittest.TestCase):
    def test_wildcards_off_anywhere_is_off(self):
        eff = T.merge_policies([('Top', {'wildcards': False}), ('Web', {'wildcards': True})])
        self.assertFalse(eff['wildcards'])
        self.assertEqual(eff['from']['wildcards'], 'Web')
        eff = T.merge_policies([('Top', {'wildcards': True}), ('Web', {'wildcards': False})])
        self.assertFalse(eff['wildcards'])
        env = T.merge_policies([
            ('Top', {'approval': {'mode': 'outside', 'outside': {'wildcards': False}}}),
            ('Web', {'approval': {'mode': 'outside', 'outside': {'max_days': 30}}})])
        self.assertEqual(env['approval']['outside'], {'max_days': 30, 'wildcards': False})

    def test_test_kinds_intersected(self):
        eff = T.merge_policies([('Top', {'test_kinds': ['https', 'smtp']}),
                                ('Web', {'test_kinds': ['smtp', 'ldaps']})])
        self.assertEqual(eff['test_kinds'], ['smtp'])

    def test_pairs_every_level(self):
        top = {'pairs': {'le': ['dns1', 'dns2'], 'own': []}}
        web = {'pairs': {'LE': ['dns2', 'dns3']}}
        eff = T.merge_policies([('Top', top), ('Web', web)])
        self.assertEqual(eff['pairs'], {'le': ['dns2']})
        self.assertTrue(T.pair_allowed(eff, 'le', 'DNS2'))
        self.assertFalse(T.pair_allowed(eff, 'le', 'dns1'))      # Web does not allow it
        self.assertFalse(T.pair_allowed(eff, 'le', 'dns3'))      # Top does not allow it
        self.assertFalse(T.pair_allowed(eff, 'own', None))       # not paired below
        self.assertTrue(T.pair_allowed(eff, 'le', None))         # a source alone
        # a source not paired, listed in the same team's issuers: any validation
        eff = T.merge_policies([('Top', {'pairs': {'le': ['dns1']}, 'issuers': ['le', 'own']})])
        self.assertTrue(T.pair_allowed(eff, 'own', 'anything'))
        self.assertFalse(T.pair_allowed(eff, 'le', 'anything'))
        # ...but issuers of ANOTHER level do not open what a level's pairs closed
        eff = T.merge_policies([('Top', {'pairs': {'le': ['dns1']}}),
                                ('Web', {'issuers': ['le', 'own']})])
        self.assertFalse(T.pair_allowed(eff, 'own', 'x'))
        # a level below pairing what the level above lets through by its issuers
        eff = T.merge_policies([('Top', {'pairs': {'le': ['dns1']}, 'issuers': ['le', 'own']}),
                                ('Web', {'pairs': {'own': ['dns9']}})])
        self.assertEqual(eff['pairs'], {'own': ['dns9']})
        self.assertTrue(T.pair_allowed(eff, 'own', 'dns9'))
        self.assertFalse(T.pair_allowed(eff, 'le', 'dns1'))      # Web pairs only own
        # no pairs anywhere: no limit of this kind
        self.assertNotIn('pairs', T.merge_policies([('Top', {'issuers': ['le']})]))

    def test_rename_followed(self):
        clean()
        T.save_team(STORE, {'name': 'Web', 'policy': {'pairs': {'self': ['dnsA', 'dnsB']}}},
                    'x')
        T.policy_rename(STORE, 'issuers', 'self', 'self2')
        T.policy_rename(STORE, 'validations', 'dnsA', 'dnsZ')
        self.assertEqual(T.policy_of(T.team_get(STORE, 'Web'))['pairs'],
                         {'self2': ['dnsZ', 'dnsB']})

    def test_sub_team_never_wider(self):
        base = {'pairs': {'le': ['dns1']}, 'from': {}}
        self.assertTrue(PT.widened(base, {'pairs': {'le': ['dns1', 'dns2']}}))
        self.assertTrue(PT.widened(base, {'pairs': {'own': []}}))
        self.assertFalse(PT.widened(base, {'pairs': {'le': ['dns1']}}))
        self.assertFalse(PT.widened(base, {'pairs': {'le': []}}))
        self.assertTrue(PT.widened({'wildcards': False}, {'wildcards': True}))
        self.assertTrue(PT.widened({'test_kinds': ['https']}, {'test_kinds': ['https', 'smtp']}))
        env = {'approval': {'mode': 'outside', 'outside': {'wildcards': False}}}
        self.assertTrue(PT.widened(env, {'approval': {'mode': 'outside', 'outside': {}}}))


class FreeForm(unittest.TestCase):
    def setUp(self):
        clean()
        E.CONFIG.update(portal_cert_auto=1)

    def tearDown(self):
        wait_jobs()

    def ask(self, names, issuer='self', team='Web'):
        return outcome(portal, 'eva', 'POST', '/api/portal/cert_request',
                       {'names': names, 'issuer': issuer, 'team': team})

    def test_wildcards(self):
        tree()
        self.assertEqual(self.ask(['*.a.example.test'])[0], 200)          # as before
        setp('Top', {'wildcards': False})
        st, words = self.ask(['*.b.example.test'])
        self.assertEqual(st, 403)
        self.assertIn('the team Top', words)
        self.assertIn('wildcard', words)
        self.assertTrue(events('refused by the limits of the team Top'))
        self.assertEqual(self.ask(['plain.example.test'])[0], 200)
        # off above: the team below says true - still off
        setp('Web', {'wildcards': True})
        self.assertEqual(self.ask(['*.c.example.test'])[0], 403)
        # the free form told: no wildcard for Web
        got = portal('eva', 'GET', '/api/portal/certs')
        self.assertFalse(got['team_limits']['Web']['wildcards'])

    def test_pairs(self):
        E.CONFIG.update(portal_cert_challenge='dnsA')
        tree({'pairs': {'self': ['dnsA']}})
        st, words = self.ask(['p1.example.test'], issuer='other')
        self.assertEqual(st, 403)
        self.assertIn('the source other', words)
        self.assertIn('the team Web', words)
        self.assertNotEqual(self.ask(['p2.example.test'], issuer='self')[0], 403)
        setp('Web', {'pairs': {'self': ['dnsB']}})
        st, words = self.ask(['p3.example.test'], issuer='self')
        self.assertEqual(st, 403)
        self.assertIn('dnsA', words)
        # the source not paired, but in the team's own issuers: allowed
        setp('Web', {'pairs': {'self': ['dnsB']}, 'issuers': ['self', 'other']})
        self.assertNotEqual(self.ask(['p4.example.test'], issuer='other')[0], 403)
        got = portal('eva', 'GET', '/api/portal/certs')
        self.assertEqual(got['team_limits']['Web']['issuers'], ['other'])

    def test_outside_envelope_wildcard_waits(self):
        tree({'approval': {'mode': 'outside', 'outside': {'suffixes': ['example.test'],
                                                          'wildcards': False}}})
        self.assertFalse(portal('eva', 'POST', '/api/portal/cert_request', {
            'names': ['in.example.test'], 'issuer': 'self', 'team': 'Web'})['waits'])
        self.assertTrue(portal('eva', 'POST', '/api/portal/cert_request', {
            'names': ['*.in.example.test'], 'issuer': 'self', 'team': 'Web'})['waits'])
        self.assertFalse(TP.inside_envelope(T.effective_policy(STORE, 'Web'),
                                            names=['*.x.example.test']))
        self.assertTrue(TP.inside_envelope(T.effective_policy(STORE, 'Web'),
                                           names=['x.example.test']))


class Profiles(unittest.TestCase):
    def setUp(self):
        clean()
        E.CONFIG.update(portal_cert_suffixes='', portal_cert_issuers='', portal_cert_auto=0)
        if not OWN:
            OWN['ca'] = int(CA.ca_create(STORE, 'Limits CA', {'CN': 'Limits CA'},
                                         key_type='ec-256'))
        if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'own'"):
            STORE.db.insert('cert_issuers', {'name': 'own', 'kind': 'internal_ca',
                                             'config': json.dumps({'ca': OWN['ca']}),
                                             'enabled': 1})
        tree()
        self.prof(make_key=True, csr=True)

    def tearDown(self):
        wait_jobs()

    def prof(self, **more):
        b = {'name': 'Web servers', 'issuer': 'own', 'suffixes': ['example.test'],
             'wildcards': True, 'max_names': 5, 'make_key': True, 'csr': True,
             'key_types': ['ec-256'], 'key_default': 'ec-256', 'auto_renew': True,
             'days': 30, 'approval': False, 'owner': 'team', 'teams': ['Web'], 'pfx': True}
        b.update(more)
        if R.profile_get(STORE, 'Web servers'):
            b['old_name'] = 'Web servers'
        R.save_profile(STORE, b, 'x')

    def ask(self, **b):
        b.setdefault('profile', 'Web servers')
        b.setdefault('team', 'Web')
        return outcome(portal, 'eva', 'POST', '/api/portal/cert_request', b)

    def csr(self, names):
        return pki.make_csr(pki.make_key('ec-256'), names)[0]

    def test_wildcards_from_a_profile_and_a_csr(self):
        self.assertEqual(self.ask(names=['*.w1.example.test'])[0], 200)
        setp('Web', {'wildcards': False})
        st, words = self.ask(names=['*.w2.example.test'])
        self.assertEqual(st, 403)
        self.assertIn('the team Web', words)
        st, words = self.ask(csr=self.csr(['*.w3.example.test']))
        self.assertEqual(st, 403)
        self.assertIn('wildcard', words)
        self.assertEqual(self.ask(names=['w4.example.test'])[0], 200)
        self.assertEqual(self.ask(csr=self.csr(['w5.example.test']))[0], 200)

    def test_pairs_from_a_profile(self):
        setp('Web', {'pairs': {'self': []}})
        st, words = self.ask(names=['pp.example.test'])
        self.assertEqual(st, 403)
        self.assertIn('the source own', words)
        setp('Web', {'pairs': {'own': []}})
        self.assertEqual(self.ask(names=['pp.example.test'])[0], 200)

    def test_new_csr_with_other_names(self):
        self.prof(make_key=False, csr=True, pfx=False)
        st, _w = self.ask(csr=self.csr(['c1.example.test']))
        self.assertEqual(st, 200)
        cid = STORE.db.value("SELECT id FROM certs WHERE cn = 'c1.example.test'")
        wait_jobs()
        setp('Web', {'wildcards': False})
        st, words = outcome(portal, 'mgr', 'POST', '/api/portal/cert_csr',
                            {'id': cid, 'csr': self.csr(['*.c1.example.test'])})
        self.assertEqual(st, 403)
        self.assertIn('wildcard', words)
        self.assertEqual(json.loads(S.cert_get(STORE, cid)['names']), ['c1.example.test'])


class ScopedAdmin(unittest.TestCase):
    def setUp(self):
        clean()
        E.CONFIG.update(certs_certadmin_all=0)
        tree()

    def save(self, b):
        return outcome(admin, 'POST', '/api/certs/save', b, who='mgr', role='certadmin')

    def test_wildcards(self):
        new = {'names': ['*.adm.example.test'], 'issuer': 'self', 'owner': 'Web', 'hold': 1,
               'name': 'adm1'}
        self.assertEqual(self.save(new)[0], 200)                    # no limit: as before
        setp('Web', {'wildcards': False})
        st, words = self.save(dict(new, name='adm2', names=['*.adm2.example.test']))
        self.assertEqual(st, 403)
        self.assertIn('the team Web', words)
        # changing one: its names made a wildcard - refused; other fields still saved
        cid = A.cert_save(STORE, {'name': 'adm3', 'names': ['adm3.example.test'],
                                  'issuer': 'self', 'owner': 'Web', 'hold': 1}, 'test')
        self.assertEqual(self.save({'id': cid, 'names': ['*.adm3.example.test']})[0], 403)
        self.assertEqual(self.save({'id': cid, 'note': 'fine'})[0], 200)
        # a full administrator is never limited
        self.assertEqual(outcome(admin, 'POST', '/api/certs/save',
                                 dict(new, name='adm4'))[0], 200)

    def test_pairs(self):
        setp('Web', {'pairs': {'self': ['dnsA']}})
        new = {'names': ['pa.example.test'], 'issuer': 'self', 'challenge': 'dnsB',
               'owner': 'Web', 'hold': 1, 'name': 'pa1'}
        st, words = self.save(new)
        self.assertEqual(st, 403)
        self.assertIn('proved by dnsA only', words)
        st, _w = self.save(dict(new, issuer='other', challenge='dnsA'))
        self.assertEqual(st, 403)
        # a name's own validation (challenge_map) too
        st, _w = self.save(dict(new, challenge='dnsA',
                                challenge_map={'pa.example.test': 'dnsB'}))
        self.assertEqual(st, 403)
        # the right pair: past the limits (the route may still say what does not fit)
        self.assertNotEqual(self.save(dict(new, challenge='dnsA'))[0], 403)
        # an existing certificate: its validation changed to one not paired
        # no source said: the default one is checked (here 'other' made the default)
        from acmelib.certs import defaults as DF
        real = DF.default_issuer
        DF.default_issuer = lambda store: S.plugin_row(store, 'issuer', 'other')
        try:
            st, words = self.save({'names': ['pd.example.test'], 'owner': 'Web', 'hold': 1,
                                   'name': 'pd1'})
        finally:
            DF.default_issuer = real
        self.assertEqual(st, 403)
        self.assertIn('the source other', words)
        cid = A.cert_save(STORE, {'name': 'pa2', 'names': ['pa2.example.test'],
                                  'issuer': 'self', 'owner': 'Web', 'hold': 1}, 'test')
        self.assertEqual(self.save({'id': cid, 'challenge': 'dnsB'})[0], 403)
        self.assertEqual(self.save({'id': cid, 'note': 'kept'})[0], 200)


class NoSourcesOrValidations(unittest.TestCase):
    def test_teams_never_make_them(self):
        clean()
        E.CONFIG.update(certs_certadmin_all=0)
        tree(members=[{'who': 'local:own', 'roles': ['Team owner']}])
        for path, kind in (('/api/sources/save', 'selfsigned'),
                           ('/api/validations/save', 'dns_builtin'),
                           ('/api/sources/delete', None), ('/api/validations/delete', None),
                           ('/api/sources/default', None)):
            body = {'name': 'mine', 'kind': kind} if kind else {'id': 1, 'name': 'self'}
            for role in ('certadmin', 'readonly'):
                self.assertEqual(outcome(admin, 'POST', path, body, who='own', role=role)[0],
                                 403, (path, role))
        # the portal has no route that makes them, and a test is never saved as another family
        self.assertFalse([k for k in E.ROUTES if k[1].startswith('/api/portal/') and
                          any(w in k[1] for w in ('source', 'validation', 'issuer',
                                                  'challenge'))])
        self.assertIsNone(STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'mine'"))


class Migration(unittest.TestCase):
    def test_old_cert_tests(self):
        path = os.path.join(TMP, 'old-tests.db')
        c = sqlite3.connect(path)
        c.execute('CREATE TABLE cert_tests (id INTEGER PRIMARY KEY AUTOINCREMENT, name '
                  'VARCHAR(190) NOT NULL UNIQUE, kind VARCHAR(190), config TEXT, state TEXT, '
                  'enabled INTEGER, note TEXT, created REAL, created_by VARCHAR(190), updated '
                  'REAL, last_ok REAL, last_error TEXT, tags TEXT)')
        c.execute("INSERT INTO cert_tests (name, kind, config) VALUES ('old1', 'https', '{}')")
        c.commit()
        c.close()
        for _ in range(2):                                    # idempotent
            db = E.Db('sqlite', path=path)
            db.make_tables()
            self.assertIn('owner', db.columns('cert_tests'))
            row = db.row("SELECT * FROM cert_tests WHERE name = 'old1'")
            self.assertIsNone(row['owner'])                   # acme's own, as before
            db.close()
        self.assertIn('cert_tests', E.carry_tables())         # backup, export, HA


class PortalTests(unittest.TestCase):
    def setUp(self):
        clean()
        tree(members=[{'who': 'local:dm', 'roles': ['Device manager']},
                      {'who': 'local:vw', 'roles': ['Viewer']},
                      {'who': 'local:dp', 'roles': ['Deployer']}])
        T.save_team(STORE, {'name': 'Other', 'members': [
            {'who': 'local:om', 'roles': ['Device manager']}]}, 'x')
        # acme's own test and one of the other team
        A.family_save(STORE, 'check', {'name': 'acme1', 'kind': 'https',
                                       'config': {'host': 'acme.example.test'}}, 'test')
        A.family_save(STORE, 'check', {'name': 'oth1', 'kind': 'https', 'owner': 'Other',
                                       'config': {'host': 'oth.example.test'}}, 'test')
        self.real_test = A.family_test
        A.family_test = lambda *a, **k: {'ok': True, 'said': 'stub', 'job_id': 'j',
                                         'steps': []}

    def tearDown(self):
        A.family_test = self.real_test

    def add(self, who='dm', **b):
        body = {'team': 'Web', 'name': 'web-https', 'kind': 'https',
                'config': {'host': 'web.example.test'}}
        body.update(b)
        return outcome(portal, who, 'POST', 'test_save', body)

    def test_scoping(self):
        self.assertEqual(self.add()[0], 200)
        tid = STORE.db.value("SELECT id FROM cert_tests WHERE name = 'web-https'")
        self.assertEqual(STORE.db.value('SELECT owner FROM cert_tests WHERE id = ?', (tid,)),
                         'Web')
        rows = portal('vw', 'GET', 'tests', args={'team': 'Web'})['rows']
        self.assertEqual([r['name'] for r in rows], ['web-https'])  # never acme's, nor Other's
        self.assertFalse(portal('vw', 'GET', 'tests', args={'team': 'Web'})['may']['manage'])
        self.assertEqual(outcome(portal, 'vw', 'GET', 'test', args={'id': tid})[0], 200)
        # a Viewer neither adds, nor changes, deletes or runs
        self.assertEqual(self.add('vw', name='v2')[0], 403)
        for route in ('test_run', 'test_delete'):
            self.assertEqual(outcome(portal, 'vw', 'POST', route, {'id': tid})[0], 403)
        # a Deployer (no test capability... but a Viewer's view) sees, does not manage
        self.assertEqual(outcome(portal, 'dp', 'GET', 'tests', args={'team': 'Web'})[0], 200)
        self.assertEqual(self.add('dp', name='d2')[0], 403)
        # another team's member: 404 (not theirs), Web's tests not seen
        self.assertEqual(outcome(portal, 'om', 'GET', 'test', args={'id': tid})[0], 404)
        self.assertEqual(outcome(portal, 'om', 'GET', 'tests', args={'team': 'Web'})[0], 404)
        oth = STORE.db.value("SELECT id FROM cert_tests WHERE name = 'oth1'")
        own = STORE.db.value("SELECT id FROM cert_tests WHERE name = 'acme1'")
        for ident in (oth, own):
            self.assertEqual(outcome(portal, 'dm', 'GET', 'test', args={'id': ident})[0], 404)
            self.assertEqual(outcome(portal, 'dm', 'POST', 'test_delete', {'id': ident})[0],
                             404)
            self.assertEqual(outcome(portal, 'dm', 'POST', 'test_save',
                                     {'id': ident, 'team': 'Web', 'note': 'mine'})[0], 404)
        # a test given to another team: refused
        self.assertEqual(self.add(name='w3', team='Other')[0], 404)
        # run, change, delete by the Device manager
        self.assertTrue(portal('dm', 'POST', 'test_run', {'id': tid})['ok'])
        self.assertEqual(outcome(portal, 'dm', 'POST', 'test_save',
                                 {'id': tid, 'note': 'changed'})[0], 200)
        self.assertEqual(outcome(portal, 'dm', 'POST', 'test_delete', {'id': tid})[0], 200)
        self.assertIsNone(STORE.db.value('SELECT id FROM cert_tests WHERE id = ?', (tid,)))
        # a person in no team: refused
        self.assertEqual(outcome(portal, 'nobody', 'GET', 'tests', args={'team': 'Web'})[0],
                         404)

    def test_test_kinds(self):
        setp('Web', {'test_kinds': ['smtp']})
        st, words = self.add()
        self.assertEqual(st, 403)
        self.assertIn('the team Web', words)
        self.assertIn('smtp', words)
        self.assertEqual(self.add(kind='smtp', config={'host': 'mail.example.test'})[0], 200)
        kinds = portal('dm', 'GET', 'test_kinds', args={'team': 'Web'})
        self.assertEqual([k['kind'] for k in kinds['kinds']], ['smtp'])
        self.assertEqual(kinds['limit'], ['smtp'])
        # above it narrower: intersection
        setp('Top', {'test_kinds': ['https']})
        self.assertEqual(portal('dm', 'GET', 'test_kinds', args={'team': 'Web'})['kinds'], [])
        setp('Top', {})
        setp('Web', {})
        self.assertTrue(len(portal('dm', 'GET', 'test_kinds', args={'team': 'Web'})['kinds'])
                        > 5)

    def test_secrets_never_returned(self):
        got = portal('dm', 'POST', 'test_save', {
            'team': 'Web', 'name': 'relay1', 'kind': 'ssh_relay',
            'config': {'host': 'relay.example.test', 'user': 'u', 'auth': 'password',
                       'password': SECRET}})
        tid = got['id']
        answers = [got, portal('dm', 'GET', 'test', args={'id': tid}),
                   portal('dm', 'GET', 'tests', args={'team': 'Web'})]
        for a in answers:
            text = json.dumps(a)
            self.assertNotIn(SECRET, text)
            self.assertNotIn('sealed:', text)
            self.assertNotIn('•', text)
        one = answers[1]['test']
        self.assertEqual(one['config']['password'], '')
        self.assertTrue(one['secrets']['password'])
        # the host moved with the secret kept: refused (it would go to the new place)
        st, words = outcome(portal, 'dm', 'POST', 'test_save', {
            'id': tid, 'config': dict(one['config'], host='evil.example.test')})
        self.assertEqual(st, 403)
        self.assertIn('type them again', words)

    def test_connectors_of_the_team_only(self):
        A.family_save(STORE, 'check', {'name': 'relay-other', 'kind': 'ssh_relay',
                                       'owner': 'Other', 'config': {'host': 'r.example.test',
                                                                    'user': 'u'}}, 'test')
        A.family_save(STORE, 'check', {'name': 'relay-acme', 'kind': 'ssh_relay',
                                       'config': {'host': 'r2.example.test', 'user': 'u'}},
                      'test')
        for via in ('relay-other', 'relay-acme'):
            st, words = self.add(name='v-' + via, config={'host': 'x.example.test',
                                                          'via': via})
            self.assertEqual(st, 403, via)
            self.assertIn('not a connector of the team Web', words)
        portal('dm', 'POST', 'test_save', {'team': 'Web', 'name': 'relay-web',
                                           'kind': 'ssh_relay',
                                           'config': {'host': 'r3.example.test', 'user': 'u'}})
        self.assertEqual(self.add(name='v-ok', config={'host': 'x.example.test',
                                                       'via': 'relay-web'})[0], 200)
        # the form offers the team's connector only
        kinds = portal('dm', 'GET', 'test_kinds', args={'team': 'Web'})['kinds']
        https = [k for k in kinds if k['kind'] == 'https'][0]
        via = [f for f in https['fields'] if f.get('key') == 'via'][0]
        self.assertEqual(sorted(o[0] for o in via['options']), ['', 'relay-web'])
        # a connector's old list of tests: the team's own only
        st, _w = outcome(portal, 'dm', 'POST', 'test_save', {
            'team': 'Web', 'name': 'relay-x', 'kind': 'ssh_relay',
            'config': {'host': 'r4.example.test', 'user': 'u', 'tests': ['oth1']}})
        self.assertEqual(st, 403)

    def test_team_renamed_and_deleted(self):
        self.add()
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web2'}, 'x')
        self.assertEqual(STORE.db.value("SELECT owner FROM cert_tests WHERE name = "
                                        "'web-https'"), 'Web2')
        T.delete_team(STORE, 'Web2', 'x')
        self.assertIsNone(STORE.db.value("SELECT owner FROM cert_tests WHERE name = "
                                         "'web-https'"))

    def test_admin_owner(self):
        tid = A.family_save(STORE, 'check', {'name': 'adm-t', 'kind': 'https',
                                             'owner': 'Web', 'config': {'host': 'a.test'}},
                            'test')
        self.assertEqual(S.plugin_public(STORE, 'check', S.plugin_row(STORE, 'check', tid))
                         ['owner'], 'Web')
        with self.assertRaises(ValueError):
            A.family_save(STORE, 'check', {'id': tid, 'owner': 'Nope'}, 'test')
        A.family_save(STORE, 'check', {'id': tid, 'owner': ''}, 'test')
        self.assertIsNone(STORE.db.value('SELECT owner FROM cert_tests WHERE id = ?', (tid,)))

    def test_policy_catalog(self):
        T.save_team(STORE, {'old_name': 'Top', 'name': 'Top', 'members': [
            {'who': 'local:tm', 'roles': ['Team manager']}],
            'policy': {'issuers': ['self'], 'pairs': {'self': ['dnsA']}}}, 'x')
        got = portal('tm', 'GET', 'policy_catalog', args={'team': 'Top'})
        self.assertEqual([r['name'] for r in got['sources']], ['self'])
        self.assertEqual(sorted(r['name'] for r in got['validations']), ['dnsA', 'dnsB'])
        self.assertNotIn('config', json.dumps(got))
        self.assertEqual(outcome(portal, 'vw', 'GET', 'policy_catalog',
                                 args={'team': 'Web'})[0], 403)
        # the designer: a team below never wider
        st, words = outcome(portal, 'tm', 'POST', 'team_save', {
            'old_name': 'Web', 'policy': {'pairs': {'self': ['dnsA', 'dnsB']}}})
        self.assertEqual(st, 403)
        self.assertIn('pairs', words)
        self.assertEqual(outcome(portal, 'tm', 'POST', 'team_save', {
            'old_name': 'Web', 'policy': {'pairs': {'self': ['dnsA']}, 'wildcards': False,
                                          'test_kinds': ['https']}})[0], 200)
        self.assertEqual(T.policy_of(T.team_get(STORE, 'Web'))['test_kinds'], ['https'])


class Cli(unittest.TestCase):
    def test_policy_and_show(self):
        clean()
        import io
        from contextlib import redirect_stdout
        T.save_team(STORE, {'name': 'Web', 'policy': T.clean_policy(
            '{"wildcards": false, "pairs": {"self": ["dnsA"]}, "test_kinds": ["https"]}')},
            'x')
        c = type('C', (), {'store': STORE, 'json': False})()
        buf = io.StringIO()
        with redirect_stdout(buf):
            api_teams._cli_show(c, 'Web')
        out = buf.getvalue()
        self.assertIn('"wildcards": false', out)
        self.assertIn('"pairs": {"self": ["dnsA"]}', out)
        self.assertIn('"test_kinds": ["https"]', out)


class UiPage(unittest.TestCase):
    """The limit editor of the administration in Chromium (test/team_limits_ui_page.js) against
    a real daemon and php -S: the rows of the new limits, the pairs editor offering the
    catalog's sources and validations, a pair added and saved."""

    @classmethod
    def setUpClass(cls):
        import shutil
        cls.node = shutil.which('node')
        if not cls.node or not shutil.which('php') or subprocess_ok(
                [cls.node, '-e', 'require("playwright")']) is False:
            raise unittest.SkipTest('no node, php or playwright here')
        import test_certs_core as TCC
        import test_teams_admin_ui as TAU
        cls.TCC, cls.TAU = TCC, TAU
        cls.call = classmethod(TCC.CertsCore.__dict__['call'].__func__)
        cls.login = classmethod(TCC.CertsCore.__dict__['login'].__func__)
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.started = True
        for name in ('self', 'other'):
            cls.must('POST', '/api/sources/save', {'name': name, 'kind': 'selfsigned',
                                                   'config': {'days': 40}})
        TAU.Pages.sql.__func__(cls, [
            ("INSERT INTO cert_challenges (name, kind, config, enabled, state) VALUES "
             "(?, 'dns_builtin', '{}', 1, '{}')", (n,)) for n in ('dnsA', 'dnsB')])
        cls.must('POST', '/api/teams/save', {'name': 'Web', 'members': [
            {'who': 'local:tester', 'rights': ['manage']}],
            'policy': {'wildcards': False, 'pairs': {'self': ['dnsA']},
                       'test_kinds': ['https']}})

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'started', False):
            cls.TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None, args=None):
        st, got = cls.call(method, path, body, cls.admin, args)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def test_limit_editor(self):
        import subprocess
        php, base = self.TAU.Pages.pages.__func__(self.__class__)
        try:
            got = subprocess.run([self.node, os.path.join(HERE, 'team_limits_ui_page.js'), base,
                                  self.pw], capture_output=True, text=True, timeout=600,
                                 cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [], seen)
        for key in ('wildcards', 'pairs', 'test_kinds'):
            self.assertIn(key, seen['rows'], seen)
        self.assertEqual(seen['wildcardsOn'], 'no', seen)
        self.assertEqual(len(seen['pairsShown']), 1, seen)
        self.assertIn('other', seen['pairsOffer'], seen)
        # the test modules from the catalog ('https' chosen already, the others offered)
        self.assertIn('smtp', seen['testKinds'], seen)
        self.assertNotIn('https', seen['testKinds'], seen)
        t = [x for x in self.must('GET', '/api/teams')['teams'] if x['name'] == 'Web'][0]
        self.assertEqual(t['policy']['pairs'], {'self': ['dnsA'], 'other': ['dnsB']}, seen)
        self.assertIs(t['policy']['wildcards'], False)


def subprocess_ok(argv):
    import subprocess
    try:
        return subprocess.run(argv, capture_output=True, timeout=60, cwd=ROOT).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


if __name__ == '__main__':
    unittest.main(verbosity=1)
