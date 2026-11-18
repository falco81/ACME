#!/usr/bin/env python3
"""Enterprise teams (1.0.125, docs/teams.md "Enterprise teams").

    python3 test/test_teams_enterprise.py

- the tree: parent, a circle refused, a rename followed by the teams below and the devices,
  a team with teams below deleted only with reparent;
- capabilities inherited downwards; the limits narrowed downwards (intersection);
- every built-in role's capabilities; the old rights give exactly what they gave;
- the guard maps each route to its capability (a Renewer renews, does not revoke);
- the limits refuse in words naming the team: free form, profiles, sources, suffixes,
  max_certs, max_days, key download, device modules, deployments; a scoped certificate
  administrator's new certificate; approval "always" makes it wait;
- approvals: two approvers (four-eyes), the team then the team above, self, outside the
  envelope, none; each approval recorded in the timeline; "Waiting for you";
- roles: custom roles saved, renamed, deleted (strip); only a full administrator writes;
- the directory: the access check, the search (the text never a filter), a group's members,
  teams from groups (dry run and made) - against test/mockldap.py;
- an old database given the new columns and table; export and import carry roles, parent,
  policy and the owner of targets; the configuration's tables (backup, HA) hold cert_roles;
- a team's enrollment code makes the team's devices.
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
TMP = tempfile.mkdtemp(prefix='acme-teams-ent-')
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
from acmelib.certs import portal as P  # noqa: E402
from acmelib.certs import api_teams  # noqa: E402,F401
import mockldap  # noqa: E402

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
BASE = 'DC=corpnet,DC=loc'


class FakeH(object):
    def __init__(self, who='boss', role='fulladmin', body=None, args=None, source='local',
                 groups='', portal=None, dirs=None):
        self.store, self._body, self.args = STORE, dict(body or {}), dict(args or {})
        self.who, self.role, self.source, self.groups, self.portal = who, role, source, groups, \
            portal
        self.headers = {}
        self.d = type('D', (), {'dirs': dirs or {}})()

    def me(self, _role='readonly'):
        return {'name': self.who, 'role': self.role,
                'account': {'name': self.who, 'role': self.role, 'source': self.source,
                            'dn': ('CN=%s,OU=People,%s' % (self.who, BASE))
                            if self.source == 'directory' else '',
                            'group_list': self.groups}}

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


def call(method, path, body=None, args=None, **who):
    return E.ROUTES[(method, path)](FakeH(body=body, args=args, **who))


def status(fn, *a, **kw):
    try:
        fn(*a, **kw)
        return 200
    except E.ApiError as e:
        return e.status
    except LookupError:
        return 404
    except ValueError:
        return 400


def may(method, path, body=None, args=None, **who):
    return status(call, method, path, body, args, **who)


def clean():
    for t in ('certs', 'cert_teams', 'cert_tags', 'cert_versions', 'cert_jobs', 'cert_deploys',
              'cert_targets', 'cert_roles', 'cert_req_profiles'):
        STORE.db.run('DELETE FROM %s' % t)
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:portal:%' OR k LIKE 'teams:action:%'")
    T.changed()
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1, certs_notify_mail='',
                    portal=1, portal_cert=1, portal_local=1, mail_mode='off',
                    portal_cert_auto=1, portal_cert_suffixes='example.test',
                    portal_cert_issuers='self', portal_cert_max=100)
    for n in ('eva', 'mgr', 'lead', 'lead1', 'lead2', 'boss', 'marta'):
        if not STORE.account(n):
            STORE.add_account(n, 'readonly', 'Local-Only-Pw-77!x' + n)
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
        STORE.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'other'"):
        STORE.db.insert('cert_issuers', {'name': 'other', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})


def cert(name, owner='', **more):
    b = {'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
         'key_type': 'ec-256', 'auto_renew': 0, 'owner': owner, 'hold': 1}
    b.update(more)
    return A.cert_save(STORE, b, 'test')


def person(name, local=True, groups=(), mail=''):
    data = {'kind': 'local' if local else 'directory', 'mail': mail, 'about': {'upn': mail},
            'cert_groups': [list(g) for g in groups], 'cert_groups_at': time.time(),
            'dn': 'CN=%s,%s' % (name, BASE), 'dir_checked': time.time()}
    return {'name': name, 'data': data, 'kind': 'portal'}


def portal(s, method, path, body=None):
    return E.ROUTES[(method, path)](FakeH(portal=s, body=body))


def portal_status(s, method, path, body=None):
    return status(portal, s, method, path, body)


def wait_jobs():
    from acmelib.certs import jobs
    end = time.time() + 20
    while time.time() < end and (jobs.RUNNING or jobs.BUSY_CERTS):
        time.sleep(0.05)


class Tree(unittest.TestCase):
    def setUp(self):
        clean()

    def test_parent_circle_rename_delete(self):
        T.save_team(STORE, {'name': 'Europe', 'kind': 'unit'}, 'x')
        T.save_team(STORE, {'name': 'Prague', 'kind': 'unit', 'parent': 'Europe'}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Prague', 'description': 'web people'}, 'x')
        tr = T.tree(STORE)
        self.assertEqual(tr.chain('web'), ['europe', 'prague', 'web'])
        self.assertEqual(sorted(T.descendants(STORE, 'Europe')), ['Prague', 'Web'])
        # no circle: Europe under Web (below it), a team under itself
        with self.assertRaises(ValueError):
            T.save_team(STORE, {'old_name': 'Europe', 'name': 'Europe', 'parent': 'Web'}, 'x')
        with self.assertRaises(ValueError):
            T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'parent': 'Web'}, 'x')
        with self.assertRaises(LookupError):
            T.save_team(STORE, {'name': 'Nowhere', 'parent': 'Missing'}, 'x')
        # a device of the team; renamed, the children and the device follow
        STORE.db.insert('cert_targets', {'name': 'dev1', 'kind': 'ssh', 'config': '{}',
                                         'owner': 'Prague'})
        T.save_team(STORE, {'old_name': 'Prague', 'name': 'Praha'}, 'x')
        self.assertEqual(T.team_get(STORE, 'Web')['parent'], 'Praha')
        self.assertEqual(STORE.db.value("SELECT owner FROM cert_targets WHERE name = 'dev1'"),
                         'Praha')
        # deleted with teams below: refused, then moved to the top / another team
        with self.assertRaises(ValueError):
            T.delete_team(STORE, 'Praha', 'x')
        with self.assertRaises(LookupError):
            T.delete_team(STORE, 'Praha', 'x', reparent='Web')       # below it
        got = T.delete_team(STORE, 'Praha', 'x', reparent='Europe')
        self.assertEqual((got['children'], got['reparented_to']), (['Web'], 'Europe'))
        self.assertEqual(T.team_get(STORE, 'Web')['parent'], 'Europe')
        self.assertIsNone(STORE.db.value("SELECT owner FROM cert_targets WHERE name = 'dev1'"))
        # a team saved as before keeps NULL in the new columns
        T.save_team(STORE, {'name': 'Plain', 'members': ['local:a']}, 'x')
        row = T.team_get(STORE, 'Plain')
        self.assertEqual((row['parent'], row['policy'], row['description']), (None, None, None))
        # GET /api/teams: the tree, roles, caps
        got = call('GET', '/api/teams')
        self.assertEqual([n['name'] for n in got['tree']], ['Europe', 'Web', 'Plain'])
        self.assertEqual(got['tree'][1]['depth'], 1)
        self.assertIn('Team owner', [r['name'] for r in got['roles']])
        self.assertEqual(len(got['caps']), len(T.CAPS))
        web = [t for t in got['teams'] if t['name'] == 'Web'][0]
        self.assertEqual((web['parent'], web['description']), ('Europe', 'web people'))

    def test_inheritance_and_intersection(self):
        T.save_team(STORE, {'name': 'Top', 'members': [
            {'who': 'local:boss2', 'roles': ['Certificate manager']}],
            'policy': {'suffixes': ['example.test'], 'max_days': 200,
                       'issuers': ['self', 'other'], 'key_download': True}}, 'x')
        T.save_team(STORE, {'name': 'Mid', 'parent': 'Top',
                            'policy': {'suffixes': ['a.example.test', 'elsewhere.test'],
                                       'max_days': 400, 'issuers': ['self']}}, 'x')
        T.save_team(STORE, {'name': 'Leaf', 'parent': 'Mid', 'policy': {'key_download': False}},
                    'x')
        eff = T.effective_policy(STORE, 'Leaf')
        self.assertEqual(eff['suffixes'], ['a.example.test'])     # elsewhere.test not widened
        self.assertEqual(eff['max_days'], 200)                    # the parent's narrower
        self.assertEqual(eff['issuers'], ['self'])
        self.assertFalse(eff['key_download'])
        self.assertEqual(eff['from']['max_days'], 'Top')
        caps = T.person_caps(STORE, {'local:boss2'}, [])
        self.assertEqual(sorted(caps), ['leaf', 'mid', 'top'])
        self.assertIn('cert.revoke', caps['leaf']['caps'])
        self.assertEqual(caps['leaf']['direct'], frozenset())
        # scope: certificates of the teams below seen and managed
        E.CONFIG.update(certs_certadmin_all=0)
        cid = cert('leafcert', 'Leaf')
        self.assertEqual(may('POST', '/api/certs/renew', {'id': cid}, who='boss2',
                             role='certadmin') in (200, 400, 409), True)
        self.assertEqual(T.scope(STORE, {'name': 'boss2', 'role': 'certadmin'}, 'manage'),
                         {'top', 'mid', 'leaf'})
        # an expired membership gives nothing
        T.save_team(STORE, {'old_name': 'Top', 'name': 'Top', 'members': [
            {'who': 'local:boss2', 'roles': ['Viewer'], 'until': time.time() - 5}]}, 'x')
        self.assertEqual(T.person_caps(STORE, {'local:boss2'}, []), {})

    def test_policy_clean(self):
        with self.assertRaises(ValueError):
            T.clean_policy({'nonsense': 1})
        with self.assertRaises(ValueError):
            T.clean_policy({'approval': {'mode': 'sometimes'}})
        self.assertEqual(T.clean_policy({'approval': 'always'}), {'approval': {'mode': 'always'}})
        self.assertEqual(T.clean_policy('{"max_certs": "5"}'), {'max_certs': 5})
        self.assertEqual(T.clean_policy({}), {})


class Roles(unittest.TestCase):
    def setUp(self):
        clean()

    def test_builtin_roles_caps(self):
        want = {
            # test.view (1.0.128): every role built on the Viewer sees the team's tests
            'Viewer': {'cert.view', 'deploy.view', 'target.view', 'team.view', 'test.view'},
        }
        want['Requester'] = want['Viewer'] | {'cert.request'}
        want['Renewer'] = want['Viewer'] | {'cert.renew', 'cert.auto'}
        want['Deployer'] = want['Viewer'] | {'deploy.run'}
        want['Device manager'] = want['Viewer'] | {'target.manage', 'target.test',
                                                    'deploy.manage', 'deploy.run'}
        want['Certificate manager'] = want['Requester'] | want['Renewer'] | {
            'cert.edit', 'cert.revoke', 'cert.delete', 'cert.key', 'deploy.run', 'deploy.manage'}
        want['Approver'] = want['Viewer'] | {'cert.approve'}
        want['Team manager'] = want['Viewer'] | {'team.members', 'team.policy', 'team.create',
                                                  'team.activity'}
        # 1.0.128: the Device manager manages the team's tests
        want['Device manager'] |= {'test.manage'}
        want['Team owner'] = set(T.CAPS)
        got = {r['name']: set(r['caps']) for r in T.roles(STORE) if r['builtin']}
        self.assertEqual(got, want)
        self.assertEqual(len(T.CAPS), 22)

    def test_old_rights_unchanged(self):
        self.assertEqual(T.RIGHT_CAPS['view'], {'cert.view', 'deploy.view', 'target.view',
                                                'team.view'})
        for right, implies in T.IMPLIES.items():
            self.assertEqual(T.rights_of_caps(T.RIGHT_CAPS[right]), implies, right)
        T.save_team(STORE, {'name': 'Web', 'members': ['local:a=manage', 'local:b=view',
                                                       'local:c=approve',
                                                       'local:d=request,approve']}, 'x')
        for who, rights in (('a', {'view', 'request', 'manage'}), ('b', {'view'}),
                            ('c', {'view', 'approve'}), ('d', {'view', 'request', 'approve'})):
            self.assertEqual(T.person_teams(STORE, {'local:' + who}, [])['web'][1], rights, who)
        # stored as before: no roles / until keys
        self.assertEqual(T.team_get(STORE, 'Web')['members'],
                         json.dumps([{'who': 'local:a', 'rights': ['manage']},
                                     {'who': 'local:b', 'rights': ['view']},
                                     {'who': 'local:c', 'rights': ['approve']},
                                     {'who': 'local:d', 'rights': ['request', 'approve']}]))

    def test_custom_roles(self):
        got = T.save_role(STORE, {'name': 'Ops', 'caps': ['cert.view', 'cert.renew'],
                                  'description': 'night shift'}, 'x')
        self.assertEqual(got['caps'], ['cert.view', 'cert.renew'])
        with self.assertRaises(ValueError):
            T.save_role(STORE, {'name': 'Viewer', 'caps': ['cert.view']}, 'x')
        with self.assertRaises(ValueError):
            T.save_role(STORE, {'name': 'Bad', 'caps': ['cert.fly']}, 'x')
        T.save_team(STORE, {'name': 'Web', 'members': ['local:z=Ops+Deployer']}, 'x')
        m = json.loads(T.team_get(STORE, 'Web')['members'])[0]
        self.assertEqual((m['rights'], m['roles']), ([], ['Ops', 'Deployer']))
        with self.assertRaises(ValueError):
            T.save_team(STORE, {'name': 'X', 'members': [{'who': 'a', 'roles': ['Nope']}]}, 'x')
        T.save_role(STORE, {'old_name': 'Ops', 'name': 'Operators'}, 'x')
        m = json.loads(T.team_get(STORE, 'Web')['members'])[0]
        self.assertEqual(m['roles'], ['Operators', 'Deployer'])
        with self.assertRaises(ValueError):
            T.delete_role(STORE, 'Operators', 'x')
        T.delete_role(STORE, 'Operators', 'x', strip=True)
        m = json.loads(T.team_get(STORE, 'Web')['members'])[0]
        self.assertEqual(m['roles'], ['Deployer'])
        # only a full administrator writes
        for path, body in (('/api/roles/save', {'name': 'R1', 'caps': ['cert.view']}),
                           ('/api/teams/save', {'name': 'New'}),
                           ('/api/roles/delete', {'name': 'R1'})):
            self.assertEqual(may('POST', path, body, who='c', role='certadmin'), 403, path)
        self.assertEqual(may('POST', '/api/roles/save', {'name': 'R1', 'caps': 'cert.view'}),
                         200)


class Guard(unittest.TestCase):
    """Each route its capability; the old manage keeps everything."""
    def setUp(self):
        clean()
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:old', 'rights': ['manage']},
            {'who': 'local:ren', 'roles': ['Renewer']},
            {'who': 'local:dep', 'roles': ['Deployer']},
            {'who': 'local:cm', 'roles': ['Certificate manager']},
            {'who': 'local:dm', 'roles': ['Device manager']},
            {'who': 'local:ap', 'roles': ['Approver']}]}, 'x')
        self.cid = cert('g1', 'Web')

    def can(self, who, path, body):
        st = may('POST', path, dict(body), who=who, role='certadmin')
        return st != 403

    def test_routes(self):
        cid = self.cid
        cases = [
            ('/api/certs/auto', {'id': cid, 'on': 0}, {'old', 'ren', 'cm'}),
            ('/api/certs/hold', {'id': cid, 'on': 1}, {'old', 'ren', 'cm'}),
            ('/api/certs/save', {'id': cid, 'note': 'n'}, {'old', 'cm'}),
            ('/api/certs/export', {'id': cid, 'format': 'cert-pem'}, {'old', 'cm'}),
            # the old right manage approves (as before); the role Certificate manager does not
            ('/api/certs/approve', {'id': cid, 'ok': 0, 'why': 'no'}, {'old', 'ap'}),
        ]
        for path, body, yes in cases:
            for who in ('old', 'ren', 'dep', 'cm', 'dm', 'ap'):
                self.assertEqual(self.can(who, path, body), who in yes, (path, who))
        # the capability each needs, without running them
        self.assertEqual(T.route_cap('/api/certs/renew'), 'cert.renew')
        self.assertEqual(T.route_cap('/api/certs/revoke'), 'cert.revoke')
        self.assertEqual(T.route_cap('/api/certs/delete'), 'cert.delete')
        self.assertEqual(T.route_cap('/api/certs/deploy'), 'deploy.run')
        self.assertEqual(T.route_cap('/api/certs/export', {'format': 'pfx'}), 'cert.key')
        for who, cap, yes in (('ren', 'cert.renew', True), ('ren', 'cert.revoke', False),
                              ('dep', 'deploy.run', True), ('dep', 'deploy.manage', False),
                              ('dm', 'deploy.manage', True), ('cm', 'cert.delete', True),
                              ('old', 'cert.delete', True), ('old', 'deploy.manage', True),
                              ('ap', 'cert.renew', False)):
            got = T.cert_may(STORE, {'name': who, 'role': 'certadmin'}, {'owner': 'Web'}, cap)
            self.assertEqual(got, yes, (who, cap))
        # the defaults: certificate administrators manage everything, as before
        E.CONFIG.update(certs_certadmin_all=1)
        self.assertTrue(self.can('dep', '/api/certs/save', {'id': cid, 'note': 'n'}))
        self.assertIsNone(T.scope_cap(STORE, {'name': 'x', 'role': 'certadmin'}, 'cert.delete'))


class Limits(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Top', 'policy': {'suffixes': ['example.test']}}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Top', 'members': [
            'local:eva=request', 'local:mgr=manage', 'local:lead=approve']}, 'x')
        self.eva = person('eva')

    def tearDown(self):
        wait_jobs()

    def ask(self, names, team='Web', who=None):
        return portal(who or self.eva, 'POST', '/api/portal/cert_request',
                      {'names': names, 'issuer': 'self', 'team': team})

    def refused(self, names, words, team='Web'):
        try:
            self.ask(names, team)
        except E.ApiError as e:
            self.assertEqual(e.status, 403)
            self.assertIn(words, str(e))
            return str(e)
        self.fail('not refused')

    def set(self, team, policy):
        T.save_team(STORE, {'old_name': team, 'name': team, 'policy': policy}, 'x')

    def test_no_policy_as_before(self):
        T.save_team(STORE, {'old_name': 'Top', 'name': 'Top', 'policy': {}}, 'x')
        got = self.ask(['free.example.test'])
        self.assertFalse(got['waits'])

    def test_refusals_name_the_team(self):
        self.set('Web', {'suffixes': ['web.example.test']})
        self.refused(['x.example.test'], 'the team Web')
        self.set('Web', {'suffixes': ['other.test']})       # wider than Top's: nothing allowed
        self.refused(['x.other.test'], 'not under the names')
        self.set('Web', {'free_form': False})
        self.refused(['w.example.test'], 'request profile only')
        self.set('Web', {'issuers': ['other']})
        self.refused(['w.example.test'], 'the source self')
        self.set('Top', {'max_certs': 1})
        self.set('Web', {})
        self.ask(['one.example.test'])
        msg = self.refused(['two.example.test'], 'the team Top')
        self.assertIn('1 certificate', msg)
        words = [r['words'] for r in STORE.db.rows(
            "SELECT words FROM events WHERE words LIKE '%refused by the limits of the team%'")]
        self.assertTrue(words)

    def test_approval_modes(self):
        E.CONFIG.update(portal_cert_auto=0)
        self.set('Web', {'approval': {'mode': 'none'}})
        self.assertFalse(self.ask(['n1.example.test'])['waits'])
        E.CONFIG.update(portal_cert_auto=1)
        self.set('Web', {'approval': 'always'})                  # the old word still read
        self.assertTrue(self.ask(['n2.example.test'])['waits'])
        self.set('Web', {'approval': {'mode': 'outside',
                                      'outside': {'suffixes': ['in.example.test']}}})
        self.assertFalse(self.ask(['a.in.example.test'])['waits'])
        self.assertTrue(self.ask(['a.out.example.test'])['waits'])

    def test_key_download_and_devices(self):
        self.set('Web', {'key_download': False, 'target_kinds': ['ssh', 'agent'],
                         'agents': False})
        with self.assertRaises(E.ApiError) as e:
            TP.need_key_download(STORE, 'Web', 'eva')
        self.assertIn('the team Web', str(e.exception))
        TP.need_key_download(STORE, 'Top', 'eva')               # Top allows it
        TP.need_target_kind(STORE, 'Web', 'ssh')
        for kind in ('f5', 'agent'):
            with self.assertRaises(E.ApiError):
                TP.need_target_kind(STORE, 'Web', kind)
        T.save_team(STORE, {'name': 'Other'}, 'x')
        tgt = {'name': 'dev', 'kind': 'ssh', 'owner': 'Other'}
        with self.assertRaises(E.ApiError):
            TP.need_deploy(STORE, {'owner': 'Web'}, tgt, 'eva')
        TP.need_deploy(STORE, {'owner': 'Web'}, dict(tgt, owner='Web'), 'eva')
        # a key on the portal: refused by the limit
        cid = cert('k1', 'Web')
        STORE.db.update('certs', cid, {'cert_pem': 'PEM', 'key_sealed': 'x', 'state': 'ok'})
        E.CONFIG.update(portal_cert_keys=1)
        st = portal_status(person('mgr'), 'POST', '/api/portal/cert_download',
                           {'id': cid, 'format': 'pfx', 'password': 'long-enough-pw'})
        self.assertEqual(st, 403)

    def test_scoped_admin(self):
        E.CONFIG.update(certs_certadmin_all=0)
        self.set('Web', {'issuers': ['self'], 'max_days': 30})
        new = {'names': ['adm.example.test'], 'issuer': 'other', 'owner': 'Web', 'hold': 1}
        self.assertEqual(may('POST', '/api/certs/save', new, who='mgr', role='certadmin'), 403)
        self.assertEqual(may('POST', '/api/certs/save', dict(new, issuer='self',
                                                              profile={'days': 90}),
                             who='mgr', role='certadmin'), 403)
        self.assertEqual(may('POST', '/api/certs/save', dict(new, issuer='self'),
                             who='mgr', role='certadmin'), 200)
        # a full administrator is never limited
        self.assertEqual(may('POST', '/api/certs/save', dict(new, issuer='other',
                                                              name='full1')), 200)
        # approval always: a scoped administrator's certificate waits, approved by another
        self.set('Web', {'approval': 'always'})
        call('POST', '/api/certs/save', {'names': ['w8.example.test'], 'issuer': 'self',
                                         'owner': 'Web', 'name': 'w8'},
             who='mgr', role='certadmin')
        row = STORE.db.row("SELECT * FROM certs WHERE name = 'w8'")
        self.assertEqual(row['state'], P.WAITING)
        self.assertEqual(may('POST', '/api/certs/approve', {'id': row['id'], 'ok': 1},
                             who='mgr', role='certadmin'), 403)          # not one's own
        self.assertEqual(may('POST', '/api/certs/approve', {'id': row['id'], 'ok': 1},
                             who='lead', role='certadmin'), 200)


class Approvals(unittest.TestCase):
    def setUp(self):
        clean()
        E.CONFIG.update(portal_cert_auto=0)
        T.save_team(STORE, {'name': 'Region', 'members': ['local:boss=approve']}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Region', 'members': [
            'local:eva=request', 'local:lead1=approve', 'local:lead2=approve'],
            'contact_mail': 'web@example.test'}, 'x')

    def tearDown(self):
        wait_jobs()

    def ask(self):
        return portal(person('eva'), 'POST', '/api/portal/cert_request',
                      {'names': ['ap%d.example.test' % int(time.time() * 1000 % 100000)],
                       'issuer': 'self', 'team': 'Web'})['id']

    def approve(self, who, cid, ok=1):
        return portal(person(who), 'POST', '/api/portal/cert_approve',
                      {'id': cid, 'ok': ok, 'why': 'fine' if ok else 'no'})

    def state(self, cid):
        return STORE.db.value('SELECT state FROM certs WHERE id = ?', (cid,))

    def test_no_rule_one_approval_recorded(self):
        cid = self.ask()
        self.approve('lead1', cid)
        self.assertEqual(self.state(cid) in ('new', 'renewing', 'ok', 'failed'), True)
        tl = TP.timeline(STORE, cid)
        self.assertEqual([e['what'] for e in tl][:3], ['asked', 'approved', 'let through'])

    def test_four_eyes(self):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web',
                            'policy': {'approval': {'mode': 'always', 'count': 2}}}, 'x')
        cid = self.ask()
        self.assertEqual(self.state(cid), P.WAITING)
        got = self.approve('lead1', cid)
        self.assertTrue(got['recorded'])
        self.assertEqual(self.state(cid), P.WAITING)
        with self.assertRaises(E.ApiError) as e:
            self.approve('lead1', cid)                            # the same person again
        self.assertEqual(e.exception.status, 409)
        waiting = TP.waiting_for(STORE, {'by': 'lead2', 'ids': ['local:lead2'],
                                         'caps': T.person_caps(STORE, {'local:lead2'}, [])})
        self.assertEqual([w['id'] for w in waiting], [cid])
        self.approve('lead2', cid)
        self.assertNotEqual(self.state(cid), P.WAITING)
        self.assertEqual(len(TP.approval_state(STORE, STORE.db.row(
            'SELECT * FROM certs WHERE id = ?', (cid,)))['approvals']), 2)

    def test_team_then_parent(self):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web',
                            'policy': {'approval': {'mode': 'always', 'approvers': 'both'}}}, 'x')
        cid = self.ask()
        with self.assertRaises(E.ApiError) as e:
            self.approve('boss', cid)                             # the team's lead first
        self.assertEqual(e.exception.status, 403)
        self.approve('lead1', cid)
        self.assertEqual(self.state(cid), P.WAITING)
        with self.assertRaises(E.ApiError):
            self.approve('lead2', cid)                            # not of the team above
        self.approve('boss', cid)
        self.assertNotEqual(self.state(cid), P.WAITING)

    def test_parent_only_and_decline(self):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {
            'approval': {'mode': 'always', 'approvers': 'parent'}}}, 'x')
        cid = self.ask()
        with self.assertRaises(E.ApiError):
            self.approve('lead1', cid)
        self.approve('boss', cid, ok=0)
        self.assertEqual(self.state(cid), P.DECLINED)

    def test_self(self):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'members': [
            'local:eva=request,approve'], 'policy': {'approval': {'mode': 'always'}}}, 'x')
        cid = self.ask()
        with self.assertRaises(E.ApiError):
            self.approve('eva', cid)
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {
            'approval': {'mode': 'always', 'self': True}}}, 'x')
        self.approve('eva', cid)
        self.assertNotEqual(self.state(cid), P.WAITING)

    def test_actions(self):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {
            'approve_actions': ['revoke'], 'approval': {'count': 2}}}, 'x')
        self.assertTrue(TP.action_needs_approval(STORE, 'Web', 'revoke'))
        self.assertFalse(TP.action_needs_approval(STORE, 'Web', 'delete'))
        rec = TP.action_ask(STORE, 'Web', 'revoke', 'web1', {'by': 'eva', 'ids': ['local:eva']})
        # asked again while it waits: the same one, not a second (hunt t10)
        self.assertEqual(TP.action_ask(STORE, 'Web', 'revoke', 'web1',
                                       {'by': 'eva', 'ids': ['local:eva']})['id'], rec['id'])
        other = TP.action_ask(STORE, 'Web', 'revoke', 'web2', {'by': 'eva', 'ids': ['local:eva']})
        self.assertNotEqual(other['id'], rec['id'])
        STORE.db.run('DELETE FROM meta WHERE k = ?', (TP.ACTION_META + other['id'],))
        ap = lambda who: {'by': who, 'ids': ['local:' + who],
                          'caps': T.person_caps(STORE, {'local:' + who}, [])}
        with self.assertRaises(E.ApiError):
            TP.action_approve(STORE, rec['id'], ap('eva'), True)
        self.assertEqual(TP.action_approve(STORE, rec['id'], ap('lead1'), True)['state'],
                         'waiting')
        self.assertEqual(TP.action_approve(STORE, rec['id'], ap('lead2'), True)['state'],
                         'approved')
        self.assertEqual([a['id'] for a in TP.actions(STORE, 'Region')], [rec['id']])


class Directory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port, cls.stop = mockldap.serve(0)
        cls.ad = E.Directory({'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.port,
                              'tls': 'none', 'verify': 0, 'base': BASE,
                              'bind_dn': 'CN=isemon,OU=Service,' + BASE,
                              'bind_pw': 'the-service-password'})

    @classmethod
    def tearDownClass(cls):
        cls.stop.set()

    def setUp(self):
        clean()
        E.CONFIG.update(portal_directory='corp')

    def h(self, **kw):
        return FakeH(dirs={'corp': self.ad}, **kw)

    def route(self, method, path, body=None, args=None, **who):
        h = self.h(body=body, args=args, **who)
        return E.ROUTES[(method, path)](h)

    def test_access_check(self):
        T.save_team(STORE, {'name': 'Suppliers', 'members': [
            {'who': 'group:CERT_USERS', 'roles': ['Requester']}]}, 'x')
        T.save_team(STORE, {'name': 'SupplierX', 'parent': 'Suppliers', 'members': [
            {'who': 'group:CERT_SUPPLIER_X', 'roles': ['Renewer']}]}, 'x')
        got = self.route('GET', '/api/teams/access', args={'who': 'nested@corpnet.cz'})
        self.assertEqual(got['who']['kind'], 'user')
        self.assertIn('CERT_USERS', got['groups'])            # nested: through SUPPLIER_X
        by = {t['team']: t for t in got['teams']}
        self.assertEqual(sorted(by), ['SupplierX', 'Suppliers'])
        self.assertIn('cert.request', by['SupplierX']['caps'])  # inherited from Suppliers
        self.assertIn('cert.renew', by['SupplierX']['caps'])
        self.assertTrue(any(v['inherited'] and v['who'] == 'group:CERT_USERS'
                            for v in by['SupplierX']['via']))
        # a stranger: no team; a reader of the administration may not ask
        got = self.route('GET', '/api/teams/access', args={'who': 'outsider'})
        self.assertEqual(got['teams'], [])
        self.assertEqual(status(self.route, 'GET', '/api/teams/access', args={'who': 'x'},
                                role='readonly'), 403)

    def test_search_never_a_filter(self):
        got = self.route('GET', '/api/dir/search', args={'q': 'novak', 'kind': 'user'})
        self.assertEqual([r['sam'] for r in got['rows']], ['jnovak'])
        for q in ('*', '*)(objectClass=*', 'a*)(|(cn=*'):
            got = self.route('GET', '/api/dir/search', args={'q': q + 'x', 'kind': 'user'})
            self.assertEqual(got['rows'], [], q)
        got = self.route('GET', '/api/dir/search', args={'q': 'CERT', 'kind': 'group',
                                                         'limit': 1})
        self.assertEqual(len(got['rows']), 1)
        self.assertTrue(got['more'])
        got = self.route('GET', '/api/dir/group', args={'name': 'CERT_USERS'})
        self.assertGreaterEqual(got['count'], 2)
        self.assertIn('nested', [u['sam'] for u in got['first']])

    def test_from_groups(self):
        T.save_team(STORE, {'name': 'Regions'}, 'x')
        b = {'filter': 'CN=CERT_*', 'role': 'Requester', 'parent': 'Regions', 'dry_run': True}
        got = self.route('POST', '/api/teams/from_groups', b, role='certadmin', who='c')
        self.assertEqual(sorted(g['cn'] for g in got['groups']),
                         ['CERT_SUPPLIER_X', 'CERT_USERS'])
        self.assertEqual(got['made'], [])
        self.assertIsNone(T.team_get(STORE, 'CERT_USERS'))
        self.assertEqual(status(self.route, 'POST', '/api/teams/from_groups',
                                dict(b, dry_run=False), role='certadmin', who='c'), 403)
        got = self.route('POST', '/api/teams/from_groups', dict(b, dry_run=False))
        self.assertEqual(sorted(got['made']), ['CERT_SUPPLIER_X', 'CERT_USERS'])
        t = T.team_get(STORE, 'CERT_USERS')
        self.assertEqual((t['parent'], json.loads(t['members'])),
                         ('Regions', [{'who': 'group:CERT_USERS', 'rights': [],
                                       'roles': ['Requester']}]))
        got = self.route('POST', '/api/teams/from_groups', dict(b, dry_run=False))
        self.assertEqual(got['made'], [])                     # there already


class Carry(unittest.TestCase):
    def setUp(self):
        clean()

    def test_migration_of_an_old_database(self):
        path = os.path.join(TMP, 'old.db')
        c = sqlite3.connect(path)
        c.execute('CREATE TABLE cert_teams (id INTEGER PRIMARY KEY AUTOINCREMENT, name '
                  'VARCHAR(190) NOT NULL UNIQUE, kind VARCHAR(190), members TEXT, contact_mail '
                  'TEXT, contact_phone VARCHAR(190), note TEXT, created REAL, created_by '
                  'VARCHAR(190), updated REAL, updated_by VARCHAR(190))')
        c.execute('CREATE TABLE cert_targets (id INTEGER PRIMARY KEY AUTOINCREMENT, name '
                  'VARCHAR(190) NOT NULL UNIQUE, kind VARCHAR(190), config TEXT, state TEXT, '
                  'enabled INTEGER, note TEXT, created REAL, created_by VARCHAR(190), updated '
                  'REAL, last_ok REAL, last_error TEXT, tags TEXT)')
        c.execute("INSERT INTO cert_teams (name, kind, members) VALUES ('Old', 'team', "
                  "'[{\"who\": \"local:a\", \"rights\": [\"manage\"]}]')")
        c.commit()
        c.close()
        db = E.Db('sqlite', path=path)
        db.make_tables()
        self.assertTrue({'parent', 'policy', 'description'} <= set(db.columns('cert_teams')))
        self.assertIn('owner', db.columns('cert_targets'))
        self.assertIn('caps', db.columns('cert_roles'))
        row = db.row("SELECT * FROM cert_teams WHERE name = 'Old'")
        self.assertEqual((row["parent"], row["policy"]), (None, None))
        db.close()

    def test_export_import_round_trip(self):
        T.save_role(STORE, {'name': 'Ops', 'caps': ['cert.view', 'cert.renew']}, 'x')
        T.save_team(STORE, {'name': 'Top'}, 'x')
        T.save_team(STORE, {'name': 'Kid', 'parent': 'Top', 'policy': {'max_days': 30},
                            'members': [{'who': 'local:z', 'roles': ['Ops'],
                                         'until': 2000000000}]}, 'x')
        STORE.db.insert('cert_targets', {'name': 'devx', 'kind': 'ssh', 'config': '{}',
                                         'owner': 'Kid', 'state': '{}'})
        out = E.carry_export(STORE, True)
        self.assertIn('cert_roles', out)
        self.assertIn('cert_roles', E.carry_tables())          # backup, export, HA
        for t in ('cert_roles', 'cert_teams', 'cert_targets'):
            STORE.db.run('DELETE FROM %s' % t)
        T.changed()
        from collections import Counter
        E.carry_import(STORE, {k: out[k] for k in ('cert_roles', 'cert_teams', 'cert_targets')},
                       'x', False, Counter())
        T.changed()
        kid = T.team_get(STORE, 'Kid')
        self.assertEqual((kid['parent'], json.loads(kid['policy'])), ('Top', {'max_days': 30}))
        self.assertEqual(json.loads(kid['members'])[0]['roles'], ['Ops'])
        self.assertEqual([r['name'] for r in T.role_rows(STORE)], ['Ops'])
        self.assertEqual(STORE.db.value("SELECT owner FROM cert_targets WHERE name = 'devx'"),
                         'Kid')
        self.assertIn('cert.renew', T.person_caps(STORE, {'local:z'}, [])['kid']['caps'])


class Agents(unittest.TestCase):
    def setUp(self):
        clean()

    def test_team_enrollment(self):
        from acmelib.certs import agents as G
        T.save_team(STORE, {'name': 'Ops', 'policy': {'agents_auto_confirm': False}}, 'x')
        ec = {'id': 'abcdef012345', 'title': 'ops', 'mode': 'passive', 'team': 'Ops'}
        row = G._enroll_target(STORE, ec, 'agent', 'srv1', 'srv1.example.test', '10.0.0.1')
        self.assertEqual(row['owner'], 'Ops')
        self.assertFalse(G.enroll_auto_ok(STORE, dict(ec, auto=True)))
        T.save_team(STORE, {'old_name': 'Ops', 'name': 'Ops',
                            'policy': {'agents_auto_confirm': True}}, 'x')
        self.assertTrue(G.enroll_auto_ok(STORE, ec))
        self.assertEqual(G.waiting(STORE, {'nobody'}), [])
        T.save_team(STORE, {'old_name': 'Ops', 'name': 'Ops', 'policy': {'agents': False}}, 'x')
        with self.assertRaises(Exception) as e:
            G.enroll_new(STORE, 'x', team='Ops')
        self.assertIn('the team Ops', str(e.exception))
        # a plain code: as before
        self.assertTrue(G.enroll_auto_ok(STORE, {'id': 'x'}))
        # the target owner set by an administrator
        A.family_save(STORE, 'target', {'id': row['id'], 'owner': ''}, 'x')
        self.assertIsNone(STORE.db.value('SELECT owner FROM cert_targets WHERE id = ?',
                                         (row['id'],)))
        with self.assertRaises(ValueError):
            A.family_save(STORE, 'target', {'id': row['id'], 'owner': 'Nope'}, 'x')


class Activity(unittest.TestCase):
    def setUp(self):
        clean()

    def test_activity(self):
        T.save_team(STORE, {'name': 'Web', 'members': ['local:a']}, 'x')
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'members': ['local:a',
                                                                          'local:b']}, 'x')
        cert('actcert', 'Web')
        got = call('GET', '/api/teams/activity', args={'team': 'Web'})
        words = ' | '.join(r['words'] for r in got['rows'])
        self.assertIn('members added: local:b', words)
        self.assertIn('actcert', words)
        E.CONFIG.update(certs_readonly_all=0)
        self.assertEqual(may('GET', '/api/teams/activity', args={'team': 'Web'}, who='zz',
                             role='readonly'), 403)


class Speed(unittest.TestCase):
    def test_two_thousand_teams(self):
        clean()
        rows = []
        t0 = time.time()
        for i in range(2000):
            rows.append({'name': 'T%04d' % i, 'kind': 'team',
                         'parent': ('T%04d' % (i // 10)) if i >= 10 else None,
                         'members': json.dumps([{'who': 'group:G%d' % j, 'rights': ['view']}
                                                for j in range(i % 7)] +
                                               [{'who': 'local:u%d' % i,
                                                 'roles': ['Requester']}]),
                         'updated': t0})
        for r in rows:
            STORE.db.insert('cert_teams', r)
        T.changed()
        groups = [('CN=G%d,%s' % (j, BASE), 'G%d' % j) for j in range(300)]
        t = time.time()
        got = T.person_caps(STORE, {'local:u3'}, groups)
        first = time.time() - t
        t = time.time()
        for _ in range(50):
            T.person_caps(STORE, {'local:u3'}, groups)
        again = (time.time() - t) / 50
        self.assertGreater(len(got), 1000)
        self.assertLess(first, 5.0)
        self.assertLess(again, 0.05)


if __name__ == '__main__':
    unittest.main(verbosity=2)
