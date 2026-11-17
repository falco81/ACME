#!/usr/bin/env python3
"""The portal's team workspace (1.0.125, acmelib/certs/portal_teams.py, docs/certificate-portal.md
"Teams").

    python3 test/test_teams_portal.py

- every route allowed / refused (403) for each built-in role: Viewer, Requester, Renewer,
  Deployer, Device manager, Certificate manager, Approver, Team manager, Team owner;
- inheritance down the tree (a member of a team above works in the teams below, never above);
- the limits: device modules, key download, max certificates, profiles/free form;
- no escalation: members given only what the giver holds, their own membership never raised,
  ancestors never touched, sub-team limits never wider;
- approvals end to end on the portal: the team's lead then the team above, four-eyes, one's
  own refused; actions waiting (approve_actions revoke, key, device);
- a device's secrets are never returned (set / not set only);
- a team's enrollment code: the server that enrolls is the team's device, waiting, confirmed
  (or refused) by a member of the team;
- a person in no team: the portal as before, every team route refused.
"""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-teams-portal-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402  (the routes)
from acmelib.certs import teams as T  # noqa: E402
from acmelib.certs import portal as P  # noqa: E402
from acmelib.certs import portal_teams  # noqa: E402,F401
from acmelib.certs import agents as G  # noqa: E402
from acmelib.certs import api_deploys, api_runplan  # noqa: E402

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
SECRET = 'Sup3r-Secret-Pw!42'


class FakeH(object):
    def __init__(self, portal=None, body=None, args=None):
        self.store, self._body, self.args, self.portal = STORE, dict(body or {}), \
            {k: str(v) for k, v in (args or {}).items()}, portal
        self.headers = {}
        self.d = type('D', (), {'dirs': {}})()

    def session(self, kind):
        return self.portal if kind == 'portal' else None

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


def call(who, method, name, body=None, args=None):
    s = who if isinstance(who, dict) else person(who)
    return E.ROUTES[(method, '/api/portal/' + name)](FakeH(s, body, args))


def status(who, method, name, body=None, args=None):
    try:
        call(who, method, name, body, args)
        return 200
    except E.ApiError as e:
        return e.status
    except LookupError:
        return 404
    except ValueError:
        return 400


def refusal(who, method, name, body=None, args=None):
    try:
        call(who, method, name, body, args)
    except E.ApiError as e:
        return e.status, str(e)
    return 200, ''


def wait_jobs():
    from acmelib.certs import jobs
    end = time.time() + 30
    while time.time() < end and (jobs.RUNNING or jobs.BUSY_CERTS):
        time.sleep(0.05)


def clean():
    wait_jobs()
    for t in ('certs', 'cert_teams', 'cert_versions', 'cert_jobs', 'cert_deploys',
              'cert_targets', 'cert_roles', 'cert_checks'):
        STORE.db.run('DELETE FROM %s' % t)
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:portal:%' OR k LIKE 'teams:action:%' "
                 "OR k LIKE 'agents:%'")
    T.changed()
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1, certs_notify_mail='',
                    portal=1, portal_cert=1, portal_local=1, mail_mode='off',
                    portal_cert_auto=0, portal_cert_suffixes='example.test',
                    portal_cert_issuers='self', portal_cert_max=1000, portal_cert_keys=1,
                    portal_directory='', admin_directory='', certs_agents_active=1)
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
        STORE.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})


def cert(name, owner, issued=True):
    cid = A.cert_save(STORE, {'name': name, 'names': ['%s.example.test' % name],
                              'issuer': 'self', 'key_type': 'ec-256', 'auto_renew': 0,
                              'owner': owner, 'hold': 1}, 'test')
    if issued:
        STORE.db.update('certs', cid, {'cert_pem': 'PEM', 'key_sealed': 'x', 'state': 'ok',
                                       'not_after': time.time() + 10 * 86400})
    return cid


def device(name, owner, kind='ssh', cfg=None):
    return A.family_save(STORE, 'target', {
        'name': name, 'kind': kind, 'owner': owner,
        'config': cfg or {'host': '%s.example.test' % name, 'user': 'u', 'auth': 'password',
                          'password': SECRET}}, 'test')


def deploy(cid, target):
    return A.deploy_save(STORE, {'cert_id': cid, 'target': target, 'options': {}}, 'test')


def tree(members=None, web_policy=None):
    T.save_team(STORE, {'name': 'Europe', 'kind': 'unit'}, 'x')
    T.save_team(STORE, {'name': 'Prague', 'kind': 'unit', 'parent': 'Europe'}, 'x')
    T.save_team(STORE, {'name': 'Web', 'parent': 'Prague', 'members': members or [],
                        'policy': web_policy or {}}, 'x')
    T.save_team(STORE, {'name': 'WebDev', 'parent': 'Web'}, 'x')


class Stubs(object):
    """Jobs that would reach a CA or a device: recorded, not run."""
    def __enter__(self):
        self.saved = (A.start_renew, P.start_revoke, A.start_deploy, A.family_test,
                      api_runplan._go, api_deploys._deploys_dry_run, A.cert_export)
        A.cert_export = lambda *a, **k: {'name': 'x.pfx', 'data_b64': ''}
        A.start_renew = lambda *a, **k: 'job-renew'
        P.start_revoke = lambda *a, **k: 'job-revoke'
        A.start_deploy = lambda *a, **k: 'job-deploy'
        A.family_test = lambda *a, **k: {'ok': True, 'said': 'stub', 'job_id': 'j', 'steps': []}
        api_runplan._go = lambda *a, **k: {'plan': 'stub'}
        api_deploys._deploys_dry_run = lambda *a, **k: {'ok': True, 'said': 'stub'}
        return self

    def __exit__(self, *a):
        (A.start_renew, P.start_revoke, A.start_deploy, A.family_test, api_runplan._go,
         api_deploys._deploys_dry_run, A.cert_export) = self.saved


ROLES = [r[0] for r in T.BUILTIN_ROLES]
ROLE_CAPS = {r[0]: set(r[1]) for r in T.BUILTIN_ROLES}


def fixture(role):
    """Web's members: `rp` with the role, `asker` a Requester, `other` a Viewer; certificates,
    devices, deployments and a request waiting."""
    clean()
    tree([{'who': 'local:rp', 'roles': [role]}, {'who': 'local:asker', 'roles': ['Requester']},
          {'who': 'local:other', 'roles': ['Viewer']}])
    fx = {'ok': cert('cok', 'Web'), 'del': cert('cdel', 'Web')}
    device('dev1', 'Web')
    device('dev2', 'Web')
    device('dev3', 'Web')
    fx['ag'] = device('ag1', 'Web', 'agent', {'mode': 'passive', 'host': 'ag1.example.test'})
    fx['dev1'] = STORE.db.value("SELECT id FROM cert_targets WHERE name = 'dev1'")
    fx['dev2'] = STORE.db.value("SELECT id FROM cert_targets WHERE name = 'dev2'")
    fx['dep1'] = deploy(fx['ok'], 'dev1')
    fx['dep3'] = deploy(fx['ok'], 'dev3')
    fx['req'] = call('asker', 'POST', 'cert_request', {'names': ['req1.example.test'],
                                                       'issuer': 'self', 'team': 'Web'})['id']
    T.save_team(STORE, {'name': 'Sub1', 'parent': 'WebDev'}, 'x')
    return fx


# (route, the capability it needs, the call)
MATRIX = [
    ('certs?team', 'cert.view', lambda fx: ('GET', 'certs', None, {'team': 'Web', 'page': 0})),
    ('cert_renew', 'cert.renew', lambda fx: ('POST', 'cert_renew', {'id': fx['ok']}, None)),
    ('cert_auto', 'cert.auto', lambda fx: ('POST', 'cert_auto', {'id': fx['ok'],
                                                                 'auto_renew': 0}, None)),
    ('cert_revoke', 'cert.revoke', lambda fx: ('POST', 'cert_revoke', {'id': fx['ok']}, None)),
    ('cert_delete', 'cert.delete', lambda fx: ('POST', 'cert_delete', {'id': fx['del']}, None)),
    ('cert_download key', 'cert.key', lambda fx: ('POST', 'cert_download', {
        'id': fx['ok'], 'format': 'pfx', 'password': 'long-enough-pw'}, None)),
    ('cert_approve', 'cert.approve', lambda fx: ('POST', 'cert_approve', {
        'id': fx['req'], 'ok': 1, 'why': 'fine'}, None)),
    ('devices', 'target.view', lambda fx: ('GET', 'devices', None, {'team': 'Web'})),
    ('device', 'target.view', lambda fx: ('GET', 'device', None, {'id': fx['dev1']})),
    ('kinds', 'target.view', lambda fx: ('GET', 'kinds', None, {'team': 'Web'})),
    ('device_save', 'target.manage', lambda fx: ('POST', 'device_save', {
        'team': 'Web', 'name': 'new1', 'kind': 'ssh',
        'config': {'host': 'n.example.test', 'user': 'u'}}, None)),
    ('device_delete', 'target.manage', lambda fx: ('POST', 'device_delete',
                                                   {'id': fx['dev2']}, None)),
    ('device_test', 'target.test', lambda fx: ('POST', 'device_test', {'id': fx['dev1']}, None)),
    ('agents_waiting', 'target.view', lambda fx: ('GET', 'agents_waiting', None,
                                                  {'team': 'Web'})),
    ('agent', 'target.view', lambda fx: ('GET', 'agent', None, {'id': fx['ag']})),
    ('agent_code', 'target.manage', lambda fx: ('POST', 'agent_code', {'id': fx['ag']}, None)),
    ('enroll_code', 'target.manage', lambda fx: ('POST', 'enroll_code', {
        'team': 'Web', 'mode': 'active', 'title': 'web servers'}, None)),
    ('agent_builder', 'target.view', lambda fx: ('GET', 'agent_builder', None, {'id': fx['ag']})),
    ('agent_design', 'target.manage', lambda fx: ('POST', 'agent_design', {
        'id': fx['ag'], 'text': ''}, None)),
    ('agent_update', 'target.manage', lambda fx: ('POST', 'agent_update', {'id': fx['ag']}, None)),
    ('agent_refuse', 'target.manage', lambda fx: ('POST', 'agent_refuse', {'id': fx['ag']}, None)),
    ('deploys', 'deploy.view', lambda fx: ('GET', 'deploys', None, {'team': 'Web'})),
    ('deploy_save', 'deploy.manage', lambda fx: ('POST', 'deploy_save', {
        'cert_id': fx['ok'], 'target': 'dev2'}, None)),
    ('deploy_delete', 'deploy.manage', lambda fx: ('POST', 'deploy_delete',
                                                   {'id': fx['dep3']}, None)),
    ('deploy_run', 'deploy.run', lambda fx: ('POST', 'deploy_run', {'id': fx['dep1']}, None)),
    ('deploy_dry_run', 'deploy.view', lambda fx: ('POST', 'deploy_dry_run',
                                                  {'id': fx['dep1']}, None)),
    ('deploy_dry_run test', 'deploy.run', lambda fx: ('POST', 'deploy_dry_run',
                                                      {'id': fx['dep1'], 'test': 1}, None)),
    ('members', 'team.members', lambda fx: ('GET', 'members', None, {'team': 'Web'})),
    ('member_save', 'team.members', lambda fx: ('POST', 'member_save', {
        'team': 'Web', 'who': 'local:newbie', 'roles': ['Viewer']}, None)),
    ('member_delete', 'team.members', lambda fx: ('POST', 'member_delete', {
        'team': 'Web', 'who': 'local:other'}, None)),
    ('dir_search', 'team.members', lambda fx: ('GET', 'dir_search', None, {'q': 'jan'})),
    ('team_save new', 'team.create', lambda fx: ('POST', 'team_save', {
        'name': 'WebNew', 'parent': 'Web'}, None)),
    ('team_save policy', 'team.policy', lambda fx: ('POST', 'team_save', {
        'old_name': 'WebDev', 'policy': {'max_days': 30}}, None)),
    ('team_delete', 'team.create', lambda fx: ('POST', 'team_delete', {'name': 'Sub1'}, None)),
    ('activity', 'team.activity', lambda fx: ('GET', 'activity', None, {'team': 'Web'})),
]


class RoleMatrix(unittest.TestCase):
    def test_every_route_every_role(self):
        with Stubs():
            for role in ROLES:
                caps = ROLE_CAPS[role]
                fx = fixture(role)
                got = call('rp', 'GET', 'teams')
                web = [t for t in got['teams'] if t['name'] == 'Web'][0]
                self.assertEqual(set(web['caps']), caps, role)
                for name, cap, make in MATRIX:
                    method, route, body, args = make(fx)
                    st, words = refusal('rp', method, route, body, args)
                    # the old right manage approved (1.0.16) - its capabilities in full still do
                    # (the Certificate manager's are the same set)
                    has = cap in caps or (cap == 'cert.approve' and T.RIGHT_CAPS['manage'] <= caps)
                    with self.subTest(role=role, route=name):
                        if has:
                            self.assertNotEqual(st, 403, '%s %s: %s' % (role, name, words))
                        else:
                            self.assertEqual(st, 403, '%s %s: %s' % (role, name, st))
                            self.assertTrue(words)
                wait_jobs()
        # each refusal is an event naming who and what
        self.assertTrue(STORE.db.value("SELECT COUNT(*) FROM events WHERE words LIKE "
                                       "'rp was refused on the portal:%'"))


class Workspace(unittest.TestCase):
    def setUp(self):
        clean()

    def tearDown(self):
        wait_jobs()

    def test_inheritance_down_the_tree(self):
        tree()
        T.save_team(STORE, {'old_name': 'Prague', 'name': 'Prague', 'members': [
            {'who': 'local:pm', 'roles': ['Device manager']}]}, 'x')
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'members': [
            {'who': 'local:wm', 'roles': ['Device manager']}]}, 'x')
        device('pdev', 'Prague')
        device('wdev', 'WebDev')
        got = call('pm', 'GET', 'teams')
        self.assertEqual([t['name'] for t in got['teams']], ['Prague', 'Web', 'WebDev'])
        self.assertEqual(got['teams'][0]['children'], ['Web'])
        self.assertEqual(got['teams'][2]['direct'], [])               # inherited only
        self.assertEqual(got['teams'][2]['counts']['devices'], 1)
        # a member above works below
        self.assertEqual(status('pm', 'GET', 'devices', args={'team': 'WebDev'}), 200)
        rows = call('pm', 'GET', 'devices', args={'team': 'Prague', 'below': 1})['rows']
        self.assertEqual(sorted(r['name'] for r in rows), ['pdev', 'wdev'])
        self.assertEqual(status('pm', 'POST', 'device_save', {
            'team': 'WebDev', 'name': 'wdev2', 'kind': 'ssh',
            'config': {'host': 'x.example.test', 'user': 'u'}}), 200)
        # ...never above: Prague is not Web's member's
        self.assertEqual(status('wm', 'GET', 'devices', args={'team': 'Prague'}), 404)
        pid = STORE.db.value("SELECT id FROM cert_targets WHERE name = 'pdev'")
        self.assertEqual(status('wm', 'GET', 'device', args={'id': pid}), 404)
        self.assertEqual(status('wm', 'POST', 'device_save', {
            'id': pid, 'team': 'Web', 'name': 'pdev', 'kind': 'ssh'}), 404)
        self.assertEqual([t['name'] for t in call('wm', 'GET', 'teams')['teams']],
                         ['Web', 'WebDev'])

    def test_device_secrets_never_returned(self):
        tree([{'who': 'local:dm', 'roles': ['Device manager']}])
        got = call('dm', 'POST', 'device_save', {
            'team': 'Web', 'name': 'sec1', 'kind': 'ssh',
            'config': {'host': 's.example.test', 'user': 'root', 'auth': 'password',
                       'password': SECRET, 'sudo_password': ''}})
        did = got['id']
        answers = [got, call('dm', 'GET', 'device', args={'id': did}),
                   call('dm', 'GET', 'devices', args={'team': 'Web'})]
        for a in answers:
            text = json.dumps(a)
            self.assertNotIn(SECRET, text)
            self.assertNotIn('sealed:', text)
            self.assertNotIn('•', text)                     # not even its dots
        dev = answers[1]['device']
        self.assertEqual(dev['config']['password'], '')
        self.assertTrue(dev['secrets']['password'])
        self.assertFalse(dev['secrets']['sudo_password'])
        self.assertEqual(dev['owner'], 'Web')
        # the secret kept when saved again with '' - and the host not moved past it
        call('dm', 'POST', 'device_save', {'id': did, 'team': 'Web', 'note': 'hello',
                                           'config': dict(dev['config'])})
        from acmelib.certs import store as S
        self.assertEqual(S.plugin_config('target', S.plugin_row(STORE, 'target', did))
                         ['password'], SECRET)
        st, words = refusal('dm', 'POST', 'device_save', {
            'id': did, 'team': 'Web', 'config': dict(dev['config'], host='evil.example.test')})
        self.assertEqual(st, 403)
        self.assertIn('type them again', words)
        self.assertEqual(status('dm', 'POST', 'device_save', {
            'id': did, 'team': 'Web', 'config': dict(dev['config'], host='new.example.test',
                                                     password='Another-Pw-1')}), 200)
        # owner forced to the team: a device of acme's own is not reached
        aid = device('acmes', None)
        self.assertEqual(status('dm', 'GET', 'device', args={'id': aid}), 404)

    def test_device_rules_as_admin(self):
        tree([{'who': 'local:dm', 'roles': ['Device manager', 'Certificate manager']}],
             web_policy={'target_kinds': ['ssh', 'agent']})
        # the module's own validation: a required field
        st, words = refusal('dm', 'POST', 'device_save', {
            'team': 'Web', 'name': 'x1', 'kind': 'ssh', 'config': {'user': 'u'}})
        self.assertEqual(st, 400)
        # the limits: a module not allowed, `local` never
        st, words = refusal('dm', 'POST', 'device_save', {
            'team': 'Web', 'name': 'x2', 'kind': 'webhook', 'config': {'url': 'https://x'}})
        self.assertEqual(st, 403)
        self.assertIn('the team Web', words)
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {}}, 'x')
        st, words = refusal('dm', 'POST', 'device_save', {
            'team': 'Web', 'name': 'x3', 'kind': 'local', 'config': {}})
        self.assertEqual(st, 403)
        kinds = [k['kind'] for k in call('dm', 'GET', 'kinds', args={'team': 'Web'})['kinds']]
        self.assertNotIn('local', kinds)
        self.assertIn('webhook', kinds)
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web',
                            'policy': {'target_kinds': ['ssh', 'agent']}}, 'x')
        got = call('dm', 'GET', 'kinds', args={'team': 'Web'})
        self.assertEqual(sorted(k['kind'] for k in got['kinds']), ['agent', 'ssh'])
        ssh = [k for k in got['kinds'] if k['kind'] == 'ssh'][0]
        self.assertTrue(any(f['key'] == 'host' for f in ssh['fields']))     # the admin form's
        # deleting a device a deployment uses: refused, as the administration refuses it
        device('used1', 'Web')
        cid = cert('c1', 'Web')
        deploy(cid, 'used1')
        uid = STORE.db.value("SELECT id FROM cert_targets WHERE name = 'used1'")
        self.assertEqual(status('dm', 'POST', 'device_delete', {'id': uid}), 409)
        # What happens of the deployment (the run plan, nothing contacted)
        dep = STORE.db.value('SELECT id FROM cert_deploys WHERE cert_id = ?', (cid,))
        got = call('dm', 'POST', 'deploy_dry_run', {'id': dep})
        self.assertIn('plan', got)
        rows = call('dm', 'GET', 'deploys', args={'team': 'Web'})['rows']
        self.assertEqual([(r['id'], r['target']) for r in rows], [(dep, 'used1')])
        # a deployment to another team's device, or acme's own: refused
        T.save_team(STORE, {'name': 'Other'}, 'x')
        device('odev', 'Other')
        device('mine0', None)
        for t in ('odev', 'mine0'):
            self.assertEqual(status('dm', 'POST', 'deploy_save', {'cert_id': cid,
                                                                  'target': t}), 403)
        # the commands a deployment runs stay a full administrator's
        st, words = refusal('dm', 'POST', 'deploy_save', {
            'cert_id': cid, 'target': 'used1', 'options': {'reload_cmd': 'id'}})
        self.assertIn(st, (400, 403))
        # a device through a connector of acme's own: refused
        device('conn', None, 'ssh_connector', {'host': 'c.example.test', 'user': 'u'})
        self.assertEqual(status('dm', 'POST', 'device_save', {
            'team': 'Web', 'name': 'via1', 'kind': 'ssh',
            'config': {'host': 'v.example.test', 'user': 'u', 'via': 'conn'}}), 403)

    def test_limits_key_max_free_form(self):
        tree([{'who': 'local:cm', 'roles': ['Certificate manager']}],
             web_policy={'key_download': False, 'max_certs': 1, 'free_form': False})
        cid = cert('k1', 'Web')
        st, words = refusal('cm', 'POST', 'cert_download', {
            'id': cid, 'format': 'pfx', 'password': 'long-enough-pw'})
        self.assertEqual(st, 403)
        self.assertIn('the team Web', words)
        st, words = refusal('cm', 'POST', 'cert_request', {
            'names': ['a.example.test'], 'issuer': 'self', 'team': 'Web'})
        self.assertEqual(st, 403)
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {'max_certs': 1}}, 'x')
        st, words = refusal('cm', 'POST', 'cert_request', {
            'names': ['a.example.test'], 'issuer': 'self', 'team': 'Web'})
        self.assertEqual(st, 403)
        self.assertIn('1 certificate', words)
        # the counts of the team
        got = call('cm', 'GET', 'teams')['teams'][0]
        self.assertEqual((got['counts']['certs'], got['counts']['expiring']), (1, 1))
        self.assertEqual(got['policy']['max_certs'], 1)
        self.assertEqual(got['policy']['from']['max_certs'], 'Web')

    def test_certs_paged(self):
        tree([{'who': 'local:v', 'roles': ['Viewer']}])
        for i in range(7):
            cert('p%02d' % i, 'Web' if i < 5 else 'WebDev')
        cert('mine1', 'v')
        STORE.db.run("UPDATE certs SET state = 'failed' WHERE name = 'p03'")
        old = call('v', 'GET', 'certs')
        self.assertNotIn('total', old)                    # as before without the arguments
        self.assertEqual(len(old['rows']), 8)
        got = call('v', 'GET', 'certs', args={'team': 'Web', 'per': 2, 'page': 1})
        self.assertEqual((got['total'], got['pages'], len(got['rows'])), (5, 3, 2))
        self.assertEqual([r['name'] for r in got['rows']], ['p02', 'p03'])
        self.assertIn('cert.view', got['rows'][0]['caps'])
        got = call('v', 'GET', 'certs', args={'team': 'Web', 'below': 1})
        self.assertEqual(got['total'], 7)
        self.assertEqual(call('v', 'GET', 'certs', args={'q': 'p06'})['total'], 1)
        self.assertEqual([r['name'] for r in call('v', 'GET', 'certs', args={
            'state': 'failing'})['rows']], ['p03'])
        self.assertEqual([r['name'] for r in call('v', 'GET', 'certs', args={
            'team': 'me'})['rows']], ['mine1'])
        self.assertEqual(status('v', 'GET', 'certs', args={'state': 'nonsense'}), 400)

    def test_no_team_as_before(self):
        tree()
        cert('solo', 'loner')
        got = call('loner', 'GET', 'teams')
        self.assertEqual((got['teams'], got['in_teams']), ([], False))
        old = call('loner', 'GET', 'certs')
        self.assertEqual([r['name'] for r in old['rows']], ['solo'])
        self.assertEqual(old['rows'][0]['may'], ['view'])
        self.assertEqual(old['rows'][0]['via'], 'me')
        for method, route, args in (('GET', 'devices', {'team': 'Web'}),
                                    ('GET', 'members', {'team': 'Web'}),
                                    ('GET', 'activity', {'team': 'Web'}),
                                    ('GET', 'deploys', {'team': 'Web'})):
            self.assertEqual(status('loner', method, route, args=args), 404)
        self.assertEqual(status('loner', 'GET', 'dir_search', args={'q': 'ab'}), 403)
        inbox = call('loner', 'GET', 'inbox')
        self.assertEqual((inbox['requests'], inbox['actions']), ([], []))
        # their own certificate: renewing is not theirs (as before: no team gives it)
        cid = STORE.db.value("SELECT id FROM certs WHERE name = 'solo'")
        self.assertEqual(status('loner', 'POST', 'cert_renew', {'id': cid}), 403)


class Escalation(unittest.TestCase):
    def setUp(self):
        clean()
        tree([{'who': 'local:tm', 'roles': ['Team manager']},
              {'who': 'local:own', 'roles': ['Team owner']},
              {'who': 'local:v1', 'roles': ['Viewer']}],
             web_policy={'suffixes': ['example.test'], 'max_days': 90})
        T.save_team(STORE, {'old_name': 'Prague', 'name': 'Prague', 'members': [
            {'who': 'local:pboss', 'roles': ['Viewer']}]}, 'x')

    def test_members_no_escalation(self):
        # only what one holds: a Viewer yes, a Requester (cert.request) no
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'Web', 'who': 'local:n1', 'roles': ['Viewer']}), 200)
        st, words = refusal('tm', 'POST', 'member_save', {
            'team': 'Web', 'who': 'local:n2', 'roles': ['Requester']})
        self.assertEqual(st, 403)
        self.assertIn('cert.request', words)
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'Web', 'who': 'local:n3', 'rights': ['manage']}), 403)
        # a custom role within one's caps is fine; one wider is not
        T.save_role(STORE, {'name': 'Watch', 'caps': ['cert.view', 'team.view']}, 'x')
        T.save_role(STORE, {'name': 'Big', 'caps': ['cert.view', 'cert.revoke']}, 'x')
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'WebDev', 'who': 'local:n4', 'roles': ['Watch']}), 200)
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'WebDev', 'who': 'local:n5', 'roles': ['Big']}), 403)
        # never their own membership upwards, never themselves added
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'Web', 'who': 'local:tm', 'roles': ['Team manager', 'Viewer']}), 200)
        st, words = refusal('tm', 'POST', 'member_save', {
            'team': 'WebDev', 'who': 'local:tm', 'roles': ['Viewer']})
        self.assertEqual(st, 403)
        self.assertIn('yourself', words)
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'members': [
            {'who': 'local:tm', 'roles': ['Team manager'], 'until': time.time() + 3600},
            {'who': 'local:own', 'roles': ['Team owner']}]}, 'x')
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'Web', 'who': 'local:tm', 'roles': ['Team manager'],
            'until': time.time() + 86400 * 30}), 403)              # not lengthened
        # a member holding more than them: not changed, not removed
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'Web', 'who': 'local:own', 'roles': ['Viewer']}), 403)
        self.assertEqual(status('tm', 'POST', 'member_delete', {
            'team': 'Web', 'who': 'local:own'}), 403)
        # the owner may give a Team owner (they hold every cap)
        self.assertEqual(status('own', 'POST', 'member_save', {
            'team': 'Web', 'who': 'local:n6', 'roles': ['Team owner']}), 200)
        # ancestors are never touched
        self.assertEqual(status('tm', 'GET', 'members', args={'team': 'Prague'}), 404)
        self.assertEqual(status('tm', 'POST', 'member_save', {
            'team': 'Prague', 'who': 'local:x', 'roles': ['Viewer']}), 404)
        # what may be given is said
        got = call('tm', 'GET', 'members', args={'team': 'Web'})
        give = {r['name']: r['givable'] for r in got['roles']}
        self.assertTrue(give['Viewer'])
        self.assertFalse(give['Requester'])
        self.assertTrue(any(m['me'] for m in got['members']))
        self.assertEqual([a['team'] for a in got['above']], ['Prague'])
        # removing one's own membership is fine
        self.assertEqual(status('tm', 'POST', 'member_delete', {
            'team': 'Web', 'who': 'local:tm'}), 200)

    def test_sub_teams_and_limits(self):
        got = call('tm', 'POST', 'team_save', {'name': 'WebOps', 'parent': 'Web',
                                               'kind': 'unit', 'description': 'ops'})
        self.assertEqual((got['team']['parent'], got['team']['kind']), ('Web', 'unit'))
        # renamed by a manager of the team above it; Web itself is not theirs to rename
        self.assertEqual(status('tm', 'POST', 'team_save', {'old_name': 'WebOps',
                                                            'name': 'WebOps2'}), 200)
        self.assertEqual(status('tm', 'POST', 'team_save', {'old_name': 'Web',
                                                            'name': 'Web2'}), 403)
        self.assertEqual(status('tm', 'POST', 'team_save', {'name': 'X', 'parent': 'Prague'}),
                         404)
        self.assertEqual(status('tm', 'POST', 'team_save', {'name': 'Top1'}), 403)
        # the limits of a team below: narrower yes, wider refused in words
        self.assertEqual(status('tm', 'POST', 'team_save', {
            'old_name': 'WebDev', 'policy': {'max_days': 30,
                                             'suffixes': ['dev.example.test']}}), 200)
        st, words = refusal('tm', 'POST', 'team_save', {
            'old_name': 'WebDev', 'policy': {'max_days': 365}})
        self.assertEqual(st, 403)
        self.assertIn('max_days', words)
        st, words = refusal('tm', 'POST', 'team_save', {
            'old_name': 'WebDev', 'policy': {'suffixes': ['other.test']}})
        self.assertEqual(st, 403)
        self.assertIn('suffixes', words)
        self.assertEqual(status('tm', 'POST', 'team_save', {
            'old_name': 'WebDev', 'policy': {'agents_auto_confirm': True}}), 403)
        # never the policy of their own team
        self.assertEqual(status('tm', 'POST', 'team_save', {
            'old_name': 'Web', 'policy': {'max_days': 10}}), 403)
        # members are not saved through team_save
        self.assertEqual(status('tm', 'POST', 'team_save', {
            'old_name': 'WebDev', 'members': ['local:tm=manage']}), 400)
        # deleted: the teams below it move up, its certificates go to the parent
        T.save_team(STORE, {'name': 'Leaf', 'parent': 'WebOps2'}, 'x')
        cert('lc', 'WebOps2')
        got = call('tm', 'POST', 'team_delete', {'name': 'WebOps2'})
        self.assertEqual((got['children'], got['reparented_to'], got['to']),
                         (['Leaf'], 'Web', 'Web'))
        self.assertEqual(STORE.db.value("SELECT owner FROM certs WHERE name = 'lc'"), 'Web')
        self.assertEqual(status('tm', 'POST', 'team_delete', {'name': 'Web'}), 403)
        # activity of the team
        rows = call('tm', 'GET', 'activity', args={'team': 'Web'})['rows']
        self.assertTrue(any('WebOps2' in r['words'] for r in rows))


class Approvals(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Region', 'members': [
            {'who': 'local:boss', 'roles': ['Approver']}]}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Region', 'members': [
            {'who': 'local:eva', 'roles': ['Requester', 'Approver']},
            {'who': 'local:lead1', 'roles': ['Approver']},
            {'who': 'local:lead2', 'roles': ['Approver']},
            {'who': 'local:cm', 'roles': ['Certificate manager']}]}, 'x')

    def tearDown(self):
        wait_jobs()

    def rule(self, **a):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {
            'approval': dict({'mode': 'always'}, **a)}}, 'x')

    def ask(self, n):
        return call('eva', 'POST', 'cert_request', {'names': ['%s.example.test' % n],
                                                     'issuer': 'self', 'team': 'Web'})['id']

    def approve(self, who, cid, ok=1):
        return call(who, 'POST', 'cert_approve', {'id': cid, 'ok': ok,
                                                  'why': 'fine' if ok else 'no'})

    def state(self, cid):
        return STORE.db.value('SELECT state FROM certs WHERE id = ?', (cid,))

    def inbox_ids(self, who):
        return [r['id'] for r in call(who, 'GET', 'inbox')['requests']]

    def test_lead_then_parent(self):
        self.rule(approvers='both')
        cid = self.ask('both1')
        self.assertIn(cid, self.inbox_ids('lead1'))
        self.assertNotIn(cid, self.inbox_ids('boss'))           # the team's lead first
        self.assertNotIn(cid, self.inbox_ids('eva'))            # never one's own
        self.assertEqual(status('boss', 'POST', 'cert_approve', {'id': cid, 'ok': 1}), 403)
        self.assertTrue(self.approve('lead1', cid)['recorded'])
        self.assertIn(cid, self.inbox_ids('boss'))
        self.assertNotIn(cid, self.inbox_ids('lead2'))
        self.approve('boss', cid)
        self.assertNotEqual(self.state(cid), P.WAITING)
        tl = call('eva', 'GET', 'timeline', args={'id': cid})['timeline']
        whats = [e['what'] for e in tl]
        self.assertEqual(whats[:4], ['asked', 'approved', 'approved', 'let through'])
        self.assertNotIn('ids', json.dumps(tl))
        # the inbox said the timeline of each
        cid2 = self.ask('both2')
        item = [r for r in call('lead1', 'GET', 'inbox')['requests'] if r['id'] == cid2][0]
        self.assertEqual(item['timeline'][0]['what'], 'asked')
        self.assertEqual(item['needed'], ['team', 'parent'])
        asked = call('eva', 'GET', 'inbox')['asked']
        self.assertIn(cid2, [r['id'] for r in asked])

    def test_four_eyes_and_self(self):
        self.rule(count=2)
        cid = self.ask('four1')
        st, words = refusal('eva', 'POST', 'cert_approve', {'id': cid, 'ok': 1})
        self.assertEqual(st, 403)                              # one's own
        self.approve('lead1', cid)
        self.assertEqual(self.state(cid), P.WAITING)
        self.assertEqual(status('lead1', 'POST', 'cert_approve', {'id': cid, 'ok': 1}), 409)
        self.approve('lead2', cid)
        self.assertNotEqual(self.state(cid), P.WAITING)
        # a Requester alone (no cert.approve) is refused
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'members': [
            {'who': 'local:eva', 'roles': ['Requester']},
            {'who': 'local:req2', 'roles': ['Requester']}]}, 'x')
        cid = self.ask('four2')
        self.assertEqual(status('req2', 'POST', 'cert_approve', {'id': cid, 'ok': 1}), 403)

    def test_actions_wait_for_approval(self):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'policy': {
            'approve_actions': ['revoke', 'key', 'device']}}, 'x')
        cid = cert('act1', 'Web')
        with Stubs():
            got = call('cm', 'POST', 'cert_revoke', {'id': cid, 'reason': 'keyCompromise'})
            self.assertTrue(got['waits'])
            aid = got['action']['id']
            self.assertEqual(self.state(cid), 'ok')
            acts = call('lead1', 'GET', 'inbox')['actions']
            self.assertEqual([a['id'] for a in acts], [aid])
            self.assertEqual(acts[0]['what'], 'act1')
            self.assertEqual(call('cm', 'GET', 'inbox')['actions'], [])     # not one's own
            self.assertEqual(status('cm', 'POST', 'action_approve', {'id': aid, 'ok': 1}), 403)
            done = call('lead1', 'POST', 'action_approve', {'id': aid, 'ok': 1})
            self.assertIn('revoked', done['message'])
            self.assertEqual(done['action']['state'], 'done')
            # the key: asked, approved, taken once with the approval
            got = call('cm', 'POST', 'cert_download', {'id': cid, 'format': 'pfx',
                                                      'password': 'long-enough-pw'})
            self.assertTrue(got['waits'])
            kid = got['action']['id']
            self.assertEqual(status('cm', 'POST', 'cert_download', {
                'id': cid, 'format': 'pfx', 'password': 'long-enough-pw', 'action': kid}), 409)
            call('lead2', 'POST', 'action_approve', {'id': kid, 'ok': 1})
            st = status('cm', 'POST', 'cert_download', {
                'id': cid, 'format': 'pfx', 'password': 'long-enough-pw', 'action': kid})
            self.assertNotIn(st, (403, 404, 409))          # through to the export itself
            self.assertEqual(status('lead1', 'POST', 'cert_download', {
                'id': cid, 'format': 'pfx', 'password': 'long-enough-pw', 'action': kid}),
                403)                                       # an Approver holds no cert.key
            # a device deleted: waits; declined, it stays
            T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'members': [
                {'who': 'local:dm', 'roles': ['Device manager']},
                {'who': 'local:lead1', 'roles': ['Approver']}]}, 'x')
            did = device('gone1', 'Web')
            got = call('dm', 'POST', 'device_delete', {'id': did})
            self.assertTrue(got['waits'])
            self.assertEqual(status('lead1', 'POST', 'action_approve',
                                    {'id': got['action']['id'], 'ok': 0}), 400)   # say why
            call('lead1', 'POST', 'action_approve', {'id': got['action']['id'], 'ok': 0,
                                                     'why': 'still used'})
            self.assertTrue(STORE.db.value('SELECT id FROM cert_targets WHERE id = ?', (did,)))


class Agents(unittest.TestCase):
    def setUp(self):
        clean()
        tree([{'who': 'local:dm', 'roles': ['Device manager']},
              {'who': 'local:v', 'roles': ['Viewer']}],
             web_policy={'target_kinds': ['ssh', 'agent', 'agent_windows']})
        T.save_team(STORE, {'name': 'Other', 'members': [
            {'who': 'local:odm', 'roles': ['Device manager']}]}, 'x')

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0

    def enroll(self, code, fqdn):
        raw = code.split('.', 1)[1]
        data = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
        key = subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                              'ec_paramgen_curve:P-256'], capture_output=True, check=True).stdout
        csr = subprocess.run(['openssl', 'req', '-new', '-key', '/dev/stdin', '-subj',
                              '/CN=acme-agent'], input=key, capture_output=True,
                             check=True).stdout.decode()
        nonce = secrets.token_hex(16)
        enc = base64.b64encode(secrets.token_bytes(32)).decode()
        sha = hashlib.sha256(csr.encode()).hexdigest()
        body = {'e': data['e'], 'nonce': nonce, 'csr': csr, 'enc_pub': enc,
                'host': fqdn.split('.')[0], 'fqdn': fqdn, 'os': 'Rocky 9', 'platform': 'linux',
                'version': '1.0.125', 'code': 'c0de', 'port': 8446,
                'proof': G.proof(data['s'], 'enroll', data['e'], sha, enc, nonce, fqdn)}
        st, out = G.enroll_take(STORE, body, '192.0.2.10')
        self.assertEqual(st, 200, out)
        return out

    def test_team_enrollment_confirmed_by_member(self):
        # a Viewer may not make one; auto-confirm only where the administrators allowed it
        self.assertEqual(status('v', 'POST', 'enroll_code', {'team': 'Web'}), 403)
        st, words = refusal('dm', 'POST', 'enroll_code', {'team': 'Web', 'auto': 1,
                                                          'mode': 'active'})
        self.assertEqual(st, 403)
        self.assertIn('agents_auto_confirm', words)
        code = call('dm', 'POST', 'enroll_code', {'team': 'Web', 'mode': 'active',
                                                  'title': 'Web servers', 'days': 2})
        self.assertEqual(code['team'], 'Web')
        self.assertTrue(code['code'].startswith('ACAE1.'))
        out = self.enroll(code['code'], 'web7.example.test')
        row = STORE.db.row('SELECT * FROM cert_targets WHERE name = ?', (out['target'],))
        self.assertEqual((row['owner'], row['kind']), ('Web', 'agent'))
        waiting = call('dm', 'GET', 'agents_waiting', args={'team': 'Web'})
        self.assertEqual([w['name'] for w in waiting['rows']], ['web7'])
        self.assertEqual([c['title'] for c in waiting['codes']], ['Web servers'])
        self.assertEqual(call('odm', 'GET', 'teams')['teams'][0]['name'], 'Other')
        self.assertEqual(status('odm', 'POST', 'agent_confirm', {
            'id': row['id'], 'fp': waiting['rows'][0]['fp']}), 404)   # another team's
        self.assertEqual(status('v', 'POST', 'agent_confirm', {
            'id': row['id'], 'fp': waiting['rows'][0]['fp']}), 403)
        self.assertEqual(status('dm', 'POST', 'agent_confirm', {
            'id': row['id'], 'fp': '00' * 32}), 400)                  # a wrong fingerprint
        got = call('dm', 'POST', 'agent_confirm', {'id': row['id'],
                                                   'fp': waiting['rows'][0]['fp']})
        self.assertTrue(got['agent']['joined'])
        self.assertEqual(call('dm', 'GET', 'agents_waiting', args={'team': 'Web'})['rows'], [])
        info = call('v', 'GET', 'agent', args={'id': row['id']})['agent']
        self.assertEqual(info['state'] in ('answers', 'quiet'), True)
        self.assertIn('system', info)
        self.assertIn('facts', call('v', 'GET', 'agent_builder', args={'id': row['id']}))
        # another server refused: forgotten, its device (made by the code) gone
        out = self.enroll(code['code'], 'web8.example.test')
        rid = STORE.db.value('SELECT id FROM cert_targets WHERE name = ?', (out['target'],))
        got = call('dm', 'POST', 'agent_refuse', {'id': rid})
        self.assertTrue(got['deleted'])
        self.assertIsNone(STORE.db.value('SELECT id FROM cert_targets WHERE id = ?', (rid,)))
        # revoked by the team
        self.assertEqual(call('dm', 'POST', 'enroll_revoke', {'id': code['id']})['code']
                         ['state'], 'revoked')
        # no agents in the team's limits: refused naming the team
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web',
                            'policy': {'target_kinds': ['ssh']}}, 'x')
        st, words = refusal('dm', 'POST', 'enroll_code', {'team': 'Web', 'mode': 'active'})
        self.assertEqual(st, 403)
        self.assertIn('the team Web', words)

    def test_discovery_of_a_team_agent(self):
        """GET agent_discover (1.0.125): the last look for target.view, a new one for
        target.manage - only the kinds the agent's policy allows."""
        from acmelib.certs import agent_discover as AD
        aid = device('ag9', 'Web', 'agent', {'mode': 'passive', 'host': 'ag9.example.test'})
        got = call('v', 'GET', 'agent_discover', args={'id': aid, 'cached': 1})
        self.assertIsNone(got['discovery'])
        self.assertEqual(status('v', 'GET', 'agent_discover', args={'id': aid}), 403)
        self.assertEqual(status('odm', 'GET', 'agent_discover', args={'id': aid}), 404)
        was_info, was_run = G.info, AD.run
        ran = []
        try:
            G.info = lambda store, row: {'policy': {'discover': []}}
            st, words = refusal('dm', 'GET', 'agent_discover', args={'id': aid})
            self.assertEqual(st, 403)
            self.assertIn('acme-agent allow discover', words)
            G.info = lambda store, row: {'policy': {'discover': ['nginx']}}
            AD.run = lambda store, row, kinds=None, by='': ran.append(kinds) or {'found': []}
            self.assertEqual(status('dm', 'GET', 'agent_discover', args={'id': aid,
                                                                         'kind': 'apache'}), 403)
            got = call('dm', 'GET', 'agent_discover', args={'id': aid, 'kind': 'nginx'})
            self.assertEqual(got['discovery'], {'found': []})
            self.assertEqual(ran, [['nginx']])
        finally:
            G.info, AD.run = was_info, was_run


if __name__ == '__main__':
    unittest.main(verbosity=2)
