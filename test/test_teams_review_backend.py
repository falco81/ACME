#!/usr/bin/env python3
"""Enterprise teams, phase C1 review - the backend and its security (1.0.125, docs/teams.md
"Enterprise teams", docs/certificate-portal.md "Teams"): each test a regression of a problem
found in the review.

    python3 test/test_teams_review_backend.py

- the activity of a team is its own: never the events of a team or a certificate whose name
  only begins with its name (Web / WebDev / Web2, web1 / web10);
- GET /api/teams says every team's counts (certificates with those below, expiring, failing,
  waiting, devices, agents waiting) - a scoped account those of its own teams only;
- the limits are never widened below: the approvers and the envelope of `outside`;
- on the portal: a team is never made (or renamed) to a name certificates already carry as
  their owner, nor to a person's; a team moved with new limits needs team.policy there too;
  another's membership is not made one's own; the old right manage gives approving;
- actions waiting for an approval are approved (and declined) only at the level the rule names
  - and offered in "Waiting for you" only so; a key approved is taken once; the actions follow
  their team renamed, and are declined with it deleted;
- a device never goes through a device not of the team (`via`, `ssh_via`, ..., an id for a
  name); the module forms list only the team's connectors;
- a scoped certificate administrator keeps the team's limits on keys and deployments;
- an enrollment code of a team gone (or without agents now) makes no device;
- the portal's certificates page reads a few statements a page, not some per certificate.
"""
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_teams_portal as B  # noqa: E402  (its database, its helpers)
from acmelib import engine as E  # noqa: E402
from acmelib.certs import teams as T, teampolicy as TP  # noqa: E402
from acmelib.certs import portal as P  # noqa: E402
from acmelib.certs import api_teams  # noqa: E402
from acmelib.certs import agents as G  # noqa: E402

STORE = B.STORE
call, status, refusal, cert, device = B.call, B.status, B.refusal, B.cert, B.device


def event(words):
    STORE.add_event('certificates', words)


class Activity(unittest.TestCase):
    def setUp(self):
        B.clean()
        STORE.db.run('DELETE FROM events')
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:wm', 'roles': ['Team manager']}]}, 'x')
        T.save_team(STORE, {'name': 'WebDev', 'parent': 'Web'}, 'x')
        T.save_team(STORE, {'name': 'Web2', 'members': [
            {'who': 'local:w2', 'roles': ['Team manager']}]}, 'x')
        T.save_team(STORE, {'name': 'Web Ops'}, 'x')
        cert('web1', 'Web')
        cert('web10', 'Web2')
        STORE.db.run('DELETE FROM events')
        event('the team Web: its limits changed')
        event('web1: renewed')
        event('web1.example.test was looked at')            # its name, said as a host
        event('the team WebDev: members added: local:x')
        event('the team Web2: members added: local:y')
        event('the team Web Ops: members added: local:z')
        event('web10: renewed')
        event('the owner Web2 changed by x')

    def words(self, rows):
        return sorted(r['words'] for r in rows)

    def test_exact_names(self):
        rows, total = T.team_activity(STORE, 'Web')
        self.assertEqual(self.words(rows), sorted([
            'the team Web: its limits changed', 'web1: renewed']))
        self.assertEqual(total, 2)
        rows, _t = T.team_activity(STORE, 'Web', below=True)
        self.assertIn('the team WebDev: members added: local:x', self.words(rows))
        self.assertNotIn('the team Web2: members added: local:y', self.words(rows))
        rows, _t = T.team_activity(STORE, 'Web2')
        self.assertEqual(self.words(rows), sorted([
            'the team Web2: members added: local:y', 'web10: renewed',
            'the owner Web2 changed by x']))
        # the admin route and the portal's say the same - and page on the exact ones
        got = B.call('wm', 'GET', 'activity', args={'team': 'Web', 'per': 1})
        self.assertEqual((got['total'], len(got['rows']), got['pages']), (2, 1, 2))
        h = B.FakeH(None, args={'team': 'Web'})
        h.me = lambda *_a: {'name': 'admin', 'role': 'fulladmin',
                            'account': {'name': 'admin', 'role': 'fulladmin', 'source': 'local'}}
        got = E.ROUTES[('GET', '/api/teams/activity')](h)
        self.assertEqual(got['total'], 2)

    def test_sub_team_made_under_it(self):
        T.save_team(STORE, {'name': 'WebX', 'parent': 'Web'}, 'x')
        rows, _t = T.team_activity(STORE, 'Web')
        self.assertTrue(any('under Web' in r['words'] for r in rows))
        rows, _t = T.team_activity(STORE, 'Web2')
        self.assertFalse(any('WebX' in r['words'] for r in rows))


class Counts(unittest.TestCase):
    def setUp(self):
        B.clean()
        T.save_team(STORE, {'name': 'Top', 'kind': 'unit'}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Top', 'members': [
            {'who': 'local:ca', 'rights': ['view', 'request']}]}, 'x')
        T.save_team(STORE, {'name': 'Mail', 'parent': 'Top'}, 'x')
        a = cert('a1', 'Web')
        a2 = cert('a2', 'Web')
        STORE.db.update('certs', a2, {'not_after': time.time() + 300 * 86400})
        b = cert('b1', 'Mail')
        STORE.db.update('certs', a, {'not_after': time.time() + 86400})
        STORE.db.update('certs', b, {'state': 'failed'})
        cert('b2', 'Mail', issued=False)
        STORE.db.run("UPDATE certs SET state = 'pending-approval' WHERE name = 'b2'")
        device('d1', 'Web')
        device('ag1', 'Web', 'agent', {'mode': 'passive', 'host': 'ag1.example.test'})

    def test_counts_in_one_answer(self):
        got = api_teams.summary(STORE, {'name': 'boss', 'role': 'fulladmin'})
        c = {t['name']: t['counts'] for t in got['teams']}
        self.assertEqual(c['Web']['certs'], 2)
        self.assertEqual(c['Web']['expiring'], 1)
        self.assertEqual(c['Web']['devices'], 2)
        self.assertEqual(c['Web']['agents'], 1)
        self.assertEqual(c['Mail']['failing'], 1)
        self.assertEqual(c['Mail']['waiting'], 1)
        self.assertEqual(c['Top']['certs'], 0)
        self.assertEqual(c['Top']['certs_below'], 4)

    def test_scoped_sees_its_own(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        try:
            got = api_teams.summary(STORE, {'name': 'ca', 'role': 'certadmin',
                                            'account': {'source': 'local'}})
        finally:
            E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1)
        c = {t['name']: t.get('counts') for t in got['teams']}
        self.assertEqual(c['Web']['certs'], 2)
        self.assertIsNone(c['Mail'])            # another team's numbers are not told


class NeverWider(unittest.TestCase):
    def test_approvers_and_envelope(self):
        eff = T.merge_policies([
            ('Top', {'approval': {'mode': 'always', 'approvers': 'both'}}),
            ('Web', {'approval': {'mode': 'always', 'approvers': 'team'}})])
        self.assertEqual(eff['approval']['approvers'], 'both')
        eff = T.merge_policies([
            ('Top', {'approval': {'mode': 'always', 'approvers': 'parent'}}),
            ('Web', {'approval': {'mode': 'profile', 'approvers': 'team'}})])
        self.assertEqual((eff['approval']['mode'], eff['approval']['approvers']),
                         ('always', 'both'))
        eff = T.merge_policies([
            ('Top', {'approval': {'mode': 'outside', 'outside': {
                'suffixes': ['example.test'], 'max_days': 90, 'profiles': ['A', 'B']}}}),
            ('Web', {'approval': {'mode': 'outside', 'outside': {
                'suffixes': ['test'], 'max_days': 365, 'key_types': ['rsa-2048']}}})])
        env = eff['approval']['outside']
        self.assertEqual(env, {'suffixes': ['example.test'], 'max_days': 90,
                               'profiles': ['A', 'B'], 'key_types': ['rsa-2048']})
        # as before where one team alone says it
        eff = T.merge_policies([('Web', {'approval': {'mode': 'always'}})])
        self.assertEqual(eff['approval'], {'mode': 'always', 'count': 1, 'self': False})

    def test_portal_refuses_fewer_approvers(self):
        B.clean()
        T.save_team(STORE, {'name': 'Top', 'members': [
            {'who': 'local:tm', 'roles': ['Team manager']}],
            'policy': {'approval': {'mode': 'always', 'approvers': 'both'}}}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Top'}, 'x')
        T.save_team(STORE, {'name': 'Dev', 'parent': 'Web'}, 'x')
        st, words = refusal('tm', 'POST', 'team_save', {
            'old_name': 'Dev', 'policy': {'approval': {'mode': 'always', 'approvers': 'team'}}})
        self.assertEqual(st, 403, words)
        self.assertIn('approval', words)
        self.assertEqual(status('tm', 'POST', 'team_save', {
            'old_name': 'Dev', 'policy': {'approval': {'mode': 'always', 'approvers': 'both',
                                                       'count': 2}}}), 200)


class PortalTeams(unittest.TestCase):
    def setUp(self):
        B.clean()
        T.save_team(STORE, {'name': 'Top', 'kind': 'unit'}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Top', 'members': [
            {'who': 'local:tm', 'roles': ['Team manager']},
            {'who': 'local:mate', 'roles': ['Viewer']}]}, 'x')
        T.save_team(STORE, {'name': 'Mail', 'parent': 'Top', 'members': [
            {'who': 'local:tm', 'roles': ['Viewer'], 'until': time.time() + 86400}]}, 'x')
        T.save_team(STORE, {'name': 'WebDev', 'parent': 'Web'}, 'x')
        T.save_team(STORE, {'name': 'WebOps', 'parent': 'Web'}, 'x')
        T.save_team(STORE, {'name': 'MailSub', 'parent': 'Mail', 'members': [
            {'who': 'local:tm', 'roles': ['Team manager']}]}, 'x')

    def test_never_a_name_certificates_carry(self):
        cert('jn1', 'jnovak')                       # a person's own (a free-text owner)
        st, words = refusal('tm', 'POST', 'team_save', {'name': 'jnovak', 'parent': 'Web'})
        self.assertEqual(st, 403, words)
        self.assertIsNone(T.team_get(STORE, 'jnovak'))
        self.assertEqual(STORE.db.value("SELECT owner FROM certs WHERE name = 'jn1'"), 'jnovak')
        st, words = refusal('tm', 'POST', 'team_save', {'old_name': 'WebDev', 'name': 'JNovak'})
        self.assertEqual(st, 403, words)
        self.assertEqual(status('tm', 'POST', 'team_save', {
            'name': 'jan@corp.example', 'parent': 'Web'}), 403)
        self.assertEqual(status('tm', 'POST', 'team_save', {'name': 'WebNew', 'parent': 'Web'}),
                         200)

    def test_moved_with_limits_needs_policy_there(self):
        # team.create on MailSub (Team manager), but limits set while moving WebDev under it
        T.save_team(STORE, {'old_name': 'MailSub', 'name': 'MailSub', 'members': [
            {'who': 'local:tm', 'roles': ['Viewer']}]}, 'x')
        T.save_role(STORE, {'name': 'Maker', 'caps': ['team.view', 'team.create']}, 'x')
        T.save_team(STORE, {'old_name': 'MailSub', 'name': 'MailSub', 'members': [
            {'who': 'local:tm', 'roles': ['Maker']}]}, 'x')
        st, words = refusal('tm', 'POST', 'team_save', {
            'old_name': 'WebDev', 'parent': 'MailSub', 'policy': {'max_days': 30}})
        self.assertEqual(st, 403, words)
        self.assertIn('team.policy', words)
        self.assertEqual(T.team_get(STORE, 'WebDev')['parent'], 'Web')
        self.assertEqual(status('tm', 'POST', 'team_save', {
            'old_name': 'WebDev', 'parent': 'MailSub'}), 200)

    def test_anothers_membership_not_made_ones_own(self):
        # tm holds Viewer on Mail until tomorrow; a member's row there turned into tm's own
        # forever is adding oneself
        T.save_team(STORE, {'old_name': 'WebOps', 'name': 'WebOps', 'members': [
            {'who': 'local:mate', 'roles': ['Viewer']}]}, 'x')
        st, words = refusal('tm', 'POST', 'member_save', {
            'team': 'WebOps', 'old_who': 'local:mate', 'who': 'local:tm', 'roles': ['Viewer']})
        self.assertEqual(st, 403, words)
        self.assertIn('yourself', words)
        ms = json.loads(T.team_get(STORE, 'WebOps')['members'])
        self.assertEqual([m['who'] for m in ms], ['local:mate'])

    def test_manage_is_approving(self):
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web', 'members': [
            {'who': 'local:tm', 'roles': ['Team manager', 'Certificate manager']},
            {'who': 'local:own', 'roles': ['Team owner']}]}, 'x')
        # the Certificate manager does not approve: giving the old manage is giving approving
        st, words = refusal('tm', 'POST', 'member_save', {
            'team': 'WebDev', 'who': 'local:n1', 'rights': ['manage']})
        self.assertEqual(st, 403, words)
        rights = {r['name']: r['givable'] for r in call('tm', 'GET', 'members',
                                                        args={'team': 'WebDev'})['rights']}
        self.assertFalse(rights['manage'])
        # a Team owner holds approving: manage is theirs to give
        self.assertEqual(status('own', 'POST', 'member_save', {
            'team': 'WebDev', 'who': 'local:n1', 'rights': ['manage']}), 200)


class ActionLevels(unittest.TestCase):
    def setUp(self):
        B.clean()
        T.save_team(STORE, {'name': 'Region', 'members': [
            {'who': 'local:boss', 'roles': ['Approver']}]}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Region', 'members': [
            {'who': 'local:lead', 'roles': ['Approver']},
            {'who': 'local:cm', 'roles': ['Certificate manager']}],
            'policy': {'approve_actions': ['revoke', 'key'],
                       'approval': {'mode': 'profile', 'approvers': 'parent'}}}, 'x')
        self.cid = cert('act1', 'Web')

    def ask(self):
        with B.Stubs():
            got = call('cm', 'POST', 'cert_revoke', {'id': self.cid, 'reason': 'superseded'})
        self.assertTrue(got['waits'])
        return got['action']['id']

    def test_only_the_level_the_rule_names(self):
        aid = self.ask()
        self.assertEqual(call('lead', 'GET', 'inbox')['actions'], [])
        self.assertEqual([a['id'] for a in call('boss', 'GET', 'inbox')['actions']], [aid])
        self.assertEqual(status('lead', 'POST', 'action_approve', {'id': aid, 'ok': 0,
                                                                   'why': 'no'}), 403)
        self.assertEqual(status('lead', 'POST', 'action_approve', {'id': aid, 'ok': 1}), 403)
        self.assertEqual(TP._action_get(STORE, aid)['state'], 'waiting')
        with B.Stubs():
            got = call('boss', 'POST', 'action_approve', {'id': aid, 'ok': 1})
        self.assertEqual(got['action']['state'], 'done')

    def test_key_taken_once(self):
        with B.Stubs():
            got = call('cm', 'POST', 'cert_download', {'id': self.cid, 'format': 'pfx',
                                                      'password': 'long-enough-pw'})
            kid = got['action']['id']
            call('boss', 'POST', 'action_approve', {'id': kid, 'ok': 1})
            body = {'id': self.cid, 'format': 'pfx', 'password': 'long-enough-pw', 'action': kid}
            self.assertEqual(status('cm', 'POST', 'cert_download', body), 200)
            self.assertEqual(status('cm', 'POST', 'cert_download', body), 409)
        # two at once: one takes it
        rec = TP._action_get(STORE, kid)
        STORE.set_meta(TP.ACTION_META + kid, json.dumps(dict(rec, state='approved'),
                                                        sort_keys=True))
        self.assertIsNotNone(TP.action_take(STORE, kid, 'a'))
        self.assertIsNone(TP.action_take(STORE, kid, 'b'))

    def test_follow_rename_and_delete(self):
        aid = self.ask()
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web9'}, 'x')
        self.assertEqual(TP._action_get(STORE, aid)['team'], 'Web9')
        self.assertEqual([a['id'] for a in call('boss', 'GET', 'inbox')['actions']], [aid])
        T.delete_team(STORE, 'Web9', 'x', reassign='Region')
        self.assertEqual(TP._action_get(STORE, aid)['state'], 'declined')


class Via(unittest.TestCase):
    def setUp(self):
        B.clean()
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:dm', 'roles': ['Device manager']}]}, 'x')
        T.save_team(STORE, {'name': 'Other'}, 'x')
        conn = {'host': 'c.example.test', 'user': 'u', 'auth': 'password', 'password': 'x'}
        device('acmeconn', None, 'ssh_connector', dict(conn))
        device('otherconn', 'Other', 'ssh_connector', dict(conn))
        device('webconn', 'Web', 'ssh_connector', dict(conn))
        self.acme_id = STORE.db.value("SELECT id FROM cert_targets WHERE name = 'acmeconn'")

    def save(self, cfg, kind='ssh', name='s1'):
        base = {'host': 'h.example.test', 'user': 'u', 'auth': 'password', 'password': 'pw'}
        base.update(cfg)
        return refusal('dm', 'POST', 'device_save', {'team': 'Web', 'name': name, 'kind': kind,
                                                     'config': base})

    def test_never_through_anothers(self):
        self.assertEqual(self.save({'via': 'acmeconn'})[0], 403)
        self.assertEqual(self.save({'via': 'otherconn'})[0], 403)
        self.assertEqual(self.save({'ssh_via': 'acmeconn'}, 'opnsense')[0], 403)
        # a device of the team by its id, where the run goes by the name
        STORE.db.insert('cert_tests', {'name': str(self.acme_id), 'kind': 'ssh_relay',
                                       'config': '{}', 'enabled': 1})
        try:
            webconn = STORE.db.value("SELECT id FROM cert_targets WHERE name = 'webconn'")
            self.assertEqual(self.save({'via': str(webconn)})[0], 403)
        finally:
            STORE.db.run("DELETE FROM cert_tests WHERE kind = 'ssh_relay'")
        self.assertEqual(self.save({'via': 'webconn'}), (200, ''))

    def test_form_lists_the_teams_only(self):
        kinds = call('dm', 'GET', 'kinds', args={'team': 'Web'})['kinds']
        ssh = [k for k in kinds if k['kind'] == 'ssh'][0]
        via = [f for f in ssh['fields'] if f['key'] == 'via'][0]
        self.assertEqual(sorted(o[0] for o in via['options']), ['', 'webconn'])
        self.assertNotIn('acmeconn', json.dumps(kinds))
        self.assertNotIn('otherconn', json.dumps(kinds))


class AdminScoped(unittest.TestCase):
    def setUp(self):
        B.clean()
        T.save_team(STORE, {'name': 'Web', 'members': [{'who': 'local:ca', 'rights': ['manage']}],
                            'policy': {'key_download': False}}, 'x')
        T.save_team(STORE, {'name': 'Other'}, 'x')
        self.cid = cert('k1', 'Web')
        device('od1', 'Other')
        E.CONFIG.update(certs_certadmin_all=0)
        self.s = {'name': 'ca', 'role': 'certadmin', 'account': {'source': 'local'}}

    def tearDown(self):
        E.CONFIG.update(certs_certadmin_all=1)

    def guard(self, path, body):
        h = B.FakeH(None, body)
        try:
            T.guard(h, self.s, 'POST', path)
            return 200
        except E.ApiError as e:
            return e.status

    def test_key_and_deploy_limits(self):
        self.assertEqual(self.guard('/api/certs/export', {'id': self.cid, 'format': 'pfx'}), 403)
        self.assertEqual(self.guard('/api/certs/export', {'id': self.cid,
                                                          'format': 'fullchain-pem'}), 200)
        self.assertEqual(self.guard('/api/deploys/save', {'cert_id': self.cid,
                                                          'target': 'od1'}), 403)


class EnrollTeamGone(unittest.TestCase):
    def setUp(self):
        B.clean()
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:dm', 'roles': ['Device manager']}],
            'policy': {'target_kinds': ['ssh', 'agent']}}, 'x')

    def take(self, code, fqdn, platform='linux'):
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
                'host': fqdn.split('.')[0], 'fqdn': fqdn, 'os': 'Rocky 9', 'platform': platform,
                'version': '1.0.125', 'code': 'c0de', 'port': 8446,
                'proof': G.proof(data['s'], 'enroll', data['e'], sha, enc, nonce, fqdn)}
        return G.enroll_take(STORE, body, '192.0.2.10')

    def test_no_device_without_agents(self):
        code = call('dm', 'POST', 'enroll_code', {'team': 'Web', 'mode': 'active', 'days': 2})
        # Windows servers are not among the team's modules
        st, out = self.take(code['code'], 'win1.example.test', 'windows')
        self.assertEqual(st, 403, out)
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web',
                            'policy': {'target_kinds': ['ssh']}}, 'x')
        st, out = self.take(code['code'], 'web1.example.test')
        self.assertEqual(st, 403, out)
        self.assertIsNone(STORE.db.value("SELECT id FROM cert_targets WHERE name = 'web1'"))
        T.save_team(STORE, {'old_name': 'Web', 'name': 'Web',
                            'policy': {'target_kinds': ['ssh', 'agent']}}, 'x')
        st, out = self.take(code['code'], 'web2.example.test')
        self.assertEqual(st, 200, out)
        self.assertEqual(STORE.db.value("SELECT owner FROM cert_targets WHERE name = 'web2'"),
                         'Web')


class WaitsForWhom(unittest.TestCase):
    """A request waiting for its team's rule says whom it waits for - not an administrator."""
    def setUp(self):
        B.clean()
        STORE.db.run('DELETE FROM events')
        T.save_team(STORE, {'name': 'Prague', 'kind': 'unit'}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Prague', 'members': [
            {'who': 'local:asker', 'roles': ['Requester']}],
            'policy': {'approval': {'mode': 'always', 'approvers': 'both', 'count': 2}}}, 'x')

    def test_words_name_the_rule(self):
        got = call('asker', 'POST', 'cert_request', {'names': ['w1.example.test'],
                                                     'issuer': 'self', 'team': 'Web'})
        self.assertTrue(got['waits'])
        self.assertIn('the team Web', got['waits_for'])
        self.assertIn('then one of Prague', got['waits_for'])
        self.assertIn('two different people', got['waits_for'])
        words = [r['words'] for r in T.team_activity(STORE, 'Web')[0]]
        said = [w for w in words if 'asked on the portal' in w]
        self.assertTrue(said and 'the team Web\'s rule' in said[0], words)
        self.assertNotIn('administrator', said[0])
        # one's own request, no team: as before
        own = call('asker', 'POST', 'cert_request', {'names': ['w2.example.test'],
                                                     'issuer': 'self'})
        self.assertNotIn('waits_for', own)
        self.assertTrue(any('w2.example.test' in r['words'] and 'an administrator\'s approval'
                            in r['words'] for r in STORE.events(50)[0]))


class Statements(unittest.TestCase):
    """The certificates page of a team of hundreds: a few statements a page."""
    def test_not_per_certificate(self):
        B.clean()
        T.save_team(STORE, {'name': 'Big', 'members': [
            {'who': 'local:bm', 'roles': ['Certificate manager']}]}, 'x')
        now = time.time()
        with STORE.db.transaction():
            for n in range(300):
                STORE.db.insert('certs', {'name': 'big%03d' % n, 'owner': 'Big', 'state': 'ok',
                                          'names': json.dumps(['big%d.example.test' % n]),
                                          'issuer': 'self', 'created': now, 'version': 1,
                                          'not_after': now + 5 * 86400})
        STORE.set_meta(P.META + str(STORE.db.value("SELECT id FROM certs WHERE name = "
                                                   "'big007'")),
                       json.dumps({'who': 'local:bm', 'ids': ['local:bm'], 'profile': 'P1'}))
        counted = [0]
        db = STORE.db
        was = (db.rows, db.row, db.value)

        def wrap(f):
            def g(*a, **k):
                counted[0] += 1
                return f(*a, **k)
            return g
        db.rows, db.row, db.value = (wrap(f) for f in was)
        try:
            counted[0] = 0
            got = call('bm', 'GET', 'certs', None, {'team': 'Big', 'per': 200})
            n_page = counted[0]
            counted[0] = 0
            mine = call('bm', 'GET', 'certs', None, {'state': 'mine', 'per': 50})
            n_mine = counted[0]
        finally:
            db.rows, db.row, db.value = was
        self.assertEqual(len(got['rows']), 200)
        self.assertLess(n_page, 80, n_page)
        self.assertLess(n_mine, 80, n_mine)
        self.assertEqual([r['name'] for r in mine['rows']], ['big007'])
        one = [r for r in got['rows'] if r['name'] == 'big007'][0]
        self.assertEqual(one['req_profile'], 'P1')          # read as each alone reads it


if __name__ == '__main__':
    unittest.main(verbosity=1)
