#!/usr/bin/env python3
"""Owners and teams, tags, and who may see and do what (docs/teams.md).

    python3 test/test_teams.py

- owners added, changed, renamed (their certificates follow) and deleted - refused
  while they own certificates, or with their certificates given to another;
- tags of the catalog: renamed on certificates and targets, deleted only with strip;
- what certificates said before (free text) made owners and tags, nothing lost;
- the matrix: full administrator / certificate administrator / read-only account,
  local and from the directory (a group), x view / request / manage / approve, x the two
  settings on and off - over the routes of the API; a full administrator always all;
  every refusal an event;
- the portal: a person sees the certificates of the teams with them as a member (a
  local account, a user of the directory, a group they are in) and asks only for the
  teams where they may;
- the notices go to the owner team's mail too;
- a backup and the configuration's export carry both catalogs;
- the details saved alone (owner, tags, note, renewal) never touch the certificate:
  no new version, no new state, nothing due.
"""
import contextlib
import gzip
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-teams-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402  (the routes)
from acmelib.certs import teams as T, notices, renewer  # noqa: E402
from acmelib.certs import portal as _portal  # noqa: E402,F401  (its routes)

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
BASE = 'DC=corpnet,DC=loc'
WEB_DN = 'CN=WEB_ADMINS,OU=Groups,' + BASE


class FakeH(object):
    """A request of the administration pages (or, `portal`, of the portal)."""
    def __init__(self, who='boss', role='fulladmin', body=None, args=None, source='local',
                 groups='', portal=None):
        self.store, self._body, self.args = STORE, dict(body or {}), dict(args or {})
        self.who, self.role, self.source, self.groups, self.portal = who, role, source, groups, \
            portal
        self.headers = {}

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


def clean():
    for t in ('certs', 'cert_teams', 'cert_tags', 'cert_versions', 'cert_jobs', 'cert_deploys',
              'cert_targets'):
        STORE.db.run('DELETE FROM %s' % t)
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1, certs_notify_mail='',
                    portal=1, portal_cert=1, portal_local=1)
    if not STORE.account('marta'):
        STORE.add_account('marta', 'readonly', 'Local-Only-Pw-77!x')
    if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
        STORE.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1})


def cert(name, owner='', **more):
    b = {'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self', 'key_type': 'ec-256',
         'auto_renew': 0, 'owner': owner}
    b.update(more)
    return A.cert_save(STORE, b, 'test')


def issued(cid):
    """A certificate as if it had been issued: a version, a PEM, a state."""
    t = time.time()
    STORE.db.update('certs', cid, {'cert_pem': 'PEM', 'version': 3, 'state': 'ok',
                                   'not_before': t - 86400, 'not_after': t + 80 * 86400,
                                   'serial': 'AB', 'fingerprint': 'FP',
                                   # acme's key (1.0.96: a version with no key and no CSR
                                   # given was issued for a device's key)
                                   'key_sealed': 'sealed'})
    STORE.db.insert('cert_versions', {'cert_id': cid, 'version': 3, 'cert_pem': 'PEM',
                                      'created': t, 'why': 'issue'})


class Catalogs(unittest.TestCase):
    def setUp(self):
        clean()

    def test_teams_crud_rename_and_delete(self):
        got = call('POST', '/api/teams/save', {'name': 'Web team', 'members': [
            'local:jan=manage', {'who': 'group:WEB_ADMINS', 'rights': ['view']}, 'novak@corp'],
            'contact_mail': 'web@example.test'})['team']
        self.assertEqual([m['who'] for m in got['members']],
                         ['local:jan', 'group:WEB_ADMINS', 'novak@corp'])
        self.assertEqual(got['members'][2]['rights'], ['view', 'request'])
        self.assertEqual([m['kind'] for m in got['members']], ['local', 'group', 'user'])
        with self.assertRaises(ValueError):
            T.save_team(STORE, {'name': 'web TEAM'}, 'x')           # the same, other case
        with self.assertRaises(ValueError):
            T.save_team(STORE, {'name': 'bad:name'}, 'x')
        with self.assertRaises(ValueError):
            T.save_team(STORE, {'name': 'X', 'members': ['a=fly']}, 'x')
        with self.assertRaises(ValueError):
            T.save_team(STORE, {'name': 'X', 'contact_mail': 'not mail'}, 'x')
        cid = cert('w1', 'Web team')
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web team'}, 'x')
        self.assertEqual(STORE.db.value('SELECT owner FROM certs WHERE id = ?', (cid,)), 'Web')
        listed = call('GET', '/api/teams', role='readonly')
        self.assertEqual([(t['name'], t['used']) for t in listed['teams']], [('Web', 1)])
        self.assertFalse(listed['can_change'])
        self.assertEqual(status(call, 'POST', '/api/teams/save', {'name': 'Y'},
                                role='certadmin'), 403)
        # In use: refused, then given to another.
        with self.assertRaises(ValueError):
            T.delete_team(STORE, 'Web', 'x')
        T.save_team(STORE, {'name': 'Ops'}, 'x')
        got = call('POST', '/api/teams/delete', {'name': 'Web', 'reassign': 'Ops'})
        self.assertEqual((got['moved'], got['to']), (1, 'Ops'))
        self.assertEqual(STORE.db.value('SELECT owner FROM certs WHERE id = ?', (cid,)), 'Ops')
        got = call('POST', '/api/teams/delete', {'name': 'Ops', 'reassign': ''})
        self.assertEqual(STORE.db.value('SELECT owner FROM certs WHERE id = ?', (cid,)), '')

    def test_tags(self):
        cid = cert('t1', tags=['prod', 'web'])
        STORE.db.insert('cert_targets', {'name': 'srv', 'kind': 'ssh', 'tags': '["prod"]'})
        call('POST', '/api/tags/save', {'name': 'prod', 'colour': 'crit', 'description': 'live'})
        with self.assertRaises(ValueError):
            T.save_tag(STORE, {'name': 'two words'}, 'x')
        with self.assertRaises(ValueError):
            T.save_tag(STORE, {'name': 'x', 'colour': 'chartreuse'}, 'x')
        got = call('GET', '/api/teams')
        self.assertEqual([(t['name'], t['certs'], t['targets']) for t in got['tags']],
                         [('prod', 1, 1)])
        self.assertEqual([t['tag'] for t in got['legacy']['tags']], ['web'])
        T.save_tag(STORE, {'name': 'production', 'old_name': 'prod'}, 'x')
        self.assertEqual(json.loads(STORE.db.value('SELECT tags FROM certs WHERE id = ?', (cid,))),
                         ['production', 'web'])
        self.assertIn('production', STORE.db.value('SELECT tags FROM cert_targets'))
        with self.assertRaises(ValueError):
            T.delete_tag(STORE, 'production', 'x')
        self.assertEqual(T.delete_tag(STORE, 'production', 'x', strip=True)['stripped'], 2)
        self.assertEqual(json.loads(STORE.db.value('SELECT tags FROM certs WHERE id = ?', (cid,))),
                         ['web'])

    def test_adopt_keeps_everything(self):
        a = cert('a1', 'novak', tags=['dmz'])
        b = cert('a2', 'group:CN=X,OU=G')
        lg = T.legacy(STORE)
        self.assertEqual(sorted(o['owner'] for o in lg['owners']), ['group:CN=X,OU=G', 'novak'])
        got = call('POST', '/api/teams/adopt', {})
        self.assertEqual(len(got['teams']), 2)
        self.assertEqual(got['tags'], ['dmz'])
        self.assertEqual(T.legacy(STORE), {'owners': [], 'tags': []})
        owner_b = STORE.db.value('SELECT owner FROM certs WHERE id = ?', (b,))
        self.assertEqual(owner_b, 'X')
        self.assertEqual(T.team_get(STORE, 'X')['kind'], 'team')
        self.assertEqual(json.loads(T.team_get(STORE, 'X')['members'])[0]['who'],
                         'group:CN=X,OU=G')
        self.assertEqual(STORE.db.value('SELECT owner FROM certs WHERE id = ?', (a,)), 'novak')

    def test_backup_and_export_carry(self):
        T.save_team(STORE, {'name': 'Carried', 'members': ['local:jan']}, 'x')
        T.save_tag(STORE, {'name': 'carried-tag'}, 'x')
        path = os.path.join(TMP, 'copy.json.gz')
        with open(path, 'wb') as f:
            E.dump_tables(STORE.db, f)
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            text = f.read()
        self.assertIn('Carried', text)
        self.assertIn('carried-tag', text)
        out = E.carry_export(STORE, True)
        self.assertEqual([r['name'] for r in out.get('cert_teams', [])], ['Carried'])
        self.assertEqual([r['name'] for r in out.get('cert_tags', [])], ['carried-tag'])


class Matrix(unittest.TestCase):
    """Who sees and does what, over the routes."""
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:cweb', 'rights': ['manage']},
            {'who': 'local:rweb', 'rights': ['view']},
            {'who': 'local:appr', 'rights': ['approve']},
            {'who': 'group:WEB_ADMINS', 'rights': ['manage']}]}, 'x')
        T.save_team(STORE, {'name': 'Mail', 'members': ['local:cmail=request']}, 'x')
        self.web = cert('web1', 'Web')
        self.mail = cert('mail1', 'Mail')
        self.none = cert('none1', '')

    def seen(self, **who):
        return sorted(r['name'] for r in call('GET', '/api/certs', **who)['rows'])

    def may(self, method, path, body=None, args=None, **who):
        return status(call, method, path, body, args, **who)

    def test_defaults_change_nothing(self):
        allc = ['mail1', 'none1', 'web1']
        for role in ('fulladmin', 'certadmin', 'readonly'):
            self.assertEqual(self.seen(who='x', role=role), allc, role)
        self.assertEqual(self.may('POST', '/api/certs/save', {'id': self.mail, 'note': 'n'},
                                  who='cweb', role='certadmin'), 200)

    def test_full_admin_always_everything(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        self.assertEqual(self.seen(who='boss', role='fulladmin'), ['mail1', 'none1', 'web1'])
        for cid in (self.web, self.mail, self.none):
            self.assertEqual(self.may('GET', '/api/certs/one', args={'id': cid}), 200)
            self.assertEqual(self.may('POST', '/api/certs/save', {'id': cid, 'note': 'x'}), 200)
        self.assertEqual(self.may('POST', '/api/certs/save', {'names': ['n.example.test'],
                                                              'issuer': '', 'owner': ''}), 200)

    def test_scoped_matrix(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        cases = [
            # who, role, source, groups: sees; may manage web; may manage mail
            (('cweb', 'certadmin', 'local', ''), ['web1'], 200, 403),
            (('cmail', 'certadmin', 'local', ''), ['mail1'], 403, 403),
            (('rweb', 'readonly', 'local', ''), ['web1'], 403, 403),
            (('appr', 'certadmin', 'local', ''), ['web1'], 403, 403),
            (('stranger', 'certadmin', 'local', ''), [], 403, 403),
            (('cweb', 'readonly', 'directory', ''), [], 403, 403),        # not local:cweb
            (('eva', 'certadmin', 'directory', WEB_DN + '; ' + 'CN=Other,' + BASE),
             ['web1'], 200, 403),
        ]
        for (who, role, source, groups), sees, web, mail in cases:
            w = dict(who=who, role=role, source=source, groups=groups)
            self.assertEqual(self.seen(**w), sees, w)
            self.assertEqual(self.may('POST', '/api/certs/save', {'id': self.web, 'note': 'x'},
                                      **w), web, w)
            self.assertEqual(self.may('POST', '/api/certs/auto', {'id': self.web, 'on': 1},
                                      **w), web, w)
            self.assertEqual(self.may('POST', '/api/certs/save', {'id': self.mail, 'note': 'x'},
                                      **w), mail, w)
            self.assertEqual(self.may('GET', '/api/certs/one', args={'id': self.web}, **w),
                             200 if 'web1' in sees else 403, w)
            self.assertEqual(self.may('GET', '/api/certs/one', args={'id': self.none}, **w), 403)
        # A new certificate: for a team where they may request (or manage); never unowned.
        new = {'names': ['n.example.test'], 'issuer': ''}
        self.assertEqual(self.may('POST', '/api/certs/save', dict(new, owner='Mail'),
                                  who='cmail', role='certadmin'), 200)
        self.assertEqual(self.may('POST', '/api/certs/save', dict(new, owner='Web', name='n2'),
                                  who='cmail', role='certadmin'), 403)
        self.assertEqual(self.may('POST', '/api/certs/save', dict(new, owner='', name='n3'),
                                  who='cweb', role='certadmin'), 403)
        # Another owner: manage on the old team, request on the new.
        self.assertEqual(self.may('POST', '/api/certs/save', {'id': self.web, 'owner': 'Mail'},
                                  who='cweb', role='certadmin'), 403)
        T.save_team(STORE, {'name': 'Mail', 'old_name': 'Mail', 'members': ['local:cmail=request',
                                                       'local:cweb=request']}, 'x')
        self.assertEqual(self.may('POST', '/api/certs/save', {'id': self.web, 'owner': 'Mail'},
                                  who='cweb', role='certadmin'), 200)
        # The owner select offers what they may give.
        got = call('GET', '/api/teams', who='cmail', role='certadmin')
        self.assertEqual((got['choosable'], got['unowned_ok']), (['Mail'], False))
        self.assertEqual(call('GET', '/api/teams')['choosable'], ['Mail', 'Web'])
        # Every refusal is an event.
        words = [r['words'] for r in STORE.db.rows(
            "SELECT words FROM events WHERE kind = 'certificates' AND level = 'warn'")]
        self.assertTrue(any('cmail was refused' in w for w in words), words[-5:])

    def test_approve_right(self):
        E.CONFIG.update(certs_certadmin_all=0)
        STORE.db.update('certs', self.web, {'state': 'pending-approval'})
        self.assertEqual(self.may('POST', '/api/certs/approve', {'id': self.web, 'ok': False,
                                                                 'why': 'no'},
                                  who='cmail', role='certadmin'), 403)
        self.assertEqual(self.may('POST', '/api/certs/approve', {'id': self.web, 'ok': False,
                                                                 'why': 'no'},
                                  who='appr', role='certadmin'), 200)

    def test_jobs_and_deploys_filtered(self):
        E.CONFIG.update(certs_certadmin_all=0)
        for cid in (self.web, self.mail):
            STORE.db.insert('cert_jobs', {'ts': time.time(), 'kind': 'renew', 'cert_id': cid,
                                          'state': 'done', 'ok': 1})
        got = call('GET', '/api/certs/jobs', who='cweb', role='certadmin')
        self.assertEqual([r['cert_id'] for r in got['rows']], [self.web])
        self.assertEqual(len(call('GET', '/api/certs/jobs')['rows']), 2)
        jid = STORE.db.value('SELECT id FROM cert_jobs WHERE cert_id = ?', (self.mail,))
        self.assertEqual(self.may('GET', '/api/certs/job', args={'id': jid},
                                  who='cweb', role='certadmin'), 403)


    def test_ids_the_route_reads_are_checked_too(self):
        # ' 5', 5.0, '5 ': the route reads them as the number (api._id); the check took
        # them for a name, found nothing and let the route act (1.0.19).
        E.CONFIG.update(certs_certadmin_all=0)
        for ref in (self.mail, str(self.mail), ' %d' % self.mail, '%d ' % self.mail,
                    float(self.mail)):
            self.assertEqual(self.may('POST', '/api/certs/auto', {'id': ref, 'auto_renew': 0},
                                      who='cweb', role='certadmin'), 403, repr(ref))
            self.assertEqual(self.may('POST', '/api/certs/save', {'id': ref, 'note': 'x'},
                                      who='cweb', role='certadmin'), 403, repr(ref))
        self.assertEqual(self.may('POST', '/api/certs/auto', {'id': ' %d' % self.web,
                                                              'auto_renew': 0},
                                  who='cweb', role='certadmin'), 200)

    def test_a_deployment_of_another_team_is_not_taken_over(self):
        E.CONFIG.update(certs_certadmin_all=0)
        STORE.db.insert('cert_targets', {'name': 't1', 'kind': 'local', 'config': '{}',
                                         'enabled': 1})
        dep = A.deploy_save(STORE, {'cert_id': self.mail, 'target': 't1'}, 'x')
        for path in ('/api/deploys/save', '/api/deploys/preview'):
            self.assertEqual(self.may('POST', path, {'id': dep, 'cert_id': self.web},
                                      who='cweb', role='certadmin'), 403, path)
        self.assertEqual(STORE.db.value('SELECT cert_id FROM cert_deploys WHERE id = ?', (dep,)),
                         self.mail)
        self.assertEqual(self.may('POST', '/api/deploys/save', {'cert_id': self.web,
                                                                'target': 't1'},
                                  who='cweb', role='certadmin'), 200)

    def test_overview_and_jobs_are_its_own(self):
        E.CONFIG.update(certs_certadmin_all=0)
        issued(self.mail)
        STORE.db.update('certs', self.mail, {'state': 'failed', 'last_error': 'secret words'})
        for i in range(60):        # more than a page of the other team's jobs, newer
            STORE.db.insert('cert_jobs', {'ts': time.time() + i, 'kind': 'renew', 'state': 'done',
                                          'cert_id': self.mail, 'ok': 1})
        STORE.db.insert('cert_jobs', {'ts': time.time() - 100, 'kind': 'renew', 'state': 'done',
                                      'cert_id': self.web, 'ok': 1})
        ov = call('GET', '/api/certs/overview', who='cweb', role='certadmin')
        self.assertEqual(ov['total'], 1)
        self.assertNotIn('failed', ov['by_state'])
        self.assertEqual([a for a in ov['alerts'] if 'mail1' in a['words']], [])
        self.assertEqual({r['cert_id'] for r in ov['jobs']}, {self.web})
        got = call('GET', '/api/certs/jobs', who='cweb', role='certadmin')
        self.assertEqual(([r['cert_id'] for r in got['rows']], got['total']), ([self.web], 1))
        full = call('GET', '/api/certs/overview')
        self.assertEqual(full['total'], 3)
        self.assertTrue([a for a in full['alerts'] if 'mail1' in a['words']])
        self.assertEqual(call('GET', '/api/certs/jobs')['total'], 61)


class Portal(unittest.TestCase):
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Web', 'members': [
            'local:marta=view', 'group:WEB_ADMINS=request', 'falco@corp.test=view']}, 'x')
        T.save_team(STORE, {'name': 'Hidden', 'members': ['local:other']}, 'x')
        self.web = cert('pweb', 'Web')
        self.hidden = cert('phidden', 'Hidden')

    def person(self, name, local=False, groups=(), mail=''):
        data = {'kind': 'local' if local else 'directory', 'mail': mail,
                'about': {'upn': mail}, 'cert_groups': [list(g) for g in groups],
                'cert_groups_at': time.time(), 'dn': 'CN=%s,%s' % (name, BASE),
                'dir_checked': time.time()}     # just signed in: not asked again yet
        return {'name': name, 'data': data, 'kind': 'portal'}

    def rows(self, s):
        h = FakeH(portal=s)
        return {r['name']: r['via'] for r in E.ROUTES[('GET', '/api/portal/certs')](h)['rows']}

    def test_visibility_by_team(self):
        self.assertEqual(self.rows(self.person('marta', local=True)), {'pweb': 'Web'})
        self.assertEqual(self.rows(self.person('marta')), {})            # not the local one
        self.assertEqual(self.rows(self.person('eva', groups=[(WEB_DN, 'WEB_ADMINS')])),
                         {'pweb': 'Web'})
        self.assertEqual(self.rows(self.person('falco', mail='falco@corp.test')), {'pweb': 'Web'})
        self.assertEqual(self.rows(self.person('nobody')), {})

    def test_request_for_a_team(self):
        E.CONFIG.update(portal_cert_suffixes='example.test', portal_cert_issuers='self')
        eva = self.person('eva', groups=[(WEB_DN, 'WEB_ADMINS')])
        h = FakeH(portal=eva)
        self.assertEqual(E.ROUTES[('GET', '/api/portal/certs')](h)['teams'], ['Web'])
        marta = self.person('marta', local=True)
        h = FakeH(portal=marta, body={'names': ['m.example.test'], 'issuer': 'self',
                                      'team': 'Web'})
        self.assertEqual(status(E.ROUTES[('POST', '/api/portal/cert_request')], h), 403)
        h = FakeH(portal=eva, body={'names': ['e.example.test'], 'issuer': 'self',
                                    'team': 'Web'})
        got = E.ROUTES[('POST', '/api/portal/cert_request')](h)
        self.assertEqual(STORE.db.value('SELECT owner FROM certs WHERE id = ?', (got['id'],)),
                         'Web')


class Approvals(unittest.TestCase):
    """Who approves a request (1.0.102): never the one who asked, on either side; a name
    another team's certificate holds by that team's approver; what a scoped session is told
    of another team's certificates."""
    def setUp(self):
        clean()
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0, portal_cert_auto=1,
                        portal_cert_suffixes='example.test', portal_cert_issuers='self',
                        portal_cert_max=50, mail_mode='off')
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:portal:%'")
        T.save_team(STORE, {'name': 'Web', 'members': [
            'local:eva=request', 'local:appr=approve', 'local:both=approve',
            'local:cweb=manage', 'local:jan=request,approve',
            'novak=request']}, 'x')
        T.save_team(STORE, {'name': 'Mail', 'contact_mail': 'mail-team@example.test',
                            'members': ['local:both=approve', 'local:cmail=manage']}, 'x')
        self.held = cert('mailcert', 'Mail', names=['mail.example.test'])
        for n in ('eva', 'appr', 'both', 'jan'):
            if not STORE.account(n):
                STORE.add_account(n, 'readonly', 'Local-Only-Pw-77!x' + n)

    def tearDown(self):
        # the issues approved here done before the next test empties the tables
        from acmelib.certs import jobs
        E.CONFIG.update(portal_cert_auto=0, portal_cert_suffixes='', portal_cert_issuers='')
        end = time.time() + 20
        while time.time() < end and (jobs.RUNNING or jobs.BUSY_CERTS):
            time.sleep(0.05)

    def person(self, name, local=True, mail=''):
        return Portal.person(None, name, local=local, mail=mail)

    def ask(self, s, names, team='Web'):
        h = FakeH(portal=s, body={'names': names, 'issuer': 'self', 'team': team})
        return E.ROUTES[('POST', '/api/portal/cert_request')](h)

    def approve(self, s, cid):
        return status(E.ROUTES[('POST', '/api/portal/cert_approve')],
                      FakeH(portal=s, body={'id': cid, 'ok': 1}))

    def test_may_approve_said_before(self):
        """Approve is not offered and then refused (hunt N): each waiting row says
        may_approve and why - on the portal and in the administration's list and view - by
        the same checks the approve routes make, and saying it changes nothing."""
        cid = self.ask(self.person('eva'), ['mail.example.test', 'w2.example.test'])['id']

        def portal_row(s):
            rows = E.ROUTES[('GET', '/api/portal/certs')](FakeH(portal=s))['rows']
            return [r for r in rows if r['id'] == cid][0]
        # an approver of Web alone: not hers to approve - and the route agrees
        one = portal_row(self.person('appr'))
        self.assertIs(one['may_approve'], False)
        self.assertIn('the team Mail (mail.example.test)', one['approve_why'])
        self.assertTrue(one['approve_why'].startswith('its names are held by certificates of '
                                                      'another owner'))
        self.assertEqual(self.approve(self.person('appr'), cid), 403)
        # the one who asked: never
        one = portal_row(self.person('eva'))
        self.assertIs(one['may_approve'], False)
        self.assertIn('you asked for it yourself', one['approve_why'])
        # an approver of both teams: yes
        one = portal_row(self.person('both'))
        self.assertIs(one['may_approve'], True)
        self.assertEqual(one['approve_why'], '')
        # the administration: a scoped certadmin of Web alone no, a full administrator yes
        n = int(STORE.db.value("SELECT COUNT(*) FROM events WHERE words LIKE '%was refused%'",
                               (), 0) or 0)
        adm = call('GET', '/api/certs/one', args={'id': cid}, who='cweb', role='certadmin')
        self.assertIs(adm['cert']['may_approve'], False)
        self.assertIn('the team Mail (mail.example.test)', adm['cert']['approve_why'])
        listed = call('GET', '/api/certs', args={'state': 'pending-approval'}, who='cweb',
                      role='certadmin')['rows']
        self.assertEqual([(r['may_approve'], r['approve_why']) for r in listed],
                         [(False, adm['cert']['approve_why'])])
        # nothing said or written by asking (only the route refuses with an event)
        self.assertEqual(int(STORE.db.value(
            "SELECT COUNT(*) FROM events WHERE words LIKE '%was refused%'", (), 0) or 0), n)
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': cid, 'ok': 1},
                                who='cweb', role='certadmin'), 403)
        full = call('GET', '/api/certs/one', args={'id': cid})['cert']
        self.assertIs(full['may_approve'], True)
        self.assertEqual(S_state(cid), 'pending-approval')

    def test_a_held_name_is_approved_by_its_team(self):
        got = self.ask(self.person('eva'), ['mail.example.test'])
        cid = got['id']
        self.assertTrue(got['waits'])
        self.assertEqual(_portal.asker(STORE, cid)['held'],
                         [{'owner': 'Mail', 'names': ['mail.example.test']}])
        # the approval dialogs say whose names they are - the portal's and the administration's
        rows = E.ROUTES[('GET', '/api/portal/certs')](FakeH(portal=self.person('appr')))['rows']
        one = [r for r in rows if r['id'] == cid][0]
        self.assertEqual(one['held'], [{'team': 'Mail', 'names': ['mail.example.test']}])
        self.assertEqual(one['held_words'], ['the team Mail (mail.example.test)'])
        adm = call('GET', '/api/certs/one', args={'id': cid})['cert']
        self.assertEqual(adm['held_words'], ['the team Mail (mail.example.test)'])
        listed = [r for r in call('GET', '/api/certs', args={'state': 'pending-approval'})['rows']]
        self.assertEqual([r.get('held_words') for r in listed],
                         [['the team Mail (mail.example.test)']])
        # an approver of Web alone: no - neither on the portal nor in the administration
        self.assertEqual(self.approve(self.person('appr'), cid), 403)
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': cid, 'ok': 1},
                                who='cweb', role='certadmin'), 403)
        self.assertEqual(S_state(cid), 'pending-approval')
        # an approver of both teams: yes
        self.assertEqual(self.approve(self.person('both'), cid), 200)
        # the team that holds the name was told (an event; its mail when mail is on)
        for _ in range(50):
            words = [r['words'] for r in STORE.db.rows(
                "SELECT words FROM events WHERE words LIKE '%by the team Mail%'")]
            if words:
                break
            time.sleep(0.05)
        self.assertTrue(words)
        # in the administration: a full administrator, or one with approve on Mail too
        got = self.ask(self.person('eva'), ['mail.example.test'])
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': got['id'], 'ok': 1},
                                who='both', role='certadmin'), 200)
        got = self.ask(self.person('eva'), ['mail.example.test'])
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': got['id'], 'ok': 1}),
                         200)

    def test_never_ones_own_on_the_administration_pages(self):
        E.CONFIG.update(portal_cert_auto=0)
        got = self.ask(self.person('jan'), ['jan.example.test'])
        cid = got['id']
        self.assertEqual(self.approve(self.person('jan'), cid), 403)
        for role in ('certadmin', 'fulladmin'):
            try:
                call('POST', '/api/certs/approve', {'id': cid, 'ok': 1}, who='jan', role=role)
                self.fail('approved by the one who asked (%s)' % role)
            except E.ApiError as e:
                self.assertEqual(e.status, 403)
                self.assertIn('have another administrator approve or decline it', str(e))
        self.assertEqual(S_state(cid), 'pending-approval')
        # declined by oneself: fine
        self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                {'id': cid, 'ok': 0, 'why': 'not needed'}, who='jan',
                                role='certadmin'), 200)
        # a person of the directory, by their name without the domain or their mail
        got = self.ask(self.person('novak', local=False, mail='novak@corp.test'),
                       ['novak.example.test'])
        for who, src in (('CORP\\novak', 'directory'), ('novak@corp.test', 'directory')):
            self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': got['id'], 'ok': 1},
                                    who=who, role='fulladmin', source=src), 403, who)
        # ...but a local administrator of the same name is another person
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': got['id'], 'ok': 1},
                                who='novak', role='fulladmin'), 200)

    def test_scoped_sessions_are_not_told_of_other_teams(self):
        STORE.db.insert('cert_targets', {'name': 'cucm1', 'kind': 'cucm', 'config': '{}',
                                         'enabled': 1})
        STORE.db.insert('cert_targets', {
            'name': 'srv', 'kind': 'local', 'config': '{}', 'enabled': 1,
            'last_error': 'acme does not hold the private key of mailcert yet, and srv needs it'})
        STORE.db.update('certs', self.held, {'csr_from': 'cucm1'})
        for who, role in (('cweb', 'certadmin'), ('cweb', 'readonly')):
            rows = {r['name']: r for r in call('GET', '/api/targets', who=who, role=role)['rows']}
            self.assertEqual(rows['cucm1'].get('key_of'), A.OTHERS_CERT)
            self.assertNotIn('mailcert', rows['srv']['last_error'])
        rows = {r['name']: r for r in call('GET', '/api/targets', who='cmail',
                                           role='certadmin')['rows']}
        self.assertEqual(rows['cucm1'].get('key_of'), 'mailcert')
        self.assertIn('mailcert', rows['srv']['last_error'])
        rows = {r['name']: r for r in call('GET', '/api/targets')['rows']}
        self.assertEqual(rows['cucm1'].get('key_of'), 'mailcert')
        # a name taken by another team's certificate: not named
        mine = call('POST', '/api/certs/save', {'names': ['w1.example.test'], 'issuer': '',
                                                'owner': 'Web', 'name': 'w1'},
                    who='cweb', role='certadmin')['id']
        for b in ({'id': mine, 'name': 'mailcert'},
                  {'names': ['w2.example.test'], 'issuer': '', 'owner': 'Web',
                   'name': 'mailcert'}):
            with self.assertRaises(ValueError) as e:
                call('POST', '/api/certs/save', b, who='cweb', role='certadmin')
            self.assertNotIn('mailcert', str(e.exception))
        with self.assertRaises(ValueError) as e:
            call('POST', '/api/certs/save', {'id': mine, 'name': 'mailcert'})
        self.assertIn('mailcert', str(e.exception))
        # the device that makes another team's certificate's key: not named
        from acmelib.certs import devicekey
        why = devicekey.save_problem(STORE, {'id': mine, 'name': 'w1', 'csr_from': 'cucm1',
                                             'issuer': 'self', 'key_type': 'rsa-2048'},
                                     deploys=[], may_see=lambda r: False)
        self.assertNotIn('mailcert', why)
        why = devicekey.save_problem(STORE, {'id': mine, 'name': 'w1', 'csr_from': 'cucm1',
                                             'issuer': 'self', 'key_type': 'rsa-2048'},
                                     deploys=[])
        self.assertTrue(why)

    def test_scoped_administrator_and_names_another_team_holds(self):
        new = {'names': ['mail.example.test'], 'issuer': '', 'owner': 'Web', 'name': 'mine'}
        self.assertEqual(status(call, 'POST', '/api/certs/save', new, who='cweb',
                                role='certadmin'), 403)
        self.assertIsNone(STORE.db.row("SELECT id FROM certs WHERE name = 'mine'"))
        # under a wildcard of theirs too; its own names - fine
        self.assertEqual(status(call, 'POST', '/api/certs/save', dict(
            new, names=['*.example.test']), who='cweb', role='certadmin'), 403)
        cid = call('POST', '/api/certs/save', dict(new, names=['w.example.test']), who='cweb',
                   role='certadmin')['id']
        self.assertEqual(status(call, 'POST', '/api/certs/save', {
            'id': cid, 'names': ['w.example.test', 'mail.example.test']}, who='cweb',
            role='certadmin'), 403)
        self.assertEqual(status(call, 'POST', '/api/certs/save', {'id': cid, 'note': 'x'},
                                who='cweb', role='certadmin'), 200)
        # a full administrator may; and one who sees every certificate
        self.assertEqual(status(call, 'POST', '/api/certs/save', {
            'id': cid, 'names': ['w.example.test', 'mail.example.test']}), 200)
        E.CONFIG.update(certs_certadmin_all=1)
        self.assertEqual(status(call, 'POST', '/api/certs/save', dict(new, name='mine2'),
                                who='cweb', role='certadmin'), 200)


    def dir_person(self, upn, sam, dn):
        """A portal sign-in of the directory: its name the UPN, as the portal makes it."""
        return {'name': upn, 'kind': 'portal',
                'data': {'kind': 'directory', 'mail': '', 'dn': dn, 'dir_checked': time.time(),
                         'about': {'upn': upn, 'sam': sam}, 'cert_groups': [],
                         'cert_groups_at': time.time()}}

    def test_directory_admin_by_upn_sam_and_dn(self):
        """1.0.102: a directory administrator whose portal UPN (jan.novak@corp) is not their
        account's name (jnovak) approved their own request."""
        E.CONFIG.update(portal_cert_auto=0)
        dn = 'CN=Jan Novak,OU=People,' + BASE
        jan = self.dir_person('jan.novak@corp.test', 'jnovak', dn)
        cid = self.ask(jan, ['jn.example.test'], team='')['id']
        ids = _portal.askers_of(STORE, cid)
        self.assertTrue({'jan.novak@corp.test', 'jnovak', dn.lower()} <= ids)
        # by the DN alone: an account named otherwise
        adm = {'name': 'novak-admin', 'role': 'fulladmin',
               'account': {'name': 'novak-admin', 'source': 'directory', 'dn': dn}}
        self.assertTrue(_portal.asked_by_admin(STORE, {'id': cid}, adm))
        adm['account']['dn'] = 'CN=Someone Else,' + BASE
        self.assertFalse(_portal.asked_by_admin(STORE, {'id': cid}, adm))
        # by the sAMAccountName: the administration's account jnovak (its DN another spelling)
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': cid, 'ok': 1},
                                who='jnovak', role='fulladmin', source='directory'), 403)
        self.assertEqual(S_state(cid), 'pending-approval')
        # the other way: names given in the administration, approved on the portal
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web', 'members': [
            'local:eva=request', 'jnovak=approve', 'jan.novak@corp.test=approve']}, 'x')
        cid = self.ask(self.person('eva'), ['e2.example.test'])['id']
        call('POST', '/api/certs/save', {'id': cid, 'names': ['e3.example.test']},
             who='jnovak', role='fulladmin', source='directory')
        self.assertIn('cn=jnovak,ou=people,' + BASE.lower(), _portal.askers_of(STORE, cid))
        other = self.dir_person('jan.novak@corp.test', 'jn2', 'CN=jnovak,OU=People,' + BASE)
        self.assertEqual(self.approve(other, cid), 403)          # the same DN
        self.assertEqual(self.approve(self.dir_person('jnovak@corp.test', 'jnovak',
                                                      'CN=x,' + BASE), cid), 403)   # its sam
        self.assertEqual(S_state(cid), 'pending-approval')
        # nor in the administration: another administrator approves or declines it
        try:
            call('POST', '/api/certs/approve', {'id': cid, 'ok': 1}, who='jnovak',
                 role='fulladmin', source='directory')
            self.fail('approved by the one who gave it its names')
        except E.ApiError as e:
            self.assertIn('another administrator approve or decline it', str(e))
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': cid, 'ok': 1}), 200)

    def test_asked_by_admin_no_false_matches(self):
        """r_asker.py (1.0.102): another person's request read as the administrator's own -
        jan@partner for jan@corp, local:jan for the directory's jan, a mail jan@gmail for
        CORP\\jan."""
        got = {}
        was = _portal.asker
        _portal.asker = lambda store, cid: got
        self.addCleanup(setattr, _portal, 'asker', was)

        def adm(name, source='directory', **acc):
            return {'name': name, 'role': 'certadmin', 'account': dict(source=source, **acc)}

        def asked(who, ids, a):
            got.clear()
            got.update(who=who, ids=ids)
            return _portal.asked_by_admin(None, {'id': 1}, a)
        self.assertFalse(asked('jan@partner.example', ['jan@partner.example'],
                               adm('jan@corp.example', dn='cn=jan,dc=corp')))
        self.assertFalse(asked('local:jan', ['local:jan'], adm('jan')))
        self.assertFalse(asked('novakj', ['novakj', 'jan@gmail.example'], adm('corp\\jan')))
        # a local administrator is no directory person of the same name
        self.assertFalse(asked('jan', ['jan', 'cn=jan,dc=corp'], adm('jan', source='local')))
        # the true ones
        self.assertTrue(asked('local:jan', ['local:jan'], adm('jan', source='local')))
        self.assertTrue(asked('jan@corp.example', ['jan@corp.example', 'jan'], adm('corp\\jan')))
        self.assertTrue(asked('x', ['other\\jan'], adm('corp\\jan')))
        self.assertTrue(asked('jan@corp.example', ['jan@corp.example'],
                              adm('jan@corp.example')))
        self.assertTrue(asked('x', ['cn=jan,dc=corp'], adm('admin-jan', dn='CN=Jan,DC=corp')))
        self.assertTrue(asked('x', ['jan@corp.example'], adm('jn', mail='Jan@corp.example')))

    def test_no_owner_run_out_revoked_hold_nothing(self):
        """1.0.102 decisions: a certificate without an owner, one run out, or one revoked or
        declined holds no names - any approver approves."""
        free = cert('freecert', '', names=['free.example.test'])
        got = self.ask(self.person('eva'), ['free.example.test'])
        self.assertTrue(got['waits'])                    # waits all the same (1.0.51)...
        self.assertEqual(_portal.asker(STORE, got['id'])['held'], [])
        self.assertEqual(self.approve(self.person('appr'), got['id']), 200)   # ...any approver
        self.assertEqual(_portal.holders(STORE, ['free.example.test'], 'Web'), {})
        self.assertEqual(list(_portal.holders(STORE, ['free.example.test'], 'Web',
                                              unowned=True)), [''])
        STORE.db.run('DELETE FROM certs WHERE id = ?', (free,))
        # run out
        STORE.db.update('certs', self.held, {'not_after': time.time() - 60})
        self.assertEqual(_portal.holders(STORE, ['mail.example.test'], 'Web'), {})
        got = self.ask(self.person('eva'), ['mail.example.test'])
        self.assertFalse(got['waits'])
        STORE.db.update('certs', self.held, {'not_after': time.time() + 86400})
        self.assertEqual(list(_portal.holders(STORE, ['mail.example.test'], 'Web')), ['Mail'])
        for st in ('revoked', 'declined'):
            STORE.db.update('certs', self.held, {'state': st})
            self.assertEqual(_portal.holders(STORE, ['mail.example.test'], 'Web'), {}, st)

    def test_held_read_once_for_a_list(self):
        E.CONFIG.update(portal_cert_auto=0)
        for n in ('l1', 'l2', 'l3'):
            self.ask(self.person('eva'), ['%s.example.test' % n])
        calls = []
        real = _portal.holder_rows

        def counted(store):
            calls.append(1)
            return real(store)
        _portal.holder_rows = counted
        try:
            rows = call('GET', '/api/certs', args={'state': 'pending-approval'})['rows']
            self.assertEqual((len(rows), len(calls)), (3, 1))
            del calls[:]
            rows = E.ROUTES[('GET', '/api/portal/certs')](FakeH(portal=self.person('appr')))
            self.assertEqual(len(calls), 1)
        finally:
            _portal.holder_rows = real

    def test_no_way_past_the_approval(self):
        """1.0.106: a CSR given out (/api/certs/csr), a certificate imported into it, a CSR's
        answer took a request that waits - or one declined - out of the wait ('pending', 'ok'),
        and Renew now issued it: past the names another team holds and one's own request. And
        one moved out of the wait all the same is never issued until approved."""
        import base64
        from acmelib.certs import jobs, pki, store as S
        E.CONFIG.update(portal_cert_auto=0)
        cid = self.ask(self.person('eva'), ['mail.example.test'])['id']
        self.assertTrue(_portal.asker(STORE, cid)['waits'])
        k = pki.make_key('ec-256')
        data = (pki.self_signed(k, ['mail.example.test']) + pki.key_plain(k)).encode()
        imp = {'id': cid, 'data_b64': base64.b64encode(data).decode(), 'filename': 'c.pem'}
        for who_, role in (('cweb', 'certadmin'), ('boss', 'fulladmin')):
            self.assertEqual(status(call, 'POST', '/api/certs/csr', {'id': cid}, who=who_,
                                    role=role), 409)
            self.assertEqual(status(call, 'POST', '/api/certs/import', imp, who=who_,
                                    role=role), 409)
            self.assertEqual(status(call, 'POST', '/api/certs/csr_answer', imp, who=who_,
                                    role=role), 409)
            self.assertEqual(S_state(cid), 'pending-approval')
        with self.assertRaises(ValueError):
            A.start_renew(STORE, cid, True, 'cweb')
        with self.assertRaises(ValueError):
            A.cert_auto(STORE, cid, 1, 'cweb')
        # declined: the same
        self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                {'id': cid, 'ok': 0, 'why': 'no'}), 200)
        self.assertEqual(status(call, 'POST', '/api/certs/csr', {'id': cid}), 409)
        self.assertEqual(status(call, 'POST', '/api/certs/import', imp), 409)
        self.assertEqual(S_state(cid), 'declined')
        with self.assertRaises(ValueError):
            A.start_renew(STORE, cid, True, 'boss')
        # out of the wait without an approval (as before 1.0.106): never issued
        cid2 = self.ask(self.person('eva'), ['mail.example.test'])['id']
        STORE.db.update('certs', cid2, {'state': 'pending'})
        self.assertIn('never approved', S.unapproved_why(STORE, S.cert_get(STORE, cid2)))
        with self.assertRaises(ValueError):
            A.start_renew(STORE, cid2, True, 'boss')
        self.assertEqual(status(call, 'POST', '/api/certs/import', dict(imp, id=cid2)), 409)
        job = jobs.run_now(STORE, 'renew', renewer.renew_job(cid2, True, 'test'), cert_id=cid2)
        self.assertFalse(job.ok)
        self.assertEqual(int(STORE.db.value('SELECT version FROM certs WHERE id = ?', (cid2,))
                             or 0), 0)
        # approved: issued, renewed, imported into as any other
        STORE.db.update('certs', cid2, {'state': 'pending-approval'})
        self.assertEqual(self.approve(self.person('both'), cid2), 200)
        self.assertEqual(_portal.asker(STORE, cid2)['approved']['by'], 'portal:both')
        self.assertEqual(S.unapproved_why(STORE, S.cert_get(STORE, cid2)), '')
        # a row from before 1.0.106 (no `waits` kept): its state alone counts
        old = cert('oldportal', 'Web')
        STORE.db.update('certs', old, {'created_by': 'portal:eva'})
        STORE.set_meta(_portal.META + str(old), json.dumps({'who': 'eva'}))
        self.assertEqual(S.unapproved_why(STORE, S.cert_get(STORE, old)), '')

    def test_approval_noted_with_its_state(self):
        """1.0.106: the state taken out of the wait and `approved` noted were two writes - a
        stop between them, or a CSR sent at that moment (the meta written whole over the
        approval), left a request 'new' that was "never approved" and Approve said it did not
        wait: stuck for good. Now one transaction, the meta compare-and-swapped, and Approve
        takes such a row as a repair."""
        from acmelib.certs import store as S
        E.CONFIG.update(portal_cert_auto=0)
        cid = self.ask(self.person('eva'), ['w1.example.test'])['id']
        # the approval cannot be noted: the state is not changed either
        real = _portal.asker_change

        def broken(store, cid_, change):
            raise E.ApiError(409, 'no')
        _portal.asker_change = broken
        try:
            self.assertEqual(self.approve(self.person('appr'), cid), 409)
        finally:
            _portal.asker_change = real
        self.assertEqual(S_state(cid), 'pending-approval')
        # a write of the meta between the read and the write of another: both kept
        n = [0]

        def change(a):
            n[0] += 1
            if n[0] == 1:
                _portal.note_asker(STORE, cid, 'local:other')
            a['approved'] = {'by': 'x', 'at': 1}
        _portal.asker_change(STORE, cid, change)
        a = _portal.asker(STORE, cid)
        self.assertEqual(n[0], 2)
        self.assertIn('local:other', a['askers'])
        self.assertEqual(a['approved']['by'], 'x')
        # stuck as 1.0.106 left it: out of the wait, waits, never approved - Approve repairs it
        _portal.mark_waiting(STORE, cid)
        STORE.db.update('certs', cid, {'state': 'ok'})
        self.assertIn('never approved', S.unapproved_why(STORE, S.cert_get(STORE, cid)))
        self.assertEqual(self.approve(self.person('eva'), cid), 403)     # never one's own
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': cid, 'ok': 1}), 200)
        self.assertEqual(S.unapproved_why(STORE, S.cert_get(STORE, cid)), '')
        self.assertEqual(S_state(cid), 'ok')
        # a declined one is not "repaired": it waits for nobody
        cid2 = self.ask(self.person('eva'), ['w2.example.test'])['id']
        STORE.db.update('certs', cid2, {'state': 'declined'})
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': cid2, 'ok': 1}), 409)

    def test_stuck_one_declined(self):
        """1.0.106 (final review): a request stuck out of the wait ('new' or 'pending', waits,
        never approved) could be approved only - Decline said it did not wait. Now declined
        with the rights of declining one that waits; `approved` written false. One issued
        meanwhile is not declined (it is revoked)."""
        from acmelib.certs import store as S
        E.CONFIG.update(portal_cert_auto=0)
        for state in ('new', 'pending'):
            cid = self.ask(self.person('eva'), ['w-%s.example.test' % state])['id']
            _portal.mark_waiting(STORE, cid)
            STORE.db.update('certs', cid, {'state': state})
            body = {'id': cid, 'ok': 0, 'why': 'no'}
            # without a word why: refused, nothing changed
            self.assertEqual(status(E.ROUTES[('POST', '/api/portal/cert_approve')],
                                    FakeH(portal=self.person('appr'),
                                          body=dict(body, why=''))), 400)
            self.assertEqual(S_state(cid), state)
            self.assertEqual(status(E.ROUTES[('POST', '/api/portal/cert_approve')],
                                    FakeH(portal=self.person('appr'), body=body)), 200)
            self.assertEqual(S_state(cid), 'declined')
            a = _portal.asker(STORE, cid)
            self.assertIs(a['approved'], False)
            self.assertTrue(a['waits'])
            self.assertIn('declined', S.unapproved_why(STORE, S.cert_get(STORE, cid)))
            # declined once: neither declined nor approved again
            self.assertEqual(status(call, 'POST', '/api/certs/approve', body), 409)
            self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                    {'id': cid, 'ok': 1}), 409)
        # the administration declines one as well
        cid = self.ask(self.person('eva'), ['w-adm.example.test'])['id']
        _portal.mark_waiting(STORE, cid)
        STORE.db.update('certs', cid, {'state': 'new'})
        self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                {'id': cid, 'ok': 0, 'why': 'no'}), 200)
        self.assertEqual(S_state(cid), 'declined')
        # one with a certificate issued: not declined
        cid = self.ask(self.person('eva'), ['w-ok.example.test'])['id']
        _portal.mark_waiting(STORE, cid)
        STORE.db.update('certs', cid, {'state': 'ok', 'cert_pem': 'PEM'})
        self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                {'id': cid, 'ok': 0, 'why': 'no'}), 409)
        self.assertEqual(S_state(cid), 'ok')
        # one that never needed an approval: not declined either
        cid = self.ask(self.person('eva'), ['w-free.example.test'])['id']
        STORE.set_meta(_portal.META + str(cid), json.dumps({'who': 'local:eva'}))
        STORE.db.update('certs', cid, {'state': 'new'})
        self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                {'id': cid, 'ok': 0, 'why': 'no'}), 409)
        self.assertEqual(S_state(cid), 'new')

    def test_stuck_offered_approve_and_decline(self):
        """1.0.107: a request stuck out of the wait (approval_missing) could be declined only
        with `acme --decline` - the pages offered neither button. Now its rows say `stuck`, and
        may_approve / may_decline with why, by the checks of the routes: the asker, names
        another owner holds, the rights; one with a certificate is not declined (revoked)."""
        from acmelib.certs import store as S
        E.CONFIG.update(portal_cert_auto=0)
        T.save_team(STORE, {'name': 'Web', 'old_name': 'Web', 'members': [
            'local:eva=request', 'local:appr=approve', 'local:both=approve',
            'local:cweb=manage', 'local:jan=request,approve', 'novak=request',
            'local:vera=view']}, 'x')
        if not STORE.account('vera'):
            STORE.add_account('vera', 'readonly', 'Local-Only-Pw-77!xvera')

        def stuck(name, state='pending', **more):
            cid = self.ask(self.person('eva'), [name])['id']
            _portal.mark_waiting(STORE, cid)
            STORE.db.update('certs', cid, dict(state=state, **more))
            self.assertTrue(_portal.approval_missing(STORE, S.cert_get(STORE, cid)))
            return cid
        a = stuck('s1.example.test', 'new')
        b = stuck('s2.example.test', 'ok', cert_pem='PEM')
        h = stuck('mail.example.test')

        def portal_row(s, cid):
            rows = E.ROUTES[('GET', '/api/portal/certs')](FakeH(portal=s))['rows']
            return [r for r in rows if r['id'] == cid][0]
        appr = self.person('appr')
        one = portal_row(appr, a)
        self.assertIs(one['stuck'], True)
        self.assertEqual((one['may_approve'], one['may_decline']), (True, True))
        one = portal_row(appr, b)
        self.assertEqual((one['may_approve'], one['may_decline']), (True, False))
        self.assertIn('revoke it instead', one['decline_why'])
        one = portal_row(appr, h)
        self.assertIs(one['may_approve'], False)
        self.assertIn('the team Mail (mail.example.test)', one['approve_why'])
        one = portal_row(self.person('eva'), a)                     # the asker
        self.assertIs(one['may_approve'], False)
        self.assertIn('you asked for it yourself', one['approve_why'])
        one = portal_row(self.person('vera'), a)                    # may only look
        self.assertEqual((one['may_approve'], one['may_decline']), (False, False))
        self.assertIn('the right approve', one['approve_why'])
        self.assertEqual(one['approve_why'], one['decline_why'])
        self.assertEqual(status(E.ROUTES[('POST', '/api/portal/cert_approve')],
                                FakeH(portal=self.person('vera'),
                                      body={'id': a, 'ok': 0, 'why': 'no'})), 403)
        # a row not stuck says nothing of it
        self.assertNotIn('stuck', portal_row(self.person('both'), self.held))
        # the administration: the list and the view
        listed = {r['id']: r for r in call('GET', '/api/certs')['rows']}
        self.assertTrue(listed[a]['stuck'] and listed[b]['stuck'] and listed[h]['stuck'])
        self.assertNotIn('stuck', listed[self.held])
        self.assertNotIn('may_approve', listed[self.held])
        self.assertEqual((listed[a]['may_approve'], listed[a]['may_decline']), (True, True))
        self.assertEqual((listed[b]['may_approve'], listed[b]['may_decline']), (True, False))
        self.assertIn('revoke it instead', listed[b]['decline_why'])
        view = call('GET', '/api/certs/one', args={'id': b})['cert']
        self.assertIs(view['stuck'], True)
        self.assertEqual(view['decline_why'], listed[b]['decline_why'])
        self.assertNotIn('stuck', call('GET', '/api/certs/one', args={'id': self.held})['cert'])
        # a scoped certificate administrator of Web alone: not the held one
        view = call('GET', '/api/certs/one', args={'id': h}, who='cweb', role='certadmin')['cert']
        self.assertIs(view['may_approve'], False)
        self.assertIn('the team Mail (mail.example.test)', view['approve_why'])
        self.assertIs(view['may_decline'], True)
        # ...of Mail alone: none of Web's is seen, stuck or not
        seen = call('GET', '/api/certs', who='cmail', role='certadmin')['rows']
        self.assertEqual({r['id'] for r in seen} & {a, b, h}, set())
        self.assertEqual(status(call, 'GET', '/api/certs/one', args={'id': a}, who='cmail',
                                role='certadmin'), 403)
        # a read-only account: neither, and why
        E.CONFIG.update(certs_readonly_all=1)
        try:
            ro = call('GET', '/api/certs/one', args={'id': a}, who='ro', role='readonly')['cert']
            self.assertEqual((ro['may_approve'], ro['may_decline']), (False, False))
            self.assertIn('certificate administrator', ro['approve_why'])
            row = [r for r in call('GET', '/api/certs', who='ro', role='readonly')['rows']
                   if r['id'] == a][0]
            self.assertEqual((row['may_approve'], row['approve_why']),
                             (False, ro['approve_why']))
        finally:
            E.CONFIG.update(certs_readonly_all=0)
        # Approve and Decline through the routes - the portal's and the administration's
        got = E.ROUTES[('POST', '/api/portal/cert_approve')](FakeH(portal=appr,
                                                                   body={'id': a, 'ok': 1}))
        self.assertTrue(got.get('job_id'))                          # 'new': issued now
        self.assertEqual(S.unapproved_why(STORE, S.cert_get(STORE, a)), '')
        c = stuck('s3.example.test')
        self.assertEqual(status(E.ROUTES[('POST', '/api/portal/cert_approve')],
                                FakeH(portal=appr, body={'id': c, 'ok': 0, 'why': 'no'})), 200)
        self.assertEqual(S_state(c), 'declined')
        d = stuck('s4.example.test')
        self.assertEqual(status(call, 'POST', '/api/certs/approve', {'id': d, 'ok': 1}), 200)
        self.assertEqual(S.unapproved_why(STORE, S.cert_get(STORE, d)), '')
        e = stuck('s5.example.test')
        self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                {'id': e, 'ok': 0, 'why': 'no'}), 200)
        self.assertEqual(S_state(e), 'declined')
        # the one with a certificate: as said - not declined
        self.assertEqual(status(call, 'POST', '/api/certs/approve',
                                {'id': b, 'ok': 0, 'why': 'no'}), 409)
        # repaired or declined: stuck no more
        listed = {r['id']: r for r in call('GET', '/api/certs')['rows']}
        for cid in (a, c, d, e):
            self.assertNotIn('stuck', listed[cid])

    def test_meta_read_locked_in_a_mariadb_transaction(self):
        """1.0.106 (final review): on MariaDB (REPEATABLE READ) each try of the compare-and-
        swap inside approve_request's transaction read the snapshot again - never what another
        wrote, a 409 after a second. Read FOR UPDATE there."""
        E.CONFIG.update(portal_cert_auto=0)
        cid = self.ask(self.person('eva'), ['w-maria.example.test'])['id']
        seen = []
        real = STORE.db

        class Maria:
            """The real database, said to be MariaDB inside a transaction."""
            engine, in_tx = 'mariadb', True

            def value(self, sql, *a, **k):
                seen.append(sql)
                return real.value(sql.replace(' FOR UPDATE', ''), *a, **k)

            def transaction(self):
                return contextlib.nullcontext()

            def __getattr__(self, k):
                return getattr(real, k)

        class Store:
            db = Maria()

            def get_meta(self, k):
                seen.append('get_meta')
                return STORE.get_meta(k)
        _portal.mark_approved(Store(), cid, 'x')
        Maria.in_tx = False
        _portal.mark_approved(Store(), cid, 'y')          # outside one: as ever
        self.assertEqual(seen, ['SELECT v FROM meta WHERE k = ? FOR UPDATE', 'get_meta'])
        self.assertEqual(_portal.asker(STORE, cid)['approved']['by'], 'y')

    def test_held_only_while_a_holder_lives(self):
        """1.0.106: the team kept as holding a name when the request began to wait stayed its
        only approver for good - its certificate revoked, run out or deleted since."""
        E.CONFIG.update(portal_cert_auto=0)
        cid = self.ask(self.person('eva'), ['mail.example.test'])['id']
        row = lambda: STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))   # noqa: E731
        self.assertEqual(_portal.held_of(STORE, row()),
                         [{'owner': 'Mail', 'names': ['mail.example.test']}])
        STORE.db.update('certs', self.held, {'state': 'revoked'})
        self.assertEqual(_portal.held_of(STORE, row()), [])
        STORE.db.update('certs', self.held, {'state': 'ok', 'not_after': time.time() - 60})
        self.assertEqual(_portal.held_of(STORE, row()), [])
        STORE.db.update('certs', self.held, {'not_after': time.time() + 86400})
        self.assertEqual(_portal.held_of(STORE, row()),
                         [{'owner': 'Mail', 'names': ['mail.example.test']}])
        # a declined one keeps what still holds its names only
        STORE.db.run('DELETE FROM certs WHERE id = ?', (self.held,))
        STORE.db.update('certs', cid, {'state': 'declined'})
        self.assertEqual(_portal.held_of(STORE, row()), [])
        STORE.db.update('certs', cid, {'state': 'pending-approval'})
        # Web's approver alone approves it now
        self.assertEqual(self.approve(self.person('appr'), cid), 200)

    def test_scoped_administrator_keeps_names_held_since(self):
        """1.0.102: only the names given now are looked at - a name the certificate had
        already, held by another team's since, does not refuse every change of its names."""
        cid = call('POST', '/api/certs/save', {'names': ['w.example.test', 'mail.example.test'],
                                               'issuer': '', 'owner': 'Web', 'name': 'wm'})['id']
        self.assertEqual(status(call, 'POST', '/api/certs/save', {
            'id': cid, 'names': ['w.example.test', 'mail.example.test', 'w2.example.test']},
            who='cweb', role='certadmin'), 200)
        self.assertEqual(status(call, 'POST', '/api/certs/save', {
            'id': cid, 'names': ['w.example.test', 'mail.example.test', '*.example.test']},
            who='cweb', role='certadmin'), 403)


def S_state(cid):
    return STORE.db.value('SELECT state FROM certs WHERE id = ?', (cid,))


class Notices(unittest.TestCase):
    def setUp(self):
        clean()

    def test_owner_team_is_told(self):
        E.CONFIG['certs_notify_mail'] = 'admin@example.test'
        T.save_team(STORE, {'name': 'Web', 'contact_mail': 'web@example.test, ADMIN@example.test'},
                    'x')
        cid = cert('n1', 'Web')
        self.assertEqual(notices.recipients(STORE, STORE.db.row('SELECT * FROM certs WHERE id = ?',
                                                                (cid,))),
                         ['admin@example.test', 'web@example.test'])
        sent = []
        real = E.mail_deliver
        E.mail_deliver = lambda store, msg, to, **kw: sent.append(list(to))
        try:
            notices.notify(STORE, 'renew:%s' % cid, 'failed', 'it failed', force=True)
            notices.notify(STORE, 'renew-alt:%s' % cid, 'twin failed', 'it failed', force=True)
        finally:
            E.mail_deliver = real
        self.assertEqual(sent, [['admin@example.test', 'web@example.test']] * 2)
        other = cert('n2', '')
        self.assertEqual(notices.recipients(STORE, STORE.db.row(
            'SELECT * FROM certs WHERE id = ?', (other,))), ['admin@example.test'])


class Details(unittest.TestCase):
    """The details saved alone touch nothing of the certificate itself."""
    def setUp(self):
        clean()
        T.save_team(STORE, {'name': 'Web'}, 'x')

    def test_partial_save(self):
        cid = cert('d1', auto_renew=1)
        issued(cid)
        before = STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        call('POST', '/api/certs/save', {'id': cid, 'owner': 'Web', 'tags': ['a', 'b'],
                                         'note': 'n', 'auto_renew': 0, 'renew_days': 20,
                                         'reuse_key': 1, 'name': 'd1-renamed', 'enabled': 1})
        after = STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        for k in ('cert_pem', 'version', 'state', 'not_after', 'serial', 'fingerprint', 'names',
                  'key_type', 'issuer', 'profile', 'challenge'):
            self.assertEqual(after[k], before[k], k)
        self.assertEqual((after['owner'], json.loads(after['tags']), after['name'],
                          after['renew_days'], after['reuse_key'], after['auto_renew']),
                         ('Web', ['a', 'b'], 'd1-renamed', 20, 1, 0))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_versions WHERE cert_id = ?',
                                        (cid,)), 1)
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_jobs WHERE cert_id = ?',
                                        (cid,)), 0)
        self.assertEqual(renewer.main_due(dict(after, auto_renew=1)), '')

    def test_new_names_wait_for_the_renewal(self):
        cid = cert('d2', auto_renew=1)
        issued(cid)
        A.cert_save(STORE, {'id': cid, 'names': ['d2.example.test', 'more.example.test']}, 'x')
        after = STORE.db.row('SELECT * FROM certs WHERE id = ?', (cid,))
        self.assertEqual((after['version'], after['state'], after['cert_pem']), (3, 'ok', 'PEM'))
        self.assertEqual(renewer.main_due(after), '')     # not issued again by itself

    def test_off_and_on_again_keeps_revoked_and_unapproved(self):
        # "In use" off and on: revoked came back "ok", a request not approved "new" -
        # and was issued by itself, past its approval (1.0.19).
        cid = cert('d3', auto_renew=1)
        issued(cid)
        STORE.db.update('certs', cid, {'state': 'revoked'})
        asked = cert('d4', auto_renew=1)
        STORE.db.update('certs', asked, {'state': 'pending-approval'})
        plain = cert('d5', auto_renew=1)
        issued(plain)
        for ident, want in ((cid, 'revoked'), (asked, 'pending-approval'), (plain, 'ok')):
            A.cert_save(STORE, {'id': ident, 'enabled': 0}, 'x')
            row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (ident,))
            self.assertEqual((row['enabled'], row['state']),
                             (0, 'disabled' if ident == plain else want))
            A.cert_save(STORE, {'id': ident, 'enabled': 1}, 'x')
            row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (ident,))
            self.assertEqual((row['enabled'], row['state']), (1, want))
        self.assertEqual(renewer.main_due(STORE.db.row('SELECT * FROM certs WHERE id = ?',
                                                       (asked,))), '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
