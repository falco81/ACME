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
                                   'serial': 'AB', 'fingerprint': 'FP'})
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
            T.save_tag(STORE, {'name': 'x', 'colour': 'pink'}, 'x')
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
