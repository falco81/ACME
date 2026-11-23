#!/usr/bin/env python3
"""Hunt w4, area teams: regressions.

    python3 test/test_hunt_rw4_teams.py

- The directory's groups of an administrator (accounts.group_list) were their cn only: a team
  member named by the group's DN (group:CN=...,OU=...) gave nobody signed in anything, though the
  access check said it did; cut at 2000 characters mid-name, a group became another one.
- Taken out of a team's group in the directory, an administrator kept the team's certificates
  until their next sign-in: the check every ten minutes asked the role again, never the groups.
- A group's DN copied with spaces ("CN=PKI Web, OU=Groups,...") matched no member of it.
- A scoped certificate administrator's import (a file, or from a source) went past the team's
  limits a certificate they make is held to: the quota, the suffixes, no wildcards, the sources.
- Separation of duties of a temporary role looked at the asker's own memberships only: a
  Requester through a directory group was given Approver beside it.
"""
import collections
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-rw4-teams-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402
from acmelib import engine as EN  # noqa: E402
from acmelib.certs import teams as T  # noqa: E402
from acmelib.certs import api as A, pki, onlineimport as OI  # noqa: E402,F401
from acmelib.certs import teamgov as G  # noqa: E402

STORE = E.Storage(E.open_db())
EN.HA_STORE['store'] = STORE
BASE = 'OU=Groups,DC=corp,DC=loc'
WEB = 'CN=PKI Web,' + BASE
ADM = 'CN=Cert Admins,' + BASE
WEB_ADMINS = 'CN=PKI Web Admins,' + BASE


class FakeAd(object):
    name = 'corp'

    def __init__(self, groups):
        self.groups = list(groups)     # [(dn, cn)] the person is in now

    def find_user(self, who, how):
        return {'dn': 'CN=Jan Novak,OU=People,DC=corp,DC=loc', 'sam': 'jnovak',
                'display': 'Jan Novak'}

    def groups_of(self, entry, nested=True):
        return list(self.groups)

    def group_dns(self, name):
        return {ADM.lower()} if name.lower() in ('cert admins', 'cert-admins') else set()


class D(object):
    def __init__(self, ad):
        self.login_fails = collections.defaultdict(list)
        self.login_info = {}
        self.store = STORE
        self.dirs = {'corp': ad}


def handler(d):
    h = E.ApiHandler.__new__(E.ApiHandler)
    h.server = type('S', (), {'daemon': d})()
    h.headers = {}
    h.client_address = ('192.0.2.5', 1)
    return h


def session(acc):
    return {'name': acc['name'], 'role': acc['role'], 'account': acc}


def clean():
    STORE.db.run('DELETE FROM cert_teams')
    STORE.db.run("DELETE FROM accounts WHERE source = 'directory'")
    EN.ApiHandler.DIR_CHECKED.clear()


class GroupListKept(unittest.TestCase):
    def setUp(self):
        clean()
        self.saved = dict(EN.CONFIG)
        EN.CONFIG.update(admin_directory='corp', admin_group_cert='Cert Admins',
                         certs_readonly_all=0, certs_certadmin_all=0)

    def tearDown(self):
        EN.CONFIG.clear()
        EN.CONFIG.update(self.saved)

    def sign_in(self, ad):
        h = handler(D(ad))
        entry = ad.find_user('jnovak', 'sam')
        have = ad.groups_of(entry)
        said = {'ok': True, 'name': 'jnovak', 'role': EN.admin_role_for(have, ad),
                'dn': entry['dn'], 'display': 'Jan Novak', 'directory': 'corp', 'entry': entry,
                'groups': sorted({cn for _, cn in have}, key=str.lower),
                'group_list': EN.dir_group_list(have)}
        return h, EN.admin_directory_account(h, said)

    def test_member_by_dn_gives_its_team(self):
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'group:' + WEB, 'roles': ['Renewer']}]}, 'x')
        T.save_team(STORE, {'name': 'Spaced', 'members': [
            {'who': 'group:CN=PKI Web, OU=Groups, DC=corp, DC=loc', 'roles': ['Viewer']}]}, 'x')
        T.save_team(STORE, {'name': 'ByName', 'members': [
            {'who': 'group:PKI Web', 'roles': ['Viewer']}]}, 'x')
        _h, acc = self.sign_in(FakeAd([(ADM, 'Cert Admins'), (WEB, 'PKI Web')]))
        self.assertEqual(acc['role'], 'certadmin')
        self.assertIn(WEB, acc['group_list'])
        self.assertEqual(T.scope(STORE, session(acc), 'view'), {'web', 'spaced', 'byname'})
        self.assertEqual(T.scope(STORE, session(acc), 'cert.renew'), {'web'})

    def test_list_never_cut_mid_name(self):
        many = [('CN=Group %04d with a long name,%s' % (n, BASE), 'Group %04d' % n)
                for n in range(400)] + [(WEB_ADMINS, 'PKI Web Admins')]
        got = EN.dir_group_list(many)
        self.assertLessEqual(len(got), EN.GROUP_LIST_MOST)
        for dn, cn in T.groups_of_text(got):
            self.assertTrue(dn.endswith(BASE), dn)
        # the old cut: "...; PKI Web" of "PKI Web Admins" - another group's name
        self.assertNotIn(('PKI Web', 'PKI Web'), T.groups_of_text(got))

    def test_escaped_semicolon_in_a_dn(self):
        dn = r'CN=A\; B,' + BASE
        got = T.groups_of_text(EN.dir_group_list([(dn, 'A; B'), (WEB, 'PKI Web')]))
        self.assertEqual(sorted(c for _d, c in got), ['A; B', 'PKI Web'])

    def test_taken_out_of_a_group_followed(self):
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'group:PKI Web', 'roles': ['Renewer']}]}, 'x')
        ad = FakeAd([(ADM, 'Cert Admins'), (WEB, 'PKI Web')])
        h, acc = self.sign_in(ad)
        self.assertEqual(T.scope(STORE, session(acc), 'view'), {'web'})
        # out of the team's group in the directory, still a certificate administrator
        ad.groups = [(ADM, 'Cert Admins')]
        EN.ApiHandler.DIR_CHECKED.clear()
        acc = h.directory_recheck(STORE.account('jnovak'))
        self.assertEqual(acc['role'], 'certadmin')
        self.assertEqual(T.scope(STORE, session(acc), 'view'), set())
        self.assertNotIn('PKI Web', STORE.account('jnovak')['group_list'])
        # and put back in: the team again
        ad.groups = [(ADM, 'Cert Admins'), (WEB, 'PKI Web')]
        EN.ApiHandler.DIR_CHECKED.clear()
        acc = h.directory_recheck(STORE.account('jnovak'))
        self.assertEqual(T.scope(STORE, session(acc), 'view'), {'web'})

    def test_recheck_unchanged_writes_nothing(self):
        ad = FakeAd([(ADM, 'Cert Admins'), (WEB, 'PKI Web')])
        h, acc = self.sign_in(ad)
        calls = []
        real = STORE.set_account
        STORE.set_account = lambda *a, **k: calls.append(k) or real(*a, **k)
        try:
            EN.ApiHandler.DIR_CHECKED.clear()
            h.directory_recheck(STORE.account('jnovak'))
        finally:
            del STORE.set_account
        self.assertEqual(calls, [])

    def test_old_cn_list_still_read(self):
        # an account signed in before: its list of names still gives the teams of group:NAME
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'group:PKI Web', 'roles': ['Viewer']}]}, 'x')
        acc = {'name': 'old', 'role': 'certadmin', 'source': 'directory', 'dn': 'CN=old',
               'group_list': 'Cert Admins; PKI Web'}
        self.assertEqual(T.scope(STORE, session(acc), 'view'), {'web'})


class FakeH(object):
    def __init__(self, who, role, body):
        self.store, self._body, self.who, self.role = STORE, dict(body), who, role
        self.headers, self.args = {}, {}
        self.d = type('D', (), {'dirs': {}})()

    def me(self, _role='readonly'):
        return {'name': self.who, 'role': self.role,
                'account': {'name': self.who, 'role': self.role, 'source': 'local',
                            'dn': '', 'group_list': ''}}

    def body(self):
        return self._body

    def arg(self, name, default=''):
        return default


def pem(names):
    import base64
    k = pki.make_key('ec-256')
    return base64.b64encode((pki.self_signed(k, names) + pki.key_plain(k)).encode()).decode()


class ImportWithinLimits(unittest.TestCase):
    def setUp(self):
        clean()
        STORE.db.run('DELETE FROM certs')
        self.saved = dict(EN.CONFIG)
        EN.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'local:cweb', 'roles': ['Certificate manager']}],
            'policy': {'max_certs': 1, 'suffixes': ['example.test'], 'wildcards': False,
                       'issuers': ['allowed-src']}}, 'x')

    def tearDown(self):
        EN.CONFIG.clear()
        EN.CONFIG.update(self.saved)

    def imp(self, names, who='cweb', role='certadmin', **more):
        b = dict({'data_b64': pem(names), 'filename': 'c.pem', 'owner': 'Web'}, **more)
        try:
            return 200, EN.ROUTES[('POST', '/api/certs/import')](FakeH(who, role, b))
        except E.ApiError as e:
            return e.status, str(e)

    def test_file_import(self):
        self.assertEqual(self.imp(['a.other.test'])[0], 403)          # not under its suffix
        self.assertEqual(self.imp(['*.example.test'])[0], 403)        # no wildcards
        self.assertEqual(self.imp(['a.example.test'])[0], 200)
        st, words = self.imp(['b.example.test'])                      # its quota: one
        self.assertEqual(st, 403)
        self.assertIn('the team Web does not allow it', words)
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM certs'), 1)
        # a full administrator: never limited, as before
        self.assertEqual(self.imp(['c.other.test'], who='boss', role='fulladmin')[0], 200)

    def test_source_import(self):
        def keep(names, ref, src='allowed-src', who='cweb', role='certadmin'):
            k = pki.make_key('ec-256')
            p = {'ref': ref, 'owner': 'Web', 'tags': [], 'challenge': '', 'auto_renew': 0,
                 'name': ''}
            s = {'name': who, 'role': role, 'account': {'name': who, 'role': role,
                                                        'source': 'local'}}
            try:
                OI._keep(STORE, {'name': src}, p, {'cert_pem': pki.self_signed(k, names)},
                         OI.known(STORE, src), who, s)
                return 'kept'
            except ValueError as e:
                return str(e)
        self.assertIn('does not allow it', keep(['a.other.test'], '1'))
        self.assertIn('does not allow it', keep(['a.example.test'], '2', src='other-src'))
        self.assertEqual(keep(['a.example.test'], '3'), 'kept')
        self.assertIn('does not allow it', keep(['b.example.test'], '4'))     # the quota
        self.assertEqual(keep(['c.other.test'], '5', who='boss', role='fulladmin'), 'kept')


class ElevationSeparation(unittest.TestCase):
    def setUp(self):
        clean()
        STORE.db.run('DELETE FROM cert_team_elevations')
        T.save_team(STORE, {'name': 'Web', 'members': [
            {'who': 'group:PKI Web', 'roles': ['Requester']},
            {'who': 'direct', 'roles': ['Requester']},
            {'who': 'mgr', 'roles': ['Team manager', 'Approver', 'Renewer']}]}, 'x')
        G.set_extras(STORE, 'Web', 'jit', {'roles': ['Approver', 'Renewer'], 'max_hours': 8},
                     'x')
        G.set_extras(STORE, 'Web', 'sod', {'exclusive': [['Requester', 'Approver']]}, 'x')

    def actor(self, name, groups=()):
        return {'by': name, 'who': name, 'ids': [name], 'names': {name},
                'groups': list(groups), 'caps': T.person_caps(STORE, {name}, list(groups)),
                'all': False}

    def test_group_member_refused_as_a_direct_one(self):
        eva = self.actor('eva', [(WEB, 'PKI Web')])
        for who in (eva, self.actor('direct')):
            with self.assertRaises(E.ApiError) as e:
                r = G.elevation_ask(STORE, who, 'Web', 'Approver', 2, 'need it now')
                G.elevation_decide(STORE, r['id'], self.actor('mgr'), True, 'ok')
            self.assertEqual(e.exception.status, 403)
            self.assertIn('separation of duties', str(e.exception))
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM cert_team_elevations WHERE "
                                        "state = 'granted'"), 0)
        # a role outside the rule: asked and given as before
        r = G.elevation_ask(STORE, eva, 'Web', 'Renewer', 2, 'renewals today')
        G.elevation_decide(STORE, r['id'], self.actor('mgr'), True, 'ok')
        self.assertEqual(STORE.db.value("SELECT state FROM cert_team_elevations WHERE id = ?",
                                        (r['id'],)), 'granted')


if __name__ == '__main__':
    unittest.main(verbosity=2)
