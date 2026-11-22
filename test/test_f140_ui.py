#!/usr/bin/env python3
"""1.0.140, package "ui": request profiles from a template (P7), the expiry calendar (G2) and the
global search of Ctrl+K (G5) - docs/request-profiles.md "From a template",
docs/expiry-calendar.md, docs/context-menu.md "The command palette".

    python3 test/test_f140_ui.py
    F140_SHOTS=/some/dir python3 test/test_f140_ui.py      # and screenshots there
    F140_CS=FILE[,FILE]  {English: Czech} merged into the copy's cs.json (before they are in it)

In one process (test/test_req_profiles.py's store and FakeH):
- P7: six templates, each fitted to the source chosen (key types it signs, a wildcard where it gives
  them, a CSR where it takes one, a validity only where it may be chosen) and to the company's
  rules (min RSA, no PFX, the longest validity, wildcards with approval); code signing only with
  an authority of acme's own; a profile made is a normal profile whose first version names the
  template; a name taken refused - the profile there unchanged; a certificate administrator
  refused (403), a reader sees the templates;
- G2: the window, the urgency, the planned renewal (its window, ARI sooner, none when renewed by
  hand), the filters (team and the teams below, source, target, only mine), a team member sees
  only their team's certificates (in the calendar, the file and the subscription), the iCalendar
  text (escaped, folded, a reminder), a link made / taken back / refused once the account is
  switched off, kept only as a hash, the full administrator's list; the portal's;
- G5: certificates by SAN and serial, deployments, targets (never by a secret's words), agents,
  teams, profiles, accounts (a full administrator only), events (those the Events page hides
  stay hidden), a scoped member never sees another team's objects, 100 characters at most,
  30 questions in 10 s;
- old data: certificates with no renew_days, ARI or owner, profiles from before - all as before.
With a real daemon (test/test_certs_core.py's): the command line (--find, --calendar,
--calendar-ics, --calendar-feeds, --calendar-feed-revoke, --profile-templates,
--profile-from-template), calendar.php with a link, and the pages (php -S, Chromium via
test/f140_ui_page.js) in English and Czech at 1400 and 390 px.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_req_profiles as TRP  # noqa: E402  (its store, FakeH, setup)
import test_certs_core as TCC  # noqa: E402  (the daemon, its helpers)

from acmelib import engine as E  # noqa: E402
from acmelib.certs import api_search as AS, expirycal as EC  # noqa: E402
from acmelib.certs import reqprofiles as R, reqprofiles_more as RM  # noqa: E402
from acmelib.certs import reqprofiles_templates as RT, teams as T  # noqa: E402

STORE = TRP.STORE
SHOTS = os.environ.get('F140_SHOTS', '')
CS_EXTRA = [x for x in os.environ.get('F140_CS', '').split(',') if x]
DAY = 86400


class H(TRP.FakeH):
    """FakeH with what the routes of 1.0.140 read too."""
    def num(self, name, default, lo=0, hi=10 ** 9):
        try:
            return max(lo, min(hi, int(float(self.args.get(name, default)))))
        except (TypeError, ValueError):
            return default

    @property
    def reader(self):
        return STORE


def call(method, path, body=None, **kw):
    return E.ROUTES[(method, path)](H(body=body, **kw))


def status(method, path, body=None, **kw):
    try:
        call(method, path, body, **kw)
        return 200
    except E.ApiError as e:
        return e.status
    except LookupError:
        return 404
    except ValueError:
        return 400


def setup():
    TRP.setup()
    STORE.db.run('DELETE FROM cert_req_profile_versions')
    STORE.db.run('DELETE FROM cert_targets')
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'certs:calfeed%'")
    STORE.set_meta(RM.META_RULES, '{}')
    E.CONFIG.update(certs_certadmin_all=1, certs_readonly_all=1)
    AS.RATE['seen'].clear()
    EC.FEED_CACHE['at'].clear()


def cert(name, days, owner='', issuer='own', names=None, **more):
    now = time.time()
    row = {'name': name, 'names': json.dumps(names or [name + '.example.test']), 'issuer': issuer,
           'state': 'ok', 'not_before': now - 30 * DAY, 'not_after': now + days * DAY,
           'auto_renew': 1, 'renew_days': 10, 'enabled': 1, 'owner': owner, 'created_by': 'boss',
           'serial': '0A1B2C3D%04d' % len(name)}
    row.update(more)
    STORE.db.insert('certs', row)
    return STORE.db.row('SELECT * FROM certs WHERE name = ?', (name,))['id']


# ---------------------------------------------------------------------------------------------
class Templates(unittest.TestCase):
    def setUp(self):
        setup()

    def test_catalog_fitted(self):
        got = call('GET', '/api/reqprofiles/templates', role='readonly')
        ids = [t['id'] for t in got['templates']]
        self.assertEqual(ids, ['web', 'mail', 'vpn', 'internal', 'wildcard', 'codesign'])
        self.assertFalse(got['can_change'])
        by = {t['id']: t for t in got['templates']}
        # code signing: only the authority of acme's own (self-signed does not put the EKU in)
        self.assertEqual([s['name'] for s in by['codesign']['sources'] if s['fits']], ['own'])
        bad = [s for s in by['codesign']['sources'] if s['name'] == 'self'][0]
        self.assertIn('extended key usage', bad['why'])
        for t in got['templates']:
            self.assertIn(t['status'], ('ok', 'warn', 'bad'))
            self.assertTrue(t['sets'])
        # no authority of acme's own: code signing is not offered
        STORE.db.run("UPDATE cert_issuers SET enabled = 0 WHERE name = 'own'")
        try:
            by = {t['id']: t for t in call('GET', '/api/reqprofiles/templates')['templates']}
            self.assertFalse(by['codesign']['available'])
            self.assertEqual(by['codesign']['status'], 'none')
            with self.assertRaises(ValueError):
                RT.build(STORE, 'codesign', suffixes=['example.test'])
        finally:
            STORE.db.run("UPDATE cert_issuers SET enabled = 1 WHERE name = 'own'")

    def test_preview_follows_source_and_rules(self):
        p = call('POST', '/api/reqprofiles/template_preview',
                 {'template': 'codesign', 'issuer': 'own', 'suffixes': 'example.test'}, role='readonly')
        b = p['body']
        self.assertEqual((b['eku'], b['make_key'], b['csr'], b['approval'], b['max_names'], b['pfx']),
                         (['codeSigning'], False, True, True, 1, False))
        self.assertEqual(b['days'], 365)                 # own CA: a validity it may choose
        # self-signed signs only a key acme holds: no CSR - acme makes the key, said
        w = RT.build(STORE, 'vpn', issuer='self', suffixes=['example.test'])
        self.assertFalse(w['body']['csr'])
        self.assertTrue(w['body']['make_key'])
        self.assertTrue(any('no CSR' in n for n in w['notes']))
        # the company's rules: RSA 3072 at least, no PFX, 90 days at most, wildcards approved
        RM.save_rules(STORE, {'min_rsa': 3072, 'no_pfx': True, 'max_days': 90,
                              'wildcards_approval': True}, 'x')
        m = RT.build(STORE, 'mail', issuer='own', suffixes=['example.test'])['body']
        self.assertNotIn('rsa-2048', m['key_types'])
        self.assertFalse(m['pfx'])
        self.assertEqual(m['days'], 90)
        self.assertEqual(RT.build(STORE, 'internal', issuer='own', suffixes=['example.test'])
                         ['status'], 'ok')
        self.assertEqual(status('POST', '/api/reqprofiles/template_preview',
                                {'template': 'web', 'issuer': 'nothing'}), 400)
        self.assertEqual(status('POST', '/api/reqprofiles/template_preview', {'template': 'nope'}),
                         404)

    def test_create_is_a_normal_profile(self):
        got = call('POST', '/api/reqprofiles/from_template',
                   {'template': 'wildcard', 'name': 'Balancers', 'suffixes': ['example.test'],
                    'issuer': 'own', 'description': 'Vyvažovače'})
        p = got['profile']
        self.assertEqual((p['wildcards'], p['approval'], p['issuer'], p['description']),
                         (True, True, 'own', 'Vyvažovače'))
        self.assertIn('Load balancer', got['message'])
        listed = [x['name'] for x in call('GET', '/api/reqprofiles')['profiles']]
        self.assertIn('Balancers', listed)
        v = call('GET', '/api/reqprofiles/versions', args={'name': 'Balancers'})
        self.assertIn('template', json.dumps(v['versions']))
        # edited as any other
        call('POST', '/api/reqprofiles/save', dict(R.config_of(R.profile_get(STORE, 'Balancers')),
                                                   name='Balancers', old_name='Balancers',
                                                   max_names=2))
        self.assertEqual(R.config_of(R.profile_get(STORE, 'Balancers'))['max_names'], 2)
        # a name taken: refused, the profile there as it was
        before = R.profile_get(STORE, 'Balancers')
        self.assertEqual(status('POST', '/api/reqprofiles/from_template',
                                {'template': 'web', 'name': 'balancers', 'suffixes': ['example.test']}),
                         400)
        self.assertEqual(R.profile_get(STORE, 'Balancers')['config'], before['config'])
        # the rights: a certificate administrator, a reader - refused; the domains needed
        for role in ('certadmin', 'readonly'):
            self.assertEqual(status('POST', '/api/reqprofiles/from_template',
                                    {'template': 'web', 'name': 'X', 'suffixes': ['example.test']},
                                    role=role), 403)
        self.assertEqual(status('POST', '/api/reqprofiles/from_template',
                                {'template': 'web', 'name': 'Y', 'suffixes': []}), 400)
        self.assertIsNone(R.profile_get(STORE, 'X'))

    def test_old_profiles_untouched(self):
        """A profile from before (no versions, no base): listed and changed as before; the
        templates change none of it."""
        STORE.db.insert('cert_req_profiles', {'name': 'Old', 'description': '', 'enabled': 1,
                                              'config': json.dumps(TRP.base_profile(
                                                  name='Old', teams=[], tags=[], owner='person')),
                                              'created': time.time(), 'updated': time.time()})
        cfg = R.profile_get(STORE, 'Old')['config']
        call('GET', '/api/reqprofiles/templates')
        call('POST', '/api/reqprofiles/from_template', {'template': 'web', 'name': 'New web',
                                                        'suffixes': ['example.test']})
        self.assertEqual(R.profile_get(STORE, 'Old')['config'], cfg)
        self.assertEqual(sorted(p['name'] for p in call('GET', '/api/reqprofiles')['profiles']),
                         ['New web', 'Old'])


# ---------------------------------------------------------------------------------------------
class Calendar(unittest.TestCase):
    def setUp(self):
        setup()
        T.save_team(STORE, {'name': 'Web EU', 'parent': 'Web', 'members': []}, 'x')
        self.a = cert('alpha', 5, owner='Web')
        self.b = cert('beta', 25, owner='Web EU')
        self.c = cert('gamma', 50, owner='')
        self.d = cert('delta', 200, owner='local:mgr', created_by='mgr')
        cert('revoked1', 10, state='revoked')
        cert('gone', -400)
        STORE.db.insert('cert_targets', {'name': 'web01', 'kind': 'fake', 'config': '{}', 'enabled': 1})
        STORE.db.insert('cert_deploys', {'cert_id': self.c, 'target': 'web01', 'enabled': 1})

    def names(self, got):
        return sorted(e['name'] for e in got['certs'])

    def test_window_urgency_renewal(self):
        got = call('GET', '/api/calendar', role='readonly')
        self.assertEqual(self.names(got), ['alpha', 'beta', 'delta', 'gamma'])
        u = {e['name']: e['urgency'] for e in got['certs']}
        self.assertEqual((u['alpha'], u['beta'], u['gamma'], u['delta']), ('crit', 'warn', 'info', 'ok'))
        a = [e for e in got['certs'] if e['name'] == 'alpha'][0]
        self.assertAlmostEqual(a['not_after'] - a['renew_at'], 10 * DAY, delta=2)
        # ARI sooner wins; renewed by hand: no planned renewal
        STORE.db.run('UPDATE certs SET ari = ? WHERE id = ?',
                     (json.dumps({'at': time.time() + DAY}), self.c))
        STORE.db.run('UPDATE certs SET auto_renew = 0 WHERE id = ?', (self.b,))
        got = {e['name']: e for e in call('GET', '/api/calendar')['certs']}
        self.assertLess(got['gamma']['renew_at'], time.time() + 2 * DAY)
        self.assertIsNone(got['beta']['renew_at'])
        # a window of 30 days: what runs out in it, and what is renewed in it
        to = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        got = call('GET', '/api/calendar', args={'from': datetime.date.today().isoformat(), 'to': to})
        self.assertEqual(self.names(got), ['alpha', 'beta', 'gamma'])
        self.assertTrue(got['weeks'] and got['counts'])
        for bad in ({'from': 'x'}, {'from': '2026-01-10', 'to': '2026-01-01'},
                    {'from': '2026-01-01', 'to': '2029-01-01'}):
            self.assertEqual(status('GET', '/api/calendar', args=bad), 400, bad)

    def test_filters_and_scope(self):
        self.assertEqual(self.names(call('GET', '/api/calendar', args={'team': 'Web'})),
                         ['alpha', 'beta'])                   # and the team below it
        self.assertEqual(self.names(call('GET', '/api/calendar', args={'team': 'Web EU'})), ['beta'])
        self.assertEqual(self.names(call('GET', '/api/calendar', args={'target': 'web01'})),
                         ['gamma'])
        self.assertEqual(self.names(call('GET', '/api/calendar', args={'issuer': 'self'})), [])
        self.assertEqual(self.names(call('GET', '/api/calendar', who='mgr', args={'mine': '1'})),
                         ['delta'])
        # a member kept to their team: Web's (they manage it) - and the teams below
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        got = call('GET', '/api/calendar', who='mgr', role='certadmin')
        self.assertEqual(self.names(got), ['alpha', 'beta'])
        self.assertEqual(got['options']['teams'], ['Web', 'Web EU'])
        self.assertEqual(got['options']['targets'], [])
        # asking for another team's gives nothing more
        self.assertEqual(self.names(call('GET', '/api/calendar', who='mgr', role='certadmin',
                                         args={'target': 'web01'})), [])
        ics = call('GET', '/api/calendar/ics', who='mgr', role='certadmin')['text']
        self.assertIn('alpha', ics)
        self.assertNotIn('gamma', ics)
        self.assertEqual(self.names(call('GET', '/api/calendar', who='nobody', role='readonly')), [])

    def test_ics(self):
        cert('semi;colon,comma', 12, names=['a.example.test', 'b.example.test'])
        text = call('GET', '/api/calendar/ics', args={'lang': 'en'})['text']
        self.assertTrue(text.startswith('BEGIN:VCALENDAR\r\n') and text.endswith('END:VCALENDAR\r\n'))
        self.assertIn('semi\\;colon\\,comma', text)
        self.assertEqual(text.count('BEGIN:VEVENT'), text.count('END:VEVENT'))
        self.assertIn('TRIGGER:-P7D', text)
        self.assertIn('CATEGORIES:RENEWAL', text)
        for ln in text.split('\r\n'):
            self.assertLessEqual(len(ln.encode('utf-8')), 75, ln)
        self.assertNotIn('revoked1', text)

    def test_feed(self):
        self.assertIsNone(EC.feed_of(STORE, 'mgr'))
        got = call('POST', '/api/calendar/feed_link', {'action': 'new', 'lang': 'cs'}, who='mgr',
                   role='certadmin')
        tok = got['token']
        self.assertTrue(got['path'].endswith(tok))
        # kept only as its hash
        self.assertNotIn(tok, json.dumps([dict(r) for r in STORE.db.rows('SELECT k, v FROM meta')]))
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        h = H(who='-')
        h.headers = {'X-Acme-Calfeed': tok}
        text = E.ROUTES[('GET', '/api/calendar/feed')](h)['text']
        self.assertIn('alpha', text)
        self.assertNotIn('gamma', text)                      # never more than mgr may see
        self.assertIn('Jména:', text)                        # in the language it was made in
        h.headers = {'X-Acme-Calfeed': 'x' * 40}
        with self.assertRaises(E.ApiError):
            E.ROUTES[('GET', '/api/calendar/feed')](h)
        # the full administrator's list; a reader may not
        self.assertEqual([f['who'] for f in call('GET', '/api/calendar/feeds')['feeds']], ['mgr'])
        self.assertEqual(status('GET', '/api/calendar/feeds', role='certadmin'), 403)
        # a new link: the old one no longer works
        tok2 = call('POST', '/api/calendar/feed_link', {'action': 'new'}, who='mgr',
                    role='certadmin')['token']
        self.assertIsNone(EC.feed_session(STORE, tok)[0])
        self.assertIsNotNone(EC.feed_session(STORE, tok2)[0])
        # the account switched off: nothing
        STORE.db.run("UPDATE accounts SET disabled = 1 WHERE name = 'mgr'")
        try:
            self.assertIsNone(EC.feed_session(STORE, tok2)[0])
        finally:
            STORE.db.run("UPDATE accounts SET disabled = 0 WHERE name = 'mgr'")
        call('POST', '/api/calendar/feeds_revoke', {'who': 'mgr'})
        self.assertIsNone(EC.feed_session(STORE, tok2)[0])
        self.assertEqual(status('POST', '/api/calendar/feeds_revoke', {'who': 'mgr'}), 404)
        self.assertEqual(status('POST', '/api/calendar/feed_link', {'action': 'x'}), 400)

    def test_portal(self):
        E.CONFIG.update(portal_cert_suffixes='example.test', portal_cert_issuers='own')
        eva = TRP.EVA
        cert('evas', 15, owner='eva')
        got = TRP.portal(eva, 'GET', '/api/portal/calendar')
        # exactly what the portal lists for her: hers, and her team's (Web through her group)
        listed = sorted(r['name'] for r in TRP.portal(eva, 'GET', '/api/portal/certs')['rows'])
        self.assertEqual(sorted(e['name'] for e in got['certs']), listed)
        self.assertIn('evas', listed)
        self.assertNotIn('gamma', listed)
        self.assertNotIn('delta', listed)
        self.assertEqual(sorted(r['name'] for r in got['rows']), listed)
        self.assertIn('evas', TRP.portal(eva, 'GET', '/api/portal/calendar_ics')['text'])

    def test_old_rows(self):
        """Certificates kept before: no renew_days, no ARI, no owner, no names - as before."""
        STORE.db.insert('certs', {'name': 'legacy', 'state': 'ok', 'not_after': time.time() + 9 * DAY,
                                  'issuer': 'own', 'auto_renew': 1})
        got = {e['name']: e for e in call('GET', '/api/calendar')['certs']}
        self.assertIn('legacy', got)
        self.assertEqual(got['legacy']['names'], [])
        self.assertIsNotNone(got['legacy']['renew_at'])


# ---------------------------------------------------------------------------------------------
class Search(unittest.TestCase):
    def setUp(self):
        setup()
        self.a = cert('shop', 30, owner='Web', names=['shop.example.test', 'pay.example.test'],
                      serial='5DD2A1B2C3')
        self.b = cert('intranet', 30, owner='', names=['wiki.corp.test'])
        STORE.db.insert('cert_targets', {'name': 'edge-lb', 'kind': 'fake', 'enabled': 1,
                                         'config': json.dumps({'host': 'lb1.example.test',
                                                               'password': 'S3cretWord'})})
        STORE.db.insert('cert_targets', {'name': 'srv-agent', 'kind': 'agent', 'enabled': 1,
                                         'config': '{}'})
        STORE.db.insert('cert_deploys', {'cert_id': self.b, 'target': 'edge-lb', 'enabled': 1})
        STORE.add_event('certificates', 'renewing intranet - done', who='x')
        STORE.add_event('accounts', 'mgr changed the password of marta', who='mgr')

    def kinds(self, q, **kw):
        got = call('GET', '/api/search', args={'q': q}, **kw)['groups']
        return {k: [r['name'] for r in v] for k, v in got.items()}

    def test_finds(self):
        self.assertEqual(self.kinds('pay.example')['cert'], ['shop'])           # by a SAN
        self.assertEqual(self.kinds('5D:D2:A1')['cert'], ['shop'])              # a serial with colons
        self.assertIn('intranet → edge-lb', self.kinds('edge')['deploy'])
        self.assertEqual(self.kinds('lb1.example')['target'], ['edge-lb'])     # its host
        self.assertNotIn('target', self.kinds('S3cretWord'))                     # never a secret
        self.assertEqual(self.kinds('srv')['agent'], ['srv-agent'])
        self.assertEqual(self.kinds('Web')['team'], ['Web'])
        self.assertIn('own', self.kinds('own').get('source', []))
        self.assertIn('marta', self.kinds('marta')['account'])
        self.assertNotIn('account', self.kinds('marta', role='certadmin'))      # a full admin's only
        self.assertTrue(self.kinds('renewing intranet')['event'])
        self.assertEqual(call('GET', '/api/search', args={'q': ''})['count'], 0)
        self.assertEqual(status('GET', '/api/search', args={'q': 'x' * 101}), 400)
        # kinds asked for, limits
        got = call('GET', '/api/search', args={'q': 'example', 'kinds': 'cert', 'limit': '1'})
        self.assertEqual(list(got['groups']), ['cert'])
        self.assertEqual(len(got['groups']['cert']), 1)

    def test_scope(self):
        E.CONFIG.update(certs_certadmin_all=0, certs_readonly_all=0)
        mine = self.kinds('example', who='mgr', role='certadmin')
        self.assertEqual(mine.get('cert'), ['shop'])
        self.assertNotIn('intranet', json.dumps(self.kinds('intranet', who='mgr', role='certadmin')))
        self.assertNotIn('deploy', self.kinds('edge', who='mgr', role='certadmin'))
        self.assertEqual(self.kinds('Approvers', who='mgr', role='certadmin').get('team'), None)
        # the events the Events page hides from them stay hidden
        self.assertNotIn('event', self.kinds('renewing intranet', who='mgr', role='certadmin'))
        self.assertNotIn('event', self.kinds('password of marta', who='mgr', role='certadmin'))

    def test_rate(self):
        for _ in range(AS.RATE_N):
            call('GET', '/api/search', args={'q': 'shop'}, who='quick')
        self.assertEqual(status('GET', '/api/search', args={'q': 'shop'}, who='quick'), 429)
        self.assertEqual(status('GET', '/api/search', args={'q': 'shop'}, who='other'), 200)


# ---------------------------------------------------------------------------------------------
def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Source(unittest.TestCase):
    def test_loaded_and_hooked(self):
        adm = read('web/admin/index.php')
        for f in ('calendar.css', 'calendar.js', 'rptemplates.css', 'rptemplates.js', 'search.css'):
            self.assertIn('/assets/%s' % f, adm, f)
        road = re.search(r"preg_match\('#\^\(([a-z|]+)\)", adm).group(1).split('|')
        self.assertIn('search', road)
        self.assertIn('calendar', road)
        portal = read('web/index.php')
        self.assertIn("'calendar' => '/api/portal/calendar'", portal)
        self.assertIn('calendar.js', portal)
        self.assertIn("'calendar.css'", portal)
        self.assertIn('location = /calendar.ics', read('deploy/nginx-acme.conf'))
        self.assertIn('location = /calendar.ics', read('install.sh'))
        for f in ('calendar.js', 'palette.js', 'rptemplates.js'):
            src = read('web/assets/' + f)
            for m in re.finditer(r'localStorage\.\w+\(', src):
                self.assertIn('try', src[max(0, m.start() - 200):m.start()], f)
        # no new table, nothing that changes the schema
        for f in ('expirycal.py', 'api_search.py', 'reqprofiles_templates.py'):
            src = read('acmelib/certs/' + f)
            self.assertNotIn('CREATE TABLE', src)
            self.assertNotIn('ALTER TABLE', src)


# ---------------------------------------------------------------------------------------------
class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    cli = TCC.CertsCore.__dict__['cli']
    cli_ok = TCC.CertsCore.__dict__['cli_ok']
    cli_json = TCC.CertsCore.__dict__['cli_json']
    py = TCC.CertsCore.__dict__['py']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def seed(self):
        if getattr(type(self), '_seeded', False):
            return
        type(self)._seeded = True
        self.ok('POST', '/api/cas/create', {'name': 'Test Root', 'subject': {'CN': 'Test Root CA'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Test Root', 'days': 90}})
        self.ok('POST', '/api/teams/save', {'name': 'Webteam', 'members': [
            {'who': 'local:certer', 'rights': ['view', 'manage']}]})
        self.ok('POST', '/api/targets/save', {'name': 'fake1', 'kind': 'fake',
                                              'config': {'dir': os.path.join(self.tmp, 'out')}})
        self.py('''
now = time.time()
D = 86400
rows = [('www', 3, 'Webteam', ['www.example.test', 'web.example.test']),
        ('mail', 12, 'Webteam', ['mail.example.test', 'smtp.example.test']),
        ('vpn', 26, '', ['vpn.example.test']), ('intranet', 45, '', ['intranet.corp.test']),
        ('shop', 70, 'Webteam', ['shop.example.test']), ('api', 120, '', ['api.example.test']),
        ('wiki', 160, '', ['wiki.corp.test']), ('build', 230, '', ['build.corp.test']),
        ('legacy', -5, '', ['old.example.test']), ('portal', 12, 'local:viewer', ['portal.example.test']),
        ('mx2', 26, 'Webteam', ['mx2.example.test'])]
for i in range(18):
    rows.append(('node%02d' % i, 30 + i * 17, '' if i % 3 else 'Webteam', ['node%02d.corp.test' % i]))
for n, d, o, names in rows:
    # issued already (a certificate kept), renewed a day before its end - the daemon leaves them
    st.db.insert('certs', {'name': n, 'names': json.dumps(names), 'issuer': 'own', 'state': 'ok',
                           'not_before': now - 60 * D, 'not_after': now + d * D,
                           'auto_renew': 0 if d < 2 else 1, 'cert_pem': 'kept',
                           'renew_days': 1, 'enabled': 1, 'owner': o, 'created_by': 'tester',
                           'serial': '5DD2%06X' % abs(hash(n) % 0xFFFFFF), 'key_type': 'ec-256'})
cid = st.db.row("SELECT id FROM certs WHERE name = 'intranet'")['id']
st.db.insert('cert_deploys', {'cert_id': cid, 'target': 'fake1', 'enabled': 1, 'state': 'ok'})
print(json.dumps(True))
''')

    def test_1_cli(self):
        self.seed()
        got = self.cli_json('--find', 'smtp.example')
        self.assertEqual([r['name'] for r in got['groups']['cert']], ['mail'])
        out = self.cli_ok('--find', 'intranet').stdout
        self.assertIn('deployment', out)
        self.assertIn('intranet → fake1', out)
        self.assertEqual(self.cli('--find', 'zzzz-nothing').returncode, 1)
        cal = self.cli_json('--calendar', '--weeks', '8')
        self.assertIn('www', [e['name'] for e in cal['certs']])
        self.assertEqual(len(cal['weeks']), 9 if datetime.date.today().weekday() else 8)
        txt = self.cli_ok('--calendar', '--team', 'Webteam').stdout
        self.assertIn('www', txt)
        self.assertNotIn('intranet', txt)
        txt = self.cli_ok('--calendar', '--target', 'fake1', '--weeks', '20').stdout
        self.assertIn('intranet', txt)
        self.assertNotIn(' www ', txt)
        path = os.path.join(self.tmp, 'cal.ics')
        self.cli_ok('--calendar-ics', path, '--lang', 'cs')
        with open(path, encoding='utf-8') as f:
            ics = f.read()
        self.assertIn('BEGIN:VCALENDAR', ics)
        self.assertIn('www', ics)
        # an option of the calendar beside another one: refused, nothing done
        bad = self.cli('--certs', '--team', 'Webteam')
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn('--team goes with --calendar', bad.stderr)
        t = self.cli_json('--profile-templates')
        self.assertEqual(len(t['templates']), 6)
        made = self.cli_json('--profile-from-template', 'internal', '--name', 'Internal CLI',
                             '--names', 'corp.test', '--issuer', 'own')
        self.assertEqual(made['profile']['issuer'], 'own')
        self.assertEqual(made['profile']['eku'], ['serverAuth', 'clientAuth'])
        again = self.cli('--profile-from-template', 'web', '--name', 'Internal CLI', '--names', 'corp.test')
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('already', again.stderr + again.stdout)
        # the links: made by the account on the pages, listed and taken back here
        tok = self.ok('POST', '/api/calendar/feed_link', {'action': 'new'}, session=self.cert_admin)['token']
        self.assertIn('certer', self.cli_ok('--calendar-feeds').stdout)
        self.assertNotIn(tok, self.cli_ok('--calendar-feeds', '--json').stdout)
        self.cli_ok('--calendar-feed-revoke', 'certer', '--yes')
        self.assertNotIn('certer', self.cli_ok('--calendar-feeds').stdout)

    def test_2_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True, cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        self.seed()
        self.ok('POST', '/api/settings', {'settings': {'portal': 1, 'portal_cert': 1, 'portal_local': 1}})
        web = os.path.join(self.tmp, 'web')
        shutil.rmtree(web, ignore_errors=True)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        if CS_EXTRA:
            TCC_merge_cs(os.path.join(web, 'lang', 'cs.json'), CS_EXTRA)
        port = TCC.free_port()
        self.assertNotIn(port, (8092, 8443, 5432, 5433))
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            # the subscription through calendar.php: a link, then nothing once taken back
            tok = self.ok('POST', '/api/calendar/feed_link', {'action': 'new'})['token']
            with urllib.request.urlopen('http://127.0.0.1:%d/calendar.php?t=%s' % (port, tok), timeout=20) as r:
                self.assertIn('text/calendar', r.headers.get('Content-Type'))
                self.assertIn('BEGIN:VCALENDAR', r.read().decode())
            self.ok('POST', '/api/calendar/feed_link', {'action': 'revoke'})
            with self.assertRaises(urllib.error.HTTPError) as no:
                urllib.request.urlopen('http://127.0.0.1:%d/calendar.php?t=%s' % (port, tok), timeout=20)
            self.assertEqual(no.exception.code, 404)
            drv = subprocess.run([node, os.path.join(HERE, 'f140_ui_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw],
                                 capture_output=True, text=True, cwd=ROOT, timeout=1500,
                                 env=dict(os.environ, F140_SHOTS=SHOTS))
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(drv.returncode, 0, drv.stderr[-3000:])
        seen = [json.loads(x) for x in drv.stdout.splitlines() if x.startswith('{')][-1]
        if SHOTS:
            with open(os.path.join(SHOTS, 'f140_ui_page.json'), 'w', encoding='utf-8') as f:
                json.dump(seen, f, ensure_ascii=False, indent=1)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 4)
        for one in seen['runs']:
            tag = '%s %s' % (one['lang'], one['w'])
            self.assertTrue(one['switch'], tag)
            self.assertGreaterEqual(one['monthDays'], 35, tag)
            self.assertGreaterEqual(one['tiles'], 4, tag)
            self.assertTrue(one['dayList'], tag)
            self.assertTrue(one['certOpened'], tag)
            self.assertEqual(one['yearSquares'], 53 * 7, tag)
            self.assertTrue(one['weekList'], tag)
            self.assertTrue(one['kbMoved'], tag)
            self.assertTrue(one['filterTeam'], tag)
            self.assertIn('BEGIN:VCALENDAR', one['ics'], tag)
            self.assertRegex(one['subLink'], r'/calendar\.ics\?t=[A-Za-z0-9_-]{30,}$', tag)
            self.assertTrue(one['header'], tag)
            self.assertIn('mail', one['paletteSan'], tag)
            self.assertTrue(one['paletteKinds'], tag)
            self.assertTrue(one['paletteOpened'], tag)
            self.assertEqual(one['tplCards'], 6, tag)
            self.assertTrue(one['tplPreview'], tag)
            self.assertTrue(one['tplMade'], tag)
            self.assertTrue(one['tplEditor'], tag)
            self.assertEqual(one['hscroll'], [], tag)
            if one['lang'] == 'cs' and CS_EXTRA:
                self.assertEqual(one['english'], [], tag)
        # the profiles the pages made from the template
        names = [p['name'] for p in self.ok('GET', '/api/reqprofiles')['profiles']]
        for one in seen['runs']:
            self.assertIn(one['tplName'], names)
        ro = seen['ro']
        self.assertFalse(ro['tplButton'])
        self.assertFalse(ro['accounts'])
        self.assertTrue(ro['calendar'])
        self.assertTrue(seen['portal']['calendar'])
        self.assertGreaterEqual(seen['portal']['items'], 1)


def TCC_merge_cs(path, extras):
    """{English: Czech} added to a copy of web/lang/cs.json - a pattern where it has {0}."""
    with open(path, encoding='utf-8') as f:
        pack = json.load(f)
    have = {v['source'] for sect in ('strings', 'patterns', 'rich') for v in pack.get(sect, {}).values()}
    i = 0
    for extra in extras:
        if not os.path.exists(extra):
            continue
        with open(extra, encoding='utf-8') as f:
            more = json.load(f)
        for en, cs in more.items():
            if en in have:
                continue
            i += 1
            sect = 'patterns' if re.search(r'\{\d\}', en) else 'strings'
            pack.setdefault(sect, {})['%s8%04d' % (sect[0], i)] = {'source': en, 'text': cs}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(pack, f, ensure_ascii=False, indent=1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
