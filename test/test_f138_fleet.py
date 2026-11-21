#!/usr/bin/env python3
"""Features 1.0.138, package "fleet" (docs/agent-fleet.md):

    python3 test/test_f138_fleet.py

* B3 - policy templates (built-in ones read as the agent reads a policy; an administrator's own:
  saved with versions, a line the agent would not read refused, deleted - its agents and groups
  then follow none), groups (made, changed, one canary ring, deleted), the template an agent
  follows (its own before its group's; by target id, name or agent id: agent_template), the
  drift (matches, differs - missing and extra lines -, not asked yet, another platform), the
  fleet's view (health, versions), the actions on many (ask now as a job), the update rings
  (the canary ring first, held when it is not healthy, the rest after the wait; stopped);
* B4 - the certificates discovery found that acme does not manage, by risk; the take-over's
  preview (nothing made), its refusal to issue while the policy does not allow it, the
  certificate and its deployment made with the same names and place;
* B5 - acme-agent for Kubernetes (deploy/agent/k8s/acme_k8s_agent.py) against a fake API server:
  its policy, the policy acme is told, a deployment refused whole when the policy lacks a line,
  Secrets made / replaced / left alone, a Deployment restarted, the Secrets put back when the
  restart fails, discovery of TLS Secrets; and the whole way: joined to acme's engine (the same
  join as acme-agent's), a certificate deployed by acme's agent target into a Secret;
* who may: a read-only account looks only, a certificate administrator asks and takes over but
  does not change templates, groups or update, a session limited to teams sees no fleet;
* an upgrade: no fleet rows (or broken ones) - everything as before;
* the policy builder's mergeState (node); the pages (Chromium: daemon + php -S) in English and
  Czech, 1400 and 390 px - test/f138_fleet_page.js.

Never port 8092 nor PostgreSQL: temporary folders and ports only.
"""
import base64
import http.server
import importlib.util
import io
import json
import os
import pwd
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
K8S = os.path.join(ROOT, 'deploy', 'agent', 'k8s', 'acme_k8s_agent.py')
TMP = tempfile.mkdtemp(prefix='acme-f138-fleet-')
os.chmod(TMP, 0o755)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, store as S, agents as G, fleet as FL  # noqa: E402
from acmelib.certs import agent_discover as AD, runtime, jobs  # noqa: E402
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry()
LX = G.agent_mod()
CS_EXTRA = os.environ.get('ACME_TEST_CS_EXTRA', '')
NOW = time.time()


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


class H(object):
    """A request as a route reads it: its session, its body, its arguments."""
    def __init__(self, role, body=None, args=None, extra=None):
        self.role, self.b, self.args, self.extra = role, body or {}, args or {}, extra or {}
        self.store = STORE
        self.headers = {}

    def me(self, level='readonly'):
        return dict({'role': self.role, 'name': 'f138-' + self.role}, **self.extra)

    def body(self):
        return self.b

    def arg(self, k, default=None):
        return self.args.get(k, default)


def route(method, path, role='fulladmin', body=None, args=None):
    return E.ROUTES[(method, path)](H(role, body, args))


def target(name, kind='agent', text=None, platform='linux', version='1.0.138', seen=True):
    rid = A.family_save(STORE, 'target', {'name': name, 'kind': kind, 'config': {
        'mode': 'passive', 'host': '%s.example.test' % name}, 'enabled': 1}, 'tester')
    row = S.plugin_row(STORE, 'target', rid)
    if text is not None:
        mod = G.agent_mod_for(platform)
        pol = G.clean_policy(mod.policy_report(mod.parse_policy(text), 'ab' * 32))
        aid = 'ag-%012x' % (0x100000 + rid)
        G.state_put(STORE, rid, {'agent_id': aid, 'cert_fp': 'cd' * 32,
                                 'last_seen': NOW if seen else NOW - 7200, 'policy': pol,
                                 'policy_at': NOW, 'platform': platform, 'version': version,
                                 'host': 'srv-%s' % name, 'cert_end': NOW + 20 * 86400,
                                 'joined_at': NOW - 3600})
        STORE.set_meta(G.M_ID(aid), str(rid))
    return row


NGINX = ('allow file /etc/nginx/ssl owner=root:root mode=0644\nallow unit nginx.service reload\n'
         'allow test -- nginx -t\nallow probe local\n')


def builtin(key):
    return [t for t in FL.builtins() if t['key'] == key][0]


# ---- B3: templates ---------------------------------------------------------------------------------
class Templates(unittest.TestCase):
    def test_builtins_read_as_the_agent_reads(self):
        keys = {t['key'] for t in FL.builtins()}
        for k in ('nginx-web', 'apache-rhel', 'apache-debian', 'haproxy', 'mail', 'iis', 'rdp'):
            self.assertIn(k, keys)
        for t in FL.builtins():
            m = FL._mod(t['platform'])
            got = m.policy_check(t['text'])
            self.assertEqual(got['errors'], [], t['key'])
            self.assertTrue(t['lines'], t['key'])
            self.assertEqual(FL._canon(t['platform'], t['text']), t['lines'])
        self.assertEqual(builtin('nginx-web')['lines'], [
            'allow file /etc/nginx/ssl owner=root:root mode=0644', 'allow unit nginx.service reload',
            'allow test -- nginx -t', 'allow probe local'])
        mail = '\n'.join(builtin('mail')['lines'])
        self.assertIn('/etc/postfix/ssl', mail)
        self.assertIn('/etc/dovecot/ssl', mail)
        self.assertIn('allow rdp', builtin('rdp')['lines'])
        self.assertIn('allow iis *', builtin('iis')['lines'])

    def test_own_saved_versions_deleted(self):
        text = LX.POLICY_HEAD + 'allow file /srv/app/tls owner=root:app mode=0640\n'
        t = FL.template_save(STORE, {'title': 'App servers', 'platform': 'linux', 'text': text,
                                     'design_state': {'files': [{'dir': '/srv/app/tls',
                                                                 'owner': 'root', 'group': 'app',
                                                                 'mode': 0o640}]}}, 'tester')
        self.assertFalse(t['builtin'])
        self.assertEqual((t['n'], t['lines']), (1, ['allow file /srv/app/tls owner=root:app '
                                                    'mode=0640']))
        # the same title: a new version of it
        t2 = FL.template_save(STORE, {'title': 'app servers', 'platform': 'linux',
                                      'text': text + 'allow probe local\n'}, 'tester')
        self.assertEqual((t2['ref'], t2['n']), (t['ref'], 2))
        # saved without the builder's state: the state made from its lines
        self.assertEqual([f['dir'] for f in t2['state']['files']], ['/srv/app/tls'])
        self.assertTrue(t2['state']['probe_local'])
        self.assertEqual(len([x for x in FL.templates(STORE) if x['ref'] == t['ref']]), 1)
        # a line the agent would not read: refused, nothing kept
        with self.assertRaises(ValueError):
            FL.template_save(STORE, {'title': 'Bad', 'platform': 'linux',
                                     'text': 'allow file /srv/x mod=0600\n'}, 'tester')
        with self.assertRaises(ValueError):
            FL.template_save(STORE, {'title': '', 'platform': 'linux', 'text': text}, 'tester')
        with self.assertRaises(ValueError):
            FL.template_save(STORE, {'title': 'x', 'platform': 'linux', 'text': text,
                                     'design_state': {'files': 'no'}}, 'tester')
        self.assertFalse([x for x in FL.templates(STORE) if x['title'] == 'Bad'])
        # a built-in one is never changed nor deleted
        with self.assertRaises(ValueError):
            FL.template_delete(STORE, 'builtin:nginx-web', 'tester')
        row = target('tplagent', text=NGINX)
        FL.assign(STORE, [row['id']], t['ref'], 'tester')
        g = FL.group_save(STORE, {'name': 'Apps', 'members': [row['id']], 'template': t['ref']},
                          'tester')
        self.assertEqual(FL.agent_template(STORE, row['id'])['ref'], t['ref'])
        FL.template_delete(STORE, t['ref'], 'tester')
        self.assertIsNone(FL.agent_template(STORE, row['id']))
        self.assertEqual(FL.group_get(STORE, g['id'])['template'], '')
        self.assertIsNone(FL.template_get(STORE, t['ref']))
        FL.group_delete(STORE, g['id'], 'tester')


# ---- B3: groups, which template, the drift -----------------------------------------------------
class GroupsAndDrift(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = target('gd-web1', text=NGINX)
        cls.b = target('gd-web2', text=NGINX.replace('allow probe local\n', '') +
                       'allow discover\n')
        cls.c = target('gd-new')                              # no agent joined
        cls.w = target('gd-win', kind='agent_windows', text='allow store\nallow rdp\n',
                       platform='windows')

    def test_group_rules(self):
        g = FL.group_save(STORE, {'name': 'Web', 'color': 'teal', 'members': [self.a['id'],
                                                                               self.b['id']],
                                  'template': 'builtin:nginx-web', 'canary': True}, 'tester')
        self.assertEqual((g['color'], g['canary'], g['members']),
                         ('teal', True, [self.a['id'], self.b['id']]))
        with self.assertRaises(ValueError):
            FL.group_save(STORE, {'name': 'web'}, 'tester')               # the name taken
        with self.assertRaises(ValueError):
            FL.group_save(STORE, {'name': 'X', 'members': [999999]}, 'tester')
        with self.assertRaises(ValueError):
            FL.group_save(STORE, {'name': 'X', 'template': 'builtin:nope'}, 'tester')
        with self.assertRaises(ValueError):
            FL.group_save(STORE, {'name': 'X', 'members': ['a']}, 'tester')
        g2 = FL.group_save(STORE, {'name': 'Canary 2', 'canary': True, 'color': 'nope'}, 'tester')
        self.assertEqual(g2['color'], 'blue')
        self.assertFalse(FL.group_get(STORE, g['id'])['canary'])       # one canary ring
        FL.group_delete(STORE, g2['id'], 'tester')
        with self.assertRaises(LookupError):
            FL.group_delete(STORE, g2['id'], 'tester')
        # which template, and its drift
        t = FL.agent_template(STORE, self.a['id'])
        self.assertEqual((t['ref'], t['via'], t['group']), ('builtin:nginx-web', 'group', 'Web'))
        aid = G.state(STORE, self.a['id'])['agent_id']
        self.assertEqual(FL.agent_template(STORE, aid)['ref'], 'builtin:nginx-web')
        self.assertEqual(FL.agent_template(STORE, 'gd-web1')['ref'], 'builtin:nginx-web')
        self.assertEqual(FL.agent_template(STORE, str(self.a['id']))['ref'], 'builtin:nginx-web')
        self.assertIsNone(FL.agent_template(STORE, 'ag-000000000000'))
        self.assertIsNone(FL.agent_template(STORE, self.c['id']))
        d = FL.drift(STORE, self.a)
        self.assertEqual((d['state'], d['missing'], d['extra']), ('matches', [], []))
        d = FL.drift(STORE, self.b)
        self.assertEqual(d['state'], 'differs')
        self.assertEqual(d['missing'], ['allow probe local'])
        self.assertEqual(d['extra'], ['allow discover'])
        # the agent's own before its group's
        FL.assign(STORE, [self.b['id']], 'builtin:haproxy', 'tester')
        t = FL.agent_template(STORE, self.b['id'])
        self.assertEqual((t['ref'], t['via']), ('builtin:haproxy', 'agent'))
        FL.assign(STORE, [self.b['id']], '', 'tester')
        self.assertEqual(FL.agent_template(STORE, self.b['id'])['via'], 'group')
        with self.assertRaises(ValueError):
            FL.assign(STORE, [self.b['id']], 'builtin:nope', 'tester')
        # another platform; not asked yet
        FL.assign(STORE, [self.w['id']], 'builtin:nginx-web', 'tester')
        self.assertEqual(FL.drift(STORE, self.w)['state'], 'other')
        FL.assign(STORE, [self.w['id']], 'builtin:rdp', 'tester')
        self.assertEqual(FL.drift(STORE, self.w)['state'], 'matches')
        FL.assign(STORE, [self.c['id']], 'builtin:nginx-web', 'tester')
        self.assertEqual(FL.drift(STORE, self.c)['state'], 'unknown')
        # the view
        v = FL.view(STORE)
        by = {a['name']: a for a in v['agents']}
        self.assertEqual(by['gd-web1']['health'], 'ok')
        self.assertEqual(by['gd-web2']['health'], 'warn')
        self.assertIn('drifted from its template', by['gd-web2']['why'])
        self.assertEqual(by['gd-new']['health'], 'idle')
        self.assertEqual(by['gd-win']['kind'], 'windows')
        gv = [x for x in v['groups'] if x['name'] == 'Web'][0]
        self.assertEqual((gv['health']['ok'], gv['health']['warn'], gv['drifted']), (1, 1, 1))
        self.assertTrue(any(x['version'] == '1.0.138' for x in v['versions']))
        self.assertTrue(any(t['ref'] == 'builtin:nginx-web' and t['used'] >= 2
                            for t in v['templates']))
        self.assertNotIn('text', v['templates'][0])
        rows = FL.drift_many(STORE, [self.a['id'], self.b['id'], 424242])
        self.assertEqual([r['name'] for r in rows], ['gd-web1', 'gd-web2'])
        FL.group_delete(STORE, g['id'], 'tester')
        for r in (self.c, self.w):
            FL.assign(STORE, [r['id']], '', 'tester')

    def test_ask_now_is_a_job(self):
        asked = []
        keep = G.look

        def look(store, row, by=''):
            asked.append(row['name'])
            return {'state': 'answers', 'version': '1.0.138'}
        G.look = look
        try:
            got = FL.act(STORE, 'ask', [self.a['id'], self.b['id']], 'tester')
            end = time.time() + 30
            while time.time() < end:
                j = jobs.job_view(STORE, got['job_id'])
                if not j['live']:
                    break
                time.sleep(0.1)
        finally:
            G.look = keep
        self.assertEqual(sorted(asked), ['gd-web1', 'gd-web2'])
        self.assertTrue(j['ok'], j)
        self.assertIn('2 of 2 agent(s) answered', j['said'])
        with self.assertRaises(ValueError):
            FL.act(STORE, 'reboot', [self.a['id']], 'tester')
        with self.assertRaises(ValueError):
            FL.act(STORE, 'ask', [], 'tester')


# ---- B3: update rings ------------------------------------------------------------------------------
class Rings(unittest.TestCase):
    def setUp(self):
        self.rows = [target('ring%d' % i, text=NGINX + 'allow self-update\n', version='1.0.130')
                     for i in range(4)]
        self.updated = []
        self.keep = (G.update_candidates, G.update_agent, G.package)
        ids = [r['id'] for r in self.rows]

        def cand(store):
            out = []
            for r in self.rows:
                st = G.state(store, r['id'])
                if st.get('version') == '1.0.138':
                    continue
                out.append({'id': r['id'], 'name': r['name'], 'mode': 'passive',
                            'platform': 'linux', 'version': st.get('version'),
                            'offered': '1.0.138', 'ok': r['id'] != ids[3],
                            'why': '' if r['id'] != ids[3] else 'its policy has no allow '
                                                                'self-update'})
            return out

        def upd(store, row, by):
            self.updated.append(row['name'])
            if row['name'] == getattr(self, 'fail', ''):
                raise base.PluginError('the agent refused the update', retry=False)
            st = G.state(store, row['id'])
            st['version'] = '1.0.138'
            st['last_seen'] = time.time()
            G.state_put(store, row['id'], st)
            return {'ok': True}
        G.update_candidates, G.update_agent = cand, upd
        G.package = lambda build=True: {'version': '1.0.138', 'signed': True}
        STORE.db.run("DELETE FROM meta WHERE k = 'fleet:rollout'")
        self.g = FL.group_save(STORE, {'name': 'Ring canary %s' % self.id()[-8:], 'canary': True,
                                       'members': [self.rows[0]['id']]}, 'tester')

    def tearDown(self):
        G.update_candidates, G.update_agent, G.package = self.keep
        FL.group_delete(STORE, self.g['id'], 'tester')
        STORE.db.run("DELETE FROM meta WHERE k = 'fleet:rollout'")
        for r in self.rows:
            STORE.db.run('DELETE FROM cert_targets WHERE id = ?', (r['id'],))
            STORE.db.run('DELETE FROM meta WHERE k = ?', (G.M_T(r['id']),))

    def wait(self, phase):
        end = time.time() + 30
        while time.time() < end:
            r = FL.rollout_view(STORE)
            if r and r['phase'] == phase:
                return r
            time.sleep(0.1)
        self.fail('the rollout did not reach %s: %s' % (phase, FL.rollout_view(STORE)))

    def test_canary_then_rest(self):
        plan = FL.rollout_plan(STORE, self.g['id'])
        self.assertEqual([x['name'] for x in plan['canary']], ['ring0'])
        self.assertEqual([x['name'] for x in plan['rest']], ['ring1', 'ring2'])
        self.assertEqual([x['name'] for x in plan['skipped']], ['ring3'])
        r = FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 0}, 'tester')
        self.assertEqual(r['version'], '1.0.138')
        r = self.wait('waiting')
        self.assertEqual(self.updated, ['ring0'])
        with self.assertRaises(ValueError):
            FL.rollout_start(STORE, {'canary': self.g['id']}, 'tester')   # one at a time
        FL.tick(STORE)
        r = self.wait('done')
        self.assertEqual(sorted(self.updated), ['ring0', 'ring1', 'ring2'])
        self.assertTrue(all(v['ok'] for v in r['results'].values()))
        self.assertIsNone(FL.rollout_step(STORE, 'forget', 'tester'))

    def test_held_when_the_canary_is_not_healthy(self):
        self.fail = 'ring0'
        FL.rollout_start(STORE, {'canary': self.g['id'], 'wait': 0}, 'tester')
        self.wait('waiting')
        FL.tick(STORE)
        r = FL.rollout_view(STORE)
        self.assertEqual(r['phase'], 'held')
        self.assertIn('ring0', r['held'])
        self.assertEqual(self.updated, ['ring0'])         # the rest not touched
        FL.rollout_step(STORE, 'stop', 'tester')
        self.assertEqual(FL.rollout_view(STORE)['phase'], 'stopped')
        with self.assertRaises(ValueError):
            FL.rollout_step(STORE, 'continue', 'tester')

    def test_wait_and_share(self):
        FL.group_save(STORE, {'id': self.g['id'], 'canary': False}, 'tester')
        plan = FL.rollout_plan(STORE, '')
        self.assertEqual(len(plan['canary']), 1)               # 5 %, at least one
        FL.rollout_start(STORE, {'wait': 30}, 'tester')
        r = self.wait('waiting')
        self.assertGreater(r['next_at'], time.time() + 25 * 60)
        FL.tick(STORE)
        self.assertEqual(FL.rollout_view(STORE)['phase'], 'waiting')      # not yet
        FL.rollout_step(STORE, 'continue', 'tester')                      # go on now
        self.wait('done')
        with self.assertRaises(ValueError):
            FL.rollout_start(STORE, {'wait': 99999}, 'tester')


# ---- B4: not managed, the take-over ---------------------------------------------------------------
def discovery(row, thumb, days, more=None):
    found = [{'kind': 'nginx', 'title': 'nginx', 'preset': 'nginx', 'config': '/etc/nginx/conf.d/'
              'api.conf', 'unit': 'nginx.service', 'names': ['api.example.test'],
              'listen': ['8443 ssl'], 'port': 0, 'test': 'nginx -t',
              'reload': 'systemctl reload nginx',
              'cert': {'thumbprint': thumb, 'subject': 'CN=api.example.test',
                       'issuer': 'CN=Old CA', 'cn': 'api.example.test', 'serial': '01',
                       'not_after': NOW + days * 86400, 'sans': ['api.example.test',
                                                                  'www.api.example.test']},
              'files': [{'role': 'cert', 'format': 'fullchain-pem', 'there': True,
                         'path': '/etc/nginx/ssl/api.crt', 'mode': '0644', 'owner': 'root',
                         'group': 'root'},
                        {'role': 'key', 'format': 'key-pem', 'there': True,
                         'path': '/etc/nginx/ssl/api.key', 'mode': '0600', 'owner': 'root',
                         'group': 'root'}]}]
    certs = [dict(found[0]['cert']),
             {'thumbprint': 'AB' * 20, 'subject': 'CN=old.example.test',
              'issuer': 'CN=old.example.test', 'cn': 'old.example.test', 'serial': '02',
              'not_after': NOW - 86400, 'sans': ['old.example.test'],
              'where': ['/etc/ssl/old.pem']}]
    d = {'platform': 'linux', 'kinds': ['nginx', 'files'], 'at': NOW, 'found': found,
         'certs': certs, 'skipped': []}
    d.update(more or {})
    AD._keep(STORE, row, AD.clean(d), 'tester')


class TakeOver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        route('POST', '/api/cas/create', body={'name': 'F138 Root', 'subject': {
            'CN': 'F138 Root CA'}, 'key_type': 'ec-256', 'days': 3650})
        A.family_save(STORE, 'issuer', {'name': 'f138own', 'kind': 'internal_ca',
                                        'config': {'ca': 'F138 Root', 'days': 90}}, 'tester')
        cls.ok = target('to-web', text=NGINX)
        cls.no = target('to-bare', text='allow discover\n')
        discovery(cls.ok, 'CD' * 20, 5)
        discovery(cls.no, 'EF' * 20, 45)

    def test_list_by_risk(self):
        rows = [r for r in FL.unmanaged(STORE) if r['target'] in ('to-web', 'to-bare')]
        self.assertEqual([r['risk'] for r in rows][:2], ['expired', 'expired'])
        self.assertEqual([(r['target'], r['risk']) for r in rows if r['service']],
                         [('to-web', 'critical'), ('to-bare', 'medium')])
        web = [r for r in rows if r['target'] == 'to-web' and r['service']][0]
        self.assertEqual(web['names'], ['api.example.test', 'www.api.example.test'])
        self.assertTrue(web['can_take'])
        self.assertEqual(web['kind'], 'nginx')
        loose = [r for r in rows if not r['service']][0]
        self.assertFalse(loose['can_take'])
        self.assertGreaterEqual(FL.unmanaged_count(STORE), 4)

    def test_preview_makes_nothing(self):
        before = STORE.db.value('SELECT COUNT(*) FROM certs', (), 0)
        p = FL.takeover_preview(STORE, {'target': 'to-web', 'service': 'nginx-0',
                                        'issuer': 'f138own'})
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM certs', (), 0), before)
        self.assertTrue(p['allowed'])
        self.assertEqual(p['block'], '')
        self.assertEqual(p['cert']['names'], ['api.example.test', 'www.api.example.test'])
        self.assertEqual(p['deploy']['options']['outputs'], [
            'fullchain-pem /etc/nginx/ssl/api.crt 0644 root:root',
            'key-pem /etc/nginx/ssl/api.key 0600 root:root'])
        self.assertTrue(all(i['ok'] for i in p['items']))
        self.assertEqual(p['steps'][-1][0], 'ok')
        q = FL.takeover_preview(STORE, {'target': 'to-bare', 'service': 'nginx-0',
                                        'issuer': 'f138own'})
        self.assertFalse(q['allowed'])
        self.assertIn('sudo acme-agent allow file /etc/nginx/ssl --owner root:root --mode 0644',
                      q['block'])
        self.assertIn('sudo acme-agent allow test -- nginx -t', q['block'])
        self.assertEqual(q['steps'][-1][0], 'wait')
        with self.assertRaises(LookupError):
            FL.takeover_preview(STORE, {'target': 'to-web', 'service': 'nginx-9'})
        with self.assertRaises(ValueError):
            FL.takeover_preview(STORE, {'target': 'to-web', 'service': 'nginx-0',
                                        'issuer': 'nope'})

    def test_take_over(self):
        with self.assertRaises(ValueError):            # not confirmed
            FL.takeover(STORE, {'target': 'to-bare', 'service': 'nginx-0', 'issuer': 'f138own'},
                        'tester', True)
        with self.assertRaises(ValueError):            # the policy does not allow it: not issued
            FL.takeover(STORE, {'target': 'to-bare', 'service': 'nginx-0', 'issuer': 'f138own',
                                'confirm': True, 'issue_now': True}, 'tester', True)
        self.assertFalse(STORE.db.value("SELECT COUNT(*) FROM certs WHERE names LIKE "
                                        "'%api.example.test%'", (), 0))
        started = []
        keep = A.start_renew
        A.start_renew = lambda store, ref, force, by: started.append(ref) or 4711
        try:
            got = FL.takeover(STORE, {'target': 'to-web', 'service': 'nginx-0',
                                      'issuer': 'f138own', 'confirm': True, 'issue_now': True,
                                      'name': 'api'}, 'tester', True)
        finally:
            A.start_renew = keep
        self.assertEqual((got['name'], got['job_id']), ('api', 4711))
        self.assertEqual(started, [got['cert_id']])
        c = S.cert_get(STORE, got['cert_id'])
        self.assertEqual(json.loads(c['names']), ['api.example.test', 'www.api.example.test'])
        self.assertEqual((c['issuer'], c['auto_renew']), ('f138own', 1))
        d = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (got['deploy_id'],))
        self.assertEqual(d['target'], 'to-web')
        self.assertIn('/etc/nginx/ssl/api.crt', d['options'])
        # a second time: the name is taken
        with self.assertRaises(ValueError):
            FL.takeover(STORE, {'target': 'to-web', 'service': 'nginx-0', 'issuer': 'f138own',
                                'confirm': True, 'name': 'api'}, 'tester', True)


# ---- who may ----------------------------------------------------------------------------------------
class WhoMay(unittest.TestCase):
    def test_roles(self):
        row = target('who-web', text=NGINX)
        self.assertIn('agents', route('GET', '/api/fleet', 'readonly'))
        self.assertTrue(route('GET', '/api/fleet/templates', 'readonly', args={
            'platform': 'windows'})['templates'])
        for path, body in (('/api/fleet/template_save', {'title': 'x', 'text': 'allow probe '
                                                         'local\n'}),
                           ('/api/fleet/group_save', {'name': 'x'}),
                           ('/api/fleet/assign', {'ids': [row['id']], 'template': ''}),
                           ('/api/fleet/rollout', {}), ('/api/fleet/rollout_step', {'do': 'stop'}),
                           ('/api/fleet/act', {'action': 'ask', 'ids': [row['id']]}),
                           ('/api/fleet/takeover', {}), ('/api/fleet/takeover_preview', {})):
            with self.assertRaises(E.ApiError) as e:
                route('POST', path, 'readonly', body)
            self.assertEqual(e.exception.status, 403, path)
        for path, body in (('/api/fleet/template_save', {'title': 'x', 'text': 'allow probe '
                                                         'local\n'}),
                           ('/api/fleet/group_save', {'name': 'x'}),
                           ('/api/fleet/act', {'action': 'update', 'ids': [row['id']]}),
                           ('/api/fleet/rollout', {})):
            with self.assertRaises(E.ApiError) as e:
                route('POST', path, 'certadmin', body)
            self.assertEqual(e.exception.status, 403, path)
        # a certificate administrator asks now and looks at a take-over
        keep = G.look
        G.look = lambda store, row, by='': {'state': 'answers'}
        try:
            self.assertTrue(route('POST', '/api/fleet/act', 'certadmin', {
                'action': 'ask', 'ids': [row['id']]})['job_id'])
        finally:
            time.sleep(0.5)
            G.look = keep
        # limited to teams: no fleet
        E.CONFIG['certs_certadmin_all'] = 0
        try:
            for m, p in (('GET', '/api/fleet'), ('GET', '/api/fleet/unmanaged'),
                         ('POST', '/api/fleet/takeover_preview'), ('POST', '/api/fleet/act')):
                with self.assertRaises(E.ApiError) as e:
                    route(m, p, 'certadmin', {'action': 'ask', 'ids': [row['id']]})
                self.assertEqual(e.exception.status, 403, p)
        finally:
            E.CONFIG['certs_certadmin_all'] = 1


# ---- an upgrade: nothing of the fleet, or broken rows ---------------------------------------------
class Upgrade(unittest.TestCase):
    def test_old_data(self):
        row = target('up-web', text=NGINX)
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'fleet:%'")
        self.assertIsNone(FL.agent_template(STORE, row['id']))
        self.assertIsNone(FL.drift(STORE, row))
        FL.tick(STORE)                                  # nothing under way: nothing
        self.assertIsNone(FL.rollout_view(STORE))
        v = FL.view(STORE)
        self.assertEqual(v['groups'], [])
        self.assertTrue(all(not t['used'] for t in v['templates']))
        # rows of another shape (a hand, a bug) are left out - never an error
        STORE.set_meta('fleet:group:g0000000000', 'not json')
        STORE.set_meta('fleet:tpl:t0000000000', '{"versions": "no"}')
        STORE.set_meta('fleet:assign:%d' % row['id'], '[]')
        STORE.set_meta('fleet:rollout', '"x"')
        self.assertIsNone(FL.agent_template(STORE, row['id']))
        FL.view(STORE)
        FL.tick(STORE)
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'fleet:%'")
        # an agent's own state and design untouched by the fleet
        self.assertEqual(G.state(STORE, row['id'])['version'], '1.0.138')


# ---- the policy builder: mergeState (node) ---------------------------------------------------------
class BuilderCore(unittest.TestCase):
    def test_merge(self):
        if not shutil.which('node'):
            self.skipTest('no node')
        facts = LX.policy_facts()
        t = builtin('mail')
        js = ('const C = require(%r); C.setFacts(%s); const s = C.empty();'
              'C.mergeState(s, %s); C.mergeState(s, %s); const once = C.check(s).lines;'
              'C.mergeState(s, %s); process.stdout.write(JSON.stringify({a: once, b: '
              'C.check(s).lines}));') % (
            os.path.join(ROOT, 'web', 'assets', 'policybuilder.js'), json.dumps(facts),
            json.dumps(builtin('nginx-web')['state']), json.dumps(t['state']),
            json.dumps(t['state']))
        got = json.loads(subprocess.run(['node', '-e', js], capture_output=True, check=True,
                                        text=True).stdout)
        want = sorted(set(builtin('nginx-web')['lines']) | set(t['lines']))
        self.assertEqual(sorted(got['a']), want)
        self.assertEqual(got['a'], got['b'])              # twice: nothing more


# ---- B5: acme-agent for Kubernetes ------------------------------------------------------------------
class FakeKube(object):
    """An API server of Kubernetes as far as the agent asks it: Secrets and Deployments of the
    namespaces its RBAC lets it in (others: 403), its token checked."""
    TOKEN = 'k8s-test-token-%d' % os.getpid()

    def __init__(self, namespaces=('shop', 'intranet')):
        self.ns = set(namespaces)
        self.secrets, self.deploys, self.calls = {}, {}, []
        self.fail_patch = False
        me = self

        class Hd(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _do(self, method):
                n = int(self.headers.get('Content-Length') or 0)
                body = json.loads(self.rfile.read(n) or b'null') if n else None
                me.calls.append((method, self.path, self.headers.get('Content-Type')))
                if self.headers.get('Authorization') != 'Bearer ' + FakeKube.TOKEN:
                    return self._send(401, {'message': 'Unauthorized'})
                if self.path == '/version':
                    return self._send(200, {'gitVersion': 'v1.31.2'})
                m = re.match(r'/api/v1/namespaces/([^/]+)/secrets(?:/([^/?]+))?(\?.*)?$',
                             self.path)
                d = re.match(r'/apis/apps/v1/namespaces/([^/]+)/deployments/([^/?]+)$',
                             self.path)
                ns = (m or d).group(1) if (m or d) else ''
                if ns not in me.ns:
                    return self._send(403, {'message': 'forbidden: namespace %s' % ns})
                if d:
                    if method != 'PATCH':
                        return self._send(405, {})
                    if me.fail_patch:
                        return self._send(500, {'message': 'the deployment controller is down'})
                    if (ns, d.group(2)) not in me.deploys:
                        return self._send(404, {'message': 'not found'})
                    me.deploys[(ns, d.group(2))].append(body)
                    return self._send(200, {'kind': 'Deployment'})
                if not m:
                    return self._send(404, {'message': 'no such path'})
                name = m.group(2)
                if method == 'GET' and not name:
                    items = [s for (n2, _x), s in me.secrets.items() if n2 == ns and
                             s.get('type') == 'kubernetes.io/tls']
                    return self._send(200, {'items': items})
                if method == 'GET':
                    s = me.secrets.get((ns, name))
                    return self._send(200, s) if s else self._send(404, {'message': 'nf'})
                if method == 'POST':
                    k = (ns, body['metadata']['name'])
                    if k in me.secrets:
                        return self._send(409, {'message': 'exists'})
                    body['metadata']['resourceVersion'] = '1'
                    me.secrets[k] = body
                    return self._send(201, body)
                if method == 'PUT':
                    old = me.secrets.get((ns, name))
                    if not old:
                        return self._send(404, {'message': 'nf'})
                    rv = (body.get('metadata') or {}).get('resourceVersion')
                    if rv and rv != old['metadata'].get('resourceVersion'):
                        return self._send(409, {'message': 'conflict'})
                    body['metadata']['resourceVersion'] = str(
                        int(old['metadata'].get('resourceVersion') or 1) + 1)
                    me.secrets[(ns, name)] = body
                    return self._send(200, body)
                if method == 'DELETE':
                    me.secrets.pop((ns, name), None)
                    return self._send(200, {})
                return self._send(405, {})

            def do_GET(self):
                self._do('GET')

            def do_POST(self):
                self._do('POST')

            def do_PUT(self):
                self._do('PUT')

            def do_PATCH(self):
                self._do('PATCH')

            def do_DELETE(self):
                self._do('DELETE')
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Hd)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.token_file = os.path.join(TMP, 'k8s-token-%d' % self.port)
        with open(self.token_file, 'w') as fh:
            fh.write(FakeKube.TOKEN + '\n')
        os.chmod(self.token_file, 0o644)

    def env(self):
        return {'ACME_K8S_API': 'http://127.0.0.1:%d' % self.port,
                'ACME_K8S_TOKEN_FILE': self.token_file}

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


def certs_pair(cn, days=30):
    d = tempfile.mkdtemp(dir=TMP)
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', d + '/k.pem', '-out', d + '/c.pem', '-days', str(days), '-subj',
            '/CN=%s' % cn, '-addext', 'subjectAltName=DNS:%s' % cn)
    with open(d + '/c.pem') as a, open(d + '/k.pem') as b:
        return a.read(), b.read()


def k8s_mod(tag, policy, kube):
    d = os.path.join(TMP, 'k8s-' + tag)
    os.makedirs(d, exist_ok=True)
    pol = os.path.join(d, 'policy')
    with open(pol, 'w') as fh:
        fh.write(policy)
    os.chmod(pol, 0o644)
    env = dict(ACME_K8S_STATE=os.path.join(d, 'state'), ACME_K8S_RUN=os.path.join(d, 'run'),
               ACME_K8S_POLICY=pol, **kube.env())
    keep = {k: os.environ.get(k) for k in list(env) + ['ACME_AGENT_ETC', 'ACME_AGENT_STATE',
                                                       'ACME_AGENT_ROOT_STATE',
                                                       'ACME_AGENT_RUN']}
    for k in ('ACME_AGENT_ETC', 'ACME_AGENT_STATE', 'ACME_AGENT_ROOT_STATE', 'ACME_AGENT_RUN'):
        os.environ.pop(k, None)
    os.environ.update(env)
    try:
        spec = importlib.util.spec_from_file_location('acme_k8s_' + tag, K8S)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.KUBE = m.Kube()
    finally:
        for k, v in keep.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    m.install()
    m.places()
    return m, pol


def b64(s):
    return base64.b64encode(s.encode() if isinstance(s, str) else s).decode()


class Kubernetes(unittest.TestCase):
    POLICY = ('# the cluster\'s word\nallow secret shop/web-tls\nallow restart shop/web\n'
              'allow secret intranet/*\nallow discover\nallow from 192.0.2.0/24\n'
              'allow secret Bad/x\nallow restart shop\n')

    @classmethod
    def setUpClass(cls):
        cls.kube = FakeKube()
        cls.kube.deploys[('shop', 'web')] = []
        cls.m, cls.pol = k8s_mod('unit', cls.POLICY, cls.kube)
        cls.crt, cls.key = certs_pair('www.shop.example.test')

    @classmethod
    def tearDownClass(cls):
        cls.kube.stop()

    def args(self, ns='shop', name='web-tls', reload=True, key=True, crt=None):
        files = [{'path': '/k8s/%s/%s/tls.crt' % (ns, name), 'format': 'fullchain-pem',
                  'mode': 0o644, 'owner': '', 'data': b64(crt or self.crt)}]
        if key:
            files.append({'path': '/k8s/%s/%s/tls.key' % (ns, name), 'format': 'key-pem',
                          'mode': 0o600, 'owner': '', 'data': b64(self.key)})
        a = {'files': files, 'skip_same': True}
        if reload:
            a['reload'] = [{'argv': ['kubectl', 'rollout', 'restart', 'deployment/web', '-n',
                                     ns]}]
        return a

    def deploy(self, args):
        try:
            return self.m.K8sDeploy(self.m.K8sRoot(), args).run()
        except self.m.A.Refused as e:
            return {'ok': False, 'refused': True, 'said': str(e), 'needs': e.needs}

    def test_policy(self):
        kp = self.m.load()
        self.assertEqual(kp['secrets'], [('shop', 'web-tls'), ('intranet', '*')])
        self.assertEqual(kp['restarts'], [('shop', 'web')])
        self.assertTrue(kp['discover'])
        self.assertEqual(len(kp['problems']), 2)
        pol, h, _t = self.m.policy_load()
        self.assertEqual([f['dir'] for f in pol['files']], ['/k8s/shop/web-tls', '/k8s/intranet'])
        self.assertEqual(pol['tests'], [['kubectl', 'rollout', 'restart', 'deployment/web', '-n',
                                         'shop']])
        self.assertEqual(pol['from'], ['192.0.2.0/24'])
        rep = G.clean_policy(self.m.K8sRoot.report(pol, h))
        self.assertEqual(rep['discover'], ['*'])
        # what acme makes of it: a deployment's needs judged by acme-agent's own code
        self.assertTrue(LX.file_rule(rep, '/k8s/shop/web-tls/tls.key'))
        self.assertFalse(LX.file_rule(rep, '/k8s/shop/other/tls.key'))
        self.assertTrue(LX.file_rule(rep, '/k8s/intranet/any/tls.crt'))
        self.assertEqual(self.m.restart_of({'argv': ['kubectl', 'rollout', 'restart',
                                                     'deploy/web', '--namespace=shop']}),
                         ('shop', 'web'))
        self.assertIsNone(self.m.restart_of({'argv': ['kubectl', 'delete', 'ns', 'shop']}))
        self.assertIsNone(self.m.restart_of({'argv': ['kubectl', 'rollout', 'restart',
                                                      'deployment/web']}))          # no -n
        # a policy the agent itself could write is not believed (as root: not root's)
        os.chmod(self.pol, 0o666)
        try:
            kp = self.m.load()
            self.assertEqual(kp['secrets'], [])
            self.assertIn('nothing is allowed', kp['problems'][-1])
        finally:
            os.chmod(self.pol, 0o644)

    def test_refused_whole(self):
        before = dict(self.kube.secrets)
        for args, words in (
                (self.args('shop', 'other-tls'), 'allow secret shop/other-tls'),
                (dict(self.args(), reload=[{'argv': ['kubectl', 'rollout', 'restart',
                                                     'deployment/api', '-n', 'shop']}]),
                 'allow restart shop/api'),
                (dict(self.args(), reload=[{'unit': 'nginx', 'verb': 'reload'}]),
                 'restarts a Deployment only'),
                (dict(self.args(), test=[{'argv': ['true']}]), 'runs no command'),
                (dict(self.args(), script={'mode': 'inline', 'body': 'x'}), 'runs no script'),
                (self.args(key=False), 'certificate and its key together'),
                ({'files': [{'path': '/etc/ssl/x.pem', 'data': b64(self.crt)}]},
                 'not a place of a Secret'),
                ({'files': [{'path': '/k8s/shop/web-tls/tls.key', 'format': 'key-pem',
                             'data': b64(self.crt)},
                            {'path': '/k8s/shop/web-tls/tls.crt', 'data': b64(self.crt)}]},
                 'not PEM')):
            got = self.deploy(args)
            self.assertFalse(got['ok'], words)
            self.assertIn(words, got['said'] + json.dumps(got.get('needs') or []), words)
        self.assertEqual(self.kube.secrets, before)          # nothing written

    def test_write_replace_same_restart_back(self):
        self.kube.secrets.pop(('shop', 'web-tls'), None)
        del self.kube.deploys[('shop', 'web')][:]
        got = self.deploy(self.args())
        self.assertTrue(got['ok'], got)
        s = self.kube.secrets[('shop', 'web-tls')]
        self.assertEqual(s['type'], 'kubernetes.io/tls')
        self.assertEqual(base64.b64decode(s['data']['tls.crt']).decode(), self.crt)
        self.assertEqual(s['metadata']['labels']['app.kubernetes.io/managed-by'], 'acme-agent')
        self.assertEqual([f['sha256'] for f in got['files']][0],
                         __import__('hashlib').sha256(self.crt.encode()).hexdigest())
        p = self.kube.deploys[('shop', 'web')]
        self.assertEqual(len(p), 1)
        self.assertIn('kubectl.kubernetes.io/restartedAt',
                      p[0]['spec']['template']['metadata']['annotations'])
        self.assertIn(('PATCH', '/apis/apps/v1/namespaces/shop/deployments/web',
                       'application/strategic-merge-patch+json'), self.kube.calls)
        # the same again: nothing written, nothing restarted
        got = self.deploy(self.args())
        self.assertTrue(got.get('unchanged'), got)
        self.assertEqual(len(p), 1)
        # another certificate: replaced (its other keys and labels kept)
        s['data']['ca.crt'] = b64('x')
        crt2, _k = certs_pair('www.shop.example.test', 10)
        got = self.deploy(self.args(crt=crt2))
        self.assertTrue(got['ok'], got)
        s = self.kube.secrets[('shop', 'web-tls')]
        self.assertEqual(base64.b64decode(s['data']['tls.crt']).decode(), crt2)
        self.assertEqual(s['data']['ca.crt'], b64('x'))
        self.assertEqual(len(p), 2)
        # the restart fails: the Secret as it was is back
        self.kube.fail_patch = True
        try:
            got = self.deploy(self.args())
        finally:
            self.kube.fail_patch = False
        self.assertFalse(got['ok'])
        self.assertIn('as they were are back', got['said'])
        self.assertEqual(base64.b64decode(
            self.kube.secrets[('shop', 'web-tls')]['data']['tls.crt']).decode(), crt2)
        # a Secret of another type is never changed
        self.kube.secrets[('intranet', 'opaque')] = {'type': 'Opaque', 'metadata': {
            'name': 'opaque', 'resourceVersion': '1'}, 'data': {'x': 'eA=='}}
        got = self.deploy(self.args('intranet', 'opaque', reload=False))
        self.assertFalse(got['ok'])
        self.assertIn('not kubernetes.io/tls', got['said'])
        # NS/*: any name there; a namespace its RBAC does not open: the API's word
        got = self.deploy(self.args('intranet', 'portal-tls', reload=False))
        self.assertTrue(got['ok'], got)
        self.kube.ns.discard('intranet')
        try:
            got = self.deploy(self.args('intranet', 'portal-tls', reload=False))
            self.assertFalse(got['ok'])
            self.assertIn('403', got['said'])
        finally:
            self.kube.ns.add('intranet')

    def test_discover_and_ops(self):
        self.deploy(self.args('intranet', 'wiki-tls', reload=False))
        r = self.m.K8sRoot()
        got = r.op_discover({}, {}, {})
        names = sorted(f['site'] for f in got['discover']['found'])
        self.assertIn('intranet/wiki-tls', names)
        self.assertNotIn('PRIVATE KEY', json.dumps(got))
        v = AD.clean(got['discover'])
        f = [x for x in v['found'] if x['site'] == 'intranet/wiki-tls'][0]
        self.assertEqual(f['cert']['cn'], 'www.shop.example.test')
        o = AD.prefill(f, 'linux')
        self.assertEqual(o['outputs'], ['fullchain-pem /k8s/intranet/wiki-tls/tls.crt 0644 '
                                        'root:root', 'key-pem /k8s/intranet/wiki-tls/tls.key '
                                        '0600 root:root'])
        with self.assertRaises(self.m.A.Refused):
            r.op_keygen({}, {}, {})
        with self.assertRaises(self.m.A.Refused):
            r.op_update({}, {}, {})
        fp = r.op_fingerprints({'paths': ['/k8s/intranet/wiki-tls/tls.crt', '/etc/passwd']},
                               {}, {})
        self.assertEqual(fp['files'][0]['sha256'],
                         __import__('hashlib').sha256(self.crt.encode()).hexdigest())
        self.assertIsNone(fp['files'][1]['sha256'])
        chk = r.op_check(self.args(), {}, {})
        self.assertTrue(chk['ok'], chk)
        chk = r.op_check(self.args('shop', 'nope'), {}, {})
        self.assertFalse(chk['ok'])
        self.assertEqual(chk['needs'][0]['allow'], 'allow secret shop/nope')


# ---- B5, the whole way: joined to acme, a certificate deployed into a Secret ----------------------
class KubernetesJoined(unittest.TestCase):
    """The pod's agent as a process of its own (never root: nobody), joined to acme's engine in
    this process by acme-agent's own join, then acme's agent target deploys a certificate."""

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or not shutil.which('setpriv'):
            raise unittest.SkipTest('needs root and setpriv (to run the pod\'s agent as nobody)')
        cls.kube = FakeKube(('shop',))
        cls.kube.deploys[('shop', 'web')] = []
        cls.d = os.path.join(TMP, 'pod')
        for sub in ('state', 'run', 'cfg'):
            os.makedirs(os.path.join(cls.d, sub), exist_ok=True)
        nobody = pwd.getpwnam('nobody')
        cls.ids = (nobody.pw_uid, nobody.pw_gid)
        for sub in ('state', 'run'):
            os.chown(os.path.join(cls.d, sub), *cls.ids)
        os.chmod(cls.d, 0o755)
        cls.policy = os.path.join(cls.d, 'cfg', 'policy')
        with open(cls.policy, 'w') as fh:
            fh.write('allow secret shop/web-tls\nallow restart shop/web\n')
        os.chmod(cls.policy, 0o644)
        os.chmod(os.path.join(cls.d, 'cfg'), 0o755)
        cls.env = dict(os.environ, ACME_K8S_STATE=os.path.join(cls.d, 'state'),
                       ACME_K8S_RUN=os.path.join(cls.d, 'run'), ACME_K8S_POLICY=cls.policy,
                       ACME_K8S_CLUSTER='test-cluster', **cls.kube.env())
        for k in ('ACME_AGENT_ETC', 'ACME_AGENT_STATE', 'ACME_AGENT_ROOT_STATE', 'ACME_AGENT_RUN'):
            cls.env.pop(k, None)
        cls.proc = None

    @classmethod
    def tearDownClass(cls):
        if cls.proc is not None and cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(10)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        cls.kube.stop()

    def as_nobody(self, *args):
        return ['setpriv', '--reuid=%d' % self.ids[0], '--regid=%d' % self.ids[1],
                '--clear-groups', sys.executable, '-I', K8S] + list(args)

    def test_join_and_deploy(self):
        import socket
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()
        rid = A.family_save(STORE, 'target', {'name': 'k8s-shop', 'kind': 'agent', 'config': {
            'mode': 'passive', 'host': '127.0.0.1', 'port': port, 'timeout': 20},
            'enabled': 1}, 'tester')
        row = S.plugin_row(STORE, 'target', rid)
        code = G.code_new(STORE, row, 'tester')['code']
        got = subprocess.run(self.as_nobody('join', code, '--no-wait', '--listen', '127.0.0.1'),
                             env=self.env, capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('confirm it there', got.stdout)
        # as root it is refused
        r0 = subprocess.run([sys.executable, '-I', K8S, 'serve'], env=self.env,
                            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(r0.returncode, 0)
        self.assertIn('never runs as root', r0.stderr)
        type(self).proc = subprocess.Popen(self.as_nobody('serve'), env=self.env,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        a = {}
        for _ in range(75):
            a = G.look(STORE, row, 'tester')
            if a.get('pending'):
                break
            time.sleep(0.2)
        self.assertTrue(a.get('pending'), (a, self.proc.poll()))
        fp = subprocess.run(self.as_nobody('fingerprint'), env=self.env, capture_output=True,
                            text=True, timeout=30).stdout.strip()
        self.assertEqual(fp, a['pending']['fp_words'])
        G.confirm(STORE, row, fp, 'tester')
        for _ in range(50):
            a = G.look(STORE, row, 'tester')
            if a.get('state') == 'answers' and a.get('policy') and a.get('os'):
                break
            time.sleep(0.2)
        self.assertEqual(a.get('state'), 'answers', a)
        self.assertTrue(a['os'].startswith('Kubernetes v1.31.2'), (a, G.state(STORE, rid)))
        self.assertEqual([f['dir'] for f in a['policy']['files']], ['/k8s/shop/web-tls'])
        # acme's own agent target deploys a certificate into the Secret
        crt, key = certs_pair('www.shop.example.test')

        class Bundle(base.Bundle):
            def __init__(self):
                self.cert_pem, self.key_pem, self.chain_pems = crt, key, []
                self.fullchain_pem = crt
                self.name, self.names = 'www', ['www.shop.example.test']
                self.fingerprint = __import__('hashlib').sha256(
                    ssl.PEM_cert_to_DER_cert(crt)).hexdigest()
                self.not_after, self.serial, self.key_type, self.alt = time.time() + 86400, \
                    '1', 'ec-256', None

            def as_format(self, fmt, password=None, alias=None):
                return {'fullchain-pem': crt, 'cert-pem': crt, 'key-pem': key}[fmt].encode()
        ctx = runtime.RunContext(STORE, None, scope='target:k8s-shop')
        ctx.target_name, ctx.deploy_id = 'k8s-shop', 1
        mod = S.plugin_class('target', 'agent')(S.plugin_config('target', row), ctx)
        opts = {'outputs': 'fullchain-pem /k8s/shop/web-tls/tls.crt 0644 root:root\n'
                           'key-pem /k8s/shop/web-tls/tls.key 0600 root:root',
                'reload_cmd': 'kubectl rollout restart deployment/web -n shop'}
        needs = mod.needs(Bundle(), opts)
        self.assertTrue(all(i['ok'] for i in needs['items']), needs)
        said = mod.deploy(Bundle(), opts)
        self.assertIn('Secret', said)
        sec = self.kube.secrets[('shop', 'web-tls')]
        self.assertEqual(base64.b64decode(sec['data']['tls.key']).decode(), key)
        self.assertEqual(len(self.kube.deploys[('shop', 'web')]), 1)
        # one the policy does not allow: refused with the line, nothing written
        bad = dict(opts, outputs=opts['outputs'].replace('web-tls', 'api-tls'))
        with self.assertRaises(base.PluginError) as e:
            mod.deploy(Bundle(), bad)
        self.assertIn('allow secret shop/api-tls', str(e.exception.detail))
        self.assertNotIn(('shop', 'api-tls'), self.kube.secrets)


# ---- the pages ------------------------------------------------------------------------------------
class Pages(unittest.TestCase):
    """Settings → Agent fleet in Chromium (test/f138_fleet_page.js): the hero, groups, agents,
    templates, updates, not managed and the take-over - English and Czech, 1400 and 390 px."""

    @classmethod
    def setUpClass(cls):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            raise unittest.SkipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            raise unittest.SkipTest('no playwright for node here')
        import test_certs_core as TCC
        cls.TCC = TCC
        for k in ('call', 'login', 'ok', 'wait_job'):
            setattr(cls, k, TCC.CertsCore.__dict__[k])
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.TCC.CertsCore.tearDownClass.__func__(cls)

    def seed(self):
        self.ok('POST', '/api/cas/create', {'name': 'Fleet Root', 'subject': {'CN': 'Fleet Root'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Fleet Root', 'days': 90}})
        names = [('web-prague-01', 'agent', 'linux', NGINX, '1.0.138', True),
                 ('web-prague-02', 'agent', 'linux', NGINX.replace('allow probe local\n', ''),
                  '1.0.130', True),
                 ('web-brno-01', 'agent', 'linux', NGINX + 'allow self-update\n', '1.0.125',
                  True),
                 ('mail-01', 'agent', 'linux', 'allow file /etc/postfix/ssl owner=root:root '
                  'mode=0644\n', '1.0.138', False),
                 ('k8s-shop', 'agent', 'linux', 'allow file /k8s/shop/web-tls owner=root:root '
                  'mode=0644\n', '1.0.138', True),
                 ('iis-01', 'agent_windows', 'windows', 'allow store\nallow iis *\n', '1.0.138',
                  True),
                 ('rds-gw', 'agent_windows', 'windows', 'allow store\n', '1.0.130', True)]
        for n, kind, *_x in names:
            self.ok('POST', '/api/targets/save', {'name': n, 'kind': kind, 'config': {
                'mode': 'passive', 'host': '%s.example.test' % n}})
        rows = self.ok('GET', '/api/targets')
        rows = rows.get('rows') if isinstance(rows, dict) else rows
        ids = {r['name']: r['id'] for r in rows}
        meta = {}
        for n, kind, plat, text, ver, seen in names:
            mod = G.agent_mod_for(plat)
            pol = G.clean_policy(mod.policy_report(mod.parse_policy(text), 'ab' * 32))
            st = {'agent_id': 'ag-%012x' % (0x200000 + ids[n]), 'cert_fp': 'cd' * 32,
                  'last_seen': time.time() + (3600 * 24 if seen else -7200), 'policy': pol,
                  'policy_at': time.time(), 'platform': plat, 'version': ver,
                  'host': '%s.example.test' % n, 'cert_end': time.time() + 20 * 86400,
                  'joined_at': time.time() - 3600}
            if n == 'k8s-shop':
                st['os'] = 'Kubernetes v1.31.2 (namespace acme-agent)'
            meta['agents:t:%d' % ids[n]] = st
        # a discovery kept for web-prague-02: nginx with a certificate ending in 5 days
        d = {'platform': 'linux', 'kinds': ['nginx'], 'at': time.time(), 'skipped': [],
             'found': [{'kind': 'nginx', 'title': 'nginx', 'preset': 'nginx',
                        'config': '/etc/nginx/conf.d/shop.conf', 'unit': 'nginx.service',
                        'names': ['shop.example.test'], 'listen': ['443 ssl'], 'port': 0,
                        'test': 'nginx -t', 'reload': 'systemctl reload nginx',
                        'cert': {'thumbprint': 'CD' * 20, 'subject': 'CN=shop.example.test',
                                 'issuer': 'CN=Old Issuing CA, O=Example', 'cn': 'shop.example.test',
                                 'serial': '01', 'not_after': time.time() + 5 * 86400,
                                 'sans': ['shop.example.test', 'www.shop.example.test']},
                        'files': [{'role': 'cert', 'format': 'fullchain-pem', 'there': True,
                                   'path': '/etc/nginx/ssl/shop.crt', 'mode': '0644',
                                   'owner': 'root', 'group': 'root'},
                                  {'role': 'key', 'format': 'key-pem', 'there': True,
                                   'path': '/etc/nginx/ssl/shop.key', 'mode': '0600',
                                   'owner': 'root', 'group': 'root'}]}],
             'certs': [{'thumbprint': 'AB' * 20, 'subject': 'CN=legacy.example.test',
                        'issuer': 'CN=legacy.example.test', 'cn': 'legacy.example.test',
                        'serial': '02', 'not_after': time.time() - 3 * 86400,
                        'sans': ['legacy.example.test'], 'where': ['/etc/ssl/legacy.pem']}]}
        meta['agents:discover:%d' % ids['web-prague-02']] = dict(AD.clean(d), by='tester')
        fn = os.path.join(self.tmp, 'seed.json')
        with open(fn, 'w') as fh:
            json.dump(meta, fh)
        got = subprocess.run([sys.executable, '-c', (
            'import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); d = json.load(open(%r)); '
            '[st.set_meta(k, json.dumps(v, sort_keys=True)) for k, v in d.items()]') % (ROOT, fn)],
            env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        self.ok('POST', '/api/fleet/group_save', {
            'name': 'Web servers', 'color': 'teal', 'note': 'nginx in Prague and Brno',
            'members': [ids['web-prague-01'], ids['web-prague-02'], ids['web-brno-01']],
            'template': 'builtin:nginx-web'})
        self.ok('POST', '/api/fleet/group_save', {'name': 'Canary', 'color': 'violet',
                                                  'canary': True,
                                                  'members': [ids['web-brno-01']]})
        self.ok('POST', '/api/fleet/group_save', {
            'name': 'Windows', 'color': 'blue', 'members': [ids['iis-01'], ids['rds-gw']],
            'template': 'builtin:iis'})
        self.ok('POST', '/api/fleet/template_save', {
            'title': 'Shop cluster', 'platform': 'linux', 'note': 'the Secrets of the shop',
            'text': 'allow file /k8s/shop/web-tls owner=root:root mode=0644\n'})
        # the API answers a read-only account, refuses it a change
        st, _g = self.call('GET', '/api/fleet', session=self.ro)
        self.assertEqual(st, 200)
        st, _g = self.call('POST', '/api/fleet/group_save', {'name': 'x'}, session=self.ro)
        self.assertEqual(st, 403)
        st, _g = self.call('POST', '/api/fleet/group_save', {'name': 'x'},
                           session=self.cert_admin)
        self.assertEqual(st, 403)
        return ids

    def test_pages(self):
        node = shutil.which('node')
        self.seed()
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        extra = {}
        for fn in [x for x in CS_EXTRA.split(os.pathsep) if x]:
            if os.path.isfile(fn):
                with open(fn, encoding='utf-8') as fh:
                    extra.update(json.load(fh))
        if extra:
            cs = os.path.join(web, 'lang', 'cs.json')
            with open(cs, encoding='utf-8') as fh:
                pack = json.load(fh)
            have = {v.get('source') for part in ('strings', 'patterns')
                    for v in pack.get(part, {}).values()}
            for i, (k, v) in enumerate(sorted(extra.items())):
                if k not in have:
                    part = 'patterns' if '{0}' in k else 'strings'
                    pack[part]['xf138%04d' % i] = {'source': k, 'text': v}
            with open(cs, 'w', encoding='utf-8') as fh:
                json.dump(pack, fh, ensure_ascii=False, indent=1)
        port = self.TCC.free_port()
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
                    time.sleep(0.2)
            env = dict(os.environ)
            got = subprocess.run([node, os.path.join(HERE, 'f138_fleet_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=900)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertFalse(out.get('error'), out)
        self.assertEqual(out['errors'], [], out['errors'])
        c = out['checks']
        for tag in ('en1400_', 'en390_', 'cs1400_', 'cs390_'):
            self.assertIs(c[tag + 'fits'], True, (tag, c[tag + 'fits']))
            self.assertGreaterEqual(c[tag + 'groups'], 3, tag)
            self.assertEqual(c[tag + 'agents'], 7, tag)
            self.assertGreaterEqual(c[tag + 'templates'], 10, tag)
            self.assertGreaterEqual(c[tag + 'unmanaged'], 2, tag)
            self.assertIs(c[tag + 'takeover'], True, tag)
            self.assertIs(c[tag + 'drift'], True, tag)
        self.assertEqual(c['en1400_tab'], 'Groups')
        self.assertEqual(c['cs1400_tab'], 'Skupiny')
        self.assertNotIn('Groups', c['cs1400_words'])
        self.assertIn('builder_fleet', c)
        self.assertGreaterEqual(c['builder_fleet'], 5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
