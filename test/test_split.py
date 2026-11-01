#!/usr/bin/env python3
"""When the two nodes lose each other - split brain (docs/split-brain.md).

    python3 test/test_split.py            (or python3 -m unittest test.test_split)

In one process, SQLite, as otp 1.0.218's tests/split/t_split.py: the other node
and the arbiter are played by the test - split_step(store, now, peer=True|'words',
arbiter=True|False|None). The decision of every mode; "as until now" running
nothing at all (the other node never asked, the arbiter never pinged, nothing
written); stepping aside (maintenance_now, the lead let go, acme's DNS server
silent, nothing renewed or signed); half the tries; changes refused on the node
that is not the preferred one (the real dispatcher); the report of what was done
on both halves; the alerts; the arbiter's ping, TCP and parser; the API of the
card; the card's pieces on the pages and through the page's relay.
"""
import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-split-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as _api, ca as CA, pki, renewer, store as S  # noqa: E402,F401

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAEMON = E.Daemon(STORE, serve=False)
SWITCHES = ('split_renew', 'split_halve', 'split_freeze', 'split_report')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def beat(name, age=0):
    STORE.set_meta('node:' + name, json.dumps({'at': time.time() - age, 'address': '127.0.0.1',
                                              'version': E.__version__}))


def reset(**conf):
    """A replicated pair acme1 (slot 1, this one) + acme2, everything at its default."""
    for k in ('split_mode', 'split_prefer', 'split_arbiter', 'split_after_s') + SWITCHES:
        E.CONFIG[k] = E.DEFAULTS[k]
    E.CONFIG.update(ha_mode='replicated', ha_peer='192.0.2.250', ha_slot=1, node_name='acme1')
    E.CONFIG.update(conf)
    E.SPLIT.update(peer_ok_at=time.time(), peer_err='', apart_since=0.0, role='serve', why='',
                   arb=[], arb_state=None, arb_at=0.0, together_at=0.0, report_due=0.0,
                   written=0.0)
    E.MAINT_CACHE['at'] = 0
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'split:%' OR k LIKE 'node:%' OR "
                 "k = 'certs:leader' OR k LIKE 'ask:%'")
    beat('acme1')
    beat('acme2')


def apart(store=STORE, **kw):
    """Apart: the other node silent for longer than split_after_s."""
    t0 = time.time()
    E.split_step(store, now=t0, peer='refused', **kw)
    E.split_step(store, now=t0 + 60, peer='refused', **kw)
    return t0 + 60


class Spy(object):
    """The other node's database and the arbiter - asked, they count it."""
    def __init__(self):
        self.peer = 0
        self.arb = 0
        self._probe, self._check = E._split_peer_probe, E.split_arbiter_check

    def __enter__(self):
        def probe():
            self.peer += 1
            return 'refused'

        def check(targets=None):
            self.arb += 1
            return [], False
        # The engine's functions are its namespace's: replaced there.
        E._split_peer_probe = probe
        E.split_arbiter_check = check
        sys.modules['acmelib.engine'].__dict__['_split_peer_probe'] = probe
        sys.modules['acmelib.engine'].__dict__['split_arbiter_check'] = check
        return self

    def __exit__(self, *a):
        sys.modules['acmelib.engine'].__dict__['_split_peer_probe'] = self._probe
        sys.modules['acmelib.engine'].__dict__['split_arbiter_check'] = self._check


class FakeDaemon(object):
    def __init__(self):
        self.store = STORE
        self.stop_flag = threading.Event()


# ---------------------------------------------------------------------------
class Decide(unittest.TestCase):
    def test_every_mode(self):
        d = E.split_decide
        for mode in E.SPLIT_MODES:
            for arb in (True, False, None):
                self.assertEqual(d(mode, False, arb, False)[0], 'serve')      # together
        self.assertEqual(d('off', True, False, False)[0], 'serve')
        self.assertEqual(d('priority', True, True, True)[0], 'serve')
        self.assertEqual(d('priority', True, True, False)[0], 'aside')
        self.assertEqual(d('arbiter', True, True, False)[0], 'serve')
        self.assertEqual(d('arbiter', True, False, True)[0], 'aside')
        self.assertEqual(d('arbiter', True, None, False)[0], 'serve')    # cannot be asked


class AsUntilNow(unittest.TestCase):
    def setUp(self):
        reset()

    def test_default_is_as_until_now(self):
        for k in ('split_mode',) + SWITCHES:
            self.assertIn(E.DEFAULTS[k], ('off', 0))
        self.assertFalse(E.split_engaged())

    def test_nothing_runs(self):
        """No peer probe, no arbiter ping, no row, no limit changed, nothing frozen or held."""
        E.CONFIG['login_tries'] = 10
        with Spy() as spy:
            for i in range(5):
                E.split_step(STORE, now=time.time() + i * 100)
            # The watch's own thread too, for a few of its steps.
            d = FakeDaemon()
            E.SPLIT['thread'] = None
            E.split_tick(d)
            time.sleep(2.5)
            d.stop_flag.set()
            E.SPLIT['thread'].join(5)
        self.assertEqual((spy.peer, spy.arb), (0, 0))
        self.assertFalse(E.split_apart())
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM meta WHERE k LIKE 'split:%'"), 0)
        self.assertEqual(E.split_limit('login_tries', 5), 10)
        self.assertFalse(E.split_frozen())
        self.assertFalse(E.split_no_lead())
        self.assertEqual(E.split_issue_refused(), '')
        self.assertFalse(E.maintenance_now(STORE).get('split'))
        self.assertEqual(E.split_refuses('POST', '/api/certs/save'), '')
        E.split_took(STORE, 'renew', 'x', 'renew:1')
        self.assertIsNone(STORE.get_meta('split:took:acme1:renew:1'))
        self.assertFalse([k for k in E.alert_problems(STORE) if k.startswith('split')])
        self.assertTrue(renewer.lease_tick(STORE))      # leads as before

    def test_one_node_or_shared_never_apart(self):
        for conf in ({'ha_mode': ''}, {'ha_mode': 'shared'}, {'ha_peer': ''}):
            reset(split_mode='priority', split_report=1, **conf)
            with Spy() as spy:
                apart()
            self.assertFalse(E.split_active())
            self.assertFalse(E.split_apart())
            self.assertEqual(spy.peer, 0)


class Priority(unittest.TestCase):
    def test_the_other_node_steps_aside(self):
        reset(split_mode='priority', ha_slot=2)          # acme1 is slot 2: acme2 is preferred
        t0 = time.time()
        E.split_step(STORE, now=t0, peer=True)
        E.split_step(STORE, now=t0 + 5, peer='refused')
        self.assertFalse(E.split_apart())                # 5 s of 20
        E.split_step(STORE, now=t0 + 30, peer='refused')
        self.assertTrue(E.split_apart())
        self.assertTrue(E.split_aside())
        m = E.maintenance_now(STORE)
        self.assertTrue(m['on'] and m['split'])
        self.assertIn('stepped aside', m['why'])
        st = json.loads(STORE.get_meta('split:state:acme1'))
        self.assertEqual((st['role'], st['apart'], st['held']), ('aside', True, True))
        E.split_step(STORE, now=t0 + 32, peer=True)
        self.assertFalse(E.split_apart())
        self.assertFalse(E.maintenance_now(STORE).get('split'))

    def test_the_preferred_node_serves(self):
        reset(split_mode='priority')
        apart()
        self.assertTrue(E.split_apart())
        self.assertFalse(E.split_aside())
        self.assertFalse(E.split_no_lead())
        self.assertEqual(E.split_preferred_name(STORE), 'acme1')

    def test_preferred_by_name(self):
        reset(split_mode='priority', split_prefer='acme2')
        apart()
        self.assertTrue(E.split_aside())


class Arbiter(unittest.TestCase):
    def test_reached_lost_back(self):
        reset(split_mode='arbiter')
        t = apart(arbiter=True)
        self.assertFalse(E.split_aside())
        E.split_step(STORE, now=t + 2, peer='refused', arbiter=False)
        self.assertTrue(E.split_aside())
        E.split_step(STORE, now=t + 4, peer='refused', arbiter=None)    # cannot be asked
        self.assertFalse(E.split_aside())

    def test_tcp_listening_refused_silent(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(E.split_tcp('127.0.0.1', port)[0])
        finally:
            srv.close()
        self.assertTrue(E.split_tcp('127.0.0.1', free_port())[0])      # refused: it is there
        got, verdict = E.split_arbiter_check([('127.0.0.1', free_port()), ('192.0.2.1', 9)])
        self.assertTrue(verdict)

    def test_ping(self):
        ok, how, words = E.split_ping('127.0.0.1')
        self.assertIn(ok, (True, None), words)           # None: no way to ping here at all
        self.assertFalse(E.split_ping('no-such-name.invalid')[0])

    def test_parser(self):
        p = E.split_targets_parse
        self.assertEqual(p('192.0.2.1, gw.example.cz:443 [2001:db8::1]:53;2001:db8::2'),
                         [('192.0.2.1', None), ('gw.example.cz', 443), ('2001:db8::1', 53),
                          ('2001:db8::2', None)])
        self.assertEqual(p(''), [])
        for bad in ('a b c d e f', 'x:99999', 'a/b'):
            self.assertRaises(ValueError, p, bad)
        self.assertRaises(E.BadSetting, E.check_setting, 'split_arbiter', 'a/b')
        self.assertIsInstance(E.default_gateway(), str)
        E.CONFIG['split_arbiter'] = ''
        gw = E.default_gateway()
        self.assertEqual(E.split_targets(), [(gw, None)] if gw else [])


class Halve(unittest.TestCase):
    def test_half_while_apart(self):
        reset(split_halve=1, login_tries=10, portal_tries=3)
        self.assertEqual(E.split_limit('login_tries', 5), 10)
        apart()
        self.assertEqual(E.split_limit('login_tries', 5), 5)
        self.assertEqual(E.split_limit('portal_tries', 5), 2)
        self.assertTrue(json.loads(STORE.get_meta('split:state:acme1'))['halved'])

    def test_the_sign_ins_count_half(self):
        """The administration's and the portal's sign-ins ask the halved number."""
        reset(split_halve=1, login_tries=10, portal_tries=6, portal=1)
        apart()
        asked = []

        class H(E.CliApiHandler):
            def throttle(self, kind, tries, wait_min, **kw):
                asked.append((kind, tries))
                raise E.ApiError(429, 'counted')
        for path, body in (('/api/auth/login', {'name': 'x', 'password': 'y'}),
                           ('/api/portal/login', {'name': 'x', 'password': 'y'})):
            h = H(DAEMON, 'x', body, {}, path)
            try:
                E.ROUTES[('POST', path)](h)
            except E.ApiError:
                pass
        self.assertEqual(asked, [('admin', 5), ('portal', 3)])


# ---------------------------------------------------------------------------
class Dispatch(E.ApiHandler):
    """The real dispatcher (ApiHandler.route), no socket."""
    def __init__(self, method, path, body=None):
        raw = json.dumps(body or {}).encode()
        self.path = path
        self.headers = {'X-Acme-Token': E.api_token() or '', 'Content-Length': str(len(raw))}
        self.rfile = io.BytesIO(raw)
        self.client_address = ('127.0.0.1', 0)
        self.server = type('S', (), {'daemon': DAEMON})()
        self.sent = None
        self.route(method)

    def send_json(self, data, status=200):
        self.sent = (status, data)


class Freeze(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not E.api_token():
            E.api_token(make=True)

    def test_changes_refused_on_the_other_node(self):
        reset(split_freeze=1, ha_slot=2)                 # acme2 is the preferred node
        apart()
        self.assertTrue(E.split_frozen())
        for path in ('/api/certs/save', '/api/settings', '/api/cas/create', '/api/sources/save',
                     '/api/validations/check', '/api/targets/discover', '/api/teams/save',
                     '/api/deploys/run', '/api/users'):
            got = Dispatch('POST', path, {'id': 1}).sent
            self.assertEqual(got[0], 409, path)
            self.assertTrue(got[1]['split'])
            self.assertIn('acme2', got[1]['error'])
        # Not refused (not signed in here: 401, past the freeze): a GET, a sign-in, the card.
        for method, path, body in (('GET', '/api/certs', None),
                                   ('POST', '/api/auth/login', {'name': 'x', 'password': 'y'}),
                                   ('POST', '/api/split', {'action': 'save'}),
                                   ('POST', '/api/portal/login', {'name': 'x', 'password': 'y'}),
                                   ('POST', '/api/upgrade', {'action': 'maintenance'})):
            got = Dispatch(method, path, body).sent
            self.assertNotEqual(got[0], 409, path)
        self.assertEqual(Dispatch('POST', '/api/upgrade', {'action': 'start'}).sent[0], 409)

    def test_the_preferred_node_goes_on(self):
        reset(split_freeze=1)
        apart()
        self.assertFalse(E.split_frozen())
        self.assertEqual(E.split_refuses('POST', '/api/certs/save'), '')

    def test_together_nothing_frozen(self):
        reset(split_freeze=1, ha_slot=2)
        E.split_step(STORE, now=time.time(), peer=True)
        self.assertFalse(E.split_frozen())

    def test_a_change_while_apart_is_written_down(self):
        reset(split_report=1)
        apart()
        Dispatch('POST', '/api/certs/save', {'id': 7})       # 401 - not noted
        self.assertFalse(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'split:took:%'"))
        h = Dispatch.__new__(Dispatch)
        h._body = {'id': 7, 'action': 'x'}
        h.server = type('S', (), {'daemon': DAEMON})()
        h._split_noted('/api/certs/save')
        rows = STORE.db.rows("SELECT k, v FROM meta WHERE k LIKE 'split:took:acme1:change:%'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['v'])['name'], '/api/certs/save x #7')
        h._split_noted('/api/auth/login')                   # a free path is no change
        self.assertEqual(len(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'split:took:%'")), 1)


# ---------------------------------------------------------------------------
class StepAside(unittest.TestCase):
    """Aside, or held back (split_renew): no lead, no renewal, no signing, no DNS."""

    def test_no_lead(self):
        reset(split_mode='priority', ha_slot=2)
        self.assertTrue(renewer.lease_tick(STORE))
        apart()
        self.assertTrue(E.split_no_lead())
        self.assertFalse(renewer.lease_tick(STORE))
        self.assertIsNone(renewer.leader(STORE))         # its lease let go

    def test_renew_only_on_the_preferred_node(self):
        reset(split_renew=1, ha_slot=2)
        apart()
        self.assertFalse(E.split_aside())                # it answers...
        self.assertTrue(E.split_no_lead())               # ...but does not lead
        self.assertFalse(renewer.lease_tick(STORE))
        self.assertIn('acme2', E.split_issue_refused())
        reset(split_renew=1)                              # the preferred one leads
        apart()
        self.assertFalse(E.split_no_lead())
        self.assertTrue(renewer.lease_tick(STORE))

    def test_nothing_signed_or_renewed(self):
        reset()
        ca_id = int(CA.ca_create(STORE, 'Split CA', {'CN': 'Split CA'}, key_type='ec-256'))
        key = pki.make_key('ec-256')
        csr, _der = pki.make_csr(key, ['split.test.example'])
        CA.ca_sign(STORE, ca_id, csr, 30)                 # as until now: signed
        reset(split_mode='priority', ha_slot=2)
        apart()
        self.assertRaises(pki.PkiError, CA.ca_sign, STORE, ca_id, csr, 30)
        self.assertRaises(pki.PkiError, CA.ca_revoke, STORE, ca_id, '01')
        cid = STORE.db.insert('certs', {'name': 'split-one', 'names': '["split.test.example"]',
                                        'issuer': 'nobody', 'state': 'ok'})

        class Job(object):
            store = STORE

            def step(self, *a, **kw):
                pass
        with self.assertRaises(Exception) as got:
            renewer.renew_cert(STORE, Job(), cid)
        self.assertIn('stepped aside', str(got.exception))
        self.assertEqual(S.cert_get(STORE, cid)['state'], 'ok')    # nothing changed
        STORE.db.run('DELETE FROM certs WHERE id = ?', (cid,))

    def test_dns_server_silent(self):
        port = free_port()
        reset(split_mode='priority', ha_slot=2, dns_server=1, dns_listen='127.0.0.1',
              dns_port=port, dns_zone='acme.test.example')
        r = renewer.Renewer(type('D', (), {'store': STORE, 'stop_flag': threading.Event()})())
        try:
            r.dns_watch()
            self.assertIsNotNone(r.dns, r.dns_said)       # together: it answers
            apart()
            r.dns_watch()
            self.assertIsNone(r.dns)
            self.assertEqual(r.dns_state()['said'], 'stepped aside')
            E.split_step(STORE, now=time.time() + 120, peer=True)
            r.dns_watch()
            self.assertIsNotNone(r.dns)
        finally:
            r.dns_stop()
            E.CONFIG['dns_server'] = 0


# ---------------------------------------------------------------------------
class Report(unittest.TestCase):
    def test_done_on_both(self):
        reset(split_report=1)
        apart()
        E.split_note(STORE, 'renew', 'www.example.cz', 'renew:12')
        E.split_note(STORE, 'signin', 'boss', 'signin:admin:boss')
        E.split_note(STORE, 'sign', 'Own CA', 'sign:3')
        # What came over from the other node once together.
        for k, kind, name in (('renew:12', 'renew', 'www.example.cz'),
                              ('signin:admin:boss', 'signin', 'boss'),
                              ('change:abc', 'change', '/api/settings')):
            STORE.set_meta('split:took:acme2:' + k, json.dumps({'name': name, 'kind': kind,
                                                                'at': time.time()}))
        t = time.time() + 100
        E.split_step(STORE, now=t, peer=True)
        E.split_step(STORE, now=t + 31, peer=True)       # the report 30 s after together
        rep = json.loads(STORE.get_meta('split:report'))
        self.assertEqual(rep['taken'], {'acme1': 3, 'acme2': 3})
        self.assertEqual(rep['twice_n'], 1)              # a sign-in on both is no clash
        self.assertEqual(rep['twice'][0]['name'], 'www.example.cz')
        self.assertEqual(rep['twice'][0]['nodes'], ['acme1', 'acme2'])
        self.assertEqual(rep['kinds']['acme1'], {'renew': 1, 'signin': 1, 'sign': 1})
        self.assertFalse(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'split:took:%'"))
        al = E.alert_problems(STORE)
        self.assertIn('split:twice', al)
        self.assertIn('www.example.cz', al['split:twice']['said'])
        self.assertIn('www.example.cz', E.split_view(STORE)['report']['twice'][0]['name'])

    def test_together_nothing_written(self):
        reset(split_report=1)
        E.split_step(STORE, now=time.time(), peer=True)
        E.split_note(STORE, 'renew', 'x', 'renew:1')
        self.assertFalse(STORE.db.rows("SELECT k FROM meta WHERE k LIKE 'split:took:%'"))

    def test_a_code_let_in_unasked(self):
        reset(split_report=1)
        was = sys.modules['acmelib.engine'].__dict__['_once_peer_has']
        sys.modules['acmelib.engine'].__dict__['_once_peer_has'] = lambda k, me, store=None: None
        try:
            self.assertTrue(E.once_take(STORE, 'step', 'adm2fa:boss', 123456))
        finally:
            sys.modules['acmelib.engine'].__dict__['_once_peer_has'] = was
        rows = STORE.db.rows("SELECT k, v FROM meta WHERE k LIKE 'split:took:acme1:step:%'")
        self.assertEqual(json.loads(rows[0]['v'])['name'], 'boss')
        self.assertEqual(rows[0]['k'], 'split:took:acme1:' + E.once_key('step', 'adm2fa:boss', 123456))

    def test_signed_while_apart_is_written_down(self):
        reset()
        ca_id = int(CA.ca_create(STORE, 'Noted CA', {'CN': 'Noted CA'}, key_type='ec-256'))
        reset(split_report=1)
        apart()
        csr, _der = pki.make_csr(pki.make_key('ec-256'), ['noted.test.example'])
        CA.ca_sign(STORE, ca_id, csr, 30)                 # the preferred node signs...
        self.assertTrue(STORE.get_meta('split:took:acme1:sign:%d' % ca_id))   # ...noted

    def test_alert_while_apart(self):
        reset(split_report=1, split_mode='priority', ha_slot=2)
        apart()
        al = E.alert_problems(STORE)
        self.assertIn('split:acme1', al)
        self.assertIn('stepped aside', al['split:acme1']['title'])
        self.assertIn('does not renew', al['split:acme1']['said'])
        self.assertIn('nevidí druhý uzel', E.alert_problems(STORE, 'cs')['split:acme1']['title'])


# ---------------------------------------------------------------------------
class Card(unittest.TestCase):
    def call(self, method, path, body=None):
        h = E.CliApiHandler(DAEMON, 'tester', body, {}, path)
        return E.ROUTES[(method, path)](h)

    def status(self, *a):
        try:
            self.call(*a)
            return 200
        except E.ApiError as e:
            return e.status

    def test_view(self):
        reset()
        v = self.call('GET', '/api/split')
        self.assertTrue(v['active'])
        self.assertFalse(v['engaged'])
        self.assertEqual([n['name'] for n in v['nodes']], ['acme1', 'acme2'])
        self.assertEqual(v['preferred'], 'acme1')
        self.assertEqual(set(v['conf']), set(E.SPLIT_KEYS))
        self.assertIn('split_renew', v['conf'])

    def test_save(self):
        reset()
        self.assertEqual(self.status('POST', '/api/split', {
            'action': 'save', 'conf': {'split_mode': 'arbiter'}}), 409)    # not tried
        self.assertEqual(self.status('POST', '/api/split', {
            'action': 'save', 'conf': {'split_mode': 'nope'}}), 400)
        self.assertEqual(self.status('POST', '/api/split', {
            'action': 'save', 'conf': {'split_prefer': 'acme9'}}), 400)
        self.assertEqual(self.status('POST', '/api/split', {
            'action': 'save', 'arbiter': {'acme2': 'a/b'}}), 400)
        got = self.call('POST', '/api/split', {
            'action': 'save', 'checked': True,
            'conf': {'split_mode': 'arbiter', 'split_prefer': 'acme2', 'split_after_s': 30,
                     'split_renew': 1, 'split_report': 1},
            'arbiter': {'acme1': '192.0.2.1', 'acme2': 'gw.example.cz:443'}})
        self.assertIn('kept', got['message'])
        saved = STORE.settings_saved()
        self.assertEqual((saved['split_mode'], saved['split_prefer'], int(saved['split_after_s'])),
                         ('arbiter', 'acme2', 30))
        self.assertEqual(saved['split_arbiter@acme2'], 'gw.example.cz:443')
        self.assertEqual(saved['split_arbiter@acme1'], '192.0.2.1')
        arbs = {n['name']: n['arbiter'] for n in got['view']['nodes']}
        self.assertEqual(arbs['acme2'], 'gw.example.cz:443')
        for k in ('split_mode', 'split_prefer', 'split_after_s', 'split_renew', 'split_report',
                  'split_arbiter@acme1', 'split_arbiter@acme2'):
            STORE.drop_setting(k)

    def test_try_from_every_node(self):
        reset()
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(4)
        try:
            asked = self.call('POST', '/api/split', {
                'action': 'try', 'targets': {'acme1': '127.0.0.1:%d' % srv.getsockname()[1]}})
            self.assertIn('acme1', asked['nodes'])
            # The daemon of this node answers in its loop (node_ask_tick).
            E.node_ask_tick(type('D', (), {'store': STORE, 'serving': True})())
            for _ in range(50):
                got = self.call('POST', '/api/split', {'action': 'poll', 'id': asked['id']})
                if (got['nodes'] or {}).get('acme1'):
                    break
                time.sleep(0.1)
            one = got['nodes']['acme1']
            self.assertTrue(one['verdict'])
            self.assertEqual(one['targets'][0]['how'], 'tcp')
        finally:
            srv.close()
        self.assertEqual(self.status('POST', '/api/split', {
            'action': 'try', 'targets': {'acme1': 'a/b'}}), 400)

    def test_not_in_the_settings_lists(self):
        """On their pane (so on no other), never drawn as boxes (otp 1.0.219)."""
        keys = {s['key'] for s in DAEMON.settings_state(True)}
        self.assertFalse([k for k in keys if k.startswith('split_')])
        self.assertTrue(set(E.CARD_DRAWN) <= set(E.PANES['ha']))
        self.assertIn('split_arbiter', E.NODE_KEYS)

    def test_the_card_on_the_pages(self):
        php = open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8').read()
        js = open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8').read()
        css = open(os.path.join(ROOT, 'web', 'assets', 'acme.css'), encoding='utf-8').read()
        for piece in ('id="ha-split-card"', 'id="ha-split-state"', 'id="ha-split"'):
            self.assertIn(piece, php)
        # The relay passes it on, read and write (otp 1.0.219): else only the title shows.
        self.assertEqual(len(re.findall(r"'split' => '/api/split'", php)), 2)
        for piece in ('function loadSplit(', 'function drawSplit(', 'function splitScenarios(',
                      "pendingSet('split'", 'loadSplit(d);', "k: 'split_renew'"):
            self.assertIn(piece, js)
        self.assertNotIn('split_scratch', js)
        for piece in ('.split-now{', '.split-choice.on{', '.split-opt{', '.split-report.bad{'):
            self.assertIn(piece, css)
        cs = json.load(open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8'))
        src = {v['source']: v['text'] for sec in ('strings', 'patterns')
               for v in cs[sec].values()}
        for en, czech in (('When the nodes lose each other', 'Když se uzly ztratí'),
                          ('Try it from every node', 'Vyzkoušet ze všech uzlů'),
                          ('Renewals only on the preferred node while apart',
                           'Obnovy jen na upřednostněném uzlu během oddělení'),
                          ('{0} loses the network', '{0} ztratí síť')):
            self.assertEqual(src.get(en), czech)


if __name__ == '__main__':
    unittest.main(verbosity=2)
