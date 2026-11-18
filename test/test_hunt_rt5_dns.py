#!/usr/bin/env python3
"""Hunt R t5, area dns: regressions for the bugs fixed in domain validation.

    python3 test/test_hunt_rt5_dns.py

- a dry run stopped while it waits: its test record is taken away all the same (the
  cleanup runs as tidying, as an order's proofs do);
- nginx "listen ADDRESS;" (no port) is port 80: the HTTP-01 include goes into that block;
- a scoped certificate administrator's challenge_map is held to the team's validations.
"""
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_teams_enterprise as TE  # noqa: E402  (its database, its helpers - first: env)
import test_challenges as TC  # noqa: E402

from acmelib.certs.runtime import RunContext  # noqa: E402
from acmelib.plugins import limits as L  # noqa: E402
from acmelib.plugins.challenges import _nginx as NG  # noqa: E402
from acmelib.plugins.challenges._common import DnsChallenge  # noqa: E402

T, STORE = TE.T, TE.STORE


class StoppableCtx(TC.FakeCtx):
    """A FakeCtx that stops as acme's own RunContext does (its cancelled() and tidying())."""
    cancelled = RunContext.cancelled
    tidying = RunContext.tidying

    def __init__(self, *a, **k):
        TC.FakeCtx.__init__(self, *a, **k)
        self._stop = threading.Event()
        self.job = None


class Recorded(DnsChallenge):
    kind = 'recorded'
    title = 'recorded'
    fields = []

    def __init__(self, config, ctx):
        DnsChallenge.__init__(self, config, ctx)
        self.records = []

    def add_txt(self, fqdn, value):
        self.records.append((fqdn, value))
        return None

    def del_txt(self, fqdn, value, handle):
        # a request that has to wait for its turn at the provider (limits.throttle): stopped
        # it says "stopped" unless it runs as tidying
        L._sleep(0.05, self.ctx.cancelled)
        self.records.remove((fqdn, value))

    def ready(self, name, handle):
        self.ctx._stop.set()                # the job is stopped while it waits
        return False

    def seen_outside(self, name, handle):
        return []


class DryRunStopped(unittest.TestCase):
    def test_test_record_taken_away_after_a_stop(self):
        ctx = StoppableCtx()
        m = Recorded({'propagation': 'none'}, ctx)
        m.dry_run('www.example.com', wait=5)
        self.assertEqual(m.records, [])
        self.assertIn(('ok', 'The test value is taken away again'), ctx.steps)
        self.assertTrue(ctx.cancelled())            # still stopped afterwards


class NginxListen(unittest.TestCase):
    def port80(self, listen):
        return NG.on_port_80(NG.server_blocks('server { %s server_name a.example; }'
                                              % listen)[0])

    def test_address_alone_is_port_80(self):
        for line in ('listen 192.0.2.1;', 'listen [::];', 'listen localhost;',
                     'listen 192.0.2.1 default_server;'):
            self.assertTrue(self.port80(line), line)

    def test_as_before(self):
        for line, want in (('listen 80;', True), ('listen [::]:80;', True),
                           ('listen *:80;', True), ('listen 8080;', False),
                           ('listen 192.0.2.1:8080;', False), ('listen 443 ssl;', False),
                           ('listen 192.0.2.1 ssl;', False), ('listen unix:/run/x.sock;', False)):
            self.assertEqual(self.port80(line), want, line)

    def test_patch_includes_it(self):
        text = 'server {\n    listen 192.0.2.1;\n    server_name a.example;\n}\n'
        out, done, _left = NG.patch(text, 'include /etc/nginx/snippets/acme-challenge.conf; # acme')
        self.assertEqual(done, ['a.example'])
        self.assertIn('acme-challenge.conf', out)


class ChallengeMapLimits(unittest.TestCase):
    def setUp(self):
        TE.clean()
        for n in ('dns1', 'dns2'):
            if not STORE.db.row('SELECT id FROM cert_challenges WHERE name = ?', (n,)):
                STORE.db.insert('cert_challenges', {'name': n, 'kind': 'manual',
                                                    'config': '{}', 'enabled': 1})
        T.save_team(STORE, {'name': 'Free', 'members': ['local:eva=manage']}, 'x')
        T.save_team(STORE, {'name': 'Tight', 'members': ['local:eva=manage'],
                            'policy': {'validations': ['dns1']}}, 'x')
        TE.E.CONFIG.update(certs_certadmin_all=0)

    def tearDown(self):
        TE.E.CONFIG.update(certs_certadmin_all=1)

    def save(self, body):
        return TE.may('POST', '/api/certs/save', body, who='eva', role='certadmin')

    def new(self, name, **more):
        b = {'name': name, 'names': ['%s.example.test' % name], 'issuer': 'self',
             'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'Tight', 'hold': 1,
             'challenge': 'dns1'}
        b.update(more)
        return b

    def test_new_cert_map_refused(self):
        self.assertEqual(self.save(self.new('m1', challenge_map={
            'm1.example.test': 'dns2'})), 403)
        self.assertIsNone(STORE.db.row("SELECT id FROM certs WHERE name = 'm1'"))
        self.assertEqual(self.save(self.new('m2', challenge_map={
            'm2.example.test': 'dns1'})), 200)

    def test_change_map_refused(self):
        self.assertEqual(self.save(self.new('m3')), 200)
        row = STORE.db.row("SELECT * FROM certs WHERE name = 'm3'")
        self.assertEqual(self.save({'id': row['id'], 'challenge_map': {'*.example.test': 'dns2'}}),
                         403)
        self.assertEqual(self.save({'id': row['id'], 'challenge_map': '{"m3.example.test": '
                                                                      '"dns2"}'}), 403)
        self.assertEqual(self.save({'id': row['id'], 'challenge_map': {}}), 200)

    def test_moved_cert_map_checked(self):
        TE.cert('mv', 'Free', challenge='dns1', challenge_map={'mv.example.test': 'dns2'})
        row = STORE.db.row("SELECT * FROM certs WHERE name = 'mv'")
        self.assertEqual(self.save({'id': row['id'], 'owner': 'Tight'}), 403)
        self.assertEqual(STORE.db.value("SELECT owner FROM certs WHERE name = 'mv'"), 'Free')


if __name__ == '__main__':
    unittest.main()
