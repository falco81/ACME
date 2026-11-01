#!/usr/bin/env python3
"""Settings → DNS: named sets of DNS servers, and which of them each function asks.

    python3 test/test_dnssets.py

- sets added, changed, renamed and deleted; their names by the safe-names rule;
  "The system's" built in and never deleted; "Public" made once at the first start;
- the set each function asks: its default, the one chosen, the setting of before
  (acme_resolvers, mail_dns), and back to the default when the chosen one goes;
- a name looked up through a set reaches that set's server (acme's own DNS
  server on a high port of 127.0.0.1) - and another set gives another answer;
  UDP and TCP; Test says which server answered, and how long it took;
- ctx.http of a module reaches a local HTTP server by a name only the set knows
  (getaddrinfo asked of the set) - and not through a set that does not know it;
- the engine's own DNS client (ACME, mail) follows the choice;
- a backup and the configuration's export carry the sets;
- the routes: a read-only account sees, only a full administrator changes.
"""
import gzip
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-dnssets-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402,F401  (the routes)
from acmelib.certs import dnssets as N, runtime  # noqa: E402
from acmelib.certs.dnsserver import DnsServer  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402
from test_challenges import MemStore, free_port, server_config, ZONE  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
INSIDE = 'web.' + ZONE                 # a name only the set "Inside" knows


def start_dns(static):
    port = free_port()
    srv = DnsServer(MemStore(), server_config(port, dns_static=static))
    st = srv.start()
    if not st.get('listening'):
        raise unittest.SkipTest('a DNS server cannot listen here: %s' % st.get('failed'))
    return srv, port


class Http(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'hello from inside'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


SRV = {}


def setUpModule():
    SRV['a'], SRV['pa'] = start_dns('web A 127.0.0.1\nhost A 192.0.2.80\n'
                                    '_acme-challenge.www TXT "inside"')
    SRV['b'], SRV['pb'] = start_dns('host A 192.0.2.99')
    SRV['http'] = http.server.HTTPServer(('127.0.0.1', 0), Http)
    threading.Thread(target=SRV['http'].serve_forever, daemon=True).start()


def tearDownModule():
    for k in ('a', 'b'):
        SRV[k].stop()
    SRV['http'].shutdown()


def clean():
    STORE.db.run('DELETE FROM dns_sets')
    STORE.db.run('DELETE FROM dns_set_uses')
    STORE.db.run("DELETE FROM meta WHERE k = ?", (N.SEEDED,))
    for k in ('acme_resolvers', 'mail_dns'):
        E.CONFIG[k] = ''
    N.forget()


def add(name, port, **more):
    b = {'name': name, 'servers': '127.0.0.1:%d' % port, 'timeout': 2}
    b.update(more)
    return N.save_set(STORE, b, 'tester')


class Sets(unittest.TestCase):
    def setUp(self):
        clean()

    def test_public_made_once(self):
        N.ensure(STORE)
        names = [s['name'] for s in N.sets(STORE)]
        self.assertEqual(names[0], N.SYSTEM)
        self.assertIn(N.PUBLIC, names)
        pub = [s for s in N.sets(STORE) if s['name'] == N.PUBLIC][0]
        self.assertEqual(pub['servers'], list(N.PUBLIC_SERVERS))
        with self.assertRaises(ValueError):          # not deleted...
            N.delete_set(STORE, N.PUBLIC, 'tester')
        with self.assertRaises(ValueError):          # ...nor renamed
            N.save_set(STORE, {'old_name': N.PUBLIC, 'name': 'Other', 'servers': '9.9.9.9'}, 'x')
        got = N.save_set(STORE, {'old_name': N.PUBLIC, 'name': N.PUBLIC,
                                 'servers': '9.9.9.9\n1.1.1.1'}, 'tester')   # ...but changed
        self.assertEqual(got['servers'], ['9.9.9.9', '1.1.1.1'])
        self.assertTrue([s for s in N.sets(STORE) if s['name'] == N.PUBLIC][0].get('keep'))
        # gone anyway (from before 1.0.6): made again at the next start
        STORE.db.run("DELETE FROM dns_sets WHERE name = ?", (N.PUBLIC,))
        N.forget()
        N.ensure(STORE)
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM dns_sets WHERE name = ?",
                                        (N.PUBLIC,), 0), 1)
        self.assertEqual(N.dns_set_for('public', STORE), (N.PUBLIC, 'default'))
        N.assign(STORE, 'apis', N.PUBLIC, 'tester')
        self.assertEqual(N.dns_set_for('apis', STORE), (N.PUBLIC, 'assigned'))
        N.assign(STORE, 'apis', '', 'tester')
        N.assign(STORE, 'apis', '', 'tester')

    def test_crud_and_rename(self):
        add('Inside', SRV['pa'], note='the company resolvers')
        N.assign(STORE, 'validation', 'Inside', 'tester')
        got = N.save_set(STORE, {'old_name': 'Inside', 'name': 'Company DNS',
                                 'servers': '127.0.0.1:%d\n::1' % SRV['pa'],
                                 'protocol': 'tcp', 'timeout': 4}, 'tester')
        self.assertEqual(got['servers'], ['127.0.0.1:%d' % SRV['pa'], '::1'])
        self.assertEqual(got['protocol'], 'tcp')
        self.assertEqual(N.dns_set_for('validation', STORE), ('Company DNS', 'assigned'))
        with self.assertRaises(ValueError):     # a name taken
            add('Company DNS', SRV['pb'])
        N.delete_set(STORE, 'Company DNS', 'tester')
        self.assertEqual(N.dns_set_for('validation', STORE), (N.SYSTEM, 'default'))

    def test_safe_names_and_servers(self):
        for bad in ('', 'x;rm -rf', '(evil)', '-lead', 'a' * 121, N.SYSTEM):
            with self.assertRaises(ValueError, msg=bad):
                N.save_set(STORE, {'name': bad, 'servers': '192.0.2.1'}, 'tester')
        for bad in ('dns.example.com', '192.0.2.1:0', '192.0.2.1:70000', '', '999.1.1.1'):
            with self.assertRaises(ValueError, msg=bad):
                N.save_set(STORE, {'name': 'ok', 'servers': bad}, 'tester')
        with self.assertRaises(ValueError):
            N.save_set(STORE, {'name': 'ok', 'servers': '192.0.2.1', 'protocol': 'quic'}, 'x')
        got = N.save_set(STORE, {'name': 'DoT here', 'servers': '1.1.1.1\n[2606:4700::1111]:853',
                                 'protocol': 'dot', 'tls_name': 'cloudflare-dns.com'}, 'x')
        self.assertEqual(got['servers'], ['1.1.1.1', '2606:4700::1111'])

    def test_system_is_built_in(self):
        with self.assertRaises(ValueError):
            N.delete_set(STORE, N.SYSTEM, 'tester')
        with self.assertRaises(ValueError):
            N.save_set(STORE, {'old_name': N.SYSTEM, 'name': 'Mine', 'servers': '192.0.2.1'}, 'x')
        r = N.resolver_of(N.SYSTEM, STORE)
        self.assertTrue(r.system)
        self.assertEqual(list(r), D.system_resolvers())


class Assignments(unittest.TestCase):
    def setUp(self):
        clean()
        N.ensure(STORE)

    def test_defaults(self):
        for p in N.PURPOSE_KEYS:
            want = N.PUBLIC if p == 'public' else N.SYSTEM
            self.assertEqual(N.dns_set_for(p, STORE), (want, 'default'), p)
        self.assertEqual(list(N.resolver('public', STORE)), list(N.PUBLIC_SERVERS))
        STORE.db.run("DELETE FROM dns_sets WHERE name = ?", (N.PUBLIC,))   # gone (before 1.0.6)
        N.forget()                              # Public gone: the public resolvers still
        self.assertEqual(list(N.resolver('public', STORE)), list(N.PUBLIC_SERVERS))

    def test_chosen_legacy_and_fallback(self):
        add('Inside', SRV['pa'])
        E.CONFIG['acme_resolvers'] = '192.0.2.53, 192.0.2.54'
        self.assertEqual(N.dns_set_for('validation', STORE)[1], 'legacy')
        self.assertEqual(list(N.resolver('validation', STORE)), ['192.0.2.53', '192.0.2.54'])
        N.assign(STORE, 'validation', 'Inside', 'x')
        self.assertEqual(N.dns_set_for('validation', STORE), ('Inside', 'assigned'))
        N.assign(STORE, 'validation', N.SYSTEM, 'x')    # the system's, chosen, beats the old
        self.assertEqual(N.dns_set_for('validation', STORE), (N.SYSTEM, 'assigned'))
        N.assign(STORE, 'validation', '', 'x')
        self.assertEqual(N.dns_set_for('validation', STORE)[1], 'legacy')
        with self.assertRaises(LookupError):
            N.assign(STORE, 'validation', 'Nobody', 'x')
        with self.assertRaises(ValueError):
            N.assign(STORE, 'teleport', 'Inside', 'x')

    def test_a_module_field_is_an_override(self):
        add('Inside', SRV['pa'])
        N.assign(STORE, 'validation', 'Inside', 'x')
        ctx = runtime.RunContext(STORE, None, scope='challenge:t')
        self.assertEqual(D.resolver('validation', ['192.0.2.7'], ctx), ['192.0.2.7'])
        self.assertEqual(D.resolver('validation', [], ctx).name, 'Inside')
        # the modules' old default of "Public resolvers" counts as said nothing
        self.assertEqual(D.resolver('public', ['1.1.1.1', '8.8.8.8', '9.9.9.9'], ctx).name,
                         N.PUBLIC)

    def test_the_engine_follows(self):
        add('Inside', SRV['pa'])
        add('Plain', 0, servers='192.0.2.53\n192.0.2.54:5353')
        self.assertEqual(E.acme_resolvers(), [])
        N.assign(STORE, 'acme', 'Plain', 'x')
        self.assertEqual(E.acme_resolvers(), ['192.0.2.53'])        # port 53 only
        N.assign(STORE, 'mail', 'Plain', 'x')
        self.assertEqual(E.own_dns(), ['192.0.2.53'])
        N.assign(STORE, 'mail', N.SYSTEM, 'x')
        E.CONFIG['mail_dns'] = '192.0.2.99'
        self.assertEqual(E.own_dns(), [])                            # chosen: the system's
        N.assign(STORE, 'mail', '', 'x')
        self.assertEqual(E.own_dns(), ['192.0.2.99'])                # as before
        self.assertEqual(N.where_used(STORE).get('Plain'), ['The appliance\'s own ACME'])


class Lookups(unittest.TestCase):
    def setUp(self):
        clean()
        add('Inside', SRV['pa'])
        add('Other', SRV['pb'])

    def test_each_set_asks_its_own_server(self):
        self.assertEqual(N.resolver_of('Inside', STORE).addresses('host.' + ZONE), ['192.0.2.80'])
        self.assertEqual(N.resolver_of('Other', STORE).addresses('host.' + ZONE), ['192.0.2.99'])
        tcp = N.save_set(STORE, {'name': 'Inside TCP', 'servers': '127.0.0.1:%d' % SRV['pa'],
                                 'protocol': 'tcp'}, 'x')
        self.assertEqual(tcp['protocol'], 'tcp')
        r = N.resolver_of('Inside TCP', STORE)
        self.assertEqual(r.addresses('host.' + ZONE), ['192.0.2.80'])
        # what a validation asks goes through the set chosen for it
        N.assign(STORE, 'validation', 'Inside', 'x')
        m = D.ask_any(D.resolver('validation'), '_acme-challenge.www.' + ZONE, 16)
        self.assertEqual([x.text for x in m.answer], ['inside'])

    def test_test_says_who_answered(self):
        got = N.test(STORE, {'name': 'Inside', 'qname': 'host.' + ZONE, 'qtype': 'A'})
        self.assertTrue(got['ok'])
        self.assertEqual(got['answered_by'], '127.0.0.1:%d' % SRV['pa'])
        self.assertEqual([a['value'] for a in got['answers']], ['192.0.2.80'])
        self.assertGreaterEqual(got['tries'][0]['ms'], 0)
        dead = N.test(STORE, {'name': 'draft', 'servers': '127.0.0.1:%d\n127.0.0.1:%d' % (
            free_port(), SRV['pb']), 'timeout': 0.5, 'qname': 'host.' + ZONE, 'qtype': 'A'})
        self.assertFalse(dead['tries'][0]['ok'])
        self.assertEqual(dead['answered_by'], '127.0.0.1:%d' % SRV['pb'])
        with self.assertRaises(ValueError):
            N.test(STORE, {'name': 'Inside', 'qname': 'x y', 'qtype': 'A'})

    def test_http_by_a_name_only_the_set_knows(self):
        port = SRV['http'].server_address[1]
        ctx = runtime.RunContext(STORE, None, scope='issuer:t')
        N.assign(STORE, 'apis', 'Inside', 'x')
        status, _h, body = ctx.http('GET', 'http://%s:%d/' % (INSIDE, port), proxy=False)
        self.assertEqual((status, body), (200, b'hello from inside'))
        N.assign(STORE, 'apis', 'Other', 'x')
        with self.assertRaises(PluginError) as e:
            ctx.http('GET', 'http://%s:%d/' % (INSIDE, port), proxy=False, timeout=5)
        self.assertIn('not known to the DNS set', str(e.exception))
        # a target's context asks the set of Targets
        N.assign(STORE, 'targets', 'Inside', 'x')
        tctx = runtime.RunContext(STORE, None, scope='target:t')
        self.assertEqual(tctx.http('GET', 'http://%s:%d/' % (INSIDE, port), proxy=False)[0], 200)
        self.assertEqual(N.ssh_address(tctx, INSIDE), '127.0.0.1')
        # outside a scope nothing is redirected
        self.assertIsNone(getattr(N._SCOPE, 'r', None))
        self.assertEqual(socket.getaddrinfo('127.0.0.1', 80)[0][4][0], '127.0.0.1')


class Carried(unittest.TestCase):
    def setUp(self):
        clean()
        add('Inside', SRV['pa'], note='carried')
        N.assign(STORE, 'targets', 'Inside', 'x')

    def test_backup_and_export_carry_the_sets(self):
        path = os.path.join(TMP, 'copy.json.gz')
        with open(path, 'wb') as f:
            E.dump_tables(STORE.db, f)
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            text = f.read()
        self.assertIn('dns_sets', text)
        self.assertIn('127.0.0.1:%d' % SRV['pa'], text)
        self.assertIn('dns_set_uses', text)
        out = E.carry_export(STORE, True)
        self.assertEqual([r['name'] for r in out.get('dns_sets', [])], ['Inside'])
        self.assertEqual([(r['purpose'], r['set_name']) for r in out.get('dns_set_uses', [])],
                         [('targets', 'Inside')])


class FakeH(object):
    def __init__(self, role, body=None):
        self.store, self.role, self._body = STORE, role, body or {}

    def me(self, _role):
        return {'name': 'someone', 'role': self.role}

    def body(self):
        return self._body


class Routes(unittest.TestCase):
    def setUp(self):
        clean()

    def call(self, method, path, role, body=None):
        return E.ROUTES[(method, path)](FakeH(role, body))

    def test_roles(self):
        got = self.call('GET', '/api/dnssets', 'readonly')
        self.assertEqual(got['sets'][0]['name'], N.SYSTEM)
        self.assertEqual({p['key'] for p in got['purposes']}, set(N.PURPOSE_KEYS))
        self.assertFalse(got['can_change'])
        body = {'name': 'Inside', 'servers': '127.0.0.1:%d' % SRV['pa']}
        for path, b in (('/api/dnssets/save', body), ('/api/dnssets/delete', {'name': 'x'}),
                        ('/api/dnssets/assign', {'purpose': 'apis', 'set': N.SYSTEM})):
            with self.assertRaises(E.ApiError) as e:
                self.call('POST', path, 'readonly', b)
            self.assertEqual(e.exception.status if hasattr(e.exception, 'status')
                             else e.exception.args[0], 403)
        self.call('POST', '/api/dnssets/save', 'fulladmin', body)
        self.call('POST', '/api/dnssets/assign', 'fulladmin', {'purpose': 'apis', 'set': 'Inside'})
        got = self.call('POST', '/api/dnssets/test', 'readonly',
                        {'name': 'Inside', 'qname': 'host.' + ZONE, 'qtype': 'A'})
        self.assertTrue(got['test']['ok'])
        with self.assertRaises(E.ApiError):     # a set not saved: a full administrator's
            self.call('POST', '/api/dnssets/test', 'readonly', dict(body, qname='host.' + ZONE))
        self.assertEqual(self.call('GET', '/api/dnssets', 'readonly')['used']['Inside'],
                         ['CAs and APIs'])

    def test_events_say_it(self):
        add('Inside', SRV['pa'])
        ev = json.dumps(STORE.db.rows('SELECT * FROM events ORDER BY id DESC LIMIT 5'))
        self.assertIn('the DNS set Inside was added by tester', ev)


if __name__ == '__main__':
    unittest.main(verbosity=2)
