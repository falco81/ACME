#!/usr/bin/env python3
"""acme's own DNS server and the challenge modules, checked.

    python3 test/test_challenges.py         (or: python3 -m unittest test.test_challenges)

No root, no internet: the DNS server runs on a high port of 127.0.0.1 with an
in-memory SQLite table for its records; every module is handed a Context of
this file's own (HTTP answered by fakes, SSH by a fake session). Where BIND is
installed (named, nsupdate), RFC 2136 updates and TSIG are tried against the
real thing - every algorithm - and an update nsupdate signed is verified here.
"""
import base64
import json
import os
import random
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from acmelib.certs.dnsserver import DnsServer, parse_static  # noqa: E402
from acmelib.plugins.base import Context, PluginError, Registry, SshSession  # noqa: E402
from acmelib.plugins.challenges import _dns as D  # noqa: E402
from acmelib.plugins.challenges.route53 import canonical_request, signing_key, sigv4  # noqa: E402

import hashlib  # noqa: E402

REG = Registry(extra_dirs=[]).reload()


def plugin(kind):
    return REG.get('challenge', kind)


# ---------------------------------------------------------------------------
# Stand-ins
# ---------------------------------------------------------------------------
class MemDb(object):
    """store.db as the engine's: rows() and run(), on an in-memory SQLite."""
    def __init__(self):
        self.c = sqlite3.connect(':memory:', check_same_thread=False)
        self.c.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.fail = False
        self.c.execute('CREATE TABLE dns_records (id INTEGER PRIMARY KEY, name TEXT NOT NULL, '
                       'rtype TEXT NOT NULL, value TEXT, ttl INTEGER, expires REAL, created REAL, '
                       'owner TEXT, note TEXT)')

    def rows(self, sql, args=()):
        if self.fail:
            raise RuntimeError('the database is away')
        with self.lock:
            return [dict(r) for r in self.c.execute(sql, args)]

    def run(self, sql, args=()):
        with self.lock:
            return self.c.execute(sql, args).rowcount


class MemStore(object):
    def __init__(self):
        self.db = MemDb()

    def put(self, name, rtype, value, ttl=60, expires=0):
        self.db.run('INSERT INTO dns_records (name, rtype, value, ttl, expires, created) '
                    'VALUES (?, ?, ?, ?, ?, ?)', (name, rtype, value, ttl, expires, time.time()))

    def drop(self, name, rtype, value):
        self.db.run('DELETE FROM dns_records WHERE name = ? AND rtype = ? AND value = ?',
                    (D.norm(name), rtype, value))


class FakeSsh(SshSession):
    def __init__(self, world, conn):
        self.world, self.conn, self.host = world, conn, conn['host']
        if self.host in world.down:
            raise OSError('connection refused by %s' % self.host)
        if world.pinned and conn.get('hostkey', '') == '' and not conn.get('trust_first'):
            raise PluginError('no host key pinned for %s' % self.host)
        world.conns.append(dict(conn))

    def files(self):
        return self.world.files.setdefault(self.host, {})

    def run(self, command, input=None, timeout=120, check=True):
        self.world.commands.append((self.host, command, input))
        rc, out = 0, b''
        if command.startswith('cat '):
            out = self.files().get(command[4:].strip("'"), b'')
        elif 'install -m' in command:
            bits = command.split('install -m ', 1)[1].split(';')[0].split()
            src, dst = bits[1].strip("'"), bits[2].strip("'")
            self.files()[dst] = self.files().pop(src)
        elif 'rm -f ' in command:
            self.files().pop(command.split('rm -f ', 1)[1].strip("'"), None)
        elif command in self.world.fail_commands:
            rc = 1
        if rc and check:
            raise PluginError('%s: exit %d' % (command, rc))
        return rc, out, b''

    def put(self, data, remote_path, mode=0o600, owner=None):
        if self.host in self.world.readonly:
            raise PluginError('%s: permission denied' % remote_path)
        self.files()[remote_path] = bytes(data)
        self.world.modes[(self.host, remote_path)] = mode

    def get(self, remote_path):
        return self.files()[remote_path]


class SshWorld(object):
    def __init__(self):
        self.files, self.modes, self.commands, self.conns = {}, {}, [], []
        self.down, self.readonly, self.fail_commands = set(), set(), set()
        self.pinned = False


class FakeCtx(Context):
    """The Context of acmelib/plugins/base.py, made of fakes."""
    def __init__(self, store=None, settings=None, http=None, ssh=None):
        self.store = store
        self.settings = dict(settings or {})
        self.steps, self.debugs, self.tokens, self.kv = [], [], {}, {}
        self.http_handler = http
        self.http_calls = []
        self.ssh_world = ssh or SshWorld()
        self.node = 'test'

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def debug(self, words):
        self.debugs.append(words)

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        self.http_calls.append((method, url, body, dict(headers or {})))
        return self.http_handler(method, url, body, dict(headers or {}))

    def ssh(self, conn):
        return FakeSsh(self.ssh_world, conn)

    def openssl(self, args, data=None, timeout=60):
        return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                              timeout=timeout, check=True).stdout

    def kv_get(self, key):
        return self.kv.get(key)

    def kv_set(self, key, value, ttl_s=None):
        self.kv[key] = value

    def dns_put(self, name, type, value, ttl=60):
        self.store.put(D.norm(name), type, value, ttl)

    def dns_drop(self, name, type, value):
        self.store.drop(name, type, value)

    def http_token_put(self, token, key_authorization):
        self.tokens[token] = key_authorization

    def http_token_drop(self, token):
        self.tokens.pop(token, None)


def free_port():
    """A port free for both UDP and TCP on 127.0.0.1."""
    for _ in range(50):
        p = random.randint(20000, 60000)
        u, t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socket()
        try:
            u.bind(('127.0.0.1', p))
            t.bind(('127.0.0.1', p))
            return p
        except OSError:
            continue
        finally:
            u.close()
            t.close()
    raise RuntimeError('no free port')


def raw_query(name_bytes, qtype=16, ident=0x1234, flags=0x0100, edns=None):
    q = struct.pack('>HHHHHH', ident, flags, 1, 0, 0, 1 if edns is not None else 0)
    for lab in name_bytes.split(b'.'):
        q += bytes([len(lab)]) + lab
    q += b'\x00' + struct.pack('>HH', qtype, 1)
    if edns is not None:
        size, version = edns
        q += b'\x00' + struct.pack('>HHIH', 41, size, version << 16, 0)
    return q


def udp(port, data, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(data, ('127.0.0.1', port))
        return s.recvfrom(65535)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


ZONE = 'acme.example.net'
STATIC = '\n'.join([
    '@ CAA 0 issue "letsencrypt.org"',
    'alias CNAME www.example.com.acme.example.net.',
    'away CNAME somewhere.example.org.',
    'host 300 A 192.0.2.80',
    'host AAAA 2001:db8::80 120',
    '; a comment',
    '_acme-challenge.www.example.com. CNAME www.example.com.acme.example.net.',
    '_acme-challenge.example.com. CNAME example.com.acme.example.net.',
    'example.com. NS ns1.acme.example.net.',
])


def server_config(port, **more):
    cfg = {'dns_listen': '127.0.0.1', 'dns_port': port, 'dns_zone': ZONE + ',example.com',
           'dns_ns_names': 'ns1.acme.example.net,ns2.acme.example.net',
           'dns_ns_addresses': '127.0.0.1,127.0.0.2', 'dns_soa_mail': 'hostmaster@example.net',
           'dns_ttl': 60, 'dns_static': STATIC, 'dns_rate': 0, 'dns_cache': 1.0}
    cfg.update(more)
    return cfg


# ---------------------------------------------------------------------------
# The wire format
# ---------------------------------------------------------------------------
class TestWire(unittest.TestCase):
    def test_names_and_compression(self):
        m = D.Message(7, 0x8400)
        m.question.append(('www.example.com', 16, 1))
        m.answer.append(D.RR('www.example.com', 'TXT', 1, 60, 'hello'))
        m.answer.append(D.RR('www.example.com', 'CNAME', 1, 60, 'a.example.com'))
        m.authority.append(D.RR('example.com', 'SOA', 1, 60,
                                'ns1.example.com hostmaster.example.com 5 3600 600 86400 60'))
        w = m.to_wire()
        self.assertLess(len(w), len(D.Message.to_wire(m, compress=False)))
        p = D.parse(w)
        self.assertEqual(p.texts('TXT'), ['hello'])
        self.assertEqual(p.texts('CNAME'), ['a.example.com'])
        self.assertEqual(p.authority[0].text.split()[:3],
                         ['ns1.example.com', 'hostmaster.example.com', '5'])

    def test_rdata_round_trip(self):
        for t, v in [('A', '192.0.2.1'), ('AAAA', '2001:db8::1'), ('MX', '10 mail.example.com'),
                     ('CAA', '0 issue "letsencrypt.org"'), ('SRV', '1 2 443 svc.example.com'),
                     ('TXT', 'x' * 600)]:
            m = D.Message(1, 0x8000)
            m.answer.append(D.RR('a.example', t, 1, 1, v))
            self.assertEqual(D.parse(m.to_wire()).answer[0].text, v, t)
        self.assertEqual(len(D.txt_strings('x' * 600)), 3)
        self.assertEqual(D.txt_strings('"a b" "c\\"d"'), [b'a b', b'c"d'])

    def test_escaped_and_idn_names(self):
        w = D.name_to_wire('host\\.master.example.net')
        self.assertEqual(w[0], 11)
        self.assertEqual(D.read_name(w, 0)[0], 'host\\.master.example.net')
        self.assertEqual(D.name_labels('bücher.example')[0], b'xn--bcher-kva')

    def test_pointer_loops_are_refused(self):
        hdr = struct.pack('>HHHHHH', 1, 0, 1, 0, 0, 0)
        for body in (b'\xc0\x0c\x00\x01\x00\x01',          # points at itself
                     b'\x01a\xc0\x0e\x00\x01\x00\x01',      # points forward
                     b'\x3fabc', b'\x80abc', b'\x05ab'):
            with self.assertRaises(D.FormErr):
                D.parse(hdr + body)
        with self.assertRaises(D.FormErr):
            D.parse(hdr + (b'\x3f' + b'a' * 63) * 5 + b'\x00\x00\x01\x00\x01')

    def test_fuzz_parser(self):
        rnd = random.Random(2136)
        good = D.make_query('www.example.com', 'TXT').to_wire()
        m = D.Message(1, 0x8400)
        m.question.append(('a.example', 1, 1))
        m.answer.append(D.RR('a.example', 'A', 1, 60, '192.0.2.1'))
        m.authority.append(D.RR('example', 'SOA', 1, 60, 'ns.example h.example 1 2 3 4 5'))
        samples = [good, m.to_wire()]
        for i in range(20000):
            if i % 3 == 0:
                data = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 80)))
            else:
                data = bytearray(rnd.choice(samples))
                for _ in range(rnd.randint(1, 6)):
                    data[rnd.randrange(len(data))] = rnd.getrandbits(8)
                if rnd.random() < 0.3:
                    data = data[:rnd.randrange(len(data))]
                data = bytes(data)
            try:
                D.parse(data)
            except D.FormErr:
                pass

    def test_static_lines(self):
        self.assertEqual(parse_static('www A 192.0.2.1 300'), ('www', 'A', '192.0.2.1', 300))
        self.assertEqual(parse_static('www 300 TXT "a b"'), ('www', 'TXT', '"a b"', 300))
        self.assertEqual(parse_static('@ MX 10 mail'), ('@', 'MX', '10 mail', None))
        with self.assertRaises(ValueError):
            parse_static('www BOGUS 1')


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------
class TestDnsServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = MemStore()
        cls.port = free_port()
        cls.cfg = server_config(cls.port)
        cls.srv = DnsServer(cls.store, cls.cfg)
        st = cls.srv.start()
        assert st['ok'], st

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def ask(self, name, qtype, tcp=False, edns=1232, rd=False):
        return D.query('127.0.0.1', name, qtype, port=self.port, tcp=tcp, edns=edns, rd=rd)

    def fresh(self):
        self.srv.records(force=True)

    def test_soa_and_flags(self):
        m = self.ask(ZONE, 'SOA')
        self.assertEqual(m.rcode, D.NOERROR)
        self.assertTrue(m.aa and m.qr and not m.ra)
        soa = m.texts('SOA')[0].split()
        self.assertEqual(soa[0], 'ns1.acme.example.net')
        self.assertEqual(soa[1], 'hostmaster.example.net')

    def test_ns_with_glue(self):
        m = self.ask(ZONE, 'NS')
        self.assertEqual(sorted(m.texts('NS')), ['ns1.acme.example.net', 'ns2.acme.example.net'])
        glue = {(r.name, r.text) for r in m.additional if r.rtype == 1}
        self.assertEqual(glue, {('ns1.acme.example.net', '127.0.0.1'),
                                ('ns2.acme.example.net', '127.0.0.2')})
        self.assertEqual(self.ask('ns2.acme.example.net', 'A').texts('A'), ['127.0.0.2'])

    def test_txt_several_values(self):
        self.store.put('two.example.com.acme.example.net', 'TXT', 'value-one')
        self.store.put('two.example.com.acme.example.net', 'TXT', 'value-two')
        self.fresh()
        m = self.ask('two.example.com.acme.example.net', 'TXT')
        self.assertEqual(sorted(m.texts('TXT')), ['value-one', 'value-two'])

    def test_cname_followed_inside(self):
        self.store.put('www.example.com.acme.example.net', 'TXT', 'chased')
        self.fresh()
        m = self.ask('_acme-challenge.www.example.com', 'TXT')       # a zone of its own too
        self.assertEqual(m.texts('CNAME'), ['www.example.com.acme.example.net'])
        self.assertIn('chased', m.texts('TXT'))
        m = self.ask('alias.' + ZONE, 'TXT')
        self.assertIn('chased', m.texts('TXT'))
        m = self.ask('away.' + ZONE, 'TXT')
        self.assertEqual(m.rcode, D.NOERROR)
        self.assertEqual(m.texts('CNAME'), ['somewhere.example.org'])
        self.assertEqual(len(m.answer), 1)
        self.assertEqual(self.ask('alias.' + ZONE, 'CNAME').texts('CNAME'),
                         ['www.example.com.acme.example.net'])

    def test_nxdomain_nodata(self):
        m = self.ask('nothing.' + ZONE, 'TXT')
        self.assertEqual(m.rcode, D.NXDOMAIN)
        self.assertTrue(m.aa)
        self.assertEqual(m.authority[0].rtype, 6)
        self.assertEqual(D.norm(m.authority[0].name), ZONE)
        m = self.ask('host.' + ZONE, 'TXT')                         # there, but no TXT
        self.assertEqual((m.rcode, len(m.answer)), (D.NOERROR, 0))
        self.assertEqual(m.authority[0].rtype, 6)
        self.store.put('_x.deep.ent.' + ZONE, 'TXT', 'leaf')
        self.fresh()
        m = self.ask('ent.' + ZONE, 'A')                            # an empty non-terminal
        self.assertEqual((m.rcode, len(m.answer)), (D.NOERROR, 0))

    def test_a_aaaa_caa_ttl(self):
        m = self.ask('host.' + ZONE, 'A')
        self.assertEqual((m.texts('A'), m.answer[0].ttl), (['192.0.2.80'], 300))
        m = self.ask('host.' + ZONE, 'AAAA')
        self.assertEqual((m.texts('AAAA'), m.answer[0].ttl), (['2001:db8::80'], 120))
        self.assertEqual(self.ask(ZONE, 'CAA').texts('CAA'), ['0 issue "letsencrypt.org"'])
        m = self.ask('host.' + ZONE, 'ANY')
        self.assertEqual({r.rtype for r in m.answer}, {1, 28})

    def test_refused(self):
        m = self.ask('www.google.com', 'A')
        self.assertEqual(m.rcode, D.REFUSED)
        self.assertFalse(m.aa)
        self.assertEqual(self.ask('example.net', 'SOA').rcode, D.REFUSED)
        self.assertEqual(self.ask(ZONE, 'AXFR', tcp=True).rcode, D.REFUSED)
        upd = D.make_update(ZONE, add=[('x.' + ZONE, 'TXT', 60, 'no')])
        self.assertEqual(D.parse(udp(self.port, upd.to_wire())).rcode, D.REFUSED)
        notify = bytearray(raw_query(ZONE.encode(), 6))
        notify[2] = (4 << 3)
        self.assertEqual(D.parse(udp(self.port, bytes(notify))).rcode, D.NOTIMP)

    def test_tcp(self):
        self.store.put('tcp.' + ZONE, 'TXT', 'over-tcp')
        self.fresh()
        self.assertEqual(self.ask('tcp.' + ZONE, 'TXT', tcp=True).texts('TXT'), ['over-tcp'])
        # two questions on one connection
        s = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        try:
            for i in range(2):
                q = raw_query(b'tcp.acme.example.net', 16, ident=100 + i)
                s.sendall(struct.pack('>H', len(q)) + q)
                n = struct.unpack('>H', D._recv_exact(s, 2))[0]
                a = D.parse(D._recv_exact(s, n))
                self.assertEqual((a.id, a.texts('TXT')), (100 + i, ['over-tcp']))
        finally:
            s.close()

    def test_edns(self):
        m = self.ask(ZONE, 'SOA', edns=4096)
        self.assertIsNotNone(m.opt)
        self.assertEqual(m.opt.rclass, 1232)
        m = self.ask(ZONE, 'SOA', edns=0)
        self.assertIsNone(m.opt)
        got = D.parse(udp(self.port, raw_query(ZONE.encode(), 6, edns=(1232, 1))))
        self.assertEqual(got.rcode, D.BADVERS)
        self.assertIsNotNone(got.opt)
        two = raw_query(ZONE.encode(), 6, edns=(1232, 0))
        two = two[:10] + struct.pack('>H', 2) + two[12:] + two[-11:]
        self.assertEqual(D.parse(udp(self.port, two)).rcode, D.FORMERR)

    def test_truncation(self):
        for i in range(30):
            self.store.put('big.' + ZONE, 'TXT', ('%02d' % i) + 'y' * 200)
        self.fresh()
        a = D.parse(udp(self.port, raw_query(b'big.acme.example.net', 16)))
        self.assertTrue(a.tc)
        self.assertEqual(len(a.answer), 0)
        a = D.parse(udp(self.port, raw_query(b'big.acme.example.net', 16, edns=(4096, 0))))
        self.assertTrue(a.tc)                       # 1232 at most, whatever is asked
        m = self.ask('big.' + ZONE, 'TXT')           # query() goes on over TCP by itself
        self.assertFalse(m.tc)
        self.assertEqual(len(m.texts('TXT')), 30)

    def test_0x20_case_kept(self):
        self.store.put('case.' + ZONE, 'TXT', 'cased')
        self.fresh()
        qname = b'CaSe.AcMe.ExAmPlE.NeT'
        q = raw_query(qname, 16)
        a = udp(self.port, q)
        self.assertEqual(a[12:12 + len(q) - 12], q[12:])
        p = D.parse(a)
        self.assertEqual(p.answer[0].name, 'CaSe.AcMe.ExAmPlE.NeT')
        self.assertEqual(p.texts('TXT'), ['cased'])

    def test_expired_ignored_and_tidied(self):
        now = time.time()
        self.store.put('old.' + ZONE, 'TXT', 'long-gone', expires=now - 7200)
        self.store.put('old.' + ZONE, 'TXT', 'just-gone', expires=now - 5)
        self.store.put('old.' + ZONE, 'TXT', 'still-here', expires=now + 3600)
        self.fresh()
        self.assertEqual(self.ask('old.' + ZONE, 'TXT').texts('TXT'), ['still-here'])
        self.srv.tidy()
        left = [r['value'] for r in self.store.db.rows(
            "SELECT value FROM dns_records WHERE name = 'old.acme.example.net'")]
        self.assertEqual(sorted(left), ['just-gone', 'still-here'])

    def test_short_cache(self):
        self.srv.records()
        self.store.put('late.' + ZONE, 'TXT', 'arrived')
        deadline = time.time() + 3
        seen = False
        while time.time() < deadline and not seen:
            seen = self.ask('late.' + ZONE, 'TXT').texts('TXT') == ['arrived']
            time.sleep(0.2)
        self.assertTrue(seen, 'a new record is answered within about a second')

    def test_garbage_never_kills_it(self):
        rnd = random.Random(53)
        good = raw_query(b'host.acme.example.net', 1, edns=(1232, 0))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(3000):
            if i % 2:
                data = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 120)))
            else:
                data = bytearray(good)
                for _ in range(rnd.randint(1, 5)):
                    data[rnd.randrange(len(data))] = rnd.getrandbits(8)
                data = bytes(data[:rnd.randint(0, len(data))])
            # straight into the answering code too: it never raises
            out = self.srv.answer(data, '198.51.100.1')
            self.assertTrue(out is None or isinstance(out, bytes))
            if i % 10 == 0:
                s.sendto(data, ('127.0.0.1', self.port))
        s.close()
        for _ in range(20):                         # TCP: lengths that lie, bytes that are nothing
            t = socket.create_connection(('127.0.0.1', self.port), timeout=2)
            t.sendall(struct.pack('>H', rnd.randint(0, 65535)) +
                      bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 50))))
            t.close()
        self.assertEqual(self.ask('host.' + ZONE, 'A').texts('A'), ['192.0.2.80'])
        # an answer is never answered; a header alone gets FORMERR at most
        self.assertIsNone(self.srv.answer(b'\x12\x34\x80' + b'\x00' * 9))
        self.assertIsNone(self.srv.answer(b'\x12\x34'))
        self.assertEqual(D.parse(self.srv.answer(b'\x12\x34\x01\x00' + b'\x00\x05' +
                                                 b'\x00' * 6)).rcode, D.FORMERR)

    def test_state(self):
        st = self.srv.state()
        self.assertTrue(st['running'] and st['ok'])
        self.assertIn('127.0.0.1:%d/udp' % self.port, st['listening'])
        self.assertIn('127.0.0.1:%d/tcp' % self.port, st['listening'])
        self.assertGreater(st['queries'], 0)
        self.assertIn(ZONE, st['zones'])

    def test_database_away(self):
        self.store.db.fail = True
        try:
            m = self.ask('host.' + ZONE, 'A')       # within a minute: what was read last
            self.assertEqual(m.texts('A'), ['192.0.2.80'])
            self.srv.load_ok_at -= 120
            self.fresh()
            self.assertEqual(self.ask('host.' + ZONE, 'A').rcode, D.SERVFAIL)
            self.assertEqual(self.ask(ZONE, 'SOA').rcode, D.NOERROR)
            self.assertIn('could not be read', self.srv.state()['records_error'])
        finally:
            self.store.db.fail = False
            self.fresh()

    def test_dig_agrees(self):
        if not shutil.which('dig'):
            self.skipTest('dig is not installed')
        out = subprocess.run(['dig', '+norec', '+tries=1', '+time=2', '-p', str(self.port),
                              '@127.0.0.1', 'SOA', ZONE], capture_output=True, text=True).stdout
        self.assertIn('status: NOERROR', out)
        self.assertIn('flags: qr aa', out)
        out = subprocess.run(['dig', '+tcp', '+tries=1', '-p', str(self.port), '@127.0.0.1',
                              'NS', ZONE], capture_output=True, text=True).stdout
        self.assertIn('ns2.acme.example.net.', out)


class TestDnsServerMore(unittest.TestCase):
    def test_rate_limit(self):
        store = MemStore()
        port = free_port()
        srv = DnsServer(store, server_config(port, dns_rate=5))
        srv.start()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.3)
            got = []
            for i in range(60):
                s.sendto(raw_query(b'host.acme.example.net', 1, ident=i), ('127.0.0.1', port))
            try:
                while True:
                    got.append(D.parse(s.recvfrom(65535)[0]))
            except socket.timeout:
                pass
            s.close()
            full = [m for m in got if not m.tc]
            slipped = [m for m in got if m.tc]
            self.assertLessEqual(len(full), 12)
            self.assertGreater(len(slipped), 0)       # some go back cut short: ask over TCP
            self.assertLess(len(got), 60)
            self.assertGreater(srv.state()['stats']['rate_limited'], 0)
            m = D.query('127.0.0.1', 'host.' + ZONE, 1, port=port, tcp=True)
            self.assertEqual(m.texts('A'), ['192.0.2.80'])     # TCP is not limited
        finally:
            srv.stop()

    def test_bind_failure_said(self):
        srv = DnsServer(MemStore(), server_config(free_port(), dns_listen='192.0.2.254'))
        st = srv.start()
        try:
            self.assertFalse(st['ok'])
            self.assertEqual(st['listening'], [])
            self.assertIn('not an address of this machine', st['failed'][0]['error'])
            self.assertIn('not an address', st['last_error'])
        finally:
            srv.stop()
        import errno
        words = DnsServer._bind_words(OSError(errno.EACCES, 'Permission denied'), '0.0.0.0', 53,
                                      'udp')
        self.assertIn('CAP_NET_BIND_SERVICE', words)
        words = DnsServer._bind_words(OSError(errno.EADDRINUSE, 'in use'), '0.0.0.0', 53, 'udp')
        self.assertIn('already taken', words)

    def test_reload_and_two_nodes(self):
        store = MemStore()
        p1, p2 = free_port(), free_port()
        cfg1 = server_config(p1)
        a, b = DnsServer(store, cfg1), DnsServer(store, server_config(p2))
        a.start()
        b.start()
        try:
            store.put('shared.' + ZONE, 'TXT', 'both-nodes')
            time.sleep(1.2)
            for p in (p1, p2):
                self.assertEqual(D.query('127.0.0.1', 'shared.' + ZONE, 16, port=p).texts('TXT'),
                                 ['both-nodes'])
            self.assertEqual(a.state()['serial'], b.state()['serial'])
            cfg1['dns_zone'] = 'other.example.org'
            a.reload()
            self.assertEqual(D.query('127.0.0.1', 'other.example.org', 6, port=p1).rcode,
                             D.NOERROR)
            self.assertEqual(D.query('127.0.0.1', ZONE, 6, port=p1).rcode, D.REFUSED)
            p3 = free_port()
            cfg1['dns_port'] = p3
            a.reload()
            self.assertEqual(D.query('127.0.0.1', 'other.example.org', 6, port=p3).rcode,
                             D.NOERROR)
        finally:
            a.stop()
            b.stop()


# ---------------------------------------------------------------------------
# TSIG and RFC 2136
# ---------------------------------------------------------------------------
SECRET = base64.b64encode(b'0123456789abcdef0123456789abcdef').decode()


class TestTsig(unittest.TestCase):
    def test_sign_verify(self):
        for alg in D.TSIG_ALGS:
            m = D.make_update('example.com', add=[('x.example.com', 'TXT', 60, 'v')])
            wire, mac = D.tsig_sign(m.to_wire(), 'acme-key', SECRET, alg)
            t = D.tsig_verify(wire, 'acme-key', SECRET)
            self.assertEqual(t['mac'], mac)
            bad = bytearray(wire)
            bad[20] ^= 1
            with self.assertRaises(ValueError):
                D.tsig_verify(bytes(bad), 'acme-key', SECRET)
            with self.assertRaises(ValueError):
                D.tsig_verify(wire, 'acme-key', base64.b64encode(b'other').decode())
        wire, _ = D.tsig_sign(m.to_wire(), 'k', SECRET, time_signed=1000)
        with self.assertRaises(ValueError):
            D.tsig_verify(wire, 'k', SECRET)        # BADTIME

    def test_known_vector(self):
        """A fixed message, key and time: the MAC by RFC 8945 written out by hand."""
        import hmac as H
        m = D.make_update('example.com', add=[('x.example.com', 'TXT', 60, 'v')], ident=0x4242)
        body = m.to_wire()
        wire, mac = D.tsig_sign(body, 'Acme-Key.', SECRET, 'hmac-sha256', time_signed=1700000000)
        tsig_vars = (b'\x08acme-key\x00' + b'\x00\xff' + b'\x00\x00\x00\x00' +
                     b'\x0bhmac-sha256\x00' + b'\x00\x00' + struct.pack('>I', 1700000000) +
                     b'\x01\x2c' + b'\x00\x00' + b'\x00\x00')
        want = H.new(base64.b64decode(SECRET), body + tsig_vars, hashlib.sha256).digest()
        self.assertEqual(mac, want)
        self.assertEqual(struct.unpack('>H', wire[10:12])[0], 1)
        self.assertTrue(wire.endswith(struct.pack('>H', 32) + want + b'\x42\x42\x00\x00\x00\x00'))

    def test_update_message(self):
        m = D.make_update('example.com', add=[('a.example.com', 'TXT', 60, 'add')],
                          delete=[('a.example.com', 'TXT', 'gone'), ('b.example.com', 'TXT', None)])
        p = D.parse(m.to_wire())
        self.assertEqual(p.opcode, D.OP_UPDATE)
        self.assertEqual(p.question, [('example.com', 6, 1)])
        self.assertEqual([(r.rclass, r.ttl, r.text) for r in p.authority],
                         [(D.CLASS_NONE, 0, 'gone'), (D.CLASS_ANY, 0, None), (1, 60, 'add')])

    def test_nsupdate_signature_verified_here(self):
        """What nsupdate (BIND's own signer) sends checks out with tsig_verify."""
        if not shutil.which('nsupdate'):
            self.skipTest('nsupdate is not installed')
        for alg in ('hmac-sha256', 'hmac-sha512', 'hmac-sha1', 'hmac-md5'):
            got = []
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('127.0.0.1', 0))
            s.settimeout(5)
            port = s.getsockname()[1]
            p = subprocess.Popen(['nsupdate', '-t', '3', '-u', '3', '-y',
                                  '%s:acme-key:%s' % (alg, SECRET)], stdin=subprocess.PIPE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p.stdin.write(('server 127.0.0.1 %d\nzone example.com\nupdate add x.example.com 60 '
                           'TXT "from-nsupdate"\nsend\n' % port).encode())
            p.stdin.close()
            try:
                data, _peer = s.recvfrom(65535)
                got.append(data)
            finally:
                p.kill()
                p.wait()
                s.close()
            t = D.tsig_verify(got[0], 'acme-key', SECRET)
            self.assertEqual(D.TSIG_ALGS[alg][0], t['alg'], alg)
            self.assertEqual(D.parse(got[0]).authority[0].text, 'from-nsupdate')


BIND_CONF = '''
%(keys)s
options { directory "%(dir)s"; listen-on port %(port)d { 127.0.0.1; }; listen-on-v6 { none; };
          pid-file "%(dir)s/named.pid"; recursion no; dnssec-validation no; notify no; };
zone "example.com" { type primary; file "%(dir)s/example.com.zone";
                     update-policy { %(grants)s }; };
'''
BIND_ZONE = '''$TTL 60
@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 600 86400 60
@ IN NS ns1.example.com.
ns1 IN A 127.0.0.1
_acme-challenge.alias IN CNAME _acme-challenge.target.example.com.
'''


class TestRfc2136Bind(unittest.TestCase):
    """The rfc2136 module against a real BIND, when there is one."""
    ALGS = ('hmac-sha256', 'hmac-sha512', 'hmac-sha1', 'hmac-md5')

    @classmethod
    def setUpClass(cls):
        if not shutil.which('named'):
            raise unittest.SkipTest('BIND (named) is not installed')
        cls.dir = tempfile.mkdtemp(prefix='acme-bind-')
        cls.port = free_port()
        cls.keys = {}
        keys, grants = '', ''
        for alg in cls.ALGS:
            name = 'key-' + alg
            secret = base64.b64encode(os.urandom(32)).decode()
            cls.keys[alg] = (name, secret)
            keys += 'key "%s" { algorithm %s; secret "%s"; };\n' % (name, alg, secret)
            grants += 'grant %s zonesub TXT; ' % name
        with open(os.path.join(cls.dir, 'named.conf'), 'w') as f:
            f.write(BIND_CONF % {'keys': keys, 'dir': cls.dir, 'port': cls.port, 'grants': grants})
        with open(os.path.join(cls.dir, 'example.com.zone'), 'w') as f:
            f.write(BIND_ZONE)
        args = ['named', '-g', '-c', os.path.join(cls.dir, 'named.conf')]
        if os.geteuid() == 0:
            args += ['-u', 'root']
        cls.log = open(os.path.join(cls.dir, 'log'), 'w')
        cls.named = subprocess.Popen(args, stdout=cls.log, stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                if D.query('127.0.0.1', 'example.com', 6, port=cls.port, rd=False,
                           timeout=0.5).rcode == 0:
                    return
            except (D.DnsError, OSError):
                time.sleep(0.2)
        cls.tearDownClass()
        with open(os.path.join(cls.dir, 'log')) as f:
            raise unittest.SkipTest('named did not start: %s' % f.read()[-500:])

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'named', None):
            cls.named.terminate()
            cls.named.wait(10)
            cls.log.close()
        shutil.rmtree(getattr(cls, 'dir', ''), ignore_errors=True)

    def module(self, alg, **more):
        name, secret = self.keys[alg]
        cfg = {'server': '127.0.0.1:%d' % self.port, 'tsig_name': name, 'tsig_alg': alg,
               'tsig_secret': secret, 'resolvers': ['127.0.0.1:%d' % self.port],
               'propagation': 'auth'}
        cfg.update(more)
        m = plugin('rfc2136')(cfg, FakeCtx())
        m.auth_port = self.port
        return m

    def txt(self, name):
        return D.txt_at('127.0.0.1', name, port=self.port)

    def test_every_algorithm(self):
        for alg in self.ALGS:
            m = self.module(alg, transport='udp' if alg == 'hmac-sha1' else 'tcp')
            h1 = m.present('www.example.com', 'tok', 'ka', 'value-' + alg[5:])
            h2 = m.present('*.www.example.com', 'tok', 'ka', 'wild-' + alg[5:])
            self.assertTrue(m.ready('www.example.com', h1), m.ctx.steps)
            self.assertEqual(sorted(self.txt('_acme-challenge.www.example.com')),
                             sorted(['value-' + alg[5:], 'wild-' + alg[5:]]))
            m.cleanup('www.example.com', h1)
            self.assertEqual(self.txt('_acme-challenge.www.example.com'), ['wild-' + alg[5:]])
            m.cleanup('*.www.example.com', h2)
            self.assertEqual(self.txt('_acme-challenge.www.example.com'), [])
            self.assertIn('takes updates for example.com', self.module(alg, zone='example.com').test())

    def test_zone_found_and_cname_followed(self):
        m = self.module('hmac-sha256')
        h = m.present('alias.example.com', 't', 'k', 'via-cname')
        self.assertEqual(h['fqdn'], '_acme-challenge.target.example.com')
        self.assertEqual(h['h'], {'zone': 'example.com'})
        self.assertTrue(m.ready('alias.example.com', h))
        m.cleanup('alias.example.com', h)

    def test_wrong_key_said(self):
        name, _s = self.keys['hmac-sha256']
        m = self.module('hmac-sha256', tsig_secret=base64.b64encode(b'wrong' * 6).decode())
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'never')
        self.assertIn('BADSIG', str(e.exception))
        m = self.module('hmac-sha256', tsig_name='', tsig_secret='')
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 't', 'k', 'never')
        self.assertIn('REFUSED', str(e.exception))

    def test_ready_waits(self):
        m = self.module('hmac-sha256', delay=30)
        h = m.present('slow.example.com', 't', 'k', 'slow')
        self.assertFalse(m.ready('slow.example.com', h))
        m.cleanup('slow.example.com', h)


# ---------------------------------------------------------------------------
# AWS Signature Version 4 (the vectors of AWS's documentation)
# ---------------------------------------------------------------------------
class TestSigV4(unittest.TestCase):
    KEY = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'

    def test_signing_key(self):
        self.assertEqual(signing_key(self.KEY, '20150830', 'us-east-1', 'iam').hex(),
                         'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9')

    def test_iam_list_users(self):
        url = 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08'
        h = {'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
             'Host': 'iam.amazonaws.com', 'X-Amz-Date': '20150830T123600Z'}
        creq, _ = canonical_request('GET', url, h, b'')
        self.assertEqual(hashlib.sha256(creq.encode()).hexdigest(),
                         'f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59')
        got = sigv4('GET', url, h, b'', 'AKIDEXAMPLE', self.KEY, 'us-east-1', 'iam')
        self.assertEqual(got['Authorization'],
                         'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/'
                         'aws4_request, SignedHeaders=content-type;host;x-amz-date, '
                         'Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7')

    def test_get_vanilla(self):
        got = sigv4('GET', 'https://example.amazonaws.com/', {'X-Amz-Date': '20150830T123600Z'},
                    b'', 'AKIDEXAMPLE', self.KEY, 'us-east-1', 'service')
        self.assertTrue(got['Authorization'].endswith(
            'Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31'))


# ---------------------------------------------------------------------------
# A little HTTP API of fakes
# ---------------------------------------------------------------------------
class Router(object):
    def __init__(self):
        self.routes = []

    def on(self, method, prefix, fn):
        self.routes.append((method, prefix, fn))
        return self

    def __call__(self, method, url, body, headers):
        for m, prefix, fn in self.routes:
            if m == method and url.startswith(prefix):
                got = fn(url, body, headers)
                if isinstance(got, tuple):
                    st, data = got
                else:
                    st, data = 200, got
                if isinstance(data, (dict, list, int)):
                    data = json.dumps(data).encode()
                return st, {}, data or b''
        return 404, {}, b'{"message": "no route"}'


class TestApiModules(unittest.TestCase):
    def test_cloudflare(self):
        recs = {}
        cf = 'https://api.cloudflare.com/client/v4'
        r = Router()
        r.on('GET', cf + '/zones?name=example.com', lambda u, b, h: {
            'success': True, 'result': [{'id': 'Z1', 'name': 'example.com'}]})
        r.on('GET', cf + '/zones?name=', lambda u, b, h: {'success': True, 'result': []})

        def create(u, b, h):
            self.assertEqual(h['Authorization'], 'Bearer tok')
            d = json.loads(b)
            recs['R%d' % len(recs)] = d
            return {'success': True, 'result': {'id': 'R%d' % (len(recs) - 1)}}
        r.on('POST', cf + '/zones/Z1/dns_records', create)
        r.on('DELETE', cf + '/zones/Z1/dns_records/', lambda u, b, h: (
            recs.pop(u.rsplit('/', 1)[1], None) and {'success': True, 'result': {}}) or
            {'success': True, 'result': {}})
        m = plugin('cloudflare')({'token': 'tok', 'propagation': 'none'}, FakeCtx(http=r))
        h = m.present('www.example.com', 't', 'k', 'cf-value')
        self.assertEqual(recs['R0']['name'], '_acme-challenge.www.example.com')
        self.assertEqual(recs['R0']['content'], 'cf-value')
        self.assertTrue(m.ready('www.example.com', h))
        m.cleanup('www.example.com', h)
        self.assertEqual(recs, {})

    def test_powerdns_keeps_other_values(self):
        rrset = {'records': []}
        base = 'http://pdns:8081/api/v1/servers/localhost'
        r = Router()
        r.on('GET', base + '/zones/example.com.?', lambda u, b, h: {'rrsets': [
            {'name': '_acme-challenge.example.com.', 'type': 'TXT',
             'records': list(rrset['records'])}] if rrset['records'] else []})
        r.on('GET', base + '/zones', lambda u, b, h: [{'name': 'example.com.'},
                                                       {'name': 'com.'}])

        def patch(u, b, h):
            self.assertEqual(h['X-API-Key'], 'k')
            rs = json.loads(b)['rrsets'][0]
            rrset['records'] = [x for x in rs.get('records', [])] if \
                rs['changetype'] == 'REPLACE' else []
            return 204, b''
        r.on('PATCH', base + '/zones/example.com.', patch)
        m = plugin('powerdns')({'url': 'http://pdns:8081', 'api_key': 'k', 'propagation': 'none'},
                               FakeCtx(http=r))
        h1 = m.present('example.com', 't', 'k', 'one')
        h2 = m.present('*.example.com', 't', 'k', 'two')
        self.assertEqual([x['content'] for x in rrset['records']], ['"one"', '"two"'])
        m.cleanup('example.com', h1)
        self.assertEqual([x['content'] for x in rrset['records']], ['"two"'])
        m.cleanup('*.example.com', h2)
        self.assertEqual(rrset['records'], [])

    def test_route53(self):
        state = {'values': []}
        base = 'https://route53.amazonaws.com/2013-04-01'
        ns = 'https://route53.amazonaws.com/doc/2013-04-01/'
        r = Router()

        def signed(h):
            self.assertTrue(h['Authorization'].startswith(
                'AWS4-HMAC-SHA256 Credential=AKID/'))
            self.assertIn('/us-east-1/route53/aws4_request', h['Authorization'])

        def zones(u, b, h):
            signed(h)
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)
            if q['dnsname'][0] != 'example.com':
                return '<ListHostedZonesByNameResponse xmlns="%s"><HostedZones/>' \
                       '</ListHostedZonesByNameResponse>' % ns
            return ('<ListHostedZonesByNameResponse xmlns="%s"><HostedZones><HostedZone>'
                    '<Id>/hostedzone/ZPRIV</Id><Name>example.com.</Name><Config><PrivateZone>true'
                    '</PrivateZone></Config></HostedZone><HostedZone><Id>/hostedzone/ZPUB</Id>'
                    '<Name>example.com.</Name><Config><PrivateZone>false</PrivateZone></Config>'
                    '</HostedZone></HostedZones></ListHostedZonesByNameResponse>' % ns).encode()

        def rrset(u, b, h):
            vals = ''.join('<ResourceRecord><Value>%s</Value></ResourceRecord>' % v
                           for v in state['values'])
            body = ('<ResourceRecordSet><Name>_acme-challenge.example.com.</Name><Type>TXT'
                    '</Type><TTL>60</TTL><ResourceRecords>%s</ResourceRecords>'
                    '</ResourceRecordSet>' % vals) if state['values'] else ''
            return ('<ListResourceRecordSetsResponse xmlns="%s"><ResourceRecordSets>%s'
                    '</ResourceRecordSets></ListResourceRecordSetsResponse>' % (ns, body)).encode()

        def change(u, b, h):
            signed(h)
            self.assertIn('/hostedzone/ZPUB/rrset', u)
            import xml.etree.ElementTree as ET
            x = ET.fromstring(b)
            act = x.find('.//{%s}Action' % ns).text
            vals = [v.text for v in x.iter('{%s}Value' % ns)]
            state['values'] = [] if act == 'DELETE' else vals
            return ('<ChangeResourceRecordSetsResponse xmlns="%s"><ChangeInfo><Id>/change/C1</Id>'
                    '<Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>'
                    % ns).encode()
        r.on('GET', base + '/hostedzonesbyname', zones)
        r.on('GET', base + '/hostedzone/ZPUB/rrset', rrset)
        r.on('POST', base + '/hostedzone/ZPUB/rrset', change)
        r.on('GET', base + '/change/C1', lambda u, b, h: (
            '<GetChangeResponse xmlns="%s"><ChangeInfo><Id>C1</Id><Status>INSYNC</Status>'
            '</ChangeInfo></GetChangeResponse>' % ns).encode())
        m = plugin('route53')({'access_key_id': 'AKID', 'secret_access_key': 'S',
                               'propagation': 'none'}, FakeCtx(http=r))
        h1 = m.present('example.com', 't', 'k', 'one')
        h2 = m.present('*.example.com', 't', 'k', 'two')
        self.assertEqual(state['values'], ['"one"', '"two"'])
        self.assertTrue(m.ready('example.com', h1))
        m.cleanup('example.com', h1)
        self.assertEqual(state['values'], ['"two"'])
        m.cleanup('*.example.com', h2)
        self.assertEqual(state['values'], [])

    def test_azure(self):
        state = {'values': None}
        mg = 'https://management.azure.com'
        zid = '/subscriptions/S/resourceGroups/rg/providers/Microsoft.Network/dnsZones/example.com'
        r = Router()

        def token(u, b, h):
            q = urllib.parse.parse_qs(b.decode())
            self.assertEqual(q['grant_type'], ['client_credentials'])
            self.assertEqual(q['scope'], ['https://management.azure.com/.default'])
            return {'access_token': 'AT', 'expires_in': 3600}
        r.on('POST', 'https://login.microsoftonline.com/T/oauth2/v2.0/token', token)
        r.on('GET', mg + '/subscriptions/S/resourceGroups/rg/providers/Microsoft.Network/dnsZones?',
             lambda u, b, h: {'value': [{'name': 'example.com', 'id': zid}]})
        r.on('GET', mg + zid + '/TXT/', lambda u, b, h: (404, b'') if state['values'] is None
             else {'properties': {'TXTRecords': [{'value': [v]} for v in state['values']]}})

        def put(u, b, h):
            self.assertEqual(h['Authorization'], 'Bearer AT')
            self.assertIn('/TXT/_acme-challenge.www?api-version=2018-05-01', u)
            state['values'] = [''.join(x['value']) for x in json.loads(b)['properties']['TXTRecords']]
            return {}
        r.on('PUT', mg + zid + '/TXT/', put)
        r.on('DELETE', mg + zid + '/TXT/', lambda u, b, h: state.update(values=None) or (200, b''))
        m = plugin('azure_dns')({'tenant_id': 'T', 'client_id': 'C', 'client_secret': 'X',
                                 'subscription_id': 'S', 'resource_group': 'rg',
                                 'propagation': 'none'}, FakeCtx(http=r))
        h = m.present('www.example.com', 't', 'k', 'az')
        self.assertEqual(state['values'], ['az'])
        m.cleanup('www.example.com', h)
        self.assertIsNone(state['values'])

    def test_gcloud_jwt_signed_rs256(self):
        work = tempfile.mkdtemp()
        try:
            key = os.path.join(work, 'k.pem')
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                            'rsa_keygen_bits:2048', '-out', key], check=True, capture_output=True)
            pub = subprocess.run(['openssl', 'pkey', '-in', key, '-pubout'], check=True,
                                 capture_output=True).stdout
            from acmelib.plugins.challenges.gcloud_dns import make_jwt
            with open(key) as f:
                pem = f.read()
            sa = {'client_email': 'acme@p.iam.gserviceaccount.com', 'private_key': pem,
                  'token_uri': 'https://oauth2.googleapis.com/token', 'private_key_id': 'kid1'}
            jwt = make_jwt(FakeCtx(), sa, now=1700000000)
            head, claims, sig = jwt.split('.')
            pad = lambda s: s + '=' * (-len(s) % 4)     # noqa: E731
            self.assertEqual(json.loads(base64.urlsafe_b64decode(pad(head))),
                             {'alg': 'RS256', 'typ': 'JWT', 'kid': 'kid1'})
            c = json.loads(base64.urlsafe_b64decode(pad(claims)))
            self.assertEqual((c['iss'], c['exp'] - c['iat']), (sa['client_email'], 3600))
            with open(os.path.join(work, 'pub.pem'), 'wb') as f:
                f.write(pub)
            with open(os.path.join(work, 'sig'), 'wb') as f:
                f.write(base64.urlsafe_b64decode(pad(sig)))
            ok = subprocess.run(['openssl', 'dgst', '-sha256', '-verify',
                                 os.path.join(work, 'pub.pem'), '-signature',
                                 os.path.join(work, 'sig')], input=(head + '.' + claims).encode(),
                                capture_output=True)
            self.assertIn(b'Verified OK', ok.stdout)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_acme_dns(self):
        got = []
        r = Router().on('POST', 'https://auth.example.org/update', lambda u, b, h: (
            got.append((json.loads(b), h['X-Api-User'], h['X-Api-Key'])) or {'txt': 'x'}))
        accts = json.dumps({'example.com': {'username': 'u1', 'password': 'p1', 'subdomain': 's1',
                                            'fulldomain': 's1.auth.example.org'}})
        m = plugin('acme_dns')({'url': 'https://auth.example.org', 'accounts': accts,
                                'propagation': 'none'}, FakeCtx(http=r))
        h = m.present('*.example.com', 't', 'k', 'adns')
        self.assertEqual(got, [({'subdomain': 's1', 'txt': 'adns'}, 'u1', 'p1')])
        self.assertEqual(h['fqdn'], 's1.auth.example.org')
        with self.assertRaises(PluginError):
            m.present('other.example.net', 't', 'k', 'adns')

    def test_hetzner_cloud_and_digitalocean(self):
        calls = []
        r = Router()
        r.on('GET', 'https://api.hetzner.cloud/v1/zones?name=example.com',
             lambda u, b, h: {'zones': [{'id': 42, 'name': 'example.com'}]})
        r.on('GET', 'https://api.hetzner.cloud/v1/zones?name=', lambda u, b, h: {'zones': []})
        r.on('POST', 'https://api.hetzner.cloud/v1/zones/42/rrsets/',
             lambda u, b, h: calls.append((u, json.loads(b))) or (201, {'action': {}}))
        m = plugin('hetzner')({'token': 'T', 'propagation': 'none'}, FakeCtx(http=r))
        h = m.present('www.example.com', 't', 'k', 'hz')
        m.cleanup('www.example.com', h)
        self.assertTrue(calls[0][0].endswith('/rrsets/_acme-challenge.www/TXT/actions/add_records'))
        self.assertEqual(calls[0][1]['records'], [{'value': '"hz"'}])
        self.assertTrue(calls[1][0].endswith('/actions/remove_records'))
        do = []
        r = Router()
        r.on('GET', 'https://api.digitalocean.com/v2/domains/example.com', lambda u, b, h: {})
        r.on('POST', 'https://api.digitalocean.com/v2/domains/example.com/records',
             lambda u, b, h: do.append(json.loads(b)) or (201, {'domain_record': {'id': 7}}))
        r.on('DELETE', 'https://api.digitalocean.com/v2/domains/example.com/records/7',
             lambda u, b, h: do.append('deleted') or (204, b''))
        m = plugin('digitalocean')({'token': 'T', 'propagation': 'none'}, FakeCtx(http=r))
        h = m.present('www.example.com', 't', 'k', 'dov')
        m.cleanup('www.example.com', h)
        self.assertEqual(do, [{'type': 'TXT', 'name': '_acme-challenge.www', 'data': 'dov',
                               'ttl': 60}, 'deleted'])

    def test_api_errors_in_words(self):
        r = Router().on('GET', 'https://api.cloudflare.com/client/v4/zones', lambda u, b, h: (
            403, {'success': False, 'errors': [{'code': 9109, 'message': 'Invalid access token'}]}))
        m = plugin('cloudflare')({'token': 'bad'}, FakeCtx(http=r))
        with self.assertRaises(PluginError) as e:
            m.test()
        self.assertIn('Invalid access token', str(e.exception))
        self.assertIn('credentials', str(e.exception))


# ---------------------------------------------------------------------------
# acme's own DNS server as a challenge
# ---------------------------------------------------------------------------
class TestBuiltin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = MemStore()
        cls.port = free_port()
        cls.cfg = server_config(cls.port)
        cls.srv = DnsServer(cls.store, cls.cfg)
        cls.srv.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def module(self, **cfg):
        cfg.setdefault('resolvers', ['127.0.0.1:%d' % self.port])
        return plugin('dns_builtin')(cfg, FakeCtx(self.store, settings=self.cfg))

    def test_present_ready_cleanup_two_orders(self):
        m = self.module()
        h1 = m.present('www.example.com', 't', 'k', 'order-one')
        h2 = m.present('www.example.com', 't', 'k', 'order-two')     # two orders at once
        self.assertEqual(h1['fqdn'], 'www.example.com.acme.example.net')
        for _ in range(20):
            if m.ready('www.example.com', h1) and m.ready('www.example.com', h2):
                break
            time.sleep(0.2)
        else:
            self.fail('not answered: %s' % m.ctx.steps)
        self.assertTrue(any('as it should be' in w for _l, w in m.ctx.steps), m.ctx.steps)
        # what the CA sees, through the CNAME
        m2 = D.query('127.0.0.1', '_acme-challenge.www.example.com', 16, port=self.port)
        self.assertEqual(sorted(m2.texts('TXT')), ['order-one', 'order-two'])
        m.cleanup('www.example.com', h1)
        self.srv.records(force=True)
        self.assertEqual(D.txt_at('127.0.0.1', h1['fqdn'], port=self.port), ['order-two'])
        m.cleanup('www.example.com', h2)

    def test_schemes(self):
        self.assertEqual(self.module(scheme='label', label='all').target_of('*.x.example.org'),
                         'all.acme.example.net')
        self.assertEqual(self.module().target_of('*.example.com'), 'example.com.acme.example.net')
        self.assertEqual(self.module(scheme='direct').target_of('www.example.com'),
                         '_acme-challenge.www.example.com')        # example.com is served too
        with self.assertRaises(PluginError):
            self.module(scheme='direct').target_of('www.example.org')
        with self.assertRaises(PluginError):
            self.module(zone='not.mine.example').target_of('www.example.com')

    def test_strict_cname(self):
        m = self.module(strict_cname=True)
        with self.assertRaises(PluginError) as e:
            m.present('nocname.example.com', 't', 'k', 'v')
        self.assertIn('CNAME nocname.example.com.acme.example.net.', str(e.exception))
        m.present('example.com', 't', 'k', 'strict-ok')

    def test_test_explains(self):
        m = self.module(probe=False, public_resolvers=['127.0.0.1:%d' % self.port],
                        check_names=['www.example.com', 'missing.example.com'])
        with self.assertRaises(PluginError) as e:
            m.test()
        text = e.exception.detail
        self.assertIn('acme.example.net. NS ns1.acme.example.net.', text)
        self.assertIn('_acme-challenge.NAME. CNAME NAME.acme.example.net.', text)
        self.assertIn('answers for acme.example.net', text)
        self.assertIn('_acme-challenge.www.example.com is a CNAME to', text)
        self.assertIn('_acme-challenge.missing.example.com is not pointed at acme', text)

    def test_own_server_down(self):
        cfg = dict(self.cfg, dns_port=free_port())
        m = plugin('dns_builtin')({}, FakeCtx(self.store, settings=cfg))
        h = m.present('down.example.com', 't', 'k', 'v')
        m._said['cname:' + h['rr']] = True
        self.assertFalse(m.ready('down.example.com', h))
        self.assertFalse(m.ready('down.example.com', h))
        with self.assertRaises(PluginError):
            m.ready('down.example.com', h)


# ---------------------------------------------------------------------------
# HTTP-01
# ---------------------------------------------------------------------------
class TestHttpSsh(unittest.TestCase):
    HOSTS = ['192.0.2.21', '192.0.2.22:2222', 'web3.example.com']

    def module(self, world=None, served=None, **cfg):
        base = {'hosts': '\n'.join(self.HOSTS), 'user': 'acme', 'auth': 'key', 'key': 'KEY',
                'hostkey': ['192.0.2.21 ssh-ed25519 AAAA1', '[192.0.2.22]:2222 ssh-ed25519 AAAA2',
                            'web3.example.com ssh-ed25519 AAAA3']}
        base.update(cfg)
        world = world or SshWorld()
        served = served if served is not None else {}

        def http(method, url, body, headers):
            host = urllib.parse.urlsplit(url).hostname
            path = urllib.parse.urlsplit(url).path
            files = world.files.get(host, {})
            for p, data in files.items():
                if p.endswith(path.rsplit('/', 1)[1]) and host not in served.get('broken', ()):
                    served.setdefault('hosts', []).append((host, headers.get('Host')))
                    return 200, {}, data
            return 404, {}, b'not found'
        return plugin('http_ssh')(base, FakeCtx(http=http, ssh=world)), world, served

    def test_every_host_written_checked_removed(self):
        m, world, served = self.module()
        h = m.present('www.example.com', 'TOKEN_abc-1', 'TOKEN_abc-1.thumb', '')
        path = '/var/www/acme-challenge/.well-known/acme-challenge/TOKEN_abc-1'
        for host in ('192.0.2.21', '192.0.2.22', 'web3.example.com'):
            self.assertEqual(world.files[host][path], b'TOKEN_abc-1.thumb')
            self.assertEqual(world.modes[(host, path)], 0o644)
        self.assertEqual([c['port'] for c in world.conns], [22, 2222, 22])
        self.assertEqual(world.conns[1]['hostkey'], '[192.0.2.22]:2222 ssh-ed25519 AAAA2')
        self.assertTrue(m.ready('www.example.com', h))
        self.assertEqual(sorted(served['hosts']), sorted(
            [('192.0.2.21', 'www.example.com'), ('192.0.2.22', 'www.example.com'),
             ('web3.example.com', 'www.example.com')]))
        m.cleanup('www.example.com', h)
        self.assertTrue(all(path not in f for f in world.files.values()))

    def test_all_or_nothing(self):
        world = SshWorld()
        world.readonly.add('web3.example.com')
        m, world, _ = self.module(world)
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 'tok', 'tok.ka', '')
        self.assertIn('web3.example.com', str(e.exception))
        self.assertTrue(all(not f for f in world.files.values()), world.files)

    def test_one_not_serving_is_not_ready(self):
        m, world, served = self.module(served={'broken': ('192.0.2.22',)})
        h = m.present('www.example.com', 'tok', 'tok.ka', '')
        self.assertFalse(m.ready('www.example.com', h))
        self.assertIn('192.0.2.22', m.ctx.steps[-1][1])

    def test_sudo_and_command_after(self):
        m, world, _ = self.module(sudo=True, command_after='systemctl reload nginx')
        m.present('www.example.com', 'tok', 'tok.ka', '')
        cmds = [c for h, c, _i in world.commands if h == '192.0.2.21']
        self.assertTrue(cmds[0].startswith('sudo -n mkdir -p /var/www/acme-challenge/'))
        self.assertIn('sudo -n install -m 644', cmds[0])
        self.assertEqual(cmds[1], 'systemctl reload nginx')
        self.assertEqual(world.files['192.0.2.21'][
            '/var/www/acme-challenge/.well-known/acme-challenge/tok'], b'tok.ka')

    def test_refuses_what_it_should(self):
        m, _w, _s = self.module()
        for token in ('../../etc/passwd', 'a/b', 'a b', ''):
            with self.assertRaises(PluginError):
                m.present('www.example.com', token, 'ka', '')
        with self.assertRaises(PluginError):
            m.present('*.example.com', 'tok', 'ka', '')
        m2, _w, _s = self.module(webroot='/var/www/x; rm -rf /')
        with self.assertRaises(PluginError):
            m2.present('www.example.com', 'tok', 'ka', '')

    def test_probe(self):
        m, world, _ = self.module()
        words = m.test()
        self.assertEqual(words.count('read back and taken away'), 3)
        self.assertTrue(all(not f for f in world.files.values()))
        world.down.add('192.0.2.22')
        with self.assertRaises(PluginError) as e:
            m.test()
        self.assertIn('192.0.2.22', str(e.exception))

    # -- the action "prepare": nginx made ready on every machine ---------------------------
    class PrepWorld(SshWorld):
        """Each machine runs `id -u` and the prepare script (sh -s) as it is told."""
        def __init__(self, uid=b'1000\n', answer=(0, b'nginx: ok\nACME: written and reloaded\n')):
            SshWorld.__init__(self)
            self.uid, self.answer, self.scripts = uid, answer, []

    def prep_module(self, world, **cfg):
        cfg.setdefault('prepare_how', 'own')
        m, world, served = self.module(world, **cfg)
        orig = FakeSsh.run

        def run(s, command, input=None, timeout=120, check=True):
            if command == 'id -u':
                s.world.commands.append((s.host, command, None))
                return 0, s.world.uid, b''
            if command.endswith('sh -s'):
                s.world.commands.append((s.host, command, None))
                s.world.scripts.append((s.host, command, input.decode()))
                rc, out = s.world.answer if not callable(s.world.answer) else \
                    s.world.answer(s.host)
                if rc and check:
                    raise PluginError('exit %d' % rc)
                return rc, out, b''
            return orig(s, command, input, timeout, check)
        self.addCleanup(setattr, FakeSsh, 'run', orig)
        FakeSsh.run = run
        return m, world, served

    def test_prepare_action(self):
        d = plugin('http_ssh').describe()
        self.assertEqual([a['key'] for a in d['actions']], ['nginx_files', 'prepare'])
        world = self.PrepWorld()
        m, world, _s = self.prep_module(world)
        said = m.action('prepare')
        self.assertEqual(len(world.scripts), 3)
        host, cmd, script = world.scripts[0]
        self.assertEqual(cmd, 'sudo -n sh -s')          # not root: through sudo
        self.assertRegex(script, r"conf='?/etc/nginx/conf\.d/acme-challenge\.conf")
        self.assertIn('listen 80 default_server;', script)
        self.assertIn('alias /var/www/acme-challenge/.well-known/acme-challenge/;', script)
        self.assertIn('nginx -t', script)
        self.assertIn('systemctl reload nginx', script)
        self.assertRegex(script, r"chown '?acme")            # the token files written as acme
        self.assertIn('written and reloaded', said)
        self.assertIn('read back and taken away', said)     # then the probe of Test
        self.assertTrue(all(not f for f in world.files.values()))
        # As root, with names of its own and no IPv6: no sudo, no default_server.
        world = self.PrepWorld(uid=b'0\n')
        m, world, _s = self.prep_module(world, user='root', prepare_names='www.example.com',
                                        prepare_ipv6=False, prepare_redirect=False,
                                        check='none')
        m.action('prepare')
        _h, cmd, script = world.scripts[0]
        self.assertEqual(cmd, 'sh -s')
        self.assertIn('server_name www.example.com;', script)
        self.assertNotIn('default_server', script)
        self.assertNotIn('[::]', script)
        self.assertIn('return 404;', script)
        self.assertNotIn('chown', script)

    def test_prepare_fails_and_says_why(self):
        world = self.PrepWorld(answer=lambda h: (5, b'nginx: [emerg] a duplicate default server '
                                                    b'for 0.0.0.0:80\nACME: nginx -t fails - put '
                                                    b'back as it was\n') if h == '192.0.2.22'
                               else (0, b'ACME: already in place\n'))
        m, world, _s = self.prep_module(world, check='none')
        with self.assertRaises(PluginError) as e:
            m.action('prepare')
        self.assertIn('192.0.2.22', str(e.exception))
        self.assertIn('Names that block answers for', str(e.exception))
        with self.assertRaises(PluginError):
            m.action('nothing-such')
        m2, _w, _s = self.prep_module(self.PrepWorld(), nginx_conf='/tmp/x.conf')
        with self.assertRaises(PluginError):
            m2.action('prepare')

    def test_auto_prepare_and_firewall(self):
        # Off (the default): present() runs no prepare script.
        world = self.PrepWorld()
        m, world, _s = self.prep_module(world)
        m.present('www.example.com', 'tok1', 'tok1.ka', '')
        self.assertEqual(world.scripts, [])
        # On: once a job, on every machine, before the token - and not again.
        world = self.PrepWorld(answer=(0, b'ACME-FW: port 80 opened in firewalld\n'
                                          b'ACME: written and reloaded\n'))
        m, world, _s = self.prep_module(world, auto_prepare=True, prepare_firewall=True)
        m.present('www.example.com', 'tok2', 'tok2.ka', '')
        m.present('mail.example.com', 'tok3', 'tok3.ka', '')
        self.assertEqual(len(world.scripts), 3)
        script = world.scripts[0][2]
        self.assertIn('firewall-cmd --permanent --add-service=http', script)
        self.assertIn('ufw allow 80/tcp', script)
        self.assertTrue(any('port 80 opened in firewalld' in str(x) for x in m.ctx.steps))
        # Without the firewall switch the script leaves the firewall alone.
        world = self.PrepWorld()
        m, world, _s = self.prep_module(world, auto_prepare=True, check='none')
        m.test()
        self.assertEqual(len(world.scripts), 3)
        self.assertNotIn('firewall-cmd', world.scripts[0][2])
        # A machine where it fails: the validation fails before any token is written.
        world = self.PrepWorld(answer=(3, b'ACME: no nginx here\n'))
        m, world, _s = self.prep_module(world, auto_prepare=True)
        with self.assertRaises(PluginError) as e:
            m.present('www.example.com', 'tok4', 'tok4.ka', '')
        self.assertIn('nginx could not be set up', str(e.exception))
        self.assertTrue(all(not f for f in world.files.values()))

    # -- nginx already answering port 80: the include into its blocks --------------------
    SITES = {
        '/etc/nginx/nginx.conf': 'http {\n    include /etc/nginx/sites-enabled/*;\n}\n',
        '/etc/nginx/sites-enabled/default': (
            'server {\n    listen 80 default_server;\n    server_name _;\n'
            '    root /var/www/html;\n}\n'
            'server {\n    listen 443 ssl;\n    server_name secure;\n}\n'),
        '/etc/nginx/sites-enabled/certbot': (
            'server {\n    if ($host = www.example.com) {\n        return 301 https://$host$request_uri;\n'
            '    } # managed by Certbot\n    listen 80;\n    server_name www.example.com;\n'
            '    return 404; # "quoted { brace"\n}\n'),
        '/etc/nginx/sites-enabled/own-challenge': (
            'server {\n    listen 80;\n    server_name legacy.example.com;\n'
            '    location /.well-known/acme-challenge/ { root /srv/x; }\n}\n'),
    }

    def test_check_at_other_addresses(self):
        import socket
        from acmelib.plugins.challenges._common import pinned
        # pinned: the name connects to the address given, in this thread only
        with pinned({'www.example.com': '127.0.0.1'}):
            self.assertEqual(socket.getaddrinfo('www.example.com', 80)[0][4][0], '127.0.0.1')
        m, world, served = self.module(check='at', check_at='203.0.113.10\nhttps://198.51.100.7:8443',
                                       check_name='www.example.com')
        self.assertEqual(m.check_targets(), [('http', '203.0.113.10', 80),
                                             ('https', '198.51.100.7', 8443)])
        asked = []
        m.ctx.http = lambda method, url, body=None, headers=None, **kw: (
            asked.append((url, (headers or {}).get('Host'))) or (200, {}, b'tok.ka'))
        h = m.present('www.example.com', 'tok', 'tok.ka', '')
        self.assertTrue(m.ready('www.example.com', h))
        self.assertEqual([u for u, _h in asked], [
            'http://www.example.com/.well-known/acme-challenge/tok',
            'https://www.example.com:8443/.well-known/acme-challenge/tok'])
        self.assertTrue(all(hh is None for _u, hh in asked))   # the name is in the URL itself
        m2, _w, _s = self.module(check='at', check_at='')
        with self.assertRaises(PluginError):
            m2.check_targets()
        m3, _w, _s = self.module(check='at', check_at='bad host!')
        with self.assertRaises(PluginError):
            m3.check_targets()

    def test_nginx_parser(self):
        from acmelib.plugins.challenges import _nginx as NG
        dump = ''.join('# configuration file %s:\n%s\n' % kv for kv in self.SITES.items())
        files = NG.split_dump(dump)
        self.assertEqual(sorted(files), sorted(self.SITES))
        blocks = NG.server_blocks(self.SITES['/etc/nginx/sites-enabled/default'])
        self.assertEqual([NG.on_port_80(b) for b in blocks], [True, False])
        line = 'include /etc/nginx/snippets/acme-challenge.conf;  # acme'
        new, done, left = NG.patch(self.SITES['/etc/nginx/sites-enabled/certbot'], line)
        self.assertEqual(done, ['www.example.com'])
        self.assertTrue(new.startswith('server {\n    %s\n' % line))
        # nothing else changed: take the line out and it is the file it was
        self.assertEqual(new.replace('\n    %s\n' % line, '', 1),
                         self.SITES['/etc/nginx/sites-enabled/certbot'])
        self.assertEqual(NG.patch(new, line)[1], [])               # once only
        _n, done, left = NG.patch(self.SITES['/etc/nginx/sites-enabled/own-challenge'], line)
        self.assertEqual(done, [])
        self.assertIn('of its own', left[0][1])
        for listen, yes in (('80', True), ('0.0.0.0:80', True), ('[::]:80', True),
                            ('8080', False), ('443 ssl', False), ('80 default_server', True)):
            b = NG.server_blocks('server { listen %s; }' % listen)[0]
            self.assertEqual(NG.on_port_80(b), yes, listen)
        self.assertTrue(NG.on_port_80(NG.server_blocks('server { server_name x; }')[0]))
        snip = NG.snippet_text('/var/www/acme-challenge')
        self.assertIn('rewrite ^(/\\.well-known/acme-challenge/.*)$ $1 break;', snip)
        self.assertIn('root /var/www/acme-challenge;', snip)
        self.assertNotIn('alias', snip)

    def nginx_world(self, files, answer=(0, b'ACME-BK: /var/backups/acme-nginx/x\nACME: written and reloaded\n')):
        world = self.PrepWorld(uid=b'0\n', answer=answer)
        dump = ''.join('# configuration file %s:\n%s\n' % kv for kv in files.items()).encode()
        real = ''.join('ACME-FILE %s %s\n' % (p, base64.b64encode(t.encode()).decode())
                       for p, t in files.items()).encode()

        def ans(host):
            script = world.scripts[-1][2]
            if 'nginx -T' in script:
                return 0, dump
            if 'ACME-FILE' in script:
                return 0, real
            return answer
        world.answer = ans
        return world

    def test_prepare_into_existing_blocks(self):
        world = self.nginx_world(self.SITES)
        m, world, _s = self.prep_module(world, user='root', prepare_how='auto', check='none',
                                        hosts='192.0.2.21')
        said = m.action('prepare')
        self.assertIn('nothing else changed', said)
        script = world.scripts[-1][2]
        self.assertIn('sha256sum /etc/nginx/sites-enabled/certbot', script)   # unchanged since read
        self.assertIn('cp -p --parents /etc/nginx/sites-enabled/certbot "$bk"', script)
        self.assertIn('bk=/var/backups/acme-nginx/', script)               # not in sites-enabled
        self.assertNotIn('.acme-old', script)
        self.assertIn('if ! nginx -t 2>&1; then restore;', script)
        self.assertNotIn('own-challenge', script.split('nginx -t')[0].split('sha256sum')[-1])
        self.assertTrue(any('of its own - left as it is' in str(x) for x in m.ctx.steps))
        # manual: the same machine only checked - nothing written
        world = self.nginx_world(self.SITES)
        m, world, _s = self.prep_module(world, user='root', prepare_how='manual', check='none',
                                        hosts='192.0.2.21')
        with self.assertRaises(PluginError) as e:
            m.action('prepare')
        self.assertIn('nginx is not set up yet', str(e.exception))
        self.assertFalse(any('base64 -d' in sc for _h, _c, sc in world.scripts))
        # ... and once it is all there, the check passes
        done = {}
        for p, t in self.SITES.items():
            from acmelib.plugins.challenges import _nginx as NG
            done[p] = NG.patch(t, 'include /etc/nginx/snippets/acme-challenge.conf;  # acme')[0]
        done['/etc/nginx/snippets/acme-challenge.conf'] = m.snippet()
        world = self.nginx_world(done)
        m, world, _s = self.prep_module(world, user='root', prepare_how='manual', check='none',
                                        hosts='192.0.2.21')
        self.assertIn('checked, nothing changed', m.action('prepare'))
        # Names of its own that no block answers: acme's own block for them, not default.
        world = self.nginx_world(self.SITES)
        m, world, _s = self.prep_module(world, user='root', prepare_how='auto', check='none',
                                        hosts='192.0.2.21', prepare_names='shop.example.com')
        m.action('prepare')
        script = world.scripts[-1][2]
        self.assertIn('server_name shop.example.com;', script)
        self.assertNotIn('default_server', script)
        self.assertNotIn('sites-enabled', script)
        # ... a name a block answers already: the include into the blocks instead
        world = self.nginx_world(self.SITES)
        m, world, _s = self.prep_module(world, user='root', prepare_how='auto', check='none',
                                        hosts='192.0.2.21', prepare_names='www.example.com')
        m.action('prepare')
        self.assertIn('sha256sum /etc/nginx/sites-enabled/certbot', world.scripts[-1][2])
        self.assertTrue(any('answered by another block already' in str(x) for x in m.ctx.steps))
        # the file to download
        got = m.action('nginx_files')
        self.assertEqual(got['file']['name'], 'acme-challenge.conf')
        self.assertIn('include /etc/nginx/snippets/acme-challenge.conf;', got['file']['text'])


class TestOtherModules(unittest.TestCase):
    def test_http_local(self):
        ctx = FakeCtx(http=lambda m, u, b, h: (200, {}, ctx.tokens.get(u.rsplit('/', 1)[1], '')
                                                .encode()))
        m = plugin('http_local')({}, ctx)
        h = m.present('www.example.com', 'tok', 'tok.ka', '')
        self.assertEqual(ctx.tokens, {'tok': 'tok.ka'})
        self.assertTrue(m.ready('www.example.com', h))
        m.cleanup('www.example.com', h)
        self.assertEqual(ctx.tokens, {})
        self.assertIn('probe token', m.test())
        with self.assertRaises(PluginError):
            m.present('*.example.com', 'tok', 'ka', '')

    def test_manual(self):
        ctx = FakeCtx()
        m = plugin('manual')({'propagation': 'none'}, ctx)
        h = m.present('www.example.com', 't', 'k', 'by-hand')
        self.assertIn('_acme-challenge.www.example.com.  60  IN  TXT  "by-hand"', ctx.steps[-1][1])
        self.assertFalse(m.ready('www.example.com', h))
        ctx.kv['manual:confirmed:_acme-challenge.www.example.com:by-hand'] = '1'
        self.assertTrue(m.ready('www.example.com', h))

    def test_script(self):
        work = tempfile.mkdtemp()
        try:
            log = os.path.join(work, 'log')
            hook = os.path.join(work, 'hook.sh')
            with open(hook, 'w') as f:
                f.write('#!/bin/sh\necho "$@|$ACME_RECORD|$ACME_TXT|$MY" >> %s\n'
                        '[ "$ACME_TXT" = fail ] && exit 3\nexit 0\n' % log)
            os.chmod(hook, 0o755)
            m = plugin('script')({'path': hook, 'env': 'MY=yes', 'propagation': 'none',
                                  'follow_cname': False}, FakeCtx())
            h = m.present('www.example.com', 't', 'k', 'scripted')
            m.cleanup('www.example.com', h)
            with open(log) as f:
                lines = f.read().splitlines()
            self.assertEqual(lines, [
                'present _acme-challenge.www.example.com scripted|'
                '_acme-challenge.www.example.com|scripted|yes',
                'cleanup _acme-challenge.www.example.com scripted|'
                '_acme-challenge.www.example.com|scripted|yes'])
            with self.assertRaises(PluginError) as e:
                m.present('www.example.com', 't', 'k', 'fail')
            self.assertIn('ended with 3', str(e.exception))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_ssh_dns(self):
        world = SshWorld()
        m = plugin('ssh_dns')({'host': 'ns1.example.com', 'user': 'acme', 'key': 'K',
                               'zone': 'example.com', 'propagation': 'none',
                               'follow_cname': False, 'sudo': True}, FakeCtx(ssh=world))
        h = m.present('www.example.com', 't', 'k', 'nsupd')
        m.cleanup('www.example.com', h)
        (host, cmd, stdin), (_h2, _c2, stdin2) = world.commands
        self.assertEqual((host, cmd), ('ns1.example.com', 'sudo -n nsupdate -l'))
        self.assertEqual(stdin.decode(), 'zone example.com\nupdate add '
                         '_acme-challenge.www.example.com. 60 TXT "nsupd"\nsend\n')
        self.assertIn('update delete _acme-challenge.www.example.com. TXT "nsupd"', stdin2.decode())
        world = SshWorld()
        m = plugin('ssh_dns')({'host': 'dc1.example.com', 'user': 'acme', 'key': 'K',
                               'zone': 'example.com', 'flavour': 'powershell',
                               'propagation': 'none', 'follow_cname': False}, FakeCtx(ssh=world))
        m.present('www.example.com', 't', 'k', 'winv')
        cmd = world.commands[0][1]
        self.assertIn("Add-DnsServerResourceRecord -ZoneName 'example.com' -Name "
                      "'_acme-challenge.www' -Txt -DescriptiveText 'winv'", cmd)
        with self.assertRaises(PluginError):
            m.present('www.example.com', 't', 'k', "x'; Remove-Item C:\\ #")

    def test_registry(self):
        found = REG.all('challenge')
        self.assertEqual(REG.broken, [])
        want = {'dns_builtin', 'rfc2136', 'cloudflare', 'powerdns', 'route53', 'azure_dns',
                'hetzner', 'digitalocean', 'ovh', 'gcloud_dns', 'acme_dns', 'ssh_dns', 'script',
                'manual', 'http_local', 'http_ssh',
                'desec', 'gandi', 'linode', 'vultr', 'porkbun', 'namecheap', 'godaddy',
                'dnsimple', 'ns1', 'bunny', 'cloudns', 'inwx', 'transip', 'netcup', 'ionos',
                'scaleway', 'exoscale', 'infoblox', 'technitium', 'he_net', 'wedos', 'active24',
                'websupport',
                # acme 1.1 (test/test_dns_providers_more.py)
                'subreg', 'czechia', 'loopia', 'simply', 'hostingde', 'domeneshop', 'glesys',
                'mythic_beasts', 'infomaniak', 'alidns', 'tencentcloud', 'oci_dns',
                'akamai_edgedns', 'dnsmadeeasy', 'gcore', 'netlify', 'vercel', 'namecom',
                'namesilo', 'dynu', 'njalla', 'dreamhost', 'duckdns',
                'http_ftp', 'http_s3', 'http_azure_blob', 'http_webdav',
                # dns-persist-01, a record set once (test/test_dns_persist.py)
                'dns_persist'}
        self.assertEqual(set(found), want)
        for kind, cls in found.items():
            d = cls.describe()
            self.assertTrue(d['title'] and d['description'] and cls.types, kind)
            keys = [f['key'] for f in d['fields']]
            self.assertEqual(len(keys), len(set(keys)), kind)
            for f in d['fields']:
                if f['type'] == 'select':
                    self.assertTrue(f.get('options'), (kind, f['key']))
                    self.assertIn(f.get('default'), [o[0] for o in f['options']], (kind, f['key']))



# ---------------------------------------------------------------------------
# The VIP address: answered from the address that was asked
# ---------------------------------------------------------------------------
class TestDnsServerVip(unittest.TestCase):
    """A server on 0.0.0.0 asked at another address of this machine (here
    127.0.0.2, standing for the cluster's VIP) answers FROM that address: a
    resolver that asked the VIP throws away an answer from the node's own."""

    def ask_from(self, srv_addr, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(D.make_query('ns1.' + ZONE, 'A').to_wire(), (srv_addr, port))
            data, src = s.recvfrom(4096)
            return data, src
        finally:
            s.close()

    def test_wildcard_answers_from_the_asked_address(self):
        port = free_port()
        srv = DnsServer(MemStore(), server_config(port, dns_listen='0.0.0.0'))
        st = srv.start()
        try:
            self.assertTrue(st['ok'], st)
            for addr in ('127.0.0.1', '127.0.0.2'):
                data, src = self.ask_from(addr, port)
                self.assertEqual(src[0], addr)
                self.assertTrue(D.parse(data).answer)
        finally:
            srv.stop()

    def test_vip_added_to_listen_and_bound_freely(self):
        port = free_port()
        srv = DnsServer(MemStore(), server_config(port, dns_listen='127.0.0.1'))
        srv.vip_address = lambda: '127.0.0.2'
        st = srv.start()
        try:
            self.assertIn('127.0.0.2', st['listen'])
            self.assertTrue(any(x.startswith('127.0.0.2:') for x in st['listening']), st)
            data, src = self.ask_from('127.0.0.2', port)
            self.assertEqual(src[0], '127.0.0.2')
        finally:
            srv.stop()

    def test_vip_covered_by_a_wildcard_not_added(self):
        srv = DnsServer(MemStore(), server_config(free_port(), dns_listen='0.0.0.0,::'))
        srv.vip_address = lambda: '192.0.2.50'
        addrs, _port = srv._listen_conf(srv.cfg())
        self.assertEqual(list(addrs), ['0.0.0.0', '::'])

    def test_vip_not_on_this_node_yet_still_bound(self):
        # 192.0.2.50 is on no interface here: IP_FREEBIND lets it be bound, as
        # on the node of a cluster that does not hold the VIP right now.
        port = free_port()
        srv = DnsServer(MemStore(), server_config(port, dns_listen='127.0.0.1'))
        srv.vip_address = lambda: '192.0.2.50'
        st = srv.start()
        try:
            self.assertTrue(any(x.startswith('192.0.2.50:') for x in st['listening']), st)
        finally:
            srv.stop()


if __name__ == '__main__':
    unittest.main(verbosity=2)
