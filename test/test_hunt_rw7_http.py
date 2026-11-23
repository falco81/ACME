#!/usr/bin/env python3
"""Hunt 1.0.144, run w7, area http: the HTTP layer.

- the daemon's API (127.0.0.1, ApiHttpServer: 256 connections at most): its timeout of 60 s was
  for each read, so a byte every 50 s kept a connection - and its thread - for ever; 256 such
  connections from any program on the machine (no key needed) and the pages had no API at all,
  for as long as they kept trickling. Now the head of a request (its line and its headers) must
  be in within ApiHandler.head_s (15 s) of the connection's start - or, for one more request on a
  kept-alive connection, of its first byte;
- the body of a request refused before it was read (no key) was read and dropped a lump at a
  time, each lump waited for 60 s - the same trickle in the body held the connection for ever;
  now within drop_s (30 s) all told;
- a connection without the key was kept alive after its answer: a quick request every 59 s held
  it for ever; now kept alive 45 s all told at most;
- the daemon's answers said "Server: acme Python/3.x.y"; now "acme".

What must not change: a kept-alive connection with the key waits for its next request as long as
before; a body of the key's holder sent slowly is still read; a head sent quickly is answered.

    python3 test/test_hunt_rw7_http.py
"""
import json
import os
import socket
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC  # noqa: E402  (the daemon in a folder of its own)


def closed_within(sock, secs, trickle=None, every=2.0):
    """Seconds until the daemon closed `sock` (reading whatever it answered), or None when it
    was still open after `secs`; `trickle` sent every `every` seconds meanwhile."""
    t0 = time.monotonic()
    sock.settimeout(0.5)
    last = 0.0
    while time.monotonic() - t0 < secs:
        if trickle is not None and time.monotonic() - last >= every:
            last = time.monotonic()
            try:
                sock.send(trickle)
            except OSError:
                return time.monotonic() - t0
        try:
            got = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return time.monotonic() - t0
        if not got:
            return time.monotonic() - t0
    return None


class Http(unittest.TestCase):
    """A real daemon (test_certs_core's), asked over its socket by hand."""
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def setUp(self):
        self.socks = []

    def tearDown(self):
        for s in self.socks:
            s.close()

    def conn(self):
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        self.socks.append(s)
        return s

    def head(self, path='/api/health', method='GET', token=True, extra=b'', close=False):
        return (b'%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n' % (method.encode(), path.encode())
                + (b'X-Acme-Token: %s\r\n' % self.token.encode() if token else b'')
                + (b'Connection: close\r\n' if close else b'') + extra + b'\r\n')

    @staticmethod
    def answer(sock):
        """One answer read off a kept-alive connection: (status, headers, body)."""
        with sock.makefile('rb') as f:
            return Http._answer(f)

    @staticmethod
    def _answer(f):
        line = f.readline()
        heads = {}
        while True:
            h = f.readline()
            if h in (b'\r\n', b'\n', b''):
                break
            k, _, v = h.decode().partition(':')
            heads[k.strip().lower()] = v.strip()
        body = f.read(int(heads.get('content-length') or 0))
        return int(line.split()[1]), heads, body

    # The connections held by a trickle: closed now, at the same time (the slow ones together).
    def test_01_trickles_closed(self):
        out = {}

        def run(key, fn):
            try:
                out[key] = fn()
            except Exception as e:                      # noqa: BLE001
                out[key] = e

        def silent():
            return closed_within(self.conn(), 40)

        def head_trickle():
            return closed_within(self.conn(), 40, trickle=b'G', every=2.0)

        def body_trickle():
            s = self.conn()
            s.send(self.head('/api/settings', 'POST', token=False,
                             extra=b'Content-Type: application/json\r\nContent-Length: 1000000\r\n'))
            return closed_within(s, 70, trickle=b'x', every=2.0)

        def no_key_kept_alive():
            # a quick request without the key every 20 s (as one every 59 s did for ever)
            s = self.conn()
            got = []
            t0 = time.monotonic()
            while time.monotonic() - t0 < 70:
                try:
                    s.send(self.head('/api/status', token=False))
                    got.append(self.answer(s)[0])
                except (OSError, IndexError, ValueError):
                    return got, time.monotonic() - t0
                time.sleep(20)
            return got, None

        def health_no_key():
            s = self.conn()
            s.send(self.head('/api/health', token=False))
            st, h, _b = self.answer(s)
            return st, h.get('server'), closed_within(s, 70)

        jobs = {'silent': silent, 'head': head_trickle, 'body': body_trickle,
                'nokey': no_key_kept_alive, 'health': health_no_key}
        threads = [threading.Thread(target=run, args=(k, f)) for k, f in jobs.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        for k, v in out.items():
            self.assertNotIsInstance(v, Exception, '%s: %r' % (k, v))
        # nothing at all sent: closed after the head's 15 s (was 60 s)
        self.assertIsNotNone(out['silent'], 'a silent connection was still open after 40 s')
        self.assertLess(out['silent'], 25)
        self.assertGreater(out['silent'], 10)
        # a byte every 2 s: closed at 15 s (was never)
        self.assertIsNotNone(out['head'], 'a trickled head kept its connection past 40 s')
        self.assertLess(out['head'], 25)
        # the head quick, a refused body trickled: closed within 30 s of the refusal (was never)
        self.assertIsNotNone(out['body'], 'a trickled refused body kept its connection past 70 s')
        self.assertLess(out['body'], 45)
        # without the key: kept alive 45 s all told at most (was for ever)
        got, gone = out['nokey']
        self.assertTrue(got and set(got) == {403}, got)
        self.assertIsNotNone(gone, 'a connection without the key was kept alive past 70 s')
        self.assertLess(gone, 65)
        st, server, gone = out['health']
        self.assertEqual(st, 200)
        self.assertEqual(server, 'acme')            # no "Python/3.x.y"
        self.assertIsNotNone(gone, 'a connection without the key was kept alive past 70 s')
        self.assertLess(gone, 50)
        self.assertGreater(gone, 40)

    def test_02_what_works_as_before(self):
        out = {}

        def kept_alive():
            # with the key: answered, then the next request after 18 s of quiet (more than the
            # head's 15 s) on the same connection - the wait for a request is `timeout` (60 s)
            s = self.conn()
            s.settimeout(60)
            got = []
            s.send(self.head('/api/health'))
            got.append(self.answer(s)[0])
            time.sleep(18)
            s.send(self.head('/api/health', close=True))
            got.append(self.answer(s)[0])
            return got

        def slow_body():
            # the key's holder: a body that pauses 18 s after the head is still read
            body = json.dumps({'name': 'tester', 'password': self.pw}).encode()
            s = self.conn()
            s.settimeout(60)
            s.send(self.head('/api/auth/login', 'POST', close=True,
                             extra=b'Content-Type: application/json\r\nContent-Length: %d\r\n'
                             % len(body)))
            time.sleep(18)
            s.send(body)
            st, _h, b = self.answer(s)
            return st, bool(json.loads(b.decode()).get('token'))

        def quick_trickle():
            # a head byte by byte within the 15 s: answered
            s = self.conn()
            s.settimeout(30)
            for ch in self.head('/api/health', close=True):
                s.send(bytes([ch]))
                time.sleep(0.02)
            return self.answer(s)[0]

        def run(key, fn):
            try:
                out[key] = fn()
            except Exception as e:                      # noqa: BLE001
                out[key] = e

        threads = [threading.Thread(target=run, args=(k, f)) for k, f in
                   {'kept': kept_alive, 'slow': slow_body, 'quick': quick_trickle}.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        self.assertEqual(out['kept'], [200, 200], out)
        self.assertEqual(out['slow'], (200, True), out)
        self.assertEqual(out['quick'], 200, out)

    def test_03_the_api_full_then_free(self):
        """256 connections trickling their heads: the API is free again once they are closed (it
        was not, for as long as they trickled)."""
        socks = []
        try:
            for _ in range(258):
                try:
                    socks.append(self.conn())
                except OSError:
                    break
            t0 = time.monotonic()
            while time.monotonic() - t0 < 22:
                for s in socks:
                    try:
                        s.send(b'G')
                    except OSError:
                        pass
                time.sleep(2)
            st, got = self.call('GET', '/api/health')
            self.assertEqual(st, 200, got)
        finally:
            for s in socks:
                s.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
