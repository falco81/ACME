#!/usr/bin/env python3
"""Hunt w8 - when the outside world misbehaves.

    python3 test/test_hunt_rw8_faults.py

- a server that answers, but drips its answer a byte at a time (a target, a CA, a DNS API):
  urllib's timeout is per read, so the job (or the order of the pages' own certificate) waited
  for hours - each byte came within the timeout. Now the whole answer is read within
  max(ANSWER_WITHIN_S, 4 x timeout) seconds, and a job's stop is looked at between the pieces;
- a certificate issued while the database would not take it (SQLite locked, PostgreSQL
  restarted): the CA's certificate was thrown away and ordered again at the next try (a paid
  one twice, Let's Encrypt's weekly limit spent). Now the save is tried again for a while,
  then the certificate is kept in a file (its key sealed, written whole) and the next try
  saves that one without asking the CA; a save whose answer was lost is not saved twice.
"""
import json
import os
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-rw8-faults-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402,F401  (the routes)
from acmelib.certs import store as S, jobs, renewer, runtime  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


class Dripping(object):
    """A local server that sends its headers at once, then its body a byte every `every` s;
    `head_only`: a status line and nothing more for ever (headers never end)."""

    def __init__(self, every=0.3, length=1000, status=200):
        self.srv = socket.socket()
        self.srv.bind(('127.0.0.1', 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.every, self.length, self.status = every, length, status
        self.done = threading.Event()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while not self.done.is_set():
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.one, args=(c,), daemon=True).start()

    def one(self, c):
        try:
            c.recv(65536)
            c.sendall(b'HTTP/1.1 %d X\r\nContent-Length: %d\r\n\r\n' % (self.status, self.length))
            for _ in range(self.length):
                if self.done.is_set():
                    break
                c.sendall(b'x')
                time.sleep(self.every)
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.done.set()
        self.srv.close()


class SlowAnswer(unittest.TestCase):
    def setUp(self):
        self.was = E.ANSWER_WITHIN_S
        E.ANSWER_WITHIN_S = 2

    def tearDown(self):
        E.ANSWER_WITHIN_S = self.was

    def test_module_http_gives_up(self):
        srv = Dripping()
        try:
            ctx = runtime.RunContext(STORE, None, scope='target:w8')
            t = time.monotonic()
            with self.assertRaises(Exception) as e:
                ctx.http('GET', 'http://127.0.0.1:%d/' % srv.port, timeout=1, retries=0)
            took = time.monotonic() - t
            self.assertLess(took, 15)
            self.assertIn('too slowly', str(e.exception))
        finally:
            srv.close()

    def test_error_answer_dripped_too(self):
        srv = Dripping(status=500)
        try:
            ctx = runtime.RunContext(STORE, None, scope='target:w8')
            t = time.monotonic()
            status, _h, data = ctx.http('POST', 'http://127.0.0.1:%d/' % srv.port, body=b'{}',
                                        timeout=1, retries=0)
            self.assertLess(time.monotonic() - t, 15)
            self.assertEqual(status, 500)
            self.assertEqual(data, b'')          # not read whole: nothing, not a hang
        finally:
            srv.close()

    def test_stop_looked_at(self):
        srv = Dripping()
        E.ANSWER_WITHIN_S = 600
        try:
            ctx = runtime.RunContext(STORE, None, scope='target:w8')
            threading.Timer(1.0, ctx._stop.set).start()
            t = time.monotonic()
            with self.assertRaises(Exception) as e:
                ctx.http('GET', 'http://127.0.0.1:%d/' % srv.port, timeout=1, retries=0)
            self.assertLess(time.monotonic() - t, 10)
            self.assertIn('stopped', str(e.exception))
        finally:
            srv.close()

    def test_a_normal_answer_whole(self):
        srv = Dripping(every=0, length=200000)
        try:
            ctx = runtime.RunContext(STORE, None, scope='target:w8')
            status, _h, data = ctx.http('GET', 'http://127.0.0.1:%d/' % srv.port, timeout=5)
            self.assertEqual((status, len(data)), (200, 200000))
        finally:
            srv.close()

    def test_the_pages_own_acme_gives_up(self):
        srv = Dripping()
        try:
            a = E.Acme.__new__(E.Acme)
            a.nonce = None
            real = E.url_open

            def plain(req, timeout=30, context=None, purpose=''):
                req.full_url = req.full_url.replace('https://', 'http://')
                return real(req, timeout=1, context=None)
            real_read = E.read_within

            def quick(resp, limit, timeout=30, cancelled=None):
                return real_read(resp, limit, 0.5, cancelled)   # its 30 s per read: 2 s here
            E.url_open, E.read_within = plain, quick
            try:
                t = time.monotonic()
                with self.assertRaises(E.AcmeError) as e:
                    a._req('https://127.0.0.1:%d/directory' % srv.port)
                self.assertLess(time.monotonic() - t, 15)
                self.assertIn('too slowly', str(e.exception))
            finally:
                E.url_open, E.read_within = real, real_read
        finally:
            srv.close()


class SlowDns(unittest.TestCase):
    def test_dns_over_tcp_dripped(self):
        """A DNS server over TCP that says its answer is 500 bytes long and sends one byte a
        second: given up within twice the timeout, not 500 s."""
        from acmelib.plugins.challenges import _dns as D
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(2)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def serve():
            try:
                c, _ = srv.accept()
                c.recv(4096)
                c.sendall(b'\x01\xf4')
                while not stop.is_set():
                    c.sendall(b'x')
                    time.sleep(0.5)
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        try:
            t = time.monotonic()
            with self.assertRaises(D.DnsError):
                D.send_tcp('127.0.0.1', port, b'\x00' * 20, timeout=1.0)
            self.assertLess(time.monotonic() - t, 5)
        finally:
            stop.set()
            srv.close()


class Locked(Exception):
    pass


def locked(*_a, **_k):
    raise sqlite3.OperationalError('database is locked')


class IssuedNotLost(unittest.TestCase):
    def setUp(self):
        for t in ('certs', 'cert_versions', 'cert_jobs', 'cert_deploys'):
            STORE.db.run('DELETE FROM %s' % t)
        STORE.db.run("DELETE FROM cert_issuers WHERE name = 'Self'")
        STORE.db.insert('cert_issuers', {'name': 'Self', 'kind': 'selfsigned', 'config': '{}',
                                         'enabled': 1, 'created': time.time()})
        E.CONFIG.update(certs_notify_mail='')
        self.cid = STORE.db.insert('certs', {
            'name': 'w8', 'names': '["w8.example.test"]', 'issuer': 'Self', 'state': 'new',
            'key_type': 'ec-256', 'auto_renew': 1, 'enabled': 1, 'created': time.time(),
            'created_by': 'test', 'profile': '{}'})
        self.waits = renewer.SAVE_WAITS
        renewer.SAVE_WAITS = (0, 0)
        self.issued = []
        self.cls = S.plugin_class('issuer', 'selfsigned')
        real = self.cls.issue
        self.real_issue = real

        def issue(this, req):
            got = real(this, req)
            self.issued.append(got.cert_pem)
            return got
        self.cls.issue = issue
        self.real_save = S.save_version

    def tearDown(self):
        renewer.SAVE_WAITS = self.waits
        self.cls.issue = self.real_issue
        S.save_version = self.real_save
        renewer._unsaved_drop(self.cid, 'main')

    def renew(self):
        return jobs.run_now(STORE, 'renew', lambda job: renewer.renew_cert(
            STORE, job, self.cid, True, 'test'), cert_id=self.cid)

    def test_kept_and_saved_at_the_next_try(self):
        S.save_version = locked
        j = self.renew()
        self.assertFalse(j.ok)
        self.assertEqual(len(self.issued), 1)
        path = renewer._unsaved_path(self.cid, 'main')
        self.assertTrue(os.path.exists(path))
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path) as f:
            kept = json.load(f)
        self.assertEqual(kept['cert_pem'], self.issued[0])
        self.assertNotIn('PRIVATE KEY', kept['key'])           # sealed
        self.assertFalse(os.path.exists(path + '.part'))
        self.assertTrue(any('kept in' in str(s) for s in j.steps), j.steps[-4:])
        # the database back: saved, the CA (here: the self-signed issuer) not asked again
        S.save_version = self.real_save
        j = self.renew()
        self.assertTrue(j.ok, j.steps[-5:])
        self.assertEqual(len(self.issued), 1)
        row = S.cert_need(STORE, self.cid)
        self.assertEqual(row['cert_pem'], self.issued[0])
        self.assertTrue(row['key_sealed'])
        from acmelib.certs import pki
        self.assertTrue(pki.key_matches(row['cert_pem'], S.cert_key(row)))
        self.assertFalse(os.path.exists(path))
        # and the one after asks the CA as before
        j = self.renew()
        self.assertTrue(j.ok, j.steps[-5:])
        self.assertEqual(len(self.issued), 2)

    def test_a_short_trouble_waited_out(self):
        n = {'n': 0}

        def once(*a, **k):
            n['n'] += 1
            if n['n'] == 1:
                raise sqlite3.OperationalError('database is locked')
            return self.real_save(*a, **k)
        S.save_version = once
        j = self.renew()
        self.assertTrue(j.ok, j.steps[-5:])
        self.assertEqual(n['n'], 2)
        self.assertFalse(os.path.exists(renewer._unsaved_path(self.cid, 'main')))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_versions WHERE cert_id = ?',
                                        (self.cid,)), 1)

    def test_answer_lost_not_saved_twice(self):
        def saved_then_lost(*a, **k):
            self.real_save(*a, **k)
            raise sqlite3.OperationalError('disk I/O error')
        S.save_version = saved_then_lost
        j = self.renew()
        self.assertTrue(j.ok, j.steps[-5:])
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM cert_versions WHERE cert_id = ?',
                                        (self.cid,)), 1)

    def test_other_errors_not_waited_for(self):
        def refused(*a, **k):
            raise ValueError('not approved')
        S.save_version = refused
        j = self.renew()
        self.assertFalse(j.ok)
        self.assertFalse(os.path.exists(renewer._unsaved_path(self.cid, 'main')))

    def test_a_file_no_longer_fitting_dropped(self):
        S.save_version = locked
        self.renew()
        S.save_version = self.real_save
        path = renewer._unsaved_path(self.cid, 'main')
        self.assertTrue(os.path.exists(path))
        STORE.db.update('certs', self.cid, {'names': '["other.example.test"]'})
        j = self.renew()
        self.assertTrue(j.ok, j.steps[-5:])
        self.assertEqual(len(self.issued), 2)                   # asked again: other names
        self.assertFalse(os.path.exists(path))
        self.assertIn('other.example.test', S.cert_need(STORE, self.cid)['names'])

    def test_another_certificate_of_the_same_number(self):
        S.save_version = locked
        self.renew()
        S.save_version = self.real_save
        STORE.db.update('certs', self.cid, {'created': time.time() + 5})   # made again
        j = self.renew()
        self.assertTrue(j.ok, j.steps[-5:])
        self.assertEqual(len(self.issued), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
