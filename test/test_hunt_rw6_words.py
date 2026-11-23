#!/usr/bin/env python3
"""Bug hunt run w6, area words: what an error becomes for the person who sees it.

    python3 test/test_hunt_rw6_words.py

- A request the API answered without reading its body - the wrong token, a role that may not,
  signing in with a certificate switched off - left that body unread and the connection was
  closed under it: the page's relay, still sending a large body, got a reset (a broken pipe)
  in place of the answer, and the page said the service was not answering. The body is read
  and dropped now (up to the 8 MB a body may be), and the words arrive.
"""
import json
import re
import os
import socket
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)


class Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        # the daemon's output read, or it stops at a full pipe
        threading.Thread(target=lambda: [None for _ in iter(
            lambda: cls.daemon.stdout.read(4096), b'')], daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    def raw(self, path, body, token, session=''):
        """A POST as the pages' relay sends it (Connection: close, the whole body, then the
        answer read) -> (status line, the JSON) or ('reset', why)."""
        s = socket.create_connection(('127.0.0.1', self.port), timeout=60)
        head = ('POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n'
                'X-Acme-Token: %s\r\nX-Acme-Session: %s\r\nContent-Type: application/json\r\n'
                'Content-Length: %d\r\n\r\n' % (path, token, session, len(body))).encode()
        try:
            s.sendall(head + body)
            got = b''
            while True:
                lump = s.recv(65536)
                if not lump:
                    break
                got += lump
        except OSError as e:
            return 'reset', repr(e)
        finally:
            s.close()
        line, _, rest = got.partition(b'\r\n')
        return line.decode(), json.loads(rest.partition(b'\r\n\r\n')[2] or b'{}')

    # ---- answered without the body read --------------------------------------------------------
    def test_refused_unread_body_still_answered(self):
        big = json.dumps({'cert': 'A' * 7900000}).encode()        # under the 8 MB of a body
        for path, token, session, status, words in (
                ('/api/auth/cert', self.token, '', '404', 'switched off'),
                ('/api/certs/save', 'not-the-token', '', '403', 'token'),
                ('/api/certs/import', self.token, self.ro, '403', 'may do that')):
            line, got = self.raw(path, big, token, session)
            self.assertNotEqual(line, 'reset', '%s: %s' % (path, got))
            self.assertIn(' %s ' % status, line, (path, line, got))
            self.assertIn(words, got.get('error', ''), (path, got))
        # and the API goes on answering
        st, got = self.call('GET', '/api/auth/whoami', None, self.admin)
        self.assertEqual(st, 200, got)

    def test_keep_alive_next_request_not_the_old_body(self):
        """On a kept-alive connection the unread body was read as the next request."""
        body = json.dumps({'x': 'y' * 100}).encode()
        s = socket.create_connection(('127.0.0.1', self.port), timeout=30)
        try:
            one = ('POST /api/certs/save HTTP/1.1\r\nHost: x\r\nX-Acme-Token: wrong\r\n'
                   'Content-Length: %d\r\n\r\n' % len(body)).encode() + body
            two = ('GET /api/health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n').encode()
            s.sendall(one + two)
            got = b''
            while True:
                lump = s.recv(65536)
                if not lump:
                    break
                got += lump
        finally:
            s.close()
        lines = re.findall(rb'HTTP/1\.1 \d{3} ', got)
        self.assertEqual(len(lines), 2, got[:600])
        self.assertIn(b' 403 ', lines[0])
        self.assertNotIn(b' 400 ', lines[1], got[-400:])


    # ---- the command line: a file that is not there -------------------------------------------
    def test_cli_file_not_there_in_words(self):
        import subprocess
        for args in (['--import', '/nonexistent-w6.pem'], ['--ca-import', '/nonexistent-w6.pem']):
            r = subprocess.run([sys.executable, os.path.join(TCC.ROOT, 'acme.py')] + args,
                               env=self.env, capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn('/nonexistent-w6.pem: no such file or directory', r.stderr)
            self.assertNotIn('Errno', r.stderr)
            self.assertNotIn('Traceback', r.stderr)

    def test_errno_said(self):
        sys.path.insert(0, TCC.ROOT)
        import acme
        self.assertEqual(acme.errno_said("acme: [Errno 2] No such file or directory: '/x'"),
                         'acme: /x: no such file or directory')
        self.assertEqual(acme.errno_said('x:443 could not be reached: [Errno 111] Connection '
                                         'refused'), 'x:443 could not be reached: connection refused')
        self.assertEqual(acme.errno_said('nothing to change'), 'nothing to change')
        self.assertEqual(acme.errno_said("acme: /p/x: [Errno 2] No such file or directory: "
                                         "'/p/x'"), 'acme: /p/x: no such file or directory')

    # ---- a module's setting of the wrong kind ------------------------------------------------
    def relay(self, name, tests):
        return self.call('POST', '/api/tests/save', {
            'name': name, 'kind': 'ssh_relay', 'config': {
                'host': '127.0.0.1', 'port': 1, 'user': 'root', 'auth': 'password',
                'password': 'x', 'tests': tests}}, self.admin)

    def test_list_setting_of_another_kind_refused(self):
        for bad in (True, 5, {'a': 1}, [{'a': 1}], [None]):
            st, got = self.relay('w6relay-bad', bad)
            self.assertEqual(st, 400, (bad, got))
            self.assertEqual(got.get('field'), 'tests', got)
            self.assertIn('is a list', got['error'])
        st, got = self.relay('w6relay-ok', ['w6t1'])
        self.assertEqual(st, 200, got)
        st, got = self.call('POST', '/api/targets/save', {
            'name': 'w6dev', 'kind': 'fake', 'config': {'dir': '/tmp', 'port': [1]}}, self.admin)
        self.assertEqual((st, got.get('field')), (400, 'port'), got)

    def test_kept_wrong_kind_does_not_stop_deleting_tests(self):
        """A relay kept with `tests: true` before: the tests are listed, renamed, deleted."""
        import sqlite3
        st, got = self.relay('w6relay-old', ['x'])
        self.assertEqual(st, 200, got)
        db = sqlite3.connect(os.path.join(self.tmp, 'state', 'acme.db'), timeout=30)
        try:
            row = db.execute("SELECT config FROM cert_tests WHERE name = 'w6relay-old'").fetchone()
            cfg = json.loads(row[0])
            cfg['tests'] = True
            db.execute("UPDATE cert_tests SET config = ? WHERE name = 'w6relay-old'",
                       (json.dumps(cfg),))
            db.commit()
        finally:
            db.close()
        st, got = self.relay('w6relay-other', [])
        self.assertEqual(st, 200, got)
        other = got['id']
        st, got = self.call('GET', '/api/tests', None, self.admin)
        self.assertEqual(st, 200, got)
        st, got = self.call('POST', '/api/tests/save', {'id': other, 'name': 'w6relay-other2'},
                            self.admin)
        self.assertEqual(st, 200, got)
        st, got = self.call('POST', '/api/tests/delete', {'id': other}, self.admin)
        self.assertEqual(st, 200, got)

    def test_no_module_said(self):
        for route, word in (('targets', 'target'), ('sources', 'source'),
                            ('validations', 'validation'), ('tests', 'test')):
            st, got = self.call('POST', '/api/%s/test' % route, {'name': 'x'}, self.admin)
            self.assertEqual(st, 400, got)
            self.assertEqual(got['error'], 'which %s: its id - or a module (kind) and its '
                                           'settings to try' % word)
            st, got = self.call('POST', '/api/%s/save' % route, {'name': 'w6nokind'}, self.admin)
            self.assertEqual(st, 400, got)
            self.assertEqual(got['error'], 'a new %s needs its module (kind) - acme --plugins '
                                           'lists them' % word)
        st, got = self.call('POST', '/api/targets/save', {'name': 'w6k', 'kind': 'nosuch'},
                            self.admin)
        self.assertEqual(got.get('error'), 'there is no target module "nosuch"')


class JobWords(unittest.TestCase):
    def test_broken_job_said_with_its_kind(self):
        sys.path.insert(0, TCC.ROOT)
        import acme                                           # noqa: F401 (the engine)
        from acmelib.certs import jobs

        class Job:
            id, cert_id, store, kind, why, made = 'j1', None, None, 'test', '', 0
            state = said = ok = None

            def cancelled(self):
                return False

            def flush(self):
                pass

            def ship(self, *a, **k):
                pass

            def step(self, *a, **k):
                pass

            def finish(self, ok, said):
                self.ok, self.said = ok, said
        saved = jobs._lease_give, jobs.E.log
        jobs._lease_give = lambda *a: None
        jobs.E.log = lambda *a, **k: None
        try:
            def key(job):
                return {}['x']

            def refused(job):
                raise ConnectionRefusedError(111, 'Connection refused')
            self.assertEqual(jobs._work(Job(), key).said, "KeyError: 'x'")
            self.assertEqual(jobs._work(Job(), refused).said, 'Connection refused')
        finally:
            jobs._lease_give, jobs.E.log = saved


class AgentWords(unittest.TestCase):
    def test_allow_issuer_file_not_there(self):
        import subprocess
        import tempfile
        d = tempfile.mkdtemp(prefix='w6-agent-')
        try:
            env = dict(os.environ, ACME_AGENT_ETC=os.path.join(d, 'etc'),
                       ACME_AGENT_STATE=os.path.join(d, 'st'),
                       ACME_AGENT_ROOT_STATE=os.path.join(d, 'rst'),
                       ACME_AGENT_RUN=os.path.join(d, 'run'), ACME_AGENT_NO_SYSTEMD='1',
                       ACME_AGENT_USER='root')
            for x in ('etc', 'st', 'rst', 'run'):
                os.makedirs(os.path.join(d, x))
            r = subprocess.run([sys.executable, os.path.join(TCC.ROOT, 'deploy', 'agent',
                                                             'acme_agent.py'),
                                'allow', 'issuer', os.path.join(d, 'ca.pem')],
                               env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn('there is no file %s' % os.path.join(d, 'ca.pem'), r.stderr)
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
