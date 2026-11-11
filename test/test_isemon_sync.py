#!/usr/bin/env python3
"""The first full sync to isemon (1.0.71, acmelib/certs/isemonsync.py).

    python3 test/test_isemon_sync.py

Everything of the certificates as kind=sync lines of acme-jobs: begin, one object a line
(certificate, deployment, check, target, source...), the history of the events and the jobs
step by step with their own times, end - never a module's settings or a key; paced by the
queue; one at a time.
"""
import base64
import os
import queue
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-isemon-sync-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import isemonsync as IS  # noqa: E402
from acmelib.certs import pki  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


class Sink(object):
    def __init__(self):
        self.q = queue.Queue(maxsize=20000)
        self.lines = []

    def put(self, tag, facility, words, ts=None, file_name=None):
        self.lines.append((tag, words, ts, file_name))


class SyncTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.family_save(STORE, 'issuer', {'name': 'Own SS', 'kind': 'selfsigned', 'config': {}}, 'tester')
        A.family_save(STORE, 'target', {'name': 'web1', 'kind': 'webhook',
                                        'config': {'url': 'https://hook.example.test/x?token=SECRET123'}},
                      'tester')
        key = pki.make_key('rsa-2048')
        cert = pki.self_signed(key, ['sync.example.test'], days=90)
        cls.cid = A.cert_import(STORE, {'data_b64': base64.b64encode((cert + key).encode()).decode(),
                                        'filename': 'x.pem'}, 'tester')[0]
        STORE.db.insert('cert_deploys', {'cert_id': cls.cid, 'target': 'web1', 'options': '{}', 'enabled': 1,
                                         'state': 'ok', 'deployed_version': 1})
        STORE.db.insert('cert_checks', {'cert_id': cls.cid, 'test': 't1', 'enabled': 1, 'position': 0,
                                        'last_state': 'ok', 'last_said': 'serves it', 'after_target': 'web1'})
        STORE.db.insert('cert_jobs', {'ts': time.time() - 3600, 'kind': 'deploy', 'cert_id': cls.cid,
                                      'target': 'web1', 'node': 'n1', 'state': 'ok', 'ok': 1,
                                      'finished': time.time() - 3590, 'took_ms': 900, 'by_who': 'acme',
                                      'said': 'deployed', 'version': 1,
                                      'steps': '[[%f, "info", "connecting"], [%f, "ok", "Bearer abcdefghijkl done"]]'
                                      % (time.time() - 3600, time.time() - 3595)})
        STORE.db.insert('cert_jobs', {'ts': time.time() - 400 * 86400, 'kind': 'renew', 'cert_id': cls.cid,
                                      'state': 'ok', 'ok': 1, 'steps': '[]'})

    def run_sync(self, days):
        sink = Sink()
        s = IS.Sync(STORE, 'tester', days, sink)
        IS.STATE.update(running=True)
        s.run()
        return sink, [w for _t, w, _ts, _f in sink.lines]

    def test_everything_once(self):
        sink, lines = self.run_sync(365)
        self.assertTrue(all(t == 'acme-jobs' and f == 'acme-jobs.log' for t, _w, _ts, f in sink.lines))
        self.assertIn('event=begin', lines[0])
        self.assertIn('event=end', lines[-1])
        sid = IS.STATE.get('done_at') and lines[0].split('sync=')[1].split()[0]
        self.assertTrue(all('sync=%s' % sid in w and 'kind=sync' in w for w in lines))
        obj = lambda o: [w for w in lines if 'object=%s ' % o in w]  # noqa: E731
        self.assertEqual(len(obj('certificate')), 1)
        self.assertIn('cert=sync.example.test', obj('certificate')[0])
        self.assertIn('issuer="by hand"', obj('certificate')[0])
        self.assertIn('deploy_state=ok', obj('deployment')[0])
        self.assertIn('after=web1', obj('check')[0])
        self.assertIn('msg="serves it"', obj('check')[0])
        self.assertTrue(obj('target') and obj('source'))
        whole = '\n'.join(lines)
        self.assertNotIn('SECRET123', whole)            # no module's settings
        self.assertNotIn('PRIVATE KEY', whole)
        self.assertNotIn('abcdefghijkl', whole)          # redacted in a step
        hist = [w for w in lines if 'event=history' in w]
        self.assertTrue(any('imported' in w for w in hist))
        job = [w for w in lines if 'event=job ' in w]
        self.assertEqual(len(job), 1)                    # the one of 400 days ago left out
        steps = [(w, ts) for _t, w, ts, _f in sink.lines if 'event=job_step' in w]
        self.assertEqual(len(steps), 2)
        self.assertIn('seq=1', steps[0][0])
        self.assertTrue(steps[0][1] < time.time() - 3000)    # its own time
        self.assertEqual(IS.STATE['phase'], 'done')
        self.assertFalse(IS.STATE['running'])

    def test_no_history(self):
        _sink, lines = self.run_sync(0)
        self.assertFalse([w for w in lines if 'event=history' in w or 'event=job' in w])

    def test_start_refused(self):
        E.CONFIG['isemon'] = 0
        with self.assertRaises(E.ApiError):
            IS.start(STORE, 'tester', 30)
        E.CONFIG['isemon'] = 1
        E.DETAIL_SINK[0] = Sink()
        try:
            with self.assertRaises(E.ApiError):
                IS.start(STORE, 'tester', 99999)
            IS.STATE.update(running=True)
            with self.assertRaises(E.ApiError) as e:
                IS.start(STORE, 'tester', 30)
            self.assertEqual(e.exception.status, 409)
        finally:
            IS.STATE.update(running=False)
            E.DETAIL_SINK[0] = None
            E.CONFIG['isemon'] = 0


if __name__ == '__main__':
    unittest.main()
