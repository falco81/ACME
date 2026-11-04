"""The certificates' work in detail for isemon (isemon_detail, 1.0.44): every job's start,
steps (with the module that said each), HTTPS requests and end, and every test's result, as
acme-jobs lines of key=value fields - and nothing secret in any of them.

    python3 test/test_isemon_detail.py
"""
import os
import re
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-idetail-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402,F401
from acmelib import engine as EN  # noqa: E402
import test_certs_core as TCC  # noqa: E402

TOKEN = re.compile(r'([a-z][a-z0-9_]{0,31})=("(?:[^"\\]|\\.)*"|[^ ]*)')


def parse(line):
    body = line.split(']: ', 1)[1]
    out = {}
    for k, v in TOKEN.findall(body):
        if v.startswith('"'):
            v = v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        out[k] = v
    return out


class Redact(unittest.TestCase):
    def test_secrets_out(self):
        r = EN.detail_redact
        self.assertEqual(r('password=Hunter2 user=admin'), 'password=[hidden] user=admin')
        self.assertNotIn('abc.def', r('Authorization: Bearer abc.defghijklmnop'))
        got = r('GET https://u:p@api.ex.cz/x?apikey=SECRET1&zone=ex.cz')
        self.assertNotIn('SECRET1', got)
        self.assertNotIn('u:p', got)
        self.assertIn('zone=ex.cz', got)
        self.assertEqual(r('-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY----- x'),
                         '[private key left out] x')
        self.assertNotIn('zzz123', r('{"api_token": "zzz123", "name": "x"}'))
        self.assertNotIn('Xy9_kq2ZpL4mN8vB3cR7tW1sD6fG0hJ5aQ2', r('id Xy9_kq2ZpL4mN8vB3cR7tW1sD6fG0hJ5aQ2'))
        self.assertNotIn('eyJ', r('jws eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2ln'))
        self.assertEqual(r('tsig_secret: abcd=='), 'tsig_secret: [hidden]')

    def test_what_is_not_secret_stays(self):
        r = EN.detail_redact
        keep = ('serial 04A19C552E0B7F21AB04A19C552E0B7F21AB, sha256 '
                '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08, '
                'key_type ec-256, www.example.cz from Let\'s Encrypt, the key it has is kept')
        self.assertEqual(r(keep), keep)


class Lines(unittest.TestCase):
    """A real renewal, deployment and test by the daemon, read back from acme-jobs.log."""

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.__dict__['ok']
    wait_job = TCC.CertsCore.__dict__['wait_job']

    def lines(self):
        path = os.path.join(self.tmp, 'log', 'acme-jobs.log')
        end = time.time() + 10
        while time.time() < end and not os.path.exists(path):
            time.sleep(0.2)
        time.sleep(1.0)                 # the shipper's thread writes behind
        with open(path, encoding='utf-8') as f:
            return [parse(x) for x in f if 'acme-jobs[' in x]

    def test_10_a_renewal_step_by_step(self):
        self.ok('POST', '/api/settings', {'settings': {'ship_files': 1, 'isemon_detail': 1}})
        self.ok('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                              'config': {'days': 40}})
        cid = self.ok('POST', '/api/certs/save', {
            'name': 'web', 'names': ['www.example.test', 'example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0})['id']
        out = os.path.join(self.tmp, 'out')
        self.ok('POST', '/api/targets/save', {'name': 'fake1', 'kind': 'fake',
                                              'config': {'dir': out, 'password': 's3cret-Pw-77'}})
        self.ok('POST', '/api/deploys/save', {'cert_id': cid, 'target': 'fake1',
                                              'options': {'file': 'web.pem',
                                                          'pfx_password': 'pfx-Secret-99'}})
        jid = self.ok('POST', '/api/certs/renew', {'id': cid})['job_id']
        self.assertEqual(self.wait_job(jid)['state'], 'ok')
        got = [x for x in self.lines() if x.get('job') == str(jid)]
        events = [x['event'] for x in got]
        self.assertEqual(events[0], 'start')
        self.assertEqual(events[-1], 'end')
        self.assertIn('step', events)
        first = got[0]
        for k, v in (('kind', 'job'), ('job_kind', 'renew'), ('cert', 'web'),
                     ('issuer', 'self'), ('issuer_kind', 'selfsigned'), ('node', 'testnode'),
                     ('key_type', 'ec-256')):
            self.assertEqual(first.get(k), v, (k, first))
        self.assertEqual(first['names'], 'www.example.test,example.test')
        steps = [x for x in got if x['event'] == 'step']
        self.assertEqual([int(x['seq']) for x in steps], list(range(1, len(steps) + 1)))
        self.assertTrue(any(x.get('module_kind') == 'target' and x.get('module') == 'fake1'
                            for x in steps), steps)
        end = got[-1]
        self.assertEqual((end['state'], end['ok'], end['level']), ('ok', '1', 'ok'))
        self.assertGreaterEqual(int(end['took_ms']), 0)
        self.assertEqual(end.get('result_version'), '1')
        # nothing secret anywhere
        with open(os.path.join(self.tmp, 'log', 'acme-jobs.log'), encoding='utf-8') as f:
            text = f.read()
        for secret in ('s3cret-Pw-77', 'pfx-Secret-99', 'BEGIN PRIVATE KEY', 'BEGIN EC PRIVATE'):
            self.assertNotIn(secret, text)
        self.__class__.cid = cid

    def test_11_a_test_result(self):
        cid = self.cid
        port = TCC.free_port()          # nothing answers there: the test fails, and says so
        self.ok('POST', '/api/tests/save', {'name': 'web-https', 'kind': 'https',
                                            'config': {'host': '127.0.0.1', 'port': port}})
        att = self.ok('POST', '/api/checks/attach', {'cert_id': cid, 'tests': ['web-https']})
        self.ok('POST', '/api/checks/run', {'id': att['ids'][0]})
        got = [x for x in self.lines() if x.get('kind') == 'check']
        self.assertTrue(got)
        last = got[-1]
        self.assertEqual((last['event'], last['test'], last['test_kind'], last['cert']),
                         ('result', 'web-https', 'https', 'web'))
        self.assertEqual(last['ok'], '0')
        self.assertEqual(last['level'], 'bad')
        self.assertEqual(last.get('went'), 'bad')
        self.assertIn('127.0.0.1', last.get('endpoint', ''))

    def test_12_off(self):
        self.ok('POST', '/api/settings', {'settings': {'isemon_detail': 0}})
        before = len(self.lines())
        jid = self.ok('POST', '/api/certs/renew', {'id': self.cid, 'force': True})['job_id']
        self.wait_job(jid)
        self.assertEqual(len(self.lines()), before)
        self.ok('POST', '/api/settings', {'settings': {'isemon_detail': 1}})


if __name__ == '__main__':
    unittest.main()
