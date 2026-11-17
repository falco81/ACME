#!/usr/bin/env python3
"""Bug hunt q2 (1.0.119): the database server cards, acme-db-agent's parts and the portal.

    python3 test/test_hunt_q2_dbportal.py

No database server: acme_pg_ops, db-server.sh and the engine's functions are run in a process
of their own with what they would ask answered here; the portal against a real daemon in a
folder of its own (test/test_certs_core.py's way); the pages in a browser
(test/hunt_q2_dbportal_page.js) when node and Playwright are here.

* Joining an agent whose `status` does not answer in time once agent.json and the keys are
  written: joined all the same (it was a 400 and "Nothing was changed on this node").
* hba_add: a line of somebody else's PostgreSQL cannot read is not taken for the one added.
* The facts of MariaDB whose @@have_ssl is NULL: running, not a failed status.
* db-server.sh my_configure with no folder of MariaDB's configuration: nothing written into a
  folder that is not there.
* The card's hero wraps at a phone's width; "Last heard" red by how long ago, not by the
  database's state; the wizard's last step not said running when the agent was late.
* /api/portal/me with a one-time code asked now and never given: signed out, as /api/portal/*.
* /api/portal/art save, the picture of one's own taken away and custom picked: refused, the
  picture kept.
* The request limit counts a long sign-in name (created_by is cut to 180 characters).
* An administrator who sees every certificate: a team's certificate of their own name is not
  theirs ("me").
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)


def run_py(script, *args, env=None):
    return subprocess.run([sys.executable, '-c', script] + list(args), capture_output=True,
                          text=True, timeout=180, env=dict(os.environ, **(env or {})))


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('{') or line.startswith('['):
            return json.loads(line)
    raise AssertionError('no JSON in %r' % text[-2000:])


ENGINE = r"""
import json, os, sys, time
t = sys.argv[1]
os.makedirs(t + '/state')
json.dump({'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': 5432, 'db_name': 'acme',
           'db_user': 'acme', 'db_password': 'x' * 12, 'node_name': 'acme1'},
          open(t + '/config.json', 'w'))
os.environ.update(ACME_CONFIG=t + '/config.json', ACME_STATE=t + '/state')
sys.path.insert(0, sys.argv[2])
import acme
acme.load_config()
E = acme._engine
"""


class DbParts(unittest.TestCase):

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix='acme-hunt-q2-')
        self.addCleanup(shutil.rmtree, self.t, True)

    def test_join_late_status_is_joined(self):
        script = ENGINE + r"""
import base64
data = {'h': '192.0.2.21', 'p': 9443, 's': 'secret', 'i': 'abcd', 'f': 'a' * 64, 'k': 'b' * 64,
        'e': 'postgres'}
code = 'ADBA1.' + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
def http(host, port, path, body, *a, **k):
    if path == '/v1/enroll/key':
        return 200, json.dumps({'pub': 'PUB'}).encode(), {}
    return 200, json.dumps({'ok': True, 'token': 'tk', 'version': '1.0.119',
                            'engine': 'postgres', 'pg_port': 5432}).encode(), {}
E._db_agent_http = http
E._db_agent_pub_fp = lambda pem: 'b' * 64
E._db_agent_seal = lambda pub, fields: 'sealed'
E.hatls_ca_ensure = lambda store, by: None
E.hatls_issue = lambda *a, **k: ('KEY', 'CRT')
E.hatls_ca = lambda store: 'CA'
E.hatls_trust = lambda ca: 'TRUST'
E._db_agent_fp = lambda pem: 'c' * 64
E._cert_end = lambda pem: 0
E._db_agent_set_hash = lambda t: 'h'
E.service_ids = lambda: None
E.db_agent_fw = lambda *a, **k: {'said': []}
E.db_agent_ha_ca_local = lambda trust: None
E.db_agent_my_address = lambda *a: '192.0.2.11'
calls = []
def status(op, *a, **k):
    calls.append(op)
    raise ValueError('the database agent at 192.0.2.21:9443 does not answer')
E.db_agent_call = status
clock = [time.time()]
time.time = lambda: clock[0]
time.sleep = lambda s: clock.__setitem__(0, clock[0] + s)
class Store:
    events = []
    def add_event(self, *a, **k): self.events.append(a)
said = []
try:
    got = E.db_agent_join(Store(), code, '', say=said.append)
    err = ''
except ValueError as e:
    got, err = {}, str(e)
print(json.dumps({'err': err, 'late': got.get('late'), 'facts': got.get('facts'),
                  'joined': (E.db_agent() or {}).get('db_admin'), 'said': said,
                  'asked': len(calls), 'events': len(Store.events)}))
"""
        got = run_py(script, self.t, ROOT)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        self.assertEqual(out['err'], '')
        self.assertIn('does not answer', out['late'])
        self.assertEqual(out['facts'], {})
        self.assertEqual(out['joined'], 'agent:192.0.2.21:9443')
        self.assertGreater(out['asked'], 1)                 # waited for, then went on
        self.assertTrue(any('joined all the same' in x for x in out['said']), out['said'])
        self.assertEqual(out['events'], 1)

    def test_hba_add_counts_only_its_own_errors(self):
        script = r"""
import json, os, sys
sys.path.insert(0, sys.argv[2])
import acme_pg_ops as O
t = sys.argv[1]
W = O.W
hba = os.path.join(t, 'pg_hba.conf')
def put(path, text, mode=0o644, uid=None, gid=None):
    with open(path, 'w') as f:
        f.write(text)
def rd(path):
    with open(path) as f:
        return f.read()
W.pg_file_put, W.pg_file_read = put, rd
W.pg_file_copy = lambda a, b: put(b, rd(a))
W.pg_path_checked = lambda p, **k: p
W.pg_peer_net = lambda who: who + '/32'
out = {}
for case, before, after in (('theirs', 1, 1), ('ours', 1, 2), ('clean', 0, 0)):
    put(hba, 'local all all peer\nhost bad line\n')
    errs = [before]
    def sql(port, text, db='postgres'):
        if text == 'SHOW hba_file':
            return hba
        if 'pg_hba_file_rules' in text:
            n = errs[0]
            errs[0] = after                    # read again once it is written
            return str(n)
        return ''
    W.pg_sql = sql
    try:
        said = O.hba_add({'pg_port': 5432}, 'acme', 'acme', ['192.0.2.11'], 'allow')
    except O.Refused as e:
        said = 'refused: %s' % e
    out[case] = {'said': said, 'in': '192.0.2.11/32' in rd(hba)}
print(json.dumps(out))
"""
        got = run_py(script, self.t, os.path.join(ROOT, 'deploy'))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        self.assertTrue(out['theirs']['in'], out)
        self.assertIsInstance(out['theirs']['said'], list)
        self.assertTrue(out['clean']['in'], out)
        self.assertEqual(out['ours']['said'], 'refused: PostgreSQL does not read pg_hba.conf as '
                                              'written')
        self.assertFalse(out['ours']['in'], out)         # put back

    def test_mariadb_facts_have_ssl_null(self):
        script = r"""
import json, sys
sys.path.insert(0, sys.argv[2])
import acme_pg_ops as O
out = {}
for case, answer in (('null', 'NULL'), ('empty', ''), ('whole', '10.11.6-MariaDB|YES|/var/lib/mysql/'),
                     ('no_ssl', '10.11.6-MariaDB||/var/lib/mysql/')):
    O.my_sql = lambda conf, text, secret='', a=answer: a
    f = O.facts({'engine': 'mariadb'})
    out[case] = {'running': f.get('running'), 'version': f.get('version'), 'ssl': f.get('ssl')}
print(json.dumps(out))
"""
        got = run_py(script, self.t, os.path.join(ROOT, 'deploy'))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        self.assertEqual(out['null'], {'running': True, 'version': '', 'ssl': False})
        self.assertEqual(out['empty'], {'running': True, 'version': '', 'ssl': False})
        self.assertEqual(out['whole'], {'running': True, 'version': '10.11.6-MariaDB', 'ssl': True})
        self.assertEqual(out['no_ssl']['ssl'], False)
        with open(os.path.join(ROOT, 'deploy', 'acme_pg_ops.py'), encoding='utf-8') as f:
            self.assertIn("IFNULL(@@have_ssl, '')", f.read())

    def test_my_configure_no_config_folder(self):
        with open(os.path.join(ROOT, 'deploy', 'db-server.sh'), encoding='utf-8') as f:
            text = f.read()
        fn = re.search(r'\nmy_configure\(\) \{\n.*?\n\}\n', text, re.S).group(0)
        out = {}
        for case in ('none', 'debian'):
            etc = os.path.join(self.t, case)
            os.makedirs(etc)
            if case == 'debian':
                os.makedirs(os.path.join(etc, 'mysql', 'mariadb.conf.d'))
            body = fn.replace('/etc/', etc + '/')
            stubs = ('run() { :; }\nsay() { echo "$*"; }\nnote() { echo "$*"; }\n'
                     'warn() { echo "WARN $*"; }\ngood() { echo "$*"; }\nstep() { :; }\n'
                     'my_q() { echo 0; }\nmy_q_secret() { :; }\ndbs_systemd() { return 1; }\n'
                     'write_file() { echo "WROTE $1"; cat >/dev/null; }\n'
                     'C_BAD=""; C_OFF=""; DRY_RUN=""; DBS_NAME=acme; DBS_USER=acme; '
                     'DBS_PASSWORD=x; ACME_NODES=192.0.2.11\n')
            got = subprocess.run(['bash', '-c', 'set -Eeuo pipefail\n' + stubs + body
                                  + 'my_configure\n'], capture_output=True, text=True,
                                 timeout=60)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            out[case] = [x for x in got.stdout.splitlines() if x.startswith(('WROTE', 'WARN'))]
        self.assertEqual(len(out['none']), 1, out)
        self.assertTrue(out['none'][0].startswith('WARN no folder of MariaDB'), out)
        self.assertEqual(out['debian'][:1], ['WROTE %s/mysql/mariadb.conf.d/zz-acme-listen.cnf'
                                         % os.path.join(self.t, 'debian')])

    def test_request_limit_long_name(self):
        script = r"""
import json, os, sys
t = sys.argv[1]
os.environ.update(ACME_CONFIG=t + '/config.json', ACME_STATE=t)
json.dump({'node_name': 'acme1'}, open(t + '/config.json', 'w'))
sys.path.insert(0, sys.argv[2])
import acme
from acmelib.certs import portal as P
seen = []
class DB:
    def value(self, q, args, default=None):
        seen.append(args[0])
        return 0
class Store:
    db = DB()
long = 'CN=' + 'x' * 200 + ',OU=People,DC=corp,DC=test'
P.used(Store(), long)
P.used(Store(), 'short')
print(json.dumps({'seen': seen, 'word': P.asked_word(long)}))
"""
        got = run_py(script, self.t, ROOT)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        self.assertEqual(out['seen'][0], out['word'])
        self.assertEqual(len(out['seen'][0]), len('portal:') + 180)
        self.assertEqual(out['seen'][1], 'portal:short')
        for rel in ('acmelib/certs/portal.py', 'acmelib/certs/reqprofiles.py'):
            with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
                src = f.read()
            self.assertNotIn("'created_by': 'portal:' + who", src, rel)
            self.assertIn('asked_word(who)', src, rel)


import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)

SVG = (b'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
       b'<rect width="10" height="10"/></svg>')


class Portal(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.spool = os.path.join(cls.tmp, 'sms')
        os.makedirs(cls.spool, exist_ok=True)
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 40}})
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_tries': 50, 'portal_admins_all': 1,
            'portal_cert': 1, 'portal_cert_suffixes': 'example.test',
            'portal_cert_issuers': 'self',
            'sms_mode': 'spool', 'sms_spool_dir': cls.spool}})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def portal(self):
        st, got = self.call('POST', '/api/portal/login', {'name': 'tester', 'password': self.pw})
        self.assertEqual(st, 200, got)
        self.assertNotIn('gate', got)
        return got['token']

    def test_01_whoami_code_asked_now(self):
        tok = self.portal()
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertEqual(st, 200, me)
        self.assertTrue(me['me'] and me['me'].get('name'), me)
        self.must('POST', '/api/settings', {'settings': {'portal_code': 'sms',
                                                         'portal_local_code': 'same'}})
        try:
            st, me = self.call('GET', '/api/portal/me', None, tok)
            self.assertEqual(st, 200, me)
            self.assertIsNone(me['me'], me)             # not drawn signed in
            st, _ = self.call('GET', '/api/portal/certs', None, tok)
            self.assertEqual(st, 401)
        finally:
            self.must('POST', '/api/settings', {'settings': {'portal_code': 'off'}})
        tok = self.portal()
        st, me = self.call('GET', '/api/portal/me', None, tok)
        self.assertTrue(me['me'] and me['me'].get('name'), me)

    def test_02_art_save_forget_custom_refused_first(self):
        data = base64.b64encode(SVG).decode()
        self.must('POST', '/api/portal/art', {'action': 'upload', 'slot': 'portal', 'data': data,
                                              'name': 'mine.svg'})
        st, got = self.call('POST', '/api/portal/art', {'action': 'save', 'slot': 'portal',
                                                        'art': 'custom', 'forget': 1}, self.admin)
        self.assertEqual(st, 400, got)
        art = self.must('GET', '/api/portal/art')['portal']
        self.assertTrue(art.get('logo'), art)            # kept
        self.assertEqual(art['art'], 'custom')
        # taking it away with another picture picked still works
        got = self.must('POST', '/api/portal/art', {'action': 'save', 'slot': 'portal',
                                                    'art': art['default'], 'forget': 1})
        self.assertFalse(got['portal'].get('logo'), got)

    def test_03_admin_sees_all_team_of_their_name(self):
        st, got = self.call('POST', '/api/teams/save', {'name': 'tester', 'members': [
            'local:certer=view']}, self.admin)
        if st != 200:
            self.skipTest('a team of that name is not taken here: %s' % got)
        self.must('POST', '/api/certs/save', {
            'name': 'q2-team', 'names': ['q2-team.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'tester'})
        tok = self.portal()
        st, got = self.call('GET', '/api/portal/certs', None, tok)
        self.assertEqual(st, 200, got)
        seen = {r['name']: r['via'] for r in got['rows']}
        self.assertIn('q2-team', seen)
        self.assertNotEqual(seen['q2-team'], 'me', seen)


class Pages(unittest.TestCase):

    def test_cards_and_wizard(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60, cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(HERE, 'hunt_q2_dbportal_page.js'),
                              os.path.join(ROOT, 'web')], capture_output=True, text=True,
                             timeout=300, cwd=ROOT)
        out = last_json(got.stdout or '{}')
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
