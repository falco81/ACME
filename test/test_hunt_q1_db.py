#!/usr/bin/env python3
"""The database server cards and acme-db-agent: regressions of 1.0.119.

    python3 test/test_hunt_q1_db.py

No database server, no daemon: the agent's parts, acme_pg_ops and the engine's functions are
run in a process of their own with what they would ask answered here; the pages in a browser
(test/hunt_q1_db_page.js).

* The agent's `status` says MariaDB's port (my_port) beside pg_port; the card's tile and the
  firewall's row of a MariaDB server say it, not 5432.
* acme_db_agent.py --forget NAME of a node not joined says so (exit 1) and changes nothing.
* MariaDB given a certificate (my_tls): restarted with it and it did not come back (or came
  back without TLS) - its files put back and MariaDB started again with them, not left down.
* This machine's database server (db_local_card) switched off and on within 30 s: looked at
  again at once, not after the next 30 s.
* Joining with the agent's address a bare IPv6 address: the host is all of it (2001:db8::5 was
  the host 2001:db8: at the port 5).
* install.sh --db-agent again without --db-agent-port: the port the agent keeps is the one the
  firewall is opened for and said.
* The wizard: [IPv6]:PORT of the agent joined is not said to replace it.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run_py(script, *args, env=None):
    got = subprocess.run([sys.executable, '-c', script] + list(args), capture_output=True,
                         text=True, timeout=180, env=dict(os.environ, **(env or {})))
    return got


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('{'):
            return json.loads(line)
    raise AssertionError('no JSON in %r' % text[-2000:])


class AgentParts(unittest.TestCase):

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix='acme-hunt-db-')
        self.addCleanup(shutil.rmtree, self.t, True)

    def test_status_says_my_port(self):
        script = r"""
import json, os, sys
sys.path.insert(0, sys.argv[2])
import acme_db_agent as A
t = sys.argv[1]
c = A.conf_read(os.path.join(t, 'agent.json'))
c.update(engine='mariadb', my_port=3307, state=os.path.join(t, 'state'),
         log=os.path.join(t, 'audit.log'), ha_ca=os.path.join(t, 'ha-ca.pem'))
os.makedirs(c['state'])
f = A.Root(c).agent_facts()
print(json.dumps({'pg_port': f.get('pg_port'), 'my_port': f.get('my_port')}))
"""
        got = run_py(script, self.t, os.path.join(ROOT, 'deploy'))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(last_json(got.stdout), {'pg_port': 5432, 'my_port': 3307})

    def test_forget_a_name_not_joined(self):
        conf = os.path.join(self.t, 'agent.json')
        with open(conf, 'w') as f:
            json.dump({'state': os.path.join(self.t, 'state'), 'log': os.path.join(self.t, 'a.log')}, f)
        cl = [{'name': 'acme1', 'fp': 'a' * 64, 'key': 'b' * 64},
              {'name': 'acme2', 'fp': 'c' * 64, 'key': 'd' * 64}]
        with open(os.path.join(self.t, 'clients.json'), 'w') as f:
            json.dump(cl, f)
        prog = os.path.join(ROOT, 'deploy', 'acme_db_agent.py')
        got = subprocess.run([sys.executable, '-I', prog, '--config', conf, '--forget', 'acme3'],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 1, got.stdout + got.stderr)
        self.assertIn('acme3 is not joined here', got.stderr)
        self.assertIn('acme1, acme2', got.stderr)
        self.assertNotIn('no longer let in', got.stdout)
        with open(os.path.join(self.t, 'clients.json')) as f:
            self.assertEqual([x['name'] for x in json.load(f)], ['acme1', 'acme2'])
        got = subprocess.run([sys.executable, '-I', prog, '--config', conf, '--forget', 'acme2'],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIn('acme2 is no longer let in', got.stdout)
        with open(os.path.join(self.t, 'clients.json')) as f:
            self.assertEqual([x['name'] for x in json.load(f)], ['acme1'])

    def test_my_tls_failed_restart_starts_it_again(self):
        script = r"""
import json, os, sys
sys.path.insert(0, sys.argv[2])
import acme_pg_ops as O
t = sys.argv[1]
W = O.W
CERT = '-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----\n'
W.pem_set = lambda cert, key, *a: {'cert': CERT, 'key': 'KEY'}
W.openssl = lambda *a, **k: 'notAfter=Jan  1 00:00:00 2030 GMT'
def put(path, text, mode=0o644, uid=None, gid=None):
    with open(path, 'w') as f:
        f.write(text)
def rd(path):
    with open(path) as f:
        return f.read()
W.pg_file_put, W.pg_file_read, W.write_root = put, rd, put
cnf_dir = os.path.join(t, 'my.cnf.d')
os.makedirs(cnf_dir)
conf = {'engine': 'mariadb', 'my_tls_dir': os.path.join(t, 'tls'), 'my_cnf_dir': cnf_dir,
        'my_user': 'no-such-account-here'}
out = {}
for case in ('down', 'no_tls'):
    starts = []
    def restart(args, c):
        starts.append(os.path.exists(os.path.join(cnf_dir, O.MY_CNF_NAME)))
        if case == 'down' and len(starts) == 1:
            raise O.Refused('MariaDB did not come back after its restart')
        return {'said': 'MariaDB started again'}
    O.op_my_restart = restart
    O.my_sql = lambda c, text, secret='': 'NO'
    try:
        O.op_my_tls({'cert': CERT, 'key': 'KEY', 'trust': CERT}, conf)
        said = ''
    except O.Refused as e:
        said = str(e)
    out[case] = {'said': said, 'starts': starts,
                 'cnf': os.path.exists(os.path.join(cnf_dir, O.MY_CNF_NAME))}
print(json.dumps(out))
"""
        got = run_py(script, self.t, os.path.join(ROOT, 'deploy'))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        # with the new file, then again without it (put back): not left stopped
        self.assertEqual(out['down'], {'said': 'MariaDB did not come back after its restart',
                                       'starts': [True, False], 'cnf': False})
        self.assertEqual(out['no_tls'], {'said': 'MariaDB does not have TLS on with it',
                                         'starts': [True, False], 'cnf': False})


ENGINE = r"""
import json, os, sys, time
t = sys.argv[1]
os.makedirs(t + '/state')
json.dump({'db_engine': 'postgres', 'db_host': '127.0.0.1', 'db_port': 5432, 'db_name': 'acme',
           'db_user': 'acme', 'db_password': 'x' * 12, 'node_name': 'acme1',
           'db_local_card': True}, open(t + '/config.json', 'w'))
os.environ.update(ACME_CONFIG=t + '/config.json', ACME_STATE=t + '/state')
sys.path.insert(0, sys.argv[2])
import acme
acme.load_config()
E = acme._engine
"""


class EngineParts(unittest.TestCase):

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix='acme-hunt-db-')
        self.addCleanup(shutil.rmtree, self.t, True)

    def test_local_card_looked_at_again_at_once(self):
        script = ENGINE + r"""
class DB:
    def run(self, *a, **k): return 0
class S:
    db = DB()
E.DBLOCAL_STATE.update(wrote=True, at=time.time())
E.db_local_drop(S())
print(json.dumps({'wrote': E.DBLOCAL_STATE['wrote'], 'at': E.DBLOCAL_STATE['at'],
                  'every': E.DBLOCAL_EVERY, 'due': time.time() - E.DBLOCAL_STATE['at'] >= E.DBLOCAL_EVERY}))
"""
        got = run_py(script, self.t, ROOT)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        self.assertIs(out['wrote'], False)
        self.assertTrue(out['due'], out)

    def test_join_bare_ipv6_address(self):
        script = ENGINE + r"""
import base64
seen = []
def http(host, port, path, *a, **k):
    seen.append([host, port])
    raise OSError('nothing there')
E._db_agent_http = http
data = {'h': '192.0.2.21', 'p': 9443, 's': 'secret', 'i': 'abcd', 'f': 'a' * 64, 'k': 'b' * 64,
        'e': 'postgres'}
code = 'ADBA1.' + base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
out = []
for addr in ('2001:db8::5', '[2001:db8::5]:9555', '[2001:db8::5]', '192.0.2.30:9556', 'db1'):
    seen.clear()
    try:
        E.db_agent_join(None, code, addr)
    except ValueError:
        pass
    out.append(seen[0] if seen else None)
print(json.dumps(out))
"""
        got = run_py(script, self.t, ROOT)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(last_json('{"x": %s}' % got.stdout.strip().splitlines()[-1])['x'],
                         [['2001:db8::5', 9443], ['2001:db8::5', 9555], ['2001:db8::5', 9443],
                          ['192.0.2.30', 9556], ['db1', 9443]])


class DeployScript(unittest.TestCase):

    def test_kept_agent_port_is_the_one_opened(self):
        t = tempfile.mkdtemp(prefix='acme-hunt-db-')
        self.addCleanup(shutil.rmtree, t, True)
        with open(os.path.join(t, 'agent.json'), 'w') as f:
            json.dump({'port': 9555, 'engine': 'postgres'}, f)
        stubs = ('run() { echo "[would run] $*"; return 0; }\nsay() { echo "$*"; }\n'
                 'note() { echo "$*"; }\nwarn() { echo "$*"; }\ngood() { echo "$*"; }\n'
                 'step() { echo "$*"; }\nfail() { echo "FAIL $*"; exit 1; }\n'
                 'write_file() { cat >/dev/null; }\ndbs_systemd() { return 1; }\n'
                 'C_BAD=""; C_OFF=""; PKG=dnf; DRY_RUN=yes; SOURCE_DIR=%s\n' % ROOT)
        out = {}
        for given in ('', 'yes'):
            script = (stubs + '. %s\n' % os.path.join(ROOT, 'deploy', 'db-server.sh')
                      + 'AGENT_ETC=%s; DB_SERVER=postgres; DB_AGENT_PORT=%s; '
                        'DB_AGENT_PORT_GIVEN=%s\n' % (t, '9600' if given else '9443', given)
                      + 'agent_install >/dev/null\necho "PORT=$DB_AGENT_PORT"\n')
            got = subprocess.run(['bash', '-c', 'set -Eeuo pipefail\n' + script],
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            out[given] = got.stdout.strip().splitlines()[-1]
        self.assertEqual(out[''], 'PORT=9555')        # kept: the agent's own
        self.assertEqual(out['yes'], 'PORT=9600')     # given (written there unless --dry-run)


class Pages(unittest.TestCase):

    def test_ports_and_wizard(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(HERE, 'hunt_q1_db_page.js'),
                              os.path.join(ROOT, 'web')], capture_output=True, text=True,
                             timeout=300)
        out = last_json(got.stdout or '{}')
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
