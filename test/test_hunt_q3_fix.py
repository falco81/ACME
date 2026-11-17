#!/usr/bin/env python3
"""Bug hunt q3, the fixes (1.0.119): certificates, targets and deployments, the database agent.

    python3 test/test_hunt_q3_fix.py

The parts on their own (no daemon), then a real daemon in a folder of its own
(test/test_certs_core.py's way) for the API, and its pages from a copy of web/ through
php -S, in Chromium (test/hunt_q3_fix_page.js) when node, php and Playwright are here.

- A revoked certificate said "396 days left" in green, in the list and its window.
- A serial typed with colons (1F:AB:...) found nothing.
- /api/certs/inspect with data_b64 that is no base64 said "nothing was given".
- Import: a key dropped with an earlier certificate stayed for a new one dropped alone.
- The certificate's window: "RSA 2048 · 2048 bits".
- "CSR for an outside CA": the CSR failed after the save - pressed again, "there is one
  called … already".
- A self-signed certificate's chain file: a chain of the plan's own (~600 B), or guessed
  ~1 kB, while it is written empty - and that without a word.
- HAProxy: the previous file dropped before the Runtime API took the new one - when it did
  not, the new file stayed and nothing was put back.
- This machine: no mark of a deployment begun and not finished - acme stopped after the
  files, the next run found them the same and never ran the command.
- Push slots saved empty ("auto" on the server): "Nothing chosen", not saved until picked.
- Taking a target away: "taken off with it" said while "Take it off everywhere first" is off.
- The main tabs at 375 px: each one is what a tap on it hits.
- acme_web.py (pgtls): a line of pg_hba.conf PostgreSQL could not read before refused
  every change of acme's - only more of them than there were count.
- acme_pg_ops: MySQL 8.4+ has no @@have_ssl - the facts said "not running", TLS refused.
"""
import base64
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import test_certs_core as TCC        # noqa: E402  (the daemon, its helpers)
import test_targets as TT            # noqa: E402
from test_targets import FakeBundle, FakeCtx, FakeSsh, make  # noqa: E402


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


def run_py(script, *args):
    return subprocess.run([sys.executable, '-c', script] + list(args), capture_output=True,
                          text=True, timeout=180)


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        if line.strip().startswith('{'):
            return json.loads(line)
    raise AssertionError('no JSON in %r' % text[-2000:])


def self_signed_bundle():
    from acmelib.certs import bundle as B
    from acmelib.certs import pki
    key = pki.make_key('ec-256')
    pem = pki.self_signed(key, ['q3.example.test'], days=30)
    return B.CertBundle('q3', pem, key, [], names=['q3.example.test'])


# ---------------------------------------------------------------------------
class ChainOfASelfSigned(unittest.TestCase):
    def test_preview_says_it_empty(self):
        base = os.path.realpath(tempfile.mkdtemp(dir=TT.TMP))
        t = make('local', {'base': base}, FakeCtx())
        got = t.preview(self_signed_bundle(), {'outputs': ['chain-pem chain.pem',
                                                           'cert-pem cert.pem']})
        files = {f['path']: f for f in got['files']}
        self.assertEqual((files['chain.pem']['size'], files['chain.pem']['exact']), (0, True))
        warns = [p['words'] for p in got['problems'] if p['level'] == 'warn']
        self.assertTrue(any('chain.pem: the certificate has no chain' in w for w in warns), warns)
        # one with its chain: nothing said
        got = t.preview(FakeBundle(), {'outputs': ['chain-pem chain.pem']})
        self.assertFalse([p for p in got['problems'] if 'no chain' in p['words']], got)

    def test_not_issued_yet_guessed_empty(self):
        from acmelib.certs.api_deploys import SampleBundle
        from acmelib.plugins.targets import _script as SC
        sb = SampleBundle('q3', ['q3.example.test'])
        self.assertGreater(SC.size_of(sb, 'chain-pem')[0], 500)    # an ACME one: its chain
        sb.no_chain = True
        self.assertEqual(SC.size_of(sb, 'chain-pem'), (0, True))
        self.assertEqual(SC.size_of(sb, 'fullchain-pem')[0], SC.size_of(sb, 'cert-pem')[0])

    def test_plan_makes_no_chain_of_its_own(self):
        from acmelib.certs import plansandbox as P
        self.assertEqual(P.dummy_bundle({'names': ['q3.example.test'],
                                         'no_chain': True}).chain_pems, [])
        self.assertEqual(len(P.dummy_bundle({'names': ['q3.example.test']}).chain_pems), 1)


class HaproxyPutBack(unittest.TestCase):
    def test_swap_refused_previous_file_back(self):
        d = os.path.realpath(tempfile.mkdtemp(dir=TT.TMP))
        path = os.path.join(d, 'www.pem')
        with open(path, 'w') as f:
            f.write('OLD')
        ssh = FakeSsh(local=True)
        ctx = FakeCtx(ssh=ssh)
        t = make('haproxy', {'host': 'srv', 'socket': os.path.join(d, 'no.sock')}, ctx)
        for opts in ({}, {'backup': False}, {'backup_format': 'dated'}):
            with self.assertRaises(Exception):
                t.deploy(FakeBundle(), dict(opts, cert_path=path))
            with open(path) as f:
                self.assertEqual(f.read(), 'OLD', (opts, ctx.steps))
        self.assertTrue(any('the previous files are back' in w for lv, w in ctx.steps), ctx.steps)


class LocalUnfinished(unittest.TestCase):
    def test_command_runs_after_a_stop(self):
        base = os.path.realpath(tempfile.mkdtemp(dir=TT.TMP))
        ran = os.path.join(base, 'ran')
        cmd = 'touch %s' % ran
        ctx = FakeCtx()
        t = make('local', {'base': base, 'allow_commands': cmd}, ctx)
        o = {'outputs': ['cert-pem cert.pem'], 'command': cmd}
        real = t._run

        def stopped(c):
            raise KeyboardInterrupt('acme stopped')     # not an Exception: nothing put back
        t._run = stopped
        with self.assertRaises(KeyboardInterrupt):
            t.deploy(FakeBundle(), o)
        self.assertTrue(os.path.isfile(os.path.join(base, 'cert.pem')))
        t._run = real
        said = t.deploy(FakeBundle(), o)
        self.assertTrue(os.path.exists(ran), (said, ctx.steps))
        self.assertTrue(any('did not finish' in w for lv, w in ctx.steps), ctx.steps)
        # done: the next one is "unchanged" again, nothing run
        os.unlink(ran)
        said = t.deploy(FakeBundle(), o)
        self.assertTrue(said.startswith('unchanged'), said)
        self.assertFalse(os.path.exists(ran))


class SerialWithColons(unittest.TestCase):
    def test_where(self):
        from acmelib.certs import listsearch as L
        sql, args = L.where('1F:AB:03')
        self.assertIn('%1fab03%', args)
        self.assertIn('%1f:ab:03%', args)          # the words as typed too
        sql, args = L.where('serial:1F:AB:03 state:ok')
        self.assertEqual(args, ['1fab03', 'ok'])
        self.assertEqual(L.where('dns:ab:cd')[1], ['%"ab:cd"%'])     # another field's value


class DbAgentParts(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix='acme-hunt-q3-')
        self.addCleanup(shutil.rmtree, self.t, True)

    def test_pgtls_counts_only_its_own_errors(self):
        script = r"""
import json, os, sys
sys.path.insert(0, sys.argv[2])
import acme_web as W
t = sys.argv[1]
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
r = {'port': 5432, 'db': 'acme', 'user': 'acme', 'peer': '192.0.2.11', 'old_peer': ''}
out = {}
for fn in ('pgtls_hba', 'pgtls_peer'):
    for case, before, after in (('theirs', 1, 1), ('ours', 1, 2), ('clean', 0, 0)):
        put(hba, 'local all all peer\nhost bad line\nhost acme acme 192.0.2.11/32 scram-sha-256\n'
            if fn == 'pgtls_hba' else 'local all all peer\nhost bad line\n')
        errs = [before]
        def sql(port, text, db='postgres'):
            if text == 'SHOW hba_file':
                return hba
            if 'pg_hba_file_rules' in text:
                return str(errs[0])
            if 'pg_reload_conf' in text:
                errs[0] = after                # read again once it is written
            return ''
        put(hba + '.was', rd(hba))
        W.pg_sql = sql
        try:
            said = getattr(W, fn)(dict(r))['said']
        except W.Refused as e:
            said = 'refused: %s' % e
        out[fn + ':' + case] = {'said': said, 'changed': rd(hba) != rd(hba + '.was')}
print(json.dumps(out))
"""
        got = run_py(script, self.t, os.path.join(ROOT, 'deploy'))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        for fn in ('pgtls_hba', 'pgtls_peer'):
            self.assertTrue(out[fn + ':theirs']['changed'], out)
            self.assertFalse(out[fn + ':theirs']['said'].startswith('refused'), out)
            self.assertTrue(out[fn + ':clean']['changed'], out)
            self.assertEqual(out[fn + ':ours']['said'],
                             'refused: PostgreSQL does not read pg_hba.conf as written', out)
            self.assertFalse(out[fn + ':ours']['changed'], out)       # put back

    def test_mysql_84_no_have_ssl(self):
        script = r"""
import json, sys
sys.path.insert(0, sys.argv[2])
import acme_pg_ops as O
out = {}
def mysql84(conf, text, secret=''):
    if 'have_ssl' in text:
        raise O.Refused("MariaDB said: ERROR 1193 (HY000) at line 1: Unknown system variable 'have_ssl'")
    if 'tls_channel_status' in text:
        return 'Yes'
    if 'CONCAT' in text:
        return '8.4.3|' + ('|' if text.count("'|'") == 2 else '') + '/var/lib/mysql/'
    return ''
O.my_sql = mysql84
f = O.facts({'engine': 'mariadb'})
out['84'] = {'running': f.get('running'), 'version': f.get('version'), 'ssl': f.get('ssl')}
out['84_have'] = O.my_have_ssl({})
def maria(conf, text, secret=''):
    if text == 'SELECT @@have_ssl':
        return 'DISABLED'
    return '10.11.6-MariaDB|YES|/var/lib/mysql/'
O.my_sql = maria
f = O.facts({'engine': 'mariadb'})
out['maria'] = {'running': f.get('running'), 'version': f.get('version'), 'ssl': f.get('ssl')}
out['maria_have'] = O.my_have_ssl({})
def other(conf, text, secret=''):
    raise O.Refused('MariaDB said: Access denied')
O.my_sql = other
f = O.facts({'engine': 'mariadb'})
out['down'] = f.get('running')
print(json.dumps(out))
"""
        got = run_py(script, self.t, os.path.join(ROOT, 'deploy'))
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        out = last_json(got.stdout)
        self.assertEqual(out['84'], {'running': True, 'version': '8.4.3', 'ssl': True}, out)
        self.assertEqual(out['84_have'], 'YES')
        self.assertEqual(out['maria'], {'running': True, 'version': '10.11.6-MariaDB',
                                        'ssl': True}, out)
        self.assertEqual(out['maria_have'], 'DISABLED')
        self.assertFalse(out['down'])


# ---------------------------------------------------------------------------
class HuntQ3Daemon(unittest.TestCase):
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']

    @classmethod
    def setUpClass(cls):
        TCC.CertsCore.setUpClass.__func__(cls)
        cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                               'config': {'days': 400}})
        cls.ids = {}
        for name, kt in (('q3-revoked', 'ec-256'), ('q3-rsa', 'rsa-2048')):
            cid = cls.must('POST', '/api/certs/save', {
                'name': name, 'names': [name + '.example.test'], 'issuer': 'self',
                'key_type': kt, 'auto_renew': 0})['id']
            cls.ids[name] = cid
            job = cls.must('POST', '/api/certs/renew', {'id': cid, 'force': True})['job_id']
            end = time.time() + 90
            while time.time() < end:
                st, got = cls.call('GET', '/api/certs/job', None, cls.admin, {'id': job})
                if st == 200 and got['job']['state'] not in ('queued', 'running'):
                    break
                time.sleep(0.3)
        # revoked, as a revocation at its CA leaves it (a self-signed one has no CA to ask)
        db = sqlite3.connect(os.path.join(cls.tmp, 'state', 'acme.db'))
        db.execute("UPDATE certs SET state = 'revoked' WHERE id = ?", (cls.ids['q3-revoked'],))
        db.commit()
        db.close()
        # a target with a deployment: "Take it away" asks
        out = os.path.join(cls.tmp, 'out')
        cls.must('POST', '/api/targets/save', {'name': 'q3-target', 'kind': 'fake',
                                               'config': {'dir': out, 'password': 's3cret'}})
        cls.must('POST', '/api/deploys/save', {'cert_id': cls.ids['q3-rsa'], 'target': 'q3-target',
                                               'options': {'file': 'q3.pem'}})

    @classmethod
    def tearDownClass(cls):
        TCC.CertsCore.tearDownClass.__func__(cls)

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    def one(self, cid):
        got = self.must('GET', '/api/certs/one?id=%d' % cid)
        return got.get('cert') or got

    def test_01_serial_with_colons(self):
        serial = self.one(self.ids['q3-rsa'])['serial']
        self.assertTrue(serial)
        colons = ':'.join(serial[i:i + 2] for i in range(0, len(serial), 2))
        for q in (colons, colons.lower(), 'serial:' + colons, serial):
            st, got = self.call('GET', '/api/certs', None, self.admin, {'search': q})
            self.assertEqual(st, 200, got)
            self.assertEqual([r['name'] for r in got['rows']], ['q3-rsa'], q)

    def test_02_inspect_not_base64(self):
        for bad in ('!!!***', 'not base64 at all, really: ü'):
            st, got = self.call('POST', '/api/certs/inspect', {'data_b64': bad}, self.admin)
            self.assertEqual(st, 400, got)
            self.assertIn('not base64', json.dumps(got), got)
        pem = self.one(self.ids['q3-rsa']).get('cert_pem') or ''
        if pem:
            st, got = self.call('POST', '/api/certs/inspect', {
                'data_b64': base64.b64encode(pem.encode()).decode(), 'filename': 'c.pem'},
                self.admin)
            self.assertEqual(st, 200, got)

    def test_03_the_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        probe = subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                               cwd=ROOT)
        if probe.returncode != 0:
            self.skipTest('no playwright for node here')
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        files = os.path.join(self.tmp, 'q3files')
        os.makedirs(files, exist_ok=True)
        from acmelib.certs import pki
        made = {}
        for n in ('one', 'two'):
            key = pki.make_key('ec-256')
            made[n + '.crt'] = pki.self_signed(key, ['q3-%s.example.test' % n], days=30)
            made[n + '.key'] = key
        for n, body in made.items():
            with open(os.path.join(files, n), 'w') as f:
                f.write(body)
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'hunt_q3_fix_page.js'),
                                  'http://127.0.0.1:%d' % port, 'tester', self.pw, files],
                                 capture_output=True, text=True, timeout=400, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        # revoked: said so, not "… days left" in green
        self.assertEqual(seen['revokedList'], {'text': 'revoked', 'crit': True}, seen)
        self.assertEqual(seen['revokedHead'], [], seen)
        self.assertEqual(seen['revokedBar'], 'crit', seen)
        # the key's size once
        self.assertEqual(seen['keyRow'], 'RSA 2048', seen)
        # import: the key of the first drop not kept for a certificate dropped alone
        self.assertIn('one.key', seen['dropFirst'], seen)
        self.assertNotIn('.key', seen['dropSecond'], seen)
        self.assertEqual(seen['keyNameSecond'], '', seen)
        # the CSR failed, then made with the same certificate
        self.assertIn('openssl went away', seen['csrFirst'], seen)
        self.assertEqual(seen['csrAsked'], 2, seen)
        self.assertNotIn('already', seen['csrToasts'], seen)
        self.assertTrue(seen['csrSecond'].startswith('The CSR of q3-csr-retry'), seen)
        rows = self.must('GET', '/api/certs?search=q3-csr-retry')['rows']
        self.assertEqual([r['name'] for r in rows], ['q3-csr-retry'])
        # push slots saved empty: auto, nothing refused
        self.assertEqual(seen['slotsEmpty'], {'picks': ['auto'], 'nothing': 0}, seen)
        self.assertEqual(seen['slotsSet'], ['auto'], seen)
        # taking the target away: "taken off with it" only with the switch on
        self.assertEqual(seen['chipOff'], [True], seen)
        self.assertEqual(seen['chipOn'], [False], seen)
        # the main tabs at 375 px: a tap on each lands on it
        self.assertTrue(seen['tabs'], seen)
        self.assertEqual([t for t in seen['tabs'] if not t['hit']], [], seen)


if __name__ == '__main__':
    unittest.main(verbosity=2)
