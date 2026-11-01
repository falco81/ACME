#!/usr/bin/env python3
"""A kept secret is never shown in clear - anywhere.

    python3 test/test_secrets_shown.py      (or python3 -m unittest test.test_secrets_shown)

The customer's rule: a stored password or secret, where it is shown at all, is
shown to a full administrator as eight dots and its last two characters, to
anybody else as dots only (or not at all); saved back as it was shown (dots),
the one kept stays.

A real daemon in a folder of its own (test/test_certs_core.py's way, on an
unusual api_port): every secret it keeps is set - the settings' (mail, SMS,
the proxy, the remote backups, SNMP, the metrics token, the DNS of the pages'
own ACME), a directory's password, a remote backup destination's password,
a source's, a validation's (an SSH key in PEM too), a target's and a
deployment's - and then every route that answers GET is asked as a full
administrator, a certificate administrator and a reader: no secret appears in
clear in any answer; a full administrator gets the dots and the last two, the
others dots only. The masked values saved back keep the secrets (opened in
process to see), the configuration export carries dots (or, with the secrets,
is locked), and the command line shows dots and the last two.
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_certs_core as TCC        # noqa: E402  (its fake target, its helpers)

DOTS = '•' * 8

# Every secret ends in its own two characters and holds a core seen nowhere
# else: the core found in an answer is a secret given away.
SETTINGS = {
    'smtp_password': 'SmtpPwCORE1-xq',
    'sms_token': 'SmsTokCORE2-xw',
    'sms_tel_password': 'SmsTelCORE3-xe',
    'rbackup_password': 'RbackCORE4-Long-xr',
    'proxy_password': 'ProxyCORE5-xt',
    'snmp_auth_pass': 'SnmpAuthCORE6-xy',
    'snmp_priv_pass': 'SnmpPrivCORE7-xu',
    'metrics_token': 'MetricsTokenCORE8abcdefghij',
    'acme_dns_tsig_secret': 'QUJDREVGR0hJSktMTU5PUFFSU1RVCORE9',
    'acme_dns_token': 'AcmeDnsTokCOREa-xo',
    'acme_desec_token': 'DesecTokenCOREbabcdefgh',
}
OTHERS = {
    'bind_pw': 'BindPwCOREc-xa',
    'rb_target': 'RbTargetCOREd-xs',
    'target': 's3cretCOREe-xd',
    'deploy': 'PfxCOREf-xf',
    'eab': 'EabHmacCOREg-xg',
    'ssh_pass': 'SshPassCOREh-xh',
}
SSH_KEY = ('-----BEGIN OPENSSH PRIVATE KEY-----\n'
           'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n'
           'QyNTUxOQAAACBSshKeyCOREiDEADBEEFlinesOfBase64TextQq==\n'
           '-----END OPENSSH PRIVATE KEY-----\n')
CORES = [re.search(r'CORE\w', v).group(0) for v in list(SETTINGS.values()) +
         list(OTHERS.values()) + [SSH_KEY]]
# What the full administrator sees of the SSH key: the last two of its body.
SSH_KEY_SHOWN = DOTS + 'Qq'

# The routes that answer GET but are files, need a thing named, or are the
# portal's own (a person signed in there).
SKIP = {'/api/db/download', '/api/rbackup/download', '/api/portal/logo', '/api/portal/art',
        '/api/mailq/one', '/api/acme/challenge', '/api/certs/job', '/api/cas/one'}


def get_routes():
    """Every path of a GET route of the engine and the certificate manager."""
    found = set()
    for folder in ('acmelib/engine', 'acmelib/certs'):
        for name in sorted(os.listdir(os.path.join(ROOT, folder))):
            if not name.endswith('.py'):
                continue
            with open(os.path.join(ROOT, folder, name), encoding='utf-8') as f:
                text = f.read()
            found.update(re.findall(r"(?:route|api)\('GET', '(/api/[^'%]+)'", text))
    found.update({'/api/sources', '/api/validations', '/api/targets'})
    return sorted(found - SKIP)


class SecretsShown(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-secrets-test-')
        for d in ('state', 'run', 'log', 'plugins/targets', 'out'):
            os.makedirs(os.path.join(cls.tmp, d), exist_ok=True)
        with open(os.path.join(cls.tmp, 'plugins/targets/fake_target.py'), 'w') as f:
            f.write(TCC.FAKE_TARGET.replace("'s3cret'", repr(OTHERS['target'])))
        cls.port = 39871
        try:
            s = socket.socket()
            s.bind(('127.0.0.1', cls.port))
            s.close()
        except OSError:
            cls.port = TCC.free_port()
        free = TCC.free_port
        conf = {'api_port': cls.port, 'radius_bind': '127.0.0.1',
                'radius_auth_port': free(), 'radius_acct_port': free(),
                'ssh_gate_port': free(), 'node_name': 'secretnode', 'upgrade_check': 0,
                'db_password': 'DbPwCOREz-xz'}
        CORES.append('COREz')
        cls.conf = os.path.join(cls.tmp, 'config.json')
        with open(cls.conf, 'w') as f:
            json.dump(conf, f)
        cls.env = dict(os.environ, ACME_CONFIG=cls.conf,
                       ACME_STATE=os.path.join(cls.tmp, 'state'),
                       ACME_RUN=os.path.join(cls.tmp, 'run'),
                       ACME_LOGDIR=os.path.join(cls.tmp, 'log'),
                       ACME_PLUGINS=os.path.join(cls.tmp, 'plugins'),
                       ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        cls.pw = 'Test-Password-4711!'
        made = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); '
            'st.add_account("tester", "fulladmin", %r); '
            'st.add_account("certer", "certadmin", %r); '
            'st.add_account("viewer", "readonly", %r)') % (ROOT, cls.pw, cls.pw, cls.pw)],
            env=cls.env, capture_output=True, text=True, timeout=120)
        if made.returncode != 0:
            raise RuntimeError('the accounts could not be made: %s' % made.stderr[-2000:])
        cls.daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                      env=cls.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, cwd=cls.tmp)
        end = time.time() + 60
        while time.time() < end:
            if cls.daemon.poll() is not None:
                raise RuntimeError('the daemon stopped: %s' % cls.daemon.stdout.read()
                                   .decode('utf-8', 'replace')[-3000:])
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/api/health' % cls.port, timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError('the daemon did not answer within a minute')
        with open(os.path.join(cls.tmp, 'run', 'api-token')) as f:
            cls.token = f.read().strip()
        cls.admin = cls.login('tester')
        cls.certer = cls.login('certer')
        cls.ro = cls.login('viewer')
        cls.put_secrets()

    tearDownClass = TCC.CertsCore.__dict__['tearDownClass']
    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    cli = TCC.CertsCore.cli
    cli_ok = TCC.CertsCore.cli_ok
    cli_json = TCC.CertsCore.cli_json
    py = TCC.CertsCore.py

    @classmethod
    def must(cls, method, path, body=None):
        st, got = cls.call(method, path, body, cls.admin)
        if st != 200:
            raise RuntimeError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def put_secrets(cls):
        cls.must('POST', '/api/settings', {'settings': dict(SETTINGS)})
        cls.must('POST', '/api/directories', {'action': 'save', 'directory': {
            'name': 'corp', 'hosts': 'dc1.example.test', 'tls': 'ldaps',
            'base': 'DC=example,DC=test', 'bind_dn': 'CN=acme,DC=example,DC=test',
            'bind_pw': OTHERS['bind_pw'], 'enabled': 0}})
        got = cls.must('POST', '/api/rbackup', {'action': 'save', 'target': {
            'kind': 'ftps', 'name': 'offsite', 'host': 'backup.example.test', 'user': 'acme',
            'path': '/acme', 'password': OTHERS['rb_target'], 'enabled': 0}})
        cls.rb_id = got['target']['id']
        out = os.path.join(cls.tmp, 'out')
        cls.target_id = cls.must('POST', '/api/targets/save', {
            'name': 'fake1', 'kind': 'fake',
            'config': {'dir': out, 'password': OTHERS['target']}})['id']
        cls.source_id = cls.must('POST', '/api/sources/save', {
            'name': 'eab-ca', 'kind': 'acme', 'config': {
                'directory': 'custom', 'url': 'https://ca.example.test/directory',
                'eab_kid': 'kid1', 'eab_hmac': OTHERS['eab']}})['id']
        cls.val_id = cls.must('POST', '/api/validations/save', {
            'name': 'web-ssh', 'kind': 'http_ssh', 'config': {
                'hosts': ['192.0.2.21'], 'user': 'acme', 'auth': 'key', 'key': SSH_KEY,
                'password': OTHERS['ssh_pass']}})['id']
        sid = cls.must('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                                     'config': {'days': 40}})['id']
        assert sid
        cls.cert_id = cls.must('POST', '/api/certs/save', {
            'name': 'web', 'names': ['www.example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0})['id']
        cls.deploy_id = cls.must('POST', '/api/deploys/save', {
            'cert_id': cls.cert_id, 'target': 'fake1',
            'options': {'file': 'web.pem', 'pfx_password': OTHERS['deploy']}})['id']

    # ---- looking ---------------------------------------------------------------------
    def assertNoClear(self, text, where):
        for core in CORES:
            self.assertNotIn(core, text, '%s gives a secret away (%s)' % (where, core))

    def answers(self, session):
        out = {}
        for path in get_routes():
            st, got = self.call('GET', path, None, session)
            out[path] = (st, json.dumps(got, ensure_ascii=False))
        for path, args in (('/api/certs/one', {'id': self.cert_id}),
                           ('/api/deploys', {'target': 'fake1'}),
                           ('/api/export', {'secrets': '0'})):
            st, got = self.call('GET', path, None, session, args)
            out[path + '?' + urllib.parse.urlencode(args)] = (st, json.dumps(got, ensure_ascii=False))
        return out

    def test_01_no_route_gives_a_secret_away(self):
        if os.environ.get('ACME_TEST_SHOW'):
            for path, (st, text) in sorted(self.answers(self.admin).items()):
                print(st, path, len(text))
        for who, session in (('fulladmin', self.admin), ('certadmin', self.certer),
                             ('readonly', self.ro)):
            got = self.answers(session)
            self.assertGreater(len([1 for st, _ in got.values() if st == 200]),
                               40 if who == 'fulladmin' else 25, who)
            for path, (st, text) in got.items():
                self.assertNoClear(text, '%s as %s' % (path, who))

    def test_02_settings(self):
        rows = {r['key']: r for r in self.ok('GET', '/api/settings')['settings']}
        for k, v in SETTINGS.items():
            self.assertEqual(rows[k]['value'], DOTS + v[-2:], k)
            self.assertTrue(rows[k]['set'], k)
        self.assertEqual(rows['db_password']['value'], DOTS + 'xz')
        for session in (self.certer, self.ro):
            rows = {r['key']: r for r in self.ok('GET', '/api/settings', session=session)['settings']}
            for k in list(SETTINGS) + ['db_password']:
                self.assertEqual(rows[k]['value'], DOTS, k)
        # Saved back as shown: kept (opened in process to see).
        rows = {r['key']: r for r in self.ok('GET', '/api/settings')['settings']}
        self.ok('POST', '/api/settings', {'settings': {k: rows[k]['value'] for k in SETTINGS}})
        kept = self.py('print(json.dumps({k: E.unseal_secret(v) for k, v in '
                       'st.settings_saved().items() if k in E.SEALED_KEYS}))')
        self.assertEqual(kept, SETTINGS)

    def test_03_directory(self):
        d = self.ok('GET', '/api/directories')['directories'][0]
        self.assertEqual(d['bind_pw'], DOTS + 'xa')
        for session in (self.certer, self.ro):
            d2 = self.ok('GET', '/api/directories', session=session)['directories'][0]
            self.assertEqual(d2['bind_pw'], DOTS)
        self.ok('POST', '/api/directories', {'action': 'save', 'directory': dict(
            d, bind_pw=d['bind_pw'])})
        got = self.py('print(json.dumps(st.directory("corp", with_secret=True)["bind_pw"]))')
        self.assertEqual(got, OTHERS['bind_pw'])

    def test_04_remote_backup(self):
        t = [x for x in self.ok('GET', '/api/rbackup')['targets'] if x['id'] == self.rb_id][0]
        self.assertEqual(t['password'], DOTS + 'xs')
        self.ok('POST', '/api/rbackup', {'action': 'save', 'id': self.rb_id, 'target': dict(t)})
        got = self.py('print(json.dumps(E.rb_secret(E.rb_target(st, %r), "password")))'
                      % self.rb_id)
        self.assertEqual(got, OTHERS['rb_target'])

    def test_05_modules(self):
        def row(path, ident, session=None):
            return [r for r in self.ok('GET', path, session=session)['rows'] if r['id'] == ident][0]
        t = row('/api/targets', self.target_id)
        self.assertEqual(t['config']['password'], DOTS + 'xd')
        self.assertEqual(t['secret_set'], ['password'])
        s = row('/api/sources', self.source_id)
        self.assertEqual(s['config']['eab_hmac'], DOTS + 'xg')
        v = row('/api/validations', self.val_id)
        self.assertEqual(v['config']['password'], DOTS + 'xh')
        self.assertEqual(v['config']['key'], SSH_KEY_SHOWN)
        self.assertEqual(sorted(v['secret_set']), ['key', 'password'])
        d = self.ok('GET', '/api/certs/one', args={'id': self.cert_id})['deploys'][0]
        self.assertEqual(d['options']['pfx_password'], DOTS + 'xf')
        for session in (self.certer, self.ro):
            self.assertEqual(row('/api/targets', self.target_id, session)['config']['password'],
                             DOTS)
            self.assertEqual(row('/api/validations', self.val_id, session)['config']['key'], DOTS)
            dd = self.ok('GET', '/api/certs/one', args={'id': self.cert_id},
                         session=session)['deploys'][0]
            self.assertEqual(dd['options']['pfx_password'], DOTS)
        # Saved back as shown (and as a certificate administrator saw it): kept.
        self.ok('POST', '/api/targets/save', {'id': t['id'], 'name': 'fake1', 'kind': 'fake',
                                              'config': t['config']})
        self.ok('POST', '/api/validations/save', {'id': v['id'], 'name': 'web-ssh',
                                                  'kind': 'http_ssh', 'config': v['config']})
        self.ok('POST', '/api/sources/save', {'id': s['id'], 'name': 'eab-ca', 'kind': 'acme',
                                              'config': s['config']})
        self.ok('POST', '/api/deploys/save', {'id': self.deploy_id, 'options': {
            'file': 'web.pem', 'pfx_password': DOTS}}, session=self.certer)
        tested = self.ok('POST', '/api/targets/test', {'id': t['id'], 'config': t['config']})
        self.assertTrue(tested['ok'], tested)
        self.assertNoClear(json.dumps(tested), 'the test of a target')
        got = self.py(
            'from acmelib.certs import store as S\n'
            'out = {}\n'
            'for fam, ident in (("target", %d), ("challenge", %d), ("issuer", %d)):\n'
            '    out[fam] = S.plugin_config(fam, S.plugin_row(st, fam, ident))\n'
            'row = st.db.row("SELECT * FROM cert_deploys WHERE id = ?", (%d,))\n'
            'out["deploy"] = S.deploy_options(st, row)\n'
            'out["raw"] = st.db.row("SELECT config FROM cert_challenges WHERE id = ?", (%d,))["config"]\n'
            'print(json.dumps(out))' % (self.target_id, self.val_id, self.source_id,
                                        self.deploy_id, self.val_id))
        self.assertEqual(got['target']['password'], OTHERS['target'])
        self.assertEqual(got['challenge']['key'], SSH_KEY)
        self.assertEqual(got['challenge']['password'], OTHERS['ssh_pass'])
        self.assertEqual(got['issuer']['eab_hmac'], OTHERS['eab'])
        self.assertEqual(got['deploy']['pfx_password'], OTHERS['deploy'])
        self.assertNoClear(got['raw'], 'the database (the SSH key sealed)')
        # The modules' descriptions: no default gives anything away.
        self.assertNoClear(json.dumps(self.ok('GET', '/api/plugins')), '/api/plugins')

    def test_06_export(self):
        plain = self.ok('GET', '/api/export')
        text = json.dumps(plain, ensure_ascii=False)
        self.assertNoClear(text, 'the export without the secrets')
        self.assertNotIn('sealed:', json.dumps(plain['config'].get('tables') or {}),
                         'the modules\' secrets in the export are dots, not sealed')
        tgt = [r for r in plain['config']['tables']['cert_targets'] if r['name'] == 'fake1'][0]
        self.assertEqual(json.loads(tgt['config'])['password'], DOTS)
        locked = self.ok('GET', '/api/export', args={'secrets': '1'})
        self.assertNoClear(json.dumps(locked['bundle']), 'the export with the secrets (locked)')
        # Put back without the secrets: the ones kept here stay.
        self.ok('POST', '/api/import', {'config': plain['config']})
        got = self.py('from acmelib.certs import store as S\n'
                      'print(json.dumps(S.plugin_config("target", S.plugin_row(st, "target", '
                      '"fake1"))["password"]))')
        self.assertEqual(got, OTHERS['target'])
        # Put back with them (the passphrase): opened, sealed again for its row here.
        self.ok('POST', '/api/import', {'config': locked['bundle'],
                                        'passphrase': locked['passphrase']})
        got = self.py('from acmelib.certs import store as S\n'
                      'r = S.plugin_row(st, "target", "fake1")\n'
                      'print(json.dumps([S.plugin_config("target", r)["password"], '
                      'json.loads(r["config"])["password"][:7]]))')
        self.assertEqual(got, [OTHERS['target'], 'sealed:'])

    def test_07_command_line(self):
        shown = self.cli_ok('--settings').stdout
        self.assertNoClear(shown, 'acme --settings')
        self.assertIn(DOTS + 'xq', shown)
        rows = {r['key']: r for r in self.cli_json('--settings')}
        self.assertEqual(rows['smtp_password']['value'], DOTS + 'xq')
        for args in (['--target-show', 'fake1'], ['--validation-show', 'web-ssh'],
                     ['--source-show', 'eab-ca'], ['--deploys'], ['--targets'],
                     ['--directories'], ['--rbackup-status'], ['--export-config', '-']):
            for js in ([], ['--json']):
                got = self.cli_ok(*(args + js)).stdout
                self.assertNoClear(got, 'acme %s' % ' '.join(args + js))
        self.assertIn(DOTS + 'xd', self.cli_ok('--target-show', 'fake1').stdout)
        row = self.cli_json('--validation-show', 'web-ssh')
        self.assertEqual(row['config']['key'], SSH_KEY_SHOWN)
        self.assertEqual(self.cli_json('--target-show', 'fake1')['deploys'][0]['options']
                         ['pfx_password'], DOTS + 'xf')
        # Typed (from stdin, as getpass reads it): never echoed back.
        got = self.cli_ok('--target-edit', 'fake1', '--set', 'password=-',
                          stdin=OTHERS['target'] + '\n')
        self.assertNoClear(got.stdout + got.stderr, 'acme --target-edit')
        self.assertTrue(self.cli_json('--target-test', 'fake1')['ok'])

    def test_08_events_and_jobs(self):
        for path in ('/api/events', '/api/certs/jobs'):
            self.assertNoClear(json.dumps(self.ok('GET', path, args={'per': '500'})), path)
        self.assertNoClear(self.cli_ok('--events', '--limit', '500').stdout, 'acme --events')

    def test_09_the_pages(self):
        """In Chromium (Playwright): the kept secret shown as dots and its last two,
        typing shows dots only. The pages from a copy of web/ whose acme-api.php
        asks this daemon (its run folder, not /run/acme)."""
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
        port = TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=2)
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'secrets_shown_page.js'),
                                  'http://127.0.0.1:%d' % port, 'tester', self.pw],
                                 capture_output=True, text=True, timeout=180, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['signin_type'], 'password')
        self.assertEqual(seen['targets']['kept'], DOTS + OTHERS['target'][-2:])
        self.assertEqual(seen['sources']['kept'], DOTS + OTHERS['eab'][-2:])
        self.assertEqual(seen['validation']['kept'], SSH_KEY_SHOWN)
        self.assertEqual(seen['targets']['typing'], '\u2022' * len('NewSecretTyped'))
        self.assertEqual(seen['targets']['real'], 'NewSecretTyped')
        for key in ('targets', 'sources', 'validation'):
            self.assertNoClear(seen[key]['html'], 'the form of %s' % key)
            self.assertNoClear(seen[key]['list'], 'the list of %s' % key)
            self.assertNotIn('NewSecretTyped', seen[key]['html'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
