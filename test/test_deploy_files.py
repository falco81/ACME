#!/usr/bin/env python3
"""A deployment's files and the script after them (targets/_script.py): the
preview the page shows, the password acme makes, the ACME_* variables, the
script uploaded, run and deleted - over the fake SSH session of
test_targets.py running its commands for real with sh in a temporary folder -,
the previous files put back when it fails, and the same in PowerShell.

    python3 test/test_deploy_files.py
"""
import base64
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as TT  # noqa: E402
from test_targets import FakeBundle, FakeSsh, FakeCtx, make, read  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _script as SC  # noqa: E402


def setUpModule():
    TT.setUpModule()


def tearDownModule():
    TT.tearDownModule()


class DualBundle(FakeBundle):
    """A dual certificate: ECDSA main, its twin 'RSA' (the same files, another kind)."""
    def __init__(self):
        FakeBundle.__init__(self)
        self.key_type = 'ec-256'
        self.alt = FakeBundle('b')
        self.alt.key_type = 'rsa-2048'


class PreviewTest(unittest.TestCase):
    def test_ssh_preview(self):
        t = make('ssh', {'host': 'srv'}, FakeCtx())
        got = t.preview(FakeBundle(), {
            'outputs': 'fullchain-pem /etc/app/{name}.crt 0644 root:app\n'
                       'key-pem /etc/app/{name}.key 0644\npfx /etc/app/{name}.pfx',
            'pfx_password_mode': 'generate', 'service': 'app',
            'script_mode': 'inline', 'script_interp': 'bash', 'script_body': 'echo hi\n'})
        paths = [f['path'] for f in got['files']]
        self.assertEqual(paths, ['/etc/app/www.example.test.crt', '/etc/app/www.example.test.key',
                                 '/etc/app/www.example.test.pfx'])
        crt = got['files'][0]
        self.assertEqual((crt['mode'], crt['owner'], crt['format']), ('0644', 'root:app',
                                                                       'fullchain-pem'))
        self.assertTrue(crt['exact'])
        self.assertEqual(crt['size'], len(FakeBundle().fullchain_pem))
        self.assertGreater(got['files'][2]['size'], 500)          # guessed
        # a key anybody may read: said
        self.assertTrue(any('anybody on the machine may read it' in p['words']
                            for p in got['problems']))
        env = got['env']
        self.assertEqual(env['ACME_FILE_FULLCHAIN_PEM'], '/etc/app/www.example.test.crt')
        self.assertEqual(env['ACME_FILE_KEY_PEM'], '/etc/app/www.example.test.key')
        self.assertEqual(env['ACME_FILE_PFX'], '/etc/app/www.example.test.pfx')
        self.assertEqual(env['ACME_PASSWORD'], '\u2022' * 8)      # never the password
        self.assertEqual(env['ACME_SERVICE'], 'app')
        self.assertEqual(env['ACME_DRY_RUN'], '0')
        self.assertEqual(env['ACME_NAMES'], 'www.example.test example.test')
        self.assertEqual(env['ACME_FILES'].splitlines(), paths)
        self.assertEqual(got['script']['mode'], 'inline')
        self.assertEqual(got['password'], {'mode': 'generate', 'set': False, 'needed': True})

    def test_problems_not_errors(self):
        t = make('ssh', {'host': 'srv'}, FakeCtx())
        got = t.preview(FakeBundle(), {'outputs': 'key-pem relative/x.key'})
        self.assertEqual(got['files'], [])
        self.assertTrue(any(p['level'] == 'bad' and 'absolute' in p['words']
                            for p in got['problems']))
        got = t.preview(FakeBundle(), {'outputs': 'jks /x/{nope}.jks'})
        words = ' '.join(p['words'] for p in got['problems'])
        self.assertIn('{nope}', words)
        self.assertIn('needs a password', words)
        got = t.preview(FakeBundle(), {'outputs': 'cert-pem /x/a.crt', 'script_mode': 'path',
                                       'script_path': 'relative.sh'})
        self.assertTrue(any('absolute path' in p['words'] for p in got['problems']))

    def test_dual_files_and_variables(self):
        t = make('ssh', {'host': 'srv'}, FakeCtx())
        got = t.preview(DualBundle(), {'preset': 'nginx'})
        paths = [f['path'] for f in got['files']]
        self.assertIn('/etc/nginx/ssl/www.example.test.rsa.crt', paths)
        env = got['env']
        self.assertEqual(env['ACME_FILE_KEY_PEM'], '/etc/nginx/ssl/www.example.test.key')
        self.assertEqual(env['ACME_FILE_KEY_PEM_ALT'], '/etc/nginx/ssl/www.example.test.rsa.key')
        self.assertEqual(env['ACME_FILE_KEY_PEM_RSA'], '/etc/nginx/ssl/www.example.test.rsa.key')
        self.assertEqual(env['ACME_FILE_KEY_PEM_EC'], '/etc/nginx/ssl/www.example.test.key')
        self.assertIn('ACME_ALT_FINGERPRINT', env)
        self.assertEqual(got['commands']['test_cmd'], ['nginx -t'])

    def test_second_of_a_format(self):
        pairs = [({'format': 'key-pem', 'variant': '', 'path': '/a'}, FakeBundle()),
                 ({'format': 'key-pem', 'variant': '', 'path': '/b'}, FakeBundle())]
        self.assertEqual(SC.file_vars(pairs, FakeBundle()),
                         {'ACME_FILE_KEY_PEM': '/a', 'ACME_FILE_KEY_PEM_2': '/b'})

    def test_target_default_script(self):
        t = make('ssh', {'host': 'srv', 'script_mode': 'path',
                         'script_path': '/usr/local/bin/reload.sh', 'script_args': '{name}'},
                 FakeCtx())
        sc = SC.script_of(t, {}, {'name': 'site'})
        self.assertEqual((sc['from'], sc['path'], sc['args']),
                         ('target', '/usr/local/bin/reload.sh', 'site'))
        self.assertIsNone(SC.script_of(t, {'script_mode': 'none'}))   # the deployment's wins
        with self.assertRaises(PluginError):
            SC.script_of(t, {'script_mode': 'inline', 'script_body': 'x' * (SC.SCRIPT_MAX + 1)})
        with self.assertRaises(ValueError):
            SC.check_body('x' * (SC.SCRIPT_MAX + 1))

    def test_described_for_the_page(self):
        reg = Registry(extra_dirs=[]).reload()
        for kind in ('ssh', 'local', 'windows_ssh'):
            d = reg.get('target', kind).describe()
            ui = d['files_ui']
            json.dumps(ui)
            self.assertTrue(ui['layouts'] and ui['formats'] and ui['env'] and ui['snippets'])
            keys = [f['key'] for f in d['deploy_fields']]
            for k in ('outputs', 'pfx_password_mode', 'pfx_password', 'script_mode',
                      'script_body', 'script_interp'):
                self.assertIn(k, keys, kind)
        self.assertEqual(reg.get('target', 'windows_ssh').files_ui['interps'],
                         [['powershell', 'PowerShell']])


class SshScriptTest(unittest.TestCase):
    """The script uploaded, run and deleted - for real, with sh."""
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TT.TMP)
        self.ssh = FakeSsh(local=True)
        self.ctx = FakeCtx(ssh=self.ssh)
        self.ctx.target_name = 'web1'
        self.t = make('ssh', {'host': 'srv', 'user': 'deploy', 'tmp_dir': self.d}, self.ctx)
        self.crt = os.path.join(self.d, 'ssl', 'site.crt')
        self.key = os.path.join(self.d, 'ssl', 'site.key')
        self.pfx = os.path.join(self.d, 'ssl', 'site.pfx')
        self.out = os.path.join(self.d, 'said.txt')
        os.makedirs(os.path.dirname(self.crt))
        with open(self.crt, 'w') as fh:
            fh.write('OLD CERT\n')
        self.opts = {'outputs': 'fullchain-pem %s 0644\nkey-pem %s 0600\npfx %s 0600'
                                % (self.crt, self.key, self.pfx),
                     'pfx_password_mode': 'fixed', 'pfx_password': 'Pw-123456',
                     'service': 'web', 'script_mode': 'inline', 'script_interp': 'bash',
                     'script_args': '{name} two',
                     'script_body': '#!/bin/bash\nset -e\n'
                                    'env | grep ^ACME_ | sort > %s\n'
                                    'echo "args: $*" >> %s\n'
                                    'echo "cert: $(head -1 "$ACME_FILE_FULLCHAIN_PEM")"\n'
                                    % (self.out, self.out)}

    def leftovers(self):
        return [f for f in os.listdir(self.d) if f.startswith('.acme-')]

    def env(self):
        got = {}
        for line in read(self.out).splitlines():
            if line.startswith('ACME_') and '=' in line:
                k, v = line.split('=', 1)
                got[k] = v
        return got

    def test_runs_with_its_variables_then_is_gone(self):
        b = FakeBundle()
        words = self.t.deploy(b, self.opts)
        self.assertIn('the script ran', words)
        env = self.env()
        self.assertEqual(env['ACME_FILE_FULLCHAIN_PEM'], self.crt)
        self.assertEqual(env['ACME_FILE_KEY_PEM'], self.key)
        self.assertEqual(env['ACME_FILE_PFX'], self.pfx)
        self.assertEqual(env['ACME_PASSWORD'], 'Pw-123456')
        self.assertEqual(env['ACME_CERT_NAME'], 'www.example.test')
        self.assertEqual(env['ACME_CN'], 'www.example.test')
        self.assertEqual(env['ACME_FINGERPRINT'], b.fingerprint)
        self.assertEqual(env['ACME_SERVICE'], 'web')
        self.assertEqual(env['ACME_TARGET'], 'web1')
        self.assertEqual(env['ACME_DRY_RUN'], '0')
        self.assertTrue(env['ACME_NOT_AFTER'].endswith('Z'))
        self.assertIn('args: www.example.test two', read(self.out))
        # its words in the job, nothing left behind, never a password on a command line
        self.assertTrue(any('cert: -----BEGIN CERTIFICATE-----' in w for _l, w in self.ctx.steps))
        self.assertEqual(self.leftovers(), [])
        self.assertFalse(any('Pw-123456' in c for c, _i in self.ssh.runs))
        script_put = [p for p, _d, m in self.ssh.puts if '.acme-script-' in p]
        self.assertTrue(script_put and script_put[0].endswith('.sh'))
        self.assertTrue(any('chmod 700' in c for c, _i in self.ssh.runs))

    def test_failing_script_puts_the_files_back(self):
        o = dict(self.opts, script_body='echo "nope, broken" >&2\nexit 3\n')
        with self.assertRaises(PluginError) as e:
            self.t.deploy(FakeBundle(), o)
        self.assertIn('exit 3', str(e.exception))
        self.assertIn('previous files are back', str(e.exception))
        self.assertEqual(read(self.crt), 'OLD CERT\n')
        self.assertFalse(os.path.exists(self.key))
        self.assertTrue(any('nope, broken' in w and lvl == 'bad' for lvl, w in self.ctx.steps))
        self.assertEqual(self.leftovers(), [])

    def test_script_on_the_machine(self):
        tool = os.path.join(self.d, 'reload.sh')
        with open(tool, 'w') as fh:
            fh.write('#!/bin/sh\necho "$ACME_CN $1" > %s\n' % self.out)
        os.chmod(tool, 0o755)
        o = dict(self.opts, script_mode='path', script_path=tool, script_args='{service}')
        self.t.deploy(FakeBundle(), o)
        self.assertEqual(read(self.out).strip(), 'www.example.test web')
        self.assertEqual(self.leftovers(), [])

    def test_through_sudo(self):
        ssh = FakeSsh()
        t = make('ssh', {'host': 'srv', 'user': 'u', 'sudo': True}, FakeCtx(ssh=ssh))
        t.deploy(FakeBundle(), {'preset': 'nginx', 'script_mode': 'inline',
                                'script_body': 'systemctl reload nginx\n'})
        runs = [c for c, _i in ssh.runs if '.acme-script-' in c and 'bash ' in c]
        self.assertTrue(runs and runs[0].startswith('sudo -n sh -c '))
        env = [d for p, d, m in ssh.puts if '.acme-env-' in p][0].decode()
        self.assertIn("export ACME_FILE_KEY_PEM=/etc/nginx/ssl/www.example.test.key", env)
        self.assertTrue(all(m == 0o600 for p, d, m in ssh.puts))

    def test_dry_run(self):
        o = dict(self.opts, test_cmd='touch %s/TESTED' % self.d,
                 script_body='echo "dry=$ACME_DRY_RUN key=$ACME_FILE_KEY_PEM" > %s\n'
                             'test -s "$ACME_FILE_KEY_PEM"\n' % self.out)
        words = self.t.dry_run(FakeBundle(), o)
        self.assertIn('ACME_DRY_RUN=1', words)
        said = read(self.out)
        self.assertIn('dry=1', said)
        self.assertIn('/.acme-test-', said)                 # a copy, not the real place
        self.assertEqual(read(self.crt), 'OLD CERT\n')     # nothing in place
        self.assertFalse(os.path.exists(self.key))
        self.assertFalse(os.path.exists(os.path.join(self.d, 'TESTED')))   # not run
        self.assertEqual(self.leftovers(), [])              # the temporary folder gone
        self.assertTrue(any('replaces the one there' in w for _l, w in self.ctx.steps))
        with self.assertRaises(PluginError):
            self.t.dry_run(FakeBundle(), dict(o, script_body='exit 1\n'))
        self.assertEqual(self.leftovers(), [])


class LocalScriptTest(unittest.TestCase):
    def test_allowed_only_when_the_target_says(self):
        base = tempfile.mkdtemp(dir=TT.TMP)
        out = os.path.join(base, 'said.txt')
        o = {'outputs': 'fullchain-pem {name}/fullchain.pem\nkey-pem {name}/key.pem',
             'script_mode': 'inline', 'script_interp': 'sh',
             'script_body': 'echo "$ACME_FILE_KEY_PEM $ACME_DRY_RUN" > %s\n' % out}
        t = make('local', {'base': base}, FakeCtx())
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), o)
        self.assertIn('does not let scripts run', str(e.exception))
        self.assertFalse(os.path.exists(os.path.join(base, 'www.example.test')))
        got = t.preview(FakeBundle(), o)
        self.assertTrue(any('does not let scripts run' in p['words'] for p in got['problems']))
        t = make('local', {'base': base, 'allow_scripts': True}, FakeCtx())
        t.deploy(FakeBundle(), o)
        self.assertEqual(read(out).split(), [os.path.join(os.path.realpath(base),
                                                          'www.example.test', 'key.pem'), '0'])
        # a failing one: the files as they were
        with open(os.path.join(base, 'www.example.test', 'key.pem'), 'w') as fh:
            fh.write('OLD')
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), dict(o, script_body='exit 2\n', force=True))
        self.assertEqual(read(os.path.join(base, 'www.example.test', 'key.pem')), 'OLD')
        # a command on the machine only when allowed
        with self.assertRaises(PluginError):
            t.deploy(FakeBundle(), dict(o, script_mode='path', script_path='/bin/true', force=True))
        t = make('local', {'base': base, 'allow_commands': '/bin/true'}, FakeCtx())
        t.deploy(FakeBundle(), dict(o, script_mode='path', script_path='/bin/true', force=True))
        # the test: into a temporary folder, the script told so
        t = make('local', {'base': base, 'allow_scripts': True}, FakeCtx())
        t.dry_run(FakeBundle(), o)
        k, dry = read(out).split()
        self.assertEqual(dry, '1')
        self.assertNotIn(os.path.realpath(base), k)
        self.assertFalse(os.path.exists(k))


class WindowsScriptTest(unittest.TestCase):
    def ps(self, cmd):
        return base64.b64decode(cmd.split('-EncodedCommand ')[1]).decode('utf-16-le')

    def test_files_and_powershell(self):
        ssh = FakeSsh([(r'EncodedCommand', (0, 'IMPORTED X\n', ''))])
        ctx = FakeCtx(ssh=ssh)
        t = make('windows_ssh', {'host': 'win', 'user': 'Administrator', 'auth': 'password',
                                 'password': 'pw'}, ctx)
        b = FakeBundle()
        words = t.deploy(b, {'outputs': 'pfx C:/certs/{name}.pfx',
                             'pfx_password_mode': 'fixed', 'pfx_password': 'Secret-1',
                             'script_mode': 'inline', 'script_interp': 'powershell',
                             'script_body': 'Restart-Service W3SVC\n', 'service': 'W3SVC'})
        self.assertIn('the script ran', words)
        scripts = [self.ps(c) for c, _i in ssh.runs if 'EncodedCommand' in c]
        self.assertTrue(any("Move-Item -LiteralPath 'C:/Windows/Temp/acme-" in x and
                            "'C:/certs/www.example.test.pfx'" in x for x in scripts))
        run = [x for x in scripts if "-File '" in x][0]
        self.assertIn('ConvertFrom-Json', run)
        self.assertIn('exit $LASTEXITCODE', run)
        envf = [d for p, d, m in ssh.puts if 'acme-env-' in p][0]
        env = json.loads(envf.decode())
        self.assertEqual(env['ACME_FILE_PFX'], 'C:/certs/www.example.test.pfx')
        self.assertEqual(env['ACME_PASSWORD'], 'Secret-1')
        self.assertEqual(env['ACME_THUMBPRINT'], TT.C.sha1_thumb(b))
        body = [d for p, d, m in ssh.puts if p.endswith('.ps1')][0]
        self.assertTrue(body.startswith(b'\xef\xbb\xbfRestart-Service'))
        self.assertFalse(any('Secret-1' in self.ps(c) for c, _i in ssh.runs
                             if 'EncodedCommand' in c and 'Import-Pfx' not in self.ps(c)))
        self.assertTrue(any('Remove-Item' in x and 'acme-script-' in x for x in scripts))

    def test_failing_script_puts_the_files_back(self):
        def answer(cmd, inp):
            x = base64.b64decode(cmd.split('-EncodedCommand ')[1]).decode('utf-16-le')
            if "-File '" in x:
                return 5, 'it broke\n', ''
            if 'Copy-Item' in x and '.bak' in x and 'Move-Item' in x:
                return 0, 'HAD C:/certs/www.example.test.pfx\n', ''
            return 0, 'IMPORTED X\n', ''
        ssh = FakeSsh([(r'EncodedCommand', answer)])
        t = make('windows_ssh', {'host': 'win', 'user': 'Administrator', 'auth': 'password',
                                 'password': 'pw'}, FakeCtx(ssh=ssh))
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'outputs': 'pfx C:/certs/{name}.pfx',
                                    'script_mode': 'inline', 'script_body': 'exit 5'})
        self.assertIn('exit 5', str(e.exception))
        back = [self.ps(c) for c, _i in ssh.runs if 'EncodedCommand' in c]
        # from its dated copy (1.0.77)
        self.assertTrue(any(re.search(r"Copy-Item -LiteralPath 'C:/certs/www\.example\.test\.pfx\.\d{8}-\d{6}\.bak' "
                                      r"-Destination 'C:/certs/www\.example\.test\.pfx'", x) for x in back))

    def test_no_files_no_script_as_before(self):
        ssh = FakeSsh([(r'EncodedCommand', (0, 'IMPORTED X\n', ''))])
        t = make('windows_ssh', {'host': 'win', 'user': 'Administrator', 'auth': 'password',
                                 'password': 'pw'}, FakeCtx(ssh=ssh))
        t.deploy(FakeBundle(), {})
        self.assertEqual(len([1 for c, _i in ssh.runs if 'EncodedCommand' in c]), 1)
        self.assertFalse([p for p, _d, _m in ssh.puts if 'acme-env-' in p or p.endswith('.ps1')])


class SavedPasswordTest(unittest.TestCase):
    """pfx_password_mode 'generate': made once, sealed with the deployment."""
    def test_generated_kept_sealed(self):
        # the logic itself, without a database: deployer.generated_password
        from acmelib.certs import deployer

        class Db(object):
            def __init__(self):
                self.opts = json.dumps({'pfx_password_mode': 'generate'})

            def row(self, sql, args):
                return {'options': self.opts}

            def update(self, table, ident, fields):
                self.opts = fields['options']

        class Store(object):
            db = Db()
        sealed = []
        real_seal = deployer.E.seal_secret
        deployer.E.seal_secret = lambda v, place: sealed.append((v, place)) or 'sealed:x'
        try:
            opts = {'pfx_password_mode': 'generate'}
            pw = deployer.generated_password(Store(), {'id': 7}, opts)
            self.assertTrue(pw and len(pw) == 24 and re.match(r'^[A-Za-z0-9_-]+$', pw))
            self.assertEqual(opts['pfx_password'], pw)
            self.assertEqual(sealed, [(pw, 'cert_deploys:7:pfx_password')])
            self.assertEqual(json.loads(Store.db.opts)['pfx_password'], 'sealed:x')
            # kept: not made again
            self.assertEqual(deployer.generated_password(Store(), {'id': 7}, opts), pw)
            self.assertIsNone(deployer.generated_password(Store(), {'id': 7}, {}))
        finally:
            deployer.E.seal_secret = real_seal


if __name__ == '__main__':
    unittest.main()
