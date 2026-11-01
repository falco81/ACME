#!/usr/bin/env python3
"""The SSH keys of the modules - isemon's key card (a field of the type sshkey) -
through a real daemon.

    python3 test/test_sshkeys.py          (or python3 -m unittest test.test_sshkeys)

A daemon is started in a folder of its own (as test_certs_core does) and asked
over its API the way the page asks: a key made here is sealed and its public
half and fingerprint are right; a key of your own is taken with and without a
passphrase, a wrong passphrase is refused; Forget it, Download it (the public
half to anybody, the private half to a full administrator alone); a key made in
a form not saved yet is attached when the form is saved; a key pasted before
there was this card still works and shows as your own; and, where an sshd can
be started on a high port (as root), Try reaching it signs in for real with the
key made here - and is refused without it.
"""
import json
import os
import shutil
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

import test_certs_core as TCC        # noqa: E402  (its helpers)

KEYGEN = shutil.which('ssh-keygen')
SSHD = '/usr/sbin/sshd' if os.path.exists('/usr/sbin/sshd') else shutil.which('sshd')


def keygen(path, passphrase='', kind='ed25519', comment='you@laptop'):
    subprocess.run(['ssh-keygen', '-q', '-t', kind, '-N', passphrase, '-C', comment, '-f', path],
                   check=True, capture_output=True)
    with open(path) as f:
        private = f.read()
    with open(path + '.pub') as f:
        public = f.read().strip()
    return private, public


def fingerprint(public):
    got = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', '-'], input=public + '\n',
                         capture_output=True, text=True, check=True)
    return got.stdout.split()[1]


@unittest.skipUnless(KEYGEN, 'ssh-keygen is not here (apt install openssh-client)')
class SshKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-sshkeys-test-')
        for d in ('state', 'run', 'log', 'plugins', 'keys', 'sshd'):
            os.makedirs(os.path.join(cls.tmp, d), exist_ok=True)
        cls.port = TCC.free_port()
        free = TCC.free_port
        conf = {'api_port': cls.port, 'radius_bind': '127.0.0.1',
                'radius_auth_port': free(), 'radius_acct_port': free(),
                'ssh_gate_port': free(), 'node_name': 'keynode', 'upgrade_check': 0}
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
        cls.sshd = None
        cls.sshd_port = None
        cls.start_sshd()

    @classmethod
    def start_sshd(cls):
        """An sshd of its own on a high port, letting root in with the keys of
        a file in the test's folder - only as root, where there is one."""
        if not SSHD or os.geteuid() != 0:
            return
        d = os.path.join(cls.tmp, 'sshd')
        os.chmod(d, 0o700)
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f',
                        os.path.join(d, 'hostkey')], check=True, capture_output=True)
        cls.auth_keys = os.path.join(d, 'authorized_keys')
        open(cls.auth_keys, 'w').close()
        os.chmod(cls.auth_keys, 0o600)
        port = TCC.free_port()
        with open(os.path.join(d, 'sshd_config'), 'w') as f:
            f.write('Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\n'
                    'AuthorizedKeysFile %s\nPermitRootLogin prohibit-password\n'
                    'PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n'
                    'StrictModes no\n' % (port, os.path.join(d, 'hostkey'),
                                          os.path.join(d, 'sshd.pid'), cls.auth_keys))
        os.makedirs('/run/sshd', exist_ok=True)
        cls.sshd = subprocess.Popen([SSHD, '-D', '-e', '-f', os.path.join(d, 'sshd_config')],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.time() + 15
        import socket
        while time.time() < end:
            try:
                socket.create_connection(('127.0.0.1', port), timeout=1).close()
                cls.sshd_port = port
                return
            except OSError:
                if cls.sshd.poll() is not None:
                    return
                time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, 'sshd', None) is not None and cls.sshd.poll() is None:
            cls.sshd.terminate()
            cls.sshd.wait(10)
        TCC.CertsCore.__dict__['tearDownClass'].__func__(cls)

    call = TCC.CertsCore.__dict__['call']
    login = TCC.CertsCore.__dict__['login']
    ok = TCC.CertsCore.ok
    cli = TCC.CertsCore.cli
    cli_ok = TCC.CertsCore.cli_ok
    py = TCC.CertsCore.py

    def refused(self, path, body, status=400, session=None, words=''):
        st, got = self.call('POST', path, body, session or self.admin)
        self.assertEqual(st, status, '%s -> %s %s' % (path, st, got))
        if words:
            self.assertIn(words, got.get('error', ''))
        return got

    def target(self, name, extra=None):
        cfg = {'host': '127.0.0.1', 'port': self.sshd_port or 22, 'user': 'root', 'auth': 'key',
               'trust_first': True}
        cfg.update(extra or {})
        return self.ok('POST', '/api/targets/save', {'name': name, 'kind': 'ssh',
                                                      'config': cfg})['id']

    def raw(self, ident, table='cert_targets'):
        return self.py('print(json.dumps(st.db.row("SELECT config FROM %s WHERE id = ?", '
                       '(%d,))["config"]))' % (table, ident))

    def opened(self, ident, family='target'):
        return self.py('from acmelib.certs import store as S\n'
                       'print(json.dumps(S.plugin_config(%r, S.plugin_row(st, %r, %d))))'
                       % (family, family, ident))

    def row(self, ident, path='/api/targets', session=None):
        rows = self.ok('GET', path, session=session)['rows']
        return [r for r in rows if r['id'] == ident][0]

    # ---- the tests ---------------------------------------------------------------------
    def test_00_info_and_fields(self):
        info = self.ok('GET', '/api/sshkey/info')
        self.assertTrue(info['can_keygen'])
        self.assertEqual(info['comment'], 'acme@keynode')
        plugs = self.ok('GET', '/api/plugins')
        for fam, kind, key in (('target', 'ssh', 'key'), ('target', 'windows_ssh', 'key'),
                               ('target', 'pfsense', 'key'), ('target', 'opnsense', 'ssh_key'),
                               ('target', 'mikrotik', 'ssh_key'), ('challenge', 'http_ssh', 'key'),
                               ('challenge', 'ssh_dns', 'key')):
            p = [x for x in plugs[fam] if x['kind'] == kind][0]
            f = [x for x in p['fields'] if x['key'] == key][0]
            self.assertEqual(f['type'], 'sshkey', kind)
            self.assertTrue(f['secret'], kind)
            # no passphrase box of its own any more: the card asks for it
            self.assertFalse([x for x in p['fields'] if x['key'].endswith('key_pass')], kind)

    def test_01_made_in_a_new_form_and_saved(self):
        d = self.ok('POST', '/api/sshkey/make', {'family': 'target', 'kind': 'ssh', 'field': 'key',
                                                 'name': 'web1'})
        self.assertTrue(d['draft'].startswith('sshkey:draft:'))
        self.assertTrue(d['public'].startswith('ssh-ed25519 '))
        self.assertTrue(d['public'].endswith(' acme@keynode'))
        self.assertEqual(d['fp'], fingerprint(d['public']))
        self.assertEqual((d['type'], d['how'], d['by']), ('ED25519', 'made', 'tester'))
        self.assertNotIn('PRIVATE', json.dumps(d))
        # The form's Try / Test with the draft, before it is saved: refused only by the
        # machine (no sshd needed to see the draft is the key used).
        ident = self.target('web1', {'key': d['draft']})
        raw = self.raw(ident)
        self.assertNotIn('PRIVATE KEY', raw)
        cfg = json.loads(raw)
        self.assertTrue(cfg['key'].startswith('sealed:'))
        self.assertEqual(cfg['key.sshkey']['public'], d['public'])
        self.assertEqual(cfg['key.sshkey']['fp'], d['fp'])
        opened = self.opened(ident)
        self.assertIn('BEGIN OPENSSH PRIVATE KEY', opened['key'])
        # the private half's public half is the one shown
        p = os.path.join(self.tmp, 'keys', 'made1')
        with open(os.open(p, os.O_WRONLY | os.O_CREAT, 0o600), 'w') as f:
            f.write(opened['key'])
        pub = subprocess.run(['ssh-keygen', '-y', '-f', p], capture_output=True, text=True,
                             check=True).stdout.strip()
        self.assertEqual(pub, d['public'])
        # the draft is gone once saved
        gone = self.ok('POST', '/api/sshkey/show', {'family': 'target', 'kind': 'ssh',
                                                     'draft': d['draft']})
        self.assertTrue(gone.get('gone'))
        # what the page is given: the public half, never the private one
        r = self.row(ident)
        self.assertEqual(r['config']['key.sshkey']['public'], d['public'])
        self.assertEqual(r['secret_set'], ['key'])
        self.assertNotIn('PRIVATE', json.dumps(r))
        shown = self.ok('POST', '/api/sshkey/show', {'family': 'target', 'id': ident})
        self.assertEqual((shown['has'], shown['fp']), (True, d['fp']))
        # saved again as the page sends it (dots, no meta): kept, with its meta
        self.ok('POST', '/api/targets/save', {'id': ident, 'name': 'web1', 'kind': 'ssh',
                                              'config': {k: v for k, v in r['config'].items()
                                                         if k != 'key.sshkey'}})
        self.assertEqual(json.loads(self.raw(ident))['key.sshkey']['fp'], d['fp'])
        self.assertEqual(self.opened(ident)['key'], opened['key'])
        self.__class__.web1 = ident

    def test_02_made_on_a_saved_one_rsa(self):
        ident = self.web1
        d = self.ok('POST', '/api/sshkey/make', {'family': 'target', 'id': ident,
                                                 'key_type': 'rsa4096'})
        self.assertNotIn('draft', d)
        self.assertEqual((d['type'], d['bits']), ('RSA', 4096))
        self.assertTrue(d['public'].startswith('ssh-rsa '))
        self.assertEqual(self.row(ident)['config']['key.sshkey']['fp'], d['fp'])
        self.refused('/api/sshkey/make', {'family': 'target', 'id': ident, 'key_type': 'dsa'},
                     words='ed25519')

    def test_03_my_own_without_and_with_a_passphrase(self):
        ident = self.web1
        plain, plain_pub = keygen(os.path.join(self.tmp, 'keys', 'own'))
        d = self.ok('POST', '/api/sshkey/use_own', {'family': 'target', 'id': ident,
                                                    'pem': plain})
        self.assertEqual((d['public'], d['how'], d['locked']), (plain_pub, 'own', False))
        self.assertEqual(self.opened(ident)['key'].strip(), plain.strip())
        locked, locked_pub = keygen(os.path.join(self.tmp, 'keys', 'locked'), 'horse battery')
        self.refused('/api/sshkey/use_own', {'family': 'target', 'id': ident, 'pem': locked},
                     words='locked with a passphrase')
        self.refused('/api/sshkey/use_own', {'family': 'target', 'id': ident, 'pem': locked,
                                             'passphrase': 'wrong one'},
                     words='that passphrase does not open the key')
        # still the one before
        self.assertEqual(self.ok('POST', '/api/sshkey/show', {'family': 'target',
                                                              'id': ident})['public'], plain_pub)
        d = self.ok('POST', '/api/sshkey/use_own', {'family': 'target', 'id': ident,
                                                    'pem': locked, 'passphrase': 'horse battery'})
        self.assertEqual((d['public'], d['locked']), (locked_pub, True))
        got = self.opened(ident)
        self.assertEqual(got['key'].strip(), locked.strip())       # kept as it was given
        self.assertEqual(got['key_pass'], 'horse battery')         # beside it, for ssh
        self.assertNotIn('horse battery', self.raw(ident))
        # Download it: the private half as it was given, to a full administrator only
        dl = self.ok('POST', '/api/sshkey/download', {'family': 'target', 'id': ident,
                                                      'half': 'private'})
        self.assertEqual(dl['text'].strip(), locked.strip())
        self.assertEqual(dl['file'], 'acme-web1')
        for session in (self.certer, self.ro):
            self.refused('/api/sshkey/download', {'family': 'target', 'id': ident,
                                                  'half': 'private'}, 403, session)
        pub = self.ok('POST', '/api/sshkey/download', {'family': 'target', 'id': ident,
                                                       'half': 'public'}, session=self.ro)
        self.assertEqual((pub['text'].strip(), pub['file']), (locked_pub, 'acme-web1.pub'))
        ev = self.py('print(json.dumps([r["words"] for r in st.db.rows('
                     '"SELECT words FROM events ORDER BY id DESC LIMIT 20")]))')
        self.assertTrue(any('private SSH key was downloaded by tester' in w for w in ev), ev)
        # The others are not let make, bring or forget one.
        for path in ('make', 'use_own', 'forget'):
            self.refused('/api/sshkey/' + path, {'family': 'target', 'id': ident, 'pem': plain},
                         403, self.certer)
        # a public half is not a private key
        self.refused('/api/sshkey/use_own', {'family': 'target', 'id': ident, 'pem': plain_pub},
                     words='public half')

    def test_04_forget(self):
        ident = self.web1
        d = self.ok('POST', '/api/sshkey/forget', {'family': 'target', 'id': ident})
        self.assertFalse(d['has'])
        cfg = json.loads(self.raw(ident))
        for k in ('key', 'key.sshkey', 'key_pass'):
            self.assertNotIn(k, cfg)
        self.refused('/api/sshkey/download', {'family': 'target', 'id': ident,
                                              'half': 'public'}, 404)

    def test_05_a_key_pasted_before_still_works(self):
        """A key in the settings from before this card (pasted, sealed, no public half
        kept beside it): it signs in as before and shows as your own key."""
        own, own_pub = keygen(os.path.join(self.tmp, 'keys', 'old'))
        ident = self.target('old1')
        self.py('from acmelib.certs import store as S\n'
                'row = S.plugin_row(st, "target", %d)\n'
                'cfg = json.loads(row["config"])\n'
                'cfg["key"] = E.seal_secret(%r, "cert_targets:%d:key")\n'
                'st.db.update("cert_targets", %d, {"config": json.dumps(cfg)})\n'
                'print(json.dumps(1))' % (ident, own, ident, ident))
        r = self.row(ident)
        self.assertEqual(r['secret_set'], ['key'])
        self.assertNotIn('key.sshkey', r['config'])
        shown = self.ok('POST', '/api/sshkey/show', {'family': 'target', 'id': ident})
        self.assertEqual((shown['has'], shown['public'], shown['how']), (True, own_pub, 'pasted'))
        self.assertEqual(self.opened(ident)['key'], own)
        # also pasted whole through the API as before (acme --target-edit --set key=@file:)
        ident2 = self.target('old2', {'key': own})
        self.assertEqual(self.ok('POST', '/api/sshkey/show', {'family': 'target',
                                                              'id': ident2})['public'], own_pub)
        self.__class__.old = (ident, own, own_pub)

    def test_06_a_validation_too(self):
        d = self.ok('POST', '/api/sshkey/make', {'family': 'challenge', 'kind': 'http_ssh',
                                                 'field': 'key'})
        ident = self.ok('POST', '/api/validations/save', {
            'name': 'web-ssh', 'kind': 'http_ssh', 'config': {
                'hosts': ['192.0.2.21'], 'user': 'acme', 'auth': 'key', 'key': d['draft']}})['id']
        cfg = json.loads(self.raw(ident, 'cert_challenges'))
        self.assertEqual(cfg['key.sshkey']['fp'], d['fp'])
        self.assertTrue(cfg['key'].startswith('sealed:'))
        # a draft made for another module is not taken
        d2 = self.ok('POST', '/api/sshkey/make', {'family': 'challenge', 'kind': 'ssh_dns'})
        self.refused('/api/validations/save', {'id': ident, 'name': 'web-ssh', 'kind': 'http_ssh',
                                               'config': {'key': d2['draft']}},
                     words='another form')

    def test_07_the_command_line(self):
        got = self.cli_ok('--target-key', 'old1', 'public')
        self.assertEqual(got.stdout.strip(), self.old[2])
        got = self.cli_ok('--target-key', 'old1', 'show', '--json')
        self.assertEqual(json.loads(got.stdout)['public'], self.old[2])
        got = self.cli_ok('--validation-key', 'web-ssh', 'make', '--json')
        self.assertTrue(json.loads(got.stdout)['public'].startswith('ssh-ed25519 '))
        bad = self.cli('--target-key', 'old1', 'nonsense')
        self.assertNotEqual(bad.returncode, 0)

    @unittest.skipUnless(SSHD and os.geteuid() == 0, 'an sshd is started only as root')
    def test_08_try_reaching_it_for_real(self):
        if not self.sshd_port:
            self.skipTest('the sshd did not start')
        d = self.ok('POST', '/api/sshkey/make', {'family': 'target', 'kind': 'ssh'})
        ident = self.target('reach1', {'key': d['draft']})
        with open(self.auth_keys, 'w') as f:
            f.write('')
        got = self.ok('POST', '/api/sshkey/try', {'family': 'target', 'id': ident, 'config': {}})
        self.assertFalse(got['reached'], got)
        self.assertIn('did not let root in', got['said'])
        self.assertTrue(self.row(ident)['last_error'])
        with open(self.auth_keys, 'w') as f:
            f.write('from="127.0.0.1" %s\n' % d['public'])
        got = self.ok('POST', '/api/sshkey/try', {'family': 'target', 'id': ident, 'config': {}},
                      session=self.certer)
        self.assertTrue(got['reached'], got)
        words = [s[2] for s in got['steps']]
        self.assertTrue(any(w.startswith('signed in to 127.0.0.1 as root with the key %s'
                                         % d['fp']) for w in words), words)
        self.assertEqual(words[-1], 'nothing was written and nothing was changed')
        self.assertFalse(self.row(ident)['last_error'])
        # the host key it sees comes back for the form's Host key, as a known_hosts
        # line ([host]:port off 22) - and nothing is written: the form's Save keeps it
        with open(os.path.join(self.tmp, 'sshd', 'hostkey.pub')) as f:
            hk = f.read().split()[:2]
        line = '[127.0.0.1]:%d %s %s' % (self.sshd_port, hk[0], hk[1])
        self.assertEqual(got['hostkey_field'], 'hostkey')
        self.assertEqual(len(got['hostkeys']), 1, got['hostkeys'])
        seen = got['hostkeys'][0]
        self.assertEqual((seen['status'], seen['line'], seen['type']), ('new', line, 'ssh-ed25519'))
        self.assertEqual(seen['fp'], 'ssh-ed25519 ' + fingerprint(' '.join(hk)))
        self.assertTrue(any(w.startswith('127.0.0.1:%d shows the host key(s) ssh-ed25519 SHA256:'
                                         % self.sshd_port) for w in words), words)
        self.assertFalse(self.opened(ident).get('hostkey'))
        # pinned and the same: nothing to add
        got = self.ok('POST', '/api/sshkey/try', {'family': 'target', 'id': ident,
                                                  'config': {'hostkey': line}})
        self.assertTrue(got['reached'], got)
        self.assertEqual(got['hostkeys'][0]['status'], 'same')
        # pinned and another: refused, and said as another - with the one seen to replace it
        other = '127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
        got = self.ok('POST', '/api/sshkey/try', {'family': 'target', 'id': ident,
                                                  'config': {'hostkey': other}})
        self.assertFalse(got['reached'], got)
        self.assertIn('another host key', got['said'])
        seen = got['hostkeys'][0]
        self.assertEqual((seen['status'], seen['pinned'], seen['line']), ('other', [other], line))
        self.assertFalse(self.opened(ident).get('hostkey'))
        # the form saved with it keeps it
        base = {'host': '127.0.0.1', 'port': self.sshd_port, 'user': 'root', 'auth': 'key',
                'trust_first': True}
        self.ok('POST', '/api/targets/save', {'id': ident, 'name': 'reach1', 'kind': 'ssh',
                                              'config': dict(base, hostkey=line)})
        self.assertEqual(self.opened(ident).get('hostkey'), line)
        self.ok('POST', '/api/targets/save', {'id': ident, 'name': 'reach1', 'kind': 'ssh',
                                              'config': dict(base, hostkey='')})
        self.assertFalse(self.opened(ident).get('hostkey'))
        # the module's own Test signs in with it the same way
        tested = self.ok('POST', '/api/targets/test', {'id': ident})
        self.assertTrue(tested['ok'], tested)
        # a key made in a form not saved yet is tried as the key, before the save
        d2 = self.ok('POST', '/api/sshkey/make', {'family': 'target', 'kind': 'ssh'})
        with open(self.auth_keys, 'a') as f:
            f.write('%s\n' % d2['public'])
        got = self.ok('POST', '/api/sshkey/try', {
            'family': 'target', 'kind': 'ssh', 'draft': d2['draft'], 'name': 'unsaved',
            'config': {'host': '127.0.0.1', 'port': self.sshd_port, 'user': 'root',
                       'auth': 'key', 'trust_first': True, 'key': d2['draft']}})
        self.assertTrue(got['reached'], got)
        # a key with a passphrase signs in too
        locked, locked_pub = keygen(os.path.join(self.tmp, 'keys', 'reach-locked'), 'pass word')
        self.ok('POST', '/api/sshkey/use_own', {'family': 'target', 'id': ident, 'pem': locked,
                                                'passphrase': 'pass word'})
        with open(self.auth_keys, 'a') as f:
            f.write('%s\n' % locked_pub)
        got = self.ok('POST', '/api/sshkey/try', {'family': 'target', 'id': ident, 'config': {}})
        self.assertTrue(got['reached'], got)
        # and the command line's try - which, with no form, keeps the first seen
        self.cli_ok('--target-key', 'reach1', 'try')
        self.assertIn('ssh-ed25519', self.opened(ident).get('hostkey') or '')

    @unittest.skipUnless(SSHD and os.geteuid() == 0, 'an sshd is started only as root')
    def test_09_a_validation_on_several_hosts(self):
        """http_ssh: one line a host, a host pinned already left as it is."""
        if not self.sshd_port:
            self.skipTest('the sshd did not start')
        with open(os.path.join(self.tmp, 'sshd', 'hostkey.pub')) as f:
            hk = ' '.join(f.read().split()[:2])
        pinned = '[localhost]:%d %s' % (self.sshd_port, hk)
        got = self.ok('POST', '/api/sshkey/try', {
            'family': 'challenge', 'kind': 'http_ssh', 'name': 'webs',
            'config': {'hosts': ['127.0.0.1:%d' % self.sshd_port,
                                 'localhost:%d' % self.sshd_port],
                       'user': 'root', 'auth': 'password', 'password': 'x',
                       'hostkey': [pinned], 'trust_first': False}})
        by = {h['host']: h for h in got['hostkeys']}
        self.assertEqual(got['hostkey_field'], 'hostkey')
        self.assertEqual(by['127.0.0.1']['status'], 'new')
        self.assertEqual(by['127.0.0.1']['line'], '[127.0.0.1]:%d %s' % (self.sshd_port, hk))
        self.assertEqual(by['localhost']['status'], 'same')
        self.assertEqual(by['localhost']['pinned'], [pinned])


class HostkeyReport(unittest.TestCase):
    """What Try reaching it says of the host keys seen, against the form's field."""
    ED = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
    ED2 = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJm'
    RSA = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7'
    ECD = 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY='

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, ROOT)
        from acmelib.certs import api_sshkeys
        cls.K = api_sshkeys

    def test_best_line_and_ports(self):
        r = self.K.hostkey_report([('192.0.2.21', 22, '192.0.2.21 %s\n192.0.2.21 %s\n192.0.2.21 %s\n'
                                    % (self.RSA, self.ECD, self.ED)),
                                   ('web2', 2222, '[web2]:2222 %s\n[web2]:2222 %s\n'
                                    % (self.RSA, self.ECD))], '')
        self.assertEqual([x['line'] for x in r], ['192.0.2.21 ' + self.ED,
                                                  '[web2]:2222 ' + self.ECD])
        self.assertEqual([x['status'] for x in r], ['new', 'new'])
        self.assertEqual(len(r[0]['keys']), 3)

    def test_per_host_same_other_new(self):
        field = ['web1 ' + self.RSA, '[web2]:2222 ' + self.ED2]
        r = self.K.hostkey_report([('web1', 22, 'web1 %s\nweb1 %s' % (self.ED, self.RSA)),
                                   ('web2', 2222, '[web2]:2222 ' + self.ED),
                                   ('web3', 22, 'web3 ' + self.ED)], field)
        self.assertEqual([x['status'] for x in r], ['same', 'other', 'new'])
        self.assertEqual(r[1]['pinned'], ['[web2]:2222 ' + self.ED2])
        self.assertEqual(r[1]['line'], '[web2]:2222 ' + self.ED)

    def test_one_machine_every_line_pins_it(self):
        r = self.K.hostkey_report([('h', 22, 'h ' + self.ED)], 'server.local ' + self.ED,
                                  per_host=False)
        self.assertEqual(r[0]['status'], 'same')
        r = self.K.hostkey_report([('h', 22, 'h ' + self.ED)], 'junk', per_host=False)
        self.assertEqual((r[0]['status'], r[0]['pinned']), ('other', ['junk']))
        r = self.K.hostkey_report([('h', 22, 'h ' + self.ED)], None, per_host=False)
        self.assertEqual(r[0]['status'], 'new')

    def test_where_and_field(self):
        self.assertEqual(self.K._where('2001:db8::1:2222'), ('2001:db8::1', 2222))
        self.assertEqual(self.K._where('web1:22'), ('web1', 22))
        from acmelib.plugins.targets.mikrotik import MikroTikTarget
        from acmelib.plugins.targets.opnsense import OPNsenseTarget
        from acmelib.plugins.targets.ssh import SshTarget
        for cls, key, want in ((SshTarget, 'key', 'hostkey'), (OPNsenseTarget, 'ssh_key', 'ssh_hostkey'),
                               (MikroTikTarget, 'ssh_key', 'hostkey')):
            f = [x for x in cls.fields if x['key'] == key][0]
            self.assertEqual(self.K.hostkey_key(cls, f), want, cls.__name__)

if __name__ == '__main__':
    unittest.main(verbosity=2)
