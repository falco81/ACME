#!/usr/bin/env python3
"""The target modules, without a network and without a device.

    python3 -m unittest test/test_targets.py      (or python3 test/test_targets.py)

A fake Context records every ctx.http request and answers it from canned
responses per module; a fake SSH session records commands and files (or, for
the ssh module's rollback, runs them for real with sh in a temporary folder);
the TLS check is tried against a real local TLS server in a thread. The
certificates are made with openssl.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from acmelib.plugins.base import Bundle, Context, PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402

TMP = None
CERTS = {}


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


def read(path, mode='r'):
    with open(path, mode) as fh:
        return fh.read()


def setUpModule():
    global TMP
    TMP = tempfile.mkdtemp(prefix='acme-targets-')
    j = lambda n: os.path.join(TMP, n)  # noqa: E731
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', j('ca.key'), '-out', j('ca.crt'), '-days', '30', '-subj', '/CN=Test CA')
    for leaf in ('a', 'b'):
        openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', j(leaf + '.key'), '-out', j(leaf + '.csr'),
                '-subj', '/CN=www.example.test')
        with open(j('ext'), 'w') as fh:
            fh.write('subjectAltName=DNS:www.example.test,DNS:example.test\n')
        openssl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j('ca.crt'), '-CAkey', j('ca.key'),
                '-CAcreateserial', '-days', '10', '-out', j(leaf + '.crt'), '-extfile', j('ext'))
        CERTS[leaf] = (j(leaf + '.crt'), j(leaf + '.key'))


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class FakeBundle(Bundle):
    def __init__(self, leaf='a', name='www.example.test'):
        crt, key = CERTS[leaf]
        self.cert_pem = read(crt)
        self.key_pem = read(key)
        self.chain_pems = [read(os.path.join(TMP, 'ca.crt'))]
        self.fullchain_pem = self.cert_pem + self.chain_pems[0]
        self.name = name
        self.names = ['www.example.test', 'example.test']
        der = C.pem_to_der(self.cert_pem)
        self.fingerprint = hashlib.sha256(der).hexdigest()
        self.serial = openssl('x509', '-noout', '-serial', '-in', crt).decode().split('=')[1].strip()
        self.not_before = 1793491200          # 2026-11-01
        self.not_after = self.not_before + 90 * 86400
        self.key_file = key
        self.crt_file = crt

    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'cert-pem':
            return self.cert_pem.encode()
        if fmt in ('key-pem', 'key-rsa'):
            return self.key_pem.encode()
        if fmt == 'chain-pem':
            return ''.join(self.chain_pems).encode()
        if fmt == 'fullchain-pem':
            return self.fullchain_pem.encode()
        if fmt == 'combined-pem':
            return (self.key_pem + self.fullchain_pem).encode()
        if fmt == 'cert-der':
            return C.pem_to_der(self.cert_pem)
        if fmt in ('pfx', 'p12', 'p12-legacy'):
            return openssl('pkcs12', '-export', '-inkey', self.key_file, '-in', self.crt_file,
                           '-passout', 'pass:%s' % (password or ''), '-name', alias or 'x')
        if fmt == 'jks':
            return b'\xfe\xed\xfe\xed' + (alias or '').encode()
        raise ValueError(fmt)


# ---------------------------------------------------------------------------
class FakeSsh(object):
    """Records; answers commands from [(regex, (rc, out, err) | callable)]. With
    local=True runs them with sh on this machine instead."""
    def __init__(self, answers=None, local=False):
        self.answers = list(answers or [])
        self.local = local
        self.runs, self.puts, self.vias = [], [], []
        self.conns = []

    def __call__(self, conn):
        self.conns.append(conn)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def close(self):
        pass

    def run(self, cmd, input=None, timeout=120, check=True):
        self.runs.append((cmd, input))
        if self.local:
            p = subprocess.run(cmd, shell=True, input=input, capture_output=True, text=True,
                               timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        for rx, ans in self.answers:
            if re.search(rx, cmd + '\n' + (input or '')):
                return ans(cmd, input) if callable(ans) else ans
        return 0, '', ''

    def put(self, data, path, mode=0o600, owner=None, via='shell'):
        self.puts.append((path, data, mode))
        self.vias.append(via)
        if self.local:
            with open(path, 'wb') as fh:
                fh.write(data)
            os.chmod(path, mode)

    def get(self, path):
        return read(path, 'rb')


class FakeCtx(Context):
    def __init__(self, routes=None, ssh=None):
        self.routes = list(routes or [])
        self.calls = []
        self.steps = []
        self.kv = {}
        self._ssh = ssh or FakeSsh()

    def step(self, words, level='info'):
        self.steps.append((level, words))

    def kv_get(self, key):
        return self.kv.get(key)

    def kv_set(self, key, value, ttl_s=None):
        self.kv[key] = value

    def ssh(self, conn):
        return self._ssh(conn)

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        call = {'method': method, 'url': url, 'body': body, 'headers': dict(headers or {}),
                'path': urllib.parse.urlsplit(url).path,
                'query': urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)}
        self.calls.append(call)
        for m, rx, ans in self.routes:
            if m == method and re.search(rx, url):
                if callable(ans):
                    ans = ans(call)
                st, data = ans[0], ans[1]
                hd = ans[2] if len(ans) > 2 else {}
                if isinstance(data, (dict, list)):
                    data = json.dumps(data).encode()
                elif isinstance(data, str):
                    data = data.encode()
                return st, hd, data
        raise AssertionError('no canned answer for %s %s' % (method, url))

    def json(self, call):
        return json.loads(call['body'])

    def find(self, method, rx):
        return [c for c in self.calls if c['method'] == method and re.search(rx, c['url'])]


def make(kind, config, ctx):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    return reg.get('target', kind)(config, ctx)


# ---------------------------------------------------------------------------
class CommonTest(unittest.TestCase):
    def test_names_and_prune(self):
        b = FakeBundle()
        n = C.object_name(b, {})
        self.assertTrue(re.match(r'^acme-www\.example\.test-20261101-[0-9a-f]{8}$', n), n)
        self.assertLessEqual(len(C.object_name(b, {}, maxlen=35, serial_len=6)), 35)
        self.assertEqual(C.label_of(b, {'object_name': '*.Example.COM'}), 'wildcard.example.com')
        p = C.name_prefix(b, {})
        names = [p + '20260101-aaaa0001', p + '20260301-aaaa0002', p + '20260601-aaaa0003',
                 n, 'acme-other-20260101-aaaa0001', p + 'not-dated']
        self.assertEqual(C.prune(names, p, 1, n), [p + '20260301-aaaa0002', p + '20260101-aaaa0001'])
        self.assertEqual(C.prune(names, p, 5, n), [])

    def test_fingerprints(self):
        self.assertEqual(C.norm_fp('AB:cd:01'), 'abcd01')
        b = FakeBundle()
        self.assertEqual(C.fp_of(b), b.fingerprint)
        self.assertEqual(len(C.sha1_thumb(b)), 40)
        self.assertEqual(C.split_hostport('[2001:db8::1]:8443'), ('2001:db8::1', 8443))
        self.assertEqual(C.split_hostport('h.example'), ('h.example', 443))

    def test_multipart(self):
        body, ctype = C.multipart([('a', '1'), ('f', ('x.p12', b'\x00\x01', 'application/x'))])
        boundary = ctype.split('boundary=')[1]
        self.assertIn(b'name="f"; filename="x.p12"', body)
        self.assertTrue(body.endswith(('--%s--\r\n' % boundary).encode()))


class TlsVerifyTest(unittest.TestCase):
    """check_served() against a TLS server in a thread."""
    def setUp(self):
        crt, key = CERTS['a']
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(crt, key)
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.sni_seen = []
        sctx.sni_callback = lambda s, name, c: self.sni_seen.append(name)
        self.stop = False

        def serve():
            while not self.stop:
                try:
                    conn, _ = self.sock.accept()
                except OSError:
                    return
                try:
                    with sctx.wrap_socket(conn, server_side=True) as t:
                        t.recv(1)
                except (ssl.SSLError, OSError):
                    pass
        self.t = threading.Thread(target=serve, daemon=True)
        self.t.start()

    def tearDown(self):
        self.stop = True
        self.sock.close()

    def test_served(self):
        a, b = FakeBundle('a'), FakeBundle('b')
        self.assertEqual(C.served_fingerprint('127.0.0.1', self.port, 'www.example.test'),
                         a.fingerprint)
        self.assertIn('www.example.test', self.sni_seen)
        ctx = FakeCtx()
        hp = '127.0.0.1:%d' % self.port
        self.assertTrue(C.check_served(ctx, a, hp, tries=1))
        self.assertFalse(C.check_served(ctx, b, hp, tries=2, sleep=lambda s: None))
        self.assertIsNone(C.check_served(ctx, a, '127.0.0.1:1', tries=1))
        # through a module's verify()
        t = make('webhook', {'url': 'https://x'}, ctx)
        self.assertTrue(t.verify(a, {'verify': hp, 'verify_sni': 'www.example.test'}))
        self.assertIsNone(t.verify(a, {}))


# ---------------------------------------------------------------------------
class SshOutputsTest(unittest.TestCase):
    def test_parse(self):
        outs = C.parse_outputs('''
            # comment
            fullchain /etc/nginx/ssl/{name}.crt 0644 root:root
            key-pem   /etc/nginx/ssl/{name}.key
            pfx /opt/app/keystore.p12 640 app
        ''', {'name': 'site'})
        self.assertEqual([o['format'] for o in outs], ['fullchain-pem', 'key-pem', 'pfx'])
        self.assertEqual(outs[0]['path'], '/etc/nginx/ssl/site.crt')
        self.assertEqual((outs[0]['mode'], outs[0]['owner']), (0o644, 'root:root'))
        self.assertEqual(outs[1]['mode'], 0o600)          # a key: 0600 unless said
        self.assertEqual((outs[2]['mode'], outs[2]['owner']), (0o640, 'app'))
        for bad in ('pem', 'nope /x', 'key-pem relative/path', 'key-pem /a/../etc/shadow',
                    'key-pem /x root:root:x', 'key-pem /x;rm 0600', 'key-pem /x\nkey-pem /x',
                    'key-pem /x 0600 root:root extra'):
            with self.assertRaises(PluginError, msg=bad):
                C.parse_outputs(bad)

    def test_presets(self):
        from acmelib.plugins.targets import ssh as mod
        t = make('ssh', {'host': 'srv'}, FakeCtx())
        b = FakeBundle()
        for key in mod.PRESETS:
            if key == 'custom':
                continue
            r = t.resolved(b, {'preset': key})
            self.assertTrue(r['files'], key)
        r = t.resolved(b, {'preset': 'nginx'})
        self.assertEqual(r['files'][0]['path'], '/etc/nginx/ssl/www.example.test.crt')
        self.assertEqual(r['test_cmd'], ['nginx -t'])
        r = t.resolved(b, {'preset': 'nginx', 'reload_cmd': 'systemctl restart nginx'})
        self.assertEqual(r['reload_cmd'], ['systemctl restart nginx'])   # yours wins
        r = t.resolved(b, {'preset': 'docker', 'service': 'proxy'})
        self.assertEqual(r['reload_cmd'], ['docker restart proxy'])
        fills = [f for f in t.deploy_fields if f['key'] == 'preset'][0]['fills']
        self.assertIn('nginx -t', fills['nginx']['test_cmd'])
        with self.assertRaises(PluginError):
            t.resolved(b, {'preset': 'custom'})

    def test_jks_needs_password(self):
        t = make('ssh', {'host': 'srv'}, FakeCtx())
        with self.assertRaises(PluginError):
            t.render(FakeBundle(), t.resolved(FakeBundle(), {'outputs': 'jks /x/k.jks'}))


class SshDeployTest(unittest.TestCase):
    """The files written for real (sh in a temporary folder)."""
    def setUp(self):
        self.d = tempfile.mkdtemp(dir=TMP)
        self.ssh = FakeSsh(local=True)
        self.ctx = FakeCtx(ssh=self.ssh)
        self.t = make('ssh', {'host': 'srv', 'user': 'deploy', 'tmp_dir': self.d}, self.ctx)
        self.crt = os.path.join(self.d, 'ssl', 'site.crt')
        self.key = os.path.join(self.d, 'ssl', 'site.key')
        os.makedirs(os.path.dirname(self.crt))
        with open(self.crt, 'w') as fh:
            fh.write('OLD CERT\n')
        self.opts = {'outputs': 'fullchain-pem %s 0644\nkey-pem %s 0600' % (self.crt, self.key),
                     'test_cmd': 'true', 'reload_cmd': 'echo reloaded'}

    def test_writes_then_noop(self):
        b = FakeBundle()
        words = self.t.deploy(b, self.opts)
        self.assertIn('2 files written', words)
        self.assertEqual(read(self.crt), b.fullchain_pem)
        self.assertEqual(read(self.key), b.key_pem)
        self.assertEqual(os.stat(self.key).st_mode & 0o777, 0o600)
        kept = [x for x in os.listdir(os.path.dirname(self.crt)) if x.startswith('site.crt.')
                and x.endswith('.bak')]                       # name.<date>-<time>.bak (1.0.77)
        self.assertEqual(len(kept), 1)
        self.assertEqual(read(os.path.join(os.path.dirname(self.crt), kept[0])), 'OLD CERT\n')
        self.assertFalse([f for f in os.listdir(self.d) if f.startswith('.acme-')])  # temp gone
        self.assertTrue(any(c.startswith('sh -c') and 'echo reloaded' in c
                            for c, _ in self.ssh.runs))
        n = len(self.ssh.puts)
        self.assertTrue(self.t.deploy(b, self.opts).startswith('unchanged'))
        self.assertEqual(len(self.ssh.puts), n)
        self.t.deploy(b, dict(self.opts, force=True))
        self.assertGreater(len(self.ssh.puts), n)

    def test_rollback_when_test_fails(self):
        b = FakeBundle()
        with self.assertRaises(PluginError) as e:
            self.t.deploy(b, dict(self.opts, test_cmd='echo broken config >&2; false'))
        self.assertIn('previous files are back', str(e.exception))
        self.assertEqual(read(self.crt), 'OLD CERT\n')
        self.assertFalse(os.path.exists(self.key))          # was not there: gone again
        self.assertFalse(any('echo reloaded' in c for c, _ in self.ssh.runs))

    def test_rollback_when_reload_fails(self):
        with self.assertRaises(PluginError):
            self.t.deploy(FakeBundle(), dict(self.opts, reload_cmd='false'))
        self.assertEqual(read(self.crt), 'OLD CERT\n')

    def test_sudo(self):
        ssh = FakeSsh()
        t = make('ssh', {'host': 'srv', 'user': 'u', 'sudo': True, 'sudo_password': 'pw'},
                 FakeCtx(ssh=ssh))
        t.deploy(FakeBundle(), {'preset': 'nginx'})
        cmds = [c for c, _ in ssh.runs if 'nginx -t' in c]
        self.assertTrue(cmds and cmds[0].startswith("sudo -S -p '' sh -c "))
        self.assertTrue(all(i == 'pw\n' for c, i in ssh.runs if c.startswith('sudo')))
        self.assertTrue(all(p.startswith('/tmp/.acme-') for p, _, _ in ssh.puts))
        install = [c for c, _ in ssh.runs if 'mv -f' in c][0]
        self.assertIn('chown root:root', install)
        self.assertIn('/etc/nginx/ssl/www.example.test.key.acme-new', install)


class LocalTest(unittest.TestCase):
    def test_restricted(self):
        base = tempfile.mkdtemp(dir=TMP)
        ctx = FakeCtx()
        t = make('local', {'base': base, 'allow_commands': 'true'}, ctx)
        b = FakeBundle()
        t.deploy(b, {'outputs': 'fullchain-pem {name}/fullchain.pem\nkey-pem {name}/key.pem',
                     'command': 'true'})
        self.assertEqual(read(os.path.join(base, 'www.example.test', 'fullchain.pem')),
                         b.fullchain_pem)
        with self.assertRaises(PluginError):
            t.deploy(b, {'outputs': 'key-pem ../escape.pem'})
        with self.assertRaises(PluginError):
            t.deploy(b, {'outputs': 'key-pem x.pem', 'command': 'rm -rf /'})
        os.symlink('/tmp', os.path.join(base, 'link'))
        with self.assertRaises(PluginError):
            t.deploy(b, {'outputs': 'key-pem link/x.pem', 'force': True})


# ---------------------------------------------------------------------------
class F5Test(unittest.TestCase):
    def routes(self, installed=()):
        installed = set(installed)

        def crypto_get(call):
            name = call['path'].rsplit('/', 1)[1].replace('~', '/')
            return (200, {'name': name}) if name in installed else (404, {'code': 404})

        def install(call):
            installed.add(json.loads(call['body'])['name'])
            return 200, {}
        return [
            ('POST', r'/mgmt/shared/authn/login$', (200, {'token': {'token': 'TOK'}})),
            ('DELETE', r'/mgmt/shared/authz/tokens/TOK', (200, {})),
            ('GET', r'/mgmt/tm/sys/crypto/cert\?', (200, {'items': [
                {'name': 'acme-www.example.test-20250101-00000001'},
                {'name': 'acme-www.example.test-20250401-00000002'},
                {'name': 'acme-www.example.test-20250701-00000003'},
                {'name': 'default.crt'}]})),
            ('GET', r'/mgmt/tm/sys/crypto/(cert|key)/', crypto_get),
            ('POST', r'/mgmt/shared/file-transfer/uploads/', (200, {})),
            ('POST', r'/mgmt/tm/sys/crypto/(cert|key)$', install),
            ('POST', r'/mgmt/tm/util/unix-rm', (200, {})),
            ('GET', r'/mgmt/tm/ltm/profile/client-ssl/~Common~www_ssl', (200, {
                'name': 'www_ssl', 'certKeyChain': [
                    {'name': 'default', 'cert': '/Common/default.crt',
                     'key': '/Common/default.key', 'chain': 'none'},
                    {'name': 'rsa', 'cert': '/Common/rsa.crt', 'key': '/Common/rsa.key'}]})),
            ('PATCH', r'/mgmt/tm/ltm/profile/client-ssl/~Common~www_ssl', (200, {})),
            ('DELETE', r'/mgmt/tm/sys/crypto/', (200, {})),
            ('POST', r'/mgmt/tm/sys/config$', (200, {})),
            ('POST', r'/mgmt/tm/cm$', (200, {})),
        ]

    def test_deploy(self):
        ctx = FakeCtx(self.routes())
        t = make('f5', {'host': 'bigip', 'user': 'acme', 'password': 'pw',
                        'device_group': 'dg1'}, ctx)
        b = FakeBundle()
        name = C.object_name(b, {})
        words = t.deploy(b, {'profiles': 'www_ssl', 'keep': 1})
        login = ctx.json(ctx.calls[0])
        self.assertEqual(login, {'username': 'acme', 'password': 'pw',
                                 'loginProviderName': 'tmos'})
        self.assertTrue(all(c['headers'].get('X-F5-Auth-Token') == 'TOK' for c in ctx.calls[1:]))
        ups = ctx.find('POST', 'file-transfer/uploads/')
        self.assertEqual([c['path'].rsplit('/', 1)[1] for c in ups],
                         [name + '.key', name + '.crt', 'acme-chain-' + C.chain_id(b.chain_pems[0])
                          + '.crt'])
        for c in ups:
            self.assertEqual(c['headers']['Content-Range'], '0-%d/%d' % (len(c['body']) - 1,
                                                                        len(c['body'])))
            self.assertEqual(c['headers']['Content-Type'], 'application/octet-stream')
        self.assertEqual(ups[1]['body'], b.cert_pem.encode())
        inst = [ctx.json(c) for c in ctx.find('POST', r'/sys/crypto/(cert|key)$')]
        self.assertEqual(inst[0], {'command': 'install', 'name': '/Common/' + name,
                                   'from-local-file': '/var/config/rest/downloads/%s.key' % name})
        patch = ctx.json(ctx.find('PATCH', 'client-ssl')[0])['certKeyChain']
        self.assertEqual(patch[0]['cert'], '/Common/' + name)
        self.assertEqual(patch[0]['key'], '/Common/' + name)
        self.assertTrue(patch[0]['chain'].startswith('/Common/acme-chain-'))
        self.assertEqual(patch[1]['cert'], '/Common/rsa.crt')       # the other entry kept
        deleted = [c['path'] for c in ctx.find('DELETE', '/sys/crypto/cert/')]
        self.assertEqual(deleted, ['/mgmt/tm/sys/crypto/cert/~Common~acme-www.example.test-'
                                   '20250401-00000002',
                                   '/mgmt/tm/sys/crypto/cert/~Common~acme-www.example.test-'
                                   '20250101-00000001'])
        self.assertEqual(ctx.json(ctx.find('POST', '/sys/config$')[0]), {'command': 'save'})
        self.assertIn('config-sync to-group dg1', ctx.json(ctx.find('POST', '/tm/cm$')[0])
                      ['utilCmdArgs'])
        self.assertTrue(ctx.find('DELETE', 'authz/tokens/TOK'))
        self.assertIn('synced to dg1', words)
        # again: a no-op
        ctx.calls = []
        ctx.routes = self.routes(installed=['/Common/' + name])
        self.assertTrue(t.deploy(b, {'profiles': 'www_ssl', 'keep': 1}).startswith('unchanged'))
        self.assertFalse(ctx.find('POST', 'uploads'))
        self.assertFalse(ctx.find('PATCH', '.'))

    def test_chunks(self):
        ctx = FakeCtx(self.routes())
        t = make('f5', {'host': 'bigip', 'user': 'u', 'password': 'p'}, ctx)
        from acmelib.plugins.targets import f5
        data = b'x' * (f5.CHUNK * 2 + 10)
        t.upload('big.bin', data)
        ranges = [c['headers']['Content-Range'] for c in ctx.calls]
        total = len(data)
        self.assertEqual(ranges, ['0-%d/%d' % (f5.CHUNK - 1, total),
                                  '%d-%d/%d' % (f5.CHUNK, 2 * f5.CHUNK - 1, total),
                                  '%d-%d/%d' % (2 * f5.CHUNK, total - 1, total)])

    def test_test_and_bad_login(self):
        ctx = FakeCtx(self.routes() + [('GET', '/mgmt/tm/sys/version', (200, {'entries': {
            'x': {'nestedStats': {'entries': {'Product': {'description': 'BIG-IP'},
                                              'Version': {'description': '17.1.1'}}}}}}))])
        t = make('f5', {'host': 'bigip', 'user': 'u', 'password': 'p'}, ctx)
        self.assertIn('BIG-IP 17.1.1', t.test())
        ctx = FakeCtx([('POST', 'authn/login', (401, {'message': 'Authentication failed'}))])
        with self.assertRaises(PluginError) as e:
            make('f5', {'host': 'bigip', 'user': 'u', 'password': 'p'}, ctx).test()
        self.assertFalse(e.exception.retry)
        self.assertIn('Authentication failed', str(e.exception))


class NetScalerTest(unittest.TestCase):
    def test_deploy_new(self):
        b = FakeBundle()
        stem = C.object_name(b, {})
        ca = 'acme-ca-' + C.chain_id(b.chain_pems[0])
        made = set()

        def certkey_get(call):
            n = call['path'].rsplit('/', 1)[1]
            if n in made:
                return 200, {'errorcode': 0, 'sslcertkey': [{'certkey': n, 'cert': 'x'}]}
            return 404, {'errorcode': 258, 'message': 'No such resource'}

        def certkey_add(call):
            made.add(json.loads(call['body'])['sslcertkey']['certkey'])
            return 201, {'errorcode': 0}
        ctx = FakeCtx([
            ('POST', r'/nitro/v1/config/login$', (201, {'errorcode': 0, 'sessionid': 'SID'})),
            ('POST', r'/nitro/v1/config/logout$', (201, {'errorcode': 0})),
            ('DELETE', r'/systemfile/', (200, {'errorcode': 0})),
            ('POST', r'/nitro/v1/config/systemfile$', (201, {'errorcode': 0})),
            ('GET', r'/nitro/v1/config/sslcertkey/', certkey_get),
            ('POST', r'/nitro/v1/config/sslcertkey$', certkey_add),
            ('POST', r'/sslcertkey\?action=link', (200, {'errorcode': 0})),
            ('GET', r'/sslvserver_sslcertkey_binding/vs_www', (200, {'errorcode': 0,
                                                                     'sslvserver_sslcertkey_binding': []})),
            ('PUT', r'/sslvserver_sslcertkey_binding$', (200, {'errorcode': 0})),
            ('POST', r'/nsconfig\?action=save', (200, {'errorcode': 0})),
            ('GET', r'/systemfile\?args=', (200, {'errorcode': 0, 'systemfile': [
                {'filename': stem + '.crt'}, {'filename': stem + '.key'},
                {'filename': 'acme-www.example.test-20250101-00000001.crt'},
                {'filename': 'acme-www.example.test-20250101-00000001.key'},
                {'filename': 'ns-server.cert'}]})),
        ])
        t = make('netscaler', {'host': 'adc', 'user': 'nsroot', 'password': 'pw'}, ctx)
        words = t.deploy(b, {'vservers': 'vs_www sni', 'keep': 0})
        self.assertEqual(ctx.json(ctx.calls[0]), {'login': {'username': 'nsroot',
                                                            'password': 'pw', 'timeout': 900}})
        self.assertTrue(all(c['headers'].get('Cookie') == 'NITRO_AUTH_TOKEN=SID'
                            for c in ctx.calls[1:]))
        ups = [ctx.json(c)['systemfile'] for c in ctx.find('POST', 'systemfile$')]
        self.assertEqual([u['filename'] for u in ups], [stem + '.crt', stem + '.key', ca + '.crt'])
        self.assertEqual(base64.b64decode(ups[0]['filecontent']).decode(), b.cert_pem)
        self.assertTrue(all(u['filelocation'] == '/nsconfig/ssl' and
                            u['fileencoding'] == 'BASE64' for u in ups))
        add = ctx.json(ctx.find('POST', 'sslcertkey$')[0])['sslcertkey']
        self.assertEqual(add, {'certkey': 'acme-www.example.test', 'cert': stem + '.crt',
                               'key': stem + '.key'})
        link = ctx.json(ctx.find('POST', 'action=link')[0])['sslcertkey']
        self.assertEqual(link, {'certkey': 'acme-www.example.test', 'linkcertkeyname': ca})
        bind = ctx.json(ctx.find('PUT', 'binding$')[0])['sslvserver_sslcertkey_binding']
        self.assertEqual(bind, {'vservername': 'vs_www', 'certkeyname': 'acme-www.example.test',
                                'snicert': True})
        self.assertTrue(ctx.find('POST', 'action=save'))
        dels = [c['path'] for c in ctx.find('DELETE', 'systemfile/acme-www.example.test-2025')]
        self.assertEqual(len(dels), 2)
        self.assertTrue(ctx.find('POST', 'logout$'))
        self.assertIn('added acme-www.example.test', words)

    def test_update_in_place(self):
        b = FakeBundle()
        ctx = FakeCtx([
            ('POST', r'/login$', (201, {'sessionid': 'SID'})),
            ('POST', r'/logout$', (201, {})),
            ('DELETE', r'/systemfile/', (200, {})),
            ('POST', r'/systemfile$', (201, {})),
            ('GET', r'/sslcertkey/', (200, {'sslcertkey': [{'cert': 'old.crt',
                                                            'linkcertkeyname': 'oldca'}]})),
            ('POST', r'action=update', (200, {'errorcode': 0})),
            ('POST', r'action=unlink', (200, {})),
            ('POST', r'action=link', (200, {})),
            ('POST', r'action=save', (200, {})),
            ('GET', r'/systemfile\?', (200, {'systemfile': []})),
        ])
        t = make('netscaler', {'host': 'adc', 'user': 'u', 'password': 'p'}, ctx)
        t.deploy(b, {'certkey': 'www'})
        upd = ctx.json(ctx.find('POST', 'action=update')[0])['sslcertkey']
        self.assertEqual(upd['certkey'], 'www')
        self.assertIs(upd['nodomaincheck'], True)
        self.assertTrue(ctx.find('POST', 'action=unlink'))


class NetScaler599Test(unittest.TestCase):
    """NITRO says "not there" as HTTP 599 with an errorcode (1540 "Certificate does not
    exist" for a certkey, as a NetScaler answered; 258 "No such resource"): the certkey
    is added, a vserver not there is said; another 599 stays an error (1.0.31)."""
    def ctx(self, ck_answer, vs_answer=(200, {'errorcode': 0, 'sslvserver_sslcertkey_binding': []})):
        made = set()

        def certkey_get(call):
            n = call['path'].rsplit('/', 1)[1]
            if n in made:
                return 200, {'errorcode': 0, 'sslcertkey': [{'certkey': n, 'cert': 'x'}]}
            return ck_answer

        def certkey_add(call):
            made.add(json.loads(call['body'])['sslcertkey']['certkey'])
            return 201, {'errorcode': 0}
        return FakeCtx([
            ('POST', r'/nitro/v1/config/login$', (201, {'errorcode': 0, 'sessionid': 'SID'})),
            ('POST', r'/nitro/v1/config/logout$', (201, {'errorcode': 0})),
            ('DELETE', r'/systemfile/', (200, {'errorcode': 0})),
            ('POST', r'/nitro/v1/config/systemfile$', (201, {'errorcode': 0})),
            ('GET', r'/nitro/v1/config/sslcertkey/', certkey_get),
            ('POST', r'/nitro/v1/config/sslcertkey$', certkey_add),
            ('POST', r'/sslcertkey\?action=link', (200, {'errorcode': 0})),
            ('GET', r'/sslvserver_sslcertkey_binding/', vs_answer),
            ('PUT', r'/sslvserver_sslcertkey_binding$', (200, {'errorcode': 0})),
            ('POST', r'/nsconfig\?action=save', (200, {'errorcode': 0})),
            ('GET', r'/systemfile\?args=', (200, {'errorcode': 0, 'systemfile': []})),
        ])

    def test_certificate_does_not_exist_is_added(self):
        ctx = self.ctx((599, {'errorcode': 1540, 'message': 'Certificate does not exist',
                              'severity': 'ERROR'}))
        t = make('netscaler', {'host': 'adc', 'user': 'u', 'password': 'p'}, ctx)
        words = t.deploy(FakeBundle(), {'vservers': 'vs_www'})
        self.assertIn('added acme-www.example.test', words)
        added = [json.loads(c['body'])['sslcertkey']['certkey']
                 for c in ctx.find('POST', 'sslcertkey$')]
        self.assertEqual(len(added), 2, 'the certkey and its CA, both found missing by 599')

    def test_no_such_vserver_said(self):
        ctx = self.ctx((599, {'errorcode': 258, 'message': 'No such resource'}),
                       (599, {'errorcode': 258, 'message': 'No such resource'}))
        t = make('netscaler', {'host': 'adc', 'user': 'u', 'password': 'p'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {'vservers': 'vs_nope'})
        self.assertIn('no SSL virtual server vs_nope', str(e.exception))

    def test_another_599_stays_an_error(self):
        ctx = self.ctx((599, {'errorcode': 354, 'message': 'Invalid username or password'}))
        t = make('netscaler', {'host': 'adc', 'user': 'u', 'password': 'p'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.deploy(FakeBundle(), {})
        self.assertIn('Invalid username or password', str(e.exception))
        self.assertFalse(ctx.find('POST', 'sslcertkey$'), 'nothing added')


class FortiGateTest(unittest.TestCase):
    def test_deploy(self):
        b = FakeBundle()
        name = C.object_name(b, {}, maxlen=35, serial_len=6)
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        ctx = FakeCtx([
            ('GET', r'/vpn.certificate/local/acme', (404, {'status': 'error', 'http_status': 404})),
            ('POST', r'/monitor/vpn-certificate/local/import', (200, {'status': 'success'})),
            ('POST', r'/monitor/vpn-certificate/ca/import', (500, {'status': 'error',
                                                                  'error': -5})),
            ('PUT', r'/cmdb/system/global', (200, {'status': 'success'})),
            ('PUT', r'/cmdb/vpn.ssl/settings', (200, {'status': 'success'})),
            ('PUT', r'/cmdb/firewall/ssl-ssh-profile/inbound', (200, {'status': 'success'})),
            ('PUT', r'/cmdb/firewall/vip/web', (200, {'status': 'success'})),
            ('GET', r'/cmdb/vpn.certificate/local\?', (200, {'results': [
                {'name': prefix + '20250101-000001'}, {'name': prefix + '20250201-000002'},
                {'name': 'Fortinet_Factory'}, {'name': name}]})),
            ('DELETE', r'/cmdb/vpn.certificate/local/', (200, {'status': 'success'})),
            ('GET', r'/monitor/system/status', (200, {'status': 'success',
                                                      'version': 'v7.2.8'})),
        ])
        t = make('fortigate', {'host': 'fw', 'token': 'TKN', 'vdom': 'root'}, ctx)
        t.deploy(b, {'admin': True, 'sslvpn': True, 'ssl_ssh_profiles': 'inbound',
                     'vips': 'web', 'keep': 1})
        self.assertLessEqual(len(name), 35)
        self.assertTrue(all(c['headers']['Authorization'] == 'Bearer TKN' for c in ctx.calls))
        imp = ctx.find('POST', 'local/import')[0]
        body = ctx.json(imp)
        self.assertEqual((body['type'], body['certname'], body['scope']), ('pkcs12', name, 'global'))
        p12 = base64.b64decode(body['file_content'])
        out = openssl('pkcs12', '-in', '/dev/stdin', '-nokeys', '-passin',
                      'pass:' + body['password'], data=p12)
        self.assertIn(b'BEGIN CERTIFICATE', out)
        self.assertEqual(ctx.json(ctx.find('PUT', 'system/global')[0]), {'admin-server-cert': name})
        sv = ctx.find('PUT', 'vpn.ssl/settings')[0]
        self.assertEqual(sv['query']['vdom'], ['root'])
        self.assertEqual(ctx.json(sv), {'servercert': name})
        self.assertEqual(ctx.json(ctx.find('PUT', 'ssl-ssh-profile')[0]),
                         {'server-cert': [{'name': name}]})
        self.assertEqual(ctx.json(ctx.find('PUT', 'firewall/vip')[0]), {'ssl-certificate': name})
        dels = [urllib.parse.unquote(c['path'].rsplit('/', 1)[1])
                for c in ctx.find('DELETE', '.')]
        self.assertEqual(dels, [prefix + '20250101-000001'])

    def test_regular_import(self):
        b = FakeBundle()
        ctx = FakeCtx([('GET', r'/local/', (404, {})),
                       ('POST', r'/local/import', (200, {'status': 'success'})),
                       ('GET', r'/local\?', (200, {'results': []}))])
        t = make('fortigate', {'host': 'fw', 'token': 'T', 'vdom': ''}, ctx)
        t.deploy(b, {'import_as': 'regular', 'import_chain': False, 'scope': 'vdom'})
        body = ctx.json(ctx.find('POST', 'import')[0])
        self.assertEqual(base64.b64decode(body['key_file_content']).decode(), b.key_pem)
        self.assertEqual(body['type'], 'regular')


class MikroTikTest(unittest.TestCase):
    def test_rest(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        prefix = C.name_prefix(b, {})
        certs = [{'.id': '*1', 'name': prefix + '20250101-00000001', 'fingerprint': 'aa'},
                 {'.id': '*2', 'name': prefix + '20250301-00000002', 'fingerprint': 'bb'}]

        def imp(call):
            fn = json.loads(call['body'])['file-name']
            if fn.endswith('.crt'):
                certs.append({'.id': '*9', 'name': fn + '_0', 'fingerprint': b.fingerprint,
                              'private-key': 'false'})
            else:
                certs[-1]['private-key'] = 'true'
            return 200, [{'certificates-imported': '1'}]
        services = [{'.id': '*A', 'name': 'www-ssl', 'certificate': prefix + '20250301-00000002'},
                    {'.id': '*B', 'name': 'api-ssl', 'certificate': 'none'},
                    {'.id': '*C', 'name': 'ssh'}]

        def patch_service(call):
            sid = call['path'].rsplit('/', 1)[1]
            [s for s in services if s['.id'] == sid][0]['certificate'] = \
                json.loads(call['body'])['certificate']
            return 200, {}
        ssh = FakeSsh()
        ctx = FakeCtx([
            ('GET', r'/rest/certificate$', lambda c: (200, certs)),
            ('POST', r'/rest/certificate/import', imp),
            ('PATCH', r'/rest/certificate/', (200, {})),
            ('GET', r'/rest/file\?', (200, [{'.id': '*F'}])),
            ('DELETE', r'/rest/file/', (204, b'')),
            ('GET', r'/rest/ip/service$', lambda c: (200, services)),
            ('PATCH', r'/rest/ip/service/', patch_service),
            ('DELETE', r'/rest/certificate/', (204, b'')),
        ], ssh=ssh)
        t = make('mikrotik', {'host': 'rtr', 'user': 'acme', 'password': 'pw'}, ctx)
        t.deploy(b, {'services': 'www-ssl\napi-ssl', 'keep': 0})
        self.assertEqual([p for p, _, _ in ssh.puts], [name + '.crt', name + '.key'])
        self.assertEqual(ssh.puts[0][1], b.fullchain_pem.encode())
        self.assertEqual(ssh.vias, ['scp', 'scp'])            # RouterOS has no shell
        self.assertEqual(ssh.conns[0]['password'], 'pw')
        imps = [ctx.json(c) for c in ctx.find('POST', 'import')]
        self.assertEqual([i['file-name'] for i in imps], [name + '.crt', name + '.key'])
        self.assertEqual(ctx.json(ctx.find('PATCH', '/rest/certificate/')[0]), {'name': name})
        order = [c['path'] for c in ctx.find('PATCH', 'ip/service')]
        self.assertEqual(order, ['/rest/ip/service/*B', '/rest/ip/service/*A'])  # www-ssl last
        auth = ctx.calls[0]['headers']['Authorization']
        self.assertEqual(base64.b64decode(auth.split()[1]), b'acme:pw')
        self.assertEqual(sorted(c['path'] for c in ctx.find('DELETE', '/rest/certificate/')),
                         ['/rest/certificate/*1', '/rest/certificate/*2'])

    def test_ssh_v6(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        imported = []
        ssh = FakeSsh([
            (r'^:foreach c in=\[/certificate find where name~', lambda c, i: (
                0, '\n'.join(imported), '')),
            (r'^/certificate import file-name="[^"]+\.key"', lambda c, i: (
                imported.append(name), (0, 'certificates-imported: 1', ''))[1]),
        ])
        t = make('mikrotik', {'host': 'rtr', 'user': 'a', 'password': 'p', 'mode': 'ssh'},
                 FakeCtx(ssh=ssh))
        t.deploy(b, {'services': 'api-ssl\nsstp'})
        cmds = [c for c, _ in ssh.runs]
        self.assertIn('/certificate import file-name="%s.crt" passphrase=""' % name, cmds)
        self.assertIn('/ip service set [find where name="api-ssl"] certificate="%s"' % name, cmds)
        self.assertIn('/interface sstp-server server set certificate="%s"' % name, cmds)


class PaloAltoTest(unittest.TestCase):
    OK = '<response status="success"><result>%s</result></response>'

    def test_deploy_commit(self):
        b = FakeBundle()
        name = C.object_name(b, {})
        prefix = C.name_prefix(b, {})
        polls = []

        def api(call):
            if call['query'].get('type') == ['import']:
                return 200, '<response status="success"><msg>imported</msg></response>'
            p = urllib.parse.parse_qs(call['body'].decode())
            t = p['type'][0]
            if t == 'keygen':
                return 200, self.OK % '<key>KEY123</key>'
            if t == 'config' and p['action'][0] == 'get':
                if p['xpath'][0].endswith('/certificate'):
                    return 200, self.OK % ('<certificate><entry name="%s20250101-00000001"/>'
                                           '<entry name="%s"/></certificate>' % (prefix, name))
                return 200, self.OK % ''
            if t == 'config':
                return 200, '<response status="success" code="20"><msg>command succeeded</msg>' \
                            '</response>'
            if t == 'commit':
                return 200, self.OK % '<job>42</job>'
            if t == 'op':
                polls.append(1)
                st = 'FIN' if len(polls) > 1 else 'ACT'
                return 200, self.OK % ('<job><id>42</id><status>%s</status><result>%s</result>'
                                       '</job>' % (st, 'OK' if st == 'FIN' else 'PEND'))
            raise AssertionError(p)
        ctx = FakeCtx([('POST', r'/api/', api)])
        t = make('paloalto', {'host': 'pa', 'auth': 'password', 'user': 'acme',
                              'password': 'pw'}, ctx)
        t._sleep = lambda s: None
        words = t.deploy(b, {'profiles': 'gp-portal', 'keep': 0})
        self.assertEqual(urllib.parse.parse_qs(ctx.calls[0]['body'].decode()),
                         {'type': ['keygen'], 'user': ['acme'], 'password': ['pw']})
        self.assertTrue(all(c['headers'].get('X-PAN-KEY') == 'KEY123' for c in ctx.calls[1:]))
        imps = [c for c in ctx.calls if c['query'].get('type') == ['import']]
        self.assertEqual(imps[0]['query']['category'], ['keypair'])
        self.assertEqual(imps[0]['query']['format'], ['pkcs12'])
        self.assertEqual(imps[0]['query']['certificate-name'], [name])
        self.assertIn(b'filename="%s.p12"' % name.encode(), imps[0]['body'])
        self.assertTrue(imps[0]['headers']['Content-Type'].startswith('multipart/form-data'))
        self.assertEqual(imps[1]['query']['category'], ['certificate'])
        bodies = [urllib.parse.parse_qs(c['body'].decode()) for c in ctx.calls
                  if not c['query'].get('type')]
        sets = [x for x in bodies if x.get('action') == ['set']]
        self.assertEqual(sets[0]['xpath'], ["/config/shared/ssl-tls-service-profile/entry"
                                            "[@name='gp-portal']"])
        self.assertEqual(sets[0]['element'], ['<certificate>%s</certificate>' % name])
        dels = [x for x in bodies if x.get('action') == ['delete']]
        self.assertEqual(dels[0]['xpath'], ["/config/shared/certificate/entry[@name='%s"
                                            "20250101-00000001']" % prefix])
        commit = [x for x in bodies if x.get('type') == ['commit']][0]
        self.assertIn('<member>acme</member>', commit['cmd'][0])
        self.assertEqual(commit['action'], ['partial'])     # as the Commit page shows it
        self.assertEqual(len(polls), 2)
        self.assertIn('committed', words)

    def test_commit_fails(self):
        def api(call):
            p = urllib.parse.parse_qs(call['body'].decode())
            if p['type'][0] == 'commit':
                return 200, self.OK % '<job>7</job>'
            return 200, self.OK % ('<job><status>FIN</status><result>FAIL</result>'
                                   '<details><line>certificate is invalid</line></details></job>')
        ctx = FakeCtx([('POST', '/api/', api)])
        t = make('paloalto', {'host': 'pa', 'api_key': 'K'}, ctx)
        t.key = 'K'
        with self.assertRaises(PluginError) as e:
            t.commit('all', 10)
        self.assertIn('certificate is invalid', str(e.exception))

    def test_error_answer(self):
        ctx = FakeCtx([('POST', '/api/', (200, '<response status="error" code="403"><result>'
                                               '<msg>Invalid credentials.</msg></result>'
                                               '</response>'))])
        t = make('paloalto', {'host': 'pa', 'auth': 'password', 'user': 'u', 'password': 'x'}, ctx)
        with self.assertRaises(PluginError) as e:
            t.test()
        self.assertIn('Invalid credentials', str(e.exception))
        self.assertFalse(e.exception.retry)


# ---------------------------------------------------------------------------
class OthersTest(unittest.TestCase):
    def test_webhook_signature(self):
        ctx = FakeCtx([('POST', r'hooks\.example', (200, {}))])
        t = make('webhook', {'url': 'https://hooks.example/c', 'secret': 's3cret'}, ctx)
        b = FakeBundle()
        t.deploy(b, {})
        c = ctx.calls[0]
        ts = c['headers']['X-Acme-Timestamp']
        want = 'sha256=' + hmac.new(b's3cret', ts.encode() + b'.' + c['body'],
                                    hashlib.sha256).hexdigest()
        self.assertEqual(c['headers']['X-Acme-Signature'], want)
        d = json.loads(c['body'])
        self.assertEqual(d['fingerprint'], b.fingerprint)
        self.assertNotIn('key_pem', d)                          # keys stay unless asked
        self.assertTrue(t.deploy(b, {}).startswith('unchanged'))
        with self.assertRaises(PluginError):
            t.deploy(b, {'body': 'multipart', 'formats': 'key-pem', 'force': True})

    def test_vault(self):
        b = FakeBundle()
        ctx = FakeCtx([
            ('GET', r'/v1/secret/data/acme/www', (404, {'errors': []})),
            ('POST', r'/v1/secret/data/acme/www', (200, {'data': {'version': 3}})),
        ])
        t = make('vault', {'host': 'https://vault:8200', 'token': 'VT'}, ctx)
        self.assertIn('version 3', t.deploy(b, {}))
        post = ctx.find('POST', '.')[0]
        self.assertEqual(post['headers']['X-Vault-Token'], 'VT')
        self.assertEqual(ctx.json(post)['data']['fingerprint'], b.fingerprint)
        ctx.routes.insert(0, ('GET', r'/v1/secret/data/', (200, {'data': {'data': {
            'fingerprint': b.fingerprint}}})))
        self.assertTrue(t.deploy(b, {}).startswith('unchanged'))

    def test_kubernetes(self):
        b = FakeBundle()
        ctx = FakeCtx([
            ('GET', r'/secrets/web-tls$', (404, {'kind': 'Status'})),
            ('POST', r'/api/v1/namespaces/prod/secrets$', (201, {})),
            ('PATCH', r'/deployments/web$', (200, {})),
        ])
        t = make('kubernetes', {'host': 'https://k8s:6443', 'token': 'BT', 'namespace': 'prod'},
                 ctx)
        t.deploy(b, {'secret': 'web-tls', 'restart': 'web'})
        s = ctx.json(ctx.find('POST', '.')[0])
        self.assertEqual(s['type'], 'kubernetes.io/tls')
        self.assertEqual(base64.b64decode(s['data']['tls.crt']).decode(), b.fullchain_pem)
        self.assertEqual(ctx.calls[0]['headers']['Authorization'], 'Bearer BT')
        self.assertIn('restartedAt', json.dumps(ctx.json(ctx.find('PATCH', '.')[0])))

    def test_proxmox(self):
        b = FakeBundle()
        ctx = FakeCtx([
            ('GET', r'/nodes/pve1/certificates/info', (200, {'data': [
                {'filename': 'pveproxy-ssl.pem', 'fingerprint': 'AA:BB'}]})),
            ('POST', r'/nodes/pve1/certificates/custom', (200, {'data': {}})),
        ])
        t = make('proxmox', {'host': 'pve1', 'token_id': 'acme@pve!d', 'token_secret': 'S'}, ctx)
        t.deploy(b, {'nodes': 'pve1'})
        post = ctx.find('POST', '.')[0]
        self.assertEqual(post['headers']['Authorization'], 'PVEAPIToken=acme@pve!d=S')
        self.assertEqual(post['url'], 'https://pve1:8006/api2/json/nodes/pve1/certificates/custom')
        f = urllib.parse.parse_qs(post['body'].decode())
        self.assertEqual(f['certificates'][0], b.fullchain_pem)
        self.assertEqual(f['restart'], ['1'])

    def test_opnsense(self):
        b = FakeBundle()
        ctx = FakeCtx([
            ('GET', r'/api/trust/(cert|ca)/search', (200, {'rows': [], 'total': 0})),
            ('POST', r'/api/trust/ca/add', (200, {'result': 'saved'})),
            ('POST', r'/api/trust/cert/add', (200, {'result': 'saved', 'uuid': 'u1'})),
        ])
        t = make('opnsense', {'host': 'fw', 'api_key': 'k', 'api_secret': 's'}, ctx)
        t.deploy(b, {})
        add = ctx.json(ctx.find('POST', 'cert/add')[0])['cert']
        self.assertEqual(add['action'], 'import')
        self.assertEqual(add['prv_payload'], b.key_pem)

    def test_windows_script(self):
        from acmelib.plugins.targets import windows_ssh
        ssh = FakeSsh([(r'EncodedCommand', (0, 'IMPORTED X\nIIS Default Web Site '
                                               'www.example.test:443\nRDP\n', ''))])
        t = make('windows_ssh', {'host': 'win', 'user': 'Administrator', 'auth': 'password',
                                 'password': 'pw'}, FakeCtx(ssh=ssh))
        b = FakeBundle()
        words = t.deploy(b, {'iis': 'Default Web Site | www.example.test | 443', 'rdp': True})
        self.assertIn('RDP', words)
        cmd = ssh.runs[-1][0]
        script = base64.b64decode(cmd.split('-EncodedCommand ')[1]).decode('utf-16-le')
        self.assertIn("Import-PfxCertificate -FilePath 'C:/Windows/Temp/acme-", script)
        self.assertIn("New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 "
                      "-HostHeader 'www.example.test'", script)
        self.assertIn("SslFlags 1", script)
        self.assertIn(C.sha1_thumb(b), script)
        self.assertIn('SSLCertificateSHA1Hash', script)
        self.assertTrue(ssh.puts[0][0].endswith('.pfx'))
        self.assertEqual(ssh.vias, ['scp'])
        self.assertEqual(windows_ssh.ps_str("it's"), "'it''s'")

    def test_every_module_describes(self):
        reg = Registry(extra_dirs=[]).reload()
        kinds = set(reg.all('target'))
        for k in ('ssh', 'local', 'windows_ssh', 'f5', 'netscaler', 'mikrotik', 'fortigate',
                  'paloalto', 'opnsense', 'pfsense', 'proxmox', 'synology', 'kubernetes',
                  'webhook', 'vault'):
            self.assertIn(k, kinds)
        for d in reg.describe()['target']:
            json.dumps(d)
            for f in d['fields'] + d['deploy_fields']:
                self.assertIn(f['type'], ('text', 'secret', 'number', 'bool', 'select',
                                          'textarea', 'pem', 'list', 'hostport', 'sshkey',
                                          'catalog'), d['kind'])
                if f['type'] == 'catalog':          # the list a module fetches: it has one
                    self.assertTrue(f.get('catalog') and callable(
                        getattr(reg.get('target', d['kind']), 'catalog', None)), d['kind'])
            self.assertTrue(d['vendor'] and d['description'], d['kind'])


if __name__ == '__main__':
    unittest.main()
