#!/usr/bin/env python3
"""The FortiGate target's "Replace an existing certificate in place" (1.0.128; over SSH, the
FortiOS CLI, since 1.0.129), against a fake FortiGate - a real HTTP server on 127.0.0.1 (a port
the system gives) that keeps its local and CA certificates as FortiOS does and answers its REST
API, and a fake FortiOS CLI over SSH (test_targets' FakeSsh) working on the same certificates.

    python3 test/test_fortigate_replace.py

- Find on the device: the local certificates listed (name, CN, expiry, issuer, uses), the
  Fortinet factory ones left out, the one with the certificate's names suggested; a token
  refused says why and that the name can be typed.
- The deployment: never the REST PUT of cmdb vpn.certificate/local/<name> (the fake answers
  it as FortiOS 7.4.13 build 2933 did: 500, -651, every PEM line in cli_error); the CLI over
  SSH instead - config vpn certificate local / edit / set password / set private-key / set
  certificate, first ended with abort, then with next / end; in every version of the module;
  config global or config vdom / edit <vdom> when VDOMs are on, by the certificate's range.
- Duplicates: an unused acme copy of the new certificate deleted first (said); a used one, or
  one acme did not make, stops it before anything changes; the very one in place: nothing sent.
- A CLI error ("Command fail", "duplicated", "not a valid"): nothing saved, the old
  certificate untouched, never deleted; an encrypted key refused: the plain key tried.
- Read back: the fingerprint must be the new one, else it fails.
- No SSH sign-in: a clear error before anything changes. No PEM, key or password in the steps.
- What happens (the recorded dry run) says the SSH sign-in, what is replaced, the duplicates.
"""
import json
import os
import re
import sys
import threading
import unittest
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

import test_targets as T  # noqa: E402
from test_targets import FakeBundle, FakeCtx, openssl, read  # noqa: E402
from acmelib.plugins.base import PluginError, Registry  # noqa: E402
from acmelib.plugins.targets import _common as C  # noqa: E402
from acmelib.plugins.targets import fortigate as FG  # noqa: E402

PEMS = {}


def setUpModule():
    T.setUpModule()
    j = lambda n: os.path.join(T.TMP, n)  # noqa: E731
    # the certificates the FortiGate holds before: an RSA one of the same names (to be
    # replaced), one of other names, the factory one
    for leaf, cn, alg in (('old', 'www.example.test', 'rsa:2048'),
                          ('other', 'other.example.test', 'rsa:2048'),
                          ('factory', 'FGT60F0000000000', 'rsa:2048')):
        openssl('req', '-newkey', alg, '-nodes', '-keyout', j(leaf + '.key'),
                '-out', j(leaf + '.csr'), '-subj', '/CN=' + cn)
        with open(j('ext-' + leaf), 'w') as fh:
            fh.write('subjectAltName=DNS:%s\n' % cn)
        openssl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j('ca.crt'), '-CAkey',
                j('ca.key'), '-CAcreateserial', '-days', '20', '-out', j(leaf + '.crt'),
                '-extfile', j('ext-' + leaf))
        PEMS[leaf] = read(j(leaf + '.crt'))


def tearDownModule():
    T.tearDownModule()


class Bundle(FakeBundle):
    """The test certificate, its key also as encrypted PKCS#8 (as the real Bundle)."""
    key_type = 'ec-256'

    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'key-pem-enc':
            return openssl('pkcs8', '-topk8', '-v2', 'aes-256-cbc', '-passout',
                           'pass:%s' % password, data=self.key_pem.encode())
        return FakeBundle.as_format(self, fmt, password, alias)


def der(pem):
    return C.pem_to_der(pem)


def text_of(v):
    return v if isinstance(v, str) else ('' if v is None else str(v))


# ---------------------------------------------------------------------------
class FakeFortiGate(object):
    """A FortiGate's REST API as acme uses it, its certificates kept."""

    def __init__(self, version='v7.4.5'):
        self.version = version
        self.local = {}
        self.cas = []
        self.calls = []
        self.refuse_list = None         # the listing refused with this status
        self.refuse_delete = set()      # names whose DELETE is refused
        self.vdom_mode = None           # cmdb system global vdom-mode (None: 404)
        self.puts = {}                  # other PUTs: path -> [bodies]
        self.lock = threading.Lock()
        fg = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self):
                n = int(self.headers.get('Content-Length') or 0)
                raw = self.rfile.read(n) if n else b''
                body = json.loads(raw.decode()) if raw[:1] == b'{' else None
                u = urllib.parse.urlsplit(self.path)
                q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                with fg.lock:
                    fg.calls.append({'method': self.command, 'path': u.path, 'query': q,
                                     'body': body,
                                     'auth': self.headers.get('Authorization')})
                    st, out = fg.answer(self.command, urllib.parse.unquote(u.path), q, body)
                data = json.dumps(out).encode()
                self.send_response(st)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            do_GET = do_PUT = do_POST = do_DELETE = _go

        # port 0: one the system gives (never 8092 / 8443)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def add(self, name, pem, source='user', q_ref=0, rng='global'):
        self.local[name] = {'name': name, 'source': source, 'range': rng, 'certificate': pem,
                            'private-key': 'ENC xxxx', 'password': 'ENC xxxx', 'q_ref': q_ref}

    @staticmethod
    def put_answer(name, body):
        pem = text_of((body or {}).get('certificate'))
        return {'http_method': 'PUT', 'revision_changed': False, 'cli_error': [
            'This local certificate is duplicated.', 'current vf=root:0',
            'Input is not a valid/matched certificate.',
            'node_check_object fail! for certificate ' + (pem.splitlines() or [''])[0]] +
            pem.splitlines()[1:] + [
            "value parse error before '-----BEGIN CERTIFICATE-----'", 'MIIDtjCCA',
            'Command fail. Return code -651', 'Command fail. Return code 1'],
            'error': -651, 'status': 'error', 'http_status': 500, 'vdom': 'root',
            'path': 'vpn.certificate', 'name': 'local', 'action': '', 'mkey': name,
            'serial': 'FGT40FTK22089073', 'version': 'v7.4.13', 'build': 2933}

    @staticmethod
    def err(status, code):
        return status, {'http_method': '?', 'status': 'error', 'http_status': status,
                        'error': code}

    def answer(self, m, path, q, body):
        ok = {'http_method': m, 'status': 'success', 'http_status': 200}
        if path == '/api/v2/monitor/system/status':
            return 200, dict(ok, version=self.version, serial='FGT60F', vdom='root',
                             results={'hostname': 'fw1', 'model_name': 'FortiGate'})
        lp = '/api/v2/cmdb/vpn.certificate/local'
        if path == lp and m == 'GET':
            if self.refuse_list:
                return self.err(self.refuse_list, -37)
            rows = sorted(self.local.values(), key=lambda r: r['name'])
            if q.get('format') == 'name':
                return 200, dict(ok, results=[{'name': r['name']} for r in rows])
            meta = q.get('with_meta') == '1'
            return 200, dict(ok, results=[{k: v for k, v in r.items()
                                           if meta or k != 'q_ref'} for r in rows])
        if path.startswith(lp + '/'):
            name = path[len(lp) + 1:]
            row = self.local.get(name)
            if m == 'GET':
                if not row:
                    return self.err(404, -3)
                return 200, dict(ok, results=[{k: v for k, v in row.items()
                                               if q.get('with_meta') == '1' or k != 'q_ref'}])
            if m == 'PUT':
                # FortiOS 7.4.13 build 2933: the PUT turned into CLI lines, the PEM over
                # several lines broke them - the answer exactly as the device gave it
                return 500, self.put_answer(name, body)
            if m == 'DELETE':
                if not row:
                    return self.err(404, -3)
                if row.get('q_ref') or name in self.refuse_delete:
                    return self.err(500, -23)
                del self.local[name]
                return 200, ok
        if path == '/api/v2/monitor/vpn-certificate/local/import' and m == 'POST':
            name = body['certname']
            if name in self.local:
                return self.err(500, -5)
            self.add(name, '(imported)', rng=body.get('scope', 'global'))
            return 200, dict(ok, results={'mkey': name})
        if path == '/api/v2/monitor/vpn-certificate/ca/import' and m == 'POST':
            import base64
            pem = base64.b64decode(body['file_content']).decode()
            if der(pem) in [der(c) for c in self.cas]:
                return self.err(500, -328)
            self.cas.append(pem)
            return 200, dict(ok, results={'mkey': 'CA_Cert_%d' % len(self.cas)})
        if path == '/api/v2/cmdb/vpn.certificate/ca' and m == 'GET':
            return 200, dict(ok, results=[{'name': 'CA_Cert_%d' % (i + 1), 'ca': c}
                                          for i, c in enumerate(self.cas)])
        if path == '/api/v2/cmdb/system/global' and m == 'GET' and self.vdom_mode:
            return 200, dict(ok, results={'vdom-mode': self.vdom_mode})
        if m == 'PUT':
            self.puts.setdefault(path, []).append(body)
            return 200, ok
        if m == 'GET' and path.startswith('/api/v2/cmdb/firewall/'):
            return 200, dict(ok, results=[{'name': path.rsplit('/', 1)[-1]}])
        return self.err(404, -3)

    def find(self, method, rx):
        return [c for c in self.calls if c['method'] == method and re.search(rx, c['path'])]


# ---------------------------------------------------------------------------
STATUS = ('Version: FortiGate-40F v7.4.13,build2933,250617 (GA.M)\n'
          'Serial-Number: FGT40FTK22089073\nHostname: fw1\nOperation Mode: NAT\n'
          'Current virtual domain: root\nVirtual domain configuration: %s\n'
          'Current HA mode: standalone\n')


def cli_commands(script):
    """The lines of a CLI script, a quoted value over several lines kept as one command."""
    out, cur, open_ = [], '', False
    for ln in script.split('\n'):
        cur = (cur + '\n' + ln) if open_ else ln
        q = len(re.findall(r'(?<!\\)"', ln))
        if q % 2:
            open_ = not open_
        if not open_:
            if cur.strip():
                out.append(cur.strip())
            cur = ''
    return out


def unq(v):
    v = v.strip()
    if v.startswith('"') and v.endswith('"'):
        v = v[1:-1].replace('\\"', '"').replace('\\\\', '\\')
    return v


class FakeCli(object):
    """The FortiOS CLI over SSH as acme uses it, on the fake FortiGate's certificates: echoes
    each command as FortiOS does (the PEM too - the module must not say it back), refuses as
    FortiOS refuses, saves an edit at next only."""

    def __init__(self, fg, vdoms=False):
        self.fg = fg
        self.vdoms = vdoms
        self.fail_cert = False          # set certificate refused (not valid / -651)
        self.refuse_encrypted = False   # an encrypted private-key refused
        self.ignore = False             # next says nothing, saves nothing
        self.scripts = []
        self.commits = []
        self.ssh = T.FakeSsh([(r'^\n', self.shell)])

    def shell(self, cmd, inp):
        self.scripts.append(inp)
        out, level, scope, edit = [], [], '', None
        for c in cli_commands(inp):
            out.append('fw1 %s# %s' % ('(%s) ' % level[-1] if level else '', c))
            if c == 'get system status':
                out.append(STATUS % ('multiple' if self.vdoms else 'disable'))
            elif c in ('config global', 'config vdom') and not level:
                if not self.vdoms:
                    out += ["command parse error before '%s'" % c.split()[1],
                            'Command fail. Return code -61']
                    continue
                level.append(c.split()[1])
                scope = 'global' if c == 'config global' else 'vdom?'
            elif c.startswith('edit ') and level and level[-1] == 'vdom':
                scope = 'vdom'
                level.append('vdom:' + unq(c[5:]))
            elif c == 'config vpn certificate local':
                if self.vdoms and not scope:
                    out += ["command parse error before 'vpn'", 'Command fail. Return code -61']
                    continue
                level.append('local')
            elif c.startswith('show vpn certificate local '):
                row = self.fg.local.get(unq(c[len('show vpn certificate local '):]))
                if row:
                    out.append('config vpn certificate local\n    edit "%s"\n        set '
                               'certificate "%s"\n    next\nend' % (row['name'],
                                                                     row['certificate']))
            elif c.startswith('edit ') and level and level[-1] == 'local':
                name = unq(c[5:])
                row = self.fg.local.get(name)
                want = 'global' if scope == 'global' else 'vdom' if scope == 'vdom' else None
                if not row or (want and row['range'] != want):
                    out.append("new entry '%s' added" % name)
                edit = {'name': name, 'new': not row or bool(want and row['range'] != want),
                        'bad': False}
            elif c.startswith('set password ') and edit:
                edit['password'] = unq(c[13:])
            elif c.startswith('set private-key ') and edit:
                key = unq(c[16:])
                if 'ENCRYPTED' in key and (self.refuse_encrypted or not edit.get('password')):
                    out += ['Input is not a valid/matched private key.',
                            'node_check_object fail! for private-key ' + key,
                            'Command fail. Return code -651']
                    edit['bad'] = True
                else:
                    edit['key'] = key
            elif c.startswith('set certificate ') and edit:
                pem = unq(c[16:])
                dup = [n for n, r in self.fg.local.items() if n != edit['name'] and
                       r['certificate'].startswith('-----') and der(r['certificate']) == der(pem)]
                if dup or self.fail_cert:
                    out += (['This local certificate is duplicated.'] if dup else []) + [
                        'current vf=root:0', 'Input is not a valid/matched certificate.',
                        'node_check_object fail! for certificate ' + pem,
                        "value parse error before '-----BEGIN CERTIFICATE-----'",
                        'Command fail. Return code -651']
                    edit['bad'] = True
                else:
                    edit['cert'] = pem
            elif c == 'abort':
                edit = None
                if level:
                    level.pop()
            elif c == 'next' and edit:
                # FortiOS saves at next what the edit took - what was refused is left out
                if not self.ignore and edit.get('cert') and edit.get('key'):
                    if edit['new']:
                        self.fg.add(edit['name'], edit['cert'], rng=scope or 'global')
                    self.fg.local[edit['name']].update(
                        certificate=edit['cert'], **{'private-key': 'ENC new'})
                    self.commits.append(edit['name'])
                edit = None
            elif c == 'end':
                if level:
                    level.pop()
            else:
                out += ['Unknown action 0', 'Command fail. Return code -1']
        return 0, '\n'.join(out) + '\n', ''

    def runs(self):
        return [inp for cmd, inp in self.ssh.runs if cmd == '']


class HttpCtx(FakeCtx):
    """test_targets' Context, its HTTP sent for real (to the fake FortiGate)."""
    def debug(self, words):
        self.__dict__.setdefault('debugs', []).append(words)

    def http(self, method, url, body=None, headers=None, timeout=30, verify=True, ca_pem=None,
             client_cert=None, proxy=True):
        self.calls.append({'method': method, 'url': url, 'body': body})
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers or {}))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()


SSH = {'ssh_user': 'acme-admin', 'ssh_auth': 'password', 'ssh_password': 'SSH-pw-0002'}


def make(fg, version='', cli=None, ssh=True, **cfg):
    reg = Registry(extra_dirs=[]).reload()
    assert not reg.broken, reg.broken
    cls = reg.get('target', 'fortigate', version)
    assert cls.module_version == version
    cli = cli or FakeCli(fg)
    ctx = HttpCtx([], ssh=cli.ssh)
    ctx.cli = cli
    conf = dict({'host': 'http://127.0.0.1:%d' % fg.port, 'token': 'TKN-secret-0001',
                 'vdom': 'root'}, **(SSH if ssh else {}))
    conf.update(cfg)
    return cls(conf, ctx), ctx


def said(ctx):
    return [w for _l, w in ctx.steps]


REPLACE = {'mode': 'replace', 'replace_name': 'web-cert'}


class Base(unittest.TestCase):
    version = 'v7.4.5'

    def setUp(self):
        self.fg = FakeFortiGate(self.version)
        self.fg.add('Fortinet_Factory', PEMS['factory'], source='factory', q_ref=4)
        self.fg.add('Fortinet_SSL', PEMS['factory'], source='factory', q_ref=2)
        self.fg.add('web-cert', PEMS['old'], q_ref=7)
        self.fg.add('other', PEMS['other'], q_ref=0, rng='vdom')

    def tearDown(self):
        self.fg.close()


# ---------------------------------------------------------------------------
class DiscoveryTest(Base):
    def test_listing(self):
        t, ctx = make(self.fg)
        t.hint_names = ['www.example.test', 'example.test']
        got = t.catalog('local_certs')
        names = [o[0] for o in got['options']]
        self.assertEqual(names, ['web-cert', 'other'], 'the suggested one first, factory out')
        self.assertEqual(got['pick'], 'web-cert')
        words = dict(got['options'])
        self.assertIn('CN www.example.test', words['web-cert'])
        self.assertIn('Test CA', words['web-cert'])                 # the issuer
        self.assertIn('7×', words['web-cert'])                      # its uses
        self.assertTrue(words['web-cert'].startswith('★ '))
        self.assertRegex(words['web-cert'], r'→ \d{4}-\d\d-\d\d')   # its expiry
        self.assertIn('vdom', words['other'])
        self.assertIn('2 Fortinet factory ones left out', got['said'])
        call = self.fg.find('GET', r'/cmdb/vpn\.certificate/local$')[0]
        self.assertEqual((call['query'].get('with_meta'), call['query'].get('vdom')),
                         ('1', 'root'))
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'], 'read-only')

    def test_no_names_no_pick(self):
        t, ctx = make(self.fg)
        got = t.catalog('local_certs')
        self.assertEqual(got['pick'], '')
        self.assertEqual(sorted(o[0] for o in got['options']), ['other', 'web-cert'])

    def test_refused_says_why_and_to_type_it(self):
        self.fg.refuse_list = 403
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.catalog('local_certs')
        self.assertIn('the token may not read the certificates (403)', str(e.exception))
        self.assertIn('type the name of the certificate instead', str(e.exception))

    def test_unreachable_says_it(self):
        t, ctx = make(self.fg)
        self.fg.close()
        self.fg = FakeFortiGate()           # for tearDown
        with self.assertRaises(PluginError) as e:
            t.catalog('local_certs')
        self.assertIn('type the name of the certificate instead', str(e.exception))

    def test_the_field(self):
        f = {x['key']: x for x in FG.FortiGateTarget.deploy_fields}
        self.assertEqual(f['mode']['default'], 'new')
        self.assertEqual(f['replace_name']['type'], 'catalog')
        self.assertEqual(f['replace_name']['catalog'], 'local_certs')
        self.assertEqual(f['replace_name']['show_if'], {'mode': ['replace']})
        self.assertEqual(f['replace_name']['load_label'], 'Find on the device')
        self.assertFalse(f['replace_name'].get('autoload', True))


# ---------------------------------------------------------------------------
class ReplaceTest(Base):
    def deploy(self, version='', fos=None, cli=None, **opts):
        if fos:
            self.fg.version = fos
        t, ctx = make(self.fg, version, cli=cli)
        b = Bundle()
        got = t.deploy(b, dict(REPLACE, **opts))
        return t, ctx, b, got

    def no_secrets(self, ctx, b, extra=()):
        """Nothing of a PEM, a key or a password in what the job keeps."""
        kept = [w for _l, w in ctx.steps] + list(getattr(ctx, 'debugs', []))
        for w in kept:
            for bad in ('BEGIN', 'PRIVATE KEY', 'MII', 'TKN-secret', 'SSH-pw') + tuple(extra):
                self.assertNotIn(bad, w)
            for ln in b.cert_pem.splitlines()[1:-1]:
                self.assertNotIn(ln[:20], w)

    def check_replaced(self, b, ctx, scope=''):
        row = self.fg.local['web-cert']
        self.assertEqual(der(row['certificate']), der(b.cert_pem))
        self.assertEqual(row['private-key'], 'ENC new')
        self.assertEqual(row['q_ref'], 7, 'its uses kept')
        self.assertFalse(self.fg.find('PUT', r'/vpn\.certificate/local'), 'never the REST PUT')
        self.assertFalse(self.fg.find('POST', r'/local/import'), 'nothing imported anew')
        self.assertFalse([n for n in self.fg.local if n.startswith('acme-')])
        runs = ctx.cli.runs()
        self.assertEqual(runs[0], 'get system status\n')
        edits = [r for r in runs if 'config vpn certificate local' in r]
        self.assertEqual(len(edits), 2, 'first ended with abort, then saved')
        first, saved = edits
        head = {'': 'config vpn certificate local\nedit "web-cert"\n',
                'global': 'config global\nconfig vpn certificate local\nedit "web-cert"\n'}[scope]
        for r in edits:
            self.assertTrue(r.startswith(head), r[:80])
            self.assertRegex(r, r'\nset password "[^"\n]+"\nset private-key "-----BEGIN '
                                r'ENCRYPTED PRIVATE KEY-----\n')
            self.assertIn('\nset certificate "-----BEGIN CERTIFICATE-----\n', r)
            self.assertEqual(r.count('BEGIN CERTIFICATE'), 1, 'the leaf only')
        self.assertTrue(first.endswith('-----END CERTIFICATE-----"\nabort\n' +
                                       ('end\n' if scope else '')), first[-60:])
        self.assertTrue(saved.endswith('-----END CERTIFICATE-----"\nnext\nend\n' +
                                       ('end\n' if scope else '')), saved[-60:])
        self.assertEqual(ctx.cli.commits, ['web-cert'])
        self.assertEqual(ctx._ssh.conns[0]['host'], '127.0.0.1')
        self.assertEqual(ctx._ssh.conns[0]['user'], 'acme-admin')
        self.assertEqual(ctx._ssh.conns[0]['password'], 'SSH-pw-0002')
        self.no_secrets(ctx, b)

    def test_every_version(self):
        for ver, fos in (('', 'v7.4.5'), ('6.0', 'v6.4.15'), ('7.0', 'v7.2.10'),
                         ('7.4.2', 'v7.6.4'), ('7.4.2', 'v8.0.0')):
            self.tearDown()
            self.setUp()
            t, ctx, b, got = self.deploy(ver, fos)
            self.check_replaced(b, ctx)
            self.assertIn('web-cert replaced in place', got)
            self.assertFalse(self.fg.puts, 'nothing re-pointed: %s' % self.fg.puts)
            words = said(ctx)
            self.assertTrue(any('replacing the certificate web-cert in place: the same name, '
                                'everything that uses it keeps using it' in w for w in words))
            self.assertTrue(any('used 7 times' in w for w in words), words)
            self.assertTrue(any('key type changes from RSA to EC' in w for w in words), words)
            self.assertIn('signed in over SSH as acme-admin: FortiOS 7.4.13 on fw1, VDOMs off - '
                          'the certificate is replaced in the FortiOS CLI (its REST API '
                          'cannot)', words)
            self.assertIn('no other local certificate on the FortiGate is this one (FortiOS '
                          'refuses a duplicate)', words)
            self.assertTrue([w for w in words if w.startswith(
                'checked: web-cert holds the new certificate now (SHA-256 ')], words)
            self.assertTrue(all(c['auth'] == 'Bearer TKN-secret-0001' for c in self.fg.calls))

    def test_the_rest_put_is_what_7_4_13_refused(self):
        """The fake answers the cmdb PUT as the device did: acme no longer sends it, and the
        answer, were it to come, is kept as its error lines - no line of the PEM."""
        t, ctx = make(self.fg)
        b = Bundle()
        with self.assertRaises(C.PluginError) as e:
            t.api('PUT', '/api/v2/cmdb/vpn.certificate/local/web-cert',
                  {'certificate': b.cert_pem}, vdom='root', what='x')
        detail = e.exception.detail
        self.assertIn('This local certificate is duplicated.', detail)
        self.assertIn('Command fail. Return code -651', detail)
        self.assertIn('node_check_object fail! for certificate …', detail)
        self.assertNotIn('BEGIN', detail + str(e.exception))
        for ln in b.cert_pem.splitlines()[1:-1]:
            self.assertNotIn(ln, detail)
        self.assertNotIn('MIIDtjCCA', detail)
        self.assertIn('-651', str(e.exception))
        # and the deployment never asks it
        self.fg.calls[:] = []
        t, ctx, b, got = self.deploy()
        self.check_replaced(b, ctx)

    def test_version_refused_before_anything(self):
        self.fg.version = 'v6.4.15'
        t, ctx = make(self.fg, '7.4.2')
        with self.assertRaises(PluginError):
            t.deploy(Bundle(), dict(REPLACE))
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertFalse(ctx.cli.runs())
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))

    def test_listed_uses_point_at_the_same_name(self):
        t, ctx, b, got = self.deploy('7.4.2', admin=True, sslvpn=True, vips='web')
        self.check_replaced(b, ctx)
        self.assertEqual(self.fg.puts['/api/v2/cmdb/system/global'],
                         [{'admin-server-cert': 'web-cert'}])
        self.assertEqual(self.fg.puts['/api/v2/cmdb/vpn.ssl/settings'],
                         [{'servercert': 'web-cert'}])
        self.assertEqual(self.fg.puts['/api/v2/cmdb/firewall/vip/web'],
                         [{'ssl-certificate': [{'name': 'web-cert'}]}])

    def test_again_unchanged(self):
        t, ctx, b, got = self.deploy()
        n = len(ctx.cli.runs())
        t2, ctx2 = make(self.fg, cli=ctx.cli)
        ctx2.kv = ctx.kv
        got = t2.deploy(b, dict(REPLACE))
        self.assertTrue(got.startswith('unchanged'), got)
        self.assertEqual(len(ctx.cli.runs()), n)

    def test_already_in_place(self):
        """The very certificate at the name already (put there by hand, or forced): nothing
        sent - FortiOS would call it a duplicate of itself."""
        b = Bundle()
        self.fg.local['web-cert']['certificate'] = b.cert_pem
        t, ctx = make(self.fg)
        got = t.deploy(b, dict(REPLACE, force=True))
        self.assertEqual(got, 'already in place in web-cert')
        self.assertIn('web-cert holds this certificate already - it is in place', said(ctx))
        self.assertFalse(ctx.cli.runs())
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])

    def test_encrypted_key_refused_plain_tried(self):
        cli = FakeCli(self.fg)
        cli.refuse_encrypted = True
        t, ctx, b, got = self.deploy(cli=cli)
        edits = [r for r in cli.runs() if 'config vpn certificate local' in r]
        self.assertEqual(len(edits), 3)
        self.assertIn('ENCRYPTED PRIVATE KEY', edits[0])
        self.assertTrue(edits[0].endswith('abort\n'))
        for r in edits[1:]:
            self.assertNotIn('set password', r)
            self.assertIn('set private-key "-----BEGIN PRIVATE KEY-----\n', r)
        self.assertTrue(edits[1].endswith('abort\n') and edits[2].endswith('next\nend\n'))
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))
        warn = [w for lv, w in ctx.steps if lv == 'warn']
        self.assertTrue([w for w in warn if w.startswith(
            'FortiOS did not take the encrypted key (Input is not a valid/matched private '
            'key.')], warn)
        self.no_secrets(ctx, b)

    def test_cli_error_aborts_nothing_saved(self):
        cli = FakeCli(self.fg)
        cli.fail_cert = True
        t, ctx = make(self.fg, cli=cli)
        b = Bundle()
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(REPLACE, keep=0))
        words = str(e.exception)
        self.assertIn('FortiOS refused to replace web-cert in place: ', words)
        self.assertIn('Input is not a valid/matched certificate.', words)
        self.assertIn('Command fail. Return code -651', words)
        self.assertIn('web-cert is untouched (the old certificate, nothing deleted)', words)
        self.assertIn('nothing was saved: acme ended its lines with abort', words)
        self.assertFalse(e.exception.retry)
        for blob in (words, e.exception.detail or ''):
            self.assertNotIn('BEGIN', blob)
            self.assertNotIn('MII', blob)
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))
        self.assertFalse([r for r in cli.runs() if r.endswith('next\nend\n')], 'never saved')
        self.assertTrue(all(r.endswith('abort\n') for r in cli.runs()
                            if 'config vpn certificate local' in r))
        self.assertEqual(cli.commits, [])
        self.assertFalse(self.fg.find('DELETE', r'.'), 'nothing deleted')
        self.assertFalse(self.fg.find('POST', r'.'), 'nothing imported')
        self.no_secrets(ctx, b)

    def test_fingerprint_checked(self):
        """FortiOS takes the lines, yet the certificate is not the new one: it fails."""
        cli = FakeCli(self.fg)
        cli.ignore = True
        t, ctx = make(self.fg, cli=cli)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), dict(REPLACE))
        self.assertIn('FortiOS took the lines, yet web-cert still holds another certificate',
                      str(e.exception))
        self.assertFalse(self.fg.find('POST', r'/ca/import'), 'nothing after it')
        self.assertFalse([w for w in said(ctx) if 'replaced in place' in w])

    def test_fingerprint_read_by_cli_show(self):
        """REST does not say the certificate back: the CLI's show does."""
        orig = self.fg.answer

        def answer(m, path, q, body):
            st, out = orig(m, path, q, body)
            if m == 'GET' and path.endswith('/local/web-cert') and len(
                    self.fg.find('GET', r'/local/web-cert$')) > 1:
                for r in out.get('results') or []:
                    r.pop('certificate', None)
            return st, out
        self.fg.answer = answer
        t, ctx, b, got = self.deploy()
        self.assertTrue([r for r in ctx.cli.runs() if r == 'show vpn certificate local '
                         '"web-cert"\n'])
        self.assertTrue([w for w in said(ctx) if w.startswith('checked: web-cert holds')])

    def test_global_scope_with_vdoms(self):
        cli = FakeCli(self.fg, vdoms=True)
        t, ctx, b, got = self.deploy(cli=cli)
        self.check_replaced(b, ctx, 'global')
        self.assertIn('signed in over SSH as acme-admin: FortiOS 7.4.13 on fw1, VDOMs on '
                      '(multiple) - the certificate is replaced in the FortiOS CLI (its REST '
                      'API cannot)', said(ctx))

    def test_vdom_scope_with_vdoms(self):
        cli = FakeCli(self.fg, vdoms=True)
        t, ctx = make(self.fg, cli=cli)
        b = Bundle()
        t.deploy(b, {'mode': 'replace', 'replace_name': 'other'})
        self.assertEqual(der(self.fg.local['other']['certificate']), der(b.cert_pem))
        edits = [r for r in cli.runs() if 'config vpn certificate local' in r]
        self.assertEqual(len(edits), 2)
        for r in edits:
            self.assertTrue(r.startswith('config vdom\nedit "root"\nconfig vpn certificate '
                                         'local\nedit "other"\n'), r[:80])
        self.assertEqual(cli.commits, ['other'])

    def test_vdom_mode_from_rest_when_cli_does_not_say(self):
        cli = FakeCli(self.fg, vdoms=True)
        orig = cli.shell
        cli.ssh.answers = [(r'^\n', lambda c, i: (lambda r: (r[0], r[1].replace(
            'Virtual domain configuration: multiple\n', ''), r[2]))(orig(c, i)))]
        self.fg.vdom_mode = 'multi-vdom'
        t, ctx, b, got = self.deploy(cli=cli)
        self.check_replaced(b, ctx, 'global')

    def test_no_ssh_sign_in(self):
        for cfg in ({'ssh_user': ''}, {'ssh_password': ''}, {'ssh_auth': 'key'}):
            t, ctx = make(self.fg, **cfg)
            with self.assertRaises(PluginError) as e:
                t.deploy(Bundle(), dict(REPLACE))
            words = str(e.exception)
            self.assertIn('replace in place goes over SSH and the target has no SSH sign-in',
                          words)
            self.assertIn('Fill in the target\'s SSH user and its key or password', words)
            self.assertIn('nothing was changed', words)
            self.assertFalse(e.exception.retry)
            self.assertFalse(ctx.cli.runs())
            self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        # the new mode needs none
        t, ctx = make(self.fg, ssh=False)
        t.deploy(Bundle(), {'keep': 1})
        self.assertFalse(ctx.cli.runs())

    def test_the_fields(self):
        f = {x['key']: x for x in FG.FortiGateTarget.fields}
        for k in ('ssh_port', 'ssh_user', 'ssh_auth', 'ssh_key', 'ssh_password',
                  'ssh_hostkey', 'ssh_trust_first'):
            self.assertIn(k, f)
            self.assertFalse(f[k].get('required'), k)
        self.assertEqual(f['ssh_port']['default'], 22)
        self.assertEqual(f['ssh_user']['label'], 'SSH user (replace in place)')
        self.assertIn('only for "Replace an existing certificate in place"',
                      f['ssh_user']['help'])
        self.assertEqual(f['ssh_key']['type'], 'sshkey')
        self.assertEqual(f['ssh_key']['ssh_prefix'], 'ssh_')
        self.assertEqual(f['ssh_key']['try_command'], 'get system status')
        self.assertTrue(f['ssh_trust_first']['default'])

    def test_try_says_the_ssh_sign_in(self):
        t, ctx = make(self.fg)
        said_ = t.test()
        self.assertIn('; over SSH as acme-admin: FortiOS 7.4.13 on fw1, VDOMs off', said_)
        self.assertEqual(ctx.cli.runs(), ['get system status\n'])
        t, ctx = make(self.fg, ssh=False)
        self.assertNotIn('SSH', t.test())
        self.assertFalse(ctx.cli.runs())

    def test_missing_name_fails_early(self):
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), dict(REPLACE, replace_name='web-certt'))
        self.assertIn('there is no local certificate web-certt on the FortiGate (VDOM root)',
                      str(e.exception))
        self.assertIn('nothing was changed', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertFalse(ctx.cli.runs())

    def test_empty_and_factory_refused(self):
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), {'mode': 'replace', 'replace_name': ' '})
        self.assertIn('no certificate on the FortiGate is chosen', str(e.exception))
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), {'mode': 'replace', 'replace_name': 'Fortinet_SSL'})
        self.assertIn('Fortinet factory certificate', str(e.exception))
        self.fg.add('mine', PEMS['other'], source='factory')
        with self.assertRaises(PluginError):
            t.deploy(Bundle(), {'mode': 'replace', 'replace_name': 'mine'})
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertFalse(ctx.cli.runs())

    def test_hand_typed_name(self):
        """A name typed (discovery never asked) with characters a URL quotes."""
        self.fg.add('VPN cert/2026 #1', PEMS['other'], q_ref=1)
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, {'mode': 'replace', 'replace_name': 'VPN cert/2026 #1'})
        self.assertEqual(der(self.fg.local['VPN cert/2026 #1']['certificate']), der(b.cert_pem))
        self.assertTrue([r for r in ctx.cli.runs() if '\nedit "VPN cert/2026 #1"\n' in r])
        self.assertTrue(any('used once' in w for w in said(ctx)))

    def test_cleanup_spares_the_replaced(self):
        b = Bundle()
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        # older acme ones of this certificate (from before the mode), and the replaced one
        # itself named as acme names them
        olds = [prefix + '2026%04d-%06x' % (d, d) for d in (101, 201, 301)]
        for n in olds:
            self.fg.add(n, PEMS['other'])
        replaced = prefix + '20260401-0abcde'
        self.fg.add(replaced, PEMS['old'], q_ref=3)
        t, ctx = make(self.fg)
        t.deploy(b, {'mode': 'replace', 'replace_name': replaced, 'keep': 0})
        self.assertIn(replaced, self.fg.local)
        self.assertEqual(der(self.fg.local[replaced]['certificate']), der(b.cert_pem))
        self.assertEqual([n for n in olds if n in self.fg.local], [])
        self.assertNotIn(replaced, [c['path'].rsplit('/', 1)[-1] for c in
                                    self.fg.find('DELETE', r'.')])

    def test_new_mode_unchanged(self):
        """Off by default: imported under a new name as before, no SSH even when it is
        filled in; a saved deployment's key the same with the mode set to "new" as without."""
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, {'keep': 1})
        self.assertEqual(len(self.fg.find('POST', r'/local/import')), 1)
        self.assertFalse(self.fg.find('PUT', r'/vpn\.certificate/local/'))
        self.assertFalse(ctx.cli.runs())
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))
        self.assertEqual(t.state_key({'keep': 1}),
                         t.state_key({'keep': 1, 'mode': 'new', 'replace_name': ''}))
        self.assertNotEqual(t.state_key({'keep': 1}), t.state_key(dict(REPLACE, keep=1)))


# ---------------------------------------------------------------------------
class DuplicateTest(Base):
    """FortiOS refuses a local certificate identical to another ("This local certificate is
    duplicated") - the very failure on 7.4.13: the same certificate imported an hour before
    by a deployment in the new mode."""
    def copy(self, b, name=None, q_ref=0):
        name = name or 'acme-www.example.test-20261118-191aae'
        self.fg.add(name, b.cert_pem, q_ref=q_ref)
        return name

    def test_unused_acme_copy_deleted_first(self):
        b = Bundle()
        n = self.copy(b)
        t, ctx = make(self.fg)
        got = t.deploy(b, dict(REPLACE))
        self.assertIn('web-cert replaced in place', got)
        self.assertNotIn(n, self.fg.local)
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))
        dels = self.fg.find('DELETE', r'/vpn\.certificate/local/')
        self.assertEqual([c['path'].rsplit('/', 1)[-1] for c in dels], [n])
        words = said(ctx)
        self.assertIn('%s is this very certificate already - an unused copy acme imported '
                      'earlier; it is deleted first (FortiOS refuses two identical local '
                      'certificates)' % n, words)
        self.assertIn('deleted %s, the unused copy of this certificate' % n, words)
        # the copy was deleted only after SSH signed in, and before the CLI lines
        order = [w for w in words if w.startswith(('signed in over SSH', 'deleted '))]
        self.assertTrue(order[0].startswith('signed in over SSH'), order)
        self.assertFalse([w for w in words if 'cannot be listed' in w])

    def test_without_the_deletion_fortios_says_duplicated(self):
        """The fake CLI refuses a duplicate as FortiOS does - were the copy not deleted (it
        cannot be: refused), the lines end with abort and nothing is saved."""
        b = Bundle()
        n = self.copy(b)
        self.fg.refuse_delete.add(n)
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(REPLACE))
        self.assertIn('%s, an unused copy of this very certificate, cannot be deleted' % n,
                      str(e.exception))
        self.assertIn('nothing else was changed', str(e.exception))
        self.assertFalse([r for r in ctx.cli.runs() if 'config vpn certificate local' in r])
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))
        # the CLI itself, given the duplicate
        cli = FakeCli(self.fg)
        out = cli.shell('', 'config vpn certificate local\nedit "web-cert"\nset certificate '
                            '"%s"\nabort\n' % b.cert_pem.strip())[1]
        self.assertIn('This local certificate is duplicated.', out)
        self.assertIn('This local certificate is duplicated.',
                      FG.cli_errors(out))

    def test_used_copy_fails_before_anything(self):
        b = Bundle()
        n = self.copy(b, q_ref=2)
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(REPLACE))
        words = str(e.exception)
        self.assertIn('the FortiGate has this very certificate already as %s, an earlier '
                      'import of acme that is used (2×)' % n, words)
        self.assertIn('Nothing was changed: point what uses %s at web-cert' % n, words)
        self.assertFalse(e.exception.retry)
        self.assertIn(n, self.fg.local)
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertFalse(ctx.cli.runs(), 'not even signed in over SSH')

    def test_copy_not_acmes_fails_before_anything(self):
        b = Bundle()
        n = self.copy(b, name='my-own-copy')
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(REPLACE))
        words = str(e.exception)
        self.assertIn('the FortiGate has this very certificate already as my-own-copy, which '
                      'acme did not make', words)
        self.assertIn('"This local certificate is duplicated"', words)
        self.assertIn('delete my-own-copy on the FortiGate', words)
        self.assertIn(n, self.fg.local)
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertFalse(ctx.cli.runs())


# ---------------------------------------------------------------------------
class CaQuietTest(Base):
    def test_minus_328_said_once_quietly(self):
        b = Bundle()
        self.fg.cas.append(b.chain_pems[0])     # there already
        t, ctx = make(self.fg)
        t.deploy(b, {'keep': 1})
        words = said(ctx)
        self.assertEqual(len(self.fg.find('POST', r'/ca/import')), 1)
        self.assertFalse([w for w in words if 'not imported' in w or '-328' in w], words)
        quiet = [(lv, w) for lv, w in ctx.steps if 'on the FortiGate already' in w]
        self.assertEqual(quiet, [('info', 'the intermediate CA certificate is on the '
                                           'FortiGate already')])

    def test_minus_328_for_one_not_there_is_said(self):
        b = Bundle()
        t, ctx = make(self.fg)
        orig = self.fg.answer

        def answer(m, path, q, body):
            if path.endswith('/ca/import'):
                return self.fg.err(500, -328)     # yet the CA list does not have it
            return orig(m, path, q, body)
        self.fg.answer = answer
        t.deploy(b, {'keep': 1})
        self.assertTrue([w for w in said(ctx) if 'the CA certificate is not imported' in w])

    def test_replace_imports_the_chain_quietly(self):
        b = Bundle()
        t, ctx = make(self.fg)
        t.deploy(b, dict(REPLACE))
        self.assertEqual([der(c) for c in self.fg.cas], [der(b.chain_pems[0])])
        self.fg.local['web-cert']['certificate'] = PEMS['old']     # (as if put back)
        t2, ctx2 = make(self.fg)
        t2.deploy(b, dict(REPLACE, force=True))
        self.assertIn('the intermediate CA certificate is on the FortiGate already',
                      said(ctx2))

    def test_dup(self):
        e = PluginError('importing a CA certificate: the device said 500 - -328',
                        detail='{"status":"error","error":-328}')
        self.assertTrue(FG.FortiGateTarget.dup(e))
        self.assertFalse(FG.FortiGateTarget.dup(PluginError('x: said 500 - -3281')))
        self.assertFalse(FG.FortiGateTarget.dup(PluginError('x: said 500 - -5')))


# ---------------------------------------------------------------------------
class DryRunTest(unittest.TestCase):
    """What happens: the deployment recorded against the canned FortiGate of runplan (its
    REST API and its CLI over SSH)."""
    def record(self, version, opts, ssh=True):
        from acmelib.certs import runplan as R
        cfg = dict({'host': 'fw', 'token': 't', 'vdom': 'root', '_version': version},
                   **(SSH if ssh else {}))
        got, err = R.record({'runs': [{
            'id': 'r1', 'family': 'target', 'kind': 'fortigate', 'name': 't', 'op': 'deploy',
            'config': cfg, 'options': opts, 'seconds': 30,
            'answers': R.answers_of('fortigate', cfg, opts, version=version),
            'ssh_answers': R.ssh_answers_of('fortigate', cfg, opts, version=version)}],
            'cert': {'names': ['www.example.com'], 'key_type': 'ec-256'}}, timeout=120)
        self.assertEqual(err, '')
        return got['r1']

    def test_says_what_is_replaced(self):
        for ver in ('', '6.0', '7.0', '7.4.2'):
            r = self.record(ver, dict(REPLACE))
            self.assertFalse(r.get('error'), r.get('error'))
            evs = r['events']
            says = [e.get('words') for e in evs if e['kind'] in ('say', 'step')]
            self.assertTrue([w for w in says if w.startswith(
                'replacing the certificate web-cert in place: the same name, everything that '
                'uses it keeps using it (now www.example.com, valid to ')], says)
            self.assertIn('no other local certificate on the FortiGate is this one (FortiOS '
                          'refuses a duplicate)', says)
            self.assertIn('signed in over SSH as acme-admin: FortiOS 7.4.5 on fw01, VDOMs off - '
                          'the certificate is replaced in the FortiOS CLI (its REST API '
                          'cannot)', says)
            self.assertTrue([w for w in says if w.startswith(
                'checked: web-cert holds the new certificate now (SHA-256 ')], says)
            self.assertIn('web-cert replaced in place - its name and every use of it kept',
                          says)
            http = [(e['method'], e['url'].split('?')[0]) for e in evs if e['kind'] == 'http']
            self.assertFalse([h for h in http if h[0] == 'PUT' and 'vpn.certificate' in h[1]],
                             'never the REST PUT')
            self.assertNotIn(('POST', 'https://fw/api/v2/monitor/vpn-certificate/local/import'),
                             http)
            opens = [e for e in evs if e['kind'] == 'ssh-open']
            self.assertTrue(opens)
            self.assertEqual((opens[0]['host'], opens[0]['port'], opens[0]['user']),
                             ('fw', 22, 'acme-admin'))
            runs = [e for e in evs if e['kind'] == 'ssh-run']
            self.assertEqual(len(runs), 4, [e.get('input') for e in runs])
            self.assertTrue(all(e['input']['secret'] for e in runs[1:3]))
            dump = json.dumps(evs)
            self.assertNotIn('SSH-pw-0002', dump)

    def test_duplicate_said(self):
        """An unused acme copy of the new certificate would be named; here none is - the dry
        run lists every local certificate with its PEM and compares."""
        r = self.record('', dict(REPLACE))
        http = [e['url'] for e in r['events'] if e['kind'] == 'http']
        self.assertTrue([u for u in http if '/cmdb/vpn.certificate/local?' in u and
                         'with_meta=1' in u], http)

    def test_no_ssh_said(self):
        r = self.record('', dict(REPLACE), ssh=False)
        self.assertIn('replace in place goes over SSH and the target has no SSH sign-in',
                      r.get('error') or '')
        self.assertFalse([e for e in r['events'] if e['kind'].startswith('ssh')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
