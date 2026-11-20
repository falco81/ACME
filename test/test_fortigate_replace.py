#!/usr/bin/env python3
"""The FortiGate target's "Replace an existing certificate in place" (1.0.128) - over the REST
API (1.0.130, the default) and over SSH, the FortiOS CLI (1.0.129, "How to replace": SSH) -
against a fake FortiGate: a real HTTP server on 127.0.0.1 (a port the system gives) that keeps
its local and CA certificates and answers its REST API as FortiOS 7.6.8 build 3744 did (the
package of 2026-11-18, its samples/*.json), and a fake FortiOS CLI over SSH (test_targets'
FakeSsh) working on the same certificates.

    python3 test/test_fortigate_replace.py

- Find on the device: the local certificates listed (name, CN, expiry, issuer, uses, the
  fingerprint) - the facts from monitor/system/available-certificates where the listing says
  "certificate": "" (7.6.8), from the listing's PEM where it has one, else each read; the
  Fortinet factory ones left out, the one with the certificate's names suggested.
- The REST API: GET the certificate, GET available-certificates, the intermediates missing
  imported as CA before the PUT (-328: there), acme's own copy of the new certificate deleted
  (-23: in use - stops; another's: stops), PUT (the leaf, the key encrypted with a one-time
  password), read back (the fingerprint; q_ref changed: a warning); -651 said by its lines
  (duplicated / invalid private key / not a valid/matched certificate); the same requests in
  every version of the module; no SSH.
- SSH: config vpn certificate local / edit / set password / set private-key / set
  certificate, first ended with abort, then with next / end; config global or config vdom
  when VDOMs are on; the duplicates as above.
- No PEM, key or password in the steps; What happens (the recorded dry run) of both ways.
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
        # the other shapes as the real Bundle makes them (1.0.136)
        from acmelib.certs import pki
        if fmt == 'key-pem-enc-compat':
            return pki.key_encrypt(self.key_pem, password, iterations=2048).encode()
        if fmt == 'key-traditional-enc':
            return pki.key_traditional_encrypt(self.key_pem, password).encode()
        if fmt == 'key-traditional':
            return pki.key_traditional(self.key_pem).encode()
        return FakeBundle.as_format(self, fmt, password, alias)


def der(pem):
    return C.pem_to_der(pem)


def text_of(v):
    return v if isinstance(v, str) else ('' if v is None else str(v))


# ---------------------------------------------------------------------------
def fp_colon(pem):
    """SHA-256 as available-certificates says it: upper case, colons (samples/10)."""
    import hashlib
    try:
        h = hashlib.sha256(der(pem)).hexdigest().upper()
    except Exception:                                   # noqa: BLE001
        h = hashlib.sha256(text_of(pem).encode()).hexdigest().upper()
    return ':'.join(h[i:i + 2] for i in range(0, 64, 2))


def pubkey(pem, password=None, cert=False):
    """The public key of a certificate or a private key PEM (openssl), None unread."""
    try:
        if cert:
            return openssl('x509', '-pubkey', '-noout', data=pem.encode())
        return openssl('pkey', '-pubout', '-passin', 'pass:%s' % (password or ''),
                       data=pem.encode())
    except Exception:                                   # noqa: BLE001
        return None


def subject_cn(pem):
    try:
        out = openssl('x509', '-noout', '-subject', '-issuer', '-enddate',
                      '-nameopt', 'sep_multiline,utf8', data=pem.encode()).decode()
    except Exception:                                   # noqa: BLE001
        return {}, {}, ''
    subj, iss, cur, end = {}, {}, None, ''
    for ln in out.splitlines():
        if ln.startswith('subject='):
            cur = subj
        elif ln.startswith('issuer='):
            cur = iss
        elif ln.startswith('notAfter='):
            import email.utils
            t = email.utils.parsedate_to_datetime(ln[9:].replace('GMT', '+0000'))
            end = t.strftime('%Y-%m-%d %H:%M:%S  GMT')
            cur = None
        elif cur is not None and '=' in ln:
            k, v = ln.strip().split('=', 1)
            cur[k] = v
    return subj, iss, end


class FakeFortiGate(object):
    """A FortiGate's REST API as acme uses it, its certificates kept - answering as FortiOS
    7.6.8 build 3744 did (the package's samples/*.json, 2026-11-18): the cmdb listing with
    "certificate" empty, the GET of one with its PEM and a q_ref that leaves the admin GUI
    out; available-certificates with SHA-256 fingerprints (q_ref with the admin GUI); the PUT
    of a local certificate taking the leaf only, refusing a duplicate, a key it cannot read or
    one of another certificate with -651; a used one's DELETE refused with -23; a CA there
    already refused with -328."""

    def __init__(self, version='v7.4.5'):
        self.version = version
        self.local = {}
        self.cas = []
        self.calls = []
        self.refuse_list = None         # the listing refused with this status
        self.refuse_delete = set()      # names whose DELETE is refused (not -23)
        self.vdom_mode = None           # cmdb system global vdom-mode (None: 404)
        self.admin_server_cert = None   # system global admin-server-cert (uses it, q_ref 0)
        self.list_pem = False           # the cmdb listing with the PEM (as 7.4 is said to)
        self.no_avail = False           # no monitor/system/available-certificates (404)
        self.hidden = set()             # names available-certificates does not say (a VDOM)
        self.dup_first = False          # "duplicated" the first line of cli_error (7.4.13)
        self.put_ignore = False         # a PUT said success, nothing kept
        self.refuse_key_forms = []      # a private-key with one of these in it: refused
        # FortiOS 7.4.13 with VDOMs (the measurements of 2026-11-20): a PUT of another
        # certificate into one of the VDOM's range -651 "not a valid/matched" whatever the key;
        # one of the global range taken unchecked; "range" switched by a PUT of its own
        self.fos7413 = False
        self.range_back_error = False   # PUT {"range": "vdom"} refused
        self.put_error = None           # (error, [lines]): every PUT refused so
        self.put_uses = None            # q_ref after a PUT
        self.ca_error = None            # a CA import refused with this error
        self.serial = 'FGT60F'          # FGVMEV...: a FortiGate-VM with an EVAL licence
        self.eval_327 = False           # monitor local/import -327 (an EVAL VM, samples/11)
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
                            'private-key': '', 'password': 'ENC XXXX', 'q_ref': q_ref}

    TAIL = {'serial': 'FGVMxxxxxxxxxxxx', 'version': 'v7.6.8', 'build': 3744}

    def err(self, status, code, lines=None, **more):
        out = dict({'http_method': '?', 'status': 'error', 'http_status': status,
                    'error': code, 'revision_changed': False}, **more)
        if lines is not None:
            out['cli_error'] = lines
        out.update(self.TAIL)
        return status, out

    def in_use(self, name):
        return bool(self.local[name].get('q_ref')) or self.admin_server_cert == name

    def uses(self, name):
        """q_ref of available-certificates: the admin GUI counted too (samples/10)."""
        return (self.local[name].get('q_ref') or 0) + (self.admin_server_cert == name)

    def avail(self, q):
        if self.no_avail:
            return self.err(404, -3)
        out = []
        for r in sorted(self.local.values(), key=lambda r: r['name']):
            if r['name'] in self.hidden:
                continue
            subj, iss, end = subject_cn(r['certificate'])
            out.append({'name': r['name'], 'source': r['source'], 'range': r['range'],
                        'type': 'local-cer', 'q_path': 'certificate', 'q_name': 'local',
                        'q_ref': self.uses(r['name']), 'key_type': 'ECDSA', 'key_size': 256,
                        'status': 'valid', 'fingerprint': fp_colon(r['certificate']),
                        'subject': subj, 'issuer': iss, 'valid_to_raw': end,
                        'has_valid_cert_key': False})
        if q.get('with_ca') == '1':
            for i, c in enumerate(self.cas):
                out.append({'name': 'CA_Cert_%d' % (i + 1), 'source': 'user',
                            'range': 'global', 'type': 'remote-ca', 'q_path': 'certificate',
                            'q_name': 'ca', 'fingerprint': fp_colon(c)})
        return 200, dict({'http_method': 'GET', 'results': out, 'status': 'success',
                          'http_status': 200, 'vdom': 'root'}, **self.TAIL)

    def put(self, name, body):
        """PUT cmdb vpn.certificate/local/<name> as FortiOS 7.6.8 answered it."""
        body = body or {}
        if self.put_error:
            return self.err(500, self.put_error[0], list(self.put_error[1]), mkey=name)
        if self.fos7413 and set(body) == {'range'}:
            if self.range_back_error:
                return self.err(500, -651, ['Input is not a valid/matched certificate.',
                                            'Command fail. Return code -651'], mkey=name)
            self.local[name]['range'] = body['range']
            return 200, dict({'http_method': 'PUT', 'revision_changed': True, 'mkey': name,
                              'status': 'success', 'http_status': 200}, **self.TAIL)
        if any(f in text_of(body.get('private-key')) for f in self.refuse_key_forms):
            return self.err(500, -651, ['Invalid private key, password may be required',
                                        'Command fail. Return code -651'], mkey=name)
        pem = text_of(body.get('certificate'))
        if self.fos7413:
            row = self.local[name]
            rng = body.get('range') or row['range']
            same = row['certificate'].startswith('-----') and pem.strip() and \
                der(row['certificate']) == der(pem)
            if row['range'] == 'vdom' and rng == 'vdom' and not same:
                return self.err(500, -651, [
                    'current vf=root:0', 'Input is not a valid/matched certificate.',
                    'node_check_object fail! for certificate -----BEGIN CERTIFICATE-----',
                    "value parse error before '-----BEGIN CERTIFICATE-----",
                    'Command fail. Return code -651'], mkey=name)
            # the global range: nothing checked (U1, J3)
            row.update(certificate=pem.strip() + '\n', range=rng,
                       **{'private-key': '', 'password': 'ENC new'})
            return 200, dict({'http_method': 'PUT', 'revision_changed': True, 'mkey': name,
                              'status': 'success', 'http_status': 200}, **self.TAIL)
        blocks = re.findall(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', pem,
                            re.S)
        echo = (['node_check_object fail! for certificate -----BEGIN CERTIFICATE-----'] +
                pem.strip().splitlines()[1:-1] + ['-----END CERTIFICATE-----'])
        tail = ["value parse error before '-----BEGIN CERTIFICATE-----'", 'MIIBjTCCA',
                'Command fail. Return code -651']
        bad = ['Input is not a valid/matched certificate.'] + echo
        if not blocks or not body.get('private-key'):
            return self.err(500, -651, bad + bad + tail, mkey=name)       # samples/04
        leaf = blocks[0] + '\n'
        key = pubkey(body['private-key'], body.get('password'))
        if key is None:                                                     # samples/03
            return self.err(500, -651, ['Invalid private key, password may be required'] +
                            bad + bad + tail, mkey=name)
        if key != pubkey(leaf, cert=True):                                  # samples/04
            return self.err(500, -651, bad + bad + tail, mkey=name)
        if [n for n, r in self.local.items() if n != name and
                r['certificate'].startswith('-----') and der(r['certificate']) == der(leaf)]:
            lines = bad + tail                                              # samples/02
            lines = ((['This local certificate is duplicated.'] + lines) if self.dup_first
                     else lines + ['This local certificate is duplicated.'])
            return self.err(500, -651, lines, mkey=name)
        if not self.put_ignore:
            self.local[name].update(certificate=leaf, **{'private-key': '', 'password':
                                                         'ENC new'})
            if self.put_uses is not None:
                self.local[name]['q_ref'] = self.put_uses
        return 200, dict({'http_method': 'PUT', 'revision_changed': True, 'mkey': name,
                          'status': 'success', 'http_status': 200, 'path': 'vpn.certificate',
                          'name': 'local', 'vdom': 'root'}, **self.TAIL)            # samples/01

    def answer(self, m, path, q, body):
        ok = {'http_method': m, 'status': 'success', 'http_status': 200}
        if path == '/api/v2/monitor/system/status':
            return 200, dict(ok, version=self.version, serial=self.serial, vdom='root',
                             results={'hostname': 'fw1', 'model_name': 'FortiGate'})
        if path == '/api/v2/monitor/system/available-certificates' and m == 'GET':
            return self.avail(q)
        lp = '/api/v2/cmdb/vpn.certificate/local'
        if path == lp and m == 'GET':
            if self.refuse_list:
                return self.err(self.refuse_list, -37)
            rows = sorted(self.local.values(), key=lambda r: r['name'])
            if q.get('format') == 'name':
                return 200, dict(ok, results=[{'name': r['name']} for r in rows])
            meta = q.get('with_meta') == '1'
            # 7.6.8: every "certificate" of the listing empty (samples/09)
            return 200, dict(ok, results=[{k: (v if k != 'certificate' or self.list_pem
                                               else '') for k, v in r.items()
                                           if meta or k != 'q_ref'} for r in rows])
        if path.startswith(lp + '/'):
            name = path[len(lp) + 1:]
            row = self.local.get(name)
            if m == 'GET':
                if not row:
                    return self.err(404, -3)
                return 200, dict(ok, results=[{k: v for k, v in row.items()     # samples/08
                                               if q.get('with_meta') == '1' or k != 'q_ref'}])
            if m == 'PUT':
                if not row:
                    return self.err(404, -3)
                return self.put(name, body)
            if m == 'DELETE':
                if not row:
                    return self.err(404, -3)
                if self.in_use(name):                                       # samples/05
                    return self.err(500, -23, [
                        "Can't delete this certificate. It's currently being used.",
                        'command_cli_delete:6613 delete table entry %s unset oper error '
                        'ret=-23' % name, 'Command fail. Return code -23'], mkey=name)
                if name in self.refuse_delete:
                    return self.err(500, -37)
                del self.local[name]
                return 200, dict(ok, revision_changed=True)
        if path == '/api/v2/monitor/vpn-certificate/local/import' and m == 'POST':
            if self.eval_327:                                               # samples/11
                return self.err(500, -327, path='vpn-certificate', name='local',
                                action='import')
            name = body['certname']
            if name in self.local:
                return self.err(500, -5)
            import base64
            pem = '(imported)'
            try:
                if body.get('type') == 'pkcs12':
                    pem = openssl('pkcs12', '-nokeys', '-clcerts', '-passin', 'pass:%s' %
                                  body.get('password', ''), data=base64.b64decode(
                                      body['file_content'])).decode()
                else:
                    pem = base64.b64decode(body['file_content']).decode()
                pem = re.search(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----',
                                pem, re.S).group(0) + '\n'
            except Exception:                           # noqa: BLE001
                pem = '(imported)'
            self.add(name, pem, rng=body.get('scope', 'global'))
            return 200, dict(ok, results={'mkey': name})
        if path == '/api/v2/monitor/vpn-certificate/ca/import' and m == 'POST':
            import base64
            pem = base64.b64decode(body['file_content']).decode()
            if self.ca_error:
                return self.err(500, self.ca_error)
            if der(pem) in [der(c) for c in self.cas]:                      # samples/07
                return 500, dict({'http_method': 'POST', 'error': -328, 'status': 'error',
                                  'http_status': 500, 'path': 'vpn-certificate', 'name': 'ca',
                                  'action': 'import', 'vdom': 'root'}, **self.TAIL)
            self.cas.append(pem)
            return 200, dict({'http_method': 'POST', 'results': {}, 'path': 'vpn-certificate',
                              'name': 'ca', 'action': 'import', 'status': 'success',
                              'vdom': 'root'}, **self.TAIL)                 # samples/06
        if path == '/api/v2/cmdb/vpn.certificate/ca' and m == 'GET':
            return 200, dict(ok, results=[{'name': 'CA_Cert_%d' % (i + 1), 'ca': c}
                                          for i, c in enumerate(self.cas)])
        if path == '/api/v2/cmdb/system/global' and m == 'GET' and self.vdom_mode:
            return 200, dict(ok, results={'vdom-mode': self.vdom_mode})
        if m == 'PUT':
            self.puts.setdefault(path, []).append(body)
            if path == '/api/v2/cmdb/system/global' and (body or {}).get('admin-server-cert'):
                self.admin_server_cert = body['admin-server-cert']
            return 200, ok
        if m == 'GET' and path.startswith('/api/v2/cmdb/firewall/'):
            return 200, dict(ok, results=[{'name': path.rsplit('/', 1)[-1]}])
        return self.err(404, -3)

    def find(self, method, rx):
        return [c for c in self.calls if c['method'] == method and re.search(rx, c['path'])]

    def writes(self):
        return [(c['method'], c['path']) for c in self.calls if c['method'] != 'GET']


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


REPLACE = {'mode': 'replace', 'replace_name': 'web-cert'}            # the REST API: the default
SSHR = dict(REPLACE, replace_via='ssh')


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
        # FortiOS 7.6.8 lists every one with "certificate" empty: the facts came from
        # available-certificates (1.0.130), the fingerprint among them
        self.assertEqual(self.fg.find('GET', r'available-certificates')[0]['query'],
                         {'scope': 'vdom', 'vdom': 'root'})
        self.assertIn('SHA-256 %s…' % FG.norm_fp(fp_colon(PEMS['old']))[:8].upper(),
                      words['web-cert'])
        self.assertFalse(self.fg.find('GET', r'/local/web-cert$'), 'not read one by one')

    def facts(self):
        t, ctx = make(self.fg)
        t.hint_names = ['www.example.test']
        got = t.catalog('local_certs')
        words = dict(got['options'])
        self.assertEqual(got['pick'], 'web-cert')
        self.assertIn('CN www.example.test', words['web-cert'])
        self.assertIn('Test CA', words['web-cert'])
        self.assertRegex(words['web-cert'], r'→ \d{4}-\d\d-\d\d')
        self.assertNotIn('Fortinet_SSL', words)
        return got, words

    def test_listing_with_the_pem(self):
        """A listing that gives the PEM (as FortiOS 7.4 is said to): read from it."""
        self.fg.list_pem = True
        self.facts()
        self.assertFalse(self.fg.find('GET', r'available-certificates'))

    def test_listing_without_available_certificates(self):
        """No available-certificates (an older FortiOS): each one read by itself."""
        self.fg.no_avail = True
        got, words = self.facts()
        self.assertIn('7×', words['web-cert'])
        self.assertTrue(self.fg.find('GET', r'/local/web-cert$'))

    def test_uses_count_the_admin_gui(self):
        """cmdb q_ref leaves the admin GUI out; available-certificates counts it."""
        self.fg.admin_server_cert = 'other'
        got, words = self.facts()
        self.assertIn('1×', words['other'])

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
class WrongPasswordBundle(Bundle):
    """The key encrypted with another password than the one sent (FortiOS: "Invalid private
    key, password may be required")."""
    def as_format(self, fmt, password=None, alias=None):
        if fmt == 'key-pem-enc':
            return Bundle.as_format(self, fmt, (password or '') + '-not-it', alias)
        return Bundle.as_format(self, fmt, password, alias)


class OtherKeyBundle(Bundle):
    """A key of another certificate (FortiOS: "Input is not a valid/matched certificate")."""
    def __init__(self, *a, **k):
        Bundle.__init__(self, *a, **k)
        self.key_pem = read(os.path.join(T.TMP, 'other.key'))


class ApiReplaceTest(Base):
    """How to replace: the REST API (1.0.130, the default) - the package's algorithm."""

    def deploy(self, version='', fos=None, bundle=None, **opts):
        if fos:
            self.fg.version = fos
        t, ctx = make(self.fg, version)
        b = bundle or Bundle()
        got = t.deploy(b, dict(REPLACE, **opts))
        return t, ctx, b, got

    def fails(self, bundle=None, opts=None, cfg=None):
        t, ctx = make(self.fg, **(cfg or {}))
        b = bundle or Bundle()
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(REPLACE, **(opts or {})))
        self.assertFalse(ctx.cli.runs(), 'never SSH')
        self.no_secrets(ctx, b, [str(e.exception), e.exception.detail or ''])
        return e.exception, ctx, b

    def put_body(self):
        puts = self.fg.find('PUT', r'/vpn\.certificate/local/')
        return puts[-1]['body'] if puts else {}

    def no_secrets(self, ctx, b, extra=()):
        """Nothing of a PEM, a key, the one-time password or the token in what is kept."""
        pw = text_of(self.put_body().get('password'))
        kept = [w for _l, w in ctx.steps] + list(getattr(ctx, 'debugs', [])) + list(extra)
        for w in kept:
            for bad in ('BEGIN', 'PRIVATE KEY', 'MII', 'TKN-secret', 'SSH-pw') + (
                    (pw,) if pw else ()):
                self.assertNotIn(bad, w)
            for ln in b.cert_pem.splitlines()[1:-1]:
                self.assertNotIn(ln[:20], w)

    def unchanged_target(self):
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))

    def check_replaced(self, b, ctx, name='web-cert', uses=7):
        row = self.fg.local[name]
        self.assertEqual(der(row['certificate']), der(b.cert_pem))
        self.assertEqual(row['certificate'].count('BEGIN CERTIFICATE'), 1, 'the leaf only')
        self.assertEqual(row['password'], 'ENC new')
        self.assertEqual(row['q_ref'], uses, 'its uses kept')
        body = self.put_body()
        self.assertEqual(sorted(body), ['certificate', 'password', 'private-key'])
        self.assertTrue(body['private-key'].startswith('-----BEGIN ENCRYPTED PRIVATE KEY-----\n'))
        self.assertEqual(body['certificate'].count('BEGIN CERTIFICATE'), 1, 'the leaf sent')
        self.assertEqual(der(body['certificate']), der(b.cert_pem))
        self.assertGreaterEqual(len(body['password']), 20)
        self.assertFalse(ctx.cli.runs(), 'no SSH, though the target has its sign-in')
        self.assertFalse(self.fg.find('POST', r'/local/import'), 'nothing imported anew')
        self.assertFalse([n for n in self.fg.local if n.startswith('acme-')])
        self.assertTrue(all(c['auth'] == 'Bearer TKN-secret-0001' for c in self.fg.calls))
        self.no_secrets(ctx, b)

    def seq(self):
        """The calls of the replace, as (method, path, query)."""
        out = []
        for c in self.fg.calls:
            if re.search(r'vpn\.certificate/local/|available-certificates|ca/import', c['path']):
                out.append((c['method'], c['path'].replace('/api/v2/', ''),
                            tuple(sorted(c['query'].items()))))
        return out

    def test_happy_path_every_version_same_requests(self):
        L = 'cmdb/vpn.certificate/local/web-cert'
        want = [('GET', L, (('vdom', 'root'), ('with_meta', '1'))),
                ('GET', 'monitor/system/available-certificates',
                 (('scope', 'vdom'), ('vdom', 'root'), ('with_ca', '1'))),
                ('POST', 'monitor/vpn-certificate/ca/import', ()),
                ('PUT', L, (('vdom', 'root'),)),
                ('GET', L, (('vdom', 'root'), ('with_meta', '1'))),
                # 1.0.136: read again for the new one's key size (scope=vdom with a VDOM)
                ('GET', 'monitor/system/available-certificates',
                 (('scope', 'vdom'), ('vdom', 'root'), ('with_ca', '1')))]
        for ver, fos in (('', 'v7.6.8'), ('6.0', 'v6.4.15'), ('7.0', 'v7.2.10'),
                         ('7.4.2', 'v7.4.13'), ('7.4.2', 'v8.0.0')):
            self.tearDown()
            self.setUp()
            t, ctx, b, got = self.deploy(ver, fos)
            self.check_replaced(b, ctx)
            self.assertEqual(got, 'web-cert replaced in place')
            self.assertEqual(self.seq(), want, ver)
            self.assertFalse(self.fg.puts, 'nothing re-pointed')
            ca = self.fg.find('POST', r'/ca/import')[0]['body']
            self.assertEqual((ca['import_method'], ca['scope']), ('file', 'global'))
            words = said(ctx)
            for w in ('it is replaced over the REST API (PUT cmdb vpn.certificate/local/'
                      'web-cert) - the token is enough, no SSH',
                      'the fingerprints of the certificates on the FortiGate read (monitor/'
                      'system/available-certificates): 4 local, 0 CA',
                      'no other local certificate on the FortiGate is this one (FortiOS '
                      'refuses a duplicate)',
                      'FortiOS took the new certificate and key for web-cert',
                      'web-cert replaced in place - its name and every use of it kept'):
                self.assertIn(w, words)
            self.assertTrue(any('used 7 times' in w for w in words), words)
            self.assertTrue(any('key type changes from RSA to EC' in w for w in words))
            self.assertTrue([w for w in words if w.startswith(
                'imported the intermediate CA certificate Test CA before the replace')])
            self.assertTrue([w for w in words if w.startswith(
                'checked: web-cert holds the new certificate now (SHA-256 ')])

    def test_ca_before_put_and_none_when_there(self):
        t, ctx, b, got = self.deploy()
        w = self.fg.writes()
        self.assertEqual([m for m, _p in w], ['POST', 'PUT'], 'the CA before the PUT')
        # the next renewal: the intermediate there - GET, GET, PUT, GET only
        self.fg.local['web-cert']['certificate'] = PEMS['old']
        self.fg.calls[:] = []
        t, ctx, b, got = self.deploy(force=True)
        self.assertEqual([c['method'] for c in self.fg.calls
                          if 'monitor/system/status' not in c['path']
                          and 'cmdb/vpn.certificate/local?' not in c['path'] + '?'
                          and not c['path'].endswith('/cmdb/vpn.certificate/local')],
                         ['GET', 'GET', 'PUT', 'GET', 'GET'])
        self.assertIn('the intermediate CA certificate is on the FortiGate already', said(ctx))

    def test_already_in_place(self):
        b = Bundle()
        self.fg.local['web-cert']['certificate'] = b.cert_pem
        self.fg.cas.append(b.chain_pems[0])
        t, ctx = make(self.fg)
        got = t.deploy(b, dict(REPLACE, force=True))
        self.assertEqual(got, 'already in place in web-cert')
        self.assertIn('web-cert holds this certificate already - it is in place', said(ctx))
        self.assertFalse(self.fg.writes())

    def test_again_unchanged(self):
        t, ctx, b, got = self.deploy()
        t2, ctx2 = make(self.fg)
        ctx2.kv = ctx.kv
        n = len(self.fg.writes())
        got = t2.deploy(b, dict(REPLACE))
        self.assertTrue(got.startswith('unchanged'), got)
        self.assertEqual(len(self.fg.writes()), n)

    def test_wrong_key_or_password(self):
        """A key that does not open with its password (1.0.136): checked here, never sent -
        FortiOS 7.4.13 stores such a pair unchecked on a certificate of the global range."""
        e, ctx, b = self.fails(WrongPasswordBundle(), opts={'replace_key': 'pkcs8-enc'})
        self.assertIn('the private key is not the certificate\'s (or does not open with its '
                      'password) - checked here, nothing was sent to the FortiGate', str(e))
        self.assertFalse(e.retry)
        self.assertTrue(e.lasting)
        self.assertFalse(self.fg.find('PUT', r'.'))
        self.unchanged_target()

    def test_wrong_password_next_format_taken(self):
        """Key format automatic (1.0.136): a key FortiOS does not take - the next format;
        every refusal changes nothing (F10)."""
        t, ctx = make(self.fg)
        b = Bundle()
        self.fg.refuse_key_forms = ['ENCRYPTED PRIVATE KEY']
        t.deploy(b, dict(REPLACE))
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))
        puts = self.fg.find('PUT', r'/local/web-cert$')
        self.assertEqual(len(puts), 3)
        warn = [w for lv, w in ctx.steps if lv == 'warn']
        self.assertIn('FortiOS did not take the key encrypted with a one-time password '
                      '(nothing was changed) - the next format', warn)
        self.assertIn('this FortiGate takes the key encrypted with a one-time password '
                      '(traditional, PKCS#1 / SEC1) - "Key format" may be set to it', said(ctx))

    def test_every_key_format_chosen(self):
        """Each "Key format" sends its own shape, alone."""
        heads = {'pkcs8-enc': '-----BEGIN ENCRYPTED PRIVATE KEY-----',
                 'pkcs8-enc-compat': '-----BEGIN ENCRYPTED PRIVATE KEY-----',
                 'traditional-enc': 'Proc-Type: 4,ENCRYPTED',
                 'pkcs8': '-----BEGIN PRIVATE KEY-----',
                 'traditional': '-----BEGIN EC PRIVATE KEY-----'}
        for f, head in heads.items():
            self.tearDown()
            self.setUp()
            t, ctx = make(self.fg)
            b = Bundle()
            t.deploy(b, dict(REPLACE, replace_key=f))
            puts = self.fg.find('PUT', r'/local/web-cert$')
            self.assertEqual(len(puts), 1, f)
            body = puts[0]['body']
            self.assertIn(head, body['private-key'], f)
            self.assertEqual('password' in body, '-enc' in f, f)
            self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))

    def test_missing_name_created(self):
        """A name typed by hand that the FortiGate does not have (1.0.136, "When it is not
        there": create, the default): imported under that name; the next deployment replaces
        it in place."""
        t, ctx = make(self.fg)
        b = Bundle()
        got = t.deploy(b, dict(REPLACE, replace_name='manualy.example'))
        self.assertIn('created manualy.example', got)
        imp = self.fg.find('POST', r'/local/import')
        self.assertEqual(len(imp), 1)
        self.assertEqual(imp[0]['body']['certname'], 'manualy.example')
        self.assertEqual(der(self.fg.local['manualy.example']['certificate']), der(b.cert_pem))
        self.assertFalse(self.fg.find('PUT', r'/vpn\.certificate/local/'))
        self.assertTrue(any('there is no local certificate manualy.example on the FortiGate '
                            '(VDOM root) - it is created under this name' in w
                            for w in said(ctx)))
        self.no_secrets(ctx, b)
        # ...and the next one (another certificate there now): in place, nothing imported
        self.fg.local['manualy.example']['certificate'] = PEMS['other']
        t, ctx = make(self.fg)
        t.deploy(b, dict(REPLACE, replace_name='manualy.example', force=True))
        self.assertEqual(len(self.fg.find('PUT', r'/local/manualy\.example$')), 1)
        self.assertEqual(len(self.fg.find('POST', r'/local/import')), 1)
        self.assertEqual(der(self.fg.local['manualy.example']['certificate']), der(b.cert_pem))

    def test_missing_name_too_long(self):
        e, ctx, b = self.fails(opts={'replace_name': 'x' * 36})
        self.assertIn('FortiOS takes names of 35 characters at most - nothing was changed',
                      str(e))
        self.assertFalse(self.fg.writes())

    def test_fos_7413_vdom_range_switched(self):
        """FortiOS 7.4.13 with VDOMs: a certificate of the VDOM's range is refused by every
        PUT ("not a valid/matched" alone) - replaced through the global range and back; the
        other key formats are not tried (the format is not why)."""
        self.fg.fos7413 = True
        self.fg.local['web-cert']['range'] = 'vdom'
        t, ctx = make(self.fg)
        b = Bundle()
        got = t.deploy(b, dict(REPLACE))
        self.assertEqual(got, 'web-cert replaced in place')
        row = self.fg.local['web-cert']
        self.assertEqual(der(row['certificate']), der(b.cert_pem))
        self.assertEqual(row['range'], 'vdom')
        puts = [c['body'] for c in self.fg.find('PUT', r'/local/web-cert$')]
        self.assertEqual(len(puts), 3)
        self.assertNotIn('range', puts[0])
        self.assertEqual(puts[1]['range'], 'global')
        self.assertEqual(sorted(puts[1]), ['certificate', 'password', 'private-key', 'range'])
        self.assertEqual(puts[2], {'range': 'vdom'})
        self.assertIn("web-cert is of the VDOM's range again", said(ctx))
        self.assertTrue([w for w in said(ctx) if w.startswith('checked: web-cert holds')])
        self.no_secrets(ctx, b)

    def test_fos_7413_range_not_set_back(self):
        self.fg.fos7413 = True
        self.fg.range_back_error = True
        self.fg.local['web-cert']['range'] = 'vdom'
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, dict(REPLACE))
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))
        self.assertEqual(self.fg.local['web-cert']['range'], 'global')
        warn = [w for lv, w in ctx.steps if lv == 'warn']
        self.assertTrue([w for w in warn if w.startswith(
            'the range of web-cert could not be set back to the VDOM')], warn)

    def test_fos_7413_global_range_unchecked_pair_checked_here(self):
        """The global range takes a pair that does not match (U1): acme checks it before -
        nothing sent."""
        self.fg.fos7413 = True
        e, ctx, b = self.fails(OtherKeyBundle())
        self.assertIn('checked here, nothing was sent to the FortiGate', str(e))
        self.assertFalse(self.fg.find('PUT', r'.'))

    def test_key_of_another_certificate(self):
        e, ctx, b = self.fails(OtherKeyBundle())
        self.assertIn('the private key is not the certificate\'s (or does not open with its '
                      'password) - checked here, nothing was sent to the FortiGate', str(e))
        self.assertFalse(self.fg.find('PUT', r'.'))
        self.unchanged_target()

    def test_other_refusal_said_with_its_lines(self):
        self.fg.put_error = (-5, ['Something is odd.', 'Command fail. Return code -5'])
        e, ctx, b = self.fails()
        self.assertIn('FortiOS refused to replace web-cert in place: HTTP 500, error -5: '
                      'Something is odd.; Command fail. Return code -5 - web-cert is untouched',
                      str(e))

    def test_duplicate_fortios_found_and_acme_did_not(self):
        """A copy available-certificates did not say (another VDOM): FortiOS's -651
        "duplicated" - in the order of 7.6.8 (last) and 7.4.13 (first); no PEM said back."""
        for first in (False, True):
            self.tearDown()
            self.setUp()
            b = Bundle()
            self.fg.add('elsewhere', b.cert_pem)
            self.fg.hidden.add('elsewhere')
            self.fg.dup_first = first
            e, ctx, b = self.fails(b)
            self.assertIn('FortiOS refused to replace web-cert in place: the new certificate is '
                          'on the FortiGate already under another name ("This local certificate '
                          'is duplicated") that acme did not find - in another VDOM?', str(e))
            self.assertIn('This local certificate is duplicated.', e.detail)
            self.assertNotIn('MIIBjTCCA', e.detail)
            self.assertNotIn('BEGIN', e.detail)
            self.unchanged_target()
            self.assertIn('elsewhere', self.fg.local)

    def test_verify_failed(self):
        self.fg.put_ignore = True
        e, ctx, b = self.fails()
        self.assertIn('FortiOS answered that it took the new certificate for web-cert, yet '
                      'web-cert still holds another one (SHA-256 ', str(e))
        self.assertIn('FortiOS dropped the write without saying so', str(e))
        self.assertTrue(e.lasting)
        self.assertFalse(e.retry)
        self.assertFalse([w for w in said(ctx) if 'replaced in place' in w])

    def test_uses_changed_warned(self):
        self.fg.put_uses = 6
        t, ctx, b, got = self.deploy()
        self.assertIn(('warn', 'web-cert was used 7 times before and 6 times now - look at '
                               'what uses it'), ctx.steps)

    def test_ca_import_324_stops_without_retry(self):
        """-324 on a CA import (measured: a FortiGate-VM EVAL refuses an RSA CA over 512
        bits): stopped before the PUT, said plainly, not tried again by itself."""
        self.fg.ca_error = -324
        e, ctx, b = self.fails()
        self.assertIn('the FortiGate refused the intermediate CA certificate (error -324; '
                      'intermediate: EC-256, CN=Test CA)', str(e))
        self.assertIn('EVAL/trial licence takes RSA keys of 512 bits at most', str(e))
        self.assertIn('nothing was replaced', str(e))
        self.assertIs(e.retry, False)
        self.assertFalse(self.fg.find('PUT', r'.'))
        self.assertFalse(self.fg.find('DELETE', r'.'))
        self.unchanged_target()

    def test_ca_import_other_refusal_stops(self):
        self.fg.ca_error = -5
        e, ctx, b = self.fails()
        self.assertIn('the intermediate CA certificate cannot be imported (HTTP 500, error -5',
                      str(e))
        self.assertFalse(self.fg.find('PUT', r'.'))
        self.unchanged_target()

    def test_eval_precheck(self):
        """A FortiGate-VM EVAL (serial FGVMEV...) and an RSA intermediate over 512 bits not on
        it: refused before anything is written, not tried again; an EC one (the test chain)
        or a licensed FortiGate - replaced as usual."""
        self.fg.serial = 'FGVMEV2DKSOJF7DA'
        t, ctx, b, got = self.deploy()                  # the EC chain: taken
        self.assertTrue(self.fg.find('PUT', r'/vpn\.certificate/local/'))
        t, ctx = make(self.fg)
        t._serial = 'FGVMEV2DKSOJF7DA'
        rsa = {'key': 'RSA', 'bits': 2048, 'cn': 'R13', 'fp': 'ab'}
        cls = type(t)
        orig = cls.__dict__.get('pem_facts')
        cls.pem_facts = staticmethod(lambda pem: rsa)
        try:
            with self.assertRaises(PluginError) as e:
                t.eval_check(Bundle(), {}, {'ca': {}})
            t.eval_check(Bundle(), {}, {'ca': {'ab': ['R13']}})     # there already: fine
            t._serial = 'FGT60F'
            t.eval_check(Bundle(), {}, {'ca': {}})                  # licensed: not checked
        finally:
            cls.pem_facts = orig
        self.assertIn('error -324; intermediate: RSA 2048, CN=R13', str(e.exception))
        self.assertIs(e.exception.retry, False)

    def test_not_found_and_factory_refused(self):
        e, ctx, b = self.fails(opts={'replace_name': 'web-certt', 'replace_missing': 'stop'})
        self.assertIn('there is no local certificate web-certt on the FortiGate (VDOM root)',
                      str(e))
        for n in ('Fortinet_SSL', 'mine'):
            self.fg.add('mine', PEMS['other'], source='factory')
            e, ctx, b = self.fails(opts={'replace_name': n})
            self.assertIn('%s is a Fortinet factory certificate - it is not replaced' % n,
                          str(e))
        self.assertFalse(self.fg.writes())

    def test_global_and_vdom(self):
        """A certificate of the VDOM's range: available-certificates asked with scope vdom;
        one of the global range: scope global."""
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, dict(REPLACE, replace_name='other'))
        self.assertEqual(der(self.fg.local['other']['certificate']), der(b.cert_pem))
        av = self.fg.find('GET', r'available-certificates')[0]['query']
        self.assertEqual((av['scope'], av['vdom'], av['with_ca']), ('vdom', 'root', '1'))
        self.assertEqual(self.fg.find('PUT', r'/local/other$')[0]['query'], {'vdom': 'root'})
        # the global one: scope global
        self.tearDown()
        self.setUp()
        t, ctx = make(self.fg)
        t.deploy(b, dict(REPLACE))
        av = self.fg.find('GET', r'available-certificates')[-1]['query']
        # 1.0.136: scope=vdom whenever there is a VDOM (7.4.13: scope global leaves the VDOM's
        # certificates out) - global only on a target without one
        self.assertEqual(av['scope'], 'vdom')

    def test_no_ssh_sign_in_needed(self):
        t, ctx = make(self.fg, ssh=False)
        b = Bundle()
        got = t.deploy(b, dict(REPLACE))
        self.assertEqual(got, 'web-cert replaced in place')
        self.assertFalse(ctx.cli.runs())

    def test_without_fingerprints_each_read(self):
        """An older FortiOS without available-certificates: the names, then each one read -
        a copy found that way too."""
        self.fg.no_avail = True
        b = Bundle()
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        self.fg.add(prefix + '20261118-191aae', b.cert_pem)
        t, ctx, b, got = self.deploy(bundle=b)
        self.check_replaced(b, ctx)
        self.assertIn('the FortiGate gives no fingerprints in monitor/system/available-'
                      'certificates - its 5 local certificates are read one by one', said(ctx))
        self.assertEqual([p.rsplit('/', 1)[-1] for m, p in self.fg.writes() if m == 'DELETE'],
                         [prefix + '20261118-191aae'])

    def test_unreadable_stops(self):
        self.fg.no_avail = True
        self.fg.refuse_list = 403
        e, ctx, b = self.fails()
        self.assertIn('the certificates on the FortiGate cannot be read (', str(e))
        self.assertIn('needs VPN (vpngrp) read-write; nothing was changed', str(e))
        self.assertFalse(self.fg.find('PUT', r'.'))

    def test_listed_uses_point_at_the_same_name(self):
        t, ctx, b, got = self.deploy('7.4.2', admin=True, sslvpn=True, vips='web')
        self.check_replaced(b, ctx)
        self.assertEqual(self.fg.puts['/api/v2/cmdb/system/global'],
                         [{'admin-server-cert': 'web-cert'}])
        self.assertEqual(self.fg.puts['/api/v2/cmdb/firewall/vip/web'],
                         [{'ssl-certificate': [{'name': 'web-cert'}]}])

    def test_hand_typed_name(self):
        self.fg.add('VPN cert/2026 #1', PEMS['other'], q_ref=1)
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, {'mode': 'replace', 'replace_name': 'VPN cert/2026 #1'})
        self.assertEqual(der(self.fg.local['VPN cert/2026 #1']['certificate']), der(b.cert_pem))
        self.assertTrue(any('used once' in w for w in said(ctx)))

    def test_cleanup_spares_the_replaced(self):
        b = Bundle()
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        olds = [prefix + '2026%04d-%06x' % (d, d) for d in (101, 201, 301)]
        for n in olds:
            self.fg.add(n, PEMS['other'])
        replaced = prefix + '20260401-0abcde'
        self.fg.add(replaced, PEMS['old'], q_ref=3)
        t, ctx = make(self.fg)
        t.deploy(b, {'mode': 'replace', 'replace_name': replaced, 'keep': 0})
        self.assertEqual(der(self.fg.local[replaced]['certificate']), der(b.cert_pem))
        self.assertEqual([n for n in olds if n in self.fg.local], [])
        self.assertNotIn(replaced, [c['path'].rsplit('/', 1)[-1] for c in
                                    self.fg.find('DELETE', r'.')])

    def test_the_field_and_the_key(self):
        f = {x['key']: x for x in FG.FortiGateTarget.deploy_fields}
        self.assertEqual(f['replace_via']['default'], 'api')
        self.assertEqual([o[0] for o in f['replace_via']['options']], ['api', 'ssh'])
        self.assertEqual(f['replace_via']['show_if'], {'mode': ['replace']})
        self.assertEqual(f['replace_via']['label'], 'How to replace')
        self.assertNotIn('SSH sign-in', f['mode']['help'].split('unless')[0])
        t, ctx = make(self.fg)
        self.assertEqual(t.state_key(dict(REPLACE)),
                         t.state_key(dict(REPLACE, replace_via='api')),
                         'a deployment saved before the option keeps its key')
        self.assertNotEqual(t.state_key(dict(REPLACE)), t.state_key(dict(SSHR)))
        self.assertEqual(t.state_key({'keep': 1}),
                         t.state_key({'keep': 1, 'mode': 'new', 'replace_via': 'api'}))

    def test_new_mode_as_before(self):
        """A new certificate each time: imported under its new name; never a PUT of a local
        certificate; -327 of an EVAL VM said as FortiOS's error."""
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, {'keep': 1})
        self.assertEqual(len(self.fg.find('POST', r'/local/import')), 1)
        self.assertFalse(self.fg.find('PUT', r'/vpn\.certificate/local/'))
        self.assertFalse(self.fg.find('GET', r'available-certificates'))
        self.unchanged_target()
        self.tearDown()
        self.setUp()
        self.fg.eval_327 = True
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(b, {'keep': 1})
        self.assertIn('-327', str(e.exception))
        self.assertFalse(self.fg.find('PUT', r'/vpn\.certificate/local/'))

    def test_scrub(self):
        lines = ['Input is not a valid/matched certificate.',
                 'node_check_object fail! for certificate -----BEGIN CERTIFICATE-----',
                 'MIIDtjCCAzygAwIBAgISBOGUS0123456789abcdefABCDEF', '-----END CERTIFICATE-----',
                 "value parse error before '-----BEGIN CERTIFICATE-----'", 'MIIBjTCCA',
                 '-----BEGIN ENCRYPTED PRIVATE KEY-----', 'Command fail. Return code -651',
                 'This local certificate is duplicated.']
        out = FG.scrub_lines(lines)
        self.assertFalse([x for x in out if 'BEGIN' in x or 'MII' in x], out)
        for keep in ('This local certificate is duplicated.', 'Command fail. Return code -651',
                     'Input is not a valid/matched certificate.'):
            self.assertIn(keep, out)


# ---------------------------------------------------------------------------
class ApiDuplicateTest(ApiReplaceTest.__bases__[0]):
    """FortiOS refuses a local certificate identical to another (-651 "duplicated") - the
    1.0.128 failure: the same certificate imported an hour before by the default mode."""
    deploy = ApiReplaceTest.deploy
    fails = ApiReplaceTest.fails
    put_body = ApiReplaceTest.put_body
    no_secrets = ApiReplaceTest.no_secrets
    unchanged_target = ApiReplaceTest.unchanged_target

    def copy(self, b, name=None, q_ref=0):
        name = name or C.name_prefix(b, {}, maxlen=35, serial_len=6) + '20261118-191aae'
        self.fg.add(name, b.cert_pem, q_ref=q_ref)
        return name

    def test_the_1_0_128_failure(self):
        """The default mode first (its acme-... copy), then replace in place: the copy - the
        same certificate - deleted first, then the PUT."""
        b = Bundle()
        t, ctx = make(self.fg)
        t.deploy(b, {'keep': 1})
        n = [x for x in self.fg.local if x.startswith('acme-')]
        self.assertEqual(len(n), 1)
        t, ctx = make(self.fg)
        got = t.deploy(b, dict(REPLACE))
        self.assertEqual(got, 'web-cert replaced in place')
        self.assertNotIn(n[0], self.fg.local)
        w = [(m, p.rsplit('/', 1)[-1]) for m, p in self.fg.writes()]
        self.assertEqual(w[-2:], [('DELETE', n[0]), ('PUT', 'web-cert')], w)
        self.assertFalse(self.fg.find('POST', r'/local/import')[1:], 'no new import')

    def test_own_unused_copy_deleted_first(self):
        b = Bundle()
        n = self.copy(b)
        t, ctx = make(self.fg)
        t.deploy(b, dict(REPLACE))
        self.assertNotIn(n, self.fg.local)
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))
        words = said(ctx)
        self.assertIn('%s is this very certificate already - a copy acme imported earlier; it '
                      'is deleted first (FortiOS refuses two identical local certificates)' % n,
                      words)
        self.assertIn('deleted %s, the unused copy of this certificate' % n, words)

    def test_foreign_copy_stops(self):
        b = Bundle()
        self.copy(b, name='my-own-copy')
        e, ctx, b = self.fails(b)
        self.assertIn('the FortiGate has this very certificate already as my-own-copy, which '
                      'acme did not make', str(e))
        self.assertIn('my-own-copy', self.fg.local)
        self.assertFalse([w for w in self.fg.writes() if w[0] in ('PUT', 'DELETE')])
        self.unchanged_target()

    def test_another_deployments_acme_copy_is_foreign(self):
        """acme-... of another certificate's names: not this deployment's own - kept."""
        b = Bundle()
        self.copy(b, name='acme-mail.example.te-20261118-191aae')
        e, ctx, b = self.fails(b)
        self.assertIn('as acme-mail.example.te-20261118-191aae, an acme name of another '
                      'deployment (this one deletes only its own acme-www.example.te-… copies)',
                      str(e))
        self.assertFalse(self.fg.find('DELETE', r'.'))

    def test_copy_in_use_minus_23(self):
        """acme's copy used by the admin GUI only - cmdb q_ref 0, yet FortiOS refuses to delete
        it (-23): it stops, the target untouched, the copy kept."""
        b = Bundle()
        n = self.copy(b)
        self.fg.admin_server_cert = n
        e, ctx, b = self.fails(b)
        self.assertIn('the FortiGate has this very certificate already as %s, an earlier import '
                      'of acme that is in use - FortiOS refused to delete it (-23, "currently '
                      'being used")' % n, str(e))
        self.assertIn('point what uses %s at web-cert, then deploy again' % n, str(e))
        self.assertIn("Can't delete this certificate. It's currently being used.", e.detail)
        self.assertIn(n, self.fg.local)
        self.assertFalse(self.fg.find('PUT', r'.'))
        self.unchanged_target()

    def test_copy_delete_refused_otherwise(self):
        b = Bundle()
        n = self.copy(b)
        self.fg.refuse_delete.add(n)
        e, ctx, b = self.fails(b)
        self.assertIn('%s, an unused copy of this very certificate, cannot be deleted (HTTP '
                      '500, error -37: -) - nothing else was changed' % n, str(e))
        self.assertFalse(self.fg.find('PUT', r'.'))

    def test_never_the_replaced(self):
        """The replaced one is named as acme names its copies: never taken for a copy."""
        b = Bundle()
        prefix = C.name_prefix(b, {}, maxlen=35, serial_len=6)
        replaced = prefix + '20260401-0abcde'
        self.fg.add(replaced, b.cert_pem, q_ref=1)
        n = self.copy(b, name=prefix + '20261118-191aae')
        t, ctx = make(self.fg)
        got = t.deploy(b, {'mode': 'replace', 'replace_name': replaced, 'force': True})
        self.assertEqual(got, 'already in place in %s' % replaced)
        self.assertIn(replaced, self.fg.local)
        self.assertIn(n, self.fg.local)
        self.assertFalse(self.fg.find('DELETE', r'.'))


# ---------------------------------------------------------------------------
class SshReplaceTest(Base):
    """How to replace: SSH - the FortiOS CLI (1.0.129), kept as the other way."""
    def deploy(self, version='', fos=None, cli=None, **opts):
        if fos:
            self.fg.version = fos
        t, ctx = make(self.fg, version, cli=cli)
        b = Bundle()
        got = t.deploy(b, dict(SSHR, **opts))
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
        self.assertTrue(runs[0].startswith('get system status\n'))
        self.assertFalse(runs[0].replace('get system status\n', '').strip())
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
                          'the certificate is replaced in the FortiOS CLI', words)
            self.assertIn('no other local certificate on the FortiGate is this one (FortiOS '
                          'refuses a duplicate)', words)
            self.assertTrue([w for w in words if w.startswith(
                'checked: web-cert holds the new certificate now (SHA-256 ')], words)
            self.assertTrue(all(c['auth'] == 'Bearer TKN-secret-0001' for c in self.fg.calls))

    def test_ssh_sends_no_rest_put(self):
        """Over SSH the certificate goes to the CLI only - never the REST PUT."""
        t, ctx, b, got = self.deploy()
        self.check_replaced(b, ctx)
        self.assertFalse(self.fg.find('PUT', r'/vpn\.certificate/local/'))

    def test_version_refused_before_anything(self):
        self.fg.version = 'v6.4.15'
        t, ctx = make(self.fg, '7.4.2')
        with self.assertRaises(PluginError):
            t.deploy(Bundle(), dict(SSHR))
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
        got = t2.deploy(b, dict(SSHR))
        self.assertTrue(got.startswith('unchanged'), got)
        self.assertEqual(len(ctx.cli.runs()), n)

    def test_already_in_place(self):
        """The very certificate at the name already (put there by hand, or forced): nothing
        sent - FortiOS would call it a duplicate of itself."""
        b = Bundle()
        self.fg.local['web-cert']['certificate'] = b.cert_pem
        t, ctx = make(self.fg)
        got = t.deploy(b, dict(SSHR, force=True))
        self.assertEqual(got, 'already in place in web-cert')
        self.assertIn('web-cert holds this certificate already - it is in place', said(ctx))
        self.assertFalse(ctx.cli.runs())
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])

    def test_encrypted_key_refused_plain_tried(self):
        cli = FakeCli(self.fg)
        cli.refuse_encrypted = True
        t, ctx, b, got = self.deploy(cli=cli)
        edits = [r for r in cli.runs() if 'config vpn certificate local' in r]
        # the three encrypted shapes (1.0.136: PKCS#8, PKCS#8 PBKDF2 2048, traditional), then
        # the plain one checked and saved
        self.assertEqual(len(edits), 5)
        self.assertIn('ENCRYPTED PRIVATE KEY', edits[0])
        self.assertIn('ENCRYPTED PRIVATE KEY', edits[1])
        self.assertIn('Proc-Type: 4,ENCRYPTED', edits[2])
        for r in edits[:3]:
            self.assertTrue(r.endswith('abort\n'))
        for r in edits[3:]:
            self.assertNotIn('set password', r)
            self.assertIn('set private-key "-----BEGIN PRIVATE KEY-----\n', r)
        self.assertTrue(edits[3].endswith('abort\n') and edits[4].endswith('next\nend\n'))
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))
        warn = [w for lv, w in ctx.steps if lv == 'warn']
        self.assertTrue([w for w in warn if w.startswith(
            'FortiOS did not take the key encrypted with a one-time password (Input is not a '
            'valid/matched private key.')], warn)
        self.no_secrets(ctx, b)

    def test_status_after_the_prompt_and_paged(self):
        """A FortiGate 40F, 7.4.13 (the report of 2026-11-19): with no terminal the answer
        follows the prompt on its line, an admin of a profile has the prompt "$", and the
        console pages ("--More--") - still read as FortiOS's."""
        cli = FakeCli(self.fg)
        orig = cli.shell

        def shell(cmd, inp):
            rc, out, err = orig(cmd, inp)
            if inp.startswith('get system status'):
                body = (STATUS % 'disable').replace('Operation Mode: NAT\n',
                                                    'Operation Mode: NAT\n --More-- \r'
                                                    '          \r')
                out = 'FW-Table-PeS $ ' + body + 'FW-Table-PeS $ '
            return rc, out, err
        cli.ssh.answers = [(r'^\n', lambda c, i: shell(c, i))]
        t, ctx, b, got = self.deploy(cli=cli)
        self.check_replaced(b, ctx)
        self.assertIn('signed in over SSH as acme-admin: FortiOS 7.4.13 on fw1, VDOMs off - '
                      'the certificate is replaced in the FortiOS CLI', said(ctx))

    def test_cli_error_aborts_nothing_saved(self):
        cli = FakeCli(self.fg)
        cli.fail_cert = True
        t, ctx = make(self.fg, cli=cli)
        b = Bundle()
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(SSHR, keep=0))
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
            t.deploy(Bundle(), dict(SSHR))
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
        self.assertTrue([r for r in ctx.cli.runs() if r.startswith(
            'show vpn certificate local "web-cert"\n') and not r.split('\n', 1)[1].strip()])
        self.assertTrue([w for w in said(ctx) if w.startswith('checked: web-cert holds')])

    def test_global_scope_with_vdoms(self):
        cli = FakeCli(self.fg, vdoms=True)
        t, ctx, b, got = self.deploy(cli=cli)
        self.check_replaced(b, ctx, 'global')
        self.assertIn('signed in over SSH as acme-admin: FortiOS 7.4.13 on fw1, VDOMs on '
                      '(multiple) - the certificate is replaced in the FortiOS CLI', said(ctx))

    def test_vdom_scope_with_vdoms(self):
        cli = FakeCli(self.fg, vdoms=True)
        t, ctx = make(self.fg, cli=cli)
        b = Bundle()
        t.deploy(b, {'mode': 'replace', 'replace_via': 'ssh', 'replace_name': 'other'})
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
                t.deploy(Bundle(), dict(SSHR))
            words = str(e.exception)
            self.assertIn('replace in place over SSH ("How to replace": SSH) and the target has '
                          'no SSH sign-in', words)
            self.assertIn('fill in the target\'s SSH user and its key or password', words)
            self.assertIn('or choose the REST API - nothing was changed', words)
            self.assertFalse(e.exception.retry)
            self.assertFalse(ctx.cli.runs())
            self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        # the new mode needs none, nor the REST API way
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
        self.assertEqual(f['ssh_user']['label'], 'SSH user (replace over SSH)')
        self.assertIn('only when "How to replace" is SSH - empty: not used',
                      f['ssh_user']['help'])
        for k in ('ssh_user', 'ssh_password', 'ssh_key'):
            self.assertNotIn('required', f[k].get('help', ''), k)
        self.assertEqual(f['ssh_key']['type'], 'sshkey')
        self.assertEqual(f['ssh_key']['ssh_prefix'], 'ssh_')
        self.assertEqual(f['ssh_key']['try_command'], 'get system status')
        self.assertTrue(f['ssh_trust_first']['default'])

    def test_try_says_the_ssh_sign_in(self):
        t, ctx = make(self.fg)
        said_ = t.test()
        self.assertIn('; over SSH as acme-admin: FortiOS 7.4.13 on fw1, VDOMs off', said_)
        self.assertEqual([r.strip() for r in ctx.cli.runs()], ['get system status'])
        t, ctx = make(self.fg, ssh=False)
        self.assertNotIn('SSH', t.test())
        self.assertFalse(ctx.cli.runs())

    def test_missing_name_fails_early(self):
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), dict(SSHR, replace_name='web-certt', replace_missing='stop'))
        self.assertIn('there is no local certificate web-certt on the FortiGate (VDOM root)',
                      str(e.exception))
        self.assertIn('nothing was changed', str(e.exception))
        self.assertFalse(e.exception.retry)
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertFalse(ctx.cli.runs())

    def test_empty_and_factory_refused(self):
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), {'mode': 'replace', 'replace_via': 'ssh', 'replace_name': ' '})
        self.assertIn('no certificate on the FortiGate is chosen', str(e.exception))
        with self.assertRaises(PluginError) as e:
            t.deploy(Bundle(), {'mode': 'replace', 'replace_via': 'ssh', 'replace_name': 'Fortinet_SSL'})
        self.assertIn('Fortinet factory certificate', str(e.exception))
        self.fg.add('mine', PEMS['other'], source='factory')
        with self.assertRaises(PluginError):
            t.deploy(Bundle(), {'mode': 'replace', 'replace_via': 'ssh', 'replace_name': 'mine'})
        self.assertFalse([c for c in self.fg.calls if c['method'] != 'GET'])
        self.assertFalse(ctx.cli.runs())

    def test_hand_typed_name(self):
        """A name typed (discovery never asked) with characters a URL quotes."""
        self.fg.add('VPN cert/2026 #1', PEMS['other'], q_ref=1)
        t, ctx = make(self.fg)
        b = Bundle()
        t.deploy(b, {'mode': 'replace', 'replace_via': 'ssh', 'replace_name': 'VPN cert/2026 #1'})
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
        t.deploy(b, {'mode': 'replace', 'replace_via': 'ssh', 'replace_name': replaced, 'keep': 0})
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
        self.assertNotEqual(t.state_key({'keep': 1}), t.state_key(dict(SSHR, keep=1)))


# ---------------------------------------------------------------------------
class SshDuplicateTest(Base):
    """FortiOS refuses a local certificate identical to another ("This local certificate is
    duplicated") - the very failure on 7.4.13: the same certificate imported an hour before
    by a deployment in the new mode."""
    def copy(self, b, name=None, q_ref=0):
        name = name or C.name_prefix(b, {}, maxlen=35, serial_len=6) + '20261118-191aae'
        self.fg.add(name, b.cert_pem, q_ref=q_ref)
        return name

    def test_unused_acme_copy_deleted_first(self):
        b = Bundle()
        n = self.copy(b)
        t, ctx = make(self.fg)
        got = t.deploy(b, dict(SSHR))
        self.assertIn('web-cert replaced in place', got)
        self.assertNotIn(n, self.fg.local)
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(b.cert_pem))
        dels = self.fg.find('DELETE', r'/vpn\.certificate/local/')
        self.assertEqual([c['path'].rsplit('/', 1)[-1] for c in dels], [n])
        words = said(ctx)
        self.assertIn('%s is this very certificate already - a copy acme imported earlier; '
                      'it is deleted first (FortiOS refuses two identical local '
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
            t.deploy(b, dict(SSHR))
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
        """A copy in use: FortiOS refuses its DELETE (-23) - nothing else is changed."""
        b = Bundle()
        n = self.copy(b, q_ref=2)
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(SSHR))
        words = str(e.exception)
        self.assertIn('the FortiGate has this very certificate already as %s, an earlier '
                      'import of acme that is in use - FortiOS refused to delete it (-23, '
                      '"currently being used")' % n, words)
        self.assertIn('Nothing else was changed: point what uses %s at web-cert' % n, words)
        self.assertFalse(e.exception.retry)
        self.assertIn(n, self.fg.local)
        self.assertEqual(self.fg.writes(), [('DELETE', '/api/v2/cmdb/vpn.certificate/local/'
                                             + n)])
        self.assertFalse([r for r in ctx.cli.runs() if 'config vpn certificate local' in r])
        self.assertEqual(der(self.fg.local['web-cert']['certificate']), der(PEMS['old']))

    def test_copy_not_acmes_fails_before_anything(self):
        b = Bundle()
        n = self.copy(b, name='my-own-copy')
        t, ctx = make(self.fg)
        with self.assertRaises(PluginError) as e:
            t.deploy(b, dict(SSHR))
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

    def test_minus_328_is_there_already(self):
        """-328: the CA is there already (measured on 7.6.8) - no longer looked up in the CA
        list, never said as a failure; another refusal is said."""
        b = Bundle()
        t, ctx = make(self.fg)
        orig = self.fg.answer

        def answer(m, path, q, body):
            if path.endswith('/ca/import'):
                return self.fg.err(500, -328)     # (the CA list does not have it)
            return orig(m, path, q, body)
        self.fg.answer = answer
        t.deploy(b, {'keep': 1})
        self.assertFalse([w for w in said(ctx) if 'not imported' in w])
        self.assertIn('the intermediate CA certificate is on the FortiGate already', said(ctx))
        self.assertFalse(self.fg.find('GET', r'/cmdb/vpn\.certificate/ca'))
        self.fg.answer = orig
        self.fg.ca_error = -5
        for n in [n for n in self.fg.local if n.startswith('acme-')]:
            del self.fg.local[n]
        t, ctx = make(self.fg)
        t.deploy(b, {'keep': 1})
        self.assertTrue([w for w in said(ctx) if w.startswith(
            'the CA certificate is not imported: importing a CA certificate: the device said '
            '500')], said(ctx))

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
        """The REST API (the default): read, fingerprints, the CA before, no copy, PUT, read
        back - no SSH even when the target has its sign-in."""
        for ver in ('', '6.0', '7.0', '7.4.2'):
            r = self.record(ver, dict(REPLACE))
            self.assertFalse(r.get('error'), r.get('error'))
            evs = r['events']
            says = [e.get('words') for e in evs if e['kind'] in ('say', 'step')]
            self.assertTrue([w for w in says if w.startswith(
                'replacing the certificate web-cert in place: the same name, everything that '
                'uses it keeps using it (now www.example.com, valid to ')], says)
            self.assertIn('it is replaced over the REST API (PUT cmdb vpn.certificate/local/'
                          'web-cert) - the token is enough, no SSH', says)
            self.assertIn('the fingerprints of the certificates on the FortiGate read '
                          '(monitor/system/available-certificates): 4 local, 1 CA', says)
            self.assertTrue([w for w in says if w.startswith(
                'imported the intermediate CA certificate ') and w.endswith(
                ' before the replace - FortiOS sends it along with the certificate')], says)
            self.assertIn('no other local certificate on the FortiGate is this one (FortiOS '
                          'refuses a duplicate)', says)
            self.assertIn('the new certificate (the leaf - FortiOS keeps the leaf only, the '
                          'chain comes from its CA certificates) and its key, encrypted with a '
                          'one-time password, put into web-cert', says)
            self.assertIn('FortiOS took the new certificate and key for web-cert', says)
            self.assertTrue([w for w in says if w.startswith(
                'checked: web-cert holds the new certificate now (SHA-256 ')], says)
            self.assertIn('web-cert replaced in place - its name and every use of it kept',
                          says)
            self.assertFalse([w for w in says if 'used 3 times before' in w], says)
            http = [(e['method'], e['url'].split('?')[0]) for e in evs if e['kind'] == 'http']
            base = 'https://fw/api/v2/'
            seq = [h for h in http if 'vpn.certificate/local/web-cert' in h[1] or
                   'available-certificates' in h[1] or 'ca/import' in h[1]]
            self.assertEqual(seq, [
                ('GET', base + 'cmdb/vpn.certificate/local/web-cert'),
                ('GET', base + 'monitor/system/available-certificates'),
                ('POST', base + 'monitor/vpn-certificate/ca/import'),
                ('PUT', base + 'cmdb/vpn.certificate/local/web-cert'),
                ('GET', base + 'cmdb/vpn.certificate/local/web-cert'),
                ('GET', base + 'monitor/system/available-certificates')])
            self.assertNotIn(('POST', base + 'monitor/vpn-certificate/local/import'), http)
            self.assertFalse([h for h in http if h[0] == 'DELETE' and 'web-cert' in h[1]])
            self.assertFalse([e for e in evs if e['kind'].startswith('ssh')])
            dump = json.dumps(evs)
            self.assertNotIn('SSH-pw-0002', dump)
            self.assertNotIn('PRIVATE KEY-----\\n', dump.replace('ENCRYPTED PRIVATE KEY', ''))

    def test_over_ssh(self):
        for ver in ('', '7.4.2'):
            r = self.record(ver, dict(SSHR))
            self.assertFalse(r.get('error'), r.get('error'))
            evs = r['events']
            says = [e.get('words') for e in evs if e['kind'] in ('say', 'step')]
            self.assertIn('no other local certificate on the FortiGate is this one (FortiOS '
                          'refuses a duplicate)', says)
            self.assertIn('signed in over SSH as acme-admin: FortiOS 7.4.5 on fw01, VDOMs off - '
                          'the certificate is replaced in the FortiOS CLI', says)
            self.assertTrue([w for w in says if w.startswith(
                'checked: web-cert holds the new certificate now (SHA-256 ')], says)
            self.assertIn('web-cert replaced in place - its name and every use of it kept',
                          says)
            http = [(e['method'], e['url'].split('?')[0]) for e in evs if e['kind'] == 'http']
            self.assertFalse([h for h in http if h[0] == 'PUT' and 'vpn.certificate' in h[1]],
                             'never the REST PUT')
            opens = [e for e in evs if e['kind'] == 'ssh-open']
            self.assertEqual((opens[0]['host'], opens[0]['port'], opens[0]['user']),
                             ('fw', 22, 'acme-admin'))
            runs = [e for e in evs if e['kind'] == 'ssh-run']
            self.assertEqual(len(runs), 4, [e.get('input') for e in runs])
            self.assertTrue(all(e['input']['secret'] for e in runs[1:3]))
            self.assertNotIn('SSH-pw-0002', json.dumps(evs))

    def test_no_ssh_needed_or_said(self):
        r = self.record('', dict(REPLACE), ssh=False)
        self.assertFalse(r.get('error'), r.get('error'))
        self.assertFalse([e for e in r['events'] if e['kind'].startswith('ssh')])
        r = self.record('', dict(SSHR), ssh=False)
        self.assertIn('replace in place over SSH ("How to replace": SSH) and the target has no '
                      'SSH sign-in', r.get('error') or '')
        self.assertFalse([e for e in r['events'] if e['kind'].startswith('ssh')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
