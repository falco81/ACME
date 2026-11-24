#!/usr/bin/env python3
"""Hunt w8 (winkube): the Windows agent's IIS bindings and the Kubernetes agent.

    python3 test/test_hunt_rw8_winkube.py

* an https binding the agent MADE on an address and port whose certificate http.sys held
  already (a binding of another site there without SNI, or one left behind): that certificate is
  said as the old one (replaced, not "AddSslCertificate failed"), and an undo puts it back -
  it was taken away, and another site's https with it;
* two bindings of one site, host and port on two addresses: each compared on its own address
  (the second was taken as the first's and the deployment said "unchanged");
* Kubernetes: the RBAC of the manifests only what the agent does (no patch of Secrets, no get of
  Deployments), the Service keeps acme's own address (externalTrafficPolicy: Local), the TLS
  Secrets of a namespace listed in pages (limit/continue).

No Windows binary and no wine: PowerShell is faked (wincert.powershell), its scripts read.
"""
import base64
import http.server
import importlib.util
import json
import os
import re
import sys
import tempfile
import threading
import types
import unittest
try:
    import tmpclean  # noqa: F401
except ImportError:
    from test import tmpclean  # noqa: F401

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT_DIR = os.path.join(ROOT, 'deploy', 'agent')
K8S_DIR = os.path.join(AGENT_DIR, 'k8s')
TMP = tempfile.mkdtemp(prefix='acme-rw8-')


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


W = _load('acme_agent_wincert_rw8', os.path.join(AGENT_DIR, 'acme_agent_wincert.py'))


class Refused(Exception):
    def __init__(self, words, needs=None):
        Exception.__init__(self, words)
        self.needs = needs or []


def stub_agent():
    rs = os.path.join(TMP, 'rs')
    os.makedirs(rs, exist_ok=True)
    return types.SimpleNamespace(
        WINDOWS=True, ROOT_STATE=rs, Refused=Refused,
        _unb64=lambda v, _d, _w: base64.b64decode(v))


class Dep(object):
    agent_id = 'ag-rw8'
    key_from = None

    def __init__(self):
        self.steps = []

    def step(self, words, level='info'):
        self.steps.append((level, words))


THUMB = 'A' * 40
OTHER = 'B' * 40          # what http.sys held for 0.0.0.0:443 (another site's binding there)


class FakePS(object):
    """state / import / bind / unbind as the scripts answer them."""

    def __init__(self, state, bind_said, bind_ok=False):
        self.state, self.bind_said, self.bind_ok = state, bind_said, bind_ok
        self.calls = []

    def __call__(self, script, env, timeout=300):
        with open(env['ACME_WIN_IN']) as fh:
            j = json.load(fh)
        name = {W.PS_STATE: 'state', W.PS_IMPORT: 'import', W.PS_BIND: 'bind',
                W.PS_UNBIND: 'unbind', W.PS_REMOVE: 'remove'}[script]
        self.calls.append((name, j))
        if name == 'state':
            return 0, 'ACME ' + json.dumps(self.state)
        if name == 'import':
            return 0, 'ACME ' + json.dumps({'imported': False, 'thumb': j['thumb']})
        if name == 'bind':
            out = ['ACME ' + json.dumps(o) for o in self.bind_said]
            if self.bind_ok:
                return 0, '\n'.join(out)
            return 1, '\n'.join(out + ['ACME-ERROR Cannot create a file when that file '
                                       'already exists'])
        return 0, ''


def win(iis):
    return {'store': {'thumb': THUMB, 'from': 'stage', 'file': {'data': base64.b64encode(
        b'pfx').decode()}, 'friendly': 'x', 'exportable': False, 'keep': 1, 'slot': 'd-1',
        'cert_pem': ''}, 'iis': iis, 'rdp': False}


class IisCreatedBinding(unittest.TestCase):
    def test_script_reads_and_puts_back_the_endpoint_certificate(self):
        bind = W.PS_BIND
        made = bind.index('New-WebBinding')
        branch = bind[made:bind.index('} else {', made)]
        # after the binding is made: what http.sys holds for it is the old one
        self.assertRegex(branch, r'\$created = \$true[\s\S]*\$old = \[string\]\$b\.certificateHash')
        # ...so AddSslCertificate refused on it (error 183) is answered by replacing it
        self.assertIn("catch { if ($old) { $b.RemoveSslCertificate(); $b.AddSslCertificate("
                      "$thumb, 'My') } else { throw } }", bind)
        un = W.PS_UNBIND
        made = un.index('if ($w.created) {')
        branch = un[made:un.index('$b | Remove-WebBinding', made)]
        # undo of a made binding: its old certificate back, only none there is taken away
        self.assertIn("if (-not [string]$w.old) { try { $b.RemoveSslCertificate() } catch { } }",
                      branch)
        self.assertIn("$b.AddSslCertificate([string]$w.old, 'My')", branch)
        self.assertNotRegex(branch, r'^\s*try \{ \$b\.RemoveSslCertificate\(\) \} catch \{ \}\s*$')

    def test_undo_sends_the_old_certificate_of_a_made_binding(self):
        A = stub_agent()
        want = [{'site': 'Shop', 'host': '', 'port': 443, 'ip': '*'}]
        state = {'present': True, 'iis': [{'site': 'Shop', 'host': '', 'port': 443, 'ip': '*',
                                           'site_there': True, 'binding': False, 'thumb': ''}],
                 'rdp': ''}
        ps = FakePS(state, [{'step': 'iis', 'site': 'Shop', 'host': '', 'port': 443, 'ip': '*',
                             'old': OTHER.lower(), 'created': True}])
        old, W.powershell = W.powershell, ps
        try:
            job = W.WinJob(A, Dep(), win(want))
            with self.assertRaises(Refused):
                job._apply()
            job.undo()
        finally:
            W.powershell = old
        un = [j for n, j in ps.calls if n == 'unbind']
        self.assertEqual(len(un), 1)
        self.assertEqual(un[0]['iis'], [{'site': 'Shop', 'host': '', 'port': 443, 'ip': '*',
                                         'old': OTHER, 'created': True}])


class IisTwoAddresses(unittest.TestCase):
    def test_each_address_compared_on_its_own(self):
        A = stub_agent()
        want = [{'site': 'Shop', 'host': 'www.example.test', 'port': 443, 'ip': '192.0.2.5'},
                {'site': 'Shop', 'host': 'www.example.test', 'port': 443, 'ip': '192.0.2.6'}]
        state = {'present': True, 'rdp': '', 'iis': [
            dict(want[0], site_there=True, binding=True, thumb=THUMB),
            dict(want[1], site_there=True, binding=True, thumb=OTHER)]}
        ps = FakePS(state, [], bind_ok=True)
        old, W.powershell = W.powershell, ps
        try:
            job = W.WinJob(A, Dep(), win(want))
            self.assertFalse(job.same)              # 192.0.2.6 still has another one
            state['iis'][1]['thumb'] = THUMB
            self.assertTrue(W.WinJob(A, Dep(), win(want)).same)
            # the check says the same of each address
            state['iis'][1]['thumb'] = OTHER
            w = dict(win(want), store=dict(win(want)['store'], thumb=THUMB))
            said = [x['said'] for x in W.dry_check(A, w) if x['path'].startswith('IIS ')]
            self.assertEqual(said[0], 'uses this certificate already')
            self.assertIn('is replaced', said[1])
        finally:
            W.powershell = old


# ---- Kubernetes ----------------------------------------------------------------------------------
class Manifests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(K8S_DIR, 'manifests.yaml')) as fh:
            cls.text = fh.read()

    def docs(self, kind):
        return [d for d in self.text.split('\n---') if re.search(r'^kind: %s$' % kind, d, re.M)]

    def test_rbac_only_what_the_agent_does(self):
        roles = self.docs('Role')
        self.assertTrue(roles)
        for r in roles:
            for rule in r.split('  - apiGroups:')[1:]:
                verbs = re.search(r'verbs: \[([^\]]*)\]', rule).group(1)
                verbs = [v.strip().strip('"') for v in verbs.split(',')]
                if 'secrets' in rule:
                    # GET, PUT (update, with the resourceVersion read), POST, DELETE, a list
                    self.assertNotIn('patch', verbs, rule)
                    self.assertLessEqual(set(verbs), {'get', 'list', 'create', 'update',
                                                      'delete'}, rule)
                if 'deployments' in rule:
                    self.assertEqual(verbs, ['patch'], rule)          # the restart's PATCH only
        # the agent's code: exactly these calls
        with open(os.path.join(K8S_DIR, 'acme_k8s_agent.py')) as fh:
            src = fh.read()
        self.assertEqual(sorted(set(re.findall(r"self\.req\('([A-Z]+)', '/api", src))),
                         ['DELETE', 'GET', 'PATCH', 'POST', 'PUT'])
        self.assertNotIn("req('PATCH', '/api/v1", src)
        self.assertNotIn("req('GET', '/apis/apps", src)

    def test_service_keeps_acmes_address(self):
        svc = self.docs('Service')
        self.assertEqual(len(svc), 1)
        self.assertIn('type: LoadBalancer', svc[0])
        self.assertIn('externalTrafficPolicy: Local', svc[0])


class Pages(object):
    """An API server answering the list of TLS Secrets in pages of `limit`."""

    def __init__(self, n):
        self.items = [{'type': 'kubernetes.io/tls', 'metadata': {'name': 's%03d' % i},
                       'data': {}} for i in range(n)]
        self.asked = []
        me = self

        class Hd(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                from urllib.parse import urlsplit, parse_qs
                u = urlsplit(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                me.asked.append(q)
                lim = int(q.get('limit') or 10 ** 6)
                at = int(q.get('continue') or 0)
                body = {'items': me.items[at:at + lim], 'metadata': {}}
                if at + lim < len(me.items):
                    body['metadata']['continue'] = str(at + lim)
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Hd)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


class SecretsInPages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = os.path.join(TMP, 'k8s')
        keep = dict(os.environ)
        os.environ.update(ACME_K8S_STATE=os.path.join(d, 'state'),
                          ACME_K8S_RUN=os.path.join(d, 'run'),
                          ACME_K8S_POLICY=os.path.join(d, 'policy'))
        for k in ('ACME_AGENT_ETC', 'ACME_AGENT_STATE', 'ACME_AGENT_ROOT_STATE',
                  'ACME_AGENT_RUN'):
            os.environ.pop(k, None)
        try:
            cls.m = _load('acme_k8s_agent_rw8', os.path.join(K8S_DIR, 'acme_k8s_agent.py'))
        finally:
            os.environ.clear()
            os.environ.update(keep)

    def test_every_page_read(self):
        srv = Pages(120)
        try:
            k = self.m.Kube()
            k.base = 'http://127.0.0.1:%d' % srv.srv.server_address[1]
            k.token_file = os.path.join(TMP, 'no-token')
            got = k.secrets_tls('intranet')
            self.assertEqual([s['metadata']['name'] for s in got],
                             ['s%03d' % i for i in range(120)])
            self.assertEqual(len(srv.asked), 3)               # 50 + 50 + 20
            for q in srv.asked:
                self.assertEqual(q['fieldSelector'], 'type=kubernetes.io/tls')
                self.assertEqual(q['limit'], str(self.m.LIST_PAGE))
            self.assertNotIn('continue', srv.asked[0])
            # never more than discovery tells
            del srv.asked[:]
            self.assertEqual(len(k.secrets_tls('intranet', most=60)), 60)
            self.assertEqual(len(srv.asked), 2)
        finally:
            srv.stop()


if __name__ == '__main__':
    unittest.main(verbosity=2)
