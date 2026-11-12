#!/usr/bin/env python3
"""A server that sends its certificate without the intermediate authority (1.0.88).

Browsers fetch the missing intermediate from the certificate's AIA (caIssuers) address;
acme did not and said "unable to get local issuer certificate" (isemon behind a RapidSSL
certificate, paired from acme). Now acme fetches it too - but trusts it only as a link to a
root of the system: an intermediate that leads to no trusted root is still refused.

    python3 test/test_aia_fetch.py
"""
import http.server
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-aia-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import runtime  # noqa: E402
from acmelib.plugins import base  # noqa: E402


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=TMP)


def make_pki(tag, aia_port):
    """root -> intermediate -> leaf for 127.0.0.1, the leaf's AIA naming the intermediate."""
    d = os.path.join(TMP, tag)
    os.makedirs(d)
    j = lambda n: os.path.join(d, n)                    # noqa: E731
    sh('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-nodes', '-keyout', j('root.key'), '-out', j('root.pem'), '-days', '30',
       '-subj', '/CN=AIA Root %s' % tag,
       '-addext', 'basicConstraints=critical,CA:true', '-addext', 'keyUsage=keyCertSign,cRLSign')
    with open(j('ca.ext'), 'w') as f:
        f.write('basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=keyCertSign,cRLSign\n'
                'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
    sh('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-nodes', '-keyout', j('int.key'), '-out', j('int.csr'), '-subj', '/CN=AIA Issuing %s' % tag)
    sh('openssl', 'x509', '-req', '-in', j('int.csr'), '-CA', j('root.pem'), '-CAkey',
       j('root.key'), '-CAcreateserial', '-out', j('int.pem'), '-days', '30', '-extfile', j('ca.ext'))
    with open(j('leaf.ext'), 'w') as f:
        f.write('basicConstraints=CA:false\nsubjectAltName=IP:127.0.0.1\n'
                'extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n'
                'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n'
                'authorityInfoAccess=caIssuers;URI:http://127.0.0.1:%d/%s.crt\n' % (aia_port, tag))
    sh('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-nodes', '-keyout', j('leaf.key'), '-out', j('leaf.csr'), '-subj', '/CN=127.0.0.1')
    sh('openssl', 'x509', '-req', '-in', j('leaf.csr'), '-CA', j('int.pem'), '-CAkey',
       j('int.key'), '-CAcreateserial', '-out', j('leaf.pem'), '-days', '20', '-extfile', j('leaf.ext'))
    sh('openssl', 'x509', '-in', j('int.pem'), '-outform', 'DER', '-out',
       os.path.join(TMP, 'aia', '%s.crt' % tag))
    return d


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == '/hello':
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def serve(handler, ctx=None):
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    srv.handle_error = lambda *a: None          # a peek at the certificate hangs up early
    if ctx is not None:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class AiaFetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.makedirs(os.path.join(TMP, 'aia'))
        aia_dir = os.path.join(TMP, 'aia')
        cls.aia = serve(lambda *a, **k: Quiet(*a, directory=aia_dir, **k))
        port = cls.aia.server_address[1]
        cls.good = make_pki('good', port)       # its root trusted below
        cls.bad = make_pki('bad', port)         # its root nowhere
        # the "system" roots: the good root only
        os.environ['SSL_CERT_FILE'] = os.path.join(cls.good, 'root.pem')
        cls.servers = {}
        for tag, d in (('good', cls.good), ('bad', cls.bad)):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(os.path.join(d, 'leaf.pem'), os.path.join(d, 'leaf.key'))
            cls.servers[tag] = serve(Quiet, ctx)          # the leaf alone, no intermediate
        cls.store = E.Storage(E.open_db())

    @classmethod
    def tearDownClass(cls):
        for s in list(cls.servers.values()) + [cls.aia]:
            s.shutdown()
        shutil.rmtree(TMP, ignore_errors=True)

    def ctx(self):
        c = runtime.RunContext(self.store, None, scope='target:aia')
        c.said = []
        c.step = lambda m, lvl='info': c.said.append((m, lvl))
        return c

    def url(self, tag):
        return 'https://127.0.0.1:%d/hello' % self.servers[tag].server_address[1]

    def test_1_the_missing_intermediate_fetched(self):
        c = self.ctx()
        st, _h, body = c.http('GET', self.url('good'), proxy=False)
        self.assertEqual(st, 200)
        self.assertIn(b'"ok"', body)
        warned = [m for m, lvl in c.said if lvl == 'warn']
        self.assertTrue(any('does not send the intermediate' in m and 'AIA Issuing good' in m
                            for m in warned), c.said)

    def test_2_not_a_way_around_the_roots(self):
        with self.assertRaises(base.PluginError) as e:
            self.ctx().http('GET', self.url('bad'), proxy=False)
        self.assertIn('CERTIFICATE_VERIFY_FAILED', str(e.exception))

    def test_3_not_when_not_checked_or_own_ca(self):
        st, _h, _b = self.ctx().http('GET', self.url('bad'), verify=False, proxy=False)
        self.assertEqual(st, 200)
        with open(os.path.join(self.bad, 'root.pem')) as f:
            root = f.read()
        with self.assertRaises(base.PluginError):       # own CA given: used as it is
            self.ctx().http('GET', self.url('good'), ca_pem=root, proxy=False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
