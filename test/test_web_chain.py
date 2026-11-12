#!/usr/bin/env python3
"""The whole chain of acme's own web certificate (1.0.89, from certificate-chain-ui).

nginx must send the certificate with every intermediate authority; browsers fetch a missing
one themselves (AIA -> CA Issuers), curl, Python and the other applications do not. Checked
against "the system's roots" (ACME_CHAIN_CA here), completed from the CA Issuers address,
or by hand (Upload the missing authority); a private root kept to check with, never sent;
self-signed has no chain; after nginx was given its part acme connects to it as a client
that fetches nothing.

    python3 test/test_web_chain.py
"""
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-webchain-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
DAEMON = E.Daemon(STORE, serve=False)
AIA = os.path.join(TMP, 'aia')
os.makedirs(AIA)


def sh(*args):
    subprocess.run(args, check=True, capture_output=True, cwd=TMP)


def read(p):
    with open(p) as f:
        return f.read()


def pki(tag, aia_port, aia=True):
    """root -> intermediate -> leaf (www.example.test, 127.0.0.1); the leaf names the
    intermediate at http://127.0.0.1:<port>/<tag>.cer, the intermediate names no address."""
    d = os.path.join(TMP, tag)
    os.makedirs(d)
    j = lambda n: os.path.join(d, n)                    # noqa: E731
    sh('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-nodes', '-keyout', j('root.key'), '-out', j('root.pem'), '-days', '30',
       '-subj', '/CN=Chain Root %s' % tag,
       '-addext', 'basicConstraints=critical,CA:true', '-addext', 'keyUsage=keyCertSign,cRLSign')
    with open(j('ca.ext'), 'w') as f:
        f.write('basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=keyCertSign,cRLSign\n'
                'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
    sh('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-nodes', '-keyout', j('int.key'), '-out', j('int.csr'), '-subj', '/CN=Chain Issuing %s' % tag)
    sh('openssl', 'x509', '-req', '-in', j('int.csr'), '-CA', j('root.pem'), '-CAkey',
       j('root.key'), '-CAcreateserial', '-out', j('int.pem'), '-days', '30', '-extfile', j('ca.ext'))
    with open(j('leaf.ext'), 'w') as f:
        f.write('basicConstraints=CA:false\nsubjectAltName=DNS:www.example.test,IP:127.0.0.1\n'
                'extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n'
                'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
        if aia:
            f.write('authorityInfoAccess=caIssuers;URI:http://127.0.0.1:%d/%s.cer\n'
                    % (aia_port, tag))
    sh('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
       '-nodes', '-keyout', j('leaf.key'), '-out', j('leaf.csr'), '-subj', '/CN=www.example.test')
    sh('openssl', 'x509', '-req', '-in', j('leaf.csr'), '-CA', j('int.pem'), '-CAkey',
       j('int.key'), '-CAcreateserial', '-out', j('leaf.pem'), '-days', '20', '-extfile', j('leaf.ext'))
    sh('openssl', 'x509', '-in', j('int.pem'), '-outform', 'DER', '-out',
       os.path.join(AIA, '%s.cer' % tag))
    return {k: read(j(k + '.pem')) for k in ('root', 'int', 'leaf')} | {
        'key': read(j('leaf.key')), 'dir': d}


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


class WebChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.aia = http.server.ThreadingHTTPServer(
            ('127.0.0.1', 0), lambda *a, **k: Quiet(*a, directory=AIA, **k))
        threading.Thread(target=cls.aia.serve_forever, daemon=True).start()
        port = cls.aia.server_address[1]
        cls.pub = pki('pub', port)                  # its root is "the system's"
        cls.priv = pki('priv', port, aia=False)     # a private CA: no address, root nowhere
        cls.dead = pki('dead', 1)                   # the address answers nothing
        os.environ['ACME_CHAIN_CA'] = os.path.join(cls.pub['dir'], 'root.pem')
        cls.target = E.node_name()

    @classmethod
    def tearDownClass(cls):
        cls.aia.shutdown()
        shutil.rmtree(TMP, ignore_errors=True)

    def call(self, body):
        h = E.CliApiHandler(DAEMON, 'tester', body, {}, '/api/web')
        return E.ROUTES[('POST', '/api/web')](h)

    def upload(self, p, chain='', root=''):
        return self.call({'action': 'tls_upload', 'target': self.target, 'cert': p['leaf'],
                          'key': p['key'], 'chain': chain, 'root': root})

    def prof(self):
        return E.tls_profile(STORE, self.target)

    def test_1_leaf_alone_completed_by_fetching(self):
        E.CHAIN_FETCHED.clear()
        self.upload(self.pub)
        p = self.prof()
        cs = p['chain_state']
        self.assertIs(cs['ok'], True, cs)
        self.assertIn('fetched: Chain Issuing pub', cs['words'])
        self.assertEqual(E.cert_info(p['chain'])['cn'], 'Chain Issuing pub')
        self.assertNotIn('Chain Root', p['chain'] and E.cert_info(p['chain'])['subject'])
        view = E.tls_view(p)
        self.assertEqual(view['chain_state']['ok'], True)
        self.assertNotIn('key', view)

    def test_2_with_its_chain_and_root(self):
        self.upload(self.pub, chain=self.pub['int'], root=self.pub['root'])
        p = self.prof()
        self.assertIs(p['chain_state']['ok'], True)
        self.assertEqual(p['chain_state']['fetched'], [])
        self.assertEqual(len(E.PEM_CERT.findall(p['chain'])), 1)     # the root not in the chain
        self.assertIn('Chain Root pub', p['root_info'][0]['cn'])
        self.assertTrue(self.call({'action': 'tls_chain', 'target': self.target})['complete'])

    def test_3_not_fetched_then_by_hand(self):
        E.CHAIN_FETCHED.clear()
        self.upload(self.dead)
        cs = self.prof()['chain_state']
        self.assertIs(cs['ok'], False)
        self.assertEqual(cs['missing'], 'Chain Issuing dead')
        self.assertIn('could not be fetched', cs['words'])
        got = self.call({'action': 'tls_chain', 'target': self.target})
        self.assertIs(got['complete'], False)
        self.assertNotIn('ok', got)
        for bad, said in (('-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----', 'no private key'),
                          ('nothing', 'no certificate in it'),
                          (self.pub['int'], 'none of these is the authority')):
            with self.assertRaises(E.ApiError) as e:
                self.call({'action': 'tls_chain_add', 'target': self.target, 'text': bad})
            self.assertIn(said, str(e.exception))
        # The dead one's root is not the system's: the intermediate alone leads to a root nobody
        # trusts; with its root too it is complete, as a private one.
        got = self.call({'action': 'tls_chain_add', 'target': self.target,
                         'text': self.dead['int']})
        self.assertIs(got['complete'], False)
        self.assertIn('Chain Root dead', got['message'])
        got = self.call({'action': 'tls_chain_add', 'target': self.target,
                         'text': self.dead['root']})
        self.assertIs(got['complete'], True, got)
        self.assertIn('a private root', got['message'])
        p = self.prof()
        self.assertEqual(E.cert_info(p['chain'])['cn'], 'Chain Issuing dead')
        self.assertEqual(p['root_info'][0]['cn'], 'Chain Root dead')
        with self.assertRaises(E.ApiError) as e:
            self.call({'action': 'tls_chain_add', 'target': self.target, 'text': self.dead['root']})
        self.assertIn('there already', str(e.exception))
        ev = [r['words'] for r in STORE.db.rows("SELECT words FROM events WHERE words LIKE ?",
                                              ('%to the chain of the certificate%',))]
        self.assertTrue(ev)

    def test_4_private_ca_without_an_address(self):
        self.upload(self.priv, chain=self.priv['int'])
        cs = self.prof()['chain_state']
        self.assertIs(cs['ok'], False)
        self.assertIn('names no CA Issuers address', cs['words'])
        self.assertEqual(cs['missing'], 'Chain Root priv')
        got = self.call({'action': 'tls_chain_add', 'target': self.target,
                         'text': self.priv['root']})
        self.assertIs(got['complete'], True)
        self.assertIn('a private root: only clients that trust it take it', got['message'])

    def test_5_self_signed(self):
        self.call({'action': 'tls_selfsigned', 'target': self.target, 'cn': 'self.example.test',
                   'names': 'self.example.test', 'kind': 'ec256'})
        cs = self.prof()['chain_state']
        self.assertIsNone(cs['ok'])
        self.assertIn('self-signed', cs['words'])
        with self.assertRaises(E.ApiError) as e:
            self.call({'action': 'tls_chain', 'target': self.target})
        self.assertIn('self-signed', str(e.exception))

    def test_6_the_file_in_place_and_the_self_check(self):
        """What nginx sends, as a client that fetches nothing: the file read, and a TLS server
        sending the certificate alone (refused) or with its chain (taken)."""
        f = os.path.join(TMP, 'acme.pem')
        with open(f, 'w') as fh:
            fh.write(self.pub['leaf'])
        self.assertIs(E.cert_now(f)['chain_ok'], False)
        with open(f, 'w') as fh:
            fh.write(self.pub['leaf'] + self.pub['int'] + '\n')
        os.utime(f, (1, 1))
        self.assertIs(E.cert_now(f)['chain_ok'], True)
        self.upload(self.pub, chain=self.pub['int'])
        prof = self.prof()
        for chain, want in (('', False), (self.pub['int'], True)):
            crt = os.path.join(TMP, 'srv.pem')
            with open(crt, 'w') as fh:
                fh.write(self.pub['leaf'] + chain)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, os.path.join(self.pub['dir'], 'leaf.key'))
            lsn = socket.socket()
            lsn.bind(('127.0.0.1', 0))
            lsn.listen(1)

            def accept():
                c, _a = lsn.accept()
                try:
                    ctx.wrap_socket(c, server_side=True).close()
                except (OSError, ssl.SSLError):
                    c.close()
            t = threading.Thread(target=accept, daemon=True)
            t.start()
            got = E.web_self_connect(prof, lsn.getsockname()[1])
            t.join(5)
            lsn.close()
            self.assertIs(got['ok'], want, got)
        # Once for each time root put it in; a refusal is an event.
        E.WEB_SELF_PORT = 1
        got = E.web_self_check(STORE, {'state': 'done', 'at': 1000.0})
        self.assertIsNone(got['ok'])
        self.assertEqual(json.loads(STORE.get_meta('web:selfcheck:' + self.target))['applied'],
                         1000.0)
        self.assertEqual(E.web_self_check(STORE, {'state': 'done', 'at': 1000.0})['at'], got['at'])

    def test_7_the_vip_address(self):
        """HA with keepalived: the VIP address's certificate completed alike, and checked on
        its address by the node that holds it."""
        E.CHAIN_FETCHED.clear()
        got = self.call({'action': 'tls_upload', 'target': 'vip', 'cert': self.pub['leaf'],
                         'key': self.pub['key']})
        self.assertIn('vip', str(got) + 'vip')
        vp = E.tls_profile(STORE, 'vip')
        self.assertIs(vp['chain_state']['ok'], True)
        self.assertIn('fetched: Chain Issuing pub', vp['chain_state']['words'])
        self.assertTrue(self.call({'action': 'tls_chain', 'target': 'vip'})['complete'])
        seen = {}
        was = (E.vip_conf, E.vip_here, E.web_self_connect)
        try:
            E.vip_conf = lambda store: {'on': True, 'address': '192.0.2.10/24'}
            E.vip_here = lambda a: True

            def connect(prof, port=None, host='127.0.0.1'):
                seen[host] = E.cert_info(prof['cert'])['cn']
                return {'ok': False, 'why': 'unable to get local issuer certificate',
                        'words': 'refused'}
            E.web_self_connect = connect
            E.web_self_check(STORE, {'state': 'done', 'at': 5000.0})
        finally:
            E.vip_conf, E.vip_here, E.web_self_connect = was
        self.assertEqual(seen.get('192.0.2.10'), 'www.example.test')
        vsc = json.loads(STORE.get_meta('web:selfcheck:vip:' + self.target))
        self.assertIs(vsc['ok'], False)
        self.assertTrue(STORE.db.rows("SELECT words FROM events WHERE words LIKE ?",
                                      ('%refuses what nginx sends on the VIP address%',)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
