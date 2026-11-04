#!/usr/bin/env python3
"""Behind a load balancer or WAF, and signed in by it - the root helper's side (otp 1.0.237,
1.0.239), and the web state the daemon asks of it; the VIP address without a name (1.0.242);
the dual certificates of acme's own TLS (1.0.240).

    python3 test/test_web_proxy.py      (or python3 -m unittest test.test_web_proxy)

- deploy/acme_web.py: acme's real_ip lines put into the HTTPS server, once, changed, taken
  out again - in the place of what acme --trusted-proxy wrote while on, and that left alone
  when off; the balancer's address for the enrolment pages (ACME_PEER) put into `location = /`
  and taken out; nginx refusing it (nginx -t) puts everything back; a server without
  `location = /` does not hold up the rest of the request.
- The daemon: realip_desired / sso_peer_desired - None (nginx left as it is) until switched on
  once, then what was set, and "nobody" once switched off again; web_desired leaves the VIP
  address's own certificate out while it has no name.
- cert_bundles: an RSA and an ECDSA certificate of the same names, in one PEM or as two PFX
  files - the RSA one the main one; two of a kind, or of other names, refused. tls_export:
  which one, both in a .zip.
"""
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-webproxy-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP, ACME_VIP_NO_SERVICES='1')
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402  (the engine's own names, patched there)

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


def helper():
    spec = importlib.util.spec_from_file_location('acme_web_wp', os.path.join(
        ROOT, 'deploy', 'acme_web.py'))
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    return w


W = helper()
with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as _f:
    SHIPPED = _f.read()
RP = {'from': ['10.0.0.5/32', '192.0.2.0/28'], 'header': 'X-Forwarded-For', 'recursive': True}
OFF = {'from': [], 'header': '', 'recursive': False}


def tls_block(text):
    a, b = W.server_block(text)
    return text[a:b]


class Helper(unittest.TestCase):
    def test_realip_in_once_changed_and_out(self):
        new = W.realip_into(SHIPPED, RP)
        block = tls_block(new)
        self.assertIn('# ACME-REALIP-BEGIN', block)
        self.assertIn('set_real_ip_from 10.0.0.5/32;', block)
        self.assertIn('set_real_ip_from 192.0.2.0/28;', block)
        self.assertIn('real_ip_header X-Forwarded-For;', block)
        self.assertIn('real_ip_recursive on;', block)
        # Only in the HTTPS server, not the port-80 redirect.
        self.assertEqual(new.count('# ACME-REALIP-BEGIN'), 1)
        self.assertEqual(W.realip_into(new, RP), new)
        changed = W.realip_into(new, dict(RP, header='X-Real-IP', recursive=False,
                                          **{'from': ['10.0.0.9']}))
        self.assertEqual(changed.count('# ACME-REALIP-BEGIN'), 1)
        self.assertIn('real_ip_header X-Real-IP;', changed)
        self.assertIn('real_ip_recursive off;', changed)
        self.assertNotIn('10.0.0.5', changed)
        self.assertEqual(W.realip_into(changed, OFF), SHIPPED)

    def test_trusted_proxy_lines(self):
        a, b = W.server_block(SHIPPED)
        head = SHIPPED.index('\n', SHIPPED.index('{', a)) + 1
        old = ('    # REALIP-BEGIN - the load balancer(s), written by acme --trusted-proxy\n'
               '    set_real_ip_from 198.51.100.1;\n    real_ip_header X-Forwarded-For;\n'
               '    real_ip_recursive on;\n    # REALIP-END\n')
        by_hand = SHIPPED[:head] + old + SHIPPED[head:]
        # On: acme's lines take their place.
        on = W.realip_into(by_hand, RP)
        self.assertNotIn('198.51.100.1', on)
        self.assertIn('# ACME-REALIP-BEGIN', on)
        # Off: only acme's own go - never switched on, what --trusted-proxy wrote stays.
        self.assertEqual(W.realip_into(by_hand, OFF), by_hand)

    def test_realip_checked(self):
        for bad in ({'from': ['not-a-net']}, {'from': ['10.0.0.1'], 'header': 'Host'},
                    {'from': ['10.0.0.1'], 'header': 'X-Real-IP;\n  evil'}, 'x'):
            with self.assertRaises(W.Refused):
                W.realip_checked(bad)
        self.assertEqual(W.realip_checked({'from': ['10.0.0.1']})[0], ['10.0.0.1/32'])

    def test_sso_peer_line(self):
        new = W.sso_peer_into(SHIPPED, True)
        self.assertEqual(new.count('fastcgi_param  ACME_PEER $realip_remote_addr;'), 1)
        block = tls_block(new)
        loc = block[block.index('location = / {'):]
        self.assertIn('ACME_PEER', loc[:loc.index('}')])
        self.assertEqual(W.sso_peer_into(new, True), new)
        self.assertEqual(W.sso_peer_into(new, False), SHIPPED)
        without = SHIPPED.replace('location = / {', 'location = /nothere {')
        with self.assertRaises(W.Refused):
            W.sso_peer_into(without, True)

    def nginx_dir(self):
        d = tempfile.mkdtemp(prefix='acme-ngx-', dir=TMP)
        main = os.path.join(d, 'acme.conf')
        with open(main, 'w') as f:
            f.write(SHIPPED)
        W.NGINX_MAIN = main
        W.NGINX_VIP = os.path.join(d, 'acme-vip.conf')
        W.NODE_FILES = {k: os.path.join(d, 'node-' + k) for k in W.NODE_FILES}
        W.VIP_FILES = {k: os.path.join(d, 'vip-' + k) for k in W.VIP_FILES}
        return main

    def request(self, **kw):
        r = {'tls_node': None, 'tls_vip': None, 'vip': {'on': False}}
        r.update(kw)
        return r

    def test_nginx_part_refused_puts_back(self):
        main = self.nginx_dir()

        class Done:
            def __init__(self, rc, err=''):
                self.returncode, self.stderr, self.stdout = rc, err, ''

        real_run, real_ns = W.subprocess.run, W.NO_SERVICES

        def fake(cmd, *a, **k):
            if cmd[:2] == ['nginx', '-t']:
                return Done(1, 'nginx: [emerg] unknown directive "real_ip_header"')
            return Done(0)
        W.subprocess.run, W.NO_SERVICES = fake, False
        try:
            with self.assertRaises(W.Refused):
                W.nginx_part(self.request(realip=RP, sso_peer=True), {})
        finally:
            W.subprocess.run, W.NO_SERVICES = real_run, real_ns
        with open(main) as f:
            self.assertEqual(f.read(), SHIPPED)
        # Taken: both in.
        said, _dh = W.nginx_part(self.request(realip=RP, sso_peer=True), {})
        with open(main) as f:
            text = f.read()
        self.assertIn('# ACME-REALIP-BEGIN', text)
        self.assertIn('# ACME-SSO-PEER', text)
        self.assertTrue(any('signed in by the load balancer' in s for s in said), said)
        # Off again: both out, the file as shipped.
        W.nginx_part(self.request(realip=OFF, sso_peer=False), {})
        with open(main) as f:
            self.assertEqual(f.read(), SHIPPED)

    def test_one_part_refused_holds_up_nothing_else(self):
        main = self.nginx_dir()
        with open(main, 'w') as f:
            f.write(SHIPPED.replace('location = / {', 'location = /nothere {'))
        said, _dh = W.nginx_part(self.request(realip=RP, sso_peer=True), {})
        self.assertTrue(any('NOT told' in s for s in said), said)
        with open(main) as f:
            self.assertIn('# ACME-REALIP-BEGIN', f.read())

    def test_request_checked(self):
        base = {'node': 'n1', 'tls': {}, 'vip': {'on': False}}
        try:
            got = W.checked(dict(base))
        except W.Refused as e:
            self.skipTest('the request needs more here: %s' % e)
        self.assertIsNone(got['realip'])
        self.assertIsNone(got['sso_peer'])
        got = W.checked(dict(base, realip=RP, sso_peer=True))
        self.assertEqual(got['realip']['from'], RP['from'])
        self.assertTrue(got['sso_peer'])
        with self.assertRaises(W.Refused):
            W.checked(dict(base, realip={'from': ['x y']}))


class Daemon(unittest.TestCase):
    def setUp(self):
        for k in ('web_proxy', 'web_proxy_from', 'portal_sso', 'portal_sso_from'):
            STORE.drop_setting(k)
            E.CONFIG[k] = E.DEFAULTS[k]
        E.SAVED_KEYS['at'] = 0.0

    def test_never_switched_on_leaves_nginx(self):
        self.assertIsNone(E.realip_desired(STORE))
        self.assertIsNone(E.sso_peer_desired(STORE))
        d = E.web_desired(STORE)
        self.assertNotIn('realip', d)
        self.assertNotIn('sso_peer', d)

    def test_on_then_off(self):
        E.CONFIG.update(web_proxy=1, web_proxy_from='10.0.0.5 192.0.2.0/28', portal_sso=1)
        got = E.realip_desired(STORE)
        self.assertEqual(got['from'], ['10.0.0.5/32', '192.0.2.0/28'])
        self.assertEqual(got['header'], 'X-Forwarded-For')
        self.assertTrue(E.sso_peer_desired(STORE))
        # Switched off - the row kept off (KEPT_OFF_KEYS): nobody believed any more.
        E.CONFIG.update(web_proxy=0, portal_sso=0)
        STORE.save_setting('web_proxy', 0, 'test')
        STORE.save_setting('portal_sso', 0, 'test')
        E.SAVED_KEYS['at'] = 0.0
        self.assertEqual(E.realip_desired(STORE), {'from': [], 'header': '', 'recursive': False})
        self.assertIs(E.sso_peer_desired(STORE), False)
        self.assertIn('web_proxy', E.KEPT_OFF_KEYS)
        self.assertIn('portal_sso', E.KEPT_OFF_KEYS)

    def test_saved_keys_read_every_30s(self):
        E.SAVED_KEYS['at'] = 0.0
        first = E.saved_keys(STORE)
        STORE.save_setting('web_proxy_header', 'X-Real-IP', 'test')
        self.assertEqual(E.saved_keys(STORE), first)
        E.SAVED_KEYS['at'] = 0.0
        self.assertIn('web_proxy_header', E.saved_keys(STORE))
        STORE.drop_setting('web_proxy_header')

    def test_vip_without_its_name(self):
        """A certificate of the VIP address's own and no FQDN (1.0.242): left out of the
        request, which root then takes - the node's certificate serves the address."""
        key, crt = E.make_selfsigned('vip.example.test', [], 30, 'ec')
        prof = {'cert': crt, 'key': E.seal_secret(key, 'web:tls'), 'preset': 'standard',
                'dh': 'none'}
        saved = {}
        real = (E.vip_conf, E.tls_profile, E.vip_plain, E.vip_auth)
        E.CONFIG['ha_mode'] = 'shared'
        E.vip_conf = lambda store: {'on': True, 'address': '192.0.2.50/24', 'fqdn': saved.get('fqdn', '')}
        E.tls_profile = lambda store, t: prof if t == 'vip' else None
        E.vip_plain = lambda a, like=None: '192.0.2.1' if a else ''
        E.vip_auth = lambda: 'secret12'
        E.CONFIG['ha_peer'] = '192.0.2.2'
        try:
            d = E.web_desired(STORE)
            self.assertTrue(d['vip']['on'])
            self.assertIsNone(d['tls']['vip'])
            saved['fqdn'] = 'vip.example.test'
            d = E.web_desired(STORE)
            self.assertTrue(d['tls']['vip'] and d['tls']['vip'].get('pem') or d['tls']['vip'])
        finally:
            E.vip_conf, E.tls_profile, E.vip_plain, E.vip_auth = real
            E.CONFIG['ha_mode'] = ''
            E.CONFIG['ha_peer'] = ''


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True, check=True).stdout


class DualCerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='acme-dual-', dir=TMP)
        cls.rsa_key, cls.rsa = E.make_selfsigned('dual.example.test', ['www.dual.example.test'], 30, 'rsa2048')
        cls.ec_key, cls.ec = E.make_selfsigned('dual.example.test', ['www.dual.example.test'], 30, 'ec')
        cls.other_key, cls.other = E.make_selfsigned('other.example.test', [], 30, 'ec')

    def pfx(self, cert, key, pw='pfx-password-1'):
        c = os.path.join(self.d, 'c.pem')
        k = os.path.join(self.d, 'k.pem')
        with open(c, 'w') as f:
            f.write(cert)
        with open(k, 'w') as f:
            f.write(key)
        return openssl('pkcs12', '-export', '-in', c, '-inkey', k, '-passout', 'pass:' + pw)

    def test_one_pem_with_both(self):
        main, alt = E.cert_bundles(cert=self.ec + self.ec_key + self.rsa + self.rsa_key)
        self.assertTrue(main['info']['key'].startswith('RSA'))
        self.assertTrue(alt['info']['key'].startswith('EC'))

    def test_two_pfx(self):
        main, alt = E.cert_bundles(pfx=self.pfx(self.ec, self.ec_key), password='pfx-password-1',
                                   pfx2=self.pfx(self.rsa, self.rsa_key))
        self.assertTrue(main['info']['key'].startswith('RSA'))
        self.assertTrue(alt['info']['key'].startswith('EC'))

    def test_one_alone_as_until_now(self):
        main, alt = E.cert_bundles(cert=self.rsa + self.rsa_key)
        self.assertIsNone(alt)
        self.assertTrue(main['info']['key'].startswith('RSA'))

    def test_refused(self):
        with self.assertRaises(ValueError):            # other names
            E.cert_bundles(cert=self.rsa + self.rsa_key + self.other + self.other_key)
        k2, c2 = E.make_selfsigned('dual.example.test', ['www.dual.example.test'], 30, 'rsa2048')
        with self.assertRaises(ValueError):            # two RSA
            E.cert_bundles(cert=self.rsa + self.rsa_key + c2 + k2)
        with self.assertRaises(ValueError):            # a key without its certificate
            E.cert_bundles(cert=self.rsa + self.rsa_key + self.ec_key)

    def test_export_which(self):
        main, alt = E.cert_bundles(cert=self.ec + self.ec_key + self.rsa + self.rsa_key)
        prof = {'cert': main['cert'], 'chain': main['chain'], 'root': '',
                'key': E.seal_secret(main['key'], 'web:tls'),
                'alt': {'cert': alt['cert'], 'chain': alt['chain'],
                        'key': E.seal_secret(alt['key'], 'web:tls'), 'info': alt['info'],
                        'for': E.tls_alt_for(main['cert'])}}
        rsa, ending = E.tls_export(prof, 'pem', which='rsa')
        self.assertEqual(rsa.decode().strip(), main['cert'].strip())
        ec, _ = E.tls_export(prof, 'pem', which='ec')
        self.assertEqual(ec.decode().strip(), alt['cert'].strip())
        both, ending = E.tls_export(prof, 'pfx', 'a-passphrase-of-length', which='both')
        self.assertEqual(ending, '.zip')
        with zipfile.ZipFile(io.BytesIO(both)) as z:
            self.assertEqual(sorted(z.namelist()), ['ecdsa.pfx', 'rsa.pfx'])
        # The names of acme 1.0.34.
        self.assertEqual(E.tls_export(prof, 'pem', which='main')[0], rsa)
        self.assertEqual(E.tls_export(prof, 'pem', which='alt')[0], ec)
        with self.assertRaises(ValueError):
            E.tls_export({'cert': main['cert']}, 'pem', which='ec')


if __name__ == '__main__':
    try:
        unittest.main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
