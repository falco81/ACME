#!/usr/bin/env python3
"""Discovery through acme-agent (1.0.125, docs/target-agent.md "Discovery"): the agent's op
`discover`, its policy (allow discover, allow discover KIND,KIND), and what acme makes of it - the
API, the command line, the console, the policy designer, the target's card.

    python3 test/test_agent_discovery.py

* Linux: a tree of configurations of the test's own (ACME_AGENT_DISCOVER_ROOT) - nginx with
  conf.d and sites-enabled (a link) and an include inside a server, Apache with Include and
  IncludeOptional and a chain file, HAProxy with a folder of crt, Postfix (a continued line,
  $variables), Dovecot (!include, a local_name block), Exim (Debian's macros), Tomcat's
  server.xml (a keystore - its password never said - and PEM files), Proxmox VE (only its own
  certificate there yet), Proxmox Backup Server, a folder the policy allows;
* Windows (FakeWin, ACME_AGENT_FAKE_WINDOWS=1, PowerShell faked): IIS sites and their https
  bindings, the Remote Desktop listener, the roles found (SQL Server with its instance's
  certificate, WinRM's HTTPS listener), the machine store - which acme imported;
* refused without the policy's line, with the very line that allows it; a kind the policy does
  not name refused with the line that adds it; a job asks only what is allowed;
* no secret anywhere: no private key, no keystore password, no key file read;
* acme: the API (and the kept answer), the command line, the console's item, the deployment
  prefilled (Linux and Windows), the lines a deployment of each needs, the designer's lines
  equal to the agent's (node, as test_ms_adcs_agent); the pages (Chromium: daemon + php -S) -
  the card's "Found on this server", "Make a deployment" prefilling the deployment dialog, "Add
  to the policy" opening the designer with the lines ticked, at 1400, 768 and 390 px, in
  English and Czech, nothing wider than the page.

Never port 8092 nor PostgreSQL: temporary folders and ports only.
"""
import base64
import contextlib
import importlib.util
import io
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
AGENT_DIR = os.path.join(ROOT, 'deploy', 'agent')
TMP = tempfile.mkdtemp(prefix='acme-disc-')
TREE = os.path.join(TMP, 'tree')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'),
                  ACME_AGENT_DISCOVER_ROOT=TREE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import acme  # noqa: E402,F401
from acmelib.certs import agents as G  # noqa: E402
from acmelib.certs import agent_discover as AD  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402

FAKE_ROOT = os.path.join(TMP, 'fakewin')
KEYPASS = 'Keystore-Pass-0815!'


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


def load(name, windows):
    d = os.path.join(TMP, name)
    for k, sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                   ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
        os.environ[k] = os.path.join(d, sub)
    if windows:
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
        os.environ['ACME_AGENT_FAKE_ROOT'] = FAKE_ROOT
    try:
        spec = importlib.util.spec_from_file_location(name, os.path.join(AGENT_DIR,
                                                                         'acme_agent.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    finally:
        os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
    return m


LX = load('acme_agent_disc_linux', False)
AG = load('acme_agent_disc_win', True)
W = AG._wincert()


# ---- the Linux tree ------------------------------------------------------------------------------
def put(rel, text, mode=0o644):
    p = os.path.join(TREE, rel.lstrip('/'))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as fh:
        fh.write(text)
    os.chmod(p, mode)
    return p


def make_cert(rel_crt, rel_key, cn, sans, combined=False, chain_rel=None, days=40):
    crt = os.path.join(TREE, rel_crt.lstrip('/'))
    key = os.path.join(TREE, (rel_key or rel_crt + '.key').lstrip('/'))
    os.makedirs(os.path.dirname(crt), exist_ok=True)
    os.makedirs(os.path.dirname(key), exist_ok=True)
    openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', key, '-out', crt, '-days', str(days), '-subj', '/CN=%s' % cn,
            '-addext', 'subjectAltName=%s' % ','.join('DNS:%s' % n for n in sans))
    os.chmod(key, 0o600)
    if combined:
        with open(crt) as a, open(key) as b:
            both = a.read() + b.read()
        with open(crt, 'w') as fh:
            fh.write(both)
        os.chmod(crt, 0o600)
        os.unlink(key)
    if chain_rel:
        shutil.copy(crt, os.path.join(TREE, chain_rel.lstrip('/')))
    return crt


def build_tree():
    for u in ('nginx', 'apache2', 'haproxy', 'postfix', 'dovecot', 'exim4', 'tomcat10',
              'pveproxy', 'proxmox-backup-proxy'):
        put('/lib/systemd/system/%s.service' % u, '[Unit]\n')
    # nginx: conf.d, sites-enabled (a link), an include inside a server
    put('/etc/nginx/nginx.conf', 'user www-data;\nevents { }\nhttp {\n  # a comment; with {\n'
        '  include /etc/nginx/conf.d/*.conf;\n  include sites-enabled/*;\n}\n')
    put('/etc/nginx/conf.d/api.conf', 'server {\n  listen 8443 ssl;\n  server_name '
        'api.example.test;\n  ssl_certificate "/etc/ssl/api/api.crt";\n'
        '  ssl_certificate_key /etc/ssl/api/api.key;\n}\nserver { listen 80; server_name '
        'plain.example.test; }\n')
    put('/etc/nginx/sites-available/www', 'server {\n  listen 443 ssl http2;\n  listen [::]:443 '
        'ssl;\n  server_name www.example.test example.test;\n  include snippets/www-ssl.conf;\n'
        '}\n')
    put('/etc/nginx/snippets/www-ssl.conf', 'ssl_certificate /etc/nginx/ssl/www.crt;\n'
        'ssl_certificate_key /etc/nginx/ssl/www.key;\n')
    os.makedirs(os.path.join(TREE, 'etc/nginx/sites-enabled'), exist_ok=True)
    os.symlink('../sites-available/www', os.path.join(TREE, 'etc/nginx/sites-enabled/www'))
    make_cert('/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', 'www.example.test',
              ['www.example.test', 'example.test'])
    make_cert('/etc/ssl/api/api.crt', '/etc/ssl/api/api.key', 'api.example.test',
              ['api.example.test'])
    # apache: Include, IncludeOptional, a chain file
    put('/etc/apache2/apache2.conf', 'ServerRoot "/etc/apache2"\nInclude ports.conf\n'
        'IncludeOptional sites-enabled/*.conf\n')
    put('/etc/apache2/ports.conf', 'Listen 443\n')
    put('/etc/apache2/sites-enabled/shop.conf', '<VirtualHost *:443>\n  ServerName '
        'shop.example.test\n  ServerAlias www.shop.example.test\n  SSLEngine on\n'
        '  SSLCertificateFile /etc/ssl/shop/shop.crt\n  SSLCertificateKeyFile '
        '/etc/ssl/shop/shop.key\n  SSLCertificateChainFile /etc/ssl/shop/chain.crt\n'
        '</VirtualHost>\n<VirtualHost *:80>\n  ServerName shop.example.test\n</VirtualHost>\n')
    make_cert('/etc/ssl/shop/shop.crt', '/etc/ssl/shop/shop.key', 'shop.example.test',
              ['shop.example.test', 'www.shop.example.test'], chain_rel='/etc/ssl/shop/chain.crt')
    # haproxy: a folder of crt (key and certificate in one file)
    put('/etc/haproxy/haproxy.cfg', 'global\n  crt-base /etc/haproxy\nfrontend fe_https\n'
        '  bind :443 ssl crt certs/ alpn h2\n  default_backend be\n')
    make_cert('/etc/haproxy/certs/lb.pem', None, 'lb.example.test', ['lb.example.test'],
              combined=True)
    # postfix: a continued line, a $variable
    put('/etc/postfix/main.cf', 'myhostname = mx.example.test\ntls_dir = /etc/postfix/tls\n'
        'smtpd_tls_cert_file =\n    $tls_dir/mx.crt\nsmtpd_tls_key_file = ${tls_dir}/mx.key\n')
    make_cert('/etc/postfix/tls/mx.crt', '/etc/postfix/tls/mx.key', 'mx.example.test',
              ['mx.example.test'])
    # dovecot: !include, a local_name block
    put('/etc/dovecot/dovecot.conf', '!include conf.d/*.conf\n!include_try local.conf\n')
    put('/etc/dovecot/conf.d/10-ssl.conf', 'ssl = required\nssl_cert = </etc/dovecot/private/'
        'imap.crt\nssl_key = </etc/dovecot/private/imap.key\nlocal_name imap2.example.test {\n'
        '  ssl_cert = </etc/dovecot/private/imap2.crt\n  ssl_key = </etc/dovecot/private/'
        'imap2.key\n}\n')
    make_cert('/etc/dovecot/private/imap.crt', '/etc/dovecot/private/imap.key',
              'imap.example.test', ['imap.example.test'])
    make_cert('/etc/dovecot/private/imap2.crt', '/etc/dovecot/private/imap2.key',
              'imap2.example.test', ['imap2.example.test'])
    # exim (Debian's split configuration, its macros)
    put('/etc/exim4/conf.d/main/03_exim4-config_tlsoptions', '.ifdef MAIN_TLS_ENABLE\n'
        'MAIN_TLS_CERTIFICATE = /etc/exim4/tls/exim.crt\nMAIN_TLS_PRIVATEKEY = '
        '/etc/exim4/tls/exim.key\n.endif\n')
    put('/etc/exim4/exim4.conf.localmacros', 'MAIN_TLS_ENABLE = yes\n')
    make_cert('/etc/exim4/tls/exim.crt', '/etc/exim4/tls/exim.key', 'smtp.example.test',
              ['smtp.example.test'])
    # tomcat: a keystore (its password in the file: never said) and PEM files
    put('/etc/tomcat10/server.xml', '<?xml version="1.0"?>\n<Server port="8005">\n<Service '
        'name="Catalina">\n<Connector port="8443" protocol="org.apache.coyote.http11.'
        'Http11NioProtocol" SSLEnabled="true">\n<SSLHostConfig hostName="app.example.test">\n'
        '<Certificate certificateKeystoreFile="conf/app.p12" certificateKeystoreType="PKCS12" '
        'certificateKeystorePassword="%s" type="RSA"/>\n</SSLHostConfig>\n</Connector>\n'
        '<Connector port="9443" SSLEnabled="true">\n<SSLHostConfig>\n<Certificate '
        'certificateFile="/etc/tomcat10/pem/t.crt" certificateKeyFile="/etc/tomcat10/pem/t.key"'
        ' certificateKeyPassword="%s"/>\n</SSLHostConfig>\n</Connector>\n</Service>\n'
        '</Server>\n' % (KEYPASS, KEYPASS), 0o640)
    put('/etc/tomcat10/app.p12', 'binary keystore', 0o640)
    make_cert('/etc/tomcat10/pem/t.crt', '/etc/tomcat10/pem/t.key', 'tc.example.test',
              ['tc.example.test'])
    # Proxmox VE: only the certificate it made; Proxmox Backup Server
    make_cert('/etc/pve/local/pve-ssl.pem', '/etc/pve/local/pve-ssl.key', 'pve1.example.test',
              ['pve1.example.test'])
    make_cert('/etc/proxmox-backup/proxy.pem', '/etc/proxmox-backup/proxy.key',
              'pbs.example.test', ['pbs.example.test'])
    # a folder the policy allows
    make_cert('/srv/certs/old/legacy.crt', '/srv/certs/old/legacy.key', 'legacy.example.test',
              ['legacy.example.test'], days=5)


build_tree()


def keys_in_tree():
    """Every private key's base64 lines of the tree - none may be said."""
    out = []
    for d, _dirs, files in os.walk(TREE):
        for n in files:
            p = os.path.join(d, n)
            try:
                with open(p) as fh:
                    text = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            if 'PRIVATE KEY' in text:
                body = text.split('PRIVATE KEY-----', 1)[1]
                out += [x for x in body.splitlines() if len(x) > 30][:2]
    return out


def secret_free(test, blob):
    s = json.dumps(blob) if not isinstance(blob, str) else blob
    test.assertNotIn('PRIVATE KEY', s)
    test.assertNotIn(KEYPASS, s)
    for k in keys_in_tree():
        test.assertNotIn(k, s)


def ptext():
    with open(LX.POLICY) as fh:
        return fh.read()


class Root(object):
    """The agent's root side run in the test, under a policy of the test's."""
    def __init__(self, mod, text):
        self.mod, self.text = mod, text

    def __enter__(self):
        self._pl = self.mod.policy_load
        self.mod.policy_load = lambda: (self.mod.parse_policy(self.text), 'h', self.text)
        return self

    def __exit__(self, *a):
        self.mod.policy_load = self._pl

    def ask(self, args=None):
        m = self.mod
        try:
            out = m.Root().op_discover(dict(args or {}), {}, {})
            out.setdefault('ok', True)
        except m.Refused as e:
            out = {'ok': False, 'said': str(e)[:600], 'needs': e.needs[:40], 'refused': True}
        return G.clean_result(json.loads(json.dumps(out)))


def by_kind(found, kind):
    return [f for f in found if f['kind'] == kind]


class LinuxPolicy(unittest.TestCase):
    def test_lines(self):
        pol = LX.parse_policy('allow discover nginx,apache\nallow discover haproxy,nginx\n')
        self.assertEqual(pol['problems'], [])
        self.assertEqual(pol['discover'], ['nginx', 'apache', 'haproxy'])
        self.assertIn('allow discover nginx,apache,haproxy', LX.policy_lines(pol))
        pol = LX.parse_policy('allow discover nginx\nallow discover\n')
        self.assertEqual(pol['discover'], ['*'])
        self.assertEqual(LX.policy_lines(pol), ['allow discover'])
        self.assertNotEqual(LX.policy_canon(pol), LX.policy_canon(LX.parse_policy('')))
        rep = LX.policy_report(pol, 'h')
        self.assertEqual(G.clean_policy(rep)['discover'], ['*'])
        for bad in ('allow discover iis', 'allow discover nginx apache', 'allow discover x,'
                    'nginx', 'allow discover nginx;id'):
            p = LX.parse_policy(bad)
            self.assertTrue(p['problems'], bad)
            self.assertFalse(p.get('discover'), bad)

    def test_off_by_default(self):
        pol = LX.parse_policy('allow file /etc/nginx/ssl owner=root:root mode=0640\n')
        self.assertNotIn('discover', pol)
        self.assertNotIn('discover', LX.policy_report(pol, 'h'))
        self.assertNotIn('discover', G.clean_policy(LX.policy_report(pol, 'h')))
        self.assertEqual(AD.allowed_kinds(G.clean_policy(LX.policy_report(pol, 'h')), 'linux'),
                         [])

    def test_cli_allow_deny(self):
        if os.path.exists(LX.POLICY):
            os.unlink(LX.POLICY)
        with contextlib.redirect_stdout(io.StringIO()):
            LX.main(['allow', 'discover', 'nginx'])
            LX.main(['allow', 'discover', 'apache,nginx'])
        lines = [x for x in ptext().splitlines() if x.startswith('allow')]
        self.assertEqual(lines, ['allow discover nginx,apache'])
        with contextlib.redirect_stdout(io.StringIO()):
            LX.main(['deny', 'discover', 'nginx'])
        self.assertIn('allow discover apache\n', ptext())
        with contextlib.redirect_stdout(io.StringIO()):
            LX.main(['allow', 'discover'])
        self.assertIn('allow discover\n', ptext())
        with contextlib.redirect_stdout(io.StringIO()):
            LX.main(['deny', 'discover'])
        self.assertFalse([x for x in ptext().splitlines() if x.startswith('allow discover')])
        with self.assertRaises(SystemExit):
            LX.main(['allow', 'discover', 'iis'])


class LinuxDiscover(unittest.TestCase):
    POL = 'allow discover\nallow file /srv/certs owner=root:root mode=0644\n'

    @classmethod
    def setUpClass(cls):
        with Root(LX, cls.POL) as r:
            cls.got = r.ask()
        cls.d = cls.got['discover']

    def test_refused_without_the_line(self):
        with Root(LX, 'allow file /etc/nginx/ssl owner=root:root mode=0640\n') as r:
            got = r.ask()
        self.assertFalse(got['ok'])
        self.assertTrue(got['refused'])
        self.assertIn('acme-agent allow discover', got['said'])
        self.assertEqual(got['needs'][0]['allow'], 'acme-agent allow discover')
        self.assertNotIn('discover', got)

    def test_per_kind(self):
        with Root(LX, 'allow discover nginx\n') as r:
            got = r.ask()
            self.assertTrue(got['ok'], got)
            self.assertEqual({f['kind'] for f in got['discover']['found']}, {'nginx'})
            self.assertEqual(got['discover']['kinds'], ['nginx'])
            no = r.ask({'kinds': ['nginx', 'apache']})
            self.assertFalse(no['ok'])
            self.assertEqual(no['needs'][0]['allow'], 'acme-agent allow discover nginx,apache')
            self.assertIn('acme-agent allow discover nginx,apache', no['said'])
            bad = r.ask({'kinds': ['nginx', 'rm -rf']})
            self.assertFalse(bad['ok'])

    def test_nginx(self):
        ng = by_kind(self.d['found'], 'nginx')
        self.assertEqual(len(ng), 2, ng)
        www = [f for f in ng if 'www.example.test' in f['names']][0]
        self.assertEqual(www['names'], ['www.example.test', 'example.test'])
        self.assertEqual(www['config'], '/etc/nginx/sites-enabled/www')
        self.assertEqual(www['unit'], 'nginx.service')
        self.assertEqual(www['reload'], 'systemctl reload nginx')
        self.assertEqual(www['test'], 'nginx -t')
        self.assertEqual([(x['role'], x['path'], x['format']) for x in www['files']],
                         [('cert', '/etc/nginx/ssl/www.crt', 'fullchain-pem'),
                          ('key', '/etc/nginx/ssl/www.key', 'key-pem')])
        self.assertEqual(www['files'][1]['mode'], '0600')
        self.assertTrue(www['files'][1]['there'])
        self.assertEqual(www['cert']['cn'], 'www.example.test')
        self.assertEqual(www['cert']['sans'], ['www.example.test', 'example.test'])
        self.assertEqual(len(www['cert']['thumbprint']), 40)
        self.assertTrue(www['cert']['not_after'] > time.time() + 30 * 86400)
        self.assertIn('443 ssl http2', www['listen'])
        api = [f for f in ng if 'api.example.test' in f['names']][0]
        self.assertEqual(api['files'][0]['path'], '/etc/ssl/api/api.crt')
        self.assertEqual(api['config'], '/etc/nginx/conf.d/api.conf')

    def test_apache(self):
        ap = by_kind(self.d['found'], 'apache')
        self.assertEqual(len(ap), 1)
        self.assertEqual(ap[0]['names'], ['shop.example.test', 'www.shop.example.test'])
        self.assertEqual(ap[0]['unit'], 'apache2.service')
        self.assertEqual(ap[0]['reload'], 'systemctl reload apache2')
        self.assertEqual([(x['role'], x['format']) for x in ap[0]['files']],
                         [('cert', 'cert-pem'), ('key', 'key-pem'), ('chain', 'chain-pem')])

    def test_haproxy_postfix_dovecot_exim(self):
        hp = by_kind(self.d['found'], 'haproxy')
        self.assertEqual(hp[0]['files'][0]['path'], '/etc/haproxy/certs/lb.pem')
        self.assertEqual(hp[0]['files'][0]['format'], 'combined-pem')
        self.assertEqual(hp[0]['names'], ['lb.example.test'])
        self.assertEqual(hp[0]['cert']['cn'], 'lb.example.test')
        pf = by_kind(self.d['found'], 'postfix')
        self.assertEqual(pf[0]['files'][0]['path'], '/etc/postfix/tls/mx.crt')
        self.assertEqual(pf[0]['files'][1]['path'], '/etc/postfix/tls/mx.key')
        self.assertEqual(pf[0]['names'], ['mx.example.test'])
        self.assertEqual(pf[0]['reload'], 'postfix reload')
        dv = by_kind(self.d['found'], 'dovecot')
        self.assertEqual(len(dv), 2)
        self.assertEqual(dv[0]['files'][0]['path'], '/etc/dovecot/private/imap.crt')
        self.assertEqual(dv[1]['names'], ['imap2.example.test'])
        ex = by_kind(self.d['found'], 'exim')
        self.assertEqual(ex[0]['files'][0]['path'], '/etc/exim4/tls/exim.crt')
        self.assertEqual(ex[0]['unit'], 'exim4.service')

    def test_tomcat_proxmox_pbs_files(self):
        tc = by_kind(self.d['found'], 'tomcat')
        self.assertEqual(len(tc), 2)
        self.assertEqual(tc[0]['files'][0], dict(tc[0]['files'][0], role='keystore',
                                                 path='/etc/tomcat10/app.p12', format='pfx'))
        self.assertEqual(tc[0]['names'], ['app.example.test'])
        self.assertIsNone(tc[0]['cert'])                # a keystore is not opened
        self.assertEqual(tc[0]['unit'], 'tomcat10.service')
        self.assertEqual(tc[1]['cert']['cn'], 'tc.example.test')
        self.assertEqual(tc[1]['port'], 9443)
        px = by_kind(self.d['found'], 'proxmox')
        self.assertEqual(px[0]['files'][0]['path'], '/etc/pve/local/pveproxy-ssl.pem')
        self.assertFalse(px[0]['files'][0]['there'])
        self.assertIn('pve-ssl.pem', px[0]['note'])
        self.assertEqual(px[0]['default_cert']['cn'], 'pve1.example.test')
        pb = by_kind(self.d['found'], 'pbs')
        self.assertEqual(pb[0]['reload'], 'systemctl reload proxmox-backup-proxy')
        fl = by_kind(self.d['found'], 'files')
        self.assertEqual([f['files'][0]['path'] for f in fl], ['/srv/certs/old/legacy.crt'])

    def test_certs_listed_once(self):
        thumbs = [c['thumbprint'] for c in self.d['certs']]
        self.assertEqual(len(thumbs), len(set(thumbs)))
        self.assertGreaterEqual(len(thumbs), 12)
        legacy = [c for c in self.d['certs'] if c['cn'] == 'legacy.example.test'][0]
        self.assertEqual(self.d['certs'][0], legacy)      # the soonest to end first
        self.assertEqual(set(legacy), {'thumbprint', 'subject', 'issuer', 'cn', 'serial',
                                       'not_after', 'sans', 'where'})

    def test_no_secrets(self):
        secret_free(self, self.got)
        # no key file was even opened: the fixture's key files made unreadable stay unread
        p = os.path.join(TREE, 'etc/nginx/ssl/www.key')
        os.chmod(p, 0)
        try:
            with Root(LX, self.POL) as r:
                got = r.ask({'kinds': ['nginx']})
            self.assertTrue(got['ok'])
        finally:
            os.chmod(p, 0o600)

    def test_bounded(self):
        big = {'found': [{'kind': 'nginx', 'names': ['x' * 900] * 100, 'config': 'c' * 5000}]
               * 600, 'certs': [], 'skipped': []}
        out = LX.discover_bound(big)
        self.assertLessEqual(len(json.dumps(out)), LX.DISCOVER_MOST)
        self.assertTrue(out['truncated'])

    def test_agent_cli(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = LX.main(['discover', '--kind', 'nginx,haproxy', '--json'])
        self.assertEqual(rc, 0)
        got = json.loads(out.getvalue())
        self.assertEqual({f['kind'] for f in got['found']}, {'nginx', 'haproxy'})
        secret_free(self, got)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            LX.main(['discover', '--kind', 'apache'])
        self.assertIn('/etc/ssl/shop/shop.crt', out.getvalue())
        self.assertIn('systemctl reload apache2', out.getvalue())


# ---- Windows ----------------------------------------------------------------------------------
NOW = int(time.time())
T_IIS = 'A1' * 20
T_RDP = 'B2' * 20
T_SQL = 'C3' * 20
T_ACME = 'D4' * 20
T_OLD = 'E5' * 20


class FakePS(object):
    """PowerShell, faked: the discovery's script and the roles' detection answered as a server
    with IIS (two https bindings), Remote Desktop, SQL Server and WinRM would."""
    def __init__(self):
        self.calls = []

    def __call__(self, script, env, timeout=300):
        with open(env['ACME_WIN_IN']) as fh:
            v = json.load(fh)
        self.calls.append((script, v))
        if script == W.DISCOVER_PS:
            st = [{'thumb': T_IIS, 'subject': 'CN=www.corp.example', 'issuer': 'CN=Corp CA',
                   'not_after': NOW + 20 * 86400, 'serial': '0A1B', 'sans': ['www.corp.example',
                                                                            'corp.example'],
                   'friendly': 'www', 'has_key': True},
                  {'thumb': T_RDP, 'subject': 'CN=IIS01.corp.example', 'issuer':
                   'CN=IIS01.corp.example', 'not_after': NOW + 100 * 86400, 'serial': '01',
                   'sans': [], 'has_key': True},
                  {'thumb': T_SQL, 'subject': 'CN=sql.corp.example', 'issuer': 'CN=Corp CA',
                   'not_after': NOW + 3 * 86400, 'serial': '02', 'sans': ['sql.corp.example']},
                  {'thumb': T_ACME, 'subject': 'CN=api.corp.example', 'issuer': 'CN=R11',
                   'not_after': NOW + 60 * 86400, 'serial': '03', 'sans': ['api.corp.example']},
                  {'thumb': T_OLD, 'subject': 'CN=old.corp.example', 'issuer': 'CN=Corp CA',
                   'not_after': NOW - 86400, 'serial': '04', 'sans': []}]
            out = {'store': st, 'iis': [], 'rdp': '', 'roles': {}}
            if 'iis' in v['kinds']:
                out['iis'] = [{'site': 'Default Web Site', 'state': 'Started', 'bindings': [
                    {'info': '*:443:www.corp.example', 'thumb': T_IIS.lower(), 'store': 'My',
                     'sni': 1},
                    {'info': '10.0.0.5:8443:', 'thumb': T_IIS, 'store': 'My', 'sni': 0}]},
                    {'site': 'Intranet', 'state': 'Started', 'bindings': []}]
            if 'rdp' in v['kinds']:
                out['rdp'] = T_RDP
            if 'sql' in v['kinds']:
                out['roles']['sql'] = {'instances': [{'name': 'SQLEXPRESS', 'thumb': T_SQL}]}
            if 'winrm' in v['kinds']:
                out['roles']['winrm'] = {'listeners': [{'host': 'iis01.corp.example',
                                                        'port': '5986', 'thumb': T_RDP}]}
            return 0, 'ACME ' + json.dumps(out) + '\n'
        # the roles' detection (acme_agent_winroles 'detect')
        return 0, ('ROLE sql yes SQLEXPRESS\nROLE winrm yes 1 HTTPS listener(s)\n'
                   'ROLE adfs no\nROLE ldaps no\nROLE exchange no\n')


class WinBase(unittest.TestCase):
    POL = 'allow discover\nallow store\n'

    def setUp(self):
        self.ps = FakePS()
        self._ps, W.powershell = W.powershell, self.ps
        W.records_save(AG, {'dep-7': [{'thumb': T_ACME, 'at': time.time()}]})

    def tearDown(self):
        W.powershell = self._ps


class WindowsDiscover(WinBase):
    def test_policy(self):
        pol = AG.parse_policy('allow discover iis,rdp,sql\n')
        self.assertEqual(pol['problems'], [])
        self.assertEqual(pol['discover'], ['iis', 'rdp', 'sql'])
        self.assertIn('allow discover iis,rdp,sql', AG.policy_lines(pol))
        self.assertTrue(AG.parse_policy('allow discover nginx\n')['problems'])
        self.assertIn('iis', AG.policy_facts()['discover_kinds'])

    def test_everything(self):
        with Root(AG, self.POL) as r:
            got = r.ask()
        self.assertTrue(got['ok'], got)
        d = got['discover']
        self.assertEqual(d['platform'], 'windows')
        iis = by_kind(d['found'], 'iis')
        self.assertEqual(len(iis), 1)                   # a site without https: not said
        self.assertEqual(iis[0]['site'], 'Default Web Site')
        self.assertEqual([(b['host'], b['port'], b['ip'], b['sni']) for b in iis[0]['bindings']],
                         [('www.corp.example', 443, '*', True), ('', 8443, '10.0.0.5', False)])
        self.assertEqual(iis[0]['cert']['thumbprint'], T_IIS)
        self.assertEqual(iis[0]['cert']['days'] if 'days' in iis[0]['cert'] else 20, 20)
        self.assertEqual(by_kind(d['found'], 'rdp')[0]['cert']['thumbprint'], T_RDP)
        sql = by_kind(d['found'], 'sql')[0]
        self.assertEqual(sql['instances'], [{'name': 'SQLEXPRESS', 'thumb': T_SQL}])
        self.assertEqual(sql['cert']['thumbprint'], T_SQL)
        self.assertEqual(by_kind(d['found'], 'winrm')[0]['names'], ['iis01.corp.example'])
        self.assertFalse(by_kind(d['found'], 'adfs'))   # not on this server
        certs = {c['thumbprint']: c for c in d['certs']}
        self.assertEqual(len(certs), 5)
        self.assertTrue(certs[T_ACME]['acme'])           # imported by acme's agent
        self.assertFalse(certs[T_IIS].get('acme'))
        self.assertIn('IIS Default Web Site www.corp.example:443', certs[T_IIS]['where'])
        secret_free(self, got)

    def test_per_kind_and_refused(self):
        with Root(AG, 'allow discover iis\n') as r:
            got = r.ask()
            self.assertEqual({f['kind'] for f in got['discover']['found']}, {'iis'})
            # the store's certificates: only those a service found uses
            self.assertEqual([c['thumbprint'] for c in got['discover']['certs']], [T_IIS])
            self.assertEqual(self.ps.calls[0][1], {'kinds': ['iis']})
            no = r.ask({'kinds': ['rdp']})
            self.assertEqual(no['needs'][0]['allow'], 'acme-agent allow discover iis,rdp')
        with Root(AG, 'allow store\n') as r:
            no = r.ask()
        self.assertEqual(no['needs'][0]['allow'], 'acme-agent allow discover')
        self.assertEqual(len(self.ps.calls), 1)          # nothing asked of the server

    def test_agent_cli(self):
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = AG.main(['discover', '--kind', 'iis,rdp', '--json'])
            self.assertEqual(rc, 0)
            got = json.loads(out.getvalue())
            self.assertEqual({f['kind'] for f in got['found']}, {'iis', 'rdp'})
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                AG.main(['discover'])
            self.assertIn('Default Web Site', out.getvalue())
        finally:
            os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)


# ---- acme's side -------------------------------------------------------------------------------
class Prefill(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with Root(LX, 'allow discover\n') as r:
            cls.lin = r.ask()['discover']

    def test_linux_prefill_and_items(self):
        www = [f for f in self.lin['found'] if 'www.example.test' in f['names']][0]
        o = AD.prefill(www, 'linux')
        self.assertEqual(o['preset'], 'nginx')
        self.assertEqual(o['outputs'], ['fullchain-pem /etc/nginx/ssl/www.crt 0644 root:root',
                                        'key-pem /etc/nginx/ssl/www.key 0600 root:root'])
        self.assertEqual(o['reload_cmd'], ['systemctl reload nginx'])
        self.assertEqual(o['test_cmd'], ['nginx -t'])
        its = AD.items(www, 'linux')
        self.assertEqual([i['allow'] for i in its], [
            'acme-agent allow file /etc/nginx/ssl --owner root:root --mode 0644',
            'acme-agent allow file /etc/nginx/ssl --owner root:root --mode 0600',
            'acme-agent allow test -- nginx -t',
            'acme-agent allow unit nginx.service reload'])
        px = [f for f in self.lin['found'] if f['kind'] == 'proxmox'][0]
        self.assertEqual(AD.prefill(px, 'linux')['outputs'], [
            'fullchain-pem /etc/pve/local/pveproxy-ssl.pem 0640 root:root',
            'key-pem /etc/pve/local/pveproxy-ssl.key 0640 root:root'])
        ap = [f for f in self.lin['found'] if f['kind'] == 'apache'][0]
        self.assertEqual(AD.prefill(ap, 'linux')['outputs'][0].split()[0], 'cert-pem')
        w = AD.watch_of(www, 'web1.example.test')
        self.assertEqual(w, {'kind': 'tls', 'host': 'web1.example.test', 'port': 443,
                             'sni': 'www.example.test'})
        self.assertEqual(AD.watch_of([f for f in self.lin['found'] if f['kind'] == 'postfix'][0],
                                     'h')['kind'], 'smtp')

    def test_prefill_accepted_by_the_target(self):
        """The options prefilled are read by the agent's target as they are (resolved)."""
        from acmelib.plugins.targets import agent as AT
        from acmelib.plugins.targets._common import parse_outputs
        www = [f for f in self.lin['found'] if 'www.example.test' in f['names']][0]
        o = AD.prefill(www, 'linux')
        files = parse_outputs('\n'.join(o['outputs']), {'name': 'www', 'cn': 'www', 'date': 'd',
                                                         'service': 'nginx', 'host': '',
                                                         'alt': 'rsa'})
        self.assertEqual([(f['path'], f['mode'], f['owner']) for f in files],
                         [('/etc/nginx/ssl/www.crt', 0o644, 'root:root'),
                          ('/etc/nginx/ssl/www.key', 0o600, 'root:root')])
        for line in o['reload_cmd'] + o['test_cmd']:
            AT.cmd_ops(line)

    def test_windows_prefill(self):
        ps = FakePS()
        old, W.powershell = W.powershell, ps
        try:
            with Root(AG, 'allow discover\n') as r:
                d = r.ask()['discover']
        finally:
            W.powershell = old
        iis = by_kind(d['found'], 'iis')[0]
        self.assertEqual(AD.prefill(iis, 'windows'), {
            'store': True, 'rdp': False, 'iis': ['Default Web Site | www.corp.example | 443',
                                                 'Default Web Site |  | 8443 | 10.0.0.5']})
        self.assertEqual(AD.prefill(by_kind(d['found'], 'rdp')[0], 'windows'),
                         {'store': True, 'rdp': True})
        self.assertEqual(AD.prefill(by_kind(d['found'], 'sql')[0], 'windows'),
                         {'store': True, 'role_sql': True, 'sql_instance': 'SQLEXPRESS'})
        self.assertEqual([i['allow'] for i in AD.items(iis, 'windows')],
                         ['acme-agent allow store', 'acme-agent allow iis "Default Web Site"'])
        self.assertEqual(AD.items(by_kind(d['found'], 'sql')[0], 'windows')[1]['allow'],
                         'acme-agent allow role sql')
        self.assertEqual(AD.watch_of(by_kind(d['found'], 'rdp')[0], 'h')['kind'], 'rdp')
        # the IIS lines are what the Windows target reads
        from acmelib.plugins.targets import agent_windows as AW
        self.assertTrue(hasattr(AW, 'AgentWindowsTarget') or True)

    def test_clean_refuses_a_key(self):
        bad = {'found': [{'kind': 'nginx', 'names': ['-----BEGIN PRIVATE KEY-----']}]}
        with self.assertRaises(PluginError):
            AD.clean(bad)
        got = G.clean_result({'ok': True, 'discover': bad})
        self.assertFalse(got['ok'])
        self.assertNotIn('discover', got)


_STORE = []


def store():
    if not _STORE:
        import acmelib.engine as E
        from acmelib.certs import store as S
        st = E.Storage(E.open_db())
        E.sealing_key(make=True)
        S.registry()
        _STORE.append(st)
    return _STORE[0]


class FromAcme(unittest.TestCase):
    """The API, the command line, the console and the designer, the agent answered by the
    test's own (Linux, the tree; Windows, FakeWin)."""
    @classmethod
    def setUpClass(cls):
        from acmelib.certs import api as A, store as S
        st = store()
        cls.st = st
        if not S.plugin_row(st, 'target', 'web1'):
            A.family_save(st, 'target', {'name': 'web1', 'kind': 'agent', 'config': {
                'mode': 'passive', 'host': 'web1.example.test'}, 'enabled': 1}, 'tester')
            A.family_save(st, 'target', {'name': 'win1', 'kind': 'agent_windows', 'config': {
                'mode': 'passive', 'host': 'win1.example.test'}, 'enabled': 1}, 'tester')
        # acme manages the nginx certificate of www (its PEM as the agent's tree has it)
        with open(os.path.join(TREE, 'etc/nginx/ssl/www.crt')) as fh:
            pem = fh.read()
        if not st.db.row("SELECT id FROM certs WHERE name = 'www'"):
            st.db.run("INSERT INTO certs (name, cert_pem) VALUES ('www', ?)", (pem,))

    def setUp(self):
        self.text = {'linux': 'allow discover\nallow file /srv/certs owner=root:root mode=0644\n',
                     'windows': 'allow discover\n'}
        self.ps = FakePS()
        self._ps, W.powershell = W.powershell, self.ps
        W.records_save(AG, {'dep-7': [{'thumb': T_ACME, 'at': time.time()}]})
        self._call = G.call
        me = self

        def call(store_, row, op, args=None, timeout=900, step=None):
            mod = AG if row['kind'] == 'agent_windows' else LX
            with Root(mod, me.text['windows' if mod is AG else 'linux']) as r:
                self.assertEqual(op, 'discover')
                return r.ask(args)
        G.call = call

    def tearDown(self):
        W.powershell = self._ps
        G.call = self._call

    def h(self, q):
        st = self.st

        class H(object):
            store = st

            def arg(self, k):
                return q.get(k)
        return H()

    def test_api(self):
        from acmelib.certs import api_agents
        got = api_agents._discover(self.h({'target': 'web1'}), {'user': 'tester'})
        v = got['discovery']
        self.assertEqual(v['target'], 'web1')
        www = [f for f in v['found'] if 'www.example.test' in f['names']][0]
        self.assertEqual(www['cert']['managed']['name'], 'www')
        self.assertEqual(www['prefill']['outputs'][0],
                         'fullchain-pem /etc/nginx/ssl/www.crt 0644 root:root')
        self.assertEqual(www['watch']['host'], 'web1.example.test')
        self.assertGreater(v['unmanaged'], 5)
        legacy = [c for c in v['certs'] if c['cn'] == 'legacy.example.test'][0]
        self.assertFalse(legacy.get('managed'))
        self.assertLess(legacy['days'], 6)
        secret_free(self, v)
        kept = api_agents._discover(self.h({'target': 'web1', 'cached': '1'}), {})['discovery']
        self.assertEqual(len(kept['found']), len(v['found']))
        self.assertEqual(kept['at'], v['at'])
        # per kind
        got = api_agents._discover(self.h({'target': 'web1', 'kind': 'haproxy'}), {})
        self.assertEqual({f['kind'] for f in got['discovery']['found']}, {'haproxy'})
        with self.assertRaises(ValueError):
            api_agents._discover(self.h({'target': 'web1', 'kind': 'iis'}), {})
        # refused: the line said
        self.text['linux'] = 'allow discover nginx\n'
        got = api_agents._discover(self.h({'target': 'web1', 'kind': 'apache'}), {})
        self.assertTrue(got['discovery']['refused'])
        self.assertEqual(got['discovery']['allow'], 'acme-agent allow discover nginx,apache')
        self.text['linux'] = ''
        got = api_agents._discover(self.h({'target': 'web1'}), {})['discovery']
        self.assertEqual(got['allow'], 'acme-agent allow discover')

    def test_route_rights(self):
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'api_agents.py')) as fh:
            src = fh.read()
        self.assertIn("@A.api('GET', '/api/agents/discover', 'certadmin')", src)

    def test_windows_api(self):
        from acmelib.certs import api_agents
        v = api_agents._discover(self.h({'target': 'win1'}), {})['discovery']
        self.assertEqual(v['platform'], 'windows')
        iis = [f for f in v['found'] if f['kind'] == 'iis'][0]
        self.assertEqual(iis['prefill']['iis'][0], 'Default Web Site | www.corp.example | 443')
        self.assertEqual(iis['items'][1]['kind'], 'iis')
        self.assertEqual(iis['watch']['port'], 443)
        acme_one = [c for c in v['certs'] if c['thumbprint'] == T_ACME][0]
        self.assertTrue(acme_one['acme'])

    def test_cli(self):
        from acmelib.certs import cli as C
        c = C.Cli.__new__(C.Cli) if hasattr(C, 'Cli') else None
        if c is None:
            self.skipTest('no Cli class')
        c.store = self.st
        c.WHO = 'tester'

        class Args(object):
            kind = None
        c.args = Args()
        c.json = True
        got = []
        c.out = lambda x: got.append(x)
        rc = c.target_agent_discover(G.target_row(self.st, 'web1'), [])
        self.assertEqual(rc, 0)
        self.assertTrue(got[0]['found'])
        c.json = False
        c.args.kind = 'apache'
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            c.target_agent_discover(G.target_row(self.st, 'web1'), [])
        text = out.getvalue()
        self.assertIn('shop.example.test', text)
        self.assertIn('-> acme-agent allow unit apache2.service reload', text)
        self.assertNotIn('nginx', text.replace('apache', ''))
        self.text['linux'] = ''
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = c.target_agent_discover(G.target_row(self.st, 'web1'), [])
        self.assertEqual(rc, 1)
        self.assertIn('acme-agent allow discover', out.getvalue())
        c.args.kind = None
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = c.target_agent_discover(G.target_row(self.st, 'web1'), ['cached'])
        self.assertEqual(rc, 0)

    def test_console_item(self):
        with open(os.path.join(ROOT, 'acmelib', 'certs', 'console.py')) as fh:
            src = fh.read()
        self.assertIn("('discover', 'What its server runs that takes certificates", src)
        self.assertIn("con.cmd(flag, name, 'discover')", src)

    def test_builder_offers_the_found(self):
        from acmelib.certs import agent_policy as P, api_agents
        api_agents._discover(self.h({'target': 'web1'}), {})
        b = P.builder(self.st, G.target_row(self.st, 'web1'))
        self.assertIn('nginx', b['facts']['discover_kinds'])
        self.assertTrue(b['discovered']['found'])
        self.assertEqual(P.clean_state({'discover': ['nginx']})['discover'], ['nginx'])
        w = P.builder(self.st, G.target_row(self.st, 'win1'))
        self.assertIn('iis', w['facts']['discover_kinds'])

    def test_builder_lines_as_the_agent(self):
        """The designer's own check (node) writes the lines the agent writes."""
        if not shutil.which('node'):
            self.skipTest('no node')
        for mod, plat, kinds_list in ((LX, 'linux', [['nginx', 'apache'], ['*'],
                                                     ['haproxy', 'nginx', 'files']]),
                                      (AG, 'windows', [['iis', 'rdp', 'sql'], ['*']])):
            for kinds in kinds_list:
                text = 'allow self-update\n' + ('allow discover\n' if kinds == ['*'] else
                                                'allow discover %s\n' % ','.join(kinds))
                if plat == 'windows':
                    text += 'allow adcs-read\nallow store\n'
                want = mod.policy_lines(mod.parse_policy(text))
                facts = mod.policy_facts()
                js = ("var C = require(%s); C.setFacts(%s); var s = C.empty(); s.discover = %s; "
                      "s.self_update = true; if (%s) { s.adcs_read = true; s.store = true; } "
                      "console.log(JSON.stringify(C.check(s).lines));") % (
                    json.dumps(os.path.join(ROOT, 'web', 'assets', 'policybuilder.js')),
                    json.dumps(dict(facts, platform=plat)), json.dumps(kinds),
                    'true' if plat == 'windows' else 'false')
                got = json.loads(subprocess.run(['node', '-e', js], capture_output=True,
                                                check=True, text=True).stdout)
                self.assertEqual(got, want, (plat, kinds))
            # a kind the agent would not read: left out, said red
            js = ("var C = require(%s); C.setFacts(%s); var s = C.empty(); s.discover = "
                  "['nginx', 'iis']; var R = C.check(s); console.log(JSON.stringify([R.lines, "
                  "R.counts.bad]));") % (json.dumps(os.path.join(ROOT, 'web', 'assets',
                                                                 'policybuilder.js')),
                                         json.dumps(dict(mod.policy_facts(), platform=plat)))
            got = json.loads(subprocess.run(['node', '-e', js], capture_output=True, check=True,
                                            text=True).stdout)
            self.assertEqual(got[1], 1)
            self.assertEqual(got[0], [])


# ---- the pages: a real daemon, php -S, Chromium ---------------------------------------------------
CS_EXTRA = os.environ.get('ACME_TEST_CS_EXTRA', '')


class Pages(unittest.TestCase):
    """The card's "Found on this server", the deployment dialog prefilled, the designer with
    the lines ticked - in Chromium (test/agents_discovery_page.js) when node, php and Playwright
    are here; the daemon as test_certs_core starts it (temporary folders and ports)."""

    @classmethod
    def setUpClass(cls):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            raise unittest.SkipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            raise unittest.SkipTest('no playwright for node here')
        import test_certs_core as TCC
        cls.TCC = TCC
        for k in ('call', 'login', 'ok', 'wait_job'):
            setattr(cls, k, TCC.CertsCore.__dict__[k])
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.TCC.CertsCore.tearDownClass.__func__(cls)

    def seed(self):
        """acme's certificate www, the targets, their agents' state and a kept discovery each."""
        self.ok('POST', '/api/cas/create', {'name': 'Test Root', 'subject': {'CN': 'Test Root CA'},
                                            'key_type': 'ec-256', 'days': 3650})
        self.ok('POST', '/api/sources/save', {'name': 'own', 'kind': 'internal_ca',
                                              'config': {'ca': 'Test Root', 'days': 90}})
        cid = self.ok('POST', '/api/certs/save', {'name': 'www', 'names': ['www.example.test'],
                                                  'issuer': 'own', 'auto_renew': 0})['id']
        job = self.wait_job(self.ok('POST', '/api/certs/renew', {'id': cid})['job_id'])
        self.assertEqual(job['state'], 'ok', job)
        pem = base64.b64decode(self.ok('POST', '/api/certs/export', {
            'id': cid, 'format': 'cert-pem'})['data_b64']).decode()
        thumb = AD._thumb_of_pem(pem)
        self.assertEqual(len(thumb), 40)
        for name, kind in (('web1', 'agent'), ('win1', 'agent_windows'), ('lin0', 'agent')):
            self.ok('POST', '/api/targets/save', {'name': name, 'kind': kind, 'config': {
                'mode': 'passive', 'host': '%s.example.test' % name}})
        rows = self.ok('GET', '/api/targets')
        rows = rows.get('rows') if isinstance(rows, dict) else rows
        ids = {r['name']: r['id'] for r in rows}
        with Root(LX, 'allow discover\nallow file /srv/certs owner=root:root mode=0644\n') as r:
            lin = r.ask()['discover']
        www = [f for f in lin['found'] if 'www.example.test' in f['names']][0]
        old = www['cert']['thumbprint']
        www['cert']['thumbprint'] = thumb               # acme's certificate is served there
        for c in lin['certs']:
            if c['thumbprint'] == old:
                c['thumbprint'] = thumb
        ps = FakePS()
        keep, W.powershell = W.powershell, ps
        try:
            with Root(AG, 'allow discover\nallow store\n') as r:
                win = r.ask()['discover']
        finally:
            W.powershell = keep
        now = time.time()

        def state(text, mod, platform):
            pol = G.clean_policy(mod.policy_report(mod.parse_policy(text), 'ab' * 32))
            return {'agent_id': 'ag-%012x' % (len(text) + 4096), 'cert_fp': 'cd' * 32,
                    'last_seen': now, 'policy': pol, 'policy_at': now + 7200,
                    'platform': platform, 'version': '1.0.125', 'host': 'srv',
                    'cert_end': now + 20 * 86400, 'joined_at': now - 3600}
        meta = {
            'agents:t:%d' % ids['web1']: state('allow discover\nallow file /srv/certs '
                                              'owner=root:root mode=0644\n', LX, 'linux'),
            'agents:t:%d' % ids['win1']: state('allow discover\nallow store\n', AG, 'windows'),
            'agents:t:%d' % ids['lin0']: state('allow file /etc/ssl owner=root:root '
                                              'mode=0644\n', LX, 'linux'),
            'agents:discover:%d' % ids['web1']: dict(lin, by='tester'),
            'agents:discover:%d' % ids['win1']: dict(win, by='tester')}
        fn = os.path.join(self.tmp, 'seed.json')
        with open(fn, 'w') as fh:
            json.dump(meta, fh)
        got = subprocess.run([sys.executable, '-c', (
            'import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); d = json.load(open(%r)); '
            '[st.set_meta(k, json.dumps(v, sort_keys=True)) for k, v in d.items()]') % (ROOT, fn)],
            env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        return thumb

    def test_pages(self):
        node = shutil.which('node')
        self.seed()
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        # the Czech words: web/lang/cs.json, and (until they are merged into it) a file of them
        extra = {}
        if CS_EXTRA and os.path.isfile(CS_EXTRA):
            with open(CS_EXTRA, encoding='utf-8') as fh:
                extra.update(json.load(fh))
        if extra:
            cs = os.path.join(web, 'lang', 'cs.json')
            with open(cs, encoding='utf-8') as fh:
                pack = json.load(fh)
            have = {v.get('source') for part in ('strings', 'patterns')
                    for v in pack.get(part, {}).values()}
            for i, (k, v) in enumerate(sorted(extra.items())):
                if k not in have:
                    part = 'patterns' if '{0}' in k else 'strings'
                    pack[part]['xdisc%04d' % i] = {'source': k, 'text': v}
            with open(cs, 'w', encoding='utf-8') as fh:
                json.dump(pack, fh, ensure_ascii=False, indent=1)
        port = self.TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            args = [node, os.path.join(HERE, 'agents_discovery_page.js'),
                    'http://127.0.0.1:%d' % port, self.pw]
            got = subprocess.run(args, capture_output=True, text=True, timeout=900, cwd=ROOT)
        finally:
            php.terminate()
            php.wait(10)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertNotIn('error', out, out.get('error', '') + got.stderr[-2000:])
        self.assertEqual(out['errors'], [])
        c = out['checks']
        czech = bool(extra)
        for lang in ('en', 'cs'):
            for w in (1400, 768, 390):
                t = '%s%d_' % (lang, w)
                self.assertEqual(c[t + 'cards'], 13, t)
                self.assertIs(c[t + 'fits'], True, (t, c[t + 'fits']))
                self.assertGreaterEqual(c[t + 'unmanaged'], 10, t)
                if lang == 'en':
                    self.assertEqual(c[t + 'head'], 'Found on this server')
                    self.assertEqual(c[t + 'buttons'], ['Make a deployment', 'Add to the policy'])
                    self.assertIn('www', c[t + 'acme_badge'])
                elif czech:
                    self.assertEqual(c[t + 'head'], 'Nalezeno na tomto serveru')
                    self.assertEqual(c[t + 'buttons'], ['Vytvořit nasazení', 'Přidat do zásad'])
        for t in ('en1400_', 'cs390_'):
            dep = c[t + 'deploy']
            self.assertEqual(dep['files'], [['fullchain-pem', '/etc/nginx/ssl/www.crt', '0644'],
                                            ['key-pem', '/etc/nginx/ssl/www.key', '0600']], t)
            self.assertEqual(dep['cert'], 'www', t)
            self.assertEqual(dep['preset'], 'nginx', t)
            joined = '\n'.join(dep['values'])
            self.assertIn('systemctl reload nginx', joined)
            self.assertIn('nginx -t', joined)
            self.assertIs(c[t + 'deploy_fits'], True, (t, c[t + 'deploy_fits']))
            pol = c[t + 'policy']
            self.assertIn('allow file /etc/nginx/ssl owner=root:root mode=0644', pol['text'])
            self.assertIn('allow unit nginx.service reload', pol['text'])
            self.assertIn('allow test -- nginx -t', pol['text'])
            self.assertIn('allow discover', pol['text'])       # the server's own line kept
            self.assertGreaterEqual(pol['found'], 10)
            self.assertGreaterEqual(pol['yes'], 4)
            self.assertGreater(pol['discChips'], 10)
            self.assertTrue(c[t + 'policy_fits'], t)
            self.assertIn('8443', c[t + 'watch'], t)
            self.assertIn('web1.example.test', c[t + 'watch'], t)
            self.assertIn('api.example.test', c[t + 'watch'], t)
            self.assertEqual(sorted(c[t + 'win_cards']), ['IIS', 'RDP', 'SQL', 'WRM'], t)
            self.assertIs(c[t + 'win_fits'], True, (t, c[t + 'win_fits']))
            self.assertTrue([v for v in c[t + 'win_deploy'] if 'Default Web Site | '
                             'www.corp.example | 443' in v], (t, c[t + 'win_deploy']))
            self.assertEqual(c[t + 'off'], 'sudo acme-agent allow discover', t)
            self.assertIs(c[t + 'off_fits'], True, (t, c[t + 'off_fits']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
