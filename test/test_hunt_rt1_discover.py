#!/usr/bin/env python3
"""Hunt R (t1), agent discovery: regressions of the bugs found.

    python3 test/test_hunt_rt1_discover.py

* nginx: an include and an ssl_certificate given relative are of nginx's prefix (the folder of
  nginx.conf: /usr/local/nginx/conf), not always /etc/nginx; a snippet included in two server
  blocks is put in both (it was read once: the second server lost its certificate);
* Apache: the same with a file Included in two VirtualHosts;
* a loop of includes (a file including its own folder, a link to a folder above) ends, and a
  block read twice is one service;
* HAProxy: the test checks the configuration found (/usr/local/etc/haproxy/haproxy.cfg);
* Dovecot 2.4: ssl_server_cert_file / ssl_server_key_file;
* acme: a file whose path has a space (Apache's quoted "/etc/ssl/my cert.pem") is no output line
  of a deployment - the view of the discovery broke on it (ValueError); "Watch it" asks for a
  host name, not nginx's .example.com / ~regex forms.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-disc-')
TREE = os.path.join(TMP, 'tree')
for _k, _sub in (('ACME_AGENT_ETC', 'etc'), ('ACME_AGENT_STATE', 'st'),
                 ('ACME_AGENT_ROOT_STATE', 'rs'), ('ACME_AGENT_RUN', 'run')):
    os.makedirs(os.path.join(TMP, _sub), exist_ok=True)
    os.environ[_k] = os.path.join(TMP, _sub)
os.environ['ACME_AGENT_DISCOVER_ROOT'] = TREE
os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
sys.path.insert(0, ROOT)

_spec = importlib.util.spec_from_file_location(
    'acme_agent_hunt_disc', os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py'))
A = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(A)

from acmelib.certs import agent_discover as AD  # noqa: E402

subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                os.path.join(TMP, 'k.pem'), '-out', os.path.join(TMP, 'c.pem'), '-subj',
                '/CN=a.example', '-days', '30'], capture_output=True, check=True)
with open(os.path.join(TMP, 'c.pem')) as _f:
    PEM = _f.read()


def w(path, text):
    p = TREE + path
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f:
        f.write(text)


def fresh():
    import shutil
    shutil.rmtree(TREE, ignore_errors=True)
    os.makedirs(TREE)


def files_of(f):
    return [(x['role'], x['path']) for x in f['files']]


class Linux(unittest.TestCase):
    def setUp(self):
        fresh()

    def test_nginx_prefix_and_shared_snippet(self):
        w('/usr/local/nginx/conf/nginx.conf', 'http { include sites/*.conf; }\n')
        w('/usr/local/nginx/conf/sites/a.conf',
          'server { listen 443 ssl; server_name a.example; include snip/ssl.conf; }\n'
          'server { listen 443 ssl; server_name b.example; include snip/ssl.conf; }\n')
        w('/usr/local/nginx/conf/snip/ssl.conf',
          'ssl_certificate certs/a.pem;\nssl_certificate_key /etc/k.key;\n')
        w('/usr/local/nginx/conf/certs/a.pem', PEM)
        got = A.discover_linux({}, ['nginx'])
        self.assertEqual([f['names'] for f in got['found']], [['a.example'], ['b.example']])
        for f in got['found']:
            self.assertEqual(files_of(f), [('cert', '/usr/local/nginx/conf/certs/a.pem'),
                                           ('key', '/etc/k.key')])
            self.assertTrue(f['files'][0]['there'])
            self.assertEqual(f['cert']['cn'], 'a.example')

    def test_apache_shared_include(self):
        w('/etc/apache2/apache2.conf', 'IncludeOptional sites-enabled/*.conf\n')
        w('/etc/apache2/sites-enabled/x.conf',
          '<VirtualHost *:443>\nServerName x.example\nInclude /etc/apache2/ssl-common.conf\n'
          '</VirtualHost>\n<VirtualHost *:443>\nServerName y.example\n'
          'Include /etc/apache2/ssl-common.conf\n</VirtualHost>\n')
        w('/etc/apache2/ssl-common.conf',
          'SSLCertificateFile /etc/ssl/x.pem\nSSLCertificateKeyFile /etc/ssl/x.key\n')
        got = A.discover_linux({}, ['apache'])
        self.assertEqual([f['names'] for f in got['found']], [['x.example'], ['y.example']])
        for f in got['found']:
            self.assertEqual(files_of(f), [('cert', '/etc/ssl/x.pem'), ('key', '/etc/ssl/x.key')])

    def test_include_loops_end_once_each(self):
        w('/etc/nginx/nginx.conf', 'http { include conf.d/*.conf; }\n')
        for i in range(12):
            w('/etc/nginx/conf.d/%02d.conf' % i, 'include conf.d/*.conf;\n'
              'server { listen 443 ssl; server_name s%d; ssl_certificate /x; }\n' % i)
        os.symlink(TREE + '/etc/nginx', TREE + '/etc/nginx/conf.d/loop')
        w('/etc/apache2/apache2.conf', 'Include apache2.conf\nInclude conf/\n'
          '<VirtualHost *:443>\nServerName q\nSSLCertificateFile /q\n</VirtualHost>\n')
        os.makedirs(TREE + '/etc/apache2/conf')
        os.symlink(TREE + '/etc/apache2/conf', TREE + '/etc/apache2/conf/self')
        w('/etc/dovecot/dovecot.conf', '!include dovecot.conf\nssl_cert = </d.pem\n')
        got = A.discover_linux({}, ['nginx', 'apache', 'dovecot'])
        names = sorted(n for f in got['found'] for n in f['names'] if f['kind'] == 'nginx')
        self.assertEqual(names, sorted('s%d' % i for i in range(12)))
        self.assertEqual(len([f for f in got['found'] if f['kind'] == 'apache']), 1)
        self.assertEqual(len([f for f in got['found'] if f['kind'] == 'dovecot']), 1)
        self.assertEqual(got['skipped'], [])

    def test_haproxy_test_of_the_config_found(self):
        w('/usr/local/etc/haproxy/haproxy.cfg',
          'frontend web\n  bind :443 ssl crt /etc/haproxy/site.pem\n')
        w('/etc/haproxy/site.pem', PEM)
        got = A.discover_linux({}, ['haproxy'])
        self.assertEqual(len(got['found']), 1)
        self.assertEqual(got['found'][0]['test'],
                         'haproxy -c -q -f /usr/local/etc/haproxy/haproxy.cfg')

    def test_dovecot_24(self):
        w('/etc/dovecot/dovecot.conf', 'ssl = required\n'
          'ssl_server_cert_file = /etc/dovecot/private/dovecot.pem\n'
          'ssl_server_key_file = /etc/dovecot/private/dovecot.key\n'
          'local_name mail.example {\n  ssl_server_cert_file = /etc/ssl/mail.pem\n'
          '  ssl_server_key_file = /etc/ssl/mail.key\n}\n')
        got = A.discover_linux({}, ['dovecot'])
        self.assertEqual([files_of(f) for f in got['found']], [
            [('cert', '/etc/dovecot/private/dovecot.pem'),
             ('key', '/etc/dovecot/private/dovecot.key')],
            [('cert', '/etc/ssl/mail.pem'), ('key', '/etc/ssl/mail.key')]])
        self.assertEqual(got['found'][1]['names'], ['mail.example'])


class Acme(unittest.TestCase):
    def test_path_with_a_space_is_no_output_line(self):
        f = {'kind': 'apache', 'preset': 'apache', 'unit': 'apache2.service',
             'reload': 'systemctl reload apache2',
             'files': [{'role': 'cert', 'format': 'fullchain-pem', 'path': '/etc/ssl/my cert.pem',
                        'there': True, 'mode': '0644', 'owner': 'root', 'group': 'root'},
                       {'role': 'key', 'format': 'key-pem', 'path': '/etc/ssl/k.key',
                        'there': True, 'mode': '0600', 'owner': 'root', 'group': 'root'}]}
        o = AD.prefill(f, 'linux')
        self.assertEqual(o['outputs'], ['key-pem /etc/ssl/k.key 0600 root:root'])
        its = AD.items(f, 'linux')                       # was: ValueError (int('cert.pem', 8))
        self.assertIn('acme-agent allow file /etc/ssl --owner root:root --mode 0600',
                      [i['allow'] for i in its])
        f['files'] = f['files'][:1]
        self.assertEqual(AD.prefill(f, 'linux'), {})
        self.assertEqual(AD.items(f, 'linux'), [])

    def test_watch_asks_a_host_name(self):
        f = {'kind': 'nginx', 'listen': ['443 ssl'], 'port': 443,
             'names': ['~^www\\.example\\.com', '.example.com', 'example.*', 'www.example.com']}
        self.assertEqual(AD.watch_of(f, 'h')['sni'], 'www.example.com')
        f['names'] = ['.example.com']
        self.assertEqual(AD.watch_of(f, 'h')['sni'], '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
