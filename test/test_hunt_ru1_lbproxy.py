#!/usr/bin/env python3
"""Hunt u1, the load balancer work of 1.0.128 (PROXY protocol, the guide).

    python3 test/test_hunt_ru1_lbproxy.py

- deploy/acme_web.py: a loopback 443 line of the admin's own is never given proxy_protocol
  (the node's own checks - the VIP address's - come from there without a PROXY header), one
  given it by an earlier version is cleaned; the VIP address's server made from such a block
  has one listen of the address, not two (nginx refused both servers).
- web/assets/admin.js: the red "published through the balancer" line in Czech; the PROXY
  protocol believed only from a balancer named; TLS ended on the balancer while 443 takes
  only the PROXY protocol said (it was said to be fine); a balancer in a network named is
  trusted; the portal-only blocks refuse /assets/../admin/ and keep /pki/ plain on port 80.
"""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-u1-lb-')


def helper():
    spec = importlib.util.spec_from_file_location('acme_web_u1lb', os.path.join(
        ROOT, 'deploy', 'acme_web.py'))
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    return w


W = helper()
with open(os.path.join(ROOT, 'deploy', 'nginx-acme.conf')) as _f:
    SHIPPED = _f.read()
PP = {'from': ['192.0.2.5/32'], 'header': 'proxy_protocol', 'recursive': True}
OFF = {'from': [], 'header': '', 'recursive': False}
HAND = SHIPPED.replace('    listen      [::]:443 ssl http2;\n',
                       '    listen      [::]:443 ssl http2;\n    listen      127.0.0.1:443 ssl http2;\n', 1)


def tls_block(text):
    a, b = W.server_block(text)
    return text[a:b]


def listens(text):
    return re.findall(r'(?m)^\s*listen\s+[^\n]*', text)


class HandLoopback(unittest.TestCase):
    def test_loopback_line_of_the_admin_never_gets_it(self):
        self.assertNotEqual(HAND, SHIPPED)
        new = W.realip_into(HAND, PP)
        ls = listens(tls_block(new))
        lo = [x for x in ls if '127.0.0.1:443' in x]
        self.assertEqual(len(lo), 1, ls)                 # the admin's, no second of acme's
        self.assertNotIn('proxy_protocol', lo[0])
        self.assertTrue(any(re.search(r'listen\s+443 ssl http2 proxy_protocol;', x) for x in ls))
        # acme's own [::1] line still made for the IPv6 wildcard
        self.assertTrue(any('[::1]:443' in x and 'ACME-PROXY-LOCAL' in x for x in ls))
        self.assertEqual(W.realip_into(new, PP), new)
        self.assertEqual(W.realip_into(new, OFF), HAND)

    def test_given_it_before_is_cleaned(self):
        old = W.realip_into(HAND, PP).replace(
            'listen      127.0.0.1:443 ssl http2;',
            'listen      127.0.0.1:443 ssl http2 proxy_protocol;   # ACME-PROXY-PROTOCOL')
        again = W.realip_into(old, PP)
        lo = [x for x in listens(tls_block(again)) if '127.0.0.1:443' in x]
        self.assertEqual(lo, ['    listen      127.0.0.1:443 ssl http2;'])

    def test_shipped_unchanged(self):
        self.assertEqual(W.realip_into(W.realip_into(SHIPPED, PP), OFF), SHIPPED)

    def test_vip_server_one_listen_of_the_address(self):
        d = tempfile.mkdtemp(dir=TMP)
        saved = {k: getattr(W, k) for k in (
            'NGINX_MAIN', 'NGINX_VIP', 'NGINX_CERTLOGIN', 'CERTLOGIN_CA', 'NODE_FILES', 'VIP_FILES',
            'NO_SERVICES', 'tls_into', 'nonlocal_bind', 'dh_file')}
        try:
            W.NGINX_MAIN, W.NGINX_VIP = d + '/acme.conf', d + '/vip.conf'
            W.NGINX_CERTLOGIN, W.CERTLOGIN_CA = d + '/cl.conf', d + '/ca.pem'
            W.NODE_FILES = {k: d + '/node-' + k for k in W.NODE_FILES}
            W.VIP_FILES = {k: d + '/vip-' + k for k in W.VIP_FILES}
            W.NO_SERVICES = True
            W.tls_into = lambda block, t, files, had: (block, [], None)
            W.nonlocal_bind = lambda *a: ''
            W.dh_file = lambda *a: None
            with open(W.NGINX_MAIN, 'w') as f:
                f.write(HAND)
            W.nginx_part({'node': 'n1', 'tls_node': None, 'tls_vip': {'pem': {'x': 1}, 'dh': 'none'},
                          'vip': {'on': True, 'fqdn': 'vip.example', 'address': '192.0.2.9/24',
                                  'family': 4}, 'realip': PP}, {})
            with open(W.NGINX_VIP) as f:
                ls = listens(f.read())
        finally:
            for k, v in saved.items():
                setattr(W, k, v)
        self.assertEqual(len([x for x in ls if '192.0.2.9:443' in x]), 1, ls)
        self.assertIn('proxy_protocol', ls[0])
        self.assertFalse(any('127.0.0.1' in x for x in ls), ls)

    @unittest.skipUnless(shutil.which('nginx') and os.geteuid() == 0, 'nginx and root needed')
    def test_real_nginx_takes_the_hand_edit(self):
        d = tempfile.mkdtemp(prefix='ngx-', dir=TMP)
        subprocess.run(['openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '2',
                        '-keyout', d + '/k.key', '-out', d + '/c.pem', '-subj', '/CN=x'],
                       check=True, capture_output=True)
        import socket
        ports = []
        for _ in range(2):
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            ports.append(s.getsockname()[1])
            s.close()
        x = W.realip_into(HAND, PP)
        x = x.replace('/etc/nginx/certs/acme.pem', d + '/c.pem') \
            .replace('/etc/nginx/certs/acme.key', d + '/k.key').replace('/var/log/nginx', d)
        x = re.sub(r'(?m)^(\s*listen\s+)80;', r'\g<1>127.0.0.1:%d;' % ports[0], x)
        x = re.sub(r'(?m)^(\s*listen\s+(?:[0-9.]+:)?)443\b', r'\g<1>%d' % ports[1], x)
        if not os.path.exists('/proc/net/if_inet6'):
            x = re.sub(r'(?m)^\s*listen\s+\[[^\n]*\n', '', x)
        else:
            x = re.sub(r'(?m)^(\s*listen\s+\[[^\]]*\]:)443\b', r'\g<1>%d' % ports[1], x)
        with open(d + '/acme.conf', 'w') as f:
            f.write(x)
        if os.path.exists('/etc/nginx/fastcgi_params'):
            shutil.copy('/etc/nginx/fastcgi_params', d)
        else:
            open(d + '/fastcgi_params', 'w').close()
        with open(d + '/nginx.conf', 'w') as f:
            f.write('pid %s/n.pid; error_log %s/e.log; events {} http { include %s/acme.conf; }'
                    % (d, d, d))
        got = subprocess.run(['nginx', '-t', '-c', d + '/nginx.conf', '-p', d],
                             capture_output=True, text=True)
        self.assertEqual(got.returncode, 0, got.stderr)


# drawHaLb with a DOM of its own: the notes it shows (class, text) and the code blocks.
NODE_DRAW = r"""
const vm = require('vm'), fs = require('fs'), path = require('path');
const root = process.argv[2];
const src = fs.readFileSync(path.join(root, 'web', 'assets', 'admin.js'), 'utf8');
const a = src.indexOf('var LB_UI ='), b = src.indexOf('/* ---- signed in by a load balancer');
let notes = [], texts = [];
function N(tag, cls, text) { this.tag = tag; this.cls = cls || ''; this.kids = []; this.dataset = {};
  this.classList = {add() {}, toggle() {}}; this.text = text === undefined ? '' : String(text); }
N.prototype.appendChild = function (c) { this.kids.push(c); return c; };
N.prototype.querySelectorAll = () => [];
N.prototype.contains = () => false;
function all(n) { let s = n.text || ''; for (const k of n.kids) s += all(k); return s; }
const ctx = {console, Object, JSON, String, Number, Array,
  localStorage: {getItem: () => null, setItem() {}}, location: {hostname: 'acme1.example.cz'},
  document: {activeElement: null, createTextNode: (t) => new N('#t', '', t)},
  el: (t, c, x) => { const n = new N(t, c, x); if (x) texts.push(String(x)); return n; },
  noI18n: (n) => n, clear() {}, textBox: () => new N('input'), maskBox: () => new N('input'),
  cmdButton: () => new N('button'), copyText() {}, liveControl: () => false, showTab() {}, showPane() {}};
let host = new N('div');
ctx.$ = () => host;
vm.createContext(ctx);
vm.runInContext(src.slice(a, b) + ';this.drawHaLb = drawHaLb; this.LB_UI = LB_UI;', ctx);
const priv = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
const nodes = [{name: 'acme1', address: '10.0.0.11'}, {name: 'acme2', address: '10.0.0.12'}];
const cases = {
  pp_untrusted: ['pass', {access: {admin: {any: false, from: priv}}, trusted: ['10.0.0.99/32'], header: 'proxy_protocol', proxy_protocol: true}],
  pp_trusted: ['pass', {access: {admin: {any: false, from: priv}}, trusted: ['10.0.0.5/32'], header: 'proxy_protocol', proxy_protocol: true}],
  end_pp: ['end', {access: {admin: {any: false, from: priv}}, trusted: ['10.0.0.5/32'], header: 'proxy_protocol', proxy_protocol: true}],
  end_xff: ['end', {access: {admin: {any: false, from: priv}}, trusted: ['10.0.0.5/32'], header: 'X-Forwarded-For', proxy_protocol: false}],
  end_net: ['end', {access: {admin: {any: false, from: priv}}, trusted: ['10.0.0.0/28', '10.9.0.1/32'], header: 'X-Forwarded-For', proxy_protocol: false}],
  balancer: ['pass', {access: {admin: {any: false, from: priv}}, trusted: [], proxy_protocol: false}],
};
const out = {};
for (const [k, [tls, lb]] of Object.entries(cases)) {
  ctx.LB_UI.tls = tls; ctx.LB_UI.lb = '10.0.0.5';
  host = new N('div'); texts = [];
  ctx.drawHaLb({lb: Object.assign({}, lb, {certlogin: {on: false}, vip: {on: false}}), nodes});
  const trust = host.kids.find(n => n.cls === 'lb-trust');
  const list = host.kids.find(n => n.cls === 'lb-list');
  out[k] = {notes: trust.kids.filter(n => /^note/.test(n.cls)).map(n => [n.cls, all(n)]),
            blocks: trust.kids.filter(n => n.cls === 'lb-block').map(all),
            code: all(list), texts};
}
console.log(JSON.stringify(out));
"""

NODE_I18N = r"""
const vm = require('vm'), fs = require('fs'), path = require('path');
const root = process.argv[2];
const all = JSON.parse(fs.readFileSync(path.join(root, 'web', 'lang', 'cs.json'), 'utf8'));
const pack = {code: 'cs', strings: {}, patterns: [], rich: {}};
for (const part of ['strings', 'patterns', 'rich']) for (const e of Object.values(all[part] || {})) {
  const from = String(e.source || ''), to = String(e.text || '');
  if (!from || !to || (to === from && part !== 'patterns')) continue;
  if (part === 'patterns') pack.patterns.push([from, to]); else pack[part][from] = to;
}
const ctx = {window: {}, Map, Set, WeakMap, console, ACME_LANG_PACK: pack,
  document: {readyState: 'loading', addEventListener() {}, documentElement: {setAttribute() {}, classList: {remove() {}}},
             querySelectorAll: () => [], createTreeWalker() { return {nextNode: () => null}; }},
  MutationObserver: function () { this.observe = () => {}; this.takeRecords = () => []; }, setTimeout: () => {}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(root, 'web', 'assets', 'i18n.js'), 'utf8')
                + ';this.i18nText = i18nText; this.i18nInit = i18nInit;', ctx);
ctx.i18nInit(pack);
const out = {};
for (const s of JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))) out[s] = ctx.i18nText(s);
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which('node'), 'node needed')
class Guide(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = os.path.join(TMP, 'draw.js')
        with open(p, 'w') as f:
            f.write(NODE_DRAW)
        cls.out = json.loads(subprocess.run(['node', p, ROOT], capture_output=True, text=True,
                                            check=True).stdout)

    def exposure(self, k):
        return [n for n in self.out[k]['notes'] if 'administration pages' in n[1]][0]

    def test_pp_from_a_balancer_not_named_is_no_proxy(self):
        cls, words = self.exposure('pp_untrusted')
        self.assertEqual(cls, 'note crit', words)
        self.assertIn('is among those who may reach the administration pages', words)
        self.assertEqual(self.exposure('pp_trusted')[0], 'note good')

    def test_ended_while_443_takes_only_proxy(self):
        n = self.out['end_pp']['notes'][0]
        self.assertEqual(n[0], 'note bad')
        self.assertIn('Set the header back to X-Forwarded-For', n[1])
        self.assertTrue(any('web_proxy_header=X-Forwarded-For' in b for b in self.out['end_pp']['blocks']))
        self.assertNotIn('already take the client', ''.join(x[1] for x in self.out['end_pp']['notes']))
        self.assertEqual(self.out['end_xff']['notes'][0][0], 'note good')

    def test_balancer_in_a_network_named_is_trusted(self):
        n = self.out['end_net']['notes'][0]
        self.assertEqual(n[0], 'note good', n)
        self.assertFalse(self.out['end_net']['blocks'])

    def test_portal_only_blocks(self):
        code = self.out['end_xff']['code']
        # HAProxy, F5 and NetScaler match the path as sent: /assets/../admin/ refused there
        self.assertIn('http-request deny deny_status 404 if { path_sub /. % }', code)
        self.assertIn('[HTTP::path] contains "/." or [HTTP::path] contains "%"', code)
        self.assertIn('HTTP.REQ.URL.PATH.CONTAINS(\\"/.\\")', code)
        # /pki/ on port 80 not sent to HTTPS (HAProxy, nginx)
        self.assertIn('redirect scheme https unless { ssl_fc } || { path_beg /pki/ }', code)
        self.assertRegex(code, r'listen 10\.0\.0\.5:80;\n[^}]*location /pki/ \{\n\s+proxy_pass https://acme_nodes;')
        # still nothing of the administration let through
        self.assertIn('http-request deny deny_status 404 unless acme_portal', code)

    def test_red_line_in_czech(self):
        texts = [t for t in self.out['balancer']['texts'] if 'is among those' in t]
        self.assertEqual(len(texts), 1)
        p = os.path.join(TMP, 'i18n.js')
        with open(p, 'w') as f:
            f.write(NODE_I18N)
        q = os.path.join(TMP, 'texts.json')
        with open(q, 'w') as f:
            json.dump(texts, f)
        got = json.loads(subprocess.run(['node', p, ROOT, q], capture_output=True, text=True,
                                        check=True).stdout)
        self.assertNotEqual(got[texts[0]], texts[0])
        self.assertIn('10.0.0.5', got[texts[0]])


if __name__ == '__main__':
    unittest.main(verbosity=2)
