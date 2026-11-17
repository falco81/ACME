#!/usr/bin/env python3
"""Hunt R1 in acme's side of the target agents (acmelib/certs/agents.py, web/assets/agents.js):

    python3 test/test_hunt_r1_agentsacme.py

* an agent confirmed a second time (two people, a page not drawn again, an item twice in
  confirm-many) was signed a new certificate: the one an active agent had taken already
  (join/status) no longer let in - its first poll refused, the agent locked out;
* a refused enrollment request wrote back the enrollment code as it was read before - a
  revocation made meanwhile undone;
* shipped_codes() read and hashed acme_agent.py for every agent of the pages' list;
* "Update all agents" and the card of a Windows agent showed `sudo acme-agent allow
  self-update` (no sudo on Windows) - update_candidates says each agent's platform now;
  the pages in a browser (node with playwright; skipped without).

No agent processes, no network: temporary folders only.
"""
import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-huntr1ag-')
os.chmod(TMP, 0o755)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, store as S, agents as G  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
S.registry()


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def target(name, kind='agent', **cfg):
    rid = A.family_save(STORE, 'target', {'name': name, 'kind': kind, 'config': cfg,
                                         'enabled': 1}, 'tester')
    return S.plugin_row(STORE, 'target', rid)


def new_key():
    k = os.path.join(TMP, 'k-%s.pem' % secrets.token_hex(4))
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                    'ec_paramgen_curve:P-256', '-out', k], check=True, capture_output=True)
    return k


def join_req(c, secret, key, enc):
    csr = subprocess.run(['openssl', 'req', '-new', '-key', key, '-subj', '/CN=acme-agent'],
                         check=True, capture_output=True, text=True).stdout
    nonce = secrets.token_hex(16)
    return {'i': c['id'], 'csr': csr, 'enc_pub': enc, 'nonce': nonce, 'host': 'vm1',
            'version': '1.0.124',
            'proof': G.proof(secret, 'join', c['id'], hashlib.sha256(csr.encode()).hexdigest(),
                             enc, nonce)}


def status_req(c, secret):
    nonce = secrets.token_hex(16)
    return {'i': c['id'], 'nonce': nonce, 'proof': G.proof(secret, 'status', c['id'], nonce)}


class ConfirmedTwice(unittest.TestCase):
    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_names'] = '127.0.0.1:18444'

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0
        E.CONFIG['certs_agents_names'] = ''

    def joined(self, name):
        row = target(name, mode='active')
        G.code_new(STORE, row, 'tester')
        st = G.state(STORE, row['id'])
        c = st['code']
        secret = E.unseal_secret(c['secret'], G.M_T(row['id']) + ':code')
        key, enc = new_key(), base64.b64encode(secrets.token_bytes(32)).decode()
        self.assertEqual(G.wire(STORE, 'join', join_req(c, secret, key, enc), '', '')[0], 200)
        return row, c, secret, G.state(STORE, row['id'])['pending']['fp']

    def test_second_confirm_keeps_the_certificate_taken(self):
        row, c, secret, fp = self.joined('r1-twice')
        G.confirm(STORE, row, fp, 'anna')
        got = G.wire(STORE, 'status', status_req(c, secret), '', '')
        self.assertEqual(got[1].get('state'), 'done', got)
        taken = got[1]['cert_pem']
        cert_fp = G.state(STORE, row['id'])['cert_fp']
        # a second person (a page not drawn again) confirms it too
        G.confirm(STORE, row, fp, 'petr')
        st = G.state(STORE, row['id'])
        self.assertEqual(st['cert_fp'], cert_fp)
        self.assertEqual(st['pending']['cert'], taken)
        # the agent's first poll with the certificate it took: let in
        with mock.patch.object(G, 'HOLD_MOST', 0):
            got = G.wire(STORE, 'poll', {'results': [0]}, taken, 'SUCCESS')
        self.assertEqual(got[0], 200, got)
        self.assertEqual(G.info(STORE, row)['state'], 'answers')
        # a wrong fingerprint is still refused
        row2, _c, _s, _fp = self.joined('r1-twice-wrong')
        with self.assertRaises(G.PluginError):
            G.confirm(STORE, row2, 'ab' * 32, 'anna')

    def test_confirm_many_the_same_item_twice(self):
        row, c, secret, fp = self.joined('r1-many')
        got = G.confirm_many(STORE, [{'id': row['id'], 'fp': fp}, {'id': row['id'], 'fp': fp}],
                             'anna')
        self.assertTrue(all(x['ok'] for x in got), got)
        cert = G.state(STORE, row['id'])['pending']['cert']
        got = G.wire(STORE, 'status', status_req(c, secret), '', '')
        self.assertEqual(got[1]['cert_pem'], cert)
        self.assertEqual(G.fp_of_pem(cert), G.state(STORE, row['id'])['cert_fp'])
        signed = [r for r in STORE.db.rows("SELECT words FROM events WHERE words LIKE ?",
                                           ('the agent of target r1-many was confirmed%',))]
        self.assertEqual(len(signed), 1)


class EnrollRefused(unittest.TestCase):
    def setUp(self):
        E.CONFIG['certs_agents_active'] = 1
        E.CONFIG['certs_agents_names'] = '127.0.0.1:18444'

    def tearDown(self):
        E.CONFIG['certs_agents_active'] = 0
        E.CONFIG['certs_agents_names'] = ''

    def test_refusal_does_not_undo_a_revocation(self):
        made = G.enroll_new(STORE, 'tester', title='R1 race', mode='active')
        stale = G.enroll_get(STORE, made['id'])          # read by a request being checked
        G.enroll_revoke(STORE, made['id'], 'anna')       # meanwhile revoked
        G._enroll_refused(STORE, stale, '192.0.2.9', 'its request does not prove the code')
        ec = G.enroll_get(STORE, made['id'])
        self.assertTrue(ec.get('revoked'), ec)
        self.assertEqual(G.enroll_state(ec), 'revoked')
        self.assertTrue(ec.get('refused_at'))
        # and a request with a wrong proof through the wire: still revoked
        body = {'e': made['id'], 'csr': 'x', 'enc_pub': 'x', 'nonce': '0' * 32, 'proof': 'x'}
        with mock.patch('time.time', return_value=float(ec['refused_at']) + 120):
            self.assertEqual(G.wire(STORE, 'enroll', body, '', 'NONE')[0], 403)
        self.assertEqual(G.enroll_state(G.enroll_get(STORE, made['id'])), 'revoked')


class ShippedAndUpdates(unittest.TestCase):
    def test_shipped_codes_kept(self):
        first = G.shipped_codes()
        self.assertTrue(first)
        real = open
        seen = []

        def counting(path, *a, **k):
            if str(path).endswith('acme_agent.py'):
                seen.append(path)
            return real(path, *a, **k)
        with mock.patch('builtins.open', counting):
            for _ in range(5):
                self.assertEqual(G.shipped_codes(), first)
        self.assertEqual(seen, [])

    def test_update_candidates_say_the_platform(self):
        lin = target('r1-upd-lin', mode='passive', host='192.0.2.1')
        win = target('r1-upd-win', kind='agent_windows', mode='passive', host='192.0.2.2')
        for r in (lin, win):
            st = G.state(STORE, r['id'])
            st.update(cert_fp='ab' * 32, version='1.0.100', agent_id='ag-' + 'a' * 16)
            G.state_put(STORE, r['id'], st)
        got = {x['name']: x for x in G.update_candidates(STORE)}
        self.assertEqual(got['r1-upd-lin']['platform'], 'linux')
        self.assertEqual(got['r1-upd-win']['platform'], 'windows')


PAGE = r'''
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
(async () => {
  const web = process.argv[2];
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const ui = read('admin/certs-ui.php');
  const cut = (t, a, b) => { const i = t.indexOf(a); return t.slice(i, t.indexOf(b, i)); };
  const paneHtml = cut(ui, '<div class="ctl-pane" id="pane-agents"', '<div class="ctl-pane" id="pane-dnssrv"').replace('class="ctl-pane" id="pane-agents" hidden', 'class="ctl-pane" id="pane-agents"');
  const modalHtml = cut(read('admin/index.php'), '<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const upd = {offered: '1.0.124', newer: true, allowed: false, signed: true};
  const base = {mode: 'passive', state: 'answers', joined: true, version: '1.0.121', last_seen: now - 5, cert_end: now + 9e5, policy: null, pending: null, update: upd, agent_id: 'ag-1'};
  const ONES = {1: Object.assign({id: 1, name: 'lin1', kind: 'agent', platform: 'linux'}, base), 2: Object.assign({id: 2, name: 'win1', kind: 'agent_windows', platform: 'windows'}, base)};
  const VIEW = {active: false, port: 8444, endpoints: [], rows: [ONES[1], ONES[2]], package: null, ca: null};
  const UPD = {rows: [{id: 1, name: 'lin1', platform: 'linux', version: '1.0.121', offered: '1.0.124', ok: false, why: 'its policy has no allow self-update'},
    {id: 2, name: 'win1', platform: 'windows', version: '1.0.121', offered: '1.0.124', ok: false, why: 'its policy has no allow self-update'}]};
  const html = '<!doctype html><html><head><meta charset="utf-8">'
    + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/agents.css') + '</style>'
    + '<script>window.ACME_LANG_PACK = null;</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div></main>' + modalHtml + '<div class="toast" id="toast"></div>'
    + '<script>' + esc(read('assets/i18n.js')) + '</script>'
    + '<script>var ME = {name: "t", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var VIEW = ' + JSON.stringify(VIEW) + '; var ONES = ' + JSON.stringify(ONES) + '; var UPD = ' + JSON.stringify(UPD) + ';</script>'
    + '<script>' + esc(read('assets/core.js')) + '</script><script>' + esc(read('assets/agents.js')) + '</script>'
    + '<script>ACME_AGENTS.init({capi: function (what, body) { var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
    + ' if (what === "agents") return c(VIEW); if (what === "agents/updates") return c(UPD); if (what.indexOf("agents/one") === 0) return c(ONES[what.split("id=")[1]]);'
    + ' return c({}); }, over: function (open) { open(); }});</script></body></html>';
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({viewport: {width: 1200, height: 900}});
    page.on('pageerror', (e) => out.errors.push(String(e)));
    await page.setContent(html);
    await page.waitForTimeout(150);
    const lines = () => page.evaluate(() => Array.prototype.map.call(document.querySelectorAll('#card-host .ag-upd pre'), (p) => p.textContent));
    for (const id of [1, 2]) {
      await page.evaluate((i) => { var h = document.getElementById('card-host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.card({id: i, name: ONES[i].name, kind: ONES[i].kind})); }, id);
      await page.waitForTimeout(250);
      out.checks['card' + id] = JSON.stringify(await lines()) === JSON.stringify([id === 2 ? 'acme-agent allow self-update' : 'sudo acme-agent allow self-update']);
    }
    await page.evaluate(() => ACME_AGENTS.pane());
    await page.waitForTimeout(250);
    await page.evaluate(() => Array.prototype.filter.call(document.querySelectorAll('#pane-agents button'), (b) => /Update all agents/.test(b.textContent))[0].click());
    await page.waitForTimeout(250);
    const all = await page.evaluate(() => Array.prototype.map.call(document.querySelectorAll('#modal .ag-upd-one'), (r) => [r.querySelector('b').textContent, (r.querySelector('pre') || {}).textContent]));
    out.checks.update_all = JSON.stringify(all) === JSON.stringify([['lin1', 'sudo acme-agent allow self-update'], ['win1', 'acme-agent allow self-update']]);
    if (!out.checks.update_all) out.errors.push(JSON.stringify(all));
  } catch (e) { out.error = String(e && e.stack || e); }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
'''


class Pages(unittest.TestCase):
    def test_self_update_line_of_a_windows_agent(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        js = os.path.join(TMP, 'page.js')
        with open(js, 'w') as f:
            f.write(PAGE)
        got = subprocess.run([node, js, os.path.join(ROOT, 'web')], capture_output=True,
                             text=True, timeout=300, cwd=HERE)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


if __name__ == '__main__':
    unittest.main(verbosity=2)
