// Target agents in the administration pages (agents.js, 1.0.116) - the pane Settings → Target
// agents, the agent's card on a target, its join wizard, and what a deployment needs of the
// agent's policy, drawn in a page of their own with the API answered here (no daemon).
//
//   node test/agents_page.js /path/to/web [cs-extra.json] [screenshot-folder]
//
// cs-extra.json: {English: Czech}, added to web/lang/cs.json for the Czech pages.
//
// In English and in Czech, at 1400 and 420 px:
// * the pane, active mode off: the hero says so, no endpoints; the package tile (name, version,
//   size, the badge, the SHA-256), the four install lines each with Copy; the authority's
//   fingerprint in groups; the tiles of the agents (state, mode, version, last heard, the end of
//   the certificate amber under 14 days, the policy's chips);
// * active mode on: the port and what the agents are given;
// * the card of a joined agent: its state, its policy (folders, units, tests, scripts), Join
//   again / Ask it now / Renew / Forget; an agent waiting to be confirmed: its fingerprint in
//   sixteen groups and "It is the same - confirm" (POST agents/confirm with that fingerprint);
// * the wizard: three steps on the rail, Make the join code (POST agents/code), the code and the
//   command with Copy, then the fingerprint to confirm;
// * a deployment's needs: allowed (green), needed (red, with the sudo line to copy), unknown;
// * nothing wider than the page; in Czech nothing of it left in English that has a translation.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const extra = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf-8')) : {};
  const shots = process.argv[4] || '';
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const ui = read('admin/certs-ui.php');
  const cut = (text, from, to) => { const i = text.indexOf(from); return text.slice(i, text.indexOf(to, i)); };
  const paneHtml = cut(ui, '<div class="ctl-pane" id="pane-agents"', '<div class="ctl-pane" id="pane-dnssrv"')
    .replace('class="ctl-pane" id="pane-agents" hidden', 'class="ctl-pane" id="pane-agents"');
  const index = read('admin/index.php');
  const modalHtml = cut(index, '<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const fold = (s) => String(s).replace(/\s+/g, ' ').trim();
  const WORDS = ['acme proposes, the server decides', 'active mode off', 'The agent to install', 'Download', 'Copy',
    'acme’s agent authority', 'Targets with an agent', 'Last heard', 'Its certificate ends', 'Server', 'Agent',
    'answers', 'not heard from', 'passive', 'active', 'What its policy allows', 'Folders', 'Units', 'Tests and commands',
    'Join again…', 'Ask it now', 'Renew its certificate', 'Forget…', 'An agent asks to join', 'It is the same - confirm',
    'Install the agent', 'The join code', 'Confirm the fingerprint', 'Make the join code', 'The agent’s policy',
    'needs more on the server', 'Copy all the lines', 'On the server, as root', 'signed by acme’s release key'];
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const POL = {hash: 'ab'.repeat(32), files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o640}],
    units: {'nginx.service': ['reload', 'restart']}, tests: [['nginx', '-t']], scripts: [],
    script_hashes: ['cd'.repeat(32)], from: ['192.0.2.10/32'], problems: []};
  const FP = '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7';
  const VIEW = {
    active: false, port: 8444, endpoints: [], node: 'acme1', nginx: null, shipped_code: 'c0de',
    ca: {fp: '9b'.repeat(32), end: now + 3650 * 86400, at: now - 86400},
    package: {name: 'acme-agent-1.0.116.tar.gz', version: '1.0.116', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', size: 41234, signed: true},
    commands: ['sha256sum acme-agent-1.0.116.tar.gz', 'tar xzf acme-agent-1.0.116.tar.gz', 'cd acme-agent-1.0.116 && sudo ./install.sh', 'sudo acme-agent join CODE'],
    rows: [
      {id: 1, name: 'web1', mode: 'passive', state: 'answers', host: 'web1.example.com', agent_host: 'web1', version: '1.0.116', code_hash: 'c0de',
       last_seen: now - 12, cert_end: now + 25 * 86400, policy_summary: {files: 1, units: 1, tests: 1, scripts: 1, from: 1, problems: 0}},
      {id: 2, name: 'mail-gw', mode: 'active', state: 'quiet', host: '', agent_host: 'mx1.example.com', version: '1.0.116', code_hash: 'c0de',
       last_seen: now - 3600, cert_end: now + 6 * 86400, policy_summary: {files: 2, units: 2, tests: 0, scripts: 0, from: 0, problems: 1},
       last_error: 'the agent did not ask for the job in 90 s'},
      {id: 3, name: 'new-box', mode: 'passive', state: 'joining', host: '10.1.2.3', version: '', last_seen: null, cert_end: null, policy_summary: null}]
  };
  const ONE = {id: 1, name: 'web1', mode: 'passive', state: 'answers', joined: true, agent_id: 'ag-1234567890abcdef', host: 'web1.example.com',
    agent_host: 'web1', version: '1.0.116', code_hash: 'c0de', shipped_code: 'c0de', os: 'Rocky Linux 9.4 (Blue Onyx)', last_seen: now - 12,
    cert_end: now + 25 * 86400, key_fp: FP, policy: POL, policy_at: now - 300, pending: null, package: VIEW.package, commands: VIEW.commands,
    ca: VIEW.ca, port: 8444};
  const NEEDS = {state: 'answers', policy_hash: POL.hash, items: [
    {kind: 'file', label: 'file', what: '/etc/nginx/ssl/site.crt  0644 root:root', ok: true, allow: ''},
    {kind: 'file', label: 'file', what: '/etc/nginx/ssl/site.key  0600 root:root', ok: true, allow: ''},
    {kind: 'test', label: 'test', what: 'nginx -t', ok: true, allow: ''},
    {kind: 'reload', label: 'reload', what: 'systemctl reload nginx', ok: false, allow: 'acme-agent allow unit nginx.service reload'},
    {kind: 'script', label: 'the script written here', what: 'sha256 4f1c09aa…', ok: false, allow: 'acme-agent allow script-hash ' + '4f'.repeat(32)},
    {kind: 'post', label: 'after', what: '/usr/local/bin/notify.sh', ok: null, allow: 'acme-agent allow script /usr/local/bin/notify.sh'}]};
  let packStrings = {};
  try {
    for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 420], ['cs', 420]]) {
      let pack = 'null';
      if (lang === 'cs') {
        const all = JSON.parse(read('lang/cs.json'));
        const pk = {code: 'cs', strings: {}, patterns: [], rich: {}};
        for (const part of ['strings', 'patterns', 'rich']) {
          for (const e of Object.values(all[part] || {})) {
            if (!e || !e.source || !e.text || e.text === e.source) continue;
            if (part === 'patterns') pk.patterns.push([e.source, e.text]); else pk[part][e.source] = e.text;
          }
        }
        for (const k of Object.keys(extra)) {
          if (/\{\d/.test(k)) pk.patterns.push([k, extra[k]]); else pk.strings[k] = extra[k];
        }
        packStrings = {};
        for (const k of Object.keys(pk.strings)) packStrings[fold(k)] = pk.strings[k];
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
        + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div><div id="needs-host"></div></main>' + modalHtml
        + '<div class="toast" id="toast"></div>'
        + '<script>' + esc(read('assets/i18n.js')) + '</script>'
        + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = [];'
        + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONE = ' + JSON.stringify(ONE) + '; var NEEDS = ' + JSON.stringify(NEEDS) + ';</script>'
        + '<script>' + esc(read('assets/core.js')) + '</script>'
        + '<script>' + esc(read('assets/agents.js')) + '</script>'
        + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
        + ' var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
        + ' if (what === "agents") return c(VIEW);'
        + ' if (what.indexOf("agents/one") === 0) return c(ONE);'
        + ' if (what === "agents/look") return c({agent: ONE});'
        + ' if (what === "agents/code") return c({code: "ACAG1.eyJ2IjoxLCJ0IjoxLCJuIjoid2ViMSIsIm0iOiJwYXNzaXZlIiwiaSI6IjBhMWIyYzNkNGU1ZiIsInMiOiJ4eHh4In0", until: Date.now() / 1000 + 3600, mode: "passive", ca_fp: VIEW.ca.fp, endpoints: [], port: 8446, agent: ONE});'
        + ' if (what === "agents/confirm") return c({agent: Object.assign({}, ONE, {pending: null})});'
        + ' return c({}); }, over: function (open) { open(); }, openTarget: function (n) { window.OPENED = n; }});</script>'
        + '</body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}, deviceScaleFactor: 2});
      page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
      await page.setContent(html);
      await page.waitForTimeout(150);
      const tag = lang + width + '_';
      // ---- the pane, active mode off
      await page.evaluate(() => ACME_AGENTS.pane());
      await page.waitForTimeout(200);
      out.checks[tag + 'pane_off'] = await page.evaluate(() => {
        var h = document.getElementById('ag-hero');
        return !!h.querySelector('.dbs-hero') && !h.querySelector('.ag-eps') && h.querySelectorAll('.ag-mode').length === 2
          && !!h.querySelector('.dbs-state') && !h.querySelector('.dbs-state.ok');
      });
      out.checks[tag + 'package'] = await page.evaluate(() => {
        var p = document.getElementById('ag-pkg');
        return p.querySelector('.ag-pkg-name').textContent === 'acme-agent-1.0.116.tar.gz' && !!p.querySelector('.ag-badge.ok')
          && p.querySelector('.ag-sha-v').textContent.length === 64 && p.querySelectorAll('.ag-cmd').length === 4
          && p.querySelectorAll('.ag-cmd .btn').length === 4 && !!p.querySelector('.btn.primary');
      });
      out.checks[tag + 'authority'] = await page.evaluate(() => document.querySelectorAll('#ag-ca .ag-fp-g').length === 16);
      out.checks[tag + 'tiles'] = await page.evaluate(() => {
        var t = document.querySelectorAll('#ag-list .ag-tile');
        if (t.length !== 3) return false;
        return !!t[0].querySelector('.dbs-state.ok') && !!t[1].querySelector('.dbs-state.warn') && !!t[1].querySelector('.ag-end.warn')
          && t[0].querySelectorAll('.ag-chip').length === 4 && !!t[1].querySelector('.ag-chip.bad') && !!t[2].querySelector('.ag-chip.unk')
          && !!t[1].querySelector('.ag-mode.active') && !!t[0].querySelector('.ag-mode.passive');
      });
      await page.evaluate(() => document.querySelector('#ag-list .ag-name').click());
      out.checks[tag + 'open_target'] = await page.evaluate(() => window.OPENED === 'web1');
      out.checks[tag + 'pane_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#pane-agents').screenshot({path: path.join(shots, 'pane-off-' + lang + width + '.png')});
      // ---- active mode on
      await page.evaluate(() => { VIEW.active = true; VIEW.nginx = {port: 8444}; VIEW.endpoints = ['acme.example.com:8444', '192.0.2.11:8444', '192.0.2.12:8444']; return ACME_AGENTS.pane(); });
      await page.waitForTimeout(200);
      out.checks[tag + 'pane_on'] = await page.evaluate(() => {
        var h = document.getElementById('ag-hero');
        return !!h.querySelector('.dbs-hero.good') && !!h.querySelector('.dbs-state.ok') && h.querySelectorAll('.ag-ep').length === 3
          && h.querySelector('.ag-port').textContent === '8444';
      });
      if (shots) await page.locator('#ag-hero').screenshot({path: path.join(shots, 'pane-on-' + lang + width + '.png')});
      // ---- the card of a joined agent
      await page.evaluate(() => { document.getElementById('card-host').appendChild(ACME_AGENTS.card({id: 1, name: 'web1'})); });
      await page.waitForTimeout(200);
      out.checks[tag + 'card'] = await page.evaluate(() => {
        var c = document.querySelector('#card-host .ag-card');
        return !!c && !!c.querySelector('.dbs-state.ok') && c.querySelectorAll('.ag-pol-g').length === 5 && c.querySelectorAll('.ag-verb').length === 2
          && c.querySelectorAll('.ag-acts .btn').length === 4 && !c.querySelector('.ag-confirm');
      });
      out.checks[tag + 'card_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#card-host .ag-card').screenshot({path: path.join(shots, 'card-' + lang + width + '.png')});
      // ---- an agent waiting to be confirmed
      await page.evaluate(() => {
        ONE.pending = {fp: '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7', host: 'web1', version: '1.0.116', confirmed: false, at: Date.now() / 1000};
        ONE.joined = false; ONE.state = 'joining'; ONE.policy = null; ONE.version = ''; ONE.last_seen = null; ONE.cert_end = null;
        var h = document.getElementById('card-host'); h.innerHTML = '';
        h.appendChild(ACME_AGENTS.card({id: 1, name: 'web1'}));
      });
      await page.waitForTimeout(200);
      out.checks[tag + 'confirm_box'] = await page.evaluate(() => {
        var b = document.querySelector('#card-host .ag-confirm');
        return !!b && b.querySelectorAll('.ag-fp-g').length === 16 && b.querySelector('.ag-fp').textContent.indexOf('3F9A') === 0;
      });
      if (shots) await page.locator('#card-host .ag-card').screenshot({path: path.join(shots, 'confirm-' + lang + width + '.png')});
      await page.evaluate(() => document.querySelector('#card-host .ag-confirm .btn.primary').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'confirm_sent'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/confirm' && x[1].fp === ONE.pending.fp && x[1].id === 1; }));
      // ---- the wizard
      await page.evaluate(() => { ONE.pending = null; ONE.joined = false; ONE.state = 'new'; ACME_AGENTS.wizard({id: 1, name: 'web1'}, ONE, function () {}); });
      await page.waitForTimeout(250);
      out.checks[tag + 'wizard_1'] = await page.evaluate(() => {
        var m = document.getElementById('modal-body');
        return !document.getElementById('modal').hidden && m.querySelectorAll('.dbw-rail li').length === 3 && !!m.querySelector('.dbw-rail li.on')
          && m.querySelectorAll('.ag-cmd').length === 3 && !!m.querySelector('.ag-pkg');
      });
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'wizard1-' + lang + width + '.png')});
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(250);
      out.checks[tag + 'wizard_2'] = await page.evaluate(() => {
        var m = document.getElementById('modal-body');
        return SENT.some(function (x) { return x[0] === 'agents/code'; }) && !!m.querySelector('.ag-code pre')
          && m.querySelector('.ag-code pre').textContent.indexOf('ACAG1.') === 0 && m.querySelectorAll('.dbw-rail li.done').length === 1
          && m.querySelector('.ag-cmd pre').textContent.indexOf('sudo acme-agent join ACAG1.') === 0;
      });
      out.checks[tag + 'wizard_fits'] = await page.evaluate(() => document.getElementById('modal-box').scrollWidth <= document.getElementById('modal-box').clientWidth + 1);
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'wizard2-' + lang + width + '.png')});
      await page.evaluate(() => { ONE.pending = {fp: '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7', host: 'web1', version: '1.0.116', confirmed: false}; });
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(1200);
      out.checks[tag + 'wizard_3'] = await page.evaluate(() => {
        var m = document.getElementById('modal-body');
        return m.querySelectorAll('.dbw-rail li.done').length === 2 && !!m.querySelector('.ag-confirm') && m.querySelectorAll('.ag-fp-g').length === 16;
      });
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'wizard3-' + lang + width + '.png')});
      await page.evaluate(() => { ONE.pending = null; ONE.joined = true; ONE.state = 'answers'; ONE.policy = VIEW.rows && ONE.policy || null; ONE.code_until = null; });
      await page.evaluate(() => closeModal());
      // ---- a deployment's needs
      await page.evaluate(() => { var t = document.getElementById('toast'); if (t) t.remove(); document.getElementById('pane-agents').hidden = true; document.getElementById('card-host').hidden = true;
        document.getElementById('needs-host').appendChild(ACME_AGENTS.needs(NEEDS)); });
      out.checks[tag + 'needs'] = await page.evaluate(() => {
        var n = document.querySelector('#needs-host .ag-needs');
        return n.querySelectorAll('.ag-need.ok').length === 3 && n.querySelectorAll('.ag-need.bad').length === 2 && n.querySelectorAll('.ag-need.unk').length === 1
          && n.querySelectorAll('.ag-need.bad .ag-cmd pre')[0].textContent === 'sudo acme-agent allow unit nginx.service reload'
          && !!n.querySelector('.ag-badge.bad') && !!n.querySelector('.ag-needs-all .btn');
      });
      out.checks[tag + 'needs_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#needs-host .ag-needs').screenshot({path: path.join(shots, 'needs-' + lang + width + '.png')});
      if (lang === 'cs') {
        const text = await page.evaluate(() => document.body.innerText);
        const left = WORDS.filter((w) => packStrings[fold(w)] === undefined || (text.indexOf(w) >= 0 && packStrings[fold(w)] !== w));
        out.checks[tag + 'czech'] = !left.length;
        if (left.length) out['left_' + tag] = left;
      }
      await page.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
