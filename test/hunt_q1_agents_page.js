// Hunt Q1 (1.0.119) - the target agents' pages (agents.js) and the policy builder
// (policybuilder.js) in a browser, beside test/agents_page.js:
//
//   node test/hunt_q1_agents_page.js /path/to/web
//
// * a command typed with an open quotation: its row red and its line left out of the file (the
//   line before it stood in the file, the badge said "the agent takes all of it"); not saved;
// * a limit emptied: no "NaN KiB";
// * a template clicked in a search: the search stays (and the template it was);
// * the output's tabs say which is selected (aria-selected);
// * what was clicked together (a template) asked about before Escape takes it; nothing changed or
//   copied: Escape closes at once;
// * an earlier version of the design saved without its state (the command line) opens with its
//   lines, not empty; after a save "Start from" offers the saved design;
// * a tile's Update clicked twice sends the agent one update;
// * the wizard confirmed while it was asking: one round of asking, not two side by side;
// * the wizard's rail at 375 px: no step's words over the next step - in English and in Czech.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const ui = read('admin/certs-ui.php');
  const cut = (text, from, to) => { const i = text.indexOf(from); return text.slice(i, text.indexOf(to, i)); };
  const paneHtml = cut(ui, '<div class="ctl-pane" id="pane-agents"', '<div class="ctl-pane" id="pane-dnssrv"')
    .replace('class="ctl-pane" id="pane-agents" hidden', 'class="ctl-pane" id="pane-agents"');
  const modalHtml = cut(read('admin/index.php'), '<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const HEAD = '# acme-agent policy\n';
  const POL = {files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o640}], units: {'nginx.service': ['reload']},
    tests: [['nginx', '-t']], scripts: [], script_hashes: [], from: [], problems: []};
  const ONE = {id: 1, name: 'web1', mode: 'passive', state: 'answers', joined: true, agent_id: 'ag-1', host: 'web1.example.com', version: '1.0.116',
    last_seen: now - 12, cert_end: now + 25 * 86400, policy: POL, policy_at: now, pending: null, commands: ['a', 'b', 'c', 'd'],
    package: {name: 'acme-agent-1.0.116.tar.gz', sha256: 'e3'.repeat(32)}};
  const VIEW = {active: false, port: 8444, endpoints: [], nginx: null, ca: null, package: null, commands: [], rows: [
    {id: 2, name: 'mail-gw', mode: 'active', state: 'answers', version: '1.0.115', last_seen: now - 5, update: {offered: '1.0.116', newer: true, allowed: true, signed: true}}]};
  const FACTS = {protected: ['/etc/sudoers.d'], parts: ['.ssh'], own: ['/etc/acme-agent'], verbs: ['reload', 'restart'], shells: ['sh', 'bash'],
    config_ok: ['/etc/ssl'], head: HEAD, limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}};
  const TPL = [
    {key: 'nginx', title: 'nginx', group: 'Web servers', files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o644}], units: {'nginx.service': ['reload']}, tests: [['nginx', '-t']], scripts: [], probe_local: true},
    {key: 'postfix', title: 'Postfix', group: 'Mail', files: [{dir: '/etc/postfix/ssl', owner: 'root', group: 'root', mode: 0o644}], units: {}, tests: [['postfix', 'check']], scripts: [], probe_local: true},
    {key: 'haproxy', title: 'HAProxy', group: 'Proxies', files: [{dir: '/etc/haproxy/certs', owner: 'root', group: 'root', mode: 0o600}], units: {'haproxy.service': ['reload']}, tests: [], scripts: [], probe_local: true}];
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const build = (pack) => '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
    + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
    + '<style>' + read('assets/policybuilder.css') + '</style>'
    + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div></main>' + modalHtml
    + '<div class="toast" id="toast"></div>'
    + '<script>' + esc(read('assets/i18n.js')) + '</script>'
    + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = []; var SLOW = 0;'
    + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONE = ' + JSON.stringify(ONE) + '; var FACTS = ' + JSON.stringify(FACTS) + ';'
    + ' var TPL = ' + JSON.stringify(TPL) + '; var SAVED = null;</script>'
    + '<script>' + esc(read('assets/core.js')) + '</script>'
    + '<script>' + esc(read('assets/agents.js')) + '</script>'
    + '<script>' + esc(read('assets/policybuilder.js')) + '</script>'
    + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null, Date.now()]);'
    + ' var c = function (x) { var v = JSON.parse(JSON.stringify(x)); return SLOW ? new Promise(function (r) { setTimeout(function () { r(v); }, SLOW); }) : Promise.resolve(v); };'
    + ' if (what === "agents") return c(VIEW);'
    + ' if (what.indexOf("agents/one") === 0) return c(ONE);'
    + ' if (what === "agents/look") return c({agent: ONE});'
    + ' if (what === "agents/confirm") return c({agent: ONE});'
    + ' if (what === "agents/code") return c({code: "ACAG1.x", until: Date.now() / 1000 + 3600, mode: "passive", ca_fp: "9b".repeat(32), port: 8446, agent: ONE});'
    + ' if (what === "agents/update") return new Promise(function () { });'
    + ' if (what.indexOf("agents/builder") === 0) return c({agent: ONE, facts: FACTS, templates: TPL, needs: [], acme_from: [], design: SAVED});'
    + ' if (what === "agents/design") { SAVED = {n: 1, at: Date.now() / 1000, by: "tester", title: body.title, note: body.note, text: body.text, state: body.state, compare: {state: "matches", added: [], removed: []}, history: []}; return c({design: SAVED}); }'
    + ' return c({}); }, over: function (open) { open(); }});</script>'
    + '</body></html>';
  const csPack = () => {
    const all = JSON.parse(read('lang/cs.json'));
    const pk = {code: 'cs', strings: {}, patterns: [], rich: {}};
    for (const part of ['strings', 'patterns', 'rich']) {
      for (const e of Object.values(all[part] || {})) {
        if (!e || !e.source || !e.text || e.text === e.source) continue;
        if (part === 'patterns') pk.patterns.push([e.source, e.text]); else pk[part][e.source] = e.text;
      }
    }
    return JSON.stringify(pk).replace(/</g, '\\u003c');
  };
  try {
    const page = await browser.newPage({viewport: {width: 1400, height: 1000}});
    page.on('pageerror', (e) => out.errors.push(String(e)));
    await page.setContent(build('null'));
    await page.waitForTimeout(150);
    const open = async (opts) => { await page.evaluate((o) => ACME_POLICY_BUILDER.open({id: 1, name: 'web1'}, o || {}), opts || {}); await page.waitForTimeout(300); };
    const pre = () => page.evaluate(() => document.querySelector('.pb-pre').textContent);
    // ---- an open quotation
    await open();
    await page.evaluate(() => { var i = document.querySelector('#pb-s-tests .pb-row .pb-cmd'); i.value = 'nginx -t "unclosed'; i.dispatchEvent(new Event('input', {bubbles: true})); });
    await page.waitForTimeout(100);
    out.checks.open_quote_red = await page.evaluate(() => {
      var r = document.querySelector('#pb-s-tests .pb-row');
      return r.classList.contains('bad') && !!r.querySelector('.pb-msg.bad') && !!document.querySelector('.pb-badge.bad')
        && document.querySelector('.pb-pre').textContent.indexOf('allow test') < 0;
    });
    await page.evaluate(() => { SENT.length = 0; document.querySelector('.pb-save .btn').click(); });
    await page.waitForTimeout(100);
    out.checks.open_quote_not_saved = await page.evaluate(() => !SENT.some((x) => x[0] === 'agents/design'));
    await page.evaluate(() => { var i = document.querySelector('#pb-s-tests .pb-row .pb-cmd'); i.value = 'nginx -t'; i.dispatchEvent(new Event('input', {bubbles: true})); });
    out.checks.open_quote_closed = (await pre()).indexOf('allow test -- nginx -t') > 0 && await page.evaluate(() => !document.querySelector('.pb-badge.bad'));
    // ---- a limit emptied
    await page.evaluate(() => { var i = document.querySelectorAll('.pb-limit input')[1]; i.value = ''; i.dispatchEvent(new Event('input', {bubbles: true})); });
    out.checks.limit_no_nan = await page.evaluate(() => document.querySelectorAll('.pb-limit')[1].textContent.indexOf('NaN') < 0);
    await page.evaluate(() => closeModal(true));
    // ---- a template clicked in a search
    await open();
    await page.evaluate(() => { var f = document.querySelector('.pb-find'); f.value = 'post'; f.dispatchEvent(new Event('input')); });
    await page.locator('.pb-tpl').first().focus();
    await page.keyboard.press('Enter');
    await page.waitForTimeout(150);
    out.checks.template_search_kept = await page.evaluate(() => document.querySelector('.pb-find').value === 'post' && document.querySelectorAll('.pb-tpl').length === 1
      && document.querySelector('.pb-tpl').classList.contains('on') && document.activeElement === document.querySelector('.pb-tpl'));
    // ---- the tabs say which is selected
    await page.evaluate(() => document.querySelectorAll('.pb-tab')[2].click());
    out.checks.tabs_selected = await page.evaluate(() => Array.prototype.map.call(document.querySelectorAll('.pb-tab'), (t) => t.getAttribute('aria-selected')).join() === 'false,false,true,false');
    // ---- what was clicked together: asked before Escape takes it
    await page.keyboard.press('Escape');
    await page.waitForTimeout(150);
    out.checks.escape_asks = await page.evaluate(() => !document.getElementById('modal').hidden && !!document.querySelector('#modal-box .gd-sure'));
    await page.evaluate(() => { var b = Array.prototype.filter.call(document.querySelectorAll('.gd-sure button'), (x) => /Leave it/.test(x.textContent))[0]; if (b) b.click(); });
    await page.waitForTimeout(150);
    out.checks.escape_leave_it = await page.evaluate(() => document.getElementById('modal').hidden);
    await open();
    await page.keyboard.press('Escape');
    await page.waitForTimeout(150);
    out.checks.escape_unchanged_closes = await page.evaluate(() => document.getElementById('modal').hidden);
    await open();
    await page.evaluate(() => { window.copyText = function () { }; document.querySelector('.pb-tpl').click(); document.querySelector('.pb-out-bar .btn.primary').click(); });
    await page.keyboard.press('Escape');
    await page.waitForTimeout(150);
    out.checks.escape_after_copy_closes = await page.evaluate(() => document.getElementById('modal').hidden);
    // ---- saved: "Start from" offers it
    await page.evaluate(() => { SAVED = null; });
    await open();
    await page.evaluate(() => { document.querySelector('.pb-title').value = 'web1'; document.querySelector('.pb-save .btn').click(); });
    await page.waitForTimeout(200);
    out.checks.saved_offered = await page.evaluate(() => Array.prototype.some.call(document.querySelectorAll('.pb-seg-b'), (b) => b.textContent === 'the saved design')
      && !!document.querySelector('.pb-badge') && document.querySelector('.pb-badge').isConnected && document.querySelector('.pb-stats .pb-stat') !== null);
    await page.evaluate(() => closeModal(true));
    // ---- an earlier version kept without its state
    const text = HEAD + 'allow file /etc/postfix/ssl owner=root:postfix mode=0640\nallow unit postfix.service reload\nallow test -- postfix check\n';
    await page.evaluate(() => { SAVED = null; });
    await open({state: {}, text: text});
    out.checks.version_from_text = (await pre()) === text && await page.evaluate(() => document.querySelector('.pb-seg-b.on').textContent === 'the version opened');
    await page.evaluate(() => closeModal(true));
    // ---- a tile's Update clicked twice
    await page.evaluate(() => ACME_AGENTS.pane());
    await page.waitForTimeout(250);
    await page.evaluate(() => { SENT.length = 0; var b = Array.prototype.filter.call(document.querySelectorAll('#ag-list .ag-tile-acts .btn'), (x) => /^Update$/.test(x.textContent.trim()))[0]; b.click(); b.click(); });
    await page.waitForTimeout(200);
    out.checks.tile_update_once = await page.evaluate(() => SENT.filter((x) => x[0] === 'agents/update').length === 1);
    // ---- the wizard confirmed while it was asking: one round
    await page.evaluate(() => { ONE.pending = {fp: '3f'.repeat(32), host: 'web1', confirmed: false}; ONE.joined = false; SLOW = 400;
      ACME_AGENTS.wizard({id: 1, name: 'web1'}, ONE, function () { }); });
    await page.waitForTimeout(1300);
    await page.evaluate(() => { SENT.length = 0; document.querySelector('#modal-body .ag-confirm .btn.primary').click(); });
    await page.waitForTimeout(9000);
    out.checks.wizard_one_round = await page.evaluate(() => { var n = SENT.filter((x) => x[0] === 'agents/look').length; window.LOOKS = n; return n >= 2 && n <= 4; });
    out.looks = await page.evaluate(() => window.LOOKS);
    await page.evaluate(() => { SLOW = 0; closeModal(true); ONE.pending = null; ONE.joined = true; });
    await page.close();
    // ---- the wizard's rail on a phone, in English and in Czech
    for (const lang of ['en', 'cs']) {
      const p = await browser.newPage({viewport: {width: 375, height: 800}});
      p.on('pageerror', (e) => out.errors.push(lang + ': ' + String(e)));
      await p.setContent(build(lang === 'cs' ? csPack() : 'null'));
      await p.waitForTimeout(150);
      await p.evaluate(() => { ONE.joined = false; ONE.state = 'new'; ACME_AGENTS.wizard({id: 1, name: 'web1'}, ONE, function () { }); });
      await p.waitForTimeout(300);
      await p.locator('#modal-foot .btn.primary').click();
      await p.waitForTimeout(300);
      out.checks['rail_fits_' + lang] = await p.evaluate(() => Array.prototype.every.call(document.querySelectorAll('.ag-rail li'), (li) => {
        var r = li.getBoundingClientRect(), s = li.querySelector('button > span:last-child').getBoundingClientRect();
        return s.right <= r.right + 1 && s.left >= r.left - 1;
      }) && document.documentElement.scrollWidth <= 376);
      await p.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
