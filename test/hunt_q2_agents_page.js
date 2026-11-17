// Hunt Q2 (1.0.119) - the target agents' pages (agents.js) and the policy builder
// (policybuilder.js) in a browser, beside test/agents_page.js:
//
//   node test/hunt_q2_agents_page.js /path/to/web
//
// * the package's Download only for a certificate administrator (GET agents/package is theirs) -
//   it was there for every role, and said "forbidden";
// * "Design its policy…" clicked twice while the builder is asked: asked once, opened once;
// * a tile's update going on: the pane drawn again meanwhile keeps how it goes;
// * the pane not asked: said, and nothing below it left showing as if it were now (the first
//   time all empty; later what was seen stays, the error above it).
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
  const POL = {files: [], units: {}, tests: [], scripts: [], script_hashes: [], from: [], problems: []};
  const ONE = {id: 1, name: 'web1', mode: 'passive', state: 'answers', joined: true, agent_id: 'ag-1', host: 'web1.example.com', version: '1.0.116',
    last_seen: now - 12, cert_end: now + 25 * 86400, policy: POL, policy_at: now, pending: null};
  const VIEW = {active: false, port: 8444, endpoints: [], nginx: null, ca: null, commands: ['a', 'b', 'c', 'd'],
    package: {name: 'acme-agent-1.0.116.tar.gz', version: '1.0.116', size: 4000000, signed: true, sha256: 'e3'.repeat(32)},
    rows: [{id: 2, name: 'mail-gw', mode: 'active', state: 'answers', version: '1.0.115', last_seen: now - 5,
      update: {offered: '1.0.116', newer: true, allowed: true, signed: true}}]};
  const FACTS = {protected: ['/etc/sudoers.d'], parts: ['.ssh'], own: ['/etc/acme-agent'], verbs: ['reload', 'restart'], shells: ['sh', 'bash'],
    config_ok: ['/etc/ssl'], head: '# acme-agent policy\n', limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}};
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const build = (role) => '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
    + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
    + '<style>' + read('assets/policybuilder.css') + '</style>'
    + '<script>window.ACME_LANG_PACK = null;</script></head><body><main class="ctl-main">' + paneHtml + '</main>' + modalHtml
    + '<div class="toast" id="toast"></div>'
    + '<script>' + esc(read('assets/i18n.js')) + '</script>'
    + '<script>var ME = {name: "tester", role: "' + role + '", prefs: {}}; var LIVE = {on: false}; var SENT = []; var SLOW = 0; var FAIL = 0;'
    + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONE = ' + JSON.stringify(ONE) + '; var FACTS = ' + JSON.stringify(FACTS) + ';</script>'
    + '<script>' + esc(read('assets/core.js')) + '</script>'
    + '<script>' + esc(read('assets/agents.js')) + '</script>'
    + '<script>' + esc(read('assets/policybuilder.js')) + '</script>'
    + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
    + ' var c = function (x) { var v = JSON.parse(JSON.stringify(x)); return SLOW ? new Promise(function (r) { setTimeout(function () { r(v); }, SLOW); }) : Promise.resolve(v); };'
    + ' if (what === "agents") return FAIL ? Promise.reject(new Error("HTTP 502")) : c(VIEW);'
    + ' if (what === "agents/update") return new Promise(function () { });'
    + ' if (what.indexOf("agents/builder") === 0) return c({agent: ONE, facts: FACTS, templates: [], needs: [], acme_from: [], design: null});'
    + ' return c({}); }, over: function (open) { open(); }});</script>'
    + '</body></html>';
  try {
    // ---- the package's Download: a certificate administrator's
    for (const role of ['readonly', 'certadmin', 'fulladmin']) {
      const p = await browser.newPage({viewport: {width: 1400, height: 1000}});
      p.on('pageerror', (e) => out.errors.push(role + ': ' + String(e)));
      await p.setContent(build(role));
      await p.waitForTimeout(150);
      await p.evaluate(() => ACME_AGENTS.pane());
      await p.waitForTimeout(250);
      const has = await p.evaluate(() => !!document.querySelector('#ag-pkg .ag-pkg') && Array.prototype.some.call(document.querySelectorAll('#ag-pkg .btn'), (b) => /Download/.test(b.textContent)));
      const tile = await p.evaluate(() => !!document.querySelector('#ag-pkg .ag-pkg-name'));
      out.checks['download_' + role] = tile && (role === 'readonly' ? !has : has);
      await p.close();
    }
    const page = await browser.newPage({viewport: {width: 1400, height: 1000}});
    page.on('pageerror', (e) => out.errors.push(String(e)));
    await page.setContent(build('fulladmin'));
    await page.waitForTimeout(150);
    // ---- the pane not asked, the first time: said, nothing below
    await page.evaluate(() => { FAIL = 1; ACME_AGENTS.pane(); });
    await page.waitForTimeout(250);
    out.checks.fail_first = await page.evaluate(() => /could not be asked/.test(document.getElementById('ag-hero').textContent)
      && !document.getElementById('ag-pkg').firstChild && !document.getElementById('ag-list').firstChild && !document.getElementById('ag-ca').firstChild);
    // ---- asked, then not: what was seen stays, the error above it (once)
    await page.evaluate(() => { FAIL = 0; ACME_AGENTS.pane(); });
    await page.waitForTimeout(250);
    await page.evaluate(() => { FAIL = 1; ACME_AGENTS.pane(); });
    await page.waitForTimeout(150);
    await page.evaluate(() => { ACME_AGENTS.pane(); });
    await page.waitForTimeout(150);
    out.checks.fail_later = await page.evaluate(() => document.querySelectorAll('#ag-hero .ag-ask-err').length === 1
      && !!document.querySelector('#ag-hero .ag-hero') && !!document.querySelector('#ag-list .ag-tile') && !!document.querySelector('#ag-pkg .ag-pkg'));
    await page.evaluate(() => { FAIL = 0; ACME_AGENTS.pane(); });
    await page.waitForTimeout(250);
    out.checks.fail_gone = await page.evaluate(() => !document.querySelector('#ag-hero .ag-ask-err'));
    // ---- "Design its policy…" clicked twice while it is asked
    await page.evaluate(() => { SENT.length = 0; SLOW = 300; var b = Array.prototype.filter.call(document.querySelectorAll('#ag-list .ag-tile-acts .btn'), (x) => /Design its policy/.test(x.textContent))[0]; b.click(); b.click(); });
    await page.waitForTimeout(800);
    out.checks.design_once = await page.evaluate(() => SENT.filter((x) => x[0].indexOf('agents/builder') === 0).length === 1
      && !document.getElementById('modal').hidden && document.querySelectorAll('#modal .pb-hero').length === 1);
    await page.evaluate(() => { SLOW = 0; closeModal(true); });
    await page.waitForTimeout(100);
    // and once closed, it opens again
    await page.evaluate(() => { SENT.length = 0; var b = Array.prototype.filter.call(document.querySelectorAll('#ag-list .ag-tile-acts .btn'), (x) => /Design its policy/.test(x.textContent))[0]; b.click(); });
    await page.waitForTimeout(300);
    out.checks.design_again = await page.evaluate(() => SENT.filter((x) => x[0].indexOf('agents/builder') === 0).length === 1 && !document.getElementById('modal').hidden);
    await page.evaluate(() => closeModal(true));
    await page.waitForTimeout(100);
    // ---- a tile's update going on: the pane drawn again keeps how it goes
    await page.evaluate(() => { var b = Array.prototype.filter.call(document.querySelectorAll('#ag-list .ag-tile-acts .btn'), (x) => /^Update$/.test(x.textContent.trim()))[0]; b.click(); });
    await page.waitForTimeout(150);
    const before = await page.evaluate(() => document.querySelector('[data-upd="2"]').textContent);
    await page.evaluate(() => ACME_AGENTS.pane(true));
    await page.waitForTimeout(250);
    out.checks.marks_kept = await page.evaluate((b) => { var p = document.querySelector('[data-upd="2"]'); return !!b && !p.hidden && p.textContent === b && /run/.test(p.className); }, before);
    await page.close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
