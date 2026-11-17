// The database server cards (admin.js), regressions of 1.0.119 - drawn in a page of its own,
// the API answered here.
//
//   node test/hunt_q1_db_page.js /path/to/web
//
// * A MariaDB server with an agent: its tile's address and the firewall's row say MariaDB's
//   port (my_port), not PostgreSQL's 5432 the agent also reports; an agent that says no
//   my_port: no port at all. PostgreSQL's still its pg_port.
// * The wizard: an agent's address typed [IPv6]:PORT, the one already joined, is not said to
//   be replaced; another one is.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const admin = read('assets/admin.js');
  const a = admin.indexOf('/* ==== The database on a server of its own');
  const b = admin.indexOf('/* ==== end of the database on a server of its own');
  const dba = admin.slice(a, b);
  const fnOf = (name) => {
    const i = admin.indexOf('\nfunction ' + name + '(');
    const j = admin.indexOf('\n}\n', i);
    return admin.slice(i, j + 3);
  };
  const helpers = ['haIp', 'haWords', 'haLiveSteps'].map(fnOf).join('\n');
  const page0 = read('admin/index.php');
  const cut = (from, to) => { const i = page0.indexOf(from); return page0.slice(i, page0.indexOf(to, i)); };
  const panes = cut('<div class="ctl-pane" id="pane-db"', '<div class="ctl-pane" id="pane-codes"')
    + cut('<div class="ctl-pane" id="pane-fw"', '<div class="ctl-pane" id="pane-upgrade"');
  const body = (panes.replace(/<\?php[\s\S]*?\?>/g, '').replace(/<\?=[\s\S]*?\?>/g, ''))
    .replace(/class="ctl-pane" (id="pane-[a-z]+") hidden/g, 'class="ctl-pane" $1');
  const modalHtml = cut('<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  try {
    const html = '<!doctype html><html class="dark"><head><meta charset="utf-8"><style>' + read('assets/acme.css')
      + '</style></head><body><main>' + body + '</main>' + modalHtml + '<div class="toast" id="toast"></div>'
      + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var VIEW = {}; var SENT = [];</script>'
      + '<script>' + esc(read('assets/core.js')) + '</script>'
      + '<script>api = function (what, body) { SENT.push([what, body || null]);'
      + ' if (what === "db-agent" && !body) return Promise.resolve(JSON.parse(JSON.stringify(VIEW)));'
      + ' return Promise.resolve({view: VIEW}); };'
      + 'var ADMIN = true, HA = null, PANE = "db", TAB = "settings"; function dbMoveWizard() {} function loadDb() {}</script>'
      + '<script>' + esc(helpers) + '</script>'
      + '<script>' + esc(dba) + '</script></body></html>';
    const page = await browser.newPage({viewport: {width: 1300, height: 900}});
    page.on('pageerror', (e) => out.errors.push(String(e)));
    await page.setContent(html);
    await page.waitForTimeout(100);
    const now = Date.now() / 1000;
    const facts = {host: 'db1', engine: 'mariadb', running: true, version: '10.11.6-MariaDB', ssl: true, connections: 3};
    const server = (engine, agent) => ({kind: 'db', name: 'db:acme1', node: 'acme1', me: true, ok: true, at: now - 3,
      host: '192.0.2.21', port: 9443, db_host: '192.0.2.21', engine: engine, facts: Object.assign({}, facts, {engine: engine}), agent: agent});
    out.checks.tile_port = await page.evaluate(([my, my_old, pg]) => {
      var addr = function (s) {
        var t = dbaTile(s, {servers: [s]});
        var k = Array.prototype.filter.call(t.querySelectorAll('.dbs-kv'), function (x) { return x.querySelector('.k').textContent === 'Address'; })[0];
        return k.querySelector('.v').textContent;
      };
      var got = [addr(my), addr(my_old), addr(pg)];
      return got.join(',') === '192.0.2.21:3307,192.0.2.21,192.0.2.21:5432' ? true : got.join(',');
    }, [server('mariadb', {pg_port: 5432, my_port: 3307, version: '1.0.119'}), server('mariadb', {pg_port: 5432}),
        server('postgres', {pg_port: 5432, my_port: 3306})]);
    out.checks.firewall_port = await page.evaluate((s) => {
      VIEW = {db_admin: 'agent:192.0.2.21:9443', node: 'acme1', servers: [s], applies: {}, where: {kind: 'agent', engine: 'mariadb'},
        host: '192.0.2.21', port: 9443, engine: 'mariadb', ha_mode: '', addresses: ['192.0.2.11']};
      DBA.d = null;
      dbaFw();
      return new Promise(function (ok) { setTimeout(function () {
        var r = document.querySelector('#fw-dbs .fw-node-a');
        ok(r ? (r.textContent === '192.0.2.21 · TCP 3307' ? true : r.textContent) : 'no row');
      }, 150); });
    }, server('mariadb', {pg_port: 5432, my_port: 3307}));
    // ---- the wizard: [IPv6]:PORT of the agent joined is the same agent
    const v6 = '2001:db8::21';
    await page.evaluate((h) => {
      VIEW = {db_admin: 'agent:' + h + ':9443', node: 'acme1', servers: [], applies: {}, where: {kind: 'agent', engine: 'postgres'},
        host: h, port: 9443, engine: 'postgres', ha_mode: '', addresses: ['192.0.2.11']};
      window.CODE = 'ADBA1.' + btoa(JSON.stringify({h: h, p: 9443, s: 'x', f: 'ab'.repeat(32), e: 'postgres'})).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      DBA.d = null;
      dbaWizard();
    }, v6);
    await page.waitForTimeout(150);
    await page.locator('#modal-foot .btn.primary').click();
    const replaced = (addr) => page.evaluate((x) => {
      var t = document.getElementById('dbs-code'); t.value = CODE; t.dispatchEvent(new Event('input'));
      var ad = document.getElementById('dbs-addr'); ad.value = x; ad.dispatchEvent(new Event('input'));
      return !!document.getElementById('dbs-replace');
    }, addr);
    out.checks.wizard_same_v6 = !(await replaced('[' + v6 + ']:9443')) && !(await replaced('[' + v6 + ']')) && !(await replaced(''));
    out.checks.wizard_other = await replaced('[2001:db8::99]:9443');
    await page.evaluate(() => closeModal());
    await page.close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every((x) => x === true);
  console.log(JSON.stringify(out));
})();
