// The database server cards (admin.js), regressions of 1.0.119 (round q2) - drawn in a page of
// its own, the API answered here.
//
//   node test/hunt_q2_dbportal_page.js /path/to/web
//
// * The card's hero at a phone's width (375 px): the state chip goes under the title, the title
//   is not squeezed beside it; at a desktop's width all of it stays on one line.
// * "Last heard" of an agent's tile and of this machine's database's tile: red by how long ago
//   (stale, or never), not because its database does not run.
// * The wizard: joined, but the agent did not answer since (late) - the last step is not said
//   to be running.
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
  const panes = cut('<div class="ctl-pane" id="pane-db"', '<div class="ctl-pane" id="pane-codes"');
  const body = (panes.replace(/<\?php[\s\S]*?\?>/g, '').replace(/<\?=[\s\S]*?\?>/g, ''))
    .replace(/class="ctl-pane" (id="pane-[a-z]+") hidden/g, 'class="ctl-pane" $1');
  const modalHtml = cut('<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  try {
    const html = '<!doctype html><html class="dark"><head><meta charset="utf-8">'
      + '<meta name="viewport" content="width=device-width, initial-scale=1"><style>' + read('assets/acme.css')
      + '</style></head><body><main><div class="card" id="hero-host"></div>' + body + '</main>' + modalHtml
      + '<div class="toast" id="toast"></div>'
      + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var VIEW = {}; var SENT = []; var JOINED = null;</script>'
      + '<script>' + esc(read('assets/core.js')) + '</script>'
      + '<script>api = function (what, body) { SENT.push([what, body || null]);'
      + ' if (what === "db-agent" && body && body.action === "join") return Promise.resolve(JOINED);'
      + ' if (what === "db-agent" && !body) return Promise.resolve(JSON.parse(JSON.stringify(VIEW)));'
      + ' return Promise.resolve({view: VIEW}); };'
      + 'var ADMIN = true, HA = null, PANE = "db", TAB = "settings"; function dbMoveWizard() {} function loadDb() {}</script>'
      + '<script>' + esc(helpers) + '</script>'
      + '<script>' + esc(dba) + '</script></body></html>';
    const hero = (page) => page.evaluate(() => {
      var host = document.getElementById('hero-host');
      clear(host);
      var chip = el('span', 'dbs-state ok', 'answers · heard 3 s ago');
      var h = dbaHero('good', 'db', 'PostgreSQL 16.4 on db-primary.example.test - looked after by its agent',
        'acme-db-agent 1.0.119 at 192.0.2.21:9443', chip);
      host.appendChild(h);
      var w = h.querySelector('.dbs-hero-w').getBoundingClientRect();
      var c = chip.getBoundingClientRect();
      return {wTop: w.top, wBottom: w.bottom, wWidth: w.width, cTop: c.top, heroW: h.getBoundingClientRect().width,
        scroll: document.documentElement.scrollWidth <= window.innerWidth};
    });
    for (const [name, width] of [['phone', 375], ['phone420', 420], ['desktop', 1300]]) {
      const page = await browser.newPage({viewport: {width: width, height: 900}});
      page.on('pageerror', (e) => out.errors.push(String(e)));
      await page.setContent(html);
      await page.waitForTimeout(80);
      const g = await hero(page);
      if (name === 'desktop') out.checks.hero_desktop_one_line = g.cTop < g.wBottom ? true : g;
      else out.checks['hero_' + name + '_wraps'] = (g.cTop >= g.wBottom - 1 && g.wWidth > 180 && g.scroll) ? true : g;
      await page.close();
    }
    const page = await browser.newPage({viewport: {width: 1300, height: 900}});
    page.on('pageerror', (e) => out.errors.push(String(e)));
    await page.setContent(html);
    await page.waitForTimeout(100);
    const now = Date.now() / 1000;
    // ---- Last heard: by how long ago
    out.checks.heard = await page.evaluate((now) => {
      var cls = function (t) {
        var k = Array.prototype.filter.call(t.querySelectorAll('.dbs-kv'), function (x) { return x.querySelector('.k').textContent === 'Last heard'; })[0];
        return k ? k.querySelector('.v > span').className : 'none';
      };
      var srv = function (o) {
        return Object.assign({kind: 'db', name: 'db:acme1', node: 'acme1', me: true, ok: true, at: now - 3, stale: false,
          host: '192.0.2.21', port: 9443, db_host: '192.0.2.21', engine: 'postgres',
          facts: {host: 'db1', engine: 'postgres', running: true, version: '16.4'}, agent: {pg_port: 5432}}, o);
      };
      var down = srv({facts: {host: 'db1', engine: 'postgres', running: false, said: 'connection refused'}});
      var silent = srv({ok: false, said: 'timed out'});
      var stale = srv({at: now - 900, stale: true});
      var never = srv({at: null, ok: null});
      var got = [cls(dbaTile(srv({}), {servers: []})), cls(dbaTile(down, {servers: []})), cls(dbaTile(silent, {servers: []})),
        cls(dbaTile(stale, {servers: []})), cls(dbaTile(never, {servers: []}))];
      var loc = function (o) {
        return Object.assign({node: 'acme1', me: true, host: 'localhost', port: 5432, engine: 'postgres', at: now - 3, stale: false,
          facts: {engine: 'postgres', running: true, version: '16.4'}}, o);
      };
      got = got.concat([cls(dbaLocalTile(loc({facts: {engine: 'postgres', running: false, said: 'down'}}), [])),
        cls(dbaLocalTile(loc({at: now - 900, stale: true}), []))]);
      return got.join(',') === ',,,bad,bad,,bad' ? true : got.join(',');
    }, now);
    // ---- the wizard: joined, the agent silent since
    await page.evaluate(() => {
      VIEW = {db_admin: 'agent:192.0.2.21:9443', node: 'acme1', servers: [], applies: {}, where: {kind: 'local', engine: 'postgres'},
        host: '', port: 0, engine: 'postgres', ha_mode: '', addresses: ['192.0.2.11']};
      JOINED = {host: '192.0.2.21', port: 9443, facts: {}, agent: {}, replaced: null, late: 'the agent did not answer', view: VIEW};
      window.CODE = 'ADBA1.' + btoa(JSON.stringify({h: '192.0.2.21', p: 9443, s: 'x', f: 'ab'.repeat(32), e: 'postgres'})).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
      DBA.d = null;
      dbaWizard();
    });
    await page.waitForTimeout(150);
    await page.locator('#modal-foot .btn.primary').click();
    await page.evaluate(() => {
      var t = document.getElementById('dbs-code'); t.value = CODE; t.dispatchEvent(new Event('input'));
    });
    await page.locator('#modal-foot .btn.primary').click();
    await page.waitForTimeout(300);
    out.checks.wizard_late = await page.evaluate(() => {
      var rows = document.querySelectorAll('#dbs-wiz-2 .step');
      var last = rows[rows.length - 1];
      if (!last) return 'no steps';
      var t = last.textContent;
      return /warn/.test(last.className) && !/running/.test(t) && /did not answer/.test(t) ? true : last.className + ': ' + t;
    });
    await page.evaluate(() => closeModal());
    await page.close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every((x) => x === true);
  console.log(JSON.stringify(out));
})();
