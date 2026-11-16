// This machine's database shown as a database server (admin.js, db_local_card, 1.0.115) - the
// card of Settings -> The database drawn in a page of its own, no daemon needed: the API
// answered here.
//
//   node test/localdb_page.js /path/to/web [cs-extra.json] [screenshot-folder]
//
// cs-extra.json: {English: Czech}, added to web/lang/cs.json for the Czech pages (the new words
// before they are merged into it).
//
// In English and in Czech, at 1400 and 420 px:
// * the setting off (no `local`): no card, the pane as it was;
// * on, each node its own PostgreSQL (acme1, acme2): the card "Database server" above
//   "Encryption to the database server", a tile each - the engine and version, the address, running,
//   TLS and its certificate's end, the connections, the disk and the RAM as bars, the
//   processors and the load, up for, last heard; acme2 not heard from lately; no pill, no agent's
//   rows, no Forget; Look now asks POST look, Renew the certificate the step of Encryption to the
//   database server (or, the link's, High availability's tls_link, asked first), Restart the
//   database… the restart of the server's own settings;
// * a shared pair seen from the node whose database is elsewhere: one tile, of acme1;
// * read-only: no buttons; nothing wider than the page; in Czech nothing of it left in English
//   that has a translation.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const extra = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf-8')) : {};
  const shots = process.argv[4] || '';
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
  const helpers = ['haIp', 'haWords'].map(fnOf).join('\n');
  const page0 = read('admin/index.php');
  const cut = (from, to) => { const i = page0.indexOf(from); return page0.slice(i, page0.indexOf(to, i)); };
  const body = cut('<div class="ctl-pane" id="pane-db"', '<div class="ctl-pane" id="pane-codes"')
    .replace(/<\?php[\s\S]*?\?>/g, '').replace(/<\?=[\s\S]*?\?>/g, '')
    .replace(/class="ctl-pane" (id="pane-[a-z]+") hidden/g, 'class="ctl-pane" $1');
  const modalHtml = cut('<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const fold = (s) => String(s).replace(/\s+/g, ' ').trim();
  // The words of the card (each a piece of text of its own on the page).
  const WORDS = ['Database server', 'Each node’s database is on its own machine', 'This node’s database is on',
    'looked at by each node itself - no agent', 'Look now', 'Renew the certificate', 'Restart the database…',
    'Its certificate ends', 'Address', 'The database', 'Connections', 'Its data’s disk', 'Processors', 'Up for',
    'Last heard', 'not heard from lately', 'this node’s', 'running'];
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
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
        for (const k of Object.keys(extra)) pk.strings[k] = extra[k];
        packStrings = {};
        for (const k of Object.keys(pk.strings)) packStrings[fold(k)] = pk.strings[k];
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      const html = '<!doctype html><html class="dark"><head><meta charset="utf-8"><style>' + read('assets/acme.css')
        + '</style><script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main>' + body + '</main>' + modalHtml
        + '<div class="toast" id="toast"></div>'
        + '<script>' + esc(read('assets/i18n.js')) + '</script>'
        + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = []; var VIEW = {};</script>'
        + '<script>' + esc(read('assets/core.js')) + '</script>'
        + '<script>api = function (what, body) { SENT.push([what, body || null]);'
        + ' if (what === "db-agent" && !body) return Promise.resolve(JSON.parse(JSON.stringify(VIEW)));'
        + ' if (what === "db-agent") return Promise.resolve({row: (VIEW.local || [])[0] || null, view: JSON.parse(JSON.stringify(VIEW))});'
        + ' return Promise.resolve({}); };'
        + 'var ADMIN = true, HA = null, PANE = "db", TAB = "settings"; function loadDb() {}'
        + 'function dbtSteps(steps, done) { window.RENEWED = steps; } function tuneRestartAsk() { window.RESTART_ASKED = true; }</script>'
        + '<script>' + esc(helpers) + '</script>'
        + '<script>' + esc(dba) + '</script></body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}});
      page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
      await page.setContent(html);
      await page.waitForTimeout(150);
      const tag = lang + width + '_';
      const snap = () => page.evaluate(() => document.getElementById('pane-db').outerHTML);
      // ---- off: no `local`, nothing drawn
      const before = await snap();
      await page.evaluate(() => {
        VIEW = {db_admin: 'local', node: 'acme1', servers: [], applies: {}, where: {kind: 'here', engine: 'postgres', host: 'localhost'},
          ha_mode: 'replicated', addresses: ['192.0.2.11']};
        DBA.d = null; return dbaPane();
      });
      await page.waitForTimeout(100);
      out.checks[tag + 'off_no_card'] = !(await page.evaluate(() => !!document.getElementById('db-agent-card'))) && (await snap()) === before;
      // ---- on, each node its own PostgreSQL
      await page.evaluate(() => {
        var now = Date.now() / 1000;
        var f = {host: 'acme1', engine: 'postgres', running: true, version: '16.4 (Debian 16.4-1)', ssl: true, wal_level: 'logical', started: now - 7200,
          connections: 9, cpus: 4, ram: 8e9, avail: 5e9, load: [0.12, 0.2, 0.3], uptime: 900000, disk: {total: 1e11, free: 6e10}};
        VIEW.local = [
          {kind: 'db', name: 'db:acme1', node: 'acme1', me: true, ok: true, stale: false, at: now - 3, host: 'localhost', port: 5432, engine: 'postgres',
           cert_end: now + 300 * 86400, cert_by: 'dbtls', facts: f, restart: {may: true, unit: 'postgresql-16.service', waiting: ['shared_buffers']}},
          {kind: 'db', name: 'db:acme2', node: 'acme2', me: false, ok: true, stale: true, at: now - 900, host: 'localhost', port: 5432, engine: 'postgres',
           cert_end: now + 10 * 86400, cert_by: 'dbtls', facts: Object.assign({}, f, {host: 'acme2', connections: 4, disk: {total: 1e11, free: 5e9}})}];
        DBA.d = null; return dbaPane();
      });
      await page.waitForTimeout(150);
      out.checks[tag + 'card'] = await page.evaluate(() => {
        var c = document.getElementById('db-agent-card');
        if (!c || c.nextElementSibling.id !== 'db-tls-card' || !c.classList.contains('dbs-card')) return false;
        var tiles = c.querySelectorAll('.dbs-tile');
        var names = Array.prototype.map.call(c.querySelectorAll('.dbs-tile-n'), function (x) { return x.textContent; });
        return tiles.length === 2 && names.join() === 'acme1,acme2' && tiles[0].classList.contains('me') && tiles[0].classList.contains('ok')
          && tiles[1].classList.contains('warn') && tiles[0].querySelectorAll('.dbs-bar').length === 2
          && tiles[1].querySelector('.dbs-bar.hot') !== null && !!c.querySelector('.dbs-hero.good') && !!c.querySelector('.dbs-state.ok');
      });
      out.checks[tag + 'facts'] = await page.evaluate(() => {
        var t = document.getElementById('db-agent-card').querySelectorAll('.dbs-tile')[0].textContent;
        return t.indexOf('PostgreSQL 16.4') >= 0 && t.indexOf('localhost:5432') >= 0 && t.indexOf('9') >= 0 && t.indexOf(' · 2 h ') >= 0
          && t.indexOf('10 d 10 h') >= 0 && t.indexOf('/ 0') >= 0;
      });
      out.checks[tag + 'cert_soon_red'] = await page.evaluate(() =>
        document.getElementById('db-agent-card').querySelectorAll('.dbs-tile')[1].querySelectorAll('.dbs-kv .v .bad').length >= 1);
      out.checks[tag + 'not_the_agents'] = await page.evaluate(() => !document.querySelector('.dbs-pill') && !document.getElementById('dba-forget')
        && !document.getElementById('dba-mytls') && !document.getElementById('dba-connect') && !document.getElementById('dba-move'));
      if (lang === 'en') {
        out.checks[tag + 'words'] = await page.evaluate(() => {
          var t = document.getElementById('db-agent-card').textContent;
          return ['Database server', 'Each node’s database is on its own machine', 'looked at by each node itself - no agent', 'answers',
            'not heard from lately', 'Its certificate ends', 'Its data’s disk', 'Last heard'].every(function (w) { return t.indexOf(w) >= 0; })
            && t.indexOf('Agent') < 0 && t.indexOf('client certificate') < 0 ? true : t;
        });
        if (out.checks[tag + 'words'] !== true) { out['card_' + tag] = out.checks[tag + 'words']; out.checks[tag + 'words'] = false; }
      } else {
        const text = await page.evaluate(() => document.getElementById('db-agent-card').innerText);
        const left = WORDS.filter((w) => packStrings[fold(w)] && packStrings[fold(w)] !== w && text.indexOf(w) >= 0);
        out.checks[tag + 'czech'] = !left.length && text.indexOf('Databázový server') >= 0;
        if (left.length) out['left_' + tag] = left;
      }
      // ---- the actions
      out.checks[tag + 'actions'] = await page.evaluate(() => {
        var l = document.getElementById('dba-look'), r = document.getElementById('dba-renew'), s = document.getElementById('dba-restart');
        if (!l || !r || !s) return false;
        r.click(); s.click(); l.click();
        return !!window.RENEWED && window.RENEWED[0].body.phase === 'server' && window.RENEWED[0].body.renew === true && window.RESTART_ASKED === true;
      });
      await page.waitForTimeout(100);
      out.checks[tag + 'look_asked'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'db-agent' && x[1] && x[1].action === 'look'; })
        && !!document.getElementById('db-agent-card'));
      out.checks[tag + 'fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#db-agent-card').screenshot({path: path.join(shots, 'localdb-' + lang + width + '.png')});
      // ---- the link's certificate (a replicated pair, High availability): renewed as there
      await page.evaluate(() => { VIEW.local.forEach(function (s) { s.cert_by = 'link'; }); DBA.d = null; return dbaPane(); });
      await page.evaluate(() => document.getElementById('dba-renew').click());
      await page.waitForTimeout(100);
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(100);
      out.checks[tag + 'renew_link'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'ha' && x[1] && x[1].action === 'tls_link'; }));
      // ---- no restart waiting, no certificate of acme's: only Look now
      await page.evaluate(() => { delete VIEW.local[0].restart; VIEW.local.forEach(function (s) { s.cert_by = ''; s.cert_end = null; }); DBA.d = null; return dbaPane(); });
      out.checks[tag + 'only_look'] = await page.evaluate(() => !!document.getElementById('dba-look') && !document.getElementById('dba-renew')
        && !document.getElementById('dba-restart'));
      // ---- a shared pair, seen from acme2 (its database on acme1): one server
      await page.evaluate(() => {
        VIEW.node = 'acme2'; VIEW.ha_mode = 'shared'; VIEW.where = {kind: 'unmanaged', engine: 'postgres', host: '192.0.2.11'};
        VIEW.local = [VIEW.local[0]]; VIEW.local[0].me = false; VIEW.local[0].stale = false;
        DBA.d = null; return dbaPane();
      });
      out.checks[tag + 'shared_one'] = await page.evaluate(() => {
        var c = document.getElementById('db-agent-card');
        return !!c && c.querySelectorAll('.dbs-tile').length === 1 && c.querySelector('.dbs-hero-w b .mono').textContent === 'acme1'
          && !c.querySelector('.dbs-tile.me');
      });
      // ---- read-only: no buttons
      await page.evaluate(() => { ME.role = 'readonly'; DBA.d = null; return dbaPane(); });
      out.checks[tag + 'readonly'] = await page.evaluate(() => !!document.getElementById('db-agent-card') && !document.getElementById('dba-look'));
      // ---- off again
      await page.evaluate(() => { ME.role = 'fulladmin'; delete VIEW.local; DBA.d = null; return dbaPane(); });
      out.checks[tag + 'off_again'] = !(await page.evaluate(() => !!document.getElementById('db-agent-card')));
      await page.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
