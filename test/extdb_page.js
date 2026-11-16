// The database on a server of its own, on the pages (admin.js, hload.js; 1.0.113) - drawn in a
// page of its own, no daemon needed: the API answered here.
//
//   node test/extdb_page.js /path/to/web [screenshot-folder]
//
// * Without an agent nothing changes: Settings -> The database, High availability, the
//   firewall and the header are the same DOM before and after every new piece is asked to draw
//   (a database on this machine; a shared pair's server elsewhere).
// * One server (layout A): the card of the database server - where the database is, its tile,
//   the actions; the pills of the database servers on the cards whose settings reach them (DB
//   TLS, the server's own settings) and on no other; a server whose agent does not answer is red
//   with what was said.
// * Two servers (layout B): told apart by their node ("db · acme1"), their rows on High
//   availability (the direction, what waits, the link's TLS), the pill on Replication, the
//   commands for making it two with --ha-peer-node.
// * The wizard: the code read and checked as it is pasted, connect, the result.
// * The meter: a row a database server after the node's, gone again when there is none; its
//   panel says the database's version, connections, what waits, the size.
// * This machine's database as a database server (1.0.115, db_local_card): without `local` (the
//   setting off) and with an empty one the DOM is the same; with a row the card, no pill.
// * At 420 px nothing wider than the page.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const shots = process.argv[3] || '';
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
    + cut('<div class="ctl-pane" id="pane-ha"', '<div class="ctl-pane" id="pane-carry"')
    + cut('<div class="ctl-pane" id="pane-fw"', '<div class="ctl-pane" id="pane-upgrade"');
  const body = (panes.replace(/<\?php[\s\S]*?\?>/g, '').replace(/<\?=[\s\S]*?\?>/g, ''))
    .replace(/class="ctl-pane" (id="pane-[a-z]+") hidden/g, 'class="ctl-pane" $1');
  const modalHtml = cut('<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  try {
    for (const width of [1300, 420]) {
      const html = '<!doctype html><html class="dark"><head><meta charset="utf-8"><style>' + read('assets/acme.css') + read('assets/hload.css')
        + '</style></head><body><header><h1>acme</h1><div class="hloads"><div class="hload" id="hload" hidden aria-live="off"></div></div>'
        + '<div class="spacer"></div><div class="btnrow"><button class="btn small" id="me-btn">tester</button></div></header>'
        + '<main>' + body + '</main>' + modalHtml + '<div class="toast" id="toast"></div>'
        + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {hload: "graphs", hpanel: "tiles"}}; var LIVE = {on: false};'
        + 'var VIEW = {db_admin: "local", node: "acme1", servers: [], applies: {}, where: {kind: "here", engine: "postgres", host: "localhost"}, ha_mode: "", addresses: ["192.0.2.11"]};'
        + 'var SENT = []; var LOADS = {};'
        + 'function api(what, body) { SENT.push([what, body]);'
        + ' if (what === "db-agent" && !body) return Promise.resolve(JSON.parse(JSON.stringify(VIEW)));'
        + ' if (what === "db-agent" && body.action === "join") return Promise.resolve({host: "192.0.2.21", port: 9443, facts: VIEW.servers[0].facts, agent: {version: "1.0.113"}, view: JSON.parse(JSON.stringify(VIEW))});'
        + ' if (what === "db-agent") return Promise.resolve({view: VIEW});'
        + ' if (String(what).indexOf("load") === 0) return Promise.resolve(LOADS);'
        + ' return Promise.reject(new Error("?")); }'
        + '</script>'
        + '<script>' + esc(read('assets/core.js')) + '</script>'
        + '<script>api = function (what, body) { SENT.push([what, body]);'
        + ' if (what === "db-agent" && !body) return Promise.resolve(JSON.parse(JSON.stringify(VIEW)));'
        + ' if (what === "db-agent" && body.action === "join") return Promise.resolve({host: "192.0.2.21", port: 9443, facts: VIEW.servers[0].facts, agent: {version: "1.0.113"}, view: JSON.parse(JSON.stringify(VIEW))});'
        + ' if (what === "db-agent") return Promise.resolve({view: VIEW});'
        + ' return Promise.resolve({}); };'
        + 'var ADMIN = true, HA = null, PANE = "db", TAB = "settings"; function dbMoveWizard(o) { window.MOVED = o; } function loadDb() {}</script>'
        + '<script>' + esc(read('assets/hload.js')) + '</script>'
        + '<script>' + esc(helpers) + '</script>'
        + '<script>' + esc(dba) + '</script></body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}});
      page.on('pageerror', (e) => out.errors.push(width + ': ' + String(e)));
      await page.setContent(html);
      await page.waitForTimeout(200);
      const tag = 'w' + width + '_';
      const snap = () => page.evaluate(() => ['pane-db', 'pane-ha', 'pane-fw'].map((id) => document.getElementById(id).outerHTML).join('')
        + document.querySelector('header').outerHTML);
      // ---- without an agent: the same DOM
      const before = await snap();
      await page.evaluate(() => { DBA.d = null; return dbaPane(); });
      await page.evaluate(() => { dbaHa({nodes: [{name: 'acme1', me: true}], replication: {}, engine: 'postgres', db_admin: undefined}); dbaFw(); hloadDbsDraw(undefined); hloadDbsDraw([]); });
      await page.waitForTimeout(150);
      out.checks[tag + 'no_agent_same_dom'] = (await snap()) === before;
      // ---- this machine's database as a database server (1.0.115, db_local_card): off there is
      // no `local` (the DOM above); on with nothing to show, the same; with a row, the card - and
      // no pill anywhere; off again, the same DOM as before
      await page.evaluate(() => { VIEW.local = []; DBA.d = null; return dbaPane(); });
      out.checks[tag + 'local_empty_same_dom'] = (await snap()) === before;
      await page.evaluate(() => {
        var now = Date.now() / 1000;
        VIEW.local = [{kind: 'db', name: 'db:acme1', node: 'acme1', me: true, ok: true, stale: false, at: now - 3, host: 'localhost', port: 5432,
          engine: 'postgres', cert_end: now + 300 * 86400, cert_by: 'dbtls',
          facts: {host: 'acme1', engine: 'postgres', running: true, version: '16.4', ssl: true, started: now - 7200, connections: 7, cpus: 4,
            ram: 8e9, avail: 5e9, load: [0.1, 0.2, 0.3], uptime: 90000, disk: {total: 1e11, free: 6e10}}}];
        DBA.d = null; return dbaPane();
      });
      out.checks[tag + 'local_card'] = await page.evaluate(() => {
        var c = document.getElementById('db-agent-card');
        return !!c && c.querySelectorAll('.dbs-tile').length === 1 && c.nextElementSibling.id === 'db-tls-card'
          && !document.querySelector('.dbs-pill') && !document.getElementById('dba-forget') && !!document.getElementById('dba-look')
          && c.textContent.indexOf('localhost:5432') >= 0 && c.textContent.indexOf('Agent') < 0;
      });
      await page.evaluate(() => { delete VIEW.local; DBA.d = null; return dbaPane(); });
      out.checks[tag + 'local_off_same_dom'] = (await snap()) === before;
      await page.evaluate(() => { VIEW.where = {kind: 'unmanaged', engine: 'postgres', host: '192.0.2.50'}; VIEW.ha_mode = 'shared'; DBA.d = null; return dbaPane(); });
      out.checks[tag + 'shared_no_card'] = (await snap()) === before;
      // ---- a server elsewhere with no agent: the card says so and offers the wizard
      await page.evaluate(() => { VIEW.ha_mode = ''; DBA.d = null; return dbaPane(); });
      out.checks[tag + 'unmanaged_card'] = await page.evaluate(() => !!document.getElementById('dba-connect')
        && !document.querySelector('#db-tune-card .dbs-pill'));
      // ---- one server
      await page.evaluate(() => {
        var now = Date.now() / 1000;
        VIEW = {db_admin: 'agent:192.0.2.21:9443', node: 'acme1', host: '192.0.2.21', port: 9443, db_host: '192.0.2.21', engine: 'postgres',
          agent_cert_end: now + 700 * 86400, client_cert_end: now + 700 * 86400, state: {ok: true},
          applies: {dbtls: 'the certificate', db_tune: 'the settings', ha_replication: 'the replication', db_firewall: 'the port'},
          where: {kind: 'agent', engine: 'postgres', host: '192.0.2.21'}, ha_mode: '', addresses: ['192.0.2.11'],
          servers: [{kind: 'db', name: 'db:acme1', node: 'acme1', me: true, alive: true, ok: true, at: now - 4, host: '192.0.2.21', port: 9443,
            db_host: '192.0.2.21', engine: 'postgres', agent_cert_end: now + 700 * 86400, client_cert_end: now + 700 * 86400,
            facts: {host: 'db1', fqdn: 'db1.example.cz', cpus: 8, ram: 32e9, avail: 20e9, load: [0.4, 0.3, 0.2], uptime: 860000, engine: 'postgres',
              running: true, version: '16.4', ssl: true, wal_level: 'logical', started: now - 3600, connections: 14, disk: {total: 500e9, free: 380e9}},
            agent: {version: '1.0.113', pg_port: 5432, cert_end: now + 700 * 86400}}]};
        DBA.d = null; return dbaPane();
      });
      await page.waitForTimeout(100);
      out.checks[tag + 'card_one'] = await page.evaluate(() => {
        var c = document.getElementById('db-agent-card');
        return !!c && c.querySelectorAll('.dbs-tile').length === 1 && !!c.querySelector('.dbs-hero.good')
          && c.querySelector('.dbs-tile-n').textContent === 'db1' && !!document.getElementById('dba-restart')
          && !!document.getElementById('dba-forget') && !document.getElementById('dba-mytls') && !document.getElementById('dba-move')
          && c.textContent.indexOf('14') >= 0 && c.nextElementSibling.id === 'db-tls-card';
      });
      out.checks[tag + 'pills_where_they_apply'] = await page.evaluate(() =>
        document.querySelectorAll('#db-tune-card > h2 .dbs-pill .dbs-one').length === 1
        && document.querySelectorAll('#db-tls-card > h2 .dbs-pill').length === 1
        && document.querySelectorAll('#db-engine-card .dbs-pill, #db-dump-card .dbs-pill').length === 0
        && document.querySelector('#db-tune-card > h2 .dbs-pill .dot').className === 'dot ok');
      await page.evaluate(() => { VIEW.servers[0].ok = false; VIEW.servers[0].said = 'the database agent at 192.0.2.21:9443 does not answer: timed out'; DBA.d = null; return dbaPane(); });
      out.checks[tag + 'down_red_with_said'] = await page.evaluate(() =>
        document.querySelector('#db-tune-card > h2 .dbs-pill .dot').className === 'dot crit'
        && document.querySelector('#db-agent-card .dbs-hero.bad') !== null
        && document.getElementById('db-agent-card').textContent.indexOf('timed out') >= 0);
      await page.evaluate(() => { VIEW.servers[0].ok = true; delete VIEW.servers[0].said; VIEW.where.kind = 'here'; DBA.d = null; return dbaPane(); });
      await page.evaluate(() => document.getElementById('dba-move').click());
      out.checks[tag + 'move_onto_it'] = await page.evaluate(() => !!window.MOVED && window.MOVED.preset.host === '192.0.2.21' && window.MOVED.preset.port === '5432');
      await page.evaluate(() => { VIEW.where.kind = 'agent'; DBA.d = null; return dbaPane(); });
      // ---- the firewall and the meter
      await page.evaluate(() => dbaFw());
      await page.waitForTimeout(100);
      out.checks[tag + 'fw_tile'] = await page.evaluate(() => document.querySelectorAll('#fw-dbs .fw-node.db').length === 1
        && !!document.querySelector('#pane-fw h2 .dbs-pill'));
      await page.evaluate(() => {
        HLOAD.look = 'graphs';
        HLOAD.dbs = [1];                                   /* as hloadTick: known before the node's row */
        hloadDraw({node: 'acme1', cpu: 12, mem_used: 2e9, mem_total: 8e9, disk_rd: 0, disk_wr: 1000, net_rx: 100, net_tx: 50, cores: 4, at: Date.now() / 1000});
        hloadDbsDraw([{kind: 'db', name: 'db:acme1', node: 'acme1', host: '192.0.2.21', server: 'db1', age: 0, cpu: 31, mem_used: 12e9, mem_total: 32e9,
          disk_rd: 1e6, disk_wr: 2e6, net_rx: 3e5, net_tx: 1e5, cores: 8, load: [1, 1, 1],
          db: {engine: 'postgres', running: true, version: '16.4', started: Date.now() / 1000 - 3600, connections: 14, repl_behind: 2048, size: 9e7, disk: {total: 5e11, free: 3e11}}}], Date.now() / 1000);
      });
      out.checks[tag + 'meter_row'] = await page.evaluate(() => {
        var r = document.querySelectorAll('.hload.hl-db');
        return r.length === 1 && r[0].querySelector('.hl-node').textContent === 'db1' && r[0].querySelectorAll('[data-k]').length === 4
          && document.getElementById('hload').querySelector('.hl-node').textContent === 'acme1'
          && r[0].previousElementSibling.id === 'hload';
      });
      if (width === 1300) {
        await page.evaluate(() => { HLOAD.pnode = 'db:acme1'; hloadPanelOpen('cpu', document.querySelector('.hload.hl-db [data-k="cpu"]')); });
        out.checks[tag + 'meter_panel'] = await page.evaluate(() => {
          var t = document.getElementById('hload-panel').textContent;
          return t.indexOf('PostgreSQL 16.4') >= 0 && t.indexOf('2.0 kB') >= 0 && t.indexOf('Connections') >= 0 && t.indexOf('85.8 MB') >= 0;
        });
        if (shots) await page.screenshot({path: path.join(shots, 'extdb-meter-' + width + '.png'), clip: {x: 0, y: 0, width: width, height: 560}});
        await page.evaluate(() => hloadPanelClose());
      }
      await page.evaluate(() => hloadDbsDraw([]));
      out.checks[tag + 'meter_row_gone'] = await page.evaluate(() => !document.querySelector('.hload.hl-db'));
      // ---- two servers, replicated
      await page.evaluate(() => {
        var two = JSON.parse(JSON.stringify(VIEW.servers[0]));
        two.node = 'acme2'; two.name = 'db:acme2'; two.me = false; two.host = '192.0.2.22'; two.db_host = '192.0.2.22';
        VIEW.servers.push(two);
        VIEW.servers.forEach(function (s) { s.facts.host = 'localhost'; });
        HA = {node: 'acme1', address: '192.0.2.11', mode: 'replicated', engine: 'postgres', db_admin: VIEW.db_admin, dbservers: VIEW.servers,
          nodes: [{name: 'acme1', me: true, address: '192.0.2.11'}, {name: 'acme2', address: '192.0.2.12'}],
          replication: {mode: 'replicated', peer: '192.0.2.22', incoming: [{name: 'acme_from_2', enabled: true, running: true}],
            outgoing: [{active: true, wal_status: 'reserved', behind: 4096}]},
          link_tls: {mode: 'verify-full', own: true, nodes: [{name: 'acme1', step: 'done', cert_end: Date.now() / 1000 + 600 * 86400}, {name: 'acme2', step: 'done'}]}};
        dbaHa(HA);
      });
      await page.waitForTimeout(100);
      out.checks[tag + 'ha_rows'] = await page.evaluate(() => {
        var rows = document.querySelectorAll('#ha-dbs tbody tr');
        var t = document.getElementById('ha-dbs').textContent;
        return rows.length === 2 && t.indexOf('db · acme1 → db · acme2') >= 0 && t.indexOf('db · acme2 → db · acme1') >= 0
          && t.indexOf('4.0 kB') >= 0 && t.indexOf('verify-full') >= 0
          && document.querySelectorAll('#ha-rep-card > h2 .dbs-pill .dbs-one').length === 2;
      });
      out.checks[tag + 'ha_make'] = await page.evaluate(() => {
        var m = document.getElementById('ha-dbs-make');
        if (!m) return false;
        var i = document.getElementById('ha-dbs-peer'); i.value = '192.0.2.22'; i.dispatchEvent(new Event('input'));
        var n = document.getElementById('ha-dbs-node'); n.value = '192.0.2.12'; n.dispatchEvent(new Event('input'));
        return m.textContent.indexOf('acme --ha-setup --ha-peer 192.0.2.22 --ha-peer-node 192.0.2.12 --node-name acme1') >= 0;
      });
      // ---- the wizard
      out.checks[tag + 'code_read'] = await page.evaluate(() => {
        var good = 'ADBA1.' + btoa(JSON.stringify({h: '192.0.2.21', p: 9443, s: 'x', f: 'ab'.repeat(32), e: 'postgres'})).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
        var g = dbaCodeRead(good), b1 = dbaCodeRead('ADBA2.xx'), b2 = dbaCodeRead('ADBA1.eyJo'), e = dbaCodeRead('  ');
        window.GOOD = good;
        return g.host === '192.0.2.21' && g.port === 9443 && !!b1.bad && !!b2.bad && e.empty;
      });
      await page.evaluate(() => dbaWizard());
      await page.waitForTimeout(150);
      const h1 = await page.evaluate(() => document.getElementById('modal-box').getBoundingClientRect().height);
      out.checks[tag + 'wizard_1'] = await page.evaluate(() => document.getElementById('modal-body').textContent.indexOf('--db-server postgres --acme-node 192.0.2.11') >= 0);
      await page.locator('#modal-foot .btn.primary').click();
      await page.fill('#dbs-code', 'ADBA1.zz');
      out.checks[tag + 'wizard_bad_code'] = await page.evaluate(() => document.getElementById('dbs-code-said').className.indexOf('bad') >= 0);
      await page.evaluate(() => { var t = document.getElementById('dbs-code'); t.value = GOOD; t.dispatchEvent(new Event('input')); });
      out.checks[tag + 'wizard_good_code'] = await page.evaluate(() => document.getElementById('dbs-code-said').textContent.indexOf('192.0.2.21:9443') >= 0);
      const h2 = await page.evaluate(() => document.getElementById('modal-box').getBoundingClientRect().height);
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(200);
      out.checks[tag + 'wizard_joined'] = await page.evaluate(() => {
        var j = SENT.filter(function (x) { return x[0] === 'db-agent' && x[1] && x[1].action === 'join'; })[0];
        return !!j && j[1].code === GOOD && !!document.querySelector('#dbs-wiz-2 .dbs-tile') && !!document.querySelector('#dbs-wiz-2 .note.good');
      });
      const h3 = await page.evaluate(() => document.getElementById('modal-box').getBoundingClientRect().height);
      if (width === 1300) out.checks[tag + 'wizard_steady'] = Math.abs(h1 - h2) < 2 && h3 >= h2 - 2;
      out.checks[tag + 'fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'extdb-wizard-' + width + '.png')});
      await page.evaluate(() => closeModal());
      if (shots) await page.locator('#db-agent-card').screenshot({path: path.join(shots, 'extdb-card-' + width + '.png')});
      await page.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
