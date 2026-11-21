// 1.0.138 (agentsec): an agent watched more closely (agents.js guardBox, guardFlags, servedNote,
// keysReport) in a page of its own, the API answered here (no daemon).
//
//   node test/f138_agentsec_page.js /path/to/web [cs-extra.json] [screenshot-folder]
//
// cs-extra.json: {English: Czech} (texts with {0} are patterns), added to web/lang/cs.json.
//
// In English and in Czech, at 1400 and 390 px:
// * the card of an agent with everything on: the four features (audit chain, anomaly alerts, key
//   rotation, what the service serves) with their switches on; the chain does not agree (its
//   problems, "I have looked at it…"); the anomalies with their levels; the keys and their age
//   (an earlier command key, due); a deployment still serving the old certificate; the audit
//   timeline (12 shown, "Show all", the filters);
// * a switch sends POST agents/guard with that choice; Rotate now… asks first (three choices,
//   Esc closes) and sends what was chosen; Verify now sends agents/guard/verify;
// * the card of an agent with everything off: the switches off, the lines root would run
//   (audit on, allow probe local) - no permission taken;
// * a read-only administrator: the switches cannot be turned, no Rotate now;
// * the tiles' flags, the keys report on the pane, the note on a deployment's row;
// * nothing wider than the page or its card; no error in the console; in Czech nothing of it left
//   in English.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const extra = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf-8')) : {};
  const shots = process.argv[4] || '';
  if (shots) fs.mkdirSync(shots, {recursive: true});
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const ui = read('admin/certs-ui.php');
  const cut = (text, from, to) => { const i = text.indexOf(from); return text.slice(i, text.indexOf(to, i)); };
  const paneHtml = cut(ui, '<div class="ctl-pane" id="pane-agents"', '<div class="ctl-pane" id="pane-dnssrv"')
    .replace('class="ctl-pane" id="pane-agents" hidden', 'class="ctl-pane" id="pane-agents"');
  const index = read('admin/index.php');
  const modalHtml = cut(index, '<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const POL = {hash: 'ab'.repeat(32), files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o640}],
    units: {'nginx.service': ['reload']}, tests: [['nginx', '-t']], scripts: [], script_hashes: [], from: [], problems: [],
    probe_local: true, audit_chain: true};
  const ops = ['hello', 'deploy', 'audit', 'probe', 'hello', 'policy', 'keygen', 'deploy', 'hello', 'audit'];
  const entries = [];
  for (let i = 0; i < 20; i++) {
    const mark = i === 3 ? 'unknown' : (i === 7 ? 'server' : (i === 11 ? 'refused' : 'acme'));
    entries.push({n: 140 - i, h: (i % 16).toString(16).repeat(64), ts: now - i * 1800, op: mark === 'server' ? 'policy' : (mark === 'refused' ? 'job' : ops[i % ops.length]),
      job: mark === 'server' || mark === 'refused' ? '' : ('a1b2c3d4e5f6' + String(1000 + i) + 'abcdef00').slice(0, 24), ok: mark !== 'refused',
      said: mark === 'server' ? 'audit chain on' : (mark === 'refused' ? 'the job\'s time is 412 s from this machine\'s - set the clocks right'
        : (ops[i % ops.length] === 'deploy' ? '3 files written, reloaded' : 'acme-agent 1.0.138 here')), mark: mark});
  }
  const GUARD_ON = {id: 1, name: 'web1', joined: true, features: ['audit-chain', 'cmdkey', 'enckey'], platform: 'linux', overlap_h: 72, rotate_range: [7, 730],
    opts: {audit: true, anomaly: true, rotate: true, rotate_days: 90, health: 'on', at: now - 86400, by: 'admin'},
    audit: {on: true, state: 'mismatch', agent_on: true, supported: true, n: 140, verified_n: 140, base_n: 12, verified_at: now - 120, read_at: now - 120,
      problems: 1, entries: entries, acked: null, read_said: '', head_h: 'ff'.repeat(32),
      problem_list: [{kind: 'unknown', words: 'the agent did a job acme never sent (job a1b2c3d4e5f61003abcdef00, hello, entry 137) - somebody else signed it with acme\'s command key', n: 137, at: now - 5400}]},
    anomaly: {on: true, worst: 'bad', base_at: now - 86400 * 9, nets: ['10.20.30.0/24'], template: {name: 'nginx web', state: 'differs', added: [], removed: []}, acked: null,
      items: [{kind: 'widened', level: 'bad', live: false, at: now - 3600, words: 'the policy of the agent of target web1 was widened on the server: file /srv/www root:root 0644'},
        {kind: 'network', level: 'warn', live: false, at: now - 7200, words: 'the agent of target web1 comes from a new network: 203.0.113.9 (its usual: 10.20.30.0/24)'},
        {kind: 'clock', level: 'warn', live: true, words: 'the clock of the server of target web1 is 74 s ahead of acme\'s'},
        {kind: 'version', level: 'warn', live: true, words: 'the agent of target web1 runs 1.0.137 - 1.0.138 is offered'}]},
    served: {on: true, switch: 'on', probe_local: true, old: 1, items: [
      {deploy_id: 7, cert: 'www.example.com', state: 'old', at: now - 600, places: [{host: '127.0.0.1', port: 443, state: 'old', version: 4}], want: 'AB'},
      {deploy_id: 8, cert: 'api.example.com', state: 'ok', at: now - 600, places: [{host: '127.0.0.1', port: 8443, state: 'ok'}]}]},
    keys: {cmd_fp: '7c'.repeat(32), cmd_current: false, cmd_at: now - 86400 * 120, cmd_age: 120, enc_at: now - 86400 * 97, enc_age: 97, tls_end: now + 86400 * 21,
      tls_renewed: now - 86400 * 9, key_fp: '3f'.repeat(32), joined_at: now - 86400 * 200, rotate: true, rotate_days: 90, can: true, said: '',
      prev_until: null, unknown: '', due: ['command', 'seal']}};
  const GUARD_OFF = {id: 2, name: 'mail-gw', joined: true, features: [], platform: 'linux', overlap_h: 72, rotate_range: [7, 730],
    opts: {audit: false, anomaly: false, rotate: false, rotate_days: 90, health: 'off'},
    audit: {on: false, state: 'off', agent_on: false, supported: null, n: null, verified_n: null, problems: 0, entries: [], problem_list: []},
    anomaly: {on: false, items: []},
    served: {on: false, switch: 'off', probe_local: false, old: 0, items: []},
    keys: {cmd_fp: '9d'.repeat(32), cmd_current: true, cmd_age: 41.2, enc_age: 41.2, tls_end: now + 86400 * 27, rotate: false, rotate_days: 90, can: false,
      said: '', due: [], unknown: ''}};
  const GUARDS = {1: GUARD_ON, 2: GUARD_OFF};
  const SUM_ON = {audit: {on: true, state: 'mismatch'}, opts: {audit: true, anomaly: true, rotate: true, rotate_days: 90, health: 'on'},
    anomalies: GUARD_ON.anomaly.items.map((i) => ({kind: i.kind, level: i.level, words: i.words})),
    served: {on: true, old: 1, items: [{cert: 'www.example.com', state: 'old', deploy_id: 7}]}, keys: {due: ['command'], cmd_age: 120, enc_age: 97, rotate: true, unknown: false}};
  const SUM_OK = {audit: {on: true, state: 'ok'}, opts: {audit: true, anomaly: false, rotate: false, rotate_days: 90, health: 'off'},
    anomalies: null, served: {on: false, old: 0, items: []}, keys: {due: [], cmd_age: 3, enc_age: 3, rotate: false, unknown: false}};
  const row = (o) => Object.assign({mode: 'passive', state: 'answers', joined: true, version: '1.0.138', code_hash: 'c0de', last_seen: now - 12,
    cert_end: now + 25 * 86400, policy_summary: {files: 1, units: 1, tests: 1, scripts: 0, from: 0, problems: 0}}, o);
  const VIEW = {active: false, port: 8444, endpoints: [], node: 'acme1', nginx: null, shipped_code: 'c0de',
    ca: {fp: '9b'.repeat(32), end: now + 3650 * 86400, at: now - 86400},
    package: {name: 'acme-agent-1.0.138.tar.gz', version: '1.0.138', sha256: 'e3'.repeat(32), size: 41234, signed: true},
    commands: ['sha256sum acme-agent-1.0.138.tar.gz'],
    rows: [row({id: 1, name: 'web1', host: 'web1.example.com', agent_host: 'web1', guard: SUM_ON}),
      row({id: 2, name: 'mail-gw', host: 'mx1.example.com', agent_host: 'mx1', guard: SUM_OK}),
      row({id: 3, name: 'iis-shop', platform: 'windows', kind: 'agent_windows', host: 'iis01.example.com', agent_host: 'IIS01', guard: null})]};
  const one = (r) => Object.assign({}, r, {agent_id: 'ag-1234567890abcdef', shipped_code: 'c0de', key_fp: '3f'.repeat(32),
    policy: POL, policy_at: now - 10, pending: null, package: VIEW.package, commands: VIEW.commands, ca: VIEW.ca, port: 8444});
  const ONES = {1: one(VIEW.rows[0]), 2: one(Object.assign({}, VIEW.rows[1], {policy: Object.assign({}, POL, {probe_local: false, audit_chain: false})}))};
  const KEYS = {ca: {fp: '9b'.repeat(32), at: now - 86400 * 400, age: 400, end: now + 86400 * 3250}, ctl: {end: now + 86400 * 500, at: now - 86400 * 230, age: 230},
    cmd: [{fp: '9d'.repeat(32), at: now - 86400 * 41, age: 41.2, current: true, retired_at: null, agents: ['mail-gw', 'iis-shop']},
      {fp: '7c'.repeat(32), at: now - 86400 * 120, age: 120, current: false, retired_at: null, agents: ['web1']},
      {fp: '11'.repeat(32), at: now - 86400 * 400, age: 400, current: false, retired_at: now - 86400 * 200, agents: []}],
    agents: [{id: 1, name: 'web1', platform: 'linux', cmd_fp: '7c'.repeat(32), cmd_current: false, cmd_age: 120, enc_age: 97, tls_end: now + 86400 * 21, rotate: true, rotate_days: 90, due: ['command'], unknown: ''},
      {id: 2, name: 'mail-gw', platform: 'linux', cmd_fp: '9d'.repeat(32), cmd_current: true, cmd_age: 41.2, enc_age: 41.2, tls_end: now + 86400 * 27, rotate: false, rotate_days: 90, due: [], unknown: ''},
      {id: 3, name: 'iis-shop', platform: 'windows', cmd_fp: '9d'.repeat(32), cmd_current: true, cmd_age: 41.2, enc_age: 0.4, tls_end: now + 86400 * 5, rotate: false, rotate_days: 90, due: [], unknown: ''}],
    overlap_h: 72};
  const MARK = 'Watching this agent';
  const hasCs = !!extra[MARK] || read('lang/cs.json').indexOf(JSON.stringify(MARK).slice(1, -1)) >= 0;
  const EN = ['Watching this agent', 'Audit chain', 'Anomaly alerts', 'Key rotation', 'What the service serves', 'does not agree', 'checked up to',
    'I have looked at it', 'Verify now', 'Rotate now', 'Its key for secrets', 'Change every', 'still serves', 'Audit timeline', 'Show all', 'verified',
    'Not agreeing', 'acme’s jobs', 'On the server', 'not sent by acme', 'kept until looked at', 'Its usual since', 'Its template', 'days',
    'Keys and their age', 'Earlier command keys', 'Schedule', 'by hand', 'Deployed, but', 'anomal', 'watching', 'serves an old certificate',
    'audit chain does not agree', 'audit chain verified', 'Each of these is chosen'];
  try {
    for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 390], ['cs', 390]]) {
      let pack = 'null';
      if (lang === 'cs') {
        const all = JSON.parse(read('lang/cs.json'));
        const pk = {code: 'cs', strings: {}, patterns: [], rich: {}};
        for (const part of ['strings', 'patterns', 'rich']) {
          for (const e of Object.values(all[part] || {})) {
            if (!e || !e.source || !e.text) continue;
            if (part === 'patterns') pk.patterns.push([e.source, e.text]); else pk[part][e.source] = e.text;
          }
        }
        for (const k of Object.keys(extra)) {
          if (/\{\d/.test(k)) pk.patterns.push([k, extra[k]]); else pk.strings[k] = extra[k];
        }
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      for (const role of (width === 1400 && lang === 'en' ? ['fulladmin', 'readonly'] : ['fulladmin'])) {
        const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
          + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
          + '<style>' + read('assets/policybuilder.css') + '</style>'
          + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div><div id="dep-host" class="ct-name"></div></main>' + modalHtml
          + '<div class="toast" id="toast"></div>'
          + '<script>' + esc(read('assets/i18n.js')) + '</script>'
          + '<script>var ME = {name: "tester", role: "' + role + '", prefs: {}}; var LIVE = {on: false}; var SENT = [];'
          + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONES = ' + JSON.stringify(ONES) + '; var GUARDS = ' + JSON.stringify(GUARDS) + '; var KEYS = ' + JSON.stringify(KEYS) + ';</script>'
          + '<script>' + esc(read('assets/core.js')) + '</script>'
          + '<script>' + esc(read('assets/agents.js')) + '</script>'
          + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
          + ' var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
          + ' if (what === "agents") return c(VIEW);'
          + ' if (what === "agents/keys") return c({keys: KEYS});'
          + ' if (what.indexOf("agents/one") === 0) return c(ONES[decodeURIComponent(what.split("id=")[1])]);'
          + ' if (what.indexOf("agents/guard?id=") === 0) return c({guard: GUARDS[decodeURIComponent(what.split("id=")[1])]});'
          + ' if (what === "agents/guard") { var g = JSON.parse(JSON.stringify(GUARDS[body.id])); Object.keys(body).forEach(function (k) { if (k !== "id") g.opts[k] = body[k]; }); if ("anomaly" in body) g.anomaly.on = body.anomaly; GUARDS[body.id] = g; return c({guard: g}); }'
          + ' if (what.indexOf("agents/guard/") === 0) return c({guard: GUARDS[body.id]});'
          + ' if (what === "agents/look") return c({agent: ONES[body.id]});'
          + ' if (what.indexOf("agents/design") === 0) return c({design: null});'
          + ' return c({}); }, over: function (open) { open(); }, openTarget: function (n) { window.OPENED = n; }, newCert: function () {}});</script>'
          + '</body></html>';
        const page = await browser.newPage({viewport: {width: width, height: 900}, deviceScaleFactor: 1});
        page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
        page.on('console', (m) => { if (m.type() === 'error') out.errors.push(lang + width + ' console: ' + m.text()); });
        await page.setContent(html);
        await page.waitForTimeout(150);
        const tag = lang + width + (role === 'readonly' ? 'ro' : '') + '_';
        const fits = (sel) => page.evaluate((s) => {
          if (document.documentElement.scrollWidth > window.innerWidth + 1) {
            window.WIDE = ['page ' + document.documentElement.scrollWidth].concat(Array.prototype.filter.call(document.querySelectorAll('body *'), function (n) {
              var q = n.getBoundingClientRect(); return q.right > window.innerWidth + 1 && !n.closest('.ag-srv-wrap');
            }).slice(0, 6).map(function (n) { return n.tagName + '.' + n.className + ' ' + Math.round(n.getBoundingClientRect().right); }));
            return false;
          }
          var box = document.querySelector(s);
          if (!box) return false;
          var r = box.getBoundingClientRect();
          return Array.prototype.every.call(box.querySelectorAll('*'), function (n) {
            var q = n.getBoundingClientRect();
            if (!q.width || n.closest('.ag-srv-wrap, .ag-tl-seg')) return true;
            var ok = q.right <= r.right + 1 && q.left >= r.left - 1;
            if (!ok) window.WIDE = (window.WIDE || []).concat([n.className + ' ' + Math.round(q.right) + '>' + Math.round(r.right) + ' ' + (n.textContent || '').slice(0, 30)]);
            return ok;
          });
        }, sel);
        const english = (sel) => page.evaluate(([s, words]) => {
          var box = document.querySelector(s), t = '';
          if (box) {
            var w = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
            while (w.nextNode()) if (!w.currentNode.parentNode.closest('[data-no-i18n]')) t += w.currentNode.nodeValue + '\n';
          }
          return words.filter(function (w) { return t.indexOf(w) >= 0; });
        }, [sel, EN]);
        const czech = async (name, sel) => {
          if (lang !== 'cs' || !hasCs) return;
          const left = await english(sel);
          out.checks[tag + name + '_czech'] = left.length === 0;
          if (left.length) out.errors.push(tag + name + ' english: ' + left.join(', '));
        };
        const card = async (id) => {
          await page.evaluate((i) => { var h = document.getElementById('card-host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.card({id: i, name: ONES[i].name, kind: ONES[i].kind})); }, id);
          await page.waitForTimeout(300);
        };
        // ---- everything on, things wrong
        await card(1);
        out.checks[tag + 'card_on'] = await page.evaluate(() => {
          var g = document.querySelector('#card-host .ag-gd');
          if (!g || g.hidden) return false;
          var f = g.querySelectorAll('.ag-gd-f');
          return f.length === 4 && g.querySelectorAll('.ag-gd-f.on').length === 4 && g.querySelectorAll('.ag-gd-f .sw input:checked').length === 4
            && !!g.querySelector('.ag-gd-f.audit .ag-sys-pill.bad') && g.querySelectorAll('.ag-gd-f.audit .ag-gd-prob').length === 1
            && g.querySelectorAll('.ag-gd-an-i').length === 4 && g.querySelectorAll('.ag-gd-an-i.bad').length === 1
            && !!g.querySelector('.ag-gd-f.keys .ag-gd-tag.warn') && (ME.role !== 'fulladmin' || !!g.querySelector('.ag-gd-f.keys select'))
            && g.querySelectorAll('.ag-gd-srv-i.warn').length === 1 && g.querySelectorAll('.ag-gd-srv-i.ok').length === 1
            && g.querySelectorAll('.ag-tl-i').length === 12 && g.querySelectorAll('.ag-tl-i.bad').length === 1
            && !!g.querySelector('.ag-tl-more .btn') && g.querySelectorAll('.ag-gd-sum .ag-sys-pill').length === 4;
        });
        out.checks[tag + 'card_on_fits'] = await fits('#card-host .ag-card');
        if (!out.checks[tag + 'card_on_fits']) out.errors.push(tag + 'wide: ' + JSON.stringify(await page.evaluate(() => (window.WIDE || []).slice(0, 4))));
        await czech('card_on', '#card-host .ag-gd');
        if (shots) await page.locator('#card-host .ag-gd').screenshot({path: path.join(shots, 'guard-on-' + tag + '.png')});
        // the timeline: all, then only what does not agree
        out.checks[tag + 'timeline'] = await page.evaluate(() => {
          var g = document.querySelector('#card-host .ag-gd');
          g.querySelector('.ag-tl-more .btn').click();
          var all = g.querySelectorAll('.ag-tl-i').length === 20;
          g.querySelectorAll('.ag-tl-seg button')[3].click();
          var bad = g.querySelectorAll('.ag-tl-i').length === 1 && !!g.querySelector('.ag-tl-i.bad');
          g.querySelectorAll('.ag-tl-seg button')[2].click();
          var srv = g.querySelectorAll('.ag-tl-i').length === 2;
          g.querySelectorAll('.ag-tl-seg button')[0].click();
          return all && bad && srv && g.querySelectorAll('.ag-tl-seg button')[0].getAttribute('aria-pressed') === 'true';
        });
        if (role === 'fulladmin') {
          // a switch: its choice sent
          out.checks[tag + 'switch'] = await page.evaluate(async () => {
            SENT.length = 0;
            var sw = document.querySelector('#card-host .ag-gd-f.anomaly .sw input');
            sw.click();
            await new Promise((r) => setTimeout(r, 200));
            var s = SENT.filter(function (x) { return x[0] === 'agents/guard'; })[0];
            return !!s && s[1].anomaly === false && s[1].id === 1 && !document.querySelector('#card-host .ag-gd-f.anomaly').classList.contains('on');
          });
          // Rotate now: asked first, Esc closes, the choice sent
          await page.evaluate(() => { var b = Array.prototype.filter.call(document.querySelectorAll('#card-host .ag-gd-f.keys .btn'), function (x) { return /Rotate|Vyměnit/.test(x.textContent); })[0]; b.click(); });
          await page.waitForTimeout(200);
          out.checks[tag + 'rotate_asks'] = await page.evaluate(() => !document.getElementById('modal').hidden && document.querySelectorAll('#modal .ag-gd-opt').length === 3);
          if (shots) await page.locator('#modal .box').screenshot({path: path.join(shots, 'rotate-' + tag + '.png')});
          await czech('rotate', '#modal');
          await page.keyboard.press('Escape');
          await page.waitForTimeout(200);
          out.checks[tag + 'rotate_esc'] = await page.evaluate(() => document.getElementById('modal').hidden);
          await page.evaluate(() => { var b = Array.prototype.filter.call(document.querySelectorAll('#card-host .ag-gd-f.keys .btn'), function (x) { return /Rotate|Vyměnit/.test(x.textContent); })[0]; b.click(); });
          await page.waitForTimeout(200);
          out.checks[tag + 'rotate_sends'] = await page.evaluate(async () => {
            SENT.length = 0;
            document.querySelectorAll('#modal .ag-gd-opt input')[2].click();
            var go = Array.prototype.filter.call(document.querySelectorAll('#modal-foot button'), function (b) { return b.classList.contains('primary'); })[0];
            go.click();
            await new Promise((r) => setTimeout(r, 300));
            var s = SENT.filter(function (x) { return x[0] === 'agents/guard/rotate'; })[0];
            return !!s && s[1].what === 'seal' && s[1].id === 1;
          });
          out.checks[tag + 'verify'] = await page.evaluate(async () => {
            SENT.length = 0;
            var b = document.querySelector('#card-host .ag-gd-f.audit .ag-gd-acts .btn');
            b.click();
            await new Promise((r) => setTimeout(r, 200));
            return SENT.some(function (x) { return x[0] === 'agents/guard/verify' && x[1].id === 1; });
          });
        } else {
          out.checks[tag + 'readonly'] = await page.evaluate(() => {
            var g = document.querySelector('#card-host .ag-gd');
            return g.querySelectorAll('.sw input:disabled').length === 4 && !g.querySelector('.ag-gd-f.keys select')
              && !Array.prototype.some.call(g.querySelectorAll('.btn'), function (b) { return /Rotate|looked/.test(b.textContent); });
          });
        }
        // ---- everything off
        await card(2);
        out.checks[tag + 'card_off'] = await page.evaluate(() => {
          var g = document.querySelector('#card-host .ag-gd');
          return !!g && g.querySelectorAll('.ag-gd-f.on').length === 0 && g.querySelectorAll('.ag-gd-f .sw input:checked').length === 0
            && /acme-agent audit on/.test(g.querySelector('.ag-gd-f.audit').textContent)
            && /acme-agent allow probe local/.test(g.querySelector('.ag-gd-f.served').textContent)
            && !g.querySelector('.ag-tl') && !!g.querySelector('.ag-gd-f.keys .note');
        });
        out.checks[tag + 'card_off_fits'] = await fits('#card-host .ag-card');
        await czech('card_off', '#card-host .ag-gd');
        if (shots) await page.locator('#card-host .ag-gd').screenshot({path: path.join(shots, 'guard-off-' + tag + '.png')});
        await page.evaluate(() => { document.getElementById('card-host').innerHTML = ''; });
        // ---- a deployment's row
        await page.evaluate(() => {
          var h = document.getElementById('dep-host');
          h.appendChild(ACME_AGENTS.servedNote({state: 'old', at: Date.now() / 1000 - 300, places: [{host: '127.0.0.1', port: 443, state: 'old', version: 4}]}));
        });
        out.checks[tag + 'served_note'] = await page.evaluate(() => !!document.querySelector('#dep-host .ag-served-note.warn')
          && ACME_AGENTS.servedNote({state: 'ok'}) === null && ACME_AGENTS.servedNote(null) === null);
        await czech('served_note', '#dep-host');
        if (shots) await page.locator('#dep-host .ag-served-note').screenshot({path: path.join(shots, 'deploy-note-' + tag + '.png')});
        // ---- the pane: the tiles' flags, the keys report
        await page.evaluate(() => ACME_AGENTS.pane());
        await page.waitForTimeout(350);
        out.checks[tag + 'tiles'] = await page.evaluate(() => {
          var t = document.querySelectorAll('#ag-list .ag-tile');
          return t.length === 3 && !!t[0].querySelector('.ag-flag.bad') && t[0].querySelectorAll('.ag-flag').length >= 4
            && !!t[1].querySelector('.ag-flag.ok') && !t[2].querySelector('.ag-flags .ag-flag.bad');
        });
        out.checks[tag + 'keys_report'] = await page.evaluate(() => {
          var k = document.querySelector('#ag-list .ag-kr');
          return !!k && !k.hidden && k.querySelectorAll('.ag-kr-t').length === 4 && k.querySelectorAll('tbody tr').length === 3
            && !!k.querySelector('tbody .ag-sys-pill.warn') && (ME.role !== 'fulladmin' || !!k.querySelector('.ag-kr-foot .btn'));
        });
        out.checks[tag + 'pane_fits'] = await fits('#ag-list');
        if (!out.checks[tag + 'pane_fits']) out.errors.push(tag + 'wide: ' + JSON.stringify(await page.evaluate(() => (window.WIDE || []).slice(0, 4))));
        await czech('keys', '#ag-list .ag-kr');
        await czech('tiles', '#ag-list .ag-grid');
        if (shots) {
          await page.locator('#ag-list .ag-grid').scrollIntoViewIfNeeded();
          await page.waitForTimeout(300);
          await page.locator('#ag-list .ag-grid').screenshot({path: path.join(shots, 'tiles-' + tag + '.png')});
          await page.locator('#ag-list .ag-kr').screenshot({path: path.join(shots, 'keys-' + tag + '.png')});
        }
        await page.close();
      }
    }
  } catch (e) {
    out.error = String((e && e.stack) || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
