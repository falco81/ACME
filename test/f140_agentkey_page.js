// 1.0.140 (agentkey): what an agent deploys (A1) and where its keys are made (B7) - agentkeys.js
// (the guard's pill on the tile and the card, the card "Where keys are made", the dialog "Switch
// to a key made on the server…") and policybuilder.js (its section "What it deploys"), in a page
// of its own, the API answered here (no daemon).
//
//   node test/f140_agentkey_page.js /path/to/web [cs-extra.json] [screenshot-folder]
//
// In English and in Czech, at 1400 and 390 px:
// * the tile's flag "guards what it deploys: 2 issuers, 3 names, own key", the card's pill;
// * Where keys are made: its numbers, a block per target (require key local beside it), the
//   certificates (made on the server, acme's key, could switch, why not, at the next renewal);
//   a certificate picked, "Switch to a key made on the server…": the dialog (the two choices,
//   keyboard, Esc closes), Switch sends agents/keyplace/switch with what was chosen;
// * a read-only administrator: nothing to pick, no switch;
// * the policy builder: "What it deploys" - the issuers switch (acme's CAs offered, the ones used
//   there ticked), the names switch (filled with the names deployed there), the key switch (the
//   certificates with acme's key said, the switch offered) - and the lines in the policy file;
// * nothing wider than the page; no error in the console; in Czech nothing of it in English.
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
  const FP1 = '3a'.repeat(32), FP2 = '9c'.repeat(32), FP3 = '51'.repeat(32);
  const POL = {hash: 'ab'.repeat(32), files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o640}],
    units: {'nginx.service': ['reload']}, tests: [['nginx', '-t']], scripts: [], script_hashes: [], from: [], problems: [],
    probe_local: true, issuers: [FP1, FP2], names: ['www.example.com', 'shop.example.com', '*.api.example.com'], key_local: true};
  const row = (o) => Object.assign({mode: 'passive', state: 'answers', joined: true, version: '1.0.140', code_hash: 'c0de', last_seen: now - 12,
    cert_end: now + 25 * 86400, policy_summary: {files: 1, units: 1, tests: 1, scripts: 0, from: 0, problems: 0}, guard: null}, o);
  const VIEW = {active: false, port: 8444, endpoints: [], node: 'acme1', nginx: null, shipped_code: 'c0de',
    ca: {fp: '9b'.repeat(32), end: now + 3650 * 86400, at: now - 86400},
    package: {name: 'acme-agent-1.0.140.tar.gz', version: '1.0.140', sha256: 'e3'.repeat(32), size: 41234, signed: true},
    commands: ['sha256sum acme-agent-1.0.140.tar.gz'],
    rows: [row({id: 1, name: 'web1', host: 'web1.example.com', agent_host: 'web1', policy: POL}),
      row({id: 2, name: 'mail-gw', host: 'mx1.example.com', agent_host: 'mx1', policy: Object.assign({}, POL, {issuers: [], names: [], key_local: false})}),
      row({id: 3, name: 'iis-shop', platform: 'windows', kind: 'agent_windows', host: 'iis01.example.com', agent_host: 'IIS01', policy: Object.assign({}, POL, {names: [], key_local: false, issuers: [FP3]})})]};
  const one = (r) => Object.assign({}, r, {agent_id: 'ag-1234567890abcdef', shipped_code: 'c0de', key_fp: '3f'.repeat(32),
    policy_at: now - 10, pending: null, package: VIEW.package, commands: VIEW.commands, ca: VIEW.ca, port: 8444});
  const ONES = {1: one(VIEW.rows[0]), 2: one(VIEW.rows[1])};
  const cert = (id, name, key, more) => Object.assign({id: id, name: name, key: key, state: 'ok', not_after: now + 86400 * (20 + id), targets: ['web1'], alone: true, may: true}, more || {});
  const KP = {totals: {agent: 3, acme: 4, switchable: 2, pending: 1, refused: 4},
    targets: [
      {id: 1, name: 'web1', platform: 'linux', key_local: true, guard: {words: '2 issuers, 3 names, own key'},
        counts: {agent: 2, acme: 4, switchable: 2, pending: 1, refused: 4, hidden: 1},
        certs: [cert(11, 'www.example.com', 'agent'), cert(12, 'shop.example.com', 'agent'),
          cert(13, 'api.example.com', 'acme', {switchable: true, refused: true}),
          cert(14, 'static.example.com', 'acme', {switchable: true, refused: true}),
          cert(15, 'legacy.example.com', 'acme', {switchable: false, refused: true, why: 'it is deployed to lb1 too - a key made on the server goes to that server alone', targets: ['web1', 'lb1']}),
          cert(16, 'cdn.example.com', 'acme', {switchable: true, refused: true, pending: {by: 'admin', at: now - 3600}})]},
      {id: 3, name: 'iis-shop', platform: 'windows', key_local: false, counts: {agent: 1, acme: 0, switchable: 0},
        certs: [cert(21, 'shop.example.net', 'agent', {targets: ['iis-shop']})]},
      {id: 2, name: 'mail-gw', platform: 'linux', key_local: false, counts: {agent: 0, acme: 0}, certs: []}]};
  const FACTS = {protected: ['/etc/sudoers', '/etc/cron.d', '/etc/systemd'], parts: ['.ssh'], own: ['/etc/acme-agent', '/var/lib/acme-agent'],
    verbs: ['reload', 'restart'], shells: ['sh', 'bash'], config_ok: ['/etc/ssl', '/etc/pki'], head: '# /etc/acme-agent/policy\n',
    discover_kinds: ['nginx', 'apache'], limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}};
  const BUILDER = {agent: ONES[2], facts: FACTS, templates: [], platform: 'linux', needs: [], acme_from: ['10.0.0.5'], design: null, discovered: null,
    guard: {names: ['www.example.com', 'shop.example.com', 'api.example.com'],
      keys: {agent: 1, acme: 2, switchable: 2, switch_ids: [13, 14]},
      cas: [{fp: FP1, title: 'ISRG Root X1', subject: 'CN=ISRG Root X1,O=Internet Security Research Group,C=US', root: true, kind: 'chain', sources: ['letsencrypt'], certs: 12, here: true},
        {fp: FP2, title: 'R11', subject: 'CN=R11,O=Let\'s Encrypt,C=US', root: false, kind: 'chain', sources: ['letsencrypt'], certs: 12, here: true},
        {fp: FP3, title: 'Example Corp Root', subject: 'CN=Example Corp Root', root: true, kind: 'authority', sources: ['acme: Example Corp Root'], certs: 3, here: false}]}};
  const MARK = 'Where keys are made';
  const hasCs = !!extra[MARK] || read('lang/cs.json').indexOf(MARK) >= 0;
  const EN = ['Where keys are made', 'guards what it deploys', 'Guards what it deploys', 'issuers', 'own key', 'made on the server', 'acme’s key',
    'could switch', 'stays with acme', 'at its next renewal', 'Switch to a key made on the server', 'Pick the certificates',
    'until', 'Take back', 'certificates picked', 'at the next renewal', 'refused by', 'you may not see',
    'At its next renewal', 'Now - and renew it now', 'makes the key today', 'never leaves it', 'The certificate', 'Switch',
    'What it deploys', 'Allowed issuers', 'Allowed names', 'Key only from this server', 'Only certificates of these CAs', 'Only these names',
    'used here', 'intermediate', 'acme’s authority', 'a name', 'certificates: acme’s key', 'The agent would refuse'];
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
          + '<style>' + read('assets/policybuilder.css') + '</style><style>' + read('assets/agentkeys.css') + '</style>'
          + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div></main>' + modalHtml
          + '<div class="toast" id="toast"></div>'
          + '<script>' + esc(read('assets/i18n.js')) + '</script>'
          + '<script>var ME = {name: "tester", role: "' + role + '", prefs: {}}; var LIVE = {on: false}; var SENT = [];'
          + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONES = ' + JSON.stringify(ONES) + '; var KP = ' + JSON.stringify(KP) + '; var BUILDER = ' + JSON.stringify(BUILDER) + ';</script>'
          + '<script>' + esc(read('assets/core.js')) + '</script>'
          + '<script>' + esc(read('assets/agents.js')) + '</script>'
          + '<script>' + esc(read('assets/agentkeys.js')) + '</script>'
          + '<script>' + esc(read('assets/policybuilder.js')) + '</script>'
          + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
          + ' var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
          + ' if (what === "agents") return c(VIEW);'
          + ' if (what === "agents/keys") return c({keys: null});'
          + ' if (what === "agents/keyplace") return c(KP);'
          + ' if (what === "agents/keyplace/switch") return c({done: body.ids.map(function (i) { return {id: i, name: "api.example.com", target: "web1", when: body.when}; }), refused: []});'
          + ' if (what.indexOf("agents/builder") === 0) return c(BUILDER);'
          + ' if (what.indexOf("agents/one") === 0) return c(ONES[decodeURIComponent(what.split("id=")[1])]);'
          + ' if (what.indexOf("agents/guard?id=") === 0) return c({guard: null});'
          + ' if (what === "agents/look") return c({agent: ONES[body.id]});'
          + ' return c({}); }, over: function (open) { open(); }, openTarget: function (n) { window.OPENED = n; }, newCert: function () {}});</script>'
          + '</body></html>';
        const page = await browser.newPage({viewport: {width: width, height: 900}, deviceScaleFactor: 1});
        page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
        page.on('console', (m) => { if (m.type() === 'error') out.errors.push(lang + width + ' console: ' + m.text()); });
        await page.setContent(html);
        await page.waitForTimeout(150);
        const tag = lang + width + (role === 'readonly' ? 'ro' : '') + '_';
        const fits = () => page.evaluate(() => {
          if (document.documentElement.scrollWidth > window.innerWidth + 1) {
            window.WIDE = ['page ' + document.documentElement.scrollWidth].concat(Array.prototype.filter.call(document.querySelectorAll('body *'), function (n) {
              var q = n.getBoundingClientRect(); return q.right > window.innerWidth + 1 && !n.closest('.ag-srv-wrap');
            }).slice(0, 6).map(function (n) { return n.tagName + '.' + n.className + ' ' + Math.round(n.getBoundingClientRect().right); }));
            return false;
          }
          return true;
        });
        const english = (sel) => page.evaluate(([s, words]) => {
          var t = '';
          document.querySelectorAll(s).forEach(function (box) {
            var w = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
            while (w.nextNode()) if (!w.currentNode.parentNode.closest('[data-no-i18n]')) t += w.currentNode.nodeValue + '\n';
          });
          return words.filter(function (w) { return new RegExp('(^|[^A-Za-z])' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^A-Za-z])').test(t); });
        }, [sel, EN]);
        const czech = async (name, sel) => {
          if (lang !== 'cs' || !hasCs) return;
          await page.waitForTimeout(150);
          const left = await english(sel);
          out.checks[tag + name + '_czech'] = left.length === 0;
          if (left.length) out.errors.push(tag + name + ' english: ' + left.join(', '));
        };
        const shot = async (name) => { if (shots) await page.screenshot({path: path.join(shots, tag + name + '.png'), fullPage: false}); };
        // ---- the pane: the tiles' flag, Where keys are made
        await page.evaluate(() => { document.getElementById('pane-agents').hidden = false; ACME_AGENTS.pane(false); });
        await page.waitForTimeout(400);
        out.checks[tag + 'tile_flag'] = await page.evaluate(() => {
          var f = document.querySelectorAll('.ag-tile .ak-flag');
          return f.length === 2 && f[0].querySelectorAll('.ak-part').length === 3;
        });
        out.checks[tag + 'keys_card'] = await page.evaluate(() => {
          var c = document.querySelector('.ak-card');
          return !!c && c.querySelectorAll('.ak-t').length === 2 && c.querySelectorAll('.ak-stat').length === 5
            && c.querySelectorAll('.ak-r').length === 7 && !!c.querySelector('.ak-tag.strict') && !!c.querySelector('.ak-s.pending')
            && c.querySelectorAll('.ak-r.could').length === 3;
        });
        out.checks[tag + 'fits_pane'] = await fits();
        if (!out.checks[tag + 'fits_pane']) out.errors.push(tag + 'wide: ' + JSON.stringify(await page.evaluate(() => window.WIDE)));
        await page.evaluate(() => document.querySelector('.ak-card').scrollIntoView());
        await shot('keys_card');
        await czech('pane', '.ak-card, .ag-tile .ak-flag');
        if (role === 'readonly') {
          out.checks[tag + 'ro_nothing_to_pick'] = await page.evaluate(() => !document.querySelector('.ak-card .ak-cb:not([hidden])')
            && !document.querySelector('.ak-foot') && !document.querySelector('.ak-undo'));
          await page.close();
          continue;
        }
        // pick one, Switch…
        out.checks[tag + 'switch_off_first'] = await page.evaluate(() => document.querySelector('.ak-foot .btn.primary').disabled === true);
        await page.evaluate(() => { var cb = document.querySelector('.ak-r.could:not(.pending) .ak-cb'); cb.click(); });
        await page.waitForTimeout(100);
        out.checks[tag + 'picked'] = await page.evaluate(() => document.querySelector('.ak-foot .btn.primary').disabled === false);
        await page.evaluate(() => document.querySelector('.ak-foot .btn.primary').click());
        await page.waitForTimeout(250);
        out.checks[tag + 'dialog'] = await page.evaluate(() => {
          var m = document.getElementById('modal');
          return !m.hidden && m.querySelectorAll('.ak-when-b').length === 2 && m.querySelectorAll('.ak-when-b.on').length === 1
            && m.querySelectorAll('.ak-steps li').length === 4 && m.querySelectorAll('.ak-item').length === 1;
        });
        out.checks[tag + 'fits_dialog'] = await fits();
        await shot('dialog');
        await czech('dialog', '#modal');
        // keyboard: the second choice, then Esc closes
        await page.focus('.ak-when-b.on');
        await page.keyboard.press('ArrowDown');
        out.checks[tag + 'keyboard'] = await page.evaluate(() => document.querySelectorAll('.ak-when-b')[1].getAttribute('aria-checked') === 'true'
          && document.activeElement === document.querySelectorAll('.ak-when-b')[1]);
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);
        out.checks[tag + 'esc_closes'] = await page.evaluate(() => document.getElementById('modal').hidden);
        // again, Now, Switch: sent
        await page.evaluate(() => document.querySelector('.ak-foot .btn.primary').click());
        await page.waitForTimeout(200);
        await page.evaluate(() => { document.querySelectorAll('.ak-when-b')[1].click(); });
        await page.evaluate(() => {
          var b = Array.prototype.filter.call(document.querySelectorAll('#modal-foot .btn'), function (x) { return x.classList.contains('primary'); })[0];
          b.click();
        });
        await page.waitForTimeout(300);
        out.checks[tag + 'sent'] = await page.evaluate(() => {
          var s = SENT.filter(function (x) { return x[0] === 'agents/keyplace/switch'; });
          return s.length === 1 && s[0][1].when === 'now' && s[0][1].ids.length === 1 && s[0][1].ids[0] === 13;
        });
        // ---- the card's pill
        await page.evaluate(() => { var h = document.getElementById('card-host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.card({id: 1, name: 'web1'})); });
        await page.waitForTimeout(300);
        out.checks[tag + 'card_pill'] = await page.evaluate(() => {
          var p = document.querySelector('#card-host .ak-pill');
          return !!p && p.querySelectorAll('.ak-part').length === 3;
        });
        await page.evaluate(() => document.querySelector('#card-host').scrollIntoView());
        await shot('card');
        await czech('card', '#card-host .ak-guard');
        // ---- the builder: What it deploys
        await page.evaluate(() => ACME_POLICY_BUILDER.open({id: 2, name: 'mail-gw'}));
        await page.waitForTimeout(500);
        out.checks[tag + 'builder_section'] = await page.evaluate(() => {
          var s = document.getElementById('pb-s-guard');
          return !!s && s.querySelectorAll('.pb-gcard').length === 3 && !s.querySelector('.pb-gcard.on');
        });
        await page.evaluate(() => { document.querySelectorAll('#pb-s-guard .pb-gcard-sw')[0].click(); });
        await page.waitForTimeout(100);
        await page.evaluate(() => { document.querySelectorAll('#pb-s-guard .pb-gcard-sw')[1].click(); });
        await page.waitForTimeout(100);
        await page.evaluate(() => { document.querySelectorAll('#pb-s-guard .pb-gcard-sw')[2].click(); });
        await page.waitForTimeout(150);
        out.checks[tag + 'builder_guard'] = await page.evaluate(([f1, f2]) => {
          var s = document.getElementById('pb-s-guard');
          var cas = s.querySelectorAll('.pb-ca'), on = s.querySelectorAll('.pb-ca.on');
          var names = Array.prototype.map.call(s.querySelectorAll('.pb-gname .mono'), function (x) { return x.textContent; });
          var file = document.querySelector('.pb-out-card pre, .pb-out-card code, .pb-out-card .pb-code');
          var text = file ? file.textContent : document.querySelector('.pb-out').textContent;
          return cas.length === 3 && on.length === 1 && on[0].textContent.indexOf('ISRG Root X1') >= 0 && on[0].getAttribute('aria-pressed') === 'true'
            && names.join(' ') === 'www.example.com shop.example.com api.example.com'
            && !!s.querySelector('.pb-gcard .note.warn') && !!s.querySelector('.pb-gkeys')
            && text.indexOf('allow issuer sha256=' + f1) >= 0 && text.indexOf('allow names www.example.com shop.example.com api.example.com') >= 0
            && text.indexOf('require key local') >= 0 && text.indexOf(f2) < 0;
        }, [FP1, FP2]);
        // the intermediate too, a name taken away
        await page.evaluate(() => { document.querySelectorAll('#pb-s-guard .pb-ca')[1].click(); });
        await page.waitForTimeout(100);
        await page.evaluate(() => { document.querySelectorAll('#pb-s-guard .pb-gname-x')[2].click(); });
        await page.waitForTimeout(150);
        out.checks[tag + 'builder_edit'] = await page.evaluate(([f2]) => {
          var t = document.querySelector('.pb-out').textContent;
          return t.indexOf('allow issuer sha256=' + f2) >= 0 && t.indexOf('allow names www.example.com shop.example.com\n') >= 0 || t.indexOf('allow names www.example.com shop.example.com') >= 0 && t.indexOf('api.example.com') < 0;
        }, [FP2]);
        out.checks[tag + 'fits_builder'] = await fits();
        if (!out.checks[tag + 'fits_builder']) out.errors.push(tag + 'wide: ' + JSON.stringify(await page.evaluate(() => window.WIDE)));
        await page.evaluate(() => document.getElementById('pb-s-guard').scrollIntoView());
        await page.waitForTimeout(100);
        await shot('builder');
        await czech('builder', '#pb-s-guard');
        await page.close();
      }
    }
    out.ok = Object.values(out.checks).every(Boolean) && out.errors.length === 0;
  } catch (e) {
    out.ok = false;
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
