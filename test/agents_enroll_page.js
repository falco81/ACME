// The company enrollment code and the Windows agent in the administration pages (agents.js,
// 1.0.120): Settings → Target agents - the agents waiting for confirmation (one by one, the ones
// selected, all of one code - each asked first with its fingerprints), the enrollment codes (made
// in a dialog: title, mode, port, days, servers, "confirm automatically" red while on; the code
// shown once with the Linux and Windows lines; revoked), the package with a Windows tab (the MSI,
// Download MSI, the lines by hand / silently / from the command line; or "it comes with a release"),
// and the join wizard of a Windows target - drawn in a page of their own, the API answered here.
//
//   node test/agents_enroll_page.js /path/to/web [cs-extra.json] [screenshot-folder]
//
// In English and in Czech, at 1400 and 390 px: nothing wider than the page (nor the popups), no
// error in the console, in Czech none of the new words left in English.
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
  const WORDS = ['Waiting for confirmation', 'Enrollment codes', 'One code for many servers', 'Make an enrollment code…',
    'Confirm selected…', 'Confirm all of this code…', 'Joined with the code', 'Each with its target’s own join code', 'Confirm…',
    'confirmed automatically', 'Servers', 'Valid until', 'Who made it', 'Revoke…', 'used up', 'revoked', 'The agent to install',
    'The Windows installer comes with a release', 'Download MSI', 'On the server, as an administrator',
    'Silently, for many servers (Group Policy, Intune, SCCM):', 'Or from the command line, in an elevated prompt (Run as administrator):'];
  const DWORDS = ['Make an enrollment code', 'Its title', 'Mode', 'Their port', 'Valid for (days)', 'At most (servers)', 'Confirm automatically',
    'Make the code', 'Passive - acme connects to them', 'Active - they connect to acme'];
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const FP1 = '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7';
  const FP2 = 'a1'.repeat(32), FP3 = '5c'.repeat(32);
  const WIN = {name: 'acme-agent-1.0.120-windows-x64.msi', version: '1.0.120', sha256: 'ab'.repeat(32), size: 31457280, signed: true};
  const VIEW = {
    active: true, port: 8444, endpoints: ['acme.example.com:8444'], node: 'acme1', nginx: {port: 8444}, shipped_code: 'c0de',
    ca: {fp: '9b'.repeat(32), end: now + 3650 * 86400, at: now - 86400},
    package: {name: 'acme-agent-1.0.120.tar.gz', version: '1.0.120', sha256: 'e3'.repeat(32), size: 41234, signed: true, windows: WIN},
    commands: ['sha256sum acme-agent-1.0.120.tar.gz', 'tar xzf acme-agent-1.0.120.tar.gz', 'cd acme-agent-1.0.120 && sudo ./install.sh', 'sudo acme-agent join CODE'],
    rows: [
      {id: 1, name: 'web1', kind: 'agent', platform: 'linux', mode: 'passive', state: 'answers', host: 'web1.example.com', agent_host: 'web1', version: '1.0.120', code_hash: 'c0de',
       last_seen: now - 12, cert_end: now + 25 * 86400, policy_summary: {files: 1, units: 1, tests: 1, scripts: 1, from: 1, problems: 0}},
      {id: 5, name: 'winsrv1', kind: 'agent_windows', platform: 'windows', mode: 'passive', state: 'joining', host: 'winsrv1.corp.example.com', version: '', last_seen: null,
       cert_end: null, policy_summary: null}],
    waiting: [
      {id: 5, name: 'winsrv1', kind: 'agent_windows', platform: 'windows', mode: 'passive', host: 'WINSRV1', fqdn: 'winsrv1.corp.example.com', ip: '192.0.2.21',
       address: 'winsrv1.corp.example.com', os: 'Windows Server 2022 Standard (10.0.20348)', version: '1.0.120', fp: FP1, at: now - 300, enroll: {id: 'aaaaaaaaaaaa', title: 'Branch offices 2026'}},
      {id: 6, name: 'branch-db-with-a-rather-long-host-name-01', kind: 'agent', platform: 'linux', mode: 'passive', host: 'branch-db-with-a-rather-long-host-name-01',
       fqdn: 'branch-db-with-a-rather-long-host-name-01.branch.example.com', ip: '2001:db8:1234:5678::21', address: '', os: 'Rocky Linux 9.4 (Blue Onyx)',
       version: '1.0.120', fp: FP2, at: now - 200, enroll: {id: 'aaaaaaaaaaaa', title: 'Branch offices 2026'}},
      {id: 7, name: 'mail2', kind: 'agent', platform: 'linux', mode: 'active', host: 'mail2', fqdn: '', ip: '', address: 'mail2.example.com', os: '',
       version: '1.0.120', fp: FP3, at: now - 60, enroll: null}],
    enroll: [
      {id: 'aaaaaaaaaaaa', title: 'Branch offices 2026', mode: 'passive', port: 8446, until: now + 6 * 86400, most: 25, uses: 2, by: 'anna', at: now - 86400,
       auto: false, state: 'active', targets: ['winsrv1', 'branch-db-with-a-rather-long-host-name-01']},
      {id: 'bbbbbbbbbbbb', title: 'Lab (short-lived)', mode: 'active', port: 8446, until: now + 3600, most: 5, uses: 5, by: 'petr', at: now - 7200,
       auto: true, state: 'used', targets: ['lab1', 'lab2', 'lab3', 'lab4', 'lab5']},
      {id: 'cccccccccccc', title: 'Old rollout', mode: 'passive', port: 8446, until: now + 86400, most: 10, uses: 0, by: 'anna', at: now - 30 * 86400,
       auto: false, state: 'revoked', targets: [], revoked_by: 'petr', revoked_at: now - 600}]
  };
  const ONEW = {id: 5, name: 'winsrv1', kind: 'agent_windows', platform: 'windows', mode: 'passive', state: 'new', joined: false, host: 'winsrv1.corp.example.com',
    version: '', pending: null, package: VIEW.package, commands: VIEW.commands, ca: VIEW.ca, port: 8444, policy: null};
  const MADE = {id: 'dddddddddddd', title: 'Head office', mode: 'passive', port: 8446, until: now + 7 * 86400, most: 10, uses: 0, by: 'tester', at: now, auto: true,
    state: 'active', targets: [], code: 'ACAE1.' + 'eyJ2IjoxLCJlIjoiZGRkZGRkZGRkZGRkIiwicyI6Inh4eCJ9'.repeat(6), ca_fp: VIEW.ca.fp, endpoints: VIEW.endpoints};
  let packStrings = {};
  try {
    for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 390], ['cs', 390]]) {
      let pack = 'null';
      if (lang === 'cs') {
        const all = JSON.parse(read('lang/cs.json'));
        const pk = {code: 'cs', strings: {}, patterns: [], rich: {}};
        const same = {};
        for (const part of ['strings', 'patterns', 'rich']) {
          for (const e of Object.values(all[part] || {})) {
            if (!e || !e.source || !e.text) continue;
            if (e.text === e.source) { same[fold(e.source)] = true; continue; }
            if (part === 'patterns') pk.patterns.push([e.source, e.text]); else pk[part][e.source] = e.text;
          }
        }
        for (const k of Object.keys(extra)) {
          if (/\{\d/.test(k)) pk.patterns.push([k, extra[k]]); else pk.strings[k] = extra[k];
        }
        packStrings = {};
        for (const k of Object.keys(same)) packStrings[k] = k;
        for (const k of Object.keys(pk.strings)) packStrings[fold(k)] = pk.strings[k];
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
        + '<style>' + read('assets/policybuilder.css') + '</style>'
        + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div></main>' + modalHtml
        + '<div class="toast" id="toast"></div>'
        + '<script>' + esc(read('assets/i18n.js')) + '</script>'
        + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = [];'
        + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONEW = ' + JSON.stringify(ONEW) + '; var MADE = ' + JSON.stringify(MADE) + ';</script>'
        + '<script>' + esc(read('assets/core.js')) + '</script>'
        + '<script>' + esc(read('assets/agents.js')) + '</script>'
        + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
        + ' var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
        + ' if (what === "agents") return c(VIEW);'
        + ' if (what.indexOf("agents/one") === 0) return c(ONEW);'
        + ' if (what === "agents/look") return c({agent: ONEW});'
        + ' if (what === "agents/code") return c({code: "ACAG1.eyJ2IjoxLCJ0Ijo1fQ", until: Date.now() / 1000 + 3600, mode: "passive", ca_fp: VIEW.ca.fp, endpoints: [], port: 8446, agent: ONEW});'
        + ' if (what === "agents/enroll") return c(Object.assign({}, MADE, {title: body.title || MADE.title, auto: !!body.auto}));'
        + ' if (what === "agents/enroll/revoke") return c({code: {}});'
        + ' if (what === "agents/confirm") return c({agent: {}});'
        + ' if (what === "agents/confirm-many") return c({rows: body.items.map(function (x) { return {id: x.id, name: "x", ok: true, said: "confirmed"}; }), confirmed: body.items.length});'
        + ' if (what === "agents/package?platform=windows") return c({name: VIEW.package.windows.name, filename: VIEW.package.windows.name, mime: "application/x-msi", data_b64: "AAAA"});'
        + ' return c({}); }, over: function (open) { open(); }, openTarget: function (n) { window.OPENED = n; }});</script>'
        + '</body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}, deviceScaleFactor: 2});
      page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
      page.on('console', (m) => { if (m.type() === 'error') out.errors.push(lang + width + ' console: ' + m.text()); });
      await page.setContent(html);
      await page.waitForTimeout(150);
      const tag = lang + width + '_';
      const fits = () => page.evaluate(() => {
        var ok = document.documentElement.scrollWidth <= window.innerWidth + 1;
        var m = document.getElementById('modal-box');
        if (m && !document.getElementById('modal').hidden) {
          ok = ok && m.getBoundingClientRect().right <= window.innerWidth + 1;
          Array.prototype.forEach.call(m.querySelectorAll('*'), function (x) {
            var r = x.getBoundingClientRect();
            if (r.width && r.right > window.innerWidth + 1 && getComputedStyle(x).position !== 'fixed') { ok = false; window.WIDE = (x.className || x.tagName) + ''; }
          });
        }
        Array.prototype.forEach.call(document.querySelectorAll('#pane-agents *'), function (x) {
          var r = x.getBoundingClientRect();
          if (r.width && r.right > window.innerWidth + 1 && !x.closest('.modal')) { ok = false; window.WIDE = (x.className || x.tagName) + ''; }
        });
        return ok;
      });
      await page.evaluate(() => ACME_AGENTS.pane());
      await page.waitForTimeout(250);
      // ---- waiting for confirmation
      out.checks[tag + 'waiting'] = await page.evaluate(() => {
        var w = document.getElementById('ag-wait');
        var rows = w.querySelectorAll('.ag-wrow');
        return rows.length === 3 && w.querySelectorAll('.ag-wgroup').length === 2 && w.querySelectorAll('.ag-os.win').length === 1
          && w.querySelectorAll('.ag-os.linux').length === 2 && Array.prototype.every.call(rows, function (r) { return r.querySelectorAll('.ag-fp-g').length === 16; })
          && w.querySelectorAll('.ag-wgroup-h .btn').length === 1 && w.querySelector('.ag-wait-h .btn').disabled
          && w.querySelector('.ag-wrow .ag-wos').textContent.indexOf('Windows Server 2022') === 0;
      });
      out.checks[tag + 'pane_fits'] = await fits();
      if (!out.checks[tag + 'pane_fits']) out['wide_' + tag] = await page.evaluate(() => window.WIDE);
      if (shots) await page.locator('#ag-wait').screenshot({path: path.join(shots, 'waiting-' + lang + width + '.png')});
      // one by one: its fingerprint, then confirm
      await page.evaluate(() => document.querySelector('#ag-wait .ag-wrow > .btn').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'confirm_one_asked'] = await page.evaluate(() => document.querySelectorAll('#modal-body .ag-fp-g').length === 16 && !!document.querySelector('#modal-body .ag-os.win'));
      out.checks[tag + 'confirm_one_fits'] = await fits();
      await page.evaluate(() => { SENT.length = 0; document.querySelector('#modal-foot .btn.primary').click(); });
      await page.waitForTimeout(200);
      out.checks[tag + 'confirm_one_sent'] = await page.evaluate((fp) => SENT.some(function (x) { return x[0] === 'agents/confirm' && x[1].id === 5 && x[1].fp === fp; }), FP1);
      await page.evaluate(() => { try { closeModal(true); } catch (e) { } return ACME_AGENTS.pane(); });
      await page.waitForTimeout(250);
      // the ones selected
      await page.evaluate(() => { var c = document.querySelectorAll('#ag-wait .ag-wpick'); c[1].click(); c[2].click(); });
      out.checks[tag + 'selected'] = await page.evaluate(() => { var b = document.querySelector('#ag-wait .ag-wait-h .btn'); return !b.disabled && /2/.test(b.textContent); });
      await page.evaluate(() => document.querySelector('#ag-wait .ag-wait-h .btn').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'selected_asked'] = await page.evaluate(() => document.querySelectorAll('#modal-body .ag-many-one').length === 2
        && document.querySelectorAll('#modal-body .ag-many-one .ag-fp-g').length === 32);
      out.checks[tag + 'selected_fits'] = await fits();
      if (!out.checks[tag + 'selected_fits']) out['wide_sel_' + tag] = await page.evaluate(() => window.WIDE);
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'confirm-many-' + lang + width + '.png')});
      await page.evaluate(() => { SENT.length = 0; document.querySelector('#modal-foot .btn.primary').click(); });
      await page.waitForTimeout(200);
      out.checks[tag + 'selected_sent'] = await page.evaluate((fps) => {
        var x = SENT.filter(function (y) { return y[0] === 'agents/confirm-many'; })[0];
        return !!x && x[1].items.length === 2 && x[1].items[0].id === 6 && x[1].items[0].fp === fps[0] && x[1].items[1].id === 7 && x[1].items[1].fp === fps[1];
      }, [FP2, FP3]);
      await page.evaluate(() => { try { closeModal(true); } catch (e) { } return ACME_AGENTS.pane(); });
      await page.waitForTimeout(250);
      // all of one code
      await page.evaluate(() => document.querySelector('#ag-wait .ag-wgroup-h .btn').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'code_all_asked'] = await page.evaluate(() => document.querySelectorAll('#modal-body .ag-many-one').length === 2
        && document.getElementById('modal-title').textContent.indexOf('Branch offices 2026') >= 0);
      await page.evaluate(() => { SENT.length = 0; document.querySelector('#modal-foot .btn.primary').click(); });
      await page.waitForTimeout(200);
      out.checks[tag + 'code_all_sent'] = await page.evaluate(() => {
        var x = SENT.filter(function (y) { return y[0] === 'agents/confirm-many'; })[0];
        return !!x && x[1].items.map(function (i) { return i.id; }).join() === '5,6';
      });
      await page.evaluate(() => { try { closeModal(true); } catch (e) { } });
      // ---- the enrollment codes
      out.checks[tag + 'codes'] = await page.evaluate(() => {
        var e = document.getElementById('ag-enroll');
        var r = e.querySelectorAll('.ag-erow');
        return r.length === 3 && !!r[0].querySelector('.ag-badge.ok') && !!r[1].querySelector('.ag-badge.bad') && r[1].classList.contains('dim')
          && r[0].querySelectorAll('.btn.danger').length === 1 && !r[1].querySelector('.btn.danger') && !r[2].querySelector('.btn.danger')
          && r[0].querySelectorAll('.ag-etarget').length === 2 && r[0].querySelector('.ag-uses-bar span').style.width === '8%'
          && !e.querySelector('.ag-list-h .btn').disabled;
      });
      if (shots) { await page.evaluate(() => document.getElementById('ag-enroll').scrollIntoView()); await page.waitForTimeout(700); await page.locator('#ag-enroll').screenshot({path: path.join(shots, 'codes-' + lang + width + '.png')}); }
      await page.evaluate(() => document.querySelector('#ag-enroll .ag-etarget').click());
      out.checks[tag + 'code_target_opens'] = await page.evaluate(() => window.OPENED === 'winsrv1');
      // revoke: asked first
      await page.evaluate(() => document.querySelector('#ag-enroll .ag-erow .btn.danger').click());
      await page.waitForTimeout(150);
      await page.evaluate(() => { SENT.length = 0; document.querySelector('#modal-foot .btn.danger').click(); });
      await page.waitForTimeout(200);
      out.checks[tag + 'revoke_sent'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/enroll/revoke' && x[1].id === 'aaaaaaaaaaaa'; }));
      await page.evaluate(() => { try { closeModal(true); } catch (e) { } });
      // make one
      await page.evaluate(() => document.querySelector('#ag-enroll .ag-list-h .btn').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'dialog'] = await page.evaluate(() => {
        var b = document.getElementById('modal-body');
        return b.querySelectorAll('.set-item').length === 6 && b.querySelector('.ag-auto-warn').hidden && b.querySelectorAll('.ag-eseg button').length === 2;
      });
      await page.evaluate(() => { var s = document.querySelector('#modal-body .sw input'); s.click(); });
      await page.waitForTimeout(80);
      out.checks[tag + 'dialog_auto_red'] = await page.evaluate(() => !document.querySelector('#modal-body .ag-auto-warn').hidden
        && getComputedStyle(document.querySelector('#modal-body .ag-auto-warn')).display !== 'none');
      out.checks[tag + 'dialog_fits'] = await fits();
      if (!out.checks[tag + 'dialog_fits']) out['wide_dlg_' + tag] = await page.evaluate(() => window.WIDE);
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'make-' + lang + width + '.png')});
      if (lang === 'cs') {
        const text = await page.evaluate(() => document.getElementById('modal-box').innerText);
        const left = DWORDS.filter((w) => packStrings[fold(w)] === undefined || (text.indexOf(w) >= 0 && packStrings[fold(w)] !== w));
        out.checks[tag + 'dialog_czech'] = !left.length;
        if (left.length) out['dleft_' + tag] = left;
      }
      await page.evaluate(() => {
        var t = document.querySelector('#modal-body input[type=text]'); t.value = 'Head office'; t.dispatchEvent(new Event('input', {bubbles: true}));
        document.querySelectorAll('#modal-body .ag-eseg button')[1].click();
        var n = document.querySelectorAll('#modal-body .ag-num'); n[2].value = '40'; n[2].dispatchEvent(new Event('input', {bubbles: true}));
        SENT.length = 0;
        document.querySelector('#modal-foot .btn.primary').click();
      });
      await page.waitForTimeout(300);
      out.checks[tag + 'made_sent'] = await page.evaluate(() => {
        var x = SENT.filter(function (y) { return y[0] === 'agents/enroll'; })[0];
        return !!x && x[1].title === 'Head office' && x[1].mode === 'active' && x[1].most === 40 && x[1].days === 7 && x[1].auto === true;
      });
      out.checks[tag + 'made_shown'] = await page.evaluate((code) => {
        var b = document.getElementById('modal-body');
        return b.querySelector('.ag-code pre').textContent === code && !!b.querySelector('.ag-made .ag-badge.bad')
          && b.querySelectorAll('.ag-osseg button').length === 2 && b.querySelector('.dbs-steps').textContent.indexOf('sudo ./install.sh --join ' + code) >= 0;
      }, MADE.code);
      out.checks[tag + 'made_fits'] = await fits();
      if (!out.checks[tag + 'made_fits']) out['wide_made_' + tag] = await page.evaluate(() => window.WIDE);
      await page.evaluate(() => document.querySelectorAll('#modal-body .ag-osseg button')[1].click());
      await page.waitForTimeout(100);
      out.checks[tag + 'made_windows'] = await page.evaluate((code) => {
        var t = document.getElementById('modal-body').textContent;
        return t.indexOf('msiexec /i acme-agent-1.0.120-windows-x64.msi /qn JOINCODE=' + code) >= 0 && t.indexOf('acme-agent join ' + code) >= 0
          && document.querySelectorAll('#modal-body .ag-wincmd').length === 2;
      }, MADE.code);
      out.checks[tag + 'made_windows_fits'] = await fits();
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'made-' + lang + width + '.png')});
      await page.evaluate(() => { try { closeModal(true); } catch (e) { } });
      // ---- the package: Linux as before, Windows a tab of its own
      out.checks[tag + 'package_linux'] = await page.evaluate(() => {
        var p = document.getElementById('ag-pkg');
        return p.querySelectorAll('.ag-osseg button').length === 2 && p.querySelector('.ag-pkg-name').textContent === 'acme-agent-1.0.120.tar.gz'
          && p.querySelectorAll('.ag-cmd').length === 4;
      });
      await page.evaluate(() => document.querySelectorAll('#ag-pkg .ag-osseg button')[1].click());
      await page.waitForTimeout(100);
      out.checks[tag + 'package_windows'] = await page.evaluate(() => {
        var p = document.getElementById('ag-pkg');
        return p.querySelector('.ag-pkg-name').textContent === 'acme-agent-1.0.120-windows-x64.msi' && !!p.querySelector('.ag-pkg-win .btn.primary')
          && p.textContent.indexOf('msiexec /i acme-agent-1.0.120-windows-x64.msi /qn JOINCODE=CODE') >= 0
          && p.textContent.indexOf('Get-FileHash acme-agent-1.0.120-windows-x64.msi') >= 0 && p.querySelectorAll('.ag-cmd').length === 3;
      });
      out.checks[tag + 'package_fits'] = await fits();
      if (!out.checks[tag + 'package_fits']) out['wide_pkg_' + tag] = await page.evaluate(() => window.WIDE);
      if (shots) { await page.evaluate(() => document.getElementById('ag-pkg').scrollIntoView()); await page.waitForTimeout(500); } if (shots) await page.locator('#ag-pkg').screenshot({path: path.join(shots, 'package-win-' + lang + width + '.png')});
      await page.evaluate(() => { SENT.length = 0; document.querySelector('#ag-pkg .ag-pkg-win .btn.primary').click(); });
      await page.waitForTimeout(150);
      out.checks[tag + 'package_msi_asked'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/package?platform=windows'; }));
      // a source tree: no MSI - said so
      await page.evaluate(() => { VIEW.package.windows = null; VIEW.package.windows_why = 'a source tree has no Windows installer'; return ACME_AGENTS.pane(); });
      await page.waitForTimeout(250);
      out.checks[tag + 'package_none'] = await page.evaluate(() => {
        var p = document.getElementById('ag-pkg');
        return !!p.querySelector('.ag-pkg-none') && !p.querySelector('.ag-pkg-win') && p.textContent.indexOf('acme-agent-1.0.120-windows-x64.msi') >= 0;
      });
      if (lang === 'cs') {
        const text = await page.evaluate(() => document.getElementById('pane-agents').innerText);
        const left = WORDS.filter((w) => packStrings[fold(w)] === undefined || (text.indexOf(w) >= 0 && packStrings[fold(w)] !== w));
        out.checks[tag + 'czech'] = !left.length;
        if (left.length) out['left_' + tag] = left;
      }
      // ---- the join wizard of a Windows target
      await page.evaluate(() => ACME_AGENTS.wizard({id: 5, name: 'winsrv1', kind: 'agent_windows'}, null, function () { }));
      await page.waitForTimeout(250);
      out.checks[tag + 'wizard_windows'] = await page.evaluate(() => {
        var b = document.getElementById('modal-body');
        return !!b.querySelector('.ag-winsteps') && b.textContent.indexOf('sudo') < 0 && b.textContent.indexOf('msiexec /i') >= 0;
      });
      out.checks[tag + 'wizard_fits'] = await fits();
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'wizard-win-' + lang + width + '.png')});
      await page.evaluate(() => document.querySelector('#modal-foot .btn.primary').click());
      await page.waitForTimeout(250);
      out.checks[tag + 'wizard_windows_code'] = await page.evaluate(() => {
        var t = document.getElementById('modal-body').textContent;
        return t.indexOf('acme-agent join ACAG1.eyJ2IjoxLCJ0Ijo1fQ') >= 0 && t.indexOf('sudo acme-agent') < 0;
      });
      await page.evaluate(() => { try { closeModal(true); } catch (e) { } });
      await page.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
