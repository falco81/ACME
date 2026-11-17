// Settings (admin.js), regressions of 1.0.119 (round q3) - drawn in a page of its own, the API
// answered here.
//
//   node test/hunt_q3_settings_page.js /path/to/web
//
// * Message texts: two messages of one short name in a group (the portal's code by mail and
//   SSH's) listed by their whole titles; one of its own by its short name.
// * Backups: the list of what was sent, the backups at a destination and the question before
//   one is put back say a time as every column does (dd-mm-yyyy hh:mm:ss), not the browser's.
// * Put back from a backup: the settings and the pane drawn again once it is done.
// * Accounts: the box to find the groups by stays inside a phone's width (375 px).
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const admin = read('assets/admin.js');
  const fnOf = (name) => {
    const i = admin.indexOf('\nfunction ' + name + '(');
    if (i < 0) throw new Error('no function ' + name);
    const j = admin.indexOf('\n}\n', i);
    return admin.slice(i, j + 3);
  };
  const fns = ['txT', 'txMsg', 'drawTexts', 'rbBytes', 'drawRbRuns', 'rbListThere', 'rbPutBackConfirm',
    'rbRestoreWatch', 'paneLive'].map(fnOf).join('\n');
  const page0 = read('admin/index.php');
  const lineAt = page0.indexOf('id="ag-like"');
  const agStyle = /style="([^"]*)"/.exec(page0.slice(lineAt, page0.indexOf('>', lineAt)))[1];
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  try {
    const html = '<!doctype html><html><head><meta charset="utf-8">'
      + '<meta name="viewport" content="width=device-width, initial-scale=1"><style>' + read('assets/acme.css')
      + '</style></head><body><main><div id="tx-root"></div><div id="rb-runs-tools"></div><div id="rb-runs"></div>'
      + '<div class="btnrow" id="agrow"><input type="search" id="ag-like" style="' + agStyle + '"><button class="btn cmd primary">Find the groups</button></div>'
      + '<div class="ctl-pane" id="pane-backup"></div></main>'
      + '<div class="modal" id="modal" hidden><div id="modal-box"><h3 id="modal-title"></h3><div id="modal-body"></div><div id="modal-foot"></div></div></div>'
      + '<div class="toast" id="toast"></div>'
      + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = []; var JOB = null;'
      + ' var TAB = "settings", PANE = "backup", ADMIN = true; var LOADED = {settings: 0, backup: 0};</script>'
      + '<script>' + esc(read('assets/core.js')) + '</script>'
      + '<script>api = function (what, body) { SENT.push([what, body || null]);'
      + ' if (what === "db") return Promise.resolve({job: JOB});'
      + ' if (what === "rbackup" && body && body.action === "list") return Promise.resolve({files: [{when: 1795392369, name: "acme-backup-x.tar.gz.enc", node: "acme1", mine: true, bytes: 13000}]});'
      + ' return Promise.resolve({}); };'
      + 'function txFitShell() {} function saveBarHome() {} function txDrawEditor() {} function txLeave(go) { go(); }'
      + 'function loadSettings() { LOADED.settings++; } function loadRbackup() { LOADED.backup++; }'
      + 'var TX = {data: null, id: null, lang: "cs", dirty: {}, eds: {}}; var TX_KINDS = [["mail", "E-mails", "mail"], ["sms", "SMS", "phone"], ["prompt", "SSH", "key"]];'
      + 'var RB = null;</script>'
      + '<script>' + esc(fns) + '</script></body></html>';
    const page = await browser.newPage({viewport: {width: 1300, height: 900}});
    page.on('pageerror', (e) => out.errors.push(String(e)));
    await page.setContent(html);
    await page.waitForTimeout(100);
    // ---- the texts' list
    out.checks.texts_titles = await page.evaluate(() => {
      var m = function (id, kind, short, title) { return {id: id, kind: kind, short: short, title: title, fields: [], saved: {cs: {}, en: {}}}; };
      TX.data = {langs: ['cs', 'en'], may_change: true, placeholders: {}, messages: [
        m('verify_mail', 'mail', 'Checking an address', 'Checking an address'),
        m('admin_mail', 'mail', 'The sign-in code by mail', 'The administration: a sign-in code by mail'),
        m('portal_mail', 'mail', 'The sign-in code by mail', 'The certificate portal: a sign-in code by mail'),
        m('ssh_mail', 'mail', 'The sign-in code by mail', 'SSH: a sign-in code by mail')]};
      TX.id = 'verify_mail';
      drawTexts();
      var got = Array.prototype.map.call(document.querySelectorAll('#tx-root .tx-item-t'), function (x) { return x.textContent; });
      var want = ['Checking an address', 'The certificate portal: a sign-in code by mail', 'SSH: a sign-in code by mail',
        'The sign-in code by mail'];
      return got.join('|') === want.join('|') ? true : got.join('|');
    });
    // ---- the backups' times
    const at = 1795392369;   // a moment; said as stamp() says it
    out.checks.backup_times = await page.evaluate((at) => {
      RB = {runs: [{at: at, node: 'acme1', file: 'acme-backup-x.tar.gz.enc', encrypted: true, bytes: 13000, targets: [{ok: true, name: 'NAS', secs: 1}], by: 'tester'}]};
      drawRbRuns();
      var cell = document.querySelector('#rb-runs tbody td');
      var a = cell ? cell.textContent.trim() : '';
      rbPutBackConfirm({id: 1, name: 'x', when: at, node: 'acme1'});
      var b = document.getElementById('modal-body').textContent;
      var want = stamp(at);
      return a === want && b.indexOf(want) >= 0 && /^\d\d-\d\d-\d{4} \d\d:\d\d:\d\d$/.test(want) ? true : [a, want, b.slice(0, 120)];
    }, at);
    out.checks.backup_there_time = await page.evaluate((at) => new Promise(function (done) {
      closeModal();
      rbListThere({id: 1, name: 'NAS'});
      setTimeout(function () {
        var t = document.getElementById('modal-body').textContent;
        done(t.indexOf(stamp(at)) >= 0 ? true : t.slice(0, 200));
      }, 200);
    }), at);
    // ---- put back: what is behind the popup drawn again
    out.checks.restore_redraws = await page.evaluate(() => new Promise(function (done) {
      closeModal();
      JOB = {running: false, what: 'putting a backup back', result: {said: ['done']}};
      document.getElementById('pane-backup').hidden = false; TAB = 'settings'; PANE = 'backup';
      rbRestoreWatch();
      setTimeout(function () {
        done(LOADED.settings === 1 && LOADED.backup === 1 ? true : JSON.stringify(LOADED));
      }, 1500);
    }));
    await page.evaluate(() => closeModal());
    await page.close();
    // ---- the box to find groups by, at a phone's width
    const phone = await browser.newPage({viewport: {width: 375, height: 800}});
    phone.on('pageerror', (e) => out.errors.push(String(e)));
    await phone.setContent(html);
    await phone.waitForTimeout(100);
    out.checks.ag_like_phone = await phone.evaluate(() => {
      var r = document.getElementById('ag-like').getBoundingClientRect();
      return r.right <= window.innerWidth && document.documentElement.scrollWidth <= window.innerWidth ? true : [r.right, document.documentElement.scrollWidth];
    });
    await phone.close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every((x) => x === true);
  console.log(JSON.stringify(out));
})();
