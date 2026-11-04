// Signing in over SSH with a code from acme (admin.js, as otp 1.0.178 - 1.0.243) - the card of
// Settings → SSH server and notices in a page of its own, no daemon needed: the API answered here.
//
//   node test/sshcode_page.js /path/to/web [screenshot-folder]
//
// Drawn in English and in Czech, at 1300 and 390 px: the card "Signing in with a code from
// acme" with its switches (off until acme sets the SSH server and the code is asked), the
// "Only these accounts" picker ("Everybody but root (unless Root too)"), the key warning and
// the trial note; the SSH tokens table (Account, Note, The codes, Made, Last used; "A new one…"
// and "Remove" a row) and "Add an SSH token…" - the account picked from the nodes' accounts,
// one token per account (one that has it not offered), an app's QR shown once, mail and SMS
// only where sending is set up. Nothing in Czech left in English that has a translation.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

function fn(src, name) {
  // One top-level function of admin.js, whole.
  const a = src.indexOf('\nfunction ' + name + '(');
  if (a < 0) throw new Error('no function ' + name);
  const b = src.indexOf('\n}\n', a);
  return src.slice(a, b + 3);
}

(async () => {
  const web = process.argv[2];
  const shots = process.argv[3] || '';
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const admin = read('assets/admin.js');
  const a = admin.indexOf('var SD = {d: null');
  const b = admin.indexOf('/* ---- Settings → Syslog and SIEM, Proxy, Disks and logs', a);
  const sd = admin.slice(a, b) + ['settingByKey', 'hsOn', 'netFacts', 'liveLetGo'].map((n) => fn(admin, n)).join('\n');
  const page0 = read('admin/index.php');
  const pa = page0.indexOf('<div class="ctl-pane" id="pane-sshd"');
  const pane = page0.slice(pa, page0.indexOf('<div id="sd-host"></div>', pa) + '<div id="sd-host"></div>'.length)
    .replace(/ hidden>/, '>') + '</div>';
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  try {
    for (const [lang, width] of [['en', 1300], ['cs', 1300], ['cs', 390]]) {
      // As acme-page.php hands it to the page (acme_lang_pack).
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
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      const now = Date.now() / 1000;
      const view = {
        conf: {manage: true, port: 22, permit_root: 'prohibit-password', password: true, tries: 4, allow_users: [],
               notice: '', notice_ssh: false, notice_console: false, notice_motd: false, trial_min: 5,
               radius: true, radius_users: [], radius_root: false, radius_fallback: true, radius_with_key: true,
               radius_hide: false, hash: 'h1'},
        nodes: [{name: 'acme1', me: true, alive: true, keys: 1, state: 'done', radius: {module: true, pam: true, skip_passwd: true, conf: true, fp: 'x'},
                 now: {hash: 'h1', values: {port: '22', permitrootlogin: 'prohibit-password'}, there: true, dropins: true,
                       radius: {module: true, pam: true, skip_passwd: true, conf: true, fp: 'x'},
                       gate: {listening: true, port: 18129}}},
                {name: 'acme2', me: false, alive: true, keys: 0, state: 'done', radius: {module: false, pam: false},
                 now: {hash: 'h1', values: {port: '22'}, there: true, dropins: true,
                       radius: {module: false, pam: false}, gate: {listening: false, error: 'no free port of 18129-18199 on 127.0.0.1'}}}],
        helper: true, channels: ['mail'], gate_port: 18129,
        sshotp: [{name: 'root', kind: 'app', at: now - 86400, by: 'admin', note: 'the way in', used_at: now - 600, used_on: 'acme2', lang: 'cs', dest: ''},
                 {name: 'jan', kind: 'mail', at: now - 3600, by: 'admin', note: 'Jan Novák', used_at: null, used_on: '', lang: 'en', dest: 'j***@example.cz'}]};
      const keys = {nodes: [{name: 'acme1', alive: true, users: [{name: 'jan'}, {name: 'eva'}]},
                            {name: 'acme2', alive: true, users: [{name: 'eva'}, {name: 'petr'}]}]};
      const html = '<!doctype html><html class="dark"><head><meta charset="utf-8"><style>' + read('assets/acme.css')
        + '</style><script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main style="padding:16px">'
        + pane + '</main><div class="toast" id="toast"></div>'
        + '<div id="modal" hidden><div id="modal-box"><h2 id="modal-title"></h2><div id="modal-body"></div><div id="modal-foot"></div></div></div>'
        + '<script>' + read('assets/i18n.js').replace(/<\/script/g, '<\\/script') + '</script>'
        + '<script>' + read('assets/core.js').replace(/<\/script/g, '<\\/script') + '</script>'
        + '<script>var ADMIN = true, PENDING = {}, SENT = [], TAB = "settings", PANE = "sshd", SETTINGS = {settings: [{key: "code_lang", value: "cs"}]},'
        + ' STATUS = {node: "acme1", high_security: false};'
        + 'function pendingSet(k, p) { PENDING[k] = p; } function markDirtyCount() {}'
        + 'var VIEW = ' + JSON.stringify(view) + ', KEYS = ' + JSON.stringify(keys) + ';'
        + 'api = function (what, body) { SENT.push([what, body || null]);'
        + ' if (what === "sshkeys") return Promise.resolve(JSON.parse(JSON.stringify(KEYS)));'
        + ' if (what === "sshd" && !body) return Promise.resolve(JSON.parse(JSON.stringify(VIEW)));'
        + ' if (what === "sshd" && body.action === "sshotp_add") { var v = JSON.parse(JSON.stringify(VIEW));'
        + '   v.sshotp.push({name: body.name, kind: body.kind, at: Date.now() / 1000, by: "admin", note: body.note, lang: body.lang, dest: body.kind === "app" ? "" : "e***@example.cz"});'
        + '   v.made = body.kind === "app" ? {name: body.name, kind: "app", qr: "data:image/gif;base64,R0lGODlhAQABAAAAACw=", uri: "otpauth://totp/x", secret: "ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567"}'
        + '     : {name: body.name, kind: body.kind, dest: "e***@example.cz", lang: body.lang};'
        + '   v.message = body.kind === "app" ? "the SSH token of " + body.name + " is made - scan it now, it is not shown again" : "the SSH token of " + body.name + " is made - its codes go to e***@example.cz";'
        + '   return Promise.resolve(v); }'
        + ' if (what === "sshd" && body.action === "sshotp_remove") { var w = JSON.parse(JSON.stringify(VIEW)); w.sshotp = w.sshotp.filter(function (x) { return x.name !== body.name; }); w.message = "removed"; return Promise.resolve(w); }'
        + ' return Promise.reject(new Error("?")); };'
        + '</script><script>' + sd.replace(/<\/script/g, '<\\/script') + '</script></body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}});
      page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
      await page.setContent(html);
      await page.evaluate(() => loadSshd());
      await page.waitForTimeout(250);
      const tag = lang + width;
      const card = page.locator('#sd-host .card', {has: page.locator('.sd-tokens')});
      out.checks[tag + '_card'] = (await card.count()) === 1;
      const ct = await card.innerText();
      if (lang === 'en') {
        out.checks[tag + '_words'] = ['Signing in with a code from acme', 'Ask for a code from acme', 'Only these accounts',
          'Everybody but root (unless Root too)', 'Root too', 'A key, and then the code', 'The system password when acme does not answer',
          'Hide the code as it is typed', 'SSH tokens', 'Add an SSH token…', 'pam_radius is not on acme2',
          'A key and then the code: whoever the code is asked of needs an SSH key', 'Keep the session you have open'].every((w) => ct.indexOf(w) >= 0);
        if (!out.checks[tag + '_words']) out['card_' + tag] = ct;
        out.checks[tag + '_heads'] = JSON.stringify(await card.locator('.sd-tokens thead th').allTextContents())
          === JSON.stringify(['Account', 'Note', 'The codes', 'Made', 'Last used', '']);
        out.checks[tag + '_nodes_said'] = await page.evaluate(() => {
          const t = document.querySelector('#sd-host').innerText;
          return t.indexOf('127.0.0.1:18129') >= 0 && t.indexOf('asked (pam_radius)') >= 0 && t.indexOf('pam_radius is not here') >= 0;
        });
      }
      const rows = card.locator('.sd-tokens tbody tr');
      out.checks[tag + '_rows'] = (await rows.count()) === 2;
      out.checks[tag + '_row_buttons'] = (await rows.first().locator('td.acts button').count()) === 2;
      out.checks[tag + '_mail_row'] = (await rows.nth(1).innerText()).indexOf('j***@example.cz') >= 0;
      if (shots) await card.screenshot({path: path.join(shots, 'sshc-' + tag + '.png')});
      // Off until acme sets the SSH server: every switch of the card.
      if (lang === 'en') {
        await page.evaluate(() => { SD.draft.manage = false; drawSshd(); });
        out.checks[tag + '_off_without_manage'] = await page.evaluate(() => {
          const c = Array.prototype.filter.call(document.querySelectorAll('#sd-host .card'), (x) => x.querySelector('.sd-tokens'))[0];
          return Array.prototype.every.call(c.querySelectorAll('input[type=checkbox]'), (i) => i.disabled);
        });
        await page.evaluate(() => { SD.draft.manage = true; drawSshd(); });
      }
      // Add an SSH token: the accounts of the nodes, root and jan (who have one) not offered.
      await card.locator('.sd-tokens .btnrow button').click();
      await page.waitForSelector('#modal:not([hidden])');
      await page.waitForFunction(() => { const s = document.querySelector('#modal-body select.sd-who'); return s && !s.disabled; }, null, {timeout: 10000});
      out.checks[tag + '_picker'] = JSON.stringify(await page.evaluate(() =>
        Array.prototype.map.call(document.querySelectorAll('#modal-body select.sd-who option'), (o) => o.value).filter(Boolean)))
        === JSON.stringify(['eva', 'petr']);
      out.checks[tag + '_sms_needs_sending'] = await page.evaluate(() => {
        const bs = document.querySelectorAll('#modal-body .seg button');
        return bs.length === 3 && !bs[0].disabled && !bs[1].disabled && bs[2].disabled;
      });
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'sshc-add-' + tag + '.png')});
      if (lang === 'cs') out.checks[tag + '_picker_czech'] = await page.evaluate(() =>
        document.querySelector('#modal-body select.sd-who option').textContent === 'vyberte účet…');
      // Made without an account: refused here.
      await page.locator('#modal-foot button').last().click();
      await page.waitForTimeout(100);
      out.checks[tag + '_needs_account'] = await page.evaluate(() => SENT.every((s) => !s[1] || s[1].action !== 'sshotp_add'));
      await page.selectOption('#modal-body select.sd-who', 'eva');
      await page.locator('#modal-foot button').last().click();
      await page.waitForTimeout(250);
      out.checks[tag + '_made_app'] = await page.evaluate(() => {
        const s = SENT.filter((x) => x[1] && x[1].action === 'sshotp_add')[0];
        const t = document.querySelector('#modal-body').innerText;
        return !!s && s[1].name === 'eva' && s[1].kind === 'app' && !s[1].replace && !!document.querySelector('#modal-body .qrbox img')
          && t.indexOf('ABCD EFGH') >= 0 && t.indexOf('eva@acme1') >= 0;
      });
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'sshc-qr-' + tag + '.png')});
      await page.locator('#modal-foot button').last().click();
      await page.waitForTimeout(100);
      // A new one in jan's place: the account as it is, by mail.
      await page.evaluate(() => drawSshd());
      await page.locator('#sd-host .sd-tokens tbody tr').nth(1).locator('td.acts button').first().click();
      await page.waitForSelector('#modal:not([hidden])');
      out.checks[tag + '_replace_as_is'] = await page.evaluate(() => {
        const i = document.querySelector('#modal-body input.mono');
        return !!i && i.disabled && i.value === 'jan' && !document.querySelector('#modal-body select.sd-who');
      });
      await page.locator('#modal-foot button').last().click();
      await page.waitForTimeout(250);
      out.checks[tag + '_replaced'] = await page.evaluate(() => {
        const s = SENT.filter((x) => x[1] && x[1].action === 'sshotp_add' && x[1].name === 'jan')[0];
        return !!s && s[1].replace === true && s[1].kind === 'mail' && document.querySelector('#modal').hidden;
      });
      // Remove: asked first.
      await page.locator('#sd-host .sd-tokens tbody tr').first().locator('td.acts button').last().click();
      await page.waitForSelector('#modal:not([hidden])');
      out.checks[tag + '_remove_asks'] = (await page.locator('#modal-body').innerText()).length > 10;
      // Asked twice: "Really?" first.
      await page.locator('#modal-foot button').last().click();
      out.checks[tag + '_remove_really'] = await page.evaluate(() => SENT.every((x) => !x[1] || x[1].action !== 'sshotp_remove'));
      await page.locator('#modal-foot .sure-strip button.danger').click();
      await page.waitForTimeout(250);
      out.checks[tag + '_removed'] = await page.evaluate(() =>
        SENT.some((x) => x[1] && x[1].action === 'sshotp_remove' && x[1].name === 'root'));
      await page.evaluate(() => { SD.d = JSON.parse(JSON.stringify(VIEW)); drawSshd(); });
      if (lang === 'cs') {
        const left = await page.evaluate(() => {
          const words = ['Signing in with a code', 'Ask for a code', 'Only these accounts', 'Everybody but root', 'Root too',
                         'A key, and then the code', 'The system password when', 'Hide the code', 'SSH tokens', 'Add an SSH token',
                         'Last used', 'The codes', 'A new one', 'Remove', 'Keep the session', 'is not on', 'gate for SSH', 'never'];
          const t = document.querySelector('#sd-host').innerText;
          return words.filter((w) => t.indexOf(w) >= 0);
        });
        out.checks[tag + '_czech'] = left.length === 0;
        if (left.length) out['left_' + tag] = left;
        out.checks[tag + '_czech_words'] = await page.evaluate(() => {
          const t = document.querySelector('#sd-host').innerText;
          return t.indexOf('SSH tokeny') >= 0 && t.indexOf('Přidat SSH token') >= 0;
        });
      }
      out.checks[tag + '_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      await page.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
