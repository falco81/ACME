// The pages' half of test/test_hunt_q5_ui.py, in Chromium.
//
//   node test/hunt_q5_ui_page.js BASE_URL NAME PASSWORD
//
// Prints one line of JSON: what was seen.
//  - Settings -> Time ("Its time") and Backups ("Next"): dd-mm-yyyy hh:mm:ss, as every time.
//  - High security: a rule made an exception - the "not allowed" note of its setting goes,
//    on the panes drawn already, without a reload.
//  - The caps of the directories' passwords: a directory gone while its change waited.
//  - At 375 px: SSH server's choices inside their frame, an account's buttons on one line,
//    a source's window with its words the width of it, the certificate tool's sides.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const signIn = async (width) => {
    const ctx = await browser.newContext({viewport: {width: width, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    page.on('dialog', d => { out.errors.push('dialog: ' + d.message()); d.dismiss(); });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    return page;
  };
  const pane = async (page, p) => {
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.waitForTimeout(300);
    await page.evaluate(p => document.querySelector('#ctl-nav button[data-pane="' + p + '"]').click(), p);
    await page.waitForTimeout(1800);
  };
  try {
    const page = await signIn(1300);

    // ---- Backups: Next ----
    await pane(page, 'backup');
    await page.waitForFunction(() => typeof RB !== 'undefined' && RB, null, {timeout: 20000});
    out.next = await page.evaluate(() => {
      RB.next = '2026-11-18T04:15';
      drawRbTop();
      const f = Array.from(document.querySelectorAll('#rb-top .rb-fact')).find(x => x.querySelector('.k').textContent === 'Next');
      return f ? f.querySelector('.v').textContent : null;
    });

    // ---- Time: its time ----
    await pane(page, 'time');
    await page.waitForFunction(() => NTP.d && NTP.d.nodes && NTP.d.nodes.length, null, {timeout: 20000});
    out.clock = await page.evaluate(() => {
      const n = NTP.d.nodes[0];
      const t = 1763370000;               // 17-11-2025, whatever the time zone
      NTP.d.now = t;
      n.now = {at: t, data: Object.assign({}, (n.now || {}).data || {}, {time: t})};
      drawNtp();
      const f = Array.from(document.querySelectorAll('#ntp-host .net-fact')).find(x => x.querySelector('.k').textContent === 'Its time');
      return {shown: f ? f.querySelector('.v').textContent : null, want: stamp(t)};
    });

    // ---- High security: an exception redraws the settings drawn ----
    out.hisec = await page.evaluate(async () => {
      const was = {status: STATUS, settings: SETTINGS, api: window.api};
      const fake = {key: 'q5_fake', name: 'Q5 fake', value: 1, default: true, min: 0, max: 1, source: 'default',
                    hisec: {why: 'q5 reason', forbid: [0]}};
      STATUS = Object.assign({}, STATUS, {high_security: true, hisec_waived: []});
      SETTINGS = Object.assign({}, SETTINGS, {settings: (SETTINGS.settings || []).concat([fake])});
      const host = document.createElement('div');
      host.id = 'q5-host';
      document.body.appendChild(host);
      host.appendChild(settingItem(fake));
      const r = {before: !!host.querySelector('.hs-note'),
                 lockedBefore: document.getElementById('set-q5_fake')._input.disabled};
      // the rule made an exception: the server answers the settings without its hisec
      STATUS.hisec_waived = ['q5_fake'];
      window.api = function (what, body) {
        if (what === 'settings' && !body) {
          return Promise.resolve(Object.assign({}, SETTINGS, {settings: SETTINGS.settings.map(s => s.key === 'q5_fake' ? Object.assign({}, s, {hisec: null}) : s)}));
        }
        return was.api.apply(this, arguments);
      };
      hsSettingsAgain();
      await new Promise(res => setTimeout(res, 400));
      r.after = !!host.querySelector('.hs-note');
      r.lockedAfter = document.getElementById('set-q5_fake')._input.disabled;
      // drawn afresh while it is an exception: nothing greyed out
      const again = settingItem(Object.assign({}, fake));
      r.freshNote = !!again.querySelector('.hs-note');
      window.api = was.api;
      STATUS = was.status;
      SETTINGS = was.settings;
      host.remove();
      return r;
    });

    // ---- the directories' caps: one gone while its change waited ----
    out.dp = await page.evaluate(() => {
      const was = {data: DP.data, draft: DP.draft, pend: PENDING.dirpw};
      const r = {};
      try {
        DP.data = {directories: [{name: 'q5-a', tries: 3, window_min: 10}], setting: {tries: 0, window_min: 30}};
        DP.draft = {'q5-a': {tries: 3, window_min: 10}, 'q5-gone': {tries: 9, window_min: 10}};
        PENDING.dirpw = {save: function () { return Promise.resolve(true); }, reset: function () {}};
        dpChanged();
        r.threw = '';
        r.keys = Object.keys(DP.draft).sort();
        r.pending = !!PENDING.dirpw;
        // a change to one there still counts
        DP.draft['q5-a'].tries = 5;
        dpChanged();
        r.pendingChanged = !!PENDING.dirpw;
      } catch (e) {
        r.threw = String(e && e.message || e);
      }
      DP.data = was.data; DP.draft = was.draft;
      if (was.pend) PENDING.dirpw = was.pend; else delete PENDING.dirpw;
      return r;
    });

    // ---- at a phone's width ----
    const phone = await signIn(375);
    await pane(phone, 'sshd');
    await phone.locator('#sd-host .seg').first().waitFor({timeout: 20000});
    out.seg = await phone.evaluate(() => Array.from(document.querySelectorAll('#sd-host .seg')).filter(s => s.offsetParent).map(s => {
      const f = s.getBoundingClientRect();
      return {right: Math.round(f.right), most: Math.max.apply(null, Array.from(s.children).map(b => Math.round(b.getBoundingClientRect().right)))};
    }));
    out.phoneWide = await phone.evaluate(() => document.documentElement.scrollWidth);
    await pane(phone, 'people');
    await phone.locator('#us-table table tbody tr').first().waitFor({timeout: 20000});
    out.accountRow = await phone.evaluate(() => Math.round(document.querySelector('#us-table table tbody tr').getBoundingClientRect().height));

    await phone.evaluate(() => document.querySelector('.tabs button[data-tab="sources"]').click());
    await phone.waitForTimeout(1500);
    await phone.locator('#tab-sources table tbody tr').first().waitFor({timeout: 20000});
    await phone.evaluate(() => { const r = document.querySelector('#tab-sources table tbody tr'); (r.querySelector('a, .name, td') || r).click(); });
    await phone.locator('#modal-body .ct-plughead-w').waitFor({timeout: 20000});
    out.plughead = await phone.evaluate(() => Math.round(document.querySelector('#modal-body .ct-plughead-w').getBoundingClientRect().width));
    out.defaultTag = await phone.evaluate(() => { const t = document.querySelector('#modal-body .ct-default-note > .tag'); return t ? Math.round(t.getBoundingClientRect().height) : 0; });
    await phone.evaluate(() => { MODAL_TYPED = 0; while (!document.getElementById('modal').hidden) closeModal(true); });

    await phone.evaluate(() => document.querySelector('.tabs button[data-tab="certs"]').click());
    await phone.waitForTimeout(1500);
    await phone.evaluate(() => Array.from(document.querySelectorAll('#tab-certs button')).find(b => b.offsetParent && /Show a certificate/.test(b.textContent)).click());
    await phone.locator('#modal-body .cv-page').waitFor({timeout: 20000});
    out.cvPad = await phone.evaluate(() => getComputedStyle(document.querySelector('#modal-body .cv-page')).paddingLeft);
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
