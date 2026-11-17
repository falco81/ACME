// The pages' half of test/test_hunt_r4_settingsui.py, in Chromium against a real daemon.
//
//   node test/hunt_r4_settingsui_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: what was seen.
//  - The administration's sign-in, empty, in Czech: the page's own words, not the browser's bubble.
//  - Find a setting as a full administrator: "admin_password_off" said "adminsignin" and opened
//    the first pane - now Accounts, its card there.
//  - Find a setting as read only: the settings of panes and cards only a full administrator
//    sees (Alerts and reports, the firewall's settings) are not offered.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const signIn = async (name, lang) => {
    const ctx = await browser.newContext({viewport: {width: 1400, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.waitForFunction(() => typeof SETTINGS !== 'undefined' && SETTINGS && SETTINGS.settings, null, {timeout: 20000});
    await page.waitForTimeout(500);
    return page;
  };
  const find = (page, what) => page.evaluate(w => {
    const f = document.getElementById('ctl-find');
    f.value = w; f.dispatchEvent(new Event('input'));
    return Array.from(document.querySelectorAll('#ctl-found .ctl-hit:not(.ctl-hit-pane)')).map(h => [h.querySelector('.ctl-hit-t').textContent, h.querySelector('.ctl-hit-w').textContent]);
  }, what);
  try {
    // ---- the sign-in, empty, in Czech ----
    const ctx0 = await browser.newContext({viewport: {width: 390, height: 800}});
    await ctx0.addCookies([{name: 'acme_lang', value: 'cs', url: base}]);
    const p0 = await ctx0.newPage();
    p0.on('pageerror', e => out.errors.push(String(e.message || e)));
    await p0.goto(base + '/admin/index.php');
    out.novalidate = await p0.evaluate(() => document.getElementById('signin-form').noValidate);
    await p0.click('#in-go');
    await p0.waitForTimeout(400);
    out.emptySaid = (await p0.locator('#in-said').innerText()).trim();
    await p0.fill('#in-name', 'tester');
    await p0.click('#in-go');
    await p0.waitForTimeout(400);
    out.noPassSaid = (await p0.locator('#in-said').innerText()).trim();
    out.focused = await p0.evaluate(() => document.activeElement && document.activeElement.id);
    await ctx0.close();

    // ---- Find a setting, a full administrator ----
    const a = await signIn('tester', 'en');
    out.adminHits = await find(a, 'admin_password_off');
    await a.evaluate(() => document.querySelector('#ctl-found .ctl-hit:not(.ctl-hit-pane)').click());
    await a.waitForTimeout(1200);
    out.adminPane = await a.evaluate(() => PANE);
    out.adminItemShown = await a.evaluate(() => { const i = document.querySelector('.set-item[data-key="admin_password_off"]'); return !!(i && i.offsetParent); });
    out.portalHits = await find(a, 'portal_password_off');
    out.alertsForAdmin = (await find(a, 'alerts_to')).length;
    await a.context().close();

    // ---- Find a setting, read only ----
    const r = await signIn('viewer', 'en');
    out.roAlerts = await find(r, 'alerts_to');
    out.roFw = await find(r, 'fw_confirm_min');
    out.roCodes = (await find(r, 'code_digits')).length;
    await r.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
