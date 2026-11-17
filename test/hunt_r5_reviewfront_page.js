// The pages' half of test/test_hunt_r5_reviewfront.py, in Chromium against a real daemon.
//
//   node test/hunt_r5_reviewfront_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: what was seen.
//  - The administration's sign-in in EN and CS, at 1400 and 390: empty name, then empty password,
//    the page's own words; then the real sign-in still goes through.
//  - Find a setting as read only: a setting of Monitoring (a pane any account may read, opened from
//    a link) is still found and opens Monitoring - 1.0.124's "only what it can open" hid it.
//  - Find a setting as a full administrator: Monitoring's still found; no page errors anywhere.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], signin: {}};
  const ctxOf = async (lang, width) => {
    const ctx = await browser.newContext({viewport: {width, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(lang + width + ': ' + String(e.message || e)));
    return page;
  };
  const toSettings = async page => {
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.waitForFunction(() => typeof SETTINGS !== 'undefined' && SETTINGS && SETTINGS.settings, null, {timeout: 20000});
    await page.waitForTimeout(500);
  };
  const find = (page, what) => page.evaluate(w => {
    const f = document.getElementById('ctl-find');
    f.value = w; f.dispatchEvent(new Event('input'));
    return Array.from(document.querySelectorAll('#ctl-found .ctl-hit:not(.ctl-hit-pane)')).map(h => [h.querySelector('.ctl-hit-t').textContent, h.querySelector('.ctl-hit-w').textContent]);
  }, what);
  try {
    for (const lang of ['en', 'cs']) {
      for (const width of [1400, 390]) {
        const p = await ctxOf(lang, width);
        await p.goto(base + '/admin/index.php');
        await p.click('#in-go');
        await p.waitForTimeout(300);
        const s = {empty: (await p.locator('#in-said').innerText()).trim()};
        await p.fill('#in-name', 'tester');
        await p.click('#in-go');
        await p.waitForTimeout(300);
        s.noPass = (await p.locator('#in-said').innerText()).trim();
        await p.type('#in-pass', pass);
        await Promise.all([p.waitForNavigation(), p.click('#in-go')]);
        await p.waitForTimeout(800);
        s.signedIn = await p.evaluate(() => !!document.getElementById('signout'));
        s.wide = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        out.signin[lang + width] = s;
        await p.context().close();
      }
    }
    // the monitoring pane's setting keys, as the page knows them
    const a = await ctxOf('en', 1400);
    await a.goto(base + '/admin/index.php');
    await a.fill('#in-name', 'tester');
    await a.type('#in-pass', pass);
    await Promise.all([a.waitForNavigation(), a.click('#in-go')]);
    await a.waitForTimeout(800);
    await toSettings(a);
    out.monKeys = await a.evaluate(() => (SETTINGS.panes.monitor || []).slice());
    out.adminMon = out.monKeys.length ? await find(a, out.monKeys[0]) : [];
    await a.context().close();

    const r = await ctxOf('en', 1400);
    await r.goto(base + '/admin/index.php');
    await r.fill('#in-name', 'viewer');
    await r.type('#in-pass', pass);
    await Promise.all([r.waitForNavigation(), r.click('#in-go')]);
    await r.waitForTimeout(800);
    await toSettings(r);
    out.roMon = out.monKeys.length ? await find(r, out.monKeys[0]) : [];
    if (out.roMon.length) {
      await r.evaluate(() => document.querySelector('#ctl-found .ctl-hit:not(.ctl-hit-pane)').click());
      await r.waitForTimeout(1000);
      out.roMonPane = await r.evaluate(() => PANE);
    }
    out.roAlerts = await find(r, 'alerts_to');
    await r.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
