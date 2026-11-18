// The pages' half of test/test_hunt_rt8_uisweep.py, in Chromium against a real daemon.
//
//   node test/hunt_rt8_uisweep_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: the width of Settings -> Request profiles' columns, at 390, 768
// and 1400 px, in English and in Czech, and the errors of the pages.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], seen: []};
  try {
    for (const lang of ['en', 'cs']) for (const w of [390, 768, 1400]) {
      const ctx = await browser.newContext({viewport: {width: w, height: 900}});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(String(e.message || e)));
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1500);
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
      await page.evaluate(() => document.querySelector('#ctl-nav button[data-pane="reqprofiles"]').click());
      await page.waitForFunction(() => document.querySelector('.rp-table tr.rp-row'), null, {timeout: 20000});
      await page.waitForTimeout(800);
      out.seen.push(await page.evaluate(([lang, w]) => {
        const t = document.querySelector('.rp-table');
        const b = t.querySelector('tr.rp-row td:first-child b');
        const line = parseFloat(getComputedStyle(b).lineHeight) || 20;
        return {lang, w, profile: Math.round(t.querySelector('th').getBoundingClientRect().width),
                nameLines: Math.round(b.getBoundingClientRect().height / line),
                hscroll: document.scrollingElement.scrollWidth - innerWidth};
      }, [lang, w]));
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
