// The pages' half of test/test_hunt_rv2_ui.py (hunt v2, ui): Settings → Agent fleet for an account
// kept to its teams (a calm note, nothing asked - no 403, no red failure) and for a full
// administrator (the fleet drawn); the Events of the 1.0.140 reports and team digests in Czech.
//
//   node test/hunt_rv2_ui_page.js BASE_URL PASSWORD [screenshot-folder]
//
// English and Czech, 1400 and 390 px. Prints one line of JSON.
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  try {
    for (const who of ['tester', 'cm', 'jan']) for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      const tag = `${who}-${lang}-${w}`;
      const run = {who, lang, w, http: []};
      page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
      page.on('console', m => { if (m.type() === 'error') out.errors.push(tag + ' console: ' + m.text().slice(0, 300)); });
      page.on('response', r => { if (r.status() >= 400) run.http.push(r.status() + ' ' + r.url().replace(base, '')); });
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', who);
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1200);
      // ---- Settings → Agent fleet ----
      await page.evaluate(() => showTab('settings'));
      await page.waitForTimeout(400);
      await page.evaluate(() => showPane('fleet'));
      await page.waitForFunction(() => document.querySelector('#fl-root .fl-hero, #fl-root #fl-scoped, #fl-root .ct-bad'), null, {timeout: 30000});
      await page.waitForTimeout(300);
      Object.assign(run, await page.evaluate(() => {
        const root = document.getElementById('fl-root');
        const note = document.getElementById('fl-scoped');
        return {hero: !!root.querySelector('.fl-hero'), scoped: !!note, bad: (root.querySelector('.ct-bad') || {}).textContent || '',
                note: note ? note.textContent.trim() : '', hscroll: document.scrollingElement.scrollWidth - innerWidth};
      }));
      if (shots) await page.screenshot({path: path.join(shots, `rv2-fleet-${tag}.png`), fullPage: w < 500});
      // ---- Events: what the reports and the digests wrote (a full administrator sees them all) ----
      if (who === 'tester') {
        await page.evaluate(() => showTab('events'));
        await page.waitForFunction(() => /digest|souhrn/i.test(document.getElementById('tab-events').textContent), null, {timeout: 30000});
        await page.waitForTimeout(600);
        run.events = await page.evaluate(() => [...document.querySelectorAll('#tab-events td, #tab-events .ev-msg, #tab-events li')]
          .map(x => x.textContent.trim()).filter(t => /digest|souhrn|report/i.test(t) && t.length < 300));
        if (shots) await page.screenshot({path: path.join(shots, `rv2-events-${tag}.png`), fullPage: w < 500});
      }
      out.runs.push(run);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
