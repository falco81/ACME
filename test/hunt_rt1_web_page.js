// The pages' half of test/test_hunt_rt1_web.py, in Chromium against a real daemon.
//
//   node test/hunt_rt1_web_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: what a FortiGate target's window says of "SSH: sign in with", in
// English and in Czech at a phone's width, and the errors of the pages.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], seen: []};
  try {
    for (const lang of ['en', 'cs']) {
      const ctx = await browser.newContext({viewport: {width: 390, height: 900}});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(String(e.message || e)));
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1500);
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="targets"]').click());
      await page.waitForFunction(() => [...document.querySelectorAll('#tab-targets tr.tappable')].some(r => /fw-ssh/.test(r.innerText)), null, {timeout: 20000});
      await page.evaluate(() => [...document.querySelectorAll('#tab-targets tr.tappable')].find(r => /fw-ssh/.test(r.innerText)).click());
      await page.waitForFunction(() => document.querySelector('#modal-box table.plain.tight'), null, {timeout: 20000});
      await page.waitForTimeout(800);
      out.seen.push(await page.evaluate((lang) => {
        const want = lang === 'cs' ? /^SSH: přihlásit se/ : /^SSH: sign in with/;
        const row = [...document.querySelectorAll('#modal-box tr')].find(r => r.cells.length === 2 && want.test(r.cells[0].innerText.trim()));
        return {lang, auth: row ? row.cells[1].innerText.trim() : null,
                hscroll: document.scrollingElement.scrollWidth - innerWidth};
      }, lang));
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
