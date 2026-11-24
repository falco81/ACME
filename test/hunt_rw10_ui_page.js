// The pages' half of test/test_hunt_rw10_ui.py (hunt w10, ui): the time picker by the keyboard.
//
//   node test/hunt_rw10_ui_page.js BASE_URL PASSWORD
//
// Events' "all time" window (and the cluster history's, inside a dialog), English and Czech,
// 1400 and 390 px: opened, the focus on the window chosen; Escape closes it and gives the focus
// back (a dialog around it stays); Enter opens it, Tab and Enter pick another; a tab changed
// with it open takes it away. Prints one line of JSON.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: {}};
  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = lang + '-' + w;
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1200);
      await page.evaluate(() => showTab('events'));
      await page.waitForSelector('#ev-time .tp-main');
      await page.waitForTimeout(500);
      const open = () => page.evaluate(() => !!document.querySelector('.tp-pop'));
      const r = {};
      await page.click('#ev-time .tp-main');
      await page.waitForTimeout(300);
      r.open = await open();
      r.focusOn = await page.evaluate(() => document.activeElement.classList.contains('tp-q') && document.activeElement.classList.contains('on'));
      r.expanded = await page.evaluate(() => document.querySelector('#ev-time .tp-main').getAttribute('aria-expanded'));
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
      r.escClosed = !(await open());
      r.focusBack = await page.evaluate(() => document.activeElement.classList.contains('tp-main'));
      await page.keyboard.press('Enter');
      await page.waitForTimeout(300);
      r.kbOpen = await open();
      const was = await page.evaluate(() => document.querySelector('#ev-time .tp-words').textContent);
      await page.keyboard.press('Tab');
      await page.keyboard.press('Enter');
      await page.waitForTimeout(600);
      r.kbPicked = (await page.evaluate(() => document.querySelector('#ev-time .tp-words').textContent)) !== was;
      r.kbClosed = !(await open());
      await page.click('#ev-time .tp-main');
      await page.waitForTimeout(300);
      await page.evaluate(() => showTab('certs'));
      await page.waitForTimeout(900);
      r.tabClosed = !(await open());
      // inside a dialog: the cluster's history
      await page.evaluate(() => showTab('settings'));
      await page.evaluate(() => { location.hash = '#settings/ha'; });
      await page.waitForTimeout(1200);
      if (await page.locator('#ha-history').isVisible()) {
        await page.click('#ha-history');
        await page.waitForSelector('#ha-hist-time .tp-main', {timeout: 15000});
        await page.click('#ha-hist-time .tp-main');
        await page.waitForTimeout(300);
        r.modalPickOpen = await open();
        await page.keyboard.press('Escape');
        await page.waitForTimeout(400);
        r.modalPickClosed = !(await open());
        r.modalStays = await page.evaluate(() => !!document.querySelector('#ha-hist-time'));
      }
      out.runs[tag] = r;
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
