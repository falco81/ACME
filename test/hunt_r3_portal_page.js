// The pages' half of test/test_hunt_r3_portal.py: the certificate portal in Chromium.
//
//   node test/hunt_r3_portal_page.js BASE_URL NAME PASSWORD LANG
//
// Prints one line of JSON: what was seen.
//  - A certificate not issued yet that nothing issues (not renewed by itself): its state tag in
//    the list and in its dialog is "not issued yet", not "being issued" pulsing for good.
//  - One a job is issuing now (its job live, put into the list's answer here): still "being
//    issued", pulsing.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, lang] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: 390, height: 844}});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  // The list as the daemon gives it, with a copy of the idle one that a job is issuing now.
  await page.route(/[?&]api=certs(&|$)/, async route => {
    const r = await route.fetch();
    const d = await r.json();
    const idle = (d.rows || []).filter(x => x.name === 'r3-idle')[0];
    if (idle) {
      const busy = JSON.parse(JSON.stringify(idle));
      busy.id = 990001;
      busy.name = busy.cn = 'r3-busy';
      busy.names = ['r3-busy.example.test'];
      busy.job = {id: 990001, live: true, state: 'running'};
      d.rows.push(busy);
    }
    await route.fulfill({response: r, json: d});
  });
  const tagOf = loc => loc.locator('.ct-state').first().evaluate(t => ({
    words: t.textContent.trim(), pulse: t.classList.contains('ct-pulse'),
    dim: t.classList.contains('dim')}));
  try {
    await page.goto(base + '/');
    await page.fill('#in-name', name);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#cp-list table', {timeout: 30000});
    await page.waitForTimeout(500);
    const idleRow = page.locator('#cp-list tr', {hasText: 'r3-idle.example.test'}).first();
    out.idleRow = await tagOf(idleRow);
    out.busyRow = await tagOf(page.locator('#cp-list tr', {hasText: 'r3-busy.example.test'}).first());
    await idleRow.click();
    await page.waitForSelector('#modal .ct-head', {timeout: 10000});
    out.idleDialog = await tagOf(page.locator('#modal .ct-head'));
    out.wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
