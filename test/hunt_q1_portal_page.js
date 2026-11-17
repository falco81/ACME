// The pages' half of test/test_hunt_q1_portal.py: the certificate portal in Chromium.
//
//   node test/hunt_q1_portal_page.js BASE_URL NAME PASSWORD
//
// Prints one line of JSON: what was seen.
//  - "Ask for a certificate", off at the limit and on again: what it said while it was off goes
//    with it (its tooltip, its name for a screen reader).
//  - A certificate not issued yet that nothing is issuing (not renewed by itself): not "being
//    issued…", and not asked about every 3 s for good.
//  - The sign-in page whose only way is a certificate (q1-certonly.html, written by the test):
//    "your sign-in has run out" said there too.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: 375, height: 800}});
  await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  let certAsks = 0, full = true;
  // The list as the daemon gives it - "as many as one person may" until full is false.
  await page.route(/[?&]api=certs(&|$)/, async route => {
    certAsks += 1;
    const r = await route.fetch();
    const d = await r.json();
    if (full) { d.may_request = false; d.may_ask = false; d.used = d.most; } else { d.may_request = true; d.may_ask = true; d.used = 0; }
    await route.fulfill({response: r, json: d});
  });
  try {
    await page.clock.install();
    await page.goto(base + '/');
    await page.fill('#in-name', name);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#cp-list table', {timeout: 30000});
    await page.waitForTimeout(500);
    const ask = page.locator('#cp-ask');
    const state = () => ask.evaluate(a => ({disabled: a.disabled, label: a.getAttribute('aria-label'),
                                           help: a._explainHtml || '', words: a.textContent.trim()}));
    out.full = await state();
    out.newRow = await page.locator('#cp-list tr', {hasText: 'q1-new.example.test'}).first()
      .locator('td.ct-exp').innerText();
    out.wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    // Ten seconds on: a list with nothing at work is not asked for again.
    const before = certAsks;
    await page.clock.runFor(10000);
    await page.waitForTimeout(800);
    out.asksIn10s = certAsks - before;
    // A minute on, a request is free again.
    full = false;
    await page.clock.runFor(61000);
    await page.waitForFunction(() => !document.getElementById('cp-ask').disabled, null, {timeout: 15000});
    out.free = await state();
    // The sign-in page with the certificate as its only way (as index.php draws it then),
    // come back to after the sign-in ran out.
    const only = await ctx.newPage();
    only.on('pageerror', e => out.errors.push('certonly: ' + String(e.message || e)));
    await only.goto(base + '/q1-certonly.html');
    await only.waitForTimeout(500);
    out.certOnly = await only.locator('#cert-said').innerText();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
