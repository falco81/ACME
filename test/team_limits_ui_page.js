// The pages' half of test/test_team_limits_more.py (1.0.128): the new limits in the
// administration's limit editor (Settings → Owners and teams → a team → Limits), in Chromium
// against a real daemon.
//
//   node test/team_limits_ui_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: errors on the page, the rows of the new limits, what the pairs editor
// offers, and whether a source added there was saved.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  try {
    const ctx = await browser.newContext({viewport: {width: 1400, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', (e) => out.errors.push(String(e.message || e)));
    page.on('console', (m) => { if (m.type() === 'error') out.errors.push('console: ' + m.text()); });
    page.on('dialog', async (d) => { out.errors.push('browser dialog: ' + d.message()); await d.dismiss(); });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(500);
    await page.goto(base + '/admin/index.php#settings/teams');
    await page.waitForSelector('#tmx .tmx-row', {timeout: 30000});
    await page.evaluate(() => { const r = [...document.querySelectorAll('.tmx-row')].find((x) => x.dataset.name === 'Web'); r.click(); });
    await page.waitForSelector('.tmx-team[data-team="Web"]', {timeout: 10000});
    await page.click('.tmx-tab[data-tab="limits"]');
    await page.waitForSelector('#tmx-pol .tmx-prow[data-key="pairs"]', {timeout: 15000});
    out.rows = await page.$$eval('#tmx-pol .tmx-prow', (r) => r.map((x) => x.dataset.key));
    out.wildcardsOn = await page.$eval('.tmx-prow[data-key="wildcards"] .tmx-segb.on', (b) => b.dataset.v);
    out.pairsShown = await page.$$eval('#tmx-pairs .tmx-pairr', (r) => r.map((x) => x.querySelector('.tmx-pairh').textContent.trim()));
    out.pairsOffer = await page.$$eval('#tmx-pairs-add option', (o) => o.map((x) => x.value).filter(Boolean));
    out.testKinds = await page.$$eval('.tmx-prow[data-key="test_kinds"] select.tmx-addsel option', (o) => o.map((x) => x.value).filter(Boolean));
    await page.selectOption('#tmx-pairs-add', 'other');
    await page.waitForTimeout(200);
    // its validation: the first of the catalog picked in its own row
    const sel = page.locator('#tmx-pairs .tmx-pairr').last().locator('select.tmx-addsel');
    await sel.selectOption('dnsB');
    await page.waitForTimeout(200);
    await page.click('#tmx-polsave');
    await page.waitForTimeout(1500);
    out.clicked = true;
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
