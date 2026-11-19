// The pages' half of test/test_hunt_ru3_srcval.py, in Chromium against a real daemon.
//
//   node test/hunt_ru3_srcval_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: what the forms of Targets and Validation kept and sent.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const click = (page, words) => page.evaluate(w => {
    const b = Array.from(document.querySelectorAll('button')).filter(x => x.offsetParent).reverse()
      .find(x => x.textContent.trim() === w);
    if (b) b.click();
    return !!b;
  }, words);
  const newOf = async (page, tab, add, kind) => {
    await page.evaluate(t => document.querySelector('.tabs button[data-tab="' + t + '"]').click(), tab);
    await page.waitForFunction(id => document.getElementById(id), add, {timeout: 20000});
    await page.waitForTimeout(800);
    await page.click('#' + add);
    await page.waitForFunction(() => document.querySelector('.ct-kind-tile'), null, {timeout: 20000});
    await page.evaluate(k => Array.from(document.querySelectorAll('.ct-kind-tile'))
      .find(x => x.querySelector('.ct-kind-k').textContent === k).click(), kind);
    await page.waitForFunction(() => document.querySelector('.ct-fform'), null, {timeout: 20000});
    await page.waitForTimeout(500);
  };
  try {
    const ctx = await browser.newContext({viewport: {width: 1400, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    let sent = null;
    await page.route(/[?&]api=[^&]*discover/, r => { sent = r.request().postData();
      r.fulfill({status: 200, contentType: 'application/json',
                 body: JSON.stringify({ok: true, worked: false, said: 'not asked here'})}); });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(1500);

    // 1. another version of the module picked: the token and the tags typed stay
    await newOf(page, 'targets', 'tg-add', 'fortigate');
    await page.fill('[data-fkey="token"] input', 'Typed-Token-77');
    await page.waitForFunction(() => document.querySelector('.tm-tag-add option[value="prod"]'), null, {timeout: 20000});
    await page.selectOption('.tm-tag-add', 'prod');
    await page.evaluate(() => Array.from(document.querySelectorAll('.md-vcard')).find(c => /6\.0/.test(c.textContent)).click());
    await page.waitForTimeout(800);
    out.switched = await page.evaluate(() => ({
      token: document.querySelector('[data-fkey="token"] input').value,
      tags: document.querySelector('.tm-tags').value,
      on: (document.querySelector('.md-vcard.on') || {}).textContent || ''}));
    // 2. "Find the settings from the account": the version the form shows, sent
    await page.fill('[data-fkey="host"] input', 'fg.example.test');
    await click(page, 'Find the settings from the account');
    await page.waitForTimeout(800);
    await click(page, 'Find out');
    await page.waitForTimeout(1500);
    out.fgSent = sent ? JSON.parse(sent) : null;
    await page.reload();
    await page.waitForTimeout(1500);

    // 3. a secret typed in the form is in the popup's box too
    sent = null;
    await newOf(page, 'validation', 'val-add', 'cloudflare');
    await page.fill('[data-fkey="token"] input', 'Cf-Token-1234');
    await click(page, 'Find the settings from the account');
    await page.waitForTimeout(800);
    out.popupToken = await page.evaluate(() => Array.from(document.querySelectorAll('[data-fkey="token"] input')).map(x => x.value));
    await click(page, 'Find out');
    await page.waitForTimeout(1500);
    out.cfSent = sent ? JSON.parse(sent) : null;
    await ctx.close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
