// The pages' half of test/test_hunt_rt1_portal.py: the portal's team workspace in Chromium.
//
//   node test/hunt_rt1_portal_page.js BASE USER PASSWORD LANG WIDTH
//
// Prints one line of JSON: the device card's module words, the agent device's "Who connects"
// value, whether the limits of the sub-team were saved, and the page's errors.
const { chromium } = require('playwright');

(async () => {
  const [base, user, pass, lang, width] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: Number(width) || 390, height: 900}});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  page.on('console', m => { if (m.type() === 'error') out.errors.push('console: ' + m.text()); });
  const pause = ms => page.waitForTimeout(ms);
  const settle = async () => {
    await page.waitForFunction(() => !document.querySelector('#pw-main .pw-skels, #pw-main .cp-skel, #modal-body .pw-skels'), null, {timeout: 20000}).catch(() => {});
    await pause(700);
  };
  try {
    await page.goto(base + '/');
    await page.fill('#in-name', user);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#pw-nav .pw-navi', {timeout: 30000});
    await page.evaluate(() => { location.hash = '#devices/Top'; });
    await pause(300);
    await settle();
    out.card = await page.evaluate(() => {
      const c = [...document.querySelectorAll('.pw-dev')].find(x => /srv-agent/.test(x.textContent));
      return c ? c.querySelector('.pw-dev-k').textContent.trim() : null;
    });
    await page.locator('.pw-dev', {hasText: 'srv-agent'}).first().click();
    await page.waitForSelector('#modal:not([hidden]) .pw-dh', {timeout: 20000});
    await settle();
    out.dialog = await page.evaluate(() => {
      const s = document.querySelector('#modal .pw-dh-s span');
      const rows = [...document.querySelectorAll('#modal-body tr, #modal-body .kv-row, #modal-body .kvrow')].map(r => r.textContent.trim());
      return {kind: s ? s.textContent.trim() : null, rows: rows};
    });
    await page.keyboard.press('Escape');
    await pause(500);
    await page.evaluate(() => { location.hash = '#teams/Top'; });
    await pause(300);
    await settle();
    await page.locator('#pw-main button', {hasText: lang === 'cs' ? /^Limity$/ : /^Limits$/}).first().click();
    await page.waitForSelector('#modal:not([hidden]) .pw-led', {timeout: 20000});
    await pause(400);
    await page.locator('#modal-foot button.primary').first().click();
    await page.waitForFunction(() => document.getElementById('modal').hidden, null, {timeout: 20000}).catch(() => {});
    out.saved = await page.evaluate(() => document.getElementById('modal').hidden);
    out.said = await page.evaluate(() => { const s = document.querySelector('#modal .said'); return s ? s.textContent : ''; });
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
