// The pages' half of test/test_hunt_r4_portalui.py: the certificate portal in Chromium.
//
//   node test/hunt_r4_portalui_page.js BASE_URL NAME PASSWORD LANG WIDTH
//
// Prints one line of JSON: what was seen.
//  - Sign in pressed with the name, then the password empty: what the page said (its own words,
//    in its language - not the browser's bubble), and the fields still `required`.
//  - "Your certificates": nothing wider than the page or the list's box; each row's Expires and
//    download button inside what is seen; the table's header seen or not.
//  - The dialog of a self-signed certificate the person manages: Revoke offered or not.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, lang, width] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: Number(width) || 390, height: 844}});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  try {
    await page.goto(base + '/');
    await page.waitForSelector('#in-go');
    out.stillRequired = await page.evaluate(() =>
      document.getElementById('in-name').required && document.getElementById('in-pass').required);
    await page.click('#in-go');
    await page.waitForTimeout(300);
    out.noName = (await page.textContent('#in-said')).trim();
    await page.fill('#in-name', name);
    await page.click('#in-go');
    await page.waitForTimeout(300);
    out.noPass = (await page.textContent('#in-said')).trim();
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    /* a member of a team (1.0.125): the team workspace - its Certificates */
    await page.waitForSelector('#cp-list table, #pw-nav', {timeout: 30000});
    if (await page.$('#pw-nav')) await page.click('#pw-nav [data-view=certs]');
    await page.waitForSelector('#cp-list table', {timeout: 30000});
    await page.waitForTimeout(500);
    out.wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    Object.assign(out, await page.evaluate(() => {
      const box = document.querySelector('#cp-list .scroll');
      const b = box.getBoundingClientRect();
      const inside = e => {
        if (!e) return true;
        const r = e.getBoundingClientRect();
        return r.width > 0 && r.left >= b.left - 1 && r.right <= b.right + 1 && r.right <= window.innerWidth;
      };
      const head = box.querySelector('thead');
      return {
        listWide: box.scrollWidth - box.clientWidth,
        headSeen: !!head && head.getBoundingClientRect().height > 0,
        cols: box.querySelectorAll('thead th').length,
        rows: [...box.querySelectorAll('tbody tr')].map(tr => ({
          name: tr.querySelector('.ct-cname b').textContent,
          dlIn: inside(tr.querySelector('td.rowtools button')),
          expIn: inside(tr.querySelector('td.ct-exp'))}))
      };
    }));
    await page.locator('#cp-list tr', {hasText: 'r4-issued.example.test'}).first().click();
    await page.waitForSelector('#modal .ct-head', {timeout: 10000});
    await page.waitForTimeout(300);
    const words = await page.$$eval('#modal button', bs => bs.map(b => b.textContent.trim()));
    out.revoke = words.some(w => /^(Revoke|Odvolat)/i.test(w));
    out.renew = words.some(w => /^(Renew now|Obnovit teď)/i.test(w));
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
