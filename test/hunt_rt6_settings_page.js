// The pages' half of test/test_hunt_rt6_settings.py, in Chromium against a real daemon.
//
//   node test/hunt_rt6_settings_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: what was seen.
//  - Settings → High availability at 390 px (a cluster of three, one with a long name): the
//    copy buttons of the load balancer's guides hold their words, the table of each node's own
//    settings no wider than the page and its headings inside their columns.
//  - The same in Czech; and the message texts' "As it comes" button.
//  - "Heard from" of the nodes by the age the daemon measured, not the browser's clock (a
//    browser ten minutes ahead).
//  - A number emptied and saved: the box refused is marked.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const open = async (lang, width, skew) => {
    const ctx = await browser.newContext({viewport: {width, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    if (skew) await ctx.addInitScript(s => { const N = Date.now; Date.now = () => N() + s * 1000; }, skew);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.waitForFunction(() => typeof SETTINGS !== 'undefined' && SETTINGS && SETTINGS.settings, null, {timeout: 20000});
    await page.waitForTimeout(500);
    return page;
  };
  const pane = async (page, name) => {
    await page.evaluate(n => showPane(n), name);
    await page.waitForTimeout(1800);
  };
  const look = page => page.evaluate(() => {
    document.querySelectorAll('.lb-block-h').forEach(h => { const d = h.closest('details'); if (d) d.open = true; });
    const btnOver = Array.from(document.querySelectorAll('#pane-' + PANE + ' .lb-block-h > .btn, #pane-' + PANE + ' .tx-field-h > .btn'))
      .filter(b => b.offsetParent).filter(b => {
        const s = b.querySelector('span'); const r = b.getBoundingClientRect();
        return s && s.getBoundingClientRect().right > r.right + 1;
      }).map(b => b.textContent);
    const t = document.querySelector('#ha-own-card table');
    const thOver = t ? Array.from(t.querySelectorAll('th')).filter(x => x.scrollWidth > x.clientWidth + 1).map(x => x.textContent) : null;
    return {wide: document.documentElement.scrollWidth - innerWidth, btnOver, thOver, ths: t ? t.querySelectorAll('th').length : 0};
  });
  try {
    for (const lang of ['en', 'cs']) {
      const p = await open(lang, 390);
      await pane(p, 'ha');
      out['ha_' + lang] = await look(p);
      await pane(p, 'texts');
      out['texts_' + lang] = await look(p);
      await p.context().close();
    }
    const s = await open('en', 1400, 600);
    await pane(s, 'ha');
    out.heard = await s.evaluate(() => Array.from(document.querySelectorAll('#ha-nodes tbody tr')).map(r => [r.cells[0].textContent, r.cells[3].textContent]));
    await pane(s, 'certs');
    out.refused = await s.evaluate(async () => {
      const i = document.getElementById('set-certs_renew_days');
      i.value = ''; i.dispatchEvent(new Event('input'));
      document.getElementById('set-save').click();
      await new Promise(r => setTimeout(r, 2500));
      return Array.from(document.querySelectorAll('.set-item.refused')).map(x => x.dataset.key);
    });
    await s.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
