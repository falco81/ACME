// The pages' half of test/test_selinux_findings.py (Card): Settings -> SELinux, two nodes - in
// English and in Czech, 1400 px and a phone's 390, an admin (tester) and a read-only account
// (viewer).
//
//   node test/selinux_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: what was seen. ACME_SHOTS=DIR keeps screenshots of the card.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const shots = process.env.ACME_SHOTS;
  const browser = await chromium.launch();
  const out = {};
  try {
    for (const lang of ['en', 'cs']) {
      for (const width of [1400, 390]) {
        for (const who of ['tester', 'viewer']) {
          const key = lang + width + who;
          const ctx = await browser.newContext({viewport: {width, height: 900}});
          await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
          const page = await ctx.newPage();
          const errors = [];
          page.on('pageerror', (e) => errors.push(String(e)));
          page.on('console', (m) => {
            if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) errors.push(m.text());
          });
          await page.goto(base + '/admin/index.php');
          await page.fill('#in-name', who);
          await page.type('#in-pass', pass);
          await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
          await page.goto(base + '/admin/index.php?t=settings#settings/selinux');
          await page.evaluate(() => { if (typeof showTab === 'function') showTab('settings'); showPane('selinux'); });
          await page.waitForSelector('#se-host .se-grp', {timeout: 60000});
          await page.waitForTimeout(800);
          const seen = {errors};
          const host = page.locator('#se-host');
          seen.card = await host.innerText();
          seen.buttons = await page.locator('#se-host button.btn, #se-host .sn-re').count();
          seen.checkboxes = await page.locator('#se-host input[type=checkbox]').count();
          seen.put = await page.locator('#se-host .se-putrow button').count() > 0;
          seen.overflow = await page.evaluate(() => {
            const wide = document.documentElement.scrollWidth - window.innerWidth;
            // nothing of the card wider than the card itself
            const card = document.querySelector('#se-host .se-card');
            const cr = card.getBoundingClientRect();
            let inner = 0;
            card.querySelectorAll('*').forEach((n) => {
              const r = n.getBoundingClientRect();
              if (r.width && r.right - cr.right > inner) inner = r.right - cr.right;
            });
            return Math.max(wide, Math.round(inner));
          });
          const tall = async (name) => {
            if (!shots) return;
            await page.setViewportSize({width, height: 4200});
            await page.waitForTimeout(400);
            await page.locator('#se-host > .card').screenshot({path: shots + '/' + name + '.png'});
            await page.setViewportSize({width, height: 900});
          };
          await tall('selinux-' + key);
          if (who === 'tester' && width === 1400) {
            await page.locator('#se-host .se-putrow button').click();
            await page.waitForSelector('.se-plan', {timeout: 10000});
            const modal = page.locator('#modal-box');
            seen.confirm = await modal.innerText();
            if (shots) await modal.screenshot({path: shots + '/selinux-confirm-' + lang + '.png'});
            await page.keyboard.press('Escape');
            await page.waitForTimeout(400);
          }
          // The other node: chosen by its pill - its own mode, its own findings.
          await page.locator('#se-host .se-nodebtn', {hasText: 'acme-b'}).click();
          await page.waitForTimeout(500);
          seen.node_b = await page.locator('#se-host .se-node').innerText();
          seen.node_b_calm = await page.locator('#se-host .se-calm').count() > 0 ||
            (await page.locator('#se-host .se-k-other').count()) > 0;
          if (who === 'tester') await tall('selinux-nodeb-' + key);
          await page.locator('#se-host .se-nodebtn', {hasText: 'acme-a'}).click();
          await page.waitForTimeout(300);
          out[key] = seen;
          await ctx.close();
        }
      }
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
