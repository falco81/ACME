// The pages' half of test/test_snmp.py: Settings -> Monitoring, the SNMPv3 card - its two
// downloads (the Zabbix 7 template and ACME-MIB) - in English and in Czech, wide and a phone's.
//
//   node test/snmp_page.js BASE_URL NAME PASSWORD
//
// Prints one line of JSON: what was seen and what was downloaded. ACME_SHOTS=DIR keeps
// screenshots of the card.
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const [base, name, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {};
  try {
    for (const lang of ['en', 'cs']) {
      for (const width of [1300, 390]) {
        const ctx = await browser.newContext({viewport: {width, height: 900}, acceptDownloads: true});
        await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
        const page = await ctx.newPage();
        const errors = [];
        page.on('pageerror', (e) => errors.push(String(e)));
        await page.goto(base + '/admin/index.php');
        await page.fill('#in-name', name);
        await page.type('#in-pass', pass);
        await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
        const seen = {errors};
        await page.goto(base + '/admin/index.php?t=settings#settings/monitor');
        await page.evaluate(() => { if (typeof showTab === 'function') showTab('settings'); PANE = 'monitor'; showPane('monitor'); });
        await page.waitForSelector('#snmp-get-zabbix', {timeout: 60000});
        const btn = page.locator('#snmp-get-zabbix');
        await btn.scrollIntoViewIfNeeded();
        seen.zabbix_button = await btn.innerText();
        seen.mib_button = await page.locator('#snmp-get-mib').innerText();
        seen.card = await page.locator('#snmp-host').innerText();
        seen.overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        const shots = process.env.ACME_SHOTS;
        if (shots) {
          await page.waitForTimeout(1500);       // the card drawn again once the node's row is read
          // tall enough for the whole card: the pages scroll inside, not the window
          await page.setViewportSize({width, height: 3000});
          await page.waitForTimeout(500);
          await page.locator('#snmp-host > .card').screenshot({path: shots + '/snmp-' + lang + width + '.png'});
          await page.setViewportSize({width, height: 900});
        }
        if (width === 1300) {
          for (const what of ['zabbix', 'mib']) {
            const [dl] = await Promise.all([page.waitForEvent('download', {timeout: 60000}),
              page.click('#snmp-get-' + what)]);
            const path = await dl.path();
            const text = fs.readFileSync(path, 'utf-8');
            seen['dl_' + what] = {name: dl.suggestedFilename(), size: text.length,
                                  head: text.slice(0, 40)};
          }
        }
        out[lang + width] = seen;
        await ctx.close();
      }
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
