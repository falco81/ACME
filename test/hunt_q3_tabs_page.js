// The pages' half of test/test_hunt_q3_tabs.py: Settings → DNS, Owners and teams and
// DNS server in Chromium.
//
//   node test/hunt_q3_tabs_page.js BASE_URL NAME PASSWORD
//
// Prints one line of JSON: what was seen.
//  - DNS sets: a set chosen for a function (waiting for Save), then renamed - Save gives the
//    function the set by its new name; chosen, then deleted - Save says nothing of it.
//  - Owners and teams: "Make it an owner" pressed twice - one request, no error.
//  - DNS server: a record with TTL 0 shows 0, not "–".
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], toasts: []};
  const ctx = await browser.newContext({viewport: {width: 1300, height: 1000}});
  await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
  const page = await ctx.newPage();
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  page.on('dialog', d => { out.errors.push('dialog: ' + d.message()); d.dismiss(); });
  let adopts = 0;
  page.on('request', r => { if (/api=teams[-/%2F]+adopt/i.test(r.url())) adopts++; });
  const ask = (what, body) => page.evaluate(([w, b]) => api(w, b), [what, body]);
  const pane = async (p) => {
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.waitForTimeout(300);
    await page.evaluate(p => document.querySelector('#ctl-nav button[data-pane="' + p + '"]').click(), p);
    await page.waitForTimeout(1200);
  };
  const badToasts = () => page.evaluate(() => Array.from(document.querySelectorAll('.toast.bad')).map(t => t.textContent));
  try {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);

    // ---- DNS sets: a choice waiting for Save follows a rename, and goes with a delete ----
    await ask('dnssets-save', {name: 'q3 one', servers: '192.0.2.53'});
    await ask('dnssets-save', {name: 'q3 two', servers: '192.0.2.54'});
    await pane('dnssets');
    await page.locator('#dnss-host table.dnss-sets tbody tr', {hasText: 'q3 two'}).waitFor({timeout: 20000});
    await page.selectOption('#dnss-use-validation', 'q3 one');
    await page.selectOption('#dnss-use-mail', 'q3 two');
    await page.locator('#dnss-host table.dnss-sets tbody tr', {hasText: 'q3 one'}).locator('.dnss-edit').click();
    await page.fill('#dnss-f-name', 'q3 renamed');
    await page.locator('#modal-foot button.primary').last().click();
    await page.waitForSelector('#modal', {state: 'hidden', timeout: 20000});
    await page.locator('#dnss-host table.dnss-sets tbody tr', {hasText: 'q3 renamed'}).waitFor({timeout: 20000});
    await page.locator('#dnss-host table.dnss-sets tbody tr', {hasText: 'q3 two'}).locator('.dnss-del').click();
    await page.locator('#modal-foot button.danger').last().click();
    await page.waitForFunction(() => !Array.from(document.querySelectorAll('#dnss-host table.dnss-sets tbody tr')).some(t => t.textContent.indexOf('q3 two') >= 0), null, {timeout: 20000});
    out.pickShown = await page.locator('#dnss-use-validation').inputValue();
    await page.click('#set-save');
    await page.waitForTimeout(2500);
    const d = await ask('dnssets');
    out.validation = d.purposes.find(p => p.key === 'validation').chosen;
    out.mail = d.purposes.find(p => p.key === 'mail').chosen;
    out.dnsBad = await badToasts();

    // ---- Owners and teams: "Make it an owner" pressed twice ----
    await pane('teams');
    const mk = page.locator('.tm-legacy-row', {hasText: 'q3-legacy-owner'}).locator('button');
    await mk.waitFor({timeout: 20000});
    await mk.evaluate(b => { b.click(); b.click(); });
    await page.waitForTimeout(2500);
    out.adopts = adopts;
    out.teamBad = await badToasts();

    // ---- DNS server: TTL 0 ----
    await pane('dnssrv');
    await page.locator('#dns-table tr', {hasText: 'q3ttl'}).first().waitFor({timeout: 20000});
    out.ttlCell = (await page.locator('#dns-table tr', {hasText: 'q3ttl'}).first().locator('td').nth(3).innerText()).trim();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
