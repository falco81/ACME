// The pages' half of test/test_hunt_r6_overviewui.py, in Chromium against a real daemon.
//
//   node test/hunt_r6_overviewui_page.js BASE_URL PASSWORD
//
// Prints one line of JSON: what was seen.
//  - The Overview at a phone's width opens at its top: it opened 537 px down, under the header.
//  - The tile The database in Czech: "poslední kopie před …", not "naposledy před copy …".
//  - The count of running jobs on the tab Jobs, from the Overview: there while one runs, gone
//    once it ended (a "1" taken on the Jobs tab stayed for good under the Overview).
//  - The tile Failing (only deployments failing) opens Jobs at every failed job, not at
//    "deployment · failed", which showed none.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const signIn = async (name, lang, w) => {
    const ctx = await browser.newContext({viewport: {width: w, height: 800}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForFunction(() => document.querySelector('.ct-ovtile'), null, {timeout: 20000});
    await page.waitForTimeout(1500);
    return page;
  };
  try {
    // ---- a phone, in Czech ----
    const p = await signIn('tester', 'cs', 390);
    out.phoneScrollY = await p.evaluate(() => window.scrollY);
    out.dbSub = await p.evaluate(() => document.getElementById('m-db-sub').textContent);
    await p.context().close();

    // ---- the running count, from the Overview ----
    const a = await signIn('tester', 'en', 1400);
    out.jobsCountBefore = await a.evaluate(() => document.getElementById('tabn-jobs').textContent);
    // the job is started by the Python half once the page is up: it says so in a file it waits for
    console.log(JSON.stringify({ready: true}));
    await a.waitForFunction(() => document.getElementById('tabn-jobs').textContent === '1', null, {timeout: 45000})
      .then(() => { out.jobsCountRunning = '1'; })
      .catch(async () => { out.jobsCountRunning = await a.evaluate(() => document.getElementById('tabn-jobs').textContent); });
    // the Jobs tab looked at while it runs, then back to the Overview while it ends
    await a.evaluate(() => document.querySelector('.tabs button[data-tab="jobs"]').click());
    await a.waitForTimeout(1500);
    out.jobsCountOnJobs = await a.evaluate(() => document.getElementById('tabn-jobs').textContent);
    await a.evaluate(() => document.querySelector('.tabs button[data-tab="overview"]').click());
    await a.waitForFunction(() => document.getElementById('tabn-jobs').textContent === '', null, {timeout: 60000})
      .then(() => { out.jobsCountAfter = ''; })
      .catch(async () => { out.jobsCountAfter = await a.evaluate(() => document.getElementById('tabn-jobs').textContent); });
    // ---- the tile Failing ----
    await a.evaluate(() => { const s = document.getElementById('jb-cert'); if (s) { const o = document.createElement('option'); o.value = '999999'; s.appendChild(o); s.value = '999999'; } });
    await a.evaluate(() => document.querySelector('.ct-ovtile.crit').click());
    await a.waitForTimeout(2500);
    out.failingOpened = await a.evaluate(() => [TAB, document.getElementById('jb-kind').value, document.getElementById('jb-ok').value,
      document.getElementById('jb-cert').value, document.querySelectorAll('#jb-table tbody tr').length]);
    await a.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
