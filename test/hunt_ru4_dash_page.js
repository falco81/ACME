// The pages' half of test/test_hunt_ru4_dash.py, in Chromium against a real daemon.
//
//   node test/hunt_ru4_dash_page.js BASE_URL PASSWORD
//
// Prints lines of JSON: {ready: true} once the Python half is to start a slow job, then what
// was seen.
//  - The Overview at a phone's width: "What needs a look" has no scrollbar of its own inside
//    the page's (it stopped at 520 px).
//  - The tab Jobs' count of running jobs on a filtered list ("went well"): there, not taken
//    off by a list that does not show the running job.
//  - Live updates paused in the header: the Jobs list is not asked again every 2.5 s.
//  - A running job's window, the certificate's window opened over it and closed: it goes on
//    being asked, and says how the job ended (it said "running, 13 s so far" for good).
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const signIn = async (w) => {
    const ctx = await browser.newContext({viewport: {width: w, height: 800}});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForFunction(() => document.querySelector('.ct-ovtile'), null, {timeout: 30000});
    await page.waitForTimeout(1500);
    return page;
  };
  try {
    // ---- a phone: the lists of the Overview are part of the page ----
    const p = await signIn(390);
    await p.waitForFunction(() => document.querySelectorAll('.ct-ovlist .ct-ovrow').length > 0, null, {timeout: 20000});
    out.ovlist = await p.evaluate(() => Array.from(document.querySelectorAll('.ct-ovlist')).map(l => {
      const cs = getComputedStyle(l);
      return {rows: l.querySelectorAll('.ct-ovrow').length, scrolls: /auto|scroll/.test(cs.overflowY) && l.scrollHeight > l.clientHeight + 1};
    }));
    await p.context().close();

    const a = await signIn(1400);
    const asked = [];
    a.on('request', r => { const u = r.url(); if (u.indexOf('api=certs/job') >= 0) asked.push([Date.now(), u.split('api=')[1]]); });
    await a.evaluate(() => document.querySelector('.tabs button[data-tab="jobs"]').click());
    await a.waitForTimeout(1500);
    await a.selectOption('#jb-ok', '1');
    await a.waitForTimeout(1500);
    // ---- the slow job, started by the Python half ----
    console.log(JSON.stringify({ready: true}));
    await a.waitForFunction(() => document.getElementById('tabn-jobs').textContent === '1', null, {timeout: 25000})
      .then(() => { out.countFiltered = '1'; })
      .catch(async () => { out.countFiltered = await a.evaluate(() => document.getElementById('tabn-jobs').textContent); });
    await a.selectOption('#jb-ok', '');
    await a.waitForFunction(() => /running/.test(document.getElementById('jb-said').textContent), null, {timeout: 20000});
    // ---- paused ----
    await a.click('#updated');
    await a.waitForTimeout(500);
    const t0 = Date.now();
    await a.waitForTimeout(6000);
    out.pausedAsked = asked.filter(x => x[0] > t0 && x[1].indexOf('certs/jobs') === 0).length;
    await a.click('#updated');
    // ---- the job's window, the certificate's over it and closed ----
    await a.click('#jb-table tbody tr:first-child');
    await a.waitForFunction(() => /running/i.test((document.getElementById('modal-body') || {}).textContent || ''), null, {timeout: 10000});
    await a.click('#modal-foot button:has-text("The certificate")');
    await a.waitForTimeout(2000);
    out.overTitle = await a.evaluate(() => document.getElementById('modal-title').textContent);
    await a.keyboard.press('Escape');
    await a.waitForTimeout(500);
    const t1 = Date.now();
    await a.waitForFunction(() => /went well|failed|stopped/i.test(document.getElementById('modal-body').textContent), null, {timeout: 60000})
      .then(() => { out.windowEnded = true; })
      .catch(() => { out.windowEnded = false; });
    out.windowAsked = asked.filter(x => x[0] > t1 && x[1].indexOf('certs/job&') === 0).length;
    out.windowTitle = await a.evaluate(() => document.getElementById('modal-title').textContent);
    out.windowButtons = await a.evaluate(() => Array.from(document.querySelectorAll('#modal-foot button')).map(b => b.textContent.trim()));
    await a.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
