// The pages' half of test/test_hunt_rw1_ui.py (hunt w1, ui: what the lists do after an action).
//
//   node test/hunt_rw1_ui_page.js BASE_URL PASSWORD [screenshot-folder]
//
// English and Czech, 1400 and 390 px:
// - Certificates, the second page: a certificate deleted leaves the list at once (it stayed
//   until the next tick - with the live updates paused, for good).
// - Rows picked on Certificates, another tab opened: the dock says nothing picked and offers no
//   Actions for rows nobody sees; back on Certificates they are picked again.
// - Ctrl+K after a certificate was renamed and another deleted on this page: the new name is
//   found, the deleted one is not offered.
// - "Show in Jobs" / "Show in Events" of a certificate's menu with an outcome and a kind chosen
//   there before: the certificate's jobs and events are shown.
// Once (English, 1400): Ctrl+K in a second tab after a deletion in the first; columns put away
// in two tabs of the same browser are both kept.
// Prints one line of JSON.
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  const signIn = async (ctx, tag) => {
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    if (await page.$('#in-name')) {          /* a second tab of the same browser is signed in */
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    }
    await page.waitForTimeout(1200);
    return page;
  };
  const paletteFind = async (page, q) => {
    await page.evaluate(() => ACME_PALETTE.open());
    await page.waitForSelector('.cxp-in');
    await page.fill('.cxp-in', q);
    await page.waitForTimeout(1500);
    const got = await page.evaluate(() => [...document.querySelectorAll('.cxp-list [role=option]')]
      .map(x => (x.querySelector('.cxp-t') || x).textContent.trim()));
    await page.keyboard.press('Escape');
    return got;
  };
  try {
    let n = 0;
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const tag = `${lang}-${w}`;
      const page = await signIn(ctx, tag);
      const run = {lang, w};
      const shot = async name => { if (shots) await page.screenshot({path: path.join(shots, `rw1-${name}-${tag}.png`)}); };
      const certRows = () => page.evaluate(() => [...document.querySelectorAll('#ct-table tbody tr')].map(t => t._rec && t._rec.name).filter(Boolean));
      const said = () => page.evaluate(() => $('ct-said').textContent);

      // ---- the second page of the certificates: a deletion shown at once ----
      await page.evaluate(() => showTab('certs'));
      await page.waitForFunction(() => document.querySelectorAll('#ct-table tbody tr').length >= 25, null, {timeout: 20000});
      await page.evaluate(() => { LIVE = false; });           /* the header's pause: no tick redraws it */
      await page.evaluate(() => [...document.querySelectorAll('#ct-pager button')].filter(b => !b.disabled)[0].click());
      await page.waitForTimeout(1500);
      const before = await certRows();
      run.page2Said = await said();
      run.victim = before[0];
      await page.evaluate(async name => {
        const r = [...document.querySelectorAll('#ct-table tbody tr')].find(t => t._rec && t._rec.name === name)._rec;
        const full = (await ACME_CERTS.api('certs/one?id=' + r.id)).cert;
        ACME_CERTS.ctx.deleteDialog(full);
      }, run.victim);
      await page.waitForSelector('#modal-foot .btn.danger');
      await page.evaluate(() => document.querySelector('#modal-foot .btn.danger').click());
      await page.waitForTimeout(2000);
      run.afterDelete = await certRows();
      run.afterSaid = await said();
      run.pager = await page.evaluate(() => $('ct-pager').textContent);
      await shot('page2');
      await page.evaluate(() => { LIVE = true; });

      // ---- rows picked, another tab: nothing picked there ----
      await page.evaluate(() => [...document.querySelectorAll('#ct-pager button')].filter(b => !b.disabled)[0].click());
      await page.waitForTimeout(1500);
      const rows = await page.$$('#ct-table tbody tr');
      await rows[1].click({modifiers: ['Control'], position: {x: 4, y: 6}});
      await rows[2].click({modifiers: ['Control'], position: {x: 4, y: 6}});
      await page.waitForTimeout(300);
      const dock = () => page.evaluate(() => {
        const d = document.querySelector('.cxm-dock');
        return {sel: !!(d && d.querySelector('.cxm-dk.sel')), acts: !!(d && d.querySelector('.cxm-dk-b'))};
      });
      run.dockCerts = await dock();
      await page.click('.tabs button[data-tab="targets"]').catch(() => page.evaluate(() => showTab('targets')));
      await page.waitForTimeout(1500);
      run.dockTargets = await dock();
      await shot('dock-targets');
      await page.evaluate(() => showTab('settings'));
      await page.waitForTimeout(1500);
      run.dockSettings = await dock();
      await page.evaluate(() => showTab('certs'));
      await page.waitForTimeout(1500);
      run.dockBack = await dock();
      await page.keyboard.press('Escape');

      // ---- Ctrl+K after a rename and a deletion here ----
      n += 1;
      const ren = 'pal' + n, del = 'bulk' + String(10 + n).padStart(2, '0'), old = 'bulk' + String(20 + n).padStart(2, '0');
      run.palBefore = await paletteFind(page, old);
      await page.evaluate(async names => {
        const all = (await ACME_CERTS.api('certs?per=1000')).rows;
        const a = all.find(c => c.name === names[0]), b = all.find(c => c.name === names[1]);
        await ACME_CERTS.api('certs/save', {id: a.id, name: names[2]});
        await ACME_CERTS.api('certs/delete', {id: b.id, revoke: 0});
      }, [old, del, ren]);
      await page.waitForTimeout(500);
      run.palOld = await paletteFind(page, old);
      run.palNew = await paletteFind(page, ren);
      run.palDeleted = await paletteFind(page, del);
      run.names = {ren, del, old};

      // ---- Show in Jobs / Events with filters chosen there before ----
      await page.evaluate(() => showTab('jobs'));
      await page.waitForTimeout(1200);
      await page.selectOption('#jb-ok', '0');
      await page.waitForTimeout(800);
      await page.evaluate(() => showTab('events'));
      await page.waitForTimeout(1200);
      await page.selectOption('#ev-kind', 'accounts').catch(() => page.evaluate(() => { $('ev-kind').value = [...$('ev-kind').options][1].value; }));
      await page.waitForTimeout(800);
      await page.evaluate(() => showTab('certs'));
      await page.waitForTimeout(800);
      await page.fill('#ct-q', 'worked');
      await page.waitForTimeout(1800);
      const menuGo = async which => {
        const r = (await page.$$('#ct-table tbody tr'))[0];
        await r.click({button: 'right', position: {x: 40, y: 8}});
        await page.waitForSelector('.cxm [role=menuitem]');
        const ok = await page.evaluate(i => {
          const want = i === 'jobs' ? /^(Show in Jobs|Zobrazit v Úlohách)/ : /^(Show in Events|Zobrazit v Událostech)/;
          const items = [...document.querySelectorAll('.cxm [role=menuitem]')];
          const it = items.find(x => want.test(x.textContent.trim()));
          if (it) { it.click(); return true; }
          return items.map(x => x.textContent.trim()).join(' | ');
        }, which);
        await page.waitForTimeout(2500);
        return ok;
      };
      run.jobsMenu = await menuGo('jobs');
      run.jobs = await page.evaluate(() => ({ok: $('jb-ok').value, kind: $('jb-kind').value, cert: $('jb-cert').value,
        rows: document.querySelectorAll('#jb-table tbody tr:not(.empty-row)').length}));
      await page.evaluate(() => showTab('certs'));
      await page.waitForTimeout(1000);
      run.eventsMenu = await menuGo('events');
      run.events = await page.evaluate(() => ({q: $('ev-q').value, kind: $('ev-kind').value,
        rows: document.querySelectorAll('#ev-table tbody tr:not(.empty-row)').length}));
      await shot('events');
      await page.evaluate(() => { $('jb-ok').value = ''; $('ev-kind').value = ''; $('ev-q').value = ''; });
      run.hs = await page.evaluate(() => document.scrollingElement.scrollWidth - innerWidth);

      // ---- once: two tabs of the same browser ----
      if (lang === 'en' && w === 1400) {
        const two = await signIn(ctx, tag + ' second');
        await two.bringToFront();
        await two.evaluate(() => showTab('certs'));
        await two.waitForTimeout(1500);
        run.twoBefore = await paletteFind(two, 'bulk3');
        const gone = 'bulk3' + '5';
        await page.bringToFront();
        await page.evaluate(async name => {
          const c = (await ACME_CERTS.api('certs?per=1000')).rows.find(x => x.name === name);
          await api('certs/delete', {id: c.id, revoke: 0});        /* not through this page's lists */
        }, gone);
        await two.bringToFront();
        await two.waitForTimeout(7000);                             /* the second tab's tick */
        run.twoAfter = await paletteFind(two, 'bulk3');
        run.twoGone = gone;
        // the columns: put away in one tab, then in the other opened before (its jobs)
        await page.evaluate(() => api('columns', {edit: true}));
        await page.reload(); await two.reload();
        await page.waitForTimeout(2000);
        await two.bringToFront();
        await two.evaluate(() => showTab('jobs'));
        await two.waitForFunction(() => document.querySelector('#jb-table table thead th[data-ck]'), null, {timeout: 20000});
        await page.bringToFront();
        await page.evaluate(() => showTab('certs'));
        await page.waitForFunction(() => document.querySelector('#ct-table table thead th[data-ck]'), null, {timeout: 20000});
        run.colsA = await page.evaluate(() => {
          const t = document.querySelector('#ct-table table');
          const ck = [...t.tHead.rows[0].cells].map(c => c.dataset.ck)[3];
          colsHide(t, ck, true);
          return ck;
        });
        await page.waitForTimeout(2000);
        await two.bringToFront();
        run.colsB = await two.evaluate(() => {
          const t = document.querySelector('#jb-table table');
          const ck = [...t.tHead.rows[0].cells].map(c => c.dataset.ck)[1];
          colsHide(t, ck, true);
          return ck;
        });
        await two.waitForTimeout(2000);
        run.colsKept = await page.evaluate(() => api('my-settings').then(d => [].concat(...Object.values((d.settings || {}).columns || {}).map(x => x.h || []))));
        await page.evaluate(() => api('columns', {reset: true}).then(() => api('columns', {edit: false})));
        await two.close();
      }
      out.runs.push(run);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
