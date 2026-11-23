// The pages' half of test/test_hunt_rw5_ui.py (hunt w5, ui: a sweep of every page after w1-w4).
//
//   node test/hunt_rw5_ui_page.js BASE_URL PASSWORD [screenshot-folder]
//
// - Every main tab as a full administrator (tester), a reader (jan) and a certificate
//   administrator of one team (cm), English and Czech, 1400 and 390 px; at 390 every Settings
//   pane too; the portal's every view for a member (jan): no error, the page never wider than
//   the window.
// - Ctrl+K in Czech: an event found is said in Czech (its words and its kind), as on Events.
// - The column menu opened with the mouse: the menu has the focus, no line of it wears the focus
//   ring; the arrows go on from there; Escape closes it.
// - The portal's form to ask for a certificate for a team whose request profiles are "none at
//   all": said so (not "only from the profiles" with nothing after it, in English).
// Prints one line of JSON.
const { chromium } = require('playwright');
const path = require('path');

const OVER = () => {
  const W = document.documentElement.clientWidth;
  return document.documentElement.scrollWidth > W + 1 ? ['page ' + document.documentElement.scrollWidth + ' > ' + W] : [];
};

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], overflow: {}, tabs: {}, panes: {}, views: {}, palette: {}, cols: {}, ask: {}};
  const watch = (page, tag) => {
    page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
    page.on('console', m => {
      if (m.type() !== 'error') return;
      const t = m.text();
      if (/status of 40[39]/.test(t)) return;        /* a refusal a role is meant to get */
      out.errors.push(tag + ' console: ' + t.slice(0, 200));
    });
    page.on('dialog', async d => { out.errors.push(tag + ' browser dialog: ' + d.message()); await d.dismiss(); });
  };
  const context = async (lang, w) => {
    const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    return ctx;
  };
  const admin = async (ctx, who, tag) => {
    const page = await ctx.newPage();
    watch(page, tag);
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', who);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(1500);
    return page;
  };
  const portal = async (ctx, who, tag) => {
    const page = await ctx.newPage();
    watch(page, tag);
    await page.goto(base + '/');
    await page.fill('#in-name', who);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#pw-nav, #cp-list', {timeout: 30000});
    await page.waitForTimeout(1500);
    return page;
  };
  try {
    // ---- the sweep ----
    for (const who of ['tester', 'jan', 'cm']) for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `${who}-${lang}-${w}`;
      const ctx = await context(lang, w);
      const page = await admin(ctx, who, tag);
      const tabs = await page.evaluate(() => [...document.querySelectorAll('.tabs [role=tab]')].filter(b => !b.hidden && b.getClientRects().length).map(b => b.dataset.tab));
      out.tabs[tag] = tabs;
      for (const t of tabs) {
        await page.evaluate(t => showTab(t), t);
        await page.waitForTimeout(1200);
        const o = await page.evaluate(OVER);
        if (o.length) out.overflow[tag + ' ' + t] = o;
        if (shots && w < 500) await page.screenshot({path: path.join(shots, `rw5-${tag}-${t}.png`)});
      }
      if (w < 500) {
        await page.evaluate(() => showTab('settings'));
        await page.waitForTimeout(800);
        const panes = await page.evaluate(() => [...document.querySelectorAll('#ctl-nav [data-pane]')].filter(b => !b.hidden).map(b => b.dataset.pane));
        out.panes[tag] = panes.length;
        for (const p of panes) {
          await page.evaluate(p => { const b = document.querySelector('#ctl-nav [data-pane="' + p + '"]'); if (b) b.click(); }, p);
          await page.waitForTimeout(700);
          const o = await page.evaluate(OVER);
          if (o.length) out.overflow[tag + ' settings/' + p] = o;
        }
      }
      if (who === 'tester' && w > 1000) {
        // ---- Ctrl+K: an event in the page's language ----
        await page.evaluate(() => showTab('overview'));
        await page.keyboard.press('Control+k');
        await page.waitForSelector('.cxp-in');
        await page.fill('.cxp-in', 'shop');
        await page.waitForTimeout(1800);
        out.palette[lang] = await page.evaluate(() => [...document.querySelectorAll('.cxp-list [role=option]')]
          .filter(r => /Event|Událost/.test((r.querySelector('.cxp-k') || {}).textContent || ''))
          .map(r => [r.querySelector('.cxp-t').textContent.trim(), [...r.querySelectorAll('.cxp-s > span')].map(s => s.textContent.trim()).filter(s => s && s !== '·')]));
        if (shots) await page.screenshot({path: path.join(shots, `rw5-palette-${lang}.png`)});
        await page.keyboard.press('Escape');
        await page.waitForTimeout(300);

        // ---- the column menu by the mouse ----
        await page.evaluate(() => colsSwitch(true));
        await page.waitForTimeout(500);
        await page.evaluate(() => showTab('certs'));
        await page.waitForTimeout(1200);
        await page.click('#ct-table thead th:nth-child(2)', {button: 'right'});
        await page.waitForTimeout(300);
        const c = {};
        c.open = await page.evaluate(() => !!COLS_MENU);
        c.menuFocused = await page.evaluate(() => !!COLS_MENU && document.activeElement === COLS_MENU);
        c.lineFocused = await page.evaluate(() => !!(document.activeElement && document.activeElement.classList.contains('cols-mi')));
        if (shots) await page.screenshot({path: path.join(shots, `rw5-colsmenu-${lang}.png`)});
        await page.keyboard.press('ArrowDown');
        c.down = await page.evaluate(() => [...COLS_MENU.querySelectorAll('.cols-mi')].filter(b => !b.disabled).indexOf(document.activeElement));
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);
        c.closed = await page.evaluate(() => !COLS_MENU);
        // ...and Shift+F10 on a row still puts the focus on its first line
        await page.evaluate(() => document.querySelector('#ct-table tbody tr').focus());
        await page.keyboard.press('Shift+F10');
        await page.waitForTimeout(300);
        c.kbLine = await page.evaluate(() => !!COLS_MENU && document.activeElement.classList.contains('cols-mi'));
        await page.keyboard.press('Escape');
        await page.evaluate(() => colsSwitch(false));
        await page.waitForTimeout(300);
        out.cols[lang] = c;
      }
      await ctx.close();
    }

    // ---- the portal: every view for a member ----
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `portal-${lang}-${w}`;
      const ctx = await context(lang, w);
      const page = await portal(ctx, 'jan', tag);
      const views = await page.evaluate(() => [...new Set([...document.querySelectorAll('#pw-nav [data-view]')].map(b => b.dataset.view))]);
      out.views[tag] = views;
      for (const v of views) {
        await page.evaluate(v => { const b = [...document.querySelectorAll('#pw-nav [data-view="' + v + '"]')].find(x => x.getClientRects().length) || document.querySelector('#pw-nav [data-view="' + v + '"]'); if (b) b.click(); }, v);
        await page.waitForTimeout(1200);
        const o = await page.evaluate(OVER);
        if (o.length) out.overflow[tag + ' ' + v] = o;
      }
      await ctx.close();

      // ---- asking for a certificate for a team with no request profile at all ----
      const ctx2 = await context(lang, w);
      const p2 = await portal(ctx2, 'wreq', tag + '-ask');
      await p2.evaluate(() => { const b = [...document.querySelectorAll('#pw-nav [data-view="certs"]')].find(x => x.getClientRects().length); if (b) b.click(); });
      await p2.waitForSelector('#pw-ask-c', {timeout: 20000});
      await p2.click('#pw-ask-c');
      await p2.waitForSelector('#modal-body .pw-note-parts', {timeout: 20000});
      await p2.waitForTimeout(400);
      out.ask[tag] = await p2.evaluate(() => [...document.querySelectorAll('#modal-body .pw-note-part')].map(x => x.textContent.trim()));
      const o = await p2.evaluate(OVER);
      if (o.length) out.overflow[tag + ' ask'] = o;
      if (shots) await p2.screenshot({path: path.join(shots, `rw5-ask-${lang}-${w}.png`)});
      await ctx2.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
