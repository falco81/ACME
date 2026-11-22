// The pages' half of test/test_f140_ui.py (1.0.140): the expiry calendar (Certificates → Calendar,
// the portal's), the global search of Ctrl+K and the header, request profiles from a template -
// in Chromium against a real daemon.
//
//   node test/f140_ui_page.js BASE_URL PASSWORD
//
// In English and Czech, at 1400 and 390 px. Prints one line of JSON; F140_SHOTS=dir: screenshots.
const { chromium } = require('playwright');
const path = require('path');

const SHOTS = process.env.F140_SHOTS || '';

function inPage() {
  // English left in the calendar, the palette or one of our dialogs on the Czech page
  const EN = /(?<!\p{L})(the|and|of|is|it|for|with|not|may|this|its|what|who|from|are|run|runs|out|renewed|renewal|renewals|within|days|today|month|year|calendar|list|subscribe|link|make|template|profile|source|domains|names|find|anything|searching|every|certificate|certificates|deployment|team|only|mine|few|many|later|week|next|nothing|download)(?!\p{L})/iu;
  const out = {english: [], hscroll: 0};
  for (const w of document.querySelectorAll('.cal, .cal-switch, .cxp, .hsearch, #modal-box')) {
    if (w.id === 'modal-box' && (document.getElementById('modal').hidden || !w.querySelector('.cal, .cal-subhero, .rpf-dlg'))) continue;
    const tw = document.createTreeWalker(w, NodeFilter.SHOW_TEXT);
    let t;
    while ((t = tw.nextNode())) {
      const p = t.parentElement;
      if (!p || !t.textContent.trim() || p.closest('[data-no-i18n], .mono, kbd, input, option, select')) continue;
      if (EN.test(t.textContent)) out.english.push(t.textContent.trim().slice(0, 80));
    }
    for (const n of w.querySelectorAll('[placeholder], [aria-label], [title]')) {
      if (n.closest('[data-no-i18n]')) continue;
      for (const a of ['placeholder', 'aria-label', 'title']) {
        const v = n.getAttribute(a);
        if (v && EN.test(v) && !/^[\w.+-]+@[\w.-]+$/.test(v) && !/example\.(com|org)/.test(v)) out.english.push(a + ': ' + v);
      }
    }
  }
  out.hscroll = document.scrollingElement.scrollWidth - innerWidth;
  return out;
}

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: [], ro: null, portal: null};
  const shot = async (page, name) => { if (SHOTS) await page.screenshot({path: path.join(SHOTS, name + '.png'), fullPage: page.viewportSize().width < 500}); };
  const signIn = async (lang, w, who) => {
    const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(lang + w + ': ' + String(e.message || e)));
    page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) out.errors.push(lang + w + ' console: ' + m.text()); });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', who || 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(1200);
    return {ctx, page};
  };
  const pause = (page, ms) => page.waitForTimeout(ms);
  const look = async (page, run) => {
    const g = await page.evaluate(inPage);
    run.english.push(...g.english);
    if (g.hscroll > 0) run.hscroll.push(g.hscroll);
  };
  const toCalendar = async (page) => {
    await page.evaluate(() => showTab('certs'));
    await pause(page, 600);
    await page.click('#cal-view-cal');
    await page.waitForSelector('.cal-day, .cal-sq', {timeout: 20000});
    await pause(page, 400);
  };
  const closeModal = async (page) => {
    await page.keyboard.press('Escape');
    await pause(page, 300);
    if (await page.evaluate(() => !document.getElementById('modal').hidden)) {
      await page.evaluate(() => closeModal());
      await pause(page, 300);
    }
  };

  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `${lang}-${w}`;
      const {ctx, page} = await signIn(lang, w);
      const run = {lang, w, english: [], hscroll: []};

      // ---- the calendar: List | Calendar, a month ----
      await page.evaluate(() => showTab('certs'));
      await pause(page, 500);
      run.switch = await page.evaluate(() => !!document.querySelector('#tab-certs .cal-switch #cal-view-cal'));
      await toCalendar(page);
      if (await page.evaluate(() => !document.querySelector('.cal[data-view="month"]'))) {
        await page.click('.cal-seg .cal-segb >> nth=0');
        await page.waitForSelector('.cal[data-view="month"] .cal-day');
      }
      run.monthDays = await page.$$eval('.cal-day', n => n.length);
      run.tiles = await page.$$eval('.cal-tile', n => n.length);
      await look(page, run);
      await shot(page, `cal-month-${tag}`);
      // a day with something running out (this month, or the next)
      if (!(await page.$('.cal-day.has'))) { await page.click('.cal-nav .btn.iconbtn >> nth=1'); await page.waitForSelector('.cal-day'); await pause(page, 300); }
      const day = page.locator('.cal-day.has').first();
      await day.scrollIntoViewIfNeeded();
      await day.click();
      await pause(page, 400);
      run.dayList = await page.$$eval('.cal-side .cal-item', n => n.length) > 0;
      await shot(page, `cal-day-${tag}`);
      await page.locator('.cal-side .cal-item').first().click();
      await page.waitForSelector('#modal:not([hidden])', {timeout: 15000});
      await pause(page, 600);
      run.certOpened = await page.evaluate(() => !document.getElementById('modal').hidden && /\S/.test(document.getElementById('modal-title').textContent));
      await closeModal(page);
      // the keyboard: an arrow moves to the next day
      const before = await page.evaluate(() => { const c = document.querySelector('.cal-day[tabindex="0"]'); c.focus(); return c.dataset.day; });
      await page.keyboard.press('ArrowRight');
      await pause(page, 150);
      run.kbMoved = await page.evaluate(b => document.activeElement && document.activeElement.dataset.day && document.activeElement.dataset.day !== b, before);
      // a filter: the team's certificates only
      const teamSel = page.locator('.cal-fsel select').first();
      await teamSel.selectOption('Webteam');
      await page.waitForSelector('.cal-day', {timeout: 15000});
      await pause(page, 700);
      run.filterTeam = await page.evaluate(() => {
        const own = [...document.querySelectorAll('.cal-side .cal-own')].map(x => x.textContent.trim());
        return own.length > 0 && own.every(x => x === 'Webteam');
      });
      await shot(page, `cal-filter-${tag}`);
      await page.locator('.cal-fsel select').first().selectOption('');
      await page.waitForSelector('.cal-day', {timeout: 15000});
      await pause(page, 500);

      // ---- a year ----
      await page.click('.cal-seg .cal-segb >> nth=1');
      await page.waitForSelector('.cal-sq:not(.mini)');
      await pause(page, 400);
      run.yearSquares = await page.$$eval('.cal-hm .cal-sq', n => n.length);
      await look(page, run);
      await shot(page, `cal-year-${tag}`);
      // (clicked where it is: the page keeps its own place while things are drawn, and Playwright's
      // own scrolling to a square of a box that scrolls sideways was undone under it)
      await page.locator('.cal-wk.has').first().dispatchEvent('click');
      await pause(page, 400);
      run.weekList = await page.$$eval('.cal-side .cal-item', n => n.length) > 0;
      await shot(page, `cal-week-${tag}`);
      // back to the month for the next run
      await page.click('.cal-seg .cal-segb >> nth=0');
      await pause(page, 400);

      // ---- the file and the subscription ----
      run.ics = await page.evaluate(() => ACME_CERTS.api('calendar/ics').then(d => d.text));
      await page.click('.cal-acts .btn >> nth=1');
      await page.waitForSelector('#modal:not([hidden]) .cal-subhero');
      await shot(page, `cal-sub0-${tag}`);
      await page.click('#modal-foot .btn.primary');
      await page.waitForSelector('#modal .cal-link input', {timeout: 15000});
      run.subLink = await page.inputValue('#modal .cal-link input');
      await look(page, run);
      await shot(page, `cal-sub-${tag}`);
      await page.click('#modal-foot .btn.danger');
      await pause(page, 200);
      await page.click('#modal-foot .sure-strip .btn.danger');
      await pause(page, 600);
      await closeModal(page);

      // ---- the search: the header's box opens Ctrl+K, which asks the server ----
      run.header = await page.evaluate(() => { const b = document.getElementById('hsearch'); return !!b && b.offsetParent !== null; });
      await page.evaluate(() => scrollTo(0, 0));
      await pause(page, 200);
      await shot(page, `header-${tag}`);
      await page.locator('#hsearch').dispatchEvent('click');
      await page.waitForSelector('.cxp');
      await page.keyboard.type('smtp.example');
      await page.waitForFunction(() => [...document.querySelectorAll('.cxp-row')].some(r => /\bmail\b/.test(r.textContent)), null, {timeout: 15000});
      await pause(page, 300);
      run.paletteSan = await page.$$eval('.cxp-row .cxp-t', n => n.map(x => x.textContent.trim()).join(' | '));
      await look(page, run);
      await shot(page, `palette-san-${tag}`);
      await page.fill('.cxp-in', 'intranet');
      await page.waitForFunction(() => document.querySelectorAll('.cxp-row').length >= 2 && !document.querySelector('.cxp-busy'), null, {timeout: 15000});
      await pause(page, 300);
      run.paletteKinds = await page.evaluate(() => {
        const icons = [...document.querySelectorAll('.cxp-row .cxp-k')].map(x => x.textContent.trim());
        return new Set(icons).size >= 2;
      });
      await shot(page, `palette-kinds-${tag}`);
      // Enter on what the server found by its SAN: the certificate's card
      await page.fill('.cxp-in', 'smtp.example');
      await page.waitForFunction(() => [...document.querySelectorAll('.cxp-row')].some(r => /\bmail\b/.test(r.textContent)), null, {timeout: 15000});
      await page.locator('.cxp-row', {hasText: 'mail'}).first().click();
      await page.waitForSelector('#modal:not([hidden])', {timeout: 15000});
      await pause(page, 500);
      run.paletteOpened = await page.evaluate(() => /mail/.test(document.getElementById('modal-body').textContent));
      await closeModal(page);

      // ---- a request profile from a template ----
      await page.evaluate(() => { showTab('settings'); setTimeout(() => showPane('reqprofiles'), 50); });
      await page.waitForSelector('#rp-tpl', {timeout: 20000});
      await page.click('#rp-tpl');
      await page.waitForSelector('.rpf-card', {timeout: 20000});
      await pause(page, 400);
      run.tplCards = await page.$$eval('.rpf-card', n => n.length);
      await look(page, run);
      await shot(page, `tpl-pick-${tag}`);
      await page.click('.rpf-card[data-tpl="internal"]');
      await page.waitForSelector('#rpf-name');
      run.tplName = 'Internal ' + tag;
      await page.fill('#rpf-name', run.tplName);
      await page.fill('#rpf-suffixes', 'corp.test');
      await page.waitForSelector('.rpf-prev .rpf-chips', {timeout: 15000});
      await pause(page, 700);
      run.tplPreview = await page.$$eval('.rpf-prev .rpf-chip', n => n.length) > 2;
      await look(page, run);
      await shot(page, `tpl-form-${tag}`);
      await page.click('#modal-foot .btn.primary');
      await page.waitForSelector('#rpx-ed', {timeout: 20000});
      await pause(page, 600);
      run.tplEditor = true;
      run.tplMade = await page.evaluate(n => document.getElementById('modal-body').querySelector('input') && [...document.querySelectorAll('#modal-body input')].some(i => i.value === n), run.tplName);
      await shot(page, `tpl-editor-${tag}`);
      await closeModal(page);
      out.runs.push(run);
      await ctx.close();
    }

    // ---- a reader: the calendar yes; no template button; no accounts found ----
    {
      const {ctx, page} = await signIn('en', 1400, 'viewer');
      const ro = {};
      await toCalendar(page);
      ro.calendar = await page.$$eval('.cal-day, .cal-sq', n => n.length) > 0;
      await page.evaluate(() => { showTab('settings'); setTimeout(() => showPane('reqprofiles'), 50); });
      await page.waitForSelector('#rp-host .tmx-bar, #rp-host .rpx-bar, #rp-host', {timeout: 20000});
      await pause(page, 1200);
      ro.tplButton = !!(await page.$('#rp-tpl'));
      await page.locator('#hsearch').dispatchEvent('click');
      await page.waitForSelector('.cxp');
      await page.keyboard.type('tester');
      await page.waitForFunction(() => !document.querySelector('.cxp-busy') && document.querySelector('.cxp-row, .cxp-none'), null, {timeout: 15000});
      await pause(page, 500);
      ro.accounts = await page.evaluate(() => [...document.querySelectorAll('.cxp-row .cxp-k')].some(x => /Account/.test(x.textContent)));
      out.ro = ro;
      await ctx.close();
    }

    // ---- the portal: Calendar beside Your certificates ----
    {
      const ctx = await browser.newContext({viewport: {width: 1400, height: 900}, deviceScaleFactor: 1});
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push('portal: ' + String(e.message || e)));
      await page.goto(base + '/');
      await page.fill('#in-name', 'viewer');
      await page.fill('#in-pass', pass);
      await page.click('#in-go');
      await page.waitForSelector('.cal-pbtn', {timeout: 30000});
      await page.click('.cal-pbtn');
      await page.waitForSelector('#modal .cal-day', {timeout: 20000});
      await pause(page, 500);
      const p = {calendar: true};
      p.items = await page.$$eval('#modal .cal-side .cal-item', n => n.length);
      await shot(page, 'portal-cal-1400');
      await page.setViewportSize({width: 390, height: 844});
      await pause(page, 500);
      await shot(page, 'portal-cal-390');
      p.hscroll = await page.evaluate(() => document.scrollingElement.scrollWidth - innerWidth);
      out.portal = p;
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
