// The pages' half of test/test_hunt_rw4_a11y.py (hunt w4, a11y: the keyboard and screen readers).
//
//   node test/hunt_rw4_a11y_page.js BASE_URL PASSWORD [screenshot-folder]
//
// English and Czech, 1400 and 390 px, the administration and the portal:
// - the toast is a live region (polite, a refusal assertive);
// - the popup is a dialog named by its title, the one on top over another too;
// - the arrow keys, Home and End along the main tabs;
// - every box of the panes named (Events, mail, the mail queue, accounts, firewall, SSH keys,
//   proxy, DNS, teams);
// - the dark page's grey words (tables' headings, the header's time), the violet chips and a link
//   no rule colours reach 4.5:1;
// - the settings' search: Escape on its list back in the box, a setting chosen by Enter focused;
// - (1400) the column menu from the keyboard: Shift+F10 on a row while editing the columns, the
//   arrows in it, a column ticked keeps the focus, Escape back on the row.
// Prints one line of JSON.
const { chromium } = require('playwright');
const path = require('path');

const CONTRAST = () => {
  const parse = c => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(',').map(parseFloat); return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1}; };
  const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const blend = (t, b) => ({r: t.r * t.a + b.r * (1 - t.a), g: t.g * t.a + b.g * (1 - t.a), b: t.b * t.a + b.b * (1 - t.a), a: 1});
  window.__ratio = e => {
    const stack = [];
    for (let x = e; x && x.nodeType === 1; x = x.parentElement) {
      const c = parse(getComputedStyle(x).backgroundColor);
      if (c && c.a > 0) stack.push(c);
      if (c && c.a >= 1) break;
    }
    let bg = {r: 13, g: 17, b: 23, a: 1};
    for (let i = stack.length - 1; i >= 0; i--) bg = blend(stack[i], bg);
    const fg = blend(parse(getComputedStyle(e).color), bg);
    const a = lum(fg), b = lum(bg);
    return Math.round((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) * 100) / 100;
  };
  window.__unnamed = root => [...root.querySelectorAll('input:not([type=hidden]), select, textarea')]
    .filter(i => i.getClientRects().length)
    .filter(i => !(i.getAttribute('aria-label') || i.getAttribute('aria-labelledby') || i.closest('label')
      || (i.id && document.querySelector('label[for="' + CSS.escape(i.id) + '"]')) || i.title))
    .map(i => i.outerHTML.slice(0, 90));
};

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: [], portal: []};
  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `${lang}-${w}`;
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      await ctx.addInitScript(CONTRAST);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1500);
      const run = {lang, w};
      const act = () => page.evaluate(() => {
        const a = document.activeElement;
        return a ? {tag: a.tagName, id: a.id, cls: String(a.className), tab: a.dataset ? a.dataset.tab || a.dataset.pane || '' : '',
                    key: (a.closest('.set-item') || {dataset: {}}).dataset.key || '', menu: !!a.closest('.cols-menu'),
                    row: !!(a.tagName === 'TR' && a.closest('#ct-table'))} : null;
      });

      // ---- the toast, a live region from the start ----
      run.toast0 = await page.evaluate(() => { const t = document.getElementById('toast'); return [t.getAttribute('role'), t.getAttribute('aria-live')]; });
      run.toastBad = await page.evaluate(() => { toast('x', 'bad'); const t = document.getElementById('toast'); return t.getAttribute('aria-live'); });
      run.toastGood = await page.evaluate(() => { toast('y', 'good'); const t = document.getElementById('toast'); return t.getAttribute('aria-live'); });

      // ---- the popup: a dialog named by its title, over another too ----
      run.dialog = await page.evaluate(async () => {
        const one = () => { const b = document.getElementById('modal-box'); const t = document.getElementById(b.getAttribute('aria-labelledby') || '-');
          return [b.getAttribute('role'), b.getAttribute('aria-modal'), t ? t.textContent : null]; };
        modal('First popup', b => b.appendChild(document.createTextNode('one')));
        const a = one();
        modalOver(() => modal('Second popup', b => b.appendChild(document.createTextNode('two'))));
        const b = one();
        const under = document.querySelector('.modal.under .box');
        const u = under ? (document.getElementById(under.getAttribute('aria-labelledby')) || {}).textContent : null;
        closeModal(true);
        const c = one();
        closeModal(true);
        return {first: a, second: b, under: u, back: c};
      });

      // ---- the arrows along the tabs ----
      await page.evaluate(() => showTab('overview'));
      await page.waitForTimeout(500);
      const tabs = await page.evaluate(() => [...document.querySelectorAll('.tabs [role=tab]')].filter(b => !b.hidden).map(b => b.dataset.tab));
      await page.focus('.tabs [data-tab=overview]');
      await page.keyboard.press('ArrowRight');
      run.tabRight = (await act()).tab;
      await page.keyboard.press('End');
      run.tabEnd = (await act()).tab;
      await page.keyboard.press('ArrowRight');
      run.tabWrap = (await act()).tab;
      await page.keyboard.press('ArrowLeft');
      run.tabLeft = (await act()).tab;
      await page.keyboard.press('Home');
      run.tabHome = (await act()).tab;
      run.tabs = tabs;
      run.stillOverview = await page.evaluate(() => !document.getElementById('tab-overview').hidden);

      // ---- the header's time, the tables' headings ----
      run.ratios = {};
      run.ratios.updated = await page.evaluate(() => __ratio(document.getElementById('updated-at')));
      await page.evaluate(() => showTab('certs'));
      await page.waitForFunction(() => document.querySelectorAll('#ct-table tbody tr').length > 0, null, {timeout: 20000});
      run.ratios.th = await page.evaluate(() => Math.min(...[...document.querySelectorAll('#ct-table thead th')].filter(t => t.getClientRects().length && t.textContent.trim()).map(__ratio)));

      // ---- Events: its kind named ----
      await page.evaluate(() => showTab('events'));
      await page.waitForTimeout(800);
      run.unnamed = {events: await page.evaluate(() => __unnamed(document.getElementById('tab-events')))};
      run.evKind = await page.evaluate(() => document.getElementById('ev-kind').getAttribute('aria-label'));

      // ---- the settings' panes: every box named; the violet chips; a link ----
      await page.evaluate(() => showTab('settings'));
      await page.waitForTimeout(600);
      for (const p of ['mail', 'mailq', 'people', 'fw', 'sshkeys', 'proxy', 'dnssets', 'teams', 'modules', 'ha']) {
        await page.evaluate(p => { const b = document.querySelector('#ctl-nav [data-pane="' + p + '"]'); if (b) b.click(); }, p);
        await page.waitForTimeout(1600);
        run.unnamed[p] = await page.evaluate(() => __unnamed(document.getElementById('tab-settings')));
        {
          /* words in the violet of the pages (a full administrator's chip): the lowest ratio */
          run.ratios.violet = await page.evaluate(() => {
            const probe = document.createElement('span'); probe.style.color = 'var(--violet)'; document.body.appendChild(probe);
            const want = getComputedStyle(probe).color; probe.remove();
            const v = [...document.querySelectorAll('#tab-settings *')].filter(x => x.getClientRects().length && getComputedStyle(x).color === want
              && [...x.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()));
            return v.length ? Math.min(...v.map(__ratio)) : null;
          }).then(x => x === null ? run.ratios.violet || null : Math.min(x, run.ratios.violet || 99));
        }
        if (p === 'people') {
          run.roleLabel = await page.evaluate(() => { const r = document.querySelector('.acc-rolebox'); return r && r.getAttribute('aria-label'); });
        }
        if (p === 'ha') {
          run.ratios.links = await page.evaluate(() => [...document.querySelectorAll('#tab-settings a[href]')].filter(a => a.getClientRects().length).map(__ratio));
        }
        if (p === 'sshkeys') run.sshLabel = await page.evaluate(() => { const x = document.querySelector('#sk-host select'); return x && x.getAttribute('aria-label'); });
        if (p === 'mail') run.mailLabels = await page.evaluate(() => ['mail-test-kind', 'mail-test-lang'].map(id => document.getElementById(id).getAttribute('aria-label')));
      }
      if (shots) await page.screenshot({path: path.join(shots, `rw4-settings-${tag}.png`)});

      // ---- the settings' search ----
      await page.evaluate(() => { const f = document.getElementById('ctl-find'); f.value = ''; });
      await page.focus('#ctl-find');
      await page.keyboard.type('certs_renew_days');
      await page.waitForTimeout(600);
      run.findHits = await page.evaluate(() => document.querySelectorAll('#ctl-found .ctl-hit:not(.ctl-hit-pane)').length);
      await page.keyboard.press('ArrowDown');
      run.findInList = await page.evaluate(() => !!document.activeElement.closest('#ctl-found'));
      await page.keyboard.press('Escape');
      run.findEsc = await page.evaluate(() => [document.activeElement.id, document.getElementById('ctl-found').hidden]);
      await page.evaluate(() => { const f = document.getElementById('ctl-find'); f.value = ''; });
      await page.keyboard.type('certs_renew_days');
      await page.waitForTimeout(600);
      await page.evaluate(() => { const h = document.querySelector('#ctl-found .ctl-hit:not(.ctl-hit-pane)'); if (h) h.focus(); });
      await page.keyboard.press('Enter');
      await page.waitForTimeout(900);
      run.findChosen = (await act()).key;

      // ---- the column menu from the keyboard ----
      if (w > 1000) {
        await page.evaluate(() => colsSwitch(true));
        await page.waitForTimeout(600);
        await page.evaluate(() => showTab('certs'));
        await page.waitForTimeout(1200);
        await page.evaluate(() => document.querySelector('#ct-table tbody tr').focus());
        await page.keyboard.press('Shift+F10');
        await page.waitForTimeout(300);
        run.cols = {open: await page.evaluate(() => !!COLS_MENU), rowMenu: await page.evaluate(() => !!document.querySelector('.cxm'))};
        run.cols.first = (await act()).menu;
        await page.keyboard.press('ArrowDown');
        await page.keyboard.press('ArrowDown');
        run.cols.moved = await page.evaluate(() => [...COLS_MENU.querySelectorAll('.cols-mi')].indexOf(document.activeElement));
        // a column of the list: ticked off and on again, the focus stays on it
        const at = await page.evaluate(() => { const all = [...COLS_MENU.querySelectorAll('.cols-mi')]; const i = all.findIndex(b => b.querySelector('svg') && !b.disabled && all.indexOf(b) > 3); all[i].focus(); return i; });
        await page.keyboard.press('Enter');
        await page.waitForTimeout(300);
        run.cols.afterTick = await page.evaluate(() => [!!COLS_MENU, COLS_MENU && [...COLS_MENU.querySelectorAll('.cols-mi')].indexOf(document.activeElement)]);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(300);
        run.cols.at = at;
        await page.keyboard.press('Escape');
        await page.waitForTimeout(200);
        run.cols.closed = await page.evaluate(() => !COLS_MENU);
        run.cols.back = (await act()).row;
        await page.keyboard.press('ContextMenu');
        await page.waitForTimeout(200);
        await page.keyboard.press('Tab');
        await page.waitForTimeout(200);
        run.cols.tabOut = await page.evaluate(() => !COLS_MENU);
        run.cols.tabBack = (await act()).row;
        await page.evaluate(() => colsSwitch(false));
        await page.waitForTimeout(400);
      }
      out.runs.push(run);
      await ctx.close();
    }

    // ---- the portal ----
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `portal-${lang}-${w}`;
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      await ctx.addInitScript(CONTRAST);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
      await page.goto(base + '/');
      await page.fill('#in-name', 'jan');
      await page.fill('#in-pass', pass);
      await page.click('#in-go');
      await page.waitForSelector('#pw-nav, #cp-list', {timeout: 30000});
      await page.waitForTimeout(1500);
      const one = {lang, w};
      one.toast = await page.evaluate(() => { const t = document.getElementById('toast'); return [t.getAttribute('role'), t.getAttribute('aria-live')]; });
      one.dialog = await page.evaluate(() => { const b = document.getElementById('modal-box'); return [b.getAttribute('role'), b.getAttribute('aria-labelledby')]; });
      if (await page.$('#pw-nav [data-view=certs]')) await page.click('#pw-nav [data-view=certs]');
      await page.waitForSelector('#cp-list table', {timeout: 30000});
      await page.waitForTimeout(800);
      one.th = await page.evaluate(() => Math.min(...[...document.querySelectorAll('#cp-list thead th')].filter(t => t.getClientRects().length && t.textContent.trim()).map(__ratio)));
      one.unnamed = await page.evaluate(() => __unnamed(document));
      if (shots) await page.screenshot({path: path.join(shots, `rw4-${tag}.png`)});
      out.portal.push(one);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
