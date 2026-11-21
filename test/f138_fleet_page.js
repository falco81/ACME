// Settings → Agent fleet (1.0.138, fleet.js) in Chromium against a real daemon (test/test_f138_fleet.py
// Pages: daemon + php -S, agents' state, groups, a template and a discovery seeded).
//
//   node test/f138_fleet_page.js BASE_URL PASSWORD
//
// For English and Czech at 1400 and 390 px: the hero (health ring, versions), Groups (cards),
// Agents (rows, choose two: the bulk bar; Compare: the drift popup), Templates, Updates (the rings'
// form and its plan), Not managed (by risk) and its Take over (the preview: what happens, the
// policy lines). Nothing wider than the page; no error on the page. At 1400 in English the policy
// builder opened from a template: its fleet templates. Screenshots into $ACME_TEST_SHOTS.
// Prints one line of JSON: {checks: {name: value}, errors: [...], error?}.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const shots = process.env.ACME_TEST_SHOTS || '';
  const browser = await chromium.launch();
  const out = {checks: {}, errors: []};
  const shot = async (page, name, sel) => {
    if (!shots) return;
    await page.waitForTimeout(250);
    if (sel) { const e = await page.$(sel); if (e) { await e.screenshot({path: shots + '/' + name + '.png'}); return; } }
    await page.screenshot({path: shots + '/' + name + '.png', fullPage: false});
  };
  const fits = (page) => page.evaluate(() => {
    if (document.documentElement.scrollWidth > window.innerWidth + 1) return 'page ' + document.documentElement.scrollWidth;
    const bad = [];
    document.querySelectorAll('#fl-root *').forEach((x) => {
      const r = x.getBoundingClientRect();
      if (!r.width || !x.offsetParent) return;
      if (x.closest('.fl-tabs, .fl-diff, .fl-cmd, .fl-tpl-lines')) return;       /* they scroll by themselves */
      if (r.right > window.innerWidth + 1 || r.left < -1) bad.push((x.className || x.tagName) + ' ' + Math.round(r.left) + '-' + Math.round(r.right));
    });
    const mb = document.getElementById('modal-body');
    if (mb && mb.offsetParent && mb.scrollWidth > mb.clientWidth + 1) bad.push('modal ' + mb.scrollWidth + '>' + mb.clientWidth);
    return bad.length ? bad.slice(0, 4).join('; ') : true;
  });
  const tab = async (page, i) => {
    await page.evaluate((n) => document.querySelectorAll('.fl-tab')[n].click(), i);
    await page.waitForTimeout(500);
    /* the view under the tabs in sight (a phone: the hero is a screen of its own) */
    await page.evaluate(() => { const t = document.querySelector('.fl-tabs'); if (t && window.innerWidth < 700) t.scrollIntoView(); });
  };
  const close = async (page) => {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
    await page.evaluate(() => { const m = document.getElementById('modal'); if (m && !m.hidden && typeof closeModal === 'function') closeModal(true); });
    await page.waitForTimeout(200);
  };
  try {
    for (const [lang, w] of [['en', 1400], ['en', 390], ['cs', 1400], ['cs', 390]]) {
      const tag = lang + w + '_';
      const ctx = await browser.newContext({viewport: {width: w, height: w > 500 ? 940 : 844}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(tag + String(e.message || e)));
      page.on('console', m => { if (m.type() === 'error' && !/favicon|Failed to load resource/.test(m.text())) out.errors.push(tag + 'console: ' + m.text()); });
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(900);
      await page.evaluate(() => { try { localStorage.removeItem('acme.fleet.tab'); } catch (e) { } });
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
      await page.waitForTimeout(300);
      await page.evaluate(() => document.querySelector('#ctl-nav button[data-pane="fleet"]').click());
      await page.waitForFunction(() => document.querySelector('#fl-root .fl-hero'), null, {timeout: 30000});
      await page.waitForTimeout(900);
      out.checks[tag + 'tab'] = await page.evaluate(() => document.querySelector('.fl-tab.on span:not(.fl-ic):not(.fl-tab-n)').textContent);
      out.checks[tag + 'groups'] = await page.evaluate(() => document.querySelectorAll('.fl-group').length);
      out.checks[tag + 'words'] = await page.evaluate(() => document.querySelector('#fl-root').innerText.slice(0, 4000));
      out.checks[tag + 'fits'] = await page.evaluate(() => true);
      let f = await fits(page);
      if (f !== true) out.checks[tag + 'fits'] = 'groups: ' + f;
      await page.evaluate(() => document.querySelector('#pane-fleet').scrollIntoView());
      await shot(page, tag + 'groups');
      await shot(page, tag + 'hero', '.fl-hero');
      // ---- agents: two chosen, the bulk bar, Compare ----
      await tab(page, 1);
      out.checks[tag + 'agents'] = await page.evaluate(() => document.querySelectorAll('.fl-arow:not(.fl-ahead)').length);
      await page.evaluate(() => { const c = document.querySelectorAll('.fl-arow:not(.fl-ahead) input[type=checkbox]'); c[0].click(); c[1].click(); });
      await page.waitForTimeout(300);
      out.checks[tag + 'bulk'] = await page.evaluate(() => document.querySelector('.fl-bulk.on') ? document.querySelectorAll('.fl-bulk .btn').length : 0);
      f = await fits(page);
      if (f !== true && out.checks[tag + 'fits'] === true) out.checks[tag + 'fits'] = 'agents: ' + f;
      await shot(page, tag + 'agents');
      await page.evaluate(() => document.querySelector('.fl-bulk .fl-cmp').click());
      await page.waitForFunction(() => document.querySelector('.fl-dcard') || document.querySelector('.fl-drift-none'), null, {timeout: 20000});
      await page.waitForTimeout(400);
      out.checks[tag + 'drift'] = await page.evaluate(() => !!document.querySelector('.fl-dcard'));
      f = await fits(page);
      if (f !== true && out.checks[tag + 'fits'] === true) out.checks[tag + 'fits'] = 'drift: ' + f;
      await shot(page, tag + 'drift', '#modal-box');
      await close(page);
      // ---- templates ----
      await tab(page, 2);
      out.checks[tag + 'templates'] = await page.evaluate(() => document.querySelectorAll('.fl-tpl').length);
      f = await fits(page);
      if (f !== true && out.checks[tag + 'fits'] === true) out.checks[tag + 'fits'] = 'templates: ' + f;
      await shot(page, tag + 'templates');
      // ---- updates ----
      await tab(page, 3);
      await page.waitForFunction(() => document.querySelector('.fl-plan .fl-plan-r'), null, {timeout: 20000}).catch(() => {});
      out.checks[tag + 'plan'] = await page.evaluate(() => document.querySelectorAll('.fl-plan .fl-plan-r').length);
      f = await fits(page);
      if (f !== true && out.checks[tag + 'fits'] === true) out.checks[tag + 'fits'] = 'updates: ' + f;
      await shot(page, tag + 'updates');
      // ---- not managed, and the take-over ----
      await tab(page, 4);
      await page.waitForFunction(() => document.querySelector('.fl-um-r'), null, {timeout: 20000});
      out.checks[tag + 'unmanaged'] = await page.evaluate(() => document.querySelectorAll('.fl-um-r').length);
      f = await fits(page);
      if (f !== true && out.checks[tag + 'fits'] === true) out.checks[tag + 'fits'] = 'unmanaged: ' + f;
      await shot(page, tag + 'unmanaged');
      await page.evaluate(() => document.querySelector('.fl-um-a .btn.primary').click());
      await page.waitForFunction(() => document.querySelector('.fl-to-g'), null, {timeout: 20000});
      await page.waitForTimeout(400);
      out.checks[tag + 'takeover'] = await page.evaluate(() => document.querySelectorAll('.fl-to-s').length >= 4 && document.querySelectorAll('.fl-to-it').length >= 3);
      f = await fits(page);
      if (f !== true && out.checks[tag + 'fits'] === true) out.checks[tag + 'fits'] = 'takeover: ' + f;
      await shot(page, tag + 'takeover', '#modal-box');
      await close(page);
      // ---- the group's editor (wide only) ----
      if (w === 1400) {
        await tab(page, 0);
        await page.evaluate(() => document.querySelector('.fl-group .fl-edit').click());
        await page.waitForFunction(() => document.querySelector('.fl-mem-r'), null, {timeout: 10000});
        await shot(page, tag + 'group_edit', '#modal-box');
        await close(page);
      }
      // ---- the builder from a template: its fleet templates ----
      if (lang === 'en' && w === 1400) {
        await tab(page, 2);
        await page.evaluate(() => Array.from(document.querySelectorAll('.fl-tpl')).filter(c => /nginx web/.test(c.textContent))[0].querySelectorAll('.btn')[1].click());
        await page.waitForTimeout(600);
        const pick = await page.$('#modal-foot .btn.primary');
        if (pick && await page.evaluate(() => /Open/.test(document.querySelector('#modal-foot .btn.primary').textContent))) { await pick.click(); }
        await page.waitForFunction(() => document.querySelector('.pb-fleet .pb-ftpl'), null, {timeout: 30000});
        await page.waitForTimeout(500);
        out.checks.builder_fleet = await page.evaluate(() => document.querySelectorAll('.pb-fleet .pb-ftpl').length);
        out.checks.builder_from = await page.evaluate(() => document.querySelector('.pb-seg-b.on').textContent);
        await page.evaluate(() => document.querySelector('.pb-fleet').scrollIntoView());
        await shot(page, 'builder_fleet', '#modal-box');
        await close(page);
      }
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
