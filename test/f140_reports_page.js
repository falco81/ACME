// The pages' half of test/test_f140_reports.py: Settings → Reports and a team's Digest tab
// (1.0.140) in Chromium - in English and Czech, 1400 and 390 px wide.
//
//   node test/f140_reports_page.js BASE_URL PASSWORD [SHOTS_DIR]
//
// Prints one line of JSON: what was seen ({errors: [...]} always there).
const { chromium } = require('playwright');

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], overflow: {}, english: []};
  const watch = (page) => {
    page.on('pageerror', (e) => out.errors.push(String(e.message || e)));
    page.on('console', (m) => {
      if (m.type() !== 'error') return;
      const t = m.text();
      if (/status of 40[39]/.test(t)) return;       // a refusal the step looks for
      out.errors.push('console: ' + t);
    });
    page.on('dialog', async (d) => { out.errors.push('browser dialog: ' + d.message()); await d.dismiss(); });
  };
  const admin = async (name, lang, width) => {
    const ctx = await browser.newContext({viewport: {width, height: width < 500 ? 844 : 900}, deviceScaleFactor: 1, acceptDownloads: true});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    watch(page);
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(500);
    return page;
  };
  const reports = async (page) => {
    await page.goto(base + '/admin/index.php#settings/reports');
    await page.waitForSelector('#rpt-host .rpt-bar', {timeout: 30000});
    await page.waitForTimeout(500);
  };
  const teamTab = async (page, team) => {
    await page.goto(base + '/admin/index.php#settings/teams');
    await page.waitForSelector('#tmx .tmx-vbtn', {timeout: 30000});
    await page.waitForTimeout(400);
    if (await page.$('.tmx-vbtn[data-view="org"]')) { await page.click('.tmx-vbtn[data-view="org"]'); await page.waitForTimeout(600); }
    await page.evaluate(() => { const e = document.getElementById('tmx-expand'); if (e) e.click(); });
    await page.waitForTimeout(150);
    await page.evaluate((n) => { const r = [...document.querySelectorAll('.tmx-row')].find((x) => x.dataset.name === n); if (r) r.click(); }, team);
    await page.waitForSelector('.tmx-team[data-team="' + team + '"]', {timeout: 10000});
    await page.click('.tmx-tab[data-tab="digest"]');
    await page.waitForSelector('.rpt-dg-hero', {timeout: 15000});
    await page.waitForTimeout(400);
  };
  const shot = async (page, name, full) => {
    if (!shots) return;
    await page.waitForTimeout(300);
    await page.screenshot({path: shots + '/' + name + '.png', fullPage: full !== false});
  };
  const closeModal = async (page) => { await page.keyboard.press('Escape'); await page.waitForTimeout(350); };
  const overflow = (page) => page.evaluate(() => {
    const w = document.documentElement.clientWidth, bad = [];
    if (document.documentElement.scrollWidth > w + 1) bad.push('page ' + document.documentElement.scrollWidth + '>' + w);
    document.querySelectorAll('.rpt *, .rpt-dg *, #modal .rpt-dlg *').forEach((n) => {
      const r = n.getBoundingClientRect();
      if (!r.width) return;
      if (n.closest('.rpt-pscroll, .tmx-seg, .tmx-tabs')) return;
      if (r.right > w + 1 && bad.length < 8) bad.push((n.id || n.className || n.tagName) + ' ' + Math.round(r.right));
    });
    return bad;
  });
  const english = (page) => page.evaluate(() => {
    const EN = /(?<!\p{L})(the|of|and|is|for|with|runs?|preview|digest|weekly|monthly|daily|every|team|teams|send|sent|next|last|never|nothing|what|who|mailed|kept|hand|new|change|delete)(?!\p{L})/iu;
    const got = [];
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walk.nextNode())) {
      const t = n.nodeValue.trim();
      if (!t || !EN.test(t)) continue;
      const p = n.parentElement;
      if (!p || !p.closest('.rpt, .rpt-dg, #modal .rpt-dlg, #pane-reports .ctl-head')) continue;
      if (p.closest('[data-no-i18n], .mono, code, pre, script, style, #toast, [hidden], .rpt-paper, iframe')) continue;
      const r = p.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      got.push(t.slice(0, 100));
    }
    return Array.from(new Set(got)).slice(0, 40);
  });
  try {
    // ---- a full administrator, English, wide: nothing yet, a report made, previewed, run ----
    const p = await admin('tester', 'en', 1400);
    await reports(p);
    out.emptyKinds = await p.locator('.rpt-empty .rpt-kind').count();
    await shot(p, 'reports-empty-1400-en');
    await p.click('.rpt-empty .rpt-kind[data-kind="expiry"]');
    await p.waitForSelector('#rpt-f-name', {timeout: 10000});
    await p.fill('#rpt-f-name', 'Web - ending soon');
    await p.click('#rpt-f-scope .tmx-segb[data-v="some"]');
    await p.click('#rpt-f-teams .rpt-tog[data-team="Web"]');
    await p.click('#rpt-f-every .tmx-segb[data-v="monthly"]');
    await p.selectOption('#rpt-f-hour', '6');
    await p.fill('#rpt-f-to', 'boss@example.com');
    await shot(p, 'reports-edit-1400-en', false);
    await p.click('#modal-foot button:has-text("Save")');
    await p.waitForSelector('.rpt-card[data-report="Web - ending soon"]', {timeout: 15000});
    out.saved = true;
    // a second, for every team
    await p.click('#rpt-new');
    await p.waitForSelector('#rpt-f-name');
    await p.fill('#rpt-f-name', 'Certificate inventory');
    await p.click('#modal .rpt-kind[data-kind="inventory"]');
    await p.click('#modal-foot button:has-text("Save")');
    await p.waitForSelector('.rpt-card[data-report="Certificate inventory"]', {timeout: 15000});
    await p.click('.rpt-card[data-report="Web - ending soon"] .rpt-preview');
    await p.waitForSelector('#modal .rpt-paper', {timeout: 15000});
    out.previewRows = await p.locator('#modal .rpt-ptable tbody tr').count();
    await shot(p, 'reports-preview-1400-en', false);
    await closeModal(p);
    await p.click('.rpt-card[data-report="Web - ending soon"] .rpt-run');
    await p.waitForSelector('#rpt-run-send', {timeout: 10000});
    await p.click('#modal-foot button:has-text("Run it")');
    await p.waitForSelector('#modal .rpt-runlist', {timeout: 30000});
    await shot(p, 'reports-runs-1400-en', false);
    const [dl] = await Promise.all([p.waitForEvent('download', {timeout: 20000}),
                                    p.click('#modal .rpt-run.fresh .rpt-dl-pdf')]);
    const fs = require('fs');
    const path = await dl.path();
    out.pdf = fs.readFileSync(path).slice(0, 5).toString() === '%PDF-';
    await closeModal(p);
    await p.waitForTimeout(800);
    await shot(p, 'reports-cards-1400-en');
    out.overflow['reports-1400-en'] = await overflow(p);
    // ---- the team's digest ----
    await teamTab(p, 'Web');
    out.digestTab = true;
    await shot(p, 'digest-tab-1400-en');
    await p.click('#rpt-dg-set');
    await p.waitForSelector('#rpt-dg-members', {timeout: 10000});
    await shot(p, 'digest-edit-1400-en', false);
    await p.click('#modal-foot button:has-text("Show the preview")');
    await p.waitForSelector('#modal iframe.rpt-frame', {timeout: 15000});
    out.digestFrame = (await p.$eval('#modal iframe.rpt-frame', (f) => (f.srcdoc || '').length)) > 1000;
    await p.waitForTimeout(500);
    await shot(p, 'digest-preview-1400-en', false);
    await closeModal(p);
    await p.context().close();
    // ---- Czech and English, wide and 390 px ----
    for (const [lang, w] of [['cs', 1400], ['cs', 390], ['en', 390]]) {
      const q = await admin('tester', lang, w);
      await reports(q);
      out.overflow['reports-' + lang + '-' + w] = await overflow(q);
      if (lang === 'cs') out.english = out.english.concat(await english(q));
      await shot(q, 'reports-cards-' + w + '-' + lang);
      await q.click('.rpt-card[data-report="Web - ending soon"] .rpt-preview');
      await q.waitForSelector('#modal .rpt-paper', {timeout: 15000});
      await q.waitForTimeout(400);
      out.overflow['preview-' + lang + '-' + w] = await overflow(q);
      if (lang === 'cs') out.english = out.english.concat(await english(q));
      await shot(q, 'reports-preview-' + w + '-' + lang, false);
      await closeModal(q);
      await q.click('.rpt-card[data-report="Web - ending soon"] .rpt-edit');
      await q.waitForSelector('#rpt-f-name', {timeout: 10000});
      out.overflow['edit-' + lang + '-' + w] = await overflow(q);
      if (lang === 'cs') out.english = out.english.concat(await english(q));
      await shot(q, 'reports-edit-' + w + '-' + lang, false);
      await closeModal(q);
      await teamTab(q, 'Web');
      out.overflow['digest-' + lang + '-' + w] = await overflow(q);
      if (lang === 'cs') out.english = out.english.concat(await english(q));
      await shot(q, 'digest-tab-' + w + '-' + lang);
      await q.click('#rpt-dg-set');
      await q.waitForSelector('#rpt-dg-members', {timeout: 10000});
      out.overflow['digest-edit-' + lang + '-' + w] = await overflow(q);
      if (lang === 'cs') out.english = out.english.concat(await english(q));
      await shot(q, 'digest-edit-' + w + '-' + lang, false);
      await closeModal(q);
      await q.context().close();
    }
    out.english = Array.from(new Set(out.english));
    // ---- a certificate administrator of Web: its report only, nothing to change ----
    const c = await admin('cm', 'en', 1400);
    await reports(c);
    out.cmNew = await c.locator('#rpt-new').count();
    out.cmCards = await c.locator('.rpt-card').count();
    out.cmEdit = await c.locator('.rpt-card .rpt-edit').count();
    await shot(c, 'reports-certadmin-1400-en');
    await c.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
