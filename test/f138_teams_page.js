// The pages' half of test/test_f138_teams.py: the governance of teams (1.0.138) in Chromium -
// the administration's views (Who may, Health, Requests, Templates), a team's Governance tab,
// view as, a read-only account, the portal's Health and Access, the portal viewed as a member.
//
//   node test/f138_teams_page.js BASE_URL PASSWORD [SHOTS_DIR]
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
      // a write refused while viewing as somebody is the point of that step (403 in the console)
      if (/status of 40[13]/.test(t)) return;
      out.errors.push('console: ' + t);
    });
    page.on('dialog', async (d) => { out.errors.push('browser dialog: ' + d.message()); await d.dismiss(); });
  };
  const context = async (lang, width) => {
    const ctx = await browser.newContext({viewport: {width, height: width < 500 ? 844 : 900}, deviceScaleFactor: 1});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    return ctx;
  };
  const admin = async (name, lang, width) => {
    const ctx = await context(lang, width);
    const page = await ctx.newPage();
    watch(page);
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(500);
    await page.goto(base + '/admin/index.php#settings/teams');
    await page.waitForSelector('#tmx .tmx-vbtn', {timeout: 30000});
    await page.waitForTimeout(400);
    return page;
  };
  const portal = async (name, lang, width) => {
    const ctx = await context(lang, width);
    const page = await ctx.newPage();
    watch(page);
    await page.goto(base + '/');
    await page.fill('#in-name', name);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    await page.waitForSelector('#pw-nav .pw-navi', {timeout: 30000});
    await page.waitForTimeout(600);
    return page;
  };
  const view = async (page, v) => { await page.click('.tmx-vbtn[data-view="' + v + '"]'); await page.waitForTimeout(1200); };
  const team = async (page, name) => {
    await page.evaluate(() => { const e = document.getElementById('tmx-expand'); if (e) e.click(); });
    await page.waitForTimeout(150);
    await page.evaluate((n) => { const r = [...document.querySelectorAll('.tmx-row')].find((x) => x.dataset.name === n); r.click(); }, name);
    await page.waitForSelector('.tmx-team[data-team="' + name + '"]', {timeout: 10000});
  };
  const tab = async (page, t) => { await page.click('.tmx-tab[data-tab="' + t + '"]'); await page.waitForTimeout(1200); };
  const go = async (page, hash) => { await page.evaluate((h) => { location.hash = '#' + h; }, hash); await page.waitForTimeout(1600); };
  const closeModal = async (page) => { await page.keyboard.press('Escape'); await page.waitForTimeout(300); };
  const shot = async (page, name) => {
    if (!shots) return;
    await page.waitForTimeout(300);
    await page.screenshot({path: shots + '/' + name + '.png', fullPage: true});
  };
  const overflow = (page) => page.evaluate(() => {
    const w = document.documentElement.clientWidth, bad = [];
    if (document.documentElement.scrollWidth > w + 1) bad.push('page ' + document.documentElement.scrollWidth + '>' + w);
    document.querySelectorAll('.tmg-whomay *, .tmg-health *, .tmg-inbox *, .tmg-tpl *, .tmg-ggrid *, .pwg-health *, .pwg-acc *, .tmg-viewas *, .pwg-viewas *').forEach((n) => {
      const r = n.getBoundingClientRect();
      if (!r.width) return;
      if (n.closest('.tmx-mx-s, .pwg-mx-s, .tmx-views, .tmx-tabs, .tmx-seg, .tmg-ctable-s')) return;
      if (r.right > w + 1 && bad.length < 8) bad.push((n.id || n.className || n.tagName) + ' ' + Math.round(r.right));
    });
    return bad;
  });
  const english = (page) => page.evaluate(() => {
    const EN = /(?<!\p{L})(the|of|and|is|for|with|your|you|it|not|all|team|teams|who|may|health|access|review|reviews|requests?|roles?|temporary|members?|nothing|ask|limits|template|templates|running|failed|weak|keys|quota|waiting|approve|decline|show|confirm)(?!\p{L})/iu;
    const got = [];
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walk.nextNode())) {
      const t = n.nodeValue.trim();
      if (!t || !EN.test(t)) continue;
      const p = n.parentElement;
      if (!p || !p.closest('.tmg-whomay, .tmg-health, .tmg-inbox, .tmg-tpl, .tmg-ggrid, .tmg-hstrip, .pwg-health, .pwg-acc, .tmg-viewas, .pwg-viewas, #modal')) continue;
      if (p.closest('[data-no-i18n], .mono, code, pre, script, style, #toast, [hidden], .tmx-cap, .tmx-mx-cid')) continue;
      const r = p.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      got.push(t.slice(0, 100));
    }
    return Array.from(new Set(got)).slice(0, 40);
  });
  try {
    // ---- the portal first: anna (a Requester of Web with a request waiting) ----------------
    const p = await portal('anna', 'en', 1400);
    await go(p, 'access/Web');
    out.portalAsk = !!(await p.$('#pwg-ask'));
    out.portalMine = await p.locator('#pwg-elev .pwg-e').count();
    await shot(p, 'portal-access-1400-en');
    await p.click('#pwg-ask');
    await p.waitForSelector('#pwg-ask-roles .pw-pill', {timeout: 10000});
    await shot(p, 'portal-ask-1400-en');
    await closeModal(p);
    await go(p, 'health/*');
    out.portalHealth = await p.locator('.pwg-hcard').count();
    await shot(p, 'portal-health-1400-en');
    out.overflow['portal-1400'] = await overflow(p);
    await p.context().close();
    for (const [lang, w] of [['cs', 390], ['en', 390], ['cs', 1024]]) {
      const q = await portal('anna', lang, w);
      await go(q, 'access/Web');
      out.overflow['portal-access-' + lang + '-' + w] = await overflow(q);
      await shot(q, 'portal-access-' + w + '-' + lang);
      if (lang === 'cs') out.english.push(...(await english(q)).map((t) => 'portal access: ' + t));
      await go(q, 'health/*');
      out.overflow['portal-health-' + lang + '-' + w] = await overflow(q);
      await shot(q, 'portal-health-' + w + '-' + lang);
      if (lang === 'cs') out.english.push(...(await english(q)).map((t) => 'portal health: ' + t));
      await q.context().close();
    }

    // ---- a full administrator --------------------------------------------------------------
    const a = await admin('tester', 'en', 1400);
    out.views = await a.$$eval('.tmx-vbtn', (r) => r.map((x) => x.dataset.view));
    await team(a, 'Web');
    out.tabs = await a.$$eval('.tmx-tab', (r) => r.map((x) => x.dataset.tab));
    await a.waitForSelector('.tmg-hstrip .tmg-ring', {timeout: 15000});
    await shot(a, 'admin-overview-health-1400-en');
    await tab(a, 'gov');
    await a.waitForSelector('#tmg-g-review .tmg-rvcard, #tmg-g-review-start', {timeout: 15000});
    await shot(a, 'admin-governance-1400-en');
    await a.click('#tmg-g-sod-edit');
    await a.waitForSelector('#tmg-sod-pairs', {timeout: 10000});
    await shot(a, 'admin-sod-edit-1400-en');
    await closeModal(a);
    await a.click('#tmg-g-notify-edit');
    await a.waitForSelector('#tmg-n-teams', {timeout: 10000});
    out.hookValueShown = await a.$eval('#tmg-n-teams', (i) => i.value);
    await shot(a, 'admin-notify-edit-1400-en');
    await closeModal(a);
    // who may: a team, a cell's why; the reverse
    await view(a, 'whomay');
    await a.click('#tmg-wm-mode .tmx-segb[data-v="team"]');
    await a.selectOption('#tmg-wm-team', 'Web');
    await a.click('#tmg-wm-go');
    await a.waitForSelector('.tmg-cell', {timeout: 15000});
    out.matrixCells = await a.locator('.tmg-cell').count();
    await a.locator('.tmg-cell').first().click();
    await a.waitForTimeout(300);
    out.whyShown = (await a.locator('#tmg-why .tmx-why-l').count()) > 0;
    await shot(a, 'admin-whomay-team-1400-en');
    await a.click('#tmg-wm-mode .tmx-segb[data-v="cap"]');
    await a.selectOption('#tmg-wm-cap', 'cert.renew');
    await a.selectOption('#tmg-wm-cteam', 'Web');
    await a.click('#tmg-wm-go');
    await a.waitForSelector('#tmg-wc-list .tmg-wc-row', {timeout: 15000});
    out.whoCan = await a.$$eval('#tmg-wc-list .tmg-wc-row', (r) => r.map((x) => x.dataset.who));
    await shot(a, 'admin-whocan-1400-en');
    await a.click('#tmg-wm-mode .tmx-segb[data-v="person"]');
    await a.fill('#tmg-wm-who', 'local:anna');
    await a.click('#tmg-wm-go');
    await a.waitForSelector('.tmg-cell', {timeout: 15000});
    await shot(a, 'admin-whomay-person-1400-en');
    // health
    await view(a, 'health');
    await a.waitForSelector('.tmg-hcard', {timeout: 15000});
    out.healthCards = await a.locator('.tmg-hcard').count();
    await shot(a, 'admin-health-1400-en');
    await a.click('.tmg-hcard[data-team="Web"]');
    await a.waitForSelector('.tmg-hlist-it, .tmg-hdlg .tmx-empty', {timeout: 15000});
    await shot(a, 'admin-health-detail-1400-en');
    await closeModal(a);
    // requests: anna's role approved, a member of the review confirmed
    await view(a, 'gov');
    await a.waitForSelector('#tmg-todo .tmg-e-ok', {timeout: 15000});
    await shot(a, 'admin-requests-1400-en');
    const id = await a.$eval('#tmg-todo .tmg-erow', (r) => r.dataset.id);
    await a.click('#tmg-todo .tmg-e-ok');
    await a.waitForSelector('#tmg-e-why', {timeout: 10000});
    await a.fill('#tmg-e-why', 'for tonight');
    await a.locator('#modal-foot button.primary').last().click();
    await a.waitForSelector('#modal', {state: 'hidden', timeout: 30000});
    await a.waitForTimeout(1200);
    out.approved = !(await a.$('#tmg-todo .tmg-erow[data-id="' + id + '"]'));
    await a.click('#tmg-reviews .tmg-rvcard');
    await a.waitForSelector('#tmg-rv-list .tmg-rv-keep', {timeout: 10000});
    await shot(a, 'admin-review-1400-en');
    const before = await a.locator('#tmg-rv-list .tmg-rv-keep').count();
    await a.locator('#tmg-rv-list .tmg-rv-keep').first().click();
    await a.waitForSelector('#modal', {state: 'hidden', timeout: 30000});
    await a.waitForTimeout(800);
    await a.click('#tmg-reviews .tmg-rvcard');
    await a.waitForSelector('#tmg-rv-list', {timeout: 10000});
    out.reviewConfirmed = (await a.locator('#tmg-rv-list .tmg-rv-keep').count()) === before - 1;
    await closeModal(a);
    // templates and the CSV import's preview
    await view(a, 'templates');
    await a.waitForSelector('.tmg-tcard', {timeout: 15000});
    await shot(a, 'admin-templates-1400-en');
    await a.click('#tmg-csv');
    await a.waitForSelector('#tmg-csv-text', {timeout: 10000});
    await a.fill('#tmg-csv-text', 'name,parent,kind,template\nPlant Brno,Europe,unit,Plant\nLine A,Plant Brno,team,\nBroken,Nowhere,team,\n');
    await a.locator('#modal-foot button', {hasText: /Preview|Náhled/}).click();
    await a.waitForSelector('#tmg-csv-prev tbody tr', {timeout: 15000});
    out.csvRows = await a.locator('#tmg-csv-prev tbody tr').count();
    await shot(a, 'admin-csv-1400-en');
    await closeModal(a);
    // view as anna: the banner, a write refused, stopped
    await view(a, 'org');
    await team(a, 'Web');
    await tab(a, 'members');
    await a.click('.tmx-mrow[data-who="local:anna"] .tmg-mview');
    await a.waitForSelector('#tmg-va-admin', {timeout: 10000});
    await shot(a, 'admin-viewas-choose-1400-en');
    await Promise.all([a.waitForNavigation({timeout: 30000}), a.click('#tmg-va-admin')]);
    await a.waitForSelector('#tmg-viewas', {timeout: 20000});
    out.viewAsBanner = true;
    out.viewAsRefused = await a.evaluate(() => api('teams/save', {name: 'Sneaky'}).then(() => 'went through', (e) => String(e.message || e)));
    await a.goto(base + '/admin/index.php#settings/teams');
    await a.waitForSelector('#tmg-viewas', {timeout: 20000});
    await a.waitForTimeout(800);
    await shot(a, 'admin-viewas-banner-1400-en');
    out.viewAsWrites = await a.$$eval('#tmx-edit, #tmx-del, #tmx-addm', (r) => r.length);
    await Promise.all([a.waitForNavigation({timeout: 30000}), a.click('#tmg-viewas-stop')]);
    await a.waitForTimeout(1200);
    out.bannerAfterStop = !!(await a.$('#tmg-viewas'));
    // the portal as anna, from the administration
    const link = await a.evaluate(() => api('teams/view_as_portal', {who: 'local:anna'}).then((d) => d.url));
    const pc = await context('en', 1400);
    const pv = await pc.newPage();
    watch(pv);
    await pv.goto(base + link);
    await pv.waitForSelector('#pwg-viewas', {timeout: 30000});
    out.portalViewAs = true;
    await shot(pv, 'portal-viewas-1400-en');
    await pv.click('#pwg-viewas-stop');
    await pv.waitForTimeout(1500);
    await pc.close();

    // ---- widths and Czech ----------------------------------------------------------------
    for (const [lang, w] of [['en', 1024], ['en', 768], ['en', 390], ['cs', 1400], ['cs', 390]]) {
      const b = await admin('tester', lang, w);
      await team(b, 'Web');
      await tab(b, 'gov');
      await b.waitForTimeout(800);
      out.overflow['gov-' + lang + '-' + w] = await overflow(b);
      await shot(b, 'admin-governance-' + w + '-' + lang);
      if (lang === 'cs') out.english.push(...(await english(b)).map((t) => 'governance: ' + t));
      for (const v of ['whomay', 'health', 'gov', 'templates']) {
        await view(b, v);
        if (v === 'whomay') {
          await b.click('#tmg-wm-mode .tmx-segb[data-v="team"]');
          await b.selectOption('#tmg-wm-team', 'Web');
          await b.click('#tmg-wm-go');
          await b.waitForSelector('.tmg-cell', {timeout: 15000});
          await b.locator('.tmg-cell').first().click();
        }
        await b.waitForTimeout(900);
        out.overflow[v + '-' + lang + '-' + w] = await overflow(b);
        await shot(b, 'admin-' + v + '-' + w + '-' + lang);
        if (lang === 'cs') out.english.push(...(await english(b)).map((t) => v + ': ' + t));
      }
      await b.context().close();
    }

    // ---- a read-only account: everything to see, nothing to change --------------------------
    const r = await admin('viewer', 'en', 1400);
    out.roViews = await r.$$eval('.tmx-vbtn', (x) => x.map((y) => y.dataset.view));
    await team(r, 'Web');
    await tab(r, 'gov');
    await r.waitForTimeout(800);
    const writes = async () => r.$$eval('#tmg-g-review-edit, #tmg-g-jit-edit, #tmg-g-sod-edit, #tmg-g-notify-edit, #tmg-g-notify-try, #tmg-csv, #tmg-tpl-from, .tmg-tpl-make, .tmg-mview, #tmg-g-review-start, .tmg-va-admin',
      (x) => x.map((y) => y.id || y.className));
    out.roWrites = await writes();
    await view(r, 'templates');
    await r.waitForTimeout(800);
    out.roWrites = out.roWrites.concat(await writes());
    await shot(r, 'readonly-templates-1400-en');
    await r.context().close();
  } catch (e) {
    out.error = String((e && e.stack) || e);
  }
  out.english = Array.from(new Set(out.english)).slice(0, 60);
  await browser.close();
  console.log(JSON.stringify(out));
})();
