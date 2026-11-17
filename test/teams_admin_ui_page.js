// The pages' half of test/test_teams_admin_ui.py: Settings → Owners and teams as an organisation,
// in Chromium against a real daemon.
//
//   node test/teams_admin_ui_page.js BASE_URL PASSWORD [SHOTS_DIR]
//
// Prints one line of JSON: what was seen (errors on the page, the tree, the team's page, the
// flows - a team made, a member added through the directory, limits set, a team moved, a role's
// capability switched, the access check, a dry run of teams from groups - the read-only
// account's controls, and what overflowed the window at each width).
const { chromium } = require('playwright');

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], overflow: {}};
  const watch = (page) => {
    page.on('pageerror', (e) => out.errors.push(String(e.message || e)));
    page.on('console', (m) => { if (m.type() === 'error') out.errors.push('console: ' + m.text()); });
    page.on('dialog', async (d) => { out.errors.push('browser dialog: ' + d.message()); await d.dismiss(); });
  };
  const signIn = async (name, lang, width) => {
    const ctx = await browser.newContext({viewport: {width, height: width < 500 ? 844 : 900}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
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
  const view = async (page, v) => { await page.click('.tmx-vbtn[data-view="' + v + '"]'); await page.waitForTimeout(300); };
  const team = async (page, name) => {
    await page.evaluate(() => document.getElementById('tmx-expand').click());
    await page.waitForTimeout(150);
    await page.evaluate((n) => { const r = [...document.querySelectorAll('.tmx-row')].find((x) => x.dataset.name === n); r.click(); }, name);
    await page.waitForSelector('.tmx-team[data-team="' + name + '"]', {timeout: 10000});
  };
  const tab = async (page, t) => { await page.click('.tmx-tab[data-tab="' + t + '"]'); await page.waitForTimeout(400); };
  const primary = (page) => page.locator('#modal-foot button.primary').last();
  const modalClosed = (page) => page.waitForSelector('#modal', {state: 'hidden', timeout: 30000});
  const overflow = (page) => page.evaluate(() => {
    const w = document.documentElement.clientWidth, bad = [];
    if (document.documentElement.scrollWidth > w + 1) bad.push('page ' + document.documentElement.scrollWidth + '>' + w);
    document.querySelectorAll('#tmx *').forEach((n) => {
      const r = n.getBoundingClientRect();
      if (!r.width || n.closest('.tmx-tree') && document.querySelector('.tmx-org:not(.drawer-open)') && getComputedStyle(document.querySelector('.tmx-tree')).position === 'fixed') return;
      if (n.closest('.tmx-mx-s, .tmx-tabs, .tmx-views, .tmx-seg, .tmx-tree-s, .tmx-dir-list, .tmx-picklist')) return;
      if (r.right > w + 1 && bad.length < 8) bad.push((n.id || n.className || n.tagName) + ' ' + Math.round(r.right));
    });
    return bad;
  });
  const shot = async (page, name, whole) => { if (shots) { await page.waitForTimeout(350); await page.screenshot({path: shots + '/' + name + '.png', fullPage: !!whole}); } };
  try {
    // ---- a full administrator: the tree, the team's page, the flows ----------------------
    const a = await signIn('tester', 'en', 1400);
    await a.click('#tmx-expand');
    await a.waitForTimeout(200);
    out.treeRows = await a.locator('.tmx-row').count();
    await a.fill('#tmx-q', 'datab');
    await a.waitForTimeout(400);
    out.searchShown = await a.$$eval('.tmx-row', (r) => r.map((x) => x.dataset.name));
    out.searchHit = await a.$$eval('.tmx-row.hit', (r) => r.map((x) => x.dataset.name));
    await a.fill('#tmx-q', '');
    await a.waitForTimeout(300);
    await team(a, 'Web');
    out.crumbs = await a.$$eval('.tmx-crumbs .tmx-crumb', (r) => r.map((x) => x.textContent));
    out.tabs = await a.$$eval('.tmx-tab', (r) => r.map((x) => x.dataset.tab));
    await a.waitForFunction(() => document.querySelector('.tmx-tile[data-tile="failing"] .tmx-tile-v').textContent !== '–', null, {timeout: 15000});
    out.tiles = await a.$$eval('.tmx-tile', (r) => Object.fromEntries(r.map((x) => [x.dataset.tile, x.querySelector('.tmx-tile-v').textContent])));
    // a team made under the one chosen
    await a.click('#tmx-add-team');
    await a.fill('#tm-f-name', 'Web Shop');
    await a.fill('#tm-f-desc', 'the shop and its payment pages');
    await shot(a, 'flow-1-new-team');
    await primary(a).click();
    await modalClosed(a);
    await a.waitForSelector('.tmx-team[data-team="Web Shop"]', {timeout: 15000});
    out.made = true;
    // a member through the directory search
    await tab(a, 'members');
    await a.click('#tmx-addm');
    await a.fill('#tmx-dir-q', 'novak');
    await a.waitForSelector('.tmx-dir-it', {timeout: 15000});
    await a.click('.tmx-dir-it');
    await a.click('.tmx-rchip[data-role="Requester"]');
    await a.click('.tmx-rchip[data-role="Deployer"]');
    await shot(a, 'flow-2-member-dialog');
    await primary(a).click();
    await modalClosed(a);
    await a.waitForSelector('.tmx-mrow[data-who="jnovak@corpnet.loc"]', {timeout: 15000});
    // limits of its own, with what it inherits beside them
    await tab(a, 'limits');
    await a.click('#tmx-setlim');
    await a.waitForSelector('.tmx-prow[data-key="max_days"] .tmx-segb[data-v="on"]', {timeout: 10000});
    out.inheritedHint = await a.locator('.tmx-prow[data-key="suffixes"] .tmx-from').count() > 0;
    await a.click('.tmx-prow[data-key="max_days"] .tmx-segb[data-v="on"]');
    await a.fill('.tmx-prow[data-key="max_days"] .tmx-num', '30');
    await a.click('#tmx-appr-mode .tmx-segb[data-v="always"]');
    await shot(a, 'flow-3-limits');
    await a.click('#tmx-polsave');
    await a.waitForSelector('.tmx-prow.own[data-key="max_days"]', {timeout: 15000});
    // moved under another team, through the picker
    await team(a, 'QA');
    await a.click('#tmx-move');
    await a.click('#tmx-move-list .tmx-tp-it[data-name="Dev"]');
    await shot(a, 'flow-4-move');
    await primary(a).click();
    await modalClosed(a);
    await a.waitForFunction(() => [...document.querySelectorAll('.tmx-crumbs .tmx-crumb')].map((x) => x.textContent).join('/') === 'Group HQ/Europe/Brno/Dev/QA', null, {timeout: 15000});
    // activity
    await team(a, 'Web');
    await tab(a, 'activity');
    await a.waitForSelector('.tmx-tl-it', {timeout: 15000});
    out.activity = await a.locator('.tmx-tl-it').count();
    // the roles' matrix: built-in read only, a custom one switched
    await view(a, 'roles');
    out.builtinBoxes = await a.evaluate(() => {
      const built = (window.ACME_TEAMS && null) || [...document.querySelectorAll('#tmx-matrix th.builtin')].map((t) => t.dataset.role);
      return [...document.querySelectorAll('button.tmx-tick')].filter((b) => built.indexOf(b.dataset.role) >= 0).length;
    });
    await a.click('button.tmx-tick[data-role="Night shift"][data-cap="target.view"]');
    await a.waitForTimeout(1800);
    await shot(a, 'flow-5-roles');
    // the access check of a person nested through two groups
    await view(a, 'access');
    await a.fill('#tmx-ac-q', 'nested@corpnet.cz');
    await a.click('#tmx-ac-go');
    await a.waitForSelector('.tmx-ac-card', {timeout: 20000});
    out.access = await a.$$eval('.tmx-ac-card', (r) => r.map((x) => x.dataset.team));
    out.accessWhy = await a.locator('.tmx-ac-card .tmx-why-l .tmx-from').count() > 0;
    await shot(a, 'flow-6-access');
    // teams from directory groups: the dry run
    await a.click('#tmx-fromgroups');
    await a.fill('#tmx-fg-filter', 'CN=PKI-*');
    await a.locator('#modal-foot button', {hasText: 'Preview'}).click();
    await a.waitForSelector('tr.tmx-fg-row', {timeout: 20000});
    out.dryRun = await a.$$eval('tr.tmx-fg-row', (r) => r.map((x) => x.dataset.cn));
    await shot(a, 'flow-7-from-groups');
    await a.locator('#modal-foot button', {hasText: 'Close'}).click();
    await modalClosed(a);
    // the tags, and what other panes use
    await view(a, 'tags');
    out.tagsTab = await a.locator('#tm-tag-add').count() === 1;
    out.exports = await a.evaluate(() => Object.keys(window.ACME_TEAMS).sort());
    await a.context().close();

    // ---- every width, both languages -------------------------------------------------------
    for (const lang of ['en', 'cs']) {
      for (const width of [1400, 1024, 768, 390]) {
        const p = await signIn('tester', lang, width);
        const key = lang + '-' + width;
        const bad = [];
        await team(p, 'Web');
        await p.waitForTimeout(600);
        bad.push(...await overflow(p));
        await shot(p, key + '-1-overview', width < 800);
        await tab(p, 'members');
        bad.push(...await overflow(p));
        await shot(p, key + '-2-members', width < 800);
        await tab(p, 'limits');
        await p.waitForTimeout(400);
        bad.push(...await overflow(p));
        await shot(p, key + '-3-limits', width < 800);
        await tab(p, 'devices');
        bad.push(...await overflow(p));
        await shot(p, key + '-4-devices', width < 800);
        await view(p, 'roles');
        bad.push(...await overflow(p));
        await shot(p, key + '-5-roles', width < 800);
        await view(p, 'access');
        await p.fill('#tmx-ac-q', 'nested@corpnet.cz');
        await p.click('#tmx-ac-go');
        await p.waitForSelector('.tmx-ac-card', {timeout: 20000});
        bad.push(...await overflow(p));
        await shot(p, key + '-6-access', width < 800);
        if (width === 390) {
          await view(p, 'org');
          await p.click('#tmx-switch');
          await p.waitForTimeout(450);
          out.drawer = await p.evaluate(() => {
            const t = document.querySelector('.tmx-tree').getBoundingClientRect();
            return document.querySelector('.tmx-org').classList.contains('drawer-open') && t.left >= -1 && t.width > 200;
          });
          await shot(p, key + '-7-drawer');
          await p.click('.tmx-drawer-x');
        }
        out.overflow[key] = bad;
        await p.context().close();
      }
    }

    // ---- read only: everything to see, nothing to change -------------------------------------
    const r = await signIn('viewer', 'en', 1400);
    const writes = '#tmx-add-team, #tmx-add-unit, #tmx-edit, #tmx-move, #tmx-del, #tmx-addm, .tmx-medit, .tmx-mdel, '
      + '#tmx-setlim, #tmx-polsave, #tmx-polclear, #tmx-assign, .tmx-dfree, #tmx-role-add, button.tmx-tick, .tmx-role-copy, '
      + '.tmx-role-edit, .tmx-role-del, #tmx-fromgroups, #tm-tag-add, .tmx-pol.edit, #tmx-first';
    const seen = new Set();
    const look = async () => (await r.$$eval(writes, (n) => n.map((x) => x.id || x.className))).forEach((x) => seen.add(x));
    await r.click('#tmx-expand');
    await r.waitForTimeout(200);
    out.roTreeRows = await r.locator('.tmx-row').count();
    await team(r, 'Web');
    for (const t of ['overview', 'members', 'limits', 'devices', 'certs', 'activity']) { await tab(r, t); await look(); }
    await shot(r, 'readonly-limits');
    await view(r, 'roles');
    await look();
    await view(r, 'tags');
    await look();
    out.roWrites = [...seen];
    await r.context().close();
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
