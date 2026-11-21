// The pages' half of test/test_f138_ctxmenu.py: the right button's menu, the acme clipboard,
// picking rows and the command palette (1.0.138), in Chromium against a real daemon.
//
//   node test/f138_ctxmenu_page.js BASE_URL PASSWORD
//
// In English and Czech, at 1400 and 390 px. Prints one line of JSON; F138_SHOTS=dir: screenshots.
const { chromium } = require('playwright');
const path = require('path');

const SHOTS = process.env.F138_SHOTS || '';

function inPage() {
  // English left in the menu, the palette, the dock or one of our dialogs on the Czech page
  const EN = /(?<!\p{L})(the|and|of|is|it|for|with|not|may|this|its|what|who|from|are|copy|paste|open|select|row|rows|clone|filter|leave|show|renew|deploy|delete|edit|them|now|new|actions|clipboard|selected|done|failed|cancel|close|find|anything|recent|page|certificate|target|team)(?!\p{L})/iu;
  const out = {english: [], hscroll: 0};
  for (const w of document.querySelectorAll('.cxm, .cxp, .cxm-dock, #modal-box')) {
    if (w.id === 'modal-box' && (document.getElementById('modal').hidden || !w.querySelector('.cxb, .cxc'))) continue;
    const tw = document.createTreeWalker(w, NodeFilter.SHOW_TEXT);
    let t;
    while ((t = tw.nextNode())) {
      const p = t.parentElement;
      if (!p || !t.textContent.trim() || p.closest('[data-no-i18n], .mono, kbd, input, option')) continue;
      if (EN.test(t.textContent)) out.english.push(t.textContent.trim().slice(0, 80));
    }
    for (const n of w.querySelectorAll('[placeholder], [aria-label]')) {
      for (const a of ['placeholder', 'aria-label']) { const v = n.getAttribute(a); if (v && EN.test(v) && !/^[\w.+-]+@[\w.-]+$/.test(v)) out.english.push(a + ': ' + v); }
    }
  }
  out.hscroll = document.scrollingElement.scrollWidth - innerWidth;
  return out;
}

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: [], ro: null};
  const shot = async (page, name) => { if (SHOTS) await page.screenshot({path: path.join(SHOTS, name + '.png')}); };
  const signIn = async (lang, w, who) => {
    const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], {origin: base});
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(lang + w + ': ' + String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', who || 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(1200);
    return {ctx, page};
  };
  const rclick = async (page, loc) => {
    await loc.evaluate(e => e.scrollIntoView({block: 'center'}));
    await page.waitForTimeout(150);
    const bx = await loc.boundingBox();
    await page.mouse.click(bx.x + Math.min(30, bx.width / 2), bx.y + bx.height / 2, {button: 'right'});
    await page.waitForTimeout(300);
  };
  const items = page => page.$$eval('.cxm:not([hidden]) .cxm-i', n => n.map(x => (x.querySelector('.cxm-l') || x).textContent.trim()));
  const pick = async (page, sel) => { await page.click(sel); await page.waitForTimeout(400); };
  const byIcon = (key) => `.cxm:not(.cxm-sub) .cxm-i:has(.cxm-l) >> nth=0`;
  // an item of the menu by its English words, whatever language it is shown in
  const item = async (page, english, sub) => {
    const got = await itemTry(page, english, sub);
    if (!got) throw new Error('no item "' + english + '" in ' + JSON.stringify(await items(page)));
    return got;
  };
  const itemTry = async (page, english, sub) => page.evaluate(([en, sub]) => {
    const want = (window.I18N && I18N.on && typeof i18nText === 'function' ? (i18nText(en) || en) : en).trim();
    const list = [...document.querySelectorAll((sub ? '.cxm-sub' : '.cxm:not(.cxm-sub)') + ' .cxm-i')];
    const n = list.find(x => { const l = x.querySelector('.cxm-l'); return l && l.textContent.trim().startsWith(want); });
    if (!n) return false;
    n.click();
    return true;
  }, [english, !!sub]);

  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `${lang}-${w}`;
      const {ctx, page} = await signIn(lang, w);
      const run = {lang, w, english: [], hscroll: []};
      const check = async (where) => { const c = await page.evaluate(inPage); c.english.forEach(x => run.english.push(where + ': ' + x)); if (c.hscroll > 0) run.hscroll.push(where + ' ' + c.hscroll); };
      await page.evaluate(() => showTab('certs'));
      await page.waitForSelector('#ct-table tbody tr');
      await page.waitForTimeout(500);
      const rows = page.locator('#ct-table tbody tr');
      // the menu of a row, by the mouse
      await rclick(page, rows.nth(0).locator('td').nth(1));
      run.menu = await page.$$eval('.cxm', n => n.length);
      run.role = await page.$eval('.cxm', n => n.getAttribute('role'));
      run.items = (await items(page)).length;
      run.head = await page.$eval('.cxm-head b', n => n.textContent);
      await check('menu');
      await shot(page, `menu-${tag}`);
      // copy the cell
      run.copiedCell = await item(page, 'Copy');
      await page.waitForTimeout(300);
      run.clipCell = await page.evaluate(() => navigator.clipboard.readText().catch(() => ''));
      // the Copy sub-menu: the row as JSON, never a secret
      await rclick(page, rows.nth(0).locator('td').nth(1));
      await page.locator('.cxm:not(.cxm-sub) .cxm-i[aria-haspopup]').first().click();
      await page.waitForTimeout(400);
      run.sub = await page.$$eval('.cxm-sub', n => n.length);
      await check('sub');
      await shot(page, `copy-${tag}`);
      await item(page, 'As JSON', true);
      await page.waitForTimeout(300);
      run.json = await page.evaluate(() => navigator.clipboard.readText().catch(() => ''));
      // keyboard: arrows, Esc returns the focus to the row
      await rows.nth(1).focus();
      await page.keyboard.press('Shift+F10');
      await page.waitForTimeout(300);
      run.kbOpen = await page.$$eval('.cxm', n => n.length);
      run.kbFocusInMenu = await page.evaluate(() => !!document.activeElement.closest('.cxm'));
      await page.keyboard.press('ArrowDown');
      run.kbMoved = await page.evaluate(() => document.activeElement.classList.contains('cxm-i'));
      await page.keyboard.press('Escape');
      await page.waitForTimeout(200);
      run.kbClosed = await page.$$eval('.cxm', n => n.length);
      run.kbBack = await page.evaluate(() => document.activeElement.tagName);
      // Shift + the right button, and a box to type in: the browser's own
      const bx = await rows.nth(0).boundingBox();
      await page.keyboard.down('Shift');
      await page.mouse.click(bx.x + 40, bx.y + 10, {button: 'right'});
      await page.keyboard.up('Shift');
      run.shiftMenu = await page.$$eval('.cxm', n => n.length);
      const q = await page.locator('#ct-q').boundingBox();
      await page.mouse.click(q.x + 20, q.y + 10, {button: 'right'});
      run.inputMenu = await page.$$eval('.cxm', n => n.length);
      await page.keyboard.press('Escape');
      // editing the columns: the column menu as always, never ours
      await page.evaluate(() => colsEditing(true));
      await rclick(page, rows.nth(0).locator('td').nth(1));
      run.colsMenu = await page.$$eval('.cols-menu', n => n.length);
      run.colsOurs = await page.$$eval('.cxm', n => n.length);
      await page.keyboard.press('Escape');
      await page.evaluate(() => colsEditing(false));
      await page.waitForTimeout(200);
      // picking rows, the dock, a bulk action with what will happen, one result
      for (const i of [0, 1]) {
        await rows.nth(i).evaluate(e => e.scrollIntoView({block: 'center'}));
        await page.waitForTimeout(150);
        await rows.nth(i).locator('td').nth(1).click({modifiers: ['Control']});
      }
      await page.waitForTimeout(300);
      run.picked = await page.$$eval('#ct-table tr.cxm-sel', n => n.length);
      run.modalAfterPick = await page.evaluate(() => !document.getElementById('modal').hidden);
      await check('dock');
      await shot(page, `dock-${tag}`);
      await page.click('.cxm-dk-b');
      await page.waitForTimeout(400);
      await check('bulkmenu');
      await shot(page, `bulkmenu-${tag}`);
      run.bulkPicked = await item(page, 'Add a tag to them…');
      await page.waitForTimeout(400);
      await page.fill('#modal-body input', 'ui' + lang + w);
      await check('bulk');
      await shot(page, `bulk-${tag}`);
      await page.click('#modal-foot .btn.primary');
      await page.waitForTimeout(2500);
      run.bulkResult = await page.$eval('.cxb-result', n => n.className);
      await check('bulkdone');
      await shot(page, `bulkdone-${tag}`);
      await page.click('#modal-foot button');
      await page.waitForTimeout(500);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(200);
      run.pickedAfterEsc = await page.$$eval('#ct-table tr.cxm-sel', n => n.length);
      // a target cloned with the same credentials (saved only on Save; the server copies them)
      await page.evaluate(() => showTab('targets'));
      await page.waitForSelector('#tg-list tbody tr');
      await page.waitForTimeout(500);
      await rclick(page, page.locator('#tg-list tbody tr', {has: page.locator('td:first-child b', {hasText: /^fake1$/})}).locator('td').nth(0));
      await item(page, 'Clone…');
      await page.waitForSelector('.cxc-ch');
      await check('clone');
      await shot(page, `clone-${tag}`);
      await page.click('.cxc-ch[data-how="same"]');
      await page.waitForSelector('#modal-body .ct-fform', {timeout: 15000});
      await page.waitForTimeout(300);
      const cname = 'Clone ' + lang + ' ' + w;
      await page.fill('#modal-body input', cname);
      run.cloneSecretShown = await page.evaluate(() => [...document.querySelectorAll('#modal-body input')].some(i => i.value === 's3cret'));
      await page.click('#modal-foot .btn.primary:not(.danger)');
      await page.waitForTimeout(1500);
      run.cloneName = cname;
      // the command that makes it, and the API call
      await rclick(page, page.locator('#tg-list tbody tr', {has: page.locator('td:first-child b', {hasText: /^fake1$/})}).locator('td').nth(0));
      await page.locator('.cxm:not(.cxm-sub) .cxm-i[aria-haspopup]').first().click();
      await page.waitForTimeout(400);
      await item(page, 'As a CLI command', true);
      await page.waitForTimeout(400);
      run.cli = await page.evaluate(() => navigator.clipboard.readText().catch(() => ''));
      await rclick(page, page.locator('#tg-list tbody tr', {has: page.locator('td:first-child b', {hasText: /^fake1$/})}).locator('td').nth(0));
      await page.locator('.cxm:not(.cxm-sub) .cxm-i[aria-haspopup]').first().click();
      await page.waitForTimeout(400);
      await item(page, 'As an API call (curl)', true);
      await page.waitForTimeout(400);
      run.curl = await page.evaluate(() => navigator.clipboard.readText().catch(() => ''));
      // the acme clipboard, and Paste as new on the list's empty space
      await rclick(page, page.locator('#tg-list tbody tr', {has: page.locator('td:first-child b', {hasText: /^fake2$/})}).locator('td').nth(0));
      await item(page, 'Copy to the acme clipboard');
      await page.waitForTimeout(300);
      run.clip = await page.evaluate(() => JSON.parse(localStorage.getItem('acme.ctx.clip') || 'null'));
      await rclick(page, page.locator('#tab-targets h2'));
      run.area = await page.$$eval('.cxm', n => n.length);
      await check('area');
      await shot(page, `area-${tag}`);
      await item(page, 'Paste as new');
      await page.waitForSelector('#modal-body .ct-fform', {timeout: 15000});
      await page.waitForTimeout(300);
      run.pasteName = await page.$eval('#modal-body input', i => i.value);
      await page.evaluate(() => closeModal());
      await page.evaluate(() => ACME_CTX.clipClear());
      // DNS sets: clone in its own form, its command
      await page.evaluate(() => { showTab('settings'); });
      await page.waitForTimeout(200);
      await page.evaluate(() => showPane('dnssets'));
      await page.waitForSelector('table.dnss-sets tbody tr');
      await page.waitForTimeout(500);
      const ds = page.locator('table.dnss-sets tbody tr', {has: page.locator('td:first-child b', {hasText: /^Company DNS$/})});
      await rclick(page, ds.locator('td').nth(1));
      await item(page, 'Clone…');
      await page.waitForSelector('#dnss-f-name', {timeout: 15000});
      await page.waitForTimeout(300);
      run.dnsClone = [await page.$eval('#dnss-f-name', i => i.value), await page.$eval('#dnss-f-servers', i => i.value)];
      await page.evaluate(() => closeModal());
      await rclick(page, ds.locator('td').nth(0));
      await page.locator('.cxm:not(.cxm-sub) .cxm-i[aria-haspopup]').first().click();
      await page.waitForTimeout(400);
      await item(page, 'As a CLI command', true);
      await page.waitForTimeout(400);
      run.dnsCli = await page.evaluate(() => navigator.clipboard.readText().catch(() => ''));
      // the team tree: its menu, a clone without members
      await page.evaluate(() => showPane('teams'));
      await page.waitForSelector('#tmx-tree .tmx-row', {state: 'attached'});
      await page.waitForTimeout(500);
      /* a phone: the tree is in its drawer, opened by its button */
      if (w < 500) {
        await page.evaluate(() => { const b = document.getElementById('tmx-switch'); if (b) b.click(); });
        await page.waitForTimeout(900);
      }
      run.treeShown = await page.locator('#tmx-tree .tmx-row[data-name="Webteam"]').isVisible();
      if (run.treeShown) {
      await rclick(page, page.locator('#tmx-tree .tmx-row[data-name="Webteam"]'));
      run.teamMenu = await page.$$eval('.cxm', n => n.length);
      await check('team');
      await item(page, 'Clone…');
      await page.waitForSelector('#modal-body.cxc input', {timeout: 15000});
      await page.waitForTimeout(300);
      run.teamClone = await page.$eval('#modal-body input', i => i.value);
      await check('teamclone');
      await shot(page, `team-${tag}`);
      await page.evaluate(() => closeModal());
      }
      // the palette: Ctrl+K, a verb, Enter
      await page.keyboard.press('Control+k');
      await page.waitForSelector('.cxp');
      await page.waitForTimeout(500);
      await check('palette');
      await shot(page, `palette-${tag}`);
      await page.keyboard.type(lang === 'cs' ? 'obnov intr' : 'renew intr');
      await page.waitForTimeout(400);
      run.paletteVerb = await page.$$eval('.cxp-row .cxp-t', n => n.map(x => x.textContent.trim()).slice(0, 3));
      await shot(page, `palette2-${tag}`);
      await page.fill('.cxp-in', 'dns');
      await page.waitForTimeout(400);
      await page.keyboard.press('Enter');
      await page.waitForTimeout(800);
      run.paletteWent = await page.evaluate(() => typeof PANE === 'string' ? PANE : '');
      run.paletteClosed = await page.$$eval('.cxp', n => n.length);
      run.recent = await page.evaluate(() => JSON.parse(localStorage.getItem('acme.palette.recent') || '[]').length);
      out.runs.push(run);
      await ctx.close();
    }
    // somebody who may only look: no write action, the copies as for anybody
    const {ctx, page} = await signIn('en', 1400, 'viewer');
    await page.evaluate(() => showTab('certs'));
    await page.waitForSelector('#ct-table tbody tr');
    await page.waitForTimeout(500);
    await rclick(page, page.locator('#ct-table tbody tr').nth(0).locator('td').nth(1));
    out.ro = {items: await items(page)};
    await shot(page, 'readonly-en-1400');
    await page.keyboard.press('Escape');
    await page.evaluate(() => showTab('targets'));
    await page.waitForSelector('#tg-list tbody tr');
    await page.waitForTimeout(500);
    await rclick(page, page.locator('#tg-list tbody tr').nth(0).locator('td').nth(0));
    out.ro.targetItems = await items(page);
    await ctx.close();
  } catch (e) {
    out.error = String(e && e.stack || e);
    try { for (const c of browser.contexts()) for (const pg of c.pages()) await shot(pg, 'failed'); } catch (x) { }
    out.at = out.runs.length;
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
