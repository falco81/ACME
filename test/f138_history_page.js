// The pages' half of test/test_f138_history.py, in Chromium against a real daemon.
//
//   node test/f138_history_page.js BASE_URL PASSWORD OUTDIR
//
// At 390 and 1400 px, in English and in Czech: Settings -> Trash and history (the trash, its
// filters, the restore preview with a name taken since, the restore), the latest changes, the
// History of a target with its field-level difference and "Restore this version", and the saved
// views by the certificates (saved, left, picked again). The page's errors, a page wider than the
// window, English left on the Czech page. Prints one line of JSON. F138_SHOTS=dir: screenshots.
const { chromium } = require('playwright');
const path = require('path');

const SHOTS = process.env.F138_SHOTS || '';

function checks(where) {
  // runs in the page
  const out = {hscroll: [], english: []};
  const root = document.scrollingElement;
  if (root.scrollWidth - innerWidth > 1) out.hscroll.push('page ' + (root.scrollWidth - innerWidth));
  const mb = document.getElementById('modal-body');
  const open = mb && !document.getElementById('modal').hidden;
  if (open && mb.scrollWidth - mb.clientWidth > 1) out.hscroll.push('popup ' + (mb.scrollWidth - mb.clientWidth));
  const hosts = where.map(s => document.querySelector(s)).filter(Boolean);
  if (open) hosts.push(document.getElementById('modal-box'));
  if (window.I18N && I18N.on) {
    const EN = /(?<!\p{L})(the|and|of|is|it|for|with|not|may|this|its|what|who|from|are|deleted|restore|changed|trash|history|views?|nobody|anybody|every|kind|days|left|only|team|mine|save|name|everybody)(?!\p{L})/iu;
    for (const w of hosts) {
      const tw = document.createTreeWalker(w, NodeFilter.SHOW_TEXT);
      let t;
      while ((t = tw.nextNode())) {
        const p = t.parentElement;
        if (!p || !t.textContent.trim()) continue;
        if (p.closest('[data-no-i18n], .mono, script, style, option, .hs-kv, .hs-detail')) continue;
        if (!p.offsetParent && getComputedStyle(p).position !== 'fixed') continue;
        if (EN.test(t.textContent)) out.english.push(t.textContent.trim().slice(0, 90));
      }
      for (const n of w.querySelectorAll('[placeholder], [aria-label]')) {
        if (!n.offsetParent || n.closest('[data-no-i18n]')) continue;
        for (const a of ['placeholder', 'aria-label']) {
          const v = n.getAttribute(a);
          if (v && EN.test(v)) out.english.push(a + ': ' + v.slice(0, 80));
        }
      }
    }
  }
  return out;
}

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  const merge = (into, got) => { for (const k of Object.keys(got)) into[k] = (into[k] || []).concat(got[k]); };
  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = lang + w;
      const ctx = await browser.newContext({viewport: {width: w, height: 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
      page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) out.errors.push(tag + ' console: ' + m.text()); });
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1200);
      const run = {lang, w, hscroll: [], english: []};
      // a target made, changed twice, and one deleted whose name is taken again since
      const made = await page.evaluate(async (t) => {
        const dir = '/tmp';
        const a = await api('targets/save', {name: 'ui-' + t, kind: 'fake', note: 'first', config: {dir: dir, password: 'pw1', mode: 'a', names: ['one.example.test']}});
        await api('targets/save', {id: a.id, name: 'ui-' + t, kind: 'fake', note: 'the second note', config: {dir: dir, password: 'pw2', mode: 'b', port: 8443, names: ['one.example.test', 'two.example.test']}});
        await api('targets/save', {id: a.id, name: 'ui-' + t, kind: 'fake', note: 'the second note\nwith a second line', config: {dir: dir, password: '', mode: 'b', port: 8444, names: ['two.example.test']}});
        const g = await api('targets/save', {name: 'gone-' + t, kind: 'fake', config: {dir: dir, password: 'pw3'}});
        await api('targets/delete', {id: g.id});
        await api('targets/save', {name: 'gone-' + t, kind: 'fake', config: {dir: dir}});
        await api('tags/save', {name: 'tag-' + t, colour: 'ok'});
        await api('tags/delete', {name: 'tag-' + t});
        return a.id;
      }, tag);
      // ---- Settings -> Trash and history ----
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
      await page.evaluate(() => document.querySelector('#ctl-nav button[data-pane="trash"]').click());
      await page.waitForFunction(() => document.querySelectorAll('#hs-host .hs-item').length >= 2, null, {timeout: 20000});
      await page.waitForTimeout(500);
      run.items = await page.locator('#hs-host .hs-item').count();
      run.settings = await page.locator('#sect-trash input, #sect-trash select').count();
      merge(run, await page.evaluate(checks, ['#pane-trash']));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `trash-${w}-${lang}.png`), fullPage: true});
      // only targets
      await page.selectOption('#hs-host .hs-filters select >> nth=0', 'target');
      await page.waitForTimeout(700);
      run.onlyTargets = await page.evaluate(() => [...document.querySelectorAll('#hs-host .hs-item .hs-tile')].every(x => x.classList.contains('t-target')));
      // the restore preview: its name is taken
      const item = page.locator('#hs-host .hs-item', {hasText: 'gone-' + tag});
      await item.locator('.btn.primary').click();
      await page.waitForSelector('#modal-body .hs-conflict', {timeout: 15000});
      await page.waitForTimeout(400);
      run.suggested = await page.inputValue('#modal-body input[type=text], #modal-body .formgrid input >> nth=0').catch(() => '');
      if (!run.suggested) run.suggested = await page.evaluate(() => { const i = document.querySelector('#modal-body input:not([type=checkbox])'); return i ? i.value : ''; });
      run.sealed = await page.locator('#modal-body .hs-sealed').count();
      merge(run, await page.evaluate(checks, []));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `restore-${w}-${lang}.png`)});
      await page.click('#modal-foot .btn.primary');
      await page.waitForFunction(() => document.getElementById('modal').hidden, null, {timeout: 15000});
      await page.waitForTimeout(800);
      run.restored = await page.evaluate(async (t) => {
        const d = await api('targets');
        return (d.rows || []).some(r => r.name === 'gone-' + t + ' 2');
      }, tag);
      // ---- the latest changes ----
      await page.click('#hs-host .tmx-vbtn >> nth=1');
      await page.waitForSelector('#hs-host .hs-ev', {timeout: 15000});
      await page.waitForTimeout(400);
      run.events = await page.locator('#hs-host .hs-ev').count();
      merge(run, await page.evaluate(checks, ['#pane-trash']));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `changes-${w}-${lang}.png`), fullPage: true});
      // ---- the History of the target ----
      await page.evaluate((id) => window.acmeHistory.open('target', id), made);
      await page.waitForSelector('#modal-body .hs-ent', {timeout: 15000});
      await page.waitForTimeout(500);
      run.entries = await page.locator('#modal-body .hs-ent').count();
      run.secretShown = await page.evaluate(() => /pw1|pw2|sealed:/.test(document.getElementById('modal-body').textContent));
      run.secretChanged = await page.locator('#modal-body .hs-secret').count();
      merge(run, await page.evaluate(checks, []));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `history-${w}-${lang}.png`)});
      await page.click('#modal-body .hs-ent >> nth=2 >> .hs-acts .btn');
      await page.waitForSelector('#modal-body .hs-restore .hs-diff', {timeout: 15000});
      await page.waitForTimeout(300);
      await page.evaluate(() => document.querySelector('#modal-body .hs-restore').scrollIntoView({block: 'center'}));
      merge(run, await page.evaluate(checks, []));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `history-restore-${w}-${lang}.png`)});
      await page.click('#modal-body .hs-restore .hs-rfoot .btn.primary');
      await page.waitForFunction(() => { const e = document.querySelector('#modal-body .hs-ent'); return e && e.classList.contains('a-restore'); }, null, {timeout: 15000});
      run.versionBack = await page.evaluate(async (id) => {
        const d = await api('targets');
        const r = (d.rows || []).find(x => x.id === id);
        return r ? r.config.mode + ':' + r.note : '';
      }, made);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
      // ---- the History button in the head of the target's form, over it ----
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="targets"]').click());
      await page.waitForSelector('#tg-list :text("ui-' + tag + '")', {timeout: 15000});
      await page.click('#tg-list :text("ui-' + tag + '")');
      await page.waitForSelector('#modal .hs-hbtn', {timeout: 15000});
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `form-button-${w}-${lang}.png`)});
      await page.click('#modal .hs-hbtn');
      await page.waitForSelector('#modal-body .hs-ent', {timeout: 15000});
      run.overForm = await page.evaluate(() => document.querySelectorAll('.modal.under').length);
      await page.keyboard.press('Escape');
      await page.waitForTimeout(400);
      run.formBack = await page.evaluate(() => !document.getElementById('modal').hidden && !!document.querySelector('#modal .hs-hbtn'));
      await page.keyboard.press('Escape');
      await page.waitForTimeout(300);
      // ---- saved views by the certificates ----
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="certs"]').click());
      await page.waitForSelector('#tab-certs .sv-btn', {timeout: 15000});
      await page.selectOption('#ct-state', 'expiring');
      await page.waitForTimeout(400);
      await page.click('#tab-certs .sv-btn');
      await page.waitForSelector('.sv-menu .sv-act', {timeout: 10000});
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `views-menu-empty-${w}-${lang}.png`)});
      await page.click('.sv-menu .sv-act >> nth=0');
      await page.waitForSelector('#modal-body .sv-form', {timeout: 10000});
      await page.fill('#modal-body .sv-form input', 'Soon ' + tag);
      merge(run, await page.evaluate(checks, []));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `views-save-${w}-${lang}.png`)});
      await page.click('#modal-foot .btn.primary');
      await page.waitForFunction(() => document.getElementById('modal').hidden, null, {timeout: 10000});
      await page.waitForTimeout(500);
      run.viewName = await page.evaluate(() => document.querySelector('#tab-certs .sv-btn .sv-name').textContent);
      await page.click('#tab-certs .sv-btn');
      await page.waitForSelector('.sv-menu .sv-item', {timeout: 10000});
      merge(run, await page.evaluate(checks, ['.sv-menu']));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `views-menu-${w}-${lang}.png`)});
      // back to the list as it comes, then the view again
      await page.click('.sv-menu .sv-act >> nth=-1');
      await page.waitForTimeout(400);
      run.cleared = await page.inputValue('#ct-state');
      await page.click('#tab-certs .sv-btn');
      await page.waitForSelector('.sv-menu .sv-item', {timeout: 10000});
      await page.click('.sv-menu .sv-item .sv-pick >> nth=0');
      await page.waitForTimeout(400);
      run.picked = await page.inputValue('#ct-state');
      // Escape closes the menu
      await page.click('#tab-certs .sv-btn');
      await page.waitForSelector('.sv-menu', {timeout: 10000});
      await page.keyboard.press('Escape');
      run.menuClosed = await page.evaluate(() => !document.querySelector('.sv-menu'));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `certs-${w}-${lang}.png`)});
      out.runs.push(run);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
