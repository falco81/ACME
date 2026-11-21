// The pages' half of test/test_f138_profiles_ui.py, in Chromium against a real daemon.
//
//   node test/f138_profiles_page.js BASE_URL PASSWORD
//
// At 390 and 1400 px, in English and in Czech: Settings -> Request profiles' cards with their
// base / version / dry run / ending, the editor of a profile with a base (inherited and
// overridden fields), the history and a diff, a dry run, the compliance check, ending a profile
// and what it moves. The page's errors, a page wider than the window, English left on the Czech
// page, a box scrolling inside another, a box without a label. Prints one line of JSON.
// F138_SHOTS=dir: screenshots there (deviceScaleFactor 1).
const { chromium } = require('playwright');
const path = require('path');

const SHOTS = process.env.F138_SHOTS || '';
const ALLOW = ['#ctl-nav', '.tmx-tree-s', '.ctl-found', '.t-suggest', '.cols-menu', '.acct-panel', '.tm-cpick-panel',
  '.pw-switch-p', '.ck-pickmenu', '.joblines', 'pre.lines', 'textarea', '#modal-body'];

function checks(ALLOW) {
  const out = {hscroll: [], nested: [], english: [], unlabelled: []};
  const root = document.scrollingElement;
  if (root.scrollWidth - innerWidth > 0) out.hscroll.push('page ' + (root.scrollWidth - innerWidth));
  const mb = document.getElementById('modal-body');
  const open = mb && !document.getElementById('modal').hidden;
  if (open && mb.scrollWidth - mb.clientWidth > 1) out.hscroll.push('popup ' + (mb.scrollWidth - mb.clientWidth));
  const where = [document.getElementById('rp-host')].concat(open ? [document.getElementById('modal-box')] : []);
  const name = n => n.tagName.toLowerCase() + (n.id ? '#' + n.id : '') + (n.className && typeof n.className === 'string' ? '.' + n.className.trim().split(/\s+/).join('.') : '');
  for (const w of where) {
    for (const n of w.querySelectorAll('*')) {
      if (!n.offsetParent && getComputedStyle(n).position !== 'fixed') continue;
      const cs = getComputedStyle(n);
      if (/(auto|scroll)/.test(cs.overflowY) && n.scrollHeight > n.clientHeight + 2 && !ALLOW.some(a => n.matches(a))) out.nested.push(name(n));
    }
  }
  if (document.documentElement.lang === 'cs' || (window.I18N && I18N.on)) {
    const EN = /(?<!\p{L})(the|and|of|is|it|for|with|not|may|this|its|what|who|from|are|names?|key|profiles?|offered|issued|approved|sections?|find|add|sign|days|certificates?|person|teams|anybody|nothing|none|they|give|cards|general|duplicate|first|version|history|dry|run|compare|inherited|overridden|based|ends?|comply|complies|rules?|successor|restore|changed?|valid|now|today|at|most|show|hide|fields?|same|try|would|be|refused|moves?|renewed?|subject|used|approval|whose|tags|renewal|source|public|private)(?!\p{L})/iu;
    for (const w of where) {
      const tw = document.createTreeWalker(w, NodeFilter.SHOW_TEXT);
      let t;
      while ((t = tw.nextNode())) {
        const p = t.parentElement;
        if (!p || !t.textContent.trim()) continue;
        if (p.closest('[data-no-i18n], .mono, script, style, option')) continue;
        if (!p.offsetParent && getComputedStyle(p).position !== 'fixed') continue;
        if (EN.test(t.textContent)) out.english.push(t.textContent.trim().slice(0, 90));
      }
      for (const n of w.querySelectorAll('[placeholder], [aria-label], [title]')) {
        if (!n.offsetParent) continue;
        for (const a of ['placeholder', 'aria-label', 'title']) {
          const v = n.getAttribute(a);
          if (v && EN.test(v) && !/^[\w.*-]+\.[a-z]{2,}$/.test(v) && !/^-----BEGIN/.test(v)) out.english.push(a + ': ' + v.slice(0, 90));
        }
      }
    }
  }
  if (open) {
    for (const n of document.querySelectorAll('#modal-body input, #modal-body select, #modal-body textarea')) {
      if (n.type === 'hidden' || !n.offsetParent) continue;
      const ok = n.getAttribute('aria-label') || n.getAttribute('aria-labelledby') || n.closest('label')
        || (n.id && document.querySelector('label[for="' + n.id + '"]'));
      if (!ok) out.unlabelled.push(name(n));
    }
  }
  return out;
}

async function tap(page, sel) {
  for (let i = 0; i < 6; i++) {
    const d = await page.evaluate(s => {
      const r = document.querySelector(s).getBoundingClientRect();
      return r.top < 80 || r.bottom > innerHeight - 40 ? Math.round(r.top - innerHeight / 2) : 0;
    }, sel);
    if (!d) break;
    const vp = page.viewportSize();
    await page.mouse.move(vp.width / 2, vp.height / 2);
    await page.mouse.wheel(0, d);
    await page.waitForTimeout(300);
  }
  await page.click(sel);
}
const closed = page => page.waitForFunction(() => document.getElementById('modal').hidden, null, {timeout: 15000});

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  const merge = (into, got) => { for (const k of Object.keys(got)) into[k] = (into[k] || []).concat(got[k]); };
  try {
    for (const lang of ['en', 'cs']) for (const w of [390, 1400]) {
      const ctx = await browser.newContext({viewport: {width: w, height: 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(lang + w + ': ' + String(e.message || e)));
      page.on('console', m => { if (m.type() === 'error' && !/favicon|Failed to load resource/.test(m.text())) out.errors.push(lang + w + ' console: ' + m.text()); });
      const shot = async n => { if (SHOTS) await page.screenshot({path: path.join(SHOTS, `${n}-${w}-${lang}.png`)}); };
      const mutate = lang === 'en' && w === 1400;
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1200);
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
      await page.evaluate(() => document.querySelector('#ctl-nav button[data-pane="reqprofiles"]').click());
      await page.waitForFunction(() => document.querySelectorAll('#rp-host .rpx-card').length >= 3, null, {timeout: 20000});
      await page.waitForTimeout(600);
      const run = {lang, w, hscroll: [], nested: [], english: [], unlabelled: []};
      merge(run, await page.evaluate(checks, ALLOW));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `list-${w}-${lang}.png`), fullPage: true});

      // the editor of a profile with a base
      await tap(page, '#rp-host .rpx-card[data-name="Shop"] .rp-edit');
      await page.waitForSelector('#rpx-ed .rpx-inh-t');
      run.inherited = await page.locator('#rpx-ed .rpx-inh-t.on').count();
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('editor');
      const grp = mutate ? 'days' : 'eku';
      await page.click(`#rpx-ed .rpx-inh-t[data-group="${grp}"]`);
      await page.waitForSelector(`#rpx-ed .rpx-inh-t[data-group="${grp}"]:not(.on)`);
      run.overrideShown = await page.evaluate(g => {
        const t = document.querySelector(`#rpx-ed .rpx-inh-t[data-group="${g}"]`);
        const row = t.closest('.tmx-prow');
        return document.activeElement === t && !row.querySelector('.tmx-prow-c').hasAttribute('inert');
      }, grp);
      await page.evaluate(g => document.querySelector(`#rpx-ed .rpx-inh-t[data-group="${g}"]`).scrollIntoView({block: 'center'}), grp);
      await shot('editor-override');
      if (mutate) {
        await page.fill('#rpx-s-renewal input[type=number] >> nth=1', '30');
        await page.click('#modal-foot .btn.primary');
      } else {
        // left without saving (what was typed is asked about first - the page's own question)
        await page.evaluate(() => closeModal(true));
      }
      await closed(page);
      await page.waitForTimeout(500);

      // the history of "Company web", and the diff
      await page.waitForSelector('#rp-host .rpx-card[data-name="Company web"] .rpm-hist');
      await tap(page, '#rp-host .rpx-card[data-name="Company web"] .rpm-hist');
      await page.waitForSelector('.rpm-tl-it');
      run.versions = await page.locator('.rpm-tl-it').count();
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('history');
      await page.click('.rpm-tl-it >> nth=0 >> .rpm-what');
      await page.waitForSelector('.rpm-diff');
      run.diffRows = await page.locator('.rpm-dr.diff').count();
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('diff');
      await page.click('.rpm-same');
      merge(run, await page.evaluate(checks, ALLOW));
      await page.click('#modal-foot .btn');
      await page.waitForSelector('.rpm-tl-it');
      if (mutate) {
        const last = await page.locator('.rpm-tl-it').count();
        await page.click(`.rpm-tl-it >> nth=${last - 1} >> .rpm-restore`);
        await page.waitForSelector('#modal-foot .btn.primary');
        merge(run, await page.evaluate(checks, ALLOW));
        await page.click('#modal-foot .btn.primary');
        await closed(page);
      } else {
        await page.click('#modal-foot .btn');
        await closed(page);
      }
      await page.waitForTimeout(500);

      // a dry run
      await tap(page, '#rp-host .rpx-card[data-name="Company web"] .rpm-try');
      await page.waitForSelector('#rpm-dr-names');
      await page.fill('#rpm-dr-names', 'portal.corp.example.test');
      await page.click('#modal-foot .btn.primary');
      await page.waitForSelector('.rpm-verdict');
      run.dryFits = await page.locator('.rpm-verdict.ok').count() === 1;
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('dryrun');
      await page.fill('#rpm-dr-names', 'x.other.test');
      await page.click('#modal-foot .btn.primary');
      await page.waitForSelector('.rpm-verdict.bad');
      run.dryBad = await page.locator('.rpm-why li').count() >= 1;
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('dryrun-bad');
      await page.click('#modal-foot .btn:not(.primary)');
      await closed(page);

      // the compliance check, on the day public certificates get to 47 days
      await tap(page, '#rpm-comply');
      await page.waitForSelector('.rpm-step');
      run.steps = await page.locator('.rpm-step').count();
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('compliance');
      await page.click('.rpm-step >> nth=-1 >> button');
      await page.waitForSelector('.rpm-step.sel >> nth=0');
      await page.click('.rpm-rules-s');
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('compliance-rules');
      await page.click('#modal-foot .btn');
      await closed(page);

      // ending "Old web": what it moves
      await tap(page, '#rp-host .rpx-card[data-name="Old web"] .rpm-end');
      await page.waitForSelector('#rpm-succ');
      await page.selectOption('#rpm-succ', 'Company web');
      await page.waitForSelector('.rpm-ii');
      run.impactMoves = await page.locator('.rpm-ii.moves').count() === 1;
      merge(run, await page.evaluate(checks, ALLOW));
      await shot('ending');
      if (mutate) {
        await page.click('#modal-foot .btn.primary');
        await closed(page);
        await page.waitForSelector('#rp-host .rpx-card[data-name="Old web"] .rpm-endchip');
        merge(run, await page.evaluate(checks, ALLOW));
        if (SHOTS) await page.screenshot({path: path.join(SHOTS, `list-ends-${w}-${lang}.png`), fullPage: true});
        await tap(page, '#rp-host .rpx-card[data-name="Old web"] .rpm-end');
        await page.waitForSelector('#modal-foot .btn.primary');
        await page.waitForSelector('.rpm-ii');
        merge(run, await page.evaluate(checks, ALLOW));
        await shot('ends');
        await page.click('#modal-foot .btn.primary');
        await closed(page);
      } else {
        await page.evaluate(() => closeModal(true));     // the successor chosen, not ended
        await closed(page);
      }
      // the table view
      await page.click('#rp-host .tmx-vbtn[data-view="table"]');
      await page.waitForSelector('#rp-host .rp-table tr.rp-row');
      merge(run, await page.evaluate(checks, ALLOW));
      await page.click('#rp-host .tmx-vbtn[data-view="cards"]');
      out.runs.push(run);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
