// The pages' half of test/test_reqprofiles_ui.py, in Chromium against a real daemon.
//
//   node test/reqprofiles_ui_page.js BASE_URL PASSWORD
//
// At 390, 768 and 1400 px, in English and in Czech: Settings -> Request profiles' cards, the
// search, a profile made with every section of the editor, edited, duplicated and deleted;
// the page's errors, a page wider than the window, English left on the Czech page, a box
// scrolling inside another. Prints one line of JSON. RQUI_SHOTS=dir: screenshots there.
const { chromium } = require('playwright');
const path = require('path');

const SHOTS = process.env.RQUI_SHOTS || '';

// what may scroll on its own (test/test_no_double_scroll.py's ALLOW), and the popup's one body
const ALLOW = ['#ctl-nav', '.tmx-tree-s', '.ctl-found', '.t-suggest', '.cols-menu', '.acct-panel', '.tm-cpick-panel',
  '.pw-switch-p', '.ck-pickmenu', '.joblines', 'pre.lines', 'textarea', '#modal-body'];

function checks(ALLOW) {
  // runs in the page
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
  // English on the Czech page: words of the page (never data: marked, .mono, typed in)
  if (document.documentElement.lang === 'cs' || (window.I18N && I18N.on)) {
    // whole words only - \b of a RegExp stops at a Czech letter ("Použití" is not "it")
    const EN = /(?<!\p{L})(the|and|of|is|it|for|with|not|may|this|its|what|who|from|are|names?|key|profiles?|offered|issued|approved|sections?|find|add|sign|days|certificates?|person|teams|anybody|nothing|none|they|give|cards|general|duplicate|first)(?!\p{L})/iu;
    for (const w of where) {
      const tw = document.createTreeWalker(w, NodeFilter.SHOW_TEXT);
      let t;
      while ((t = tw.nextNode())) {
        const p = t.parentElement;
        if (!p || !t.textContent.trim()) continue;
        if (p.closest('[data-no-i18n], .mono, script, style, option')) continue;
        if (!p.offsetParent && getComputedStyle(p).position !== 'fixed') continue;
        if (EN.test(t.textContent)) out.english.push(t.textContent.trim().slice(0, 80));
      }
      for (const n of w.querySelectorAll('[placeholder], [aria-label], [title]')) {
        if (!n.offsetParent) continue;
        for (const a of ['placeholder', 'aria-label', 'title']) {
          const v = n.getAttribute(a);
          if (v && EN.test(v) && !/^[\w.*-]+\.[a-z]{2,}$/.test(v)) out.english.push(a + ': ' + v.slice(0, 80));
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
    for (const n of document.querySelectorAll('#modal-body .tmx-seg')) {
      if (n.offsetParent && !(n.getAttribute('aria-label') || n.getAttribute('aria-labelledby'))) out.unlabelled.push(name(n));
    }
  }
  return out;
}

// A click on the list after it was drawn again: the page brought to it as a reader would - with
// the wheel (core.js's viewKeep puts back a scroll nobody made while the page changes)
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

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  const merge = (into, got) => { for (const k of Object.keys(got)) into[k] = (into[k] || []).concat(got[k]); };
  try {
    for (const lang of ['en', 'cs']) for (const w of [390, 768, 1400]) {
      const ctx = await browser.newContext({viewport: {width: w, height: 900}});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(lang + w + ': ' + String(e.message || e)));
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1200);
      await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
      await page.evaluate(() => document.querySelector('#ctl-nav button[data-pane="reqprofiles"]').click());
      await page.waitForFunction(() => document.querySelectorAll('#rp-host .rpx-card').length >= 2, null, {timeout: 20000});
      await page.waitForTimeout(600);
      const run = {lang, w, hscroll: [], nested: [], english: [], unlabelled: []};
      run.cards = await page.locator('#rp-host .rpx-card').count();
      run.limits = await page.evaluate(() => {
        const c = document.querySelector('#rp-host .rpx-card[data-name="Web server certificate"]');
        const f = [...c.querySelectorAll('.rpx-fact')].pop();
        return [...f.querySelectorAll('.rpx-fact-v .tmx-chip')].map(x => x.textContent.trim());
      });
      merge(run, await page.evaluate(checks, ALLOW));
      if (SHOTS) await page.screenshot({path: path.join(SHOTS, `list-${w}-${lang}.png`), fullPage: true});
      // the search
      await page.fill('#rpx-q', 'intranet');
      await page.waitForTimeout(400);
      run.found = await page.locator('#rp-host .rpx-card').count();
      await page.fill('#rpx-q', 'zzzz-nothing');
      await page.waitForTimeout(400);
      run.none = await page.locator('#rp-host .tmx-empty').count() === 1;
      merge(run, await page.evaluate(checks, ALLOW));
      await page.fill('#rpx-q', '');
      await page.waitForTimeout(400);
      // the table view, and back
      await page.click('#rp-host .tmx-vbtn[data-view="table"]');
      await page.waitForSelector('#rp-host .rp-table tr.rp-row');
      merge(run, await page.evaluate(checks, ALLOW));
      await page.click('#rp-host .tmx-vbtn[data-view="cards"]');
      await page.waitForSelector('#rp-host .rpx-card');

      // a new profile, every section filled
      const name = `UI ${lang} ${w}`;
      run.name = name;
      await page.click('#rp-add');
      await page.waitForSelector('#rpx-ed');
      run.sections = await page.locator('#rpx-ed .rpx-sec').count();
      await page.fill('#rp-f-name', name);
      await page.click('#rpx-s-general .sw');                      // offered: off
      await page.fill('#rpx-s-general textarea', 'made by the test');
      await page.selectOption('#rp-f-issuer', 'own');
      await page.fill('#rp-f-suffixes', 'a.example.test');
      await page.press('#rp-f-suffixes', 'Enter');
      await page.type('#rp-f-suffixes', 'b.example.test,');
      await page.fill('#rp-f-suffixes', 'c.example.test');      // still typed when saved
      const wildOk = await page.evaluate(() => !document.querySelector('#rpx-s-names .sw input').disabled);
      if (wildOk) await page.click('#rpx-s-names .sw');
      await page.fill('#rpx-s-names input[type=number]', '7');
      const csrOk = await page.evaluate(() => !document.querySelectorAll('#rpx-s-key .sw input')[1].disabled);
      if (csrOk) await page.click('#rpx-s-key .tmx-prow:nth-of-type(2) .sw');
      const kts = await page.evaluate(() => [...document.querySelectorAll('#rpx-s-key .rpx-pill input')].filter(x => !x.disabled).map(x => x.dataset.kt));
      const want384 = kts.indexOf('ec-384') >= 0;
      if (want384) await page.click('#rpx-s-key .rpx-pill:has(input[data-kt="ec-384"])');
      const kdef = want384 ? 'ec-384' : 'ec-256';
      await page.click(`#rp-f-kdef .tmx-segb[data-v="${kdef}"]`);
      // the subject: O fixed, OU filled by the person
      await page.click('#rpx-s-subject .rpx-subj-row[data-field="O"] .tmx-segb[data-v="fixed"]');
      await page.fill('#rpx-s-subject .rpx-subj-row[data-field="O"] .rpx-subj-v', 'ACME Corp');
      await page.click('#rpx-s-subject .rpx-subj-row[data-field="OU"] .tmx-segb[data-v="person"]');
      await page.fill('#rpx-s-subject .rpx-subj-row[data-field="OU"] .rpx-subj-v', 'IT');
      // use and renewal
      await page.click('#rpx-s-renewal .sw');                      // renew by itself: off
      await page.fill('#rpx-s-renewal input[type=number] >> nth=0', '20');
      const daysShown = await page.evaluate(() => { const r = document.querySelectorAll('#rpx-s-renewal .tmx-prow')[2]; return !r.hidden; });
      if (daysShown) await page.fill('#rpx-s-renewal input[type=number] >> nth=1', '60');
      await page.click('#rpx-s-renewal .rpx-pill:has-text("clientAuth")');
      // approval and owner
      await page.click('#rp-f-approval .tmx-segb[data-v="1"]');
      await page.click('#rp-f-owner .tmx-segb[data-v="fixed"]');
      await page.selectOption('#rp-f-oteam', 'Webteam');
      await page.click('#rpx-s-approval .tmx-prow:has(#rp-f-oteam) + .tmx-prow .sw');   // PFX
      // who may use it
      await page.selectOption('#rp-f-teams', 'Mailteam');
      // the side navigation
      await page.click('#rpx-ed .rpx-nb[data-sec="who"]');
      await page.waitForTimeout(700);
      run.navOk = await page.evaluate(() => {
        const s = document.getElementById('rpx-s-who'), b = document.getElementById('modal-body');
        const r = s.getBoundingClientRect(), br = b.getBoundingClientRect();
        return r.top < br.bottom && r.bottom > br.top;
      });
      await page.waitForTimeout(300);
      run.preview = await page.evaluate(n => document.getElementById('rpx-prev').textContent.indexOf(n) >= 0, name);
      merge(run, await page.evaluate(checks, ALLOW));
      if (SHOTS) {
        await page.evaluate(() => { document.getElementById('modal-body').scrollTop = 0; });
        await page.screenshot({path: path.join(SHOTS, `editor-${w}-${lang}.png`)});
      }
      await page.click('#modal-foot .btn.primary');
      await page.waitForFunction(() => document.getElementById('modal').hidden, null, {timeout: 15000});
      await page.waitForTimeout(500);
      const got = await page.evaluate(n => api('reqprofiles').then(d => d.profiles.find(p => p.name === n)), name);
      const pick = p => p && {
        enabled: !!p.enabled, description: p.description, issuer: p.issuer, suffixes: p.suffixes, wildcards: !!p.wildcards,
        max_names: Number(p.max_names), make_key: !!p.make_key, csr: !!p.csr, key_types: [...p.key_types].sort(), key_default: p.key_default,
        subjectO: p.subject && p.subject.O, subjectOU: p.subject && p.subject.OU, auto_renew: !!p.auto_renew, renew_days: p.renew_days,
        days: p.days || null, eku: [...p.eku].sort(), approval: !!p.approval, owner: p.owner, owner_team: p.owner_team, pfx: !!p.pfx,
        teams: p.teams};
      run.made = pick(got);
      run.wanted = {enabled: false, description: 'made by the test', issuer: 'own',
        suffixes: ['a.example.test', 'b.example.test', 'c.example.test'], wildcards: wildOk, max_names: 7, make_key: true,
        csr: csrOk, key_types: ['ec-256', 'rsa-2048'].concat(want384 ? ['ec-384'] : []).sort(), key_default: kdef,
        subjectO: {mode: 'fixed', value: 'ACME Corp'}, subjectOU: {mode: 'person', value: 'IT'}, auto_renew: false, renew_days: 20,
        days: daysShown ? 60 : null, eku: ['clientAuth', 'serverAuth'], approval: true, owner: 'fixed', owner_team: 'Webteam', pfx: true,
        teams: ['Mailteam']};
      // edited: another description, the domains changed
      await page.waitForSelector(`#rp-host .rpx-card[data-name="${name}"]`);
      await tap(page, `#rp-host .rpx-card[data-name="${name}"] .rp-edit`);
      await page.waitForSelector('#rpx-ed');
      await page.fill('#rpx-s-general textarea', 'changed ' + lang + w);
      while (await page.locator('#rpx-s-names .tmx-chip-x').count()) await page.click('#rpx-s-names .tmx-chip-x >> nth=0');
      await page.fill('#rp-f-suffixes', `n${lang}${w}.example.test`);
      await page.press('#rp-f-suffixes', 'Enter');
      await page.fill('#rp-f-suffixes', 'more.example.test');
      await page.click('#modal-foot .btn.primary');
      await page.waitForFunction(() => document.getElementById('modal').hidden, null, {timeout: 15000});
      await page.waitForTimeout(500);
      const ed = await page.evaluate(n => api('reqprofiles').then(d => d.profiles.find(p => p.name === n)), name);
      run.edited = ed && {description: ed.description, suffixes: ed.suffixes};
      // duplicated
      await page.waitForSelector(`#rp-host .rpx-card[data-name="${name}"]`);
      await tap(page, `#rp-host .rpx-card[data-name="${name}"] .rp-dup`);
      await page.waitForSelector('#rpx-ed');
      run.copyName = await page.inputValue('#rp-f-name');
      run.copied = (await page.inputValue('#rpx-s-general textarea')) === 'changed ' + lang + w
        && await page.locator('#rpx-s-names .tmx-chip').count() === 2;
      await page.click('#modal-foot .btn.primary');
      await page.waitForFunction(() => document.getElementById('modal').hidden, null, {timeout: 15000});
      await page.waitForSelector(`#rp-host .rpx-card[data-name="${run.copyName}"]`);
      // deleted, both
      for (const n of [name, run.copyName]) {
        await tap(page, `#rp-host .rpx-card[data-name="${n}"] .rp-del`);
        await page.waitForSelector('#modal-foot .btn.danger');
        await page.click('#modal-foot .btn.danger');
        await page.waitForFunction(n => !document.querySelector(`#rp-host .rpx-card[data-name="${n}"]`), n, {timeout: 15000});
      }
      run.left = (await page.evaluate(() => api('reqprofiles').then(d => d.profiles.map(p => p.name)))).sort();
      out.runs.push(run);
      // the empty state, once at the end: every profile gone
      if (lang === 'cs' && w === 1400) {
        await page.evaluate(() => api('reqprofiles').then(d => Promise.all(d.profiles.map(p => api('reqprofiles/delete', {name: p.name})))));
        await page.evaluate(() => window.ACME_EXTRA_PANES.reqprofiles());
        await page.waitForSelector('#rp-host .tmx-empty #rpx-first');
        const e = await page.evaluate(checks, ALLOW);
        await page.click('#rpx-first');
        await page.waitForSelector('#rpx-ed');
        out.emptyState = !e.english.length && !e.hscroll.length;
        if (!out.emptyState) out.emptyWhy = e;
      }
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
