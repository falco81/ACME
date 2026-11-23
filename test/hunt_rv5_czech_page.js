// The pages' half of test/test_hunt_rv5_czech.py (hunt v5, czech): every tab of the
// administration, every pane of Settings and the portal, in Czech at 1400 and 390 px - the
// texts on them still in English (outside names, addresses, code and data).
//
//   node test/hunt_rv5_czech_page.js BASE_URL PASSWORD [screenshot-folder]
//
// Prints one line of JSON: {errors, runs: [{w, pages: {name: {english: [...], hs}}}]}.
const { chromium } = require('playwright');
const path = require('path');

function englishLeft() {
  // English words that are no Czech ones ("a", "to", "no" are both)
  const EN = /(?<![\p{L}\-_.\/])(the|and|is|are|was|of|with|not|this|that|its|from|which|when|will|yet|none|nothing|here|there|been|has|have|your|you)(?![\p{L}\-_.\/])/giu;
  const CZ = /[áčďéěíňóřšťúůýž]/i;
  const out = new Set();
  const visible = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
  const skip = 'script, style, [data-no-i18n], .mono, code, pre, kbd, samp, textarea, input, option, svg, [hidden]';
  const judge = (s, where) => {
    const t = s.replace(/\s+/g, ' ').trim();
    if (!t || !/[a-z]{2}/.test(t)) return;
    // in small letters: "The SSL Store (REST API)" is a name
    const words = (t.match(EN) || []).filter(w => w === w.toLowerCase()).length;
    // Czech with an English name or two in it is Czech; English is two such words, or one
    // in a sentence without a Czech letter
    if (CZ.test(t) ? words >= 2 : words >= 1) {
      out.add(where + t.slice(0, 160));
    }
  };
  const root = document.body;
  const tw = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = tw.nextNode())) {
    const p = n.parentElement;
    if (!p || p.closest(skip) || !visible(p)) continue;
    judge(n.textContent, '');
  }
  for (const e of root.querySelectorAll('[title], [placeholder], [aria-label]')) {
    if (e.closest('script, style, [data-no-i18n]:not(input):not(textarea), .mono:not(input):not(textarea)') || !visible(e)) continue;
    for (const a of ['title', 'placeholder', 'aria-label']) {
      const v = e.getAttribute(a);
      if (v && !/^[\w.+-]+@[\w.-]+$/.test(v)) judge(v, '@' + a + ': ');
    }
  }
  return {english: [...out], hs: document.scrollingElement.scrollWidth - innerWidth};
}

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  try {
    for (const w of [1400, 390]) {
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: 'cs', url: base}]);
      const page = await ctx.newPage();
      const run = {w, pages: {}};
      page.on('pageerror', e => out.errors.push(w + ': ' + String(e.message || e)));
      // the sign-in page itself
      await page.goto(base + '/admin/index.php');
      await page.waitForTimeout(600);
      run.pages['signin'] = await page.evaluate(englishLeft);
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1500);
      const tabs = await page.evaluate(() => (typeof allTabs === 'function' ? allTabs() : []));
      for (const t of tabs) {
        await page.evaluate(t => { location.hash = '#' + t; }, t);
        await page.waitForTimeout(1300);
        run.pages[t] = await page.evaluate(englishLeft);
        if (shots) await page.screenshot({path: path.join(shots, `rv5-${t}-${w}.png`)});
        // the tab's "Add ..." popup (opened, looked at, closed with Esc - nothing saved)
        if (t !== 'settings' && t !== 'overview') {
          const opened = await page.evaluate(() => {
            const b = [...document.querySelectorAll('.btn.primary')].find(x => {
              const r = x.getBoundingClientRect();
              return r.width > 0 && !x.closest('#modal') && /^(Přidat|Add)/.test(x.textContent.trim());
            });
            if (!b) return false;
            b.click();
            return true;
          });
          if (opened) {
            await page.waitForTimeout(1200);
            const m = await page.evaluate(() => !document.getElementById('modal').hidden);
            if (m) {
              run.pages[t + ' +add'] = await page.evaluate(englishLeft);
              if (shots) await page.screenshot({path: path.join(shots, `rv5-${t}-add-${w}.png`)});
              await page.keyboard.press('Escape');
              await page.waitForTimeout(500);
              if (await page.evaluate(() => !document.getElementById('modal').hidden)) {
                await page.keyboard.press('Escape');
                await page.waitForTimeout(400);
              }
            }
          }
        }
        if (t === 'settings') {
          const panes = await page.evaluate(() => [...document.querySelectorAll('[id^="pane-"]')].map(e => e.id.slice(5)));
          for (const p of panes) {
            await page.evaluate(p => { location.hash = '#settings/' + p; }, p);
            await page.waitForTimeout(900);
            run.pages['settings/' + p] = await page.evaluate(englishLeft);
            if (shots) await page.screenshot({path: path.join(shots, `rv5-settings-${p}-${w}.png`)});
          }
        }
      }
      // the portal
      await page.goto(base + '/index.php');
      await page.waitForTimeout(1500);
      run.pages['portal'] = await page.evaluate(englishLeft);
      if (shots) await page.screenshot({path: path.join(shots, `rv5-portal-${w}.png`)});
      out.runs.push(run);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
