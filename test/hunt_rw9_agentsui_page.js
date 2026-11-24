// Hunt w9 (1.0.144) - Settings → Target agents and Agent fleet in Chromium against a real daemon
// (test/test_hunt_rw9_agentsui.py: daemon + php -S, agents seeded, three waiting to be confirmed):
//
//   node test/hunt_rw9_agentsui_page.js BASE_URL PASSWORD
//
// * Confirm selected… / Confirm all of this code…: the page asks agents/confirm-many, which the
//   pages' relay refused ("unknown endpoint", a word with "-") - no agent was ever confirmed so;
// * a target's long name (a host name, no space) on its tile: the page was wider than a phone;
// * the policy designer's "Start from": one click on "nothing" threw away what was typed and
//   clicked together - asked first now (No keeps it);
// * the take-over of a certificate found on a server: a source that does not issue for its names
//   (the default, a public CA, for .test names) - the preview said "allows all of it" and Take
//   over was refused by the daemon; now said, Take over off; the source changed asks the
//   preview again (it said the first source); once taken over it is not offered again (a
//   second certificate "NAME 2" was made, deployed to the same files);
// * in Czech: the notes of the designer's templates (they stayed English).
// Prints one line of JSON: {checks: {name: value}, errors: [...], error?}.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {checks: {}, errors: []};
  const open = async (lang, w) => {
    const ctx = await browser.newContext({viewport: {width: w, height: w > 500 ? 940 : 844}, deviceScaleFactor: 1});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    const tag = lang + w + '_';
    page.on('pageerror', e => out.errors.push(tag + String(e.message || e)));
    page.on('console', m => {
      if (m.type() === 'error' && !/favicon|Failed to load resource/.test(m.text())) out.errors.push(tag + 'console: ' + m.text());
    });
    /* a refusal the daemon answers is fine (an agent that is not there); "unknown endpoint" of
       the relay is not */
    page.on('response', async (r) => {
      if (r.status() === 404 && /api=/.test(r.url())) {
        let t = '';
        try { t = await r.text(); } catch (e) { /* gone */ }
        if (/unknown endpoint/.test(t)) out.errors.push(tag + 'relay refused ' + r.url());
      }
    });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(900);
    return [ctx, page];
  };
  const pane = async (page, name) => {
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.waitForTimeout(300);
    await page.evaluate((n) => document.querySelector('#ctl-nav button[data-pane="' + n + '"]').click(), name);
    await page.waitForTimeout(1800);
  };
  const close = async (page) => page.evaluate(() => { const m = document.getElementById('modal'); if (m && !m.hidden && typeof closeModal === 'function') closeModal(true); });
  try {
    // ---- the waiting agents confirmed together ----
    {
      const [ctx, page] = await open('en', 1400);
      await pane(page, 'agents');
      await page.waitForFunction(() => document.querySelectorAll('.ag-wrow').length >= 3, null, {timeout: 30000});
      out.checks.waiting_before = await page.evaluate(() => document.querySelectorAll('.ag-wrow').length);
      await page.evaluate(() => Array.from(document.querySelectorAll('.ag-wrow')).filter(r => /w9-wait-0[12]/.test(r.textContent)).forEach(r => r.querySelector('.ag-wpick').click()));
      await page.waitForTimeout(200);
      out.checks.selected_words = await page.evaluate(() => document.querySelector('.ag-wait-h button').textContent.trim());
      await page.evaluate(() => document.querySelector('.ag-wait-h button').click());
      await page.waitForTimeout(500);
      await page.evaluate(() => document.querySelector('#modal-foot .btn.primary').click());
      await page.waitForFunction(() => document.querySelectorAll('.ag-wrow').length === 1, null, {timeout: 30000}).catch(() => {});
      out.checks.waiting_after = await page.evaluate(() => Array.from(document.querySelectorAll('.ag-wrow .dbs-tile-n')).map(x => x.textContent));
      out.checks.confirmed_toast = await page.evaluate(() => document.getElementById('toast').innerText);
      // ---- the designer: Start from asks before it throws away ----
      await page.evaluate(() => { const t = Array.from(document.querySelectorAll('.ag-tile')).filter(x => x.querySelector('.dbs-tile-n').textContent === 'web-prague-01')[0];
        Array.from(t.querySelectorAll('button')).filter(b => /Design/.test(b.textContent))[0].click(); });
      await page.waitForFunction(() => document.querySelector('#pb-s-files'), null, {timeout: 30000});
      await page.waitForTimeout(500);
      const dirs = () => page.evaluate(() => Array.from(document.querySelectorAll('#pb-s-files input')).map(i => i.value).filter(v => v.indexOf('/') === 0));
      await page.evaluate(() => Array.from(document.querySelectorAll('#pb-s-files button')).filter(b => /Add a folder/.test(b.textContent))[0].click());
      await page.waitForTimeout(300);
      const ins = await page.$$('#pb-s-files input');
      for (const i of ins) { if (!(await i.inputValue())) { await i.fill('/srv/w9-typed'); break; } }
      await page.waitForTimeout(300);
      out.checks.typed = await dirs();
      await page.evaluate(() => Array.from(document.querySelectorAll('.pb-seg-b')).filter(b => /nothing/.test(b.textContent))[0].click());
      await page.waitForTimeout(400);
      out.checks.start_asked = await page.evaluate(() => (document.querySelector('.gd-sure') || {}).innerText || '');
      await page.evaluate(() => { const b = document.querySelector('.gd-sure-no'); if (b) b.click(); });
      await page.waitForTimeout(300);
      out.checks.kept_on_no = await dirs();
      await page.evaluate(() => Array.from(document.querySelectorAll('.pb-seg-b')).filter(b => /nothing/.test(b.textContent))[0].click());
      await page.waitForTimeout(300);
      await page.evaluate(() => { const b = document.querySelector('.gd-sure-yes'); if (b) b.click(); });
      await page.waitForTimeout(400);
      out.checks.empty_on_yes = await dirs();
      // back to the server's: nothing changed since "nothing" - not asked
      await page.evaluate(() => document.querySelectorAll('.pb-seg-b')[0].click());
      await page.waitForTimeout(400);
      out.checks.not_asked_unchanged = await page.evaluate(() => !document.querySelector('.gd-sure'));
      out.checks.server_again = await dirs();
      await close(page);
      await ctx.close();
    }
    // ---- a long name on a phone ----
    for (const lang of ['en', 'cs']) {
      const [ctx, page] = await open(lang, 390);
      await pane(page, 'agents');
      await page.waitForFunction(() => document.querySelectorAll('.ag-tile').length >= 5, null, {timeout: 30000});
      out.checks[lang + '_phone_width'] = await page.evaluate(() => document.documentElement.scrollWidth);
      out.checks[lang + '_long_tile'] = await page.evaluate(() => { const n = Array.from(document.querySelectorAll('.ag-tile .dbs-tile-n')).filter(x => /^w9-long/.test(x.textContent))[0];
        if (!n) return 'none'; const r = n.getBoundingClientRect(), t = n.closest('.ag-tile').getBoundingClientRect(); return r.right <= t.right + 1 && r.width > 0; });
      await ctx.close();
    }
    // ---- the take-over ----
    for (const lang of ['en', 'cs']) {
      const [ctx, page] = await open(lang, 1400);
      await pane(page, 'fleet');
      await page.waitForFunction(() => document.querySelector('#fl-root .fl-hero'), null, {timeout: 30000});
      await page.evaluate(() => document.querySelectorAll('.fl-tab')[4].click());
      await page.waitForFunction(() => document.querySelector('.fl-um-r'), null, {timeout: 30000});
      await page.waitForTimeout(500);
      if (lang === 'en') {
        await page.evaluate(() => document.querySelector('.fl-um-a .btn.primary').click());
        await page.waitForFunction(() => document.querySelector('.fl-to-g') && document.querySelector('.fl-to-s'), null, {timeout: 30000});
        await page.waitForTimeout(600);
        const st = () => page.evaluate(() => ({
          steps: Array.from(document.querySelectorAll('.fl-to-s')).map(x => x.textContent),
          refused: (document.querySelector('.fl-to-refused') || {}).textContent || '',
          take: (Array.from(document.querySelectorAll('#modal-foot .btn')).filter(b => /Take over/.test(b.textContent))[0] || {}).disabled}));
        out.checks.to_public = await st();
        await page.selectOption('#modal-box select', 'own');
        await page.waitForTimeout(2000);
        out.checks.to_own = await st();
        await page.evaluate(() => Array.from(document.querySelectorAll('#modal-foot .btn')).filter(b => /Take over/.test(b.textContent))[0].click());
        await page.waitForTimeout(3000);
        out.checks.to_toast = await page.evaluate(() => document.getElementById('toast').innerText);
        await close(page);
        await page.waitForFunction(() => document.querySelector('.fl-um-taken'), null, {timeout: 30000}).catch(() => {});
      }
      out.checks[lang + '_taken'] = await page.evaluate(() => Array.from(document.querySelectorAll('.fl-um-r')).filter(r => /shop\.example\.test/.test(r.textContent))
        .map(r => ({taken: (r.querySelector('.fl-um-taken') || {}).textContent || '', take: !!r.querySelector('.fl-um-a .btn.primary')}))[0] || null);
      await ctx.close();
    }
    // ---- Czech: the designer's templates said in Czech, their notes too ----
    {
      const [ctx, page] = await open('cs', 1400);
      out.checks.cs_notes = await page.evaluate(() => ['The same paths on RHEL and Debian (/etc/nginx/ssl).', 'Its unit and its folder are examples - change them to yours.',
        'Start again from it? What was changed here is lost.', 'acme does not make this certificate from this source - choose another source or change the names']
        .map(function (w) { return i18nText(w) ? 1 : w; }));
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
