// The pages' half of test/test_hunt_rw8_newuser.py (hunt w8, a new administrator's first steps).
//
//   node test/hunt_rw8_newuser_page.js BASE_URL PASSWORD [screenshot-folder]
//
// - Owners and teams, "Certificates on the portal is off" → Open the setting: the setting itself
//   brought into view and given the focus (it opened the pane at its top, far above it).
// - Backups, "Download one here" with no password: said, and the password's field given the focus.
// - The portal's form to ask for a certificate when no name may be asked yet: said so - not
//   "Names under:" with nothing after it; asked anyway, the same words (not "Only names under
//   may be asked for here").
// - The certificate wizard's Review while the validation is not in place: the note speaks of the
//   button that is there ("Create anyway"), and says how to go on where the CA sees the names
//   otherwise (Settings → Renewal and notices → Check the validation before the CA is asked).
// English and Czech, 1400 and 390 px. Prints one line of JSON.
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], overflow: {}, portalSetting: {}, backupFocus: {}, ask: {}, review: {}};
  const watch = (page, tag) => {
    page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
    page.on('console', m => {
      if (m.type() !== 'error') return;
      const t = m.text();
      if (/status of 40[39]/.test(t)) return;
      out.errors.push(tag + ' console: ' + t.slice(0, 200));
    });
    page.on('dialog', async d => { out.errors.push(tag + ' browser dialog: ' + d.message()); await d.dismiss(); });
  };
  const context = async (lang, w) => {
    const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    return ctx;
  };
  const over = page => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  const admin = async (ctx, tag) => {
    const page = await ctx.newPage();
    watch(page, tag);
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(1500);
    return page;
  };
  const pane = async (page, name) => {
    await page.evaluate(n => { location.hash = '#settings/' + n; }, name);
    await page.waitForTimeout(1800);
  };
  const focusKey = page => page.evaluate(() => {
    const a = document.activeElement, it = a && a.closest('.set-item');
    if (!it) return null;
    const r = it.getBoundingClientRect();
    return {key: it.dataset.key, seen: r.top >= 0 && r.bottom <= window.innerHeight + 1};
  });
  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `${lang}-${w}`;
      const ctx = await context(lang, w);
      const page = await admin(ctx, tag);
      // ---- Owners and teams → Open the setting (the portal's certificates off for it) ----
      await page.evaluate(() => api('settings', {settings: {portal_cert: 0}}));
      await pane(page, 'teams');
      const go = page.locator('#pane-teams .tm-portal-off button').first();
      if (await go.count()) {
        await go.click();
        await page.waitForTimeout(2000);
        out.portalSetting[tag] = await focusKey(page);
      } else out.portalSetting[tag] = 'no warning';
      if (await over(page) > 1) out.overflow[tag + ' teams'] = await over(page);
      // ---- Backups → Download one here, no password ----
      await pane(page, 'backup');
      await page.locator('#pane-backup button').filter({hasText: lang === 'cs' ? /Stáhnout/ : /Download one here/}).first().click();
      await page.waitForTimeout(1500);
      out.backupFocus[tag] = await focusKey(page);
      await page.evaluate(() => api('settings', {settings: {portal_cert: 1}}));
      // ---- the wizard's Review, the validation not in place ----
      await page.evaluate(() => showTab('certs'));
      await page.waitForTimeout(1200);
      await page.locator('#tab-certs button.primary:visible').filter({hasText: lang === 'cs' ? /Přidat certifikát/ : /Add a certificate/}).first().click();
      await page.waitForTimeout(1500);
      const dlg = page.getByRole('dialog');
      await dlg.locator('.ct-src').filter({hasText: 'OwnAcme'}).first().click();
      const next = dlg.getByRole('button', {name: lang === 'cs' ? 'Další' : 'Next', exact: true});
      await next.click();
      await page.waitForTimeout(1200);
      await dlg.locator('input[placeholder="www.example.com"]').last().fill('localhost');
      for (let i = 0; i < 9 && await next.count(); i++) {
        await next.last().click();
        await page.waitForTimeout(1500);
      }
      await page.waitForSelector('[role=dialog] .ct-rd-review .ct-errbox, [role=dialog] .ct-rd-review .good', {timeout: 60000}).catch(() => {});
      await page.waitForTimeout(1200);
      out.review[tag] = await page.evaluate(() => {
        const d = document.querySelector('[role=dialog]');
        const note = d.querySelector('.ct-modal-body p.note, p.note');
        const skip = d.querySelector('.ct-rd-skip');
        return {note: note ? note.innerText : '', skip: skip ? skip.innerText : '',
                blocked: !!d.querySelector('.ct-rd-review .ct-errbox'),
                buttons: [...d.querySelectorAll('button')].filter(b => b.getClientRects().length).map(b => b.innerText.trim()).filter(Boolean)};
      });
      if (await over(page) > 1) out.overflow[tag + ' review'] = await over(page);
      if (shots) await page.screenshot({path: path.join(shots, `rw8-review-${tag}.png`)});
      await ctx.close();
      // ---- the portal: asking with no name open to it ----
      const pctx = await context(lang, w);
      const pp = await pctx.newPage();
      watch(pp, 'portal-' + tag);
      await pp.goto(base + '/');
      await pp.fill('#in-name', 'wnu');
      await pp.fill('#in-pass', pass);
      await pp.click('#in-go');
      await pp.waitForSelector('#pw-nav, #cp-list', {timeout: 30000});
      await pp.waitForTimeout(1500);
      // hunt w9: with nothing open to asking the button is dimmed (its reason under it) - the
      // form's own words are still looked at, opened as the button would
      const askBtn = pp.locator('#pw-ask, #pw-ask-c, #cp-ask').filter({visible: true}).first();
      if (await askBtn.isEnabled()) await askBtn.click();
      else await pp.evaluate(() => window.ACME_PORTAL_CERTS.askStart());
      await pp.waitForTimeout(1500);
      const pd = pp.getByRole('dialog');
      const hint = await pd.locator('.says').first().innerText();
      await pd.locator('textarea').first().fill('www.rw8.example.test');
      await pd.locator('button.primary').last().click();
      await pp.waitForTimeout(2000);
      const said = await pd.locator('.said').first().innerText().catch(() => '');
      out.ask[tag] = {hint, said};
      if (await over(pp) > 1) out.overflow[tag + ' portal'] = await over(pp);
      if (shots) await pp.screenshot({path: path.join(shots, `rw8-ask-${tag}.png`)});
      await pctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
