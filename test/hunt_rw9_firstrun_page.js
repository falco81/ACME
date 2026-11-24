// The pages' half of test/test_hunt_rw9_firstrun.py (hunt w9, a new administrator's next steps).
//
//   node test/hunt_rw9_firstrun_page.js BASE_URL PASSWORD [screenshot-folder]
//
// English and Czech, 1400 and 390 px: the first start's validation in the page's language; the
// names a new ACME source and a folder target are offered; a module's window - its guide opened
// from the line that named a file, the HTTP-01 module's own check by its new name; the wizard's
// Review where Let's Encrypt staging refuses a .test name; the portal's certificates on with no
// name open to asking - the setting's warning, Owners and teams', the member's dimmed button.
// Prints one line of JSON.
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], overflow: {}, tags: {}};
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
  const shot = async (page, name) => { if (shots) await page.screenshot({path: path.join(shots, name + '.png')}); };
  const closeAll = async page => {
    for (let i = 0; i < 4; i++) {
      if (!await page.locator('[role=dialog]').count()) break;
      await page.keyboard.press('Escape');
      await page.waitForTimeout(400);
    }
  };
  const pane = async (page, name) => {
    await page.evaluate(n => { location.hash = '#settings/' + n; }, name);
    await page.waitForTimeout(1800);
  };
  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const tag = `${lang}-${w}`;
      const s = out.tags[tag] = {};
      const ctx = await context(lang, w);
      const page = await ctx.newPage();
      watch(page, tag);
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1500);
      // ---- Validation: the first start's row in the page's language ----
      await page.evaluate(() => showTab('validation'));
      await page.waitForSelector('#val-list td.ct-modname b', {timeout: 30000});
      await page.waitForTimeout(800);
      Object.assign(s, await page.evaluate(() => {
        const bs = [...document.querySelectorAll('#val-list td.ct-modname b')];
        // its stored name said on hover (the title made an explanation: aria-label, the panel)
        const said = b => b.title || b.getAttribute('aria-label') || '';
        const own = bs.find(b => said(b) === 'This server HTTP-01') || bs.find(b => b.textContent === 'This server HTTP-01');
        return {valNames: bs.map(b => b.textContent), valTitle: own ? said(own) : '', dbg: bs.map(b => b.outerHTML).join(' ')};
      }));
      if (await over(page) > 1) out.overflow[tag + ' validation'] = await over(page);
      await shot(page, `rw9-validation-${tag}`);
      // ---- the HTTP-01 module's window: its own check by its new name ----
      await page.evaluate(() => { const c = ACME_CERTS.ctx; return c.plugins().then(() => c.modForm('validation', null, c.plugVersion(c.plugOf('challenge', 'http_local')), true)); });
      await page.waitForSelector('[role=dialog] .ct-basic input', {timeout: 20000});
      await page.waitForTimeout(600);
      s.httpLabels = await page.evaluate(() => [...document.querySelectorAll('[role=dialog] label, [role=dialog] .ff-label, [role=dialog] .lbl')].map(x => x.innerText.trim()).join(' | '));
      await closeAll(page);
      // ---- a new ACME source: its name, its window's line about the document ----
      await page.evaluate(() => showTab('sources'));
      await page.waitForTimeout(1200);
      await page.evaluate(() => { const c = ACME_CERTS.ctx; return c.plugins().then(() => c.loadRows('sources')).then(() => c.modForm('sources', null, c.plugVersion(c.plugOf('issuer', 'acme')), true)); });
      await page.waitForSelector('[role=dialog] .ct-basic input', {timeout: 20000});
      await page.waitForTimeout(600);
      s.acmeName = await page.locator('[role=dialog] .ct-basic input').first().inputValue();
      s.docLine = await page.locator('[role=dialog] .ct-plughead-doc').first().innerText().catch(() => '');
      if (await over(page) > 1) out.overflow[tag + ' source'] = await over(page);
      await shot(page, `rw9-source-${tag}`);
      await page.locator('[role=dialog] .ct-plughead-doc button').first().click();
      await page.waitForTimeout(1500);
      s.guideOpened = await page.evaluate(() => !!document.querySelector('.gd-content') && !/Asking/.test(document.querySelector('.gd-content').innerText.slice(0, 20)));
      await closeAll(page);
      // ---- a new target writing files here: its name ----
      await page.evaluate(() => showTab('targets'));
      await page.waitForTimeout(1200);
      await page.evaluate(() => { const c = ACME_CERTS.ctx; return c.plugins().then(() => c.loadRows('targets')).then(() => c.modForm('targets', null, c.plugVersion(c.plugOf('target', 'local')), true)); });
      await page.waitForSelector('[role=dialog] .ct-basic input', {timeout: 20000});
      s.localName = await page.locator('[role=dialog] .ct-basic input').first().inputValue();
      await closeAll(page);
      // ---- the wizard's Review: Let's Encrypt staging and a .test name ----
      await page.evaluate(() => showTab('certs'));
      await page.waitForTimeout(1200);
      await page.locator('#tab-certs button.primary:visible').filter({hasText: lang === 'cs' ? /Přidat certifikát/ : /Add a certificate/}).first().click();
      await page.waitForTimeout(1500);
      const dlg = page.getByRole('dialog');
      await dlg.locator('.ct-src').filter({hasText: /LetsEncrypt (staging|– zkušební)/}).first().click();
      const next = dlg.getByRole('button', {name: lang === 'cs' ? 'Další' : 'Next', exact: true});
      await next.click();
      await page.waitForTimeout(1200);
      await dlg.locator('input[placeholder="www.example.com"]').last().fill('www.rw9.example.test');
      for (let i = 0; i < 9 && await next.count(); i++) {
        await next.last().click();
        await page.waitForTimeout(1500);
      }
      await page.waitForSelector('[role=dialog] .ct-compat', {timeout: 60000}).catch(() => {});
      await page.waitForTimeout(800);
      s.review = await page.evaluate(() => {
        const d = document.querySelector('[role=dialog]');
        const note = d.querySelector('.ct-modal-body p.note, p.note');
        return {note: note ? note.innerText : '', blocked: !!d.querySelector('.ct-compat'),
                buttons: [...d.querySelectorAll('button')].filter(b => b.getClientRects().length).map(b => b.innerText.trim()).filter(Boolean)};
      });
      if (await over(page) > 1) out.overflow[tag + ' review'] = await over(page);
      await shot(page, `rw9-review-${tag}`);
      await closeAll(page);
      // ---- the enrolment pages' settings: the warning under the switch ----
      await pane(page, 'portal');
      s.settingWarn = await page.evaluate(() => {
        const x = document.querySelector('.set-item[data-key="portal_cert"] .portal-ask-warn');
        if (x) x.scrollIntoView({block: 'center'});
        return x && x.getClientRects().length ? x.innerText : '';
      });
      if (await over(page) > 1) out.overflow[tag + ' settings'] = await over(page);
      await shot(page, `rw9-settings-${tag}`);
      // ---- Owners and teams: said there too ----
      await pane(page, 'teams');
      s.teamsWarn = await page.evaluate(() => { const x = document.querySelector('#pane-teams .tm-portal-noask'); return x ? x.innerText : ''; });
      if (await over(page) > 1) out.overflow[tag + ' teams'] = await over(page);
      await ctx.close();
      // ---- the portal: the member's button dimmed, and why ----
      const pctx = await context(lang, w);
      const pp = await pctx.newPage();
      watch(pp, 'portal-' + tag);
      await pp.goto(base + '/');
      await pp.fill('#in-name', 'wfr');
      await pp.fill('#in-pass', pass);
      await pp.click('#in-go');
      await pp.waitForSelector('#pw-nav, #cp-list', {timeout: 30000});
      await pp.waitForSelector('.cp-ask-off', {timeout: 15000}).catch(() => {});
      await pp.waitForTimeout(800);
      s.portal = await pp.evaluate(() => {
        const b = document.querySelector('#pw-ask, #pw-ask-c, #cp-ask');
        const why = document.querySelector('.cp-ask-off');
        return {disabled: !!(b && b.disabled), why: why ? why.innerText : ''};
      });
      if (await over(pp) > 1) out.overflow[tag + ' portal'] = await over(pp);
      await shot(pp, `rw9-portal-${tag}`);
      await pctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
