// Discovery through acme-agent (1.0.125, agents.js "Found on this server") in Chromium against a real
// daemon (test/test_agent_discovery.py's Pages: daemon + php -S, the agents' state and a kept
// discovery put in its database).
//
//   node test/agents_discovery_page.js BASE_URL PASSWORD
//
// For English and Czech at 1400, 768 and 390 px: the card of web1 (Linux, discovery allowed) - a
// card per service found, the certificates acme does not manage; nothing wider than the page or
// its popup. At 1400 (and 390 in Czech): "Make a deployment" of the nginx site www opens the
// deployment dialog with its certificate (acme's) and the files where nginx reads them (format,
// path, mode), the test and the reload; "Add to the policy" opens the designer with its lines
// ticked; "Watch it" a test of what api.example.test:8443 serves. win1 (Windows): "Make a
// deployment" of IIS - the machine store and the site's bindings. lin0 (not allowed): the hint
// with the line that allows it.
// Prints one line of JSON: {checks: {name: value}, errors: [...], error?}.
const { chromium } = require('playwright');

(async () => {
  const [base, pass] = process.argv.slice(2);
  const shots = process.env.ACME_TEST_SHOTS || '';
  const browser = await chromium.launch();
  const out = {checks: {}, errors: []};
  const signIn = async (lang, w) => {
    const ctx = await browser.newContext({viewport: {width: w, height: 900}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(lang + w + ': ' + String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', 'tester');
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForFunction(() => document.querySelector('.ct-ovtile'), null, {timeout: 30000});
    await page.waitForTimeout(800);
    return page;
  };
  const openTarget = async (page, name, sel, fresh) => {
    if (fresh) {
      /* the popups opened before gone: the page again (the session stays) */
      page.once('dialog', d => d.accept().catch(() => {}));
      await page.goto(base + '/admin/index.php');
      await page.waitForFunction(() => document.querySelector('.ct-ovtile'), null, {timeout: 30000});
      await page.waitForTimeout(500);
    }
    await page.evaluate((n) => window.ACME_AGENTS_HANDS.openTarget(n), name);
    await page.waitForFunction((s) => document.querySelector(s), sel, {timeout: 30000});
    await page.waitForTimeout(500);
  };
  const fits = (page) => page.evaluate(() => {
    if (document.documentElement.scrollWidth > window.innerWidth + 1) return 'page ' + document.documentElement.scrollWidth;
    const bad = [];
    document.querySelectorAll('.ag-disc, .ag-disc *').forEach((x) => {
      const r = x.getBoundingClientRect();
      if (r.width && (r.right > window.innerWidth + 1 || r.left < -1)) bad.push(x.className + ' ' + Math.round(r.left) + '-' + Math.round(r.right));
    });
    const mb = document.getElementById('modal-body');
    if (mb && mb.scrollWidth > mb.clientWidth + 1) bad.push('modal ' + mb.scrollWidth + '>' + mb.clientWidth);
    return bad.length ? bad.slice(0, 4).join('; ') : true;
  });
  const cardOf = (text) => `Array.from(document.querySelectorAll('.ag-dc')).filter(c => c.textContent.indexOf(${JSON.stringify(text)}) >= 0)[0]`;
  try {
    for (const [lang, w] of [['en', 1400], ['en', 768], ['en', 390], ['cs', 1400], ['cs', 768], ['cs', 390]]) {
      const tag = lang + w + '_';
      const page = await signIn(lang, w);
      await openTarget(page, 'web1', '.ag-disc .ag-dc');
      out.checks[tag + 'cards'] = await page.evaluate(() => document.querySelectorAll('.ag-disc .ag-dc').length);
      out.checks[tag + 'head'] = await page.evaluate(() => document.querySelector('.ag-disc-h b').textContent);
      out.checks[tag + 'unmanaged'] = await page.evaluate(() => document.querySelectorAll('.ag-du-r').length);
      out.checks[tag + 'acme_badge'] = await page.evaluate((c) => { const x = eval(c); return x ? x.querySelector('.ag-dc-acme').textContent : ''; }, cardOf('www.example.test'));
      out.checks[tag + 'buttons'] = await page.evaluate((c) => { const x = eval(c); return x ? Array.from(x.querySelectorAll('.ag-dc-acts .btn')).map(b => b.textContent.trim()) : []; }, cardOf('www.example.test'));
      out.checks[tag + 'fits'] = await fits(page);
      if (shots) {
        await page.evaluate(() => { const d = document.querySelector('.ag-disc'); if (d) d.scrollIntoView(); });
        await page.waitForTimeout(300);
        await page.screenshot({path: shots + '/' + tag + 'card.png', fullPage: false});
        const el = await page.$('.ag-disc');
        if (el) await el.screenshot({path: shots + '/' + tag + 'disc.png'});
      }
      if (!(w === 1400 || (lang === 'cs' && w === 390))) { await page.context().close(); continue; }
      // ---- Make a deployment: the dialog prefilled ----
      await page.evaluate((c) => eval(c).querySelector('.ag-dc-deploy').click(), cardOf('www.example.test'));
      await page.waitForFunction(() => document.querySelectorAll('.df-path').length >= 2, null, {timeout: 30000});
      await page.waitForTimeout(500);
      out.checks[tag + 'deploy'] = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll('.df-rows .df-row:not(.df-head)'));
        return {
          files: rows.map(r => [r.querySelector('.df-fmt') && r.querySelector('.df-fmt').value, r.querySelector('.df-path').value,
            r.querySelector('.df-mode') ? r.querySelector('.df-mode').value : '']).filter(x => x[1]),
          cert: (document.querySelector('.dp-chosen b') || {}).textContent || '',
          values: Array.from(document.querySelectorAll('#modal-body textarea, #modal-body input')).map(x => x.value).filter(Boolean),
          preset: (document.querySelector('.df-preset') || {}).value || ''};
      });
      out.checks[tag + 'deploy_fits'] = await fits(page);
      if (shots) await page.screenshot({path: shots + '/' + tag + 'deploy.png'});
      // ---- Add to the policy: the designer, its lines ticked ----
      await openTarget(page, 'web1', '.ag-disc .ag-dc', true);
      await page.evaluate((c) => eval(c).querySelector('.ag-dc-policy').click(), cardOf('www.example.test'));
      await page.waitForFunction(() => document.querySelector('.pb') && document.querySelector('#pb-s-found'), null, {timeout: 30000});
      await page.waitForTimeout(500);
      out.checks[tag + 'policy'] = await page.evaluate(() => {
        const pre = Array.from(document.querySelectorAll('.pb pre')).map(p => p.textContent).join('\n');
        return {text: pre, found: document.querySelectorAll('#pb-s-found .pb-found').length,
          yes: document.querySelectorAll('#pb-s-found .pb-need.yes').length,
          nav: (document.querySelector('.pb-nav') || {}).textContent || '',
          discChips: document.querySelectorAll('#pb-s-discover .pb-chip-add').length};
      });
      out.checks[tag + 'policy_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) {
        await page.evaluate(() => { const d = document.querySelector('#pb-s-found'); if (d) d.scrollIntoView(); });
        await page.waitForTimeout(300);
        await page.screenshot({path: shots + '/' + tag + 'builder.png'});
      }
      // ---- Watch it: a test of what api.example.test:8443 serves ----
      await openTarget(page, 'web1', '.ag-disc .ag-dc', true);
      await page.evaluate((c) => eval(c).querySelector('.ag-dc-watch').click(), cardOf('api.example.test'));
      await page.waitForFunction(() => Array.from(document.querySelectorAll('#modal-body input')).some(x => x.value === '8443'), null, {timeout: 30000}).catch(() => {});
      out.checks[tag + 'watch'] = await page.evaluate(() => Array.from(document.querySelectorAll('#modal-body input')).map(x => x.value).filter(Boolean));
      // ---- Windows: IIS, the machine store and the site's bindings ----
      await openTarget(page, 'win1', '.ag-disc .ag-dc', true);
      out.checks[tag + 'win_cards'] = await page.evaluate(() => Array.from(document.querySelectorAll('.ag-disc .ag-dc .ag-dc-ic')).map(x => x.textContent));
      out.checks[tag + 'win_fits'] = await fits(page);
      if (shots) { const el = await page.$('.ag-disc'); if (el) await el.screenshot({path: shots + '/' + tag + 'win.png'}); }
      await page.evaluate((c) => eval(c).querySelector('.ag-dc-deploy').click(), cardOf('Default Web Site'));
      await page.waitForFunction(() => Array.from(document.querySelectorAll('#modal-body textarea')).some(x => x.value.indexOf('Default Web Site') >= 0), null, {timeout: 30000}).catch(() => {});
      out.checks[tag + 'win_deploy'] = await page.evaluate(() => Array.from(document.querySelectorAll('#modal-body textarea')).map(x => x.value).filter(Boolean));
      // ---- lin0: not allowed - the line that allows it ----
      await openTarget(page, 'lin0', '.ag-disc .ag-disc-off', true);
      out.checks[tag + 'off'] = await page.evaluate(() => (document.querySelector('.ag-disc-off pre') || {}).textContent || '');
      out.checks[tag + 'off_fits'] = await fits(page);
      if (shots) { const el = await page.$('.ag-disc'); if (el) await el.screenshot({path: shots + '/' + tag + 'off.png'}); }
      await page.context().close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
