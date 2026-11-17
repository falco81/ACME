// The pages' half of test/test_hunt_q3_fix.py, in Chromium.
//
//   node test/hunt_q3_fix_page.js BASE_URL NAME PASSWORD FILES_DIR
//
// Prints one line of JSON: what was seen.
//  - A revoked certificate: "revoked" in red in the list, no "… days left" beside its state in
//    its window, its life bar red.
//  - The window of an RSA 2048 one: its key said "RSA 2048" (not "RSA 2048 · 2048 bits").
//  - Import: one.crt + one.key dropped, then two.crt alone - the key of the first not kept.
//  - "CSR for an outside CA": a country of three letters (the CSR refused after the save), then
//    two - the CSR of the same certificate, not "there is one called … already".
//  - Push slots saved empty: Automatically, not "Nothing chosen".
//  - Taking a target away: "taken off with it" hidden while the switch is off.
//  - The main tabs at 375 px: what a tap at each one's middle hits is that tab.
const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const [base, name, pass, dir] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const page0 = async (w) => {
    const phone = w < 600;
    const ctx = await browser.newContext({viewport: {width: w, height: phone ? 800 : 1000},
                                          isMobile: phone, hasTouch: phone});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(600);
    return page;
  };
  const tab = async (page, t) => {
    await page.evaluate(t => document.querySelector('.tabs button[data-tab="' + t + '"]').click(), t);
    await page.waitForTimeout(800);
  };
  const shut = async (page) => {
    await page.evaluate(() => { MODAL_TYPED = 0; while (!document.getElementById('modal').hidden) closeModal(true); });
    await page.waitForTimeout(300);
  };
  const find = async (page, q) => {
    await page.fill('#ct-q', q);
    await page.waitForTimeout(1200);
    return page.locator('#ct-table tbody tr', {hasText: q}).first();
  };
  try {
    const page = await page0(1400);
    await tab(page, 'certs');

    // a revoked one in the list...
    let row = await find(page, 'q3-revoked');
    out.revokedList = await row.evaluate(tr => {
      const d = tr.querySelector('td.ct-exp .ct-days');
      return d ? {text: d.textContent.trim(), crit: d.classList.contains('crit')} : null;
    });
    // ...and its window
    await row.click();
    await page.waitForTimeout(1200);
    out.revokedHead = await page.evaluate(() => [...document.querySelectorAll('#modal-body .ct-head-t .ct-days')].map(x => x.textContent.trim()));
    out.revokedBar = await page.evaluate(() => { const s = document.querySelector('#modal-body .ct-life > span'); return s ? s.className : null; });
    await shut(page);

    // the key of an RSA 2048 one
    row = await find(page, 'q3-rsa');
    await row.click();
    await page.waitForTimeout(1200);
    out.keyRow = await page.evaluate(() => {
      const tr = [...document.querySelectorAll('#modal-body table tr')].filter(r => r.children[0] && r.children[0].textContent.trim() === 'Key')[0];
      return tr ? tr.children[1].textContent.trim() : null;
    });
    await shut(page);

    // import: a certificate with its key, then another alone
    await page.evaluate(() => document.getElementById('ct-import').click());
    await page.waitForTimeout(800);
    const inp = page.locator('#modal-body input[type=file]').first();
    await inp.setInputFiles([path.join(dir, 'one.crt'), path.join(dir, 'one.key')]);
    await page.waitForTimeout(2000);
    const words = () => page.evaluate(() => document.querySelector('#modal-body .ct-drop').textContent);
    out.dropFirst = await words();
    await inp.setInputFiles([path.join(dir, 'two.crt')]);
    await page.waitForTimeout(2000);
    out.dropSecond = await words();
    out.keyNameSecond = await page.evaluate(() => { const k = document.querySelector('#modal-body .ct-keyname'); return k ? k.textContent : null; });
    await shut(page);

    // a CSR for an outside CA: refused after the save (the first ask of its CSR fails), then
    // made - for the same certificate
    let csrAsked = 0;
    await page.route(u => /certs\/csr(\b|$)/.test(decodeURIComponent(u.toString())) && !/csr_/.test(decodeURIComponent(u.toString())), route => {
      csrAsked += 1;
      if (csrAsked === 1) return route.fulfill({status: 400, contentType: 'application/json', body: JSON.stringify({ok: false, error: 'openssl went away'})});
      return route.continue();
    });
    await page.evaluate(() => document.getElementById('ct-csr').click());
    await page.waitForTimeout(800);
    await page.locator('#modal-body textarea').first().fill('q3-csr-retry.example.test');
    await page.evaluate(() => {
      const f = [...document.querySelectorAll('#modal-body .formgrid input')];
      const name = f.filter(i => i.placeholder === 'the first name')[0] || f[0];
      name.value = 'q3-csr-retry';
      name.dispatchEvent(new Event('input', {bubbles: true}));
    });
    await page.locator('#modal-foot button.primary').last().click();
    await page.waitForTimeout(2500);
    out.csrFirst = await page.evaluate(() => [...document.querySelectorAll('.toast, #toasts *')].map(x => x.textContent).join(' | '));
    await page.locator('#modal-foot button.primary').last().click();
    await page.waitForTimeout(2500);
    out.csrSecond = await page.locator('#modal-title').innerText();
    out.csrToasts = await page.evaluate(() => [...document.querySelectorAll('.toast, #toasts *')].map(x => x.textContent).join(' | '));
    out.csrAsked = csrAsked;
    await page.unroute(() => true);
    await shut(page);

    // push slots saved empty
    out.slotsEmpty = await page.evaluate(() => {
      const f = window.ACME_FIELD_TYPES.push_slots({key: 'slots'}, '', {opts: {}});
      document.body.appendChild(f.input);
      const got = {picks: f.get(), nothing: f.input.querySelectorAll('.ps-none.bad').length};
      f.input.remove();
      return got;
    });
    out.slotsSet = await page.evaluate(() => {
      const f = window.ACME_FIELD_TYPES.push_slots({key: 'slots'}, ['node:a'], {opts: {}});
      f.set('');
      return f.get();
    });

    // a target taken away: the chip of a deployment with the switch off, then on
    await tab(page, 'targets');
    await page.waitForTimeout(800);
    const trow = page.locator('tr', {hasText: 'q3-target'}).first();
    await trow.locator('button.iconbtn').last().click();       // Take it away: the last of its tools
    await page.waitForTimeout(1500);
    const chips = () => page.evaluate(() => [...document.querySelectorAll('#modal-body .ct-use-tag.warn')].map(t => t.hidden || getComputedStyle(t).display === 'none'));
    out.chipOff = await chips();
    await page.evaluate(() => { const i = document.querySelector('#modal-body .sw input'); i.click(); });
    await page.waitForTimeout(300);
    out.chipOn = await chips();
    await shut(page);

    // the main tabs on a phone
    const phone = await page0(375);
    await page.waitForTimeout(800);
    out.tabs = await phone.evaluate(async () => {
      const got = [];
      for (const b of [...document.querySelectorAll('.tabs button')].filter(x => x.offsetParent)) {
        b.scrollIntoView({block: 'nearest', inline: 'center'});
        await new Promise(r => setTimeout(r, 60));
        const r = b.getBoundingClientRect();
        const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        got.push({tab: b.dataset.tab, hit: !!(hit && (hit === b || b.contains(hit))),
                  on: hit ? (hit.id || hit.className || hit.tagName) : null, top: Math.round(r.top)});
      }
      return got;
    });
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
