// The pages' half of test/test_hunt_q4_fix.py, in Chromium.
//
//   node test/hunt_q4_fix_page.js BASE_URL NAME PASSWORD RO_NAME
//
// Prints one line of JSON: what was seen.
//  - DNS sets: Test from the form with the servers box empty - not the set as saved.
//  - Request profiles: one whose source was deleted - said so, the source not changed to the
//    first; a save refused - said in Czech, as every refusal.
//  - Guides: a link with spaces and brackets in its address kept after a save and shown.
//  - A read-only account opening #settings/sshkeys or #settings/modules: not those panes.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, roName] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const signIn = async (who, lang, hash) => {
    const ctx = await browser.newContext({viewport: {width: 1300, height: 1000}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    page.on('dialog', d => { out.errors.push('dialog: ' + d.message()); d.dismiss(); });
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', who);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    if (hash) {
      await page.goto(base + '/admin/index.php' + hash);
      await page.waitForTimeout(2500);
    }
    return page;
  };
  const pane = async (page, p) => {
    await page.evaluate(() => document.querySelector('.tabs button[data-tab="settings"]').click());
    await page.waitForTimeout(300);
    await page.evaluate(p => document.querySelector('#ctl-nav button[data-pane="' + p + '"]').click(), p);
    await page.waitForTimeout(1200);
  };
  const shut = async (page) => {
    await page.evaluate(() => { MODAL_TYPED = 0; while (!document.getElementById('modal').hidden) closeModal(true); });
    await page.waitForTimeout(300);
  };
  try {
    const page = await signIn(name, 'en');
    const ask = (what, body) => page.evaluate(([w, b]) => api(w, b), [what, body]);

    // ---- DNS sets: Test from the form, the servers box emptied ----
    await ask('dnssets-save', {name: 'q4 set', servers: '192.0.2.53'});
    await pane(page, 'dnssets');
    const row = page.locator('#dnss-host table.dnss-sets tbody tr', {hasText: 'q4 set'});
    await row.waitFor({timeout: 20000});
    await row.locator('.dnss-edit').click();
    await page.waitForTimeout(500);
    await page.fill('#dnss-f-servers', '  ');
    await page.locator('#modal-foot button', {hasText: 'Test'}).click();
    await page.waitForTimeout(800);
    out.dnsTitle = await page.locator('#modal-title').innerText();
    out.dnsToast = await page.evaluate(() => { const t = document.querySelector('.toast.show.bad'); return t ? t.textContent : ''; });
    await shut(page);

    // ---- Request profiles: the source deleted ----
    await pane(page, 'reqprofiles');
    await page.locator('#rp-host tr.rp-row', {hasText: 'q4-gone'}).waitFor({timeout: 20000});
    await page.locator('#rp-host tr.rp-row', {hasText: 'q4-gone'}).locator('.rp-edit').click();
    await page.waitForTimeout(800);
    out.rpIssuer = await page.locator('#rp-f-issuer').inputValue();
    out.rpWarn = await page.evaluate(() => { const w = document.querySelector('#modal-body .rp-gone'); return w && !w.hidden ? w.textContent : ''; });
    out.rpKeys = await page.evaluate(() => Array.from(document.querySelectorAll('#modal-body input[type=checkbox]')).filter(c => c.checked).length);
    await page.locator('#modal-foot button.primary').last().click();
    await page.waitForTimeout(1500);
    out.rpSaid = await page.evaluate(() => { const s = document.querySelector('#modal-body .said:not(.rp-gone)'); return s ? s.textContent : ''; });
    out.rpToast = await page.evaluate(() => { const t = document.querySelector('.toast.show.bad'); return t ? t.textContent : ''; });
    out.rpAfter = (await ask('reqprofiles')).profiles.find(p => p.name === 'q4-gone').issuer;
    // a source there: the warning hidden
    await page.selectOption('#rp-f-issuer', 'q4-self');
    await page.waitForTimeout(300);
    out.rpWarnPicked = await page.evaluate(() => { const w = document.querySelector('#modal-body .rp-gone'); return w && !w.hidden ? w.textContent : ''; });
    await shut(page);
    // one whose source is there: nothing said
    await page.locator('#rp-host tr.rp-row', {hasText: 'q4-fine'}).locator('.rp-edit').click();
    await page.waitForTimeout(800);
    out.rpFineIssuer = await page.locator('#rp-f-issuer').inputValue();
    out.rpFineWarn = await page.evaluate(() => !!document.querySelector('#modal-body .rp-gone:not([hidden])'));
    await shut(page);

    // ---- Guides: a link with spaces and brackets in its address ----
    out.guide = await page.evaluate(() => {
      const E = window.ACME_GUIDE_EDITOR, G = window.ACME_GUIDES;
      if (!E || !G) return null;
      const got = {};
      for (const href of ['https://example.test/a b (c', 'https://example.test/x(y)z', 'http://[2001:db8::1]/p q']) {
        const md = E.toMd(new DOMParser().parseFromString('<p>see <a href="' + href + '">the page</a></p>', 'text/html').body);
        const node = G.render(md).node;
        const a = node.querySelector('a');
        got[href] = {md: md.trim(), href: a ? a.getAttribute('href') : null, words: a ? a.textContent : null};
      }
      return got;
    });

    // ---- the same refusal in Czech ----
    const cs = await signIn(name, 'cs');
    await pane(cs, 'reqprofiles');
    await cs.locator('#rp-host tr.rp-row', {hasText: 'q4-gone'}).waitFor({timeout: 20000});
    await cs.locator('#rp-host tr.rp-row', {hasText: 'q4-gone'}).locator('.rp-edit').click();
    await cs.waitForTimeout(800);
    await cs.locator('#modal-foot button.primary').last().click();
    await cs.waitForTimeout(1500);
    out.rpSaidCs = await cs.evaluate(() => { const s = document.querySelector('#modal-body .said:not(.rp-gone)'); return s ? s.textContent : ''; });
    out.rpToastCs = await cs.evaluate(() => { const t = document.querySelector('.toast.show.bad'); return t ? t.textContent : ''; });
    await shut(cs);
    // a refusal with a name in it
    await cs.locator('#rp-host tr.rp-row', {hasText: 'q4-fine'}).locator('.rp-edit').click();
    await cs.waitForTimeout(800);
    await cs.fill('#rp-f-name', 'q4-gone');
    await cs.locator('#modal-foot button.primary').last().click();
    await cs.waitForTimeout(1500);
    out.rpTakenCs = await cs.evaluate(() => { const s = document.querySelector('#modal-body .said:not(.rp-gone)'); return s ? s.textContent : ''; });

    // ---- a read-only account from a link ----
    out.ro = {};
    for (const p of ['sshkeys', 'modules', 'dnssets']) {
      const ro = await signIn(roName, 'en', '#settings/' + p);
      out.ro[p] = await ro.evaluate(() => ({pane: PANE, hash: location.hash,
        shown: Array.from(document.querySelectorAll('.ctl-pane')).filter(x => !x.hidden).map(x => x.id),
        bad: Array.from(document.querySelectorAll('.toast.show.bad')).map(t => t.textContent)}));
      await ro.context().close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
