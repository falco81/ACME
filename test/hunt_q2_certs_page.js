// The pages' half of test/test_hunt_q2_certs.py: the Certificates and Authorities tabs in
// Chromium.
//
//   node test/hunt_q2_certs_page.js BASE_URL NAME PASSWORD WILD_PEM_FILE ANSWER_PEM_FILE
//
// Prints one line of JSON: what was seen.
//  - Enter on a button of a row (Renew it now) is that button's - not the certificate opened.
//  - Import of a wildcard certificate: the name offered is one acme takes, Import is on and
//    the certificate is kept.
//  - The card on a phone (375 px): no section wider than the popup.
//  - The card of an imported certificate: "Renews" said alike in both its sections.
//  - The answer of an outside CA dropped: no "Leave what was typed here?" after it.
//  - Add a certificate: no step's words over the next step.
//  - The list 900 px wide: its names not a letter a line.
//  - Authorities: the buttons of "Published on acme" not indented when they wrap.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, wildFile, answerFile] = process.argv.slice(2);
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
    await page.waitForTimeout(700);
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

    // Enter on "Renew it now" of a row
    const row = await find(page, 'q2-issued');
    await row.locator('td.rowtools button').last().focus();
    await page.keyboard.press('Enter');
    await page.waitForTimeout(1200);
    out.enterTitle = await page.locator('#modal-title').innerText();
    await shut(page);

    // Import of a wildcard certificate
    await page.evaluate(() => document.getElementById('ct-import').click());
    await page.waitForTimeout(800);
    await page.locator('#modal-body input[type=file]').first().setInputFiles(wildFile);
    await page.waitForTimeout(2500);
    out.importName = await page.locator('#modal-body .formgrid input').first().inputValue();
    const imp = page.locator('#modal-foot button.primary').last();
    out.importOff = await imp.isDisabled();
    if (!out.importOff) {
      await imp.click();
      await page.waitForTimeout(2500);
    }
    out.importedTitle = await page.locator('#modal-title').innerText();
    // ...its card: Renews said alike
    out.renews = await page.evaluate(() => [...document.querySelectorAll('#modal-body .msect table tr')]
      .filter(tr => tr.children[0] && tr.children[0].textContent.trim() === 'Renews')
      .map(tr => tr.children[1].textContent.trim()));
    await shut(page);

    // The answer of an outside CA, dropped in its card
    const cr = await find(page, 'q2-csr');
    await cr.click();
    await page.waitForTimeout(1200);
    await page.locator('#modal-foot button', {hasText: 'Upload the answer'}).click();
    await page.waitForTimeout(800);
    await page.locator('#modal-body input[type=file]').first().setInputFiles(answerFile);
    await page.waitForTimeout(3500);
    out.answerAsked = await page.locator('.gd-sure').count();
    out.answerTitle = await page.locator('#modal-title').innerText();
    await shut(page);

    // Add a certificate: the steps
    await page.evaluate(() => document.getElementById('ct-add').click());
    await page.waitForTimeout(1200);
    out.stepsOver = await page.evaluate(() => [...document.querySelectorAll('.ct-wsteps li')]
      .filter(li => li.scrollWidth > li.clientWidth + 1).map(li => li.textContent));
    await shut(page);

    // Authorities: the line of what is published
    await tab(page, 'cas');
    out.pkiMargins = await page.evaluate(() => [...document.querySelectorAll('.ct-pki-line > .btn')]
      .map(b => getComputedStyle(b).marginLeft));
    out.pkiFlex = await page.evaluate(() => getComputedStyle(document.querySelector('.ct-pki-line')).display);

    // The list 900 px wide
    await page.setViewportSize({width: 900, height: 1000});
    await tab(page, 'certs');
    await page.fill('#ct-q', '');
    await page.waitForTimeout(1200);
    out.namesWidth = await page.evaluate(() => Math.min.apply(null,
      [...document.querySelectorAll('#ct-table td > .ct-names')].map(n => n.getBoundingClientRect().width)));

    // The card on a phone
    const phone = await page0(375);
    await tab(phone, 'certs');
    await (await find(phone, 'q2-issued')).click();
    await phone.waitForTimeout(1500);
    out.phone = await phone.evaluate(() => {
      const b = document.querySelector('#modal-body');
      const R = b.getBoundingClientRect().right;
      return {wide: b.scrollWidth - b.clientWidth, page: document.documentElement.scrollWidth - window.innerWidth,
              cut: [...b.querySelectorAll('.msect')].filter(s => s.getBoundingClientRect().right > R + 1).length};
    });
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
