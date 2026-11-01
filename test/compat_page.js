// The wizard of a new certificate offers only what fits (acmelib/certs/compat.py):
//
//   node test/compat_page.js BASE_URL NAME PASSWORD [SHOTS_DIR]
//
// Signs in, opens Certificates -> Add:
//   1. Let's Encrypt, the name "a" typed into the SAN editor: refused under its row
//      (a single label), the e-mail type offered but refused for a public CA;
//   2. the source DigiCert "DC" (DCV by a DNS TXT record), www.firma.cz: in the
//      Validation step acme's own DNS server ("own") is greyed - disabled, with
//      its reason - and deSEC ("desec") is offered;
//   3. back to the source, SCEP chosen: what no longer fits is said (the key type
//      changed to RSA, the twin left out).
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 1400, height: 1000}});
  const out = {checks: {}};
  const shot = async (n) => { if (shots) await page.screenshot({path: shots + '/' + n + '.png'}); };
  const primary = () => page.locator('#modal-foot button.primary').last();
  const stepTo = async (i) => { await page.locator('.ct-wsteps li button').nth(i).click(); await page.waitForTimeout(700); };
  const source = async (n) => {
    await page.locator('.ct-src', {has: page.locator('b', {hasText: new RegExp('^' + n + '$')})}).first().click();
    await page.waitForTimeout(900);
  };
  try {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    await page.click('.tabs button[data-tab="certs"]');
    await page.waitForTimeout(400);
    await page.click('#ct-add');
    await page.locator('.ct-src').first().waitFor({timeout: 20000});

    // ---- 1. Let's Encrypt, "a" ---------------------------------------------------------
    await source('LetsEncrypt');
    await primary().click();
    await page.locator('.ct-san-val').first().waitFor({timeout: 15000});
    await page.locator('.ct-san-val').first().fill('a');
    await page.waitForTimeout(1500);
    const why1 = await page.locator('.ct-san .ct-rowwhy').first().textContent();
    out.checks.single_label_refused = /single label|jedno/i.test(why1 || '');
    const typeSel = page.locator('.ct-san-type').first();
    await typeSel.selectOption('email');
    await page.locator('.ct-san-val').first().fill('it@firma.cz');
    await page.waitForTimeout(1500);
    const why2 = await page.locator('.ct-san .ct-rowwhy').first().textContent();
    out.checks.email_refused_public = (why2 || '').length > 0;
    await shot('1-names-refused');
    await typeSel.selectOption('dns');
    await page.locator('.ct-san-val').first().fill('www.firma.cz');
    await page.waitForTimeout(800);

    // ---- 2. DigiCert: the validations that cannot put its TXT record greyed ---------------
    await stepTo(0);
    await source('DC');
    await stepTo(1);
    await page.locator('.ct-san-val').first().fill('www.firma.cz');
    await page.waitForTimeout(800);
    await primary().click();            // -> key
    await page.waitForTimeout(700);
    await primary().click();            // -> validation
    await page.locator('select.ct-valsel').first().waitFor({timeout: 20000});
    const opts = await page.locator('select.ct-valsel').first().locator('option').evaluateAll(
      (os) => os.map((o) => ({value: o.value, disabled: o.disabled, text: o.textContent})));
    const own = opts.find((o) => o.value === 'own') || {};
    const desec = opts.find((o) => o.value === 'desec') || {};
    out.checks.builtin_greyed = !!own.disabled;
    out.checks.builtin_reason = /zones|zón/i.test(own.text || '');
    out.checks.desec_offered = desec.value === 'desec' && !desec.disabled;
    out.checks.unfit_listed = (await page.locator('.ct-unfitlist').textContent() || '').indexOf('own') >= 0;
    await shot('2-validation-greyed');

    // ---- 3. another source: what no longer fits is said ------------------------------------
    await stepTo(0);
    await source('SCEPsrc');
    await page.locator('.ct-srcsaid .ct-errbox').first().waitFor({timeout: 15000});
    const said = await page.locator('.ct-srcsaid').textContent();
    out.checks.source_change_said = /RSA/.test(said || '');
    await shot('3-source-changed');
    out.ok = Object.values(out.checks).every(Boolean);
  } catch (e) {
    out.ok = false;
    out.error = String(e && e.stack || e);
    await shot('error');
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
