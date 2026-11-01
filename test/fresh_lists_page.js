// Every view current without F5: what is made in one tab is offered in every
// other at once - and a default set in one is seen in the other.
//
//   node test/fresh_lists_page.js BASE_URL NAME PASSWORD [SHOTS_DIR]
//
// Signs in once, then, never reloading the page:
//   1. an authority made in Authorities -> Sources, Add, "Own certificate
//      authority": its select offers it at once;
//   2. a source made there -> the new certificate's wizard lists it;
//   3. a target made in Targets -> a new deployment's editor lists it;
//   4. a default set (the star) in one tab -> the other shows it: the
//      authority preselected in a new own-CA source, the source preselected
//      in the wizard, the target offered (ticked) in its Deployments step.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 1400, height: 1000}});
  const out = {checks: {}};
  const tag = Date.now().toString(36).slice(-5);
  // Names that read as data in any language (the pages may be in Czech).
  const ca = 'fr-ca-' + tag, src = 'fr-src-' + tag, tg = 'fr-tg-' + tag;
  const shot = async (n) => { if (shots) await page.screenshot({path: shots + '/' + n + '.png', fullPage: false}); };
  const tab = async (t) => {
    await page.click('.tabs button[data-tab="' + t + '"]');
    await page.waitForTimeout(400);
  };
  const modalClosed = async () => { await page.waitForSelector('#modal', {state: 'hidden', timeout: 30000}); };
  // The pages may be in another language (the account's): buttons by their
  // place, never by their words - the primary one, or the popup closed.
  const primary = () => page.locator('#modal-foot button.primary').last();
  const close = async () => { await page.evaluate(() => closeModal()); await modalClosed(); };
  let loads = 0;
  page.on('load', () => { loads++; });
  try {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    loads = 0;

    // ---- 1. an authority, then the own-CA source form offers it -----------------
    await tab('cas');
    await page.click('#ca-root');
    await page.locator('#modal-body input').first().fill(ca);
    await primary().click();
    await modalClosed();
    await page.locator('.ct-node b', {hasText: ca}).first().waitFor({timeout: 30000});
    await tab('sources');
    await page.click('#src-add');
    await page.locator('.ct-kind-tile:has(.ct-kind-k:text-is("internal_ca"))').first().click();
    const caSel = page.locator('.ct-fform [data-fkey="ca"] select').first();
    await caSel.waitFor({timeout: 15000});
    const caOpts = await caSel.locator('option').allTextContents();
    out.checks.new_ca_in_source_form = caOpts.some((t) => t.indexOf(ca) >= 0);
    await shot('1-new-ca-in-source-form');

    // ---- 2. a source, then the wizard lists it -----------------------------------
    await caSel.selectOption({label: caOpts.find((t) => t.indexOf(ca) >= 0)});
    const nameBox = page.locator('#modal-body .ct-basic input').first();
    // The name offered is a safe one; one typed with brackets is refused at once,
    // under the box, and Save is off until it is right.
    out.checks.offered_name_safe = /^[A-Za-z0-9][A-Za-z0-9 ._@+-]{0,119}$/.test(await nameBox.inputValue());
    await nameBox.fill("Bad (name)'s");
    out.checks.bad_name_said = await page.locator('#modal-body .ct-name-said:not([hidden])').count() > 0
      && await primary().isDisabled();
    await nameBox.fill(src);
    await primary().click();
    await modalClosed();
    await page.locator('#src-list b', {hasText: src}).first().waitFor({timeout: 15000});
    await tab('certs');
    await page.click('#ct-add');
    await page.locator('.ct-src').first().waitFor({timeout: 15000});
    out.checks.new_source_in_wizard = await page.locator('.ct-src b', {hasText: src}).count() > 0;
    await shot('2-new-source-in-wizard');
    await close();

    // ---- 3. a target, then a new deployment's editor lists it --------------------
    await tab('targets');
    await page.click('#tg-add');
    await page.locator('.ct-kind-tile:has(.ct-kind-k:text-is("appliance"))').first().click();
    await page.locator('#modal-body .ct-basic input').first().fill(tg);
    await primary().click();
    await modalClosed();
    await page.locator('#tg-list b', {hasText: tg}).first().waitFor({timeout: 15000});
    await page.evaluate(() => window.ACME_CERTS.deployEdit({}));
    const tSel = page.locator('#modal-body select').nth(1);
    await tSel.waitFor({timeout: 15000});
    const tOpts = await tSel.locator('option').allTextContents();
    out.checks.new_target_in_deploy_editor = tOpts.some((t) => t.indexOf(tg) >= 0);
    await shot('3-new-target-in-deploy-editor');
    await close();

    // ---- 4. defaults set in one tab, seen in the other ---------------------------
    // The authority: its star in Authorities, then the own-CA source form.
    await tab('cas');
    const node = page.locator('.ct-node', {has: page.locator('b', {hasText: ca})}).first();
    await node.locator('.ct-star').click();
    await page.locator('.ct-node', {has: page.locator('b', {hasText: ca})}).locator('.ct-star.on').first().waitFor({timeout: 15000});
    await tab('sources');
    await page.click('#src-add');
    await page.locator('.ct-kind-tile:has(.ct-kind-k:text-is("internal_ca"))').first().click();
    const caSel2 = page.locator('.ct-fform [data-fkey="ca"] select').first();
    await caSel2.waitFor({timeout: 15000});
    out.checks.default_ca_preselected = (await caSel2.evaluate((s) => s.options[s.selectedIndex].text)).indexOf(ca) >= 0;
    await shot('4a-default-ca-preselected');
    await close();
    // The source: its star in Sources, then the wizard.
    const srow = page.locator('#src-list tr', {has: page.locator('b', {hasText: src})}).first();
    await srow.locator('.ct-star').click();
    await page.locator('#src-list tr', {has: page.locator('b', {hasText: src})}).locator('.ct-star.on').first().waitFor({timeout: 15000});
    // The target: its star in Targets.
    await tab('targets');
    const trow = page.locator('#tg-list tr', {has: page.locator('b', {hasText: tg})}).first();
    await trow.locator('.ct-star').click();
    await page.locator('#tg-list tr', {has: page.locator('b', {hasText: tg})}).locator('.ct-star.on').first().waitFor({timeout: 15000});
    await tab('certs');
    await page.click('#ct-add');
    await page.locator('.ct-src').first().waitFor({timeout: 15000});
    out.checks.default_source_preselected = await page.locator('.ct-src.on b', {hasText: src}).count() > 0;
    await shot('4b-default-source-in-wizard');
    // Its Deployments step: the default target first, ticked.
    for (let i = 0; i < 10 && !(await page.locator('.ct-deps').count()); i++) {
      const names = page.locator('#modal-body .ct-wbody textarea');
      if (await names.count() && !(await names.first().inputValue())) await names.first().fill('fresh-' + tag + '.example.test');
      await primary().click();
      await page.waitForTimeout(300);
    }
    const dep = page.locator('.ct-dep', {has: page.locator('b', {hasText: tg})}).first();
    out.checks.default_target_offered = (await dep.count()) > 0 && await dep.locator('.ct-dep-top input[type=checkbox]').first().isChecked();
    await shot('4c-default-target-in-deployments');
    await close();
    out.checks.never_reloaded = loads === 0;
  } catch (e) {
    out.error = String(e && e.stack || e);
    try { await shot('error'); } catch (e2) { /* nothing */ }
  }
  out.ok = !out.error && Object.values(out.checks).every(Boolean) && Object.keys(out.checks).length >= 9;
  await browser.close();
  console.log(JSON.stringify(out));
  process.exit(out.ok ? 0 : 1);
})();
