// Settings → Owners and teams in the page, and the owner picked - never typed.
//
//   node test/teams_page.js BASE_URL NAME PASSWORD [SHOTS_DIR]
//
// Signs in and:
//   1. Settings → Owners and teams: a tag added, an owner added (a local account
//      and a directory group as members, a mail) - both listed;
//   2. the wizard's Names step offers that owner in a select (no free text);
//   3. a certificate's detail: the pencil of Details, the owner and a tag picked,
//      the note changed, saved - the daemon has them, and its version is the same;
//   4. no browser dialog was opened, no error on the page.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 1400, height: 1000}});
  const out = {checks: {}, errors: []};
  const suffix = Date.now().toString(36).slice(-4);
  const team = 'Web team ' + suffix, tag = 'prod-' + suffix;
  let dialogs = 0;
  page.on('dialog', async (d) => { dialogs++; await d.dismiss(); });
  page.on('pageerror', (e) => out.errors.push(String(e)));
  const shot = async (n) => { if (shots) await page.screenshot({path: shots + '/' + n + '.png', fullPage: false}); };
  const modalClosed = async () => { await page.waitForSelector('#modal', {state: 'hidden', timeout: 30000}); };
  const primary = () => page.locator('#modal-foot button.primary').last();
  const ask = (what, body) => page.evaluate((x) => (x.length > 1 ? api(x[0], x[1]) : api(x[0])),
                                            body === undefined ? [what] : [what, body]);
  try {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    await page.click('.tabs button[data-tab="settings"]');
    await page.click('#ctl-nav button[data-pane="teams"]');
    await page.locator('#teams-host table.tm-teams').waitFor({timeout: 20000});
    out.checks.settings_drawn = await page.locator('#sect-teams #set-certs_certadmin_all, #sect-teams [id="set-certs_certadmin_all"]').count() > 0;
    await shot('1-teams-pane');

    // ---- 1. a tag, an owner ----------------------------------------------------------
    await page.click('#tm-tag-add');
    await page.fill('#tm-t-name', tag);
    await page.selectOption('#tm-t-colour', 'crit');
    await primary().click();
    await modalClosed();
    await page.locator('#teams-host tr.tm-tagrow', {hasText: tag}).waitFor({timeout: 20000});
    out.checks.tag_listed = true;
    await page.click('#tm-add');
    await page.fill('#tm-f-name', team);
    await page.fill('#tm-f-mail', 'web-team@example.com');
    await page.waitForFunction(() => document.querySelector('.tm-f-acc') && document.querySelector('.tm-f-acc').options.length > 0, null, {timeout: 20000});
    await page.click('#tm-f-addm');                      // the first account of acme
    await page.selectOption('#tm-f-how', 'group');
    await page.fill('#tm-f-who', 'WEB_ADMINS');
    await page.click('#tm-f-addm');
    await page.locator('#tm-f-members tr.tm-mrow').nth(1).waitFor({timeout: 5000});
    await page.locator('#tm-f-members tr.tm-mrow').nth(0).locator('.tm-r-manage').check();
    await shot('2-owner-dialog');
    await primary().click();
    await modalClosed();
    const row = page.locator('#teams-host tr.tm-team', {hasText: team});
    await row.first().waitFor({timeout: 20000});
    const listed = (await ask('teams')).teams.filter((t) => t.name === team)[0] || {};
    out.checks.owner_saved = (listed.members || []).length === 2 && listed.contact_mail === 'web-team@example.com'
      && listed.members[0].who.indexOf('local:') === 0 && listed.members[0].rights.indexOf('manage') >= 0
      && listed.members[1].who === 'group:WEB_ADMINS';
    await shot('3-teams-listed');

    // ---- 2. the wizard offers it ---------------------------------------------------------
    await page.click('.tabs button[data-tab="certs"]');
    await page.locator('#ct-table').waitFor({timeout: 20000});
    await page.click('#ct-add');
    await page.locator('#modal-foot button', {hasText: /Next|Další/}).first().waitFor({timeout: 20000});
    await page.locator('#modal-foot button', {hasText: /Next|Další/}).first().click();
    await page.locator('#ct-w-owner select').waitFor({timeout: 20000});
    await page.waitForFunction((t) => Array.from(document.querySelectorAll('#ct-w-owner select option')).some((o) => o.value === t), team, {timeout: 20000});
    out.checks.wizard_owner_select = await page.locator('#ct-w-owner input').count() === 0;
    await page.locator('#ct-w-owner select').selectOption(team);
    await shot('4-wizard-owner');
    await page.locator('#modal-foot button', {hasText: /^\s*(Close|Zavřít)\s*$/}).first().click();
    await modalClosed();

    // ---- 3. the details of a certificate, without a new one ----------------------------
    const certs = (await ask('certs')).rows || [];
    const issued = certs.filter((c) => c.not_after)[0] || certs[0];
    if (!issued) throw new Error('there is no certificate to try the details on');
    const before = (await ask('certs/one&id=' + issued.id)).cert;
    await page.locator('#ct-table tr', {hasText: issued.name}).first().click();
    await page.locator('#ct-d-edit').waitFor({timeout: 20000});
    await shot('5-cert-details');
    await page.click('#ct-d-edit');
    await page.waitForFunction((t) => Array.from(document.querySelectorAll('#ct-d-owner select option')).some((o) => o.value === t), team, {timeout: 20000});
    await page.locator('#ct-d-owner select').selectOption(team);
    await page.waitForFunction((t) => Array.from(document.querySelectorAll('.tm-details select.tm-tag-add option')).some((o) => o.value === t), tag, {timeout: 20000});
    await page.locator('.tm-details select.tm-tag-add').selectOption(tag);
    await page.fill('#ct-d-note', 'changed in place ' + suffix);
    await shot('6-cert-details-edit');
    await page.click('#ct-d-save');
    await page.waitForFunction(() => !document.querySelector('#ct-d-save'), null, {timeout: 20000});
    await page.locator('#ct-d-edit').waitFor({timeout: 20000});
    const after = (await ask('certs/one&id=' + issued.id)).cert;
    out.checks.details_saved = after.owner === team && (after.tags || []).indexOf(tag) >= 0
      && after.note === 'changed in place ' + suffix;
    out.checks.not_reissued = after.version === before.version && after.fingerprint === before.fingerprint
      && after.state === before.state;
    await shot('7-cert-details-saved');
    // ---- 4. the wizard: another key on an issued one - now, or at the next renewal ----
    await page.locator('#modal-foot button', {hasText: /^\s*(Edit|Upravit)\s*$/}).first().click();
    await page.locator('.ct-wsteps li button').nth(2).waitFor({timeout: 20000});
    await page.locator('.ct-wsteps li button').nth(2).click();
    await page.locator('.ct-keys .ct-keyt').first().waitFor({timeout: 20000});
    out.checks.wizard_says_next_renewal = await page.locator('.tm-next-renewal').count() === 1;
    await page.locator('.ct-keys .ct-keyt:not(.on)').first().click();
    await shot('8-wizard-key');
    await page.locator('#modal-foot button', {hasText: /^\s*(Save|Uložit)\s*$/}).first().click();
    await page.locator('#modal-title', {hasText: /next renewal|příštím obnovení/}).waitFor({timeout: 20000});
    await shot('9-renew-now-or-later');
    await page.locator('#modal-foot button', {hasText: /At the next renewal|Při příštím obnovení/}).click();
    await page.locator('#ct-d-edit').waitFor({timeout: 20000});
    const later = (await ask('certs/one&id=' + issued.id)).cert;
    out.checks.key_waits_for_renewal = later.key_type !== before.key_type && later.version === before.version
      && later.fingerprint === before.fingerprint;
    // back as it was
    await ask('certs/save', {id: issued.id, owner: before.owner || '', tags: before.tags || [], note: before.note || '',
                             key_type: before.key_type});
    await page.evaluate(() => closeModal());
    await ask('teams/delete', {name: team, reassign: ''});
    await ask('tags/delete', {name: tag, strip: true});

    out.checks.no_browser_dialog = dialogs === 0;
    out.checks.no_page_error = out.errors.length === 0;
    out.ok = Object.values(out.checks).every(Boolean);
  } catch (e) {
    out.ok = false;
    out.error = String(e && e.stack || e);
    await shot('error');
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
