// Settings → DNS in the page: a set added, tried and chosen for a function.
//
//   node test/dnssets_page.js BASE_URL NAME PASSWORD DNS_PORT [SHOTS_DIR]
//
// DNS_PORT: a DNS server on 127.0.0.1 that knows intranet.acme.example.net
// (A 10.20.30.40) - acme's own, started by the test (test_challenges'
// server_config). Signs in, opens Settings → DNS, and:
//   1. the built-in "The system's" is listed first, with no Delete;
//   2. Add a set: a name, the server, saved - listed;
//   3. Test it: the name looked up, answered by that server, with its time;
//   4. it is chosen for "Validation checks": the daemon says so, and the
//      "Used for" column shows it;
//   5. no browser dialog was opened on the way;
//   6. the set deleted again (the page's own "Really?").
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, port, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 1400, height: 1000}});
  const out = {checks: {}};
  const set = 'Company DNS ' + Date.now().toString(36).slice(-4);
  let dialogs = 0;
  page.on('dialog', async (d) => { dialogs++; await d.dismiss(); });
  const shot = async (n) => { if (shots) await page.screenshot({path: shots + '/' + n + '.png', fullPage: false}); };
  const modalClosed = async () => { await page.waitForSelector('#modal', {state: 'hidden', timeout: 30000}); };
  const primary = () => page.locator('#modal-foot button.primary').last();
  const ask = (what) => page.evaluate((w) => api(w), what);
  try {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(800);
    await page.click('.tabs button[data-tab="settings"]');
    await page.click('#ctl-nav button[data-pane="dnssets"]');
    await page.locator('#dnss-host table.dnss-sets tbody tr').first().waitFor({timeout: 20000});
    const firstRow = page.locator('#dnss-host table.dnss-sets tbody tr').first();
    out.checks.system_first = (await firstRow.getAttribute('class') || '').indexOf('dnss-builtin') >= 0;
    out.checks.system_not_deletable = await firstRow.locator('.dnss-del').count() === 0;
    await shot('1-dns-pane');

    // ---- 2. Add a set ------------------------------------------------------------------
    await page.click('#dnss-add');
    await page.fill('#dnss-f-name', set);
    await page.fill('#dnss-f-servers', '127.0.0.1:' + port);
    await shot('2-add-a-set');
    await primary().click();
    await modalClosed();
    const row = page.locator('#dnss-host table.dnss-sets tbody tr', {hasText: set});
    await row.first().waitFor({timeout: 20000});
    out.checks.set_listed = await row.count() === 1;

    // ---- 3. Test it --------------------------------------------------------------------
    await row.locator('.dnss-test').click();
    await page.fill('#dnss-t-name', 'intranet.acme.example.net');
    await page.click('#dnss-t-go');
    await page.locator('.dnss-result .dnss-head').waitFor({timeout: 20000});
    const head = await page.locator('.dnss-result .dnss-head').getAttribute('class');
    const answers = await page.locator('.dnss-result table.dnss-answers').innerText();
    out.checks.test_answered = head.indexOf('good') >= 0 && answers.indexOf('10.20.30.40') >= 0;
    out.checks.test_says_server_and_time = /127\.0\.0\.1:\d+/.test(await page.locator('.dnss-result .dnss-head').innerText())
      && /\d+ ms/.test(await page.locator('.dnss-result .dnss-tries').innerText());
    await shot('3-test-a-set');
    await page.evaluate(() => closeModal());
    await modalClosed();

    // ---- 4. Chosen for the validation checks ---------------------------------------------
    await page.selectOption('#dnss-use-validation', set);
    await page.waitForFunction((s) => {
      const r = Array.from(document.querySelectorAll('#dnss-host table.dnss-sets tbody tr')).find((t) => t.textContent.indexOf(s) >= 0);
      return r && r.querySelectorAll('.tag.info').length > 0;
    }, set, {timeout: 20000});
    const d = await ask('dnssets');
    const v = d.purposes.find((p) => p.key === 'validation');
    out.checks.assigned = v.set === set && v.how === 'assigned';
    out.checks.used_for_shown = (d.used[set] || []).length === 1;
    await page.locator('#dnss-use-validation').scrollIntoViewIfNeeded();
    await shot('4-assigned');

    // ---- 6. Delete it again (the page's own "Really?") --------------------------------------
    await row.locator('.dnss-del').click();
    await page.locator('#modal-foot button.danger').last().click();
    await page.locator('#modal-foot .sure-strip button.danger').click();
    await modalClosed();
    await page.waitForFunction((s) => !Array.from(document.querySelectorAll('#dnss-host table.dnss-sets tbody tr')).some((t) => t.textContent.indexOf(s) >= 0), set, {timeout: 20000});
    const after = await ask('dnssets');
    out.checks.deleted_back_to_default = after.purposes.find((p) => p.key === 'validation').how !== 'assigned';
    out.checks.no_browser_dialog = dialogs === 0;
  } catch (e) {
    out.error = String(e && e.message || e);
    await shot('error');
  }
  out.ok = !out.error && Object.keys(out.checks).length > 0 && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
  await browser.close();
  process.exit(out.ok ? 0 : 1);
})();
