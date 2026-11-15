// The sign-in cards drawn again without F5 (1.0.108): Settings -> Accounts, the cards of
// Windows (Kerberos), of a certificate and of the sign-in page - every change shows at once.
//
//   node test/signin_redraw_page.js BASE_URL NAME PASSWORD KEYTAB CAS PORT
//
// Signs in once, then, never reloading the page:
//   1. Windows switched on and saved: its card says On, "no keytab yet" warned, the realm's box
//      awake; the portal's card says the administration is on;
//   2. a keytab put in through the card: the card has it, this node has written it out;
//   3. a certificate's authorities put in, the port set to PORT and the part switched on: the
//      card says On, the sign-in page's card offers the button;
//   4. something takes the port a moment later (as nginx does, once root's helper wrote its
//      server): the node's row says so within seconds, without a reload;
//   5. "Which account" compat: the card warns Not strong;
//   6. the keytab taken away: the card and the sign-in page's say so - and the certificate's
//      card has the facts of Windows anew after either (its "No password at all").
// Prints one line of JSON: {ok, checks: {name: true|false}, loads, error?}.
const { chromium } = require('playwright');
const net = require('net');

(async () => {
  const [base, name, pass, keytab, cas, port] = process.argv.slice(2);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: 1400, height: 1000}});
  await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {checks: {}};
  let loads = 0, srv = null;
  page.on('load', () => { loads++; });
  page.on('dialog', (d) => d.dismiss().catch(() => {}));
  const text = (sel) => page.evaluate((s) => { const e = document.querySelector(s); return e ? e.textContent.replace(/\s+/g, ' ') : ''; }, sel);
  const until = async (fn, ms) => {
    const end = Date.now() + (ms || 15000);
    for (;;) { if (await fn()) return true; if (Date.now() > end) return false; await page.waitForTimeout(300); }
  };
  const save = async () => {
    await page.click('#set-save');
    await until(() => page.evaluate(() => !document.querySelector('#save-bar.dirty')), 15000);
  };
  const flip = async (key) => { await page.locator('#set-' + key).scrollIntoViewIfNeeded(); await page.locator('#set-' + key).click(); };
  const file = async (host, path) => {
    const [fc] = await Promise.all([page.waitForEvent('filechooser'),
      page.locator('#' + host + ' .krb-btns button').first().click()]);
    await fc.setFiles(path);
  };
  try {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.goto(base + '/admin/index.php#settings/people');
    await page.waitForSelector('#krb-host-admin .lb-facts', {timeout: 20000});
    loads = 0;

    // ---- 1. Windows on ------------------------------------------------------------------
    await flip('admin_krb');
    await save();
    out.checks.krb_on = await until(async () => /^On/.test(await text('#krb-host-admin .lb-facts')));
    out.checks.krb_no_keytab_warned = (await text('#krb-host-admin')).indexOf('no keytab is put in yet') >= 0;
    out.checks.realm_awake = await page.evaluate(() => !document.querySelector('.set-item[data-key="admin_krb_realm"]').classList.contains('asleep'));
    out.checks.portal_card_says_admin_on = (await text('#krb-host-portal')).indexOf('on there too') >= 0;

    // ---- 2. a keytab put in -------------------------------------------------------------
    await file('krb-host-admin', keytab);
    out.checks.keytab_shown = await until(async () => (await text('#krb-host-admin .lb-facts')).indexOf('A keytab is put in') >= 0);
    out.checks.keytab_written = await until(async () => (await text('#krb-host-admin')).indexOf('written out') >= 0);
    // the certificate's card has its facts of Windows anew too (its "No password at all")
    out.checks.cert_card_knows_keytab = await until(() => page.evaluate(() => !!(CERTC.d && CERTC.d.parts.admin.krb)));

    // ---- 3. a certificate: the authorities, the port, switched on -----------------------
    await file('cert-host-admin', cas);
    out.checks.cas_shown = await until(async () => (await text('#cert-host-admin .lb-facts')).indexOf('Authorities put in') >= 0);
    await page.fill('#set-certlogin_port', String(port));
    await page.dispatchEvent('#set-certlogin_port', 'input');
    await flip('admin_certlogin');
    await save();
    out.checks.cert_on = await until(async () => /^On/.test(await text('#cert-host-admin .lb-facts')));
    out.checks.port_shown = await until(async () => (await text('#cert-host-admin .krb-facts')).indexOf(String(port)) >= 0);
    out.checks.signin_offers_cert = await until(async () => /Sign in with a certificate\s*a button/.test(await text('#signin-host-admin')));
    out.checks.not_listening_yet = (await text('#cert-host-admin .cert-nodes-t')).indexOf('not listening') >= 0;

    // ---- 4. the port taken a moment later: the node's row follows -----------------------
    srv = net.createServer((c) => c.end());
    await new Promise((r) => srv.listen(+port, '127.0.0.1', r));
    out.checks.port_state_followed = await until(async () => (await text('#cert-host-admin .cert-nodes-t')).indexOf('not listening') < 0, 20000);

    // ---- 5. Which account: compat ---------------------------------------------------------
    await page.selectOption('#set-admin_certlogin_match', 'compat');
    await save();
    out.checks.not_strong = await until(async () => (await text('#cert-host-admin .lb-facts')).indexOf('Not strong') >= 0);

    // ---- 6. the keytab taken away ---------------------------------------------------------
    await page.locator('#krb-host-admin .krb-btns button.danger').first().click();
    await page.locator('#modal-foot button.primary, #modal-foot button.danger').last().click();
    out.checks.keytab_gone = await until(async () => (await text('#krb-host-admin .lb-facts')).indexOf('No keytab yet') >= 0);
    out.checks.cert_card_knows_no_keytab = await until(() => page.evaluate(() => !!(CERTC.d && !CERTC.d.parts.admin.krb)));
    out.checks.signin_windows_off = await until(async () => /Sign in with Windows\s*off/.test(await text('#signin-host-admin')));
    out.loads = loads;
    out.checks.never_reloaded = loads === 0;
  } catch (e) {
    out.error = String(e && e.stack || e).slice(0, 2000);
  }
  if (srv) srv.close();
  out.ok = !out.error && Object.keys(out.checks).every((k) => out.checks[k]);
  console.log(JSON.stringify(out));
  await browser.close();
})();
