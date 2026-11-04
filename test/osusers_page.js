// The pages' half of test/test_osusers.py: Settings -> Local users, SSH keys (Whose keys), the
// SSH server's Who may sign in and the console at login's normal users (the account pickers) -
// in English and in Czech, on a wide screen and a phone's.
//
//   node test/osusers_page.js BASE_URL NAME PASSWORD USER
//
// USER is a local user the test made on the node. Prints one line of JSON: what was seen.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass, user] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {};
  try {
    for (const lang of ['en', 'cs']) {
      for (const width of [1300, 390]) {
        const ctx = await browser.newContext({viewport: {width, height: 900}});
        await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
        const page = await ctx.newPage();
        const errors = [];
        page.on('pageerror', (e) => errors.push(String(e)));
        await page.goto(base + '/admin/index.php');
        await page.fill('#in-name', name);
        await page.type('#in-pass', pass);
        await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
        const seen = {errors};
        // Local users: one row a user, root first, view only.
        await page.goto(base + '/admin/index.php?t=settings#settings/osusers');
        await page.evaluate(() => { if (typeof showTab === 'function') showTab('settings'); PANE = 'osusers'; showPane('osusers'); });
        const rows = page.locator('#osu-host tbody tr');
        await page.waitForFunction((u) => {
          const t = document.querySelector('#osu-host');
          return t && t.innerText.indexOf(u) >= 0;
        }, user, {timeout: 60000});
        seen.nav = await page.locator('button[data-pane="osusers"]').innerText();
        seen.host = await page.locator('#osu-host').innerText();
        seen.rows = await rows.count();
        seen.first = await rows.first().innerText();
        const shots = process.env.ACME_SHOTS;
        const shot = async (what) => { if (shots) await page.screenshot({path: shots + '/' + lang + width + '-' + what + '.png', fullPage: false}); };
        await shot('osusers');
        seen.overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        // root's popup: nothing to change, Close only.
        await rows.first().locator('button').last().click();
        await page.waitForSelector('#modal:not([hidden])');
        seen.root_inputs = await page.locator('#modal-body input, #modal-body select, #modal-body textarea').count();
        seen.root_buttons = await page.locator('#modal-foot button').allInnerTexts();
        await page.locator('#modal-foot button').last().click();
        await page.waitForSelector('#modal', {state: 'hidden'});
        // The user's popup: its sections.
        const urow = page.locator('#osu-host tbody tr', {hasText: user}).first();
        await urow.locator('button').last().click();
        await page.waitForSelector('#modal:not([hidden])');
        seen.user_popup = await page.locator('#modal-body').innerText();
        await shot('user');
        seen.user_buttons = await page.locator('#modal-foot button').allInnerTexts();
        // The password boxes are never type=password (no autofill).
        seen.pw_types = await page.locator('#modal-body input').evaluateAll((l) => l.map((x) => x.type));
        await page.locator('#modal-foot button').last().click();
        await page.waitForSelector('#modal', {state: 'hidden'});
        // Add a user.
        const add = page.locator('#osu-host button', {hasText: lang === 'cs' ? 'Přidat uživatele' : 'Add a user'}).first();
        await add.click();
        await page.waitForSelector('#modal:not([hidden])');
        seen.add_popup = await page.locator('#modal-body').innerText();
        seen.add_title = await page.locator('#modal-title').innerText();
        await shot('add');
        await page.locator('#modal-x').click();
        // SSH keys: whose keys.
        await page.evaluate(() => { PANE = 'sshkeys'; showPane('sshkeys'); });
        await page.waitForSelector('#sk-host .sk-who select', {timeout: 30000});
        await page.waitForFunction((u) => Array.prototype.some.call(
          document.querySelectorAll('#sk-host .sk-who select option'), (o) => o.value === u), user, {timeout: 60000});
        seen.sk_users = await page.locator('#sk-host .sk-who select option').allInnerTexts();
        await page.selectOption('#sk-host .sk-who select', user);
        await page.waitForFunction((u) => (document.querySelector('#sk-host') || {}).innerText.indexOf(u) >= 0, user);
        seen.sk_host = await page.locator('#sk-host').innerText();
        await shot('sshkeys');
        // The SSH server: Who may sign in, picked.
        await page.evaluate(() => { PANE = 'sshd'; showPane('sshd'); });
        await page.waitForSelector('#sd-host details.acct-pick', {timeout: 30000});
        const pick = page.locator('#sd-host details.acct-pick').first();
        seen.sd_picker = await pick.locator('summary').innerText();
        await pick.scrollIntoViewIfNeeded();
        await pick.locator('summary').click();
        await page.waitForTimeout(400);
        await shot('sshd-picker');
        await pick.locator('summary').click();
        // The console at login: normal users, picked.
        await page.evaluate(() => { PANE = 'about'; showPane('about'); });
        await page.waitForSelector('.con-row details.acct-pick', {timeout: 30000});
        seen.con_row = await page.locator('.con-row').first().innerText();
        const cp = page.locator('.con-row details.acct-pick').first();
        await cp.locator('summary').click();
        await page.waitForFunction(() => {
          const p = document.querySelector('.con-row .acct-panel');
          return p && p.querySelectorAll('.acct-row').length >= 2;
        }, null, {timeout: 30000});
        seen.con_panel = await cp.locator('.acct-panel').innerText();
        await shot('console');
        seen.overflow_about = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        out[lang + width] = seen;
        await ctx.close();
      }
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
