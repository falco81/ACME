// The pages' half of test/test_secrets_shown.py: a source's / target's secret
// field shows the kept one as dots and its last two, typing into it shows dots
// only, and saved untouched it is sent back as the dots (the daemon keeps it).
//
//   node test/secrets_shown_page.js BASE_URL NAME PASSWORD
//
// Prints one line of JSON: what was seen.
const { chromium } = require('playwright');

(async () => {
  const [base, name, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const out = {};
  try {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    out.signin_type = await page.getAttribute('#in-pass', 'type');
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    // What a box shows (the element's own value, not the masked box's getter).
    const shownOf = 'el => Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").get.call(el)';
    for (const [key, rowName, field] of [['targets', 'fake1', 'password'], ['sources', 'eab-ca', 'eab_hmac'],
                                          ['validation', 'web-ssh', 'key']]) {
      await page.goto(base + '/admin/index.php?t=' + key + '#' + key);
      const row = page.locator('tr', {has: page.locator('b', {hasText: new RegExp('^' + rowName + '$')})}).first();
      await row.waitFor({timeout: 30000});
      // The list itself: no secret in it.
      out[key] = {list: await page.locator('body').evaluate(n => n.innerText)};
      // Its tools: ... Edit, Take it away (titles in the page's language).
      const tools = row.locator('.rowtools button');
      await tools.nth((await tools.count()) - 2).click();
      // An SSH key is isemon's key card (sshkey.js): what it says, never the key.
      const card = page.locator('.ct-fform .sshk[data-fkey="' + field + '"]').first();
      const box = page.locator('.ct-fform [data-fkey="' + field + '"] input').first();
      if (key === 'validation') {
        await card.waitFor();
        out[key].kept = await card.evaluate(n => n.innerText);
      } else {
        await box.waitFor();
        out[key].kept = await box.evaluate(new Function('return ' + shownOf)());
      }
      // The page's own HTML of the form: the secret nowhere in it.
      out[key].html = await page.locator('.ct-fform').first().evaluate(n => n.outerHTML);
      if (key === 'targets') {
        await box.click();
        await page.keyboard.type('NewSecretTyped');
        out[key].typing = await box.evaluate(new Function('return ' + shownOf)());
        out[key].real = await box.evaluate(el => el.value);
        out[key].type = await box.getAttribute('type');
      }
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
