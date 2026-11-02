// What a screen reader is told of a setting, in the page's language (core.js
// explain() with i18n.js) - in a page of its own, no daemon needed.
//
//   node test/explain_aria_page.js /path/to/web/assets
//
// The help of a setting with tags in it (<i>, <code>) is among the rich
// translations only: its aria-label stayed English (1.0.19). Plain words were
// translated before and still are.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const dir = process.argv[2];
  const js = (f) => fs.readFileSync(path.join(dir, f), 'utf-8').replace(/<\/script/g, '<\\/script');
  const pack = {code: 'cs', strings: {'Plain words.': 'Prostá slova.'},
                patterns: [['{0} lead, {1}', '{0} vedou, {1}']],     // a loose one, as acme_dns_url met
                rich: {'Where the links lead, <code>https://x.example/</code>. Empty: <i>none</i>.':
                       'Kam vedou odkazy, <code>https://x.example/</code>. Prázdné: <i>žádné</i>.'}};
  const html = '<!doctype html><html><body><script>window.ACME_LANG_PACK = ' + JSON.stringify(pack)
    + ';</script><script>' + js('i18n.js') + '</script><script>' + js('core.js') + '</script>'
    + '<span id="a">a</span><span id="b">b</span></body></html>';
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const out = {checks: {}, errors: []};
  page.on('pageerror', (e) => out.errors.push(String(e)));
  try {
    await page.setContent(html);
    const got = await page.evaluate(() => {
      explain(document.getElementById('a'), 'Where the links lead, <code>https://x.example/</code>. Empty: <i>none</i>.');
      explain(document.getElementById('b'), 'Plain words.');
      return [document.getElementById('a').getAttribute('aria-label'),
              document.getElementById('b').getAttribute('aria-label')];
    });
    out.got = got;
    out.checks.rich_help_spoken_in_czech = got[0] === 'Kam vedou odkazy, https://x.example/. Prázdné: žádné.';
    out.checks.plain_help_still_in_czech = got[1] === 'Prostá slova.';
  } catch (e) {
    out.error = String(e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
