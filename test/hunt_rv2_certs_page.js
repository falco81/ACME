// The pages' half of test/test_hunt_rv2_certs.py (hunt v2, certificates): a request profile made
// from a template on the Czech page keeps the description the page showed (Czech), as it keeps
// the name - and "Open in the editor…" fills it in so too.
//
//   node test/hunt_rv2_certs_page.js BASE_URL PASSWORD
//
// Prints one line of JSON; HUNT_SHOTS=dir: screenshots (deviceScaleFactor 1).
const { chromium } = require('playwright');
const path = require('path');

const SHOTS = process.env.HUNT_SHOTS || '';

(async () => {
  const [base, pass] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  const shot = async (page, name) => { if (SHOTS) await page.screenshot({path: path.join(SHOTS, name + '.png'), fullPage: page.viewportSize().width < 500}); };
  const pause = (page, ms) => page.waitForTimeout(ms);
  try {
    for (const [lang, w] of [['cs', 1400], ['cs', 390], ['en', 1400]]) {
      const tag = `${lang}-${w}`;
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
      page.on('console', m => { if (m.type() === 'error' && !/Failed to load resource/.test(m.text())) out.errors.push(tag + ' console: ' + m.text()); });
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await pause(page, 1200);
      const run = {lang, w};
      const open = async (src) => {
        await page.evaluate(() => { showTab('settings'); setTimeout(() => showPane('reqprofiles'), 50); });
        await page.waitForSelector('#rp-tpl', {timeout: 20000});
        await page.click('#rp-tpl');
        await page.waitForSelector('.rpf-card[data-tpl="web"]', {timeout: 20000});
        await pause(page, 300);
        await page.click('.rpf-card[data-tpl="web"]');
        await page.waitForSelector('#rpf-name');
        run.about = await page.$eval('.rpf-hero .rpf-hw p', n => n.textContent);
        await page.fill('#rpf-suffixes', 'web.test');
        if (src) await page.selectOption('#rpf-issuer', src);
        await page.waitForSelector('.rpf-prev .rpf-chips', {timeout: 15000});
        await pause(page, 900);
      };
      // a public CA and a name never public: the preview says what "Make the profile" refuses
      await open('LetsEncrypt');
      run.previewBad = await page.$eval('.rpf-prev .rpf-ph .rpf-badge', n => n.classList.contains('bad'));
      run.previewSays = await page.$$eval('.rpf-prev .rpf-finds li.bad', n => n.map(x => x.textContent).join(' | '));
      await shot(page, `rv2-preview-${tag}`);
      await page.selectOption('#rpf-issuer', 'own');
      await pause(page, 900);
      run.previewOwnBad = await page.$eval('.rpf-prev .rpf-ph .rpf-badge', n => n.classList.contains('bad'));
      // "Open in the editor…": filled in, nothing saved
      await page.click('#modal-foot .btn:not(.primary):has-text("' + (lang === 'cs' ? 'editoru' : 'editor') + '")');
      await page.waitForSelector('.rp-f-desc', {timeout: 20000});
      await pause(page, 400);
      run.editorDesc = await page.$eval('.rp-f-desc', n => n.value);
      await shot(page, `rv2-editor-${tag}`);
      // nothing saved: the page loaded again (the editor asks before it drops what is typed)
      await page.reload();
      await page.waitForSelector('#modal', {state: 'attached'});
      await pause(page, 1200);
      // "Make the profile": saved with that description
      await open('own');
      run.name = 'Web ' + tag;
      await page.fill('#rpf-name', run.name);
      await pause(page, 500);
      await page.click('#modal-foot .btn.primary');
      try { await page.waitForSelector('.rp-f-desc', {timeout: 20000}); } catch (e) {
        await shot(page, `rv2-fail-${tag}`);
        throw new Error(tag + ': no editor after "Make the profile": ' + await page.evaluate(() => (document.querySelector('.toast, #toast') || {}).textContent || ''));
      }
      await pause(page, 500);
      run.madeDesc = await page.$eval('.rp-f-desc', n => n.value);
      await shot(page, `rv2-made-${tag}`);
      out.runs.push(run);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
