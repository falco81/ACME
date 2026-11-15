// Look up a person for a certificate, and a CSR made in the browser (1.0.110): Settings ->
// Accounts, the card of a certificate - "Look up a person…", nested found (Enter), the values each
// with Copy, the request's tabs (the popup stays where it is), Find again (nothing collapses);
// "Make a CSR…": RSA 2048 with a passphrase, then ECDSA P-256 without one - both downloaded into
// OUT for openssl to look at; the Kerberos card's commands with the domain's NetBIOS name read
// from the directory and the service account typed and checked.
//
//   node test/cert_lookup_page.js BASE_URL NAME PASSWORD OUT [SHOTS] [czech]
//
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
(async () => {
  const [base, name, pass, outDir, shots, czech] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {checks: {}, errors: []};
  const runs = czech ? [['en', 1400, 1500], ['cs', 1400, 1500], ['en', 420, 2600], ['cs', 420, 2600]] : [['en', 1400, 1500], ['en', 420, 2600]];
  try {
    for (const [lang, width, height] of runs) {
      const tag = lang + width;
      const ctx = await browser.newContext({viewport: {width, height}, acceptDownloads: true});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      page.on('pageerror', (e) => out.errors.push(tag + ': ' + String(e)));
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', name);
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.goto(base + '/admin/index.php#settings/people');
      await page.waitForSelector('#cert-host-admin .krb-btns', {timeout: 30000});
      out.checks[tag + '_button'] = await page.evaluate(() => document.querySelectorAll('#cert-host-admin .krb-btns button').length >= 1
        && Array.prototype.some.call(document.querySelectorAll('#cert-host-admin .krb-btns button'), (b) => /Look up a person|Vyhledat osobu/.test(b.textContent)));
      // the button itself
      await page.evaluate(() => Array.prototype.find.call(document.querySelectorAll('#cert-host-admin .krb-btns button'), (b) => /Look up a person|Vyhledat osobu/.test(b.textContent)).click());
      await page.waitForSelector('#modal-body .clk-find input', {timeout: 10000});
      out.checks[tag + '_focused'] = await page.evaluate(() => document.activeElement && document.activeElement.closest('.clk-find') !== null);
      await page.fill('#modal-body .clk-find input', 'nested');
      await page.locator('#modal-body .clk-find input').press('Enter');
      await page.waitForSelector('#modal-body .clk-head', {timeout: 15000});
      await page.waitForTimeout(400);
      out.checks[tag + '_values'] = await page.evaluate(() => document.querySelectorAll('#modal-body .clk-row').length === 7
        && document.querySelectorAll('#modal-body .clk-copy').length === 6);
      out.checks[tag + '_san_url'] = await page.evaluate(() => document.querySelector('#modal-body').innerText.indexOf('tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111-2222-3333-1106') >= 0);
      out.checks[tag + '_fits'] = await page.evaluate(() => { const b = document.getElementById('modal-body'); return b.scrollWidth <= b.clientWidth + 1 && document.documentElement.scrollWidth <= window.innerWidth + 1; });
      // tabs: the popup stays where it is (the keeper leaves popups alone)
      const box0 = await page.evaluate(() => { const r = document.getElementById('modal-box').getBoundingClientRect(); return [r.top, r.height, document.getElementById('modal-body').scrollTop]; });
      await page.locator('#modal-body .clk-tabs button').nth(2).click();
      await page.waitForTimeout(300);
      const box1 = await page.evaluate(() => { const r = document.getElementById('modal-box').getBoundingClientRect(); return [r.top, r.height, document.getElementById('modal-body').scrollTop]; });
      out.checks[tag + '_inf_tab'] = await page.evaluate(() => document.querySelector('#modal-body .clk-pre').textContent.indexOf('[Extensions]') >= 0);
      out.checks[tag + '_no_jump_tab'] = Math.abs(box0[0] - box1[0]) <= 1 && Math.abs(box0[2] - box1[2]) <= 1;
      out['box_' + tag] = [box0, box1];
      // Find again: the result stays while it asks, nothing collapses
      const h0 = await page.evaluate(() => document.getElementById('modal-body').scrollHeight);
      await page.locator('#modal-body .clk-find button').click();
      await page.waitForTimeout(60);
      const hmid = await page.evaluate(() => document.getElementById('modal-body').scrollHeight);
      await page.waitForTimeout(600);
      out.checks[tag + '_no_collapse'] = hmid >= h0 - 2;
      await page.locator('#modal-body .clk-tabs button').nth(0).click();
      await page.waitForTimeout(200);
      if (lang === 'cs') {
        const left = await page.evaluate(() => {
          const words = ['The values of the certificate', 'What to put into the request', 'A certificate with these values here', 'signs in', 'enabled', 'the strong mapping', 'Which account here now'];
          const t = document.getElementById('modal').innerText;
          return words.filter((w) => t.indexOf(w) >= 0);
        });
        out.checks[tag + '_czech'] = left.length === 0;
        if (left.length) out['left_' + tag] = left;
      }
      // the popup whole: its body unscrolled into a tall box for the picture
      await page.evaluate(() => { const b = document.getElementById('modal-box'); b.style.maxHeight = 'none'; const bd = document.getElementById('modal-body'); bd.style.maxHeight = 'none'; bd.style.overflow = 'visible'; });
      await page.waitForTimeout(200);
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'lookup-' + tag + '.png')});
      // ---- Make a CSR: over the lookup popup, made in the browser ----------------------------
      await page.evaluate(() => { const b = document.getElementById('modal-box'); b.style.maxHeight = ''; const bd = document.getElementById('modal-body'); bd.style.maxHeight = ''; bd.style.overflow = ''; });
      await page.locator('#modal-body .clk-req-h button').click();
      await page.waitForSelector('#modal-body .csr-list', {timeout: 10000});
      out.checks[tag + '_csr_prefilled'] = await page.evaluate(() => {
        const rows = Array.prototype.map.call(document.querySelectorAll('#modal-body .csr-row'), (r) => [r.querySelector('input').checked, (r.querySelector('input[type=text]') || {}).value || '']);
        return rows[0][0] && rows[0][1] === 'Nested Person' && rows[5][0] && rows[5][1] === 'nested@corpnet.cz'
          && rows[6][0] && rows[6][1].indexOf('tag:microsoft.com,2022-09-14:sid:S-1-5-21-') === 0 && !rows[8][0];
      });
      out.checks[tag + '_csr_fits'] = await page.evaluate(() => { const b = document.getElementById('modal-body'); return b.scrollWidth <= b.clientWidth + 1; });
      const first = width === 1400;
      if (first) {
        await page.fill('#modal-body .csr-pass input >> nth=0', 'a-good-passphrase');
        await page.fill('#modal-body .csr-pass input >> nth=1', 'a-good-passphrase');
        // the e-mail address in the SAN too, and the country
        await page.fill('#modal-body .csr-row >> nth=3 >> input[type=text]', 'CZ');
      } else {
        await page.locator('#modal-body .csr-kinds button').nth(3).click();
        await page.locator('#modal-body .csr-plain input').check();
        out.checks[tag + '_plain_warned'] = await page.evaluate(() => !document.querySelector('#modal-body .csr-pass + .csr-plain + .note').hidden);
      }
      if (shots) {
        await page.evaluate(() => { const b = document.getElementById('modal-box'); b.style.maxHeight = 'none'; const bd = document.getElementById('modal-body'); bd.style.maxHeight = 'none'; bd.style.overflow = 'visible'; });
        await page.waitForTimeout(150);
        await page.locator('#modal-box').screenshot({path: path.join(shots, 'csr-' + tag + '.png')});
        await page.evaluate(() => { const b = document.getElementById('modal-box'); b.style.maxHeight = ''; const bd = document.getElementById('modal-body'); bd.style.maxHeight = ''; bd.style.overflow = ''; });
      }
      const got = [], sent = [];
      page.on('download', (d) => got.push(d));
      page.on('request', (r) => sent.push(r.url() + ' ' + (r.postData() || '')));
      await page.locator('#modal-foot .btn.primary').click();
      for (let i = 0; i < 100 && got.length < 2; i++) await page.waitForTimeout(200);
      const dir = path.join(outDir, tag);
      fs.mkdirSync(dir, {recursive: true});
      for (const d of got) await d.saveAs(path.join(dir, d.suggestedFilename()));
      out.checks[tag + '_csr_downloaded'] = got.length === 2;
      // made here: nothing of the key or the passphrase went anywhere
      out.checks[tag + '_nothing_sent'] = !sent.some((x) => /PRIVATE KEY|a-good-passphrase|CERTIFICATE REQUEST/.test(x));
      out.checks[tag + '_csr_shown'] = await page.evaluate(() => /BEGIN CERTIFICATE REQUEST/.test((document.querySelector('#modal-body .csr-pem') || {}).textContent || ''));
      if (shots && first) await page.locator('#modal-box').screenshot({path: path.join(shots, 'csr-made-' + tag + '.png')});
      // the card's way: the commands, no key made here
      await page.locator('#modal-body .csr-where button').nth(1).click();
      out.checks[tag + '_card_way'] = await page.evaluate(() => document.querySelector('#modal-foot .btn.primary').hidden && document.querySelector('#modal-body').innerText.indexOf('ykman piv') >= 0);
      if (shots && !first) await page.locator('#modal-box').screenshot({path: path.join(shots, 'csr-card-' + tag + '.png')});
      await page.evaluate(() => { MODAL_TYPED = 0; closeModal(true); });
      await page.waitForTimeout(200);
      out.checks[tag + '_back_to_lookup'] = await page.evaluate(() => !document.getElementById('modal').hidden && !!document.querySelector('#modal-body .clk-head'));
      // The Kerberos card's commands: the NetBIOS name read from AD, the account checked
      await page.evaluate(() => closeModal());
      if (width === 1400) {
        await page.waitForSelector('#krb-host-admin .krb-acct input', {timeout: 15000});
        out.checks[tag + '_krb_netbios'] = await page.evaluate(() => document.querySelector('#krb-host-admin').innerText.indexOf('MERIT_NT\\svc-acme-http') >= 0);
        await page.fill('#krb-host-admin .krb-acct input', 'svc-web');
        out.checks[tag + '_krb_typed'] = await page.evaluate(() => document.querySelector('#krb-host-admin .lb-code').textContent.indexOf('MERIT_NT\\svc-web') >= 0);
        await page.locator('#krb-host-admin .krb-acct input').press('Enter');
        await page.waitForSelector('#krb-host-admin .krb-acct-line', {timeout: 10000});
        await page.waitForTimeout(300);
        // the part of the card with the commands, copied into a box of its own over the page
        // (the page keeps its scroll where the reader is: an element screenshot scrolled it away)
        await page.evaluate(() => {
          const h = document.querySelector('#krb-host-admin'), from = h.querySelector('.krb-dom').previousElementSibling.previousElementSibling;
          const to = h.querySelector('.krb-acct-said').nextElementSibling;
          const box = document.createElement('div');
          box.id = 'shot-krb';
          box.className = 'card';
          box.style.cssText = 'position:fixed;top:0;left:0;width:1100px;z-index:99999;background:var(--panel);padding:16px 22px';
          let on = false;
          Array.prototype.forEach.call(h.children, (c) => { if (c === from) on = true; if (on) box.appendChild(c.cloneNode(true)); if (c === to) on = false; });
          document.body.appendChild(box);
        });
        if (shots) await page.locator('#shot-krb').screenshot({path: path.join(shots, 'krb-' + tag + '.png')});
        await page.evaluate(() => document.getElementById('shot-krb').remove());
      }
      await ctx.close();
    }
  } catch (e) { out.error = String(e && e.stack || e); }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
