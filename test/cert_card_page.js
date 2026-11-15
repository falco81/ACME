// The card watched (1.0.113), in Chromium: a page signed in with a certificate (Playwright's
// clientCertificates for the certificate's port) and what it does when the card is taken out.
//
//   node test/cert_card_page.js PHASE BASE CERT KEY NAME PASSWORD [SHOTS_DIR]
//
// BASE is the page's https origin on 443 (https://localhost); the certificate's port is 8443.
// PHASE:
//   signout - signed in with the certificate, the checks seen answered, then every request of the
//             browser to the port failed (as a handshake does when the card's key no longer
//             signs - Playwright cannot take a client certificate away from a running context):
//             the page goes to the sign-in page saying "Signed out: your card was removed";
//   lock    - the same with the part set to lock: the lock over the page, its countdown, nothing
//             else answered; the port let through again (the card back): the lock goes and the
//             page is as it was - in English and Czech, 1400 and 420 px wide (screenshots);
//   options - signed in with the password as NAME: Settings -> Accounts, the certificate's card
//             with its "When the card is taken out" options (screenshots).
// Prints one line of JSON: {ok, checks: {name: true|false}, error?} - or {skip} where Chromium
// does not start.
const fs = require('fs');
const path = require('path');
let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { console.log(JSON.stringify({skip: 'no playwright: ' + e.message})); process.exit(0); }

(async () => {
  const [phase, base, cert, key, name, pass, shots] = process.argv.slice(2);
  const port = base.replace(/\/$/, '') + ':8443';
  let browser;
  try {
    browser = await chromium.launch();
  } catch (e) {
    console.log(JSON.stringify({skip: 'chromium does not start: ' + String(e.message).slice(0, 200)}));
    return;
  }
  const out = {checks: {}, timing: {}};
  const shot = async (page, file, sel) => {
    if (!shots) return;
    fs.mkdirSync(shots, {recursive: true});
    if (sel) await page.locator(sel).first().screenshot({path: path.join(shots, file)});
    else await page.screenshot({path: path.join(shots, file)});
  };
  const until = async (page, fn, ms) => {
    const end = Date.now() + (ms || 15000);
    for (;;) {
      let v = false;
      try { v = await fn(); } catch (e) { v = false; }
      if (v) return true;
      if (Date.now() > end) return false;
      await page.waitForTimeout(250);
    }
  };
  const context = async (lang, width) => {
    const ctx = await browser.newContext({
      ignoreHTTPSErrors: true, viewport: {width: width || 1400, height: width && width < 600 ? 900 : 1000},
      clientCertificates: [{origin: port, certPath: cert, keyPath: key}]});
    await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base + '/'}]);
    const page = await ctx.newPage();
    page.on('dialog', (d) => d.dismiss().catch(() => {}));
    const seen = {ok: 0, all: 0};
    page.on('response', (r) => {
      if (r.url().indexOf(':8443/admin/?api=cert-alive') < 0) return;
      seen.all++;
      r.json().then((d) => { if (d && d.state === 'ok') seen.ok++; }).catch(() => {});
    });
    return {ctx, page, seen};
  };
  const certSignIn = async (page) => {
    await page.goto(base + '/admin/');
    await page.waitForSelector('#cert-go', {timeout: 15000});
    await Promise.all([page.waitForURL(/\/admin\/(\?|#|$)/, {timeout: 30000}), page.click('#cert-go')]);
    return await until(page, async () => (await page.locator('#signout').count()) > 0, 20000);
  };
  try {
    if (phase === 'signout') {
      const {ctx, page, seen} = await context('en');
      out.checks.signed_in_with_the_card = await certSignIn(page);
      out.checks.page_knows_the_watch = await page.evaluate(() => !!(window.ME && ME.card && ME.card.watch === 'signout'));
      out.checks.checks_answered_ok = await until(page, () => seen.ok >= 2, 20000);
      // The card taken out: every handshake with the port fails from now on.
      const t0 = Date.now();
      await page.route(port + '/**', (r) => r.abort('failed'));
      out.checks.to_the_sign_in_page = await until(page, async () => {
        const said = await page.evaluate(() => { const e = document.querySelector('#cert-said') || document.querySelector('#in-said'); return e ? e.textContent : ''; });
        return /Signed out: your card was removed/.test(said) && (await page.locator('#signout').count()) === 0;
      }, 45000);
      out.timing.signed_out_after_s = Math.round((Date.now() - t0) / 100) / 10;
      out.checks.not_gone_to_the_card_again = await page.evaluate(() => !/:8443/.test(location.href));
      out.checks.address_clean = await page.evaluate(() => !/certsaid/.test(location.search));
      await shot(page, 'signin-removed-en-1400.png');
      await ctx.close();
    } else if (phase === 'lock') {
      let n = 0;
      for (const lang of ['en', 'cs']) {
        for (const width of [1400, 420]) {
          const tag = lang + '-' + width;
          const {ctx, page, seen} = await context(lang, width);
          out.checks['signed_in_' + tag] = await certSignIn(page);
          out.checks['checks_ok_' + tag] = await until(page, () => seen.ok >= 1, 20000);
          const t0 = Date.now();
          await page.route(port + '/**', (r) => r.abort('failed'));
          out.checks['locked_' + tag] = await until(page, async () => (await page.locator('#card-lock').count()) > 0, 40000);
          out.timing['locked_after_s_' + tag] = Math.round((Date.now() - t0) / 100) / 10;
          await page.waitForTimeout(1600);
          if (n === 0) {
            // Nothing of the pages answered while locked: the API says 423.
            out.checks.api_locked = await page.evaluate(() => fetch('?api=status', {credentials: 'same-origin'}).then((r) => r.status === 423));
            out.checks.countdown = /Signed out in \d+ s/.test(await page.locator('.card-lock-left').textContent());
            out.checks.focus_on_sign_out = await page.evaluate(() => !!document.activeElement && !!document.activeElement.closest('#card-lock'));
          }
          await shot(page, 'lock-' + tag + '.png');
          // The card back: the lock goes, the page reloads signed in.
          const t1 = Date.now();
          await page.unroute(port + '/**');
          out.checks['back_' + tag] = await until(page, async () => (await page.locator('#card-lock').count()) === 0 &&
                                                   (await page.locator('#signout').count()) > 0, 30000);
          out.timing['back_after_s_' + tag] = Math.round((Date.now() - t1) / 100) / 10;
          out.checks['api_again_' + tag] = await page.evaluate(() => fetch('?api=status', {credentials: 'same-origin'}).then((r) => r.status === 200));
          await ctx.close();
          n++;
        }
      }
    } else if (phase === 'options') {
      for (const lang of ['en', 'cs']) {
        for (const width of [1400, 420]) {
          const tag = lang + '-' + width;
          const ctx = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: width, height: width < 600 ? 900 : 1000}});
          await ctx.addCookies([{name: 'acme_lang', value: lang, url: base + '/'}]);
          const page = await ctx.newPage();
          await page.goto(base + '/admin/');
          await page.fill('#in-name', name);
          await page.type('#in-pass', pass);
          await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
          await page.goto(base + '/admin/#settings/people');
          await page.waitForSelector('#set-admin_certlogin_card_watch', {timeout: 20000});
          await until(page, async () => (await page.locator('#cert-host-admin .krb-facts').count()) > 0, 20000);
          out.checks['seg_' + tag] = await page.evaluate(() => {
            const s = document.querySelector('#set-admin_certlogin_card_watch');
            return !!s && s.classList.contains('seg') && s.querySelectorAll('button').length === 3;
          });
          out.checks['no_page_scroll_' + tag] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
          const item = page.locator('.set-item[data-key="admin_certlogin_card_watch"]');
          await page.evaluate(() => document.querySelector('.set-item[data-key="admin_certlogin_card_watch"]').scrollIntoView({block: 'start'}));
          await page.waitForTimeout(400);
          // The settings of the card watched, as one piece.
          const box = await page.evaluate(() => {
            const keys = ['admin_certlogin_card_watch', 'admin_certlogin_card_every', 'admin_certlogin_card_grace', 'admin_certlogin_card_stale'];
            const r = keys.map((k) => document.querySelector('.set-item[data-key="' + k + '"]')).filter(Boolean).map((e) => e.getBoundingClientRect());
            const top = Math.min.apply(null, r.map((x) => x.top)), bottom = Math.max.apply(null, r.map((x) => x.bottom));
            const left = Math.min.apply(null, r.map((x) => x.left)), right = Math.max.apply(null, r.map((x) => x.right));
            return {top: top, left: left, width: right - left, height: bottom - top};
          });
          if (shots && box.height > 0) {
            fs.mkdirSync(shots, {recursive: true});
            await page.screenshot({path: path.join(shots, 'options-' + tag + '.png'),
                                   clip: {x: Math.max(0, box.left - 12), y: Math.max(0, box.top - 12), width: Math.min(width, box.width + 24), height: box.height + 24}});
          }
          const facts = page.locator('#cert-host-admin .krb-facts');
          await page.evaluate(() => document.querySelector('#cert-host-admin .krb-facts').scrollIntoView({block: 'start'}));
          await page.waitForTimeout(400);
          out.checks['facts_' + tag] = /(Card watched|Hlídání karty)/.test(await facts.textContent());
          if (shots) {
            const fb = await page.evaluate(() => {
              const a = document.querySelector('#cert-host-admin .krb-facts'), b = document.querySelector('#cert-host-admin .card-watch-note') || a;
              const r1 = a.getBoundingClientRect(), r2 = b.getBoundingClientRect();
              return {x: Math.min(r1.left, r2.left), y: r1.top, w: Math.max(r1.right, r2.right) - Math.min(r1.left, r2.left), h: r2.bottom - r1.top};
            });
            await page.screenshot({path: path.join(shots, 'facts-' + tag + '.png'),
                                   clip: {x: Math.max(0, fb.x - 12), y: Math.max(0, fb.y - 12), width: Math.min(width, fb.w + 24), height: fb.h + 24}});
          }
          await ctx.close();
        }
      }
    }
    out.ok = Object.keys(out.checks).every((k) => out.checks[k] === true);
  } catch (e) {
    out.ok = false;
    out.error = String(e && e.stack || e).slice(0, 1500);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
