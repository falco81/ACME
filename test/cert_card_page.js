// The card watched (1.0.113; 1.0.114 as the kit "card-removal-watch"), in Chromium: a page signed
// in with a certificate (Playwright's clientCertificates for the certificate's port, as a card's
// once its PIN is given) and what it does when the card is taken out.
//
//   node test/cert_card_page.js PHASE BASE CERT KEY NAME PASSWORD [SHOTS_DIR]
//
// BASE is the page's https origin on 443 (https://localhost); the certificate's port is 8443.
// The card "taken out" is the port's handshake failing: every request of the browser to the port
// aborted (Playwright cannot take a client certificate away from a running context), "put back"
// is the port let through again. PHASE:
//   signout - the checks' pictures loaded (let in by the page's policy, no CSP refusal); taken out:
//             the sign-in page at once - "Signed out: the card you signed in with was taken out.",
//             signed out on the server, the address clean, nothing gone to by itself;
//   grace   - taken out: the notice (design B) within a check or so - the seconds in an emptying
//             ring counting down by the second, "Put the card back", Sign out, nothing behind it
//             reachable (inert), the server answering 423 code card; checked about every 5 s,
//             not more; back in time: the notice gone, "The card is back.", answered again; two
//             tabs of one browser sharing one check; in Czech, 1400 and 420 px wide (a phone:
//             no sideways scroll) - screenshots;
//   late    - (the grace 5 s) taken out and not back: the sign-in page - "...was not put back in
//             time.", signed out on the server - in English and Czech, 1400 and 420 px;
//   options - signed in with the password as NAME: the port never asked; Settings -> Accounts,
//             When the card is taken out (off, signout, grace), the seconds, A browser that
//             cannot be checked (allow, signout), the card's facts;
//   unable  - an iPad simulated (1.0.114, the kit's 3rd edition): the sign-in on the port works,
//             the background's picture never does - after one more try the page tells the
//             server, which leaves the sign-in unwatched: "This browser cannot have the card
//             checked (as an iPad cannot): this sign-in is not watched.", no notice, still signed
//             in, answered (200), whoami's card `unable`, checked only once a minute (loaded
//             again: not at once either) - in English and Czech, 1400 and 420 px; then (1.0.115)
//             the picture let through and the page woken: watched again ("The card is checked in
//             this browser after all: this sign-in is watched again.").
//   mixed   - (review round 2) an upgrade half way: a node of 1.0.114 sends no CORS - this
//             page's picture fails, asked once more without its Origin and that answer taken (1
//             in, 2 the notice); this version's answer to a picture without an Origin (6 by 2,
//             says nothing) taken as none. A page of 1.0.114 (its core.js) on this version: its
//             picture without an Origin gets 6 by 2, never a 403; it is told to load itself
//             again - this version's page then checks with its Origin - neither signed out nor
//             "cannot be checked".
// Prints one line of JSON: {ok, checks: {name: true|false}, timing, error?} - or {skip} where
// Chromium does not start.
const fs = require('fs');
const path = require('path');
let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { console.log(JSON.stringify({skip: 'no playwright: ' + e.message})); process.exit(0); }

(async () => {
  const [phase, base, cert, key, name, pass, shots] = process.argv.slice(2);
  const port = base.replace(/\/$/, '') + ':8443';
  const ALIVE = /:8443\/(admin\/)?\?api=cert-alive/;
  let browser;
  try {
    browser = await chromium.launch({args: ['--no-proxy-server']});
  } catch (e) {
    console.log(JSON.stringify({skip: 'chromium does not start: ' + String(e.message).slice(0, 200)}));
    return;
  }
  const out = {checks: {}, timing: {}};
  const shot = async (page, file) => {
    if (!shots) return;
    fs.mkdirSync(shots, {recursive: true});
    await page.screenshot({path: path.join(shots, file)});
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
  const context = async (lang, width, withCert) => {
    const phone = width && width < 600;
    const ctx = await browser.newContext(Object.assign({
      ignoreHTTPSErrors: true, viewport: {width: width || 1400, height: phone ? 880 : 1000},
      deviceScaleFactor: phone ? 2 : 1, isMobile: !!phone, hasTouch: !!phone},
      withCert === false ? {} : {clientCertificates: [{origin: port, certPath: cert, keyPath: key}]}));
    await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base + '/'}]);
    // A check is the picture asked with its Origin (1.0.115); one that failed is asked once more
    // without it (a node of 1.0.114 sends no CORS) - kept apart (`bare`), not a check of its own.
    ctx.looks = [];
    ctx.bare = [];
    const seen = (r) => (r.headers().origin ? ctx.looks : ctx.bare);
    ctx.on('requestfinished', async (r) => {
      if (!ALIVE.test(r.url())) return;
      const s = await r.response();
      seen(r).push(s ? s.status() : 0);
    });
    ctx.on('requestfailed', (r) => { if (ALIVE.test(r.url())) seen(r).push('x'); });
    return ctx;
  };
  const newPage = async (ctx) => {
    const page = await ctx.newPage();
    page.errs = [];
    page.csp = [];
    page.on('pageerror', (e) => page.errs.push(String(e)));
    page.on('console', (m) => { if (/Content Security Policy|Content-Security-Policy/i.test(m.text())) page.csp.push(m.text()); });
    page.on('dialog', (d) => d.dismiss().catch(() => {}));
    return page;
  };
  const certSignIn = async (page) => {
    await page.goto(base + '/admin/');
    await page.waitForSelector('#cert-go', {timeout: 15000});
    await Promise.all([page.waitForURL(/\/admin\/(\?|#|$)/, {timeout: 30000}), page.click('#cert-go')]);
    return await until(page, async () => (await page.locator('#signout').count()) > 0, 20000);
  };
  const said = (page) => page.evaluate(() => {
    const e = document.querySelector('#cert-said') || document.querySelector('#in-said');
    return e ? e.textContent : '';
  });
  const status = (page) => page.evaluate(() => fetch('?api=status', {credentials: 'same-origin'})
    .then((r) => r.json().then((d) => r.status + ':' + (d.code || ''), () => r.status + ':')));
  const whoGone = (page) => page.evaluate(() => fetch('?api=whoami', {credentials: 'same-origin'})
    .then((r) => r.json()).then((d) => !d.who));
  const cardOut = (ctx) => ctx.route(ALIVE, (r) => r.abort('failed'));
  const cardIn = (ctx) => ctx.unroute(ALIVE);
  try {
    if (phase === 'signout') {
      const ctx = await context('en');
      const page = await newPage(ctx);
      out.checks.signed_in_with_the_card = await certSignIn(page);
      out.checks.page_knows_the_watch = await page.evaluate(() => !!(window.ME && ME.card && ME.card.watch === 'signout'));
      out.checks.pictures_let_in = await until(page, () => ctx.looks.filter((s) => s === 200).length >= 2, 20000) &&
        ctx.looks.every((s) => s === 200) && page.csp.length === 0;
      out.timing.looks = ctx.looks.join(',');
      if (page.csp.length) out.timing.csp = page.csp.slice(0, 3);
      const t0 = Date.now();
      await cardOut(ctx);
      out.checks.to_the_sign_in_page_saying_why = await until(page, async () =>
        /^Signed out: the card you signed in with was taken out\.$/.test(await said(page)) &&
        (await page.locator('#signout').count()) === 0, 30000);
      out.timing.signed_out_after_s = Math.round((Date.now() - t0) / 100) / 10;
      out.checks.signed_out_on_the_server = await whoGone(page);
      out.checks.no_notice = (await page.locator('#card-lock').count()) === 0;
      out.checks.not_gone_to_the_card_again = await page.evaluate(() => !/:8443/.test(location.href));
      out.checks.address_clean = await page.evaluate(() => !/certsaid/.test(location.search));
      await shot(page, 'signed-out-signout-en-1400.png');
      // Said once: the page loaded again says nothing (a word of the tab's own, used up).
      await page.reload();
      await page.waitForTimeout(800);
      out.checks.said_once = !(/card/.test(await said(page)));
      // The address cannot make the page say it.
      await page.goto(base + '/admin/?certsaid=out');
      await page.waitForTimeout(800);
      out.checks.never_from_the_address = !(/taken out/.test(await said(page)));
      out.checks.no_page_errors = page.errs.length === 0;
      if (page.errs.length) out.errs = page.errs;
      await ctx.close();
    } else if (phase === 'grace') {
      // In English, 1400 px: everything; then Czech and a phone's width.
      let ctx = await context('en');
      let page = await newPage(ctx);
      out.checks.signed_in = await certSignIn(page);
      out.checks.pictures_200_let_in_by_the_policy = await until(page, () => ctx.looks.length >= 2, 15000) &&
        ctx.looks.every((s) => s === 200) && page.csp.length === 0;
      out.checks.first_check_soon = ctx.looks.length >= 1;
      out.checks.nothing_covers = (await page.locator('#card-lock').count()) === 0;
      await cardOut(ctx);
      let t0 = Date.now();
      out.checks.notice_within_a_check = await until(page, async () => (await page.locator('#card-lock').count()) > 0, 15000) &&
        Date.now() - t0 < 12000;
      out.timing.notice_after_s = Math.round((Date.now() - t0) / 100) / 10;
      const n1 = parseInt(await page.textContent('#card-lock-n'), 10);
      const r1 = await page.evaluate(() => +document.querySelector('#card-lock .card-lock-arc').getAttribute('stroke-dashoffset'));
      await page.waitForTimeout(2100);
      const n2 = parseInt(await page.textContent('#card-lock-n'), 10);
      const r2 = await page.evaluate(() => +document.querySelector('#card-lock .card-lock-arc').getAttribute('stroke-dashoffset'));
      out.timing.countdown = n1 + ' -> ' + n2;
      out.checks.counts_down_by_the_second = n1 <= 30 && n2 <= n1 - 2 && n2 >= n1 - 3;
      out.checks.the_ring_empties = r2 > r1 && r1 >= 0;
      out.checks.put_the_card_back = /Put the card back/.test(await page.textContent('#card-lock'));
      out.checks.until_line = /^Signed out in \d+ s unless the card is back$/.test(await page.textContent('#card-lock-left'));
      out.checks.sign_out_red = await page.evaluate(() => { const b = document.querySelector('#card-lock-out'); return !!b && b.classList.contains('danger'); });
      out.checks.nothing_behind_reachable = await page.evaluate(() => { const h = document.querySelector('header'); return !!(h && h.closest('[inert]')) && !document.querySelector('#card-lock').closest('[inert]'); });
      out.checks.focus_in_the_notice = await page.evaluate(() => !!document.activeElement && !!document.activeElement.closest('#card-lock'));
      out.checks.server_answers_423_card = (await status(page)) === '423:card';
      await shot(page, 'notice-en-1400.png');
      const outLooks = ctx.looks.length;
      await page.waitForTimeout(6000);
      out.timing.looks_in_6s_out = ctx.looks.length - outLooks;
      out.checks.out_checked_every_5s_not_more = ctx.looks.length - outLooks <= 2 && ctx.looks.length - outLooks >= 1;
      await cardIn(ctx);
      t0 = Date.now();
      out.checks.back_in_time_notice_gone = await until(page, async () => (await page.locator('#card-lock').count()) === 0, 12000);
      out.timing.back_after_s = Math.round((Date.now() - t0) / 100) / 10;
      await page.waitForTimeout(300);
      out.checks.said_the_card_is_back = /The card is back\./.test(await page.evaluate(() => document.body.innerText));
      out.checks.answered_again_nothing_inert = (await status(page)).startsWith('200') &&
        await page.evaluate(() => !document.querySelector('body > [inert]'));
      out.checks.still_signed_in_same_page = (await page.locator('#signout').count()) > 0;
      // Two tabs of one browser: one check for both.
      const p2 = await newPage(ctx);
      await p2.goto(base + '/admin/');
      await p2.waitForTimeout(3000);
      const l0 = ctx.looks.length;
      await page.waitForTimeout(20000);
      const per = ctx.looks.length - l0;
      out.timing.two_tabs_checks_in_20s = per;
      out.checks.two_tabs_one_check = per >= 3 && per <= 6;
      // One tab finds the card out: the other learns it at once (its notice too).
      await cardOut(ctx);
      out.checks.other_tab_told = await until(p2, async () => (await p2.locator('#card-lock').count()) > 0 &&
                                              (await page.locator('#card-lock').count()) > 0, 15000);
      await cardIn(ctx);
      out.checks.both_back = await until(page, async () => (await page.locator('#card-lock').count()) === 0 &&
                                         (await p2.locator('#card-lock').count()) === 0, 15000);
      if (!out.checks.both_back) {
        out.timing.both_back = {looks: ctx.looks.slice(-12).join(','), bare: ctx.bare.slice(-12).join(','),
                                one: await page.locator('#card-lock').count(), two: await p2.locator('#card-lock').count(),
                                card: await p2.evaluate(() => JSON.stringify({busy: CARD.busy, out: CARD.out, done: CARD.done, misses: CARD.misses}))};
      }
      out.checks.no_page_errors = page.errs.length === 0 && p2.errs.length === 0;
      if (page.errs.length || p2.errs.length) out.errs = page.errs.concat(p2.errs);
      await ctx.close();
      for (const [lang, width] of [['cs', 1400], ['en', 420], ['cs', 420]]) {
        const tag = lang + '-' + width;
        ctx = await context(lang, width);
        page = await newPage(ctx);
        out.checks['signed_in_' + tag] = await certSignIn(page);
        await until(page, () => ctx.looks.length >= 1, 10000);
        await cardOut(ctx);
        out.checks['notice_' + tag] = await until(page, async () => (await page.locator('#card-lock').count()) > 0, 15000);
        await page.waitForTimeout(1200);
        const txt = await page.textContent('#card-lock');
        if (lang === 'cs') {
          out.checks['czech_' + tag] = /Vraťte kartu zpět/.test(txt) && /sekund/.test(txt) &&
            /Odhlášení za \d+ s, pokud se karta nevrátí/.test(txt) && /Odhlásit/.test(txt);
          if (!out.checks['czech_' + tag]) out.timing['czech_' + tag] = txt.slice(0, 300);
        }
        if (width < 600) {
          out.checks['fits_' + tag] = await page.evaluate(() => {
            const b = document.querySelector('.card-lock-box').getBoundingClientRect();
            return b.left >= 0 && b.right <= window.innerWidth && document.documentElement.scrollWidth <= window.innerWidth + 1;
          });
        }
        await shot(page, 'notice-' + tag + '.png');
        await cardIn(ctx);
        out.checks['back_' + tag] = await until(page, async () => (await page.locator('#card-lock').count()) === 0, 15000);
        await ctx.close();
      }
    } else if (phase === 'late') {
      for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 420], ['cs', 420]]) {
        const tag = lang + '-' + width;
        const ctx = await context(lang, width);
        const page = await newPage(ctx);
        out.checks['signed_in_' + tag] = await certSignIn(page);
        await until(page, () => ctx.looks.length >= 1, 10000);
        await cardOut(ctx);
        const t0 = Date.now();
        const want = lang === 'cs' ? /^Odhlášeno: karta, kterou jste se přihlásili, nebyla včas vrácena\.$/
                                   : /^Signed out: the card you signed in with was not put back in time\.$/;
        out.checks['not_back_in_time_' + tag] = await until(page, async () => want.test(await said(page)) &&
                                                           (await page.locator('#signout').count()) === 0, 40000);
        out.timing['signed_out_after_s_' + tag] = Math.round((Date.now() - t0) / 100) / 10;
        if (!out.checks['not_back_in_time_' + tag]) out.timing['said_' + tag] = await said(page);
        out.checks['signed_out_on_the_server_' + tag] = await whoGone(page);
        out.checks['nothing_tried_by_itself_' + tag] = await page.evaluate(() => !/:8443/.test(location.href));
        await page.waitForTimeout(400);
        await shot(page, 'signed-out-late-' + tag + '.png');
        await ctx.close();
      }
    } else if (phase === 'options') {
      for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 420], ['cs', 420]]) {
        const tag = lang + '-' + width;
        const ctx = await context(lang, width, false);
        const page = await newPage(ctx);
        await page.goto(base + '/admin/');
        await page.fill('#in-name', name);
        await page.type('#in-pass', pass);
        await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
        await page.goto(base + '/admin/#settings/people');
        await page.waitForSelector('#set-admin_certlogin_card_watch', {timeout: 20000});
        await until(page, async () => (await page.locator('#cert-host-admin .krb-facts').count()) > 0, 20000);
        await page.waitForTimeout(1500);
        out.checks['password_never_watched_' + tag] = ctx.looks.length === 0;
        const un = await page.evaluate(() => {
          const seg = document.querySelector('#set-admin_certlogin_card_unable');
          const it = document.querySelector('.set-item[data-key="admin_certlogin_card_unable"]');
          return {opts: seg ? Array.prototype.map.call(seg.querySelectorAll('button'), (b) => b.dataset.v).join(',') : '',
                  val: seg ? seg.value : '', awake: !!it && !it.classList.contains('asleep'),
                  label: it ? it.innerText.split('\n')[0] : ''};
        });
        out.checks['unable_seg_' + tag] = un.opts === 'allow,signout' && un.awake &&
          (lang === 'en' ? /A browser that cannot be checked/.test(un.label) : /Prohlížeč, který kontrolovat nejde/.test(un.label));
        if (!out.checks['unable_seg_' + tag]) out.timing['unable_' + tag] = un;
        const st = await page.evaluate(() => {
          const seg = document.querySelector('#set-admin_certlogin_card_watch');
          const it = (k) => document.querySelector('.set-item[data-key="' + k + '"]');
          const num = (k) => { const i = document.querySelector('#set-' + k); return i ? [i.type, i.min, i.max, i.value].join(',') : ''; };
          return {opts: seg ? Array.prototype.map.call(seg.querySelectorAll('button'), (b) => b.dataset.v).join(',') : '',
                  val: seg ? seg.value : '',
                  every: !!it('admin_certlogin_card_every') && !it('admin_certlogin_card_every').classList.contains('asleep'),
                  grace: !!it('admin_certlogin_card_grace') && !it('admin_certlogin_card_grace').classList.contains('asleep'),
                  everyBox: num('admin_certlogin_card_every'), graceBox: num('admin_certlogin_card_grace'),
                  stale: !!it('admin_certlogin_card_stale')};
        });
        out.checks['seg_' + tag] = st.opts === 'off,signout,grace' && st.val === 'grace' && st.every && st.grace && !st.stale;
        out.checks['seconds_boxes_' + tag] = st.everyBox === 'number,5,300,5' && st.graceBox === 'number,5,600,30';
        if (!out.checks['seg_' + tag] || !out.checks['seconds_boxes_' + tag]) out.timing['settings_' + tag] = st;
        out.checks['no_page_scroll_' + tag] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
        await page.evaluate(() => document.querySelector('.set-item[data-key="admin_certlogin_card_watch"]').scrollIntoView({block: 'start'}));
        await page.waitForTimeout(400);
        await shot(page, 'settings-' + tag + '.png');
        await page.evaluate(() => document.querySelector('.set-item[data-key="admin_certlogin_card_unable"]').scrollIntoView({block: 'center'}));
        await page.waitForTimeout(400);
        await shot(page, 'settings-unable-' + tag + '.png');
        const facts = await page.evaluate(() => document.querySelector('#cert-host-admin .krb-facts').innerText);
        out.checks['facts_' + tag] = lang === 'en'
          ? /When the card is taken out\s+a notice, then signed out unless it is back within 30 s \(checked every 5 s\)/.test(facts)
          : /Když se karta vytáhne\s+upozornění, pak odhlášení, pokud se karta nevrátí do 30 s \(kontrola každých 5 s\)/.test(facts);
        if (!out.checks['facts_' + tag]) out.timing['facts_' + tag] = facts.slice(-600);
        await page.evaluate(() => document.querySelector('#cert-host-admin .krb-facts').scrollIntoView({block: 'start'}));
        await page.waitForTimeout(400);
        await shot(page, 'facts-' + tag + '.png');
        out.checks['no_page_errors_' + tag] = page.errs.length === 0;
        await ctx.close();
      }
    } else if (phase === 'unable') {
      const want = {en: 'This browser cannot have the card checked (as an iPad cannot): this sign-in is not watched.',
                    cs: 'V tomto prohlížeči kartu kontrolovat nejde (stejně jako na iPadu): toto přihlášení se nehlídá.'};
      for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 420], ['cs', 420]]) {
        const tag = lang + '-' + width;
        const ctx = await context(lang, width);
        // The background's picture never comes (Safari on iPadOS signs no connection for it);
        // the sign-in itself, a top-level navigation, does.
        await cardOut(ctx);
        const page = await newPage(ctx);
        out.checks['signed_in_' + tag] = await certSignIn(page);
        out.checks['page_watches_at_first_' + tag] = await page.evaluate(() => !!(window.ME && ME.card));
        const t0 = Date.now();
        out.checks['said_' + tag] = await until(page, async () => (await page.evaluate(() => {
          const t = document.querySelector('#toast'); return t && t.classList.contains('show') ? t.textContent : '';
        })) === want[lang], 20000);
        out.timing['said_after_s_' + tag] = Math.round((Date.now() - t0) / 100) / 10;
        out.timing['looks_' + tag] = ctx.looks.join(',');
        out.checks['two_tries_then_told_' + tag] = ctx.looks.filter((x) => x === 'x').length === 2 &&
          ctx.bare.filter((x) => x === 'x').length === 2;
        await page.waitForTimeout(300);
        await shot(page, 'unable-' + tag + '.png');
        out.checks['no_notice_' + tag] = (await page.locator('#card-lock').count()) === 0;
        out.checks['still_signed_in_' + tag] = (await page.locator('#signout').count()) > 0 &&
          (await status(page)).startsWith('200');
        out.checks['whoami_card_unable_' + tag] = await page.evaluate(() => fetch('?api=whoami', {credentials: 'same-origin'})
          .then((r) => r.json()).then((d) => !!d.who && !!d.who.card && d.who.card.unable === true));
        const l0 = ctx.looks.length;
        await page.waitForTimeout(8000);
        out.checks['no_more_checks_' + tag] = ctx.looks.length === l0;
        if (width === 1400) {
          await page.reload();
          await page.waitForSelector('#signout', {timeout: 15000});
          await page.waitForTimeout(4000);
          out.checks['loaded_again_unable_' + tag] = await page.evaluate(() => !!(window.ME && ME.card && ME.card.unable)) &&
            ctx.looks.length <= l0 + 1;      // the one check of the page woken (pageshow) at most
        }
        if (tag === 'en-1400') {
          // Not for ever (1.0.115): the picture comes now, the page woken - watched again.
          await cardIn(ctx);
          await page.evaluate(() => window.dispatchEvent(new Event('focus')));
          out.checks.watched_again = await until(page, async () => (await page.evaluate(() => {
            const t = document.querySelector('#toast'); return t && t.classList.contains('show') ? t.textContent : '';
          })) === 'The card is checked in this browser after all: this sign-in is watched again.', 15000);
          out.checks.watched_again_whoami = await page.evaluate(() => fetch('?api=whoami', {credentials: 'same-origin'})
            .then((r) => r.json()).then((d) => !!d.who && !!d.who.card && !d.who.card.unable));
        }
        if (width < 600) out.checks['no_page_scroll_' + tag] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
        out.checks['no_page_errors_' + tag] = page.errs.length === 0;
        if (page.errs.length) out.errs = (out.errs || []).concat(page.errs);
        await ctx.close();
      }
    } else if (phase === 'mixed') {
      // acme-api.php's pictures: 1 and 2 wide (a node of 1.0.114 too), 6 by 2 (says nothing)
      const gifs = {'1x1': 'R0lGODlhAQABAIEAAAAAAP///wAAAAAAACH5BAEAAAAALAAAAAABAAEAAAgEAAEEBAA7',
                    '2x1': 'R0lGODlhAgABAIEAAAAAAP///wAAAAAAACH5BAEAAAAALAAAAAACAAEAAAgFAAEACAgAOw==',
                    '6x2': 'R0lGODlhBgACAIEAAAAAAP///wAAAAAAACH5BAEAAAAALAAAAAAGAAIAAAgIAAEIHEhQYEAAOw=='};
      const gif = (w, h) => Buffer.from(gifs[w + 'x' + h], 'base64');
      // a) This page against a node of 1.0.114: no CORS on the picture asked with its Origin; the
      // same picture asked without it is that node's answer.
      let ctx = await context('en');
      let page = await newPage(ctx);
      out.checks.signed_in = await certSignIn(page);
      await until(page, () => ctx.looks.length >= 1, 10000);
      let oldNode = 1;
      let lost = 0;
      page.on('request', (r) => { if (/[?&]api=cert-lost/.test(r.url())) lost += 1; });
      // (the picture asked with its Origin failed as a CORS refusal fails it - to the page an
      // error like any other; Playwright's own answers are not held to CORS)
      await ctx.route(ALIVE, (r) => r.request().headers().origin ? r.abort('failed')
        : r.fulfill({status: 200, contentType: 'image/gif', body: gif(oldNode, 1), headers: {'Cache-Control': 'no-store'}}));
      const l0 = ctx.bare.length;
      await page.evaluate(() => cardCheckNow());
      out.checks.old_node_asked_without_origin = await until(page, () => ctx.bare.length > l0, 10000);
      await page.waitForTimeout(1500);
      out.checks.old_node_card_in = (await page.locator('#card-lock').count()) === 0 && lost === 0 &&
        (await page.locator('#signout').count()) > 0;
      oldNode = 2;
      await page.evaluate(() => cardCheckNow());
      out.checks.old_node_card_out_the_notice = await until(page, async () => (await page.locator('#card-lock').count()) > 0, 10000) &&
        lost === 0;
      oldNode = 1;
      out.checks.old_node_card_back = await until(page, async () => (await page.locator('#card-lock').count()) === 0, 15000);
      // ...this version's answer to a picture without an Origin: says nothing - taken as none.
      await ctx.unroute(ALIVE);
      await ctx.route(ALIVE, (r) => r.request().headers().origin ? r.abort('failed')
        : r.fulfill({status: 200, contentType: 'image/gif', body: gif(6, 2), headers: {'Cache-Control': 'no-store'}}));
      await page.evaluate(() => cardCheckNow());
      out.checks.nothing_said_is_none = await until(page, () => lost >= 1, 10000);
      await ctx.unroute(ALIVE);
      await ctx.close();
      // b) A page of 1.0.114 on this version (its core.js, as a tab left open over the upgrade).
      const oldJs = process.env.ACME_OLD_CORE_JS;
      if (oldJs && fs.existsSync(oldJs)) {
        ctx = await context('en');
        page = await newPage(ctx);
        out.checks.old_page_signed_in = await certSignIn(page);
        let served = 0;
        await ctx.route(/\/assets\/core\.js/, (r) => {
          if (served++ === 0) return r.fulfill({status: 200, contentType: 'application/javascript', body: fs.readFileSync(oldJs)});
          return r.continue();
        });
        const answers = [];
        ctx.on('response', async (r) => {
          if (!ALIVE.test(r.url())) return;
          answers.push({status: r.status(), origin: !!r.request().headers().origin});
        });
        const posted = [];
        page.on('request', (r) => { if (/[?&]api=cert-lost/.test(r.url())) posted.push(r.postData() || ''); });
        await page.reload();
        await page.waitForSelector('#signout', {timeout: 15000});
        out.checks.old_page_running = await page.evaluate(() => typeof cardCheck === 'function' && !/crossOrigin/.test(cardCheck.toString()));
        // its first check (1.5 s): 6 by 2 - no cookie to it, said over 443 without `v`; told
        // to load itself again - this version's core.js then, its picture with its Origin.
        out.checks.old_page_loaded_again_new_script = await until(page, async () => served >= 2 &&
          await page.evaluate(() => typeof cardCheck === 'function' && /crossOrigin/.test(cardCheck.toString())), 30000);
        out.timing.old_page_answers = answers;
        out.timing.old_page_posted = posted;
        out.checks.old_page_never_403 = answers.filter((a) => !a.origin).every((a) => a.status === 200) &&
          answers.some((a) => !a.origin);
        out.checks.old_page_told_without_v = posted.some((x) => !/"v"/.test(x) && /nocookie/.test(x));
        await until(page, () => answers.some((a) => a.origin && a.status === 200), 15000);
        await page.waitForTimeout(1000);
        out.checks.old_page_still_signed_in_watched = (await page.locator('#signout').count()) > 0 &&
          (await status(page)).startsWith('200') &&
          await page.evaluate(() => fetch('?api=whoami', {credentials: 'same-origin'})
            .then((r) => r.json()).then((d) => !!d.who && !!d.who.card && !d.who.card.unable && !d.who.card.locked));
        out.checks.old_page_no_notice = (await page.locator('#card-lock').count()) === 0;
        await ctx.close();
      } else {
        out.timing.old_page = 'skipped: ACME_OLD_CORE_JS not given';
      }
    }
    out.ok = Object.keys(out.checks).length > 0 && Object.keys(out.checks).every((k) => out.checks[k] === true);
  } catch (e) {
    out.ok = false;
    out.error = String(e && e.stack || e).slice(0, 1500);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
