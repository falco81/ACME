// The pages' half of test/test_upgrade_ui.py, in Chromium: an upgrade simulated as the kit's
// sim.js does it - root's progress file written by hand, the API and PHP killed and started.
//
//   node test/upgrade_ui_page.js MODE BASE_A BASE_B NAME PASSWORD CTL LANG WIDTH
//
//   MODE single  one server: running -> API killed -> PHP killed -> PHP back -> API back -> done
//                (exactly one reload) -> failed (red, dismissible) -> signed out during an upgrade
//                (the sign-in page's band, loaded again when the API answers)
//   MODE short   the band running and failed only (the layout at another width or language)
//   MODE cluster two nodes: the cluster's plan says A done, B at it, while A's own file says done
//                - no reload; the page then answered by B's PHP (the VIP address moved) - the
//                band and the session stay; the plan done - one reload.
//   CTL          a command that does what the page cannot: CTL file A|B JSON, CTL rm A|B,
//                CTL kill-api, CTL start-api, CTL kill-php A, CTL start-php A, CTL plan JSON,
//                CTL vip A|B (the VIP address moved: BASE_A is then the address both nodes share)
//
// Prints one line of JSON: what was seen.
const { chromium } = require('playwright');
const { execSync } = require('child_process');

(async () => {
  const [mode, baseA, baseB, name, pass, ctl, lang, widthS] = process.argv.slice(2);
  const width = Number(widthS || 1300);
  const out = {mode, lang, width, errors: [], bad: []};
  const run = (args) => execSync(ctl + ' ' + args, {stdio: ['ignore', 'pipe', 'inherit']}).toString();
  const now = () => Math.floor(Date.now() / 1000);
  const tell = (node, o) => run("file " + node + " '" + JSON.stringify(Object.assign({at: now()}, o)) + "'");
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: width, height: 900}});
  await ctx.addCookies([{name: 'acme_lang', value: lang, url: baseA}]);
  const page = await ctx.newPage();
  let navs = 0;
  page.on('framenavigated', f => { if (f === page.mainFrame()) navs++; });
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  page.on('dialog', d => { out.errors.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (ms) => page.waitForTimeout(ms);
  // Anything red while an upgrade is expected: a red toast or the "not answering" bar.
  const watchRed = async () => {
    await page.evaluate(() => {
      if (window.__watching) return;
      window.__watching = true;
      window.__bad = [];
      const look = () => {
        const t = document.getElementById('toast');
        if (t && t.classList.contains('show') && t.classList.contains('bad')) window.__bad.push('toast: ' + t.textContent);
        const o = document.getElementById('offline');
        if (o && !o.hidden) window.__bad.push('offline: ' + o.textContent);
      };
      new MutationObserver(look).observe(document.body, {subtree: true, attributes: true, childList: true});
    });
  };
  const red = async () => (await page.evaluate(() => (window.__bad || []).slice()));
  const band = async () => page.evaluate(() => {
    const b = document.getElementById('upband');
    if (!b || b.hidden) return null;
    const r = b.getBoundingClientRect();
    const pill = document.getElementById('state-pill');
    return {text: b.innerText, cls: b.className, right: Math.round(r.right), left: Math.round(r.left),
            title: (b.querySelector('.upband-title') || {}).textContent || '',
            line: (b.querySelector('.upband-line') || {}).textContent || '',
            means: (b.querySelector('.upband-means') || {}).textContent || '',
            rows: b.querySelectorAll('.upband-node').length,
            x: !!b.querySelector('.upband-x'), open: !!b.querySelector('.upband-means a.fgo'),
            pill: pill ? pill.textContent.trim() : '', pillCls: pill ? pill.className : '',
            offline: !document.getElementById('offline').hidden,
            maint: (document.getElementById('m-maint') || {}).textContent || '',
            server: (document.getElementById('m-server') || {}).textContent || '',
            wide: document.documentElement.scrollWidth, inner: window.innerWidth,
            signedIn: !!document.getElementById('signout')};
  });
  const bandWait = async (fn, ms) => {
    const end = Date.now() + (ms || 15000);
    let got = null;
    while (Date.now() < end) {
      got = await band();
      if (fn(got)) return got;
      await wait(400);
    }
    return got;
  };
  const signIn = async (base) => {
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForSelector('#signout', {timeout: 15000});
    await wait(1200);
    await watchRed();
  };
  const shot = async (n) => {
    if (!process.env.UPG_SHOTS) return;
    await page.evaluate(() => { window.scrollTo(0, 0); const p = document.querySelector('.panel:not([hidden])'); if (p) p.scrollTop = 0; });
    await wait(300);
    await page.screenshot({path: process.env.UPG_SHOTS + '/' + mode + '-' + lang + '-' + width + '-' + n + '.png'});
    out.scrolled = out.scrolled || [];
    out.scrolled.push(await page.evaluate(() => Math.round(window.scrollY)));
  };
  try {
    run('rm A');
    run('rm B');
    if (mode === 'single' || mode === 'short') {
      await signIn(baseA);
      const started = now();
      const base = {id: 'k1', version: '1.0.121', from: '1.0.120', by: 'tester on the pages', node: 'testnode',
                    parts: 9, started: started};
      // ---- 1. running: the band at once, the pill, the cards ----
      tell('A', Object.assign({state: 'running', part: 1, words: 'root checks the package'}, base));
      out.running = await bandWait(b => b && /1\.0\.121/.test(b.title), 15000);
      await shot('01-running');
      if (mode === 'short') {
        tell('A', Object.assign({}, base, {id: 'k2', state: 'failed', part: 5, words: 'The tree', started: started - 95,
                                           said: 'install.sh --upgrade stopped (exit 1) - 1.0.120 runs again'}));
        out.failed = await bandWait(b => b && /bad/.test(b.cls), 15000);
        await shot('08-failed');
        out.red = await red();
      } else {
        // ---- 2. the API restarting ----
        tell('A', Object.assign({state: 'running', part: 7, words: 'The pages'}, base));
        run('kill-api');
        await wait(7000);
        out.apiDown = await band();
        await shot('03-api-down');
        // ---- 3. nginx and PHP restarting too ----
        tell('A', Object.assign({state: 'running', part: 8, words: 'The service'}, base));
        run('kill-php A');
        await wait(7000);
        out.phpDown = await band();
        await shot('04-php-down');
        // ---- 4. PHP back, the API not yet ----
        run('start-php A');
        out.phpBack = await bandWait(b => b && /8/.test(b.line) && !/nginx/.test(b.means), 15000);
        await shot('05-php-back');
        // ---- 5. the API back, still running ----
        run('start-api');
        const navs0 = navs;
        out.apiBack = await bandWait(b => b && !/not answering/.test(b.means) && !/neodpovíd/.test(b.means), 30000);
        out.navsWhileRunning = navs - navs0;
        out.redWhileRunning = await red();
        await shot('06-api-back');
        // ---- 6. done: loaded again, once ----
        const navs1 = navs;
        tell('A', Object.assign({state: 'done', part: 9, words: 'acme 1.0.121 runs'}, base));
        const end = Date.now() + 15000;
        while (Date.now() < end && navs === navs1) await wait(300);
        await wait(8000);                       // ...and not again
        out.reloads = navs - navs1;
        await page.waitForSelector('#signout', {timeout: 15000});
        out.afterDone = await band();
        await shot('07-done');
        await watchRed();
        // ---- 7. failed: red, the reason, dismissible ----
        tell('A', Object.assign({}, base, {id: 'k2', state: 'failed', part: 5, words: 'The tree', started: started - 95,
                                           said: 'install.sh --upgrade stopped (exit 1) - 1.0.120 runs again'}));
        out.failed = await bandWait(b => b && /bad/.test(b.cls), 15000);
        await shot('08-failed');
        // the x is what a finger at its place touches (the page at its top), then pressed
        out.xOnTop = await page.evaluate(() => {
          window.scrollTo(0, 0);
          const x = document.querySelector('#upband .upband-x');
          const r = x.getBoundingClientRect();
          const at = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
          return at === x;
        });
        await page.evaluate(() => document.querySelector('#upband .upband-x').click());
        await wait(600);
        out.failedHidden = await band();
        await page.reload();
        await page.waitForSelector('#signout', {timeout: 15000});
        await wait(3000);
        out.failedHiddenAfterReload = await band();
        // ---- 8. signed out during an upgrade ----
        await ctx.clearCookies();
        await ctx.addCookies([{name: 'acme_lang', value: lang, url: baseA}]);
        tell('A', Object.assign({}, base, {id: 'k3', state: 'running', part: 8, words: 'The service', started: now() - 30}));
        run('kill-api');
        await page.goto(baseA + '/admin/index.php');
        await wait(2500);
        out.signin = await page.evaluate(() => {
          const b = document.getElementById('upband');
          return {band: !!b, text: b ? b.innerText : '', api: b ? b.dataset.api : '', form: !!document.getElementById('in-name'),
                  offline: Array.from(document.querySelectorAll('.signin .offline:not(.upband)')).map(x => x.textContent),
                  wide: document.documentElement.scrollWidth, inner: window.innerWidth};
        });
        await shot('09-signin');
        const navs2 = navs;
        run('start-api');
        const end2 = Date.now() + 30000;
        while (Date.now() < end2 && navs === navs2) await wait(300);
        await wait(1500);
        out.signinReloaded = navs - navs2;
        out.signinAfter = await page.evaluate(() => ({form: !!document.getElementById('in-name'),
          api: (document.getElementById('upband') || {dataset: {}}).dataset.api || ''}));
      }
    } else if (mode === 'cluster') {
      const t = now();
      const plan = (bState, bMore) => run("plan '" + JSON.stringify({
        id: 'p1', version: '1.0.121', order: ['acmeA', 'acmeB'], by: 'tester', at: t - 300, from: 'acmeB',
        steps: {acmeA: {state: 'done', at: t - 120, from_version: '1.0.120', said: '1.0.121, checked, back in service'},
                acmeB: Object.assign({state: bState, at: now(), from_version: '1.0.120'}, bMore || {})}}) + "'");
      plan('installing', {asked: t - 60, part: 3, parts: 9, part_words: 'Python', said: 'handed to root (acme-upgrade.service)'});
      // the node that answers (A) is done itself - its own file says so
      tell('A', {state: 'done', id: 'p1', version: '1.0.121', from: '1.0.120', by: 'tester', node: 'acmeA', part: 9, parts: 9,
                 words: 'acme 1.0.121 runs', started: t - 300});
      tell('B', {state: 'running', id: 'p1', version: '1.0.121', from: '1.0.120', by: 'tester', node: 'acmeB', part: 5, parts: 9,
                 words: 'The pages', started: t - 200});
      await signIn(baseA);
      const navs0 = navs;
      out.onA = await bandWait(b => b && b.rows === 2, 15000);
      await wait(7000);
      out.onA2 = await band();
      out.reloadsWhileBRuns = navs - navs0;
      await shot('c1-on-a');
      // ---- the VIP address moves: the page answered by B's PHP ----
      run('vip B');
      out.onB = await bandWait(b => b && /(step|krok) 5 (of|z) 9/.test(b.text) && b.rows === 2 && /acmeB/.test(b.line), 15000);
      await shot('c2-on-b');
      // B's API restarting while the page is on B
      run('kill-api');
      await wait(6000);
      out.onBapiDown = await band();
      run('start-api');
      out.onBback = await bandWait(b => b && !/API/.test(b.means), 30000);
      out.reloadsBeforeEnd = navs - navs0;
      out.redBeforeEnd = await red();
      // ---- every node done: loaded again, once ----
      const navs1 = navs;
      plan('done', {said: '1.0.121, checked, back in service'});
      tell('B', {state: 'done', id: 'p1', version: '1.0.121', from: '1.0.120', by: 'tester', node: 'acmeB', part: 9, parts: 9,
                 words: 'acme 1.0.121 runs', started: t - 200});
      const end = Date.now() + 20000;
      while (Date.now() < end && navs === navs1) await wait(300);
      await wait(8000);
      out.reloadsAtEnd = navs - navs1;
      out.afterEnd = await band();
      await shot('c3-done');
      run('vip A');
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
