// The pages' half of test/test_dir_picker.py: "Pick from the directory" (core.js dirPickButton,
// 1.0.128) beside every box that holds a name of the directory - in Chromium against a real
// daemon, php -S and test/mockldap.py.
//
//   node test/dir_picker_page.js BASE_URL PASSWORD MODE [SHOTS_DIR]
//
// MODE admin  - the settings' groups, the directory's look-up and try boxes, the certificate
//               look-up, the teams' access check and Teams from directory groups; typed by hand
//               still works; 390 / 768 / 1400 px; Czech; a read-only account sees no button
// MODE portal - the portal's member dialog of a team manager
// MODE nodir  - the directory gone: the picker says so, the boxes still take what is typed
//
// Prints one line of JSON: what was seen ({errors: [...]} always there).
const { chromium } = require('playwright');

(async () => {
  const [base, pass, mode, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const watch = (page) => {
    page.on('pageerror', (e) => out.errors.push(String(e.message || e)));
    page.on('console', (m) => {
      // a refusal of the API is said on the page; the browser logs its status too
      if (m.type() === 'error' && !/status of 40[34]/.test(m.text())) out.errors.push('console: ' + m.text());
    });
    page.on('dialog', async (d) => { out.errors.push('browser dialog: ' + d.message()); await d.dismiss(); });
  };
  const admin = async (name, lang, width, hash) => {
    const ctx = await browser.newContext({viewport: {width, height: width < 500 ? 844 : 900}});
    await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
    const page = await ctx.newPage();
    watch(page);
    await page.goto(base + '/admin/index.php');
    await page.fill('#in-name', name);
    await page.type('#in-pass', pass);
    await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
    await page.waitForTimeout(400);
    await page.goto(base + '/admin/index.php' + hash);
    await page.waitForTimeout(900);
    return page;
  };
  const shot = async (page, name) => { if (shots) { await page.waitForTimeout(300); await page.screenshot({path: shots + '/' + name + '.png'}); } };
  const pop = (page) => page.waitForSelector('#dpk-pop', {timeout: 10000});
  const search = async (page, words) => {
    await page.fill('#dpk-q', words);
    await page.waitForFunction(() => {
      const s = document.querySelector('#dpk-pop .dpk-said');
      return document.querySelector('#dpk-pop .dpk-it') || (s && /Nothing|Nic|directory|adresář/i.test(s.textContent) && !/Asking|Ptám/.test(s.textContent));
    }, null, {timeout: 15000});
  };
  const pickItem = (page, v) => page.evaluate((v) => {
    const it = [...document.querySelectorAll('#dpk-pop .dpk-it')].find((x) => x.dataset.v === v);
    if (!it) return false;
    it.click();
    return true;
  }, v);
  const items = (page) => page.$$eval('#dpk-pop .dpk-it', (r) => r.map((x) => ({v: x.dataset.v, on: x.classList.contains('on'),
    state: (x.querySelector('.dpk-state') || {}).textContent || '', dn: (x.querySelector('.dpk-dn') || {}).textContent || ''})));
  const said = (page) => page.$eval('#dpk-pop .dpk-said', (s) => s.textContent).catch(() => '');
  const closed = (page) => page.waitForSelector('#dpk-pop', {state: 'detached', timeout: 5000});
  // the popover on the screen, the page and the popup under it unchanged: no new scrollbar
  const fits = (page) => page.evaluate(() => {
    const p = document.getElementById('dpk-pop');
    const r = p.getBoundingClientRect(), vw = document.documentElement.clientWidth;
    const list = p.querySelector('.dpk-list');
    const scrollers = [...document.querySelectorAll('body *')].filter((n) => {
      if (p.contains(n)) return false;
      const cs = getComputedStyle(n);
      return /(auto|scroll)/.test(cs.overflowY) && n.scrollHeight > n.clientHeight + 1 && n.clientHeight > 0;
    }).length;
    return {inside: r.left >= 0 && r.right <= vw + 1 && r.top >= 0 && r.bottom <= window.innerHeight + 1,
            pageWide: document.documentElement.scrollWidth > vw + 1,
            listMax: list ? parseFloat(getComputedStyle(list).maxHeight) : 0,
            outsideModal: !p.closest('#modal'), scrollers};
  });
  const scrollers = (page) => page.evaluate(() => [...document.querySelectorAll('body *')].filter((n) => {
    const cs = getComputedStyle(n);
    return /(auto|scroll)/.test(cs.overflowY) && n.scrollHeight > n.clientHeight + 1 && n.clientHeight > 0;
  }).length);
  try {
    if (mode === 'admin') {
      // ---- the settings: the administrators' groups (Accounts) ------------------------------
      const a = await admin('tester', 'en', 1400, '#settings/people');
      await a.waitForSelector('#set-admin_group_full', {timeout: 30000});
      out.settingButtons = await a.evaluate(() => ['admin_group_full', 'admin_group_cert', 'admin_group_readonly', 'admin_group_portal']
        .filter((k) => document.getElementById('set-' + k)).map((k) => {
          const b = document.getElementById('set-' + k + '-pick');
          return [k, !!b && b.parentNode === document.getElementById('set-' + k).parentNode];
        }));
      // typed by hand, as before
      await a.fill('#set-admin_group_full', 'CN=Typed By Hand,OU=X,DC=corpnet,DC=loc');
      out.typedKept = await a.inputValue('#set-admin_group_full');
      const before = await scrollers(a);
      await a.click('#set-admin_group_full-pick');
      await pop(a);
      await search(a, 'PKI');
      out.groupItems = await items(a);
      out.fit1400 = await fits(a);
      out.scrollersBefore = before;
      await shot(a, 'settings-groups');
      await pickItem(a, 'CN=PKI-Web,OU=Groups,DC=corpnet,DC=loc');
      await pickItem(a, 'CN=PKI-Mail,OU=Groups,DC=corpnet,DC=loc');
      out.multiCount = await a.$eval('#dpk-pop .dpk-count', (x) => x.textContent);
      out.afterTwo = await a.inputValue('#set-admin_group_full');
      await pickItem(a, 'CN=PKI-Mail,OU=Groups,DC=corpnet,DC=loc');
      out.afterToggle = await a.inputValue('#set-admin_group_full');
      out.dirtyMarked = await a.evaluate(() => !!document.querySelector('.set-item[data-key="admin_group_full"].dirty, .set-item[data-key="admin_group_full"].changed')
        || (typeof DIRTY === 'object' && DIRTY && Object.keys(DIRTY).indexOf('admin_group_full') >= 0));
      await a.keyboard.press('Escape');
      await closed(a);
      out.escapeKeepsPage = !(await a.$('#modal:not([hidden])'));
      // a list separated by "; " keeps its separator
      await a.fill('#set-admin_group_cert', 'CN=One,DC=corpnet,DC=loc; CN=Two,DC=corpnet,DC=loc');
      await a.click('#set-admin_group_cert-pick');
      await pop(a);
      await search(a, 'PKI-V');
      await pickItem(a, 'CN=PKI-VPN,OU=Groups,DC=corpnet,DC=loc');
      out.semiList = await a.inputValue('#set-admin_group_cert');
      await a.click('#dpk-pop .dpk-done');
      await closed(a);
      // the directory's "try a sign-in": a person's login
      await a.click('#ag-try');
      await a.waitForSelector('#ag-try-pick', {timeout: 10000});
      await a.click('#ag-try-pick');
      await pop(a);
      await search(a, 'novak');
      out.userItems = await items(a);
      await pickItem(a, 'jnovak@corpnet.loc');
      await closed(a);
      out.tryName = await a.evaluate(() => { const b = document.getElementById('ag-try-pick'); return b.parentNode.querySelector('input').value; });
      await a.evaluate(() => closeModal(true));
      await a.waitForTimeout(300);
      // a disabled account says so
      await a.evaluate(() => lookupDir('corp'));
      await a.waitForSelector('#dir-look-pick', {timeout: 10000});
      await a.click('#dir-look-pick');
      await pop(a);
      await search(a, 'gone');
      out.goneItems = await items(a);
      await pickItem(a, 'gone@corpnet.cz');
      out.lookName = await a.evaluate(() => document.getElementById('dir-look-pick').parentNode.querySelector('input').value);
      await a.evaluate(() => closeModal(true));
      await a.waitForTimeout(300);
      // the certificate look-up for a person
      await a.evaluate(() => certLookup('admin'));
      await a.waitForSelector('#clk-pick', {timeout: 10000});
      out.certLookupButton = true;
      await a.evaluate(() => closeModal(true));
      await a.waitForTimeout(300);
      // ---- the portal's groups (Settings → the enrolment pages) -----------------------------
      await a.goto(base + '/admin/index.php#settings/portal');
      await a.waitForSelector('#set-portal_groups', {timeout: 30000});
      out.portalGroupsButton = !!(await a.$('#set-portal_groups-pick'));
      out.portalGroupsOld = !!(await a.$('#portal-groups-find'));
      await a.click('#set-portal_groups-pick');
      await pop(a);
      await search(a, 'CERT_SUP');
      await pickItem(a, 'CN=CERT_SUPPLIER_X,OU=Groups,DC=corpnet,DC=loc');
      out.portalGroups = await a.inputValue('#set-portal_groups');
      await a.click('#dpk-pop .dpk-done');
      await closed(a);
      await a.context().close();

      // ---- Owners and teams: the access check, Teams from directory groups -----------------
      for (const width of [1400, 768, 390]) {
        const t = await admin('tester', 'en', width, '#settings/teams');
        await t.waitForSelector('#tmx .tmx-vbtn', {timeout: 30000});
        if (width === 1400) {
          await t.click('.tmx-vbtn[data-view="access"]');
          await t.waitForSelector('#tmx-ac-pick', {timeout: 10000});
          await t.click('#tmx-ac-pick');
          await pop(t);
          await search(t, 'nested');
          await pickItem(t, 'nested@corpnet.cz');
          await closed(t);
          out.accessWho = await t.inputValue('#tmx-ac-q');
          await t.waitForSelector('.tmx-ac-card', {timeout: 20000});
          out.accessTeams = await t.$$eval('.tmx-ac-card', (r) => r.map((x) => x.dataset.team));
          await t.click('.tmx-vbtn[data-view="tree"]').catch(() => {});
          await t.waitForTimeout(300);
        }
        await t.click('#tmx-fromgroups');
        await t.waitForSelector('#tmx-fg-pick', {timeout: 10000});
        const key = 'w' + width;
        out[key] = {};
        out[key].besideFilter = await t.evaluate(() => document.getElementById('tmx-fg-pick').parentNode === document.getElementById('tmx-fg-filter').parentNode);
        const mb0 = await t.evaluate(() => { const b = document.getElementById('modal-body'); return [b.scrollHeight, b.clientHeight]; });
        const sc0 = await scrollers(t);
        await t.click('#tmx-fg-pick');
        await pop(t);
        await search(t, 'PKI');
        out[key].fit = await fits(t);
        out[key].modalSame = await t.evaluate((mb0) => { const b = document.getElementById('modal-body'); return b.scrollHeight === mb0[0] && b.clientHeight === mb0[1]; }, mb0);
        out[key].scrollersSame = (await scrollers(t)) <= sc0 + 1;    // + the popover's own small list at most
        await shot(t, 'from-groups-' + width);
        if (width === 1400) {
          // picked groups beside the filter: the filter emptied, only those two
          await pickItem(t, 'CN=PKI-Web,OU=Groups,DC=corpnet,DC=loc');
          await pickItem(t, 'CN=PKI-Factory,OU=Groups,DC=corpnet,DC=loc');
          await t.click('#dpk-pop .dpk-done');
          await closed(t);
          out.fgChips = await t.$$eval('#tmx-fg-picked .tmx-fg-chip', (r) => r.map((x) => x.dataset.dn));
          out.fgFilterKept = await t.inputValue('#tmx-fg-filter');
          await t.fill('#tmx-fg-filter', '');
          await t.locator('#modal-foot button', {hasText: 'Preview'}).click();
          await t.waitForSelector('tr.tmx-fg-row', {timeout: 20000});
          out.fgPickedOnly = await t.$$eval('tr.tmx-fg-row', (r) => r.map((x) => x.dataset.cn).sort());
          // with a typed filter beside them
          await t.fill('#tmx-fg-filter', 'CN=PKI-V*');
          await t.locator('#modal-foot button', {hasText: 'Preview'}).click();
          await t.waitForFunction(() => document.querySelectorAll('tr.tmx-fg-row').length === 3, null, {timeout: 20000});
          out.fgBoth = await t.$$eval('tr.tmx-fg-row', (r) => r.map((x) => x.dataset.cn).sort());
          // the chips taken away: the filter alone, as before
          while (await t.$('#tmx-fg-picked .tmx-fg-chip .btn')) await t.click('#tmx-fg-picked .tmx-fg-chip .btn');
          await t.fill('#tmx-fg-filter', 'CN=PKI-*');
          await t.locator('#modal-foot button', {hasText: 'Preview'}).click();
          await t.waitForFunction(() => document.querySelectorAll('tr.tmx-fg-row').length === 4, null, {timeout: 20000});
          out.fgTyped = await t.$$eval('tr.tmx-fg-row', (r) => r.map((x) => x.dataset.cn).sort());
        } else {
          await t.keyboard.press('Escape');
          await closed(t);
        }
        out[key].modalStillOpen = !!(await t.$('#modal:not([hidden])'));
        await t.context().close();
      }

      // ---- Czech --------------------------------------------------------------------------
      const c = await admin('tester', 'cs', 1400, '#settings/people');
      await c.waitForSelector('#set-admin_group_full-pick', {timeout: 30000});
      await c.click('#set-admin_group_full-pick');
      await pop(c);
      await c.waitForTimeout(500);
      out.csTitle = await c.$eval('#dpk-pop .dpk-title', (x) => x.textContent);
      out.csSaid = await said(c);
      out.csPlaceholder = await c.$eval('#dpk-q', (x) => x.placeholder);
      await search(c, 'PKI');
      await pickItem(c, 'CN=PKI-Web,OU=Groups,DC=corpnet,DC=loc');
      out.csCount = await c.$eval('#dpk-pop .dpk-count', (x) => x.textContent);
      out.csHint = await c.$eval('#dpk-pop .dpk-hint', (x) => x.textContent);
      await shot(c, 'czech');
      await c.context().close();

      // ---- read only: no button anywhere --------------------------------------------------
      const r = await admin('viewer', 'en', 1400, '#settings/people');
      await r.waitForTimeout(1500);
      out.roPeople = await r.$$eval('.dpk-btn', (n) => n.length);
      await r.goto(base + '/admin/index.php#settings/teams');
      await r.waitForSelector('#tmx .tmx-vbtn', {timeout: 30000});
      await r.waitForTimeout(500);
      out.roTeams = await r.$$eval('.dpk-btn', (n) => n.length);
      await r.context().close();
    } else if (mode === 'portal') {
      for (const width of [1400, 390]) {
        const ctx = await browser.newContext({viewport: {width, height: width < 500 ? 844 : 900}});
        await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
        const p = await ctx.newPage();
        watch(p);
        await p.goto(base + '/');
        await p.fill('#in-name', 'tmgr');
        await p.fill('#in-pass', pass);
        await p.click('#in-go');
        await p.waitForSelector('#pw-nav', {timeout: 30000});
        await p.evaluate(() => { location.hash = '#members/Web'; });
        await p.waitForSelector('#pw-add-member', {timeout: 20000});
        await p.click('#pw-add-member');
        await p.waitForSelector('#pw-mem-pick', {timeout: 10000});
        const key = 'p' + width;
        out[key] = {beside: await p.evaluate(() => document.getElementById('pw-mem-pick').parentNode === document.getElementById('pw-mem-who').parentNode)};
        // typed by hand still works
        await p.fill('#pw-mem-who', 'local:someone');
        out[key].typed = await p.inputValue('#pw-mem-who');
        await p.click('#pw-mem-pick');
        await pop(p);
        await search(p, 'novak');
        out[key].fit = await fits(p);
        out[key].userItems = await items(p);
        await pickItem(p, 'jnovak@corpnet.loc');
        await closed(p);
        out[key].pickedUser = await p.inputValue('#pw-mem-who');
        await p.click('#pw-mem-pick');
        await pop(p);
        await p.click('#dpk-pop .dpk-segb[data-kind="group"]');
        await search(p, 'CERT');
        out[key].groupItems = await items(p);
        await pickItem(p, 'group:CERT_USERS');
        await closed(p);
        out[key].pickedGroup = await p.inputValue('#pw-mem-who');
        await shot(p, 'portal-' + width);
        await ctx.close();
      }
    } else if (mode === 'nodir') {
      const a = await admin('tester', 'en', 1400, '#settings/people');
      await a.waitForSelector('#set-admin_group_full-pick', {timeout: 30000});
      await a.fill('#set-admin_group_full', 'CN=PKI-*');
      await a.click('#set-admin_group_full-pick');
      await pop(a);
      await a.waitForFunction(() => /directory/.test((document.querySelector('#dpk-pop .dpk-said') || {}).textContent || ''), null, {timeout: 15000});
      out.noDirSaid = await said(a);
      out.noDirBad = await a.$eval('#dpk-pop .dpk-said', (x) => x.classList.contains('bad'));
      await shot(a, 'nodir');
      await a.keyboard.press('Escape');
      await closed(a);
      await a.type('#set-admin_group_full', ',OU=Typed');
      out.noDirTyped = await a.inputValue('#set-admin_group_full');
      await a.context().close();
      const c = await admin('tester', 'cs', 1400, '#settings/teams');
      await c.waitForSelector('#tmx .tmx-vbtn', {timeout: 30000});
      await c.click('.tmx-vbtn[data-view="access"]');
      await c.waitForSelector('#tmx-ac-pick', {timeout: 10000});
      await c.click('#tmx-ac-pick');
      await pop(c);
      await c.waitForFunction(() => /adresář/.test((document.querySelector('#dpk-pop .dpk-said') || {}).textContent || ''), null, {timeout: 15000});
      out.noDirSaidCs = await said(c);
      await c.context().close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  console.log(JSON.stringify(out));
  await browser.close();
})();
