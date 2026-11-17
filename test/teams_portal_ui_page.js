// The pages' half of test/test_teams_portal_ui.py: the portal's team workspace in Chromium.
//
//   node test/teams_portal_ui_page.js BASE FLOW PASSWORD LANG WIDTH [SHOTS_DIR]
//
// FLOW: viewer | requester | renewer | devman | approver | boss | manager | solo | tour.
// Prints one line of JSON: what was seen ({errors: [...]} - the page's errors and console
// errors - always there).
const { chromium } = require('playwright');
const path = require('path');

const USERS = {viewer: 'tviewer', requester: 'treq', renewer: 'trenew', devman: 'tdev',
               approver: 'tlead', boss: 'tboss', manager: 'tmgr', solo: 'tsolo', tour: 'towner'};

(async () => {
  const [base, flow, pass, lang, width, shots] = process.argv.slice(2);
  const w = Number(width) || 1400;
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}});
  await ctx.addCookies([{name: 'acme_lang', value: lang || 'en', url: base}]);
  const page = await ctx.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  page.on('console', m => { if (m.type() === 'error') out.errors.push('console: ' + m.text()); });
  const pause = ms => page.waitForTimeout(ms);
  const shot = async name => {
    if (!shots) return;
    await page.evaluate(() => {
      for (const n of [document.documentElement, document.body, document.getElementById('portal'), document.querySelector('.wrap')]) {
        if (!n) continue;
        n.style.setProperty('height', 'auto', 'important');
        n.style.setProperty('overflow', 'visible', 'important');
      }
      document.body.style.setProperty('display', 'block', 'important');
    });
    await pause(150);
    await page.screenshot({path: path.join(shots, name + '.png'), fullPage: true});
    await page.evaluate(() => {
      for (const n of [document.documentElement, document.body, document.getElementById('portal'), document.querySelector('.wrap')]) {
        if (n) { n.style.removeProperty('height'); n.style.removeProperty('overflow'); }
      }
      document.body.style.removeProperty('display');
    });
  };
  const wide = () => page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  const toastText = async () => (await page.textContent('#toast').catch(() => '')) || '';
  const view = async (v, team) => {
    await page.evaluate(([v, t]) => { location.hash = '#' + v + '/' + encodeURIComponent(t); }, [v, team || 'Web']);
    await pause(250);
    await page.waitForFunction(() => !document.querySelector('#pw-main .pw-skels, #pw-main .cp-skel'), null, {timeout: 20000}).catch(() => {});
    await pause(500);
  };
  const modalButtons = () => page.$$eval('#modal-foot button', bs => bs.filter(b => !b.hidden).map(b => b.textContent.trim()));
  const clickModal = async words => {
    const b = page.locator('#modal-foot button', {hasText: words === 'Close' ? /^(Close|Zavřít)$/ : words}).first();
    await b.click();
  };
  /* text a Czech page still shows in English: visible text nodes outside data and names */
  const english = () => page.evaluate(() => {
    const EN = /(?<!\p{L})(the|of|and|is|for|with|your|you|it|not|all|team|teams|certificates?|devices?|members?|requests?|waiting|nothing|add|ask|limits|deployments?|activity|home|search|valid|failing|expiring|workspace|title)(?!\p{L})/iu;
    const got = [];
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walk.nextNode())) {
      const t = n.nodeValue.trim();
      if (!t || !EN.test(t)) continue;
      const p = n.parentElement;
      if (!p || p.closest('[data-no-i18n], .pw-act-t, .mono, code, pre, script, style, #toast, .langpick, [hidden]')) continue;
      const r = p.getBoundingClientRect();
      if (!r.width || !r.height) continue;
      if (getComputedStyle(p).visibility === 'hidden') continue;
      got.push(t.slice(0, 120));
    }
    return Array.from(new Set(got)).slice(0, 40);
  });
  try {
    await page.goto(base + '/');
    await page.fill('#in-name', USERS[flow]);
    await page.fill('#in-pass', pass);
    await page.click('#in-go');
    if (flow === 'solo') {
      await page.waitForSelector('#cp-list table', {timeout: 30000});
      await pause(600);
      out.workspace = !!(await page.$('#pw'));
      out.oldTable = !!(await page.$('#cp-list table.cp-table'));
      out.cols = await page.$$eval('#cp-list thead th', t => t.length);
      out.wide = await wide();
      await shot((lang || 'en') + '_' + w + '_solo');
      await page.locator('#cp-list tr', {hasText: 'solo-one.example.test'}).first().click();
      await page.waitForSelector('#modal .ct-head', {timeout: 10000});
      out.dialog = true;
      await shot((lang || 'en') + '_' + w + '_solo_dialog');
      throw null;
    }
    await page.waitForSelector('#pw-nav', {timeout: 30000});
    await pause(800);
    out.nav = await page.$$eval('#pw-nav .pw-navi', bs => {
      const o = {};
      ['home', 'certs', 'inbox', 'devices', 'deploys', 'members', 'teams', 'activity'].forEach(v => {
        o[v] = bs.some(b => b.getAttribute('data-view') === v);
      });
      return o;
    });
    if (flow === 'viewer') {
      await view('certs');
      await page.waitForSelector('#cp-list table', {timeout: 20000});
      out.askShown = !!(await page.$('#pw-ask-c'));
      out.total = Number(await page.textContent('#cp-said b'));
      out.rowsShown = await page.$$eval('#cp-list tbody tr', t => t.length);
      const acts = [];
      if (await page.$('.cp-renew')) acts.push('row renew');
      await page.locator('#cp-list tr', {hasText: 'api.example.test'}).first().click();
      await page.waitForSelector('#modal .ct-head', {timeout: 10000});
      await pause(400);
      (await modalButtons()).forEach(b => { if (!/^(Close|Download)$/.test(b)) acts.push(b); });
      if (await page.$('#modal .sw input:not([disabled])')) acts.push('auto switch');
      await clickModal('Close');
      await view('devices');
      if (await page.$('#pw-add-device, #pw-enrol')) acts.push('add device');
      await view('home');
      if (await page.$('#pw-ask')) acts.push('home ask');
      out.actions = acts;
    }
    if (flow === 'requester') {
      await page.click('#pw-ask');
      await page.waitForSelector('#modal textarea.cp-names', {timeout: 10000});
      out.team = await page.$eval('#cp-team', s => s.value).catch(() => '');
      await page.fill('#modal textarea.cp-names', 'b2-asked.example.test');
      await shot('requester_ask');
      await clickModal('Ask');
      await page.waitForFunction(() => /asked for/i.test(document.getElementById('toast').textContent), null, {timeout: 20000});
      out.said = await toastText();
      out.asked = true;
      await view('inbox');
      out.state = await page.locator('.pw-mine').innerText();
      out.mine = /b2-asked/.test(out.state);
    }
    if (flow === 'renewer') {
      await view('certs');
      await page.fill('.pw-search input', 'shop');
      await page.waitForFunction(() => document.querySelectorAll('#cp-list tbody tr').length === 1, null, {timeout: 10000});
      await page.click('#cp-list .cp-renew');
      await page.waitForSelector('#modal-foot button.primary', {timeout: 10000});
      await clickModal('Renew now');
      await page.waitForFunction(() => /renewed/i.test(document.getElementById('toast').textContent), null, {timeout: 20000});
      out.renewed = true;
    }
    if (flow === 'devman') {
      await view('devices');
      await page.click('#pw-add-device');
      await page.waitForSelector('.pw-kind', {timeout: 30000});
      await shot('devman_kinds');
      await page.locator('.pw-kind', {hasText: 'Fake target'}).first().click();
      await page.waitForSelector('#pw-dev-name', {timeout: 10000});
      await page.fill('#pw-dev-name', 'b2-new');
      await page.fill('[data-fkey=dir] input', process.env.TP_OUT || '/tmp');
      await page.fill('[data-fkey=password] input', 's3cret');
      await shot('devman_form');
      await clickModal('Add it');
      await page.waitForFunction(() => /b2-new/.test(document.getElementById('modal-title').textContent)
        && document.querySelector('#modal-foot button.primary'), null, {timeout: 20000});
      out.added = true;
      await pause(500);
      await clickModal('Test it');
      await page.waitForSelector('#pw-testbox.good, #pw-testbox.bad', {timeout: 60000});
      out.tested = !!(await page.$('#pw-testbox.good'));
      out.testSaid = await page.textContent('#pw-testbox');
      await shot('devman_test');
      await clickModal('Close');
      /* a deployment of a team's certificate to the new device, run */
      await view('deploys');
      await page.click('#pw-add-deploy');
      await page.waitForSelector('#pw-dep-cert', {timeout: 30000});
      await page.fill('#pw-dep-cert', 'shop');
      await page.locator('.pw-pick-o', {hasText: 'shop'}).first().click();
      await page.selectOption('#pw-dep-dev', 'b2-new');
      await page.waitForSelector('#modal [data-fkey=file] input', {timeout: 10000});
      await page.fill('#modal [data-fkey=file] input', 'b2-shop.pem');
      await shot('devman_deploy');
      await clickModal('Add it');
      await page.locator('.pw-dep', {hasText: 'b2-new'}).first().waitFor({timeout: 15000});
      out.deployAdded = true;
      await page.locator('.pw-dep', {hasText: 'b2-new'}).first().locator('.pw-run').click();
      await page.waitForFunction(() => /Deployed|It failed/.test((document.getElementById('modal-body') || {}).textContent || ''), null, {timeout: 60000});
      out.deployed = /Deployed/.test(await page.textContent('#modal-body'));
      await shot('devman_deployed');
    }
    if (flow === 'approver' || flow === 'boss') {
      await view('inbox', flow === 'boss' ? 'Prague' : 'Web');
      const card = page.locator('.pw-inbox .pw-req', {hasText: 'b2-asked.example.test'}).first();
      await card.waitFor({timeout: 15000});
      await shot(flow + '_inbox');
      await card.locator('.pw-approve').click();
      await page.waitForFunction(() => window.ACME_PORTAL_WS.state.lastApproval, null, {timeout: 20000});
      const got = await page.evaluate(() => window.ACME_PORTAL_WS.state.lastApproval);
      out.approved = true;
      out.needed = got.needed || [];
      out.message = got.message || '';
    }
    if (flow === 'manager') {
      await view('members');
      await page.click('#pw-add-member');
      await page.waitForSelector('#pw-mem-who', {timeout: 10000});
      await page.fill('#pw-mem-who', 'local:b2guest');
      await page.locator('.pw-role', {hasText: 'Viewer'}).first().locator('input').check();
      await shot('manager_member');
      await clickModal('Add them');
      await page.locator('.pw-mem', {hasText: 'b2guest'}).first().waitFor({timeout: 15000});
      out.memberAdded = true;
      await view('teams');
      await page.click('#pw-add-team');
      await page.waitForSelector('#pw-team-name', {timeout: 10000});
      await page.fill('#pw-team-name', 'WebOps');
      const row = page.locator('.pw-led-r', {hasText: 'Longest validity'}).first();
      await row.locator('.sw').click();
      await page.fill('#pw-led-max_days', '30');
      await shot('manager_team');
      await clickModal('Make the team');
      await page.locator('.pw-node', {hasText: 'WebOps'}).first().waitFor({timeout: 15000});
      out.teamMade = true;
    }
    if (flow === 'tour') {
      const tag = (lang || 'en') + '_' + w;
      out.wide = 0;
      out.english = [];
      const look = async name => {
        out.wide = Math.max(out.wide, await wide());
        if (lang === 'cs') (await english()).forEach(t => out.english.push(name + ': ' + t));
        await shot(tag + '_' + name);
      };
      for (const v of ['home', 'certs', 'inbox', 'devices', 'deploys', 'members', 'teams', 'activity']) {
        await view(v);
        await look(v);
      }
      await view('home', '*');
      await look('home_all');
      /* the switcher open */
      await page.click('#pw-switch');
      await pause(300);
      await look('switcher');
      await page.keyboard.press('Escape');
      /* a few dialogs */
      await view('certs');
      await page.locator('#cp-list tr', {hasText: 'api.example.test'}).first().click();
      await page.waitForSelector('#modal .ct-head', {timeout: 10000});
      await pause(800);
      await look('cert_dialog');
      await clickModal('Close');
      await view('devices');
      await page.locator('.pw-dev', {hasText: 'web-lb1'}).first().click();
      await page.waitForSelector('#modal .pw-dh', {timeout: 10000});
      await pause(400);
      await look('device_dialog');
      await clickModal('Close');
      await page.click('#pw-enrol');
      await page.waitForSelector('#modal .pw-enrol-lead', {timeout: 10000});
      await look('enrol');
      await clickModal('Close');
      await view('teams');
      const lim = page.locator('.pw-node', {hasText: 'WebDev'}).first().locator('button', {hasText: /Limits|Limity/});
      if (await lim.count()) {
        await lim.click();
        await page.waitForSelector('#modal .pw-led', {timeout: 10000});
        await look('limits');
        await clickModal('Close');
      }
      await view('members');
      await page.click('#pw-add-member');
      await page.waitForSelector('#pw-mem-who', {timeout: 10000});
      await look('member_dialog');
      await clickModal('Close');
      await view('inbox');
      const tl = page.locator('.pw-req button', {hasText: /Timeline|Průběh/}).first();
      if (await tl.count()) {
        await tl.click();
        await page.waitForSelector('#modal ol.pw-tl', {timeout: 10000});
        await look('timeline');
        await clickModal('Close');
      }
    }
  } catch (e) {
    if (e !== null) out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
