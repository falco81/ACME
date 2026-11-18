// The pages' half of test/test_teams_review_ui.py (1.0.125 review C2: the look of the teams'
// pages) in Chromium against a real daemon.
//
//   node test/teams_review_ui_page.js BASE PASSWORD admin|portal [SHOTS_DIR]
//
// admin: Settings → Owners and teams, the team Web's Overview in Czech at 1400, 1024 and 390 px -
//   no tile label broken inside a word (CERTIFIKÁTY, not CERTIFIKA / TY), none cut, and the seven
//   tiles in one row, four and three, or two a row with the last across - never one left alone.
// portal: the team workspace in Czech as the team's owner - the built-in roles of the members in
//   Czech (Čtenář, not Viewer), the limit above said in Czech ("90 dní", not "90 days"), the
//   tiles' lines whole (not "ke schválení nebo za…") and six tiles in rows of six, three or two.
// Prints one line of JSON: what was seen ({errors: [...]} always there).
const { chromium } = require('playwright');

/* words of an element split across two lines, and whether its text is cut */
const LOOK = (sel) => {
  const out = {split: [], cut: []};
  document.querySelectorAll(sel).forEach((e) => {
    const walk = document.createTreeWalker(e, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walk.nextNode())) {
      const re = /[\p{L}\d]{2,}/gu;
      let m;
      while ((m = re.exec(n.nodeValue))) {
        const r = document.createRange();
        r.setStart(n, m.index);
        r.setEnd(n, m.index + m[0].length);
        const rs = [...r.getClientRects()].filter((x) => x.width > 0);
        if (rs.length > 1 && Math.abs(rs[0].top - rs[rs.length - 1].top) > 3) out.split.push(m[0]);
      }
    }
    if (e.scrollWidth > e.clientWidth + 1 || e.scrollHeight > e.clientHeight + 1) out.cut.push(e.textContent.trim());
  });
  return out;
};
/* the tiles a row holds, row by row */
const ROWS = (sel) => {
  const tops = {};
  document.querySelectorAll(sel).forEach((t) => { const y = Math.round(t.getBoundingClientRect().top); tops[y] = (tops[y] || 0) + 1; });
  return Object.keys(tops).map(Number).sort((a, b) => a - b).map((y) => tops[y]);
};

(async () => {
  const [base, pass, mode, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  const open = async (width) => {
    const ctx = await browser.newContext({viewport: {width, height: width < 500 ? 844 : 900}});
    await ctx.addCookies([{name: 'acme_lang', value: 'cs', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', (e) => out.errors.push(String(e.message || e)));
    page.on('console', (m) => { if (m.type() === 'error') out.errors.push('console: ' + m.text()); });
    return page;
  };
  const shot = async (page, name) => { if (shots) await page.screenshot({path: shots + '/review_' + name + '.png'}); };
  try {
    if (mode === 'admin') {
      out.tiles = {};
      for (const width of [1400, 1024, 390]) {
        const p = await open(width);
        await p.goto(base + '/admin/index.php');
        await p.fill('#in-name', 'tester');
        await p.type('#in-pass', pass);
        await Promise.all([p.waitForNavigation(), p.click('#in-go')]);
        await p.goto(base + '/admin/index.php#settings/teams');
        await p.waitForSelector('#tmx .tmx-vbtn', {timeout: 30000});
        await p.evaluate(() => document.getElementById('tmx-expand').click());
        await p.waitForTimeout(200);
        await p.evaluate(() => [...document.querySelectorAll('.tmx-row')].find((x) => x.dataset.name === 'Web').click());
        await p.waitForSelector('.tmx-team[data-team="Web"] .tmx-tile', {timeout: 15000});
        await p.waitForFunction(() => document.querySelector('.tmx-tile[data-tile="failing"] .tmx-tile-v').textContent !== '–', null, {timeout: 15000}).catch(() => {});
        await p.waitForTimeout(400);
        const seen = await p.evaluate(LOOK, '.tmx-tile-h');
        seen.rows = await p.evaluate(ROWS, '.tmx-tile');
        seen.labels = await p.$$eval('.tmx-tile-h', (r) => r.map((x) => x.textContent));
        seen.value = await p.$eval('.tmx-tile[data-tile="certs"] .tmx-tile-v', (x) => x.textContent);
        seen.lastWide = await p.evaluate(() => { const t = [...document.querySelectorAll('.tmx-tile')]; const l = t[t.length - 1]; return l.getBoundingClientRect().width > t[0].getBoundingClientRect().width * 1.5; });
        out.tiles[width] = seen;
        await shot(p, 'admin_' + width);
        await p.context().close();
      }
    }
    if (mode === 'portal') {
      out.tiles = {};
      for (const width of [1400, 1024, 390]) {
        const p = await open(width);
        await p.goto(base + '/');
        await p.fill('#in-name', 'towner');
        await p.fill('#in-pass', pass);
        await p.click('#in-go');
        await p.waitForSelector('.pw-tile', {timeout: 30000});
        await p.waitForTimeout(1500);
        const seen = await p.evaluate(LOOK, '.pw-tile-s, .pw-attn-w span');
        seen.rows = await p.evaluate(ROWS, '.pw-tile');
        out.tiles[width] = seen;
        await shot(p, 'portal_' + width);
        if (width === 1400) {
          await p.evaluate(() => { location.hash = '#members/Web'; });
          await p.waitForSelector('.pw-mem .pw-mem-r .pw-chip', {timeout: 20000});
          await p.waitForTimeout(500);
          out.roles = await p.$$eval('.pw-mem .pw-mem-r .pw-chip', (r) => r.map((x) => x.textContent.trim()));
          await p.evaluate(() => { location.hash = '#teams/Web'; });
          await p.locator('.pw-node', {hasText: 'WebDev'}).first().waitFor({timeout: 20000});
          await p.waitForTimeout(500);
          await p.locator('.pw-node', {hasText: 'WebDev'}).first().locator('button', {hasText: /Limits|Limity/}).click();
          await p.waitForSelector('#modal .pw-led', {timeout: 10000});
          await p.waitForTimeout(300);
          out.above = await p.$$eval('#modal .pw-above', (r) => r.map((x) => x.textContent.trim()));
        }
        await p.context().close();
      }
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
