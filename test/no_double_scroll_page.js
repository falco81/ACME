// The pages' half of test/test_no_double_scroll.py: nowhere a scrolling box inside another
// scrolling area, both with a vertical scrollbar (1.0.128).
//
//   node test/no_double_scroll_page.js BASE PASSWORD WHAT WIDTHS ALLOW_JSON [USER]
//
// WHAT: admin (every top tab, every Settings pane, the four views of Owners and teams, the
// team's own tabs, the main add/edit dialogs) | portal (every view of the team workspace and
// its dialogs, signed in as USER) | solo (the portal of a person in no team).
// WIDTHS: "2000x1100,1400,768,390" - a width, or WIDTHxHEIGHT.
// ALLOW_JSON: a JSON list of CSS selectors; a scroller matching one of them (or inside one)
// is reported under "allowed", not "found".
//
// The rule: a box shows a vertical scrollbar when its overflow-y is auto or scroll and its
// content is taller than it (scrollHeight > clientHeight + 1) and it is drawn. Such a box is
// nested when an ancestor of it (not html/body) also shows one, or when it lives in the page
// (no fixed ancestor - a dialog, a drawer, a popover) and the page itself scrolls. A dialog's
// own single body is the dialog's page.
//
// Prints one line of JSON: {errors, steps, found: [...], allowed: [...]}.
const { chromium } = require('playwright');

/* runs in the page */
function scan(arg) {
  const allow = arg.allow || [];
  const root = arg.root ? document.querySelector(arg.root) : document.body;
  if (!root) return [];
  const drawn = el => {
    if (!el.getClientRects().length) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    return getComputedStyle(el).visibility !== 'hidden';
  };
  const scrollsY = el => {
    const cs = getComputedStyle(el);
    return /auto|scroll/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 1 && drawn(el);
  };
  const name = el => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += '#' + el.id;
    const c = (typeof el.className === 'string' ? el.className : '').trim().split(/\s+/).filter(Boolean).slice(0, 3);
    if (c.length) s += '.' + c.join('.');
    return s;
  };
  const path = el => {
    const out = [];
    for (let n = el; n && n !== document.body && out.length < 4; n = n.parentElement) out.unshift(name(n));
    return out.join(' > ');
  };
  const se = document.scrollingElement;
  const hid = n => getComputedStyle(n).overflowY === 'hidden' || getComputedStyle(n).overflowY === 'clip';
  const pageScrolls = se.scrollHeight > se.clientHeight + 1 && !hid(document.documentElement) && !hid(document.body);
  const got = [];
  const all = [root].concat(Array.from(root.querySelectorAll('*')));
  for (const el of all) {
    if (el === document.body || el === document.documentElement) continue;
    if (!scrollsY(el)) continue;
    let fixed = false;
    const outer = [];
    for (let n = el; n && n !== document.body; n = n.parentElement) {
      if (n !== el && scrollsY(n)) outer.push(n);
      if (getComputedStyle(n).position === 'fixed') fixed = true;
    }
    const inPage = pageScrolls && !fixed;
    if (!outer.length && !inPage) continue;
    const ok = allow.find(sel => { try { return el.matches(sel) || !!el.closest(sel); } catch (e) { return false; } });
    got.push({el: path(el), h: el.clientHeight, sh: el.scrollHeight,
              outer: outer.length ? outer.map(name).join(' < ') : 'the page',
              allowed: ok || null});
  }
  return got;
}

(async () => {
  const [base, pass, what, widths, allowJson, user] = process.argv.slice(2);
  const allow = JSON.parse(allowJson || '[]');
  const out = {errors: [], steps: [], found: [], allowed: []};
  const browser = await chromium.launch();
  const sizes = (widths || '1400').split(',').map(w => {
    const m = /^(\d+)(?:x(\d+))?$/.exec(w.trim());
    const ww = Number(m[1]);
    return {width: ww, height: m[2] ? Number(m[2]) : (ww < 500 ? 844 : 900)};
  });

  const tour = async size => {
    const tag = size.width + 'x' + size.height;
    const ctx = await browser.newContext({viewport: size});
    await ctx.addCookies([{name: 'acme_lang', value: 'en', url: base}]);
    const page = await ctx.newPage();
    page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
    const pause = ms => page.waitForTimeout(ms);
    const look = async (where, root) => {
      const got = await page.evaluate(scan, {allow, root: root || null});
      out.steps.push(tag + ' ' + where);
      for (const g of got) {
        g.where = where;
        g.size = tag;
        (g.allowed ? out.allowed : out.found).push(g);
      }
    };
    const modalOpen = () => page.evaluate(() => { const m = document.getElementById('modal'); return !!m && !m.hidden; });
    const shut = async () => {
      for (let i = 0; i < 4 && await modalOpen(); i++) {
        await page.evaluate(() => { const x = document.getElementById('modal-x'); if (x) x.click(); });
        await pause(250);
        // a "leave without saving?" question: yes
        await page.evaluate(() => {
          const q = Array.from(document.querySelectorAll('.ask-box button, .confirm button, #ask button'))
            .find(b => /leave|discard|close|yes|zahodit|ano/i.test(b.textContent));
          if (q) q.click();
        });
        await pause(150);
      }
      if (await modalOpen()) await page.keyboard.press('Escape');
    };
    /* a dialog opened by clicking sel (a selector, or a function in the page that clicks) */
    const dialog = async (where, sel) => {
      try {
        const clicked = await page.evaluate(sel => {
          const b = Array.from(document.querySelectorAll(sel)).find(x => x.getClientRects().length && !x.disabled);
          if (!b) return false;
          b.click();
          return true;
        }, sel);
        if (!clicked) { out.steps.push(tag + ' ' + where + ' (no ' + sel + ')'); return; }
        await page.waitForFunction(() => { const m = document.getElementById('modal'); return m && !m.hidden; }, null, {timeout: 8000});
        await pause(1300);
        await look(where, '#modal');
      } catch (e) {
        out.steps.push(tag + ' ' + where + ' (' + String(e.message || e).split('\n')[0] + ')');
      }
      await shut();
    };
    try {
      if (what === 'admin') {
        await page.goto(base + '/admin/index.php');
        await page.fill('#in-name', 'tester');
        await page.type('#in-pass', pass);
        await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
        await pause(1800);
        const tabs = await page.$$eval('.tabs button[data-tab]', bs => bs.filter(b => b.getClientRects().length).map(b => b.dataset.tab));
        const tab = async t => {
          await page.evaluate(t => document.querySelector('.tabs button[data-tab="' + t + '"]').click(), t);
          await pause(1500);
        };
        for (const t of tabs) {
          if (t === 'settings') continue;
          await tab(t);
          await look('tab ' + t);
          const adds = {certs: ['#ct-add', 'the list row'], sources: ['#src-add'], validation: ['#val-add'],
                        targets: ['#tg-add'], tests: ['#ts-add']}[t] || [];
          for (const a of adds) {
            if (a === 'the list row') {
              await dialog('tab certs: a certificate', '#tab-certs table tbody tr');
            } else {
              await dialog('tab ' + t + ': ' + a, a);
            }
          }
          if (t === 'events') await dialog('tab events: the daemon log', '#log-read');
        }
        await tab('settings');
        const panes = await page.$$eval('#ctl-nav button[data-pane]', bs => bs.filter(b => b.getClientRects().length).map(b => b.dataset.pane));
        for (const p of panes) {
          await page.evaluate(p => document.querySelector('#ctl-nav button[data-pane="' + p + '"]').click(), p);
          await pause(1300);
          if (p !== 'teams') {
            await look('settings ' + p);
            if (p === 'people') { await dialog('settings people: #us-add', '#us-add'); await dialog('settings people: #ad-add', '#ad-add'); }
            continue;
          }
          await page.waitForSelector('#tmx .tmx-vbtn', {timeout: 20000}).catch(() => {});
          await pause(600);
          const views = await page.$$eval('#tmx .tmx-vbtn', bs => bs.map((b, i) => i));
          for (const i of views) {
            await page.evaluate(i => document.querySelectorAll('#tmx .tmx-vbtn')[i].click(), i);
            await pause(1300);
            const v = await page.evaluate(i => document.querySelectorAll('#tmx .tmx-vbtn')[i].textContent.trim().replace(/\s*\d+$/, ''), i);
            await look('settings teams / ' + v);
            if (i === 0) {
              // the team with the most members, and each of its tabs
              await page.evaluate(() => {
                const r = Array.from(document.querySelectorAll('#tmx .tmx-row')).find(x => /Big team/.test(x.textContent));
                if (r) r.click();
              });
              await pause(1300);
              const tt = await page.$$eval('#tmx .tmx-tab', bs => bs.map(b => b.dataset.tab));
              for (const x of tt) {
                await page.evaluate(x => document.querySelector('#tmx .tmx-tab[data-tab="' + x + '"]').click(), x);
                await pause(1300);
                await look('settings teams / Organisation / Big team / ' + x);
              }
            }
          }
        }
      } else {
        await page.goto(base + '/');
        await page.fill('#in-name', user);
        await page.fill('#in-pass', pass);
        await page.click('#in-go');
        if (what === 'solo') {
          await page.waitForSelector('#cp-list table', {timeout: 30000});
          await pause(1000);
          await look('portal solo');
          await dialog('portal solo: a certificate', '#cp-list tbody tr');
        } else {
          await page.waitForSelector('#pw-nav', {timeout: 30000});
          await pause(1200);
          const navs = await page.$$eval('#pw-nav .pw-navi', bs => bs.map(b => b.getAttribute('data-view')));
          for (const v of navs) {
            await page.evaluate(v => document.querySelector('#pw-nav .pw-navi[data-view="' + v + '"]').click(), v);
            await pause(1500);
            await look('portal ' + v);
            if (v === 'certs') await dialog('portal certs: a certificate', '#cp-list tbody tr');
            if (v === 'home') await dialog('portal home: ask', '#pw-ask');
            if (v === 'devices') await dialog('portal devices: add', '#pw-add-device');
            if (v === 'members') await dialog('portal members: add', '#pw-add-member');
            if (v === 'deploys') await dialog('portal deploys: add', '#pw-add-deploy');
            if (v === 'teams') await dialog('portal teams: add', '#pw-add-team');
          }
          // the team switcher open (a popover: allowed)
          if (await page.$('.pw-switch-b')) {
            await page.click('.pw-switch-b').catch(() => {});
            await pause(500);
            await look('portal: the team switcher open');
            await page.keyboard.press('Escape');
          }
        }
      }
    } catch (e) {
      out.errors.push(tag + ': ' + String(e && e.stack || e));
    }
    await ctx.close();
  };

  await Promise.all(sizes.map(tour));
  console.log(JSON.stringify(out));
  await browser.close();
})();
