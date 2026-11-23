const { chromium } = require('playwright');
const path = require('path');
const [base, pass, shots, lang, wS, only] = process.argv.slice(2);
const w = +wS;
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
  await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(String(e.message)));
  page.on('console', m => { if (m.type() === 'error') errs.push('console ' + m.text().slice(0, 200)); });
  await page.goto(base + '/admin/index.php');
  await page.fill('#in-name', 'tester');
  await page.type('#in-pass', pass);
  await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
  await page.waitForTimeout(1500);
  const panes = await page.evaluate(() => [...document.querySelectorAll('[data-pane]')].map(x => x.dataset.pane));
  const tabs = await page.evaluate(() => [...document.querySelectorAll('[data-tab]')].map(x => x.dataset.tab));
  const places = tabs.map(t => ['tab', t]).concat([...new Set(panes)].map(p => ['pane', p]));
  const rep = [];
  for (const [kind, name] of places) {
    if (only && !only.split(',').includes(name)) continue;
    await page.evaluate(([k, n]) => { try { if (k === 'tab') showTab(n); else { showTab('settings'); showPane(n); } } catch (e) {} }, [kind, name]);
    await page.waitForTimeout(1500);
    const btns = await page.evaluate(() => {
      const vis = x => x.offsetParent !== null;
      const host = document.querySelector('.tab:not([hidden]) .pane:not([hidden])') || document.querySelector('main') || document.body;
      return [...document.querySelectorAll('button')].filter(b => vis(b) && !b.closest('#modal') && !b.closest('nav,header,.rail,.tabs'))
        .map((b, i) => { b.dataset.swp = 'b' + i; return {id: 'b' + i, t: b.textContent.trim().slice(0, 60)}; })
        .filter(b => /^(Add|New|Make|Edit|A new|Create|Connect|Import|Přidat|Nov|Upravit|Vytvo)/i.test(b.t));
    });
    for (const b of btns) {
      try {
        await page.click(`[data-swp="${b.id}"]`, {timeout: 3000});
      } catch (e) { continue; }
      await page.waitForTimeout(1200);
      const open = await page.evaluate(() => !document.getElementById('modal').hidden);
      if (!open) { rep.push({where: name, btn: b.t, open: false}); continue; }
      const info = await page.evaluate(() => {
        const box = document.getElementById('modal-box'), r = box.getBoundingClientRect();
        const over = [...box.querySelectorAll('*')].filter(e => { const q = e.getBoundingClientRect(); return q.width && (q.right > r.right + 1 || q.left < r.left - 1) && e.offsetParent !== null; })
          .slice(0, 5).map(e => e.tagName + '.' + e.className + ' ' + (e.textContent || '').slice(0, 40));
        const bodyH = document.getElementById('modal-body'); 
        const a = document.activeElement;
        return {title: document.getElementById('modal-title').textContent, focus: a ? a.tagName + '#' + a.id + '.' + a.className + ' ' + (a.getAttribute('aria-label') || a.textContent || '').slice(0, 30) : '',
          over, hs: bodyH.scrollWidth - bodyH.clientWidth, boxRight: r.right - innerWidth, pageH: document.scrollingElement.scrollWidth - innerWidth,
          foot: [...document.querySelectorAll('#modal-foot > button')].filter(x => !x.hidden).map(x => x.textContent.trim())};
      });
      await page.screenshot({path: path.join(shots, `${lang}-${w}-${name}-${b.t.replace(/[^a-z0-9]+/gi, '_').slice(0, 30)}.png`)});
      // try submitting empty: press the primary
      const sub = await page.evaluate(() => {
        const p = [...document.querySelectorAll('#modal-foot .btn.primary')].filter(x => !x.hidden && !x.disabled);
        return p.length ? p[p.length - 1].textContent.trim() : '';
      });
      let after = null;
      if (sub && !/deploy|issue|restart|nasadit|vydat/i.test(sub)) {
        const toasts0 = await page.evaluate(() => document.querySelectorAll('.toast').length);
        await page.evaluate(() => { const p = [...document.querySelectorAll('#modal-foot .btn.primary')].filter(x => !x.hidden && !x.disabled); p[p.length - 1].click(); });
        await page.waitForTimeout(1200);
        after = await page.evaluate(() => ({open: !document.getElementById('modal').hidden,
          toasts: [...document.querySelectorAll('.toast, #toast, .toasts > *')].map(x => x.textContent.trim().slice(0, 120)),
          inline: [...document.querySelectorAll('#modal-box .bad, #modal-box .err, #modal-box .ct-bad, #modal-box [aria-invalid=true], #modal-box .field-err, #modal-box .invalid')].filter(x=>x.offsetParent!==null).map(x => (x.tagName+' '+(x.textContent || x.name || '')).trim().slice(0, 120))}));
        await page.screenshot({path: path.join(shots, `${lang}-${w}-${name}-${b.t.replace(/[^a-z0-9]+/gi, '_').slice(0, 30)}-sub.png`)});
      }
      rep.push({where: name, btn: b.t, ...info, sub, after});
      // close
      for (let i = 0; i < 4; i++) {
        const st = await page.evaluate(() => !document.getElementById('modal').hidden);
        if (!st) break;
        await page.keyboard.press('Escape'); await page.waitForTimeout(300);
        await page.evaluate(() => { const y = document.querySelector('.gd-sure-yes'); if (y) y.click(); });
        await page.waitForTimeout(300);
        await page.evaluate(() => { try { closeModal(true); } catch (e) {} });
      }
    }
  }
  console.log(JSON.stringify({errs, rep}, null, 1));
  await browser.close();
})();
