// A popup is as tall as what is in it (core.js modal() and the redraw keeper VIEWKEEP), in a
// page of its own - no daemon needed.
//
//   node test/modal_fresh_page.js /path/to/web/assets/core.js
//
// 1. A long picker scrolled down, a tile in it clicked, and the popup drawn again as a short
//    form (Targets -> Add a target -> a module): the form's popup is its own height at once and
//    stays so - the keeper kept the picker's height as empty room in it, and then gave it back
//    seconds later: the popup grew and shrank by itself (1.0.108).
// 2. A part of a popup emptied for "Loading…": no height kept in it.
// 3. "More" closed at the end of a popup scrolled down: no room left in its place.
// 4. ...while on the page itself a box emptied for "Loading…" still keeps its height.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const core = fs.readFileSync(process.argv[2], 'utf-8');
  const html = '<!doctype html><html><head><style>'
    + 'html,body{margin:0;height:100%;overflow:hidden;font:14px sans-serif}'
    + '.main{position:absolute;top:0;left:0;right:0;bottom:0;overflow-y:auto}'
    + '.modal{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:24px 16px}'
    + '.modal[hidden]{display:none}'
    + '.modal .box{width:600px;max-height:92vh;display:flex;flex-direction:column;background:#fff;border:1px solid #888}'
    + '.modal .head{padding:10px}.modal .foot{padding:10px;border-top:1px solid #ccc}'
    + '.modal .body{padding:10px;overflow:auto;display:flex;flex-direction:column;min-height:0}'
    + '.modal .body > *{flex:none}'
    + '.tile{display:block;width:100%;height:70px;margin:0 0 6px}'
    + '</style></head><body>'
    + '<div class="main" id="main"><div id="list" style="height:300px">the list</div>'
    + '<div style="height:3000px">more of the page</div></div>'
    + '<div class="modal" id="modal" hidden><div class="box" id="modal-box"><div class="head">'
    + '<h3 id="modal-title"></h3><button class="xbtn" id="modal-x"></button></div>'
    + '<div class="body" id="modal-body"></div><div class="foot" id="modal-foot"></div></div></div>'
    + '<div class="toast" id="toast"></div><script>' + core.replace(/<\/script/g, '<\\/script') + '</script></body></html>';
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 900, height: 800}});
  const out = {checks: {}, errors: []};
  page.on('pageerror', (e) => out.errors.push(String(e)));
  // the box as it is, and as tall as what is in it would make it
  const size = () => page.evaluate(() => {
    const box = $('modal-box'), body = $('modal-body');
    /* where what is in it ends, its margin and the body's padding under it */
    const br = body.getBoundingClientRect(), cs = getComputedStyle(body);
    let end = 0;
    Array.prototype.forEach.call(body.children, (c) => {
      if (c.classList.contains('view-room')) return;
      end = Math.max(end, c.getBoundingClientRect().bottom - br.top - body.clientTop + body.scrollTop + parseFloat(getComputedStyle(c).marginBottom));
    });
    const natural = Math.min(end + parseFloat(cs.paddingBottom), body.scrollHeight);
    const kept = [body].concat(Array.from(body.querySelectorAll('*'))).filter((e) => e.style.minHeight).length;
    return {h: Math.round(box.getBoundingClientRect().height), top: Math.round(box.getBoundingClientRect().top),
            body: Math.round(body.scrollHeight), natural: Math.round(natural),
            rooms: document.querySelectorAll('.modal .view-room').length, kept};
  });
  const own = (s) => s.rooms === 0 && s.kept === 0 && Math.abs(s.body - s.natural) <= 2;
  try {
    await page.setContent(html);
    await page.waitForTimeout(100);
    await page.evaluate(() => { VIEWKEEP.roomWait = 600; });
    // 1. the picker, scrolled down, a tile clicked: the form in its place
    await page.evaluate(() => {
      window.form = () => modal('A new target · Barracuda', (body) => {
        body.appendChild(el('p', '', 'The settings of the module'));
        const d = el('details', 'ct-more'); d.id = 'more';
        d.appendChild(el('summary', '', 'More'));
        d.appendChild(el('div', '', 'what is in More')).style.height = '160px';
        body.appendChild(el('div')).appendChild(el('div', '', 'Name, In use, Tags, Note')).style.height = '200px';
        body.appendChild(d);
      }, [{words: 'Back', go: window.picker}, {words: 'Close', close: true}]);
      window.picker = () => modal('Add a target', (body) => {
        for (let i = 0; i < 40; i++) {
          const t = el('button', 'tile', 'module ' + i);
          t.onclick = window.form;
          body.appendChild(t);
        }
      }, [{words: 'Close', close: true}]);
      window.picker();
    });
    await page.waitForTimeout(150);
    await page.mouse.move(450, 400);
    for (let i = 0; i < 15; i++) { await page.mouse.wheel(0, 200); await page.waitForTimeout(30); }
    await page.waitForTimeout(700);    /* the wheel's half a second over: a click, not a scroll */
    out.scrolled = await page.evaluate(() => $('modal-body').scrollTop);
    await page.mouse.click(450, 400);
    const f = [];
    for (const wait of [30, 200, 1500, 3000]) { await page.waitForTimeout(wait); f.push(await size()); }
    out.form = f;
    out.checks.picker_was_scrolled = out.scrolled > 500;
    out.checks.form_drawn = await page.evaluate(() => /Barracuda/.test($('modal-title').textContent));
    out.checks.form_its_own_height_at_once = own(f[0]);
    out.checks.form_never_grows_or_shrinks_by_itself = f.every((s) => own(s) && Math.abs(s.h - f[0].h) <= 1 && Math.abs(s.top - f[0].top) <= 1);
    // 2. a part of the popup emptied for "Loading…"
    await page.evaluate(() => {
      const part = $('modal-body').children[1];
      part.id = 'part';
      clear(part);
      part.appendChild(el('p', '', 'Loading…'));
    });
    const l = [];
    for (const wait of [50, 1000, 4500]) { await page.waitForTimeout(wait); l.push(await size()); }
    out.loading = l;
    out.checks.loading_part_keeps_no_height = l.every((s) => own(s) && Math.abs(s.h - l[0].h) <= 1);
    // 3. More opened, scrolled to its end, closed again
    await page.evaluate(() => {
      $('part').firstChild.style.height = '900px';
      $('more').open = true;
    });
    await page.waitForTimeout(100);
    await page.mouse.move(450, 400);
    for (let i = 0; i < 10; i++) { await page.mouse.wheel(0, 300); await page.waitForTimeout(30); }
    await page.waitForTimeout(300);
    await page.evaluate(() => { $('part').firstChild.style.height = '300px'; });
    await page.click('#more summary');
    const m = [];
    for (const wait of [50, 1000, 2000]) { await page.waitForTimeout(wait); m.push(await size()); }
    out.more = m;
    out.checks.more_closed_leaves_no_room = m.every((s) => own(s) && Math.abs(s.h - m[0].h) <= 1);
    // 4. the page itself: a box emptied for "Loading…" keeps its height a moment (1.0.105)
    await page.evaluate(() => closeModal());
    await page.waitForTimeout(100);
    const kept = await page.evaluate(() => new Promise((res) => {
      const list = $('list');
      clear(list);
      list.style.height = '';
      list.appendChild(el('p', '', 'Loading…'));
      setTimeout(() => res(list.offsetHeight), 100);
    }));
    out.page_kept = kept;
    out.checks.page_box_still_kept_while_loading = kept >= 290;
  } catch (e) {
    out.error = String(e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.keys(out.checks).length > 0
    && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
