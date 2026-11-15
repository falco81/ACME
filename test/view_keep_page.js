// The redraw keeper (core.js VIEWKEEP), in a page of its own - no daemon needed.
//
//   node test/view_keep_page.js /path/to/web/assets/core.js
//
// 1. A box that scrolls, with help shown under the pointer on every row the
//    pointer comes over (what the Settings do): the wheel scrolls it all the
//    way - the help drawn before the scroll was heard of undid it, and the
//    box stuck (1.0.106).
// 2. Read at the very end, the end drawn shorter: room is kept under it, but
//    never a whole frame of nothing, and none of it is left once another part
//    of the same box is shown (a Settings pane) - it went along to every pane.
// 3. The focus taken away on purpose (a click on nothing) is not put back by a
//    redraw of what had it: Space turned the page no more.
// 4. A popup whose main button cannot be pressed: the focus goes to its Close.
// 5. The room on the screen is never taken away (it moved everything up by its
//    height): not when its time is up with nothing held (a resize), not on a
//    wheel or a key down at the end; given back as the end grows again, never
//    more than half a frame of it however often the end is drawn shorter, and
//    given back as the reader scrolls up out of it.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const core = fs.readFileSync(process.argv[2], 'utf-8');
  const rows = (p, n) => Array.from({length: n}, (_, i) => '<div class="row" style="height:60px;border-bottom:1px solid #ccc">'
    + p + ' row ' + i + '</div>').join('');
  const html = '<!doctype html><html><head><style>'
    + 'html,body{margin:0;height:100%;overflow:hidden}'
    + '.main{position:absolute;top:0;left:0;right:0;bottom:0;overflow-y:auto}'
    + '.sethelp{position:fixed;display:none;left:10px;top:10px;width:200px;background:#eee}'
    + '</style></head><body>'
    + '<div class="main" id="main"><div class="pane" id="pane-a">' + rows('a', 80)
    + '<div class="card" id="last"><p>the end</p><div id="tail" style="height:500px">its rows</div></div></div>'
    + '<div class="pane" id="pane-b" hidden>' + rows('b', 6) + '</div></div>'
    + '<div class="modal" id="modal" hidden><div class="box" id="modal-box"><div class="head">'
    + '<h3 id="modal-title"></h3><button class="xbtn" id="modal-x"></button></div>'
    + '<div class="body" id="modal-body"></div><div class="foot" id="modal-foot"></div></div></div>'
    + '<div class="toast" id="toast"></div><script>' + core.replace(/<\/script/g, '<\\/script') + '</script></body></html>';
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 800, height: 600}});
  const out = {checks: {}, errors: []};
  page.on('pageerror', (e) => out.errors.push(String(e)));
  try {
    await page.setContent(html);
    await page.waitForTimeout(100);
    // 1. the wheel over rows that show help
    await page.evaluate(() => {
      window.HELPS = 0;
      document.querySelectorAll('#pane-a .row').forEach((r) => r.addEventListener('mouseover', (e) => {
        window.HELPS += 1; helpAt(r, 'about ' + r.textContent + ' ' + window.HELPS, e);
      }));
      window.addEventListener('scroll', hideHelp, true);
    });
    await page.mouse.move(400, 300);
    for (let i = 0; i < 20; i++) { await page.mouse.wheel(0, 120); await page.waitForTimeout(50); }
    await page.waitForTimeout(300);
    let y = await page.evaluate(() => $('main').scrollTop);
    out.wheel = {y, helps: await page.evaluate(() => window.HELPS)};
    out.checks.wheel_scrolls_all_the_way = y >= 2400 - 2;
    out.checks.help_was_shown = out.wheel.helps > 3;
    // 2. at the very end, the end drawn shorter
    await page.mouse.move(400, 300);
    for (let i = 0; i < 40; i++) { await page.mouse.wheel(0, 200); await page.waitForTimeout(20); }
    await page.waitForTimeout(300);
    await page.mouse.move(790, 590);
    await page.waitForTimeout(300);
    const r = await page.evaluate(() => new Promise((res) => {
      const m = $('main'), max = m.scrollHeight - m.clientHeight, at = m.scrollTop;
      $('tail').remove();
      setTimeout(() => {
        const room = document.querySelector('.view-room');
        const pane = $('pane-a').getBoundingClientRect();
        res({max, at, room: room ? parseFloat(room.style.height) : 0,
             blank: Math.max(0, Math.round(m.getBoundingClientRect().bottom - Math.max(pane.bottom, 0)))});
      }, 100);
    }));
    out.room = r;
    out.checks.was_at_the_end = Math.abs(r.at - r.max) < 2;
    out.checks.room_kept_under_it = r.room > 0;
    out.checks.never_a_frame_of_nothing = r.blank <= 300 + 20;
    await page.evaluate(() => { $('pane-a').hidden = true; $('pane-b').hidden = false; });
    await page.waitForTimeout(150);
    const b = await page.evaluate(() => ({rooms: document.querySelectorAll('.view-room').length,
                                          h: $('main').scrollHeight, top: $('main').scrollTop}));
    out.other = b;
    out.checks.no_room_on_another_pane = b.rooms === 0 && b.top === 0;
    // 3. the focus left on purpose
    await page.evaluate(() => { window.B = '<button id="go">a row</button><p id="empty" style="height:200px">nothing</p>'
      + '<div style="height:2000px">more</div>'; });
    await page.evaluate(() => { $('pane-b').innerHTML = window.B; });
    await page.click('#go');
    await page.mouse.click(400, 150);
    await page.waitForTimeout(50);
    await page.evaluate(() => { $('pane-b').innerHTML = window.B; });
    await page.waitForTimeout(100);
    out.checks.focus_left_stays_left = await page.evaluate(() => document.activeElement === document.body);
    // ...and still put back when the redraw took it
    await page.focus('#go');
    await page.evaluate(() => { $('pane-b').innerHTML = window.B; });
    await page.waitForTimeout(100);
    out.checks.focus_taken_by_a_redraw_back = await page.evaluate(() => document.activeElement === $('go'));
    // 4. a popup whose main button cannot be pressed
    await page.evaluate(() => modal('Approve it?', (body) => { body.appendChild(el('p', '', 'not yours')); },
      [{words: 'Close', close: true}, {words: 'Approve', cls: 'primary', disabled: true, go: () => {}}]));
    await page.waitForTimeout(100);
    out.checks.focus_in_the_popup_on_close = await page.evaluate(() =>
      $('modal').contains(document.activeElement) && document.activeElement.textContent.trim() === 'Close');
    // 5. the room on the screen kept
    await page.setContent(html);
    await page.waitForTimeout(100);
    await page.evaluate(() => { VIEWKEEP.roomWait = 400; });
    await page.mouse.move(400, 300);
    for (let i = 0; i < 40; i++) { await page.mouse.wheel(0, 200); await page.waitForTimeout(20); }
    await page.waitForTimeout(400);
    await page.mouse.click(400, 100);
    await page.waitForTimeout(400);
    const pos = () => page.evaluate(() => {
      const p = $('last').querySelector('p').getBoundingClientRect();
      return {top: $('main').scrollTop, end: Math.round(p.top),
              room: Array.from(document.querySelectorAll('.view-room')).reduce((n, r) => n + (parseFloat(r.style.height) || 0), 0)};
    });
    await page.evaluate(() => { $('tail').style.height = '100px'; });
    await page.waitForTimeout(200);
    const r0 = await pos();
    await page.setViewportSize({width: 800, height: 590});
    await page.waitForTimeout(1200);
    const r1 = await pos();
    out.room_kept = [r0, r1];
    out.checks.room_on_screen_kept_after_a_resize = r0.room > 0 && r1.room > 0 && Math.abs(r1.end - r0.end) <= 12;
    await page.mouse.move(400, 300);
    await page.mouse.wheel(0, 120);
    await page.waitForTimeout(300);
    await page.keyboard.press('PageDown');
    await page.keyboard.press('End');
    await page.waitForTimeout(300);
    const r2 = await pos();
    out.room_kept.push(r2);
    out.checks.room_kept_on_wheel_and_keys_down = Math.abs(r2.end - r1.end) < 1 && r2.room > 0;
    // drawn shorter again and again: never more than half a frame of room
    await page.evaluate(() => { $('tail').style.height = '500px'; });
    await page.waitForTimeout(200);
    const r3 = await pos();
    for (let i = 0; i < 10; i++) { await page.mouse.wheel(0, 200); await page.waitForTimeout(20); }
    await page.waitForTimeout(400);
    await page.mouse.click(400, 100);
    await page.waitForTimeout(300);
    await page.evaluate(() => { $('tail').style.height = '100px'; });
    await page.waitForTimeout(200);
    const r4 = await pos();
    out.room_kept.push(r3, r4);
    /* (the browser's own scroll anchoring may move it up as the end grows - never down) */
    out.checks.room_given_back_as_the_end_grows = r3.room === 0 && r3.end <= r2.end + 1;
    out.checks.room_never_over_half_a_frame = r4.room > 0 && r4.room <= 295 + 2;
    // scrolled up out of it: given back, nothing moves
    for (let i = 0; i < 5; i++) { await page.mouse.wheel(0, -200); await page.waitForTimeout(30); }
    await page.waitForTimeout(400);
    const r5 = await pos();
    out.room_kept.push(r5);
    out.checks.room_given_back_scrolling_up = r5.room === 0 && r5.top > 0;
  } catch (e) {
    out.error = String(e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.keys(out.checks).length > 0
    && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
