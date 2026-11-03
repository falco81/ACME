// The popup over a popup (core.js), in a page of its own - no daemon needed.
//
//   node test/modal_stack_page.js /path/to/web/assets/core.js
//
// 1. A certificate open, "Renew now?" asked over it; the answer closes the
//    question and opens the job's log over the certificate at once: the log
//    stays on top (it was replaced by the certificate drawn afresh, 1.0.19),
//    and the certificate is drawn afresh once the log is closed.
// 2. A question closed with nothing opened after it: the one under it is drawn
//    afresh as before.
// 3. A long popup scrolled far down, something looked at over it and closed:
//    drawn afresh, it is where it was - not at its top (1.0.38); also when it
//    is drawn first as "Asking…" and then whole a moment later.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const core = fs.readFileSync(process.argv[2], 'utf-8');
  const html = '<!doctype html><html><body>'
    + '<div class="modal" id="modal" hidden><div class="box" id="modal-box"><div class="head">'
    + '<h3 id="modal-title"></h3><button class="xbtn" id="modal-x"></button></div>'
    + '<div class="body" id="modal-body"></div><div class="foot" id="modal-foot"></div></div></div>'
    + '<div class="toast" id="toast"></div><script>' + core.replace(/<\/script/g, '<\\/script') + '</script></body></html>';
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const out = {checks: {}, errors: []};
  page.on('pageerror', (e) => out.errors.push(String(e)));
  try {
    await page.setContent(html);
    const top = () => page.evaluate(() => ({title: $('modal-title').textContent, stack: MODAL_STACK.length,
                                            drawn: window.DRAWN}));
    const wait = () => page.waitForTimeout(80);
    // 1. the question answered, the log opened at once
    await page.evaluate(() => {
      window.DRAWN = 0;
      window.cert = function () { window.DRAWN += 1; modal('the certificate', function (b) { b.textContent = 'its body'; }, [{words: 'Close', close: true}]); };
      cert();
      modalOver(function () { modal('Renew it now?', function (b) { b.textContent = 'sure?'; }, [{words: 'No', close: true}]); }, cert);
      closeModal();                                            // the question goes
      modalOver(function () { modal('the job', function (b) { b.textContent = 'its log'; }, [{words: 'Close', close: true}]); });
    });
    await wait();
    let t = await top();
    out.checks.log_stays_on_top = t.title === 'the job' && t.stack === 1;
    out.checks.not_drawn_under_it_yet = t.drawn === 1;
    await page.evaluate(() => closeModal());
    await wait();
    t = await top();
    out.checks.certificate_again_after_the_log = t.title === 'the certificate' && t.stack === 0 && t.drawn === 2;
    await page.evaluate(() => closeModal());
    // 2. a question closed, nothing opened after it
    await page.evaluate(() => {
      window.DRAWN = 0;
      cert();
      modalOver(function () { modal('Renew it now?', function (b) { b.textContent = 'sure?'; }, [{words: 'No', close: true}]); }, cert);
      closeModal();
    });
    await wait();
    t = await top();
    out.checks.drawn_afresh_when_nothing_opened = t.title === 'the certificate' && t.stack === 0 && t.drawn === 2;
    await page.evaluate(() => closeModal());
    // 3. where it was scrolled to stays
    await page.evaluate(() => {
      document.head.insertAdjacentHTML('beforeend', '<style>#modal-body{height:200px;overflow:auto}</style>');
      window.longOne = function (b) { for (var i = 0; i < 80; i++) { var p = document.createElement('p'); p.textContent = 'line ' + i; b.appendChild(p); } };
      window.big = function () { modal('the certificate', longOne, [{words: 'Close', close: true}]); };
      window.slow = function () {
        modal('the certificate', function (b) { b.textContent = 'Asking…'; }, [{words: 'Close', close: true}]);
        setTimeout(big, 60);
      };
    });
    for (const [name, redraw] of [['kept_where_it_was', 'big'], ['kept_after_asking', 'slow']]) {
      await page.evaluate((redraw) => {
        big();
        $('modal-body').scrollTop = 900;
        modalOver(function () { modal('what the server served', function (b) { b.textContent = 'it'; }, [{words: 'Close', close: true}]); }, window[redraw]);
      }, redraw);
      await wait();
      await page.evaluate(() => closeModal());
      await page.waitForTimeout(400);
      out.checks[name] = await page.evaluate(() => $('modal-title').textContent === 'the certificate'
                                                  && Math.abs($('modal-body').scrollTop - 900) < 3);
      await page.evaluate(() => closeModal());
    }
    // ...and a popup opened afresh later opens at its top
    await page.evaluate(() => big());
    await wait();
    out.checks.a_new_one_at_its_top = await page.evaluate(() => $('modal-body').scrollTop === 0);
  } catch (e) {
    out.error = String(e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
