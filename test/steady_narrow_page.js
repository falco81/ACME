// Steady columns (core.js ltSteady) in a box narrower than the list - a phone -
// in a page of its own, no daemon needed.
//
//   node test/steady_narrow_page.js /path/to/web/assets/core.js
//
// The widths kept were shares of the box: every column squeezed under its
// words and the tags of one cell lay over the next (Settings → Upgrades at
// 390 px, 1.0.19). Kept at its own width, the list scrolls in its box, and is
// drawn again at the same widths.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  const core = fs.readFileSync(process.argv[2], 'utf-8');
  const html = '<!doctype html><html><head><style>.scroll{overflow-x:auto} table{width:100%;border-collapse:collapse}'
    + ' td,th{padding:4px 8px} .tag{display:inline-block;white-space:nowrap}</style></head><body>'
    + '<div id="host" style="width:300px"></div><div class="toast" id="toast"></div><script>'
    + core.replace(/<\/script/g, '<\\/script') + '</script></body></html>';
  const browser = await chromium.launch();
  const page = await browser.newPage({viewport: {width: 390, height: 800}});
  const out = {checks: {}, errors: []};
  page.on('pageerror', (e) => out.errors.push(String(e)));
  try {
    await page.setContent(html);
    const draw = () => page.evaluate(() => {
      const host = document.getElementById('host');
      host.innerHTML = '';
      const rows = [{n: 'acme1', v: '1.0.19', s: 'in service'}, {n: 'acme2', v: '1.0.19', s: 'in maintenance'}];
      host.appendChild(listTable(['Node', 'Version', 'Heard from', 'State', ''], rows, function (r) {
        const tr = el('tr');
        const a = el('td'); a.appendChild(el('b', '', r.n)); a.appendChild(el('span', 'tag', 'this page')); tr.appendChild(a);
        tr.appendChild(el('td', '', r.v)); tr.appendChild(el('td', '', '12 seconds ago'));
        const s = el('td'); s.appendChild(el('span', 'tag', r.s)); tr.appendChild(s);
        const t = el('td'); t.appendChild(el('span', 'tag', 'Maintenance mode')); tr.appendChild(t);
        return tr;
      }));
    });
    const look = () => page.evaluate(() => {
      const t = document.querySelector('#host table');
      const spill = Array.from(t.querySelectorAll('td .tag')).some(function (g) {
        return g.getBoundingClientRect().right > g.closest('td').getBoundingClientRect().right + 1;
      });
      return {spill: spill, fixed: t.style.tableLayout, width: t.getBoundingClientRect().width,
              cols: Array.from(t.tHead.rows[0].cells).map(function (c) { return Math.round(c.getBoundingClientRect().width); })};
    });
    await draw();
    await page.waitForTimeout(100);
    const first = await look();
    await draw();
    await page.waitForTimeout(100);
    const again = await look();
    out.first = first; out.again = again;
    out.checks.kept_steady = first.fixed === 'fixed' && again.fixed === 'fixed';
    out.checks.wider_than_its_box_scrolls = first.width > 300;
    out.checks.nothing_lies_over_the_next_cell = !first.spill && !again.spill;
    out.checks.same_widths_drawn_again = JSON.stringify(first.cols) === JSON.stringify(again.cols);
  } catch (e) {
    out.error = String(e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
