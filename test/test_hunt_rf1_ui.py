#!/usr/bin/env python3
"""Hunt r f1, the UI of 1.0.138: what was found in the browser and fixed.

    python3 test/test_hunt_rf1_ui.py

- The right button's menu is placed by its laid-out size: the opening animation scales it to
  .98 while it is measured, and a long menu near the bottom ran 8-16 px past the window.
- The line a list says it is empty with ("No job yet") is no row: no "Filter by No job yet",
  nothing to pick.
- A module's rows picked together (sources, validation, targets, tests, agents): "Copy them to
  the acme clipboard" once, not twice.
- The "now" chip of an object's History stays whole on a phone (it was "n…").
- Czech for what the 1.0.138 events and the "Who may" answers say (the Events tab, a team's
  activity): every text below translated, with nothing English left. The Czech comes from
  web/lang/cs.json, with this hunt's scratchpad file merged in while it is not in it yet.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def node():
    n = shutil.which('node')
    return n if n and subprocess.run([n, '-e', '1'], capture_output=True).returncode == 0 else None


def playwright():
    n = node()
    return bool(n) and subprocess.run([n, '-e', 'require("playwright")'], capture_output=True,
                                      cwd=ROOT).returncode == 0


def czech_pack(out):
    """web/lang/cs.json with this hunt's Czech merged in (when it is not in it yet)."""
    with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
        pack = json.load(f)
    have = {v['source'] for s in ('strings', 'patterns', 'rich') for v in pack.get(s, {}).values()}
    for fn in glob.glob('/tmp/claude-*/*/*/scratchpad/huntr/cs_rf1_ui.json'):
        with open(fn, encoding='utf-8') as f:
            more = json.load(f)
        for i, (en, cs) in enumerate(sorted(more.items())):
            if en not in have:
                part = 'patterns' if re.search(r'\{\d\}', en) else 'strings'
                pack.setdefault(part, {})['%srf1ui%04d' % (part[0], i)] = {'source': en, 'text': cs}
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(pack, f, ensure_ascii=False)


TRANSLATE = r"""
const vm = require('vm'), fs = require('fs'), path = require('path');
const [root, csjson, list] = process.argv.slice(2);
const all = JSON.parse(fs.readFileSync(csjson, 'utf8'));
const pack = {code: 'cs', strings: {}, patterns: [], rich: {}};
for (const part of ['strings', 'patterns', 'rich']) for (const e of Object.values(all[part] || {})) {
  const from = String(e.source || ''), to = String(e.text || '');
  if (!from || !to || (to === from && part !== 'patterns')) continue;
  if (part === 'patterns') pack.patterns.push([from, to]); else pack[part][from] = to;
}
const ctx = {window: {}, Map, Set, WeakMap, console, ACME_LANG_PACK: pack,
  document: {readyState: 'loading', addEventListener() {}, documentElement: {setAttribute() {}, classList: {remove() {}}},
             querySelectorAll: () => [], createTreeWalker() { return {nextNode: () => null}; }},
  MutationObserver: function () { this.observe = () => {}; this.takeRecords = () => []; }, setTimeout: () => {}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(root, 'web', 'assets', 'i18n.js'), 'utf8')
                + ';this.i18nText = i18nText; this.i18nInit = i18nInit;', ctx);
ctx.i18nInit(pack);
const out = {};
for (const s of JSON.parse(fs.readFileSync(list, 'utf8'))) out[s] = ctx.i18nText(s);
console.log(JSON.stringify(out));
"""

# What the 1.0.138 events and answers say (acmelib/certs/fleet.py, teamgov.py, history.py,
# viewas.py, teams.py, api_ctxmenu.py, teamaccess.py), as the daemon writes them.
TEXTS = [
    "target copy-one made as a copy of fake1 - with its credentials (password) by tester",
    "the fleet template Shop cluster was saved by tester (version 3, 4 line(s)) - documentation only: "
    "acme never sends a policy",
    "the fleet template Shop cluster was deleted by tester",
    "the agents' group Windows was made by tester (2 member(s))",
    "the agents' group Windows was changed by tester (1 member(s))",
    "the agents' group Windows was deleted by tester",
    "the fleet template of 3 agent(s) was set to Shop cluster by tester",
    "the fleet template of 1 agent(s) was taken away by tester",
    "the agents' update rollout to 1.0.138 is done: 5 agent(s), 0 failed",
    "an update rollout of the agents to 1.0.138 was started by tester: 1 in the canary ring, 4 after "
    "30 minute(s)",
    "the agents' update rollout to 1.0.138 was stopped by tester",
    "the agents' update rollout to 1.0.138 goes on with the rest, by tester",
    "the certificate found on web-02 (/etc/nginx/ssl/shop.crt) was taken over by tester: certificate "
    "shop.example.test, its deployment there",
    "the target hist-a: the version of 2026-11-21 10:00 restored by tester",
    "the target trashme restored from the trash by tester",
    "the request profile Shop restored from the trash by tester",
    "3 item(s) deleted from the trash for good by tester",
    "the team Webteam: just-in-time elevation switched off by tester",
    "the team Webteam: its webhooks changed by tester (teams set, slack taken away)",
    "local:jan asks for the role Approver on the team Webteam for 4 hour(s): tonight",
    "local:eva gave local:jan the role Approver on the team Webteam until 2026-11-22 02:00 (4 h, asked: x)",
    "local:eva declined the request of local:jan for the role Approver on the team Webteam: no",
    "local:eva ended the role Approver of local:jan on the team Webteam",
    "the temporary role Approver of local:jan on the team Webteam ended by itself",
    "the request of local:jan for the role Approver on the team Webteam ended: nobody answered it in a week",
    "an access review of the team Webteam was opened by tester: 3 member(s) to confirm by 2026-12-21",
    "local:boss confirmed local:jan in the access review of the team Webteam - the review is done",
    "the access review of the team Webteam is overdue: 2 member(s) not confirmed (local:jan, local:eva)",
    "the team template Shop tpl deleted by tester",
    "the team Shop made from the template Shop tpl by tester",
    "3 team(s) imported from CSV by tester: A, B, C",
    "the notification channels of the team Webteam were tried",
    "tester views the administration as local:jan (readonly, read-only) - member of the team Webteam",
    "tester stopped viewing the administration as local:jan",
    "tester views the portal as local:jan (read-only)",
    "the role Gone role added by tester: cert.view",
    "the role Gone role deleted by tester",
    "a full administrator - every capability on every team, whatever is set",
    "a read-only account, with \"Read-only accounts see every certificate\" on",
]
ENGLISH = re.compile(r"(?<![\w'-])(the|was|by|made|saved|changed|deleted|added|group|template|"
                     r"rollout|restored|trash|asks|gave|declined|ended|review|views|viewing|"
                     r"stopped|imported|tried|every|account|with)(?![\w'-])", re.I)


class Source(unittest.TestCase):
    def test_menu_placed_by_its_laid_out_size(self):
        js = read('web/assets/ctxmenu.js')
        place = js[js.index('function place('):js.index('function keys(')]
        self.assertIn('node.offsetHeight', place)
        self.assertNotIn('getBoundingClientRect', place)

    def test_placeholder_row_is_no_row(self):
        js = read('web/assets/ctxmenu.js')
        where = js[js.index('function where('):js.index('CX.where = where')]
        self.assertIn('placeholderRow(got.row)', where)

    def test_copy_them_once(self):
        reg = read('web/assets/ctxmenu-registry.js')
        bulk = reg[reg.index('function modBulk('):reg.index('Jobs\n')]
        self.assertNotIn("'Copy them to the acme clipboard'", bulk)
        self.assertIn("'Copy them to the acme clipboard'", read('web/assets/ctxmenu.js'))

    def test_now_chip_whole(self):
        self.assertIn('.hs-top > .tmx-chip{flex:0 0 auto}', read('web/assets/history.css'))


@unittest.skipUnless(node(), 'no node here')
class Czech(unittest.TestCase):
    def test_events_and_answers_in_czech(self):
        tmp = tempfile.mkdtemp(prefix='hunt-rf1-')
        try:
            cs = os.path.join(tmp, 'cs.json')
            czech_pack(cs)
            lst = os.path.join(tmp, 'texts.json')
            js = os.path.join(tmp, 'tr.js')
            with open(lst, 'w') as f:
                json.dump(TEXTS, f)
            with open(js, 'w') as f:
                f.write(TRANSLATE)
            r = subprocess.run([node(), js, ROOT, cs, lst], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            got = json.loads(r.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        bad = []
        for en in TEXTS:
            said = got.get(en)
            if not said:
                bad.append('untranslated: ' + en)
                continue
            left = ENGLISH.findall(said.replace('Gone role', '').replace('Shop cluster', ''))
            if left:
                bad.append('%s => %s (%s)' % (en, said, left))
        self.assertEqual(bad, [])
        # user data stays as it is
        self.assertIn('Shop cluster', got[TEXTS[2]])
        self.assertIn('(Teams nastaven, Slack odebrán)', got[TEXTS[18]])


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="ROOT/web/assets/acme.css"><link rel="stylesheet" href="ROOT/web/assets/ctxmenu.css">
</head><body><main class="ctl-main"><div style="height:700px"></div>
<table id="t1"><thead><tr><th>Name</th><th>State</th></tr></thead><tbody></tbody></table>
<table id="t2"><thead><tr><th>Name</th><th>State</th></tr></thead>
<tbody><tr class="empty-row"><td colspan="2">No thing yet</td></tr></tbody></table>
<div style="height:40px"></div></main>
<div id="modal" hidden><div id="modal-box"><div id="modal-body"></div><div id="modal-foot"></div></div></div>
<div class="toast" id="toast"></div>
<script>var ME = {name: 'tester', role: 'fulladmin', prefs: {}}; var LIVE = {on: false};</script>
<script src="ROOT/web/assets/i18n.js"></script><script src="ROOT/web/assets/core.js"></script>
<script src="ROOT/web/assets/ctxmenu.js"></script>
<script>
var tb = document.querySelector('#t1 tbody');
['a', 'b', 'c'].forEach(function (n) {
  var r = document.createElement('tr'); r.innerHTML = '<td>' + n + '</td><td>ok</td>'; r._rec = {name: n}; tb.appendChild(r);
});
var acts = [];
for (var i = 0; i < 14; i++) acts.push({label: 'Action ' + i, icon: 'gear', go: function () {}});
ACME_CTX.type('thing', {label: 'Thing', plural: 'things', icon: 'gear', key: function (o) { return o.name; },
  nameOf: function (o) { return o.name; }, actions: function () { return acts; }});
ACME_CTX.scope({sel: '#t1', type: 'thing'});
ACME_CTX.scope({sel: '#t2', type: 'thing'});
</script></body></html>"""

DRIVE = r"""
const { chromium } = require('playwright');
(async () => {
  const [html] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: []};
  for (const [w, h] of [[1400, 900], [390, 844]]) {
    const page = await browser.newPage({viewport: {width: w, height: h}, deviceScaleFactor: 1});
    page.on('pageerror', e => out.errors.push(String(e.message || e)));
    await page.goto('file://' + html);
    await page.waitForTimeout(300);
    const cell = page.locator('#t1 tbody tr').last().locator('td').first();
    await cell.evaluate(e => e.scrollIntoView({block: 'end'}));   /* near the bottom of the window */
    const b = await cell.boundingBox();
    await page.mouse.click(b.x + 5, b.y + b.height / 2, {button: 'right'});
    await page.waitForTimeout(400);
    out['fit' + w] = await page.evaluate(() => {
      const m = document.querySelector('.cxm'); if (!m) return null; const r = m.getBoundingClientRect();
      return {n: m.querySelectorAll('.cxm-i').length, left: r.left, right: r.right, top: r.top, bottom: r.bottom, w: innerWidth, h: innerHeight};
    });
    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);
    await page.locator('#t2 tbody td').scrollIntoViewIfNeeded();
    const e = await page.locator('#t2 tbody td').boundingBox();
    await page.mouse.click(e.x + 5, e.y + e.height / 2, {button: 'right'});
    await page.waitForTimeout(300);
    out['empty' + w] = await page.$$eval('.cxm', n => n.length);
    await page.close();
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
"""


@unittest.skipUnless(playwright(), 'no node with playwright here')
class Browser(unittest.TestCase):
    def test_menu_fits_and_empty_line_has_none(self):
        tmp = tempfile.mkdtemp(prefix='hunt-rf1-')
        try:
            html = os.path.join(tmp, 'page.html')
            with open(html, 'w', encoding='utf-8') as f:
                f.write(PAGE.replace('ROOT/', 'file://' + ROOT + '/'))
            js = os.path.join(tmp, 'drive.js')
            with open(js, 'w') as f:
                f.write(DRIVE)
            r = subprocess.run([node(), js, html], capture_output=True, text=True, cwd=ROOT, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            got = json.loads(r.stdout.strip().splitlines()[-1])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(got['errors'], [])
        for w in (1400, 390):
            f = got['fit%d' % w]
            self.assertIsNotNone(f, w)
            self.assertGreater(f['n'], 12, w)
            self.assertLess(f['bottom'] - f['top'], f['h'] - 16, (w, f))   # not cut by its max-height
            self.assertGreaterEqual(f['top'], 7.5, (w, f))
            self.assertLessEqual(f['bottom'], f['h'] - 7.5, (w, f))
            self.assertGreaterEqual(f['left'], 7.5, (w, f))
            self.assertLessEqual(f['right'], f['w'] - 7.5, (w, f))
            self.assertEqual(got['empty%d' % w], 0, w)


if __name__ == '__main__':
    unittest.main(verbosity=2)
