#!/usr/bin/env python3
"""Hunt v2, area ui: what the UI sweep of 1.0.141 found and fixed.

    python3 test/test_hunt_rv2_ui.py
    ACME_RV2_CS=FILE   {English: Czech} merged into the copy's cs.json (before they are in it)
    ACME_SHOTS=DIR     screenshots there

- Settings → Agent fleet for an account kept to its teams (a certificate administrator or a
  reader with certs_*_all off): the pane asked /api/fleet, got 403 (a console error) and showed a
  red "The fleet could not be asked"; it now says calmly whom the fleet is for and asks nothing.
  A full administrator's fleet is drawn as before.
- The Events of the 1.0.140 reports and team digests ("the team Web: the digest switched on by
  tester (weekly, day 1, 07:00)", "the report X (inventory) was added by Y", ...) stayed in
  English on the Czech page; with the Czech of cs_rv2_ui.json they are Czech (checked here with
  web/assets/i18n.js itself, and on the page).
- Owners and teams: the tree's head said "2 teams · 1 units" in English; now "1 unit" / "1 team".
"""
import json
import os
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_f140_reports as RP  # noqa: E402  (its daemon, accounts cm/jan, teams, php -S)

CS = os.environ.get('ACME_RV2_CS', '')
SHOTS = os.environ.get('ACME_SHOTS', '')

EVENTS = [
    'the team Web: the digest switched on by tester (weekly, day 1, 07:00)',
    'the team Web: the digest set (off) by tester (daily, 07:00)',
    'a preview of the digest of the team Web was sent to tester (a@example.test)',
    'the digest of the team Web was not sent: nothing to tell',
    'the digest of the team Web was not sent: mail is switched off',
    'the digest of the team Web was not sent: nobody to send it to (no contact address, '
    'no member with an address)',
    'the digest of the team Web was sent to a@example.test (3 item(s))',
    'the digest of the team Web could not be made: boom',
    'tester downloaded the report Inv (PDF, run 3)',
    'the report Inv (inventory) was added by tester',
    'the report Inv (inventory) was changed by tester',
    'the report Inv was deleted by tester',
    'the report Inv was made by tester (3 row(s), CSV, PDF)',
    'the report Inv was made by tester (3 row(s), CSV) and sent to a@example.test',
    'the report Inv could not be made: boom',
]

TRANSLATE = r'''
const fs = require('fs'), vm = require('vm');
const [web, extraPath] = process.argv.slice(1);
const pack = JSON.parse(fs.readFileSync(web + '/lang/cs.json', 'utf8'));
const extra = extraPath ? JSON.parse(fs.readFileSync(extraPath, 'utf8')) : {};
const p = {code: 'cs', strings: {}, patterns: [], rich: {}};
for (const v of Object.values(pack.strings || {})) p.strings[v.source] = v.text;
for (const v of Object.values(pack.patterns || {})) p.patterns.push([v.source, v.text]);
for (const v of Object.values(pack.rich || {})) p.rich[v.source] = v.text;
for (const [en, cs] of Object.entries(extra)) { if (/\{\d\}/.test(en)) p.patterns.push([en, cs]); else p.strings[en] = cs; }
const ctx = {Map, RegExp, console, navigator: {}, document: {documentElement: {classList: {remove() {}, add() {}},
  getAttribute() { return null; }}, addEventListener() {}, querySelectorAll() { return []; }}};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(web + '/assets/i18n.js', 'utf8'), ctx);
ctx.i18nInit(p);
const lines = JSON.parse(fs.readFileSync(0, 'utf8'));
console.log(JSON.stringify(lines.map(l => ctx.i18nText(l))));
'''

ENGLISH = ('the digest', 'the report', 'switched on', 'was added', 'weekly', 'daily', 'was made',
           'not sent', 'nothing to tell', 'downloaded', 'item(s)', 'row(s)', 'could not')


def node_ok():
    node = shutil.which('node')
    return node if node else None


class Source(unittest.TestCase):
    def test_fleet_asks_nothing_when_scoped(self):
        with open(os.path.join(ROOT, 'web', 'assets', 'fleet.js'), encoding='utf-8') as f:
            src = f.read()
        self.assertIn('function scopedOut()', src)
        self.assertIn("d.scoped && d.scoped.view", src)
        pane = src[src.index('function pane(live)'):src.index('function paneAsk(')]
        self.assertNotIn("ask('fleet')", pane, 'the fleet is asked only once the account may see it')

    def test_event_texts_in_czech(self):
        node = node_ok()
        if not node:
            self.skipTest('no node here')
        if not CS or not os.path.isfile(CS):
            self.skipTest('ACME_RV2_CS not given (the Czech is not in web/lang/cs.json yet)')
        got = subprocess.run([node, '-e', TRANSLATE, os.path.join(ROOT, 'web'), CS],
                             input=json.dumps(EVENTS), capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        out = json.loads(got.stdout)
        for en, cs in zip(EVENTS, out):
            self.assertTrue(cs and cs != en, en)
            for word in ENGLISH:
                self.assertNotIn(word, cs, (en, cs))
            self.assertIn('Web' if 'Web' in en else 'Inv', cs)


class Pages(RP.Pages):
    test_pages = None

    @classmethod
    def setUpClass(cls):
        if CS and os.path.isfile(CS):
            os.environ['ACME_EXTRA_CS'] = CS
        RP.Pages.setUpClass.__func__(cls)
        cls.must('POST', '/api/reports/save', {'name': 'Inv', 'kind': 'inventory', 'formats': ['csv'],
                                               'schedule': {'every': 'off'}})

    def test_pages_rv2(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rv2_ui_page.js'), base, self.pw,
                                  SHOTS], capture_output=True, text=True, timeout=1500, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 12)
        for r in seen['runs']:
            tag = '%s %s %s' % (r['who'], r['lang'], r['w'])
            self.assertEqual(r['hscroll'], 0, tag)
            self.assertEqual(r['bad'], '', tag)
            self.assertFalse([x for x in r['http'] if 'fleet' in x], (tag, r['http']))
            if r['lang'] == 'en':
                self.assertEqual(r['treeCounts'], '2 teams · 1 unit', tag)
            else:
                self.assertEqual(r['treeCounts'].split(' · ')[1], '1 jednotka', tag)
            if r['who'] == 'tester':
                self.assertTrue(r['hero'], tag)
                self.assertFalse(r['scoped'], tag)
                self.assertTrue(r['events'], tag)
                if r['lang'] == 'cs' and CS:
                    for t in r['events']:
                        for word in ('the digest', 'the report', 'switched on', 'was added'):
                            self.assertNotIn(word, t, (tag, t))
            else:
                self.assertTrue(r['scoped'], tag)
                self.assertFalse(r['hero'], tag)
                if r['lang'] == 'cs' and CS:
                    self.assertIn('Flotila agentů je pro toho', r['note'], tag)
                elif r['lang'] == 'en':
                    self.assertIn('The fleet is for whoever sees every certificate', r['note'], tag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
