#!/usr/bin/env python3
"""Hunt w1, area ui: what the administration's lists do after an action.

    python3 test/test_hunt_rw1_ui.py
    ACME_SHOTS=DIR     screenshots there

- Certificates, a page further than the first: a certificate deleted (its dialog, a bulk
  action, anything that calls ACME_CERTS.refresh) stayed in the list - and in the count - until
  the next live tick found the daemon's serial moved; with the live updates paused, until F5.
  The page's own refresh after a change draws it on any page (drawTab ... moved).
- Rows picked (Ctrl+click) on one tab stayed "2 selected" in the dock on every other tab, and
  its Actions - Delete them... among them - ran on rows nobody could see. A list not shown has
  nothing picked for the dock; shown again, its rows are picked again.
- Ctrl+K kept the objects it found for a minute whatever happened: a certificate deleted on the
  page was still offered (its card a 404), one renamed was found only by its old name. The
  page's own changes empty it, and the daemon's serial (another tab, another person) too.
- "Show in Jobs" and "Show in Events" of a row's menu set the certificate (the words) but left
  the outcome, the kind chosen there before: "No job matches" for a certificate with jobs.
  They are cleared, as the Overview's links have done since 1.0.125.
- Columns laid out in two tabs of one browser: the whole layout is saved at once, so the tab
  opened first saved its older copy over the other's change. The other tabs take the layout as
  kept when one saves.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_f140_reports as RP  # noqa: E402  (its daemon, accounts, php -S)

SHOTS = os.environ.get('ACME_SHOTS', '')


def src(name):
    with open(os.path.join(ROOT, 'web', 'assets', name), encoding='utf-8') as f:
        return f.read()


class Source(unittest.TestCase):
    def test_refresh_on_any_page(self):
        js = src('certs.js')
        body = js[js.index('CT.refresh = function'):js.index('CT.draw = drawTab')]
        self.assertIn('drawTab(tab, true, true)', body)
        # the live tick still leaves a page further back alone
        self.assertIn("if (live && name === 'certs' && CL.page > 0 && !moved) return;", js)

    def test_hidden_list_has_nothing_picked(self):
        js = src('ctxmenu.js')
        sel = js[js.index('function selRows()'):js.index('CX.selected = selRows')]
        self.assertIn('SEL.box.offsetParent === null && !SEL.box.getClientRects().length', sel)

    def test_palette_follows_changes(self):
        pal = src('palette.js')
        items = pal[pal.index('function objectItems()'):pal.index('function openTeam(')]
        self.assertIn('CACHE.serial === serialNow()', items)
        self.assertIn('gen !== CACHE.gen', items)
        self.assertIn('CACHE.gen++', pal)
        js = src('certs.js')
        aw = js[js.index('function afterWrite(path)'):js.index('function looksMissing(')]
        self.assertIn('ACME_PALETTE.refresh()', aw)

    def test_show_in_clears_other_filters(self):
        js = src('ctxmenu.js')
        ev = js[js.index('CX.showEvents = function'):js.index('CX.showJobs = function')]
        self.assertIn("getElementById('ev-kind')", ev)
        jb = js[js.index('CX.showJobs = function'):js.index('function rowMenu(')]
        self.assertIn("['jb-kind', 'jb-ok']", jb)

    def test_columns_other_tabs(self):
        js = src('cols.js')
        self.assertIn("then(colsTellTabs, function (e)", js)
        self.assertIn("e.key !== COLS_TABS_KEY", js)
        for m in re.finditer(r'localStorage\.\w+\(', js):
            self.assertIn('try', js[max(0, m.start() - 120):m.start()])
        self.assertNotIn('ctxmenu', js)       # test_f138_ctxmenu: cols.js knows nothing of it


class Pages(RP.Pages):
    test_pages = None

    @classmethod
    def setUpClass(cls):
        RP.Pages.setUpClass.__func__(cls)
        m = cls.must
        for i in range(64):
            m('POST', '/api/certs/save', {'name': 'bulk%02d' % i, 'names': ['b%02d.example.test' % i],
                                          'issuer': 'self', 'key_type': 'ec-256', 'auto_renew': 0})
        got = m('POST', '/api/certs/save', {'name': 'worked', 'names': ['worked.example.test'],
                                            'issuer': 'self', 'key_type': 'ec-256', 'auto_renew': 0})
        m('POST', '/api/certs/renew', {'id': got['id'], 'force': True})
        end = time.time() + 60
        while time.time() < end:
            jobs = m('GET', '/api/certs/jobs', args={'cert_id': got['id']})
            rows = jobs.get('rows') or jobs.get('jobs') or []
            if rows and all(j.get('state') not in ('queued', 'running') for j in rows):
                break
            time.sleep(1)
        cls.worked = got['id']

    def test_pages_rw1(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rw1_ui_page.js'), base, self.pw,
                                  SHOTS], capture_output=True, text=True, timeout=1500, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 4)
        for r in seen['runs']:
            tag = '%s %s' % (r['lang'], r['w'])
            # the second page: the deleted one gone at once, the count one less
            self.assertTrue(r['victim'], tag)
            self.assertNotIn(r['victim'], r['afterDelete'], (tag, r['afterDelete']))
            n0 = int(re.sub(r'\D', '', r['page2Said']))
            self.assertEqual(int(re.sub(r'\D', '', r['afterSaid'])), n0 - 1, (tag, r['afterSaid']))
            # picked on Certificates: nothing picked on another tab, picked again back
            self.assertEqual(r['dockCerts'], {'sel': True, 'acts': True}, tag)
            self.assertEqual(r['dockTargets'], {'sel': False, 'acts': False}, tag)
            self.assertEqual(r['dockSettings'], {'sel': False, 'acts': False}, tag)
            self.assertEqual(r['dockBack'], {'sel': True, 'acts': True}, tag)
            # Ctrl+K: the new name found, the old and the deleted one not offered
            names = r['names']
            self.assertIn(names['old'], r['palBefore'], tag)
            self.assertNotIn(names['old'], r['palOld'], (tag, r['palOld']))
            self.assertIn(names['ren'], r['palNew'], (tag, r['palNew']))
            self.assertNotIn(names['del'], r['palDeleted'], (tag, r['palDeleted']))
            # Show in Jobs / Events: the other filters cleared, the certificate's rows there
            self.assertIs(r['jobsMenu'], True, (tag, r['jobsMenu']))
            self.assertEqual((r['jobs']['ok'], r['jobs']['kind'], r['jobs']['cert']),
                             ('', '', str(self.worked)), tag)
            self.assertGreater(r['jobs']['rows'], 0, tag)
            self.assertIs(r['eventsMenu'], True, (tag, r['eventsMenu']))
            self.assertEqual(r['events']['kind'], '', tag)
            self.assertIn('worked', r['events']['q'], tag)
            self.assertGreater(r['events']['rows'], 0, tag)
            self.assertEqual(r['hs'], 0, tag)
        one = seen['runs'][0]
        self.assertIn(one['twoGone'], one['twoBefore'])
        self.assertNotIn(one['twoGone'], one['twoAfter'], one['twoAfter'])
        self.assertIn(one['colsA'], one['colsKept'], one)
        self.assertIn(one['colsB'], one['colsKept'], one)


if __name__ == '__main__':
    unittest.main(verbosity=2)
