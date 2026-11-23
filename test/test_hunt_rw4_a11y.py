#!/usr/bin/env python3
"""Hunt w4, area a11y: the administration and the portal with the keyboard and a screen reader.

    python3 test/test_hunt_rw4_a11y.py
    ACME_SHOTS=DIR     screenshots there
    ACME_RW4_CS=FILE   {English: Czech} merged into a copy of cs.json for the pages

- The toast of the administration and of the portal was no live region (only the sign-in page's,
  made by toast() itself): "saved", "refused: ..." were never heard. It is one from the start -
  polite, a refusal assertive.
- The popup (#modal-box) had no role: a screen reader read it as part of the page behind it, with
  no name. It is a dialog, modal, named by its title - the one on top of another as well.
- role="tab" without the arrow keys: the main tabs (and most rows of tabs) did nothing on Left,
  Right, Home or End. They move the focus along the row; Enter or Space opens a tab, as before.
- Boxes with no name: Events' kind, the mail test's two choices, the mail queue's state, an
  account's role, the firewall's networks, whose SSH keys, the proxy's address, DNS's choice per
  function, the team search - and any box with a placeholder drawn outside a popup.
- The dark page's grey (--tx-mut: the tables' headings, the tiles' labels, the header's time) was
  2.7-3.2:1 and the violet of a chip 3.9:1 - WCAG AA wants 4.5:1; a link no rule coloured was the
  browser's own blue, 1.5:1 (Settings -> High availability).
- The column menu (editing the columns) opened only on the right button: no Menu key or
  Shift+F10, no focus in it, no arrows, Escape left the focus nowhere.
- The settings' search: Escape on its list did nothing; a setting chosen with Enter left the focus
  on the list just hidden - Tab began again at the top of the page.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_f140_reports as RP  # noqa: E402  (its daemon, accounts, php -S)

SHOTS = os.environ.get('ACME_SHOTS', '')
CS = os.environ.get('ACME_RW4_CS', '')


def src(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def lum(hexc):
    c = [int(hexc[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def ratio(a, b):
    la, lb = lum(a), lum(b)
    return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)


class Source(unittest.TestCase):
    def test_toast_live(self):
        core = src('web/assets/core.js')
        body = core[core.index('function toast(words, kind)'):core.index('function toastAway()')]
        self.assertIn("node.setAttribute('aria-live', kind === 'bad' ? 'assertive' : 'polite')", body)
        self.assertIn("getElementById('toast')", body)        # made live at load, before any words
        for page in ('web/index.php', 'web/admin/index.php'):
            # other tests cut the page at this very tag: it stays as it is
            self.assertIn('<div class="toast" id="toast"></div>', src(page))
            # ...and core.js comes after it
            text = src(page)
            self.assertLess(text.index('id="toast"'), text.rindex('/assets/core.js'))

    def test_popup_dialog(self):
        for page in ('web/index.php', 'web/admin/index.php'):
            self.assertIn('id="modal-box" role="dialog" aria-modal="true" aria-labelledby="modal-title"',
                          src(page), page)
        core = src('web/assets/core.js')
        self.assertIn('id="modal-box" role="dialog" aria-modal="true" aria-labelledby="modal-title"', core)
        self.assertEqual(core.count('modalAria();'), 2)

    def test_tokens_aa(self):
        css = src('web/assets/acme.css')
        root = css[css.index(':root{'):css.index('*{box-sizing')]
        tok = dict(re.findall(r'--([\w-]+):(#[0-9a-fA-F]{6})', root))
        for bg in ('bg', 'panel', 'panel2'):
            self.assertGreaterEqual(ratio(tok['tx-mut'], tok[bg]), 4.5, bg)
            self.assertGreaterEqual(ratio(tok['tx-dim'], tok[bg]), 4.5, bg)
        self.assertIn(':where(a:link, a:visited){color:var(--info)}', css)
        # the violet words on their chip (--violet-bg: 14 % of it) on a panel
        v = tok['violet']
        bgv = re.search(r'--violet-bg:rgba\((\d+),(\d+),(\d+),([\d.]+)\)', root)
        rgb, a = [int(bgv.group(i)) for i in (1, 2, 3)], float(bgv.group(4))
        for bg in ('panel', 'panel2'):
            base = [int(tok[bg][i:i + 2], 16) for i in (1, 3, 5)]
            chip = '#' + ''.join('%02x' % round(c * a + b * (1 - a)) for c, b in zip(rgb, base))
            self.assertGreaterEqual(ratio(v, chip), 4.5, (bg, chip))

    def test_column_menu_keys(self):
        js = src('web/assets/cols.js')
        self.assertIn("e.key === 'ContextMenu' || (e.key === 'F10' && e.shiftKey)", js)
        self.assertIn("menu.addEventListener('keydown'", js)
        self.assertNotIn('ctxmenu', js)       # test_f138_ctxmenu: cols.js knows nothing of it
        for m in re.finditer(r'localStorage\.\w+\(', js):
            self.assertIn('try', js[max(0, m.start() - 120):m.start()])

    def test_named_boxes(self):
        adm = src('web/admin/index.php')
        for sel in ('<select id="ev-kind" aria-label="Kind">', '<select id="mq-state" aria-label="State">',
                    '<select id="mail-test-kind" aria-label="What to send">',
                    '<select id="mail-test-lang" aria-label="Language">'):
            self.assertIn(sel, adm)
        self.assertIn("sel.setAttribute('aria-label', p.title)", src('web/assets/dnssets.js'))
        self.assertIn('labelsFromPlaceholdersIn(n)', src('web/assets/core.js'))


class Pages(RP.Pages):
    test_pages = None

    @classmethod
    def setUpClass(cls):
        if CS and os.path.isfile(CS):
            os.environ['ACME_EXTRA_CS'] = CS
        RP.Pages.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_cert_suffixes': 'example.test', 'portal_cert_issuers': 'self'}})

    def test_pages_rw4(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rw4_a11y_page.js'), base, self.pw,
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
            self.assertEqual(r['toast0'], ['status', 'polite'], tag)
            self.assertEqual((r['toastBad'], r['toastGood']), ('assertive', 'polite'), tag)
            d = r['dialog']
            self.assertEqual(d['first'], ['dialog', 'true', 'First popup'], tag)
            self.assertEqual(d['second'], ['dialog', 'true', 'Second popup'], tag)
            self.assertEqual(d['under'], 'First popup', tag)
            self.assertEqual(d['back'], ['dialog', 'true', 'First popup'], tag)
            tabs = r['tabs']
            self.assertEqual((r['tabRight'], r['tabEnd'], r['tabWrap'], r['tabLeft'], r['tabHome']),
                             (tabs[1], tabs[-1], tabs[0], tabs[-1], tabs[0]), tag)
            self.assertTrue(r['stillOverview'], tag)          # the arrows move the focus only
            for k, v in r['ratios'].items():
                for one in (v if isinstance(v, list) else [v]):
                    if one is not None:
                        self.assertGreaterEqual(one, 4.5, (tag, k, v))
            self.assertTrue(r['ratios']['links'], tag)
            for where, boxes in r['unnamed'].items():
                self.assertEqual(boxes, [], (tag, where))
            if r['lang'] == 'cs':
                self.assertEqual(r['evKind'], 'Druh', tag)
                self.assertEqual(r['mailLabels'][1], 'Jazyk', tag)
                self.assertEqual(r['sshLabel'], 'Čí klíče', tag)
                if CS:
                    self.assertEqual(r['mailLabels'][0], 'Co poslat', tag)
            else:
                self.assertEqual(r['mailLabels'], ['What to send', 'Language'], tag)
                self.assertEqual(r['sshLabel'], 'Whose keys', tag)
            self.assertGreater(r['findHits'], 0, tag)
            self.assertTrue(r['findInList'], tag)
            self.assertEqual(r['findEsc'], ['ctl-find', True], tag)
            self.assertEqual(r['findChosen'], 'certs_renew_days', tag)
            if r['w'] > 1000:
                c = r['cols']
                self.assertTrue(c['open'] and not c['rowMenu'] and c['first'], (tag, c))
                self.assertEqual(c['moved'], 2, (tag, c))
                self.assertEqual(c['afterTick'], [True, c['at']], (tag, c))
                self.assertTrue(c['closed'] and c['back'], (tag, c))
                self.assertTrue(c['tabOut'] and c['tabBack'], (tag, c))
        self.assertEqual(len(seen['portal']), 4)
        for p in seen['portal']:
            tag = 'portal %s %s' % (p['lang'], p['w'])
            self.assertEqual(p['toast'], ['status', 'polite'], tag)
            self.assertEqual(p['dialog'], ['dialog', 'modal-title'], tag)
            if p['th'] is not None:
                self.assertGreaterEqual(p['th'], 4.5, tag)
            self.assertEqual(p['unnamed'], [], tag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
