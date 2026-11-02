#!/usr/bin/env python3
"""The pages, read without a browser: things that must never be in them.

    python3 test/test_pages_static.py

- no window.prompt / confirm / alert: every question is asked in acme's own
  popup (modal, confirmThen), in the look of the application - never in the
  browser's grey box.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE = re.compile(r'(?<![A-Za-z0-9_$.])(?:window\s*\.\s*)?(prompt|confirm|alert)\s*\(')


def page_files():
    for base in ('web',):
        for d, _dirs, files in os.walk(os.path.join(ROOT, base)):
            for f in files:
                if f.endswith(('.js', '.php', '.html')):
                    yield os.path.join(d, f)


class NoNativeDialogs(unittest.TestCase):
    def test_no_prompt_confirm_alert(self):
        found = []
        for path in page_files():
            with open(path, encoding='utf-8', errors='replace') as f:
                for n, line in enumerate(f, 1):
                    code = line.split('//', 1)[0]
                    for m in NATIVE.finditer(code):
                        found.append('%s:%d: %s' % (os.path.relpath(path, ROOT), n, m.group(0)))
        self.assertEqual(found, [], 'the browser\'s own dialogs - use modal() / confirmThen():\n'
                         + '\n'.join(found))



class PagesVersion(unittest.TestCase):
    """The pages say the version acme is, and key their assets' cache by it:
    otp's 1.0.209 stayed there, and browsers kept the old core.js and admin.js
    after every upgrade - new pages drawn by old scripts."""

    def test_page_version_is_acmelib_version(self):
        with open(os.path.join(ROOT, 'acmelib', '__init__.py'), encoding='utf-8') as f:
            want = re.search(r"^__version__ = '([^']+)'", f.read(), re.M).group(1)
        with open(os.path.join(ROOT, 'web', 'acme-page.php'), encoding='utf-8') as f:
            got = re.search(r"^const ACME_VERSION = '([^']+)';", f.read(), re.M).group(1)
        self.assertEqual(got, want)

    def test_every_script_and_style_keyed_by_its_file(self):
        bare = []
        for path in page_files():
            if not path.endswith('.php'):
                continue
            with open(path, encoding='utf-8') as f:
                for n, line in enumerate(f, 1):
                    if re.search(r'/assets/[\w.-]+\.(js|css)\?v=<\?= h\(ACME_VERSION\) \?>', line):
                        bare.append('%s:%d' % (os.path.relpath(path, ROOT), n))
        self.assertEqual(bare, [], 'assets keyed by the version alone: ' + ', '.join(bare))


class HintsOfDataBoxes(unittest.TestCase):
    """A box marked as data (noI18n) is skipped whole by i18n.js - its hint too:
    "the first name", "set - leave empty to keep it", "choose one…" stayed English
    on a Czech page (1.0.19). Such a hint in words goes through tr()."""

    BOX = re.compile(r"(?:textBox|secretBox|areaBox|maskBox)\([^,]*,\s*'((?:[^'\\]|\\.)*)'")
    SEL = re.compile(r"selectBox\(\[\['[^']*',\s*'((?:[^'\\]|\\.)*)'\]")

    def test_hints_of_data_boxes_are_translated(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            pack = json.load(f)
        known = {x.get('source') for x in pack['strings'].values() if isinstance(x, dict)}
        found = []
        for name in ('certs.js', 'deployfiles.js', 'teams.js'):
            path = os.path.join(ROOT, 'web', 'assets', name)
            with open(path, encoding='utf-8') as f:
                lines = f.read().split('\n')
            for n, line in enumerate(lines):
                m = re.search(r'noI18n\(([\w.]+)\)', line)
                if not m:
                    continue
                var = re.escape(m.group(1))
                for back in range(1, 4):
                    made = lines[n - back] if n - back >= 0 else ''
                    if not re.search(r'(?<![\w.])' + var + r'\s*=', made):
                        continue
                    for rx in (self.BOX, self.SEL):
                        for hint in rx.findall(made):
                            words = hint.replace("\\'", "'")
                            if words in known and (' ' in words or words == 'default'):
                                found.append('%s:%d: %s' % (name, n + 1 - back, words))
                    break
        self.assertEqual(found, [], 'English hints of boxes marked as data - tr() them:\n'
                         + '\n'.join(found))


class PopupStack(unittest.TestCase):
    """The popup over a popup (core.js) in a browser: a question answered by
    opening the job's log over the certificate keeps the log on top - the
    certificate drawn afresh took its place, and the log was lost (1.0.19)."""

    def test_opened_after_a_close_stays_on_top(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(ROOT, 'test', 'modal_stack_page.js'),
                              os.path.join(ROOT, 'web', 'assets', 'core.js')],
                             capture_output=True, text=True, timeout=120)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


class ExplainSpoken(unittest.TestCase):
    """What explain() puts in aria-label in the page's language (core.js with
    i18n.js, in a browser): a setting's help with <i> or <code> in it is among
    the rich translations only, and stayed English to a screen reader (1.0.19)."""

    def test_rich_help_translated(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(ROOT, 'test', 'explain_aria_page.js'),
                              os.path.join(ROOT, 'web', 'assets')],
                             capture_output=True, text=True, timeout=120)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


class SavedWithTheBar(unittest.TestCase):
    def test_role_waits_for_the_save_bar(self):
        """An account's role in Settings → Accounts was given the moment the
        select changed (1.0.19): it waits for Save as every other change."""
        js = read('web', 'assets', 'admin.js')
        self.assertNotRegex(js, r"role\.onchange = function \(\) \{ userDo\(")
        self.assertIn("pendingSet(rkey, {pane: 'people', role: want", js)


class SteadyNarrow(unittest.TestCase):
    """Steady columns (core.js) in a box narrower than the list, in a browser: the
    list keeps its own width and scrolls in its box - the tags of one cell lay over
    the next at 390 px (Settings → Upgrades, 1.0.19)."""

    def test_list_wider_than_its_box(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          timeout=60).returncode:
            self.skipTest('no playwright for node here')
        got = subprocess.run([node, os.path.join(ROOT, 'test', 'steady_narrow_page.js'),
                              os.path.join(ROOT, 'web', 'assets', 'core.js')],
                             capture_output=True, text=True, timeout=120)
        out = json.loads((got.stdout.strip().splitlines() or ['{}'])[-1])
        self.assertTrue(out.get('ok'), json.dumps(out) + got.stderr[-2000:])


class Phone(unittest.TestCase):
    def test_node_cards_fit_a_phone(self):
        """Settings → Time scrolled sideways at 390 px: its cards were 520 px at
        least (1.0.19). The columns of node cards are never wider than the page."""
        css = read('web', 'assets', 'acme.css')
        self.assertIn('#ntp-host .pw-grid{grid-template-columns:repeat(auto-fill,'
                      'minmax(min(520px,100%),1fr))}', css)
        self.assertIn('.pw-grid{grid-template-columns:repeat(auto-fill,'
                      'minmax(min(360px,100%),1fr))}', css)


if __name__ == '__main__':
    sys.exit(unittest.main())
