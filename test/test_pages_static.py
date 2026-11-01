#!/usr/bin/env python3
"""The pages, read without a browser: things that must never be in them.

    python3 test/test_pages_static.py

- no window.prompt / confirm / alert: every question is asked in acme's own
  popup (modal, confirmThen), in the look of the application - never in the
  browser's grey box.
"""
import os
import re
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


if __name__ == '__main__':
    sys.exit(unittest.main())


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
