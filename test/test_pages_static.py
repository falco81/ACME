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
