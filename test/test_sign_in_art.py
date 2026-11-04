#!/usr/bin/env python3
"""The pictures of the sign-in (web/acme-art.php) and the names the daemon takes (1.0.41).

    python3 test/test_sign_in_art.py

The pages and the daemon list the same pictures (a name only one of them knows is
either never offered or refused when saved); every drawing is drawn, of the same
size as the others, says what it is (its title) and has its words in Czech.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-art-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

with open(os.path.join(ROOT, 'web', 'acme-art.php'), encoding='utf-8') as f:
    ART_PHP = f.read()
PHP_NAMES = re.findall(r"'(\w+)'", re.search(r'const ACME_ARTS = \[(.*?)\];', ART_PHP, re.S).group(1))
DRAWN = [n for n in PHP_NAMES if n not in ('none', 'custom')]


def drawn(name):
    code = ('function h($s){return htmlspecialchars((string)$s);} function acme_call(){return [404,""];}'
            'require %s; echo acme_art_svg(%s);' % (json.dumps(os.path.join(ROOT, 'web', 'acme-art.php')),
                                                    json.dumps(name)))
    return subprocess.run(['php', '-r', code], capture_output=True, text=True, timeout=30).stdout


@unittest.skipUnless(shutil.which('php'), 'no php here')
class Art(unittest.TestCase):
    def test_the_same_names_both_sides(self):
        self.assertEqual(PHP_NAMES, list(E.ART_NAMES))

    def test_every_one_has_its_words(self):
        words = re.search(r'const ACME_ART_WORDS = \[(.*?)\];', ART_PHP, re.S).group(1)
        for n in PHP_NAMES:
            self.assertIn("'%s'" % n, words, n)

    def test_every_one_drawn(self):
        for n in DRAWN:
            svg = drawn(n)
            self.assertTrue(svg.startswith('<svg class="signart art-%s" viewBox="0 0 420 188"' % n), n)
            self.assertIn('<title id="sa-title">', svg, n)
            self.assertTrue(svg.endswith('</svg>'), n)

    def test_their_words_in_czech(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = json.load(f)
        have = {v['source'] for sec in ('strings', 'patterns') for v in cs[sec].values()}
        for n in DRAWN:
            svg = drawn(n)
            # Every label (the small capitals) and the title, not what is written as it is.
            words = re.findall(r'<text class="lbl"[^>]*>([^<]+)</text>', svg)
            words += re.findall(r'<title id="sa-title">([^<]+)</title>', svg)
            for w in words:
                if not re.search('[A-Za-z]{2}', w) or w in ('ACME',):
                    continue
                self.assertIn(w, have, '%s: "%s" has no Czech' % (n, w))

    def test_saved_on_both_pages(self):
        store = E.Storage(E.open_db())
        for n in DRAWN:
            for slot in ('portal', 'admin'):
                E.art_set(store, slot, n)
                self.assertEqual(E.art_state(store, slot)['art'], n)


if __name__ == '__main__':
    unittest.main()
