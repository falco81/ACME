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
            # Every label (the small capitals) and the title, not what is written as it is;
            # in the pictures of one sign-in only (1.0.41) every word drawn but what is
            # marked as written as it is (data-no-i18n: names, files, addresses).
            if n in E.ART_ONLY:
                words = [w for attrs, w in re.findall(r'<text([^>]*)>([^<]+)</text>', svg)
                         if 'data-no-i18n' not in attrs]
            else:
                words = re.findall(r'<text class="lbl"[^>]*>([^<]+)</text>', svg)
            words += re.findall(r'<title id="sa-title">([^<]+)</title>', svg)
            for w in words:
                if not re.search('[A-Za-z]{2}', w) or w in ('ACME',):
                    continue
                self.assertTrue(w in have, '%s: "%s" has no Czech' % (n, w))

    def test_saved_on_both_pages(self):
        store = E.Storage(E.open_db())
        for n in DRAWN:
            for slot in ('portal', 'admin'):
                if E.ART_ONLY.get(n, slot) != slot:
                    continue
                E.art_set(store, slot, n)
                self.assertEqual(E.art_state(store, slot)['art'], n)

    # ---- the pictures of one sign-in only (1.0.41) ----------------------------------
    def test_the_same_only_both_sides(self):
        only = dict(re.findall(r"'(\w+)'\s*=>\s*'(portal|admin)'",
                               re.search(r'const ACME_ART_ONLY = \[(.*?)\];', ART_PHP, re.S).group(1)))
        self.assertEqual(only, E.ART_ONLY)
        self.assertEqual(sum(1 for v in only.values() if v == 'portal'), 5)
        self.assertEqual(sum(1 for v in only.values() if v == 'admin'), 5)
        for n in only:
            self.assertIn(n, DRAWN, n)
        # The ten there were stay for both.
        for n in ('cert', 'chain', 'renew', 'deploy', 'order', 'dns', 'keys', 'watch', 'revoke',
                  'cycle'):
            self.assertNotIn(n, only, n)

    def test_the_other_ones_refused(self):
        store = E.Storage(E.open_db())
        for n, slot in E.ART_ONLY.items():
            other = 'admin' if slot == 'portal' else 'portal'
            E.art_set(store, slot, n)
            self.assertEqual(E.art_read(store, slot)['art'], n)
            with self.assertRaises(ValueError) as got:
                E.art_set(store, other, n)
            self.assertIn('only', str(got.exception))
            self.assertNotEqual(E.art_read(store, other)['art'], n)

    def test_the_messages_in_czech(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = json.load(f)
        have = {v['source'] for v in cs['strings'].values()}
        for slot in ('portal', 'admin'):
            n = next(k for k, v in E.ART_ONLY.items() if v != slot)
            try:
                E.art_set(E.Storage(E.open_db()), slot, n)
            except ValueError as e:
                self.assertIn(str(e), have)

    def test_one_saved_for_the_wrong_page_shown_as_its_own(self):
        # Never saved so through the pages; a hand-made row is read as the page's own.
        store = E.Storage(E.open_db())
        store.set_meta('admin:art', json.dumps({'art': 'ask', 'sha': ''}))
        self.assertEqual(E.art_read(store, 'admin')['art'], 'deploy')
        code = ('function h($s){return htmlspecialchars((string)$s);} function acme_call(){return [404,""];}'
                'require %s; echo acme_art_for(["art" => "jobs"], "portal", "x");'
                % json.dumps(os.path.join(ROOT, 'web', 'acme-art.php')))
        svg = subprocess.run(['php', '-r', code], capture_output=True, text=True, timeout=30).stdout
        self.assertTrue(svg.startswith('<svg class="signart art-cert"'), svg[:60])

    def test_each_tab_offers_its_own(self):
        with open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8') as f:
            page = f.read()
        self.assertIn('data-for="<?= h(ACME_ART_ONLY[$a] ?? \'\') ?>"', page)
        with open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertIn("if (src.dataset['for'] && src.dataset['for'] !== slot) return;", js)


if __name__ == '__main__':
    unittest.main()
