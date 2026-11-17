#!/usr/bin/env python3
"""Bug hunt r7 (1.0.125): the Czech translation (web/lang/cs.json) and its machinery (i18n.js).

    python3 test/test_hunt_r7_i18n.py

- A number before a noun said the same word whatever the number: "zbývá 1 dní", "Přesunout
  1 tokenů", "vypršel před 1 dny", "1 neuložených změn bylo zahozeno", "poslední 2 dní",
  "úplný – 5 certifikáty". The patterns now say the word for the number ({0:one|2-4|5+}),
  the verb with it where it changes ("zbývají 3 dny", "3 tokeny přesunuty").
- Messages of the daemon that reach the pages (errors of the API) had no Czech, or came out
  half Czech: "klíč that came with it cannot be zapsán do ...", "a job is working on web1 -
  počkejte, až skončí", "not a backup z acme: ...". They have their translation now.
- i18n.js: a weak pattern ("{0} of {1}") took a slot of English words with "a" among them
  ("not a backup") for a name and said "not a backup z acme". "a" between two words is a
  sentence too: the text stays wholly English when nothing translates it whole.
- Untranslated or wrong: "Take every certificate of the mail server away" (said "adresáře the
  mail server"), the groups that may sign in to the portal, the import note, "signed out".
- The file itself: every {n} of a text is one of its source, each plural has 2 or 3 forms
  and is in a pattern (a plain string is never worked out), no value slot is lost.

In node (no browser) the translation of texts as i18n.js does it; in Chromium (Playwright),
when node and Playwright are here, a page in Czech drawing those texts.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LANG = os.path.join(ROOT, 'web', 'lang', 'cs.json')
SLOT = re.compile(r'\{(\d+)(?::[^}]*)?\}')

# the pack as acme-page.php's acme_lang_pack() cuts it, and i18n.js run on texts
NODE_HARNESS = r"""
const vm = require('vm'), fs = require('fs'), path = require('path');
const root = process.argv[2];
const all = JSON.parse(fs.readFileSync(path.join(root, 'web', 'lang', 'cs.json'), 'utf8'));
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
for (const s of JSON.parse(fs.readFileSync(process.argv[3], 'utf8'))) out[s] = ctx.i18nText(s);
console.log(JSON.stringify(out));
"""

PAGE = r"""
const { chromium } = require('playwright');
(async () => {
  const [html, texts] = process.argv.slice(2);
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const out = {errors: []};
  page.on('pageerror', e => out.errors.push(String(e.message || e)));
  await page.goto('file://' + html);
  await page.waitForTimeout(300);
  // drawn after the page is up, as the pages draw - the watcher translates them
  out.shown = await page.evaluate(async (list) => {
    const box = document.getElementById('box');
    list.forEach(t => { const p = document.createElement('p'); p.textContent = t; box.appendChild(p); });
    await new Promise(r => setTimeout(r, 200));
    return Array.from(box.children).map(p => p.textContent);
  }, JSON.parse(require('fs').readFileSync(texts, 'utf8')));
  out.lang = await page.evaluate(() => document.documentElement.getAttribute('lang'));
  console.log(JSON.stringify(out));
  await browser.close();
})().catch(e => { console.log(JSON.stringify({error: String(e.stack || e)})); process.exit(1); });
"""

# English as the pages get it -> what a Czech page must show
SAID = {
    'from the CA · 1 days left': 'od CA · zbývá 1 den',
    'from the CA · 3 days left': 'od CA · zbývají 3 dny',
    'from the CA · 12 days left': 'od CA · zbývá 12 dní',
    '3 days left': 'zbývají 3 dny',
    'Move 1 token(s) under @corp?': 'Přesunout 1 token pod @corp?',
    '3 token(s) moved under @corp': '3 tokeny přesunuty pod @corp',
    '7 token(s) moved under @corp': '7 tokenů přesunuto pod @corp',
    'expired 1 days ago': 'vypršel před 1 dnem',
    'last 2 days': 'poslední 2 dny',
    'last 7 days': 'posledních 7 dní',
    'by itself, 1 days before the end': 'automaticky, 1 den před koncem',
    'by itself, 30 days before the end': 'automaticky, 30 dní před koncem',
    'Deployed on 1 targets.': 'Nasazen na 1 cíli.',
    '1 thing(s) stand against switching it on.': 'Zapnutí brání 1 věc.',
    'makes 2 keys': 'vytváří 2 klíče',
    'complete - 3 certificates up to ISRG Root X1': 'úplný – 3 certifikáty až k ISRG Root X1',
    'complete - 5 certificates up to ISRG Root X1': 'úplný – 5 certifikátů až k ISRG Root X1',
    'this page is answered by acme2 now, not acme1 (the VIP address moved): the settings are '
    'drawn again from acme2; 1 change(s) not saved were put aside':
        'tuto stránku teď obsluhuje acme2, ne acme1 (VIP adresa se přesunula): nastavení se znovu '
        'načetla z acme2; 1 neuložená změna byla zahozena',
    # messages of the daemon
    'a job is working on web1 - wait for it to end': 'na web1 pracuje úloha – počkejte, až skončí',
    'the key that came with it cannot be written to /var/lib/acme/k - nothing was put back':
        'klíč, který s ní přišel, nelze zapsat do /var/lib/acme/k – nic se nevrátilo',
    "not a backup of acme: 'x.tar'": "není to záloha acme: 'x.tar'",
    'web1 is switched off - switch it on first': 'web1 je vypnutý – nejdřív ho zapněte',
    'Take every certificate of the mail server away': 'Odebrat všechny certifikáty mailového serveru',
    'signed out': 'odhlášeno',
}
# never half Czech, half English: wholly English when nothing says it whole
NOT_HALF = ['not a member of web1']


def node_ok():
    node = shutil.which('node')
    return node if node and subprocess.run([node, '-e', '1'], capture_output=True).returncode == 0 else None


class TheFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(LANG, encoding='utf-8') as f:
            cls.raw = f.read()
        cls.d = json.loads(cls.raw)

    def test_still_its_form(self):
        self.assertEqual(json.dumps(self.d, ensure_ascii=False, indent=1) + '\n', self.raw)
        for part in ('strings', 'patterns', 'rich'):
            for k, e in self.d[part].items():
                self.assertEqual(sorted(e), ['source', 'text'], k)

    def test_slots_of_every_text(self):
        bad = []
        for part in ('strings', 'patterns', 'rich'):
            for k, e in self.d[part].items():
                s, t = e['source'], e['text']
                if not t:
                    continue
                if not set(SLOT.findall(t)) <= set(SLOT.findall(s)):
                    bad.append('%s: a slot not in its source: %s' % (k, t))
                for m in re.finditer(r'\{(\d+):([^}]*)\}', t):
                    if len(m.group(2).split('|')) not in (2, 3):
                        bad.append('%s: plural of %d forms: %s' % (k, len(m.group(2).split('|')), t))
                if part == 'strings' and re.search(r'\{\d+:', t):
                    bad.append('%s: a plural in a plain string is shown as it is: %s' % (k, t))
                if part != 'strings':
                    for n in set(SLOT.findall(s)) - set(SLOT.findall(t)):
                        # only an ending glued to a word ("certificate{1}") may be left out
                        if not re.search(r'[A-Za-z]\{%s\}' % n, s):
                            bad.append('%s: {%s} lost: %s' % (k, n, t))
        self.assertEqual(bad, [], '\n'.join(bad))

    def test_no_english_copy_beside_a_translation(self):
        """The same source twice, once "translated" into itself (Login key)."""
        by = {}
        for k, e in self.d['strings'].items():
            by.setdefault(e['source'], []).append(e['text'])
        bad = [s for s, ts in by.items() if len(set(ts)) > 1 and s in ts]
        self.assertEqual(bad, [])

    def test_number_words_agree(self):
        p = self.d['patterns']
        for k in ('p0003', 'p0137', 'p1136', 'p1459', 'p0996', 'p0556', 'pchain_2', 'p1137'):
            self.assertRegex(p[k]['text'], r'\{\d+:[^}]*\|[^}]*\|[^}]*\}', k)


@unittest.skipUnless(node_ok(), 'no node here')
class Translated(unittest.TestCase):
    def said(self, texts):
        tmp = tempfile.mkdtemp()
        try:
            js, lst = os.path.join(tmp, 'h.js'), os.path.join(tmp, 't.json')
            with open(js, 'w') as f:
                f.write(NODE_HARNESS)
            with open(lst, 'w') as f:
                json.dump(texts, f)
            r = subprocess.run(['node', js, ROOT, lst], capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stderr)
            return json.loads(r.stdout)
        finally:
            shutil.rmtree(tmp)

    def test_czech(self):
        got = self.said(list(SAID) + NOT_HALF)
        for en, cs in SAID.items():
            self.assertEqual(got[en], cs, en)
        for en in NOT_HALF:
            self.assertIsNone(got[en], en)


@unittest.skipUnless(node_ok(), 'no node here')
class InTheBrowser(unittest.TestCase):
    def test_page(self):
        if subprocess.run(['node', '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        with open(LANG, encoding='utf-8') as f:
            d = json.load(f)
        pack = {'code': 'cs', 'strings': {}, 'patterns': [], 'rich': {}}
        for part in ('strings', 'patterns', 'rich'):
            for e in d[part].values():
                s, t = e['source'], e['text']
                if not s or not t or (t == s and part != 'patterns'):
                    continue
                if part == 'patterns':
                    pack['patterns'].append([s, t])
                else:
                    pack[part][s] = t
        tmp = tempfile.mkdtemp()
        try:
            html = os.path.join(tmp, 'p.html')
            with open(html, 'w', encoding='utf-8') as f:
                f.write('<!doctype html><html class="i18n-wait"><head><meta charset="utf-8">'
                        '<script>window.ACME_LANG_PACK = %s;</script>'
                        '<script src="file://%s"></script></head><body><div id="box"></div>'
                        '</body></html>' % (json.dumps(pack, ensure_ascii=False).replace('</', '<\\/'),
                                            os.path.join(ROOT, 'web', 'assets', 'i18n.js')))
            js, lst = os.path.join(tmp, 'p.js'), os.path.join(tmp, 't.json')
            with open(js, 'w') as f:
                f.write(PAGE)
            texts = list(SAID) + NOT_HALF
            with open(lst, 'w') as f:
                json.dump(texts, f)
            r = subprocess.run(['node', js, html, lst], capture_output=True, text=True, cwd=ROOT,
                               timeout=180)
            line = [x for x in r.stdout.splitlines() if x.startswith('{')]
            self.assertTrue(line, r.stdout + r.stderr)
            seen = json.loads(line[-1])
        finally:
            shutil.rmtree(tmp)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(seen['lang'], 'cs')
        shown = dict(zip(texts, seen['shown']))
        for en, cs in SAID.items():
            self.assertEqual(shown[en], cs, en)
        for en in NOT_HALF:
            self.assertEqual(shown[en], en)


if __name__ == '__main__':
    unittest.main(verbosity=2)
