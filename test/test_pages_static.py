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


class DeviceKeyRound1e(unittest.TestCase):
    """What the UI bug hunt of the versions and the device-made key found (round 1e)."""

    def test_version_labels_in_the_page_language(self):
        core = read('web', 'assets', 'core.js')
        certs = read('web', 'assets', 'certs.js')
        guides = read('web', 'assets', 'guides.js')
        self.assertIn('function versionWords(v)', core)
        # drawn as data, so translated before: the picker, the module's version rows, the guide
        self.assertIn("data('span', 'md-vcard-l', versionWords(v) || v.title || '')", certs)
        self.assertIn("t.appendChild(data('span', 'muted', ' · ' + versionWords(v)))", certs)
        self.assertIn("versionWords(v) || v.version || tr('plain')", guides)
        for src in (certs, guides, read('web', 'assets', 'guides-editor.js')):
            self.assertNotRegex(src, r"(data\('[a-z]+', '[^']*', |, )v\.version_label \|\|")
        # the plain version of a module that says nothing: "any version"
        node = shutil.which('node')
        if node:
            fn = re.search(r'\nfunction versionWords[\s\S]*?\n}\n', core).group(0)
            js = ('function known(x) { return x === "any version" ? "jakákoli verze" : x; }' + fn +
                  'console.log(JSON.stringify([versionWords({version: ""}), versionWords({version: "8.0.2"}),'
                  ' versionWords({version: "", version_label: "X 1"})]));')
            got = subprocess.run([node, '-e', js], capture_output=True, text=True, timeout=60)
            self.assertEqual(json.loads(got.stdout), ['jakákoli verze', '', 'X 1'], got.stderr)

    def test_modules_filter_by_version(self):
        certs = read('web', 'assets', 'certs.js')
        self.assertIn("version: mdVersionWords(p),", certs)
        self.assertIn("'version:9.10'", certs)
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        fn = re.search(r'\nfunction mdVersionWords[\s\S]*?\n}\n', certs).group(0)
        js = ('function arr(x) { return Array.isArray(x) ? x : []; } function tr(x) { return x; }' + fn +
              'console.log(JSON.stringify(mdVersionWords({versions: [{version: ""}, {version: "9.10",'
              ' version_label: "ONTAP 9.10.1 - 9.19"}]})));')
        got = subprocess.run([node, '-e', js], capture_output=True, text=True, timeout=60)
        out = json.loads(got.stdout)
        for want in ('plain', '9.10', '9.10.1', '9.19'):
            self.assertIn(want, out)

    def test_what_happens_for_a_device_key(self):
        rp = read('web', 'assets', 'runplan.js')
        self.assertIn("ph.key === 'key' && cert && cert.csr_from ? LEDE_DEVICE_KEY", rp)
        self.assertIn("phaseBlock(ph, i + 1, p.cert)", rp)
        self.assertIn("kd.appendChild(el('span', '', 'key made by'));", rp)
        # a decimal comma in Czech
        self.assertIn("numDecimal() === ',') took = took.replace('.', ',')", rp)

    def test_the_wizard_and_the_deployment(self):
        certs = read('web', 'assets', 'certs.js')
        # back to "Key made by the device": the device given or picked last, not the first
        self.assertNotIn("W.d.csr_from = o[0] ? (W.d.csr_from || (devs[0] || {}).name || '') : '';", certs)
        self.assertIn("[W.devLast, opts.csrFrom, c.csr_from]", certs)
        self.assertIn("W.d.csr_from = W.devLast = dsel.value;", certs)
        # "acme, here" on a certificate deployed to its device: said in the key step
        self.assertIn("rowsOf(obj(detail).deploys).some(function (r) { return r.target === c.csr_from; })", certs)
        # Deploy it on a target: its device only, or no device that makes its own key
        self.assertIn("return csrFrom ? (t.name === csrFrom && !depHas[t.name]) : !devKeyOf(t);", certs)
        self.assertIn("return !x.csr_from || (x.csr_from === tName && !haveHere[String(x.id)]);", certs)
        # no deployment to the device: said
        self.assertIn("it has no deployment to {0}, whose device makes its key", certs)
        # not the default target
        self.assertIn('function targetDefaultable(t)', certs)
        self.assertNotIn("(key !== 'targets' || deployable(r))", certs)
        # a key tile that cannot be chosen is not "recommended"; off tiles look off
        self.assertIn("if (rec) rec.hidden = !k.ok;", certs)
        css = read('web', 'assets', 'certs.css')
        self.assertIn('.ct-src.off,.ct-keyt.off{opacity:.45;cursor:not-allowed;border-style:dashed', css)
        self.assertIn('.ct-src.off.on,.ct-keyt.off.on{border-color:var(--line)}', css)

    def test_round_2c(self):
        certs = read('web', 'assets', 'certs.js')
        # 1: the device it is deployed to not offered again; every deployment there looked at
        self.assertIn("if (MANAGE && !devDone) {", certs)
        self.assertIn("var devOn = devDeps.some(", certs)
        self.assertNotIn("var devDep = arr(deploys).filter(function (d) { return d.target === c.csr_from; })[0];", certs)
        # 3: where its key is made changed - issued anew right after Save, no question after
        self.assertIn("var devSwitched = function () {", certs)
        self.assertIn("inCert(sent) !== inCert(c) && !devSwitched();", certs)
        self.assertIn("note warn tm-devswitch", certs)
        # 4: a device taken by another certificate shown, not chosen; deployed elsewhere said
        self.assertIn("var devTaken = function (t)", certs)
        self.assertIn("if (tt && devTaken(tt) && op.value !== W.d.csr_from) op.disabled = true;", certs)
        self.assertIn("note warn ct-develse", certs)
        self.assertIn("var keyOf = r.key_of ||", certs)
        # 5: what the device takes, said where the device is chosen
        self.assertIn("(devPlug(devOf()) || {}).device_key_names", certs)
        # 6: an auto-made test's note as a translated hint, kept as it is
        self.assertIn("note: autoNote && note.value === '' ? autoNote : note.value", certs)
        self.assertIn("autoNote ? tr(autoNote) : ''", certs)
        # 8: the device's deployment saved by certs/save with its options, not again
        self.assertIn("if (devT) sent.deploy_options = W.deploys[devT];", certs)
        self.assertIn("filter(function (t) { return !skip[t]; })", certs)
        # 9: the shipped original's version words; the tests that go with a certificate
        self.assertIn("/* its words too, as the row of its replacement above has them (1.0.96) */", certs)
        self.assertIn("The tests acme made from its deployments go with it", certs)


class FinalSweep3b(unittest.TestCase):
    """What the final UI sweep (round 3b) found in the wizard, the Deploy dialog and the
    Modules page."""

    def node_js(self, js):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        got = subprocess.run([node, '-e', js], capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        return json.loads(got.stdout)

    def test_form_check_holds_min_and_max(self):
        certs = read('web', 'assets', 'certs.js')
        self.assertIn("' is ' + lo + ' at least (not ' + v + ')'", certs)
        self.assertIn("' is ' + hi + ' at most (not ' + v + ')'", certs)
        # a value kept as saved is not asked again, as the daemon does
        self.assertIn("var was = opts.kept && Object.prototype.hasOwnProperty.call(opts.kept, it.f.key)", certs)
        self.assertIn("kept: d.id && t.name === d.target ? obj(d.options) : null", certs)
        # the required one in words for any label (no "Grid members is needed")
        self.assertIn("bad = 'fill in \\u201c' + tr(it.f.label || it.f.key) + '\\u201d';", certs)
        self.assertNotIn("tr(it.f.label || it.f.key) + ' is needed'", certs)

    def test_refusal_marks_its_field_in_the_page_language(self):
        certs = read('web', 'assets', 'certs.js')
        fn = re.search(r'\n    refused: function \(words\) \{[\s\S]*?\n      return msg;\n    \}', certs).group(0)
        js = ('var tr = function (x) { return {Bay: "Pozice", "Grid members": "Členové Gridu"}[x] || x; };'
              'function mk(f) { return {f: f, item: {classList: {s: {}, add: function (c) { this.s[c] = 1; },'
              ' remove: function (c) { delete this.s[c]; }}}, input: {focus: function () {}}}; }'
              'var items = [mk({key: "bay", label: "Bay"}), mk({key: "members", label: "Grid members"})];'
              'var more = {}; var shown = function () { return true; }; var current = function () { return {}; };'
              'var o = {' + fn.strip() + '};'
              'var a = o.refused("Bay is 2 at most (not 3)");'
              'var b = o.refused("fill in “Grid members”");'
              'console.log(JSON.stringify([a, !!items[0].item.classList.s.refused, b,'
              ' !!items[1].item.classList.s.refused, !!items[0].item.classList.s.refused]));')
        self.assertEqual(self.node_js(js), ['Pozice is 2 at most (not 3)', False,
                                            'fill in “Členové Gridu”', True, False])
        # used where the daemon refuses: the Deploy dialog and the wizard
        self.assertIn("if (form && form.refused && e && e.message) e.message = form.refused(e.message);", certs)
        self.assertIn("var why = f && f.refused ? f.refused(e.message) : e.message;", certs)

    def test_wizard_checks_the_deployments_before_saving(self):
        certs = read('web', 'assets', 'certs.js')
        fin = re.search(r'\n  function finish\(b, issue, hold\) \{[\s\S]*?capi\(\'certs/save\', sent\)', certs).group(0)
        self.assertIn("var dbad = dstep && dstep.check ? dstep.check() : '';", fin)
        self.assertIn("if (dbad) { backToDeploy(dbad); toast(dbad, 'bad'); return; }", fin)
        # refused after the save: said, and the wizard back on the deployment step
        self.assertIn("backToDeploy(e.message, e.deployOf, e.raw);", certs)
        self.assertIn("'The certificate is saved, but its deployment to ' + W.depRefused.target", certs)
        # the wizard's deployment step leaves out "Check what is served" as the Deploy dialog does
        self.assertIn("(!x.dual_only || W.d.key_type_alt) && VERIFY_KEYS.indexOf(x.key) < 0", certs)

    def test_deploy_asks_for_the_target_before_the_confirmation(self):
        core = read('web', 'assets', 'core.js')
        certs = read('web', 'assets', 'certs.js')
        act = re.search(r"if \(b\.act && b\.go && !b\.once\) \{[\s\S]*?var strip", core).group(0)
        self.assertIn("if (typeof b.ready === 'function' && b.ready(button) === false) return;", act)
        self.assertIn("buttons.push({words: 'Save and deploy now', cls: 'primary', icon: 'deploy', ready: ready,", certs)

    def test_toast_above_the_popup_buttons(self):
        core = read('web', 'assets', 'core.js')
        fn = re.search(r'\nfunction toast\(words, kind\) \{[\s\S]*?\n\}\n', core).group(0)
        self.assertIn("foot.getBoundingClientRect().top", fn)
        self.assertIn("node.style.bottom =", fn)

    def test_long_choices_are_not_cut(self):
        certs = read('web', 'assets', 'certs.js')
        self.assertIn("if (pairs.some(function (p) { return String(p[1] || '').length > 32; })) wide = true;", certs)

    def test_version_filter_inside_ranges(self):
        core = read('web', 'assets', 'core.js')
        certs = read('web', 'assets', 'certs.js')
        g = lambda src, rx: re.search(rx, src).group(0)
        js = ('function arr(x) { return Array.isArray(x) ? x : []; } function tr(x) { return x; }'
              + g(certs, r'\nfunction mdVersionWords[\s\S]*?\n}\n') + g(core, r'\nfunction qVerCmp[\s\S]*?\n}\n')
              + g(core, r'\nfunction qWild[\s\S]*?\n}\n') + g(core, r'\nfunction qOneMatch[\s\S]*?\n}\n')
              + 'var P = {ontap: {versions: [{version: ""}, {version: "9.10", version_label: "ONTAP 9.10.1 - 9.19"}]},'
              ' iosxe: {versions: [{version: "17.12", version_label: "IOS XE 17.12 - 26.1"}]},'
              ' aria: {description: "Aria Automation and Automation Orchestrator 8.18: sets the ingress"},'
              ' syn: {version_label: "OneView for Synergy 9.x - 11.x (detects the API)"}};'
              'var out = {}; Object.keys(P).forEach(function (k) { var w = mdVersionWords(P[k]);'
              ' out[k] = ["9.15", "17.15", "8.18", "9.10", "9.9", "26.2", "10.2"].filter(function (q) {'
              ' return qOneMatch("text", ":", q, w, "version"); }); });'
              'console.log(JSON.stringify(out));')
        self.assertEqual(self.node_js(js), {'ontap': ['9.15', '9.10'], 'iosxe': ['17.15'],
                                            'aria': ['8.18'], 'syn': ['9.15', '9.10', '9.9', '10.2']})



class OwnPasswordAndSshRoot(unittest.TestCase):
    """One's own new password in one form everywhere (1.0.98), and AllowUsers without root
    saved only when asked for in the page's own question."""

    def node_js(self, js):
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        got = subprocess.run([node, '-e', js], capture_output=True, text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        return json.loads(got.stdout)

    def test_one_form_wherever_a_person_changes_their_own(self):
        core = read('web', 'assets', 'core.js')
        admin = read('web', 'assets', 'admin.js')
        portal = read('web', 'assets', 'portal.js')
        form = re.search(r'\nfunction pwChangeForm\(host, o\) \{[\s\S]*?\n\}\n', core).group(0)
        # three boxes, each with its eye; the hints; the button only when all is right; Enter
        for words in ("maskEye(old)", "maskEye(nw)", "maskEye(again)", "'At least ' + PW_MIN + ' characters'",
                      "'Not the same as the one you have now'", "'The same as the new one'",
                      "go.disabled = working || !ready;", "if (e.key !== 'Enter') return;",
                      "busy(go, true);", "said.textContent = String((e && e.message) || e);",
                      "again: again.value"):
            self.assertIn(words, form)
        # the rules of these accounts, as password_problem has them
        small = read('acmelib', 'engine', '020_small_things_said_once.py')
        self.assertIn("var PW_MIN = 8, PW_MAX = 200;", core)
        self.assertIn("if len(p) < 8:", small)
        self.assertIn("if len(p) > 200:", small)
        # Your account, the password to choose first, the enrolment pages: that form
        me = re.search(r'\nfunction showMe\(\) \{[\s\S]*?\n\}\n', admin).group(0)
        must = re.search(r'\nfunction mustChange\(\) \{[\s\S]*?\n\}\n', admin).group(0)
        pf = re.search(r'\nfunction passwordForm\(host, first, done\) \{[\s\S]*?\n\}\n', portal).group(0)
        for fn in (me, must, pf):
            self.assertIn('pwChangeForm(', fn)
            self.assertNotIn('maskBox(', fn)
            self.assertNotIn('secretBox(', fn)
        # an administrator typing one in: twice, sent twice
        self.assertIn("password: v[0], again: v[1], must_change: 1", admin)
        self.assertIn("password: pw.value, again: pw2.value", admin)
        self.assertIn("var shown = f.type === 'password' ? maskEye(input) : input;", admin)
        # the daemon takes "again"
        self.assertIn("'old', 'new', 'again'", read('acmelib', 'engine', '345_the_api_the_web.py'))
        self.assertIn("bad = password_change_problem(b)", read('acmelib', 'engine', '355_editing_the_columns_switched.py'))
        self.assertIn("bad = password_change_problem(b)", read('acmelib', 'engine', '390_the_portal_sign_in.py'))

    def test_eye_shows_and_hides(self):
        core = read('web', 'assets', 'core.js')
        self.assertIn("i._hide = function () {", core)
        eye = re.search(r'\nfunction maskEye\(box\) \{[\s\S]*?\n\}\n', core).group(0)
        self.assertIn("iconMarkup(open ? 'eyeoff' : 'eye', 16)", eye)
        self.assertIn("wrap._input = box;", eye)
        self.assertIn("eyeoff: ", core)

    def test_ssh_root_left_out_asked_first(self):
        admin = read('web', 'assets', 'admin.js')
        core = read('web', 'assets', 'core.js')
        save = re.search(r'\nfunction sdSave\(\) \{[\s\S]*?\n\}\n', admin).group(0)
        self.assertIn("modalSure('Root will not be able to sign in over SSH while it is not among these accounts - save anyway?'", save)
        self.assertIn("conf.ok_no_root = true;", save)
        self.assertIn("function () { resolve(false); }", save)
        # the question over the page when no popup is open
        sure = re.search(r'\nfunction modalSure\(words, go, yesWords, noGo\) \{[\s\S]*?\n\}\n', core).group(0)
        self.assertIn("var onPage = !pop || pop.hidden;", sure)
        self.assertIn(".gd-sure.on-page", read('web', 'assets', 'acme.css'))
        # said in the pane, the node cards and SSH keys
        self.assertIn("'Root cannot sign in over SSH'", admin)
        self.assertEqual(admin.count("'no - not in AllowUsers'"), 2)
        fn = re.search(r'\nfunction sdRootListed\(users\) \{[\s\S]*?\n\}\n', admin).group(0)
        got = self.node_js(fn + 'console.log(JSON.stringify([[], ["jan"], ["jan", "root"], ["r*"], '
                           '"jan root@10.0.0.*", "jan ro", ["ro?t"], ["a.b"]].map(sdRootListed)));')
        self.assertEqual(got, [True, False, True, True, True, False, True, False])


class WhatHappensLayout(unittest.TestCase):
    """What happens (runplan.js/css), checked in a browser at 1400/768/420 px: the fixes kept."""

    def test_copy_buttons_and_lines_line_up(self):
        css = read('web', 'assets', 'runplan.css')
        # every copy button 6 px from its box's edges: the http line's padding, the code block's place
        self.assertIn('.rp-code .rp-copy{position:absolute;top:5px;right:5px}', css)
        self.assertIn('align-items:flex-start;min-width:0;padding:5px;', css)
        # a code block with no heading as tall as an http line: its copy button not on its edge
        self.assertIn('.rp-code > pre:first-child{box-sizing:border-box;min-height:42px;', css)
        # a long address wraps under the buttons, which stay at the top
        self.assertIn('.rp-method{flex:none;font:700 11px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:5px 7px;margin-top:5.5px;', css)
        # one gap in a column: no extra margins of the chips or a folded part
        self.assertIn('.rp-conn{display:flex;flex-wrap:wrap;gap:6px;margin:0}', css)
        self.assertIn('.rp-withconn{display:flex;flex-direction:column;gap:6px;min-width:0}', css)
        self.assertNotIn('.rp-raw{margin-top:6px}', css)
        self.assertIn('.rp-more{margin:4px 10px 10px;', css)

    def test_numbers_in_one_column(self):
        rp = read('web', 'assets', 'runplan.js')
        css = read('web', 'assets', 'runplan.css')
        self.assertIn("box.style.setProperty('--rp-nw', widest + 'ch');", rp)
        self.assertIn('min-width:max(34px,var(--rp-nw,0px))', css)
        # on a phone the number stays beside the words, the tags go under the words
        self.assertNotIn('flex:1 1 calc(100% - 40px)', css)
        self.assertIn('padding-left:calc(max(34px,var(--rp-nw,0px)) + 10px)', css)

    def test_tables_wrap_inside_the_page(self):
        css = read('web', 'assets', 'runplan.css')
        # a facts value (table td > span.mono is nowrap in acme.css): 2958 px wide before
        self.assertIn('.rp-page .rp-val,.rp-page td > .rp-val{white-space:pre-wrap;', css)
        self.assertNotIn('word-break:break-all;white-space:normal}}', css)
        # the files: the path wraps, mode and size do not; a card a file on a phone
        self.assertIn('.rp-page table.rp-files td:first-child{width:auto;white-space:normal;', css)
        self.assertIn('.rp-page table.rp-files td:not(:first-child){white-space:nowrap}', css)
        self.assertIn('.rp-page table.rp-files thead{display:none}', css)
        # a long module name cut inside its station; the head's guide button wraps in its card
        self.assertIn('.rp-station-s .mono,.rp-station-s .rp-tag{overflow:hidden;text-overflow:ellipsis;', css)
        self.assertIn('.rp-mod .rp-guide{white-space:normal;max-width:100%;', css)
        self.assertIn('.rp-htab .rp-hk{width:25%;', css)

    def test_module_words_with_a_command_translated(self):
        rp = read('web', 'assets', 'runplan.js')
        self.assertIn("var SAID_CMD = /^(ran|test|reload|reload with the previous files)(:? )([\\s\\S]+)$/;", rp)
        self.assertIn("top.appendChild(st.said ? saidWords(st.words || '') : el('span', 'rp-words', masked(st.words || '')));", rp)
        # "< input (text, 52 B)" and the comment over a device's CLI lines in the page's language
        self.assertIn("'< ' + inputWords(d.input)", rp)
        self.assertIn("codeBlock(shellComment(d.command), 'rp-shell')", rp)
        self.assertIn("var CLI_HEAD = '# a shell session, these lines on its input:';", rp)
        self.assertIn("'# a shell session, these lines on its ' \\\n                            'input:\\n'",
                      read('acmelib', 'certs', 'runplan.py'))
        node = shutil.which('node')
        if not node:
            self.skipTest('no node here')
        pre = ("var CS={'ran {0}':'spušteno {0}','a password made for this run':'heslo pro tento běh'};"
               "function tr(w){return CS[w]||w;} function noI18n(n){n.ni=1;return n;}"
               "function el(k,c,t){return {k:k,c:c,t:t===undefined?'':t,kids:[],appendChild:function(x){this.kids.push(x);}};}"
               "var document={createTextNode:function(t){return {t:t};}};"
               "function data(k,c,t){return noI18n(el(k,c,t));}")
        fns = ''.join(re.search(r'\n  ' + n + r'[\s\S]*?\n  }\n', rp).group(0)
                      for n in (r'function masked\(', r'var SAID_CMD[\s\S]*?function saidWords\('))
        js = (pre + fns + 'var a=saidWords("ran sh -c \\"test -d /x || mkdir /x\\"");'
              'var b=saidWords("wrote /a •••• (a password made for this run)");'
              'console.log(JSON.stringify([a.kids.map(function(x){return x.t;}), a.ni, b.t]));')
        got = subprocess.run([node, '-e', js], capture_output=True, text=True, timeout=60)
        self.assertEqual(json.loads(got.stdout), [['spušteno ', 'sh -c "test -d /x || mkdir /x"'], 1,
                                                  'wrote /a •••• (heslo pro tento běh)'], got.stderr)


if __name__ == '__main__':
    sys.exit(unittest.main())
