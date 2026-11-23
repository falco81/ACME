#!/usr/bin/env python3
"""Hunt v5, area czech: the Czech translation across the whole application.

    python3 test/test_hunt_rv5_czech.py
    ACME_RV5_CS=FILE[,FILE...]   {English: Czech} merged into a copy of web/lang/cs.json first
                                 (an English text with <tags> goes into its `rich` part, with
                                 {0} into `patterns`, else `strings` - and a source already in
                                 the file is left as it is)
    ACME_RV5_FIX=FILE            {English: corrected Czech}: the texts of sources already there
                                 replaced in the copy
    ACME_SHOTS=DIR               screenshots of the pages there

- Every text the daemon says itself - ApiError, LookupError, ValueError, PermissionError,
  PluginError, PkiError and PushError words and the events (add_event) of acmelib, each "%s",
  "%d", f-string field and .format slot a {0} - is read out of the source and filled with names
  and numbers; each must come out in Czech by the pages' own translation (web/assets/i18n.js,
  in node) - but those in NOT_SAID (words only an API caller or a parser sees, the command
  line's own, or texts made of the pieces of several sentences, whose real forms are in WHOLE).
- WHOLE: the sentences such texts really make (plurals, "made"/"changed"), the daemon's
  refusals the PHP pages make, and words of the pages that were left English - each in Czech by
  the page's translation and by the mails' (acmelib/i18n_mail.py).
- The patterns the plural of a count never reached ("{2} trustpoint{3}": a slot after a letter
  never starts with one, so "4 trustpoints" stayed half English).
- The pages (php -S on a copy of web/, Chromium via test/hunt_rv5_czech_page.js) in Czech at
  1400 and 390 px: every tab, every pane of Settings, the sign-in page and the portal - no
  English left outside names, addresses and code, no page wider than the window, no error.
"""
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

CS_EXTRA = [x for x in os.environ.get('ACME_RV5_CS', '').split(',') if x]
CS_FIX = os.environ.get('ACME_RV5_FIX', '')
SHOTS = os.environ.get('ACME_SHOTS', '')

CALLS = {'ApiError': 1, 'LookupError': 0, 'ValueError': 0, 'add_event': 1, 'PermissionError': 0,
         'PluginError': 0, 'PkiError': 0, 'PushError': 0}

# Words only an API caller, a parser's caller or the command line sees, a tool's own output
# put after its name, or a text joined from pieces whose real sentences are in WHOLE below.
NOT_SAID = {
    'CBOR cut short', 'CBOR of a kind not taken here', 'a CBOR map key of a kind not taken',
    'a field twice', 'a length not of LDAP', 'a length past the end', 'a length that is not DER',
    'a tag of more than one byte', 'no AP-REQ', 'no GSS-API token', 'no NegTokenInit',
    'no authenticator', 'no cipher', 'no mechToken', 'no mechanism', 'no messageID',
    'no resultCode', 'not Kerberos 5', 'not base64url', 'too long', 'bad padding',
    'a copy is a JSON object', 'approval.outside knows no {0}', 'as: auto, main or alt (the twin)',
    'check, prepare, enforce or permissive', 'data_b64 is the file as base64', 'days: 0 to {0}',
    'days: a number', 'do is stop, continue or forget', 'family is issuer, challenge, target or check',
    'ids are numbers', 'ids: 1 to {0} ids of what was found, each 12 of 0-9 a-f', 'mib or zabbix',
    'no such thing to do with a user', 'rsa, ec or both', 'save, try or poll',
    'since is a time (seconds)', 'text is the policy file', 'the exclusive pairs are a list',
    'the names are a list of names', 'the options are an object',
    'the table is named by letters, digits and . _ : - (80 at most)',
    'the variant is main, alt or both (or ec, rsa)', 'what: audit or anomaly',
    'what: command, seal or both', 'when is next (at its next renewal) or now',
    'which one: id or name', 'which role? --set-role {0} --role {1}', 'which: ids',
    'which: rsa, ec or both', '{0}: {1} at most',
    'add ssl crt-list {0}: {1}', 'commit ssl cert {0}: {1}', 'new ssl cert {0}: {1}',
    'set ssl cert {0}: {1}', 'knotc zone-read {0}: {1}', 'openssl cmp: {0}', 'openssl crl: {0}',
    'pg_hba.conf: {0}', 'ssh-keygen: {0}', '{0}: acme push - {1}', '{0}: {1} on the command line',
    '{0} {1} (version {2}, until {3})',
    '--members as JSON is a list of {"who": ..., "roles": [...], "until": ..., "note": ...}: {0}',
    'a review is {every_days, answer_days, action}',
    'a template is {kind, description, members, policy, contact_mail, extras}',
    'approval.outside is {{0}}', "config is the module's settings {key: value}",
    'ids go with fix or rule_drop only', 'items: the agents to confirm, each {id, fp}',
    'just-in-time elevation is {roles, max_hours}', 'pairs is {"source": ["validation", ...]}',
    'pairs is {"source": ["validation", ...]} (or null: no limit)',
    'separation of duties is {no_self_approval, exclusive}',
    "the builder's state: a folder is {dir, owner, group, mode}",
    'the notifications are {mail, manager_mail, oncall_mail, ...}',
    'the schedule is {every, day, hour}', 'type is one of {0}', '{0} is a list of target ids',
    '{0} is one of {1}', '{0} is not a file', 'two .pfx / .p12 at most (an RSA and an ECDSA one)',
    # pieces - their sentences are in WHOLE
    'only a full administrator may {0} settings that are not saved - save them first, or use the one saved',
    "Let's Encrypt allows {0} {1} in {2} hours: acme holds this one back until {3}",
    'the CA refused the sign-in of {0} with NTLM (wrong password, a locked account, or NTLM not allowed for it){1}: {2}',
    'the enrollment code "{0}" was made by {1} ({2}, {3} day{4}, at most {5} server{6}){7}{8}',
    'the enrollment code "{0}" was revoked by {1} ({2} server{3} joined with it) - no other server joins with it',
    'the policy design of the agent of target {0} was saved by {1} (version {2}{3}, {4} entr{5}) - acme never sends it: root applies it on the server',
    'the report {0} ({1}) was {2} by {3}', 'the {0} {1}: the version of {2} restored by {3}',
    '{0} did not find {1} {2} - look again on that node (each node puts right only what it found itself)',
    '{0} made {1} SSH token for {2}{3}', '{0} was signed out of {1}{2}: {3}',
    '{0} {1} made as a copy of {2} - with its credentials ({3}) by {4}',
    '{0} {1} the backup destination {2} ({3})',
    '{0} {1} the password policy of the local users (command line)',
    'test {0} of {1} runs after {2} by {3}', 'the task {0} {1}{2}',
    'the {0} {1} restored from the trash by {2}{3}',
    '{0} took {1} tr{2} of backups off the list; the backups stay where they are',
    '{0} {1} the password policy of the local users{2}', '{0} {1} the role {2} of {3} on the team {4}',
    '{0} {1} {2} in the access review of the team {3}{4}',
    '{0}: {1} no longer looks after its database server through acme-db-agent ({2}){3}; {4}',
}

# The sentences as the code really makes them (names and numbers filled in).
WHOLE = [
    'the enrollment code "web" was made by tester (active, 7 days, at most 5 servers) - each server that joins with it waits to be confirmed',
    'the enrollment code "web" was made by tester (passive, 1 day, at most 1 server) for the team Web - each server that joins with it is CONFIRMED AUTOMATICALLY',
    'the enrollment code "web" was revoked by tester (3 servers joined with it) - no other server joins with it',
    'a server enrolled with web: target srv1 (srv1.example.test, 192.0.2.5, Linux, key 0123456789abcdef…) - it waits for its fingerprint to be confirmed',
    'the policy design of the agent of target srv1 was saved by tester (version 3, 12 entries) - acme never sends it: root applies it on the server',
    'only a full administrator may look up with settings that are not saved - save them first, or use the one saved',
    "Let's Encrypt allows 300 new orders in 3 hours: acme holds this one back until 14:05",
    'tester made a new SSH token for jan (codes by mail to j***@example.test)',
    'tester took the SELinux report - without acme2',
    'tester set the password policy of the local users (command line)',
    'signed in to NSX Manager nsx1.example.test; 4 certificates',
    'signed in to asa1: Cisco Adaptive Security Appliance Software Version 9.20(2); 4 trustpoints',
    'signed in to sw1 (10.0.0.2): NX-OS 10.4(1); 2 trustpoints',
    'the agent of dc1 reaches CA1: 5 templates; Web is offered',
    '3 CAs the agent of dc1 lists',
    'Caddy has 3 certificates loaded through its API - nothing of acme in it',
    'the download failed (HTTP 502)',
    'that file is bigger than this page takes (300 MB sent, at most 200 MB)',
    'the daemon is not answering',
    'web (web.example.test) holds no certificate, request, CRL or key that can be read',
    'srv1:22 showed no host key through the agent of gw: refused',
    'the CA refused the sign-in of EXAMPLE\\acme with NTLM (wrong password, a locked account, or NTLM not allowed for it): rejected',
    'the certificate web restored from the trash by tester with 2 deployments',
    'the task 7f3a failed: no space left',
    'tester took 3 tries of backups off the list; the backups stay where they are',
    'tester took back the request for the role Approver of jan on the team Web',
    'tester took out jan in the access review of the team Web - the review is done',
    'test tls of web runs after a deployment on fake1 by tester',
    'Certificates ending soon',
    '(no such user)',
]


def py_pattern(node):
    n = [0]

    def slot():
        n[0] += 1
        return '{%d}' % (n[0] - 1)

    def walk(nd):
        if isinstance(nd, ast.Constant) and isinstance(nd.value, str):
            return nd.value.replace('{', '\x01').replace('}', '\x02')
        if isinstance(nd, ast.JoinedStr):
            return ''.join(str(v.value) if isinstance(v, ast.Constant) else slot() for v in nd.values)
        if isinstance(nd, ast.BinOp) and isinstance(nd.op, ast.Mod) and isinstance(nd.left, (ast.Constant, ast.BinOp)):
            left = walk(nd.left)
            if left is None:
                return None
            return re.sub(r'%(\([^)]*\))?[-#0 +]*\d*(?:\.\d+)?[sdfrix]', lambda m: slot(), left).replace('%%', '%')
        if isinstance(nd, ast.BinOp) and isinstance(nd.op, ast.Add):
            left, right = walk(nd.left), walk(nd.right)
            if left is None and right is None:
                return None
            return (left if left is not None else slot()) + (right if right is not None else slot())
        if isinstance(nd, ast.Call) and isinstance(nd.func, ast.Attribute) and nd.func.attr == 'format' \
                and isinstance(nd.func.value, ast.Constant) and isinstance(nd.func.value.value, str):
            return re.sub(r'\{[^}]*\}', lambda m: slot(), nd.func.value.value)
        return None
    s = walk(node)
    return None if s is None else s.replace('\x01', '{').replace('\x02', '}')


def said_by_daemon():
    """{text: 'file:line'} - the words of acmelib's errors and events, {0} where filled in."""
    out = {}
    for base, dirs, files in os.walk(os.path.join(ROOT, 'acmelib')):
        dirs[:] = [d for d in dirs if d not in ('vendor', '__pycache__')]
        for f in files:
            if not f.endswith('.py'):
                continue
            p = os.path.join(base, f)
            with open(p, encoding='utf-8') as fh:
                try:
                    tree = ast.parse(fh.read())
                except SyntaxError:
                    continue
            for nd in ast.walk(tree):
                if not isinstance(nd, ast.Call):
                    continue
                fn = nd.func
                name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else '')
                if name not in CALLS or len(nd.args) <= CALLS[name]:
                    continue
                s = py_pattern(nd.args[CALLS[name]])
                if not s:
                    continue
                s = s.strip()
                t = re.sub(r'\{\d+\}', ' ', s)
                # words, not a key or a name: two words of letters, one in small letters
                if len(re.findall(r'[A-Za-z]{2,}', t)) < 2 or not re.search(r'(^|\s)[a-z]{2,}', t):
                    continue
                if re.fullmatch(r'[\w.:/{}\s-]*', s) and not re.search(r'[a-z]{2,} [a-z]{2,}', t):
                    continue
                out.setdefault(s, '%s:%d' % (os.path.relpath(p, ROOT), nd.lineno))
    return out


def merged_pack(tmp):
    """A copy of web/lang/cs.json with ACME_RV5_CS added and ACME_RV5_FIX applied."""
    src = os.path.join(ROOT, 'web', 'lang', 'cs.json')
    with open(src, encoding='utf-8') as f:
        pack = json.load(f)
    have = {v['source'] for sect in ('strings', 'patterns', 'rich') for v in pack.get(sect, {}).values()}
    i = 0
    for extra in CS_EXTRA:
        if not os.path.exists(extra):
            continue
        with open(extra, encoding='utf-8') as f:
            more = json.load(f)
        for en, cs in more.items():
            if en in have:
                continue
            i += 1
            sect = 'rich' if '<' in en else ('patterns' if re.search(r'\{\d\}', en) else 'strings')
            pack.setdefault(sect, {})['%s5%04d' % (sect[0], i)] = {'source': en, 'text': cs}
    if CS_FIX and os.path.exists(CS_FIX):
        with open(CS_FIX, encoding='utf-8') as f:
            fix = json.load(f)
        for sect in ('strings', 'patterns', 'rich'):
            for v in pack.get(sect, {}).values():
                if v['source'] in fix:
                    v['text'] = fix[v['source']]
    path = os.path.join(tmp, 'cs.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(pack, f, ensure_ascii=False)
    return path


SAY = r'''
const vm = require('vm'), fs = require('fs'), path = require('path');
const [root, csPath, inPath] = process.argv.slice(2);
const all = JSON.parse(fs.readFileSync(csPath, 'utf8'));
const pack = {code: 'cs', strings: {}, patterns: [], rich: {}};
for (const part of ['strings', 'patterns', 'rich']) {
  for (const e of Object.values(all[part] || {})) {
    if (!e || typeof e !== 'object') continue;
    const from = String(e.source || ''), to = String(e.text || '');
    if (!from || !to || (to === from && part !== 'patterns')) continue;
    if (part === 'patterns') pack.patterns.push([from, to]); else pack[part][from] = to;
  }
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
for (const s of JSON.parse(fs.readFileSync(inPath, 'utf8'))) out[s] = ctx.i18nText(s);
console.log(JSON.stringify(out));
'''


def fills(t):
    """The text with names and numbers in its slots, a few ways (a slot after a word may be a
    whole name, a number, or nothing at all)."""
    if '{' not in t:
        return [t]
    seq = iter(['web1', '3', 'alice', '4', 'node2', '5', 'x7', '6', 'y8', '7', 'z9', '8'])
    return [re.sub(r'\{\d+\}', 'web1', t), re.sub(r'\{\d+\}', '3', t),
            re.sub(r'\{\d+\}', 'example.com', t), re.sub(r'\{\d+\}', '', t),
            re.sub(r'\{\d+\}', lambda m: next(seq), t),
            re.sub(r'\{\d+\}', 'web1', re.sub(r'(\{\d+\})+$', '', t))]


def fold(s):
    return re.sub(r'\s+', ' ', str(s)).strip()


class Czech(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which('node')
        cls.tmp = tempfile.mkdtemp(prefix='acme-rv5cz-')
        cls.cs = merged_pack(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def say(self, texts):
        if not self.node:
            self.skipTest('no node here')
        p = os.path.join(self.tmp, 'in.json')
        with open(p, 'w', encoding='utf-8') as f:
            json.dump(sorted(set(texts)), f)
        js = os.path.join(self.tmp, 'say.js')
        with open(js, 'w', encoding='utf-8') as f:
            f.write(SAY)
        got = subprocess.run([self.node, js, ROOT, self.cs, p], capture_output=True, text=True,
                             timeout=600)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        return json.loads(got.stdout)

    def test_daemon_words_in_czech(self):
        texts = said_by_daemon()
        self.assertGreater(len(texts), 3000)            # the reader still finds them
        todo = {t: fills(t) for t in texts if t not in NOT_SAID}
        said = self.say([x for v in todo.values() for x in v])
        left = sorted('%s  (%s)' % (t, texts[t]) for t, vs in todo.items()
                      if not any(said.get(v) is not None and fold(said[v]) != fold(v) for v in vs))
        self.assertEqual(left, [], '%d text(s) of the daemon with no Czech' % len(left))

    def test_whole_sentences(self):
        said = self.say(WHOLE)
        for t in WHOLE:
            self.assertIsNotNone(said[t], t)
            self.assertNotEqual(fold(said[t]), fold(t), t)
            # no English words left beside the Czech ones
            rest = re.sub(r'NX-OS|IOS XE|Cisco Adaptive Security Appliance Software Version|CONFIRMED',
                          '', said[t])
            self.assertFalse(re.search(r'\b(the|with|is|of|was|by|templates|certificates|trustpoints|'
                                       r'servers|days|offered|loaded|nothing)\b', rest), (t, said[t]))

    def test_mails_say_them_too(self):
        import acmelib.i18n_mail as M
        keep = M._places, dict(M._PACKS)
        M._places = lambda code: [self.cs]
        M._PACKS.clear()
        try:
            for t in WHOLE:
                got = M.tr(t, 'cs')
                self.assertNotEqual(fold(got), fold(t), t)
        finally:
            M._places = keep[0]
            M._PACKS.clear()
            M._PACKS.update(keep[1])

    def test_no_slot_glued_to_a_word_for_a_plural(self):
        """A pattern "... {2} trustpoint{3}" never takes "4 trustpoints": the plural of each such
        text is in the file too."""
        with open(self.cs, encoding='utf-8') as f:
            pack = json.load(f)
        sources = {v['source'] for v in pack['patterns'].values()}
        for en, plural in (('signed in to {0}: IOS XE {1}; {2} trustpoint{3}, the HTTPS server uses {4}',
                            'signed in to {0}: IOS XE {1}; {2} trustpoints, the HTTPS server uses {3}'),
                           ('signed in to {0} ({1}): NX-OS {2}; {3} trustpoint{4}',
                            'signed in to {0} ({1}): NX-OS {2}; {3} trustpoints'),
                           ('signed in to NSX Manager {0}; {1} certificate{2}',
                            'signed in to NSX Manager {0}; {1} certificates'),
                           ('{0} CA certificate{1} added to the trust store',
                            '{0} CA certificates added to the trust store')):
            if en in sources and CS_EXTRA:
                self.assertIn(plural, sources)
        if CS_EXTRA:
            said = self.say(['2 CA certificates added to the trust store',
                             'signed in to Aria Suite Lifecycle 8.18; 6 certificates in the Locker'])
            self.assertEqual(said['2 CA certificates added to the trust store'],
                             'do úložiště důvěry přidáno certifikátů CA: 2')
            self.assertEqual(said['signed in to Aria Suite Lifecycle 8.18; 6 certificates in the Locker'],
                             'přihlášeno do Aria Suite Lifecycle 8.18; certifikátů v Lockeru: 6')

    def test_fixes(self):
        """English left in the Czech, a word for a slot (ACME_RV5_FIX)."""
        if not CS_FIX:
            self.skipTest('ACME_RV5_FIX not given')
        said = self.say(['Enrollment code', 'User principal name', 'web1, web2 still reach a database with TLS - '
                         'perhaps this one: switch them off first'])
        self.assertEqual(said['Enrollment code'], 'Registrační kód')
        self.assertNotEqual(said['User principal name'], 'User principal name')
        self.assertIn('připojují', said['web1, web2 still reach a database with TLS - perhaps this one: switch them off first'])


class Pages(unittest.TestCase):
    """Every tab, pane, the sign-in page and the portal in Czech."""

    @classmethod
    def setUpClass(cls):
        import test_certs_core as TCC
        cls.TCC = TCC
        TCC.CertsCore.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        cls.TCC.CertsCore.tearDownClass.__func__(cls)

    def test_pages(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        shutil.copy(merged_pack(self.tmp), os.path.join(web, 'lang', 'cs.json'))
        port = self.TCC.free_port()
        self.assertNotIn(port, (8092, 5432, 5433))
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='6'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rv5_czech_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw, SHOTS],
                                 capture_output=True, text=True, timeout=1500, cwd=ROOT)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        seen = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(len(seen['runs']), 2)
        left = []
        for r in seen['runs']:
            self.assertGreater(len(r['pages']), 20, list(r['pages']))
            for name, p in sorted(r['pages'].items()):
                self.assertLessEqual(p['hs'], 1, (r['w'], name))
                left += ['%s %s: %s' % (r['w'], name, e) for e in p['english']]
        if os.environ.get('ACME_RV5_SHOW'):
            print('\n'.join(left))
        if CS_EXTRA:
            self.assertEqual(left, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
