#!/usr/bin/env python3
"""Hunt w9, area firstrun: what a new administrator met next on a fresh installation.

    python3 test/test_hunt_rw9_firstrun.py
    ACME_SHOTS=DIR     screenshots there
    ACME_RW9_CS=FILE   {English: Czech} merged into a copy of cs.json for the pages

- A new source, target or test was offered a name made of its module's title with the
  punctuation dropped ("ACME Lets Encrypt and others", "This machine files", "TLS any port") -
  now a name of its own that reads right ("ACME CA", "Files on this machine", "TLS"); the rows
  made keep their names.
- The source and validation acme makes at the first start ("This server HTTP-01", "acme DNS
  server", "LetsEncrypt staging") stayed English on Czech pages - now shown in the page's
  language (own_name), the stored name kept and said on hover; a row a person made or renamed is
  shown as it is.
- Certificates on the portal on with Names people may ask for or Sources people may ask empty:
  the members had an Ask button whose every request was refused, the administrator no word - now
  said under the switch (Settings → The enrolment pages) and on Owners and teams, and the
  portal's button is dimmed with the reason under it.
- Two settings called "Check before the CA is asked" (Renewal and notices', and the HTTP-01
  modules' own) - the modules' is "Check the token from here first" now (pages, docs, guides).
- The wizard's Review where the source refuses the names outright (a .test name from Let's
  Encrypt staging) spoke of "Add and issue now" and "Add only" - buttons not there.
- "More in docs/X.md" in a module's window: a file the pages cannot open - now a link to its
  setup guide, and the document said where it is on the server.
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
sys.path.insert(0, ROOT)

import test_f140_reports as RP  # noqa: E402  (its daemon, accounts, php -S)
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import defaults as DF  # noqa: E402
from acmelib.certs import store as S  # noqa: E402

SHOTS = os.environ.get('ACME_SHOTS', '')
_SCRATCH = ('/tmp/claude-0/-home-user-ACME/845070b5-9900-5dee-8b93-2de7397138a5/scratchpad/'
            'hunt140/cs_rw9_firstrun.json')
CS = os.environ.get('ACME_RW9_CS', _SCRATCH if os.path.isfile(_SCRATCH) else '')
OLD_LABEL = 'Check before the CA is asked'
NEW_LABEL = 'Check the token from here first'


def src(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Units(unittest.TestCase):
    def test_suggested_names_read_right(self):
        reg = S.registry()
        d = reg.describe()
        got = {}
        for fam in ('issuer', 'challenge', 'target', 'check'):
            for one in d[fam]:
                name = S.safe_name(one.get('default_name') or A.SUGGESTED.get(
                    (fam, one.get('kind'))) or one.get('title') or one.get('kind'))
                self.assertTrue(S.NAME_RE.match(name), (fam, one.get('kind'), name))
                got[(fam, one.get('kind'))] = name
        self.assertEqual(got[('issuer', 'acme')], 'ACME CA')
        self.assertEqual(got[('target', 'local')], 'Files on this machine')
        self.assertEqual(got[('target', 'appliance')], 'This acme server')
        self.assertEqual(got[('check', 'tls')], 'TLS')
        self.assertEqual(got[('challenge', 'http_local')], DF.HTTP_LOCAL)
        for (fam, kind), v in A.SUGGESTED.items():
            self.assertEqual(S.safe_name(v), v, (fam, kind))

    def test_own_name(self):
        row = {'name': DF.HTTP_LOCAL, 'created_by': DF.BY}
        self.assertTrue(DF.own_name(row))
        self.assertFalse(DF.own_name(dict(row, created_by='admin')))       # a person's row
        self.assertFalse(DF.own_name(dict(row, name='web proof')))          # renamed
        self.assertFalse(DF.own_name(None))
        for n in (DF.LE, DF.LE_STAGING, DF.DNS_OWN):
            self.assertTrue(DF.own_name({'name': n, 'created_by': DF.BY}), n)

    def test_two_settings_two_names(self):
        from acmelib.plugins.challenges import http_local
        labels = [f['label'] for f in http_local.HttpLocal.fields if f['key'] == 'self_check']
        self.assertEqual(labels, [NEW_LABEL])
        for rel in ('acmelib/plugins/challenges/http_ssh.py', 'acmelib/plugins/challenges/_upload.py'):
            self.assertIn("'check', '%s'" % NEW_LABEL, src(rel), rel)
        # the global one keeps its name
        self.assertIn("'certs_precheck': 'Check the validation before the CA is asked'",
                      src('acmelib/engine/900_certificates.py'))
        for root in ('acmelib', 'web/assets', 'docs'):
            for dp, _dn, fns in os.walk(os.path.join(ROOT, root)):
                for fn in fns:
                    if fn.endswith(('.py', '.js', '.md', '.php')):
                        with open(os.path.join(dp, fn), encoding='utf-8', errors='replace') as f:
                            self.assertNotIn(OLD_LABEL, f.read(), os.path.join(dp, fn))
        self.assertTrue(re.search(r'then switch "Check the token from here\s*\'\s*\'first" off',
                                  src('acmelib/certs/httpinfo.py')))

    def test_page_sources(self):
        js = src('web/assets/certs.js')
        self.assertNotIn("document.createTextNode('More in '));\n    d.appendChild(mono(p.doc))", js)
        self.assertIn("'/usr/local/lib/acme/' + p.doc", js)
        self.assertIn("compatProblems().length ? 'What it would be - it cannot be created so", js)
        self.assertIn('ownNameEl(', js)
        self.assertIn('askMark', src('web/assets/portal-teams.js'))
        self.assertIn('function portalAskWarn', src('web/assets/admin.js'))
        self.assertTrue(os.path.isfile(os.path.join(ROOT, 'docs', 'acme-issuers.md')))

    def test_czech(self):
        if not CS:
            self.skipTest('no Czech file of this round here (merged into web/lang/cs.json)')
        with open(CS, encoding='utf-8') as f:
            cs = json.load(f)
        for en in (NEW_LABEL, 'Files on this machine', 'This server HTTP-01',
                   'Nobody can ask for a certificate on the portal yet - empty:'):
            self.assertIn(en, cs)
        for en, cz in cs.items():
            self.assertEqual(sorted(re.findall(r'\{\d\}', en)), sorted(set(re.findall(r'\{\d\}', cz))),
                             en)


class Pages(RP.Pages):
    test_pages = None

    @classmethod
    def setUpClass(cls):
        if CS and os.path.isfile(CS):
            os.environ['ACME_EXTRA_CS'] = CS
        RP.Pages.setUpClass.__func__(cls)
        cls.must('POST', '/api/settings', {'settings': {
            'portal': 1, 'portal_local': 1, 'portal_cert': 1, 'portal_tries': 50,
            'portal_cert_suffixes': '', 'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/users', {'action': 'add', 'name': 'wfr', 'role': 'portal',
                                        'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {
            'name': 'WFirst', 'members': [{'who': 'local:wfr', 'roles': ['Requester']}]})

    def test_first_start_rows(self):
        st, got = self.call('GET', '/api/validations', None, self.admin)
        self.assertEqual(st, 200, got)
        rows = {r['name']: r for r in got.get('rows') or []}
        self.assertIn(DF.HTTP_LOCAL, rows, list(rows))
        self.assertTrue(rows[DF.HTTP_LOCAL]['own_name'])
        st, got = self.call('GET', '/api/sources', None, self.admin)
        rows = {r['name']: r for r in got.get('rows') or []}
        self.assertTrue(rows[DF.LE_STAGING]['own_name'])
        self.assertFalse(rows['self']['own_name'])                # a person's
        st, got = self.call('GET', '/api/teams', None, self.admin)
        self.assertEqual(st, 200, got)
        self.assertFalse(got['portal']['ask'])

    def test_pages_rw9(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rw9_firstrun_page.js'), base,
                                  self.pw, SHOTS], capture_output=True, text=True, timeout=1800,
                                 cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        print([t.get('dbg') for t in seen.get('tags', {}).values()])
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(seen['overflow'], {})
        self.assertEqual(len(seen['tags']), 4, seen)
        for tag, s in seen['tags'].items():
            cs = tag.startswith('cs')
            # the first start's validation, in the page's language, its name kept on hover
            if cs and CS:
                self.assertIn('Tento server HTTP-01', s['valNames'], tag)
                self.assertEqual(s['valTitle'], 'This server HTTP-01', tag)
            elif not cs:
                self.assertIn('This server HTTP-01', s['valNames'], tag)
            # a new source and target: names that read right
            self.assertEqual(s['acmeName'], 'ACME CA', tag)
            self.assertEqual(s['localName'], 'Soubory na tomto stroji' if cs and CS
                             else ('Files on this machine' if not cs else s['localName']), tag)
            # the module's window: its guide opens, the document said where it is
            self.assertIn('/usr/local/lib/acme/docs/acme-issuers.md', s['docLine'], tag)
            self.assertTrue(s['guideOpened'], tag)
            # the HTTP-01 module's own check, named apart from the global one
            if not cs:
                self.assertIn(NEW_LABEL, s['httpLabels'], tag)
                self.assertNotIn(OLD_LABEL, s['httpLabels'], tag)
            elif CS:
                self.assertIn('Nejdřív ověřit token odsud', s['httpLabels'], tag)
            # Review, the source refusing the names: no button named that is not there
            self.assertTrue(s['review']['blocked'], (tag, s['review']))
            for b in ('Add and issue now', 'Add only', 'Přidat a hned vydat', 'Jen přidat'):
                self.assertNotIn(b, s['review']['note'], tag)
            if not cs:
                self.assertIn('it cannot be created so', s['review']['note'], tag)
            elif CS:
                self.assertIn('takto ho vytvořit nelze', s['review']['note'], tag)
            # the administrator told, the member's button dimmed with the reason
            self.assertTrue(s['settingWarn'], tag)
            self.assertTrue(s['teamsWarn'], tag)
            self.assertTrue(s['portal']['disabled'], (tag, s['portal']))
            self.assertTrue(s['portal']['why'], (tag, s['portal']))
            if not cs:
                self.assertIn('Names people may ask for', s['settingWarn'], tag)
                self.assertIn('not set up yet', s['portal']['why'], tag)
            elif CS:
                self.assertIn('Jména, o která smějí lidé žádat', s['settingWarn'], tag)
                self.assertNotIn('not set up', s['portal']['why'], tag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
