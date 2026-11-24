#!/usr/bin/env python3
"""Hunt w8, area newuser: the pages through the eyes of a new administrator.

    python3 test/test_hunt_rw8_newuser.py
    ACME_SHOTS=DIR     screenshots there
    ACME_RW8_CS=FILE   {English: Czech} merged into a copy of cs.json for the pages

Walked from a fresh installation (the first account as the installer makes it, the first
sign-in) to a first certificate from pebble deployed to a folder of this machine, a team with a
member on the portal, a report and a backup - in Czech and in English, 1400 and 390 px. Found:

- A source of one's own ACME server whose TLS certificate is from a private CA: Test said only
  openssl's "certificate verify failed" - now also where its CA goes (More → CA certificate of
  the ACME server), or that the CA given there does not sign it.
- The first certificate refused before the CA was asked ("the validation is not ready") said
  what to put in place, never how to go on where the CA sees the names otherwise than this
  server (split DNS, a proxy) - now it names the switch (the job's words and the wizard).
- The wizard's Review while the validation was not in place spoke of "Add and issue now" and
  "Add only" - buttons not there (only "Create anyway").
- "Settings → Certificates" (no such section: it is Renewal and notices) in the help of tests,
  the CRLs, the message texts, the mails' foot; "Settings → Codes by mail and SMS" (it is Codes
  by e-mail and SMS).
- Owners and teams / Request profiles, "Certificates on the portal is off" → Open the setting:
  opened the pane at its top, the setting far below a gallery of pictures - now it is brought
  into view with the focus. Backups' "Download one here" without a password: the same for the
  password's field.
- The portal's form to ask for a certificate with no name open to asking: "Names under:" with
  nothing after it, and "Only names under may be asked for here" when asked; the daemon's
  refusal "asking for certificates here is not set up" did not say what was missing.
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
from acmelib.certs import readiness  # noqa: E402
from acmelib.plugins.base import PluginError  # noqa: E402
from acmelib.plugins.issuers import _acme_client as ac  # noqa: E402

SHOTS = os.environ.get('ACME_SHOTS', '')
_SCRATCH = ('/tmp/claude-0/-home-user-ACME/845070b5-9900-5dee-8b93-2de7397138a5/scratchpad/'
            'hunt140/cs_rw8_newuser.json')
CS = os.environ.get('ACME_RW8_CS', _SCRATCH if os.path.isfile(_SCRATCH) else '')


def src(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


class Ctx(object):
    def __init__(self, err):
        self.err = err

    def http(self, *a, **k):
        raise self.err


class Units(unittest.TestCase):
    def client(self, err, ca_pem=None):
        c = ac.AcmeClient(Ctx(err), 'https://ca.example.test/dir', ca_pem=ca_pem)
        self.addCleanup(c.close)
        return c

    def test_tls_not_trusted_says_where_the_ca_goes(self):
        bad = PluginError('ca.example.test could not be reached: [SSL: CERTIFICATE_VERIFY_FAILED] '
                          'certificate verify failed: unable to get local issuer certificate')
        with self.assertRaises(PluginError) as cm:
            self.client(bad).http('GET', 'https://ca.example.test/dir')
        self.assertIn('paste its CA under More → CA certificate of the ACME server', str(cm.exception))
        self.assertFalse(cm.exception.retry)
        with self.assertRaises(PluginError) as cm:
            self.client(bad, ca_pem='-----BEGIN CERTIFICATE-----').http('GET', 'https://ca.example.test/dir')
        self.assertIn('the CA given under More → CA certificate of the ACME server does not sign it',
                      str(cm.exception))
        # anything else as it was
        other = PluginError('ca.example.test could not be reached: timed out')
        with self.assertRaises(PluginError) as cm:
            self.client(other).http('GET', 'https://ca.example.test/dir')
        self.assertIs(cm.exception, other)

    def test_not_ready_says_how_to_go_on(self):
        class Job(object):
            def step(self, *a, **k):
                pass
        was = readiness.check
        readiness.check = lambda *a, **k: {'blocking': [{'name': 'www.example.test',
                                                         'fix': 'Create in your DNS: www A 192.0.2.1'}]}
        try:
            with self.assertRaises(readiness.NotReady) as cm:
                readiness.precheck(None, Job(), {'issuer': 'LE'}, ['www.example.test'])
        finally:
            readiness.check = was
        words = str(cm.exception)
        self.assertTrue(words.startswith('the CA was not asked - the validation is not ready: '
                                         'www.example.test: Create in your DNS'), words)
        self.assertIn('switch off Settings → Renewal and notices → Check the validation before the '
                      'CA is asked', words)
        self.assertTrue(readiness.failed_on_validation(cm.exception))

    def test_no_pointer_to_sections_that_are_not_there(self):
        for rel in ('web/assets/certs.js', 'web/admin/certs-ui.php', 'acmelib/certs/publish.py',
                    'acmelib/certs/texts.py', 'acmelib/certs/deployer.py', 'acmelib/certs/runplan.py',
                    'acmelib/engine/900_certificates.py', 'acmelib/engine/095_how_many_were_sent.py',
                    'acmelib/certs/api_checks.py', 'acmelib/certs/cli.py'):
            text = re.sub(r"'\s*\n\s*'", '', src(rel))
            self.assertNotRegex(text, r'Settings\s+→ Certificates(?! and TLS)', rel)
            self.assertNotIn('Codes by mail', text, rel)
        # the sections pointed at are there, by these names
        page = src('web/admin/index.php') + src('web/admin/certs-ui.php')
        self.assertTrue('Renewal and notices' in page, 'no section Renewal and notices')
        self.assertTrue('Codes by e-mail and SMS' in page, 'no section Codes by e-mail and SMS')

    def test_czech(self):
        if not CS:
            self.skipTest('no Czech file of this round here (merged into web/lang/cs.json)')
        with open(CS, encoding='utf-8') as f:
            cs = json.load(f)
        for en in ('What it will be. "Create anyway" keeps it; acme asks the source by itself once '
                   'what is marked below is in place.',
                   'No name may be asked for here yet - an administrator says which (Names people '
                   'may ask for).',
                   'The regular runs are off now: Settings → Renewal and notices → Test the servers '
                   'by themselves.'):
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
            'portal': 1, 'portal_local': 1, 'portal_cert': 0, 'portal_tries': 50,
            'portal_cert_suffixes': '', 'portal_cert_issuers': 'self'}})
        cls.must('POST', '/api/users', {'action': 'add', 'name': 'wnu', 'role': 'portal',
                                        'password': cls.pw, 'must_change': 0})
        cls.must('POST', '/api/teams/save', {
            'name': 'WNew', 'members': [{'who': 'local:wnu', 'roles': ['Requester']}]})
        # as the first start makes it (kept when it is there already)
        cls.call('POST', '/api/sources/save', {'name': 'LetsEncrypt staging', 'kind': 'acme',
                                               'config': {'directory': 'letsencrypt-staging'}},
                 cls.admin)

    def test_api_refusal_says_what_is_missing(self):
        st, got = self.call('POST', '/api/settings', {'settings': {'portal_cert': 1}}, self.admin)
        self.assertEqual(st, 200, got)
        try:
            s = self.login('wnu')
            st, got = self.call('POST', '/api/portal/cert_request',
                                {'names': ['www.example.test'], 'key_type': 'ec-256'}, s)
            self.assertEqual(st, 403, got)
            self.assertIn('an administrator sets Names people may ask for (Settings → The '
                          'enrolment pages)', json.dumps(got, ensure_ascii=False))
        finally:
            self.call('POST', '/api/settings', {'settings': {'portal_cert': 0}}, self.admin)

    def test_pages_rw8(self):
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode:
            self.skipTest('no playwright for node here')
        # the portal's certificates off for the teams' warning, then on for the form (the
        # page script switches them)
        php, base = self.pages()
        try:
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rw8_newuser_page.js'), base, self.pw,
                                  SHOTS], capture_output=True, text=True, timeout=1800, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-3000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        self.assertEqual(seen['errors'], [])
        self.assertEqual(seen['overflow'], {})
        self.assertEqual(len(seen['portalSetting']), 4)
        for tag, f in seen['portalSetting'].items():
            self.assertEqual(f, {'key': 'portal_cert', 'seen': True}, tag)
        for tag, f in seen['backupFocus'].items():
            self.assertEqual(f, {'key': 'rbackup_password', 'seen': True}, tag)
        for tag, r in seen['review'].items():
            self.assertTrue(r['blocked'], (tag, r))
            self.assertNotIn('Add only', r['note'], tag)
            if tag.startswith('en'):
                self.assertIn('"Create anyway" keeps it', r['note'], tag)
                self.assertIn('Settings → Renewal and notices → Check the validation before the '
                              'CA is asked', r['skip'], tag)
            elif CS:
                self.assertIn('„Přesto vytvořit“ ho uloží', r['note'], tag)
                self.assertIn('Obnovování a upozornění', r['skip'], tag)
        for tag, a in seen['ask'].items():
            self.assertNotRegex(a['hint'], r'Names under:\s*$', tag)
            self.assertNotIn('Only names under  may', a['said'], tag)
            if tag.startswith('en'):
                self.assertIn('No name may be asked for here yet', a['hint'], tag)
                self.assertIn('No name may be asked for here yet', a['said'], tag)
            elif CS:
                self.assertIn('Zatím tu nelze žádat o žádné jméno', a['hint'], tag)


if __name__ == '__main__':
    unittest.main(verbosity=2)
