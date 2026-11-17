"""Hunt R, run 4, area accounts: regressions.

    python3 test/test_hunt_r4_accounts.py
"""
import os
import socketserver
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
TMP = tempfile.mkdtemp(prefix='acme-r4acc-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
import acme as E  # noqa: E402,F401
from acmelib import engine as EN  # noqa: E402


class _Relay(socketserver.StreamRequestHandler):
    """A relay that lets this machine send: no AUTH, no STARTTLS offered."""
    got = []
    auth_tried = []

    def handle(self):
        def w(s):
            self.wfile.write((s + '\r\n').encode())
        w('220 relay ESMTP')
        data = False
        while True:
            ln = self.rfile.readline()
            if not ln:
                return
            s = ln.decode('utf-8', 'replace').rstrip('\r\n')
            if data:
                if s == '.':
                    data = False
                    w('250 queued as R4')
                else:
                    self.got.append(s)
                continue
            c = s.split(' ')[0].upper()
            if c == 'EHLO':
                w('250-relay')
                w('250 8BITMIME')
            elif c == 'AUTH':
                self.auth_tried.append(s)
                w('502 no AUTH here')
            elif c in ('MAIL', 'RCPT', 'RSET', 'NOOP'):
                w('250 ok')
            elif c == 'DATA':
                data = True
                w('354 go on')
            elif c == 'QUIT':
                w('221 bye')
                return
            else:
                w('502 no')


class SmtpAutoWithoutAccount(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = socketserver.ThreadingTCPServer(('127.0.0.1', 0), _Relay)
        cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.saved = dict(EN.CONFIG)
        EN.CONFIG.update(mail_mode='smtp', smtp_host='127.0.0.1',
                         smtp_port=cls.srv.server_address[1], mail_from='acme@example.cz',
                         smtp_user='', smtp_timeout_s=5)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        EN.CONFIG.clear()
        EN.CONFIG.update(cls.saved)

    def send(self, security, auth):
        EN.CONFIG.update(smtp_security=security, smtp_auth=auth)
        return EN.mail_send(None, EN.test_mail('x@example.cz', 'en'), ['x@example.cz'])

    def test_auto_no_account_plain_relay(self):
        # Signing in "auto" (the default) and no account set: the relay that needs none took
        # nothing before - "SMTP AUTH extension not supported by server".
        steps = self.send('none', 'auto')
        self.assertTrue(steps[-1]['ok'], steps)
        self.assertIn('not signed in', [s['what'] for s in steps])

    def test_auto_no_account_starttls_if(self):
        # ...and with "STARTTLS if offered", refused for "the password" there was none of.
        steps = self.send('starttls-if', 'auto')
        self.assertTrue(steps[-1]['ok'], steps)

    def test_auto_with_account_still_signs_in(self):
        # An account set: signing in is tried as before - and its failure said.
        EN.CONFIG['smtp_user'] = 'acme'
        try:
            with self.assertRaises(EN.MailError):
                self.send('none', 'auto')
        finally:
            EN.CONFIG['smtp_user'] = ''

    def test_explicit_mechanism_unchanged(self):
        # A mechanism named by hand is tried as before, account or not.
        with self.assertRaises(EN.MailError):
            self.send('none', 'plain')

    def test_none_unchanged(self):
        steps = self.send('none', 'none')
        self.assertTrue(steps[-1]['ok'])
        self.assertNotIn('not signed in', [s['what'] for s in steps])


class _H(object):
    def __init__(self, headers):
        self.headers = headers


class CodeLanguageOfThePage(unittest.TestCase):
    """The administration's second step: its code in the language of the page it was asked
    from (code_lang's help) - the page opens in ui_lang until a language is chosen there."""

    def setUp(self):
        self.saved = {k: EN.CONFIG.get(k) for k in ('ui_lang', 'mail_lang', 'code_lang')}

    def tearDown(self):
        EN.CONFIG.update(self.saved)

    def test_no_choice_is_the_pages_language(self):
        EN.CONFIG.update(ui_lang='en', mail_lang='cs', code_lang='')
        self.assertEqual(EN.mfa_lang(_H({})), 'en')
        EN.CONFIG.update(ui_lang='cs', mail_lang='en', code_lang='en')
        self.assertEqual(EN.mfa_lang(_H({})), 'cs')

    def test_chosen_language_wins(self):
        EN.CONFIG.update(ui_lang='en', mail_lang='cs', code_lang='')
        self.assertEqual(EN.mfa_lang(_H({'X-Acme-Lang': 'cs'})), 'cs')
        self.assertEqual(EN.mfa_lang(_H({'Cookie': 'a=b; acme_lang=cs'})), 'cs')
        EN.CONFIG.update(ui_lang='cs')
        self.assertEqual(EN.mfa_lang(_H({'X-Acme-Lang': 'en'})), 'en')


if __name__ == '__main__':
    unittest.main(verbosity=1)
