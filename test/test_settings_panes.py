#!/usr/bin/env python3
"""Every setting has a pane of its own.

    python3 test/test_settings_panes.py

A setting in no pane is drawn in the card of "everything else", which shows
under every pane of Settings - one added without its pane turned up
everywhere (db_path, 1.0.2).
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-panes-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402

# The cluster's own wiring, set by its wizard and never listed (settings_state).
WIRING = {'ha_mode', 'ha_slot', 'ha_peer', 'ha_peer_port', 'ha_address', 'ha_tls',
          'ha_tls_ca', 'db_guard_kept_off'}


class Panes(unittest.TestCase):
    def test_every_setting_in_a_pane(self):
        placed = set(k for keys in E.PANES.values() for k in keys)
        loose = sorted(k for k in E.DEFAULTS if k not in placed and k not in WIRING)
        self.assertEqual(loose, [], 'settings in no pane (shown under every pane): %s' % loose)

    def test_every_pane_has_its_place(self):
        # A pane with no <div id="sect-PANE"> on the page draws its settings nowhere, so
        # they fell into the card of everything else - under every pane (ssh_gate_port,
        # 1.0.40). The settings a card of their own draws need no place.
        page = ''
        for p in ('web/admin/index.php', 'web/admin/certs-ui.php'):
            with open(os.path.join(ROOT, p), encoding='utf-8') as f:
                page += f.read()
        homeless = sorted(p for p, keys in E.PANES.items()
                          if 'id="sect-%s"' % p not in page
                          and any(k not in E.CARD_DRAWN for k in keys))
        self.assertEqual(homeless, [], 'panes with no sect- on the page: %s' % homeless)

    def test_no_pane_names_an_unknown_setting(self):
        unknown = sorted(k for keys in E.PANES.values() for k in keys if k not in E.DEFAULTS)
        self.assertEqual(unknown, [])


# Read other than by CONFIG.get('key') / ['key'] - each said where.
READ_OTHERWISE = {
    'debug_ldap', 'debug_api', 'debug_codes',          # debug_on(): 'debug_' + what
    'portal_tries', 'login_tries',                     # split_limit('...')
    'certs_certadmin_all', 'certs_readonly_all',       # acmelib/certs/teams.py _setting()
    'alerts_trial', 'alerts_sso',                      # ALERT_EVENTS: CONFIG.get(r[0]) (1.0.40)
    'alerts_kerberos',                                 # ALERT_EVENTS too (1.0.99)
    # Signing in with Windows (1.0.99): each part's, CONFIG.get(part + '_krb_auto') ...
    'admin_krb_auto', 'admin_krb_realm', 'admin_password_off',
    'portal_krb_auto', 'portal_krb_realm', 'portal_password_off',
    'alerts_certlogin',                                # ALERT_EVENTS too (1.0.100)
    # Signing in with a certificate (1.0.100): CONFIG.get(part + '_certlogin_match') ...
    'admin_certlogin_match', 'admin_certlogin_crl', 'portal_certlogin_match',
    'portal_certlogin_crl',
    'admin_certlogin_auto', 'portal_certlogin_auto',  # CONFIG.get(part + '_certlogin_auto')
}


def engine_sources():
    out = []
    for top in ('acmelib', 'web'):
        for d, _dirs, files in os.walk(os.path.join(ROOT, top)):
            for f in files:
                if f.endswith(('.py', '.php', '.js')):
                    with open(os.path.join(d, f), encoding='utf-8', errors='replace') as fh:
                        out.append(fh.read())
    return '\n'.join(out)


class Read(unittest.TestCase):
    def test_every_setting_is_read(self):
        """A setting shown, checked and saved that nothing reads does nothing
        (code_tries until 1.0.19: wrong codes were never counted)."""
        import re
        src = engine_sources()
        indirect = set(READ_OTHERWISE) | set(E.PROXY_FOR.values()) | \
            set(k for k, _r in E.ROLE_GROUP_KEYS)
        unread = []
        for key in E.DEFAULTS:
            if key in indirect or key in WIRING:
                continue
            k = re.escape(key)
            if not re.search(r"(\.get\(\s*['\"]%s['\"]|\[\s*['\"]%s['\"]\s*\]|_alerts_to\('%s'\))"
                             % (k, k, k), src):
                unread.append(key)
        self.assertEqual(unread, [])

    def test_tall_settings_are_drawn_tall(self):
        """A PEM or the records of the DNS server in a box of one line lost their
        line breaks (1.0.19): the page draws as tall what the API says is."""
        self.assertIn('dns_static', E.SETTING_TALL)
        for key in ('isemon_ca', 'siem_ca', 'acme_ca_pem'):
            self.assertIn(key, E.SETTING_TALL)
        with open(os.path.join(ROOT, 'acmelib', 'engine', '130_the_daemon.py'), encoding='utf-8') as f:
            self.assertIn("'tall': key in SETTING_TALL", f.read())
        with open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8') as f:
            self.assertIn('TALL[s.key] || s.tall', f.read())


class WrongCodes(unittest.TestCase):
    """code_tries (1.0.19): a mailed or texted code of the second step is gone after
    that many wrong tries, and another has to be sent."""

    @classmethod
    def setUpClass(cls):
        cls.store = E.Storage(E.open_db())

    def session(self, field, saved):
        tok = self.store.session_new('admin-half', 'codes1', 'fulladmin', '127.0.0.1', 1,
                                     data={field: saved})
        return self.store.session_get(tok, 'admin-half', 3600, touch=False)

    def saved(self):
        return {'hash': E.code_hash('aa', '123456'), 'salt': 'aa', 't': 0, 'exp': 9e12}

    def test_gone_after_the_tries(self):
        E.CONFIG['code_tries'] = 3
        s = self.session('mfa_code', self.saved())
        h = type('H', (), {'store': self.store})()
        E._mfa_wrong(h, s, 'mfa_code', s['data']['mfa_code'])
        E._mfa_wrong(h, s, 'mfa_code', s['data']['mfa_code'])
        with self.assertRaises(E.ApiError) as said:
            E._mfa_wrong(h, s, 'mfa_code', s['data']['mfa_code'])
        self.assertIn('last try', str(said.exception))
        raw = self.store.db.value('SELECT data FROM sessions WHERE id = ?', (s['id'],))
        self.assertNotIn('mfa_code', raw)

    def test_a_new_one_keeps_the_way_chosen(self):
        E.CONFIG['code_tries'] = 1
        saved = dict(self.saved(), kind='mail', dest='a@example.cz')
        s = self.session('mfa_new', saved)
        h = type('H', (), {'store': self.store})()
        with self.assertRaises(E.ApiError):
            E._mfa_wrong(h, s, 'mfa_new', saved)
        import json
        raw = json.loads(self.store.db.value('SELECT data FROM sessions WHERE id = ?', (s['id'],)))
        self.assertEqual(raw['mfa_new'], {'kind': 'mail', 'dest': 'a@example.cz'})
        self.assertFalse(E._mfa_code_ok(raw['mfa_new'], '123456'))

    def test_checks_count_the_wrong_ones(self):
        with open(os.path.join(ROOT, 'acmelib', 'engine', '415_the_texts_of_the.py'),
                  encoding='utf-8') as f:
            src = f.read()
        self.assertIn("_mfa_wrong(h, s, 'mfa_code'", src)
        self.assertIn("_mfa_wrong(h, s, 'mfa_new'", src)


if __name__ == '__main__':
    unittest.main(verbosity=2)
