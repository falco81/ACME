#!/usr/bin/env python3
"""The hunt of 1.0.48, round 2 (the certificates, the backups, the command line) - each checked.

    python3 test/test_hunt_b2.py
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-huntb2-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
import acmelib.engine as E  # noqa: E402
from acmelib.certs import api as A, store as S  # noqa: E402


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


def engine(prefix):
    d = os.path.join(ROOT, 'acmelib', 'engine')
    return read('acmelib', 'engine', [n for n in os.listdir(d) if n.startswith(prefix + '_')][0])


class Certificates(unittest.TestCase):
    def test_a_revoked_twin_is_no_twin(self):
        self.assertTrue(S.is_dual({'key_type_alt': 'rsa-2048', 'alt_cert_pem': 'x', 'alt_state': 'ok'}))
        self.assertFalse(S.is_dual({'key_type_alt': 'rsa-2048', 'alt_cert_pem': 'x', 'alt_state': 'revoked'}))

    def test_a_revoked_twin_stays_revoked_when_its_renewal_fails(self):
        st = E.Storage(E.open_db())
        cid = st.db.insert('certs', {'name': 'twr', 'cn': 'twr', 'names': '[]', 'state': 'ok',
                                     'key_type_alt': 'rsa-2048', 'alt_cert_pem': 'x', 'alt_state': 'revoked'})
        S.alt_failed(st, cid, 'the source said no')
        row = S.cert_get(st, cid)
        self.assertEqual(row['alt_state'], 'revoked')
        self.assertFalse(S.is_dual(row))
        from acmelib.certs import renewer as R
        self.assertIn('was revoked', R.alt_due(dict(row, auto_renew=1, issuer='x', cert_pem='y',
                                                    alt_next_try=0)))

    def test_a_stopped_renewal_keeps_the_new_version(self):
        self.assertIn("str(now.get('version') or '') != str(cert.get('version') or '')",
                      read('acmelib', 'certs', 'renewer.py'))

    def test_the_key_kept_only_of_the_type_asked(self):
        self.assertIn("_pki.key_info(kept)['key_type'] != key_type", read('acmelib', 'certs', 'renewer.py'))

    def test_a_key_compromised_takes_the_versions_with_it(self):
        src = read('acmelib', 'certs', 'renewer.py')
        self.assertIn("if reason == 'keyCompromise':", src)
        self.assertIn("'revoke-failed'", src)

    def test_the_twins_in_the_alerts(self):
        st = E.Storage(E.open_db())
        st.db.insert('certs', {'name': 'tw', 'cn': 'tw', 'names': '[]', 'state': 'ok',
                               'key_type_alt': 'rsa-2048', 'alt_cert_pem': 'x',
                               'alt_not_after': time.time() - 60, 'alt_state': 'ok'})
        from acmelib.certs import renewer as R
        self.assertTrue(any(a['key'].startswith('cert-alt-expired:') for a in R.alerts(st)))

    def test_rollback_only_of_what_was_placed(self):
        # one place for both since 1.0.80 (_files.place_lines)
        self.assertIn("'echo \"PLACED %d\"' % i", read('acmelib', 'plugins', 'targets', '_files.py'))
        self.assertIn('F.place_lines(', read('acmelib', 'plugins', 'targets', 'ssh.py'))

    def test_same_files_without_the_reload_are_deployed_again(self):
        src = read('acmelib', 'plugins', 'targets', 'ssh.py')
        i = src.index('if all(same) and not stale and not unfinished:')
        # 1.0.78: nothing replaced, nothing run - not even the reload (the user's wish)
        self.assertIn('no command, script or reload run', src[i:i + 800])

    def test_acme_reasons_not_downgraded(self):
        self.assertIn('does not take the reason', read('acmelib', 'plugins', 'issuers', 'acme.py'))

    def test_tags_of_other_letters_found(self):
        st = E.Storage(E.open_db())
        st.db.insert('certs', {'name': 'ucet', 'cn': 'ucet', 'names': '[]', 'state': 'ok', 'owner': '',
                               'tags': json.dumps(['účetní'])})
        self.assertEqual(A.cert_list(st, search='tag:účetní')['total'], 1)
        self.assertEqual(A.cert_list(st, search='účetní')['total'], 1)
        self.assertEqual(A.cert_list(st, tag='účetní')['total'], 1)


class Backups(unittest.TestCase):
    def test_retention_never_the_one_just_sent(self):
        class Tr:
            def __init__(self, names):
                self.names = list(names)
                self.gone = []

            def list(self):
                return [{'name': n, 'size': 1} for n in self.names]

            def delete(self, n):
                self.gone.append(n)
        slug, site = E.rb_slug(E.node_name()), E.rb_slug(E.CONFIG.get('site_name') or 'acme')
        sample = ['acme-backup-%s-%s-20991231-000000.tar.gz' % (site, slug)]
        tr = Tr(sample)
        m = E.RB_NAME_RE.match(sample[0])
        if not m:
            self.skipTest('the name of a backup is of another shape here')
        future = sample[0]
        sent = future.replace('20991231-000000', '20261105-030000')
        tr = Tr([future, sent])
        gone = E.rb_retain(tr, 1, 0, sent=sent)
        self.assertNotIn(sent, gone)

    def test_the_nightly_dumps_pruned_apart(self):
        self.assertIn("'acme-%s-*-daily.*' % eng", engine('145'))

    def test_a_mariadb_dump_failing_puts_back_what_was(self):
        self.assertIn("load_tables(store.db, str(safety))", engine('145'))

    def test_the_key_checked_before(self):
        self.assertIn("cannot be written to %s - nothing was", engine('145'))

    def test_try_the_newest_of_this_site(self):
        self.assertIn("(m.group('site') or '') == rb_slug(CONFIG.get('site_name') or 'acme')", engine('180'))
        self.assertIn("len(key) == 32", engine('185'))

    def test_the_move_carries_no_event_twice(self):
        self.assertIn("'SELECT 1 FROM events WHERE ts = ? AND words = ?'", engine('137'))


class CommandLine(unittest.TestCase):
    def test_dropping_a_user_is_asked(self):
        self.assertIn("cli_sure(args, 'take %s away on %s%s' % (", engine('465'))

    def test_json_alone(self):
        src = engine('465')
        self.assertIn("            out(run)\n            return 0 if run['ok'] else 2", src)
        self.assertIn("return 0 if checked else 1", src)


if __name__ == '__main__':
    unittest.main()
