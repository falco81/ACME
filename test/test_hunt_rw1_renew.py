#!/usr/bin/env python3
"""Hunt w1 (the certificate lifecycle: the renewer's look, ARI, due):

- ARI asked for a row read at the start of the look: a renewal that ended meanwhile (Renew now,
  the command line) had the window of the certificate before written over the new one's - the
  new certificate was renewed again at the old one's moment (twice);
- the look decided "due" on the row read at its start: a certificate failed (its wait over) or
  not issued yet, renewed by a person while the look asked the CA's ARI of the others, was
  ordered a second time right after;
- `acme --renew all` (and the console's "Renew every one that is due") took the twin of a
  source that gives none (a paid one, "Allow the twin" switched off) as due - a job that did
  nothing at every run, said as renewed.

    python3 test/test_hunt_rw1_renew.py
"""
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-rw1-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import acme as E  # noqa: E402
from acmelib.certs import jobs, pki, renewer, store as S  # noqa: E402
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry()


class AriCa(base.Issuer):
    """Signs itself; its ARI window is what the test says, and asking it may run `during`."""
    kind = 'rw1ari'
    title = 'ARI CA (tests)'
    dual = True
    WINDOW = None
    during = None
    issued = []

    def issue(self, req):
        AriCa.issued.append(req.key_type)
        return base.Issued(pki.self_signed(req.key_pem, req.names, days=90), [])

    def renewal_window(self, cert_pem):
        if AriCa.during:
            fn, AriCa.during = AriCa.during, None
            fn()
        return AriCa.WINDOW


class PaidTwinCa(AriCa):
    kind = 'rw1paid'
    dual = False
    dual_field = 'dual_order'
    fields = [base.dual_order_field()]


for cls in (AriCa, PaidTwinCa):
    base.REGISTRY.found['issuer'][cls.kind] = cls


def add_issuer(name, kind, config=None):
    return STORE.db.insert('cert_issuers', {'name': name, 'kind': kind,
                                            'config': json.dumps(config or {}), 'state': '{}',
                                            'enabled': 1, 'created': time.time()})


def cert(name, issuer, alt=''):
    return STORE.db.insert('certs', {
        'name': name, 'names': json.dumps([name]), 'cn': name, 'issuer': issuer,
        'challenge': '', 'challenge_map': '{}', 'key_type': 'ec-256', 'key_type_alt': alt,
        'auto_renew': 1, 'state': 'new', 'enabled': 1, 'version': 0, 'fails': 0, 'ari': '{}',
        'profile': '{}', 'created': time.time() - 7200})


def renew(cid, only=None):
    job = jobs.run_now(STORE, 'renew', renewer.renew_job(cid, False, 'test', only), cert_id=cid,
                       by='test')
    assert job.ok, '\n'.join(s[2] for s in job.steps)
    return job


def wait_idle(cid, s=20):
    end = time.time() + s
    while time.time() < end and jobs.cert_busy(STORE, cid):
        time.sleep(0.05)


add_issuer('aric', 'rw1ari')
add_issuer('paidc', 'rw1paid')


class AriStaleRow(unittest.TestCase):
    def tearDown(self):
        AriCa.WINDOW = None
        AriCa.during = None

    def test_window_of_the_one_before_not_written_over_the_new_one(self):
        cid = cert('ari-stale.example', 'aric')
        renew(cid)
        old = S.cert_get(STORE, cid)
        # the old one's ARI asked six hours ago; its CA now says: renew it (a window past)
        STORE.db.update('certs', cid, {'ari': json.dumps({'checked': time.time() - 7 * 3600})})
        stale = S.cert_get(STORE, cid)
        AriCa.WINDOW = (time.time() - 3600, time.time() - 60)
        # ...while it is asked, the certificate is renewed (Renew now, another process)
        AriCa.during = lambda: renew(cid)
        renewer.ari_refresh(STORE, stale)
        now = S.cert_get(STORE, cid)
        self.assertNotEqual(now['cert_pem'], old['cert_pem'])
        ari = S.jload(now['ari'], {})
        self.assertFalse(ari.get('at'), ari)                 # not the old one's moment
        self.assertEqual(renewer.main_due(now), '')
        # the new one asked for itself afterwards: its own window counts
        AriCa.WINDOW = (time.time() - 3600, time.time() - 60)
        renewer.ari_refresh(STORE, now)
        self.assertIn('ARI', renewer.main_due(S.cert_get(STORE, cid)))

    def test_twin_window_kept_to_its_own_twin(self):
        cid = cert('ari-twin.example', 'aric', alt='rsa-2048')
        renew(cid)
        STORE.db.update('certs', cid, {'alt_ari': json.dumps({'checked': time.time() - 7 * 3600})})
        stale = S.cert_get(STORE, cid)
        AriCa.WINDOW = (time.time() - 3600, time.time() - 60)
        AriCa.during = lambda: renew(cid, only='alt')
        renewer.ari_refresh(STORE, stale, 'alt')
        now = S.cert_get(STORE, cid)
        self.assertNotEqual(now['alt_cert_pem'], stale['alt_cert_pem'])
        self.assertFalse(S.jload(now['alt_ari'], {}).get('at'))
        self.assertEqual(renewer.alt_due(now), '')


class ScanStaleRow(unittest.TestCase):
    def tearDown(self):
        AriCa.during = None

    def test_failed_one_renewed_meanwhile_is_not_ordered_again(self):
        # another certificate asked for its ARI first (the look is slow): meanwhile this one
        # is renewed by a person
        other = cert('scan-other.example', 'aric')
        renew(other)
        cid = cert('scan-failed.example', 'aric')
        renew(cid)
        STORE.db.update('certs', cid, {'state': 'failed', 'next_try': time.time() - 10,
                                       'fails': 1})
        STORE.db.update('certs', other, {'ari': json.dumps({'checked': 0})})
        AriCa.during = lambda: renew(cid)
        versions = lambda: STORE.db.value('SELECT COUNT(*) FROM cert_versions WHERE cert_id = ?',
                                          (cid,), 0)
        before = versions()
        renewer.scan(STORE)
        wait_idle(cid)
        self.assertEqual(versions(), before + 1,
                         'renewed by the person, then ordered again by the look')
        self.assertEqual(S.cert_get(STORE, cid)['state'], 'ok')


class RenewAllTwin(unittest.TestCase):
    def test_twin_of_a_source_that_gives_none_is_not_due_at_the_command_line(self):
        from acmelib.certs import cli
        cid = cert('paid-twin.example', 'paidc', alt='rsa-2048')
        renew(cid)
        row = S.cert_get(STORE, cid)
        self.assertIsNone(row['alt_cert_pem'])
        self.assertEqual(renewer.main_due(row), '')
        c = cli.Cli.__new__(cli.Cli)
        c.store = STORE
        c.json = False
        c.WHO = 'test'
        c.args = type('A', (), {'renew': 'all', 'force': False})()
        ran = []
        c._run_job = lambda *a, **k: ran.append(a) or type('J', (), {'ok': True})()
        before = list(AriCa.issued)
        c.renew()
        self.assertFalse([a for a in ran if a[2] == cid], 'the paid twin taken as due')
        # with the twin allowed it is due (not issued yet)
        STORE.db.run("UPDATE cert_issuers SET config = ? WHERE name = 'paidc'",
                     (json.dumps({'dual_order': True}),))
        try:
            c.renew()
            self.assertTrue([a for a in ran if a[2] == cid])
        finally:
            STORE.db.run("UPDATE cert_issuers SET config = '{}' WHERE name = 'paidc'")
        self.assertEqual(AriCa.issued, before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
