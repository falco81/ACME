#!/usr/bin/env python3
"""Hunt N round 1 (1.0.102), the lifecycles: what was found and is shut now - each checked here.

    python3 test/test_hunt_n1.py

In this process, no network: certificates issued by an authority of acme's own. A key revoked
is known after a configuration's export and import (and never kept again); a renewal killed at
the command line is ended as failed, its lease taken over at once; a certificate issued again
after a revoke is renewed by itself as before; the answer to a CSR checked for its names, and
its key carried in the configuration's file; the alerts of deployments nothing tries again; the
option `variant` of a deployment checked; Renew now while a deployment runs; and the command
line: the first issue logged as one, --revoke refused as the pages refuse it, --reissue,
--cert-del --revoke-first, --cert-keep, --approve, --decline.
"""
import base64
import collections
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-huntn1-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "testnode", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme as E  # noqa: E402
from acmelib.certs import api as A, ca as CA, jobs, pki, renewer, store as S  # noqa: E402
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry()
CA_ID = CA.ca_create(STORE, 'Hunt N Root', {'CN': 'Hunt N Root'}, key_type='ec-256', by='t')
ACME = [sys.executable, os.path.join(ROOT, 'acme.py')]
ENV = dict(os.environ, ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')


class OneTarget(base.Target):
    kind = 'huntnone'
    title = 'One certificate at a time (tests)'

    def deploy(self, bundle, options):
        return 'took it'


base.REGISTRY.found['target'][OneTarget.kind] = OneTarget


def add(table, name, kind, config):
    return STORE.db.insert(table, {'name': name, 'kind': kind, 'config': json.dumps(config),
                                   'state': '{}', 'enabled': 1, 'created': time.time()})


add('cert_issuers', 'own', 'internal_ca', {'ca': CA_ID, 'days': 60})
add('cert_issuers', 'self', 'selfsigned', {})
add('cert_targets', 'one', 'huntnone', {})


def cert(name, names, issuer='own', reuse_key=0, auto_renew=1):
    return STORE.db.insert('certs', {
        'name': name, 'names': json.dumps(names), 'cn': names[0], 'issuer': issuer,
        'challenge': '', 'challenge_map': '{}', 'key_type': 'ec-256', 'auto_renew': auto_renew,
        'reuse_key': reuse_key, 'state': 'new', 'enabled': 1, 'version': 0, 'fails': 0,
        'ari': '{}', 'profile': '{}', 'created': time.time()})


def renew(cid, force=True):
    return jobs.run_now(STORE, 'renew', renewer.renew_job(cid, force, 'test'), cert_id=cid,
                        by='test')


def revoke(cid, reason='unspecified', again=False):
    return jobs.run_now(STORE, 'revoke', A.revoke_job(S.cert_get(STORE, cid), reason, 'test',
                                                       again), cert_id=cid, by='test')


def words(job):
    return '\n'.join(s[2] for s in job.steps)


class FakeH(object):
    def __init__(self, body=None):
        self.store, self._body, self.args, self.headers = STORE, dict(body or {}), {}, {}

    def me(self, _role='readonly'):
        return {'name': 'boss', 'role': 'fulladmin',
                'account': {'name': 'boss', 'role': 'fulladmin', 'source': 'local'}}

    def session(self, kind):
        return self.me()

    def body(self):
        return self._body

    def arg(self, name, default=''):
        return self.args.get(name, default)


def call(path, body):
    return E.ROUTES[('POST', path)](FakeH(body))


def moved(table_rows, name, new_id):
    """The file's row of `name`, given another number (as a machine where its own is taken)."""
    return [dict(r, id=new_id) for r in table_rows if r.get('name') == name]


def drop(cid):
    S.cert_leftovers(STORE, cid)
    STORE.db.run('DELETE FROM certs WHERE id = ?', (cid,))


def dead_pid():
    p = subprocess.Popen(['true'])
    p.wait()
    return p.pid


class RevokedKeyCarried(unittest.TestCase):
    def test_a_key_revoked_after_an_import_is_never_kept(self):
        cid = cert('rk', ['rk.example'], reuse_key=1)
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        pub0 = pki.cert_info(S.cert_get(STORE, cid)['cert_pem'])['pub_sha256']
        # exported with the secrets, put in on "another machine" under another number
        rows = moved(E.carry_export(STORE, True)['certs'], 'rk', 900)
        drop(cid)
        E.carry_import(STORE, {'certs': rows}, 'test', False, collections.Counter())
        row = S.cert_get(STORE, 'rk')
        self.assertEqual(row['id'], 900)
        self.assertFalse(STORE.db.value('SELECT COUNT(*) FROM cert_versions WHERE cert_id = 900'))
        self.assertTrue(pki.key_matches(row['cert_pem'], S.cert_key(row)))
        # revoked for keyCompromise there - written down although it has no versions
        job = revoke(900, 'keyCompromise')
        self.assertTrue(job.ok, words(job))
        self.assertIn(pub0.upper(), S.revoked_keys_meta(STORE, 900))
        self.assertIn(pub0.upper(), {k.upper() for k in renewer._revoked_keys(STORE, 900)})
        # the new one failed once: "failed", not "revoked" - the one it holds still known revoked
        STORE.db.update('certs', 900, {'state': 'failed'})
        self.assertTrue(S.current_revoked(STORE, S.cert_get(STORE, 900)))
        job = renew(900)
        self.assertTrue(job.ok, words(job))
        self.assertIn('it was revoked: a new key', words(job))
        self.assertNotIn('the key it has is kept', words(job))
        pub1 = pki.cert_info(S.cert_get(STORE, 900)['cert_pem'])['pub_sha256']
        self.assertNotEqual(pub0, pub1)
        # ...and what is revoked goes on in the next file, without the secrets too
        out = [r for r in E.carry_export(STORE, False)['certs'] if r['name'] == 'rk'][0]
        self.assertIn(pub0.upper(), json.loads(out['_meta']['revkeys'])['keys'])
        drop(900)

    def test_a_kept_key_once_revoked_is_not_kept(self):
        cid = cert('rk2', ['rk2.example'], reuse_key=1)
        self.assertTrue(renew(cid).ok)
        row = S.cert_get(STORE, cid)
        S.revoked_keys_add(STORE, cid, [pki.cert_info(row['cert_pem'])['pub_sha256']])
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertIn('a new key', words(job))
        self.assertFalse(pki.key_matches(S.cert_get(STORE, cid)['cert_pem'], S.cert_key(row)))
        drop(cid)


class AutoRenewAfterRevoke(unittest.TestCase):
    def test_renew_now_after_a_revoke_renews_by_itself_again(self):
        cid = cert('ar', ['ar.example'])
        self.assertTrue(renew(cid).ok)
        self.assertTrue(revoke(cid).ok)
        row = S.cert_get(STORE, cid)
        self.assertEqual((row['state'], row['auto_renew']), ('revoked', 0))
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        row = S.cert_get(STORE, cid)
        self.assertEqual((row['state'], row['auto_renew']), ('ok', 1))
        self.assertIsNone(STORE.get_meta(S.CERT_META['revauto'] % cid))
        drop(cid)

    def test_by_hand_stays_by_hand(self):
        cid = cert('ah', ['ah.example'], auto_renew=0)
        self.assertTrue(renew(cid).ok)
        self.assertTrue(revoke(cid, 'superseded').ok)
        job = renew(cid)
        self.assertTrue(job.ok, words(job))
        self.assertEqual(S.cert_get(STORE, cid)['auto_renew'], 0)
        # revoked and a new one at once: renewed by itself (as since 1.0.77)
        self.assertTrue(revoke(cid, 'superseded', again=True).ok)
        self.assertEqual(S.cert_get(STORE, cid)['auto_renew'], 1)
        drop(cid)


class CsrAnswer(unittest.TestCase):
    def test_carried_and_its_names_checked(self):
        cid = STORE.db.insert('certs', {
            'name': 'cs', 'names': json.dumps(['cs.example.com', 'www.cs.example.com']),
            'cn': 'cs.example.com', 'issuer': '', 'challenge': '', 'challenge_map': '{}',
            'key_type': 'ec-256', 'auto_renew': 0, 'state': 'new', 'enabled': 1, 'version': 0,
            'fails': 0, 'ari': '{}', 'profile': '{}', 'created': time.time()})
        csr = call('/api/certs/csr', {'id': cid})['csr_pem']
        # the file without the secrets: no key of the CSR at all; with them: in clear
        bare = [r for r in E.carry_export(STORE, False)['certs'] if r['name'] == 'cs'][0]
        self.assertNotIn('key', json.loads(bare['csr_pending']).get('key_sealed', '') +
                         ''.join(json.loads(bare['csr_pending'])))
        rows = moved(E.carry_export(STORE, True)['certs'], 'cs', 901)
        self.assertIn('BEGIN', json.loads(rows[0]['csr_pending'])['key_pem'])
        drop(cid)
        E.carry_import(STORE, {'certs': rows}, 'test', False, collections.Counter())
        pend = json.loads(S.cert_get(STORE, 901)['csr_pending'])
        self.assertNotIn('key_pem', pend)
        key = E.unseal_secret(pend['key_sealed'], 'certs:901:csr_pending')
        self.assertTrue(key)
        self.assertEqual(pend['csr_pem'], csr)
        # an answer for other names (the same key): refused in words, taken with force
        other = pki.make_csr(key, ['evil.example.org'])[0]
        pem, chain = CA.ca_sign(STORE, CA_ID, other, 30)
        body = {'id': 901, 'data_b64': base64.b64encode(pem.encode()).decode(),
                'filename': 'answer.pem'}
        with self.assertRaises(ValueError) as e:
            call('/api/certs/csr_answer', body)
        self.assertIn('the answer is not for cs: it lacks cs.example.com, www.cs.example.com',
                      str(e.exception))
        self.assertIn('with force', str(e.exception))
        # the right one is taken (after the import: its key opens here)
        good, _chain = CA.ca_sign(STORE, CA_ID, csr, 30)
        got = call('/api/certs/csr_answer', dict(body, data_b64=base64.b64encode(
            good.encode()).decode()))
        self.assertEqual(got['version'], 1)
        drop(901)

    def test_force_takes_other_names(self):
        cid = STORE.db.insert('certs', {
            'name': 'cs2', 'names': json.dumps(['cs2.example.com']), 'cn': 'cs2.example.com',
            'issuer': '', 'challenge': '', 'challenge_map': '{}', 'key_type': 'ec-256',
            'auto_renew': 0, 'state': 'new', 'enabled': 1, 'version': 0, 'fails': 0,
            'ari': '{}', 'profile': '{}', 'created': time.time()})
        call('/api/certs/csr', {'id': cid})
        pend = json.loads(S.cert_get(STORE, cid)['csr_pending'])
        key = E.unseal_secret(pend['key_sealed'], 'certs:%d:csr_pending' % cid)
        pem, _c = CA.ca_sign(STORE, CA_ID, pki.make_csr(key, ['x.example.org'])[0], 30)
        got = call('/api/certs/csr_answer', {
            'id': cid, 'data_b64': base64.b64encode(pem.encode()).decode(),
            'filename': 'a.pem', 'force': 1})
        self.assertEqual(got['version'], 1)
        drop(cid)


class LeftByACommandLine(unittest.TestCase):
    def left(self, name):
        cid = cert(name, ['%s.example' % name])
        self.assertTrue(renew(cid).ok)
        STORE.db.update('certs', cid, {'state': 'renewing'})
        pid = dead_pid()
        jid = STORE.db.insert('cert_jobs', {
            'ts': time.time() - 30, 'kind': 'renew', 'cert_id': cid, 'node': E.node_name(),
            'state': 'running', 'steps': '[]', 'by_who': 'command line', 'said': ''})
        mark = jobs._cli_mark(jid)
        mark.parent.mkdir(parents=True, exist_ok=True)
        mark.write_text('%d x\n' % pid)
        STORE.set_meta(jobs._lease_key(cid), '%s|%d|%d' % (E.node_name(), pid, int(time.time())))
        return cid, jid

    def test_the_scan_ends_it(self):
        cid, jid = self.left('kl')
        self.assertGreaterEqual(renewer.orphans(STORE), 1)
        self.assertEqual(STORE.db.value('SELECT state FROM cert_jobs WHERE id = ?', (jid,)),
                         'failed')
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['state'], 'failed')
        self.assertIn('command line', row['last_error'])
        self.assertIn('cert-failed:%d' % cid, [a['key'] for a in renewer.alerts(STORE)])
        self.assertFalse(jobs._cli_mark(jid).exists())
        self.assertTrue(STORE.db.value("SELECT COUNT(*) FROM events WHERE words LIKE ?",
                                       ('%%job %d%%command line that is gone%%' % jid,)))
        drop(cid)

    def test_taken_over_at_once(self):
        cid, jid = self.left('kt')
        self.assertFalse(jobs.cert_busy(STORE, cid))
        jobs._claim(STORE, cid)                         # no 409 for a minute (or two hours)
        jobs._unclaim(cid, STORE)
        drop(cid)

    def test_a_lease_of_a_dead_daemon(self):
        cid = cert('kd', ['kd.example'])
        STORE.set_meta(jobs._lease_key(cid), '%s|%d|%d' % (E.node_name(), dead_pid(),
                                                         int(time.time())))
        jobs._claim(STORE, cid)
        jobs._unclaim(cid, STORE)
        # one of a process that lives (this one's): kept for its minute
        STORE.set_meta(jobs._lease_key(cid), '%s|%d|%d' % (E.node_name(), os.getppid(),
                                                         int(time.time())))
        with self.assertRaises(ValueError):
            jobs._claim(STORE, cid)
        STORE.db.run('DELETE FROM meta WHERE k = ?', (jobs._lease_key(cid),))
        drop(cid)

    def test_a_live_command_line_is_not_touched(self):
        cid = cert('kv', ['kv.example'])
        STORE.db.update('certs', cid, {'state': 'renewing'})
        jid = STORE.db.insert('cert_jobs', {
            'ts': time.time(), 'kind': 'renew', 'cert_id': cid, 'node': E.node_name(),
            'state': 'running', 'steps': '[]', 'by_who': 'command line', 'said': ''})
        jobs._cli_mark_write(jid)          # this process: alive
        try:
            self.assertEqual(jobs.reap_cli(STORE), [])
            self.assertTrue(jobs.cert_busy(STORE, cid))
        finally:
            jobs._cli_mark(jid).unlink()
            STORE.db.update('cert_jobs', jid, {'state': 'failed'})
        drop(cid)


class Alerts(unittest.TestCase):
    def test_deploy_alert_only_while_tried_again(self):
        cid = cert('al', ['al.example'])
        self.assertTrue(renew(cid).ok)
        did = STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'one', 'options': '{}',
                                               'state': 'failed', 'enabled': 1, 'fails': 1,
                                               'last_error': 'nope', 'created': time.time()})
        key = 'cert-deploy:%d' % did

        def keys():
            return [a['key'] for a in renewer.alerts(STORE)]
        self.assertIn(key, keys())
        STORE.db.update('certs', cid, {'enabled': 0})
        self.assertNotIn(key, keys())
        STORE.db.update('certs', cid, {'enabled': 1})
        STORE.db.run("UPDATE cert_targets SET enabled = 0 WHERE name = 'one'")
        self.assertNotIn(key, keys())
        STORE.db.run("UPDATE cert_targets SET enabled = 1 WHERE name = 'one'")
        self.assertIn(key, keys())
        self.assertTrue(revoke(cid).ok)
        self.assertNotIn(key, keys())
        # a new one failed after: "failed", the one held revoked - not deployed, no alert
        STORE.db.update('certs', cid, {'state': 'failed'})
        self.assertNotIn(key, keys())
        drop(cid)


class DeployVariant(unittest.TestCase):
    def test_variant_checked(self):
        cid = cert('va', ['va.example'])
        with self.assertRaises(ValueError) as e:
            A.deploy_save(STORE, {'cert_id': cid, 'target': 'one',
                                  'options': {'variant': 'both'}}, 'test')
        self.assertIn('not both', str(e.exception))
        self.assertEqual(getattr(e.exception, 'field', ''), 'variant')
        self.assertFalse(STORE.db.value('SELECT COUNT(*) FROM cert_deploys WHERE cert_id = ?',
                                        (cid,)))
        A.deploy_save(STORE, {'cert_id': cid, 'target': 'one', 'options': {'variant': 'rsa'}},
                      'test')
        drop(cid)


class RenewWhileDeploying(unittest.TestCase):
    def test_409_unless_a_renewal_runs(self):
        cid = cert('rd', ['rd.example'])
        self.assertTrue(renew(cid).ok)
        jid = STORE.db.insert('cert_jobs', {
            'ts': time.time(), 'kind': 'deploy', 'cert_id': cid, 'node': 'othernode',
            'state': 'running', 'steps': '[]', 'by_who': 'x', 'said': ''})
        with self.assertRaises(E.ApiError) as e:
            A.start_renew(STORE, cid, False, 'test')
        self.assertEqual(e.exception.status, 409)
        self.assertIn('busy with another job (deploy, job %d)' % jid, str(e.exception))
        STORE.db.update('cert_jobs', jid, {'kind': 'renew'})
        self.assertEqual(A.start_renew(STORE, cid, False, 'test'), jid)
        STORE.db.update('cert_jobs', jid, {'state': 'ok'})
        drop(cid)


def cli(*args):
    return subprocess.run(ACME + list(args), env=ENV, capture_output=True, text=True,
                          timeout=300)


class CommandLine(unittest.TestCase):
    def test_issue_revoke_reissue_delete(self):
        got = cli('--cert-add', 'cl1', '--names', 'cl1.example', '--issuer', 'own')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        got = cli('--renew', 'cl1')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        cid = S.cert_get(STORE, 'cl1')['id']
        self.assertEqual(STORE.db.value('SELECT kind FROM cert_jobs WHERE cert_id = ? ORDER BY '
                                        'id LIMIT 1', (cid,)), 'issue')
        v1 = S.cert_get(STORE, cid)['version']
        got = cli('--revoke', 'cl1', '--reason', 'keyCompromise', '--reissue', '--yes')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        row = S.cert_get(STORE, cid)
        self.assertEqual(row['state'], 'ok')
        self.assertGreater(row['version'], v1)
        # kept after a failed revocation
        STORE.db.update('certs', cid, {'state': 'revoke-failed'})
        got = cli('--cert-keep', 'cl1')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(S.cert_get(STORE, cid)['state'], 'ok')
        got = cli('--cert-del', 'cl1', '--revoke-first', '--yes')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertIsNone(S.cert_get(STORE, cid))

    def test_revoke_refused_as_the_pages_refuse_it(self):
        cid = cert('cl2', ['cl2.example'], issuer='self')
        self.assertTrue(renew(cid).ok)
        got = cli('--revoke', 'cl2', '--yes')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('a self-signed certificate has no CA', got.stderr)
        self.assertFalse(STORE.db.value("SELECT COUNT(*) FROM cert_jobs WHERE cert_id = ? AND "
                                        "kind = 'revoke'", (cid,)))
        drop(cid)

    def test_approve_and_decline(self):
        ids = []
        for n in ('cl3', 'cl4'):
            cid = cert(n, ['%s.example' % n], auto_renew=0)
            STORE.db.update('certs', cid, {'state': 'pending-approval', 'owner': 'eva'})
            ids.append(cid)
        got = cli('--decline', 'cl4')
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('--why', got.stderr)
        got = cli('--decline', 'cl4', '--why', 'not ours')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(S.cert_get(STORE, ids[1])['state'], 'declined')
        got = cli('--approve', 'cl3')
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        row = S.cert_get(STORE, ids[0])
        self.assertEqual((row['state'], row['version'], row['auto_renew']), ('ok', 1, 1))
        for cid in ids:
            drop(cid)


if __name__ == '__main__':
    unittest.main(verbosity=2)
