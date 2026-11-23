#!/usr/bin/env python3
"""Hunt u2, the scheduler: what runs when, and what a failure says of the next try.

    python3 test/test_hunt_ru2_scheduler.py

- deployer.run_deploys: a deployment failed by a test after it (checks.after_deploy) was told
  "acme tries again in -" (the certificate's next try, none after a renewal) - not the
  deployment's own wait.
- notices.notify('deploy:<id>'): the renewer's "Deploying X failed" said the certificate's
  next try (none) - not when its failed deployments are tried again.
- api.start_deploy: Deploy now (the whole certificate) while a dry run worked on it was given
  that dry run's job - nothing was deployed.
"""
import json
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-ru2sched-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

import acme as E  # noqa: E402
from acmelib.certs import api, ca as CA, checks, deployer, jobs, notices, renewer  # noqa: E402
from acmelib.certs import store as S  # noqa: E402
from acmelib.plugins import base  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
E.CONFIG['certs_precheck'] = 0
S.registry()


class Ru2Target(base.Target):
    kind = 'ru2target'
    title = 'A target that takes anything (tests)'

    def deploy(self, bundle, options):
        return 'took it'


base.REGISTRY.found['target'][Ru2Target.kind] = Ru2Target

CA_ID = CA.ca_create(STORE, 'Ru2 Root', {'CN': 'Ru2 Root'}, key_type='ec-256', by='t')


def add(table, name, kind, config):
    return STORE.db.insert(table, {'name': name, 'kind': kind, 'config': json.dumps(config),
                                   'state': '{}', 'enabled': 1, 'created': time.time()})


add('cert_issuers', 'own', 'internal_ca', {'ca': CA_ID, 'days': 60})
add('cert_targets', 'box', 'ru2target', {})


def issued(name):
    cid = STORE.db.insert('certs', {
        'name': name, 'names': json.dumps([name]), 'cn': name, 'issuer': 'own',
        'challenge': '', 'challenge_map': '{}', 'key_type': 'ec-256', 'auto_renew': 1,
        'state': 'new', 'enabled': 1, 'version': 0, 'fails': 0, 'ari': '{}', 'profile': '{}',
        'created': time.time()})
    job = jobs.run_now(STORE, 'renew', renewer.renew_job(cid, False, 'test'), cert_id=cid,
                       by='test')
    assert job.ok, job.steps
    return cid


def deployment(cid):
    return STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'box', 'options': '{}',
                                            'enabled': 1, 'state': 'new', 'fails': 0,
                                            'created': time.time() - 3600})


class Sent(object):
    def __enter__(self):
        self.got = []
        self.old = notices.send
        notices.send = lambda store, mid, key, values, *a, **kw: self.got.append(
            (mid, key, dict(values))) or {'mail': [], 'sms': []}
        return self

    def __exit__(self, *a):
        notices.send = self.old


class DeployRetryWords(unittest.TestCase):
    def test_failed_by_test_says_its_own_wait(self):
        cid = issued('tested.example')
        did = deployment(cid)
        cert = S.cert_need(STORE, cid)
        self.assertFalse(cert.get('next_try'))
        old = checks.after_deploy

        def failing(store, job, cert_id, targets=None, failed=None):
            failed['box'] = 'it serves the old certificate'
            return False
        checks.after_deploy = failing
        try:
            with Sent() as s:
                job = jobs.run_now(STORE, 'deploy', deployer.deploy_job(cid), cert_id=cid,
                                   by='test')
        finally:
            checks.after_deploy = old
        self.assertFalse(job.ok)
        dep = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (did,))
        self.assertEqual((dep['state'], dep['fails']), ('failed', 1))
        told = [v for mid, key, v in s.got if mid == 'cert_deploy_failed']
        self.assertEqual(len(told), 1, s.got)
        # its own wait (5 min after the first failure) - not "-"
        self.assertEqual(told[0]['retry'], notices.T.span(S.backoff(1), notices.lang()))
        self.assertIn('tried again in 5 min', '\n'.join(st[2] for st in job.steps))

    def test_renewers_deploy_notice_says_the_deployments_wait(self):
        cid = issued('summary.example')
        did = deployment(cid)
        STORE.db.update('cert_deploys', did, {'state': 'failed', 'fails': 3,
                                              'next_try': time.time() + 1200 + 30})
        self.assertFalse(S.cert_need(STORE, cid).get('next_try'))
        with Sent() as s:
            notices.notify(STORE, 'deploy:%d' % cid, 'Deploying failed', 'box: refused')
        self.assertEqual(len(s.got), 1, s.got)
        self.assertEqual(s.got[0][2]['retry'], notices.T.span(1230, notices.lang()))
        self.assertEqual(s.got[0][2]['target'], 'box')


class DeployNowBesideADryRun(unittest.TestCase):
    def test_not_given_the_dry_runs_job(self):
        cid = issued('dry.example')
        deployment(cid)
        # a dry run of it is at work (its job queued/running, the certificate claimed)
        jobs._claim(STORE, cid)
        dry = jobs.new_job(STORE, 'dry-run', cert_id=cid, by='test')
        try:
            with self.assertRaises(E.ApiError) as cm:
                api.start_deploy(STORE, cid, None, 'test')
            self.assertEqual(cm.exception.status, 409)
            self.assertIn('busy', str(cm.exception))
        finally:
            dry.finish(True, 'done')
            jobs._unclaim(cid, STORE)
            with jobs._LOCK:
                jobs.RUNNING.pop(dry.id, None)
        # a renewal at work still puts it in place: that job is the one given
        jobs._claim(STORE, cid)
        ren = jobs.new_job(STORE, 'renew', cert_id=cid, by='test')
        try:
            self.assertEqual(api.start_deploy(STORE, cid, None, 'test'), ren.id)
        finally:
            ren.finish(True, 'done')
            jobs._unclaim(cid, STORE)
            with jobs._LOCK:
                jobs.RUNNING.pop(ren.id, None)



class Ru2Lasting(base.Target):
    kind = 'ru2lasting'
    title = 'A target that always refuses for good (tests)'

    def deploy(self, bundle, options):
        raise base.PluginError('refused for good', retry=False, lasting=True)


base.REGISTRY.found['target'][Ru2Lasting.kind] = Ru2Lasting


class LastingFailure(unittest.TestCase):
    """1.0.134: a PluginError(lasting=True) (FortiGate EVAL, -324) is not tried again by
    itself - its next try is not within the backoff, and the step says so."""
    def test_not_tried_again_by_itself(self):
        add('cert_targets', 'stuck', 'ru2lasting', {})
        cid = issued('lasting.example.test')
        did = STORE.db.insert('cert_deploys', {'cert_id': cid, 'target': 'stuck',
                                               'options': '{}', 'enabled': 1, 'state': 'new',
                                               'fails': 0, 'created': time.time()})
        job = jobs.run_now(STORE, 'deploy', lambda j: deployer.run_deploys(STORE, j, cid,
                                                                          only=[did]),
                           cert_id=cid, by='test')
        row = STORE.db.row('SELECT * FROM cert_deploys WHERE id = ?', (did,))
        self.assertEqual(row['state'], 'failed')
        self.assertGreater(float(row['next_try']) - time.time(), 300 * 86400)
        words = ' '.join(str(x) for x in job.steps)
        self.assertIn('not tried again by itself', words)

if __name__ == '__main__':
    unittest.main(verbosity=2)
