# -*- coding: utf-8 -*-
"""
A certificate put on its targets: for each deployment (a row of
cert_deploys) the target's module is handed the certificate in every shape
(a Bundle) and the deployment's options, puts it in place, makes the
service take it, and is asked whether it is what is served now.

A deployment that fails is tried again by the renewer after a wait that
doubles each time (5 min, 10, 20 ... certs_retry_max_h at most).

A dual certificate (ECDSA and RSA of the same names): a target that can serve
both (Target.dual - nginx, Apache, HAProxy over SSH, F5, acme's own pages...)
gets the bundle whole, the twin as bundle.alt; any other target gets one of
the two, as its deployment's option `variant` says - 'auto' (the default) the
RSA one, which every client can use.
"""
from __future__ import annotations

import json
import time

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S
from acmelib.certs import runtime
from acmelib.certs.jobs import JobStopped


def hostkey_keeper(store, target_row):
    """fn(known_hosts) that writes the first host key seen into the target's config."""
    def keep(text):
        row = store.db.row('SELECT id, config FROM cert_targets WHERE id = ?', (target_row['id'],))
        if not row:
            return
        cfg = S.jload(row.get('config'), {}) or {}
        if cfg.get('hostkey'):
            return
        cfg['hostkey'] = str(text).strip()
        store.db.update('cert_targets', row['id'], {'config': json.dumps(cfg), 'updated': time.time()})
        store.add_event('certificates', 'the host key of target %s was taken as the first one '
                        'seen (trust_first)' % target_row['name'], 'warn')
    return keep


def target_context(store, job, target_row):
    return runtime.RunContext(store, job, scope='target:%s' % target_row['name'],
                              on_hostkey=hostkey_keeper(store, target_row))


def pick_variant(bundle, options, target_cls):
    """What a target is handed of a (maybe dual) certificate: the bundle whole for
    a target that serves both, else the one its option `variant` says."""
    if bundle.alt is None or getattr(target_cls, 'dual', False):
        return bundle
    want = str((options or {}).get('variant') or 'auto').strip().lower()
    if want == 'auto':
        rsa = [b for b in bundle.variants() if b.family == 'rsa']
        return rsa[0] if rsa else bundle
    try:
        return bundle.variant(want)
    except Exception as e:                              # noqa: BLE001
        raise base.PluginError('the deployment asks for %s: %s' % (want, e), retry=False)


def deploy_one(store, job, cert, dep, force=False):
    """One deployment run. (ok, words). `force`: asked by a person - the target puts it
    in place even where the fingerprint there is the same (options['force'])."""
    t = time.time()
    trow = S.plugin_row(store, 'target', dep['target'])
    step = job.step
    if not trow:
        why = 'there is no target %s' % dep['target']
        _failed(store, dep, why)
        step(why, 'bad')
        return False, why
    if not trow.get('enabled', 1):
        step('target %s is switched off: not deployed' % trow['name'], 'warn')
        return True, 'target switched off'
    if not cert.get('cert_pem'):
        why = 'the certificate %s has not been issued yet' % cert['name']
        step(why, 'bad')
        return False, why
    step('deploying %s (version %s) to %s (%s)' % (cert['name'], cert.get('version'),
                                                  trow['name'], trow['kind']))
    store.db.update('cert_deploys', dep['id'], {'last_try': t, 'state': 'deploying'})
    ctx = target_context(store, job, trow)
    try:
        target = S.plugin_instance(store, 'target', trow, ctx)
        opts = S.deploy_options(store, dep)
        whole = S.bundle_of(cert)
        bundle = pick_variant(whole, opts, type(target))
        if whole.alt is not None:
            if bundle is whole:
                step('dual: both go to %s (%s and %s)' % (
                    trow['name'], whole.key_type, whole.alt.key_type))
            else:
                step('dual: %s holds one certificate - the %s one goes there (its option '
                     '"variant": %s)' % (trow['name'], bundle.key_type,
                                         opts.get('variant') or 'auto'))
        if force:
            opts['force'] = True
        said = target.deploy(bundle, opts)
        job.check()
        if said:
            step(str(said), 'info')
        try:
            seen = target.verify(bundle, opts)
        except base.PluginError as e:
            step('could not be checked: %s' % e, 'warn')
            seen = None
        if seen is False:
            raise base.PluginError('%s does not serve the new certificate after it was put '
                                   'in place' % trow['name'])
        step('%s: in place%s' % (trow['name'], ' and served' if seen else ''), 'ok')
    except JobStopped:
        raise
    except Exception as e:                              # noqa: BLE001
        why = str(e) if isinstance(e, base.PluginError) else '%s: %s' % (type(e).__name__, e)
        if isinstance(e, base.PluginError) and e.detail:
            step(str(e.detail)[:4000], 'debug')
        fails = _failed(store, dep, why)
        store.db.update('cert_targets', trow['id'], {'last_error': why[:2000]})
        step('%s: %s (tried again in %s)' % (trow['name'], why,
                                             E.human_span(S.backoff(fails))), 'bad')
        with E.event_with(**_fields(store, cert, trow, 'deploy', 'failed')):
            store.add_event('certificates', 'deploying %s to %s failed: %s' % (
                cert['name'], trow['name'], why), 'bad')
        _tell(store, 'cert_deploy_failed', 'deploy-one:%s' % dep['id'], cert, trow,
              error=why[:500], retry=_notices().T.span(S.backoff(fails), _notices().lang()))
        return False, why
    finally:
        ctx.tidy()
    t2 = time.time()
    store.db.update('cert_deploys', dep['id'], {
        'state': 'ok', 'deployed_version': S.generation(cert),
        'deployed_fp': cert.get('fingerprint'), 'last_ok': t2, 'last_error': '', 'fails': 0,
        'next_try': None})
    store.db.update('cert_targets', trow['id'], {'last_ok': t2, 'last_error': ''})
    with E.event_with(**_fields(store, cert, trow, 'deployed', 'ok')):
        store.add_event('certificates', '%s (version %s) deployed to %s' % (
            cert['name'], cert.get('version'), trow['name']))
    if _notices().ok_wanted():
        _tell(store, 'cert_deployed', 'deployed:%s:%s' % (dep['id'], cert.get('version')), cert,
              trow)
    return True, 'deployed to %s' % trow['name']


def _notices():
    from acmelib.certs import notices
    return notices


def _fields(store, cert, trow, action, result):
    try:
        from acmelib.certs import monitor
        return monitor.fields_of(store, cert, action=action, result=result,
                                 target=trow['name'], target_kind=trow.get('kind'),
                                 version=cert.get('version'))
    except Exception:                                   # noqa: BLE001
        return {'cert': cert.get('name'), 'target': trow.get('name'), 'action': action,
                'result': result}


def _tell(store, mid, key, cert, trow, **more):
    """A notification about one deployment, in the words of the texts. Never raises."""
    try:
        n = _notices()
        if mid == 'cert_deploy_failed':
            # The renewer says the same of the whole renewal: not twice.
            store.set_meta('certs:notified:deploycert:%s' % cert['id'], str(time.time()))
        n.send(store, mid, key, n.cert_values(store, cert, target=trow['name'], **more))
    except Exception as e:                              # noqa: BLE001
        E.log('telling about the deployment of %s: %s' % (cert.get('name'), e), 'warn')


def _failed(store, dep, why):
    fails = int(dep.get('fails') or 0) + 1
    store.db.update('cert_deploys', dep['id'], {
        'state': 'failed', 'last_error': str(why)[:2000], 'fails': fails,
        'next_try': time.time() + S.backoff(fails)})
    return fails


def deploys_of(store, cert_id, only=None, enabled=True):
    rows = store.db.rows('SELECT * FROM cert_deploys WHERE cert_id = ? ORDER BY position, id',
                         (cert_id,))
    if only:
        want = {int(x) for x in only}
        rows = [r for r in rows if r['id'] in want]
    elif enabled:
        rows = [r for r in rows if r.get('enabled', 1)]
    return rows


def run_deploys(store, job, cert_id, only=None, force=False):
    """Every enabled deployment of the certificate (or those asked). (all_ok, words)."""
    cert = S.cert_need(store, cert_id)
    told_renewed(store, job, cert_id)
    rows = deploys_of(store, cert_id, only)
    if not rows:
        job.step('no deployment to run')
        return True, 'nothing to deploy'
    good, bad = 0, []
    for dep in rows:
        job.check()
        ok, said = deploy_one(store, job, cert, dep, force)
        if ok:
            good += 1
        else:
            bad.append('%s: %s' % (dep['target'], said))
    if bad:
        return False, '%d of %d deployment(s) failed - %s' % (len(bad), len(rows), '; '.join(bad))
    return True, '%d deployment(s) done' % good


def told_renewed(store, job, cert_id):
    """After a renewal (a job of kind renew that made a version): told, when
    certs_notify_ok says so. Never raises."""
    try:
        n = _notices()
        if getattr(job, 'kind', '') != 'renew' or not getattr(job, 'version', None) or \
                not n.ok_wanted():
            return
        cert = S.cert_need(store, cert_id)
        n.send(store, 'cert_renewed', 'renewed:%s:%s' % (cert_id, job.version),
               n.cert_values(store, cert))
    except Exception as e:                              # noqa: BLE001
        E.log('telling about a renewal: %s' % e, 'warn')


def deploy_job(cert_id, only=None, force=False):
    """A job's function: the deployments of one certificate (force: asked by a person)."""
    def fn(job):
        return run_deploys(job.store, job, cert_id, only, force)
    return fn
