# -*- coding: utf-8 -*-
"""
A certificate put on its targets: for each deployment (a row of
cert_deploys) the target's module is handed the certificate in every shape
(a Bundle) and the deployment's options, puts it in place and makes the
service take it. What is served afterwards is checked by the tests attached to
the certificate only (1.0.92; checks.after_deploy) - a failing one fails the
deployment on its target.

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
from acmelib.certs import jobs
from acmelib.certs.jobs import JobStopped


def hostkey_keeper(store, target_row):
    """fn(known_hosts) that writes the first host key seen into the target's config."""
    def keep(text, field='hostkey'):
        # the field the connection reads (1.0.51): OPNsense's is ssh_hostkey - its key was
        # written as hostkey, never read, and any key taken on every run
        field = str(field or 'hostkey') if str(field or '').endswith('hostkey') else 'hostkey'
        row = store.db.row('SELECT id, config FROM cert_targets WHERE id = ?', (target_row['id'],))
        if not row:
            return
        cfg = S.jload(row.get('config'), {}) or {}
        if cfg.get(field):
            return
        cfg[field] = str(text).strip()
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

    def step(words, level='info'):                      # isemon's line names the target
        jobs.step_in(job, words, level, scope='target:%s' % dep['target'])
    if not trow:
        why = 'there is no target %s' % dep['target']
        _failed(store, dep, why)
        step(why, 'bad')
        return False, why
    if not trow.get('enabled', 1):
        step('target %s is switched off: not deployed' % trow['name'], 'warn')
        return None, 'target switched off'          # neither done nor failed (1.0.77)
    if not cert.get('cert_pem'):
        why = 'the certificate %s has not been issued yet' % cert['name']
        step(why, 'bad')
        return False, why
    # The key made by a device (certs.csr_from, devicekey.py): the certificate goes to that
    # target alone, and such a target takes no other certificate.
    from acmelib.certs import devicekey
    why = devicekey.deploy_problem(store, cert, trow)
    if why:
        _failed(store, dep, why)
        step(why, 'bad')
        return False, why
    step('deploying %s (version %s) to %s (%s)%s' % (
        cert['name'], cert.get('version'), trow['name'], trow['kind'],
        ' - the certificate for the key its device made (acme holds no key)'
        if cert.get('csr_from') else ''))
    store.db.update('cert_deploys', dep['id'], {'last_try': t, 'state': 'deploying'})
    ctx = target_context(store, job, trow)
    ctx.deploy_id = dep['id']       # what a target wrote for this deployment is kept by it
    ctx.target_name = trow['name']  # ACME_TARGET of a script after the files
    try:
        target = S.plugin_instance(store, 'target', trow, ctx)
        opts = S.deploy_options(store, dep)
        generated_password(store, dep, opts, step)
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
        # What is served is looked at by the tests attached to the certificate only (1.0.92):
        # the module's own check after the push (a handshake to names it guessed - isemon's
        # node named merit.cz, the company's web answering there) failed a deployment that
        # was put in and served. The tests run after it (checks.after_deploy) and, failing,
        # fail it.
        step('%s: in place - %s' % (trow['name'], _tested_words(store, cert, trow['name'])),
             'ok')
    except JobStopped:
        # Stopped half way (a restart, an upgrade, Stop pressed) - not left "deploying"
        # (1.0.44), which the renewer passes over: the target kept the old certificate
        # until the next renewal, a month after the old one ran out. Tried again soon.
        try:
            store.db.update('cert_deploys', dep['id'], {
                'state': 'failed', 'last_error': 'stopped before it was done',
                'next_try': time.time() + 300})
        except Exception:                               # noqa: BLE001
            pass
        raise
    except Exception as e:                              # noqa: BLE001
        why = str(e) if isinstance(e, base.PluginError) else '%s: %s' % (type(e).__name__, e)
        if cert.get('csr_from') and 'key' in why.lower():
            why = ('%s is issued for the key the device of %s made, so acme holds no key (%s)'
                   % (cert['name'], cert['csr_from'], why))
        elif cert.get('csr_given') and 'key' in why.lower():
            why = ('%s was issued for a CSR that was sent in, so acme holds no key, and %s needs '
                   'one (%s) - deploy it where only the certificate is needed, or put it in place '
                   'by hand beside its key' % (cert['name'], trow['name'], why))
        elif not cert.get('key_sealed') and 'key' in why.lower():
            # Imported without its key (a file, or Import from a source): the certificate
            # alone goes where only it is needed; here the key is wanted too.
            why = ('acme does not hold the private key of %s yet, and %s needs it (%s) - add '
                   'it in the certificate\'s window (Add its private key), or deploy it where '
                   'only the certificate is needed' % (cert['name'], trow['name'], why))
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
    return True, 'deployed to %s' % trow['name']


def _tested_words(store, cert, target):
    """What says what is served there (1.0.93): the tests attached, or that none does."""
    try:
        from acmelib.certs import checks
        if not E.CONFIG.get('certs_checks_after_deploy', 1):
            return 'tests after a deployment are switched off (Settings → Certificates)'
        # as after_deploy picks them (1.0.95): a test switched off, or one gone, checks nothing
        for r in store.db.rows('SELECT c.after_target FROM cert_checks c JOIN cert_tests t ON '
                               't.name = c.test WHERE c.cert_id = ? AND COALESCE(c.enabled, 1) '
                               '<> 0 AND COALESCE(t.enabled, 1) <> 0', (cert['id'],)):
            have = checks.after_list(r.get('after_target'))
            if checks.AFTER_NONE not in have and (not have or target in have):
                return 'what it serves is checked by the tests attached'
    except Exception:                                   # noqa: BLE001
        pass
    return 'no test attached checks what it serves (the certificate → Tests → Attach a test)'


def _told_deployed(store, cert, dep):
    """Its event and notice (1.0.93: after the tests of the certificate - a deployment a test
    then failed was said deployed first, every five minutes)."""
    trow = S.plugin_row(store, 'target', dep['target']) or {'name': dep['target']}
    with E.event_with(**_fields(store, cert, trow, 'deployed', 'ok')):
        store.add_event('certificates', '%s (version %s) deployed to %s' % (
            cert['name'], cert.get('version'), trow['name']))
    if _notices().ok_wanted():
        _tell(store, 'cert_deployed', 'deployed:%s:%s' % (dep['id'], cert.get('version')), cert,
              trow)


def generated_password(store, dep, opts, step=None, again=False):
    """A deployment whose PKCS#12 / keystore password acme makes (pfx_password_mode
    'generate') and that has none yet - made by the command line, say -: one made
    now, kept sealed in its options, and put into `opts`. -> the password or None."""
    if str(opts.get('pfx_password_mode') or '') != 'generate':
        return None
    if opts.get('pfx_password') and not again:
        return opts['pfx_password']
    from acmelib.plugins.targets._common import random_password
    pw = random_password(24)
    row = store.db.row('SELECT options FROM cert_deploys WHERE id = ?', (dep['id'],))
    kept = S.jload((row or {}).get('options'), {}) or {}
    kept['pfx_password'] = E.seal_secret(pw, 'cert_deploys:%s:pfx_password' % dep['id'])
    store.db.update('cert_deploys', dep['id'], {'options': json.dumps(kept)})
    opts['pfx_password'] = pw
    if step:
        step('a password for the PKCS#12 / keystore files was made and kept with the '
             'deployment (a full administrator sees it)')
    return pw


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
        n.send(store, mid, key, n.cert_values(store, cert, target=trow['name'], **more),
               mail_to=n.recipients(store, cert))
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
    if cert.get('enabled') == 0:
        # switched off (1.0.79): not deployed, whoever asks (the command line did)
        job.step('%s is switched off: nothing deployed' % cert['name'], 'warn')
        return True, 'nothing deployed: the certificate is switched off'
    if S.current_revoked(store, cert):
        job.step('the certificate %s holds now is revoked: nothing deployed - a new one is '
                 'issued first' % cert['name'], 'bad')
        return False, 'nothing deployed: the certificate it holds is revoked'
    told_renewed(store, job, cert_id)
    # Held (1.0.86, its source changed with "I deploy it myself"): issued, not put anywhere
    # until a person deploys it - who does it lets it go for all of them.
    if S.deploy_held(store, cert) and not force:
        job.step('%s (version %s) is kept here, not deployed: it waits for Deploy now (its '
                 'deployments are held)' % (cert['name'], cert.get('version')), 'warn')
        if cert.get('csr_from'):
            # its key is the device's: the device keeps its old certificate meanwhile, and a
            # new key and CSR is asked of it at the next issue - this one is then of no use
            job.step('its key was made by the device of %s, which keeps its old certificate '
                     'until Deploy now; the next issue asks the device for a new key and CSR, '
                     'and this certificate then fits no key there any more' % cert['csr_from'],
                     'warn')
        return True, 'issued, not deployed - it waits for Deploy now'
    if force and not only and S.deploy_hold(store, cert['id']):
        # all of them deployed by a person: the hold ends (1.0.88: also with nothing new waiting)
        S.deploy_hold_set(store, cert, False)
        job.step('the hold of its deployments ends: they go now', 'info')
    rows = deploys_of(store, cert_id, only)
    if not rows:
        job.step('no deployment to run')
        return True, 'nothing to deploy'
    good, bad, done_on, skipped = 0, [], set(), 0
    ok_ids = set()
    for dep in rows:
        job.check()
        from acmelib.certs import dnssets       # a target's own connections: Settings → DNS
        with dnssets.scope('targets', store):
            ok, said = deploy_one(store, job, cert, dep, force)
        if ok is None:
            # Its target switched off (1.0.77): not counted as done, and its tests not run -
            # they probed a server that never got the new certificate, and said "old version".
            skipped += 1
        elif ok:
            good += 1
            ok_ids.add(dep['id'])
            done_on.add(str(dep.get('target') or ''))
        else:
            bad.append('%s: %s' % (dep['target'], said))
    # Its tests (1.0.32): what the servers really serve now - a failed one is a warning of
    # the job; the deployments themselves went as said.
    tested = None
    failed_by_test = {}
    if good:
        try:
            from acmelib.certs import checks
            tested = checks.after_deploy(store, job, cert_id, done_on, failed_by_test)
        except JobStopped:
            # stopped while its tests ran (1.0.95): what went through is told as deployed -
            # it was in place already, and never said (no event, no notice) and never tried
            for dep in rows:
                if dep['id'] in ok_ids and not failed_by_test.get(str(dep.get('target') or '')):
                    try:
                        _told_deployed(store, cert, dep)
                    except Exception:                   # noqa: BLE001
                        pass
            raise
        except Exception as e:                          # noqa: BLE001
            job.step('the tests of the certificate could not run: %s' % e, 'warn')
    # A test tied to a target that failed (1.0.77, as "Check what is served" did): the
    # deployment there failed - tried again later, and said in the alerts.
    for dep in rows:
        why = failed_by_test.get(str(dep.get('target') or ''))
        # only those that went through in this run (1.0.78: one failed by itself was failed
        # twice - its backoff doubled - and counted twice)
        if why and dep['id'] in ok_ids:
            cur = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (dep['id'],)) or dep
            # counted on from its failures before this run (1.0.93): put in place it had 0,
            # and every try waited five minutes - redeployed and restarted for ever
            _failed(store, dict(cur, fails=dep.get('fails') or 0), why)
            job.step('%s: %s' % (dep['target'], why), 'bad')
            good -= 1
            bad.append('%s: %s' % (dep['target'], why))
            # said as a failed deployment is (1.0.78): its event, its notice
            try:
                trow = S.plugin_row(store, 'target', dep['target']) or {'name': dep['target']}
                with E.event_with(**_fields(store, cert, trow, 'deploy', 'failed')):
                    store.add_event('certificates', 'deploying %s to %s failed: %s' % (
                        cert['name'], dep['target'], why), 'bad')
                _tell(store, 'cert_deploy_failed', 'deploy-one:%s' % dep['id'], cert, trow,
                      error=why[:500])
            except Exception as e:                      # noqa: BLE001
                job.step('the failure could not be told: %s' % e, 'warn')
    for dep in rows:
        if dep['id'] in ok_ids and not failed_by_test.get(str(dep.get('target') or '')):
            try:
                _told_deployed(store, cert, dep)
            except Exception as e:                      # noqa: BLE001
                job.step('the deployment could not be told: %s' % e, 'warn')
    if bad:
        return False, '%d of %d deployment(s) failed - %s' % (len(bad), len(rows), '; '.join(bad))
    off = ' (%d left out: target switched off)' % skipped if skipped else ''
    if tested is False:
        return True, '%d deployment(s) done%s - but a test of what is served failed' % (good, off)
    return True, '%d deployment(s) done%s' % (good, off)


def told_renewed(store, job, cert_id):
    """After a renewal (a job of kind renew that made a version): told, when
    certs_notify_ok says so. Never raises."""
    try:
        n = _notices()
        # the first issue and a revoke's new one too (1.0.88: jobs of kind issue since 1.0.79)
        if getattr(job, 'kind', '') not in ('renew', 'issue', 'revoke') or \
                not getattr(job, 'version', None) or \
                not n.ok_wanted():
            return
        cert = S.cert_need(store, cert_id)
        n.send(store, 'cert_renewed', 'renewed:%s:%s' % (cert_id, job.version),
               n.cert_values(store, cert), mail_to=n.recipients(store, cert))
    except Exception as e:                              # noqa: BLE001
        E.log('telling about a renewal: %s' % e, 'warn')


def deploy_job(cert_id, only=None, force=False):
    """A job's function: the deployments of one certificate (force: asked by a person)."""
    def fn(job):
        return run_deploys(job.store, job, cert_id, only, force)
    return fn
