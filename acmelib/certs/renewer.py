# -*- coding: utf-8 -*-
"""
The scheduler: certificates renewed and deployed by themselves.

One node works at a time. A lease in meta ('certs:leader' = {node, until,
vip}) says which: renewed every 30 s, it runs out after 90 s.

* One database (alone, or two nodes on one - ha_mode "shared"): the database
  is the judge. The lease is taken and kept with a conditional write (INSERT
  of a key not there, UPDATE ... WHERE v = what was read), so of two nodes
  asking at the same moment one wins. The node that holds the VIP address
  takes it over from one that does not; any node takes it once it ran out.
* Two databases (ha_mode "replicated"): each has a copy of the row, and a
  copy can be late - or not come at all while the replication is paused or
  broken - so the row cannot be the judge: both nodes would see a lease that
  ran out and both would lead. Who leads is decided by a rule both nodes
  reach alone: the node holding the VIP address; else the first by name of
  the nodes alive (engine ha_lead: heartbeats, and a node that sorts first
  and looks stale here asked in its own database). Only that node writes the
  lease, which then only says who it is. A node that should lead waits while
  the row names another node and has not run out (that one lets it go at its
  next look - 30 s - and the row's removal comes over); one that should not
  lets its lease go. Both lead only when neither can reach the other's
  database at all (a network cut between them) - see docs/high-availability.md.

A node trusts its own lead for LEASE_S - LEASE_EVERY seconds after it last
got it: one that cannot reach its database stops before another may start.

Every certs_check_min minutes the leader looks for what is due:

    auto_renew, and not_after - renew_days * 86400 <= now
    or inside the window the issuer suggests (ACME ARI, issuer.renewal_window):
        a moment chosen at random inside it, kept in certs.ari
    or never issued yet (state new)
    or failed, and past its wait (5 min doubled each time, certs_retry_max_h at most)

and for each starts a job: a new key (unless reuse_key), the CSR, the issuer
asked (each name proved by its challenge: challenge_map by the exact name,
then '*.parent', then the longest suffix; else the certificate's own
challenge), the certificate kept as the new current version, then every
enabled deployment run. A deployment that failed is tried again after its
own wait. Failures are events (and so syslog / SIEM / isemon), mails to
certs_notify_mail and SMS to certs_notify_sms, and alerts.

The DNS server of acme (dnsserver.DnsServer) runs on every node where
dns_server is on, started again when one of the dns_* settings changes.
"""
from __future__ import annotations

import json
import random
import threading
import time
import traceback

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S
from acmelib.certs import jobs, deployer, readiness, runtime

LEASE_KEY = 'certs:leader'
LEASE_S = 90
LEASE_EVERY = 30
ARI_EVERY = 6 * 3600
DNS_KEYS = ('dns_server', 'dns_listen', 'dns_port', 'dns_zone', 'dns_ns_names',
            'dns_ns_addresses', 'dns_soa_mail', 'dns_ttl', 'dns_static', 'dns_rate', 'dns_cache', 'dns_expose')
RENEWER = [None]


# ---------------------------------------------------------------------------
# Who leads
# ---------------------------------------------------------------------------
def vip_mine(store):
    """Does this node hold the cluster's VIP address now (False with none)."""
    try:
        if not E.CONFIG.get('ha_mode'):
            return False
        v = E.vip_conf(store)
        return bool(v.get('on')) and bool(E.vip_here(v.get('address')))
    except Exception:                                   # noqa: BLE001
        return False


def lease_read(store):
    got = S.jload(store.get_meta(LEASE_KEY), None)
    return got if isinstance(got, dict) else None


def replicated():
    return E.CONFIG.get('ha_mode') == 'replicated'


def vip_elsewhere(store):
    """Another node, alive, says it holds the VIP address."""
    try:
        if not E.CONFIG.get('ha_mode') or not E.vip_conf(store).get('on'):
            return False
        return any(n.get('alive') and not n.get('me') and (n.get('web') or {}).get('vip_here')
                   for n in E.ha_nodes(store))
    except Exception:                                   # noqa: BLE001
        return False


def lease_swap(store, was_raw, new_raw):
    """The lease row from what was read to the new one, in one conditional
    statement: True when this write is the one that went in."""
    if was_raw is None:
        try:
            store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (LEASE_KEY, new_raw))
            return True
        except Exception:                               # noqa: BLE001
            return False                                # another node made it first
    return bool(store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?',
                             (new_raw, LEASE_KEY, was_raw)))


def lease_tick(store):
    """Take or keep the lease where this node should. True: this node leads."""
    me = E.node_name()
    t = time.time()
    raw = store.get_meta(LEASE_KEY)
    cur = S.jload(raw, None)
    if not isinstance(cur, dict):
        cur = None
    vip = vip_mine(store)
    live = bool(cur) and float(cur.get('until') or 0) >= t
    if replicated():
        want = vip or (not vip_elsewhere(store) and bool(E.ha_lead(store)))
        if not want:
            if cur and cur.get('node') == me:
                lease_drop(store)
            return False
        if live and cur.get('node') != me and not (vip and not cur.get('vip')):
            return False                # the other lets it go at its next look
        store.set_meta(LEASE_KEY, json.dumps({'node': me, 'until': t + LEASE_S, 'vip': vip,
                                              'at': t}))
        won = True
    else:
        take = not live or cur.get('node') == me or (vip and not cur.get('vip'))
        if not take:
            return False
        won = lease_swap(store, raw, json.dumps({'node': me, 'until': t + LEASE_S, 'vip': vip,
                                                 'at': t}))
        if not won:
            return False                # another node wrote it first
    if not cur or cur.get('node') != me or not live:
        store.add_event('certificates', '%s now renews and deploys the certificates%s' % (
            me, ' (it holds the VIP address)' if vip else ''))
    return won


def leader(store):
    """{'node', 'until', 'vip', 'me'} - who leads now, or None."""
    cur = lease_read(store)
    if not cur or float(cur.get('until') or 0) < time.time():
        return None
    cur['me'] = cur.get('node') == E.node_name()
    return cur


def lease_drop(store):
    """This node's lease let go (only if it is still this node's)."""
    raw = store.get_meta(LEASE_KEY)
    cur = S.jload(raw, None)
    if isinstance(cur, dict) and cur.get('node') == E.node_name():
        store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (LEASE_KEY, raw))


# ---------------------------------------------------------------------------
# What is due
# ---------------------------------------------------------------------------
def renew_days(row):
    return int(row.get('renew_days') or E.CONFIG.get('certs_renew_days') or 30)


def due_why(row, t=None):
    """Why the certificate is due now, or '' when it is not."""
    t = t or time.time()
    if not row.get('auto_renew') or row.get('enabled') == 0 or not row.get('issuer'):
        return ''
    if row.get('state') in ('renewing', 'pending', 'revoked', 'disabled'):
        return ''
    if row.get('state') == 'failed':
        return 'it failed last time; the wait is over' \
            if float(row.get('next_try') or 0) <= t else ''
    if not row.get('cert_pem'):
        return 'it has not been issued yet'
    na = float(row.get('not_after') or 0)
    if na - renew_days(row) * 86400 <= t:
        return 'it ends in %s' % E.human_span(max(0, na - t)) if na > t else 'it has expired'
    ari = S.jload(row.get('ari'), {}) or {}
    if ari.get('at') and float(ari['at']) <= t:
        return 'inside the renewal window its CA suggests (ARI)'
    return ''


def ari_refresh(store, row):
    """The renewal window the issuer suggests, asked at most every 6 hours."""
    ari = S.jload(row.get('ari'), {}) or {}
    if time.time() - float(ari.get('checked') or 0) < ARI_EVERY or not row.get('cert_pem'):
        return
    irow = S.plugin_row(store, 'issuer', row.get('issuer'))
    if not irow:
        return
    ctx = runtime.RunContext(store, None, scope='issuer:%s' % irow['name'])
    try:
        win = S.plugin_instance(store, 'issuer', irow, ctx).renewal_window(row['cert_pem'])
    except Exception as e:                              # noqa: BLE001
        ari['checked'] = time.time()
        ari['error'] = str(e)[:300]
        store.db.update('certs', row['id'], {'ari': json.dumps(ari)})
        return
    ari['checked'] = time.time()
    ari.pop('error', None)
    if win and len(win) == 2 and win[0] and win[1]:
        start, end = float(win[0]), float(win[1])
        if (ari.get('start'), ari.get('end')) != (start, end) or not ari.get('at'):
            # A moment at random inside the window (RFC 9773 4.2); past its end, now.
            at = random.uniform(start, max(start, end)) if end > time.time() else time.time()
            ari.update(start=start, end=end, at=at)
    else:
        for k in ('start', 'end', 'at'):
            ari.pop(k, None)
    store.db.update('certs', row['id'], {'ari': json.dumps(ari)})


# ---------------------------------------------------------------------------
# Renewing one
# ---------------------------------------------------------------------------
def renew_cert(store, job, cert_id, force=False, by=''):
    """Issue or renew one certificate, then deploy it. (ok, words)."""
    pki = S.pki()
    cert = S.cert_need(store, cert_id)
    if not cert.get('issuer'):
        raise base.PluginError('%s has no issuer: it was imported, or is answered by a CSR - '
                               'nothing to renew it with' % cert['name'], retry=False)
    contexts = []
    was = cert.get('state')
    store.db.update('certs', cert['id'], {'state': 'renewing', 'state_at': time.time(),
                                          'last_try': time.time()})
    try:
        irow = S.plugin_row(store, 'issuer', cert['issuer'])
        if not irow:
            raise base.PluginError('there is no issuer %s' % cert['issuer'], retry=False)
        if not irow.get('enabled', 1):
            raise base.PluginError('the issuer %s is switched off' % irow['name'], retry=False)
        names = S.jload(cert.get('names'), []) or []
        if not names:
            raise base.PluginError('%s has no names' % cert['name'], retry=False)
        ctx = runtime.RunContext(store, job, scope='issuer:%s' % irow['name'])
        contexts.append(ctx)
        issuer = S.plugin_instance(store, 'issuer', irow, ctx)
        job.step('%s %s for %s from %s (%s)' % ('renewing' if cert.get('cert_pem') else 'issuing',
                                              cert['name'], ', '.join(names), irow['name'],
                                              irow['kind']))
        if any(n.startswith('*.') for n in names) and not issuer.wildcards:
            raise base.PluginError('%s gives no wildcard certificates' % irow['name'], retry=False)
        if not issuer.ip_names and any(':' in n or n.replace('.', '').isdigit() for n in names):
            raise base.PluginError('%s gives no certificates for IP addresses' % irow['name'],
                                   retry=False)
        # The first certificate, or after a failed validation: what the validation
        # needs is checked first, and the CA is not asked while something is missing
        # (Let's Encrypt counts failed validations) - certs_precheck.
        if issuer.needs_challenge and readiness.precheck_due(store, cert):
            readiness.precheck(store, job, cert, names)
        profile = S.jload(cert.get('profile'), {}) or {}
        key_type = cert.get('key_type') or 'ec-256'
        key_pem = None
        if cert.get('reuse_key') and cert.get('key_sealed'):
            key_pem = S.cert_key(cert)
            if key_pem:
                job.step('the key it has is kept (reuse_key)')
        if not key_pem:
            key_pem = pki.make_key(key_type)
            job.step('a new %s key made' % key_type)
        job.check()
        subject = profile.get('subject') or {}
        csr = pki.make_csr(key_pem, names, subject=subject or None,
                           must_staple=bool(profile.get('must_staple')), eku=profile.get('eku'))
        csr_pem, csr_der = (csr if isinstance(csr, (tuple, list)) else (csr, b''))
        challenges = {}
        if issuer.needs_challenge:
            made = {}
            for n in names:
                which = S.challenge_for(cert, n)
                if not which:
                    raise base.PluginError('there is no way of proving %s: give the certificate a '
                                           'challenge (or one for that name)' % n, retry=False)
                if which not in made:
                    crow = S.plugin_row(store, 'challenge', which)
                    if not crow:
                        raise base.PluginError('there is no challenge %s (for %s)' % (which, n),
                                               retry=False)
                    if not crow.get('enabled', 1):
                        raise base.PluginError('the challenge %s is switched off' % which,
                                               retry=False)
                    cctx = runtime.RunContext(store, job, scope='challenge:%s' % crow['name'])
                    contexts.append(cctx)
                    made[which] = S.plugin_instance(store, 'challenge', crow, cctx)
                challenges[n] = made[which]
                job.step('%s is proved by %s' % (n, which))
        req = base.CertRequest(names=names, key_type=key_type, key_pem=key_pem, csr_pem=csr_pem,
                               csr_der=csr_der, subject=subject, days=profile.get('days'),
                               profile=profile, challenges=challenges,
                               previous=cert.get('cert_pem') or None, cert_id=cert['id'])
        job.check()
        issued = issuer.issue(req)
        job.check()
        if not issued or not getattr(issued, 'cert_pem', None):
            raise base.PluginError('%s gave no certificate' % irow['name'])
        key_out = issued.key_pem or key_pem
        chain = list(issued.chain_pems or [])
        try:
            ordered = pki.order_chain(issued.cert_pem, chain)
            if isinstance(ordered, (list, tuple)) and ordered:
                chain = [p for p in ordered if p.strip() != issued.cert_pem.strip()]
        except Exception as e:                          # noqa: BLE001
            job.step('the chain could not be put in order: %s' % e, 'warn')
        try:
            if pki.key_matches(issued.cert_pem, key_out) is False:
                raise base.PluginError('the certificate %s gave does not belong to the key'
                                       % irow['name'])
        except base.PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            job.step('whether the key fits could not be checked: %s' % e, 'warn')
        info = S.info_of(issued.cert_pem)
        ari = {}
        if (issued.info or {}).get('ari_id') or info.get('ari_id'):
            ari['id'] = (issued.info or {}).get('ari_id') or info.get('ari_id')
        extra = {'ari': json.dumps(ari), 'csr_pending': None}
        if info.get('cn'):
            extra['cn'] = str(info['cn'])[:190]
        version = S.save_version(store, cert['id'], issued.cert_pem, chain, key_out,
                                 'renewal' if cert.get('cert_pem') else 'issue', by,
                                 info=info, extra=extra)
        job.version = version
        store.db.update('cert_issuers', irow['id'], {'last_ok': time.time(), 'last_error': ''})
        readiness.mark(store, cert['id'], False)
        until = time.strftime('%Y-%m-%d', time.gmtime(info['not_after'])) \
            if info.get('not_after') else '?'
        job.step('issued: version %d, serial %s, valid until %s' % (
            version, info.get('serial') or '?', until), 'ok')
        store.add_event('certificates', '%s %s (version %d, until %s)' % (
            cert['name'], 'renewed' if cert.get('cert_pem') else 'issued', version, until))
        for c in contexts:
            c.tidy()
        contexts = []
        ok, said = deployer.run_deploys(store, job, cert['id'])
        words = 'version %d, valid until %s; %s' % (version, until, said)
        if not ok:
            notify(store, 'deploy:%s' % cert['id'], 'Deploying %s failed' % cert['name'], said)
        return ok, words
    except jobs.JobStopped:
        store.db.update('certs', cert['id'], {'state': was if was != 'renewing' else 'failed',
                                              'state_at': time.time()})
        raise
    except Exception as e:
        cert = S.cert_need(store, cert_id)
        if cert.get('state') == 'renewing':
            why = str(e) if isinstance(e, base.PluginError) else '%s: %s' % (type(e).__name__, e)
            fails = int(cert.get('fails') or 0) + 1
            wait = S.backoff(fails)
            store.db.update('certs', cert['id'], {
                'state': 'failed', 'state_at': time.time(), 'fails': fails,
                'last_error': why[:2000], 'next_try': time.time() + wait})
            job.step('tried again in %s' % E.human_span(wait), 'warn')
            store.add_event('certificates', 'renewing %s failed: %s' % (cert['name'], why), 'bad')
            readiness.mark(store, cert['id'], readiness.failed_on_validation(e))
            try:
                irow = S.plugin_row(store, 'issuer', cert['issuer'])
                if irow and not isinstance(e, readiness.NotReady):
                    store.db.update('cert_issuers', irow['id'], {'last_error': why[:2000]})
            except Exception:                           # noqa: BLE001
                pass
            notify(store, 'renew:%s' % cert['id'], 'Renewing %s failed' % cert['name'], why)
        raise
    finally:
        for c in contexts:
            c.tidy()


def renew_job(cert_id, force=False, by=''):
    def fn(job):
        return renew_cert(job.store, job, cert_id, force, by)
    return fn


def revoke_cert(store, job, cert_id, reason='unspecified', by=''):
    cert = S.cert_need(store, cert_id)
    if not cert.get('cert_pem'):
        raise base.PluginError('%s has no certificate to revoke' % cert['name'], retry=False)
    irow = S.plugin_row(store, 'issuer', cert.get('issuer')) if cert.get('issuer') else None
    if not irow:
        raise base.PluginError('%s has no issuer acme speaks to: revoke it where it was issued, '
                               'then delete it here' % cert['name'], retry=False)
    ctx = runtime.RunContext(store, job, scope='issuer:%s' % irow['name'])
    issuer = S.plugin_instance(store, 'issuer', irow, ctx)
    job.step('revoking %s (serial %s) at %s, reason %s' % (cert['name'], cert.get('serial'),
                                                          irow['name'], reason))
    said = issuer.revoke(cert['cert_pem'], reason, S.cert_key(cert))
    t = time.time()
    store.db.update('certs', cert['id'], {'state': 'revoked', 'state_at': t, 'auto_renew': 0,
                                          'updated': t, 'updated_by': str(by)[:190]})
    store.db.run('UPDATE cert_versions SET revoked = ? WHERE cert_id = ? AND version = ?',
                 (t, cert['id'], cert.get('version') or 0))
    store.add_event('certificates', '%s revoked (%s) by %s' % (cert['name'], reason, by or '?'),
                    'warn')
    job.step('revoked', 'ok')
    return True, str(said or 'revoked')


# ---------------------------------------------------------------------------
# Telling people
# ---------------------------------------------------------------------------
NOTIFY_EVERY = 6 * 3600


NOTIFY_TEXTS = True


def notify(store, key, subject, words, force=False):
    """A mail to certs_notify_mail and an SMS to certs_notify_sms, in the words
    of Settings -> Message texts (acmelib.certs.notices) - each key at most
    every 6 hours. Never raises."""
    from acmelib.certs import notices
    return notices.notify(store, key, subject, words, force=force)


# ---------------------------------------------------------------------------
# One look at everything (the leader, every certs_check_min minutes)
# ---------------------------------------------------------------------------
def tidy(store):
    t = time.time()
    # Run out: said once.
    for r in store.db.rows("SELECT id, name, not_after FROM certs WHERE not_after < ? AND "
                           "state IN ('ok', 'due')", (t,)):
        store.db.update('certs', r['id'], {'state': 'expired', 'state_at': t})
        store.add_event('certificates', '%s has expired' % r['name'], 'bad')
        notify(store, 'expired:%s' % r['id'], '%s has expired' % r['name'],
               'It ended %s.' % time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(r['not_after'])))
    # Running out, and nothing will renew it (or renewing it fails).
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    if days:
        today = time.strftime('%Y-%m-%d')
        for r in store.db.rows("SELECT id, name, not_after, auto_renew, state FROM certs WHERE "
                               "not_after > ? AND not_after < ? AND state NOT IN "
                               "('revoked', 'disabled')", (t, t + days * 86400)):
            if r['auto_renew'] and r['state'] != 'failed':
                continue
            mk = 'certs:warned:%s' % r['id']
            if store.get_meta(mk) == today:
                continue
            store.set_meta(mk, today)
            left = E.human_span(float(r['not_after']) - t)
            store.add_event('certificates', '%s ends in %s%s' % (
                r['name'], left, '' if r['auto_renew'] else ' and is not renewed by itself'),
                'warn')
            notify(store, 'expiring:%s' % r['id'], '%s ends in %s' % (r['name'], left),
                   'Renew it, or switch on renewing it by itself.')
    store.db.run('DELETE FROM dns_records WHERE expires IS NOT NULL AND expires < ?', (t,))
    jobs.prune(store)


def scan(store, by='the renewer'):
    """Start a job for each certificate due and each deployment to try again.
    Returns the number of jobs started."""
    t = time.time()
    started = 0
    try:
        tidy(store)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-tidy', 'tidying the certificates: %s' % e, 'warn', every=3600)
    # The CRLs of acme's own authorities made again past half their life, so
    # one published on acme (publish.py) never runs out.
    try:
        from acmelib.certs import publish
        publish.refresh(store)
    except Exception as e:                              # noqa: BLE001
        E.log_sparing('certs-crl', 'making the CRLs again: %s' % e, 'warn', every=3600)
    rows = store.db.rows("SELECT * FROM certs WHERE COALESCE(enabled, 1) <> 0 AND "
                         "COALESCE(auto_renew, 0) <> 0 AND COALESCE(issuer, '') <> ''")
    for r in rows:
        try:
            if r.get('cert_pem') and r.get('state') in ('ok', 'due'):
                ari_refresh(store, r)
                r = S.cert_get(store, r['id']) or r
            why = due_why(r, t)
            if not why or jobs.cert_busy(store, r['id']):
                continue
            jobs.submit(store, 'renew', renew_job(r['id'], by=by), cert_id=r['id'], by=by,
                        said=why)
            started += 1
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('certs-scan:%s' % r.get('id'), 'looking at %s: %s' % (r.get('name'), e),
                          'warn', every=3600)
    # Deployments: failed and past their wait, or not given the current version yet.
    deps = store.db.rows(
        "SELECT d.*, c.version AS cur_version FROM cert_deploys d JOIN certs c ON c.id = d.cert_id "
        "WHERE COALESCE(d.enabled, 1) <> 0 AND COALESCE(c.enabled, 1) <> 0 AND "
        "c.cert_pem IS NOT NULL AND c.state IN ('ok', 'due', 'failed')")
    todo = {}
    for d in deps:
        if d.get('state') == 'failed':
            if float(d.get('next_try') or 0) > t:
                continue
        elif d.get('deployed_version') == d.get('cur_version') or d.get('state') == 'deploying':
            continue
        todo.setdefault(d['cert_id'], []).append(d['id'])
    for cert_id, ids in todo.items():
        if jobs.cert_busy(store, cert_id):
            continue
        try:
            jobs.submit(store, 'deploy', deployer.deploy_job(cert_id, ids), cert_id=cert_id,
                        by=by, said='deployments to (re)try: %d' % len(ids))
            started += 1
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('certs-deploy:%s' % cert_id, 'deploying: %s' % e, 'warn', every=3600)
    store.set_meta('certs:last_scan', json.dumps({'at': t, 'node': E.node_name(),
                                                  'started': started}))
    return started


# ---------------------------------------------------------------------------
# The thread
# ---------------------------------------------------------------------------
class Renewer(object):
    def __init__(self, daemon):
        self.daemon = daemon
        self.store = daemon.store
        self.stop_flag = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        self.dns = None
        self.dns_sig = None
        self.dns_said = ''
        self.leading = False
        self.lead_until = 0.0
        self.last_scan = 0.0
        self.last_lease = 0.0

    def start(self):
        jobs.recover(self.store)
        self.thread = threading.Thread(target=self.loop, name='certs-renewer', daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.stop_flag.set()
        self.wake.set()
        self.dns_stop()
        try:
            lease_drop(self.store)
        except Exception:                               # noqa: BLE001
            pass
        jobs.shutdown()

    def stopping(self):
        return self.stop_flag.is_set() or self.daemon.stop_flag.is_set()

    def loop(self):
        # A moment for the daemon to settle (the VIP address, the cluster).
        self.wake.wait(3)
        while not self.stopping():
            self.wake.clear()
            if E.HA_REBUILDING.is_set():
                self.wake.wait(5)
                continue
            try:
                self.dns_watch()
            except Exception as e:                      # noqa: BLE001
                E.log_sparing('certs-dns', 'acme\'s DNS server: %s' % e, 'warn', every=600)
            try:
                if time.time() - self.last_lease >= LEASE_EVERY:
                    self.last_lease = time.time()
                    self.leading = False
                    self.leading = lease_tick(self.store)
                    if self.leading:
                        self.lead_until = self.last_lease + LEASE_S - LEASE_EVERY
                every = max(1, int(E.CONFIG.get('certs_check_min') or 5)) * 60
                if self.leading and time.time() < self.lead_until and \
                        time.time() - self.last_scan >= every:
                    self.last_scan = time.time()
                    scan(self.store)
            except Exception as e:                      # noqa: BLE001
                E.log_sparing('certs-renewer', 'the renewer: %s\n%s' % (
                    e, traceback.format_exc()), 'warn', every=600)
            self.wake.wait(5)
        self.dns_stop()

    def scan_soon(self):
        self.last_scan = 0.0
        self.wake.set()

    # ---- acme's own DNS server ------------------------------------------------------------
    def dns_watch(self):
        sig = tuple(str(E.CONFIG.get(k)) for k in DNS_KEYS)
        # The VIP address too: switched on, moved or switched off, the DNS
        # server binds again (it answers on the VIP whatever dns_listen says).
        try:
            v = E.vip_conf(self.store) or {}
            sig += (str(v.get('address') or '') if v.get('on') else '',)
        except Exception:                               # noqa: BLE001
            pass
        on = bool(E.CONFIG.get('dns_server'))
        if self.dns is not None and (not on or sig != self.dns_sig):
            self.dns_stop()
            if on:
                E.log('acme\'s DNS server starts again with its new settings')
        if on and self.dns is None:
            try:
                from acmelib.certs import dnsserver
            except ImportError as e:
                if self.dns_said != 'missing':
                    self.dns_said = 'missing'
                    E.log('dns_server is on, but the DNS server is not part of this '
                          'installation (%s)' % e, 'warn')
                return
            self.dns_sig = sig
            srv = dnsserver.DnsServer(self.store)
            try:
                srv.start()
            except Exception as e:                      # noqa: BLE001
                if self.dns_said != str(e):
                    self.dns_said = str(e)
                    self.store.add_event('certificates', 'acme\'s DNS server did not start: %s'
                                         % e, 'bad')
                try:
                    srv.stop()
                except Exception:                       # noqa: BLE001
                    pass
                return
            self.dns = srv
            self.dns_said = ''

    def dns_stop(self):
        srv, self.dns = self.dns, None
        if srv is not None:
            try:
                srv.stop()
            except Exception as e:                      # noqa: BLE001
                E.log('stopping acme\'s DNS server: %s' % e, 'warn')

    def dns_state(self):
        if self.dns is None:
            return {'running': False, 'said': self.dns_said}
        try:
            got = dict(self.dns.state() or {})
        except Exception as e:                          # noqa: BLE001
            got = {'error': str(e)}
        got.setdefault('running', True)
        return got


def start(daemon):
    r = RENEWER[0]
    if r is not None:
        return r
    RENEWER[0] = Renewer(daemon).start()
    return RENEWER[0]


def stop(daemon=None):
    r, RENEWER[0] = RENEWER[0], None
    if r is not None:
        r.stop()


# ---------------------------------------------------------------------------
# For the alerts, the report, the metrics and --status
# ---------------------------------------------------------------------------
def alerts(store):
    t = time.time()
    out = []
    days = int(E.CONFIG.get('certs_notify_days') or 14)
    for r in store.db.rows("SELECT id, name, state, not_after, auto_renew, last_error FROM certs "
                           "WHERE COALESCE(enabled, 1) <> 0 AND state NOT IN ('revoked', "
                           "'disabled', 'new')"):
        na = float(r.get('not_after') or 0)
        if na and na < t:
            out.append({'key': 'cert-expired:%s' % r['id'], 'level': 'bad',
                        'words': 'the certificate %s has expired' % r['name']})
        elif r['state'] == 'failed':
            out.append({'key': 'cert-failed:%s' % r['id'], 'level': 'bad',
                        'words': 'renewing the certificate %s failed: %s' % (
                            r['name'], (r.get('last_error') or '')[:200])})
        elif na and days and na - t < days * 86400 and not r.get('auto_renew'):
            out.append({'key': 'cert-expiring:%s' % r['id'], 'level': 'warn',
                        'words': 'the certificate %s ends in %s and is not renewed by itself'
                                 % (r['name'], E.human_span(na - t))})
    for d in store.db.rows("SELECT d.id, d.target, d.last_error, c.name FROM cert_deploys d "
                           "JOIN certs c ON c.id = d.cert_id WHERE d.state = 'failed' AND "
                           "COALESCE(d.enabled, 1) <> 0"):
        out.append({'key': 'cert-deploy:%s' % d['id'], 'level': 'bad',
                    'words': 'deploying %s to %s failed: %s' % (d['name'], d['target'],
                                                                (d.get('last_error') or '')[:200])})
    return out


def counts(store):
    out = {}
    for r in store.db.rows('SELECT state, COUNT(*) AS n FROM certs GROUP BY state'):
        out[r['state'] or 'new'] = int(r['n'])
    return out


def report(store, since):
    t = time.time()
    c = counts(store)
    lines = ['%d certificate(s): %s' % (sum(c.values()), ', '.join(
        '%d %s' % (n, s) for s, n in sorted(c.items())) or 'none')]
    got = store.db.rows("SELECT kind, ok, COUNT(*) AS n FROM cert_jobs WHERE ts >= ? AND "
                        "kind IN ('renew', 'deploy') GROUP BY kind, ok", (float(since or 0),))
    for g in got:
        lines.append('%s: %d %s' % (g['kind'], g['n'], 'done' if g['ok'] else 'failed'))
    soon = store.db.rows("SELECT name, not_after FROM certs WHERE not_after > ? AND not_after < ? "
                         "ORDER BY not_after", (t, t + 30 * 86400))
    for s in soon[:20]:
        lines.append('ends %s: %s' % (time.strftime('%Y-%m-%d', time.gmtime(s['not_after'])),
                                      s['name']))
    for a in alerts(store)[:20]:
        lines.append('! ' + a['words'])
    return [('Certificates', lines)]


def metrics(store):
    t = time.time()
    c = counts(store)
    rows = store.db.rows("SELECT name, not_after FROM certs WHERE not_after IS NOT NULL AND "
                         "COALESCE(enabled, 1) <> 0")
    failed_d = int(store.db.value("SELECT COUNT(*) FROM cert_deploys WHERE state = 'failed'",
                                  (), 0) or 0)
    jobs_fail = int(store.db.value("SELECT COUNT(*) FROM cert_jobs WHERE ok = 0 AND ts > ?",
                                   (t - 86400,), 0) or 0)
    lead = leader(store)
    return [
        ('acme_certs', 'Certificates kept, by state', 'gauge',
         [({'state': s}, n) for s, n in sorted(c.items())]),
        ('acme_cert_expiry_seconds', 'Seconds until each certificate ends', 'gauge',
         [({'name': r['name']}, round(float(r['not_after']) - t)) for r in rows]),
        ('acme_cert_deploys_failed', 'Deployments whose last try failed', 'gauge',
         [({}, failed_d)]),
        ('acme_cert_jobs_failed_24h', 'Certificate jobs that failed in the last 24 hours',
         'gauge', [({}, jobs_fail)]),
        ('acme_cert_leader', 'Whether this node renews and deploys (1) or not (0)', 'gauge',
         [({'node': E.node_name()}, 1 if lead and lead.get('me') else 0)]),
    ]


def status_lines(store, pal):
    c = counts(store)
    total = sum(c.values())
    if not total:
        return ['certificates      none yet  (acme --cert-add NAME --names ... --issuer ...)']
    t = time.time()
    soon = int(store.db.value('SELECT COUNT(*) FROM certs WHERE not_after > ? AND not_after < ?',
                              (t, t + int(E.CONFIG.get('certs_notify_days') or 14) * 86400),
                              0) or 0)
    bad = c.get('failed', 0) + c.get('expired', 0)
    parts = ['%d %s' % (n, s) for s, n in sorted(c.items())]
    line = 'certificates      %d (%s)' % (total, ', '.join(parts))
    if soon:
        line += ', %d ending within %s days' % (soon, E.CONFIG.get('certs_notify_days') or 14)
    lead = leader(store)
    out = [pal.bad(line) if bad else (pal.warn(line) if soon else line)]
    out.append('  renewed by        %s' % ((lead or {}).get('node') or 'nobody right now'))
    r = RENEWER[0]
    if r is not None and E.CONFIG.get('dns_server'):
        st = r.dns_state()
        out.append('  DNS server        %s' % ('answering' if st.get('running') else
                                              'not running %s' % (st.get('said') or '')))
    return out
