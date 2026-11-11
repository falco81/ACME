# -*- coding: utf-8 -*-
"""The first full sync to isemon (1.0.71): everything acme holds of its certificates, once,
for isemon to start from what is here, not only from what happens from now on.

Settings → isemon → First full sync (POST /api/isemon/sync, a full administrator) sends, from
the node it is pressed on, as lines of the program `acme-jobs` (filed by isemon's rule as
acme-jobs.log, beside the job lines), `kind=sync`:

    event=begin   sync=<id> and how many of each there are
    event=object  object=source | validation | target | test | authority | certificate |
                  deployment | check - one a line, its state as it is now (never a secret: no
                  module's settings, no key; every value through detail_redact)
    event=history the events of the certificates (kind=certificates) of the last <days>, each
                  with its own time (the syslog stamp, and at=ISO 8601 UTC), oldest first
    event=job     each job of the last <days>: what, on what, how it went; and event=job_step
                  each step it kept (seq, level, msg), with the step's own time
    event=end     sync=<id> lines=<n> took_ms

Paced: the shipper's queue is never filled past half, so nothing of the live lines is dropped
for it. One at a time; GET /api/isemon/sync says how far it is.
"""
from __future__ import annotations

import threading
import time
import uuid

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S

STATE = {'running': False}
_LOCK = threading.Lock()
DAYS_MOST = 3650


def _iso(t):
    try:
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(t))) if t else None
    except (TypeError, ValueError):
        return None


class Sync(object):
    def __init__(self, store, by, days, sink):
        self.store = store
        self.by = by
        self.days = days
        self.sink = sink
        self.id = uuid.uuid4().hex[:12]
        self.lines = 0
        self.started = time.time()

    # ---- one line --------------------------------------------------------------------------
    def line(self, event, fields, words='', level='info', ts=None):
        while self.sink.q.qsize() > self.sink.q.maxsize // 2:      # the live lines first
            time.sleep(0.1)
        f = dict(fields or {}, event=event, sync=self.id)
        if not words and f.get('object'):
            words = '%s %s' % (f['object'], f.get('name') or f.get('cert') or '')
            if f['object'] in ('deployment', 'check'):
                words += ' on %s' % (f.get('target') or f.get('test') or '')
        text = E.event_kv('sync', E.detail_redact(words), level, self.by, E.log_node(),
                          E.detail_fields(f))
        self.sink.put('acme-jobs', 'daemon', text, ts=ts, file_name='acme-jobs.log')
        self.lines += 1
        STATE['sent'] = self.lines

    # ---- what there is ---------------------------------------------------------------------
    def rows(self, table, order='id'):
        return self.store.db.rows('SELECT * FROM %s ORDER BY %s' % (table, order))

    def modules(self, table, obj):
        for r in self.rows(table):
            self.line('object', {'object': obj, 'name': r.get('name'), 'module_kind': r.get('kind'),
                                 'enabled': 0 if r.get('enabled') == 0 else 1,
                                 'last_ok': _iso(r.get('last_ok')), 'last_error': r.get('last_error'),
                                 'note': r.get('note'), 'tags': ','.join(S.jload(r.get('tags'), []) or [])
                                 if r.get('tags') else None})

    def authorities(self):
        for r in self.rows('cert_cas'):
            self.line('object', {'object': 'authority', 'name': r.get('name'), 'subject': r.get('subject_dn'),
                                 'key_type': r.get('key_type'), 'not_before': _iso(r.get('not_before')),
                                 'not_after': _iso(r.get('not_after')), 'fingerprint': r.get('fingerprint'),
                                 'external': r.get('external'), 'enabled': 0 if r.get('disabled') else 1,
                                 'crl_at': _iso(r.get('crl_at'))})

    def certificates(self):
        names = {}
        for r in self.rows('certs'):
            names[r['id']] = r.get('name')
            prof = S.jload(r.get('profile'), {}) or {}
            self.line('object', {
                'object': 'certificate', 'cert': r.get('name'), 'cert_id': r['id'],
                'names': ','.join(S.jload(r.get('names'), []) or []), 'cn': r.get('cn'),
                'cert_state': r.get('state'), 'enabled': 0 if r.get('enabled') == 0 else 1,
                'issuer': r.get('issuer') or 'by hand', 'source': r.get('source'),
                'challenge': r.get('challenge'), 'key_type': r.get('key_type'),
                'key_type_alt': r.get('key_type_alt'), 'version': r.get('version'),
                'serial': r.get('serial'), 'fingerprint': r.get('fingerprint'),
                'issuer_dn': r.get('issuer_dn'), 'not_before': _iso(r.get('not_before')),
                'not_after': _iso(r.get('not_after')), 'days_left': S.days_left(r),
                'auto_renew': r.get('auto_renew'), 'renew_days': r.get('renew_days'),
                'last_ok': _iso(r.get('last_ok')), 'last_try': _iso(r.get('last_try')),
                'next_try': _iso(r.get('next_try')), 'fails': r.get('fails'),
                'last_error': r.get('last_error'), 'owner': r.get('owner'),
                'tags': ','.join(S.jload(r.get('tags'), []) or []), 'note': r.get('note'),
                'eku': ','.join(prof.get('eku') or []) or None,
                'alt_not_after': _iso(r.get('alt_not_after')), 'alt_state': r.get('alt_state'),
                'created': _iso(r.get('created')), 'created_by': r.get('created_by')})
        for r in self.rows('cert_deploys', 'cert_id, position, id'):
            self.line('object', {
                'object': 'deployment', 'cert': names.get(r['cert_id']), 'cert_id': r['cert_id'],
                'deploy_id': r['id'], 'target': r.get('target'), 'deploy_state': r.get('state'),
                'enabled': 0 if r.get('enabled') == 0 else 1,
                'deployed_version': r.get('deployed_version'), 'deployed_fp': r.get('deployed_fp'),
                'last_ok': _iso(r.get('last_ok')), 'last_try': _iso(r.get('last_try')),
                'fails': r.get('fails'), 'last_error': r.get('last_error')})
        for r in self.rows('cert_checks', 'cert_id, position, id'):
            self.line('object', {
                'object': 'check', 'cert': names.get(r['cert_id']), 'cert_id': r['cert_id'],
                'check_id': r['id'], 'test': r.get('test'), 'enabled': 0 if r.get('enabled') == 0 else 1,
                'state': r.get('last_state') or 'not run', 'last_at': _iso(r.get('last_at')),
                'last_ok': _iso(r.get('last_ok')), 'fails': r.get('fails'),
                'after': (r.get('after_target') or '').replace('\n', ',') or 'any'},
                words=r.get('last_said') or '')
        return names

    # ---- what happened ---------------------------------------------------------------------
    def history(self, names):
        since = time.time() - self.days * 86400
        n = 0
        for r in self.store.db.rows("SELECT * FROM events WHERE kind = 'certificates' AND ts >= ? "
                                    "ORDER BY ts, id", (since,)):
            self.line('history', {'at': _iso(r.get('ts')), 'event_node': r.get('node'),
                                  'by': r.get('who')}, words=r.get('words') or '',
                      level=r.get('level') or 'info', ts=r.get('ts'))
            n += 1
        jobs = 0
        for r in self.store.db.rows('SELECT * FROM cert_jobs WHERE ts >= ? ORDER BY ts, id', (since,)):
            steps = S.jload(r.get('steps'), []) or []
            base = {'job': r['id'], 'job_kind': r.get('kind'), 'cert': names.get(r.get('cert_id')),
                    'cert_id': r.get('cert_id'), 'deploy_id': r.get('deploy_id'), 'target': r.get('target')}
            self.line('job', dict(base, at=_iso(r.get('ts')), state=r.get('state'), ok=r.get('ok'),
                                  finished=_iso(r.get('finished')), took_ms=r.get('took_ms'),
                                  by=r.get('by_who'), job_node=r.get('node'), version=r.get('version'),
                                  steps=len(steps)), words=r.get('said') or '',
                      level='info' if r.get('ok') or r.get('ok') is None else 'warn', ts=r.get('ts'))
            for i, st in enumerate(steps):
                if not isinstance(st, (list, tuple)) or len(st) < 3:
                    continue
                self.line('job_step', dict(base, seq=i + 1, at=_iso(st[0])), words=str(st[2]),
                          level=str(st[1] or 'info'), ts=st[0])
            jobs += 1
        return n, jobs

    def run(self):
        db = self.store.db
        count = lambda t: int((db.row('SELECT COUNT(*) AS n FROM %s' % t) or {}).get('n') or 0)  # noqa: E731
        try:
            self.line('begin', {'certificates': count('certs'), 'deployments': count('cert_deploys'),
                                'checks': count('cert_checks'), 'targets': count('cert_targets'),
                                'sources': count('cert_issuers'), 'days': self.days},
                      words='the first full sync of acme begins')
            STATE['phase'] = 'objects'
            self.modules('cert_issuers', 'source')
            self.modules('cert_challenges', 'validation')
            self.modules('cert_targets', 'target')
            self.modules('cert_tests', 'test')
            self.authorities()
            names = self.certificates()
            events = jobs = 0
            if self.days:
                STATE['phase'] = 'history'
                events, jobs = self.history(names)
            took = int((time.time() - self.started) * 1000)
            self.line('end', {'lines': self.lines + 1, 'events': events, 'jobs': jobs, 'took_ms': took},
                      words='the first full sync of acme is done')
            STATE.update(running=False, phase='done', done_at=time.time(), sent=self.lines,
                         events=events, jobs=jobs)
            self.store.add_event('settings', '%s: the full sync to isemon is done - %d lines (%d events, '
                                 '%d jobs)' % (self.by, self.lines, events, jobs), 'info', who=self.by)
        except Exception as e:                          # noqa: BLE001
            STATE.update(running=False, phase='failed', error=str(e)[:300], done_at=time.time())
            self.store.add_event('settings', '%s: the full sync to isemon failed: %s' % (self.by, e),
                                 'warn', who=self.by)


def start(store, by, days):
    if not E.CONFIG.get('isemon'):
        raise E.ApiError(400, 'sending to isemon is off')
    sink = E.DETAIL_SINK[0]
    if sink is None:
        raise E.ApiError(503, 'the daemon\'s sending is not running')
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise E.ApiError(400, 'days: a number')
    if not 0 <= days <= DAYS_MOST:
        raise E.ApiError(400, 'days: 0 to %d' % DAYS_MOST)
    with _LOCK:
        if STATE.get('running'):
            raise E.ApiError(409, 'a full sync is running already')
        job = Sync(store, by, days, sink)
        STATE.clear()
        STATE.update(running=True, id=job.id, by=by, days=days, started=job.started, sent=0,
                     phase='begin')
    store.add_event('settings', '%s: the full sync to isemon starts (history of %d days)' % (by, days),
                    'info', who=by)
    threading.Thread(target=job.run, name='isemon-sync', daemon=True).start()
    return dict(STATE)


@A.api('POST', '/api/isemon/sync', 'fulladmin')
def _sync(h, s):
    b = h.body()
    return start(h.store, A.who(s), b.get('days', 365))


@A.api('GET', '/api/isemon/sync', 'fulladmin')
def _sync_state(h, s):
    return dict(STATE, node=E.node_name())


__all__ = ['start', 'STATE', 'Sync']
