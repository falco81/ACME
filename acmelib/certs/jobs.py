# -*- coding: utf-8 -*-
"""
The jobs: one piece of work - an issue or a renewal, a deployment, a
revocation, a test - each a row of cert_jobs with every step it took.

Run in a bounded pool (certs_parallel threads). The steps are written into
the row as they come (at most a second late; at once for ok / warn / bad),
so the pages and `acme --job ID` on either node of a cluster follow a job
while it runs. A job is stopped by job_stop(): the module is told through
ctx.cancelled() and gives up at its next step; a job of another node is
asked through meta ('certs:stop:<id>'), which that node looks at.

    steps   JSON [[epoch, level, words], ...]   level: info ok warn bad debug
    state   queued | running | ok | failed | stopped
"""
from __future__ import annotations

import concurrent.futures
import json
import threading
import time
import traceback

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S

STOP_PREFIX = 'certs:stop:'
RUNNING = {}                    # id -> Job, the jobs of this process
_LOCK = threading.Lock()
_POOL = {'pool': None, 'size': 0}
BUSY_CERTS = set()              # certificates a job of this process works on
STEPS_MOST = 2000


class JobStopped(Exception):
    pass


class Job(object):
    def __init__(self, store, ident, kind, cert_id=None, deploy_id=None, target=None, by='',
                 echo=None):
        self.store = store
        self.id = ident
        self.kind = kind
        self.cert_id = cert_id
        self.deploy_id = deploy_id
        self.target = target
        self.by = by
        self.steps = []
        self.echo = echo                # fn(step) - the command line prints them as they come
        self.stop = threading.Event()
        self.started = time.time()
        self.state = 'queued'
        self.ok = None
        self.said = ''
        self.version = None
        self._lock = threading.Lock()
        self._flushed = 0.0
        self._looked = 0.0

    # ---- the steps -------------------------------------------------------------------------
    def step(self, words, level='info'):
        one = [round(time.time(), 3), level, str(words)[:4000]]
        with self._lock:
            if len(self.steps) < STEPS_MOST:
                self.steps.append(one)
            elif len(self.steps) == STEPS_MOST:
                self.steps.append([one[0], 'warn', 'more steps than are kept: the rest is left out'])
        if self.echo:
            try:
                self.echo(one)
            except Exception:                           # noqa: BLE001
                pass
        if level in ('ok', 'warn', 'bad') or time.time() - self._flushed > 1.0:
            self.flush()

    def flush(self, **more):
        with self._lock:
            steps = json.dumps(self.steps, ensure_ascii=False)
            self._flushed = time.time()
        row = {'steps': steps, 'state': self.state}
        row.update(more)
        try:
            self.store.db.update('cert_jobs', self.id, row)
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('certs-job-flush', 'a job\'s steps could not be written: %s' % e,
                          'warn', every=300)

    def cancelled(self):
        if self.stop.is_set():
            return True
        if time.time() - self._looked > 3:
            self._looked = time.time()
            try:
                if self.store.get_meta(STOP_PREFIX + str(self.id)):
                    self.stop.set()
            except Exception:                           # noqa: BLE001
                pass
        return self.stop.is_set()

    def check(self):
        """Raise when the job was stopped - for loops of acme's own."""
        if self.cancelled():
            raise JobStopped('the job was stopped')

    def finish(self, ok, said=''):
        self.ok = bool(ok)
        self.state = 'stopped' if self.stop.is_set() and not ok else ('ok' if ok else 'failed')
        self.said = str(said or '')[:2000]
        t = time.time()
        self.flush(ok=1 if ok else 0, finished=t, took_ms=int((t - self.started) * 1000),
                   said=self.said, version=self.version)
        try:
            self.store.db.run('DELETE FROM meta WHERE k = ?', (STOP_PREFIX + str(self.id),))
        except Exception:                               # noqa: BLE001
            pass

    def view(self):
        with self._lock:
            steps = list(self.steps)
        return {'id': self.id, 'kind': self.kind, 'cert_id': self.cert_id,
                'deploy_id': self.deploy_id, 'target': self.target, 'state': self.state,
                'ok': self.ok, 'steps': steps, 'live': True}


# ---------------------------------------------------------------------------
# Running them
# ---------------------------------------------------------------------------
def _pool():
    want = max(1, min(32, int(E.CONFIG.get('certs_parallel') or 4)))
    with _LOCK:
        if _POOL['pool'] is None or _POOL['size'] != want:
            old = _POOL['pool']
            _POOL['pool'] = concurrent.futures.ThreadPoolExecutor(
                max_workers=want, thread_name_prefix='certs-job')
            _POOL['size'] = want
            if old is not None:
                old.shutdown(wait=False)        # what it runs runs to its end
        return _POOL['pool']


def new_job(store, kind, cert_id=None, deploy_id=None, target=None, by='', said='',
            echo=None):
    try:
        # a module uploaded on another node: written here and loaded first (1.0.32)
        from acmelib.certs import custom_modules
        custom_modules.keep_current(store)
    except Exception:                                   # noqa: BLE001
        pass
    t = time.time()
    ident = store.db.insert('cert_jobs', {
        'ts': t, 'kind': kind, 'cert_id': cert_id, 'deploy_id': deploy_id,
        'target': target, 'node': E.node_name(), 'state': 'queued', 'ok': None,
        'finished': None, 'took_ms': None, 'steps': '[]', 'by_who': str(by or '')[:190],
        'said': str(said or '')[:2000], 'version': None})
    job = Job(store, ident, kind, cert_id, deploy_id, target, by, echo)
    with _LOCK:
        RUNNING[ident] = job
    return job


def _work(job, fn):
    try:
        if job.cancelled():
            job.step('stopped before it began', 'warn')
            job.finish(False, 'stopped before it began')
            return job
        job.state = 'running'
        job.started = time.time()
        job.flush()
        try:
            got = fn(job)
        except JobStopped as e:
            job.step(str(e), 'warn')
            job.finish(False, str(e))
            return job
        except base.PluginError as e:
            job.step(str(e), 'bad')
            if e.detail:
                job.step(str(e.detail)[:4000], 'debug')
            job.finish(False, str(e))
            return job
        except Exception as e:                          # noqa: BLE001
            job.step('%s: %s' % (type(e).__name__, e), 'bad')
            E.log('a certificate job (%s %s) broke: %s\n%s' % (job.kind, job.id, e,
                                                                traceback.format_exc()), 'error')
            job.finish(False, str(e))
            return job
        if isinstance(got, tuple):
            ok, said = got[0], got[1] if len(got) > 1 else ''
        elif isinstance(got, bool):
            ok, said = got, ''
        else:
            ok, said = True, got or ''
        job.finish(ok, said)
        return job
    finally:
        with _LOCK:
            RUNNING.pop(job.id, None)
            if job.cert_id is not None:
                BUSY_CERTS.discard(job.cert_id)


def submit(store, kind, fn, cert_id=None, deploy_id=None, target=None, by='', said=''):
    """A job queued in the pool: its id at once."""
    if cert_id is not None and cert_busy(store, cert_id):
        raise ValueError('a job is already working on that certificate')
    job = new_job(store, kind, cert_id, deploy_id, target, by, said)
    if cert_id is not None:
        with _LOCK:
            BUSY_CERTS.add(cert_id)
    _pool().submit(_work, job, fn)
    return job.id


def run_now(store, kind, fn, cert_id=None, deploy_id=None, target=None, by='', said='',
            echo=None):
    """A job run here and now (the command line): the Job when it is done."""
    if cert_id is not None and cert_busy(store, cert_id):
        raise ValueError('a job is already working on that certificate')
    job = new_job(store, kind, cert_id, deploy_id, target, by, said, echo)
    if cert_id is not None:
        with _LOCK:
            BUSY_CERTS.add(cert_id)
    return _work(job, fn)


def cert_busy(store, cert_id):
    with _LOCK:
        if cert_id in BUSY_CERTS:
            return True
    # Another process (the daemon, the command line, the other node) on it, within
    # the last two hours (a job older than that was left by a process that is gone).
    got = store.db.value("SELECT COUNT(*) FROM cert_jobs WHERE cert_id = ? AND state IN "
                         "('queued', 'running') AND ts > ?", (cert_id, time.time() - 7200), 0)
    if int(got or 0):
        return True
    return False


def cert_job(store, cert_id):
    """The id of the job working on a certificate now (queued or running), or None."""
    row = store.db.row("SELECT id FROM cert_jobs WHERE cert_id = ? AND state IN ('queued', "
                       "'running') AND ts > ? ORDER BY id DESC LIMIT 1",
                       (cert_id, time.time() - 7200))
    return row['id'] if row else None


def stop(store, ident):
    """Stop a job: here at once, on another node through meta. Words to show."""
    ident = int(ident)
    with _LOCK:
        job = RUNNING.get(ident)
    if job is not None:
        job.stop.set()
        return 'job %d is told to stop' % ident
    row = store.db.row('SELECT id, state, node FROM cert_jobs WHERE id = ?', (ident,))
    if not row:
        raise LookupError('there is no job %d' % ident)
    if row['state'] not in ('queued', 'running'):
        return 'job %d is not running (%s)' % (ident, row['state'])
    store.set_meta(STOP_PREFIX + str(ident), '1')
    if row['node'] == E.node_name() or not _node_alive(store, row['node']):
        # Ours, but this process does not run it: left by a daemon that is gone - or
        # by another node that is gone (1.0.19): asked, it never answered, and the
        # certificate stayed busy for two hours.
        store.db.update('cert_jobs', ident, {'state': 'stopped', 'ok': 0,
                                             'finished': time.time(),
                                             'said': 'stopped (nothing was running it)'})
        return 'job %d marked stopped' % ident
    return 'job %d on %s is asked to stop' % (ident, row['node'])


def _node_alive(store, name):
    """Whether the node that runs a job is heard from (True when it cannot be told)."""
    try:
        for n in E.ha_nodes(store):
            if n.get('name') == name:
                return bool(n.get('alive'))
    except Exception:                                   # noqa: BLE001
        return True
    return False


def recover(store):
    """At the start of the daemon: the jobs this node left running are over."""
    try:
        # Only this node's own: a certificate the other node is renewing right
        # now is that node's to finish (shared database).
        store.db.run("UPDATE certs SET state = 'failed', last_error = ? WHERE state = 'renewing' "
                     "AND id IN (SELECT cert_id FROM cert_jobs WHERE node = ? AND "
                     "state IN ('queued', 'running'))",
                     ('acme stopped while it was renewed', E.node_name()))
        n = store.db.run("UPDATE cert_jobs SET state = 'failed', ok = 0, finished = ?, "
                         "said = ? WHERE node = ? AND state IN ('queued', 'running')",
                         (time.time(), 'acme stopped while it ran', E.node_name()))
        if n:
            store.add_event('certificates', '%s job(s) left running when acme stopped are marked '
                            'failed' % n, 'warn')
    except Exception as e:                              # noqa: BLE001
        E.log('the jobs left running could not be tidied: %s' % e, 'warn')


def shutdown():
    for job in list(RUNNING.values()):
        job.stop.set()
    with _LOCK:
        pool = _POOL['pool']
        _POOL['pool'] = None
    if pool is not None:
        pool.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Looking at them
# ---------------------------------------------------------------------------
def job_view(store, ident):
    ident = int(ident)
    row = store.db.row('SELECT * FROM cert_jobs WHERE id = ?', (ident,))
    if not row:
        raise LookupError('there is no job %d' % ident)
    out = dict(row)
    out['steps'] = S.jload(row.get('steps'), [])
    with _LOCK:
        job = RUNNING.get(ident)
    if job is not None:
        v = job.view()
        out['steps'] = v['steps']
        out['state'] = v['state']
    out['live'] = out.get('state') in ('queued', 'running')
    if out.get('cert_id'):
        out['cert_name'] = store.db.value('SELECT name FROM certs WHERE id = ?', (out['cert_id'],))
    return out


def job_rows(store, cert_id=None, kind='', ok=None, page=1, per=50, since=None, where=None):
    """A page of jobs. `where`: (' AND ...', args) on the certificate `c` (teams.where)."""
    scoped = where if where and where[0] else None
    where, args = [], []
    if scoped:
        where.append(scoped[0][len(' AND '):])
        args += list(scoped[1])
    if cert_id:
        where.append('j.cert_id = ?')
        args.append(int(cert_id))
    if kind:
        where.append('j.kind = ?')
        args.append(str(kind))
    if ok in (0, 1, '0', '1'):
        where.append('j.ok = ?')
        args.append(int(ok))
    if since:
        where.append('j.ts >= ?')
        args.append(float(since))
    w = (' WHERE ' + ' AND '.join(where)) if where else ''
    total = int(store.db.value('SELECT COUNT(*) FROM cert_jobs j LEFT JOIN certs c ON '
                               'c.id = j.cert_id' + w, tuple(args), 0) or 0)
    per = max(1, min(500, int(per or 50)))
    page = max(1, int(page or 1))
    rows = store.db.rows(
        'SELECT j.id, j.ts, j.kind, j.cert_id, j.deploy_id, j.target, j.node, j.state, j.ok, '
        'j.finished, j.took_ms, j.by_who, j.said, j.version, c.name AS cert_name '
        'FROM cert_jobs j LEFT JOIN certs c ON c.id = j.cert_id' + w +
        ' ORDER BY j.ts DESC, j.id DESC LIMIT %d OFFSET %d' % (per, (page - 1) * per), tuple(args))
    return {'rows': rows, 'total': total, 'page': page, 'per': per}


def prune(store):
    days = max(1, int(E.CONFIG.get('certs_keep_jobs_days') or 90))
    return store.db.run("DELETE FROM cert_jobs WHERE ts < ? AND state NOT IN ('queued', 'running')",
                        (time.time() - days * 86400,))
