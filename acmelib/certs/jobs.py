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
import os
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
        self._base = None               # what isemon's lines of this job carry (1.0.44)
        self.made = time.time()
        self.why = ''
        self._seq = 0

    # ---- the steps -------------------------------------------------------------------------
    def step(self, words, level='info', scope=None):
        one = [round(time.time(), 3), level, str(words)[:4000]]
        with self._lock:
            if len(self.steps) < STEPS_MOST:
                self.steps.append(one)
            elif len(self.steps) == STEPS_MOST:
                self.steps.append([one[0], 'warn', 'more steps than are kept: the rest is left out'])
        self.ship('step', level, one[2], scope=scope)
        if self.echo:
            try:
                self.echo(one)
            except Exception:                           # noqa: BLE001
                pass
        if level in ('ok', 'warn', 'bad') or time.time() - self._flushed > 1.0:
            self.flush()

    # ---- isemon's lines of it (isemon_detail, 1.0.44) --------------------------------------
    def base_fields(self):
        """What every line of this job says of it: the job, its certificate (name, names, the
        source it comes from and the source's kind, the key), its target - read once."""
        if self._base is not None:
            return self._base
        b = {'job': self.id, 'job_kind': self.kind}
        try:
            cert = S.cert_get(self.store, self.cert_id) if self.cert_id is not None else None
            if cert:
                b.update(cert=cert.get('name'), cert_id=cert.get('id'),
                         names=S.jload(cert.get('names'), []) or None,
                         issuer=cert.get('issuer'), key_type=cert.get('key_type'),
                         key_type_alt=cert.get('key_type_alt'), version=cert.get('version'),
                         cert_state=cert.get('state'), serial=cert.get('serial'),
                         fingerprint=cert.get('fingerprint'),
                         not_after=_iso(cert.get('not_after')),
                         not_before=_iso(cert.get('not_before')),
                         challenge=cert.get('challenge'), owner=cert.get('owner'))
                if cert.get('issuer'):
                    irow = S.plugin_row(self.store, 'issuer', cert['issuer'])
                    if irow:
                        b['issuer_kind'] = irow.get('kind')
            target = self.target
            if self.deploy_id is not None:
                dep = self.store.db.row('SELECT target FROM cert_deploys WHERE id = ?',
                                        (self.deploy_id,))
                target = (dep or {}).get('target') or target
                b['deploy_id'] = self.deploy_id
            if target:
                b['target'] = target
                trow = S.plugin_row(self.store, 'target', target)
                if trow:
                    b['target_kind'] = trow.get('kind')
        except Exception:                               # noqa: BLE001
            pass
        self._base = b
        return b

    def ship(self, event, level, words, scope=None, **more):
        """One line of this job to isemon (event start / step / http / end) - nothing when
        isemon_detail is off; never raises."""
        try:
            if not E.detail_on():
                return
            f = dict(self.base_fields())
            f['event'] = event
            f['t_ms'] = int((time.time() - self.started) * 1000)
            if event == 'step':
                self._seq += 1
                f['seq'] = self._seq
            if scope and ':' in str(scope):
                f['module_kind'], f['module'] = str(scope).split(':', 1)
            elif scope:
                f['module'] = scope
            f.update(more)
            E.ship_detail('job', level, self.by or 'acme', f, words)
        except Exception:                               # noqa: BLE001
            pass

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
        _lease_give(self.store, self.cert_id)          # given back before it says it is done
        self.ok = bool(ok)
        self.state = 'stopped' if self.stop.is_set() and not ok else ('ok' if ok else 'failed')
        self.said = str(said or '')[:2000]
        t = time.time()
        self._base = None               # the certificate as it is now: its new version
        self.ship('end', 'ok' if ok else ('warn' if self.state == 'stopped' else 'bad'),
                  self.said or self.state, state=self.state, ok=bool(ok),
                  took_ms=int((t - self.started) * 1000), steps=len(self.steps),
                  result_version=self.version)
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


def _iso(t):
    try:
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(float(t))) if t else None
    except (TypeError, ValueError):
        return None


def step_in(job, words, level='info', scope=None):
    """A step said for a module (scope 'challenge:<name>', 'target:<name>'...): isemon's line
    names it (1.0.44). Any other kind of job takes the step as it is."""
    if scope and hasattr(job, 'ship'):
        job.step(words, level, scope=scope)
    else:
        job.step(words, level)


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
    job.why = str(said or '')[:500]
    with _LOCK:
        RUNNING[ident] = job
    return job


def unstick_deleting(store, cert_id, why):
    """A certificate left "deleting" by a job that never ran or never ended (1.0.77): it is
    "revocation failed" - kept, Keep it or Delete again - not stuck for good."""
    if cert_id is None:
        return
    try:
        store.db.run("UPDATE certs SET state = 'revoke-failed', last_error = ? WHERE id = ? AND "
                     "state = 'deleting'", (why, cert_id))
    except Exception:                                   # noqa: BLE001
        pass


def _work(job, fn):
    try:
        if job.cancelled():
            job.step('stopped before it began', 'warn')
            job.finish(False, 'stopped before it began')
            unstick_deleting(job.store, getattr(job, 'cert_id', None), 'stopped before it began')
            return job
        job.state = 'running'
        job.started = time.time()
        job.flush()
        job.ship('start', 'info', job.why or '%s started' % job.kind, queued_ms=int(
            (job.started - float(getattr(job, 'made', job.started))) * 1000))
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
        _lease_give(job.store, job.cert_id)


def submit(store, kind, fn, cert_id=None, deploy_id=None, target=None, by='', said=''):
    """A job queued in the pool: its id at once."""
    _claim(store, cert_id)
    try:
        job = new_job(store, kind, cert_id, deploy_id, target, by, said)
    except BaseException:
        _unclaim(cert_id, store)
        raise
    _pool().submit(_work, job, fn)
    return job.id


def _claim(store, cert_id):
    """The certificate taken for a job before anything else (1.0.45): checked and taken
    in one step - two asks at once (the scan and a person) both passed the check, and two
    orders went to the CA."""
    if cert_id is None:
        return
    if cert_busy(store, cert_id):
        raise ValueError('a job is already working on that certificate')
    with _LOCK:
        if cert_id in BUSY_CERTS:
            raise ValueError('a job is already working on that certificate')
        BUSY_CERTS.add(cert_id)
    # ...and in the database, in one statement (1.0.80): the check above is of this process -
    # the command line beside the daemon, or the other node on a shared database, both passed
    # it, both ordered, and the second one's certificate (paid for, maybe) was lost
    if not _lease_take(store, cert_id):
        with _LOCK:
            BUSY_CERTS.discard(cert_id)
        raise ValueError('a job is already working on that certificate')


LEASE_S = 7200          # as cert_busy's: a job older than that was left by a process that is gone


def _lease_key(cert_id):
    return 'certs:busy:%s' % cert_id


def _lease_on(store):
    # Two replicated databases are two tables: a row both write breaks the replication -
    # there the lead node alone renews and deploys (claim_once's rule)
    return E.CONFIG.get('ha_mode') != 'replicated'


def _lease_take(store, cert_id):
    if not _lease_on(store):
        return True
    key = _lease_key(cert_id)
    mine = '%s|%s|%d' % (E.node_name(), os.getpid(), int(time.time()))
    try:
        if store.get_meta(key) is None:
            try:
                store.db.run('INSERT INTO meta (k, v) VALUES (?, ?)', (key, ''))
            except Exception:                           # noqa: BLE001
                pass                                    # another made it at the same moment
        if store.db.run("UPDATE meta SET v = ? WHERE k = ? AND (v IS NULL OR v = '')",
                        (mine, key)):
            return True
        was = str(store.get_meta(key) or '')
        try:
            at = int(was.rsplit('|', 1)[-1])
        except ValueError:
            at = 0
        # left by a process that is gone, or by a job that has ended (its row says so before
        # the lease is given back) - taken over, in one statement again
        live = int(store.db.value("SELECT COUNT(*) FROM cert_jobs WHERE cert_id = ? AND state IN "
                                  "('queued', 'running') AND ts > ?",
                                  (cert_id, time.time() - LEASE_S), 0) or 0)
        # (a lease of the last minute stays: its job may be about to be written)
        if time.time() - at > LEASE_S or (not live and time.time() - at > 60):
            return bool(store.db.run('UPDATE meta SET v = ? WHERE k = ? AND v = ?',
                                     (mine, key, was)))
        return False
    except Exception as e:                              # noqa: BLE001
        E.log('the certificate %s could not be taken for a job: %s' % (cert_id, e), 'warn')
        return True                                     # as before: this process's check


def _lease_give(store, cert_id):
    if cert_id is None or store is None or not _lease_on(store):
        return
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', (_lease_key(cert_id),))
    except Exception:                                   # noqa: BLE001
        pass


def _unclaim(cert_id, store=None):
    if cert_id is not None:
        with _LOCK:
            BUSY_CERTS.discard(cert_id)
        _lease_give(store, cert_id)


# The command line's jobs carry this node's name as the daemon's do (1.0.51): a file of their own
# beside the state, the process running it in it - the daemon starting (recover) or a stop asked
# from the pages took a renewal still running at the command line for left behind, and the scan
# sent a second order for it.
def _cli_mark(ident):
    return E.STATE_DIR / 'cli-jobs' / ('%d.pid' % int(ident))


def _started(pid):
    """When the process began (its start time in clock ticks since boot, and the boot): a pid
    used again after a reboot or by another process is not taken for it (1.0.51)."""
    try:
        with open('/proc/%d/stat' % int(pid)) as f:
            st = f.read().rsplit(')', 1)[1].split()
        with open('/proc/sys/kernel/random/boot_id') as f:
            boot = f.read().strip()
        return '%s:%s' % (boot, st[19])
    except (OSError, IndexError, ValueError):
        return ''


def cli_alive(ident):
    try:
        words = _cli_mark(ident).read_text().split()
        pid = int(words[0]) if words else 0
    except (OSError, ValueError):
        return False
    if pid <= 0:
        return False
    if len(words) > 1 and _started(pid) != words[1]:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _cli_alive_ids(store):
    try:
        ids = [int(r['id']) for r in store.db.rows(
            "SELECT id FROM cert_jobs WHERE node = ? AND state IN ('queued', 'running')",
            (E.node_name(),))]
    except Exception:                                   # noqa: BLE001
        return []
    return [i for i in ids if cli_alive(i)]


def run_now(store, kind, fn, cert_id=None, deploy_id=None, target=None, by='', said='',
            echo=None):
    """A job run here and now (the command line): the Job when it is done."""
    _claim(store, cert_id)
    try:
        job = new_job(store, kind, cert_id, deploy_id, target, by, said, echo)
    except BaseException:
        _unclaim(cert_id, store)
        raise
    mark = _cli_mark(job.id)
    try:
        mark.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        mark.write_text('%d %s\n' % (os.getpid(), _started(os.getpid())))
    except OSError:
        mark = None
    try:
        return _work(job, fn)
    finally:
        if mark is not None:
            try:
                mark.unlink()
            except OSError:
                pass


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
    row = store.db.row('SELECT id, state, node, cert_id FROM cert_jobs WHERE id = ?', (ident,))
    if not row:
        raise LookupError('there is no job %d' % ident)
    if row['state'] not in ('queued', 'running'):
        return 'job %d is not running (%s)' % (ident, row['state'])
    store.set_meta(STOP_PREFIX + str(ident), '1')
    if row['node'] == E.node_name() and cli_alive(ident):
        return 'job %d is told to stop (it runs at the command line)' % ident
    if row['node'] == E.node_name() or not _node_alive(store, row['node']):
        # Ours, but this process does not run it: left by a daemon that is gone - or
        # by another node that is gone (1.0.19): asked, it never answered, and the
        # certificate stayed busy for two hours.
        store.db.update('cert_jobs', ident, {'state': 'stopped', 'ok': 0,
                                             'finished': time.time(),
                                             'said': 'stopped (nothing was running it)'})
        # ...and its certificate not left "renewing" (1.0.44): no renewal of its own
        # ever came again, and recover() looks only at jobs still running.
        if row.get('cert_id') is not None:
            store.db.run("UPDATE certs SET state = 'failed', last_error = ?, next_try = ? "
                         "WHERE id = ? AND state = 'renewing'",
                         ('stopped before it was done', time.time() + 300, row['cert_id']))
            store.db.run("UPDATE cert_deploys SET state = 'failed', last_error = ?, next_try = ? "
                         "WHERE cert_id = ? AND state = 'deploying'",
                         ('stopped before it was done', time.time() + 300, row['cert_id']))
            unstick_deleting(store, row['cert_id'], 'stopped before it was done')
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
        # now is that node's to finish (shared database) - nor one the command line of this
        # node is still at (1.0.51).
        live = _cli_alive_ids(store)
        nl = (' AND id NOT IN (%s)' % ','.join(str(i) for i in live)) if live else ''
        store.db.run("UPDATE certs SET state = 'failed', last_error = ?, next_try = ? WHERE "
                     "state = 'renewing' AND id IN (SELECT cert_id FROM cert_jobs WHERE node = ? "
                     "AND state IN ('queued', 'running')" + nl + ")",
                     ('acme stopped while it was renewed', time.time() + 300, E.node_name()))
        # One being revoked to be deleted (1.0.77): "revocation failed", not stuck for good.
        store.db.run("UPDATE certs SET state = 'revoke-failed', last_error = ? WHERE "
                     "state = 'deleting' AND id IN (SELECT cert_id FROM cert_jobs WHERE node = ? "
                     "AND state IN ('queued', 'running')" + nl + ")",
                     ('acme stopped while it was revoked', E.node_name()))
        # Its deployments half done too (1.0.44): "deploying" was passed over for good.
        store.db.run("UPDATE cert_deploys SET state = 'failed', last_error = ?, next_try = ? "
                     "WHERE state = 'deploying' AND cert_id IN (SELECT cert_id FROM cert_jobs "
                     "WHERE node = ? AND state IN ('queued', 'running')" + nl + ")",
                     ('acme stopped while it was deployed', time.time() + 60, E.node_name()))
        n = store.db.run("UPDATE cert_jobs SET state = 'failed', ok = 0, finished = ?, "
                         "said = ? WHERE node = ? AND state IN ('queued', 'running')" + nl,
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


def job_rows(store, cert_id=None, kind='', ok=None, page=1, per=50, since=None, where=None,
             state=''):
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
    if state == 'running':             # asked by the page (1.0.79): it counted every job
        where.append("j.state IN ('queued', 'running')")
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
