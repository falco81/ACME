# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- a backup tried, without putting it back (1.0.169) ---------------------------------
# Settings → Backups → Try a backup: the newest backup of this node at a
# destination fetched into a folder of its own, opened with the password of
# the backups, every file checked against its manifest, the copy of the
# database read to its last line and counted, the key in it checked against
# the secrets sealed in it (each must open with it), config.json read -
# what a restore needs, done without touching the database in use. The
# newest nightly copy on this machine is read through as well. By hand, after
# every backup, or weekly (rbackup_verify); in a thread of its own, the
# result kept per node ('rbackup:verified:NODE') and alerted when it failed.
RB_VERIFY_KEEP = 30


def _seal_tag_ok(key, value, bind):
    """Whether `key` is the one `value` was sealed with - its tag checked, the
    secret itself never opened."""
    if not isinstance(value, str) or not value:
        return None
    if value.startswith(SEALED2):
        v2, prefix = True, SEALED2
    elif value.startswith(SEALED):
        v2, prefix = False, SEALED
    else:
        return None
    try:
        raw = base64.urlsafe_b64decode(value[len(prefix):].encode('ascii'))
    except (ValueError, TypeError):
        return False
    if len(raw) < 32:
        return False
    nonce, body, tag = raw[:16], raw[16:-16], raw[-16:]
    sign = hmac.new(key, b'sign', hashlib.sha256).digest()
    signed = (b'2|' + str(bind).encode('utf-8') + b'|' if v2 else b'') + nonce + body
    return hmac.compare_digest(tag, hmac.new(sign, signed, hashlib.sha256).digest()[:16])


def copy_read_through(path, key=None, sample=50, child=False):
    """A copy of the database read to its last line: what it holds, and - with
    a key - how many sealed secrets of a sample open with it: the settings
    sealed, and every column of SCHEMA ending in _sealed (bound to
    'table:id:column', as the modules seal them). In the daemon by `acme
    --read-copy`, a process of its own (1.0.186): a big copy read line by line
    is minutes of Python, which held its one lock against everything else."""
    if not child and DAEMON_DB[0] is not None:
        r = subprocess.run([sys.executable, '-I', os.path.abspath(__file__), '--read-copy',
                            str(path)], input=(key.hex() if key else '') + '\n',
                           capture_output=True, text=True, timeout=6 * 3600)
        try:
            got = json.loads(r.stdout.strip().split('\n')[-1])
        except (ValueError, IndexError):
            raise RbError('the copy could not be read: %s' % (r.stderr or r.stdout).strip()[-300:])
        if got.get('error'):
            raise RbError(got['error'])
        return got
    import gzip
    counts, table, admins = {}, None, 0
    tried = opened = 0
    cols = {}
    for t, c in sealed_columns():
        if t != 'settings':
            cols.setdefault(t, []).append(c)
    with gzip.open(str(path), 'rt', encoding='utf-8') as f:
        head = json.loads(f.readline() or '{}')
        if 'acme' not in head and 'opt' not in head:
            raise RbError('the copy of the database is not one made by acme')
        for line in f:
            got = json.loads(line)
            if set(got.keys()) == {'table'}:
                table = got['table']
                counts.setdefault(table, 0)
                continue
            if not table:
                continue
            counts[table] += 1
            if table == 'accounts' and got.get('role') == 'fulladmin' and not got.get('disabled'):
                admins += 1
            if not key or tried >= sample:
                continue
            if table == 'settings':
                try:
                    value = json.loads(got.get('v') or 'null')
                except (TypeError, ValueError):
                    value = None
                pairs = [(value, None)] if isinstance(value, str) and \
                    value.startswith(SEALED) else []
            else:
                pairs = [(got.get(c), seal_bind(table, got, c))
                         for c in cols.get(table, ()) if got.get(c)]
            for value, bind in pairs:
                ok = _seal_tag_ok(key, value, bind)
                if ok is not None:
                    tried += 1
                    opened += 1 if ok else 0
    return {'head': head, 'counts': counts, 'admins': admins, 'tried': tried, 'opened': opened}


# Rows that come by themselves while the copy is made, as the logs do (1.0.19): a sign-in,
# a code used once, a job of the certificate manager (900 adds its own) - one of them in
# that moment made the backup "not good" when it was tried.
RB_GROWING = ['sessions', 'used_once']


def rb_verify_file(path, password, work, made_here=True):
    """The checks on one backup file: [(what, ok, said)] and its manifest."""
    checks = []

    def check(what, ok, said=''):
        checks.append({'what': what, 'ok': bool(ok), 'said': said})
        return ok
    try:
        top, m = rb_open(path, password, work)
    except RbError as e:
        check('opened with the password of the backups, every file as its manifest says',
              False, str(e))
        return checks, {}
    check('opened with the password of the backups, every file as its manifest says', True,
          '%d file(s)' % len(m.get('files') or {}))
    key = None
    try:
        key = bytes.fromhex(open(os.path.join(top, 'secrets.key')).read().strip())
        check('the key of the sealed secrets is in it', len(key) == 32)   # as a restore takes it: 64 hex (1.0.48)
    except (OSError, ValueError) as e:
        check('the key of the sealed secrets is in it', False, str(e)[:200])
    try:
        got = copy_read_through(os.path.join(top, 'acme-copy.json.gz'), key)
        c = got['counts']
        check('the copy of the database reads to its last line', True, '%d tables, %d rows, '
              '%d accounts' % (len(c), sum(c.values()), c.get('accounts', 0)))
        want = m.get('counts') or {}
        # The logs grow while the copy is made: the tables the manifest counted
        # that are no log are to hold as many rows as it says.
        short = sorted(t for t, n in want.items() if t not in LOG_TABLES and t != 'events'
                       and t not in RB_GROWING and isinstance(n, int) and c.get(t, 0) < n)
        if want:
            check('every row the manifest counts is in it', not short,
                  ', '.join('%s %d of %d' % (t, c.get(t, 0), want[t]) for t in short)
                  or '%d rows' % sum(n for n in want.values() if isinstance(n, int)))
        check('a full administrator can sign in after it', got['admins'] > 0,
              '%d' % got['admins'])
        if got['tried']:
            check('the sealed secrets open with the key in it', got['opened'] == got['tried'],
                  '%d of %d tried' % (got['opened'], got['tried']))
    except (OSError, ValueError, EOFError, RbError) as e:
        check('the copy of the database reads to its last line', False, str(e)[:200])
    try:
        with open(os.path.join(top, 'config.json')) as f:
            json.load(f)
        check('config.json is in it and reads', True)
    except (OSError, ValueError) as e:
        check('config.json is in it and reads', False, str(e)[:200])
    return checks, m


def rb_verify(store, by, tid=None, name=None, progress=None):
    """The newest backup of this node at a destination (or the one named),
    tried. The result is kept and returned."""
    def say(n, t):
        if progress:
            progress(n, 4, t)
    # one named: tried switched off too (1.0.51) - "back up now" sends to one switched off,
    # and its "try it after" failed a good backup with "no such destination"
    targets = [t for t in rb_targets(store) if (t['id'] == tid if tid else t.get('enabled'))]
    if tid and not targets:
        raise RbError('no such destination')
    if not targets:
        raise RbError('no destination is switched on')
    t = targets[0]
    began = time.time()
    res = {'at': began, 'by': by, 'node': node_name(), 'target': t['id'], 'target_name': t['name'],
           'checks': [], 'ok': False}
    work = tempfile.mkdtemp(prefix='acme-verify-', dir=str(STATE_DIR))
    os.chmod(work, 0o700)
    try:
        say(1, 'the backups at %s listed' % t['name'])
        files = rb_remote_list(store, t['id'])
        # This node's own, never another node's in its place (1.0.205): it was
        # said to put back here, and this node's own missing went unnoticed.
        pick = [f for f in files if f['name'] == name] if name else \
            [f for f in files if f['mine']]
        if not pick:
            raise RbError('there is no backup %s at %s' % (('called ' + name) if name else
                                                           'of this node', t['name']))
        f = pick[0]
        res.update(file=f['name'], made=f['when'], bytes=f['bytes'])
        say(2, 'fetched from %s' % t['name'])
        dst = os.path.join(work, 'b')
        rb_room(store)                      # otp 1.0.234
        rb_fetch(store, t['id'], f['name'], dst)
        say(3, 'opened and read through')
        res['checks'], m = rb_verify_file(dst, rb_password(), work)
        res['acme'] = m.get('acme')
    except (RbError, OSError, ValueError, subprocess.SubprocessError,
            tarfile.TarError, zlib.error, EOFError) as e:
        # A file damaged at the destination is what this is for (1.0.207): tar's and
        # zlib's own errors went past it - nothing written, no alert, for ever.
        res['checks'].append({'what': 'fetched from the destination', 'ok': False,
                              'said': rb_said(e) if not isinstance(e, RbError) else str(e)})
    finally:
        shutil.rmtree(work, ignore_errors=True)
    # The newest nightly copy here, read through too.
    say(4, 'the newest nightly copy read through')
    try:
        # The nightly copies themselves (otp 1.0.234): read from where the hand-made ones are, the
        # nightly ones were never looked at - and a check that tried nothing passed.
        nightly = [d for d in kept_dumps(store.db.engine) if d['mine']]
        what = 'the newest nightly copy here reads to its last line'
        if nightly:
            d = nightly[0]
            path = DUMP_DIR / d['name']
            if d['kind'] == 'copy':
                got = copy_read_through(path, sealing_key())
                ok = got['tried'] > 0 and got['tried'] == got['opened']
                said = '%s, %d rows' % (d['name'], sum(got['counts'].values()))
            elif d['kind'] == 'sqlite' and not str(d['name']).endswith('.gz'):
                got, why = _peek_sqlite(str(path))
                ok = bool(got)
                said = '%s, %d rows' % (d['name'], sum(got['counts'].values())) if got else why
            else:
                import gzip
                n = 0
                opener = gzip.open if str(d['name']).endswith('.gz') else open
                with opener(str(path), 'rb') as f:
                    while True:
                        chunk = f.read(1 << 20)
                        if not chunk:
                            break
                        n += len(chunk)
                ok = n > 0
                said = '%s, %d MB read' % (d['name'], n >> 20)
            res['checks'].append({'what': what, 'ok': ok, 'said': said})
        elif CONFIG.get('backup_daily'):
            res['checks'].append({'what': what, 'ok': False,
                                  'said': 'there is no nightly copy in %s' % DUMP_DIR})
    except Exception as e:                              # noqa: BLE001
        res['checks'].append({'what': 'the newest nightly copy here reads to its last line',
                              'ok': False, 'said': str(e)[:200]})
    res['ok'] = bool(res['checks']) and all(c['ok'] for c in res['checks'])
    res['secs'] = round(time.time() - began, 1)
    k = 'rbackup:verified:' + node_name()
    rows = _meta_json(store, k) or []
    if not isinstance(rows, list):
        rows = []
    store.set_meta(k, json.dumps(([res] + rows)[:RB_VERIFY_KEEP]))
    bad = [c['what'] + (': ' + c['said'] if c['said'] else '') for c in res['checks'] if not c['ok']]
    store.add_event('backups', 'the backup %s at %s was tried: %s' % (
        res.get('file') or '?', t['name'], 'it can be put back' if res['ok'] else
        'NOT GOOD - ' + '; '.join(bad)), 'info' if res['ok'] else 'bad', who=by)
    return res


def _rb_vforgot(store):
    """(all before, {times}) of the tries forgotten, every node's word together."""
    before, ats = 0.0, set()
    for r in store.db.rows("SELECT v FROM meta WHERE k LIKE 'rbackup:vforgot:%'"):
        try:
            v = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if isinstance(v, dict):
            before = max(before, float(v.get('all_before') or 0))
            ats |= {round(float(x), 3) for x in (v.get('ats') or []) if isinstance(x, (int, float))}
    return before, ats


def rb_verified(store):
    """Every node's tries, newest first - less those forgotten."""
    out = []
    before, ats = _rb_vforgot(store)
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'rbackup:verified:%'"):
        try:
            rows = json.loads(r['v'] or '[]')
        except ValueError:
            continue
        out += [x for x in rows if isinstance(x, dict) and float(x.get('at') or 0) > before
                and round(float(x.get('at') or 0), 3) not in ats]
    out.sort(key=lambda x: -float(x.get('at') or 0))
    return out


def rb_verified_forget(store, at=None):
    """Taken off the list - one try (by its time) or all; the backups stay. This node's own row
    rewritten, the other nodes' tries noted as forgotten in a row of this node's (1.0.51): one
    writer a row - the other node's rewritten here crossed its own write of a new try."""
    n, hits = 0, []
    mine = 'rbackup:verified:' + node_name()
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'rbackup:verified:%'"):
        try:
            rows = json.loads(r['v'] or '[]')
        except ValueError:
            rows = []
        rows = [x for x in rows if isinstance(x, dict)]
        hit = rows if at is None else [x for x in rows
                                       if abs(float(x.get('at') or 0) - float(at)) <= 0.001]
        if not hit:
            continue
        n += len(hit)
        hits += hit
        if r['k'] == mine:
            store.set_meta(mine, json.dumps([x for x in rows if x not in hit]))
    fk = 'rbackup:vforgot:' + node_name()
    fg = _meta_json(store, fk) or {}
    if not isinstance(fg, dict):
        fg = {}
    if at is None:
        fg['all_before'] = time.time()
    else:
        fg['ats'] = ([x for x in (fg.get('ats') or []) if isinstance(x, (int, float))])[-500:] + \
            [round(float(x.get('at') or 0), 3) for x in hits]
    store.set_meta(fk, json.dumps(fg))
    return n


def rb_verify_start(store, by, tid=None, name=None):
    """In a thread of its own, followed as a backup is (RB_JOB)."""
    with RB_LOCK:
        if RB_JOB['running']:
            raise ValueError('a backup is being made or tried already')
        RB_JOB.update(running=True, what='verify', says='starting', done=0, whole=4, error='',
                      began=time.time(), ended=0, result=None, by=by)

    def progress(done, whole, says):
        RB_JOB.update(done=done, whole=whole, says=says)

    def work():
        try:
            RB_JOB['result'] = rb_verify(store, by, tid, name, progress)
            if not RB_JOB['result'].get('ok'):
                RB_JOB['error'] = 'the backup is not good: ' + '; '.join(
                    c['what'] for c in RB_JOB['result']['checks'] if not c['ok'])
        except Exception as e:                          # noqa: BLE001
            RB_JOB['error'] = scrub_secret(str(e))[:400]
        finally:
            RB_JOB.update(running=False, ended=time.time())
    threading.Thread(target=work, name='rbackup-verify', daemon=True).start()
    return dict(RB_JOB)


def rb_verify_due(store):
    """Weekly: a week since this node last tried one."""
    if (CONFIG.get('rbackup_verify') or 'off') != 'weekly':
        return False
    rows = _meta_json(store, 'rbackup:verified:' + node_name()) or []
    last = float(rows[0].get('at') or 0) if isinstance(rows, list) and rows else 0
    return time.time() - last > 7 * 86400

