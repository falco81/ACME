# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the backup itself -----------------------------------------------------------------
def rb_password():
    # Sealed in config.json like the other passwords: until 1.0.139 the sealed
    # text itself locked the backups - not the password typed, so a new
    # machine could not open them.
    pw = str(CONFIG.get('rbackup_password') or '')
    return (unseal_secret(pw) or '') if pw else ''


def rb_password_old():
    """What locked the backups made here before 1.0.139: the sealed text."""
    pw = str(CONFIG.get('rbackup_password') or '')
    return pw if pw.startswith((SEALED, SEALED2)) else ''


def rb_files_named():
    """Files config.json names that live outside the database: the
    authority of a database on another machine."""
    out = []
    for k in ('db_tls_ca',):
        p = str(CONFIG.get(k) or '')
        if p and os.path.isfile(p):
            out.append(p)
    return out


def rb_restore_md(m):
    """RESTORE.md: the exact steps, filled in with what this backup is."""
    enc = m.get('encrypted')
    name = m['file']
    tar = name[:-4] if enc else name
    ha = m.get('ha_mode') == 'replicated'
    site, node, ver = m.get('site') or 'acme', m.get('node') or '?', m.get('acme') or '?'
    lines = [
        '# Restoring acme from %s' % name, '',
        '| | |', '|---|---|',
        '| Made | %s |' % m.get('made_words'),
        '| Installation | %s |' % site,
        '| Node | %s (%s) |' % (node, m.get('host') or ''),
        '| acme | %s |' % ver,
        '| Database | %s |' % m.get('engine_words'),
        '| Cluster | %s |' % (('two nodes, replicated - this is node %s of 2; the other was %s'
                               % (m.get('ha_slot'), m.get('ha_peer'))) if ha else
                              ('two nodes, one shared database' if m.get('ha_mode') == 'shared'
                               else 'one server')),
        '| Locked | %s |' % ('yes - AES-256-CBC, PBKDF2-SHA256, %d rounds (openssl enc)'
                             % RB_ITER if enc else '**no** - anybody with the file has every '
                             'private key: keep it as you would the server'),
        '| Rows | %s |' % (', '.join('%s %s' % (t, n) for t, n in sorted(
            (m.get('counts') or {}).items()) if n) or '?'),
        '', 'Everything is in it: the whole database (the certificates with their private keys,',
        'the authorities, the issuers, the targets, the directories, the accounts, every setting,',
        'the certificates and keys of the pages, the VIP address, the firewall, the message',
        'texts, the logs), the key that opens its sealed secrets (`secrets.key`) and this',
        'machine\'s `/etc/acme/config.json`.', '',
        'Keep the password of the backups apart from the backups (a password vault): without it',
        'the file cannot be opened - by anybody.', '',
        '## 0. Check the file', '', '```bash',
        'sha256sum -c %s.sha256          # "%s: OK"' % (name, name), '```', '',
    ]
    if enc:
        lines += ['## 1. Open it', '',
                  'acme opens it by itself (step 3). With openssl alone, on any machine:', '',
                  '```bash',
                  'openssl enc -d -aes-256-cbc -pbkdf2 -iter %d -md sha256 -in %s -out %s'
                  % (RB_ITER, name, tar),
                  '# it asks for the password of the backups',
                  'tar tzf %s                    # what is inside' % tar, '```', '']
    else:
        lines += ['## 1. It is not locked', '', '```bash',
                  'tar tzf %s' % tar, '```', '']
    lines += [
        'Inside: `acme-copy.json.gz` (the database, in a shape SQLite, MariaDB and PostgreSQL',
        'all take), `secrets.key`, `config.json`, `manifest.json` (a checksum of each file),',
        'this file, and the files config.json names (`files/`).', '',
        '## 2. A machine to put it on', '',
        'AlmaLinux / Rocky / RHEL 9 (or the machine it came from). Install acme **%s or newer**' % ver,
        'from its package - the same way as the first time:', '', '```bash',
        'tar xzf acme-%s.tar.gz && cd acme-%s' % (ver, ver),
        './install.sh                     # SQLite unless you choose otherwise',
        '```', '',
        'The backup goes into whichever database the new machine uses - SQLite after a plain',
        'install is fine. PostgreSQL (needed again for a cluster) can be chosen afterwards:',
        '`./install.sh --with-db postgres --yes`, then *Settings → The database → Try it → Set it',
        'up → Carry everything across → Start using it* (PostgreSQL 16 or later).', '',
        '## 3. Put it back', '', '```bash',
        'acme --restore-bundle %s          # shows what is in it, asks for the password' % name,
        'acme --restore-bundle %s --yes    # puts it back' % name,
        'systemctl restart acme', '```', '',
        'The password may come from a file instead (`--passphrase-file FILE`, one line) or from',
        'the environment (`ACME_BACKUP_PASSWORD`).', '',
        'What it does: a copy of what the new machine has is made first; then the database is',
        'replaced with the one in the backup, `secrets.key` is put in place and the node keeps',
        'its name (`%s`). The new machine\'s own database connection in config.json stays as' % node,
        'it is - it belongs to the new machine. The other files config.json named are in `files/`.',
        '',
    ]
    if ha:
        lines += [
            '## 4. A cluster of two', '',
            '- **One node lost, the other alive:** do not put this back. Install the lost node',
            '  again and join it to the living one - it copies every row from it:',
            '  `acme --ha-bundle FILE` on the living node, `acme --ha-join FILE` on the new one',
            '  (docs/high-availability.md, "When a node is lost").',
            '- **Both lost:** put this backup back on one new machine (steps 2-3). It comes back as',
            '  one server with everything. Move it to PostgreSQL (step 2), then make it two again:',
            '  `acme --ha-setup --ha-peer ADDRESS-OF-THE-SECOND --node-name %s` on it; on the' % node,
            '  second `./install.sh --with-db postgres --yes` and `acme --ha-join FILE`',
            '  (docs/high-availability.md, "Building it - replicated"). The VIP address, the',
            '  firewall, the certificates of the pages and the encrypted link between the',
            '  databases come back by themselves from the database.',
            '- Each node sends its own backups; either node\'s newest is the whole cluster\'s data.',
            '',
        ]
    lines += [
        '## %d. Check it' % (5 if ha else 4), '', '```bash',
        'acme --status                     # the daemon, the database, the certificates',
        '```', '',
        'Then sign in to the pages with an account from the backup. DNS and a load balancer',
        'point at the new machine\'s address if it has another one',
        '(docs/renaming-and-readdressing.md).', '',
        '## By hand, without --restore-bundle', '', '```bash',
        'systemctl stop acme',
        'install -o acme -g acme -m 0600 secrets.key /var/lib/acme/secrets.key',
        'acme --restore acme-copy.json.gz --yes',
        'systemctl start acme', '```', '',
        '---', 'Made by acme %s on %s. The whole subject: docs/backup-and-recovery.md and' % (
            __version__, node),
        'docs/remote-backups.md in the package.', '']
    return '\n'.join(lines)


def rb_counts(store):
    """How many rows each table of SCHEMA holds - for the manifest, and the
    check of a backup against it; {} where the database cannot be asked."""
    out = {}
    for t in TABLES:
        try:
            out[t] = int(store.db.value('SELECT COUNT(*) FROM %s' % t) or 0)
        except Exception:                               # noqa: BLE001
            continue                    # a table not made (yet) in this database
    return out


def rb_manifest(store, base, counts=None):
    """What a backup made now is: the head of its manifest and of RESTORE.md."""
    pw = rb_password()
    m = {'acme': __version__, 'made': time.time(),
         'made_words': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z').strip(),
         'site': CONFIG.get('site_name') or 'acme', 'node': node_name(),
         'host': socket.getfqdn(), 'engine': store.db.engine,
         'engine_words': ENGINE_WORDS.get(store.db.engine, store.db.engine),
         'ha_mode': CONFIG.get('ha_mode') or '', 'ha_slot': CONFIG.get('ha_slot'),
         'ha_peer': CONFIG.get('ha_peer') or '', 'counts': counts or {},
         'encrypted': bool(pw), 'iter': RB_ITER if pw else 0,
         'file': base + ('.tar.gz.enc' if pw else '.tar.gz'), 'files': {}}
    return m


def rb_restore_guide(store):
    """RESTORE.md as a backup made now would carry it (1.0.110) - for reading
    on the pages before anything is lost. No secret is in it."""
    site = rb_slug(CONFIG.get('site_name') or 'acme')
    node = rb_slug(node_name())
    base = 'acme-backup-%s-%s-%s' % (site, node, datetime.now().strftime('%Y%m%d-%H%M%S'))
    m = rb_manifest(store, base, rb_counts(store))
    return {'md': rb_restore_md(m), 'name': 'RESTORE-%s-%s.md' % (site, node),
            'file': m['file']}


def rb_build(store, work, progress=None):
    """The backup, built in `work`: (path of the file to send, its name,
    manifest, RESTORE.md text)."""
    def say(n, t):
        if progress:
            progress(n, 6, t)
    stamp_ = datetime.now().strftime('%Y%m%d-%H%M%S')
    site = rb_slug(CONFIG.get('site_name') or 'acme')
    node = rb_slug(node_name())
    base = 'acme-backup-%s-%s-%s' % (site, node, stamp_)
    inner = os.path.join(work, 'in')
    os.makedirs(inner, mode=0o700)
    say(1, 'the database is copied')
    copy = os.path.join(inner, 'acme-copy.json.gz')
    with open(copy, 'wb') as f:
        dump_tables(store.db, f)
    key = sealing_key()
    if not key:
        raise RbError('this machine has no key that opens its sealed secrets - nothing worth '
                      'sending')
    with open(os.path.join(inner, 'secrets.key'), 'w') as f:
        f.write(key.hex() + '\n')
    try:
        shutil.copyfile(str(CONFIG_FILE), os.path.join(inner, 'config.json'))
    except OSError as e:
        raise RbError('%s cannot be read: %s' % (CONFIG_FILE, e))
    extra = rb_files_named()
    if extra:
        os.makedirs(os.path.join(inner, 'files'))
        for p in extra:
            shutil.copyfile(p, os.path.join(inner, 'files', os.path.basename(p)))
    say(2, 'what is in it is counted')
    pw = rb_password()
    m = rb_manifest(store, base, rb_counts(store))
    for root, _dirs, files in os.walk(inner):
        for n in sorted(files):
            p = os.path.join(root, n)
            h = hashlib.sha256()
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
            m['files'][os.path.relpath(p, inner)] = {'sha256': h.hexdigest(),
                                                    'bytes': os.path.getsize(p)}
    md = rb_restore_md(m)
    with open(os.path.join(inner, 'RESTORE.md'), 'w') as f:
        f.write(md)
    with open(os.path.join(inner, 'manifest.json'), 'w') as f:
        json.dump(m, f, indent=2, default=str)
    say(3, 'packed')
    tar = os.path.join(work, base + '.tar.gz')
    with tarfile.open(tar, 'w:gz', compresslevel=6) as tf:
        for n in sorted(os.listdir(inner)):
            tf.add(os.path.join(inner, n), arcname='%s/%s' % (base, n))
    shutil.rmtree(inner, ignore_errors=True)
    out = tar
    if pw:
        say(4, 'locked with the password of the backups')
        out = tar + '.enc'
        _openssl(['enc', '-aes-256-cbc', '-pbkdf2', '-iter', str(RB_ITER), '-md', 'sha256',
                  '-salt', '-in', tar, '-out', out, '-pass', 'fd:@'],
                 secret=pw, what='locking it')
        os.unlink(tar)
    h = hashlib.sha256()
    with open(out, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    m['sha256'] = h.hexdigest()
    m['bytes'] = os.path.getsize(out)
    with open(os.path.join(work, m['file'] + '.sha256'), 'w') as f:
        f.write('%s  %s\n' % (m['sha256'], m['file']))
    with open(os.path.join(work, base + '-RESTORE.md'), 'w') as f:
        f.write(md)
    return out, m, md


def rb_companions(name):
    m = RB_NAME_RE.match(name)
    if not m:
        return []
    base = name.split('.tar.gz')[0]
    return [name + '.sha256', base + '-RESTORE.md']


def rb_retain(tr, keep, days, now=None):
    """This node's backups at a destination beyond what is kept, taken away -
    never the newest."""
    now = now or time.time()
    mine = rb_slug(node_name())
    files = tr.list()
    names = set(x['name'] for x in files)
    ours = []
    for x in files:
        m = RB_NAME_RE.match(x['name'])
        if m and m.group('node') == mine and m.group('site') == rb_slug(
                CONFIG.get('site_name') or 'acme'):
            try:
                when = datetime.strptime(m.group('stamp'), '%Y%m%d-%H%M%S').timestamp()
            except ValueError:
                continue
            ours.append((when, x['name']))
    ours.sort(reverse=True)
    gone = []
    for i, (when, name) in enumerate(ours):
        if i == 0:
            continue
        if (keep and i >= keep) or (days and now - when > days * 86400):
            for n in [name] + [c for c in rb_companions(name) if c in names]:
                try:
                    tr.delete(n)
                except Exception:                       # noqa: BLE001
                    pass
            gone.append(name)
    return gone


def rb_run(store, by, only=None, progress=None):
    """Made once, sent to every destination switched on (or the ones asked):
    the result of each, kept in the history."""
    targets = [t for t in rb_targets(store)
               if (only and t['id'] in only) or (not only and t.get('enabled'))]
    if not targets:
        raise RbError('no destination is switched on')
    # Never sent unlocked (1.0.136): it holds the key every secret is sealed
    # with, the whole database and config.json - whoever reads the share
    # could unseal every private key.
    if not rb_password():
        raise RbError('the backups have no password: set one (Settings - Backups - '
                      'Backups to other machines) - unlocked, a copy would hand every private '
                      'key to whoever can read the destination')
    work = tempfile.mkdtemp(prefix='acme-rbackup-', dir=str(STATE_DIR))
    os.chmod(work, 0o700)
    began = time.time()
    run = {'at': began, 'by': by, 'node': node_name(), 'targets': [], 'ok': False}
    try:
        path, m, _md = rb_build(store, work, progress)
        if not m.get('encrypted'):
            # The password asked again as it was locked (1.0.205): taken away
            # during a long dump, the copy came out unlocked - it is not sent.
            raise RbError('the backup came out unlocked (its password was taken away meanwhile) '
                          '- not sent anywhere')
        run.update(file=m['file'], bytes=m['bytes'], encrypted=m['encrypted'],
                   rows=sum((m.get('counts') or {}).values()))
        sha = os.path.join(work, m['file'] + '.sha256')
        md = os.path.join(work, m['file'].split('.tar.gz')[0] + '-RESTORE.md')
        for i, t in enumerate(targets):
            if progress:
                progress(5, 6, 'sent to %s (%d of %d)' % (t['name'], i + 1, len(targets)))
            one = {'id': t['id'], 'name': t['name'], 'kind': t['kind'], 'ok': False}
            t0 = time.time()
            tr = rb_transport(t)
            try:
                tr.open()
                tr.put(path, m['file'])
                tr.put(sha, os.path.basename(sha))
                tr.put(md, os.path.basename(md))
                got = {x['name']: x['size'] for x in tr.list()}
                if m['file'] not in got:
                    # Not there after it was sent (1.0.205): taken as sent, and
                    # the old ones taken away after it.
                    raise RbError('the server does not list it after it was sent')
                if got.get(m['file']) not in (None, m['bytes']):
                    raise RbError('the server holds %s bytes of it, not %s' % (
                        got.get(m['file']), m['bytes']))
                one['ok'] = True
                try:
                    one['taken_away'] = rb_retain(tr, int(CONFIG.get('rbackup_keep') or 0),
                                                  int(CONFIG.get('rbackup_keep_days') or 0))
                except Exception as e:                  # noqa: BLE001
                    one['retain_error'] = str(e)[:200]
            except Exception as e:                      # noqa: BLE001
                one['error'] = rb_said(e)
            finally:
                tr.close()
            one['secs'] = round(time.time() - t0, 1)
            run['targets'].append(one)
            rb_set_fields(store, t['id'], '', '', last={
                'at': time.time(), 'ok': one['ok'], 'error': one.get('error') or '',
                'file': m['file'], 'bytes': m['bytes']})
        run['ok'] = all(x['ok'] for x in run['targets'])
    except (RbError, OSError, ValueError, subprocess.SubprocessError) as e:
        run['error'] = scrub_secret(str(e))[:400]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    run['secs'] = round(time.time() - began, 1)
    rb_history_add(store, run)
    good = [x['name'] for x in run['targets'] if x['ok']]
    bad = ['%s (%s)' % (x['name'], x.get('error')) for x in run['targets'] if not x['ok']]
    store.add_event('backups', 'a backup of %s (%s) %s%s%s' % (
        node_name(), human_bytes(run.get('bytes') or 0), ('went to ' + ', '.join(good))
        if good else 'went nowhere', ('; not to ' + '; '.join(bad)) if bad else '',
        ('; ' + run['error']) if run.get('error') else ''),
        'info' if run['ok'] else 'bad', who=by)
    log('remote backup: %s' % ('sent to ' + ', '.join(good) if good else 'not sent')
        + (' - failed: ' + '; '.join(bad) if bad else '')
        + (' - ' + run['error'] if run.get('error') else ''), 'info' if run['ok'] else 'warn')
    return run


def human_bytes(n):
    n = float(n or 0)
    for unit in ('B', 'kB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return ('%d %s' % (n, unit)) if unit == 'B' else ('%.1f %s' % (n, unit))
        n /= 1024.0
    return '%d B' % n


def rb_history(store):
    try:
        got = json.loads(store.get_meta('rbackup:runs') or '[]')
    except ValueError:
        got = []
    return [x for x in got if isinstance(x, dict)]


def rb_history_forget(store, at=None, file=None):
    """One line off the list (at and file), or all of it (1.0.110). The
    backups themselves stay where they went."""
    with RB_LOCK:
        runs = rb_history(store)
        if at is None:
            left = []
        else:
            left = [r for r in runs if not (abs(float(r.get('at') or 0) - float(at)) < 0.001 and
                                           str(r.get('file') or '') == str(file or ''))]
        store.set_meta('rbackup:runs', json.dumps(left, default=str))
        return len(runs) - len(left)


def rb_history_add(store, run):
    with RB_LOCK:
        runs = [run] + rb_history(store)
        store.set_meta('rbackup:runs', json.dumps(runs[:60], default=str))


def rb_job_start(store, by, only=None):
    """In a thread of its own; the page follows RB_JOB."""
    with RB_LOCK:
        if RB_JOB['running']:
            raise ValueError('a backup is being made already')
        RB_JOB.update(running=True, what='backup', says='starting', done=0, whole=6, error='',
                      began=time.time(), ended=0, result=None, by=by)

    def progress(done, whole, says):
        RB_JOB.update(done=done, whole=whole, says=says)

    def work():
        try:
            RB_JOB['result'] = rb_run(store, by, only, progress)
            if RB_JOB['result'].get('error'):
                RB_JOB['error'] = RB_JOB['result']['error']
            elif RB_JOB['result'].get('ok') and CONFIG.get('rbackup_verify') == 'after':
                # Tried at once, at the first destination it went to (1.0.169).
                RB_JOB.update(what='verify', says='the backup just sent is tried', done=0, whole=4)
                sent = RB_JOB['result']
                v = rb_verify(store, by, sent['targets'][0]['id'], sent.get('file'), progress)
                sent['verified'] = v
                if not v['ok']:
                    RB_JOB['error'] = 'sent, but it is not good: ' + '; '.join(
                        c['what'] for c in v['checks'] if not c['ok'])
        except Exception as e:                          # noqa: BLE001
            RB_JOB['error'] = scrub_secret(str(e))[:400]
            log('remote backup failed: %s' % e, 'error')
        finally:
            RB_JOB.update(running=False, ended=time.time())
    threading.Thread(target=work, name='rbackup', daemon=True).start()
    return dict(RB_JOB)


def rb_due(store, last_day):
    """Whether the scheduled backup is due now; the day it is for."""
    if not CONFIG.get('rbackup'):
        return None
    try:
        hh, mm = (int(x) for x in str(CONFIG.get('rbackup_at') or '04:00').split(':', 1))
    except ValueError:
        hh, mm = 4, 0
    now = datetime.now()
    if (now.hour, now.minute) < (hh, mm):
        return None
    if str(CONFIG.get('rbackup_every') or 'daily') == 'weekly' and \
            now.isoweekday() != int(CONFIG.get('rbackup_day') or 7):
        return None
    today = now.strftime('%Y-%m-%d')
    return today if today != last_day else None


RB_NOW_LIVE_S = 900


def rb_now_ask_others(store, by):
    """Back up now on the other nodes too (1.0.149), as the schedule does: each
    node makes its own. Asked in a row of the asking node's own per node
    asked - 'rbackup:now:NODE@@ASKER' - so only one node ever writes it."""
    if not CONFIG.get('ha_mode'):
        return []
    asked = []
    ident = secrets.token_hex(6)
    for n in ha_nodes(store):
        if n.get('me') or not n.get('alive'):
            continue
        store.set_meta(node_key('rbackup:now', n['name']),
                       json.dumps({'id': ident, 'at': time.time(), 'by': by,
                                   'from': node_name()}))
        asked.append(n['name'])
    return asked


def rb_now_asked(daemon):
    """A Back up now asked of this node by another; started once each."""
    store = daemon.store
    done_k = 'rbackup:nowdone:' + node_name()
    try:
        done = set(json.loads(store.get_meta(done_k) or '[]'))
    except ValueError:
        done = set()
    for r in node_key_rows(store, 'rbackup:now', node_name()):
        try:
            ask = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        ident = str(ask.get('id') or '')
        if not ident or ident in done or time.time() - float(ask.get('at') or 0) > RB_NOW_LIVE_S:
            continue
        if RB_JOB['running']:
            return                      # asked again at the next tick
        store.set_meta(done_k, json.dumps(sorted(done | {ident})[-20:]))
        rb_job_start(store, '%s (Back up now on %s)' % (ask.get('by') or 'acme',
                                                        ask.get('from') or '?'))
        return


def rb_tick(daemon):
    """Once a minute from the daemon's loop: the scheduled backup, this node's."""
    store = daemon.store
    if CONFIG.get('ha_mode'):
        try:
            rb_now_asked(daemon)
        except Exception as e:                          # noqa: BLE001
            log_sparing('rb-now:' + str(e)[:60], 'Back up now asked by the other node: %s'
                        % e, 'warn', 600)
    if not RB_JOB['running'] and rb_verify_due(store) and \
            time.time() - float(getattr(daemon, '_rb_verify_at', 0)) > 3600:
        daemon._rb_verify_at = time.time()          # once an hour at most, if it fails to start
        try:
            rb_verify_start(store, 'acme (weekly)')
        except ValueError:
            pass
    day = rb_due(store, getattr(daemon, '_rb_day', ''))
    if not day or RB_JOB['running']:
        return
    # Marked done only once the database said whether it is this run's
    # (1.0.146): the database away just then left the day without a backup.
    claimed = claim_once(store, 'rbackup_day:' + node_name(), day)
    daemon._rb_day = day
    if not claimed:
        return
    if not any(t.get('enabled') for t in rb_targets(store)):
        return
    rb_job_start(store, 'acme (scheduled)')


