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


def rb_plugins_dir():
    """The folder of modules of your own (acmelib/plugins/base.py REGISTRY)."""
    return os.environ.get('ACME_PLUGINS', '/etc/acme/plugins')


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
        'this file, the files config.json names (`files/`) and modules of your own',
        '(`plugins/`, put back into /etc/acme/plugins).', '',
        '## 2. A machine to put it on', '',
        'AlmaLinux / Rocky / RHEL 9 (or the machine it came from). Install acme **%s or newer**' % ver,
        'from its package - the same way as the first time:', '', '```bash',
        'tar xzf acme-%s.tar.gz && cd acme-%s' % (ver, ver),
        './install.sh                     # SQLite unless you choose otherwise',
        '```', '',
        'The backup goes into whichever database the new machine uses - SQLite after a plain',
        'install is fine. PostgreSQL (needed again for a cluster) can be chosen afterwards:',
        '`./install.sh --with-db postgres --yes`, then *Settings → The database → Move to',
        'another database…* (PostgreSQL 16 or later).', '',
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
        'The guard against writes to the database is switched on again if it was on.', '',
        'On the new machine, by itself: what the old one said it had in place is forgotten, so',
        'the SSH server, the time, the console at login and the password policy saved are put in',
        'there again (the web certificates, the VIP address and the firewall too); the SNMP',
        'engine keeps its ID. The keys of root made on the pages are put on again.', '',
        'Not in any backup - the machine\'s own, not acme\'s: the **local users** of the system',
        'and their passwords, and SSH keys added to authorized_keys other than on the pages.',
        '*Settings → Local users* lists the users the machine had (*Make them again* - the same',
        'name, UID, shell and sudo, no password); *SSH keys* the fingerprints of the keys it had.', '',
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
            # meta as the copy holds it: without the pieces of an uploaded
            # package, which the copy leaves out - counted, they made every
            # backup after an upgrade from the pages "not good".
            out[t] = int(store.db.value(
                "SELECT COUNT(*) FROM meta WHERE k NOT LIKE 'upgrade:piece:%'" if t == 'meta'
                else 'SELECT COUNT(*) FROM %s' % t) or 0)
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
    try:
        from acmelib.certs import custom_modules as _CM      # their files, kept (1.0.32)
        _CM.record(store)
    except Exception:                                   # noqa: BLE001
        pass
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
    # Modules of your own (ACME_PLUGINS, /etc/acme/plugins): sources, validations,
    # targets written for this installation - put back with the rest.
    pdir = rb_plugins_dir()
    if pdir and os.path.isdir(pdir):
        for root, _dirs, files in os.walk(pdir):
            for n in files:
                if not n.endswith('.py'):
                    continue
                src = os.path.join(root, n)
                dst = os.path.join(inner, 'plugins', os.path.relpath(src, pdir))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(src, dst)
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


def rb_retain(tr, keep, days, now=None, sent=None):
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
            # A time ahead of now (a clock that was wrong when it was made, 1.0.48): never the
            # newest - it kept itself for good and had the one just sent taken away.
            if when > now + 86400:
                when = 0
            ours.append((when, x['name']))
    ours.sort(reverse=True)
    gone = []
    for i, (when, name) in enumerate(ours):
        if i == 0 or (sent and name == sent):
            continue                    # never the newest, never the one just sent
        if (keep and i >= keep) or (days and now - when > days * 86400):
            for n in [name] + [c for c in rb_companions(name) if c in names]:
                try:
                    tr.delete(n)
                except Exception:                       # noqa: BLE001
                    pass
            gone.append(name)
    return gone


def rb_room(store, times=2):
    """Room for a backup made, locked or opened beside the live database (otp 1.0.234): the copy
    and its archive, then the archive and its locked one - twice the database at once. A nightly
    backup filled the disk under a SQLite database, and every sign-in was refused."""
    try:
        free = shutil.disk_usage(str(STATE_DIR)).free
    except OSError:
        return
    size = 0
    if store.db.engine == 'sqlite':
        try:
            size = os.path.getsize(str(store.db.path))
        except (OSError, TypeError):
            size = 0
    need = times * size + BACKUP_ROOM_MIN
    if free < need:
        raise RbError('there is no room for it in %s: %d MB free, %d MB needed so that the disk '
                      'is not filled under the database - take old copies away, or give the disk '
                      'more room' % (STATE_DIR, free >> 20, need >> 20))


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
    rb_room(store)
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
                                                  int(CONFIG.get('rbackup_keep_days') or 0),
                                                  sent=m['file'])
                except Exception as e:                  # noqa: BLE001
                    one['retain_error'] = str(e)[:200]
            except Exception as e:                      # noqa: BLE001
                one['error'] = rb_said(e)
            finally:
                tr.close()
            one['secs'] = round(time.time() - t0, 1)
            run['targets'].append(one)
            rb_last_set(store, t['id'], {
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


RB_RUNS_OLD = 'rbackup:runs'          # one row for both nodes, until 1.0.43


def _rb_runs_rows(store):
    """{key: [run...]}: each node's own row (1.0.44), and the one row of before."""
    out = {}
    rows = store.db.rows("SELECT k, v FROM meta WHERE k = ? OR k LIKE ?",
                         (RB_RUNS_OLD, RB_RUNS_OLD + '@@%'))
    for r in rows:
        try:
            got = json.loads(r.get('v') or '[]')
        except ValueError:
            got = []
        out[r['k']] = [x for x in (got if isinstance(got, list) else []) if isinstance(x, dict)]
    return out


def rb_forgotten(store):
    """The lines of the other node taken off the list here (1.0.45): {(at, file)} - each node
    forgets in its own row, and every node's list leaves them out."""
    out = set()
    for r in store.db.rows("SELECT v FROM meta WHERE k LIKE 'rbackup:forgot%'"):
        try:
            got = json.loads(r['v'] or '{}')
            if not isinstance(got, dict):
                continue
            for x in got.get('lines') or []:
                if isinstance(x, list) and len(x) == 2:
                    out.add((round(float(x[0] or 0), 3), str(x[1] or '')))
            if got.get('all_before'):
                out.add(('all_before', float(got['all_before'])))
        except (ValueError, TypeError, AttributeError):
            continue
    return out


def rb_history(store):
    """The backups sent away, newest first - every node's. Each node keeps its own row
    (1.0.44): two backups made at once on the two nodes each wrote the one row over the
    other's, and one of them was gone from the list (and from the alerts)."""
    runs = []
    for got in _rb_runs_rows(store).values():
        runs += got
    gone = rb_forgotten(store)
    before = max([b for a, b in gone if a == 'all_before'] or [0])
    runs = [r for r in runs if float(r.get('at') or 0) > before and
            (round(float(r.get('at') or 0), 3), str(r.get('file') or '')) not in gone]
    runs.sort(key=lambda r: float(r.get('at') or 0), reverse=True)
    return runs[:120]


def rb_history_forget(store, at=None, file=None):
    """One line off the list (at and file), or all of it (1.0.110). The
    backups themselves stay where they went."""
    with RB_LOCK:
        rows = _rb_runs_rows(store)
        gone = 0
        # This node's own row and the one of before only (1.0.45): one writer a row - the
        # other node's rewritten here crossed its own write of a new run.
        mine = node_key('rbackup', 'runs')
        others = [r for k, v in rows.items() if k not in (mine, RB_RUNS_OLD) for r in v]
        rows = {k: v for k, v in rows.items() if k in (mine, RB_RUNS_OLD)}
        # ...and the other node's lines noted as forgotten in this node's own row, which every
        # node's list leaves out.
        fk = node_key('rbackup', 'forgot')
        try:
            fg = json.loads(store.get_meta(fk) or '{}')
        except ValueError:
            fg = {}
        if not isinstance(fg, dict) or not isinstance(fg.get('lines') or [], list):
            fg = {}
        if at is None:
            fg['all_before'] = time.time()
            gone += len(others)
        else:
            hit = [r for r in others if abs(float(r.get('at') or 0) - float(at)) < 0.001 and
                   str(r.get('file') or '') == str(file or '')]
            if hit:
                # the line's own time, as rb_history compares it - not the one sent
                fg['lines'] = (fg.get('lines') or [])[-500:] + [
                    [round(float(x.get('at') or 0), 3), str(file or '')] for x in hit]
                gone += len(hit)
        store.set_meta(fk, json.dumps(fg))
        for k, runs in rows.items():
            if at is None:
                left = []
            else:
                left = [r for r in runs if not (abs(float(r.get('at') or 0) - float(at)) < 0.001
                                               and str(r.get('file') or '') == str(file or ''))]
            if len(left) != len(runs):
                gone += len(runs) - len(left)
                store.set_meta(k, json.dumps(left, default=str))
        return gone


def rb_history_add(store, run):
    with RB_LOCK:
        k = node_key('rbackup', 'runs')
        try:
            mine = json.loads(store.get_meta(k) or '[]')
        except ValueError:
            mine = []
        mine = [run] + [x for x in mine if isinstance(x, dict)]
        store.set_meta(k, json.dumps(mine[:60], default=str))


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
    rb_now_tidy(store)
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


def rb_now_tidy(store):
    """This node's asks of Back up now that are over (1.0.45): never taken away, an ask of
    an older version (unsigned) was refused by the other node for good, at every look."""
    t = time.time()
    me = NODE_KEY_SEP + node_name()[:63]            # as node_key() writes it
    # ...and those of a node forgotten or renamed since (1.0.46), whoever tidies: nobody else
    # would ever take them away.
    try:
        known = {str(n.get('name') or '')[:63] for n in ha_nodes(store)}
    except Exception:                                   # noqa: BLE001
        known = set()
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE 'rbackup:now:%'"):
        asker = str(r['k']).rsplit(NODE_KEY_SEP, 1)[-1] if NODE_KEY_SEP in str(r['k']) else ''
        if not str(r['k']).endswith(me) and not (known and node_name()[:63] in known
                                                 and asker and asker not in known):
            continue
        try:
            at = float((json.loads(r['v'] or '{}') or {}).get('at') or 0)
        except (ValueError, TypeError, AttributeError):
            at = 0
        if t - at > RB_NOW_LIVE_S:
            store.db.run('DELETE FROM meta WHERE k = ? AND v = ?', (r['k'], r['v']))


def rb_now_asked(daemon):
    """A Back up now asked of this node by another; started once each."""
    store = daemon.store
    done_k = 'rbackup:nowdone:' + node_name()
    try:
        done = set(str(x) for x in json.loads(store.get_meta(done_k) or '[]'))
    except (ValueError, TypeError):
        done = set()
    for r in node_key_rows(store, 'rbackup:now', node_name()):
        try:
            ask = json.loads(r['v'] or '{}')
        except ValueError:
            continue
        if not isinstance(ask, dict):
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
            rb_now_tidy(store)
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
    # The scheduled one failed (every destination away - a NAS restarting): tried again each
    # hour that day, three times (1.0.45) - it waited for the next day, or a whole week.
    today = datetime.now().strftime('%Y-%m-%d')
    if getattr(daemon, '_rb_day', '') == today and not RB_JOB['running'] and \
            getattr(daemon, '_rb_again', 0) < 3 and \
            time.time() - float(getattr(daemon, '_rb_tried', 0) or 0) > 3600:
        mine = [r for r in rb_history(store) if r.get('node') == node_name()]
        # Only after the scheduled one (a failed Back up now of one destination is no reason),
        # and only while backups are on, to a destination switched on.
        if CONFIG.get('rbackup') and any(t.get('enabled') for t in rb_targets(store)) and \
                mine and not mine[0].get('ok') and \
                str(mine[0].get('by') or '').startswith('acme (scheduled') and \
                datetime.fromtimestamp(float(mine[0].get('at') or 0)).strftime('%Y-%m-%d') == today:
            daemon._rb_again = getattr(daemon, '_rb_again', 0) + 1
            daemon._rb_tried = time.time()
            # Only to the destinations that failed (1.0.46): one NAS away sent the backup again
            # to all of them, and each kept only so many - a week of S3 became two days.
            on = {t['id'] for t in rb_targets(store) if t.get('enabled')}
            failed = [x.get('id') for x in (mine[0].get('targets') or [])
                      if isinstance(x, dict) and not x.get('ok') and x.get('id') in on]
            try:
                rb_job_start(store, 'acme (scheduled, again: the one before failed)',
                             only=failed or None)
            except ValueError:
                pass
            return
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
    daemon._rb_again, daemon._rb_tried = 0, time.time()
    rb_job_start(store, 'acme (scheduled)')


