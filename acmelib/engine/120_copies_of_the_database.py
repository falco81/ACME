# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Copies of the database
# ---------------------------------------------------------------------------
BACKUP_ROOM_MIN = 128 << 20


def backup_room_check(store, folder=None):
    """Room left for a copy without filling the disk (1.0.149): a full disk
    under a SQLite database refused every sign-in until space was freed.
    What the copy may take - the database file itself at most - and 128 MB
    more must stay free."""
    try:
        free = shutil.disk_usage(str(folder or BACKUP_DIR)).free
    except OSError:
        return
    size = 0
    if store.db.engine == 'sqlite':
        try:
            size = os.path.getsize(str(store.db.path))
        except (OSError, TypeError):
            size = 0
    need = size + BACKUP_ROOM_MIN
    if free < need:
        raise ValueError('there is no room for a copy in %s: %d MB free, %d MB needed so that '
                         'the disk is not filled under the database - take old copies away, '
                         'or give the disk more room' % (folder or BACKUP_DIR, free >> 20,
                                                         need >> 20))


def make_backup(store, why='by hand'):
    """A copy of everything into the backups folder - and the key that opens
    its sealed secrets beside it, because one without the other is nothing."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_room_check(store)
    stamp_ = datetime.now().strftime('%Y%m%d-%H%M%S')
    # A name of its own (two in one second overwrote each other) and written
    # under another until it is whole (1.0.59): a half file counted as a
    # kept copy and pushed a good one out.
    # The name taken with O_EXCL (1.0.61): two processes - the daemon's
    # nightly copy and a root --backup - in the same second both saw it free.
    base = stamp_
    for suffix in [''] + ['-' + c for c in 'bcdefghijklmnopqrstuvwxyz']:
        stamp_ = base + suffix
        out = BACKUP_DIR / ('acme-%s.json.gz' % stamp_)
        try:
            os.close(os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640))
            break
        except FileExistsError:
            continue
    else:
        raise ValueError('no free name for a copy in %s' % BACKUP_DIR)
    # A name nobody can have put there first, opened without following a
    # link, its mode and owner set on the open file (1.0.101): run by root
    # (--ha-resync, --backup) in a folder the service's account can write,
    # the name it wrote to was the service account's to point anywhere.
    part = BACKUP_DIR / ('.acme-%s-%s.json.gz.part' % (stamp_, secrets.token_hex(6)))
    owner = service_ids() if os.geteuid() == 0 else None
    try:
        fd = os.open(str(part), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        os.fchmod(fd, 0o640)
        if owner:
            os.fchown(fd, owner[0], owner[1])
        try:
            # modules of your own go into the copy with what they are (1.0.32)
            from acmelib.certs import custom_modules as _CM
            _CM.record(store)
        except Exception:                               # noqa: BLE001
            pass
        with os.fdopen(fd, 'wb') as raw_f:
            dump_tables(store.db, raw_f)
        os.replace(str(part), str(out))
    except BaseException:
        try:
            out.unlink()            # the empty name taken, given back
        except OSError:
            pass
        raise
    finally:
        try:
            part.unlink()
        except OSError:
            pass
    key = sealing_key()
    if key:
        # Made by root on the command line (1.0.59): the service's own, or
        # the pages could neither list, download nor put it back.
        write_replacing(BACKUP_DIR / ('acme-%s.key' % stamp_), key.hex() + '\n', 0o600,
                        owner=owner)
    keep = int(CONFIG.get('backup_keep') or 14)
    copies = sorted(list(BACKUP_DIR.glob('acme-*.json.gz')) + list(BACKUP_DIR.glob('opt-*.json.gz')),
                    key=lambda f: f.stat().st_mtime)
    for old in copies[:-keep] if len(copies) > keep else []:
        for f in (old, old.with_name(old.name.replace('.json.gz', '.key'))):
            try:
                f.unlink()
            except OSError:
                pass
    store.add_event('backups', 'a copy of the database was made (%s): %s' % (why, out.name))
    return out


def backups():
    if not BACKUP_DIR.is_dir():
        return []
    out = []
    for f in sorted(list(BACKUP_DIR.glob('acme-*.json.gz')) + list(BACKUP_DIR.glob('opt-*.json.gz')),
                   key=lambda f: f.stat().st_mtime, reverse=True):
        st = f.stat()
        out.append({'name': f.name, 'size': st.st_size, 'at': st.st_mtime,
                    'key': f.with_name(f.name.replace('.json.gz', '.key')).exists()})
    return out




STALE_WORK = ('acme-rbackup-', 'acme-putback-', 'acme-download-', 'acme-dl-', 'acme-peek-',
              'acme-fetch-')


def stale_work_away(older=6 * 3600):
    """What a backup, a download or a putting back left in the state folder
    when the program stopped in the middle of it (1.0.146) - a copy of the
    database, unlocked, for nobody. Hours old only: the command line may be
    at one just now."""
    try:
        items = list(STATE_DIR.iterdir())
    except OSError:
        return
    for p in items:
        if not p.name.startswith(STALE_WORK):
            continue
        try:
            if time.time() - p.lstat().st_mtime < older:
                continue
            if p.is_dir() and not p.is_symlink():
                shutil.rmtree(str(p), ignore_errors=True)
            else:
                p.unlink()
            log('left from before, taken away: %s' % p.name, 'info')
        except OSError:
            pass
