# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- putting one back -----------------------------------------------------------------
def rb_open(path, password, work):
    """A backup file opened into `work`: its folder and its manifest - every
    file checked against the checksum the manifest has."""
    src = path
    with open(path, 'rb') as f:
        head = f.read(8)
    if head.startswith(b'Salted__'):
        if not password:
            raise RbError('the backup is locked: its password is needed')
        src = os.path.join(work, 'b.tar.gz')
        tries = [password]
        if password == rb_password() and rb_password_old():
            tries.append(rb_password_old())             # made here before 1.0.139
        for n, pw in enumerate(tries):
            try:
                _openssl(['enc', '-d', '-aes-256-cbc', '-pbkdf2', '-iter', str(RB_ITER), '-md',
                          'sha256', '-in', path, '-out', src, '-pass', 'fd:@'],
                         secret=pw, what='opening it')
                break
            except ValueError:
                if n == len(tries) - 1:
                    raise RbError('the password does not open it (or the file is damaged)')
    elif not head.startswith(b'\x1f\x8b'):
        raise RbError('that is not a backup of acme (neither locked nor a .tar.gz)')
    elif password:
        # Backups are always locked: an unlocked one where a password is in
        # play was put there by somebody else - its database, its accounts,
        # its key (1.0.139).
        raise RbError('the backup is not locked, and backups of acme always are - it was not '
                      'made by acme; not put in')
    out = os.path.join(work, 'x')
    os.makedirs(out, mode=0o700)
    with tarfile.open(src, 'r:gz') as tf:
        members = tf.getmembers()
        tops = set()
        for mb in members:
            parts = mb.name.split('/')
            if mb.name.startswith('/') or '..' in parts or not (mb.isfile() or mb.isdir()):
                raise RbError('the archive has a file it may not have: %r' % mb.name[:100])
            tops.add(parts[0])
        if len(tops) != 1:
            raise RbError('the archive is not one backup')
        # Unpacked only when it fits (1.0.136): a small file that unpacks to
        # more than the disk has would fill /var/lib/acme, the database's too.
        total = sum(mb.size for mb in members if mb.isfile())
        try:
            free = shutil.disk_usage(work).free
        except OSError:
            free = None
        if free is not None and total > free - 512 * 1024 * 1024:
            raise RbError('unpacked it is %s, more than there is room for here (%s free)'
                          % (human_bytes(total), human_bytes(max(0, free))))
        for mb in members:
            if mb.isfile():
                dst = os.path.join(out, *mb.name.split('/'))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with tf.extractfile(mb) as s, open(dst, 'wb') as d:
                    shutil.copyfileobj(s, d)
    top = os.path.join(out, tops.pop())
    try:
        with open(os.path.join(top, 'manifest.json')) as f:
            m = json.load(f)
    except (OSError, ValueError):
        raise RbError('there is no manifest in it')
    for rel, want in (m.get('files') or {}).items():
        p = os.path.join(top, *rel.split('/'))
        h = hashlib.sha256()
        try:
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
        except OSError:
            raise RbError('%s is missing from it' % rel)
        if h.hexdigest() != want.get('sha256'):
            raise RbError('%s is damaged (its checksum is not the one in the manifest)' % rel)
    return top, m


def rb_restore(store, path, password, by, keep_node_name=False, need_admin=True):
    """Everything in a backup put back on this machine: the database, the key
    of its sealed secrets, the node's name. The connection to the database in
    config.json stays this machine's."""
    work = tempfile.mkdtemp(prefix='acme-putback-', dir=str(STATE_DIR))
    os.chmod(work, 0o700)
    try:
        top, m = rb_open(path, password, work)
        got = db_file_restore(store, os.path.join(top, 'acme-copy.json.gz'), by,
                              key_file=os.path.join(top, 'secrets.key'),
                              from_name=os.path.basename(str(path)), need_admin=need_admin)
        said = [got.get('key') or '']
        old_name = node_name()
        if m.get('node') and not keep_node_name and m['node'] != old_name and \
                not CONFIG.get('ha_mode'):
            write_file_settings({'node_name': m['node']})
            CONFIG['node_name'] = m['node']
            try:
                node_carry(store, old_name, m['node'], by=by)
            except Exception:                           # noqa: BLE001
                pass
            said.append('this machine is node %s again (it was %s)' % (m['node'], old_name))
        store.add_event('backups', '%s put back the backup %s (made %s on %s, acme %s)' % (
            by, os.path.basename(str(path)), m.get('made_words'), m.get('node'), m.get('acme')),
            'warn', who=by)
        return {'manifest': m, 'safety': got.get('safety'), 'said': [x for x in said if x]}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def rb_fetch(store, tid, name, dst):
    t = rb_target(store, tid)
    if not t:
        raise ValueError('no such destination')
    if not RB_NAME_RE.match(str(name or '')):
        raise ValueError('not a backup of acme: %r' % str(name)[:80])
    tr = rb_transport(t)
    try:
        tr.open()
        tr.get(name, dst)
    finally:
        tr.close()


def rb_remote_list(store, tid):
    t = rb_target(store, tid)
    if not t:
        raise ValueError('no such destination')
    tr = rb_transport(t)
    try:
        tr.open()
        files = tr.list()
    finally:
        tr.close()
    names = set(x['name'] for x in files)
    out = []
    for x in files:
        m = RB_NAME_RE.match(x['name'])
        if not m:
            continue
        try:
            when = datetime.strptime(m.group('stamp'), '%Y%m%d-%H%M%S').timestamp()
        except ValueError:
            when = x.get('mtime') or 0
        out.append({'name': x['name'], 'bytes': x['size'], 'when': when,
                    'node': m.group('node'), 'site': m.group('site'),
                    'encrypted': bool(m.group('enc')),
                    'mine': m.group('node') == rb_slug(node_name()),
                    'sha256': (x['name'] + '.sha256') in names})
    out.sort(key=lambda x: -x['when'])
    return out



