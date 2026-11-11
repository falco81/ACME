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
        # its key (1.0.139). One fetched from a destination is refused unlocked
        # whether a password is in play or not (rb_fetch).
        raise RbError('the backup is not locked, and backups of acme always are - it was not '
                      'made by acme; not put in')
    out = os.path.join(work, 'x')
    os.makedirs(out, mode=0o700)
    try:
        tf = tarfile.open(src, 'r:gz')
        members = tf.getmembers()
    except (tarfile.TarError, OSError, EOFError) as e:
        # A gzip file that is no archive (a copy of the database, 1.0.45): said, not a traceback.
        raise RbError('that is not a backup of acme (no archive in it: %s) - a copy of the '
                      'database is put back with acme --restore' % str(e)[:80])
    with tf:
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
        # A copy made while a job ran (1.0.19): its rows came back as running, and
        # kept their certificate busy for hours - nothing runs them here now.
        try:
            began = time.time()
            store.db.run("UPDATE certs SET state = 'failed', last_error = ? WHERE state = "
                         "'renewing' AND id IN (SELECT cert_id FROM cert_jobs WHERE state IN "
                         "('queued', 'running') AND ts < ?)",
                         ('the backup put back was made while it was renewed', began))
            n = store.db.run("UPDATE cert_jobs SET state = 'failed', ok = 0, finished = ?, "
                             "said = ? WHERE state IN ('queued', 'running') AND ts < ?",
                             (began, 'the backup put back was made while it ran', began))
            if n:
                said.append('%s job(s) running when the backup was made are marked failed' % n)
        except Exception as e:                          # noqa: BLE001
            log('the jobs of the backup put back could not be tidied: %s' % e, 'warn')
        # Modules of your own, as they were (a file of the same name is replaced).
        pin = os.path.join(top, 'plugins')
        if os.path.isdir(pin):
            pdir = rb_plugins_dir()
            n = 0
            try:
                for root, _dirs, files in os.walk(pin):
                    for f in files:
                        if not f.endswith('.py'):
                            continue
                        src = os.path.join(root, f)
                        dst = os.path.join(pdir, os.path.relpath(src, pin))
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        shutil.copyfile(src, dst)
                        n += 1
                said.append('%d module(s) of your own put back into %s' % (n, pdir))
            except OSError as e:
                said.append('the modules of your own could not be put into %s: %s - they '
                            'are in plugins/ of the backup' % (pdir, e))
        # Another machine than the one the backup was made on (1.0.43): what that one said it had
        # (the SSH server, the time, the console...) is forgotten here, so that it is put in.
        try:
            if machine_changed_check(store, put_back=True, name=m.get('node') or None):
                said.append('what the machine of the backup had in place is put in on this one')
            # The other nodes of the cluster it came from too: built again into the cluster
            # (a clean machine under the old name), each puts in what is wanted, and gets its
            # users and keys back to make again; one that is the same machine reads it again.
            others = set()
            for pre in MACHINE_ROWS:
                for r in store.db.rows('SELECT k FROM meta WHERE k LIKE ?', (pre + '%',)):
                    n = r['k'][len(pre):]
                    if n and n != (m.get('node') or node_name()) and '@@' not in n:
                        others.add(n)
            for n in sorted(others):
                machine_changed_check(store, put_back=True, name=n)
        except Exception as e:                          # noqa: BLE001
            log('the machine of the backup could not be compared: %s' % e, 'warn')
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
        # The SNMP engine of the node as the backup has it (1.0.44): the file a first start here
        # wrote (a new, random ID) came first, and wrote that over the database's at once.
        try:
            eng = str(store.get_meta('snmp:engine:' + node_name(), '') or '')
            if re.match(r'^[0-9a-f]{18,64}\Z', eng):
                try:
                    had = (STATE_DIR / 'snmp-engine').read_text().strip()
                except OSError:
                    had = ''
                (STATE_DIR / 'snmp-engine').write_text(eng + '\n')
                # The count of starts kept when the engine is the same (1.0.79): the backup's
                # older count came back - engineBoots went from 13 to 4 under the same ID, and
                # the receivers refused the traps (RFC 3414) - the larger of the two is taken.
                if had != eng:
                    try:
                        (STATE_DIR / 'snmp-boots').unlink()
                    except OSError:
                        pass
        except Exception as e:                          # noqa: BLE001
            log('the SNMP engine of the backup could not be put in place: %s' % e, 'warn')
        # (After the name: its rows are signed as the node it is now.)
        # The guard against writes to the database (1.0.43): kept in config.json, not in the
        # database - a node made again from its backup had it off. On again, as it was, once
        # the rows are signed as this node's word (db_file_restore did that).
        try:
            with open(os.path.join(top, 'config.json')) as f:
                was = json.load(f)
        except (OSError, ValueError):
            was = {}
        if isinstance(was, dict) and was.get('db_guard') and not CONFIG.get('db_guard'):
            if dbguard_key():
                n = dbguard_resign(store, 'the guard switched on again with the backup put back '
                                          'by %s' % by)
                write_file_settings({'db_guard': 1})
                CONFIG['db_guard'] = 1
                store.set_meta('conf_serial', '%.6f:%s' % (time.time(), node_name()))
                said.append('the guard against writes to the database is on again, as it was '
                            '(%d rows signed)' % n)
            else:
                said.append('the guard against writes to the database was on - it could not be '
                            'switched on here: no secrets.key to sign with')
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
    # Sent away, a backup is always locked (rb_run refuses without a password): an unlocked one
    # there was put by somebody else - on a machine with no password set yet it was put back
    # (otp 1.0.234; its checksums are only what its maker wrote).
    try:
        with open(str(dst), 'rb') as f:
            head = f.read(8)
    except OSError:
        head = b''
    if not head.startswith(b'Salted__'):
        try:
            os.unlink(str(dst))
        except OSError:
            pass
        raise RbError('the backup is not locked, and backups of acme sent away always are - it '
                      'was not made by acme; not put in')


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
                    # this node's of this installation (1.0.48): a node of another site with the
                    # same name, on a shared destination, had its backup tried as this one's
                    'mine': m.group('node') == rb_slug(node_name()) and
                    (m.group('site') or '') == rb_slug(CONFIG.get('site_name') or 'acme'),
                    'sha256': (x['name'] + '.sha256') in names})
    out.sort(key=lambda x: -x['when'])
    return out



