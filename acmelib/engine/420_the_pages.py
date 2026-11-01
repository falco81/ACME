# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- the pages ----------------------------------------------------------------------
RB_UPLOADS = STATE_DIR / 'rbackup-uploads'


def rb_tools():
    return {k: bool(shutil.which(k)) for k in ('ssh', 'sftp', 'scp', 'ssh-keygen', 'ssh-keyscan',
                                                'smbclient', 'openssl')}


def rb_page(store):
    nodes = {}
    for r in rb_history(store):
        nodes.setdefault(r.get('node') or '?', r)
    return {'targets': [rb_view(t) for t in rb_targets(store)], 'runs': rb_history(store)[:40],
            'verified': rb_verified(store)[:20],
            'last_by_node': nodes, 'job': {k: v for k, v in RB_JOB.items()},
            'kinds': [{'kind': k, 'words': RB_KIND_WORDS[k], 'port': RB_PORTS.get(k)}
                      for k in RB_KINDS],
            'tools': rb_tools(), 'node': node_name(), 'locked': bool(rb_password()),
            'iter': RB_ITER, 'site': CONFIG.get('site_name') or 'acme',
            'next': rb_next_words()}


def rb_next_words():
    if not CONFIG.get('rbackup'):
        return ''
    try:
        hh, mm = (int(x) for x in str(CONFIG.get('rbackup_at') or '04:15').split(':', 1))
    except ValueError:
        hh, mm = 4, 15
    now = datetime.now()
    nxt = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    if str(CONFIG.get('rbackup_every')) == 'weekly':
        want = int(CONFIG.get('rbackup_day') or 7)
        while nxt.isoweekday() != want:
            nxt += timedelta(days=1)
    return nxt.isoformat(timespec='minutes')


@route('GET', '/api/rbackup')
def _rbackup(h):
    h.me('fulladmin')
    return rb_page(h.store)


def _rb_target_for(h, b):
    """The destination asked about: the one saved, with what is typed over
    it (Try it before Save)."""
    tid = str(b.get('id') or '')
    old = rb_target(h.store, tid) if tid else None
    if tid and not old:
        raise ApiError(404, 'no such destination')
    if isinstance(b.get('target'), dict):
        try:
            t = rb_checked(dict(b['target'], id=tid or None), old)
        except ValueError as e:
            raise ApiError(400, str(e))
        if old:
            for k in ('key', 'pub', 'hostkey', 'client_cert', 'client_key', 'key_pass', 'ca',
                      'pin', 'ssh_cert'):
                if k in old and k not in t:
                    t[k] = old[k]
        return t
    if not old:
        raise ApiError(400, 'which destination?')
    return old


@route('POST', '/api/rbackup')
def _rbackup_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    by = s['name']
    try:
        if act == 'save':
            t = rb_save(h.store, dict(b.get('target') or {}, id=b.get('id') or
                                      (b.get('target') or {}).get('id')), by)
            return {'message': 'saved', 'target': rb_view(t)}
        if act == 'delete':
            rb_delete(h.store, b.get('id'), by)
            return {'message': 'taken away'}
        if act == 'try':
            t = _rb_target_for(h, b)
            out = {}
            if t['kind'] in ('sftp', 'scp') and not t.get('hostkey'):
                lines, fps = ssh_keyscan(t['host'], t['port'])
                return {'hostkey_needed': True, 'hostkey': lines, 'fingerprints': fps,
                        'message': 'the server\'s host key is not trusted yet'}
            out = rb_try(t)
            h.store.add_event('settings', '%s tried the backup destination %s: %s' % (
                by, t['name'], 'it works' if out['ok'] else out.get('error')), who=by)
            if t.get('id') and rb_target(h.store, t['id']):
                rb_set_fields(h.store, t['id'], '', '', tried={'at': time.time(), 'ok': out['ok'],
                                                               'error': out.get('error') or ''})
            return out
        if act == 'hostkey_scan':
            t = _rb_target_for(h, b)
            lines, fps = ssh_keyscan(t['host'], t['port'])
            return {'hostkey': lines, 'fingerprints': fps}
        if act == 'hostkey_trust':
            t = _rb_target_for(h, b)
            lines = str(b.get('hostkey') or '')
            fresh, fps = ssh_keyscan(t['host'], t['port'])
            # Only what the server shows now, as the page showed it: nothing
            # typed in its place.
            if sorted(x.strip() for x in lines.splitlines() if x.strip()) != \
                    sorted(x.strip() for x in fresh.splitlines() if x.strip()):
                raise ValueError('the server shows other host keys now than the ones shown: '
                                 'Try it again')
            rb_set_fields(h.store, t['id'], by, 'its host key trusted (%s)' % '; '.join(fps),
                          hostkey=fresh)
            return {'message': 'trusted', 'fingerprints': fps}
        if act == 'hostkey_forget':
            t = _rb_target_for(h, b)
            rb_set_fields(h.store, t['id'], by, 'its host key forgotten', hostkey=None)
            return {'message': 'forgotten'}
        if act == 'keygen':
            t = _rb_target_for(h, b)
            private, public = ssh_keygen('acme-backup@%s' % node_name())
            rb_set_fields(h.store, t['id'], by, 'a new ssh key made here',
                          key=seal_secret(private, bind=RB_BIND), pub=public, key_pass=None)
            return {'message': 'made', 'pub': public}
        if act == 'key_paste':
            t = _rb_target_for(h, b)
            pp = str(b.get('passphrase') or '')
            private, public = ssh_public_of(b.get('key'), pp)
            rb_set_fields(h.store, t['id'], by, 'an ssh key of their own given',
                          key=seal_secret(private, bind=RB_BIND), pub=public,
                          key_pass=seal_secret(pp, bind=RB_BIND) if pp else None)
            return {'message': 'taken', 'pub': public}
        if act == 'key_download':
            t = _rb_target_for(h, b)
            private = rb_secret(t, 'key')
            if not private:
                raise ApiError(404, 'there is no key')
            h.store.add_event('settings', '%s downloaded the private ssh key of the backup '
                              'destination %s' % (by, t['name']), 'warn', who=by)
            return {'pem': private if private.endswith('\n') else private + '\n',
                    'file': 'acme-backup-%s-key' % rb_slug(t['name'])}
        if act == 'key_forget':
            t = _rb_target_for(h, b)
            rb_set_fields(h.store, t['id'], by, 'its ssh key forgotten', key=None, pub=None,
                          key_pass=None, ssh_cert=None)
            return {'message': 'forgotten'}
        if act == 'cert_make':
            t = _rb_target_for(h, b)
            key, crt = rb_client_cert_make(b.get('cn') or 'acme-backup-%s' % rb_slug(node_name()))
            rb_set_fields(h.store, t['id'], by, 'a client certificate made here',
                          client_cert=crt, client_key=seal_secret(key, bind=RB_BIND))
            return {'message': 'made', 'cert': crt, 'info': cert_info(crt)}
        if act == 'cert_given':
            t = _rb_target_for(h, b)
            key, crt = rb_client_cert_given(b.get('text'), str(b.get('password') or ''))
            rb_set_fields(h.store, t['id'], by, 'a client certificate of their own given',
                          client_cert=crt, client_key=seal_secret(key, bind=RB_BIND))
            return {'message': 'taken', 'cert': crt, 'info': cert_info(crt)}
        if act == 'cert_forget':
            t = _rb_target_for(h, b)
            rb_set_fields(h.store, t['id'], by, 'its client certificate forgotten',
                          client_cert=None, client_key=None)
            return {'message': 'forgotten'}
        if act == 'pin':
            t = _rb_target_for(h, b)
            pin = re.sub(r'[^0-9a-f]', '', str(b.get('pin') or '').lower())
            if len(pin) != 64:
                raise ValueError('the fingerprint is SHA-256: 64 hex digits')
            rb_set_fields(h.store, t['id'], by, 'the server\'s certificate pinned (%s)' % pin,
                          pin=pin, tls_check='pin')
            return {'message': 'pinned'}
        if act == 'run':
            only = [str(x) for x in (b.get('ids') or [])] or None
            job = rb_job_start(h.store, by, only)
            # Every node's, as the schedule makes them (1.0.149): in a cluster
            # Back up now made only the backup of the node the page was on.
            others = rb_now_ask_others(h.store, by) if not only else []
            return {'message': 'the backup is being made' + (
                ' here; %s make%s theirs within a minute' % (
                    ', '.join(others), 's' if len(others) == 1 else '') if others else ''),
                'job': job, 'others': others}
        if act == 'job':
            return {'job': dict(RB_JOB)}
        if act == 'verify':
            # Tried without being put back (1.0.169), followed as a backup is.
            job = rb_verify_start(h.store, by, str(b.get('id') or '') or None,
                                  str(b.get('name') or '') or None)
            return {'message': 'the backup is being tried', 'job': job}
        if act == 'verified':
            return {'verified': rb_verified(h.store)[:40]}
        if act == 'verified_forget':
            at = None
            if not b.get('all'):
                try:
                    at = float(b.get('at'))
                except (TypeError, ValueError):
                    raise ValueError('which try?')
            n = rb_verified_forget(h.store, at)
            if not n:
                raise ValueError('that try is not on the list any more')
            h.store.add_event('backups', '%s took %d tr%s of backups off the list; the backups '
                              'stay where they are' % (by, n, 'y' if n == 1 else 'ies'), who=by)
            return {'message': 'taken off the list', 'verified': rb_verified(h.store)[:20]}
        if act == 'list':
            return {'files': rb_remote_list(h.store, b.get('id'))}
        if act == 'delete_file':
            t = rb_target(h.store, b.get('id'))
            name = str(b.get('name') or '')
            if not t or not RB_NAME_RE.match(name):
                raise ValueError('which backup?')
            tr = rb_transport(t)
            try:
                tr.open()
                names = set(x['name'] for x in tr.list())
                for n in [name] + [c for c in rb_companions(name) if c in names]:
                    tr.delete(n)
            finally:
                tr.close()
            h.store.add_event('backups', '%s deleted the backup %s at %s' % (by, name, t['name']),
                              'warn', who=by)
            return {'message': 'deleted'}
        if act == 'restore_md':
            return rb_restore_guide(h.store)
        if act == 'runs_forget':
            if b.get('all'):
                n = rb_history_forget(h.store)
                h.store.add_event('backups', '%s cleared the list of backups sent (%d line(s)); '
                                  'the backups stay where they went' % (by, n), who=by)
                return {'message': 'the list is empty; the backups stay where they went',
                        'runs': rb_history(h.store)[:40]}
            try:
                at = float(b.get('at'))
            except (TypeError, ValueError):
                raise ValueError('which line?')
            n = rb_history_forget(h.store, at, b.get('file'))
            if not n:
                raise ValueError('that line is not on the list any more')
            h.store.add_event('backups', '%s took %s off the list of backups sent; the backup '
                              'stays where it went' % (by, b.get('file') or 'a failed backup'),
                              who=by)
            return {'message': 'taken off the list', 'runs': rb_history(h.store)[:40]}
        if act == 'restore':
            return _rb_restore_job(h, b, by)
    except (RbError, ValueError) as e:
        raise ApiError(400, str(e))
    except subprocess.SubprocessError as e:
        raise ApiError(504, 'it took too long: %s' % str(e)[:200])
    raise ApiError(400, 'no such thing to do')


def _rb_restore_job(h, b, by):
    """A backup put back - one at a destination, or one sent from the page -
    as a job the page follows (Settings → The database shows it too)."""
    password = str(b.get('password') or '') or rb_password()
    src = None
    if b.get('upload'):
        up = str(b.get('upload'))
        if not re.match(r'^[0-9a-f]{16}\Z', up):
            raise ValueError('which file?')
        src = RB_UPLOADS / up
        if not src.is_file():
            raise ValueError('the file sent is not here any more: send it again')
    else:
        t = rb_target(h.store, b.get('id'))
        name = str(b.get('name') or '')
        if not t or not RB_NAME_RE.match(name):
            raise ValueError('which backup?')
    store, daemon = h.store, h.d

    def work(progress):
        tmp = None
        try:
            path = src
            if path is None:
                progress(1, 4, 'fetched from %s' % t['name'])
                tmp = Path(tempfile.mkdtemp(prefix='acme-fetch-', dir=str(STATE_DIR)))
                os.chmod(str(tmp), 0o700)
                path = tmp / name
                rb_fetch(store, t['id'], name, str(path))
            progress(2, 4, 'opened and checked')
            got = rb_restore(store, str(path), password, by)
            progress(4, 4, 'put back')
            try:
                daemon.reload_all('a backup was put back')
            except Exception:                           # noqa: BLE001
                pass
            return got
        finally:
            if tmp:
                shutil.rmtree(str(tmp), ignore_errors=True)
            if src is not None:
                try:
                    src.unlink()
                except OSError:
                    pass
    db_job('putting a backup back', work)
    return {'message': 'the backup is being put back', 'job': job_read()}


@route('POST', '/api/rbackup/upload')
def _rbackup_upload(h):
    """A backup file sent from the page, kept for an hour to be put back."""
    h.me('fulladmin')
    RB_UPLOADS.mkdir(mode=0o700, exist_ok=True)
    now = time.time()
    for p in RB_UPLOADS.iterdir():
        try:
            if now - p.stat().st_mtime > 3600:
                p.unlink()
        except OSError:
            pass
    up = secrets.token_hex(8)
    dst = RB_UPLOADS / up
    try:
        # Inside the try (1.0.205): one that did not arrive whole, or too big,
        # stayed behind - up to 4 GB until the next upload an hour later.
        h.body_to_file(dst, 4 * 1024 ** 3)        # as nginx takes (1.0.139)
        with open(str(dst), 'rb') as f:
            head = f.read(8)
        if not (head.startswith(b'Salted__') or head.startswith(b'\x1f\x8b')):
            raise ApiError(400, 'that is not a backup of acme')
        work = tempfile.mkdtemp(prefix='acme-peek-', dir=str(STATE_DIR))
        try:
            if head.startswith(b'Salted__') and not rb_password():
                return {'upload': up, 'locked': True}
            try:
                _top, m = rb_open(str(dst), rb_password(), work)
            except RbError as e:
                return {'upload': up, 'locked': head.startswith(b'Salted__'), 'said': str(e)}
            return {'upload': up, 'locked': head.startswith(b'Salted__'), 'manifest': m}
        finally:
            shutil.rmtree(work, ignore_errors=True)
    except BaseException:
        try:
            dst.unlink()
        except OSError:
            pass
        raise


@route('GET', '/api/rbackup/download')
def _rbackup_download(h):
    """A backup made now for the machine somebody is sitting at - or one
    fetched from a destination."""
    s = h.me('fulladmin')
    tid, name = h.arg('id'), h.arg('name')
    work = Path(tempfile.mkdtemp(prefix='acme-dl-', dir=str(STATE_DIR)))
    os.chmod(str(work), 0o700)
    try:
        if tid and name:
            rb_fetch(h.store, tid, name, str(work / name))
            h.store.add_event('backups', '%s downloaded the backup %s' % (s['name'], name),
                              'warn', who=s['name'])
            h.send_file(work / name, name)
            return None
        if not rb_password():
            # Locked always (1.0.136): unlocked it holds every token's key.
            raise ApiError(403, 'without a password of the backups the file would hold every '
                                'token\'s key unlocked: set the password first')
        path, m, _md = rb_build(h.store, str(work))
        if not m.get('encrypted'):
            # The password asked again as it was locked (1.0.205): taken away during
            # a long dump, the file came out unlocked - it is not handed out.
            raise ApiError(409, 'the backup came out unlocked (its password was taken away '
                                'meanwhile) - it is not handed out; set the password and ask again')
        h.store.add_event('backups', '%s downloaded a backup made for it (%s, %s)' % (
            s['name'], m['file'], 'locked' if m['encrypted'] else 'NOT locked'),
            'info' if m['encrypted'] else 'warn', who=s['name'])
        h.send_file(Path(path), m['file'])
        return None
    except (RbError, ValueError) as e:
        raise ApiError(400, str(e))
    finally:
        shutil.rmtree(str(work), ignore_errors=True)
