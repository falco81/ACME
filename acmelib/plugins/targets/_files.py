# -*- coding: utf-8 -*-
"""
Files on a machine over SSH, for the targets that write a few files and then
tell a program to read them (not a module: the registry skips "_" files).

    hashes(t, s, paths)              {path: sha256} of the files there
    all_same(t, s, files)            every file there holds exactly this already
    write_files(t, s, files, tmp_dir, options)
                                     each uploaded, then put in place by a rename; with the
                                     deployment's options (1.0.77): a file that holds the same
                                     already left alone, the one replaced kept as they say
    put_back(t, s, files, existed)   the previous files back (after a failure)
    drop_previous(t, s, files, options)
                                     after success: the copies only for putting back removed,
                                     the older dated copies beyond "keep" deleted
    ls(t, s, folder)                 the names in a folder

The deployment's choices of the files (1.0.77), the same for every target that writes them
(ssh, local, windows_ssh, caddy, esxi, haproxy, strongswan, traefik, zimbra):

    file_fields(fmt)                 the fields: Leave a file alone when it is the same (on),
                                     Keep a copy of a file replaced (on), Name of the copy
                                     (a choice, `fmt` the default), Copies kept
    skip_same(options)               on unless switched off
    backup_mode(options, fmt)        'none', or the name of the copy: 'dated' | 'daily' | 'bak'
                                     | 'folder' (the old on/off switch and choice read too)
    backup_path(path, mode, when)    where the copy of this file goes
    prune_posix(path, mode, keep)    the shell that keeps only the newest dated copies

`files` is [{'path', 'data' (bytes), 'mode' (int), 'owner' (or None)}];
`t` a target with SshMixin (t.sh: through sudo when it says so). write_files marks each
file: '_same' (left alone), '_was' (True / False: was there before), '_bak' (its copy).
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time

from acmelib.plugins.base import field
from acmelib.plugins.targets._common import PluginError, as_bool, as_int, quote, text

PREV = '.acme-prev'
FOLDER = '.acme-backup'
# short, to be read whole in the list (1.0.78: "name.20261111-153000.bak - beside it," was all
# of it there); what each means is in the field's help and docs/targets.md
BACKUP_FORMATS = [
    ['dated', 'name.20261111-153000.bak'],
    ['daily', 'name.2026-11-11.bak (one a day)'],
    ['folder', '.acme-backup/name.….bak'],
    ['bak', 'name.bak (the last one)'],
]
FORMAT_KEYS = [f[0] for f in BACKUP_FORMATS]


def same_field():
    return field('skip_same', 'Leave a file alone when it is the same (SHA-256)', 'bool',
                 default=True,
                 help='each file is compared with the one there by its SHA-256 fingerprint: '
                      'the same one is not replaced (nor copied aside) and the deployment is '
                      'still fine - the job says why. Off: every file is written each time')


def backup_fields(fmt='dated'):
    return [
        field('backup', 'Keep a copy of a file replaced', 'bool', default=True,
              help='the file there kept before the new one replaces it. Off: just '
                   'overwritten. Either way a failing test or reload puts the previous files '
                   'back'),
        field('backup_format', 'Name of the copy', 'select', default=fmt,
              options=BACKUP_FORMATS, show_if={'backup': [True, 1, '1', 'true', 'on']},
              help='beside the file: its name, the date and time, .bak (each time), its name and '
                   'the date (one a day) or its name.bak (the last one only); or in the folder '
                   '.acme-backup beside it - for a folder a program reads whole (HAProxy\'s crt '
                   'folder)'),
        field('backup_keep', 'Copies kept', 'number', default=5, min=0, advanced=True,
              help='of each file, the newest so many dated copies; the older ones are '
                   'deleted (0: all kept)'),
    ]


def file_fields(fmt='dated', show_if=None):
    """`show_if`: when the target writes files only in one of its ways (Caddy: files)."""
    out = [same_field()] + backup_fields(fmt)
    if show_if:
        out = [dict(f, show_if=dict(f.get('show_if') or {}, **show_if)) for f in out]
    return out


def skip_same(options):
    return as_bool((options or {}).get('skip_same'), True)


def backup_mode(options, fmt='dated'):
    """'none', or the copy's name. `backup` is the on/off switch (as before 1.0.77); a value
    of the choice in it (a deployment saved while 1.0.77 was made) is read as on + that."""
    o = options or {}
    v = o.get('backup')
    f = str(o.get('backup_format') or '').strip().lower()
    if isinstance(v, str) and v.strip().lower() in FORMAT_KEYS + ['none']:
        if v.strip().lower() == 'none':
            return 'none'
        f = f or v.strip().lower()
        v = True
    if not as_bool(v, True):
        return 'none'
    return f if f in FORMAT_KEYS else fmt


def backup_keep(options):
    return max(0, as_int((options or {}).get('backup_keep'), 5))


def _split(path):
    i = max(path.rfind('/'), path.rfind('\\'))
    return (path[:i], path[i + 1:]) if i >= 0 else ('', path)


def backup_path(path, mode, when=None):
    """Where the copy of the file at `path` goes: beside it with the time, the day, .bak; in
    the folder .acme-backup beside it; or (no copy wanted) <path>.acme-prev, only for putting
    it back and removed after."""
    when = time.localtime(when if when is not None else time.time())
    if mode == 'dated':
        return path + '.' + time.strftime('%Y%m%d-%H%M%S', when) + '.bak'
    if mode == 'daily':
        return path + '.' + time.strftime('%Y-%m-%d', when) + '.bak'
    if mode == 'bak':
        return path + '.bak'
    if mode == 'folder':
        d, n = _split(path)
        sep = '\\' if '\\' in path and '/' not in path else '/'
        return '%s%s%s%s%s.%s.bak' % (d, sep, FOLDER, sep, n, time.strftime('%Y%m%d-%H%M%S', when))
    return path + PREV


def backup_suffix(mode, when=None):
    """What follows a file's path in its copy (beside it): kept for those that ask so."""
    return backup_path('', mode, when) if mode != 'folder' else backup_path('', 'dated', when)


DATED_GLOB = '[0-9][0-9][0-9][0-9][0-9-]*.bak'
DATED_RE = r'\.\d{4}[\d-]*\.bak'


def dated_pattern(path, mode):
    """(folder, name prefix) of the dated copies of this file, or None when they are not dated."""
    if mode not in ('dated', 'daily', 'folder'):
        return None
    d, n = _split(path)
    if mode == 'folder':
        sep = '\\' if '\\' in path and '/' not in path else '/'
        d = '%s%s%s' % (d, sep, FOLDER)
    return d, n + '.'


def prune_posix(path, mode, keep=None):
    """The shell that deletes the older dated copies of this file, the newest `keep` left."""
    if keep is None:                    # prune_posix(path, keep): beside it, dated
        mode, keep = 'dated', mode
    pat = dated_pattern(path, mode)
    if not keep or not pat:
        return ''
    d, n = pat
    return ('ls -1t -- %s/%s%s 2>/dev/null | tail -n +%d | while IFS= read -r f; do rm -f -- "$f"; '
            'done' % (quote(d or '.'), quote(n), DATED_GLOB, int(keep) + 1))


def said_sha(path, there, new):
    """One file compared, in words for the job (1.0.78)."""
    if there is None:
        return '%s: not there yet - written' % path
    if there == new:
        return '%s: the same SHA-256 (%s…) - left as it is' % (path, new[:16])
    return '%s: SHA-256 there %s…, new %s… - replaced' % (path, there[:16], new[:16])


def describe_same(t, paths):
    """The step of the files left as they were."""
    if paths:
        t.ctx.step('left as they are, the same SHA-256 there already: %s' % ', '.join(paths), 'ok')


def hashes(t, s, paths):
    if not paths:
        return {}
    rc, out, err = t.sh(s, 'sha256sum %s 2>/dev/null; true' % ' '.join(quote(p) for p in paths),
                        check=False)
    have = {}
    for line in text(out).splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            have[parts[1].strip().lstrip('*')] = parts[0].lower()
    return have


def all_same_said(t, s, files, where=None):
    """Every file there holds exactly this already - each said in the job (1.0.78), and when so
    that nothing is replaced and nothing run."""
    have = hashes(t, s, [f['path'] for f in files])
    ok = bool(files)
    for f in files:
        new = hashlib.sha256(f['data']).hexdigest()
        t.ctx.step(said_sha(f['path'], have.get(f['path']), new),
                   'ok' if have.get(f['path']) == new else 'info')
        f['_said'] = True
        ok = ok and have.get(f['path']) == new
    if ok:
        t.ctx.step('nothing replaced: every file holds this certificate already (the same '
                   'SHA-256) - nothing run', 'ok')
    return ok


def all_same(t, s, files):
    have = hashes(t, s, [f['path'] for f in files])
    return bool(files) and all(have.get(f['path']) == hashlib.sha256(f['data']).hexdigest()
                               for f in files)


def write_files(t, s, files, tmp_dir='/tmp', options=None, fmt=None):
    """-> [True/False: was there one before, None: left alone - the same], one a file. On a
    failure the previous files are put back and PluginError raised. Without `options` as
    before 1.0.77: every file written, the old one as <path>.acme-prev."""
    mode = backup_mode(options, fmt or 'dated') if options is not None else 'none'
    stamp = time.time()
    for f in files:
        f['_bak'] = backup_path(f['path'], mode, stamp)
        f['_bmode'] = mode
        f['_same'] = False
    if options is not None and skip_same(options):
        # also on "Deploy now" (1.0.78): only the switch off writes every file
        have = hashes(t, s, [f['path'] for f in files])
        for f in files:
            new = hashlib.sha256(f['data']).hexdigest()
            f['_same'] = have.get(f['path']) == new
            if not f.get('_said'):
                t.ctx.step(said_sha(f['path'], have.get(f['path']), new), 'ok' if f['_same'] else 'info')
    todo = [i for i, f in enumerate(files) if not f['_same']]
    existed = [None] * len(files)
    if not todo:
        for f in files:
            f['_was'] = None
        return existed
    token = secrets.token_hex(6)
    tmps = {}
    tmp_dir = (tmp_dir or '/tmp').rstrip('/')
    try:
        for i in todo:
            tmp = '%s/.acme-%s-%d' % (tmp_dir, token, i)
            s.put(files[i]['data'], tmp, 0o600)
            tmps[i] = tmp
        script = ['set -e']
        for i in todo:
            f = files[i]
            p = quote(f['path'])
            new = quote(f['path'] + '.acme-new')
            script += ['mkdir -p "$(dirname %s)"' % p,
                       'if [ -e %s ]; then mkdir -p "$(dirname %s)"; cp -p %s %s; '
                       'echo "EXISTED %d"; fi' % (p, quote(f['_bak']), p, quote(f['_bak']), i),
                       'cp %s %s' % (quote(tmps[i]), new),
                       'chmod %o %s' % (f.get('mode') or 0o600, new)]
            if f.get('owner'):
                script.append('chown %s %s' % (quote(f['owner']), new))
            script.append('mv -f %s %s' % (new, p))
            script.append('echo "PLACED %d"' % i)
        rc, out, err = t.sh(s, '\n'.join(script), check=False)
        placed = [False] * len(files)
        for i in todo:
            existed[i] = False
        for line in text(out).splitlines():
            if line.startswith('EXISTED '):
                existed[int(line.split()[1])] = True
            elif line.startswith('PLACED '):
                placed[int(line.split()[1])] = True
        for f, was in zip(files, existed):
            f['_was'] = was
        if rc != 0:
            # only what was put in place (1.0.48), as targets/ssh.py
            put_back(t, s, files, existed, placed)
            raise PluginError('the files could not be written, the previous ones are back: %s'
                              % (text(err).strip() or text(out).strip())[-300:])
        if mode != 'none' and any(existed):
            t.ctx.step('the files replaced kept as %s' % ', '.join(
                f['_bak'] for f, was in zip(files, existed) if was))
        return existed
    finally:
        if tmps:
            try:
                s.run('rm -f ' + ' '.join(quote(x) for x in tmps.values()), check=False)
            except Exception:                           # noqa: BLE001
                pass


def put_back(t, s, files, existed, placed=None):
    script = []
    for i, (f, was) in enumerate(zip(files, existed)):
        if was is None:                                 # left alone: the same
            continue
        p = quote(f['path'])
        bak = f.get('_bak') or f['path'] + PREV
        if placed is not None and not placed[i]:
            script.append('rm -f %s' % quote(f['path'] + '.acme-new'))
            continue
        if was:
            script.append('cp -p %s %s' % (quote(bak), p))
            if bak.endswith(PREV):
                script.append('rm -f %s' % quote(bak))
        else:
            script.append('rm -f %s' % p)
        script.append('rm -f %s' % quote(f['path'] + '.acme-new'))
    if not script:
        return
    rc, out, err = t.sh(s, '\n'.join(script), check=False)
    t.ctx.step('the previous files are back' if rc == 0 else
               'putting the previous files back failed: %s' % text(err).strip()[-200:],
               'warn' if rc == 0 else 'bad')


def drop_previous(t, s, files, options=None):
    """After a deployment that went through. Without `options`: the .acme-prev copies removed
    (as before). With them: the copies only for putting back removed, of the dated ones the
    older beyond "Copies kept" deleted."""
    if options is None:
        t.sh(s, 'rm -f ' + ' '.join(quote(f['path'] + PREV) for f in files), check=False)
        return
    keep = backup_keep(options)
    script = []
    for f in files:
        if f.get('_was') is not True:
            continue
        mode = f.get('_bmode') or 'none'
        if mode == 'none':
            script.append('rm -f %s' % quote(f.get('_bak') or f['path'] + PREV))
        elif keep:
            line = prune_posix(f['path'], mode, keep)
            if line:
                script.append(line)
    if script:
        t.sh(s, '\n'.join(script), check=False)


def ls(t, s, folder):
    rc, out, err = t.sh(s, 'ls -1 %s 2>/dev/null; true' % quote(folder), check=False)
    return [x.strip() for x in text(out).splitlines() if x.strip()]


def dated_regex(name):
    """A regular expression of the dated copies of the file called `name` (for PowerShell)."""
    return '^' + re.escape(name) + DATED_RE + '$'
