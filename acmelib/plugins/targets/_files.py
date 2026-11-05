# -*- coding: utf-8 -*-
"""
Files on a machine over SSH, for the targets that write a few files and then
tell a program to read them (not a module: the registry skips "_" files).

    hashes(t, s, paths)              {path: sha256} of the files there
    all_same(t, s, files)            every file there holds exactly this already
    write_files(t, s, files)         each uploaded, then put in place by a rename,
                                     the old one copied to <path>.acme-prev
    put_back(t, s, files, existed)   the previous files back (after a failure)
    drop_previous(t, s, files)       the .acme-prev copies removed (after success)
    ls(t, s, folder)                 the names in a folder

`files` is [{'path', 'data' (bytes), 'mode' (int), 'owner' (or None)}];
`t` a target with SshMixin (t.sh: through sudo when it says so).
"""
from __future__ import annotations

import hashlib
import secrets

from acmelib.plugins.targets._common import PluginError, quote, text

PREV = '.acme-prev'


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


def all_same(t, s, files):
    have = hashes(t, s, [f['path'] for f in files])
    return bool(files) and all(have.get(f['path']) == hashlib.sha256(f['data']).hexdigest()
                               for f in files)


def write_files(t, s, files, tmp_dir='/tmp'):
    """-> [True/False: was there one before], one a file. On a failure the
    previous files are put back and PluginError raised."""
    token = secrets.token_hex(6)
    tmps = []
    tmp_dir = (tmp_dir or '/tmp').rstrip('/')
    try:
        for i, f in enumerate(files):
            tmp = '%s/.acme-%s-%d' % (tmp_dir, token, i)
            s.put(f['data'], tmp, 0o600)
            tmps.append(tmp)
        script = ['set -e']
        for i, (f, tmp) in enumerate(zip(files, tmps)):
            p = quote(f['path'])
            new = quote(f['path'] + '.acme-new')
            script += ['mkdir -p "$(dirname %s)"' % p,
                       'if [ -e %s ]; then cp -p %s %s; echo "EXISTED %d"; fi'
                       % (p, p, quote(f['path'] + PREV), i),
                       'cp %s %s' % (quote(tmp), new),
                       'chmod %o %s' % (f.get('mode') or 0o600, new)]
            if f.get('owner'):
                script.append('chown %s %s' % (quote(f['owner']), new))
            script.append('mv -f %s %s' % (new, p))
            script.append('echo "PLACED %d"' % i)
        rc, out, err = t.sh(s, '\n'.join(script), check=False)
        existed = [False] * len(files)
        placed = [False] * len(files)
        for line in text(out).splitlines():
            if line.startswith('EXISTED '):
                existed[int(line.split()[1])] = True
            elif line.startswith('PLACED '):
                placed[int(line.split()[1])] = True
        if rc != 0:
            # only what was put in place (1.0.48), as targets/ssh.py
            put_back(t, s, files, existed, placed)
            raise PluginError('the files could not be written, the previous ones are back: %s'
                              % (text(err).strip() or text(out).strip())[-300:])
        return existed
    finally:
        if tmps:
            try:
                s.run('rm -f ' + ' '.join(quote(x) for x in tmps), check=False)
            except Exception:                           # noqa: BLE001
                pass


def put_back(t, s, files, existed, placed=None):
    script = []
    for i, (f, was) in enumerate(zip(files, existed)):
        p = quote(f['path'])
        if placed is not None and not placed[i]:
            script.append('rm -f %s' % quote(f['path'] + '.acme-new'))
            continue
        script.append(('cp -p %s %s' % (quote(f['path'] + PREV), p)) if was else 'rm -f %s' % p)
        script.append('rm -f %s' % quote(f['path'] + '.acme-new'))
    rc, out, err = t.sh(s, '\n'.join(script), check=False)
    t.ctx.step('the previous files are back' if rc == 0 else
               'putting the previous files back failed: %s' % text(err).strip()[-200:],
               'warn' if rc == 0 else 'bad')


def drop_previous(t, s, files):
    t.sh(s, 'rm -f ' + ' '.join(quote(f['path'] + PREV) for f in files), check=False)


def ls(t, s, folder):
    rc, out, err = t.sh(s, 'ls -1 %s 2>/dev/null; true' % quote(folder), check=False)
    return [x.strip() for x in text(out).splitlines() if x.strip()]
