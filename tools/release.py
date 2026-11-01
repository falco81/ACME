#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""release.py - a release of acme, built from this source tree.

    python3 tools/release.py                 build release/acme-X.Y.Z.tar.gz
    python3 tools/release.py --version       say which version would be built
    python3 tools/release.py --bump patch    raise the version (patch|minor|major); with
                                             a key it then builds, without one it stops
    python3 tools/release.py --make-key      a new release keypair (see below)
    python3 tools/release.py --index-only    write release/index.json and LATEST again

What it makes, in release/ and nowhere else:

  acme-X.Y.Z.tar.gz   one folder, acme-X.Y.Z/, holding the source tree (no .git,
                      no release/, no caches) and
                        MANIFEST      "SHA256  path" for every other file in it
                        MANIFEST.sig  the Ed25519 signature of MANIFEST (64 bytes,
                                      raw), by the release key
  index.json          every package here, newest first:
                        [{"name", "version", "size", "sha256", "date",
                          "download_url"}, ...]
                      - the list the engine's "new versions from the web" reads
                      (acmelib/engine/210_new_versions_from_the.py)
  LATEST              the newest version, and its name, sha256, size and date

Only the last ten versions are kept: an older package is deleted from
release/ (git still has it).

The version is the one in acmelib/__init__.py; nothing changes it unless
--bump is given (which rewrites that one line, and nothing else outside
release/). CHANGELOG.md must have a "## X.Y.Z" section for it.

The signature is checked the way a server checks it before it is built
twice: once with `openssl pkeyutl -verify` and once by
deploy/acme_upgrade.py --inspect itself, against deploy/release-keys/*.pub.

The release key: the private half comes from $ACME_RELEASE_KEY or --key FILE
and is never in the repository; the public half is
deploy/release-keys/acme-release-N.pub, put into every server by install.sh.
--make-key [--key FILE] [--name acme-release-N] makes a new pair.
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RELEASE_DIR = os.path.join(ROOT, 'release')
KEYS_DIR = os.path.join(ROOT, 'deploy', 'release-keys')
VERSION_FILE = os.path.join(ROOT, 'acmelib', '__init__.py')
KEEP = 10
DOWNLOAD_BASE = os.environ.get(
    'ACME_RELEASE_BASE', 'https://raw.githubusercontent.com/falco81/ACME/main/release/')

# Not in a package, wherever they are in the tree.
SKIP_DIRS = {'__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.tox', '.nox',
             'node_modules', '.idea', '.vscode'}
# Not in a package, at the top of the tree.
SKIP_TOP = {'.git', '.github', '.claude', 'release', 'build', 'dist', '.venv', 'venv',
            '.gitignore', '.gitattributes', '.editorconfig', 'MANIFEST', 'MANIFEST.sig'}
SKIP_SUFFIX = ('.pyc', '.pyo', '.swp', '.swo', '~', '.orig', '.rej', '.key')
SKIP_NAMES = {'.DS_Store', 'Thumbs.db'}
NAME_RE = re.compile(r'^acme-(\d+)\.(\d+)\.(\d+)\.tar\.gz\Z')
VERSION_RE = re.compile(r"^__version__ = '(\d+)\.(\d+)\.(\d+)'", re.M)


def say(text):
    print(text, flush=True)


def die(text):
    sys.stderr.write('release.py: %s\n' % text)
    sys.exit(1)


def vtuple(v):
    return tuple(int(x) for x in str(v).split('.'))


def read_version():
    with open(VERSION_FILE, encoding='utf-8') as f:
        m = VERSION_RE.search(f.read())
    if not m:
        die("%s has no line  __version__ = 'X.Y.Z'" % VERSION_FILE)
    return '.'.join(m.groups())


def bump(part):
    with open(VERSION_FILE, encoding='utf-8') as f:
        text = f.read()
    m = VERSION_RE.search(text)
    if not m:
        die("%s has no line  __version__ = 'X.Y.Z'" % VERSION_FILE)
    a, b, c = (int(x) for x in m.groups())
    a, b, c = {'major': (a + 1, 0, 0), 'minor': (a, b + 1, 0), 'patch': (a, b, c + 1)}[part]
    new = '%d.%d.%d' % (a, b, c)
    text = text[:m.start()] + "__version__ = '%s'" % new + text[m.end():]
    with open(VERSION_FILE, 'w', encoding='utf-8') as f:
        f.write(text)
    page_version(new)
    say('acmelib/__init__.py: %s -> %s (add its section to CHANGELOG.md)' % (
        '.'.join(m.groups()), new))
    return new


def openssl(*args, data=None):
    try:
        r = subprocess.run(['openssl'] + list(args), input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=60)
    except OSError as e:
        die('openssl did not run: %s' % e)
    return r


def key_path(given):
    path = given or os.environ.get('ACME_RELEASE_KEY') or ''
    if not path:
        die('which release key? --key FILE or ACME_RELEASE_KEY=FILE (the private half; '
            '--make-key makes a pair)')
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        die('the release key %s is not there' % path)
    inside = os.path.commonpath([ROOT, path]) == ROOT
    if inside:
        die('the private key %s is inside the repository - keep it outside' % path)
    st = os.stat(path)
    if st.st_mode & 0o077:
        say('note: %s can be read by others than you (chmod 600 it)' % path)
    return path


def public_of(private):
    r = openssl('pkey', '-in', private, '-pubout')
    if r.returncode != 0 or b'BEGIN PUBLIC KEY' not in r.stdout:
        die('%s is not a private key openssl reads: %s' % (
            private, r.stderr.decode('utf-8', 'replace').strip()[-300:]))
    text = openssl('pkey', '-in', private, '-noout', '-text').stdout.decode('utf-8', 'replace')
    if 'ED25519' not in text.upper():
        die('%s is not an Ed25519 key - the servers check Ed25519 signatures only' % private)
    return r.stdout


def trusted_key_for(private):
    """The deploy/release-keys/*.pub the private key belongs to."""
    pub = public_of(private).strip()
    for name in sorted(os.listdir(KEYS_DIR)) if os.path.isdir(KEYS_DIR) else []:
        if name.endswith('.pub'):
            with open(os.path.join(KEYS_DIR, name), 'rb') as f:
                if f.read().strip() == pub:
                    return name
    die('the public half of %s is not in deploy/release-keys/ - no server would trust what '
        'it signs (put it there with --make-key, or use the key that belongs to one there)'
        % private)


def make_key(given, name):
    path = os.path.abspath(os.path.expanduser(
        given or os.environ.get('ACME_RELEASE_KEY') or '~/.acme/%s.key' % name))
    if os.path.commonpath([ROOT, path]) == ROOT:
        die('the private key must be kept outside the repository, not at %s' % path)
    if not re.match(r'^[A-Za-z0-9_.-]+\Z', name):
        die('--name: letters, digits, . _ - only')
    pub = os.path.join(KEYS_DIR, name + '.pub')
    for one in (path, pub):
        if os.path.exists(one):
            die('%s is there already - choose another --name / --key' % one)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    old = os.umask(0o077)
    try:
        r = openssl('genpkey', '-algorithm', 'ed25519', '-out', path)
    finally:
        os.umask(old)
    if r.returncode != 0:
        die('openssl genpkey: %s' % r.stderr.decode('utf-8', 'replace'))
    os.chmod(path, 0o600)
    os.makedirs(KEYS_DIR, exist_ok=True)
    with open(pub, 'wb') as f:
        f.write(public_of(path))
    say('private key:  %s   (keep it safe, never commit it)' % path)
    say('public key:   %s   (commit it: install.sh makes every server trust it)'
        % os.path.relpath(pub, ROOT))
    say('sign with:    ACME_RELEASE_KEY=%s python3 tools/release.py' % path)


# ---- the tree --------------------------------------------------------------------
def tree_files():
    """Every file of the package, as paths relative to the tree, sorted."""
    out = []
    for top, dirs, files in os.walk(ROOT):
        rel_top = os.path.relpath(top, ROOT)
        rel_top = '' if rel_top == '.' else rel_top.replace(os.sep, '/')
        keep = []
        for d in sorted(dirs):
            if d in SKIP_DIRS or (not rel_top and d in SKIP_TOP):
                continue
            full = os.path.join(top, d)
            if os.path.islink(full):
                die('%s is a link: a package holds plain files only' % os.path.join(rel_top, d))
            keep.append(d)
        dirs[:] = keep
        for name in sorted(files):
            if not rel_top and name in SKIP_TOP:
                continue
            if name in SKIP_NAMES or name.endswith(SKIP_SUFFIX):
                continue
            rel = (rel_top + '/' + name) if rel_top else name
            full = os.path.join(top, name)
            if os.path.islink(full) or not os.path.isfile(full):
                die('%s is not a plain file: a package holds plain files only' % rel)
            if '\\' in rel or rel.startswith('/') or '..' in rel.split('/'):
                die('%s: a name a package cannot hold' % rel)
            out.append(rel)
    return sorted(out)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for lump in iter(lambda: f.read(1 << 20), b''):
            h.update(lump)
    return h.hexdigest()


def manifest_of(files):
    lines = ['%s  %s' % (sha256_file(os.path.join(ROOT, rel)), rel) for rel in files]
    return ('\n'.join(lines) + '\n').encode('utf-8')


def checks_before(version, files):
    for need in ('acme.py', 'install.sh', 'acmelib/__init__.py', 'deploy/acme_upgrade.py'):
        if need not in files:
            die('the tree has no %s' % need)
    if not [f for f in files if f.startswith('deploy/release-keys/') and f.endswith('.pub')]:
        die('deploy/release-keys/ has no .pub: a server installed from it would trust no '
            'later release')
    try:
        with open(os.path.join(ROOT, 'CHANGELOG.md'), encoding='utf-8') as f:
            log = f.read()
    except OSError:
        log = ''
    return bool(re.search(r'^## %s\b' % re.escape(version), log, re.M))


PAGE_FILE = os.path.join(ROOT, 'web', 'acme-page.php')
PAGE_RE = re.compile(r"^const ACME_VERSION = '([^']*)';", re.M)


def page_version(new=None):
    """The version the pages say (and key their assets' cache by), read - or
    written as `new`. It was otp's 1.0.209 for every acme release: browsers kept
    the old core.js and admin.js after every upgrade."""
    with open(PAGE_FILE, encoding='utf-8') as f:
        text = f.read()
    m = PAGE_RE.search(text)
    if not m:
        die("%s has no line  const ACME_VERSION = 'X.Y.Z';" % PAGE_FILE)
    if new is not None and m.group(1) != new:
        text = text[:m.start()] + "const ACME_VERSION = '%s';" % new + text[m.end():]
        with open(PAGE_FILE, 'w', encoding='utf-8') as f:
            f.write(text)
        return new
    return m.group(1)


def build(version, key, force=False, epoch=None):
    if page_version() != version:
        return None, ('web/acme-page.php says ACME_VERSION %s, acmelib/__init__.py %s - '
                      'make them the same (--bump writes both)' % (page_version(), version))
    files = tree_files()
    if not checks_before(version, files):
        return None, 'CHANGELOG.md has no "## %s" section - write what changed first' % version
    os.makedirs(RELEASE_DIR, exist_ok=True)
    name = 'acme-%s.tar.gz' % version
    dest = os.path.join(RELEASE_DIR, name)
    if os.path.exists(dest) and not force:
        return None, ('%s is there already - a version released is never built again '
                      '(--bump patch for the next one, or --force to replace it)' % name)
    top = 'acme-%s' % version
    if epoch is None:
        epoch = int(os.environ.get('SOURCE_DATE_EPOCH') or 0) or int(datetime.datetime.now(
            datetime.timezone.utc).timestamp())
    manifest = manifest_of(files)
    work = tempfile.mkdtemp(prefix='acme-release-')
    try:
        man = os.path.join(work, 'MANIFEST')
        sig = os.path.join(work, 'MANIFEST.sig')
        with open(man, 'wb') as f:
            f.write(manifest)
        r = openssl('pkeyutl', '-sign', '-inkey', key, '-rawin', '-in', man, '-out', sig)
        if r.returncode != 0:
            die('signing failed: %s' % r.stderr.decode('utf-8', 'replace').strip())
        signer = trusted_key_for(key)
        r = openssl('pkeyutl', '-verify', '-pubin', '-inkey', os.path.join(KEYS_DIR, signer),
                    '-rawin', '-in', man, '-sigfile', sig)
        if r.returncode != 0:
            die('the signature just made does not verify with %s' % signer)
        with open(sig, 'rb') as f:
            signature = f.read()
        # Folders first (only those that hold a file - the servers refuse an
        # empty one), then every file, the same owner, time and modes always.
        dirs = {top}
        for rel in files + ['MANIFEST']:
            bits = rel.split('/')[:-1]
            for k in range(1, len(bits) + 1):
                dirs.add(top + '/' + '/'.join(bits[:k]))

        def info(arcname, size, mode, kind=tarfile.REGTYPE):
            ti = tarfile.TarInfo(arcname)
            ti.size, ti.mode, ti.type, ti.mtime = size, mode, kind, epoch
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = 'root'
            return ti
        part = dest + '.part'
        with open(part, 'wb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch,
                               compresslevel=9) as gz:
                with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                    for d in sorted(dirs):
                        tar.addfile(info(d, 0, 0o755, tarfile.DIRTYPE))
                    for rel, blob in (('MANIFEST', manifest), ('MANIFEST.sig', signature)):
                        tar.addfile(info(top + '/' + rel, len(blob), 0o644), io.BytesIO(blob))
                    for rel in files:
                        full = os.path.join(ROOT, rel)
                        mode = 0o755 if os.stat(full).st_mode & 0o111 else 0o644
                        with open(full, 'rb') as src:
                            tar.addfile(info(top + '/' + rel, os.path.getsize(full), mode), src)
        os.replace(part, dest)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {'name': name, 'files': len(files), 'signed_by': signer[:-4], 'path': dest,
            'epoch': epoch}, None


def verify_like_a_server(path):
    """deploy/acme_upgrade.py --inspect on the package, trusting only
    deploy/release-keys/ - exactly what a server does with it."""
    work = tempfile.mkdtemp(prefix='acme-release-check-')
    try:
        env = dict(os.environ, ACME_RELEASE_KEYS=KEYS_DIR, ACME_LIB=os.path.join(work, 'lib'),
                   ACME_STATE=os.path.join(work, 'state'))
        r = subprocess.run([sys.executable, '-I', os.path.join(ROOT, 'deploy', 'acme_upgrade.py'),
                            '--inspect', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=env, timeout=300)
        try:
            got = json.loads(r.stdout.decode('utf-8', 'replace') or '{}')
        except ValueError:
            got = {'ok': False, 'said': (r.stdout + r.stderr).decode('utf-8', 'replace')[-500:]}
        return got
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---- release/: the last ten, the index ----------------------------------------------
def packages_here(folder=None):
    folder = folder or RELEASE_DIR
    out = []
    for name in os.listdir(folder) if os.path.isdir(folder) else []:
        m = NAME_RE.match(name)
        if m and os.path.isfile(os.path.join(folder, name)):
            out.append(('%s.%s.%s' % m.groups(), name))
    return sorted(out, key=lambda x: vtuple(x[0]), reverse=True)


def prune(folder=None, keep=KEEP):
    """Every package but the newest `keep` deleted. The names deleted."""
    folder = folder or RELEASE_DIR
    gone = []
    for _v, name in packages_here(folder)[keep:]:
        os.unlink(os.path.join(folder, name))
        gone.append(name)
    return gone


def write_index(folder=None, base=None, built=None):
    """index.json and LATEST for the packages in `folder`. A package's date
    is kept from the index before (it is when it was released), else the
    time inside it."""
    folder = folder or RELEASE_DIR
    base = base or DOWNLOAD_BASE
    if not base.endswith('/'):
        base += '/'
    before = {}
    try:
        with open(os.path.join(folder, 'index.json'), encoding='utf-8') as f:
            for it in json.load(f):
                if isinstance(it, dict) and it.get('name'):
                    before[it['name']] = it
    except (OSError, ValueError, TypeError):
        pass
    rows = []
    for version, name in packages_here(folder):
        path = os.path.join(folder, name)
        sha = sha256_file(path)
        date = None
        was = before.get(name) or {}
        if was.get('sha256') == sha and was.get('date'):
            date = was['date']
        if not date and built and built.get('name') == name:
            date = _iso(built['epoch'])
        if not date:
            date = _iso(_tar_time(path) or os.path.getmtime(path))
        rows.append({'name': name, 'version': version, 'size': os.path.getsize(path),
                     'sha256': sha, 'date': date, 'download_url': base + name})
    _write(os.path.join(folder, 'index.json'), json.dumps(rows, indent=2) + '\n')
    latest = os.path.join(folder, 'LATEST')
    if rows:
        top = rows[0]
        _write(latest, '%s\n%s\nsha256 %s\nsize %d\ndate %s\nurl %s\n' % (
            top['version'], top['name'], top['sha256'], top['size'], top['date'],
            top['download_url']))
    elif os.path.exists(latest):
        os.unlink(latest)
    return rows


def _iso(t):
    return datetime.datetime.fromtimestamp(int(t), datetime.timezone.utc).strftime(
        '%Y-%m-%dT%H:%M:%SZ')


def _tar_time(path):
    try:
        with tarfile.open(path, 'r:gz') as tar:
            one = tar.next()
            return one.mtime if one else None
    except (tarfile.TarError, OSError, EOFError):
        return None


def _write(path, text):
    tmp = path + '.part'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, path)


def main(argv=None):
    p = argparse.ArgumentParser(description='Build a signed release of acme into release/.')
    p.add_argument('--version', action='store_true',
                   help='say the version acmelib/__init__.py has, and stop')
    p.add_argument('--bump', choices=('patch', 'minor', 'major'),
                   help='raise the version in acmelib/__init__.py first')
    p.add_argument('--key', help='the private release key (default: $ACME_RELEASE_KEY)')
    p.add_argument('--make-key', action='store_true',
                   help='make a new Ed25519 keypair: the private half at --key (or '
                        '$ACME_RELEASE_KEY, or ~/.acme/NAME.key), the public half in '
                        'deploy/release-keys/NAME.pub')
    p.add_argument('--name', default='acme-release-1',
                   help='the name of a key made with --make-key (default acme-release-1)')
    p.add_argument('--keep', type=int, default=KEEP, help='versions kept in release/ (10)')
    p.add_argument('--base-url', default=DOWNLOAD_BASE,
                   help='where the packages are downloaded from (index.json download_url); '
                        'default %s' % DOWNLOAD_BASE)
    p.add_argument('--index-only', action='store_true',
                   help='build nothing: prune release/ and write index.json and LATEST again')
    p.add_argument('--force', action='store_true',
                   help='build a version that is in release/ already again')
    p.add_argument('--no-verify', action='store_true',
                   help='skip checking the package with deploy/acme_upgrade.py --inspect')
    a = p.parse_args(argv)

    if a.make_key:
        make_key(a.key, a.name)
        return 0
    if a.version:
        print(read_version())
        return 0
    if a.keep < 1:
        die('--keep takes 1 or more')
    if a.index_only:
        gone = prune(keep=a.keep)
        rows = write_index(base=a.base_url)
        for g in gone:
            say('deleted %s (only the last %d are kept)' % (g, a.keep))
        say('release/index.json: %d versions%s' % (len(rows), (', newest %s' % rows[0]['version'])
                                                     if rows else ''))
        return 0
    if a.bump and not (a.key or os.environ.get('ACME_RELEASE_KEY')):
        # The first step of a release alone: the version raised, nothing built.
        new = bump(a.bump)
        say('next: its "## %s" section in CHANGELOG.md, then build it with the key' % new)
        return 0
    key = key_path(a.key)
    trusted_key_for(key)
    version = bump(a.bump) if a.bump else read_version()
    newest = packages_here()
    if newest and vtuple(version) < vtuple(newest[0][0]):
        die('%s is older than %s, which is in release/ already' % (version, newest[0][0]))
    built, why = build(version, key, force=a.force)
    if not built:
        die(why)
    say('built   release/%s - %d files, signed by %s' % (built['name'], built['files'],
                                                         built['signed_by']))
    if not a.no_verify:
        got = verify_like_a_server(built['path'])
        if not got.get('ok') or got.get('version') != version:
            os.unlink(built['path'])
            die('the package does not pass the servers\' own check, so it was deleted: %s'
                % (got.get('said') or got))
        say('checked as a server checks it: acme %s, %d files, signed by %s' % (
            got['version'], got['files'], got['signed_by']))
    gone = prune(keep=a.keep)
    for g in gone:
        say('deleted release/%s (only the last %d are kept)' % (g, a.keep))
    rows = write_index(base=a.base_url, built=built)
    say('release/index.json and release/LATEST: %d versions, newest %s' % (len(rows),
                                                                         rows[0]['version']))
    say('next: git add -A release/ && git commit (with the source), push to main')
    return 0


if __name__ == '__main__':
    sys.exit(main())
