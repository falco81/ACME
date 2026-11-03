# -*- coding: utf-8 -*-
"""
Modules of your own (1.0.32) - the files in ACME_PLUGINS (/etc/acme/plugins):
sources, validations, targets written for this installation, an override of a
module shipped, more versions of one.

They live on the disk of each node, so acme keeps what they are in the
database too: `custom-modules:<node>` in `meta` holds each file of this node
(its path under the folder, sha256, size and its text). That is in every copy
of the database (the nightly ones, a download, a backup to another machine -
which has the files in `plugins/` as well) and, in a cluster, replicated: each
node sees whether the other has the same files (status()), and
`acme --plugins-sync NODE` (root) writes a node's files from the database into
this node's folder - after a copy was put back on a new machine, or to make the
second node of a cluster the same as the first.

Nothing is ever run from the database by itself: the files are written only by
that command, by root, and loaded as any file put there by hand.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time

from acmelib.certs import store as S

KEY = 'custom-modules:'
MOST = 1 << 20                   # a file bigger than this is listed, its text not kept
FOLDERS = ('issuers', 'challenges', 'targets')


def plugins_dir():
    return os.environ.get('ACME_PLUGINS', '/etc/acme/plugins')


def _node():
    try:
        from acmelib import engine as E
        return E.node_name()
    except Exception:                                   # noqa: BLE001
        return 'this node'


def inventory(folder=None, text=True):
    """{relative path: {sha256, bytes, text?}} of the .py files of the folder."""
    folder = folder or plugins_dir()
    out = {}
    if not folder or not os.path.isdir(folder):
        return out
    for sub in FOLDERS:
        d = os.path.join(folder, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            p = os.path.join(d, fn)
            if not fn.endswith('.py') or not os.path.isfile(p) or os.path.islink(p):
                continue
            try:
                with open(p, 'rb') as f:
                    data = f.read(MOST + 1)
            except OSError:
                continue
            one = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
            if text and len(data) <= MOST:
                one['text'] = base64.b64encode(data).decode('ascii')
            out['%s/%s' % (sub, fn)] = one
    return out


def record(store):
    """This node's files, kept in the database when they changed. Never raises."""
    try:
        files = inventory()
        key = KEY + _node()
        old = S.jload(store.get_meta(key), {}) or {}
        if {k: v.get('sha256') for k, v in (old.get('files') or {}).items()} == \
                {k: v.get('sha256') for k, v in files.items()}:
            return False
        store.set_meta(key, json.dumps({'at': time.time(), 'dir': plugins_dir(),
                                        'node': _node(), 'files': files}))
        return True
    except Exception:                                   # noqa: BLE001
        return False


def kept(store):
    """{node: {at, dir, files}} of every node that said its files."""
    out = {}
    try:
        rows = store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (KEY + '%',))
    except Exception:                                   # noqa: BLE001
        return out
    for r in rows:
        got = S.jload(r['v'], {}) or {}
        if isinstance(got, dict):
            out[r['k'][len(KEY):]] = got
    return out


def status(store):
    """What the page shows: this node's files, and how each other node's differ.
    {'node', 'dir', 'files': [{path, sha256, bytes}], 'others': [{node, at,
    missing_here: [paths], only_here: [paths], different: [paths]}]}"""
    record(store)
    me = _node()
    mine = inventory(text=False)
    out = {'node': me, 'dir': plugins_dir(),
           'files': [{'path': k, 'sha256': v['sha256'], 'bytes': v['bytes']}
                     for k, v in sorted(mine.items())], 'others': []}
    for node, got in sorted(kept(store).items()):
        if node == me:
            continue
        theirs = {k: v.get('sha256') for k, v in (got.get('files') or {}).items()}
        here = {k: v['sha256'] for k, v in mine.items()}
        out['others'].append({
            'node': node, 'at': got.get('at'),
            'missing_here': sorted(k for k in theirs if k not in here),
            'only_here': sorted(k for k in here if k not in theirs),
            'different': sorted(k for k in here if k in theirs and here[k] != theirs[k])})
    return out


def sync(store, node, folder=None, remove=False, say=print):
    """The files `node` keeps in the database written into this node's folder
    (root, `acme --plugins-sync NODE`). `remove`: files here it does not have go.
    -> [(what, path)]."""
    got = kept(store).get(node)
    if not got:
        raise ValueError('the database keeps no modules of a node called %s (it has: %s)'
                         % (node, ', '.join(sorted(kept(store))) or 'none'))
    folder = folder or plugins_dir()
    files = got.get('files') or {}
    done = []
    for rel, one in sorted(files.items()):
        sub, _, fn = rel.partition('/')
        if sub not in FOLDERS or not fn.endswith('.py') or '/' in fn or fn.startswith('.'):
            continue
        if 'text' not in one:
            say('%s: too big to be kept in the database - copy it by hand' % rel)
            continue
        data = base64.b64decode(one['text'])
        if hashlib.sha256(data).hexdigest() != one.get('sha256'):
            raise ValueError('%s: what the database keeps does not match its sha256' % rel)
        dst = os.path.join(folder, sub, fn)
        try:
            with open(dst, 'rb') as f:
                if f.read() == data:
                    continue
        except OSError:
            pass
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        part = dst + '.part'
        with open(part, 'wb') as f:
            f.write(data)
        os.chmod(part, 0o644)
        os.replace(part, dst)
        done.append(('written', rel))
    if remove:
        for rel in inventory(folder, text=False):
            if rel not in files:
                os.remove(os.path.join(folder, rel))
                done.append(('removed', rel))
    return done


# ---------------------------------------------------------------------------
# Uploaded on the page (Modules → Upload): kept in the database, written by each node
# ---------------------------------------------------------------------------
FILE_KEY = 'module-file:'           # meta: module-file:<folder>/<file.py> -> {text, sha256...}
SIG_KEY = 'module-files:sig'        # meta: what the uploaded files are, all of them
FOLDER_OF = {'issuer': 'issuers', 'challenge': 'challenges', 'target': 'targets'}
FAMILY_OF = {v: k for k, v in FOLDER_OF.items()}
NAME_RE = __import__('re').compile(r'^[a-z][a-z0-9_]{0,60}\.py\Z')
MOST_UPLOAD = 512 * 1024
_SEEN = {'sig': None, 'at': 0.0}


def uploaded_dir():
    from acmelib.plugins import base
    return base.UPLOADED_DIR


def uploaded(store, text=False):
    """{folder/file.py: {sha256, bytes, by, at, note, text?}} of the uploaded modules."""
    out = {}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (FILE_KEY + '%',)):
        got = S.jload(r['v'], {}) or {}
        if not isinstance(got, dict):
            continue
        rel = r['k'][len(FILE_KEY):]
        if not text:
            got = {k: v for k, v in got.items() if k != 'text'}
        out[rel] = got
    return out


def _signature(store):
    return store.get_meta(SIG_KEY) or ''


def _sign(store):
    files = uploaded(store)
    sig = hashlib.sha256(json.dumps(sorted((k, v.get('sha256')) for k, v in files.items()))
                         .encode()).hexdigest()
    store.set_meta(SIG_KEY, sig)
    return sig


def materialize(store, force=False):
    """The uploaded modules written into this node's folder for them (and files no longer
    kept taken away) - each node does it itself, so a cluster has the same ones. True
    when something changed (the modules are to be loaded again)."""
    sig = _signature(store)
    d = uploaded_dir()
    if not force and sig == _SEEN['sig'] and os.path.isdir(d):
        return False
    want = uploaded(store, text=True)
    changed = False
    for rel, one in want.items():
        sub, _, fn = rel.partition('/')
        if sub not in FOLDERS or not NAME_RE.match(fn) or 'text' not in one:
            continue
        data = base64.b64decode(one['text'])
        if hashlib.sha256(data).hexdigest() != one.get('sha256'):
            continue
        dst = os.path.join(d, sub, fn)
        try:
            with open(dst, 'rb') as f:
                if f.read() == data:
                    continue
        except OSError:
            pass
        os.makedirs(os.path.dirname(dst), mode=0o750, exist_ok=True)
        part = dst + '.part'
        with open(part, 'wb') as f:
            f.write(data)
        os.chmod(part, 0o640)
        os.replace(part, dst)
        changed = True
    for rel in inventory(d, text=False):
        if rel not in want:
            try:
                os.remove(os.path.join(d, rel))
                changed = True
            except OSError:
                pass
    _SEEN['sig'] = sig
    return changed


def keep_current(store, every=20.0):
    """Called where modules are used (the plugins list, a job): another node's upload
    is written here and loaded, at most every `every` seconds asked."""
    now = time.time()
    if now - _SEEN['at'] < every:
        return False
    _SEEN['at'] = now
    try:
        if materialize(store):
            S.registry(True)
            return True
    except Exception:                                   # noqa: BLE001
        pass
    return False


ANALYSE = r'''
import json, sys, importlib.util
sys.path.insert(0, sys.argv[1])
from acmelib.plugins import base
fam = sys.argv[3]
spec = importlib.util.spec_from_file_location('acme_upload_check', sys.argv[2])
mod = importlib.util.module_from_spec(spec)
sys.modules['acme_upload_check'] = mod
spec.loader.exec_module(mod)
out = []
for obj in vars(mod).values():
    if isinstance(obj, type) and issubclass(obj, base.FAMILIES[fam]) and \
            obj is not base.FAMILIES[fam] and obj.kind and obj.__module__ == mod.__name__:
        out.append({'kind': obj.kind, 'version': str(obj.__dict__.get('module_version',
                    obj.module_version) or ''), 'title': obj.title or obj.kind,
                    'label': obj.version_label or '', 'default': bool(obj.__dict__.get(
                    'default_version')), 'fields': len(obj.fields or [])})
print(json.dumps(out))
'''


def analyse(family, filename, text):
    """What an uploaded file is, before it is kept: compiled and loaded in a process of
    its own (an error stays there). -> {ok, classes: [{kind, version, title, label,
    default, fields, does: 'override' | 'version' | 'new', replaces}], error}"""
    import subprocess
    import sys
    import tempfile
    if family not in FOLDER_OF:
        raise ValueError('a module is a source, a validation or a target')
    if not NAME_RE.match(filename or ''):
        raise ValueError('the file name: lowercase letters, digits and _, ending .py '
                         '(netscaler_v14.py)')
    data = text.encode('utf-8') if isinstance(text, str) else bytes(text or b'')
    if not data.strip():
        raise ValueError('the file is empty')
    if len(data) > MOST_UPLOAD:
        raise ValueError('the file is bigger than %d KB' % (MOST_UPLOAD // 1024))
    try:
        compile(data, filename, 'exec')
    except SyntaxError as e:
        return {'ok': False, 'classes': [], 'error': 'line %s: %s' % (e.lineno, e.msg)}
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with tempfile.TemporaryDirectory(prefix='acme-module-') as tmp:
        p = os.path.join(tmp, filename)
        with open(p, 'wb') as f:
            f.write(data)
        try:
            got = subprocess.run([sys.executable, '-I', '-c', ANALYSE, root, p, family],
                                 capture_output=True, text=True, timeout=30, cwd=tmp)
        except subprocess.TimeoutExpired:
            return {'ok': False, 'classes': [], 'error': 'loading it took more than 30 s'}
    if got.returncode != 0:
        last = [x for x in (got.stderr or '').strip().splitlines() if x.strip()]
        return {'ok': False, 'classes': [], 'error': last[-1] if last else 'it did not load',
                'detail': (got.stderr or '')[-4000:]}
    try:
        classes = json.loads(got.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {'ok': False, 'classes': [], 'error': 'it said nothing acme understands'}
    if not classes:
        return {'ok': False, 'classes': [], 'error': 'it has no %s module (a class with a '
                'kind)' % {'issuer': 'source', 'challenge': 'validation',
                           'target': 'target'}[family]}
    reg = S.registry()
    for c in classes:
        have = reg.versions_of(family, c['kind'])
        old = have.get(c['version'])
        if old is not None:
            c['does'] = 'override'
            c['replaces'] = getattr(old, '_source', 'builtin')
        elif have:
            c['does'] = 'version'
            c['replaces'] = ''
        else:
            c['does'] = 'new'
            c['replaces'] = ''
    return {'ok': True, 'classes': classes, 'error': ''}


def install(store, family, filename, text, by, note=''):
    """An uploaded module kept (after analyse() found it loads) and loaded here."""
    got = analyse(family, filename, text)
    if not got['ok']:
        raise ValueError('the module was not taken: %s' % got['error'])
    data = text.encode('utf-8') if isinstance(text, str) else bytes(text)
    rel = '%s/%s' % (FOLDER_OF[family], filename)
    store.set_meta(FILE_KEY + rel, json.dumps({
        'text': base64.b64encode(data).decode('ascii'),
        'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'by': str(by)[:190],
        'at': time.time(), 'note': str(note or '')[:500], 'family': family,
        'classes': got['classes']}))
    _sign(store)
    materialize(store, force=True)
    S.registry(True)
    return dict(got, path=rel)


def remove(store, rel, by):
    if not store.get_meta(FILE_KEY + rel):
        raise LookupError('there is no uploaded module %s' % rel)
    store.db.run('DELETE FROM meta WHERE k = ?', (FILE_KEY + rel,))
    _sign(store)
    materialize(store, force=True)
    S.registry(True)
    return rel


def source_of(family, kind, version=None):
    """(file name, text) of a module as it is loaded - shipped or your own."""
    cls = S.plugin_class(family, kind, version)
    if cls is None:
        raise LookupError('there is no %s module "%s"' % (family, kind))
    path = getattr(cls, '_module_file', '')
    with open(path, 'rb') as f:
        return os.path.basename(path), f.read().decode('utf-8', 'replace')


# ---------------------------------------------------------------------------
# Marks: tested / works - a full administrator's, and the release's own
# ---------------------------------------------------------------------------
MARK_KEY = 'module-mark:'           # meta: module-mark:<family>/<kind>@<version>
MARK_STATES = ('tested', 'works', 'problem')
VERIFIED_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             'plugins', 'verified.json')


def mark_id(family, kind, version=''):
    return '%s/%s@%s' % (family, kind, version or '')


def _file_sha(family, kind, version):
    cls = S.plugin_class(family, kind, version if version is not None else None)
    path = getattr(cls, '_module_file', '') if cls else ''
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ''


def released():
    """The marks this release ships (acmelib/plugins/verified.json):
    {"target/netscaler@": {"state": "works", "note": "...", "since": "1.0.31"}}."""
    try:
        with open(VERIFIED_FILE, encoding='utf-8') as f:
            got = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for k, v in (got.get('modules') or {}).items() if isinstance(got, dict) else []:
        if isinstance(v, dict) and v.get('state') in MARK_STATES:
            out[k if '@' in k else k + '@'] = v
    return out


def marks(store):
    """{mark id: {state, note, by, at, sha256, changed, release?}}: the marks set here,
    with whether the module's file changed since (its sha256 then and now)."""
    out = {}
    for r in store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (MARK_KEY + '%',)):
        got = S.jload(r['v'], {}) or {}
        if not isinstance(got, dict) or got.get('state') not in MARK_STATES:
            continue
        mid = r['k'][len(MARK_KEY):]
        fam, _, rest = mid.partition('/')
        kind, _, ver = rest.partition('@')
        now = _file_sha(fam, kind, ver)
        got['changed'] = bool(got.get('sha256') and now and now != got['sha256'])
        out[mid] = got
    return out


def set_mark(store, family, kind, version, state, note, by):
    """A full administrator's mark on one version of a module ('' state: taken away)."""
    if S.plugin_class(family, kind) is None:
        raise LookupError('there is no %s module "%s"' % (family, kind))
    have = S.registry().versions_of(family, kind)
    version = str(version or '')
    if have and version not in have:
        raise LookupError('the module %s has no version "%s"' % (kind, version))
    mid = mark_id(family, kind, version)
    if not state:
        store.db.run('DELETE FROM meta WHERE k = ?', (MARK_KEY + mid,))
        return None
    if state not in MARK_STATES:
        raise ValueError('a mark is one of: %s' % ', '.join(MARK_STATES))
    one = {'state': state, 'note': str(note or '')[:500], 'by': str(by)[:190],
           'at': time.time(), 'sha256': _file_sha(family, kind, version)}
    store.set_meta(MARK_KEY + mid, json.dumps(one))
    return one


def export_marks(store, version):
    """The marks set here as verified.json wants them (for the next release)."""
    out = {}
    for mid, m in sorted(marks(store).items()):
        out[mid] = {'state': m['state'], 'note': m.get('note') or '', 'since': version}
    return {'modules': out}
