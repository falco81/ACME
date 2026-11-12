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
import re
import time

from acmelib.certs import store as S

KEY = 'custom-modules:'
MOST = 1 << 20                   # a file bigger than this is listed, its text not kept
FOLDERS = ('issuers', 'challenges', 'targets', 'checks')


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
FOLDER_OF = {'issuer': 'issuers', 'challenge': 'challenges', 'target': 'targets',
             'check': 'checks'}
FAMILY_OF = {v: k for k, v in FOLDER_OF.items()}
NAME_RE = __import__('re').compile(r'^[a-z][a-z0-9_]{0,60}\.py\Z')
MOST_UPLOAD = 512 * 1024
_SEEN = {'sig': None, 'at': 0.0}


def uploaded_dir():
    from acmelib.plugins import base
    return base.UPLOADED_DIR


def _guarded(store, rows):
    return S.E.dbguard_rows(store.db, rows)


def uploaded(store, text=False):
    """{folder/file.py: {sha256, bytes, by, at, note, text?}} of the uploaded modules."""
    out = {}
    # only those acme wrote (1.0.95): with the guard on, one written past acme is not run
    for r in _guarded(store, store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (FILE_KEY + '%',))):
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
    is written here and loaded, at most every `every` seconds asked - and the default
    versions chosen on the page taken (1.0.34)."""
    now = time.time()
    if now - _SEEN['at'] < every:
        return False
    _SEEN['at'] = now
    changed = False
    try:
        if materialize(store):
            S.registry(True)
            changed = True
    except Exception:                                   # noqa: BLE001
        pass
    try:
        changed = apply_defaults(store) or changed
    except Exception:                                   # noqa: BLE001
        pass
    return changed


# ---------------------------------------------------------------------------
# The default version of a module, chosen on the page (1.0.34): kept in the database
# (both nodes, every copy), over default_version in the code
# ---------------------------------------------------------------------------
DEFAULT_KEY = 'module-default:'     # meta: module-default:<family>/<kind> -> {version, by, at}


def defaults(store):
    """{(family, kind): {version, by, at}} chosen on the page."""
    out = {}
    for r in _guarded(store, store.db.rows('SELECT k, v FROM meta WHERE k LIKE ?', (DEFAULT_KEY + '%',))):
        fam, _, kind = r['k'][len(DEFAULT_KEY):].partition('/')
        got = S.jload(r['v'], {}) or {}
        if fam and kind and isinstance(got, dict) and 'version' in got:
            out[(fam, kind)] = got
    return out


def apply_defaults(store):
    """The chosen default versions handed to the registry; True when that changed."""
    S.registry()
    return S.registry().set_picked({k: str(v.get('version') or '') for k, v in defaults(store).items()})


def using_default(store, family, kind):
    """How many sources, validations, targets or tests of a kind name no version (they
    take the default one)."""
    table = S.TABLE_OF.get(family)
    if not table:
        return 0
    n = 0
    for r in store.db.rows('SELECT kind, config FROM %s WHERE kind = ?' % table, (kind,)):
        if S.version_of(r) is None:
            n += 1
    return n


def set_default(store, family, kind, version, by):
    """The default version of a kind chosen (version None: as the code says again)."""
    if family not in FOLDER_OF:
        raise ValueError('family is issuer, challenge, target or check')
    vers = S.registry().versions_of(family, kind)
    if not vers:
        raise LookupError('there is no %s module "%s"' % (family, kind))
    key = DEFAULT_KEY + '%s/%s' % (family, kind)
    if version is None:
        store.db.run('DELETE FROM meta WHERE k = ?', (key,))
    else:
        version = str(version)
        if version not in vers:
            raise ValueError('%s has no version "%s" (it has: %s)' % (
                kind, version, ', '.join(v or 'plain' for v in sorted(vers))))
        store.set_meta(key, json.dumps({'version': version, 'by': str(by)[:190], 'at': time.time()}))
    apply_defaults(store)
    store.add_event('settings', 'module %s/%s: the default version %s by %s' % (
        family, kind, ('is %s' % (version or 'plain')) if version is not None
        else 'is as its code says again', by), who=by)
    return S.registry().get(family, kind).module_version or ''


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
        raise ValueError('a module is a source, a validation, a target or a test')
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
                           'target': 'target', 'check': 'test'}[family]}
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


def class_of(family, kind, version=None, original=False):
    """The class of a version as loaded - or with `original`, the shipped one an
    override of yours replaces (1.0.34: its code can still be had)."""
    cls = S.plugin_class(family, kind, version)
    if cls is None:
        raise LookupError('there is no %s module "%s"' % (family, kind))
    if original:
        cls = getattr(cls, '_replaced', None) or cls
    return cls


def source_of(family, kind, version=None, original=False):
    """(file name, text) of a module as it is loaded - shipped or your own; with
    `original`, the shipped one your override replaces."""
    cls = class_of(family, kind, version, original)
    path = getattr(cls, '_module_file', '')
    with open(path, 'rb') as f:
        return os.path.basename(path), f.read().decode('utf-8', 'replace')


def copy_as(family, kind, from_version=None, version='', label='', override=False, original=False):
    """(file name, text): the whole source of a module's version, made into a file
    of your own to change and upload (1.0.34) - its class says the version asked
    for (module_version, version_label, default_version False), or for an override
    the version of the shipped one, which it then replaces. Nothing else is touched."""
    import ast
    cls = class_of(family, kind, from_version, original)
    _name, text = source_of(family, kind, from_version, original)
    if override:
        shipped = [getattr(c, '_replaced', None) or c
                   for c in (S.registry().versions.get(family, {}).get(kind) or {}).values()
                   if getattr(c, '_origin', 'builtin') == 'builtin' or getattr(c, '_replaced', None)]
        version = (shipped[0].module_version or '') if shipped else (cls.module_version or '')
    version = str(version or '')
    if not override and not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$', version):
        raise ValueError('a version: letters, digits and . _ - (up to 40)')
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        raise ValueError('the source cannot be read: %s' % e)
    node = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls.__name__), None)
    if node is None:
        raise ValueError('the class %s is not in its file' % cls.__name__)
    lines = text.splitlines(True)
    edits = []                               # (first line, last line, new lines), 1-based
    for st in node.body:
        targets = st.targets if isinstance(st, ast.Assign) else ([st.target] if isinstance(st, ast.AnnAssign) else [])
        if any(isinstance(t, ast.Name) and t.id in ('module_version', 'version_label', 'default_version')
               for t in targets):
            edits.append((st.lineno, st.end_lineno, []))
    first = node.body[0]
    doc = isinstance(first, ast.Expr) and isinstance(getattr(first, 'value', None), ast.Constant) \
        and isinstance(first.value.value, str)
    at = first.end_lineno if doc else first.lineno - 1          # insert after this line (1-based)
    ind = ' ' * first.col_offset
    edits.append((at + 1, at, [
        ind + '# made from %s %s %s by acme - your own from here (docs/writing-a-module.md)\n' % (
            family, kind, cls.module_version or 'plain'),
        ind + 'module_version = %r\n' % version,
        ind + 'version_label = %r\n' % str(label or ''),
        ind + 'default_version = False      # True: a new one, and one that says none, take this one\n']))
    # Another module of the same file (tls.py holds tls and https) is taken as it is
    # from where it comes - defined here again, the upload would replace it too.
    for other in tree.body:
        if other is node or not isinstance(other, ast.ClassDef):
            continue
        is_mod = any(isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'kind'
                                                         for t in st.targets)
                     for st in other.body)
        if is_mod:
            start = min([other.lineno] + [d.lineno for d in other.decorator_list])
            edits.append((start, other.end_lineno, [
                'from %s import %s  # another module of this file, as it is there\n' % (
                    cls.__module__, other.name)]))
    for a, b, add in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        lines[a - 1:b] = add
    out = ''.join(lines)
    if not out.endswith('\n'):
        out += '\n'
    fname = '%s_%s.py' % (kind, 'override' if override else re.sub(r'[^a-z0-9]+', '_', version.lower()))
    return fname, out


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
