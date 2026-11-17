#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent_windows.py - acme-agent for Windows: its own Python, its own OpenSSL and the MSI
(1.0.120, docs/target-agent.md "Install on Windows").

    python3 tools/agent_windows.py check            are the tools and the downloads here?
    python3 tools/agent_windows.py fetch            download the pinned sources into the cache
    python3 tools/agent_windows.py runtime DIR      the trimmed runtime (runtime\\ and openssl\\)
    python3 tools/agent_windows.py msi --out DIR [--version X.Y.Z] [--key FILE]
                                                    acme-agent-X.Y.Z-windows-x64.msi

tools/release.py builds the MSI with every release (signed MANIFEST inside, by the release
key); a release fails when anything here is missing - never a release without it.

What goes in (all pinned, downloaded once into the cache, checked by SHA-256 every time):

  * CPython for Windows x64 - the NuGet package `python` (its tools\\ folder is a whole
    CPython with vcruntime140.dll), trimmed to the standard library modules the agent's own
    files import (modulefinder over deploy/agent/acme_agent*.py, plus the Windows-only
    modules), the C extension modules among them and the DLLs those need (read from their
    import tables). A `python313._pth` makes sys.path exactly Lib, DLLs and the program
    folder: nothing of the machine is ever imported (and the CLI runs it with -I -B).
  * OpenSSL for Windows x64 - conda-forge's `openssl` package: openssl.exe and its two DLLs,
    with vcruntime140.dll beside them, and an openssl.cnf of its own.

The cache: $ACME_AGENT_WINDOWS_CACHE, else ~/.cache/acme-agent-windows (outside the repository).
A machine with no network: put the two files named below into the cache by hand.

The MSI is made with wixl (msitools) - per-machine, x64, C:\\Program Files\\acme-agent, a major
upgrade replacing any older version, the custom actions running the installed
`runtime\\python.exe -I -B acme_agent.py windows-install|windows-uninstall` - and its wizard
(Welcome, Join, Ready, Progress, Finish, and the Cancel/UserExit/FatalError/Error/Maintenance
dialogs) is imported afterwards with msibuild as Windows Installer tables, because wixl has no
<UI>. check_ui() checks those tables' references; the build refuses an MSI that fails it.
"""
import argparse
import ast
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_DIR = os.path.join(ROOT, 'deploy', 'agent')
WIN_DIR = os.path.join(AGENT_DIR, 'windows')
KEYS_DIR = os.path.join(ROOT, 'deploy', 'release-keys')

PY_VERSION = '3.13.17'
PY_TAG = '313'
SOURCES = {
    'python': {
        'file': 'python.%s.nupkg' % PY_VERSION,
        'url': 'https://api.nuget.org/v3-flatcontainer/python/%s/python.%s.nupkg' % (
            PY_VERSION, PY_VERSION),
        'sha256': 'dce409744b088f94c6e37ba41f8100c384c27e029e843237364c602d30d475e5',
    },
    'openssl': {
        'file': 'openssl-3.6.5-hf411b9b_0.conda',
        'url': 'https://conda.anaconda.org/conda-forge/win-64/openssl-3.6.5-hf411b9b_0.conda',
        'sha256': 'bc44625e0c6d83f3e02b5f6adc01e0e3ca7001d3d94e24959591a57f5a011b9a',
    },
}
TOOLS = ('wixl', 'msibuild', 'zstd')

# The product: one UpgradeCode for ever (a newer MSI replaces an older one); the ProductCode is
# the version's own (made from it, so `msiexec /x {...}` is the same for every build of it).
UPGRADE_CODE = '{6F1D3C2A-8E45-4B7A-9C11-2D5E7A40C9B3}'
PRODUCT_NS = uuid.UUID('9b0e7c52-3f6a-4d8e-a1b4-5c7d2e9f0a16')
MANUFACTURER = 'acme'

# Never in the runtime, whatever imports them (the agent does not run them).
EXCLUDES = ['tkinter', '_tkinter', 'idlelib', 'test', 'unittest', 'doctest', 'pdb', 'pydoc',
            'pydoc_data', 'ensurepip', 'venv', 'lib2to3', 'turtle', 'turtledemo', 'curses',
            '_pyrepl', 'sqlite3', '_sqlite3', 'dbm', 'xmlrpc', 'pip', 'setuptools', 'distutils',
            'idle', 'tabnanny', 'cProfile', 'profile', 'pstats', 'trace', 'tracemalloc',
            'multiprocessing', 'concurrent.futures.process', 'asyncio', 'wsgiref',
            'mailbox', 'smtplib', 'imaplib', 'poplib', 'ftplib', 'xml.dom', 'xml.sax',
            'xml.etree', 'pyexpat', 'webbrowser', 'winsound', '_testcapi', 'zipapp',
            'lzma', '_lzma', 'bz2', '_bz2', 'decimal', '_decimal', '_pydecimal',
            'readline', 'rlcompleter', 'statistics', 'fractions']
# Always in it: what Windows code of the agent uses (Part A/B's files are scanned too, these
# make sure of the Windows-only ones whatever the scan finds), and what Python starts with.
WINDOWS_MODULES = ['nt', 'ntpath', 'msvcrt', '_winapi', 'winreg', '_overlapped', 'ctypes',
                   'ctypes.wintypes', 'ctypes.util', '_ctypes', 'ssl', '_ssl', 'hashlib',
                   '_hashlib', 'socket', '_socket', 'select', 'selectors', 'unicodedata',
                   'encodings', 'subprocess', 'platform', '_wmi', 'uuid', '_uuid', 'locale',
                   'tarfile', 'gzip', 'zipfile', 'json', 'http.client', 'http.server',
                   'ipaddress', 'tempfile', 'threading', 'queue', '_queue', 'shutil', 'base64',
                   'datetime', 'secrets', 'struct', 'stat', 'string', 'textwrap', 'traceback',
                   'zipimport', 'runpy', 'importlib.util', 'importlib.machinery', 'io', 'abc',
                   'codecs', 'os', 'site', '_sitebuiltins', 'genericpath', 'warnings', 'typing']
# DLLs Windows has itself (never shipped): anything not in the downloads is taken as one of
# these; this list only says which are expected.
SYSTEM_DLLS = re.compile(r'^(api-ms-win-.*|kernel32|advapi32|ws2_32|crypt32|user32|ole32|'
                         r'oleaut32|shell32|version|bcrypt|ntdll|rpcrt4|secur32|iphlpapi|'
                         r'shlwapi|userenv|netapi32|wtsapi32|cabinet|msi|propsys|gdi32|'
                         r'comdlg32|winmm|dnsapi|ncrypt|mpr|psapi|setupapi|wbemuuid|'
                         r'ucrtbase)\.dll$', re.I)


class Missing(Exception):
    """A tool or a pinned download is not here - a release stops on it."""


def say(text):
    print(text, flush=True)


# ---- the cache, the pinned downloads ------------------------------------------------------------
def cache_dir():
    return os.path.abspath(os.path.expanduser(
        os.environ.get('ACME_AGENT_WINDOWS_CACHE') or '~/.cache/acme-agent-windows'))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for lump in iter(lambda: f.read(1 << 20), b''):
            h.update(lump)
    return h.hexdigest()


def missing_tools():
    return [t for t in TOOLS if not shutil.which(t)]


def _download(url, dest):
    import ssl
    import urllib.request
    ctx = ssl.create_default_context(cafile=os.environ.get('SSL_CERT_FILE') or None)
    req = urllib.request.Request(url, headers={'User-Agent': 'acme-release'})
    tmp = dest + '.part'
    with urllib.request.urlopen(req, context=ctx, timeout=120) as r, open(tmp, 'wb') as f:
        shutil.copyfileobj(r, f, 1 << 20)
    os.replace(tmp, dest)


def fetch(download=True, cache=None):
    """{name: path} of the pinned sources in the cache, each checked by its SHA-256 (downloaded
    when missing and `download`). Missing when one is not there or not the pinned one."""
    cache = cache or cache_dir()
    os.makedirs(cache, exist_ok=True)
    out = {}
    for name, src in sorted(SOURCES.items()):
        path = os.path.join(cache, src['file'])
        if os.path.isfile(path) and sha256_file(path) != src['sha256']:
            os.unlink(path)                 # a broken or other file: never used
        if not os.path.isfile(path):
            if not download:
                raise Missing('%s is not in %s (python3 tools/agent_windows.py fetch, or put '
                              '%s there by hand)' % (src['file'], cache, src['url']))
            say('downloading %s' % src['url'])
            try:
                _download(src['url'], path)
            except Exception as e:          # noqa: BLE001 - any failure is "missing"
                raise Missing('%s could not be downloaded (%s) - put it into %s by hand'
                              % (src['url'], e, cache))
            if sha256_file(path) != src['sha256']:
                os.unlink(path)
                raise Missing('%s is not the pinned file (SHA-256 differs) - refused'
                              % src['url'])
        out[name] = path
    return out


def _safe_member(name):
    parts = name.replace('\\', '/').split('/')
    return not (name.startswith('/') or '..' in parts or ':' in parts[0])


def unpacked(cache=None, download=True):
    """The sources unpacked once into the cache: {'python': <tools folder>, 'openssl': <folder
    with openssl.exe, its DLLs and LICENSE.txt>}."""
    cache = cache or cache_dir()
    got = fetch(download=download, cache=cache)
    out = {}
    py = os.path.join(cache, 'unpacked', 'python-' + SOURCES['python']['sha256'][:16])
    if not os.path.isfile(os.path.join(py, '.done')):
        shutil.rmtree(py, ignore_errors=True)
        with zipfile.ZipFile(got['python']) as z:
            for m in z.infolist():
                if not m.filename.startswith('tools/') or m.is_dir():
                    continue
                if not _safe_member(m.filename):
                    raise Missing('the python package holds a strange name: %s' % m.filename)
                dest = os.path.join(py, *m.filename[len('tools/'):].split('/'))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with z.open(m) as src, open(dest, 'wb') as f:
                    shutil.copyfileobj(src, f)
        open(os.path.join(py, '.done'), 'w').close()
    out['python'] = py
    ossl = os.path.join(cache, 'unpacked', 'openssl-' + SOURCES['openssl']['sha256'][:16])
    if not os.path.isfile(os.path.join(ossl, '.done')):
        if not shutil.which('zstd'):
            raise Missing('zstd is not installed (the conda package is zstd-compressed)')
        shutil.rmtree(ossl, ignore_errors=True)
        os.makedirs(ossl)
        want = {'Library/bin/openssl.exe': 'openssl.exe',
                'Library/bin/libcrypto-3-x64.dll': 'libcrypto-3-x64.dll',
                'Library/bin/libssl-3-x64.dll': 'libssl-3-x64.dll',
                'info/licenses/LICENSE.txt': 'LICENSE.txt'}
        with zipfile.ZipFile(got['openssl']) as z:
            for m in z.namelist():
                if not (m.endswith('.tar.zst') and (m.startswith('pkg-') or
                                                    m.startswith('info-'))):
                    continue
                r = subprocess.run(['zstd', '-d', '-c', '-q'], input=z.read(m),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
                if r.returncode != 0:
                    raise Missing('zstd could not unpack %s: %s' % (
                        m, r.stderr.decode('utf-8', 'replace')[-200:]))
                with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tar:
                    for ti in tar.getmembers():
                        if ti.name in want and ti.isfile():
                            with open(os.path.join(ossl, want[ti.name]), 'wb') as f:
                                f.write(tar.extractfile(ti).read())
        lost = [v for v in want.values() if not os.path.isfile(os.path.join(ossl, v))]
        if lost:
            raise Missing('the openssl package has no %s' % ', '.join(lost))
        open(os.path.join(ossl, '.done'), 'w').close()
    out['openssl'] = ossl
    return out


# ---- PE import tables (which DLLs a .exe/.dll/.pyd needs) ---------------------------------------
def pe_imports(path):
    """The DLL names a PE file imports (lower case) - read from its import directory."""
    with open(path, 'rb') as f:
        data = f.read()
    if data[:2] != b'MZ':
        raise ValueError('%s is not a PE file' % path)
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('%s is not a PE file' % path)
    nsec, = struct.unpack_from('<H', data, pe + 6)
    opt_size, = struct.unpack_from('<H', data, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from('<H', data, opt)
    dd = opt + (112 if magic == 0x20b else 96)
    imp_rva, _imp_size = struct.unpack_from('<II', data, dd + 8)
    secs = []
    so = opt + opt_size
    for i in range(nsec):
        vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, so + 40 * i + 8)
        secs.append((vaddr, max(vsize, rsize), raddr))

    def off(rva):
        for vaddr, size, raddr in secs:
            if vaddr <= rva < vaddr + size:
                return rva - vaddr + raddr
        raise ValueError('%s: an address outside its sections' % path)
    out = []
    if not imp_rva:
        return out
    p = off(imp_rva)
    while True:
        desc = struct.unpack_from('<IIIII', data, p)
        if not any(desc):
            break
        n = off(desc[3])
        out.append(data[n:data.index(b'\0', n)].decode('ascii').lower())
        p += 20
    return out


# ---- the runtime ------------------------------------------------------------------------------
def agent_files(agent_dir=None):
    """AGENT_FILES of deploy/agent/acme_agent.py (read, not run)."""
    agent_dir = agent_dir or AGENT_DIR
    with open(os.path.join(agent_dir, 'acme_agent.py'), encoding='utf-8') as f:
        text = f.read()
    m = re.search(r'^AGENT_FILES\s*=\s*(\([^)]*\))', text, re.M)
    names = ast.literal_eval(m.group(1)) if m else ('acme_agent.py',)
    return tuple(names)


def stdlib_needed(lib, scripts, extra=()):
    """(the .py files of `lib` the scripts import, relative to lib; every module name seen)."""
    import modulefinder
    mf = modulefinder.ModuleFinder(path=[lib] + sorted({os.path.dirname(s) for s in scripts}),
                                   excludes=EXCLUDES)
    for s in scripts:
        mf.run_script(s)
    # encodings is looked up by name at run time (the console's code page, mbcs, oem, cp1250...)
    encs = ['encodings.' + n[:-3] for n in sorted(os.listdir(os.path.join(lib, 'encodings')))
            if n.endswith('.py') and n != '__init__.py']
    for name in list(extra) + encs:
        try:
            mf.import_hook(name)
        except ImportError:
            pass                            # a builtin of python313.dll, or a .pyd
    files, names = set(), set(mf.modules) | set(mf.badmodules) | set(extra)
    lib_abs = os.path.abspath(lib)
    for name, mod in mf.modules.items():
        fn = getattr(mod, '__file__', None)
        if fn and os.path.abspath(fn).startswith(lib_abs + os.sep):
            files.add(os.path.relpath(os.path.abspath(fn), lib_abs).replace(os.sep, '/'))
    return files, names


OPENSSL_CNF = """# acme-agent's own OpenSSL configuration (ACME_AGENT's openssl.exe is run with
# OPENSSL_CONF pointing here, so no other file of the machine is ever read)
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect

[default_sect]
activate = 1
"""

PTH = 'Lib\r\nDLLs\r\n..\r\n'


def build_runtime(dest, cache=None, agent_dir=None, compile_pyc=None, download=True):
    """dest\\runtime (python.exe, python313.dll, Lib\\, DLLs\\, python313._pth) and dest\\openssl
    -> facts {'modules', 'pyds', 'files', 'pyc', 'bytes'}."""
    agent_dir = agent_dir or AGENT_DIR
    src = unpacked(cache, download=download)
    py, ossl = src['python'], src['openssl']
    lib, dlls = os.path.join(py, 'Lib'), os.path.join(py, 'DLLs')
    scripts = [os.path.join(agent_dir, n) for n in agent_files(agent_dir)
               if os.path.isfile(os.path.join(agent_dir, n))]
    files, names = stdlib_needed(lib, scripts, WINDOWS_MODULES)
    rt = os.path.join(dest, 'runtime')
    os.makedirs(rt)
    for n in ('python.exe', 'python%s.dll' % PY_TAG, 'vcruntime140.dll', 'LICENSE.txt'):
        shutil.copyfile(os.path.join(py, n), os.path.join(rt, n))
    with open(os.path.join(rt, 'python%s._pth' % PY_TAG), 'w', newline='') as f:
        f.write(PTH)
    for rel in sorted(files):
        d = os.path.join(rt, 'Lib', *rel.split('/'))
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copyfile(os.path.join(lib, *rel.split('/')), d)
    # the C extension modules seen (a .pyd of DLLs\ of the same name), and the DLLs they need
    pyds = sorted(n for n in names if '.' not in n and n not in EXCLUDES and
                  os.path.isfile(os.path.join(dlls, n + '.pyd')))
    os.makedirs(os.path.join(rt, 'DLLs'))
    for n in pyds:
        shutil.copyfile(os.path.join(dlls, n + '.pyd'), os.path.join(rt, 'DLLs', n + '.pyd'))
    _close_dlls(rt, {'': py, 'DLLs': dlls})
    # OpenSSL: openssl.exe, its DLLs, vcruntime140.dll beside them (found first: the folder of
    # the .exe), its licence and a configuration of its own
    od = os.path.join(dest, 'openssl')
    os.makedirs(od)
    for n in ('openssl.exe', 'libcrypto-3-x64.dll', 'libssl-3-x64.dll', 'LICENSE.txt'):
        shutil.copyfile(os.path.join(ossl, n), os.path.join(od, n))
    shutil.copyfile(os.path.join(py, 'vcruntime140.dll'), os.path.join(od, 'vcruntime140.dll'))
    with open(os.path.join(od, 'openssl.cnf'), 'w', newline='') as f:
        f.write(OPENSSL_CNF.replace('\n', '\r\n'))
    _close_dlls(od, {'': ossl})
    # .pyc beside the sources (checked by hash: an installed file's time is the install's), so
    # the CLI starts quickly - only with this very Python version (3.13's bytecode)
    if compile_pyc is None:
        compile_pyc = sys.version_info[:2] == (int(PY_TAG[0]), int(PY_TAG[1:]))
    if compile_pyc:
        import py_compile
        for rel in sorted(files):
            full = os.path.join(rt, 'Lib', *rel.split('/'))
            d, base = os.path.split(full)
            cfile = os.path.join(d, '__pycache__', base[:-3] + '.cpython-%s.pyc' % PY_TAG)
            py_compile.compile(full, cfile=cfile, dfile='Lib/' + rel, doraise=True,
                               invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
    total, count = 0, 0
    for top, _d, fs in os.walk(dest):
        for n in fs:
            total += os.path.getsize(os.path.join(top, n))
            count += 1
    return {'modules': len(files), 'pyds': pyds, 'files': count, 'pyc': bool(compile_pyc),
            'bytes': total}


def _close_dlls(folder, sources):
    """Every DLL a PE file in `folder` imports that the download has (not Windows' own) copied in,
    until nothing is missing; Missing when one is neither."""
    have = {}
    for top, _d, fs in os.walk(folder):
        for n in fs:
            have[n.lower()] = os.path.join(top, n)
    known = {}
    for sub, src in sources.items():
        for n in os.listdir(src):
            if n.lower().endswith('.dll'):
                known.setdefault(n.lower(), (sub, os.path.join(src, n)))
    todo = [p for p in have.values() if p.lower().endswith(('.exe', '.dll', '.pyd'))]
    while todo:
        p = todo.pop()
        for dll in pe_imports(p):
            if dll in have:
                continue
            if dll in known:
                sub, src = known[dll]
                # a DLL of DLLs\ beside the .pyd that needs it; one of the top beside python.exe
                where = os.path.join(folder, sub) if sub else folder
                os.makedirs(where, exist_ok=True)
                dest = os.path.join(where, os.path.basename(src))
                shutil.copyfile(src, dest)
                have[dll] = dest
                todo.append(dest)
            elif not SYSTEM_DLLS.match(dll) and not dll.startswith('python'):
                raise Missing('%s needs %s, which is neither in the download nor one of '
                              'Windows\' own' % (os.path.basename(p), dll))


# ---- the payload: what C:\Program Files\acme-agent holds ----------------------------------------
def _crlf(data):
    return data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')


def build_payload(dest, version, key=None, keys_dir=None, cache=None, agent_dir=None,
                  download=True):
    """The program folder as it is installed, MANIFEST (every file) and - with the release key
    - MANIFEST.sig, as the Linux package. -> facts."""
    agent_dir = agent_dir or AGENT_DIR
    keys_dir = keys_dir or KEYS_DIR
    os.makedirs(dest)
    names = agent_files(agent_dir)
    lost = [n for n in names if not os.path.isfile(os.path.join(agent_dir, n))]
    if lost:
        raise Missing('deploy/agent has no %s (AGENT_FILES names it)' % ', '.join(lost))
    for n in names + ('README.md',):
        shutil.copyfile(os.path.join(agent_dir, n), os.path.join(dest, n))
    win = os.path.join(agent_dir, 'windows')
    for n in ('acme-agent.cmd', 'README.txt'):
        with open(os.path.join(win, n), 'rb') as f:
            data = _crlf(f.read())
        with open(os.path.join(dest, n), 'wb') as f:
            f.write(data)
    with open(os.path.join(dest, 'release'), 'w', newline='') as f:
        f.write(version + '\n')
    pubs = sorted(n for n in (os.listdir(keys_dir) if os.path.isdir(keys_dir) else [])
                  if n.endswith('.pub'))
    if pubs:
        os.makedirs(os.path.join(dest, 'release-keys'))
        for n in pubs:
            shutil.copyfile(os.path.join(keys_dir, n), os.path.join(dest, 'release-keys', n))
    facts = build_runtime(dest, cache=cache, agent_dir=agent_dir, download=download)
    rels = []
    for top, _d, fs in os.walk(dest):
        for n in fs:
            rel = os.path.relpath(os.path.join(top, n), dest).replace(os.sep, '/')
            if ' ' in rel or '\\' in rel:
                raise Missing('%s: a name MANIFEST cannot hold' % rel)
            rels.append(rel)
    manifest = ''.join('%s  %s\n' % (sha256_file(os.path.join(dest, *r.split('/'))), r)
                       for r in sorted(rels)).encode()
    with open(os.path.join(dest, 'MANIFEST'), 'wb') as f:
        f.write(manifest)
    facts['signed'] = False
    if key:
        r = subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', key, '-rawin', '-in',
                            os.path.join(dest, 'MANIFEST'), '-out',
                            os.path.join(dest, 'MANIFEST.sig')], capture_output=True)
        if r.returncode != 0:
            raise Missing('signing the Windows MANIFEST failed: %s'
                          % r.stderr.decode('utf-8', 'replace').strip())
        facts['signed'] = True
    facts['manifest'] = len(rels)
    return facts


# ---- the MSI ----------------------------------------------------------------------------------
def product_code(version):
    return '{%s}' % str(uuid.uuid5(PRODUCT_NS, 'acme-agent-windows-x64-' + version)).upper()


def msi_name(version):
    return 'acme-agent-%s-windows-x64.msi' % version


def _id(prefix, rel):
    return '%s_%s' % (prefix, hashlib.sha1(rel.encode()).hexdigest()[:24])


# Files whose ids the custom actions and the tests name
FILE_IDS = {'runtime/python.exe': 'python_exe', 'acme_agent.py': 'acme_agent_py',
            'acme-agent.cmd': 'acme_agent_cmd', 'openssl/openssl.exe': 'openssl_exe',
            'MANIFEST': 'manifest', 'MANIFEST.sig': 'manifest_sig'}

PY = '-I -B &quot;[INSTALLDIR]acme_agent.py&quot;'
# (id, command, when, sequence, kind) - kind: deferred (fails the install), ignore (an
# uninstall never fails on it: a package that cannot be uninstalled is worse), rollback.
INSTALL = 'NOT REMOVE~="ALL"'
REMOVE = 'REMOVE~="ALL"'
ACTIONS = [
    ('AgentUninstallRollback', 'windows-install', REMOVE, 1690, 'rollback'),
    ('AgentUpgradeStop', 'windows-uninstall --upgrade', REMOVE + ' AND UPGRADINGPRODUCTCODE',
     1700, 'ignore'),
    ('AgentUninstall', 'windows-uninstall',
     REMOVE + ' AND NOT UPGRADINGPRODUCTCODE AND PURGE&lt;&gt;"1"', 1701, 'ignore'),
    ('AgentUninstallPurge', 'windows-uninstall --purge',
     REMOVE + ' AND NOT UPGRADINGPRODUCTCODE AND PURGE="1"', 1702, 'ignore'),
    # only a first install (or a major upgrade's new product) is undone so: a repair that fails
    # leaves the services that were there
    ('AgentInstallRollback', 'windows-uninstall', 'NOT Installed AND ' + INSTALL, 6490,
     'rollback'),
    ('AgentInstall', 'windows-install', INSTALL + ' AND NOT JOINCODE', 6500, 'deferred'),
    ('AgentInstallJoin', 'windows-install --join &quot;[JOINCODE]&quot;',
     INSTALL + ' AND JOINCODE', 6501, 'deferred'),
]
# msidbCustomActionTypeHideTarget: the command line of these never written into the install's
# log (it holds the join code; MsiHiddenProperties alone does not hide it there) - wixl has no
# HideTarget, so the bit is set on its CustomAction table after it
HIDE_TARGET = 0x2000
HIDDEN_ACTIONS = ('AgentInstallJoin',)


def wxs(payload, version):
    """The WiX source wixl builds the MSI from."""
    def esc(s):
        return (s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                .replace('"', '&quot;'))
    tree = {}
    for top, dirs, fs in os.walk(payload):
        dirs.sort()
        rel = os.path.relpath(top, payload).replace(os.sep, '/')
        rel = '' if rel == '.' else rel
        tree[rel] = sorted(fs)
    comps = []
    out = []

    def emit(rel, depth):
        pad = '  ' * depth
        for n in tree.get(rel, []):
            frel = (rel + '/' + n) if rel else n
            fid = FILE_IDS.get(frel) or _id('f', frel)
            cid = 'c_' + fid
            comps.append(cid)
            out.append('%s<Component Id="%s" Guid="*" Win64="yes"><File Id="%s" Name="%s" '
                       'Source="%s" KeyPath="yes"/></Component>' % (
                           pad, cid, fid, esc(n), esc(os.path.join(payload, *frel.split('/')))))
        subs = sorted(k for k in tree if k and (k.rsplit('/', 1)[0] if '/' in k else '') == rel)
        for k in subs:
            out.append('%s<Directory Id="%s" Name="%s">' % (pad, _id('d', k),
                                                              esc(k.rsplit('/', 1)[-1])))
            emit(k, depth + 1)
            out.append('%s</Directory>' % pad)
    emit('', 5)
    acts, seq = [], []
    for aid, cmd, cond, n, kind in ACTIONS:
        acts.append('    <CustomAction Id="%s" FileKey="python_exe" ExeCommand="%s %s" '
                    'Execute="%s" Impersonate="no" Return="%s"/>' % (
                        aid, PY, cmd, 'rollback' if kind == 'rollback' else 'deferred',
                        'check' if kind == 'deferred' else 'ignore'))
        seq.append('      <Custom Action="%s" Sequence="%d">%s</Custom>' % (aid, n, cond))
    return '''<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="%(pc)s" Name="acme-agent" Language="1033" Version="%(v)s"
           Manufacturer="%(m)s" UpgradeCode="%(uc)s">
    <Package InstallerVersion="500" Compressed="yes" InstallScope="perMachine"
             Description="acme-agent %(v)s for Windows x64" Comments="acme-agent %(v)s: takes its
 certificates from acme by this server's own policy"/>
    <Media Id="1" Cabinet="agent.cab" EmbedCab="yes"/>
    <MajorUpgrade DowngradeErrorMessage="A newer acme-agent is installed already - an older one is never installed over it."/>
    <Property Id="JOINCODE" Secure="yes"/>
    <Property Id="PURGE" Secure="yes"/>
    <Property Id="MsiHiddenProperties" Value="JOINCODE"/>
    <Property Id="ARPCOMMENTS" Value="Takes its certificates from acme - only what this server's policy allows."/>
    <Property Id="ARPCONTACT" Value="acme"/>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFiles64Folder">
        <Directory Id="INSTALLDIR" Name="acme-agent">
%(files)s
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Agent" Title="acme-agent" Level="1" Absent="disallow">
%(refs)s
    </Feature>
%(acts)s
    <InstallExecuteSequence>
%(seq)s
    </InstallExecuteSequence>
  </Product>
</Wix>
''' % {'pc': product_code(version), 'v': version, 'm': MANUFACTURER, 'uc': UPGRADE_CODE,
       'files': '\n'.join(out), 'refs': '\n'.join('      <ComponentRef Id="%s"/>' % c
                                                  for c in comps),
       'acts': '\n'.join(acts), 'seq': '\n'.join(seq)}


# ---- the wizard: Windows Installer tables (wixl has no <UI>) ------------------------------------
# (columns, types, keys) exactly as the Windows Installer SDK's schemas
SCHEMA = {
    'Dialog': (('Dialog', 'HCentering', 'VCentering', 'Width', 'Height', 'Attributes', 'Title',
                'Control_First', 'Control_Default', 'Control_Cancel'),
               ('s72', 'i2', 'i2', 'i2', 'i2', 'I4', 'L128', 's50', 'S50', 'S50'), ('Dialog',)),
    'Control': (('Dialog_', 'Control', 'Type', 'X', 'Y', 'Width', 'Height', 'Attributes',
                 'Property', 'Text', 'Control_Next', 'Help'),
                ('s72', 's50', 's20', 'i2', 'i2', 'i2', 'i2', 'I4', 'S72', 'L0', 'S50', 'L50'),
                ('Dialog_', 'Control')),
    'ControlEvent': (('Dialog_', 'Control_', 'Event', 'Argument', 'Condition', 'Ordering'),
                     ('s72', 's50', 's50', 's255', 'S255', 'I2'),
                     ('Dialog_', 'Control_', 'Event', 'Argument', 'Condition')),
    'ControlCondition': (('Dialog_', 'Control_', 'Action', 'Condition'),
                         ('s72', 's50', 's50', 's255'),
                         ('Dialog_', 'Control_', 'Action', 'Condition')),
    'EventMapping': (('Dialog_', 'Control_', 'Event', 'Attribute'),
                     ('s72', 's50', 's50', 's50'), ('Dialog_', 'Control_', 'Event')),
    'TextStyle': (('TextStyle', 'FaceName', 'Size', 'Color', 'StyleBits'),
                  ('s72', 's32', 'i2', 'I4', 'I2'), ('TextStyle',)),
    'CheckBox': (('Property', 'Value'), ('s72', 'S64'), ('Property',)),
    'UIText': (('Key', 'Text'), ('s72', 'L255'), ('Key',)),
    'ActionText': (('Action', 'Description', 'Template'), ('s72', 'L0', 'L0'), ('Action',)),
    'Error': (('Error', 'Message'), ('i2', 'L0'), ('Error',)),
    'InstallUISequence': (('Action', 'Condition', 'Sequence'), ('s72', 'S255', 'I2'),
                          ('Action',)),
    'Property': (('Property', 'Value'), ('s72', 'l0'), ('Property',)),
    'Binary': (('Name', 'Data'), ('s72', 'v0'), ('Name',)),
    'CustomAction': (('Action', 'Type', 'Source', 'Target', 'ExtendedType'),
                     ('s72', 'i2', 'S72', 'S255', 'I4'), ('Action',)),
}

W, H = 370, 270
VIS, EN, SUNK, TRANSP, NOPREFIX = 1, 2, 4, 65536, 131072
DLG = 1 | 2 | 4                     # visible, modal, minimize
BTN = VIS | EN
TXT = VIS | EN | TRANSP | NOPREFIX
ACCENT = (0x58, 0xa6, 0xff)
DARK = (0x0d, 0x11, 0x17)
LIGHT = (0x16, 0x2a, 0x45)


def _bmp(w, h, paint):
    """A 24-bit BMP: paint(x, y) -> (r, g, b)."""
    rows = []
    pad = b'\0' * ((4 - (w * 3) % 4) % 4)
    for y in range(h - 1, -1, -1):
        rows.append(b''.join(bytes((b, g, r)) for r, g, b in (paint(x, y) for x in range(w)))
                    + pad)
    data = b''.join(rows)
    return (b'BM' + struct.pack('<IHHI', 54 + len(data), 0, 0, 54) +
            struct.pack('<IiiHHIIiiII', 40, w, h, 1, 24, 0, len(data), 2835, 2835, 0, 0) + data)


def bitmaps():
    def banner(x, y):
        if y >= 55:
            return ACCENT
        t = x / 493.0
        return tuple(int(DARK[i] + (LIGHT[i] - DARK[i]) * t) for i in range(3))

    def side(x, y):
        if x >= 164:
            return (0xff, 0xff, 0xff)
        if 158 <= x < 164:
            return ACCENT
        t = y / 312.0
        return tuple(int(DARK[i] + (LIGHT[i] - DARK[i]) * t) for i in range(3))
    return {'AcmeBanner': _bmp(493, 58, banner), 'AcmeSide': _bmp(493, 312, side)}


def _buttons(dlg, back=None, nxt=None, nxt_text='&Next', cancel=True, back_on=True,
             nxt_events=None, first_before=None):
    """The bottom row: Back, Next, Cancel - their controls and events."""
    ctl, ev = [], []
    ctl.append((dlg, 'BottomLine', 'Line', 0, 234, W, 0, VIS, None, None, None, None))
    ctl.append((dlg, 'Back', 'PushButton', 180, 243, 56, 17, BTN if back_on else VIS, None,
                '&Back', 'Next', None))
    ctl.append((dlg, 'Next', 'PushButton', 236, 243, 56, 17, BTN, None, nxt_text, 'Cancel', None))
    ctl.append((dlg, 'Cancel', 'PushButton', 304, 243, 56, 17, BTN if cancel else VIS, None,
                'Cancel', first_before or 'Back', None))
    if back:
        ev.append((dlg, 'Back', 'NewDialog', back, '1', 1))
    for i, e in enumerate(nxt_events or ([('NewDialog', nxt, '1')] if nxt else []), 1):
        ev.append((dlg, 'Next', e[0], e[1], e[2], i))
    if cancel:
        ev.append((dlg, 'Cancel', 'SpawnDialog', 'CancelDlg', '1', 1))
    return ctl, ev


def _banner(dlg, title, sub):
    return [(dlg, 'Banner', 'Bitmap', 0, 0, W, 44, VIS, None, 'AcmeBanner', None, None),
            (dlg, 'Title', 'Text', 15, 7, 340, 15, TXT, None, '{\\AcmeBannerTitle}' + title,
             None, None),
            (dlg, 'Description', 'Text', 15, 24, 340, 15, TXT, None,
             '{\\AcmeBannerText}' + sub, None, None),
            (dlg, 'BannerLine', 'Line', 0, 44, W, 0, VIS, None, None, None, None)]


def ui_tables(version):
    """{table: rows} of the wizard (with SCHEMA's columns)."""
    D, C, E, CC, EM = [], [], [], [], []

    def dialog(name, title, first, default, cancel, attrs=DLG, w=W, h=H):
        D.append((name, 50, 50, w, h, attrs, title, first, default, cancel))

    T = '[ProductName] [ProductVersion]'
    # -- Welcome
    dialog('WelcomeDlg', T, 'Next', 'Next', 'Cancel')
    C.append(('WelcomeDlg', 'Side', 'Bitmap', 0, 0, W, 234, VIS, None, 'AcmeSide', None, None))
    C.append(('WelcomeDlg', 'Title', 'Text', 135, 20, 220, 40, TXT, None,
              '{\\AcmeTitle}Welcome to acme-agent [ProductVersion]', None, None))
    C.append(('WelcomeDlg', 'Text1', 'Text', 135, 70, 220, 60, TXT, None,
              'acme-agent lets this server take its certificates from acme without acme '
              'holding any of its credentials: no password, no remote desktop, no WinRM. '
              'acme proposes, signed; this server decides by its own policy.', None, None))
    C.append(('WelcomeDlg', 'Text2', 'Text', 135, 135, 220, 50, TXT, None,
              'Nothing is allowed until the policy says so: after installing, acme may do '
              'here only what an administrator allows with acme-agent allow ...', None, None))
    C.append(('WelcomeDlg', 'Text3', 'Text', 135, 195, 220, 30, TXT, None,
              'Click Next to continue, or Cancel to leave.', None, None))
    c, e = _buttons('WelcomeDlg', nxt='JoinDlg', back_on=False)
    C += c
    E += e
    # -- Join
    dialog('JoinDlg', T, 'CodeEdit', 'Next', 'Cancel')
    C += _banner('JoinDlg', 'Join acme', 'A join code or a company enrollment code - or later.')
    C.append(('JoinDlg', 'CodeLabel', 'Text', 20, 56, 330, 12, TXT, None,
              '&Join code (optional):', None, None))
    C.append(('JoinDlg', 'CodeEdit', 'Edit', 20, 70, 330, 18, VIS | EN | SUNK, 'JOINCODE',
              '{2048}', 'Back', 'The join code|'))
    C.append(('JoinDlg', 'Help1', 'Text', 20, 98, 330, 36, TXT, None,
              'A join code made on the target\'s card in acme (ACAG1..., an hour, once), or '
              'a company enrollment code (ACAE1..., one code for many servers: this server '
              'then waits in acme for an administrator\'s confirmation).', None, None))
    C.append(('JoinDlg', 'Help2', 'Text', 20, 140, 330, 36, TXT, None,
              'Or leave it empty and join later from an elevated prompt (Run as '
              'administrator):', None, None))
    C.append(('JoinDlg', 'Help3', 'Text', 30, 162, 320, 14, TXT, None,
              '{\\AcmeMono}acme-agent join CODE', None, None))
    C.append(('JoinDlg', 'Help4', 'Text', 20, 186, 330, 40, TXT, None,
              'The service finishes the join in the background - no network is needed while '
              'installing. Confirm the agent\'s fingerprint in acme only when it is the one '
              'acme-agent fingerprint prints here.', None, None))
    ok = 'NOT JOINCODE OR JOINCODE << "ACAG1." OR JOINCODE << "ACAE1."'
    c, e = _buttons('JoinDlg', back='WelcomeDlg', first_before='CodeEdit', nxt_events=[
        ('SpawnDialog', 'InvalidCodeDlg', 'NOT (%s)' % ok), ('NewDialog', 'ReadyDlg', ok)])
    C += c
    E += e
    # -- Ready
    dialog('ReadyDlg', T, 'Next', 'Next', 'Cancel')
    C += _banner('ReadyDlg', 'Ready to install', 'acme-agent [ProductVersion] for Windows x64')
    C.append(('ReadyDlg', 'Where', 'Text', 20, 56, 330, 24, TXT, None,
              'acme-agent will be installed into [INSTALLDIR] and its two services started: '
              'acme-agent-root (LocalSystem) and acme-agent (no privileges).', None, None))
    C.append(('ReadyDlg', 'WithCode', 'Text', 20, 90, 330, 36, TXT, None,
              'It will join acme with the code you gave: the service finishes the join in '
              'the background, and acme-agent status says how it goes.', None, None))
    C.append(('ReadyDlg', 'NoCode', 'Text', 20, 90, 330, 36, TXT, None,
              'No join code given: it will not talk to acme until you run acme-agent join '
              'CODE in an elevated prompt.', None, None))
    C.append(('ReadyDlg', 'Policy', 'Text', 20, 132, 330, 36, TXT, None,
              'The policy (C:\\ProgramData\\acme-agent\\etc\\policy) allows nothing until '
              'you say so. Click Install to begin.', None, None))
    CC += [('ReadyDlg', 'WithCode', 'Hide', 'NOT JOINCODE'),
           ('ReadyDlg', 'WithCode', 'Show', 'JOINCODE'),
           ('ReadyDlg', 'NoCode', 'Hide', 'JOINCODE'),
           ('ReadyDlg', 'NoCode', 'Show', 'NOT JOINCODE')]
    c, e = _buttons('ReadyDlg', back='JoinDlg', nxt_text='&Install',
                    nxt_events=[('EndDialog', 'Return', '1')])
    C += c
    E += e
    # -- Progress (modeless: the sequence runs on while it is shown)
    dialog('ProgressDlg', T, 'Cancel', 'Cancel', 'Cancel', attrs=VIS | 4)
    C += _banner('ProgressDlg', 'Installing acme-agent', 'Please wait.')
    C.append(('ProgressDlg', 'RemovingTitle', 'Text', 15, 7, 340, 15, TXT, None,
              '{\\AcmeBannerTitle}Removing acme-agent', None, None))
    CC += [('ProgressDlg', 'Title', 'Hide', 'REMOVE="ALL"'),
           ('ProgressDlg', 'RemovingTitle', 'Hide', 'NOT REMOVE="ALL"')]
    C.append(('ProgressDlg', 'StatusLabel', 'Text', 20, 70, 50, 12, TXT, None, 'Status:',
              None, None))
    C.append(('ProgressDlg', 'ActionText', 'Text', 70, 70, 280, 12, TXT, None, None, None,
              None))
    C.append(('ProgressDlg', 'ProgressBar', 'ProgressBar', 20, 90, 330, 12, VIS | 65536,
              None, 'Progress done', None, None))
    EM += [('ProgressDlg', 'ActionText', 'ActionText', 'Text'),
           ('ProgressDlg', 'ProgressBar', 'SetProgress', 'Progress')]
    C.append(('ProgressDlg', 'BottomLine', 'Line', 0, 234, W, 0, VIS, None, None, None, None))
    C.append(('ProgressDlg', 'Back', 'PushButton', 180, 243, 56, 17, VIS, None, '&Back',
              'Next', None))
    C.append(('ProgressDlg', 'Next', 'PushButton', 236, 243, 56, 17, VIS, None, '&Next',
              'Cancel', None))
    C.append(('ProgressDlg', 'Cancel', 'PushButton', 304, 243, 56, 17, BTN, None, 'Cancel',
              'Back', None))
    E.append(('ProgressDlg', 'Cancel', 'SpawnDialog', 'CancelDlg', '1', 1))
    # -- Finish (success), UserExit, FatalError
    for name, title, lines in (
            ('ExitDlg', 'acme-agent is installed', [
                ('Done', 'The services run now. Next, in an elevated prompt (Run as '
                 'administrator):', 'NOT REMOVE="ALL"'),
                ('Cmd1', '{\\AcmeMono}acme-agent status', 'NOT REMOVE="ALL"'),
                ('Cmd2', '{\\AcmeMono}acme-agent policy show', 'NOT REMOVE="ALL"'),
                ('Joined', 'The join goes on in the background: confirm the agent\'s '
                 'fingerprint in acme (Targets, the target\'s card) when it is the one '
                 'acme-agent fingerprint prints.', 'JOINCODE AND NOT REMOVE="ALL"'),
                ('NotJoined', 'Not joined yet: acme-agent join CODE, with a code from the '
                 'target\'s card in acme (or a company enrollment code).',
                 'NOT JOINCODE AND NOT REMOVE="ALL"'),
                ('Allow', 'Then allow what acme may do: acme-agent allow ... (acme shows the '
                 'very lines for each deployment).', 'NOT REMOVE="ALL"'),
                ('Removed', 'acme-agent was removed. Its policy and identity in '
                 'C:\\ProgramData\\acme-agent stay unless you chose to delete them.',
                 'REMOVE="ALL"')]),
            ('UserExitDlg', 'acme-agent was not installed', [
                ('Text1', 'The setup was interrupted: nothing was changed on this server. Run '
                 'it again to install acme-agent.', None)]),
            ('FatalErrorDlg', 'The setup ended because of an error', [
                ('Text1', 'acme-agent could not be installed; nothing was changed on this '
                 'server. To see why, run it again with a log:', None),
                ('Cmd1', '{\\AcmeMono}msiexec /i acme-agent-%s-windows-x64.msi /l*v '
                 'acme-agent.log' % version, None)])):
        dialog(name, T, 'Finish', 'Finish', 'Finish')
        C.append((name, 'Side', 'Bitmap', 0, 0, W, 234, VIS, None, 'AcmeSide', None, None))
        C.append((name, 'Title', 'Text', 135, 20, 220, 40, TXT, None, '{\\AcmeTitle}' + title,
                  None, None))
        if name == 'ExitDlg':
            C.append((name, 'RemovedTitle', 'Text', 135, 20, 220, 40, TXT, None,
                      '{\\AcmeTitle}acme-agent is removed', None, None))
            CC += [(name, 'Title', 'Hide', 'REMOVE="ALL"'),
                   (name, 'RemovedTitle', 'Hide', 'NOT REMOVE="ALL"')]
        y, at = 66, {}
        for cid, text, cond in lines:
            mono = text.startswith('{\\AcmeMono}')
            hgt = 13 if mono else 12 * ((len(text) + 47) // 48) + 2
            if cid == 'Removed':
                y = 66                      # alone after a removal: the others are hidden
            if cid == 'NotJoined':
                y = at['Joined']            # one of the two is shown
            at[cid] = y
            C.append((name, cid, 'Text', 145 if mono else 135, y, 215, hgt, TXT, None, text,
                      None, None))
            if cond:
                CC += [(name, cid, 'Hide', 'NOT (%s)' % cond), (name, cid, 'Show', cond)]
            y += hgt + 5
        C.append((name, 'BottomLine', 'Line', 0, 234, W, 0, VIS, None, None, None, None))
        C.append((name, 'Back', 'PushButton', 180, 243, 56, 17, VIS, None, '&Back', 'Finish',
                  None))
        C.append((name, 'Finish', 'PushButton', 236, 243, 56, 17, BTN, None, '&Finish',
                  'Cancel', None))
        C.append((name, 'Cancel', 'PushButton', 304, 243, 56, 17, VIS, None, 'Cancel', 'Back',
                  None))
        E.append((name, 'Finish', 'EndDialog', 'Return' if name == 'ExitDlg' else 'Exit', '1',
                  1))
    # -- Cancel? (small, over the others)
    dialog('CancelDlg', T, 'No', 'No', 'No', w=260, h=85)
    C.append(('CancelDlg', 'Text', 'Text', 20, 15, 220, 30, TXT, None,
              'Are you sure you want to cancel installing acme-agent?', None, None))
    C.append(('CancelDlg', 'Yes', 'PushButton', 72, 57, 56, 17, BTN, None, '&Yes', 'No', None))
    C.append(('CancelDlg', 'No', 'PushButton', 132, 57, 56, 17, BTN, None, '&No', 'Yes', None))
    E += [('CancelDlg', 'Yes', 'EndDialog', 'Exit', '1', 1),
          ('CancelDlg', 'No', 'EndDialog', 'Return', '1', 1)]
    # -- not a join code
    dialog('InvalidCodeDlg', T, 'OK', 'OK', 'OK', w=260, h=95)
    C.append(('InvalidCodeDlg', 'Text', 'Text', 20, 12, 220, 45, TXT, None,
              'That is not a join code of acme: a join code starts with ACAG1. and an '
              'enrollment code with ACAE1. - copy the whole code, or leave it empty.',
              None, None))
    C.append(('InvalidCodeDlg', 'OK', 'PushButton', 102, 67, 56, 17, BTN, None, 'OK', None,
              None))
    E.append(('InvalidCodeDlg', 'OK', 'EndDialog', 'Return', '1', 1))
    # -- the installer's own error messages (Property ErrorDialog)
    dialog('ErrorDlg', 'Installer Information', 'ErrorText', None, None,
           attrs=DLG | 65536, w=270, h=105)
    C.append(('ErrorDlg', 'ErrorText', 'Text', 15, 15, 240, 50, VIS | EN | NOPREFIX, None,
              'Information text', None, None))
    for i, (cid, label, event) in enumerate((
            ('A', '&Abort', 'ErrorAbort'), ('C', '&Cancel', 'ErrorCancel'),
            ('I', '&Ignore', 'ErrorIgnore'), ('N', '&No', 'ErrorNo'), ('O', '&OK', 'ErrorOk'),
            ('R', '&Retry', 'ErrorRetry'), ('Y', '&Yes', 'ErrorYes'))):
        C.append(('ErrorDlg', cid, 'PushButton', 100, 80, 56, 17, BTN, None, label, None,
                  None))
        E.append(('ErrorDlg', cid, 'EndDialog', event, '1', 1))
    # -- installed already: repair or remove
    dialog('MaintenanceDlg', T, 'Repair', 'Repair', 'Cancel')
    C += _banner('MaintenanceDlg', 'acme-agent is installed', 'Repair it, or remove it.')
    C.append(('MaintenanceDlg', 'Text1', 'Text', 20, 60, 330, 30, TXT, None,
              'Repair puts every file of acme-agent [ProductVersion] back as it was installed '
              'and sets its services up again; its policy and identity stay.', None, None))
    C.append(('MaintenanceDlg', 'Text2', 'Text', 20, 100, 330, 30, TXT, None,
              'Remove takes acme-agent away from this server (the next page asks about its '
              'policy and identity).', None, None))
    C.append(('MaintenanceDlg', 'BottomLine', 'Line', 0, 234, W, 0, VIS, None, None, None,
              None))
    C.append(('MaintenanceDlg', 'Repair', 'PushButton', 124, 243, 56, 17, BTN, None,
              '&Repair', 'Remove', None))
    C.append(('MaintenanceDlg', 'Remove', 'PushButton', 184, 243, 56, 17, BTN, None,
              'Re&move', 'Cancel', None))
    C.append(('MaintenanceDlg', 'Cancel', 'PushButton', 304, 243, 56, 17, BTN, None, 'Cancel',
              'Repair', None))
    E += [('MaintenanceDlg', 'Repair', 'ReinstallMode', 'ecmus', '1', 1),
          ('MaintenanceDlg', 'Repair', 'Reinstall', 'ALL', '1', 2),
          ('MaintenanceDlg', 'Repair', 'EndDialog', 'Return', '1', 3),
          ('MaintenanceDlg', 'Remove', 'NewDialog', 'RemoveDlg', '1', 1),
          ('MaintenanceDlg', 'Cancel', 'SpawnDialog', 'CancelDlg', '1', 1)]
    dialog('RemoveDlg', T, 'Next', 'Next', 'Cancel')
    C += _banner('RemoveDlg', 'Remove acme-agent', 'Its services stop and are taken away.')
    C.append(('RemoveDlg', 'Text1', 'Text', 20, 60, 330, 36, TXT, None,
              'acme-agent will be removed from this server. Its policy, its key and its '
              'place in acme stay in C:\\ProgramData\\acme-agent: installed again, it is the '
              'same agent.', None, None))
    C.append(('RemoveDlg', 'Purge', 'CheckBox', 20, 105, 330, 18, BTN, 'PURGE',
              'Also &delete the policy and the agent\'s identity', 'Back', None))
    C.append(('RemoveDlg', 'Text2', 'Text', 35, 125, 315, 30, TXT, None,
              'Then forget the target in acme too: this server could join again only with a '
              'new code.', None, None))
    c, e = _buttons('RemoveDlg', back='MaintenanceDlg', nxt_text='&Remove', first_before='Purge',
                    nxt_events=[('Remove', 'ALL', '1'), ('EndDialog', 'Return', '1')])
    C += c
    E += e

    seq = [('FindRelatedProducts', None, 25), ('AppSearch', None, 50),
           ('LaunchConditions', None, 100), ('ValidateProductID', None, 700),
           ('CostInitialize', None, 800), ('FileCost', None, 900),
           ('CostFinalize', None, 1000), ('MigrateFeatureStates', None, 1200),
           ('WelcomeDlg', 'NOT Installed', 1297), ('MaintenanceDlg', 'Installed', 1298),
           ('ProgressDlg', None, 1299), ('ExecuteAction', None, 1300),
           ('ExitDlg', None, -1), ('UserExitDlg', None, -2), ('FatalErrorDlg', None, -3)]
    styles = [('AcmeDefault', 'Segoe UI', 9, None, 0),
              ('AcmeTitle', 'Segoe UI', 14, 0x40271b, 1),
              ('AcmeBannerTitle', 'Segoe UI', 11, 0xffffff, 1),
              ('AcmeBannerText', 'Segoe UI', 9, 0xffd8c8, 0),
              ('AcmeMono', 'Consolas', 9, None, 0)]
    action_text = [
        ('InstallValidate', 'Validating install', None),
        ('InstallFiles', 'Copying new files', 'File: [1],  Folder: [9]'),
        ('RemoveFiles', 'Removing files', 'File: [1], Folder: [9]'),
        ('RemoveExistingProducts', 'Removing the older acme-agent', '[1]'),
        ('RegisterProduct', 'Registering the product', '[1]'),
        ('PublishProduct', 'Publishing product information', None),
        ('PublishFeatures', 'Publishing product features', 'Feature: [1]'),
        ('UnpublishFeatures', 'Unpublishing product features', 'Feature: [1]'),
        ('InstallFinalize', 'Finishing', None),
        ('AgentInstall', 'Setting up the services of acme-agent', None),
        ('AgentInstallJoin', 'Setting up the services of acme-agent and its join', None),
        ('AgentUninstall', 'Stopping and removing the services of acme-agent', None),
        ('AgentUninstallPurge', 'Removing acme-agent, its policy and its identity', None),
        ('AgentUpgradeStop', 'Stopping the older acme-agent', None),
        ('AgentInstallRollback', 'Taking acme-agent away again', None),
        ('AgentUninstallRollback', 'Setting acme-agent up again', None)]
    errors = [
        (0, '{{Fatal error: }}'), (1, '{{Error [1]. }}'), (2, 'Warning [1]. '),
        (4, 'Info [1]. '),
        (5, 'The installer has encountered an unexpected error installing this package. This '
            'may indicate a problem with this package. The error code is [1]. {{The arguments '
            'are: [2], [3], [4]}}'),
        (7, '{{Disk full: }}'), (8, 'Action [Time]: [1]. [2]'), (9, '[ProductName]'),
        (10, '{[2]}{, [3]}{, [4]}'), (11, 'Message type: [1], Argument: [2]'),
        (12, '=== Logging started: [Date]  [Time] ==='),
        (13, '=== Logging stopped: [Date]  [Time] ==='),
        (14, 'Action start [Time]: [1].'), (15, 'Action ended [Time]: [1]. Return value [2].'),
        (16, 'Time remaining: {[1] minutes }{[2] seconds}'),
        (17, 'Out of memory. Shut down other applications before retrying.'),
        (18, 'Installer is no longer responding.'), (19, 'Installer stopped prematurely.'),
        (20, 'Please wait while Windows configures [ProductName]'),
        (21, 'Gathering required information...'),
        (22, 'Removing older versions of this application'),
        (23, 'Preparing to remove older versions of this application'),
        (32, '{[ProductName] }Setup completed successfully.'),
        (33, '{[ProductName] }Setup failed.')]
    return {'Dialog': D, 'Control': C, 'ControlEvent': E, 'ControlCondition': CC,
            'EventMapping': EM, 'TextStyle': styles, 'CheckBox': [('PURGE', '1')],
            'UIText': [('bytes', 'bytes'), ('KB', 'KB'), ('MB', 'MB'), ('GB', 'GB')],
            'ActionText': action_text, 'Error': errors, 'InstallUISequence': seq,
            'Binary': [(k, k + '.ibd') for k in sorted(bitmaps())]}


def check_ui(t):
    """Problems of the wizard's tables (an empty list: none) - every reference resolved."""
    bad = []
    rows = lambda name: t.get(name) or []                              # noqa: E731
    cols = lambda name: SCHEMA[name][0]                                 # noqa: E731

    def dicts(name):
        return [dict(zip(cols(name), r)) for r in rows(name)]
    dlgs = {d['Dialog']: d for d in dicts('Dialog')}
    ctls = {}
    keys = {(c['Dialog_'], c['Control']) for c in dicts('Control')}
    for c in dicts('Control'):
        k = (c['Dialog_'], c['Control'])
        if k in ctls:
            bad.append('Control %s/%s twice' % k)
        ctls[k] = c
        if c['Dialog_'] not in dlgs:
            bad.append('Control %s/%s: no dialog %s' % (k + (c['Dialog_'],)))
        nxt = c.get('Control_Next')
        if nxt and (c['Dialog_'], nxt) not in keys:
            bad.append('Control %s/%s: Control_Next %s is not there' % (k + (nxt,)))
        if c['Type'] == 'Bitmap' and c['Text'] not in [b[0] for b in rows('Binary')]:
            bad.append('Control %s/%s: no Binary %s' % (k + (c['Text'],)))
        for style in re.findall(r'\{\\([A-Za-z0-9_]+)\}', c.get('Text') or ''):
            if style not in [s[0] for s in rows('TextStyle')]:
                bad.append('Control %s/%s: no TextStyle %s' % (k + (style,)))
        if c['Type'] == 'CheckBox' and c.get('Property') not in [x[0] for x in rows('CheckBox')]:
            bad.append('Control %s/%s: CheckBox %s has no CheckBox row' % (
                k + (c.get('Property'),)))
        if c['X'] + c['Width'] > dlgs.get(c['Dialog_'], {}).get('Width', 10 ** 6) or \
                c['Y'] + c['Height'] > dlgs.get(c['Dialog_'], {}).get('Height', 10 ** 6):
            bad.append('Control %s/%s lies outside its dialog' % k)
    for name, d in dlgs.items():
        for col in ('Control_First', 'Control_Default', 'Control_Cancel'):
            if d[col] and (name, d[col]) not in ctls:
                bad.append('Dialog %s: %s %s is not one of its controls' % (name, col, d[col]))
        # the tab order: from Control_First round to itself, every step a control of it
        first = d['Control_First']
        seen, cur = [], first
        while cur and (name, cur) in ctls and cur not in seen:
            seen.append(cur)
            cur = ctls[(name, cur)].get('Control_Next')
        if cur and cur != first and cur in seen:
            bad.append('Dialog %s: the tab order loops back to %s, not to %s' % (name, cur,
                                                                                  first))
        if cur and (name, cur) not in ctls:
            bad.append('Dialog %s: the tab order reaches %s, which is not there' % (name, cur))
        for (dn, cn), c in ctls.items():
            if dn == name and c['Type'] in ('PushButton', 'Edit', 'CheckBox') and \
                    c['Attributes'] & EN and c.get('Control_Next') is None and \
                    cn not in seen and name != 'ErrorDlg':
                bad.append('Dialog %s: %s cannot be reached with Tab' % (name, cn))
    for e in dicts('ControlEvent'):
        k = (e['Dialog_'], e['Control_'])
        if k not in ctls:
            bad.append('ControlEvent %s/%s: no such control' % k)
        if e['Event'] in ('NewDialog', 'SpawnDialog', 'SpawnWaitDialog') and \
                e['Argument'] not in dlgs:
            bad.append('ControlEvent %s/%s: %s %s - no such dialog' % (k + (e['Event'],
                                                                          e['Argument'])))
        if e['Event'] == 'EndDialog' and e['Argument'] not in ('Exit', 'Retry', 'Ignore',
                                                               'Return', 'ErrorAbort',
                                                               'ErrorCancel', 'ErrorIgnore',
                                                               'ErrorNo', 'ErrorOk',
                                                               'ErrorRetry', 'ErrorYes'):
            bad.append('ControlEvent %s/%s: EndDialog %s' % (k + (e['Argument'],)))
    for e in dicts('ControlCondition'):
        if (e['Dialog_'], e['Control_']) not in ctls:
            bad.append('ControlCondition %s/%s: no such control' % (e['Dialog_'], e['Control_']))
        if e['Action'] not in ('Default', 'Disable', 'Enable', 'Hide', 'Show'):
            bad.append('ControlCondition %s/%s: action %s' % (e['Dialog_'], e['Control_'],
                                                             e['Action']))
    for e in dicts('EventMapping'):
        if (e['Dialog_'], e['Control_']) not in ctls:
            bad.append('EventMapping %s/%s: no such control' % (e['Dialog_'], e['Control_']))
    # the sequence: every dialog it shows is there, the first is Welcome/Maintenance
    shown = [r for r in rows('InstallUISequence') if r[0] in dlgs or r[0].endswith('Dlg')]
    for r in shown:
        if r[0] not in dlgs:
            bad.append('InstallUISequence shows %s, which is not a dialog' % r[0])
    firsts = sorted((r for r in shown if r[2] > 0), key=lambda r: r[2])
    if not firsts or firsts[0][0] != 'WelcomeDlg':
        bad.append('InstallUISequence: the first dialog is not WelcomeDlg')
    for n in (-1, -2, -3):
        if not [r for r in shown if r[2] == n]:
            bad.append('InstallUISequence: no dialog for %d' % n)
    # Next and Back walk: every page reached from Welcome by Next comes back by Back
    walk, cur = [], 'WelcomeDlg'
    while cur and cur not in walk:
        walk.append(cur)
        nxt = [e['Argument'] for e in dicts('ControlEvent')
               if e['Dialog_'] == cur and e['Control_'] == 'Next' and e['Event'] == 'NewDialog']
        if nxt:
            back = [e['Argument'] for e in dicts('ControlEvent')
                    if e['Dialog_'] == nxt[0] and e['Control_'] == 'Back' and
                    e['Event'] == 'NewDialog']
            if back != [cur]:
                bad.append('%s -> Next -> %s, whose Back goes to %s' % (cur, nxt[0], back))
        cur = nxt[0] if nxt else None
    props = dict(rows('Property'))
    if props:
        for p in ('DefaultUIFont', 'ErrorDialog'):
            if p not in props:
                bad.append('Property %s is missing' % p)
        if props.get('ErrorDialog') not in dlgs:
            bad.append('Property ErrorDialog: no dialog %s' % props.get('ErrorDialog'))
        if props.get('DefaultUIFont') not in [s[0] for s in rows('TextStyle')]:
            bad.append('Property DefaultUIFont: no TextStyle %s' % props.get('DefaultUIFont'))
    return bad


def write_idt(folder, table, rows):
    cols, types, keys = SCHEMA[table]

    def cell(v):
        if v is None:
            return ''
        s = str(v)
        if any(ch in s for ch in '\t\r\n'):
            raise ValueError('%s: a tab or a line break in %r' % (table, s))
        return s
    lines = ['\t'.join(cols), '\t'.join(types), '\t'.join((table,) + tuple(keys))]
    lines += ['\t'.join(cell(v) for v in r) for r in rows]
    with open(os.path.join(folder, table + '.idt'), 'w', encoding='ascii', newline='') as f:
        f.write('\r\n'.join(lines) + '\r\n')


def read_table(msi, table):
    """A table of an MSI as [dict] (msiinfo export) - for the checks and the tests."""
    # (an export of a table with streams writes them into the current folder: a scratch one)
    with tempfile.TemporaryDirectory(prefix='acme-msiinfo-') as scratch:
        r = subprocess.run(['msiinfo', 'export', os.path.abspath(msi), table], cwd=scratch,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    if r.returncode != 0:
        raise Missing('msiinfo export %s %s: %s' % (msi, table,
                                                     r.stderr.decode('utf-8', 'replace')))
    lines = r.stdout.decode('utf-8', 'replace').replace('\r\n', '\n').split('\n')
    cols, types = lines[0].split('\t'), lines[1].split('\t')
    out = []
    for ln in lines[3:]:
        if not ln:
            continue
        vals = ln.split('\t')
        row = {}
        for c, ty, v in zip(cols, types, vals):
            if ty[0] in 'iI':
                row[c] = int(v) if v != '' else None
            else:
                row[c] = v if v != '' else None
        out.append(row)
    return out


def tables_of(msi):
    """The wizard's tables read back from an MSI, as ui_tables gives them (for check_ui)."""
    out = {}
    for name in ('Dialog', 'Control', 'ControlEvent', 'ControlCondition', 'EventMapping',
                 'TextStyle', 'CheckBox', 'InstallUISequence', 'Property', 'Binary'):
        cols = SCHEMA[name][0]
        out[name] = [tuple(r.get(c) for c in cols) for r in read_table(msi, name)]
    return out


def _run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=1800)
    if r.returncode != 0:
        raise Missing('%s failed: %s' % (' '.join(cmd[:2]), (r.stdout + r.stderr).decode(
            'utf-8', 'replace').strip()[-800:]))
    return r


def build_msi(out_dir, version, key=None, keys_dir=None, cache=None, agent_dir=None,
              download=True):
    """out_dir/acme-agent-X.Y.Z-windows-x64.msi -> facts {name, path, version, size, sha256,
    product_code, signed, runtime...}. Missing when a tool or a download is not here."""
    lost = missing_tools() + ([] if shutil.which('msiinfo') else ['msiinfo'])
    if lost:
        raise Missing('%s not installed (msitools and zstd: apt install msitools zstd)'
                      % ', '.join(lost))
    work = tempfile.mkdtemp(prefix='acme-agent-msi-')
    try:
        payload = os.path.join(work, 'payload')
        facts = build_payload(payload, version, key=key, keys_dir=keys_dir, cache=cache,
                              agent_dir=agent_dir, download=download)
        src = os.path.join(work, 'agent.wxs')
        with open(src, 'w', encoding='utf-8') as f:
            f.write(wxs(payload, version))
        msi = os.path.join(work, msi_name(version))
        _run(['wixl', '-a', 'x64', '-o', msi, src], cwd=work)
        # the wizard, imported over wixl's tables
        idt = os.path.join(work, 'idt')
        os.makedirs(os.path.join(idt, 'Binary'))
        for k, data in bitmaps().items():
            with open(os.path.join(idt, 'Binary', k + '.ibd'), 'wb') as f:
                f.write(data)
        t = ui_tables(version)
        props = [(r['Property'], r['Value']) for r in read_table(msi, 'Property')]
        pd = dict(props)
        secure = sorted(set(filter(None, (pd.get('SecureCustomProperties') or '').split(';')))
                        | {'JOINCODE', 'PURGE'})
        props = [p for p in props if p[0] not in ('SecureCustomProperties', 'DefaultUIFont',
                                                   'ErrorDialog')]
        props += [('SecureCustomProperties', ';'.join(secure)), ('DefaultUIFont', 'AcmeDefault'),
                  ('ErrorDialog', 'ErrorDlg'), ('ARPNOMODIFY', '1')]
        t['Property'] = props
        cols = SCHEMA['CustomAction'][0]
        t['CustomAction'] = [tuple((r.get(c) | HIDE_TARGET) if c == 'Type' and
                                   r.get('Action') in HIDDEN_ACTIONS else r.get(c)
                                   for c in cols) for r in read_table(msi, 'CustomAction')]
        bad = check_ui(t)
        if bad:
            raise Missing('the wizard\'s tables are wrong: %s' % '; '.join(bad[:10]))
        for name in t:
            write_idt(idt, name, t[name])
        for name in sorted(t):
            _run(['msibuild', msi, '-i', name + '.idt'], cwd=idt)
        # read back: what the MSI holds is what was meant
        back = tables_of(msi)
        bad = check_ui(back)
        if bad:
            raise Missing('the MSI\'s wizard tables are wrong: %s' % '; '.join(bad[:10]))
        os.makedirs(out_dir, exist_ok=True)
        dest = os.path.join(out_dir, msi_name(version))
        shutil.copyfile(msi, dest + '.part')
        os.replace(dest + '.part', dest)
        facts.update({'name': msi_name(version), 'path': dest, 'version': version,
                      'size': os.path.getsize(dest), 'sha256': sha256_file(dest),
                      'product_code': product_code(version), 'upgrade_code': UPGRADE_CODE})
        return facts
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    p = argparse.ArgumentParser(description='acme-agent for Windows: the runtime and the MSI.')
    sub = p.add_subparsers(dest='cmd')
    sub.add_parser('check', help='are the tools and the pinned downloads here?')
    sub.add_parser('fetch', help='download the pinned sources into the cache')
    r = sub.add_parser('runtime', help='the trimmed runtime into DIR')
    r.add_argument('dir')
    m = sub.add_parser('msi', help='build the MSI into --out')
    m.add_argument('--out', required=True)
    m.add_argument('--version', help='default: acmelib/__init__.py\'s')
    m.add_argument('--key', help='the private release key (MANIFEST.sig); none: unsigned')
    m.add_argument('--agent-dir', help='the agent\'s files (default deploy/agent)')
    a = p.parse_args(argv)
    try:
        if a.cmd == 'check':
            lost = missing_tools()
            say('tools: %s' % ('all there' if not lost else 'missing ' + ', '.join(lost)))
            say('cache: %s' % cache_dir())
            fetch(download=False)
            say('downloads: both there and the pinned ones')
            return 1 if lost else 0
        if a.cmd == 'fetch':
            for n, path in sorted(fetch().items()):
                say('%-8s %s' % (n, path))
            return 0
        if a.cmd == 'runtime':
            facts = build_runtime(os.path.abspath(a.dir))
            say('runtime: %(files)d files, %(bytes)d bytes, %(modules)d modules' % facts)
            return 0
        if a.cmd == 'msi':
            version = a.version
            if not version:
                with open(os.path.join(ROOT, 'acmelib', '__init__.py'), encoding='utf-8') as f:
                    version = re.search(r"__version__ = '([^']+)'", f.read()).group(1)
            facts = build_msi(os.path.abspath(a.out), version, key=a.key, agent_dir=a.agent_dir)
            say('%(name)s: %(size)d bytes, sha256 %(sha256)s, %(manifest)d files, product '
                'code %(product_code)s%(s)s' % dict(facts, s=', signed' if facts['signed']
                                                     else ', not signed'))
            return 0
    except Missing as e:
        sys.stderr.write('agent_windows.py: %s\n' % e)
        return 1
    p.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
