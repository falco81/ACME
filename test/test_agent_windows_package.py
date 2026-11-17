#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Windows agent's package (1.0.120, Part C): tools/agent_windows.py's trimmed runtime and
MSI, its tables (files, custom actions, properties, the wizard's references), the signed
MANIFEST inside, tools/release.py carrying it, and acme handing it out (GET /api/agents/package
?platform=windows, package.windows).

Built into a temporary folder; skipped when wixl/msibuild/msiinfo/msiextract/zstd or the
pinned downloads (python3 tools/agent_windows.py fetch) are not here.

    python3 test/test_agent_windows_package.py
"""
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-winpkg-')
os.chmod(TMP, 0o755)
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "n1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


W = load('agent_windows_t', os.path.join(ROOT, 'tools', 'agent_windows.py'))
VERSION = '9.9.9'
BUILT = {}


def why_not():
    lost = [t for t in ('wixl', 'msibuild', 'msiinfo', 'msiextract', 'zstd', 'openssl')
            if not shutil.which(t)]
    if lost:
        return 'not installed: %s' % ', '.join(lost)
    try:
        W.fetch(download=False)
    except W.Missing as e:
        return str(e)
    return None


WHY = why_not()


def openssl(*args):
    return subprocess.run(['openssl'] + list(args), capture_output=True, check=True).stdout


def agent_dir():
    """deploy/agent when every file AGENT_FILES names is there; else a copy with a stand-in for
    each one not written yet (the other parts of 1.0.120 are made at the same time)."""
    names = W.agent_files()
    if all(os.path.isfile(os.path.join(W.AGENT_DIR, n)) for n in names):
        return W.AGENT_DIR
    d = os.path.join(TMP, 'agent')
    shutil.copytree(W.AGENT_DIR, d, ignore=shutil.ignore_patterns('__pycache__', '*.msi',
                                                                  '*.tar.gz'))
    for n in names:
        p = os.path.join(d, n)
        if not os.path.exists(p):
            with open(p, 'w') as fh:
                fh.write('import ctypes\nimport ctypes.wintypes\nimport winreg\nimport ntpath\n')
    return d


def setUpModule():
    if WHY:
        return
    d = os.path.join(TMP, 'keys')
    os.makedirs(d)
    key = os.path.join(TMP, 'k.pem')
    openssl('genpkey', '-algorithm', 'ed25519', '-out', key)
    openssl('pkey', '-in', key, '-pubout', '-out', os.path.join(d, 'test-1.pub'))
    BUILT.update(key=key, keys=d, agent=agent_dir())
    BUILT['facts'] = W.build_msi(os.path.join(TMP, 'out'), VERSION, key=key, keys_dir=d,
                                 agent_dir=BUILT['agent'], download=False)
    ex = os.path.join(TMP, 'ex')
    os.makedirs(ex)
    subprocess.run(['msiextract', '-C', ex, BUILT['facts']['path']], check=True,
                   capture_output=True)
    BUILT['files'] = os.path.join(ex, 'acme-agent')


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


def table(name):
    return W.read_table(BUILT['facts']['path'], name)


@unittest.skipIf(WHY, 'the Windows package cannot be built here: %s' % WHY)
class Msi(unittest.TestCase):
    def test_files(self):
        f = BUILT['facts']
        self.assertEqual(f['name'], 'acme-agent-9.9.9-windows-x64.msi')
        self.assertTrue(f['signed'])
        self.assertGreater(f['size'], 4 << 20)
        self.assertLess(f['size'], 40 << 20)
        rows = table('File')
        ids = {r['File']: r for r in rows}
        for fid, name in (('python_exe', 'python.exe'), ('openssl_exe', 'openssl.exe'),
                          ('acme_agent_py', 'acme_agent.py'), ('acme_agent_cmd', 'acme-agent.cmd'),
                          ('manifest', 'MANIFEST'), ('manifest_sig', 'MANIFEST.sig')):
            self.assertEqual(ids[fid]['FileName'], name)
        names = {r['FileName'] for r in rows}
        for n in W.agent_files() + ('README.md', 'README.txt', 'release', 'test-1.pub',
                                    'python313.dll', 'python313._pth', 'vcruntime140.dll',
                                    'libcrypto-3-x64.dll', 'libssl-3-x64.dll', 'openssl.cnf',
                                    '_ssl.pyd', '_hashlib.pyd', '_ctypes.pyd', 'libffi-8.dll',
                                    '_socket.pyd', 'select.pyd', 'libcrypto-3.dll', '_overlapped.pyd',
                                    'libssl-3.dll', 'ssl.py', 'subprocess.py', 'ntpath.py'):
            self.assertIn(n, names)
        # what the agent never runs is not there
        for n in ('_tkinter.pyd', 'tkinter', 'pip', 'ensurepip', 'idlelib', 'pydoc.py',
                  'doctest.py', 'sqlite3.dll', '_sqlite3.pyd', 'pythonw.exe', 'openssl.pdb'):
            self.assertNotIn(n, names)
        dirs = {r['DefaultDir'] for r in table('Directory')}
        for n in ('tkinter', 'test', 'ensurepip', 'venv', 'idlelib', 'pydoc_data', 'lib2to3',
                  'unittest', 'asyncio', 'sqlite3'):
            self.assertNotIn(n, dirs)
        self.assertIn('acme-agent', dirs)
        top = [r for r in table('Directory') if r['Directory'] == 'INSTALLDIR'][0]
        self.assertEqual(top['Directory_Parent'], 'ProgramFiles64Folder')
        comp = table('Component')
        self.assertTrue(all(c['Attributes'] & 256 for c in comp))     # 64-bit components
        self.assertEqual(len(comp), len(rows))

    def test_runtime_whole(self):
        """Every DLL a .exe/.dll/.pyd needs is beside it or Windows' own; the ._pth isolates."""
        base = BUILT['files']
        rt = os.path.join(base, 'runtime')
        with open(os.path.join(rt, 'python313._pth'), 'rb') as fh:
            self.assertEqual(fh.read(), b'Lib\r\nDLLs\r\n..\r\n')
        for folder, beside in ((rt, [rt, os.path.join(rt, 'DLLs')]),
                               (os.path.join(base, 'openssl'), [os.path.join(base, 'openssl')])):
            for top, _d, fs in os.walk(folder):
                for n in fs:
                    if not n.lower().endswith(('.exe', '.dll', '.pyd')):
                        continue
                    for dll in W.pe_imports(os.path.join(top, n)):
                        here = any(os.path.exists(os.path.join(b, x)) for b in beside + [top]
                                   for x in os.listdir(b) if x.lower() == dll)
                        self.assertTrue(here or W.SYSTEM_DLLS.match(dll),
                                        '%s needs %s' % (n, dll))
        self.assertIn('vcruntime140.dll', W.pe_imports(os.path.join(base, 'openssl',
                                                                     'openssl.exe')))
        self.assertTrue(os.path.exists(os.path.join(base, 'openssl', 'vcruntime140.dll')))
        with open(os.path.join(base, 'acme-agent.cmd'), 'rb') as fh:
            self.assertEqual(fh.read(), b'@"%~dp0runtime\\python.exe" -I -B "%~dp0acme_agent.py" '
                                        b'%*\r\n')
        with open(os.path.join(base, 'README.txt'), 'rb') as fh:
            text = fh.read()
        self.assertNotIn(b'\n', text.replace(b'\r\n', b''))
        for line in (b'msiexec /i acme-agent-X.Y.Z-windows-x64.msi /qn JOINCODE=', b'PURGE=1',
                     b'Intune', b'SCCM', b'GPO', b'acme-agent status', b'acme-agent policy show'):
            self.assertIn(line, text)

    @unittest.skipUnless(sys.version_info[:2] == (3, 13), 'the runtime is Python 3.13')
    def test_stdlib_enough(self):
        """The trimmed Lib (with this machine's C modules standing in for the .pyd) imports
        the agent - nothing it imports at its top was left out."""
        base = BUILT['files']
        dyn = sysconfig.get_config_var('DESTSHARED') or ''
        code = ('import sys; sys.path[:] = [%r, %r, %r]; import acme_agent, ssl, subprocess, '
                'ctypes, http.server, http.client, tarfile, json, ipaddress, uuid, platform, '
                'stringprep, unicodedata; '
                'print(acme_agent.__file__)' % (os.path.join(base, 'runtime', 'Lib'), dyn, base))
        r = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code], capture_output=True,
                           text=True, cwd=TMP)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertTrue(r.stdout.strip().startswith(base))
        # the code pages a Windows console or a subprocess may speak (looked up by name)
        for n in ('encodings/mbcs.py', 'encodings/oem.py', 'encodings/cp1250.py',
                  'encodings/cp852.py', 'encodings/idna.py', 'stringprep.py'):
            self.assertTrue(os.path.isfile(os.path.join(base, 'runtime', 'Lib', n)), n)
        # the .pyc beside the sources are this Python's, checked by hash
        pyc = os.path.join(base, 'runtime', 'Lib', '__pycache__', 'ssl.cpython-313.pyc')
        with open(pyc, 'rb') as fh:
            head = fh.read(8)
        import importlib.util as iu
        self.assertEqual(head[:4], iu.MAGIC_NUMBER)
        self.assertEqual(int.from_bytes(head[4:8], 'little'), 0b11)   # hash-based, checked

    def test_custom_actions(self):
        ca = {r['Action']: r for r in table('CustomAction')}
        py = '-I -B "[INSTALLDIR]acme_agent.py" '
        want = {'AgentInstall': (3090, 'windows-install'),
                'AgentInstallJoin': (3090, 'windows-install --join "[JOINCODE]"'),
                'AgentInstallRollback': (3410, 'windows-uninstall'),
                'AgentUninstall': (3154, 'windows-uninstall'),
                'AgentUninstallPurge': (3154, 'windows-uninstall --purge'),
                'AgentUpgradeStop': (3154, 'windows-uninstall --upgrade'),
                'AgentUninstallRollback': (3410, 'windows-install')}
        for k, (typ, cmd) in want.items():
            self.assertEqual(ca[k]['Type'], typ, k)
            self.assertEqual(ca[k]['Source'], 'python_exe')
            self.assertEqual(ca[k]['Target'], py + cmd)
        # 3090 = 18 (an .exe of the File table) + deferred 1024 + no impersonation 2048;
        # +64 = its exit code ignored (an uninstall never fails on it); +256 = rollback
        for t in (3090, 3154, 3410):
            self.assertEqual(t & 0x3f, 18)
            self.assertTrue(t & 1024 and t & 2048)
        seq = {r['Action']: r for r in table('InstallExecuteSequence')}
        n = lambda a: seq[a]['Sequence']                          # noqa: E731
        for a in ('AgentUninstall', 'AgentUninstallPurge', 'AgentUpgradeStop',
                  'AgentUninstallRollback'):
            self.assertTrue(n('InstallInitialize') < n(a) < n('RemoveFiles'), a)
        for a in ('AgentInstall', 'AgentInstallJoin', 'AgentInstallRollback'):
            self.assertTrue(n('InstallFiles') < n(a) < n('InstallFinalize'), a)
        self.assertLess(n('AgentInstallRollback'), n('AgentInstall'))
        self.assertLess(n('AgentUninstallRollback'), n('AgentUninstall'))
        self.assertEqual(seq['AgentInstall']['Condition'], 'NOT REMOVE~="ALL" AND NOT JOINCODE')
        self.assertEqual(seq['AgentInstallJoin']['Condition'], 'NOT REMOVE~="ALL" AND JOINCODE')
        self.assertIn('PURGE="1"', seq['AgentUninstallPurge']['Condition'])
        self.assertIn('PURGE<>"1"', seq['AgentUninstall']['Condition'])
        self.assertIn('NOT UPGRADINGPRODUCTCODE', seq['AgentUninstall']['Condition'])
        self.assertIn('UPGRADINGPRODUCTCODE', seq['AgentUpgradeStop']['Condition'])
        # the major upgrade: older ones found and removed first, a newer one refuses
        self.assertIn('RemoveExistingProducts', seq)
        self.assertIn('FindRelatedProducts', seq)
        up = table('Upgrade')
        self.assertEqual({r['UpgradeCode'] for r in up}, {W.UPGRADE_CODE})
        self.assertEqual(sorted(r['ActionProperty'] for r in up),
                         ['WIX_DOWNGRADE_DETECTED', 'WIX_UPGRADE_DETECTED'])
        self.assertIn('NOT WIX_DOWNGRADE_DETECTED',
                      [r['Condition'] for r in table('LaunchCondition')])

    def test_properties(self):
        p = {r['Property']: r['Value'] for r in table('Property')}
        self.assertIn('JOINCODE', p['SecureCustomProperties'].split(';'))
        self.assertIn('PURGE', p['SecureCustomProperties'].split(';'))
        self.assertEqual(p['MsiHiddenProperties'], 'JOINCODE')
        self.assertNotIn('JOINCODE', p)              # no default: empty means no join
        self.assertEqual(p['ProductCode'], W.product_code(VERSION))
        self.assertEqual(p['ProductCode'], W.product_code(VERSION))   # the version's own
        self.assertNotEqual(W.product_code('9.9.10'), p['ProductCode'])
        self.assertEqual(p['UpgradeCode'], W.UPGRADE_CODE)
        self.assertEqual(p['ProductVersion'], VERSION)
        self.assertEqual(p['ALLUSERS'], '1')
        self.assertEqual(p['ErrorDialog'], 'ErrorDlg')
        self.assertEqual(p['DefaultUIFont'], 'AcmeDefault')
        r = subprocess.run(['msiinfo', 'suminfo', BUILT['facts']['path']], capture_output=True,
                           text=True)
        self.assertIn('Template: x64;1033', r.stdout)

    def test_wizard(self):
        t = W.tables_of(BUILT['facts']['path'])
        self.assertEqual(W.check_ui(t), [])
        dlgs = {r[0] for r in t['Dialog']}
        for d in ('WelcomeDlg', 'JoinDlg', 'ReadyDlg', 'ProgressDlg', 'ExitDlg', 'UserExitDlg',
                  'FatalErrorDlg', 'CancelDlg', 'ErrorDlg', 'MaintenanceDlg', 'RemoveDlg',
                  'InvalidCodeDlg'):
            self.assertIn(d, dlgs)
        edit = [r for r in t['Control'] if r[0] == 'JoinDlg' and r[2] == 'Edit']
        self.assertEqual(edit[0][8], 'JOINCODE')
        texts = ' '.join(str(r[9]) for r in t['Control'])
        for words in ('ACAG1', 'ACAE1', 'acme-agent join CODE', 'acme-agent status',
                      'acme-agent policy show', 'Nothing is allowed until the policy says so'):
            self.assertIn(words, texts)
        seq = {r[0]: r for r in t['InstallUISequence']}
        self.assertEqual(seq['WelcomeDlg'][1], 'NOT Installed')
        self.assertEqual(seq['ExitDlg'][2], -1)
        ev = [r for r in table('ControlEvent') if r['Dialog_'] == 'JoinDlg' and
              r['Control_'] == 'Next']
        self.assertEqual({e['Argument'] for e in ev}, {'ReadyDlg', 'InvalidCodeDlg'})
        self.assertEqual(len(table('Binary')), 2)
        em = {(r['Control_'], r['Event']) for r in table('EventMapping')}
        self.assertEqual(em, {('ActionText', 'ActionText'), ('ProgressBar', 'SetProgress')})

    def test_checker_finds_faults(self):
        good = W.ui_tables(VERSION)
        good['Property'] = [('DefaultUIFont', 'AcmeDefault'), ('ErrorDialog', 'ErrorDlg')]
        self.assertEqual(W.check_ui(good), [])

        def broken(fn):
            t = {k: list(v) for k, v in good.items()}
            fn(t)
            return ' | '.join(W.check_ui(t))
        self.assertIn('no such dialog', broken(lambda t: t['ControlEvent'].append(
            ('JoinDlg', 'Next', 'NewDialog', 'NoSuchDlg', '1', 9))))
        self.assertIn('no such control', broken(lambda t: t['ControlEvent'].append(
            ('JoinDlg', 'Nope', 'EndDialog', 'Return', '1', 9))))
        self.assertIn('no dialog', broken(lambda t: t['Control'].append(
            ('GoneDlg', 'X', 'Text', 0, 0, 10, 10, 1, None, 'x', None, None))))
        self.assertIn('Control_First', broken(lambda t: t['Dialog'].__setitem__(
            0, t['Dialog'][0][:7] + ('Nope',) + t['Dialog'][0][8:])))

        def bad_next(t):
            i = [k for k, r in enumerate(t['Control']) if r[:2] == ('JoinDlg', 'Back')][0]
            r = t['Control'][i]
            t['Control'][i] = r[:10] + ('Gone',) + r[11:]
        self.assertIn('Control_Next Gone', broken(bad_next))

        def bad_back(t):
            t['ControlEvent'] = [e for e in t['ControlEvent']
                                 if not (e[0] == 'ReadyDlg' and e[1] == 'Back')]
            t['ControlEvent'].append(('ReadyDlg', 'Back', 'NewDialog', 'WelcomeDlg', '1', 1))
        self.assertIn('whose Back goes to', broken(bad_back))
        self.assertIn('first dialog', broken(lambda t: t.__setitem__(
            'InstallUISequence', [r for r in t['InstallUISequence'] if r[0] != 'WelcomeDlg'])))
        self.assertIn('ErrorDialog', broken(lambda t: t.__setitem__(
            'Property', [('DefaultUIFont', 'AcmeDefault'), ('ErrorDialog', 'Nope')])))
        self.assertIn('TextStyle', broken(lambda t: t['Control'].append(
            ('JoinDlg', 'X', 'Text', 0, 0, 10, 10, 1, None, '{\\Nope}x', None, None))))

    def test_manifest_signed(self):
        base = BUILT['files']
        with open(os.path.join(base, 'MANIFEST'), 'rb') as fh:
            man = fh.read()
        got = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey',
                              os.path.join(BUILT['keys'], 'test-1.pub'), '-rawin', '-in',
                              os.path.join(base, 'MANIFEST'), '-sigfile',
                              os.path.join(base, 'MANIFEST.sig')], capture_output=True)
        self.assertEqual(got.returncode, 0, got.stderr)
        listed = {}
        for line in man.decode().splitlines():
            m = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line)
            self.assertTrue(m, line)
            listed[m.group(2)] = m.group(1)
        on_disk = set()
        for top, _d, fs in os.walk(base):
            for n in fs:
                rel = os.path.relpath(os.path.join(top, n), base).replace(os.sep, '/')
                on_disk.add(rel)
                if rel in ('MANIFEST', 'MANIFEST.sig'):
                    continue
                with open(os.path.join(top, n), 'rb') as fh:
                    self.assertEqual(listed.get(rel), hashlib.sha256(fh.read()).hexdigest(), rel)
        self.assertEqual(set(listed), on_disk - {'MANIFEST', 'MANIFEST.sig'})
        for n in W.agent_files() + ('release', 'release-keys/test-1.pub', 'acme-agent.cmd',
                                    'runtime/python.exe', 'openssl/openssl.exe'):
            self.assertIn(n, listed)
        with open(os.path.join(base, 'release')) as fh:
            self.assertEqual(fh.read(), VERSION + '\n')
        # the agent's own check (its release keys beside it, Ed25519) takes the same signature
        AG = load('acme_agent_winpkg', os.path.join(base, 'acme_agent.py'))
        with open(os.path.join(base, 'MANIFEST.sig'), 'rb') as fh:
            sig = fh.read()
        keys = AG.release_keys()
        self.assertIn('test-1', ''.join(keys))
        self.assertTrue(any(AG.ed25519_verify(k, man, sig) for k in keys.values()))
        self.assertFalse(any(AG.ed25519_verify(k, man + b' ', sig) for k in keys.values()))

    def test_unsigned_without_key(self):
        f = W.build_msi(os.path.join(TMP, 'out2'), VERSION, key=None, keys_dir=BUILT['keys'],
                        agent_dir=BUILT['agent'], download=False)
        self.assertFalse(f['signed'])
        names = {r['FileName'] for r in W.read_table(f['path'], 'File')}
        self.assertIn('MANIFEST', names)
        self.assertNotIn('MANIFEST.sig', names)


@unittest.skipIf(WHY, 'the Windows package cannot be built here: %s' % WHY)
class Release(unittest.TestCase):
    def test_release_carries_it(self):
        """tools/release.py: the MSI inside acme's package (deploy/agent/) and beside it in
        release/, in MANIFEST, in index.json; pruned like the others."""
        import tarfile
        R = load('release_winpkg', os.path.join(ROOT, 'tools', 'release.py'))
        d = tempfile.mkdtemp(dir=TMP)
        R.RELEASE_DIR = os.path.join(d, 'release')
        R.KEYS_DIR = BUILT['keys']
        os.makedirs(R.RELEASE_DIR)
        ver = R.read_version()
        R.checks_before = lambda version, files: True
        Wm = load('agent_windows_rel', os.path.join(ROOT, 'tools', 'agent_windows.py'))
        Wm.AGENT_DIR = BUILT['agent']
        R.agent_windows = lambda: Wm
        built, why = R.build(ver, BUILT['key'], force=True, epoch=1700000000)
        self.assertTrue(built, why)
        msi = 'acme-agent-%s-windows-x64.msi' % ver
        side = os.path.join(R.RELEASE_DIR, msi)
        self.assertTrue(os.path.exists(side))
        with tarfile.open(built['path']) as tar:
            man = tar.extractfile('acme-%s/MANIFEST' % ver).read().decode()
            inner = tar.extractfile('acme-%s/deploy/agent/%s' % (ver, msi)).read()
        self.assertIn('%s  deploy/agent/%s' % (hashlib.sha256(inner).hexdigest(), msi), man)
        with open(side, 'rb') as fh:
            self.assertEqual(inner, fh.read())
        rows = R.write_index(R.RELEASE_DIR, base='https://example.test/r/')
        aw = rows[0]['agent_windows']
        self.assertEqual(aw['name'], msi)
        self.assertEqual(aw['sha256'], hashlib.sha256(inner).hexdigest())
        self.assertEqual(aw['product_code'], W.product_code(ver))
        self.assertEqual(aw['download_url'], 'https://example.test/r/' + msi)
        # only the last ten
        for v in range(1, 13):
            open(os.path.join(R.RELEASE_DIR, 'acme-agent-0.0.%d-windows-x64.msi' % v), 'w').close()
        gone = R.prune(R.RELEASE_DIR, keep=10)
        self.assertIn('acme-agent-0.0.1-windows-x64.msi', gone)
        self.assertIn('acme-agent-0.0.2-windows-x64.msi', gone)
        self.assertTrue(os.path.exists(side))
        # a source tree's copy is never packed as a file of the tree
        self.assertTrue(R.AGENT_PKG_RE.match('deploy/agent/%s' % msi))

    def test_release_stops_without_it(self):
        R = load('release_winpkg2', os.path.join(ROOT, 'tools', 'release.py'))
        d = tempfile.mkdtemp(dir=TMP)
        R.RELEASE_DIR = os.path.join(d, 'release')
        R.KEYS_DIR = BUILT['keys']
        R.checks_before = lambda version, files: True
        Wm = load('agent_windows_rel2', os.path.join(ROOT, 'tools', 'agent_windows.py'))
        Wm.cache_dir = lambda: os.path.join(d, 'empty-cache')
        Wm._download = lambda url, dest: (_ for _ in ()).throw(OSError('no network'))
        R.agent_windows = lambda: Wm
        built, why = R.build(R.read_version(), BUILT['key'], force=True, epoch=1700000000)
        self.assertIsNone(built)
        self.assertIn('Windows agent', why)
        self.assertFalse(os.listdir(R.RELEASE_DIR) if os.path.isdir(R.RELEASE_DIR) else [])
        Wm2 = load('agent_windows_rel3', os.path.join(ROOT, 'tools', 'agent_windows.py'))
        Wm2.missing_tools = lambda: ['wixl']
        R.agent_windows = lambda: Wm2
        built, why = R.build(R.read_version(), BUILT['key'], force=True, epoch=1700000000)
        self.assertIsNone(built)
        self.assertIn('wixl', why)


class Api(unittest.TestCase):
    """acme hands it out: package.windows, GET /api/agents/package?platform=windows."""
    @classmethod
    def setUpClass(cls):
        import acme  # noqa: F401
        import acmelib
        import acmelib.engine as E
        from acmelib.certs import api as A, store as S, agents as G  # noqa: F401
        cls.E, cls.G, cls.ver = E, G, acmelib.__version__
        cls.store = E.Storage(E.open_db())
        E.sealing_key(make=True)
        S.registry()
        cls.dir = tempfile.mkdtemp(dir=TMP)
        cls.was = G.AGENT_DIR

    @classmethod
    def tearDownClass(cls):
        cls.G.AGENT_DIR = cls.was

    def call(self, path, role='certadmin', args=None):
        E = self.E

        class H(object):
            store = self.store

            def me(self, level='readonly'):
                return {'role': role, 'name': 'w-' + role}

            def body(self):
                return {}

            def arg(self, k, default=None):
                return (args or {}).get(k, default)
        return E.ROUTES[('GET', path)](H())

    def test_none_in_a_source_tree(self):
        G = self.G
        G.AGENT_DIR = os.path.join(self.dir, 'empty')
        os.makedirs(G.AGENT_DIR, exist_ok=True)
        shutil.copyfile(os.path.join(self.was, 'acme_agent.py'),
                        os.path.join(G.AGENT_DIR, 'acme_agent.py'))
        win, why = G.package_windows()
        self.assertIsNone(win)
        self.assertIn('comes with a release', why)
        with self.assertRaises(self.E.ApiError) as e:
            self.call('/api/agents/package', args={'platform': 'windows'})
        self.assertEqual(e.exception.status, 404)
        self.assertIn('comes with a release', str(e.exception))

    def test_facts_and_download(self):
        G = self.G
        G.AGENT_DIR = os.path.join(self.dir, 'rel')
        shutil.copytree(self.was, G.AGENT_DIR, ignore=shutil.ignore_patterns(
            '__pycache__', '*.msi', '*.tar.gz'))
        name = 'acme-agent-%s-windows-x64.msi' % self.ver
        src = BUILT.get('facts', {}).get('path')
        data = open(src, 'rb').read() if src else b'\xd0\xcf\x11\xe0 a stand-in MSI'
        with open(os.path.join(G.AGENT_DIR, name), 'wb') as fh:
            fh.write(data)
        # an older version's MSI is not this acme's
        with open(os.path.join(G.AGENT_DIR, 'acme-agent-0.0.1-windows-x64.msi'), 'wb') as fh:
            fh.write(b'old')
        win, why = G.package_windows()
        self.assertIsNone(why)
        self.assertEqual(win['name'], name)
        self.assertEqual(win['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(win['size'], len(data))
        self.assertTrue(win['signed'])
        self.assertEqual(win['product_code'], W.product_code(self.ver))
        got = self.call('/api/agents/package', args={'platform': 'windows'})
        import base64
        self.assertEqual(base64.b64decode(got['data_b64']), data)
        self.assertEqual(got['filename'], name)
        self.assertEqual(got['mime'], 'application/x-msi')
        self.assertEqual(got['product_code'], win['product_code'])
        # the Linux package as before, with the Windows facts beside it
        lin = self.call('/api/agents/package')
        self.assertTrue(lin['name'].endswith('.tar.gz'))
        self.assertEqual(lin['windows']['sha256'], win['sha256'])
        allp = self.call('/api/agents', role='readonly')
        self.assertEqual(allp['package']['windows']['name'], name)
        self.assertNotIn('path', allp['package']['windows'])
        self.assertIn('msiexec /i %s /qn JOINCODE=CODE' % name, allp['windows_commands'])
        # a read-only administrator does not download it
        with self.assertRaises(self.E.ApiError) as e:
            self.call('/api/agents/package', role='readonly', args={'platform': 'windows'})
        self.assertEqual(e.exception.status, 403)


if __name__ == '__main__':
    unittest.main(verbosity=2)
