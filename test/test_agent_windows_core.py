#!/usr/bin/env python3
"""acme-agent on Windows, its platform core (1.0.120, docs/target-agent.md "Windows") - on Linux,
with ACME_AGENT_FAKE_WINDOWS=1: deploy/agent/acme_agent_win.py's FakeWin maps C:\\... into a
temporary folder and keeps ACLs, services, the event log, the registry and the firewall as JSON;
the named pipe is a Unix socket whose client's account is its ACME_AGENT_FAKE_SID.

    python3 test/test_agent_windows_core.py

What is tried: the service SID (NT SERVICE\\TrustedInstaller's known one); Windows paths and
their refusals (UNC, \\\\?\\, alternate data streams, .., device and short names, reparse points,
protected places, executable extensions, a drive's root); the policy's Windows words, lines and
hash - and a Linux policy's hash and lines the same as acme_agent.py made them before the
Windows agent (git); a
policy or agent.json others may change not believed; a whole round trip - the root side and the
network side as services of the fake, a signed job over TLS to the passive port, through the pipe
to root: hello (platform windows), a deployment writing files with a readers= ACL, a service
restarted, a PowerShell script from root's copy, a failing test putting files and ACLs back, a
refused account at the pipe; the CLI (allow, deny, policy apply, status, a prompt not elevated);
windows-install and windows-uninstall (--upgrade, --purge).

Needs openssl and the `cryptography` module (for the test's own Ed25519 signatures).
"""
import base64
import importlib.util
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import time
import unittest
import http.client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AGENT = os.path.join(ROOT, 'deploy', 'agent', 'acme_agent.py')
TMP = tempfile.mkdtemp(prefix='acme-win-')
FAKE = os.path.join(TMP, 'fake')
os.makedirs(FAKE)
for k in ('ACME_AGENT_ETC', 'ACME_AGENT_STATE', 'ACME_AGENT_ROOT_STATE', 'ACME_AGENT_RUN',
          'ACME_AGENT_FAKE_SID', 'ACME_AGENT_FAKE_ELEVATED', 'ACME_AGENT_NO_SYSTEMD'):
    os.environ.pop(k, None)
os.environ.update(ACME_AGENT_FAKE_WINDOWS='1', ACME_AGENT_FAKE_ROOT=FAKE)

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:                                     # pragma: no cover
    ed25519 = None


def load(path=AGENT, name='acme_agent_wt', fake=True):
    old = os.environ.pop('ACME_AGENT_FAKE_WINDOWS', None)
    if fake:
        os.environ['ACME_AGENT_FAKE_WINDOWS'] = '1'
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    finally:
        if old is not None:
            os.environ['ACME_AGENT_FAKE_WINDOWS'] = old


AG = load()
W = AG.W
SVC_SID = AG.WIN['service_sid']('acme-agent')


def cli(*args, ok=True, **env):
    e = dict(os.environ)
    e.update(env)
    got = subprocess.run([sys.executable, '-I', '-B', AGENT] + list(args), env=e,
                         capture_output=True, text=True, timeout=120)
    if ok and got.returncode != 0:
        raise AssertionError('acme-agent %s: %s %s' % (args, got.stdout, got.stderr))
    return got


def local(p):
    return W.local(p)


def put(p, text, mode=0o644):
    lp = local(p)
    os.makedirs(os.path.dirname(lp), exist_ok=True)
    with open(lp, 'w') as fh:
        fh.write(text)
    os.chmod(lp, mode)


def read(p, mode='r'):
    with open(p, mode) as fh:
        return fh.read()


def openssl(*args, data=None):
    return subprocess.run(['openssl'] + list(args), input=data, capture_output=True,
                          check=True).stdout


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def setUpModule():
    cli('windows-install')


def tearDownModule():
    for p in list(Sides.PROCS):
        if p.poll() is None:
            p.kill()
    shutil.rmtree(TMP, ignore_errors=True)


def before_windows():
    """acme_agent.py as it was before the Windows agent (its newest commit without the platform
    hook), or None."""
    got = subprocess.run(['git', '-C', ROOT, 'log', '--format=%H', '-n', '40', '--',
                          'deploy/agent/acme_agent.py'], capture_output=True, text=True)
    for h in got.stdout.split():
        one = subprocess.run(['git', '-C', ROOT, 'show', '%s:deploy/agent/acme_agent.py' % h],
                             capture_output=True)
        if one.returncode == 0 and b'acme_agent_win' not in one.stdout:
            return one.stdout
    return None


# ---------------------------------------------------------------------------------------------
class ServiceSid(unittest.TestCase):
    def test_known_values(self):
        sid = AG.WIN['service_sid']
        self.assertEqual(sid('TrustedInstaller'),
                         'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        self.assertEqual(sid('trustedinstaller'), sid('TRUSTEDINSTALLER'))
        self.assertEqual(W.lookup_sid('NT SERVICE\\acme-agent'), SVC_SID)
        self.assertEqual(W.lookup_sid('IIS_IUSRS'), 'S-1-5-32-568')
        self.assertTrue(SVC_SID.startswith('S-1-5-80-'))


class Paths(unittest.TestCase):
    def refused(self, p, words):
        with self.assertRaises(AG.Refused) as c:
            AG.norm_dir(p, real=False)
        self.assertIn(words, str(c.exception))

    def test_normalised_and_refused(self):
        self.assertEqual(AG.norm_dir('c:/certs//www/', real=False), 'C:\\certs\\www')
        self.assertEqual(AG.norm_dir('D:\\a\\.\\b', real=False), 'D:\\a\\b')
        self.refused('\\\\server\\share\\x', 'UNC')
        self.refused('\\\\?\\C:\\x', 'UNC')
        self.refused('\\\\.\\pipe\\x', 'UNC')
        self.refused('//server/share', 'UNC')
        self.refused('C:\\certs\\www.pem:evil', 'alternate data stream')
        self.refused('C:\\certs\\..\\Windows', '..')
        self.refused('certs\\x', 'not an absolute path')
        self.refused('C:certs', 'not an absolute path')
        self.refused('/etc/ssl', 'not an absolute path')
        self.refused('C:\\certs\\NUL', 'device name')
        self.refused('C:\\certs\\com1.pem', 'device name')
        self.refused('C:\\PROGRA~1\\x', 'short (8.3)')
        self.refused('C:\\Windows.\\x', 'dot or a space')
        self.refused('C:\\a<b', 'character')

    def test_protected(self):
        P = AG.protected
        for p in ('C:\\Windows\\System32\\x.pem', 'c:\\program files\\nginx\\x.pem',
                  'C:\\Program Files (x86)\\x\\y.pem', 'C:\\ProgramData\\Microsoft\\x.pem',
                  'C:\\ProgramData\\ssh\\administrators_authorized_keys',
                  'C:\\Users\\bob\\AppData\\Roaming\\x.pem', 'D:\\$Recycle.Bin\\x',
                  'E:\\System Volume Information\\x', 'C:\\ProgramData\\acme-agent\\etc\\policy',
                  'C:\\ProgramData\\ACME-AGENT\\net\\tls.key', 'C:\\srv\\.ssh\\keys',
                  'C:\\Boot\\x', 'C:\\'):
            self.assertTrue(P(p), p)
        for ext in ('exe', 'DLL', 'ps1', 'bat', 'cmd', 'lnk', 'pth', 'msi', 'reg', 'js'):
            self.assertIn('never writes one', P('C:\\certs\\x.' + ext))
        for p in ('C:\\certs\\www.pem', 'C:\\Users\\bob\\certs\\x.pfx', 'D:\\nginx\\ssl\\a.crt',
                  'C:\\ProgramData\\certs\\a.key'):
            self.assertEqual(P(p), '', p)

    def test_reparse_points_refused(self):
        os.makedirs(local('C:\\real\\ssl'), exist_ok=True)
        os.makedirs(local('C:\\links'), exist_ok=True)
        lk = os.path.join(local('C:\\links'), 'via')
        if not os.path.lexists(lk):
            os.symlink(local('C:\\real'), lk)
        with self.assertRaises(AG.Refused) as c:
            AG.open_dir('C:\\links\\via\\ssl')
        self.assertIn('reparse point', str(c.exception))
        d = AG.open_dir('C:\\real\\ssl')
        AG.dir_close(d)
        with self.assertRaises(AG.Refused) as c:
            AG.open_dir('C:\\real\\nothere')
        self.assertIn('not there', str(c.exception))
        # a link to a file is no plain file
        os.symlink(local('C:\\real\\ssl'), os.path.join(local('C:\\real\\ssl'), 'x.pem'))
        d = AG.open_dir('C:\\real\\ssl')
        try:
            with self.assertRaises(AG.Refused):
                AG.read_at(d, 'x.pem', 1000)
        finally:
            AG.dir_close(d)
        self.assertEqual(AG.norm_dir('C:\\links\\via\\ssl'), 'C:\\real\\ssl')


class Policy(unittest.TestCase):
    TEXT = ('allow file C:/certs readers=IIS_IUSRS,"NT SERVICE\\W3SVC"\n'
            'allow file "D:\\web site\\ssl"\n'
            'allow service W3SVC restart,try-restart\n'
            'allow unit nginx start\n'
            'allow test -- "C:\\Program Files\\nginx\\nginx.exe" -t\n'
            'allow script C:\\scripts\\after.ps1 sha256=' + 'ab' * 32 + '\n'
            'allow script-hash ' + 'cd' * 32 + '\n'
            'allow store\nallow iis "Default Web Site"\nallow iis *\nallow rdp\n'
            'allow from 192.0.2.0/24\nallow self-update\nlimit files 5\n')

    def test_parse_lines_hash(self):
        pol = AG.parse_policy(self.TEXT)
        self.assertEqual(pol['problems'], [])
        self.assertEqual(pol['files'][0]['dir'], 'C:\\certs')
        self.assertEqual(pol['files'][0]['readers'], ['IIS_IUSRS', 'NT SERVICE\\W3SVC'])
        self.assertEqual(pol['files'][1]['dir'], 'D:\\web site\\ssl')
        self.assertEqual(pol['units'], {'w3svc': ['restart', 'try-restart'], 'nginx': ['start']})
        self.assertEqual(pol['tests'], [['C:\\Program Files\\nginx\\nginx.exe', '-t']])
        self.assertTrue(pol['store'] and pol['rdp'])
        self.assertEqual(pol['iis'], ['Default Web Site', '*'])
        lines = AG.policy_lines(pol)
        self.assertIn('allow file C:\\certs readers="IIS_IUSRS,NT SERVICE\\W3SVC"', lines)
        self.assertIn('allow file "D:\\web site\\ssl"', lines)
        self.assertIn('allow service w3svc restart,try-restart', lines)
        self.assertIn('allow iis "Default Web Site"', lines)
        self.assertIn('allow store', lines)
        self.assertIn('allow rdp', lines)
        # the lines read back are the same policy, the same hash
        again = AG.parse_policy('\n'.join(lines))
        self.assertEqual(AG.policy_canon(again), AG.policy_canon(pol))
        rep = AG.policy_report(pol, 'h')
        self.assertEqual(rep['iis'], ['Default Web Site', '*'])
        self.assertTrue(rep['store'])

    def test_refused_words(self):
        for line, words in (('allow file C:\\certs owner=root:root', 'not for Windows'),
                            ('allow file C:\\certs mode=0640', 'not for Windows'),
                            ('allow file C:\\', 'drive\'s root'),
                            ('allow file \\\\srv\\share', 'UNC'),
                            ('allow service W3SVC reload', 'the verbs are'),
                            ('allow test -- C:\\x\\deploy.bat', 'batch file'),
                            ('allow test -- C:\\x\\deploy.CMD a', 'batch file'),
                            ('allow script C:\\x.exe sha256=' + 'ab' * 32, 'PowerShell'),
                            ('allow store now', 'allow store'),
                            ('allow iis', 'allow iis SITE'),
                            ('allow file C:\\certs readers=a=b', 'readers=')):
            pol = AG.parse_policy(line)
            self.assertTrue(pol['problems'], line)
            self.assertIn(words, pol['problems'][0], line)

    def test_linux_unchanged(self):
        """A Linux policy: the lines and the hash acme_agent.py made before Windows (git), and
        no Windows key in it (a policy of before keeps its hash)."""
        lin = load(name='acme_agent_lin', fake=False)
        self.assertEqual(lin.PLATFORM, 'linux')
        text = ('allow file /etc/nginx/ssl owner=root:nginx mode=0640\nallow unit nginx reload\n'
                'allow test -- /usr/sbin/nginx -t\nallow from 10.0.0.0/8\nallow probe local\n'
                'allow self-update\nallow store\nlimit size 2048\n')
        pol = lin.parse_policy(text)
        self.assertNotIn('store', pol)
        self.assertTrue(pol['problems'])                # allow store: not a Linux word
        head = before_windows()
        if head is None:
            self.skipTest('no git history of acme_agent.py before the Windows agent')
        old_path = os.path.join(TMP, 'acme_agent_head.py')
        with open(old_path, 'wb') as fh:
            fh.write(head)
        old = load(old_path, 'acme_agent_head', fake=False)
        opol = old.parse_policy(text)
        self.assertEqual(lin.policy_lines(pol), old.policy_lines(opol))
        self.assertEqual(lin.policy_canon(pol), old.policy_canon(opol))
        self.assertEqual(lin.policy_report(pol, 'h'), old.policy_report(opol, 'h'))
        self.assertEqual(lin._sha(lin.policy_canon(pol)), old._sha(old.policy_canon(opol)))
        plan_args = {'files': [{'path': '/etc/nginx/ssl/a.pem', 'mode': 0o640,
                                'owner': 'root:nginx'}], 'reload': [{'unit': 'nginx.service',
                                                                      'verb': 'restart'}]}
        for m, p in ((lin, pol), (old, opol)):
            with self.assertRaises(m.Refused) as c:
                m.plan_check(p, plan_args)
            self.assertIn('acme-agent allow unit nginx.service restart',
                          [n['allow'] for n in c.exception.needs])

    def test_facts_and_check(self):
        f = AG.policy_facts()
        self.assertEqual(f['platform'], 'windows')
        self.assertEqual(f['verbs'], ['restart', 'try-restart', 'start'])
        self.assertIn('.exe', f['exec_ext'])
        self.assertIn('cmd', f['shells'])
        got = AG.policy_check('allow file C:\\Windows\\certs\nallow file C:\\Users\n'
                              'allow test -- cmd /c echo\nallow test -- powershell -Command x\n'
                              'allow file C:\\certs\nallow file c:\\CERTS\n')
        codes = sorted(x['code'] for x in got['errors'] + got['warnings'])
        self.assertEqual(codes, ['above-protected', 'protected', 'shell', 'shell', 'twice'])

    def test_plan_needs_in_windows_words(self):
        pol = AG.parse_policy('allow file C:\\certs\n')
        with self.assertRaises(AG.Refused) as c:
            AG.plan_check(pol, {'files': [{'path': 'C:\\other\\a.pem', 'data': ''}],
                                'reload': [{'unit': 'W3SVC', 'verb': 'restart'}],
                                'test': [{'argv': ['C:\\Program Files\\x\\check.exe', '-t']}]})
        allows = [n['allow'] for n in c.exception.needs]
        self.assertIn('acme-agent allow file C:\\other', allows)
        self.assertIn('acme-agent allow service w3svc restart', allows)
        self.assertIn('acme-agent allow test -- "C:\\Program Files\\x\\check.exe" -t', allows)
        for bad in ('C:\\certs\\run.exe', 'C:\\certs\\x.ps1', 'C:\\Windows\\a.pem'):
            with self.assertRaises(AG.Refused):
                AG.plan_check(pol, {'files': [{'path': bad, 'data': ''}]})


class Trusted(unittest.TestCase):
    def test_only_the_administrators(self):
        d = 'C:\\trust'
        os.makedirs(local(d), exist_ok=True)
        put(d + '\\p', 'allow store\n')
        path = local(d + '\\p')
        text, problem = AG.trusted_text(path, 'x')
        self.assertEqual((text, problem), ('allow store\n', ''))
        W.set_sd(d + '\\p', 'O:BAD:(A;;FW;;;BU)')          # Users may write it
        text, problem = AG.trusted_text(path, 'x')
        self.assertIsNone(text)
        self.assertIn(AG.WIN['USERS'], problem)
        W.set_sd(d + '\\p', 'O:BUD:P(A;;FA;;;SY)')          # owned by Users
        self.assertIn('its owner', AG.trusted_text(path, 'x')[1])
        W.set_sd(d + '\\p', 'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)')
        self.assertEqual(AG.trusted_text(path, 'x')[1], '')
        W.set_sd(d, 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)')   # its folder: Everyone writes
        self.assertIn('the folder of', AG.trusted_text(path, 'x')[1])
        W.set_sd(d, 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-80-956008885-'
                    '3418522649-1831038044-1853292631-2271478464)')
        self.assertEqual(AG.trusted_text(path, 'x')[1], '')
        os.symlink(path, local(d) + '/l')
        self.assertIn('symbolic link', AG.trusted_text(local(d) + '/l', 'x')[1])

    def test_every_ace_counts(self):
        """A conditional (callback) ACE - its condition in parentheses - and an ACE not read
        are writers too; no owner is no trust."""
        sd_problem, parse = AG.WIN['sd_problem'], AG.WIN['parse_sddl']
        ok = 'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'
        self.assertEqual(sd_problem(parse(ok)), '')
        cond = ok + '(XA;;FA;;;WD;(Member_of {SID(BA)}))'
        self.assertEqual(len(parse(cond)['aces']), 4)
        self.assertIn('S-1-1-0', sd_problem(parse(cond)))
        self.assertIn('S-1-1-0', sd_problem(parse(ok + '(A;;FA;;)')))
        self.assertIn('S-1-1-0', sd_problem(parse(ok + '(OA;;FA;;;WD)')))
        self.assertIn('owner', sd_problem(parse(ok[len('O:SY'):])))
        self.assertTrue(AG.WIN['pipe_sddl']().startswith('O:SYD:P'))

    def test_a_folder_made_before_the_install_is_refused(self):
        place = AG.WIN['_place_check']
        d = 'C:\\squat'
        os.makedirs(local(d), exist_ok=True)
        place(local(d))                                 # SYSTEM's (the fake's default)
        W.set_sd(d, 'O:BUD:(A;OICI;FA;;;BU)')           # an account's own
        with self.assertRaises(SystemExit):
            place(local(d))
        os.symlink(local(d), local('C:\\squat2'))
        with self.assertRaises(SystemExit):
            place(local('C:\\squat2'))
        place(local('C:\\not-there'))

    def test_the_policy_others_may_change_allows_nothing(self):
        cli('allow', 'store')
        AG_ = load(name='acme_agent_t2')
        pol, _h, _t = AG_.policy_load()
        self.assertTrue(pol.get('store'))
        W.set_sd('C:\\ProgramData\\acme-agent\\etc\\policy', 'O:BAD:(A;;FA;;;AU)')
        pol, _h, _t = AG_.policy_load()
        self.assertFalse(pol.get('store'))
        self.assertTrue(pol['problems'])
        cli('init')                                    # written again: its folder's ACL
        pol, _h, _t = AG_.policy_load()
        self.assertTrue(pol.get('store'))
        self.assertEqual(pol['problems'], [])
        cli('deny', 'store')


# ---- the two sides, a signed job over TLS, the pipe, root -------------------------------------
class Sides(unittest.TestCase):
    PROCS = []

    @classmethod
    def setUpClass(cls):
        if ed25519 is None:
            raise unittest.SkipTest('the cryptography module is not here')
        cli('windows-install')
        j = lambda n: os.path.join(TMP, n)  # noqa: E731
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', j('ca.key'), '-out', j('ca.crt'), '-days', '30', '-subj', '/CN=Test CA')
        cls.aid = 'ag-0123456789abcdef'
        for leaf, cn in (('agent', 'acme-agent:' + cls.aid), ('ctl', 'acme-agents')):
            openssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                    '-keyout', j(leaf + '.key'), '-out', j(leaf + '.csr'), '-subj', '/CN=' + cn)
            openssl('x509', '-req', '-in', j(leaf + '.csr'), '-CA', j('ca.crt'), '-CAkey',
                    j('ca.key'), '-CAcreateserial', '-days', '10', '-out', j(leaf + '.crt'))
        cls.key = ed25519.Ed25519PrivateKey.generate()
        pub = cls.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
        cls.port = free_port()
        etc, net = AG.ETC, AG.STATE
        shutil.copy(j('ca.crt'), os.path.join(etc, 'ca.pem'))
        shutil.copy(j('agent.key'), os.path.join(net, 'tls.key'))
        shutil.copy(j('agent.crt'), os.path.join(net, 'tls.crt'))
        with open(os.path.join(etc, 'agent.json'), 'w') as fh:
            json.dump({'agent_id': cls.aid, 'joined': True, 'mode': 'passive',
                       'port': cls.port, 'listen': '127.0.0.1', 'cmd_pub':
                       base64.b64encode(pub).decode(), 'acme': []}, fh)
        # the machine: a service, a broken one, programs, PowerShell (a stub running sh)
        for name, broken in (('WAS', False), ('W3SVC', False), ('Broken', True),
                             ('Ftpsvc', False)):
            W.service_install({'name': name, 'display': name,
                               'depends': {'W3SVC': ['WAS'], 'Ftpsvc': ['W3SVC']}.get(name, [])})
            W._update('services.json', {}, lambda s, n=name, b=broken: s[n.lower()].update(
                state='Running', broken=b))
        put('C:\\tools\\ok.exe', '#!/bin/sh\nexit 0\n', 0o755)
        put('C:\\tools\\fail.exe', '#!/bin/sh\necho it failed\nexit 3\n', 0o755)
        put(W.powershell(), '#!/bin/sh\necho "$@" > %s\nwhile [ "$1" != "-File" ]; do shift; '
            'done\nshift\nf="$1"; shift\nexec sh "$f" "$@"\n' % j('ps.args'), 0o755)
        put('C:\\scripts\\after.ps1', 'echo "after $1" > %s\n' % j('after.out'))
        os.makedirs(local('C:\\certs'), exist_ok=True)
        h = AG._sha(read(local('C:\\scripts\\after.ps1'), 'rb'))
        for words in (['file', 'C:\\certs', '--readers', 'IIS_IUSRS'],
                      ['service', 'W3SVC', 'restart'], ['service', 'Broken', 'restart'],
                      ['service', 'WAS', 'restart,try-restart'],
                      ['test', '--', 'C:\\tools\\ok.exe'], ['test', '--', 'C:\\tools\\fail.exe'],
                      ['script', 'C:\\scripts\\after.ps1'], ['from', '127.0.0.1']):
            cli('allow', *words)
        cls.script_hash = h
        cls.root = cls.start('root', ACME_AGENT_FAKE_SID=AG.WIN['SYSTEM'])
        cls.wait(lambda: os.path.exists(W._pipe_path(AG.WIN['PIPE'])))
        cls.net = cls.start('serve', ACME_AGENT_FAKE_SID=SVC_SID, ACME_AGENT_FAKE_ELEVATED='0')
        cls.wait(cls.listening)

    @classmethod
    def tearDownClass(cls):
        for p in (getattr(cls, 'net', None), getattr(cls, 'root', None)):
            if p is not None and p.poll() is None:
                p.kill()

    @classmethod
    def start(cls, which, **env):
        e = dict(os.environ)
        e.update(env)
        p = subprocess.Popen([sys.executable, '-I', '-B', AGENT, 'winservice', which], env=e,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        cls.PROCS.append(p)
        return p

    @classmethod
    def wait(cls, cond, most=20):
        end = time.time() + most
        while time.time() < end:
            if cond():
                return
            time.sleep(0.1)
        raise AssertionError('not ready: %s / %s' % (
            cls.root.stderr.read1(4000) if cls.root.poll() is not None else '',
            cls.net.stderr.read1(4000) if getattr(cls, 'net', None) and
            cls.net.poll() is not None else ''))

    @classmethod
    def listening(cls):
        try:
            socket.create_connection(('127.0.0.1', cls.port), 1).close()
            return True
        except OSError:
            return False

    def job(self, op, args=None):
        text = json.dumps({'v': 1, 'agent': self.aid, 'ts': time.time(), 'op': op,
                           'nonce': os.urandom(16).hex(), 'job': os.urandom(8).hex(),
                           'args': args or {}})
        sig = self.key.sign(b'acme-agent/1 job\n' + text.encode())
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(os.path.join(TMP, 'ctl.crt'), os.path.join(TMP, 'ctl.key'))
        c = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=60)
        try:
            body = json.dumps({'job': text, 'sig': base64.b64encode(sig).decode()})
            c.request('POST', '/v1/job', body=body, headers={'Content-Type': 'application/json'})
            return json.loads(c.getresponse().read())
        finally:
            c.close()

    def deploy(self, data, **more):
        args = {'files': [{'path': 'C:\\certs\\www.pem',
                           'data': base64.b64encode(data).decode()}],
                'reload': [{'unit': 'W3SVC', 'verb': 'restart'}], 'backup': 'dated'}
        args.update(more)
        return self.job('deploy', args)

    def test_1_hello(self):
        got = self.job('hello')
        self.assertTrue(got.get('ok'), got)
        self.assertEqual(got['platform'], 'windows')
        self.assertEqual(got['os'], 'Windows Server 2022 Standard (10.0.20348)')
        self.assertTrue(got['policy']['files'][0]['readers'], got['policy'])

    def test_2_deploy_with_readers_service_and_script(self):
        before = W.service_config('W3SVC').get('times', 0)
        got = self.deploy(b'CERT ONE\n', test=[{'argv': ['C:\\tools\\ok.exe']}],
                          script={'mode': 'path', 'path': 'C:\\scripts\\after.ps1',
                                  'args': 'x1'})
        self.assertTrue(got.get('ok'), got)
        self.assertEqual(read(local('C:\\certs\\www.pem'), 'rb'), b'CERT ONE\n')
        sd = AG.WIN['parse_sddl'](W.file_sd('C:\\certs\\www.pem'))
        self.assertTrue(sd['protected'])
        self.assertEqual(sorted(a['sid'] for a in sd['aces']),
                         sorted([AG.WIN['SYSTEM'], AG.WIN['ADMINS'], 'S-1-5-32-568']))
        self.assertEqual(W.service_config('W3SVC')['times'], before + 1)
        self.assertIn('is Running', json.dumps(got['steps']))
        self.assertIn('Restart-Service w3svc', json.dumps(got['steps']))
        self.assertEqual(read(os.path.join(TMP, 'after.out')).strip(), 'after x1')
        args = read(os.path.join(TMP, 'ps.args'))
        self.assertIn('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File', args)
        self.assertIn(os.path.join(AG.ROOT_STATE, 'stage', 'script-'), args)
        # the same again: nothing done
        got = self.deploy(b'CERT ONE\n')
        self.assertTrue(got.get('unchanged'), got)
        events = W.lines('eventlog.jsonl')
        self.assertTrue(any('"op": "deploy"' in e['text'] for e in events))
        self.assertIn('"op": "deploy"', read(os.path.join(AG.ROOT_STATE, 'audit.log')))

    def test_3_failing_test_puts_back(self):
        self.assertTrue(self.deploy(b'CERT ONE\n').get('ok'))
        W.set_sd('C:\\certs\\www.pem', 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-32-568)'
                                       '(A;;FR;;;S-1-5-11)')
        old_sd = W.file_sd('C:\\certs\\www.pem')
        got = self.deploy(b'CERT TWO\n', test=[{'argv': ['C:\\tools\\fail.exe']}])
        self.assertFalse(got.get('ok'), got)
        self.assertTrue(got.get('rolled_back'), got)
        self.assertIn('it failed', got['said'])
        self.assertEqual(read(local('C:\\certs\\www.pem'), 'rb'), b'CERT ONE\n')
        self.assertEqual(W.file_sd('C:\\certs\\www.pem'), old_sd)
        # a service that does not start: the files back too
        got = self.deploy(b'CERT THREE\n', reload=[{'unit': 'Broken', 'verb': 'restart'}])
        self.assertFalse(got.get('ok'), got)
        self.assertEqual(read(local('C:\\certs\\www.pem'), 'rb'), b'CERT ONE\n')
        # a dated copy was kept by the deployment that replaced a file
        got = self.deploy(b'CERT FOUR\n')
        self.assertTrue(got.get('ok'), got)
        self.assertTrue([n for n in os.listdir(local('C:\\certs')) if n.endswith('.bak')])

    def test_4_refused(self):
        got = self.deploy(b'X', files=[{'path': 'C:\\certs\\evil.exe', 'data': 'WA=='}])
        self.assertFalse(got.get('ok'))
        self.assertIn('never writes one', got['said'])
        got = self.deploy(b'X', files=[{'path': 'C:\\elsewhere\\a.pem', 'data': 'WA=='}],
                          reload=[{'unit': 'Spooler', 'verb': 'restart'}])
        self.assertIn('acme-agent allow file C:\\elsewhere',
                      [n['allow'] for n in got.get('needs') or []])
        self.assertIn('acme-agent allow service spooler restart',
                      [n['allow'] for n in got.get('needs') or []])
        os.makedirs(local('C:\\certs\\sub'), exist_ok=True)
        lk = os.path.join(local('C:\\certs'), 'jn')
        os.symlink(local('C:\\certs\\sub'), lk)
        got = self.deploy(b'X', files=[{'path': 'C:\\certs\\jn\\a.pem', 'data': 'WA=='}])
        self.assertFalse(got.get('ok'))
        self.assertIn('reparse point', got['said'])

    def test_5_the_pipe_checks_who(self):
        code = ('import sys, json, importlib.util; spec = importlib.util.spec_from_file_location('
                '"a", %r); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); '
                'print(json.dumps(m.RootLink().ask({"kind": "status"})))' % AGENT)
        for env, ok in (({'ACME_AGENT_FAKE_SID': 'S-1-5-21-1-2-3-1001',
                          'ACME_AGENT_FAKE_ELEVATED': '0'}, False),
                        ({'ACME_AGENT_FAKE_SID': 'S-1-5-21-1-2-3-500',
                          'ACME_AGENT_FAKE_ELEVATED': '0'}, False),
                        ({'ACME_AGENT_FAKE_SID': SVC_SID, 'ACME_AGENT_FAKE_ELEVATED': '0'}, True),
                        ({'ACME_AGENT_FAKE_SID': 'S-1-5-21-1-2-3-500'}, True)):
            e = dict(os.environ)
            e.update(env)
            out = subprocess.run([sys.executable, '-I', '-B', '-c', code], env=e,
                                 capture_output=True, text=True, timeout=60)
            got = json.loads(out.stdout)
            self.assertEqual(bool(got.get('ok')), ok, (env, got))
        self.assertIn('S-1-5-21-1-2-3-1001', json.dumps(W.lines('eventlog.jsonl')))

    def test_6_net_side_never_admin(self):
        got = cli('serve', ok=False)
        self.assertNotEqual(got.returncode, 0)
        self.assertIn('never as SYSTEM or an administrator', got.stderr)
        got = cli('root', ok=False, ACME_AGENT_FAKE_SID='S-1-5-21-1-2-3-1001',
                  ACME_AGENT_FAKE_ELEVATED='0')
        self.assertIn('LocalSystem', got.stderr)

    def test_7_restart_as_restart_service_force(self):
        """WAS has W3SVC depending on it (and Ftpsvc on W3SVC): a restart stops them first,
        then starts them again - as Restart-Service -Force; a dependent stopped stays so."""
        with self.assertRaises(OSError) as c:
            W.service_stop('WAS')                       # as Windows: dependents run
        self.assertEqual(c.exception.errno, 1051)
        n = len(W.lines('services.log'))
        got = self.deploy(b'CERT FIVE\n', reload=[{'unit': 'WAS', 'verb': 'restart'}])
        self.assertTrue(got.get('ok'), got)
        steps = json.dumps(got['steps'])
        self.assertIn('the services depending on it restarted too: Ftpsvc, W3SVC', steps)
        done = [(x['verb'], x['name'].lower()) for x in W.lines('services.log')[n:]
                if x['verb'] in ('stop', 'start')]
        self.assertEqual(done, [('stop', 'ftpsvc'), ('stop', 'w3svc'), ('stop', 'was'),
                                ('start', 'was'), ('start', 'w3svc'), ('start', 'ftpsvc')])
        for name in ('WAS', 'W3SVC', 'Ftpsvc'):
            self.assertEqual(W.service_state(name), 'Running')
        # try-restart the same; a dependent that was stopped is left stopped
        W._update('services.json', {}, lambda s: s['ftpsvc'].update(state='Stopped'))
        got = self.deploy(b'CERT SIX\n', reload=[{'unit': 'WAS', 'verb': 'try-restart'}])
        self.assertTrue(got.get('ok'), got)
        self.assertIn('restarted too: W3SVC', json.dumps(got['steps']))
        self.assertEqual(W.service_state('Ftpsvc'), 'Stopped')
        self.assertEqual(W.service_state('W3SVC'), 'Running')

    def test_9_graceful_stop(self):
        self.net.send_signal(signal.SIGTERM)
        self.assertEqual(self.net.wait(20), 0)
        self.root.send_signal(signal.SIGTERM)
        self.assertEqual(self.root.wait(20), 0)


class Cli(unittest.TestCase):
    def test_allow_deny_apply_status(self):
        got = cli('allow', 'file', 'C:\\shop\\ssl', '--readers', 'IIS_IUSRS,NT SERVICE\\W3SVC')
        self.assertIn('allow file C:\\shop\\ssl readers="IIS_IUSRS,NT SERVICE\\W3SVC"',
                      got.stdout)
        got = cli('allow', 'file', 'C:\\shop\\ssl', '--owner', 'x', ok=False)
        self.assertIn('not for Windows', got.stderr)
        got = cli('allow', 'file', 'C:\\shop2', '--readers', 'Nobody', ok=False)
        self.assertIn('no account Nobody', got.stderr)
        cli('allow', 'service', 'W3SVC', 'start')
        cli('allow', 'iis', 'Default Web Site')
        cli('allow', 'rdp')
        show = cli('policy', 'show').stdout
        self.assertIn('allow iis "Default Web Site"', show)
        self.assertIn('allow rdp', show)
        cli('deny', 'iis', 'Default Web Site')
        cli('deny', 'rdp')
        cli('deny', 'file', 'C:\\shop\\ssl')
        show = cli('policy', 'show').stdout
        self.assertNotIn('iis', show)
        self.assertNotIn('C:\\shop', show)
        got = cli('allow', 'store', ok=False, ACME_AGENT_FAKE_SID='S-1-5-21-1-2-3-1001',
                  ACME_AGENT_FAKE_ELEVATED='0')
        self.assertIn('elevated prompt (Run as administrator)', got.stderr)
        f = os.path.join(TMP, 'pol')
        with open(f, 'w') as fh:
            fh.write(AG.POLICY_HEAD + 'allow file C:\\applied readers=IIS_IUSRS\n'
                     'allow service W3SVC restart\nallow store\n')
        got = cli('policy', 'check', f)
        self.assertIn('3 entries, 0 errors', got.stdout)
        got = cli('policy', 'apply', f)
        self.assertIn('applied: 3 entries', got.stdout)
        got = cli('policy', 'apply', f, ok=False, ACME_AGENT_FAKE_SID='S-1-5-21-1-2-3-1001',
                  ACME_AGENT_FAKE_ELEVATED='0')
        self.assertIn('Run as administrator', got.stderr)
        st = json.loads(cli('status').stdout)
        self.assertEqual(st['platform'], 'windows')
        self.assertEqual(st['policy']['entries'], 3)
        self.assertIn('acme-agent-root', st['services'])


class ZInstall(unittest.TestCase):
    """(last: it takes the agent away)"""

    def test_zz_install_uninstall(self):
        cli('windows-install')                          # again: the same, nothing breaks
        cfg = W.service_config('acme-agent')
        self.assertEqual(cfg['account'], 'NT SERVICE\\acme-agent')
        self.assertEqual(cfg['sid_type'], 'restricted')
        self.assertEqual(cfg['privileges'], ['SeChangeNotifyPrivilege'])
        self.assertEqual(cfg['depends'], ['acme-agent-root'])
        self.assertTrue(cfg['delayed'])
        self.assertIn('-I -B', cfg['cmdline'])
        self.assertTrue(cfg['cmdline'].endswith('winservice serve'))
        rcfg = W.service_config('acme-agent-root')
        self.assertIsNone(rcfg['account'])
        self.assertEqual(W.service_state('acme-agent-root'), 'Running')
        self.assertTrue(W.load('registry.json', {}).get('eventsource'))
        prog = AG.WIN['program_dir']()
        self.assertIn(prog.lower(), W.path_get().lower())
        sd = AG.WIN['parse_sddl'](W.file_sd('C:\\ProgramData\\acme-agent\\root'))
        self.assertTrue(sd['protected'])
        self.assertEqual(sorted(a['sid'] for a in sd['aces']),
                         sorted([AG.WIN['SYSTEM'], AG.WIN['ADMINS']]))
        sd = AG.WIN['parse_sddl'](W.file_sd('C:\\ProgramData\\acme-agent\\net'))
        self.assertIn(SVC_SID, [a['sid'] for a in sd['aces']])
        # a passive join under way: its rule, only from `allow from`
        with open(os.path.join(AG.ROOT_STATE, 'join-pins.json'), 'w') as fh:
            json.dump({'ca': 'x', 'm': 'passive', 'p': 8446, 'until': time.time() + 60}, fh)
        cli('allow', 'from', '192.0.2.7')
        rules = W.firewall_rules()            # (agent.json of the round trip says its port)
        self.assertEqual(len(rules), 1, rules)
        rule = list(rules.values())[0]
        self.assertEqual(list(rules)[0], 'acme-agent (passive, TCP %d)' % rule['port'])
        self.assertIn('192.0.2.7/32', rule['remote'])
        # an upgrade only stops the services
        cli('windows-uninstall', '--upgrade')
        self.assertEqual(W.service_state('acme-agent'), 'Stopped')
        self.assertTrue(W.firewall_rules())
        cli('windows-install')
        cli('windows-uninstall')
        self.assertIsNone(W.service_state('acme-agent'))
        self.assertIsNone(W.service_state('acme-agent-root'))
        self.assertEqual(W.firewall_rules(), {})
        self.assertNotIn(prog.lower(), W.path_get().lower())
        self.assertFalse(W.load('registry.json', {}).get('eventsource'))
        self.assertTrue(os.path.exists(AG.POLICY))
        cli('windows-uninstall', '--purge')
        self.assertFalse(os.path.exists(AG.POLICY))


if __name__ == '__main__':
    unittest.main(verbosity=2)
