"""acme_agent_win.py - acme-agent on Windows: the platform under the same agent (1.0.120,
docs/target-agent.md "Windows").

acme_agent.py keeps all the logic - the policy, the jobs, the protocol, the two sides. At its end
(the platform hook) it calls install(globals()) of this file when it runs on Windows (or, for the
tests, with ACME_AGENT_FAKE_WINDOWS=1 on Linux), and this puts in place of what is POSIX there:

  * where things are: C:\\ProgramData\\acme-agent\\etc (the policy, agent.json, ca.pem), \\root
    (the root side's own: SYSTEM and the Administrators only), \\net (the network side's);
  * paths: C:\\folder (case-insensitive, `/` taken as `\\`); UNC, \\\\?\\ and \\\\.\\ paths,
    alternate data streams, device names, short (8.3) names refused; folders walked without
    following a reparse point (symbolic link, junction, mount point) and held open without
    FILE_SHARE_DELETE while a job works in them; no executable file ever written (.exe, .dll,
    .ps1 ... - the analogue of "no x bit");
  * who may read a file: its folder's inherited ACL, or (allow file C:\\certs readers=A,B) a
    protected DACL - SYSTEM and the Administrators full control, each reader read;
  * a file only the machine's administrators may change (the policy, agent.json): its owner
    SYSTEM, the Administrators or TrustedInstaller, nobody else allowed to write it or its folder;
  * the two sides: the Windows services acme-agent-root (LocalSystem) and acme-agent (the virtual
    account NT SERVICE\\acme-agent, a restricted service SID, SeChangeNotifyPrivilege only),
    linked by the named pipe \\\\.\\pipe\\acme-agent-root (its DACL: SYSTEM, the Administrators,
    the service; the root side checks the client's token: SYSTEM, the service, or an elevated
    administrator - the analogue of uid 0 / uid acme-agent);
  * services instead of systemd units (restart, try-restart, start), commands by CreateProcess
    (never a shell; a .bat/.cmd refused), scripts by powershell.exe -File (root's copy);
  * the Application event log (source acme-agent) and root\\audit.log; the passive port's
    firewall rule; the program folder on the system PATH; `acme-agent windows-install`,
    `windows-uninstall`, `winservice root|serve` (what the MSI and the services run).

Every Win32 call goes through ONE object, W: RealWin (ctypes, the standard API) on Windows,
FakeWin under the tests (C:\\... mapped into ACME_AGENT_FAKE_ROOT, ACLs, services, the event
log, the registry and the firewall kept as JSON there, the pipe a Unix socket) - so all of the
logic above runs in the tests on Linux.

Python 3.7+, the standard library only.
"""
import hashlib
import json
import ntpath
import os
import re
import secrets
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

SYSTEM = 'S-1-5-18'
ADMINS = 'S-1-5-32-544'
USERS = 'S-1-5-32-545'
TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
TRUSTED = (SYSTEM, ADMINS, TRUSTED_INSTALLER)
SERVICE = 'acme-agent'                  # the network side (NT SERVICE\acme-agent)
ROOT_SERVICE = 'acme-agent-root'        # the root side (LocalSystem)
ACCOUNT = 'NT SERVICE\\' + SERVICE
EVENT_SOURCE = 'acme-agent'
PIPE = r'\\.\pipe\acme-agent-root'
FIREWALL = 'acme-agent (passive, TCP %d)'
FIREWALL_PREFIX = 'acme-agent (passive'
WIN_VERBS = ('restart', 'try-restart', 'start')
# never written by a job: what Windows runs (or loads) as code - the analogue of the x bit
EXEC_EXT = ('.exe', '.dll', '.sys', '.com', '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.vbs',
            '.vbe', '.js', '.jse', '.wsf', '.wsh', '.msi', '.msp', '.scr', '.cpl', '.hta', '.lnk',
            '.pif', '.reg', '.inf', '.jar', '.py', '.pyw',
            # ...and what loads code all the same (1.0.120)
            '.pth', '.ps1xml', '.psc1', '.msc', '.ocx', '.drv', '.url', '.scf')
WIN_SHELLS = ('cmd', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32', 'python',
              'py')
SVC_RE = re.compile(r'[A-Za-z0-9_.$@+-]{1,256}\Z')
ACCOUNT_RE = re.compile(r'[^\x00-\x1f\x7f",=:*?<>|]{1,256}\Z')
SITE_RE = re.compile(r'[^\x00-\x1f\x7f"]{1,256}\Z')
DEVICE_RE = re.compile(r'(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$)(\..*)?\Z')

POLICY_HEAD_WIN = """# C:\\ProgramData\\acme-agent\\etc\\policy - what acme may do on this machine (docs/target-agent.md).
# acme proposes, this machine decides: nothing is allowed that is not written here, and acme
# can never change this file. Change it with `acme-agent allow ...` / `acme-agent deny ...` in
# an elevated prompt (or by hand: one entry a line; `acme-agent policy show` checks it), or write
# it whole with `acme-agent policy apply FILE` (checked first; the one before kept as policy.DATE).
#
#   allow file C:\\certs readers=IIS_IUSRS        files in C:\\certs (and below); readers=: only
#                                                SYSTEM, the Administrators and those may read them
#   allow service W3SVC restart,try-restart,start  a Windows service (Restart-Service ...)
#   allow test -- C:\\tools\\check.exe ARGS...     a fixed command line (never a shell)
#   allow script C:\\scripts\\after.ps1 sha256=HEX  a PowerShell script on this machine, by its hash
#   allow script-hash HEX                        a PowerShell script written in acme, by its hash
#   allow store                                  the certificate into Cert:\\LocalMachine\\My
#   allow iis "Default Web Site" | allow iis *   the https bindings of an IIS site
#   allow rdp                                    the Remote Desktop listener's certificate
#   allow from ADDRESS[/BITS]                    passive: acme only from there
#   allow probe HOST:PORT | allow probe local    a test of what HOST:PORT serves, from here
#   allow connect HOST:PORT                      acme reaches HOST:PORT through this agent
#   allow self-update                            acme may update this agent (signed, newer)
#   limit files 20                               files in one deployment
#   limit size 1048576                           bytes of one file
"""

WIN_DOC = """acme-agent (Windows): a server that takes its certificates from acme without acme holding any
of its credentials (docs/target-agent.md). Run it in an elevated prompt (Run as administrator).

  acme-agent join CODE [--no-wait]       join acme with a join code (or a company enrollment code)
  acme-agent status                      what is here (JSON)
  acme-agent fingerprint                 the fingerprint acme asks you to confirm
  acme-agent forget                      leave acme: its keys and pins taken away
  acme-agent policy show [--json]        what acme may do here
  acme-agent policy check FILE|-         a whole policy checked: what the agent would not read
  acme-agent policy apply FILE|-         ...and written in place of the one there
  acme-agent allow file C:\\certs [--readers ACCOUNT,ACCOUNT]
  acme-agent allow service NAME restart,try-restart,start
  acme-agent allow test -- C:\\tools\\check.exe ARGS...
  acme-agent allow script C:\\scripts\\after.ps1   (its SHA-256 pinned now)
  acme-agent allow script-hash SHA256    (a PowerShell script written in acme, by its hash)
  acme-agent allow store                 the certificate into the machine store (LocalMachine\\My)
  acme-agent allow iis SITE | allow iis *  the https bindings of an IIS site
  acme-agent allow rdp                   the Remote Desktop listener's certificate
  acme-agent allow from ADDRESS[/BITS]   (passive: only from there)
  acme-agent allow probe HOST:PORT | probe local | connect HOST:PORT | self-update
  acme-agent limit files N | limit size BYTES
  acme-agent deny ...                    the same words: that entry taken away
  acme-agent version
  acme-agent windows-install [--join CODE]   folders, services, PATH, event log (the MSI runs it)
  acme-agent windows-uninstall [--purge|--upgrade]  ...taken away (the policy stays unless --purge;
                                         --upgrade: only the services stopped)
  acme-agent winservice root|serve           the two services' entry points
"""


class Refused(Exception):
    """Replaced by acme_agent.Refused at install()."""
    def __init__(self, words, needs=None):
        Exception.__init__(self, words)
        self.needs = needs or []


class WinFail(OSError):
    """A Win32 call that failed: its error code and words."""


# ---- pure helpers (the same on Windows and in the fake) ---------------------------------------
def service_sid(name):
    """The SID of a service (NT SERVICE\\NAME): S-1-5-80- and the SHA-1 of its name in upper
    case, UTF-16LE, as five 32-bit numbers (little-endian) - what `sc showsid` says."""
    h = hashlib.sha1(str(name).upper().encode('utf-16-le')).digest()
    return 'S-1-5-80-' + '-'.join(str(x) for x in struct.unpack('<5I', h))


ALIASES = {'SY': SYSTEM, 'BA': ADMINS, 'BU': USERS, 'AU': 'S-1-5-11', 'WD': 'S-1-1-0',
           'NS': 'S-1-5-20', 'LS': 'S-1-5-19', 'IU': 'S-1-5-4', 'SU': 'S-1-5-6',
           'AN': 'S-1-5-7', 'BG': 'S-1-5-32-546', 'PU': 'S-1-5-32-547', 'BO': 'S-1-5-32-551',
           'SO': 'S-1-5-32-549', 'AO': 'S-1-5-32-548', 'PO': 'S-1-5-32-550',
           'RD': 'S-1-5-32-555', 'NU': 'S-1-5-2', 'IS': 'S-1-5-32-568', 'CO': 'S-1-3-0',
           'CG': 'S-1-3-1', 'OW': 'S-1-3-4', 'RC': 'S-1-5-12', 'WR': 'S-1-5-33',
           'AC': 'S-1-15-2-1', 'RU': 'S-1-5-32-554', 'LU': 'S-1-5-32-559', 'MU': 'S-1-5-32-558',
           'ER': 'S-1-5-32-573', 'CY': 'S-1-5-32-569', 'NO': 'S-1-5-32-556', 'RM': 'S-1-5-32-580',
           'HA': 'S-1-5-32-578', 'RA': 'S-1-5-32-575', 'ES': 'S-1-5-32-576', 'MS': 'S-1-5-32-577'}
RIGHTS = {'GA': 0x10000000, 'GX': 0x20000000, 'GW': 0x40000000, 'GR': 0x80000000,
          'FA': 0x1F01FF, 'FR': 0x120089, 'FW': 0x120116, 'FX': 0x1200A0,
          'SD': 0x10000, 'RC': 0x20000, 'WD': 0x40000, 'WO': 0x80000,
          'CC': 0x1, 'DC': 0x2, 'LC': 0x4, 'SW': 0x8, 'RP': 0x10, 'WP': 0x20, 'DT': 0x40,
          'LO': 0x80, 'CR': 0x100, 'KA': 0xF003F, 'KR': 0x20019, 'KW': 0x20006, 'KX': 0x20019}
# what lets a SID change an object (or what it holds): write or append data, extended attributes,
# delete a child, attributes, delete, the DACL, the owner, generic all/write
WRITE_MASK = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | \
    0x40000000
READ_MASK = 0x120089
ACE_RE = re.compile(r'\(([^;()]*);([^;()]*);([^;()]*);([^;()]*);([^;()]*);([^;()]*)\)')


def _rights(text):
    t = str(text or '')
    if t.lower().startswith('0x'):
        try:
            return int(t, 16)
        except ValueError:
            return 0xFFFFFFFF
    m = 0
    for i in range(0, len(t), 2):
        m |= RIGHTS.get(t[i:i + 2], 0xFFFFFFFF if t[i:i + 2] else 0)
    return m


def _sid(word):
    w = str(word or '')
    return ALIASES.get(w, w)


def parse_sddl(text):
    """An SDDL string -> {owner, protected, null_dacl, aces: [{type, flags, mask, sid}]}."""
    t = str(text or '')
    out = {'owner': '', 'protected': False, 'null_dacl': False, 'aces': []}
    m = re.search(r'O:([A-Z]{2}|S-[0-9-]+)', t)
    if m:
        out['owner'] = _sid(m.group(1))
    d = t.find('D:')
    if d < 0:
        out['null_dacl'] = True
        return out
    dacl = t[d + 2:]
    s = dacl.find('S:')
    if s >= 0:
        dacl = dacl[:s]
    head = dacl.split('(', 1)[0]
    if 'NO_ACCESS_CONTROL' in head:
        out['null_dacl'] = True
    out['protected'] = 'P' in head
    for ace in ACE_RE.findall(dacl):
        out['aces'].append({'type': ace[0], 'flags': ace[1], 'mask': _rights(ace[2]),
                            'sid': _sid(ace[5])})
    return out


def _flags(flags):
    return [flags[i:i + 2] for i in range(0, len(flags), 2)]


def sddl_for(entries, folder=False, owner=ADMINS, protected=True):
    """A security descriptor in SDDL: [(SID, 'F'|'M'|'RX'|'R'|'RW')] allowed, each folder's
    inherited by what is in it (folder=True), nothing else (protected)."""
    rights = {'F': 'FA', 'M': '0x1301bf', 'RX': '0x1200a9', 'R': 'FR', 'RW': 'GRGW'}
    inh = 'OICI' if folder else ''
    return 'O:%sD:%s%s' % (owner, 'P' if protected else '', ''.join(
        '(A;%s;%s;;;%s)' % (inh, rights[r], sid) for sid, r in entries))


def sddl_readers(readers):
    """The DACL of a file `allow file DIR readers=...` writes: SYSTEM and the Administrators full
    control, each reader read - nothing inherited."""
    return sddl_for([(SYSTEM, 'F'), (ADMINS, 'F')] + [(s, 'R') for s in readers])


def sd_writers(sd):
    """The SIDs an SDDL lets change the object (allow ACEs with a writing right that apply to
    the object itself)."""
    out = []
    for a in sd['aces']:
        if a['type'] not in ('A', 'XA') or 'IO' in _flags(a['flags']):
            continue
        if a['mask'] & WRITE_MASK and a['sid'] not in out:
            out.append(a['sid'])
    return out


def sd_problem(sd):
    """'' when only SYSTEM, the Administrators and TrustedInstaller may change the object - or
    what else may."""
    if sd is None:
        return 'its permissions cannot be read'
    if sd['null_dacl']:
        return 'it has no DACL (everybody may change it)'
    if sd['owner'] and sd['owner'] not in TRUSTED:
        return 'its owner is %s (it must be SYSTEM, the Administrators or TrustedInstaller)' % \
            sd['owner']
    bad = [s for s in sd_writers(sd) if s not in TRUSTED]
    if bad:
        return '%s may change it (only SYSTEM, the Administrators and TrustedInstaller may)' % \
            ', '.join(bad[:4])
    return ''


class AclId(tuple):
    """Who may read a file the agent wrote with readers= (the SIDs beside SYSTEM and the
    Administrators) - compared as a tuple; `sddl` the whole descriptor it was read with (a copy,
    a putting back writes exactly that)."""
    sddl = None


def acl_id(sddl):
    """AclId of a file's SDDL when its DACL is protected (readers=), else None (inherited)."""
    if not sddl:
        return None
    sd = parse_sddl(sddl)
    if not sd['protected']:
        return None
    who = []
    for a in sd['aces']:
        if a['type'] != 'A' or a['sid'] in (SYSTEM, ADMINS):
            continue
        w = a['sid'] + (':w' if a['mask'] & WRITE_MASK else '')
        if w not in who:
            who.append(w)
    out = AclId(sorted(who))
    out.sddl = sddl
    return out


class WinStat(object):
    """What the agent asks of a file it read (the shape of an os.stat_result it uses)."""

    def __init__(self, size=0, mtime=0.0, attrs=0, sddl=None, links=1):
        self.st_size, self.st_mtime, self.attrs, self.sddl = size, mtime, attrs, sddl
        self.st_mode = stat.S_IFREG | 0o600
        self.st_uid = acl_id(sddl)
        self.st_gid = None
        self.links = links
        self.is_dir = bool(attrs & 0x10)
        self.is_reparse = bool(attrs & 0x400)
        self.is_file = not self.is_dir and not self.is_reparse


def norm_win(path):
    """C:\\folder\\name as Windows writes it (the drive upper-case, `\\`) - or Refused."""
    p = str(path or '').strip()
    if not p or len(p) > 1024 or re.search(r'[\x00-\x1f\x7f]', p):
        raise Refused('%r is not an absolute path (C:\\folder)' % p[:120])
    if p.startswith(('\\\\', '//', '\\/', '/\\')):
        raise Refused('%s is a network (UNC) or device path (\\\\server\\share, \\\\?\\, \\\\.\\) '
                      '- only a folder on a drive of this machine (C:\\folder)' % p[:120])
    p = p.replace('/', '\\')
    m = re.match(r'([A-Za-z]):\\(.*)\Z', p, re.S)
    if not m:
        raise Refused('%r is not an absolute path (C:\\folder)' % p[:120])
    parts = [x for x in m.group(2).split('\\') if x not in ('', '.')]
    if '..' in parts:
        raise Refused('a path with .. in it: %s' % p[:120])
    for x in parts:
        if ':' in x:
            raise Refused('%s: a ":" after the drive (an alternate data stream) - refused' %
                          p[:120])
        if re.search(r'[<>"|?*]', x):
            raise Refused('%s holds a character no Windows path holds' % p[:120])
        if x.endswith(('.', ' ')):
            raise Refused('%s: a name ending in a dot or a space (Windows drops it) - write the '
                          'name as it is' % p[:120])
        if DEVICE_RE.match(x):
            raise Refused('%s: %s is a device name (CON, NUL, COM1 ...) - refused' % (
                p[:120], x))
        if re.search(r'~\d', x):
            raise Refused('%s: %s looks like a short (8.3) name - write the long name' % (
                p[:120], x))
    return m.group(1).upper() + ':\\' + '\\'.join(parts)


def wq(word):
    """A word of a policy line or a command line as typed in cmd.exe or PowerShell."""
    w = str(word)
    if w and not re.search(r'[\s\'"&|<>^%;,()`$]', w):
        return w
    return ("'%s'" % w) if '"' in w and "'" not in w else '"%s"' % w


def win_split(line):
    """A line of the policy -> its words: quotes as sh reads them ("..." and '...'), but a `\\`
    is a backslash (C:\\certs), never an escape."""
    lx = shlex.shlex(line, posix=True)
    lx.whitespace_split = True
    lx.escape = ''
    lx.commenters = ''
    return list(lx)


def acl_sddl(acl):
    """The SDDL a new file is made with: None (inherited from its folder), a copy's own
    (AclId.sddl, or an SDDL string), or readers= (SIDs)."""
    if acl is None:
        return None
    if isinstance(acl, str):
        return acl
    if getattr(acl, 'sddl', None):
        return acl.sddl
    return sddl_readers([x.split(':')[0] for x in acl])


def _dacl_part(sddl):
    s = str(sddl or '')
    i = s.find('D:')
    return s[i:] if i >= 0 else ''


def _ft(ft):
    """A FILETIME (100 ns since 1601) -> seconds since 1970."""
    return max(0.0, (ft - 116444736000000000) / 1e7)


# ---- the facade: every Win32 call of the agent -------------------------------------------------
class DirH(object):
    """A folder held open (each folder of its path held too, none of them sharable for delete:
    nothing on the way can be renamed, replaced or taken away while a job works in it)."""

    def __init__(self, path, handles=(), local=None):
        self.path, self.handles, self.local = path, list(handles), local
        self.refs = 1


class _Api(object):
    """kernel32, advapi32, shell32, user32 by ctypes: every function its argtypes and restype,
    errors by ctypes.get_last_error() (use_last_error=True)."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes as wt
        self.ct, self.wt = ctypes, wt
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        adv = ctypes.WinDLL('advapi32', use_last_error=True)
        sh32 = ctypes.WinDLL('shell32', use_last_error=True)
        u32 = ctypes.WinDLL('user32', use_last_error=True)
        P, H, D, B, W_, V = ctypes.POINTER, wt.HANDLE, wt.DWORD, wt.BOOL, wt.LPCWSTR, \
            ctypes.c_void_p

        class FILETIME(ctypes.Structure):
            _fields_ = [('lo', D), ('hi', D)]

        class BHFI(ctypes.Structure):
            _fields_ = [('attrs', D), ('ctime', FILETIME), ('atime', FILETIME),
                        ('mtime', FILETIME), ('serial', D), ('size_hi', D), ('size_lo', D),
                        ('links', D), ('index_hi', D), ('index_lo', D)]

        class WFAD(ctypes.Structure):
            _fields_ = [('attrs', D), ('ctime', FILETIME), ('atime', FILETIME),
                        ('mtime', FILETIME), ('size_hi', D), ('size_lo', D)]

        class SA(ctypes.Structure):
            _fields_ = [('nLength', D), ('lpSecurityDescriptor', V), ('bInheritHandle', B)]

        class SERVICE_STATUS(ctypes.Structure):
            _fields_ = [('dwServiceType', D), ('dwCurrentState', D), ('dwControlsAccepted', D),
                        ('dwWin32ExitCode', D), ('dwServiceSpecificExitCode', D),
                        ('dwCheckPoint', D), ('dwWaitHint', D)]

        class SERVICE_STATUS_PROCESS(ctypes.Structure):
            _fields_ = SERVICE_STATUS._fields_ + [('dwProcessId', D), ('dwServiceFlags', D)]

        class SC_ACTION(ctypes.Structure):
            _fields_ = [('Type', ctypes.c_int), ('Delay', D)]

        class SERVICE_FAILURE_ACTIONSW(ctypes.Structure):
            _fields_ = [('dwResetPeriod', D), ('lpRebootMsg', wt.LPWSTR),
                        ('lpCommand', wt.LPWSTR), ('cActions', D), ('lpsaActions', P(SC_ACTION))]

        class SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [('Sid', V), ('Attributes', D)]

        self.FILETIME, self.BHFI, self.WFAD, self.SA = FILETIME, BHFI, WFAD, SA
        self.SERVICE_STATUS, self.SERVICE_STATUS_PROCESS = SERVICE_STATUS, SERVICE_STATUS_PROCESS
        self.SC_ACTION, self.SERVICE_FAILURE_ACTIONSW = SC_ACTION, SERVICE_FAILURE_ACTIONSW
        self.SID_AND_ATTRIBUTES = SID_AND_ATTRIBUTES
        self.MAIN = ctypes.WINFUNCTYPE(None, D, P(wt.LPWSTR))
        self.HANDLER_EX = ctypes.WINFUNCTYPE(D, D, D, V, V)

        class SERVICE_TABLE_ENTRYW(ctypes.Structure):
            _fields_ = [('lpServiceName', wt.LPWSTR), ('lpServiceProc', self.MAIN)]
        self.SERVICE_TABLE_ENTRYW = SERVICE_TABLE_ENTRYW

        def fn(dll, name, res, *args):
            f = getattr(dll, name)
            f.restype, f.argtypes = res, list(args)
            setattr(self, name, f)
        # files
        fn(k32, 'CreateFileW', H, W_, D, D, V, D, D, H)
        fn(k32, 'CloseHandle', B, H)
        fn(k32, 'ReadFile', B, H, V, D, P(D), V)
        fn(k32, 'WriteFile', B, H, V, D, P(D), V)
        fn(k32, 'FlushFileBuffers', B, H)
        fn(k32, 'GetFileInformationByHandle', B, H, P(BHFI))
        fn(k32, 'GetFileAttributesExW', B, W_, ctypes.c_int, P(WFAD))
        fn(k32, 'GetFinalPathNameByHandleW', D, H, wt.LPWSTR, D, D)
        fn(k32, 'MoveFileExW', B, W_, W_, D)
        fn(k32, 'DeleteFileW', B, W_)
        fn(k32, 'CreateDirectoryW', B, W_, V)
        fn(k32, 'LocalFree', V, V)
        # the pipe, processes
        fn(k32, 'CreateNamedPipeW', H, W_, D, D, D, D, D, D, V)
        fn(k32, 'ConnectNamedPipe', B, H, V)
        fn(k32, 'DisconnectNamedPipe', B, H)
        fn(k32, 'GetNamedPipeClientProcessId', B, H, P(wt.ULONG))
        fn(k32, 'WaitNamedPipeW', B, W_, D)
        fn(k32, 'OpenProcess', H, D, B, D)
        fn(k32, 'GetCurrentProcess', H)
        # security
        fn(adv, 'OpenProcessToken', B, H, D, P(H))
        fn(adv, 'GetTokenInformation', B, H, ctypes.c_int, V, D, P(D))
        fn(adv, 'ConvertSidToStringSidW', B, V, P(wt.LPWSTR))
        fn(adv, 'LookupAccountNameW', B, W_, W_, V, P(D), wt.LPWSTR, P(D), P(D))
        fn(adv, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', B, W_, D, P(V), P(wt.ULONG))
        fn(adv, 'ConvertSecurityDescriptorToStringSecurityDescriptorW', B, V, D, D,
           P(wt.LPWSTR), P(wt.ULONG))
        fn(adv, 'GetSecurityInfo', D, H, ctypes.c_int, D, P(V), P(V), P(V), P(V), P(V))
        fn(adv, 'SetNamedSecurityInfoW', D, wt.LPWSTR, ctypes.c_int, D, V, V, V, V)
        fn(adv, 'GetSecurityDescriptorDacl', B, V, P(B), P(V), P(B))
        fn(adv, 'GetSecurityDescriptorOwner', B, V, P(V), P(B))
        fn(adv, 'GetSecurityDescriptorControl', B, V, P(wt.WORD), P(D))
        # services
        fn(adv, 'OpenSCManagerW', H, W_, W_, D)
        fn(adv, 'CreateServiceW', H, H, W_, W_, D, D, D, D, W_, W_, P(D), W_, W_, W_)
        fn(adv, 'OpenServiceW', H, H, W_, D)
        fn(adv, 'ChangeServiceConfigW', B, H, D, D, D, W_, W_, P(D), W_, W_, W_, W_)
        fn(adv, 'ChangeServiceConfig2W', B, H, D, V)
        fn(adv, 'StartServiceW', B, H, D, V)
        fn(adv, 'ControlService', B, H, D, P(SERVICE_STATUS))
        fn(adv, 'QueryServiceStatusEx', B, H, ctypes.c_int, V, D, P(D))
        fn(adv, 'DeleteService', B, H)

        class ENUM_SERVICE_STATUSW(ctypes.Structure):
            _fields_ = [('lpServiceName', wt.LPWSTR), ('lpDisplayName', wt.LPWSTR),
                        ('ServiceStatus', SERVICE_STATUS)]
        self.ENUM_SERVICE_STATUSW = ENUM_SERVICE_STATUSW
        fn(adv, 'EnumDependentServicesW', B, H, D, V, D, P(D), P(D))
        fn(adv, 'CloseServiceHandle', B, H)
        fn(adv, 'StartServiceCtrlDispatcherW', B, P(SERVICE_TABLE_ENTRYW))
        fn(adv, 'RegisterServiceCtrlHandlerExW', H, W_, self.HANDLER_EX, V)
        fn(adv, 'SetServiceStatus', B, H, P(SERVICE_STATUS))
        # the event log
        fn(adv, 'RegisterEventSourceW', H, W_, W_)
        fn(adv, 'ReportEventW', B, H, wt.WORD, wt.WORD, D, V, wt.WORD, D, P(wt.LPCWSTR), V)
        fn(adv, 'DeregisterEventSource', B, H)
        # elevation, the settings broadcast
        fn(sh32, 'IsUserAnAdmin', B)
        fn(u32, 'SendMessageTimeoutW', ctypes.c_ssize_t, H, ctypes.c_uint, ctypes.c_size_t,
           W_, ctypes.c_uint, ctypes.c_uint, P(ctypes.c_size_t))
        self.INVALID = H(-1).value

    def fail(self, what, err=None):
        err = self.ct.get_last_error() if err is None else err
        return WinFail(err, '%s: %s' % (what, self.ct.FormatError(err).strip()))


# constants (winnt.h, winbase.h, winsvc.h, sddl.h)
GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE = 0x10000, 0x20000, 0x40000, 0x80000, \
    0x100000
FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_TRAVERSE = 0x1, 0x80, 0x20
FILE_WRITE_DATA = 0x2
SHARE_READ, SHARE_WRITE = 0x1, 0x2
CREATE_NEW, OPEN_EXISTING = 1, 3
ATTR_DIRECTORY, ATTR_REPARSE, ATTR_NORMAL = 0x10, 0x400, 0x80
FLAG_BACKUP_SEMANTICS, FLAG_OPEN_REPARSE_POINT, FLAG_WRITE_THROUGH = 0x02000000, 0x00200000, \
    0x80000000
MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH = 0x1, 0x8
SE_FILE_OBJECT = 1
OWNER_INFO, DACL_INFO, PROTECTED_DACL_INFO, UNPROTECTED_DACL_INFO = 0x1, 0x4, 0x80000000, \
    0x20000000
ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_ACCESS_DENIED = 2, 3, 5
ERROR_BROKEN_PIPE, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER = 109, 80, 122
ERROR_ALREADY_EXISTS, ERROR_PIPE_CONNECTED, ERROR_NO_DATA = 183, 535, 232
ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST = 1056, 1060
ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE = 1062, 1073, 1072
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_SPECIFIC_ERROR = 1063, 1066
PIPE_ACCESS_DUPLEX, FIRST_PIPE_INSTANCE, PIPE_REJECT_REMOTE_CLIENTS = 0x3, 0x80000, 0x8
SQOS_PRESENT, SECURITY_IDENTIFICATION = 0x100000, 0x10000
PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_QUERY = 0x1000, 0x8
TOKEN_USER, TOKEN_GROUPS, TOKEN_ELEVATION = 1, 2, 20
SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY = 0x4, 0x10
SC_MANAGER_CONNECT, SC_MANAGER_ALL_ACCESS = 0x1, 0xF003F
SERVICE_ALL_ACCESS, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOP = 0xF01FF, 0x4, 0x10, 0x20
SERVICE_ENUMERATE_DEPENDENTS, SERVICE_ACTIVE, ERROR_MORE_DATA = 0x8, 0x1, 234
ERROR_DEPENDENT_SERVICES_RUNNING = 1051
SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL = 0x10, 2, 1
SERVICE_NO_CHANGE = 0xFFFFFFFF
CONFIG_DESCRIPTION, CONFIG_FAILURE_ACTIONS, CONFIG_DELAYED_AUTO_START = 1, 2, 3
CONFIG_FAILURE_ACTIONS_FLAG, CONFIG_SERVICE_SID_INFO, CONFIG_REQUIRED_PRIVILEGES = 4, 5, 6
SID_TYPE_UNRESTRICTED, SID_TYPE_RESTRICTED = 1, 3
SC_ACTION_RESTART = 1
STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4
STATE_WORDS = {1: 'Stopped', 2: 'StartPending', 3: 'StopPending', 4: 'Running',
               5: 'ContinuePending', 6: 'PausePending', 7: 'Paused'}
CONTROL_STOP, CONTROL_INTERROGATE, CONTROL_SHUTDOWN = 1, 4, 5
ACCEPT_STOP, ACCEPT_SHUTDOWN = 0x1, 0x4
EVENTLOG_ERROR, EVENTLOG_WARNING, EVENTLOG_INFORMATION = 0x1, 0x2, 0x4
HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG = 0xFFFF, 0x1A, 0x2
CREATE_NO_WINDOW, DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP = 0x08000000, 0x8, 0x200
EVENT_KEY = r'SYSTEM\CurrentControlSet\Services\EventLog\Application' + '\\' + EVENT_SOURCE
ENV_KEY = r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
OS_KEY = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'


def _os_words(product, build, major, minor):
    """'Windows Server 2022 Standard (10.0.20348)' (Windows 11 says 'Windows 10' in the
    registry)."""
    product = str(product or 'Windows')
    try:
        if int(build) >= 22000 and product.startswith('Windows 10'):
            product = 'Windows 11' + product[len('Windows 10'):]
    except (TypeError, ValueError):
        pass
    return ('%s (%s.%s.%s)' % (product, major, minor, build))[:80]


def restart_force(w, name, wait=60):
    """Restart-Service -Force (W3SVC depends on WAS, many services have dependents): the
    running services that depend on it stopped first, it stopped and started, then they started
    again (in their start order)."""
    deps = w.service_dependents(name)
    for d in deps:
        w.service_stop(d, wait)
    if w.service_state(name) not in ('Stopped', None):
        w.service_stop(name, wait)
    w.service_start(name, wait)
    for d in reversed(deps):
        w.service_start(d, wait)
    return deps


class RealWin(object):
    """Windows itself."""
    fake = False

    def __init__(self):
        self._api = None

    @property
    def api(self):
        if self._api is None:
            self._api = _Api()
        return self._api

    # -- where things are -------------------------------------------------------------------
    def local(self, path):
        return path

    def winpath(self, path):
        return path

    def env_dir(self, name, default):
        return os.environ.get(name) or default

    def system_root(self):
        return self.env_dir('SystemRoot', 'C:\\Windows')

    def system_drive(self):
        return self.env_dir('SystemDrive', 'C:')

    def program_data(self):
        return self.env_dir('ProgramData', 'C:\\ProgramData')

    def program_files(self):
        return self.env_dir('ProgramFiles', 'C:\\Program Files')

    def program_files_x86(self):
        return self.env_dir('ProgramFiles(x86)', 'C:\\Program Files (x86)')

    def powershell(self):
        return ntpath.join(self.system_root(), 'System32', 'WindowsPowerShell', 'v1.0',
                           'powershell.exe')

    def openssl_default(self, lib):
        return ntpath.join(lib, 'openssl', 'openssl.exe')

    # -- files and folders --------------------------------------------------------------------
    def _open(self, path, access, share, disp, flags, sa=None):
        a = self.api
        h = a.CreateFileW(path, access, share, sa, disp, flags, None)
        if h is None or h == a.INVALID:
            raise a.fail(path)
        return h

    def _info(self, h):
        a = self.api
        info = a.BHFI()
        if not a.GetFileInformationByHandle(h, a.ct.byref(info)):
            raise a.fail('GetFileInformationByHandle')
        return info

    def _final(self, h):
        a = self.api
        buf = a.ct.create_unicode_buffer(1024)
        n = a.GetFinalPathNameByHandleW(h, buf, 1024, 0)
        if not n or n >= 1024:
            raise a.fail('GetFinalPathNameByHandleW')
        p = buf.value
        return p[4:] if p.startswith('\\\\?\\') and not p.startswith('\\\\?\\UNC\\') else p

    def _close(self, h):
        if h:
            self.api.CloseHandle(h)

    def open_dir(self, path, make_from=None):
        """The folder walked from its drive's root: each folder opened (no reparse point
        followed, the handle not sharable for delete), checked to be a folder and no reparse
        point, its final path the one asked; missing folders below `make_from` made."""
        p = norm_win(path)
        drive, rest = p[:3], [x for x in p[3:].split('\\') if x]
        handles, walked = [], drive
        mk = (make_from or '').rstrip('\\').lower()
        try:
            for i in range(len(rest) + 1):
                if i:
                    walked = ntpath.join(walked, rest[i - 1])
                try:
                    h = self._open(walked, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
                                   READ_CONTROL | SYNCHRONIZE, SHARE_READ | SHARE_WRITE,
                                   OPEN_EXISTING, FLAG_BACKUP_SEMANTICS | FLAG_OPEN_REPARSE_POINT)
                except WinFail as e:
                    if e.errno not in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                        raise
                    if not mk or not (walked.lower() + '\\').startswith(mk + '\\'):
                        raise Refused('%s is not there' % walked)
                    if not self.api.CreateDirectoryW(walked, None):
                        err = self.api.ct.get_last_error()
                        if err != ERROR_ALREADY_EXISTS:
                            raise self.api.fail(walked, err)
                    h = self._open(walked, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES |
                                   READ_CONTROL | SYNCHRONIZE, SHARE_READ | SHARE_WRITE,
                                   OPEN_EXISTING, FLAG_BACKUP_SEMANTICS | FLAG_OPEN_REPARSE_POINT)
                handles.append(h)
                info = self._info(h)
                if info.attrs & ATTR_REPARSE:
                    raise Refused('%s is a symbolic link, a junction or a mount point (a reparse '
                                  'point) - refused' % walked)
                if not info.attrs & ATTR_DIRECTORY:
                    raise Refused('%s is not a folder' % walked)
                if self._final(h).rstrip('\\').lower() != walked.rstrip('\\').lower():
                    raise Refused('%s is not where it says (%s) - refused' % (walked,
                                                                                self._final(h)))
            return DirH(walked, handles)
        except BaseException:
            for h in handles:
                self._close(h)
            raise

    def dup(self, dh):
        dh.refs += 1
        return dh

    def close(self, dh):
        dh.refs -= 1
        if dh.refs <= 0:
            for h in dh.handles:
                self._close(h)
            dh.handles = []

    def open_sub(self, dh, name, make=False):
        p = ntpath.join(dh.path, name)
        if make and not self.api.CreateDirectoryW(p, None):
            err = self.api.ct.get_last_error()
            if err != ERROR_ALREADY_EXISTS:
                raise self.api.fail(p, err)
        try:
            h = self._open(p, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL |
                           SYNCHRONIZE, SHARE_READ | SHARE_WRITE, OPEN_EXISTING,
                           FLAG_BACKUP_SEMANTICS | FLAG_OPEN_REPARSE_POINT)
        except WinFail as e:
            if e.errno in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                raise FileNotFoundError(e.errno, str(e))
            raise
        info = self._info(h)
        if info.attrs & ATTR_REPARSE or not info.attrs & ATTR_DIRECTORY:
            self._close(h)
            raise WinFail(ERROR_ACCESS_DENIED, '%s is a reparse point or not a folder' % p)
        return DirH(p, [h])

    def _sddl_of(self, h):
        a = self.api
        psd = a.ct.c_void_p()
        err = a.GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_INFO | DACL_INFO, None, None, None,
                                None, a.ct.byref(psd))
        if err:
            raise a.fail('GetSecurityInfo', err)
        try:
            s = a.wt.LPWSTR()
            if not a.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    psd, 1, OWNER_INFO | DACL_INFO, a.ct.byref(s), None):
                raise a.fail('ConvertSecurityDescriptorToStringSecurityDescriptorW')
            try:
                return s.value
            finally:
                a.LocalFree(s)
        finally:
            a.LocalFree(psd)

    def _read_handle(self, h, most):
        a = self.api
        info = self._info(h)
        size = (info.size_hi << 32) | info.size_lo
        if size > most:
            return None, size, info
        chunks, left = [], size + 1
        buf = a.ct.create_string_buffer(1 << 16)
        n = a.wt.DWORD()
        while left > 0:
            if not a.ReadFile(h, buf, min(left, 1 << 16), a.ct.byref(n), None):
                raise a.fail('ReadFile')
            if not n.value:
                break
            chunks.append(buf.raw[:n.value])
            left -= n.value
        return b''.join(chunks), size, info

    def read_file(self, dh, name, most):
        """(bytes, WinStat) of a plain file in the folder, or (None, None) when there is none;
        a reparse point or a folder refused."""
        p = ntpath.join(dh.path, name)
        try:
            h = self._open(p, GENERIC_READ | READ_CONTROL, SHARE_READ, OPEN_EXISTING,
                           FLAG_OPEN_REPARSE_POINT | FLAG_BACKUP_SEMANTICS)
        except WinFail as e:
            if e.errno in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                return None, None
            raise
        try:
            info = self._info(h)
            if info.attrs & ATTR_REPARSE:
                raise Refused('%s is a symbolic link (a reparse point) - refused' % name)
            if info.attrs & ATTR_DIRECTORY:
                raise Refused('%s is not a plain file' % name)
            data, size, info = self._read_handle(h, most)
            if data is None:
                raise Refused('%s is bigger than %d bytes' % (name, most))
            mt = _ft((info.mtime.hi << 32) | info.mtime.lo)
            return data, WinStat(size, mt, info.attrs, self._sddl_of(h), info.links)
        finally:
            self._close(h)

    def stat(self, dh, name):
        a = self.api
        d = a.WFAD()
        if not a.GetFileAttributesExW(ntpath.join(dh.path, name), 0, a.ct.byref(d)):
            return None
        return WinStat((d.size_hi << 32) | d.size_lo, _ft((d.mtime.hi << 32) | d.mtime.lo),
                       d.attrs)

    def listdir(self, dh):
        return os.listdir(dh.path)

    def _sa(self, sddl):
        """SECURITY_ATTRIBUTES of an SDDL string (LocalFree its descriptor after use)."""
        a = self.api
        psd = a.ct.c_void_p()
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, a.ct.byref(psd),
                                                                      None):
            raise a.fail('ConvertStringSecurityDescriptorToSecurityDescriptorW')
        sa = a.SA()
        sa.nLength = a.ct.sizeof(a.SA)
        sa.lpSecurityDescriptor = psd
        sa.bInheritHandle = False
        return sa, psd

    def write_new(self, dh, name, data, acl=None):
        """A new file (never one there: CREATE_NEW) with its security descriptor from the
        start - inherited (acl None), exactly a copy's (acl.sddl), or readers= (SIDs)."""
        a = self.api
        sddl = acl_sddl(acl)
        sa, psd = (self._sa(sddl) if sddl else (None, None))
        try:
            h = self._open(ntpath.join(dh.path, name), GENERIC_WRITE | DELETE, 0, CREATE_NEW,
                           ATTR_NORMAL | FLAG_WRITE_THROUGH | FLAG_OPEN_REPARSE_POINT,
                           a.ct.byref(sa) if sa is not None else None)
        finally:
            if psd:
                a.LocalFree(psd)
        try:
            view, n = memoryview(bytes(data)), a.wt.DWORD()
            while len(view):
                chunk = bytes(view[:1 << 20])
                if not a.WriteFile(h, chunk, len(chunk), a.ct.byref(n), None):
                    raise a.fail('WriteFile')
                view = view[n.value:]
            if not a.FlushFileBuffers(h):
                raise a.fail('FlushFileBuffers')
        finally:
            self._close(h)

    def rename(self, dh, src, dst):
        """src over dst in the same folder: atomic, the old one replaced, through to the disk."""
        a = self.api
        if not a.MoveFileExW(ntpath.join(dh.path, src), ntpath.join(dh.path, dst),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH):
            raise a.fail('MoveFileExW %s' % dst)

    def delete(self, dh, name):
        a = self.api
        if not a.DeleteFileW(ntpath.join(dh.path, name)):
            err = a.ct.get_last_error()
            if err in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                raise FileNotFoundError(err, name)
            raise a.fail('DeleteFileW %s' % name, err)

    def read_checked(self, path, most):
        """(bytes | None, its SDDL, its folder's SDDL, 'file' | 'missing' | 'link' | 'other')
        - the file opened without following a reparse point and checked on its handle."""
        try:
            h = self._open(path, GENERIC_READ | READ_CONTROL, SHARE_READ, OPEN_EXISTING,
                           FLAG_OPEN_REPARSE_POINT | FLAG_BACKUP_SEMANTICS)
        except WinFail as e:
            if e.errno in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                return None, None, None, 'missing'
            raise
        try:
            info = self._info(h)
            if info.attrs & ATTR_REPARSE:
                return None, None, None, 'link'
            if info.attrs & ATTR_DIRECTORY:
                return None, None, None, 'other'
            sddl = self._sddl_of(h)
            data, _size, _i = self._read_handle(h, most)
        finally:
            self._close(h)
        return data, sddl, self.file_sd(ntpath.dirname(path)), 'file'

    def read_path(self, path, most=64 * 1024 * 1024):
        with open(path, 'rb') as f:
            return f.read(most)

    def file_sd(self, path):
        """The SDDL (owner, DACL) of a file or folder, or None."""
        try:
            h = self._open(path, READ_CONTROL, SHARE_READ | SHARE_WRITE, OPEN_EXISTING,
                           FLAG_BACKUP_SEMANTICS)
        except WinFail:
            return None
        try:
            return self._sddl_of(h)
        finally:
            self._close(h)

    def set_sd(self, path, sddl):
        """The owner and the DACL of `sddl` set on a file or folder (protected when it says P;
        the folder's children inherit what it passes on)."""
        a = self.api
        sa, psd = self._sa(sddl)
        try:
            present, dacl, dflt = a.wt.BOOL(), a.ct.c_void_p(), a.wt.BOOL()
            if not a.GetSecurityDescriptorDacl(psd, a.ct.byref(present), a.ct.byref(dacl),
                                               a.ct.byref(dflt)):
                raise a.fail('GetSecurityDescriptorDacl')
            owner, odflt = a.ct.c_void_p(), a.wt.BOOL()
            if not a.GetSecurityDescriptorOwner(psd, a.ct.byref(owner), a.ct.byref(odflt)):
                raise a.fail('GetSecurityDescriptorOwner')
            info = DACL_INFO | (PROTECTED_DACL_INFO if parse_sddl(sddl)['protected'] else
                                UNPROTECTED_DACL_INFO)
            if owner.value:
                info |= OWNER_INFO
            err = a.SetNamedSecurityInfoW(path, SE_FILE_OBJECT, info, owner if owner.value
                                          else None, None, dacl, None)
            if err:
                raise a.fail('SetNamedSecurityInfoW %s' % path, err)
        finally:
            a.LocalFree(psd)

    def set_owner(self, path, sid):
        self.set_sd(path, 'O:%s%s' % (sid, _dacl_part(self.file_sd(path))))

    def final_path(self, path):
        """The real path of `path` (links followed) as far as it is there, the rest as it is."""
        p = norm_win(path)
        head, tail = p, []
        while True:
            try:
                h = self._open(head, FILE_READ_ATTRIBUTES, SHARE_READ | SHARE_WRITE,
                               OPEN_EXISTING, FLAG_BACKUP_SEMANTICS)
            except WinFail:
                if len(head) <= 3:
                    return p
                head, last = ntpath.split(head)
                tail.insert(0, last)
                continue
            try:
                real = self._final(h)
            finally:
                self._close(h)
            return ntpath.join(real, *tail) if tail else real

    # -- accounts, tokens ------------------------------------------------------------------------
    def _sid_str(self, psid):
        a = self.api
        s = a.wt.LPWSTR()
        if not a.ConvertSidToStringSidW(psid, a.ct.byref(s)):
            raise a.fail('ConvertSidToStringSidW')
        try:
            return s.value
        finally:
            a.LocalFree(s)

    def lookup_sid(self, name):
        """An account's SID (S-1-...) by its name (IIS_IUSRS, NT SERVICE\\W3SVC, DOMAIN\\user)."""
        n = str(name or '').strip()
        if re.fullmatch(r'S-1-[0-9-]+', n):
            return n
        if n.upper().startswith('NT SERVICE\\'):
            return service_sid(n.split('\\', 1)[1])
        a = self.api
        cb, cd, use = a.wt.DWORD(0), a.wt.DWORD(0), a.wt.DWORD(0)
        a.LookupAccountNameW(None, n, None, a.ct.byref(cb), None, a.ct.byref(cd),
                             a.ct.byref(use))
        if not cb.value:
            raise a.fail('there is no account %s on this machine' % n)
        sid = a.ct.create_string_buffer(cb.value)
        dom = a.ct.create_unicode_buffer(cd.value + 1)
        if not a.LookupAccountNameW(None, n, sid, a.ct.byref(cb), dom, a.ct.byref(cd),
                                    a.ct.byref(use)):
            raise a.fail('there is no account %s on this machine' % n)
        return self._sid_str(sid)

    def _token_info(self, tok, cls):
        a = self.api
        n = a.wt.DWORD(0)
        a.GetTokenInformation(tok, cls, None, 0, a.ct.byref(n))
        if not n.value:
            raise a.fail('GetTokenInformation')
        buf = a.ct.create_string_buffer(n.value)
        if not a.GetTokenInformation(tok, cls, buf, n.value, a.ct.byref(n)):
            raise a.fail('GetTokenInformation')
        return buf

    def _who(self, tok):
        """{sid, elevated, admin} of a token."""
        a = self.api
        ubuf = self._token_info(tok, TOKEN_USER)        # user.Sid points into it: kept
        user = a.SID_AND_ATTRIBUTES.from_buffer(ubuf)
        sid = self._sid_str(user.Sid)
        elev = self._token_info(tok, TOKEN_ELEVATION)
        elevated = bool(struct.unpack('<I', elev.raw[:4])[0])
        groups = self._token_info(tok, TOKEN_GROUPS)
        count = struct.unpack('<I', groups.raw[:4])[0]
        off = a.ct.sizeof(a.ct.c_void_p)              # GroupCount, padded to the pointer
        arr = (a.SID_AND_ATTRIBUTES * count).from_buffer(groups, off)
        admin = False
        for g in arr:
            if self._sid_str(g.Sid) == ADMINS and g.Attributes & SE_GROUP_ENABLED and \
                    not g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY:
                admin = True
        return {'sid': sid, 'elevated': elevated, 'admin': admin or sid == SYSTEM}

    def _process_who(self, pid=None):
        a = self.api
        if pid is None:
            ph, own = a.GetCurrentProcess(), False
        else:
            ph = a.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not ph:
                raise a.fail('OpenProcess %d' % pid)
            own = True
        try:
            tok = a.wt.HANDLE()
            if not a.OpenProcessToken(ph, TOKEN_QUERY, a.ct.byref(tok)):
                raise a.fail('OpenProcessToken')
            try:
                return self._who(tok)
            finally:
                self._close(tok)
        finally:
            if own:
                self._close(ph)

    def current_sid(self):
        return self._process_who()['sid']

    def is_admin(self):
        """An elevated administrator (or SYSTEM): what `sudo` is on Linux."""
        try:
            if self.api.IsUserAnAdmin():
                return True
        except (OSError, AttributeError):
            pass
        try:
            w = self._process_who()
            return w['sid'] == SYSTEM or (w['admin'] and w['elevated'])
        except OSError:
            return False

    # -- services -----------------------------------------------------------------------------
    def _scm(self, access=SC_MANAGER_CONNECT):
        a = self.api
        h = a.OpenSCManagerW(None, None, access)
        if not h:
            raise a.fail('OpenSCManagerW')
        return h

    def _svc(self, name, access, scm=None):
        a = self.api
        mine = scm is None
        scm = scm or self._scm()
        try:
            h = a.OpenServiceW(scm, name, access)
            if not h:
                err = a.ct.get_last_error()
                if err == ERROR_SERVICE_DOES_NOT_EXIST:
                    raise WinFail(err, 'there is no service %s here' % name)
                raise a.fail('OpenServiceW %s' % name, err)
            return h
        finally:
            if mine:
                a.CloseServiceHandle(scm)

    def _status(self, h):
        a = self.api
        st, n = a.SERVICE_STATUS_PROCESS(), a.wt.DWORD()
        if not a.QueryServiceStatusEx(h, 0, a.ct.byref(st), a.ct.sizeof(st), a.ct.byref(n)):
            raise a.fail('QueryServiceStatusEx')
        return st.dwCurrentState

    def service_state(self, name):
        """'Running', 'Stopped' ... or None when there is no such service."""
        try:
            h = self._svc(name, SERVICE_QUERY_STATUS)
        except WinFail as e:
            if e.errno == ERROR_SERVICE_DOES_NOT_EXIST:
                return None
            raise
        try:
            return STATE_WORDS.get(self._status(h), '?')
        finally:
            self.api.CloseServiceHandle(h)

    def _wait(self, h, want, most):
        end = time.time() + most
        while time.time() < end:
            s = self._status(h)
            if s == want:
                return True
            if s == STOPPED and want == RUNNING:
                return False
            time.sleep(0.3)
        return False

    def service_start(self, name, wait=60):
        a = self.api
        h = self._svc(name, SERVICE_START | SERVICE_QUERY_STATUS)
        try:
            if not a.StartServiceW(h, 0, None):
                err = a.ct.get_last_error()
                if err != ERROR_SERVICE_ALREADY_RUNNING:
                    raise a.fail('StartServiceW %s' % name, err)
            if wait and not self._wait(h, RUNNING, wait):
                raise WinFail(0, '%s did not start in %d s (it is %s)' % (
                    name, wait, STATE_WORDS.get(self._status(h), '?')))
        finally:
            a.CloseServiceHandle(h)

    def service_stop(self, name, wait=60):
        a = self.api
        h = self._svc(name, SERVICE_STOP | SERVICE_QUERY_STATUS)
        try:
            st = a.SERVICE_STATUS()
            if not a.ControlService(h, CONTROL_STOP, a.ct.byref(st)):
                err = a.ct.get_last_error()
                if err != ERROR_SERVICE_NOT_ACTIVE:
                    raise a.fail('ControlService stop %s' % name, err)
            if wait and not self._wait(h, STOPPED, wait):
                raise WinFail(0, '%s did not stop in %d s' % (name, wait))
        finally:
            a.CloseServiceHandle(h)

    def service_dependents(self, name):
        """The services running that depend on `name` (and on those), in the order to stop
        them (EnumDependentServicesW gives the reverse of the start order)."""
        a, ct = self.api, self.api.ct
        h = self._svc(name, SERVICE_ENUMERATE_DEPENDENTS)
        try:
            need, count = a.wt.DWORD(0), a.wt.DWORD(0)
            if a.EnumDependentServicesW(h, SERVICE_ACTIVE, None, 0, ct.byref(need),
                                        ct.byref(count)):
                return []                               # none
            err = ct.get_last_error()
            if err != ERROR_MORE_DATA:
                raise a.fail('EnumDependentServicesW %s' % name, err)
            buf = ct.create_string_buffer(need.value)
            if not a.EnumDependentServicesW(h, SERVICE_ACTIVE, buf, need.value, ct.byref(need),
                                            ct.byref(count)):
                raise a.fail('EnumDependentServicesW %s' % name)
            arr = (a.ENUM_SERVICE_STATUSW * count.value).from_buffer(buf)
            return [x.lpServiceName for x in arr]
        finally:
            a.CloseServiceHandle(h)

    def service_restart(self, name, wait=60):
        """Restart-Service -Force: its running dependents stopped first, it restarted, they
        started again."""
        return restart_force(self, name, wait)

    def service_delete(self, name):
        a = self.api
        try:
            h = self._svc(name, DELETE | SERVICE_QUERY_STATUS)
        except WinFail as e:
            if e.errno == ERROR_SERVICE_DOES_NOT_EXIST:
                return False
            raise
        try:
            if not a.DeleteService(h):
                err = a.ct.get_last_error()
                if err != ERROR_SERVICE_MARKED_FOR_DELETE:
                    raise a.fail('DeleteService %s' % name, err)
            return True
        finally:
            a.CloseServiceHandle(h)

    def service_install(self, spec):
        """A service made, or the one there set to `spec`: {name, display, description,
        cmdline, account (None: LocalSystem), depends, sid_type ('restricted' |
        'unrestricted'), privileges ([...] | None), delayed, restart_ms}."""
        a, ct = self.api, self.api.ct
        deps = ''.join(d + '\0' for d in spec.get('depends') or []) + '\0'
        account = spec.get('account') or 'LocalSystem'
        scm = self._scm(SC_MANAGER_ALL_ACCESS)
        try:
            h = a.CreateServiceW(scm, spec['name'], spec['display'], SERVICE_ALL_ACCESS,
                                 SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                 SERVICE_ERROR_NORMAL, spec['cmdline'], None, None,
                                 ct.create_unicode_buffer(deps, len(deps)), account, None)
            if not h:
                err = ct.get_last_error()
                if err != ERROR_SERVICE_EXISTS:
                    raise a.fail('CreateServiceW %s' % spec['name'], err)
                h = self._svc(spec['name'], SERVICE_ALL_ACCESS, scm)
                if not a.ChangeServiceConfigW(h, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
                                              SERVICE_ERROR_NORMAL, spec['cmdline'], None, None,
                                              ct.create_unicode_buffer(deps, len(deps)),
                                              account, None, spec['display']):
                    raise a.fail('ChangeServiceConfigW %s' % spec['name'])
            try:
                self._config2(h, spec)
            finally:
                a.CloseServiceHandle(h)
        finally:
            a.CloseServiceHandle(scm)

    def _config2(self, h, spec):
        a, ct, wt = self.api, self.api.ct, self.api.wt

        def set2(level, obj, what):
            if not a.ChangeServiceConfig2W(h, level, ct.byref(obj)):
                raise a.fail('ChangeServiceConfig2W %s' % what)

        class DESC(ct.Structure):
            _fields_ = [('lpDescription', wt.LPWSTR)]

        class ONE(ct.Structure):
            _fields_ = [('value', wt.DWORD)]
        set2(CONFIG_DESCRIPTION, DESC(spec.get('description') or ''), 'description')
        acts = (a.SC_ACTION * 3)(*[a.SC_ACTION(SC_ACTION_RESTART, int(spec.get('restart_ms') or
                                                                      5000))] * 3)
        fa = a.SERVICE_FAILURE_ACTIONSW(86400, None, None, 3,
                                        ct.cast(acts, ct.POINTER(a.SC_ACTION)))
        set2(CONFIG_FAILURE_ACTIONS, fa, 'failure actions')
        set2(CONFIG_FAILURE_ACTIONS_FLAG, ONE(1), 'failure actions flag')
        set2(CONFIG_DELAYED_AUTO_START, ONE(1 if spec.get('delayed') else 0), 'delayed start')
        set2(CONFIG_SERVICE_SID_INFO, ONE(SID_TYPE_RESTRICTED if spec.get('sid_type') ==
                                          'restricted' else SID_TYPE_UNRESTRICTED), 'service SID')
        privs = spec.get('privileges')
        if privs:
            ms = ''.join(p + '\0' for p in privs) + '\0'
            buf = ct.create_unicode_buffer(ms, len(ms))

            class PRIV(ct.Structure):
                _fields_ = [('pmszRequiredPrivileges', ct.c_void_p)]
            set2(CONFIG_REQUIRED_PRIVILEGES, PRIV(ct.cast(buf, ct.c_void_p)), 'privileges')

    def service_config(self, name):
        return None                     # what a test of the fake reads; Windows: sc qc

    # -- the named pipe ------------------------------------------------------------------------
    def pipe_server(self, name, sddl):
        return _RealPipeServer(self, name, sddl)

    def pipe_connect(self, name, timeout=900):
        a = self.api
        end = time.time() + min(timeout, 30)
        quick = time.time() + 3
        while True:
            try:
                # read, and write data - not GENERIC_WRITE, which on a pipe would include
                # FILE_CREATE_PIPE_INSTANCE (a server of the same name)
                h = self._open(name, GENERIC_READ | FILE_WRITE_DATA, 0, OPEN_EXISTING,
                               SQOS_PRESENT | SECURITY_IDENTIFICATION)
                return _RealPipe(self, h)
            except WinFail as e:
                if e.errno == 231 and time.time() < end:    # ERROR_PIPE_BUSY
                    a.WaitNamedPipeW(name, 2000)
                elif e.errno == ERROR_FILE_NOT_FOUND and time.time() < quick:
                    time.sleep(0.05)        # between two instances of the root side's pipe
                else:
                    raise

    # -- the event log -------------------------------------------------------------------------
    def event_source_add(self):
        import winreg
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, EVENT_KEY, 0,
                                winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, 'EventMessageFile', 0, winreg.REG_EXPAND_SZ,
                              r'%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319'
                              r'\EventLogMessages.dll')
            winreg.SetValueEx(k, 'TypesSupported', 0, winreg.REG_DWORD, 7)

    def event_source_remove(self):
        import winreg
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, EVENT_KEY)
        except OSError:
            pass

    def event(self, ok, text, warn=False):
        a = self.api
        h = a.RegisterEventSourceW(None, EVENT_SOURCE)
        if not h:
            return False
        try:
            arr = (a.wt.LPCWSTR * 1)(str(text)[:30000])
            kind = EVENTLOG_INFORMATION if ok and not warn else (EVENTLOG_WARNING if ok or warn
                                                                  else EVENTLOG_ERROR)
            return bool(a.ReportEventW(h, kind, 0, 1000 if ok else 1001, None, 1, 0, arr, None))
        finally:
            a.DeregisterEventSource(h)

    # -- firewall, PATH, what Windows this is -------------------------------------------------
    def _netsh(self, args):
        exe = ntpath.join(self.system_root(), 'System32', 'netsh.exe')
        got = subprocess.run([exe, 'advfirewall', 'firewall'] + args, capture_output=True,
                             stdin=subprocess.DEVNULL, timeout=60,
                             creationflags=CREATE_NO_WINDOW)
        return got.returncode, (got.stdout or b'').decode('utf-8', 'replace')

    def firewall_set(self, port, remote, program):
        """The passive port's inbound rule - only this one (the ones before taken away)."""
        self.firewall_remove()
        rc, out = self._netsh(['add', 'rule', 'name=' + FIREWALL % int(port), 'dir=in',
                               'action=allow', 'protocol=TCP', 'localport=%d' % int(port),
                               'remoteip=' + (','.join(remote) if remote else 'any'),
                               'program=' + program, 'profile=any', 'enable=yes'])
        if rc != 0:
            raise WinFail(rc, 'netsh: %s' % out.strip()[-200:])

    def firewall_remove(self):
        for port in self._rule_ports():
            self._netsh(['delete', 'rule', 'name=' + FIREWALL % port])

    def _rule_ports(self):
        rc, out = self._netsh(['show', 'rule', 'name=all'])
        return sorted({int(m) for m in re.findall(r'acme-agent \(passive, TCP (\d+)\)', out)})

    def firewall_rules(self):
        return {FIREWALL % p: {} for p in self._rule_ports()}

    def _path_get(self):
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ENV_KEY, 0, winreg.KEY_READ) as k:
            v, kind = winreg.QueryValueEx(k, 'Path')
        return v, kind

    def _path_set(self, value, kind):
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ENV_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, 'Path', 0, kind, value)
        a = self.api
        res = a.ct.c_size_t()
        a.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 'Environment',
                              SMTO_ABORTIFHUNG, 5000, a.ct.byref(res))

    def path_get(self):
        return self._path_get()[0]

    def path_add(self, folder):
        v, kind = self._path_get()
        parts = [x for x in v.split(';') if x]
        if folder.rstrip('\\').lower() in [x.rstrip('\\').lower() for x in parts]:
            return False
        self._path_set(';'.join(parts + [folder]), kind)
        return True

    def path_remove(self, folder):
        v, kind = self._path_get()
        parts = [x for x in v.split(';') if x]
        keep = [x for x in parts if x.rstrip('\\').lower() != folder.rstrip('\\').lower()]
        if keep != parts:
            self._path_set(';'.join(keep), kind)
            return True
        return False

    def os_name(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, OS_KEY, 0, winreg.KEY_READ) as k:
                def get(n, d=''):
                    try:
                        return winreg.QueryValueEx(k, n)[0]
                    except OSError:
                        return d
                return _os_words(get('ProductName', 'Windows'), get('CurrentBuild', '?'),
                                 get('CurrentMajorVersionNumber', 10),
                                 get('CurrentMinorVersionNumber', 0))
        except OSError:
            return 'Windows'

    # -- processes -----------------------------------------------------------------------------
    def run(self, argv, env, cwd, timeout):
        """argv by CreateProcess (never a shell) -> (exit code, stdout, stderr)."""
        got = subprocess.run(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=timeout,
                             creationflags=CREATE_NO_WINDOW)
        return got.returncode, got.stdout, got.stderr

    def spawn_detached(self, argv):
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True,
                         creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP |
                         CREATE_NO_WINDOW)

    # -- the service host ------------------------------------------------------------------------
    def service_host(self, name, run, stop):
        """This process as the Windows service `name`: StartServiceCtrlDispatcherW; its
        ServiceMain reports running and runs `run` (in a thread of its own); a stop or the
        machine's shutdown calls `stop` (the graceful end Linux does on SIGTERM) and waits for
        `run` to end (reporting it stops, at most five minutes) - then stopped."""
        a, ct = self.api, self.api.ct
        st = a.SERVICE_STATUS()
        st.dwServiceType = SERVICE_WIN32_OWN_PROCESS
        box = {'h': None, 'rc': 0}
        stopping = threading.Event()

        def report(state, wait=0, rc=0):
            st.dwCurrentState = state
            st.dwControlsAccepted = 0 if state in (START_PENDING, STOP_PENDING) else \
                ACCEPT_STOP | ACCEPT_SHUTDOWN
            st.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR if rc else 0
            st.dwServiceSpecificExitCode = rc if rc else 0
            st.dwWaitHint = wait
            st.dwCheckPoint = st.dwCheckPoint + 1 if state in (START_PENDING, STOP_PENDING) \
                else 0
            if box['h']:
                a.SetServiceStatus(box['h'], ct.byref(st))

        def on_control(ctl, _etype, _edata, _ctx):
            if ctl in (CONTROL_STOP, CONTROL_SHUTDOWN):
                report(STOP_PENDING, 30000)
                if not stopping.is_set():
                    stopping.set()
                    threading.Thread(target=stop, daemon=True).start()
                return 0
            if ctl == CONTROL_INTERROGATE:
                return 0
            return 120                                  # ERROR_CALL_NOT_IMPLEMENTED
        handler = a.HANDLER_EX(on_control)

        def go():
            try:
                box['rc'] = int(run() or 0)
            except SystemExit as e:
                box['rc'] = e.code if isinstance(e.code, int) else (1 if e.code else 0)
            except BaseException:                       # noqa: BLE001
                box['rc'] = 1

        def service_main(_argc, _argv):
            box['h'] = a.RegisterServiceCtrlHandlerExW(name, handler, None)
            if not box['h']:
                return
            report(START_PENDING, 10000)
            t = threading.Thread(target=go, daemon=True)
            t.start()
            report(RUNNING)
            since = None
            while t.is_alive():
                t.join(5)
                if stopping.is_set():
                    since = since or time.time()
                    if time.time() - since > 300:
                        break
                    report(STOP_PENDING, 30000)
            report(STOPPED, rc=box['rc'] if not stopping.is_set() else 0)
        main = a.MAIN(service_main)
        table = (a.SERVICE_TABLE_ENTRYW * 2)()
        table[0].lpServiceName = name
        table[0].lpServiceProc = main
        if not a.StartServiceCtrlDispatcherW(table):
            err = ct.get_last_error()
            if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
                raise SystemExit('acme-agent winservice is what the service %s runs - start it '
                                 'so: Start-Service %s' % (name, name))
            raise a.fail('StartServiceCtrlDispatcherW', err)
        return box['rc']


class _RealPipe(object):
    """One end of the named pipe: what the link reads and writes (recv, sendall)."""

    def __init__(self, win, h, server=False):
        self.win, self.h, self.server = win, h, server

    def settimeout(self, _t):
        pass                    # a blocking pipe; the other end closing ends a read

    def recv(self, n):
        a = self.win.api
        buf, got = a.ct.create_string_buffer(n), a.wt.DWORD()
        if not a.ReadFile(self.h, buf, n, a.ct.byref(got), None):
            err = a.ct.get_last_error()
            if err in (ERROR_BROKEN_PIPE, ERROR_NO_DATA):
                return b''
            raise a.fail('ReadFile (pipe)', err)
        return buf.raw[:got.value]

    def sendall(self, data):
        a = self.win.api
        view, n = memoryview(bytes(data)), a.wt.DWORD()
        while len(view):
            chunk = bytes(view[:65536])
            if not a.WriteFile(self.h, chunk, len(chunk), a.ct.byref(n), None):
                raise a.fail('WriteFile (pipe)')
            view = view[n.value:]

    def peer(self):
        """{sid, elevated, admin} of the process at the other end (its token)."""
        a = self.win.api
        pid = a.wt.ULONG()
        if not a.GetNamedPipeClientProcessId(self.h, a.ct.byref(pid)):
            raise a.fail('GetNamedPipeClientProcessId')
        who = self.win._process_who(pid.value)
        who['pid'] = pid.value
        return who

    def close(self):
        if self.h:
            if self.server:
                self.win.api.FlushFileBuffers(self.h)
                self.win.api.DisconnectNamedPipe(self.h)
            self.win._close(self.h)
            self.h = None


class _RealPipeServer(object):
    """\\\\.\\pipe\\NAME with a DACL (SDDL): the first instance made with
    FILE_FLAG_FIRST_PIPE_INSTANCE (nobody else holds the name), remote clients refused."""

    def __init__(self, win, name, sddl):
        self.win, self.name, self.sddl = win, name, sddl
        self.first, self.closed = True, False

    def accept(self):
        a = self.win.api
        if self.closed:
            raise OSError('the pipe is closed')
        sa, psd = self.win._sa(self.sddl)
        try:
            h = a.CreateNamedPipeW(self.name, PIPE_ACCESS_DUPLEX |
                                   (FIRST_PIPE_INSTANCE if self.first else 0),
                                   PIPE_REJECT_REMOTE_CLIENTS, 255, 65536, 65536, 0,
                                   a.ct.byref(sa))
        finally:
            a.LocalFree(psd)
        if h is None or h == a.INVALID:
            raise a.fail('CreateNamedPipeW %s' % self.name)
        self.first = False
        if not a.ConnectNamedPipe(h, None):
            err = a.ct.get_last_error()
            if err != ERROR_PIPE_CONNECTED:
                self.win._close(h)
                raise a.fail('ConnectNamedPipe', err)
        if self.closed:
            self.win._close(h)
            raise OSError('the pipe is closed')
        return _RealPipe(self.win, h, server=True)

    def close(self):
        """No more connections: the one waiting in accept() released (a connection of our own)."""
        if self.closed:
            return
        self.closed = True
        try:
            self.win.pipe_connect(self.name, 2).close()
        except OSError:
            pass


# ---- the tests' Windows: C:\... in a folder, the rest as JSON beside it ------------------------
FAKE_ADMIN = 'S-1-5-21-1111111111-2222222222-3333333333-500'
FAKE_ROOT_SD = 'O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
FAKE_ACCOUNTS = {'system': SYSTEM, 'nt authority\\system': SYSTEM, 'localsystem': SYSTEM,
                 'administrators': ADMINS, 'builtin\\administrators': ADMINS,
                 'users': USERS, 'builtin\\users': USERS,
                 'iis_iusrs': 'S-1-5-32-568', 'builtin\\iis_iusrs': 'S-1-5-32-568',
                 'network service': 'S-1-5-20', 'nt authority\\network service': 'S-1-5-20',
                 'local service': 'S-1-5-19', 'nt authority\\local service': 'S-1-5-19',
                 'everyone': 'S-1-1-0', 'authenticated users': 'S-1-5-11',
                 'nt authority\\authenticated users': 'S-1-5-11',
                 'nt service\\trustedinstaller': TRUSTED_INSTALLER}


class FakeWin(object):
    """Windows as the tests have it (ACME_AGENT_FAKE_WINDOWS=1): C:\\x\\y is
    $ACME_AGENT_FAKE_ROOT/C/x/y (names found whatever their case), a symbolic link is a reparse
    point; ACLs (SDDL, inherited as Windows does), services, the event log, the registry's few
    values and the firewall's rules are JSON files in $ACME_AGENT_FAKE_ROOT/.fakewin; the named
    pipe is a Unix socket there, its client's account the ACME_AGENT_FAKE_SID (and
    ACME_AGENT_FAKE_ELEVATED) of the process at the other end."""
    fake = True

    def __init__(self, root=None):
        self.root = os.path.abspath(root or os.environ.get('ACME_AGENT_FAKE_ROOT') or
                                    os.path.join(tempfile.gettempdir(), 'acme-agent-fakewin'))
        self.meta = os.path.join(self.root, '.fakewin')
        os.makedirs(os.path.join(self.root, 'C'), exist_ok=True)
        os.makedirs(self.meta, exist_ok=True)

    # -- its JSON files, one writer at a time ---------------------------------------------------
    def _path(self, name):
        return os.path.join(self.meta, name)

    def load(self, name, default):
        try:
            with open(self._path(name)) as f:
                got = json.load(f)
        except (OSError, ValueError):
            return default
        return got if isinstance(got, type(default)) else default

    def _update(self, name, default, fn):
        import fcntl
        with open(self._path(name + '.lock'), 'a') as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            got = self.load(name, default)
            out = fn(got)
            tmp = self._path(name + '.%s' % secrets.token_hex(4))
            with open(tmp, 'w') as f:
                json.dump(got, f, indent=1, sort_keys=True)
            os.replace(tmp, self._path(name))
            return out

    def _log(self, name, obj):
        with open(self._path(name), 'a') as f:
            f.write(json.dumps(obj, sort_keys=True) + '\n')

    def lines(self, name):
        out = []
        try:
            with open(self._path(name)) as f:
                for line in f:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass
        return out

    # -- where things are -------------------------------------------------------------------
    @staticmethod
    def _child(folder, name):
        p = os.path.join(folder, name)
        if os.path.lexists(p):
            return p
        try:
            for n in os.listdir(folder):
                if n.lower() == name.lower():
                    return os.path.join(folder, n)
        except OSError:
            pass
        return p

    def local(self, path):
        """C:\\x\\y -> its place in the fake (a path that is not C:\\... as it is)."""
        p = str(path or '').replace('/', '\\')
        m = re.match(r'([A-Za-z]):\\?(.*)\Z', p, re.S)
        if not m:
            return path
        here = os.path.join(self.root, m.group(1).upper())
        for comp in [x for x in m.group(2).split('\\') if x]:
            here = self._child(here, comp)
        return here

    def winpath(self, local):
        """A path of the fake -> C:\\..., or None for one outside it."""
        rp = os.path.abspath(str(local))
        if rp != self.root and not rp.startswith(self.root + os.sep):
            return None
        rest = [x for x in rp[len(self.root):].split(os.sep) if x]
        if not rest or not re.fullmatch(r'[A-Z]', rest[0]):
            return None
        return rest[0] + ':\\' + '\\'.join(rest[1:])

    def system_root(self):
        return 'C:\\Windows'

    def system_drive(self):
        return 'C:'

    def program_data(self):
        return 'C:\\ProgramData'

    def program_files(self):
        return 'C:\\Program Files'

    def program_files_x86(self):
        return 'C:\\Program Files (x86)'

    def powershell(self):
        return 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'

    def openssl_default(self, lib):
        return shutil.which('openssl') or 'openssl'

    # -- files and folders --------------------------------------------------------------------
    def open_dir(self, path, make_from=None):
        p = norm_win(path)
        here = os.path.join(self.root, p[0])
        walked = p[:3]
        mk = (make_from or '').rstrip('\\').lower()
        for comp in [x for x in p[3:].split('\\') if x]:
            walked = ntpath.join(walked, comp)
            nxt = self._child(here, comp)
            if os.path.islink(nxt):
                raise Refused('%s is a symbolic link, a junction or a mount point (a reparse '
                              'point) - refused' % walked)
            if not os.path.lexists(nxt):
                if not mk or not (walked.lower() + '\\').startswith(mk + '\\'):
                    raise Refused('%s is not there' % walked)
                os.mkdir(nxt)
            if not os.path.isdir(nxt):
                raise Refused('%s is not a folder' % walked)
            here = nxt
        return DirH(walked, local=here)

    def dup(self, dh):
        dh.refs += 1
        return dh

    def close(self, dh):
        dh.refs -= 1

    def open_sub(self, dh, name, make=False):
        p = self._child(dh.local, name)
        if make and not os.path.lexists(p):
            os.mkdir(p)
        if os.path.islink(p):
            raise WinFail(5, '%s is a reparse point' % name)
        if not os.path.lexists(p):
            raise FileNotFoundError(2, name)
        if not os.path.isdir(p):
            raise WinFail(5, '%s is not a folder' % name)
        return DirH(ntpath.join(dh.path, name), local=p)

    def _key(self, winpath):
        return str(winpath).rstrip('\\').lower()

    def _eff(self, p, acl):
        own = acl.get(self._key(p))
        if own and parse_sddl(own)['protected']:
            return own
        if len(p.rstrip('\\')) <= 2:
            return own or FAKE_ROOT_SD
        parent = ntpath.dirname(p.rstrip('\\'))
        psd = parse_sddl(self._eff(parent, acl))
        folder = os.path.isdir(self.local(p))
        aces = []
        if own:
            aces += ['(%s;%s;0x%x;;;%s)' % (a['type'], a['flags'], a['mask'], a['sid'])
                     for a in parse_sddl(own)['aces']]
        for a in psd['aces']:
            fl = _flags(a['flags'])
            if ('CI' in fl) if folder else ('OI' in fl):
                nf = ''.join(['ID'] + ([x for x in fl if x in ('OI', 'CI')] if folder else []))
                aces.append('(%s;%s;0x%x;;;%s)' % (a['type'], nf, a['mask'], a['sid']))
        owner = parse_sddl(own)['owner'] if own else SYSTEM
        return 'O:%sD:%s' % (owner or SYSTEM, ''.join(aces))

    def file_sd(self, path):
        p = norm_win(path)
        if len(p) > 3 and not os.path.lexists(self.local(p)):
            return None
        return self._eff(p, self.load('acl.json', {}))

    def set_sd(self, path, sddl):
        p = norm_win(path)

        def go(acl):
            acl[self._key(p)] = sddl
        self._update('acl.json', {}, go)

    def set_owner(self, path, sid):
        p = norm_win(path)
        own = self.load('acl.json', {}).get(self._key(p))
        self.set_sd(p, 'O:%s%s' % (sid, _dacl_part(own) if own else 'D:'))

    def _acl_move(self, src, dst):
        def go(acl):
            v = acl.pop(self._key(src), None)
            acl.pop(self._key(dst), None)
            if dst and v is not None:
                acl[self._key(dst)] = v
        self._update('acl.json', {}, go)

    def read_file(self, dh, name, most):
        p = self._child(dh.local, name)
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            return None, None
        if stat.S_ISLNK(st.st_mode):
            raise Refused('%s is a symbolic link (a reparse point) - refused' % name)
        if not stat.S_ISREG(st.st_mode):
            raise Refused('%s is not a plain file' % name)
        if st.st_size > most:
            raise Refused('%s is bigger than %d bytes' % (name, most))
        with open(p, 'rb') as f:
            data = f.read(most + 1)
        return data, WinStat(st.st_size, st.st_mtime, 0x20,
                             self.file_sd(ntpath.join(dh.path, name)), st.st_nlink)

    def stat(self, dh, name):
        try:
            st = os.lstat(self._child(dh.local, name))
        except OSError:
            return None
        attrs = 0x400 if stat.S_ISLNK(st.st_mode) else (0x10 if stat.S_ISDIR(st.st_mode)
                                                        else 0x20)
        return WinStat(st.st_size, st.st_mtime, attrs)

    def listdir(self, dh):
        return os.listdir(dh.local)

    def write_new(self, dh, name, data, acl=None):
        fd = os.open(os.path.join(dh.local, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(bytes(data))
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        sddl = acl_sddl(acl)
        key = self._key(ntpath.join(dh.path, name))

        def go(a):
            if sddl:
                a[key] = sddl
            else:
                a.pop(key, None)
        self._update('acl.json', {}, go)

    def rename(self, dh, src, dst):
        d = self._child(dh.local, dst)
        if os.path.isdir(d) and not os.path.islink(d):
            raise IsADirectoryError(21, dst)
        os.rename(self._child(dh.local, src), d)
        self._acl_move(ntpath.join(dh.path, src), ntpath.join(dh.path, dst))

    def delete(self, dh, name):
        p = self._child(dh.local, name)
        if os.path.isdir(p) and not os.path.islink(p):
            raise IsADirectoryError(21, name)
        os.unlink(p)
        self._acl_move(ntpath.join(dh.path, name), None)

    def read_checked(self, path, most):
        w = self.winpath(path)
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None, None, None, 'missing'
        if stat.S_ISLNK(st.st_mode):
            return None, None, None, 'link'
        if not stat.S_ISREG(st.st_mode):
            return None, None, None, 'other'
        with open(path, 'rb') as f:
            data = f.read(most + 1)
        if w is None:                   # a place of the tests' own, outside C:\
            ok = 'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'
            return data, ok, ok, 'file'
        return data, self.file_sd(w), self.file_sd(ntpath.dirname(w)), 'file'

    def read_path(self, path, most=64 * 1024 * 1024):
        with open(self.local(path), 'rb') as f:
            return f.read(most)

    def final_path(self, path):
        p = norm_win(path)
        real = self.winpath(os.path.realpath(self.local(p)))
        return real or p

    # -- accounts, tokens ------------------------------------------------------------------------
    def lookup_sid(self, name):
        n = str(name or '').strip()
        if re.fullmatch(r'S-1-[0-9-]+', n):
            return n
        if n.lower().startswith('nt service\\'):
            return service_sid(n.split('\\', 1)[1])
        more = self.load('accounts.json', {})
        sid = FAKE_ACCOUNTS.get(n.lower()) or more.get(n.lower())
        if not sid:
            raise WinFail(1332, 'there is no account %s on this machine' % n)
        return sid

    @staticmethod
    def _who_env(env):
        sid = env.get('ACME_AGENT_FAKE_SID') or FAKE_ADMIN
        elevated = env.get('ACME_AGENT_FAKE_ELEVATED', '1') != '0'
        admin = sid == SYSTEM or (elevated and not sid.startswith('S-1-5-80-') and
                                  sid not in ('S-1-5-19', 'S-1-5-20'))
        return {'sid': sid, 'elevated': elevated or sid == SYSTEM, 'admin': admin}

    def current_sid(self):
        return self._who_env(os.environ)['sid']

    def is_admin(self):
        return self._who_env(os.environ)['admin']

    # -- services -----------------------------------------------------------------------------
    def _svc_do(self, name, verb):
        self._log('services.log', {'verb': verb, 'name': name})

        def go(svcs):
            s = svcs.get(name.lower())
            if s is None:
                raise WinFail(ERROR_SERVICE_DOES_NOT_EXIST, 'there is no service %s here' % name)
            if verb in ('start', 'restart') and s.get('broken'):
                s['state'] = 'Stopped'
                raise WinFail(1053, '%s did not start (it is Stopped)' % name)
            if verb == 'stop':
                up = [d for d in self._dependents(svcs, name) if svcs[d].get('state') ==
                      'Running']
                if up:
                    # as Windows: ERROR_DEPENDENT_SERVICES_RUNNING
                    raise WinFail(ERROR_DEPENDENT_SERVICES_RUNNING, '%s cannot be stopped: '
                                  'services that depend on it run (%s)' % (name, ', '.join(up)))
            s['state'] = 'Stopped' if verb == 'stop' else 'Running'
            if verb != 'stop':
                s['times'] = s.get('times', 0) + 1
        self._update('services.json', {}, go)

    def service_state(self, name):
        s = self.load('services.json', {}).get(str(name).lower())
        return None if s is None else s.get('state') or 'Stopped'

    def service_start(self, name, wait=60):
        self._svc_do(name, 'start')

    def service_stop(self, name, wait=60):
        self._svc_do(name, 'stop')

    @staticmethod
    def _dependents(svcs, name):
        """Keys of the services depending on `name` (and on those), the deepest first."""
        out = []

        def walk(n):
            for k, s in sorted(svcs.items()):
                if n.lower() in [str(d).lower() for d in s.get('depends') or []] and k not in out:
                    walk(k)
                    out.append(k)
        walk(name)
        return out

    def service_dependents(self, name):
        svcs = self.load('services.json', {})
        if str(name).lower() not in svcs:
            raise WinFail(ERROR_SERVICE_DOES_NOT_EXIST, 'there is no service %s here' % name)
        return [svcs[k].get('name') or k for k in self._dependents(svcs, name)
                if svcs[k].get('state') == 'Running']

    def service_restart(self, name, wait=60):
        return restart_force(self, name, wait)

    def service_delete(self, name):
        def go(svcs):
            return svcs.pop(str(name).lower(), None) is not None
        self._log('services.log', {'verb': 'delete', 'name': name})
        return self._update('services.json', {}, go)

    def service_install(self, spec):
        def go(svcs):
            old = svcs.get(spec['name'].lower()) or {}
            svcs[spec['name'].lower()] = dict(spec, state=old.get('state') or 'Stopped')
        self._log('services.log', {'verb': 'install', 'name': spec['name']})
        self._update('services.json', {}, go)

    def service_config(self, name):
        return self.load('services.json', {}).get(str(name).lower())

    # -- the named pipe: a Unix socket ---------------------------------------------------------
    def _pipe_path(self, name):
        d = os.path.join(self.meta, 'pipes')
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, str(name).rsplit('\\', 1)[-1])

    def pipe_server(self, name, sddl):
        p = self._pipe_path(name)
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(p)
        srv.listen(16)

        def go(pipes):
            pipes[name] = sddl
        self._update('pipes.json', {}, go)
        return _FakePipeServer(srv)

    def pipe_connect(self, name, timeout=900):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self._pipe_path(name))
        except OSError:
            s.close()
            raise
        return _FakePipe(s)

    # -- the event log, firewall, PATH, the registry ------------------------------------------
    def event_source_add(self):
        self._update('registry.json', {}, lambda r: r.__setitem__('eventsource', True))

    def event_source_remove(self):
        self._update('registry.json', {}, lambda r: r.pop('eventsource', None))

    def event(self, ok, text, warn=False):
        self._log('eventlog.jsonl', {'source': EVENT_SOURCE, 'level': 'Information' if ok and
                                     not warn else ('Warning' if ok or warn else 'Error'),
                                     'text': str(text)})
        return True

    def firewall_set(self, port, remote, program):
        def go(fw):
            for k in [k for k in fw if k.startswith(FIREWALL_PREFIX)]:
                del fw[k]
            fw[FIREWALL % int(port)] = {'port': int(port), 'remote': list(remote or []) or
                                        ['any'], 'program': program}
        self._update('firewall.json', {}, go)

    def firewall_remove(self):
        def go(fw):
            for k in [k for k in fw if k.startswith(FIREWALL_PREFIX)]:
                del fw[k]
        self._update('firewall.json', {}, go)

    def firewall_rules(self):
        return self.load('firewall.json', {})

    def path_get(self):
        return self.load('registry.json', {}).get('Path') or 'C:\\Windows\\system32;C:\\Windows'

    def path_add(self, folder):
        def go(r):
            parts = [x for x in (r.get('Path') or 'C:\\Windows\\system32;C:\\Windows').split(';')
                     if x]
            if folder.rstrip('\\').lower() in [x.rstrip('\\').lower() for x in parts]:
                return False
            r['Path'] = ';'.join(parts + [folder])
            return True
        return self._update('registry.json', {}, go)

    def path_remove(self, folder):
        def go(r):
            parts = [x for x in (r.get('Path') or '').split(';') if x]
            keep = [x for x in parts if x.rstrip('\\').lower() != folder.rstrip('\\').lower()]
            r['Path'] = ';'.join(keep)
            return keep != parts
        return self._update('registry.json', {}, go)

    def os_name(self):
        o = self.load('registry.json', {}).get('os') or ['Windows Server 2022 Standard', '20348',
                                                          10, 0]
        return _os_words(*o)

    # -- processes -----------------------------------------------------------------------------
    def _argv(self, argv):
        a = list(argv)
        if a and re.match(r'[A-Za-z]:[\\/]', a[0]):
            a[0] = self.local(a[0])
        return a

    def run(self, argv, env, cwd, timeout):
        env = dict(env or {})
        env['PATH'] = os.environ.get('PATH', '/usr/bin:/bin')
        c = self.local(cwd) if cwd and re.match(r'[A-Za-z]:', cwd) else cwd
        got = subprocess.run(self._argv(argv), env=env, cwd=c if c and os.path.isdir(c) else None,
                             stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        return got.returncode, got.stdout, got.stderr

    def spawn_detached(self, argv):
        self._log('services.log', {'verb': 'spawn', 'name': ' '.join(argv[-2:])})
        subprocess.Popen(self._argv(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)

    def service_host(self, name, run, stop):
        """The service host of the fake: `run` here, SIGTERM (what the tests send) -> `stop`."""
        import signal

        def bye(*_):
            stop()
        signal.signal(signal.SIGTERM, bye)
        signal.signal(signal.SIGINT, bye)
        self._log('services.log', {'verb': 'host', 'name': name})
        return run()


class _FakePipe(object):
    def __init__(self, sock):
        self.sock = sock

    def settimeout(self, t):
        self.sock.settimeout(t)

    def recv(self, n):
        return self.sock.recv(n)

    def sendall(self, data):
        self.sock.sendall(data)

    def peer(self):
        """The account of the process at the other end: its ACME_AGENT_FAKE_SID (and
        ..._ELEVATED) - what Windows says of its token."""
        cred = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        pid = struct.unpack('3i', cred)[0]
        if pid == os.getpid():
            env = dict(os.environ)
        else:
            env = {}
            try:
                with open('/proc/%d/environ' % pid, 'rb') as f:
                    for kv in f.read().split(b'\0'):
                        k, _, v = kv.partition(b'=')
                        env[k.decode('utf-8', 'replace')] = v.decode('utf-8', 'replace')
            except OSError:
                pass
        who = FakeWin._who_env(env)
        who['pid'] = pid
        return who

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class _FakePipeServer(object):
    def __init__(self, srv):
        self.srv = srv

    def accept(self):
        conn, _ = self.srv.accept()
        return _FakePipe(conn)

    def close(self):
        try:
            self.srv.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.srv.close()


W = FakeWin() if os.environ.get('ACME_AGENT_FAKE_WINDOWS') else RealWin()


# ==== what acme_agent.py does on Windows ========================================================
class _View(object):
    """acme_agent.py's names as they are when asked (the ones put in place here included)."""

    def __init__(self, g):
        self.__dict__['_g'] = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(name)


A = None                    # acme_agent.py's globals (a _View) - set by install()
ORIG = {}                   # its functions as they were (the Linux ones) where these wrap them
STOPPERS = []               # what the service host's stop calls (the end SIGTERM is on Linux)
SERVERS = []                # the passive servers running (a stop shuts them down)
UNDER_HOST = {'on': False}


def stop_all():
    for cb in list(STOPPERS):
        try:
            cb()
        except Exception:                               # noqa: BLE001
            pass


def _in_main_thread():
    return threading.current_thread() is threading.main_thread()


# ---- where things are --------------------------------------------------------------------------
def base_dir():
    """C:\\ProgramData\\acme-agent (its place in the fake under the tests)."""
    return W.local(ntpath.join(W.program_data(), 'acme-agent'))


def program_dir():
    """The program's folder as Windows names it (C:\\Program Files\\acme-agent)."""
    return W.winpath(A.lib_dir()) or ntpath.join(W.program_files(), 'acme-agent')


def own_places():
    """The agent's own places (Windows paths): never written by a job."""
    out = []
    for p in (A.ETC, A.STATE, A.ROOT_STATE, base_dir(), A.lib_dir()):
        w = W.winpath(p)
        if w and w.lower() not in [x.lower() for x in out]:
            out.append(w)
    for w in (ntpath.join(W.program_data(), 'acme-agent'),
              ntpath.join(W.program_files(), 'acme-agent')):
        if w.lower() not in [x.lower() for x in out]:
            out.append(w)
    return out


def protected_list():
    """What no job ever writes, whatever the policy says: Windows' own, the programs, what runs
    as SYSTEM or at a log-on (C:\\ProgramData\\Microsoft holds the Start Menu's StartUp), the
    profiles' AppData, OpenSSH's keys. `*` is any drive (X:\\...) or any user."""
    sd = W.system_drive()
    return [W.system_root(), W.program_files(), W.program_files_x86(),
            sd + '\\ProgramData\\Microsoft', sd + '\\ProgramData\\ssh', sd + '\\Boot',
            sd + '\\Recovery', sd + '\\Users\\*\\AppData', '*:\\$Recycle.Bin',
            '*:\\System Volume Information', '*:\\Windows', '*:\\$WinREAgent']


def _pattern(top):
    rx = re.escape(top.rstrip('\\').lower()).replace(r'\*', '[^\\\\]+')
    if rx.startswith('[^\\\\]+:'):
        rx = '[a-z]:' + rx[len('[^\\\\]+:'):]
    return re.compile(rx + r'(\\.*)?\Z', re.S)


def _under(path, top):
    """`path` is `top` or in it (case-insensitive; a drive's root holds nothing here, as / on
    Linux)."""
    t = str(top).rstrip('\\').lower()
    p = str(path).rstrip('\\').lower()
    if re.fullmatch(r'[a-z]:', t):
        return False
    return p == t or p.startswith(t + '\\')


def protected(path):
    """Why `path` is never written nor taken away by a job, whatever the policy says - or ''."""
    p = str(path)
    if re.fullmatch(r'[A-Za-z]:\\?', p):
        return '%s is a drive\'s root - acme-agent never writes there' % p
    for top in own_places():
        if _under(p, top):
            return '%s is acme-agent\'s own (%s) - never written by a job' % (p, top)
    for top in protected_list():
        if _pattern(top).match(p.lower()):
            return '%s is under %s - Windows runs (or loads) what is there; acme-agent never ' \
                   'writes there, whatever the policy says' % (p, top)
    parts = [x.lower() for x in p.split('\\')]
    if '.ssh' in parts:
        return '%s is in a .ssh folder - acme-agent never writes there' % p
    ext = ntpath.splitext(p)[1].lower()
    if ext in EXEC_EXT:
        return '%s: a file Windows runs or loads as a program (%s) - acme-agent never writes ' \
               'one (the analogue of the x bit)' % (p, ext)
    return ''


def norm_dir(path, real=True):
    p = norm_win(path)
    return W.final_path(p) if real else p


def norm_unit(name):
    n = str(name or '').strip()
    if not SVC_RE.match(n) or n.startswith('-'):
        raise Refused('%r is not a service name' % n[:80])
    return n.lower()


def split_path(path):
    d, name = ntpath.split(path)
    return d, name


def file_rule(pol, path):
    best = None
    p = str(path).lower()
    for f in pol['files']:
        d = f['dir'].rstrip('\\').lower()
        if p.startswith(d + '\\') and (best is None or len(d) > len(best['dir'])):
            best = f
    return best


def runs_from(pol, path):
    p = str(path).lower()
    for s in pol.get('scripts') or []:
        if s.get('path', '').lower() == p:
            return '%s is a script the policy runs - never written by a job' % path
    for argv in pol.get('tests') or []:
        for w in argv:
            if isinstance(w, str) and re.match(r'[A-Za-z]:[\\/]', w):
                try:
                    if norm_win(w).lower() == p:
                        return '%s is named by a test the policy runs (%s) - never written by a ' \
                               'job' % (path, ' '.join(wq(a) for a in argv)[:200])
                except Refused:
                    continue
    return ''


def _bad_argv0(argv):
    return bool(argv) and ntpath.splitext(str(argv[0]))[1].lower() in ('.bat', '.cmd')


def _shell_line(argv):
    """A test that is a shell or an interpreter given its program on its command line."""
    if not argv:
        return False
    prog = re.sub(r'\.exe\Z', '', ntpath.basename(argv[0]).lower())
    prog = re.sub(r'[0-9.]+\Z', '', prog) or prog
    rest = [a.lower() for a in argv[1:]]
    if prog == 'cmd':
        return any(a.startswith(('/c', '/k')) for a in rest)
    if prog in ('powershell', 'pwsh'):
        return any(a in ('-c', '-e', '-ec', '-enc') or a.startswith(('-comm', '-encodedc',
                                                                     '/c', '/e'))
                   for a in rest) or not any(a in ('-file', '-f') for a in rest)
    if prog in ('wscript', 'cscript', 'mshta', 'rundll32'):
        return True
    if prog in ('python', 'py', 'pythonw'):
        return any(a in ('-c', '-m') for a in rest)
    return False


# ---- the policy: the same words, Windows meanings ----------------------------------------------
def parse_policy(text):
    pol = {'files': [], 'units': {}, 'tests': [], 'scripts': [], 'script_hashes': [],
           'from': [], 'self_update': False, 'connect': [], 'probe': [], 'probe_local': False,
           'limits': {'files': A.FILES_MOST, 'size': A.FILE_MOST}, 'problems': []}
    for n, raw in enumerate(str(text or '').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        try:
            words = win_split(line)
        except ValueError as e:
            pol['problems'].append('line %d: %s' % (n, e))
            continue
        try:
            _policy_line(pol, words)
        except Refused as e:
            pol['problems'].append('line %d: %s' % (n, e))
    return pol


def _readers(text):
    out = []
    for r in [x.strip() for x in str(text or '').split(',')]:
        if not r:
            continue
        if not ACCOUNT_RE.match(r):
            raise Refused('%r is not an account (readers=IIS_IUSRS,"NT SERVICE\\W3SVC")' % r[:80])
        if r.lower() not in [x.lower() for x in out]:
            out.append(r)
    if len(out) > 16:
        raise Refused('readers= names sixteen accounts at most')
    return out


def _policy_line(pol, words):
    if not words or words[0] != 'allow' or len(words) < 2:
        return ORIG['_policy_line'](pol, words)
    what, rest = words[1], words[2:]
    if what == 'file':
        kv, rest = A._kv(rest, ('readers', 'owner', 'mode'))
        if 'owner' in kv or 'mode' in kv:
            raise Refused('owner= and mode= are not for Windows: a file gets its folder\'s '
                          'permissions, or with readers=ACCOUNT,... only SYSTEM, the '
                          'Administrators and those accounts may read it')
        if len(rest) != 1:
            raise Refused('allow file C:\\FOLDER [readers=ACCOUNT,ACCOUNT]')
        d = norm_dir(rest[0], real=False)
        if re.fullmatch(r'[A-Z]:\\', d):
            raise Refused('a drive\'s root is no folder to allow')
        readers = _readers(kv.get('readers'))
        entry = {'dir': d, 'owner': ','.join(readers), 'group': '', 'mode': 0o666,
                 'readers': readers}
        pol['files'] = [x for x in pol['files'] if x['dir'].lower() != d.lower()] + [entry]
    elif what in ('service', 'unit'):
        if len(rest) != 2:
            raise Refused('allow service NAME restart,try-restart,start')
        verbs = [v.strip() for v in rest[1].split(',') if v.strip()]
        if not verbs or [v for v in verbs if v not in WIN_VERBS]:
            raise Refused('the verbs are %s' % ', '.join(WIN_VERBS))
        have = pol['units'].setdefault(norm_unit(rest[0]), [])
        for v in verbs:
            if v not in have:
                have.append(v)
    elif what == 'test':
        if rest[:1] == ['--']:
            rest = rest[1:]
        argv = A.check_argv(rest)
        if _bad_argv0(argv):
            raise Refused('%s is a batch file: cmd.exe would read its arguments as commands - '
                          'a program (.exe) or a script (allow script C:\\x.ps1)' % argv[0])
        pol['tests'].append(argv)
    elif what == 'script':
        kv, rest = A._kv(rest, ('sha256',))
        if len(rest) != 1 or not A.HEX64.match(str(kv.get('sha256') or '').lower()):
            raise Refused('allow script C:\\PATH.ps1 sha256=HEX (acme-agent allow script PATH '
                          'pins it)')
        path = norm_dir(rest[0], real=False)
        if not path.lower().endswith('.ps1'):
            raise Refused('a script on Windows is a PowerShell script (.ps1) - a program is a '
                          'test (allow test -- C:\\x.exe)')
        pol['scripts'] = [x for x in pol['scripts'] if x['path'].lower() != path.lower()] + \
            [{'path': path, 'sha256': kv['sha256'].lower()}]
    elif what == 'store':
        if rest:
            raise Refused('allow store')
        pol['store'] = True
    elif what == 'iis':
        if len(rest) != 1 or not SITE_RE.match(rest[0]):
            raise Refused('allow iis SITE (its name as IIS says it, "Default Web Site") or '
                          'allow iis *')
        have = pol.setdefault('iis', [])
        if rest[0].lower() not in [x.lower() for x in have]:
            have.append(rest[0])
    elif what == 'rdp':
        if rest:
            raise Refused('allow rdp')
        pol['rdp'] = True
    elif what in ('script-hash', 'from', 'self-update', 'connect', 'probe'):
        ORIG['_policy_line'](pol, words)
    else:
        raise Refused('allow file | service | test | script | script-hash | store | iis | rdp | '
                      'from | probe | connect | self-update')


def policy_lines(pol):
    out = []
    for f in pol['files']:
        out.append('allow file %s%s' % (wq(f['dir']), (' readers=%s' % wq(','.join(
            f.get('readers') or []))) if f.get('readers') else ''))
    for u, vs in sorted(pol['units'].items()):
        out.append('allow service %s %s' % (u, ','.join(vs)))
    for t in pol['tests']:
        out.append('allow test -- %s' % ' '.join(wq(a) for a in t))
    for s in pol['scripts']:
        out.append('allow script %s sha256=%s' % (wq(s['path']), s['sha256']))
    return out + ORIG['policy_lines'](dict(pol, files=[], units={}, tests=[], scripts=[]))


def policy_facts():
    return {'platform': 'windows', 'protected': protected_list(), 'parts': ['.ssh'],
            'own': own_places(), 'verbs': list(WIN_VERBS), 'shells': list(WIN_SHELLS),
            'exec_ext': list(EXEC_EXT), 'config_ok': [], 'head': POLICY_HEAD_WIN,
            'limits': {'files': A.FILES_MOST, 'size': A.FILE_MOST, 'files_most': 200,
                       'size_most': 64 * 1024 * 1024}}


def policy_check(text, machine=False):
    """acme-agent policy check / apply on Windows - the same errors and warnings."""
    errors, warnings, entries = [], [], []
    for n, raw in enumerate(str(text or '').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        one = parse_policy(line)
        if one['problems']:
            errors.append({'line': n, 'code': 'unread',
                           'words': one['problems'][0].split(': ', 1)[-1]})
            continue
        entries.append((n, one))
    pol = parse_policy(text)
    dirs = [f['dir'] for f in pol['files']]
    seen_dirs, seen_scripts = {}, {}

    def warn(n, code, words):
        warnings.append({'line': n, 'code': code, 'words': words})

    def inside(path):
        return [d for d in dirs if _under(path, d) and path.lower() != d.lower()]
    tops = [t for t in protected_list() + own_places() if '*' not in t]
    for n, one in entries:
        for f in one['files']:
            d = f['dir']
            why = protected(d)
            if why:
                errors.append({'line': n, 'code': 'protected', 'words': why.replace(
                    ' - never written by a job', ' - no job ever writes there')})
                continue
            if d.lower() in seen_dirs:
                warn(n, 'twice', 'files in %s are said twice (line %d too): only this line '
                                 'counts' % (d, seen_dirs[d.lower()]))
            seen_dirs[d.lower()] = n
            under = [t for t in tops if _under(t, d) and t.lower() != d.lower()]
            if re.fullmatch(r'[A-Za-z]:\\Users(\\[^\\]+)?', d, re.I):
                under.append(d + '\\...\\AppData')
            if under:
                warn(n, 'above-protected', '%s holds places no job ever writes (%s%s): the rest '
                     'of it is allowed - allow the narrowest folder that holds only certificates'
                     % (d, ', '.join(under[:3]), ' …' if len(under) > 3 else ''))
            if machine:
                try:
                    real = norm_dir(d, real=True)
                except Refused:
                    real = d
                if real.lower() != d.lower():
                    errors.append({'line': n, 'code': 'link', 'words': '%s is %s (a link on the '
                                   'way) - write the real folder' % (d, real)})
                for r in f.get('readers') or []:
                    try:
                        W.lookup_sid(r)
                    except OSError:
                        warn(n, 'no-owner', 'there is no account %s on this machine - a file of '
                             'this folder is refused until there is' % r)
        for argv in one['tests']:
            if _shell_line(argv):
                warn(n, 'shell', '%s runs what its command line says as SYSTEM - a fixed script '
                     '(allow script) says what it runs' % ' '.join(wq(a) for a in argv[:3]))
            for w in argv:
                if re.match(r'[A-Za-z]:[\\/]', w):
                    try:
                        nw = norm_win(w)
                    except Refused:
                        continue
                    if inside(nw):
                        warn(n, 'runs-from', '%s is in a folder allowed for files (%s): the test '
                             'runs it, so a job never writes it' % (w, inside(nw)[0]))
        for s in one['scripts']:
            k = s['path'].lower()
            if k in seen_scripts:
                warn(n, 'twice', 'the script %s is said twice (line %d too): only this line '
                                 'counts' % (s['path'], seen_scripts[k]))
            seen_scripts[k] = n
            if inside(s['path']):
                warn(n, 'runs-from', '%s is in a folder allowed for files (%s): the policy runs '
                     'it, so a job never writes it' % (s['path'], inside(s['path'])[0]))
            if machine:
                try:
                    h = A._sha(W.read_path(s['path']))
                except OSError as e:
                    errors.append({'line': n, 'code': 'script-missing', 'words': '%s cannot be '
                                   'read here (%s) - acme-agent allow script pins a script that is '
                                   'there' % (s['path'], e.strerror or e)})
                    continue
                if h != s['sha256']:
                    errors.append({'line': n, 'code': 'script-hash', 'words': '%s is not the '
                                   'script the line says: its SHA-256 here is %s' % (
                                       s['path'], h)})
        for c in one['connect']:
            warn(n, 'connect', 'acme may reach %s through this server (a connector of SSH '
                               'targets)' % c)
    return {'pol': pol, 'lines': policy_lines(pol), 'errors': errors, 'warnings': warnings}


def allow_file_words(d, owner, group, mode):
    return 'acme-agent allow file %s' % wq(d)


def owner_ids(user, group):
    """readers= -> (AclId of their SIDs, None) - or (None, None): the folder's ACL inherited."""
    names = [x.strip() for x in str(user or '').split(',') if x.strip()]
    if not names:
        return None, None
    sids = []
    for n in names:
        try:
            sids.append(W.lookup_sid(n))
        except OSError:
            raise Refused('there is no account %s on this machine' % n)
    return AclId(sorted(set(sids))), None


def qw(word):
    return wq(word)


def op_words(op):
    if 'any' in op:
        return ' || '.join(op_words(a) for a in op['any']) or '(nothing allowed)'
    if 'unit' in op:
        return {'restart': 'Restart-Service %s', 'start': 'Start-Service %s',
                'try-restart': 'Restart-Service %s (when it runs)'}.get(
                    op['verb'], op['verb'] + ' %s') % op['unit']
    if 'argv' in op:
        return ' '.join(wq(a) for a in op['argv'])
    if 'script' in op:
        return ' '.join([wq(op['script'])] + [wq(a) for a in op.get('args') or []])
    return '?'


def policy_words(words):
    """The words of `allow ...` as a line of the policy (a folder's real path, a script
    pinned, each reader an account of this machine)."""
    usage = 'acme-agent allow file|service|test|script|script-hash|store|iis|rdp|from|probe|' \
            'connect|self-update'
    if not words:
        raise SystemExit(usage)
    what, rest = words[0], words[1:]
    try:
        if what == 'file':
            if not rest:
                raise SystemExit('acme-agent allow file C:\\FOLDER [--readers ACCOUNT,ACCOUNT]')
            if '--owner' in rest or '--mode' in rest:
                raise SystemExit('acme-agent: --owner and --mode are not for Windows: a file '
                                 'gets its folder\'s permissions, or with --readers ACCOUNT,... '
                                 'only SYSTEM, the Administrators and those accounts may read it')
            readers = ''
            if '--readers' in rest:
                i = rest.index('--readers')
                if i + 1 >= len(rest):
                    raise SystemExit('acme-agent allow file C:\\FOLDER --readers ACCOUNT,ACCOUNT')
                readers = rest[i + 1]
                rest = rest[:i] + rest[i + 2:]
            if len(rest) != 1:
                raise SystemExit('acme-agent allow file C:\\FOLDER [--readers ACCOUNT,ACCOUNT]')
            d = norm_dir(rest[0], real=False)
            real = norm_dir(d, real=True)
            if real.lower() != d.lower():
                print('note: %s is %s - that is what is allowed' % (d, real))
            for r in _readers(readers):
                try:
                    W.lookup_sid(r)
                except OSError:
                    raise SystemExit('acme-agent: there is no account %s on this machine' % r)
            return 'allow file %s%s' % (wq(real), (' readers=%s' % wq(','.join(
                _readers(readers)))) if readers else '')
        if what in ('service', 'unit'):
            if len(rest) != 2:
                raise SystemExit('acme-agent allow service NAME restart,try-restart,start')
            return 'allow service %s %s' % (rest[0], rest[1])
        if what == 'test':
            if rest[:1] == ['--']:
                rest = rest[1:]
            if not rest:
                raise SystemExit('acme-agent allow test -- C:\\PROGRAM.exe ARGS...')
            return 'allow test -- %s' % ' '.join(wq(a) for a in rest)
        if what == 'script':
            if len(rest) != 1:
                raise SystemExit('acme-agent allow script C:\\PATH\\OF\\SCRIPT.ps1')
            p = norm_dir(rest[0], real=False)
            try:
                h = A._sha(W.read_path(p))
            except OSError as e:
                raise SystemExit('acme-agent: %s cannot be read: %s' % (p, e))
            return 'allow script %s sha256=%s' % (wq(p), h)
        if what in ('store', 'rdp'):
            return 'allow %s' % what
        if what == 'iis':
            if len(rest) != 1:
                raise SystemExit('acme-agent allow iis SITE (its name as IIS says it) | '
                                 'allow iis *')
            return 'allow iis %s' % wq(rest[0])
    except Refused as e:
        raise SystemExit('acme-agent: %s' % e)
    return ORIG['policy_words'](words)


def policy_edit(add, words):
    rc = ORIG['policy_edit'](add, words)
    if words[:1] == ['from']:
        firewall_sync()
    return rc


def policy_apply(text):
    rc = ORIG['policy_apply'](text)
    if rc == 0:
        firewall_sync()
    return rc


# ---- a file only the machine's administrators may change ---------------------------------------
def trusted_text(path, what):
    """(the text of a file only SYSTEM, the Administrators or TrustedInstaller may change, or
    None when it is not there; the problem or '') - opened without following a reparse point,
    its security descriptor read on the open file, its folder's checked too."""
    try:
        data, sddl, dsddl, kind = W.read_checked(path, A.POLICY_MOST)
    except OSError as e:
        return None, '%s cannot be read (%s) - %s' % (path, e, what)
    if kind == 'missing':
        return None, ''
    if kind == 'link':
        return None, '%s is a symbolic link or a junction (a reparse point) - %s' % (path, what)
    if kind != 'file':
        return None, '%s is not a plain file - %s' % (path, what)
    why = sd_problem(parse_sddl(sddl) if sddl else None)
    if why:
        return None, '%s may be changed by somebody else than SYSTEM and the Administrators ' \
                     '(%s) - %s' % (path, why, what)
    why = sd_problem(parse_sddl(dsddl) if dsddl else None)
    if why:
        return None, 'the folder of %s may be changed by somebody else than SYSTEM and the ' \
                     'Administrators (%s) - %s' % (path, why, what)
    if len(data) > A.POLICY_MOST:
        return None, '%s is bigger than %d bytes - %s' % (path, A.POLICY_MOST, what)
    return data.decode('utf-8', 'replace'), ''


def _write(path, data, mode=0o600, owner=None):
    """A file of the agent's own written atomically: a new file beside it (it inherits its
    folder's ACL), synced, renamed over; owned by the Administrators (a file of the policy's
    and the pins' is trusted only so)."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.acme-', dir=d)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    w = W.winpath(path)
    if w and W.is_admin():
        try:
            W.set_owner(w, ADMINS)
        except OSError:
            pass


def audit(**kw):
    """Every operation, refusals too: the Application event log (source acme-agent) and the
    root side's own log - names, paths, hashes and results only, never what a file holds."""
    kw['ts'] = round(time.time(), 3)
    line = json.dumps(kw, sort_keys=True)[:4000]
    try:
        W.event(kw.get('ok', True), line)
    except Exception:                                   # noqa: BLE001
        pass
    try:
        if os.path.isdir(A.ROOT_STATE) or W.is_admin():
            os.makedirs(A.ROOT_STATE, exist_ok=True)
            with open(os.path.join(A.ROOT_STATE, 'audit.log'), 'a', encoding='utf-8') as f:
                f.write(line + '\n')
    except OSError:
        pass


# ---- files in the policy's folders: through W ------------------------------------------------
def open_dir(path, make_from=None):
    try:
        return W.open_dir(path, make_from)
    except WinFail as e:
        raise Refused('%s cannot be opened: %s' % (path, e))


def dir_close(dfd):
    W.close(dfd)


def unlink_at(dfd, name):
    W.delete(dfd, name)


def subdir_at(dfd, name, make=False):
    return W.open_sub(dfd, name, make)


def dup_dir(dfd):
    return W.dup(dfd)


def read_at(dfd, name, most):
    try:
        return W.read_file(dfd, name, most)
    except WinFail as e:
        raise Refused('%s cannot be read: %s' % (name, e))


def write_at(dfd, name, data, mode, uid, gid):
    """The file put in place: written under a random name in the same folder (CREATE_NEW, its
    ACL from the start: inherited, the copy's, or readers=), flushed, moved over the old one
    (MoveFileExW, replace, write-through). `uid` carries the ACL (owner_ids); mode and gid mean
    nothing here."""
    if ntpath.splitext(name)[1].lower() in EXEC_EXT:
        raise Refused('%s: acme-agent never writes a file Windows runs or loads' % name)
    tmp = '.acme-new.%s' % secrets.token_hex(8)
    W.write_new(dfd, tmp, data, uid)
    try:
        W.rename(dfd, tmp, name)
    except BaseException:
        try:
            W.delete(dfd, tmp)
        except OSError:
            pass
        raise


def prune_backups(dfd, name, keep):
    if not keep:
        return 0
    rx = re.compile(re.escape(name) + r'\.\d{4}[\d-]*\.bak\Z', re.I)
    got = []
    for n in W.listdir(dfd):
        if rx.match(n):
            st = W.stat(dfd, n)
            if st is not None and st.is_file:
                got.append((st.st_mtime, n))
    got.sort(reverse=True)
    n = 0
    for _t, old in got[keep:]:
        try:
            W.delete(dfd, old)
            n += 1
        except OSError:
            pass
    return n


def install_files(here, files, names):
    for name in names:
        tmp = os.path.join(here, '.%s.new' % name)
        with open(tmp, 'wb') as f:
            f.write(files[name])
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, os.path.join(here, name))


# ---- openssl: never /dev/stdin ------------------------------------------------------------------
def _stage_file(data):
    """A file in root's stage folder (SYSTEM and the Administrators only), made new."""
    stage = os.path.join(A.ROOT_STATE, 'stage')
    os.makedirs(stage, exist_ok=True)
    fn = os.path.join(stage, 'k-%s.pem' % secrets.token_hex(8))
    with open(fn, 'xb') as f:
        f.write(data.encode() if isinstance(data, str) else data)
    return fn


def make_key_csr(key_pem, names):
    pairs = A.check_names(names)
    san = ','.join('%s:%s' % p for p in pairs)
    fn = _stage_file(key_pem)
    try:
        return A._openssl(['req', '-new', '-key', fn, '-subj', '/CN=%s' % pairs[0][1],
                           '-addext', 'subjectAltName=%s' % san])
    finally:
        os.unlink(fn)


def make_csr(key):
    return A._openssl(['req', '-new', '-key', key, '-subj', '/CN=acme-agent'])


def self_signed(key):
    return A._openssl(['req', '-new', '-x509', '-days', '2', '-key', key, '-subj',
                       '/CN=acme-agent-joining'])


def _base_env():
    sr = W.system_root()
    return {'SystemRoot': sr, 'windir': sr, 'SystemDrive': W.system_drive(),
            'PATH': ';'.join([ntpath.join(sr, 'System32'), sr, ntpath.join(sr, 'System32', 'Wbem'),
                              ntpath.join(sr, 'System32', 'WindowsPowerShell', 'v1.0')]),
            'PATHEXT': '.COM;.EXE', 'ProgramData': W.program_data(),
            'ProgramFiles': W.program_files(), 'COMPUTERNAME': socket.gethostname()[:63],
            **{k: os.environ[k] for k in ('OPENSSL_CONF', 'OPENSSL_MODULES')
               if os.environ.get(k)}}


def _p12_env(password):
    return dict(_base_env(), ACME_AGENT_P12=password or '')


def _probe_env():
    return _base_env()


def reuse_addr(ls):
    """Windows: the passive port held exclusively (SO_REUSEADDR there lets another process take
    it over)."""
    opt = getattr(socket, 'SO_EXCLUSIVEADDRUSE', None)
    if opt is not None:
        ls.setsockopt(socket.SOL_SOCKET, opt, 1)
    else:
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def _os_name():
    try:
        return W.os_name()
    except Exception:                                   # noqa: BLE001
        return 'Windows'


# ---- the deployment's commands: services, CreateProcess, PowerShell ---------------------------
def deploy_env(self, env):
    out = _base_env()
    stage = os.path.join(A.ROOT_STATE, 'stage')
    out.update({'TEMP': stage, 'TMP': stage,
                'USERPROFILE': ntpath.join(W.system_root(), 'System32', 'config',
                                           'systemprofile')})
    out.update(env)
    return out


def deploy_run_argv(self, argv, env, timeout=None):
    timeout = timeout or A.CMD_TIMEOUT
    if _bad_argv0(argv):
        return 126, '%s is a batch file - cmd.exe would read its arguments as commands; ' \
                    'acme-agent never runs one' % argv[0]
    try:
        rc, out, err = W.run(argv, self._env(env), ntpath.join(W.system_root(), 'System32'),
                             timeout)
    except FileNotFoundError:
        return 127, '%s is not on this machine' % argv[0]
    except subprocess.TimeoutExpired:
        return 124, 'it did not end in %d s' % timeout
    except OSError as e:
        return 126, str(e)
    said = ((out or b'').decode('utf-8', 'replace').rstrip() + '\n' +
            (err or b'').decode('utf-8', 'replace').rstrip()).strip()
    return rc, said[-A.OUT_MOST:]


def deploy_unit_verb(self, op):
    """Restart-Service (restart), only when it runs (try-restart), Start-Service (start) - then
    the state it is in."""
    name, verb = op['unit'], op['verb']
    try:
        st = W.service_state(name)
        if st is None:
            return 1, 'there is no service %s here' % name
        if verb == 'try-restart' and st != 'Running':
            return 0, 'is %s - not running, left as it is' % st
        deps = []
        if verb == 'start':
            if st != 'Running':
                W.service_start(name)
        else:
            deps = W.service_restart(name) or []      # Restart-Service -Force
        st = W.service_state(name)
    except OSError as e:
        return 1, str(e)
    said = 'is %s' % st
    if deps:
        said += ' (the services depending on it restarted too: %s)' % ', '.join(deps)
    return (0 if st == 'Running' else 1), said


def deploy_run_file(self, path, args, env, body):
    """A PowerShell script: its bytes checked against the policy's hash when it runs, run from
    a copy root keeps (powershell.exe -File COPY)."""
    pol, _h, _t = A.policy_load()
    if body is None:
        rule = next((s for s in pol['scripts'] if s['path'].lower() == path.lower()), None)
        if rule is None:
            return 126, 'the script is not allowed by the policy'
        d, name = split_path(path)
        try:
            dfd = A.open_dir(d)
        except Refused as e:
            return 126, str(e)
        try:
            data, _st = A.read_at(dfd, name, A.SCRIPT_MOST * 16)
        except Refused as e:
            return 126, str(e)
        finally:
            A.dir_close(dfd)
        if data is None:
            return 127, '%s is not there' % path
        import hmac
        if not hmac.compare_digest(A._sha(data), rule['sha256']):
            return 126, ('%s is not the script the policy allows (its SHA-256 changed) - '
                         'acme-agent allow script %s again once it is checked' % (path, path))
    else:
        if body.get('interp') != 'powershell':
            return 126, 'a script written in acme runs in PowerShell here'
        data = body['data']
    stage = os.path.join(A.ROOT_STATE, 'stage')
    os.makedirs(stage, exist_ok=True)
    fn = os.path.join(stage, 'script-%s.ps1' % secrets.token_hex(8))
    try:
        with open(fn, 'xb') as f:
            f.write(data)
        argv = [W.powershell(), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                'Bypass', '-File', fn] + list(args)
        return self.run_argv(argv, env, A.SCRIPT_TIMEOUT)
    finally:
        try:
            os.unlink(fn)
        except OSError:
            pass


# ---- the services -----------------------------------------------------------------------------
def _no_services():
    return bool(os.environ.get('ACME_AGENT_NO_SYSTEMD') or os.environ.get('ACME_AGENT_NO_SERVICES'))


def restart_both():
    """The network side stopped, the root side restarted, the network side started."""
    for step, name in (('stop', SERVICE), ('restart', ROOT_SERVICE), ('start', SERVICE)):
        try:
            if W.service_state(name) is None:
                continue
            getattr(W, 'service_' + step)(name)
        except OSError as e:
            A.audit(op='service', ok=False, said='%s %s: %s' % (step, name, str(e)[:200]))


def restart_services():
    firewall_sync()
    if _no_services():
        return
    restart_both()


def restart_later(delay=2.0):
    """Both services started again after an update - by a process of its own (the root side
    cannot restart itself and see it through)."""
    if _no_services():
        return False
    W.spawn_detached([sys.executable, '-I', '-B', os.path.join(A.lib_dir(), 'acme_agent.py'),
                      'winservice', 'restart'])
    return True


def firewall_sync():
    """The passive port's inbound rule as the join and `allow from` say - none when the agent
    is not passive (or not joined)."""
    try:
        c = A._json(A.CONF, {})
        pins = A._json(os.path.join(A.ROOT_STATE, 'join-pins.json'), {})
        c = c if isinstance(c, dict) else {}
        pins = pins if isinstance(pins, dict) else {}
        mode = c.get('mode') or pins.get('m')
        port = int(c.get('port') or pins.get('p') or A.PASSIVE_PORT)
        if mode == 'passive' and (c.get('agent_id') or pins.get('ca')):
            pol = A.policy_load()[0]
            W.firewall_set(port, pol['from'], sys.executable)
        else:
            W.firewall_remove()
        return True
    except Exception as e:                              # noqa: BLE001
        try:
            A.audit(op='firewall', ok=False, said=str(e)[:300])
        except Exception:                               # noqa: BLE001
            pass
        return False


def need_root(words):
    if W.is_admin():
        return
    w = str(words)
    if 'the policy is root' in w:
        w = 'acme-agent: the policy is the Administrators\''
    else:
        w = w.replace(' runs as root', ' needs administrator rights')
        w = re.sub(r':.*\Z', '', w)
    raise SystemExit('%s - run it in an elevated prompt (Run as administrator)' % w)


def agent_ids():
    sid = W.service_sid(SERVICE) if hasattr(W, 'service_sid') else service_sid(SERVICE)
    return sid, sid


def make_places(ids=None):
    """C:\\ProgramData\\acme-agent and its three folders, each with its DACL (protected):
    etc - SYSTEM, the Administrators full, Users and the network side read; root - SYSTEM and
    the Administrators only; net - ...and the network side's account modify."""
    svc = service_sid(SERVICE)
    base = base_dir()
    if os.path.dirname(A.ETC) == base:
        os.makedirs(base, exist_ok=True)
        _acl(base, [(SYSTEM, 'F'), (ADMINS, 'F'), (USERS, 'RX')])
    for d, aces in ((A.ETC, [(SYSTEM, 'F'), (ADMINS, 'F'), (USERS, 'RX'), (svc, 'RX')]),
                    (A.STATE, [(SYSTEM, 'F'), (ADMINS, 'F'), (svc, 'M')]),
                    (A.ROOT_STATE, [(SYSTEM, 'F'), (ADMINS, 'F')])):
        os.makedirs(d, exist_ok=True)
        _acl(d, aces)


def _acl(local, aces):
    w = W.winpath(local)
    if w:
        W.set_sd(w, sddl_for(aces, folder=True, owner=ADMINS))


def cmd_init():
    """The folders (their DACLs) and an empty policy: nothing allowed."""
    need_root('acme-agent init runs as root')
    make_places()
    text, problem = trusted_text(A.POLICY, 'it is written again')
    if text is None and not problem:
        _write(A.POLICY, POLICY_HEAD_WIN)
    elif problem:
        # a policy somebody else may change: written again (its folder's ACL, the
        # Administrators' own) - what it says kept
        try:
            with open(A.POLICY, 'rb') as f:
                old = f.read(A.POLICY_MOST + 1)
        except OSError:
            old = POLICY_HEAD_WIN.encode()
        w = W.winpath(A.POLICY)
        if w:
            W.set_sd(w, 'O:BAD:')                   # its own ACEs gone: the folder's inherited
        _write(A.POLICY, old)
    return 0


def status_facts():
    out = ORIG['status_facts']()
    out['platform'] = 'windows'
    svc = {}
    for n in (ROOT_SERVICE, SERVICE):
        try:
            svc[n] = W.service_state(n) or 'not installed'
        except OSError as e:
            svc[n] = str(e)[:80]
    out['services'] = svc
    return out


# ---- the two sides ----------------------------------------------------------------------------
def pipe_sddl():
    """The pipe's DACL: SYSTEM and the Administrators, the network side's service (read and
    write) - nobody else even opens it; nobody from another machine (the pipe refuses them)."""
    # 0x12008b: read, write data, attributes, READ_CONTROL, SYNCHRONIZE - never
    # FILE_CREATE_PIPE_INSTANCE: only the root side serves this pipe
    return 'D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;%s)' % service_sid(SERVICE)


def peer_ok(who):
    """The root side's check of the account at the other end of the pipe: SYSTEM, the network
    side's service, or an elevated administrator (uid 0 / uid acme-agent on Linux)."""
    if not isinstance(who, dict):
        return False
    if who.get('sid') in (SYSTEM, service_sid(SERVICE)):
        return True
    return bool(who.get('admin') and who.get('elevated'))


def serve_root():
    """The root side (the service acme-agent-root, LocalSystem): the named pipe, for the network
    side alone (its account checked) - never the network."""
    if not W.is_admin():
        raise SystemExit('acme-agent root runs as LocalSystem (the service %s)' % ROOT_SERVICE)
    root = A.Root()
    firewall_sync()
    srv = W.pipe_server(PIPE, pipe_sddl())
    room = threading.BoundedSemaphore(A.ROOT_THREADS)
    stop = {'now': False}

    def bye(*_):
        stop['now'] = True
        srv.close()
    STOPPERS.append(bye)
    if not UNDER_HOST['on'] and _in_main_thread():
        import signal
        signal.signal(signal.SIGTERM, bye)
        signal.signal(signal.SIGINT, bye)
    A.audit(op='start', ok=True, said='acme-agent %s (root side)' % A.VERSION)

    def one(conn):
        try:
            try:
                who = conn.peer()
            except OSError as e:
                A.audit(op='refused', ok=False, said='a connection whose account cannot be read '
                        '(%s)' % str(e)[:100])
                return
            if not peer_ok(who):
                A.audit(op='refused', ok=False, said='a connection of %s' % who.get('sid'))
                return
            conn.settimeout(900)
            while True:
                try:
                    msg = A._recv(conn)
                except (EOFError, OSError, ValueError):
                    return
                if not isinstance(msg, dict):
                    return
                A._send(conn, root.handle(msg, who.get('sid')))
        finally:
            conn.close()
            room.release()
    while not stop['now']:
        try:
            conn = srv.accept()
        except OSError:
            break
        if stop['now']:
            conn.close()
            break
        if not room.acquire(timeout=30):
            conn.close()
            continue
        threading.Thread(target=one, args=(conn,), daemon=True).start()
    if root.work.acquire(timeout=300):
        root.work.release()
    return 0


class RootLink(object):
    """The network side's way to root: the named pipe, one request at a time."""

    def __init__(self, path=None):
        self.path = path or PIPE

    def ask(self, msg, timeout=900):
        try:
            conn = W.pipe_connect(self.path, timeout)
        except OSError as e:
            return {'ok': False, 'said': 'the root side of the agent does not answer (%s) - '
                                         'Get-Service %s' % (e, ROOT_SERVICE)}
        try:
            A._send(conn, msg)
            return A._recv(conn)
        except (OSError, EOFError, ValueError) as e:
            return {'ok': False, 'said': 'the root side of the agent does not answer (%s) - '
                                         'Get-Service %s' % (e, ROOT_SERVICE)}
        finally:
            conn.close()


def serve_net():
    """The network side (the service acme-agent, NT SERVICE\\acme-agent): never SYSTEM, never
    an administrator."""
    sid = W.current_sid()
    if sid == SYSTEM or W.is_admin():
        raise SystemExit('acme-agent serve runs as %s (the service %s), never as SYSTEM or an '
                         'administrator' % (ACCOUNT, SERVICE))
    tmp = os.path.join(A.STATE, 'tmp')
    try:
        os.makedirs(tmp, exist_ok=True)
        tempfile.tempdir = tmp
    except OSError:
        pass
    net = A.Net()

    def bye(*_):
        net.stopping = True
        for s in list(SERVERS):
            threading.Thread(target=s.shutdown, daemon=True).start()
    STOPPERS.append(bye)
    if not UNDER_HOST['on'] and _in_main_thread():
        import signal

        def bye_exit(*_):
            bye()
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, bye_exit)
        signal.signal(signal.SIGINT, bye_exit)
    return A.net_loop(net)


def _serve_forever(self, poll_interval=0.5):
    SERVERS.append(self)
    try:
        return ORIG['serve_forever'](self, poll_interval)
    finally:
        if self in SERVERS:
            SERVERS.remove(self)


# ---- the command line: windows-install, windows-uninstall, winservice ---------------------------
def service_specs():
    py = sys.executable
    prog = os.path.join(A.lib_dir(), 'acme_agent.py')
    line = '"%s" -I -B "%s" winservice %%s' % (py, prog)
    return [{'name': ROOT_SERVICE, 'display': 'acme-agent (root side)',
             'description': 'acme-agent: takes certificates from acme as the local policy '
                            'allows - the side that writes them (never the network).',
             'cmdline': line % 'root', 'account': None, 'depends': [],
             'sid_type': 'unrestricted', 'privileges': None, 'delayed': False,
             'restart_ms': 5000},
            {'name': SERVICE, 'display': 'acme-agent (network side)',
             'description': 'acme-agent: the TLS channel to acme (no privileges) - what it is '
                            'asked goes to acme-agent-root.',
             'cmdline': line % 'serve', 'account': ACCOUNT, 'depends': [ROOT_SERVICE],
             'sid_type': 'restricted', 'privileges': ['SeChangeNotifyPrivilege'],
             'delayed': True, 'restart_ms': 5000}]


def windows_install(argv):
    """The MSI's install (and upgrade): folders and DACLs, an empty policy, the event source,
    the services made or set again and started, the program on the system PATH; a join code
    given: the join started (the services finish it - nothing needs the network now)."""
    need_root('acme-agent windows-install runs as root')
    code = ''
    if '--join' in argv:
        i = argv.index('--join')
        code = (argv[i + 1] if i + 1 < len(argv) else '').strip()
        if not code:
            raise SystemExit('acme-agent windows-install [--join CODE]')
    cmd_init()
    W.event_source_add()
    for spec in service_specs():
        W.service_install(spec)
    W.path_add(program_dir())
    A.audit(op='install', ok=True, said='acme-agent %s installed (Windows)' % A.VERSION)
    print('acme-agent %s is installed. Nothing is allowed yet: acme-agent policy show' % A.VERSION)
    if code:
        try:
            return_code = A.cmd_join([code, '--no-wait'])
            if return_code:
                print('acme-agent: the join did not start (%s)' % return_code)
            return 0
        except SystemExit as e:
            said = str(e.code if e.code is not None else '')
            print('acme-agent: the join code was not taken: %s - run `acme-agent join CODE` in '
                  'an elevated prompt' % said)
            A.audit(op='join', ok=False, said=('at the install: %s' % said)[:300])
            A.status_write(state='refused', said='the join code given at the install was not '
                           'taken: %s' % said[:200])
    restart_services()
    if not code:
        print('next: acme-agent join CODE (the code is made on the target\'s card in acme)')
    return 0


def windows_uninstall(argv):
    """The MSI's uninstall: the services stopped and taken away, the firewall rule, the PATH
    entry, the event source; C:\\ProgramData\\acme-agent stays (the policy, the identity) unless
    --purge."""
    need_root('acme-agent windows-uninstall runs as root')
    if '--upgrade' in argv:
        # a newer MSI takes this one's place: only the services stopped (their files are
        # replaced) - identity, policy, firewall rule, PATH and event source stay; the new
        # MSI's windows-install sets them again and starts the services
        for n in (SERVICE, ROOT_SERVICE):
            try:
                if W.service_state(n) not in (None, 'Stopped'):
                    W.service_stop(n)
            except OSError as e:
                print('acme-agent: the service %s did not stop: %s' % (n, e))
        A.audit(op='uninstall', ok=True, said='stopped for an upgrade')
        return 0
    for n in (SERVICE, ROOT_SERVICE):
        try:
            if W.service_state(n) not in (None, 'Stopped'):
                W.service_stop(n)
        except OSError:
            pass
        try:
            W.service_delete(n)
        except OSError as e:
            print('acme-agent: the service %s could not be taken away: %s' % (n, e))
    W.firewall_remove()
    W.path_remove(program_dir())
    A.audit(op='uninstall', ok=True, said='acme-agent taken away%s' % (
        ' with its policy' if '--purge' in argv else ''))
    W.event_source_remove()
    if '--purge' in argv:
        for d in (A.ETC, A.STATE, A.ROOT_STATE):
            shutil.rmtree(d, ignore_errors=True)
        b = base_dir()
        if os.path.isdir(b) and not os.listdir(b):
            os.rmdir(b)
        print('acme-agent taken away, its policy too')
    else:
        print('acme-agent taken away; its policy stays in %s (--purge takes it too)' % A.ETC)
    return 0


def winservice(argv):
    which = (argv or [''])[0]
    if which == 'root':
        UNDER_HOST['on'] = True
        return W.service_host(ROOT_SERVICE, A.serve_root, stop_all)
    if which == 'serve':
        UNDER_HOST['on'] = True
        return W.service_host(SERVICE, A.serve_net, stop_all)
    if which == 'restart':
        time.sleep(2)
        restart_both()
        return 0
    raise SystemExit('acme-agent winservice root|serve')


def main(argv):
    cmd = (argv or [''])[0]
    if cmd == 'windows-install':
        return windows_install(argv[1:])
    if cmd == 'windows-uninstall':
        return windows_uninstall(argv[1:])
    if cmd == 'winservice':
        return winservice(argv[1:])
    return ORIG['main'](argv)


# ---- install(): all of the above put in place of acme_agent.py's own ----------------------------
REPLACED = ('norm_dir', 'norm_unit', 'protected', 'runs_from', 'trusted_text', 'parse_policy',
            '_policy_line', 'policy_lines', 'own_places', 'policy_facts', '_shell_line',
            'policy_check', 'policy_apply', 'allow_file_words', 'file_rule', 'owner_ids', 'qw',
            'split_path', 'dir_close', 'unlink_at', 'subdir_at', 'dup_dir', 'open_dir',
            'read_at', 'write_at', 'prune_backups', 'make_key_csr', 'make_csr', 'self_signed',
            '_p12_env', '_probe_env', 'install_files', 'restart_later', '_os_name', 'op_words',
            'agent_ids', 'serve_root', 'RootLink', 'serve_net', 'reuse_addr', 'need_root',
            'make_places', 'cmd_init', 'restart_services', 'policy_edit', 'policy_words',
            'status_facts', 'main', '_write', 'audit', '_under')


def install(g):
    """acme_agent.py's POSIX parts replaced by the Windows ones (its globals `g`)."""
    global A, Refused
    A = _View(g)
    Refused = g['Refused']
    here = globals()
    for name in REPLACED:
        if name in g and name not in ORIG:
            ORIG[name] = g[name]
    ORIG['serve_forever'] = g['PassiveServer'].serve_forever
    lib = os.path.dirname(os.path.realpath(g['__file__']))
    base = base_dir()
    etc = os.environ.get('ACME_AGENT_ETC') or os.path.join(base, 'etc')
    g.update(PLATFORM='windows', WINDOWS=True, UNIT_WORD='service', STDIN_IN=[],
             VERBS=WIN_VERBS, INTERPS={'powershell': W.powershell()}, SHELLS=WIN_SHELLS,
             PROTECTED=tuple(protected_list()), PROTECTED_PARTS=('.ssh',), CONFIG_OK=(),
             POLICY_HEAD=POLICY_HEAD_WIN, ETC=etc,
             STATE=os.environ.get('ACME_AGENT_STATE') or os.path.join(base, 'net'),
             ROOT_STATE=os.environ.get('ACME_AGENT_ROOT_STATE') or os.path.join(base, 'root'),
             RUN=os.environ.get('ACME_AGENT_RUN') or base, USER=ACCOUNT,
             POLICY=os.path.join(etc, 'policy'), CONF=os.path.join(etc, 'agent.json'),
             CA_FILE=os.path.join(etc, 'ca.pem'), SOCK=PIPE,
             OPENSSL=os.environ.get('ACME_AGENT_OPENSSL') or W.openssl_default(lib),
             WIN=here, W=W, __doc__=WIN_DOC)
    for name in REPLACED:
        if name in here:
            g[name] = here[name]
    if not W.fake and not os.environ.get('ACME_AGENT_OPENSSL'):
        # the bundled openssl.exe: its configuration and providers beside it (the build's own
        # folders are of the machine it was built on)
        ossl = os.path.join(lib, 'openssl')
        if os.path.isdir(ossl):
            os.environ.setdefault('OPENSSL_CONF', os.path.join(ossl, 'openssl.cnf'))
            os.environ.setdefault('OPENSSL_MODULES', ossl)
    g['Deploy']._env = deploy_env
    g['Deploy'].run_argv = deploy_run_argv
    g['Deploy'].unit_verb = deploy_unit_verb
    g['Deploy']._run_file = deploy_run_file
    g['PassiveServer'].serve_forever = _serve_forever
    return g
