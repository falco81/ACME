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
  acme-agent windows-uninstall [--purge]     ...taken away (the policy stays unless --purge)
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
    """'Windows Server 2022 Standard (10.0.20348)' - Windows 11 says 'Windows 10' in the registry."""
    product = str(product or 'Windows')
    try:
        if int(build) >= 22000 and product.startswith('Windows 10'):
            product = 'Windows 11' + product[len('Windows 10'):]
    except (TypeError, ValueError):
        pass
    return ('%s (%s.%s.%s)' % (product, major, minor, build))[:80]


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

    def service_restart(self, name, wait=60):
        """Restart-Service: stopped (when running), started, waited for."""
        if self.service_state(name) not in ('Stopped', None):
            self.service_stop(name, wait)
        self.service_start(name, wait)

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
        while True:
            try:
                h = self._open(name, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING,
                               SQOS_PRESENT | SECURITY_IDENTIFICATION)
                return _RealPipe(self, h)
            except WinFail as e:
                if e.errno != 231 or time.time() > end:    # ERROR_PIPE_BUSY
                    raise
                a.WaitNamedPipeW(name, 2000)

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
            s['state'] = 'Stopped' if verb == 'stop' else 'Running'
            s['times'] = s.get('times', 0) + 1
        self._update('services.json', {}, go)

    def service_state(self, name):
        s = self.load('services.json', {}).get(str(name).lower())
        return None if s is None else s.get('state') or 'Stopped'

    def service_start(self, name, wait=60):
        self._svc_do(name, 'start')

    def service_stop(self, name, wait=60):
        self._svc_do(name, 'stop')

    def service_restart(self, name, wait=60):
        self._svc_do(name, 'restart')

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
