#!/usr/bin/python3 -I
"""acme_agent.py - acme-agent: a server that takes its certificates from acme without acme
holding any of its credentials (1.0.116, docs/target-agent.md).

acme proposes, the target decides. acme holds no SSH key, no password, no sudo of this machine:
it sends a signed job ("these files, this test, this reload"), and this agent does what the
local policy (/etc/acme-agent/policy, root's, never changed by acme) allows - nothing else.
Whoever steals acme's database or backups gets nothing of this machine; whoever controls a
running acme can do here only what the policy allows.

Two processes:

  * the network side (`acme-agent serve`, systemd acme-agent.service) runs as the account
    acme-agent with no privileges at all (it refuses to run as root): TLS 1.3 with mutual
    certificates and the protocol, nothing more. It writes only into its own state folder
    (/var/lib/acme-agent). Its key is made here and never leaves this machine; its certificate
    comes from acme's agent authority (30 days) and is renewed over the channel.
      passive  it listens (8446) for acme, which shows a certificate of acme's agent authority
               (pinned at the join) - optionally only from the addresses `allow from` names;
      active   nothing listens here: it connects out to acme's agents endpoint (8444), asks for
               jobs (long-poll), fails over between acme's nodes and backs off.
  * the root side (`acme-agent root`, systemd acme-agent-root.service) never talks to the
    network: a Unix socket for the network side alone (its uid checked), and a closed set of
    operations - stage and install files atomically (a backup copy, owner and mode, rollback),
    run an allowed test (a fixed argv, never a shell), systemctl reload/restart of an allowed
    unit, an allowed script (its SHA-256 checked when it runs), fingerprints of files, a key
    made here for a deployment (kept by root, written only into allowed files - it never
    leaves this machine), an update of this agent (signed, newer, allowed). Every
    job is checked here again: acme's signature (its command key pinned at the join), the
    agent's id, a nonce never seen, the time; then every file, owner, mode, unit, command and
    script against the policy. Private keys arrive sealed to this side's own X25519 key.

  acme-agent join CODE [--no-wait]       join acme with a one-time code (made by acme) - or
                                         a company enrollment code (ACAE1.: acme makes this
                                         server a target of its own, confirmed there)
  acme-agent status                      what is here (JSON)
  acme-agent fingerprint                 the fingerprint acme asks you to confirm
  acme-agent forget                      leave acme: its keys and pins taken away
  acme-agent policy show [--json]        what acme may do here
  acme-agent policy check FILE|-         a whole policy checked: what the agent would not read
  acme-agent policy apply FILE|-         ...and written in place of the one there (as root; the
                                         one before kept as policy.DATE) - acme's policy builder
  acme-agent allow file DIR [--owner U:G] [--mode 0640]
  acme-agent allow unit NAME reload,restart
  acme-agent allow test -- COMMAND ARGS...
  acme-agent allow script PATH           (its SHA-256 pinned now)
  acme-agent allow script-hash SHA256    (a script written in acme, by its hash)
  acme-agent allow from ADDRESS[/BITS]   (passive: only from there)
  acme-agent allow probe HOST:PORT       a test of what HOST:PORT serves, run from here
  acme-agent allow probe local           ...of anything on 127.0.0.1 / ::1 / localhost
  acme-agent allow connect HOST:PORT     acme reaches HOST:PORT through this agent (passive)
  acme-agent allow self-update           acme may update this agent: signed, newer only
  acme-agent limit files N | limit size BYTES
  acme-agent deny ...                    the same words: that entry taken away
  acme-agent root | serve                the two sides (systemd)
  acme-agent init                        its folders and an empty policy (install.sh)

Python 3 standard library only (the `cryptography` module used when it is there); openssl for
the TLS key and its requests.
"""
import base64
import binascii
import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

PROTO = 'acme-agent/1'
SKEW = 300                      # a job's time this far from ours at most (s)
BODY_MOST = 4 * 1024 * 1024     # a request or an answer
FILE_MOST = 1024 * 1024         # one file, unless the policy says another limit
FILES_MOST = 20                 # files in one job, unless the policy says another
SCRIPT_MOST = 64 * 1024
OUT_MOST = 2000                 # characters of what a command said kept in the job
CMD_TIMEOUT = 300
SCRIPT_TIMEOUT = 600
JOBS_A_MINUTE = 60
PASSIVE_PORT = 8446
CTL_CN = 'acme-agents'          # acme's own certificate (passive client, active server)
AGENT_CN = 'acme-agent:'        # this agent's certificate: acme-agent:<agent id>
RENEW_DAYS = 10                 # the certificate renewed this long before its end
VERBS = ('reload', 'restart', 'try-reload-or-restart', 'reload-or-restart', 'try-restart')
INTERPS = {'bash': '/bin/bash', 'sh': '/bin/sh', 'python3': '/usr/bin/python3'}
BACKUPS = ('dated', 'daily', 'bak', 'folder', 'none')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
UNIT_RE = re.compile(r'[A-Za-z0-9:_.@\\-]{1,128}\Z')
OWNER_RE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}\Z')
AGENT_ID_RE = re.compile(r'ag-[0-9a-f]{12,32}\Z')
SAFE_PATH = re.compile(r'/[^\x00-\x1f\x7f]{0,1023}\Z')
SAFE_ENV = re.compile(r'[A-Z][A-Z0-9_]{0,63}\Z')
ROOT_OPS = ('hello', 'policy', 'fingerprints', 'deploy', 'check', 'keygen', 'update')
# checked by root (the signature, and - probe, connect - the policy), done by the network side:
# root never opens a network connection
NET_OPS = ('csr', 'cert', 'probe', 'connect')
# the agent's program (code_hash, the update package): the Windows parts ride along everywhere
# (on Linux they are never loaded - see the platform hook at the end)
AGENT_FILES = ('acme_agent.py', 'acme_agent_win.py', 'acme_agent_wincert.py')
PLATFORM = 'linux'              # 'windows': acme_agent_win.install() (the platform hook)
WINDOWS = False
UNIT_WORD = 'unit'              # allow unit NAME ... (Windows: allow service NAME ...)
STDIN_IN = ['-in', '/dev/stdin']    # openssl reading what it is given (Windows: [] - stdin)
# a key the agent makes (phase 3): its types, and the formats root writes it in
KEY_TYPES = {'ec-256': ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'],
             'ec-384': ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384'],
             'rsa-2048': ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
             'rsa-3072': ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072'],
             'rsa-4096': ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096']}
AGENT_KEY_FORMATS = ('key-pem', 'key-traditional', 'key-rsa', 'key-der', 'combined-pem', 'pfx',
                     'p12')
SLOT_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,63}\Z')
KEYS_MOST = 64                  # deployments whose key this agent holds
DNS_RE = re.compile(r'(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]{0,62})(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,62}))*\Z')
# a test of what is served, from here (probe): the protocols `openssl s_client -starttls` speaks
STARTTLS = ('smtp', 'imap', 'pop3', 'ftp', 'xmpp', 'ldap', 'postgres', 'mysql', 'lmtp', 'nntp',
            'sieve')
PROBE_S = 30
TUNNEL_IDLE_S = 600             # a connector's tunnel with nothing going through it this long
PKG_MOST = 4 * 1024 * 1024      # an update's package
PKG_ENTRIES = 256               # entries of an update's package (1.0.116: a tar of a million
                                # empty folders read whole into root's memory before)
PASSIVE_MOST = 64               # connections at once on the passive port (the rest closed)
POLICY_MOST = 1024 * 1024       # bytes of the policy file, of agent.json
# Never written nor taken away by a job, whatever the policy says (1.0.116 security): the
# agent's own places - its policy, the key of acme it pinned, its program, its state - and the
# places whose files give root to whoever writes them. A policy that allows a folder above one
# of them (allow file /etc) still allows the rest of that folder.
PROTECTED = ('/etc/sudoers', '/etc/sudoers.d', '/etc/doas.conf', '/etc/crontab', '/etc/cron.d',
             '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly',
             '/etc/anacrontab', '/var/spool/cron', '/etc/systemd', '/run/systemd',
             '/usr/lib/systemd', '/lib/systemd', '/etc/init.d', '/etc/rc.d', '/etc/rc.local',
             '/etc/pam.d', '/etc/security', '/etc/ld.so.preload', '/etc/ld.so.conf',
             '/etc/ld.so.conf.d', '/etc/profile', '/etc/profile.d', '/etc/bashrc',
             '/etc/bash.bashrc', '/etc/environment', '/etc/passwd', '/etc/shadow', '/etc/group',
             '/etc/gshadow', '/etc/ssh', '/root', '/etc/polkit-1', '/etc/udev', '/etc/modprobe.d',
             '/etc/modules-load.d', '/etc/sysctl.conf', '/etc/sysctl.d', '/etc/selinux',
             '/etc/audit', '/etc/apt', '/etc/yum.repos.d', '/etc/dnf', '/etc/logrotate.d',
             '/etc/logrotate.conf', '/boot', '/proc', '/sys', '/dev', '/bin', '/sbin', '/lib',
             '/lib64', '/usr/bin', '/usr/sbin', '/usr/lib', '/usr/lib64', '/usr/libexec',
             '/usr/local/bin', '/usr/local/sbin', '/usr/local/lib/acme-agent')
PROTECTED_PARTS = ('.ssh',)     # ~/.ssh/authorized_keys and the like, in any folder
ED25519_SPKI = bytes.fromhex('302a300506032b6570032100')


# ---- where things are ---------------------------------------------------------------------
def _env(name, default):
    return os.environ.get(name) or default


ETC = _env('ACME_AGENT_ETC', '/etc/acme-agent')
STATE = _env('ACME_AGENT_STATE', '/var/lib/acme-agent')
ROOT_STATE = _env('ACME_AGENT_ROOT_STATE', '/var/lib/acme-agent-root')
RUN = _env('ACME_AGENT_RUN', '/run/acme-agent')
USER = _env('ACME_AGENT_USER', 'acme-agent')
POLICY = os.path.join(ETC, 'policy')
CONF = os.path.join(ETC, 'agent.json')
CA_FILE = os.path.join(ETC, 'ca.pem')
SOCK = os.path.join(RUN, 'root.sock')
OPENSSL = _env('ACME_AGENT_OPENSSL', 'openssl')


def _agent_version():
    """The acme release this agent came with: the file `release` beside it (the package),
    else acme's own tree around it - never a number bumped by hand."""
    here = os.path.dirname(os.path.realpath(__file__))
    for path, rx in ((os.path.join(here, 'release'), r'\s*([0-9]+(?:\.[0-9]+)*)\s*\Z'),
                     (os.path.join(os.path.dirname(os.path.dirname(here)), 'acmelib',
                                   '__init__.py'), r'(?m)^__version__ = [\'"]([0-9.]+)[\'"]')):
        try:
            with open(path) as f:
                m = re.search(rx, f.read())
        except OSError:
            continue
        if m:
            return m.group(1)
    return '?'


def code_hash(folder=None):
    """sha256 of the agent's program, as acme ships it: acme compares it with its own."""
    folder = folder or os.path.dirname(os.path.realpath(__file__))
    h = hashlib.sha256()
    for name in AGENT_FILES:
        try:
            with open(os.path.join(folder, name), 'rb') as f:
                h.update(hashlib.sha256(f.read()).digest())
        except OSError:
            h.update(b'\0' * 32)
    return h.hexdigest()


VERSION = _agent_version()
CODE = code_hash()


# ---- small things ---------------------------------------------------------------------------
def _write(path, data, mode=0o600, owner=None):
    if isinstance(data, str):
        data = data.encode('utf-8')
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix='.acme-', dir=d)
    try:
        os.fchmod(fd, mode)
        if owner is not None:
            os.fchown(fd, owner[0], owner[1])
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


def _read(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default


def _json(path, default):
    try:
        got = json.loads(_read(path, '') or 'null')
    except ValueError:
        got = None
    return got if got is not None else default


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


def _unb64(text, n=None, what='a value'):
    try:
        raw = base64.b64decode(str(text or '').strip().encode('ascii'), validate=True)
    except (ValueError, binascii.Error, UnicodeEncodeError):
        raise Refused('%s is not base64' % what)
    if n is not None and len(raw) != n:
        raise Refused('%s is not %d bytes' % (what, n))
    return raw


def _sha(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _openssl(args, data=None, binary=False):
    got = subprocess.run([OPENSSL] + args, input=data, capture_output=True,
                         text=not binary)
    if got.returncode != 0:
        err = got.stderr if not binary else got.stderr.decode('utf-8', 'replace')
        raise Refused('openssl: %s' % (err or '').strip()[-200:])
    return got.stdout


def fp_of_pem(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(str(pem).strip() + '\n')).hexdigest()


def spki_fp(pem_key_or_cert_or_csr):
    """sha256 of the public key (SubjectPublicKeyInfo DER) - what acme shows and the admin
    confirms, the same whatever certificate the key has."""
    text = str(pem_key_or_cert_or_csr or '')
    if 'CERTIFICATE REQUEST' in text:
        pub = _openssl(['req', '-noout', '-pubkey'], text)
    elif 'CERTIFICATE' in text:
        pub = _openssl(['x509', '-noout', '-pubkey'], text)
    else:
        pub = _openssl(['pkey', '-pubout'], text)
    der = _openssl(['pkey', '-pubin', '-outform', 'DER'], pub.encode(), binary=True)
    return hashlib.sha256(der).hexdigest()


def fp_words(fp):
    """AB12 CD34 ... - the fingerprint as it is compared by eye."""
    fp = str(fp or '').upper()
    return ' '.join(fp[i:i + 4] for i in range(0, len(fp), 4))


def cert_end(pem):
    out = _openssl(['x509', '-noout', '-enddate'], pem)
    return float(ssl.cert_time_to_seconds(out.strip().split('=', 1)[-1]))


def cert_cn(pem):
    out = _openssl(['x509', '-noout', '-subject', '-nameopt', 'RFC2253'], pem)
    m = re.search(r'CN=([^,]+)', out)
    return m.group(1).strip() if m else ''


class Refused(Exception):
    """Said to acme as it is: what is not done, and why."""
    def __init__(self, words, needs=None):
        Exception.__init__(self, words)
        self.needs = needs or []


def audit(**kw):
    """Every operation, refusals too: journald (syslog) and the root side's own log - names,
    paths, hashes and results only, never what a file holds."""
    kw['ts'] = round(time.time(), 3)
    line = json.dumps(kw, sort_keys=True)[:4000]
    try:
        import syslog
        syslog.openlog('acme-agent', 0, syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_NOTICE if kw.get('ok', True) else syslog.LOG_WARNING, line)
    except Exception:                                   # noqa: BLE001
        pass
    try:
        os.makedirs(ROOT_STATE, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(ROOT_STATE, 'audit.log'),
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(line + '\n')
    except OSError:
        pass


# ---- cryptography: Ed25519 (verify), X25519, HKDF, AES-256-GCM (open) -----------------------
# RFC 8032 / 7748 in plain Python - the same as acme's (acmelib/engine/467...), the `cryptography`
# module used instead when it is installed.
def _crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return ed25519, x25519, AESGCM
    except ImportError:
        return None


_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _ed_add(a, b):
    x = (a[1] - a[0]) * (b[1] - b[0]) % _P
    y = (a[1] + a[0]) * (b[1] + b[0]) % _P
    c = 2 * a[3] * b[3] * _D % _P
    d = 2 * a[2] * b[2] % _P
    e, f, g, h = y - x, d - c, d + c, y + x
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _ed_add(q, pt)
        pt = _ed_add(pt, pt)
        s >>= 1
    return q


def _ed_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _ed_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _ed_unpack(raw):
    y = int.from_bytes(raw, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _ed_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    c = _crypto()
    if c:
        try:
            c[0].Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except Exception:                               # noqa: BLE001
            return False
    a = _ed_unpack(pub)
    r = _ed_unpack(sig[:32])
    s = int.from_bytes(sig[32:], 'little')
    if a is None or r is None or s >= _Q:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), 'little') % _Q
    left = _ed_mul(s, _G)
    right = _ed_add(r, _ed_mul(k, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and \
        (left[1] * right[2] - right[1] * left[2]) % _P == 0


def x25519(k, u):
    c = _crypto()
    if c:
        return c[1].X25519PrivateKey.from_private_bytes(k).exchange(
            c[1].X25519PublicKey.from_public_bytes(u))
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    n = int.from_bytes(bytes(kb), 'little')
    x1 = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = x2 + z2, x2 - z2
        aa, bb = a * a % _P, b * b % _P
        e = aa - bb
        c_, d = x3 + z3, x3 - z3
        da, cb = d * a % _P, c_ * b % _P
        x3 = (da + cb) * (da + cb) % _P
        z3 = x1 * (da - cb) * (da - cb) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + 121665 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return int.to_bytes(x2 * pow(z2, _P - 2, _P) % _P, 32, 'little')


def x25519_public(k):
    return x25519(k, int.to_bytes(9, 32, 'little'))


def hkdf_sha256(ikm, salt, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def _xt(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


_SBOX = []


def _sbox():
    if _SBOX:
        return _SBOX
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            # multiplication in GF(2^8)
            a, b, p = i, j, 0
            while b:
                if b & 1:
                    p ^= a
                a = _xt(a)
                b >>= 1
            if p == 1:
                inv[i] = j
                break
    for i in range(256):
        x = inv[i]
        s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xFF
            s ^= x
        _SBOX.append(s ^ 0x63)
    return _SBOX


class _Aes256(object):
    """AES-256, encryption only (GCM needs no more)."""
    def __init__(self, key):
        sb = _sbox()
        w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
        rcon = 1
        for i in range(8, 60):
            t = list(w[i - 1])
            if i % 8 == 0:
                t = [sb[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _xt(rcon)
            elif i % 8 == 4:
                t = [sb[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i - 8], t)])
        self.rk = [sum(w[r * 4:r * 4 + 4], []) for r in range(15)]
        self.sb = sb

    def block(self, data):
        sb, rk = self.sb, self.rk
        s = [a ^ b for a, b in zip(data, rk[0])]
        for r in range(1, 15):
            s = [sb[x] for x in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
            if r != 14:
                m = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                    t = a0 ^ a1 ^ a2 ^ a3
                    m += [a0 ^ t ^ _xt(a0 ^ a1), a1 ^ t ^ _xt(a1 ^ a2),
                          a2 ^ t ^ _xt(a2 ^ a3), a3 ^ t ^ _xt(a3 ^ a0)]
                s = m
            s = [a ^ b for a, b in zip(s, rk[r])]
        return bytes(s)


def _gcm_mul(x, y):
    z, v = 0, x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def aes256gcm_open(key, nonce, data, aad):
    c = _crypto()
    if c:
        try:
            return c[2](key).decrypt(nonce, data, aad)
        except Exception:                               # noqa: BLE001
            raise ValueError('the tag does not match')
    if len(data) < 16:
        raise ValueError('the tag does not match')
    aes = _Aes256(key)
    h = int.from_bytes(aes.block(bytes(16)), 'big')
    body, tag = data[:-16], data[-16:]
    y = 0
    for part in (aad, body):
        for i in range(0, len(part), 16):
            y = _gcm_mul(y ^ int.from_bytes(part[i:i + 16].ljust(16, b'\x00'), 'big'), h)
    y = _gcm_mul(y ^ ((len(aad) * 8) << 64 | len(body) * 8), h)
    want = (y ^ int.from_bytes(aes.block(nonce + b'\x00\x00\x00\x01'), 'big')).to_bytes(16, 'big')
    if not hmac.compare_digest(want, tag):
        raise ValueError('the tag does not match')
    out = bytearray()
    for i in range(0, len(body), 16):
        ks = aes.block(nonce + ((2 + i // 16) & 0xFFFFFFFF).to_bytes(4, 'big'))
        out.extend(a ^ b for a, b in zip(body[i:i + 16], ks))
    return bytes(out)


SEAL_ALG = 'X25519-HKDF-SHA256-A256GCM'


def seal_aad(agent_id, label):
    return ('%s seal\n%s\n%s' % (PROTO, agent_id, label)).encode('utf-8')


def unseal(sealed, priv, agent_id, label):
    """What acme sealed to this agent's X25519 key for `label` (a file's path, 'env'): bytes,
    or Refused. The scheme of acme push (docs/acme-push-protocol.md section 7), its info and
    aad of its own: a sealed thing cannot be moved to another agent nor another file."""
    if not isinstance(sealed, dict) or sealed.get('alg') != SEAL_ALG:
        raise Refused('a secret is sealed with %s or not at all' % SEAL_ALG)
    epk = _unb64(sealed.get('epk'), 32, 'epk')
    nonce = _unb64(sealed.get('nonce'), 12, 'nonce')
    ct = _unb64(sealed.get('ct'), None, 'ct')
    pub = x25519_public(priv)
    shared = x25519(priv, epk)
    if shared == bytes(32):
        raise Refused('a secret was sealed to nothing')
    k = hkdf_sha256(shared, epk + pub, ('%s seal' % PROTO).encode())
    try:
        return aes256gcm_open(k, nonce, ct, seal_aad(agent_id, label))
    except ValueError:
        raise Refused('a secret does not open: it was sealed to another key (join again) or '
                      'for another file')


def proof(secret, *parts):
    """HMAC-SHA256 of the join code's secret over a few lines (the join, both ways)."""
    msg = '\n'.join([PROTO] + [str(p) for p in parts]).encode('utf-8')
    return hmac.new(str(secret).encode('utf-8'), msg, hashlib.sha256).hexdigest()


def endpoints_words(eps):
    return json.dumps(list(eps), separators=(',', ':'))


def proven_endpoints(j, ans, nonce):
    """acme's addresses an active agent pins: those of acme's answer only when acme proved them
    with the code's secret (1.0.116 security: they were taken as they came - somebody between
    could make the agent poll an address of theirs for ever), else those the code named."""
    eps = ans.get('endpoints') if isinstance(ans, dict) else None
    if isinstance(eps, list) and eps and len(eps) <= 8 and \
            all(isinstance(x, str) and 0 < len(x) <= 300 for x in eps):
        want = proof(j['s'], 'endpoints', j['i'], endpoints_words(eps), nonce)
        if hmac.compare_digest(want, str(ans.get('endpoints_proof') or '')):
            return list(eps)
    return [str(x)[:300] for x in (j.get('a') or []) if isinstance(x, str)][:8]


# ---- the policy -----------------------------------------------------------------------------
POLICY_HEAD = """# /etc/acme-agent/policy - what acme may do on this machine (docs/target-agent.md).
# acme proposes, this machine decides: nothing is allowed that is not written here, and acme
# can never change this file. Change it with `acme-agent allow ...` / `acme-agent deny ...`
# (or by hand: one entry a line; `acme-agent policy show` checks it), or write it whole with
# `acme-agent policy apply FILE` (checked first; the one before kept as policy.DATE).
#
#   allow file DIR owner=USER:GROUP mode=0640   files in DIR (and below), at most that mode
#   allow unit NAME reload,restart              systemctl VERB NAME
#   allow test -- COMMAND ARGS...               a fixed command line (never a shell)
#   allow script PATH sha256=HEX                a script on this machine, by its hash
#   allow script-hash HEX                       a script written in acme, by its hash
#   allow from ADDRESS[/BITS]                   passive: acme only from there
#   allow probe HOST:PORT | allow probe local   a test of what HOST:PORT serves, from here
#   allow connect HOST:PORT                     acme reaches HOST:PORT through this agent
#   allow self-update                           acme may update this agent (signed, newer)
#   limit files 20                              files in one deployment
#   limit size 1048576                          bytes of one file
"""


def norm_unit(name):
    name = str(name or '').strip()
    if not UNIT_RE.match(name) or name.startswith('-'):
        raise Refused('%r is not a unit name' % name[:80])
    if '.' not in name.rsplit('@', 1)[-1]:
        name += '.service'
    return name


def norm_dir(path, real=True):
    p = str(path or '').strip()
    if not SAFE_PATH.match(p) or '\\' in p:
        raise Refused('%r is not an absolute path' % p[:120])
    parts = [x for x in p.split('/') if x not in ('', '.')]
    if '..' in parts:
        raise Refused('a path with .. in it: %s' % p[:120])
    p = '/' + '/'.join(parts)
    return os.path.realpath(p) if real else p


def parse_mode(text):
    t = str(text or '').strip()
    if not re.fullmatch(r'0?[0-7]{3}', t):
        raise Refused('a mode is three octal digits (0640): %r' % t[:12])
    return int(t, 8)


def _under(path, top):
    top = top.rstrip('/') or '/'
    if top == '/':
        return False
    return path == top or path.startswith(top + '/')


def protected(path):
    """Why `path` is never written nor taken away by a job, whatever the policy says - or ''.
    The agent's own places (its policy and pins, its state, its program, its socket) and the
    places whose files give root (sudoers, cron, systemd, PAM, ~/.ssh ...)."""
    own = [ETC, STATE, ROOT_STATE, RUN]
    try:
        own.append(lib_dir())
    except Exception:                                   # noqa: BLE001
        pass
    for top in own:
        for t in {os.path.normpath(top), os.path.realpath(top)}:
            if _under(path, t):
                return '%s is acme-agent\'s own (%s) - never written by a job' % (path, t)
    for top in PROTECTED:
        if _under(path, top):
            return '%s is under %s - a file there gives root to whoever writes it; acme-agent ' \
                   'never writes there, whatever the policy says' % (path, top)
    if any(part in PROTECTED_PARTS for part in path.split('/')):
        return '%s is in a .ssh folder - acme-agent never writes there' % path
    return ''


def runs_from(pol, path):
    """Why `path` is never written by a job: a file the policy runs as root - a script it
    allows, a word of a test's command line (`allow test -- /bin/sh /etc/app/check.sh`) - or ''
    (1.0.116 security: a folder allowed for certificates could hold one, and acme would have
    had its own code run as root)."""
    for s in pol.get('scripts') or []:
        if s.get('path') == path:
            return '%s is a script the policy runs - never written by a job' % path
    for argv in pol.get('tests') or []:
        for w in argv:
            if isinstance(w, str) and w.startswith('/') and \
                    (w == path or os.path.normpath(w) == path):
                return '%s is named by a test the policy runs (%s) - never written by a job' % (
                    path, ' '.join(shlex.quote(a) for a in argv)[:200])
    return ''


def trusted_text(path, what):
    """(the text of a file only root may change, or None when it is not there; the problem or
    '') - opened without following a link, checked on the open file (no swap between the
    check and the read): a plain file of root's that nobody else may write, in a folder of
    root's that nobody else may write."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY)
    except FileNotFoundError:
        return None, ''
    except OSError as e:
        if e.errno == 40:                                   # ELOOP: a symbolic link
            return None, '%s is a symbolic link - %s' % (path, what)
        return None, '%s cannot be read (%s) - %s' % (path, e.strerror or e, what)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, '%s is not a plain file - %s' % (path, what)
        if st.st_uid != 0 or st.st_mode & 0o022:
            return None, '%s may be written by somebody else than root (it must be root\'s, ' \
                         'not writable by group or others) - %s' % (path, what)
        try:
            dst = os.stat(os.path.dirname(path) or '/')
        except OSError:
            dst = None
        if dst is None or dst.st_uid != 0 or dst.st_mode & 0o022:
            return None, 'the folder of %s may be written by somebody else than root (it must ' \
                         'be root\'s, not writable by group or others) - %s' % (path, what)
        if st.st_size > POLICY_MOST:
            return None, '%s is bigger than %d bytes - %s' % (path, POLICY_MOST, what)
        chunks, left = [], POLICY_MOST + 1
        while left > 0:
            got = os.read(fd, min(left, 65536))
            if not got:
                break
            chunks.append(got)
            left -= len(got)
        return b''.join(chunks).decode('utf-8', 'replace'), ''
    finally:
        os.close(fd)


def parse_policy(text):
    """The policy file -> {files, units, tests, scripts, script_hashes, from, self_update,
    connect, limits, problems}. A line it cannot read is left out and said (problems)."""
    pol = {'files': [], 'units': {}, 'tests': [], 'scripts': [], 'script_hashes': [],
           'from': [], 'self_update': False, 'connect': [], 'probe': [], 'probe_local': False,
           'limits': {'files': FILES_MOST, 'size': FILE_MOST}, 'problems': []}
    for n, raw in enumerate(str(text or '').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        try:
            words = shlex.split(line, comments=False, posix=True)
        except ValueError as e:
            pol['problems'].append('line %d: %s' % (n, e))
            continue
        try:
            _policy_line(pol, words)
        except Refused as e:
            pol['problems'].append('line %d: %s' % (n, e))
    return pol


def _kv(words, keys=()):
    """(key=value words, the rest). 1.0.116 security: a key the entry does not know, or one
    said twice, makes the line unread - `mod=0600` (a typo) was left out and the entry
    allowed the default 0644 instead."""
    out, rest = {}, []
    for w in words:
        if '=' in w and re.match(r'^[a-z0-9_-]+=', w):
            k, v = w.split('=', 1)
            if k not in keys:
                raise Refused('%s= is not a word of this entry (%s)' % (
                    k[:20], ', '.join(x + '=' for x in keys) or 'none'))
            if k in out:
                raise Refused('%s= twice' % k)
            out[k] = v
        else:
            rest.append(w)
    return out, rest


def _policy_line(pol, words):
    if not words:
        return
    head = words[0]
    if head == 'limit' and len(words) == 3 and words[1] in ('files', 'size'):
        try:
            v = int(words[2])
        except ValueError:
            raise Refused('limit %s takes a number' % words[1])
        top = {'files': 200, 'size': 64 * 1024 * 1024}[words[1]]
        if not 1 <= v <= top:
            raise Refused('limit %s is 1 to %d' % (words[1], top))
        pol['limits'][words[1]] = v
        return
    if head != 'allow' or len(words) < 2:
        raise Refused('an entry begins with "allow" or "limit"')
    what, rest = words[1], words[2:]
    if what == 'file':
        kv, rest = _kv(rest, ('owner', 'mode'))
        if len(rest) != 1:
            raise Refused('allow file DIR [owner=U:G] [mode=0640]')
        owner = kv.get('owner') or 'root:root'
        u, _, g = owner.partition(':')
        g = g or u
        if not OWNER_RE.match(u) or not OWNER_RE.match(g):
            raise Refused('owner=USER:GROUP')
        entry = {'dir': norm_dir(rest[0], real=False), 'owner': u, 'group': g,
                 'mode': parse_mode(kv.get('mode') or '0644')}
        if entry['dir'] == '/':
            raise Refused('the whole file system is no folder to allow')
        pol['files'] = [x for x in pol['files'] if x['dir'] != entry['dir']] + [entry]
    elif what == 'unit':
        if len(rest) != 2:
            raise Refused('allow unit NAME reload,restart')
        verbs = [v.strip() for v in rest[1].split(',') if v.strip()]
        bad = [v for v in verbs if v not in VERBS + ('is-active',)]
        if bad or not verbs:
            raise Refused('the verbs are %s' % ', '.join(VERBS))
        name = norm_unit(rest[0])
        have = pol['units'].setdefault(name, [])
        for v in verbs:
            if v not in have:
                have.append(v)
    elif what == 'test':
        if rest[:1] == ['--']:
            rest = rest[1:]
        pol['tests'].append(check_argv(rest))
    elif what == 'script':
        kv, rest = _kv(rest, ('sha256',))
        if len(rest) != 1 or not HEX64.match(str(kv.get('sha256') or '').lower()):
            raise Refused('allow script PATH sha256=HEX (acme-agent allow script PATH pins it)')
        pol['scripts'] = [x for x in pol['scripts'] if x['path'] != norm_dir(rest[0], False)] + \
            [{'path': norm_dir(rest[0], real=False), 'sha256': kv['sha256'].lower()}]
    elif what == 'script-hash':
        if len(rest) != 1 or not HEX64.match(rest[0].lower()):
            raise Refused('allow script-hash HEX (64 hex digits, sha256)')
        if rest[0].lower() not in pol['script_hashes']:
            pol['script_hashes'].append(rest[0].lower())
    elif what == 'from':
        if len(rest) != 1:
            raise Refused('allow from ADDRESS[/BITS]')
        try:
            pol['from'].append(str(ipaddress.ip_network(rest[0], strict=False)))
        except ValueError:
            raise Refused('%r is not an address or a network' % rest[0][:60])
    elif what == 'self-update':
        pol['self_update'] = True
    elif what == 'connect':
        if len(rest) != 1:
            raise Refused('allow connect HOST:PORT')
        hp = norm_hostport(rest[0])
        if hp not in pol['connect']:
            pol['connect'].append(hp)
    elif what == 'probe':
        if len(rest) != 1:
            raise Refused('allow probe HOST:PORT (or allow probe local)')
        if rest[0] == 'local':
            pol['probe_local'] = True
        else:
            hp = norm_hostport(rest[0])
            if hp not in pol['probe']:
                pol['probe'].append(hp)
    else:
        raise Refused('allow file | unit | test | script | script-hash | from | probe | connect '
                      '| self-update')


HOST_RE = re.compile(r'[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})\Z')
LOCAL = ('127.0.0.1', '::1', 'localhost')


def split_hostport(text):
    """'host:port', '[v6]:port' -> (host, port) - checked: a name or an address, a port 1-65535."""
    t = str(text or '').strip()
    m = re.fullmatch(r'\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})', t) or \
        re.fullmatch(r'([^\s:\[\]]+):([0-9]{1,5})', t)
    if not m:
        raise Refused('%r is not HOST:PORT ([v6 address]:PORT for IPv6)' % t[:80])
    host, port = m.group(1).lower().rstrip('.'), int(m.group(2))
    if not 0 < port < 65536:
        raise Refused('%d is not a port' % port)
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not HOST_RE.match(host) or host.startswith('-') or '..' in host:
            raise Refused('%r is not a host name or an address' % host[:80])
    return host, port


def norm_hostport(text):
    host, port = split_hostport(text)
    return ('[%s]:%d' % (host, port)) if ':' in host else ('%s:%d' % (host, port))


def dest_allowed(pol, host, port, kind):
    """May acme have this machine reach host:port - for a test ('probe') or as its connector
    ('connect')? Only what the policy names: no name resolved to judge it."""
    hp = norm_hostport('[%s]:%d' % (host, port) if ':' in str(host) else '%s:%s' % (host, port))
    if kind == 'connect':
        return hp in pol['connect']
    h = split_hostport(hp)[0]
    return hp in pol['probe'] or (pol['probe_local'] and h in LOCAL)


def check_argv(argv):
    if not isinstance(argv, list) or not argv or len(argv) > 64:
        raise Refused('a command is one to 64 words')
    out = []
    for a in argv:
        a = str(a)
        if not a or len(a) > 1024 or re.search(r'[\x00-\x1f\x7f]', a):
            raise Refused('a word of a command holds a control character or is empty')
        out.append(a)
    if sum(len(a) for a in out) > 4096:
        raise Refused('a command is 4096 characters at most')
    return out


def policy_canon(pol):
    keep = {k: pol[k] for k in ('files', 'units', 'tests', 'scripts', 'script_hashes', 'from',
                                'self_update', 'connect', 'limits')}
    # what phase 3 added - only when used, so a policy of phase 2 keeps its hash
    # ...and what Windows adds (the machine store, IIS, Remote Desktop): never on Linux
    for k in ('probe', 'probe_local', 'store', 'iis', 'rdp'):
        if pol.get(k):
            keep[k] = pol[k]
    return json.dumps(keep, sort_keys=True, separators=(',', ':'))


def policy_load():
    """(parsed policy, its hash, the text) - read each time: a change is in effect at once."""
    # 1.0.116 security: opened without following a link and checked on the open file, its
    # folder too - a policy somebody but root may write (or swap) is not the machine's word
    text, problem = trusted_text(POLICY, 'nothing is allowed')
    if problem and ('symbolic link' in problem or 'not a plain file' in problem):
        raise Refused(problem)
    if text is None:
        pol = parse_policy('')
        if problem:
            pol['problems'].append(problem)
        return pol, _sha(policy_canon(pol)), ''
    pol = parse_policy(text)
    return pol, _sha(policy_canon(pol)), text


def policy_lines(pol):
    """The policy as the lines `acme-agent allow` writes."""
    out = []
    for f in pol['files']:
        out.append('allow file %s owner=%s:%s mode=%04o' % (shlex.quote(f['dir']), f['owner'],
                                                           f['group'], f['mode']))
    for u, vs in sorted(pol['units'].items()):
        out.append('allow unit %s %s' % (u, ','.join(vs)))
    for t in pol['tests']:
        out.append('allow test -- %s' % ' '.join(shlex.quote(a) for a in t))
    for s in pol['scripts']:
        out.append('allow script %s sha256=%s' % (shlex.quote(s['path']), s['sha256']))
    for h in pol['script_hashes']:
        out.append('allow script-hash %s' % h)
    for f in pol['from']:
        out.append('allow from %s' % f)
    if pol.get('probe_local'):
        out.append('allow probe local')
    for c in pol.get('probe') or []:
        out.append('allow probe %s' % c)
    for c in pol['connect']:
        out.append('allow connect %s' % c)
    if pol['self_update']:
        out.append('allow self-update')
    if pol.get('store'):
        out.append('allow store')
    for site in pol.get('iis') or []:
        out.append('allow iis %s' % (site if not re.search(r'[\s"\']', site) else
                                     '"%s"' % site))
    if pol.get('rdp'):
        out.append('allow rdp')
    if pol['limits']['files'] != FILES_MOST:
        out.append('limit files %d' % pol['limits']['files'])
    if pol['limits']['size'] != FILE_MOST:
        out.append('limit size %d' % pol['limits']['size'])
    return out


def policy_report(pol, h):
    """What acme is told of the policy: what is allowed, never a file's content."""
    out = {'hash': h, 'files': pol['files'], 'units': pol['units'], 'tests': pol['tests'],
           'scripts': pol['scripts'], 'script_hashes': pol['script_hashes'],
           'from': pol['from'], 'self_update': pol['self_update'], 'connect': pol['connect'],
           'probe': pol.get('probe') or [], 'probe_local': bool(pol.get('probe_local')),
           'limits': pol['limits'], 'problems': pol['problems'][:20]}
    for k in ('store', 'iis', 'rdp'):               # Windows only, when there
        if pol.get(k):
            out[k] = pol[k]
    return out


# ---- a whole policy checked before it is written (1.0.118: acme-agent policy check / apply,
# the policy builder of acme's pages - which checks the same with the same facts, policy_facts)
SHELLS = ('sh', 'bash', 'dash', 'zsh', 'ksh', 'mksh', 'csh', 'tcsh', 'fish', 'busybox', 'python',
          'python3', 'perl', 'ruby', 'php', 'node')
CONFIG_OK = ('/etc/ssl', '/etc/pki')    # /etc/NAME of certificates, not of a service's settings
POLICY_COPIES = 10                      # the copies of the policy apply keeps (policy.DATE)


def own_places():
    """The agent's own places: never written by a job (protected)."""
    own = [ETC, STATE, ROOT_STATE, RUN]
    try:
        own.append(lib_dir())
    except Exception:                                   # noqa: BLE001
        pass
    return own


def policy_facts():
    """What the policy builder of acme's pages checks with - the very lists the agent uses."""
    return {'protected': list(PROTECTED), 'parts': list(PROTECTED_PARTS),
            'own': ['/etc/acme-agent', '/var/lib/acme-agent', '/var/lib/acme-agent-root',
                    '/run/acme-agent'], 'verbs': list(VERBS), 'shells': list(SHELLS),
            'config_ok': list(CONFIG_OK), 'head': POLICY_HEAD,
            'limits': {'files': FILES_MOST, 'size': FILE_MOST, 'files_most': 200,
                       'size_most': 64 * 1024 * 1024}}


def _shell_line(argv):
    """A test that is a shell (or an interpreter) given a program on its command line."""
    prog = os.path.basename(argv[0]) if argv else ''
    prog = re.sub(r'[0-9.]+\Z', '', prog) or prog
    return prog in SHELLS and any(a in ('-c', '-e', '-E', '--command', '--eval') for a in argv[1:])


def policy_check(text, machine=False):
    """A policy file checked as `acme-agent policy apply` checks it before it writes it ->
    {'pol', 'lines', 'errors': [{line, code, words}], 'warnings': [...]}. An error is a line the
    agent would not read (the line left out - `apply` writes nothing then) or one that can never
    allow anything (a folder under a place no job ever writes); a warning is what the policy
    allows but should be looked at twice. `machine`: on the server itself - each folder its
    real path, each script there with the SHA-256 the line says, each owner an account."""
    errors, warnings = [], []
    entries = []                                        # (line number, its own parse)
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
    tops = list(PROTECTED) + own_places()
    seen_dirs, seen_scripts = {}, {}

    def warn(n, code, words):
        warnings.append({'line': n, 'code': code, 'words': words})

    def inside(path):
        return [d for d in dirs if _under(path, d) and path != d]
    for n, one in entries:
        for f in one['files']:
            d = f['dir']
            why = protected(d)
            if why:
                errors.append({'line': n, 'code': 'protected', 'words': why.replace(
                    ' - never written by a job', ' - no job ever writes there')})
                continue
            if d in seen_dirs:
                warn(n, 'twice', 'files in %s are said twice (line %d too): only this line '
                                 'counts' % (d, seen_dirs[d]))
            seen_dirs[d] = n
            under = [t for t in tops if _under(t, d) and t != d]
            if under:
                warn(n, 'above-protected', '%s holds places no job ever writes (%s%s): the rest '
                     'of it is allowed - allow the narrowest folder that holds only certificates'
                     % (d, ', '.join(under[:3]), ' …' if len(under) > 3 else ''))
            elif re.fullmatch(r'/etc/[^/]+', d) and d not in CONFIG_OK:
                warn(n, 'config-folder', '%s is a folder of configuration: acme could write a '
                     'file the service then reads as root - allow its ssl or certs sub-folder '
                     'where it can' % d)
            if f['mode'] & 0o111:
                warn(n, 'exec-bits', 'mode %04o: no file acme-agent writes is ever executable - '
                     'its x bits are never given (%04o is what a file gets at most)' % (
                         f['mode'], f['mode'] & 0o666))
            if machine:
                real = os.path.realpath(d)
                if real != d:
                    errors.append({'line': n, 'code': 'link', 'words': '%s is %s (a link on the '
                                   'way) - write the real folder' % (d, real)})
                try:
                    owner_ids(f['owner'], f['group'])
                except Refused as e:
                    warn(n, 'no-owner', '%s - a file of this folder owned so is refused' % e)
        for argv in one['tests']:
            if _shell_line(argv):
                warn(n, 'shell', '%s runs what its command line says as root - a fixed script '
                     '(allow script) says what it runs' % ' '.join(
                         shlex.quote(a) for a in argv[:3]))
            for w in argv:
                if w.startswith('/') and inside(os.path.normpath(w)):
                    warn(n, 'runs-from', '%s is in a folder allowed for files (%s): the test runs '
                         'it, so a job never writes it' % (w, inside(os.path.normpath(w))[0]))
        for s in one['scripts']:
            if s['path'] in seen_scripts:
                warn(n, 'twice', 'the script %s is said twice (line %d too): only this line '
                                 'counts' % (s['path'], seen_scripts[s['path']]))
            seen_scripts[s['path']] = n
            if inside(s['path']):
                warn(n, 'runs-from', '%s is in a folder allowed for files (%s): the policy runs '
                     'it, so a job never writes it' % (s['path'], inside(s['path'])[0]))
            if machine:
                try:
                    with open(s['path'], 'rb') as fh:
                        h = _sha(fh.read())
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


def _policy_input(src):
    """The text of a policy given to check / apply: a file, or - (standard input)."""
    try:
        if src == '-':
            raw = sys.stdin.buffer.read(POLICY_MOST + 1)
        else:
            with open(src, 'rb') as fh:
                raw = fh.read(POLICY_MOST + 1)
    except OSError as e:
        raise SystemExit('acme-agent: %s cannot be read: %s' % (src, e.strerror or e))
    if len(raw) > POLICY_MOST:
        raise SystemExit('acme-agent: a policy is %d bytes at most' % POLICY_MOST)
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise SystemExit('acme-agent: the policy is not UTF-8 text')
    if '\x00' in text:
        raise SystemExit('acme-agent: the policy holds a NUL byte')
    return text


def _say_check(got):
    for x in sorted(got['errors'] + got['warnings'], key=lambda x: x['line']):
        print('line %d: %s: %s' % (x['line'], 'error' if x in got['errors'] else 'warning',
                                   x['words']))
    print('%d entr%s, %d error%s, %d warning%s' % (
        len(got['lines']), 'y' if len(got['lines']) == 1 else 'ies', len(got['errors']),
        '' if len(got['errors']) == 1 else 's', len(got['warnings']),
        '' if len(got['warnings']) == 1 else 's'))


def policy_copy_order(name):
    """policy.DATE-TIME[-N] oldest first: by the time, then N as a number (1.0.119: by the
    name, policy.X-10 went before policy.X-2 - a newer copy deleted, an older one kept)."""
    m = re.fullmatch(r'policy\.(\d{8}-\d{6})(?:-(\d+))?', name)
    if not m:
        return ('', 0)
    return (m.group(1), int(m.group(2) or 1))


def policy_apply(text):
    """`acme-agent policy apply`: the whole policy replaced by `text` - checked first (any line
    the agent would not read, a folder no job may write, a script not there with its hash:
    nothing written), root:root 0644 written atomically, the one before kept as
    policy.YYYYMMDD-HHMMSS (the last ten). The root side reads it with its next job."""
    got = policy_check(text, machine=True)
    _say_check(got)
    if got['errors']:
        print('acme-agent: nothing written - %d line%s the agent would not take (above)' % (
            len(got['errors']), '' if len(got['errors']) == 1 else 's'))
        audit(op='policy-apply', ok=False, said='%d errors' % len(got['errors']))
        return 1
    if not text.endswith('\n'):
        text += '\n'
    os.makedirs(ETC, exist_ok=True)
    old, problem = trusted_text(POLICY, 'it is replaced')
    if old is not None and old == text:
        print('nothing changes: %s says this already' % POLICY)
        return 0
    kept = ''
    if old is not None:
        stamp = time.strftime('%Y%m%d-%H%M%S')
        kept = POLICY + '.' + stamp
        i = 1
        while os.path.lexists(kept):
            i += 1
            kept = '%s.%s-%d' % (POLICY, stamp, i)
        _write(kept, old, 0o600, (0, 0))
        mine = sorted((n for n in os.listdir(ETC)
                       if re.fullmatch(r'policy\.\d{8}-\d{6}(-\d+)?', n)),
                      key=policy_copy_order)
        for n in mine[:-POLICY_COPIES]:
            try:
                os.unlink(os.path.join(ETC, n))
            except OSError:
                pass
    elif problem:
        print('note: %s' % problem)
    _write(POLICY, text, 0o644, (0, 0))
    import difflib
    diff = list(difflib.unified_diff((old or '').splitlines(), text.splitlines(),
                                     'policy (before)', 'policy (now)', lineterm='', n=0))
    for line in diff:
        if not line.startswith('@@'):
            print(line)
    said = 'applied: %d entr%s in %s%s - the root side reads it with its next job' % (
        len(got['lines']), 'y' if len(got['lines']) == 1 else 'ies', POLICY,
        (' (the one before: %s)' % kept) if kept else '')
    audit(op='policy-apply', ok=True, said=said[:300])
    print(said)
    return 0


# What acme is told to run on this machine, to allow something (docs/target-agent.md).
def allow_file_words(d, owner, group, mode):
    return 'acme-agent allow file %s --owner %s:%s --mode %04o' % (shlex.quote(d), owner, group,
                                                                    mode)


def file_rule(pol, path):
    """The entry of the policy a file falls under: the deepest folder that holds it."""
    best = None
    for f in pol['files']:
        d = f['dir'].rstrip('/')
        if path.startswith(d + '/') and (best is None or len(d) > len(best['dir'])):
            best = f
    return best


def owner_ids(user, group):
    import grp
    import pwd
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        raise Refused('there is no user %s on this machine' % user)
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError:
        raise Refused('there is no group %s on this machine' % group)
    return uid, gid


def qw(word):
    """A word of a command line as it is typed (sh here; cmd.exe / PowerShell on Windows)."""
    return shlex.quote(word)


def cmd_check(pol, op, needs):
    """One command of a deployment (a test, a reload...) against the policy -> what is run."""
    if not isinstance(op, dict):
        raise Refused('a command is an object')
    if 'any' in op:
        alts = op['any'] if isinstance(op['any'], list) else []
        if not 1 <= len(alts) <= 4:
            raise Refused('one to four alternatives')
        # 1.0.119 security: only the alternatives the policy allows are kept - one it does not
        # allow went into the plan beside an allowed one and ran (as root) when that failed
        ok, miss, bad = [], [], None
        for a in alts:
            got = []
            try:
                one = cmd_check(pol, a, got)
            except Refused as e:
                bad = bad or e
                continue
            if got:
                miss += got
            else:
                ok.append(one)
        if not ok:
            if not miss:
                # not one alternative is a command at all: refused as it is
                raise bad or Refused('one to four alternatives')
            needs += miss
            return {'any': []}
        return {'any': ok}
    if 'unit' in op:
        unit = norm_unit(op.get('unit'))
        verb = str(op.get('verb') or '')
        if verb not in VERBS:
            raise Refused('%r is not one of %s' % (verb[:40], ', '.join(VERBS)))
        if verb not in pol['units'].get(unit, []):
            needs.append({'kind': 'unit', 'what': '%s %s' % (verb, unit),
                          'allow': 'acme-agent allow %s %s %s' % (UNIT_WORD, unit, verb)})
        return {'unit': unit, 'verb': verb}
    if 'argv' in op:
        argv = check_argv(op.get('argv'))
        if argv not in pol['tests']:
            needs.append({'kind': 'test', 'what': ' '.join(qw(a) for a in argv),
                          'allow': 'acme-agent allow test -- %s' % ' '.join(
                              qw(a) for a in argv)})
        return {'argv': argv}
    if 'script' in op:
        path = norm_dir(op.get('script'), real=False)
        rule = next((s for s in pol['scripts'] if s['path'] == path), None)
        if rule is None:
            needs.append({'kind': 'script', 'what': path,
                          'allow': 'acme-agent allow script %s' % qw(path)})
        return {'script': path, 'args': check_argv(op['args']) if op.get('args') else []}
    raise Refused('a command is a unit and a verb, a command line or a script')


class _Here(object):
    """This module as acme_agent_wincert.py sees it: its names as they are when asked (on
    Windows the ones acme_agent_win.py put in their place)."""

    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name)


def _wincert():
    """acme_agent_wincert.py beside this file (the machine store, IIS, the Remote Desktop
    listener) - loaded only for a job that has `win` (Windows)."""
    m = sys.modules.get('acme_agent_wincert')
    if m is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location('acme_agent_wincert', os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'acme_agent_wincert.py'))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        sys.modules['acme_agent_wincert'] = m
    return m


def plan_check(pol, args):
    """Every file, owner, mode, command and script of a deployment against the policy: the
    plan as it will run, or Refused with what the policy lacks (and the lines that allow it)."""
    needs = []
    if 'win' in args:
        # Windows: the PKCS#12 only for the machine store (no path) is no file to write
        _wincert().take_store_file(_Here(), args)
    files = args.get('files') if isinstance(args.get('files'), list) else []
    if len(files) > pol['limits']['files']:
        raise Refused('%d files - the policy allows %d in one deployment' % (
            len(files), pol['limits']['files']),
            [{'kind': 'limit', 'what': '%d files' % len(files),
              'allow': 'acme-agent limit files %d' % len(files)}])
    plan = {'files': [], 'stale': [], 'pre': [], 'test': [], 'reload': [], 'post': [],
            'script': None}
    seen = set()
    for f in files:
        if not isinstance(f, dict):
            raise Refused('a file is an object')
        path = norm_dir(f.get('path'), real=False)
        if path in seen:
            raise Refused('%s twice' % path)
        seen.add(path)
        name = split_path(path)[1]
        if name.startswith('.acme-'):
            raise Refused('%s: a name acme-agent keeps for itself' % path)
        try:
            mode = int(f.get('mode', 0o600))
        except (TypeError, ValueError):
            raise Refused('%s: its mode is a number' % path)
        if not 0 <= mode <= 0o777:
            raise Refused('%s: no setuid, setgid or sticky bits' % path)
        if mode & 0o111:
            # 1.0.116 security: a certificate's file is never a program - an executable
            # written where an allowed test, unit or script runs from would run as root
            raise Refused('%s: %04o - a file acme-agent writes is never executable' % (
                path, mode))
        why = protected(path) or runs_from(pol, path)
        if why:
            raise Refused(why)
        owner = str(f.get('owner') or '')
        rule = file_rule(pol, path)
        u, g = (owner.split(':', 1) + [''])[:2] if owner else (None, None)
        if rule is None:
            d = split_path(path)[0]
            needs.append({'kind': 'file', 'what': path, 'allow': allow_file_words(
                d, u or 'root', g or u or 'root', mode | (0o600 if mode else 0))})
            plan['files'].append({'path': path})
            continue
        u = u or rule['owner']
        g = g or (rule['group'] if not owner else u)
        if (u, g) != (rule['owner'], rule['group']):
            needs.append({'kind': 'owner', 'what': '%s %s:%s' % (path, u, g),
                          'allow': allow_file_words(rule['dir'], u, g, rule['mode'] | mode)})
        if mode & ~rule['mode']:
            needs.append({'kind': 'mode', 'what': '%s %04o' % (path, mode),
                          'allow': allow_file_words(rule['dir'], rule['owner'], rule['group'],
                                                    rule['mode'] | mode)})
        plan['files'].append({'path': path, 'mode': mode, 'owner': u, 'group': g,
                              'rule': rule['dir']})
    for p in args.get('stale') or []:
        try:
            p = norm_dir(p, real=False)
        except Refused:
            continue
        if file_rule(pol, p) and p not in seen and not protected(p) and not runs_from(pol, p):
            plan['stale'].append(p)
    for k in ('pre', 'test', 'reload', 'post'):
        ops = args.get(k) or []
        if not isinstance(ops, list) or len(ops) > 16:
            raise Refused('%s: sixteen commands at most' % k)
        plan[k] = [cmd_check(pol, o, needs) for o in ops]
    sc = args.get('script')
    if sc:
        if not isinstance(sc, dict):
            raise Refused('the script is an object')
        if sc.get('mode') == 'inline':
            body = str(sc.get('body') or '')
            if not body.strip() or len(body.encode('utf-8')) > SCRIPT_MOST:
                raise Refused('a script is 1 byte to 64 KiB')
            interp = str(sc.get('interp') or 'bash')
            if interp not in INTERPS:
                raise Refused('the interpreter is one of %s' % ', '.join(INTERPS))
            h = _sha(body)
            if h not in pol['script_hashes']:
                needs.append({'kind': 'script-hash', 'what': 'the script written in acme '
                              '(%s, sha256 %s)' % (interp, h),
                              'allow': 'acme-agent allow script-hash %s' % h})
            plan['script'] = {'mode': 'inline', 'body': body, 'interp': interp, 'sha256': h,
                              'args': _split_args(sc.get('args'))}
        elif sc.get('mode') == 'path':
            op = cmd_check(pol, {'script': sc.get('path'), 'args': _split_args(sc.get('args'))},
                          needs)
            plan['script'] = {'mode': 'path', 'path': op['script'], 'args': op['args']}
        else:
            raise Refused('a script is written in acme or a path on this machine')
    if 'win' in args:
        plan['win'] = _wincert().win_check(_Here(), pol, args, needs)
    if needs:
        words = '; '.join(n['what'] for n in needs[:6]) + (' …' if len(needs) > 6 else '')
        raise Refused('not allowed by the policy of this machine: %s' % words, needs)
    return plan


def _split_args(text):
    if isinstance(text, list):
        return check_argv(text) if text else []
    t = str(text or '').strip()
    if not t:
        return []
    try:
        return check_argv(shlex.split(t))
    except ValueError:
        raise Refused('the arguments of the script cannot be read')


# ---- files, safely: every folder opened without following a link ---------------------------
# The small steps the classes below take on an open folder - the platform hook (Windows,
# acme_agent_win.py) puts its own in their place.
def split_path(path):
    """(its folder, its name) of a normalised path."""
    d, name = path.rsplit('/', 1)
    return d or '/', name


def dir_close(dfd):
    os.close(dfd)


def unlink_at(dfd, name):
    os.unlink(name, dir_fd=dfd)


def subdir_at(dfd, name, make=False):
    """A folder in an open folder, opened without following a link (made first: `make`)."""
    if make:
        try:
            os.mkdir(name, 0o700, dir_fd=dfd)
        except FileExistsError:
            pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dfd)


def dup_dir(dfd):
    return os.dup(dfd)


def open_dir(path, make_from=None):
    """A descriptor of the folder `path`, walked from / without following any symbolic link;
    the folders below `make_from` (an allowed folder) made when they are not there."""
    parts = [x for x in path.split('/') if x]
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    walked = ''
    try:
        for comp in parts:
            walked += '/' + comp
            try:
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if make_from is None or not (walked + '/').startswith(make_from.rstrip('/') + '/'):
                    raise Refused('%s is not there' % walked)
                os.mkdir(comp, 0o755, dir_fd=fd)
                nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as e:
                if e.errno in (40, 20):     # ELOOP, ENOTDIR: a link, or not a folder
                    raise Refused('%s is a symbolic link or not a folder - refused' % walked)
                raise
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_at(dfd, name, most):
    """(bytes, stat) of a plain file in the folder, or (None, None) when there is none; a link or
    anything but a plain file is refused."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY,
                     dir_fd=dfd)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        if e.errno == 40:
            raise Refused('%s is a symbolic link - refused' % name)
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused('%s is not a plain file' % name)
        if st.st_size > most:
            raise Refused('%s is bigger than %d bytes' % (name, most))
        chunks, left = [], st.st_size + 1
        while left > 0:
            got = os.read(fd, min(left, 1 << 20))
            if not got:
                break
            chunks.append(got)
            left -= len(got)
        return b''.join(chunks), st
    finally:
        os.close(fd)


def write_at(dfd, name, data, mode, uid, gid):
    """The file put in place: written under a random name in the same folder (never readable by
    others meanwhile), its owner and mode set, synced, renamed over (atomic)."""
    tmp = '.acme-new.%s' % secrets.token_hex(8)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            view = view[n:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise


def backup_name(name, mode, when):
    t = time.localtime(when)
    if mode == 'dated' or mode == 'folder':
        return name + '.' + time.strftime('%Y%m%d-%H%M%S', t) + '.bak'
    if mode == 'daily':
        return name + '.' + time.strftime('%Y-%m-%d', t) + '.bak'
    if mode == 'bak':
        return name + '.bak'
    return None


def prune_backups(dfd, name, keep):
    """The newest `keep` dated copies of a file kept, the older ones deleted."""
    if not keep:
        return 0
    rx = re.compile(re.escape(name) + r'\.\d{4}[\d-]*\.bak\Z')
    got = []
    for n in os.listdir(dfd):
        if rx.match(n):
            try:
                st = os.stat(n, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                got.append((st.st_mtime, n))
    got.sort(reverse=True)
    n = 0
    for _t, old in got[keep:]:
        try:
            os.unlink(old, dir_fd=dfd)
            n += 1
        except OSError:
            pass
    return n


# ---- keys made here (phase 3): root's, never leaving this machine ----------------------------
def keys_dir():
    d = os.path.join(ROOT_STATE, 'keys')
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def key_paths(slot):
    """(the key waiting for its certificate, the key in use) of one deployment."""
    if not SLOT_RE.match(str(slot or '')):
        raise Refused('%r is not a deployment this agent keeps a key for' % str(slot)[:40])
    d = keys_dir()
    return os.path.join(d, slot + '.pending'), os.path.join(d, slot + '.key')


def key_type_of(pem):
    """'ec-256' ... 'rsa-4096' of a private key (PEM), or '' - asked of openssl."""
    try:
        txt = _openssl(['pkey'] + STDIN_IN + ['-noout', '-text_pub'], pem)
    except Refused:
        return ''
    if 'prime256v1' in txt or 'P-256' in txt:
        return 'ec-256'
    if 'secp384r1' in txt or 'P-384' in txt:
        return 'ec-384'
    m = re.search(r'Public-Key: \((\d+) bit', txt)
    if m and 'Modulus' in txt:
        return 'rsa-%s' % m.group(1)
    return ''


def check_names(names):
    out = []
    for n in names or []:
        n = str(n).strip().lower().rstrip('.')
        try:
            out.append(('IP', str(ipaddress.ip_address(n))))
            continue
        except ValueError:
            pass
        if not DNS_RE.match(n) or len(n) > 253:
            raise Refused('%r is not a name a certificate holds' % n[:80])
        out.append(('DNS', n))
    if not 1 <= len(out) <= 100:
        raise Refused('a request for one to a hundred names')
    return out


def make_key_csr(key_pem, names):
    """A CSR of `key_pem` for the names (the first its common name), by openssl."""
    pairs = check_names(names)
    san = ','.join('%s:%s' % p for p in pairs)
    cn = pairs[0][1]
    return _openssl(['req', '-new', '-key', '/dev/stdin', '-subj', '/CN=%s' % cn,
                     '-addext', 'subjectAltName=%s' % san], key_pem)


def _p12_env(password):
    """What openssl pkcs12 runs with: the password in its environment, nothing else."""
    return {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'ACME_AGENT_P12': password or ''}


def key_file(fmt, key_pem, data, password, alias, kt):
    """The bytes of a file holding the key this agent made: the key in its format, or the
    certificate's files acme sent (`data`) with the key put in."""
    kb = key_pem.encode() if isinstance(key_pem, str) else key_pem
    if fmt == 'key-pem':
        return kb
    if fmt in ('key-traditional', 'key-rsa'):
        if fmt == 'key-rsa' and not kt.startswith('rsa'):
            raise Refused('key-rsa (PKCS#1) is only for RSA keys - this one is %s' % kt)
        for args in (['pkey', '-traditional'], ['rsa' if kt.startswith('rsa') else 'ec']):
            try:
                out = _openssl(args + STDIN_IN, kb, binary=True)
            except Refused:
                continue
            if b'BEGIN PRIVATE KEY' not in out:
                return out
        raise Refused('openssl could not write the key in the traditional form')
    if fmt == 'key-der':
        return _openssl(['pkey'] + STDIN_IN + ['-outform', 'DER'], kb, binary=True)
    if fmt == 'combined-pem':
        return kb + (b'' if kb.endswith(b'\n') else b'\n') + data
    if fmt in ('pfx', 'p12'):
        stage = os.path.join(ROOT_STATE, 'stage')
        os.makedirs(stage, mode=0o700, exist_ok=True)
        t = tempfile.mkdtemp(dir=stage)
        try:
            kf, cf = os.path.join(t, 'k.pem'), os.path.join(t, 'c.pem')
            for fn, b in ((kf, kb), (cf, data)):
                fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as f:
                    f.write(b)
            got = subprocess.run([OPENSSL, 'pkcs12', '-export', '-inkey', kf, '-in', cf,
                                  '-name', str(alias or 'acme')[:64], '-passout',
                                  'env:ACME_AGENT_P12'], capture_output=True,
                                 env=_p12_env(password))
            if got.returncode != 0:
                raise Refused('openssl pkcs12: %s' % got.stderr.decode('utf-8', 'replace')
                              .strip()[-200:])
            return got.stdout
        finally:
            for fn in os.listdir(t):
                os.unlink(os.path.join(t, fn))
            os.rmdir(t)
    raise Refused('a key this agent made cannot be written as %s (it can: %s)' % (
        fmt, ', '.join(AGENT_KEY_FORMATS)))


# ---- a signed update of this agent (phase 4: allow self-update) -------------------------------
def lib_dir():
    return os.path.dirname(os.path.realpath(__file__))


def vtuple(v):
    try:
        return tuple(int(x) for x in str(v).strip().split('.'))
    except ValueError:
        return ()


def release_keys():
    """{name: Ed25519 public key (32 bytes)} - the release keys shipped with this agent (beside
    it, or in acme's tree around it): pinned, never taken from what is being installed."""
    here = lib_dir()
    out = {}
    for d in (os.path.join(here, 'release-keys'),
              os.path.join(os.path.dirname(here), 'release-keys')):
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for n in names:
            if not n.endswith('.pub'):
                continue
            pem = _read(os.path.join(d, n), '') or ''
            m = re.search(r'-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----', pem, re.S)
            if not m:
                continue
            try:
                der = base64.b64decode(''.join(m.group(1).split()))
            except (ValueError, binascii.Error):
                continue
            if len(der) == 44 and der[:12] == ED25519_SPKI:
                out[n[:-4]] = der[12:]
        if out:
            break
    return out


def read_package(raw):
    """acme-agent-X.Y.Z.tar.gz -> {name: bytes} of its one folder: plain files only, no link,
    no .. - nothing of it written anywhere."""
    import io
    import tarfile
    if len(raw) > PKG_MOST:
        raise Refused('the package is bigger than %d bytes' % PKG_MOST)
    try:
        tar = tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz')
    except (tarfile.TarError, OSError, EOFError):
        raise Refused('the package is not a .tar.gz')
    out, top, total, n = {}, None, 0, 0
    with tar:
        # one entry at a time, counted (1.0.116 security: getmembers() read every entry of a
        # tar of a million empty folders into root's memory first)
        for m in tar:
            n += 1
            if n > PKG_ENTRIES:
                raise Refused('the package holds more than %d entries' % PKG_ENTRIES)
            parts = m.name.split('/')
            if not parts or '..' in parts or m.name.startswith('/') or '' in parts[1:]:
                raise Refused('the package holds a path that is not one: %r' % m.name[:80])
            if top is None:
                top = parts[0]
            if parts[0] != top or not re.fullmatch(r'acme-agent-[0-9.]+', top):
                raise Refused('the package is not one folder acme-agent-X.Y.Z')
            if m.isdir():
                continue
            if not m.isfile():
                raise Refused('the package holds a link or a device: %s' % m.name[:80])
            total += m.size
            if total > 4 * PKG_MOST or len(out) > 64:
                raise Refused('the package is too big')
            out['/'.join(parts[1:])] = tar.extractfile(m).read()
    return top, out


def verify_package(top, files):
    """Every file against MANIFEST, MANIFEST against its signature by a pinned release key,
    the version newer than this one -> (version, the key's name). Refused otherwise."""
    man = files.get('MANIFEST')
    sig = files.get('MANIFEST.sig')
    if man is None:
        raise Refused('the package has no MANIFEST')
    if sig is None:
        raise Refused('the package is not signed (made from a source tree) - only a release '
                      'package signed by acme\'s release key updates an agent')
    keys = release_keys()
    if not keys:
        raise Refused('this agent has no release key to check a package with (install the '
                      'package of a release by hand once: install.sh)')
    who = next((n for n, k in sorted(keys.items()) if len(sig) == 64 and
                ed25519_verify(k, man, sig)), None)
    if who is None:
        raise Refused('the package\'s signature is not of a release key this agent knows - '
                      'refused')
    listed = {}
    for line in man.decode('utf-8', 'replace').splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line.strip())
        if not m:
            raise Refused('MANIFEST holds a line that is not one')
        listed[m.group(2)] = m.group(1)
    for n, b in files.items():
        if n in ('MANIFEST', 'MANIFEST.sig'):
            continue
        if listed.get(n) != _sha(b):
            raise Refused('%s is not the file MANIFEST names - refused' % n)
    missing = [n for n in listed if n not in files]
    if missing or any(n not in files for n in AGENT_FILES) or 'release' not in files:
        raise Refused('the package is not whole (%s)' % ', '.join(missing[:3] or ['its program']))
    ver = files['release'].decode('ascii', 'replace').strip()
    if not re.fullmatch(r'[0-9]+(\.[0-9]+){1,3}', ver) or top != 'acme-agent-' + ver:
        raise Refused('the package says no version')
    if vtuple(ver) <= vtuple(VERSION):
        raise Refused('the package is version %s, not newer than this agent (%s) - an agent is '
                      'never put back to an older one' % (ver, VERSION))
    return ver, who


def install_files(here, files, names):
    """The files of a checked package put in place of the agent's own, each atomically."""
    for name in names:
        tmp = os.path.join(here, '.%s.new' % name)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                     0o755 if name.endswith('.py') else 0o644)
        with os.fdopen(fd, 'wb') as f:
            f.write(files[name])
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o755 if name.endswith('.py') else 0o644)
        os.replace(tmp, os.path.join(here, name))


def restart_later(delay=2.0):
    """Both sides started again by systemd after an update (not under a test)."""
    if not os.path.isdir('/run/systemd/system') or os.environ.get('ACME_AGENT_NO_SYSTEMD'):
        return False

    def go():
        time.sleep(delay)
        subprocess.run(['systemctl', '--no-block', 'restart', 'acme-agent.service',
                        'acme-agent-root.service'], capture_output=True)
    threading.Thread(target=go, daemon=True).start()
    return True


# ---- the root side --------------------------------------------------------------------------
class Root(object):
    """What root does: every job checked, the plan checked against the policy, done."""

    def __init__(self):
        self.lock = threading.RLock()
        self.work = threading.Lock()
        self.jobs_at = []
        os.makedirs(ROOT_STATE, mode=0o700, exist_ok=True)
        os.makedirs(os.path.join(ROOT_STATE, 'stage'), mode=0o700, exist_ok=True)
        self.seen = self._seen_load()

    # -- the nonces and jobs seen, kept across a restart --------------------------------
    def _seen_path(self):
        return os.path.join(ROOT_STATE, 'seen.json')

    def _seen_load(self):
        got = _json(self._seen_path(), {})
        now = time.time()
        if not isinstance(got, dict):
            return {}
        return {str(k): float(v) for k, v in got.items()
                if isinstance(v, (int, float)) and v > now - 3 * SKEW}

    def _seen_keep(self, keys, now):
        self.seen = {k: v for k, v in self.seen.items() if v > now - 3 * SKEW}
        for k in keys:
            self.seen[k] = now
        try:
            _write(self._seen_path(), json.dumps(self.seen))
        except OSError:
            pass

    # -- the conf root pinned at the join ----------------------------------------------------
    @staticmethod
    def conf():
        """What root pinned at the join (agent.json) - believed only when root alone may change
        it and its folder (1.0.116 security: it names acme's command key, and the systemctl
        root runs); otherwise nothing is pinned and every job is refused."""
        text, problem = trusted_text(CONF, 'no job is taken')
        if problem:
            audit(op='conf', ok=False, said=problem[:300])
        try:
            c = json.loads(text) if text else {}
        except ValueError:
            c = {}
        return c if isinstance(c, dict) else {}

    @staticmethod
    def enc_key():
        raw = _read(os.path.join(ROOT_STATE, 'enc.key'), '') or ''
        try:
            k = bytes.fromhex(raw.strip())
        except ValueError:
            k = b''
        return k if len(k) == 32 else None

    def status(self):
        pol, h, _t = policy_load()
        c = self.conf()
        k = self.enc_key()
        return {'version': VERSION, 'code': CODE, 'policy': policy_report(pol, h),
                'agent_id': c.get('agent_id') or '', 'joined': bool(c.get('joined')),
                'enc_pub': _b64(x25519_public(k)) if k else ''}

    # -- one signed job ---------------------------------------------------------------------
    def verify(self, msg):
        """acme's signature, the agent's id, the time, a nonce and a job never seen -> the job."""
        c = self.conf()
        if not c.get('joined') or not c.get('cmd_pub') or not c.get('agent_id'):
            raise Refused('this agent has not joined acme')
        text = str(msg.get('job') or '')
        if not 2 <= len(text) <= BODY_MOST:
            raise Refused('the job is not one this agent reads')
        sig = _unb64(msg.get('sig'), 64, 'the signature')
        pub = _unb64(c['cmd_pub'], 32, 'acme\'s key')
        if not ed25519_verify(pub, ('%s job\n' % PROTO).encode() + text.encode('utf-8'), sig):
            raise Refused('the job is not signed by the acme this agent joined')
        try:
            job = json.loads(text)
        except ValueError:
            raise Refused('the job is not JSON')
        if not isinstance(job, dict) or job.get('v') != 1:
            raise Refused('the job is not one this agent reads')
        if job.get('agent') != c['agent_id']:
            raise Refused('the job is for another agent')
        try:
            ts = float(job.get('ts'))
        except (TypeError, ValueError, OverflowError):
            raise Refused('the job has no time')
        if not math.isfinite(ts):
            # NaN passed `abs(now - ts) > SKEW` - a job of no time held for ever (1.0.116)
            raise Refused('the job has no time')
        now = time.time()
        if abs(now - ts) > SKEW:
            raise Refused('the job\'s time is %d s from this machine\'s - set the clocks right'
                          % (now - ts))
        nonce, jid = str(job.get('nonce') or ''), str(job.get('job') or '')
        if not re.fullmatch(r'[0-9a-f]{32}', nonce) or not re.fullmatch(r'[0-9A-Za-z_-]{1,64}',
                                                                         jid):
            raise Refused('the job has no nonce or no id')
        op = str(job.get('op') or '')
        if op not in ROOT_OPS + NET_OPS:
            raise Refused('%r is not an operation of this agent' % op[:40])
        with self.lock:
            if 'n:' + nonce in self.seen or 'j:' + jid in self.seen:
                raise Refused('the job was seen before (a replay) - refused')
            self.jobs_at = [t for t in self.jobs_at if t > now - 60] + [now]
            if len(self.jobs_at) > JOBS_A_MINUTE:
                raise Refused('more than %d jobs a minute - wait a moment' % JOBS_A_MINUTE)
            self._seen_keep(['n:' + nonce, 'j:' + jid], now)
        if not isinstance(job.get('args'), dict):
            job['args'] = {}
        return job

    def handle(self, msg, peer_uid):
        kind = msg.get('kind')
        if kind == 'status':
            return {'ok': True, 'status': self.status()}
        if kind == 'pin':
            return self.pin(msg)
        if kind != 'job':
            return {'ok': False, 'said': 'not a request of this agent'}
        jid, op = '', ''
        try:
            job = self.verify(msg)
            jid, op = job['job'], job['op']
            if op in ('probe', 'connect'):
                # where the network side may go: the policy names it, or nothing
                pol, _h, _t = policy_load()
                host, port = split_hostport(job['args'].get('to'))
                hp = norm_hostport(job['args'].get('to'))
                if not dest_allowed(pol, host, port, op):
                    raise Refused('not allowed by the policy of this machine: %s %s' % (
                        'a test of' if op == 'probe' else 'a connection to', hp),
                        [{'kind': op, 'what': hp, 'allow': 'acme-agent allow %s %s' % (op, hp)}])
                audit(op=op, job=jid, ok=True, said='%s allowed for the network side' % hp)
                return {'ok': True, 'verified': True, 'job': job, 'dest': [host, port]}
            if op in NET_OPS:
                audit(op=op, job=jid, ok=True, said='checked for the network side')
                return {'ok': True, 'verified': True, 'job': job}
            out = getattr(self, 'op_' + op)(job['args'], job, msg)
            audit(op=op, job=jid, ok=bool(out.get('ok', True)),
                  said=str(out.get('said') or '')[:300],
                  files=[(f.get('path'), f.get('sha256')) for f in out.get('files') or []][:40])
            out.setdefault('ok', True)
            return out
        except Refused as e:
            audit(op=op or 'job', job=jid, ok=False, said=str(e)[:300],
                  needs=[n.get('what') for n in e.needs][:20])
            return {'ok': False, 'said': str(e)[:600], 'needs': e.needs[:40], 'refused': True}
        except Exception as e:                          # noqa: BLE001
            audit(op=op or 'job', job=jid, ok=False, said='it went wrong: %s' % str(e)[:200])
            return {'ok': False, 'said': 'it went wrong on the agent: %s' % str(e)[:300]}

    # -- the join: what root pins itself, from the code it was given ------------------------
    def pin(self, msg):
        """The authority and acme's command key, checked against the join code's fingerprints
        (given to root by `acme-agent join`, never by the network side) - then pinned."""
        with self.lock:
            pins = _json(os.path.join(ROOT_STATE, 'join-pins.json'), {})
            if not isinstance(pins, dict) or float(pins.get('until') or 0) < time.time():
                return {'ok': False, 'said': 'no join is under way here (acme-agent join CODE)'}
            ca = str(msg.get('ca_pem') or '')
            try:
                cmd = _unb64(msg.get('cmd_pub'), 32, 'acme\'s key')
                ca_fp = fp_of_pem(ca)
            except (Refused, ValueError):
                return {'ok': False, 'said': 'the authority or the key is not one'}
            if not hmac.compare_digest(ca_fp, str(pins.get('ca') or '')) or \
                    not hmac.compare_digest(_sha(cmd), str(pins.get('ck') or '')):
                audit(op='pin', ok=False, said='the authority or acme\'s key does not match the '
                      'join code')
                return {'ok': False, 'said': 'the authority or acme\'s key is not the one the '
                                             'join code names - refused'}
            aid = str(msg.get('agent_id') or '')
            if not AGENT_ID_RE.match(aid):
                return {'ok': False, 'said': 'the agent\'s id is not one'}
            c = {'agent_id': aid, 'target': pins.get('t'), 'name': pins.get('n'),
                 'mode': pins.get('m'), 'port': int(pins.get('p') or PASSIVE_PORT),
                 'listen': pins.get('listen') or '0.0.0.0',
                 'acme': [str(x)[:300] for x in (msg.get('endpoints') or pins.get('a') or [])
                          if isinstance(x, str)][:8],
                 'ca_fp': ca_fp, 'cmd_pub': _b64(cmd), 'cmd_fp': _sha(cmd),
                 'joined': bool(msg.get('final')), 'at': time.time()}
            old = self.conf()
            for k in ('systemctl',):
                if old.get(k):
                    c[k] = old[k]
            _write(CA_FILE, ca.strip() + '\n', 0o644)
            _write(CONF, json.dumps(c, indent=1, sort_keys=True), 0o644)
            if msg.get('final'):
                try:
                    os.unlink(os.path.join(ROOT_STATE, 'join-pins.json'))
                except OSError:
                    pass
            audit(op='pin', ok=True, said='joined acme as %s' % aid if msg.get('final')
                  else 'acme pinned for %s' % aid)
            return {'ok': True}

    # -- operations --------------------------------------------------------------------------
    def op_hello(self, args, job, msg):
        st = self.status()
        return {'ok': True, 'said': 'acme-agent %s here' % VERSION, 'version': VERSION,
                'code': CODE, 'policy': st['policy'], 'enc_pub': st['enc_pub'],
                'host': socket.gethostname()[:120], 'os': _os_name(), 'platform': PLATFORM}

    def op_policy(self, args, job, msg):
        return self.op_hello(args, job, msg)

    def op_fingerprints(self, args, job, msg):
        pol, _h, _t = policy_load()
        out = []
        for p in (args.get('paths') or [])[:200]:
            try:
                p = norm_dir(p, real=False)
            except Refused:
                continue
            if not file_rule(pol, p):
                out.append({'path': p, 'sha256': None, 'said': 'not in a folder the policy '
                                                               'allows'})
                continue
            if protected(p):
                out.append({'path': p, 'sha256': None, 'said': protected(p)})
                continue
            d, name = split_path(p)
            try:
                dfd = open_dir(d or '/')
            except Refused as e:
                out.append({'path': p, 'sha256': None, 'said': str(e)})
                continue
            try:
                data, _st = read_at(dfd, name, pol['limits']['size'] * 4)
                out.append({'path': p, 'sha256': _sha(data) if data is not None else None})
            except Refused as e:
                out.append({'path': p, 'sha256': None, 'said': str(e)})
            finally:
                dir_close(dfd)
        return {'ok': True, 'files': out}

    def op_check(self, args, job, msg):
        """A deployment as it would run, against the policy - nothing changed."""
        pol, h, _t = policy_load()
        try:
            plan = plan_check(pol, args)
        except Refused as e:
            return {'ok': False, 'refused': True, 'said': str(e), 'needs': e.needs,
                    'policy_hash': h}
        out = []
        for f in args.get('files') or []:
            p = norm_dir(f.get('path'), real=False)
            d, name = split_path(p)
            try:
                dfd = open_dir(d or '/')
            except Refused as e:
                out.append({'path': p, 'said': str(e) if 'not there' not in str(e) else
                            'its folder is not there yet - it is made'})
                continue
            try:
                data, _st = read_at(dfd, name, pol['limits']['size'] * 4)
                out.append({'path': p, 'said': 'replaces the one there' if data is not None
                            else 'a new file', 'sha256': _sha(data) if data is not None else None})
            except Refused as e:
                out.append({'path': p, 'said': str(e), 'bad': True})
            finally:
                dir_close(dfd)
        if plan.get('win'):
            out += _wincert().dry_check(_Here(), plan['win'])
        bad = [x for x in out if x.get('bad')]
        return {'ok': not bad, 'said': 'the policy allows all of it' if not bad else
                bad[0]['said'], 'files': out, 'policy_hash': h}

    def op_deploy(self, args, job, msg):
        with self.work:
            return Deploy(self, args, job).run()

    def op_keygen(self, args, job, msg):
        """A new key for one deployment, made here and kept by root (never sent anywhere), and
        its CSR: what acme has signed. The files that will hold it are checked against the
        policy first - a key is made only for a deployment that may run. The key goes into its
        files with the deployment of its certificate (until then the key in use stays)."""
        pol, h, _t = policy_load()
        slot = str(args.get('slot') or '')
        pending, current = key_paths(slot)
        kt = str(args.get('key_type') or 'ec-256')
        if kt not in KEY_TYPES:
            raise Refused('%r is not a key type this agent makes (%s)' % (kt[:20],
                                                                      ', '.join(KEY_TYPES)))
        files = args.get('files') if isinstance(args.get('files'), list) else []
        if not files and not args.get('store'):
            raise Refused('no file of the deployment holds the key - give it a key file '
                          '(key-pem, combined-pem, pfx ...)')
        for f in files:
            if not isinstance(f, dict) or str(f.get('format') or '') not in AGENT_KEY_FORMATS:
                raise Refused('%s: a key this agent makes cannot be written as %s (it can: %s)'
                              % (str((f or {}).get('path'))[:200], str((f or {}).get('format')),
                                 ', '.join(AGENT_KEY_FORMATS)))
        plan_check(pol, {'files': [{k: f.get(k) for k in ('path', 'mode', 'owner') if k in f}
                                   for f in files]})
        if args.get('store'):
            # Windows: the key goes into the machine store with its certificate
            _wincert().keygen_check(_Here(), pol)
        names = args.get('names') if isinstance(args.get('names'), list) else []
        held = [n for n in os.listdir(keys_dir()) if n.endswith(('.key', '.pending'))]
        if len({n.rsplit('.', 1)[0] for n in held} | {slot}) > KEYS_MOST:
            raise Refused('this agent holds the keys of %d deployments already' % KEYS_MOST)
        key, kept = None, False
        if args.get('keep'):
            cur = _read(current, '') or ''
            if cur and key_type_of(cur) == kt:
                key, kept = cur, True
        if key is None:
            key = _openssl(['genpkey'] + KEY_TYPES[kt])
        csr = make_key_csr(key, names)
        _write(pending, key, 0o600)
        return {'ok': True, 'csr': csr, 'kept': kept, 'key_fp': spki_fp(key), 'policy_hash': h,
                'said': ('the key in use kept (%s), a CSR of it' if kept else
                         'a new %s key made here - it stays on this machine - and its CSR') % kt}

    def op_update(self, args, job, msg):
        """This agent replaced by a newer one acme offers: only with `allow self-update`, only
        a package signed by a release key this agent was installed with, only a newer version.
        Without the entry acme is told a newer one is there, nothing more."""
        pol, _h, _t = policy_load()
        if not pol['self_update']:
            raise Refused('this machine does not let acme update its agent',
                          [{'kind': 'self-update', 'what': 'acme-agent %s' % str(
                              args.get('version') or '')[:20],
                            'allow': 'acme-agent allow self-update'}])
        raw = _unb64(args.get('package'), None, 'the package')
        top, files = read_package(raw)
        ver, who = verify_package(top, files)
        here = lib_dir()
        with self.work:
            install_files(here, files, AGENT_FILES + ('release',))
        again = restart_later()
        return {'ok': True, 'version': ver,
                'said': 'acme-agent %s is installed (from %s, signed by %s)%s' % (
                    ver, VERSION, who, ' - both sides start again' if again else
                    ' - start both sides again to use it')}


def _os_name():
    got = _read('/etc/os-release', '') or ''
    m = re.search(r'(?m)^PRETTY_NAME="?([^"\n]+)', got)
    return (m.group(1) if m else sys.platform)[:80]


# ---- what the agent tells about its server (1.0.121, docs/target-agent.md "What the agent tells
# about its server"): basic facts of the machine, never a secret - collected by root, kept a
# minute, each bounded in size and time: a fact that is slow or fails is left out, never the
# hello. Sent whole in the hello (`system`), its hash with every active poll (`system_hash`, as
# the policy's) - acme asks the hello again when it changed. Windows: acme_agent_win.py has its
# own system_facts (the registry, the service manager), the rest is this.
SYS_ROOT = _env('ACME_AGENT_SYS_ROOT', '')     # the tests' layout of /proc, /sys, /etc (else /)
SYS_TTL = 60                    # the facts kept this long (s)
SYS_BUDGET_S = 6.0              # all of them at most this long; one slow fact at most:
SYS_FACT_S = 3.0
SYS_MOST = 12 * 1024            # bytes of the facts, as JSON
SYS_TEXT = 200                  # characters of one fact
SYS_LISTS = {'addrs': 16, 'disks': 8, 'services': 40, 'load': 3}
# the services a certificate is deployed to, looked for by their unit (present: its unit file;
# active: systemctl is-active, once for all of them)
SYS_SERVICES = ('nginx', 'httpd', 'apache2', 'haproxy', 'postfix', 'dovecot', 'exim4', 'sendmail',
                'lighttpd', 'caddy', 'traefik', 'envoy', 'squid', 'varnish', 'slapd', 'dirsrv',
                'postgresql', 'mariadb', 'mysql', 'mysqld', 'redis', 'redis-server', 'mongod',
                'vsftpd', 'proftpd', 'pure-ftpd', 'cockpit', 'grafana-server', 'keycloak',
                'tomcat', 'tomcat9', 'tomcat10', 'jenkins', 'gitlab-runsvdir', 'openvpn',
                'strongswan', 'ipsec', 'named', 'bind9', 'rabbitmq-server', 'mosquitto', 'docker',
                'podman', 'kubelet', 'k3s', 'coturn', 'prosody', 'ejabberd', 'asterisk',
                'freeradius', 'radiusd', 'zabbix-server', 'zabbix-agent', 'zabbix-agent2',
                'webmin', 'minio', 'vault', 'consul', 'nomad', 'opensearch', 'elasticsearch',
                'kibana', 'splunk', 'icinga2', 'nagios', 'sshd', 'ssh')
_SYS = {'at': 0.0, 'facts': None, 'hash': '', 'busy': set(), 'cli': (0.0, None)}
_SYS_LOCK = threading.Lock()


def _sysp(path):
    """A place of the machine's (/proc/...) - under ACME_AGENT_SYS_ROOT in the tests."""
    return os.path.join(SYS_ROOT, path.lstrip('/')) if SYS_ROOT else path


def _sysread(path, most=256 * 1024):
    try:
        with open(_sysp(path), 'rb') as f:
            return f.read(most).decode('utf-8', 'replace')
    except OSError:
        return None


def _timed(name, fn, most=SYS_FACT_S, until=None):
    """fn() in a thread of its own -> what it returned, or None when it failed or took longer
    than `most` s (it is left to end by itself, and not started again meanwhile)."""
    if until is not None:
        most = min(most, until - time.time())
    if most <= 0 or name in _SYS['busy']:
        return None
    box = {}

    def go():
        try:
            box['v'] = fn()
        except Exception:                               # noqa: BLE001
            pass
        finally:
            _SYS['busy'].discard(name)
    _SYS['busy'].add(name)
    t = threading.Thread(target=go, daemon=True, name='acme-agent-fact-' + name)
    t.start()
    t.join(most)
    return box.get('v')


def _sys_try(out, fn, *args):
    """One fact (a dict of keys) into `out` - a fact that fails is left out."""
    try:
        got = fn(*args)
    except Exception:                                   # noqa: BLE001
        return
    if isinstance(got, dict):
        out.update({k: v for k, v in got.items() if v not in (None, '', [], {})})


def _sys_value(v, depth=0):
    """A fact as acme is told it: one line of text cut to size, a finite number, short lists."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, int):
        return v if abs(v) < 2 ** 62 else None
    if isinstance(v, float):
        return round(v, 3) if math.isfinite(v) else None
    if isinstance(v, str):
        return re.sub(r'\s+', ' ', re.sub(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]', '', v)).strip()[
            :SYS_TEXT]
    if depth >= 2:
        return None
    if isinstance(v, dict):
        return {str(k)[:40]: _sys_value(x, depth + 1) for k, x in list(v.items())[:20]}
    if isinstance(v, (list, tuple)):
        return [_sys_value(x, depth + 1) for x in list(v)[:40]]
    return None


def sys_bound(facts):
    """The facts bounded: each value, each list, the whole (the long lists cut first)."""
    out = {}
    for k, v in list((facts or {}).items())[:60]:
        v = _sys_value(v)
        if isinstance(v, list):
            v = v[:SYS_LISTS.get(k, 20)]
        if v not in (None, '', [], {}):
            out[str(k)[:40]] = v
    for k in ('services', 'addrs', 'disks', 'load', 'machine', 'cpu'):
        if len(json.dumps(out)) <= SYS_MOST:
            break
        out.pop(k, None)
    while len(json.dumps(out)) > SYS_MOST and out:
        out.pop(sorted(out, key=lambda x: len(json.dumps(out[x])))[-1])
    return out


def sys_hash(facts):
    """The hash of what changes seldom: not the clock, the uptime, the memory or the load
    (a disk by the percent it is used) - a changed one has acme ask the hello again."""
    keep = {k: v for k, v in facts.items()
            if k not in ('clock', 'uptime', 'mem_avail', 'load', 'hash')}
    if isinstance(keep.get('boot'), (int, float)):
        keep['boot'] = int(keep['boot'] // 600)
    keep['disks'] = [[d.get('path'), d.get('size'),
                      int(100 * (1 - d.get('free', 0) / d['size'])) if d.get('size') else 0]
                     for d in facts.get('disks') or [] if isinstance(d, dict)]
    return _sha(json.dumps(keep, sort_keys=True, separators=(',', ':')))


def _vkey(v):
    """'5.14.0-427.13.1.el9_4.x86_64' as something sorted as versions are."""
    return [(0, int(x), '') if x.isdigit() else (1, 0, x) for x in re.findall(r'\d+|[A-Za-z]+',
                                                                             str(v))]


def _sf_runtime():
    out = {'python': sys.version.split()[0], 'openssl': ssl.OPENSSL_VERSION}
    at, cli = _SYS['cli']
    if time.time() - at > 3600:
        def ask():
            got = subprocess.run([OPENSSL, 'version'], capture_output=True, text=True,
                                 timeout=SYS_FACT_S, stdin=subprocess.DEVNULL)
            return got.stdout.strip() if got.returncode == 0 else None
        cli = _timed('openssl', ask)
        _SYS['cli'] = (time.time(), cli)
    if cli:
        out['openssl_cli'] = cli
    return out


def _sf_disks(out, pol, usage, mount_of, extra=()):
    """The file systems of / (C:\\ on Windows) and of the policy's folders: size and free."""
    seen, disks = set(), []
    places = list(extra) + [f.get('dir') for f in (pol or {}).get('files') or []
                            if isinstance(f, dict)]
    for p in places[:24]:
        if not p:
            continue
        try:
            key, mount, fs = mount_of(p)
        except Exception:                               # noqa: BLE001
            continue
        if key in seen:
            continue
        seen.add(key)
        try:
            size, free = usage(mount)
        except Exception:                               # noqa: BLE001
            continue
        if size:
            d = {'path': mount, 'size': int(size), 'free': int(free)}
            if fs:
                d['fs'] = fs
            disks.append(d)
        if len(disks) >= SYS_LISTS['disks']:
            break
    out['disks'] = disks


def _linux_mounts():
    rows = []
    for line in (_sysread('/proc/self/mounts') or '').splitlines()[:2000]:
        w = line.split()
        if len(w) >= 3:
            rows.append((w[1].replace('\\040', ' '), w[2]))
    return rows


def _linux_mount_of(path, mounts):
    p = os.path.realpath(path)
    while not os.path.exists(p) and p != '/':
        p = os.path.dirname(p)
    st = os.stat(p)
    best = ('/', '')
    for mp, fs in mounts:
        if (p == mp or p.startswith(mp.rstrip('/') + '/')) and len(mp) >= len(best[0]):
            best = (mp, fs)
    return st.st_dev, best[0] if os.path.exists(best[0]) else p, best[1]


def _linux_usage(path):
    v = os.statvfs(path)
    return v.f_blocks * v.f_frsize, v.f_bavail * v.f_frsize


def _sf_os_linux():
    text = _sysread('/etc/os-release') or _sysread('/usr/lib/os-release') or ''
    kv = {}
    for line in text.splitlines():
        m = re.match(r'([A-Z_]+)=(.*)\Z', line.strip())
        if m:
            kv[m.group(1)] = m.group(2).strip().strip('"\'')
    out = {'os': kv.get('PRETTY_NAME') or kv.get('NAME') or 'Linux',
           'os_id': kv.get('ID') or 'linux', 'os_version': kv.get('VERSION_ID') or '',
           'os_like': kv.get('ID_LIKE') or ''}
    kern = (_sysread('/proc/sys/kernel/osrelease') or '').strip()
    out['kernel'] = kern or os.uname().release
    out['arch'] = os.uname().machine
    vendor = (_sysread('/sys/class/dmi/id/sys_vendor', 200) or '').strip()
    product = (_sysread('/sys/class/dmi/id/product_name', 200) or '').strip()
    if vendor or product:
        out['machine'] = ' '.join(x for x in (vendor, product) if x and
                                  not product.startswith(vendor or '\0'))[:120] or product
    return out


def _sf_host_linux(until):
    host = (_sysread('/proc/sys/kernel/hostname') or '').strip() or socket.gethostname()
    out = {'hostname': host}
    fqdn = _timed('fqdn', lambda: socket.getfqdn(host), until=until) or ''
    if fqdn and fqdn != host and '.' in fqdn and not fqdn.startswith('localhost'):
        out['fqdn'] = fqdn
    elif '.' in host:
        out['fqdn'] = host
    dom = out.get('fqdn', '').split('.', 1)[1] if '.' in out.get('fqdn', '') else ''
    if not dom:
        nis = (_sysread('/proc/sys/kernel/domainname') or '').strip()
        dom = '' if nis in ('', '(none)') else nis
    if dom:
        out['domain'] = dom
    return out


def _linux_addrs():
    """The interfaces' addresses (no loopback, no link-local): IPv4 by SIOCGIFADDR, IPv6 from
    /proc/net/if_inet6 - never a command."""
    import fcntl
    out = []
    try:
        names = [n for _i, n in socket.if_nameindex()][:64]
    except OSError:
        names = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for n in names:
            if n == 'lo':
                continue
            try:
                raw = fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', n[:15].encode()))
                ip = socket.inet_ntoa(raw[20:24])
                bits = ''
                try:
                    m = fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', n[:15].encode()))
                    bits = '/%d' % bin(struct.unpack('!I', m[20:24])[0]).count('1')
                except OSError:
                    pass
                if not ip.startswith('127.'):
                    out.append({'if': n, 'ip': ip + bits})
            except OSError:
                continue
    finally:
        s.close()
    return out


def _linux_addrs6():
    out = []
    for line in (_sysread('/proc/net/if_inet6') or '').splitlines()[:200]:
        w = line.split()
        if len(w) < 6 or w[5] == 'lo':
            continue
        try:
            ip = ipaddress.IPv6Address(bytes.fromhex(w[0]))
        except ValueError:
            continue
        if ip.is_link_local or ip.is_loopback:
            continue
        out.append({'if': w[5], 'ip': '%s/%d' % (ip, int(w[2], 16))})
    return out


def _sf_hw_linux():
    out = {}
    cpu = _sysread('/proc/cpuinfo', 512 * 1024) or ''
    model = re.search(r'(?mi)^(?:model name|hardware|cpu model|processor\s*:\s*[A-Za-z])\s*:\s*'
                      r'(.+)$', cpu)
    if model:
        out['cpu'] = model.group(1).strip()
    n = len(re.findall(r'(?m)^processor\s*:\s*\d+', cpu))
    out['cores'] = n or os.cpu_count() or 0
    mem = _sysread('/proc/meminfo') or ''
    for k, name in (('MemTotal', 'mem_total'), ('MemAvailable', 'mem_avail')):
        m = re.search(r'(?m)^%s:\s*(\d+)\s*kB' % k, mem)
        if m:
            out[name] = int(m.group(1)) * 1024
    load = (_sysread('/proc/loadavg') or '').split()
    if len(load) >= 3:
        out['load'] = [float(x) for x in load[:3]]
    up = (_sysread('/proc/uptime') or '').split()
    stat_ = _sysread('/proc/stat') or ''
    m = re.search(r'(?m)^btime\s+(\d+)', stat_)
    if m:
        out['boot'] = int(m.group(1))
    elif up:
        out['boot'] = int(time.time() - float(up[0]))
    return out


def _sf_tz_linux():
    out = {}
    name = (_sysread('/etc/timezone', 200) or '').strip()
    if not name:
        try:
            link = os.readlink(_sysp('/etc/localtime'))
            name = link.split('zoneinfo/', 1)[1] if 'zoneinfo/' in link else ''
        except OSError:
            name = ''
    out['tz'] = name or time.strftime('%Z')
    out['tz_offset'] = int(time.localtime().tm_gmtoff // 60)
    return out


def _sf_security_linux():
    out = {}
    enf = (_sysread('/sys/fs/selinux/enforce', 8) or '').strip()
    if enf in ('0', '1'):
        out['selinux'] = 'enforcing' if enf == '1' else 'permissive'
    else:
        # SELinux not mounted: disabled where it is installed (its configuration there)
        if _sysread('/etc/selinux/config', 8192) is not None:
            out['selinux'] = 'disabled'
    aa = (_sysread('/sys/module/apparmor/parameters/enabled', 8) or '').strip()
    if aa:
        out['apparmor'] = aa.upper().startswith('Y')
    comm = (_sysread('/proc/1/comm', 64) or '').strip()
    if os.path.isdir(_sysp('/run/systemd/system')) or comm == 'systemd':
        out['init'] = 'systemd'
    elif comm:
        out['init'] = comm
    return out


def _sf_reboot_linux(kernel):
    why = []
    for p in ('/run/reboot-required', '/var/run/reboot-required'):
        if os.path.exists(_sysp(p)):
            pkgs = (_sysread(p + '.pkgs', 4096) or '').split()
            why.append('reboot-required' + (' (%s)' % ', '.join(sorted(set(pkgs))[:4])
                                            if pkgs else ''))
            break
    for top in ('/lib/modules', '/usr/lib/modules'):
        try:
            have = [x for x in os.listdir(_sysp(top)) if not x.startswith('.')]
        except OSError:
            continue
        if kernel and kernel in have:
            newest = max(have, key=_vkey)
            if newest != kernel and _vkey(newest) > _vkey(kernel):
                why.append('a newer kernel is installed (%s)' % newest)
        break
    return {'reboot': bool(why), 'reboot_why': '; '.join(why)}


def _sf_services_linux(until):
    """The known services there (their unit file) and which run (one systemctl is-active)."""
    dirs = ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system',
            '/lib/systemd/system')
    have = []
    for name in SYS_SERVICES:
        if any(os.path.exists(_sysp('%s/%s.service' % (d, name))) for d in dirs):
            have.append(name)
    if not have:
        return {'services': []}
    states = {}
    ctl = next((p for p in ('/usr/bin/systemctl', '/bin/systemctl')
                if os.path.exists(_sysp(p))), None)
    if ctl:
        def ask():
            got = subprocess.run([_sysp(ctl), 'is-active', '--'] + ['%s.service' % n
                                                                   for n in have],
                                 capture_output=True, text=True, timeout=SYS_FACT_S,
                                 stdin=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin'})
            return got.stdout.split()
        said = _timed('services', ask, until=until) or []
        if len(said) == len(have):
            states = dict(zip(have, said))
    return {'services': [{'name': n, 'state': 'active' if states.get(n) == 'active'
                          else 'present'} for n in have]}


def system_facts(pol=None):
    """The facts of this Linux server (Windows: acme_agent_win.system_facts)."""
    until = time.time() + SYS_BUDGET_S
    out = {'platform': PLATFORM}
    _sys_try(out, _sf_os_linux)
    _sys_try(out, _sf_hw_linux)
    _sys_try(out, _sf_tz_linux)
    _sys_try(out, _sf_security_linux)
    _sys_try(out, _sf_reboot_linux, out.get('kernel'))
    _sys_try(out, _sf_runtime)
    _sys_try(out, _sf_host_linux, until)
    addrs = (_timed('addrs', _linux_addrs, until=until) or []) + \
        (_timed('addrs6', _linux_addrs6, until=until) or [])
    if addrs:
        out['addrs'] = addrs
    mounts = _timed('mounts', _linux_mounts, until=until) or []
    _sys_try(out, lambda: _sf_disks(out, pol, _linux_usage,
                                    lambda p: _linux_mount_of(p, mounts), ('/',)) or {})
    _sys_try(out, _sf_services_linux, until)
    return out


def system_info(fresh=False):
    """(the facts, their hash) - collected at most once a minute; the clock and the uptime of
    now. Never raises: what could not be said is left out."""
    with _SYS_LOCK:
        if fresh or _SYS['facts'] is None or time.time() - _SYS['at'] > SYS_TTL:
            try:
                pol = policy_load()[0]
            except Exception:                           # noqa: BLE001
                pol = None
            try:
                facts = sys_bound(system_facts(pol))
            except Exception:                           # noqa: BLE001
                facts = {'platform': PLATFORM}
            _SYS.update(facts=facts, hash=sys_hash(facts), at=time.time())
        facts, h = dict(_SYS['facts']), _SYS['hash']
    now = time.time()
    facts['clock'] = round(now, 3)
    if isinstance(facts.get('boot'), (int, float)):
        facts['uptime'] = max(0, int(now - facts['boot']))
    facts['hash'] = h
    return facts, h


class Deploy(object):
    """One deployment: checked, files staged and put in place, tested, reloaded - or the
    previous files back."""

    def __init__(self, root, args, job):
        self.root, self.args, self.job = root, args, job
        self.steps = []
        self.done = []          # (dir, name, old bytes | None, old stat | None) for putting back
        self.gone = []          # stale files taken away: (dir, name, bytes, stat)
        self.agent_id = root.conf().get('agent_id') or ''
        self.key_from = None        # the key this agent made: ('pending' | 'current', slot)

    def step(self, words, level='info'):
        self.steps.append([level, str(words)[:600]])

    def run(self):
        pol, h, _t = policy_load()
        plan = plan_check(pol, self.args)           # Refused: nothing done
        priv = self.root.enc_key()
        datas = []
        ak = self.args.get('agent_key') if isinstance(self.args.get('agent_key'), dict) else None
        key_pem, kt, pw = None, '', None
        for f, p in zip(self.args.get('files') or [], plan['files']):
            if f.get('agent_key'):
                # the key this agent made for this deployment: root's own, put in here
                if ak is None:
                    raise Refused('%s holds a key this agent made, and the job says no more of '
                                  'it' % p['path'])
                if key_pem is None:
                    key_pem, kt = self.agent_key(ak)
                    if ak.get('pass_sealed'):
                        if priv is None:
                            raise Refused('this agent has no key to open secrets with (join '
                                          'again)')
                        pw = unseal(ak['pass_sealed'], priv, self.agent_id,
                                    'pfx').decode('utf-8')
                data = key_file(str(f.get('format') or ''), key_pem,
                                _unb64(f.get('data') or '', None, p['path']), pw,
                                ak.get('alias'), kt)
            elif f.get('sealed'):
                if priv is None:
                    raise Refused('this agent has no key to open secrets with (join again)')
                data = unseal(f['sealed'], priv, self.agent_id, 'file ' + p['path'])
            else:
                data = _unb64(f.get('data'), None, p['path'])
            if len(data) > pol['limits']['size']:
                raise Refused('%s is %d bytes - the policy allows %d' % (
                    p['path'], len(data), pol['limits']['size']),
                    [{'kind': 'limit', 'what': '%s %d bytes' % (p['path'], len(data)),
                      'allow': 'acme-agent limit size %d' % len(data)}])
            p['uid'], p['gid'] = owner_ids(p['owner'], p['group'])
            p['keep_if_there'] = bool(f.get('keep_if_there'))
            datas.append(data)
        env = {}
        for k, v in (self.args.get('env') or {}).items():
            if SAFE_ENV.match(str(k)) and str(k).startswith('ACME_') and \
                    not re.search(r'[\x00]', str(v)):
                env[str(k)] = str(v)[:8192]
        if self.args.get('env_sealed'):
            if priv is None:
                raise Refused('this agent has no key to open secrets with (join again)')
            try:
                more = json.loads(unseal(self.args['env_sealed'], priv, self.agent_id, 'env'))
            except ValueError:
                raise Refused('the sealed variables are not JSON')
            for k, v in (more if isinstance(more, dict) else {}).items():
                # a NUL in a value stopped the first command with ValueError after the files
                # were written - nothing put back (1.0.119): left out, as of the plain ones
                if SAFE_ENV.match(str(k)) and str(k).startswith('ACME_') and \
                        '\x00' not in str(v):
                    env[str(k)] = str(v)[:8192]
        backup = str(self.args.get('backup') or 'dated')
        backup = backup if backup in BACKUPS else 'dated'
        try:
            keep = max(0, min(1000, int(self.args.get('backup_keep', 5))))
        except (TypeError, ValueError):
            keep = 5
        when = time.time()
        win = None
        if plan.get('win'):
            # Windows: the machine store, IIS, the Remote Desktop listener (acme_agent_wincert)
            win = self.win = _wincert().WinJob(_Here(), self, plan['win'], priv, datas, ak)
        # the files there now, each compared
        same, olds = [], []
        for p, data in zip(plan['files'], datas):
            d, name = split_path(p['path'])
            try:
                dfd = open_dir(d or '/')
            except Refused as e:
                if 'not there' not in str(e):
                    raise
                same.append(False)
                olds.append((None, None))
                self.step('%s: not there yet - written' % p['path'])
                continue
            try:
                old, st = read_at(dfd, name, max(pol['limits']['size'], FILE_MOST) * 4)
            finally:
                dir_close(dfd)
            olds.append((old, st))
            if old is None:
                same.append(False)
                self.step('%s: not there yet - written' % p['path'])
            elif p['keep_if_there']:
                same.append(True)
                self.step('%s: made anew each time - this certificate was put there already: '
                          'left as it is' % p['path'], 'ok')
            elif _sha(old) == _sha(data) and stat.S_IMODE(st.st_mode) == p['mode'] and \
                    (st.st_uid, st.st_gid) == (p['uid'], p['gid']):
                same.append(True)
                self.step('%s: the same SHA-256 (%s…) - left as it is' % (p['path'],
                                                                          _sha(data)[:16]), 'ok')
            else:
                same.append(False)
                self.step('%s: SHA-256 there %s…, new %s… - replaced' % (
                    p['path'], _sha(old)[:16], _sha(data)[:16]))
        skip = self.args.get('skip_same', True) not in (False, 0, '0')
        if not skip:
            same = [False] * len(same)
        result_files = [{'path': p['path'], 'sha256': _sha(d)} for p, d in zip(plan['files'],
                                                                                  datas)]
        if win is not None and win.same:
            win.say_same()
        if all(same) and not plan['stale'] and not self.args.get('pending') and \
                (win is None or win.same):
            self.step('nothing replaced: every file holds this certificate already (the same '
                      'SHA-256) - no command, script or reload run', 'ok')
            self.key_in_use()
            return {'ok': True, 'unchanged': True, 'steps': self.steps, 'files': result_files,
                    'said': 'unchanged: every file holds it already', 'policy_hash': h}
        if all(same) and (win is None or win.same):
            self.step('every file holds it already, but the last deployment here did not finish '
                      '- the commands run all the same', 'warn')
        for op in plan['pre']:
            ok, said = self.run_op(op, env, 'before')
            if not ok:
                raise Refused('"%s" failed before anything was written: %s' % (
                    op_words(op), said))
        try:
            written = []
            for p, data, s, (old, st) in zip(plan['files'], datas, same, olds):
                if s:
                    continue
                self.put(p, data, old, st, backup, when)
                written.append(p['path'])
            if written:
                self.step('wrote %s' % ', '.join(written), 'ok')
            for path in plan['stale']:
                self.take_away(path)
        except Exception as e:                          # noqa: BLE001
            self.put_back()
            raise Refused('the files could not be written, the previous ones are back: %s'
                          % str(e)[:300])
        if win is not None:
            try:
                win.apply()
            except Exception as e:                      # noqa: BLE001
                self.put_back()             # the bindings, the store and the files back
                return self.failed('%s - the previous files are back' % str(e)[:300],
                                   result_files, h)
        try:
            for op in plan['test']:
                ok, said = self.run_op(op, env, 'test')
                if not ok:
                    self.put_back()
                    return self.failed('the test "%s" failed, the previous files are back: %s'
                                       % (op_words(op), said), result_files, h)
            if plan['script']:
                ok, said = self.run_script(plan['script'], env, plan, datas)
                if not ok:
                    self.put_back()
                    return self.failed('the script failed, the previous files are back: %s' % said,
                                       result_files, h)
            for op in plan['reload']:
                ok, said = self.run_op(op, env, 'reload')
                if not ok:
                    self.put_back()
                    for again in plan['reload']:
                        self.run_op(again, env, 'reload with the previous files')
                    return self.failed('"%s" failed, the previous files are back: %s' % (
                        op_words(op), said), result_files, h)
        except Exception as e:                          # noqa: BLE001
            # 1.0.119: a command that could not even be started (a staging folder not
            # writable, a value it cannot take) left the new files in place - put back now
            self.put_back()
            return self.failed('it went wrong after the files were written, the previous '
                               'files are back: %s' % str(e)[:300], result_files, h)
        for op in plan['post']:
            self.run_op(op, env, 'after', warn=True)
        self.after(backup, keep)
        if win is not None:
            win.finish()
        self.key_in_use()
        return {'ok': True, 'steps': self.steps, 'files': result_files, 'policy_hash': h,
                'said': '%d file%s written%s%s%s' % (
                    sum(1 for s in same if not s), '' if sum(1 for s in same if not s) == 1
                    else 's', win.words() if win is not None else '',
                    ', the script ran' if plan['script'] else '',
                    ', reloaded' if plan['reload'] else '')}

    def agent_key(self, ak):
        """(the key this agent made that the certificate is for, its type): the one waiting
        for its certificate, or the one in use - never one the certificate is not of."""
        pending, current = key_paths(str(ak.get('slot') or ''))
        cert = str(ak.get('cert_pem') or '')
        try:
            want = spki_fp(cert)
        except (Refused, ValueError):
            raise Refused('the job holds no certificate for the key this agent made')
        for which, path in (('pending', pending), ('current', current)):
            pem = _read(path, '') or ''
            if pem and spki_fp(pem) == want:
                self.key_from = (which, pending, current)
                self.step('the key: the one this agent made %s (it never left this machine)' % (
                    'for this certificate' if which == 'pending' else 'before, still in use'),
                    'ok')
                return pem, key_type_of(pem)
        raise Refused('the certificate is not for a key this agent made for this deployment - '
                      'it is issued anew for one')

    def key_in_use(self):
        """The key made for this certificate is the one in use now."""
        if self.key_from and self.key_from[0] == 'pending':
            try:
                os.replace(self.key_from[1], self.key_from[2])
            except OSError:
                pass

    def failed(self, words, files, h):
        self.step(words, 'bad')
        return {'ok': False, 'said': words, 'steps': self.steps, 'files': files,
                'policy_hash': h, 'rolled_back': True}

    def put(self, p, data, old, st, backup, when):
        d, name = split_path(p['path'])
        dfd = open_dir(d or '/', make_from=p['rule'])
        try:
            if old is not None and backup != 'none':
                if backup == 'folder':
                    bfd = subdir_at(dfd, '.acme-backup', make=True)
                else:
                    bfd = dup_dir(dfd)
                try:
                    # the copy without setuid, setgid or sticky bits (1.0.116 security): a
                    # copy of a program of root's that runs as root is not made by acme
                    write_at(bfd, backup_name(name, backup, when), old,
                             stat.S_IMODE(st.st_mode) & 0o777, st.st_uid, st.st_gid)
                finally:
                    dir_close(bfd)
            self.done.append((d or '/', name, old, st))
            write_at(dfd, name, data, p['mode'], p['uid'], p['gid'])
        finally:
            dir_close(dfd)

    def take_away(self, path):
        d, name = split_path(path)
        try:
            dfd = open_dir(d or '/')
        except Refused:
            return
        try:
            old, st = read_at(dfd, name, 64 * 1024 * 1024)
            if old is None:
                return
            unlink_at(dfd, name)
            self.gone.append((d or '/', name, old, st))
            self.step('taken away (written by acme before, not any more): %s' % path)
        finally:
            dir_close(dfd)

    def put_back(self):
        if getattr(self, 'win', None) is not None:
            self.win.undo()                 # Windows: the bindings and the store first
        bad = []
        for d, name, old, st in reversed(self.done):
            try:
                dfd = open_dir(d)
                try:
                    if old is None:
                        unlink_at(dfd, name)
                    else:
                        write_at(dfd, name, old, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
                finally:
                    dir_close(dfd)
            except Exception as e:                      # noqa: BLE001
                bad.append('%s/%s: %s' % (d, name, e))
        for d, name, old, st in self.gone:
            try:
                dfd = open_dir(d)
                try:
                    write_at(dfd, name, old, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
                finally:
                    dir_close(dfd)
            except Exception as e:                      # noqa: BLE001
                bad.append('%s/%s: %s' % (d, name, e))
        self.done, self.gone = [], []
        self.step('the previous files are back' if not bad else
                  'putting the previous files back failed: %s' % '; '.join(bad)[:300],
                  'warn' if not bad else 'bad')

    def after(self, backup, keep):
        if backup in ('dated', 'daily', 'folder') and keep:
            for d, name, old, _st in self.done:
                if old is None:
                    continue
                try:
                    dfd = open_dir(d)
                except Refused:
                    continue
                try:
                    if backup == 'folder':
                        try:
                            bfd = subdir_at(dfd, '.acme-backup')
                        except OSError:
                            continue
                        try:
                            prune_backups(bfd, name, keep)
                        finally:
                            dir_close(bfd)
                    else:
                        prune_backups(dfd, name, keep)
                finally:
                    dir_close(dfd)

    def _env(self, env):
        out = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LANG': 'C.UTF-8', 'HOME': '/root'}
        out.update(env)
        return out

    def run_argv(self, argv, env, timeout=CMD_TIMEOUT):
        try:
            got = subprocess.run(argv, env=self._env(env), cwd='/', stdin=subprocess.DEVNULL,
                                 capture_output=True, timeout=timeout)
        except FileNotFoundError:
            return 127, '%s is not on this machine' % argv[0]
        except subprocess.TimeoutExpired:
            return 124, 'it did not end in %d s' % timeout
        except OSError as e:
            return 126, str(e)
        said = (got.stdout.decode('utf-8', 'replace').rstrip() + '\n' +
                got.stderr.decode('utf-8', 'replace').rstrip()).strip()
        return got.returncode, said[-OUT_MOST:]

    def systemctl(self):
        return str(self.root.conf().get('systemctl') or 'systemctl')

    def unit_verb(self, op):
        """systemctl VERB UNIT, then the state it is in -> (exit code, what is said)."""
        rc, said = self.run_argv([self.systemctl(), op['verb'], op['unit']], {})
        if rc == 0:
            rc2, st = self.run_argv([self.systemctl(), 'is-active', op['unit']], {})
            said = 'is %s' % (st.strip() or ('active' if rc2 == 0 else '?'))
            if rc2 != 0 and op['verb'] != 'try-restart':
                rc = rc2
        return rc, said

    def run_op(self, op, env, what, warn=False):
        if 'any' in op:
            last = (False, 'nothing allowed')
            for a in op['any']:
                last = self.run_op(a, env, what, warn=True)
                if last[0]:
                    return last
            if not warn:
                self.step('%s: none of %s worked' % (what, ' || '.join(op_words(a)
                                                                      for a in op['any'])), 'bad')
            return last
        if 'unit' in op:
            rc, said = self.unit_verb(op)
        elif 'argv' in op:
            rc, said = self.run_argv(op['argv'], env)
        else:
            path = op['script']
            rc, said = self._run_file(path, op.get('args') or [], env, None)
        if rc != 0:
            self.step('%s: %s failed: %s' % (what, op_words(op), said or 'exit %s' % rc),
                      'warn' if warn else 'bad')
            return False, said or 'exit %s' % rc
        self.step('%s: %s%s' % (what, op_words(op), (' - ' + said[-200:]) if said and
                                'unit' in op else ''), 'ok')
        return True, said

    def _run_file(self, path, args, env, body):
        """A script: its bytes checked against the policy's hash when it runs and run from a
        copy root keeps (never the file somebody may change meanwhile)."""
        pol, _h, _t = policy_load()
        if body is None:
            rule = next((s for s in pol['scripts'] if s['path'] == path), None)
            if rule is None:
                return 126, 'the script is not allowed by the policy'
            d, name = split_path(path)
            try:
                dfd = open_dir(d or '/')
            except Refused as e:
                return 126, str(e)
            try:
                data, _st = read_at(dfd, name, SCRIPT_MOST * 16)
            except Refused as e:
                return 126, str(e)
            finally:
                dir_close(dfd)
            if data is None:
                return 127, '%s is not there' % path
            if not hmac.compare_digest(_sha(data), rule['sha256']):
                return 126, ('%s is not the script the policy allows (its SHA-256 changed) - '
                             'acme-agent allow script %s again once it is checked' % (path, path))
            argv0 = None
        else:
            data = body['data']
            argv0 = INTERPS[body['interp']]
        stage = os.path.join(ROOT_STATE, 'stage')
        os.makedirs(stage, mode=0o700, exist_ok=True)
        fn = os.path.join(stage, 'script-%s' % secrets.token_hex(8))
        try:
            fd = os.open(fn, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
            argv = ([argv0, fn] if argv0 else [fn]) + list(args)
            return self.run_argv(argv, env, SCRIPT_TIMEOUT)
        finally:
            try:
                os.unlink(fn)
            except OSError:
                pass

    def run_script(self, sc, env, plan, datas):
        env = dict(env)
        env['ACME_DRY_RUN'] = '0'
        if sc['mode'] == 'inline':
            pol, _h, _t = policy_load()
            if sc['sha256'] not in pol['script_hashes']:
                return False, 'the script is not allowed by the policy any more'
            rc, said = self._run_file('', sc['args'], env,
                                      {'data': sc['body'].encode('utf-8'), 'interp': sc['interp']})
        else:
            rc, said = self._run_file(sc['path'], sc['args'], env, None)
        lines = (said or '').splitlines()
        if rc != 0:
            self.step('the script failed (exit %s)%s' % (rc, (': ' + lines[-1][-200:]) if lines
                                                       else ''), 'bad')
            return False, 'exit %s%s' % (rc, (': ' + lines[-1][-200:]) if lines else '')
        self.step('the script ran%s' % ((': ' + '\n'.join(lines[-8:])) if lines else ''), 'ok')
        return True, said


def op_words(op):
    if 'any' in op:
        return ' || '.join(op_words(a) for a in op['any']) or '(nothing allowed)'
    if 'unit' in op:
        return 'systemctl %s %s' % (op['verb'], op['unit'])
    if 'argv' in op:
        return ' '.join(shlex.quote(a) for a in op['argv'])
    if 'script' in op:
        return ' '.join([op['script']] + [shlex.quote(a) for a in op.get('args') or []])
    return '?'


# ---- the link between the two sides (a Unix socket, length-prefixed JSON) ---------------------
def _send(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack('!I', len(data)) + data)


def _recv(sock, most=BODY_MOST + 65536):
    head = b''
    while len(head) < 4:
        got = sock.recv(4 - len(head))
        if not got:
            raise EOFError
        head += got
    n = struct.unpack('!I', head)[0]
    if n > most:
        raise ValueError('too big')
    data = b''
    while len(data) < n:
        got = sock.recv(min(65536, n - len(data)))
        if not got:
            raise EOFError
        data += got
    return json.loads(data.decode())


def agent_ids():
    """(uid, gid) of the account the network side runs as."""
    import pwd
    try:
        pw = pwd.getpwnam(USER)
    except KeyError:
        return None
    return pw.pw_uid, pw.pw_gid


ROOT_THREADS = 8


def serve_root():
    """The root side: a Unix socket only the network side (and root) may use - never the
    network."""
    if os.geteuid() != 0:
        raise SystemExit('acme-agent root runs as root')
    ids = agent_ids()
    if ids is None:
        raise SystemExit('acme-agent: the account %s is not there (install.sh makes it)' % USER)
    root = Root()
    os.makedirs(RUN, exist_ok=True)
    os.chown(RUN, 0, ids[1])
    os.chmod(RUN, 0o750)
    try:
        os.unlink(SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        srv.bind(SOCK)
    finally:
        os.umask(old)
    os.chown(SOCK, 0, ids[1])
    os.chmod(SOCK, 0o660)
    srv.listen(16)
    room = threading.BoundedSemaphore(ROOT_THREADS)
    stop = {'now': False}

    def bye(*_):
        stop['now'] = True
        try:
            srv.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        srv.close()
    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    audit(op='start', ok=True, said='acme-agent %s (root side)' % VERSION)

    def one(conn):
        try:
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', cred)
            if uid not in (0, ids[0]):
                audit(op='refused', ok=False, said='a connection of uid %d' % uid)
                return
            conn.settimeout(900)
            while True:
                try:
                    msg = _recv(conn)
                except (EOFError, OSError, ValueError):
                    return
                if not isinstance(msg, dict):
                    return
                out = root.handle(msg, uid)
                _send(conn, out)
        finally:
            conn.close()
            room.release()
    while not stop['now']:
        try:
            conn, _ = srv.accept()
        except OSError:
            break
        if not room.acquire(timeout=30):
            conn.close()
            continue
        threading.Thread(target=one, args=(conn,), daemon=True).start()
    # an operation under way finishes (the files put in place or back) before the end
    if root.work.acquire(timeout=300):
        root.work.release()
    return 0


class RootLink(object):
    """The network side's way to root: one request at a time on a connection of its own."""

    def __init__(self, path=SOCK):
        self.path = path

    def ask(self, msg, timeout=900):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(self.path)
            _send(s, msg)
            return _recv(s)
        except (OSError, EOFError, ValueError) as e:
            return {'ok': False, 'said': 'the root side of the agent does not answer (%s) - '
                                         'systemctl status acme-agent-root' % e}
        finally:
            s.close()


# ---- the network side -----------------------------------------------------------------------
def net_conf():
    c = _json(CONF, {})
    return c if isinstance(c, dict) else {}


def tls_paths():
    return os.path.join(STATE, 'tls.key'), os.path.join(STATE, 'tls.crt')


def make_csr(key):
    with open(key) as f:
        kpem = f.read()
    return _openssl(['req', '-new', '-key', '/dev/stdin', '-subj', '/CN=acme-agent'], kpem)


def self_signed(key):
    with open(key) as f:
        kpem = f.read()
    return _openssl(['req', '-new', '-x509', '-days', '2', '-key', '/dev/stdin', '-subj',
                     '/CN=acme-agent-joining'], kpem)


def check_issued(cert_pem, key_path):
    """A certificate acme sent: of this agent's own key, signed by the pinned authority."""
    with open(key_path) as f:
        kpem = f.read()
    if spki_fp(cert_pem) != spki_fp(kpem):
        raise Refused('the certificate is not of this agent\'s key')
    with tempfile.TemporaryDirectory() as t:
        cf, af = os.path.join(t, 'c.pem'), os.path.join(t, 'a.pem')
        with open(cf, 'w') as f:
            f.write(cert_pem)
        with open(af, 'w') as f:
            f.write(_read(CA_FILE, '') or '')
        got = subprocess.run([OPENSSL, 'verify', '-CAfile', af, cf], capture_output=True,
                             text=True)
        if got.returncode != 0:
            raise Refused('the certificate is not one of the authority this agent pinned')


def status_write(**kw):
    kw['at'] = time.time()
    try:
        _write(os.path.join(STATE, 'join-status.json'), json.dumps(kw))
    except OSError:
        pass


def _probe_env():
    """What openssl s_client runs with (a test of what a place serves)."""
    return {'PATH': '/usr/bin:/bin:/usr/local/bin'}


class Net(object):
    """What the network side knows and does: its key and certificate, the join, the jobs."""

    def __init__(self):
        self.root = RootLink()
        self.lock = threading.Lock()
        self.ctx_passive = None
        self.stopping = False
        self.bucket = {}
        self.lsock = None
        self.lsock_at = None

    def conf(self):
        return net_conf()

    def joined(self):
        c = self.conf()
        key, crt = tls_paths()
        return bool(c.get('joined')) and os.path.exists(crt) and os.path.exists(key)

    def join_info(self):
        j = _json(os.path.join(STATE, 'join.json'), {})
        # (1.0.120: or a join with a company enrollment code, before acme named its target)
        return j if isinstance(j, dict) and (j.get('i') or j.get('e')) else None

    def facts(self):
        _key, crt = tls_paths()
        pem = _read(crt, '') or ''
        out = {'version': VERSION, 'code': CODE}
        # 1.0.118: the policy's hash with every poll and answer - acme asks for the policy
        # itself at once when it is not the one it holds (the pages never show an old one)
        try:
            out['policy_hash'] = policy_load()[1]
        except Exception:                               # noqa: BLE001
            pass
        if pem:
            try:
                out.update(cert_fp=fp_of_pem(pem), cert_end=cert_end(pem))
            except (Refused, ValueError):
                pass
        return out

    # -- a job, from acme: root checks it; csr and cert are this side's own ----------------
    def job(self, body, peer_ip=''):
        if not isinstance(body, dict):
            return {'ok': False, 'said': 'not a job'}
        got = self.root.ask({'kind': 'job', 'job': body.get('job'), 'sig': body.get('sig'),
                             'ip': peer_ip})
        if got.get('verified'):
            job = got['job']
            try:
                return getattr(self, 'net_' + job['op'])(job['args'], got)
            except Refused as e:
                return {'ok': False, 'said': str(e)}
        if got.get('ok') and isinstance(got, dict) and 'policy' in got:
            got.update(self.facts())
        return got

    def net_probe(self, args, got):
        """What host:port serves (root checked the policy allows a test of it): the chain it
        sent, by `openssl s_client` - TLS at once or after the protocol's STARTTLS."""
        host, port = got['dest']
        sni = str(args.get('sni') or '').strip().lower()
        if sni not in ('', '-') and not DNS_RE.match(sni):
            raise Refused('%r is not a name to ask for (SNI)' % sni[:80])
        st = str(args.get('starttls') or '')
        if st and st not in STARTTLS:
            raise Refused('%r is not a protocol this agent starts TLS in (%s)' % (
                st[:20], ', '.join(STARTTLS)))
        try:
            timeout = max(2, min(PROBE_S, int(args.get('timeout') or 15)))
        except (TypeError, ValueError):
            timeout = 15
        argv = [OPENSSL, 's_client', '-connect', '[%s]:%d' % (host, port) if ':' in host
                else '%s:%d' % (host, port), '-showcerts']
        argv += ['-servername', sni] if sni not in ('', '-') else ['-noservername']
        if st:
            argv += ['-starttls', st]
            if st == 'xmpp':
                argv += ['-xmpphost', sni if sni not in ('', '-') else host]
        want = str(args.get('key_want') or '')
        if want in ('rsa', 'ecdsa'):
            argv += ['-tls1_2', '-cipher', ('aRSA' if want == 'rsa' else 'aECDSA') +
                     ':!aNULL:@SECLEVEL=0']
        t0 = time.time()
        try:
            r = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                               timeout=timeout, env=_probe_env())
        except subprocess.TimeoutExpired:
            return {'ok': False, 'said': '%s:%d did not finish a handshake in %d s' % (
                host, port, timeout)}
        except OSError as e:
            return {'ok': False, 'said': 'openssl could not be run: %s' % e}
        out = r.stdout.decode('utf-8', 'replace')
        pems = re.findall(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', out, re.S)
        if not pems:
            err = [x for x in r.stderr.decode('utf-8', 'replace').splitlines() if x.strip()]
            return {'ok': False, 'said': '%s:%d: no certificate came (%s)' % (
                host, port, (' / '.join(err[-2:]) or 'no TLS')[:300])}
        chain = [_b64(ssl.PEM_cert_to_DER_cert(p + '\n')) for p in pems[:10]]
        m = re.search(r'Protocol\s*:\s*(\S+)', out) or re.search(r'New, (TLSv[\d.]+)', out)
        c = re.search(r'Cipher\s*(?:is|:)\s*(\S+)', out)
        return {'ok': True, 'chain': chain, 'tls': m.group(1) if m else '',
                'cipher': c.group(1) if c else '', 'ms': int((time.time() - t0) * 1000),
                'said': '%s:%d sent %d certificate%s' % (host, port, len(chain),
                                                         '' if len(chain) == 1 else 's')}

    def net_connect(self, args, got):
        """A connection to host:port for acme (root checked `allow connect` names it)."""
        host, port = got['dest']
        try:
            timeout = max(2, min(60, int(args.get('timeout') or 20)))
        except (TypeError, ValueError):
            timeout = 20
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            return {'ok': False, 'said': '%s:%d cannot be reached from here: %s' % (
                host, port, e.strerror or e)}
        return {'ok': True, 'sock': sock, 'said': 'connected to %s:%d' % (host, port)}

    def net_csr(self, args, got=None):
        key, _crt = tls_paths()
        return {'ok': True, 'csr': make_csr(key), 'said': 'a request for the next certificate'}

    def net_cert(self, args, got=None):
        pem = str(args.get('cert_pem') or '')
        key, crt = tls_paths()
        check_issued(pem, key)
        _write(crt, pem.strip() + '\n', 0o600)
        with self.lock:
            self.ctx_passive = None         # new connections use it
        return {'ok': True, 'said': 'the new certificate is in use', 'cert_fp': fp_of_pem(pem),
                'cert_end': cert_end(pem)}

    # -- the join (both modes): the code's secret proves both ends ---------------------------
    def join_request(self, j, nonce):
        key, _crt = tls_paths()
        csr = make_csr(key)
        st = self.root.ask({'kind': 'status'}).get('status') or {}
        enc = st.get('enc_pub') or ''
        return {'i': j['i'], 'csr': csr, 'enc_pub': enc, 'version': VERSION, 'code': CODE,
                'host': socket.gethostname()[:120], 'nonce': nonce,
                'proof': proof(j['s'], 'join', j['i'], _sha(csr), enc, nonce)}

    def enroll_request(self, j, nonce):
        """The join with a company enrollment code (1.0.120): this server's name and system
        besides what a join says - acme makes the target of it."""
        key, _crt = tls_paths()
        csr = make_csr(key)
        st = self.root.ask({'kind': 'status'}).get('status') or {}
        enc = st.get('enc_pub') or ''
        fqdn = (socket.getfqdn() or socket.gethostname())[:253]
        return {'e': j['e'], 'csr': csr, 'enc_pub': enc, 'version': VERSION, 'code': CODE,
                'host': socket.gethostname()[:120], 'fqdn': fqdn, 'os': _os_name(),
                'platform': PLATFORM, 'port': int(j.get('p') or PASSIVE_PORT), 'nonce': nonce,
                'proof': proof(j['s'], 'enroll', j['e'], _sha(csr), enc, nonce, fqdn)}

    def join_answer(self, j, ans, nonce):
        """acme's answer to the join: its authority and command key against the code's pins,
        its proof of the code - then root pins them itself."""
        ca, cmd, aid = str(ans.get('ca_pem') or ''), str(ans.get('cmd_pub') or ''), \
            str(ans.get('agent_id') or '')
        want = proof(j['s'], 'joined', j['i'], _sha(ca), cmd, aid, nonce)
        if not hmac.compare_digest(want, str(ans.get('proof') or '')):
            raise Refused('the answer is not of the acme that made this code')
        try:
            fp = fp_of_pem(ca)
        except ValueError:
            raise Refused('acme sent no authority')
        if not hmac.compare_digest(fp, j['ca']):
            raise Refused('the authority is not the one the code names (its fingerprint '
                          'differs) - refused')
        if not hmac.compare_digest(_sha(_unb64(cmd, 32, 'acme\'s key')), j['ck']):
            raise Refused('acme\'s key is not the one the code names - refused')
        got = self.root.ask({'kind': 'pin', 'ca_pem': ca, 'cmd_pub': cmd, 'agent_id': aid,
                             'endpoints': proven_endpoints(j, ans, nonce)})
        if not got.get('ok'):
            raise Refused(got.get('said') or 'root refused the pins')
        return aid

    def join_finish(self, j, ans, nonce, aid):
        pem = str(ans.get('cert_pem') or '')
        want = proof(j['s'], 'cert', j['i'], _sha(pem), nonce)
        if not hmac.compare_digest(want, str(ans.get('proof') or '')):
            raise Refused('the certificate is not of the acme that made this code')
        key, crt = tls_paths()
        check_issued(pem, key)
        if cert_cn(pem) != AGENT_CN + aid:
            raise Refused('the certificate is not for this agent')
        _write(crt, pem.strip() + '\n', 0o600)
        got = self.root.ask({'kind': 'pin', 'ca_pem': _read(CA_FILE, ''),
                             'cmd_pub': self.conf().get('cmd_pub'), 'agent_id': aid,
                             'endpoints': proven_endpoints(j, ans, nonce),
                             'final': True})
        if not got.get('ok'):
            raise Refused(got.get('said') or 'root refused the pins')
        try:
            os.unlink(os.path.join(STATE, 'join.json'))
        except OSError:
            pass
        status_write(state='joined', agent_id=aid, said='joined acme')

    # -- passive: this side listens ---------------------------------------------------------
    def passive_ctx(self):
        with self.lock:
            if self.ctx_passive is None:
                key, crt = tls_paths()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.load_cert_chain(crt, key)
                ctx.load_verify_locations(CA_FILE)
                ctx.verify_mode = ssl.CERT_REQUIRED
                self.ctx_passive = ctx
            return self.ctx_passive

    def from_ok(self, ip):
        """`allow from` of the policy (passive): when there is any, only from there."""
        pol, _h, _t = policy_load()
        if not pol['from']:
            return True
        try:
            a = ipaddress.ip_address(ip.split('%')[0])
            if a.version == 6 and a.ipv4_mapped:
                a = a.ipv4_mapped
        except ValueError:
            return False
        return any(a in ipaddress.ip_network(n) for n in pol['from'])

    def take(self, ip, n=1.0, rate=5.0, burst=60.0):
        now = time.monotonic()
        with self.lock:
            left, at = self.bucket.get(ip, (burst, now))
            left = min(burst, left + (now - at) * rate)
            if left < n:
                self.bucket[ip] = (left, now)
                return False
            self.bucket[ip] = (left - n, now)
            if len(self.bucket) > 4096:
                self.bucket = {}
            return True


class PassiveHandler(http.server.BaseHTTPRequestHandler):
    server_version = 'acme-agent'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def answer(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.answer(404, {'ok': False, 'said': 'not here'})

    def do_POST(self):
        net = self.server.net
        ip = self.client_address[0]
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= BODY_MOST:
            return self.answer(413, {'ok': False, 'said': 'too big'})
        raw = self.rfile.read(n)
        if not net.take(ip):
            return self.answer(429, {'ok': False, 'said': 'too many requests'})
        try:
            body = json.loads(raw.decode('utf-8') or '{}')
        except (ValueError, UnicodeDecodeError):
            return self.answer(400, {'ok': False, 'said': 'not JSON'})
        if not isinstance(body, dict):
            return self.answer(400, {'ok': False, 'said': 'not an object'})
        if self.server.joining:
            return self.joining(body)
        if not net.from_ok(ip):
            audit(op='refused', ok=False, said='a request from %s, not among `allow from`' % ip)
            return self.answer(403, {'ok': False, 'said': 'not from an address this agent '
                                                          'allows'})
        peer = self.connection.getpeercert() or {}
        cn = ''
        for rdn in peer.get('subject') or ():
            for k, v in rdn:
                if k == 'commonName':
                    cn = v
        if cn != CTL_CN:
            net.take(ip, 3)
            return self.answer(403, {'ok': False, 'said': 'not acme\'s certificate'})
        if self.path == '/v1/tunnel':
            return self.tunnel(net, body, ip)
        if self.path != '/v1/job':
            return self.answer(404, {'ok': False, 'said': 'not here'})
        out = net.job(body, ip)
        if out.get('sock') is not None:
            out.pop('sock').close()
            out = {'ok': False, 'said': 'a connection is asked on /v1/tunnel'}
        if not out.get('ok') and out.get('said', '').startswith(('the job is not signed',
                                                                  'the job was seen')):
            net.take(ip, 2)
        self.answer(200, out)

    def tunnel(self, net, body, ip):
        """acme's connector (allow connect): a signed job `connect`, root's yes, then this very
        connection carries the bytes both ways until either end closes (or ten idle minutes)."""
        job = {}
        try:
            job = json.loads(str(body.get('job') or '{}'))
        except ValueError:
            pass
        if not isinstance(job, dict) or job.get('op') != 'connect':
            return self.answer(400, {'ok': False, 'said': 'a tunnel is asked by the job connect'})
        out = net.job(body, ip)
        sock = out.pop('sock', None)
        if sock is None:
            return self.answer(403 if out.get('refused') or out.get('needs') else 502, out)
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', '0')
            self.end_headers()
            self.wfile.flush()
            relay(self.connection, sock, TUNNEL_IDLE_S)
        finally:
            self.close_connection = True
            try:
                sock.close()
            except OSError:
                pass
        return None

    def joining(self, body):
        net = self.server.net
        j = net.join_info()
        if not j:
            return self.answer(409, {'ok': False, 'said': 'no join under way'})
        try:
            if self.path == '/v1/join':
                nonce = str(body.get('nonce') or '')
                if not re.fullmatch(r'[0-9a-f]{32}', nonce):
                    raise Refused('no nonce')
                aid = net.join_answer(j, body, nonce)
                j['agent_id'] = aid
                _write(os.path.join(STATE, 'join.json'), json.dumps(j))
                mine = secrets.token_hex(16)
                req = net.join_request(j, mine)
                key, _crt = tls_paths()
                status_write(state='confirm', fp=spki_fp(_read(key, '')),
                             said='acme reached this agent - confirm the fingerprint in acme')
                return self.answer(200, dict(req, ok=True))
            if self.path == '/v1/join/finish':
                nonce = str(body.get('nonce') or '')
                net.join_finish(j, body, nonce, j.get('agent_id') or '')
                self.answer(200, {'ok': True, 'said': 'joined'})
                self.server.restart = True
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return None
        except Refused as e:
            audit(op='join', ok=False, said=str(e))
            status_write(state='refused', said=str(e))
            return self.answer(403, {'ok': False, 'said': str(e)})
        return self.answer(404, {'ok': False, 'said': 'not here'})


def relay(a, b, idle):
    """Bytes both ways between `a` (TLS, acme) and `b` (the connection asked for) until either
    closes or nothing goes through for `idle` seconds."""
    import select
    for x in (a, b):
        x.settimeout(idle)
    while True:
        if getattr(a, 'pending', None) and a.pending():
            ready = [a]
        else:
            ready, _w, _x = select.select([a, b], [], [], idle)
            if not ready:
                return
        for x in ready:
            try:
                data = x.recv(65536)
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                continue
            except OSError:
                return
            if not data:
                return
            try:
                (b if x is a else a).sendall(data)
            except OSError:
                return


class PassiveServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    joining = False
    restart = False
    room = None

    def process_request(self, request, client_address):
        """A thread for a connection while there are fewer than PASSIVE_MOST (1.0.116 security:
        every connection had a thread of its own, held 30 s by a handshake that never came -
        anybody reaching the port could exhaust the network side)."""
        if self.room is None:
            self.room = threading.BoundedSemaphore(PASSIVE_MOST)
        if not self.room.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            http.server.ThreadingHTTPServer.process_request(self, request, client_address)
        except BaseException:
            self.room.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            http.server.ThreadingHTTPServer.process_request_thread(self, request, client_address)
        finally:
            if self.room is not None:
                self.room.release()

    def finish_request(self, request, client_address):
        request.settimeout(30)
        if not self.joining and not self.net.from_ok(client_address[0]):
            # `allow from`: anybody else gets not even a TLS handshake (1.0.116 security)
            audit(op='refused', ok=False, said='a connection from %s, not among `allow from`'
                  % str(client_address[0])[:60])
            return
        try:
            ctx = self.join_ctx if self.joining else self.net.passive_ctx()
            tls = ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError, ValueError):
            self.net.take(client_address[0], 3)
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def handle_error(self, request, client_address):
        pass


def reuse_addr(ls):
    """The passive port bound again at once after a restart (Windows: exclusively)."""
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def serve_passive(net, joining):
    c = net.conf()
    j = net.join_info() or {}
    port = int(c.get('port') or j.get('p') or PASSIVE_PORT)
    listen = str(c.get('listen') or j.get('listen') or '0.0.0.0')
    fam = socket.AF_INET6 if ':' in listen else socket.AF_INET
    PassiveServer.address_family = fam
    # One listening socket for the life of this side: from the join to serving, connections
    # wait in its queue rather than being refused.
    if net.lsock is None or net.lsock_at != (listen, port):
        if net.lsock is not None:
            net.lsock.close()
        ls = socket.socket(fam, socket.SOCK_STREAM)
        reuse_addr(ls)
        ls.bind((listen, port))
        ls.listen(64)
        net.lsock, net.lsock_at = ls, (listen, port)
    srv = PassiveServer((listen, port), PassiveHandler, bind_and_activate=False)
    srv.socket.close()
    srv.socket = net.lsock
    srv.net = net
    srv.joining = joining
    if joining:
        key, _crt = tls_paths()
        tmp = os.path.join(STATE, 'joining.crt')
        _write(tmp, self_signed(key), 0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(tmp, key)
        srv.join_ctx = ctx
        status_write(state='waiting', said='waiting for acme to reach this agent on port %d'
                     % port, fp=spki_fp(_read(key, '')))
    srv.serve_forever(poll_interval=0.2)
    return srv.restart


# -- active: this side connects out ----------------------------------------------------------
def _split_hp(hp, port):
    hp = str(hp or '').strip()
    m = re.fullmatch(r'\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?', hp)
    if m:
        return m.group(1), int(m.group(2) or port)
    if hp.count(':') == 1:
        h, p = hp.split(':')
        return h, int(p)
    return hp, port


class Active(object):
    """The long-poll to acme's agents endpoint: the jobs, their results, failing over."""

    def __init__(self, net):
        self.net = net
        self.results = []
        self.at = 0
        self.wait = 1.0

    def ctx(self, joining=False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        if joining:
            ctx.verify_mode = ssl.CERT_NONE         # the code's secret proves acme here
        else:
            ctx.load_verify_locations(CA_FILE)
            ctx.verify_mode = ssl.CERT_REQUIRED
            key, crt = tls_paths()
            ctx.load_cert_chain(crt, key)
        return ctx

    def post(self, path, body, joining=False, timeout=60):
        c = self.net.conf()
        j = self.net.join_info() or {}
        eps = list(c.get('acme') or j.get('a') or [])
        if not eps:
            raise Refused('no address of acme is known')
        last = None
        for k in range(len(eps)):
            ep = eps[(self.at + k) % len(eps)]
            host, port = _split_hp(ep, 8444)
            conn = http.client.HTTPSConnection(host, port, context=self.ctx(joining),
                                               timeout=timeout)
            try:
                raw = json.dumps(body).encode()
                conn.request('POST', path, body=raw, headers={
                    'Content-Type': 'application/json', 'User-Agent': 'acme-agent/%s' % VERSION})
                if not joining:
                    peer = conn.sock.getpeercert() or {}
                    cn = ''
                    for rdn in peer.get('subject') or ():
                        for kk, v in rdn:
                            if kk == 'commonName':
                                cn = v
                    if cn != CTL_CN:
                        raise Refused('%s does not answer with acme\'s certificate' % ep)
                r = conn.getresponse()
                data = r.read(BODY_MOST + 1)
                if len(data) > BODY_MOST:
                    raise Refused('the answer is too big')
                try:
                    got = json.loads(data.decode('utf-8') or '{}')
                except (ValueError, UnicodeDecodeError):
                    got = {'ok': False, 'said': 'HTTP %d from %s' % (r.status, ep)}
                if r.status >= 500 or r.status == 429:
                    raise Refused(str(got.get('said') or got.get('error') or 'HTTP %d' % r.status))
                self.at = (self.at + k) % len(eps)
                got['_status'] = r.status
                return got
            except (OSError, ssl.SSLError, http.client.HTTPException, Refused) as e:
                last = e
            finally:
                conn.close()
        raise Refused('acme does not answer (%s)' % last)

    def enroll(self, j, fp):
        """A company enrollment code (1.0.120): acme makes this server a target of its own and
        answers as a join does, with the target's join code `i` - its secret derived from the
        enrollment code's, never sent. Then it goes on as the join of `i`."""
        nonce = secrets.token_hex(16)
        req = self.net.enroll_request(j, nonce)
        status_write(state='asking', fp=fp, said='asking acme (an enrollment code)')
        got = self.post('/agent/v1/enroll', req, joining=True)
        if got.get('_status') != 200 or not got.get('ok'):
            said = str(got.get('said') or got.get('error') or 'refused')
            status_write(state='refused', fp=fp, said=said)
            raise Refused(said)
        i = str(got.get('i') or '')
        if not re.fullmatch(r'[0-9a-f]{12}', i):
            raise Refused('acme answered no join of this server\'s')
        name = re.sub(r'[^A-Za-z0-9 ._@+-]', '', str(got.get('target') or ''))[:120]
        j2 = dict(j, i=i, s=proof(j['s'], 'target', j['e'], i), n=name or j.get('n') or '')
        aid = self.net.join_answer(j2, got, nonce)
        j2['agent_id'] = aid
        _write(os.path.join(STATE, 'join.json'), json.dumps(j2))
        status_write(state='confirm', fp=fp, said='acme made the target %s - confirm the '
                     'fingerprint in acme' % (name or '?'))
        return j2

    def join(self):
        j = self.net.join_info()
        key, _crt = tls_paths()
        fp = spki_fp(_read(key, ''))
        if j.get('e') and not j.get('i'):
            j = self.enroll(j, fp)
        if not j.get('agent_id'):
            nonce = secrets.token_hex(16)
            req = self.net.join_request(j, nonce)
            status_write(state='asking', fp=fp, said='asking acme')
            got = self.post('/agent/v1/join', req, joining=True)
            if got.get('_status') != 200 or not got.get('ok'):
                status_write(state='refused', fp=fp, said=str(got.get('said') or got.get('error')
                                                               or 'refused'))
                raise Refused(str(got.get('said') or got.get('error') or 'refused'))
            aid = self.net.join_answer(j, got, nonce)
            j['agent_id'] = aid
            _write(os.path.join(STATE, 'join.json'), json.dumps(j))
            status_write(state='confirm', fp=fp, said='confirm the fingerprint in acme')
        nonce = secrets.token_hex(16)
        got = self.post('/agent/v1/join/status', {'i': j['i'], 'nonce': nonce,
                                                  'proof': proof(j['s'], 'status', j['i'],
                                                                 nonce)}, joining=True)
        st = got.get('state')
        if st == 'done':
            self.net.join_finish(j, got, nonce, j['agent_id'])
            return True
        if st == 'refused' or got.get('_status') not in (200,):
            status_write(state='refused', fp=fp, said=str(got.get('said') or 'refused'))
            raise Refused(str(got.get('said') or 'refused'))
        status_write(state='confirm', fp=fp, said='confirm the fingerprint in acme')
        return False

    def renew_wanted(self):
        f = self.net.facts()
        return bool(f.get('cert_end')) and f['cert_end'] - time.time() < RENEW_DAYS * 86400

    def loop(self):
        backoff = 2.0
        while not self.net.stopping:
            try:
                if not self.net.joined():
                    if not self.net.join_info():
                        time.sleep(5)
                        continue
                    if self.join():
                        backoff = 2.0
                        if self.net.conf().get('mode') != 'active':
                            return      # 1.0.120: enrolled, passive - it listens from now on
                        continue
                    time.sleep(4)
                    continue
                c = self.net.conf()
                body = {'agent': c.get('agent_id'), 'results': self.results[:20],
                        'facts': self.net.facts(), 'renew': self.renew_wanted()}
                got = self.post('/agent/v1/poll', body, timeout=75)
                if got.get('_status') != 200:
                    # refused (switched off, forgotten), or a node that takes no change now:
                    # the next address, after a while - the results kept for it
                    self.at += 1
                    raise Refused(str(got.get('said') or got.get('error') or 'HTTP %s from acme'
                                      % got.get('_status')))
                self.results = self.results[20:]
                jobs = got.get('jobs') if isinstance(got.get('jobs'), list) else []
                for one in jobs[:20]:
                    out = self.net.job(one)
                    if out.get('sock') is not None:
                        out.pop('sock').close()
                        out = {'ok': False, 'said': 'a connector through the agent needs a '
                                                    'passive agent (acme connects to it)'}
                    jid = ''
                    try:
                        jid = str(json.loads(str(one.get('job') or '{}')).get('job') or '')
                    except ValueError:
                        pass
                    self.results.append({'job': jid[:64], 'result': out})
                backoff = 2.0
                if not jobs and not self.results:
                    try:
                        w = float(got.get('wait') or 0)
                    except (TypeError, ValueError):
                        w = 0
                    time.sleep(max(0.2, min(w, 60)))
            except Refused as e:
                status_write(state='trouble', said=str(e)[:300])
                time.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
            except Exception as e:                      # noqa: BLE001
                status_write(state='trouble', said='it went wrong: %s' % str(e)[:300])
                time.sleep(backoff)
                backoff = min(backoff * 2, 60.0)


def serve_net():
    """The network side: never root."""
    if os.geteuid() == 0 or os.getuid() == 0:
        raise SystemExit('acme-agent serve runs as the account %s, never as root '
                         '(systemd: acme-agent.service)' % USER)
    try:
        import ctypes
        ctypes.CDLL(None).prctl(38, 1, 0, 0, 0)        # PR_SET_NO_NEW_PRIVS
    except Exception:                                   # noqa: BLE001
        pass
    net = Net()

    def bye(*_):
        net.stopping = True
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    return net_loop(net)


def net_loop(net):
    """The network side's life: passive or active, as the join or agent.json says."""
    while not net.stopping:
        c = net.conf()
        j = net.join_info()
        mode = (j or {}).get('m') if j else c.get('mode')
        if not net.joined() and not j:
            time.sleep(3)
            continue
        if mode == 'active':
            Active(net).loop()
        else:
            serve_passive(net, joining=bool(j) and not net.joined())
    return 0


# ---- the command line (root) -----------------------------------------------------------------
def read_enroll_code(code):
    """A company enrollment code (ACAE1., 1.0.120): one code for many servers - acme makes
    each a target of its own. -> what read_code gives, with 'e' (no target yet: 'i', 't' empty)."""
    raw = code[6:]
    try:
        c = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode())
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise SystemExit('acme-agent: the enrollment code is not whole - copy it again')
    if not isinstance(c, dict) or any(k not in c for k in ('e', 's', 'ca', 'ck', 'm')) or \
            not re.fullmatch(r'[0-9a-f]{12}', str(c.get('e'))) or \
            c.get('m') not in ('passive', 'active') or not HEX64.match(str(c.get('ca'))) or \
            not HEX64.match(str(c.get('ck'))):
        raise SystemExit('acme-agent: the enrollment code is not whole - copy it again')
    if float(c.get('u') or 0) and float(c['u']) < time.time():
        raise SystemExit('acme-agent: the enrollment code ran out - ask for a new one')
    if not c.get('a') or not isinstance(c.get('a'), list):
        raise SystemExit('acme-agent: the enrollment code names no address of acme')
    c.update(i='', t='', n=str(c.get('n') or '')[:80])
    return c


def enroll_pins(c, pins, j):
    """What `join` writes for an enrollment code: the join goes as an active one (the agent
    asks acme) whatever the mode the servers take after it (root pins that mode) - and it
    may wait for a person to confirm it as long as the code is valid."""
    pins.update(e=c['e'], until=max(pins['until'], float(c.get('u') or 0) + 86400))
    j.update(e=c['e'], m='active', final=c['m'])


def read_code(code):
    code = str(code or '').strip()
    if code.startswith('ACAE1.'):
        return read_enroll_code(code)
    if not code.startswith('ACAG1.'):
        if re.fullmatch(r'[0-9A-Fa-f: ]{40,}', code):
            raise SystemExit('acme-agent: that is a fingerprint (of acme\'s agent authority, from '
                             'Settings → Target agents), not a join code. The join code starts '
                             'with ACAG1. and is made on the target\'s card in acme: Targets → '
                             'Add a target → Server with acme-agent, then its card → Join.')
        raise SystemExit('acme-agent: that is not a join code of acme (ACAG1.…) - it is made on '
                         'the target\'s card in acme: Targets → the target → Join.')
    raw = code[6:]
    try:
        c = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode())
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise SystemExit('acme-agent: the join code is not whole - copy it again')
    need = ('t', 'm', 'i', 's', 'ca', 'ck')
    if not isinstance(c, dict) or any(k not in c for k in need) or \
            c.get('m') not in ('passive', 'active') or not HEX64.match(str(c.get('ca'))) or \
            not HEX64.match(str(c.get('ck'))):
        raise SystemExit('acme-agent: the join code is not whole - copy it again')
    if float(c.get('u') or 0) and float(c['u']) < time.time():
        raise SystemExit('acme-agent: the join code ran out - make a new one in acme')
    if c['m'] == 'active' and not c.get('a'):
        raise SystemExit('acme-agent: the join code names no address of acme')
    return c


def _owned(path, ids, mode):
    os.chown(path, ids[0], ids[1])
    os.chmod(path, mode)


def need_root(words):
    """The command line's check that it runs as root (Windows: in an elevated prompt)."""
    if os.geteuid() != 0:
        raise SystemExit(words)


def make_places(ids):
    """The agent's folders, each with its owner and mode."""
    for d, owner, mode in ((ETC, (0, 0), 0o755), (STATE, ids, 0o700),
                           (ROOT_STATE, (0, 0), 0o700)):
        os.makedirs(d, exist_ok=True)
        os.chown(d, owner[0], owner[1])
        os.chmod(d, mode)


def cmd_join(argv):
    need_root('acme-agent join runs as root')
    if not argv:
        raise SystemExit('acme-agent join CODE')
    c = read_code(argv[0])
    # 1.0.119: --listen with no address stopped with an IndexError after the key and agent.json
    # of the agent joined until now were already replaced - said before anything changes
    if '--listen' in argv and not str((argv + [''])[argv.index('--listen') + 1]).strip():
        raise SystemExit('acme-agent join CODE [--listen ADDRESS]')
    ids = agent_ids()
    if ids is None:
        raise SystemExit('acme-agent: the account %s is not there (install.sh makes it)' % USER)
    make_places(ids)
    if not os.path.exists(POLICY):
        _write(POLICY, POLICY_HEAD, 0o644)
    # a new identity: the TLS key (the network side's, made here, never leaving), the X25519
    # key secrets are sealed to (root's)
    key, crt = tls_paths()
    for p in (crt, os.path.join(STATE, 'join-status.json'), os.path.join(STATE, 'joining.crt')):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    kpem = _openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'])
    _write(key, kpem, 0o600, ids)
    _write(os.path.join(ROOT_STATE, 'enc.key'), secrets.token_bytes(32).hex(), 0o600)
    old = _json(CONF, {})
    keep = {k: old[k] for k in ('systemctl',) if isinstance(old, dict) and old.get(k)}
    _write(CONF, json.dumps(dict(keep, joined=False), indent=1), 0o644)
    for p in (CA_FILE,):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    pins = {'ca': c['ca'], 'ck': c['ck'], 'i': c['i'], 't': c['t'], 'n': c.get('n') or '',
            'm': c['m'], 'p': int(c.get('p') or PASSIVE_PORT), 'a': c.get('a') or [],
            'until': time.time() + 3 * 3600}
    if '--listen' in argv:
        pins['listen'] = argv[argv.index('--listen') + 1]
    j = {'i': c['i'], 's': c['s'], 'm': c['m'], 'a': c.get('a') or [], 'p': pins['p'],
         't': c['t'], 'n': c.get('n') or '', 'ca': c['ca'], 'ck': c['ck'],
         'listen': pins.get('listen') or ''}
    if c.get('e'):
        enroll_pins(c, pins, j)                         # 1.0.120: an enrollment code
    _write(os.path.join(ROOT_STATE, 'join-pins.json'), json.dumps(pins))
    _write(os.path.join(STATE, 'join.json'), json.dumps(j), 0o600, ids)
    fp = spki_fp(kpem)
    if c.get('e'):
        print('acme-agent: joining acme with the enrollment code "%s" (%s mode) - acme makes '
              'this server a target of its own' % (c.get('n') or c['e'], c['m']))
    else:
        print('acme-agent: joining acme as the target %s (%s mode)' % (c.get('n') or c['t'],
                                                                       c['m']))
    print('')
    print('  The fingerprint of this agent - acme shows the same; confirm it there:')
    print('')
    print('    %s' % fp_words(fp))
    print('')
    if c['m'] == 'passive':
        print('  acme connects to this machine on port %d (open it to acme only).' % pins['p'])
    restart_services()
    if '--no-wait' in argv:
        print('  (not waiting: acme-agent status says how it goes)')
        return 0
    return wait_joined(fp)


def restart_services():
    if not os.path.isdir('/run/systemd/system') or os.environ.get('ACME_AGENT_NO_SYSTEMD'):
        return
    for unit in ('acme-agent-root', 'acme-agent'):
        subprocess.run(['systemctl', 'restart', unit], capture_output=True)


def wait_joined(fp, most=1800):
    end = time.time() + most
    said = ''
    while time.time() < end:
        st = _json(os.path.join(STATE, 'join-status.json'), {})
        words = '%s: %s' % (st.get('state') or 'starting', st.get('said') or '')
        if words != said:
            print('  ' + words)
            said = words
        if st.get('state') == 'joined':
            print('acme-agent: joined. `acme-agent policy show` says what acme may do here.')
            return 0
        if st.get('state') == 'refused':
            return 1
        time.sleep(2)
    print('acme-agent: not confirmed in %d minutes - it goes on in the background '
          '(acme-agent status)' % (most // 60))
    return 1


def cmd_init():
    """The folders and an empty policy (install.sh): nothing allowed."""
    if os.geteuid() != 0:
        raise SystemExit('acme-agent init runs as root')
    ids = agent_ids()
    if ids is None:
        raise SystemExit('acme-agent: the account %s is not there' % USER)
    for d, owner, mode in ((ETC, (0, 0), 0o755), (STATE, ids, 0o700),
                           (ROOT_STATE, (0, 0), 0o700)):
        os.makedirs(d, exist_ok=True)
        os.chown(d, owner[0], owner[1])
        os.chmod(d, mode)
    if not os.path.exists(POLICY):
        _write(POLICY, POLICY_HEAD, 0o644)
    else:
        st = os.lstat(POLICY)
        if st.st_uid != 0 or st.st_mode & 0o022:
            os.chown(POLICY, 0, 0)
            os.chmod(POLICY, 0o644)
    return 0


def cmd_forget():
    need_root('acme-agent forget runs as root')
    for p in (CONF, CA_FILE, os.path.join(ROOT_STATE, 'enc.key'),
              os.path.join(ROOT_STATE, 'join-pins.json'), os.path.join(STATE, 'tls.key'),
              os.path.join(STATE, 'tls.crt'), os.path.join(STATE, 'join.json'),
              os.path.join(STATE, 'join-status.json'), os.path.join(STATE, 'joining.crt')):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    audit(op='forget', ok=True, said='acme forgotten here')
    restart_services()
    print('acme-agent: acme is forgotten here - its keys, certificate and pins are gone. The '
          'policy stays (%s).' % POLICY)
    return 0


def cmd_status():
    print(json.dumps(status_facts(), indent=1))
    return 0


def status_facts():
    """What `acme-agent status` says."""
    c = net_conf()
    key, crt = tls_paths()
    out = {'version': VERSION, 'code': CODE, 'joined': bool(c.get('joined')),
           'agent_id': c.get('agent_id') or '', 'mode': c.get('mode') or '',
           'acme': c.get('acme') or []}
    if (c.get('mode') or '') != 'active':
        out['port'] = c.get('port')                     # an active agent listens on nothing
    if os.path.exists(key):
        out['fingerprint'] = fp_words(spki_fp(_read(key, '')))
    pem = _read(crt, '')
    if pem:
        out['cert_end'] = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(cert_end(pem)))
    st = _json(os.path.join(STATE, 'join-status.json'), {})
    if st:
        out['last'] = st
    pol, h, _t = policy_load()
    out['policy'] = {'hash': h, 'entries': len(policy_lines(pol)), 'problems': pol['problems']}
    return out


def policy_edit(add, words):
    """`acme-agent allow ...` / `deny ...`: the entry written into (or taken out of) the
    policy - the file read, checked and written whole (root:root 0644). Comments stay."""
    need_root('the policy is root\'s: run it as root')
    line = policy_words(words)
    probe = parse_policy(line)
    if probe['problems']:
        raise SystemExit('acme-agent: %s' % probe['problems'][0].split(': ', 1)[-1])
    text = _read(POLICY, '') or POLICY_HEAD
    lines = text.rstrip('\n').split('\n')

    def entry(x):
        x = x.strip()
        return None if not x or x.startswith('#') else parse_policy(x)
    out, said = [], ''
    if line.startswith('allow file '):
        d = probe['files'][0]['dir']
        out = [x for x in lines if not ((entry(x) or {}).get('files') and
                                         entry(x)['files'][0]['dir'] == d)]
        if add:
            out.append(policy_lines(probe)[0])
            said = 'allowed: %s' % policy_lines(probe)[0]
        else:
            said = 'taken away: files in %s' % d
            if len(out) == len(lines):
                raise SystemExit('acme-agent: no such entry in the policy: files in %s' % d)
    elif line.startswith('allow %s ' % UNIT_WORD):
        name, verbs = list(probe['units'].items())[0]
        have = []
        for x in lines:
            e = entry(x)
            if e and name in e['units']:
                have += [v for v in e['units'][name] if v not in have]
            else:
                out.append(x)
        now = [v for v in have if v not in verbs] if not add else \
            have + [v for v in verbs if v not in have]
        if not add and now == have:
            raise SystemExit('acme-agent: no such entry in the policy: %s %s' % (
                name, ','.join(verbs)))
        if now:
            out.append('allow %s %s %s' % (UNIT_WORD, name, ','.join(now)))
        said = ('allowed: %s %s %s' if add else 'now: %s %s %s') % (
            UNIT_WORD, name, ','.join(now) or 'nothing')
    elif line.startswith('limit '):
        k = line.split()[1]
        out = [x for x in lines if not (x.strip().startswith('limit %s ' % k))]
        if add:
            out.append(line)
        said = ('set: %s' % line) if add else ('back to the default: limit %s' % k)
    else:
        key = policy_lines(probe)[0]
        out = [x for x in lines if not (entry(x) and policy_lines(entry(x))[:1] == [key])]
        if add:
            if len(out) != len(lines):
                print('already allowed: %s' % key)
                return 0
            out.append(key)
            said = 'allowed: %s' % key
        else:
            if len(out) == len(lines):
                raise SystemExit('acme-agent: no such entry in the policy: %s' % key)
            said = 'taken away: %s' % key
    os.makedirs(ETC, exist_ok=True)
    _write(POLICY, '\n'.join(out) + '\n', 0o644)
    audit(op='policy', ok=True, said=said[:300])
    print(said)
    return 0


def policy_words(words):
    """The words of `allow ...` as a line of the policy (paths made real, a script pinned)."""
    if not words:
        raise SystemExit('acme-agent allow file|unit|test|script|script-hash|from|probe|connect|'
                         'self-update')
    what, rest = words[0], words[1:]
    if what == 'file':
        if not rest:
            raise SystemExit('acme-agent allow file DIR [--owner U:G] [--mode 0640]')
        d = rest[0]
        owner, mode = 'root:root', '0644'
        if '--owner' in rest:
            owner = rest[rest.index('--owner') + 1]
        if '--mode' in rest:
            mode = rest[rest.index('--mode') + 1]
        if not os.path.isabs(d):
            raise SystemExit('acme-agent: the folder is an absolute path')
        real = os.path.realpath(d)
        if real != os.path.normpath(d):
            print('note: %s is %s - that is what is allowed' % (d, real))
        return 'allow file %s owner=%s mode=%s' % (shlex.quote(real), owner, mode)
    if what == 'unit':
        if len(rest) != 2:
            raise SystemExit('acme-agent allow unit NAME reload,restart')
        return 'allow unit %s %s' % (rest[0], rest[1])
    if what == 'test':
        if rest[:1] == ['--']:
            rest = rest[1:]
        if not rest:
            raise SystemExit('acme-agent allow test -- COMMAND ARGS...')
        return 'allow test -- %s' % ' '.join(shlex.quote(a) for a in rest)
    if what == 'script':
        if len(rest) != 1 or not os.path.isabs(rest[0]):
            raise SystemExit('acme-agent allow script /PATH/OF/SCRIPT')
        try:
            with open(rest[0], 'rb') as f:
                h = _sha(f.read())
        except OSError as e:
            raise SystemExit('acme-agent: %s cannot be read: %s' % (rest[0], e))
        return 'allow script %s sha256=%s' % (shlex.quote(os.path.normpath(rest[0])), h)
    if what == 'script-hash':
        return 'allow script-hash %s' % (rest[0].lower() if rest else '')
    if what == 'from':
        return 'allow from %s' % (rest[0] if rest else '')
    if what == 'self-update':
        return 'allow self-update'
    if what == 'connect':
        return 'allow connect %s' % (rest[0] if rest else '')
    if what == 'probe':
        return 'allow probe %s' % (rest[0] if rest else '')
    if what == 'limit':
        return 'limit %s' % ' '.join(rest)
    raise SystemExit('acme-agent allow file|unit|test|script|script-hash|from|probe|connect|'
                     'self-update')


def cmd_policy(argv):
    if argv[:1] in (['check'], ['apply']):
        if len([a for a in argv[1:] if a != '--json']) != 1:
            raise SystemExit('acme-agent policy %s FILE|-' % argv[0])
        src = [a for a in argv[1:] if a != '--json'][0]
        if argv[0] == 'apply':
            need_root('acme-agent policy apply runs as root: the policy is root\'s')
            return policy_apply(_policy_input(src))
        got = policy_check(_policy_input(src), machine=True)
        if '--json' in argv:
            print(json.dumps({'ok': not got['errors'], 'lines': got['lines'],
                              'errors': got['errors'], 'warnings': got['warnings']}, indent=1))
        else:
            _say_check(got)
        return 1 if got['errors'] else 0
    pol, h, _t = policy_load()
    if argv[:1] == ['show'] or not argv:
        if '--json' in argv:
            print(json.dumps(policy_report(pol, h), indent=1))
            return 0
        lines = policy_lines(pol)
        print('# the policy of this machine (%s) - sha256 %s' % (POLICY, h[:16]))
        print('\n'.join(lines) if lines else '# nothing is allowed: acme can do nothing here')
        for p in pol['problems']:
            print('# NOT READ: %s' % p)
        return 0
    raise SystemExit('acme-agent policy show [--json] | check FILE|- | apply FILE|-')


# ---- the package (tools/release.py, and acme's pages) ------------------------------------------
PKG_FILES = ('acme_agent.py', 'install.sh', 'acme-agent.service', 'acme-agent-root.service',
             'README.md')
PKG_MORE = ('acme_agent_win.py', 'acme_agent_wincert.py')     # the Windows parts, when there


def build_package(dest, version, key=None, keys_dir=None, epoch=None):
    """acme-agent-X.Y.Z.tar.gz: one folder holding the agent, its units, install.sh, README,
    `release` (its version), the release keys, MANIFEST and - with the release key -
    MANIFEST.sig (Ed25519 over MANIFEST, as acme's own package). tools/release.py makes it
    with the release key; acme makes one without (a source tree) for its pages."""
    import gzip
    import io
    import tarfile
    here = os.path.dirname(os.path.realpath(__file__))
    top = 'acme-agent-%s' % version
    epoch = int(epoch or os.environ.get('SOURCE_DATE_EPOCH') or 0) or int(time.time())
    keys_dir = keys_dir or os.path.join(os.path.dirname(here), 'release-keys')
    blobs = []
    for n in PKG_FILES + tuple(x for x in PKG_MORE if os.path.exists(os.path.join(here, x))):
        with open(os.path.join(here, n), 'rb') as f:
            blobs.append((n, f.read(), 0o755 if n in ('acme_agent.py', 'install.sh') else 0o644))
    blobs.append(('release', (version + '\n').encode(), 0o644))
    try:
        for n in sorted(os.listdir(keys_dir)):
            if n.endswith('.pub'):
                with open(os.path.join(keys_dir, n), 'rb') as f:
                    blobs.append(('release-keys/' + n, f.read(), 0o644))
    except OSError:
        pass
    manifest = ''.join('%s  %s\n' % (hashlib.sha256(b).hexdigest(), n)
                       for n, b, _m in sorted(blobs)).encode()
    blobs = [('MANIFEST', manifest, 0o644)] + blobs
    if key:
        with tempfile.TemporaryDirectory() as t:
            man, sig = os.path.join(t, 'MANIFEST'), os.path.join(t, 'MANIFEST.sig')
            with open(man, 'wb') as f:
                f.write(manifest)
            r = subprocess.run([OPENSSL, 'pkeyutl', '-sign', '-inkey', key, '-rawin', '-in',
                                man, '-out', sig], capture_output=True)
            if r.returncode != 0:
                raise Refused('signing the agent\'s package failed: %s'
                              % r.stderr.decode('utf-8', 'replace').strip())
            with open(sig, 'rb') as f:
                blobs.insert(1, ('MANIFEST.sig', f.read(), 0o644))

    def ti(name, size, mode, kind=tarfile.REGTYPE):
        x = tarfile.TarInfo(name)
        x.size, x.mode, x.type, x.mtime = size, mode, kind, epoch
        x.uid = x.gid = 0
        x.uname = x.gname = 'root'
        return x
    raw = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
            tar.addfile(ti(top, 0, 0o755, tarfile.DIRTYPE))
            if any(n.startswith('release-keys/') for n, _b, _m in blobs):
                tar.addfile(ti(top + '/release-keys', 0, 0o755, tarfile.DIRTYPE))
            for n, b, m in blobs:
                tar.addfile(ti(top + '/' + n, len(b), m), io.BytesIO(b))
    tmp = dest + '.part'
    with open(tmp, 'wb') as f:
        f.write(raw.getvalue())
    os.replace(tmp, dest)
    return dest


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == 'root':
        return serve_root()
    if cmd == 'serve':
        return serve_net()
    if cmd == 'join':
        return cmd_join(rest)
    if cmd == 'status':
        return cmd_status()
    if cmd == 'fingerprint':
        key, _crt = tls_paths()
        if not os.path.exists(key):
            raise SystemExit('acme-agent: no key yet (acme-agent join CODE makes it)')
        print(fp_words(spki_fp(_read(key, ''))))
        return 0
    if cmd == 'forget':
        return cmd_forget()
    if cmd == 'init':
        return cmd_init()
    if cmd == 'policy':
        return cmd_policy(rest)
    if cmd == 'allow':
        return policy_edit(True, rest)
    if cmd == 'deny':
        return policy_edit(False, rest)
    if cmd == 'limit':
        return policy_edit(True, ['limit'] + rest)
    if cmd == 'version':
        print(VERSION)
        return 0
    print(__doc__)
    return 2



# ---- the platform hook: on Windows (or the tests' fake of it) acme_agent_win.py beside this file
# puts its own in place of what is POSIX here (paths, folders, ACLs, services, the named pipe).
def _platform_hook(g):
    import importlib.util
    spec = importlib.util.spec_from_file_location('acme_agent_win', os.path.join(
        os.path.dirname(os.path.realpath(__file__)), 'acme_agent_win.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    sys.modules.setdefault('acme_agent_win', m)
    m.install(g)


if os.name == 'nt' or os.environ.get('ACME_AGENT_FAKE_WINDOWS'):
    _platform_hook(globals())


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
