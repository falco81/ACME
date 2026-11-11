# -*- coding: utf-8 -*-
"""
What the target modules share (not a module itself: the registry skips files
starting with "_").

    fields      ssh_fields(), http_fields(), verify_fields(), keep_field()
    names       object_name(bundle, options) -> 'acme-www.example.com-20261101-0a1b2c3d'
                prune(names, prefix, keep, current) -> the ones to delete
    TLS         served_der(host, port, sni) / served_fingerprint(...) / check_served(...)
    files       parse_outputs(lines, vars) - the "format path [mode] [owner]" lines
    HTTP        HttpTarget.req() - ctx.http with JSON, errors in words
    state       Base.unchanged() / Base.remember() - the same certificate twice is a no-op
    dual        alt_of(bundle), variant_of(bundle, v), variants_of(bundle), family_of(bundle):
                a dual certificate (ECDSA and RSA of the same names) - see Target.dual

Your own module in /etc/acme/plugins/targets/ may import all of this:

    from acmelib.plugins.targets._common import HttpTarget, object_name, ...
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import shlex
import socket
import ssl
import time
import urllib.parse
import warnings

from acmelib.plugins.base import Target, PluginError, field

__all__ = [
    'PluginError', 'field', 'Base', 'HttpTarget', 'SshMixin',
    'norm_fp', 'pem_blocks', 'pem_to_der', 'fp_of', 'sha1_thumb', 'chain_id',
    'lines', 'as_bool', 'as_int', 'label_of', 'stamp', 'short_serial', 'object_name',
    'name_prefix', 'prune', 'split_hostport', 'served_der', 'served_fingerprint',
    'check_served', 'multipart', 'form', 'parse_outputs', 'subst', 'random_password',
    'ssh_fields', 'http_fields', 'verify_fields', 'keep_field', 'ssh_conn', 'text',
    'PFX_FORMATS', 'quote', 'chain_list', 'tls_fields', 'put_scp',
    'alt_of', 'variant_of', 'variants_of', 'family_of', 'dual_fp', 'VARIANT_WORDS',
    'outputs_for', 'ours', 'covers', 'service_of',
]

PFX_FORMATS = ('pfx', 'p12', 'p12-legacy', 'jks')
quote = shlex.quote


# ---------------------------------------------------------------------------
# Small things
# ---------------------------------------------------------------------------
def text(v):
    """bytes or str (or None) -> str."""
    if v is None:
        return ''
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode('utf-8', 'replace')
    return str(v)


def as_bool(v, default=False):
    if v is None or v == '':
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ('1', 'yes', 'true', 'on', 'y')


def as_int(v, default=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def lines(v):
    """A 'list' field as lines: a list, or text with one a line. Blank lines
    and lines starting with # are left out."""
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        raw = []
        for x in v:
            raw.extend(str(x).splitlines())
    else:
        raw = str(v).splitlines()
    return [x.strip() for x in raw if x.strip() and not x.strip().startswith('#')]


def random_password(n=24):
    return secrets.token_urlsafe(n)[:n]


def norm_fp(fp):
    """'AB:CD:..' / 'abcd..' -> 'abcd..' (hex, lower case, nothing else)."""
    return re.sub(r'[^0-9a-f]', '', text(fp).lower())


_PEM_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----.+?-----END \1-----', re.S)


def pem_blocks(pem):
    """Every PEM block in a text, as text, in order."""
    return [m.group(0).strip() + '\n' for m in _PEM_RE.finditer(text(pem))]


def pem_to_der(pem):
    blocks = pem_blocks(pem)
    if not blocks:
        raise PluginError('not a PEM certificate', retry=False)
    body = ''.join(blocks[0].strip().splitlines()[1:-1])
    return base64.b64decode(body)


def fp_of(bundle):
    """The SHA-256 fingerprint of the bundle's certificate, normalised."""
    fp = norm_fp(getattr(bundle, 'fingerprint', ''))
    if len(fp) == 64:
        return fp
    return hashlib.sha256(pem_to_der(bundle.cert_pem)).hexdigest()


def sha1_thumb(bundle):
    """The Windows thumbprint (SHA-1 of the DER), upper case."""
    return hashlib.sha1(pem_to_der(bundle.cert_pem)).hexdigest().upper()


def chain_id(pem):
    """A short stable id of a CA certificate (for 'acme-ca-<id>' names)."""
    try:
        return hashlib.sha256(pem_to_der(pem)).hexdigest()[:8]
    except Exception:                                   # noqa: BLE001
        return hashlib.sha256(text(pem).encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# A dual certificate: the main one and its twin (another kind of key)
# ---------------------------------------------------------------------------
VARIANT_WORDS = ('main', 'alt', 'ec', 'ecdsa', 'rsa', 'ed', 'ed25519')
_FAMILY = {'ecdsa': 'ec', 'ed25519': 'ed'}


def family_of(bundle):
    """'ec' | 'rsa' | 'ed' - the kind of the bundle's key."""
    fam = getattr(bundle, 'family', None)
    if fam:
        return fam
    kt = text(getattr(bundle, 'key_type', '')).lower()
    if not kt:
        pem = text(getattr(bundle, 'key_pem', ''))
        kt = 'ec' if 'EC PRIVATE' in pem else ('rsa' if 'RSA PRIVATE' in pem else '')
    return 'ec' if kt.startswith('ec') else ('rsa' if kt.startswith('rsa') else
                                             ('ed' if kt.startswith('ed') else kt))


def alt_of(bundle):
    """The twin of a dual certificate, or None."""
    return getattr(bundle, 'alt', None)


def variants_of(bundle):
    """[main] or [main, twin]."""
    alt = alt_of(bundle)
    return [bundle] + ([alt] if alt is not None else [])


def variant_of(bundle, v):
    """'main' / '' -> the bundle; 'alt' -> its twin; 'ec' / 'rsa' / 'ed' -> the one with
    that kind of key. None when there is no such one."""
    v = text(v).strip().lower()
    v = _FAMILY.get(v, v)
    if v in ('', 'main'):
        return bundle
    if v == 'alt':
        return alt_of(bundle)
    for b in variants_of(bundle):
        if family_of(b) == v:
            return b
    return None


def dual_fp(bundle):
    """What says "the same certificate" for a target: the fingerprint, and the twin's
    after it when the certificate is dual."""
    return '+'.join(fp_of(b) for b in variants_of(bundle))


def chain_list(bundle):
    out = []
    for p in list(getattr(bundle, 'chain_pems', None) or []):
        out.extend(pem_blocks(p))
    return out


# ---------------------------------------------------------------------------
# Names on a device: acme-<label>-<YYYYMMDD>-<serial>, so old ones can be found
# ---------------------------------------------------------------------------
def label_of(bundle, options=None, maxlen=40):
    """The certificate's name made safe for any device: a-z 0-9 . - _ only."""
    raw = (options or {}).get('object_name') or getattr(bundle, 'name', '') or \
        (list(getattr(bundle, 'names', None) or ['cert'])[0])
    raw = text(raw).strip().lower().replace('*.', 'wildcard.').replace('*', 'wildcard')
    s = re.sub(r'[^a-z0-9._-]+', '-', raw).strip('-.') or 'cert'
    return s[:maxlen].rstrip('-.')


def stamp(bundle):
    t = getattr(bundle, 'not_before', None) or time.time()
    return time.strftime('%Y%m%d', time.gmtime(float(t)))


def short_serial(bundle, n=8):
    s = re.sub(r'[^0-9a-f]', '', text(getattr(bundle, 'serial', '')).lower())
    if not s:
        s = fp_of(bundle)
    return s[-n:].rjust(n, '0')


def object_name(bundle, options=None, maxlen=63, serial_len=8):
    """acme-<label>-<YYYYMMDD>-<serial>, the label cut so the whole fits maxlen."""
    tail = '-%s-%s' % (stamp(bundle), short_serial(bundle, serial_len))
    room = max(1, maxlen - len('acme-') - len(tail))
    return 'acme-%s%s' % (label_of(bundle, options, room), tail)


def name_prefix(bundle, options=None, maxlen=63, serial_len=8):
    """What every name object_name() made for this certificate starts with."""
    n = object_name(bundle, options, maxlen, serial_len)
    return n[:-(len(stamp(bundle)) + serial_len + 1)]


_TAIL_RE = re.compile(r'(\d{8})-([0-9a-f]+)$')


def covers(names, host):
    """Whether one of a certificate's names covers the hostname (a wildcard: one label)."""
    host = text(host).lower().rstrip('.')
    for n in names or []:
        n = text(n).lower().rstrip('.')
        if n == host:
            return True
        if n.startswith('*.') and '.' in host and host.split('.', 1)[1] == n[2:]:
            return True
    return False


def ours(name, prefix):
    """Whether `name` is one object_name() made with this prefix (prefix + date + serial)
    - not the twin's or another deployment's that only starts the same."""
    name = text(name)
    return name.startswith(prefix) and bool(_TAIL_RE.match(name[len(prefix):]))


def prune(names, prefix, keep, current):
    """Of `names`, those made by acme for this certificate (prefix + date +
    serial) beyond the `keep` newest previous ones - the current one is never
    in it. -> the names to delete, oldest last."""
    keep = max(0, as_int(keep, 2))
    mine = []
    for n in set(names):
        if n == current or not n.startswith(prefix):
            continue
        m = _TAIL_RE.match(n[len(prefix):])
        if m:
            mine.append((m.group(1), n))
    mine.sort(reverse=True)
    return [n for _, n in mine[keep:]]


# ---------------------------------------------------------------------------
# What a server serves: a TLS handshake from acme, trust not checked
# ---------------------------------------------------------------------------
def split_hostport(s, default_port=443):
    s = text(s).strip()
    if s.startswith('['):                       # [2001:db8::1]:443
        host, _, rest = s[1:].partition(']')
        port = rest.lstrip(':')
        return host, as_int(port, default_port) if port else default_port
    if s.count(':') == 1:
        host, port = s.split(':')
        return host, as_int(port, default_port)
    return s, default_port


# Offering only these (TLS 1.2: the cipher suite says the kind of the server's key),
# a server that holds a certificate of each kind shows the one asked for.
ONLY_CIPHERS = {'ec': 'aECDSA:@SECLEVEL=0', 'ed': 'aECDSA:@SECLEVEL=0',
                'rsa': 'aRSA:@SECLEVEL=0'}


def served_der(host, port, sni=None, timeout=10, only=None):
    """The certificate a server shows on a TLS handshake (DER). SNI is sent
    as `sni` (or the host when it is a name). The trust is not checked: this
    is only to compare what is served with what was deployed. `only` 'ec' or
    'rsa': the handshake offers only what that kind of key signs (TLS 1.2, the
    cipher suites of ECDSA or of RSA), so a server with both - a dual
    certificate - shows that one."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():         # old devices still speak TLS 1.0
            warnings.simplefilter('ignore', DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    if only:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(ONLY_CIPHERS.get(only, 'ALL'))
    name = sni or host
    if name and re.match(r'^[0-9.]+$|:', name):
        name = None                             # no SNI for an address
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=name) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise OSError('no certificate was shown')
    return der


def served_fingerprint(host, port, sni=None, timeout=10, only=None):
    return hashlib.sha256(served_der(host, port, sni, timeout, only)).hexdigest()


def check_served(ctx, bundle, hostports, sni=None, tries=3, wait=3.0, sleep=time.sleep,
                 default_port=443):
    """Is the bundle's certificate what each host:port serves?
    True: all of them; False: one serves another; None: none could be asked.
    A dual certificate: each of the two asked for on its own (a handshake that
    offers only ECDSA, then one that offers only RSA)."""
    if alt_of(bundle) is not None:
        return _check_served_dual(ctx, bundle, hostports, sni, tries, wait, sleep,
                                  default_port)
    want = fp_of(bundle)
    if not sni:
        names = [n for n in (getattr(bundle, 'names', None) or []) if not n.startswith('*')]
        sni = names[0] if names else None
    seen_any, all_ok = False, True
    for hp in lines(hostports):
        host, port = split_hostport(hp, default_port)
        got, err = None, None
        for i in range(max(1, as_int(tries, 3))):
            try:
                got = served_fingerprint(host, port, sni)
                err = None
            except (OSError, ssl.SSLError, ValueError) as e:
                got, err = None, e
            if got == want:
                break
            if i + 1 < tries:
                sleep(wait)
        if err is not None and got is None:
            ctx.step('%s:%s cannot be asked: %s' % (host, port, err), 'warn')
            continue
        seen_any = True
        if got == want:
            ctx.step('%s:%s serves the new certificate' % (host, port), 'ok')
        else:
            all_ok = False
            ctx.step('%s:%s serves another certificate (%s…)' % (host, port, got[:16]), 'bad')
    if not seen_any:
        return None
    return all_ok


def _check_served_dual(ctx, bundle, hostports, sni, tries, wait, sleep, default_port):
    if not sni:
        names = [n for n in (getattr(bundle, 'names', None) or []) if not n.startswith('*')]
        sni = names[0] if names else None
    seen_any, all_ok = False, True
    pairs = [(family_of(b), fp_of(b), b) for b in variants_of(bundle)]
    for hp in lines(hostports):
        host, port = split_hostport(hp, default_port)
        refused = []
        for fam, want, b in pairs:
            got, err = None, None
            for i in range(max(1, as_int(tries, 3))):
                try:
                    got = served_fingerprint(host, port, sni, only=fam)
                    err = None
                except (OSError, ssl.SSLError, ValueError) as e:
                    got, err = None, e
                if got == want:
                    break
                if i + 1 < tries:
                    sleep(wait)
            if got is None:
                refused.append((fam, err))
                continue
            seen_any = True
            if got == want:
                ctx.step('%s:%s serves the new %s certificate' % (host, port, fam.upper()), 'ok')
            else:
                all_ok = False
                ctx.step('%s:%s serves another %s certificate (%s…)' % (
                    host, port, fam.upper(), got[:16]), 'bad')
        if len(refused) == len(pairs):
            # No TLS 1.2 there (or nothing answers): which one goes to which client
            # cannot be told - what is served is compared with either.
            try:
                got = served_fingerprint(host, port, sni)
            except (OSError, ssl.SSLError, ValueError) as e:
                ctx.step('%s:%s cannot be asked: %s' % (host, port, e), 'warn')
                continue
            seen_any = True
            if got in [w for _f, w, _b in pairs]:
                ctx.step('%s:%s serves one of the two new certificates (TLS 1.2 is not offered: '
                         'which one each client gets cannot be told)' % (host, port), 'ok')
            else:
                all_ok = False
                ctx.step('%s:%s serves another certificate (%s…)' % (host, port, got[:16]),
                         'bad')
            continue
        for fam, err in refused:
            all_ok = False
            ctx.step('%s:%s does not serve the %s certificate (a handshake offering only %s '
                     'failed: %s) - is the server told of both (two ssl_certificate lines, two '
                     'certificate files)?' % (host, port, fam.upper(), fam.upper(), err), 'bad')
    if not seen_any:
        return None
    return all_ok


# ---------------------------------------------------------------------------
# Bodies
# ---------------------------------------------------------------------------
def put_scp(s, data, path, mode=0o600):
    """s.put for a device with no POSIX shell (RouterOS, Windows): straight
    to the path with scp, where the session can."""
    try:
        return s.put(data, path, mode, via='scp')
    except TypeError:
        return s.put(data, path, mode)


def form(d):
    return urllib.parse.urlencode([(k, v) for k, v in d.items() if v is not None]).encode()


def multipart(parts):
    """parts: [(name, value)] with value a str, or (filename, bytes, content_type).
    -> (body bytes, content-type header)."""
    boundary = '----acme' + secrets.token_hex(12)
    out = []
    for name, value in parts:
        out.append(('--%s\r\n' % boundary).encode())
        if isinstance(value, tuple):
            fn, data, ctype = value
            out.append(('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
                        'Content-Type: %s\r\n\r\n' % (name, fn, ctype or
                                                       'application/octet-stream')).encode())
            out.append(data if isinstance(data, bytes) else text(data).encode())
        else:
            out.append(('Content-Disposition: form-data; name="%s"\r\n\r\n' % name).encode())
            out.append(text(value).encode())
        out.append(b'\r\n')
    out.append(('--%s--\r\n' % boundary).encode())
    return b''.join(out), 'multipart/form-data; boundary=%s' % boundary


# ---------------------------------------------------------------------------
# Files: "format path [mode] [owner[:group]]", one a line
# ---------------------------------------------------------------------------
FORMAT_ALIASES = {
    'cert': 'cert-pem', 'crt': 'cert-pem', 'pem': 'cert-pem', 'der': 'cert-der',
    'key': 'key-pem', 'privkey': 'key-pem', 'rsa': 'key-rsa',
    'chain': 'chain-pem', 'ca': 'chain-pem', 'fullchain': 'fullchain-pem',
    'combined': 'combined-pem', 'haproxy': 'combined-pem', 'p7': 'p7b',
    'pkcs12': 'pfx', 'keystore': 'jks',
}
ALL_FORMATS = ('cert-pem', 'cert-der', 'key-pem', 'key-rsa', 'key-der', 'chain-pem',
               'fullchain-pem', 'combined-pem', 'p7b', 'pfx', 'p12', 'p12-legacy', 'jks')
KEY_FORMATS = ('key-pem', 'key-rsa', 'key-der', 'combined-pem', 'pfx', 'p12', 'p12-legacy',
               'jks')
_OWNER_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?$')


SERVICE_RE = re.compile(r'^[A-Za-z0-9_@.:+=][A-Za-z0-9_@.:+=/-]{0,127}\Z')


def service_of(value, fallback):
    """The service / container / secret name a command is given as {service} (1.0.44): a
    name, nothing a shell reads as more - "web; id>/tmp/x #" made the preset's
    "docker restart {service}" run anything as root on the target, for whoever may only
    choose a deployment's preset and not its commands."""
    v = text(value or '').strip() or text(fallback or '')
    parts = v.split()
    # Several, a space between (two units: "nginx php-fpm"), each a name of its own.
    if not parts or len(parts) > 8 or not all(SERVICE_RE.match(x) for x in parts):
        raise PluginError('the service name is letters, digits and _ @ . : + = / - only (several '
                          'with a space between), and does not begin with - or /', retry=False)
    return ' '.join(parts)


def subst(s, vars):
    """{name} {cn} {service} {date} ... in a path or a command."""
    def one(m):
        k = m.group(1)
        return text(vars[k]) if k in vars else m.group(0)
    return re.sub(r'\{([a-z_]+)\}', one, text(s))


def parse_outputs(spec, vars=None, max_outputs=20, absolute=True):
    """The output lines of a deployment ->
    [{'format', 'variant', 'path', 'mode' (int), 'owner' (str or None)}].

        fullchain-pem  /etc/nginx/ssl/{name}.crt   0644  root:root
        key-pem        /etc/nginx/ssl/{name}.key   0600
        pfx            /opt/app/keystore.p12       0640  app:app
        fullchain-pem@rsa  /etc/nginx/ssl/{name}.rsa.crt   (a dual certificate's RSA one;
        key-pem@alt        /etc/nginx/ssl/{name}.alt.key    @ec @rsa @main @alt)

    'variant' is '' (the main one) or what follows the @; render_outputs()
    leaves out a line whose variant the certificate does not have."""
    out, seen = [], set()
    for n, line in enumerate(lines(spec), 1):
        parts = line.split()
        if len(parts) < 2 or len(parts) > 4:
            raise PluginError('output line %d is not "format path [mode] [owner]": %s'
                              % (n, line), retry=False)
        word, _, variant = parts[0].lower().partition('@')
        variant = _FAMILY.get(variant, variant)
        if variant == 'main':
            variant = ''
        if variant and variant not in VARIANT_WORDS:
            raise PluginError('output line %d: "@%s" is not one of a dual certificate\'s two '
                              '(@main @alt @ec @rsa)' % (n, variant), retry=False)
        fmt = FORMAT_ALIASES.get(word, word)
        if fmt not in ALL_FORMATS:
            raise PluginError('output line %d: "%s" is not a format (%s)'
                              % (n, parts[0], ', '.join(ALL_FORMATS)), retry=False)
        path = subst(parts[1], vars or {})
        if absolute and not path.startswith('/') and not re.match(r'^[A-Za-z]:[\\/]', path):
            raise PluginError('output line %d: the path must be absolute: %s' % (n, path),
                              retry=False)
        if '..' in re.split(r'[\\/]', path) or re.search(r'[\x00-\x1f\'"`$;&|<>]', path):
            raise PluginError('output line %d: the path is not allowed: %s' % (n, path),
                              retry=False)
        mode = 0o600 if fmt in KEY_FORMATS else 0o644
        owner = None
        for extra in parts[2:]:
            if re.match(r'^0?[0-7]{3,4}$', extra):
                mode = int(extra, 8)
            elif _OWNER_RE.match(extra):
                owner = extra
            else:
                raise PluginError('output line %d: "%s" is neither a mode (0640) nor an '
                                  'owner (user:group)' % (n, extra), retry=False)
        if path in seen:
            raise PluginError('output line %d: %s is written twice' % (n, path), retry=False)
        seen.add(path)
        out.append({'format': fmt, 'variant': variant, 'path': path, 'mode': mode,
                    'owner': owner})
    if len(out) > max_outputs:
        raise PluginError('at most %d outputs' % max_outputs, retry=False)
    return out


def outputs_for(ctx, bundle, outs):
    """The outputs with the bundle each is written from: [(output, bundle)]. A
    line for a variant the certificate does not have (@rsa of one that is only
    ECDSA, @alt of one that is not dual) is left out, and said."""
    got = []
    for o in outs:
        b = variant_of(bundle, o.get('variant'))
        if b is None:
            try:
                ctx.step('%s is left out: the certificate has no %s one%s' % (
                    o['path'], o['variant'].upper() if o['variant'] != 'alt' else 'second',
                    '' if alt_of(bundle) is not None else ' (it is not dual)'))
            except Exception:                           # noqa: BLE001
                pass
            continue
        got.append((o, b))
    return got


# ---------------------------------------------------------------------------
# Fields every module uses
# ---------------------------------------------------------------------------
def ssh_fields(sudo=True, port=22, prefix='', show_if=None, advanced=False, user_default='root',
               howto='linux', try_command=None, via=True):
    """The SSH sign-in: host, port, user, key or password, host key. The key is
    the key card of isemon (type sshkey): made here or brought, kept sealed; a
    passphrase of a key brought is kept in <prefix>key_pass, as before."""
    p = prefix
    si = dict(show_if or {})

    def f(*a, **k):
        if si:
            k.setdefault('show_if', si)
        if advanced:
            k.setdefault('advanced', True)
        return field(*a, **k)
    out = []
    if not p:
        out.append(f('host', 'Address', 'text', required=True,
                     placeholder='server.example.local', help='name or IP address'))
    out += [
        f(p + 'port', 'SSH port', 'number', default=port),
        f(p + 'user', 'User', 'text', default=user_default, required=not p),
        f(p + 'auth', 'Sign in with', 'select', default='key',
          options=[['key', 'a private key'], ['password', 'a password']]),
        f(p + 'key', 'The SSH key', 'sshkey', secret=True, pass_key=p + 'key_pass',
          auth_key=p + 'auth', ssh_prefix=p, howto=howto,
          **({'try_command': try_command} if try_command else {}),
          help='Made here (ed25519) or your own (OpenSSH or PEM); its public half goes on '
               'the machine. Shown whatever "Sign in with" says, as isemon shows it.'),
        f(p + 'password', 'Password', 'secret',
          show_if=dict(si, **{p + 'auth': ['password']})),
        f(p + 'hostkey', 'Host key', 'text', advanced=True,
          placeholder='server.example.local ssh-ed25519 AAAA…',
          help='a known_hosts line; empty with "trust the first" takes the one seen first'),
        f(p + 'trust_first', 'Trust the first host key seen', 'bool', default=True,
          advanced=True),
    ]
    if via:
        # Through a connector (1.0.74): a server only another network reaches, signed in to
        # from the connector's Linux server (ssh -W), as the tests run through it.
        out.append(f(p + 'via', 'Through a connector', 'select', default='', options=[['', 'directly']],
                     options_from='connectors', advanced=True,
                     help='a server only another network reaches: acme signs in to the connector '
                          '(Targets → Connector over SSH) and from it to this one - nothing '
                          'installed there'))
    if sudo:
        out += [
            f(p + 'sudo', 'Use sudo', 'bool', default=False,
              help='the user is not root: commands and writes go through sudo'),
            f(p + 'sudo_password', 'sudo password', 'secret',
              show_if=dict(si, **{p + 'sudo': [True, 'true', '1']}),
              help='empty: sudo must not ask (NOPASSWD)'),
        ]
    return out


def http_fields(port=443, host_placeholder='device.example.local', proxy=False):
    return [
        field('host', 'Address', 'text', required=True, placeholder=host_placeholder,
              help='name or IP address of the management interface'),
        field('port', 'HTTPS port', 'number', default=port),
    ]


def tls_fields(proxy=False):
    return [
        field('verify_tls', 'Check the device\'s certificate', 'bool', default=True,
              help='off only for a device that still has its self-signed certificate'),
        field('ca_pem', 'CA certificate', 'pem', advanced=True,
              help='the CA the device\'s own certificate is from, when not a public one'),
        field('proxy', 'Through the proxy', 'bool', default=proxy, advanced=True,
              help='go out through the proxy of Settings → Proxy'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]


def verify_fields(default_port=443):
    return [
        field('verify', 'Check what is served', 'list', advanced=False,
              placeholder='www.example.com:%d' % default_port,
              help='host:port, one a line: after deploying acme makes a TLS handshake '
                   'there and compares the certificate served with the new one'),
        field('verify_sni', 'SNI name for the check', 'text', advanced=True,
              help='empty: the first name of the certificate'),
    ]


def keep_field(default=2):
    return field('keep', 'Previous versions to keep', 'number', default=default,
                 advanced=True,
                 help='older certificates acme put there (named acme-…-date-serial) are '
                      'deleted beyond this many; -1 keeps all')


def ssh_conn(plugin, prefix=''):
    """The conn dict ctx.ssh() takes, from fields made by ssh_fields()."""
    p = prefix
    c = plugin.c
    auth = c(p + 'auth', 'key')
    return {
        'host': c('host'),
        'port': as_int(c(p + 'port', 22), 22),
        'user': c(p + 'user') or c('user'),
        'password': (c(p + 'password') or (c('password') if p else None)) if auth == 'password'
        else None,
        'key': c(p + 'key') if auth == 'key' else None,
        'key_pass': c(p + 'key_pass') if auth == 'key' else None,
        'hostkey': c(p + 'hostkey') or None,
        'hostkey_field': p + 'hostkey',        # where the first one seen is kept (1.0.51)
        'trust_first': as_bool(c(p + 'trust_first', True), True),
        'timeout': as_int(c('timeout', 30), 30),
        'via': c(p + 'via') or '',                # through a connector (1.0.74)
    }


# ---------------------------------------------------------------------------
# The base of every target here
# ---------------------------------------------------------------------------
class Base(Target):
    """Idempotency, cleanup and verify, the same in every module."""
    kind = ''
    default_verify_port = 443

    def ident(self):
        return '%s:%s' % (self.c('host') or self.c('url') or self.c('base') or '-',
                          self.c('port') or '')

    def state_key(self, options):
        o = {k: v for k, v in (options or {}).items() if k not in ('force',)}
        h = hashlib.sha256(json.dumps(o, sort_keys=True, default=str).encode()).hexdigest()
        return 'deployed:%s:%s:%s' % (self.kind, self.ident(), h[:16])

    def unchanged(self, bundle, options, present=None):
        """True when this very certificate was deployed here with these very
        options and (when `present` is given) the device still has it - unless
        options['force']."""
        if as_bool((options or {}).get('force')):
            return False
        try:
            v = self.ctx.kv_get(self.state_key(options))
        except Exception:                               # noqa: BLE001
            v = None
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                v = {'fp': v}
        if not isinstance(v, dict) or norm_fp(v.get('fp')) != norm_fp(dual_fp(bundle)):
            return False
        if present is not None:
            try:
                if not present():
                    return False
            except PluginError:
                return False
        return True

    def remember(self, bundle, options, **more):
        d = {'fp': dual_fp(bundle), 'at': int(time.time())}
        d.update(more)
        try:
            self.ctx.kv_set(self.state_key(options), d)
        except Exception as e:                          # noqa: BLE001
            self.ctx.debug('cannot remember the deployment: %s' % e)

    # A deployment begun and not finished (1.0.79): the files written, the reload cut off (the
    # SSH session dropped, the job stopped) - the next one found every file the same and ran
    # nothing, and the service kept the old certificate. Marked before the files are written,
    # taken off when it went through; while marked, "nothing to replace" still runs the commands.
    def _pending_key(self):
        return 'pending:%s:%s' % (self.kind, self.ident())

    def mark_pending(self, bundle):
        try:
            self.ctx.kv_set(self._pending_key(), {'fp': dual_fp(bundle), 'at': int(time.time())})
        except Exception:                               # noqa: BLE001
            pass

    def pending(self):
        try:
            v = self.ctx.kv_get(self._pending_key())
        except Exception:                               # noqa: BLE001
            v = None
        return bool(v)

    def done_pending(self):
        try:
            self.ctx.kv_set(self._pending_key(), '')
        except Exception:                               # noqa: BLE001
            pass

    def same(self, bundle, words='already there'):
        self.ctx.step('%s %s - nothing to do (force to do it again)' % (fp_of(bundle)[:16],
                                                                         words), 'ok')
        return 'unchanged: the same certificate is %s' % words

    def verify(self, bundle, options):
        options = options or {}
        hp = lines(options.get('verify'))
        if not hp:
            return None
        return check_served(self.ctx, bundle, hp, options.get('verify_sni') or None,
                            tries=as_int(options.get('verify_tries', 4), 4),
                            wait=float(options.get('verify_wait', 3) or 3),
                            sleep=getattr(self, '_sleep', time.sleep),
                            default_port=self.default_verify_port)

    def keep(self, options):
        return as_int((options or {}).get('keep', self.deploy_default('keep', 2)), 2)

    def deploy_default(self, key, default=None):
        for f in self.deploy_fields:
            if f['key'] == key:
                return f.get('default', default)
        return default

    def opt(self, options, key, default=None):
        """A deploy option, the field's default where it is not set."""
        v = (options or {}).get(key)
        if v in (None, ''):
            return self.deploy_default(key, default)
        return v


class HttpTarget(Base):
    """A device spoken to over HTTPS through ctx.http - which is kind to it
    (acmelib/plugins/limits.py): two requests at once and a few a second at
    most, a 429 / 503 waited out for a call that may be repeated."""
    kind = ''
    scheme = 'https'

    def base_url(self):
        host = text(self.c('host')).strip()
        if host.startswith(('http://', 'https://')):
            return host.rstrip('/')
        port = as_int(self.c('port', 443), 443)
        if ':' in host and not host.startswith('['):
            host = '[%s]' % host
        default = 443 if self.scheme == 'https' else 80
        return '%s://%s%s' % (self.scheme, host, '' if port == default else ':%d' % port)

    def auth_headers(self):
        return {}

    def req(self, method, path, body=None, headers=None, ok=None, timeout=None, auth=True,
            what=None):
        """-> (status, headers, data) - data the JSON parsed, or the bytes.
        A status outside `ok` (default 2xx) is a PluginError in words."""
        url = path if path.startswith(('http://', 'https://')) else self.base_url() + path
        h = dict(self.auth_headers()) if auth else {}
        h.update(headers or {})
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            h.setdefault('Content-Type', 'application/json')
        elif isinstance(body, str):
            data = body.encode()
        else:
            data = body
        h.setdefault('Accept', 'application/json')
        self.ctx.debug('%s %s' % (method, re.sub(r'(key|password|passwd|token|_sid|sid)=[^&]*',
                                                 r'\1=…', url)))
        try:
            st, hd, raw = self.ctx.http(
                method, url, body=data, headers=h,
                timeout=timeout or as_int(self.c('timeout', 30), 30),
                verify=as_bool(self.c('verify_tls', True), True),
                ca_pem=self.c('ca_pem') or None, proxy=as_bool(self.c('proxy', False)))
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('%s cannot be reached: %s' % (self.base_url(), e))
        hd = {text(k).lower(): v for k, v in (hd or {}).items()}
        raw = raw or b''
        parsed = raw
        if raw[:1] in (b'{', b'['):
            try:
                parsed = json.loads(raw.decode('utf-8', 'replace'))
            except ValueError:
                parsed = raw
        good = ok if ok is not None else range(200, 300)
        if st not in good:
            raise PluginError(self.http_error(st, parsed, raw, method, path, what),
                              detail=text(raw)[:4000],
                              retry=st not in (400, 401, 403, 404, 405, 409, 422))
        return st, hd, parsed

    def http_error(self, status, parsed, raw, method, path, what=None):
        msg = ''
        if isinstance(parsed, dict):
            for k in ('message', 'errorMessage', 'error', 'errors', 'detail', 'cli_error'):
                if parsed.get(k):
                    msg = text(parsed[k] if not isinstance(parsed[k], list)
                               else '; '.join(map(text, parsed[k])))
                    break
        if not msg:
            msg = re.sub(r'<[^>]+>', ' ', text(raw))
            msg = re.sub(r'\s+', ' ', msg).strip()[:200]
        from acmelib.plugins import limits
        if status == 429 or (status in (400, 401, 403, 503) and limits.is_slow_words(msg)):
            head = 'the device asks acme to slow down (%d) - acme tries again later by itself' \
                % status
        elif status in (401, 403):
            head = 'the device does not let acme in (%d)' % status
        elif status == 404:
            head = 'not found on the device (404)'
        else:
            head = 'the device said %d' % status
        return '%s: %s%s' % (what or '%s %s' % (method, path.split('?')[0]), head,
                             (' - ' + msg) if msg else '')


class SshMixin(object):
    """Commands over SSH, through sudo when the target says so."""

    def ssh(self):
        return self.ctx.ssh(ssh_conn(self))

    def sh(self, s, script, timeout=120, sudo=None, check=True, what=None):
        """Run a POSIX sh script (through sudo when asked) -> (rc, out, err)."""
        use_sudo = as_bool(self.c('sudo')) if sudo is None else sudo
        cmd = 'sh -c %s' % quote(script)
        inp = None
        if use_sudo:
            pw = self.c('sudo_password')
            if pw:
                cmd = "sudo -S -p '' " + cmd
                inp = pw + '\n'
            else:
                cmd = 'sudo -n ' + cmd
        rc, out, err = s.run(cmd, input=inp, timeout=timeout, check=False)
        out, err = text(out), text(err)
        if check and rc != 0:
            raise PluginError('%s failed (exit %s): %s' % (
                what or 'a command', rc, (err.strip() or out.strip())[-300:]),
                detail='$ %s\n%s\n%s' % (script, out, err))
        return rc, out, err
