# -*- coding: utf-8 -*-
"""
Keys, requests and certificates: made with the `openssl` program (OpenSSL
3.0 or later), read in Python (acmelib.certs.asn1) - so reading a certificate
costs no process, and what is read does not depend on how a version of
openssl prints it.

    make_key(key_type) -> PKCS#8 PEM            ec-256 ec-384 rsa-2048 rsa-3072 rsa-4096 ed25519
    make_csr(key_pem, names, subject=None, must_staple=False, eku=None) -> (csr_pem, csr_der)
    self_signed(key_pem, names, ...) -> cert_pem
    cert_info(pem_or_der) / csr_info(pem) / key_info(key_pem, password) / crl_info(pem)
    key_matches(cert_pem, key_pem)
    split_pem(text) / pem_to_der(pem) / der_to_pem(der, label)
    order_chain(leaf_pem, pems) / verify_chain(leaf_pem, chain_pems, roots_pems, purpose)
    openssl(args, data=None, timeout=60, env=None) -> bytes

A password never goes on a command line: it is handed over in the
environment of that one openssl process (`-passin env:ACME_PKI_PASS`).
Keys that openssl must read from a file are written into a directory of
our own (0700, in /dev/shm where there is one) and removed at once.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import ipaddress
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time

from acmelib.certs import asn1 as A
from acmelib.plugins.base import PluginError

OPENSSL = os.environ.get('ACME_OPENSSL', 'openssl')
KEY_TYPES = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096', 'ed25519')
PASS_ENV = 'ACME_PKI_PASS'
PASS_ENV_OUT = 'ACME_PKI_PASS_OUT'


class PkiError(PluginError):
    """openssl said no, or the bytes are not what they were taken for.
    `detail` holds what openssl wrote (its stderr)."""
    def __init__(self, words, detail=None, retry=False):
        PluginError.__init__(self, words, detail, retry)


class PasswordError(PkiError):
    """A password is needed, or the one given is wrong."""


# ---------------------------------------------------------------------------
# The openssl program
# ---------------------------------------------------------------------------
_VERSION = {}


def openssl_version():
    """(major, minor, patch, text) of the openssl program."""
    if 'v' not in _VERSION:
        out = openssl(['version']).decode('ascii', 'replace').strip()
        m = re.search(r'(\d+)\.(\d+)\.(\d+)', out)
        _VERSION['v'] = (int(m.group(1)), int(m.group(2)), int(m.group(3)), out) if m \
            else (0, 0, 0, out)
    return _VERSION['v']


def _said(err):
    """The line of openssl's stderr worth showing."""
    text = err.decode('utf-8', 'replace') if isinstance(err, bytes) else str(err)
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        # 40E7...:error:1C800064:Provider routines:ossl_cipher_unpadblock:bad decrypt:...
        m = re.search(r':error:[0-9A-F]+:([^:]*):([^:]*):([^:]+)', ln)
        if m:
            return '%s (%s)' % (m.group(3).strip(), m.group(2).strip())
    for ln in lines:
        if not ln.lower().startswith(('using configuration', 'check that the request')):
            return ln
    return 'no reason given'


_PASSWORD_WORDS = ('bad decrypt', 'mac verify failure', 'invalid password',
                   'maybe wrong password', 'bad password read', 'unable to load key',
                   'could not read key', 'pkcs12 cipherfinal error')


def openssl(args, data=None, timeout=60, env=None):
    """Run openssl with `args`, `data` (bytes or str) on its stdin; its stdout
    back. A failure raises PkiError with openssl's words; passwords only ever
    through `env` (and `-passin env:NAME`)."""
    cmd = [OPENSSL] + [str(a) for a in args]
    full_env = dict(os.environ)
    full_env.update({k: v for k, v in (env or {}).items() if v is not None})
    if isinstance(data, str):
        data = data.encode('utf-8')
    try:
        p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=None if data is not None else subprocess.DEVNULL,
                           timeout=timeout, env=full_env, start_new_session=True)
    except FileNotFoundError:
        raise PkiError('the openssl program is not installed (%s)' % OPENSSL)
    except subprocess.TimeoutExpired:
        raise PkiError('openssl %s took longer than %d seconds' % (args[0] if args else '',
                                                                  timeout), retry=True)
    if p.returncode != 0:
        said = _said(p.stderr)
        detail = p.stderr.decode('utf-8', 'replace')
        cls = PasswordError if any(w in detail.lower() for w in _PASSWORD_WORDS) and \
            any(a.startswith('env:') for a in cmd) else PkiError
        raise cls('openssl %s: %s' % (args[0] if args else '', said), detail)
    return p.stdout


@contextlib.contextmanager
def workdir():
    """A directory of our own for the files openssl must have, removed after."""
    base = None
    if os.path.isdir('/dev/shm') and os.access('/dev/shm', os.W_OK | os.X_OK):
        base = '/dev/shm'
    try:
        d = tempfile.mkdtemp(prefix='acme-pki-', dir=base)
    except OSError:
        d = tempfile.mkdtemp(prefix='acme-pki-')
    os.chmod(d, 0o700)
    try:
        yield d
    finally:
        for root, _dirs, files in os.walk(d):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    size = os.path.getsize(p)
                    if size and fn.endswith(('.key', '.p12')):
                        with open(p, 'r+b') as f:
                            f.write(b'\0' * size)
                except OSError:
                    pass
        shutil.rmtree(d, ignore_errors=True)


def wfile(d, name, data, mode=0o600):
    path = os.path.join(d, name)
    if isinstance(data, str):
        data = data.encode('utf-8')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    return path


def rfile(d, name):
    with open(os.path.join(d, name), 'rb') as f:
        return f.read()


# ---------------------------------------------------------------------------
# PEM
# ---------------------------------------------------------------------------
_PEM_RE = re.compile(r'-----BEGIN ([A-Z0-9 #._-]+?)-----(.*?)-----END \1-----', re.S)


def _text(data):
    if isinstance(data, (bytes, bytearray)):
        data = bytes(data)
        if data.startswith(b'\xef\xbb\xbf'):
            data = data[3:]
        if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
            return data.decode('utf-16')
        return data.decode('utf-8', 'replace')
    return str(data)


def split_pem(text):
    """Every PEM block in `text` (str or bytes, any line ends, words around
    them): [(label, pem)], each pem cleaned (64-column base64, \\n ends, the
    headers of an old encrypted key kept)."""
    text = _text(text).replace('\r\n', '\n').replace('\r', '\n')
    out = []
    for m in _PEM_RE.finditer(text):
        label, body = m.group(1).strip(), m.group(2)
        headers, b64 = [], []
        for ln in body.split('\n'):
            ln = ln.strip()
            if not ln:
                continue
            if ':' in ln and not b64:
                headers.append(ln)
            else:
                b64.append(ln)
        raw = ''.join(b64).replace(' ', '').replace('\t', '')
        try:
            der = base64.b64decode(raw + '=' * (-len(raw) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        if not der:
            continue
        out.append((label, _pem(der, label, headers)))
    return out


def _pem(der, label, headers=None):
    b = base64.b64encode(der).decode('ascii')
    lines = ['-----BEGIN %s-----' % label]
    if headers:
        lines += list(headers) + ['']
    lines += [b[i:i + 64] for i in range(0, len(b), 64)]
    lines.append('-----END %s-----' % label)
    return '\n'.join(lines) + '\n'


def der_to_pem(der, label='CERTIFICATE'):
    return _pem(bytes(der), label)


def pem_to_der(pem):
    """The bytes of the first PEM block (or `pem` itself when it is DER already)."""
    if isinstance(pem, (bytes, bytearray)) and b'-----BEGIN' not in pem:
        return bytes(pem)
    blocks = split_pem(pem)
    if not blocks:
        raise PkiError('no PEM block found')
    body = blocks[0][1].strip().split('\n')[1:-1]
    body = [ln for ln in body if ln and ':' not in ln]
    return base64.b64decode(''.join(body))


def _cert_der(x):
    """A certificate's DER from PEM (str/bytes) or DER."""
    if isinstance(x, str) or (isinstance(x, (bytes, bytearray)) and b'-----BEGIN' in x):
        for label, pem in split_pem(x):
            if label in ('CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'):
                der = pem_to_der(pem)
                if label == 'TRUSTED CERTIFICATE':
                    der = A.parse(der).raw      # the certificate, without openssl's aux
                return der
        raise PkiError('no certificate found in the text')
    return bytes(x)


def cert_pem(x):
    """A certificate as clean PEM, from PEM or DER."""
    return der_to_pem(_cert_der(x), 'CERTIFICATE')


def certs_in(text):
    """Every certificate of a PEM text, clean."""
    out = []
    for label, pem in split_pem(text):
        if label in ('CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'):
            out.append(cert_pem(pem))
    return out


# ---------------------------------------------------------------------------
# Reading names and extensions
# ---------------------------------------------------------------------------
def _rfc4514_escape(v):
    out = ''
    for i, ch in enumerate(v):
        if ch in ',+"\\<>;=' or (ch == '#' and i == 0) or (ch == ' ' and i in (0, len(v) - 1)):
            out += '\\' + ch
        elif ord(ch) < 0x20:
            out += '\\%02X' % ord(ch)
        else:
            out += ch
    return out


def parse_name(node):
    """A Name: (dn 'CN=x,O=y' most specific first (RFC 4514), {short: first
    value}, [(short, value)] in the order written)."""
    pairs = []
    rdns = []
    for rdn in node:
        parts = []
        for atv in rdn:
            k = A.oid_name(atv[0].oid())
            try:
                v = atv[1].text()
            except A.Asn1Error:
                v = atv[1].content.hex()
            pairs.append((k, v))
            parts.append('%s=%s' % (k, _rfc4514_escape(v)))
        rdns.append('+'.join(parts))
    dn = ','.join(reversed(rdns))
    d = {}
    for k, v in pairs:
        d.setdefault(k, v)
    return dn, d, pairs


def _general_names(node):
    """[(type, value)] of a GeneralNames: DNS, IP, email, URI, DirName, UPN, other."""
    out = []
    for gn in node:
        if gn.cls != A.CONTEXT:
            continue
        t = gn.tag
        try:
            if t == 2:
                out.append(('DNS', gn.content.decode('ascii', 'replace')))
            elif t == 7:
                out.append(('IP', gn.ip()))
            elif t == 1:
                out.append(('email', gn.content.decode('ascii', 'replace')))
            elif t == 6:
                out.append(('URI', gn.content.decode('ascii', 'replace')))
            elif t == 4:
                out.append(('DirName', parse_name(gn[0])[0]))
            elif t == 0:
                o = gn[0].oid()
                val = gn[1][0]
                if o == '1.3.6.1.4.1.311.20.2.3':
                    out.append(('UPN', val.text()))
                else:
                    out.append(('otherName', '%s;%s' % (o, val.content.hex())))
            elif t == 8:
                out.append(('RID', A.decode_oid(gn.content)))
        except (A.Asn1Error, ValueError, IndexError):
            continue
    return out


KEY_USAGE_BITS = ('digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
                  'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly')


def parse_extensions(node):
    """The extensions (a SEQUENCE OF Extension) as a dict of what they say."""
    info = {'san': [], 'eku': [], 'key_usage': [], 'ski': '', 'aki': '', 'ocsp': [],
            'crl': [], 'ca_issuers': [], 'is_ca': False, 'path_len': None,
            'must_staple': False, 'sct': False, 'name_constraints': {}, 'policies': [],
            'extensions': [], 'critical': []}
    for ext in node:
        try:
            o = ext[0].oid()
            crit = len(ext) > 2 and ext[1].is_(A.BOOLEAN) and ext[1].bool()
            val = ext[len(ext) - 1].content
            info['extensions'].append(A.oid_name(o))
            if crit:
                info['critical'].append(A.oid_name(o))
            v = A.parse(val) if val else None
            if o == '2.5.29.17':
                info['san'] = _general_names(v)
            elif o == '2.5.29.37':
                info['eku'] = [A.oid_name(x.oid()) for x in v]
            elif o == '2.5.29.15':
                info['key_usage'] = [KEY_USAGE_BITS[b] for b in v.bit_list()
                                     if b < len(KEY_USAGE_BITS)]
            elif o == '2.5.29.19':
                for x in v:
                    if x.is_(A.BOOLEAN):
                        info['is_ca'] = x.bool()
                    elif x.is_(A.INTEGER):
                        info['path_len'] = x.int()
            elif o == '2.5.29.14':
                info['ski'] = v.content.hex().upper()
            elif o == '2.5.29.35':
                for x in v:
                    if x.is_ctx(0):
                        info['aki'] = x.content.hex().upper()
            elif o == '1.3.6.1.5.5.7.1.1':
                for ad in v:
                    m = ad[0].oid()
                    loc = _general_names([ad[1]])
                    uris = [val2 for t, val2 in loc if t == 'URI']
                    if m == '1.3.6.1.5.5.7.48.1':
                        info['ocsp'] += uris
                    elif m == '1.3.6.1.5.5.7.48.2':
                        info['ca_issuers'] += uris
            elif o == '2.5.29.31':
                for dp in v:
                    for part in dp:
                        if part.is_ctx(0):          # distributionPoint
                            for full in part:
                                if full.is_ctx(0):  # fullName
                                    info['crl'] += [u for t, u in _general_names(full)
                                                    if t == 'URI']
            elif o == '1.3.6.1.5.5.7.1.24':
                info['must_staple'] = any(x.is_(A.INTEGER) and x.int() == 5 for x in v)
            elif o == '1.3.6.1.4.1.11129.2.4.2':
                info['sct'] = True
            elif o == '2.5.29.30':
                nc = {'permitted': [], 'excluded': []}
                for part in v:
                    key = 'permitted' if part.is_ctx(0) else 'excluded'
                    for sub in part:
                        nc[key] += ['%s:%s' % gn for gn in _general_names([sub[0]])]
                info['name_constraints'] = nc
            elif o == '2.5.29.32':
                info['policies'] = [p[0].oid() for p in v]
        except (A.Asn1Error, IndexError, ValueError):
            continue
    return info


_CURVES = {'1.2.840.10045.3.1.7': ('ec-256', 256), '1.3.132.0.34': ('ec-384', 384),
           '1.3.132.0.35': ('ec-521', 521), '1.3.132.0.10': ('ec-secp256k1', 256)}


def spki_info(spki):
    """A SubjectPublicKeyInfo node: (key_type, key_bits, pub_sha256 (hex upper of its DER))."""
    alg = spki[0][0].oid()
    sha = hashlib.sha256(spki.raw).hexdigest().upper()
    if alg in ('1.2.840.113549.1.1.1', '1.2.840.113549.1.1.10'):
        rsa = A.parse(spki[1].bits())
        bits = rsa[0].int().bit_length()
        return ('rsa-%d' % bits if alg.endswith('.1') else 'rsa-pss-%d' % bits), bits, sha
    if alg == '1.2.840.10045.2.1':
        curve = spki[0][1].oid() if len(spki[0]) > 1 and spki[0][1].is_(A.OID) else ''
        kt, bits = _CURVES.get(curve, ('ec-' + A.oid_name(curve), 0))
        return kt, bits, sha
    if alg == '1.3.101.112':
        return 'ed25519', 256, sha
    if alg == '1.3.101.113':
        return 'ed448', 456, sha
    if alg == '1.2.840.10040.4.1':
        try:
            bits = spki[0][1][0].int().bit_length()
        except (A.Asn1Error, IndexError):
            bits = 0
        return 'dsa-%d' % bits, bits, sha
    return A.oid_name(alg), 0, sha


def _names_of(san, cn):
    names = [v for t, v in san if t in ('DNS', 'IP', 'email', 'URI', 'UPN')]
    if not names and cn:
        names = [cn]
    return names


def serial_hex(b_or_int):
    """A serial as hex upper, no colons, an even number of digits."""
    if isinstance(b_or_int, int):
        h = '%X' % b_or_int
    else:
        h = bytes(b_or_int).hex().upper()
    if len(h) % 2:
        h = '0' + h
    return h


def norm_serial(s):
    """A serial as people write it ('01:a3:..', '0x1A3', 'A3') to hex upper as serial_hex."""
    s = str(s).strip().replace(':', '').replace(' ', '')
    if s.lower().startswith('0x'):
        s = s[2:]
    if not s or not re.match(r'^[0-9A-Fa-f]+$', s):
        raise PkiError('not a serial number: %r' % s)
    return serial_hex(int(s, 16))


def _b64url(b):
    return base64.urlsafe_b64encode(bytes(b)).decode('ascii').rstrip('=')


def ari_id(aki_hex, serial_der_bytes):
    """The ACME Renewal Information certificate identifier (RFC 9773 §4.1):
    base64url(keyIdentifier of the AKI) "." base64url(the serial's DER content
    bytes, a leading 00 included)."""
    if isinstance(serial_der_bytes, str):
        h = serial_der_bytes.replace(':', '')
        b = bytes.fromhex(('0' if len(h) % 2 else '') + h)
        if b and b[0] & 0x80:
            b = b'\x00' + b
        serial_der_bytes = b
    return '%s.%s' % (_b64url(bytes.fromhex(aki_hex.replace(':', ''))), _b64url(serial_der_bytes))


def cert_info(pem_or_der):
    """What a certificate says - see the module's documentation for the keys."""
    der = _cert_der(pem_or_der)
    try:
        cert = A.parse(der)
        tbs = cert[0]
        i = 0
        version = 1
        if tbs[0].is_ctx(0):
            version = tbs[0][0].int() + 1
            i = 1
        serial_node = tbs[i]
        sig_alg = A.oid_name(tbs[i + 1][0].oid())
        issuer_dn, issuer, _ = parse_name(tbs[i + 2])
        nb, na = tbs[i + 3][0].time(), tbs[i + 3][1].time()
        subject_dn, subject, subject_list = parse_name(tbs[i + 4])
        spki = tbs[i + 5]
        exts = None
        for x in tbs.children[i + 6:]:
            if x.is_ctx(3):
                exts = x[0]
        subject_raw = tbs[i + 4].raw
        issuer_raw = tbs[i + 2].raw
    except (A.Asn1Error, IndexError, ValueError) as e:
        raise PkiError('this is not a certificate that can be read: %s' % e)
    ext = parse_extensions(exts) if exts is not None else parse_extensions([])
    key_type, key_bits, pub_sha = spki_info(spki)
    cn = subject.get('CN', '')
    serial_bytes = serial_node.content
    self_signed = subject_raw == issuer_raw and (not ext['aki'] or not ext['ski'] or
                                                 ext['aki'] == ext['ski'])
    info = {
        'subject_dn': subject_dn, 'subject': subject, 'subject_list': subject_list,
        'issuer_dn': issuer_dn, 'issuer': issuer, 'cn': cn,
        'names': _names_of(ext['san'], cn), 'san': ext['san'],
        'serial': serial_hex(serial_node.uint_bytes()),
        'not_before': nb, 'not_after': na,
        'sha256': hashlib.sha256(der).hexdigest().upper(),
        'sha1': hashlib.sha1(der).hexdigest().upper(),
        'key_type': key_type, 'key_bits': key_bits, 'pub_sha256': pub_sha,
        'is_ca': ext['is_ca'], 'path_len': ext['path_len'], 'self_signed': self_signed,
        'eku': ext['eku'], 'key_usage': ext['key_usage'], 'ski': ext['ski'], 'aki': ext['aki'],
        'ocsp': ext['ocsp'], 'crl': ext['crl'], 'ca_issuers': ext['ca_issuers'],
        'must_staple': ext['must_staple'], 'sct': ext['sct'],
        'name_constraints': ext['name_constraints'], 'policies': ext['policies'],
        'extensions': ext['extensions'],
        'ari_id': ari_id(ext['aki'], serial_bytes) if ext['aki'] else '',
        'sig_alg': sig_alg, 'version': version,
        'subject_der': subject_raw, 'issuer_der': issuer_raw,
        'pem': der_to_pem(der, 'CERTIFICATE'),
    }
    return info


def csr_info(pem):
    """What a request says: subject_dn, subject, cn, names, san, key_type,
    key_bits, sha256 (= pub_sha256, of the public key), eku, must_staple."""
    if isinstance(pem, str) or b'-----BEGIN' in pem:
        blocks = [b for b in split_pem(pem) if 'REQUEST' in b[0]]
        if not blocks:
            raise PkiError('no certificate request (CSR) found in the text')
        der = pem_to_der(blocks[0][1])
    else:
        der = bytes(pem)
    try:
        req = A.parse(der)
        cri = req[0]
        subject_dn, subject, subject_list = parse_name(cri[1])
        spki = cri[2]
        exts = parse_extensions([])
        challenge = ''
        for x in cri.children[3:]:
            if x.is_ctx(0):
                attrs = x.children if x.constructed else A.parse_all(x.content)
                for attr in attrs:
                    o = attr[0].oid()
                    if o == '1.2.840.113549.1.9.14':
                        exts = parse_extensions(attr[1][0])
                    elif o == '1.2.840.113549.1.9.7':
                        challenge = attr[1][0].text()
        sig_alg = A.oid_name(req[1][0].oid())
    except (A.Asn1Error, IndexError, ValueError) as e:
        raise PkiError('this is not a certificate request that can be read: %s' % e)
    key_type, key_bits, pub_sha = spki_info(spki)
    cn = subject.get('CN', '')
    return {'subject_dn': subject_dn, 'subject': subject, 'subject_list': subject_list,
            'cn': cn, 'names': _names_of(exts['san'], cn), 'san': exts['san'],
            'key_type': key_type, 'key_bits': key_bits, 'sha256': pub_sha,
            'pub_sha256': pub_sha, 'eku': exts['eku'], 'key_usage': exts['key_usage'],
            'must_staple': exts['must_staple'], 'sig_alg': sig_alg,
            'challenge_password': bool(challenge),
            'pem': der_to_pem(der, 'CERTIFICATE REQUEST'), 'der': der}


def csr_verify(csr_pem):
    """True when the request is signed by the key inside it."""
    try:
        openssl(['req', '-verify', '-noout'], data=csr_pem)
        return True
    except PkiError:
        return False


CRL_REASONS = ('unspecified', 'keyCompromise', 'CACompromise', 'affiliationChanged',
               'superseded', 'cessationOfOperation', 'certificateHold', None,
               'removeFromCRL', 'privilegeWithdrawn', 'AACompromise')


def crl_info(pem_or_der):
    """A CRL: issuer_dn, this_update, next_update, number, aki,
    revoked [{serial, at, reason}], sig_alg."""
    if isinstance(pem_or_der, str) or b'-----BEGIN' in pem_or_der:
        der = pem_to_der(pem_or_der)
    else:
        der = bytes(pem_or_der)
    try:
        crl = A.parse(der)
        tbs = crl[0]
        i = 1 if tbs[0].is_(A.INTEGER) else 0
        out = {'version': tbs[0].int() + 1 if i else 1,
               'sig_alg': A.oid_name(tbs[i][0].oid()),
               'issuer_dn': parse_name(tbs[i + 1])[0],
               'this_update': tbs[i + 2].time(), 'next_update': None,
               'number': None, 'aki': '', 'revoked': []}
        rest = tbs.children[i + 3:]
        if rest and rest[0].is_(A.UTCTIME) or rest and rest[0].is_(A.GENERALIZEDTIME):
            out['next_update'] = rest[0].time()
            rest = rest[1:]
        for x in rest:
            if x.is_seq:
                for entry in x:
                    reason = 'unspecified'
                    if len(entry) > 2:
                        for e in entry[2]:
                            if e[0].oid() == '2.5.29.21':
                                code = A.parse(e[len(e) - 1].content).int()
                                if 0 <= code < len(CRL_REASONS) and CRL_REASONS[code]:
                                    reason = CRL_REASONS[code]
                    out['revoked'].append({'serial': serial_hex(entry[0].uint_bytes()),
                                           'at': entry[1].time(), 'reason': reason})
            elif x.is_ctx(0):
                for e in x[0]:
                    o = e[0].oid()
                    v = A.parse(e[len(e) - 1].content)
                    if o == '2.5.29.20':
                        out['number'] = v.int()
                    elif o == '2.5.29.35':
                        for y in v:
                            if y.is_ctx(0):
                                out['aki'] = y.content.hex().upper()
    except (A.Asn1Error, IndexError, ValueError) as e:
        raise PkiError('this is not a CRL that can be read: %s' % e)
    return out


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def make_key(key_type):
    """A new private key, PKCS#8 PEM."""
    kt = str(key_type or '').lower().replace('_', '-')
    kt = {'ec256': 'ec-256', 'ec384': 'ec-384', 'p-256': 'ec-256', 'p-384': 'ec-384',
          'rsa2048': 'rsa-2048', 'rsa3072': 'rsa-3072', 'rsa4096': 'rsa-4096',
          'ec-521': 'ec-521', 'ec521': 'ec-521', 'p-521': 'ec-521'}.get(kt, kt)
    if kt in ('ec-256', 'ec-384', 'ec-521'):
        curve = {'ec-256': 'P-256', 'ec-384': 'P-384', 'ec-521': 'P-521'}[kt]
        args = ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:' + curve,
                '-pkeyopt', 'ec_param_enc:named_curve']
    elif kt.startswith('rsa-') and kt[4:].isdigit() and 2048 <= int(kt[4:]) <= 8192:
        args = ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:' + kt[4:]]
    elif kt == 'ed25519':
        args = ['genpkey', '-algorithm', 'ED25519']
    else:
        raise PkiError('an unknown key type: %s (one of %s)' % (key_type, ' '.join(KEY_TYPES)))
    out = openssl(args, timeout=300).decode('ascii')
    blocks = [p for lab, p in split_pem(out) if lab == 'PRIVATE KEY']
    if not blocks:
        raise PkiError('openssl genpkey gave no key')
    return blocks[0]


def _key_label(text):
    for label, pem in split_pem(text):
        if label.endswith('PRIVATE KEY'):
            return label, pem
    return None, None


def is_encrypted_key(key_pem):
    label, pem = _key_label(key_pem)
    return label == 'ENCRYPTED PRIVATE KEY' or bool(pem and 'Proc-Type: 4,ENCRYPTED' in pem)


def key_plain(key, password=None):
    """Any private key - PEM (PKCS#8, PKCS#1, SEC1, encrypted or not) or DER -
    as unencrypted PKCS#8 PEM. Raises PasswordError when it is encrypted and
    the password is missing or wrong."""
    if isinstance(key, (bytes, bytearray)) and b'-----BEGIN' not in key:
        data, inform = bytes(key), 'DER'
    else:
        label, pem = _key_label(key)
        if not pem:
            raise PkiError('no private key found in the text')
        if label == 'PRIVATE KEY':
            return pem
        data, inform = pem, 'PEM'
    try:
        out = openssl(['pkey', '-inform', inform, '-passin', 'env:' + PASS_ENV],
                      data=data, env={PASS_ENV: password or ''})
    except PkiError as e:
        enc = inform == 'DER' or is_encrypted_key(data)
        if enc and (isinstance(e, PasswordError) or 'unsupported' in str(e).lower() or
                    'decrypt' in str(e).lower()):
            raise PasswordError('the private key is encrypted: %s' %
                                ('the password is wrong' if password else 'a password is needed'),
                                e.detail)
        raise
    return _key_label(out.decode('ascii'))[1]


def key_encrypt(key_pem, password, cipher='aes-256-cbc'):
    """The key as encrypted PKCS#8 PEM (PBES2, PBKDF2)."""
    if not password:
        raise PkiError('a password is needed to encrypt a key')
    out = openssl(['pkey', '-' + cipher, '-passout', 'env:' + PASS_ENV_OUT],
                  data=key_plain(key_pem), env={PASS_ENV_OUT: password})
    return out.decode('ascii')


def key_der(key_pem):
    """PKCS#8 DER."""
    return pem_to_der(key_plain(key_pem))


def key_traditional(key_pem):
    """The key in its own type's format: PKCS#1 for RSA (BEGIN RSA PRIVATE
    KEY), SEC1 for EC."""
    out = openssl(['pkey', '-traditional'], data=key_plain(key_pem))
    return out.decode('ascii')


def public_der(key_pem, password=None):
    """The SubjectPublicKeyInfo DER of a private key."""
    return openssl(['pkey', '-pubout', '-outform', 'DER'], data=key_plain(key_pem, password))


def key_info(key_pem, password=None):
    """{key_type, key_bits, pub_sha256} of a private key."""
    kt, bits, sha = spki_info(A.parse(public_der(key_pem, password)))
    return {'key_type': kt, 'key_bits': bits, 'pub_sha256': sha}


def key_matches(cert_pem, key_pem, password=None):
    try:
        return cert_info(cert_pem)['pub_sha256'] == key_info(key_pem, password)['pub_sha256']
    except PkiError:
        return False


def md_args(key_type):
    """The digest to sign with, by the signer's key."""
    kt = str(key_type or '')
    if kt.startswith('ed'):
        return []
    if kt == 'ec-384':
        return ['-sha384']
    if kt == 'ec-521':
        return ['-sha512']
    return ['-sha256']


def md_name(key_type):
    a = md_args(key_type)
    return a[0][1:] if a else 'default'


# ---------------------------------------------------------------------------
# Requests and self-signed certificates
# ---------------------------------------------------------------------------
SUBJECT_ORDER = ('C', 'ST', 'L', 'street', 'postalCode', 'O', 'OU', 'title', 'serialNumber',
                 'DC', 'UID', 'GN', 'SN', 'CN', 'emailAddress')
_SUBJECT_ALIAS = {'commonname': 'CN', 'cn': 'CN', 'o': 'O', 'organization': 'O',
                  'organizationname': 'O', 'ou': 'OU', 'organizationalunitname': 'OU',
                  'organizationunit': 'OU', 'c': 'C', 'country': 'C', 'countryname': 'C',
                  'st': 'ST', 's': 'ST', 'state': 'ST', 'stateorprovincename': 'ST', 'l': 'L',
                  'locality': 'L', 'localityname': 'L', 'email': 'emailAddress',
                  'emailaddress': 'emailAddress', 'e': 'emailAddress', 'dc': 'DC',
                  'uid': 'UID', 'serialnumber': 'serialNumber', 'street': 'street',
                  'postalcode': 'postalCode', 'title': 'title', 'gn': 'GN', 'sn': 'SN',
                  'givenname': 'GN', 'surname': 'SN'}


def subject_pairs(subject):
    """A subject - {CN: .., O: .., OU: [..]} or [(k, v)] or 'CN=x,O=y' or
    '/C=CZ/CN=x' - as [(short, value)], in the usual order (C first, CN late)."""
    if not subject:
        return []
    pairs = []
    if isinstance(subject, str):
        s = subject.strip()
        if s.startswith('/'):
            parts = [p for p in re.split(r'(?<!\\)/', s) if p]
        else:
            parts = [p for p in re.split(r'(?<!\\),', s) if p.strip()]
        for p in parts:
            if '=' not in p:
                raise PkiError('a subject part without "=": %s' % p)
            k, v = p.split('=', 1)
            pairs.append((k.strip(), v.strip().replace('\\/', '/').replace('\\,', ',')))
        if not s.startswith('/'):
            pairs.reverse()             # RFC 4514 writes the most specific first
    elif isinstance(subject, dict):
        for k, v in subject.items():
            for one in (v if isinstance(v, (list, tuple)) else [v]):
                if one not in (None, ''):
                    pairs.append((k, str(one)))
    else:
        pairs = [(k, str(v)) for k, v in subject if v not in (None, '')]
    out = []
    for k, v in pairs:
        key = _SUBJECT_ALIAS.get(str(k).strip().lower().replace(' ', ''), str(k).strip())
        if not re.match(r'^[A-Za-z][A-Za-z0-9]*$|^\d+(\.\d+)+$', key):
            raise PkiError('an unknown subject field: %s' % k)
        v = str(v).strip()
        if '\n' in v or '\r' in v or '\x00' in v:
            raise PkiError('a subject value with a line break in it: %s' % k)
        if key == 'C' and len(v) != 2:
            raise PkiError('the country (C) is two letters: %r' % v)
        out.append((key, v))
    if isinstance(subject, dict):
        rank = {k: i for i, k in enumerate(SUBJECT_ORDER)}
        out.sort(key=lambda kv: rank.get(kv[0], len(SUBJECT_ORDER) - 2))
    return out


def classify_name(n):
    """('DNS'|'IP'|'email'|'URI', value) of one name as acme is given it."""
    s = str(n).strip()
    for prefix, kind in (('dns:', 'DNS'), ('ip:', 'IP'), ('email:', 'email'),
                         ('uri:', 'URI'), ('upn:', 'UPN')):
        if s.lower().startswith(prefix) and not (prefix == 'uri:' and '://' in s[:4]):
            s, forced = s[len(prefix):].strip(), kind
            break
    else:
        forced = None
    if forced in (None, 'IP'):
        try:
            return 'IP', str(ipaddress.ip_address(s.strip('[]')))
        except ValueError:
            if forced == 'IP':
                raise PkiError('not an IP address: %s' % s)
    if forced == 'URI' or (forced is None and re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', s)):
        return 'URI', s
    if forced == 'UPN':
        return 'UPN', s
    if forced == 'email' or (forced is None and '@' in s):
        local, _, dom = s.rpartition('@')
        if not local or not dom:
            raise PkiError('not an e-mail address: %s' % s)
        return 'email', '%s@%s' % (local, _idna(dom))
    return 'DNS', _idna(s)


def _idna(name):
    name = name.strip().rstrip('.').lower()
    if not name:
        raise PkiError('an empty name')
    labels = []
    for lab in name.split('.'):
        if lab == '*' or all(ord(c) < 128 for c in lab):
            labels.append(lab)
        else:
            try:
                labels.append(lab.encode('idna').decode('ascii'))
            except UnicodeError:
                raise PkiError('a name that cannot be written in DNS: %s' % name)
    out = '.'.join(labels)
    if not re.match(r'^[A-Za-z0-9*_.-]+$', out) or len(out) > 253:
        raise PkiError('not a DNS name: %s' % name)
    return out


def _cv(s):
    """A value in an openssl config file, its specials taken literally."""
    s = str(s)
    if '\n' in s or '\r' in s:
        raise PkiError('a line break where none may be')
    return re.sub(r'([\\"\'$#])', r'\\\1', s)


def _subj_arg(pairs):
    """A subject for -subj (/C=CZ/CN=x), its specials escaped."""
    return '/' + '/'.join('%s=%s' % (k, re.sub(r'([\\/+=])', r'\\\1', v)) for k, v in pairs) \
        if pairs else '/'


def san_lines(names):
    """The [san] section of a config: DNS.1 = .., IP.1 = .. - and the names as classified."""
    lines, typed, count = [], [], {}
    for n in names or []:
        t, v = classify_name(n)
        if (t, v) in typed:
            continue
        typed.append((t, v))
        if t == 'UPN':
            key, val = 'otherName', '1.3.6.1.4.1.311.20.2.3;UTF8:' + v
        else:
            key, val = t, v
        count[key] = count.get(key, 0) + 1
        lines.append('%s.%d = %s' % (key, count[key], _cv(val)))
    return lines, typed


def _eku_value(eku):
    if isinstance(eku, str):
        eku = [e for e in re.split(r'[\s,]+', eku) if e]
    out = []
    for e in eku or []:
        e = str(e).strip()
        if not re.match(r'^[A-Za-z0-9.]+$', e):
            raise PkiError('an unknown extended key usage: %s' % e)
        try:
            A.name_oid(e)
        except A.Asn1Error:
            raise PkiError('an unknown extended key usage: %s' % e)
        out.append(A.oid_name(A.name_oid(e)) if not re.match(r'^\d', e) else e)
    return out


def _ku_value(ku):
    if isinstance(ku, str):
        ku = [e for e in re.split(r'[\s,]+', ku) if e]
    out = []
    for k in ku or []:
        k = str(k).strip()
        hit = [b for b in KEY_USAGE_BITS if b.lower() == k.lower()]
        if not hit:
            raise PkiError('an unknown key usage: %s' % k)
        out.append(hit[0])
    return out


def req_config(pairs, ext_lines, san, utf8=True):
    """An openssl config for `req`: [dn] from pairs, [ext] and [san]."""
    lines = ['[req]', 'distinguished_name = dn', 'prompt = no',
             'string_mask = utf8only' if utf8 else 'string_mask = default',
             'utf8 = yes', 'req_extensions = ext', 'x509_extensions = ext', '', '[dn]']
    seen = {}
    for k, v in pairs:
        seen[k] = seen.get(k, -1) + 1
        lines.append('%d.%s = %s' % (seen[k], k, _cv(v)))
    if not pairs:
        lines.append('CN = unused')     # replaced by -subj /
    lines += ['', '[ext]'] + list(ext_lines) + ['']
    if san:
        lines += ['[san]'] + san + ['']
    return '\n'.join(lines) + '\n'


def _subject_for(names, subject):
    pairs = subject_pairs(subject)
    if not any(k == 'CN' for k, _ in pairs) and names:
        first = str(names[0]).strip()
        try:
            v = classify_name(first)[1]
        except PkiError:
            v = first
        if len(v) <= 64:
            pairs.append(('CN', v))
    return pairs


def make_csr(key_pem, names, subject=None, must_staple=False, eku=None):
    """A request for `names` (DNS, IP v4/v6, e-mail, URI), signed with the key.
    The common name is the first name, where it fits in 64 characters and
    `subject` names none. -> (csr_pem, csr_der)"""
    names = list(names or [])
    pairs = _subject_for(names, subject)
    san, typed = san_lines(names)
    ext = []
    if san:
        ext.append('subjectAltName = %s@san' % ('critical, ' if not pairs else ''))
    if eku:
        ext.append('extendedKeyUsage = ' + ', '.join(_eku_value(eku)))
    if must_staple:
        ext.append('tlsfeature = status_request')
    if not pairs and not san:
        raise PkiError('a request needs a name or a subject')
    key = key_plain(key_pem)
    kt = key_info(key)['key_type']
    with workdir() as d:
        wfile(d, 'k.key', key)
        wfile(d, 'req.cnf', req_config(pairs, ext, san))
        args = ['req', '-new', '-key', os.path.join(d, 'k.key'), '-config',
                os.path.join(d, 'req.cnf'), '-utf8'] + md_args(kt)
        if not pairs:
            args += ['-subj', '/']
        out = openssl(args)
    pem = [p for lab, p in split_pem(out) if 'REQUEST' in lab][0]
    return pem, pem_to_der(pem)


def random_serial():
    """20 random bytes, positive (RFC 5280 allows 20 octets), as hex."""
    b = bytearray(secrets.token_bytes(20))
    b[0] = (b[0] & 0x7f) | 0x10
    return b.hex().upper()


def self_signed(key_pem, names, subject=None, days=365, eku=None, must_staple=False,
                key_usage=None, is_ca=False, path_len=None, serial=None):
    """A certificate signed by its own key: a leaf for `names` (is_ca False)
    or a root (is_ca True). -> cert_pem"""
    names = list(names or [])
    pairs = _subject_for(names, subject)
    san, _ = san_lines(names)
    key = key_plain(key_pem)
    kt = key_info(key)['key_type']
    ext = ['subjectKeyIdentifier = hash']
    if is_ca:
        bc = 'critical, CA:TRUE' + (', pathlen:%d' % int(path_len) if path_len not in
                                   (None, '') else '')
        ext += ['basicConstraints = ' + bc,
                'keyUsage = critical, ' + ', '.join(_ku_value(key_usage) or
                                                   ['keyCertSign', 'cRLSign',
                                                    'digitalSignature'])]
    else:
        ext += ['basicConstraints = critical, CA:FALSE',
                'keyUsage = critical, ' + ', '.join(_ku_value(key_usage) or
                                                   default_key_usage(kt))]
        ext.append('extendedKeyUsage = ' + ', '.join(_eku_value(eku) or ['serverAuth',
                                                                        'clientAuth']))
    ext.append('authorityKeyIdentifier = keyid:always')
    if san:
        ext.append('subjectAltName = %s@san' % ('critical, ' if not pairs else ''))
    elif not is_ca and not pairs:
        raise PkiError('a certificate needs a name or a subject')
    if must_staple:
        ext.append('tlsfeature = status_request')
    with workdir() as d:
        wfile(d, 'k.key', key)
        wfile(d, 'req.cnf', req_config(pairs, ext, san))
        args = ['req', '-new', '-x509', '-key', os.path.join(d, 'k.key'), '-config',
                os.path.join(d, 'req.cnf'), '-utf8', '-days', str(max(1, int(days))),
                '-set_serial', '0x' + (serial or random_serial())] + md_args(kt)
        if not pairs:
            args += ['-subj', '/']
        out = openssl(args)
    return certs_in(out)[0]


def default_key_usage(key_type):
    if str(key_type).startswith('rsa'):
        return ['digitalSignature', 'keyEncipherment']
    return ['digitalSignature']


# ---------------------------------------------------------------------------
# Chains
# ---------------------------------------------------------------------------
def _issued_by(child, parent):
    """Whether `parent` (info) is the issuer of `child` (info), by name and key ids."""
    if child['issuer_der'] != parent['subject_der']:
        return False
    if child['aki'] and parent['ski']:
        return child['aki'] == parent['ski']
    return True


def order_chain(leaf_pem, pems):
    """The certificates above the leaf, nearest first, out of `pems` (any
    order, duplicates, the leaf itself and strangers among them)."""
    leaf = cert_info(leaf_pem)
    pool = {}
    for p in pems or []:
        for pem in (certs_in(p) if isinstance(p, str) and p.count('BEGIN') > 1 else [p]):
            try:
                inf = cert_info(pem)
            except PkiError:
                continue
            if inf['sha256'] != leaf['sha256']:
                pool.setdefault(inf['sha256'], inf)
    out, cur, used = [], leaf, {leaf['sha256']}
    while not cur['self_signed']:
        cands = [c for c in pool.values() if c['sha256'] not in used and _issued_by(cur, c)]
        if not cands:
            break
        # The one whose key id answers, then the one valid longest.
        cands.sort(key=lambda c: (bool(cur['aki'] and c['ski'] == cur['aki']),
                                  c['not_after']), reverse=True)
        cur = cands[0]
        used.add(cur['sha256'])
        out.append(cur['pem'])
    return out


def verify_chain(leaf_pem, chain_pems, roots_pems=None, purpose='sslserver', at=None):
    """(ok, words): whether openssl verify takes the leaf through the chain
    to one of `roots_pems` (None: the system's authorities). A root among
    `roots_pems` that is not self-signed is trusted as it is (partial chain)."""
    with workdir() as d:
        args = ['verify']
        leaf = wfile(d, 'leaf.pem', cert_pem(leaf_pem))
        chain = [cert_pem(c) for c in chain_pems or []]
        if roots_pems is not None:
            roots = [cert_pem(c) for c in roots_pems]
            if not roots:
                return False, 'no root certificates to verify against'
            args += ['-CAfile', wfile(d, 'roots.pem', ''.join(roots)), '-no-CApath',
                     '-no-CAstore']
            if any(not cert_info(r)['self_signed'] for r in roots):
                args.append('-partial_chain')
        if chain:
            args += ['-untrusted', wfile(d, 'chain.pem', ''.join(chain))]
        if purpose:
            args += ['-purpose', purpose]
        if at:
            args += ['-attime', str(int(at))]
        args.append(leaf)
        try:
            out = openssl(args).decode('utf-8', 'replace')
        except PkiError as e:
            text = (e.detail or str(e)).replace(leaf, 'certificate')
            m = re.search(r'error \d+ at (\d+) depth lookup: ?(.*)', text)
            if m:
                return False, '%s (at depth %s)' % (m.group(2).strip(), m.group(1))
            return False, _said(text)
    return (': OK' in out), out.replace(leaf, 'certificate').strip()


def now():
    return int(time.time())
