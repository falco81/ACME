# -*- coding: utf-8 -*-
"""
Whatever a certificate comes in, read: read_any(data, filename, password).

    PEM - one block or many, Windows line ends, words around them (.pem .crt .cer .key)
    DER - a certificate, a key (PKCS#8, PKCS#1, SEC1), encrypted PKCS#8
    PKCS#7 / P7B / P7C - PEM or DER (BER too), the certificates in it
    PKCS#12 / PFX - modern (AES, PBKDF2) and legacy (RC2, 3DES; openssl -legacy)
    JKS and JCEKS - Java keystores, read here in Python: Sun's key protection
                    (JKS) and PBEWithMD5AndTripleDES (JCEKS)
    ZIP - holding any of these

The answer:

    {'format': 'pem' | 'der' | 'pkcs7' | 'pkcs12' | 'jks' | 'jceks' | 'pkcs8-encrypted' |
               'pkcs8' | 'pkcs1' | 'sec1' | 'zip' | 'csr' | 'crl',
     'certs': [pem], 'keys': [PKCS#8 pem], 'leaf': pem | None, 'key': pem | None,
     'chain': [pem nearest first], 'others': [pem not in the chain],
     'csrs': [pem], 'crls': [pem], 'aliases': [..], 'notes': [words],
     'needs_password': bool, 'info': cert_info of the leaf (JSON-able) | None}

The leaf is the certificate that matches a key, else the end entity (not a
CA) that issued nothing else in the file.

jks_write(...) writes a JKS keystore (it is what bundle.CertBundle hands out).
"""
from __future__ import annotations

import base64
import hashlib
import io
import re
import secrets
import struct
import time
import zipfile

from acmelib.certs import asn1 as A
from acmelib.certs import pki
from acmelib.certs.pki import PkiError, PasswordError

MAX_ZIP_MEMBER = 20 * 1024 * 1024
MAX_ZIP_MEMBERS = 200

JKS_MAGIC = 0xFEEDFEED
JCEKS_MAGIC = 0xCECECECE
JKS_KEY_OID = '1.3.6.1.4.1.42.2.17.1.1'
JCEKS_KEY_OID = '1.3.6.1.4.1.42.2.19.1'


class _Got(object):
    def __init__(self):
        self.formats = []
        self.certs = []
        self.keys = []
        self.csrs = []
        self.crls = []
        self.aliases = []
        self.notes = []
        self.needs_password = False

    def cert(self, x):
        try:
            pem = pki.cert_pem(x)
            pki.cert_info(pem)
        except (PkiError, A.Asn1Error, ValueError) as e:
            self.notes.append('a certificate that cannot be read was left out: %s' % e)
            return
        if pem not in self.certs:
            self.certs.append(pem)

    def key(self, x, password=''):
        try:
            pem = pki.key_plain(x, password or None)
        except PasswordError as e:
            self.needs_password = True
            self.notes.append(str(e))
            return
        except PkiError as e:
            self.notes.append('a private key that cannot be read was left out: %s' % e)
            return
        if pem not in self.keys:
            self.keys.append(pem)


def read_any(data, filename='', password=''):
    """See the module's documentation."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = bytes(data or b'')
    if not data.strip():
        raise PkiError('the file is empty')
    got = _Got()
    _read(data, filename or '', password or '', got, 0)
    if not (got.certs or got.keys or got.csrs or got.crls) and not got.needs_password:
        raise PkiError('%s holds no certificate, key or keystore acme can read%s'
                       % (filename or 'this', (': ' + '; '.join(got.notes)) if got.notes else ''))
    return _finish(got)


def _read(data, filename, password, got, depth):
    low = filename.lower()
    if data[:4] == b'PK\x03\x04' and depth < 2:
        return _read_zip(data, password, got, depth)
    if len(data) >= 4 and struct.unpack('>I', data[:4])[0] in (JKS_MAGIC, JCEKS_MAGIC):
        return _read_jks(data, password, got)
    head = data[:64 * 1024]
    if b'-----BEGIN' in data:
        return _read_pem(data, password, got)
    if A.looks_like_der(data):
        return _read_der(data, password, got, low)
    # Base64 without the PEM lines around it (pasted, or a .p7b of some tools).
    txt = re.sub(rb'\s+', b'', data)
    if txt and re.match(rb'^[A-Za-z0-9+/=_-]+$', txt) and len(txt) >= 32:
        try:
            raw = base64.b64decode(txt.replace(b'-', b'+').replace(b'_', b'/') +
                                       b'=' * (-len(txt) % 4))
        except ValueError:
            raw = b''
        if raw and A.looks_like_der(raw):
            got.notes.append('base64 without PEM lines, read as DER')
            return _read_der(raw, password, got, low)
    if head.lstrip()[:1] == b'\x30':
        # A DER element followed by garbage, or BER with an indefinite length.
        try:
            A.parse(data)
            return _read_der(data, password, got, low)
        except A.Asn1Error:
            pass
    got.notes.append('%s: not a format acme knows' % (filename or 'the data'))


def _read_zip(data, password, got, depth):
    got.formats.append('zip')
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        got.notes.append('a ZIP that cannot be opened: %s' % e)
        return
    members = [i for i in z.infolist() if not i.is_dir()][:MAX_ZIP_MEMBERS]
    for info in members:
        base = info.filename.rsplit('/', 1)[-1]
        if base.startswith('.') or info.filename.startswith('__MACOSX/'):
            continue
        if info.file_size > MAX_ZIP_MEMBER:
            got.notes.append('%s is too big to be read (%d bytes)' % (info.filename,
                                                                       info.file_size))
            continue
        try:
            body = z.read(info, pwd=password.encode('utf-8') if password else None)
        except RuntimeError as e:
            got.needs_password = True
            got.notes.append('%s in the ZIP is encrypted: %s' % (info.filename, e))
            continue
        except (zipfile.BadZipFile, NotImplementedError, OSError) as e:
            got.notes.append('%s in the ZIP cannot be read: %s' % (info.filename, e))
            continue
        if not body.strip():
            continue
        sub = _Got()
        try:
            _read(body, base, password, sub, depth + 1)
        except (PkiError, A.Asn1Error, ValueError) as e:
            got.notes.append('%s: %s' % (info.filename, e))
            continue
        for c in sub.certs:
            if c not in got.certs:
                got.certs.append(c)
        for k in sub.keys:
            if k not in got.keys:
                got.keys.append(k)
        got.csrs += sub.csrs
        got.crls += sub.crls
        got.aliases += sub.aliases
        got.needs_password = got.needs_password or sub.needs_password
        got.notes += ['%s: %s' % (info.filename, n) for n in sub.notes]


def _read_pem(data, password, got):
    blocks = pki.split_pem(data)
    kinds = set()
    for label, pem in blocks:
        if label in ('CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'):
            got.cert(pem)
            kinds.add('pem')
        elif label in ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY'):
            if 'Proc-Type: 4,ENCRYPTED' in pem:
                kinds.add('pem-encrypted')
            got.key(pem, password)
            kinds.add('pem')
        elif label == 'ENCRYPTED PRIVATE KEY':
            got.key(pem, password)
            kinds.add('pkcs8-encrypted')
        elif label in ('PKCS7', 'CMS'):
            _read_p7(pki.pem_to_der(pem), got)
            kinds.add('pkcs7')
        elif label in ('CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'):
            got.csrs.append(pki.der_to_pem(pki.pem_to_der(pem), 'CERTIFICATE REQUEST'))
            kinds.add('csr')
        elif label == 'X509 CRL':
            got.crls.append(pem)
            kinds.add('crl')
        elif label == 'PUBLIC KEY':
            got.notes.append('a public key alone is not kept')
        elif label in ('OPENSSH PRIVATE KEY',):
            got.notes.append('an OpenSSH key is not a certificate key (convert it with '
                             'ssh-keygen -p -m PKCS8)')
        else:
            got.notes.append('a PEM block "%s" is not used' % label)
    if not blocks:
        got.notes.append('PEM lines without any block that could be read')
    for k in ('pkcs7', 'pkcs8-encrypted', 'pem', 'csr', 'crl'):
        if k in kinds:
            got.formats.append(k if not (k == 'pkcs8-encrypted' and got.certs) else 'pem')
            break


def _classify_der(n):
    """What a DER element is: cert, crl, csr, pkcs7, pkcs12, pkcs8, pkcs8-encrypted,
    pkcs1, sec1, or None."""
    try:
        ch = n.children
    except A.Asn1Error:
        return None
    if not ch:
        return None
    if ch[0].is_(A.OID):
        o = ch[0].oid()
        if o in ('1.2.840.113549.1.7.2',):
            return 'pkcs7'
        return None
    if ch[0].is_(A.INTEGER):
        v = ch[0].int()
        if v == 3 and len(ch) >= 2 and ch[1].is_seq and ch[1][0].is_(A.OID) and \
                ch[1][0].oid() == '1.2.840.113549.1.7.1':
            return 'pkcs12'
        if v in (0, 1) and len(ch) >= 3 and ch[1].is_seq and ch[2].is_(A.OCTET_STRING):
            return 'pkcs8'
        if v == 0 and len(ch) >= 9 and all(c.is_(A.INTEGER) for c in ch[:9]):
            return 'pkcs1'
        if v == 1 and len(ch) >= 2 and ch[1].is_(A.OCTET_STRING):
            return 'sec1'
        return None
    if ch[0].is_seq and len(ch) == 2 and ch[1].is_(A.OCTET_STRING):
        return 'pkcs8-encrypted'
    if ch[0].is_seq and len(ch) == 3 and ch[2].is_(A.BIT_STRING):
        tbs = ch[0].children
        if tbs and tbs[0].is_ctx(0):
            return 'cert'
        # v1 certificate: serial, alg, issuer, validity(SEQ of times), subject, spki
        if len(tbs) >= 6 and tbs[0].is_(A.INTEGER) and tbs[3].is_seq and len(tbs[3]) == 2 \
                and tbs[3][0].tag in (A.UTCTIME, A.GENERALIZEDTIME):
            return 'cert'
        if len(tbs) >= 3 and tbs[0].is_(A.INTEGER) and tbs[0].int() == 0 and tbs[1].is_seq \
                and tbs[2].is_seq and len(tbs[2]) == 2 and tbs[2][0].is_seq:
            return 'csr'
        return 'crl'
    return None


def _read_der(data, password, got, low):
    try:
        n = A.parse(data)
    except A.Asn1Error as e:
        got.notes.append('DER that cannot be read: %s' % e)
        return
    data = n.raw
    kind = _classify_der(n)
    if kind == 'cert':
        got.formats.append('der')
        got.cert(data)
    elif kind == 'pkcs7':
        got.formats.append('pkcs7')
        _read_p7(data, got)
    elif kind == 'pkcs12':
        got.formats.append('pkcs12')
        _read_p12(data, password, got)
    elif kind in ('pkcs8', 'pkcs1', 'sec1', 'pkcs8-encrypted'):
        got.formats.append(kind)
        got.key(data, password)
    elif kind == 'csr':
        got.formats.append('csr')
        got.csrs.append(pki.der_to_pem(data, 'CERTIFICATE REQUEST'))
    elif kind == 'crl':
        try:
            pki.crl_info(data)
            got.formats.append('crl')
            got.crls.append(pki.der_to_pem(data, 'X509 CRL'))
        except PkiError as e:
            got.notes.append('DER that is none of what acme reads: %s' % e)
    else:
        got.notes.append('DER that is none of what acme reads')


def _read_p7(der, got):
    """The certificates (and CRLs) of a PKCS#7 SignedData."""
    try:
        ci = A.parse(der)
        if ci[0].oid() != '1.2.840.113549.1.7.2':
            got.notes.append('a PKCS#7 that is not signedData (%s)' % ci[0].oid())
            return
        sd = ci[1][0]
        found = 0
        for part in sd.children[1:]:
            if part.is_ctx(0):
                for c in part:
                    if c.is_seq:
                        got.cert(c.raw)
                        found += 1
            elif part.is_ctx(1):
                for c in part:
                    if c.is_seq:
                        got.crls.append(pki.der_to_pem(c.raw, 'X509 CRL'))
        if not found:
            got.notes.append('the PKCS#7 holds no certificates')
    except (A.Asn1Error, IndexError) as e:
        got.notes.append('a PKCS#7 that cannot be read: %s' % e)


def _read_p12(der, password, got):
    args = ['pkcs12', '-nodes', '-passin', 'env:' + pki.PASS_ENV]
    env = {pki.PASS_ENV: password or ''}
    try:
        out = pki.openssl(args, data=der, env=env)
    except PasswordError:
        got.needs_password = True
        got.notes.append('the PKCS#12 file needs its password' if not password else
                         'the password of the PKCS#12 file is wrong')
        return
    except PkiError as e:
        detail = (e.detail or '').lower()
        if any(w in detail for w in ('unsupported', 'rc2', 'legacy', 'fetch', 'algorithm')):
            try:
                out = pki.openssl(args + ['-legacy'], data=der, env=env)
                got.notes.append('a legacy PKCS#12 (RC2/3DES/RC4), read with -legacy')
            except PasswordError:
                got.needs_password = True
                got.notes.append('the password of the PKCS#12 file is wrong or missing')
                return
            except PkiError as e2:
                got.notes.append('a PKCS#12 that cannot be read: %s' % e2)
                return
        else:
            got.notes.append('a PKCS#12 that cannot be read: %s' % e)
            return
    text = out.decode('utf-8', 'replace')
    for m in re.finditer(r'friendlyName:\s*(.+)', text):
        if m.group(1).strip() not in got.aliases:
            got.aliases.append(m.group(1).strip())
    for label, pem in pki.split_pem(text):
        if label == 'CERTIFICATE':
            got.cert(pem)
        elif label.endswith('PRIVATE KEY'):
            got.key(pem)


# ---------------------------------------------------------------------------
# Choosing the leaf
# ---------------------------------------------------------------------------
def _json_info(info):
    return {k: v for k, v in info.items() if not isinstance(v, (bytes, bytearray))}


def _finish(got):
    infos = {}
    for c in got.certs:
        infos[c] = pki.cert_info(c)
    key_pubs = {}
    for k in got.keys:
        try:
            key_pubs[k] = pki.key_info(k)['pub_sha256']
        except PkiError:
            pass
    leaf, key = None, None
    # The certificate a key belongs to - an end entity before a CA.
    matches = [(c, k) for c in got.certs for k, pub in key_pubs.items()
               if infos[c]['pub_sha256'] == pub]
    matches.sort(key=lambda ck: infos[ck[0]]['is_ca'])
    if matches:
        leaf, key = matches[0]
    elif got.certs:
        def issues_others(c):
            return any(o != c and pki._issued_by(infos[o], infos[c]) for o in got.certs)
        ee = [c for c in got.certs if not infos[c]['is_ca'] and not issues_others(c)]
        if not ee:
            ee = [c for c in got.certs if not issues_others(c)] or list(got.certs)
            if ee and infos[ee[0]]['is_ca']:
                got.notes.append('only CA certificates: the lowest is taken as the certificate')
        leaf = ee[0]
        if len(ee) > 1:
            got.notes.append('%d certificates could each be the certificate; the first is '
                             'taken' % len(ee))
        if got.keys:
            got.notes.append('the private key does not belong to the certificate')
    chain = pki.order_chain(leaf, [c for c in got.certs if c != leaf]) if leaf else []
    others = [c for c in got.certs if c != leaf and c not in chain]
    if others:
        got.notes.append('%d certificate(s) not in the chain of the certificate' % len(others))
    if leaf and not key and not got.keys and not got.needs_password:
        got.notes.append('no private key in the file')
    fmt = got.formats[0] if got.formats else ('pem' if got.certs else 'unknown')
    if len(set(got.formats)) > 1 and fmt != 'zip':
        got.notes.append('formats inside: %s' % ', '.join(sorted(set(got.formats))))
    return {'format': fmt, 'certs': list(got.certs), 'keys': list(got.keys), 'leaf': leaf,
            'key': key, 'chain': chain, 'others': others, 'csrs': got.csrs, 'crls': got.crls,
            'aliases': got.aliases, 'notes': got.notes, 'needs_password': got.needs_password,
            'info': _json_info(infos[leaf]) if leaf else None}


# ---------------------------------------------------------------------------
# Java keystores: JKS and JCEKS
# ---------------------------------------------------------------------------
def _java_pw(password):
    return str(password or '').encode('utf-16-be')


def _read_utf(data, pos):
    (n,) = struct.unpack('>H', data[pos:pos + 2])
    raw = data[pos + 2:pos + 2 + n]
    return _decode_mutf8(raw), pos + 2 + n


def _decode_mutf8(raw):
    # Java's modified UTF-8: 0 as C0 80, characters past the BMP as two surrogates.
    try:
        return raw.replace(b'\xc0\x80', b'\x00').decode('utf-8', 'surrogatepass') \
            .encode('utf-16', 'surrogatepass').decode('utf-16')
    except UnicodeError:
        return raw.decode('latin-1')


def _encode_mutf8(s):
    out = bytearray()
    for unit in struct.unpack('>%dH' % (len(s.encode('utf-16-be')) // 2), s.encode('utf-16-be')):
        if 0 < unit < 0x80:
            out.append(unit)
        elif unit < 0x800:
            out += bytes([0xc0 | (unit >> 6), 0x80 | (unit & 0x3f)])
        else:
            out += bytes([0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f)])
    if len(out) > 0xffff:
        raise PkiError('an alias too long for a keystore')
    return struct.pack('>H', len(out)) + bytes(out)


def jks_parse(data, password=''):
    """A JKS or JCEKS keystore: {'type', 'entries': [{'alias', 'kind'
    ('key'|'cert'|'secret'), 'ts', 'certs': [der], 'protected': bytes}], 'ok'
    (the integrity check passed - None when no password was given), 'notes'}."""
    data = bytes(data)
    magic, version, count = struct.unpack('>III', data[:12])
    kind = 'jks' if magic == JKS_MAGIC else 'jceks'
    if version not in (1, 2):
        raise PkiError('a %s keystore of version %d, which acme does not read' % (kind.upper(),
                                                                                version))
    pos = 12
    entries, notes = [], []
    stopped = False
    for _ in range(count):
        (tag,) = struct.unpack('>I', data[pos:pos + 4])
        pos += 4
        alias, pos = _read_utf(data, pos)
        (ts,) = struct.unpack('>Q', data[pos:pos + 8])
        pos += 8
        e = {'alias': alias, 'ts': ts, 'certs': [], 'protected': b''}
        if tag == 1:
            (n,) = struct.unpack('>I', data[pos:pos + 4])
            e['protected'] = data[pos + 4:pos + 4 + n]
            pos += 4 + n
            (nc,) = struct.unpack('>I', data[pos:pos + 4])
            pos += 4
            for _c in range(nc):
                if version == 2:
                    _ctype, pos = _read_utf(data, pos)
                (cl,) = struct.unpack('>I', data[pos:pos + 4])
                e['certs'].append(data[pos + 4:pos + 4 + cl])
                pos += 4 + cl
            e['kind'] = 'key'
        elif tag == 2:
            if version == 2:
                _ctype, pos = _read_utf(data, pos)
            (cl,) = struct.unpack('>I', data[pos:pos + 4])
            e['certs'].append(data[pos + 4:pos + 4 + cl])
            pos += 4 + cl
            e['kind'] = 'cert'
        elif tag == 3:
            # A secret key (JCEKS): a serialized Java object, of no length
            # given - what follows cannot be found, so the reading stops.
            notes.append('a secret key entry (%s) and what follows it are not read' % alias)
            entries.append({'alias': alias, 'ts': ts, 'certs': [], 'kind': 'secret'})
            stopped = True
            break
        else:
            raise PkiError('a keystore entry of an unknown kind (%d)' % tag)
        entries.append(e)
    ok = None
    if not stopped and password:
        body, digest = data[:pos], data[pos:pos + 20]
        want = hashlib.sha1(_java_pw(password) + b'Mighty Aphrodite' + body).digest()
        ok = want == digest
    return {'type': kind, 'entries': entries, 'ok': ok, 'notes': notes}


def _jks_unprotect(protected, password):
    """A private key out of a JKS/JCEKS entry -> PKCS#8 DER."""
    epki = A.parse(protected)
    alg = epki[0][0].oid()
    blob = epki[1].octets()
    if alg == JKS_KEY_OID:
        pw = _java_pw(password)
        salt, enc, check = blob[:20], blob[20:-20], blob[-20:]
        stream, digest = b'', salt
        while len(stream) < len(enc):
            digest = hashlib.sha1(pw + digest).digest()
            stream += digest
        plain = bytes(a ^ b for a, b in zip(enc, stream))
        if hashlib.sha1(pw + plain).digest() != check:
            raise PasswordError('the password of the key in the keystore is wrong')
        return plain
    if alg == JCEKS_KEY_OID:
        params = epki[0][1]
        salt, count = params[0].octets(), params[1].int()
        key, iv = _pbe_md5_3des_key(password, salt, count)
        try:
            plain = des3_cbc_decrypt(key, iv, blob)
        except ValueError:
            raise PasswordError('the password of the key in the keystore is wrong')
        try:
            A.parse(plain, strict=True)
        except A.Asn1Error:
            raise PasswordError('the password of the key in the keystore is wrong')
        return plain
    raise PkiError('a keystore key protected with %s, which acme does not read'
                   % A.oid_name(alg))


def _read_jks(data, password, got):
    try:
        ks = jks_parse(data, password)
    except (struct.error, IndexError, PkiError) as e:
        got.notes.append('a Java keystore that cannot be read: %s' % e)
        return
    got.formats.append(ks['type'])
    got.notes += ks['notes']
    if ks['ok'] is False:
        got.needs_password = True
        got.notes.append('the password of the keystore is wrong')
        return
    for e in ks['entries']:
        got.aliases.append(e['alias'])
        for c in e['certs']:
            got.cert(c)
        if e['kind'] == 'key':
            if not password:
                got.needs_password = True
                got.notes.append('the key "%s" needs the keystore\'s password' % e['alias'])
                continue
            try:
                der = _jks_unprotect(e['protected'], password)
            except PasswordError as ex:
                got.needs_password = True
                got.notes.append('%s (%s)' % (ex, e['alias']))
                continue
            got.key(pki.der_to_pem(der, 'PRIVATE KEY'))


def jks_write(key_pem, cert_pems, password, alias='1', trusted=None):
    """A JKS keystore with one private key entry (`alias`, the key with the
    certificate and its chain), plus [(alias, pem)] `trusted` entries.
    The key is protected with the store's password (as keytool does)."""
    if not password:
        raise PkiError('a JKS keystore needs a password')
    pw = _java_pw(password)
    ts = int(time.time() * 1000)
    entries = []
    if key_pem:
        plain = pki.key_der(key_pem)
        salt = secrets.token_bytes(20)
        stream, digest = b'', salt
        while len(stream) < len(plain):
            digest = hashlib.sha1(pw + digest).digest()
            stream += digest
        enc = bytes(a ^ b for a, b in zip(plain, stream))
        check = hashlib.sha1(pw + plain).digest()
        protected = A.seq(A.seq(A.oid(JKS_KEY_OID), A.null()), A.octets(salt + enc + check))
        body = struct.pack('>I', 1) + _encode_mutf8(str(alias).lower()) + struct.pack('>Q', ts)
        body += struct.pack('>I', len(protected)) + protected
        certs = [pki.pem_to_der(pki.cert_pem(c)) for c in cert_pems]
        body += struct.pack('>I', len(certs))
        for der in certs:
            body += _encode_mutf8('X.509') + struct.pack('>I', len(der)) + der
        entries.append(body)
    for t_alias, t_pem in trusted or []:
        der = pki.pem_to_der(pki.cert_pem(t_pem))
        entries.append(struct.pack('>I', 2) + _encode_mutf8(str(t_alias).lower()) +
                       struct.pack('>Q', ts) + _encode_mutf8('X.509') +
                       struct.pack('>I', len(der)) + der)
    data = struct.pack('>III', JKS_MAGIC, 2, len(entries)) + b''.join(entries)
    return data + hashlib.sha1(pw + b'Mighty Aphrodite' + data).digest()


def _pbe_md5_3des_key(password, salt, count):
    """Sun's PBEWithMD5AndTripleDES key and IV (com.sun.crypto.provider.PBES1Core)."""
    salt = bytearray(salt)
    if salt[0:4] == salt[4:8]:
        # Sun's own code, its slip (salt[3-1]) kept: what Java does is what decrypts.
        for i in range(2):
            tmp = salt[i]
            salt[i] = salt[3 - i]
            salt[2] = tmp
    pw = bytes(ord(c) & 0xff for c in str(password or ''))
    out = b''
    for i in range(2):
        h = bytes(salt[i * 4:(i + 1) * 4])
        for _ in range(count):
            h = hashlib.md5(h + pw).digest()
        out += h
    return out[:24], out[24:32]


# ---------------------------------------------------------------------------
# DES / 3DES (for JCEKS only - the standard library has none)
# ---------------------------------------------------------------------------
_IP = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22,
       14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27,
       19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)
_FP = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22,
       62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11,
       51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)
_E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16,
      17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)
_P = (16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
      19, 13, 30, 6, 22, 11, 4, 25)
_PC1 = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19,
        11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
        61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
_PC2 = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13,
        2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50,
        36, 29, 32)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_S = (
    (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
     11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
     1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
     10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
     4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
     14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
     9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
     12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
     13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
     10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
     2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
     14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
     15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
     12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
     10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
     11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
     8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
)


def _perm(v, table, nbits):
    out = 0
    for p in table:
        out = (out << 1) | ((v >> (nbits - p)) & 1)
    return out


def _des_subkeys(key8):
    k = _perm(int.from_bytes(key8, 'big'), _PC1, 64)
    c, d = k >> 28, k & 0xfffffff
    subs = []
    for s in _SHIFTS:
        c = ((c << s) | (c >> (28 - s))) & 0xfffffff
        d = ((d << s) | (d >> (28 - s))) & 0xfffffff
        subs.append(_perm((c << 28) | d, _PC2, 56))
    return subs


def _des_block(block, subs):
    v = _perm(int.from_bytes(block, 'big'), _IP, 64)
    left, right = v >> 32, v & 0xffffffff
    for k in subs:
        x = _perm(right, _E, 32) ^ k
        s_out = 0
        for i in range(8):
            six = (x >> (42 - 6 * i)) & 0x3f
            row = ((six >> 4) & 2) | (six & 1)
            col = (six >> 1) & 0xf
            s_out = (s_out << 4) | _S[i][row * 16 + col]
        left, right = right, left ^ _perm(s_out, _P, 32)
    return _perm((right << 32) | left, _FP, 64).to_bytes(8, 'big')


def des3_cbc_decrypt(key24, iv, data):
    """Triple DES (EDE, three keys) in CBC, PKCS#5 padding taken off."""
    if len(data) % 8 or not data:
        raise ValueError('not a whole number of blocks')
    k1, k2, k3 = (_des_subkeys(key24[i:i + 8]) for i in (0, 8, 16))
    d1, d3 = list(reversed(k1)), list(reversed(k3))
    out, prev = bytearray(), bytes(iv)
    for i in range(0, len(data), 8):
        blk = data[i:i + 8]
        p = _des_block(_des_block(_des_block(blk, d3), k2), d1)
        out += bytes(a ^ b for a, b in zip(p, prev))
        prev = blk
    pad = out[-1]
    if not 1 <= pad <= 8 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError('bad padding')
    return bytes(out[:-pad])


def des3_cbc_encrypt(key24, iv, data):
    k1, k2, k3 = (_des_subkeys(key24[i:i + 8]) for i in (0, 8, 16))
    d2 = list(reversed(k2))
    pad = 8 - len(data) % 8
    data = bytes(data) + bytes([pad]) * pad
    out, prev = bytearray(), bytes(iv)
    for i in range(0, len(data), 8):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 8], prev))
        c = _des_block(_des_block(_des_block(blk, k1), d2), k3)
        out += c
        prev = c
    return bytes(out)
