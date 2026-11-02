# -*- coding: utf-8 -*-
"""
Show a certificate (1.0.23): whatever is given - a file or pasted text - read
and described in full, for the viewer of the pages (web/assets/certview.js).
Nothing is kept, nothing is contacted; a private key is never sent back.

    describe(data, filename='', password='', key_password='') -> dict

What is read (formats.py reads the same for an import; this keeps where each
piece came from - its alias, its entry - and reads what an import leaves out):

    PEM      any number of blocks: CERTIFICATE, TRUSTED CERTIFICATE, CERTIFICATE
             REQUEST / NEW CERTIFICATE REQUEST, PKCS7 / CMS, X509 CRL, PRIVATE KEY,
             RSA / EC / DSA PRIVATE KEY (also the old encrypted ones), ENCRYPTED
             PRIVATE KEY, PUBLIC KEY, RSA PUBLIC KEY
    DER      a certificate, a CSR, a CRL, PKCS#7, PKCS#8 (plain or encrypted),
             PKCS#1, SEC1, a SubjectPublicKeyInfo
    PKCS#7   .p7b / .p7c - the certificates and CRLs in it
    PKCS#12  .pfx / .p12, also a Java PKCS12 keystore - modern (AES, PBKDF2) and
             legacy (RC2, 3DES: openssl -legacy); its bags, their friendlyName
    JKS      Java keystores, read here in Python (formats.jks_parse): the
    JCEKS    entries, their certificates without a password, the integrity check
             and the keys with it
    base64 without the PEM lines around it, of any of these; a ZIP of them

The answer:

    {'format', 'format_words', 'size', 'now',
     'password': {'needed', 'wrong', 'words'},
     'container': {...what the file itself is: its MAC, its encryption, entries},
     'notes': [words],
     'things': [{'id': 'c1' | 'r1' | 'l1' | 'k1' | 'p1', 'kind': 'cert' | 'csr' |
                 'crl' | 'key' | 'pubkey', ...}],
     'entries': [{'alias', 'kind': 'key' | 'cert' | 'secret', 'created', 'items': [ids]}],
     'chains': [{'items': [ids, leaf first], 'links': [{'child', 'parent', 'ok',
                 'words'}], 'top': {...}}]}
"""
from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import struct
import subprocess
import threading
import time
import zipfile

from acmelib.certs import asn1 as A
from acmelib.certs import formats as F
from acmelib.certs import pki
from acmelib.certs.pki import PkiError, PasswordError

MAX_THINGS = 400            # certificates and the rest, in one file
MAX_LINKS = 60              # links whose signature is checked (an openssl each)
CRL_SHOWN = 50              # entries of a CRL sent
MAX_OPENSSL = 80            # other openssl runs (a key read, a CSR's or a CRL's signature)
MAX_UNZIPPED = 40 * 1024 * 1024     # what all the members of a ZIP may hold together

TRUST_STORES = ('/etc/ssl/certs/ca-certificates.crt',           # Debian, Ubuntu
                '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',  # RHEL, Fedora
                '/etc/pki/tls/certs/ca-bundle.crt',
                '/etc/ssl/ca-bundle.pem',                        # SUSE
                '/etc/ssl/cert.pem')                             # Alpine, BSD

EXT_NAMES = {
    '2.5.29.16': 'privateKeyUsagePeriod', '2.5.29.33': 'policyMappings',
    '2.5.29.36': 'policyConstraints', '2.5.29.46': 'freshestCRL', '2.5.29.54': 'inhibitAnyPolicy',
    '2.5.29.9': 'subjectDirectoryAttributes', '1.3.6.1.5.5.7.1.3': 'qcStatements',
    '1.3.6.1.5.5.7.1.11': 'subjectInfoAccess', '1.3.6.1.5.5.7.48.1.5': 'ocspNoCheck',
    '1.3.6.1.4.1.311.21.10': 'msApplicationPolicies', '1.3.6.1.4.1.311.21.1': 'msCAVersion',
    '1.3.6.1.4.1.311.21.2': 'msPreviousCAHash', '2.16.840.1.113730.1.1': 'netscapeCertType',
    '2.16.840.1.113730.1.13': 'netscapeComment', '1.3.6.1.4.1.311.20.2': 'msCertificateTemplateName',
    '1.3.6.1.4.1.311.21.7': 'msCertificateTemplate', '1.3.6.1.4.1.11129.2.4.3': 'ct_precert_poison',
}
POLICY_NAMES = {
    '2.23.140.1.2.1': 'Domain validated (DV)', '2.23.140.1.2.2': 'Organization validated (OV)',
    '2.23.140.1.2.3': 'Individual validated (IV)', '2.23.140.1.1': 'Extended validation (EV)',
    '2.23.140.1.3': 'EV code signing', '2.23.140.1.4.1': 'Code signing',
    '2.23.140.1.4.2': 'Code signing (time stamping)',
    '2.23.140.1.5.1.1': 'S/MIME mailbox validated', '2.23.140.1.5.2.1': 'S/MIME organization validated',
    '2.23.140.1.5.3.1': 'S/MIME sponsor validated', '2.23.140.1.5.4.1': 'S/MIME individual validated',
    '2.5.29.32.0': 'Any policy', '1.3.6.1.4.1.44947.1.1.1': 'ISRG domain validation (Let\'s Encrypt)',
}
EKU_MORE = {'1.3.6.1.4.1.311.10.3.12': 'msDocumentSigning', '1.3.6.1.4.1.311.10.3.1': 'msCTLSign',
            '1.3.6.1.4.1.311.10.3.3': 'msSGC', '2.16.840.1.113730.4.1': 'nsSGC',
            '1.3.6.1.4.1.311.2.1.21': 'msCodeInd', '1.3.6.1.4.1.311.2.1.22': 'msCodeCom',
            '1.3.6.1.5.5.7.3.36': 'documentSigning', '1.3.6.1.4.1.311.80.1': 'msDocumentEncryption'}


def _oid_name(o, more=None):
    if more and o in more:
        return more[o]
    return EXT_NAMES.get(o) or A.oid_name(o)


# ---------------------------------------------------------------------------
# What was found, kept as it was found
# ---------------------------------------------------------------------------
class _Box(object):
    def __init__(self, password, key_password):
        self.password = password or ''
        self.key_password = key_password or ''
        self.things = []
        self.by_sha = {}
        self.entries = []
        self.notes = []
        self.formats = []
        self.container = {}
        self.need_pw = False
        self.wrong_pw = False
        self.pw_words = []
        self.counts = {'cert': 0, 'csr': 0, 'crl': 0, 'key': 0, 'pubkey': 0}
        self.runs = 0
        self.unzipped = 0

    def may_run(self):
        """One more openssl run, while there are not too many in one file."""
        self.runs += 1
        return self.runs <= MAX_OPENSSL

    def _id(self, kind):
        self.counts[kind] += 1
        return {'cert': 'c', 'csr': 'r', 'crl': 'l', 'key': 'k', 'pubkey': 'p'}[kind] + \
            str(self.counts[kind])

    def full(self):
        if len(self.things) >= MAX_THINGS:
            if not any('only the first' in n for n in self.notes):
                self.notes.append('only the first %d things of the file are shown' % MAX_THINGS)
            return True
        return False

    def cert(self, der_or_pem, alias=None, origin=None):
        if self.full():
            return None
        try:
            der = pki._cert_der(der_or_pem)
            sha = hashlib.sha256(der).hexdigest().upper()
            if sha in self.by_sha:
                t = self.by_sha[sha]
                if alias and alias not in t['aliases']:
                    t['aliases'].append(alias)
                return t['id']
            t = cert_detail(der)
        except (PkiError, A.Asn1Error, ValueError, IndexError) as e:
            self.notes.append('a certificate that cannot be read: %s' % e)
            return None
        t['id'] = self._id('cert')
        t['aliases'] = [alias] if alias else []
        if origin:
            t['origin'] = origin
        self.by_sha[sha] = t
        self.things.append(t)
        return t['id']

    def csr(self, der):
        if self.full():
            return None
        try:
            t = csr_detail(der, self.may_run())
        except (PkiError, A.Asn1Error, ValueError, IndexError) as e:
            self.notes.append('a certificate request that cannot be read: %s' % e)
            return None
        t['id'] = self._id('csr')
        self.things.append(t)
        return t['id']

    def crl(self, der):
        if self.full():
            return None
        try:
            t = crl_detail(der)
        except (PkiError, A.Asn1Error, ValueError, IndexError) as e:
            self.notes.append('a CRL that cannot be read: %s' % e)
            return None
        t['id'] = self._id('crl')
        self.things.append(t)
        return t['id']

    def pubkey(self, der):
        try:
            kt, bits, sha = pki.spki_info(A.parse(der))
        except (A.Asn1Error, IndexError, ValueError) as e:
            self.notes.append('a public key that cannot be read: %s' % e)
            return None
        t = {'kind': 'pubkey', 'id': self._id('pubkey'), 'key': _key_words(kt, bits, sha),
             'pub_sha256': sha}
        self.things.append(t)
        return t['id']

    def key(self, data, fmt, alias=None, password=None, cipher=None, encrypted=False,
            plain_der=None):
        """A private key: what it is, never itself. `data` PEM text or DER."""
        if self.full():
            return None
        t = {'kind': 'key', 'id': self._id('key'), 'format': fmt, 'encrypted': bool(encrypted),
             'cipher': cipher or '', 'alias': alias or '', 'readable': False, 'key': None,
             'pub_sha256': '', 'matches': []}
        if plain_der is None and not self.may_run():
            t['error'] = 'not read: too many keys in one file'
            self.things.append(t)
            return t['id']
        try:
            if plain_der is not None:
                plain = pki.der_to_pem(plain_der, 'PRIVATE KEY')
            else:
                pw = password if password is not None else self.password
                plain = pki.key_plain(data, pw or None)
            ki = pki.key_info(plain)
            plain = None
            t.update(readable=True, key=_key_words(ki['key_type'], ki['key_bits'],
                                                   ki['pub_sha256']),
                     pub_sha256=ki['pub_sha256'])
        except PasswordError as e:
            t['locked'] = 'wrong' if (password or self.password) else 'needed'
            self.need_pw = True
            if t['locked'] == 'wrong':
                self.wrong_pw = True
            self.pw_words.append(str(e).replace('openssl pkey: ', ''))
        except PkiError as e:
            t['error'] = str(e)
        self.things.append(t)
        return t['id']


def _key_words(kt, bits, sha):
    kt = str(kt or '')
    if kt.startswith('rsa-pss'):
        algo, curve = 'RSA-PSS', ''
    elif kt.startswith('rsa'):
        algo, curve = 'RSA', ''
    elif kt.startswith('ec-'):
        algo = 'EC'
        curve = {'ec-256': 'P-256', 'ec-384': 'P-384', 'ec-521': 'P-521',
                 'ec-secp256k1': 'secp256k1'}.get(kt, kt[3:])
    elif kt.startswith('dsa'):
        algo, curve = 'DSA', ''
    elif kt in ('ed25519', 'ed448'):
        algo, curve = kt.capitalize(), ''
    else:
        algo, curve = kt, ''
    return {'type': kt, 'algo': algo, 'bits': bits or 0, 'curve': curve, 'spki_sha256': sha}


# ---------------------------------------------------------------------------
# A certificate, a request, a CRL - in full
# ---------------------------------------------------------------------------
def _gn_list(node):
    return [[t, v] for t, v in pki._general_names(node)]


def _sct_list(octets):
    """The SCTs of the CT extension (RFC 6962 §3.3): [{version, log_id, ts, hash, sig}]."""
    out = []
    raw = A.parse(octets).content if octets[:1] == b'\x04' else octets
    if len(raw) < 2:
        return out
    (total,) = struct.unpack('>H', raw[:2])
    pos, end = 2, min(len(raw), 2 + total)
    while pos + 2 <= end:
        (n,) = struct.unpack('>H', raw[pos:pos + 2])
        s = raw[pos + 2:pos + 2 + n]
        pos += 2 + n
        if len(s) < 43:
            continue
        ver, log_id, (ts,) = s[0], s[1:33], struct.unpack('>Q', s[33:41])
        (el,) = struct.unpack('>H', s[41:43])
        p = 43 + el
        hash_alg = {4: 'SHA-256', 5: 'SHA-384', 6: 'SHA-512'}.get(s[p] if p < len(s) else -1, '')
        sig_alg = {1: 'RSA', 3: 'ECDSA'}.get(s[p + 1] if p + 1 < len(s) else -1, '')
        out.append({'version': ver + 1, 'log_id': base64.b64encode(log_id).decode('ascii'),
                    'log_id_hex': log_id.hex().upper(), 'ts': ts // 1000,
                    'sig': ('%s %s' % (sig_alg, hash_alg)).strip()})
    return out


def _policies(v):
    out = []
    for pi in v:
        o = pi[0].oid()
        p = {'oid': o, 'name': POLICY_NAMES.get(o, ''), 'cps': [], 'notice': ''}
        if len(pi) > 1:
            for q in pi[1]:
                qo = q[0].oid()
                try:
                    if qo == '1.3.6.1.5.5.7.2.1':
                        p['cps'].append(q[1].text())
                    elif qo == '1.3.6.1.5.5.7.2.2':
                        for part in q[1]:
                            if not part.is_seq:
                                p['notice'] = part.text()
                except (A.Asn1Error, IndexError):
                    continue
        out.append(p)
    return out


def decode_extension(ext):
    """One Extension: {oid, name, critical, kind, value, hex?}."""
    o = ext[0].oid()
    crit = len(ext) > 2 and ext[1].is_(A.BOOLEAN) and ext[1].bool()
    raw = ext[len(ext) - 1].content
    out = {'oid': o, 'name': _oid_name(o), 'critical': bool(crit), 'kind': 'other',
           'value': None}
    try:
        v = A.parse(raw) if raw else None
        base = pki.parse_extensions([ext])
        if o in ('2.5.29.17', '2.5.29.18'):
            out['kind'], out['value'] = 'names', _gn_list(v)
        elif o == '2.5.29.15':
            out['kind'], out['value'] = 'list', base['key_usage']
        elif o == '2.5.29.37':
            out['kind'] = 'eku'
            out['value'] = [{'oid': x.oid(), 'name': _oid_name(x.oid(), EKU_MORE)} for x in v]
        elif o == '2.5.29.19':
            out['kind'], out['value'] = 'basic', {'ca': base['is_ca'], 'path_len': base['path_len']}
        elif o == '2.5.29.30':
            out['kind'], out['value'] = 'constraints', base['name_constraints']
        elif o == '2.5.29.32':
            out['kind'], out['value'] = 'policies', _policies(v)
        elif o in ('2.5.29.31', '2.5.29.46'):
            urls, other = [], []
            for dp in v:
                for part in dp:
                    if part.is_ctx(0):
                        for full in part:
                            if full.is_ctx(0):
                                for t, val in pki._general_names(full):
                                    (urls if t == 'URI' else other).append(
                                        val if t == 'URI' else '%s:%s' % (t, val))
            out['kind'], out['value'] = 'urls', {'urls': urls, 'other': other}
        elif o in ('1.3.6.1.5.5.7.1.1', '1.3.6.1.5.5.7.1.11'):
            got = {'ocsp': [], 'ca_issuers': [], 'other': []}
            for ad in v:
                m = ad[0].oid()
                locs = ['%s' % val if t == 'URI' else '%s:%s' % (t, val)
                        for t, val in pki._general_names([ad[1]])]
                key = {'1.3.6.1.5.5.7.48.1': 'ocsp', '1.3.6.1.5.5.7.48.2': 'ca_issuers'}.get(m)
                if key:
                    got[key] += locs
                else:
                    got['other'] += ['%s %s' % (_oid_name(m), x) for x in locs]
            out['kind'], out['value'] = 'aia', got
        elif o == '2.5.29.14':
            out['kind'], out['value'] = 'hex', base['ski']
        elif o == '2.5.29.35':
            got = {'key_id': '', 'issuer': [], 'serial': ''}
            for x in v:
                if x.is_ctx(0):
                    got['key_id'] = x.content.hex().upper()
                elif x.is_ctx(1):
                    got['issuer'] = _gn_list(x)
                elif x.is_ctx(2):
                    got['serial'] = pki.serial_hex(x.content.lstrip(b'\x00') or b'\x00')
            out['kind'], out['value'] = 'aki', got
        elif o == '1.3.6.1.4.1.11129.2.4.2':
            out['kind'], out['value'] = 'scts', _sct_list(v.content if v is not None else b'')
        elif o == '1.3.6.1.4.1.11129.2.4.3':
            out['kind'], out['value'] = 'flag', 'precertificate'
        elif o == '1.3.6.1.5.5.7.1.24':
            feats = [{5: 'status_request', 17: 'status_request_v2'}.get(x.int(), str(x.int()))
                     for x in v if x.is_(A.INTEGER)]
            out['kind'], out['value'] = 'list', feats
        elif o == '1.3.6.1.5.5.7.48.1.5':
            out['kind'], out['value'] = 'flag', 'ocspNoCheck'
        elif o == '2.5.29.54':
            out['kind'], out['value'] = 'number', v.int()
        elif o == '1.3.6.1.4.1.311.20.2':
            out['kind'], out['value'] = 'text', v.text()
        elif o == '2.16.840.1.113730.1.13':
            out['kind'], out['value'] = 'text', v.text()
        elif o == '1.3.6.1.4.1.311.21.7':
            out['kind'] = 'template'
            out['value'] = {'oid': v[0].oid(), 'major': v[1].int() if len(v) > 1 else None,
                            'minor': v[2].int() if len(v) > 2 else None}
    except (A.Asn1Error, IndexError, ValueError, struct.error):
        out['kind'], out['value'] = 'other', None
        out['unreadable'] = True
    if out['kind'] == 'other':
        out['hex'] = raw[:1024].hex().upper()
        out['length'] = len(raw)
    return out


def _rdns(pairs):
    return [[k, v] for k, v in pairs]


def _issuer_pairs(node):
    return pki.parse_name(node)[2]


def cert_detail(der):
    """Everything a certificate says, JSON-able."""
    info = pki.cert_info(der)
    cert = A.parse(der)
    tbs = cert[0]
    i = 1 if tbs[0].is_ctx(0) else 0
    exts = []
    for x in tbs.children[i + 6:]:
        if x.is_ctx(3):
            exts = [decode_extension(e) for e in x[0]]
    spki = tbs[i + 5]
    key = _key_words(info['key_type'], info['key_bits'], info['pub_sha256'])
    if key['algo'] == 'RSA':
        try:
            key['exponent'] = A.parse(spki[1].bits())[1].int()
        except (A.Asn1Error, IndexError):
            pass
    serial_hex = info['serial']
    if info['is_ca']:
        role = 'root' if info['self_signed'] else 'intermediate'
    else:
        role = 'self-signed' if info['self_signed'] else 'leaf'
    return {
        'kind': 'cert', 'cn': info['cn'], 'subject_dn': info['subject_dn'],
        'subject': _rdns(info['subject_list']), 'issuer_dn': info['issuer_dn'],
        'issuer': _rdns(_issuer_pairs(tbs[i + 2])), 'issuer_cn': info['issuer'].get('CN', ''),
        'serial': serial_hex, 'serial_dec': str(int(serial_hex, 16)) if serial_hex else '',
        'version': info['version'], 'sig_alg': info['sig_alg'],
        'not_before': info['not_before'], 'not_after': info['not_after'],
        'key': key, 'sha256': info['sha256'], 'sha1': info['sha1'],
        'is_ca': info['is_ca'], 'path_len': info['path_len'], 'self_signed': info['self_signed'],
        'role': role, 'names': [[t, v] for t, v in info['san']], 'eku': info['eku'],
        'key_usage': info['key_usage'], 'ski': info['ski'], 'aki': info['aki'],
        'must_staple': info['must_staple'], 'ocsp': info['ocsp'], 'crl': info['crl'],
        'ca_issuers': info['ca_issuers'], 'extensions': exts, 'pem': info['pem'],
        'size': len(der), '_subject_der': info['subject_der'], '_issuer_der': info['issuer_der'],
        '_pub': info['pub_sha256'],
    }


def csr_detail(der, check=True):
    info = pki.csr_info(der)
    req = A.parse(der)
    cri = req[0]
    exts, attrs = [], []
    for x in cri.children[3:]:
        if x.is_ctx(0):
            for attr in (x.children if x.constructed else A.parse_all(x.content)):
                o = attr[0].oid()
                if o == '1.2.840.113549.1.9.14':
                    exts = [decode_extension(e) for e in attr[1][0]]
                elif o == '1.2.840.113549.1.9.7':
                    pass        # the challenge password: only that there is one
                else:
                    val = ''
                    try:
                        val = attr[1][0].text()
                    except (A.Asn1Error, IndexError):
                        val = ''
                    attrs.append({'oid': o, 'name': A.oid_name(o), 'value': val})
    pem = info['pem']
    return {'kind': 'csr', 'cn': info['cn'], 'subject_dn': info['subject_dn'],
            'subject': _rdns(info['subject_list']), 'names': [[t, v] for t, v in info['san']],
            'key': _key_words(info['key_type'], info['key_bits'], info['pub_sha256']),
            'sig_alg': info['sig_alg'], 'signature_ok': pki.csr_verify(pem) if check else None,
            'challenge_password': info['challenge_password'], 'extensions': exts,
            'attributes': attrs, 'eku': info['eku'], 'key_usage': info['key_usage'],
            'must_staple': info['must_staple'], 'version': cri[0].int() + 1, 'pem': pem,
            'size': len(der), '_pub': info['pub_sha256']}


def crl_detail(der):
    info = pki.crl_info(der)
    crl = A.parse(der)
    tbs = crl[0]
    i = 1 if tbs[0].is_(A.INTEGER) else 0
    issuer_pairs = pki.parse_name(tbs[i + 1])[2]
    revoked = info['revoked']
    return {'kind': 'crl', 'issuer_dn': info['issuer_dn'], 'issuer': _rdns(issuer_pairs),
            'issuer_cn': dict(issuer_pairs).get('CN', ''), 'this_update': info['this_update'],
            'next_update': info['next_update'], 'number': None if info['number'] is None
            else str(info['number']), 'aki': info['aki'], 'sig_alg': info['sig_alg'],
            'version': info['version'], 'count': len(revoked), 'revoked': revoked[:CRL_SHOWN],
            'pem': pki.der_to_pem(der, 'X509 CRL'), 'size': len(der),
            '_issuer_der': tbs[i + 1].raw}


# ---------------------------------------------------------------------------
# Reading the file
# ---------------------------------------------------------------------------
_KEY_LABELS = ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY',
               'ENCRYPTED PRIVATE KEY')


def _epki_cipher(der):
    """The encryption of an EncryptedPrivateKeyInfo, as words."""
    try:
        n = A.parse(der)
        alg = n[0][0].oid()
        if alg == '1.2.840.113549.1.5.13':
            kdf, enc = n[0][1][0], n[0][1][1]
            words = '%s, %s' % (A.oid_name(kdf[0].oid()), A.oid_name(enc[0].oid()))
            try:
                words += ', %d iterations' % kdf[1][1].int()
            except (A.Asn1Error, IndexError):
                pass
            return 'PBES2, ' + words
        return A.oid_name(alg)
    except (A.Asn1Error, IndexError):
        return ''


def _read(data, filename, box, depth):
    if data[:4] == b'PK\x03\x04' and depth < 2:
        return _read_zip(data, box, depth)
    if len(data) >= 4 and struct.unpack('>I', data[:4])[0] in (F.JKS_MAGIC, F.JCEKS_MAGIC):
        return _read_jks(data, box)
    if b'-----BEGIN' in data:
        return _read_pem(data, box)
    if A.looks_like_der(data):
        return _read_der(data, box, filename)
    txt = re.sub(rb'\s+', b'', data)
    if txt and re.match(rb'^[A-Za-z0-9+/=_-]+$', txt) and len(txt) >= 32 and depth < 2:
        try:
            raw = base64.b64decode(txt.replace(b'-', b'+').replace(b'_', b'/') +
                                   b'=' * (-len(txt) % 4))
        except ValueError:
            raw = b''
        if raw:
            box.notes.append('base64 without PEM lines around it, read as what it holds')
            box.formats.append('base64')
            return _read(raw, filename, box, depth + 1)
    if data[:1] == b'\x30':
        try:
            A.parse(data)
            return _read_der(data, box, filename)
        except A.Asn1Error:
            pass
    box.notes.append('%s is none of the formats a certificate comes in' % (filename or 'this'))


def _read_zip(data, box, depth):
    box.formats.append('zip')
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        box.notes.append('a ZIP that cannot be opened: %s' % e)
        return
    members = [i for i in z.infolist() if not i.is_dir()][:F.MAX_ZIP_MEMBERS]
    box.container = {'type': 'zip', 'members': [i.filename for i in members][:50]}
    for info in members:
        base = info.filename.rsplit('/', 1)[-1]
        if base.startswith('.') or info.filename.startswith('__MACOSX/'):
            continue
        box.unzipped += info.file_size
        if box.unzipped > MAX_UNZIPPED:
            box.notes.append('the rest of the ZIP is not read: it holds too much')
            break
        if info.file_size > F.MAX_ZIP_MEMBER:
            box.notes.append('%s is too big to be read' % info.filename)
            continue
        try:
            body = z.read(info, pwd=box.password.encode('utf-8') if box.password else None)
        except RuntimeError:
            box.need_pw = True
            if box.password:
                box.wrong_pw = True
            box.pw_words.append('%s in the ZIP is encrypted' % info.filename)
            continue
        except (zipfile.BadZipFile, NotImplementedError, OSError) as e:
            box.notes.append('%s in the ZIP cannot be read: %s' % (info.filename, e))
            continue
        if body.strip():
            _read(body, base, box, depth + 1)


def _read_pem(data, box):
    blocks = pki.split_pem(data)
    if not blocks:
        box.notes.append('PEM lines without any block that could be read')
        return
    box.formats.append('pem')
    for label, pem in blocks:
        if label in ('CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'):
            box.cert(pem)
        elif label in ('CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'):
            box.csr(pki.pem_to_der(pem))
        elif label == 'X509 CRL':
            box.crl(pki.pem_to_der(pem))
        elif label in ('PKCS7', 'CMS'):
            _read_p7(pki.pem_to_der(pem), box)
        elif label == 'ENCRYPTED PRIVATE KEY':
            box.key(pem, 'PKCS#8, encrypted', encrypted=True,
                    cipher=_epki_cipher(pki.pem_to_der(pem)))
        elif label in _KEY_LABELS:
            enc = 'Proc-Type: 4,ENCRYPTED' in pem
            m = re.search(r'DEK-Info:\s*([^,\n]+)', pem)
            fmt = {'PRIVATE KEY': 'PKCS#8', 'RSA PRIVATE KEY': 'PKCS#1 (RSA)',
                   'EC PRIVATE KEY': 'SEC1 (EC)', 'DSA PRIVATE KEY': 'DSA'}[label]
            box.key(pem, fmt + (', encrypted (old PEM style)' if enc else ''), encrypted=enc,
                    cipher=m.group(1).strip() if m else '')
        elif label == 'PUBLIC KEY':
            box.pubkey(pki.pem_to_der(pem))
        elif label == 'RSA PUBLIC KEY':
            spki = A.seq(A.seq(A.oid('1.2.840.113549.1.1.1'), A.null()),
                         A.bitstring(pki.pem_to_der(pem)))
            box.pubkey(spki)
        elif label == 'OPENSSH PRIVATE KEY':
            box.notes.append('an OpenSSH private key: an SSH key, not one of a certificate')
        else:
            box.notes.append('a PEM block "%s" that is not shown' % label)


def _is_spki(n):
    try:
        ch = n.children
        return len(ch) == 2 and ch[0].is_seq and ch[0][0].is_(A.OID) and ch[1].is_(A.BIT_STRING)
    except (A.Asn1Error, IndexError):
        return False


def _read_der(data, box, filename):
    try:
        n = A.parse(data)
    except A.Asn1Error as e:
        box.notes.append('DER that cannot be read: %s' % e)
        return
    der = n.raw
    kind = F._classify_der(n)
    if kind is None and _is_spki(n):
        kind = 'spki'
    box.formats.append({'cert': 'der', 'pkcs8-encrypted': 'pkcs8'}.get(kind, kind or 'der'))
    if kind == 'cert':
        box.cert(der)
    elif kind == 'csr':
        box.csr(der)
    elif kind == 'crl':
        box.crl(der)
    elif kind == 'pkcs7':
        _read_p7(der, box)
    elif kind == 'pkcs12':
        _read_p12(der, box)
    elif kind == 'spki':
        box.pubkey(der)
    elif kind == 'pkcs8-encrypted':
        box.key(der, 'PKCS#8, encrypted (DER)', encrypted=True, cipher=_epki_cipher(der))
    elif kind in ('pkcs8', 'pkcs1', 'sec1'):
        box.key(der, {'pkcs8': 'PKCS#8 (DER)', 'pkcs1': 'PKCS#1 (RSA, DER)',
                      'sec1': 'SEC1 (EC, DER)'}[kind])
    else:
        box.notes.append('DER that is none of what a certificate comes in')


def _read_p7(der, box):
    try:
        ci = A.parse(der)
        if ci[0].oid() != '1.2.840.113549.1.7.2':
            box.notes.append('a PKCS#7 that is not signedData (%s)' % A.oid_name(ci[0].oid()))
            return
        sd = ci[1][0]
        certs = crls = signers = 0
        for part in sd.children[1:]:
            if part.is_ctx(0):
                for c in part:
                    if c.is_seq and box.cert(c.raw):
                        certs += 1
            elif part.is_ctx(1):
                for c in part:
                    if c.is_seq and box.crl(c.raw):
                        crls += 1
            elif part.is_set:
                signers = len(part)
        if not box.container:
            box.container = {'type': 'pkcs7', 'certs': certs, 'crls': crls, 'signers': signers}
        if 'pkcs7' not in box.formats:
            box.formats.append('pkcs7')
    except (A.Asn1Error, IndexError) as e:
        box.notes.append('a PKCS#7 that cannot be read: %s' % e)


def _p12_run(der, password, legacy):
    args = [pki.OPENSSL, 'pkcs12', '-info', '-nodes', '-passin', 'env:' + pki.PASS_ENV]
    if legacy:
        args.append('-legacy')
    env = dict(os.environ)
    env[pki.PASS_ENV] = password or ''
    try:
        p = subprocess.run(args, input=der, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=60, env=env, start_new_session=True)
    except FileNotFoundError:
        raise PkiError('the openssl program is not installed')
    except subprocess.TimeoutExpired:
        raise PkiError('openssl took longer than 60 seconds to open the PKCS#12 file')
    return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')


_P12_INFO = re.compile(r'^(MAC: .*|MAC length: .*|PKCS7 Encrypted data: .*|Shrouded Keybag: .*|'
                       r'PKCS7 Data|Certificate bag|Key bag|Safe Contents bag)$', re.M)


def _read_p12(der, box):
    box.formats.append('pkcs12')
    pw = box.password
    legacy = False
    rc, out, err = _p12_run(der, pw, False)
    low = err.lower()
    if rc != 0 and any(w in low for w in ('unsupported', 'rc2', 'legacy', 'fetch')) and \
            'mac verify' not in low:
        legacy = True
        rc, out, err = _p12_run(der, pw, True)
        low = err.lower()
    lines = _P12_INFO.findall(err)
    c = {'type': 'pkcs12', 'legacy': legacy, 'mac': '', 'cert_encryption': '',
         'key_encryption': '', 'bags': {}}
    for ln in lines:
        if ln.startswith('MAC: '):
            c['mac'] = ln[5:]
        elif ln.startswith('PKCS7 Encrypted data: '):
            c['cert_encryption'] = ln.split(': ', 1)[1]
        elif ln.startswith('Shrouded Keybag: '):
            c['key_encryption'] = ln.split(': ', 1)[1]
            c['bags']['key'] = c['bags'].get('key', 0) + 1
        elif ln == 'Certificate bag':
            c['bags']['cert'] = c['bags'].get('cert', 0) + 1
    box.container = c
    if rc != 0:
        if 'mac verify' in low or 'invalid password' in low or 'bad decrypt' in low:
            box.need_pw = True
            if pw:
                box.wrong_pw = True
                box.pw_words.append('the password of the PKCS#12 file is wrong')
            else:
                box.pw_words.append('the PKCS#12 file is locked: give its password')
            return
        box.notes.append('a PKCS#12 that cannot be read: %s' % pki._said(err))
        return
    # Each bag: its attributes (friendlyName, localKeyID, Java's trusted mark) above its PEM.
    pos = 0
    entries = {}
    for m in pki._PEM_RE.finditer(out):
        attrs = out[pos:m.start()]
        pos = m.end()
        fn = re.search(r'friendlyName:\s*(.+)', attrs)
        lk = re.search(r'localKeyID:\s*([0-9A-Fa-f ]+)', attrs)
        alias = fn.group(1).strip() if fn else ''
        local = lk.group(1).replace(' ', '').upper() if lk else ''
        trusted = '2.16.840.1.113894.746875.1.1' in attrs or 'Trusted key usage' in attrs
        label = m.group(1).strip()
        block = m.group(0)
        if label == 'CERTIFICATE':
            tid = box.cert(block, alias=alias or None)
            if tid:
                key = local or ('alias:' + alias if alias else 'cert:' + tid)
                e = entries.setdefault(key, {'alias': alias, 'kind': 'trusted' if trusted
                                             else 'cert', 'items': [], 'local_id': local})
                e['items'].append(tid)
        elif label.endswith('PRIVATE KEY'):
            kid = box.key(block, 'PKCS#12 bag', alias=alias or None, encrypted=True,
                          cipher=c['key_encryption'])
            key = local or ('alias:' + alias if alias else 'key:' + str(kid))
            e = entries.setdefault(key, {'alias': alias, 'kind': 'key', 'items': [],
                                         'local_id': local})
            e['kind'] = 'key'
            if kid:
                e['items'].insert(0, kid)
    box.entries += list(entries.values())


def _read_jks(data, box):
    try:
        ks = F.jks_parse(data, box.password)
    except (struct.error, IndexError, PkiError, ValueError) as e:
        box.notes.append('a Java keystore that cannot be read: %s' % e)
        return
    kind = ks['type']
    box.formats.append(kind)
    (version,) = struct.unpack('>I', data[4:8])
    box.container = {'type': kind, 'version': version, 'count': len(ks['entries']),
                     'integrity': ks['ok']}
    box.notes += ks['notes']
    if ks['ok'] is False:
        box.wrong_pw = True
        box.need_pw = True
        box.pw_words.append('the password of the keystore is wrong: its integrity check '
                            'does not pass (the certificates are shown, the keys are not read)')
    elif ks['ok'] is None and not box.password:
        box.need_pw = True
        box.pw_words.append('without the keystore\'s password its integrity cannot be checked '
                            'and its keys cannot be read; the certificates are shown')
    for e in ks['entries']:
        ent = {'alias': e['alias'], 'kind': {'cert': 'trusted'}.get(e['kind'], e['kind']),
               'created': int(e['ts'] // 1000) if e.get('ts') else None, 'items': []}
        if e['kind'] == 'key':
            cipher = ''
            try:
                cipher = A.oid_name(A.parse(e['protected'])[0][0].oid())
            except (A.Asn1Error, IndexError):
                pass
            plain = None
            locked = None
            if box.password and ks['ok'] is not False:
                tried = [p for p in (box.key_password, box.password) if p]
                for p in tried:
                    try:
                        plain = F._jks_unprotect(e['protected'], p)
                        break
                    except PasswordError:
                        locked = 'wrong'
                    except PkiError as ex:
                        box.notes.append('%s: %s' % (e['alias'], ex))
                        locked = None
                        break
            else:
                locked = 'needed'
            if plain is not None:
                kid = box.key(None, '%s entry' % kind.upper(), alias=e['alias'], encrypted=True,
                              cipher=cipher, plain_der=plain)
                plain = None
            else:
                kid = box._id('key')
                box.things.append({'kind': 'key', 'id': kid, 'format': '%s entry' % kind.upper(),
                                   'encrypted': True, 'cipher': cipher, 'alias': e['alias'],
                                   'readable': False, 'key': None, 'pub_sha256': '',
                                   'matches': [], 'locked': locked or 'needed'})
                if locked == 'wrong':
                    box.need_pw = True
                    box.wrong_pw = True
                    box.pw_words.append('the password of the key "%s" is wrong - give the key\'s '
                                        'own password if it has one' % e['alias'])
            ent['items'].append(kid)
        for der in e.get('certs') or []:
            cid = box.cert(der, alias=e['alias'])
            if cid:
                ent['items'].append(cid)
        box.entries.append(ent)


# ---------------------------------------------------------------------------
# The chains
# ---------------------------------------------------------------------------
_STORE = {'key': None, 'by_sha': {}, 'by_subject': {}, 'path': ''}
_STORE_LOCK = threading.Lock()


def trust_store():
    """The system's trusted roots (offline: the bundle file of the distribution)."""
    path = next((p for p in TRUST_STORES if os.path.isfile(p)), '')
    if not path:
        return _STORE
    try:
        st = os.stat(path)
    except OSError:
        return _STORE
    key = (path, st.st_mtime, st.st_size)
    with _STORE_LOCK:
        if _STORE['key'] == key:
            return _STORE
        by_sha, by_subject = {}, {}
        try:
            with open(path, 'rb') as f:
                text = f.read()
            for pem in pki.certs_in(text):
                try:
                    info = pki.cert_info(pem)
                except PkiError:
                    continue
                by_sha[info['sha256']] = info
                by_subject.setdefault(info['subject_der'], []).append(info)
        except OSError:
            pass
        _STORE.update(key=key, by_sha=by_sha, by_subject=by_subject, path=path)
        return _STORE


def _issued(child, parent):
    if child['_issuer_der'] != parent['_subject_der']:
        return False
    if child.get('aki') and parent.get('ski'):
        return child['aki'] == parent['ski']
    return True


def link_check(child_pem, parent_pem):
    """(ok, words): the child's signature made by the parent's key (and the parent
    may sign certificates) - openssl verify, times not looked at."""
    with pki.workdir() as d:
        c = pki.wfile(d, 'child.pem', child_pem)
        p = pki.wfile(d, 'parent.pem', parent_pem)
        try:
            pki.openssl(['verify', '-no-CApath', '-no-CAstore', '-partial_chain',
                         '-no_check_time', '-CAfile', p, c])
            return True, 'the signature is right'
        except PkiError as e:
            text = (e.detail or str(e)).replace(c, 'certificate')
            m = re.search(r'error \d+ at \d+ depth lookup: ?(.*)', text)
            return False, (m.group(1).strip() if m else pki._said(text))


def _chains(box):
    certs = [t for t in box.things if t['kind'] == 'cert' and t.get('origin') != 'store']
    by_id = {t['id']: t for t in certs}
    parent = {}
    for t in certs:
        if t['self_signed']:
            continue
        cands = [p for p in certs if p is not t and _issued(t, p)]
        cands.sort(key=lambda p: (bool(t['aki'] and p['ski'] == t['aki']), p['not_after']),
                   reverse=True)
        if cands:
            parent[t['id']] = cands[0]['id']
    issuers = set(parent.values())
    starts = [t['id'] for t in certs if t['id'] not in issuers]
    seen = set()
    chains = []
    checks = [0]

    def chain_from(start):
        items, links, cur = [start], [], start
        used = {start}
        while cur in parent and parent[cur] not in used:
            nxt = parent[cur]
            links.append(_link(by_id[cur], by_id[nxt], checks))
            items.append(nxt)
            used.add(nxt)
            cur = nxt
        seen.update(used)
        top = by_id[cur]
        return {'items': items, 'links': links, 'top': _top(top, box, checks, items, links)}

    for s in starts:
        chains.append(chain_from(s))
    for t in certs:                     # a loop (cross-signed both ways): each is a start
        if t['id'] not in seen:
            chains.append(chain_from(t['id']))
    # the longest first: the chain of the certificate before lone roots
    chains.sort(key=lambda c: -len(c['items']))
    return chains


def _link(child, parent, checks):
    if checks[0] >= MAX_LINKS:
        return {'child': child['id'], 'parent': parent['id'], 'ok': None,
                'words': 'not checked: too many in one file'}
    checks[0] += 1
    ok, words = link_check(child['pem'], parent['pem'])
    return {'child': child['id'], 'parent': parent['id'], 'ok': ok, 'words': words}


def _top(top, box, checks, items, links):
    store = trust_store()
    out = {'id': top['id'], 'self_signed': top['self_signed'], 'store': store['path'],
           'in_store': False, 'missing': ''}
    if top['self_signed']:
        if checks[0] < MAX_LINKS:
            checks[0] += 1
            ok, words = link_check(top['pem'], top['pem'])
            out['self_ok'], out['self_words'] = ok, words
        if top['sha256'] in store['by_sha']:
            out['in_store'] = True
        else:
            same = [s for s in store['by_subject'].get(top['_subject_der'], [])
                    if s['pub_sha256'] == top['_pub']]
            if same:
                out['in_store'] = True
                out['store_copy'] = True        # the same root, another copy of it
        return out
    out['missing'] = top['issuer_dn']
    # Its issuer among the system's roots: drawn as one more station, from the store.
    cands = [s for s in store['by_subject'].get(top['_issuer_der'], [])
             if not top['aki'] or not s['ski'] or s['ski'] == top['aki']]
    if cands:
        sid = box.cert(cands[0]['pem'], origin='store')
        if sid:
            anchor = next(t for t in box.things if t['id'] == sid)
            links.append(_link(top, anchor, checks))
            items.append(sid)
            out.update(id=sid, self_signed=anchor['self_signed'], in_store=True, missing='',
                       added_from_store=True)
    return out


def _finish(box, data, filename):
    certs = [t for t in box.things if t['kind'] == 'cert']
    for k in box.things:
        if k['kind'] in ('key', 'pubkey') and k.get('pub_sha256'):
            k['matches'] = [c['id'] for c in certs if c['_pub'] == k['pub_sha256']]
            for c in certs:
                if c['_pub'] == k['pub_sha256']:
                    c.setdefault('keys', []).append(k['id'])
    for r in box.things:
        if r['kind'] == 'csr':
            r['matches'] = [c['id'] for c in certs if c['_pub'] == r['_pub']]
    for l in box.things:
        if l['kind'] != 'crl':
            continue
        iss = [c for c in certs if c['_subject_der'] == l['_issuer_der']
               and (not l['aki'] or not c['ski'] or c['ski'] == l['aki'])]
        if iss:
            l['issuer_id'] = iss[0]['id']
            l['signature_ok'] = _crl_ok(l['pem'], iss[0]['pem']) if box.may_run() else None
    chains = _chains(box) if certs else []
    for t in box.things:
        for k in [k for k in t if k.startswith('_')]:
            del t[k]
    fmt = box.formats[0] if box.formats else 'unknown'
    if fmt == 'base64' and len(box.formats) > 1:
        fmt = box.formats[1]
    if fmt in ('pem', 'der') and box.container.get('type') == 'pkcs7':
        fmt = 'pkcs7'
    pw_words = []
    for w in box.pw_words:
        if w not in pw_words:
            pw_words.append(w)
    return {'format': fmt, 'formats': sorted(set(box.formats)), 'filename': filename or '',
            'size': len(data), 'now': int(time.time()),
            'password': {'needed': box.need_pw, 'wrong': box.wrong_pw, 'words': pw_words},
            'container': box.container, 'notes': box.notes, 'things': box.things,
            'entries': box.entries, 'chains': chains}


def _crl_ok(crl_pem, issuer_pem):
    with pki.workdir() as d:
        c = pki.wfile(d, 'crl.pem', crl_pem)
        p = pki.wfile(d, 'ca.pem', issuer_pem)
        try:
            pki.openssl(['crl', '-in', c, '-CAfile', p, '-noout'])
            return True
        except PkiError:
            return False


def describe(data, filename='', password='', key_password=''):
    """See the module's documentation."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    data = bytes(data or b'')
    if not data.strip():
        raise PkiError('nothing was given: drop a file or paste its text')
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            data = data.decode('utf-16').encode('utf-8')
        except UnicodeError:
            pass
    box = _Box(password, key_password)
    _read(data, filename or '', box, 0)
    if not box.things and not box.need_pw:
        raise PkiError('%s holds no certificate, request, CRL or key that can be read%s' % (
            filename or 'this', (': ' + '; '.join(box.notes)) if box.notes else ''))
    return _finish(box, data, filename)
