# -*- coding: utf-8 -*-
"""
A certificate as a target gets it: CertBundle, the real acmelib.plugins.base.Bundle.

    b = CertBundle(name, cert_pem, key_pem, chain_pems, names=None)
    b.name b.names b.serial b.fingerprint (SHA-256, hex upper) b.not_before b.not_after
    b.cert_pem b.key_pem b.chain_pems b.fullchain_pem
    b.as_format(fmt, password=None, alias=None) -> bytes

The formats (Bundle.FORMATS, and a few more):

    cert-pem cert-der            the certificate
    key-pem                      the key, PKCS#8 PEM (never encrypted - see key-pem-enc)
    key-rsa                      PKCS#1 (BEGIN RSA PRIVATE KEY) - RSA keys only
    key-der                      PKCS#8 DER
    key-pem-enc                  PKCS#8 PEM encrypted (AES-256, PBKDF2) with `password`
    key-traditional              PKCS#1 for RSA, SEC1 for EC
    chain-pem fullchain-pem      the chain; the certificate and the chain
    combined-pem                 the key, then the certificate and the chain (HAProxy, ...)
    p7b / p7b-pem                PKCS#7, certificates only (DER - as Windows writes it - / PEM)
    pfx p12                      PKCS#12, AES-256-CBC, PBKDF2, MAC SHA-256 (OpenSSL 3 default)
    p12-legacy                   PKCS#12, 3DES (PBE-SHA1-3DES) and MAC SHA-1, for old devices
                                 (Windows Server 2016 and older, old Java, appliances)
    jks                          a Java keystore (written in Python), password required

The password of `password`; the alias (friendly name) `alias`, else the
bundle's name.
"""
from __future__ import annotations

import os
import re

from acmelib.certs import asn1 as A
from acmelib.certs import formats, pki
from acmelib.certs.pki import PkiError
from acmelib.plugins.base import Bundle

EXTRA_FORMATS = ('key-pem-enc', 'key-traditional', 'p7b-pem')

MIME = {'cert-pem': 'application/x-pem-file', 'cert-der': 'application/pkix-cert',
        'key-pem': 'application/x-pem-file', 'key-rsa': 'application/x-pem-file',
        'key-der': 'application/octet-stream', 'key-pem-enc': 'application/x-pem-file',
        'key-traditional': 'application/x-pem-file', 'chain-pem': 'application/x-pem-file',
        'fullchain-pem': 'application/x-pem-file', 'combined-pem': 'application/x-pem-file',
        'p7b': 'application/x-pkcs7-certificates', 'p7b-pem': 'application/x-pkcs7-certificates',
        'pfx': 'application/x-pkcs12', 'p12': 'application/x-pkcs12',
        'p12-legacy': 'application/x-pkcs12', 'jks': 'application/x-java-keystore'}

EXT = {'cert-pem': '.crt', 'cert-der': '.cer', 'key-pem': '.key', 'key-rsa': '.rsa.key',
       'key-der': '.key.der', 'key-pem-enc': '.enc.key', 'key-traditional': '.key',
       'chain-pem': '.chain.pem', 'fullchain-pem': '.fullchain.pem',
       'combined-pem': '.pem', 'p7b': '.p7b', 'p7b-pem': '.p7b', 'pfx': '.pfx',
       'p12': '.p12', 'p12-legacy': '.p12', 'jks': '.jks'}


def p7b_der(cert_pems):
    """A degenerate PKCS#7 SignedData holding only certificates (RFC 2315 / 5652)."""
    certs = b''.join(pki.pem_to_der(pki.cert_pem(c)) for c in cert_pems)
    signed = A.seq(A.integer(1), A.set_of(), A.seq(A.oid('1.2.840.113549.1.7.1')),
                   A.ctx(0, certs), A.set_of())
    return A.seq(A.oid('1.2.840.113549.1.7.2'), A.explicit(0, signed))


def pkcs12(key_pem, cert_pem, chain_pems, password, alias='', legacy=False):
    """PKCS#12 by openssl pkcs12 -export; the password only in the environment."""
    with pki.workdir() as d:
        args = ['pkcs12', '-export', '-inkey', pki.wfile(d, 'k.key', pki.key_plain(key_pem)),
                '-in', pki.wfile(d, 'c.pem', pki.cert_pem(cert_pem)),
                '-passout', 'env:' + pki.PASS_ENV_OUT]
        if chain_pems:
            args += ['-certfile', pki.wfile(d, 'chain.pem',
                                            ''.join(pki.cert_pem(c) for c in chain_pems))]
        if alias:
            args += ['-name', alias]
        if legacy:
            args += ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1']
        else:
            args += ['-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC', '-macalg', 'sha256']
        return pki.openssl(args, env={pki.PASS_ENV_OUT: password or ''})


class CertBundle(Bundle):
    FORMATS = Bundle.FORMATS + EXTRA_FORMATS

    def __init__(self, name, cert_pem, key_pem, chain_pems, names=None):
        self.name = str(name or '')
        self.cert_pem = pki.cert_pem(cert_pem)
        self.key_pem = pki.key_plain(key_pem) if key_pem else None
        chain = []
        for c in chain_pems or []:
            chain += pki.certs_in(c) if isinstance(c, str) and c.count('BEGIN') > 1 \
                else [pki.cert_pem(c)]
        self.chain_pems = chain
        self.info = pki.cert_info(self.cert_pem)
        self.names = list(names) if names else list(self.info['names'])
        self.serial = self.info['serial']
        self.fingerprint = self.info['sha256']
        self.not_before = self.info['not_before']
        self.not_after = self.info['not_after']
        self.fullchain_pem = self.cert_pem + ''.join(self.chain_pems)
        self.key_type = self.info['key_type']

    def __repr__(self):
        return '<CertBundle %s %s>' % (self.name, self.serial)

    @property
    def chain_pem(self):
        return ''.join(self.chain_pems)

    def _need_key(self, fmt):
        if not self.key_pem:
            raise PkiError('%s needs the private key, and there is none with this certificate'
                           % fmt)
        return self.key_pem

    def default_alias(self):
        a = re.sub(r'[^A-Za-z0-9._-]+', '-', self.name or (self.names[0] if self.names
                                                            else 'acme')).strip('-')
        return a or 'acme'

    def filename(self, fmt):
        base = re.sub(r'[^A-Za-z0-9._-]+', '_', self.name or self.info['cn'] or 'cert')
        return base.strip('_.') + EXT.get(fmt, '.bin')

    def as_format(self, fmt, password=None, alias=None):
        fmt = str(fmt or '').lower()
        if fmt == 'cert-pem':
            return self.cert_pem.encode('ascii')
        if fmt == 'cert-der':
            return pki.pem_to_der(self.cert_pem)
        if fmt == 'key-pem':
            return self._need_key(fmt).encode('ascii')
        if fmt == 'key-der':
            return pki.key_der(self._need_key(fmt))
        if fmt == 'key-rsa':
            if not self.key_type.startswith('rsa'):
                raise PkiError('key-rsa (PKCS#1) is only for RSA keys; this one is %s - take '
                               'key-pem' % self.key_type, retry=False)
            return pki.key_traditional(self._need_key(fmt)).encode('ascii')
        if fmt == 'key-traditional':
            return pki.key_traditional(self._need_key(fmt)).encode('ascii')
        if fmt == 'key-pem-enc':
            if not password:
                raise PkiError('an encrypted key needs a password')
            return pki.key_encrypt(self._need_key(fmt), password).encode('ascii')
        if fmt == 'chain-pem':
            return self.chain_pem.encode('ascii')
        if fmt == 'fullchain-pem':
            return self.fullchain_pem.encode('ascii')
        if fmt == 'combined-pem':
            return (self._need_key(fmt) + self.fullchain_pem).encode('ascii')
        if fmt == 'p7b':
            return p7b_der([self.cert_pem] + self.chain_pems)
        if fmt == 'p7b-pem':
            return pki.der_to_pem(p7b_der([self.cert_pem] + self.chain_pems),
                                  'PKCS7').encode('ascii')
        if fmt in ('pfx', 'p12', 'p12-legacy'):
            return pkcs12(self._need_key(fmt), self.cert_pem, self.chain_pems,
                          password or '', alias or self.default_alias(),
                          legacy=fmt == 'p12-legacy')
        if fmt == 'jks':
            if not password:
                raise PkiError('a Java keystore (jks) needs a password', retry=False)
            return formats.jks_write(self._need_key(fmt), [self.cert_pem] + self.chain_pems,
                                     password, alias or self.default_alias())
        raise PkiError('an unknown format: %s (one of %s)' % (fmt, ' '.join(self.FORMATS)),
                       retry=False)

    def write_files(self, folder, fmts, password=None, alias=None):
        """Every format of `fmts` into `folder` (0600) -> {fmt: path}. For tests and the CLI."""
        out = {}
        for fmt in fmts:
            path = os.path.join(folder, self.filename(fmt))
            pki.wfile(folder, os.path.basename(path), self.as_format(fmt, password, alias))
            out[fmt] = path
        return out
