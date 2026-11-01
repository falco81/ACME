# -*- coding: utf-8 -*-
"""
The little of a certificate some targets need to know without openssl: its
issuer and subject as DER, so a root (self-signed) can be told from an
intermediate (not a module: the registry skips "_" files).

    names_of(pem) -> (issuer DER, subject DER)
    is_root(pem)  -> True when the issuer is the subject
    split_chain(bundle, root_pem='') -> (intermediates, root or None)
"""
from __future__ import annotations

from acmelib.plugins.targets._common import pem_to_der, chain_list, pem_blocks, text


def _tlv(der, i):
    """(tag, start of the value, end of the value) of the element at i."""
    tag = der[i]
    n = der[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(der[j:j + k], 'big')
        j += k
    return tag, j, j + n


def names_of(pem):
    der = pem_to_der(pem)
    _, s, _ = _tlv(der, 0)              # Certificate
    _, t, t_end = _tlv(der, s)           # tbsCertificate
    i = t
    out = []
    while i < t_end:
        tag, v, end = _tlv(der, i)
        out.append(der[i:end])
        i = end
    if out and out[0][0] == 0xa0:       # [0] version
        out = out[1:]
    # serial, signature, issuer, validity, subject
    return out[2], out[4]


def is_root(pem):
    try:
        issuer, subject = names_of(pem)
    except (IndexError, ValueError, Exception):     # noqa: BLE001
        return False
    return issuer == subject


def split_chain(bundle, root_pem=''):
    """The intermediates of the bundle, and the root: the one given, or the
    chain's last when it is self-signed, or None."""
    chain = chain_list(bundle)
    root = None
    given = pem_blocks(text(root_pem))
    if given:
        root = given[0]
    if chain and is_root(chain[-1]):
        last = chain.pop()
        root = root or last
    return chain, root
