# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# What is kept, and how it is asked for
# ---------------------------------------------------------------------------
def secret_shown(value, last=True):
    """A secret as the page may see it: dots and its last two characters, so
    that "the one I set" can be told from "something else". Only a full
    administrator is ever given this (the routes give everybody else dots
    alone); `last=False` for what leaves the pages - an export without its
    secrets carries dots only (1.0.101)."""
    said = str(value or '')
    if not said:
        return ''
    if not last:
        return '••••••••'
    # Always eight dots (1.0.207): as many as the secret was long told its length.
    return '•' * 8 + said[-2:] if len(said) > 4 else '•' * 8


def is_masked(value):
    return isinstance(value, str) and value.startswith('•')


def norm_name(name):
    return str(name or '').strip().lower()[:190]


PLAIN_ADDR_RE = re.compile(r'^[0-9A-Fa-f:.]+(/[0-9]{1,3})?\Z')


def plain_ip(text, how='network'):
    """An address, a network or an address with its prefix, and nothing else
    (1.0.57): ipaddress keeps an IPv6 scope id (fe80::1%eth0) with any
    character in it - newlines and braces too - which then went on into the
    files root writes (nginx, keepalived, ip6tables)."""
    said = str(text or '').strip()
    if not PLAIN_ADDR_RE.match(said):
        raise ValueError('%r is not a plain address' % said[:60])
    got = {'address': ipaddress.ip_address, 'interface': ipaddress.ip_interface,
           'network': lambda t: ipaddress.ip_network(t, strict=False)}[how](said)
    if '%' in str(got):
        raise ValueError('a scope id is not taken')
    return got


def address_net(text):
    """An address or a range of them, as a network - ValueError if neither."""
    said = str(text or '').strip()
    if not said:
        raise ValueError('an address is needed')
    return plain_ip(said, 'network')



