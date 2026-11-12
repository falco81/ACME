# -*- coding: utf-8 -*-
"""
Small things the VMware targets share - not a module: the registry skips "_" files.

    vi_about(t, release)     the "about" of a vCenter or ESX (VI JSON API, no sign-in)
    parse_version(s)         '8.0.3' / '9.1.1.0' -> (8, 0, 3) / (9, 1, 1); None when it is not one
    version_words(v)         (8, 0, 3) -> '8.0.3'
    pem_body(pem)            the base64 of the first certificate of a PEM, one line
    has_cert(raw, bundle)    whether an answer (JSON, PEM, escaped) holds the bundle's certificate
    root_of(bundle, pem)     the root the chain ends in: the one given, else the last of the chain
                             when it signs itself, else ''
    intermediates(bundle)    the chain without its root
    wait_task(...)           asks a task until it says it is done (or failed), a while at most

The VI JSON API (vCenter 8.0 U1 and later): GET /sdk/vim25/<release>/ServiceInstance/
ServiceInstance/content needs no sign-in and says "about": {"version", "build", "apiVersion"}
(developer.broadcom.com, virtual-infrastructure-json-api 8.0.3 - "Getting started").
"""
from __future__ import annotations

import re
import time

from acmelib.plugins.targets._common import PluginError, text
from acmelib.plugins.targets._x509 import split_chain

VI_RELEASE = '8.0.1.0'      # the first release of the VI JSON API: newer vCenters serve it too


def parse_version(s):
    m = re.match(r'^\s*v?(\d+)\.(\d+)(?:\.(\d+))?', text(s))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def version_words(v):
    return '.'.join(str(x) for x in v) if v else '?'


def vi_about(t, release=VI_RELEASE):
    """{'version', 'build', 'apiVersion', ...} of the vCenter (or ESX) `t` speaks to - {} when it
    cannot be read (a vCenter older than 8.0 U1 has no VI JSON API)."""
    try:
        st, hd, d = t.req('GET', '/sdk/vim25/%s/ServiceInstance/ServiceInstance/content' % release,
                          auth=False, what='reading the version')
    except PluginError as e:
        t.ctx.debug('the version cannot be read: %s' % e)
        return {}
    a = d.get('about') if isinstance(d, dict) else None
    return a if isinstance(a, dict) else {}


def pem_body(pem):
    m = re.search(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', text(pem), re.S)
    return re.sub(r'[^A-Za-z0-9+/=]', '', m.group(1)) if m else ''


def has_cert(raw, bundle_or_pem):
    """Whether `raw` (whatever an API answered: JSON, PEM, with \\n escaped) holds the
    certificate - its base64 compared, line breaks and escapes taken away."""
    pem = bundle_or_pem if isinstance(bundle_or_pem, str) else \
        text(bundle_or_pem.as_format('cert-pem'))
    want = pem_body(pem)
    flat = re.sub(r'\\n|\\r|\\/|[^A-Za-z0-9+/=]', '', text(raw if isinstance(raw, (str, bytes))
                                                            else repr(raw)))
    return bool(want) and want in flat


def root_of(bundle, given=None):
    """The root CA certificate (PEM) the chain ends in: the one given in the form, else the last
    of the chain when it signs itself, else ''."""
    return split_chain(bundle, given or '')[1] or ''


def intermediates(bundle):
    """The chain without its root."""
    return split_chain(bundle, '')[0]


def wait_task(t, ask, done, failed, tries=60, every=10.0, what='the task'):
    """Ask `ask()` -> data until `done(data)` (returned) or `failed(data)` (a PluginError with
    words), `tries` times `every` seconds at most - then a PluginError that it is still running.
    A stopped job gives up."""
    sleep = getattr(t, '_sleep', time.sleep)
    last = None
    for i in range(max(1, tries)):
        if i:
            if t.ctx.cancelled():
                raise PluginError('stopped while waiting for %s' % what)
            sleep(every)
        last = ask()
        if failed(last):
            raise PluginError('%s failed' % what, detail=text(last)[:4000], retry=False)
        if done(last):
            return last
    raise PluginError('%s is still running after %d s - look at it on the device' % (
        what, int(tries * every)), detail=text(last)[:4000])
