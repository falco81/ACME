# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- which DNS servers a function asks: Settings → DNS (1.0.210) ----------------------
# The certificate manager keeps named sets of DNS servers and which of them each
# function asks (acmelib/certs/dnssets.py, docs/dns-sets.md). The engine's own
# DNS client - the appliance's own ACME (acme_resolvers), mail going direct
# (own_dns) - asks it here; it answers once it is imported.
DNS_SETS_HOOK = {'fn': None}


def dns_set_servers(purpose):
    """The addresses (port 53) of the set chosen under Settings → DNS for one of
    the engine's functions ('acme', 'mail'): [] for the system's own resolver,
    None when nothing is chosen there - then the setting of before is asked."""
    fn = DNS_SETS_HOOK.get('fn')
    if fn is None:
        try:
            _importlib.import_module('acmelib.certs.dnssets')
        except Exception:                               # noqa: BLE001
            return None
        fn = DNS_SETS_HOOK.get('fn')
        if fn is None:
            return None
    try:
        got = fn(purpose)
    except Exception:                                   # noqa: BLE001
        return None
    return None if got is None else [str(x) for x in got]
