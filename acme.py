#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
acme - certificates kept, renewed and put in place by themselves.

Let's Encrypt (and any ACME CA), your own certificate authorities, Microsoft
AD CS and SCEP on one side; the servers, load balancers, firewalls and
appliances that use the certificates on the other. acme orders and renews
them, answers the validation itself (its own DNS server, or the DNS and web
servers you have), and puts every new certificate where it belongs - in the
format that place wants - and makes the service there take it.

    acme --status              what it is doing, in one screen
    acme --certs               every certificate it keeps
    acme --console             the menus, on the server's own screen
    acme --help                all of it

This file only starts it: the engine is in acmelib/.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from acmelib import __version__          # noqa: E402
from acmelib import engine as _engine    # noqa: E402

DOWNGRADE_FLOOR = _engine.DOWNGRADE_FLOOR
# Whoever imports acme (the console runs itself as `import acme; acme.entry()`,
# the tests read its functions) finds the engine's names here, as before.
globals().update({k: v for k, v in vars(_engine).items()
                  if not (k.startswith('__') and k.endswith('__'))})
entry = _engine.entry

if __name__ == '__main__':
    entry()
