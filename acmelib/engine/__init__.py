# -*- coding: utf-8 -*-
"""
The acme engine: the platform the certificate manager stands on - settings,
the database (SQLite / MariaDB / PostgreSQL), the sealed secrets, the cluster
(HA), mail and SMS, backups, the firewall, the network, time, updates, the
JSON API the pages ask, the command line and the console.

It is assembled from the numbered parts beside this file into one namespace,
in the order of their numbers: each part is a module of its own on disk (and in
every traceback), and every part sees the names of all the others, as they did
when they were one file. A part is taken out by deleting it; a new one is put
in by giving it a number where it belongs.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# The launcher (acme.py beside acmelib/) is what the engine calls "itself":
# it starts its own copies with --dump-copy and finds acme_web.py beside it.
__file__ = os.environ.get('ACME_LAUNCHER') or os.path.join(
    os.path.dirname(os.path.dirname(_HERE)), 'acme.py')

PARTS = sorted(f for f in os.listdir(_HERE)
               if f[:3].isdigit() and f.endswith('.py'))

for _part in PARTS:
    _path = os.path.join(_HERE, _part)
    with open(_path, encoding='utf-8') as _f:
        _code = compile(_f.read(), _path, 'exec', dont_inherit=True)
    exec(_code, globals())
del _part, _path, _f, _code
