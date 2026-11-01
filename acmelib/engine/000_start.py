# -*- coding: utf-8 -*-
from __future__ import annotations
"""
acme - certificates kept, renewed and deployed by themselves.

Let's Encrypt (and any ACME CA), your own certificate authorities, Microsoft
AD CS and SCEP on one side; the servers, load balancers, firewalls and
appliances that use the certificates on the other. This is the engine under
it: the settings, the database (SQLite, MariaDB or PostgreSQL), the sealed
secrets, the cluster of two nodes, mail and SMS, the administrators and their
second step, backups, the firewall, the network, time, updates, the JSON API
the web pages ask, the command line and the console. The certificate manager
(acmelib/certs) plugs into it through HOOKS below.

    acme --status              what it is doing, in one screen
    acme --console             the menus, on the server's own screen
    acme --help                all of it

With nothing at all on the command line it runs the daemon in the foreground.

The Python standard library and nothing else, except the driver of a database
server where one is chosen instead of the file on this machine.
"""

import argparse
import base64
import bisect
import calendar
import binascii
import collections
import contextlib
import errno
import getpass
import hashlib
import heapq
import hmac
import html

import io
import ipaddress
import json
import os
import queue
import re
import secrets
import select

import shutil
import signal
import smtplib
import socket

import sqlite3
import ssl
import string
import struct
import subprocess
import sys
import tempfile

import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# No proxy from the environment (1.0.201): http_proxy, https_proxy and the like
# in /etc/environment or a shell are not for acme - the proxy is for the updates
# only (Settings → Proxy, handed over by itself). Gone before anything opens a
# connection, and from what acme runs too (smbclient, nsupdate, openssl…), so a
# proxy never stands between the VIP address's check, ACME or SMS and what
# they ask.
for _pk in ('http_proxy', 'https_proxy', 'ftp_proxy', 'all_proxy', 'no_proxy',
            'HTTP_PROXY', 'HTTPS_PROXY', 'FTP_PROXY', 'ALL_PROXY', 'NO_PROXY'):
    os.environ.pop(_pk, None)

from acmelib import __version__  # noqa: E402  (one place for the version)
# The oldest version this one may go back to (1.0.143): one that reads what
# this one writes into the database and config.json the same, and has every
# security fix that matters. Raised whenever a version writes something an
# older one would misread, or fixes a hole an older one has. install.sh keeps
# the highest of these in a file of root's (downgrade-floor); each node keeps
# its own in the database.
DOWNGRADE_FLOOR = '1.0.0'

# ---------------------------------------------------------------------------
# Where the modules plug in
# ---------------------------------------------------------------------------
# The engine knows nothing of certificates: acmelib.certs (and anything else
# put in later) adds itself through these lists, each a list of functions.
#   daemon_start(daemon)          the daemon is up (API listening): start threads
#   daemon_stop(daemon)           it is going down
#   cli_args(parser)              add options to the command line
#   cli_run(args) -> int|None     run them; a number is the exit code, None: not mine
#   console_main(console) -> [(key, words, fn)]   lines of the console's main menu
#   status(store, pal) -> [lines] lines for `acme --status`
#   alerts(store) -> [{'key', 'level' ('warn'|'bad'), 'words'}]   what Alerts and reports mails
#   report(store, since) -> [(heading, [lines])]                  sections of the weekly report
#   metrics(store) -> [(name, help, 'gauge'|'counter', [({labels}, value)])]   for Prometheus
#   carry_tables() -> [table names] that belong to the configuration (Export and import)
#   firewall(store, node) -> [{'key', 'title', 'why', 'rules': [{'family', 'proto',
#       'port', 'source'}]}]   what a module needs open on a node (its DNS server, say)
HOOKS = {'daemon_start': [], 'daemon_stop': [], 'cli_args': [], 'cli_run': [],
         'console_main': [], 'status': [], 'alerts': [], 'report': [], 'metrics': [],
         'carry_tables': [], 'firewall': []}


def hook(kind):
    """@hook('daemon_start') - a function added to one of the HOOKS."""
    def wrap(fn):
        HOOKS[kind].append(fn)
        return fn
    return wrap


