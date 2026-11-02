# -*- coding: utf-8 -*-
"""
Being kind to other people's servers (1.0.21): acme never runs into the rate
limits and the brute-force protections of the services it talks to.

Every HTTP(S) request a module makes goes through RunContext.http
(acmelib/certs/runtime.py), which uses what is here:

    throttle(url, ...)      a context manager around one request: at most
                            HOST_CONCURRENT requests at once to one host, at most
                            HOST_RATE a second (a token bucket of HOST_BURST),
                            nothing at all while the host asked to slow down
                            (hold), and Let's Encrypt's documented limits for new
                            accounts and new orders kept
    slowdown(st, headers, body)  seconds a service asks to wait (429, 503, a
                            "Too Many Attempts" / "rate limit" refusal), or None
    pause(attempt, asked)   how long to wait before trying once more: what the
                            service asked (Retry-After, seconds or an HTTP date),
                            else a growing delay with jitter
    note_slow(url, wait)    the host held for that long (others wait too)

And what the modules share, so that a readiness check of six certificates
signs in once, not six times:

    session(key, login)     a sign-in token per module and its settings, kept for
                            its lifetime, one sign-in at a time (thread-safe);
                            a refused sign-in is kept a little while too, so a
                            wrong password is not tried again and again
    session_drop(key, tok)  the token forgotten (a 401: it ran out)
    shared(key, fn, ttl)    a read (a list of zones, domains, records) shared for
                            a little while, asked once even when asked at once
    forget_shared(prefix)   reads forgotten (after a write)
    key_of(plugin, what)    the key of a module's settings (secrets only hashed)
    sharing(ctx)            whether that ctx shares (RunContext does; a test's
                            stand-in does not, unless it says so)

Loopback addresses are not throttled (the machine itself; LOCAL_FREE).
"""
from __future__ import annotations

import email.utils
import hashlib
import ipaddress
import json
import random
import re
import threading
import time
import urllib.parse

from acmelib.plugins.base import PluginError

HOST_CONCURRENT = 2         # requests at once to one host
HOST_RATE = 4.0             # requests a second to one host, on average
HOST_BURST = 6.0            # ... and at once after a quiet while
IDEMPOTENT = ('GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE')
RETRIES = 2                 # an idempotent call asked again at most this often
WAIT_MAX = 60.0             # the longest wait acme sits out in a request
HOLD_CAP = 300.0            # a host is held at most this long (a longer wait is the caller's)
LOCKOUT_S = 60.0            # a "too many attempts" refusal without a Retry-After
BASE_S = 2.0                # the first wait when the service says nothing
SESSION_FAIL_S = 60.0       # a refused sign-in is not tried again for this long
SHARED_S = 45.0             # how long a shared read is kept
LOCAL_FREE = True           # loopback is not throttled (tests set it off)
SLEEP = time.sleep          # a test puts its own here
NOW = time.time

# Let's Encrypt's documented limits (letsencrypt.org/docs/rate-limits):
# 10 new accounts per IP address in 3 hours, 300 new orders per account in 3
# hours - kept per host here (stricter: every account of this node together).
ACME_LIMITS = (
    (re.compile(r'(^|\.)api\.letsencrypt\.org\Z'), re.compile(r'/new-acct\b|/new-account\b'),
     'new-account', 10, 3 * 3600.0, 'new accounts'),
    (re.compile(r'(^|\.)api\.letsencrypt\.org\Z'), re.compile(r'/new-order\b'),
     'new-order', 300, 3 * 3600.0, 'new orders'),
)

SLOW_WORDS = re.compile(r'too many (attempts|requests|login|sign|calls|failed)|rate.?limit|'
                        r'slow down|throttl|too frequent|try again later|ratelimited',
                        re.I)

_LOCK = threading.Lock()
_HOSTS = {}


# ---------------------------------------------------------------------------
# One host
# ---------------------------------------------------------------------------
class _Host(object):
    def __init__(self):
        self.sem = threading.BoundedSemaphore(HOST_CONCURRENT)
        self.lock = threading.Lock()
        self.tokens = HOST_BURST
        self.at = NOW()
        self.hold_until = 0.0
        self.hold_said = ''
        self.buckets = {}               # ACME limit -> [tokens, at]
        self.active = 0                 # requests running now (tests look)
        self.most = 0


def _host(netloc):
    with _LOCK:
        h = _HOSTS.get(netloc)
        if h is None:
            h = _HOSTS[netloc] = _Host()
        return h


def host_of(url):
    try:
        u = urllib.parse.urlsplit(str(url))
    except ValueError:
        return ''
    return (u.netloc.rsplit('@', 1)[-1] or '').lower()


def _local(netloc):
    name = netloc.rsplit(':', 1)[0].strip('[]') if not netloc.startswith('[') else \
        netloc[1:].split(']', 1)[0]
    if name in ('localhost', 'localhost.localdomain'):
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def forget():
    """Every host, session and shared read forgotten (tests)."""
    with _LOCK:
        _HOSTS.clear()
    with _S_LOCK:
        _SESSIONS.clear()
    with _R_LOCK:
        _READS.clear()


def _sleep(seconds, cancelled=None):
    end = NOW() + max(0.0, seconds)
    while True:
        left = end - NOW()
        if left <= 0:
            return
        if cancelled is not None and cancelled():
            raise PluginError('stopped', retry=False)
        SLEEP(min(left, 1.0))


def _clock(t):
    return time.strftime('%H:%M:%S', time.localtime(t))


class throttle(object):
    """with throttle(url, say=fn, cancelled=fn): one request to its host."""

    def __init__(self, url, say=None, cancelled=None, method='GET'):
        self.url = url
        self.netloc = host_of(url)
        self.say = say
        self.cancelled = cancelled
        self.method = str(method or 'GET').upper()
        self.h = None

    def __enter__(self):
        if not self.netloc or (LOCAL_FREE and _local(self.netloc)):
            return self
        h = self.h = _host(self.netloc)
        name = self.netloc.rsplit(':', 1)[0] if not self.netloc.startswith('[') else self.netloc
        # a host that asked to slow down: nothing sent until then
        with h.lock:
            left = h.hold_until - NOW()
        if left > 0:
            if left > WAIT_MAX:
                raise PluginError(
                    '%s asked acme to slow down: it is not asked again before %s' % (
                        name, _clock(h.hold_until)), retry=True)
            if self.say:
                self.say('%s asked acme to slow down: waiting %d s' % (name, int(left + 0.999)))
            _sleep(left, self.cancelled)
        self._acme_limits(h, name)
        # the token bucket
        while True:
            with h.lock:
                t = NOW()
                h.tokens = min(HOST_BURST, h.tokens + (t - h.at) * HOST_RATE)
                h.at = t
                if h.tokens >= 1.0:
                    h.tokens -= 1.0
                    break
                wait = (1.0 - h.tokens) / HOST_RATE
            _sleep(wait, self.cancelled)
        # at most HOST_CONCURRENT at once
        if not h.sem.acquire(timeout=180):
            self.h = None                       # something hangs: not waited for longer
            return self
        with h.lock:
            h.active += 1
            h.most = max(h.most, h.active)
        return self

    def _acme_limits(self, h, name):
        if self.method != 'POST':
            return
        path = urllib.parse.urlsplit(str(self.url)).path
        hostname = self.netloc.rsplit(':', 1)[0]
        for hre, pre, key, most, per, words in ACME_LIMITS:
            if not hre.search(hostname) or not pre.search(path):
                continue
            with h.lock:
                t = NOW()
                tok, at = h.buckets.get(key, (float(most), t))
                tok = min(float(most), tok + (t - at) * most / per)
                if tok >= 1.0:
                    h.buckets[key] = (tok - 1.0, t)
                    continue
                h.buckets[key] = (tok, t)
                ready = t + (1.0 - tok) * per / most
            raise PluginError(
                'Let\'s Encrypt allows %d %s in %d hours: acme holds this one back until %s' % (
                    most, words, int(per // 3600), _clock(ready)), retry=True)

    def __exit__(self, *exc):
        h = self.h
        if h is not None:
            with h.lock:
                h.active -= 1
            h.sem.release()
        return False


def slowdown(status, headers, body):
    """Seconds a service asks to wait (0.0: it said nothing of how long), or
    None when the answer is not a "slow down"."""
    try:
        status = int(status)
    except (TypeError, ValueError):
        return None
    ra = retry_after(headers)
    if status in (429, 503):
        return ra if ra is not None else 0.0
    if status in (400, 401, 403, 420) and _slow_words(body):
        return ra if ra is not None else LOCKOUT_S
    return None


def _slow_words(body):
    if not body:
        return False
    if isinstance(body, bytes):
        body = body[:4000].decode('utf-8', 'replace')
    return bool(SLOW_WORDS.search(str(body)[:4000]))


def is_slow_words(text):
    """Whether a refusal says "too many attempts", "rate limit"..."""
    return _slow_words(text)


def retry_after(headers, now=None):
    """Seconds a Retry-After header asks for (a number or an HTTP date); None: none."""
    v = ''
    for k, x in (headers or {}).items():
        if str(k).lower() == 'retry-after':
            v = str(x or '').strip()
            break
    if not v:
        return None
    try:
        return max(0.0, float(v))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(v).timestamp()
    except (TypeError, ValueError, IndexError):
        return None
    return max(0.0, when - (NOW() if now is None else now))


def pause(attempt, asked=0.0):
    """How long to wait before try number attempt+2: what was asked, else
    BASE_S doubled each time - with up to a fifth more, at random (jitter)."""
    if asked and asked > 0:
        return float(asked) + random.uniform(0, min(2.0, asked * 0.1))
    base = BASE_S * (2 ** max(0, int(attempt)))
    return base + random.uniform(0, base * 0.2)


def note_slow(url, wait):
    """The host held for `wait` seconds (at most HOLD_CAP): no request goes there
    before - from any job."""
    netloc = host_of(url)
    if not netloc or wait is None or wait <= 0 or wait > HOLD_CAP:
        return
    h = _host(netloc)
    with h.lock:
        h.hold_until = max(h.hold_until, NOW() + wait)


def held(url):
    """Seconds left of a host's hold (0: none)."""
    netloc = host_of(url)
    with _LOCK:
        h = _HOSTS.get(netloc)
    if h is None:
        return 0.0
    with h.lock:
        return max(0.0, h.hold_until - NOW())


def most_at_once(url):
    """The most requests that ran at once to the host of url (tests)."""
    with _LOCK:
        h = _HOSTS.get(host_of(url))
    return h.most if h else 0


def waiting_words(url, wait, status):
    name = host_of(url).rsplit(':', 1)[0] or url
    return '%s asked acme to slow down (HTTP %s): waiting %d s, then asking once more' % (
        name, status, int(wait + 0.999))


# ---------------------------------------------------------------------------
# What modules share: sign-ins and reads
# ---------------------------------------------------------------------------
_S_LOCK = threading.Lock()
_SESSIONS = {}                  # key -> {'lock', 'token', 'until', 'fail', 'fail_until', 'n'}
_R_LOCK = threading.Lock()
_READS = {}                     # key -> {'lock', 'until', 'value', 'error'}


def sharing(ctx):
    """Whether a module run with this ctx shares sign-ins and reads."""
    return bool(getattr(ctx, 'shares_limits', False))


def key_of(plugin, what=''):
    """A key of the module's kind and settings - secrets only as a hash, never kept."""
    try:
        cfg = json.dumps(getattr(plugin, 'config', {}) or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        cfg = repr(getattr(plugin, 'config', {}))
    fp = hashlib.sha256(cfg.encode('utf-8', 'replace')).hexdigest()[:32]
    return '%s|%s|%s' % (getattr(plugin, 'kind', '') or type(plugin).__name__, fp, what)


def _slot(key):
    with _S_LOCK:
        s = _SESSIONS.get(key)
        if s is None:
            if len(_SESSIONS) > 500:
                t = NOW()
                for k in [k for k, v in _SESSIONS.items()
                          if v['until'] < t and v['fail_until'] < t]:
                    _SESSIONS.pop(k, None)
            s = _SESSIONS[key] = {'lock': threading.Lock(), 'token': None, 'until': 0.0,
                                  'fail': None, 'fail_until': 0.0, 'n': 0}
        return s


def session(key, login):
    """The token of `key`: login() -> (token, seconds it lives) is called only
    when there is none or it ran out - by one thread, the others wait for it.
    A sign-in refused (a PluginError) is raised again for SESSION_FAIL_S
    without asking (a wrong password not tried again and again)."""
    s = _slot(key)
    with s['lock']:
        t = NOW()
        if s['token'] is not None and t < s['until']:
            return s['token']
        if s['fail'] is not None and t < s['fail_until']:
            raise s['fail']
        try:
            token, life = login()
        except PluginError as e:
            if not getattr(e, 'retry', True) or is_slow_words(str(e)):
                s['fail'], s['fail_until'] = e, NOW() + SESSION_FAIL_S
            raise
        s['n'] += 1
        s['fail'] = None
        try:
            life = float(life)
        except (TypeError, ValueError):
            life = 600.0
        s['token'], s['until'] = token, NOW() + max(min(life, 86400.0) - 30.0, 15.0)
        return token


def session_drop(key, token=None):
    """The token forgotten (a 401) - only that one, when given: another thread
    may have signed in again already."""
    s = _slot(key)
    with s['lock']:
        if token is None or s['token'] == token:
            s['token'], s['until'] = None, 0.0


def session_logins(key):
    """How often `key` signed in (tests)."""
    with _S_LOCK:
        s = _SESSIONS.get(key)
    return s['n'] if s else 0


def shared(key, fn, ttl=None):
    """fn() asked once for `key` and kept `ttl` seconds (SHARED_S); asked at
    once by several threads, the others wait for the first. An error is kept
    a little too (the same refusal not asked again at once)."""
    ttl = SHARED_S if ttl is None else ttl
    with _R_LOCK:
        r = _READS.get(key)
        if r is None:
            if len(_READS) > 2000:
                t = NOW()
                for k in [k for k, v in _READS.items() if v['until'] < t]:
                    _READS.pop(k, None)
            r = _READS[key] = {'lock': threading.Lock(), 'until': 0.0, 'value': None,
                               'error': None}
    with r['lock']:
        if NOW() < r['until']:
            if r['error'] is not None:
                raise r['error']
            return r['value']
        try:
            value = fn()
        except PluginError as e:
            r['error'], r['value'], r['until'] = e, None, NOW() + min(ttl, 20.0)
            raise
        r['error'], r['value'], r['until'] = None, value, NOW() + ttl
        return value


def forget_shared(prefix):
    """Shared reads whose key starts with prefix forgotten (after a write)."""
    with _R_LOCK:
        for k in [k for k in _READS if k.startswith(prefix)]:
            _READS.pop(k, None)
