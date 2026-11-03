# -*- coding: utf-8 -*-
"""
What the challenge modules share (the name starts with "_": the registry does
not take it for a module):

    DnsChallenge    the base of every DNS-01 module: where the record goes
                    (_acme-challenge.NAME, its CNAME followed), whether it is
                    seen (the zone's own name servers asked straight, then
                    public resolvers if asked), the fields for that
    HttpChallenge   the base of the HTTP-01 modules: the file fetched as the CA will
    api()           a JSON API asked through ctx.http, its errors in words
    http_call()     one request through ctx.http, a 429 waited out (Retry-After)
    suffixes() / longest_zone() / no_zone() / zones_seen()   what the API modules
                    share to find the zone a name is in and to say what they see
    openssl_sign()  data signed with a private key by the openssl program
    ssh fields / ssh_conn()   how to reach a machine over SSH
"""
from __future__ import annotations

import email.utils
import json
import os
import re
import shutil
import socket
import tempfile
import threading
import time

from acmelib.plugins import limits
from acmelib.plugins.base import (GENERIC_DISCOVERY, Challenge, Plugin, PluginError, field,
                                 guide_of, guide_step)
from acmelib.plugins.challenges import _dns as D

# A name connected to at an address of its own, in this thread only (a check of
# HTTP-01 made at a load balancer, a public address, NAT): the URL keeps the
# name - its Host and its TLS SNI are the name's - the connection goes there.
_PIN = threading.local()
_PIN_PREV = {'fn': None}


def _pinned_getaddrinfo(host, port, *a, **k):
    pins = getattr(_PIN, 'map', None)
    if pins and host:
        h = (host.decode() if isinstance(host, bytes) else str(host)).lower().rstrip('.')
        if h in pins:
            return _PIN_PREV['fn'](pins[h], port, *a, **k)
    return _PIN_PREV['fn'](host, port, *a, **k)


class pinned(object):
    """with pinned({'www.example.com': '203.0.113.7'}): connections to that name
    in this thread go to that address."""
    def __init__(self, pins):
        self.pins = {str(k).lower().rstrip('.'): str(v).strip('[]')
                     for k, v in (pins or {}).items() if k and v}

    def __enter__(self):
        if _PIN_PREV['fn'] is None:
            _PIN_PREV['fn'] = socket.getaddrinfo
            socket.getaddrinfo = _pinned_getaddrinfo
        self.was = getattr(_PIN, 'map', None)
        _PIN.map = dict(self.was or {}, **self.pins)
        return self

    def __exit__(self, *exc):
        _PIN.map = self.was
        return False

SAFE_TOKEN = re.compile(r'^[A-Za-z0-9_-]{1,256}$')
SAFE_NAME = re.compile(r'^[A-Za-z0-9_*.-]{1,253}$')
SAFE_TXT = re.compile(r'^[A-Za-z0-9_.+/=-]{1,255}$')


def as_list(v):
    if v in (None, ''):
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in re.split(r'[\n,;]+', str(v)) if x.strip()]


def as_bool(v):
    if isinstance(v, bool):
        return v
    return str(v or '').strip().lower() in ('1', 'true', 'yes', 'on', 'y')


def as_num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def base_name(name):
    """The name a DNS-01 record is about: lower case, no '*.' (a wildcard is
    proved at its base name)."""
    n = D.norm(name)
    while n.startswith('*.'):
        n = n[2:]
    if not n or not SAFE_NAME.match(n) or '*' in n:
        raise PluginError('"%s" is not a name acme can prove' % name, retry=False)
    return n


def relative(fqdn, zone):
    fqdn, zone = D.norm(fqdn), D.norm(zone)
    if fqdn == zone:
        return '@'
    if not fqdn.endswith('.' + zone):
        raise PluginError('%s is not in the zone %s' % (fqdn, zone), retry=False)
    return fqdn[:-len(zone) - 1]


def check_txt(value):
    if not SAFE_TXT.match(str(value or '')):
        raise PluginError('a TXT value acme will not write (not base64url): %r' % value,
                          retry=False)
    return value


def settings(ctx):
    """The settings as the module may read them: ctx.settings, else the engine's."""
    s = getattr(ctx, 'settings', None)
    if s:
        return s
    import sys
    E = sys.modules.get('acmelib.engine')
    return getattr(E, 'CONFIG', {}) if E is not None else {}


# ---------------------------------------------------------------------------
# A JSON API through ctx.http
# ---------------------------------------------------------------------------
ACCESS_S = 30.0             # a module's test() for the readiness checks, kept so long
RETRIES_429 = 3             # how often a "429 Too Many Requests" is waited out
WAIT_429_MAX = 60.0         # the longest wait a Retry-After is believed for
SLEEP = time.sleep          # a test puts its own here


def retry_after(headers, default=5.0, now=None):
    """Seconds a Retry-After header asks for (a number or an HTTP date)."""
    v = str(_header(headers, 'retry-after') or '').strip()
    if not v:
        return default
    try:
        return max(0.0, float(v))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(v).timestamp()
    except (TypeError, ValueError, IndexError):
        return default
    return max(0.0, when - (time.time() if now is None else now))


def http_call(ctx, method, url, body=None, headers=None, who='the API', timeout=30,
              verify=True, ca_pem=None, retries=None, idempotent=None):
    """(status, headers, bytes) through ctx.http (so through the proxy of
    Settings → Proxy). acme's own ctx (RunContext) is kind to the server
    itself (acmelib/plugins/limits.py: a few requests a second per host, a 429
    / 503 / "too many attempts" waited out for an idempotent call, the job told
    so). A stand-in ctx without that: a 429 is waited out as long as it says
    (Retry-After, at most WAIT_429_MAX), up to RETRIES_429 times; a server that
    cannot be reached is a PluginError in words."""
    retries = RETRIES_429 if retries is None else retries
    kw = {'ca_pem': ca_pem} if ca_pem else {}
    if getattr(ctx, 'shares_limits', False):
        if idempotent is not None:
            kw['idempotent'] = idempotent
        try:
            return ctx.http(method, url, body=body, headers=headers, timeout=timeout,
                            verify=verify, retries=min(retries, 2), **kw)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('%s did not answer: %s' % (who, e))
    for attempt in range(retries + 1):
        try:
            status, rh, got = ctx.http(method, url, body=body, headers=headers,
                                       timeout=timeout, verify=verify, **kw)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('%s did not answer: %s' % (who, e))
        if status != 429 or attempt >= retries:
            return status, rh, got
        pause = min(max(retry_after(rh), 1.0), WAIT_429_MAX)
        ctx.step('%s asks to slow down (429): waiting %d s' % (who, pause), 'warn')
        if getattr(ctx, 'cancelled', lambda: False)():
            break
        SLEEP(pause)
    return status, rh, got


def api(ctx, method, url, body=None, headers=None, who='the API', ok=(200, 201, 202, 204),
        verify=True, raw_body=None, timeout=30, missing_ok=False, ca_pem=None, retries=None,
        with_headers=False):
    """(status, parsed JSON or None) - with the answer's headers third when
    with_headers. Raises PluginError in words on a status not in `ok` (404
    returns (404, None) when missing_ok); a 429 is waited out first."""
    h = {'Accept': 'application/json', 'User-Agent': 'acme-challenge'}
    data = raw_body
    if body is not None:
        data = json.dumps(body).encode()
        h['Content-Type'] = 'application/json'
    h.update(headers or {})
    status, rh, got = http_call(ctx, method, url, data, h, who=who, timeout=timeout,
                                verify=verify, ca_pem=ca_pem, retries=retries)
    parsed = None
    if got:
        try:
            parsed = json.loads(got.decode('utf-8') if isinstance(got, bytes) else got)
        except (ValueError, UnicodeDecodeError):
            parsed = None
    if status == 404 and missing_ok:
        return (status, parsed, rh) if with_headers else (status, parsed)
    if status not in ok:
        raise said_error(who, status, parsed, got)
    return (status, parsed, rh) if with_headers else (status, parsed)


def said_error(who, status, parsed, got):
    """The PluginError for an answer that is not what was asked for."""
    said = _said(parsed) or (got[:300].decode('utf-8', 'replace') if isinstance(got, bytes)
                              else str(got or '')[:300])
    words = '%s said %s: %s' % (who, status, said.strip() or 'nothing more')
    if status in (401, 403):
        words += ' - the credentials are wrong or may not do this'
    elif status == 429 or (status in (400, 403) and _slow(said)):
        words += ' - it asks acme to slow down; acme tries again later by itself'
    return PluginError(words, detail=said, retry=status >= 500 or status == 429)


def _slow(text):
    from acmelib.plugins import limits
    return limits.is_slow_words(text)


def _said(p):
    if not isinstance(p, dict):
        return ''
    for k in ('errors', 'error', 'message', 'detail', 'error_description'):
        v = p.get(k)
        if isinstance(v, list):
            return '; '.join(x.get('message', str(x)) if isinstance(x, dict) else str(x)
                             for x in v)
        if isinstance(v, dict):
            return str(v.get('message') or v.get('code') or v)
        if v:
            return str(v)
    return ''


# ---------------------------------------------------------------------------
# What the API modules share
# ---------------------------------------------------------------------------
def suffixes(fqdn):
    """The names a zone of `fqdn` can be, longest first, the top level left out:
    _acme-challenge.www.example.co.uk -> ..., example.co.uk, co.uk."""
    labels = D.norm(fqdn).split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels) - 1)]


def longest_zone(fqdn, zones):
    """The longest of `zones` that fqdn is in, or None."""
    best = None
    for z in zones or []:
        z = D.norm(z)
        if z and D.in_zone(fqdn, z) and (best is None or len(z) > len(best)):
            best = z
    return best


def no_zone(who, fqdn):
    return PluginError('%s has no zone for %s that these credentials may see - set the zone, '
                       'or give them access to it' % (who, D.norm(fqdn)), retry=False)


def zones_seen(who, names):
    """What a test() says when it could sign in and list the zones."""
    names = [D.norm(n) for n in names or [] if n]
    if not names:
        return '%s: signed in, but no zone is seen - give the credentials access to one' % who
    return '%s: signed in, %d zone(s) seen: %s' % (who, len(names), ', '.join(names[:20]) + (
        ', …' if len(names) > 20 else ''))


def unquote_txt(v):
    """A TXT value as the API wrote it ("abc", "ab" "c") as the one string it is."""
    v = str(v or '').strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return ''.join(re.findall(r'"((?:[^"\\]|\\.)*)"', v)) or v[1:-1]
    return v


def openssl_sign(ctx, key_pem, data, digest='sha256'):
    """`data` signed with the private key by the openssl program (RSA PKCS#1
    v1.5 or ECDSA, as the key is), the key in a file of its own for the moment."""
    work = tempfile.mkdtemp(prefix='acme-sign-')
    try:
        os.chmod(work, 0o700)
        kf = os.path.join(work, 'key.pem')
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(str(key_pem).strip() + '\n')
        try:
            sig = ctx.openssl(['dgst', '-' + digest, '-sign', kf], data=data)
        except Exception as e:                          # noqa: BLE001
            raise PluginError('openssl could not sign with the private key - is it a '
                              'PEM private key without a passphrase? (%s)' % e, retry=False)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if not sig:
        raise PluginError('openssl did not sign', retry=False)
    return sig


# ---------------------------------------------------------------------------
# DNS-01
# ---------------------------------------------------------------------------
PROPAGATION_FIELDS = [
    field('propagation', 'Wait until it is seen by', 'select', default='auth',
          options=[['auth', 'the zone\'s own name servers (asked straight)'],
                   ['auth+public', 'the zone\'s name servers, then public resolvers'],
                   ['resolvers', 'the resolvers below only'],
                   ['none', 'nothing: the CA is asked at once (after the delay)']],
          help='Before the CA is told to look, acme asks every name server of the zone '
               '(found by NS) for the record, without recursion, until each has it - the '
               'CA asks them the same way. Through public resolvers too, when your name '
               'servers are anycast or hidden behind a provider.', advanced=True),
    field('delay', 'Wait at least (seconds)', 'number', default=0,
          help='Seconds after the record is put in before the first look - for a DNS '
               'provider that says "done" before its servers have it.', advanced=True),
    field('resolvers', 'Resolvers', 'list', default='',
          placeholder='1.1.1.1\n8.8.8.8',
          help='DNS servers acme looks names up with (CNAMEs, the zone, its name '
               'servers) - an override. Empty: Settings → DNS (Validation checks).',
          advanced=True),
    field('public_resolvers', 'Public resolvers', 'list', default='',
          placeholder='1.1.1.1\n8.8.8.8\n9.9.9.9',
          help='Asked at the end when "then public resolvers" is chosen, and by a dry run - '
               'an override. Empty: Settings → DNS (The public view).', advanced=True),
    field('follow_cname', 'Follow a CNAME at _acme-challenge', 'bool', default=True,
          help='When _acme-challenge.NAME is a CNAME (a delegation to another zone), '
               'the TXT record is written where it points - the CA follows it too.',
          advanced=True),
]


class DnsChallenge(Challenge):
    """The base of the DNS-01 modules. A module sets `fields` (its own +
    PROPAGATION_FIELDS) and writes add_txt / del_txt; zone_hint() where the
    provider says which zones it has."""
    types = ('dns-01',)
    vendor = 'DNS'
    doc = 'docs/validation.md'
    auth_port = 53                  # where the zone's name servers are asked (a test changes it)

    def __init__(self, config, ctx):
        Challenge.__init__(self, config, ctx)
        self._zones = {}
        self._said = {}

    # -- settings -----------------------------------------------------------
    def flag(self, key):
        return as_bool(self.c(key, False))

    def num(self, key, default=0):
        return as_num(self.c(key, default), default)

    def lst(self, key):
        return as_list(self.c(key, ''))

    def resolvers(self):
        return D.resolver('validation', self.lst('resolvers'), self.ctx)

    def ttl(self):
        return int(self.num('ttl', 60) or 60)

    def say_once(self, key, words, level='info'):
        if self._said.get(key) != words:
            self._said[key] = words
            self.ctx.step(words, level)

    # -- discovery (1.0.29) ------------------------------------------------------
    def discover_setup(self):
        """The lists of the form, and the zones the credentials see: the Zone field
        offered them (empty - each name in the longest zone it is in - stays a choice)."""
        out = Plugin.discover_setup(self)
        names = getattr(self, 'zone_names', None)
        if not callable(names) or not any(f.get('key') == 'zone' and f.get('type') != 'catalog'
                                          for f in self.fields or []):
            return out
        try:
            zones = names()
        except NotImplementedError:
            return out
        except PluginError as e:
            out['notes'].append('the zones could not be listed: %s' % e)
            return out
        if zones is None:
            out['notes'].append('%s does not list the zones of the account - set the zone '
                                'by hand, or leave it empty (found by its SOA)' % (
                                    self.who or self.title or self.kind))
            return out
        zones = sorted({D.norm(z) for z in zones if z})
        out['facts'].append(['Zones the account sees', str(len(zones))])
        opts = [['', 'Empty: each name in the longest zone of the account it is in']] + \
            [[z, z] for z in zones[:500]]
        now = D.norm(self.config.get('zone') or '')
        self.offer(out, 'zone', opts, pick=now if now in zones else '')
        return out

    @classmethod
    def discover_offered(cls):
        if cls.discovery is not None or cls.discover_setup not in GENERIC_DISCOVERY:
            return Plugin.discover_offered.__func__(cls)
        lists = getattr(cls, 'zone_names', None)
        own_zones = callable(lists) and getattr(lists, '__qualname__', '') not in (
            'ApiDns.zone_names', 'DnsChallenge.zone_names')
        has_zone = any(f.get('key') == 'zone' for f in cls.fields or [])
        return (own_zones and has_zone and bool(cls.discover_keys_of())) or \
            Plugin.discover_offered.__func__(cls)

    # -- where it goes ----------------------------------------------------------
    def record_name(self, name):
        return '_acme-challenge.' + base_name(name)

    def target(self, rr):
        """Where the TXT record for `rr` is written: rr itself, or where its CNAMEs end."""
        if not self.flag('follow_cname'):
            return rr
        try:
            chain = D.follow_cname(rr, self.resolvers())
        except D.DnsError as e:
            self.ctx.debug('the CNAME of %s could not be looked up (%s): written there' % (rr, e))
            return rr
        if len(chain) > 1:
            self.ctx.step('%s is a CNAME to %s: the TXT record goes there' % (rr, chain[-1]))
        return chain[-1]

    def zone_hint(self, fqdn):
        """The zone, where the provider knows it better than DNS (a module overrides)."""
        z = D.norm(self.c('zone', ''))
        if z and D.in_zone(fqdn, z):
            return z
        return None

    def zone_for(self, fqdn):
        fqdn = D.norm(fqdn)
        if fqdn in self._zones:
            return self._zones[fqdn]
        z = self.zone_hint(fqdn)
        if not z:
            try:
                z = D.find_zone(fqdn, self.resolvers())
            except D.DnsError as e:
                raise PluginError('the zone of %s could not be found by its SOA (%s) - set the '
                                  'zone in the challenge' % (fqdn, e))
        self._zones[fqdn] = z
        return z

    def zone_of(self, name):
        try:
            return self.zone_for(self.target(self.record_name(name)))
        except PluginError:
            return None

    # -- the contract ---------------------------------------------------------------
    def present(self, name, token, key_authorization, txt_value):
        check_txt(txt_value)
        rr = self.record_name(name)
        fqdn = self.target(rr)
        h = self.add_txt(fqdn, txt_value)
        self.ctx.step('%s TXT "%s" put in (%s)' % (fqdn, txt_value, self.title or self.kind))
        return {'rr': rr, 'fqdn': fqdn, 'txt': txt_value, 'at': time.time(), 'h': h}

    def ready(self, name, handle):
        handle = handle or {}
        if time.time() < float(handle.get('at') or 0) + self.num('delay', 0):
            return False
        mode = self.c('propagation', 'auth')
        if mode == 'none':
            return True
        fqdn, rr, txt = handle.get('fqdn'), handle.get('rr'), handle.get('txt')
        if mode == 'resolvers':
            return self.seen_by(self.resolvers(), rr, txt, 'the resolvers')
        ok = self.seen_by_authority(fqdn, txt)
        if ok is None:                          # the name servers cannot be reached from here
            ok = self.seen_by(self.resolvers(), rr, txt, 'the resolvers')
        if ok and mode == 'auth+public':
            ok = self.seen_by(D.resolver('public', self.lst('public_resolvers'), self.ctx), rr,
                              txt, 'the public resolvers')
        return ok

    def cleanup(self, name, handle):
        handle = handle or {}
        if not handle.get('fqdn'):
            return
        self.del_txt(handle['fqdn'], handle.get('txt'), handle.get('h'))

    # -- what a module writes ------------------------------------------------------------
    def add_txt(self, fqdn, value):
        """Put the TXT record in (other values at that name stay). Returns a
        JSON-able handle for del_txt."""
        raise NotImplementedError

    def del_txt(self, fqdn, value, handle):
        """Take that one value away; quiet when it is gone already."""
        raise NotImplementedError

    def add_cname(self, fqdn, target):
        """Make fqdn a CNAME to target (a module whose API can; NotImplementedError
        otherwise - the module then does not offer cname-any). Returns a handle."""
        raise NotImplementedError

    def del_cname(self, fqdn, target, handle):
        raise NotImplementedError

    # -- any record, for a commercial CA's DCV (base.Challenge.place) -----------------------
    @classmethod
    def writes_cname(cls):
        return getattr(cls, 'add_cname') is not DnsChallenge.add_cname

    @classmethod
    def writes_txt(cls):
        return getattr(cls, 'add_txt') is not DnsChallenge.add_txt

    @classmethod
    def proofs_for(cls, config):
        out = ['acme-dns-01']
        if cls.writes_txt():
            out.append('txt-any')
        if cls.writes_cname():
            out.append('cname-any')
        return out

    def place(self, kind, name, where, content):
        fqdn = D.norm(where)
        if not SAFE_NAME.match(fqdn) or '*' in fqdn:
            raise PluginError('"%s" is not a name acme writes a record at' % where, retry=False)
        content = str(content or '').strip()
        if kind == 'txt':
            if not re.match(r'^[A-Za-z0-9_.+/=:-]{1,255}\Z', content):
                raise PluginError('a TXT value acme will not write: %r' % content, retry=False)
            target = self.target(fqdn)
            h = self.add_txt(target, content)
            self.ctx.step('%s TXT "%s" put in (%s)' % (target, content, self.title or self.kind))
            return {'kind': 'txt', 'rr': fqdn, 'fqdn': target, 'txt': content,
                    'at': time.time(), 'h': h}
        if kind == 'cname':
            tgt = D.norm(content)
            if not SAFE_NAME.match(tgt) or '*' in tgt:
                raise PluginError('"%s" is not a name a CNAME points at' % content, retry=False)
            if not self.writes_cname():
                raise NotImplementedError('%s writes no CNAME records' % (self.title or self.kind))
            h = self.add_cname(fqdn, tgt)
            self.ctx.step('%s CNAME %s put in (%s)' % (fqdn, tgt, self.title or self.kind))
            return {'kind': 'cname', 'rr': fqdn, 'target': tgt, 'at': time.time(), 'h': h}
        raise NotImplementedError('%s puts no %s in place' % (self.title or self.kind, kind))

    def placed_ready(self, handle):
        h = handle or {}
        if h.get('kind') == 'cname':
            if self.c('propagation', 'auth') == 'none':
                return True
            if time.time() < float(h.get('at') or 0) + self.num('delay', 0):
                return False
            chain = self.cname_chain(h.get('rr'))
            return len(chain) > 1 and chain[1] == D.norm(h.get('target'))
        return self.ready(h.get('rr'), h)

    def unplace(self, handle):
        h = handle or {}
        if h.get('kind') == 'cname':
            self.del_cname(h.get('rr'), h.get('target'), h.get('h'))
        elif h.get('fqdn'):
            self.del_txt(h['fqdn'], h.get('txt'), h.get('h'))

    # -- is it there -------------------------------------------------------------------------
    def seen_by(self, servers, name, txt, who):
        """Every one of `servers` (asked with recursion) sees txt at name."""
        missing, asked = [], 0
        for srv in servers:
            try:
                m = D.ask_server(servers, srv, name, 16, rd=True)
            except (D.DnsError, D.FormErr, OSError):
                continue
            asked += 1
            if txt not in [r.text for r in m.answer if r.rtype == 16]:
                missing.append(srv)
        if not asked:
            self.say_once('seen:' + name, 'none of %s answered for %s' % (who, name), 'warn')
            return False
        if missing:
            self.say_once('seen:' + name, '%s TXT not yet seen by %s' % (name, ', '.join(missing)))
            return False
        self.say_once('seen:' + name, '%s TXT seen by %s' % (name, who), 'ok')
        return True

    def authority(self, fqdn):
        """[(ns name, [addresses])] of the zone fqdn is in."""
        zone = self.zone_for(fqdn)
        try:
            return zone, D.zone_servers(zone, self.resolvers())
        except D.DnsError as e:
            self.say_once('ns:' + zone, 'the name servers of %s could not be found: %s'
                          % (zone, e), 'warn')
            return zone, []

    def seen_by_authority(self, fqdn, txt):
        """True: every name server of the zone has it; False: not yet; None:
        none of them could be reached from here."""
        zone, servers = self.authority(fqdn)
        if not servers:
            return None
        have, lacking, unreachable = [], [], []
        for ns, addrs in servers:
            state = None
            for a in addrs:
                try:
                    got = D.txt_at(a, fqdn, port=self.auth_port)
                except (D.DnsError, D.FormErr, OSError):
                    continue
                state = txt in got
                break
            (have if state else lacking if state is False else unreachable).append(ns)
        if not have and not lacking:
            self.say_once('auth:' + fqdn, 'the name servers of %s (%s) cannot be asked from '
                          'here - the resolvers are asked instead'
                          % (zone, ', '.join(unreachable)), 'warn')
            return None
        if lacking:
            self.say_once('auth:' + fqdn, '%s TXT: on %s, not yet on %s' % (
                fqdn, ', '.join(have) or 'none', ', '.join(lacking)))
            return False
        self.say_once('auth:' + fqdn, '%s TXT is on every name server of %s (%s)' % (
            fqdn, zone, ', '.join(have)), 'ok')
        return True

    # -- what a person is told (guide) and the dry run --------------------------------------
    guide_timeout = 2.0             # seconds for one DNS question of guide()
    api_provider = False            # True: zone_hint() asks the provider which zones it holds
    guide_needs_dry_run = False     # True: only a dry run can tell (a script, commands)

    def who_words(self):
        return self.who if getattr(self, 'who', '') else (self.title or self.kind)

    def name_zone(self, fqdn):
        """The zone a name is in as DNS says (its SOA), or None."""
        try:
            return D.find_zone(fqdn, self.resolvers(), timeout=self.guide_timeout)
        except (D.DnsError, D.FormErr, OSError):
            return None

    def home_of(self, name):
        """The zone of a name for the words 'your DNS at ...' (DNS, else its domain)."""
        n = D.norm(name)
        while n.startswith('*.'):
            n = n[2:]
        return self.name_zone(n) or D.registrable(n)

    def ask_authority(self, name, qtype, zone=None):
        """(zone, [(ns, Message or None, words)]): the zone's own name servers
        asked straight (no recursion) - what they hold, no cache in between."""
        zone = zone or self.name_zone(name)
        if not zone:
            return None, []
        try:
            servers = D.zone_servers(zone, self.resolvers(), timeout=self.guide_timeout)
        except (D.DnsError, D.FormErr, OSError):
            return zone, []
        out = []
        for ns, addrs in servers[:4]:
            got, err = None, 'no address'
            for a in addrs[:2]:
                try:
                    got = D.query(a, name, qtype, port=self.auth_port, timeout=self.guide_timeout,
                                  rd=False)
                    if got.rcode not in (D.NOERROR, D.NXDOMAIN):
                        err = '%s said %s' % (ns, D.RCODES.get(got.rcode, got.rcode))
                        got = None
                        continue
                    break
                except (D.DnsError, D.FormErr, OSError) as e:
                    err = str(e)
            out.append((ns, got, '' if got is not None else err))
        return zone, out

    def cname_chain(self, rr):
        """[rr, where its CNAME points, ...] as the zone's own name servers say
        it (the resolvers when those cannot be asked) - no cached answer."""
        chain = [D.norm(rr)]
        for _ in range(8):
            cur = chain[-1]
            _zone, said = self.ask_authority(cur, 5)
            nxt = None
            for _ns, m, _w in said:
                if m is None:
                    continue
                got = [D.norm(r.text) for r in m.answer if r.rtype == 5 and D.norm(r.name) == cur]
                nxt = got[0] if got else ''
                break
            if nxt is None:
                try:
                    m = D.ask_any(self.resolvers(), cur, 5, self.guide_timeout)
                except (D.DnsError, D.FormErr, OSError):
                    break
                got = [D.norm(r.text) for r in m.answer if r.rtype == 5 and D.norm(r.name) == cur]
                nxt = got[0] if got else ''
            if not nxt or nxt in chain:
                break
            chain.append(nxt)
        return chain

    def provider_zone(self, fqdn):
        """The zone the provider holds fqdn in (asked of its API), or None -
        only for a module that speaks a provider's API (api_provider)."""
        if not self.api_provider:
            return None
        try:
            return self.zone_hint(fqdn)
        except Exception:                               # noqa: BLE001
            return None

    def guide(self, name):
        try:
            base = base_name(name)
        except PluginError as e:
            return guide_of([guide_step('name', 'The name can be proved by DNS-01', done=False,
                                        said=str(e), fix='Correct the name')])
        rr = '_acme-challenge.' + base
        home = self.home_of(base)
        steps = []
        fqdn = rr
        if self.flag('follow_cname'):
            chain = self.cname_chain(rr)
            if len(chain) > 1:
                fqdn = chain[-1]
                steps.append(guide_step(
                    'cname', 'The TXT record goes where _acme-challenge points',
                    where='your DNS at %s' % home,
                    record={'name': rr, 'type': 'CNAME', 'value': chain[1] + '.', 'ttl': None},
                    done=True, said='%s is a CNAME to %s' % (rr, fqdn)))
        access = self.guide_access()
        steps += access
        if self.api_provider and any(s['done'] is False for s in access):
            steps.append(guide_step('zone', 'The zone of the TXT record is at %s'
                                    % self.who_words(), where=self.who_words(), done=None,
                                    blocking=False,
                                    said='this can be checked once acme can sign in there'))
        else:
            steps += self.guide_zone(rr, fqdn, home)
        steps.append(self.guide_txt(fqdn, rr))
        steps.append(self.guide_wait())
        if self.guide_needs_dry_run:
            steps.append(guide_step(
                'try', 'A dry run shows whether the record is really put in', where='acme',
                done=None, blocking=False,
                said='%s puts the record in by means acme cannot look into beforehand'
                     % self.who_words(),
                fix='Run a dry run: a test record is put in, looked for and taken away'))
        return guide_of(steps)

    def _tested(self):
        """test() - under acme's own ctx asked once for a little while for the same
        settings (a readiness check of many names signs in once)."""
        if not limits.sharing(self.ctx):
            return self.test()
        return limits.shared(limits.key_of(self, 'access'), self.test, ttl=ACCESS_S)

    def guide_access(self):
        """The module's own test(), which changes nothing: credentials, the server."""
        where = self.who_words()
        try:
            said = self._tested()
        except PluginError as e:
            return [guide_step('access', 'acme can reach and sign in to %s' % where, where=where,
                               done=False, said=str(e),
                               fix='Correct the settings of the validation (credentials, '
                                   'address), then check again')]
        except Exception as e:                          # noqa: BLE001
            return [guide_step('access', 'acme can reach and sign in to %s' % where, where=where,
                               done=False, said='%s: %s' % (type(e).__name__, e),
                               fix='Correct the settings of the validation, then check again')]
        return [guide_step('access', 'acme can reach and sign in to %s' % where, where=where,
                           done=True, said=str(said or '').split('\n')[0][:300])]

    def guide_zone(self, rr, fqdn, home):
        """Which zone the TXT record goes in, and whether the internet asks that zone."""
        who = self.who_words()
        out = []
        if self.api_provider:
            pz = self.provider_zone(fqdn)
            if not pz:
                seen = list(getattr(self, '_zone_list', None) or [])
                rec = None
                fix = ('Add the zone of %s at %s, or give the credentials access to it' % (
                    fqdn, who))
                if seen:
                    rec = {'name': rr, 'type': 'CNAME', 'value': '%s.%s.' % (rr, seen[0]),
                           'ttl': None}
                    fix += (' - or point %s by CNAME into a zone that is there: %s. CNAME '
                            '%s.%s.' % (rr, rr, rr, seen[0]))
                out.append(guide_step('zone', 'The zone of the TXT record is at %s' % who,
                                      where=who, record=rec, done=False,
                                      said='%s is in no zone these credentials see' % fqdn,
                                      fix=fix))
                return out
            out.append(guide_step('zone', 'The zone of the TXT record is at %s' % who,
                                  where=who, done=True,
                                  said='%s goes in the zone %s' % (fqdn, pz)))
            out.append(self.guide_delegated(fqdn, pz))
            return out
        try:
            z = self.zone_for(fqdn)
        except PluginError as e:
            out.append(guide_step('zone', 'The zone of the TXT record is known', where=home,
                                  done=False, said=str(e),
                                  fix='Set the zone in the validation\'s settings'))
            return out
        out.append(guide_step('zone', 'The zone of the TXT record is known',
                              where='your DNS at %s' % z, done=True,
                              said='%s goes in the zone %s' % (fqdn, z)))
        return out

    def guide_delegated(self, fqdn, zone):
        """Is `zone` the one the internet asks for fqdn (no other zone under it,
        its name servers there)?"""
        who = self.who_words()
        seen = self.name_zone(fqdn)
        if seen and seen != D.norm(zone) and D.in_zone(seen, zone):
            return guide_step(
                'delegated', 'The internet asks %s for the record' % who,
                where='the DNS of %s' % zone, done=False,
                said='%s is in the zone %s on the internet, not in %s' % (fqdn, seen, zone),
                fix='The zone %s is delegated elsewhere: write the record there (another '
                    'validation), or take that delegation away' % seen)
        try:
            ns = D.zone_servers(zone, self.resolvers(), timeout=self.guide_timeout)
        except (D.DnsError, D.FormErr, OSError) as e:
            return guide_step('delegated', 'The internet asks %s for the record' % who,
                              where='the registry of %s' % zone, done=None, blocking=False,
                              said='the name servers of %s could not be looked up: %s'
                                   % (zone, e))
        if not ns:
            return guide_step('delegated', 'The internet asks %s for the record' % who,
                              where='the registry of %s' % zone, done=False,
                              said='the zone %s has no name servers on the internet' % zone,
                              fix='Make the registrar of %s point it at the name servers of %s'
                                  % (zone, who))
        return guide_step('delegated', 'The internet asks %s for the record' % who,
                          where='the registry of %s' % zone, done=True,
                          said='%s is answered by %s' % (zone, ', '.join(n for n, _a in ns)))

    def guide_txt(self, fqdn, rr=None):
        return guide_step('txt', 'acme writes the TXT record itself at every order',
                          where=self.who_words(),
                          record={'name': fqdn, 'type': 'TXT', 'value': '(new at every order)',
                                  'ttl': self.ttl()},
                          done=None, blocking=False,
                          said='nothing to create by hand: %s is written and taken away by '
                               'acme' % fqdn)

    def wait_words(self):
        mode = self.c('propagation', 'auth')
        how = {'auth': 'every name server of the zone has it',
               'auth+public': 'every name server of the zone, then the public resolvers have it',
               'resolvers': 'the resolvers of the validation see it',
               'none': 'nothing: the CA is asked at once'}.get(mode, mode)
        words = 'TTL %d s; before the CA looks, acme waits until %s' % (self.ttl(), how)
        if self.num('delay', 0):
            words += ' (and at least %d s)' % self.num('delay', 0)
        return words

    def guide_wait(self):
        return guide_step('wait', 'acme waits until the record can be seen', where='acme',
                          done=None, blocking=False, said=self.wait_words())

    def dry_said(self, name, handle):
        h = handle or {}
        return '%s TXT "%s"' % (h.get('fqdn') or '?', h.get('txt') or '')

    def seen_outside(self, name, handle):
        """The test value asked of the zone's name servers and of public resolvers."""
        h = handle or {}
        fqdn, rr, txt = h.get('fqdn'), h.get('rr'), h.get('txt')
        if not fqdn or not txt:
            return []
        out = []
        if rr and D.norm(rr) != D.norm(fqdn):
            # the CA asks rr and follows its CNAME: it must lead where the value is
            chain = self.cname_chain(rr)
            out.append(guide_step(
                'cname', 'The CA is led from %s to the test value' % rr,
                where='your DNS at %s' % self.home_of(base_name(name)),
                record={'name': rr, 'type': 'CNAME', 'value': D.norm(fqdn) + '.', 'ttl': None},
                done=chain[-1] == D.norm(fqdn),
                said=('%s is a CNAME to %s' % (rr, chain[-1])) if len(chain) > 1 else
                     '%s has no CNAME' % rr,
                fix='Create in your DNS: %s. CNAME %s.' % (rr, D.norm(fqdn))))
        try:
            zone = self.zone_for(fqdn)
        except PluginError:
            zone = fqdn
        try:
            ok = self.seen_by_authority(fqdn, txt)
        except PluginError as e:
            ok, self._said['auth:' + fqdn] = False, str(e)
        out.append(guide_step(
            'authoritative', 'The zone\'s own name servers answer the test value',
            where='the name servers of %s' % zone, done=ok,
            said=self._said.get('auth:' + fqdn, '') or (
                'none of them can be asked from here' if ok is None else ''),
            fix='The record is not on every name server of %s: is the zone delegated to the '
                'servers acme writes to (the NS records at its parent)?' % zone))
        pub = D.resolver('public', self.lst('public_resolvers'), self.ctx)
        have, lacking = [], []
        for srv in pub:
            try:
                m = D.ask_server(pub, srv, rr, 16, rd=True, timeout=self.guide_timeout)
            except (D.DnsError, D.FormErr, OSError):
                continue
            if m.rcode not in (D.NOERROR, D.NXDOMAIN):
                continue
            (have if txt in [r.text for r in m.answer if r.rtype == 16] else lacking).append(srv)
        state = None if not have and not lacking else not lacking
        out.append(guide_step(
            'public', 'Public resolvers see the test value at %s' % rr,
            where='asked through %s' % D.servers_words(pub), done=state, blocking=False,
            said=('seen by the resolvers %s' % ', '.join(have)) if state else
                 ('not seen by %s' % ', '.join(lacking)) if lacking else
                 'none of them answered from here',
            fix='A resolver may still keep an older answer (its TTL); the CA asks without one'))
        return out


# ---------------------------------------------------------------------------
# HTTP-01
# ---------------------------------------------------------------------------
_PUBLIC_DOWN = {}                   # the public view's servers -> not asked again until


GENERIC_DISCOVERY.add(DnsChallenge.discover_setup)


class HttpChallenge(Challenge):
    types = ('http-01',)
    vendor = 'HTTP'
    doc = 'docs/validation.md'

    def flag(self, key):
        return as_bool(self.c(key, False))

    def check_name(self, name):
        n = D.norm(name)
        if n.startswith('*.'):
            raise PluginError('%s: a wildcard can only be proved by DNS-01 - choose a DNS '
                              'challenge for it' % name, retry=False)
        if not SAFE_NAME.match(n):
            raise PluginError('"%s" is not a name acme can prove' % name, retry=False)
        return n

    @staticmethod
    def check_token(token):
        if not SAFE_TOKEN.match(str(token or '')):
            raise PluginError('a token acme will not write: %r' % token, retry=False)
        return token

    # -- any file under /.well-known/, for a commercial CA's DCV (base.Challenge.place) ----
    @staticmethod
    def dcv_path(where):
        """A path a DCV file may have: under /.well-known/, plain letters only."""
        p = '/' + str(where or '').strip().lstrip('/')
        if not re.match(r'^/\.well-known/[A-Za-z0-9_-]+(/[A-Za-z0-9_.-]+)+\Z', p) or \
                '/../' in p + '/' or '/./' in p + '/':
            raise PluginError('acme writes files only under /.well-known/, not %r' % where,
                              retry=False)
        return p

    @classmethod
    def place_problem(cls, proof, where, config, settings):
        bad = Challenge.place_problem.__func__(cls, proof, where, config, settings)
        if bad or proof != 'http-file-any':
            return bad
        w = str(where or '/.well-known/pki-validation/')
        try:
            cls.dcv_path(w + 'file.txt' if w.endswith('/') else w)
        except PluginError as e:
            return str(e)
        return ''

    def place_file(self, name, path, data):
        """Write the DCV file (a module that can): returns a handle of its own."""
        raise NotImplementedError('%s writes no files but its ACME tokens' % (self.title or
                                                                           self.kind))

    def unplace_file(self, handle):
        pass

    def place(self, kind, name, where, content):
        if kind != 'file':
            raise NotImplementedError('%s puts no %s record in place' % (self.title or self.kind,
                                                                        kind))
        n = self.check_name(name)
        path = self.dcv_path(where)
        data = str(content if content is not None else '').encode('utf-8')
        if len(data) > 8192:
            raise PluginError('a DCV file of more than 8 KiB will not be written', retry=False)
        h = self.place_file(n, path, data)
        self.ctx.step('http://%s%s put in place (%s)' % (n, path, self.title or self.kind))
        return {'kind': 'file', 'name': n, 'path': path, 'content': data.decode('utf-8'),
                'h': h}

    def placed_ready(self, handle):
        h = handle or {}
        if not self.dcv_self_check():
            return True
        ok, words = self.fetch('http://%s%s' % (h.get('name'), h.get('path')),
                               str(h.get('content') or '').strip())
        self.ctx.step(words, 'ok' if ok else 'info')
        return ok

    def dcv_self_check(self):
        return True

    def unplace(self, handle):
        h = handle or {}
        if h.get('kind') == 'file' and h.get('path'):
            self.unplace_file(h)

    def fetch(self, url, want, host=None, hops=3):
        """(True|False, words): the body at url is `want` (redirects followed
        as the CA follows them)."""
        headers = {'User-Agent': 'acme-http01-check', 'Accept': '*/*'}
        if host:
            headers['Host'] = host
        for _ in range(hops + 1):
            try:
                status, rh, body = self.ctx.http('GET', url, headers=headers, timeout=10,
                                                 verify=False, proxy=False)
            except Exception as e:                      # noqa: BLE001
                return False, '%s: %s' % (url, e)
            if status in (301, 302, 303, 307, 308):
                loc = _header(rh, 'location')
                if not loc:
                    return False, '%s: a redirect with nowhere to go' % url
                if loc.startswith('/'):
                    loc = url.split('/', 3)[0] + '//' + url.split('/', 3)[2] + loc
                url = loc
                headers.pop('Host', None)
                continue
            if status != 200:
                return False, '%s said %s' % (url, status)
            text = body.decode('utf-8', 'replace') if isinstance(body, bytes) else str(body)
            if text.strip() == want:
                return True, '%s answers with the right value' % url
            return False, '%s answers something else (%r)' % (url, text.strip()[:60])
        return False, '%s: too many redirects' % url

    # -- what a person is told (guide) and the dry run --------------------------------------
    http_port = 80                  # where the CA fetches (a test changes it)
    guide_timeout = 2.0

    def resolvers(self):
        return D.resolver('validation', (), self.ctx)

    def lookup(self, name):
        """The addresses a name has (A and AAAA, CNAMEs followed by the resolvers)."""
        try:
            return D.addresses(D.norm(name), self.resolvers(), timeout=self.guide_timeout)
        except (D.DnsError, D.FormErr, OSError):
            return []

    def lookup_public(self, name):
        """The addresses a name has as the internet sees it (Settings → DNS: the
        public view) - [] when that cannot be asked from here (then for a minute
        it is not asked again: a machine without the internet waits once)."""
        n = D.norm(name)
        try:
            servers = D.resolver('public', (), self.ctx)
        except Exception:                               # noqa: BLE001
            return []
        key = D.servers_words(servers)
        if _PUBLIC_DOWN.get(key, 0) > time.time():
            return []
        out = []
        for qt in (1, 28):
            try:
                m = D.ask_any(servers, n, qt, self.guide_timeout)
            except (D.DnsError, D.FormErr, OSError):
                if qt == 1:
                    _PUBLIC_DOWN[key] = time.time() + 60
                    return []
                continue
            out += [r.text for r in m.answer if r.rtype == qt]
        return out

    def ca_view(self, name):
        """(addresses, inside) of a name as the CA sees it. The validation's
        resolvers first; where they give private addresses only (or none) - the
        inside view of a split DNS, the server's own address behind a NAT - the
        public view is asked as well, and its public addresses are the ones the CA
        connects to. `inside`: the addresses here, when they were set aside so."""
        got = self.lookup(name)
        if got and not all(private_ip(a) for a in got):
            return got, []
        pub = [a for a in self.lookup_public(name) if not private_ip(a)]
        if pub:
            return pub, got
        return got, []

    def url(self, host, token):
        h = '[%s]' % host if ':' in host else host
        return 'http://%s%s/.well-known/acme-challenge/%s' % (
            h, '' if int(self.http_port) == 80 else ':%d' % int(self.http_port), token)

    def answering(self, name):
        """[address] of the machines that answer http://NAME/ (a module says)."""
        return []

    def guide_wildcard(self, name):
        """[step] refusing a wildcard (HTTP-01 cannot prove one), else []."""
        if D.norm(name).startswith('*.'):
            return [guide_step(
                'wildcard', 'HTTP-01 can prove this name', where='acme', done=False,
                said='%s is a wildcard: the CA proves a wildcard by DNS-01 only' % name,
                fix='Choose a DNS validation for %s (acme\'s own DNS server or your DNS '
                    'provider)' % name)]
        return []

    def guide_points(self, name, want, record_value, fix_else, soft=False):
        """The step: the name's A/AAAA are among `want` addresses."""
        got, inside = self.ca_view(name)
        n = D.norm(name)
        home = D.registrable(n)
        seen = (' (as the internet sees it; here it resolves to %s)' % ', '.join(inside)) \
            if inside else ''
        rtype = 'AAAA' if ':' in (record_value or '') else 'A'
        rec = {'name': n, 'type': rtype, 'value': record_value, 'ttl': None} \
            if record_value else None
        if not got:
            return guide_step('address', 'The name points at the machine that answers HTTP-01',
                              where='your DNS at %s' % home, record=rec, done=False,
                              said='%s has no A or AAAA record' % n,
                              fix=('Create in your DNS: %s. %s %s' % (n, rtype, record_value))
                              if record_value else 'Create an A record for %s' % n)
        hit = [a for a in got if a in set(want)]
        if hit:
            return guide_step('address', 'The name points at the machine that answers HTTP-01',
                              where='your DNS at %s' % home, record=rec, done=True,
                              said='%s resolves to %s%s' % (n, ', '.join(hit), seen))
        return guide_step('address', 'The name points at the machine that answers HTTP-01',
                          where='your DNS at %s' % home, record=rec, done=False,
                          blocking=not soft,
                          said='%s resolves to %s, not to %s%s' % (
                              n, ', '.join(got), ', '.join(want) or 'any address acme knows',
                              seen),
                          fix=fix_else)

    def dry_said(self, name, handle):
        h = handle or {}
        return self.url(D.norm(name), h.get('token') or '?')

    def seen_outside(self, name, handle):
        """The test file fetched over plain HTTP: by the name, as the CA does,
        and from each machine that should answer it, by its address (Host: NAME)."""
        h = handle or {}
        token, ka = h.get('token'), h.get('ka')
        if not token or not ka:
            return []
        n = D.norm(name)
        out = []
        ok, words = self.fetch(self.url(n, token), ka)
        out.append(guide_step('by_name', 'The test file is served at http://%s/' % n,
                              where=n, done=ok, said=words, blocking=False,
                              fix='This machine may not reach its own public name (no hairpin '
                                  'NAT); the CA asks from the internet - the steps below say '
                                  'more'))
        for addr in self.answering(name):
            ok, words = self.fetch(self.url(addr, token), ka, host=n)
            out.append(guide_step('by_address', 'The test file is served by %s' % addr,
                                  where='the web server %s' % addr, done=ok, said=words,
                                  fix='Make %s serve /.well-known/acme-challenge/ for %s on '
                                      'port %d' % (addr, n, int(self.http_port))))
        return out


def private_ip(addr):
    """Is it an address the internet cannot reach (private, loopback, link-local)?"""
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(addr).strip('[]'))
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _header(h, name):
    if not h:
        return ''
    if isinstance(h, dict):
        for k, v in h.items():
            if k.lower() == name:
                return v
        return ''
    try:
        return h.get(name) or ''
    except AttributeError:
        for k, v in h:
            if k.lower() == name:
                return v
    return ''


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------
def ssh_fields(port=22, user='root', with_hostkey=True):
    out = [
        field('user', 'User', 'text', default=user, required=True),
        field('auth', 'Signs in with', 'select', default='key',
              options=[['key', 'a private key'], ['password', 'a password']]),
        field('key', 'The SSH key', 'sshkey', secret=True, pass_key='key_pass',
              auth_key='auth', howto='linux',
              help='Made here (ed25519) or your own (OpenSSH or PEM); its public half in the '
                   'user\'s ~/.ssh/authorized_keys on the machine.'),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
    ]
    if with_hostkey:
        out += [
            field('hostkey', 'Host keys', 'list', default='',
                  placeholder='web1.example.com ssh-ed25519 AAAAC3Nza...',
                  help='Pinned host keys, as known_hosts lines (ssh-keyscan -t ed25519 HOST). '
                       'A connection to a host whose key is not this is refused.'),
            field('trust_first', 'Trust the first key seen', 'bool', default=False,
                  help='With no host key pinned: the first key seen is kept and pinned from '
                       'then on. Off: a host without a pinned key is not connected to.'),
        ]
    out.append(field('timeout', 'Timeout (s)', 'number', default=20, advanced=True))
    return out


def hostkey_for(lines, host):
    """The known_hosts line(s) for a host from the pinned list."""
    out = []
    for line in as_list(lines):
        first = line.split(None, 1)[0] if line.split() else ''
        names = [x.strip('[]').split(']:')[0] for x in first.split(',')]
        if host in names or ('[%s]' % host) in first:
            out.append(line)
    return '\n'.join(out)


def ssh_conn(plugin, host, port=22):
    c = plugin.c
    auth = c('auth', 'key')
    return {'host': host, 'port': int(port or 22), 'user': c('user', 'root'),
            'password': c('password', '') if auth == 'password' else '',
            'key': c('key', '') if auth != 'password' else '',
            'key_pass': c('key_pass', '') if auth != 'password' else '',
            'hostkey': hostkey_for(c('hostkey', ''), host),
            'trust_first': as_bool(c('trust_first', False)),
            'timeout': as_num(c('timeout', 20), 20)}


def shq(s):
    """A word for a POSIX shell."""
    s = str(s)
    if s and re.match(r'^[A-Za-z0-9_@%+=:,./-]+$', s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


# ---------------------------------------------------------------------------
# A DNS provider's API
# ---------------------------------------------------------------------------
_RMW_LOCKS = {}


def rmw_lock(key):
    """One lock per provider (and account): a module that writes a whole
    RRset (read, add ours, write back) holds it, so two orders on this node
    do not write over each other's value."""
    import threading
    return _RMW_LOCKS.setdefault(key, threading.Lock())


class ApiDns(DnsChallenge):
    """The base of the modules that speak a DNS provider's API: the zone is
    the one set, else the longest of the provider's zones the name is in
    (zone_names(), asked once), the TTL never under what the provider takes
    (min_ttl), test() lists the zones. A module writes zone_names(), add_txt
    and del_txt."""
    who = ''                        # the provider in words: 'deSEC', 'Gandi'
    min_ttl = 60
    api_provider = True

    def ttl(self):
        return max(int(self.num('ttl', self.min_ttl) or self.min_ttl), self.min_ttl)

    def zone_names(self):
        """Every zone the credentials may see (names). None: the API cannot list them."""
        raise NotImplementedError

    def _zone_names(self):
        if getattr(self, '_zone_list', None) is None:
            def ask():
                return [D.norm(z) for z in (self.zone_names() or []) if z]
            if limits.sharing(self.ctx):
                # one list for every run with the same settings, for a little while
                self._zone_list = list(limits.shared(limits.key_of(self, 'zones'), ask))
            else:
                self._zone_list = ask()
        return self._zone_list

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        best = longest_zone(fqdn, self._zone_names())
        if not best:
            raise no_zone(self.who or self.title, fqdn)
        return best

    def test(self):
        return zones_seen(self.who or self.title, self._zone_names())
