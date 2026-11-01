# -*- coding: utf-8 -*-
"""DNS-01 at Webglobe (webglobe.cz / .sk, the Yegon group), through the
Webglobe API - a REST API signed in with a JWT:

    POST   /auth/login  {login, token}  (or {login, password})
                                        {success, data: {token, token_type, expires_in, ...}}
    GET    /domains                     the domains of the account: {data: {ID: {...}}, ...}
    GET    /domains/{id or name}        one domain: {data: {domain, domain_id, ...}}
    GET    /{domainId}/dns              {data: {records: [{id, name, type, data, ttl}], soa}}
    POST   /{domainId}/dns  {name, type, data, ttl}        {new_id, data: {id, ...}}
    DELETE /{domainId}/dns/{id}

Every other call carries "Authorization: Bearer <JWT>". A refusal is HTTP
400 with {success: false, error: {code, message}}; a JWT that ran out is a
401, after which acme signs in once more. Sign-in is non-interactive only
with an API key: an account with two-factor sign-in (SMS, OTP, e-mail - codes
1034, 24, 1382) cannot sign in with its password from a machine, and a key
signs in only from the IP addresses allowed for it. Production is
https://api.webglobe.com, staging https://api.staging.core.webglobe.com.

Each value is a record of its own: present() writes one TXT record and keeps
its id; cleanup deletes that id only, and only while it still is a TXT
record holding acme's value at that name - never another record.

Source: the Webglobe API's OpenAPI description ("Webglobe API" 1.0, servers
https://api.webglobe.com/ and https://api.staging.core.webglobe.com/),
kept as test/fixtures/webglobe-openapi.yaml. How sure this is: the calls
and bodies are as that description gives them; the list of domains
(GET /domains) is described loosely (a map keyed by the domain's ID), so
it is read every way it may come, and a domain it does not show is asked
for by name (GET /domains/{name}).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, http_call,
                                                relative, suffixes, unquote_txt, zones_seen)

APIS = {'production': 'https://api.webglobe.com',
        'staging': 'https://api.staging.core.webglobe.com'}
WHO = 'Webglobe'
# the error codes of POST /auth/login
BAD_LOGIN = (5,)
SUSPENDED = (51,)
TWO_FACTOR = {1034: 'an SMS code', 24: 'a one-time password (OTP)', 1382: 'an e-mail code'}
DENIED = (3,)                               # "Access to requested module is denied"


class WebglobeError(PluginError):
    """A refusal of the Webglobe API, its error code kept."""
    def __init__(self, words, code=None, status=None, detail=None, retry=False):
        PluginError.__init__(self, words, detail=detail, retry=retry)
        self.code = code
        self.status = status


def credential_fields(required=True):
    """The sign-in of both Webglobe modules (validation and target)."""
    return [
        field('login', 'Login', 'text', required=required, placeholder='you@example.cz',
              help='The login name (e-mail) you sign in to the Webglobe administration with - '
                   'best a sub-account (My account → Users) that sees only the domains acme '
                   'needs.'),
        field('auth', 'Sign in with', 'select', default='token',
              options=[['token', 'an API key (works with two-factor sign-in)'],
                       ['password', 'the password (only an account without two-factor sign-in)']]),
        field('api_token', 'API key', 'secret', show_if={'auth': ['token']},
              help='Webglobe administration → My account → API keys → a new key for this '
                   'login: allow the public IP address (or network) acme calls from - Webglobe '
                   'refuses a key from every other, and a key without one. The key is shown '
                   'only once.'),
        field('password', 'Password', 'secret', show_if={'auth': ['password']},
              help='The login\'s password. An account with two-factor sign-in (SMS, OTP, '
                   'e-mail) cannot sign in so from a machine: use an API key.'),
        field('endpoint', 'API', 'select', default='production', advanced=True,
              options=[['production', 'api.webglobe.com'],
                       ['staging', 'api.staging.core.webglobe.com (staging)']]),
        field('api', 'API address', 'text', default='', advanced=True,
              placeholder='https://api.webglobe.com',
              help='Empty: as API above says.'),
    ]


def ascii_name(name):
    """A domain name as DNS writes it (an IDN as xn--), lower case, no dot at the end."""
    n = D.norm(str(name or ''))
    try:
        return n.encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return n


def _first(d, keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, ''):
            return v
    return None


def domain_pairs(got):
    """{name: domain ID} out of an answer of GET /domains, whatever way it
    comes: data a map ID -> name or ID -> {domain, domain_id...}, data a
    list, the paginated lists of `domains` per category, last_used_domains."""
    out = {}

    def take(item, key=None):
        if isinstance(item, str):
            name, did = item, key
        elif isinstance(item, dict):
            name = _first(item, ('domain', 'domain_name', 'name', 'domena', 'nazov'))
            did = _first(item, ('domain_id', 'domainId', 'IDdomeny', 'IDdomain', 'id')) or key
        else:
            return
        if isinstance(name, str) and '.' in name and did not in (None, '') and \
                str(did).isdigit():
            out.setdefault(ascii_name(name), int(did))

    def take_all(v):
        if isinstance(v, dict):
            for k, x in v.items():
                take(x, k)
        elif isinstance(v, list):
            for x in v:
                take(x)

    if not isinstance(got, dict):
        return out
    take_all(got.get('data'))
    for cat in (got.get('domains') or {}).values() if isinstance(got.get('domains'), dict) \
            else []:
        if isinstance(cat, dict):
            take_all(cat.get('data'))
        elif isinstance(cat, list):
            take_all(cat)
    take_all(got.get('last_used_domains'))
    return out


class WebglobeClient(object):
    """The Webglobe API for one module: signed in once a run (the JWT kept
    until it runs out), signed in once more on a 401."""

    def __init__(self, plugin):
        self.p = plugin
        self.ctx = plugin.ctx
        self.jwt = None
        self.until = 0.0
        self.me = {}
        self.lock = threading.Lock()
        self.logins = 0

    def base(self):
        own = str(self.p.c('api', '') or '').strip()
        if own:
            return own.rstrip('/')
        return APIS.get(str(self.p.c('endpoint', 'production')), APIS['production'])

    # -- one request -----------------------------------------------------------------
    def _raw(self, method, path, body=None, jwt=None):
        h = {'Accept': 'application/json', 'User-Agent': 'acme-challenge'}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h['Content-Type'] = 'application/json'
        if jwt:
            h['Authorization'] = 'Bearer ' + jwt
        st, _rh, got = http_call(self.ctx, method, self.base() + path, data, h, who=WHO)
        parsed = None
        if got:
            try:
                parsed = json.loads(got.decode('utf-8') if isinstance(got, bytes) else got)
            except (ValueError, UnicodeDecodeError):
                parsed = None
        return st, parsed, got

    @staticmethod
    def refusal(st, parsed, got, what):
        err = (parsed or {}).get('error') if isinstance(parsed, dict) else None
        code, msg = None, ''
        if isinstance(err, dict):
            code, msg = err.get('code'), str(err.get('message') or '')
        elif isinstance(err, str):
            msg = err
        elif isinstance(parsed, dict) and parsed.get('message'):
            msg = str(parsed.get('message'))
        if not msg:
            msg = (got[:300].decode('utf-8', 'replace') if isinstance(got, bytes)
                   else str(got or '')[:300]).strip() or 'nothing more'
        try:
            code = int(code) if code not in (None, '') else None
        except (TypeError, ValueError):
            code = None
        said = '%s (%s)' % (msg, code) if code is not None else msg
        words = 'Webglobe refused %s (HTTP %s): %s' % (what, st, said)
        if code in DENIED:
            words += ' - this login may not use that part of the API'
        return WebglobeError(words, code=code, status=st, detail=parsed or got,
                             retry=st >= 500 or st == 429)

    # -- signing in ----------------------------------------------------------------------
    def login(self):
        login = str(self.p.c('login', '') or '').strip()
        how = str(self.p.c('auth', 'token') or 'token')
        secret = str(self.p.c('api_token' if how == 'token' else 'password', '') or '')
        if not login or not secret:
            raise PluginError('Webglobe: set the login and %s' % (
                'the API key' if how == 'token' else 'the password'), retry=False)
        body = {'login': login}
        body['token' if how == 'token' else 'password'] = secret
        st, parsed, got = self._raw('POST', '/auth/login', body)
        self.logins += 1
        ok = isinstance(parsed, dict) and parsed.get('success') is not False
        data = (parsed or {}).get('data') if isinstance(parsed, dict) else None
        if st == 200 and ok and isinstance(data, dict) and data.get('token'):
            self.jwt = str(data['token'])
            life = data.get('expires_in')
            try:
                life = float(life)
            except (TypeError, ValueError):
                life = 600.0
            self.until = time.time() + max(min(life, 86400.0) - 30.0, 30.0)
            self.me = data
            return self.jwt
        e = self.refusal(st, parsed, got, 'the sign-in')
        if e.code in TWO_FACTOR:
            if how == 'token':
                raise WebglobeError(
                    'Webglobe asks %s at sign-in even with the API key - acme cannot give it: '
                    'sign in as a login (a sub-account) without two-factor sign-in, with its '
                    'own API key' % TWO_FACTOR[e.code], code=e.code, status=st,
                    detail=e.detail)
            raise WebglobeError(
                'the Webglobe account has two-factor sign-in (it asks %s), which acme cannot '
                'give - sign in with an API key instead (My account → API keys, acme\'s IP '
                'address allowed)' % TWO_FACTOR[e.code], code=e.code, status=st,
                detail=e.detail)
        if e.code in BAD_LOGIN or st in (401, 403):
            if how == 'token':
                raise WebglobeError(
                    'Webglobe did not take the login and API key - check both, that the key is '
                    'enabled and not expired, and that it allows the IP address acme calls '
                    'from', code=e.code, status=st, detail=e.detail)
            raise WebglobeError('Webglobe did not take the login and password - check both',
                                code=e.code, status=st, detail=e.detail)
        if e.code in SUSPENDED:
            raise WebglobeError('the Webglobe account is suspended', code=e.code, status=st,
                                detail=e.detail)
        if st == 200:
            raise WebglobeError('Webglobe answered the sign-in without a token',
                                status=st, detail=parsed or got)
        raise e

    def token(self):
        with self.lock:
            if not self.jwt or time.time() >= self.until:
                self.login()
            return self.jwt

    def call(self, method, path, body=None, what=None, quiet=()):
        """The parsed answer of a signed-in call; a 401 signs in again, once.
        A refusal whose code is in `quiet` comes back as None."""
        jwt = self.token()
        st, parsed, got = self._raw(method, path, body, jwt)
        if st == 401:
            with self.lock:
                if self.jwt == jwt:
                    self.jwt = None
            st, parsed, got = self._raw(method, path, body, self.token())
            if st == 401:
                raise WebglobeError('Webglobe signed acme in, but then did not take its token '
                                    '(401) for %s' % (what or path), status=st,
                                    detail=parsed or got)
        if 200 <= st < 300 and not (isinstance(parsed, dict) and parsed.get('success') is False):
            return parsed if parsed is not None else {}
        e = self.refusal(st, parsed, got, what or '%s %s' % (method, path.split('?')[0]))
        if e.code is not None and e.code in quiet:
            return None
        raise e

    # -- domains ------------------------------------------------------------------------------
    def domains(self):
        """{name: ID} of every domain the login sees."""
        got = self.call('GET', '/domains?per_page=1000', what='the list of domains')
        return domain_pairs(got)

    def domain(self, name):
        """(name, ID) of one domain asked for by its name, or None when the
        account has no such domain."""
        try:
            got = self.call('GET', '/domains/%s' % urllib.parse.quote(ascii_name(name)),
                            what='the domain %s' % name)
        except WebglobeError as e:
            if e.status in (400, 403, 404) and e.code not in DENIED:
                return None
            raise
        d = (got or {}).get('data') if isinstance(got, dict) else None
        if not isinstance(d, dict):
            return None
        did = _first(d, ('domain_id', 'domainId', 'IDdomeny', 'id'))
        if did in (None, '') or not str(did).isdigit():
            return None
        return ascii_name(d.get('domain') or name), int(did)

    def find(self, fqdn, listed=None):
        """(name, ID) of the longest domain of the account fqdn is in - from
        the list, else asked name by name; None when there is none."""
        listed = self.domains() if listed is None else listed
        best = None
        for n, did in listed.items():
            if D.in_zone(fqdn, n) and (best is None or len(n) > len(best[0])):
                best = (n, did)
        if best:
            return best
        for cand in suffixes(fqdn):
            if '.' not in cand:
                continue
            got = self.domain(cand)
            if got:
                return got
        return None


class Webglobe(ApiDns):
    kind = 'webglobe'
    title = 'Webglobe'
    vendor = 'Webglobe'
    who = 'Webglobe'
    min_ttl = 60
    description = 'TXT records in a domain at Webglobe (its DNS), through the Webglobe API.'
    fields = credential_fields() + [
        field('zone', 'Domain', 'text', default='', placeholder='example.cz',
              help='Empty: the longest domain of the account the name is in.'),
        field('domain_id', 'Domain ID', 'text', default='', advanced=True,
              help='The domain\'s number at Webglobe, with Domain set above. Empty: found by '
                   'its name.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True),
    ] + PROPAGATION_FIELDS

    def __init__(self, config, ctx):
        ApiDns.__init__(self, config, ctx)
        self.wg = WebglobeClient(self)
        self._ids = {}                          # zone -> domain ID
        self._listed = None

    # -- which domain ---------------------------------------------------------------------------
    def _domains(self):
        if self._listed is None:
            self._listed = self.wg.domains()
        return self._listed

    def zone_names(self):
        return list(self._domains())

    def zone_hint(self, fqdn):
        fqdn = D.norm(fqdn)
        z = ascii_name(self.c('zone', '')) if self.c('zone') else ''
        if z and D.in_zone(fqdn, z):
            if self.c('domain_id'):
                self._ids[z] = str(self.c('domain_id')).strip()
                return z
            got = self._domains().get(z)
            if got is None:
                one = self.wg.domain(z)
                got = one[1] if one else None
            if got is None:
                raise PluginError('the domain %s is not in this Webglobe account (or the login '
                                  'may not see it)' % z, retry=False)
            self._ids[z] = got
            return z
        got = self.wg.find(fqdn, self._domains())
        if not got:
            raise PluginError('the Webglobe account has no domain that %s is in - add the '
                              'domain there, give the login access to it, or set the domain'
                              % fqdn, retry=False)
        self._ids[got[0]] = got[1]
        return got[0]

    def _id(self, zone):
        if zone not in self._ids:
            self.zone_hint(zone)
        return self._ids[zone]

    # -- the records ------------------------------------------------------------------------
    def _records(self, did, zone):
        got = self.wg.call('GET', '/%s/dns' % did, what='the DNS records of %s' % zone) or {}
        data = got.get('data') if isinstance(got, dict) else None
        if not isinstance(data, dict) or ('records' not in data and not data.get('soa')):
            raise PluginError('Webglobe keeps no DNS zone for %s (its DNS is not at Webglobe?)'
                              % zone, retry=False)
        return [r for r in data.get('records') or [] if isinstance(r, dict)]

    @staticmethod
    def _at(rec, zone, rel):
        n = str(rec.get('name') or '').strip().rstrip('.').lower()
        if n in ('', '@'):
            n = '@'
        elif n == zone or n.endswith('.' + zone):
            n = relative(n, zone)
        return n == rel

    def _ours(self, recs, zone, rel, rtype, value):
        out = []
        for r in recs:
            if str(r.get('type') or '').upper() != rtype or not self._at(r, zone, rel):
                continue
            v = str(r.get('data') or '')
            same = (unquote_txt(v) == value if rtype == 'TXT'
                    else D.norm(v) == D.norm(value))
            if same and r.get('id') not in (None, ''):
                out.append(r['id'])
        return out

    def _add(self, fqdn, rtype, value):
        zone = self.zone_for(fqdn)
        did, rel = self._id(zone), relative(D.norm(fqdn), zone)
        have = self._ours(self._records(did, zone), zone, rel, rtype, value)
        if have:
            return {'zone': zone, 'did': did, 'id': have[0]}
        data = value if rtype == 'TXT' else D.norm(value) + '.'
        got = self.wg.call('POST', '/%s/dns' % did, {
            'name': rel, 'type': rtype, 'data': data, 'ttl': self.ttl()},
            what='a %s record at %s' % (rtype, D.norm(fqdn))) or {}
        rid = got.get('new_id') if isinstance(got, dict) else None
        if rid in (None, '') and isinstance(got.get('data'), dict):
            rid = got['data'].get('id')
        if rid in (None, ''):
            found = self._ours(self._records(did, zone), zone, rel, rtype, value)
            rid = found[0] if found else None
        return {'zone': zone, 'did': did, 'id': rid}

    def _del(self, fqdn, rtype, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        did = h.get('did') or self._id(zone)
        rel = relative(D.norm(fqdn), zone)
        ours = self._ours(self._records(did, zone), zone, rel, rtype, value)
        if h.get('id') not in (None, ''):
            # only the record put in - and only while it still is ours
            ours = [r for r in ours if str(r) == str(h['id'])]
        for rid in ours:
            try:
                self.wg.call('DELETE', '/%s/dns/%s' % (did, rid),
                             what='the %s record %s at %s' % (rtype, rid, D.norm(fqdn)))
            except WebglobeError as e:
                if e.status not in (400, 404):
                    raise
                if rid in self._ours(self._records(did, zone), zone, rel, rtype, value):
                    raise                       # still there: the refusal counts

    def add_txt(self, fqdn, value):
        return self._add(fqdn, 'TXT', value)

    def del_txt(self, fqdn, value, handle):
        self._del(fqdn, 'TXT', value, handle)

    def add_cname(self, fqdn, target):
        zone = self.zone_for(fqdn)
        if relative(D.norm(fqdn), zone) == '@':
            raise PluginError('a CNAME cannot be at the domain %s itself' % zone, retry=False)
        return self._add(fqdn, 'CNAME', target)

    def del_cname(self, fqdn, target, handle):
        self._del(fqdn, 'CNAME', target, handle)

    # -- trying it ------------------------------------------------------------------------------
    def test(self):
        if self.c('zone') or self.c('domain_id'):
            zone = ascii_name(self.c('zone', '')) if self.c('zone') else ''
            if zone:
                self.zone_hint(zone)
                did = self._ids[zone]
            else:
                did = str(self.c('domain_id')).strip()
            recs = self._records(did, zone or did)
            return 'Webglobe: signed in as %s; the domain %s (ID %s) has %d DNS record(s)' % (
                self.c('login'), zone or '?', did, len(recs))
        self._zone_list = [D.norm(z) for z in self._domains()]
        return zones_seen('Webglobe', self._zone_list)

    def guide_access(self):
        out = ApiDns.guide_access(self)
        for s in out:
            if s.get('done') is False:
                if 'two-factor' in s.get('said', ''):
                    s['fix'] = ('Webglobe administration → My account → API keys: make a key for '
                                'this login, allow the public IP address acme calls from, and '
                                'sign in with it (Sign in with: an API key)')
                elif 'did not take' in s.get('said', '') or 'set the login' in s.get('said', ''):
                    s['fix'] = ('Set Login to the e-mail you sign in to Webglobe with and API '
                                'key to a key of that login (My account → API keys), one that '
                                'allows the public IP address acme calls from')
                else:
                    s['fix'] = ('Correct the settings of the validation (login, API key, API), '
                                'then check again')
        return out
