# -*- coding: utf-8 -*-
"""dns-persist-01: one TXT record, set once, proves a domain for good
(draft-ietf-acme-dns-persist; Let's Encrypt announced it in February 2026).

The record names the CA and the ACME account that may issue:

    _validation-persist.example.com.  TXT  "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123; policy=wildcard"

    issuer-domain-name   one of the CA's names (the challenge object's
                         "issuer-domain-names"; Let's Encrypt: letsencrypt.org)
    accounturi=          the URL of the ACME account (required)
    policy=wildcard      the record also covers wildcards (*.example.com) and the
                         names under the domain (www.example.com) - optional
    persistUntil=        a Unix time after which the CA does not use the record -
                         optional

The syntax is the issuer-value of a CAA record (RFC 8659 4.2): the domain name,
then "; tag=value" parameters - tags compared without case, unknown ones
ignored. Several TXT records may stand at the name (one per CA account: Let's
Encrypt and its staging have different accounts); the CA takes the one that
names it and the account. There is no token and nothing per order: at an
order the client only answers the challenge (POST {}).

Until a CA offers dns-persist-01 in an authorization (Let's Encrypt has not
in production yet), the names are proved by the validation chosen as the
fallback, and the job says so. The first time a CA is seen offering it is
kept (the module's state, per CA) and shown. The orders themselves are the
probe: none is made only to look, except by "Look now" at a staging CA.

The record can be written by acme itself (1.0.21): "Write the record through"
names another DNS validation that writes TXT records (Active24, Webglobe,
Cloudflare, SSH DNS...). "Write the records to DNS" writes what is missing or
not right through its add_txt, replaces only a value acme wrote itself, never
touches anybody else's record, and keeps what it wrote (the module's state,
WRITTEN_KEY) so that "Take the records away" - and deleting the validation
with its records - removes exactly that. With "Write it by itself when
missing" an order writes a missing record first. Written or not, it is
looked up first: nothing is written twice.
See docs/validation.md.
"""
from __future__ import annotations

import hashlib
import re
import time

from acmelib.plugins.base import (Challenge, PluginError, PROOFS, field, guide_of,
                                  guide_step)
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import as_bool, as_list

CHALLENGE = 'dns-persist-01'
PREFIX = '_validation-persist.'
# The CAs' issuer domain names where the challenge object has not said them yet.
# Google Trust Services offers it since September 2026 (pki.goog).
ISSUER_DOMAINS = {'letsencrypt': ['letsencrypt.org'], 'letsencrypt-staging': ['letsencrypt.org'],
                  'google': ['pki.goog'], 'google-staging': ['pki.goog']}
LE_DIRECTORIES = ('https://acme-v02.api.letsencrypt.org/directory',
                  'https://acme-staging-v02.api.letsencrypt.org/directory')
SOON_S = 30 * 86400             # a persistUntil this close is said
TAG_RE = re.compile(r'^[A-Za-z0-9](?:-*[A-Za-z0-9])*\Z')
VALUE_RE = re.compile(r'^[\x21-\x3a\x3c-\x7e]*\Z')
DOMAIN_RE = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}\Z')
# The DNS validations that cannot hold a record that stays: acme's own DNS server
# (its records go at the end of the job), Duck DNS (one value a name), the ones
# a person or another server answers.
NOT_WRITERS = frozenset(('dns_builtin', 'duckdns', 'manual', 'dns_persist', 'acme_dns'))
WRITTEN_KEY = 'written'         # the module's state: what acme wrote, to take away exactly that
SEEN_SOON_S = 3600              # a value written this recently is not written again
VISIBLE_S = 90                  # at an order: how long a record just written is waited for


# ---------------------------------------------------------------------------
# The record: written and read
# ---------------------------------------------------------------------------
def make_value(issuer_domain, account_url, wildcard=True, persist_until=None):
    """The TXT value: 'letsencrypt.org; accounturi=URL[; policy=wildcard][; persistUntil=N]'."""
    out = '%s; accounturi=%s' % (D.norm(issuer_domain), str(account_url or '').strip())
    if wildcard:
        out += '; policy=wildcard'
    if persist_until:
        out += '; persistUntil=%d' % int(persist_until)
    return out


def parse_value(text):
    """One TXT value read: {'issuer', 'params' {tag lower case: value}, 'error'}.
    'error' says what is wrong with the syntax ('' when nothing)."""
    out = {'issuer': '', 'params': {}, 'error': ''}
    parts = str(text or '').split(';')
    issuer = parts[0].strip().lower().rstrip('.')
    if not issuer:
        out['error'] = 'no issuer domain name before the first ";"'
        return out
    if not DOMAIN_RE.match(issuer):
        out['error'] = '"%s" is not a domain name (the CA\'s issuer domain name comes first)' \
            % parts[0].strip()
        return out
    out['issuer'] = issuer
    rest = parts[1:]
    if rest and not rest[-1].strip():
        rest = rest[:-1]                    # a ";" at the end
    for p in rest:
        p = p.strip()
        if '=' not in p:
            out['error'] = '"%s" is not tag=value' % p if p else 'an empty parameter (";;")'
            return out
        tag, value = p.split('=', 1)
        tag, value = tag.strip(), value.strip()
        if not TAG_RE.match(tag):
            out['error'] = '"%s" is not a parameter name' % tag
            return out
        if not VALUE_RE.match(value):
            out['error'] = 'the value of %s has a space or a character not allowed' % tag
            return out
        if tag.lower() in out['params']:
            out['error'] = '%s is there twice' % tag
            return out
        out['params'][tag.lower()] = value
    return out


def judge(values, issuers, account_url, need_wildcard, now=None):
    """Whether one of the TXT `values` at a name lets this account issue:
    (ok, [(kind, words)], warnings). `issuers`: the CA's issuer domain names;
    `need_wildcard`: the name is a wildcard or under the record's domain (policy
    wildcard needed). kind: missing | issuer | syntax | account | policy | expired."""
    now = time.time() if now is None else now
    want = [D.norm(i) for i in issuers or [] if D.norm(i)]
    if not values:
        return False, [('missing', 'there is no TXT record at the name')], []
    parsed = [(v, parse_value(v)) for v in values]
    mine = [(v, p) for v, p in parsed if p['issuer'] and p['issuer'] in want]
    if not mine:
        broken = [p['error'] for v, p in parsed if p['error']]
        if broken:
            return False, [('syntax', 'the record cannot be read: %s' % broken[0])], []
        others = sorted({p['issuer'] for v, p in parsed if p['issuer']})
        if others:
            return False, [('issuer', 'no record names %s (the records there name %s)' % (
                ' or '.join(want) or 'this CA', ', '.join(others)))], []
        return False, [('missing', 'no dns-persist-01 record among the TXT records there')], []
    best = None
    for v, p in mine:
        probs, warns = [], []
        if p['error']:
            probs.append(('syntax', 'the record cannot be read: %s' % p['error']))
        prm = p['params']
        acct = prm.get('accounturi')
        if not acct:
            probs.append(('account', 'the record has no accounturi'))
        elif acct != str(account_url or ''):
            probs.append(('account', 'the record names the account %s, not this one (%s)' % (
                acct, account_url or '?')))
        if need_wildcard and str(prm.get('policy') or '').lower() != 'wildcard':
            probs.append(('policy', 'policy=wildcard is missing: without it the record covers '
                                    'only its own name, not wildcards or names under it'))
        until = prm.get('persistuntil')
        if until is not None:
            if not until.isdigit():
                probs.append(('syntax', 'persistUntil=%s is not a Unix time' % until))
            elif int(until) <= now:
                probs.append(('expired', 'persistUntil=%s ran out on %s' % (until, _day(int(until)))))
            elif int(until) - now < SOON_S:
                warns.append('persistUntil runs out on %s' % _day(int(until)))
        if not probs:
            return True, [], warns
        rank = (any(k == 'account' for k, _w in probs), len(probs))
        if best is None or rank < best[0]:
            best = (rank, probs, warns)
    return False, best[1], best[2]


def _day(t):
    return time.strftime('%Y-%m-%d', time.gmtime(t))


def until_ts(v):
    """A persistUntil as set: a Unix time or a day (YYYY-MM-DD, its midnight UTC);
    None when empty."""
    v = str(v or '').strip()
    if not v:
        return None
    if v.isdigit():
        return int(v)
    try:
        import calendar
        return int(calendar.timegm(time.strptime(v[:10], '%Y-%m-%d')))
    except ValueError:
        raise PluginError('"%s" is neither a day (2027-12-31) nor a Unix time' % v, retry=False)


def can_write(cls):
    """Whether a validation module can write the record (a TXT record that stays)."""
    from acmelib.plugins.challenges._common import DnsChallenge
    try:
        return bool(cls) and issubclass(cls, DnsChallenge) and cls.writes_txt() and \
            getattr(cls, 'kind', '') not in NOT_WRITERS
    except TypeError:
        return False


# ---------------------------------------------------------------------------
# The module
# ---------------------------------------------------------------------------
class DnsPersist(Challenge):
    kind = 'dns_persist'
    discovery = False               # discovery: nothing to read from an account
    title = 'DNS record set once (dns-persist-01)'
    default_name = 'dns-persist'
    vendor = 'DNS'
    doc = 'docs/validation.md'
    description = ('One TXT record at _validation-persist.DOMAIN, set once, lets acme\'s ACME '
                   'account issue for the domain, its subdomains and wildcards - nothing to put '
                   'in DNS at an order. Until the CA offers dns-persist-01, the fallback '
                   'validation proves the names.')
    types = (CHALLENGE,)
    fields = [
        field('domains', 'Domains with the record', 'list', default='',
              placeholder='example.com\nexample.org',
              help='Where the record stands: _validation-persist.DOMAIN. With "subdomains and '
                   'wildcards" on, it covers every name under the domain. Empty: each name\'s '
                   'registered domain (www.shop.example.co.uk: example.co.uk).'),
        field('wildcard', 'Cover subdomains and wildcards (policy=wildcard)', 'bool',
              default=True,
              help='On: one record at the domain covers *.DOMAIN and every name under it. Off: '
                   'a record at each name itself, and no wildcard.'),
        field('persist_until', 'Valid until (persistUntil)', 'text', default='',
              placeholder='2028-12-31',
              help='Optional: a day (or a Unix time) after which the CA no longer takes the '
                   'record. Empty: until you take the record away.'),
        field('fallback', 'Fallback validation', 'select', default='',
              options=[['', 'none']], options_from='validations',
              help='Proves the names while the CA does not offer dns-persist-01 (Let\'s '
                   'Encrypt has not in production yet), and when the record is not right. acme '
                   'switches to the record by itself once the CA offers it.'),
        field('writer', 'Write the record through', 'select', default='',
              options=[['', 'by hand']], options_from='dns_writers',
              help='A DNS validation acme already has (Active24, Webglobe, Cloudflare, SSH DNS'
                   '...) that writes TXT records in the domains: acme writes the record through '
                   'it ("Write the records to DNS") and takes away exactly what it wrote. '
                   'Empty: you set the record by hand.'),
        field('write_missing', 'Write it by itself when missing', 'bool', default=True,
              help='With a validation chosen above: at an order, a missing or wrong record is '
                   'written first (only a value acme wrote itself is replaced; other records '
                   'stay). Off: only "Write the records to DNS" writes it.'),
        field('sources', 'Sources the record is for', 'list', default='', advanced=True,
              help='The ACME sources whose accounts the record names (one record each). '
                   'Empty: every ACME source.'),
        field('issuer_domain', 'The CA\'s issuer domain name', 'text', default='',
              placeholder='letsencrypt.org', advanced=True,
              help='The name the record starts with. Empty: letsencrypt.org for Let\'s Encrypt; '
                   'for another CA, what it says in the challenge once it offers it.'),
        field('resolvers', 'Resolvers', 'list', default='', advanced=True,
              help='For looking the record up - an override. Empty: Settings → DNS (Validation '
                   'checks).'),
    ]
    actions = [
        {'key': 'record', 'label': 'Make the record',
         'help': 'The record for each ACME source, the ACME account made at the CA where '
                 'there is none yet.', 'changes': False},
        {'key': 'look', 'label': 'Look now (staging)',
         'help': 'An order made only to see whether the CA offers dns-persist-01 - at a staging '
                 'CA only; nothing is issued.', 'changes': False},
        {'key': 'check_records', 'label': 'Check the records',
         'help': 'For each domain: whether the record is there, missing, or holds another '
                 'value - nothing is changed.', 'changes': False},
        {'key': 'write_records', 'label': 'Write the records to DNS',
         'help': 'Through the validation chosen in "Write the record through": only what is '
                 'missing or not right; only a value acme wrote itself is replaced.',
         'changes': True, 'needs': 'writer'},
        {'key': 'remove_records', 'label': 'Take the records away',
         'help': 'Removes exactly the records acme wrote - records set by hand stay.',
         'confirm': 'The dns-persist-01 records acme wrote are removed from DNS. Until they are '
                    'written again, the names are proved by the fallback validation.',
         'changes': True, 'needs': 'written'},
    ]
    guide_timeout = 2.0
    persist_source = None           # the source a certificate uses (readiness sets it)

    def __init__(self, config, ctx):
        Challenge.__init__(self, config, ctx)
        self._fb = None
        self._said = set()
        self._writers = {}
        self._ensured = set()

    # -- what it can prove (acmelib/certs/compat.py) ------------------------------------
    @classmethod
    def place_problem(cls, proof, where, config, settings):
        if proof == 'acme-dns-persist-01':
            return ''
        if proof == 'acme-http-01':
            return 'an IP address cannot be proved by DNS (dns-persist-01) - choose an HTTP-01 ' \
                   'validation for it'
        if str(proof or '').startswith('acme-'):
            return 'this ACME source does not use dns-persist-01 - choose another validation'
        return ('dns-persist-01 works only with an ACME source (Let\'s Encrypt and other ACME '
                'CAs): this source checks the domain its own way (%s) - choose another '
                'validation' % PROOFS.get(proof, proof))

    # -- settings ------------------------------------------------------------------------
    def resolvers(self):
        return D.resolver('validation', as_list(self.c('resolvers', '')), self.ctx)

    def wildcard_on(self):
        v = self.config.get('wildcard')
        return True if v in (None, '') else as_bool(v)

    def until(self):
        return until_ts(self.c('persist_until', ''))

    def domains(self):
        return [D.norm(d).lstrip('*.') for d in as_list(self.c('domains', '')) if D.norm(d)]

    def base_of(self, bare):
        """The domain whose record covers `bare`: the longest one set that holds it,
        else its registered domain - with policy wildcard off, the name itself."""
        if not self.wildcard_on():
            return bare
        hits = [d for d in self.domains() if bare == d or bare.endswith('.' + d)]
        if hits:
            return max(hits, key=len)
        return D.registrable(bare)

    def say_once(self, words, level='info'):
        if words not in self._said:
            self._said.add(words)
            self.ctx.step(words, level)

    # -- the sources and the CAs ----------------------------------------------------------
    def issuer_domains_for(self, preset, directory):
        own = D.norm(self.c('issuer_domain', ''))
        if own:
            return [own]
        if preset in ISSUER_DOMAINS:
            return list(ISSUER_DOMAINS[preset])
        if directory in LE_DIRECTORIES:
            return ['letsencrypt.org']
        if 'pki.goog' in str(directory or ''):
            return ['pki.goog']
        seen = (self.ca_state(directory) or {}).get('issuer_domains') or []
        return [D.norm(x) for x in seen if D.norm(x)]

    def sources(self, register=False):
        """[{'source', 'title', 'directory', 'preset', 'account', 'issuer_domains',
        'staging', 'error', 'issuer'}] - the ACME sources whose accounts a record names."""
        want = [self.persist_source] if self.persist_source else \
            (as_list(self.c('sources', '')) or None)
        out = []
        for name, inst in self.ctx.acme_sources(want) or []:
            try:
                info = dict(inst.persist_info(register=register))
            except PluginError as e:
                info = {'error': str(e), 'directory': '', 'preset': '', 'title': name,
                        'account': None, 'staging': False}
            info['source'] = name
            info['issuer'] = inst
            info['issuer_domains'] = self.issuer_domains_for(info.get('preset'),
                                                              info.get('directory'))
            out.append(info)
        return out

    def _ca_key(self, directory):
        return 'ca:' + hashlib.sha256(str(directory or '').encode()).hexdigest()[:24]

    def ca_state(self, directory):
        got = self.ctx.kv_get(self._ca_key(directory)) if directory else None
        return got if isinstance(got, dict) else {}

    def _ca_put(self, directory, **change):
        st = dict(self.ca_state(directory))
        st.update(change)
        st['directory'] = directory
        try:
            self.ctx.kv_set(self._ca_key(directory), st)
        except Exception as e:                          # noqa: BLE001
            self.ctx.debug('the state of %s was not kept: %s' % (directory, e))
        return st

    def seen_offered(self, directory, title, issuer_domains):
        st = self.ca_state(directory)
        t = time.time()
        if not st.get('offered_since'):
            self.ctx.step('%s offers dns-persist-01 - the first time acme sees it' % title, 'ok')
        return self._ca_put(directory, title=title, offered_since=st.get('offered_since') or t,
                            offered_last=t, looked=t,
                            issuer_domains=list(issuer_domains or st.get('issuer_domains') or []))

    def seen_not_offered(self, directory, title):
        return self._ca_put(directory, title=title, looked=time.time(), not_offered_last=time.time())

    @staticmethod
    def offer_words(st, title):
        """'offered by Let's Encrypt since 2026-07-01' / 'not offered yet - last looked ...'"""
        if st.get('offered_since'):
            words = 'offered by %s since %s' % (title, _day(st['offered_since']))
            if (st.get('not_offered_last') or 0) > (st.get('offered_last') or 0):
                words += ' - not in its last order (%s)' % _day(st['not_offered_last'])
            return words
        if st.get('looked'):
            return 'not offered by %s yet - last looked %s' % (
                title, time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(st['looked'])))
        return 'not known yet whether %s offers it - its next order shows it' % title

    def offered_now(self, directory):
        st = self.ca_state(directory)
        return bool(st.get('offered_since')) and \
            (st.get('offered_last') or 0) >= (st.get('not_offered_last') or 0)

    # -- the fallback ---------------------------------------------------------------------
    def fallback_name(self):
        return str(self.c('fallback', '') or '').strip()

    def fallback_module(self):
        """The fallback validation (None when none is chosen)."""
        name = self.fallback_name()
        if not name:
            return None
        if self._fb is None:
            inst = self.ctx.validation(name)
            if inst is None:
                raise PluginError('the fallback validation %s is not there or switched off'
                                  % name, retry=False)
            if isinstance(inst, DnsPersist):
                raise PluginError('the fallback of a dns-persist-01 validation cannot be '
                                  'another one (%s)' % name, retry=False)
            self._fb = inst
        return self._fb

    # -- the record written through another validation (1.0.21) ----------------------------
    def writer_name(self):
        return str(self.c('writer', '') or '').strip()

    def write_missing_on(self):
        v = self.config.get('write_missing')
        return True if v in (None, '') else as_bool(v)

    def writer_module(self, name=None):
        """The validation that writes the record (None when none is chosen)."""
        name = str(name or self.writer_name() or '').strip()
        if not name:
            return None
        if name not in self._writers:
            inst = self.ctx.validation(name)
            if inst is None:
                raise PluginError('the validation %s that writes the record is not there or '
                                  'switched off' % name, retry=False)
            if not can_write(type(inst)):
                raise PluginError('the validation %s (%s) cannot write a TXT record that stays'
                                  % (name, getattr(inst, 'kind', '?')), retry=False)
            self._writers[name] = inst
        return self._writers[name]

    def written(self):
        """What acme wrote: [{domain, name, value, account, directory, source, via, kind,
        handle, at}]."""
        got = self.ctx.kv_get(WRITTEN_KEY)
        return [dict(x) for x in got if isinstance(x, dict)] if isinstance(got, list) else []

    def _keep_written(self, rows):
        try:
            self.ctx.kv_set(WRITTEN_KEY, list(rows) if rows else None)
        except Exception as e:                          # noqa: BLE001
            raise PluginError('what was written could not be kept: %s - take the record away '
                              'by hand when it is no longer wanted' % e)

    def record_domains(self):
        """The domains whose record is written and checked: the ones set, else those of
        the certificates this validation proves."""
        doms = self.domains()
        if doms:
            return doms, False
        out = []
        for n in self.ctx.names_using() or []:
            n = D.norm(n)
            bare = n[2:] if n.startswith('*.') else n
            if not bare or re.match(r'^[\d.:]+\Z', bare):
                continue
            try:
                d = self.base_of(bare)
            except Exception:                           # noqa: BLE001
                continue
            if d and d not in out:
                out.append(d)
        return out, True

    def wanted(self, register=False):
        """[{domain, name, value, source, title, account, directory, issuers, error}] - the
        record each source needs at each domain."""
        doms, _derived = self.record_domains()
        out = []
        for src in self.sources(register=register):
            title = src.get('title') or src['source']
            for dom in doms:
                one = {'domain': dom, 'source': src['source'], 'title': title,
                       'account': src.get('account'), 'directory': src.get('directory') or '',
                       'issuers': src.get('issuer_domains') or [], 'name': PREFIX + dom,
                       'value': None, 'error': src.get('error') or ''}
                if not one['error']:
                    rec = self.record_for(('*.' + dom) if self.wildcard_on() else dom, src)
                    one['name'], one['value'] = rec['name'], rec['value']
                    if not src.get('account'):
                        one['error'] = 'no ACME account at %s yet' % title
                    elif not rec['value']:
                        one['error'] = 'the issuer domain name of %s is not known yet' % title
                out.append(one)
        return out

    def state_of(self, want, values):
        """('present' | 'missing' | 'different', words) of one wanted record among the
        TXT values at its name."""
        if want['value'] in values:
            return 'present', 'the record is there'
        ok, probs, _w = judge(values, want['issuers'], want['account'], self.wildcard_on())
        if ok:
            return 'present', 'a record that names this account is there'
        if any(parse_value(v)['issuer'] in [D.norm(i) for i in want['issuers']]
               for v in values):
            return 'different', '; '.join(w for _k, w in probs) or 'it holds another value'
        return 'missing', 'there is no record for this CA at %s' % want['name']

    def check_records(self):
        """For each domain and source: the record wanted, what is there - read-only."""
        mine = self.written()
        rows = []
        for w in self.wanted(register=False):
            row = dict(w, state='unknown', said=w['error'], written=False, via='')
            hit = [m for m in mine if m.get('name') == w['name'] and m.get('value') == w['value']]
            if hit:
                row['written'], row['via'] = True, hit[0].get('via') or ''
            if not w['error']:
                try:
                    values = self.txt(w['name'])
                except (D.DnsError, D.FormErr, OSError) as e:
                    row['said'] = 'it could not be looked up: %s' % e
                else:
                    row['state'], row['said'] = self.state_of(w, values)
            rows.append(row)
        return rows

    def _write_one(self, wr, via, want, values, mine, say):
        """want written through wr when it is not there; acme's own older value at the
        name (the same CA) replaced. Returns 'written' | 'present' | 'soon'."""
        state, _words = self.state_of(want, values)
        old = [m for m in mine if m.get('name') == want['name'] and
               m.get('value') != want['value'] and
               (m.get('directory') == want['directory'] or m.get('source') == want['source'])]
        did = 'present'
        if state != 'present':
            soon = [m for m in mine if m.get('name') == want['name'] and
                    m.get('value') == want['value'] and
                    time.time() - float(m.get('at') or 0) < SEEN_SOON_S]
            if soon:
                say('%s: written %s, not seen in DNS yet - it takes a while' % (
                    want['name'], time.strftime('%H:%M', time.localtime(soon[0]['at']))), 'info')
                did = 'soon'
            else:
                handle = wr.add_txt(want['name'], want['value'])
                mine[:] = [m for m in mine if not (m.get('name') == want['name'] and
                                                   m.get('value') == want['value'])]
                mine.append({'domain': want['domain'], 'name': want['name'],
                             'value': want['value'], 'account': want['account'],
                             'directory': want['directory'], 'source': want['source'],
                             'via': via, 'kind': getattr(wr, 'kind', ''),
                             'handle': handle, 'at': time.time()})
                self._keep_written(mine)
                say('%s. TXT "%s" written through %s' % (want['name'], want['value'], via), 'ok')
                did = 'written'
        for o in old:
            try:
                self.writer_module(o.get('via')).del_txt(o['name'], o['value'], o.get('handle'))
            except PluginError as e:
                say('%s: acme\'s older value was not taken away: %s' % (o['name'], e), 'warn')
                continue
            mine[:] = [m for m in mine if m is not o]
            self._keep_written(mine)
            say('%s: acme\'s older value "%s" taken away' % (o['name'], o['value']), 'ok')
        return did

    def write_records(self):
        """What is missing or not right written through the chosen validation."""
        via = self.writer_name()
        if not via:
            raise PluginError('choose the validation that writes the record ("Write the '
                              'record through") and save it first', retry=False)
        wr = self.writer_module()
        doms, _derived = self.record_domains()
        if not doms:
            raise PluginError('set "Domains with the record" (no certificate uses this '
                              'validation yet)', retry=False)
        mine = self.written()
        done = {'written': 0, 'present': 0, 'soon': 0}
        bad = []
        for w in self.wanted(register=True):
            if w['error']:
                bad.append('%s (%s): %s' % (w['domain'], w['title'], w['error']))
                self.ctx.step(bad[-1], 'warn')
                continue
            try:
                values = self.txt(w['name'])
            except (D.DnsError, D.FormErr, OSError) as e:
                bad.append('%s could not be looked up: %s' % (w['name'], e))
                self.ctx.step(bad[-1], 'warn')
                continue
            try:
                done[self._write_one(wr, via, w, values, mine, self.ctx.step)] += 1
            except PluginError as e:
                bad.append('%s: %s' % (w['name'], e))
                self.ctx.step(bad[-1], 'bad')
        words = '%d written, %d there already' % (done['written'], done['present'] + done['soon'])
        if bad and not done['written'] and not done['present'] + done['soon']:
            raise PluginError('nothing written: %s' % '; '.join(bad))
        if bad:
            words += ', %d not - see every step' % len(bad)
        return words

    def remove_records(self):
        """Exactly what acme wrote taken away; a record set by hand stays."""
        mine = self.written()
        if not mine:
            return 'acme wrote no record - nothing to take away'
        gone, bad = 0, []
        for m in list(mine):
            try:
                self.writer_module(m.get('via')).del_txt(m['name'], m['value'], m.get('handle'))
            except PluginError as e:
                bad.append('%s: %s' % (m['name'], e))
                self.ctx.step(bad[-1], 'bad')
                continue
            mine = [x for x in mine if x is not m]
            self._keep_written(mine)
            gone += 1
            self.ctx.step('%s. TXT "%s" taken away through %s' % (m['name'], m['value'],
                                                                 m.get('via')), 'ok')
        if bad:
            raise PluginError('%d taken away, %d not: %s' % (gone, len(bad), '; '.join(bad)))
        return '%d record(s) taken away' % gone

    def ensure_record(self, name, account_url, issuers, directory):
        """At an order: the record of `name` written first when it is missing or not
        right (Write it by itself when missing). True when it was written now."""
        if not self.writer_name() or not self.write_missing_on() or not account_url or \
                not issuers:
            return False
        n = D.norm(name)
        bare = n[2:] if n.startswith('*.') else n
        dom = self.base_of(bare)
        want = {'domain': dom, 'name': PREFIX + dom, 'account': account_url,
                'directory': directory or '', 'source': '', 'issuers': list(issuers),
                'value': make_value(issuers[0], account_url, self.wildcard_on(), self.until())}
        key = (want['name'], want['value'])
        if key in self._ensured:
            return False
        self._ensured.add(key)
        mine = self.written()
        if any(m.get('name') == want['name'] and m.get('value') == want['value'] for m in mine):
            return False                        # written by acme already
        try:
            values = self.txt(want['name'])
        except (D.DnsError, D.FormErr, OSError) as e:
            self.ctx.step('%s could not be looked up (%s): not written now' % (want['name'], e),
                          'warn')
            return False
        if self.state_of(want, values)[0] == 'present':
            return False
        try:
            wr = self.writer_module()
            return self._write_one(wr, self.writer_name(), want, values, mine,
                                   self.ctx.step) == 'written'
        except PluginError as e:
            self.ctx.step('the dns-persist-01 record %s was not written: %s' % (want['name'], e),
                          'warn')
            return False

    def wait_visible(self, shown, issuers, account_url, seconds=VISIBLE_S):
        """A record just written looked for until it is seen (at most `seconds`)."""
        end = time.time() + seconds
        while True:
            ok, words, rr = self.check_name(shown, issuers, account_url)
            if ok or time.time() >= end or self.ctx.cancelled():
                return ok, words, rr
            time.sleep(5)

    # -- where the record is looked for, and what is there ------------------------------
    def places(self, name):
        """(bare name, wildcard, [(record name, needs policy wildcard)]): the name itself
        first, then each domain above it up to the record's domain."""
        n = D.norm(name)
        wild = n.startswith('*.')
        bare = n[2:] if wild else n
        if not bare or '*' in bare or not re.match(r'^[a-z0-9_.-]+\Z', bare):
            raise PluginError('"%s" is not a name dns-persist-01 can prove' % name, retry=False)
        top = self.base_of(bare)
        out, cur = [], bare
        while True:
            out.append((PREFIX + cur, wild or cur != bare))
            if cur == top or '.' not in cur:
                break
            cur = cur.split('.', 1)[1]
        return bare, wild, out

    auth_port = 53

    def txt(self, rr):
        """The TXT values at a name: from the zone's own name servers first (1.0.22) - a
        resolver keeps "no such record" from a look made before the record was written
        (its negative cache, often an hour), so a record just written read as missing -
        else as the validation checks' resolvers see them."""
        try:
            zone = D.find_zone(rr, self.resolvers(), timeout=self.guide_timeout)
            servers = D.zone_servers(zone, self.resolvers(), timeout=self.guide_timeout) \
                if zone else []
        except (D.DnsError, D.FormErr, OSError):
            servers = []
        for _ns, addrs in servers[:4]:
            for a in addrs[:2]:
                try:
                    return list(D.txt_at(a, rr, port=self.auth_port, timeout=self.guide_timeout))
                except (D.DnsError, D.FormErr, OSError):
                    continue
        m = D.ask_any(self.resolvers(), rr, 16, self.guide_timeout)
        if m.rcode == D.NXDOMAIN:
            return []
        return [r.text for r in m.answer if r.rtype == 16]

    def record_for(self, name, src):
        """{'name', 'type', 'value', 'ttl'} - what to set for `name` and this source
        (value None while the account or the CA's name is not known)."""
        bare, _wild, _pl = self.places(name)
        rr = PREFIX + self.base_of(bare)
        idn = (src.get('issuer_domains') or [None])[0]
        value = make_value(idn, src['account'], self.wildcard_on(), self.until()) \
            if src.get('account') and idn else None
        return {'name': rr, 'type': 'TXT', 'value': value, 'ttl': None}

    def check_name(self, name, issuers, account_url):
        """(ok, words, record name): whether the CA would take a record for
        `name` naming this account - the name itself, then the domains above it."""
        bare, wild, places = self.places(name)
        if wild and not self.wildcard_on():
            return False, 'a wildcard needs policy=wildcard - turn on "Cover subdomains and ' \
                          'wildcards"', places[0][0]
        top = PREFIX + self.base_of(bare)
        seen = []
        for rr, need in places:
            try:
                values = self.txt(rr)
            except (D.DnsError, D.FormErr, OSError) as e:
                seen.append((rr, [('lookup', 'it could not be looked up: %s' % e)]))
                continue
            ok, probs, warns = judge(values, issuers, account_url, need)
            if ok:
                return True, '%s names this account%s' % (
                    rr, ('; ' + '; '.join(warns)) if warns else ''), rr
            seen.append((rr, probs))

        def rank(item):
            # a record of this CA that is wrong says the most; else the record's own place
            kinds = {k for k, _w in item[1]}
            return 0 if kinds - {'missing', 'issuer', 'lookup'} else 1 if item[0] == top else 2
        rr, probs = min(seen, key=rank)
        return False, '%s: %s' % (rr, '; '.join(w for _k, w in probs)), rr

    # -- at an order (issuers/acme.py) -------------------------------------------------------
    def persist_choose(self, name, wild, offered, account_url, directory, title):
        """For one authorization: ('persist', the challenge object) when the CA offers
        dns-persist-01 and the record is right, else ('fallback', the fallback
        validation). Raises when neither can be used."""
        shown = ('*.' + name) if wild else name
        ch = offered.get(CHALLENGE)
        if not ch:
            self.seen_not_offered(directory, title)
            # written now, it is ready the day the CA offers dns-persist-01
            self.ensure_record(shown, account_url, self.issuer_domains_for('', directory),
                               directory)
            fb = self.fallback_module()
            if fb is None:
                raise PluginError('%s does not offer dns-persist-01 yet (it offers %s) and the '
                                  'validation %s has no fallback - choose a fallback validation'
                                  % (title, ', '.join(sorted(t for t in offered if t)) or
                                     'nothing', self.title), retry=False)
            self.say_once('the CA does not offer dns-persist-01 yet - used %s'
                          % self.fallback_name(), 'warn')
            return 'fallback', fb
        idn = [D.norm(x) for x in ch.get('issuer-domain-names') or [] if D.norm(x)]
        self.seen_offered(directory, title, idn)
        issuers = idn or self.issuer_domains_for('', directory)
        ok, words, rr = self.check_name(shown, issuers, account_url)
        if not ok and self.ensure_record(shown, account_url, issuers, directory):
            ok, words, rr = self.wait_visible(shown, issuers, account_url)
        if ok:
            self.ctx.step('%s: dns-persist-01 - %s' % (shown, words), 'ok')
            return 'persist', ch
        want = make_value((issuers or ['?'])[0], account_url, self.wildcard_on(), self.until())
        fb = self.fallback_module()
        if fb is not None:
            self.ctx.step('%s: the CA offers dns-persist-01, but %s - used %s' % (
                shown, words, self.fallback_name()), 'warn')
            self.ctx.step('the record to set: %s. TXT "%s"' % (rr, want), 'warn')
            return 'fallback', fb
        raise PluginError('%s: the CA offers dns-persist-01, but %s - set the record %s. TXT '
                          '"%s"' % (shown, words, PREFIX + self.base_of(name), want),
                          retry=False)

    # The renewer hands every name to the issuer; nothing is put in place here.
    def present(self, name, token, key_authorization, txt_value):
        raise PluginError('dns-persist-01 puts nothing in place - the record is set once '
                          '(an issuer other than ACME cannot use it)', retry=False)

    # -- what a person is told -------------------------------------------------------------
    def guide(self, name):
        steps = []
        try:
            bare, wild, _pl = self.places(name)
        except PluginError as e:
            return guide_of([guide_step('name', 'The name can be proved by dns-persist-01',
                                        done=False, said=str(e), fix='Correct the name')])
        fb_name = self.fallback_name()
        try:
            srcs = self.sources()
        except Exception as e:                          # noqa: BLE001
            srcs = []
            steps.append(guide_step('persist-source', 'acme knows the ACME sources', done=None,
                                    blocking=False, said='%s: %s' % (type(e).__name__, e)))
        if not srcs:
            steps.append(guide_step(
                'persist-source', 'An ACME source names the account the record is for',
                done=False, blocking=not fb_name,
                said='no ACME source is there%s' % (
                    (' (%s)' % self.persist_source) if self.persist_source else ''),
                fix='Add an ACME source (Let\'s Encrypt) - the record names its account'))
        all_offered = bool(srcs)
        home = 'your DNS at %s' % self.base_of(bare)
        for s in srcs:
            title = s.get('title') or s['source']
            offered = self.offered_now(s.get('directory'))
            all_offered = all_offered and offered
            if s.get('error'):
                steps.append(guide_step('persist-source', 'The source %s can be used' %
                                        s['source'], done=False, said=s['error'],
                                        blocking=not fb_name, fix='Correct the source'))
                continue
            if not s.get('account'):
                steps.append(guide_step(
                    'persist-account', 'acme has an ACME account at %s' % title,
                    where='acme', done=False, blocking=not fb_name,
                    said='the record names the account, and %s has none yet' % s['source'],
                    fix='Press "Make the record" at the validation (or acme --validation-action '
                        'NAME record): the account is made and the record shown - an order '
                        'makes it too'))
                continue
            if not s.get('issuer_domains'):
                steps.append(guide_step(
                    'persist-record', 'The dns-persist-01 record for %s' % title, where=home,
                    done=None, blocking=False,
                    said='the issuer domain name of %s is not known yet' % title,
                    fix='Set "The CA\'s issuer domain name" in the validation, or wait until the '
                        'CA offers dns-persist-01 (its challenge says it)'))
                continue
            rec = self.record_for(name, s)
            ok, words, _rr = self.check_name(name, s['issuer_domains'], s['account'])
            steps.append(guide_step(
                'persist-record', 'The dns-persist-01 record names the account at %s' % title,
                where=home, record=rec, done=ok, said=words, blocking=not fb_name,
                fix=('Press "Write the records to DNS" at the validation: %s writes %s. TXT '
                     '"%s" (other TXT records at the name stay)' % (
                         self.writer_name(), rec['name'], rec['value'])) if self.writer_name()
                else 'Set this TXT record once in your DNS (other TXT records at the name '
                     'stay - one for each account): %s. TXT "%s"' % (rec['name'], rec['value'])))
            steps.append(guide_step('persist-ca', 'The CA offers dns-persist-01', where=title,
                                    done=True if offered else None, blocking=False,
                                    said=self.offer_words(self.ca_state(s.get('directory')),
                                                          title)))
        if wild and not self.wildcard_on():
            steps.append(guide_step('persist-policy', 'The record covers wildcards', where=home,
                                    done=False, blocking=not fb_name,
                                    said='policy=wildcard is off',
                                    fix='Turn on "Cover subdomains and wildcards"'))
        if all_offered:
            return guide_of(steps)
        if not fb_name:
            steps.append(guide_step(
                'fallback', 'A fallback validation proves the names until the CA offers '
                'dns-persist-01', done=False,
                said='no fallback validation is chosen',
                fix='Choose a fallback validation (DNS-01 or HTTP-01) in this validation'))
            return guide_of(steps)
        try:
            fb = self.fallback_module()
        except PluginError as e:
            steps.append(guide_step('fallback', 'The fallback validation can be used', done=False,
                                    said=str(e), fix='Choose another fallback validation'))
            return guide_of(steps)
        if wild and 'dns-01' not in (getattr(fb, 'types', ()) or ()):
            steps.append(guide_step('fallback', 'The fallback validation proves %s' % name,
                                    done=False, said='a wildcard needs DNS-01, and %s is not'
                                    % fb_name, fix='Choose a DNS-01 fallback validation'))
            return guide_of(steps)
        steps.append(guide_step('fallback', 'Until the CA offers dns-persist-01, %s proves the '
                                'names' % fb_name, where='acme', done=None, blocking=False,
                                said='its steps follow'))
        try:
            steps += list((fb.guide(name) or {}).get('steps') or [])
        except Exception as e:                          # noqa: BLE001
            steps.append(guide_step('guide', 'The fallback validation can say what it needs',
                                    done=None, blocking=False, said='%s: %s' % (type(e).__name__,
                                                                                e)))
        return guide_of(steps)

    def dry_run(self, name, wait=None):
        """Nothing to put in place: the record is looked up (the guide), and the
        fallback tried for real while a CA does not offer dns-persist-01."""
        g = self.guide(name)
        for st in g['steps']:
            lvl = 'ok' if st['done'] is True else ('bad' if st['blocking'] else
                                                   'warn' if st['done'] is False else 'info')
            self.ctx.step(st['what'], lvl)
            if st['said']:
                self.ctx.step(st['said'], 'info')
        fb = None
        try:
            fb = self.fallback_module()
        except PluginError:
            pass
        if fb is not None and not all(self.offered_now(s.get('directory'))
                                      for s in self.sources() or [{}]):
            self.ctx.step('the fallback %s is tried' % self.fallback_name())
            got = fb.dry_run(name, wait)
            steps = [s for s in g['steps'] if s.get('key', '').startswith('persist')]
            return guide_of(steps + list(got.get('steps') or []))
        return g

    def overview(self, register=False, check=True):
        """For the page and the command line: each source's record, whether it is
        there, and whether its CA offers dns-persist-01."""
        names, derived = self.record_domains()
        mine = self.written()
        recs, cas = [], {}
        for s in self.sources(register=register):
            title = s.get('title') or s['source']
            d = s.get('directory') or ''
            if d and d not in cas:
                st = self.ca_state(d)
                cas[d] = {'directory': d, 'title': title, 'sources': [],
                          'offered_since': st.get('offered_since'),
                          'offered_last': st.get('offered_last'), 'looked': st.get('looked'),
                          'offered': self.offered_now(d), 'staging': bool(s.get('staging')),
                          'words': self.offer_words(st, title)}
            if d:
                cas[d]['sources'].append(s['source'])
            for dom in names or ['']:
                one = {'source': s['source'], 'title': title, 'account': s.get('account'),
                       'issuer_domains': s.get('issuer_domains') or [], 'error': s.get('error')
                       or '', 'domain': dom, 'record': None, 'ok': None, 'said': ''}
                if dom and not one['error']:
                    rec = self.record_for(('*.' + dom) if self.wildcard_on() else dom, s)
                    one['record'] = rec
                    if not s.get('account'):
                        one['said'] = 'no ACME account at %s yet - "Make the record" makes it' \
                            % title
                    elif not rec['value']:
                        one['said'] = 'the issuer domain name of %s is not known yet' % title
                    elif check:
                        ok, words, _rr = self.check_name(('*.' + dom) if self.wildcard_on()
                                                         else dom, s['issuer_domains'],
                                                         s['account'])
                        one['ok'], one['said'] = ok, words
                        try:
                            want = {'name': rec['name'], 'value': rec['value'],
                                    'issuers': s['issuer_domains'], 'account': s['account']}
                            one['state'] = self.state_of(want, self.txt(rec['name']))[0]
                        except (D.DnsError, D.FormErr, OSError):
                            one['state'] = 'unknown'
                    hit = [m for m in mine if m.get('name') == rec['name'] and
                           m.get('value') == rec['value']]
                    one['written'] = bool(hit)
                    one['via'] = hit[0].get('via') if hit else ''
                recs.append(one)
        return {'records': recs, 'cas': list(cas.values()), 'domains': names,
                'derived': derived, 'fallback': self.fallback_name(),
                'wildcard': self.wildcard_on(), 'persist_until': self.until(),
                'writer': self.writer_name(), 'write_missing': self.write_missing_on(),
                'written': [{k: m.get(k) for k in ('domain', 'name', 'value', 'via', 'at',
                                                   'source')} for m in mine]}

    def overview_lines(self, got):
        out = []
        for r in got['records']:
            rec = r.get('record') or {}
            if r.get('error'):
                out.append('%s: %s' % (r['source'], r['error']))
            elif rec.get('value'):
                out.append('%s: %s. TXT "%s"%s' % (r['source'], rec['name'], rec['value'], (
                    ' - %s' % r['said']) if r.get('said') else ''))
            elif r.get('said'):
                out.append('%s: %s' % (r['source'], r['said']))
        for c in got['cas']:
            out.append('dns-persist-01: %s' % c['words'])
        return out

    def test(self):
        """What is ready and, in words, what is still to do (1.0.22) - as a list of
        steps, not one line of everything: failed only when a certificate would fail."""
        got = self.overview(register=False, check=True)
        if not got['records']:
            raise PluginError('there is no ACME source: the record names an ACME account',
                              retry=False)
        lines = self.overview_lines(got)
        if not got['domains']:
            return '; '.join(['set "Domains with the record" to check them'] + lines)
        for line in lines:
            self.ctx.step(line)
        fb, writer = self.fallback_name(), self.writer_name()
        auto = bool(writer) and self.write_missing_on()
        todo, blocking = [], False
        for r in got['records']:
            rec = r.get('record') or {}
            if r.get('error'):
                todo.append('%s: %s' % (r['title'], r['error']))
                blocking = True
            elif not r.get('account'):
                todo.append('%s: no ACME account there yet - it is made at the first order, '
                            'or now with "Make the record"' % r['title'])
            elif r.get('ok') is False:
                if writer:
                    todo.append('%s: the record is not in DNS yet - "Write the records to DNS" '
                                'writes it through %s%s' % (
                                    r['title'], writer,
                                    ' (or it is written by itself at the next order)'
                                    if auto else ''))
                    blocking = blocking or not auto
                else:
                    todo.append('%s: put this record in DNS: %s. TXT "%s" (or choose a '
                                'validation in "Write the record through")' % (
                                    r['title'], rec.get('name'), rec.get('value')))
                    blocking = True
        for c in got['cas']:
            if c.get('offered'):
                continue
            if fb:
                self.ctx.step('%s does not offer dns-persist-01 (yet): %s proves the names '
                              'meanwhile' % (c['title'], fb), 'info')
            elif c.get('looked'):
                todo.append('%s: does not offer dns-persist-01 yet - choose a "Fallback '
                            'validation" (such as %s) to prove the names meanwhile'
                            % (c['title'], writer or 'a DNS validation'))
                blocking = True
            else:
                # not looked yet: the first order shows it - said, not a failure
                todo.append('%s: whether it offers dns-persist-01 is not known yet ("Look now" '
                            'at a staging CA, or the first order shows it) - a "Fallback '
                            'validation" makes the order safe either way' % c['title'])
        if not todo:
            return 'the record is right: %s' % '; '.join(lines)
        for i, t in enumerate(todo, 1):
            self.ctx.step('to do %d: %s' % (i, t), 'bad' if blocking else 'warn')
        words = ' · '.join('%d) %s' % (i, t) for i, t in enumerate(todo, 1))
        if blocking:
            raise PluginError('not ready yet - %s' % words, retry=False)
        records_ok = all(r.get('ok') for r in got['records'])
        return ('the record is right; still - %s' if records_ok else
                'works now; still to do - %s') % words

    def action(self, key):
        if key == 'check_records':
            rows = self.check_records()
            if not rows:
                raise PluginError('nothing to check: set "Domains with the record" and add an '
                                  'ACME source', retry=False)
            for r in rows:
                lvl = {'present': 'ok', 'missing': 'warn', 'different': 'warn'}.get(
                    r['state'], 'info')
                self.ctx.step('%s (%s): %s - %s%s' % (r['name'], r['title'], {
                    'present': 'there', 'missing': 'missing', 'different': 'another value',
                    'unknown': 'not known'}[r['state']], r['said'],
                    (' (written by acme through %s)' % r['via']) if r['written'] else ''), lvl)
            n = sum(1 for r in rows if r['state'] == 'present')
            return '%d of %d record(s) there' % (n, len(rows))
        if key == 'write_records':
            return self.write_records()
        if key == 'remove_records':
            return self.remove_records()
        if key == 'record':
            got = self.overview(register=True, check=bool(self.domains()))
            if not got['records']:
                raise PluginError('there is no ACME source: the record names an ACME account',
                                  retry=False)
            if not got['domains']:
                got['domains'] = ['DOMAIN']
                for r in got['records']:
                    src = {'account': r['account'], 'issuer_domains': r['issuer_domains']}
                    r['record'] = {'name': PREFIX + 'DOMAIN', 'type': 'TXT', 'value': make_value(
                        r['issuer_domains'][0], r['account'], self.wildcard_on(), self.until())
                        if src['account'] and r['issuer_domains'] else None}
            lines = self.overview_lines(got)
            for line in lines:
                self.ctx.step(line, 'ok')
            return '; '.join(lines)
        if key == 'look':
            doms = self.domains()
            if not doms:
                raise PluginError('set "Domains with the record": the order to look is for one '
                                  'of them', retry=False)
            said = []
            for s in self.sources():
                title = s.get('title') or s['source']
                if not s.get('staging'):
                    said.append('%s: not asked - an order only to look is made at a staging CA '
                                'only; its next real order shows it' % title)
                    continue
                got = s['issuer'].persist_probe(doms[0])
                if CHALLENGE in got['types']:
                    self.seen_offered(s['directory'], title, got['issuer_domains'])
                else:
                    self.seen_not_offered(s['directory'], title)
                said.append('%s: %s (it offers %s)' % (
                    title, self.offer_words(self.ca_state(s['directory']), title),
                    ', '.join(got['types']) or 'nothing'))
            for w in said:
                self.ctx.step(w)
            return '; '.join(said) or 'there is no ACME source'
        return Challenge.action(self, key)
