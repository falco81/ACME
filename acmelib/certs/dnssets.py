# -*- coding: utf-8 -*-
"""
Settings → DNS: named sets of DNS servers, and which of them each function of
acme asks (docs/dns-sets.md).

    sets(store)                      every set: the built-in "The system's"
                                     (/etc/resolv.conf, read as the engine reads
                                     it) first, then the table dns_sets
    save_set(store, b, by)           a set added or changed (b: name, old_name,
                                     servers, protocol, tls_name, timeout, note)
    delete_set(store, name, by)      a set taken away - the functions it was
                                     chosen for go back to their default
    assign(store, purpose, name, by) a function given a set ('' its default)
    dns_set_for(purpose, store=None) -> (name, how): the set a function asks
                                     (how: assigned | legacy | default)
    resolver(purpose, store=None)    -> Resolver: that set, ready to ask
    test(store, name|draft, qname, qtype)  a name looked up through a set,
                                     every server of it, with timings
    scope(purpose, store=None)       with scope('apis'): the names this thread
                                     looks up through socket.getaddrinfo (HTTPS
                                     to a CA, a DNS API, a target) are asked of
                                     that set - as the engine's acme_dns_scope()
                                     does for the appliance's own ACME

A Resolver is a list of servers ('192.0.2.53', '192.0.2.53:5353',
'[2001:db8::53]:53') that also knows how to ask them (UDP with TCP when cut
short, TCP only, DNS over TLS): every function of _dns.py that takes a list of
resolvers takes one (_dns.ask_any hands the question to it), and a module's own
'resolvers' field is still a plain list - an override of the set.

The sets are kept in the tables dns_sets and dns_set_uses (schema.py), so a
backup, the configuration's export and the other node of a cluster carry them
as everything else. The answers are read from the database at most every
CACHE_S seconds.

The order, for a function: a set chosen for it here; else the setting it had
before this card (acme_resolvers for validation checks and the appliance's own
ACME, mail_dns for mail - so an installation that set those goes on as it
did); else its default ("Public" for the public view, "The system's" for the
others).
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import struct
import threading
import time

from acmelib import engine as E
from acmelib.certs import store as S
from acmelib.plugins.challenges import _dns as D

TABLE = 'dns_sets'
USES = 'dns_set_uses'
SYSTEM = "The system's"
PUBLIC = 'Public'
PUBLIC_SERVERS = ('1.1.1.1', '8.8.8.8', '9.9.9.9')
OLD_PUBLIC_DEFAULT = ['1.1.1.1', '8.8.8.8', '9.9.9.9']    # the modules' field default before
PROTOCOLS = {'udp': 'UDP, TCP when an answer is cut short',
             'tcp': 'TCP only',
             'dot': 'DNS over TLS (port 853)'}
DEFAULT_TIMEOUT = 3.0
MOST_SERVERS = 8
CACHE_S = 5.0
SEEDED = 'dnssets:seeded'
QTYPES = ('A', 'AAAA', 'TXT', 'CNAME', 'NS', 'MX', 'SOA', 'CAA', 'SRV', 'PTR')

# The functions of acme that look names up: (key, title, default set, what it
# is used for, the legacy setting that served it before, or '').
PURPOSES = [
    ('validation', 'Validation checks', SYSTEM,
     'The guides, the readiness of a certificate and the check before the CA is asked, '
     'dry runs, and the wait for a DNS record: the CNAME at _acme-challenge, the zone '
     '(SOA) and its name servers (NS), the TXT record, the address a name points at for '
     'HTTP-01.', 'acme_resolvers'),
    ('public', 'The public view', PUBLIC,
     'The internet as a CA sees it: whether public resolvers see the test value of a dry '
     'run, and the delegation of acme\'s own DNS server.', ''),
    ('apis', 'CAs and APIs', SYSTEM,
     'The names of the HTTPS addresses acme reaches: ACME directories, DNS providers\' '
     'APIs, commercial CAs\' APIs.', ''),
    ('targets', 'Targets', SYSTEM,
     'The names of the targets and servers acme reaches over SSH or their API when it '
     'deploys a certificate or puts a file in place.', ''),
    ('acme', 'The appliance\'s own ACME', SYSTEM,
     'Settings → Automatic certificates: the CA of this server\'s own certificates, its '
     'DNS API, and whether the TXT record is seen. Asked over port 53 (UDP, then TCP).',
     'acme_resolvers'),
    ('mail', 'Mail going direct', SYSTEM,
     'Settings → Mail sending straight to the recipients\' servers: their MX records and '
     'addresses. Asked over port 53 (UDP, then TCP).', 'mail_dns'),
]
PURPOSE_KEYS = [p[0] for p in PURPOSES]
LEGACY_WORDS = {'acme_resolvers': '"DNS servers for ACME"',
                'mail_dns': '"DNS servers for the recipients\u2019 domains"'}
# What is always looked up as the machine looks names up (/etc/hosts too).
FIXED = ('The database, the other node of a cluster, the proxy, Active Directory, syslog '
         'and isemon, SNMP, the backups\' destinations and the names in the firewall\'s '
         'rules: always the system\'s resolver (/etc/hosts, nsswitch), whatever is chosen '
         'here - a name inside your network that a public resolver does not know.')

_CACHE = {'at': 0.0, 'sets': None, 'uses': None, 'store': None}
_LOCK = threading.Lock()
_BUSY = threading.local()


# ---------------------------------------------------------------------------
# The servers of a set
# ---------------------------------------------------------------------------
def parse_server(text, port=53):
    """'192.0.2.1', '192.0.2.1:5353', '[2001:db8::1]:53', '2001:db8::1' -> (address, port).
    An address only: a DNS server is not looked up by name."""
    s = str(text or '').strip()
    if not s:
        raise ValueError('an empty line')
    host, p = D.split_hostport(s, port)
    try:
        host = str(ipaddress.ip_address(host.split('%')[0]))
    except ValueError:
        raise ValueError('%s is not an IPv4 or IPv6 address (with :port if not %d)' % (s, port))
    if not 0 < int(p) < 65536:
        raise ValueError('%s: the port is 1 to 65535' % s)
    return host, int(p)


def server_text(host, port, default=53):
    if int(port) == int(default):
        return host
    return ('[%s]:%d' % (host, port)) if ':' in host else '%s:%d' % (host, port)


def clean_servers(v, protocol='udp'):
    lines = v if isinstance(v, (list, tuple)) else re.split(r'[\n,;]+', str(v or ''))
    default = 853 if protocol == 'dot' else 53
    out = []
    for line in lines:
        line = str(line).strip()
        if not line or line.startswith('#'):
            continue
        host, port = parse_server(line, default)
        t = server_text(host, port, default)
        if t not in out:
            out.append(t)
    if not out:
        raise ValueError('a set needs at least one DNS server, an address a line')
    if len(out) > MOST_SERVERS:
        raise ValueError('at most %d servers in a set' % MOST_SERVERS)
    return out


class Resolver(list):
    """The servers of a set, and how they are asked. A list of their texts -
    so whatever took a list of resolvers takes it - with `name` (the set's),
    `protocol`, `timeout` (None: the caller's), `tls_name` and `system`."""

    def __init__(self, servers, protocol='udp', timeout=None, tls_name='', name='',
                 system=False, how=''):
        list.__init__(self, [str(s) for s in servers or []])
        self.protocol = protocol if protocol in PROTOCOLS else 'udp'
        self.timeout = float(timeout) if timeout else None
        self.tls_name = str(tls_name or '').strip()
        self.name = name
        self.system = bool(system)
        self.how = how

    @property
    def default_port(self):
        return 853 if self.protocol == 'dot' else 53

    def label(self):
        """'Public' (1.1.1.1, 8.8.8.8) - how a guide says what it asked."""
        return '\'%s\' (%s)' % (self.name, ', '.join(self)) if self.name else ', '.join(self)

    def ask_one(self, srv, name, qtype, timeout=None, rd=True):
        """One server of the set asked, the set's way: the answer, parsed."""
        host, port = D.split_hostport(srv, self.default_port)
        t = self.timeout or timeout or DEFAULT_TIMEOUT
        if self.protocol == 'dot':
            return _ask_tls(host, port, name, qtype, t, rd, self.tls_name)
        return D.query(host, name, qtype, port=port, timeout=t, rd=rd,
                       tcp=self.protocol == 'tcp')

    def ask_any(self, name, qtype, timeout=None, rd=True, port=53):
        """The first usable answer (NOERROR or NXDOMAIN), as _dns.ask_any."""
        last = None
        for srv in self:
            try:
                m = self.ask_one(srv, name, qtype, timeout, rd)
            except (D.DnsError, D.FormErr, OSError, ssl.SSLError) as e:
                last = e
                continue
            if m.rcode in (D.NOERROR, D.NXDOMAIN):
                return m
            last = D.DnsError('%s said %s' % (srv, D.RCODES.get(m.rcode, m.rcode)))
        raise D.DnsError('no DNS server of %s answered for %s (%s)' % (
            '\'%s\'' % self.name if self.name else 'the set', name, last or 'none asked'))

    def addresses(self, host, family=0, timeout=None):
        """[addresses] of a name (A and AAAA, its CNAMEs followed by the server)."""
        try:
            return [str(ipaddress.ip_address(str(host).strip('[]')))]
        except ValueError:
            pass
        out = []
        for qt, fam in ((1, socket.AF_INET), (28, socket.AF_INET6)):
            if family not in (0, socket.AF_UNSPEC, fam):
                continue
            try:
                m = self.ask_any(D.norm(host), qt, timeout)
            except D.DnsError:
                continue
            out += [r.text for r in m.answer if r.rtype == qt]
        return out


def _ask_tls(host, port, name, qtype, timeout, rd=True, tls_name=''):
    """DNS over TLS (RFC 7858): the TCP framing inside TLS, the server's
    certificate checked against its name (or its address)."""
    q = D.make_query(name, qtype, rd=rd).to_wire()
    ctx = ssl.create_default_context()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise D.DnsError('cannot connect to %s:%d: %s' % (host, port, e))
    try:
        with ctx.wrap_socket(raw, server_hostname=tls_name or host) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack('>H', len(q)) + q)
            n = struct.unpack('>H', D._recv_exact(s, 2))[0]
            data = D._recv_exact(s, n)
    except ssl.SSLError as e:
        raise D.DnsError('%s:%d over TLS: %s' % (host, port, getattr(e, 'reason', None) or e))
    except socket.timeout:
        raise D.DnsError('no answer from %s:%d over TLS' % (host, port))
    finally:
        try:
            raw.close()
        except OSError:
            pass
    if data[:2] != q[:2]:
        raise D.DnsError('%s answered another question over TLS' % host)
    try:
        return D.parse(data)
    except D.FormErr as e:
        raise D.DnsError('%s sent an answer that cannot be read: %s' % (host, e))


# ---------------------------------------------------------------------------
# What is kept
# ---------------------------------------------------------------------------
def _store(store=None):
    return store or E.HA_STORE.get('store')


def forget():
    with _LOCK:
        _CACHE.update(at=0.0, sets=None, uses=None, store=None)


def _row_view(r):
    proto = r.get('protocol') if r.get('protocol') in PROTOCOLS else 'udp'
    return {'name': r['name'], 'builtin': False,
            'servers': [x for x in str(r.get('servers') or '').split('\n') if x.strip()],
            'protocol': proto, 'tls_name': r.get('tls_name') or '',
            'timeout': float(r.get('timeout_s') or DEFAULT_TIMEOUT),
            'note': r.get('note') or '', 'updated': r.get('updated'),
            'updated_by': r.get('updated_by') or r.get('created_by') or ''}


def system_view():
    return {'name': SYSTEM, 'builtin': True, 'servers': D.system_resolvers(),
            'protocol': 'udp', 'tls_name': '', 'timeout': DEFAULT_TIMEOUT,
            'note': 'The machine\'s own DNS servers, read from /etc/resolv.conf each time '
                    '(Settings → Network sets them).'}


def _load(store=None):
    """({name: set view}, {purpose: set name}) - from the database at most every
    CACHE_S seconds. Asked again while it is being read (a database reached by
    name, inside a scope): nothing known, so nothing redirected."""
    t = time.monotonic()
    st = _store(store)
    if st is None:
        return {}, {}
    with _LOCK:
        if _CACHE['sets'] is not None and t - _CACHE['at'] < CACHE_S and \
                _CACHE['store'] is st:
            return _CACHE['sets'], _CACHE['uses']
    if getattr(_BUSY, 'on', False):
        return {}, {}
    _BUSY.on = True
    try:
        sets = {r['name']: _row_view(r) for r in st.db.rows(
            'SELECT * FROM %s ORDER BY name' % TABLE)}
        uses = {r['purpose']: r['set_name'] for r in st.db.rows(
            'SELECT purpose, set_name FROM %s' % USES) if r.get('purpose') in PURPOSE_KEYS}
    except Exception:                                   # noqa: BLE001 - no table yet
        return {}, {}
    finally:
        _BUSY.on = False
    with _LOCK:
        _CACHE.update(at=t, sets=sets, uses=uses, store=st)
    return sets, uses


def ensure(store):
    """The suggested set "Public" made once, at the first start - deleted, it
    stays deleted."""
    try:
        if store.get_meta(SEEDED):
            return
        if not store.db.value('SELECT COUNT(*) FROM %s WHERE name = ?' % TABLE, (PUBLIC,), 0):
            store.db.insert(TABLE, {
                'name': PUBLIC, 'servers': '\n'.join(PUBLIC_SERVERS), 'protocol': 'udp',
                'tls_name': '', 'timeout_s': DEFAULT_TIMEOUT,
                'note': 'Cloudflare, Google and Quad9: the internet as a CA sees it.',
                'created': time.time(), 'created_by': 'acme', 'updated': time.time(),
                'updated_by': 'acme'})
        store.set_meta(SEEDED, str(int(time.time())))
    except Exception as e:                              # noqa: BLE001
        E.log('DNS sets: the set Public could not be made: %s' % e, 'warn')
    forget()


def sets(store):
    got, _uses = _load(store)
    return [system_view()] + [got[k] for k in sorted(got, key=str.lower)]


def purposes(store):
    sets_, uses = _load(store)
    out = []
    for key, title, default, says, legacy in PURPOSES:
        name, how = dns_set_for(key, store)
        out.append({'key': key, 'title': title, 'default': _default_of(key, sets_),
                    'says': says, 'set': name, 'how': how, 'chosen': uses.get(key, ''),
                    'legacy': legacy, 'legacy_value': ', '.join(_legacy(legacy))})
    return out


def _default_of(purpose, sets_):
    want = dict((p[0], p[2]) for p in PURPOSES).get(purpose, SYSTEM)
    if want != SYSTEM and want not in sets_:
        return SYSTEM if purpose != 'public' else want
    return want


def _legacy(key, settings=None):
    """The servers of a setting from before this card (acme_resolvers, mail_dns):
    addresses, with :port where one is said."""
    if not key:
        return []
    src = settings if settings is not None else E.CONFIG
    out = []
    for w in re.split(r'[\s,;]+', str((src or {}).get(key) or '')):
        try:
            host, port = parse_server(w)
        except ValueError:
            continue
        out.append(server_text(host, port))
    return out


def dns_set_for(purpose, store=None, settings=None):
    """(the name of the set the function asks, how it was chosen): 'assigned'
    here, 'legacy' (its setting from before this card - the name is then that
    setting's), or 'default'."""
    if purpose not in PURPOSE_KEYS:
        raise ValueError('acme does not look names up for %r (%s)' % (
            purpose, ', '.join(PURPOSE_KEYS)))
    sets_, uses = _load(store)
    chosen = uses.get(purpose)
    if chosen and (chosen == SYSTEM or chosen in sets_):
        return chosen, 'assigned'
    legacy = dict((p[0], p[4]) for p in PURPOSES)[purpose]
    if _legacy(legacy, settings):
        return 'the setting %s' % LEGACY_WORDS.get(legacy, legacy), 'legacy'
    return _default_of(purpose, sets_), 'default'


def resolver_of(name, store=None, purpose=''):
    """The Resolver of a set by its name (SYSTEM: /etc/resolv.conf). None: no such set."""
    if name == SYSTEM:
        return Resolver(D.system_resolvers(), name=SYSTEM, system=True)
    sets_, _uses = _load(store)
    v = sets_.get(name)
    if v is None:
        if name == PUBLIC and purpose == 'public':
            return Resolver(PUBLIC_SERVERS, name=PUBLIC)
        return None
    return Resolver(v['servers'], v['protocol'], v['timeout'], v['tls_name'], name=name)


def resolver(purpose, store=None, settings=None):
    """The Resolver a function asks (see dns_set_for). `settings`: where the
    settings of before are read (a module's ctx.settings), else the engine's."""
    name, how = dns_set_for(purpose, store, settings)
    if how == 'legacy':
        legacy = dict((p[0], p[4]) for p in PURPOSES)[purpose]
        return Resolver(_legacy(legacy, settings), name=name, how=how)
    got = resolver_of(name, store, purpose)
    if got is None:
        got = Resolver(PUBLIC_SERVERS, name=PUBLIC) if purpose == 'public' else \
            Resolver(D.system_resolvers(), name=SYSTEM, system=True)
    got.how = how
    return got


def for_module(purpose, given=(), ctx=None):
    """What a module asks: its own field (`given`, an override) when it says
    something, else the set of the function. The modules' old default of
    their public resolvers field (1.1.1.1, 8.8.8.8, 9.9.9.9) counts as said
    nothing."""
    given = [str(x).strip() for x in (given or []) if str(x).strip()]
    if given and not (purpose == 'public' and given == OLD_PUBLIC_DEFAULT):
        return given
    s = getattr(ctx, 'settings', None)
    return resolver(purpose, getattr(ctx, 'store', None), s if isinstance(s, dict) else None)


def engine_servers(purpose):
    """For the engine's own DNS client (port 53, UDP then TCP): the addresses of
    the set chosen here for the function, [] for the system's own, None when
    nothing is chosen here (the engine then does as it did)."""
    try:
        sets_, uses = _load()
    except Exception:                                   # noqa: BLE001
        return None
    chosen = uses.get(purpose)
    if not chosen:
        return None
    if chosen == SYSTEM:
        return []
    v = sets_.get(chosen)
    if v is None:
        return None
    out = []
    for s in v['servers']:
        host, port = D.split_hostport(s, 53)
        if port == 53:
            out.append(host)
    return out or None


def where_used(store):
    """{set name: [purpose titles]} - the card's "where each set is used"."""
    out = {}
    for p in purposes(store):
        if p['how'] == 'legacy':
            continue
        out.setdefault(p['set'], []).append(p['title'])
    return out


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------
def _num(v, lo, hi, what):
    try:
        x = float(v)
    except (TypeError, ValueError):
        raise ValueError('%s is a number' % what)
    if not lo <= x <= hi:
        raise ValueError('%s is %s to %s' % (what, lo, hi))
    return x


def clean(b):
    name = str(b.get('name') or '').strip()
    if name == SYSTEM:
        raise ValueError('"%s" is built in: it cannot be changed' % SYSTEM)
    name = S.clean_name(name, 'the name of the set')
    protocol = str(b.get('protocol') or 'udp').strip().lower()
    if protocol not in PROTOCOLS:
        raise ValueError('the protocol is one of %s' % ', '.join(PROTOCOLS))
    tls_name = str(b.get('tls_name') or '').strip().rstrip('.')
    if tls_name and not re.match(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})\Z', tls_name):
        raise ValueError('the server name for TLS is a host name (dns.example.net)')
    return {'name': name, 'servers': '\n'.join(clean_servers(b.get('servers'), protocol)),
            'protocol': protocol, 'tls_name': tls_name if protocol == 'dot' else '',
            'timeout_s': _num(b.get('timeout') if b.get('timeout') not in (None, '')
                              else DEFAULT_TIMEOUT, 0.5, 30, 'the timeout'),
            'note': str(b.get('note') or '').strip()[:500]}


def save_set(store, b, by):
    row = clean(b)
    old = str(b.get('old_name') or '').strip()
    if old == SYSTEM:
        raise ValueError('"%s" is built in: it cannot be changed' % SYSTEM)
    t = time.time()
    have = store.db.row('SELECT * FROM %s WHERE name = ?' % TABLE, (old or row['name'],))
    if old and not have:
        raise LookupError('there is no DNS set %s' % old)
    clash = store.db.row('SELECT id FROM %s WHERE name = ?' % TABLE, (row['name'],))
    if clash and (not have or clash['id'] != have['id']):
        raise ValueError('there is a DNS set %s already' % row['name'])
    row.update(updated=t, updated_by=by)
    if have:
        store.db.update(TABLE, have['id'], row)
        if old and old != row['name']:
            store.db.run('UPDATE %s SET set_name = ? WHERE set_name = ?' % USES,
                         (row['name'], old))
        words = 'the DNS set %s was changed%s by %s' % (
            row['name'], (' (it was %s)' % old) if old and old != row['name'] else '', by)
    else:
        row.update(created=t, created_by=by)
        store.db.insert(TABLE, row)
        words = 'the DNS set %s was added by %s' % (row['name'], by)
    store.add_event('settings', '%s: %s' % (words, row['servers'].replace('\n', ', ')))
    forget()
    return _row_view(store.db.row('SELECT * FROM %s WHERE name = ?' % TABLE, (row['name'],)))


def delete_set(store, name, by):
    name = str(name or '').strip()
    if name == SYSTEM:
        raise ValueError('"%s" is built in: it cannot be deleted' % SYSTEM)
    row = store.db.row('SELECT id FROM %s WHERE name = ?' % TABLE, (name,))
    if not row:
        raise LookupError('there is no DNS set %s' % name)
    was = [p[1] for p in PURPOSES if _load(store)[1].get(p[0]) == name]
    store.db.run('DELETE FROM %s WHERE set_name = ?' % USES, (name,))
    store.db.run('DELETE FROM %s WHERE id = ?' % TABLE, (row['id'],))
    store.add_event('settings', 'the DNS set %s was deleted by %s%s' % (
        name, by, ('; back to their default: %s' % ', '.join(was)) if was else ''))
    forget()
    return {'deleted': name, 'back_to_default': was}


def assign(store, purpose, name, by):
    if purpose not in PURPOSE_KEYS:
        raise ValueError('no such function: %s (%s)' % (purpose, ', '.join(PURPOSE_KEYS)))
    name = str(name or '').strip()
    sets_, _uses = _load(store)
    if name and name != SYSTEM and name not in sets_:
        raise LookupError('there is no DNS set %s' % name)
    title = dict((p[0], p[1]) for p in PURPOSES)[purpose]
    store.db.run('DELETE FROM %s WHERE purpose = ?' % USES, (purpose,))
    if name:
        store.db.insert(USES, {'purpose': purpose, 'set_name': name, 'updated': time.time(),
                               'updated_by': by})
    forget()
    got, how = dns_set_for(purpose, store)
    store.add_event('settings', '%s: names are looked up through the DNS set %s%s (by %s)' % (
        title, got, '' if name else ' (its default)', by))
    return {'purpose': purpose, 'set': got, 'how': how}


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------
def test(store, b):
    """A name looked up through a set - every server of it, each with how long
    it took, what it said and what it answered. b: {name} of a set kept, or
    the set's fields (a form not saved), qname, qtype."""
    qname = D.norm(str(b.get('qname') or '').strip())
    if not qname or not re.match(r'^[A-Za-z0-9_*]([A-Za-z0-9_.*-]{0,252})\Z', qname):
        raise ValueError('which name? (www.example.com)')
    qtype = str(b.get('qtype') or 'A').strip().upper()
    if qtype not in QTYPES:
        raise ValueError('the type is one of %s' % ', '.join(QTYPES))
    if b.get('servers') not in (None, '', []):
        row = clean(dict(b, name=b.get('name') or 'draft'))
        r = Resolver(row['servers'].split('\n'), row['protocol'], row['timeout_s'],
                     row['tls_name'], name=str(b.get('name') or '').strip())
    else:
        r = resolver_of(str(b.get('name') or '').strip(), store)
        if r is None:
            raise LookupError('there is no DNS set %s' % b.get('name'))
    tries, answered_by, answers = [], '', []
    for srv in r:
        t0 = time.monotonic()
        one = {'server': srv, 'ok': False, 'rcode': '', 'said': '', 'answers': []}
        try:
            m = r.ask_one(srv, qname, D.type_code(qtype))
            one['rcode'] = D.RCODES.get(m.rcode, str(m.rcode))
            one['ok'] = m.rcode in (D.NOERROR, D.NXDOMAIN)
            one['answers'] = [{'name': D.norm(x.name), 'type': D.type_name(x.rtype),
                               'ttl': x.ttl, 'value': x.text} for x in m.answer]
            one['said'] = '%d record(s)' % len(m.answer) if m.rcode == D.NOERROR else \
                'the name does not exist (NXDOMAIN)' if m.rcode == D.NXDOMAIN else \
                'said %s' % one['rcode']
        except (D.DnsError, D.FormErr, OSError, ssl.SSLError) as e:
            one['said'] = str(e)[:300]
        one['ms'] = int((time.monotonic() - t0) * 1000)
        if one['ok'] and not answered_by:
            answered_by, answers = srv, one['answers']
        tries.append(one)
    return {'set': r.name or '(not saved)', 'protocol': r.protocol, 'qname': qname,
            'qtype': qtype, 'answered_by': answered_by, 'answers': answers, 'tries': tries,
            'ok': bool(answered_by)}


# ---------------------------------------------------------------------------
# Names looked up through a set by socket.getaddrinfo, in one thread
# ---------------------------------------------------------------------------
_SCOPE = threading.local()
_PREV = {'fn': None}


def purpose_of(ctx_scope, how='http'):
    """The function a module's connection serves, by its RunContext's scope
    ('target:NAME', 'issuer:NAME', 'challenge:NAME') - SSH always 'targets'."""
    if how == 'ssh' or str(ctx_scope or '').startswith('target:'):
        return 'targets'
    return 'apis'


def _plain_host(host):
    return host.decode() if isinstance(host, bytes) else str(host)


def _getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    prev = _PREV['fn']
    r = getattr(_SCOPE, 'r', None)
    if r is None or not host or getattr(_BUSY, 'on', False):
        return prev(host, port, family, type, proto, flags)
    h = _plain_host(host).strip('[]')
    try:
        ipaddress.ip_address(h.split('%')[0])
        return prev(host, port, family, type, proto, flags)
    except ValueError:
        pass
    try:
        skip = E._acme_proxy_host()
    except Exception:                                   # noqa: BLE001
        skip = set()
    if h.lower() in ('localhost',) or h.lower().endswith('.localhost') or h.lower() in skip:
        return prev(host, port, family, type, proto, flags)
    addrs = r.addresses(h, family)
    if not addrs:
        raise socket.gaierror(socket.EAI_NONAME, '%s is not known to the DNS set %s' % (
            h, r.label()))
    out = []
    for a in addrs:
        try:
            out += prev(a, port, family, type, proto, flags | socket.AI_NUMERICHOST)
        except socket.gaierror:
            continue
    if not out:
        raise socket.gaierror(socket.EAI_NONAME, '%s: no address of the right family' % h)
    return out


def install():
    if _PREV['fn'] is None:
        _PREV['fn'] = socket.getaddrinfo
        socket.getaddrinfo = _getaddrinfo


class scope(object):
    """with scope('apis', store, say=fn): the names this thread looks up through
    getaddrinfo are asked of the function's set - nothing changes for "The
    system's". `say(words)` is told once which set it is."""

    def __init__(self, purpose, store=None, say=None, using=None):
        self.purpose, self.store, self.say, self.using = purpose, store, say, using

    def __enter__(self):
        install()
        self.was = getattr(_SCOPE, 'r', None)
        try:
            r = self.using if self.using is not None else resolver(self.purpose, self.store)
        except Exception:                               # noqa: BLE001
            r = None
        if r is not None and (r.system or not len(r)):
            r = None
        _SCOPE.r = r
        if r is not None and self.say:
            try:
                self.say('names looked up through the DNS set %s (Settings → DNS)' % r.label())
            except Exception:                           # noqa: BLE001
                pass
        return r

    def __exit__(self, *a):
        _SCOPE.r = self.was


def ssh_address(ctx, host):
    """Where ssh connects for `host` (a target, a server over SSH): the host
    itself for "The system's" (ssh looks it up), else its address as the set of
    "Targets" answers it."""
    h = str(host or '').strip().strip('[]')
    try:
        ipaddress.ip_address(h.split('%')[0])
        return h
    except ValueError:
        pass
    try:
        r = resolver('targets', getattr(ctx, 'store', None))
    except Exception:                                   # noqa: BLE001
        return h
    if r.system or not len(r) or h.lower() == 'localhost':
        return h
    got = r.addresses(h)
    if not got:
        from acmelib.plugins import base
        raise base.PluginError('%s is not known to the DNS set %s (Settings → DNS, Targets)'
                               % (h, r.label()))
    try:
        ctx.step('%s is %s, as the DNS set %s says' % (h, got[0], r.label()))
    except Exception:                                   # noqa: BLE001
        pass
    return got[0]


# ---------------------------------------------------------------------------
# A guide's step: which sets it asked
# ---------------------------------------------------------------------------
def guide_step(store=None):
    try:
        v, how_v = dns_set_for('validation', store)
        p, how_p = dns_set_for('public', store)
    except Exception:                                   # noqa: BLE001
        return None
    from acmelib.plugins import base
    return base.guide_step(
        'dns_sets', 'DNS looked up through \'%s\', the public view through \'%s\'' % (v, p),
        where='Settings → DNS', done=None, blocking=False,
        said='a validation\'s own "Resolvers" and "Public resolvers" fields come first')


def summary(store):
    """What the API's list answers."""
    return {'sets': sets(store), 'purposes': purposes(store), 'used': where_used(store),
            'fixed': FIXED, 'protocols': PROTOCOLS, 'qtypes': list(QTYPES), 'system': SYSTEM,
            'public': PUBLIC}


# The engine's own DNS client (the appliance's own ACME, mail going direct)
# asks which servers a function has here.
try:
    E.DNS_SETS_HOOK['fn'] = engine_servers
except (AttributeError, TypeError):
    pass
install()
