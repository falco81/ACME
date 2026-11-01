# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# A directory, as the sign-ins use it
# ---------------------------------------------------------------------------
# Several servers, asked in the order given: one that cannot be reached is
# passed over for the next, one that answers is believed. Two questions are
# asked of it - who is this, and which groups are they in - and their answers
# are kept for a minute, because a page asks twice in a row for the same
# person more often than not.

AD_UAC_DISABLED = 0x2
AD_NEVER = (0, 0x7FFFFFFFFFFFFFFF)
USER_ATTRS = ('distinguishedName', 'sAMAccountName', 'userPrincipalName', 'displayName',
              'mail', 'userAccountControl', 'accountExpires', 'memberOf', 'lockoutTime',
              'pwdLastSet', 'department', 'title', 'mobile', 'telephoneNumber',
              'objectClass', 'msDS-User-Account-Control-Computed')
# msDS-User-Account-Control-Computed (1.0.101): what AD works out now -
# locked out (0x10) and the password expired (0x800000). lockoutTime alone
# stays set after the lockout is over.
AD_UACC_LOCKED = 0x10
AD_UACC_PW_EXPIRED = 0x800000


def ad_time(value):
    """A Windows time (hundreds of nanoseconds since 1601) as seconds since
    1970, or None for never."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n in AD_NEVER or n <= 0:
        return None
    return n / 10000000.0 - 11644473600


class Directory(object):
    """One directory from the table, made usable."""

    CACHE_S = 60
    USER_CACHE_S = 15

    def __init__(self, row):
        self.row = row
        self.name = row['name']
        self.hosts = [h.strip() for h in str(row.get('hosts') or '').split(',') if h.strip()]
        self.port = int(row.get('port') or 636)
        self.tls = row.get('tls') or 'ldaps'
        # NULL (a row imported or moved without it) is verify, never off (1.0.57).
        self.verify = row.get('verify') is None or bool(int(row.get('verify') or 0))
        self.ca = row.get('ca') or ''
        self.weak = bool(int(row.get('weak') or 0))    # old, weak certificates (1.0.77)
        self.base = row.get('base') or ''
        self.bind_dn = row.get('bind_dn') or ''
        self.bind_pw = row.get('bind_pw') or ''
        self.timeout = float(row.get('timeout_s') or 10)
        self.cache = {}
        self.lock = threading.Lock()
        self.last_good = None

    def _hostport(self, host):
        host = str(host).strip()
        # [fd00::1]:636 and [fd00::1] as well (1.0.44); a bare IPv6 address
        # has no port of its own.
        m = re.match(r'^\[([^\]]+)\](?::(\d+))?\Z', host)
        if m:
            return m.group(1), int(m.group(2) or self.port)
        m = re.match(r'^([^:]+)(?::(\d+))?\Z', host)
        if m:
            return m.group(1), int(m.group(2) or self.port)
        return host, self.port

    # Servers that did not answer, and until when they are passed over
    # (1.0.101): every request asked each of them in turn and waited out its
    # timeout first - with two dead servers of 10 s, every sign-in waited
    # 20 s. Shared by every directory object (a reload makes new ones).
    DEAD = {}
    DEAD_S = 30
    DEAD_LOCK = threading.Lock()

    @contextlib.contextmanager
    def held(self):
        """Around every question asked of it - the place to count or limit
        them, should that be needed again."""
        yield

    def _order(self):
        """The servers in the order to ask them: the one that answered last
        first, those that did not answer lately last - and when none has,
        one try every few seconds, the rest refused at once."""
        order = [h for h in self.hosts if h]
        if self.last_good in order:
            order.remove(self.last_good)
            order.insert(0, self.last_good)
        t = time.time()
        with self.DEAD_LOCK:
            live = [h for h in order if self.DEAD.get(h.lower(), 0) <= t]
            if live:
                return live + [h for h in order if h not in live]
            probe = self.DEAD.get('probe:' + self.name.lower(), 0)
            if probe > t - 5:
                return []
            self.DEAD['probe:' + self.name.lower()] = t
        return order[:1]

    def _down(self, host):
        with self.DEAD_LOCK:
            if len(self.DEAD) > 1000:
                self.DEAD.clear()
            self.DEAD[str(host).lower()] = time.time() + self.DEAD_S

    def _up(self, host):
        with self.DEAD_LOCK:
            self.DEAD.pop(str(host).lower(), None)

    def link(self, bind=True):
        """A conversation with the first server that answers, signed in as the
        reading account. LdapUnreachable where none of them can be."""
        tried = []
        order = self._order()
        if not order:
            tried.append('every server failed within the last %d s' % self.DEAD_S)
        refused = None
        for host in order:
            h, p = self._hostport(host)
            one = Ldap(h, p, self.tls, self.ca, self.verify, self.timeout, self.weak)
            try:
                one.open()
                if bind and self.bind_dn:
                    try:
                        one.bind(self.bind_dn, self.bind_pw)
                    except LdapUnreachable:
                        raise
                    except LdapError as e:
                        if e.code in LDAP_TRY_ANOTHER or e.code is None:
                            # Busy, unavailable, an answer that does not read
                            # (1.0.59): that server's trouble - the next one.
                            raise
                        one.close()
                        # The reading account refused - an answer of the
                        # server itself - is the same on every server: no
                        # point going round them all.
                        refused = LdapUnreachable('the account this reads the directory with '
                                                  '(%s) was refused by %s: %s'
                                                  % (self.bind_dn, h, e), e.code, e.detail)
                        break
                self.last_good = host
                self._up(host)
                one.acme_host = host
                return one
            except (LdapError, OSError, ValueError) as e:
                # Unreachable, timed out, the line dropped, StartTLS hung
                # (1.0.57): the next server is asked - a server that takes
                # the connection and then says nothing no longer stops
                # every sign-in.
                one.close()
                self._down(host)
                tried.append('%s: %s' % (h, e))
                if host == self.last_good:
                    self.last_good = None
        if refused is not None:
            raise refused
        raise LdapUnreachable('no server of %s could be reached (%s)'
                              % (self.name, '; '.join(tried) or 'none is set'))

    def asked(self, do):
        """do(link) on the first server that answers - and on the next when
        the search itself is not answered (1.0.149): a server that took the
        connection and the reading account's bind but then left its searches
        unanswered was never passed over, and the other server never asked."""
        with self.held():
            return self._asked(do)

    def _asked(self, do):
        last = None
        for _ in range(max(1, len(self.hosts))):
            link = self.link()
            host = getattr(link, 'acme_host', None)
            try:
                return do(link)
            except (LdapError, OSError) as e:
                if isinstance(e, LdapError) and not (isinstance(e, LdapUnreachable) or
                                                     e.code in LDAP_TRY_ANOTHER):
                    raise
                last = e
                if host:
                    self._down(host)
                    if self.last_good == host:
                        self.last_good = None
            finally:
                link.close()
        raise last if isinstance(last, LdapUnreachable) else LdapUnreachable(str(last))

    def find_user(self, name, how='upn'):
        """The entry of one account, or None. `how` is upn (the whole
        name@domain against userPrincipalName), sam (the part before the @
        against sAMAccountName) or mail."""
        key = ('u', how, str(name).lower())
        with self.lock:
            got = self.cache.get(key)
            # An account's own entry - disabled, expired, locked - kept 15 s,
            # not a minute (1.0.136): a sign-in relies on it being now.
            if got and time.time() - got[0] < self.USER_CACHE_S:
                return got[1]
        said = str(name or '').strip()
        if how == 'sam':
            said = said.split('@', 1)[0].split('\\')[-1]
            want = ldap_equal(self.row.get('user_attr') or 'sAMAccountName', said)
        elif how == 'mail':
            want = ldap_equal('mail', said)
        else:
            want = ldap_equal('userPrincipalName', said)
        flt = ldap_and(ldap_equal('objectClass', 'user'), want)
        # Three, not two (1.0.101): a computer's account among them is
        # dropped below, and must not hide a second person of the name.
        rows = self.asked(lambda link: link.search(self.base, flt, USER_ATTRS, scope=2,
                                                   limit=3))
        entry = None
        # A computer's account is not a person's (1.0.101): objectClass=user
        # takes them in on AD, and anybody in the domain may make up to ten
        # with a password of their own choosing - which then outlive them.
        rows = [r for r in rows if not computer_account(r)]
        if rows:
            r = rows[0]
            a = {k.lower(): v for k, v in r['attrs'].items()}
            first = lambda k: (a.get(k.lower()) or [''])[0]
            uac = 0
            try:
                uac = int(first('userAccountControl') or 0)
            except ValueError:
                pass
            try:
                uacc = int(first('msDS-User-Account-Control-Computed') or 0)
            except ValueError:
                uacc = 0
            entry = {'dn': r['dn'], 'sam': first('sAMAccountName'),
                     'upn': first('userPrincipalName'), 'display': first('displayName'),
                     'mail': first('mail'), 'uac': uac,
                     'disabled': bool(uac & AD_UAC_DISABLED),
                     'expires': ad_time(first('accountExpires')),
                     'locked': bool(uacc & AD_UACC_LOCKED),
                     'pw_expired': bool(uacc & AD_UACC_PW_EXPIRED),
                     # An AD account (it has a sAMAccountName) whose state
                     # could not be read: not taken as "in use" (1.0.101).
                     'uac_unread': bool(first('sAMAccountName')) and not first('userAccountControl'),
                     # Ranged too (memberOf;range=0-1499, 1.0.59).
                     'member_of': [g for k, v in a.items()
                                   if k == 'memberof' or k.startswith('memberof;range=')
                                   for g in (v or [])],
                     'department': first('department'), 'title': first('title'),
                     # For a code by SMS (1.0.76): the number a page may offer.
                     'mobile': first('mobile') or first('telephoneNumber'),
                     'phone': first('telephoneNumber'),
                     'pw_set': ad_time(first('pwdLastSet')),
                     'many': len(rows) > 1}
        with self.lock:
            self.cache[key] = (time.time(), entry)
            if len(self.cache) > 5000:
                self.cache.clear()
        return entry

    def groups_of(self, entry, nested=True):
        """[(dn, cn)] of every group the account is in - with the groups
        inside groups where `nested`, which on Active Directory is one search
        with the in-chain matching rule rather than a walk of the tree."""
        if not entry:
            return []
        if not nested:
            return [(g, cn_of(g)) for g in entry.get('member_of') or []]
        key = ('g', entry['dn'].lower())
        with self.lock:
            got = self.cache.get(key)
            if got and time.time() - got[0] < self.CACHE_S:
                return got[1]
        def do(link):
            link.PAGES_MOST = 20        # a sign-in's groups, not a census (1.0.59)
            # From the root of the domain (1.0.153), as group_dns looks: a base
            # for the people (OU=Users,...) left out every group kept beside
            # it (OU=Groups,...), and nobody was in any group.
            return link.search(self.domain_root(), ldap_and(ldap_equal('objectClass', 'group'),
                                                   ldap_in_chain('member', entry['dn'])),
                               ('cn',), scope=2, limit=5000, paged=True)
        rows = self.asked(do)
        out = [(r['dn'], (r['attrs'].get('cn') or [cn_of(r['dn'])])[0]) for r in rows]
        with self.lock:
            if len(self.cache) > 5000:            # as find_user keeps it (1.0.209)
                self.cache.clear()
            self.cache[key] = (time.time(), out)
        return out

    def domain_root(self):
        """DC=corpnet,DC=loc out of the base the people are looked for under."""
        dcs = [p for p in re.split(r'(?<!\\),', str(self.base or '')) if
               p.strip().lower().startswith('dc=')]
        return ','.join(p.strip() for p in dcs) or self.base

    def group_dns(self, name):
        """The DN of the one group a name given without its place stands for
        (1.0.101), as a set of 0 or 1 lower-case DNs. Matched by its name
        alone, any group anywhere under the base called alike - one a
        helpdesk or an OU's admin could make - passed as the real one, the
        administrators' group too. So: the group whose sAMAccountName it is
        (one in a domain, never two); where nothing has one, the group
        whose cn it is - and if more than one is, none of them."""
        said = str(name or '').strip()
        key = ('gn', said.lower())
        with self.lock:
            got = self.cache.get(key)
            if got and time.time() - got[0] < self.CACHE_S:
                return got[1]
        # From the root of the domain, not the base the accounts are looked
        # for under: groups often live elsewhere (OU=Groups beside OU=Users).
        where = self.domain_root()
        def do(link):
            link.PAGES_MOST = 5
            return link.search(where, ldap_and(
                ldap_equal('objectClass', 'group'),
                ldap_or(ldap_equal('sAMAccountName', said), ldap_equal('cn', said))),
                ('cn', 'sAMAccountName'), scope=2, limit=50, paged=True)
        rows = self.asked(do)

        def first(r, a):
            for k, v in r['attrs'].items():
                if k.lower() == a and v:
                    return str(v[0])
            return ''
        by_sam = [r['dn'] for r in rows if first(r, 'samaccountname').lower() == said.lower()]
        by_cn = [r['dn'] for r in rows if (first(r, 'cn') or cn_of(r['dn'])).lower() == said.lower()]
        pick = by_sam if by_sam else by_cn
        out = {pick[0].lower()} if len(pick) == 1 else set()
        if len(pick) > 1:
            log_sparing('group-many-' + said.lower(), 'the group %s named without its place '
                        'answers to %d groups in %s (%s): none of them is taken - give it as '
                        'its full DN' % (said, len(pick), self.name, '; '.join(pick[:4])), 'warn')
        with self.lock:
            if len(self.cache) > 5000:
                self.cache.clear()
            self.cache[key] = (time.time(), out)
        return out

    def password_ok(self, entry, password):
        """True, or LdapError with the directory's reason in words."""
        if not str(password or ''):
            raise LdapError('a password is needed')
        if not str((entry or {}).get('dn') or '').strip():
            # A bind with no name and a password is an anonymous one on many
            # servers (1.0.101): never asked.
            raise LdapError('no account to check the password of')
        if any(ord(c) < 32 or ord(c) == 127 for c in str(password)):
            # Cut at a NUL somewhere on the way, a password is empty - and an
            # empty one binds anonymously (1.0.101).
            raise LdapError('the password holds a control character')
        with self.held():
            return self._password_ok(entry, password)

    def _password_ok(self, entry, password):
        tried = []
        order = self._order()
        if not order:
            tried.append('every server failed within the last %d s' % self.DEAD_S)
        for host in order:
            h, p = self._hostport(host)
            one = Ldap(h, p, self.tls, self.ca, self.verify, self.timeout, self.weak)
            try:
                one.open()
            except (LdapError, OSError) as e:
                self._down(host)
                tried.append(str(e))
                continue
            try:
                one.bind(entry['dn'], password)
                self._up(host)
                return True
            except LdapUnreachable as e:
                # The line dropped mid-bind: the next server is asked, the
                # password is not called wrong (1.0.44).
                self._down(host)
                tried.append(str(e))
                continue
            except LdapError as e:
                # Busy, unavailable, or an answer that does not read (1.0.59):
                # not the directory's word on the password - the next one.
                if e.code in LDAP_TRY_ANOTHER or (e.code is None and 'does not read' in str(e)):
                    tried.append(str(e))
                    continue
                raise
            finally:
                one.close()
        raise LdapUnreachable('no server of %s could be reached (%s)'
                              % (self.name, '; '.join(tried)))

    def find_users(self, like, limit=25):
        """People whose name, account, principal name or mail holds what is
        typed - for the boxes that offer a person as one types (1.0.19)."""
        like = str(like or '').strip()
        if len(like) < 2:
            return []
        attr = self.row.get('user_attr') or 'sAMAccountName'
        want = ldap_and(ldap_equal('objectClass', 'user'),
                        ldap_or(ldap_contains(attr, like), ldap_contains('userPrincipalName', like),
                                ldap_contains('displayName', like), ldap_contains('mail', like)))
        link = self.link()
        try:
            rows = link.search(self.base, want, ('sAMAccountName', 'userPrincipalName',
                                                 'displayName', 'mail', 'userAccountControl',
                                                 'mobile', 'telephoneNumber', attr), scope=2,
                                limit=limit + 10)
        finally:
            link.close()
        out = []
        for r in rows:
            a = {k.lower(): v for k, v in r['attrs'].items()}
            first = lambda k: (a.get(k.lower()) or [''])[0]
            if str(first('sAMAccountName')).endswith('$'):
                continue                         # a computer, not a person
            try:
                uac = int(first('userAccountControl') or 0)
            except ValueError:
                uac = 0
            out.append({'dn': r['dn'], 'sam': first(attr) or first('sAMAccountName'),
                        'upn': first('userPrincipalName'), 'display': first('displayName'),
                        'mail': first('mail'), 'disabled': bool(uac & AD_UAC_DISABLED),
                        'mobile': first('mobile') or first('telephoneNumber')})
        low = like.lower()
        out.sort(key=lambda u: (not (u['sam'] or '').lower().startswith(low),
                                not (u['display'] or '').lower().startswith(low),
                                (u['display'] or u['sam'] or '').lower()))
        return out[:limit]

    def find_groups(self, like='', limit=300):
        """Group names for a picker."""
        want = ldap_equal('objectClass', 'group')
        if like.strip():
            want = ldap_and(want, ldap_contains('cn', like.strip()))
        link = self.link()
        try:
            rows = link.search(self.base, want, ('cn', 'description'), scope=2,
                               limit=limit, paged=True)
        finally:
            link.close()
        out = [{'dn': r['dn'], 'cn': (r['attrs'].get('cn') or [cn_of(r['dn'])])[0],
                'description': (r['attrs'].get('description') or [''])[0]} for r in rows]
        return sorted(out, key=lambda g: g['cn'].lower())

    def check(self):
        """Every server, step by step, the way isemon's directory check reads."""
        out = []
        began = time.time()
        for host in self.hosts:
            h, p = self._hostport(host)
            steps = []
            one = Ldap(h, p, self.tls, self.ca, self.verify, self.timeout, self.weak)
            t = time.time()
            try:
                one.open()
                steps.append({'what': 'reached %s:%d%s' % (h, p, {
                    'ldaps': ' over TLS', 'starttls': ' and started TLS'}.get(self.tls, '')),
                    'ok': True, 'said': '%d ms' % int((time.time() - t) * 1000)})
            except (LdapError, OSError) as e:
                steps.append({'what': 'reach the server %s:%d' % (h, p), 'ok': False, 'said': str(e)})
                out.append({'host': h, 'port': p, 'steps': steps, 'ok': False})
                continue
            try:
                if self.bind_dn:
                    one.bind(self.bind_dn, self.bind_pw)
                    steps.append({'what': 'signed in as %s' % self.bind_dn, 'ok': True,
                                  'said': ''})
                rows = one.search(self.base, ldap_present('objectClass'), ('objectClass',),
                                  scope=0, limit=1)
                steps.append({'what': 'read the base %s' % self.base, 'ok': bool(rows),
                              'said': '' if rows else 'nothing is there - is the base right?'})
                n = len(one.search(self.base, ldap_equal('objectClass', 'group'), ('cn',),
                                   scope=2, limit=5000, paged=True))
                steps.append({'what': 'counted the groups', 'ok': True,
                              'said': '%d group(s) under the base' % n})
                out.append({'host': h, 'port': p, 'steps': steps, 'ok': bool(rows)})
            except LdapError as e:
                steps.append({'what': 'the next step', 'ok': False, 'said': str(e),
                              'detail': e.detail})
                out.append({'host': h, 'port': p, 'steps': steps, 'ok': False})
            finally:
                one.close()
        return {'name': self.name, 'servers': out, 'ok': bool(out) and all(s['ok'] for s in out),
                'took_ms': int((time.time() - began) * 1000), 'tls': self.tls,
                'verify': self.verify, 'weak': self.weak}


def entry_unusable(entry, locked=True):
    """Why the directory's account may not sign in now, or None (1.0.101):
    switched off, run out, locked out, its password expired - or, on AD,
    its state not readable at all, which is not taken as "in use"."""
    if not entry:
        return 'there is no such account'
    if entry.get('disabled'):
        return 'it is disabled in the directory'
    if entry.get('uac_unread'):
        return 'the directory does not say whether it is in use (userAccountControl cannot be read)'
    if entry.get('expires') and entry['expires'] < time.time():
        return 'it expired %s' % stamp(entry['expires'])
    if locked and entry.get('locked'):
        return 'it is locked out in the directory'
    if locked and entry.get('pw_expired'):
        return 'its password has expired in the directory'
    return None


def computer_account(r):
    """Whether a search result is a computer's account (1.0.101)."""
    a = {k.lower(): v for k, v in (r.get('attrs') or {}).items()}
    if any(str(x).lower() == 'computer' for x in a.get('objectclass') or []):
        return True
    return str((a.get('samaccountname') or [''])[0]).endswith('$')


def dn_norm(dn):
    """A DN as it is compared (1.0.205): lower case, no spaces around the
    commas and equals signs that part it - "CN=Cert Admins, OU=Groups" copied
    from a page matched nothing AD said."""
    return re.sub(r'(?<!\\)\s*([,=])\s*', r'\1', str(dn or '').strip().lower())


def group_matches(wanted, have, ad=None):
    """Whether any group in `have` ([(dn, cn)]) is one of `wanted` (names or
    DNs). Returns the wanted entry that matched first, in `wanted`'s order.

    A name without its place is the one group `ad` says it is (1.0.101), by
    its DN - never any group of that cn wherever it is. Without `ad` to ask,
    a name alone matches nothing."""
    by_dn = {dn_norm(dn) for dn, _ in have}
    by_cn = {str(cn).lower() for _, cn in have}
    for one in wanted:
        said = str(one.get('group') if isinstance(one, dict) else one).strip()
        if not said:
            continue
        if '=' in said and ',' in said:
            if dn_norm(said) in by_dn:
                return one
        elif said.lower() in by_cn and ad is not None:
            try:
                dns = {dn_norm(x) for x in ad.group_dns(said)}
            except LdapUnreachable:
                # The directory not answering is not "not a member" (1.0.205):
                # said as it is, and never counted as somebody guessing.
                raise
            except LdapError as e:
                # Not known which group it is: no match, never a guess.
                log_sparing('group-dns', 'the group %s could not be looked up in %s: %s'
                            % (said, ad.name, e), 'warn')
                dns = set()
            if dns & by_dn:
                return one
    return None


