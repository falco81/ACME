#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mockldap.py - a directory that is not there, answering the way one does.

Taken from isemon's tests, with a few people added the way acme's sign-ins
see them (the administrators', the enrolment pages'): names in another UPN
suffix than the domain's, a group of certificate users, a group inside it, a
disabled account.

It speaks enough LDAP to be asked the questions acme asks: is this password
right, who is this, which groups are they in, and what groups are there.
It exists because the alternative is shipping protocol code that has never
had an answer come back at it - and because nobody can put an Active
Directory in a test.

Run on its own it serves a small made-up domain on a port it prints:

    ./test/mockldap.py [port] [--tls certfile keyfile]
"""
import socket
import ssl
import sys
import threading

HERE = __file__
sys.path.insert(0, __file__.rsplit('/', 2)[0])
import acme as isemon                                 # noqa: E402  (the same BER helpers)

# Windows counts time in hundreds of nanoseconds since 1601, and a test that
# hard-codes one of those is a test that expires. These make them relative to
# now, which is what a directory holding a live account looks like.
def AD_TICKS(seconds_from_now):
    import time as _t
    return str(int((_t.time() + seconds_from_now + 11644473600) * 10000000))


def AD_WHEN(seconds_from_now):
    import time as _t
    return _t.strftime('%Y%m%d%H%M%S.0Z', _t.gmtime(_t.time() + seconds_from_now))


# What a directory says about itself when it is asked with no base at all -
# the root DSE - and what the partitions container beside it holds. The
# second is the list of name suffixes the forest answers for: a domain called
# corpnet.loc whose people sign in as somebody@corpnet.cz says so here, and nowhere
# else.
ROOTDSE = {
    'defaultNamingContext': ['DC=corpnet,DC=loc'],
    'configurationNamingContext': ['CN=Configuration,DC=corpnet,DC=loc'],
    'rootDomainNamingContext': ['DC=corpnet,DC=loc'],
    'objectClass': ['top'],
}
PARTITIONS = {
    'uPNSuffixes': ['corpnet.cz', 'corpnet.example'],
    'objectClass': ['top', 'crossRefContainer'],
}


# One small domain: two people, three groups, one of them inside another.
BASE = 'DC=corpnet,DC=loc'
PEOPLE = {
    'CN=Jan Novak,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['jnovak'],
        'userPrincipalName': ['jnovak@corpnet.loc'],
        'displayName': ['Jan Novák'],
        'mail': ['jan.novak@corpnet.loc'],
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'memberOf': ['CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc'],
        '_password': 'a-good-long-password',
    },
    'CN=Eva Dvorak,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['edvorak'],
        'userPrincipalName': ['edvorak@corpnet.loc'],
        'displayName': ['Eva Dvořák'],
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'memberOf': ['CN=Helpdesk,OU=Groups,DC=corpnet,DC=loc'],
        '_password': 'another-good-password',
    },
    'CN=Nobody,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['nogroups'],
        'objectClass': ['top', 'person', 'user'],
        'memberOf': [],
        '_password': 'still-a-good-password',
    },
    # Somebody the directory is holding back: locked out after a run of wrong
    # passwords, with a password that expired yesterday. This is the account
    # the "who is this?" card exists for - forty failures in the log, and the
    # reason is sitting in the directory where nobody was looking.
    'CN=Petr Kolar,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['pkolar'],
        'userPrincipalName': ['pkolar@corpnet.loc'],
        'displayName': ['Petr Kolář'],
        'mail': ['petr.kolar@corpnet.loc'],
        'department': ['Odbor informatiky'],
        'title': ['Správce sítě'],
        'physicalDeliveryOfficeName': ['4NP, 412'],
        'telephoneNumber': ['+420 585 000 000'],
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'userAccountControl': ['512'],
        # The locked-out bit is only ever in the computed one, which is the
        # whole reason this program reads both.
        'msDS-User-Account-Control-Computed': ['16'],
        'lockoutTime': [AD_TICKS(-1800)],
        'badPwdCount': ['7'],
        'badPasswordTime': [AD_TICKS(-1500)],
        'pwdLastSet': [AD_TICKS(-86400 * 95)],
        'msDS-UserPasswordExpiryTimeComputed': [AD_TICKS(-86400)],
        'lastLogonTimestamp': [AD_TICKS(-86400 * 3)],
        'whenCreated': [AD_WHEN(-86400 * 900)],
        'whenChanged': [AD_WHEN(-1800)],
        'memberOf': ['CN=Helpdesk,OU=Groups,DC=corpnet,DC=loc'],
        '_password': 'a-password-that-will-not-help',
    },
    # A machine, because 802.1X signs in as one and a machine account is a
    # perfectly ordinary thing to ask the directory about.
    'CN=PC123,OU=Computers,DC=corpnet,DC=loc': {
        'sAMAccountName': ['PC123$'],
        'dNSHostName': ['pc123.corpnet.loc'],
        'cn': ['PC123'],
        'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        'userAccountControl': ['4096'],
        'operatingSystem': ['Windows 11 Enterprise'],
        'operatingSystemVersion': ['10.0 (22631)'],
        'lastLogonTimestamp': [AD_TICKS(-3600)],
        'whenCreated': [AD_WHEN(-86400 * 400)],
        'memberOf': [],
        '_password': 'no-one-signs-in-as-a-machine-here',
    },
    'CN=isemon,OU=Service,DC=corpnet,DC=loc': {
        'sAMAccountName': ['isemon'],
        'objectClass': ['top', 'person', 'user'],
        'memberOf': [],
        '_password': 'the-service-password',
    },
}
# The people the sign-ins ask about: names ending in @corpnet.cz while the
# domain is corpnet.loc, as on the site this was written for.
PEOPLE.update({
    'CN=Falco Tester,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['falco'], 'userPrincipalName': ['falco@corpnet.cz'],
        'displayName': ['Falco Tester'], 'objectClass': ['top', 'person', 'user'],
        'userAccountControl': ['512'],
        'memberOf': ['CN=CERT_USERS,OU=Groups,DC=corpnet,DC=loc'],
        '_password': 'falco-password-1',
    },
    # With a mail and a mobile in the directory (1.0.91).
    'CN=Marta Mobilni,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['marta'], 'userPrincipalName': ['marta@corpnet.cz'],
        'displayName': ['Marta Mobilni'], 'objectClass': ['top', 'person', 'user'],
        'mail': ['marta.mobilni@corpnet.cz'], 'mobile': ['+420 777 111 222'],
        'userAccountControl': ['512'],
        'memberOf': ['CN=CERT_USERS,OU=Groups,DC=corpnet,DC=loc'],
        '_password': 'marta-password-1',
    },
    'CN=Nested Person,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['nested'], 'userPrincipalName': ['nested@corpnet.cz'],
        'displayName': ['Nested Person'], 'objectClass': ['top', 'person', 'user'],
        'userAccountControl': ['512'],
        'memberOf': ['CN=CERT_SUPPLIER_X,OU=Groups,DC=corpnet,DC=loc'],
        '_password': 'nested-password-1',
    },
    'CN=Outsider,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['outsider'], 'userPrincipalName': ['outsider@corpnet.cz'],
        'objectClass': ['top', 'person', 'user'], 'userAccountControl': ['512'],
        'memberOf': [], '_password': 'outsider-password-1',
    },
    'CN=Gone Away,OU=People,DC=corpnet,DC=loc': {
        'sAMAccountName': ['gone'], 'userPrincipalName': ['gone@corpnet.cz'],
        'objectClass': ['top', 'person', 'user'], 'userAccountControl': ['514'],
        'memberOf': ['CN=CERT_USERS,OU=Groups,DC=corpnet,DC=loc'],
        '_password': 'gone-password-1',
    },
    'CN=acme,OU=Service,DC=corpnet,DC=loc': {
        'sAMAccountName': ['acme'], 'userPrincipalName': ['acme@corpnet.loc'],
        'objectClass': ['top', 'person', 'user'], 'memberOf': [],
        '_password': 'the-acme-service-password',
    },
})

GROUPS = {
    'CN=CERT_USERS,OU=Groups,DC=corpnet,DC=loc': {
        'cn': ['CERT_USERS'], 'objectClass': ['top', 'group'],
        'member': ['CN=Falco Tester,OU=People,DC=corpnet,DC=loc',
                   'CN=Gone Away,OU=People,DC=corpnet,DC=loc',
                   'CN=CERT_SUPPLIER_X,OU=Groups,DC=corpnet,DC=loc'],
    },
    'CN=CERT_SUPPLIER_X,OU=Groups,DC=corpnet,DC=loc': {
        'cn': ['CERT_SUPPLIER_X'], 'objectClass': ['top', 'group'],
        'member': ['CN=Nested Person,OU=People,DC=corpnet,DC=loc'],
        'memberOf': ['CN=CERT_USERS,OU=Groups,DC=corpnet,DC=loc'],
    },
    'CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc': {
        'cn': ['ISE Admins'], 'objectClass': ['top', 'group'],
        'description': ['may change everything'],
        'member': ['CN=Jan Novak,OU=People,DC=corpnet,DC=loc'],
    },
    'CN=Helpdesk,OU=Groups,DC=corpnet,DC=loc': {
        'cn': ['Helpdesk'], 'objectClass': ['top', 'group'],
        'member': ['CN=Eva Dvorak,OU=People,DC=corpnet,DC=loc'],
        # Helpdesk is inside ISE Watchers: the nested case.
        'memberOf': ['CN=ISE Watchers,OU=Groups,DC=corpnet,DC=loc'],
    },
    'CN=ISE Watchers,OU=Groups,DC=corpnet,DC=loc': {
        'cn': ['ISE Watchers'], 'objectClass': ['top', 'group'],
        'description': ['may look, and change nothing'],
        'member': ['CN=Helpdesk,OU=Groups,DC=corpnet,DC=loc'],
    },
}


# What this hands back in one answer however much is asked for, the way a
# domain controller has a MaxPageSize. Small on purpose: a test that needs
# four pages should not need four thousand groups to get them.
MAX_PAGE = 250

# The domain object itself, which holds the rules every account under it is
# judged by. Windows writes its intervals in tenths of a microsecond, negative:
# -18,000,000,000 is half an hour.
DOMAIN = {
    'DC=corpnet,DC=loc': {
        'objectClass': ['top', 'domain', 'domainDNS'],
        'name': ['corpnet'],
        'msDS-Behavior-Version': ['7'],
        'lockoutThreshold': ['5'],
        'lockoutDuration': ['-18000000000'],
        'lockOutObservationWindow': ['-18000000000'],
        'minPwdLength': ['8'],
        'minPwdAge': ['-864000000000'],
        'maxPwdAge': ['-77760000000000'],
        'pwdHistoryLength': ['24'],
        'pwdProperties': ['1'],
        'ms-DS-MachineAccountQuota': ['10'],
        'whenCreated': ['20230101120000.0Z'],
    },
}
# ...what else it trusts, one level down of its tree, and a controller of its
# own, which is a computer account with the SERVER_TRUST_ACCOUNT bit set.
TRUSTS = {
    'CN=corpnettech.loc,CN=System,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'leaf', 'trustedDomain'],
        'trustPartner': ['corpnettech.loc'],
        'flatName': ['CORPNETTECH'],
        'trustDirection': ['3'],
        'trustType': ['2'],
        'trustAttributes': ['8'],
    },
}
TREE = {
    'OU=People,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'organizationalUnit'], 'name': ['People']},
    'OU=Groups,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'organizationalUnit'], 'name': ['Groups']},
    'OU=Service,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'organizationalUnit'], 'name': ['Service']},
}
CONTROLLERS = {
    'CN=DC01,OU=Domain Controllers,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'person', 'computer'],
        'sAMAccountName': ['DC01$'],
        'dNSHostName': ['dc01.corpnet.loc'],
        'operatingSystem': ['Windows Server 2022 Standard'],
        'operatingSystemVersion': ['10.0 (20348)'],
        'userAccountControl': ['8192'],
        'lastLogonTimestamp': ['133700000000000000'],
    },
}
# The configuration of the forest, which lives beside the domain rather than
# inside it: the sites, and the address ranges that belong to each. This is
# what turns an address in a controller's log into a place.
SITES = {
    'CN=Hometown,CN=Sites,CN=Configuration,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'site'], 'cn': ['Hometown']},
    'CN=Prostejov,CN=Sites,CN=Configuration,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'site'], 'cn': ['Prostejov']},
    'CN=172.29.11.0/24,CN=Subnets,CN=Sites,CN=Configuration,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'subnet'], 'cn': ['172.29.11.0/24'],
        'location': ['the main building'],
        'siteObject': ['CN=Hometown,CN=Sites,CN=Configuration,DC=corpnet,DC=loc']},
    'CN=172.30.0.0/16,CN=Subnets,CN=Sites,CN=Configuration,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'subnet'], 'cn': ['172.30.0.0/16'],
        'siteObject': ['CN=Prostejov,CN=Sites,CN=Configuration,DC=corpnet,DC=loc']},
}
POLICIES = {
    'CN=Admins PSO,CN=Password Settings Container,CN=System,DC=corpnet,DC=loc': {
        'objectClass': ['top', 'msDS-PasswordSettings'],
        'name': ['Admins PSO'],
        'msDS-LockoutThreshold': ['3'],
        'msDS-MinimumPasswordLength': ['15'],
        'msDS-PSOAppliesTo': ['CN=Domain Admins,OU=Groups,DC=corpnet,DC=loc'],
    },
}


def below(dn, base):
    """Whether `dn` is under `base`, and how far down."""
    if not base:
        return 0
    if dn.lower() == base.lower():
        return 0
    if not dn.lower().endswith(',' + base.lower()):
        return None
    return dn[:-(len(base) + 1)].count(',') + 1


def make_groups(how_many, first=1):
    """A domain with a great many groups in it, for the paging."""
    for n in range(first, first + how_many):
        dn = 'CN=Group %04d,OU=Groups,DC=corpnet,DC=loc' % n
        GROUPS[dn] = {'cn': ['Group %04d' % n], 'objectClass': ['top', 'group'],
                      'description': ['one of many']}
    return how_many


def move(who, group_dn):
    """Put somebody in one of the groups, and in no other.

    What a domain administrator does when they take an administrator's rights
    away, or give them - and the thing this application has to notice. `None`
    takes them out of every group, which is how somebody is shut out without
    their account being touched.
    """
    person = None
    for dn, one in PEOPLE.items():
        if who.lower() in (dn.lower(),
                           (one.get('sAMAccountName') or [''])[0].lower()):
            person = dn
            break
    if person is None:
        raise KeyError('%s is not in this directory' % who)
    # Both halves, the way a real directory keeps them: the group's list of
    # members, and the person's own list of groups. One without the other is
    # a directory that answers two different things to two questions that
    # mean the same, which is not a thing to test against.
    for one in GROUPS.values():
        one['member'] = [m for m in one.get('member', []) if m != person]
    PEOPLE[person]['memberOf'] = []
    if group_dn:
        GROUPS[group_dn].setdefault('member', []).append(person)
        PEOPLE[person]['memberOf'] = [group_dn]
    return person


def _read(data, at=0):
    return isemon._ber_read(data, at)


def _unpack_filter(body, tag):
    """The filter, as something this can answer: a small tree."""
    if tag == 0xA0 or tag == 0xA1:                  # and / or
        parts, at = [], 0
        while at < len(body):
            t, inner, at = _read(body, at)
            parts.append(_unpack_filter(inner, t))
        return {'op': 'and' if tag == 0xA0 else 'or', 'parts': parts}
    if tag == 0xA2:                                 # not
        t, inner, _ = _read(body)
        return {'op': 'not', 'part': _unpack_filter(inner, t)}
    if tag == 0xA3:                                 # equality
        t, name, at = _read(body)
        t, value, _ = _read(body, at)
        return {'op': '=', 'attr': name.decode(), 'value': value.decode()}
    if tag == 0x87:                                 # present
        return {'op': '*', 'attr': body.decode()}
    if tag == 0xA4:                                 # substrings
        t, name, at = _read(body)
        t, seq, _ = _read(body, at)
        bits, deep = [], 0
        while deep < len(seq):
            t, piece, deep = _read(seq, deep)
            bits.append(piece.decode())
        return {'op': '~', 'attr': name.decode(), 'value': ''.join(bits)}
    if tag == 0xA9:                                 # extensible: in chain
        rule = attr = value = ''
        at = 0
        while at < len(body):
            t, piece, at = _read(body, at)
            if t == 0x81:
                rule = piece.decode()
            elif t == 0x82:
                attr = piece.decode()
            elif t == 0x83:
                value = piece.decode()
        return {'op': 'chain', 'rule': rule, 'attr': attr, 'value': value}
    return {'op': 'none'}


def _members_of(group_dn, seen=None):
    """Everything in a group, walking the groups inside it."""
    seen = seen if seen is not None else set()
    if group_dn in seen:
        return set()
    seen.add(group_dn)
    out = set()
    for one in GROUPS.get(group_dn, {}).get('member', []):
        out.add(one)
        out |= _members_of(one, seen)
    return out


def _matches(dn, attrs, want):
    op = want.get('op')
    if op == 'and':
        return all(_matches(dn, attrs, p) for p in want['parts'])
    if op == 'or':
        return any(_matches(dn, attrs, p) for p in want['parts'])
    if op == 'not':
        return not _matches(dn, attrs, want['part'])
    if op == '*':
        return bool(attrs.get(want['attr']))
    if op == '=':
        return any(v.lower() == want['value'].lower()
                   for v in attrs.get(want['attr'], []))
    if op == '~':
        return any(want['value'].lower() in v.lower()
                   for v in attrs.get(want['attr'], []))
    if op == 'chain':
        # The other extensible rule this program uses: "this bit is set in
        # this number", which is how Active Directory is asked for the
        # accounts whose pre-authentication is off, whose account is
        # switched off, or which are domain controllers. Answered as a
        # different thing altogether before, so every one of those searches
        # came back with whatever the group walk happened to match.
        if want.get('rule') == isemon.LDAP_BITS:
            try:
                bit = int(want['value'])
                got = int((attrs.get(want['attr']) or ['0'])[0])
            except (TypeError, ValueError, IndexError):
                return False
            return bool(got & bit)
        # Active Directory answers this rule on either attribute, and this
        # program asks it both ways round, so this has to as well.
        #
        #   (member:1.2.840.113556.1.4.1941:=<dn>)   - is this entry a group
        #                                              that dn is in, at any
        #                                              depth?
        #   (memberOf:1.2.840.113556.1.4.1941:=<dn>) - is this entry in that
        #                                              group, at any depth?
        #
        # Only the first was answered here, so a search for "who is in the
        # groups that run the domain" came back empty against this and the
        # check that asked it could not tell that from a domain with nobody
        # in them.
        if want.get('attr', '').lower() == 'memberof':
            return dn in _members_of(want['value'])
        return want['value'] in _members_of(dn)
    return False


def serve(port=0, tls=None, stop=None):
    """Start it on a thread. Returns (port, stop_event)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = stop or threading.Event()

    def one(sock):
        bound_as = ['']
        buffer = b''
        try:
            while not stop.is_set():
                try:
                    tag, body, end = _read(buffer)
                except ValueError:
                    more = sock.recv(65536)
                    if not more:
                        return
                    buffer += more
                    continue
                buffer = buffer[end:]
                _t, mid_body, at = _read(body)
                mid = isemon._ber_int_of(mid_body)
                op_tag, op_body, after = _read(body, at)
                out = answer(op_tag, op_body, mid, bound_as, body[after:])
                if out is None:
                    return
                sock.sendall(out)
        except (OSError, ValueError):
            return
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def result(mid, tag, code, said=''):
        body = (isemon._ber_int(code, tag=0x0A) + isemon._ber_str('')
                + isemon._ber_str(said))
        return isemon._ber(0x30, isemon._ber_int(mid) + isemon._ber(tag, body))

    def paged_asked(controls):
        """The page size and cookie out of a request's controls, if it asked."""
        if not controls:
            return None
        try:
            _t, all_of, _ = _read(controls)
            at = 0
            while at < len(all_of):
                _t, one, at = _read(all_of, at)
                _t, oid, where = _read(one)
                if oid.decode() != '1.2.840.113556.1.4.319':
                    continue
                while where < len(one):
                    _t, value, where = _read(one, where)
                    if _t != 0x04:
                        continue
                    _t, inner, _ = _read(value)
                    _t, size, deep = _read(inner)
                    _t, cookie, _ = _read(inner, deep)
                    return (isemon._ber_int_of(size), cookie)
        except (ValueError, IndexError):
            return None
        return None

    def paged_done(mid, cookie):
        """A searchResDone carrying the cookie for the next page."""
        inner = isemon._ber(0x30, isemon._ber_int(0) + isemon._ber_str(cookie))
        controls = isemon._ber(0xA0, isemon._ber(
            0x30, isemon._ber_str('1.2.840.113556.1.4.319') + isemon._ber_str(inner)))
        body = (isemon._ber_int(0, tag=0x0A) + isemon._ber_str('') + isemon._ber_str(''))
        return isemon._ber(0x30, isemon._ber_int(mid) + isemon._ber(0x65, body) + controls)

    def answer(op_tag, body, mid, bound_as, controls=b''):
        if op_tag == 0x42:                           # unbind
            return None
        if op_tag == 0x60:                           # bind
            _t, _ver, at = _read(body)
            _t, dn_body, at = _read(body, at)
            _t, pw_body, _ = _read(body, at)
            dn = dn_body.decode()
            password = pw_body.decode()
            if not dn and not password:
                bound_as[0] = ''
                return result(mid, 0x61, 0)          # anonymous
            who = PEOPLE.get(dn)
            if not who:
                for entry_dn, attrs in PEOPLE.items():
                    # By its DN, or - as Active Directory also takes - by the
                    # userPrincipalName.
                    if entry_dn.lower() == dn.lower() or dn.lower() in [
                            u.lower() for u in attrs.get('userPrincipalName', [])]:
                        who = attrs
                        dn = entry_dn
                        break
            if not who or who['_password'] != password:
                return result(mid, 0x61, isemon.LDAP_BAD_CREDENTIALS,
                              '80090308: LdapErr: DSID-0C09044E, comment: '
                              # ...ended with a NUL, as a real domain
                              # controller ends it: 1.10.93 could not
                              # store that on PostgreSQL.
                              'AcceptSecurityContext error, data 52e, v4563\x00')
            bound_as[0] = dn
            return result(mid, 0x61, 0)
        if op_tag == 0x63:                           # search
            if not bound_as[0]:
                return result(mid, 0x65, 1, 'no anonymous searching here')
            _t, base_body, at = _read(body)
            _t, _scope, at = _read(body, at)
            _t, _deref, at = _read(body, at)
            _t, _size, at = _read(body, at)
            _t, _time, at = _read(body, at)
            _t, _types, at = _read(body, at)
            f_tag, f_body, at = _read(body, at)
            _t, attrs_body, _ = _read(body, at)
            want = _unpack_filter(f_body, f_tag)
            asked, deep = [], 0
            while deep < len(attrs_body):
                _t, one_attr, deep = _read(attrs_body, deep)
                asked.append(one_attr.decode())
            base = base_body.decode()
            out = b''
            # The root of the directory, and the partitions container beside
            # it: what a client asks when it wants to know what this
            # directory calls itself, rather than asking about a person.
            # Active Directory answers both, and what it says about its name
            # suffixes is how a program can know which names belong here
            # without anybody typing them in.
            if not base or base.lower().startswith('cn=partitions,'):
                one = ROOTDSE if not base else PARTITIONS
                pairs = b''
                for name, values in one.items():
                    if asked and '*' not in asked and name.lower() not in [a.lower() for a in asked]:  # "*": all (otp 1.0.229)
                        continue
                    pairs += isemon._ber(0x30, isemon._ber_str(name) + isemon._ber(
                        0x31, b''.join(isemon._ber_str(v) for v in values)))
                return isemon._ber(0x30, isemon._ber_int(mid) + isemon._ber(
                    0x64, isemon._ber_str(base) + isemon._ber(0x30, pairs))) \
                    + result(mid, 0x65, 0)
            everything = dict(PEOPLE)
            everything.update(GROUPS)
            everything.update(DOMAIN)
            everything.update(TRUSTS)
            everything.update(TREE)
            everything.update(CONTROLLERS)
            everything.update(POLICIES)
            everything.update(SITES)
            # Every domain controller has a ceiling of its own on how many
            # entries it will hand back in one answer - a thousand on Active
            # Directory unless somebody has changed it - and says "there is
            # more" by handing back a cookie rather than by sending them.
            # This is that, because a client that does not page is a client
            # that silently sees the first thousand of everything.
            paging = paged_asked(controls)
            # Scope, which this used to ignore altogether: 0 is the base
            # entry and nothing else, 1 is one level below it, 2 is
            # everything under it. A directory that answers a scope-0 search
            # with the whole subtree is a directory nothing can be tested
            # against - the domain object and the entries below it would all
            # come back as "the domain".
            scope = 2
            try:
                scope = isemon._ber_int_of(_scope)
            except Exception:
                scope = 2

            def in_scope(dn):
                deep = below(dn, base)
                if deep is None:
                    return False
                if scope == 0:
                    return deep == 0
                if scope == 1:
                    return deep == 1
                return True

            found = [(dn, attrs) for dn, attrs in everything.items()
                     if in_scope(dn) and _matches(dn, attrs, want)]
            found.sort()
            total = len(found)
            page_to = total
            if paging is not None:
                asked_size, cookie = paging
                page_from = int(cookie.decode() or 0) if cookie else 0
                per = max(1, min(int(asked_size) or MAX_PAGE, MAX_PAGE))
                page_to = min(total, page_from + per)
                found = found[page_from:page_to]
            for dn, attrs in found:
                pairs = b''
                for name, values in attrs.items():
                    if name.startswith('_'):
                        continue
                    if asked and '*' not in asked and name.lower() not in [a.lower() for a in asked]:  # "*": all (otp 1.0.229)
                        continue
                    pairs += isemon._ber(0x30, isemon._ber_str(name) + isemon._ber(
                        0x31, b''.join(isemon._ber_str(v) for v in values)))
                out += isemon._ber(0x30, isemon._ber_int(mid) + isemon._ber(
                    0x64, isemon._ber_str(dn) + isemon._ber(0x30, pairs)))
            if paging is not None and page_to < total:
                return out + paged_done(mid, str(page_to).encode())
            return out + result(mid, 0x65, 0)
        if op_tag == 0x77:                           # extended: StartTLS
            return result(mid, 0x78, 53, 'this one has no StartTLS')
        return result(mid, 0x65, 2, 'not something this answers')

    def run():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                sock, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if tls:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(tls[0], tls[1])
                    sock = ctx.wrap_socket(sock, server_side=True)
                except (ssl.SSLError, OSError):
                    continue
            threading.Thread(target=one, args=(sock,), daemon=True).start()
        try:
            srv.close()
        except OSError:
            pass

    threading.Thread(target=run, daemon=True).start()
    return port, stop


if __name__ == '__main__':
    args = sys.argv[1:]
    want_port = int(args[0]) if args and args[0].isdigit() else 0
    tls = None
    if '--tls' in args:
        at = args.index('--tls')
        tls = (args[at + 1], args[at + 2])
    port, stop = serve(want_port, tls)
    print('a directory that is not there, on 127.0.0.1:%d%s'
          % (port, ' over TLS' if tls else ''))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        stop.set()
