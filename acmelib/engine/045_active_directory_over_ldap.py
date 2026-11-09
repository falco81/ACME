# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Active Directory, over LDAP
# ---------------------------------------------------------------------------
# Taken whole from isemon, where it has been signing people in against Active
# Directory for a long time: enough of LDAP to bind, search and page, written
# out so that nothing has to be installed, and refusing on the wire to send
# anything that would change a directory.
LDAP_TIMEOUT = 12.0
LDAP_MAX_MESSAGE = 8 * 1024 * 1024

# The result codes worth telling apart.
LDAP_OK = 0
LDAP_NO_SUCH_OBJECT = 32
LDAP_BAD_CREDENTIALS = 49
# busy, unavailable, unwilling to answer now, other: another server may (1.0.59)
LDAP_TRY_ANOTHER = (51, 52, 80)
LDAP_SAYS = {
    0: 'success',
    1: 'the directory had an operations error',
    # Windows Server 2025 domain controllers require LDAP signing by default (1.0.61): a simple
    # bind over plain LDAP is refused with this code.
    8: 'the directory wants a signed or encrypted connection (strongerAuthRequired) - a domain '
       'controller that requires LDAP signing (Windows Server 2025 does by default) refuses a '
       'sign-in over plain LDAP: switch this directory to LDAPS (636) or STARTTLS',
    32: 'there is no such object under that base',
    34: 'the distinguished name is not well formed',
    48: 'that server will not take this kind of authentication',
    49: 'the name or the password was not accepted',
    50: 'that account may not read what was asked for',
    53: 'the server is unwilling to do that (a blank password, or an account '
        'that must change it)',
}

# Active Directory answers every one of these with the same code 49 and the
# same sentence, with the reason hidden in a hex number at the end of it:
# "data 52e" is a wrong password and "data 533" is a disabled account, and
# telling somebody to check their password when their account is disabled is
# how an afternoon gets wasted.
AD_REASONS = {
    '525': 'there is no such account',
    '52e': 'the password is not right',
    '530': 'that account may not sign in at this time of day',
    '531': 'that account may not sign in from this machine',
    '532': 'the password has expired',
    '533': 'the account is disabled',
    '568': 'the directory ran out of room for the groups this account is in',
    '701': 'the account has expired',
    '773': 'the password must be changed before this account can be used',
    '775': 'the account is locked out',
}


def ad_reason(said):
    """What Active Directory meant, in plain words - or what it said, when
    the hex number is not one of the known ones. What it said in full
    travels beside this as the error's `detail`, for whoever hovers over
    the sentence and wants the whole of it."""
    m = re.search(r'data ([0-9a-fA-F]{3})', str(said or ''))
    if not m:
        return str(said or '')
    return AD_REASONS.get(m.group(1).lower()) or str(said)


class Refused(ValueError):
    """A plain sentence for the person, with the whole of what happened
    kept beside it. The sentence is what the sign-in page shows; the detail
    is what appears when somebody hovers over it - "the password is not
    right" first, and the directory's own "80090308: LdapErr: DSID-..."
    only for whoever wants to read it."""

    def __init__(self, words, detail=''):
        super(Refused, self).__init__(words)
        self.detail = str(detail or '')


# The matching rule Active Directory uses for "in this group, or in a group
# inside it". It is the only way to see nested membership without walking
# the tree, and walking the tree over a slow link is how a sign-in takes ten
# seconds.
LDAP_IN_CHAIN = '1.2.840.113556.1.4.1941'


def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    body = b''
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def _ber(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _ber_int(value, tag=0x02):
    value = int(value)
    if value == 0:
        return _ber(tag, b'\x00')
    body = b''
    negative = value < 0
    n = value if not negative else -value - 1
    while n:
        body = bytes([(n & 0xFF) ^ (0xFF if negative else 0)]) + body
        n >>= 8
    if not body:
        body = b'\x00'
    top = body[0]
    if negative and not top & 0x80:
        body = b'\xff' + body
    elif not negative and top & 0x80:
        body = b'\x00' + body
    return _ber(tag, body)


def _ber_str(text, tag=0x04):
    if isinstance(text, bytes):
        return _ber(tag, text)
    return _ber(tag, str(text or '').encode('utf-8'))


def _ber_bool(value, tag=0x01):
    return _ber(tag, b'\xff' if value else b'\x00')


class BerMalformed(ValueError):
    """Not an answer cut short, but one that can never be read (1.0.59):
    said at once, not waited on until the deadline."""


def _ber_read(data, at=0):
    """One tag, its body, and where the next one starts."""
    if at + 2 > len(data):
        raise ValueError('the answer stopped in the middle')
    tag = data[at]
    length = data[at + 1]
    at += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise BerMalformed('the answer has a length this does not understand')
        if at + count > len(data):
            raise ValueError('the answer stopped in the middle')
        length = int.from_bytes(data[at:at + count], 'big')
        at += count
    if length > LDAP_MAX_MESSAGE:
        raise BerMalformed('the answer says it is longer than this will read')
    if at + length > len(data):
        raise ValueError('the answer is longer than it says it is')
    return tag, data[at:at + length], at + length


def _ber_int_of(body):
    if not body:
        # An INTEGER with no octets is no integer (1.0.101): read as 0 it
        # made a reply with an empty resultCode a successful bind.
        raise BerMalformed('an INTEGER with no value')
    value = int.from_bytes(body, 'big')
    if body[0] & 0x80:
        value -= 1 << (8 * len(body))
    return value


def ldap_escape(text):
    r"""A value going into a TEXT filter, with the four characters that mean
    something else written the way RFC 4515 says to write them.

    Not for the filters this program sends. Those are built as BER, where an
    assertion value goes on the wire as raw bytes and nothing in it means
    anything else - so there is nothing to escape, and escaping anyway
    CORRUPTS the value: `CN=Novak\, Jan` became `CN=Novak\5c, Jan`, which
    read as a distinguished name is a different name, and somebody who was an
    administrator only through a group inside a group was refused. A name
    with a bracket in it - `(VPN)`, which Active Directory allows - was never
    found at all. Kept for the debug log, which is text.
    """
    out = []
    for ch in str(text or ''):
        if ch in '\\*()' or ch == '\x00':
            out.append('\\%02x' % ord(ch))
        else:
            out.append(ch)
    return ''.join(out)


def ldap_equal(attr, value):
    """(attr=value), as BER."""
    return _ber(0xA3, _ber_str(attr) + _ber_str(value))


def ldap_present(attr):
    """(attr=*)"""
    return _ber_str(attr, tag=0x87)


def ldap_contains(attr, value):
    """(attr=*value*)"""
    return _ber(0xA4, _ber_str(attr) + _ber(0x30, _ber_str(value, tag=0x81)))


def ldap_and(*parts):
    return _ber(0xA0, b''.join(parts))


def ldap_or(*parts):
    return _ber(0xA1, b''.join(parts))


# Active Directory's "this bit is set in this number" rule, which is the
# only way to ask it for the accounts whose pre-authentication is off or
# whose account is disabled.
LDAP_BITS = '1.2.840.113556.1.4.803'


def ldap_bits(attr, value):
    """(attr:1.2.840.113556.1.4.803:=value)"""
    return _ber(0xA9, _ber_str(LDAP_BITS, tag=0x81)
                + _ber_str(attr, tag=0x82) + _ber_str(str(int(value)), tag=0x83))


def ldap_in_chain(attr, value):
    """(attr:1.2.840.113556.1.4.1941:=value) - Active Directory's "or in a
    group inside it"."""
    return _ber(0xA9, _ber_str(LDAP_IN_CHAIN, tag=0x81)
                + _ber_str(attr, tag=0x82) + _ber_str(value, tag=0x83))


# What each filter tag is, in the words RFC 4515 writes them in. Used for
# nothing but the debug log.
LDAP_FILTER_JOIN = {0xA0: '&', 0xA1: '|', 0xA2: '!'}
LDAP_FILTER_SIGN = {0xA3: '=', 0xA5: '>=', 0xA6: '<=', 0xA8: '~='}


def ldap_filter_words(ber, deep=0):
    """A filter that has been built as BER, written back out as text.

    Only ever for the log. The filters go on to the wire as BER and are
    built that way, so a debug line saying what was asked has either to be
    passed down through every caller - a second argument on a dozen
    functions, which would go out of step with the real one the first time
    somebody changed a filter and forgot the words beside it - or read back
    off the thing that was actually sent. This reads it back: what appears
    in the log is what went to the directory, and it cannot say otherwise.

    Nothing secret is ever in a filter - a name, a group, a flag - and the
    one thing that is secret, the password on a bind, is not a filter and
    never reaches this.
    """
    try:
        tag, body, _ = _ber_read(ber)
    except (ValueError, IndexError):
        return '(?)'
    if deep > 12:
        return '(…)'
    if tag in LDAP_FILTER_JOIN:
        out, at = [], 0
        while at < len(body):
            try:
                _t, one, nxt = _ber_read(body, at)
            except (ValueError, IndexError):
                break
            # Put the tag and the length back on the piece that was read
            # out, so each one goes round again as a filter in its own
            # right rather than as a body with no head.
            out.append(ldap_filter_words(_ber(_t, one), deep + 1))
            at = nxt
        return '(%s%s)' % (LDAP_FILTER_JOIN[tag], ''.join(out))
    if tag == 0x87:                                    # present
        return '(%s=*)' % body.decode('utf-8', 'replace')
    if tag in LDAP_FILTER_SIGN:
        try:
            _t, attr, at = _ber_read(body)
            _t, value, _ = _ber_read(body, at)
        except (ValueError, IndexError):
            return '(?)'
        return '(%s%s%s)' % (attr.decode('utf-8', 'replace'), LDAP_FILTER_SIGN[tag],
                             value.decode('utf-8', 'replace'))
    if tag == 0xA4:                                    # substrings
        try:
            _t, attr, at = _ber_read(body)
            _t, parts, _ = _ber_read(body, at)
        except (ValueError, IndexError):
            return '(?)'
        bits, where, first, last = [], 0, '', ''
        while where < len(parts):
            try:
                _t, one, where = _ber_read(parts, where)
            except (ValueError, IndexError):
                break
            text = one.decode('utf-8', 'replace')
            if _t == 0x80:
                first = text
            elif _t == 0x82:
                last = text
            else:
                bits.append(text)
        return '(%s=%s*%s%s)' % (attr.decode('utf-8', 'replace'), first,
                                 '*'.join(bits) + ('*' if bits else ''), last)
    if tag == 0xA9:                                    # extensible match
        rule, attr, value = '', '', ''
        where = 0
        while where < len(body):
            try:
                _t, one, where = _ber_read(body, where)
            except (ValueError, IndexError):
                break
            text = one.decode('utf-8', 'replace')
            if _t == 0x81:
                rule = text
            elif _t == 0x82:
                attr = text
            elif _t == 0x83:
                value = text
        return '(%s:%s:=%s)' % (attr, rule, value)
    return '(?)'


LDAP_SCOPE_WORDS = {0: 'that entry only', 1: 'one level down', 2: 'everything below'}

# Attributes never written to the log, whatever the debug switches say. None
# of these is ever asked for by this program; they are named here because a
# debug log is a file somebody copies into a ticket, and "it cannot happen"
# is not a reason to leave the door open: a password never reaches a row or
# a log.
LDAP_NEVER_LOG = ('userpassword', 'unicodepwd', 'dbcspwd', 'lmpwdhistory',
                  'ntpwdhistory', 'supplementalcredentials', 'msds-keycredentiallink',
                  'clearpassword', 'currentvalue', 'msds-managedpassword',
                  'trustauthincoming', 'trustauthoutgoing')


def ldap_entry_words(entries, most=6, wide=400):
    """What came back, short enough to be a line in a log.

    A search for the disabled accounts on a big domain is a thousand entries
    and nobody wants a thousand lines; a search that found one is exactly
    what somebody turned the debug on to see. So: the first few, whole, and
    a count of the rest.
    """
    out = []
    for one in list(entries)[:max(1, int(most))]:
        said = []
        for name in sorted((one.get('attrs') or {})):
            if name.lower() in LDAP_NEVER_LOG:
                said.append('%s=(not logged)' % name)
                continue
            values = (one.get('attrs') or {}).get(name) or []
            said.append('%s=%s' % (name, '|'.join(str(v) for v in values)))
        line = one.get('dn') or '(no dn)'
        if said:
            line += ' [' + '; '.join(said) + ']'
        out.append(line[:wide] + ('…' if len(line) > wide else ''))
    rest = len(entries) - len(out)
    if rest > 0:
        out.append('and %d more' % rest)
    return ' · '.join(out)


def describe_certificate(pem):
    """What a pasted certificate is, in words, or None if it is not one.

    Somebody importing a certificate authority wants to see that the right
    one landed - the name on it and when it runs out - and not a green tick
    that means "the text was saved". Python can read a certificate without
    any package being installed; what it cannot do without one is read it
    from a string, so it goes through a file that exists for a moment.
    """
    text = str(pem or '').strip()
    if '-----BEGIN CERTIFICATE-----' not in text:
        return None
    folder = None
    try:
        folder = tempfile.mkdtemp(prefix='acme-ca-')
        where = os.path.join(folder, 'ca.pem')
        with open(where, 'w', encoding='utf-8') as f:
            f.write(text if text.endswith('\n') else text + '\n')
        said = ssl._ssl._test_decode_cert(where)     # noqa: SLF001 - the only way in
        def one(pairs):
            out = {}
            for row in pairs or ():
                for key, value in row:
                    out[key] = value
            return out
        subject, issuer = one(said.get('subject')), one(said.get('issuer'))
        return {
            'subject': subject.get('commonName') or subject.get('organizationName') or '',
            'issuer': issuer.get('commonName') or issuer.get('organizationName') or '',
            'from': said.get('notBefore') or '',
            'until': said.get('notAfter') or '',
            'self_signed': subject == issuer,
            'count': text.count('-----BEGIN CERTIFICATE-----'),
        }
    except Exception:
        return None
    finally:
        if folder:
            shutil.rmtree(folder, ignore_errors=True)


PEM_BLOCK = re.compile(r'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----')


def certificate_is_ca(pem):
    """True when the certificate says it is an authority (basicConstraints CA:TRUE), False when
    it says it is not or says nothing, None when it cannot be read (no openssl)."""
    exe = shutil.which('openssl')
    if not exe:
        return None
    try:
        got = subprocess.run([exe, 'x509', '-noout', '-text'], input=str(pem), capture_output=True,
                             text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if got.returncode != 0:
        return None
    if 'Basic Constraints' not in got.stdout:
        return None         # an old (v1) root says nothing: not taken for a server's (1.0.62)
    return bool(re.search(r'CA:\s*TRUE', got.stdout))


def split_certificates(pem):
    """Each certificate of a bundle, as its own PEM block, in order."""
    return [m.group(0).strip() for m in PEM_BLOCK.finditer(str(pem or ''))]


def describe_certificates(pem):
    """Every certificate of a bundle, one by one: who it is, who signed it,
    when it runs out and its fingerprint - so that one of several chains can
    be told apart from another and taken out by itself. (1.0.11)"""
    out = []
    for block in split_certificates(pem):
        said = describe_certificate(block) or {}
        try:
            fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest()
        except Exception:                               # noqa: BLE001
            fp = hashlib.sha256(block.encode()).hexdigest()
        said = dict(said, fingerprint=fp, readable=bool(said))
        said.pop('count', None)
        out.append(said)
    return out


class LdapError(RuntimeError):
    """Something the person setting this up needs to read."""

    def __init__(self, said, code=None, detail=''):
        # The directory ends its own error text with a NUL. It means nothing
        # to anybody, and a database server refuses to store it.
        said = str(said).replace('\x00', '')
        super(LdapError, self).__init__(said)
        self.code = code
        # What the directory said, word for word, when `said` is the plain
        # reading of it. Empty when `said` already is the whole of it.
        self.detail = str(detail or '').replace('\x00', '')

    def whole(self):
        """Everything known about this, for a tooltip: the detail when there
        is one, the sentence itself otherwise."""
        return self.detail or str(self)


class LdapNotAsked(LdapError):
    """A password refused before the directory was asked - empty, holding a control
    character, no account to bind as (otp 1.0.234): not one of the directory's wrong
    passwords, so not counted against the person's cap."""


class LdapUnreachable(LdapError):
    """The directory could not be asked at all.

    Different from the directory saying no, and the difference decides
    whether a sign-in may fall back to a local account. A domain controller
    being rebooted must not lock everybody out of this dashboard; a domain
    account being disabled must not be got round by an old local password.
    Anything that happens before there is an answer about the person - the
    connection, the TLS, the account this reads the directory with - is this
    one.
    """


class Ldap(object):
    """One conversation with a directory.

    Opened, asked, closed. Nothing is kept between sign-ins: a pooled
    connection to a domain controller that has been restarted is a sign-in
    that fails for no reason anybody can see.
    """

    # How many pages one search may take. A directory of a hundred thousand
    # groups at a thousand a page is a hundred; two hundred is room to spare
    # and a floor under a server whose paging cookie never empties.
    PAGES_MOST = 200

    def __init__(self, host, port=389, tls='none', ca_pem='', verify=True,
                 timeout=LDAP_TIMEOUT, weak=False):
        self.host = str(host or '').strip()
        self.weak = bool(weak)
        self.port = int(port or 389)
        self.tls = str(tls or 'none').strip().lower()
        self.ca_pem = str(ca_pem or '')
        self.verify = bool(verify)
        self.timeout = float(timeout or LDAP_TIMEOUT)
        self.sock = None
        self.next_id = 1
        self.buffer = b''
        # The controls that came with the last message read; the paging
        # cookie is taken out of them.
        self.last_controls = b''

    # ---- the wire ---------------------------------------------------------
    def open(self):
        if not self.host:
            raise LdapError('no directory server has been given')
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
        except OSError as e:
            raise LdapError('%s:%d could not be reached: %s'
                            % (self.host, self.port, str(e)[:120]))
        self.sock.settimeout(self.timeout)
        if self.tls == 'ldaps':
            self.sock = self._wrap(self.sock)
        elif self.tls == 'starttls':
            self._start_tls()
        if debugging('ldap'):
            log('ldap %s:%d open, %s' % (self.host, self.port,
                                         {'ldaps': 'over TLS',
                                          'starttls': 'over TLS after STARTTLS'}
                                         .get(self.tls, 'in the clear')), 'debug')
        return self

    def _context(self):
        ctx = ssl.create_default_context()
        if self.ca_pem.strip():
            try:
                ctx.load_verify_locations(cadata=self.ca_pem)
            except (ssl.SSLError, ValueError) as e:
                raise LdapError('the certificate authority could not be read: %s'
                                % str(e)[:120])
        if self.weak:
            # Old domain controllers (1.0.77): a 1024-bit RSA key, a SHA-1
            # signature, TLS 1.0 - refused at OpenSSL's default level
            # ("EE certificate key too weak", "ca md too weak"). Level 0 takes
            # them; the certificate is still checked against the authority
            # and the server's name, unless that check is off as well.
            try:
                ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
            except ssl.SSLError:
                ctx.set_ciphers('ALL:@SECLEVEL=0')
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            except (ValueError, AttributeError):
                pass
            # And an old authority's certificate without the extensions
            # Python 3.13 insists on (key usage, a critical basicConstraints):
            # still a chain to that authority, checked.
            ctx.verify_flags &= ~getattr(ssl, 'VERIFY_X509_STRICT', 0)
        if not self.verify:
            # Deliberate, and said out loud wherever it is switched on: a
            # directory reached without checking its certificate is a
            # directory anybody on the path can pretend to be.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _wrap(self, sock):
        try:
            return self._context().wrap_socket(sock, server_hostname=self.host)
        except ssl.SSLCertVerificationError as e:
            said = str(e.verify_message or e)[:120]
            if 'too weak' in said and not self.weak:
                raise LdapError('the server’s certificate was not accepted: %s. Its key or its '
                                'signature is older than OpenSSL takes by default (a 1024-bit '
                                'key, SHA-1): switch on "Take old, weak certificates" for this '
                                'directory - or better, give the server a new certificate.'
                                % said)
            if 'mismatch' in said.lower():
                try:
                    ipaddress.ip_address(self.host.strip('[]'))
                    is_ip = True
                except ValueError:
                    is_ip = False
                if is_ip:
                    # A domain controller's certificate names it, not its address (1.0.61).
                    raise LdapError('the server’s certificate does not name the address %s: give '
                                    'the domain controller by its name (its FQDN, as in '
                                    'dc1.example.com) - its certificate names that, not its '
                                    'address' % self.host)
                raise LdapError('the server’s certificate does not name %s: %s. Give the server '
                                'by a name its certificate has' % (self.host, said))
            raise LdapError('the server’s certificate was not accepted: %s. Import the '
                            'certificate authority that signed it, or switch the check off '
                            'if this is a test.' % said)
        except (ssl.SSLError, OSError) as e:
            said = str(e)[:160]
            if not self.weak and any(w in said.lower() for w in (
                    'too small', 'too weak', 'legacy', 'unsupported protocol', 'sslv3',
                    'no protocols available', 'version')):
                raise LdapError('TLS to %s:%d did not start: %s - an old server (a weak key, '
                                'TLS 1.0): switch on "Take old, weak certificates" for this '
                                'directory' % (self.host, self.port, said))
            raise LdapError('TLS to %s:%d did not start: %s'
                            % (self.host, self.port, said))

    def _start_tls(self):
        """The extended operation that turns a plain connection into a
        secure one, on the same port."""
        body = _ber_str(self.START_TLS_OID, tag=0x80)
        tag, answer = self._ask(_ber(0x77, body))
        if tag != 0x78:
            raise LdapError('the server did not answer the StartTLS request')
        code, said = self._result_of(answer)
        if code != LDAP_OK:
            raise LdapError('StartTLS was refused: %s' % (said or LDAP_SAYS.get(code, code)),
                            code)
        # Nothing may be left in the read buffer from BEFORE the connection
        # was made secure. Whatever arrived in plain text after the StartTLS
        # reply used to sit there and be read back as if it had come over
        # TLS - so somebody on the path could append a forged "bind
        # succeeded" to the server's reply, the real handshake would then
        # complete, and the next bind - a person signing in with any
        # password at all - would be answered by the forgery. RFC 4511
        # says the same thing: a client MUST NOT have outstanding data at
        # this point, and the honest thing to do with any is to refuse.
        if self.buffer:
            many = len(self.buffer)
            # Thrown away, and the connection with it: nothing may ever be
            # read off this socket again.
            self.buffer = b''
            try:
                self.sock.close()
            except Exception:
                pass
            raise LdapError('%s sent %d byte(s) in the clear after agreeing to TLS, '
                            'which is not something a directory does' % (self.host, many))
        self.sock = self._wrap(self.sock)
        self.buffer = b''

    def close(self):
        if self.sock:
            try:
                self._send(_ber(0x42, b''))          # unbindRequest, politely
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *_):
        self.close()

    # The only four things this program may ever say to a directory, as the
    # tags they go on to the wire as.
    #
    #   0x60 bind      - sign in
    #   0x63 search    - ask
    #   0x42 unbind    - go away
    #   0x77 extended  - StartTLS, and nothing else is sent
    #
    # THIS PROGRAM NEVER CHANGES ANYTHING IN ACTIVE DIRECTORY. Not an
    # attribute, not a group, not a password, not an account: it reads, and
    # that is the whole of it. That is not a promise about what the code
    # happens to do today - it is checked here, on the way out, on every
    # message: an add (0x68), a modify (0x66), a delete (0x4A), a rename
    # (0x6C) or a compare (0x6E) cannot leave this program even if somebody
    # writes the code to build one. A check reads this list and another
    # proves the socket refuses each of them.
    MAY_SAY = (0x60, 0x63, 0x42, 0x77)
    START_TLS_OID = '1.3.6.1.4.1.1466.20037'
    WRITES = {0x66: 'modify', 0x68: 'add', 0x4A: 'delete', 0x6C: 'rename',
              0x6D: 'rename', 0x6E: 'compare'}

    def _send(self, op, controls=b''):
        tag = op[0] if op else 0
        if tag not in self.MAY_SAY:
            raise LdapError(
                'this program only ever READS a directory, and something tried to '
                'send it a %s. Nothing was sent.'
                % self.WRITES.get(tag, 'message of kind 0x%02X' % tag))
        # An extended operation is a door to anything the server offers -
        # a password change is one of them (1.3.6.1.4.1.4203.1.11.1). The
        # only one this program has any business sending is StartTLS, so
        # the only one it may send is StartTLS, by name.
        # The whole message, byte for byte: the name being somewhere inside
        # it let a password change through that carried it as its value.
        if tag == 0x77 and op != _ber(0x77, _ber_str(self.START_TLS_OID, tag=0x80)):
            raise LdapError('this program only ever READS a directory, and something '
                            'tried to send it an extended operation that is not '
                            'StartTLS. Nothing was sent.')
        mid = self.next_id
        self.next_id += 1
        try:
            self.sock.sendall(_ber(0x30, _ber_int(mid) + op + controls))
        except OSError as e:
            # The line gone, not the directory saying no (1.0.44).
            raise LdapUnreachable('the connection to %s failed: %s' % (self.host, str(e)[:100]))
        return mid

    def _read_message(self):
        """One whole LDAP message off the wire.

        The controls come back too. Only one is read here and it is the one
        that matters on a real domain: how to ask for the next page.
        """
        while True:
            try:
                tag, body, end = _ber_read(self.buffer)
                self.buffer = self.buffer[end:]
                if tag != 0x30:
                    raise LdapError('the server sent something that is not an LDAP message')
                # The message is whole by now (1.0.98): what does not read
                # inside it is damaged, not "not all here yet" - that waited
                # the whole timeout for bytes that were never coming.
                try:
                    _mid_tag, mid_body, at = _ber_read(body)
                    op_tag, op_body, after = _ber_read(body, at)
                except ValueError as e:
                    raise BerMalformed('a message whose inside does not read (%s)' % e)
                self.last_controls = body[after:]
                mid = _ber_int_of(mid_body)
                if mid == 0 and op_tag == 0x78:
                    # A Notice of Disconnection (RFC 4511 4.4.1, 1.0.59): the
                    # server is going away - the next one is asked now, not
                    # after the whole timeout.
                    raise LdapUnreachable('%s said it is closing the connection' % self.host)
                return mid, op_tag, op_body
            except BerMalformed as e:
                raise LdapError('%s sent an answer that does not read: %s' % (self.host, e))
            except ValueError:
                pass                                  # not all here yet
            # One deadline for the whole answer (1.0.33): a server that sends
            # a byte at a time, or answers to other message IDs, kept the
            # worker that asked for as long as it liked.
            left = getattr(self, '_deadline', 0) - time.time()
            if getattr(self, '_deadline', 0) and left <= 0:
                raise LdapUnreachable('%s did not finish answering within %d s'
                                % (self.host, int(self.timeout * 3)))
            try:
                if getattr(self, '_deadline', 0):
                    self.sock.settimeout(max(0.05, min(self.timeout, left)))
                more = self.sock.recv(65536)
            except socket.timeout:
                raise LdapUnreachable('%s did not answer within %d s'
                                      % (self.host, int(self.timeout)))
            except OSError as e:
                raise LdapUnreachable('the connection to %s failed: %s'
                                      % (self.host, str(e)[:100]))
            if not more:
                raise LdapUnreachable('%s closed the connection' % self.host)
            if len(self.buffer) + len(more) > LDAP_MAX_MESSAGE:
                raise LdapError('the server sent more than this will read')
            self.buffer += more

    def _ask(self, op):
        mid = self._send(op)
        self._deadline = time.time() + self.timeout * 3
        try:
            while True:
                got_id, tag, body = self._read_message()
                if got_id == mid:
                    return tag, body
        finally:
            # Left set, the old deadline ran out under the next search on the
            # same connection, which then failed at once. (1.0.36)
            self._deadline = 0

    @staticmethod
    def _result_of(body):
        """resultCode and the message beside it, out of any LDAPResult."""
        tag, code_body, at = _ber_read(body)
        code = _ber_int_of(code_body)
        said = ''
        try:
            _t, _matched, at = _ber_read(body, at)
            _t, message, _ = _ber_read(body, at)
            said = message.decode('utf-8', 'replace').strip()
        except ValueError:
            pass
        return code, said

    # ---- what it is asked -------------------------------------------------
    def bind(self, dn='', password=''):
        try:
            return self._bind(dn, password)
        except (ValueError, IndexError) as e:
            # An answer that does not read is the directory failing, not this
            # program (1.0.33).
            raise LdapError('%s sent an answer that does not read: %s' % (self.host, e))

    def _bind(self, dn='', password=''):
        """A simple bind. An empty password is refused here rather than on
        the server: many directories take one as an anonymous bind and
        answer "yes", which would turn a blank password into a sign-in."""
        if dn and not str(password or ''):
            raise LdapError('a password is needed', LDAP_BAD_CREDENTIALS)
        # The name only. The password is the one thing in this program that
        # is never written anywhere, debug or no debug, and a bind is where
        # it would be easiest to write by accident.
        if debugging('ldap'):
            log('ldap %s: signing in as %s (the password is never logged)'
                % (self.host, dn or 'nobody — anonymous'), 'debug')
        op = _ber(0x60, _ber_int(3) + _ber_str(dn)
                  + _ber_str(password, tag=0x80))
        tag, body = self._ask(op)
        if tag != 0x61:
            raise LdapError('the server did not answer the sign-in')
        code, said = self._result_of(body)
        if code != LDAP_OK:
            plain = ad_reason(said) or LDAP_SAYS.get(code, 'the directory said %d' % code)
            raise LdapError(plain, code,
                            detail='%s (result %d)' % (said, code) if said else '')
        return True

    # Simple paged results: the control every directory of any size needs.
    # Active Directory will not hand back more than its MaxPageSize - a
    # thousand entries by default - however large a size limit is asked for.
    # It answers with a cookie instead, and the next page is asked for by
    # handing that cookie back. Without it, a domain with three thousand
    # groups looked like a domain with a thousand, and nobody could tell
    # which thousand.
    PAGED_OID = '1.2.840.113556.1.4.319'
    PAGE_SIZE = 500

    def _paging_control(self, cookie=b'', size=None):
        # `size=0` with the cookie is how a paged search is given up on
        # (RFC 2696): the server lets the result set go. Anything else with
        # the cookie asks for the next page.
        inner = _ber(0x30, _ber_int(self.PAGE_SIZE if size is None else int(size))
                     + _ber_str(cookie))
        return _ber(0xA0, _ber(0x30, _ber_str(self.PAGED_OID) + _ber_str(inner)))

    def _paging_cookie(self, controls):
        """The cookie out of a searchResDone, or b'' when there is no more."""
        if not controls:
            return b''
        try:
            tag, body, _ = _ber_read(controls)         # [0] controls
            at = 0
            while at < len(body):
                _t, one, at = _ber_read(body, at)
                _t, oid, where = _ber_read(one)
                if oid.decode('utf-8', 'replace') != self.PAGED_OID:
                    continue
                while where < len(one):
                    _t, value, where = _ber_read(one, where)
                    if _t != 0x04:                     # criticality, skip it
                        continue
                    _t, inner, _ = _ber_read(value)
                    _t, _size, deep = _ber_read(inner)
                    _t, cookie, _ = _ber_read(inner, deep)
                    return cookie
        except (ValueError, IndexError):
            return b''
        return b''

    def search(self, base, filter_ber, attrs=(), scope=2, limit=200, paged=False):
        try:
            return self._search(base, filter_ber, attrs, scope, limit, paged)
        except (ValueError, IndexError) as e:
            raise LdapError('%s sent an answer that does not read: %s' % (self.host, e))
        finally:
            self._deadline = 0

    def _search(self, base, filter_ber, attrs=(), scope=2, limit=200, paged=False):
        """Entries under `base` matching `filter_ber`.

        scope 0 = that entry, 1 = one level down, 2 = everything below.
        Referrals are skipped: Active Directory answers a search at the
        domain root with one per other partition, and following them needs
        credentials for those partitions.

        `paged` asks the directory for it a page at a time and keeps going
        until it says there is no more, which is the only way to see past a
        thousand of anything on Active Directory. `limit` is then how many
        this will hold rather than how many the directory will send.
        """
        want = b''.join(_ber_str(a) for a in attrs)
        cap = max(0, int(limit))
        out = []
        cookie = b''
        # With the LDAP debug on, what is being asked and what came back.
        # Two lines rather than one - the question goes into the log BEFORE
        # the directory is asked, so a search that never answers is still in
        # there with the question that hung it, which is the whole reason
        # anybody turns this on.
        loud = debugging('ldap')
        began = time.time()
        if loud:
            log('ldap %s: %s under %s, %s, wanting %s%s'
                % (self.host, ldap_filter_words(filter_ber), base or '(root)',
                   LDAP_SCOPE_WORDS.get(int(scope), 'scope %d' % scope),
                   ', '.join(attrs) if attrs else 'everything',
                   ', a page at a time' if paged else ''), 'debug')
        # A page count as well as the two exits below. A directory that hands
        # back a cookie with no entries in it - broken, or hostile - would
        # otherwise keep this thread here for ever.
        pages = 0
        while True:
            pages += 1
            if pages > self.PAGES_MOST:
                # What was read so far is the answer, said to be cut short -
                # NOT nothing. This used to fall out of the loop with no
                # return at all, so a search over more than a hundred
                # thousand entries came back as `None`, the caller read that
                # as "nought of them", and a big domain's count of switched-
                # off accounts was written down as zero.
                log('%s: one search ran to %d pages (%s entries) and was cut short there'
                    % (self.host, pages - 1, len(out)), 'warn')
                self._let_go(base, scope, filter_ber, want, cookie)
                return out
            asked = 0 if paged else cap
            op = _ber(0x63,
                      _ber_str(base) + _ber_int(scope, tag=0x0A) + _ber_int(0, tag=0x0A)
                      + _ber_int(asked) + _ber_int(int(self.timeout))
                      + _ber_bool(False) + filter_ber + _ber(0x30, want))
            mid = self._send(op, self._paging_control(cookie) if paged else b'')
            # Per page (1.0.36), and never past the whole search's (1.0.59):
            # a server handing out page after page slowly held a sign-in
            # for as long as two hundred pages took.
            self._deadline = min(time.time() + self.timeout * 3, began + self.timeout * 6)
            if self._deadline <= time.time():
                raise LdapUnreachable('%s did not finish the search within %d s'
                                      % (self.host, int(self.timeout * 6)))
            done = False
            while not done:
                got_id, tag, body = self._read_message()
                if got_id != mid:
                    continue
                if tag == 0x64:                        # searchResEntry
                    if not cap or len(out) < cap:
                        out.append(self._entry_of(body))
                elif tag == 0x73:                      # searchResRef
                    continue
                elif tag == 0x65:                      # searchResDone
                    code, said = self._result_of(body)
                    if code not in (LDAP_OK, 4, LDAP_NO_SUCH_OBJECT):
                        raise LdapError(said or LDAP_SAYS.get(
                            code, 'the directory said %d' % code), code)
                    cookie = self._paging_cookie(self.last_controls) if paged else b''
                    done = True
                else:
                    raise LdapError('the server sent an answer this does not understand')
            self._deadline = 0
            if not paged or not cookie or (cap and len(out) >= cap):
                # A search that is being given up on mid-way is abandoned
                # properly, so the directory is not left holding the page.
                if paged and cookie:
                    self._let_go(base, scope, filter_ber, want, cookie)
                if loud:
                    log('ldap %s: %d entr%s in %d ms%s%s'
                        % (self.host, len(out), 'y' if len(out) == 1 else 'ies',
                           int((time.time() - began) * 1000),
                           ' over %d pages' % pages if pages > 1 else '',
                           (' — ' + ldap_entry_words(out)) if out else ''), 'debug')
                return out

    def _let_go(self, base, scope, filter_ber, want, cookie):
        """Tell the directory to drop a paged search that will not be finished.

        RFC 2696: the same search again, with the cookie and a page size of
        NOUGHT. Sent with the ordinary page size - which is what this did -
        it is not an abandon at all but a request for another five hundred
        entries, whose reply then sits unread on the connection; and a
        directory allows only so many open result sets per connection, so
        the tenth search that stopped early made the eleventh fail.
        """
        try:
            mid = self._send(_ber(0x63,
                                  _ber_str(base) + _ber_int(scope, tag=0x0A)
                                  + _ber_int(0, tag=0x0A) + _ber_int(0)
                                  + _ber_int(int(self.timeout)) + _ber_bool(True)
                                  + filter_ber + _ber(0x30, want)),
                             self._paging_control(cookie, size=0))
            # ...and its one-line answer read, so it is not left lying on
            # the connection for the next search to trip over.
            self._deadline = time.time() + self.timeout
            for _ in range(50):
                got_id, tag, _body = self._read_message()
                if got_id == mid and tag == 0x65:
                    break
        except (OSError, LdapError, ValueError):
            pass
        finally:
            self._deadline = 0

    @staticmethod
    def _entry_of(body):
        tag, dn_body, at = _ber_read(body)
        entry = {'dn': dn_body.decode('utf-8', 'replace'), 'attrs': {}}
        tag, attrs_body, _ = _ber_read(body, at)
        inner = 0
        while inner < len(attrs_body):
            _t, one, inner = _ber_read(attrs_body, inner)
            _t, name, where = _ber_read(one)
            _t, values, _ = _ber_read(one, where)
            got = []
            deep = 0
            while deep < len(values):
                _t, value, deep = _ber_read(values, deep)
                got.append(value.decode('utf-8', 'replace'))
            entry['attrs'][name.decode('utf-8', 'replace')] = got
        return entry



