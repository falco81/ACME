# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Sending mail (1.0.20)
# ---------------------------------------------------------------------------
# A token's QR code, and if wanted its recovery codes, sent to the person it
# is for. Two ways out: through a mail server (SMTP relay, with STARTTLS,
# SMTPS or nothing, signing in with PLAIN, LOGIN, CRAM-MD5, XOAUTH2 or not at
# all), or straight to the server of the recipient's domain - its MX record,
# looked up here - with no relay at all. A certificate signed by an authority
# of your own is trusted once that authority is added, as for a directory.

MAIL_CA_META = 'mail_ca'
MAIL_DIRECT_DEADLINE_S = 60     # every MX of one domain together (1.0.59)


def mail_ca_pem(store):
    try:
        return str(store.get_meta(MAIL_CA_META) or '')
    except Exception:
        return ''


def mail_ca_set(store, pem, mode='add', fingerprint=''):
    """The authorities trusted for the mail server, each added and taken out
    by itself - the same as a directory's."""
    pem = str(pem or '').strip()
    have = split_certificates(mail_ca_pem(store))
    if mode == 'add':
        # Nothing sent is not "empty the list" (1.0.146): only 'clear' empties it.
        new = split_certificates(pem)
        if not new or not all(describe_certificate(b) for b in new):
            raise ValueError('that is not a certificate this can read: a PEM certificate '
                             'starts -----BEGIN CERTIFICATE-----')
        seen = {c['fingerprint'] for c in describe_certificates('\n'.join(have))}
        have += [b for b, c in zip(new, describe_certificates('\n'.join(new)))
                 if c['fingerprint'] not in seen]
    elif mode == 'drop':
        keep = [b for b, c in zip(have, describe_certificates('\n'.join(have)))
                if c['fingerprint'] != fingerprint]
        if len(keep) == len(have):
            raise ValueError('that certificate is not among the ones kept')
        have = keep
    elif mode == 'clear':
        have = []
    else:
        raise ValueError('add, drop or clear?')
    store.set_meta(MAIL_CA_META, '\n'.join(have))
    return describe_certificates('\n'.join(have))


def mail_tls(store, verify=None):
    verify = bool(CONFIG.get('smtp_verify', 1)) if verify is None else verify
    ctx = ssl.create_default_context()
    pem = mail_ca_pem(store)
    if pem.strip():
        try:
            ctx.load_verify_locations(cadata=pem)
        except (ssl.SSLError, ValueError) as e:
            raise MailError('the certificate authorities kept for mail cannot be read: %s' % e)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class MailError(RuntimeError):
    """`permanent` (1.0.95): the receiving side said no for good (a 5xx) -
    not tried again. Anything else - a 4xx (greylisting), a server away -
    is, from the outgoing mail."""
    def __init__(self, said, steps=None, permanent=False):
        super(MailError, self).__init__(said)
        self.steps = steps or []
        self.permanent = bool(permanent)
        self.queued = None
        # The recipients still to be sent to (1.0.206); None: every one of them.
        self.left = None


# ---- the recipients' servers, without a library to ask DNS with -----------------
def own_dns():
    """The DNS servers set for mail going direct (`mail_dns`), if any."""
    good = []
    for w in re.split(r'[\s,;]+', str(CONFIG.get('mail_dns') or '')):
        try:
            good.append(str(ipaddress.ip_address(w)))
        except ValueError:
            pass
    return good


def dns_servers():
    if own_dns():
        return own_dns()
    out = []
    try:
        with open('/etc/resolv.conf') as f:
            for line in f:
                bits = line.split()
                if len(bits) >= 2 and bits[0] == 'nameserver':
                    out.append(bits[1])
    except OSError:
        pass
    return out or ['127.0.0.1']


def _dns_name(data, at):
    labels, jumped, end = [], False, at
    for _ in range(64):
        n = data[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = at + 2
            at = ((n & 0x3F) << 8) | data[at + 1]
            jumped = True
            continue
        labels.append(data[at + 1:at + 1 + n].decode('ascii', 'replace'))
        at += 1 + n
    return '.'.join(labels), (end if jumped else at)


def _dns_ask(server, name, qtype, timeout):
    """One question to one DNS server: the raw answer. EDNS0 asks for room
    for a long answer; one that is cut short anyway is asked again over TCP
    (1.0.22)."""
    ident = secrets.randbits(16)
    q = struct.pack('>HHHHHH', ident, 0x0100, 1, 0, 0, 1)
    for label in name.split('.'):
        if not label:
            continue
        raw = label.encode('idna') if any(ord(c) > 127 for c in label) else label.encode()
        q += bytes([len(raw)]) + raw
    q += b'\x00' + struct.pack('>HH', qtype, 1)
    q += b'\x00' + struct.pack('>HHIH', 41, 4096, 0, 0)          # OPT: 4096 bytes
    fam = socket.AF_INET6 if ':' in server else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    deadline = time.time() + timeout
    question = q[12:-11]                    # the name, the type and the class asked
    try:
        # connect(): only answers from the server asked are read at all.
        s.connect((server, 53))
        s.send(q)
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout('no answer from %s' % server)
            s.settimeout(left)
            data = s.recv(65535)
            # Its own answer: the same ID, and the same question (1.0.33) -
            # and no waiting past the deadline however many others come.
            if len(data) >= 12 + len(question) and struct.unpack('>H', data[:2])[0] == ident \
                    and data[12:12 + len(question)].lower() == question.lower():
                break
    finally:
        s.close()
    if struct.unpack('>H', data[2:4])[0] & 0x0200:                # TC: cut short
        t = socket.create_connection((server, 53), timeout=timeout)
        try:
            t.sendall(struct.pack('>H', len(q)) + q)
            want, got = None, b''
            while want is None or len(got) < want + 2:
                chunk = t.recv(65535)
                if not chunk:
                    break
                got += chunk
                if want is None and len(got) >= 2:
                    want = struct.unpack('>H', got[:2])[0]
            data = got[2:]
        finally:
            t.close()
    return data


def _dns_records(data):
    """(rcode, [(type, name, rdata-offset, size)]) of an answer."""
    flags, qd, an = struct.unpack('>HHH', data[2:8])
    at = 12
    for _ in range(qd):
        _, at = _dns_name(data, at)
        at += 4
    out = []
    for _ in range(an):
        rname, at = _dns_name(data, at)
        rtype, _cls, _ttl, size = struct.unpack('>HHIH', data[at:at + 10])
        at += 10
        out.append((rtype, rname, at, size))
        at += size
    return flags & 0x0F, out


DNS_RCODES = {1: 'could not read the question', 2: 'failed (SERVFAIL)', 4: 'does not do that',
              5: 'refused to answer'}


def dns_mx_full(domain, timeout=5.0):
    """The mail servers of a domain, best first, and how they were found:
    ([(preference, host)], words). A domain with no MX record is its own
    mail server (RFC 5321) - but only when a DNS server said so, never
    because one failed to answer (1.0.22: a failed answer was taken for
    "no MX" and the mail went to the domain's own address)."""
    domain = str(domain).strip().strip('.').lower()
    try:                                       # dnspython, where it is installed
        if own_dns():
            # The DNS servers set for mail are the ones asked (1.0.59):
            # dnspython reads the system's, and with a split horizon its
            # NXDOMAIN was taken for the last word.
            raise ImportError('mail_dns is set')
        import dns.resolver                     # type: ignore
        try:
            ans = dns.resolver.resolve(domain, 'MX', lifetime=timeout * 2)
            got = sorted((int(r.preference), str(r.exchange).rstrip('.')) for r in ans)
            got = [g for g in got if g[1]]
            if got:
                return got, 'MX records (dnspython)'
        except dns.resolver.NXDOMAIN:
            raise MailError('the domain %s does not exist' % domain)
        except dns.resolver.NoAnswer:
            return [(0, domain)], 'no MX record: the domain itself (dnspython)'
        except Exception:                       # noqa: BLE001 - our own below
            pass
    except ImportError:
        pass
    trouble = []
    name = domain
    for server in dns_servers():
        name = domain
        for _hop in range(6):                   # a CNAME, followed
            try:
                data = _dns_ask(server, name, 15, timeout)
                rcode, recs = _dns_records(data)
            except (OSError, struct.error, IndexError, ValueError) as e:
                trouble.append('%s: %s' % (server, e))
                break
            if rcode == 3:
                raise MailError('the domain %s does not exist (DNS %s)' % (name, server))
            if rcode:
                trouble.append('%s %s' % (server, DNS_RCODES.get(rcode, 'answered %d' % rcode)))
                break
            mx, cname, nullmx = [], None, False
            try:
                for rtype, _rname, at, _size in recs:
                    if rtype == 15:
                        pref = struct.unpack('>H', data[at:at + 2])[0]
                        host, _ = _dns_name(data, at + 2)
                        if host and host != '.':
                            mx.append((pref, host.rstrip('.').lower()))
                        else:
                            nullmx = True
                    elif rtype == 5:
                        cname, _ = _dns_name(data, at)
            except (struct.error, IndexError, ValueError) as e:
                trouble.append('%s: an answer that does not read: %s' % (server, e))
                break
            if mx:
                return sorted(mx), 'MX records from DNS %s' % server
            if nullmx:
                return [], 'a null MX (DNS %s): the domain takes no mail' % server
            if cname and cname.lower() != name:
                name = cname.rstrip('.').lower()
                continue
            # A null MX (RFC 7505) is "0 ." - the domain takes no mail.
            return [(0, name)], 'no MX record (DNS %s): the domain itself' % server
    raise MailError('no DNS server could say where mail for %s goes%s' % (
        domain, (': ' + '; '.join(trouble)) if trouble else ''))


def dns_mx(domain, timeout=5.0):
    return dns_mx_full(domain, timeout)[0]


def dns_addrs(host, timeout=5.0):
    """The IPv4 and IPv6 addresses of a host (A and AAAA, a CNAME followed),
    asked of the same DNS servers as the MX records (1.0.23) - not of the
    system's resolver, which may be the very one that will not answer."""
    host = str(host).strip().strip('.').lower()
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    out, trouble = [], []
    for qtype in (1, 28):
        for server in dns_servers():
            name, done = host, False
            for _hop in range(6):
                try:
                    data = _dns_ask(server, name, qtype, timeout)
                    rcode, recs = _dns_records(data)
                except (OSError, struct.error, IndexError, ValueError) as e:
                    trouble.append('%s: %s' % (server, e))
                    break
                if rcode == 3:
                    done = True
                    break
                if rcode:
                    trouble.append('%s %s' % (server, DNS_RCODES.get(rcode, 'answered %d' % rcode)))
                    break
                cname, got = None, []
                try:
                    for rtype, _rname, at, size in recs:
                        if rtype == 1 and size == 4:
                            got.append(socket.inet_ntop(socket.AF_INET, data[at:at + 4]))
                        elif rtype == 28 and size == 16:
                            got.append(socket.inet_ntop(socket.AF_INET6, data[at:at + 16]))
                        elif rtype == 5:
                            cname, _ = _dns_name(data, at)
                except (struct.error, IndexError, ValueError, OSError) as e:
                    trouble.append('%s: an answer that does not read: %s' % (server, e))
                    break
                if got:
                    out += [g for g in got if g not in out]
                    done = True
                    break
                if cname and cname.rstrip('.').lower() != name:
                    name = cname.rstrip('.').lower()
                    continue
                done = True                     # no record of this type
                break
            if done:
                break
    if not out:
        raise MailError('no address found for %s%s' % (host, (': ' + '; '.join(trouble))
                                                       if trouble else ''))
    # IPv4 first: a machine with an IPv6 address and no IPv6 route waits out
    # the whole timeout on every server otherwise.
    return sorted(out, key=lambda a: ':' in a)


class _Deadline(object):
    """One conversation's whole time, not each read's (1.0.101): a server
    sending a byte every 19 s of a 20 s timeout held the thread - and a page
    waiting on it - for as long as it liked."""
    deadline = 0.0

    def _left(self):
        if not self.deadline:
            return None
        left = self.deadline - time.time()
        if left <= 0:
            raise smtplib.SMTPServerDisconnected('the mail server took longer than allowed')
        return left

    def _watch(self):
        """A watchman that ends the conversation at its deadline (1.0.103):
        the time of each read alone was set again line by line, so a server
        dripping its reply byte by byte held the thread past any deadline.
        Shut down, the socket ends whatever read waits on it."""
        if not self.deadline or getattr(self, '_watchman', None):
            return
        def expire():
            sock = getattr(self, 'sock', None)
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        t = threading.Timer(max(0.5, self.deadline - time.time()), expire)
        t.daemon = True
        t.start()
        self._watchman = t

    # The conversation into the log, with "Debug log" and "...every code sent"
    # on (1.0.113): what was said each way, never a password or the message.
    _SAFE = ('EHLO', 'HELO', 'MAIL', 'RCPT', 'DATA', 'QUIT', 'STARTTLS', 'RSET', 'NOOP')

    def _print_debug(self, *args):
        words = ' '.join(str(a) for a in args)
        m = re.match(r"^(send|reply):\s*(b?['\"])(.*)", words, re.S)
        if m and m.group(1) == 'send':
            body = m.group(3)
            head = body.split(' ', 1)[0].split('\\r')[0].upper()
            if head.startswith('AUTH'):
                words = 'send: AUTH %s <the credentials, not written>' % (
                    body.split(' ')[1] if ' ' in body else '')
            elif head not in self._SAFE:
                words = 'send: <%d characters - the message or the credentials, not written>' \
                    % len(body)
        log('mail %s: %s' % (getattr(self, '_host', '') or '?', words[:300]), 'debug')

    def close(self):
        t = getattr(self, '_watchman', None)
        if t is not None:
            t.cancel()
        return smtplib.SMTP.close(self)

    def getreply(self):
        self._watch()
        left = self._left()
        if left is not None and self.sock is not None:
            try:
                self.sock.settimeout(min(left, self.timeout or left))
            except OSError:
                pass
        return smtplib.SMTP.getreply(self)

    def send(self, s):
        left = self._left()
        if left is not None and self.sock is not None:
            try:
                self.sock.settimeout(min(left, self.timeout or left))
            except OSError:
                pass
        return smtplib.SMTP.send(self, s)


class _AddrSMTP(_Deadline, smtplib.SMTP):
    """smtplib, connecting to addresses already looked up; the host's name
    is still what the certificate is checked against. It keeps what the
    server answered to the message itself - "250 Ok: queued as 4Xy..." -
    which is what its own log is searched by (1.0.27)."""
    addrs = ()
    last_reply = None

    def data(self, msg):
        got = smtplib.SMTP.data(self, msg)
        self.last_reply = got
        return got

    def _get_socket(self, host, port, timeout):
        last = None
        for a in self.addrs or [host]:
            try:
                return socket.create_connection((a, port), timeout, self.source_address)
            except OSError as e:
                last = e
        raise last or OSError('no address to reach')


class _AddrSMTPS(_Deadline, smtplib.SMTP_SSL):
    addrs = ()
    last_reply = None

    def data(self, msg):
        got = smtplib.SMTP.data(self, msg)
        self.last_reply = got
        return got

    def _get_socket(self, host, port, timeout):
        sock = _AddrSMTP._get_socket(self, host, port, timeout)
        try:
            return self.context.wrap_socket(sock, server_hostname=self._host)
        except BaseException:
            sock.close()                # not left to the collector (1.0.59)
            raise


# ---- one conversation with one server ---------------------------------------------
def _xoauth2(user, token):
    return lambda challenge=None: 'user=%s\x01auth=Bearer %s\x01\x01' % (user, token)


def smtp_talk(store, host, port, security, auth, msg, to, steps, helo='', verify=None,
              timeout=None, direct=False):
    """Send one message through one server, writing down every step."""
    timeout = float(timeout or CONFIG.get('smtp_timeout_s') or 20)
    helo = str(helo or CONFIG.get('mail_helo') or socket.getfqdn() or 'localhost')
    ctx = mail_tls(store, verify)
    if direct and security == 'starttls-if':
        # TLS where offered, going straight to somebody's MX (1.0.59): their
        # certificate is not checked, as no mail server checks another's -
        # a self-signed one there failed every message to the domain, where
        # plain text would have gone. "required" still checks it.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    began = time.time()

    def step(what, ok=True, said=''):
        steps.append({'what': what, 'ok': ok, 'said': str(said or '')[:500]})
        if debugging('codes'):
            log('mail %s:%d: %s %s%s' % (host, port, 'ok' if ok else 'FAILED', what,
                                         (' - %s' % str(said)[:200]) if said else ''), 'debug')

    # Going direct, the recipients' servers are looked up by the same DNS
    # servers that gave their MX records - A, AAAA and CNAME (1.0.23).
    # Only here, and only for mail going straight to the recipients, are
    # the DNS servers of `mail_dns` asked; with none set it is the system's
    # own resolver (/etc/hosts, nsswitch), as for everything else. (1.0.23)
    addrs = ()
    if direct:
        try:
            if own_dns():
                addrs = tuple(dns_addrs(host))
                how = 'DNS ' + ', '.join(own_dns())
            else:
                addrs = tuple(sorted({a[4][0] for a in socket.getaddrinfo(
                    host, port, 0, socket.SOCK_STREAM)}, key=lambda a: ':' in a))
                how = 'the system resolver'
            step('looked up %s' % host, True, ', '.join(addrs) + ' · ' + how)
        except (MailError, OSError) as e:
            step('look up %s' % host, False, e)
            raise MailError('no address found for %s: %s' % (host, e), steps)
    try:
        if security == 'tls':
            conn = _AddrSMTPS(local_hostname=helo, timeout=timeout, context=ctx)
            if debugging('codes'):
                conn.set_debuglevel(1)
            conn.deadline = began + 4 * timeout
            conn.addrs = addrs
            conn._host = host           # the name its certificate is checked against
            code, said = conn.connect(host, port)
            if code != 220:
                conn.close()
                raise smtplib.SMTPConnectError(code, said)
            step('reached %s:%d over TLS' % (host, port), True,
                 '%d ms' % int((time.time() - began) * 1000))
        else:
            conn = _AddrSMTP(local_hostname=helo, timeout=timeout)
            if debugging('codes'):
                conn.set_debuglevel(1)
            conn.deadline = began + 4 * timeout
            conn.addrs = addrs
            # The name STARTTLS checks the certificate against (1.0.96):
            # smtplib keeps the one given when it is made - none here, the
            # address is connected to - and every server that offered
            # STARTTLS failed: "server_hostname cannot be an empty string".
            conn._host = host
            code, said = conn.connect(host, port)
            if code != 220:
                conn.close()
                raise smtplib.SMTPConnectError(code, said)
            step('reached %s:%d' % (host, port), True,
                 '%d ms' % int((time.time() - began) * 1000))
    except ssl.SSLCertVerificationError as e:
        step('reach the server %s:%d over TLS' % (host, port), False,
             'its certificate is not trusted: %s' % e.verify_message)
        raise MailError('the certificate of %s is not trusted - add the authority that '
                        'signed it, or switch the check off' % host, steps)
    except (OSError, smtplib.SMTPException) as e:
        step('reach the server %s:%d' % (host, port), False, e)
        raise MailError('%s:%d could not be reached: %s' % (host, port, e), steps)
    try:
        code, said = conn.ehlo()
        step('greeted it as %s' % helo, 200 <= code < 300, said.decode('utf-8', 'replace')
             .split('\n')[0] if isinstance(said, bytes) else said)
        if security in ('starttls', 'starttls-if'):
            if conn.has_extn('starttls'):
                try:
                    conn.starttls(context=ctx)
                except ssl.SSLCertVerificationError as e:
                    step('started TLS', False, 'its certificate is not trusted: %s'
                         % e.verify_message)
                    raise MailError('the certificate of %s is not trusted - add the authority '
                                    'that signed it, or switch the check off' % host, steps)
                conn.ehlo()
                cert = conn.sock.getpeercert() if hasattr(conn.sock, 'getpeercert') else None
                who = ''
                if cert:
                    who = ', '.join('%s=%s' % kv for part in cert.get('subject', ())
                                    for kv in part if kv[0] == 'commonName')
                step('started TLS', True, (conn.sock.version() if hasattr(conn.sock, 'version')
                                           else '') + ((' · ' + who) if who else ''))
            elif security == 'starttls':
                step('start TLS', False, 'the server does not offer STARTTLS')
                raise MailError('%s does not offer STARTTLS - choose TLS from the start, or '
                                'none' % host, steps)
            else:
                step('stayed in plain text', True, 'the server does not offer STARTTLS')
                if auth and auth != 'none' and not direct:
                    # Not the password in plain text (1.0.94): a STARTTLS taken
                    # out on the way would have had it read off the wire.
                    step('sign in', False, 'not without TLS: the password would go in plain text')
                    raise MailError('%s offered no STARTTLS, and the password is not sent in '
                                    'plain text - choose STARTTLS (required) or TLS from the '
                                    'start, or Security none if a plain connection is meant'
                                    % host, steps)
        if auth and auth != 'none' and not direct:
            user = str(CONFIG.get('smtp_user') or '')
            pw = unseal_secret(CONFIG.get('smtp_password') or '') or ''
            offered = (conn.esmtp_features.get('auth') or '').upper().split()
            try:
                if auth == 'auto':
                    conn.login(user, pw)
                elif auth == 'xoauth2':
                    conn.auth('XOAUTH2', _xoauth2(user, pw), initial_response_ok=True)
                else:
                    conn.user, conn.password = user, pw
                    mech = {'plain': 'PLAIN', 'login': 'LOGIN', 'cram-md5': 'CRAM-MD5'}[auth]
                    fn = {'PLAIN': conn.auth_plain, 'LOGIN': conn.auth_login,
                          'CRAM-MD5': conn.auth_cram_md5}[mech]
                    conn.auth(mech, fn, initial_response_ok=(mech != 'CRAM-MD5'))
                step('signed in as %s (%s)' % (user, auth.upper()), True,
                     'it offers: %s' % (' '.join(offered) or 'nothing'))
            except smtplib.SMTPAuthenticationError as e:
                step('sign in as %s (%s)' % (user, auth.upper()), False,
                     '%s %s' % (e.smtp_code, (e.smtp_error or b'').decode('utf-8', 'replace')))
                raise MailError('the mail server did not take the account or the password',
                                steps)
            except smtplib.SMTPException as e:
                step('sign in as %s (%s)' % (user, auth.upper()), False,
                     '%s · it offers: %s' % (e, ' '.join(offered) or 'nothing'))
                raise MailError('signing in failed: %s' % e, steps)
        if msg is not None:
            refused = conn.send_message(msg, to_addrs=list(to))
            if refused:
                step('handed the message over', False, '; '.join(
                    '%s: %s' % (k, v) for k, v in refused.items()))
                err = MailError('the server refused %s' % ', '.join(refused), steps,
                                permanent=all(int((v or (0,))[0] or 0) >= 500
                                              for v in refused.values()))
                # The others took it (1.0.206): only these are tried again - every
                # try sent it once more to everybody who had it already.
                err.left = list(refused)
                raise err
            reply = getattr(conn, 'last_reply', None)
            said = ''
            if reply:
                said = ' · %s %s' % (reply[0], (reply[1] or b'').decode('utf-8', 'replace')
                                     if isinstance(reply[1], bytes) else reply[1])
            step('handed the message over', True, 'for %s%s' % (', '.join(to), said))
    except smtplib.SMTPRecipientsRefused as e:
        step('handed the message over', False, '; '.join(
            '%s: %s %s' % (k, v[0], v[1].decode('utf-8', 'replace') if isinstance(v[1], bytes)
                           else v[1]) for k, v in e.recipients.items()))
        raise MailError('the server would not take mail for %s' % ', '.join(e.recipients), steps,
                        permanent=all(int((v or (0,))[0] or 0) >= 500
                                      for v in e.recipients.values()))
    except smtplib.SMTPSenderRefused as e:
        step('handed the message over', False, '%s %s' % (e.smtp_code, (
            e.smtp_error or b'').decode('utf-8', 'replace')))
        raise MailError('the server would not take mail from %s' % e.sender, steps,
                        permanent=int(e.smtp_code or 0) >= 500)
    except (smtplib.SMTPException, OSError) as e:
        if not isinstance(e, MailError):
            step('talking to it', False, e)
            raise MailError('the conversation with %s broke off: %s' % (host, e), steps,
                            permanent=int(getattr(e, 'smtp_code', 0) or 0) >= 500)
        raise
    finally:
        try:
            conn.quit()
        except Exception:
            pass
        try:
            conn.close()        # the watchman goes too (1.0.103)
        except Exception:
            pass
    return steps


def mail_send(store, msg, to, mode=None):
    """Send `msg` to `to` ([addresses]) the way the settings say. Returns the
    steps; raises MailError with them where it failed."""
    mode = mode or CONFIG.get('mail_mode') or 'off'
    steps = []
    if mode == 'off':
        raise MailError('sending mail is switched off - Settings → Mail', steps)
    if mode == 'smtp':
        host = str(CONFIG.get('smtp_host') or '').strip()
        if not host:
            raise MailError('no mail server is set - Settings → Mail', steps)
        security = CONFIG.get('smtp_security') or 'starttls'
        port = int(CONFIG.get('smtp_port') or 0) or {'tls': 465, 'none': 25}.get(security, 587)
        return smtp_talk(store, host, port, security, CONFIG.get('smtp_auth') or 'auto', msg,
                         to, steps)
    # Straight to each domain's own server: one conversation per domain.
    by_domain = collections.OrderedDict()
    for one in to:
        by_domain.setdefault(one.rsplit('@', 1)[-1].lower(), []).append(one)
    port = int(CONFIG.get('mail_direct_port') or 25)
    failed = []                         # (recipients still to do, the error) per domain
    for domain, who in by_domain.items():
        try:
            try:
                mxs, how = dns_mx_full(domain)
                mxs = [m for m in mxs if m[1] not in ('', '.')]
                if not mxs:
                    raise MailError('%s takes no mail (its MX record is a null MX)' % domain,
                                    permanent=True)
            except MailError as e:
                steps.append({'what': 'look up the mail servers of %s' % domain, 'ok': False,
                              'said': str(e)})
                raise MailError(str(e), steps, permanent=e.permanent)
            steps.append({'what': 'looked up the mail servers of %s' % domain, 'ok': True,
                          'said': ', '.join('%s (%d)' % (h, p) for p, h in mxs) + ' · ' + how})
            last = None
            # One deadline over every MX of the domain (1.0.59): four servers of
            # two addresses each at 20 s outlasted the page asking.
            deadline = time.time() + MAIL_DIRECT_DEADLINE_S
            for _pref, host in mxs[:4]:
                left = deadline - time.time()
                if left < 3:
                    last = last or MailError('no time left to try %s' % host, steps)
                    break
                try:
                    smtp_talk(store, host, port,
                              'starttls' if CONFIG.get('mail_direct_tls') == 'required'
                              else 'starttls-if', 'none', msg, who, steps, direct=True,
                              timeout=min(float(CONFIG.get('smtp_timeout_s') or 20), left / 2))
                    last = None
                    break
                except MailError as e:
                    last = e
                    if e.left is not None and len(e.left) < len(who):
                        break               # this server took the others: not the next one
            if last:
                err = MailError('no mail server of %s took it: %s' % (domain, last), steps,
                                permanent=getattr(last, 'permanent', False))
                err.left = list(last.left) if last.left is not None else list(who)
                raise err
        except MailError as e:
            # Each domain on its own (1.0.206): one that would not take it no longer
            # stops the next ones, nor sends it again to the ones that took it.
            failed.append((e.left if e.left is not None else list(who), e))
    if failed:
        left = [a for one, _e in failed for a in one]
        err = MailError('; '.join(str(e) for _l, e in failed), steps,
                        permanent=all(e.permanent for _l, e in failed))
        err.left = left
        raise err
    return steps


# ---- the QR code as a picture every mail program shows ----------------------------
def qr_png(text, scale=8, border=4):
    """A PNG of the QR code: mail programs do not show SVG."""
    q = QrCode(text, 'M')
    size = q.size + border * 2
    width = size * scale
    rows = []
    for y in range(-border, q.size + border):
        line = bytearray()
        for x in range(-border, q.size + border):
            dark = 0 <= x < q.size and 0 <= y < q.size and q.modules[y][x]
            line += (b'\x00' if dark else b'\xff') * scale
        rows.extend([b'\x00' + bytes(line)] * scale)
    raw = b''.join(rows)

    def chunk(kind, data):
        body = kind + data
        return struct.pack('>I', len(data)) + body + struct.pack('>I', zlib.crc32(body)
                                                                & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, width, 8, 0,
                                                            0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


# ---- the token's mail, in Czech or in English --------------------------------------
MAIL_WORDS = {
    'cs': {
        'subject': 'Váš token pro přihlášení do VPN – {site}',
        'title': 'VPN · Dvoufázové přihlášení',
        'hello': 'Dobrý den, {name},',
        'hello_anon': 'Dobrý den,',
        'lede': 'pro účet <b>{account}</b> byl vytvořen token pro dvoufázové přihlášení. '
                'Kód z telefonu budete zadávat při přihlášení do VPN.',
        'step1': 'Nainstalujte si do telefonu aplikaci pro jednorázové kódy – například '
                 '<b>Microsoft Authenticator</b>, <b>Google Authenticator</b> nebo '
                 '<b>FreeOTP</b>.',
        'step2': 'V aplikaci zvolte přidání účtu a naskenujte tento QR kód:',
        'step3': 'Nejde-li kód naskenovat, zadejte do aplikace klíč ručně:',
        'key': 'Klíč',
        'facts': 'Typ: časový (TOTP) · {digits} číslic · platnost {period} s',
        'pending': 'Token začne platit, až ho potvrdíte prvním kódem z aplikace na stránce '
                   'registrace.',
        'codes_h': 'Záložní kódy',
        'codes_p': 'Každý platí jednou, místo kódu z telefonu – pro případ, že telefon ztratíte '
                   'nebo nebude po ruce. Uschovejte je jinde než v telefonu.',
        'warn': 'Tento e-mail je stejně cenný jako heslo: kdo má QR kód nebo klíč, může '
                'vytvářet vaše kódy. Po naskenování ho smažte a nikomu ho nepřeposílejte.',
        'foot': 'Vytvořil(a) {by} na {site}. Pokud jste token nečekali, obraťte se na správce.',
    },
    'en': {
        'subject': 'Your sign-in token for the VPN – {site}',
        'title': 'VPN · Two-step sign-in',
        'hello': 'Hello {name},',
        'hello_anon': 'Hello,',
        'lede': 'a token for two-step sign-in has been made for the account <b>{account}</b>. '
                'You will type the code from your phone when you sign in to the VPN.',
        'step1': 'Install an app for one-time codes on your phone – for example '
                 '<b>Microsoft Authenticator</b>, <b>Google Authenticator</b> or <b>FreeOTP</b>.',
        'step2': 'In the app, choose to add an account and scan this QR code:',
        'step3': 'If the code cannot be scanned, type the key into the app instead:',
        'key': 'Key',
        'facts': 'Type: time-based (TOTP) · {digits} digits · every {period} s',
        'pending': 'The token starts working once you confirm it with the first code from the '
                   'app on the enrolment pages.',
        'codes_h': 'Recovery codes',
        'codes_p': 'Each works once, in place of a code from the phone – for when the phone is '
                   'lost or not at hand. Keep them somewhere other than the phone.',
        'warn': 'This mail is worth as much as a password: whoever has the QR code or the key '
                'can make your codes. Delete it once the code is scanned, and do not forward it.',
        'foot': 'Made by {by} on {site}. If you did not expect this token, contact your '
                'administrator.',
    },
}


# The numbers of the steps as pictures for Outlook on Windows (1.0.31): it
# draws mail with Word, which has no round corners, and its own VML circles
# put the digit at the bottom edge. 56 px, shown at 28 for sharp screens;
# Inter Bold, white on #2563eb, on white. Every mail program gets the same
# pictures - one shown only to Outlook would be an attachment elsewhere.
MAIL_BADGES = {
    1: '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',
    2: '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',
    3: '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',
    4: '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',
}


def _h(text):
    return html.escape(str(text or ''), quote=True)


def token_mail(to, name, picture, codes=None, lang='cs', display='', by='', pending=False,
               portal_url='', w=None):
    """The mail a token's owner gets: the QR code inline, the key, and the
    recovery codes where wanted - laid out in tables with the styles written
    on each element, which is what every mail program shows the same. Its
    words as Settings → Message texts has them (1.0.103), or `w`."""
    lang = lang if lang in MAIL_WORDS else 'cs'
    if w is None:
        w = texts_for('token', lang)
    site = str(CONFIG.get('site_name') or socket.gethostname())
    issuer = picture.get('issuer') or site
    fmt = {'site': _h(site), 'name': _h(display or name), 'account': _h(name), 'by': _h(by),
           'digits': picture.get('digits'), 'period': picture.get('period')}
    cid = make_msgid(domain='acme.local')[1:-1]
    hello = (w['hello'] if display else w['hello_anon']).format(**fmt)
    key = picture.get('secret_spaced') or picture.get('secret') or ''
    font = ("font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;")
    # Tables and attributes, not floats and inline blocks (1.0.29): Outlook
    # draws mail with Word, which ignores width, height and border-radius on
    # anything but a table cell - the numbered badges came out as a sliver
    # and the recovery codes ran together into one long number.
    def nobreak_link(text):
        # Outlook and others make every name@domain a link; a zero-width
        # joiner after the @ keeps it plain text, the way it reads.
        return ('<span style="white-space:nowrap">%s</span>'
                % _h(text).replace('@', '@&#8205;'))
    fmt['account'] = nobreak_link(name)
    txt = 'font-size:15px;line-height:1.55;color:#111827;'

    badge_cid = {n: make_msgid(domain='acme.local')[1:-1] for n in MAIL_BADGES}
    # The values as text, for a line that is escaped as a whole (a heading).
    plain_fmt_h = {'site': site, 'name': display or name, 'account': name, 'by': by,
                   'digits': picture.get('digits'), 'period': picture.get('period')}

    def step(n, words, extra=''):
        return ('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                'border="0" style="margin:0 0 %s"><tr>'
                '<td width="40" valign="top" style="width:40px;padding:1px 0 0">'
                # A picture of the number in its circle (1.0.31): the one
                # thing Outlook on Windows draws the same as everybody else.
                '<img src="cid:%s" width="28" height="28" alt="%d" '
                'style="display:block;width:28px;height:28px;border:0"></td>'
                '<td valign="top" style="padding-top:3px;%s%s">%s%s</td></tr></table>'
                % ('16px' if not extra else '8px', badge_cid[n], n, txt, font, words, extra))

    rows = []
    if hello.strip():
        rows.append('<p style="margin:0 0 6px;font-size:16px;color:#111827">%s</p>' % hello)
    if w['lede'].strip():
        rows.append('<p style="margin:0 0 24px;font-size:15px;line-height:1.55;color:#374151">'
                    '%s</p>' % w['lede'].format(**fmt))
    rows.append(step(1, w['step1'].format(**fmt)))
    rows.append(step(2, w['step2'].format(**fmt)))
    rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                'border="0" style="margin:4px 0 20px"><tr><td align="center">'
                '<table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr>'
                '<td align="center" bgcolor="#ffffff" style="padding:10px;border:1px solid #e5e7eb;'
                'border-radius:12px;background:#ffffff"><img src="cid:%s" width="220" height="220" '
                'alt="QR" style="display:block;width:220px;height:220px;border:0"></td></tr></table>'
                '<div style="margin-top:8px;font-size:13px;color:#6b7280;%s">%s · %s</div>'
                '</td></tr></table>'
                % (cid, font, _h(issuer), nobreak_link(picture.get('label') or name)))
    rows.append(step(3, w['step3'].format(**fmt)))
    rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                'border="0" style="margin:0 0 6px"><tr><td style="padding-left:40px">'
                '<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                'border="0"><tr><td align="center" bgcolor="#f3f4f6" style="padding:12px 10px;'
                'background:#f3f4f6;border-radius:8px;font-family:Consolas,Menlo,\'Courier New\','
                'monospace;font-size:15px;font-weight:700;letter-spacing:1px;color:#111827;white-space:nowrap">%s'
                '</td></tr></table>'
                '<div style="margin:6px 0 0;font-size:12.5px;color:#6b7280;text-align:center;%s">'
                '%s</div></td></tr></table>' % (_h(key), font, w['facts'].format(**fmt)))
    rows.append('<div style="height:18px;line-height:18px;font-size:1px">&nbsp;</div>')
    if pending and w['pending'].strip():
        rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                    'border="0" style="margin:0 0 20px"><tr><td bgcolor="#eff6ff" '
                    'style="padding:12px 16px;background:#eff6ff;border-left:4px solid #2563eb;'
                    'font-size:14px;line-height:1.5;color:#1e3a8a;%s">%s%s</td></tr></table>'
                    % (font, w['pending'].format(**fmt), (' <a href="%s" style="color:#1d4ed8">%s</a>'
                                            % (_h(portal_url), _h(portal_url)))
                       if portal_url else ''))
    if codes:
        codes = [str(c) for c in codes]
        per = 5 if len(codes) % 5 == 0 or len(codes) > 6 else (3 if len(codes) % 3 == 0 else 4)
        per = min(per, len(codes))
        lines = []
        for at in range(0, len(codes), per):
            chunk = codes[at:at + per]
            cells = []
            for c in chunk:
                cells.append('<td align="center" width="%d%%" style="padding:4px">'
                             '<table role="presentation" width="100%%" cellspacing="0" '
                             'cellpadding="0" border="0"><tr><td align="center" bgcolor="#f9fafb" '
                             'style="padding:9px 2px;background:#f9fafb;border:1px solid #d1d5db;'
                             'border-radius:6px;font-family:Consolas,Menlo,\'Courier New\','
                             'monospace;font-size:14px;font-weight:700;letter-spacing:.5px;'
                             'color:#111827;white-space:nowrap">%s</td></tr></table></td>' % (100 // per, _h(c)))
            cells += ['<td width="%d%%" style="padding:4px">&nbsp;</td>' % (100 // per)] * (
                per - len(chunk))
            lines.append('<tr>%s</tr>' % ''.join(cells))
        rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                    'border="0" style="margin:0 0 22px"><tr><td bgcolor="#ffffff" '
                    'style="padding:16px 16px 12px;border:1px solid #e5e7eb;border-radius:10px">'
                    '<div style="font-size:15px;font-weight:700;color:#111827;%s">%s</div>'
                    '<div style="margin:4px 0 10px;font-size:13.5px;line-height:1.5;color:#4b5563;'
                    '%s">%s</div>'
                    '<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                    'border="0">%s</table></td></tr></table>'
                    % (font, _h(w['codes_h'].format(**plain_fmt_h)), font, w['codes_p'].format(**fmt),
                       ''.join(lines)))
    if w['warn'].strip():
        rows.append('<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
                    'border="0"><tr><td bgcolor="#fff7ed" style="padding:12px 16px;'
                    'background:#fff7ed;border-left:4px solid #f59e0b;font-size:13px;'
                    'line-height:1.5;color:#7c2d12;%s">%s</td></tr></table>'
                    % (font, w['warn'].format(**fmt)))
    body = ''.join(rows)
    page = ('<!doctype html><html lang="%s" xmlns:v="urn:schemas-microsoft-com:vml" '
            'xmlns:o="urn:schemas-microsoft-com:office:office"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>'
            '<!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch>'
            '</o:OfficeDocumentSettings></xml><![endif]--></head>'
            '<body style="margin:0;padding:0;background:#f3f4f6;%s">'
            '<table role="presentation" width="100%%" cellspacing="0" cellpadding="0" '
            'border="0" bgcolor="#f3f4f6" style="background:#f3f4f6"><tr><td align="center" '
            'style="padding:28px 12px">'
            '<table role="presentation" width="560" cellspacing="0" cellpadding="0" border="0" '
            'bgcolor="#ffffff" style="max-width:560px;width:100%%;background:#ffffff;border-radius:14px;'
            'overflow:hidden;border:1px solid #e5e7eb">'
            '<tr><td bgcolor="#1e3a8a" style="background:#1e3a8a;padding:20px 28px;'
            'color:#ffffff;%s">'
            '<p style="margin:0;font-size:12px;letter-spacing:1.5px;text-transform:uppercase;'
            'color:#c7d2fe">%s</p><p style="margin:4px 0 0;font-size:20px;font-weight:700;'
            'color:#ffffff">%s</p></td></tr>'
            '<tr><td style="padding:26px 28px;%s">%s</td></tr>'
            '<tr><td style="padding:14px 28px 22px;font-size:12px;color:#9ca3af;%s;'
            'border-top:1px solid #f3f4f6">%s</td></tr></table></td></tr></table></body></html>'
            % (lang, _h(w['subject'].format(site=site)), font, font, _h(issuer),
               _h(w['title'].format(site=site)), font, body, font, w['foot'].format(**fmt)))
    # The text version (1.0.103): the words' tags taken out and their
    # entities read first, then the values put in as they are - the name of
    # the account plain, not with the HTML that keeps it from becoming a link.
    raw = {'site': site, 'name': display or name, 'account': name, 'by': by,
           'digits': picture.get('digits'), 'period': picture.get('period')}

    def plain(k, values=None):
        if k in ('subject', 'title', 'codes_h'):
            t = str(w[k])               # a plain line already, not HTML
        else:
            t = html.unescape(re.sub('<[^>]+>', '', re.sub(r'<br\s*/?>', '\n', str(w[k]))))
        return t.format(**(raw if values is None else values))
    text = []
    first = plain('hello') if display else plain('hello_anon')
    for part in (first, plain('lede')):
        if part.strip():
            text += [part, '']
    text += ['1. ' + plain('step1'), '2. ' + plain('step2') + ' (QR)', '3. ' + plain('step3'),
             '', '   ' + key, '', plain('facts'), '']
    if pending and w['pending'].strip():
        text += [plain('pending') + (' ' + portal_url if portal_url else ''), '']
    if codes:
        text += [plain('codes_h') + ':', '   ' + '   '.join(codes), '']
        if w['codes_p'].strip():
            text += [plain('codes_p'), '']
    if w['warn'].strip():
        text += [plain('warn'), '']
    text += ['-- ', plain('foot')]
    msg = EmailMessage()
    msg['Subject'] = w['subject'].format(site=site)
    sender = mail_sender()
    if not sender:
        raise MailError('no sender address is set - Settings → Mail → From (address)')
    msg['From'] = formataddr((str(CONFIG.get('mail_from_name') or site), sender))
    msg['To'] = to
    if CONFIG.get('mail_reply_to'):
        msg['Reply-To'] = str(CONFIG.get('mail_reply_to'))
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=sender.rsplit('@', 1)[-1] or None)
    msg['Auto-Submitted'] = 'auto-generated'
    msg.set_content('\n'.join(text))
    msg.add_alternative(page, subtype='html')
    msg.get_payload()[1].add_related(qr_png(picture['uri']), 'image', 'png', cid='<%s>' % cid,
                                     filename='qr.png', disposition='inline')
    for n in (1, 2, 3):
        msg.get_payload()[1].add_related(base64.b64decode(MAIL_BADGES[n]), 'image', 'png',
                                         cid='<%s>' % badge_cid[n], filename='%d.png' % n,
                                         disposition='inline')
    return msg


def test_mail(to, lang='cs'):
    site = str(CONFIG.get('site_name') or socket.gethostname())
    msg = EmailMessage()
    msg['Subject'] = ('Zkušební zpráva z %s' if lang == 'cs' else 'A test message from %s') % site
    sender = mail_sender()
    if not sender:
        raise MailError('no sender address is set - Settings → Mail → From (address)')
    msg['From'] = formataddr((str(CONFIG.get('mail_from_name') or site), sender))
    msg['To'] = to
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=sender.rsplit('@', 1)[-1] or None)
    msg.set_content(('Tato zpráva ověřuje, že %s umí odesílat poštu. Není třeba nic dělat.'
                     if lang == 'cs' else 'This message checks that %s can send mail. '
                     'Nothing needs doing.') % site)
    return msg


