# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Sending mail (1.0.20)
# ---------------------------------------------------------------------------
# The codes of the administrators' second step, the alerts, the report and
# whatever a module mails (a certificate running out, say). Two ways out: through a mail server (SMTP relay, with STARTTLS,
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


def _h(text):
    return html.escape(str(text or ''), quote=True)


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


