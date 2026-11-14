# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- signing in with a certificate: a smart card, a YubiKey (1.0.100, as otp 1.0.275) ----------
# A certificate of the domain's authority (AD CS) - on a smart card, a YubiKey (PIV) or in the
# computer - signs its person in without a password. Two parts, each with its own switches: the
# administration (admin_certlogin...) and the certificate portal (portal_certlogin...); one port
# of nginx's own for both (certlogin_port, 8443) - the nonce and the page say which part - and
# the authorities put in once, for both, on the pages (or acme --cert-login-ca FILE).
#
# The rules, kept whatever is set:
#   - A port of its own: nginx asks for a certificate there only (ssl_verify_client
#     optional_no_ca, the authorities' names sent) - never on 443, so nobody who opens the pages
#     is ever asked for one - and serves nothing there but the sign-in (deploy/acme_web.py).
#   - acme checks the certificate, not nginx: the chain to the authorities put in (nothing else:
#     openssl is told to use no store of the system's), its dates, a key usage for signing in
#     (Client Authentication or Smart Card Logon), revocation by the CRL at its CRL Distribution
#     Point (http, fetched only for a certificate whose chain is good, kept until its next
#     update, its signature checked by openssl; no CRL to be had, no sign-in), and the UPN in its
#     Subject Alternative Name.
#   - The person: the UPN looked up in that part's directory, the account then found by its
#     sAMAccountName exactly as a password or a Kerberos ticket finds it, and the entry checked to
#     be the same DN - one person, one account. The SID of KB5014754 (the certificate's
#     szOID_NTDS_CA_SECURITY_EXT) compared with the account's objectSid: compat (the default) when
#     there, strong always, upn never. Who may sign in decides as for a password; the second step
#     (the administration's) or the one-time code (the portal's) is asked after it every time.
#   - Every refusal: "Certificate sign-in refused: " and a kind (certificate not accepted,
#     revoked, run out, not allowed, not available just now) to whoever sent it - the reason only
#     in Events (and to an administrator trying a certificate).
#   - The authorities kept in the database (signed - db_guard - where access-granting rows are
#     signed), written out by each node itself (0600, the service's own user): a node put back
#     from a backup or joined later too; nginx's copy written by the root helper.
#   - "No password at all - only Windows or a certificate" (admin_password_off, the portal's):
#     switched on only from a sign-in made with one of them, in effect while one of them can sign
#     anybody in (392's krb_password_off, shared); sessions record how they were made
#     ('certificate') and end when that way is switched off or its authorities taken away.
#
# The Python standard library and the openssl command only.

CL_META = 'certlogin:cas'
CL_NODE_META = 'certlogin:node:'
CL_TRIED_META = 'certlogin:tried:'
CL_SERVED_META = 'certlogin:served'
CL_PARTS = ('admin', 'portal')
CL_CERT_MOST = 16384            # a person's certificate in PEM: a few kB
CL_CAS_MOST = 20                # authorities put in
CL_CA_FILE_MOST = 1 << 20       # a .p7b or a PEM of authorities put in
CL_CRL_MOST = 8 << 20
CL_OID_SAN = '2.5.29.17'
CL_OID_EKU = '2.5.29.37'
CL_OID_CDP = '2.5.29.31'
CL_OID_BC = '2.5.29.19'
CL_OID_KU = '2.5.29.15'
CL_OID_UPN = '1.3.6.1.4.1.311.20.2.3'
CL_OID_SID_EXT = '1.3.6.1.4.1.311.25.2'
CL_OID_SID = '1.3.6.1.4.1.311.25.2.1'
CL_OID_FRESHEST = '2.5.29.46'       # Freshest CRL: where the delta CRL is
CL_OID_DELTA = '2.5.29.27'          # Delta CRL Indicator (of a CRL)
CL_OID_NC = '2.5.29.30'             # nameConstraints (of an authority)
# The SID in the Subject Alternative Name (an otherName of CL_OID_SID, or the URL form of 2025)
# is written by whoever asks for the certificate on a template where the requester supplies the
# subject - never taken as the account's SID: only the extension CL_OID_SID_EXT, which the
# authority writes itself, is (security review F1).
CL_SID_URL = 'tag:microsoft.com,2022-09-14:sid:'
# A CRL fetched is used for this long at most (or until its next update, if sooner), then fetched
# again; while its CDP does not answer, the last good one until its next update (fail closed
# after it). The delta CRL (Freshest CRL) the same way. Review F3.
CL_CRL_FRESH_S = 600
CL_CRL_FETCH_S = 15                 # one CRL: the whole fetch, connecting and reading
# Names of clouds' metadata services, and their addresses that are not link-local (F5).
CL_CDP_NAMES_NO = ('metadata', 'metadata.google.internal', 'metadata.goog', 'instance-data',
                   'instance-data.ec2.internal', 'metadata.azure.com', 'metadata.oraclecloud.com')
CL_CDP_IPS_NO = ('169.254.169.254', '169.254.170.2', 'fd00:ec2::254', '100.100.100.200')
# The nonce of the page, once in the whole cluster (as Kerberos' authenticator): F7.
CL_ONCE = 'certonce'
CL_ONCE_S = 330
CL_EKU_SIGN_IN = {'1.3.6.1.5.5.7.3.2': 'Client Authentication',
                  '1.3.6.1.4.1.311.20.2.2': 'Smart Card Logon'}
# Extensions a person's certificate may have marked critical and still be read here.
CL_CRIT_KNOWN = (CL_OID_SAN, CL_OID_EKU, CL_OID_BC, CL_OID_KU, CL_OID_CDP, '2.5.29.32',
                 CL_OID_FRESHEST)
CL_REFUSED = 'Certificate sign-in refused'
CL_KINDS = {'certificate': 'certificate not accepted', 'revoked': 'revoked', 'expired': 'run out',
            'allowed': 'not allowed', 'unavailable': 'not available just now'}
CL_MATCH_WORDS = {'compat': 'the UPN; the SID in it must be the account\'s when it is there',
                  'strong': 'the UPN and the SID in it - a certificate without the SID is refused',
                  'upn': 'the UPN alone - the SID in it is not looked at'}
CL_MATCH_RANK = {'upn': 0, 'compat': 1, 'strong': 2}
# On the card (and in the docs) while a part is not strong: who may ask the authority for a
# certificate naming any UPN may sign in as that person (F2).
CL_MATCH_WARN = ('Not strong: a certificate without the SID of KB5014754 is taken by its UPN '
                 'alone - anybody who may ask an authority put in here for a certificate with a '
                 'name of their choosing (a template where the requester supplies the subject) '
                 'signs in as whoever they name, a full administrator too. Windows itself '
                 'requires the SID since September 2025.')
CL_CRL_CACHE = {}
CL_CRL_LOCK = threading.Lock()
CL_STATE = {'have': None, 'sha': None, 'checked': 0.0, 'said_at': 0.0, 'said': None,
            'error': '', 'written': False, 'writer': False}


class CertRefused(KrbRefused):
    """A sign-in with a certificate refused: `why` for Events (and an administrator trying a
    certificate), `said` for whoever sent it - "Certificate sign-in refused: " and the kind
    only."""

    def __init__(self, why, kind='certificate', status=None, more=''):
        Exception.__init__(self, why)
        self.kind = kind if kind in CL_KINDS else 'certificate'
        self.status = status or (503 if self.kind == 'unavailable' else 401)
        self.why = why + ('' if not more else ' (%s)' % more)
        self.said = cl_refused_words(self.kind)


def cl_refused_words(kind):
    return '%s: %s' % (CL_REFUSED, CL_KINDS.get(kind, CL_KINDS['certificate']))


# ---- a certificate read ----------------------------------------------------------------------
def _cl_openssl(args, data=None, what='openssl'):
    try:
        r = subprocess.run(['openssl'] + list(args), input=data, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise ValueError('%s: openssl did not run (%s)' % (what, e))
    if r.returncode != 0:
        raise ValueError('%s: %s' % (what, (r.stderr or b'').decode('utf-8', 'replace').strip()[-300:]))
    return r.stdout


def _cl_der(b, i=0):
    if i + 2 > len(b):
        raise ValueError('cut short')
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7f
        if not 0 < k <= 4 or i + k > len(b):
            raise ValueError('a length that cannot be')
        n = int.from_bytes(b[i:i + k], 'big')
        i += k
    if i + n > len(b):
        raise ValueError('cut short')
    return tag, b[i:i + n], i + n


def _cl_der_all(b):
    out, i = [], 0
    while i < len(b):
        t, v, i = _cl_der(b, i)
        out.append((t, v))
    return out


def _cl_oid(v):
    if not v:
        return ''
    parts = [v[0] // 40, v[0] % 40] if v[0] < 80 else [2, v[0] - 80]
    n = 0
    for c in v[1:]:
        n = (n << 7) | (c & 0x7f)
        if not c & 0x80:
            parts.append(n)
            n = 0
    return '.'.join(str(x) for x in parts)


def _cl_der_find(b, want, depth=0):
    """Every value of tag `want` anywhere in b (constructed tags walked into)."""
    out = []
    if depth > 12:
        return out
    try:
        items = _cl_der_all(b)
    except ValueError:
        return out
    for t, v in items:
        if t == want:
            out.append(v)
        if t & 0x20:
            out += _cl_der_find(v, want, depth + 1)
    return out


CL_PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----')


def cl_pem_one(pem):
    """The one certificate of a PEM, its base64 tidied - CertRefused for anything else."""
    pem = str(pem or '').strip()
    found = CL_PEM_RE.findall(pem)
    if len(found) != 1:
        raise CertRefused('that is not one certificate (PEM)' if not found else
                          'more than one certificate was sent')
    body = re.sub(r'\s+', '', found[0])
    try:
        der = base64.b64decode(body, validate=True)
    except (ValueError, binascii.Error):
        raise CertRefused('the certificate is not whole')
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % '\n'.join(lines), der


def cl_facts(pem):
    """What the checks need of a certificate: its extensions read from DER, its names, serial,
    dates and fingerprint from openssl. CertRefused when it cannot be read."""
    pem, der = cl_pem_one(pem)
    try:
        _t, cert, _ = _cl_der(der)
        _t, tbs, _ = _cl_der(cert)
        items = _cl_der_all(tbs)
    except ValueError as e:
        raise CertRefused('the certificate cannot be read: %s' % e)
    exts = {}
    for t, v in items:
        if t != 0xa3:
            continue
        try:
            for _t, one in _cl_der_all(_cl_der(v)[1]):
                parts = _cl_der_all(one)
                oid = _cl_oid(parts[0][1])
                crit = len(parts) == 3 and parts[1][0] == 0x01 and parts[1][1] != b'\x00'
                if oid in exts:
                    raise CertRefused('the certificate has the extension %s twice' % oid)
                exts[oid] = (crit, parts[-1][1])
        except (ValueError, IndexError):
            raise CertRefused('the extensions of the certificate cannot be read')
    upns, mails, sid, san_sids = [], [], '', []
    if CL_OID_SAN in exts:
        try:
            for gt, gv in _cl_der_all(_cl_der(exts[CL_OID_SAN][1])[1]):
                if gt == 0xa0:                      # otherName
                    p = _cl_der_all(gv)
                    if p and _cl_oid(p[0][1]) == CL_OID_UPN and len(p) > 1:
                        inner = _cl_der_all(p[1][1])
                        if inner:
                            upns.append(inner[0][1].decode('utf-8', 'replace'))
                    elif p and _cl_oid(p[0][1]) == CL_OID_SID and len(p) > 1:
                        # Written by the requester (F1): never the account's SID - only
                        # compared, below and with the account.
                        inner = _cl_der_all(p[1][1])
                        san_sids.append(inner[0][1].decode('ascii', 'replace') if inner else '?')
                elif gt == 0x81:                    # rfc822Name
                    mails.append(gv.decode('ascii', 'replace'))
                elif gt == 0x86:                    # URI - the SID's URL form of 2025
                    u = gv.decode('ascii', 'replace')
                    if u.lower().startswith(CL_SID_URL):
                        san_sids.append(u[len(CL_SID_URL):])
        except (ValueError, IndexError):
            raise CertRefused('the Subject Alternative Name of the certificate cannot be read')
    if CL_OID_SID_EXT in exts:
        try:
            for _gt, gv in _cl_der_all(_cl_der(exts[CL_OID_SID_EXT][1])[1]):
                p = _cl_der_all(gv)
                if p and _cl_oid(p[0][1]) == CL_OID_SID and len(p) > 1:
                    inner = _cl_der_all(p[1][1])
                    if inner:
                        sid = inner[0][1].decode('ascii', 'replace')
        except (ValueError, IndexError):
            raise CertRefused('the SID extension of the certificate cannot be read')
    eku = []
    if CL_OID_EKU in exts:
        try:
            eku = [_cl_oid(v) for t, v in _cl_der_all(_cl_der(exts[CL_OID_EKU][1])[1]) if t == 0x06]
        except ValueError:
            raise CertRefused('the key usages of the certificate cannot be read')
    is_ca = False
    if CL_OID_BC in exts:
        try:
            p = _cl_der_all(_cl_der(exts[CL_OID_BC][1])[1])
            is_ca = bool(p and p[0][0] == 0x01 and p[0][1] != b'\x00')
        except ValueError:
            is_ca = False
    cdp = [u.decode('ascii', 'replace') for u in _cl_der_find(exts[CL_OID_CDP][1], 0x86)] \
        if CL_OID_CDP in exts else []
    freshest = [u.decode('ascii', 'replace') for u in _cl_der_find(exts[CL_OID_FRESHEST][1], 0x86)] \
        if CL_OID_FRESHEST in exts else []
    nc = cl_name_constraints(exts[CL_OID_NC][1]) if CL_OID_NC in exts else None
    try:
        txt = _cl_openssl(['x509', '-noout', '-subject', '-issuer', '-serial', '-startdate',
                           '-enddate', '-fingerprint', '-sha256', '-nameopt', 'RFC2253'],
                          pem.encode(), what='the certificate').decode('utf-8', 'replace')
    except ValueError as e:
        raise CertRefused(str(e)[:300])

    def one(k):
        m = re.search(r'(?m)^%s=\s*(.*)$' % k, txt)
        return m.group(1).strip() if m else ''
    fp = (re.search(r'(?mi)^sha256 Fingerprint=([0-9A-F:]+)', txt) or [None, ''])[1]
    sid = sid if re.match(r'^S-1-[0-9-]{1,180}\Z', sid or '') else ('?' if sid else '')
    san_sids = [x if re.match(r'^S-1-[0-9-]{1,180}\Z', x or '') else '?' for x in san_sids]
    # Every UPN, never a few of them (F6): "more than one user" is told from all of them.
    return {'pem': pem, 'subject': one('subject'), 'issuer': one('issuer'), 'serial': one('serial'),
            'not_before': one('notBefore'), 'not_after': one('notAfter'),
            'not_after_t': cl_time(one('notAfter')), 'not_before_t': cl_time(one('notBefore')),
            'sha256': fp.replace(':', '').lower(), 'upn': upns, 'mail': mails[:4], 'sid': sid,
            'san_sids': san_sids[:8] + (['?'] if len(san_sids) > 8 else []),
            'eku': eku, 'ca': is_ca, 'cdp': cdp[:6], 'freshest': freshest[:6], 'nc': nc,
            'unknown_critical': sorted(k for k, (c, _v) in exts.items()
                                       if c and k not in CL_CRIT_KNOWN)}


def cl_name_constraints(v):
    """{permitted: [(kind, value)], excluded: [...]} of an authority's nameConstraints - kind
    'email' (rfc822Name), 'dns', 'upn' (an otherName of the UPN) or 'other' (anything else:
    a directory name, an address, a URI). CertRefused when it cannot be read."""
    out = {'permitted': [], 'excluded': []}
    try:
        for t, trees in _cl_der_all(_cl_der(v)[1]):
            key = {0xa0: 'permitted', 0xa1: 'excluded'}.get(t)
            if not key:
                continue
            for _t, sub in _cl_der_all(trees):
                base = _cl_der_all(sub)
                if not base:
                    continue
                gt, gv = base[0]
                if gt == 0x81:
                    out[key].append(('email', gv.decode('ascii', 'replace')))
                elif gt == 0x82:
                    out[key].append(('dns', gv.decode('ascii', 'replace')))
                elif gt == 0xa0:
                    p = _cl_der_all(gv)
                    if p and _cl_oid(p[0][1]) == CL_OID_UPN and len(p) > 1:
                        inner = _cl_der_all(p[1][1])
                        out[key].append(('upn', inner[0][1].decode('utf-8', 'replace')
                                         if inner else ''))
                    else:
                        out[key].append(('other', ''))
                else:
                    out[key].append(('other', ''))
    except (ValueError, IndexError):
        raise CertRefused('the name constraints of an authority cannot be read')
    return out


def _cl_nc_hit(kind, base, upn):
    """Whether a UPN (name@domain) is within one subtree. rfc822Name (RFC 5280 4.2.1.10): a
    mailbox exactly, a host exactly, or ".domain" any host under it; dNSName: the domain and
    every name under it; the UPN's own otherName: as rfc822Name."""
    name, _, dom = upn.lower().rpartition('@')
    base = str(base or '').strip().lower()
    if not base:
        return kind == 'dns'                        # an empty dNSName: every name
    if kind in ('email', 'upn'):
        if '@' in base:
            return upn.lower() == base
        if base.startswith('.'):
            return dom.endswith(base)
        return dom == base
    if kind == 'dns':
        base = base.lstrip('.')
        return dom == base or dom.endswith('.' + base)
    return False


def cl_nc_check(upn, cas):
    """openssl does not apply an authority's name constraints to the UPN (an otherName): acme
    does, for the names they can say of it - rfc822Name, dNSName and the UPN's otherName. An
    authority of the chain that constrains any of those: the UPN within one permitted subtree of
    them, and in none excluded. CertRefused."""
    for ca in cas:
        nc = ca.get('nc')
        if not nc:
            continue
        mine = ('email', 'dns', 'upn')
        allowed = [(k, b) for k, b in nc['permitted'] if k in mine]
        if allowed and not any(_cl_nc_hit(k, b, upn) for k, b in allowed):
            raise CertRefused('the UPN %s is outside the names the authority %s may issue for '
                              '(its name constraints)' % (upn, ca.get('subject') or '?'))
        if any(_cl_nc_hit(k, b, upn) for k, b in nc['excluded'] if k in mine):
            raise CertRefused('the UPN %s is among the names the authority %s may not issue for '
                              '(its name constraints)' % (upn, ca.get('subject') or '?'))


def cl_time(words):
    """Seconds of 'Nov 13 00:31:40 2031 GMT' (openssl's dates), or 0."""
    try:
        return float(calendar.timegm(time.strptime(re.sub(r'\s+', ' ', str(words or '').strip())
                                                   .replace(' GMT', ''), '%b %d %H:%M:%S %Y')))
    except ValueError:
        return 0.0


def cl_who_words(f):
    """A certificate as it may be written down: subject and serial - nothing more of it."""
    return '%s (serial %s)' % (str(f.get('subject') or '?')[:200], str(f.get('serial') or '?')[:64])


# ---- the CRL at a certificate's CRL Distribution Point ------------------------------------------
def cl_addr_no(ip):
    """Why acme fetches no CRL from an address ('' when it does): loopback, link-local
    (169.254/16, fe80::/10 - a cloud's metadata service), multicast, unspecified, reserved, "this
    network", a cloud's metadata address. AD CS's CDPs are mostly inside: private addresses
    (RFC 1918, fc00::/7) are fetched from (security review F5)."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip.split('%', 1)[0])
    if getattr(ip, 'ipv4_mapped', None):
        ip = ip.ipv4_mapped
    if any(ip == ipaddress.ip_address(x) for x in CL_CDP_IPS_NO):
        return 'a cloud\'s metadata service'
    if ip.is_loopback:
        # The tests' CRL is served on this machine (never set by acme itself).
        return '' if os.environ.get('ACME_CDP_LOOPBACK_OK') == '1' else 'loopback'
    if ip.is_link_local:
        return 'link-local'
    if ip.is_multicast:
        return 'multicast'
    if ip.is_unspecified or (ip.version == 4 and ip in ipaddress.ip_network('0.0.0.0/8')):
        return 'unspecified'
    if ip.is_reserved:
        return 'reserved'
    return ''


def cl_cdp_ok(url):
    """An address a CRL is fetched from: http only, no user or password in it, no name of a
    cloud's metadata service, a number in it none of cl_addr_no's - in whatever form it is
    written. Its name's addresses are checked again when it is fetched (cl_http_get)."""
    try:
        u = urllib.parse.urlsplit(url)
        u.port
    except ValueError:
        return False
    if u.scheme != 'http' or not u.hostname or u.username or u.password:
        return False
    host = u.hostname.lower().rstrip('.')
    if host in CL_CDP_NAMES_NO or any(host.endswith('.' + n) for n in CL_CDP_NAMES_NO
                                      if '.' in n):
        return False
    try:
        return not cl_addr_no(ipaddress.ip_address(host.split('%', 1)[0]))
    except ValueError:
        return True


def cl_http_get(url):
    """The body at a CRL's http address: every address its name has looked up and checked
    (cl_addr_no - 2852039166 or 0251.0376.0251.0376 as the resolver reads them, a name that
    resolves to 169.254.169.254) and the connection made to the address checked, never looked up
    again; no redirect followed, CL_CRL_MOST at most, CL_CRL_FETCH_S for the whole of it.
    ValueError says why not."""
    import http.client as _hc
    if not cl_cdp_ok(url):
        raise ValueError('not an address acme fetches a CRL from (http; no loopback, link-local '
                         'or metadata address)')
    u = urllib.parse.urlsplit(url)
    host, port = u.hostname, u.port or 80
    deadline = time.monotonic() + CL_CRL_FETCH_S
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as e:
        raise ValueError('%s cannot be looked up (%s)' % (host, e))
    addrs = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(str(info[4][0]).split('%', 1)[0])
        except ValueError:
            raise ValueError('%s has an address acme cannot read (%s)' % (host, info[4][0]))
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:
        raise ValueError('%s has no address' % host)
    for ip in addrs:
        why = cl_addr_no(ip)
        if why:
            raise ValueError('%s is %s (%s) - no CRL is fetched from it' % (host, ip, why))
    path = (u.path or '/') + ('?' + u.query if u.query else '')
    last = None
    for ip in addrs[:4]:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        conn = _hc.HTTPConnection(str(ip), port, timeout=min(5.0, left))
        try:
            conn.request('GET', path, headers={
                'Host': ('[%s]' % host if ':' in host else host) + (':%d' % port if u.port else ''),
                'User-Agent': 'acme/%s' % __version__, 'Accept': '*/*', 'Connection': 'close'})
            r = conn.getresponse()
            if 300 <= r.status < 400:
                raise ValueError('it answers with a redirect (HTTP %d to %s) - not followed'
                                 % (r.status, str(r.getheader('Location') or '?')[:120]))
            if r.status != 200:
                raise ValueError('HTTP %d' % r.status)
            try:
                if int(r.getheader('Content-Length') or 0) > CL_CRL_MOST:
                    raise ValueError('larger than %d MB' % (CL_CRL_MOST >> 20))
            except (TypeError, ValueError) as e:
                if 'larger' in str(e):
                    raise
            raw = b''
            while True:
                if time.monotonic() > deadline:
                    raise ValueError('it took longer than %d s' % CL_CRL_FETCH_S)
                part = r.read1(65536)
                if not part:
                    break
                raw += part
                if len(raw) > CL_CRL_MOST:
                    raise ValueError('larger than %d MB' % (CL_CRL_MOST >> 20))
            return raw
        except (OSError, _hc.HTTPException) as e:
            last = e
        finally:
            conn.close()
    raise ValueError(('%s' % last)[:200] if last else 'it took longer than %d s' % CL_CRL_FETCH_S)


def cl_crl_info(pem):
    """Of a CRL (PEM): its next update (seconds, or None), the Freshest CRL it names (where its
    delta is), whether it is a delta CRL itself."""
    out = {'next': None, 'freshest': [], 'delta': False}
    m = re.search(r'-----BEGIN X509 CRL-----([A-Za-z0-9+/=\s]+)-----END X509 CRL-----', pem)
    try:
        der = base64.b64decode(re.sub(r'\s+', '', m.group(1))) if m else b''
        _t, body, _ = _cl_der(der)
        _t, tbs, _ = _cl_der(body)
        for t, v in _cl_der_all(tbs):
            if t != 0xa0:
                continue
            for _t, one in _cl_der_all(_cl_der(v)[1]):
                parts = _cl_der_all(one)
                oid = _cl_oid(parts[0][1])
                if oid == CL_OID_FRESHEST:
                    out['freshest'] = [u.decode('ascii', 'replace')
                                       for u in _cl_der_find(parts[-1][1], 0x86)][:6]
                elif oid == CL_OID_DELTA:
                    out['delta'] = True
    except (ValueError, IndexError, binascii.Error, AttributeError):
        pass
    try:
        nu = _cl_openssl(['crl', '-noout', '-nextupdate'], pem.encode(), what='the CRL').decode()
        m = re.search(r'nextUpdate=(.+)', nu)
        if m and 'NONE' not in m.group(1):
            out['next'] = cl_time(m.group(1)) or None
    except ValueError:
        pass
    return out


def cl_crl_fetch(url):
    """The CRL at url as PEM: fetched again after CL_CRL_FRESH_S (ten minutes) at most - sooner
    at its next update; while the address does not answer, the last good one until its next update,
    then nothing. CertRefused ('unavailable') when there is none to be had - a CRL already past
    its next update is none (a delta CRL past it openssl would leave out without a word)."""
    now = time.time()
    with CL_CRL_LOCK:
        got = CL_CRL_CACHE.get(url)
    good = bool(got and got.get('pem') and now < got['next'])
    if good and (now - got['at'] < CL_CRL_FRESH_S or now - float(got.get('tried') or 0) < 60):
        return got
    try:
        raw = cl_http_get(url)
        form = 'PEM' if b'-----BEGIN X509 CRL' in raw else 'DER'
        pem = _cl_openssl(['crl', '-inform', form, '-outform', 'PEM'], raw,
                          what='the CRL').decode('ascii', 'replace')
        info = cl_crl_info(pem)
        nxt = info['next'] or now + 3600
        if nxt <= now:
            raise ValueError('it has run out (its next update was %s)'
                             % time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(nxt)))
        one = {'at': now, 'pem': pem, 'next': nxt, 'url': url, 'err': '', 'tried': 0,
               'freshest': info['freshest'], 'delta': info['delta']}
        with CL_CRL_LOCK:
            if len(CL_CRL_CACHE) > 50:
                CL_CRL_CACHE.clear()
            CL_CRL_CACHE[url] = one
        return one
    except Exception as e:                              # noqa: BLE001
        why = str(e)[:200] or e.__class__.__name__
        if good:
            kept = dict(got, err=why, tried=now)        # the last good one, said why
            with CL_CRL_LOCK:
                CL_CRL_CACHE[url] = kept
            return kept
        with CL_CRL_LOCK:
            CL_CRL_CACHE[url] = {'at': now, 'pem': '', 'next': 0, 'url': url, 'err': why}
        raise CertRefused('the CRL at %s could not be had (%s) - nobody signs in while the '
                          'certificate cannot be checked for revocation' % (url, why), 'unavailable')


def _cl_crl_any(urls):
    last = None
    for u in urls[:3]:
        try:
            return cl_crl_fetch(u)
        except CertRefused as e:
            last = e
    raise last


def cl_crls_of(c, what):
    """The CRL of one certificate (a person's, or an authority's above it), and its delta CRL
    when it or the CRL names one (Freshest CRL): [PEM], and whether a delta is among them.
    CertRefused - no CRL, no sign-in; a delta named and not to be had neither (review F3)."""
    named = list(c.get('cdp') or [])
    urls = [u for u in named if u.lower().startswith('http://')]
    if not urls:
        raise CertRefused('%s names no CRL over http (CRL Distribution Points) - it cannot be '
                          'checked for revocation' % what)
    urls = [u for u in urls if cl_cdp_ok(u)]
    if not urls:
        raise CertRefused('the CRL Distribution Point of %s is not an address acme fetches from '
                          '(http; no loopback, link-local or metadata address)' % what)
    base = _cl_crl_any(urls)
    out = [base['pem']]
    named = list(dict.fromkeys(list(c.get('freshest') or []) + list(base.get('freshest') or [])))
    if not named:
        return out, False
    urls = [u for u in named if u.lower().startswith('http://') and cl_cdp_ok(u)]
    if not urls:
        raise CertRefused('the delta CRL (Freshest CRL) of %s is at no address acme fetches '
                          'from (http; no loopback, link-local or metadata address) - its '
                          'revocations of the last days cannot be seen' % what, 'unavailable')
    out.append(_cl_crl_any(urls)['pem'])
    return out, True


def _cl_verify(ca_file, leaf, crl_file=None, deltas=False):
    """openssl verify against the authorities put in and nothing else - never the system's own
    store (-CAfile alone still reads the default folder of roots): CertRefused, or None. With
    CRLs: every certificate of the chain checked (-crl_check_all: an issuing authority its root
    revoked too; the root itself, its own anchor, is not), deltas applied (-use_deltas)."""
    args = ['openssl', 'verify', '-no-CApath', '-no-CAstore', '-CAfile', str(ca_file)]
    if crl_file:
        args += ['-crl_check_all', '-CRLfile', crl_file] + (['-use_deltas'] if deltas else [])
    args.append(leaf)
    try:
        got = subprocess.run(args, capture_output=True, text=True, timeout=30,
                             env=dict(os.environ, SSL_CERT_DIR='/nonexistent',
                                      SSL_CERT_FILE='/nonexistent'))
    except (OSError, subprocess.SubprocessError) as e:
        raise CertRefused('openssl did not run: %s' % e, 'unavailable')
    if got.returncode == 0 and re.search(r':\s*OK\s*$', got.stdout or ''):
        return None
    words = (got.stdout or '') + '\n' + (got.stderr or '')
    m = re.search(r'error (\d+) at (\d+) depth lookup:\s*(.+)', words)
    code = int(m.group(1)) if m else 0
    kind = {23: 'revoked', 10: 'expired', 9: 'certificate', 12: 'unavailable',
            11: 'unavailable', 3: 'unavailable'}.get(code, 'certificate')
    if code in (10, 23) and m.group(2) != '0':
        kind = 'certificate'
    why = ('%s%s' % (m.group(3).strip(), '' if m.group(2) == '0' else ' (an authority above it)')) \
        if m else re.sub(r'\S*acme-cert-\S*:?\s*', '', words).strip()[:300]
    raise CertRefused('the certificate is not taken: %s' % why, kind)


CL_CA_FACTS = {'sha': None, 'cas': []}


def cl_ca_facts(ca_file):
    """The facts of every authority in the file (cl_facts), read once for each content."""
    try:
        with open(str(ca_file), 'rb') as fh:
            raw = fh.read(CL_CA_FILE_MOST + 1)
    except OSError:
        return []
    sha = hashlib.sha256(raw).hexdigest()
    if CL_CA_FACTS['sha'] == sha:
        return CL_CA_FACTS['cas']
    out = []
    for body in CL_PEM_RE.findall(raw.decode('ascii', 'replace'))[:CL_CAS_MOST * 2]:
        try:
            out.append(cl_facts('-----BEGIN CERTIFICATE-----%s-----END CERTIFICATE-----' % body))
        except CertRefused:
            continue
    CL_CA_FACTS.update(sha=sha, cas=out)
    return out


def cl_chain(f, cas):
    """The authorities above a certificate among those put in, the nearest first - by subject
    and issuer, as openssl built it (every one of a name, should two have it); a root ends it."""
    out, want, seen = [], f.get('issuer'), set()
    for _ in range(8):
        hit = [c for c in cas if c['subject'] == want and c['sha256'] not in seen]
        if not hit:
            break
        for c in hit:
            seen.add(c['sha256'])
            out.append(c)
        if any(c['subject'] == c['issuer'] for c in hit):
            break
        want = hit[0]['issuer']
    return out


def cl_check(pem, ca_file, crl=True):
    """The facts of a client certificate that passed every check of its own, or CertRefused.
    The person is looked for after it (cl_admin_would, cl_portal_would)."""
    pem = str(pem or '').strip()
    if not pem:
        raise CertRefused('no certificate was sent (none chosen, or the browser has none of the '
                          'authorities put in here)')
    if len(pem) > CL_CERT_MOST:
        raise CertRefused('larger than any certificate of a person')
    f = cl_facts(pem)
    if f['ca']:
        raise CertRefused('that is the certificate of an authority, not of a person')
    if f['unknown_critical']:
        raise CertRefused('the certificate has a critical extension acme does not know (%s)'
                          % ', '.join(f['unknown_critical'])[:200])
    if not f['eku'] or not set(f['eku']) & set(CL_EKU_SIGN_IN):
        raise CertRefused('the certificate is not for signing in (no Client Authentication or '
                          'Smart Card Logon among its key usages)')
    if not os.path.exists(str(ca_file)):
        raise CertRefused('no authority is put in', 'unavailable')
    # Every UPN first, all of them (F6), and the SIDs of the SAN against the extension (F1).
    if not f['upn']:
        raise CertRefused('the certificate names no user (no UPN in its Subject Alternative Name)')
    if len(set(u.strip().lower() for u in f['upn'])) > 1:
        raise CertRefused('the certificate names more than one user (UPN)')
    if f['san_sids'] and f['sid'] and (f['sid'] == '?' or
                                       any(s.upper() != f['sid'].upper() for s in f['san_sids'])):
        raise CertRefused('the SID in the Subject Alternative Name of the certificate (%s) is not '
                          'the one of its SID extension (%s) - the requester writes the first: '
                          'not taken' % (', '.join(f['san_sids'])[:120], f['sid']))
    upn = f['upn'][0].strip()
    if not re.match(r'^[^@\s\\/\x00-\x1f\x7f]{1,190}@[A-Za-z0-9.-]{1,253}\Z', upn):
        raise CertRefused('the UPN in the certificate is not a name@domain')
    work = tempfile.mkdtemp(prefix='acme-cert-')
    try:
        leaf = os.path.join(work, 'leaf.pem')
        with open(leaf, 'w') as fh:
            fh.write(f['pem'])
        # The chain first, without the CRL: a CDP is fetched only for a certificate of the
        # authorities put in - never an address written into anybody's certificate.
        _cl_verify(ca_file, leaf)
        chain = cl_chain(f, cl_ca_facts(ca_file))
        # The authorities' name constraints for the UPN: openssl does not apply them to it.
        cl_nc_check(upn, chain)
        if crl:
            pems, deltas = cl_crls_of(f, 'the certificate')
            # ...and every authority's above it but the root's (F4): an issuing authority its
            # root revoked signs nobody in.
            for c in chain:
                if c['subject'] != c['issuer']:
                    more, d = cl_crls_of(c, 'the authority %s' % c['subject'])
                    pems += more
                    deltas = deltas or d
            cp = os.path.join(work, 'crl.pem')
            with open(cp, 'w') as fh:
                fh.write(''.join(p if p.endswith('\n') else p + '\n' for p in pems))
            _cl_verify(ca_file, leaf, cp, deltas)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    f['upn_one'] = upn
    f['cas'] = [c['sha256'] for c in chain]
    return f


# ---- the authorities, kept in the database ----------------------------------------------------
def cl_cas_row(store):
    """[{pem, subject, issuer, not_after, sha256, ...}] as the database keeps them (the row read as
    signed: with db_guard on, one not written by acme reads as not there)."""
    try:
        got = json.loads(store.get_meta(CL_META) or 'null')
    except (ValueError, TypeError):
        return []
    cas = got.get('cas') if isinstance(got, dict) else None
    return [c for c in cas if isinstance(c, dict) and c.get('pem')] if isinstance(cas, list) else []


def cl_ca_view(c):
    return {k: c.get(k) for k in ('subject', 'issuer', 'not_before', 'not_after', 'sha256', 'serial',
                                  'by', 'at', 'name', 'self_signed')}


def cl_cas_read(raw):
    """Every certificate of a file put in - PEM (one or many), DER, or PKCS#7 (.p7b, PEM or
    DER) - as PEM; ValueError when it holds none."""
    raw = bytes(raw or b'')
    if not raw:
        raise ValueError('the file is empty')
    if len(raw) > CL_CA_FILE_MOST:
        raise ValueError('the file is %s - authorities are a few kB' % bytes_words(len(raw)))
    pems = []
    if b'-----BEGIN PKCS7-----' in raw or (not b'-----BEGIN' in raw and raw[:1] == b'\x30' and
                                           _cl_is_p7(raw)):
        form = 'PEM' if b'-----BEGIN PKCS7-----' in raw else 'DER'
        out = _cl_openssl(['pkcs7', '-inform', form, '-print_certs'], raw,
                          what='the PKCS#7 file').decode('ascii', 'replace')
        pems = ['-----BEGIN CERTIFICATE-----%s-----END CERTIFICATE-----' % b
                for b in CL_PEM_RE.findall(out)]
    elif b'-----BEGIN CERTIFICATE-----' in raw:
        pems = ['-----BEGIN CERTIFICATE-----%s-----END CERTIFICATE-----' % b
                for b in CL_PEM_RE.findall(raw.decode('ascii', 'replace'))]
    elif b'-----BEGIN' in raw:
        raise ValueError('that is no certificate - a key, or a request? Put in the authorities\' '
                         'certificates (PEM, DER or .p7b)')
    else:
        pems = [_cl_openssl(['x509', '-inform', 'DER', '-outform', 'PEM'], raw,
                            what='the certificate (DER)').decode('ascii', 'replace')]
    if not pems:
        raise ValueError('the file holds no certificate')
    if len(pems) > CL_CAS_MOST:
        raise ValueError('the file holds %d certificates - %d at most' % (len(pems), CL_CAS_MOST))
    return pems


def _cl_is_p7(raw):
    """A DER of PKCS#7 signedData: its content type is 1.2.840.113549.1.7.2."""
    try:
        _t, body, _ = _cl_der(raw)
        items = _cl_der_all(body)
        return bool(items and items[0][0] == 0x06 and _cl_oid(items[0][1]) == '1.2.840.113549.1.7.2')
    except ValueError:
        return False


def cl_cas_checked(raw):
    """The authorities of a file, each one checked: an authority (basicConstraints CA:TRUE), not a
    person's certificate. [facts]; ValueError says what is wrong."""
    out = []
    for pem in cl_cas_read(raw):
        try:
            f = cl_facts(pem)
        except CertRefused as e:
            raise ValueError(e.why)
        if not f['ca']:
            raise ValueError('%s is not an authority (basicConstraints CA:TRUE) - put in the '
                             'issuing authority and its root, never a person\'s certificate'
                             % (f['subject'] or 'a certificate in the file'))
        f['self_signed'] = f['subject'] == f['issuer']
        out.append(f)
    return out


def cl_cas_save(store, cas, by, keep=None, words=''):
    before = krb_state_now(store)
    store.set_meta(CL_META, json.dumps({'cas': cas, 'at': time.time(), 'by': str(by or '')[:120]}))
    CL_STATE.update(have=bool(cas), checked=0.0)
    if words:
        store.add_event('settings', words, 'warn', who=by)
    if CL_STATE['writer']:
        try:
            cl_write_out(store)
        except Exception as e:                          # noqa: BLE001
            log('the authorities could not be written out on %s: %s' % (node_name(), e), 'warn')
    krb_sessions_settle(store, before, keep, by)


def cl_cas_put(store, raw, by, name='', keep=None):
    """Authorities put in (the pages, acme --cert-login-ca, a configuration file): checked, added
    to those there (the same one again changes nothing), kept signed in the database; this node
    writes them out at once, the others within seconds. (added, all) as the card shows them."""
    new = cl_cas_checked(raw)
    cas = cl_cas_row(store)
    have = {c['sha256'] for c in cas}
    added = []
    for f in new:
        if f['sha256'] in have:
            continue
        one = {k: f[k] for k in ('pem', 'subject', 'issuer', 'serial', 'not_before', 'not_after',
                                 'sha256', 'self_signed')}
        one.update(by=str(by or '')[:120], at=time.time(),
                   name=os.path.basename(str(name or ''))[:120])
        cas.append(one)
        have.add(f['sha256'])
        added.append(one)
    if len(cas) > CL_CAS_MOST:
        raise ValueError('%d authorities at most' % CL_CAS_MOST)
    if added:
        cl_cas_save(store, cas, by, keep, '%s put in the authorities of the sign-in with a '
                    'certificate: %s' % (by, '; '.join('%s (SHA-256 %s)' % (c['subject'], c['sha256'][:16])
                                                     for c in added)[:600]))
    return [cl_ca_view(c) for c in added], [cl_ca_view(c) for c in cas]


def cl_cas_drop(store, sha, by, keep=None):
    """One authority taken away, by its SHA-256 (or the first 12 or more of it). The one taken
    away, or None."""
    sha = re.sub(r'[^0-9a-f]', '', str(sha or '').lower())
    if len(sha) < 12:
        return None
    cas = cl_cas_row(store)
    hit = [c for c in cas if c['sha256'].startswith(sha)]
    if len(hit) != 1:
        return None
    left = [c for c in cas if c is not hit[0]]
    if not left:
        sso_last_way_check(store, 'certificate')        # ValueError: the last way in
    cl_cas_save(store, left, by, keep, '%s took the authority %s away from the sign-in with a '
                'certificate%s' % (by, hit[0]['subject'], '' if left else
                                   ' - nobody signs in with a certificate until another is put in'))
    if not left:
        meta_drop(store, CL_META)
    else:
        # Those made with a certificate of it end (one made before the chain was kept, too).
        gone = hit[0]['sha256'][:16]
        cl_sessions_end(store, lambda _p, data: gone in (data.get('cas') or [gone]), keep, by,
                        'the authority %s was taken away' % hit[0]['subject'][:200])
    return cl_ca_view(hit[0])


def cl_export(store):
    """The authorities in an exported configuration: public certificates, always whole."""
    cas = cl_cas_row(store)
    return {'cas': [{k: c.get(k) for k in ('pem', 'name')} for c in cas]} if cas else None


def cl_import_checked(conf):
    """The authorities of a configuration file, checked before anything is applied: None (not in
    the file), or the PEM of them all ('' for none)."""
    got = conf.get('certlogin')
    if got is None:
        return None
    if not isinstance(got, dict) or not isinstance(got.get('cas') or [], list):
        raise ApiError(400, 'certlogin in the file is not an object with a list of authorities')
    pems = []
    for c in got.get('cas') or []:
        pem = str((c or {}).get('pem') or '') if isinstance(c, dict) else ''
        try:
            cl_cas_checked(pem.encode('ascii', 'replace'))
        except ValueError as e:
            raise ApiError(400, 'the authorities of the sign-in with a certificate in the file: %s'
                           % e)
        pems.append(pem.strip())
    return '\n'.join(pems)


def cl_import_apply(store, pems, by, replace, keep=None):
    """The authorities of a configuration file put in (with replace, those not in it taken
    away). True when something changed."""
    if pems is None:
        return False
    want = cl_cas_checked(pems.encode()) if pems.strip() else []
    if replace:
        cas = cl_cas_row(store)
        keep_sha = {f['sha256'] for f in want}
        for c in cas:
            if c['sha256'] not in keep_sha:
                cl_cas_drop(store, c['sha256'], by, keep)
    added, _ = cl_cas_put(store, pems.encode(), by, 'the configuration file', keep) if want \
        else ([], [])
    return bool(added) or bool(replace)


def cl_ca_path():
    return Path(STATE_DIR) / 'certlogin' / 'cas.pem'


def cl_cas_pem(cas):
    return ''.join(c['pem'] if c['pem'].endswith('\n') else c['pem'] + '\n' for c in cas)


def cl_write_out(store):
    """The authorities as the database has them, written to this node's own file (0600, the
    service's user, the folder 0700) - or the file taken away when there are none. True when
    the file is as the database says."""
    path = cl_ca_path()
    cas = cl_cas_row(store)
    if not cas:
        if path.exists():
            path.unlink()
            log('the authorities of the sign-in with a certificate are taken away on %s'
                % node_name())
        CL_STATE.update(have=False, sha=None, written=False, error='')
        return True
    CL_STATE['have'] = True
    text = cl_cas_pem(cas).encode('ascii')
    sha = hashlib.sha256(text).hexdigest()
    try:
        now = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    except OSError:
        now = None
    if now != sha:
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(path.parent), 0o700)
        fd, tmp = tempfile.mkstemp(prefix='.cas.pem.', dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(text)
            os.replace(tmp, str(path))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        log('the authorities of the sign-in with a certificate are written out on %s (%d)'
            % (node_name(), len(cas)))
    CL_STATE.update(sha=sha, written=True, error='')
    return True


def cl_listening(port):
    """Whether something answers on this node's port (nginx, once the root helper wrote its
    server)."""
    try:
        with socket.create_connection(('127.0.0.1', int(port)), timeout=0.5):
            return True
    except (OSError, ValueError):
        return False


def cl_tick(d):
    """Every node: the authorities written out as the database has them, the tries of past
    minutes tidied, and this node's state published for the card."""
    CL_STATE['writer'] = True
    now = time.time()
    if now - CL_STATE['checked'] < 15:
        return
    CL_STATE['checked'] = now
    try:
        cl_write_out(d.store)
    except Exception as e:                              # noqa: BLE001
        CL_STATE.update(written=False, error=str(e)[:300])
    port = cl_port()
    listening = bool(cl_any_on() and cl_listening(port))
    said = {'written': bool(CL_STATE['written']), 'sha': str(CL_STATE['sha'] or '')[:12],
            'error': CL_STATE['error'], 'port': port, 'listening': listening,
            'busy': cl_port_busy(port, served=listening and cl_web_served(port)),
            'crls': cl_crls_now(), 'version': __version__}
    if said != CL_STATE['said'] or now - CL_STATE['said_at'] > 300:
        d.store.set_meta(CL_NODE_META + node_name(), json.dumps(dict(said, at=now)))
        CL_STATE.update(said=said, said_at=now)
        for r in d.store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (CL_TRIED_META + '%',)):
            try:
                if now - float(json.loads(r['v'] or '{}').get('at') or 0) > 600:
                    d.store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
            except (ValueError, TypeError, AttributeError):
                d.store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))


def cl_web_served(port):
    """Whether root's last word on this node says nginx was given the certificate's port."""
    try:
        return int((web_status().get('certlogin') or {}).get('port') or 0) == int(port)
    except Exception:                                   # noqa: BLE001
        return False


def cl_crls_now():
    with CL_CRL_LOCK:
        got = list(CL_CRL_CACHE.values())
    return [{'url': c['url'], 'ok': bool(c.get('pem')), 'at': c.get('at'),
             'next': c.get('next') or None, 'err': c.get('err') or ''}
            for c in sorted(got, key=lambda c: c['url'])][:20]


def cl_have(store=None, unknown=False):
    """Whether authorities are put in - as this node last read it; not read yet, the database is
    asked; `unknown` when that cannot be known ("only ..." fails closed on it)."""
    if CL_STATE['have'] is None and store is not None:
        try:
            CL_STATE['have'] = bool(cl_cas_row(store))
        except Exception as e:                          # noqa: BLE001
            log_sparing('cl-have', 'whether authorities are put in could not be read: %s' % e,
                        'warn', every=300)
    if CL_STATE['have'] is None:
        return unknown
    return bool(CL_STATE['have'])


def cl_startup(store):
    """At the daemon's start, before it serves anybody: whether authorities are put in."""
    try:
        CL_STATE['have'] = bool(cl_cas_row(store))
    except Exception as e:                              # noqa: BLE001
        CL_STATE['have'] = None                         # fails closed: cl_have(unknown=True)
        log('whether authorities of the sign-in with a certificate are put in could not be '
            'read: %s' % e, 'warn')


# ---- each part's switches ------------------------------------------------------------------
def cl_port():
    try:
        return int(CONFIG.get('certlogin_port') or 8443)
    except (TypeError, ValueError):
        return 8443


def certlogin_port_taken(port):
    """What a port is already, or '' when the certificate's port may be it."""
    port = int(port)
    fixed = {80: 'HTTP (port 80)', 443: 'the pages (HTTPS, 443)', 22: 'SSH', 53: 'DNS',
             25: 'mail', 161: 'SNMP', 162: 'SNMP traps', 5432: 'PostgreSQL', 3306: 'MariaDB',
             1812: 'RADIUS', 1813: 'RADIUS accounting', 9861: 'acme\'s API'}
    if port in fixed:
        return fixed[port]
    own = {'api_port': 'acme\'s API (api_port)', 'ssh_gate_port': 'acme\'s gate for SSH',
           'snmp_port': 'SNMP (snmp_port)', 'dns_port': 'acme\'s DNS server (dns_port)',
           'ha_peer_port': 'the database of the other node', 'db_port': 'the database'}
    for k, words in own.items():
        try:
            if int(CONFIG.get(k) or 0) == port:
                return words
        except (TypeError, ValueError):
            continue
    try:
        if port in [int(p) for p in sshd_ports_open(None)]:
            return 'SSH'
    except Exception:                                   # noqa: BLE001
        pass
    if 18129 <= port <= 18199:
        return 'acme\'s gate for SSH (18129-18199)'
    return ''


def cl_port_users(port):
    """[(process name, pid)] of what listens on TCP `port` on this machine (any address, IPv4 and
    IPv6) - read from /proc/net/tcp and tcp6, the processes found by their sockets ('' and 0
    for one whose process cannot be seen: another user's, when this is not root)."""
    inodes = set()
    for name in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            with open(name) as f:
                lines = f.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            p = line.split()
            if len(p) < 10 or p[3] != '0A':             # LISTEN
                continue
            try:
                if int(p[1].rsplit(':', 1)[1], 16) == int(port):
                    inodes.add(p[9])
            except (ValueError, IndexError):
                continue
    if not inodes:
        return []
    found = {}
    try:
        pids = [x for x in os.listdir('/proc') if x.isdigit()]
    except OSError:
        pids = []
    for pid in pids:
        fd_dir = '/proc/%s/fd' % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                link = os.readlink('%s/%s' % (fd_dir, fd))
            except OSError:
                continue
            if link.startswith('socket:[') and link[8:-1] in inodes:
                try:
                    with open('/proc/%s/comm' % pid) as f:
                        comm = f.read().strip()
                except OSError:
                    comm = '?'
                found.setdefault(link[8:-1], (comm, int(pid)))
                break
    out = sorted(set(found.values()))
    if len(found) < len(inodes):
        out.append(('', 0))
    return out


# The system's nginx, the one acme's root helper writes for (review F8): its master's pid file,
# and the configuration it is started with.
CL_NGINX_PID_FILES = ['/run/nginx.pid', '/var/run/nginx.pid']
CL_NGINX_CONF = '/etc/nginx/nginx.conf'


def _cl_proc(pid):
    """(comm, ppid, argv) of a process, or None."""
    try:
        with open('/proc/%d/stat' % int(pid)) as f:
            st = f.read()
        comm = st[st.index('(') + 1:st.rindex(')')]
        ppid = int(st[st.rindex(')') + 2:].split()[1])
        with open('/proc/%d/cmdline' % int(pid), 'rb') as f:
            argv = [a.decode('utf-8', 'replace') for a in f.read().split(b'\0') if a]
        return comm, ppid, argv
    except (OSError, ValueError, IndexError):
        return None


def cl_nginx_ours(pid):
    """Whether a process named nginx is acme's: the master the system's pid file names (or a
    worker of it), started with the system's configuration - not any other nginx on this machine
    (a container's, another product's) that only shares the name."""
    me = _cl_proc(pid)
    if not me or me[0] != 'nginx':
        return False
    master = int(pid)
    up = _cl_proc(me[1]) if me[1] > 1 else None
    if up and up[0] == 'nginx':
        master, me = me[1], up
    pids = set()
    for name in CL_NGINX_PID_FILES:
        try:
            with open(name) as f:
                pids.add(int(f.read().strip() or 0))
        except (OSError, ValueError):
            continue
    if master not in pids:
        return False
    words = ' '.join(me[2])
    # The master's title: "nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf".
    m = re.search(r'(?:^|\s)-c\s+(\S+)', words)
    if m and os.path.realpath(m.group(1)) != os.path.realpath(CL_NGINX_CONF):
        return False
    return not re.search(r'(?:^|\s)-p\s+(?!/etc/nginx/?(?:\s|$))', words)


def cl_port_busy(port, served=False):
    """Words when something other than acme's nginx listens on `port` here - '' when nothing
    does, or acme's nginx (cl_nginx_ours; a listener that cannot be seen counts as it only while
    `served`)."""
    users = cl_port_users(port)
    others = [(n if n != 'nginx' else 'nginx that is not acme\'s (not the system\'s service)', p)
              for n, p in users if n and not (n == 'nginx' and cl_nginx_ours(p))]
    if not others and ('', 0) in users and not served:
        others = [('another program (not to be seen as this user)', 0)]
    if not others:
        return ''
    return 'port %d is used by %s on %s - choose another port' % (
        int(port), ', '.join('%s%s' % (n, ' (pid %d)' % p if p else '') for n, p in others),
        node_name())


def cl_save_check(store, checked):
    """Before the settings are saved: the port the certificates would be served on is free on
    this node (nothing but nginx listening there) - checked when it changes, or when a part is
    switched on while the port is not served yet. The other nodes say theirs on the card, and
    their root helper writes nothing for a port taken there."""
    after = dict(CONFIG)
    after.update(checked)
    wants = any(after.get(p + '_certlogin') for p in CL_PARTS)
    if not wants:
        return
    port = int(after.get('certlogin_port') or 8443)
    st = cl_node_state(store, node_name())
    served = bool(cl_any_on()) and int(st.get('port') or cl_port()) == port and \
        bool(st.get('listening'))
    if served and 'certlogin_port' not in checked:
        return
    why = cl_port_busy(port, served=served and port == cl_port())
    if why:
        raise BadSetting('certlogin_port: ' + why)


def cl_on(part):
    """Whether a part signs people in with a certificate: its switch, and a directory to find
    them in (the portal: the portal switched on as well)."""
    if part == 'admin':
        return bool(CONFIG.get('admin_certlogin') and krb_directory_name('admin'))
    return bool(CONFIG.get('portal') and CONFIG.get('portal_certlogin') and
                krb_directory_name('portal'))


def cl_any_on():
    return any(cl_on(p) for p in CL_PARTS)


def cl_usable(part, store=None):
    """Whether a part signs anybody in with a certificate now: switched on, with authorities."""
    return bool(cl_on(part) and cl_have(store))


def cl_page_info(part, store=None):
    """What a sign-in page shows of it: the button, gone to by itself, no password - and the
    port the button leads to (nothing else; asked before anybody is signed in)."""
    only = krb_password_off(part, store)
    on = cl_usable(part, store) or (only and cl_on(part))
    return {'on': bool(on), 'auto': bool(on and CONFIG.get(part + '_certlogin_auto')),
            'only': bool(only), 'port': cl_port() if on else 0}


# Both ways by themselves on one sign-in page: Windows first - a request of the page's own that
# asks the person nothing - and the certificate (a visible trip to its port: the chooser, the
# PIN) only when Windows did not sign in. No setting: the other order would ask for a card where
# Windows would have signed the person in without a word.
SSO_AUTO_ORDER = ('windows', 'certificate')


def sso_signin_modes(part, store=None):
    """What a part's sign-in page offers, in effect now: {password: offered or not, windows and
    certificate: 'off', 'button' or 'auto', order: those tried by themselves, in the order
    tried}. The cards' summary and the page's own facts (/api/health, /api/portal/info)."""
    def mode(i):
        return 'off' if not i.get('on') else ('auto' if i.get('auto') else 'button')
    k, c = krb_page_info(part, store), cl_page_info(part, store)
    got = {'windows': mode(k), 'certificate': mode(c)}
    # What the page decides by, as the kit's pseudo-code has it: on / auto (Windows), cert /
    # cert_port / cert_auto, only (no password at all in effect).
    return dict(got, password=not krb_password_off(part, store),
                order=[w for w in SSO_AUTO_ORDER if got[w] == 'auto'],
                on=bool(k['on']), auto=bool(k['auto']), only=bool(k['only'] or c['only']),
                cert=bool(c['on']), cert_port=c['port'], cert_auto=bool(c['auto']))


def sso_last_way_check(store, way):
    """Before the keytab (way 'windows') or the last authority ('certificate') is taken away:
    ValueError while it alone signs people in to a part with "no password at all" in effect -
    nobody would get in. The switch itself may go off (the passwords come back with it)."""
    for part in KRB_PARTS:
        if not krb_password_off(part, store):
            continue
        mine = krb_usable(part, store) if way == 'windows' else cl_usable(part, store)
        other = cl_usable(part, store) if way == 'windows' else krb_usable(part, store)
        if mine and not other:
            raise ValueError('%s alone signs people in to %s with no password at all - switch "no '
                             'password at all" off first (acme --set %s_password_off=0), or put '
                             'the other way on' % ('Windows' if way == 'windows' else
                                                   'the certificate',
                                                   'these pages' if part == 'admin' else
                                                   'the enrolment pages', part))


def cl_session_gone(part, s, store):
    data = (s or {}).get('data') or {}
    return bool(data.get('how') == 'certificate' and not data.get('krb_kept') and
                not cl_usable(part, store))


def cl_session_cas(f):
    """What a session made with a certificate keeps of its chain: the authorities' SHA-256 (the
    first 16), so that taking one of them away ends it (review F8)."""
    return [str(x)[:16] for x in (f.get('cas') or [])][:8]


def cl_sessions_end(store, which, keep=None, by='', why=''):
    """The sign-ins made with a certificate that which(part, data) picks, ended - the one of
    whoever did it (`keep`, a session id of the administration) left, marked as the other
    changes leave it. The number ended."""
    keep = int(keep or 0)
    ended = {}
    try:
        rows = store.db.rows('SELECT id, kind, data FROM sessions')
    except Exception as e:                              # noqa: BLE001
        log('the sign-ins made with a certificate could not be ended: %s' % e, 'warn')
        return 0
    for r in rows:
        part = str(r.get('kind') or '')
        if part not in CL_PARTS:
            continue
        try:
            data = json.loads(r.get('data') or '{}')
        except ValueError:
            data = {}
        if not isinstance(data, dict) or data.get('how') != 'certificate' or \
                not which(part, data):
            continue
        if part == 'admin' and int(r['id']) == keep:
            store.session_merge(r['id'], {'krb_kept': time.time()})
            continue
        store.db.run('DELETE FROM sessions WHERE id = ?', (r['id'],))
        ended[part] = ended.get(part, 0) + 1
    for part, n in ended.items():
        store.add_event('accounts' if part == 'admin' else 'portal', '%s: %d sign-in(s) to %s made '
                        'with a certificate ended - %s' % (
                            by or 'acme', n, 'these pages' if part == 'admin' else
                            'the enrolment pages', why), 'warn', who=by or None)
    return sum(ended.values())


def cl_rule(part):
    """How strictly a part takes a certificate: (revocation checked, the rank of its matching) -
    made stricter, the sign-ins made with a certificate before end (review F8)."""
    return (1 if CONFIG.get(part + '_certlogin_crl', 1) else 0, CL_MATCH_RANK.get(cl_match(part), 2))


def cl_rule_stricter(was, now):
    try:
        return bool(was) and bool(now) and (now[0] > was[0] or now[1] > was[1])
    except (TypeError, IndexError):
        return False


def cl_match(part):
    m = str(CONFIG.get(part + '_certlogin_match') or 'strong')
    return m if m in CL_MATCH_WORDS else 'strong'


# ---- a certificate taken -----------------------------------------------------------------------
def cl_certificate(h, part, pem):
    """The checks both parts share: the authorities written out (first, if this node has not
    yet), the certificate's own checks with the part's revocation setting. The facts, or
    CertRefused."""
    cas = cl_cas_row(h.store)
    if not cas:
        raise CertRefused('no authority is put in yet (Settings → Accounts → Signing in with a '
                          'certificate)', 'unavailable')
    want = hashlib.sha256(cl_cas_pem(cas).encode('ascii')).hexdigest()
    if not CL_STATE.get('written') or CL_STATE.get('sha') != want:
        try:
            cl_write_out(h.store)
        except Exception as e:                          # noqa: BLE001
            raise CertRefused('the authorities could not be written out on this node',
                              'unavailable', more=str(e))
    crl = bool(CONFIG.get(part + '_certlogin_crl', 1))
    return cl_check(pem, cl_ca_path(), crl=crl)


def cl_entry_same(h, part, f, entry_upn):
    """The entry found by the account's sAMAccountName is the one of the certificate's UPN (the
    same DN), and the SID of the certificate (KB5014754) is the account's as the part says."""
    def check(entry):
        a = str((entry or {}).get('dn') or '').strip().lower()
        b = str((entry_upn or {}).get('dn') or '').strip().lower()
        if not a or a != b:
            raise CertRefused('%s is %s in the directory, and its account by sAMAccountName is %s '
                              '- not taken as the same person' % (f['upn_one'], b or '?', a or '?'),
                              'allowed')
        match = cl_match(part)
        if match == 'upn':
            return
        have = str((entry or {}).get('sid') or entry_upn.get('sid') or '')
        if not f['sid']:
            # A SID in the Subject Alternative Name only is the requester's word (F1): never
            # strong - compat still refuses one that is not the account's.
            if match == 'strong':
                raise CertRefused('the certificate of %s has no SID extension (KB5014754)%s, and '
                                  '"Which account a certificate is" is strong' % (
                                      f['upn_one'], ' - a SID in its Subject Alternative Name '
                                      'is not taken for it' if f.get('san_sids') else ''),
                                  'allowed')
            if f.get('san_sids'):
                if not have:
                    raise CertRefused('the directory did not say the SID (objectSid) of %s - the '
                                      'SID in its certificate cannot be compared' % f['upn_one'],
                                      'unavailable')
                if any(s.upper() != have.upper() for s in f['san_sids']):
                    raise CertRefused('the SID in the Subject Alternative Name of the certificate '
                                      '(%s) is not the one of %s in the directory (%s)' % (
                                          ', '.join(f['san_sids'])[:120], f['upn_one'], have),
                                      'allowed')
            return
        if f['sid'] == '?':
            raise CertRefused('the SID in the certificate of %s cannot be read' % f['upn_one'],
                              'certificate')
        if not have:
            raise CertRefused('the directory did not say the SID (objectSid) of %s - the SID in '
                              'its certificate cannot be compared' % f['upn_one'], 'unavailable')
        if have.upper() != f['sid'].upper():
            raise CertRefused('the SID in the certificate (%s) is not the one of %s in the '
                              'directory (%s)' % (f['sid'], f['upn_one'], have), 'allowed')
    return check


def cl_find_upn(h, ad, upn):
    """The directory's entry of a UPN, and its sAMAccountName. CertRefused."""
    if ad is None:
        raise CertRefused('no directory is set (or switched on) for this part', 'unavailable')
    try:
        entry = ad.find_user(upn, 'upn')
    except LdapUnreachable as e:
        raise CertRefused('the directory cannot be reached just now', 'unavailable', more=str(e))
    if not entry:
        raise CertRefused('the directory does not let %s in: nobody has that UPN' % upn, 'allowed')
    if entry.get('many'):
        raise CertRefused('the directory does not let %s in: more than one account has that UPN'
                          % upn, 'allowed')
    if not entry.get('sam'):
        raise CertRefused('the directory\'s entry of %s has no sAMAccountName' % upn, 'allowed')
    return entry


def cl_admin_would(h, f):
    """Who a certificate signs in to the administration, and as what - nothing made. The
    directory's answer (admin_ask_directory's), or CertRefused."""
    ad = h.d.dirs.get(krb_directory_name('admin').lower()) if krb_directory_name('admin') else None
    entry_upn = cl_find_upn(h, ad, f['upn_one'])
    return sso_admin_would(h, entry_upn['sam'], f['upn_one'], CertRefused,
                           cl_entry_same(h, 'admin', f, entry_upn))


def cl_portal_would(h, f):
    """Who a certificate signs in to the portal - (ad, entry, groups). CertRefused."""
    entry_upn = cl_find_upn(h, portal_directory(h), f['upn_one'])
    return sso_portal_would(h, entry_upn['sam'], f['upn_one'], CertRefused,
                            cl_entry_same(h, 'portal', f, entry_upn))


def cl_refused_event(h, part, why, who=''):
    kind = 'sign-ins' if part == 'admin' else 'portal'
    log_sparing('cl-refused:%s:%s' % (part, str(why)[:40]),
                'a sign-in with a certificate to %s from %s was refused: %s'
                % ('these pages' if part == 'admin' else 'the enrolment pages', h.client_ip(), why),
                'warn', every=300)
    h.store.add_event(kind, 'a sign-in with a certificate was refused (from %s%s): %s'
                      % (h.client_ip(), ', for %s' % who if who else '', why), 'warn',
                      who=who.split('@', 1)[0] if who else None)


def cl_body(h):
    """{cert, failed} as the page relays them from nginx - capped before anything is read."""
    b = h.body()
    pem = str(b.get('cert') or '')
    once = str(b.get('once') or '')[:64]
    if len(pem) > CL_CERT_MOST:
        return {'too_big': True, 'once': once}
    return {'cert': pem, 'failed': str(b.get('failed') or '')[:200], 'once': once}


def cl_once(h, b):
    """The page's nonce, used once in the whole cluster (review F7): the random part of it the
    page checked against its cookie, kept five minutes and a half (as long as the nonce lives) -
    a second request with it, from wherever, is refused. CertRefused."""
    once = str(b.get('once') or '')
    if not re.match(r'^[0-9a-f]{32}\Z', once):
        raise CertRefused('no nonce of the page came with the certificate')
    if not node_key_add(h.store, CL_ONCE, once, CL_ONCE_S, limit=1):
        raise CertRefused('the nonce of the page was used already - sent again (a replay?)')


def cl_take(h, part, b):
    """The certificate of a request, checked - the facts, or CertRefused (nginx's own refusal
    of one, said as it said it, too). The page's nonce first: once only."""
    cl_once(h, b)
    if b.get('too_big'):
        raise CertRefused('larger than any certificate of a person')
    if b.get('failed'):
        why = re.sub(r'[^\x20-\x7e]', '', b['failed'])
        raise CertRefused('nginx did not take the certificate: %s' % (why.split(':', 1)[-1] or
                                                                      'refused'),
                          'expired' if 'expired' in why else 'certificate')
    return cl_certificate(h, part, b.get('cert'))


@route('POST', '/api/auth/cert')
def _auth_cert(h):
    """The administration's sign-in with a certificate: {cert} as nginx handed it to the page on
    the certificate's port (after the nonce was checked there)."""
    if not cl_on('admin'):
        raise ApiError(404, 'signing in with a certificate is switched off here')
    b = cl_body(h)
    tries = max(20, 4 * split_limit('login_tries', 5))
    key = h.throttle('certlogin', tries, int(CONFIG.get('login_wait_min') or 15),
                     what='refused sign-ins with a certificate')
    who = ''
    try:
        f = cl_take(h, 'admin', b)
        who = f['upn_one']
        said = cl_admin_would(h, f)
        acc = admin_directory_account(h, said)
        if not acc:
            raise CertRefused('%s is an account of this server - it signs in with its password'
                              % said['name'], 'allowed')
        if acc.get('disabled'):
            raise CertRefused('%s is switched off here (Accounts)' % acc['name'], 'allowed')
        if acc.get('role') == 'portal':
            raise CertRefused('%s: %s' % (acc['name'], PORTAL_ONLY_SAID), 'allowed')
    except CertRefused as e:
        h.failed(key)
        cl_refused_event(h, 'admin', e.why, who)
        raise ApiError(e.status, e.said)
    return sso_admin_open(h, key, acc, 'certificate',
                          {'subject': f['subject'][:200], 'serial': f['serial'][:64],
                           'principal': f['upn_one'], 'cas': cl_session_cas(f)},
                          'with a certificate (%s)' % cl_who_words(f), 'with a certificate')


@route('POST', '/api/portal/cert')
def _portal_cert(h):
    """The portal's sign-in with a certificate - its own switch, its own directory and rules."""
    if not cl_on('portal'):
        raise ApiError(404, 'signing in with a certificate is switched off here')
    b = cl_body(h)
    tries = max(20, 4 * split_limit('portal_tries', 5))
    key = h.throttle('portal-certlogin', tries, int(CONFIG.get('portal_wait_min') or 15),
                     what='refused sign-ins with a certificate')
    who = ''
    try:
        f = cl_take(h, 'portal', b)
        who = f['upn_one']
        ad, entry, _groups = cl_portal_would(h, f)
    except CertRefused as e:
        h.failed(key)
        cl_refused_event(h, 'portal', e.why, who)
        raise ApiError(e.status, e.said)
    if h.headers.get('X-Acme-Session'):
        h.store.session_end(h.headers.get('X-Acme-Session'))
    try:
        got = portal_open_dir(h, key, entry['sam'], ad, entry, how='certificate',
                              more={'cas': cl_session_cas(f)})
    except ApiError as e:
        cl_refused_event(h, 'portal', str(e), who)
        raise ApiError(503 if e.status == 503 else 401,
                       cl_refused_words('unavailable' if e.status == 503 else 'allowed'))
    return dict(got, how='certificate')


@route('POST', '/api/certlogin/try')
def _certlogin_try(h):
    """Try my certificate (the card, on the certificate's port): who it would sign in to that
    part, and as what - nobody signed in. Kept ten minutes for the card to show (`id`)."""
    s = h.me('readonly')
    b = cl_body(h)
    part = str(h.body().get('part') or 'admin')
    if part not in CL_PARTS:
        raise ApiError(400, 'admin or portal')
    key = h.throttle('certlogin', max(20, 4 * split_limit('login_tries', 5)),
                     int(CONFIG.get('login_wait_min') or 15),
                     what='refused sign-ins with a certificate')
    out = {'part': part, 'on': cl_on(part), 'at': time.time()}
    try:
        f = cl_take(h, part, b)
        out.update(cert=True, upn=f['upn_one'], subject=f['subject'], issuer=f['issuer'],
                   serial=f['serial'], not_after=f['not_after'], sid=f['sid'])
        if part == 'admin':
            said = cl_admin_would(h, f)
            out.update(ok=True, name=said['name'], role=said['role'],
                       display=said.get('display') or '', second=bool(CONFIG.get('admin_2fa')))
        else:
            _ad, entry, groups = cl_portal_would(h, f)
            out.update(ok=True, name=str(entry.get('upn') or entry.get('sam') or '').lower(),
                       role='portal', display=entry.get('display') or '', groups=groups[:10],
                       second=portal_gate_needed())
    except CertRefused as e:
        h.failed(key)
        out.update(ok=False, said=e.why, kind=e.kind)
        out.setdefault('cert', False)
    ident = secrets.token_hex(12)
    h.store.set_meta(CL_TRIED_META + ident, json.dumps(dict(out, by=s.get('id'))))
    return dict(out, id=ident)


# ---- the card ---------------------------------------------------------------------------------
def cl_node_state(store, n):
    try:
        got = json.loads(store.get_meta(CL_NODE_META + n) or '{}')
    except (ValueError, TypeError):
        got = {}
    return got if isinstance(got, dict) else {}


def cl_names(store):
    """The names the port is opened by: the VIP address's and each node's (as acme knows them)."""
    out = []

    def add(name, of):
        n = str(name or '').strip().lower().rstrip('.')
        if n and re.match(r'^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\Z', n) and \
                n not in [x['name'] for x in out]:
            out.append({'name': n, 'of': of})
    try:
        if vip_conf(store).get('on'):
            add(acme_name_of(store, 'vip'), 'vip')
    except Exception:                                   # noqa: BLE001
        pass
    for n in sorted(set([node_name()] + [x['name'] for x in ha_nodes(store)])):
        try:
            add(acme_name_of(store, n), n)
        except Exception:                               # noqa: BLE001
            pass
    return out


def cl_view(h, tried=''):
    store = h.store
    cas = cl_cas_row(store)
    sha = hashlib.sha256(cl_cas_pem(cas).encode('ascii')).hexdigest()[:12] if cas else ''
    parts = {}
    for part in CL_PARTS:
        parts[part] = {
            'on': cl_on(part), 'switch': bool(CONFIG.get(part + '_certlogin')),
            'auto': bool(CONFIG.get(part + '_certlogin_auto')),
            'usable': cl_usable(part, store), 'match': cl_match(part),
            'match_words': CL_MATCH_WORDS[cl_match(part)],
            'match_warn': '' if cl_match(part) == 'strong' else CL_MATCH_WARN,
            'crl': bool(CONFIG.get(part + '_certlogin_crl', 1)),
            'directory': krb_directory_name(part),
            'password_off': bool(CONFIG.get(part + '_password_off')),
            'only_in_effect': krb_password_off(part, store),
            'krb': krb_usable(part, store),
            'signin': sso_signin_modes(part, store),
            'second': bool(CONFIG.get('admin_2fa')) if part == 'admin' else portal_gate_needed()}
    parts['portal']['portal'] = bool(CONFIG.get('portal'))
    now = time.time()
    nodes, crls = [], {}
    for n in sorted(set([node_name()] + [x['name'] for x in ha_nodes(store)])):
        st = cl_node_state(store, n)
        if n == node_name() and CL_STATE['writer']:
            port = cl_port()
            listening = bool(cl_any_on() and cl_listening(port))
            st = dict(st, written=bool(CL_STATE['written']), error=CL_STATE['error'],
                      sha=str(CL_STATE['sha'] or '')[:12], crls=cl_crls_now(),
                      listening=listening, port=port, at=st.get('at') or now,
                      busy=cl_port_busy(port, served=listening and cl_web_served(port)))
        for c in st.get('crls') or []:
            if c.get('url') and (c['url'] not in crls or float(c.get('at') or 0) >
                                 float(crls[c['url']].get('at') or 0)):
                crls[c['url']] = dict(c, node=n)
        nodes.append({'node': n, 'me': n == node_name(),
                      'heard': bool(st) and now - float(st.get('at') or 0) < 900,
                      'at': st.get('at'), 'written': bool(st.get('written')),
                      'same': bool(cas and st.get('sha') and st.get('sha') == sha),
                      'listening': bool(st.get('listening')), 'port': st.get('port') or cl_port(),
                      'busy': st.get('busy') or '',
                      'error': st.get('error') or '', 'version': st.get('version') or ''})
    out = {'cas': [cl_ca_view(c) for c in cas], 'parts': parts, 'port': cl_port(),
           'nodes': nodes, 'crls': sorted(crls.values(), key=lambda c: c['url']),
           'names': cl_names(store), 'any_on': cl_any_on(),
           'access': {k: (access_conf(store).get(k) or {}) for k in ('admin', 'portal')},
           'own_cas': cl_own_authorities(store)}
    if tried:
        try:
            got = json.loads(store.get_meta(CL_TRIED_META + tried) or 'null')
        except (ValueError, TypeError):
            got = None
        if isinstance(got, dict) and got.get('by') == (h.me('readonly') or {}).get('id') and \
                now - float(got.get('at') or 0) < 600:
            got.pop('by', None)
            out['tried'] = got
    return out


def cl_own_authorities(store):
    """acme's own authorities (Certificates → Authorities) that may be trusted here too: [{id,
    name, subject}] - an issuing authority of the certificate manager's own, when a person's
    certificates are issued by it."""
    out = []
    try:
        for r in store.db.rows('SELECT id, name, cert_pem, disabled FROM cert_cas ORDER BY id'):
            if r.get('disabled') or '-----BEGIN CERTIFICATE-----' not in _cl_text(r.get('cert_pem')):
                continue
            out.append({'id': int(r['id']), 'name': str(r.get('name') or '')[:120]})
    except Exception:                                   # noqa: BLE001
        return []
    return out[:50]


def cl_own_pem(store, ident):
    try:
        r = store.db.row('SELECT cert_pem, chain_pem FROM cert_cas WHERE id = ?', (int(ident),))
    except Exception:                                   # noqa: BLE001
        r = None
    if not r or '-----BEGIN CERTIFICATE-----' not in _cl_text(r.get('cert_pem')):
        raise ApiError(404, 'there is no such authority of acme\'s own')
    return (_cl_text(r['cert_pem']).strip() + '\n' + _cl_text(r.get('chain_pem')).strip()).strip()


def _cl_text(v):
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).decode('ascii', 'replace')
    return str(v or '')


@route('GET', '/api/certlogin')
def _certlogin_view(h):
    h.me('readonly')
    tried = re.sub(r'[^0-9a-f]', '', str(h.arg('tried') or ''))[:24]
    return cl_view(h, tried)


@route('POST', '/api/certlogin')
def _certlogin_do(h):
    s = h.me('fulladmin')
    b = h.body()
    act = str(b.get('action') or '')
    if act in ('put', 'own'):
        if act == 'own':
            raw = cl_own_pem(h.store, b.get('id')).encode('ascii')
            name = 'acme\'s own authority %s' % int(b.get('id') or 0)
        else:
            data = str(b.get('data') or '')
            if data.startswith('data:'):
                data = data.split(',', 1)[-1]
            if len(data) > CL_CA_FILE_MOST * 4 // 3 + 8:
                raise ApiError(400, 'that file is too big to be authorities')
            try:
                raw = base64.b64decode(data, validate=True)
            except (binascii.Error, ValueError):
                raise ApiError(400, 'the file did not arrive whole')
            name = str(b.get('name') or '')
        try:
            added, _all = cl_cas_put(h.store, raw, s['name'], name, keep=s.get('id'))
        except ValueError as e:
            raise ApiError(400, str(e))
        msg = ('%d authorit%s put in - every node writes them out within seconds'
               % (len(added), 'y' if len(added) == 1 else 'ies')) if added else \
            'those authorities are put in already'
        return {'message': msg, 'added': added, 'view': cl_view(h)}
    if act == 'drop':
        try:
            gone = cl_cas_drop(h.store, b.get('sha256'), s['name'], keep=s.get('id'))
        except ValueError as e:
            raise ApiError(409, str(e))
        if not gone:
            raise ApiError(404, 'there is no such authority to take away')
        return {'message': 'the authority is taken away', 'gone': gone, 'view': cl_view(h)}
    raise ApiError(400, 'no such thing to do')


# ---- the firewall, and what root writes for nginx --------------------------------------------
@hook('firewall')
def cl_firewall(store, node):
    """The certificate's port, while either part is on: from the networks that may reach that
    part's pages (Who may reach the pages), or from everywhere when that part is for everybody."""
    if not cl_any_on():
        return []
    a = access_conf(store)
    srcs = []
    for part in CL_PARTS:
        if not cl_on(part):
            continue
        one = a.get(part) or {}
        if not a or one.get('any'):
            srcs = ['']
            break
        for n in one.get('from') or []:
            if n not in srcs:
                srcs.append(n)
    rules = []
    for s in srcs or ['']:
        for f in ((4, 6) if not s else (_fam(s),)):
            rules.append({'family': f, 'proto': 'tcp', 'port': str(cl_port()), 'source': s})
    return [{'key': 'certlogin', 'title': 'Signing in with a certificate',
             'why': 'nginx asks for a certificate on this port only (Settings → Accounts → '
                    'Signing in with a certificate) - from the networks that may reach the pages '
                    'of the parts switched on', 'rules': rules}]


def certlogin_desired(store):
    """What the root helper writes for nginx: {port, cas, admin, portal} while a part signs
    anybody in, {port: 0} once it was on and is no longer, None when never (nginx as it is)."""
    cas = cl_cas_row(store)
    on = {p: bool(cl_on(p) and cas) for p in CL_PARTS}
    try:
        served = bool(store.get_meta(CL_SERVED_META))
        if any(on.values()) and not served:
            # Remembered (a setting back at its default is no row at all): once served, the
            # port is taken away again when it is no longer.
            store.set_meta(CL_SERVED_META, '1')
    except Exception:                                   # noqa: BLE001
        served = True
    if any(on.values()):
        return dict(on, port=cl_port(), cas=cl_cas_pem(cas))
    return {'port': 0} if served else None
