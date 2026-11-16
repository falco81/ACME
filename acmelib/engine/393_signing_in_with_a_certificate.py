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
#   - Besides the CRL (1.0.105, as isemon 1.10.348): an OCSP responder, per part off (as before),
#     first, only or both - the certificate and every authority above it but the root, the
#     answer checked by openssl against the authorities put in only, kept ten minutes at most,
#     each node its own; and the CRL of a CDP object in the directory (ldap:///...CN=CDP,CN=Public
#     Key Services,...), read with the part's own directory connection, never the host in it.
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
CL_OID_AIA = '1.3.6.1.5.5.7.1.1'    # Authority Information Access
CL_OID_OCSP = '1.3.6.1.5.5.7.48.1'  # ...its OCSP responder
CL_OID_SKI = '2.5.29.14'            # Subject Key Identifier (of an authority)
CL_OID_AKI = '2.5.29.35'            # Authority Key Identifier: which key of its issuer signed it
CL_OID_CRLNUM = '2.5.29.20'         # CRL Number (of a CRL)
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
CL_CRLS_SAID = 24                   # CRLs on the card (each node's, the authorities' named)
# Names of clouds' metadata services, and their addresses that are not link-local (F5).
CL_CDP_NAMES_NO = ('metadata', 'metadata.google.internal', 'metadata.goog', 'instance-data',
                   'instance-data.ec2.internal', 'metadata.azure.com', 'metadata.oraclecloud.com')
CL_CDP_IPS_NO = ('169.254.169.254', '169.254.170.2', 'fd00:ec2::254', '100.100.100.200',
                 '168.63.129.16', '192.0.0.192')     # ...Azure's WireServer, Oracle's (1.0.106)
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
# OCSP (1.0.105, as isemon 1.10.348): the answers kept on this node - url|issuer|serial ->
# {status, this, next, ...} and the certificate and its issuer (PEM) for Ask again, never said
# anywhere. 200 at most; an answer used ten minutes at most (or until its next update), a
# responder that failed asked again after a minute, the last good answer kept until its next
# update while it does not answer.
CL_OCSP_CACHE = {}
CL_OCSP_LOCK = threading.Lock()
CL_OCSP_MOST = 1 << 20
CL_OCSP_KEPT = 200
CL_OCSP_MODES = ('off', 'first', 'only', 'both')
CL_OCSP_NO_NEXT_S = 900             # an answer with no next update: taken 15 minutes (1.0.106)
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
    # Which key it is, and which key of its issuer signed it (1.0.106): an authority renewed with
    # a new key keeps its name - its issuer is told by key, never by name alone.
    ski, aki = '', ''
    try:
        if CL_OID_SKI in exts:
            t, v, _ = _cl_der(exts[CL_OID_SKI][1])
            ski = v.hex() if t == 0x04 else ''
        if CL_OID_AKI in exts:
            aki = next((v.hex() for t, v in _cl_der_all(_cl_der(exts[CL_OID_AKI][1])[1])
                        if t == 0x80), '')
    except (ValueError, IndexError):
        ski, aki = '', ''
    ocsp = []
    if CL_OID_AIA in exts:
        # Authority Information Access: SEQUENCE OF {accessMethod, accessLocation} - the URIs of
        # its OCSP responders (1.0.105). One that cannot be read names none.
        try:
            for _t, one in _cl_der_all(_cl_der(exts[CL_OID_AIA][1])[1]):
                parts = _cl_der_all(one)
                if len(parts) == 2 and _cl_oid(parts[0][1]) == CL_OID_OCSP and \
                        parts[1][0] == 0x86:
                    ocsp.append(parts[1][1].decode('ascii', 'replace'))
        except (ValueError, IndexError):
            ocsp = []
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
            'ocsp': ocsp[:4], 'ski': ski, 'aki': aki, 'keyhash': cl_key_hash(items),
            'unknown_critical': sorted(k for k, (c, _v) in exts.items()
                                       if c and k not in CL_CRIT_KNOWN)}


def cl_key_hash(items):
    """SHA-1 of a certificate's public key (its subjectPublicKey's bits), as an OCSP request names
    the issuer by (issuerKeyHash) - of its TBSCertificate's items; '' when it cannot be read."""
    try:
        off = 1 if items and items[0][0] == 0xa0 else 0
        t, spki = items[off + 5]
        parts = _cl_der_all(spki) if t == 0x30 else []
        if len(parts) < 2 or parts[1][0] != 0x03 or not parts[1][1]:
            return ''
        return hashlib.sha1(parts[1][1][1:]).hexdigest()
    except (ValueError, IndexError):
        return ''


def cl_pem_key_hash(pem):
    """cl_key_hash of a certificate in PEM ('' when it cannot be read)."""
    try:
        _pem, der = cl_pem_one(pem)
        _t, cert, _ = _cl_der(der)
        _t, tbs, _ = _cl_der(cert)
        return cl_key_hash(_cl_der_all(tbs))
    except (CertRefused, ValueError):
        return ''


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
    if ip.version == 6:
        # An IPv4 address carried in an IPv6 one (1.0.106): 6to4 (2002::/16), Teredo (2001::/32 -
        # its server and its client) and NAT64 (64:ff9b::/96) - refused when the IPv4 one is.
        inner = [ip.sixtofour] if ip.sixtofour else []
        inner += list(ip.teredo) if ip.teredo else []
        if ip in ipaddress.ip_network('64:ff9b::/96'):
            # NAT64 by its IPv4 address alone (1.0.106): on an IPv6-only host with DNS64 every
            # CDP is reached so, and 64:ff9b::/96 is in ::/8 - each was refused as reserved.
            # (64:ff9b:1::/48, the local-use prefix, stays refused.)
            why = cl_addr_no(ipaddress.IPv4Address(int(ip) & 0xffffffff))
            return '%s, carried in an IPv6 address' % why if why else ''
        for v4 in inner:
            why = cl_addr_no(v4)
            if why:
                return '%s, carried in an IPv6 address' % why
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


def cl_http_get(url, body=None, ctype='', most=None):
    """The body at a CRL's http address: every address its name has looked up and checked
    (cl_addr_no - 2852039166 or 0251.0376.0251.0376 as the resolver reads them, a name that
    resolves to 169.254.169.254) and the connection made to the address checked, never looked up
    again; no redirect followed, CL_CRL_MOST at most, CL_CRL_FETCH_S for the whole of it.
    With a body, POSTed with its content type (an OCSP request, 1.0.105) - `most` its answer's
    limit. ValueError says why not."""
    most = most or CL_CRL_MOST
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
            heads = {
                'Host': ('[%s]' % host if ':' in host else host) + (':%d' % port if u.port else ''),
                'User-Agent': 'acme/%s' % __version__, 'Accept': '*/*', 'Connection': 'close'}
            if body is not None:
                heads['Content-Type'] = ctype or 'application/octet-stream'
            conn.request('POST' if body is not None else 'GET', path, body=body, headers=heads)
            r = conn.getresponse()
            if 300 <= r.status < 400:
                raise ValueError('it answers with a redirect (HTTP %d to %s) - not followed'
                                 % (r.status, str(r.getheader('Location') or '?')[:120]))
            if r.status != 200:
                raise ValueError('HTTP %d' % r.status)
            try:
                if int(r.getheader('Content-Length') or 0) > most:
                    raise ValueError(cl_too_big(most))
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
                if len(raw) > most:
                    raise ValueError(cl_too_big(most))
            return raw
        except (OSError, _hc.HTTPException) as e:
            last = e
        finally:
            conn.close()
    raise ValueError(('%s' % last)[:200] if last else 'it took longer than %d s' % CL_CRL_FETCH_S)


def cl_too_big(most):
    return 'larger than %d MB' % (most >> 20) if most >= 1 << 20 else \
        'larger than %d kB' % max(1, most >> 10) if most >= 1024 else 'larger than %d B' % most


# ---- a CRL Distribution Point in the directory (1.0.105, as isemon 1.10.348) -------------------
def cl_ldap_cdp(url):
    """(DN, attribute) of a CRL Distribution Point in the directory as AD CS writes it
    (ldap:///CN=<CA>,CN=<server>,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,
    DC=...?certificateRevocationList?base?objectClass=cRLDistributionPoint) - or None. Only a CDP
    object under the configuration's Public Key Services, base scope, and only its
    certificateRevocationList or deltaRevocationList (";binary" allowed): the address is text in
    a certificate. The host in it, if any, is never used."""
    u = str(url or '')
    if not u.lower().startswith('ldap://'):
        return None
    rest = u[7:]
    if '/' not in rest:
        return None
    rest = rest.split('/', 1)[1]
    parts = rest.split('?')
    dn = urllib.parse.unquote(parts[0]).strip()
    attr = (parts[1] if len(parts) > 1 else '').strip() or 'certificateRevocationList'
    scope = (parts[2] if len(parts) > 2 else '').strip().lower()
    base_attr = attr.split(';', 1)[0].lower()
    if base_attr not in ('certificaterevocationlist', 'deltarevocationlist'):
        return None
    if scope not in ('', 'base') or not dn or len(dn) > 600 or re.search(r'[\x00-\x1f]', dn):
        return None
    # ...CN=Configuration followed by the forest's DC= components alone, to the end (1.0.106):
    # "...,CN=Configuration,DC=x,OU=elsewhere" is somewhere else of the directory.
    if not re.search(r'(?i),\s*CN=CDP\s*,\s*CN=Public Key Services\s*,\s*CN=Services\s*,\s*'
                     r'CN=Configuration(?:\s*,\s*DC\s*=\s*[^,=+\\"<>;#\s][^,=+\\"<>;]*)+\Z',
                     dn.rstrip()):
        return None
    return dn, ('certificateRevocationList' if base_attr == 'certificaterevocationlist'
                else 'deltaRevocationList')


def cl_ldap_name(url):
    """The authority's name of an LDAP CDP (its first CN), for the card - '' for none."""
    got = cl_ldap_cdp(url)
    m = re.match(r'(?i)\s*CN\s*=\s*((?:\\.|[^,\\])+)', got[0]) if got else None
    return re.sub(r'\\(.)', r'\1', m.group(1)).strip()[:120] if m else ''


def cl_crl_urls(named, ldap=None):
    """The addresses of a CRL tried in turn: up to three http ones (cl_cdp_ok), then the
    directory's - one, while reading CRLs from the directory is on (`ldap` its reader)."""
    named = list(named or [])
    http = [u for u in named if u.lower().startswith('http://') and cl_cdp_ok(u)][:3]
    dirs = [u for u in named if ldap and cl_ldap_cdp(u)][:1]
    return http + dirs


def cl_ldap_reader(ad, store):
    """A function(url) -> the CRL (DER) of a CDP object, read with the directory `ad`'s own
    connection (its reading account) - never the host in the address; None without one, or
    with its row not as acme wrote it."""
    if ad is None:
        return None
    try:
        if not dbguard_directory_ok(store.db, ad.name):
            return None
    except Exception:                                   # noqa: BLE001
        return None

    def read(url):
        got = cl_ldap_cdp(url)
        if not got:
            raise ValueError('not a CDP object of the directory')
        dn, attr = got
        try:
            found = ad.asked(lambda link: link.search(
                dn, ldap_equal('objectClass', 'cRLDistributionPoint'), (attr,), scope=0,
                limit=1))
        except LdapError as e:
            raise ValueError('the directory %s said: %s' % (ad.name, str(e)[:160]))
        if not found:
            raise ValueError('the directory %s has no such CDP object' % ad.name)
        for k, v in (found[0].get('attrs') or {}).items():
            if k.split(';', 1)[0].lower() == attr.lower() and v and v[0]:
                try:
                    raw = bytes.fromhex(v[0])
                except ValueError:
                    raise ValueError('the directory sent a %s that does not read' % attr)
                if len(raw) > CL_CRL_MOST:
                    raise ValueError(cl_too_big(CL_CRL_MOST))
                return raw
        raise ValueError('the CDP object holds no %s' % attr)
    read.directory = ad.name
    return read


def cl_ldap_on(part):
    return bool(CONFIG.get(part + '_certlogin_crl_ldap'))


def cl_ldap_for(d, store, part):
    """The reader of a part's CRLs in the directory (cl_ldap_reader), or None while it is off:
    the administration's with the directory administrators sign in against, the portal's with
    the portal's own (portal_directory, else the administrators')."""
    if not cl_ldap_on(part):
        return None
    name = krb_directory_name(part)
    dirs = getattr(d, 'dirs', None) or {}
    return cl_ldap_reader(dirs.get(name.lower()) if name else None, store)


def cl_ldap_any(d, store):
    """The reader for Fetch now of a CRL in the directory on this node: the administration's
    when it reads them, else the portal's."""
    for part in CL_PARTS:
        got = cl_ldap_for(d, store, part)
        if got:
            return got
    return None


def _cl_der_count(b):
    """How many elements a DER SEQUENCE OF holds (its body): the revoked entries of a CRL."""
    n, i = 0, 0
    while i < len(b):
        _t, _v, i = _cl_der(b, i)
        n += 1
    return n


def _cl_der_int(v):
    """An INTEGER's value (its body)."""
    if not v or len(v) > 40:
        raise ValueError('not a number of a CRL')
    return int.from_bytes(v, 'big', signed=True)


def cl_crl_info(pem):
    """Of a CRL (PEM): its next update (seconds, or None), the Freshest CRL it names (where its
    delta is), whether it is a delta CRL itself; for the card (1.0.104) its issuer, number, this
    update and how many certificates it lists as revoked."""
    out = {'next': None, 'freshest': [], 'delta': False, 'issuer': '', 'number': '',
           'this': None, 'revoked': None, 'num': None, 'base': None}
    m = re.search(r'-----BEGIN X509 CRL-----([A-Za-z0-9+/=\s]+)-----END X509 CRL-----', pem)
    try:
        der = base64.b64decode(re.sub(r'\s+', '', m.group(1))) if m else b''
        _t, body, _ = _cl_der(der)
        _t, tbs, _ = _cl_der(body)
        items = _cl_der_all(tbs)
        times = [i for i, (t, _v) in enumerate(items) if t in (0x17, 0x18)]
        if times:
            after = times[-1] + 1
            out['revoked'] = _cl_der_count(items[after][1]) \
                if after < len(items) and items[after][0] == 0x30 else 0
        for t, v in items:
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
                    # ...and the number of the base CRL it is a delta of (1.0.106)
                    out['base'] = _cl_der_int(_cl_der(parts[-1][1])[1])
                elif oid == CL_OID_CRLNUM:
                    out['num'] = _cl_der_int(_cl_der(parts[-1][1])[1])
    except (ValueError, IndexError, binascii.Error, AttributeError):
        pass
    try:
        nu = _cl_openssl(['crl', '-noout', '-issuer', '-crlnumber', '-lastupdate', '-nextupdate',
                          '-nameopt', 'RFC2253'], pem.encode(), what='the CRL') \
            .decode('utf-8', 'replace')
        m = re.search(r'nextUpdate=(.+)', nu)
        if m and 'NONE' not in m.group(1):
            out['next'] = cl_time(m.group(1)) or None
        m = re.search(r'lastUpdate=(.+)', nu)
        if m:
            out['this'] = cl_time(m.group(1)) or None
        m = re.search(r'(?m)^issuer=\s*(.*)$', nu)
        out['issuer'] = m.group(1).strip()[:300] if m else ''
        m = re.search(r'crlNumber=(\S+)', nu)
        out['number'] = m.group(1)[:80] if m and 'NONE' not in m.group(1) else ''
    except ValueError:
        pass
    return out


def cl_crl_sig(pem):
    """Whether a CRL's signature is good by the authorities put in, as openssl crl -CAfile says
    it (1.0.104, for the card): 'ok', 'bad', 'unknown' (its authority is not among them) or ''
    (no authority written out on this node). Only said - openssl verify checks it again at every
    sign-in, and a CRL it does not take signs nobody in."""
    ca = cl_ca_path()
    if not ca.exists():
        return ''
    try:
        r = subprocess.run(['openssl', 'crl', '-noout', '-CAfile', str(ca), '-no-CApath',
                            '-no-CAstore'], input=pem.encode(), capture_output=True, timeout=30,
                           env=dict(os.environ, SSL_CERT_DIR='/nonexistent',
                                    SSL_CERT_FILE='/nonexistent'))
    except (OSError, subprocess.SubprocessError):
        return ''
    words = (r.stdout or b'').decode('utf-8', 'replace') + (r.stderr or b'').decode('utf-8', 'replace')
    if 'verify OK' in words:
        return 'ok'
    if 'verify fail' in words:
        return 'bad'
    return 'unknown'


CL_CRL_URL_LOCKS = {}
CL_CRL_RETRY_S = 60                 # an address that failed: not fetched again sooner (1.0.106)


def cl_crl_fetch(url, force=False, ldap=None):
    """cl_crl_fetch_one, one fetch of an address at a time on this node (1.0.106): sign-ins
    together waited each on a fetch of its own of the same CRL - the second one now takes what the
    first one got (or failed with)."""
    with CL_CRL_LOCK:
        lock = CL_CRL_URL_LOCKS.get(url)
        if lock is None:
            if len(CL_CRL_URL_LOCKS) > 200:
                for u in [u for u, k in CL_CRL_URL_LOCKS.items() if not k.locked()]:
                    CL_CRL_URL_LOCKS.pop(u, None)
            lock = CL_CRL_URL_LOCKS[url] = threading.Lock()
    if not lock.acquire(timeout=CL_CRL_FETCH_S * 3):
        raise CertRefused('the CRL at %s is being fetched and that takes too long - nobody signs '
                          'in while the certificate cannot be checked for revocation' % url,
                          'unavailable')
    try:
        return cl_crl_fetch_one(url, force=force, ldap=ldap)
    finally:
        lock.release()


def cl_crl_fetch_one(url, force=False, ldap=None):
    """The CRL at url as PEM: fetched again after CL_CRL_FRESH_S (ten minutes) at most - sooner
    at its next update; while the address does not answer, the last good one until its next update,
    then nothing. CertRefused ('unavailable') when there is none to be had - a CRL already past
    its next update is none (a delta CRL past it openssl would leave out without a word).
    `force` (Fetch now, 1.0.104): fetched whatever is kept - failing, the same as ever: the last
    good one until its next update, else none."""
    now = time.time()
    with CL_CRL_LOCK:
        got = CL_CRL_CACHE.get(url)
    good = bool(got and got.get('pem') and now < got['next'])
    if good and not force and (now - got['at'] < CL_CRL_FRESH_S or
                               now - float(got.get('tried') or 0) < CL_CRL_RETRY_S):
        return got
    if got and not good and not force and now - float(got.get('tried') or 0) < CL_CRL_RETRY_S:
        # Failed less than a minute ago (1.0.106): not fetched again at every sign-in.
        raise CertRefused('the CRL at %s could not be had (%s) - nobody signs in while the '
                          'certificate cannot be checked for revocation'
                          % (url, got.get('err') or 'no answer'), 'unavailable')
    via = 'ldap' if url.lower().startswith('ldap://') else 'http'
    try:
        if via == 'ldap':
            # The directory's CDP object (1.0.105), with the directory's own connection.
            if not ldap:
                raise ValueError('reading CRLs from the directory is off')
            raw = ldap(url)
        else:
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
               'freshest': info['freshest'], 'delta': info['delta'], 'issuer': info['issuer'],
               'number': info['number'], 'this': info['this'], 'revoked': info['revoked'],
               'size': len(raw), 'sig': cl_crl_sig(pem), 'num': info['num'],
               'base': info['base']}
        if via == 'ldap':
            one['via'] = 'ldap'
        with CL_CRL_LOCK:
            if len(CL_CRL_CACHE) > 50:
                CL_CRL_CACHE.clear()
            CL_CRL_CACHE[url] = one
        return one
    except Exception as e:                              # noqa: BLE001
        why = str(e)[:200] or e.__class__.__name__
        if good:
            kept = dict(got, err=why, tried=now, err_at=now)    # the last good one, said why
            with CL_CRL_LOCK:
                CL_CRL_CACHE[url] = kept
            return kept
        with CL_CRL_LOCK:
            CL_CRL_CACHE[url] = dict({'at': now, 'pem': '', 'next': 0, 'url': url, 'err': why,
                                      'err_at': now, 'tried': now},
                                     **({'via': 'ldap'} if via == 'ldap' else {}))
        raise CertRefused('the CRL at %s could not be had (%s) - nobody signs in while the '
                          'certificate cannot be checked for revocation' % (url, why), 'unavailable')


def _cl_crl_any(urls, ldap=None):
    last = None
    for u in urls[:4]:
        try:
            return cl_crl_fetch(u, ldap=ldap)
        except CertRefused as e:
            last = e
    raise last


def cl_crls_of(c, what, ldap=None):
    """The CRL of one certificate (a person's, or an authority's above it), and its delta CRL
    when it or the CRL names one (Freshest CRL): [PEM], and whether a delta is among them.
    CertRefused - no CRL, no sign-in; a delta named and not to be had neither (review F3).
    `ldap` (1.0.105): the reader of the directory's CDP objects, tried after up to three http
    addresses - None while reading CRLs from the directory is off (as before)."""
    named = list(c.get('cdp') or [])
    urls = [u for u in named if u.lower().startswith('http://')]
    if ldap and cl_crl_urls(named, ldap):
        urls = cl_crl_urls(named, ldap)
        base = _cl_crl_any(urls, ldap)
        return cl_deltas_of(c, what, base, ldap)
    if not urls:
        raise CertRefused('%s names no CRL over http (CRL Distribution Points) - it cannot be '
                          'checked for revocation' % what)
    urls = [u for u in urls if cl_cdp_ok(u)]
    if not urls:
        raise CertRefused('the CRL Distribution Point of %s is not an address acme fetches from '
                          '(http; no loopback, link-local or metadata address)' % what)
    base = _cl_crl_any(urls[:3])
    return cl_deltas_of(c, what, base, ldap)


def cl_deltas_of(c, what, base, ldap=None):
    """[the base CRL, its delta when one is named], whether a delta is among them."""
    out = [base['pem']]
    named = list(dict.fromkeys(list(c.get('freshest') or []) + list(base.get('freshest') or [])))
    if not named:
        return out, False
    urls = cl_crl_urls(named, ldap)
    if not urls:
        raise CertRefused('the delta CRL (Freshest CRL) of %s is at no address acme fetches '
                          'from (http; no loopback, link-local or metadata address) - its '
                          'revocations of the last days cannot be seen' % what, 'unavailable')
    delta = _cl_crl_any(urls, ldap)
    # A delta of a base newer than the one held (1.0.106): openssl leaves it out without a word
    # (-use_deltas), and what it lists as revoked signs in. The base fetched again; still older,
    # nobody signs in.
    want = delta.get('base')
    if delta.get('delta') and want is not None:
        held = base.get('num')
        if (held is None or held < want) and base.get('url'):
            try:
                base = cl_crl_fetch(base['url'], force=True, ldap=ldap)
            except CertRefused:
                pass
            held = base.get('num')
            out[0] = base['pem']
        if held is None or held < want:
            raise CertRefused('the delta CRL of %s is of the base CRL number %d, and the base CRL '
                              'to be had is %s - its revocations cannot be seen'
                              % (what, want, 'number %d' % held if held is not None else
                                 'of no number'), 'unavailable')
        if delta.get('issuer') and base.get('issuer') and delta['issuer'] != base['issuer']:
            raise CertRefused('the delta CRL of %s is of another authority (%s) than its base CRL '
                              '(%s)' % (what, delta['issuer'], base['issuer']), 'unavailable')
    out.append(delta['pem'])
    return out, True


def _cl_verify(ca_file, leaf, crl_file=None, deltas=False, every=True):
    """openssl verify against the authorities put in and nothing else - never the system's own
    store (-CAfile alone still reads the default folder of roots): CertRefused, or None. With
    CRLs: every certificate of the chain checked (-crl_check_all: an issuing authority its root
    revoked too; the root itself, its own anchor, is not), deltas applied (-use_deltas).
    every=False (1.0.105, OCSP not off): that certificate alone against its CRL (-crl_check) -
    the others of the chain were asked of a responder, or are checked on their own."""
    args = ['openssl', 'verify', '-no-CApath', '-no-CAstore', '-CAfile', str(ca_file)]
    if crl_file:
        args += ['-crl_check_all' if every else '-crl_check', '-CRLfile', crl_file] + \
            (['-use_deltas'] if deltas else [])
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


CL_SIGNED_BY = {}


def cl_signed_by(c, p):
    """Whether the authority p's key signed the certificate c - openssl verify with p alone as
    its anchor (-partial_chain; its dates not looked at: only which key signed it). Kept."""
    k = (c.get('sha256'), p.get('sha256'))
    if k in CL_SIGNED_BY:
        return CL_SIGNED_BY[k]
    with tempfile.TemporaryDirectory(prefix='acme-cert-') as work:
        cp, pp = os.path.join(work, 'c.pem'), os.path.join(work, 'p.pem')
        with open(cp, 'w') as fh:
            fh.write(c['pem'])
        with open(pp, 'w') as fh:
            fh.write(p['pem'])
        try:
            got = subprocess.run(['openssl', 'verify', '-no-CApath', '-no-CAstore',
                                  '-partial_chain', '-no_check_time', '-CAfile', pp, cp],
                                 capture_output=True,
                                 text=True, timeout=30,
                                 env=dict(os.environ, SSL_CERT_DIR='/nonexistent',
                                          SSL_CERT_FILE='/nonexistent'))
            yes = got.returncode == 0 and bool(re.search(r':\s*OK\s*$', got.stdout or ''))
        except (OSError, subprocess.SubprocessError):
            return False
    if len(CL_SIGNED_BY) > 500:
        CL_SIGNED_BY.clear()
    CL_SIGNED_BY[k] = yes
    return yes


def cl_issuer_of(c, cas):
    """The authority among those put in whose key signed c (1.0.106) - or None. By name, and of
    those of its name the one whose Subject Key Identifier is c's Authority Key Identifier; two
    of a name (an authority renewed with a new key - AD CS keeps its name), the one whose key
    verifies c's signature. Never the first of a name: an OCSP request with the old key's hash
    is asked of another certificate, and the answer "good". Of those that verify (an authority
    renewed with the same key - two of a name and key, the old one expired), the one whose dates
    hold now, then the one that ends last: the expired one only when no other verifies (its
    signature is checked with no regard to dates, and the chain checked with it said expired)."""
    named = [p for p in cas if p['subject'] == c.get('issuer') and p['sha256'] != c.get('sha256')]
    if c.get('subject') == c.get('issuer') and not named:
        return None
    aki = c.get('aki') or ''
    if aki:
        cands = [p for p in named if p.get('ski') == aki] or \
            [p for p in named if not p.get('ski')]
    else:
        cands = list(named)
    if len(named) == 1 and cands == named:
        # one of that name, its key the one named (or none named): openssl built the chain with it
        return named[0]
    good = [p for p in cands if cl_signed_by(c, p)]
    if not good:
        return None
    now = time.time()

    def rank(p):
        nb, na = float(p.get('not_before_t') or 0), float(p.get('not_after_t') or 0)
        return (bool(na) and nb <= now <= na, na)
    return max(good, key=rank)          # the first of the best, as they were put in


def cl_chain(f, cas):
    """The authorities above a certificate among those put in, the nearest first - each the one
    whose key signed the one below it (cl_issuer_of, 1.0.106: an authority of the same name and
    another key - the old certificate of one renewed - is not in its chain; of one renewed with
    the same key, the one valid now); a root ends it."""
    out, cur, seen = [], f, {f.get('sha256')}
    for _ in range(8):
        if cur.get('subject') == cur.get('issuer') and cur is not f:
            break
        p = cl_issuer_of(cur, cas)
        if p is None or p['sha256'] in seen:
            break
        seen.add(p['sha256'])
        out.append(p)
        cur = p
    return out


# ---- OCSP (1.0.105, as isemon 1.10.348) ---------------------------------------------------------
def cl_ocsp_key(url, f, issuer_pem=''):
    """url|the issuer's key hash|serial (1.0.106: its key, not its name - two authorities of a
    name, one renewed with a new key, each with its own answers)."""
    ikh = cl_pem_key_hash(issuer_pem) if issuer_pem else ''
    return '%s|%s|%s' % (url, ikh or f.get('issuer') or '', (f.get('serial') or '').upper())


def _cl_ocsp_args(args, env):
    try:
        got = subprocess.run(args, capture_output=True, text=True, timeout=30, env=env)
        if got.returncode and re.search(r'(?i)unknown option|unrecognized', got.stderr or '') \
                and '-no-CAstore' in args:
            args = [a for a in args if a != '-no-CAstore']          # OpenSSL 1.1.1
            got = subprocess.run(args, capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        raise ValueError('openssl did not run: %s' % e)
    return got


def cl_ocsp_ask(url, f, pem, issuer_pem, ca_file, force=False):
    """The responder at url asked about one certificate (asked only of one whose chain is good):
    {status: good | revoked | unknown, this, next, at, revoked_at, reason, responder, ...}.
    The request has no nonce (Windows asks without one, AD CS answers without one); the answer is
    checked by openssl against the authorities put in and nothing else (-CAfile, -no-CApath,
    -no-CAstore, the system's folders pointed nowhere) - signed by the authority, or by a
    responder certificate it issued for OCSP Signing. Kept ten minutes at most (or until its next
    update); a responder that failed is asked again after a minute; while it does not answer, the
    last good answer until its next update. CertRefused ('unavailable') when there is no answer
    to be had - a forged or out-of-date one is none. `force` (Ask again): asked whatever is kept."""
    key = cl_ocsp_key(url, f, issuer_pem)
    now = time.time()
    with CL_OCSP_LOCK:
        got = CL_OCSP_CACHE.get(key)
    usable = bool(got and got.get('status') and (
        now < got['next'] if got.get('next') else
        now - float(got.get('this') or 0) < CL_OCSP_NO_NEXT_S))
    if usable and not force and (now - got['at'] < CL_CRL_FRESH_S or
                                 now - float(got.get('tried') or 0) < 60):
        return got
    if not usable and got and not force and not got.get('status') and \
            now - float(got.get('tried') or 0) < 60:
        # Failed less than a minute ago: not asked again at every sign-in.
        raise CertRefused('the OCSP responder at %s gave no answer (%s)'
                          % (url, got.get('err') or 'no answer'), 'unavailable')
    env = dict(os.environ, SSL_CERT_DIR='/nonexistent', SSL_CERT_FILE='/nonexistent')
    base = {'url': url, 'key': key, 'subject': f.get('subject') or '',
            'serial': (f.get('serial') or '').upper(), 'issuer': f.get('issuer') or '',
            '_pem': pem, '_ipem': issuer_pem, '_ca': str(ca_file)}
    try:
        if not cl_cdp_ok(url):
            raise ValueError('not an address acme asks (http; no loopback, link-local or '
                             'metadata address)')
        with tempfile.TemporaryDirectory(prefix='acme-ocsp-') as work:
            cp, ip = os.path.join(work, 'cert.pem'), os.path.join(work, 'issuer.pem')
            rq, rs = os.path.join(work, 'req.der'), os.path.join(work, 'resp.der')
            with open(cp, 'w') as fh:
                fh.write(pem.strip() + '\n')
            with open(ip, 'w') as fh:
                fh.write(issuer_pem.strip() + '\n')
            made = _cl_ocsp_args(['openssl', 'ocsp', '-issuer', ip, '-cert', cp, '-no_nonce',
                                  '-reqout', rq], env)
            if made.returncode or not os.path.exists(rq):
                raise ValueError('the request could not be made: %s'
                                 % (made.stderr or '').strip()[-200:])
            with open(rq, 'rb') as fh:
                body = fh.read()
            raw = cl_http_get(url, body=body, ctype='application/ocsp-request',
                              most=CL_OCSP_MOST)
            with open(rs, 'wb') as fh:
                fh.write(raw)
            # The answer checked (1.0.106): WITHOUT -resp_text - its text is the responder's
            # to write (a responder named "Response verify OK" was taken by a word search of
            # it). openssl's own lines only: its return code, "Response verify OK" a line of
            # its errors' output alone, and the status of this certificate's file alone.
            said = _cl_ocsp_args(['openssl', 'ocsp', '-respin', rs, '-issuer', ip, '-cert', cp,
                                  '-CAfile', str(ca_file), '-no-CApath', '-no-CAstore'], env)
            out, err = said.stdout or '', said.stderr or ''
            m = re.search(r'(?m)^Responder Error:\s*(\w+)', out)
            if m:
                raise ValueError('the responder said: %s' % m.group(1))
            verified = said.returncode == 0 and \
                'Response verify OK' in [x.strip() for x in err.splitlines()] and \
                not re.search(r'(?i)Response Verify Failure|Verify error', err)
            if not verified:
                why = re.search(r'(?m)Verify error:\s*([^\n]+)$', err) or \
                    re.search(r'OCSP routines:([^:\n]+)', err)
                raise ValueError('the answer\'s signature is not good by the authorities put in '
                                 '(%s)' % (why.group(1) if why else
                                           'openssl said no').strip()[:120])
            # Only now read: who answered (its text, for the card - never a check).
            told = _cl_ocsp_args(['openssl', 'ocsp', '-respin', rs, '-noverify', '-resp_text'],
                                 env)
        # openssl says it after the certificate's file (1.0.106: "<file>: WARNING: Status times
        # invalid." - a line's start alone never matched, and it was "says nothing of this
        # certificate")
        if re.search(r'(?mi)^(?:%s: )?WARNING: Status times invalid' % re.escape(cp), out):
            raise ValueError('the answer is out of date (its next update has passed, or its '
                             'this update is ahead)')
        lines = out.splitlines()
        at = next((i for i, x in enumerate(lines)
                   if re.match(r'^%s: (good|revoked|unknown)$' % re.escape(cp), x.rstrip())), None)
        if at is None:
            raise ValueError('the answer says nothing of this certificate')
        status = lines[at].rstrip().rsplit(': ', 1)[1]
        mine = []
        for x in lines[at + 1:]:
            if not x.startswith('\t'):
                break
            mine.append(x)

        def when(label):
            mm = next((re.match(r'^\t%s: (.+)$' % label, x) for x in mine
                       if re.match(r'^\t%s: ' % label, x)), None)
            return (cl_time(mm.group(1)) or None) if mm else None
        this, nxt = when('This Update'), when('Next Update')
        if not this:
            raise ValueError('the answer has no this update')
        if nxt and nxt <= this:
            raise ValueError('the answer\'s next update is not after its this update')
        if not nxt and now - this > CL_OCSP_NO_NEXT_S:
            # No next update, and made long ago (1.0.106): a good answer of a year ago replayed
            # on the plain http path - taken only while it is fresh.
            made = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(this))
            raise ValueError('the answer has no next update and was made %s - more than %d '
                             'minutes ago' % (made, CL_OCSP_NO_NEXT_S // 60))
        rid = re.search(r'(?m)^\s*Responder Id:\s*(.+)$', told.stdout or '')
        reason = next((re.match(r'^\tReason: (.+)$', x) for x in mine
                       if x.startswith('\tReason: ')), None)
        one = dict(base, status=status, at=now, tried=0, err='', err_at=None,
                   this=this, next=nxt, revoked_at=when('Revocation Time'),
                   reason=reason.group(1).strip()[:60] if reason else '',
                   responder=re.sub(r'\s*=\s*', '=', rid.group(1).strip())[:200] if rid else '',
                   size=len(raw))
        with CL_OCSP_LOCK:
            if len(CL_OCSP_CACHE) >= CL_OCSP_KEPT and key not in CL_OCSP_CACHE:
                CL_OCSP_CACHE.clear()
            CL_OCSP_CACHE[key] = one
        return one
    except Exception as e:                              # noqa: BLE001
        why = str(e)[:200] or e.__class__.__name__
        if usable and got.get('next'):
            kept = dict(got, err=why, tried=now, err_at=now)    # the last good one, said why
            with CL_OCSP_LOCK:
                CL_OCSP_CACHE[key] = kept
            return kept
        with CL_OCSP_LOCK:
            if len(CL_OCSP_CACHE) >= CL_OCSP_KEPT and key not in CL_OCSP_CACHE:
                CL_OCSP_CACHE.clear()
            CL_OCSP_CACHE[key] = dict(base, status='', at=now, this=None, next=None, err=why,
                                      err_at=now, tried=now)
        raise CertRefused('the OCSP responder at %s gave no answer (%s)' % (url, why),
                          'unavailable')


CL_OCSP_SAID = ('key', 'url', 'subject', 'serial', 'issuer', 'status', 'at', 'this', 'next',
                'err', 'err_at', 'revoked_at', 'reason', 'responder', 'size')


def cl_ocsp_now():
    """The OCSP answers kept on this node, as the card shows them: facts and dates only, never a
    certificate (the meta row stays small) - CL_CRLS_SAID * 2 at most."""
    with CL_OCSP_LOCK:
        got = list(CL_OCSP_CACHE.values())
    out = []
    for c in sorted(got, key=lambda c: (c['url'], c.get('subject') or ''))[:CL_CRLS_SAID * 2]:
        out.append({k: c.get(k) for k in CL_OCSP_SAID})
    return out


def cl_revocation(f, leaf, ca_file, work, crl=True, ocsp='off', ocsp_url='', ldap=None):
    """Whether a certificate whose chain is good is revoked - by its CRL, by OCSP, or by both, as
    set (1.0.105, isemon 1.10.348's cl_revocation):
      off   the CRLs as before (-crl_check_all once, the chain's CRLs together);
      first OCSP; a responder that does not answer (or none named) - its CRL instead;
      only  OCSP; no answer (or none named), no sign-in;
      both  OCSP and the CRL, both must say good.
    The certificate and every authority above it but the root, each asked of its own issuer.
    [how each was checked: 'ocsp' | 'crl'], or CertRefused."""
    cas = cl_ca_facts(ca_file)
    chain = cl_chain(f, cas)
    if ocsp not in ('first', 'only', 'both'):
        if not crl:
            return []
        pems, deltas = cl_crls_of(f, 'the certificate', ldap)
        # ...and every authority's above it but the root's (F4): an issuing authority its
        # root revoked signs nobody in.
        for c in chain:
            if c['subject'] != c['issuer']:
                more, d = cl_crls_of(c, 'the authority %s' % c['subject'], ldap)
                pems += more
                deltas = deltas or d
        cp = os.path.join(work, 'crl.pem')
        with open(cp, 'w') as fh:
            fh.write(''.join(p if p.endswith('\n') else p + '\n' for p in pems))
        _cl_verify(ca_file, leaf, cp, deltas)
        return ['crl']
    items = [(f, f['pem'], leaf, 'the certificate', True)]
    for i, c in enumerate(x for x in chain if x['subject'] != x['issuer']):
        path = os.path.join(work, 'ca%d.pem' % i)
        with open(path, 'w') as fh:
            fh.write(c['pem'])
        items.append((c, c['pem'], path, 'the authority %s' % c['subject'], False))
    how = []
    for n, (c, cpem, path, what, is_leaf) in enumerate(items):
        # Its issuer by key (1.0.106): the authority whose key signed it, never the first of
        # its name - the OCSP request names the issuer by its key's hash.
        parent = cl_issuer_of(c, cas)
        urls = [ocsp_url] if ocsp_url else \
            [u for u in c.get('ocsp') or [] if u.lower().startswith('http://')][:2]
        by_crl = ocsp == 'both'
        if not urls or parent is None:
            if ocsp == 'only':
                raise CertRefused('%s names no OCSP responder (Authority Information Access) and '
                                  'none is set - with OCSP only it cannot be checked' % what,
                                  'unavailable')
            by_crl = True
        else:
            answer, last = None, None
            for u in urls:
                try:
                    answer = cl_ocsp_ask(u, c, cpem, parent['pem'], ca_file)
                    break
                except CertRefused as e:
                    last = e
            if answer is None:
                if ocsp in ('only', 'both') or not crl:
                    raise last
                by_crl = True
            elif answer['status'] == 'revoked':
                raise CertRefused('%s is revoked, the OCSP responder says (%s%s)' % (
                    what, answer.get('reason') or 'no reason given',
                    time.strftime(', %Y-%m-%d %H:%M UTC', time.gmtime(answer['revoked_at']))
                    if answer.get('revoked_at') else ''), 'revoked' if is_leaf else 'certificate')
            elif answer['status'] != 'good':
                raise CertRefused('the OCSP responder does not know %s (unknown) - it is not one '
                                  'its authority issued' % what)
            else:
                how.append('ocsp')
        if by_crl:
            if not crl and ocsp == 'first':
                raise CertRefused('%s cannot be checked: no OCSP answer, and CRLs are off' % what,
                                  'unavailable')
            if crl or ocsp == 'both':
                pems, deltas = cl_crls_of(c, what, ldap)
                cp = os.path.join(work, 'crl%d.pem' % n)
                with open(cp, 'w') as fh:
                    fh.write(''.join(p if p.endswith('\n') else p + '\n' for p in pems))
                try:
                    _cl_verify(ca_file, path, cp, deltas, every=False)
                except CertRefused as e:
                    if is_leaf or e.kind not in ('revoked', 'expired'):
                        raise
                    # A revoked authority: the certificate is not taken (as -crl_check_all
                    # says it), never "revoked" of the person's own.
                    raise CertRefused('%s (an authority above it)' % e.why, 'certificate')
                how.append('crl')
    return how


def cl_check(pem, ca_file, crl=True, ocsp='off', ocsp_url='', ldap=None):
    """The facts of a client certificate that passed every check of its own, or CertRefused.
    The person is looked for after it (cl_admin_would, cl_portal_would). Revocation (1.0.105):
    `ocsp` off (the CRLs as ever), first, only or both; `ocsp_url` a responder for all; `ldap`
    the reader of CRLs in the directory (None: http only)."""
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
        # Revoked? (a CDP, a responder, is asked only now: for a chain of the authorities put in)
        f['revocation'] = cl_revocation(f, leaf, ca_file, work, crl=crl, ocsp=ocsp,
                                        ocsp_url=ocsp_url, ldap=ldap)
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
        cl_card_sweep(d.store, now)                     # the card watched (1.0.113)
    except Exception as e:                              # noqa: BLE001
        log_sparing('cl-card-sweep', 'the watched sign-ins: %s' % e, 'warn', every=300)
    try:
        cl_write_out(d.store)
    except Exception as e:                              # noqa: BLE001
        CL_STATE.update(written=False, error=str(e)[:300])
    if cl_say(d.store):
        for r in d.store.db.rows("SELECT k, v FROM meta WHERE k LIKE ?", (CL_TRIED_META + '%',)):
            try:
                if now - float(json.loads(r['v'] or '{}').get('at') or 0) > 600:
                    d.store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))
            except (ValueError, TypeError, AttributeError):
                d.store.db.run('DELETE FROM meta WHERE k = ?', (r['k'],))


def cl_say(store, now_too=False):
    """This node's state for the card (CL_NODE_META + node), written when it changed or every
    five minutes - at once after Fetch now or Clear (now_too). Whether it was written."""
    now = time.time()
    port = cl_port()
    listening = bool(cl_any_on() and cl_listening(port))
    said = {'written': bool(CL_STATE['written']), 'sha': str(CL_STATE['sha'] or '')[:12],
            'error': CL_STATE['error'], 'port': port, 'listening': listening,
            'busy': cl_busy_now(port, listening),
            'crls': cl_crls_now(), 'ocsp': cl_ocsp_now(), 'version': __version__}
    if now_too or said != CL_STATE['said'] or now - CL_STATE['said_at'] > 300:
        store.set_meta(CL_NODE_META + node_name(), json.dumps(dict(said, at=now)))
        CL_STATE.update(said=said, said_at=now)
        return True
    return False


def cl_web_served(port):
    """Whether root's last word on this node says nginx was given the certificate's port."""
    try:
        return int((web_status().get('certlogin') or {}).get('port') or 0) == int(port)
    except Exception:                                   # noqa: BLE001
        return False


def cl_busy_now(port, listening):
    """Why the port is not served here, for the card (1.0.103): root's own words first - root
    sees every process, so it names what listens there (and its pid) - else what this account
    can see."""
    try:
        said = web_status().get('certlogin') or {}
    except Exception:                                   # noqa: BLE001
        said = {}
    # Only root's words of this port (1.0.106): those of a port asked for earlier were shown
    # for the new one. `want` from a root of 1.0.106 on; the port in the words before it.
    want = said.get('want')
    if said.get('busy') and not int(said.get('port') or 0) and (
            int(want or 0) == int(port) if want else
            re.search(r'(?<![0-9])%d(?![0-9])' % int(port), str(said['busy']))):
        return str(said['busy'])[:300]
    return cl_port_busy(port, served=listening and cl_web_served(port))


def cl_crls_now():
    """The CRLs kept on this node, as the card shows them: facts and dates only, never a CRL
    (the meta row stays small) - CL_CRLS_SAID at most."""
    with CL_CRL_LOCK:
        got = list(CL_CRL_CACHE.values())
    out = []
    for c in sorted(got, key=lambda c: c['url'])[:CL_CRLS_SAID]:
        one = {'url': c['url'], 'ok': bool(c.get('pem')), 'at': c.get('at'),
               'next': c.get('next') or None, 'err': c.get('err') or ''}
        for k in ('err_at', 'this', 'size', 'revoked', 'number', 'issuer', 'sig', 'delta', 'via'):
            if c.get(k) not in (None, ''):
                one[k] = c[k]
        if c.get('freshest'):
            one['freshest'] = list(c['freshest'])[:3]
        out.append(one)
    return out


# ---- the CRLs on the card: Fetch now, Clear (1.0.104) ------------------------------------------
CL_CA_CDPS = {}


def cl_crl_known(store, ldap=None):
    """The CRLs the authorities put in name (their CRL Distribution Points, Freshest CRL) - those
    a sign-in fetches for the authorities above a person's certificate (the roots' own, never
    looked at, left out): [{url, of: [subject], delta}], each address one acme fetches from."""
    out = {}
    for c in cl_cas_row(store):
        f = CL_CA_CDPS.get(c.get('sha256'))
        if f is None:
            try:
                got = cl_facts(c['pem'])
                f = {'cdp': got['cdp'], 'freshest': got['freshest'],
                     'root': got['subject'] == got['issuer']}
            except CertRefused:
                f = {'cdp': [], 'freshest': [], 'root': True}
            if len(CL_CA_CDPS) > 200:
                CL_CA_CDPS.clear()
            CL_CA_CDPS[c.get('sha256')] = f
        if f['root']:
            continue
        if ldap is None:
            ldap = any(cl_ldap_on(p) for p in CL_PARTS)
        for delta, urls in ((False, f['cdp']), (True, f['freshest'])):
            for u in urls:
                # ...and a CDP object of the directory while either part reads them (1.0.105)
                if (u.lower().startswith('http://') and cl_cdp_ok(u)) or (ldap and
                                                                          cl_ldap_cdp(u)):
                    one = out.setdefault(u, {'url': u, 'of': [], 'delta': delta})
                    if c.get('subject') and c['subject'] not in one['of']:
                        one['of'].append(c['subject'])
    return [out[u] for u in sorted(out)][:CL_CRLS_SAID]


def cl_crl_where_ok(url, ldap=None):
    """An address a CRL is taken from: http by cl_cdp_ok, or the directory's CDP object while
    reading them from the directory is on (1.0.105)."""
    if str(url or '').lower().startswith('ldap://'):
        return bool(ldap) and cl_ldap_cdp(url) is not None
    return cl_cdp_ok(url)


def cl_crl_urls_here(store, ldap=None):
    """Every CRL Fetch now fetches on this node: those kept here (and the delta CRLs they name)
    and those the authorities name."""
    with CL_CRL_LOCK:
        got = list(CL_CRL_CACHE.values())
    urls = [c['url'] for c in got]
    for c in got:
        urls += [u for u in c.get('freshest') or [] if u.lower().startswith(('http://', 'ldap://'))]
    urls += [k['url'] for k in cl_crl_known(store)]
    return [u for u in dict.fromkeys(urls) if cl_crl_where_ok(u, ldap)][:CL_CRLS_SAID]


def cl_crl_do(store, act, url='', ldap=None):
    """Fetch now ('fetch') or Clear ('clear') on this node - every CRL, or the one at url.
    Fetched whatever is kept; a fetch that fails changes nothing that lets anybody in (the last
    good CRL until its next update, else none - no sign-in). Cleared, the next sign-in (or Fetch
    now) fetches it again. [{url, ok, err}]; this node's state written at once."""
    out = []
    if act == 'clear':
        with CL_CRL_LOCK:
            gone = [u for u in CL_CRL_CACHE if not url or u == url]
            for u in gone:
                CL_CRL_CACHE.pop(u, None)
        out = [{'url': u, 'ok': True, 'err': ''} for u in sorted(gone)]
    elif act == 'fetch':
        todo, done = ([url] if url else cl_crl_urls_here(store, ldap)), set()
        while todo and len(done) < CL_CRLS_SAID:
            u = todo.pop(0)
            if u in done:
                continue
            done.add(u)
            try:
                got = cl_crl_fetch(u, force=True, ldap=ldap)
                out.append({'url': u, 'ok': not got.get('err'), 'err': got.get('err') or '',
                            'number': got.get('number') or ''})
                if not url:
                    todo += [f for f in got.get('freshest') or [] if cl_crl_where_ok(f, ldap)]
            except CertRefused as e:
                with CL_CRL_LOCK:
                    why = (CL_CRL_CACHE.get(u) or {}).get('err') or e.why
                out.append({'url': u, 'ok': False, 'err': str(why)[:200]})
            except Exception as e:                      # noqa: BLE001
                out.append({'url': u, 'ok': False, 'err': str(e)[:200]})
    try:
        cl_say(store, now_too=True)
    except Exception as e:                              # noqa: BLE001
        log_sparing('cl-say', 'the state of the sign-in with a certificate: %s' % e, 'warn',
                    every=300)
    return out


@node_ask_kind('crl_fetch')
def _ask_crl_fetch(daemon, args):
    got = cl_crl_do(daemon.store, 'fetch', str(args.get('url') or ''),
                    ldap=cl_ldap_any(daemon, daemon.store))
    return {'ok': all(x['ok'] for x in got), 'crls': got}


@node_ask_kind('crl_clear')
def _ask_crl_clear(daemon, args):
    got = cl_crl_do(daemon.store, 'clear', str(args.get('url') or ''))
    return {'ok': True, 'crls': got}


def cl_crl_ask(d, act, url, by):
    """Fetch now or Clear asked of every node (each does it itself; this one at once, from the
    pages): the ask {id, nodes}, the event written. ValueError for an address not known."""
    url = str(url or '').strip()
    if url:
        known = {k['url'] for k in cl_crl_known(d.store)}
        for n in sorted(set([node_name()] + [x['name'] for x in ha_nodes(d.store)])):
            known.update(c.get('url') for c in cl_node_state(d.store, n).get('crls') or [])
        if CL_STATE['writer'] or getattr(d, 'serving', False):
            known.update(c['url'] for c in cl_crls_now())
        if url not in known:
            raise ValueError('no CRL at that address is known here (acme --cert-login-crl lists '
                             'them)')
    if act == 'fetch':
        words = ('%s asked every node to fetch the CRL at %s again' % (by, url) if url else
                 '%s asked every node to fetch every CRL of the sign-in with a certificate again'
                 % by)
    else:
        words = ('%s cleared the CRL at %s on every node - it is fetched again at the next sign-in'
                 % (by, url) if url else '%s cleared the CRLs of the sign-in with a certificate '
                 'on every node - each is fetched again at the next sign-in' % by)
    d.store.add_event('settings', words[:600], 'info', who=by)
    return node_ask(d, 'crl_' + act, {'url': url, 'by': by}, by)


# ---- the OCSP answers on the card: Ask again, Clear (1.0.105) -----------------------------------
def cl_ocsp_do(store, act, key=''):
    """Ask again ('fetch') or forget ('clear') the OCSP answers kept on this node - every one, or
    the one of key. An asking that fails changes nothing that lets anybody in (the last good
    answer until its next update, else none). [{url, key, ok, err, status}]; this node's state
    written at once."""
    out = []
    with CL_OCSP_LOCK:
        todo = [dict(c) for k, c in CL_OCSP_CACHE.items() if not key or k == key]
    if act == 'clear':
        with CL_OCSP_LOCK:
            for c in todo:
                CL_OCSP_CACHE.pop(c['key'], None)
        out = [{'url': c['url'], 'key': c['key'], 'ok': True, 'err': ''} for c in todo]
    elif act == 'fetch':
        for c in todo[:CL_CRLS_SAID * 2]:
            f = {'subject': c.get('subject'), 'issuer': c.get('issuer'), 'serial': c.get('serial')}
            try:
                if not c.get('_pem') or not c.get('_ipem'):
                    raise CertRefused('nothing to ask with', 'unavailable')
                got = cl_ocsp_ask(c['url'], f, c['_pem'], c['_ipem'], c.get('_ca') or
                                  str(cl_ca_path()), force=True)
                out.append({'url': c['url'], 'key': c['key'], 'ok': not got.get('err'),
                            'err': got.get('err') or '', 'status': got.get('status') or ''})
            except CertRefused as e:
                with CL_OCSP_LOCK:
                    why = (CL_OCSP_CACHE.get(c['key']) or {}).get('err') or e.why
                out.append({'url': c['url'], 'key': c['key'], 'ok': False,
                            'err': str(why)[:200], 'status': ''})
            except Exception as e:                      # noqa: BLE001
                out.append({'url': c['url'], 'key': c['key'], 'ok': False, 'err': str(e)[:200],
                            'status': ''})
    try:
        cl_say(store, now_too=True)
    except Exception as e:                              # noqa: BLE001
        log_sparing('cl-say', 'the state of the sign-in with a certificate: %s' % e, 'warn',
                    every=300)
    return out


@node_ask_kind('ocsp_fetch')
def _ask_ocsp_fetch(daemon, args):
    got = cl_ocsp_do(daemon.store, 'fetch', str(args.get('key') or ''))
    return {'ok': all(x['ok'] for x in got), 'crls': got}


@node_ask_kind('ocsp_clear')
def _ask_ocsp_clear(daemon, args):
    got = cl_ocsp_do(daemon.store, 'clear', str(args.get('key') or ''))
    return {'ok': True, 'crls': got}


def cl_ocsp_keys(d):
    """The keys of the OCSP answers kept on any node (as each said last, this one as it is)."""
    known = set()
    for n in sorted(set([node_name()] + [x['name'] for x in ha_nodes(d.store)])):
        known.update(c.get('key') for c in cl_node_state(d.store, n).get('ocsp') or []
                     if isinstance(c, dict))
    if CL_STATE['writer'] or getattr(d, 'serving', False):
        known.update(c['key'] for c in cl_ocsp_now())
    return known


def cl_ocsp_ask_all(d, act, key, by):
    """Ask again or Clear asked of every node (each its own answers; this one at once, from the
    pages): {id, nodes}, the event written. ValueError for a key not kept anywhere."""
    key = str(key or '').strip()
    if key and key not in cl_ocsp_keys(d):
        raise ValueError('no OCSP answer of that is kept here (acme --cert-login-ocsp lists them)')
    what = key.split('|', 1)[0] if key else ''
    if act == 'fetch':
        words = ('%s asked the OCSP responder at %s again on every node' % (by, what) if key else
                 '%s asked every OCSP responder of the sign-in with a certificate again on every '
                 'node' % by)
    else:
        words = ('%s cleared an OCSP answer of %s on every node - asked again at the next sign-in'
                 % (by, what) if key else '%s cleared the OCSP answers of the sign-in with a '
                 'certificate on every node - each is asked again at the next sign-in' % by)
    d.store.add_event('settings', words[:600], 'info', who=by)
    return node_ask(d, 'ocsp_' + act, {'key': key, 'by': by}, by)


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
        comm = None
        # Every socket of the process (1.0.106): a listener on 0.0.0.0 and [::] has two, and
        # the second was "one whose process cannot be seen".
        for fd in fds:
            try:
                link = os.readlink('%s/%s' % (fd_dir, fd))
            except OSError:
                continue
            if link.startswith('socket:[') and link[8:-1] in inodes:
                if comm is None:
                    try:
                        with open('/proc/%s/comm' % pid) as f:
                            comm = f.read().strip()
                    except OSError:
                        comm = '?'
                found.setdefault(link[8:-1], (comm, int(pid)))
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


def cl_api_port_clash(saved, checked, node, per_node):
    """'' or why the API's port of a node would be the certificate sign-in's (1.0.101): api_port
    is each node's own (api_port@node), certlogin_port the cluster's - nginx listens on it on
    every node, and the daemon of a node whose API is there could not start (or the sign-in with
    a certificate was lost on it). Every node is looked at, both ways."""
    def num(v, dflt):
        try:
            return int(v)
        except (TypeError, ValueError):
            return dflt
    cl = num(checked.get('certlogin_port', CONFIG.get('certlogin_port')) or 8443, 8443)
    shared = num(saved.get('api_port', FILE_CONFIG.get('api_port', DEFAULTS['api_port'])), 9861)
    if 'api_port' in checked and not per_node:
        shared = num(checked['api_port'], shared)
    ports = {node_name(): num(CONFIG.get('api_port'), 9861)}
    if 'api_port' in checked and not per_node:
        ports[node_name()] = shared
    own = {}
    for k, v in saved.items():
        if str(k).startswith('api_port@'):
            own[str(k).split('@', 1)[1]] = num(v, shared)
    if 'api_port' in checked and per_node:
        own[node] = num(checked['api_port'], shared)
    ports.update(own)
    ports.setdefault('', shared)          # every node without a port of its own
    for n in sorted(ports, key=lambda x: (x != node, x)):
        if ports[n] != cl:
            continue
        if 'certlogin_port' in checked:
            if n:
                return ('certlogin_port: %s is acme\'s API on %s (api_port) - choose a port of '
                        'its own (8443)' % (cl, n))
            return ('certlogin_port: %s is acme\'s API on every node without a port of its own '
                    '(api_port) - choose a port of its own (8443)' % cl)
        if n:
            return ('api_port: %s is the port of the sign-in with a certificate (certlogin_port), '
                    'where nginx listens on every node - choose another one for the API on %s'
                    % (cl, n))
        return ('api_port: %s is the port of the sign-in with a certificate (certlogin_port), '
                'where nginx listens on every node - choose another one for the API' % cl)
    return ''


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


CL_SERVED = {'at': 0.0, 'port': 0, 'yes': False}


def cl_served(store=None):
    """Whether the certificate's port answers somewhere now (hunt M round 3): on this node (asked
    at most every 5 s), or on another node as it said last (cl_tick, heard in the last 15
    minutes). With nothing on the port the button sent the browser to "connection refused" -
    and, gone to by itself, every new tab of the sign-in page."""
    port = cl_port()
    now = time.time()
    if CL_SERVED['port'] != port or now - CL_SERVED['at'] > 5:
        CL_SERVED.update(at=now, port=port, yes=cl_listening(port))
    if CL_SERVED['yes']:
        return True
    if store is None:
        return False
    try:
        for n in ha_nodes(store):
            name = n.get('name') if isinstance(n, dict) else n['name']
            if not name or name == node_name():
                continue
            st = cl_node_state(store, name)
            if st.get('listening') and int(st.get('port') or 0) == port and \
                    now - float(st.get('at') or 0) < 900:
                return True
    except Exception as e:                              # noqa: BLE001
        log_sparing('cl-served', 'whether another node serves the certificate port could not '
                                 'be read: %s' % e, 'warn', every=300)
    return False


def cl_page_info(part, store=None, configured=False):
    """What a sign-in page shows of it: the button, gone to by itself, no password - and the
    port the button leads to (nothing else; asked before anybody is signed in).
    ready: whether some node serves the port now - not ready, no button and nothing gone to
    by itself (the page says it is not available just now) and no port. `configured`: as
    set, served or not (the cards' summary)."""
    only = krb_password_off(part, store)
    on = cl_usable(part, store) or (only and cl_on(part))
    ready = bool(on) and (configured or cl_served(store))
    return {'on': bool(on), 'ready': ready,
            'auto': bool(ready and CONFIG.get(part + '_certlogin_auto')),
            'only': bool(only), 'port': cl_port() if ready else 0}


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
    k, c = krb_page_info(part, store), cl_page_info(part, store, configured=True)
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
    # ...or its card taken out and not put back, or no check of it for too long (1.0.113).
    return bool(data.get('how') == 'certificate' and not data.get('krb_kept') and
                not cl_usable(part, store)) or cl_card_dead(part, s, store)


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
    # The OCSP mode too (1.0.105): off < first < only < both - made stricter, the same.
    ocsp = {'off': 0, 'first': 1, 'only': 2, 'both': 3}.get(
        str(CONFIG.get(part + '_certlogin_ocsp') or 'off'), 0)
    # The card watched (1.0.113): switched on, the sign-ins made before (none kept its card) end.
    return (1 if CONFIG.get(part + '_certlogin_crl', 1) else 0, CL_MATCH_RANK.get(cl_match(part), 2),
            ocsp, 0 if cl_card_mode(part) == 'off' else 1)


def cl_rule_stricter(was, now):
    try:
        if not (bool(was) and bool(now)):
            return False
        if now[0] > was[0] or now[1] > was[1]:
            return True
        # A rule kept before 1.0.105 has no OCSP part: it was off then.
        if len(now) > 2 and now[2] > (was[2] if len(was) > 2 else 0):
            return True
        # ...nor one before 1.0.113 the card's watch.
        return len(now) > 3 and now[3] > (was[3] if len(was) > 3 else 0)
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
    return cl_check(pem, cl_ca_path(), crl=crl, ocsp=cl_ocsp_mode(part),
                    ocsp_url=cl_ocsp_url(part), ldap=cl_ldap_for(h.d, h.store, part))


def cl_ocsp_mode(part):
    m = str(CONFIG.get(part + '_certlogin_ocsp') or 'off')
    return m if m in CL_OCSP_MODES else 'off'


def cl_ocsp_url(part):
    """The responder set for every certificate of a part - '' for none, or one acme would not
    ask (refused when it is saved; a file read back is checked again here)."""
    u = str(CONFIG.get(part + '_certlogin_ocsp_url') or '').strip()
    return u if u and cl_cdp_ok(u) else ''


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


# ---- a person looked up for their certificate request (1.0.110) -------------------------------
# "Look a person up for a certificate": a name typed (sAMAccountName, DOMAIN\name, UPN or e-mail)
# looked up in the part's directory, as a certificate administrator looks a name up in the
# directory card - and what goes into that person's certificate request: the CN, the UPN of the
# Subject Alternative Name (otherName msUPN), the SAN URL of the strong mapping (KB5014754,
# tag:microsoft.com,2022-09-14:sid:<SID>) and the request itself for openssl and certreq; their
# account's state, the role (or the enrolment pages) a certificate of theirs would sign in to, and
# which "Which account" mode takes it. Read only: nothing changed, the event says who looked.
CL_LOOKUP_MOST = 256
# Not in any name, UPN or address an account has: the characters a filter, a DN or AD itself
# keeps for something else - refused as they are typed, never escaped and sent.
CL_LOOKUP_BAD = re.compile(r'[\x00-\x1f\x7f*()"/\[\]:;|=,+?<>]')
# Which "Which account" modes take a certificate of these values: the SID in the extension
# AD CS writes itself, the SID in the SAN URL only (the requester's word: never strong here),
# and no SID at all (the directory says none).
CL_LOOKUP_ACCEPTS = {'sid_extension': ['upn', 'compat', 'strong'], 'san_url': ['upn', 'compat'],
                     'none': ['upn', 'compat']}


class CertLookupError(Exception):
    def __init__(self, status, words):
        Exception.__init__(self, words)
        self.status = status


def cl_lookup_name(text):
    """The name typed, as the directory is asked: (name, [how, ...]). CertLookupError."""
    s = str(text if text is not None else '').strip()
    if not s:
        raise CertLookupError(400, 'type a name: the account (novak), its UPN (novak@example.cz) '
                                   'or its e-mail address')
    if len(s) > CL_LOOKUP_MOST:
        raise CertLookupError(400, 'that name is too long to be an account\'s')
    if CL_LOOKUP_BAD.search(s) or s.count('\\') > 1 or s.count('@') > 1:
        raise CertLookupError(400, 'that is no account name: an account, a UPN or an e-mail '
                                   'address has none of * ( ) = , ; : " / [ ] | + ? < >')
    if '\\' in s:
        s = s.split('\\', 1)[1].strip()
        if not s or '@' in s:
            raise CertLookupError(400, 'DOMAIN\\name: the name after the backslash, please')
    return s, (['upn', 'mail'] if '@' in s else ['sam'])


def cl_dn_quoted(cn):
    """A CN as an X.500 string for certreq's Subject: quoted where it holds a separator."""
    return '"%s"' % cn.replace('"', '""') if re.search(r'[,+="\\<>#;\n]', cn) else cn


def cl_lookup_snippets(cn, upn, sid, mail, sam):
    """What goes into the request - openssl (a -config file, written by a here-document) and
    certreq (an INF) -
    with the e-mail address in the SAN and without it: {False: {...}, True: {...}}."""
    out = {}
    base = re.sub(r'[^A-Za-z0-9._-]', '_', sam or upn.split('@', 1)[0] or 'person')[:40] or 'person'
    cnf_cn = re.sub(r'([\\$#])', r'\\\1', cn)
    url = CL_SID_URL + sid if sid else ''
    for with_mail in (False, True):
        m = mail if with_mail and mail else ''
        san = ['otherName:%s;UTF8:%s' % (CL_OID_UPN, upn)] if upn else []
        if url:
            san.append('URI:' + url)
        if m:
            san.append('email:' + m)
        # A file, not -addext: the comma in the SAN URL (tag:microsoft.com,2022-09-14:...) splits
        # an -addext list, and no quoting keeps it whole.
        run = 'openssl req -new -config %s.cnf -newkey rsa:2048 -nodes -keyout %s.key -out %s.csr' \
            % (base, base, base)
        cnf = ['# ' + run, '[req]', 'prompt = no', 'utf8 = yes', 'string_mask = utf8only',
               'distinguished_name = dn', 'req_extensions = ext', '', '[dn]', 'CN = ' + cnf_cn,
               '', '[ext]']
        if san:
            cnf.append('subjectAltName = @san')
        cnf += ['extendedKeyUsage = clientAuth, 1.3.6.1.4.1.311.20.2.2',
                'keyUsage = critical, digitalSignature, keyEncipherment']
        if san:
            cnf += ['', '[san]']
            if upn:
                cnf.append('otherName.1 = %s;UTF8:%s' % (CL_OID_UPN, upn))
            if url:
                cnf.append('URI.1 = ' + url)
            if m:
                cnf.append('email.1 = ' + m)
        inf = ['; certreq -new %s.inf %s.csr' % (base, base), '[Version]',
               'Signature = "$Windows NT$"', '', '[NewRequest]',
               'Subject = "CN=%s"' % cl_dn_quoted(cn).replace('"', '""'),
               'KeyLength = 2048', 'KeySpec = 1', 'KeyUsage = 0xA0', 'Exportable = FALSE',
               'MachineKeySet = FALSE', 'RequestType = PKCS10',
               '; on a smart card or a YubiKey:',
               '; ProviderName = "Microsoft Smart Card Key Storage Provider"', '',
               '[EnhancedKeyUsageExtension]', 'OID = 1.3.6.1.5.5.7.3.2',
               'OID = 1.3.6.1.4.1.311.20.2.2']
        parts = (['upn=' + upn] if upn else []) + (['url=' + url] if url else []) + \
            (['email=' + m] if m else [])
        if parts:
            inf += ['', '[Extensions]', '2.5.29.17 = "{text}"']
            inf += ['_continue_ = "%s%s"' % (p, '&' if i < len(parts) - 1 else '')
                    for i, p in enumerate(parts)]
        lines = ["cat > %s.cnf <<'EOF'" % base] + cnf[1:] + ['EOF', run]
        out[with_mail] = {'openssl': '\n'.join(lines), 'openssl_cnf': '\n'.join(cnf),
                          'certreq_inf': '\n'.join(inf)}
    return out


def cl_lookup_would(h, part, upn, sid, kind):
    """Whether a certificate with these values (kind: sid_extension - the SID written by AD CS;
    san_url - the SID in the SAN URL only; none - no SID) signs in to the part now, as the
    sign-in checks it: {ok, role, why, kind}. Nothing made."""
    f = {'upn_one': upn, 'sid': sid if kind == 'sid_extension' else '',
         'san_sids': [sid] if sid and kind != 'none' else []}
    try:
        if part == 'admin':
            said = cl_admin_would(h, f)
            return {'ok': True, 'role': said['role']}
        _ad, _entry, groups = cl_portal_would(h, f)
        return {'ok': True, 'role': 'portal', 'groups': groups[:10]}
    except CertRefused as e:
        # The words only (never the library's own, `more`): the directory unreachable is said
        # as that, no host or error of it.
        return {'ok': False, 'why': str(e.args[0] if e.args else e.why)[:400], 'kind': e.kind}


def cl_lookup(h, name, part, by):
    """A person looked up for their certificate request - the card's popup and acme
    --cert-login-lookup. A dict; CertLookupError (400 a name that is none, 404 no directory,
    503 the directory not answering - in words that say nothing of it)."""
    if part not in CL_PARTS:
        raise CertLookupError(400, 'admin or portal')
    who, hows = cl_lookup_name(name)
    if part == 'admin':
        dname = krb_directory_name('admin')
        ad = h.d.dirs.get(dname.lower()) if dname else None
    else:
        ad = portal_directory(h)
    if ad is None:
        raise CertLookupError(404, 'no directory is set (or switched on) for %s' % (
            'administrators' if part == 'admin' else 'the enrolment pages'))
    out = {'part': part, 'directory': ad.name, 'asked': who, 'on': cl_on(part),
           'match': cl_match(part), 'match_words': CL_MATCH_WORDS[cl_match(part)]}
    entry, how = None, hows[0]
    try:
        for how in hows:
            entry = ad.find_user(who, how)
            if entry:
                break
        groups = ad.groups_of(entry, True) if entry and not entry.get('many') else []
    except LdapError as e:
        log('a person looked up for a certificate: the directory %s: %s' % (ad.name, e), 'warn')
        raise CertLookupError(503, 'the directory cannot be reached just now')
    out['how'] = how
    if not entry:
        out['found'] = 'none'
    elif entry.get('many'):
        out['found'] = 'many'
    else:
        out['found'] = 'one'
        sid = str(entry.get('sid') or '')
        upn = str(entry.get('upn') or '')
        mail = str(entry.get('mail') or '')
        cn = cn_of(entry['dn'])
        out.update({
            'cn': cn, 'sam': entry.get('sam') or '', 'upn': upn, 'dn': entry['dn'],
            'display': entry.get('display') or '', 'sid': sid, 'mail': mail,
            'disabled': bool(entry.get('disabled')), 'locked': bool(entry.get('locked')),
            'expired': bool(entry.get('expires') and entry['expires'] < time.time()),
            'expires': entry.get('expires') or None,
            'pw_expired': bool(entry.get('pw_expired')),
            'unusable': entry_unusable(entry) or '',
            'groups_count': len({dn.lower() for dn, _cn in groups}),
            'groups': sorted({c for _dn, c in groups}, key=str.lower)[:30],
            'san_upn': upn, 'san_url': CL_SID_URL + sid if sid else '',
            'accepts': {k: v for k, v in CL_LOOKUP_ACCEPTS.items()
                        if ((k != 'none') if sid else (k == 'none'))}})
        if part == 'admin':
            out['role'] = admin_role_for(groups, ad) or ''
        else:
            out['portal'] = bool(CONFIG.get('portal'))
        snip = cl_lookup_snippets(cn, upn, sid, mail, out['sam'])
        out['snippets'] = snip[False]
        out['snippets_mail'] = snip[True]
        out['openssl'] = snip[False]['openssl']
        out['certreq_inf'] = snip[False]['certreq_inf']
        if upn:
            kinds = ('sid_extension', 'san_url') if sid else ('none',)
            out['would'] = {k: cl_lookup_would(h, part, upn, sid, k) for k in kinds}
    said = {'none': 'nobody by that name', 'many': 'more than one account answers to it'}.get(
        out['found'], '%s (%s)' % (out.get('upn') or out.get('sam'), out.get('dn')))
    h.store.add_event('accounts', '%s looked %s up in the directory %s for a certificate request '
                      '(%s): %s' % (by, who[:120], ad.name, 'the administration' if part == 'admin'
                                    else 'the enrolment pages', said), who=by)
    return out


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
                          dict({'subject': f['subject'][:200], 'serial': f['serial'][:64],
                                'principal': f['upn_one'], 'cas': cl_session_cas(f)},
                               **cl_card_data('admin', f)),
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
                              more=dict({'cas': cl_session_cas(f)}, **cl_card_data('portal', f)))
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
            'crl_ldap': cl_ldap_on(part), 'ocsp': cl_ocsp_mode(part),
            'ocsp_url': str(CONFIG.get(part + '_certlogin_ocsp_url') or '').strip(),
            'ocsp_url_ok': bool(cl_ocsp_url(part)),
            'directory': krb_directory_name(part),
            'password_off': bool(CONFIG.get(part + '_password_off')),
            'only_in_effect': krb_password_off(part, store),
            'krb': krb_usable(part, store),
            'signin': sso_signin_modes(part, store),
            'second': bool(CONFIG.get('admin_2fa')) if part == 'admin' else portal_gate_needed()}
        if cl_card_mode(part) != 'off':
            # The card watched (1.0.113) - a key of the answer only then.
            parts[part]['card'] = {'watch': cl_card_mode(part), 'every': cl_card_every(part),
                                   'grace': cl_card_grace(part),
                                   'unable': cl_card_unable_mode(part),
                                   'sessions': cl_card_sessions(store, part)}
    parts['portal']['portal'] = bool(CONFIG.get('portal'))
    now = time.time()
    nodes, crls, ocsp = [], {}, {}
    for n in sorted(set([node_name()] + [x['name'] for x in ha_nodes(store)])):
        st = cl_node_state(store, n)
        if n == node_name() and CL_STATE['writer']:
            port = cl_port()
            listening = bool(cl_any_on() and cl_listening(port))
            st = dict(st, written=bool(CL_STATE['written']), error=CL_STATE['error'],
                      sha=str(CL_STATE['sha'] or '')[:12], crls=cl_crls_now(), ocsp=cl_ocsp_now(),
                      listening=listening, port=port, at=st.get('at') or now,
                      busy=cl_busy_now(port, listening))
        elif n == node_name() and getattr(getattr(h, 'd', None), 'serving', False):
            # The daemon before its first round (writer not yet): its CRLs are its own.
            st = dict(st, crls=cl_crls_now(), ocsp=cl_ocsp_now())
        for c in st.get('crls') or []:
            if isinstance(c, dict) and c.get('url'):
                crls.setdefault(c['url'], []).append(dict(c, node=n))
        for c in st.get('ocsp') or []:
            if isinstance(c, dict) and c.get('key'):
                ocsp.setdefault(c['key'], []).append(dict(c, node=n))
        nodes.append({'node': n, 'me': n == node_name(),
                      'heard': bool(st) and now - float(st.get('at') or 0) < 900,
                      'at': st.get('at'), 'written': bool(st.get('written')),
                      'same': bool(cas and st.get('sha') and st.get('sha') == sha),
                      'listening': bool(st.get('listening')), 'port': st.get('port') or cl_port(),
                      'busy': st.get('busy') or '',
                      'error': st.get('error') or '', 'version': st.get('version') or ''})
    out = {'cas': [cl_ca_view(c) for c in cas], 'parts': parts, 'port': cl_port(),
           'nodes': nodes, 'crls': cl_crl_rows(store, crls),
           'ocsp_answers': cl_ocsp_rows(ocsp),
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


def cl_crl_rows(store, seen):
    """One row of the card for each CRL: as kept on each node (seen: {url: [its state on a node,
    node=...]}) - the facts of the newest good one, else of the newest - and those the authorities
    name, not fetched yet."""
    known = {k['url']: k for k in cl_crl_known(store)}
    out = []
    for url in sorted(set(seen) | set(known)):
        each = sorted(seen.get(url) or [], key=lambda c: c['node'])
        good = [c for c in each if c.get('ok') and float(c.get('next') or 0) > time.time()]
        best = max(good or each, key=lambda c: float(c.get('at') or 0)) if each else {}
        k = known.get(url) or {}
        row = {'url': url, 'fetched': bool(each), 'ok': bool(good),
               'via': 'ldap' if url.lower().startswith('ldap://') else 'http',
               'name': cl_ldap_name(url) if url.lower().startswith('ldap://') else '',
               'of': k.get('of') or [], 'named': bool(k),
               'delta': bool(best.get('delta') if best else k.get('delta')),
               'err': next((c.get('err') for c in sorted(each, key=lambda c: -float(
                   c.get('err_at') or c.get('at') or 0)) if c.get('err')), '') if each else '',
               'nodes': [{x: c.get(x) for x in ('node', 'ok', 'at', 'next', 'err', 'err_at',
                                               'number')} for c in each]}
        for x in ('at', 'next', 'this', 'issuer', 'number', 'size', 'revoked', 'sig', 'err_at'):
            row[x] = best.get(x) if best else None
        out.append(row)
    return out[:CL_CRLS_SAID * 2]


def cl_ocsp_rows(seen):
    """One row of the card for each OCSP answer kept (seen: {key: [its state on a node,
    node=...]}): the facts of the newest one with an answer, else of the newest; each node's in
    `nodes`. Never a certificate."""
    out = []
    for key in sorted(seen, key=lambda k: (k.split('|', 1)[0], k)):
        each = sorted(seen[key], key=lambda c: c['node'])
        answered = [c for c in each if c.get('status')]
        best = max(answered or each, key=lambda c: float(c.get('at') or 0))
        row = {k: best.get(k) for k in CL_OCSP_SAID}
        row['nodes'] = [{x: c.get(x) for x in ('node', 'status', 'at', 'next', 'err', 'err_at')}
                        for c in each]
        out.append(row)
    return out[:CL_CRLS_SAID * 2]


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
    b = h.body()
    act = str(b.get('action') or '')
    if act == 'lookup':
        # Look a person up for a certificate (1.0.110): read only - whoever may look a name up
        # in the directory card (a certificate administrator), not only a full one.
        s = h.me('certadmin')
        try:
            return {'lookup': cl_lookup(h, b.get('name'), str(b.get('part') or 'admin'),
                                        s['name'])}
        except CertLookupError as e:
            raise ApiError(e.status, str(e))
    s = h.me('fulladmin')
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
    if act in ('ocsp_fetch', 'ocsp_clear'):
        # Ask again / Clear of the OCSP answers (1.0.105): every node its own.
        try:
            asked = cl_ocsp_ask_all(h.d, act[5:], b.get('url') or b.get('key'), s['name'])
        except ValueError as e:
            raise ApiError(404, str(e))
        return dict(asked, message=('every node asks the OCSP responders again'
                                    if act == 'ocsp_fetch' else
                                    'the OCSP answers are cleared on every node'))
    if act in ('crl_fetch', 'crl_clear'):
        try:
            asked = cl_crl_ask(h.d, act[4:], b.get('url'), s['name'])
        except ValueError as e:
            raise ApiError(404, str(e))
        return dict(asked, message=('every node fetches the CRLs again' if act == 'crl_fetch'
                                    else 'the CRLs are cleared on every node'))
    if act == 'result':
        # What each node answered to Fetch now or Clear (the page's askNodes).
        ident = str(b.get('id') or '')
        got = node_ask_results(h.store, 'crl_fetch', ident)
        for kind in ('crl_clear', 'ocsp_fetch', 'ocsp_clear'):
            for n, v in node_ask_results(h.store, kind, ident).items():
                got[n] = got.get(n) or v
        return {'nodes': got}
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
        out = dict(on, port=cl_port(), cas=cl_cas_pem(cas))
        # The card watched (1.0.113): only then the port resumes no TLS session and keeps no
        # connection open - with it off for both parts nginx's server stays as it was.
        if any(on[p] and cl_card_mode(p) != 'off' for p in CL_PARTS):
            out['watch'] = True
        return out
    return {'port': 0} if served else None


# ---- the card watched: taken out, signed out or locked (1.0.113, 1.0.114) ---------------------
# No browser tells a page that a smart card or a YubiKey was taken out; the only sure sign is that
# the card can no longer sign. So the page loads a picture from the certificate's port every few
# seconds (?api=cert-alive): a new connection - nginx keeps no TLS session and no connection there
# while the card is watched - whose handshake only the card can sign. The session cookie goes
# with it (cookies are not kept apart by port), PHP hands nginx's certificate here, and the
# sign-in must be one made with a certificate - the SAME one (its SHA-256, kept in the sign-in's
# own row at the sign-in). The answer is the picture's width: 1 the card is there, 2 it is out
# and the sign-in waits (grace), 3-5 the sign-in ended just now (another card, taken out, not put
# back in time), 6 no cookie came with the check (PHP, before asking here - the page then says so
# over 443, where its cookie does come), 7 this browser cannot be checked - not watched; none
# (403) no such sign-in. (The kit's 3 and 4 are acme's 6 and 7: acme's 3-5 were taken already.)
# Per part:
#   <part>_certlogin_card_watch  off (the default: nothing of this runs) | signout | grace (1.0.113's
#                                "lock", still read as it)
#   <part>_certlogin_card_every  seconds between two checks of the page (5-300)
#   <part>_certlogin_card_grace  seconds the card may be out (5-600)
#   <part>_certlogin_card_unable allow (the default) | signout - a browser that cannot be checked
# 1.0.114 - the kit "card-removal-watch" merged (its MERGE-NOTES):
#   - the state is kept in the sign-in's row (card_seen: the last check that found the card, at
#     most every 20 s; card_out: when it was first found out) - either node of a cluster answers
#     a check, a restart forgets nothing; nothing of it in `meta`;
#   - a handshake that failed (nothing to sign it with) is said by the page itself over 443
#     (?api=cert-lost): the events say why, and in grace nothing of the sign-in is answered (423,
#     code card) until the card is back;
#   - asleep is not out: a sign-in whose page has not checked for late + grace + max(every, 30)
#     is held (423), not ended - the page checks the moment it wakes; "No check of the card for"
#     is no setting any more;
#   - the card's fingerprint is kept with every sign-in made with a certificate: switched on, those
#     sign-ins are watched from then on (their pages learn it within a minute).
#   - a browser that cannot be checked (the kit's 3rd edition, found on a real iPad: Safari on
#     iPadOS signs no connection for a page in the background - the card is in, yet the check
#     never comes): a sign-in keeps whether a check IN THE BACKGROUND has ever found its card in
#     this browser (card_ok: the time of the first that did - the sign-in itself, a top-level
#     navigation the iPad does sign, does not count; -1: cannot be checked). Until one has, a
#     check without the card means "this browser cannot be checked": with
#     <part>_certlogin_card_unable = allow that sign-in is not watched from then on (said in the
#     events, with why), with signout it goes on as a card taken out. Once found, a check without
#     the card is a card taken out, as always. An unwatched one is never held for its card.
CL_CARD_MODES = ('off', 'signout', 'grace')
CL_CARD_OLD_META = 'certlogin:cardgone:'        # 1.0.113's notes of ended sign-ins: tidied away
CL_CARD_SWEEP = {'at': 0.0, 'tidied': False}
CL_CARD_SEEN_S = 20                             # card_seen written at most this often
# What a sign-in whose card is out (or held) may still ask.
CL_CARD_ALLOWED = ('/api/auth/logout', '/api/auth/whoami', '/api/certlogin/alive',
                   '/api/certlogin/lost', '/api/portal/logout', '/api/portal/me')
CL_CARD_OUT = 'the card they signed in with was taken out'
CL_CARD_LATE = 'the card they signed in with was not put back in time'
CL_CARD_OTHER = 'another certificate than the one signed in with was offered (the card was changed)'
# Why a check came without the card (the events): no certificate with it, no cookie with it, no
# answer at all (the page's word over 443).
CL_CARD_WHY = {
    'nocert': 'no certificate came with the check (the browser does not sign it in the background)',
    'nocookie': 'the browser sent no cookie with the check',
    'nopicture': 'the check got no answer at all (the browser did not sign the connection)'}
CL_CARD_UNABLE = ('allow', 'signout')
# The page's word for why it ended (the sign-in page's own sentence for it).
CL_CARD_WORD = {CL_CARD_OUT: 'out', CL_CARD_LATE: 'late', CL_CARD_OTHER: 'other'}


def cl_card_mode(part):
    m = str(CONFIG.get(part + '_certlogin_card_watch') or 'off')
    m = SETTING_ALIASES.get(part + '_certlogin_card_watch', {}).get(m, m)
    return m if m in CL_CARD_MODES else 'off'


def cl_card_unable_mode(part):
    """What a browser that cannot be checked gets: allow (not watched) | signout."""
    m = str(CONFIG.get(part + '_certlogin_card_unable') or 'allow')
    return m if m in CL_CARD_UNABLE else 'allow'


def _cl_card_ok(data):
    """card_ok of a sign-in's row: > 0 a check in the background has found the card in this
    browser, -1 this browser cannot be checked, 0 neither yet."""
    try:
        return float((data or {}).get('card_ok') or 0)
    except (TypeError, ValueError):
        return 0.0


def cl_card_unable(s):
    """Whether this sign-in's browser was found not to be checkable (not watched)."""
    return _cl_card_ok((s or {}).get('data') or {}) < 0


def cl_card_any():
    return any(cl_on(p) and cl_card_mode(p) != 'off' for p in CL_PARTS)


def _cl_card_int(part, what, default, lo, hi):
    try:
        return max(lo, min(hi, int(CONFIG.get(part + '_certlogin_card_' + what) or default)))
    except (TypeError, ValueError):
        return default


def cl_card_every(part):
    return _cl_card_int(part, 'every', 15, 5, 300)


def cl_card_grace(part):
    return _cl_card_int(part, 'grace', 30, 5, 600)


def cl_card_late(part):
    """How late a check may be: a browser lets a tab in the background check about once a
    minute - three checks or 150 s, the longer."""
    return max(3 * cl_card_every(part), 150)


def cl_card_fp(pem):
    """The SHA-256 of a certificate in PEM (as openssl's fingerprint, lower case), or ''."""
    try:
        _pem, der = cl_pem_one(pem)
    except Exception:                                   # noqa: BLE001
        return ''
    return hashlib.sha256(der).hexdigest()


def cl_card_data(part, f):
    """What a sign-in made with a certificate keeps of it for the watch: its SHA-256 - never the
    certificate. Kept whatever the setting (1.0.114): switched on later, the sign-in is watched
    from then on instead of ended."""
    if not re.match(r'^[0-9a-f]{64}\Z', str(f.get('sha256') or '')):
        return {}
    return {'card': f['sha256']}


def cl_card_watched(part, s):
    """Whether this sign-in is watched: made with a certificate whose SHA-256 it kept, the part
    watching the card - never one kept on purpose by a change of its rules (krb_kept)."""
    data = (s or {}).get('data') or {}
    return bool(part in CL_PARTS and cl_card_mode(part) != 'off' and
                data.get('how') == 'certificate' and data.get('card') and
                not data.get('krb_kept') and _cl_card_ok(data) >= 0)


def _cl_card_pending(part, s):
    """The second step (or the portal's one-time code) still to give: not watched yet."""
    try:
        if part == 'admin':
            return bool(mfa_pending(s))
        return bool(portal_gated(s) or portal_mfa_pending(s))
    except Exception:                                   # noqa: BLE001
        return False


def _cl_card_t(data, key, old):
    """A time of the sign-in's row - 1.0.113 named card_seen card_at and card_out card_lock."""
    try:
        return float(data.get(key) or data.get(old) or 0)
    except (TypeError, ValueError):
        return 0.0


def cl_card_due(part, s, store=None, now=None):
    """The server's half, on every question of a sign-in: (None (not watched) | 'in' | 'out' (the
    card out, within the time) | 'held' (its page stopped checking) | 'gone' (to be ended), why).
    `store`: a sign-in never checked yet is watched from now (its row says so)."""
    if not cl_card_watched(part, s):
        return None, ''
    now = time.time() if now is None else now
    data = s.get('data') or {}
    mode = cl_card_mode(part)
    out = _cl_card_t(data, 'card_out', 'card_lock')
    if out:
        if mode == 'signout':
            return 'gone', CL_CARD_OUT
        # The page signs out at the grace; the server gives it the time a late check takes.
        if now - out >= cl_card_grace(part) + cl_card_late(part):
            return 'gone', CL_CARD_LATE
        return 'out', ''
    if _cl_card_pending(part, s):
        return 'in', ''
    seen = _cl_card_t(data, 'card_seen', 'card_at')
    if not seen:
        # Watched from now: its first question, or switched on after the sign-in was made.
        if store is not None and s.get('id'):
            store.session_merge(s['id'], {'card_seen': now})
            data['card_seen'] = now
        return 'in', ''
    grace = cl_card_grace(part) if mode == 'grace' else 0
    if now - seen >= cl_card_late(part) + grace + max(cl_card_every(part), 30):
        # Asleep is not out: a page stopped (an iPad's screen locked, the browser in the
        # background) checks nothing. Nothing of it is answered until a check finds the card -
        # the page checks the moment it wakes; no card then, and it goes as one taken out.
        return 'held', ''
    return 'in', ''


def _cl_card_said(store, part, s, why, ip=''):
    store.add_event('sign-ins' if part == 'admin' else 'portal',
                    '%s was signed out of %s%s: %s' % (
                        s.get('name') or '?', 'these pages' if part == 'admin' else
                        'the enrolment pages', ' (from %s)' % ip if ip else '', why),
                    'warn', who=s.get('name') or None)


def cl_card_end(store, part, s, why, ip=''):
    """A watched sign-in ended for its card: the row gone and said in Events - once, by the node
    whose DELETE took it (both nodes may find it due at the same moment)."""
    n = store.db.run('DELETE FROM sessions WHERE id = ?', (s['id'],))
    if n is None or n:
        _cl_card_said(store, part, s, why, ip)


def cl_card_dead(part, s, store):
    """For cl_session_gone: a watched sign-in whose card was out longer than allowed - said in
    the events here, True for the caller (which ends it)."""
    st, why = cl_card_due(part, s)
    if st != 'gone':
        return False
    try:
        _cl_card_said(store, part, s, why)
    except Exception:                                   # noqa: BLE001
        pass
    return True


def cl_card_hold(h, part, s):
    """Every question of a sign-in whose card is out (grace) or whose page stopped checking
    (held) but the check's own, whoami and Sign out: 423, code card - so a covered page cannot be
    worked around from the browser's console."""
    st, _why = cl_card_due(part, s, h.store)
    if st in ('out', 'held') and getattr(h, 'route_path', '') not in CL_CARD_ALLOWED:
        raise ApiError(423, 'the card is out - put back the card you signed in with',
                       extra={'code': 'card'})


def cl_card_view(part, s, store=None):
    """What the page needs to watch its card (whoami, /api/portal/me): None for a sign-in not
    watched - and then not a key of the answer at all."""
    st, _why = cl_card_due(part, s, store)
    if st is None or st == 'gone':
        return None
    out = _cl_card_t((s or {}).get('data') or {}, 'card_out', 'card_lock')
    left = cl_card_grace(part)
    if out:
        left = max(0, int(cl_card_grace(part) - (time.time() - out)))
    return {'watch': cl_card_mode(part), 'every': cl_card_every(part),
            'grace': cl_card_grace(part), 'port': cl_port(), 'locked': st == 'out',
            'left': left, 'stale': st == 'held'}


def cl_card_sessions(store, part):
    """The sign-ins of a part watched now (the card's facts)."""
    n = 0
    try:
        for r in store.db.rows('SELECT data FROM sessions WHERE kind = ?', (part,)):
            try:
                d = json.loads(r.get('data') or '{}')
            except ValueError:
                continue
            if isinstance(d, dict) and d.get('how') == 'certificate' and d.get('card') and \
                    not d.get('krb_kept') and _cl_card_ok(d) >= 0:
                n += 1
    except Exception:                                   # noqa: BLE001
        return 0
    return n


def cl_card_sweep(store, now=None):
    """Every 15 s while a part watches the card: the watched sign-ins whose card was out longer
    than allowed ended (a tab closed with the card out). A sign-in whose page stopped checking is
    held, not ended - the idle time ends it as any other."""
    now = time.time() if now is None else now
    if not CL_CARD_SWEEP['tidied']:
        # 1.0.113 kept a note of each sign-in ended for its card in `meta`: no more (1.0.114).
        CL_CARD_SWEEP['tidied'] = True
        try:
            store.db.run('DELETE FROM meta WHERE k LIKE ?', (CL_CARD_OLD_META + '%',))
        except Exception:                               # noqa: BLE001
            pass
    if not cl_card_any() or now - CL_CARD_SWEEP['at'] < 15:
        return 0
    CL_CARD_SWEEP['at'] = now
    ended = 0
    for part in CL_PARTS:
        if cl_card_mode(part) == 'off':
            continue
        try:
            rows = store.db.rows('SELECT * FROM sessions WHERE kind = ?', (part,))
        except Exception as e:                          # noqa: BLE001
            log_sparing('cl-card-sweep', 'the watched sign-ins could not be read: %s' % e,
                        'warn', every=300)
            return ended
        for r in rows:
            try:
                r['data'] = json.loads(r.get('data') or '{}')
            except ValueError:
                continue
            if not isinstance(r['data'], dict) or not cl_card_watched(part, r):
                continue
            st, why = cl_card_due(part, r, None, now)
            if st == 'gone':
                cl_card_end(store, part, r, why)
                ended += 1
    return ended


def cl_card_session(h, part):
    """The sign-in of the request's cookie, read without touching it (a check is no activity of
    the person: the idle time runs on), or None."""
    token = str(h.headers.get('X-Acme-Session') or '')
    if part == 'admin':
        idle = int(CONFIG.get('session_idle_min') or 120) * 60
    else:
        idle = int(CONFIG.get('portal_session_min') or 15) * 60
    return token, h.store.session_get(token, part, idle, touch=False)


def _cl_card_gone(why):
    return {'ok': False, 'state': 'gone', 'why': CL_CARD_WORD.get(why, 'out')}


def _cl_card_unable_now(h, part, s, how):
    """A check without the card while none in the background has found it in this browser yet:
    with <part>_certlogin_card_unable = allow, this browser cannot be checked (an iPad) - the
    sign-in not watched from now on, said once in the events with why; the answer. None with
    signout (on as a card taken out) or once the card was found here before."""
    data = s.get('data') or {}
    if _cl_card_ok(data) > 0 or cl_card_unable_mode(part) != 'allow':
        return None
    got = h.store.session_merge(s['id'], {'card_ok': -1, 'card_out': None, 'card_lock': None},
                                expect={'card_ok': data.get('card_ok')})
    if got is not False and got is not None:
        h.store.add_event('sign-ins' if part == 'admin' else 'portal',
                          'the card of %s\'s sign-in to %s cannot be checked in this browser - %s: '
                          'it is not watched (from %s; the setting "A browser that cannot be '
                          'checked")' % (s.get('name') or '?', 'these pages' if part == 'admin' else
                                         'the enrolment pages', how, h.client_ip()),
                          'warn', who=s.get('name') or None)
    elif got is False:
        # Another check got there first: found the card (proven) - then this one is a card out.
        fresh = h.store.db.value('SELECT data FROM sessions WHERE id = ?', (s['id'],))
        try:
            if _cl_card_ok(json.loads(fresh or '{}')) > 0:
                return None
        except ValueError:
            pass
    return {'ok': True, 'state': 'unable'}


def cl_card_failed(h, part, s, how):
    """A check without the card (no certificate, nginx's refusal, no cookie, the handshake
    failed): never found in this browser - cannot be checked (allow); else signout - the sign-in
    ends; grace - the time out counted, ended past the grace. The answer."""
    unable = _cl_card_unable_now(h, part, s, how)
    if unable:
        return unable
    now = time.time()
    data = s.get('data') or {}
    if cl_card_mode(part) == 'signout':
        cl_card_end(h.store, part, s, '%s (%s)' % (CL_CARD_OUT, how), h.client_ip())
        return _cl_card_gone(CL_CARD_OUT)
    grace = cl_card_grace(part)
    out = _cl_card_t(data, 'card_out', 'card_lock')
    if not out:
        out = now
        # Once, by whichever node got there first (the other's write refused by `expect`).
        got = h.store.session_merge(s['id'], {'card_out': now}, expect={'card_out': None,
                                                                         'card_lock': None})
        if got is not False and got is not None:
            h.store.add_event('sign-ins' if part == 'admin' else 'portal',
                              '%s: the card they signed in with is out - the sign-in to %s waits '
                              '%d s for it (%s, from %s)' % (
                                  s.get('name') or '?', 'these pages' if part == 'admin' else
                                  'the enrolment pages', grace, how, h.client_ip()),
                              'warn', who=s.get('name') or None)
        elif got is False:
            fresh = h.store.db.value('SELECT data FROM sessions WHERE id = ?', (s['id'],))
            try:
                out = _cl_card_t(json.loads(fresh or '{}'), 'card_out', 'card_lock') or now
            except ValueError:
                pass
    if now - out >= grace:
        cl_card_end(h.store, part, s, CL_CARD_LATE, h.client_ip())
        return _cl_card_gone(CL_CARD_LATE)
    return {'ok': False, 'state': 'locked', 'left': max(0, int(grace - (now - out))),
            'grace': grace}


@route('POST', '/api/certlogin/alive')
def _certlogin_alive(h):
    """The check of the card (relayed by the page on the certificate's port, nginx's certificate
    with it): the same certificate as the sign-in's - alive; another - ended at once (every
    mode); none or nginx's refusal - signed out, or out and waiting (grace). 404 while the part
    does not watch the card."""
    b = h.body()
    part = str(b.get('part') or '')
    if part not in CL_PARTS or cl_card_mode(part) == 'off' or not cl_on(part):
        raise ApiError(404, 'the card is not watched here')
    token, s = cl_card_session(h, part)
    if not s:
        return {'ok': False, 'state': 'none'}
    if cl_card_unable(s):
        return {'ok': True, 'state': 'unable'}
    if not cl_card_watched(part, s):
        return {'ok': True, 'state': 'unwatched'}
    pem = str(b.get('cert') or '')
    failed = str(b.get('failed') or '')[:200]
    fp = cl_card_fp(pem) if pem and len(pem) <= CL_CERT_MOST and not failed else ''
    data = s.get('data') or {}
    want = str(data.get('card') or '')
    if fp and hmac.compare_digest(fp, want):
        st, why = cl_card_due(part, s, h.store)
        if st == 'gone':
            cl_card_end(h.store, part, s, why, h.client_ip())
            return _cl_card_gone(why)
        now = time.time()
        was = _cl_card_t(data, 'card_out', 'card_lock')
        ch = {}
        if was:
            ch.update(card_out=None, card_lock=None)
        if was or st == 'held' or now - _cl_card_t(data, 'card_seen', 'card_at') >= CL_CARD_SEEN_S:
            ch.update(card_seen=now, card_at=None)
        if _cl_card_ok(data) <= 0:
            # Found by a check in the background: this browser can be checked - from now on a
            # check without the card is a card taken out.
            ch['card_ok'] = round(now, 3)
        if ch:
            h.store.session_merge(s['id'], ch)
        if was:
            h.store.add_event('sign-ins' if part == 'admin' else 'portal',
                              '%s: the card they signed in with is back - the sign-in to %s goes '
                              'on (from %s)' % (s.get('name') or '?', 'these pages' if part ==
                                                'admin' else 'the enrolment pages',
                                                h.client_ip()), who=s.get('name') or None)
        return {'ok': True, 'state': 'ok', 'resumed': bool(was), 'every': cl_card_every(part)}
    if fp:
        cl_card_end(h.store, part, s, CL_CARD_OTHER, h.client_ip())
        return _cl_card_gone(CL_CARD_OTHER)
    return cl_card_failed(h, part, s, 'nginx did not take the certificate' if failed else
                          CL_CARD_WHY['nocert'])


@route('POST', '/api/certlogin/lost')
def _certlogin_lost(h):
    """The page's picture got no answer at all, twice (over 443, this page's own): the handshake
    failed - nothing to sign it with (why: nopicture); or it came back saying no cookie came with
    it (why: nocookie). Taken as the card out only while this node serves the certificate's port
    (else a port down is no card taken out) - never found in this browser, as one that cannot be
    checked (allow). It only ever ends, holds or leaves unwatched its own sign-in."""
    b = h.body()
    part = str(b.get('part') or '')
    said = str(b.get('why') or 'nopicture')
    said = said if said in ('nopicture', 'nocookie') else 'nopicture'
    if part not in CL_PARTS or cl_card_mode(part) == 'off' or not cl_on(part):
        raise ApiError(404, 'the card is not watched here')
    token, s = cl_card_session(h, part)
    if not s:
        return {'ok': False, 'state': 'none'}
    if cl_card_unable(s):
        return {'ok': True, 'state': 'unable'}
    if not cl_card_watched(part, s):
        return {'ok': True, 'state': 'unwatched'}
    if not cl_listening(cl_port()):
        return {'ok': True, 'state': 'unknown'}
    st, why = cl_card_due(part, s, h.store)
    if st == 'gone':
        cl_card_end(h.store, part, s, why, h.client_ip())
        return _cl_card_gone(why)
    return cl_card_failed(h, part, s, CL_CARD_WHY[said])


def _cl_portal_me_card(h, s):
    v = cl_card_view('portal', s, h.store)
    if not v:
        return {}
    # Out, or held: no role (as whoami's) - the page covered until the card is back.
    return dict({'card': v}, **({'role': ''} if v['locked'] or v['stale'] else {}))


PORTAL_ME.append(_cl_portal_me_card)
