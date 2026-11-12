# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- certificates: read, taken apart, made -----------------------------------
def _openssl(args, data=None, env=None, what='openssl', secret=None):
    """openssl run; a passphrase (`secret`) handed over on a pipe of its own
    (1.0.205), named 'fd:@' in args - never on the command line nor in the
    environment, where /proc keeps it; stdin stays for the data."""
    e = dict(os.environ)
    e.update(env or {})
    fds = ()
    rd = wr = None
    if secret is not None:
        rd, wr = os.pipe()
        args = ['fd:%d' % rd if a == 'fd:@' else a for a in args]
        fds = (rd,)
        os.write(wr, (str(secret) + '\n').encode('utf-8'))
        os.close(wr)
    try:
        got = subprocess.run(['openssl'] + args, input=data, capture_output=True, env=e,
                             timeout=3600 if args[:1] == ['enc'] else 120, pass_fds=fds)
    finally:
        if rd is not None:
            os.close(rd)
    if got.returncode != 0:
        said = (got.stderr or got.stdout or b'').decode('utf-8', 'replace').strip()
        raise ValueError('%s: %s' % (what, (said.splitlines() or ['openssl said no'])[-1][:200]))
    return got.stdout


TLS_EXPORT_KINDS = {
    # kind: (what it is, its file's ending, the private key in it)
    'pem': ('the certificate, PEM', '.crt', False),
    'fullchain': ('the certificate and its chain, PEM', '-fullchain.pem', False),
    'der': ('the certificate, DER', '.cer', False),
    'p7b': ('the certificate and its chain, PKCS#7', '.p7b', False),
    'pfx': ('the certificate, its chain and its private key, PKCS#12', '.pfx', True),
    'pemkey': ('the certificate, its chain and its private key, PEM (the key locked)', '-with-key.pem', True),
}


def tls_export(prof, kind, passphrase='', legacy=False, which='rsa'):
    """One certificate as a file to download (1.0.191): (bytes, ending). A private
    key in it is always locked with the passphrase - given to openssl on its
    stdin, never on a command line; its file only in a folder of 0700, gone after.
    `which` (otp 1.0.240): the main certificate ('rsa'), the second one beside it ('ec'), or
    both ('both': a .zip of the two, each as asked). 'main' and 'alt' (acme 1.0.34) are the
    same as 'rsa' and 'ec'."""
    if kind not in TLS_EXPORT_KINDS:
        raise ValueError('pem, fullchain, der, p7b, pfx or pemkey')
    which = {'main': 'rsa', 'alt': 'ec'}.get(str(which or 'rsa'), str(which or 'rsa'))
    if which in ('ec', 'both'):
        alt = tls_alt(prof) or ((prof or {}).get('alt') if ((prof or {}).get('alt') or {}).get('cert')
                                else None)
        if not alt:
            raise ValueError('there is no second (ECDSA) certificate beside this one')
        second = dict(alt, root=prof.get('root') or '')
        if which == 'ec':
            return tls_export(second, kind, passphrase, legacy)
        import zipfile
        a, ending = tls_export(prof, kind, passphrase, legacy)
        b2, _ = tls_export(second, kind, passphrase, legacy)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            z.writestr('rsa' + ending, a)
            z.writestr('ecdsa' + ending, b2)
        return buf.getvalue(), '.zip'
    if which != 'rsa':
        raise ValueError('rsa, ec or both')
    cert = str(prof.get('cert') or '').strip()
    if not cert:
        raise ValueError('no certificate is kept for it')
    chain = '\n'.join(x.strip() for x in (prof.get('chain') or '', prof.get('root') or '') if x and x.strip())
    _what, ending, with_key = TLS_EXPORT_KINDS[kind]
    if kind == 'pem':
        return (cert + '\n').encode(), ending
    if kind == 'fullchain':
        return (cert + '\n' + (chain + '\n' if chain else '')).encode(), ending
    if kind == 'der':
        return _openssl(['x509', '-outform', 'DER'], cert.encode(), what='the certificate'), ending
    with tempfile.TemporaryDirectory(prefix='acme-tlsx-') as t:
        os.chmod(t, 0o700)
        cf = os.path.join(t, 'cert.pem')
        with open(cf, 'w') as f:
            f.write(cert + '\n' + (chain + '\n' if chain else ''))
        if kind == 'p7b':
            return _openssl(['crl2pkcs7', '-nocrl', '-certfile', cf, '-outform', 'DER'],
                            what='the PKCS#7 bundle'), ending
        if len(passphrase) < 10:
            raise ValueError('a passphrase of 10 characters at least locks the private key')
        key = unseal_secret(prof.get('key') or '', 'web:tls') if prof.get('key') else ''
        if not key:
            raise ValueError('the private key is not kept here (made elsewhere, or let go)')
        kf = os.path.join(t, 'key.pem')
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(key)
        try:
            if kind == 'pfx':
                args = ['pkcs12', '-export', '-inkey', kf, '-in', cf, '-passout', 'stdin',
                        '-name', (cert_info(cert).get('cn') or 'acme')[:64]]
                if legacy:
                    # Windows before 10 1709 / Server 2016 open no AES PKCS#12.
                    args += ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1']
                return _openssl(args, (passphrase + '\n').encode(), what='the PKCS#12 file'), ending
            locked = _openssl(['pkey', '-in', kf, '-aes256', '-passout', 'stdin'],
                              (passphrase + '\n').encode(), what='locking the key').decode()
            return (cert + '\n' + (chain + '\n' if chain else '') + locked).encode(), ending
        finally:
            try:
                with open(kf, 'w') as f:
                    f.write('\0' * len(key))
            except OSError:
                pass


PEM_CERT = re.compile(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----')
PEM_KEY = re.compile(r'-----BEGIN ((?:RSA |EC |ENCRYPTED )?PRIVATE KEY)-----[A-Za-z0-9+/=\s:,-]+?'
                     r'-----END \1-----')


def cert_info(pem):
    """What a certificate says of itself, for the pages."""
    out = _openssl(['x509', '-noout', '-subject', '-issuer', '-startdate', '-enddate',
                    '-fingerprint', '-sha256', '-ext', 'subjectAltName', '-nameopt',
                    'RFC2253'], pem.encode(), what='the certificate').decode()
    info = {'san': []}
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line.startswith('subject='):
            info['subject'] = line[8:].strip()
        elif line.startswith('issuer='):
            info['issuer'] = line[7:].strip()
        elif line.startswith('notBefore='):
            info['not_before'] = _cert_time(line[10:])
        elif line.startswith('notAfter='):
            info['not_after'] = _cert_time(line[9:])
        elif 'Fingerprint=' in line:
            info['fingerprint'] = line.split('=', 1)[1].strip()
        elif 'Subject Alternative Name' in line and i + 1 < len(lines):
            info['san'] = [x.strip().split(':', 1)[-1] for x in lines[i + 1].split(',')
                           if x.strip()]
    info['self_signed'] = info.get('subject') == info.get('issuer')
    cn = re.search(r'(?:^|,)CN=([^,]+)', info.get('subject') or '')
    info['cn'] = cn.group(1) if cn else ''
    try:
        pub = _openssl(['x509', '-noout', '-pubkey'], pem.encode()).decode()
        txt = _openssl(['pkey', '-pubin', '-noout', '-text'], pub.encode()).decode()
        m = re.search(r'\((\d+) bit\)', txt)
        info['key'] = ('%s %s bit' % ('EC' if 'ASN1 OID' in txt or 'NIST' in txt else 'RSA',
                                      m.group(1))) if m else ''
    except ValueError:
        info['key'] = ''
    return info


def _cert_time(text):
    try:
        return datetime.strptime(text.strip().replace('  ', ' '),
                                 '%b %d %H:%M:%S %Y %Z').replace(
            tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def _pub_of_cert(pem):
    return _openssl(['x509', '-noout', '-pubkey'], pem.encode(), what='the certificate')


def _pub_of_key(pem):
    return _openssl(['pkey', '-pubout'], pem.encode(), what='the key')


def key_plain(pem, password=''):
    """A private key without its passphrase, as PEM."""
    return _openssl(['pkey', '-passin', 'fd:@'], pem.encode(), secret=password or '',
                    what='the key (a wrong or missing password?)').decode()


def cert_bundle(cert='', key='', chain='', root='', pfx=b'', password='', pending_key=''):
    """Whatever was sent - one PEM with everything in it, separate parts, or
    a PFX / PKCS#12 with or without a password - as the parts nginx needs:
    the certificate, its key, the chain up from it, the root. The key is the
    certificate's own or nothing is taken."""
    certs, keys = [], []
    if pfx:
        got = None
        for extra in ([], ['-legacy']):
            try:
                got = _openssl(['pkcs12', '-nodes', '-passin', 'fd:@'] + extra, pfx,
                               secret=password or '', what='the PFX / PKCS#12 file')
                break
            except ValueError as e:
                last = e
        if got is None:
            raise ValueError('%s - is the password right?' % last)
        text = got.decode('utf-8', 'replace')
        certs += [m.group(0) for m in PEM_CERT.finditer(text)]
        keys += [m.group(0) for m in PEM_KEY.finditer(text)]
    for part in (cert, chain, root, key):
        part = str(part or '')
        certs += [m.group(0) for m in PEM_CERT.finditer(part)]
        keys += [m.group(0) for m in PEM_KEY.finditer(part)]
    if not certs:
        raise ValueError('no certificate was found in what was sent (PEM, or a PFX / PKCS#12 '
                         'file)')
    if len(keys) > 1:
        raise ValueError('more than one private key was sent')
    if keys:
        key_pem = key_plain(keys[0], password)
    elif pending_key:
        key_pem = pending_key
    else:
        raise ValueError('no private key came with it: send the key too (or the PFX), or make '
                         'the request here first so the key is waiting')
    want = _pub_of_key(key_pem)
    leaf = next((c for c in certs if _pub_of_cert(c) == want), None)
    if not leaf:
        raise ValueError('none of the certificates is the one of this key')
    others = [c for c in certs if c != leaf]
    infos = {c: cert_info(c) for c in others}
    roots = [c for c in others if infos[c]['self_signed']]
    roots += [m.group(0) for m in PEM_CERT.finditer(str(root or '')) if m.group(0) not in roots]
    inter = [c for c in others if c not in roots]
    # The chain in order: each the issuer of the one before it.
    chain_out, at = [], cert_info(leaf)
    while inter:
        nxt = next((c for c in inter if infos[c].get('subject') == at.get('issuer')), None)
        if not nxt:
            chain_out += inter
            break
        chain_out.append(nxt)
        inter.remove(nxt)
        at = infos[nxt]
    info = cert_info(leaf)
    verify = ''
    if roots:
        with tempfile.TemporaryDirectory(prefix='acme-cert-') as t:
            def put(name, text):
                p = os.path.join(t, name)
                with open(p, 'w') as f:
                    f.write(text)
                return p
            args = ['verify', '-CAfile', put('root.pem', '\n'.join(roots) + '\n')]
            if chain_out:
                args += ['-untrusted', put('chain.pem', '\n'.join(chain_out) + '\n')]
            args.append(put('leaf.pem', leaf + '\n'))
            try:
                _openssl(args, what='the chain')
                verify = 'ok'
            except ValueError as e:
                verify = str(e)
    # The whole chain (1.0.89): checked against the system's roots as clients that fetch
    # nothing check it, completed from the CA Issuers addresses where it does not reach one.
    chain_out, chain_state = chain_complete(leaf, chain_out, ''.join(c + '\n' for c in roots))
    return {'cert': leaf + '\n', 'chain': ''.join(c + '\n' for c in chain_out),
            'root': ''.join(c + '\n' for c in roots), 'key': key_pem, 'info': info,
            'chain_info': [cert_info(c) for c in chain_out],
            'root_info': [cert_info(c) for c in roots], 'verify': verify,
            'chain_state': chain_state}


# ---- the whole chain (1.0.89) ------------------------------------------------------------
# nginx must send the certificate with every intermediate authority up to (not including) a
# root. Browsers fetch a missing intermediate themselves (Authority Information Access -> CA
# Issuers) and say nothing; curl, Python, Java, Go, rsyslog, the other applications (acme
# push) and the monitoring agents do not, and refuse the connection. So whatever comes - an
# upload, a PFX, a request signed elsewhere, ACME, acme push - is checked against the system's
# roots, and a chain that does not reach one is completed as browsers do it: the intermediate
# fetched from its CA Issuers address, at most four steps. What is fetched is trusted only as
# a link to a root of the system; a root is never sent.
CHAIN_CA_FILES = ('/etc/pki/tls/certs/ca-bundle.crt',
                  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
                  '/etc/ssl/certs/ca-certificates.crt')
CHAIN_FETCHED = {}                  # url -> (when, [pem]) - kept a day


def chain_ca_file():
    for f in (os.environ.get('ACME_CHAIN_CA'),) + CHAIN_CA_FILES:
        if f and os.path.isfile(f):
            return f
    return None


def chain_verify(leaf, chain, roots=''):
    """(True, '') when leaf + chain lead to a root of the system (or to `roots`, a private CA
    given with it); else (False, what openssl said - without the paths of its files)."""
    ca = chain_ca_file()
    bundle = ''
    if ca:
        try:
            with open(ca) as f:
                bundle = f.read()
        except OSError:
            bundle = ''
    bundle += '\n' + (roots or '')
    if '-----BEGIN CERTIFICATE-----' not in bundle:
        return False, 'the system has no list of root authorities to check against'
    with tempfile.TemporaryDirectory(prefix='acme-chain-') as t:
        def put(name, text):
            p = os.path.join(t, name)
            with open(p, 'w') as f:
                f.write(text)
            return p
        args = ['verify', '-CAfile', put('ca.pem', bundle)]
        if chain.strip():
            args += ['-untrusted', put('chain.pem', chain)]
        args.append(put('leaf.pem', leaf))
        try:
            got = subprocess.run(['openssl'] + args, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, 'the chain could not be checked: %s' % e
        if got.returncode == 0:
            return True, ''
        # the reason (1.0.93): "error 20 at 0 depth lookup: unable to get local issuer
        # certificate" - the last line says only "verification failed"
        out = (got.stdout + b'\n' + got.stderr).decode('utf-8', 'replace')
        why = [ln for ln in out.splitlines() if 'lookup:' in ln or re.match(r'error \d+ at', ln)]
        text = re.sub(r'^error \d+ at \d+ depth lookup:\s*', '', why[0].strip()) if why else \
            ((out.strip().splitlines() or ['verification failed'])[-1])
        return False, re.sub(r'(error )?\S*acme-chain-\S*:\s*', '', text).strip()[:300]


def aia_issuer_url(pem):
    """The CA Issuers address of a certificate (http or https, as the CAs publish it)."""
    try:
        out = _openssl(['x509', '-noout', '-ext', 'authorityInfoAccess'], pem.encode(),
                       what='the certificate').decode('utf-8', 'replace')
    except ValueError:
        return ''
    m = re.search(r'CA Issuers\s*-\s*URI:(https?://\S+)', out)
    return m.group(1) if m else ''


def aia_fetch(url):
    """The certificates at a CA Issuers address - DER, PEM or PKCS#7 - as PEM (kept a day)."""
    got = CHAIN_FETCHED.get(url)
    if got and time.time() - got[0] < 86400:
        return got[1]
    if not re.match(r'^https?://[A-Za-z0-9.-]+(:\d+)?/\S*\Z', url):
        return []
    with url_open(urllib.request.Request(url, headers={'User-Agent': 'acme/%s' % __version__}),
                  timeout=15, purpose='acme') as r:
        raw = r.read(262145)
    if len(raw) > 262144:
        return []
    pems = []
    if b'-----BEGIN' in raw:
        text = raw.decode('ascii', 'replace')
        if '-----BEGIN PKCS7-----' in text:
            try:
                text = _openssl(['pkcs7', '-print_certs'], raw,
                                what='PKCS#7').decode('ascii', 'replace')
            except ValueError:
                text = ''
        pems = [m.group(0) for m in PEM_CERT.finditer(text)]
    else:
        for args in (['x509', '-inform', 'DER'], ['pkcs7', '-inform', 'DER', '-print_certs']):
            try:
                text = _openssl(args, raw, what='the authority').decode('ascii', 'replace')
            except ValueError:
                continue
            pems = [m.group(0) for m in PEM_CERT.finditer(text)]
            if pems:
                break
    CHAIN_FETCHED[url] = (time.time(), pems[:6])
    return pems[:6]


def _cn_of(dn):
    m = re.search(r'(?:^|,)\s*CN\s*=\s*([^,]+)', str(dn or ''))
    return (m.group(1) if m else str(dn or '?')).strip()


def chain_complete(leaf, chain_out, roots=''):
    """The chain checked against the system's roots and, where it does not reach one,
    completed from the CA Issuers addresses: (the chain, a list of PEM; its state
    {ok: True | False | None, words, fetched, missing, private_root})."""
    leaf = leaf.strip()
    chain_out = [c.strip() for c in chain_out]
    if cert_info(leaf).get('self_signed'):
        return chain_out, {'ok': None, 'fetched': [],
                           'words': 'self-signed - no chain; whoever connects must trust this '
                                    'certificate itself'}

    def joined(cs):
        return ''.join(c + '\n' for c in cs)
    ok, why = chain_verify(leaf + '\n', joined(chain_out), roots)
    fetched, chain = [], list(chain_out)
    tried, root_seen = 0, ''
    # only a link missing is fetched (1.0.93): an expired or wrong one, or a machine without
    # its roots, said it led to a root nobody trusted - and offered to complete it
    missing = re.compile(r'unable to get (local )?issuer certificate', re.I)
    if not ok and not missing.search(why or ''):
        return chain_out, {'ok': False, 'fetched': [], 'missing': '',
                           'words': 'the chain does not check: %s' % (why or '?')[:300]}
    while not ok and tried < 4:
        tried += 1
        last = chain[-1] if chain else leaf
        info = cert_info(last)
        if info.get('self_signed'):
            break
        url = aia_issuer_url(last)
        if not url:
            why = '%s names no CA Issuers address to fetch it from' % (
                info.get('cn') or 'the certificate')
            break
        try:
            got = aia_fetch(url)
        except Exception as e:                          # noqa: BLE001
            why = 'the authority %s could not be fetched from %s: %s' % (
                _cn_of(info.get('issuer')), url, getattr(e, 'reason', e))
            break
        nxt = next((c for c in got if cert_info(c).get('subject') == info.get('issuer')), None)
        if not nxt:
            why = '%s does not hold the authority %s' % (url, _cn_of(info.get('issuer')))
            break
        ni = cert_info(nxt)
        if ni.get('self_signed'):
            root_seen = ni.get('cn') or ni.get('subject')
            break                       # a root: never sent - it has to be the system's own
        chain.append(nxt.strip())
        fetched.append(ni.get('cn') or ni.get('subject'))
        ok, why = chain_verify(leaf + '\n', joined(chain), roots)
    n = len(chain)
    if ok:
        top = cert_info(chain[-1] if chain else leaf).get('issuer')
        words = 'complete - %d certificates up to %s' % (n + 1, _cn_of(top))
        if fetched:
            words += ' (fetched: %s - it was not sent with the certificate)' % ', '.join(fetched)
        if roots and not chain_verify(leaf + '\n', joined(chain))[0]:
            words += ' - a private root: only clients that trust it take it'
        return chain, {'ok': True, 'words': words, 'fetched': fetched}
    if root_seen:
        return chain, {'ok': False, 'fetched': fetched, 'missing': '', 'private_root': root_seen,
                       'words': 'it leads to %s, a root the system does not trust (a private '
                                'CA?) - the chain is complete; the clients must trust that '
                                'root, or give its root here' % root_seen}
    last = cert_info(chain[-1] if chain else leaf)
    return (chain if fetched else chain_out), {
        'ok': False, 'fetched': fetched, 'missing': _cn_of(last.get('issuer')),
        'words': 'incomplete - the authority %s is not sent and could not be completed (%s); '
                 'curl, other applications and monitoring refuse it - only browsers fetch it '
                 'themselves; send the certificate with its chain, or, for a private CA, its '
                 'root to the clients' % (_cn_of(last.get('issuer')), why[:200])}


def cert_bundles(cert='', key='', chain='', root='', pfx=b'', password='', pending_key='',
                 pfx2=b'', password2=''):
    """As cert_bundle - and, when two keys came (otp 1.0.240: an RSA and an ECDSA certificate of the
    same names, in the PEM or as two PFX files), both: (the RSA one, the ECDSA one as a second
    certificate beside it) - as ACME's "both" keeps them. One key: (the bundle, None), as until
    now."""
    texts = []
    for blob, pw in ((pfx, password), (pfx2, password2 or password)):
        if not blob:
            continue
        got = None
        for extra in ([], ['-legacy']):
            try:
                got = _openssl(['pkcs12', '-nodes', '-passin', 'fd:@'] + extra, blob,
                               secret=pw or '', what='the PFX / PKCS#12 file')
                break
            except ValueError as e:
                last = e
        if got is None:
            raise ValueError('%s - is the password right?' % last)
        texts.append(got.decode('utf-8', 'replace'))
    keys = []
    for part in texts + [str(cert or ''), str(chain or ''), str(root or ''), str(key or '')]:
        keys += [m.group(0) for m in PEM_KEY.finditer(part)]
    if len(keys) <= 1 and not pfx2:
        return cert_bundle(cert, key, chain, root, pfx, password, pending_key), None
    if len(keys) != 2:
        raise ValueError('two certificates come with two keys - one RSA, one ECDSA (%d key(s) '
                         'came)' % len(keys))
    certs = []
    for part in texts + [str(cert or ''), str(chain or ''), str(root or '')]:
        certs += [m.group(0) for m in PEM_CERT.finditer(part) if m.group(0) not in certs]
    plain = [key_plain(k, password) for k in keys]
    leaves = []
    for k in plain:
        want = _pub_of_key(k)
        leaf = next((c for c in certs if _pub_of_cert(c) == want), None)
        if not leaf:
            raise ValueError('one of the two keys has no certificate of its own among those sent')
        leaves.append(leaf)
    got = []
    for i, k in enumerate(plain):
        rest = [c for c in certs if c != leaves[1 - i]]
        got.append(cert_bundle(cert='\n'.join(rest), key=k))
    kinds = [str(g['info'].get('key') or '').split(' ')[0] for g in got]
    if sorted(kinds) != ['EC', 'RSA']:
        raise ValueError('two certificates: one with an RSA key and one with an ECDSA key '
                         '(these are %s)' % ' and '.join(kinds))
    main, alt = (got[0], got[1]) if kinds[0] == 'RSA' else (got[1], got[0])
    names = lambda g: sorted(set([g['info'].get('cn') or ''] + list(g['info'].get('san') or [])) - {''})
    if names(main) != names(alt):
        raise ValueError('the two certificates are not of the same names (%s / %s)'
                         % (', '.join(names(main)), ', '.join(names(alt))))
    return main, alt

def _san_ext(names):
    out = []
    for n in names:
        n = str(n).strip()
        if not n:
            continue
        try:
            plain_ip(n, 'address')
            out.append('IP:' + n)
        except ValueError:
            if not re.match(r'^(\*\.)?[A-Za-z0-9.-]{1,253}\Z', n):
                raise ValueError('%r is not a name or an address' % n)
            out.append('DNS:' + n)
    return ','.join(out)


def _subject(cn, org='', unit='', country='', city=''):
    def esc(v):
        return re.sub(r'([/\\=+,])', r'\\\1', str(v).strip())
    if not cn or not re.match(r'^[A-Za-z0-9*.-]{1,64}\Z', cn):
        raise ValueError('the common name is a host name')
    s = '/CN=' + esc(cn)
    if org:
        s += '/O=' + esc(org)
    if unit:
        s += '/OU=' + esc(unit)
    if city:
        s += '/L=' + esc(city)
    if country:
        if not re.match(r'^[A-Za-z]{2}\Z', country):
            raise ValueError('the country is two letters (CZ)')
        s += '/C=' + country.upper()
    return s


def new_key(kind):
    # ECDSA P-256 or P-384, RSA 2048, 3072 or 4096 (1.0.196): what Let's Encrypt
    # takes for a certificate.
    curve = {'ec': 'P-256', 'ec256': 'P-256', 'ec384': 'P-384'}.get(kind)
    if curve:
        return _openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt',
                         'ec_paramgen_curve:%s' % curve]).decode()
    bits = {'rsa2048': 2048, 'rsa3072': 3072, 'rsa4096': 4096}.get(kind)
    if not bits:
        raise ValueError('the key is ec (P-256), ec384, rsa2048, rsa3072 or rsa4096')
    return _openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt',
                     'rsa_keygen_bits:%d' % bits]).decode()


def make_csr(cn, names, kind='rsa2048', **subject):
    key = new_key(kind)
    with tempfile.TemporaryDirectory(prefix='acme-csr-') as t:
        kf = os.path.join(t, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key)
        # A name longer than a CN may be (64) goes in the names alone (1.0.205), as
        # Let's Encrypt takes it - refused here, after the CA had been asked.
        long_ = len(cn or '') > 64 and re.match(r'^[A-Za-z0-9*.-]{1,253}\Z', cn or '')
        csr = _openssl(['req', '-new', '-key', kf, '-subj', '/' if long_ else _subject(cn, **subject),
                        '-addext', 'subjectAltName=' + _san_ext([cn] + list(names))],
                       what='the request').decode()
    return key, csr


def make_selfsigned(cn, names, days=825, kind='rsa2048', **subject):
    key = new_key(kind)
    with tempfile.TemporaryDirectory(prefix='acme-crt-') as t:
        kf = os.path.join(t, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key)
        crt = _openssl(['req', '-new', '-x509', '-key', kf, '-days', str(int(days)), '-subj',
                        _subject(cn, **subject), '-addext',
                        'subjectAltName=' + _san_ext([cn] + list(names))],
                       what='the certificate').decode()
    return key, crt


