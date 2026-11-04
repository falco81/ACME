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


def tls_export(prof, kind, passphrase='', legacy=False, which='main'):
    """One certificate as a file to download (1.0.191): (bytes, ending). A private
    key in it is always locked with the passphrase - given to openssl on its
    stdin, never on a command line; its file only in a folder of 0700, gone after.
    `which` (1.0.34): a dual one's main certificate, its second (alt: the ECDSA
    one beside the RSA one), or both - PEM only, one after the other."""
    if kind not in TLS_EXPORT_KINDS:
        raise ValueError('pem, fullchain, der, p7b, pfx or pemkey')
    which = str(which or 'main')
    if which in ('alt', 'both'):
        alt = (prof or {}).get('alt') or {}
        if not alt.get('cert'):
            raise ValueError('there is no second certificate beside it')
        second = dict(prof, cert=alt['cert'], chain=alt.get('chain') or '', key=alt.get('key') or '')
        if which == 'alt':
            return tls_export(second, kind, passphrase, legacy)
        if kind not in ('pem', 'fullchain', 'pemkey'):
            raise ValueError('both certificates go into a PEM file only (one after the other)')
        a, ending = tls_export(prof, kind, passphrase, legacy)
        b2, _e = tls_export(second, kind, passphrase, legacy)
        return a + b2, ending
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
    return {'cert': leaf + '\n', 'chain': ''.join(c + '\n' for c in chain_out),
            'root': ''.join(c + '\n' for c in roots), 'key': key_pem, 'info': info,
            'chain_info': [cert_info(c) for c in chain_out],
            'root_info': [cert_info(c) for c in roots], 'verify': verify}


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


