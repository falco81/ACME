"""CSRs made the way a person trying to get past a profile makes them (1.0.102), by openssl
alone: one with two extensionRequest attributes (OpenSSL and a CA that takes the CSR as it
is read the first, acme checked the last), and ones with names or extensions a profile never
gives. Used by test_pki.py and test_req_profiles.py."""
import base64
import os
import subprocess
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402

UPN_SAN = 'subjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:administrator@corp.test'
SMARTCARD_EKU = 'extendedKeyUsage=clientAuth,1.3.6.1.4.1.311.20.2.2'


def _ossl(args, data=None):
    return subprocess.run(['openssl'] + args, input=data, capture_output=True,
                          check=True).stdout


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _len(len(body)) + body


def _items(buf):
    """[(tag, whole TLV bytes, content)] of the DER items one after another in buf."""
    out, i = [], 0
    while i < len(buf):
        tag, n, j = buf[i], buf[i + 1], i + 2
        if n & 0x80:
            k = n & 0x7f
            n, j = int.from_bytes(buf[j:j + k], 'big'), j + k
        out.append((tag, buf[i:j + n], buf[j:j + n]))
        i = j + n
    return out


def csr(key_pem, cn, *addext):
    """A CSR (PEM) of an EC key, made by openssl req with these -addext."""
    with tempfile.TemporaryDirectory() as d:
        kf = os.path.join(d, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key_pem)
        args = ['req', '-new', '-key', kf, '-subj', '/CN=%s' % cn]
        for a in addext:
            args += ['-addext', a]
        return _ossl(args).decode()


def _der(pem):
    body = ''.join(l for l in pem.splitlines() if l and not l.startswith('-----'))
    return base64.b64decode(body)


def two_ext_requests(key_pem, first, second, cn='www.example.test'):
    """A CSR signed by the EC key, with the extensionRequest of `first` (a list of -addext)
    and then that of `second` - as the hunt's mk_dualext_csr.py made it."""
    def parts(pem):
        cri = _items(_items(_der(pem))[0][2])[0][2]
        it = _items(cri)
        return it, [w for _t, w, _c in _items(it[3][2])]
    p1, a1 = parts(csr(key_pem, cn, *first))
    _p2, a2 = parts(csr(key_pem, cn, *second))
    cri = _tlv(0x30, p1[0][1] + p1[1][1] + p1[2][1] + _tlv(0xa0, a1[0] + a2[0]))
    with tempfile.TemporaryDirectory() as d:
        kf = os.path.join(d, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key_pem)
        sig = _ossl(['dgst', '-sha256', '-sign', kf], cri)
    alg = _tlv(0x30, _tlv(0x06, bytes.fromhex('2a8648ce3d040302')))     # ecdsa-with-SHA256
    der = _tlv(0x30, cri + alg + _tlv(0x03, b'\x00' + sig))
    b64 = base64.b64encode(der).decode()
    return '-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----\n' % \
        '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))


def _oid(s):
    p = [int(x) for x in s.split('.')]
    out = bytes([40 * p[0] + p[1]])
    for n in p[2:]:
        b = [n & 0x7f]
        n >>= 7
        while n:
            b.insert(0, 0x80 | (n & 0x7f))
            n >>= 7
        out += bytes(b)
    return _tlv(0x06, out)


def _attr(o, *vals):
    return _tlv(0x30, _oid(o) + _tlv(0x31, b''.join(vals)))


def _sign(key_pem, cri):
    with tempfile.TemporaryDirectory() as d:
        kf = os.path.join(d, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key_pem)
        sig = _ossl(['dgst', '-sha256', '-sign', kf], cri)
    alg = _tlv(0x30, _tlv(0x06, bytes.fromhex('2a8648ce3d040302')))     # ecdsa-with-SHA256
    der = _tlv(0x30, cri + alg + _tlv(0x03, b'\x00' + sig))
    b64 = base64.b64encode(der).decode()
    return '-----BEGIN CERTIFICATE REQUEST-----\n%s\n-----END CERTIFICATE REQUEST-----\n' % \
        '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))


def windows_csr(key_pem, cn='web01.example.test', pairs=(('CertificateTemplate', 'WebServer'),
                                                         ('SAN', 'dns=web01.example.test'))):
    """A CSR as Windows certreq -new / ConfigMgr makes it: the OS version attribute, each
    enrollment name-value pair (1.3.6.1.4.1.311.13.2.1) an attribute of its own, then the
    extensionRequest (subjectAltName DNS:cn)."""
    def bmp(s):
        return _tlv(0x1e, s.encode('utf-16-be'))
    base = csr(key_pem, cn, 'subjectAltName=DNS:%s' % cn)
    it = _items(_items(_items(_der(base))[0][2])[0][2])
    ext_attr = [w for _t, w, _c in _items(it[3][2])][0]
    attrs = _attr('1.3.6.1.4.1.311.13.2.3', _tlv(0x16, b'10.0.20348.2'))
    for n, v in pairs:
        attrs += _attr('1.3.6.1.4.1.311.13.2.1', _tlv(0x30, bmp(n) + bmp(v)))
    cri = _tlv(0x30, it[0][1] + it[1][1] + it[2][1] + _tlv(0xa0, attrs + ext_attr))
    return _sign(key_pem, cri)


def msext_csr(key_pem, cn='www.example.test', *addext):
    """A CSR whose extensions (`addext`, subjectAltName DNS:cn where they name none) are in Microsoft's old
    msExtReq attribute (1.3.6.1.4.1.311.2.1.14) instead of a standard extensionRequest: AD CS
    reads them, acme does not (1.0.102)."""
    if not any(a.startswith('subjectAltName') for a in addext):
        addext = ('subjectAltName=DNS:%s' % cn,) + tuple(addext)
    base = csr(key_pem, cn, *addext)
    it = _items(_items(_items(_der(base))[0][2])[0][2])
    ext_attr = _items(it[3][2])[0][2]              # OID, SET of the extensionRequest
    the_set = _items(ext_attr)[1][1]
    cri = _tlv(0x30, it[0][1] + it[1][1] + it[2][1] + _tlv(0xa0, _tlv(
        0x30, _oid('1.3.6.1.4.1.311.2.1.14') + the_set)))
    return _sign(key_pem, cri)
