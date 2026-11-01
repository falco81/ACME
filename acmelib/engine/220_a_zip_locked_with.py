# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- a ZIP locked with a passphrase: WinZip AES-256 (1.0.167) ----------------------------
# The .totp files of the tokens, as the export gives them: every entry AES-256
# in CTR mode with an HMAC-SHA1 over it (WinZip's AE-2, compression method 99),
# its key from the passphrase by PBKDF2-HMAC-SHA1 - what 7-Zip, WinRAR, PeaZip
# and `7z x` open, and acme reads back. AES itself from `cryptography` where the
# system has it, else here in Python: a few kilobytes a token, not much to do.
_AES_SBOX = None


def _aes_tables():
    global _AES_SBOX
    if _AES_SBOX is None:
        sbox = [0] * 256
        p = q = 1
        while True:
            p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
            q ^= q << 1
            q ^= q << 2
            q ^= q << 4
            q &= 0xFF
            if q & 0x80:
                q ^= 0x09
            x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ \
                ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
            sbox[p] = (x ^ 0x63) & 0xFF
            if p == 1:
                break
        sbox[0] = 0x63
        _AES_SBOX = sbox
    return _AES_SBOX


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


class _Aes256(object):
    """AES-256, encryption only (CTR needs no more)."""
    def __init__(self, key):
        sb = _aes_tables()
        w = [list(key[i:i + 4]) for i in range(0, 32, 4)]
        rcon = 1
        for i in range(8, 60):
            t = list(w[i - 1])
            if i % 8 == 0:
                t = [sb[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _xt(rcon)
            elif i % 8 == 4:
                t = [sb[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i - 8], t)])
        self.rk = [sum(w[r * 4:r * 4 + 4], []) for r in range(15)]
        self.sb = sb

    def block(self, data):
        sb, rk = self.sb, self.rk
        s = [a ^ b for a, b in zip(data, rk[0])]
        for r in range(1, 15):
            s = [sb[x] for x in s]
            s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]       # ShiftRows
            if r != 14:
                m = []
                for c in range(4):
                    a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                    t = a0 ^ a1 ^ a2 ^ a3
                    m += [a0 ^ t ^ _xt(a0 ^ a1), a1 ^ t ^ _xt(a1 ^ a2),
                          a2 ^ t ^ _xt(a2 ^ a3), a3 ^ t ^ _xt(a3 ^ a0)]
                s = m
            s = [a ^ b for a, b in zip(s, rk[r])]
        return bytes(s)


def _aes_ctr_le(key, data):
    """WinZip's CTR: a 16-byte little-endian counter from 1, the same both ways."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        Cipher = None
    out = bytearray()
    if Cipher is not None:
        enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
        stream = enc.update(b''.join((n + 1).to_bytes(16, 'little')
                                     for n in range((len(data) + 15) // 16)))
    else:
        aes = _Aes256(key)
        stream = b''.join(aes.block((n + 1).to_bytes(16, 'little'))
                          for n in range((len(data) + 15) // 16))
    out.extend(a ^ b for a, b in zip(data, stream))
    return bytes(out)


def _ae_keys(passphrase, salt):
    k = hashlib.pbkdf2_hmac('sha1', str(passphrase).encode('utf-8'), salt, 1000, 66)
    return k[:32], k[32:64], k[64:66]


_AE_EXTRA = struct.pack('<HHH2sBH', 0x9901, 7, 2, b'AE', 3, 8)


def zip_aes_write(files, passphrase):
    """[(name, bytes)] -> the bytes of a ZIP, every entry locked (AE-2)."""
    buf = io.BytesIO()
    central = []
    t = time.localtime()
    dtime = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    ddate = ((max(t.tm_year, 1980) - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    for name, data in files:
        fname = str(name).encode('utf-8')
        comp = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = comp.compress(data) + comp.flush()
        salt = secrets.token_bytes(16)
        ekey, akey, check = _ae_keys(passphrase, salt)
        body = _aes_ctr_le(ekey, packed)
        mac = hmac.new(akey, body, hashlib.sha1).digest()[:10]
        blob = salt + check + body + mac
        off = buf.tell()
        flags = 0x0001 | 0x0800                # locked, the name in UTF-8
        head = struct.pack('<IHHHHHIIIHH', 0x04034B50, 51, flags, 99, dtime, ddate, 0,
                           len(blob), len(data), len(fname), len(_AE_EXTRA))
        buf.write(head + fname + _AE_EXTRA + blob)
        central.append(struct.pack('<IHHHHHHIIIHHHHHII', 0x02014B50, 0x031E, 51, flags, 99,
                                   dtime, ddate, 0, len(blob), len(data), len(fname),
                                   len(_AE_EXTRA), 0, 0, 0, 0o100600 << 16, off) +
                       fname + _AE_EXTRA)
    cd_off = buf.tell()
    for c in central:
        buf.write(c)
    buf.write(struct.pack('<IHHHHIIH', 0x06054B50, 0, 0, len(central), len(central),
                          buf.tell() - cd_off, cd_off, 0))
    return buf.getvalue()


def zip_is_locked(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            return any(i.flag_bits & 1 for i in z.infolist())
    except zipfile.BadZipFile:
        return False


def zip_aes_open(raw, info, passphrase, most=64 * 1024):
    """One entry of a locked ZIP (AE-1/AE-2, AES-256 made by acme, 7-Zip or
    WinZip), opened; ValueError when the passphrase is not its own."""
    if info.compress_type != 99:
        raise ValueError('%s is locked the old ZipCrypto way - only AES is read' % info.filename)
    ex = info.extra
    strength, method = None, None
    i = 0
    while i + 4 <= len(ex):
        hid, size = struct.unpack('<HH', ex[i:i + 4])
        if hid == 0x9901 and size >= 7:
            _ver, _ae, strength, method = struct.unpack('<H2sBH', ex[i + 4:i + 11])
        i += 4 + size
    if strength != 3:
        raise ValueError('%s: only AES-256 is read' % info.filename)
    off = info.header_offset
    sig, = struct.unpack('<I', raw[off:off + 4])
    if sig != 0x04034B50:
        raise ValueError('the ZIP is damaged')
    n, m = struct.unpack('<HH', raw[off + 26:off + 30])
    start = off + 30 + n + m
    blob = raw[start:start + info.compress_size]
    if len(blob) < 28:
        raise ValueError('the ZIP is damaged')
    salt, check, body, mac = blob[:16], blob[16:18], blob[18:-10], blob[-10:]
    ekey, akey, want = _ae_keys(passphrase, salt)
    if not hmac.compare_digest(check, want) or \
            not hmac.compare_digest(mac, hmac.new(akey, body, hashlib.sha1).digest()[:10]):
        raise PermissionError('the passphrase does not open it')
    packed = _aes_ctr_le(ekey, body)
    if method == 0:
        return packed[:most + 1]
    if method != 8:
        raise ValueError('%s: compressed in a way acme does not read' % info.filename)
    d = zlib.decompressobj(-15)
    return d.decompress(packed, most + 1)


