# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# One-time passwords: RFC 4226 (HOTP) and RFC 6238 (TOTP)
# ---------------------------------------------------------------------------
# What the phone does, done again here: the key and the number of thirty-
# second periods since 1970 go through HMAC, and six digits are cut out of the
# answer - the second step of an administrator's sign-in with an
# authenticator app. Nothing in this needs anything but hashlib and hmac.
HASHES = {'SHA1': hashlib.sha1, 'SHA256': hashlib.sha256, 'SHA512': hashlib.sha512}


def b32_clean(text):
    """A base32 key as somebody may have written it - small letters, spaces,
    dashes, no padding - as the bytes it stands for. ValueError if it is not
    base32 at all."""
    said = re.sub(r'[\s\-]', '', str(text or '')).upper().rstrip('=')
    if not said or not re.match(r'^[A-Z2-7]+\Z', said):
        raise ValueError('that is not a base32 key (A-Z and 2-7)')
    pad = '=' * ((8 - len(said) % 8) % 8)
    return base64.b32decode(said + pad)


def b32_new(size=20):
    """A fresh key: 160 bits, the size RFC 4226 recommends, as base32."""
    return base64.b32encode(secrets.token_bytes(size)).decode('ascii').rstrip('=')


def hotp(key, counter, digits=6, algorithm='SHA1'):
    """The code for one counter value, as a string of `digits` digits."""
    if isinstance(key, str):
        key = b32_clean(key)
    mac = hmac.new(key, struct.pack('>Q', int(counter)),
                   HASHES.get(str(algorithm).upper(), hashlib.sha1)).digest()
    at = mac[-1] & 0x0F
    code = struct.unpack('>I', mac[at:at + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** int(digits))).zfill(int(digits))


def totp_step(when=None, period=30):
    return int((time.time() if when is None else float(when)) // int(period))


def totp(key, when=None, digits=6, period=30, algorithm='SHA1'):
    return hotp(key, totp_step(when, period), digits, algorithm)


def totp_match(key, code, when=None, digits=6, period=30, algorithm='SHA1', window=1):
    """Which period the code belongs to - its step number - or None.

    Looked for in this period first and then outwards, one step either side
    at a time, so that when two would do the nearest one is the answer.
    Compared in constant time, every one of them.
    """
    code = re.sub(r'\s', '', str(code or ''))
    if not re.fullmatch(r'[0-9]+', code, re.ASCII) or len(code) != int(digits):
        return None
    if isinstance(key, str):
        key = b32_clean(key)
    here = totp_step(when, period)
    found = None
    for off in [0] + [d for i in range(1, int(window) + 1) for d in (-i, i)]:
        if hmac.compare_digest(hotp(key, here + off, digits, algorithm), code) and found is None:
            found = here + off
    return found


def otpauth_uri(secret, label, issuer, digits=6, period=30, algorithm='SHA1'):
    """What the QR code holds: the Key URI Format every phone application
    reads (otpauth://totp/Issuer:label?secret=...&issuer=...)."""
    from urllib.parse import quote
    issuer = str(issuer or '').strip()
    who = (quote(issuer, safe='') + ':' if issuer else '') + quote(str(label), safe='@.')
    args = ['secret=' + str(secret).upper().replace('=', '')]
    if issuer:
        args.append('issuer=' + quote(issuer, safe=''))
    if str(algorithm).upper() != 'SHA1':
        args.append('algorithm=' + str(algorithm).upper())
    if int(digits) != 6:
        args.append('digits=%d' % int(digits))
    if int(period) != 30:
        args.append('period=%d' % int(period))
    return 'otpauth://totp/%s?%s' % (who, '&'.join(args))
