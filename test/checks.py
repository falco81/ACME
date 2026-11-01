#!/usr/bin/env python3
"""The pieces acme does by itself, checked against what the standards say.

    python3 test/checks.py

No server, no database, no network: TOTP/HOTP against the RFC 4226 and
RFC 6238 test vectors, the RADIUS packets (User-Password hiding,
Message-Authenticator, the Response Authenticator), the sealing of secrets,
the account passwords, the readers of the old totpcgi and FreeRADIUS files,
and the QR codes - decoded again with zxing-cpp and Pillow when they are
installed (pip install zxing-cpp pillow), and checked for shape when not.
"""
import binascii
import hashlib
import hmac
import os
import random
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ.setdefault('ACME_STATE', tempfile.mkdtemp(prefix='acme-checks-'))
import acme  # noqa: E402

FAILS = []


def check(what, ok):
    print('%s %s' % ('ok  ' if ok else 'FAIL', what))
    if not ok:
        FAILS.append(what)


# ---- HOTP, RFC 4226 appendix D --------------------------------------------
key = b'12345678901234567890'
want = ['755224', '287082', '359152', '969429', '338314',
        '254676', '287922', '162583', '399871', '520489']
check('HOTP: the ten RFC 4226 vectors',
      [acme.hotp(key, i) for i in range(10)] == want)

# ---- TOTP, RFC 6238 appendix B --------------------------------------------
keys = {'SHA1': b'12345678901234567890',
        'SHA256': b'12345678901234567890123456789012',
        'SHA512': b'1234567890123456789012345678901234567890123456789012345678901234'}
vectors = [(59, '94287082', '46119246', '90693936'),
           (1111111109, '07081804', '68084774', '25091201'),
           (1111111111, '14050471', '67062674', '99943326'),
           (1234567890, '89005924', '91819424', '93441116'),
           (2000000000, '69279037', '90698825', '38618901'),
           (20000000000, '65353130', '77737706', '47863826')]
good = True
for t, s1, s256, s512 in vectors:
    for algo, code in (('SHA1', s1), ('SHA256', s256), ('SHA512', s512)):
        if acme.totp(keys[algo], t, digits=8, algorithm=algo) != code:
            good = False
check('TOTP: the eighteen RFC 6238 vectors (SHA-1, SHA-256, SHA-512)', good)

# the window: a code from the period before is taken with window 1, not 0
k = os.urandom(20)
now = 1_800_000_000
before = acme.totp(k, now - 30)
check('TOTP: a code one period old is taken inside a window of 1',
      acme.totp_match(k, before, now, window=1) is not None)
check('TOTP: ... and refused with a window of 0',
      acme.totp_match(k, before, now, window=0) is None)
check('TOTP: a wrong code is refused',
      acme.totp_match(k, '%06d' % ((int(acme.totp(k, now)) + 1) % 1000000), now, window=0) is None)

# base32 the way the phone applications write it
sec = acme.b32_new()
check('base32: a new key reads back as 20 bytes', len(acme.b32_clean(sec)) == 20)
check('base32: spaces and small letters are forgiven',
      acme.b32_clean(sec.lower()[:8] + ' ' + sec[8:]) == acme.b32_clean(sec))
uri = acme.otpauth_uri(sec, 'novak@example.cz', 'Example')
check('otpauth URI: the shape Google Authenticator reads',
      uri.startswith('otpauth://totp/Example:novak') and '?secret=' in uri and 'issuer=Example' in uri)

# recovery codes
codes = acme.scratch_new(5, 8)
check('recovery codes: five of eight digits, all different',
      len(set(codes)) == 5 and all(len(c) == 8 and c.isdigit() for c in codes))
check('recovery codes: kept as a hash tied to the person',
      acme.scratch_hash('a@x', codes[0]) != acme.scratch_hash('b@x', codes[0]))

# ---- RADIUS ----------------------------------------------------------------
secret = b'testing123'
for password in ('135830', 'a-password-of-exactly-32-bytes!!', 'x' * 100, ''):
    raw, auth = acme.build_request(acme.ACCESS_REQUEST, 7,
                                  [acme.attr_bytes('User-Name', 'falco')], secret, password)
    p = acme.Packet.parse(raw)
    if not (p.password(secret) == password and p.message_authenticator_ok(secret)):
        check('RADIUS: User-Password of %d characters hidden and read back' % len(password), False)
        break
else:
    check('RADIUS: User-Password hidden and read back (0, 6, 32 and 100 characters)', True)

raw, auth = acme.build_request(acme.ACCESS_REQUEST, 9, [acme.attr_bytes('User-Name', 'falco')],
                              secret, '135830')
p = acme.Packet.parse(raw)
check('RADIUS: a wrong secret fails the Message-Authenticator',
      not p.message_authenticator_ok(b'not-the-secret'))
tampered = bytearray(raw)
tampered[-20] ^= 1
check('RADIUS: a packet changed on the way fails it too',
      not acme.Packet.parse(bytes(tampered)).message_authenticator_ok(secret))

# The User-Password hiding, by hand from RFC 2865 5.2, against the builder
pw = b'135830'.ljust(16, b'\x00')
hand = bytes(a ^ b for a, b in zip(pw, hashlib.md5(secret + auth).digest()))
check('RADIUS: User-Password exactly as RFC 2865 5.2 hides it', hand in raw)

reply = acme.build_reply(p, acme.ACCESS_ACCEPT, [acme.attr_bytes('Class', 'VPN')], secret)
check('RADIUS: the Response Authenticator of an answer checks out',
      acme.reply_ok(reply, p.authenticator, secret))
check('RADIUS: ... and not with another secret',
      not acme.reply_ok(reply, p.authenticator, b'other'))
# the Message-Authenticator of the answer (RFC 3579 3.2, over the request authenticator)
body = reply[20:]
at = body.find(bytes([80, 18]))
zeroed = reply[:4] + p.authenticator + body[:at + 2] + b'\x00' * 16 + body[at + 18:]
check('RADIUS: the answer carries a right Message-Authenticator (BlastRADIUS)',
      hmac.new(secret, zeroed, hashlib.md5).digest() == body[at + 2:at + 18])
check('RADIUS: Class comes back in the answer', b'VPN' in reply)

raw, _ = acme.build_request(acme.ACCOUNTING_REQUEST, 3, [acme.attr_bytes('User-Name', 'falco'),
                                                       acme.attr_bytes('Acct-Status-Type', 'Start')
                                                       if 'Acct-Status-Type' in str(acme.__dict__.get('ATTRS', ''))
                                                       else b''], secret)
check('RADIUS: an Accounting-Request authenticator checks out',
      acme.Packet.parse(raw).accounting_ok(secret))

# ---- sealing and passwords -------------------------------------------------
sealed = acme.seal_secret('JBSWY3DPEHPK3PXP')
check('sealing: a secret is not kept as it was', 'JBSWY3DPEHPK3PXP' not in str(sealed))
check('sealing: and opens again', acme.unseal_secret(sealed) == 'JBSWY3DPEHPK3PXP')
h = acme.password_hash('Correct-Horse-1', rounds=1000)
check('passwords: the right one is taken', acme.password_ok('Correct-Horse-1', h))
check('passwords: a wrong one is not', not acme.password_ok('correct-horse-1', h))

# ---- the old server's files ------------------------------------------------
t = acme.parse_totp_file('JBSWY3DPEHPK3PXP\n" RATE_LIMIT 3 30\n" WINDOW_SIZE 17\n" DISALLOW_REUSE\n'
                        '" TOTP_AUTH\n12345678\n87654321\n')
check('totpcgi .totp file: the key and the two recovery codes',
      t and t[0] == 'JBSWY3DPEHPK3PXP' and t[2] == ['12345678', '87654321']
      and t[1].get('WINDOW_SIZE') == ['17'])
c = acme.parse_clients_conf('client 192.9.212.1 {\n    secret = something\n    shortname = ASA\n}\n')
check('FreeRADIUS clients.conf: the ASA and its secret',
      bool(c) and c[0].get('secret') == 'something')

# ---- QR codes --------------------------------------------------------------
try:
    import zxingcpp
    from PIL import Image
except ImportError:
    zxingcpp = None
random.seed(6238)
texts = [acme.otpauth_uri(acme.b32_new(), 'user%d@example.cz' % i, 'Issuer %d' % i) for i in range(40)]
texts += ['x' * n for n in (1, 17, 100, 300, 1000, 2000)]
bad = 0
for text in texts:
    for ecl in ('L', 'M', 'Q', 'H'):
        try:
            q = acme.QrCode(text, ecl)
        except Exception:
            if len(text) < 1200:
                bad += 1
            continue
        if q.size != len(q.modules) or (q.size - 17) % 4:
            bad += 1
            continue
        if zxingcpp:
            img = Image.new('L', (q.size + 8, q.size + 8), 255)
            for y, row in enumerate(q.modules):
                for x, dark in enumerate(row):
                    if dark:
                        img.putpixel((x + 4, y + 4), 0)
            img = img.resize(((q.size + 8) * 4,) * 2, Image.NEAREST)
            got = zxingcpp.read_barcodes(img)
            if not got or got[0].text != text:
                bad += 1
check('QR: %d codes made%s' % (len(texts) * 4, ', every one decoded back by zxing-cpp'
                               if zxingcpp else ' (zxing-cpp not installed: shape only)'), bad == 0)
check('QR: an SVG for the page', acme.qr_svg('otpauth://totp/x?secret=AAAA').startswith('<svg'))

print()
print('%d check(s) failed' % len(FAILS) if FAILS else 'all checks passed')
sys.exit(1 if FAILS else 0)
