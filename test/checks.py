#!/usr/bin/env python3
"""The pieces acme does by itself, checked against what the standards say.

    python3 test/checks.py

No server, no database, no network: TOTP/HOTP (the administrators' second
step with an app) against the RFC 4226 and RFC 6238 test vectors, the
sealing of secrets, the account passwords, the line isemon gets, the tables
as a module appends to them, and the QR codes - decoded again with zxing-cpp
and Pillow when they are installed (pip install zxing-cpp pillow), and
checked for shape when not.
"""
import os
import random
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

# ---- sealing and passwords -------------------------------------------------
sealed = acme.seal_secret('JBSWY3DPEHPK3PXP')
check('sealing: a secret is not kept as it was', 'JBSWY3DPEHPK3PXP' not in str(sealed))
check('sealing: and opens again', acme.unseal_secret(sealed) == 'JBSWY3DPEHPK3PXP')
h = acme.password_hash('Correct-Horse-1', rounds=1000)
check('passwords: the right one is taken', acme.password_ok('Correct-Horse-1', h))
check('passwords: a wrong one is not', not acme.password_ok('correct-horse-1', h))
# One's own new one (1.0.98): typed again the same, and the rules of these accounts.
check('passwords: the new one typed again not the same is said',
      'typed again' in acme.password_change_problem({'new': 'Correct-Horse-2', 'again': 'Correct-Horse-3'}))
check('passwords: eight characters at least, 200 at most',
      'eight' in acme.password_change_problem({'new': 'short', 'again': 'short'})
      and 'longer' in acme.password_change_problem({'new': 'x' * 201}))
check('passwords: the new one typed twice the same will do',
      acme.password_change_problem({'new': 'Correct-Horse-2', 'again': 'Correct-Horse-2'}) == ''
      and acme.password_change_problem({'new': 'Correct-Horse-2'}) == '')

# ---- what goes to isemon ----------------------------------------------------
line = acme.event_kv('certificates', 'www.example.cz renewed "now"\nnext', 'warn', 'acme', 'n1')
check('isemon: an event as one key=value line, its quotes escaped',
      line == 'level=warn kind=certificates node=n1 who=acme msg="www.example.cz renewed '
              '\\"now\\" next"')

# ---- the tables, as a module appends to them -----------------------------------
acme.SCHEMA.append(('zz_checks', 'CREATE TABLE IF NOT EXISTS zz_checks (id {ID}, name {K} '
                                 'NOT NULL UNIQUE, key_sealed {B})'))
check('TABLES follows SCHEMA: a table appended later is in it', 'zz_checks' in acme.TABLES)
check('a table appended later has its name for the replication\'s trigger',
      ('zz_checks', 'name') in acme.schema_named_columns())
check('... and its sealed column is looked at', ('zz_checks', 'key_sealed') in acme.sealed_columns())
acme.SCHEMA.pop()

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
