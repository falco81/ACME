# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# acme push (protocol 1): certificates put on these pages by an acme
# ---------------------------------------------------------------------------
# docs/acme-push-protocol.md is the whole of it; this is the reference
# implementation of both ends, written so that an application on this same
# engine (otp, isemon's engine parts) takes the part as it is - see "For an
# application on this engine" there.
#
#   the receiver   Settings → Certificates and TLS → Certificates from acme:
#                  switched on, paired with an acme (a one-time pairing code, or
#                  acme's key pasted), it answers
#                      GET  /admin/?api=acme-push-hello       who it is (no sign-in)
#                      POST /admin/?api=acme-push-pair        acme's key, with the code
#                      POST /admin/?api=acme-push-inventory   its slots and what is in them
#                      POST /admin/?api=acme-push-install     a certificate put in
#                  each POST signed with acme's Ed25519 key, its private key
#                  sealed to this server's X25519 key (X25519 + HKDF-SHA256 +
#                  AES-256-GCM). The PHP page hands the body and the headers on
#                  as they came (POST /api/acme-push/<op>, both in its JSON), and
#                  this decides.
#   the sender     push_identity() - this acme's own Ed25519 key, made once and
#                  sealed (meta acme_push:identity) - and push_signed(),
#                  push_seal_key(), used by acmelib/plugins/targets/acme_push.py.
#
# The Python standard library and nothing else: `cryptography` is used where the
# system has it (faster, and constant-time), else the few lines below do the same
# (RFC 8032, RFC 7748, RFC 5869, NIST SP 800-38D) - the AES block is the one of
# the ZIPs (_Aes256).

PUSH_PROTOCOL = 1
PUSH_APP = 'acme'                   # the application's name in hello (otp: 'otp')
PUSH_SKEW_S = 300                   # a request older or newer than this is refused
PUSH_NONCE_S = 900                  # nonces kept for this long (more than twice the skew)
PUSH_NONCES_MOST = 20000
PUSH_CODE_S = 900                   # a pairing code lasts 15 minutes
PUSH_CODE_TRIES = 5                 # and is gone after five wrong proofs
PUSH_KEYS_MOST = 8                  # acme keys one server may be paired with
PUSH_BODY_MOST = 1024 * 1024
PUSH_KEY_WORD = 'acme-push-ed25519'
PUSH_ENC_ALG = 'X25519-HKDF-SHA256-A256GCM'
PUSH_LOCK = threading.Lock()


class PushError(Exception):
    """A refusal said to acme: an HTTP status, a code machines read, words people do."""
    def __init__(self, status, code, words):
        Exception.__init__(self, words)
        self.status = status
        self.code = code


# ---- the small pieces of cryptography ---------------------------------------------------
def push_b64(raw):
    return base64.b64encode(raw).decode('ascii')


def push_unb64(text, n=None, what='a value'):
    try:
        raw = base64.b64decode(str(text or '').strip().encode('ascii'), validate=True)
    except (ValueError, binascii.Error, UnicodeEncodeError):
        raise PushError(400, 'bad_request', '%s is not base64' % what)
    if n is not None and len(raw) != n:
        raise PushError(400, 'bad_request', '%s is not %d bytes' % (what, n))
    return raw


def _push_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return ed25519, x25519, AESGCM
    except ImportError:
        return None


_ED_P = 2 ** 255 - 19
_ED_Q = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_add(a, b):
    p = _ED_P
    x = (a[1] - a[0]) * (b[1] - b[0]) % p
    y = (a[1] + a[0]) * (b[1] + b[0]) % p
    c = 2 * a[3] * b[3] * _ED_D % p
    d = 2 * a[2] * b[2] % p
    e, f, g, h = y - x, d - c, d + c, y + x
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def _ed_mul(s, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _ed_add(q, pt)
        pt = _ed_add(pt, pt)
        s >>= 1
    return q


def _ed_x(y, sign):
    p = _ED_P
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, p - 2, p) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p:
        x = x * _ED_I % p
    if (x * x - x2) % p:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_ED_GY = 4 * pow(5, _ED_P - 2, _ED_P) % _ED_P
_ED_GX = _ed_x(_ED_GY, 0)
_ED_G = (_ED_GX, _ED_GY, 1, _ED_GX * _ED_GY % _ED_P)


def _ed_pack(pt):
    zi = pow(pt[2], _ED_P - 2, _ED_P)
    x, y = pt[0] * zi % _ED_P, pt[1] * zi % _ED_P
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')


def _ed_unpack(raw):
    y = int.from_bytes(raw, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _ed_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _ED_P)


def _ed_secret(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _ed_hq(data):
    return int.from_bytes(hashlib.sha512(data).digest(), 'little') % _ED_Q


def ed25519_public(seed):
    """The public key (32 bytes) of an Ed25519 private key (its 32-byte seed)."""
    c = _push_crypto()
    if c:
        from cryptography.hazmat.primitives import serialization as _ser
        return c[0].Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            _ser.Encoding.Raw, _ser.PublicFormat.Raw)
    return _ed_pack(_ed_mul(_ed_secret(seed)[0], _ED_G))


def ed25519_sign(seed, msg):
    c = _push_crypto()
    if c:
        return c[0].Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    a, prefix = _ed_secret(seed)
    pub = _ed_pack(_ed_mul(a, _ED_G))
    r = _ed_hq(prefix + msg)
    rs = _ed_pack(_ed_mul(r, _ED_G))
    s = (r + _ed_hq(rs + pub + msg) * a) % _ED_Q
    return rs + int.to_bytes(s, 32, 'little')


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    c = _push_crypto()
    if c:
        try:
            c[0].Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except Exception:                               # noqa: BLE001 - InvalidSignature
            return False
    a = _ed_unpack(pub)
    r = _ed_unpack(sig[:32])
    s = int.from_bytes(sig[32:], 'little')
    if a is None or r is None or s >= _ED_Q:
        return False
    left = _ed_mul(s, _ED_G)
    right = _ed_add(r, _ed_mul(_ed_hq(sig[:32] + pub + msg), a))
    p = _ED_P
    return (left[0] * right[2] - right[0] * left[2]) % p == 0 and \
        (left[1] * right[2] - right[1] * left[2]) % p == 0


def x25519(k, u):
    """X25519(k, u) of RFC 7748: 32 bytes."""
    c = _push_crypto()
    if c:
        return c[1].X25519PrivateKey.from_private_bytes(k).exchange(
            c[1].X25519PublicKey.from_public_bytes(u))
    p = _ED_P
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64
    n = int.from_bytes(bytes(kb), 'little')
    x1 = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (n >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = x2 + z2, x2 - z2
        aa, bb = a * a % p, b * b % p
        e = aa - bb
        c_, d = x3 + z3, x3 - z3
        da, cb = d * a % p, c_ * b % p
        x3 = (da + cb) * (da + cb) % p
        z3 = x1 * (da - cb) * (da - cb) % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p
    if swap:
        x2, z2 = x3, z3
    return int.to_bytes(x2 * pow(z2, p - 2, p) % p, 32, 'little')


def x25519_public(k):
    return x25519(k, int.to_bytes(9, 32, 'little'))


def hkdf_sha256(ikm, salt, info, n=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b'', b'', 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def _push_gcm_mul(x, y):
    z, v = 0, x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= v
        v = (v >> 1) ^ (0xE1 << 120) if v & 1 else v >> 1
    return z


def _gcm_pure(key, nonce, data, aad, open_):
    aes = _Aes256(key)
    h = int.from_bytes(aes.block(bytes(16)), 'big')
    j0 = nonce + b'\x00\x00\x00\x01'

    def ctr(text):
        out = bytearray()
        for i in range(0, len(text), 16):
            n = (2 + i // 16) & 0xFFFFFFFF
            ks = aes.block(nonce + n.to_bytes(4, 'big'))
            out.extend(a ^ b for a, b in zip(text[i:i + 16], ks))
        return bytes(out)

    def ghash(c):
        y = 0
        for part in (aad, c):
            for i in range(0, len(part), 16):
                y = _push_gcm_mul(y ^ int.from_bytes(part[i:i + 16].ljust(16, b'\x00'), 'big'), h)
        y = _push_gcm_mul(y ^ ((len(aad) * 8) << 64 | len(c) * 8), h)
        return (y ^ int.from_bytes(aes.block(j0), 'big')).to_bytes(16, 'big')
    if open_:
        body, tag = data[:-16], data[-16:]
        if len(data) < 16 or not hmac.compare_digest(ghash(body), tag):
            raise ValueError('the tag does not match')
        return ctr(body)
    c = ctr(data)
    return c + ghash(c)


def aes256gcm(key, nonce, data, aad, open_=False):
    """AES-256-GCM, 12-byte nonce, 16-byte tag after the ciphertext."""
    c = _push_crypto()
    if c:
        if open_:
            try:
                return c[2](key).decrypt(nonce, data, aad)
            except Exception:                           # noqa: BLE001 - InvalidTag
                raise ValueError('the tag does not match')
        return c[2](key).encrypt(nonce, data, aad)
    return _gcm_pure(key, nonce, data, aad, open_)


# ---- the protocol's own pieces ------------------------------------------------------------
def push_key_id(pub):
    return hashlib.sha256(pub).hexdigest()[:16]


def push_key_text(pub, comment=''):
    """acme's public key as it is pasted: acme-push-ed25519 BASE64 [comment]"""
    out = '%s %s' % (PUSH_KEY_WORD, push_b64(pub))
    comment = re.sub(r'[^A-Za-z0-9 ._@()+:-]', '', str(comment or ''))[:80].strip()
    return out + (' ' + comment if comment else '')


def push_key_parse(text):
    """(public key bytes, comment) of a pasted key, or PushError."""
    parts = str(text or '').strip().split(None, 2)
    if len(parts) < 2 or parts[0] != PUSH_KEY_WORD:
        raise PushError(400, 'bad_request', 'acme\'s key reads "%s AAAA…" - copy it whole from '
                                            'acme (the target\'s Try, or Certificates from acme)'
                        % PUSH_KEY_WORD)
    raw = push_unb64(parts[1], 32, 'acme\'s key')
    return raw, (parts[2] if len(parts) > 2 else '')


def push_canonical(op, app_id, key_id, ts, nonce, body):
    """What is signed: seven lines, LF between them, none after the last."""
    return '\n'.join(['acme-push/%d' % PUSH_PROTOCOL, op, app_id, key_id, str(ts), nonce,
                      hashlib.sha256(body).hexdigest()]).encode('utf-8')


def push_signed(seed, op, app_id, body, ts=None, nonce=None):
    """The headers of a request of acme's (the sender's side)."""
    pub = ed25519_public(seed)
    ts = int(time.time()) if ts is None else int(ts)
    nonce = nonce or secrets.token_hex(16)
    sig = ed25519_sign(seed, push_canonical(op, app_id, push_key_id(pub), ts, nonce, body))
    return {'X-Acme-Push-Version': str(PUSH_PROTOCOL), 'X-Acme-Push-Key': push_key_id(pub),
            'X-Acme-Push-Time': str(ts), 'X-Acme-Push-Nonce': nonce,
            'X-Acme-Push-Signature': push_b64(sig)}


def push_aad(app_id, fingerprint):
    return ('acme-push/%d key\n%s\n%s' % (PUSH_PROTOCOL, app_id,
                                          str(fingerprint or '').lower())).encode('utf-8')


def push_seal_key(key_pem, app_pub, app_id, fingerprint, eph=None, nonce=None):
    """The private key of a certificate sealed to the server's X25519 key (the
    sender's side). `eph` and `nonce` only for the test vectors."""
    eph = eph or secrets.token_bytes(32)
    nonce = nonce or secrets.token_bytes(12)
    epk = x25519_public(eph)
    shared = x25519(eph, app_pub)
    if shared == bytes(32):
        raise ValueError('the server\'s key is not one to seal to')
    k = hkdf_sha256(shared, epk + app_pub, b'acme-push/1 key_pem')
    ct = aes256gcm(k, nonce, str(key_pem).encode('utf-8'), push_aad(app_id, fingerprint))
    return {'alg': PUSH_ENC_ALG, 'epk': push_b64(epk), 'nonce': push_b64(nonce),
            'ct': push_b64(ct)}


def push_open_key(sealed, app_priv, app_id, fingerprint):
    """The receiver's side of push_seal_key: the key PEM, or PushError."""
    if not isinstance(sealed, dict) or sealed.get('alg') != PUSH_ENC_ALG:
        raise PushError(400, 'bad_request', 'the key is sealed with %s or not at all'
                        % PUSH_ENC_ALG)
    epk = push_unb64(sealed.get('epk'), 32, 'key.epk')
    nonce = push_unb64(sealed.get('nonce'), 12, 'key.nonce')
    ct = push_unb64(sealed.get('ct'), None, 'key.ct')
    app_pub = x25519_public(app_priv)
    shared = x25519(app_priv, epk)
    if shared == bytes(32):
        raise PushError(400, 'bad_key', 'the key was sealed to nothing')
    k = hkdf_sha256(shared, epk + app_pub, b'acme-push/1 key_pem')
    try:
        return aes256gcm(k, nonce, ct, push_aad(app_id, fingerprint), open_=True).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        raise PushError(400, 'bad_key', 'the private key does not open: it was sealed to another '
                                        'key of this server (pair again), or for another '
                                        'certificate')


def push_proof(code, words, *parts):
    """HMAC-SHA256 of the pairing code over a few lines, as hex."""
    key = re.sub(r'[^A-Z0-9]', '', str(code or '').upper()).encode('ascii')
    msg = '\n'.join(['acme-push/%d %s' % (PUSH_PROTOCOL, words)] + [str(p) for p in parts])
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).hexdigest()


# ---- what is kept (meta, so every node of a cluster has it) ---------------------------------
def push_identity(store):
    """This acme's own Ed25519 key (the sender's): {'seed', 'public', 'id', 'text'},
    made the first time it is asked for and kept sealed."""
    with PUSH_LOCK:
        got = _meta_json(store, 'acme_push:identity') or {}
        seed = None
        if got.get('seed'):
            plain = unseal_secret(got['seed'], 'acme_push:identity')
            if plain:
                seed = base64.b64decode(plain)
        if not seed:
            seed = secrets.token_bytes(32)
            store.set_meta('acme_push:identity', json.dumps(
                {'seed': seal_secret(push_b64(seed), 'acme_push:identity'), 'at': time.time()}))
    pub = ed25519_public(seed)
    return {'seed': seed, 'public': pub, 'id': push_key_id(pub),
            'text': push_key_text(pub, '%s@%s' % (PUSH_APP, node_name()))}


def push_pin(store, url, pin=None):
    """What the sender keeps of an application it is paired with ({app_id, enc_key,
    how, ...}), by the application's address - not by the target's name, so a Try
    before the target is saved (or after it is renamed) pairs it for good."""
    k = 'acme_push:pin:' + hashlib.sha256(str(url).encode('utf-8')).hexdigest()[:32]
    if pin is None:
        got = _meta_json(store, k)
        return got if isinstance(got, dict) else None
    store.set_meta(k, json.dumps(dict(pin, url=str(url))))
    return pin


def push_box(store):
    """This server's own keys (the receiver's): app_id and the X25519 pair."""
    with PUSH_LOCK:
        got = _meta_json(store, 'acme_push:box') or {}
        priv = None
        if got.get('priv') and got.get('app_id'):
            plain = unseal_secret(got['priv'], 'acme_push:box')
            if plain:
                priv = base64.b64decode(plain)
        if not priv:
            priv = secrets.token_bytes(32)
            got = {'app_id': secrets.token_hex(16), 'at': time.time(),
                   'priv': seal_secret(push_b64(priv), 'acme_push:box')}
            store.set_meta('acme_push:box', json.dumps(got))
    return {'app_id': got['app_id'], 'priv': priv, 'pub': x25519_public(priv)}


def push_conf(store):
    got = _meta_json(store, 'acme_push:conf') or {}
    keys = [k for k in (got.get('keys') or []) if isinstance(k, dict) and k.get('public')]
    return {'on': bool(got.get('on')), 'keys': keys[:PUSH_KEYS_MOST],
            'other_names': bool(got.get('other_names')),
            'pairing': got.get('pairing') if isinstance(got.get('pairing'), dict) else None,
            'last': got.get('last') if isinstance(got.get('last'), dict) else None}


def push_conf_save(store, conf):
    store.set_meta('acme_push:conf', json.dumps(conf))


def push_nonce_take(store, key_id, nonce, ts):
    """False when the nonce was seen already (a replay)."""
    with PUSH_LOCK:
        seen = _meta_json(store, 'acme_push:nonces') or {}
        t = time.time()
        seen = {k: v for k, v in seen.items() if t - float(v) < PUSH_NONCE_S}
        k = '%s:%s' % (key_id, nonce)
        if k in seen:
            return False
        if len(seen) >= PUSH_NONCES_MOST:
            for old in sorted(seen, key=seen.get)[:len(seen) // 4]:
                seen.pop(old, None)
        seen[k] = t
        store.set_meta('acme_push:nonces', json.dumps(seen))
        return True


# ---- the slots: where a certificate can go here ---------------------------------------------
def push_cert_view(info, alt=None):
    if not info:
        return None
    fp = str(info.get('fingerprint') or '').replace(':', '').lower()
    out = {'fingerprint': fp, 'not_before': info.get('not_before'),
           'not_after': info.get('not_after'), 'subject': info.get('subject') or '',
           'issuer': info.get('issuer') or '',
           'names': [str(n) for n in (info.get('san') or [])] or
           ([info['cn']] if info.get('cn') else []),
           'key_type': push_key_type(info.get('key') or ''), 'alt': None}
    if alt:
        a = alt.get('info') or {}
        out['alt'] = {'fingerprint': str(a.get('fingerprint') or '').replace(':', '').lower(),
                      'not_after': a.get('not_after'), 'key_type': push_key_type(a.get('key') or '')}
    return out


def push_key_type(words):
    m = re.match(r'(EC|RSA)\s+(\d+)', str(words or ''))
    return ('%s-%s' % (m.group(1).lower(), m.group(2))) if m else ''


def push_slots(store):
    """Every slot of this server: each node's pages, and the VIP address's.
    [{id, title, kind, node, names, key_types, dual, current, managed_by,
      installable, why_not}] - docs/acme-push-protocol.md, "inventory"."""
    v = vip_conf(store) or {}
    cluster = bool(CONFIG.get('ha_mode'))
    acme_on = bool(CONFIG.get('acme'))
    try:
        wanted = acme_wanted(store)
    except Exception:                                   # noqa: BLE001
        wanted = []
    out = []
    for t in tls_targets(store):
        is_vip = t == 'vip'
        if is_vip and not (cluster and v.get('on')):
            continue
        prof = tls_profile(store, t) or {}
        name = acme_name_of(store, t)
        how = str(prof.get('how') or '')
        if how.startswith('acme push'):
            managed = 'acme-push'
        elif acme_on and t in wanted and acme_care(store, t):
            managed = 'own-acme'
        elif prof.get('cert'):
            managed = 'manual'
        else:
            managed = 'none'
        why = ''
        if is_vip and not name:
            why = 'the VIP address has no name (Settings → High availability → Its name)'
        out.append({'id': 'vip' if is_vip else 'node:' + t, 'node': None if is_vip else t,
                    'kind': 'vip' if is_vip else 'node',
                    'title': ('the VIP address' if is_vip else 'node %s' % t) + (
                        ' (%s)' % name if name else ''),
                    'names': [name] if name else [], 'key_types': ['ec', 'rsa'], 'dual': True,
                    'current': push_cert_view(prof.get('info') if prof.get('cert') else None,
                                              tls_alt(prof)),
                    'how': how, 'managed_by': managed, 'installable': True, 'why_not': why})
    return out


def push_cluster(store):
    v = vip_conf(store) or {}
    cluster = bool(CONFIG.get('ha_mode'))
    return {'on': cluster, 'node': node_name(),
            'nodes': [t for t in tls_targets(store) if t != 'vip'],
            'vip': {'on': bool(v.get('on')) and cluster, 'fqdn': str(v.get('fqdn') or ''),
                    'address': str(v.get('address') or '')}}


def push_covers(names, host):
    host = str(host or '').lower().rstrip('.')
    for n in names or []:
        n = str(n).lower().rstrip('.')
        if n == host or (n.startswith('*.') and '.' in host and host.split('.', 1)[1] == n[2:]):
            return True
    return False


def push_pick(slots, asked, cert_names):
    """The slots a request names: 'auto' (every slot whose names the certificate
    holds), 'nodes', 'vip', 'this', or slot ids."""
    if isinstance(asked, str):
        asked = [asked]
    asked = [str(a).strip() for a in (asked or ['auto']) if str(a).strip()] or ['auto']
    ids = {s['id']: s for s in slots}
    out = []
    for a in asked:
        if a == 'auto':
            got = [s for s in slots if s['names'] and s.get('installable', True) and
                   not str(s.get('managed_by') or '').startswith('follows:') and
                   all(push_covers(cert_names, n) for n in s['names'])]
            if not got:
                raise PushError(422, 'names', 'no slot here has a name this certificate holds '
                                '(it holds %s; the slots: %s)' % (
                                    ', '.join(cert_names) or '-', '; '.join(
                                        '%s %s' % (s['id'], ', '.join(s['names']) or '-')
                                        for s in slots)))
            out += got
        elif a == 'nodes':
            out += [s for s in slots if s['kind'] == 'node']
        elif a == 'this':
            out += [s for s in slots if s['node'] == node_name()]
        elif a in ids:
            out.append(ids[a])
        elif 'node:' + a in ids:
            out.append(ids['node:' + a])
        else:
            raise PushError(404, 'no_slot', 'there is no slot %s here (there are %s)' % (
                a[:80], ', '.join(ids) or 'none'))
    seen, uniq = set(), []
    for s in out:
        if s['id'] not in seen:
            seen.add(s['id'])
            uniq.append(s)
    return uniq


def push_put(store, slot, got, alt, by):
    """One slot given a certificate, as an upload on Certificates and TLS takes it:
    its TLS settings kept, the engine's own ACME told to leave it. Every node puts
    its own into nginx within seconds (web_tick); the VIP's whichever holds it."""
    target = 'vip' if slot['kind'] == 'vip' else slot['node']
    prof = tls_profile(store, target) or {}
    prof.update(cert=got['cert'], chain=got['chain'], root=got['root'],
                key=seal_secret(got['key'], 'web:tls'), info=got['info'],
                chain_info=got['chain_info'], root_info=got['root_info'],
                verify=got['verify'], how=('acme push: %s' % by)[:190])
    for k in ('pending_key', 'csr', 'alt'):
        prof.pop(k, None)
    if alt:
        prof['alt'] = {'cert': alt['cert'], 'chain': alt['chain'],
                       'key': seal_secret(alt['key'], 'web:tls'), 'info': alt['info'],
                       'for': tls_alt_for(got['cert'])}
    prof.setdefault('preset', 'standard')
    prof.setdefault('dh', 'none')
    tls_save(store, target, prof, 'acme push (%s)' % by)
    acme_care_set(store, target, False, 'acme push (%s)' % by, 'acme puts its certificates here')
    info = got['info']
    store.add_event('settings', 'acme push: %s has the certificate %s (until %s), from %s' % (
        'the VIP address' if target == 'vip' else target, info.get('subject') or '?',
        stamp(info.get('not_after')) if info.get('not_after') else '?', by),
        'warn', who='acme push')


def push_bundle(cert_pem, chain_pem, key_pem, what):
    try:
        got = cert_bundle(cert_pem, key_pem, chain_pem)
    except ValueError as e:
        raise PushError(422, 'key_mismatch' if 'of this key' in str(e) else 'bad_cert',
                        '%s: %s' % (what, e))
    first = PEM_CERT.search(str(cert_pem or ''))
    if not first or got['cert'].strip() != first.group(0).strip():
        raise PushError(422, 'key_mismatch', '%s: the key is not the one of cert_pem' % what)
    info = got['info']
    t = time.time()
    if info.get('not_after') and float(info['not_after']) < t:
        raise PushError(422, 'expired', '%s ran out on %s' % (what, stamp(info['not_after'])))
    if info.get('not_before') and float(info['not_before']) > t + PUSH_SKEW_S:
        raise PushError(422, 'not_yet_valid', '%s is valid only from %s' % (
            what, stamp(info['not_before'])))
    return got


# ---- a request: checked ---------------------------------------------------------------------
def push_check(store, op, raw, headers, conf, box, key=None):
    """The signature, the time and the nonce of a request -> the acme key's entry."""
    def hd(name):
        return str(headers.get('X-Acme-Push-' + name) or '').strip()
    if hd('Version') not in ('', str(PUSH_PROTOCOL)):
        raise PushError(400, 'version', 'this server speaks acme push %d' % PUSH_PROTOCOL)
    key_id, ts, nonce, sig = hd('Key'), hd('Time'), hd('Nonce'), hd('Signature')
    if not re.match(r'^[0-9a-f]{16}\Z', key_id) or not re.match(r'^[0-9]{1,12}\Z', ts) or \
            not re.match(r'^[A-Za-z0-9_-]{16,64}\Z', nonce) or not sig:
        raise PushError(401, 'unsigned', 'the request is not signed (X-Acme-Push-Key, -Time, '
                                         '-Nonce, -Signature)')
    if key is None:
        key = next((k for k in conf['keys'] if k.get('id') == key_id), None)
        if key is None:
            raise PushError(401, 'unknown_key', 'this server is not paired with that acme key '
                                                '(%s) - pair them on Certificates from acme'
                            % key_id)
    pub = base64.b64decode(key['public'])
    if push_key_id(pub) != key_id:
        raise PushError(401, 'unknown_key', 'the key said is not the key used')
    if abs(time.time() - int(ts)) > PUSH_SKEW_S:
        raise PushError(401, 'stale', 'the request is %d s away from this server\'s time - '
                                      'is the clock of one of the two wrong?'
                        % int(time.time() - int(ts)))
    if not ed25519_verify(pub, push_canonical(op, box['app_id'], key_id, int(ts), nonce, raw),
                          push_unb64(sig, 64, 'the signature')):
        raise PushError(401, 'bad_signature', 'the signature does not match')
    if not push_nonce_take(store, key_id, nonce, ts):
        raise PushError(401, 'replay', 'that request was sent before (the same nonce)')
    return key, nonce


def push_body(raw):
    try:
        b = json.loads(raw.decode('utf-8'), parse_constant=_no_constant) if raw else {}
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise PushError(400, 'bad_request', 'the body is not JSON')
    if not isinstance(b, dict):
        raise PushError(400, 'bad_request', 'the body is not a JSON object')
    return b


def push_hello(store):
    conf = push_conf(store)
    out = {'ok': True, 'protocol': [PUSH_PROTOCOL], 'app': PUSH_APP, 'version': __version__,
           'on': conf['on']}
    if not conf['on']:
        return out
    box = push_box(store)
    cl = push_cluster(store)
    out.update(app_id=box['app_id'], enc_key=push_b64(box['pub']), enc_alg=PUSH_ENC_ALG,
               node=cl['node'], cluster=cl['on'], nodes=cl['nodes'], vip=cl['vip'],
               slots=[s['id'] for s in push_slots(store)], paired=len(conf['keys']),
               pairing=bool(conf['pairing'] and conf['pairing'].get('until', 0) > time.time()))
    return out


def push_handle(store, op, raw, headers):
    """One request of an acme: (status, JSON answer). `raw` the body as it came."""
    try:
        if op == 'hello':
            return 200, push_hello(store)
        if len(raw) > PUSH_BODY_MOST:
            raise PushError(413, 'too_big', 'that is more than a certificate')
        conf = push_conf(store)
        if not conf['on']:
            raise PushError(403, 'off', 'this server takes no certificates from acme: switch it '
                                        'on at Settings → Certificates and TLS → Certificates '
                                        'from acme')
        box = push_box(store)
        if op == 'pair':
            return 200, push_do_pair(store, raw, headers, conf, box)
        if op not in ('inventory', 'install'):
            raise PushError(404, 'bad_request', 'no such request: %s' % op[:40])
        if not conf['keys']:
            raise PushError(401, 'not_paired', 'this server is not paired with any acme yet')
        key, _nonce = push_check(store, op, raw, headers, conf, box)
        b = push_body(raw)
        if op == 'inventory':
            return 200, {'ok': True, 'app': PUSH_APP, 'version': __version__,
                         'app_id': box['app_id'], 'cluster': push_cluster(store),
                         'slots': push_slots(store), 'other_names': conf['other_names']}
        return 200, push_do_install(store, b, conf, box, key)
    except PushError as e:
        return e.status, {'ok': False, 'code': e.code, 'error': str(e)}


def push_do_pair(store, raw, headers, conf, box):
    b = push_body(raw)
    pub, comment = push_key_parse(b.get('acme_key'))
    p = conf['pairing'] or {}
    if not p or float(p.get('until') or 0) < time.time():
        raise PushError(403, 'pairing_closed', 'no pairing code is waiting here: make one on '
                                               'Certificates from acme (it lasts 15 minutes)')
    key = {'id': push_key_id(pub), 'public': push_b64(pub)}
    _k, nonce = push_check(store, 'pair', raw, headers, conf, box, key=key)
    code = unseal_secret(p.get('code') or '', 'acme_push:code') or ''
    if not code or not hmac.compare_digest(
            push_proof(code, 'pair', box['app_id'], key['id'], nonce), str(b.get('proof') or '')):
        with PUSH_LOCK:
            c2 = push_conf(store)
            pp = c2.get('pairing') or {}
            pp['tries'] = int(pp.get('tries') or 0) + 1
            c2['pairing'] = pp if pp['tries'] < PUSH_CODE_TRIES else None
            push_conf_save(store, c2)
        store.add_event('settings', 'acme push: a pairing with a wrong code was refused (key %s)'
                        % key['id'], 'warn', who='acme push')
        raise PushError(403, 'bad_code', 'the pairing code is not the one shown here%s' % (
            '' if int(p.get('tries') or 0) + 1 < PUSH_CODE_TRIES else
            ' - and it is gone now: make a new one'))
    name = re.sub(r'[^A-Za-z0-9 ._@()+:-]', '', str(b.get('acme_name') or comment or 'acme'))[:80]
    with PUSH_LOCK:
        c2 = push_conf(store)
        keys = [k for k in c2['keys'] if k.get('id') != key['id']]
        keys.append(dict(key, name=name, at=time.time(), by='pairing code'))
        c2['keys'] = keys[-PUSH_KEYS_MOST:]
        c2['pairing'] = None
        push_conf_save(store, c2)
    store.add_event('settings', 'acme push: paired with %s (key %s)' % (name, key['id']), 'warn',
                    who='acme push')
    enc = push_b64(box['pub'])
    return {'ok': True, 'app': PUSH_APP, 'app_id': box['app_id'], 'key_id': key['id'],
            'enc_key': enc, 'enc_alg': PUSH_ENC_ALG,
            'confirm': push_proof(code, 'paired', box['app_id'], key['id'], nonce, enc)}


def push_do_install(store, b, conf, box, key):
    cert_pem, fp = str(b.get('cert_pem') or ''), str(b.get('fingerprint') or '').lower()
    if not re.match(r'^[0-9a-f]{64}\Z', fp):
        raise PushError(400, 'bad_request', 'fingerprint is the SHA-256 of the certificate, hex')
    first = PEM_CERT.search(cert_pem)
    if not first:
        raise PushError(400, 'bad_request', 'cert_pem holds no certificate')
    der = base64.b64decode(''.join(first.group(0).strip().splitlines()[1:-1]))
    if hashlib.sha256(der).hexdigest() != fp:
        raise PushError(400, 'bad_request', 'fingerprint is not the one of cert_pem')
    key_pem = push_open_key(b.get('key'), box['priv'], box['app_id'], fp)
    got = push_bundle(cert_pem, str(b.get('chain_pem') or ''), key_pem, 'the certificate')
    alt = None
    a = b.get('alt')
    if isinstance(a, dict) and a.get('cert_pem'):
        afp = str(a.get('fingerprint') or '').lower()
        if not re.match(r'^[0-9a-f]{64}\Z', afp):
            raise PushError(400, 'bad_request', 'alt.fingerprint is the SHA-256 of alt.cert_pem')
        alt = push_bundle(a['cert_pem'], str(a.get('chain_pem') or ''),
                          push_open_key(a.get('key'), box['priv'], box['app_id'], afp),
                          'the second certificate (alt)')
        alt_fp = str(alt['info'].get('fingerprint') or '').replace(':', '').lower()
        if alt_fp != afp:
            raise PushError(400, 'bad_request', 'alt.fingerprint is not the one of alt.cert_pem')
    names = [str(n) for n in (got['info'].get('san') or [])] or [got['info'].get('cn') or '']
    slots = push_pick(push_slots(store), b.get('slots'), names)
    check = b.get('check_names') is not False or not conf['other_names']
    for s in slots:
        if str(s.get('managed_by') or '').startswith('follows:'):
            raise PushError(409, 'not_installable', '%s follows %s by itself: push to that one'
                            % (s['id'], s['managed_by'][8:]))
        if not s['installable']:
            raise PushError(409, 'not_installable', '%s: %s' % (s['id'], s['why_not']))
        if check:
            if not s['names']:
                raise PushError(422, 'names', '%s has no name to check the certificate against: '
                                '%s' % (s['id'], s['why_not'] or 'give it one'))
            missing = [n for n in s['names'] if not push_covers(names, n)]
            if missing:
                raise PushError(422, 'names', 'the certificate does not hold %s, the name of %s '
                                '(it holds %s)' % (', '.join(missing), s['id'], ', '.join(names)))
    by = str(key.get('name') or key.get('id'))
    put, same = [], []
    for s in slots:
        cur = s['current'] or {}
        want_alt = str(alt['info'].get('fingerprint') or '').replace(':', '').lower() if alt else ''
        if cur.get('fingerprint') == fp and ((cur.get('alt') or {}).get('fingerprint') or '') \
                == want_alt and s['managed_by'] == 'acme-push' and not b.get('force'):
            same.append(s)
            continue
        push_put(store, s, got, alt, by)
        put.append(s)
    with PUSH_LOCK:
        c2 = push_conf(store)
        c2['last'] = {'at': time.time(), 'by': by, 'fingerprint': fp,
                      'slots': [s['id'] for s in slots], 'put': [s['id'] for s in put]}
        push_conf_save(store, c2)
    one = lambda s, st: {'slot': s['id'], 'names': s['names'], 'node': s['node'],  # noqa: E731
                         'fingerprint': fp, 'not_after': got['info'].get('not_after'),
                         'state': st}
    said = []
    if put:
        said.append('put in for %s - each node puts it into nginx within seconds'
                    % ', '.join(s['id'] for s in put))
    if same:
        said.append('already there for %s' % ', '.join(s['id'] for s in same))
    return {'ok': True, 'installed': [one(s, 'installed') for s in put] +
            [one(s, 'already') for s in same], 'said': '; '.join(said)}


# ---- the routes: what PHP hands on, and the card ---------------------------------------------
def _push_route(op):
    """What the page hands on: {"body": base64 of the body as it came, "headers":
    {"Version", "Key", "Time", "Nonce", "Signature"}} - in the body, not as headers
    of its own, so every application's relay takes it as it is."""
    def run(h):
        raw, hd = b'', {}
        if op != 'hello':
            b = h.body()
            try:
                raw = base64.b64decode(str(b.get('body') or ''), validate=True)
            except (ValueError, binascii.Error):
                raw = None
            got = b.get('headers') if isinstance(b.get('headers'), dict) else {}
            hd = {'X-Acme-Push-' + k: str(got.get(k) or '')[:300]
                  for k in ('Version', 'Key', 'Time', 'Nonce', 'Signature')}
        if raw is None:
            h.send_json({'ok': False, 'code': 'bad_request',
                         'error': 'the body did not arrive whole'}, 400)
            return
        status, out = push_handle(h.store, op, raw, hd)
        if not out.get('ok'):
            log('acme push %s refused (%s): %s' % (op, out.get('code'), out.get('error')), 'info')
        h.send_json(out, status)
    run.__name__ = '_push_' + op
    route('GET' if op == 'hello' else 'POST', '/api/acme-push/' + op)(run)


for _op in ('hello', 'pair', 'inventory', 'install'):
    _push_route(_op)
del _op


def push_view(store):
    conf = push_conf(store)
    box = push_box(store) if conf['on'] else None
    p = conf['pairing'] or {}
    # This server's own key as a sender - only where it is an acme (the
    # certificate manager), which pushes to others.
    me = push_identity(store) if PUSH_APP == 'acme' else None
    return {'on': conf['on'], 'other_names': conf['other_names'],
            'keys': [{k: x.get(k) for k in ('id', 'name', 'at', 'by')} for x in conf['keys']],
            'pairing': {'until': p.get('until'), 'tries': p.get('tries') or 0}
            if p and float(p.get('until') or 0) > time.time() else None,
            'app_id': box['app_id'] if box else '',
            'enc_fp': push_key_id(box['pub']) if box else '', 'last': conf['last'],
            'slots': push_slots(store) if conf['on'] else [],
            'mine': {'text': me['text'], 'id': me['id']} if me else None}


@route('GET', '/api/acme-push')
def _push_card(h):
    h.me()
    return push_view(h.store)


@route('POST', '/api/acme-push')
def _push_card_do(h):
    s = h.me('fulladmin')
    return push_card_do(h.store, h.body(), s['name'])


def push_card_do(store, b, who):
    """What the card asks: on, off, pair, pair_drop, key_add, key_forget, other_names."""
    act = str(b.get('action') or '')
    out = {}
    with PUSH_LOCK:
        conf = push_conf(store)
        if act in ('on', 'off'):
            conf['on'] = act == 'on'
            if not conf['on']:
                conf['pairing'] = None
            msg = 'certificates from acme are %s' % ('taken' if conf['on'] else 'no longer taken')
        elif act == 'pair':
            if not conf['on']:
                raise ApiError(409, 'switch it on first')
            abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
            code = ''.join(secrets.choice(abc) for _ in range(16))
            conf['pairing'] = {'code': seal_secret(code, 'acme_push:code'),
                               'until': time.time() + PUSH_CODE_S, 'tries': 0, 'by': who}
            out['code'] = '-'.join(code[i:i + 4] for i in range(0, 16, 4))
            msg = 'the pairing code waits for acme for 15 minutes'
        elif act == 'pair_drop':
            conf['pairing'] = None
            msg = 'no pairing code waits now'
        elif act == 'key_add':
            if not conf['on']:
                raise ApiError(409, 'switch it on first')
            try:
                pub, comment = push_key_parse(b.get('key'))
            except PushError as e:
                raise ApiError(400, str(e))
            kid = push_key_id(pub)
            keys = [k for k in conf['keys'] if k.get('id') != kid]
            if len(keys) >= PUSH_KEYS_MOST:
                raise ApiError(409, 'at most %d acme keys - forget one first' % PUSH_KEYS_MOST)
            keys.append({'id': kid, 'public': push_b64(pub), 'name': comment[:80] or 'acme',
                         'at': time.time(), 'by': who})
            conf['keys'] = keys
            msg = 'acme\'s key %s is taken' % kid
        elif act == 'key_forget':
            kid = str(b.get('id') or '')
            if not any(k.get('id') == kid for k in conf['keys']):
                raise ApiError(404, 'there is no such acme key here')
            conf['keys'] = [k for k in conf['keys'] if k.get('id') != kid]
            msg = 'acme\'s key %s is forgotten: it puts nothing here from now on' % kid
        elif act == 'other_names':
            conf['other_names'] = b.get('on') is True
            msg = 'kept'
        else:
            raise ApiError(400, 'no such thing to do')
        push_conf_save(store, conf)
    store.add_event('settings', '%s: acme push - %s' % (who, msg), 'warn', who=who)
    out.update(message=msg, view=push_view(store))
    return out
