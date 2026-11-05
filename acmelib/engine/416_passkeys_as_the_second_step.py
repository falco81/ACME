# A passkey - Face ID, Touch ID, Windows Hello, a security key - as the second step of signing in
# to the administration (1.0.51; docs/admin-second-step.md). Never instead of the password: the password
# opens a sign-in that can do nothing but its second step (MFA_ALLOWED), and the passkey is one
# more way of giving that step, beside the app, the code by mail and the code by SMS. Off unless
# switched on (Settings → Sign-in protection, admin_2fa_passkey); chosen by the account when it
# sets its second step up, reset as the others are (Accounts, acme --reset-2fa NAME).
#
# WebAuthn as the standard says, only the standard library and openssl: the attestation is not
# checked ("none"), the face or finger (UV) always is, the signature over authenticatorData and
# the hash of clientDataJSON, the counter going on. The passkey is bound to the name the pages
# were reached by (the RP ID: the Host header, never an address) - set up on acme.example.cz, it
# works there only. Nothing secret is kept: the public key, its id, its counter.

PASSKEY_MOST = 10                   # an account's passkeys
PASSKEY_CHALLENGE_S = 300
PASSKEY_ALGS = (-7, -257, -8)       # ES256, RS256, EdDSA


def pk_b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def pk_unb64u(text):
    text = str(text or '').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]*', text):
        raise ValueError('not base64url')
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def pk_rp_id(h):
    """The name the page was reached by - the passkey's RP ID - or ApiError: WebAuthn takes no
    address, and a passkey made on one name is of no use on another."""
    host = str(h.headers.get('X-Acme-Host') or '').strip()
    host = re.sub(r':[0-9]{1,5}$', '', host).lower().rstrip('.')
    if not host or host.startswith('['):
        raise ApiError(400, 'a passkey works on the pages opened by their name over HTTPS '
                            '(https://name/), not by an address')
    try:
        ipaddress.ip_address(host)
        raise ApiError(400, 'a passkey works on the pages opened by their name over HTTPS '
                            '(https://name/), not by an address')
    except ValueError:
        pass
    if not re.fullmatch(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*',
                        host):
        raise ApiError(400, 'that is not a name a passkey can be made for')
    return host


# ---- CBOR, as much as WebAuthn needs -------------------------------------------------------
def pk_cbor(data, at=0, depth=0):
    """(value, next offset) of one CBOR item - ints, byte and text strings, arrays, maps,
    simple values; nothing indefinite."""
    if depth > 16 or at >= len(data):
        raise ValueError('CBOR cut short')
    ib = data[at]
    major, info = ib >> 5, ib & 31
    at += 1
    if info < 24:
        val = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        if at + n > len(data):
            raise ValueError('CBOR cut short')
        val = int.from_bytes(data[at:at + n], 'big')
        at += n
    else:
        raise ValueError('CBOR of a kind not taken here')
    if major == 0:
        return val, at
    if major == 1:
        return -1 - val, at
    if major in (2, 3):
        if at + val > len(data):
            raise ValueError('CBOR cut short')
        raw = bytes(data[at:at + val])
        return (raw if major == 2 else raw.decode('utf-8')), at + val
    if major == 4:
        out = []
        for _ in range(val):
            item, at = pk_cbor(data, at, depth + 1)
            out.append(item)
        return out, at
    if major == 5:
        out = {}
        for _ in range(val):
            k, at = pk_cbor(data, at, depth + 1)
            v, at = pk_cbor(data, at, depth + 1)
            out[k] = v
        return out, at
    if major == 7:
        return {20: False, 21: True, 22: None}.get(info, None), at
    raise ValueError('CBOR of a kind not taken here')


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _der(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(n):
    b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return _der(0x02, b)


def pk_cose_pem(cose):
    """(PEM of the public key, its alg) from a COSE key - or ValueError."""
    if not isinstance(cose, dict):
        raise ValueError('the key is not a COSE key')
    kty, alg = cose.get(1), cose.get(3)
    if alg not in PASSKEY_ALGS:
        raise ValueError('a key of an algorithm not taken (%s)' % alg)
    if kty == 2 and alg == -7 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
            raise ValueError('a P-256 key of the wrong size')
        der = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200') + b'\x04' + x + y
    elif kty == 3 and alg == -257:
        n, e = cose.get(-1), cose.get(-2)
        if not (isinstance(n, bytes) and isinstance(e, bytes)) or len(n) * 8 < 2048:
            raise ValueError('an RSA key under 2048 bits')
        rsa = _der(0x30, _der_int(int.from_bytes(n, 'big')) + _der_int(int.from_bytes(e, 'big')))
        der = _der(0x30, bytes.fromhex('300d06092a864886f70d0101010500') + _der(0x03, b'\x00' + rsa))
    elif kty == 1 and alg == -8 and cose.get(-1) == 6:
        x = cose.get(-2)
        if not (isinstance(x, bytes) and len(x) == 32):
            raise ValueError('an Ed25519 key of the wrong size')
        der = bytes.fromhex('302a300506032b6570032100') + x
    else:
        raise ValueError('a key of a kind not taken (kty %s, alg %s)' % (kty, alg))
    b64 = base64.b64encode(der).decode('ascii')
    pem = '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' % '\n'.join(
        b64[i:i + 64] for i in range(0, len(b64), 64))
    return pem, alg


def pk_verify(pem, alg, data, sig):
    """Whether `sig` is the key's signature of `data` (openssl)."""
    exe = shutil.which('openssl')
    if not exe:
        raise ApiError(503, 'openssl is not on this machine - a passkey cannot be checked')
    d = tempfile.mkdtemp(prefix='acme-pk-')
    try:
        for fn, body in (('k.pem', pem.encode()), ('d.bin', data), ('s.bin', sig)):
            with open(os.path.join(d, fn), 'wb') as f:
                f.write(body)
        if alg == -8:
            args = [exe, 'pkeyutl', '-verify', '-pubin', '-inkey', os.path.join(d, 'k.pem'),
                    '-rawin', '-in', os.path.join(d, 'd.bin'), '-sigfile', os.path.join(d, 's.bin')]
        else:
            args = [exe, 'dgst', '-sha256', '-verify', os.path.join(d, 'k.pem'), '-signature',
                    os.path.join(d, 's.bin'), os.path.join(d, 'd.bin')]
        got = subprocess.run(args, capture_output=True, timeout=20)
        return got.returncode == 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


def pk_auth_data(raw, rp_id, attested=False):
    """The parts of authenticatorData, checked: the name's hash, the person there (UP) and
    known by face, finger or PIN (UV) - without UV it would be no second step."""
    if len(raw) < 37:
        raise ApiError(400, 'the passkey\'s answer is cut short')
    if not hmac.compare_digest(raw[:32], hashlib.sha256(rp_id.encode()).digest()):
        raise ApiError(400, 'the passkey is for another name than %s' % rp_id)
    flags = raw[32]
    if not flags & 0x01:
        raise ApiError(400, 'the passkey says nobody was there')
    if not flags & 0x04:
        raise ApiError(400, 'the passkey did not ask for the face, the finger or the PIN - '
                            'that is no second step')
    out = {'flags': flags, 'count': int.from_bytes(raw[33:37], 'big'),
           'backed_up': bool(flags & 0x10)}
    if attested:
        if not flags & 0x40 or len(raw) < 55:
            raise ApiError(400, 'the passkey gave no key')
        n = int.from_bytes(raw[53:55], 'big')
        if n < 16 or n > 1023 or len(raw) < 55 + n + 1:
            raise ApiError(400, 'the passkey\'s id is not of a size taken')
        out['id'] = pk_b64u(raw[55:55 + n])
        try:
            cose, _end = pk_cbor(raw, 55 + n)
            out['pem'], out['alg'] = pk_cose_pem(cose)
        except ValueError as e:
            raise ApiError(400, 'the passkey\'s key: %s' % e)
    return out


def pk_client_data(b64, want_type, challenge, rp_id):
    try:
        raw = pk_unb64u(b64)
        cd = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, 'the passkey\'s answer is not one')
    if not isinstance(cd, dict) or cd.get('type') != want_type:
        raise ApiError(400, 'the passkey\'s answer is of another kind')
    if not hmac.compare_digest(str(cd.get('challenge') or ''), str(challenge or '')):
        raise ApiError(400, 'the passkey answered another question - try again')
    try:
        o = urllib.parse.urlsplit(str(cd.get('origin') or ''))
        o_ok = o.scheme == 'https' and (o.hostname or '').lower() == rp_id and not o.path
    except ValueError:
        o_ok = False
    if not o_ok or cd.get('crossOrigin'):
        raise ApiError(400, 'the passkey was asked from another page (%s)' % cd.get('origin'))
    return raw


def pk_challenge(h, s, purpose, rp_id):
    """A question for the passkey, kept in the sign-in (once, five minutes, for this name)."""
    ch = pk_b64u(secrets.token_bytes(32))
    h.store.session_merge(s['id'], {'mfa_pk': {'c': ch, 'p': purpose, 'host': rp_id,
                                               'exp': time.time() + PASSKEY_CHALLENGE_S}})
    return ch


def pk_challenge_take(h, s, purpose, rp_id):
    got = ((s.get('data') or {}).get('mfa_pk')) or {}
    if not h.store.session_take(s['id'], 'mfa_pk'):
        raise ApiError(400, 'the question for the passkey was answered already, or never asked - '
                            'try again')
    if got.get('p') != purpose or got.get('host') != rp_id or \
            time.time() > float(got.get('exp') or 0):
        raise ApiError(400, 'the question for the passkey ran out, or was for another page - '
                            'try again')
    return got['c']


def pk_user_id(name):
    return pk_b64u(hashlib.sha256(('acme-user:' + str(name).lower()).encode()).digest()[:16])


def pk_create_options(h, s, acc, rp_id):
    site = str(CONFIG.get('site_name') or 'acme')
    rec = mfa_get(h.store, acc['name']) or {}
    return {'publicKey': {
        'challenge': pk_challenge(h, s, 'enrol', rp_id),
        'rp': {'id': rp_id, 'name': '%s · %s' % (site, rp_id)},
        'user': {'id': pk_user_id(acc['name']), 'name': acc['name'],
                 'displayName': acc.get('display') or acc['name']},
        'pubKeyCredParams': [{'type': 'public-key', 'alg': a} for a in PASSKEY_ALGS],
        'authenticatorSelection': {'residentKey': 'preferred', 'requireResidentKey': False,
                                   'userVerification': 'required'},
        'excludeCredentials': [{'type': 'public-key', 'id': k['id']}
                               for k in (rec.get('keys') or []) if k.get('id')],
        'attestation': 'none', 'timeout': PASSKEY_CHALLENGE_S * 1000}}


def pk_get_options(h, s, acc, rp_id):
    rec = mfa_get(h.store, acc['name']) or {}
    keys = [k for k in (rec.get('keys') or []) if k.get('host') == rp_id]
    if not keys:
        raise ApiError(400, 'the passkey of this account is for %s - open the pages by that name'
                       % ', '.join(sorted({str(k.get('host')) for k in rec.get('keys') or []})
                                   or ['another name']))
    return {'publicKey': {'challenge': pk_challenge(h, s, 'check', rp_id), 'rpId': rp_id,
                          'userVerification': 'required', 'timeout': PASSKEY_CHALLENGE_S * 1000,
                          'allowCredentials': [{'type': 'public-key', 'id': k['id']} for k in keys]}}


def pk_enrol_finish(h, s, acc, b, rp_id):
    """The passkey made on the device, checked: the key kept for the account."""
    challenge = pk_challenge_take(h, s, 'enrol', rp_id)
    pk_client_data(b.get('clientDataJSON'), 'webauthn.create', challenge, rp_id)
    try:
        att, _end = pk_cbor(pk_unb64u(b.get('attestationObject')))
    except ValueError as e:
        raise ApiError(400, 'the passkey\'s answer: %s' % e)
    if not isinstance(att, dict) or not isinstance(att.get('authData'), bytes):
        raise ApiError(400, 'the passkey\'s answer has no authenticator data')
    ad = pk_auth_data(att['authData'], rp_id, attested=True)
    name = re.sub(r'[\x00-\x1f<>]', '', str(b.get('name') or ''))[:60].strip() or 'passkey'
    return {'id': ad['id'], 'pem': ad['pem'], 'alg': ad['alg'], 'count': ad['count'],
            'host': rp_id, 'name': name, 'created': time.time(), 'last_used': 0,
            'backed_up': ad['backed_up']}


def pk_check(h, s, acc, b, rp_id):
    """The passkey's answer at a sign-in: the second step given, or ApiError. The counter and
    the time it was used kept (under MFA_LOCK, by the caller)."""
    challenge = pk_challenge_take(h, s, 'check', rp_id)
    rec = mfa_get(h.store, acc['name']) or {}
    kid = str(b.get('id') or '')
    key = [k for k in (rec.get('keys') or []) if k.get('id') == kid and k.get('host') == rp_id]
    if not key:
        h.store.add_event('sign-ins', '%s: a passkey not known here was given from %s' % (
            acc['name'], h.client_ip()), 'warn', who=acc['name'])
        raise ApiError(400, 'that passkey is not known here (taken away, or of another server)')
    key = key[0]
    cd_raw = pk_client_data(b.get('clientDataJSON'), 'webauthn.get', challenge, rp_id)
    try:
        ad_raw, sig = pk_unb64u(b.get('authenticatorData')), pk_unb64u(b.get('signature'))
    except ValueError:
        raise ApiError(400, 'the passkey\'s answer is not one')
    ad = pk_auth_data(ad_raw, rp_id)
    if not pk_verify(key['pem'], key.get('alg'), ad_raw + hashlib.sha256(cd_raw).digest(), sig):
        h.store.add_event('sign-ins', '%s: a passkey\'s signature did not hold, from %s' % (
            acc['name'], h.client_ip()), 'bad', who=acc['name'])
        raise ApiError(400, 'the passkey\'s signature does not hold')
    was = int(key.get('count') or 0)
    if was and ad['count'] and ad['count'] <= was:
        h.store.add_event('sign-ins', '%s: the counter of the passkey %s went back (%d after %d) '
                          '- it may have been copied' % (acc['name'], key.get('name'), ad['count'],
                                                         was), 'bad', who=acc['name'])
        raise ApiError(400, 'the counter of the passkey went back - it may have been copied')
    key['count'] = ad['count']
    key['last_used'] = time.time()
    return rec, key


def pk_keys_view(rec):
    """An account's passkeys as the pages show them - never the key itself."""
    return [{'id': k.get('id'), 'name': k.get('name'), 'host': k.get('host'),
             'created': k.get('created'), 'last_used': k.get('last_used'),
             'backed_up': k.get('backed_up')} for k in (rec or {}).get('keys') or []]
