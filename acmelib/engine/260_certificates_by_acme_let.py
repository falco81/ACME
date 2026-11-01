# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- certificates by ACME: Let's Encrypt and the like (1.0.169) --------------------------
# Settings → Automatic certificates: the certificate of the VIP address (and,
# where asked, each node's own) ordered from an ACME CA - Let's Encrypt, its
# staging, or one of your own (step-ca, an internal CA) - by HTTP-01, and
# renewed when fewer than acme_days are left. The answer to the challenge is
# kept in the database, so whichever node the CA reaches on port 80 gives it
# (nginx sends /.well-known/acme-challenge/ to acme.php, which asks the
# daemon): in a cluster the VIP address may be on either node. The web
# address's certificate is ordered by the one node that does what one node
# does for both (alerts_lead); a node's own by that node. Signed with openssl;
# done in a thread of its own, never on the way of a sign-in.
ACME_CAS = {'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
            'letsencrypt-staging': 'https://acme-staging-v02.api.letsencrypt.org/directory'}
ACME_WORK = {'busy': False, 'at': 0.0, 'says': '', 'target': '', 'n': 0, 'of': 0, 'done': 0, 'each': {}}
# Several certificates at once (1.0.203): at most this many orders side by side.
ACME_PARALLEL = max(1, int(os.environ.get('ACME_ACME_PARALLEL') or 3))
_ACME_CUR = threading.local()          # the certificate this thread orders
_ACME_LOCK = threading.Lock()


def acme_progress(text):
    """What the order of this thread waits for now - on its own card, and as
    the last word of the whole (1.0.203)."""
    text = str(text)[:300]
    ACME_WORK['says'] = text
    t = getattr(_ACME_CUR, 'target', '')
    if t:
        with _ACME_LOCK:
            one = ACME_WORK['each'].get(t)
            if one is not None:
                one['says'] = text
ACME_EVERY = float(os.environ.get('ACME_ACME_EVERY') or 3600)
ACME_RETRY = float(os.environ.get('ACME_ACME_RETRY') or 6 * 3600)


class AcmeError(Exception):
    pass


def _b64u(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def acme_directory_url():
    ca = CONFIG.get('acme_ca') or 'letsencrypt'
    if ca == 'custom':
        return str(CONFIG.get('acme_url') or '').strip()
    return ACME_CAS.get(ca, ACME_CAS['letsencrypt'])


def _acme_ctx():
    ctx = ssl.create_default_context()
    pem = str(CONFIG.get('acme_ca_pem') or '').strip()
    if pem and CONFIG.get('acme_ca') == 'custom':
        ctx.load_verify_locations(cadata=pem)
    return ctx


def _acme_account_gone(kind, said):
    """The CA's error says the account it was asked with is no more (RFC 8555
    accountDoesNotExist; Boulder's 'unauthorized' for one deactivated or not found)."""
    if kind.endswith(':accountDoesNotExist') or kind == 'accountDoesNotExist':
        return True
    low = str(said or '').lower()
    return kind.endswith('unauthorized') and 'account' in low and \
        any(w in low for w in ('deactivated', 'not valid', 'not found', 'does not exist', 'revoked'))


def _rfc3339(text):
    """2025-01-02T04:00:00Z (fractions and offsets too) as a time, or 0."""
    m = re.match(r'^(\d{4})-(\d\d)-(\d\d)[Tt ](\d\d):(\d\d):(\d\d)(\.\d+)?(Z|z|[+-]\d\d:\d\d)$',
                 str(text or '').strip())
    if not m:
        return 0.0
    t = calendar.timegm(tuple(int(m.group(i)) for i in range(1, 7)) + (0, 0, 0))
    if m.group(8) not in ('Z', 'z'):
        sign = 1 if m.group(8)[0] == '+' else -1
        t -= sign * (int(m.group(8)[1:3]) * 3600 + int(m.group(8)[4:6]) * 60)
    return float(t) + (float(m.group(7)) if m.group(7) else 0.0)


# The keys Let's Encrypt takes (1.0.196): RSA of 2048, 3072, 4096 bits, ECDSA on
# P-256 or P-384 - for the account and for a certificate alike.
ACME_KEY_WORDS = {'ec': 'ECDSA P-256', 'ec384': 'ECDSA P-384', 'rsa2048': 'RSA 2048',
                  'rsa3072': 'RSA 3072', 'rsa4096': 'RSA 4096'}
# A certificate's choice: one key, or two certificates - RSA served by default,
# ECDSA to the clients that take it (what Let's Encrypt advises).
ACME_CERT_KEYS = {'dual': ('rsa2048', 'ec'), 'dual-strong': ('rsa4096', 'ec384'),
                  'ec': ('ec',), 'ec384': ('ec384',), 'rsa2048': ('rsa2048',),
                  'rsa3072': ('rsa3072',), 'rsa4096': ('rsa4096',)}


def ari_cert_id(cert):
    """A certificate's ARI id (RFC 9773): base64url of its Authority Key
    Identifier, ".", base64url of its serial number's DER bytes - '' when it
    has no AKI (not one an ACME CA made)."""
    if not cert:
        return ''
    try:
        out = _openssl(['x509', '-noout', '-serial', '-ext', 'authorityKeyIdentifier'],
                       str(cert).encode(), what='the certificate').decode()
    except ValueError:
        return ''
    serial = re.search(r'serial=([0-9A-Fa-f]+)', out)
    aki = re.search(r'(?:keyid:)?((?:[0-9A-Fa-f]{2}:){7,}[0-9A-Fa-f]{2})', out.split('Authority Key Identifier', 1)[-1])
    if not serial or not aki:
        return ''
    sb = bytes.fromhex(serial.group(1).rjust(len(serial.group(1)) + len(serial.group(1)) % 2, '0'))
    if sb and sb[0] & 0x80:
        sb = b'\x00' + sb                      # DER: a positive integer
    return '%s.%s' % (_b64u(bytes.fromhex(aki.group(1).replace(':', ''))), _b64u(sb))


class Acme(object):
    """One conversation with the CA: the account, its key, the nonces."""
    def __init__(self, store):
        self.store = store
        self.dir_url = acme_directory_url()
        if not re.match(r'^https://[^\s]+\Z', self.dir_url):
            raise AcmeError('the ACME directory is an https:// address')
        self.work = tempfile.mkdtemp(prefix='acme-acme-', dir=str(STATE_DIR))
        os.chmod(self.work, 0o700)
        self.nonce = None
        self.kid = None
        try:
            self.dir = self._get(self.dir_url)[0]
            self._account()
        except BaseException:
            # Its folder gone with it (1.0.205): every CA not answering left one,
            # and after a refused account a key unsealed in it.
            self.close()
            raise

    def close(self):
        shutil.rmtree(self.work, ignore_errors=True)

    # -- HTTP ------------------------------------------------------------------------
    def _req(self, url, data=None, method=None, accept='application/json'):
        if not str(url).startswith('https://'):
            raise AcmeError('the CA sent an address that is not https: %s' % url)
        req = urllib.request.Request(url, data=data, method=method or ('POST' if data else 'GET'),
                                     headers={'User-Agent': 'acme/%s (acme)' % __version__,
                                              'Accept': accept})
        if data is not None:
            req.add_header('Content-Type', 'application/jose+json')
        try:
            with url_open(req, timeout=30, context=_acme_ctx(), purpose='acme') as r:
                body, headers, status = r.read(1 << 20), r.headers, r.status
        except urllib.error.HTTPError as e:
            body, headers, status = e.read(1 << 20), e.headers, e.code
        except (OSError, ssl.SSLError) as e:
            raise AcmeError('the CA did not answer (%s): %s' % (
                urllib.parse.urlsplit(url).hostname, getattr(e, 'reason', e)))
        if headers.get('Replay-Nonce'):
            self.nonce = headers['Replay-Nonce']
        return body, headers, status

    def _get(self, url):
        body, headers, status = self._req(url)
        if status >= 400:
            raise AcmeError('the CA said %d: %s' % (status, body[:200]))
        return json.loads(body.decode('utf-8')), headers

    # -- signing ---------------------------------------------------------------------
    def _key_file(self):
        p = os.path.join(self.work, 'account.pem')
        if not os.path.exists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(self.key_pem)
        return p

    def _alg(self):
        """(JWS alg, digest, bytes of r and s) of the account key (1.0.196)."""
        kind = getattr(self, 'akind', 'ec')
        if kind == 'ec384':
            return 'ES384', '-sha384', 48
        if kind.startswith('rsa'):
            return 'RS256', '-sha256', 0
        return 'ES256', '-sha256', 32

    def _jwk(self):
        if getattr(self, '_jwk_done', None):
            return self._jwk_done
        alg, _, size = self._alg()
        if alg == 'RS256':
            txt = _openssl(['pkey', '-in', self._key_file(), '-noout', '-text_pub'],
                           what='the account key').decode()
            m = re.search(r'(?s)Modulus:\s*\n(.*?)\n\S', txt)
            e = re.search(r'Exponent:\s*(\d+)', txt)
            if not m or not e:
                raise AcmeError('the RSA account key does not read')
            n = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', m.group(1))).lstrip(b'\x00')
            ev = int(e.group(1))
            jwk = {'e': _b64u(ev.to_bytes((ev.bit_length() + 7) // 8, 'big')), 'kty': 'RSA',
                   'n': _b64u(n)}
        else:
            der = _openssl(['pkey', '-in', self._key_file(), '-pubout', '-outform', 'DER'],
                           what='the account key')
            point = der[-2 * size:]
            jwk = {'crv': 'P-384' if size == 48 else 'P-256', 'kty': 'EC',
                   'x': _b64u(point[:size]), 'y': _b64u(point[size:])}
        self._jwk_done = jwk
        return jwk

    def thumbprint(self):
        # RFC 7638: the required members only, sorted - the JWK holds just those.
        return _b64u(hashlib.sha256(json.dumps(
            self._jwk(), separators=(',', ':'), sort_keys=True).encode()).digest())

    def _sign(self, data):
        alg, digest, size = self._alg()
        der = _openssl(['dgst', digest, '-sign', self._key_file()], data=data,
                       what='signing for the CA')
        if alg == 'RS256':
            return der                       # PKCS#1 v1.5, as JWS wants it
        # DER SEQUENCE { INTEGER r, INTEGER s } -> r || s, `size` bytes each.
        i = 2 if der[1] < 0x80 else 3

        def integer(at):
            n = der[at + 1]
            v = der[at + 2:at + 2 + n].lstrip(b'\x00')
            return v.rjust(size, b'\x00'), at + 2 + n
        r, i = integer(i)
        s, _ = integer(i)
        return r + s

    def post(self, url, payload, use_jwk=False):
        anew = False
        for attempt in (1, 2, 3):
            if not self.nonce:
                self._req(self.dir['newNonce'], method='HEAD')
            protected = {'alg': self._alg()[0], 'nonce': self.nonce, 'url': url}
            if use_jwk or not self.kid:
                protected['jwk'] = self._jwk()
            else:
                protected['kid'] = self.kid
            p64 = _b64u(json.dumps(protected))
            b64 = '' if payload is None else _b64u(json.dumps(payload))
            sig = _b64u(self._sign(('%s.%s' % (p64, b64)).encode('ascii')))
            self.nonce = None
            body, headers, status = self._req(url, json.dumps(
                {'protected': p64, 'payload': b64, 'signature': sig}).encode('utf-8'),
                accept='application/json' if 'cert' not in url else
                'application/pem-certificate-chain')
            if status == 400 and b'badNonce' in body and attempt == 1:
                continue
            if status >= 400:
                try:
                    err = json.loads(body.decode('utf-8'))
                    said = err.get('detail') or err.get('type')
                    kind = str(err.get('type') or '')
                except (ValueError, AttributeError):
                    said, kind = body[:200].decode('utf-8', 'replace'), ''
                # The account kept here gone from the CA (1.0.187): deleted,
                # deactivated, a CA of the same address started anew. Each
                # renewal was refused for it until the certificates ran out;
                # now a new account is made, and the request asked again.
                if self.kid and not use_jwk and not anew and url != self.dir.get('newAccount') and \
                        _acme_account_gone(kind, said):
                    anew = True
                    log('ACME: the CA does not know the account any more (%s) - a new one is made'
                        % said, 'warn')
                    self._account(fresh=True)
                    continue
                raise AcmeError('the CA refused it: %s' % said)
            return body, headers

    def post_json(self, url, payload):
        body, headers = self.post(url, payload)
        return (json.loads(body.decode('utf-8')) if body else {}), headers

    # -- the account -----------------------------------------------------------------
    def _account(self, fresh=False):
        row = {} if fresh else (_meta_json(self.store, 'acme:account') or {})
        pem = unseal_secret(row.get('key') or '', 'acme') if row.get('key') else ''
        # The kind of key asked for (1.0.196): another one than the account has
        # makes a new account with a key of that kind.
        self.akind = str(CONFIG.get('acme_account_key') or 'ec')
        if self.akind not in ACME_KEY_WORDS:
            self.akind = 'ec'
        if row.get('directory') != self.dir_url or not pem or \
                (row.get('kind') or 'ec') != self.akind:
            pem = ''
        if fresh:
            self.kid = None
            self._jwk_done = None
            try:
                os.unlink(os.path.join(self.work, 'account.pem'))
            except OSError:
                pass
        if not pem:
            pem = new_key(self.akind)
            row = {}
            self.kid = None
            self._jwk_done = None
            try:
                os.unlink(os.path.join(self.work, 'account.pem'))
            except OSError:
                pass
        self.key_pem = pem
        if row.get('kid'):
            self.kid = row['kid']
            return
        mail = str(CONFIG.get('acme_email') or '').strip()
        payload = {'termsOfServiceAgreed': True}
        if mail:
            payload['contact'] = ['mailto:' + mail]
        body, headers = self.post(self.dir['newAccount'], payload, use_jwk=True)
        self.kid = headers.get('Location')
        if not self.kid:
            raise AcmeError('the CA made no account')
        self.store.set_meta('acme:account', json.dumps({
            'key': seal_secret(pem, 'acme'), 'kid': self.kid, 'directory': self.dir_url,
            'email': mail, 'at': time.time(), 'kind': self.akind}))

    # -- an order --------------------------------------------------------------------
    def _poll(self, url, done, what, secs=90):
        end = time.time() + secs
        while True:
            got, hdr = self.post_json(url, None)
            st = got.get('status')
            if st in done:
                return got
            if st == 'invalid':
                errs = [c.get('error', {}).get('detail') for c in got.get('challenges') or []
                        if c.get('error')] or [got.get('error', {}).get('detail')]
                raise AcmeError('%s: %s' % (what, '; '.join(e for e in errs if e) or 'invalid'))
            if time.time() > end:
                raise AcmeError('%s: the CA has not said in %d s (%s)' % (what, secs, st))
            # As long as the CA asks (Retry-After, 1.0.196), within reason.
            try:
                wait = float(hdr.get('Retry-After') or 2)
            except (TypeError, ValueError):
                wait = 2.0
            time.sleep(max(1.0, min(30.0, wait, max(0.0, end - time.time()))))

    def renewal_info(self, cert_id):
        """The CA's window to renew a certificate in (ARI, RFC 9773), or None."""
        base = self.dir.get('renewalInfo')
        if not base or not cert_id:
            return None
        got, _ = self._get(base.rstrip('/') + '/' + cert_id)
        w = got.get('suggestedWindow') or {}
        start, end = _rfc3339(w.get('start')), _rfc3339(w.get('end'))
        if not start or not end or end < start:
            return None
        return {'start': start, 'end': end, 'url': got.get('explanationURL') or ''}

    def order(self, names, say, key_kind=None, replaces=''):
        say('ordered from the CA' + (' (%s)' % ACME_KEY_WORDS.get(key_kind, key_kind) if key_kind else ''))
        ask = {'identifiers': [{'type': 'dns', 'value': n} for n in names]}
        # The profile asked for (1.0.196), where the CA offers it - tlsserver,
        # shortlived at Let's Encrypt; a CA without profiles is asked as before.
        prof = str(CONFIG.get('acme_profile') or '')
        offered = (self.dir.get('meta') or {}).get('profiles') or {}
        if prof and prof in offered:
            ask['profile'] = prof
        elif prof:
            say('this CA offers no profile %s - its own is used' % prof)
        # The certificate it renews (1.0.196, ARI - RFC 9773): the CA counts it as
        # a renewal, its rate limits too.
        if replaces and self.dir.get('renewalInfo'):
            ask['replaces'] = replaces
        try:
            got, headers = self.post_json(self.dir['newOrder'], ask)
        except AcmeError as e:
            # Only the account that ordered a certificate may say it replaces
            # it (1.0.199): an account made since - another kind of its key,
            # one the CA forgot - is refused ("requester account did not
            # request the certificate being replaced"). Ordered again as a new
            # one: a renewal all the same, just not counted as one.
            if 'replaces' not in ask or 'replace' not in str(e).lower():
                raise
            say('the CA does not take it as the renewal of the one before (another account ordered '
                'that one) - ordered as a new certificate')
            ask.pop('replaces', None)
            got, headers = self.post_json(self.dir['newOrder'], ask)
        order_url = headers.get('Location')
        thumb = self.thumbprint()
        for az in got.get('authorizations') or []:
            a, _ = self.post_json(az, None)
            if a.get('status') == 'valid':
                continue
            name = a.get('identifier', {}).get('value')
            kind = 'dns-01' if (CONFIG.get('acme_challenge') or 'http-01') == 'dns-01' else 'http-01'
            ch = [c for c in a.get('challenges') or [] if c.get('type') == kind]
            if not ch:
                raise AcmeError('the CA offers no %s challenge for %s' % (kind.upper(), name))
            token = ch[0]['token']
            if not re.match(r'^[A-Za-z0-9_-]{8,256}\Z', token):
                raise AcmeError('the CA sent a token that is not one')
            auth = token + '.' + thumb
            if kind == 'dns-01':
                # A TXT record in DNS (1.0.169): for a server the CA cannot
                # reach - nothing has to be open to the internet.
                txt = _b64u(hashlib.sha256(auth.encode()).digest())
                undo = acme_dns_put(self.store, name, txt, say)
                try:
                    say('the CA looks up _acme-challenge.%s' % name)
                    self.post_json(ch[0]['url'], {})
                    self._poll(az, ('valid',), 'the CA did not take %s' % name, 180)
                finally:
                    try:
                        undo()
                    except Exception as e:              # noqa: BLE001
                        log('ACME: the TXT record of %s was not taken away: %s' % (name, e), 'warn')
                continue
            # Kept where every node finds it; the other node's copy of the
            # database has it within seconds.
            self.store.set_meta('acme:chal:' + token, json.dumps(
                {'auth': auth, 'at': time.time(), 'name': name}))
            time.sleep(float(os.environ.get('ACME_ACME_SETTLE') or 3))
            say('the CA looks at http://%s/.well-known/acme-challenge/' % name)
            try:
                self.post_json(ch[0]['url'], {})
                self._poll(az, ('valid',), 'the CA did not take %s' % name)
            finally:
                self.store.db.run('DELETE FROM meta WHERE k = ?', ('acme:chal:' + token,))
        key, csr = make_csr(names[0], names[1:], key_kind or (CONFIG.get('acme_key') or 'ec'))
        der = _openssl(['req', '-in', '/dev/stdin', '-outform', 'DER'], data=csr.encode(),
                       what='the request')
        say('the certificate is made')
        o, _ = self.post_json(got['finalize'], {'csr': _b64u(der)})
        if o.get('status') != 'valid':
            o = self._poll(order_url, ('valid',), 'the order', 120)
        body, _ = self.post(o['certificate'], None)
        return key, body.decode('utf-8')


