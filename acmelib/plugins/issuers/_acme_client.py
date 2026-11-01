# -*- coding: utf-8 -*-
"""
An ACME client (RFC 8555) for the `acme` issuer - accounts (EAB too), orders,
authorizations, finalize, the chain (alternates), revocation and ARI
(RFC 9773). Adapted from the engine's own client (acmelib/engine/260_*,
265_*), all its traffic going through the module's Context: ctx.http for
HTTP, ctx.openssl for the keys and the JWS signatures.

Not a plugin (its name starts with "_", the registry passes it by).
"""
from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
import urllib.parse

from acmelib.plugins.base import PluginError
from acmelib.plugins.issuers import _scep_pkcs7 as der

try:
    from acmelib import __version__ as VERSION
except Exception:                                   # noqa: BLE001
    VERSION = '?'

DIRECTORIES = {
    'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
    'letsencrypt-staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
    'zerossl': 'https://acme.zerossl.com/v2/DV90',
    'google': 'https://dv.acme-v02.api.pki.goog/directory',
    'google-staging': 'https://dv.acme-v02.test-api.pki.goog/directory',
    'buypass': 'https://api.buypass.com/acme/directory',
    'buypass-staging': 'https://api.test4.buypass.no/acme/directory',
    'sslcom-rsa': 'https://acme.ssl.com/sslcom-dv-rsa',
    'sslcom-ecc': 'https://acme.ssl.com/sslcom-dv-ecc',
    # DigiCert CertCentral (also as sold by SSLmarket: the EAB from its customer
    # administration) - see docs/sslmarket.md
    'digicert': 'https://acme.digicert.com/v2/acme/directory/',
}
DIRECTORY_WORDS = {
    'letsencrypt': "Let's Encrypt", 'letsencrypt-staging': "Let's Encrypt (staging)",
    'zerossl': 'ZeroSSL', 'google': 'Google Trust Services',
    'google-staging': 'Google Trust Services (staging)', 'buypass': 'Buypass Go SSL',
    'buypass-staging': 'Buypass (test)', 'sslcom-rsa': 'SSL.com (RSA)',
    'sslcom-ecc': 'SSL.com (ECC)', 'digicert': 'DigiCert (EAB)', 'custom': 'your own ACME server',
}
ACCOUNT_KEYS = {'ec-256': ('ES256', '-sha256', 32), 'ec-384': ('ES384', '-sha384', 48),
                'rsa-2048': ('RS256', '-sha256', 0), 'rsa-3072': ('RS256', '-sha256', 0),
                'rsa-4096': ('RS256', '-sha256', 0)}
REVOKE_REASONS = {'unspecified': 0, 'keyCompromise': 1, 'key_compromise': 1,
                  'affiliationChanged': 3, 'superseded': 4, 'cessationOfOperation': 5,
                  'cessation_of_operation': 5, 'privilegeWithdrawn': 9}

# What the CA's problem types mean, in words one can act on (RFC 8555 6.7 and
# what Let's Encrypt says).
PROBLEM_WORDS = {
    'badNonce': 'the CA refused a stale nonce again and again',
    'badCSR': 'the CA refused the request (CSR) - its key or names are not allowed',
    'badPublicKey': 'the CA does not take this kind of key - choose another key type',
    'badSignatureAlgorithm': 'the CA does not take this signature algorithm - choose another '
                             'account key type',
    'rejectedIdentifier': 'the CA will not issue for one of these names (its policy, a '
                          'blocked name, an IP address without the right profile)',
    'unsupportedIdentifier': 'the CA does not issue for this kind of name (IP addresses: '
                             "Let's Encrypt only with the shortlived profile)",
    'caa': 'a CAA record in DNS does not allow this CA for the name - add the CA (for '
           'Let\'s Encrypt: 0 issue "letsencrypt.org") to the CAA record',
    'dns': 'the CA could not look the name up in DNS (no such name, a DNS server that fails)',
    'connection': 'the CA could not reach the server for the challenge (port 80 closed, a '
                  'firewall, the wrong address in DNS)',
    'tls': 'the CA had a TLS problem talking to the server for the challenge',
    'incorrectResponse': 'the CA saw a wrong answer to the challenge (an old TXT record, '
                         'another server answering on port 80)',
    'unauthorized': 'the CA did not accept the proof for the name',
    'rateLimited': 'the CA\'s rate limit is reached',
    'externalAccountRequired': 'this CA needs External Account Binding: set the EAB key id '
                               'and HMAC key from the CA\'s dashboard',
    'accountDoesNotExist': 'the CA does not know the account',
    'userActionRequired': 'the CA wants something done by hand (new terms of service?) - '
                          'see its website',
    'invalidContact': 'the CA refused the contact e-mail address',
    'unsupportedContact': 'the CA refused the contact e-mail address',
    'malformed': 'the CA could not read the request',
    'serverInternal': 'the CA had an error of its own - try again later',
    'orderNotReady': 'the order was not ready to be finalized',
    'alreadyRevoked': 'the certificate is revoked already',
    'badRevocationReason': 'the CA does not take that reason for revocation',
    'conflict': 'the CA reported a conflict',
}


def b64u(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64u_decode(text):
    text = str(text).strip()
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def rfc3339(text):
    """2025-01-02T04:00:00Z (fractions and offsets too) as epoch seconds, or 0."""
    m = re.match(r'^(\d{4})-(\d\d)-(\d\d)[Tt ](\d\d):(\d\d):(\d\d)(\.\d+)?(Z|z|[+-]\d\d:\d\d)$',
                 str(text or '').strip())
    if not m:
        return 0.0
    t = calendar.timegm(tuple(int(m.group(i)) for i in range(1, 7)) + (0, 0, 0))
    if m.group(8) not in ('Z', 'z'):
        sign = 1 if m.group(8)[0] == '+' else -1
        t -= sign * (int(m.group(8)[1:3]) * 3600 + int(m.group(8)[4:6]) * 60)
    return float(t) + (float(m.group(7)) if m.group(7) else 0.0)


def http_date(text):
    """Retry-After: seconds or an HTTP date -> seconds from now (None)."""
    text = str(text or '').strip()
    if not text:
        return None
    if re.match(r'^\d+(\.\d+)?$', text):
        return float(text)
    try:
        import email.utils
        t = email.utils.parsedate_to_datetime(text).timestamp()
        return max(0.0, t - time.time())
    except (TypeError, ValueError):
        return None


def ari_id(cert):
    """A certificate's ARI CertID (RFC 9773 4.1): base64url(AKI keyIdentifier)
    '.' base64url(the serial number's DER content bytes). '' without an AKI."""
    try:
        c = der.Cert(cert)
    except (der.DerError, ValueError, IndexError):
        return ''
    keyid = c.aki_keyid
    if not keyid:
        return ''
    return '%s.%s' % (b64u(keyid), b64u(c.serial_content))


def identifiers(names):
    out = []
    seen = set()
    for n in names:
        n = str(n).strip()
        try:
            ip = ipaddress.ip_address(n)
            ident = {'type': 'ip', 'value': str(ip)}
        except ValueError:
            ident = {'type': 'dns', 'value': n.lower().rstrip('.')}
        k = (ident['type'], ident['value'])
        if k not in seen:
            seen.add(k)
            out.append(ident)
    return out


def ecdsa_der_to_raw(sig, size):
    """DER SEQUENCE { INTEGER r, INTEGER s } -> r || s, `size` bytes each (JWS)."""
    _t, c, _w = der.der_one(sig)
    items = der.der_items(c)
    r = items[0][1].lstrip(b'\x00').rjust(size, b'\x00')
    s = items[1][1].lstrip(b'\x00').rjust(size, b'\x00')
    if len(r) != size or len(s) != size:
        raise PluginError('the ECDSA signature does not have the size of the key')
    return r + s


def ecdsa_raw_to_der(raw):
    size = len(raw) // 2

    def integer(b):
        b = b.lstrip(b'\x00') or b'\x00'
        if b[0] & 0x80:
            b = b'\x00' + b
        return der.tlv(0x02, b)
    return der.seq(integer(raw[:size]), integer(raw[size:]))


def problem_words(prob, status=None):
    """('words', 'short type', detail) of an RFC 7807 problem document."""
    if not isinstance(prob, dict):
        return ('the CA said %s' % (status or '?'), '', str(prob)[:300])
    typ = str(prob.get('type') or '')
    short = typ.rsplit(':', 1)[-1] if typ else ''
    detail = str(prob.get('detail') or '')
    subs = []
    for sp in prob.get('subproblems') or []:
        if isinstance(sp, dict):
            idv = (sp.get('identifier') or {}).get('value') or ''
            subs.append('%s: %s' % (idv, sp.get('detail') or sp.get('type')))
    if subs:
        detail = (detail + ' (' + '; '.join(subs) + ')').strip()
    base = PROBLEM_WORDS.get(short) or ('the CA refused it (%s)' % (short or status or '?'))
    return base, short, detail


class AcmeKey(object):
    """The account key (or a certificate's key, for revocation): JWK, thumbprint, JWS."""
    def __init__(self, client, pem_text, kind=None):
        self.client = client
        self.pem = pem_text
        self.file = client.file(pem_text)
        spki = client.run(['pkey', '-in', self.file, '-pubout', '-outform', 'DER'])
        alg_items = der.der_items(der.der_items(der.der_one(spki)[1])[0][1])
        alg = der.oid_decode(alg_items[0][1])
        bits = der.der_items(der.der_one(spki)[1])[1][1][1:]   # the BIT STRING less its unused-bits byte
        if alg == '1.2.840.10045.2.1':
            curve = der.oid_decode(alg_items[1][1])
            if curve == '1.2.840.10045.3.1.7':
                self.alg, self.digest, self.size, crv = 'ES256', '-sha256', 32, 'P-256'
            elif curve == '1.3.132.0.34':
                self.alg, self.digest, self.size, crv = 'ES384', '-sha384', 48, 'P-384'
            else:
                raise PluginError('the key is on a curve ACME does not use (P-256, P-384 only)',
                                  retry=False)
            if bits[:1] != b'\x04':
                raise PluginError('a compressed EC key cannot be used')
            pt = bits[1:]
            self.jwk = {'crv': crv, 'kty': 'EC', 'x': b64u(pt[:self.size]),
                        'y': b64u(pt[self.size:])}
        elif alg == der.OID_RSA:
            self.alg, self.digest, self.size = 'RS256', '-sha256', 0
            rsa = der.der_items(der.der_one(bits)[1])
            n = rsa[0][1].lstrip(b'\x00')
            e = rsa[1][1].lstrip(b'\x00')
            self.jwk = {'e': b64u(e), 'kty': 'RSA', 'n': b64u(n)}
        else:
            raise PluginError('the key is neither EC nor RSA - ACME cannot sign with it',
                              retry=False)

    def thumbprint(self):
        # RFC 7638: the required members only, sorted, no white space.
        return b64u(hashlib.sha256(json.dumps(self.jwk, separators=(',', ':'),
                                              sort_keys=True).encode()).digest())

    def sign(self, data):
        sig = self.client.run(['dgst', self.digest, '-sign', self.file], data)
        if self.alg == 'RS256':
            return sig
        return ecdsa_der_to_raw(sig, self.size)

    def jws(self, url, payload, nonce, kid=None):
        protected = {'alg': self.alg, 'nonce': nonce, 'url': url}
        if kid:
            protected['kid'] = kid
        else:
            protected['jwk'] = self.jwk
        p64 = b64u(json.dumps(protected, separators=(',', ':')))
        body = '' if payload is None else b64u(json.dumps(payload, separators=(',', ':')))
        sig = self.sign(('%s.%s' % (p64, body)).encode('ascii'))
        return {'protected': p64, 'payload': body, 'signature': b64u(sig)}


def eab_jws(account_jwk, eab_kid, eab_hmac_b64u, url):
    """The externalAccountBinding of a newAccount (RFC 8555 7.3.4): the account's
    JWK signed with the CA's HMAC key (HS256)."""
    try:
        key = b64u_decode(re.sub(r'\s+', '', eab_hmac_b64u))
    except (ValueError, TypeError):
        raise PluginError('the EAB HMAC key is not base64url - copy it again from the CA',
                          retry=False)
    protected = b64u(json.dumps({'alg': 'HS256', 'kid': eab_kid, 'url': url},
                                separators=(',', ':')))
    payload = b64u(json.dumps(account_jwk, separators=(',', ':'), sort_keys=True))
    sig = hmac.new(key, ('%s.%s' % (protected, payload)).encode('ascii'), hashlib.sha256).digest()
    return {'protected': protected, 'payload': payload, 'signature': b64u(sig)}


class AcmeClient(object):
    """One conversation with an ACME CA, through a module's Context."""
    def __init__(self, ctx, directory_url, verify=True, ca_pem=None, timeout=30,
                 say=None, allow_http_local=True, sleep=time.sleep):
        self.ctx = ctx
        self.dir_url = str(directory_url or '').strip()
        self.verify = verify
        self.ca_pem = ca_pem or None
        self.timeout = timeout
        self.say = say or (lambda words, level='info': None)
        self.allow_http_local = allow_http_local
        self.sleep = sleep
        self.nonce = None
        self.kid = None
        self.key = None
        self.dir = None
        self.work = tempfile.mkdtemp(prefix='acme-issuer-')
        os.chmod(self.work, 0o700)
        self._n = 0

    # -- files and openssl -----------------------------------------------------------
    def file(self, data):
        self._n += 1
        p = os.path.join(self.work, 'k%d.pem' % self._n)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data.encode() if isinstance(data, str) else data)
        return p

    def run(self, args, data=None):
        try:
            out = self.ctx.openssl(list(args), data)
        except PluginError:
            raise
        except Exception as e:                      # noqa: BLE001
            raise PluginError('openssl failed (%s): %s' % (args[0], e))
        return out if isinstance(out, bytes) else str(out).encode()

    def close(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- HTTP ------------------------------------------------------------------------
    def _check_url(self, url):
        u = urllib.parse.urlsplit(str(url))
        if u.scheme == 'https':
            return
        if u.scheme == 'http' and self.allow_http_local and \
                (u.hostname or '') in ('localhost', '127.0.0.1', '::1'):
            return
        raise PluginError('the CA gave an address that is not https: %s' % url, retry=False)

    def http(self, method, url, body=None, headers=None, accept='application/json'):
        self._check_url(url)
        h = {'User-Agent': 'acme/%s (acme certificate manager)' % VERSION, 'Accept': accept}
        if body is not None:
            h['Content-Type'] = 'application/jose+json'
        h.update(headers or {})
        try:
            status, hdrs, data = self.ctx.http(method, url, body, h, self.timeout, self.verify,
                                               self.ca_pem)
        except PluginError:
            raise
        except Exception as e:                      # noqa: BLE001
            raise PluginError('the CA does not answer (%s): %s - check DNS, the proxy '
                              '(Settings → Proxy) and the firewall'
                              % (urllib.parse.urlsplit(url).hostname, e))
        hdrs = {str(k).lower(): v for k, v in (hdrs or {}).items()}
        if hdrs.get('replay-nonce'):
            self.nonce = hdrs['replay-nonce']
        return status, hdrs, data or b''

    def get_json(self, url):
        status, hdrs, data = self.http('GET', url)
        if status >= 400:
            self._raise(status, hdrs, data, 'GET ' + url)
        try:
            return json.loads(data.decode('utf-8')), hdrs
        except ValueError:
            raise PluginError('the CA answered something that is not JSON at %s' % url,
                              detail=data[:300].decode('utf-8', 'replace'))

    def directory(self):
        if self.dir is None:
            got, _ = self.get_json(self.dir_url)
            if not isinstance(got, dict) or 'newOrder' not in got or 'newAccount' not in got:
                raise PluginError('%s is not an ACME directory (no newOrder/newAccount)'
                                  % self.dir_url, retry=False)
            self.dir = got
        return self.dir

    @property
    def meta(self):
        return (self.directory().get('meta') or {})

    def new_nonce(self):
        status, _h, _b = self.http('HEAD', self.directory()['newNonce'])
        if not self.nonce:
            status, _h, _b = self.http('GET', self.directory()['newNonce'])
        if not self.nonce:
            raise PluginError('the CA gives no nonce (newNonce answered %s)' % status)

    def _raise(self, status, hdrs, data, what=''):
        try:
            prob = json.loads(data.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            prob = data[:300].decode('utf-8', 'replace')
        words, short, detail = problem_words(prob, status)
        retry = short not in ('badCSR', 'badPublicKey', 'rejectedIdentifier',
                              'unsupportedIdentifier', 'externalAccountRequired', 'caa',
                              'invalidContact', 'unsupportedContact', 'userActionRequired',
                              'alreadyRevoked', 'badRevocationReason')
        if short == 'rateLimited':
            wait = http_date(hdrs.get('retry-after'))
            if wait:
                words += ' - try again after %s' % time.strftime(
                    '%Y-%m-%d %H:%M UTC', time.gmtime(time.time() + wait))
            else:
                words += ' - try again later (Let\'s Encrypt: 5 certificates a week for the '\
                         'same names, 50 a week per domain; use the staging directory to test)'
        if short == 'userActionRequired':
            for link in parse_links(hdrs.get('link')):
                if link[1] in ('terms-of-service', 'help'):
                    words += ': %s' % link[0]
        err = PluginError('%s%s' % (words, (': ' + detail) if detail else ''),
                          detail='%s -> HTTP %s %s' % (what, status, json.dumps(prob)[:2000]
                                                      if isinstance(prob, dict) else prob),
                          retry=retry)
        err.acme_type = short
        err.status = status
        raise err

    def post(self, url, payload, use_jwk=False, key=None, accept='application/json'):
        """A JWS POST (POST-as-GET when payload is None) -> (status, headers, body).
        badNonce is tried again (up to five times), rateLimited once when the
        CA asks for a short wait."""
        key = key or self.key
        limited = False
        for attempt in range(6):
            if not self.nonce:
                self.new_nonce()
            nonce, self.nonce = self.nonce, None
            jws = key.jws(url, payload, nonce, kid=None if (use_jwk or key is not self.key)
                          else self.kid)
            status, hdrs, data = self.http('POST', url, json.dumps(jws).encode('utf-8'),
                                           accept=accept)
            if status < 400:
                return status, hdrs, data
            short = ''
            try:
                short = str(json.loads(data.decode('utf-8')).get('type') or '').rsplit(':', 1)[-1]
            except (ValueError, UnicodeDecodeError, AttributeError):
                pass
            if short == 'badNonce' and attempt < 5:
                self.ctx.debug('ACME: badNonce, asked again')
                continue
            if short == 'rateLimited' and not limited:
                wait = http_date(hdrs.get('retry-after'))
                if wait is not None and wait <= 60:
                    limited = True
                    self.say('the CA asks to wait %d s (rate limit)' % wait, 'warn')
                    self.sleep(max(1.0, wait))
                    continue
            if (status >= 500 or status == 503) and attempt < 2:
                wait = http_date(hdrs.get('retry-after')) or 3
                self.sleep(min(wait, 30))
                continue
            self._raise(status, hdrs, data, 'POST ' + url)
        raise PluginError('the CA kept refusing the request')

    def post_json(self, url, payload, **kw):
        status, hdrs, data = self.post(url, payload, **kw)
        if not data:
            return {}, hdrs
        try:
            return json.loads(data.decode('utf-8')), hdrs
        except ValueError:
            raise PluginError('the CA answered something that is not JSON',
                              detail=data[:300].decode('utf-8', 'replace'))

    # -- the account -----------------------------------------------------------------
    def use_key(self, pem_text):
        self.key = AcmeKey(self, pem_text)
        return self.key

    def new_key(self, kind):
        if kind.startswith('ec-'):
            curve = 'P-256' if kind == 'ec-256' else 'P-384'
            args = ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:' + curve,
                    '-pkeyopt', 'ec_param_enc:named_curve']
        elif kind.startswith('rsa-'):
            args = ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:' + kind[4:]]
        else:
            raise PluginError('an account key type ACME does not use: %s' % kind, retry=False)
        return self.run(args).decode('ascii')

    def register(self, contacts=(), eab=None, only_existing=False):
        """newAccount -> (account URL, account object). `eab` (kid, hmac)."""
        url = self.directory()['newAccount']
        payload = {'termsOfServiceAgreed': True}
        if contacts:
            payload['contact'] = ['mailto:' + c if not c.startswith('mailto:') else c
                                  for c in contacts]
        if only_existing:
            payload = {'onlyReturnExisting': True}
        elif eab and eab[0]:
            payload['externalAccountBinding'] = eab_jws(self.key.jwk, eab[0], eab[1], url)
        elif self.meta.get('externalAccountRequired'):
            raise PluginError(PROBLEM_WORDS['externalAccountRequired'], retry=False)
        _status, hdrs, data = self.post(url, payload, use_jwk=True)
        self.kid = hdrs.get('location')
        if not self.kid:
            raise PluginError('the CA made no account (no Location in its answer)')
        try:
            acct = json.loads(data.decode('utf-8')) if data else {}
        except ValueError:
            acct = {}
        if acct.get('status') and acct['status'] != 'valid':
            raise PluginError('the ACME account is %s at the CA - a new one is made at the next '
                              'try' % acct['status'], retry=True)
        return self.kid, acct

    def update_contacts(self, contacts):
        payload = {'contact': ['mailto:' + c for c in contacts]}
        got, _ = self.post_json(self.kid, payload)
        return got

    # -- an order --------------------------------------------------------------------
    def new_order(self, names, profile=None, replaces=None, not_after=None):
        ask = {'identifiers': identifiers(names)}
        if profile:
            ask['profile'] = profile
        if replaces:
            ask['replaces'] = replaces
        got, hdrs = self.post_json(self.directory()['newOrder'], ask)
        url = hdrs.get('location')
        if not url:
            raise PluginError('the CA made no order (no Location in its answer)')
        return url, got

    def poll(self, url, done, what, timeout, interval=2.0, cancelled=None):
        """POST-as-GET `url` until its status is one of `done`; 'invalid' raises."""
        end = time.time() + timeout
        while True:
            got, hdrs = self.post_json(url, None)
            st = got.get('status')
            if st in done:
                return got
            if st in ('invalid', 'revoked', 'deactivated', 'expired'):
                errs = []
                for c in got.get('challenges') or []:
                    if c.get('error'):
                        w, _s, d = problem_words(c['error'])
                        errs.append('%s (%s)' % (w, d) if d else w)
                if got.get('error'):
                    w, _s, d = problem_words(got['error'])
                    errs.append('%s (%s)' % (w, d) if d else w)
                raise PluginError('%s: %s' % (what, '; '.join(errs) or st),
                                  detail=json.dumps(got)[:2000])
            if cancelled and cancelled():
                raise PluginError('stopped', retry=False)
            if time.time() > end:
                raise PluginError('%s: the CA has not said in %d s (still %s)' % (what, timeout, st))
            wait = http_date(hdrs.get('retry-after'))
            wait = interval if wait is None else wait
            self.sleep(max(min(interval, 1.0), min(30.0, wait, max(0.0, end - time.time()))))

    def download_chain(self, url, preferred=None):
        """The certificate and its chain (PEM, nearest first), the one whose top
        is issued by (or is) `preferred` among the alternates when given."""
        status, hdrs, data = self.post(url, None, accept='application/pem-certificate-chain')
        first = data.decode('ascii', 'replace')
        if not preferred:
            return first, 'default'
        tried = [(first, url)]
        for link, rel in parse_links(hdrs.get('link')):
            if rel == 'alternate':
                try:
                    _s, _h, d2 = self.post(urllib.parse.urljoin(url, link), None,
                                           accept='application/pem-certificate-chain')
                    tried.append((d2.decode('ascii', 'replace'), link))
                except PluginError as e:
                    self.ctx.debug('ACME: alternate chain %s not fetched: %s' % (link, e))
        want = preferred.strip().lower()
        for text, where in tried:
            if chain_matches(text, want):
                return text, where
        self.say('no chain of the CA ends at "%s" - its default chain is used' % preferred, 'warn')
        return first, 'default'

    def renewal_info(self, cert_id):
        base = self.directory().get('renewalInfo')
        if not base or not cert_id:
            return None
        got, hdrs = self.get_json(base.rstrip('/') + '/' + cert_id)
        w = got.get('suggestedWindow') or {}
        start, end = rfc3339(w.get('start')), rfc3339(w.get('end'))
        if not start or not end or end < start:
            return None
        return {'start': start, 'end': end, 'explanation': got.get('explanationURL') or '',
                'retry_after': http_date(hdrs.get('retry-after'))}

    def revoke(self, cert_pem, reason=0, cert_key_pem=None):
        payload = {'certificate': b64u(der.cert_der(cert_pem)), 'reason': int(reason)}
        url = self.directory()['revokeCert']
        if cert_key_pem:
            ck = AcmeKey(self, cert_key_pem)
            self.post(url, payload, key=ck, use_jwk=True)
        else:
            self.post(url, payload)


def parse_links(value):
    """[(target, rel)] of Link headers (several may come joined by ', ')."""
    out = []
    if not value:
        return out
    if isinstance(value, (list, tuple)):
        value = ', '.join(value)
    for m in re.finditer(r'<([^>]*)>\s*((?:;\s*[^,;]+)*)', str(value)):
        rel = re.search(r'rel\s*=\s*"?([^";,]+)"?', m.group(2) or '')
        out.append((m.group(1), rel.group(1).strip() if rel else ''))
    return out


def chain_matches(text, want):
    """Does this chain end at, or come from, the CA named `want` (lower case)?"""
    pems = der.split_pem_chain(text)
    if not pems:
        return False
    try:
        certs = [der.Cert(p) for p in pems]
    except (der.DerError, ValueError, IndexError):
        return False
    top = certs[-1]
    names = {(top.issuer_cn or '').lower()} | {(c.subject_cn or '').lower() for c in certs[1:]}
    return want in names
