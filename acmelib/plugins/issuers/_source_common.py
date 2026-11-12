# -*- coding: utf-8 -*-
"""
What the certificate sources of docs/sources.md share (EST, CMP, Vault PKI,
EJBCA, step-ca, AWS Private CA, Google CAS, FreeIPA, GlobalSign Atlas,
DigiCert CertCentral): HTTP through ctx.http with the answer read as JSON,
certificates read out of whatever shape a CA hands them in (PEM, base64 DER,
PKCS#7, JSON), the certificate matched to the request's key and its chain put
in order, a request a CA holds kept in the module's state (with its key
sealed) for the next try, files for the openssl program, and JWTs signed by it.

Not a module itself (its name starts with "_": the registry skips it).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
import time

from acmelib.plugins.base import Issued, PluginError
from acmelib.plugins.issuers import _scep_pkcs7 as p7

# RFC 5280 CRLReason, by the names acme uses (renewer.revoke_cert) and others.
REASONS = {'unspecified': 0, 'keycompromise': 1, 'cacompromise': 2, 'affiliationchanged': 3,
           'superseded': 4, 'cessationofoperation': 5, 'certificatehold': 6,
           'removefromcrl': 8, 'privilegewithdrawn': 9, 'aacompromise': 10}
REASON_NAMES = {v: k for k, v in REASONS.items()}


def reason_code(reason):
    """The RFC 5280 code of a reason given as a name (keyCompromise,
    key_compromise, KEY_COMPROMISE) or a number; 0 when unknown."""
    if isinstance(reason, int):
        return reason if reason in REASON_NAMES else 0
    r = re.sub(r'[^a-z0-9]', '', str(reason or '').lower())
    if r.isdigit():
        return int(r) if int(r) in REASON_NAMES else 0
    return REASONS.get(r, 0)


def as_bool(v, default=False):
    if v in (None, ''):
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() not in ('0', 'false', 'no', 'off')


def num(v, default=0.0):
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def say(ctx, words, level='info'):
    try:
        ctx.step(words, level)
    except Exception:                               # noqa: BLE001
        pass


def lines(v):
    """A 'list' field as its values."""
    if isinstance(v, str):
        v = v.splitlines()
    return [str(x).strip() for x in (v or []) if str(x).strip()]


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def http(ctx, method, url, body=None, headers=None, who='the CA', verify=True, ca_pem=None,
         client_cert=None, timeout=60):
    """(status, {lower-case header: value}, bytes) through ctx.http (the proxy of
    Settings → Proxy). A dict or list body goes as JSON."""
    h = {'Accept': 'application/json'}
    h.update(headers or {})
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode('utf-8')
        if not any(k.lower() == 'content-type' for k in h):
            h['Content-Type'] = 'application/json'
    elif isinstance(body, str):
        body = body.encode('utf-8')
    kw = {}
    if ca_pem:
        kw['ca_pem'] = ca_pem
    if client_cert:
        kw['client_cert'] = client_cert
    try:
        status, rh, data = ctx.http(method, url, body, h, timeout, verify, **kw)
    except PluginError:
        raise
    except Exception as e:                          # noqa: BLE001
        raise PluginError('%s does not answer: %s' % (who, e))
    return status, {str(k).lower(): v for k, v in (rh or {}).items()}, data or b''


def parse_json(data):
    if not data:
        return None
    try:
        return json.loads(data.decode('utf-8') if isinstance(data, bytes) else data)
    except (ValueError, UnicodeDecodeError):
        return None


def said_of(parsed, data=b''):
    """What an error answer says, in a line."""
    out = []

    def walk(o, depth=0):
        if depth > 4 or len(out) > 6:
            return
        if isinstance(o, dict):
            for k in ('message', 'error_message', 'errors', 'error', 'detail', 'details',
                      'description', 'error_description', 'title', 'warnings'):
                if k in o:
                    walk(o[k], depth + 1)
        elif isinstance(o, list):
            for x in o:
                walk(x, depth + 1)
        elif o not in (None, '', True, False):
            s = str(o).strip()
            if s and s not in out:
                out.append(s)
    walk(parsed)
    if out:
        return '; '.join(out)[:400]
    if isinstance(data, bytes):
        data = data.decode('utf-8', 'replace')
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', str(data or '')))[:300].strip()


def refusal(who, status, parsed, data, hint=''):
    said = said_of(parsed, data) or 'nothing more'
    words = '%s answered %s: %s' % (who, status, said)
    if status in (401, 403):
        words += ' - %s' % (hint or 'the credentials are wrong or may not do this')
    elif hint and status in (400, 404, 409, 422):
        words += ' - %s' % hint
    return PluginError(words, detail=(data.decode('utf-8', 'replace') if isinstance(data, bytes)
                                      else str(data or ''))[:3000],
                       retry=status >= 500 or status in (408, 429))


def retry_after(headers, default=10.0):
    v = str((headers or {}).get('retry-after') or '').strip()
    try:
        return max(1.0, float(v))
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Certificates in whatever shape
# ---------------------------------------------------------------------------
def certs_of(data):
    """Every certificate (DER) in `data`: PEM (one or many, PKCS7 blocks too),
    DER, base64 of DER, a PKCS#7 certs-only (DER, PEM or base64), a list of any
    of these, or FreeIPA's {'__base64__': ...}. [] when there is none."""
    if data is None:
        return []
    if isinstance(data, dict):
        if '__base64__' in data:
            return certs_of(base64.b64decode(data['__base64__']))
        return []
    if isinstance(data, (list, tuple)):
        out = []
        for x in data:
            for c in certs_of(x):
                if c not in out:
                    out.append(c)
        return out
    if isinstance(data, str):
        data = data.encode('ascii', 'replace')
    data = bytes(data)
    if b'-----BEGIN' in data:
        out = []
        for kind, der in p7.pem_blocks(data):
            if kind in ('CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'):
                out.append(der)
            elif kind in ('PKCS7', 'CMS'):
                out += [c for c in _p7(der)]
        return out
    if data[:1] == b'\x30':
        got = _p7(data)
        if got:
            return got
        try:
            p7.Cert(data)
            return [data]
        except (p7.DerError, ValueError, IndexError):
            return []
    txt = re.sub(rb'\s+', b'', data)
    if txt and re.match(rb'^[A-Za-z0-9+/=_-]+$', txt):
        try:
            raw = base64.b64decode(txt.replace(b'-', b'+').replace(b'_', b'/') +
                                   b'=' * (-len(txt) % 4))
        except ValueError:
            return []
        if raw[:1] == b'\x30':
            return certs_of(raw)
        if raw[:3] == b'MII' or b'-----BEGIN' in raw:        # base64 of base64 (EJBCA)
            return certs_of(raw)
    return []


def _p7(der):
    try:
        return p7.certs_from_pkcs7(der)
    except (p7.DerError, ValueError, IndexError):
        return []


def csr_der(req):
    if getattr(req, 'csr_der', None):
        return bytes(req.csr_der)
    blocks = p7.pem_blocks(req.csr_pem or '', 'CERTIFICATE REQUEST') or \
        p7.pem_blocks(req.csr_pem or '', 'NEW CERTIFICATE REQUEST')
    if not blocks:
        raise PluginError('there is no request (CSR) to send', retry=False)
    return blocks[0][1]


def csr_pem(req):
    if req.csr_pem and 'BEGIN' in req.csr_pem:
        return req.csr_pem.strip() + '\n'
    return p7.pem(csr_der(req), 'CERTIFICATE REQUEST')


def cert_of_pem(cert_pem):
    return p7.Cert(cert_pem)


def serial_hex(cert_pem, sep=''):
    """The serial as hex (upper case), its bytes joined by `sep` (':' for Vault)."""
    s = '%X' % p7.Cert(cert_pem).serial
    if len(s) % 2:
        s = '0' + s
    return sep.join(s[i:i + 2] for i in range(0, len(s), 2)) if sep else s


def fingerprint(cert_pem):
    return hashlib.sha256(p7.cert_der(cert_pem)).hexdigest()


def finish(ctx, req, certs, chain=(), info=None, key_pem=None, who='the CA'):
    """The Issued of what came: the certificate for the request's key (the
    CSR's), its chain above it in order. Raises when none is for that key."""
    certs = [c for c in certs or [] if c]
    chain = [c for c in chain or [] if c and c not in certs]
    if not certs:
        raise PluginError('%s sent no certificate' % who)
    want = None
    try:
        want = p7.csr_spki(csr_der(req)) if (req.csr_der or req.csr_pem) else None
    except (p7.DerError, ValueError, IndexError, PluginError):
        want = None
    parsed = [p7.Cert(c) for c in certs]
    leaf = None
    if want is not None:
        leaf = next((c for c in parsed if c.spki_der == want), None)
        if leaf is None:
            raise PluginError('%s sent a certificate for another key than this request\'s - it is '
                              'not used' % who, retry=False)
    if leaf is None:
        leaf = next((c for c in parsed if not c.is_ca), parsed[0])
    others = []
    for c in [c.der for c in parsed if c.der != leaf.der] + chain:
        if c not in others and c != leaf.der:
            others.append(c)
    ordered = p7.order_chain(leaf.der, others)
    say(ctx, 'the certificate came: serial %X, until %s, from %s' % (
        leaf.serial, time.strftime('%Y-%m-%d', time.gmtime(leaf.not_after)),
        leaf.issuer_cn or '?'), 'ok')
    return Issued(p7.pem(leaf.der), [p7.pem(c) for c in ordered], key_pem=key_pem, info=info)


def existing(certs, chain=(), who='the CA', ref=None):
    """What fetch_existing() gives (Import from a source): the certificate among
    `certs` (DER, the newest one that is not an authority) and the chain above it in
    order - no key, no request to match."""
    certs = [c for c in certs or [] if c]
    if not certs:
        raise PluginError('%s sent no certificate' % who, retry=False)
    parsed = [p7.Cert(c) for c in certs]
    leafs = [c for c in parsed if not c.is_ca]
    if not leafs:
        raise PluginError('%s sent only certificates of authorities' % who, retry=False)
    leaf = max(leafs, key=lambda c: c.not_before or 0)
    others = []
    for c in [c.der for c in parsed if c.der != leaf.der] + [c for c in chain or [] if c]:
        if c not in others and c != leaf.der:
            others.append(c)
    out = {'cert_pem': p7.pem(leaf.der),
           'chain_pems': [p7.pem(c) for c in p7.order_chain(leaf.der, others)]}
    if ref is not None:
        out['ref'] = str(ref)
    return out


# ---------------------------------------------------------------------------
# A request the CA holds: kept for the next try, its key sealed with it
# ---------------------------------------------------------------------------
def pending_slot(kind, where, req):
    """'<kind>-pending:<hash of the CA>:<the certificate>' (at most 120 characters)."""
    who = str(req.cert_id) if getattr(req, 'cert_id', None) else \
        hashlib.sha256(','.join(sorted(req.names or [])).encode()).hexdigest()[:24]
    # ...and its key type (1.0.51): the twin's request held, the main one went on with the
    # twin's CSR and key - an RSA certificate kept as the EC one
    kt = str(getattr(req, 'key_type', '') or '')
    if kt:
        who += ':' + kt
    return ('%s-pending:%s:%s' % (kind, hashlib.sha256(str(where).encode()).hexdigest()[:12],
                                  who))[:120]


def _drop_held(ctx, slot, req, v, issuer):
    """A request held no longer used: its DCV records taken away first (1.0.96: the TXT and
    CNAME records it put in DNS stayed there for good)."""
    if issuer is not None and v.get('dcv'):
        try:
            from acmelib.plugins.issuers import _dcv
            _dcv.Placer(issuer).cleanup(req, v.get('dcv') or [])
        except Exception as e:                          # noqa: BLE001
            say(ctx, 'the DCV records of the request left behind could not be taken away: %s'
                % e, 'warn')
    ctx.kv_set(slot, None)


def pending_get(ctx, slot, req, issuer=None):
    """What is held for this certificate - None when nothing, or when it was for
    other names (then it is dropped, its DCV records taken away when `issuer` is given). The
    key held comes back as 'key_pem'."""
    v = ctx.kv_get(slot)
    if isinstance(v, str):
        v = parse_json(v)
    if not isinstance(v, dict):
        return None
    if sorted(v.get('names') or []) != sorted(req.names or []):
        say(ctx, 'the request waiting at the CA (%s) was for other names - left alone, a new '
                 'one is made' % (v.get('id') or '?'), 'warn')
        _drop_held(ctx, slot, req, v, issuer)
        return None
    if v.get('key'):
        from acmelib.plugins.issuers.acme import _unseal
        v['key_pem'] = _unseal(ctx, v['key'], slot)
        if not v['key_pem']:
            _drop_held(ctx, slot, req, v, issuer)
            return None
    return v


def pending_put(ctx, slot, req, value, ttl_days=90):
    """Keeps `value` (JSON-able; with the request's key, sealed) for the next try."""
    from acmelib.plugins.issuers.acme import _seal
    v = {k: x for k, x in dict(value).items() if k != 'key_pem'}
    v.setdefault('at', time.time())
    v['names'] = list(req.names or [])
    if req.key_pem and 'key' not in v:
        v['key'] = _seal(ctx, req.key_pem, slot)
    ctx.kv_set(slot, json.dumps(v), ttl_s=int(ttl_days * 86400))
    return v


def pending_drop(ctx, slot):
    ctx.kv_set(slot, None)


def held_request(req, held):
    """The request as it was when it was held (its key and CSR), for finish()."""
    if not held:
        return req
    from acmelib.plugins.base import CertRequest
    r = CertRequest(**dict(req.__dict__))
    if held.get('key_pem'):
        r.key_pem = held['key_pem']
    if held.get('csr_pem'):
        r.csr_pem = held['csr_pem']
        r.csr_der = p7.pem_blocks(held['csr_pem'], 'CERTIFICATE REQUEST')[0][1]
    return r


# ---------------------------------------------------------------------------
# Files for the openssl program, and what it signs
# ---------------------------------------------------------------------------
class Work(object):
    """A directory of its own (0700) for files openssl reads, gone afterwards."""
    def __init__(self, prefix='acme-src-'):
        self.dir = tempfile.mkdtemp(prefix=prefix)
        os.chmod(self.dir, 0o700)

    def file(self, name, data):
        p = os.path.join(self.dir, name)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data.encode('utf-8') if isinstance(data, str) else bytes(data))
        return p

    def path(self, name):
        return os.path.join(self.dir, name)

    def read(self, name):
        p = os.path.join(self.dir, name)
        if not os.path.exists(p):
            return b''
        with open(p, 'rb') as f:
            return f.read()

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def run_openssl(ctx, args, data=None, timeout=60):
    try:
        out = ctx.openssl([str(a) for a in args], data, timeout)
    except TypeError:
        out = ctx.openssl([str(a) for a in args], data)
    except PluginError:
        raise
    except Exception as e:                          # noqa: BLE001
        raise PluginError('openssl %s failed: %s' % (args[0] if args else '', e))
    return out if isinstance(out, bytes) else str(out or '').encode()


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def b64u_dec(text):
    text = str(text or '')
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def key_alg(ctx, key_pem):
    """('ES256' | 'ES384' | 'ES512' | 'RS256', bytes of r or s) of a private key."""
    with Work('acme-key-') as w:
        kf = w.file('k.pem', key_pem.strip() + '\n')
        try:
            text = run_openssl(ctx, ['pkey', '-in', kf, '-noout', '-text_pub']).decode('utf-8', 'replace')
        except PluginError:
            raise PluginError('the private key cannot be read (a PEM key without a passphrase?)',
                              retry=False)
    if re.search(r'prime256v1|P-256\b', text):
        return 'ES256', 32
    if re.search(r'secp384r1|P-384\b', text):
        return 'ES384', 48
    if re.search(r'secp521r1|P-521\b', text):
        return 'ES512', 66
    if 'RSA' in text or 'Modulus' in text:
        return 'RS256', 0
    raise PluginError('a key of a kind that cannot sign the token (EC P-256/384/521 or RSA)',
                      retry=False)


def jwt(ctx, key_pem, claims, header=None):
    """A compact JWS of `claims` signed with the key by openssl (ES*/RS256)."""
    alg, size = key_alg(ctx, key_pem)
    head = {'alg': alg, 'typ': 'JWT'}
    head.update(header or {})
    signing = (b64u(json.dumps(head, separators=(',', ':')).encode()) + '.' +
               b64u(json.dumps(claims, separators=(',', ':')).encode()))
    digest = {'ES256': '-sha256', 'ES384': '-sha384', 'ES512': '-sha512', 'RS256': '-sha256'}[alg]
    with Work('acme-jwt-') as w:
        kf = w.file('k.pem', key_pem.strip() + '\n')
        sig = run_openssl(ctx, ['dgst', digest, '-sign', kf], signing.encode())
    if not sig:
        raise PluginError('openssl did not sign the token')
    if size:
        from acmelib.plugins.issuers._acme_client import ecdsa_der_to_raw
        sig = ecdsa_der_to_raw(sig, size)
    return signing + '.' + b64u(sig)


CURVES = {'P-256': ('1.2.840.10045.3.1.7', 32), 'P-384': ('1.3.132.0.34', 48),
          'P-521': ('1.3.132.0.35', 66)}


def jwk_to_pem(jwk):
    """A private JWK (EC or RSA, as `step crypto jwe decrypt` gives it) as PEM."""
    if isinstance(jwk, str):
        jwk = parse_json(jwk)
    if not isinstance(jwk, dict) or not jwk.get('d'):
        raise PluginError('the key is not a private JWK (no "d")', retry=False)
    kty = jwk.get('kty')
    if kty == 'EC':
        crv = CURVES.get(jwk.get('crv'))
        if not crv:
            raise PluginError('a JWK of a curve that is not P-256/384/521', retry=False)
        oid, size = crv
        d = b64u_dec(jwk['d']).rjust(size, b'\x00')
        pub = b'\x04' + b64u_dec(jwk['x']).rjust(size, b'\x00') + b64u_dec(jwk['y']).rjust(size, b'\x00')
        der = p7.seq(p7.der_int(1), p7.der_octets(d), p7.ctx_tag(0, p7.der_oid(oid)),
                     p7.ctx_tag(1, p7.tlv(0x03, b'\x00' + pub)))
        return p7.pem(der, 'EC PRIVATE KEY')
    if kty == 'RSA':
        ints = [0] + [int.from_bytes(b64u_dec(jwk[k]), 'big')
                      for k in ('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi')]
        return p7.pem(p7.seq(*[p7.der_int(i) for i in ints]), 'RSA PRIVATE KEY')
    raise PluginError('a JWK of kind %s cannot be used (EC or RSA)' % kty, retry=False)


def dn_rfc2253(ctx, cert_pem, which='issuer'):
    """The certificate's issuer (or subject) as RFC 2253 text: CN=..,O=..,C=.."""
    with Work('acme-dn-') as w:
        cf = w.file('c.pem', cert_pem)
        out = run_openssl(ctx, ['x509', '-in', cf, '-noout', '-' + which, '-nameopt', 'RFC2253'])
    text = out.decode('utf-8', 'replace').strip()
    return re.sub(r'^(issuer|subject)\s*=\s*', '', text)


# -- discovery (1.0.29): what the sources' discover_setup() share -------------------------
def day(epoch):
    """An epoch as YYYY-MM-DD, or ''."""
    try:
        return time.strftime('%Y-%m-%d', time.gmtime(float(epoch))) if epoch else ''
    except (TypeError, ValueError, OverflowError):
        return ''


def reuse_choice(plugin, out, key, rows, empty, limit=300):
    """Offer the orders (list_existing() rows) a certificate can be reissued in as the
    choice `key` of discover_setup()'s answer - never picked by itself: the option ''
    (`empty`: what an empty field means) is picked. Returns how many were offered."""
    now = time.time()
    keep = []
    for r in rows or []:
        if not isinstance(r, dict) or not str(r.get('ref') or '').strip():
            continue
        if r.get('renewable') != 'reissue':
            continue
        end = r.get('paid_until') or r.get('not_after')
        if end and end < now:
            continue
        keep.append((end or 0, r))
    keep.sort(key=lambda x: x[0], reverse=True)
    opts, sets = [], {}
    for end, r in keep[:limit]:
        bits = [str(r.get('cn') or (r.get('names') or ['?'])[0] or '?')]
        if r.get('product'):
            bits.append(str(r['product']))
        if end:
            bits.append(day(end))
        ref = str(r['ref']).strip()
        opts.append([ref, ' · '.join(bits)])
        if isinstance(r.get('sets'), dict) and r['sets']:
            sets[ref] = dict(r['sets'])     # what picking it sets too (its product)
    if opts:
        plugin.offer(out, key, [['', empty]] + opts, sets, pick='')
    return len(opts)


def _shown(plugin, key):
    """Whether the field `key` is shown by the settings now (its show_if)."""
    f = next((x for x in plugin.fields or [] if x.get('key') == key), None) or {}
    for k, vals in (f.get('show_if') or {}).items():
        if str(plugin.c(k)) not in [str(v) for v in vals]:
            return False
    return True


def discover_lists(plugin):
    """Plugin.discover_setup() - each list of the form (a catalog field) whose fields it
    needs are set - where a field it needs that the settings hide (the other way of
    signing in, its show_if) is not needed."""
    out = {'sets': {}, 'choices': {}, 'facts': [], 'notes': []}
    for f in plugin.fields or []:
        if f.get('type') != 'catalog' or not f.get('key'):
            continue
        key = f['key']
        need = [d for d in f.get('depends') or [] if _shown(plugin, d) and
                plugin.c(d) in (None, '')]
        if need:
            labels = [str(next((x.get('label') for x in plugin.fields
                                if x.get('key') == d), d)) for d in need]
            out['notes'].append('%s: set %s first, then ask again' % (
                f.get('label') or key, ', '.join(labels)))
            continue
        try:
            got = plugin.catalog(f.get('catalog') or key) or {}
        except PluginError as e:
            out['notes'].append('%s: %s' % (f.get('label') or key, e))
            continue
        except NotImplementedError:
            continue
        plugin.offer(out, key, got.get('options') or [], got.get('sets') or {})
    return out


def merge_found(out, more):
    """discover_setup()'s answer `more` added to `out`: what out has already stays."""
    for k, v in ((more or {}).get('sets') or {}).items():
        out['sets'].setdefault(k, v)
    for k, v in ((more or {}).get('choices') or {}).items():
        out['choices'].setdefault(k, v)
    out['facts'] += [f for f in (more or {}).get('facts') or [] if f not in out['facts']]
    out['notes'] += [n for n in (more or {}).get('notes') or [] if n not in out['notes']]
    return out


class assumed(object):
    """with assumed(plugin, {key: value}): the values found used as settings while the
    module asks for more (a list that needs them) - only where the field is empty, the
    settings as they were afterwards (discovery saves nothing)."""
    def __init__(self, plugin, values):
        self.plugin, self.values, self.saved = plugin, dict(values or {}), None

    def __enter__(self):
        self.saved = dict(self.plugin.config)
        for k, v in self.values.items():
            if v not in (None, '') and self.plugin.config.get(k) in (None, ''):
                self.plugin.config[k] = v
        return self.plugin

    def __exit__(self, *_exc):
        self.plugin.config.clear()
        self.plugin.config.update(self.saved)
        return False
