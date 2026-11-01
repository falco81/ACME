# -*- coding: utf-8 -*-
"""
Certificates from an ACME CA (RFC 8555): Let's Encrypt first, its staging,
ZeroSSL, Google Trust Services, Buypass, SSL.com, or one of your own
(step-ca, Smallstep, an internal CA with ACME, pebble). Each name is proved by
the challenge module chosen for it (DNS-01 or HTTP-01); the renewal window is
the CA's own where it has ARI (RFC 9773). See docs/acme-issuers.md.
"""
from __future__ import annotations

import hashlib
import json
import re
import time

from acmelib.plugins.base import Issuer, Issued, PluginError, field
from acmelib.plugins.issuers import _acme_client as ac
from acmelib.plugins.issuers import _scep_pkcs7 as der


def _engine():
    try:
        from acmelib import engine as E
        return E if callable(getattr(E, 'seal_secret', None)) else None
    except Exception:                               # noqa: BLE001
        return None


def _seal(ctx, text, bind):
    """The account key sealed: by the Context where it offers it, else by the
    engine's sealing key (bound to the slot), else - outside the daemon - as it is."""
    fn = getattr(ctx, 'seal', None)
    if callable(fn):
        return fn(text, bind)
    E = _engine()
    if E:
        try:
            return E.seal_secret(text, 'certs:' + bind)
        except Exception:                           # noqa: BLE001
            pass
    return text


def _unseal(ctx, value, bind):
    fn = getattr(ctx, 'unseal', None)
    if callable(fn):
        return fn(value, bind)
    E = _engine()
    if E and isinstance(value, str) and not value.startswith('-----'):
        try:
            return E.unseal_secret(value, 'certs:' + bind)
        except Exception:                           # noqa: BLE001
            return None
    return value


class AcmeIssuer(Issuer):
    kind = 'acme'
    title = "ACME (Let's Encrypt and others)"
    description = ("Certificates from Let's Encrypt or any other ACME CA (ZeroSSL, Google "
                   "Trust Services, Buypass, SSL.com, step-ca), each name proved by DNS-01 "
                   "or HTTP-01, renewed in the CA's own window (ARI).")
    vendor = 'Public CA'
    doc = 'docs/acme-issuers.md'
    needs_challenge = True
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = True
    fields = [
        field('directory', 'CA', 'select', required=True, default='letsencrypt',
              options=[['letsencrypt', "Let's Encrypt"],
                       ['letsencrypt-staging', "Let's Encrypt staging (for tests, not trusted)"],
                       ['zerossl', 'ZeroSSL (EAB)'],
                       ['google', 'Google Trust Services (EAB)'],
                       ['google-staging', 'Google Trust Services staging (EAB)'],
                       ['buypass', 'Buypass Go SSL'],
                       ['sslcom-rsa', 'SSL.com RSA (EAB)'],
                       ['sslcom-ecc', 'SSL.com ECC (EAB)'],
                       ['custom', 'Another ACME server (its directory URL)']]),
        field('directory_url', 'Directory URL', 'text', placeholder='https://ca.example.local/acme/acme/directory',
              show_if={'directory': ['custom']},
              help='The ACME directory of your server (step-ca: https://HOST/acme/PROVISIONER/directory).'),
        field('contacts', 'Contact e-mails', 'list', placeholder='pki@example.com',
              help='Told to the CA with the account (expiry and policy mails). ZeroSSL needs one '
                   'to make the EAB itself.'),
        field('eab_kid', 'EAB key id', 'text', advanced=False,
              help='External Account Binding: the key id from the CA (ZeroSSL, Google, SSL.com, '
                   'Sectigo, step-ca with EAB). Empty for Let\'s Encrypt.'),
        field('eab_hmac', 'EAB HMAC key', 'secret',
              help='The HMAC key that comes with the key id (base64url, as the CA shows it).'),
        field('account_key', 'Account key', 'select', default='ec-256',
              options=[['ec-256', 'ECDSA P-256 (ES256)'], ['ec-384', 'ECDSA P-384 (ES384)'],
                       ['rsa-2048', 'RSA 2048'], ['rsa-3072', 'RSA 3072'], ['rsa-4096', 'RSA 4096']],
              advanced=True,
              help='Another kind makes a new account at the CA (renewals are not counted as '
                   'renewals of certificates the old account ordered).'),
        field('profile', 'ACME profile', 'text', placeholder='classic | tlsserver | shortlived',
              advanced=True,
              help="The CA's certificate profile (Let's Encrypt: classic, tlsserver, shortlived - "
                   "6-day certificates, IP addresses). A certificate's own profile wins."),
        field('preferred_chain', 'Preferred chain', 'text', placeholder='ISRG Root X1',
              advanced=True,
              help='The common name of the root (or intermediate) the chain should end at, where '
                   'the CA offers several.'),
        field('ca_pem', 'CA certificate of the ACME server', 'pem', advanced=True,
              help='For an ACME server of your own whose TLS certificate is from a private CA.'),
        field('verify', 'Check the server\'s TLS certificate', 'bool', default=True, advanced=True),
        field('wait_ready', 'Wait for the proof to be visible (s)', 'number', default=300,
              advanced=True, help='How long DNS records are waited for (propagation).'),
        field('wait_valid', 'Wait for the CA to check (s)', 'number', default=180, advanced=True),
        field('wait_order', 'Wait for the certificate (s)', 'number', default=300, advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=5, advanced=True),
    ]

    # -- settings --------------------------------------------------------------------
    def directory_url(self):
        d = self.c('directory') or 'letsencrypt'
        if d == 'custom':
            url = str(self.c('directory_url') or '').strip()
            if not url:
                raise PluginError('set the directory URL of your ACME server', retry=False)
            return url
        if d not in ac.DIRECTORIES:
            raise PluginError('an unknown CA: %s' % d, retry=False)
        return ac.DIRECTORIES[d]

    def contacts(self):
        v = self.c('contacts') or []
        if isinstance(v, str):
            v = re.split(r'[\s,;]+', v)
        out = []
        for c in v:
            c = str(c).strip()
            if c.startswith('mailto:'):
                c = c[7:]
            if c:
                if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+\Z', c):
                    raise PluginError('%s is not an e-mail address' % c, retry=False)
                out.append(c)
        return out

    def _num(self, key, default):
        try:
            return float(self.c(key) or default)
        except (TypeError, ValueError):
            return float(default)

    def account_slot(self, url):
        h = hashlib.sha256(json.dumps([url, str(self.c('eab_kid') or ''),
                                       str(self.c('account_key') or 'ec-256')]).encode()).hexdigest()[:16]
        slot = 'acme-account:%s:%s' % (url, h)
        if len(slot) > 110:          # the Context keeps keys of 120 characters
            slot = 'acme-account:%s:%s' % (hashlib.sha256(url.encode()).hexdigest()[:24], h)
        return slot

    def _say(self, words, level='info'):
        try:
            self.ctx.step(words, level)
        except Exception:                           # noqa: BLE001
            pass

    def client(self):
        verify = self.c('verify')
        verify = True if verify in (None, '') else bool(verify) and str(verify).lower() not in ('0', 'false', 'no')
        return ac.AcmeClient(self.ctx, self.directory_url(), verify=verify,
                             ca_pem=(self.c('ca_pem') or None), say=self._say)

    # -- the account -----------------------------------------------------------------
    def account(self, cl, fresh=False):
        """The account, found in the module's state or made at the CA."""
        url = cl.dir_url
        slot = self.account_slot(url)
        kind = str(self.c('account_key') or 'ec-256')
        if kind not in ac.ACCOUNT_KEYS:
            kind = 'ec-256'
        row = None if fresh else self.ctx.kv_get(slot)
        if isinstance(row, (str, bytes)):
            try:
                row = json.loads(row)
            except ValueError:
                row = None
        pem_text = None
        if isinstance(row, dict) and row.get('key') and row.get('url'):
            pem_text = _unseal(self.ctx, row['key'], slot)
        if pem_text:
            cl.use_key(pem_text)
            cl.kid = row['url']
            want = self.contacts()
            if sorted(row.get('contacts') or []) != sorted(want) and want:
                try:
                    cl.update_contacts(want)
                    row['contacts'] = want
                    self.ctx.kv_set(slot, json.dumps(row))
                    self._say('the account\'s contacts are now %s' % ', '.join(want))
                except PluginError as e:
                    if self._account_gone(e):
                        return self.account(cl, fresh=True)
                    self._say('the account\'s contacts could not be changed: %s' % e, 'warn')
            return row
        cl.directory()
        self._say('a new ACME account at %s (%s key)' % (url, kind))
        pem_text = cl.new_key(kind)
        cl.use_key(pem_text)
        eab = self.eab(cl)
        kid, acct = cl.register(self.contacts(), eab=eab)
        row = {'url': kid, 'key': _seal(self.ctx, pem_text, slot), 'kind': kind,
               'contacts': self.contacts(), 'at': time.time(), 'directory': url,
               'eab_kid': (eab or ('',))[0]}
        self.ctx.kv_set(slot, json.dumps(row))
        self._say('the account is %s' % kid, 'ok')
        return row

    def eab(self, cl):
        kid = str(self.c('eab_kid') or '').strip()
        mac = str(self.c('eab_hmac') or '').strip()
        if kid and mac:
            return kid, mac
        if kid or mac:
            raise PluginError('set both the EAB key id and its HMAC key', retry=False)
        if (self.c('directory') == 'zerossl') and cl.meta.get('externalAccountRequired'):
            # ZeroSSL hands out EAB credentials for an e-mail address.
            mails = self.contacts()
            if not mails:
                raise PluginError('ZeroSSL needs a contact e-mail (or EAB credentials from its '
                                  'dashboard) to make an account', retry=False)
            self._say('ZeroSSL: EAB credentials asked for %s' % mails[0])
            body = ('email=' + mails[0]).encode()
            status, _h, data = self.ctx.http('POST', 'https://api.zerossl.com/acme/eab-credentials-email',
                                             body, {'Content-Type': 'application/x-www-form-urlencoded'},
                                             30, True, None)
            try:
                got = json.loads(data.decode('utf-8'))
            except ValueError:
                got = {}
            if status >= 400 or not got.get('eab_kid'):
                raise PluginError('ZeroSSL gave no EAB credentials - make them in its dashboard '
                                  '(Developer → EAB Credentials) and set them here',
                                  detail=data[:300].decode('utf-8', 'replace'))
            return got['eab_kid'], got['eab_hmac_key']
        return None

    @staticmethod
    def _account_gone(e):
        t = getattr(e, 'acme_type', '')
        low = str(e).lower()
        return t == 'accountDoesNotExist' or (t == 'unauthorized' and 'account' in low and any(
            w in low for w in ('deactivated', 'not valid', 'not found', 'does not exist', 'revoked')))

    def _with_account(self, cl, fn):
        """fn() with the account, once more with a new account if the CA forgot it."""
        self.account(cl)
        try:
            return fn()
        except PluginError as e:
            if not self._account_gone(e):
                raise
            self._say('the CA does not know the account any more - a new one is made', 'warn')
            self.account(cl, fresh=True)
            return fn()

    # -- trying it -------------------------------------------------------------------
    def test(self):
        with self.client() as cl:
            d = cl.directory()
            row = self.account(cl)
            meta = d.get('meta') or {}
            bits = ['the directory answers (%s)' % cl.dir_url, 'account %s' % row.get('url')]
            if meta.get('profiles'):
                bits.append('profiles: %s' % ', '.join(sorted(meta['profiles'])))
            if d.get('renewalInfo'):
                bits.append('ARI')
            if meta.get('termsOfService'):
                bits.append('terms: %s' % meta['termsOfService'])
            return '; '.join(bits)

    # -- an order --------------------------------------------------------------------
    def issue(self, req):
        if not req.names:
            raise PluginError('no names to order a certificate for', retry=False)
        if not req.csr_der:
            raise PluginError('there is no request (CSR) to finalize the order with', retry=False)
        with self.client() as cl:
            self._say('the CA: %s' % cl.dir_url)
            cl.directory()
            return self._with_account(cl, lambda: self._order(cl, req))

    def _profile(self, cl, req):
        prof = str((req.profile or {}).get('acme_profile') or self.c('profile') or '').strip()
        if not prof:
            return None
        offered = cl.meta.get('profiles') or {}
        if prof in offered:
            return prof
        self._say('this CA offers no profile "%s"%s - its default is used' % (
            prof, (' (it has %s)' % ', '.join(sorted(offered))) if offered else ''), 'warn')
        return None

    def _order(self, cl, req):
        names = list(req.names)
        profile = self._profile(cl, req)
        replaces = None
        if req.previous and cl.directory().get('renewalInfo'):
            replaces = ac.ari_id(req.previous) or None
        self._say('a new order for %s%s%s' % (', '.join(names),
                                               (' (profile %s)' % profile) if profile else '',
                                               ' replacing %s' % replaces if replaces else ''))
        try:
            order_url, order = cl.new_order(names, profile, replaces)
        except PluginError as e:
            # Only the account that ordered a certificate may say it replaces it
            # (engine 1.0.199): ordered again as a new one.
            if not replaces or 'replace' not in str(e).lower() + str(e.detail or '').lower():
                raise
            self._say('the CA does not take it as the renewal of the one before (another '
                      'account ordered that one) - ordered as a new certificate', 'warn')
            order_url, order = cl.new_order(names, profile, None)
        self.ctx.debug('ACME order %s: %s' % (order_url, json.dumps(order)[:500]))
        if order.get('status') == 'invalid':
            raise PluginError('the CA made the order invalid at once', detail=json.dumps(order))
        if order.get('status') == 'pending':
            self._authorize(cl, req, order)
        o = order
        if o.get('status') in ('pending', 'ready'):
            o = cl.poll(order_url, ('ready', 'processing', 'valid'), 'the order', self._num('wait_valid', 180),
                        self._num('poll_every', 5), self.ctx.cancelled)
        if o.get('status') == 'ready':
            self._say('the order is finalized with the request')
            o, _ = cl.post_json(o.get('finalize') or order['finalize'], {'csr': ac.b64u(req.csr_der)})
        if o.get('status') != 'valid':
            o = cl.poll(order_url, ('valid',), 'the certificate', self._num('wait_order', 300),
                        self._num('poll_every', 5), self.ctx.cancelled)
        if not o.get('certificate'):
            raise PluginError('the order is valid but has no certificate URL',
                              detail=json.dumps(o))
        pref = str(self.c('preferred_chain') or '').strip()
        text, where = cl.download_chain(o['certificate'], pref or None)
        pems = der.split_pem_chain(text)
        if not pems:
            raise PluginError('the CA sent no certificate', detail=text[:300])
        cert_pem, chain = pems[0], pems[1:]
        info = {'order_url': order_url, 'account_url': cl.kid, 'directory': cl.dir_url,
                'ari_id': ac.ari_id(cert_pem), 'chain': where}
        if profile:
            info['acme_profile'] = profile
        if replaces:
            info['replaces'] = replaces
        try:
            c = der.Cert(cert_pem)
            info['not_after'] = c.not_after
            self._say('the certificate came: serial %x, until %s, from %s' % (
                c.serial, time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(c.not_after)),
                c.issuer_cn or '?'), 'ok')
        except (der.DerError, ValueError, IndexError):
            self._say('the certificate came', 'ok')
        return Issued(cert_pem, chain, info=info)

    def _authorize(self, cl, req, order):
        thumb = cl.key.thumbprint()
        todo = []
        for az_url in order.get('authorizations') or []:
            az, _ = cl.post_json(az_url, None)
            if az.get('status') == 'valid':
                continue
            if az.get('status') != 'pending':
                raise PluginError('an authorization of the order is %s' % az.get('status'),
                                  detail=json.dumps(az)[:2000])
            ident = (az.get('identifier') or {})
            value = str(ident.get('value') or '')
            wild = bool(az.get('wildcard'))
            shown = ('*.' + value) if wild else value
            chal_mod = self._challenge_for(req, value, wild)
            offered = {c.get('type'): c for c in az.get('challenges') or []}
            kinds = [t for t in (getattr(chal_mod, 'types', ()) or ()) if t in self.challenge_types]
            pick = next((t for t in kinds if t in offered), None)
            if not pick:
                raise PluginError('the CA offers %s for %s, the challenge chosen for it does %s'
                                  % (', '.join(sorted(offered)) or 'nothing', shown,
                                     (', '.join(kinds) or 'nothing')
                                     + (' (wildcards need dns-01)' if wild else '')), retry=False)
            ch = offered[pick]
            token = str(ch.get('token') or '')
            if not re.match(r'^[A-Za-z0-9_-]{8,256}\Z', token):
                raise PluginError('the CA sent a token that is not one')
            keyauth = token + '.' + thumb
            txt = ac.b64u(hashlib.sha256(keyauth.encode('ascii')).digest())
            todo.append({'url': az_url, 'name': value, 'shown': shown, 'mod': chal_mod,
                         'type': pick, 'chal': ch, 'token': token, 'keyauth': keyauth,
                         'txt': txt, 'handle': None, 'presented': False})
        if not todo:
            self._say('every name is proved already (authorizations still valid)')
            return
        together = all(getattr(t['mod'], 'parallel', True) for t in todo)
        groups = [todo] if together else [[t] for t in todo]
        for g in groups:
            self._prove(cl, g)

    def _challenge_for(self, req, value, wild):
        chs = req.challenges or {}
        for k in (('*.' + value) if wild else value, value, value.lower()):
            if k in chs and chs[k] is not None:
                return chs[k]
        if len(chs) == 1:
            return list(chs.values())[0]
        raise PluginError('no challenge is chosen for %s' % (('*.' + value) if wild else value),
                          retry=False)

    def _prove(self, cl, group):
        try:
            for t in group:
                self._say('%s: %s put in place%s' % (
                    t['shown'], t['type'].upper(),
                    (' (TXT _acme-challenge.%s = %s)' % (t['name'], t['txt']))
                    if t['type'] == 'dns-01' else ' (/.well-known/acme-challenge/%s)' % t['token']))
                t['handle'] = t['mod'].present(t['name'], t['token'], t['keyauth'], t['txt'])
                t['presented'] = True
            self._wait_ready(group)
            for t in group:
                self._say('%s: the CA is asked to check' % t['shown'])
                cl.post_json(t['chal']['url'], {})
            for t in group:
                cl.poll(t['url'], ('valid',), 'the CA did not accept %s' % t['shown'],
                        self._num('wait_valid', 180), self._num('poll_every', 5), self.ctx.cancelled)
                self._say('%s: proved' % t['shown'], 'ok')
        finally:
            for t in group:
                if not t['presented']:
                    continue
                try:
                    t['mod'].cleanup(t['name'], t['handle'])
                except Exception as e:              # noqa: BLE001
                    self._say('%s: the proof was not taken away: %s' % (t['shown'], e), 'warn')

    def _wait_ready(self, group):
        end = time.time() + self._num('wait_ready', 300)
        every = self._num('poll_every', 5)
        left = list(group)
        said = False
        while left:
            if self.ctx.cancelled():
                raise PluginError('stopped', retry=False)
            still = []
            for t in left:
                try:
                    ok = t['mod'].ready(t['name'], t['handle'])
                except PluginError:
                    raise
                except Exception as e:              # noqa: BLE001
                    self.ctx.debug('ready(%s): %s' % (t['name'], e))
                    ok = False
                if not ok:
                    still.append(t)
            left = still
            if not left:
                return
            if time.time() > end:
                raise PluginError('the proof for %s is not visible after %d s - for DNS-01 check '
                                  'that the record is in the zone the world sees (the CNAME, the '
                                  'delegation), or wait longer (More → Wait for the proof)'
                                  % (', '.join(t['shown'] for t in left), self._num('wait_ready', 300)))
            if not said:
                self._say('waiting for %s to be visible' % ', '.join(t['shown'] for t in left))
                said = True
            time.sleep(every)

    # -- after -----------------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        code = ac.REVOKE_REASONS.get(str(reason), None)
        if code is None:
            try:
                code = int(reason)
            except (TypeError, ValueError):
                code = 0
        with self.client() as cl:
            cl.directory()
            try:
                self._with_account(cl, lambda: cl.revoke(cert_pem, code))
            except PluginError as e:
                if not key_pem or getattr(e, 'acme_type', '') == 'alreadyRevoked':
                    raise
                # Another account ordered it: the certificate's own key may revoke it.
                self._say('revoked with the certificate\'s own key (the account may not: %s)' % e, 'warn')
                cl.revoke(cert_pem, code, cert_key_pem=key_pem)
            self._say('the CA revoked the certificate (%s)' % reason, 'ok')
        return 'revoked'

    def renewal_window(self, cert_pem):
        cid = ac.ari_id(cert_pem)
        if not cid:
            return None
        try:
            with self.client() as cl:
                w = cl.renewal_info(cid)
        except PluginError as e:
            self.ctx.debug('ARI not asked: %s' % e)
            return None
        if not w:
            return None
        return (w['start'], w['end'])
