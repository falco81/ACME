# -*- coding: utf-8 -*-
"""
Certificates from a Microsoft CA (Active Directory Certificate Services)
asked directly over RPC, the way certreq.exe does: MS-ICPR's
ICertPassage::CertServerRequest (interface 91ae6020-9e3c-11cf-8d7c-00aa00c091be
v0.0, opnum 0) over DCE/RPC on TCP - the endpoint mapper on port 135 says the
port (or a fixed one is set) -, signed in with Kerberos (AES, the default) or
NTLMv2, always sealed (RPC_C_AUTHN_LEVEL_PKT_PRIVACY: AD CS enforces it with
IF_ENFORCEENCRYPTICERTREQUEST). No IIS, no Web Enrollment. See
docs/ms-adcs-rpc.md.

The request (the CSR acme made: the key never leaves acme) goes with the
attribute CertificateTemplate:<name>; the CA answers issued (3), under
submission (5: the request id is kept, and asked for again at later tries
with that id and no request - MS-WCCE's retrieval), denied (2) or an error
(an HRESULT such as 0x80094012: the user may not enroll for the template).
The certificate must be for the CSR's key; its chain comes in the PKCS#7 the
CA sends with it (else the chain set here, else its AIA address).

Kerberos needs the AES of the optional package `cryptography`
(python3-cryptography); NTLM does not. The pieces: _krb5.py (Kerberos),
_dcerpc.py (DCE/RPC, NDR, NTLM sealing), _ntlm.py (NTLMv2).

What happens (runplan) gets the conversation step by step from
ctx.rpc_plan where the context has it - nothing is connected, no secret goes
into it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import time

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.issuers import _dcerpc as R
from acmelib.plugins.issuers import _krb5 as K
from acmelib.plugins.issuers import _scep_pkcs7 as der
from acmelib.plugins.issuers import _source_common as sc

# How connections are made - socket.create_connection; the tests put their own servers here.
OPEN = socket.create_connection

# What the CA's answers mean (MS-WCCE 2.2.2.x, certsrv's error codes) - as words one can act on
ADCS_ERRORS = {
    0x80094800: 'the CA does not offer this template (CA → Certificate Templates → New → '
                'Certificate Template to Issue), or it is the display name - give the template '
                'name (without spaces)',
    0x80094801: 'the request has no template - set the template',
    0x80094012: 'the user may not enroll for this template (template → Security: Read and '
                'Enroll for the account)',
    0x80094011: 'the CA\'s permissions do not let the user enroll (CA → Properties → Security: '
                'Request Certificates for the account)',
    0x80094005: 'the CA refused the request\'s names (the template builds the subject from '
                'Active Directory: set it to "Supply in the request")',
    0x80094004: 'the template needs a subject (e-mail, DNS name) the user\'s AD account does not '
                'have - set the template to "Supply in the request"',
    0x80094006: 'the CA refused the request\'s key (too small, of a kind the template does not '
                'take)',
    0x80094009: 'the request has a key smaller than the template wants',
    0x8009480f: 'the template needs a DNS name in Active Directory the user does not have',
    0x80094811: 'the template needs a key the request does not have (key size, provider)',
    0x80070005: 'access is denied (the account\'s rights on the CA: Request Certificates; '
                'the CA wants the call encrypted - it is)',
    0x80094013: 'the CA cannot reach Active Directory for the template',
    0x80094014: 'the CA does not know this template in Active Directory',
    0x8009400c: 'the CA could not read the request',
    0x800b0110: 'the certificate is not for that purpose',
    0x80070057: 'the CA says a parameter is wrong (the CA name? give the CA\'s own name, as '
                'certutil -config shows it after the backslash)',
    0x800706ba: 'the CA service is not available (RPC server unavailable)',
    0x80094002: 'the request ID the CA was asked about is not known to it',
}
CR_DISP_DENIED, CR_DISP_ISSUED, CR_DISP_OUT_OF_BAND, CR_DISP_PENDING, CR_DISP_REVOKED = 2, 3, 4, 5, 6


def hresult_words(code):
    w = ADCS_ERRORS.get(code & 0xffffffff)
    return '%s (0x%08x)' % (w, code) if w else 'the CA said 0x%08x' % (code & 0xffffffff)


def is_name(host):
    try:
        ipaddress.ip_address(str(host).strip('[]'))
        return False
    except ValueError:
        return True


class MsAdcsRpcIssuer(Issuer):
    kind = 'ms_adcs_rpc'
    dual = True                     # where the template takes both kinds of key
    title = 'Microsoft AD CS (RPC, as certreq)'
    description = ('Certificates from a Microsoft CA asked directly over RPC, as certreq does '
                   '(MS-ICPR, no IIS): signed in with Kerberos or NTLM, always encrypted, with '
                   'a template. Requests waiting for approval are fetched later.')
    vendor = 'Microsoft'
    doc = 'docs/ms-adcs-rpc.md'
    discovery = False
    needs_challenge = False
    wildcards = True
    ip_names = True
    fields = [
        field('host', 'CA server', 'text', required=True, placeholder='ca01.example.local',
              help='The full DNS name of the server the CA runs on (Kerberos needs the name its '
                   'computer account has - not an address, not an alias).'),
        field('ca_name', 'CA name', 'text', required=True, placeholder='EXAMPLE-CA01-CA',
              help='The CA\'s own name: certutil -config shows "server\\CA name" - the part after '
                   'the backslash.'),
        field('template', 'Template', 'text', required=True, placeholder='WebServer',
              help='The template\'s name (not its display name): WebServer, or a copy of it, '
                   'published on the CA.'),
        field('auth', 'Signing in', 'select', default='kerberos',
              options=[['kerberos', 'Kerberos, NTLM where Kerberos cannot be used'],
                       ['kerberos_only', 'Kerberos only'],
                       ['ntlm', 'NTLM (v2) only']],
              help='Kerberos needs the domain controllers (TCP 88) and the CA server\'s DNS '
                   'name; NTLM signs in at the CA server alone. Either way the connection is '
                   'encrypted (packet privacy).'),
        field('realm', 'Domain', 'text', placeholder='EXAMPLE.LOCAL',
              help='The Active Directory domain\'s DNS name (the Kerberos realm). Empty: the '
                   'CA server\'s name without its first label. For NTLM also DOMAIN\\user.'),
        field('user', 'User', 'text', required=True, placeholder='svc-acme',
              help='An account with Read and Enroll on the template and Request Certificates '
                   'on the CA: user, user@domain or DOMAIN\\user.'),
        field('password', 'Password', 'secret', required=True),
        field('kdc', 'Domain controllers (KDC)', 'text', advanced=True,
              placeholder='dc01.example.local, dc02.example.local',
              help='Where to ask for Kerberos tickets (TCP 88; host or host:port, several '
                   'separated by commas). Empty: found in DNS (_kerberos._tcp.<domain>).'),
        field('spn', 'Service name of the CA server (SPN)', 'text', advanced=True,
              placeholder='host/ca01.example.local',
              help='The Kerberos name the ticket is for. Empty: host/<CA server> (RPCSS/ is the '
                   'same account).'),
        field('port', 'Fixed port', 'number', advanced=True, placeholder='135 → the port it says',
              help='The CA\'s RPC port when it is fixed (and the firewall opens only it). '
                   'Empty: asked from the endpoint mapper on port 135.'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
        field('attributes', 'More attributes', 'list', advanced=True,
              placeholder='SAN:dns=www.example.com',
              help='Lines added to the request\'s attributes (where the CA takes them).'),
        field('ca_chain', 'CA chain', 'pem', advanced=True,
              help='The CA\'s certificate and those above it, for when the CA\'s answer carries '
                   'none. Empty: from the answer, else the certificate\'s AIA address.'),
        field('key_kinds', 'Key types the template takes', 'select', default='any',
              options=[['any', 'RSA and ECDSA (a template of schema 2 or later, Key Storage '
                               'Provider)'],
                       ['rsa', 'RSA only (a template of schema 1, e.g. WebServer, or a legacy '
                               'CSP)'],
                       ['ec', 'ECDSA only']],
              help='What the template\'s Cryptography tab allows. The certificate\'s key type '
                   'is checked against it before the CA is asked; a twin (dual certificate) '
                   'needs both.'),
    ]

    per_cert = [{'key': 'template', 'label': 'Certificate template', 'field': 'template',
                 'placeholder': 'WebServer',
                 'help': 'The template on the Windows CA for this certificate. Empty: the '
                         'source\'s own.'}]

    @classmethod
    def key_types_for(cls, config):
        k = str((config or {}).get('key_kinds') or 'any')
        if k == 'rsa':
            return ['rsa-2048', 'rsa-3072', 'rsa-4096']
        if k == 'ec':
            return ['ec-256', 'ec-384']
        return ['ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096']

    @classmethod
    def dual_for(cls, config):
        return str((config or {}).get('key_kinds') or 'any') == 'any'

    # -- the settings -------------------------------------------------------------------
    def _say(self, words, level='info'):
        sc.say(self.ctx, words, level)

    def _host(self):
        h = str(self.c('host') or '').strip().rstrip('.')
        h = re.sub(r'^[a-z]+://', '', h, flags=re.I).split('/')[0]
        if not h:
            raise PluginError('set the CA server (its DNS name)', retry=False)
        return h

    def _ca(self):
        ca = str(self.c('ca_name') or '').strip()
        if '\\' in ca:                  # "server\CA name" as certutil -config says it
            ca = ca.split('\\', 1)[1].strip()
        if not ca:
            raise PluginError('set the CA name (certutil -config: the part after the backslash)',
                              retry=False)
        return ca

    def _timeout(self):
        return max(3.0, sc.num(self.c('timeout'), 30) or 30)

    def _port(self):
        try:
            p = int(float(self.c('port') or 0))
        except (TypeError, ValueError):
            raise PluginError('the fixed port is not a number', retry=False)
        if p and not 0 < p < 65536:
            raise PluginError('the fixed port is not a port (1-65535)', retry=False)
        return p

    def _realm(self):
        user = str(self.c('user') or '')
        r = str(self.c('realm') or '').strip().upper()
        if not r and '@' in user:
            r = user.rsplit('@', 1)[1].upper()
        if not r:
            host = self._host()
            if is_name(host) and '.' in host:
                r = host.split('.', 1)[1].upper()
        return r

    def _spn(self):
        s = str(self.c('spn') or '').strip()
        return s or 'host/%s' % self._host().lower()

    def _mode(self):
        m = str(self.c('auth') or 'kerberos')
        return m if m in ('kerberos', 'kerberos_only', 'ntlm') else 'kerberos'

    def _user(self):
        u = str(self.c('user') or '').strip()
        if not u:
            raise PluginError('set the user that signs in to the CA', retry=False)
        return u

    def _kdcs(self):
        """[(host, port)]: those set, else the SRV records of _kerberos._tcp.<realm>."""
        given = [x.strip() for x in re.split(r'[,\s;]+', str(self.c('kdc') or '')) if x.strip()]
        out = []
        for g in given:
            m = re.match(r'^\[?([^\]]+?)\]?(?::(\d+))?$', g)
            if m:
                out.append((m.group(1), int(m.group(2) or 88)))
        if out:
            return out
        realm = self._realm()
        name = '_kerberos._tcp.%s' % realm.lower()
        try:
            from acmelib.plugins.challenges import _dns
            msg = _dns.ask_any(_dns.system_resolvers(), name, 'SRV', timeout=5.0)
            recs = []
            for t in msg.texts('SRV'):
                bits = t.split()
                if len(bits) == 4 and bits[3].strip('.'):
                    recs.append((int(bits[0]), -int(bits[1]), bits[3].rstrip('.'), int(bits[2])))
            recs.sort()
            out = [(h, p) for _pr, _w, h, p in recs]
        except Exception as e:                          # noqa: BLE001
            self.ctx.debug('no SRV records for %s: %s' % (name, e))
        if not out:
            raise K.KrbError('no domain controller found: DNS has no SRV records %s - set the '
                             'domain controllers (KDC) under More' % name, fallback=True)
        return out

    # -- signing in and binding ------------------------------------------------------
    def _kerberos(self):
        """(_krb5.Client, the CA's ticket) - KrbError when Kerberos cannot be had."""
        K.need_crypto()
        host = self._host()
        if not is_name(host):
            raise K.KrbError('the CA server is given as an address (%s) - Kerberos needs its DNS '
                             'name' % host, fallback=True)
        realm = self._realm()
        if not realm:
            raise K.KrbError('set the domain (the Kerberos realm, e.g. EXAMPLE.LOCAL)',
                             fallback=True)
        kdc = K.Kdc(self._kdcs(), timeout=min(self._timeout(), 15), opener=OPEN)
        client = K.Client(self._user(), str(self.c('password') or ''), realm, kdc)
        client.login()
        ticket = client.service_ticket(self._spn())
        self._say('Kerberos: a ticket for %s from the domain controller %s:%d (%s), as %s' % (
            self._spn(), kdc.used[0], kdc.used[1], K.ETYPE_NAMES.get(ticket.key.etype, '?'),
            client.who))
        return client, ticket

    def _ntlm(self):
        # DOMAIN\\user and user@domain as given; a bare name: the CA server's own domain (the
        # NetBIOS name its CHALLENGE says)
        return R.NtlmAuth(self._user(), str(self.c('password') or ''), None,
                          spn=self._spn(), workstation='ACME')

    def _endpoint(self):
        host, port = self._host(), self._port()
        if port:
            return port, 'fixed'
        try:
            p = R.epm_port(host, R.ICPR, 135, self._timeout(), OPEN)
        except R.RpcError as e:
            raise self._rpc_error(e)
        self._say('the endpoint mapper of %s:135 says ICertPassage listens on port %d' % (host, p))
        return p, 'epm'

    def _bind(self, port, auth):
        t = R.Transport(self._host(), port, self._timeout(), OPEN, what='the CA')
        c = R.Client(t, auth)
        try:
            c.bind(R.ICPR)
        except Exception:
            c.close()
            raise
        return c

    def _connect(self):
        """(bound Client, words of how) - the endpoint, the sign-in, the bind; Kerberos
        falling back to NTLM where it cannot be used and the setting allows."""
        mode = self._mode()
        port, how = self._endpoint()
        tried = []
        if mode in ('kerberos', 'kerberos_only'):
            try:
                client, ticket = self._kerberos()
            except K.KrbError as e:
                if mode == 'kerberos' and e.fallback:
                    self._say('Kerberos cannot be used: %s - signing in with NTLM instead' % e,
                              'warn')
                    tried.append('Kerberos: %s' % e)
                else:
                    raise self._krb_error(e)
            else:
                for spnego in (False, True):
                    auth = R.KerberosAuth(client, ticket, spnego=spnego)
                    try:
                        c = self._bind(port, auth)
                        return c, self._how(auth, port, how, ticket)
                    except K.KrbError as e:
                        raise self._krb_error(e)
                    except R.RpcError as e:
                        if not e.auth_refused:
                            raise self._rpc_error(e)
                        tried.append('%s: %s' % ('Kerberos in SPNEGO' if spnego else
                                                 'Kerberos', e))
                        if not spnego:
                            self._say('the CA did not take Kerberos (auth type 16): %s - trying '
                                      'it inside SPNEGO (Negotiate)' % e, 'warn')
                if mode == 'kerberos_only':
                    raise PluginError('the CA refused the Kerberos sign-in: %s' % '; '.join(tried),
                                      retry=False)
                self._say('the CA refused Kerberos - signing in with NTLM instead', 'warn')
        auth = self._ntlm()
        try:
            c = self._bind(port, auth)
        except R.RpcError as e:
            if e.auth_refused:
                raise PluginError('the CA refused the sign-in of %s with NTLM (wrong password, a '
                                  'locked account, or NTLM not allowed for it)%s: %s' % (
                                      self._user(), ' after %s' % '; '.join(tried) if tried
                                      else '', e), retry=False)
            raise self._rpc_error(e)
        return c, self._how(auth, port, how, None)

    def _how(self, auth, port, how, ticket):
        if isinstance(auth, R.KerberosAuth):
            sign = 'Kerberos%s (%s) as %s' % (' in SPNEGO' if auth.spnego else '',
                                               K.ETYPE_NAMES.get(auth.ctx.key.etype, '?'),
                                               auth.who)
        else:
            sign = 'NTLMv2 as %s' % auth.who
        return '%s:%d (%s), signed in with %s, encrypted (packet privacy)' % (
            self._host(), port, 'from the endpoint mapper' if how == 'epm' else 'fixed', sign)

    def _krb_error(self, e):
        if e.code == 37:
            return PluginError(str(e), retry=False)
        retry = e.code not in (6, 7, 12, 14, 18, 23, 24, 31, 41, 68)
        return PluginError('Kerberos: %s' % e, retry=retry)

    def _rpc_error(self, e):
        if e.stage == 'connect':
            return PluginError('%s - the CA server must be reachable on TCP 135 (the endpoint '
                               'mapper) and its RPC port (49152-65535 by default, or the fixed '
                               'one)' % e, retry=True)
        if e.stage == 'epm':
            return PluginError(str(e), retry=True)
        if e.stage == 'fault' and e.status in (5, 0x80070005):
            # NTLM's last message (AUTH3) has no answer: a wrong password shows only here
            return PluginError('the CA refused the call: access is denied - the user or the '
                               'password is wrong (NTLM finds out only at the first call), the '
                               'account is locked, or it lacks Request Certificates on the CA '
                               '(0x%08x)' % e.status, retry=False)
        if e.auth_refused:
            return PluginError('the CA refused the sign-in: %s' % e, retry=False)
        return PluginError('RPC to the CA: %s' % e, retry=True)

    # -- trying it ---------------------------------------------------------------------
    def test(self):
        plan = getattr(self.ctx, 'rpc_plan', None)
        if callable(plan):
            plan(self._plan_steps(None, None, test=True))
            return 'written down, nothing connected'
        c, how = self._connect()
        c.close()
        return 'the CA answers at %s - ICertPassage bound, no certificate asked for' % how

    # -- a certificate -----------------------------------------------------------------
    def _template(self, req):
        t = str((req.profile or {}).get('template') or self.c('template') or '').strip()
        if not t:
            raise PluginError('set the template', retry=False)
        return t

    def _attributes(self, template):
        attrs = ['CertificateTemplate:%s' % template]
        more = self.c('attributes') or []
        if isinstance(more, str):
            more = more.splitlines()
        attrs += [str(a).strip() for a in more if str(a).strip()]
        return attrs

    def _slot(self, req):
        return sc.pending_slot('ms_adcs_rpc', '%s\\%s' % (self._host().lower(), self._ca()), req)

    def issue(self, req):
        if not req.csr_pem and not req.csr_der:
            raise PluginError('there is no request (CSR) to send to the CA', retry=False)
        template = self._template(req)
        ca = self._ca()
        slot = self._slot(req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held) if held and held.get('csr_pem') else req
        req_id = int(held.get('id') or 0) if held else 0
        plan = getattr(self.ctx, 'rpc_plan', None)
        if callable(plan):
            got = plan(self._plan_steps(r, template, req_id=req_id)) or {}
            if not got.get('CERT'):
                raise PluginError('the plan has no certificate to show', retry=False)
            return sc.finish(self.ctx, r, [der.cert_der(got['CERT'])],
                             [der.cert_der(x) for x in der.split_pem_chain(got.get('CHAIN') or '')],
                             info={'req_id': req_id or 4711, 'ca': ca})
        c, how = self._connect()
        self._say('connected to the CA at %s' % how)
        try:
            if req_id:
                self._say('the request %d waits at the CA since %s - asked for again' % (
                    req_id, time.strftime('%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
                res = self._call(c, 0, ca, req_id, [], b'')
            else:
                csr = sc.csr_der(req)
                self._say('the request goes to the CA %s (template %s)' % (ca, template))
                res = self._call(c, R.CR_IN_PKCS10, ca, 0, self._attributes(template), csr)
        finally:
            c.close()
        return self._outcome(res, req, r, slot, template, req_id)

    def _call(self, c, flags, ca, req_id, attrs, csr):
        stub = R.cert_server_request_stub(flags, ca, req_id, R.attributes_blob(attrs), csr)
        try:
            out = c.call(0, stub)
        except R.RpcError as e:
            raise self._rpc_error(e)
        return R.cert_server_response(out)

    def _outcome(self, res, req, r, slot, template, held_id):
        disp, rid = res['disposition'], res['request_id'] or held_id
        said = res['message']
        if disp == CR_DISP_ISSUED:
            leaf = res['encoded_cert']
            chain = []
            if res['cert']:
                try:
                    chain = der.certs_from_pkcs7(res['cert'])
                except (der.DerError, ValueError, IndexError):
                    chain = []
            if not leaf:
                leaf = next((x for x in chain if not der.Cert(x).is_ca), None)
            if not leaf:
                raise PluginError('the CA said issued but sent no certificate (request %s)' % rid)
            others = [x for x in chain if x != leaf]
            if not [x for x in others if der.Cert(x).is_ca]:
                others += self._chain_elsewhere(leaf)
            self._say('the CA issued the certificate (request %s)' % rid, 'ok')
            out = sc.finish(self.ctx, r, [leaf], others,
                            info={'req_id': rid, 'ca': '%s\\%s' % (self._host(), self._ca())})
            if r is not req and r.key_pem:
                out.key_pem = r.key_pem             # the key of the request held
            sc.pending_drop(self.ctx, slot)
            return out
        if disp == CR_DISP_PENDING:
            if not held_id:
                sc.pending_put(self.ctx, slot, req, {'id': rid, 'template': template,
                                                     'csr_pem': sc.csr_pem(req)}, ttl_days=90)
            self._say('the CA holds the request %s for a certificate manager to approve' % rid,
                      'warn')
            raise PluginError('the CA holds the request %s for a certificate manager to approve '
                              '(Certification Authority → Pending Requests → Issue); acme asks '
                              'for it again at the next try%s' % (
                                  rid, (' - it says: %s' % said[:200]) if said else ''),
                              retry=True)
        # refused one way or another: what is held is let go
        sc.pending_drop(self.ctx, slot)
        if disp == CR_DISP_DENIED:
            words = 'the CA denied the request %s' % rid
        elif disp == CR_DISP_REVOKED:
            words = 'the certificate of request %s was revoked at the CA' % rid
        elif disp == CR_DISP_OUT_OF_BAND:
            words = 'the CA issued request %s out of band - it sends no certificate' % rid
        elif disp >= 0x80000000:
            words = hresult_words(disp)
        elif res['status']:
            words = hresult_words(res['status'])
        else:
            words = 'the CA did not issue the certificate (disposition %d, %s)' % (
                disp, R.DISPOSITIONS.get(disp, '?'))
        if res['status'] and (disp in (CR_DISP_REVOKED, CR_DISP_OUT_OF_BAND) or (
                disp >= 0x80000000 and res['status'] != disp)):
            words += ' - %s' % hresult_words(res['status'])
        if said:
            words += ' - it says: %s' % said[:300]
        raise PluginError(words, retry=False)

    def _chain_elsewhere(self, leaf):
        """The chain set here, else the AIA (caIssuers, http) of the certificate."""
        given = str(self.c('ca_chain') or '').strip()
        if given:
            try:
                return [der.cert_der(x) for x in der.split_pem_chain(given)]
            except (der.DerError, ValueError):
                self._say('the CA chain set here does not read - not used', 'warn')
        out, cur = [], leaf
        for _i in range(4):
            url = aia_url(cur)
            if not url:
                break
            try:
                st, _h, data = self.ctx.http('GET', url, None, {}, 15)
            except Exception as e:                      # noqa: BLE001
                self._say('the CA certificate at %s could not be fetched: %s' % (url, e), 'warn')
                break
            if st != 200 or not data:
                break
            try:
                got = der.certs_from_pkcs7(data) if data[:1] == b'\x30' and b'\x06\x09\x2a\x86' \
                    b'\x48\x86\xf7\x0d\x01\x07\x02' in data[:40] else [der.cert_der(data)]
            except (der.DerError, ValueError, IndexError):
                break
            out += [x for x in got if x not in out]
            cur = got[0]
            c = der.Cert(cur)
            if c.subject_der == c.issuer_der:
                break
        if not out:
            self._say('the CA sent no chain and none is known (set the CA chain under More)',
                      'warn')
        return out

    # -- What happens: the conversation written down -----------------------------------
    def _plan_steps(self, req, template, req_id=0, test=False):
        host, port, mode = self._host(), self._port(), self._mode()
        realm = self._realm()
        steps = []
        if not port:
            steps.append({'kind': 'connect', 'words': 'Asks the endpoint mapper of {0} for the '
                                                       'port of ICertPassage',
                          'args': ['%s:135' % host],
                          'pairs': [['Protocol', 'DCE/RPC over TCP (ncacn_ip_tcp), not signed in',
                                     'words'],
                                    ['Call', 'ept_map (opnum 3) for 91ae6020-9e3c-11cf-8d7c-'
                                             '00aa00c091be v0.0'],
                                    ['Answer', 'the port the CA listens on (49152-65535 by '
                                               'default)', 'words']]})
        where = '%s:%s' % (host, port or '‹port from the endpoint mapper›')
        user = self._user()
        if mode != 'ntlm':
            given = str(self.c('kdc') or '').strip()
            kdcs = given or 'DNS SRV _kerberos._tcp.%s' % realm.lower()
            steps.append({'kind': 'connect', 'words': 'Asks the domain controller for Kerberos '
                                                       'tickets: {0} and {1}',
                          'args': ['krbtgt/%s' % realm, self._spn()],
                          'pairs': [['Domain controllers', '%s (TCP 88)' % kdcs],
                                    ['User', '%s@%s' % (K.split_user(user, realm)[0], realm)],
                                    ['Password', 'not shown - only the key made from it '
                                                 'encrypts a timestamp (PA-ENC-TIMESTAMP)', 'words'],
                                    ['Encryption', 'AES256 / AES128 (RFC 3962)', 'words'],
                                    ['Calls', 'AS-REQ → TGT, TGS-REQ → the ticket for %s'
                                     % self._spn()]]})
            how = 'Kerberos (auth type 16; SPNEGO where the CA wants it)' + (
                ', NTLMv2 where Kerberos cannot be used' if mode == 'kerberos' else '')
        else:
            how = 'NTLMv2 (auth type 10)'
        steps.append({'kind': 'connect', 'words': 'Connects to the CA {0} and signs in: {1}',
                      'args': [where, 'Kerberos' if mode != 'ntlm' else 'NTLMv2'],
                      'pairs': [['Interface', 'ICertPassage 91ae6020-9e3c-11cf-8d7c-00aa00c091be '
                                              'v0.0 (MS-ICPR)'],
                                ['Signs in with', how, 'words'],
                                ['Authentication level', 'packet privacy - every call encrypted '
                                                         '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)', 'words'],
                                ['Mutual authentication', 'yes - the CA proves itself (AP-REP)'
                                 if mode != 'ntlm' else 'no (NTLM)', 'words']]})
        if test:
            return {'steps': steps, 'test': True}
        ca = self._ca()
        if req_id:
            steps.append({'kind': 'read', 'words': 'Asks the CA {0} for the request {1} it held',
                          'args': [ca, str(req_id)],
                          'pairs': [['Call', 'CertServerRequest (opnum 0), encrypted'],
                                    ['Request ID', str(req_id)],
                                    ['Request', 'none - a retrieval (MS-WCCE)', 'words']]})
        else:
            csr = sc.csr_der(req) if req is not None else b''
            spki = der.csr_spki(csr) if csr else b''
            steps.append({'kind': 'call', 'words': 'Sends the request to the CA {0} with the '
                                                   'template {1}',
                          'args': [ca, template],
                          'pairs': [['Call', 'CertServerRequest (opnum 0), encrypted'],
                                    ['CA', ca],
                                    ['Flags', 'CR_IN_PKCS10 (0x100)'],
                                    ['Attributes', '\n'.join(self._attributes(template))],
                                    ['Request', 'the CSR, %d bytes (DER); its key: sha256 %s' % (
                                        len(csr), hashlib.sha256(spki).hexdigest()[:16])],
                                    ['Answer', 'issued (3): the certificate and its chain '
                                               '(PKCS#7); under submission (5): the request ID '
                                               'kept for the next try', 'words']]})
        return {'steps': steps, 'test': False}


def aia_url(cert_der):
    """The first http(s) caIssuers address of a certificate's AIA, or None."""
    try:
        c = der.Cert(cert_der)
        ext = c.extensions.get('1.3.6.1.5.5.7.1.1')
        if not ext:
            return None
        for _t, ad, _w in der.der_items(der.der_one(ext[1])[1]):
            parts = der.der_items(ad)
            if der.oid_decode(parts[0][1]) == '1.3.6.1.5.5.7.48.2' and parts[1][0] == 0x86:
                url = parts[1][1].decode('ascii', 'replace')
                if url.lower().startswith(('http://', 'https://')):
                    return url
    except (der.DerError, ValueError, IndexError):
        return None
    return None
