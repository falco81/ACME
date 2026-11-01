# -*- coding: utf-8 -*-
"""
Certificates by SCEP (RFC 8894): Microsoft NDES, EJBCA, Smallstep step-ca,
Cisco IOS CA, Fortinet, Palo Alto, Jamf, Intune-style servers - whatever
speaks GetCACaps, GetCACert and PKIOperation. The request (with its challenge
password) is signed by a transient self-signed certificate of its own key and
encrypted to the CA's (or RA's) certificate; a PENDING answer is polled with
CertPoll (GetCertInitial). See docs/scep.md.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
import urllib.parse

from acmelib.plugins.base import Issuer, Issued, PluginError, field
from acmelib.plugins.issuers import _scep_pkcs7 as p7


class ScepIssuer(Issuer):
    kind = 'scep'
    dual = False                    # SCEP needs an RSA key: no ECDSA twin
    title = 'SCEP (NDES, EJBCA, step-ca, ...)'
    description = ('Certificates from a CA that speaks SCEP (RFC 8894): Microsoft NDES, EJBCA, '
                   'step-ca and others, with a challenge password. Requests the CA holds '
                   '(PENDING) are asked for again.')
    vendor = 'SCEP'
    doc = 'docs/scep.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    fields = [
        field('url', 'SCEP address', 'text', required=True,
              placeholder='https://ndes.example.local/certsrv/mscep/mscep.dll',
              help='The SCEP URL of the CA (NDES: .../certsrv/mscep/mscep.dll; EJBCA: '
                   '.../ejbca/publicweb/apply/scep/ALIAS/pkiclient.exe; step-ca: '
                   '.../scep/PROVISIONER).'),
        field('challenge', 'Challenge password', 'secret',
              help='The one-time or fixed password the CA gives for enrolment (NDES: from '
                   '/certsrv/mscep_admin).'),
        field('ca_ident', 'CA identifier', 'text', advanced=True,
              help='The "message" of GetCACert where the server hosts several CAs (EJBCA: the CA name).'),
        field('ca_fingerprint', 'CA fingerprint', 'text', advanced=False,
              placeholder='SHA-256 (or SHA-1/MD5) of the CA certificate',
              help='The CA certificate the server sends must be this one - set it: SCEP is often '
                   'over plain HTTP.'),
        field('cipher', 'Encryption', 'select', default='auto', advanced=True,
              options=[['auto', 'As the CA says (AES-256, else 3DES)'], ['aes256', 'AES-256-CBC'],
                       ['aes128', 'AES-128-CBC'], ['3des', '3DES (old servers)']]),
        field('digest', 'Digest', 'select', default='auto', advanced=True,
              options=[['auto', 'As the CA says (SHA-256, else SHA-1)'], ['sha256', 'SHA-256'],
                       ['sha512', 'SHA-512'], ['sha1', 'SHA-1 (old servers)']]),
        field('ca_pem', 'CA certificate of the web server', 'pem', advanced=True,
              help='For HTTPS with a private CA.'),
        field('verify', 'Check the web server\'s TLS certificate', 'bool', default=True, advanced=True),
        field('wait_pending', 'Wait for approval (s)', 'number', default=60, advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=10, advanced=True),
    ]

    # -- settings and HTTP -----------------------------------------------------------
    def _url(self):
        url = str(self.c('url') or '').strip()
        if not re.match(r'^https?://\S+\Z', url):
            raise PluginError('set the SCEP address (http:// or https://)', retry=False)
        return url

    def _say(self, words, level='info'):
        try:
            self.ctx.step(words, level)
        except Exception:                           # noqa: BLE001
            pass

    def _verify(self):
        v = self.c('verify')
        return True if v in (None, '') else bool(v) and str(v).lower() not in ('0', 'false', 'no')

    def _get(self, operation, message=None, raw_query=None):
        q = {'operation': operation}
        if message is not None:
            q['message'] = message
        url = self._url()
        url += ('&' if '?' in url else '?') + (raw_query or urllib.parse.urlencode(q))
        return self._http('GET', url)

    def _http(self, method, url, body=None, headers=None):
        try:
            status, hdrs, data = self.ctx.http(method, url, body, headers or {}, 60, self._verify(),
                                               self.c('ca_pem') or None)
        except PluginError:
            raise
        except Exception as e:                      # noqa: BLE001
            raise PluginError('the SCEP server does not answer: %s' % e)
        hdrs = {str(k).lower(): v for k, v in (hdrs or {}).items()}
        return status, hdrs, data or b''

    def caps(self):
        status, _h, data = self._get('GetCACaps', self.c('ca_ident') or None)
        if status != 200:
            self._say('the server has no GetCACaps (%s) - the oldest algorithms are used' % status, 'warn')
            return set()
        return {w.strip() for w in data.decode('ascii', 'replace').split()
                if w.strip()}

    def ca_certs(self):
        """(the CA certificate, the certificate the request is encrypted to,
        every certificate sent) - all DER."""
        status, h, data = self._get('GetCACert', self.c('ca_ident') or 'acme')
        if status != 200 or not data:
            raise PluginError('GetCACert answered %s - check the SCEP address and the CA identifier'
                              % status, detail=data[:300].decode('utf-8', 'replace'))
        ctype = (h.get('content-type') or '').lower()
        try:
            if 'ra-cert' in ctype or (data[:1] == b'\x30' and b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02' in data[:40]):
                certs = p7.certs_from_pkcs7(data)
            else:
                certs = [p7.cert_der(data)]
        except (p7.DerError, ValueError, IndexError) as e:
            raise PluginError('the CA certificate from GetCACert does not read: %s' % e)
        parsed = [p7.Cert(c) for c in certs]
        cas = [c for c in parsed if c.is_ca] or parsed
        pin = re.sub(r'[^0-9a-fA-F]', '', str(self.c('ca_fingerprint') or '')).lower()
        ca = None
        if pin:
            algo = {32: 'md5', 40: 'sha1', 64: 'sha256'}.get(len(pin))
            if not algo:
                raise PluginError('the CA fingerprint is neither SHA-256, SHA-1 nor MD5', retry=False)
            ca = next((c for c in parsed if c.fingerprint(algo) == pin), None)
            if not ca:
                raise PluginError('the CA certificate the server sent is not the one of the fingerprint '
                                  '- someone in between, or another CA (it sent %s)' % ', '.join(
                                      '%s %s' % (c.subject_cn, c.fingerprint()) for c in parsed),
                                  retry=False)
        # The RA (NDES): not a CA; for encryption the one with keyEncipherment.
        ras = [c for c in parsed if not c.is_ca]
        enc = [c for c in ras if c.key_usage is None or c.key_usage & (1 << 2)]
        if not ca:
            if ras:
                ca = next((c for c in cas if c.subject_der == (enc or ras)[0].issuer_der), cas[0])
            else:
                # the issuing CA: the one no other certificate sent was issued by
                ca = next((c for c in cas if not any(x is not c and x.issuer_der == c.subject_der
                                                     for x in cas)), cas[0])
        recipient = (enc or ras or [ca])[0]
        if pin:
            self._say('the CA certificate is the one of the fingerprint', 'ok')
        elif self._url().startswith('http://'):
            self._say('the CA certificate is taken as the server sends it over plain HTTP - set its '
                      'fingerprint to be sure (%s)' % ca.fingerprint(), 'warn')
        return ca, recipient, [c.der for c in parsed]

    def _algos(self, caps):
        ci = self.c('cipher') or 'auto'
        if ci == 'auto':
            ci = 'aes256' if 'AES' in caps else '3des'
        dg = self.c('digest') or 'auto'
        if dg == 'auto':
            dg = 'sha256' if ('SHA-256' in caps or 'SCEPStandard' in caps) else \
                'sha512' if 'SHA-512' in caps else 'sha1'
        if ci not in p7.CIPHERS or dg not in p7.DIGESTS:
            raise PluginError('an unknown encryption or digest', retry=False)
        return ci, dg

    # -- trying it -------------------------------------------------------------------
    def test(self):
        caps = self.caps()
        ca, rcpt, certs = self.ca_certs()
        ci, dg = self._algos(caps)
        return 'the SCEP server answers: CA %s (SHA-256 %s)%s; it can %s; requests go %s/%s' % (
            ca.subject_cn, ca.fingerprint()[:16] + '…',
            (', RA %s' % rcpt.subject_cn) if rcpt.der != ca.der else '',
            ', '.join(sorted(caps)) or 'nothing it says', ci, dg)

    # -- a certificate ---------------------------------------------------------------
    def issue(self, req):
        if not req.csr_der or not req.key_pem:
            raise PluginError('there is no request (CSR and key) for SCEP', retry=False)
        caps = self.caps()
        ci, dg = self._algos(caps)
        ca, rcpt, all_certs = self.ca_certs()
        with p7.Crypto(self._openssl) as cr:
            key_file = cr.file(req.key_pem, 'key.pem')
            spki = p7.csr_spki(req.csr_der)
            if p7.spki_algorithm(spki) != p7.OID_RSA:
                raise PluginError('SCEP needs an RSA key (the CA encrypts its answer to it) - set the '
                                  'certificate\'s key type to RSA', retry=False)
            tid = p7.transaction_id(spki)
            slot = 'scep-pending:%s:%s' % (hashlib.sha256(self._url().encode()).hexdigest()[:16], tid[:32])
            signer = cr.selfsigned(key_file, (req.names or ['acme'])[0])
            held = self.ctx.kv_get(slot)
            if held:
                self._say('the CA held this request (transaction %s…) - asked for again' % tid[:16])
                msg_type, content = 'CertPoll', p7.seq(ca.subject_der, p7.csr_subject(req.csr_der))
            else:
                csr = req.csr_der
                pw = str(self.c('challenge') or '')
                if pw:
                    csr = p7.add_challenge_password(cr, csr, key_file, pw, 'sha256' if dg == 'sha1' else dg)
                msg_type, content = 'PKCSReq', csr
            self._say('%s to the SCEP server (%s, %s)' % (msg_type, ci.upper(), dg.upper()))
            got = self._operation(cr, caps, ci, dg, msg_type, content, tid, signer, key_file, rcpt, ca,
                                  all_certs)
            end = time.time() + float(self.c('wait_pending') or 0)
            while got[0] == 'PENDING':
                self.ctx.kv_set(slot, json.dumps({'at': time.time(), 'tid': tid}), ttl_s=30 * 86400)
                if time.time() >= end:
                    raise PluginError('the CA holds the request (PENDING, transaction %s…) for someone '
                                      'to approve - acme asks for it again at the next try' % tid[:16])
                if self.ctx.cancelled():
                    raise PluginError('stopped', retry=False)
                self._say('the CA holds the request (PENDING) - asked again in a moment')
                time.sleep(max(0.2, float(self.c('poll_every') or 10)))
                got = self._operation(cr, caps, ci, dg, 'CertPoll',
                                      p7.seq(ca.subject_der, p7.csr_subject(req.csr_der)),
                                      tid, signer, key_file, rcpt, ca, all_certs)
            if held or got[0] in ('SUCCESS', 'FAILURE'):
                self.ctx.kv_set(slot, None)
            if got[0] == 'FAILURE':
                fi = got[1]
                raise PluginError('the CA refused the request: %s%s' % (
                    p7.FAIL_WORDS.get(fi, 'no reason given'), (' (failInfo %s)' % fi) if fi else ''),
                    retry=False)
            certs = got[1]
        leaf = next((c for c in certs if p7.Cert(c).spki_der == spki), None)
        if not leaf:
            raise PluginError('the CA\'s answer holds no certificate for this key')
        chain = [c for c in certs if c != leaf]
        for c in all_certs:
            x = p7.Cert(c)
            if x.is_ca and c not in chain:
                chain.append(c)
        chain = p7.order_chain(leaf, chain)
        x = p7.Cert(leaf)
        self._say('the certificate came: serial %x, until %s, from %s' % (
            x.serial, time.strftime('%Y-%m-%d', time.gmtime(x.not_after)), x.issuer_cn or '?'), 'ok')
        return Issued(p7.pem(leaf), [p7.pem(c) for c in chain], info={'transaction_id': tid})

    def _openssl(self, args, data=None):
        try:
            out = self.ctx.openssl(list(args), data)
        except PluginError:
            raise
        except Exception as e:                      # noqa: BLE001
            raise PluginError('openssl failed (%s): %s' % (args[0], e))
        return out if isinstance(out, bytes) else str(out).encode()

    def _operation(self, cr, caps, ci, dg, msg_type, content, tid, signer, key_file, rcpt, ca, all_certs):
        nonce = os.urandom(16)
        env = p7.build_enveloped(cr, content, rcpt.der, ci)
        msg = p7.build_signed(cr, env, signer, key_file, [
            (p7.OID_SCEP_MESSAGE_TYPE, p7.der_printable(p7.MESSAGE_TYPES[msg_type])),
            (p7.OID_SCEP_TRANSACTION_ID, p7.der_printable(tid)),
            (p7.OID_SCEP_SENDER_NONCE, p7.der_octets(nonce))], dg)
        if 'POSTPKIOperation' in caps or 'SCEPStandard' in caps:
            url = self._url()
            url += ('&' if '?' in url else '?') + 'operation=PKIOperation'
            status, h, data = self._http('POST', url, msg, {'Content-Type': 'application/x-pki-message'})
        else:
            status, h, data = self._get('PKIOperation', raw_query='operation=PKIOperation&message=' +
                                        urllib.parse.quote(base64.b64encode(msg).decode(), safe=''))
        if status != 200:
            raise PluginError('the SCEP server answered %s to %s' % (status, msg_type),
                              detail=data[:500].decode('utf-8', 'replace'))
        return self._cert_rep(cr, data, tid, nonce, key_file, signer, ca, rcpt, all_certs)

    def _cert_rep(self, cr, data, tid, nonce, key_file, signer, ca, rcpt, all_certs):
        try:
            rep = p7.SignedMessage(data)
        except (p7.DerError, ValueError, IndexError) as e:
            raise PluginError('the SCEP answer is not a PKCS#7 message: %s' % e,
                              detail=data[:300].decode('latin-1'))
        mtype = rep.attr_text(p7.OID_SCEP_MESSAGE_TYPE)
        if mtype != p7.MESSAGE_TYPES['CertRep']:
            raise PluginError('the SCEP answer is not a CertRep (messageType %s)' % mtype)
        if rep.attr_text(p7.OID_SCEP_TRANSACTION_ID) != tid:
            raise PluginError('the SCEP answer is for another transaction')
        rn = rep.attr_bytes(p7.OID_SCEP_RECIPIENT_NONCE)
        if rn is not None and rn != nonce:
            raise PluginError('the SCEP answer does not carry our nonce (a replay?)')
        if not rep.digest_ok():
            raise PluginError('the SCEP answer\'s messageDigest does not match its content')
        self._check_signature(cr, data, rep, ca, rcpt, all_certs)
        status = p7.PKI_STATUS.get(rep.attr_text(p7.OID_SCEP_PKI_STATUS) or '', 'FAILURE')
        if status == 'PENDING':
            return ('PENDING', None)
        if status == 'FAILURE':
            fi = rep.attr_text(p7.OID_SCEP_FAIL_INFO)
            return ('FAILURE', p7.FAIL_INFO.get(fi or '', fi))
        inner = self._decrypt(cr, rep.content, key_file, signer)
        try:
            certs = p7.certs_from_pkcs7(inner)
        except (p7.DerError, ValueError, IndexError) as e:
            raise PluginError('the certificates in the SCEP answer do not read: %s' % e)
        return ('SUCCESS', certs)

    def _check_signature(self, cr, data, rep, ca, rcpt, all_certs):
        """The CertRep verified by openssl cms: its signature with the signer's key,
        that signer being the CA or the RA (or issued by the CA)."""
        signer = rep.signer_cert()
        known = {c for c in all_certs}
        if signer is None:
            signer = next((c for c in all_certs if p7.Cert(c).serial == rep.signer_serial and
                           p7.Cert(c).issuer_der == rep.signer_issuer), None)
        if signer is None:
            raise PluginError('the SCEP answer is signed by a certificate acme does not have')
        sx = p7.Cert(signer)
        if signer not in known and sx.issuer_der != ca.subject_der:
            raise PluginError('the SCEP answer is signed by %s, neither the CA nor its RA' % sx.subject_cn,
                              retry=False)
        f_msg = cr.file(data)
        f_signer = cr.file(p7.pem(signer))
        try:
            cr.run(['cms', '-verify', '-inform', 'DER', '-in', f_msg, '-noverify', '-certfile', f_signer,
                    '-binary', '-out', os.path.join(cr.dir, 'verified')])
        except PluginError as e:
            raise PluginError('the signature of the SCEP answer does not verify', detail=str(e))

    def _decrypt(self, cr, env_der, key_file, signer):
        f_env = cr.file(env_der)
        f_cert = cr.file(p7.pem(signer))
        try:
            return cr.run(['cms', '-decrypt', '-inform', 'DER', '-in', f_env, '-recip', f_cert,
                           '-inkey', key_file, '-binary'])
        except PluginError:
            # openssl cms wants the recipient by issuer and serial; a server that addressed it
            # otherwise is opened by hand.
            try:
                return p7.open_enveloped(cr, env_der, key_file)
            except (p7.DerError, PluginError, ValueError, IndexError) as e:
                raise PluginError('the SCEP answer could not be decrypted: %s' % e)
