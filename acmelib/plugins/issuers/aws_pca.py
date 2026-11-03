# -*- coding: utf-8 -*-
"""
Certificates from AWS Private CA (ACM PCA): the CSR acme made issued by a
private CA of the account, with an IAM access key (AWS Signature Version 4,
written in challenges/route53.py and used from there).

From the API's own model (github.com/boto/botocore, botocore/data/acm-pca/
2017-08-22/service-2.json, read 2026-11; the same as
https://docs.aws.amazon.com/privateca/latest/APIReference/):

* JSON 1.1 protocol: POST https://acm-pca.<region>.amazonaws.com/ with
  X-Amz-Target: ACMPrivateCA.<Action> and Content-Type
  application/x-amz-json-1.1, signed for the service "acm-pca".
* IssueCertificate {CertificateAuthorityArn, Csr (blob: base64 of the PEM),
  SigningAlgorithm, Validity {Value, Type: DAYS}, TemplateArn,
  IdempotencyToken} -> {CertificateArn}.
* GetCertificate {CertificateAuthorityArn, CertificateArn} ->
  {Certificate, CertificateChain} (PEM); RequestInProgressException while the
  CA is still making it (asked again).
* RevokeCertificate {CertificateAuthorityArn, CertificateSerial (hex),
  RevocationReason}; DescribeCertificateAuthority for "Try it" and the CA's
  signing algorithm.

* Templates (TemplateArn): AWS has no call that lists them; the 18 end-entity
  templates (Base, CSRPassthrough, APIPassthrough, APICSRPassthrough) are a fixed
  list here, as https://docs.aws.amazon.com/privateca/latest/userguide/
  template-varieties.html names them ("If this parameter is not provided, AWS
  Private CA defaults to the EndEntityCertificate/V1 template"). Any other ARN can
  be typed (GovCloud's ARNs differ). An APIPassthrough template takes ApiPassthrough
  values, which acme does not send.

The IAM policy needs acm-pca:IssueCertificate, acm-pca:GetCertificate,
acm-pca:DescribeCertificateAuthority (and acm-pca:RevokeCertificate). A
certificate of a private CA costs per certificate issued (AWS pricing) -
there is no order to buy: what the CA's account pays is AWS's.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time

from acmelib.plugins.base import Issuer, PluginError, field
from acmelib.plugins.challenges.route53 import sigv4
from acmelib.plugins.issuers import _source_common as sc

ARN_RE = re.compile(r'^arn:(aws[a-z-]*):acm-pca:([a-z0-9-]+):(\d{12}):certificate-authority/[0-9a-f-]+\Z')
REASONS = {0: 'UNSPECIFIED', 1: 'KEY_COMPROMISE', 2: 'CERTIFICATE_AUTHORITY_COMPROMISE',
           3: 'AFFILIATION_CHANGED', 4: 'SUPERSEDED', 5: 'CESSATION_OF_OPERATION',
           9: 'PRIVILEGE_WITHDRAWN', 10: 'A_A_COMPROMISE'}
# The end-entity templates of template-varieties.html, in its order (catalog()).
TEMPLATES = ['arn:aws:acm-pca:::template/%s/V1' % t for t in (
    'EndEntityCertificate', 'EndEntityClientAuthCertificate', 'EndEntityServerAuthCertificate',
    'BlankEndEntityCertificate_CSRPassthrough',
    'BlankEndEntityCertificate_CriticalBasicConstraints_CSRPassthrough',
    'EndEntityCertificate_CSRPassthrough', 'EndEntityClientAuthCertificate_CSRPassthrough',
    'EndEntityServerAuthCertificate_CSRPassthrough',
    'BlankEndEntityCertificate_APIPassthrough',
    'BlankEndEntityCertificate_CriticalBasicConstraints_APIPassthrough',
    'EndEntityCertificate_APIPassthrough', 'EndEntityClientAuthCertificate_APIPassthrough',
    'EndEntityServerAuthCertificate_APIPassthrough',
    'BlankEndEntityCertificate_APICSRPassthrough',
    'BlankEndEntityCertificate_CriticalBasicConstraints_APICSRPassthrough',
    'EndEntityCertificate_APICSRPassthrough', 'EndEntityClientAuthCertificate_APICSRPassthrough',
    'EndEntityServerAuthCertificate_APICSRPassthrough')]
ALGOS = ['SHA256WITHECDSA', 'SHA384WITHECDSA', 'SHA512WITHECDSA', 'SHA256WITHRSA',
         'SHA384WITHRSA', 'SHA512WITHRSA']


class AwsPcaIssuer(Issuer):
    kind = 'aws_pca'
    dual = True
    title = 'AWS Private CA'
    description = ('Certificates issued by a private CA of AWS Private CA (ACM PCA) from acme\'s '
                   'request, signed in with an IAM access key. Revocation included.')
    vendor = 'Amazon'
    doc = 'docs/sources.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    choose_days = True
    per_cert = [{'key': 'template', 'field': 'template_arn', 'catalog': 'templates',
                 'label': 'Template (ARN)',
                 'placeholder': 'arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1',
                 'help': 'The AWS Private CA template for this certificate. Empty: the source\'s own.'}]
    fields = [
        field('ca_arn', 'CA ARN', 'text', required=True,
              placeholder='arn:aws:acm-pca:eu-central-1:123456789012:certificate-authority/…',
              help='The private CA (AWS Private CA → the CA → ARN); its region is taken from it.'),
        field('access_key', 'Access key ID', 'text', required=True),
        field('secret_key', 'Secret access key', 'secret', required=True,
              help='Of an IAM user (or role) allowed acm-pca:IssueCertificate, GetCertificate, '
                   'DescribeCertificateAuthority and RevokeCertificate on the CA.'),
        field('session_token', 'Session token', 'secret', advanced=True,
              help='For temporary credentials only.'),
        field('days', 'Validity (days)', 'number', default=90,
              help='A certificate\'s own days win; at most what the CA\'s own validity allows.'),
        field('template_arn', 'Template', 'catalog', catalog='templates', advanced=True,
              placeholder='arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1',
              help='Load the list: the end-entity templates AWS documents (AWS has no call that '
                   'lists them); another ARN can be typed. Empty: AWS\'s default '
                   '(EndEntityCertificate/V1). A certificate\'s own template (Add a certificate '
                   '→ Settings) wins.'),
        field('signing_algorithm', 'Signing algorithm', 'select', default='auto', advanced=True,
              options=[['auto', 'As the CA signs (from the CA)']] + [[a, a] for a in ALGOS]),
        field('endpoint', 'API endpoint', 'text', advanced=True,
              placeholder='https://acm-pca.eu-central-1.amazonaws.com',
              help='Empty: the region\'s (a VPC endpoint or FIPS endpoint otherwise).'),
        field('wait', 'Wait for the certificate (s)', 'number', default=60, advanced=True),
    ]

    # -- the form's lists (base.py: a field of the type catalog) ------------------------
    def catalog(self, key):
        """The end-entity templates of AWS Private CA - a fixed list from AWS's user guide
        (template-varieties.html): the API has no call that lists them. Asks nothing."""
        if key != 'templates':
            raise PluginError('there is no list called %s here' % key, retry=False)
        opts = [[t, t.split('/')[1] + (' (AWS\'s default)' if t == TEMPLATES[0] else '')]
                for t in TEMPLATES]
        return {'options': opts, 'said': '%d end-entity templates AWS documents (another ARN '
                                         'can be typed)' % len(opts)}

    def _arn(self):
        arn = str(self.c('ca_arn') or '').strip()
        m = ARN_RE.match(arn)
        if not m:
            raise PluginError('set the CA ARN (arn:aws:acm-pca:REGION:ACCOUNT:certificate-'
                              'authority/ID)', retry=False)
        return arn, m.group(2)

    def _endpoint(self):
        _arn, region = self._arn()
        ep = str(self.c('endpoint') or '').strip().rstrip('/')
        if ep and not re.match(r'^https://[^\s/]+\Z', ep):
            raise PluginError('the API endpoint is https://HOST', retry=False)
        return (ep or 'https://acm-pca.%s.amazonaws.com' % region) + '/', region

    def call(self, action, body):
        if not self.c('access_key') or not self.c('secret_key'):
            raise PluginError('set the access key ID and the secret access key', retry=False)
        url, region = self._endpoint()
        data = json.dumps(body).encode('utf-8')
        headers = sigv4('POST', url, {'Content-Type': 'application/x-amz-json-1.1',
                                      'X-Amz-Target': 'ACMPrivateCA.' + action}, data,
                        str(self.c('access_key')).strip(), str(self.c('secret_key')).strip(),
                        region, 'acm-pca', session_token=self.c('session_token') or None)
        status, _h, raw = sc.http(self.ctx, 'POST', url, data, headers, who='AWS Private CA')
        parsed = sc.parse_json(raw) or {}
        if status != 200:
            kind = str(parsed.get('__type') or '').split('#')[-1]
            return status, kind, parsed
        return status, '', parsed

    def _ok(self, action, body):
        status, kind, got = self.call(action, body)
        if status != 200:
            raise self._error(action, status, kind, got)
        return got

    @staticmethod
    def _error(action, status, kind, got):
        said = got.get('message') or got.get('Message') or ''
        words = 'AWS Private CA (%s) answered %s %s: %s' % (action, status, kind or '', said)
        if kind in ('AccessDeniedException', 'UnrecognizedClientException',
                    'InvalidSignatureException') or status == 403:
            words += ' - the access key is wrong or its policy does not allow acm-pca:%s' % action
        return PluginError(words, retry=status >= 500 or kind in ('ThrottlingException',
                                                                  'LimitExceededException'))

    def _algorithm(self, arn):
        a = self.c('signing_algorithm') or 'auto'
        if a != 'auto':
            return a
        ca = self._ok('DescribeCertificateAuthority', {'CertificateAuthorityArn': arn})
        a = ((ca.get('CertificateAuthority') or {}).get('CertificateAuthorityConfiguration') or {})\
            .get('SigningAlgorithm')
        return a or 'SHA256WITHRSA'

    def test(self):
        arn, region = self._arn()
        ca = self._ok('DescribeCertificateAuthority', {'CertificateAuthorityArn': arn})\
            .get('CertificateAuthority') or {}
        conf = ca.get('CertificateAuthorityConfiguration') or {}
        subj = (conf.get('Subject') or {}).get('CommonName') or '?'
        words = 'AWS Private CA answers (%s): the CA %s is %s, %s, signs %s' % (
            region, subj, ca.get('Status') or '?', ca.get('Type') or '?',
            conf.get('SigningAlgorithm') or '?')
        if ca.get('Status') != 'ACTIVE':
            raise PluginError(words + ' - it does not issue unless ACTIVE', retry=False)
        return words

    def issue(self, req):
        arn, _region = self._arn()
        slot = sc.pending_slot('aws_pca', arn, req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        if held and held.get('id'):
            cert_arn = held['id']
            sc.say(self.ctx, 'the certificate %s asked for at %s is fetched' % (
                cert_arn, time.strftime('%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
        else:
            days = int(req.days or sc.num(self.c('days'), 90) or 90)
            csr = sc.csr_pem(req).encode('ascii')
            body = {'CertificateAuthorityArn': arn, 'Csr': base64.b64encode(csr).decode('ascii'),
                    'SigningAlgorithm': self._algorithm(arn),
                    'Validity': {'Value': days, 'Type': 'DAYS'},
                    'IdempotencyToken': hashlib.sha256(csr).hexdigest()[:36]}
            tpl = str((req.profile or {}).get('template') or self.c('template_arn') or '').strip()
            if tpl:
                if not tpl.startswith('arn:'):
                    raise PluginError('the template is an ARN (arn:aws:acm-pca:::template/…)',
                                      retry=False)
                body['TemplateArn'] = tpl
            sc.say(self.ctx, 'IssueCertificate at AWS Private CA (%d days, %s)' % (
                days, body['SigningAlgorithm']))
            cert_arn = self._ok('IssueCertificate', body).get('CertificateArn')
            if not cert_arn:
                raise PluginError('AWS Private CA said no certificate ARN')
            held = sc.pending_put(self.ctx, slot, req, {'id': cert_arn, 'csr_pem': sc.csr_pem(req)})
            r = req
        end = time.time() + sc.num(self.c('wait'), 60)
        while True:
            status, kind, got = self.call('GetCertificate', {'CertificateAuthorityArn': arn,
                                                             'CertificateArn': cert_arn})
            if status == 200:
                break
            if kind == 'RequestInProgressException':
                if time.time() >= end or self.ctx.cancelled():
                    raise PluginError('AWS Private CA is still making the certificate - acme '
                                      'fetches it at the next try')
                time.sleep(2)
                continue
            sc.pending_drop(self.ctx, slot)
            raise self._error('GetCertificate', status, kind, got)
        sc.pending_drop(self.ctx, slot)
        certs = sc.certs_of(got.get('Certificate'))
        chain = sc.certs_of(got.get('CertificateChain'))
        return sc.finish(self.ctx, r, certs, chain, who='AWS Private CA',
                         key_pem=r.key_pem if r is not req else None,
                         info={'certificate_arn': cert_arn})

    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        arn, _region = self._arn()
        serial = sc.serial_hex(cert_pem, ':').lower()
        self._ok('RevokeCertificate', {'CertificateAuthorityArn': arn, 'CertificateSerial': serial,
                                       'RevocationReason': REASONS.get(sc.reason_code(reason),
                                                                       'UNSPECIFIED')})
        return 'AWS Private CA revoked serial %s' % serial
