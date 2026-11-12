# -*- coding: utf-8 -*-
"""
AWS Certificate Manager: the certificate imported (ImportCertificate) and on
each renewal re-imported into the same ARN, so the load balancers (ALB, NLB),
CloudFront distributions and API Gateway domains using it take the new one
by themselves. Signed with Signature Version 4 (challenges/route53.py).

    POST https://acm.<region>.amazonaws.com/
         X-Amz-Target: CertificateManager.ImportCertificate   (JSON 1.1)
         {Certificate, PrivateKey, CertificateChain (base64 of the PEM),
          CertificateArn (re-import), Tags (only on the first import)}
    CertificateManager.DescribeCertificate  {CertificateArn} -> Certificate.Serial
    CertificateManager.ListCertificates     (test)

Sources:
    https://docs.aws.amazon.com/acm/latest/APIReference/API_ImportCertificate.html
    https://docs.aws.amazon.com/acm/latest/userguide/import-reimport.html
    https://docs.aws.amazon.com/acm/latest/APIReference/API_DescribeCertificate.html
CloudFront takes only certificates in us-east-1.
Checked against api-docs/aws_acm/notes.md and service-2.json: on a re-import
"the key type and size cannot be changed", so a certificate of another key
type than the one in the ARN is refused before ImportCertificate, in words.
"""
from __future__ import annotations

import base64
import json
import re

from acmelib.plugins.targets._common import (
    PluginError, field, lines, as_bool, label_of, norm_fp, text, verify_fields)
from acmelib.plugins.targets._cloud import CloudTarget, cloud_fields, sigv4


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


ACM_CURVES = {'ec-256': 'EC_prime256v1', 'ec-384': 'EC_secp384r1', 'ec-521': 'EC_secp521r1'}


def acm_key_type(bundle):
    """ACM's KeyAlgorithm of the bundle's key (RSA_2048, EC_prime256v1, ...); '' unknown."""
    kt = text(getattr(bundle, 'key_type', '')).lower()
    if kt.startswith('rsa-') and kt[4:].isdigit():
        return 'RSA_' + kt[4:]
    return ACM_CURVES.get(kt, '')


class AwsAcmTarget(CloudTarget):
    kind = 'aws_acm'
    discovery = False       # nothing to find: its fields are the sign-in and the region
    title = 'AWS Certificate Manager (ACM)'
    vendor = 'Amazon'
    description = ('Imports the certificate into ACM and re-imports each renewal into the same '
                   'ARN, so load balancers, CloudFront and API Gateway take it by themselves.')
    doc = 'targets.md'
    fields = [
        field('access_key_id', 'Access key ID', 'text', required=True, placeholder='AKIA...',
              help='An IAM user with acm:ImportCertificate, acm:DescribeCertificate, '
                   'acm:ListCertificates and acm:AddTagsToCertificate.'),
        field('secret_access_key', 'Secret access key', 'secret', required=True),
        field('session_token', 'Session token', 'secret', advanced=True,
              help='Only for temporary credentials (STS).'),
        field('region', 'Region', 'text', required=True, default='eu-central-1',
              help='The region of the load balancers; us-east-1 for CloudFront.'),
    ] + cloud_fields()
    deploy_fields = [
        field('certificate_arn', 'Certificate ARN', 'text',
              placeholder='arn:aws:acm:eu-central-1:123456789012:certificate/…',
              help='Re-import into this certificate. Empty: imported once as a new one, whose '
                   'ARN acme keeps and re-imports into from then on.'),
        field('tags', 'Tags', 'list', advanced=True, placeholder='Owner=it\nApp=web',
              help='key=value, one a line; set on the first import only (ACM does not take '
                   'tags on a re-import)'),
    ] + verify_fields()

    _amz_date = None            # the tests fix the time

    def endpoint(self):
        region = text(self.c('region') or 'us-east-1').strip()
        if not re.match(r'^[a-z]{2}(-[a-z]+)+-\d$', region):
            raise PluginError('"%s" is not an AWS region' % region, retry=False)
        dom = 'amazonaws.com.cn' if region.startswith('cn-') else 'amazonaws.com'
        return region, 'https://acm.%s.%s/' % (region, dom)

    def call(self, action, payload, what=None):
        region, url = self.endpoint()
        body = json.dumps(payload).encode()
        h = sigv4('POST', url, {'Accept': 'application/json',
                                'Content-Type': 'application/x-amz-json-1.1',
                                'X-Amz-Target': 'CertificateManager.%s' % action},
                  body, text(self.c('access_key_id')), text(self.c('secret_access_key')),
                  region, 'acm', amz_date=self._amz_date,
                  session_token=self.c('session_token') or None)
        st, hd, d = self.req('POST', url, body, h, ok=range(0, 600), auth=False,
                             what=what or action)
        if st >= 300:
            kind = text((d or {}).get('__type', '') if isinstance(d, dict) else '')
            kind = kind.split('#')[-1]
            msg = text((d or {}).get('message') or (d or {}).get('Message') or ''
                       if isinstance(d, dict) else d)[:300]
            raise PluginError('%s: ACM said %d %s%s' % (what or action, st, kind,
                                                        (' - ' + msg) if msg else ''),
                              detail=text(d)[:4000],
                              retry=st >= 500 or kind in ('ThrottlingException',
                                                          'RequestInProgressException'))
        return d if isinstance(d, dict) else {}

    def kv_arn(self, bundle, options):
        return 'aws-acm:%s:%s:%s' % (self.c('region'), self.c('access_key_id'),
                                     label_of(bundle, options))

    def test(self):
        d = self.call('ListCertificates', {'MaxItems': 100}, what='signing in')
        n = len(d.get('CertificateSummaryList') or [])
        return 'signed in to ACM in %s, %d%s certificate%s' % (
            self.endpoint()[0], n, '+' if d.get('NextToken') else '', '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        arn = text(options.get('certificate_arn')).strip()
        kept_typed = False
        if not arn:
            # one ARN per key type (1.0.88: the EC and the RSA half of a dual certificate in one
            # region found each other's ARN, and the second was refused); the one kept before
            # by the name alone is taken when it is of this key type
            try:
                arn = text(self.ctx.kv_get(self.kv_arn(bundle, options) + ':' +
                                           acm_key_type(bundle)) or '')
                kept_typed = bool(arn)
                if not arn:
                    arn = text(self.ctx.kv_get(self.kv_arn(bundle, options)) or '')
            except Exception:                           # noqa: BLE001
                arn = ''
        if arn:
            try:
                d = self.call('DescribeCertificate', {'CertificateArn': arn},
                              what='reading %s' % arn)
                info = d.get('Certificate') or {}
                serial = norm_fp(info.get('Serial'))
                if serial and serial.lstrip('0') == norm_fp(bundle.serial).lstrip('0') and \
                        not as_bool(options.get('force')):
                    self.remember(bundle, options, arn=arn)
                    return self.same(bundle, 'in %s' % arn)
                have, want = text(info.get('KeyAlgorithm')), acm_key_type(bundle)
                half = str(options.get('variant') or '').strip().lower() in ('ec', 'rsa', 'alt')
                if have and want and have != want and half and \
                        not options.get('certificate_arn') and not kept_typed:
                    # the other half's, kept by the name alone: this one gets its own
                    self.ctx.step('%s holds the %s certificate: this one (%s) is imported as '
                                  'one of its own' % (arn, have, want))
                    arn = ''
                elif have and want and have != want:
                    raise PluginError(
                        'ACM cannot change the key type on a re-import (%s has %s, this '
                        'certificate %s): keep the key type, or import it as a new '
                        'certificate (another Certificate ARN, or delete %s first) and '
                        'point the services using it at the new one%s'
                        % (arn, have, want, arn, (' - used by %s' % ', '.join(
                            info.get('InUseBy') or [])) if info.get('InUseBy') else ''),
                        retry=False)
            except PluginError as e:
                if 'ResourceNotFound' not in str(e):
                    raise
                if options.get('certificate_arn'):
                    raise PluginError('there is no certificate %s in ACM' % arn, retry=False)
                self.ctx.step('the certificate imported before is gone: importing it anew',
                              'warn')
                arn = ''
        body = {'Certificate': b64(bundle.as_format('cert-pem')),
                'PrivateKey': b64(bundle.as_format('key-pem'))}
        chain = bundle.as_format('chain-pem')
        if chain and chain.strip():
            body['CertificateChain'] = b64(chain)
        if arn:
            body['CertificateArn'] = arn
        else:
            tags = []
            for t in lines(options.get('tags')):
                k, _, v = t.partition('=')
                if k.strip():
                    tags.append({'Key': k.strip(), 'Value': v.strip()})
            if tags:
                body['Tags'] = tags
        d = self.call('ImportCertificate', body,
                      what='re-importing into %s' % arn if arn else 'importing')
        new = d.get('CertificateArn') or arn
        if not new:
            raise PluginError('ACM gave no ARN for the imported certificate', detail=text(d))
        try:
            self.ctx.kv_set(self.kv_arn(bundle, options) + ':' + acm_key_type(bundle), new)
            if not text(self.ctx.kv_get(self.kv_arn(bundle, options)) or ''):
                self.ctx.kv_set(self.kv_arn(bundle, options), new)
        except Exception as e:                          # noqa: BLE001
            self.ctx.debug('cannot keep the ARN: %s' % e)
        self.ctx.step('%s %s' % ('re-imported into' if arn else 'imported as', new), 'ok')
        self.remember(bundle, options, arn=new)
        return '%s %s' % ('re-imported into' if arn else 'imported as', new)

    def remove(self, bundle, options):
        arn = text((options or {}).get('certificate_arn')).strip() or \
            text(self.ctx.kv_get(self.kv_arn(bundle, options)) or '')
        if arn:
            self.call('DeleteCertificate', {'CertificateArn': arn}, what='deleting %s' % arn)
