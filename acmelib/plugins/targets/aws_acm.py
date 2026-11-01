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


class AwsAcmTarget(CloudTarget):
    kind = 'aws_acm'
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
        if not arn:
            try:
                arn = text(self.ctx.kv_get(self.kv_arn(bundle, options)) or '')
            except Exception:                           # noqa: BLE001
                arn = ''
        if arn and not as_bool(options.get('force')):
            try:
                d = self.call('DescribeCertificate', {'CertificateArn': arn},
                              what='reading %s' % arn)
                serial = norm_fp((d.get('Certificate') or {}).get('Serial'))
                if serial and serial.lstrip('0') == norm_fp(bundle.serial).lstrip('0'):
                    self.remember(bundle, options, arn=arn)
                    return self.same(bundle, 'in %s' % arn)
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
