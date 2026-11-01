# -*- coding: utf-8 -*-
"""HTTP-01 by uploading the token file to an S3 bucket (Amazon S3, or one
that speaks its API: MinIO, Ceph, Wasabi, Cloudflare R2, Backblaze B2,
Hetzner, Exoscale SOS, OVH, ...) - for a static site or a CDN served from
the bucket. Each request signed with AWS Signature Version 4 (the one of
route53.py), the payload's SHA-256 in x-amz-content-sha256:

    PUT    https://{bucket}.s3.{region}.amazonaws.com/{folder}.well-known/acme-challenge/{token}
    GET    the same (read back by test())
    DELETE the same (204, also when it is not there)
    HEAD   https://{bucket}.s3.{region}.amazonaws.com/   (the guide: may the key see the bucket)

Path style (https://{endpoint}/{bucket}/{key}) for the S3-compatible ones
that want it. The object is public only if the bucket (or CDN) serves it so:
a bucket policy for .well-known/acme-challenge/*, or the ACL set below.

Sources: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html,
.../API_DeleteObject.html, .../sig-v4-header-based-auth.html - not
reachable from where this was written; written from them as known, the
signature the same code that signs Route 53 (its test vectors in
test/test_dns_providers_more.py).
"""
from __future__ import annotations

import hashlib
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import as_bool, http_call, said_error
from acmelib.plugins.challenges._upload import CHECK_FIELDS, UploadHttp
from acmelib.plugins.challenges.route53 import sigv4


class HttpS3(UploadHttp):
    kind = 'http_s3'
    title = 'HTTP-01 uploaded to an S3 bucket'
    vendor = 'HTTP'
    description = ('The token file is uploaded to an S3 (or S3-compatible) bucket that serves '
                   'the name - a static site or a CDN in front of it. Not for wildcards.')
    fields = [
        field('bucket', 'Bucket', 'text', required=True, placeholder='www-example-com'),
        field('region', 'Region', 'text', default='us-east-1',
              help='The bucket\'s region ("auto" for Cloudflare R2).'),
        field('access_key_id', 'Access key ID', 'text', required=True,
              help='An IAM user (or the S3 service\'s key) allowed s3:PutObject, s3:GetObject '
                   'and s3:DeleteObject on BUCKET/FOLDER.well-known/acme-challenge/*.'),
        field('secret_access_key', 'Secret access key', 'secret', required=True),
        field('session_token', 'Session token', 'secret', advanced=True,
              help='Only for temporary credentials (STS).'),
        field('folder', 'Folder in the bucket', 'text', default='',
              help='Where the site\'s root is in the bucket; empty: the bucket\'s root.'),
        field('endpoint', 'Endpoint', 'text', default='', advanced=True,
              placeholder='https://s3.eu-central-003.backblazeb2.com',
              help='Empty: Amazon S3 of the region. For another service its S3 address.'),
        field('path_style', 'Path style (endpoint/bucket/key)', 'bool', default=False,
              advanced=True, help='For S3-compatible services without bucket names in the host '
                                  '(MinIO, Ceph, most self-hosted).'),
        field('acl', 'ACL of the file', 'select', default='', advanced=True,
              options=[['', 'none (the bucket policy decides)'],
                       ['public-read', 'public-read']]),
    ] + CHECK_FIELDS

    @property
    def where_words(self):
        return 's3://%s/%s' % (self.c('bucket', '?'), self.prefix())

    def _url(self, key=''):
        bucket = str(self.c('bucket', '') or '').strip()
        if not bucket or not all(c.isalnum() or c in '.-_' for c in bucket):
            raise PluginError('"%s" is not a bucket' % bucket, retry=False)
        region = str(self.c('region', 'us-east-1') or 'us-east-1').strip()
        ep = str(self.c('endpoint', '') or '').strip().rstrip('/')
        k = urllib.parse.quote(key, safe='/-_.~')
        if as_bool(self.c('path_style', False)):
            base = ep or 'https://s3.%s.amazonaws.com' % region
            return '%s/%s/%s' % (base, bucket, k)
        if ep:
            u = urllib.parse.urlsplit(ep)
            return '%s://%s.%s/%s' % (u.scheme or 'https', bucket, u.netloc or u.path, k)
        return 'https://%s.s3.%s.amazonaws.com/%s' % (bucket, region, k)

    def _call(self, method, key='', body=b'', ok=(200, 204), headers=None):
        url = self._url(key)
        h = dict(headers or {})
        h['x-amz-content-sha256'] = hashlib.sha256(body or b'').hexdigest()
        h = sigv4(method, url, h, body or b'', str(self.c('access_key_id', '')),
                  str(self.c('secret_access_key', '')),
                  str(self.c('region', 'us-east-1') or 'us-east-1'), 's3',
                  session_token=self.c('session_token') or None)
        h['User-Agent'] = 'acme-challenge'
        st, _rh, got = http_call(self.ctx, method, url, body if method == 'PUT' else None, h,
                                 who='S3')
        if st not in ok:
            raise said_error('S3', st, None, got)
        return st, got

    def put_object(self, key, data):
        h = {'Content-Type': 'text/plain'}
        if self.c('acl'):
            h['x-amz-acl'] = str(self.c('acl'))
        self._call('PUT', key, data, headers=h)

    def drop_object(self, key):
        self._call('DELETE', key, ok=(200, 204, 404))

    def get_object(self, key):
        return self._call('GET', key)[1] or b''

    def access(self):
        st, _got = self._call('HEAD', '', ok=(200, 403, 404))
        if st == 404:
            raise PluginError('there is no bucket %s there' % self.c('bucket'), retry=False)
        if st == 403:
            return 'S3 answers; the key may not list the bucket %s (writing may still be ' \
                   'allowed - a dry run tells)' % self.c('bucket')
        return 'the key sees the bucket %s' % self.c('bucket')
