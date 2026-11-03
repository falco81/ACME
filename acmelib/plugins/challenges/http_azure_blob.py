# -*- coding: utf-8 -*-
"""HTTP-01 by uploading the token file to Azure Blob Storage - a static
website ($web container) or a container behind Azure Front Door / CDN:

    PUT    https://{account}.blob.core.windows.net/{container}/{folder}.well-known/acme-challenge/{token}
           x-ms-blob-type: BlockBlob
    GET    the same (read back by test())
    DELETE the same (202; 404 when it is not there)
    GET    https://{account}.blob.core.windows.net/{container}?restype=container   (the guide)

Signed in with a SAS token (its query added to each address; it needs
create, write, read and delete on the container) or the account's Shared
Key: Authorization: SharedKey ACCOUNT:base64(HMAC-SHA256(key,
StringToSign)), StringToSign = VERB, Content-Encoding, Content-Language,
Content-Length ("" for 0), Content-MD5, Content-Type, Date,
If-Modified-Since, If-Match, If-None-Match, If-Unmodified-Since, Range -
each a line - then the x-ms- headers (lower case, sorted, "name:value"
lines), then /ACCOUNT/PATH and each query parameter as "\\nname:value"
(sorted, lower-case names).

Sources: https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
and .../put-blob, .../delete-blob - not reachable from where this was
written; written from them as known (the test checks the string to sign
against the rules above, Microsoft publishes no full worked example).
"""
from __future__ import annotations

import base64
import binascii
import email.utils
import hashlib
import hmac
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import http_call, said_error
from acmelib.plugins.challenges._upload import CHECK_FIELDS, UploadHttp

VERSION = '2021-08-06'


def string_to_sign(method, url, headers, account):
    h = {k.lower(): str(v).strip() for k, v in headers.items()}
    length = h.get('content-length', '')
    if length == '0':
        length = ''
    lines = [method.upper(), h.get('content-encoding', ''), h.get('content-language', ''),
             length, h.get('content-md5', ''), h.get('content-type', ''), h.get('date', ''),
             h.get('if-modified-since', ''), h.get('if-match', ''), h.get('if-none-match', ''),
             h.get('if-unmodified-since', ''), h.get('range', '')]
    canon_h = ''.join('%s:%s\n' % (k, h[k]) for k in sorted(h) if k.startswith('x-ms-'))
    u = urllib.parse.urlsplit(url)
    res = '/%s%s' % (account, u.path or '/')
    q = {}
    for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True):
        q.setdefault(k.lower(), []).append(v)
    for k in sorted(q):
        res += '\n%s:%s' % (k, ','.join(sorted(q[k])))
    return '\n'.join(lines) + '\n' + canon_h + res


def shared_key(method, url, headers, account, key_b64):
    try:
        key = base64.b64decode(key_b64)
    except (binascii.Error, ValueError):
        raise PluginError('the account key is not base64 (Storage account → Access keys)',
                          retry=False)
    sts = string_to_sign(method, url, headers, account)
    sig = base64.b64encode(hmac.new(key, sts.encode('utf-8'), hashlib.sha256).digest()).decode()
    return 'SharedKey %s:%s' % (account, sig)


class HttpAzureBlob(UploadHttp):
    kind = 'http_azure_blob'
    discovery = False               # discovery: nothing to read from an account
    title = 'HTTP-01 uploaded to Azure Blob Storage'
    vendor = 'HTTP'
    description = ('The token file is uploaded to an Azure Storage container that serves the '
                   'name - a static website ($web) or a CDN in front of it. Not for wildcards.')
    fields = [
        field('account', 'Storage account', 'text', required=True, placeholder='mysite'),
        field('container', 'Container', 'text', default='$web',
              help='$web for a static website.'),
        field('auth', 'Signs in with', 'select', default='sas',
              options=[['sas', 'a SAS token'], ['key', 'the account key (Shared Key)']]),
        field('sas', 'SAS token', 'secret', show_if={'auth': ['sas']},
              help='Storage account → Shared access signature (or the container\'s): Blob, '
                   'Object, permissions Read, Write, Create, Delete; the part after "?".'),
        field('key', 'Account key', 'secret', show_if={'auth': ['key']},
              help='Storage account → Access keys: key1 or key2 (base64).'),
        field('folder', 'Folder in the container', 'text', default='',
              help='Where the site\'s root is in the container; empty: its root.'),
        field('endpoint', 'Blob endpoint', 'text', default='', advanced=True,
              placeholder='https://mysite.blob.core.windows.net',
              help='Empty: https://ACCOUNT.blob.core.windows.net (another cloud: its own).'),
    ] + CHECK_FIELDS

    @property
    def where_words(self):
        return 'azure://%s/%s/%s' % (self.c('account', '?'), self.c('container', '$web'),
                                     self.prefix())

    def _url(self, key=None, query=None):
        acct = str(self.c('account', '') or '').strip()
        cont = str(self.c('container', '$web') or '$web').strip()
        if not acct.isalnum() or not all(c.isalnum() or c in '-$' for c in cont):
            raise PluginError('"%s/%s" is not a storage account and container' % (acct, cont),
                              retry=False)
        ep = str(self.c('endpoint', '') or '').strip().rstrip('/') or \
            'https://%s.blob.core.windows.net' % acct
        url = '%s/%s' % (ep, cont)
        if key is not None:
            url += '/' + urllib.parse.quote(key, safe='/-_.~')
        q = dict(query or {})
        qs = urllib.parse.urlencode(q)
        if self.c('auth', 'sas') == 'sas':
            sas = str(self.c('sas', '') or '').strip().lstrip('?')
            qs = '&'.join(x for x in (qs, sas) if x)
        return url + ('?' + qs if qs else '')

    def _call(self, method, key=None, body=None, ok=(200, 201, 202), query=None, headers=None):
        url = self._url(key, query)
        h = {'x-ms-date': email.utils.formatdate(usegmt=True), 'x-ms-version': VERSION,
             'User-Agent': 'acme-challenge'}
        h.update(headers or {})
        if body is not None:
            h['Content-Length'] = str(len(body))
        if self.c('auth', 'sas') == 'key':
            h['Authorization'] = shared_key(method, url, {k: v for k, v in h.items()
                                                          if k != 'User-Agent'},
                                            str(self.c('account', '')), str(self.c('key', '')))
        st, _rh, got = http_call(self.ctx, method, url, body, h, who='Azure Storage')
        if st not in ok:
            raise said_error('Azure Storage', st, None, got)
        return st, got

    def put_object(self, key, data):
        self._call('PUT', key, data, headers={'x-ms-blob-type': 'BlockBlob',
                                              'Content-Type': 'text/plain'})

    def drop_object(self, key):
        self._call('DELETE', key, ok=(200, 202, 204, 404))

    def get_object(self, key):
        return self._call('GET', key)[1] or b''

    def access(self):
        st, _got = self._call('GET', None, query={'restype': 'container'}, ok=(200, 403, 404))
        if st == 404:
            raise PluginError('there is no container %s in %s' % (self.c('container', '$web'),
                                                                   self.c('account')),
                              retry=False)
        if st == 403:
            return 'Azure Storage answers; these credentials may not read the container\'s ' \
                   'properties (writing may still be allowed - a dry run tells)'
        return 'the container %s of %s is there' % (self.c('container', '$web'), self.c('account'))
