# -*- coding: utf-8 -*-
"""HTTP-01 by uploading the token file to a WebDAV folder that the site is
served from (Nextcloud, a hosting's WebDAV access, Apache mod_dav, IIS):

    MKCOL  {base}.well-known/  and  {base}.well-known/acme-challenge/   (405: there already)
    PUT    {base}.well-known/acme-challenge/{token}
    GET    the same (read back by test())
    DELETE the same (404: gone already)
    PROPFIND {base}  Depth: 0                                           (the guide: may it see the folder)

Basic authentication (over HTTPS). Sources: RFC 4918 (HTTP Extensions for
WebDAV: MKCOL, PROPFIND, the status codes) - the calls are plain RFC 4918.
"""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import as_bool, http_call, said_error
from acmelib.plugins.challenges._records import basic
from acmelib.plugins.challenges._upload import CHECK_FIELDS, UploadHttp, prefix_of


class HttpWebdav(UploadHttp):
    kind = 'http_webdav'
    title = 'HTTP-01 uploaded over WebDAV'
    vendor = 'HTTP'
    description = ('The token file is uploaded over WebDAV into the folder the site of the '
                   'name is served from. Not for wildcards.')
    fields = [
        field('url', 'WebDAV address of the web root', 'text', required=True,
              placeholder='https://webdav.example.com/www/',
              help='The WebDAV address of the folder http://NAME/ is served from; '
                   '.well-known/acme-challenge/ is made in it.'),
        field('user', 'User', 'text', default=''),
        field('password', 'Password', 'secret'),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + CHECK_FIELDS

    @property
    def where_words(self):
        return str(self.c('url', '') or '?')

    def prefix(self):
        return ''

    def _base(self):
        u = str(self.c('url', '') or '').strip()
        if not u.startswith(('https://', 'http://')):
            raise PluginError('"%s" is not a WebDAV address (https://...)' % u, retry=False)
        return u.rstrip('/') + '/'

    def _call(self, method, rel='', body=None, ok=(200, 201, 204), headers=None):
        h = {'User-Agent': 'acme-challenge'}
        if self.c('user'):
            h['Authorization'] = basic(self.c('user', ''), self.c('password', ''))
        h.update(headers or {})
        if rel:
            prefix_of(rel)                      # no ".." in it
        url = self._base() + rel
        st, _rh, got = http_call(self.ctx, method, url, body, h, who='WebDAV',
                                 verify=as_bool(self.c('verify_tls', True)))
        if st not in ok:
            raise said_error('WebDAV', st, None, got)
        return st, got

    def put_object(self, key, data):
        for folder in ('.well-known/', '.well-known/acme-challenge/'):
            self._call('MKCOL', folder, ok=(200, 201, 204, 301, 405))
        self._call('PUT', key, data, headers={'Content-Type': 'text/plain'})

    def drop_object(self, key):
        self._call('DELETE', key, ok=(200, 204, 404))

    def get_object(self, key):
        return self._call('GET', key)[1] or b''

    def access(self):
        st, _got = self._call('PROPFIND', '', b'', ok=(200, 207, 401, 403, 404, 405),
                              headers={'Depth': '0'})
        if st in (401, 403):
            raise PluginError('the WebDAV server said %s - the user or password is wrong, or '
                              'may not see the folder' % st, retry=False)
        if st == 404:
            raise PluginError('there is no folder %s' % self._base(), retry=False)
        return 'the WebDAV folder %s is there' % self._base()
