# -*- coding: utf-8 -*-
"""What the HTTP-01 upload modules share (the name starts with "_": the
registry does not take it for a module): the token file put where a web
site is served from - an FTP or SFTP account of a web hosting, an S3 or
Azure bucket behind a static site or CDN, a WebDAV folder - instead of onto
a server acme signs in to with a shell (http_ssh).

    UploadHttp      present() puts .well-known/acme-challenge/TOKEN under the
                    folder set, ready() fetches http://NAME/... as the CA will,
                    cleanup() takes it away; test() puts a probe, reads it back
                    and takes it away; guide() checks access (read only), the
                    name's address and that the name answers HTTP.

A module writes put_object(key, data), drop_object(key), get_object(key)
(None when it cannot read back) and access() - words, read only.
"""
from __future__ import annotations

import binascii
import os
import posixpath

from acmelib.plugins.base import PluginError, field, guide_of, guide_step
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import HttpChallenge

WELL_KNOWN = '.well-known/acme-challenge/'

CHECK_FIELDS = [
    field('check', 'Check before the CA is asked', 'select', default='name',
          options=[['name', 'http://NAME/ as the CA will (needs this machine to reach it)'],
                   ['url', 'the address below (the bucket\'s or the site\'s own)'],
                   ['none', 'no check']],
          help='The token is fetched over HTTP and compared before the CA is told to look.'),
    field('check_url', 'Address the folder is served at', 'text', default='', advanced=True,
          placeholder='http://my-bucket.s3-website.eu-central-1.amazonaws.com/',
          help='For "the address below": where the uploaded folder can be fetched from '
               '(.well-known/acme-challenge/TOKEN is added).'),
]


def prefix_of(v):
    """A folder prefix: no leading "/", one trailing "/" (or "")."""
    p = posixpath.normpath('/' + str(v or '').strip()).lstrip('/')
    if p in ('', '.'):
        return ''
    if '..' in p.split('/') or any(c in p for c in '\n\r\0\\'):
        raise PluginError('the folder %r will not be written to' % v, retry=False)
    return p + '/'


class UploadHttp(HttpChallenge):
    """The base of the HTTP-01 modules that upload the token file."""
    where_words = 'the web space'

    # -- what a module writes ----------------------------------------------------
    def put_object(self, key, data):
        raise NotImplementedError

    def drop_object(self, key):
        """Quiet when it is gone already."""
        raise NotImplementedError

    def get_object(self, key):
        return None

    def access(self):
        """Signs in and looks, changing nothing: words, or PluginError."""
        raise NotImplementedError

    # -- where -------------------------------------------------------------------------
    def prefix(self):
        return prefix_of(self.c('folder', ''))

    def key_of(self, token):
        return self.prefix() + WELL_KNOWN + token

    def check_base(self, name):
        if self.c('check', 'name') == 'url' and str(self.c('check_url', '') or '').strip():
            return str(self.c('check_url')).strip().rstrip('/') + '/'
        return 'http://%s/' % D.norm(name)

    # -- a commercial CA's DCV file, anywhere under /.well-known/ ---------------------
    proofs = ('http-file-any',)

    def place_file(self, name, path, data):
        key = self.prefix() + path.lstrip('/')
        self.put_object(key, data)
        return {'key': key}

    def unplace_file(self, handle):
        key = ((handle or {}).get('h') or {}).get('key')
        if key and key.startswith(self.prefix() + '.well-known/'):
            try:
                self.drop_object(key)
            except PluginError as e:
                self.ctx.step('%s could not be taken away from %s: %s' % (key, self.where_words, e),
                              'warn')

    def placed_ready(self, handle):
        h = handle or {}
        if self.c('check', 'name') == 'none':
            return True
        ok, words = self.fetch(self.check_base(h.get('name')) + str(h.get('path') or '').lstrip('/'),
                               str(h.get('content') or '').strip())
        self.ctx.step(words, 'ok' if ok else 'info')
        return ok

    # -- the contract ---------------------------------------------------------------
    def present(self, name, token, key_authorization, txt_value):
        n = self.check_name(name)
        self.check_token(token)
        key = self.key_of(token)
        self.put_object(key, key_authorization.encode('ascii'))
        self.ctx.step('%s written to %s' % (key, self.where_words))
        return {'token': token, 'ka': key_authorization, 'name': n, 'key': key}

    def ready(self, name, handle):
        h = handle or {}
        if self.c('check', 'name') == 'none':
            return True
        url = self.check_base(h.get('name') or name) + WELL_KNOWN + str(h.get('token'))
        ok, words = self.fetch(url, h.get('ka'))
        self.ctx.step(words, 'ok' if ok else 'info')
        return ok

    def cleanup(self, name, handle):
        key = (handle or {}).get('key')
        if not key or not key.startswith(self.prefix() + WELL_KNOWN):
            return
        try:
            self.drop_object(key)
        except PluginError as e:
            self.ctx.step('%s could not be taken away from %s: %s' % (key, self.where_words, e),
                          'warn')

    def test(self):
        token = 'acme-probe-' + binascii.hexlify(os.urandom(8)).decode()
        data = ('acme probe ' + binascii.hexlify(os.urandom(8)).decode()).encode()
        key = self.key_of(token)
        self.put_object(key, data)
        try:
            back = self.get_object(key)
            if back is not None and bytes(back).strip() != data:
                raise PluginError('wrote a probe file but read back something else')
        finally:
            self.drop_object(key)
        return '%s: a probe file written to %s%s and taken away' % (
            self.where_words, key, ', read back' if back is not None else '')

    # -- what a person is told ---------------------------------------------------------
    def guide(self, name):
        bad = self.guide_wildcard(name)
        if bad:
            return guide_of(bad)
        n = D.norm(name)
        where = self.where_words
        steps = []
        try:
            said = self.access()
            steps.append(guide_step('access', 'acme can reach and sign in to %s' % where,
                                    where=where, done=True, said=str(said or '')[:300]))
        except Exception as e:                          # noqa: BLE001
            steps.append(guide_step('access', 'acme can reach and sign in to %s' % where,
                                    where=where, done=False, said=str(e) or type(e).__name__,
                                    fix='Correct the settings of the validation (address, '
                                        'credentials, folder), then check again'))
        got = self.lookup(n)
        steps.append(guide_step(
            'address', 'The name points at the site the files are uploaded to',
            where='your DNS at %s' % D.registrable(n), done=bool(got) or False,
            said=('%s points at %s' % (n, ', '.join(got))) if got else
                 '%s has no A or AAAA record' % n,
            fix='Point %s at the web hosting, CDN or bucket website that serves %s' % (n, where)))
        url = self.check_base(n) + WELL_KNOWN + 'acme-guide-' + binascii.hexlify(
            os.urandom(6)).decode()
        try:
            st, _h, _b = self.ctx.http('GET', url, headers={'User-Agent': 'acme-guide'},
                                       timeout=10, verify=False, proxy=False)
            steps.append(guide_step('web', '%s answers HTTP' % self.check_base(n), where=n,
                                    done=True, blocking=False,
                                    said='it answers (%s for a file that is not there)' % st))
        except Exception as e:                          # noqa: BLE001
            steps.append(guide_step('web', '%s answers HTTP' % self.check_base(n), where=n,
                                    done=False, blocking=False, said=str(e) or type(e).__name__,
                                    fix='This machine may not reach the name (the CA asks from '
                                        'the internet); a dry run tells more'))
        steps.append(guide_step(
            'try', 'A dry run shows whether the uploaded file is what http://%s/ serves' % n,
            where='acme', done=None, blocking=False,
            said='only a real file shows that the folder set is the one the site serves',
            fix='Run a dry run: a test file is uploaded, fetched and taken away'))
        return guide_of(steps)

    def seen_outside(self, name, handle):
        h = handle or {}
        token, ka = h.get('token'), h.get('ka')
        out = HttpChallenge.seen_outside(self, name, handle)
        if token and ka and self.c('check', 'name') == 'url':
            url = self.check_base(name) + WELL_KNOWN + token
            ok, words = self.fetch(url, ka)
            out.append(guide_step('by_address', 'The test file is served at %s' % url,
                                  where=url, done=ok, said=words,
                                  fix='The address set is not where the folder is served'))
        return out
