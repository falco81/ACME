# -*- coding: utf-8 -*-
"""HTTP-01 by uploading the token file to a web hosting over FTP, FTPS or
SFTP - the account most hostings give, without a shell:

    FTP / FTPS    Python's ftplib (FTPS: explicit TLS, "AUTH TLS", the data
                  channel protected too - PROT P); passive mode. The folders
                  .well-known/acme-challenge/ are made (MKD) when missing.
                  Straight from this machine, not through the HTTP proxy.
    SFTP          through acme's SSH (ctx.ssh): the file put with scp (the
                  SFTP protocol with today's OpenSSH) and removed with
                  "rm -f" where the account has a shell. An SFTP-only account
                  cannot run rm: the file is then emptied instead (a file of
                  nothing is harmless), and the job says so.

FTP sends the password in the clear: FTPS or SFTP wherever the hosting has
it. Sources: RFC 959 (FTP), RFC 4217 (FTP over TLS), Python's ftplib
(https://docs.python.org/3/library/ftplib.html).
"""
from __future__ import annotations

import ftplib
import io
import posixpath
import ssl

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import as_bool, shq, ssh_conn, ssh_fields
from acmelib.plugins.challenges._upload import CHECK_FIELDS, UploadHttp


class HttpFtp(UploadHttp):
    kind = 'http_ftp'
    discovery = False               # discovery: nothing to read from an account
    title = 'HTTP-01 uploaded over FTP, FTPS or SFTP'
    vendor = 'HTTP'
    description = ('The token file is uploaded over FTP, FTPS or SFTP into the web space of a '
                   'hosting that serves the name; the CA fetches it from there. Not for '
                   'wildcards.')
    fields = [
        field('protocol', 'Protocol', 'select', default='ftps',
              options=[['ftps', 'FTPS (FTP with explicit TLS)'], ['ftp', 'FTP (no encryption)'],
                       ['sftp', 'SFTP (over SSH)']]),
        field('host', 'Server', 'text', required=True, placeholder='ftp.example.com',
              help='host or host:port (21 for FTP and FTPS, 22 for SFTP).'),
        field('ftp_user', 'User', 'text', default='', show_if={'protocol': ['ftp', 'ftps']}),
        field('ftp_password', 'Password', 'secret', show_if={'protocol': ['ftp', 'ftps']}),
        field('folder', 'Web root of the site', 'text', default='/www',
              placeholder='/www/example.com',
              help='The folder http://NAME/ is served from, as the account sees it (often '
                   '/www, /public_html, /httpdocs or /web). .well-known/acme-challenge/ is '
                   'made in it.'),
        field('verify_tls', 'Check the server\'s certificate (FTPS)', 'bool', default=True,
              advanced=True, show_if={'protocol': ['ftps']}),
        field('ftp_timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ] + [dict(f, show_if={'protocol': ['sftp']}, required=False) for f in ssh_fields(user='')
         if f['key'] not in ('timeout', 'password')] + [
        field('password', 'Password', 'secret', show_if={'protocol': ['sftp']}),
    ] + CHECK_FIELDS

    @property
    def where_words(self):
        return '%s://%s' % (self.c('protocol', 'ftps'), self.c('host', '?'))

    def _hostport(self):
        proto = self.c('protocol', 'ftps')
        host, port = D.split_hostport(str(self.c('host', '') or '').strip(),
                                      22 if proto == 'sftp' else 21)
        if not host or not all(c.isalnum() or c in '.-:_' for c in host):
            raise PluginError('"%s" is not a server' % self.c('host', ''), retry=False)
        return host, int(port)

    def path_of(self, key):
        return '/' + key if not key.startswith('/') else key

    # -- FTP / FTPS --------------------------------------------------------------------
    FTP = ftplib.FTP                    # a test puts its own here
    FTP_TLS = ftplib.FTP_TLS

    def _ftp(self):
        host, port = self._hostport()
        timeout = float(self.c('ftp_timeout', 30) or 30)
        try:
            if self.c('protocol', 'ftps') == 'ftps':
                ctx = ssl.create_default_context()
                if not as_bool(self.c('verify_tls', True)):
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                f = self.FTP_TLS(context=ctx, timeout=timeout)
                f.connect(host, port)
                f.login(str(self.c('ftp_user', '') or ''), str(self.c('ftp_password', '') or ''))
                f.prot_p()
            else:
                f = self.FTP(timeout=timeout)
                f.connect(host, port)
                f.login(str(self.c('ftp_user', '') or ''), str(self.c('ftp_password', '') or ''))
            f.set_pasv(True)
            return f
        except ftplib.error_perm as e:
            raise PluginError('%s did not let %s in: %s' % (host, self.c('ftp_user', ''), e),
                              retry=False)
        except (OSError, EOFError, ftplib.Error) as e:
            raise PluginError('%s:%d could not be reached over %s: %s' % (
                host, port, self.c('protocol', 'ftps').upper(), e))

    def _ftp_mkdirs(self, f, folder):
        cur = ''
        for part in [p for p in folder.split('/') if p]:
            cur += '/' + part
            try:
                f.mkd(cur)
            except ftplib.error_perm:
                pass                            # there already (or not ours to make)

    @staticmethod
    def _quit(f):
        try:
            f.quit()
        except Exception:                               # noqa: BLE001
            f.close()

    # -- either way ----------------------------------------------------------------------
    def put_object(self, key, data):
        path = self.path_of(key)
        if self.c('protocol', 'ftps') == 'sftp':
            host, port = self._hostport()
            with self.ctx.ssh(ssh_conn(self, host, port)) as s:
                try:
                    s.put(data, path, mode=0o644, via='scp')
                except TypeError:
                    s.put(data, path, mode=0o644)
            return
        f = self._ftp()
        try:
            self._ftp_mkdirs(f, posixpath.dirname(path))
            f.storbinary('STOR ' + path, io.BytesIO(data))
        except ftplib.all_errors as e:
            raise PluginError('%s could not be written: %s' % (path, e))
        finally:
            self._quit(f)

    def drop_object(self, key):
        path = self.path_of(key)
        if self.c('protocol', 'ftps') == 'sftp':
            host, port = self._hostport()
            with self.ctx.ssh(ssh_conn(self, host, port)) as s:
                try:
                    rc = s.run('rm -f %s' % shq(path), check=False)[0]
                except PluginError:
                    rc = 1
                if rc:
                    try:
                        s.put(b'', path, mode=0o644, via='scp')
                    except TypeError:
                        s.put(b'', path, mode=0o644)
                    self.ctx.step('%s could not be removed (no shell there): emptied instead'
                                  % path, 'warn')
            return
        f = self._ftp()
        try:
            f.delete(path)
        except ftplib.error_perm as e:
            if not str(e).startswith('550'):
                raise PluginError('%s could not be taken away: %s' % (path, e))
        except ftplib.all_errors as e:
            raise PluginError('%s could not be taken away: %s' % (path, e))
        finally:
            self._quit(f)

    def get_object(self, key):
        path = self.path_of(key)
        if self.c('protocol', 'ftps') == 'sftp':
            return None
        f = self._ftp()
        buf = io.BytesIO()
        try:
            f.retrbinary('RETR ' + path, buf.write)
        except ftplib.all_errors as e:
            raise PluginError('%s could not be read back: %s' % (path, e))
        finally:
            self._quit(f)
        return buf.getvalue()

    def access(self):
        host, port = self._hostport()
        folder = self.path_of(self.prefix()).rstrip('/') or '/'
        if self.c('protocol', 'ftps') == 'sftp':
            with self.ctx.ssh(ssh_conn(self, host, port)) as s:
                try:
                    s.run('true', timeout=30, check=False)
                except PluginError as e:
                    if 'did not let' in str(e) or 'host key' in str(e):
                        raise
            return '%s: signed in over SFTP' % host
        f = self._ftp()
        try:
            f.cwd(folder)
        except ftplib.error_perm as e:
            raise PluginError('signed in to %s, but the folder %s is not there: %s'
                              % (host, folder, e), retry=False)
        finally:
            self._quit(f)
        return '%s: signed in over %s, the folder %s is there' % (
            host, self.c('protocol', 'ftps').upper(), folder)
