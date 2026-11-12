# -*- coding: utf-8 -*-
"""
Files put on an FTP / FTPS server for a device to take them from there (not a module:
the registry skips files starting with "_").

Some devices take a certificate only from a file server: Fujitsu ISM-VA from its own
FTP area (/<user group>/ftp), ETERNUS DX/AF from an FTP(S) server it is told of in its
CLI command. acme puts the files there with Python's ftplib - the same way the HTTP-01
validation over FTP does (acmelib/plugins/challenges/http_ftp.py), so "What happens"
writes every FTP command down - and takes them away again after the device read them:
one of them is the private key.

    st = FtpStage(module, host, port, user, password, tls=True, verify=True)
    with st:
        st.put('acme-x.key', data, folder='Administrator/ftp')
        ...
        st.delete('acme-x.key', folder='Administrator/ftp')
"""
from __future__ import annotations

import ftplib
import io
import ssl

from acmelib.plugins.base import PluginError


class FtpStage(object):
    """One FTP(S) connection of a module. The module's class attributes FTP / FTP_TLS
    (ftplib's by default) are used, so a test puts its own fake there."""

    def __init__(self, module, host, port, user, password, tls=False, verify=True,
                 timeout=30.0):
        self.m = module
        self.host = str(host or '').strip()
        self.port = int(port or 21)
        self.user = str(user or '')
        self.password = str(password or '')
        self.tls = bool(tls)
        self.verify = bool(verify)
        self.timeout = float(timeout or 30)
        self.f = None

    def words(self):
        return '%s:%d (%s)' % (self.host, self.port, 'FTPS' if self.tls else 'FTP')

    def open(self):
        try:
            if self.tls:
                c = ssl.create_default_context()
                if not self.verify:
                    c.check_hostname = False
                    c.verify_mode = ssl.CERT_NONE
                f = getattr(self.m, 'FTP_TLS', ftplib.FTP_TLS)(context=c, timeout=self.timeout)
                f.connect(self.host, self.port)
                f.login(self.user, self.password)
                f.prot_p()
            else:
                f = getattr(self.m, 'FTP', ftplib.FTP)(timeout=self.timeout)
                f.connect(self.host, self.port)
                f.login(self.user, self.password)
            f.set_pasv(True)
        except ftplib.error_perm as e:
            raise PluginError('the FTP server %s did not let %s in: %s' % (
                self.words(), self.user, e), retry=False)
        except (OSError, EOFError, ftplib.Error) as e:
            raise PluginError('the FTP server %s cannot be reached: %s' % (self.words(), e))
        self.f = f
        return self

    def close(self):
        if self.f is None:
            return
        try:
            self.f.quit()
        except Exception:                               # noqa: BLE001
            try:
                self.f.close()
            except Exception:                           # noqa: BLE001
                pass
        self.f = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *a):
        self.close()

    @staticmethod
    def path(name, folder=''):
        folder = str(folder or '').strip().strip('/')
        return '%s/%s' % (folder, name) if folder else name

    def listing(self, folder=''):
        """The names in a folder (read-only - what Try does)."""
        try:
            return [n.rsplit('/', 1)[-1] for n in self.f.nlst(str(folder or '').strip('/') or '.')]
        except ftplib.error_perm as e:
            # an empty folder answers 550 on some servers
            if '550' in str(e) and 'No such' not in str(e):
                return []
            raise PluginError('the FTP server cannot list %s: %s' % (folder or 'its home', e),
                              retry=False)
        except (OSError, EOFError, ftplib.Error) as e:
            raise PluginError('the FTP server cannot list %s: %s' % (folder or 'its home', e))

    def put(self, name, data, folder=''):
        p = self.path(name, folder)
        try:
            self.f.storbinary('STOR %s' % p, io.BytesIO(data if isinstance(data, bytes)
                                                         else str(data).encode()))
        except ftplib.error_perm as e:
            raise PluginError('the FTP server refused %s: %s' % (p, e), retry=False)
        except (OSError, EOFError, ftplib.Error) as e:
            raise PluginError('%s could not be written over FTP: %s' % (p, e))
        return p

    def delete(self, name, folder=''):
        """Taken away; False (and a warning) when it cannot be."""
        p = self.path(name, folder)
        try:
            self.f.delete(p)
            return True
        except Exception as e:                          # noqa: BLE001
            self.m.ctx.step('%s stays on the FTP server - delete it by hand: %s' % (p, e), 'warn')
            return False
