# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- keys and certificates ----------------------------------------------------------
def ssh_keygen(comment):
    if not shutil.which('ssh-keygen'):
        raise ValueError('ssh-keygen is not on this machine (dnf install openssh-clients)')
    with tempfile.TemporaryDirectory(prefix='acme-key-') as d:
        path = os.path.join(d, 'k')
        got = subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', comment,
                              '-f', path], capture_output=True, text=True, timeout=30)
        if got.returncode != 0:
            raise ValueError('ssh-keygen: %s' % (got.stderr or got.stdout).strip()[:200])
        with open(path) as f:
            private = f.read()
        with open(path + '.pub') as f:
            public = f.read().strip()
    return private, public


def ssh_public_of(private, passphrase=''):
    """The public half of a private key given - and that it is one."""
    if not shutil.which('ssh-keygen'):
        raise ValueError('ssh-keygen is not on this machine (dnf install openssh-clients)')
    private = str(private or '').replace('\r\n', '\n').strip() + '\n'
    if 'PRIVATE KEY-----' not in private:
        raise ValueError('that is not a private key (-----BEGIN OPENSSH PRIVATE KEY----- or '
                         'another PEM private key)')
    with tempfile.TemporaryDirectory(prefix='acme-key-') as d:
        path = os.path.join(d, 'k')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(private)
        # The passphrase through SSH_ASKPASS, not on the command line where
        # `ps` shows it (1.0.136).
        env = dict(os.environ, DISPLAY=':0', SSH_ASKPASS_REQUIRE='force')
        if passphrase:
            ask = os.path.join(d, 'ask')
            with open(ask, 'w') as f:
                f.write('#!/bin/sh\nprintf "%s\\n" "$ACME_RB_SECRET"\n')
            os.chmod(ask, 0o700)
            env.update(SSH_ASKPASS=ask, ACME_RB_SECRET=passphrase)
            argv = ['ssh-keygen', '-y', '-f', path]
        else:
            argv = ['ssh-keygen', '-y', '-P', '', '-f', path]
        got = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=env,
                             stdin=subprocess.DEVNULL)
    if got.returncode != 0:
        said = (got.stderr or got.stdout).strip()
        if 'passphrase' in said.lower() or 'incorrect' in said.lower():
            raise ValueError('the key is locked with a passphrase: give it too')
        raise ValueError('ssh-keygen does not read it: %s' % said[:200])
    return private, got.stdout.strip()


def rb_client_cert_make(cn, days=1825):
    """A key and a self-signed client certificate for FTPS."""
    key = new_key('ec')
    with tempfile.TemporaryDirectory(prefix='acme-crt-') as d:
        kf = os.path.join(d, 'k.pem')
        with open(kf, 'w') as f:
            f.write(key)
        os.chmod(kf, 0o600)
        cn = re.sub(r'[^A-Za-z0-9.@_-]', '', str(cn or 'acme-backup'))[:64] or 'acme-backup'
        crt = _openssl(['req', '-new', '-x509', '-key', kf, '-days', str(int(days)), '-subj',
                        '/CN=' + cn, '-addext', 'extendedKeyUsage=clientAuth',
                        '-addext', 'keyUsage=critical,digitalSignature'],
                       what='the certificate').decode()
    return key, crt


def rb_client_cert_given(text, password=''):
    """A client certificate brought: PEM (certificate and key, in any order)
    or PFX (base64 of it, with its password)."""
    text = str(text or '').strip()
    if 'BEGIN' in text:
        certs = [m.group(0) for m in PEM_CERT.finditer(text)]
        m = re.search(r'-----BEGIN (?:[A-Z ]*)PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]*)'
                      r'PRIVATE KEY-----', text)
        if not certs or not m:
            raise ValueError('a client certificate needs its certificate and its private key')
        key = m.group(0) + '\n'
        if 'ENCRYPTED' in key:
            key = _openssl(['pkey', '-passin', 'fd:@'], key.encode(),
                           secret=password, what='the key (its password)').decode()
        if _pub_of_key(key).strip() != _pub_of_cert(certs[0]).strip():
            raise ValueError('the key is not the one of this certificate')
        return key, '\n'.join(certs) + '\n'
    try:
        pfx = base64.b64decode(text, validate=False)
    except (binascii.Error, ValueError):
        raise ValueError('neither PEM nor PFX')
    with tempfile.TemporaryDirectory(prefix='acme-pfx-') as d:
        pf = os.path.join(d, 'c.pfx')
        with open(pf, 'wb') as f:
            f.write(pfx)
        both = ''
        for extra in ([], ['-legacy']):
            try:
                both = _openssl(['pkcs12', '-in', pf, '-nodes', '-passin', 'fd:@'] + extra,
                                secret=password, what='the PFX (its password?)').decode()
                break
            except ValueError:
                if extra:
                    raise
    return rb_client_cert_given(both)


# ---- the transports ------------------------------------------------------------------
class RbFolder(object):
    def __init__(self, t):
        self.t = t
        self.dir = t['path']

    def open(self):
        try:
            os.makedirs(self.dir, exist_ok=True)
        except OSError as e:
            raise RbError('the folder %s cannot be made: %s' % (self.dir, e))
        if not os.access(self.dir, os.W_OK):
            raise RbError('the acme account may not write into %s' % self.dir)

    def put(self, local, name):
        part = os.path.join(self.dir, '.%s.part' % name)
        shutil.copyfile(local, part)
        os.chmod(part, 0o640)
        os.replace(part, os.path.join(self.dir, name))

    def get(self, name, local):
        shutil.copyfile(os.path.join(self.dir, rb_safe_name(name)), local)

    def list(self):
        out = []
        for e in os.scandir(self.dir):
            if e.is_file() and not e.name.startswith('.'):
                st = e.stat()
                out.append({'name': e.name, 'size': st.st_size, 'mtime': st.st_mtime})
        return out

    def delete(self, name):
        os.unlink(os.path.join(self.dir, rb_safe_name(name)))

    def close(self):
        pass


def rb_safe_name(name):
    name = str(name or '')
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}\Z', name):
        raise RbError('not a file name of a backup: %r' % name[:80])
    return name


class _ImplicitFTP_TLS(ftplib.FTP_TLS):
    """FTPS on its own port (990): TLS from the first byte."""
    def connect(self, host='', port=0, timeout=-999, source_address=None):
        if host:
            self.host = host
        if port > 0:
            self.port = port
        if timeout != -999:
            self.timeout = timeout
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.af = self.sock.family
        self.sock = self.context.wrap_socket(self.sock, server_hostname=self.host)
        self.file = self.sock.makefile('r', encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome


class _ReuseMixin(object):
    """The data connection resumes the control connection's TLS session:
    vsftpd, ProFTPD and FileZilla Server refuse one that does not (522)."""
    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(conn, server_hostname=self.host,
                                            session=self.sock.session)
        return conn, size


class RbFtpTls(_ReuseMixin, ftplib.FTP_TLS):
    pass


class RbFtpTlsImplicit(_ReuseMixin, _ImplicitFTP_TLS):
    pass


class RbFtp(object):
    def __init__(self, t):
        self.t = t
        self.ftp = None
        self.tmp = None
        self.seen = {}

    def _context(self):
        t = self.t
        check = t.get('tls_check') or 'system'
        if check == 'ca':
            ctx = ssl.create_default_context(cadata=t.get('ca') or '')
        elif check == 'system':
            ctx = ssl.create_default_context()
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if t.get('client_cert') and t.get('client_key'):
            self.tmp = tempfile.mkdtemp(prefix='acme-ftps-')
            cf, kf = os.path.join(self.tmp, 'c.pem'), os.path.join(self.tmp, 'k.pem')
            with open(cf, 'w') as f:
                f.write(t['client_cert'])
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(rb_secret(t, 'client_key'))
            ctx.load_cert_chain(cf, kf)
        return ctx

    def open(self):
        t = self.t
        try:
            if t['kind'] == 'ftps':
                cls = RbFtpTlsImplicit if t.get('implicit') else RbFtpTls
                self.ftp = cls(context=self._context(), timeout=RB_TIMEOUT)
                self.ftp.connect(t['host'], int(t['port']))
                if not t.get('implicit'):
                    self.ftp.auth()
                der = self.ftp.sock.getpeercert(True)
                fp = hashlib.sha256(der).hexdigest() if der else ''
                self.seen = {'fingerprint': fp}
                try:
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    self.seen['cert'] = cert_info(pem)
                except Exception:                       # noqa: BLE001
                    pass
                if (t.get('tls_check') == 'pin') and fp != (t.get('pin') or ''):
                    raise RbError('the server answers with another certificate than the one '
                                  'pinned (SHA-256 %s)' % fp)
            else:
                self.ftp = ftplib.FTP(timeout=RB_TIMEOUT)
                self.ftp.connect(t['host'], int(t['port']))
            self.ftp.login(t.get('user') or 'anonymous', rb_secret(t, 'password'))
            if t['kind'] == 'ftps':
                self.ftp.prot_p()
            self.ftp.set_pasv(bool(t.get('passive', 1)))
            self._cd(t.get('path') or '')
        except ssl.SSLCertVerificationError as e:
            raise RbError('the server\'s certificate is not trusted: %s - check it against '
                          'its authority, or pin it' % e.verify_message)
        except ftplib.error_perm as e:
            raise RbError('the FTP server said: %s' % str(e)[:200])
        except (OSError, EOFError, ftplib.Error) as e:
            raise RbError(str(e)[:200] or e.__class__.__name__)

    def _cd(self, path):
        if not path:
            return
        if path.startswith('/'):
            self.ftp.cwd('/')
        for part in [p for p in path.split('/') if p]:
            try:
                self.ftp.cwd(part)
            except ftplib.error_perm:
                self.ftp.mkd(part)
                self.ftp.cwd(part)

    def put(self, local, name):
        with open(local, 'rb') as f:
            self.ftp.storbinary('STOR .%s.part' % name, f, blocksize=262144)
        try:
            self.ftp.delete(name)
        except ftplib.error_perm:
            pass
        self.ftp.rename('.%s.part' % name, name)

    def get(self, name, local):
        with open(local, 'wb') as f:
            self.ftp.retrbinary('RETR %s' % rb_safe_name(name), f.write, blocksize=262144)

    def list(self):
        out = []
        try:
            for name, facts in self.ftp.mlsd(facts=['type', 'size', 'modify']):
                if facts.get('type') == 'file':
                    m = facts.get('modify') or ''
                    try:
                        mt = datetime.strptime(m[:14], '%Y%m%d%H%M%S').replace(
                            tzinfo=timezone.utc).timestamp()
                    except ValueError:
                        mt = 0
                    out.append({'name': name, 'size': int(facts.get('size') or 0), 'mtime': mt})
            return out
        except ftplib.error_perm:
            pass
        for name in self.ftp.nlst():
            name = name.rsplit('/', 1)[-1]
            if name in ('.', '..'):
                continue
            try:
                size = self.ftp.size(name) or 0
            except ftplib.error_perm:
                continue            # a folder
            out.append({'name': name, 'size': size, 'mtime': 0})
        return out

    def delete(self, name):
        self.ftp.delete(rb_safe_name(name))

    def close(self):
        try:
            if self.ftp:
                self.ftp.quit()
        except Exception:                               # noqa: BLE001
            try:
                self.ftp.close()
            except Exception:                           # noqa: BLE001
                pass
        if self.tmp:
            shutil.rmtree(self.tmp, ignore_errors=True)


def ssh_keyscan(host, port):
    """The server's host keys, as known_hosts lines - and their fingerprints."""
    if not shutil.which('ssh-keyscan'):
        raise ValueError('ssh-keyscan is not on this machine (dnf install openssh-clients)')
    got = subprocess.run(['ssh-keyscan', '-T', '10', '-p', str(int(port)), host],
                         capture_output=True, text=True, timeout=30)
    lines = [x for x in got.stdout.splitlines() if x.strip() and not x.startswith('#')]
    if not lines:
        raise ValueError('%s:%s did not show a host key: %s' % (
            host, port, (got.stderr or '').strip().splitlines()[-1:] or 'no answer'))
    return '\n'.join(lines) + '\n', ssh_fingerprints('\n'.join(lines) + '\n')


class RbSsh(object):
    """SFTP (the sftp program) or SCP (scp, and ssh for the list and the
    deleting) - OpenSSH itself, the server's host key checked against the one
    trusted on the pages, a key of its own or a password."""
    def __init__(self, t):
        self.t = t
        self.d = None

    def open(self):
        t = self.t
        tools = ['ssh'] + (['sftp'] if t['kind'] == 'sftp' else ['scp'])
        for tool in tools:
            if not shutil.which(tool):
                raise RbError('%s is not on this machine (dnf install openssh-clients)' % tool)
        if not t.get('hostkey'):
            raise RbError('the server\'s host key is not trusted yet: Try it, then trust the '
                          'fingerprint it shows')
        self.d = tempfile.mkdtemp(prefix='acme-ssh-')
        kh = os.path.join(self.d, 'known_hosts')
        with open(kh, 'w') as f:
            f.write(t['hostkey'])
        self.opts = ['-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + kh,
                     '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=20',
                     '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4',
                     '-o', 'LogLevel=ERROR', '-o', 'IdentitiesOnly=yes', '-F', '/dev/null']
        key = rb_secret(t, 'key')
        if key:
            kf = os.path.join(self.d, 'id')
            fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(key if key.endswith('\n') else key + '\n')
            self.opts += ['-i', kf]
            if t.get('ssh_cert'):
                cf = os.path.join(self.d, 'id-cert.pub')
                with open(cf, 'w') as f:
                    f.write(t['ssh_cert'] + '\n')
                self.opts += ['-o', 'CertificateFile=' + cf]
        else:
            self.opts += ['-o', 'IdentityFile=/dev/null']
        # A password (or the key's passphrase) through SSH_ASKPASS: never on
        # a command line, never in a file of the acme account's.
        self.env = dict(os.environ, DISPLAY=':0', SSH_ASKPASS_REQUIRE='force')
        # Each prompt its own answer (1.0.139): with a password and a key that
        # has a passphrase, the password went to the key, and the key failed.
        pw = rb_secret(t, 'password') or rb_secret(t, 'key_pass')
        kp = rb_secret(t, 'key_pass') or rb_secret(t, 'password')
        ask = os.path.join(self.d, 'ask')
        with open(ask, 'w') as f:
            f.write('#!/bin/sh\ncase "$1" in\n  *assphrase*) printf "%s\\n" "$ACME_RB_KEYPASS";;\n'
                    '  *) printf "%s\\n" "$ACME_RB_SECRET";;\nesac\n')
        os.chmod(ask, 0o700)
        self.env.update(SSH_ASKPASS=ask, ACME_RB_SECRET=pw, ACME_RB_KEYPASS=kp)
        auths = ['publickey'] if key else []
        if rb_secret(t, 'password'):
            auths += ['password', 'keyboard-interactive']
        if not auths:
            raise RbError('neither a key nor a password is set')
        self.opts += ['-o', 'PreferredAuthentications=' + ','.join(auths),
                      '-o', 'NumberOfPasswordPrompts=1']
        if rb_secret(t, 'password') or rb_secret(t, 'key_pass'):
            # sftp -b asks ssh for batch mode, which takes no password; the
            # first value given wins, and this comes first.
            self.opts += ['-o', 'BatchMode=no']
        host = str(t['host']).strip('[]')
        self.dest = '%s@%s' % (t.get('user') or 'root', host)
        # scp and sftp read user@host:path - an IPv6 address in brackets
        # there (1.0.146), ssh takes it bare.
        self.rdest = '%s@[%s]' % (t.get('user') or 'root', host) if ':' in host else self.dest
        self.dir = (t.get('path') or '').rstrip('/') or '.'
        # Signed in and the folder made, at once - the errors said here.
        if t['kind'] == 'sftp':
            parts = [p for p in self.dir.split('/') if p and p != '.']
            cmds = []
            acc = '/' if self.dir.startswith('/') else ''
            for p in parts:
                acc = (acc + '/' + p) if acc not in ('', '/') else (acc + p)
                cmds.append('-mkdir "%s"' % acc)
            cmds.append('cd "%s"' % self.dir)
            self._sftp(cmds)
        else:
            self._ssh('mkdir -p -- %s && test -w %s' % (shlex_quote(self.dir),
                                                        shlex_quote(self.dir)))

    def _run(self, args, what, stdin=None, timeout=3600):
        got = subprocess.run(args, input=stdin, capture_output=True, text=True,
                             timeout=timeout, env=self.env, start_new_session=True)
        if got.returncode != 0:
            said = (got.stderr or got.stdout or '').strip().splitlines()
            said = [x for x in said if x.strip() and not x.startswith('Warning: Permanently')]
            tail = ' / '.join(said[-3:])[:300] or 'it said nothing (exit %d)' % got.returncode
            if 'Host key verification failed' in tail or 'REMOTE HOST IDENTIFICATION' in tail:
                tail = ('the server shows another host key than the one trusted - if it was '
                        'reinstalled on purpose, Try it and trust the new one')
            elif 'Permission denied' in tail:
                tail = 'the server did not let the account in (%s)' % tail
            raise RbError('%s: %s' % (what, tail))
        return got.stdout

    def _ssh(self, command):
        return self._run(['ssh'] + self.opts + ['-p', str(int(self.t['port'])), '--',
                                                self.dest, command], 'ssh')

    def _sftp(self, cmds, timeout=3600):
        batch = os.path.join(self.d, 'batch')
        with open(batch, 'w') as f:
            f.write('\n'.join(cmds) + '\n')
        return self._run(['sftp'] + self.opts + ['-P', str(int(self.t['port'])), '-b', batch,
                                                 '--', self.rdest], 'sftp', timeout=timeout)

    def put(self, local, name):
        name = rb_safe_name(name)
        if self.t['kind'] == 'sftp':
            self._sftp(['cd "%s"' % self.dir, 'put "%s" ".%s.part"' % (local, name),
                        '-rm "%s"' % name, 'rename ".%s.part" "%s"' % (name, name)])
        else:
            self._run(['scp'] + self.opts + ['-P', str(int(self.t['port'])), '-q', '--', local,
                                             '%s:%s/.%s.part' % (self.rdest, self.dir, name)],
                      'scp')
            self._ssh('mv -f -- %s %s' % (shlex_quote('%s/.%s.part' % (self.dir, name)),
                                          shlex_quote('%s/%s' % (self.dir, name))))

    def get(self, name, local):
        name = rb_safe_name(name)
        if self.t['kind'] == 'sftp':
            self._sftp(['cd "%s"' % self.dir, 'get "%s" "%s"' % (name, local)])
        else:
            self._run(['scp'] + self.opts + ['-P', str(int(self.t['port'])), '-q', '--',
                                             '%s:%s/%s' % (self.rdest, self.dir, name), local],
                      'scp')

    def list(self):
        if self.t['kind'] == 'sftp':
            text = self._sftp(['cd "%s"' % self.dir, 'ls -ln'])
        else:
            text = self._ssh('LC_ALL=C ls -ln -- %s' % shlex_quote(self.dir))
        out = []
        for line in text.splitlines():
            f = line.split(None, 8)
            if len(f) == 9 and f[0].startswith('-'):
                name = f[8].rsplit('/', 1)[-1]
                try:
                    out.append({'name': name, 'size': int(f[4]), 'mtime': 0})
                except ValueError:
                    pass
        return out

    def delete(self, name):
        name = rb_safe_name(name)
        if self.t['kind'] == 'sftp':
            self._sftp(['cd "%s"' % self.dir, 'rm "%s"' % name])
        else:
            self._ssh('rm -f -- %s' % shlex_quote('%s/%s' % (self.dir, name)))

    def close(self):
        if self.d:
            shutil.rmtree(self.d, ignore_errors=True)


class RbSmb(object):
    """SMB through smbclient: an authentication file of its own (never the
    password on a command line), SMB2 at least, SMB3 encryption when asked."""
    def __init__(self, t):
        self.t = t
        self.d = None

    def open(self):
        t = self.t
        if not shutil.which('smbclient'):
            raise RbError('smbclient is not on this machine (dnf install samba-client)')
        self.d = tempfile.mkdtemp(prefix='acme-smb-')
        auth = os.path.join(self.d, 'auth')
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write('username = %s\npassword = %s\n' % (t.get('user') or 'guest',
                                                       rb_secret(t, 'password')))
            if t.get('domain'):
                f.write('domain = %s\n' % t['domain'])
        self.args = ['smbclient', '//%s/%s' % (t['host'], t['share']), '-A', auth,
                     '-p', str(int(t['port'])), '--option=client min protocol=SMB2',
                     '-t', str(RB_TIMEOUT)]
        if t.get('smb_encrypt'):
            self.args += ['--client-protection=encrypt']
        self.dir = (t.get('path') or '').replace('/', '\\').strip('\\')
        cmds = []
        acc = ''
        for p in [x for x in self.dir.split('\\') if x]:
            acc = (acc + '\\' + p) if acc else p
            cmds.append('mkdir "%s"' % acc)
        self._run(cmds + ['cd "\\%s"' % self.dir, 'ls'], ignore=('NT_STATUS_OBJECT_NAME_COLLISION',))

    def _run(self, cmds, ignore=(), timeout=3600):
        got = subprocess.run(self.args + ['-c', '; '.join(cmds)], capture_output=True, text=True,
                             timeout=timeout, cwd=self.d, start_new_session=True)
        text = (got.stdout or '') + (got.stderr or '')
        if 'Could not determine network interfaces' in text and \
                not any(a.startswith('--option=interfaces=') for a in self.args):
            # Samba lists the network interfaces over netlink, and a service
            # kept from netlink sockets (acme.service before 1.0.195) gets none -
            # it then stops before it connects at all. A client needs no
            # interface of its own to reach a server by its name or address.
            self.args.append('--option=interfaces=127.0.0.1/8')
            return self._run(cmds, ignore, timeout)
        bad = [x for x in text.splitlines() if 'NT_STATUS_' in x and
               not any(i in x for i in ignore)]
        if got.returncode != 0 or bad:
            said = ' / '.join((bad or text.strip().splitlines() or ['no answer'])[-2:])[:300]
            if 'NT_STATUS_LOGON_FAILURE' in said:
                said = 'the server did not take the account and password (%s)' % said
            elif 'NT_STATUS_BAD_NETWORK_NAME' in said:
                said = 'there is no share %s on %s' % (self.t['share'], self.t['host'])
            elif 'protection' in said.lower() and 'unknown' in said.lower():
                said = ('this smbclient does not know --client-protection: switch "SMB3 '
                        'encryption required" off or install a newer samba-client')
            raise RbError('smbclient: %s' % said)
        return got.stdout or ''

    def _cd(self):
        return 'cd "\\%s"' % self.dir

    def put(self, local, name):
        name = rb_safe_name(name)
        self._run([self._cd(), 'put "%s" ".%s.part"' % (local, name), 'del "%s"' % name,
                   'rename ".%s.part" "%s"' % (name, name)], ignore=('NT_STATUS_NO_SUCH_FILE',
                                                                   'NT_STATUS_OBJECT_NAME_NOT_FOUND'))

    def get(self, name, local):
        self._run([self._cd(), 'get "%s" "%s"' % (rb_safe_name(name), local)])

    def list(self):
        out = []
        for line in self._run([self._cd(), 'ls']).splitlines():
            m = re.match(r'^\s\s(.+?)\s+([ADHNRS]*)\s+(\d+)\s+(\w{3} \w{3}\s+\d+ [\d:]+ \d{4})\s*$',
                         line)
            if m and 'D' not in m.group(2) and m.group(1) not in ('.', '..'):
                try:
                    mt = datetime.strptime(re.sub(r'\s+', ' ', m.group(4)),
                                           '%a %b %d %H:%M:%S %Y').timestamp()
                except ValueError:
                    mt = 0
                out.append({'name': m.group(1), 'size': int(m.group(3)), 'mtime': mt})
        return out

    def delete(self, name):
        self._run([self._cd(), 'del "%s"' % rb_safe_name(name)])

    def close(self):
        if self.d:
            shutil.rmtree(self.d, ignore_errors=True)


def rb_said(e):
    """An error in words, whatever library raised it."""
    if isinstance(e, EOFError):
        return 'the server closed the connection'
    if isinstance(e, socket.timeout):
        return 'the server did not answer in time'
    if isinstance(e, ssl.SSLCertVerificationError):
        return ('the server\'s certificate is not trusted: %s - check it against its authority, '
                'or pin it' % e.verify_message)
    if isinstance(e, ftplib.Error):
        return 'the FTP server said: %s' % str(e)[:300]
    return scrub_secret(str(e) or e.__class__.__name__)[:400]


def rb_runtime_checked(t):
    """A destination as it is used, checked again (1.0.44) - not only when the page saved it: a
    row written another way put an account "-oProxyCommand=..." on ssh's command line, or a
    folder with "!" (a shell command of smbclient) into its -c."""
    if t.get('kind') not in ('folder', 'ftp', 'ftps', 'sftp', 'scp', 'smb'):
        raise RbError('a destination of an unknown kind')
    for k in ('host', 'user', 'path', 'share', 'domain'):
        v = str(t.get(k) or '')
        if v.lstrip().startswith('-') or re.search(r'[\x00-\x1f\x7f]', v):
            raise RbError('the destination\'s %s is not one this takes' % k)
    path = str(t.get('path') or '')
    if t['kind'] != 'folder' and re.search(r'[;"]', path) or \
            t['kind'] == 'smb' and '!' in path:
        # smbclient's -c: ";" the next command, "!" a shell command; sftp's batch: '"'.
        raise RbError('the destination\'s folder has %s in it - not used: change it there'
                      % ('; " or !' if t['kind'] == 'smb' else '; or "'))
    host = str(t.get('host') or '')
    if t['kind'] != 'folder' and host and not re.match(r'^[A-Za-z0-9.:\[\]_-]{1,253}\Z', host):
        raise RbError('the destination\'s server is not a name or an address')
    if re.search(r'[\s:@/\\]', str(t.get('user') or '')):
        raise RbError('the destination\'s account is not one this takes')
    return t


def rb_transport(t):
    rb_runtime_checked(t)
    return {'folder': RbFolder, 'ftp': RbFtp, 'ftps': RbFtp, 'sftp': RbSsh, 'scp': RbSsh,
            'smb': RbSmb}[t['kind']](t)


def rb_try(t):
    """Signed in, a small file written, seen in the list, taken away again."""
    out = {'ok': False, 'steps': []}
    began = time.time()
    tr = rb_transport(t)
    try:
        tr.open()
        out['steps'].append('signed in, the folder is there')
        if getattr(tr, 'seen', None):
            out['server_cert'] = tr.seen
        name = 'acme-try-%s-%s.txt' % (rb_slug(node_name()), secrets.token_hex(4))
        with tempfile.NamedTemporaryFile('w', prefix='acme-try-', delete=False) as f:
            f.write('acme %s on %s tried this destination at %s - this file is taken away again\n'
                    % (__version__, node_name(), datetime.now().isoformat(timespec='seconds')))
            local = f.name
        try:
            tr.put(local, name)
        finally:
            os.unlink(local)
        out['steps'].append('a file written')
        names = [x['name'] for x in tr.list()]
        if name not in names:
            raise RbError('the file written is not in the list the server gives')
        out['steps'].append('it is in the list (%d file(s) there)' % len(names))
        tr.delete(name)
        out['steps'].append('taken away again')
        out['ok'] = True
    except Exception as e:                              # noqa: BLE001
        out['error'] = rb_said(e)
        if getattr(tr, 'seen', None):
            out['server_cert'] = tr.seen
    finally:
        tr.close()
    out['secs'] = round(time.time() - began, 1)
    return out


